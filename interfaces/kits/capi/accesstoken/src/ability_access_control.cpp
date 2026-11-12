/*
 * Copyright (c) 2024 Huawei Device Co., Ltd.
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 *
 *     http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 */

#include "ability_access_control.h"

#include <memory>
#include <string>
#include <thread>
#include <utility>
#include <vector>

#include "ability_manager_client.h"
#include "accesstoken_common_log.h"
#include "accesstoken_kit.h"
#include "token_callback_stub.h"
#include "token_setproc.h"
#include "tokenid_attributes.h"
#include "want.h"

using namespace OHOS;
using namespace OHOS::Security::AccessToken;

bool OH_AT_CheckSelfPermission(const char* permission)
{
    if (permission == nullptr) {
        return false;
    }

    uint64_t tokenId = GetSelfTokenID();
    std::string permissionName(permission);
    return (AccessTokenKit::VerifyAccessToken(tokenId, permissionName) == PermissionState::PERMISSION_GRANTED);
}

namespace {
constexpr int32_t MAX_PERMISSION_COUNT = 1024;

constexpr int GRANT_RESULT_GRANTED = 0;
constexpr int GRANT_RESULT_USER_DENIED = -1;
constexpr int GRANT_RESULT_NOT_SUPPORTED = 2;
constexpr int GRANT_RESULT_COMMON_ERROR = 3;
constexpr int GRANT_RESULT_COMMON_ERROR_LEGACY = 4;
constexpr int GRANT_RESULT_NOT_DECLARED = 5;

const std::string PERMISSION_KEY = "ohos.user.grant.permission";
const std::string STATE_KEY = "ohos.user.grant.permission.state";
const std::string CALLBACK_KEY = "ohos.ability.params.callback";

struct CallbackContext {
    std::vector<std::string> permNames;
    std::vector<OH_AT_PermissionOperResult> preJudged;
    std::vector<bool> isDynamic;
    OH_AT_PermissionsRequestResultCallback callback;
    void* userData;
};

struct DeliveryResult {
    OH_AT_AbilityAccessControlErrorCode errorcode;
    std::vector<OH_AT_PermissionOperResult> operResults;
    std::unique_ptr<bool[]> dialogShown;
};

OH_AT_PermissionOperResult MapOperResult(PermissionOper state, PermissionErrorReason reason)
{
    switch (state) {
        case TypePermissionOper::PASS_OPER:
            return OH_AT_PERMISSION_OPER_GRANTED;
        case TypePermissionOper::SETTING_OPER:
            return OH_AT_PERMISSION_OPER_SETTING;
        default:
            break;
    }
    switch (reason) {
        case PERM_NOT_DECLEARED:
            return OH_AT_PERMISSION_OPER_NOT_DECLARED;
        case CONDITIONS_NOT_MET:
            return OH_AT_PERMISSION_OPER_CONSTRAINTS_NOT_MET;
        case UNABLE_POP_UP:
            return OH_AT_PERMISSION_OPER_POP_UP_RESTRICTED;
        case PERM_INVALID:
            return OH_AT_PERMISSION_OPER_INVALID_NAME;
        case PRIVACY_STATEMENT_NOT_AGREED:
            return OH_AT_PERMISSION_OPER_PRIVACY_STATEMENT_REQUIRED;
        case MANUAL_SETTING_PERM:
            return OH_AT_PERMISSION_OPER_GRANT_MODE_MISMATCH;
        default:
            LOGW(ATM_DOMAIN, ATM_TAG, "Unknown permission error reason: %{public}d, state: %{public}d.",
                static_cast<int32_t>(reason), static_cast<int32_t>(state));
            return OH_AT_PERMISSION_OPER_POP_UP_RESTRICTED;
    }
}

OH_AT_PermissionOperResult MapGrantResult(int grantResult)
{
    switch (grantResult) {
        case GRANT_RESULT_GRANTED:
            return OH_AT_PERMISSION_OPER_GRANTED;
        case GRANT_RESULT_USER_DENIED:
            return OH_AT_PERMISSION_OPER_SETTING;
        case GRANT_RESULT_NOT_SUPPORTED:
            return OH_AT_PERMISSION_OPER_CONSTRAINTS_NOT_MET;
        case GRANT_RESULT_NOT_DECLARED:
            return OH_AT_PERMISSION_OPER_NOT_DECLARED;
        default:
            return OH_AT_PERMISSION_OPER_POP_UP_RESTRICTED;
    }
}

OH_AT_AbilityAccessControlErrorCode DetectRequestLevelError(const std::vector<int>& grantResults)
{
    for (size_t i = 0; i < grantResults.size(); ++i) {
        switch (grantResults[i]) {
            case GRANT_RESULT_COMMON_ERROR:
            case GRANT_RESULT_COMMON_ERROR_LEGACY:
                LOGE(ATM_DOMAIN, ATM_TAG, "Grant dialog request failed with common error.");
                return OH_AT_ABILITY_ACCESS_CONTROL_COMMON_INNER_ERROR;
            default:
                break;
        }
    }
    return OH_AT_ABILITY_ACCESS_CONTROL_SUCCESS;
}

bool IsValidRequest(const char* permissions[], int32_t permCount, OH_AT_PermissionsRequestResultCallback callback)
{
    if ((permissions == nullptr) || (callback == nullptr) || (permCount <= 0) ||
        (permCount > MAX_PERMISSION_COUNT)) {
        return false;
    }
    for (int32_t i = 0; i < permCount; ++i) {
        if ((permissions[i] == nullptr) || (permissions[i][0] == '\0')) {
            return false;
        }
    }
    return true;
}

std::vector<PermissionListState> BuildPermissionList(const char* permissions[], int32_t permCount)
{
    std::vector<PermissionListState> permList;
    permList.reserve(static_cast<size_t>(permCount));
    for (int32_t i = 0; i < permCount; ++i) {
        PermissionListState permState;
        permState.permissionName = permissions[i];
        permState.state = TypePermissionOper::INVALID_OPER;
        permState.errorReason = PermissionErrorReason::PERM_INVALID;
        permList.emplace_back(std::move(permState));
    }
    return permList;
}

void CollectPreJudgedResults(const std::vector<PermissionListState>& permList, CallbackContext& context)
{
    size_t count = permList.size();
    context.permNames.reserve(count);
    context.preJudged.reserve(count);
    context.isDynamic.reserve(count);
    for (size_t i = 0; i < count; ++i) {
        context.permNames.emplace_back(permList[i].permissionName);
        bool isDynamic = permList[i].state == TypePermissionOper::DYNAMIC_OPER;
        context.preJudged.push_back(isDynamic ? OH_AT_PERMISSION_OPER_POP_UP_RESTRICTED
            : MapOperResult(permList[i].state, permList[i].errorReason));
        context.isDynamic.push_back(isDynamic);
    }
}

DeliveryResult AssembleDeliveryResult(const CallbackContext& context, const std::vector<int>& grantResults)
{
    DeliveryResult delivery;
    delivery.errorcode = DetectRequestLevelError(grantResults);
    size_t count = context.preJudged.size();
    delivery.operResults.resize(count);
    delivery.dialogShown = std::make_unique<bool[]>(count);
    for (size_t i = 0; i < count; ++i) {
        bool isDynamic = context.isDynamic[i];
        delivery.dialogShown[i] = isDynamic;
        if (delivery.errorcode != OH_AT_ABILITY_ACCESS_CONTROL_SUCCESS) {
            delivery.operResults[i] = OH_AT_PERMISSION_OPER_POP_UP_RESTRICTED;
        } else if (isDynamic && (i < grantResults.size())) {
            delivery.operResults[i] = MapGrantResult(grantResults[i]);
        } else {
            delivery.operResults[i] = context.preJudged[i];
        }
    }
    return delivery;
}

void DeliverResultAsync(const std::shared_ptr<CallbackContext>& context, DeliveryResult delivery)
{
    std::thread([context, delivery = std::move(delivery)]() mutable {
        std::vector<const char*> permPtrs;
        permPtrs.reserve(context->permNames.size());
        for (const auto& name : context->permNames) {
            permPtrs.push_back(name.c_str());
        }
        OH_AT_PermissionsRequestResult result = { delivery.errorcode, permPtrs.data(),
            static_cast<int32_t>(permPtrs.size()), delivery.operResults.data(), delivery.dialogShown.get() };
        context->callback(&result, context->userData);
    }).detach();
}

class BinDialogResultReceiver : public TokenCallbackStub {
public:
    explicit BinDialogResultReceiver(const std::shared_ptr<CallbackContext>& context) : context_(context) {}
    ~BinDialogResultReceiver() override = default;

    void GrantResultsCallback(const std::vector<std::string>& permissions,
        const std::vector<int>& grantResults) override
    {
        (void)permissions;
        DeliverResultAsync(context_, AssembleDeliveryResult(*context_, grantResults));
    }

private:
    std::shared_ptr<CallbackContext> context_;
};

OH_AT_AbilityAccessControlErrorCode StartGrantDialog(const PermissionGrantInfo& grantInfo,
    const std::vector<PermissionListState>& permList, const std::shared_ptr<CallbackContext>& context)
{
    AAFwk::Want want;
    want.SetElementName(grantInfo.grantBundleName, grantInfo.grantServiceAbilityName);
    std::vector<std::string> permNames;
    std::vector<int32_t> states;
    permNames.reserve(permList.size());
    states.reserve(permList.size());
    for (const auto& perm : permList) {
        permNames.push_back(perm.permissionName);
        states.push_back(static_cast<int32_t>(perm.state));
    }
    want.SetParam(PERMISSION_KEY, permNames);
    want.SetParam(STATE_KEY, states);
    sptr<IRemoteObject> receiver = sptr<BinDialogResultReceiver>::MakeSptr(context);
    want.SetParam(CALLBACK_KEY, receiver);
    auto err = AAFwk::AbilityManagerClient::GetInstance()->StartAbility(want);
    if (err != 0) {
        LOGE(ATM_DOMAIN, ATM_TAG, "StartAbility failed, err: %{public}d.", err);
        return OH_AT_ABILITY_ACCESS_CONTROL_COMMON_INNER_ERROR;
    }
    return OH_AT_ABILITY_ACCESS_CONTROL_SUCCESS;
}
} // namespace

OH_AT_AbilityAccessControlErrorCode OH_AT_RequestPermissionsFromUser(const char* permissions[],
    int32_t permCount, OH_AT_PermissionsRequestResultCallback callback, void* userData)
{
    if (!AccessTokenKit::IsBinPermissionDialogEnabled()) {
        LOGI(ATM_DOMAIN, ATM_TAG, "called, permCount: %{public}d.", permCount);
        return OH_AT_ABILITY_ACCESS_CONTROL_NOT_SUPPORTED_ERROR;
    }
    LOGI(ATM_DOMAIN, ATM_TAG, "called, permCount: %{public}d.", permCount);
    if (!IsValidRequest(permissions, permCount, callback)) {
        return OH_AT_ABILITY_ACCESS_CONTROL_INVALID_PARAMETER_ERROR;
    }
    AccessTokenID selfTokenId = static_cast<AccessTokenID>(GetSelfTokenID());
    if (!TokenIDAttributes::IsBinTokenId(selfTokenId)) {
        LOGE(ATM_DOMAIN, ATM_TAG, "Caller is not bin process, tokenId: %{public}u.", selfTokenId);
        return OH_AT_ABILITY_ACCESS_CONTROL_NOT_PERMITTED_PROCESS_TYPE_ERROR;
    }

    std::vector<PermissionListState> permList = BuildPermissionList(permissions, permCount);
    PermissionGrantInfo grantInfo;
    PermissionOper oper = AccessTokenKit::GetSelfPermissionsState(permList, grantInfo);
    if (grantInfo.grantBundleName.empty()) {
        LOGE(ATM_DOMAIN, ATM_TAG, "Communicate with access token service failed.");
        return OH_AT_ABILITY_ACCESS_CONTROL_SERVICE_EXCEPTION_ERROR;
    }
    if (oper == TypePermissionOper::INVALID_OPER) {
        LOGE(ATM_DOMAIN, ATM_TAG, "Access token service returned invalid oper.");
        return OH_AT_ABILITY_ACCESS_CONTROL_SERVICE_EXCEPTION_ERROR;
    }

    auto context = std::make_shared<CallbackContext>();
    CollectPreJudgedResults(permList, *context);
    context->callback = callback;
    context->userData = userData;
    if (oper != TypePermissionOper::DYNAMIC_OPER) {
        DeliverResultAsync(context, AssembleDeliveryResult(*context, {}));
        return OH_AT_ABILITY_ACCESS_CONTROL_SUCCESS;
    }
    return StartGrantDialog(grantInfo, permList, context);
}
