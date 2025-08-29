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

#include "request_permission_on_setting.h"
#include "ability_access_ctrl_common.h"
#include "ability.h"
#include "access_token.h"
#include "macro.h"
#include "token_setproc.h"
#include "want.h"

using namespace OHOS::FFI;
using OHOS::Security::AccessToken::AccessTokenID;
using OHOS::Security::AccessToken::AccessTokenKit;

namespace OHOS {
namespace CJSystemapi {
namespace {
const std::string PERMISSION_KEY = "ohos.user.setting.permission";
const std::string PERMISSION_RESULT_KEY = "ohos.user.setting.permission.result";

// error code from dialog
const int32_t RET_SUCCESS = 0;
const int32_t REQUEST_ALREADY_EXIST = 1;
const int32_t PERM_NOT_BELONG_TO_SAME_GROUP = 2;
const int32_t PERM_IS_NOT_DECLARE = 3;
const int32_t ALL_PERM_GRANTED = 4;
const int32_t PERM_REVOKE_BY_USER = 5;

std::mutex g_lockFlag;
} // namespace

extern "C" {
static int32_t TransferToCJErrorCode(int32_t errCode)
{
    int32_t cjCode = CJ_OK;
    switch (errCode) {
        case RET_SUCCESS:
            cjCode = CJ_OK;
            break;
        case REQUEST_ALREADY_EXIST:
            cjCode = CJ_ERROR_REQUEST_IS_ALREADY_EXIST;
            break;
        case PERM_NOT_BELONG_TO_SAME_GROUP:
            cjCode = CJ_ERROR_PARAM_INVALID;
            break;
        case PERM_IS_NOT_DECLARE:
            cjCode = CJ_ERROR_PARAM_INVALID;
            break;
        case ALL_PERM_GRANTED:
            cjCode = CJ_ERROR_ALL_PERM_GRANTED;
            break;
        case PERM_REVOKE_BY_USER:
            cjCode = CJ_ERROR_PERM_REVOKE_BY_USER;
            break;
        default:
            cjCode = CJ_ERROR_INNER;
            break;
    }
    return cjCode;
}

void PermissonOnSettingUICallback::ReleaseHandler(int32_t code)
{
    {
        std::lock_guard<std::mutex> lock(g_lockFlag);
        if (this->reqContext_->releaseFlag) {
            return;
        }
        this->reqContext_->releaseFlag = true;
    }
    Ace::UIContent* uiContent = nullptr;
    if (this->reqContext_->uiAbilityFlag) {
        uiContent = this->reqContext_->abilityContext->GetUIContent();
    } else {
        uiContent = this->reqContext_->uiExtensionContext->GetUIContent();
    }
    if (uiContent != nullptr) {
        LOGI("Close uiextension component");
        uiContent->CloseModalUIExtension(this->sessionId_);
    }
    if (code == 0) { // dialog terminate normally
        return;
    }
    LOGI("ReleaseHandler code %{public}d", code);
    RetDataCArrI32 retArr = {.code = code, .data = {.head = nullptr, .size = 0}};
    this->reqContext_->callbackRef(retArr);
}

PermissonOnSettingUICallback::PermissonOnSettingUICallback(
    const std::shared_ptr<RequestPermOnSettingAsyncContext>& reqContext)
{
    this->reqContext_ = reqContext;
}

PermissonOnSettingUICallback::~PermissonOnSettingUICallback()
{}

void PermissonOnSettingUICallback::SetSessionId(int32_t sessionId)
{
    this->sessionId_ = sessionId;
}

/*
 * when UIExtensionAbility use terminateSelfWithResult
 */
void PermissonOnSettingUICallback::OnResult(int32_t resultCode, const AAFwk::Want& result)
{
    this->reqContext_->errorCode = result.GetIntParam(RESULT_ERROR_KEY, 0);
    this->reqContext_->stateList = result.GetIntArrayParam(PERMISSION_RESULT_KEY);
    LOGI("ResultCode is %{public}d, errorCode=%{public}d, listSize=%{public}zu",
        resultCode, this->reqContext_->errorCode, this->reqContext_->stateList.size());
    ReleaseHandler(0);
    RetDataCArrI32 retArr = {.code = CJ_OK, .data = {.head = nullptr, .size = 0}};
    if (this->reqContext_->errorCode != 0) {
        retArr.code = TransferToCJErrorCode(this->reqContext_->errorCode);
        this->reqContext_->callbackRef(retArr);
        return;
    }

    auto size = this->reqContext_->stateList.size();
    if (size <= 0) {
        LOGE("StateList empty");
        retArr.code = CJ_ERROR_INNER;
        this->reqContext_->callbackRef(retArr);
        return;
    }
    auto arr = static_cast<int32_t*>(malloc(sizeof(int32_t) * size));
    if (!arr) {
        LOGE("Array malloc failed");
        retArr.code = CJ_ERROR_INNER;
        this->reqContext_->callbackRef(retArr);
        return;
    }

    for (int i = 0; i < static_cast<int32_t>(size); i++) {
        arr[i] = this->reqContext_->stateList[i];
    }
    retArr.data.head = arr;
    retArr.data.size = static_cast<int64_t>(size);
    this->reqContext_->callbackRef(retArr);
}

/*
 * when UIExtensionAbility send message to UIExtensionComponent
 */
void PermissonOnSettingUICallback::OnReceive(const AAFwk::WantParams& receive)
{
    LOGI("OnReceive Called!");
}

/*
 * when UIExtensionAbility disconnect or use terminate or process die
 * releaseCode is 0 when process normal exit
 */
void PermissonOnSettingUICallback::OnRelease(int32_t releaseCode)
{
    LOGI("releaseCode is %{public}d", releaseCode);
    ReleaseHandler(releaseCode);
}

/*
 * when UIExtensionComponent init or turn to background or destroy UIExtensionAbility occur error
 */
void PermissonOnSettingUICallback::OnError(int32_t code, const std::string& name, const std::string& message)
{
    LOGE("OnError: code is %{public}d, name is %{public}s, message is %{public}s",
        code, name.c_str(), message.c_str());
    ReleaseHandler(code);
}

/*
 * when UIExtensionComponent connect to UIExtensionAbility, ModalUIExtensionProxy will init,
 * UIExtensionComponent can send message to UIExtensionAbility by ModalUIExtensionProxy
 */
void PermissonOnSettingUICallback::OnRemoteReady(const std::shared_ptr<Ace::ModalUIExtensionProxy>& uiProxy)
{
    LOGI("Connect to UIExtensionAbility successfully.");
}

/*
 * when UIExtensionComponent destructed
 */
void PermissonOnSettingUICallback::OnDestroy()
{
    LOGI("UIExtensionAbility destructed.");
}

static Ace::ModalUIExtensionCallbacks BindCallbacks(std::shared_ptr<PermissonOnSettingUICallback> uiExtCallback)
{
    Ace::ModalUIExtensionCallbacks uiExtensionCallbacks = {
        [uiExtCallback](int32_t releaseCode) {
            uiExtCallback->OnRelease(releaseCode);
        },
        [uiExtCallback](int32_t resultCode, const OHOS::AAFwk::Want& result) {
            uiExtCallback->OnResult(resultCode, result);
        },
        [uiExtCallback](const OHOS::AAFwk::WantParams& request) {
            uiExtCallback->OnReceive(request);
        },
        [uiExtCallback](int32_t code, const std::string& name, [[maybe_unused]]const std::string& message) {
            uiExtCallback->OnError(code, name, name);
        },
        [uiExtCallback](const std::shared_ptr<OHOS::Ace::ModalUIExtensionProxy>& uiProxy) {
            uiExtCallback->OnRemoteReady(uiProxy);
        },
        [uiExtCallback] {
            uiExtCallback->OnDestroy();
        },
    };
    return uiExtensionCallbacks;
}

static int32_t CreateUIExtension(const Want &want, std::shared_ptr<RequestPermOnSettingAsyncContext> asyncContext)
{
    if (asyncContext == nullptr) {
        return CJ_ERROR_INNER;
    }
    Ace::UIContent* uiContent = nullptr;
    if (asyncContext->uiAbilityFlag) {
        uiContent = asyncContext->abilityContext->GetUIContent();
    } else {
        uiContent = asyncContext->uiExtensionContext->GetUIContent();
    }
    if (uiContent == nullptr) {
        LOGE("Get ui content failed!");
        return CJ_ERROR_INNER;
    }
    auto uiExtCallback = std::make_shared<PermissonOnSettingUICallback>(asyncContext);
    auto uiExtensionCallbacks = BindCallbacks(uiExtCallback);
    Ace::ModalUIExtensionConfig config;
    config.isProhibitBack = true;
    int32_t sessionId = uiContent->CreateModalUIExtension(want, uiExtensionCallbacks, config);
    if (sessionId == 0) {
        LOGE("SessionId invalid");
        return CJ_ERROR_INNER;
    }
    uiExtCallback->SetSessionId(sessionId);
    return CJ_OK;
}

static int32_t StartUIExtension(std::shared_ptr<RequestPermOnSettingAsyncContext> asyncContext)
{
    AAFwk::Want want;
    AccessTokenKit::GetPermissionManagerInfo(asyncContext->info);
    LOGI("bundleName: %{public}s, permStateAbilityName: %{public}s.",
        asyncContext->info.grantBundleName.c_str(), asyncContext->info.permStateAbilityName.c_str());
    want.SetElementName(asyncContext->info.grantBundleName, asyncContext->info.permStateAbilityName);
    want.SetParam(PERMISSION_KEY, asyncContext->permissionList);
    want.SetParam(EXTENSION_TYPE_KEY, UI_EXTENSION_TYPE);
    return CreateUIExtension(want, asyncContext);
}

void FfiRequestPermissionOnSetting::RequestPermissionOnSetting(OHOS::AbilityRuntime::Context* context,
    CArrString cPermissionList, const std::function<void(RetDataCArrI32)>& callbackRef)
{
    RetDataCArrI32 retArr = {.code = CJ_OK, .data = {.head = nullptr, .size = 0}};
    std::shared_ptr<RequestPermOnSettingAsyncContext> asyncContext =
        std::make_shared<RequestPermOnSettingAsyncContext>();
    if (!ParseRequestPermissionOnSetting(context, cPermissionList, asyncContext)) {
        LOGE("Param invalid");
        retArr.code = CJ_ERROR_PARAM_INVALID;
        callbackRef(retArr);
        return;
    }
    asyncContext->callbackRef = callbackRef;

    int32_t result = StartUIExtension(asyncContext);
    if (result != CJ_OK) {
        LOGE("Start UI failed, result %{public}d", result);
        retArr.code = result;
        callbackRef(retArr);
    }
    return;
}

bool FfiRequestPermissionOnSetting::ParseRequestPermissionOnSetting(OHOS::AbilityRuntime::Context* context,
    CArrString cPermissionList, const std::shared_ptr<RequestPermOnSettingAsyncContext>& asyncContext)
{
    AccessTokenID tokenID = 0;
    auto contextSharedPtr = context->shared_from_this();
    asyncContext->abilityContext = AbilityRuntime::Context::ConvertTo<AbilityRuntime::AbilityContext>(contextSharedPtr);
    if (asyncContext->abilityContext != nullptr) {
        asyncContext->uiAbilityFlag = true;
        tokenID = asyncContext->abilityContext->GetApplicationInfo()->accessTokenId;
    } else {
        asyncContext->uiExtensionContext =
            AbilityRuntime::Context::ConvertTo<AbilityRuntime::UIExtensionContext>(contextSharedPtr);
        if (asyncContext->uiExtensionContext == nullptr) {
            LOGE("Convert to ui extension context failed");
            return false;
        }
        tokenID = asyncContext->uiExtensionContext->GetApplicationInfo()->accessTokenId;
    }
    if (tokenID != static_cast<AccessTokenID>(GetSelfTokenID())) {
        LOGE("tokenID invalid");
        return false;
    }

    // check PermissionList
    if (cPermissionList.size == 0) {
        LOGE("PermissionList is empty");
        return false;
    }

    std::vector<std::string> permList;
    for (int64_t i = 0; i < cPermissionList.size; i++) {
        permList.emplace_back(std::string(cPermissionList.head[i]));
    }
    asyncContext->permissionList = permList;
    return true;
}
}
} // namespace CJSystemapi
} // namespace OHOS
