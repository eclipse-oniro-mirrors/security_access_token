/*
 * Copyright (c) 2026 Huawei Device Co., Ltd.
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 *
 * http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 */

#include "ability_access_control_mock.h"

#include <memory>

#define private public  // NOLINT
#include "ability_manager_client.h"
#undef private
#include "tokenid_attributes.h"

namespace OHOS {
namespace Security {
namespace AccessToken {
MockState g_mockState;

void ResetMockState()
{
    g_mockState.dialogEnabled = true;
    g_mockState.selfTokenId = 0;
    g_mockState.isBinToken = true;
    g_mockState.grantInfoValid = true;
    g_mockState.oper = TypePermissionOper::PASS_OPER;
    g_mockState.permState = TypePermissionOper::PASS_OPER;
    g_mockState.reason = PermissionErrorReason::REQ_SUCCESS;
    g_mockState.verifyResult = 0;
    g_mockState.startAbilityErr = 0;
    g_mockState.startAbilityCount = 0;
    g_mockState.receivers.clear();
}
} // namespace AccessToken
} // namespace Security
} // namespace OHOS

extern "C" uint64_t GetSelfTokenID(void)
{
    return OHOS::Security::AccessToken::g_mockState.selfTokenId;
}

namespace OHOS {
namespace Security {
namespace AccessToken {
PermissionOper AccessTokenKit::GetSelfPermissionsState(std::vector<PermissionListState>& permList,
    PermissionGrantInfo& info)
{
    for (auto& perm : permList) {
        perm.state = g_mockState.permState;
        perm.errorReason = g_mockState.reason;
    }
    if (!g_mockState.grantInfoValid) {
        info.grantBundleName = "";
        info.grantAbilityName = "";
        info.grantServiceAbilityName = "";
        return g_mockState.oper;
    }
    info.grantBundleName = "com.ohos.mockgrant";
    info.grantAbilityName = "MockGrantAbility";
    info.grantServiceAbilityName = "MockGrantServiceAbility";
    return g_mockState.oper;
}

bool AccessTokenKit::IsBinPermissionDialogEnabled()
{
    return g_mockState.dialogEnabled;
}

int AccessTokenKit::VerifyAccessToken(AccessTokenID tokenId, const std::string& permissionName)
{
    (void)tokenId;
    (void)permissionName;
    return g_mockState.verifyResult;
}

bool TokenIDAttributes::IsBinTokenId(AccessTokenID id)
{
    (void)id;
    return g_mockState.isBinToken;
}
} // namespace AccessToken
} // namespace Security
} // namespace OHOS

namespace OHOS {
namespace AAFwk {
AbilityManagerClient::AbilityManagerClient() {}

AbilityManagerClient::~AbilityManagerClient() {}

std::shared_ptr<AbilityManagerClient> AbilityManagerClient::GetInstance()
{
    static std::shared_ptr<AbilityManagerClient> instance = std::make_shared<AbilityManagerClient>();
    return instance;
}

ErrCode AbilityManagerClient::StartAbility(const AAFwk::Want& want, int requestCode, int32_t userId,
    uint64_t specifiedFullTokenId)
{
    (void)requestCode;
    (void)userId;
    (void)specifiedFullTokenId;
    const std::string callbackKey = "ohos.ability.params.callback";
    OHOS::Security::AccessToken::g_mockState.receivers.push_back(want.GetRemoteObject(callbackKey));
    OHOS::Security::AccessToken::g_mockState.startAbilityCount++;
    return OHOS::Security::AccessToken::g_mockState.startAbilityErr;
}
} // namespace AAFwk
} // namespace OHOS
