/*
 * Copyright (c) 2021-2022 Huawei Device Co., Ltd.
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

#include "accesstoken_kit.h"
#include <string>
#include <vector>
#include "accesstoken_dfx_define.h"
#include "accesstoken_log.h"
#include "access_token_error.h"
#include "accesstoken_manager_client.h"
#include "constant_common.h"
#include "data_validator.h"
#include "hap_token_info.h"
#include "hisysevent.h"
#include "permission_def.h"
#include "perm_state_change_callback_customize.h"
#include "token_setproc.h"

namespace OHOS {
namespace Security {
namespace AccessToken {
namespace {
static constexpr OHOS::HiviewDFX::HiLogLabel LABEL = {LOG_CORE, SECURITY_DOMAIN_ACCESSTOKEN, "AccessTokenKit"};
static const int INVALID_DLP_TOKEN_FLAG = -1;
static const int FIRSTCALLER_TOKENID_DEFAULT = 0;
} // namespace

AccessTokenIDEx AccessTokenKit::AllocHapToken(const HapInfoParams& info, const HapPolicyParams& policy)
{
    AccessTokenIDEx res = {0};
    ACCESSTOKEN_LOG_DEBUG(LABEL, "called!");
    if ((!DataValidator::IsUserIdValid(info.userID)) || !DataValidator::IsAppIDDescValid(info.appIDDesc) ||
        !DataValidator::IsBundleNameValid(info.bundleName) || !DataValidator::IsAplNumValid(policy.apl) ||
        !DataValidator::IsDomainValid(policy.domain) || !DataValidator::IsDlpTypeValid(info.dlpType)) {
        ACCESSTOKEN_LOG_ERROR(LABEL, "input param failed");
        return res;
    }

    return AccessTokenManagerClient::GetInstance().AllocHapToken(info, policy);
}

AccessTokenID AccessTokenKit::AllocLocalTokenID(const std::string& remoteDeviceID, AccessTokenID remoteTokenID)
{
    ACCESSTOKEN_LOG_DEBUG(LABEL, "called, deviceID=%{public}s, tokenID=%{public}d",
        ConstantCommon::EncryptDevId(remoteDeviceID).c_str(), remoteTokenID);
#ifdef DEBUG_API_PERFORMANCE
    ACCESSTOKEN_LOG_DEBUG(LABEL, "api_performance:start call");
    AccessTokenID resID = AccessTokenManagerClient::GetInstance().AllocLocalTokenID(remoteDeviceID, remoteTokenID);
    ACCESSTOKEN_LOG_DEBUG(LABEL, "api_performance:end call");
    return resID;
#else
    return AccessTokenManagerClient::GetInstance().AllocLocalTokenID(remoteDeviceID, remoteTokenID);
#endif
}

int AccessTokenKit::UpdateHapToken(
    AccessTokenID tokenID, const std::string& appIDDesc, int32_t apiVersion, const HapPolicyParams& policy)
{
    ACCESSTOKEN_LOG_DEBUG(LABEL, "called");
    if ((tokenID == 0) || (!DataValidator::IsAppIDDescValid(appIDDesc)) ||
        (!DataValidator::IsAplNumValid(policy.apl))) {
        ACCESSTOKEN_LOG_ERROR(LABEL, "input param failed");
        return RET_FAILED;
    }
    return AccessTokenManagerClient::GetInstance().UpdateHapToken(tokenID, appIDDesc, apiVersion, policy);
}

int AccessTokenKit::DeleteToken(AccessTokenID tokenID)
{
    ACCESSTOKEN_LOG_DEBUG(LABEL, "called, tokenID=%{public}d", tokenID);
    if (tokenID == 0) {
        ACCESSTOKEN_LOG_ERROR(LABEL, "tokenID is invalid");
        return RET_FAILED;
    }
    return AccessTokenManagerClient::GetInstance().DeleteToken(tokenID);
}

ATokenTypeEnum AccessTokenKit::GetTokenType(AccessTokenID tokenID)
{
    ACCESSTOKEN_LOG_DEBUG(LABEL, "called, tokenID=%{public}d", tokenID);
    if (tokenID == 0) {
        ACCESSTOKEN_LOG_ERROR(LABEL, "tokenID is invalid");
        return TOKEN_INVALID;
    }
    return AccessTokenManagerClient::GetInstance().GetTokenType(tokenID);
}

ATokenTypeEnum AccessTokenKit::GetTokenTypeFlag(AccessTokenID tokenID)
{
    ACCESSTOKEN_LOG_DEBUG(LABEL, "called, tokenID=%{public}d", tokenID);
    if (tokenID == 0) {
        ACCESSTOKEN_LOG_ERROR(LABEL, "tokenID is invalid");
        return TOKEN_INVALID;
    }
    AccessTokenIDInner *idInner = reinterpret_cast<AccessTokenIDInner *>(&tokenID);
    return static_cast<ATokenTypeEnum>(idInner->type);
}

int AccessTokenKit::CheckNativeDCap(AccessTokenID tokenID, const std::string& dcap)
{
    ACCESSTOKEN_LOG_DEBUG(LABEL, "called, tokenID=%{public}d, dcap=%{public}s", tokenID, dcap.c_str());
    if (tokenID == 0) {
        ACCESSTOKEN_LOG_ERROR(LABEL, "tokenID is invalid");
        return RET_FAILED;
    }
    if (!DataValidator::IsDcapValid(dcap)) {
        ACCESSTOKEN_LOG_ERROR(LABEL, "dcap is invalid");
        return RET_FAILED;
    }
    return AccessTokenManagerClient::GetInstance().CheckNativeDCap(tokenID, dcap);
}

AccessTokenID AccessTokenKit::GetHapTokenID(int userID, const std::string& bundleName, int instIndex)
{
    ACCESSTOKEN_LOG_DEBUG(LABEL, "called, userID=%{public}d, bundleName=%{public}s, instIndex=%{public}d",
        userID, bundleName.c_str(), instIndex);
    if (!DataValidator::IsUserIdValid(userID) || !DataValidator::IsBundleNameValid(bundleName)) {
        ACCESSTOKEN_LOG_ERROR(LABEL, "hap token param failed");
        return 0;
    }
    return AccessTokenManagerClient::GetInstance().GetHapTokenID(userID, bundleName, instIndex);
}

int AccessTokenKit::GetHapTokenInfo(AccessTokenID tokenID, HapTokenInfo& hapTokenInfoRes)
{
    ACCESSTOKEN_LOG_DEBUG(LABEL, "called, tokenID=%{public}d", tokenID);
    if (tokenID == 0) {
        ACCESSTOKEN_LOG_ERROR(LABEL, "tokenID is invalid");
        return RET_FAILED;
    }

    return AccessTokenManagerClient::GetInstance().GetHapTokenInfo(tokenID, hapTokenInfoRes);
}

int AccessTokenKit::GetNativeTokenInfo(AccessTokenID tokenID, NativeTokenInfo& nativeTokenInfoRes)
{
    ACCESSTOKEN_LOG_DEBUG(LABEL, "called, tokenID=%{public}d", tokenID);

    return AccessTokenManagerClient::GetInstance().GetNativeTokenInfo(tokenID, nativeTokenInfoRes);
}

PermissionOper AccessTokenKit::GetSelfPermissionsState(std::vector<PermissionListState>& permList)
{
    ACCESSTOKEN_LOG_DEBUG(LABEL, "called, permList.size=%{public}zu.", permList.size());
    return AccessTokenManagerClient::GetInstance().GetSelfPermissionsState(permList);
}

int AccessTokenKit::VerifyAccessToken(AccessTokenID tokenID, const std::string& permissionName)
{
    ACCESSTOKEN_LOG_DEBUG(LABEL, "called, tokenID=%{public}d, permissionName=%{public}s",
        tokenID, permissionName.c_str());
    if (!DataValidator::IsPermissionNameValid(permissionName)) {
        ACCESSTOKEN_LOG_ERROR(LABEL, "permissionName is invalid");
        return PERMISSION_DENIED;
    }
    return AccessTokenManagerClient::GetInstance().VerifyAccessToken(tokenID, permissionName);
}

int AccessTokenKit::VerifyAccessToken(
    AccessTokenID callerTokenID, AccessTokenID firstTokenID, const std::string& permissionName)
{
    ACCESSTOKEN_LOG_DEBUG(LABEL, "called, callerTokenID=%{public}d, firstTokenID=%{public}d, permissionName=%{public}s",
        callerTokenID, firstTokenID, permissionName.c_str());
    int ret = AccessTokenKit::VerifyAccessToken(callerTokenID, permissionName);
    if (ret != PERMISSION_GRANTED) {
        return ret;
    }
    if (firstTokenID == FIRSTCALLER_TOKENID_DEFAULT) {
        return ret;
    }
    return AccessTokenKit::VerifyAccessToken(firstTokenID, permissionName);
}

int AccessTokenKit::GetDefPermission(const std::string& permissionName, PermissionDef& permissionDefResult)
{
    ACCESSTOKEN_LOG_DEBUG(LABEL, "called, permissionName=%{public}s", permissionName.c_str());
    if (!DataValidator::IsPermissionNameValid(permissionName)) {
        ACCESSTOKEN_LOG_ERROR(LABEL, "permissionName is invalid");
        return AccessTokenError::ERR_PARAM_INVALID;
    }

    int ret = AccessTokenManagerClient::GetInstance().GetDefPermission(permissionName, permissionDefResult);
    ACCESSTOKEN_LOG_DEBUG(LABEL, "GetDefPermission bundleName = %{public}s", permissionDefResult.bundleName.c_str());

    return ret;
}

int AccessTokenKit::GetDefPermissions(AccessTokenID tokenID, std::vector<PermissionDef>& permDefList)
{
    ACCESSTOKEN_LOG_DEBUG(LABEL, "called, tokenID=%{public}d", tokenID);
    if (tokenID == 0) {
        ACCESSTOKEN_LOG_ERROR(LABEL, "tokenID is invalid");
        return RET_FAILED;
    }

    return AccessTokenManagerClient::GetInstance().GetDefPermissions(tokenID, permDefList);
}

int AccessTokenKit::GetReqPermissions(
    AccessTokenID tokenID, std::vector<PermissionStateFull>& reqPermList, bool isSystemGrant)
{
    ACCESSTOKEN_LOG_DEBUG(LABEL, "called, tokenID=%{public}d, isSystemGrant=%{public}d", tokenID, isSystemGrant);
    if (tokenID == 0) {
        ACCESSTOKEN_LOG_ERROR(LABEL, "tokenID is invalid");
        return RET_FAILED;
    }

    return AccessTokenManagerClient::GetInstance().GetReqPermissions(tokenID, reqPermList, isSystemGrant);
}

int AccessTokenKit::GetPermissionFlag(AccessTokenID tokenID, const std::string& permissionName, int& flag)
{
    ACCESSTOKEN_LOG_DEBUG(LABEL, "called, tokenID=%{public}d, permissionName=%{public}s",
        tokenID, permissionName.c_str());
    if (tokenID == 0) {
        ACCESSTOKEN_LOG_ERROR(LABEL, "tokenID is invalid");
        return AccessTokenError::ERR_PARAM_INVALID;
    }
    if (!DataValidator::IsPermissionNameValid(permissionName)) {
        ACCESSTOKEN_LOG_ERROR(LABEL, "permissionName is invalid");
        return AccessTokenError::ERR_PARAM_INVALID;
    }
    return AccessTokenManagerClient::GetInstance().GetPermissionFlag(tokenID, permissionName, flag);
}

int AccessTokenKit::GrantPermission(AccessTokenID tokenID, const std::string& permissionName, int flag)
{
    ACCESSTOKEN_LOG_DEBUG(LABEL, "called, tokenID=%{public}d, permissionName=%{public}s, flag=%{public}d",
        tokenID, permissionName.c_str(), flag);
    if (tokenID == 0) {
        ACCESSTOKEN_LOG_ERROR(LABEL, "tokenID is invalid");
        return AccessTokenError::ERR_PARAM_INVALID;
    }
    if (!DataValidator::IsPermissionNameValid(permissionName)) {
        ACCESSTOKEN_LOG_ERROR(LABEL, "permissionName is invalid");
        return AccessTokenError::ERR_PARAM_INVALID;
    }
    if (!DataValidator::IsPermissionFlagValid(flag)) {
        ACCESSTOKEN_LOG_ERROR(LABEL, "flag is invalid");
        return AccessTokenError::ERR_PARAM_INVALID;
    }
    return AccessTokenManagerClient::GetInstance().GrantPermission(tokenID, permissionName, flag);
}

int AccessTokenKit::RevokePermission(AccessTokenID tokenID, const std::string& permissionName, int flag)
{
    ACCESSTOKEN_LOG_DEBUG(LABEL, "called, tokenID=%{public}d, permissionName=%{public}s, flag=%{public}d",
        tokenID, permissionName.c_str(), flag);
    if (tokenID == 0) {
        ACCESSTOKEN_LOG_ERROR(LABEL, "tokenID is invalid");
        return AccessTokenError::ERR_PARAM_INVALID;
    }
    if (!DataValidator::IsPermissionNameValid(permissionName)) {
        ACCESSTOKEN_LOG_ERROR(LABEL, "permissionName is invalid");
        return AccessTokenError::ERR_PARAM_INVALID;
    }
    if (!DataValidator::IsPermissionFlagValid(flag)) {
        ACCESSTOKEN_LOG_ERROR(LABEL, "flag is invalid");
        return AccessTokenError::ERR_PARAM_INVALID;
    }
    return AccessTokenManagerClient::GetInstance().RevokePermission(tokenID, permissionName, flag);
}

int AccessTokenKit::ClearUserGrantedPermissionState(AccessTokenID tokenID)
{
    ACCESSTOKEN_LOG_DEBUG(LABEL, "called, tokenID=%{public}d", tokenID);
    if (tokenID == 0) {
        ACCESSTOKEN_LOG_ERROR(LABEL, "tokenID is invalid");
        return RET_FAILED;
    }
    return AccessTokenManagerClient::GetInstance().ClearUserGrantedPermissionState(tokenID);
}

int32_t AccessTokenKit::RegisterPermStateChangeCallback(
    const std::shared_ptr<PermStateChangeCallbackCustomize>& callback)
{
    ACCESSTOKEN_LOG_INFO(LABEL, "called");
    return AccessTokenManagerClient::GetInstance().RegisterPermStateChangeCallback(callback);
}

int32_t AccessTokenKit::UnRegisterPermStateChangeCallback(
    const std::shared_ptr<PermStateChangeCallbackCustomize>& callback)
{
    ACCESSTOKEN_LOG_INFO(LABEL, "called");
    return AccessTokenManagerClient::GetInstance().UnRegisterPermStateChangeCallback(callback);
}

int32_t AccessTokenKit::GetHapDlpFlag(AccessTokenID tokenID)
{
    ACCESSTOKEN_LOG_DEBUG(LABEL, "called, tokenID=%{public}d", tokenID);
    if (tokenID == 0) {
        ACCESSTOKEN_LOG_ERROR(LABEL, "tokenID is invalid");
        return INVALID_DLP_TOKEN_FLAG;
    }
    AccessTokenIDInner *idInner = reinterpret_cast<AccessTokenIDInner *>(&tokenID);
    return static_cast<int32_t>(idInner->dlpFlag);
}

int32_t AccessTokenKit::ReloadNativeTokenInfo()
{
    return AccessTokenManagerClient::GetInstance().ReloadNativeTokenInfo();
}

AccessTokenID AccessTokenKit::GetNativeTokenId(const std::string& processName)
{
    if (!DataValidator::IsProcessNameValid(processName)) {
        ACCESSTOKEN_LOG_ERROR(LABEL, "processName is invalid, processName=%{public}s", processName.c_str());
        return INVALID_TOKENID;
    }
    return AccessTokenManagerClient::GetInstance().GetNativeTokenId(processName);
}

#ifdef TOKEN_SYNC_ENABLE
int AccessTokenKit::GetHapTokenInfoFromRemote(AccessTokenID tokenID, HapTokenInfoForSync& hapSync)
{
    ACCESSTOKEN_LOG_DEBUG(LABEL, "called, tokenID=%{public}d", tokenID);
    if (tokenID == 0) {
        ACCESSTOKEN_LOG_ERROR(LABEL, "tokenID is invalid");
        return RET_FAILED;
    }

    return AccessTokenManagerClient::GetInstance().GetHapTokenInfoFromRemote(tokenID, hapSync);
}

int AccessTokenKit::GetAllNativeTokenInfo(std::vector<NativeTokenInfoForSync>& nativeTokenInfosRes)
{
    ACCESSTOKEN_LOG_DEBUG(LABEL, "called");

    return AccessTokenManagerClient::GetInstance().GetAllNativeTokenInfo(nativeTokenInfosRes);
}

int AccessTokenKit::SetRemoteHapTokenInfo(const std::string& deviceID,
    const HapTokenInfoForSync& hapSync)
{
    ACCESSTOKEN_LOG_DEBUG(LABEL, "called, deviceID=%{public}s, tokenID=%{public}d",
        ConstantCommon::EncryptDevId(deviceID).c_str(), hapSync.baseInfo.tokenID);
    return AccessTokenManagerClient::GetInstance().SetRemoteHapTokenInfo(deviceID, hapSync);
}

int AccessTokenKit::SetRemoteNativeTokenInfo(const std::string& deviceID,
    const std::vector<NativeTokenInfoForSync>& nativeTokenInfoList)
{
    ACCESSTOKEN_LOG_DEBUG(LABEL, "called, deviceID=%{public}s", ConstantCommon::EncryptDevId(deviceID).c_str());
    return AccessTokenManagerClient::GetInstance().SetRemoteNativeTokenInfo(deviceID, nativeTokenInfoList);
}

int AccessTokenKit::DeleteRemoteToken(const std::string& deviceID, AccessTokenID tokenID)
{
    ACCESSTOKEN_LOG_DEBUG(LABEL, "called, deviceID=%{public}s, tokenID=%{public}d",
        ConstantCommon::EncryptDevId(deviceID).c_str(), tokenID);
    return AccessTokenManagerClient::GetInstance().DeleteRemoteToken(deviceID, tokenID);
}

int AccessTokenKit::DeleteRemoteDeviceTokens(const std::string& deviceID)
{
    ACCESSTOKEN_LOG_DEBUG(LABEL, "called, deviceID=%{public}s", ConstantCommon::EncryptDevId(deviceID).c_str());
    return AccessTokenManagerClient::GetInstance().DeleteRemoteDeviceTokens(deviceID);
}

AccessTokenID AccessTokenKit::GetRemoteNativeTokenID(const std::string& deviceID, AccessTokenID tokenID)
{
    ACCESSTOKEN_LOG_DEBUG(LABEL, "called, deviceID=%{public}s, tokenID=%{public}d",
        ConstantCommon::EncryptDevId(deviceID).c_str(), tokenID);
    return AccessTokenManagerClient::GetInstance().GetRemoteNativeTokenID(deviceID, tokenID);
}
#endif

void AccessTokenKit::DumpTokenInfo(AccessTokenID tokenID, std::string& dumpInfo)
{
    ACCESSTOKEN_LOG_DEBUG(LABEL, "called, tokenID=%{public}d", tokenID);
    AccessTokenManagerClient::GetInstance().DumpTokenInfo(tokenID, dumpInfo);
}

int32_t AccessTokenKit::GetVersion(void)
{
    return DEFAULT_TOKEN_VERSION;
}
} // namespace AccessToken
} // namespace Security
} // namespace OHOS
