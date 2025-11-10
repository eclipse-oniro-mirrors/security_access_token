/*
 * Copyright (c) 2021-2024 Huawei Device Co., Ltd.
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
#include <cinttypes>
#include <string>
#include <vector>
#include "accesstoken_common_log.h"
#include "access_token_error.h"
#include "accesstoken_manager_client.h"
#include "constant_common.h"
#include "data_validator.h"
#include "hap_token_info.h"
#include "permission_def.h"
#include "permission_map.h"
#include "perm_setproc.h"
#include "perm_state_change_callback_customize.h"
#include "tokenid_kit.h"
#include "token_setproc.h"

namespace OHOS {
namespace Security {
namespace AccessToken {
namespace {
static const uint64_t SYSTEM_APP_MASK = (static_cast<uint64_t>(1) << 32);
static const uint64_t ATOMIC_SERVICE_MASK = (static_cast<uint64_t>(1) << 33);
static const uint64_t TOKEN_ID_LOWMASK = 0xffffffff;
static const int INVALID_DLP_TOKEN_FLAG = -1;
static const int FIRSTCALLER_TOKENID_DEFAULT = 0;
static const int MAX_LENGTH = 256;
} // namespace

PermUsedTypeEnum AccessTokenKit::GetPermissionUsedType(
    AccessTokenID tokenID, const std::string& permissionName)
{
    LOGD(ATM_DOMAIN, ATM_TAG, "TokenID=%{public}d, permissionName=%{public}s.",
        tokenID, permissionName.c_str());
    if ((tokenID == INVALID_TOKENID) || (!DataValidator::IsPermissionNameValid(permissionName))) {
        LOGE(ATM_DOMAIN, ATM_TAG, "Input param failed.");
        return PermUsedTypeEnum::INVALID_USED_TYPE;
    }
    return AccessTokenManagerClient::GetInstance().GetPermissionUsedType(tokenID, permissionName);
}

int AccessTokenKit::GrantPermissionForSpecifiedTime(
    AccessTokenID tokenID, const std::string& permissionName, uint32_t onceTime)
{
    LOGI(ATM_DOMAIN, ATM_TAG, "TokenID=%{public}d, permissionName=%{public}s, onceTime=%{public}d.",
        tokenID, permissionName.c_str(), onceTime);
    if (tokenID == INVALID_TOKENID) {
        LOGE(ATM_DOMAIN, ATM_TAG, "Invalid tokenID");
        return AccessTokenError::ERR_PARAM_INVALID;
    }
    if (!DataValidator::IsPermissionNameValid(permissionName)) {
        LOGE(ATM_DOMAIN, ATM_TAG, "Invalid permissionName");
        return AccessTokenError::ERR_PARAM_INVALID;
    }
    return AccessTokenManagerClient::GetInstance().GrantPermissionForSpecifiedTime(tokenID, permissionName, onceTime);
}

static bool IsRenderToken(AccessTokenID tokenID)
{
    AccessTokenIDInner* idInner = reinterpret_cast<AccessTokenIDInner*>(&tokenID);
    return idInner->renderFlag;
}

static void TransferHapPolicyParams(const HapPolicyParams& policyIn, HapPolicy& policyOut)
{
    policyOut.apl = policyIn.apl;
    policyOut.domain = policyIn.domain;
    policyOut.permList.assign(policyIn.permList.begin(), policyIn.permList.end());
    policyOut.aclRequestedList.assign(policyIn.aclRequestedList.begin(), policyIn.aclRequestedList.end());
    policyOut.preAuthorizationInfo.assign(policyIn.preAuthorizationInfo.begin(), policyIn.preAuthorizationInfo.end());
    for (const auto& perm : policyIn.permStateList) {
        PermissionStatus tmp;
        tmp.permissionName = perm.permissionName;
        tmp.grantStatus = perm.grantStatus[0];
        tmp.grantFlag = perm.grantFlags[0];
        policyOut.permStateList.emplace_back(tmp);
    }
    policyOut.checkIgnore = policyIn.checkIgnore;
    policyOut.aclExtendedMap = policyIn.aclExtendedMap;
}

AccessTokenIDEx AccessTokenKit::AllocHapToken(const HapInfoParams& info, const HapPolicyParams& policy)
{
    AccessTokenIDEx res = {0};
    LOGI(ATM_DOMAIN, ATM_TAG, "UserID: %{public}d, bundleName :%{public}s, \
permList: %{public}zu, stateList: %{public}zu, checkIgnore: %{public}d, isAtomicService: %{public}d",
        info.userID, info.bundleName.c_str(), policy.permList.size(), policy.permStateList.size(), policy.checkIgnore,
        info.isAtomicService);
    if ((!DataValidator::IsUserIdValid(info.userID)) || !DataValidator::IsAppIDDescValid(info.appIDDesc) ||
        !DataValidator::IsBundleNameValid(info.bundleName) || !DataValidator::IsAplNumValid(policy.apl) ||
        !DataValidator::IsDomainValid(policy.domain) || !DataValidator::IsDlpTypeValid(info.dlpType)) {
        LOGE(ATM_DOMAIN, ATM_TAG, "Input param failed");
        return res;
    }
    HapPolicy newPolicy;
    TransferHapPolicyParams(policy, newPolicy);
    return AccessTokenManagerClient::GetInstance().AllocHapToken(info, newPolicy);
}

int32_t AccessTokenKit::InitHapToken(const HapInfoParams& info, HapPolicyParams& policy,
    AccessTokenIDEx& fullTokenId)
{
    HapInfoCheckResult result;
    return InitHapToken(info, policy, fullTokenId, result);
}

int32_t AccessTokenKit::InitHapToken(const HapInfoParams& info, HapPolicyParams& policy,
    AccessTokenIDEx& fullTokenId, HapInfoCheckResult& result)
{
    LOGI(ATM_DOMAIN, ATM_TAG, "UserID: %{public}d, bundleName :%{public}s, permList: %{public}zu, "
        "stateList: %{public}zu, aclExtendedMap: %{public}zu, checkIgnore: %{public}d, isAtomicService: %{public}d",
        info.userID, info.bundleName.c_str(), policy.permList.size(), policy.permStateList.size(),
        policy.aclExtendedMap.size(), policy.checkIgnore, info.isAtomicService);
    if ((!DataValidator::IsUserIdValid(info.userID)) || !DataValidator::IsAppIDDescValid(info.appIDDesc) ||
        !DataValidator::IsBundleNameValid(info.bundleName) || !DataValidator::IsAplNumValid(policy.apl) ||
        !DataValidator::IsDomainValid(policy.domain) || !DataValidator::IsDlpTypeValid(info.dlpType) ||
        !DataValidator::IsAclExtendedMapSizeValid(policy.aclExtendedMap)) {
        LOGE(ATM_DOMAIN, ATM_TAG, "Input param failed");
        return AccessTokenError::ERR_PARAM_INVALID;
    }
    HapPolicy newPolicy;
    TransferHapPolicyParams(policy, newPolicy);
    return AccessTokenManagerClient::GetInstance().InitHapToken(info, newPolicy, fullTokenId, result);
}

AccessTokenID AccessTokenKit::AllocLocalTokenID(const std::string& remoteDeviceID, AccessTokenID remoteTokenID)
{
    LOGI(ATM_DOMAIN, ATM_TAG, "DeviceID=%{public}s, tokenID=%{public}d",
        ConstantCommon::EncryptDevId(remoteDeviceID).c_str(), remoteTokenID);
#ifdef DEBUG_API_PERFORMANCE
    LOGD(ATM_DOMAIN, ATM_TAG, "Api_performance:start call");
    AccessTokenID resID = AccessTokenManagerClient::GetInstance().AllocLocalTokenID(remoteDeviceID, remoteTokenID);
    LOGD(ATM_DOMAIN, ATM_TAG, "Api_performance:end call");
    return resID;
#else
    return AccessTokenManagerClient::GetInstance().AllocLocalTokenID(remoteDeviceID, remoteTokenID);
#endif
}

int32_t AccessTokenKit::UpdateHapToken(
    AccessTokenIDEx& tokenIdEx, const UpdateHapInfoParams& info, const HapPolicyParams& policy)
{
    HapInfoCheckResult result;
    return UpdateHapToken(tokenIdEx, info, policy, result);
}

int32_t AccessTokenKit::UpdateHapToken(AccessTokenIDEx& tokenIdEx, const UpdateHapInfoParams& info,
    const HapPolicyParams& policy, HapInfoCheckResult& result)
{
    LOGI(ATM_DOMAIN, ATM_TAG, "TokenID: %{public}d, isSystemApp: %{public}d, \
permList: %{public}zu, stateList: %{public}zu, aclExtendedMap: %{public}zu, checkIgnore: %{public}d, \
isAtomicService: %{public}d",
        tokenIdEx.tokenIdExStruct.tokenID, info.isSystemApp, policy.permList.size(), policy.permStateList.size(),
        policy.aclExtendedMap.size(), policy.checkIgnore, info.isAtomicService);
    if ((tokenIdEx.tokenIdExStruct.tokenID == INVALID_TOKENID) || (!DataValidator::IsAppIDDescValid(info.appIDDesc)) ||
        (!DataValidator::IsAplNumValid(policy.apl)) ||
        !DataValidator::IsAclExtendedMapSizeValid(policy.aclExtendedMap)) {
        LOGE(ATM_DOMAIN, ATM_TAG, "Input param failed");
        return AccessTokenError::ERR_PARAM_INVALID;
    }
    HapPolicy newPolicy;
    TransferHapPolicyParams(policy, newPolicy);
    return AccessTokenManagerClient::GetInstance().UpdateHapToken(tokenIdEx, info, newPolicy, result);
}

int AccessTokenKit::DeleteToken(AccessTokenID tokenID)
{
    LOGI(ATM_DOMAIN, ATM_TAG, "TokenID=%{public}d.", tokenID);
    if (tokenID == INVALID_TOKENID) {
        return AccessTokenError::ERR_PARAM_INVALID;
    }
    return AccessTokenManagerClient::GetInstance().DeleteToken(tokenID);
}

ATokenTypeEnum AccessTokenKit::GetTokenType(AccessTokenID tokenID) __attribute__((no_sanitize("cfi")))
{
    LOGD(ATM_DOMAIN, ATM_TAG, "TokenID=%{public}d.", tokenID);
    if (tokenID == INVALID_TOKENID) {
        LOGE(ATM_DOMAIN, ATM_TAG, "TokenID is invalid.");
        return TOKEN_INVALID;
    }
    return AccessTokenManagerClient::GetInstance().GetTokenType(tokenID);
}

ATokenTypeEnum AccessTokenKit::GetTokenTypeFlag(AccessTokenID tokenID)
{
    LOGD(ATM_DOMAIN, ATM_TAG, "TokenID=%{public}d.", tokenID);
    if (tokenID == INVALID_TOKENID) {
        LOGE(ATM_DOMAIN, ATM_TAG, "TokenID is invalid");
        return TOKEN_INVALID;
    }
    AccessTokenIDInner* idInner = reinterpret_cast<AccessTokenIDInner*>(&tokenID);
    return static_cast<ATokenTypeEnum>(idInner->type);
}

ATokenTypeEnum AccessTokenKit::GetTokenType(FullTokenID tokenID)
{
    AccessTokenID id = tokenID & TOKEN_ID_LOWMASK;
    LOGD(ATM_DOMAIN, ATM_TAG, "TokenID=%{public}d.", id);
    if (id == INVALID_TOKENID) {
        LOGE(ATM_DOMAIN, ATM_TAG, "TokenID is invalid");
        return TOKEN_INVALID;
    }
    return AccessTokenManagerClient::GetInstance().GetTokenType(id);
}

ATokenTypeEnum AccessTokenKit::GetTokenTypeFlag(FullTokenID tokenID)
{
    AccessTokenID id = tokenID & TOKEN_ID_LOWMASK;
    LOGD(ATM_DOMAIN, ATM_TAG, "TokenID=%{public}d.", id);
    if (id == INVALID_TOKENID) {
        LOGE(ATM_DOMAIN, ATM_TAG, "TokenID is invalid");
        return TOKEN_INVALID;
    }
    AccessTokenIDInner* idInner = reinterpret_cast<AccessTokenIDInner*>(&id);
    return static_cast<ATokenTypeEnum>(idInner->type);
}

AccessTokenID AccessTokenKit::GetHapTokenID(
    int32_t userID, const std::string& bundleName, int32_t instIndex) __attribute__((no_sanitize("cfi")))
{
    LOGD(ATM_DOMAIN, ATM_TAG, "UserID=%{public}d, bundleName=%{public}s, instIndex=%{public}d.",
        userID, bundleName.c_str(), instIndex);
    if ((!DataValidator::IsUserIdValid(userID)) || (!DataValidator::IsBundleNameValid(bundleName))) {
        LOGE(ATM_DOMAIN, ATM_TAG, "Hap token param check failed");
        return INVALID_TOKENID;
    }
    AccessTokenIDEx tokenIdEx =
        AccessTokenManagerClient::GetInstance().GetHapTokenID(userID, bundleName, instIndex);
    return tokenIdEx.tokenIdExStruct.tokenID;
}

AccessTokenIDEx AccessTokenKit::GetHapTokenIDEx(int32_t userID, const std::string& bundleName, int32_t instIndex)
{
    AccessTokenIDEx tokenIdEx = {0};
    LOGD(ATM_DOMAIN, ATM_TAG, "UserID=%{public}d, bundleName=%{public}s, instIndex=%{public}d.",
        userID, bundleName.c_str(), instIndex);
    if ((!DataValidator::IsUserIdValid(userID)) || (!DataValidator::IsBundleNameValid(bundleName))) {
        LOGE(ATM_DOMAIN, ATM_TAG, "Hap token param check failed");
        return tokenIdEx;
    }
    return AccessTokenManagerClient::GetInstance().GetHapTokenID(userID, bundleName, instIndex);
}

int32_t AccessTokenKit::GetTokenIDByUserID(int32_t userID, std::unordered_set<AccessTokenID>& tokenIdList)
{
    LOGD(ATM_DOMAIN, ATM_TAG, "UserID=%{public}d.", userID);
    if (!DataValidator::IsUserIdValid(userID)) {
        LOGE(ATM_DOMAIN, ATM_TAG, "UserID=%{public}d is invalid", userID);
        return  AccessTokenError::ERR_PARAM_INVALID;
    }
    return AccessTokenManagerClient::GetInstance().GetTokenIDByUserID(userID, tokenIdList);
}

int AccessTokenKit::GetHapTokenInfo(
    AccessTokenID tokenID, HapTokenInfo& hapTokenInfoRes) __attribute__((no_sanitize("cfi")))
{
    LOGD(ATM_DOMAIN, ATM_TAG, "TokenID=%{public}d.", tokenID);
    if (GetTokenTypeFlag(tokenID) != TOKEN_HAP) {
        LOGE(ATM_DOMAIN, ATM_TAG, "TokenID =%{public}d is invalid", tokenID);
        return AccessTokenError::ERR_PARAM_INVALID;
    }
    if (IsRenderToken(tokenID)) {
        LOGI(ATM_DOMAIN, ATM_TAG, "TokenID %{public}d is render process.", tokenID);
        return ERR_TOKENID_NOT_EXIST;
    }

    return AccessTokenManagerClient::GetInstance().GetHapTokenInfo(tokenID, hapTokenInfoRes);
}

int AccessTokenKit::GetNativeTokenInfo(
    AccessTokenID tokenID, NativeTokenInfo& nativeTokenInfoRes) __attribute__((no_sanitize("cfi")))
{
    LOGD(ATM_DOMAIN, ATM_TAG, "TokenID=%{public}d.", tokenID);
    if (GetTokenTypeFlag(tokenID) != TOKEN_NATIVE && GetTokenTypeFlag(tokenID) != TOKEN_SHELL) {
        LOGE(ATM_DOMAIN, ATM_TAG, "TokenID =%{public}d is invalid", tokenID);
        return AccessTokenError::ERR_PARAM_INVALID;
    }
    return AccessTokenManagerClient::GetInstance().GetNativeTokenInfo(tokenID, nativeTokenInfoRes);
}

int32_t AccessTokenKit::GetSelfPermissionStatus(const std::string& permissionName, PermissionOper& status)
{
    if (permissionName.empty() || permissionName.size() > MAX_LENGTH) {
        return ERR_PARAM_INVALID;
    }
    return AccessTokenManagerClient::GetInstance().GetSelfPermissionStatus(permissionName, status);
}

PermissionOper AccessTokenKit::GetSelfPermissionsState(std::vector<PermissionListState>& permList,
    PermissionGrantInfo& info)
{
    LOGD(ATM_DOMAIN, ATM_TAG, "PermList.size=%{public}zu.", permList.size());
    return AccessTokenManagerClient::GetInstance().GetSelfPermissionsState(permList, info);
}

int32_t AccessTokenKit::GetPermissionsStatus(AccessTokenID tokenID, std::vector<PermissionListState>& permList)
{
    LOGD(ATM_DOMAIN, ATM_TAG, "TokenID=%{public}d, permList.size=%{public}zu.", tokenID, permList.size());
    if (tokenID == INVALID_TOKENID) {
        LOGE(ATM_DOMAIN, ATM_TAG, "TokenID is invalid");
        return ERR_PARAM_INVALID;
    }
    return AccessTokenManagerClient::GetInstance().GetPermissionsStatus(tokenID, permList);
}

int AccessTokenKit::VerifyAccessToken(AccessTokenID tokenID, const std::string& permissionName, bool crossIpc)
{
    LOGD(ATM_DOMAIN, ATM_TAG, "TokenID=%{public}d, permissionName=%{public}s, crossIpc=%{public}d.",
        tokenID, permissionName.c_str(), crossIpc);
    if (IsRenderToken(tokenID)) {
        LOGI(ATM_DOMAIN, ATM_TAG, "TokenID %{public}d is render process, perm denied.", tokenID);
        return PERMISSION_DENIED;
    }
    uint32_t code;
    if (!TransferPermissionToOpcode(permissionName, code)) {
        LOGE(ATM_DOMAIN, ATM_TAG, "PermissionName(%{public}s) is not exist.", permissionName.c_str());
        return PERMISSION_DENIED;
    }
    if (crossIpc) {
        return AccessTokenManagerClient::GetInstance().VerifyAccessToken(tokenID, permissionName);
    }
    bool isGranted = false;
    int32_t ret = GetPermissionFromKernel(tokenID, code, isGranted);
    if (ret != 0) {
        return AccessTokenManagerClient::GetInstance().VerifyAccessToken(tokenID, permissionName);
    }
    return isGranted ? PERMISSION_GRANTED : PERMISSION_DENIED;
}

int AccessTokenKit::VerifyAccessToken(
    AccessTokenID callerTokenID, AccessTokenID firstTokenID, const std::string& permissionName, bool crossIpc)
{
    LOGD(ATM_DOMAIN, ATM_TAG, "CallerToken=%{public}d, firstToken=%{public}d, permissionName=%{public}s.",
        callerTokenID, firstTokenID, permissionName.c_str());
    int ret = AccessTokenKit::VerifyAccessToken(callerTokenID, permissionName, crossIpc);
    if (ret != PERMISSION_GRANTED) {
        return ret;
    }
    if (firstTokenID == FIRSTCALLER_TOKENID_DEFAULT) {
        return ret;
    }
    return AccessTokenKit::VerifyAccessToken(firstTokenID, permissionName, crossIpc);
}

int AccessTokenKit::VerifyAccessToken(AccessTokenID tokenID, const std::string& permissionName)
{
    LOGD(ATM_DOMAIN, ATM_TAG, "TokenID=%{public}d, permissionName=%{public}s.",
        tokenID, permissionName.c_str());
    if (IsRenderToken(tokenID)) {
        LOGI(ATM_DOMAIN, ATM_TAG, "TokenID %{public}d is render process, perm denied.", tokenID);
        return PERMISSION_DENIED;
    }
    uint32_t code;
    if (!TransferPermissionToOpcode(permissionName, code)) {
        LOGE(ATM_DOMAIN, ATM_TAG, "PermissionName(%{public}s) is not exist.", permissionName.c_str());
        return PERMISSION_DENIED;
    }
    bool isGranted = false;
    int32_t ret = GetPermissionFromKernel(tokenID, code, isGranted);
    if (ret != 0) {
        return AccessTokenManagerClient::GetInstance().VerifyAccessToken(tokenID, permissionName);
    }
    return isGranted ? PERMISSION_GRANTED : PERMISSION_DENIED;
}

int AccessTokenKit::VerifyAccessToken(
    AccessTokenID callerTokenID, AccessTokenID firstTokenID, const std::string& permissionName)
{
    LOGD(ATM_DOMAIN, ATM_TAG, "CallerToken=%{public}d, firstToken=%{public}d, permissionName=%{public}s.",
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

int AccessTokenKit::VerifyAccessToken(AccessTokenID tokenID, const std::vector<std::string>& permissionList,
    std::vector<int32_t>& permStateList, bool crossIpc)
{
    LOGD(ATM_DOMAIN, ATM_TAG, "TokenID=%{public}d, permissionlist.size=%{public}zu, crossIpc=%{public}d.",
        tokenID, permissionList.size(), crossIpc);
    permStateList.clear();
    if (IsRenderToken(tokenID)) {
        LOGI(ATM_DOMAIN, ATM_TAG, "TokenID %{public}d is render process, perm denied.", tokenID);
        permStateList.resize(permissionList.size(), PERMISSION_DENIED);
        return RET_SUCCESS;
    }
    if (crossIpc) {
        return AccessTokenManagerClient::GetInstance().VerifyAccessToken(tokenID, permissionList, permStateList);
    }

    permStateList.resize(permissionList.size(), PERMISSION_DENIED);
    std::vector<std::string> permListCrossIpc;
    std::unordered_map<size_t, size_t> permToState;
    for (size_t i = 0; i < permissionList.size(); i++) {
        bool isGranted = false;
        uint32_t code;
        if (!TransferPermissionToOpcode(permissionList[i], code)) {
            LOGE(ATM_DOMAIN, ATM_TAG, "PermissionName(%{public}s) is not exist.", permissionList[i].c_str());
            permStateList[i] = PERMISSION_DENIED;
            continue;
        }
        int32_t ret = GetPermissionFromKernel(tokenID, code, isGranted);
        if (ret != 0) {
            permToState[permListCrossIpc.size()] = i;
            permListCrossIpc.emplace_back(permissionList[i]);
            continue;
        }
        permStateList[i] = isGranted ? PERMISSION_GRANTED : PERMISSION_DENIED;
    }
    if (!permListCrossIpc.empty()) {
        std::vector<int32_t> permStateCrossIpc;
        int ret = AccessTokenManagerClient::GetInstance().VerifyAccessToken(tokenID,
            permListCrossIpc, permStateCrossIpc);
        if (ret != ERR_OK) {
            return ret;
        }
        for (size_t i = 0; i < permStateCrossIpc.size(); i++) {
            if (permToState.find(i) != permToState.end()) {
                permStateList[permToState[i]] = permStateCrossIpc[i];
            }
        }
    }
    return ERR_OK;
}

int AccessTokenKit::GetDefPermission(const std::string& permissionName, PermissionDef& permissionDefResult)
{
    LOGD(ATM_DOMAIN, ATM_TAG, "PermissionName=%{public}s.", permissionName.c_str());
    if (!DataValidator::IsPermissionNameValid(permissionName)) {
        LOGE(ATM_DOMAIN, ATM_TAG, "PermissionName is invalid");
        return AccessTokenError::ERR_PARAM_INVALID;
    }

    PermissionBriefDef briefDef;
    if (!GetPermissionBriefDef(permissionName, briefDef)) {
        return AccessTokenError::ERR_PERMISSION_NOT_EXIST;
    }

    if (briefDef.grantMode == GrantMode::SYSTEM_GRANT) {
        ConvertPermissionBriefToDef(briefDef, permissionDefResult);
        return 0;
    }

    return AccessTokenManagerClient::GetInstance().GetDefPermission(permissionName, permissionDefResult);
}

int AccessTokenKit::GetReqPermissions(
    AccessTokenID tokenID, std::vector<PermissionStateFull>& reqPermList, bool isSystemGrant)
{
    LOGD(ATM_DOMAIN, ATM_TAG, "TokenID=%{public}d, isSystemGrant=%{public}d.", tokenID, isSystemGrant);
    if (tokenID == INVALID_TOKENID) {
        LOGE(ATM_DOMAIN, ATM_TAG, "TokenID is invalid");
        return AccessTokenError::ERR_PARAM_INVALID;
    }

    return AccessTokenManagerClient::GetInstance().GetReqPermissions(tokenID, reqPermList, isSystemGrant);
}

int AccessTokenKit::GetPermissionFlag(AccessTokenID tokenID, const std::string& permissionName, uint32_t& flag)
{
    LOGD(ATM_DOMAIN, ATM_TAG, "TokenID=%{public}d, permissionName=%{public}s.",
        tokenID, permissionName.c_str());
    if (tokenID == INVALID_TOKENID) {
        LOGE(ATM_DOMAIN, ATM_TAG, "TokenID is invalid");
        return AccessTokenError::ERR_PARAM_INVALID;
    }
    if (!DataValidator::IsPermissionNameValid(permissionName)) {
        LOGE(ATM_DOMAIN, ATM_TAG, "PermissionName is invalid");
        return AccessTokenError::ERR_PARAM_INVALID;
    }
    return AccessTokenManagerClient::GetInstance().GetPermissionFlag(tokenID, permissionName, flag);
}

int AccessTokenKit::GrantPermission(
    AccessTokenID tokenID, const std::string& permissionName, uint32_t flag, UpdatePermissionFlag updateFlag)
{
    LOGD(ATM_DOMAIN, ATM_TAG, "TokenID=%{public}d, permissionName=%{public}s, flag=%{public}d.",
        tokenID, permissionName.c_str(), flag);
    if (tokenID == INVALID_TOKENID) {
        LOGE(ATM_DOMAIN, ATM_TAG, "TokenID is invalid");
        return AccessTokenError::ERR_PARAM_INVALID;
    }
    if (IsRenderToken(tokenID)) {
        LOGI(ATM_DOMAIN, ATM_TAG, "TokenID %{public}d is render process.", tokenID);
        return ERR_TOKENID_NOT_EXIST;
    }
    if (!DataValidator::IsPermissionNameValid(permissionName)) {
        LOGE(ATM_DOMAIN, ATM_TAG, "PermissionName is invalid");
        return AccessTokenError::ERR_PARAM_INVALID;
    }
    if (!DataValidator::IsPermissionFlagValid(flag) || DataValidator::IsPermissionFlagValidForAdmin(flag)) {
        LOGE(ATM_DOMAIN, ATM_TAG, "Flag is invalid");
        return AccessTokenError::ERR_PARAM_INVALID;
    }
    return AccessTokenManagerClient::GetInstance().GrantPermission(tokenID, permissionName, flag, updateFlag);
}

int AccessTokenKit::RevokePermission(
    AccessTokenID tokenID, const std::string& permissionName, uint32_t flag, UpdatePermissionFlag updateFlag)
{
    LOGD(ATM_DOMAIN, ATM_TAG, "TokenID=%{public}d, permissionName=%{public}s, flag=%{public}d.",
        tokenID, permissionName.c_str(), flag);
    if (tokenID == INVALID_TOKENID) {
        LOGE(ATM_DOMAIN, ATM_TAG, "Invalid tokenID");
        return AccessTokenError::ERR_PARAM_INVALID;
    }
    if (IsRenderToken(tokenID)) {
        LOGI(ATM_DOMAIN, ATM_TAG, "TokenID %{public}d is render process.", tokenID);
        return ERR_TOKENID_NOT_EXIST;
    }
    if (!DataValidator::IsPermissionNameValid(permissionName)) {
        LOGE(ATM_DOMAIN, ATM_TAG, "Invalid permissionName");
        return AccessTokenError::ERR_PARAM_INVALID;
    }
    if (!DataValidator::IsPermissionFlagValid(flag) || DataValidator::IsPermissionFlagValidForAdmin(flag)) {
        LOGE(ATM_DOMAIN, ATM_TAG, "Invalid flag");
        return AccessTokenError::ERR_PARAM_INVALID;
    }
    return AccessTokenManagerClient::GetInstance().RevokePermission(tokenID, permissionName, flag, updateFlag);
}

int AccessTokenKit::ClearUserGrantedPermissionState(AccessTokenID tokenID)
{
    LOGD(ATM_DOMAIN, ATM_TAG, "TokenID=%{public}d.", tokenID);
    if (tokenID == INVALID_TOKENID) {
        LOGE(ATM_DOMAIN, ATM_TAG, "TokenID is invalid");
        return AccessTokenError::ERR_PARAM_INVALID;
    }
    return AccessTokenManagerClient::GetInstance().ClearUserGrantedPermissionState(tokenID);
}

int32_t AccessTokenKit::SetPermissionRequestToggleStatus(const std::string& permissionName, uint32_t status,
    int32_t userID = 0)
{
    LOGD(ATM_DOMAIN, ATM_TAG, "PermissionName=%{public}s, status=%{public}d, userID=%{public}d.",
        permissionName.c_str(), status, userID);
    if (!DataValidator::IsPermissionNameValid(permissionName)) {
        LOGE(ATM_DOMAIN, ATM_TAG, "PermissionName is invalid.");
        return AccessTokenError::ERR_PARAM_INVALID;
    }
    if (!DataValidator::IsToggleStatusValid(status)) {
        LOGE(ATM_DOMAIN, ATM_TAG, "Toggle status is invalid.");
        return AccessTokenError::ERR_PARAM_INVALID;
    }
    if (!DataValidator::IsUserIdValid(userID)) {
        LOGE(ATM_DOMAIN, ATM_TAG, "UserID is invalid.");
        return AccessTokenError::ERR_PARAM_INVALID;
    }
    return AccessTokenManagerClient::GetInstance().SetPermissionRequestToggleStatus(permissionName, status, userID);
}

int32_t AccessTokenKit::GetPermissionRequestToggleStatus(const std::string& permissionName, uint32_t& status,
    int32_t userID = 0)
{
    LOGD(ATM_DOMAIN, ATM_TAG, "PermissionName=%{public}s, userID=%{public}d.",
        permissionName.c_str(), userID);
    if (!DataValidator::IsPermissionNameValid(permissionName)) {
        LOGE(ATM_DOMAIN, ATM_TAG, "PermissionName is invalid.");
        return AccessTokenError::ERR_PARAM_INVALID;
    }
    if (!DataValidator::IsUserIdValid(userID)) {
        LOGE(ATM_DOMAIN, ATM_TAG, "UserID is invalid.");
        return AccessTokenError::ERR_PARAM_INVALID;
    }
    return AccessTokenManagerClient::GetInstance().GetPermissionRequestToggleStatus(permissionName, status, userID);
}

int32_t AccessTokenKit::RequestAppPermOnSetting(AccessTokenID tokenID)
{
    LOGD(ATM_DOMAIN, ATM_TAG, "tokenID=%{public}d.", tokenID);
    if (tokenID == INVALID_TOKENID) {
        LOGE(ATM_DOMAIN, ATM_TAG, "TokenID is invalid");
        return AccessTokenError::ERR_PARAM_INVALID;
    }
    return AccessTokenManagerClient::GetInstance().RequestAppPermOnSetting(tokenID);
}

int32_t AccessTokenKit::RegisterPermStateChangeCallback(
    const std::shared_ptr<PermStateChangeCallbackCustomize>& callback)
{
    return AccessTokenManagerClient::GetInstance().RegisterPermStateChangeCallback(callback, SYSTEM_REGISTER_TYPE);
}

int32_t AccessTokenKit::UnRegisterPermStateChangeCallback(
    const std::shared_ptr<PermStateChangeCallbackCustomize>& callback)
{
    return AccessTokenManagerClient::GetInstance().UnRegisterPermStateChangeCallback(callback, SYSTEM_REGISTER_TYPE);
}

int32_t AccessTokenKit::RegisterSelfPermStateChangeCallback(
    const std::shared_ptr<PermStateChangeCallbackCustomize>& callback)
{
    return AccessTokenManagerClient::GetInstance().RegisterPermStateChangeCallback(callback, SELF_REGISTER_TYPE);
}

int32_t AccessTokenKit::UnRegisterSelfPermStateChangeCallback(
    const std::shared_ptr<PermStateChangeCallbackCustomize>& callback)
{
    return AccessTokenManagerClient::GetInstance().UnRegisterPermStateChangeCallback(callback, SELF_REGISTER_TYPE);
}

int32_t AccessTokenKit::GetHapDlpFlag(AccessTokenID tokenID)
{
    LOGD(ATM_DOMAIN, ATM_TAG, "TokenID=%{public}d.", tokenID);
    if (tokenID == INVALID_TOKENID) {
        LOGE(ATM_DOMAIN, ATM_TAG, "TokenID is invalid");
        return INVALID_DLP_TOKEN_FLAG;
    }
    AccessTokenIDInner* idInner = reinterpret_cast<AccessTokenIDInner*>(&tokenID);
    return static_cast<int32_t>(idInner->dlpFlag);
}

int32_t AccessTokenKit::ReloadNativeTokenInfo()
{
#ifndef ATM_BUILD_VARIANT_USER_ENABLE
    return AccessTokenManagerClient::GetInstance().ReloadNativeTokenInfo();
#else
    return 0;
#endif
}

int AccessTokenKit::GetHapTokenInfoExtension(AccessTokenID tokenID, HapTokenInfoExt& info)
{
    LOGD(ATM_DOMAIN, ATM_TAG, "TokenID=%{public}d.", tokenID);
    if (GetTokenTypeFlag(tokenID) != TOKEN_HAP) {
        LOGE(ATM_DOMAIN, ATM_TAG, "TokenID =%{public}d is invalid.", tokenID);
        return AccessTokenError::ERR_PARAM_INVALID;
    }
    if (IsRenderToken(tokenID)) {
        LOGI(ATM_DOMAIN, ATM_TAG, "TokenID %{public}d is render process.", tokenID);
        return ERR_TOKENID_NOT_EXIST;
    }

    return AccessTokenManagerClient::GetInstance().GetHapTokenInfoExtension(tokenID, info);
}

AccessTokenID AccessTokenKit::GetNativeTokenId(const std::string& processName)
{
    if (!DataValidator::IsProcessNameValid(processName)) {
        LOGE(ATM_DOMAIN, ATM_TAG, "ProcessName is invalid, processName=%{public}s", processName.c_str());
        return INVALID_TOKENID;
    }
    return AccessTokenManagerClient::GetInstance().GetNativeTokenId(processName);
}

#ifdef TOKEN_SYNC_ENABLE
int AccessTokenKit::GetHapTokenInfoFromRemote(AccessTokenID tokenID, HapTokenInfoForSync& hapSync)
{
    LOGD(ATM_DOMAIN, ATM_TAG, "TokenID=%{public}d.", tokenID);
    if (tokenID == INVALID_TOKENID) {
        LOGE(ATM_DOMAIN, ATM_TAG, "TokenID is invalid");
        return AccessTokenError::ERR_PARAM_INVALID;
    }

    return AccessTokenManagerClient::GetInstance().GetHapTokenInfoFromRemote(tokenID, hapSync);
}

int AccessTokenKit::SetRemoteHapTokenInfo(const std::string& deviceID,
    const HapTokenInfoForSync& hapSync)
{
    LOGD(ATM_DOMAIN, ATM_TAG, "DeviceID=%{public}s, tokenID=%{public}d.",
        ConstantCommon::EncryptDevId(deviceID).c_str(), hapSync.baseInfo.tokenID);
    return AccessTokenManagerClient::GetInstance().SetRemoteHapTokenInfo(deviceID, hapSync);
}

int AccessTokenKit::DeleteRemoteToken(const std::string& deviceID, AccessTokenID tokenID)
{
    LOGD(ATM_DOMAIN, ATM_TAG, "DeviceID=%{public}s, tokenID=%{public}d.",
        ConstantCommon::EncryptDevId(deviceID).c_str(), tokenID);
    return AccessTokenManagerClient::GetInstance().DeleteRemoteToken(deviceID, tokenID);
}

int AccessTokenKit::DeleteRemoteDeviceTokens(const std::string& deviceID)
{
    LOGD(ATM_DOMAIN, ATM_TAG, "DeviceID=%{public}s.", ConstantCommon::EncryptDevId(deviceID).c_str());
    return AccessTokenManagerClient::GetInstance().DeleteRemoteDeviceTokens(deviceID);
}

AccessTokenID AccessTokenKit::GetRemoteNativeTokenID(const std::string& deviceID, AccessTokenID tokenID)
{
    LOGD(ATM_DOMAIN, ATM_TAG, "DeviceID=%{public}s., tokenID=%{public}d",
        ConstantCommon::EncryptDevId(deviceID).c_str(), tokenID);
    return AccessTokenManagerClient::GetInstance().GetRemoteNativeTokenID(deviceID, tokenID);
}

int32_t AccessTokenKit::RegisterTokenSyncCallback(const std::shared_ptr<TokenSyncKitInterface>& syncCallback)
{
    LOGD(ATM_DOMAIN, ATM_TAG, "Call RegisterTokenSyncCallback.");
    return AccessTokenManagerClient::GetInstance().RegisterTokenSyncCallback(syncCallback);
}

int32_t AccessTokenKit::UnRegisterTokenSyncCallback()
{
    LOGD(ATM_DOMAIN, ATM_TAG, "Call UnRegisterTokenSyncCallback.");
    return AccessTokenManagerClient::GetInstance().UnRegisterTokenSyncCallback();
}
#endif

void AccessTokenKit::DumpTokenInfo(const AtmToolsParamInfo& info, std::string& dumpInfo)
{
    LOGD(ATM_DOMAIN, ATM_TAG, "TokenID=%{public}d, bundleName=%{public}s, processName=%{public}s.",
        info.tokenId, info.bundleName.c_str(), info.processName.c_str());

    AccessTokenManagerClient::GetInstance().DumpTokenInfo(info, dumpInfo);
}

int32_t AccessTokenKit::GetVersion(uint32_t& version)
{
    return AccessTokenManagerClient::GetInstance().GetVersion(version);
}

int32_t AccessTokenKit::SetPermDialogCap(const HapBaseInfo& hapBaseInfo, bool enable)
{
    return AccessTokenManagerClient::GetInstance().SetPermDialogCap(hapBaseInfo, enable);
}

void AccessTokenKit::GetPermissionManagerInfo(PermissionGrantInfo& info)
{
    AccessTokenManagerClient::GetInstance().GetPermissionManagerInfo(info);
}

int32_t AccessTokenKit::SetUserPolicy(const std::vector<UserPermissionPolicy>& userPermissionList)
{
    LOGI(ATM_DOMAIN, ATM_TAG, "Enter.");
    return AccessTokenManagerClient::GetInstance().SetUserPolicy(userPermissionList);
}

int32_t AccessTokenKit::ClearUserPolicy(const std::vector<std::string>& permissionList)
{
    LOGI(ATM_DOMAIN, ATM_TAG, "Enter.");
    return AccessTokenManagerClient::GetInstance().ClearUserPolicy(permissionList);
}

bool AccessTokenKit::IsSystemAppByFullTokenID(uint64_t tokenId)
{
    return (tokenId & SYSTEM_APP_MASK) == SYSTEM_APP_MASK;
}

uint64_t AccessTokenKit::GetRenderTokenID(uint64_t tokenId)
{
    AccessTokenID id = tokenId & TOKEN_ID_LOWMASK;
    if (id == INVALID_TOKENID) {
        LOGE(ATM_DOMAIN, ATM_TAG, "TokenID is invalid");
        return tokenId;
    }
    AccessTokenIDInner* idInner = reinterpret_cast<AccessTokenIDInner*>(&id);
    idInner->renderFlag = 1;

    id = *reinterpret_cast<AccessTokenID*>(idInner);
    return static_cast<uint64_t>(id);
}

int32_t AccessTokenKit::GetKernelPermissions(
    AccessTokenID tokenID, std::vector<PermissionWithValue>& kernelPermList)
{
    LOGI(ATM_DOMAIN, ATM_TAG, "TokenID=%{public}d.", tokenID);
    return AccessTokenManagerClient::GetInstance().GetKernelPermissions(tokenID, kernelPermList);
}

int32_t AccessTokenKit::GetReqPermissionByName(
    AccessTokenID tokenID, const std::string& permissionName, std::string& value)
{
    LOGI(ATM_DOMAIN, ATM_TAG,
        "TokenID=%{public}d permissionName=%{public}s.", tokenID, permissionName.c_str());
    if (!DataValidator::IsPermissionNameValid(permissionName)) {
        LOGE(ATM_DOMAIN, ATM_TAG, "PermissionName is invalid.");
        return AccessTokenError::ERR_PARAM_INVALID;
    }
    return AccessTokenManagerClient::GetInstance().GetReqPermissionByName(tokenID, permissionName, value);
}

#ifdef SECURITY_COMPONENT_ENHANCE_ENABLE
int32_t AccessTokenKit::RegisterSecCompEnhance(const SecCompEnhanceData& enhance)
{
    return AccessTokenManagerClient::GetInstance().RegisterSecCompEnhance(enhance);
}

int32_t AccessTokenKit::UpdateSecCompEnhance(int32_t pid, uint32_t seqNum)
{
    return AccessTokenManagerClient::GetInstance().UpdateSecCompEnhance(pid, seqNum);
}

int32_t AccessTokenKit::GetSecCompEnhance(int32_t pid, SecCompEnhanceData& enhance)
{
    return AccessTokenManagerClient::GetInstance().GetSecCompEnhance(pid, enhance);
}
#endif

bool AccessTokenKit::IsAtomicServiceByFullTokenID(uint64_t tokenId)
{
    LOGI(ATM_DOMAIN, ATM_TAG, "Called, tokenId=%{public}" PRId64, tokenId);
    return (tokenId & ATOMIC_SERVICE_MASK) == ATOMIC_SERVICE_MASK;
}

int32_t AccessTokenKit::SetPermissionStatusWithPolicy(
    uint32_t tokenID, const std::vector<std::string>& permissionList, int32_t status, uint32_t flag)
{
    LOGI(ATM_DOMAIN, ATM_TAG, "TokenID=%{public}d, permList.size=%{public}zu, status=%{public}d, flag=%{public}u.",
        tokenID, permissionList.size(), status, flag);
    if (tokenID == INVALID_TOKENID) {
        LOGE(ATM_DOMAIN, ATM_TAG, "tokenID: %{public}d, TokenID is invalid.", tokenID);
        return AccessTokenError::ERR_PARAM_INVALID;
    }
    if (permissionList.empty()) {
        LOGE(ATM_DOMAIN, ATM_TAG, "PermissionList is empty.");
        return AccessTokenError::ERR_PARAM_INVALID;
    }
    for (const auto& perm : permissionList) {
        if (!DataValidator::IsPermissionNameValid(perm)) {
            LOGE(ATM_DOMAIN, ATM_TAG, "PermissionName is invalid: %{public}s.", perm.c_str());
            return AccessTokenError::ERR_PARAM_INVALID;
        }
    }
    if (!DataValidator::IsPermissionStatusValid(status)) {
        LOGE(ATM_DOMAIN, ATM_TAG, "Status: %{public}d, status is invalid.", status);
        return AccessTokenError::ERR_PARAM_INVALID;
    }
    if (!DataValidator::IsPermissionFlagValidForAdmin(flag)) {
        LOGE(ATM_DOMAIN, ATM_TAG, "Flag: %{public}u, flag is invalid.", flag);
        return AccessTokenError::ERR_PARAM_INVALID;
    }
    if (!DataValidator::IsPermissionListSizeValid(permissionList)) {
        LOGE(ATM_DOMAIN, ATM_TAG, "PermissionList size is invalid: %{public}zu.", permissionList.size());
        return AccessTokenError::ERR_PARAM_INVALID;
    }
    return AccessTokenManagerClient::GetInstance().SetPermissionStatusWithPolicy(tokenID, permissionList, status, flag);
}
} // namespace AccessToken
} // namespace Security
} // namespace OHOS
