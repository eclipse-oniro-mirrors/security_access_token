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

#include "accesstoken_manager_service.h"

#include <unistd.h>

#include "access_token.h"
#include "access_token_error.h"
#include "accesstoken_config_policy.h"
#include "accesstoken_dfx_define.h"
#include "accesstoken_id_manager.h"
#include "accesstoken_info_manager.h"
#include "accesstoken_log.h"
#include "constant_common.h"
#ifdef SUPPORT_SANDBOX_APP
#include "dlp_permission_set_parser.h"
#endif
#include "hap_token_info.h"
#include "hap_token_info_inner.h"
#include "hisysevent.h"
#ifdef HITRACE_NATIVE_ENABLE
#include "hitrace_meter.h"
#endif
#include "ipc_skeleton.h"
#include "native_token_info_inner.h"
#include "native_token_receptor.h"
#include "parameter.h"
#include "permission_list_state.h"
#include "permission_manager.h"
#ifndef COMMON_EVENT_SERVICE_ENABLE
#include "privacy_kit.h"
#endif // COMMON_EVENT_SERVICE_ENABLE
#include "string_ex.h"
#include "system_ability_definition.h"
#include "permission_definition_parser.h"
#include "time_util.h"
#ifdef TOKEN_SYNC_ENABLE
#include "token_modify_notifier.h"
#endif // TOKEN_SYNC_ENABLE

namespace OHOS {
namespace Security {
namespace AccessToken {
namespace {
static constexpr OHOS::HiviewDFX::HiLogLabel LABEL = {
    LOG_CORE, SECURITY_DOMAIN_ACCESSTOKEN, "ATMServ"
};
static const char* ACCESS_TOKEN_SERVICE_INIT_KEY = "accesstoken.permission.init";
constexpr int TWO_ARGS = 2;
const std::string GRANT_ABILITY_BUNDLE_NAME = "com.ohos.permissionmanager";
const std::string GRANT_ABILITY_ABILITY_NAME = "com.ohos.permissionmanager.GrantAbility";
static const std::string ACCESSTOKEN_PROCESS_NAME = "accesstoken_service";
static constexpr char ADD_DOMAIN[] = "PERFORMANCE";
}

const bool REGISTER_RESULT =
    SystemAbility::MakeAndRegisterAbility(DelayedSingleton<AccessTokenManagerService>::GetInstance().get());

AccessTokenManagerService::AccessTokenManagerService()
    : SystemAbility(SA_ID_ACCESSTOKEN_MANAGER_SERVICE, true), state_(ServiceRunningState::STATE_NOT_START)
{
    ACCESSTOKEN_LOG_INFO(LABEL, "AccessTokenManagerService()");
}

AccessTokenManagerService::~AccessTokenManagerService()
{
    ACCESSTOKEN_LOG_INFO(LABEL, "~AccessTokenManagerService()");
}

void AccessTokenManagerService::OnStart()
{
    if (state_ == ServiceRunningState::STATE_RUNNING) {
        ACCESSTOKEN_LOG_INFO(LABEL, "AccessTokenManagerService has already started!");
        return;
    }
    ACCESSTOKEN_LOG_INFO(LABEL, "AccessTokenManagerService is starting");
    if (!Initialize()) {
        ACCESSTOKEN_LOG_ERROR(LABEL, "Failed to initialize");
        return;
    }
    state_ = ServiceRunningState::STATE_RUNNING;
    bool ret = Publish(DelayedSingleton<AccessTokenManagerService>::GetInstance().get());
    if (!ret) {
        ACCESSTOKEN_LOG_ERROR(LABEL, "Failed to publish service!");
        return;
    }
    (void)AddSystemAbilityListener(SECURITY_COMPONENT_SERVICE_ID);
    ACCESSTOKEN_LOG_INFO(LABEL, "Congratulations, AccessTokenManagerService start successfully!");
}

void AccessTokenManagerService::OnStop()
{
    ACCESSTOKEN_LOG_INFO(LABEL, "Stop service.");
    state_ = ServiceRunningState::STATE_NOT_START;
}

void AccessTokenManagerService::OnRemoveSystemAbility(int32_t systemAbilityId, const std::string& deviceId)
{
    if (systemAbilityId == SECURITY_COMPONENT_SERVICE_ID) {
        std::vector<AccessTokenID> tokenIdList;
        AccessTokenIDManager::GetInstance().GetHapTokenIdList(tokenIdList);
        PermissionManager::GetInstance().ClearAllSecCompGrantedPerm(tokenIdList);
        return;
    }
}

PermUsedTypeEnum AccessTokenManagerService::GetUserGrantedPermissionUsedType(
    AccessTokenID tokenID, const std::string& permissionName)
{
    ACCESSTOKEN_LOG_INFO(LABEL, "TokenID=%{public}d, permission=%{public}s", tokenID, permissionName.c_str());
    return PermissionManager::GetInstance().GetUserGrantedPermissionUsedType(tokenID, permissionName);
}

int AccessTokenManagerService::VerifyAccessToken(AccessTokenID tokenID, const std::string& permissionName)
{
#ifdef HITRACE_NATIVE_ENABLE
    StartTrace(HITRACE_TAG_ACCESS_CONTROL, "AccessTokenVerifyPermission");
#endif
    int32_t res = PermissionManager::GetInstance().VerifyAccessToken(tokenID, permissionName);
    ACCESSTOKEN_LOG_DEBUG(LABEL, "tokenID: %{public}d, permission: %{public}s, res %{public}d",
        tokenID, permissionName.c_str(), res);
#ifdef HITRACE_NATIVE_ENABLE
    FinishTrace(HITRACE_TAG_ACCESS_CONTROL);
#endif
    return res;
}

int AccessTokenManagerService::GetDefPermission(
    const std::string& permissionName, PermissionDefParcel& permissionDefResult)
{
    ACCESSTOKEN_LOG_INFO(LABEL, "permission: %{public}s", permissionName.c_str());
    return PermissionManager::GetInstance().GetDefPermission(permissionName, permissionDefResult.permissionDef);
}

int AccessTokenManagerService::GetDefPermissions(AccessTokenID tokenID, std::vector<PermissionDefParcel>& permList)
{
    ACCESSTOKEN_LOG_INFO(LABEL, "tokenID: %{public}d", tokenID);
    std::vector<PermissionDef> permVec;
    int ret = PermissionManager::GetInstance().GetDefPermissions(tokenID, permVec);
    for (const auto& perm : permVec) {
        PermissionDefParcel permParcel;
        permParcel.permissionDef = perm;
        permList.emplace_back(permParcel);
    }
    return ret;
}

int AccessTokenManagerService::GetReqPermissions(
    AccessTokenID tokenID, std::vector<PermissionStateFullParcel>& reqPermList, bool isSystemGrant)
{
    ACCESSTOKEN_LOG_DEBUG(LABEL, "tokenID: %{public}d, isSystemGrant: %{public}d", tokenID, isSystemGrant);

    std::vector<PermissionStateFull> permList;
    int ret = PermissionManager::GetInstance().GetReqPermissions(tokenID, permList, isSystemGrant);

    for (const auto& perm : permList) {
        PermissionStateFullParcel permParcel;
        permParcel.permStatFull = perm;
        reqPermList.emplace_back(permParcel);
    }
    return ret;
}

PermissionOper AccessTokenManagerService::GetSelfPermissionsState(std::vector<PermissionListStateParcel>& reqPermList,
    PermissionGrantInfoParcel& infoParcel)
{
    infoParcel.info.grantBundleName = grantBundleName_;
    infoParcel.info.grantAbilityName = grantAbilityName_;
    AccessTokenID callingTokenID = IPCSkeleton::GetCallingTokenID();
    return GetPermissionsState(callingTokenID, reqPermList);
}

int32_t AccessTokenManagerService::GetPermissionsStatus(AccessTokenID tokenID,
    std::vector<PermissionListStateParcel>& reqPermList)
{
    if (!AccessTokenInfoManager::GetInstance().IsTokenIdExist(tokenID)) {
        ACCESSTOKEN_LOG_ERROR(LABEL, "tokenID=%{public}d does not exist", tokenID);
        return ERR_TOKENID_NOT_EXIST;
    }
    PermissionOper ret = GetPermissionsState(tokenID, reqPermList);
    return ret == INVALID_OPER ? RET_FAILED : RET_SUCCESS;
}

PermissionOper AccessTokenManagerService::GetPermissionsState(AccessTokenID tokenID,
    std::vector<PermissionListStateParcel>& reqPermList)
{
    int32_t apiVersion = 0;
    if (!PermissionManager::GetInstance().GetApiVersionByTokenId(tokenID, apiVersion)) {
        ACCESSTOKEN_LOG_ERROR(LABEL, "get api version error");
        return INVALID_OPER;
    }
    ACCESSTOKEN_LOG_INFO(LABEL, "tokenID: %{public}d, apiVersion: %{public}d", tokenID, apiVersion);

    bool needRes = false;
    std::vector<PermissionStateFull> permsList;
    int retUserGrant = PermissionManager::GetInstance().GetReqPermissions(tokenID, permsList, false);
    int retSysGrant = PermissionManager::GetInstance().GetReqPermissions(tokenID, permsList, true);
    if ((retSysGrant != RET_SUCCESS) || (retUserGrant != RET_SUCCESS)) {
        ACCESSTOKEN_LOG_ERROR(LABEL,
            "GetReqPermissions failed, retUserGrant:%{public}d, retSysGrant:%{public}d",
            retUserGrant, retSysGrant);
        return INVALID_OPER;
    }

    // api9 location permission handle here
    if (apiVersion >= ACCURATE_LOCATION_API_VERSION) {
        needRes = PermissionManager::GetInstance().LocationPermissionSpecialHandle(reqPermList, permsList, apiVersion);
    }

    uint32_t size = reqPermList.size();
    for (uint32_t i = 0; i < size; i++) {
        // api9 location permission special handle above
        if (((reqPermList[i].permsState.permissionName == VAGUE_LOCATION_PERMISSION_NAME) ||
            (reqPermList[i].permsState.permissionName == ACCURATE_LOCATION_PERMISSION_NAME) ||
            (reqPermList[i].permsState.permissionName == BACKGROUND_LOCATION_PERMISSION_NAME)) &&
            (apiVersion >= ACCURATE_LOCATION_API_VERSION)) {
            continue;
        }

        PermissionManager::GetInstance().GetSelfPermissionState(permsList, reqPermList[i].permsState, apiVersion);
        if (static_cast<PermissionOper>(reqPermList[i].permsState.state) == DYNAMIC_OPER) {
            needRes = true;
        }
        ACCESSTOKEN_LOG_DEBUG(LABEL, "perm: 0x%{public}s, state: 0x%{public}d",
            reqPermList[i].permsState.permissionName.c_str(), reqPermList[i].permsState.state);
    }
    if (GetTokenType(tokenID) == TOKEN_HAP && AccessTokenInfoManager::GetInstance().GetPermDialogCap(tokenID)) {
        ACCESSTOKEN_LOG_ERROR(LABEL, "tokenID=%{public}d is under control", tokenID);
        uint32_t size = reqPermList.size();
        for (uint32_t i = 0; i < size; i++) {
            if (reqPermList[i].permsState.state != INVALID_OPER) {
                reqPermList[i].permsState.state = FORBIDDEN_OPER;
            }
        }
        return FORBIDDEN_OPER;
    }
    if (needRes) {
        return DYNAMIC_OPER;
    }
    return PASS_OPER;
}

int AccessTokenManagerService::GetPermissionFlag(
    AccessTokenID tokenID, const std::string& permissionName, uint32_t& flag)
{
    ACCESSTOKEN_LOG_INFO(LABEL, "tokenID: %{public}d, permission: %{public}s",
        tokenID, permissionName.c_str());
    return PermissionManager::GetInstance().GetPermissionFlag(tokenID, permissionName, flag);
}

int32_t AccessTokenManagerService::SetPermissionRequestToggleStatus(
    const std::string& permissionName, uint32_t status, int32_t userID = 0)
{
    ACCESSTOKEN_LOG_INFO(LABEL, "Permission=%{public}s, status=%{public}d, userID=%{public}d",
        permissionName.c_str(), status, userID);
    return PermissionManager::GetInstance().SetPermissionRequestToggleStatus(permissionName, status, userID);
}

int32_t AccessTokenManagerService::GetPermissionRequestToggleStatus(
    const std::string& permissionName, uint32_t& status, int32_t userID = 0)
{
    ACCESSTOKEN_LOG_INFO(LABEL, "Permission=%{public}s, userID=%{public}d", permissionName.c_str(), userID);
    return PermissionManager::GetInstance().GetPermissionRequestToggleStatus(permissionName, status, userID);
}

int AccessTokenManagerService::GrantPermission(AccessTokenID tokenID, const std::string& permissionName, uint32_t flag)
{
    ACCESSTOKEN_LOG_INFO(LABEL, "tokenID: %{public}d, permission: %{public}s, flag: %{public}d",
        tokenID, permissionName.c_str(), flag);
    int32_t ret = PermissionManager::GetInstance().GrantPermission(tokenID, permissionName, flag);
    DumpTokenIfNeeded();
    return ret;
}

int AccessTokenManagerService::RevokePermission(AccessTokenID tokenID, const std::string& permissionName, uint32_t flag)
{
    ACCESSTOKEN_LOG_INFO(LABEL, "tokenID: %{public}d, permission: %{public}s, flag: %{public}d",
        tokenID, permissionName.c_str(), flag);
    int32_t ret = PermissionManager::GetInstance().RevokePermission(tokenID, permissionName, flag);
    DumpTokenIfNeeded();
    return ret;
}

int AccessTokenManagerService::ClearUserGrantedPermissionState(AccessTokenID tokenID)
{
    ACCESSTOKEN_LOG_INFO(LABEL, "tokenID: %{public}d", tokenID);
    PermissionManager::GetInstance().ClearUserGrantedPermissionState(tokenID);
    AccessTokenInfoManager::GetInstance().SetPermDialogCap(tokenID, false);
    AccessTokenInfoManager::GetInstance().RefreshTokenInfoIfNeeded();
    DumpTokenIfNeeded();
    return RET_SUCCESS;
}

int32_t AccessTokenManagerService::RegisterPermStateChangeCallback(
    const PermStateChangeScopeParcel& scope, const sptr<IRemoteObject>& callback)
{
    ACCESSTOKEN_LOG_INFO(LABEL, "Entry");
    return PermissionManager::GetInstance().AddPermStateChangeCallback(scope.scope, callback);
}

int32_t AccessTokenManagerService::UnRegisterPermStateChangeCallback(const sptr<IRemoteObject>& callback)
{
    ACCESSTOKEN_LOG_INFO(LABEL, "Entry");
    return PermissionManager::GetInstance().RemovePermStateChangeCallback(callback);
}

AccessTokenIDEx AccessTokenManagerService::AllocHapToken(const HapInfoParcel& info, const HapPolicyParcel& policy)
{
    ACCESSTOKEN_LOG_INFO(LABEL, "bundleName: %{public}s", info.hapInfoParameter.bundleName.c_str());
    AccessTokenIDEx tokenIdEx;
    tokenIdEx.tokenIDEx = 0LL;

    int ret = AccessTokenInfoManager::GetInstance().CreateHapTokenInfo(
        info.hapInfoParameter, policy.hapPolicyParameter, tokenIdEx);
    if (ret != RET_SUCCESS) {
        ACCESSTOKEN_LOG_ERROR(LABEL, "hap token info create failed");
    }
    DumpTokenIfNeeded();
    return tokenIdEx;
}

int32_t AccessTokenManagerService::InitHapToken(
    const HapInfoParcel& info, HapPolicyParcel& policy, AccessTokenIDEx& fullTokenId)
{
    ACCESSTOKEN_LOG_INFO(LABEL, "Init hap %{public}s.", info.hapInfoParameter.bundleName.c_str());
    std::vector<PermissionStateFull> initializedList;
    if (info.hapInfoParameter.dlpType == DLP_COMMON) {
        if (!PermissionManager::GetInstance().InitPermissionList(info.hapInfoParameter.appDistributionType,
            policy.hapPolicyParameter, initializedList)) {
            return ERR_PERM_REQUEST_CFG_FAILED;
        }
    } else {
        if (!PermissionManager::GetInstance().InitDlpPermissionList(
            info.hapInfoParameter.bundleName, info.hapInfoParameter.userID, initializedList)) {
            return ERR_PERM_REQUEST_CFG_FAILED;
        }
    }
    policy.hapPolicyParameter.permStateList = initializedList;

    int32_t ret = AccessTokenInfoManager::GetInstance().CreateHapTokenInfo(
        info.hapInfoParameter, policy.hapPolicyParameter, fullTokenId);
    if (ret != RET_SUCCESS) {
        ACCESSTOKEN_LOG_ERROR(LABEL, "Hap token info create failed.");
        return ret;
    }

    DumpTokenIfNeeded();
    return ret;
}

int AccessTokenManagerService::DeleteToken(AccessTokenID tokenID)
{
    ACCESSTOKEN_LOG_INFO(LABEL, "tokenID: %{public}d", tokenID);
#ifndef COMMON_EVENT_SERVICE_ENABLE
    PrivacyKit::RemovePermissionUsedRecords(tokenID, "");
#endif // COMMON_EVENT_SERVICE_ENABLE
    // only support hap token deletion
    int ret = AccessTokenInfoManager::GetInstance().RemoveHapTokenInfo(tokenID);
    DumpTokenIfNeeded();
    return ret;
}

int AccessTokenManagerService::GetTokenType(AccessTokenID tokenID)
{
    ACCESSTOKEN_LOG_DEBUG(LABEL, "tokenID: %{public}d", tokenID);
    return AccessTokenIDManager::GetInstance().GetTokenIdType(tokenID);
}

int AccessTokenManagerService::CheckNativeDCap(AccessTokenID tokenID, const std::string& dcap)
{
    ACCESSTOKEN_LOG_INFO(LABEL, "tokenID: %{public}d, dcap: %{public}s",
        tokenID, dcap.c_str());
    return AccessTokenInfoManager::GetInstance().CheckNativeDCap(tokenID, dcap);
}

AccessTokenIDEx AccessTokenManagerService::GetHapTokenID(
    int32_t userID, const std::string& bundleName, int32_t instIndex)
{
    ACCESSTOKEN_LOG_DEBUG(LABEL, "userID: %{public}d, bundle: %{public}s, instIndex: %{public}d",
        userID, bundleName.c_str(), instIndex);
    return AccessTokenInfoManager::GetInstance().GetHapTokenID(userID, bundleName, instIndex);
}

AccessTokenID AccessTokenManagerService::AllocLocalTokenID(
    const std::string& remoteDeviceID, AccessTokenID remoteTokenID)
{
    ACCESSTOKEN_LOG_INFO(LABEL, "remoteDeviceID: %{public}s, remoteTokenID: %{public}d",
        ConstantCommon::EncryptDevId(remoteDeviceID).c_str(), remoteTokenID);
    AccessTokenID tokenID = AccessTokenInfoManager::GetInstance().AllocLocalTokenID(remoteDeviceID, remoteTokenID);
    DumpTokenIfNeeded();
    return tokenID;
}

int32_t AccessTokenManagerService::UpdateHapToken(AccessTokenIDEx& tokenIdEx,
    const UpdateHapInfoParams& info, const HapPolicyParcel& policyParcel)
{
    ACCESSTOKEN_LOG_INFO(LABEL, "tokenID: %{public}d", tokenIdEx.tokenIdExStruct.tokenID);
    std::vector<PermissionStateFull> InitializedList;
    if (!PermissionManager::GetInstance().InitPermissionList(
        info.appDistributionType, policyParcel.hapPolicyParameter, InitializedList)) {
        return ERR_PERM_REQUEST_CFG_FAILED;
    }
    int32_t ret = AccessTokenInfoManager::GetInstance().UpdateHapToken(tokenIdEx, info,
        InitializedList, policyParcel.hapPolicyParameter.apl, policyParcel.hapPolicyParameter.permList);
    DumpTokenIfNeeded();
    return ret;
}

int AccessTokenManagerService::GetHapTokenInfo(AccessTokenID tokenID, HapTokenInfoParcel& infoParcel)
{
    ACCESSTOKEN_LOG_DEBUG(LABEL, "tokenID: %{public}d", tokenID);

    return AccessTokenInfoManager::GetInstance().GetHapTokenInfo(tokenID, infoParcel.hapTokenInfoParams);
}

int AccessTokenManagerService::GetNativeTokenInfo(AccessTokenID tokenID, NativeTokenInfoParcel& infoParcel)
{
    ACCESSTOKEN_LOG_DEBUG(LABEL, "tokenID: %{public}d", tokenID);

    return AccessTokenInfoManager::GetInstance().GetNativeTokenInfo(tokenID, infoParcel.nativeTokenInfoParams);
}

#ifndef ATM_BUILD_VARIANT_USER_ENABLE
int32_t AccessTokenManagerService::ReloadNativeTokenInfo()
{
    int32_t ret = NativeTokenReceptor::GetInstance().Init();
    DumpTokenIfNeeded();
    return ret;
}
#endif

AccessTokenID AccessTokenManagerService::GetNativeTokenId(const std::string& processName)
{
    return AccessTokenInfoManager::GetInstance().GetNativeTokenId(processName);
}

#ifdef TOKEN_SYNC_ENABLE
int AccessTokenManagerService::GetHapTokenInfoFromRemote(AccessTokenID tokenID,
    HapTokenInfoForSyncParcel& hapSyncParcel)
{
    ACCESSTOKEN_LOG_INFO(LABEL, "tokenID: %{public}d", tokenID);

    return AccessTokenInfoManager::GetInstance().GetHapTokenInfoFromRemote(tokenID,
        hapSyncParcel.hapTokenInfoForSyncParams);
}

int AccessTokenManagerService::GetAllNativeTokenInfo(std::vector<NativeTokenInfoForSyncParcel>& nativeTokenInfosRes)
{
    ACCESSTOKEN_LOG_INFO(LABEL, "called");

    std::vector<NativeTokenInfoForSync> nativeVec;
    AccessTokenInfoManager::GetInstance().GetAllNativeTokenInfo(nativeVec);
    for (const auto& native : nativeVec) {
        NativeTokenInfoForSyncParcel nativeParcel;
        nativeParcel.nativeTokenInfoForSyncParams = native;
        nativeTokenInfosRes.emplace_back(nativeParcel);
    }

    return RET_SUCCESS;
}

int AccessTokenManagerService::SetRemoteHapTokenInfo(const std::string& deviceID,
    HapTokenInfoForSyncParcel& hapSyncParcel)
{
    ACCESSTOKEN_LOG_INFO(LABEL, "deviceID: %{public}s", ConstantCommon::EncryptDevId(deviceID).c_str());
    int ret = AccessTokenInfoManager::GetInstance().SetRemoteHapTokenInfo(deviceID,
        hapSyncParcel.hapTokenInfoForSyncParams);
    DumpTokenIfNeeded();
    return ret;
}

int AccessTokenManagerService::SetRemoteNativeTokenInfo(const std::string& deviceID,
    std::vector<NativeTokenInfoForSyncParcel>& nativeTokenInfoForSyncParcel)
{
    ACCESSTOKEN_LOG_INFO(LABEL, "deviceID: %{public}s", ConstantCommon::EncryptDevId(deviceID).c_str());

    std::vector<NativeTokenInfoForSync> nativeList;
    std::transform(nativeTokenInfoForSyncParcel.begin(),
        nativeTokenInfoForSyncParcel.end(), std::back_inserter(nativeList),
        [](const auto& nativeParcel) { return nativeParcel.nativeTokenInfoForSyncParams; });
    int ret = AccessTokenInfoManager::GetInstance().SetRemoteNativeTokenInfo(deviceID, nativeList);
    DumpTokenIfNeeded();
    return ret;
}

int AccessTokenManagerService::DeleteRemoteToken(const std::string& deviceID, AccessTokenID tokenID)
{
    ACCESSTOKEN_LOG_INFO(LABEL, "deviceID: %{public}s, token id %{public}d",
        ConstantCommon::EncryptDevId(deviceID).c_str(), tokenID);
    int ret = AccessTokenInfoManager::GetInstance().DeleteRemoteToken(deviceID, tokenID);
    DumpTokenIfNeeded();
    return ret;
}

AccessTokenID AccessTokenManagerService::GetRemoteNativeTokenID(const std::string& deviceID,
    AccessTokenID tokenID)
{
    ACCESSTOKEN_LOG_INFO(LABEL, "deviceID: %{public}s, token id %{public}d",
        ConstantCommon::EncryptDevId(deviceID).c_str(), tokenID);

    return AccessTokenInfoManager::GetInstance().GetRemoteNativeTokenID(deviceID, tokenID);
}

int AccessTokenManagerService::DeleteRemoteDeviceTokens(const std::string& deviceID)
{
    ACCESSTOKEN_LOG_INFO(LABEL, "deviceID: %{public}s", ConstantCommon::EncryptDevId(deviceID).c_str());
    int ret = AccessTokenInfoManager::GetInstance().DeleteRemoteDeviceTokens(deviceID);
    DumpTokenIfNeeded();
    return ret;
}

int32_t AccessTokenManagerService::RegisterTokenSyncCallback(const sptr<IRemoteObject>& callback)
{
    ACCESSTOKEN_LOG_INFO(LABEL, "Call token sync callback registed.");
    return TokenModifyNotifier::GetInstance().RegisterTokenSyncCallback(callback);
}

int32_t AccessTokenManagerService::UnRegisterTokenSyncCallback()
{
    ACCESSTOKEN_LOG_INFO(LABEL, "Call token sync callback unregisted.");
    return TokenModifyNotifier::GetInstance().UnRegisterTokenSyncCallback();
}
#endif

void AccessTokenManagerService::DumpTokenInfo(const AtmToolsParamInfoParcel& infoParcel, std::string& dumpInfo)
{
    ACCESSTOKEN_LOG_INFO(LABEL, "called");

    AccessTokenInfoManager::GetInstance().DumpTokenInfo(infoParcel.info, dumpInfo);
}

int32_t AccessTokenManagerService::DumpPermDefInfo(std::string& dumpInfo)
{
    ACCESSTOKEN_LOG_INFO(LABEL, "called");

    return PermissionManager::GetInstance().DumpPermDefInfo(dumpInfo);
}

int32_t AccessTokenManagerService::GetVersion(uint32_t& version)
{
    ACCESSTOKEN_LOG_INFO(LABEL, "called");
    version = DEFAULT_TOKEN_VERSION;
    return RET_SUCCESS;
}

int32_t AccessTokenManagerService::SetPermDialogCap(const HapBaseInfoParcel& hapBaseInfoParcel, bool enable)
{
    AccessTokenIDEx tokenIdEx = AccessTokenInfoManager::GetInstance().GetHapTokenID(
        hapBaseInfoParcel.hapBaseInfo.userID,
        hapBaseInfoParcel.hapBaseInfo.bundleName,
        hapBaseInfoParcel.hapBaseInfo.instIndex);

    return AccessTokenInfoManager::GetInstance().SetPermDialogCap(tokenIdEx.tokenIdExStruct.tokenID, enable);
}

int AccessTokenManagerService::Dump(int fd, const std::vector<std::u16string>& args)
{
    if (fd < 0) {
        return ERR_INVALID_VALUE;
    }

    dprintf(fd, "AccessToken Dump:\n");
    std::string arg0 = ((args.size() == 0)? "" : Str16ToStr8(args.at(0)));
    if (arg0.compare("-h") == 0) {
        dprintf(fd, "Usage:\n");
        dprintf(fd, "       -h: command help\n");
        dprintf(fd, "       -a: dump all tokens\n");
        dprintf(fd, "       -t <TOKEN_ID>: dump special token id\n");
    } else if (arg0.compare("-t") == 0) {
        if (args.size() < TWO_ARGS) {
            return ERR_INVALID_VALUE;
        }
        long long tokenID = atoll(static_cast<const char *>(Str16ToStr8(args.at(1)).c_str()));
        if (tokenID <= 0) {
            return ERR_INVALID_VALUE;
        }
        AtmToolsParamInfoParcel infoParcel;
        infoParcel.info.tokenId = static_cast<AccessTokenID>(tokenID);
        std::string dumpStr;
        DumpTokenInfo(infoParcel, dumpStr);
        dprintf(fd, "%s\n", dumpStr.c_str());
    }  else if (arg0.compare("-a") == 0 || arg0 == "") {
        std::string dumpStr;
        AtmToolsParamInfoParcel infoParcel;
        DumpTokenInfo(infoParcel, dumpStr);
        dprintf(fd, "%s\n", dumpStr.c_str());
    }
    return ERR_OK;
}

void AccessTokenManagerService::DumpTokenIfNeeded()
{
#ifdef EVENTHANDLER_ENABLE
    if (AccessTokenInfoManager::GetInstance().GetCurDumpTaskNum() > 1) {
        ACCESSTOKEN_LOG_INFO(LABEL, "has refresh task!");
        return;
    }
    AccessTokenInfoManager::GetInstance().AddDumpTaskNum();
    if (dumpEventHandler_ == nullptr) {
        ACCESSTOKEN_LOG_ERROR(LABEL, "Fail to get EventHandler.");
        AccessTokenInfoManager::GetInstance().ReduceDumpTaskNum();
        return;
    }

    std::function<void()> delayed = ([]() {
        AccessTokenInfoManager::GetInstance().DumpToken();
        ACCESSTOKEN_LOG_INFO(LABEL, "Dump token end.");
        // Sleep for one minute to avoid frequent refresh of the file.
        std::this_thread::sleep_for(std::chrono::minutes(1));
        AccessTokenInfoManager::GetInstance().ReduceDumpTaskNum();
    });

    dumpEventHandler_->ProxyPostTask(delayed);
#endif
}

void AccessTokenManagerService::AccessTokenServiceParamSet() const
{
    int32_t res = SetParameter(ACCESS_TOKEN_SERVICE_INIT_KEY, std::to_string(1).c_str());
    if (res != 0) {
        ACCESSTOKEN_LOG_ERROR(LABEL, "SetParameter ACCESS_TOKEN_SERVICE_INIT_KEY failed %{public}d", res);
    }
    ACCESSTOKEN_LOG_INFO(LABEL, "SetParameter ACCESS_TOKEN_SERVICE_INIT_KEY success");
}

void AccessTokenManagerService::SetDefaultConfigValue()
{
    ACCESSTOKEN_LOG_INFO(LABEL, "no config file or config file is not valid, use default values");

    grantBundleName_ = GRANT_ABILITY_BUNDLE_NAME;
    grantAbilityName_ = GRANT_ABILITY_ABILITY_NAME;
}

void AccessTokenManagerService::GetConfigValue()
{
    AccessTokenConfigPolicy policy;
    AccessTokenConfigValue value;
    if (policy.GetConfigValue(ServiceType::ACCESSTOKEN_SERVICE, value)) {
        // set value from config
        grantBundleName_ = value.atConfig.grantBundleName;
        grantAbilityName_ = value.atConfig.grantAbilityName;
    } else {
        SetDefaultConfigValue();
    }

    ACCESSTOKEN_LOG_INFO(LABEL, "grantBundleName_ is %{public}s, grantAbilityName_ is %{public}s",
        grantBundleName_.c_str(), grantAbilityName_.c_str());
}

bool AccessTokenManagerService::Initialize()
{
    // accesstoken_service add CPU_SCENE_ENTRY system event in OnStart, avoid CPU statistics
    long id = 1 << 0; // first scene
    int64_t time = TimeUtil::GetCurrentTimestamp();

    HiSysEventWrite(ADD_DOMAIN, "CPU_SCENE_ENTRY", HiviewDFX::HiSysEvent::EventType::BEHAVIOR,
        "PACKAGE_NAME", ACCESSTOKEN_PROCESS_NAME, "SCENE_ID", std::to_string(id).c_str(), "HAPPEN_TIME", time);
    AccessTokenInfoManager::GetInstance().Init();
    NativeTokenReceptor::GetInstance().Init();

#ifdef EVENTHANDLER_ENABLE
    eventRunner_ = AppExecFwk::EventRunner::Create(true);
    if (!eventRunner_) {
        ACCESSTOKEN_LOG_ERROR(LABEL, "failed to create a recvRunner.");
        return false;
    }
    dumpEventRunner_ = AppExecFwk::EventRunner::Create(true);
    if (!dumpEventRunner_) {
        ACCESSTOKEN_LOG_ERROR(LABEL, "failed to create a recvRunner.");
        return false;
    }
    eventHandler_ = std::make_shared<AccessEventHandler>(eventRunner_);
    dumpEventHandler_ = std::make_shared<AccessEventHandler>(dumpEventRunner_);
    TempPermissionObserver::GetInstance().InitEventHandler(eventHandler_);
#endif

#ifdef SUPPORT_SANDBOX_APP
    DlpPermissionSetParser::GetInstance().Init();
#endif
    HiSysEventWrite(HiviewDFX::HiSysEvent::Domain::ACCESS_TOKEN, "PERMISSION_CHECK_EVENT",
        HiviewDFX::HiSysEvent::EventType::BEHAVIOR, "CODE", ACCESS_TOKEN_SERVICE_INIT_EVENT,
        "PID_INFO", getpid());
    PermissionDefinitionParser::GetInstance().Init();
    AccessTokenServiceParamSet();
    GetConfigValue();
    ACCESSTOKEN_LOG_INFO(LABEL, "Initialize success");
    return true;
}
} // namespace AccessToken
} // namespace Security
} // namespace OHOS
