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

#include "accesstoken_manager_service.h"

#include <algorithm>
#include <sys/types.h>
#include <thread>
#include <unistd.h>

#include "access_token.h"
#include "accesstoken_dfx_define.h"
#include "accesstoken_id_manager.h"
#include "accesstoken_info_manager.h"
#include "accesstoken_log.h"
#ifdef TOKEN_SYNC_ENABLE
#include "atm_device_state_callback.h"
#include "device_manager.h"
#endif
#include "constant_common.h"
#ifdef SUPPORT_SANDBOX_APP
#include "dlp_permission_set_parser.h"
#endif
#include "hap_token_info.h"
#include "hap_token_info_inner.h"
#include "hisysevent.h"
#include "hitrace_meter.h"
#include "ipc_skeleton.h"
#include "native_token_info_inner.h"
#include "native_token_receptor.h"
#include "permission_list_state.h"
#include "permission_manager.h"
#include "privacy_kit.h"
#include "string_ex.h"

namespace OHOS {
namespace Security {
namespace AccessToken {
namespace {
static constexpr OHOS::HiviewDFX::HiLogLabel LABEL = {
    LOG_CORE, SECURITY_DOMAIN_ACCESSTOKEN, "ATMServ"
};
static const std::string ACCESS_TOKEN_PACKAGE_NAME = "ohos.security.distributed_token_sync";
constexpr int TWO_ARGS = 2;
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
    ACCESSTOKEN_LOG_INFO(LABEL, "Congratulations, AccessTokenManagerService start successfully!");
}

void AccessTokenManagerService::OnStop()
{
    ACCESSTOKEN_LOG_INFO(LABEL, "stop service");
    state_ = ServiceRunningState::STATE_NOT_START;
#ifdef TOKEN_SYNC_ENABLE
    DestroyDeviceListener();
#endif
}

int AccessTokenManagerService::VerifyAccessToken(AccessTokenID tokenID, const std::string& permissionName)
{
    StartTrace(HITRACE_TAG_ACCESS_CONTROL, "AccessTokenVerifyPermission");
    int32_t res = PermissionManager::GetInstance().VerifyAccessToken(tokenID, permissionName);
    ACCESSTOKEN_LOG_DEBUG(LABEL, "tokenID: %{public}d, permission: %{public}s, res %{public}d",
        tokenID, permissionName.c_str(), res);
    FinishTrace(HITRACE_TAG_ACCESS_CONTROL);
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
    ACCESSTOKEN_LOG_INFO(LABEL, "tokenID: 0x%{public}x", tokenID);
    std::vector<PermissionDef> permVec;
    int ret = PermissionManager::GetInstance().GetDefPermissions(tokenID, permVec);
    for (const auto& perm : permVec) {
        PermissionDefParcel permPrcel;
        permPrcel.permissionDef = perm;
        permList.emplace_back(permPrcel);
    }
    return ret;
}

int AccessTokenManagerService::GetReqPermissions(
    AccessTokenID tokenID, std::vector<PermissionStateFullParcel>& reqPermList, bool isSystemGrant)
{
    ACCESSTOKEN_LOG_INFO(LABEL, "tokenID: 0x%{public}x, isSystemGrant: %{public}d", tokenID, isSystemGrant);

    std::vector<PermissionStateFull> permList;
    int ret = PermissionManager::GetInstance().GetReqPermissions(tokenID, permList, isSystemGrant);

    for (const auto& perm : permList) {
        PermissionStateFullParcel permPrcel;
        permPrcel.permStatFull = perm;
        reqPermList.emplace_back(permPrcel);
    }
    return ret;
}

PermissionOper AccessTokenManagerService::GetSelfPermissionsState(
    std::vector<PermissionListStateParcel>& reqPermList)
{
    AccessTokenID callingTokenID = IPCSkeleton::GetCallingTokenID();

    int32_t apiVersion = 0;
    if (!PermissionManager::GetInstance().GetApiVersionByTokenId(callingTokenID, apiVersion)) {
        ACCESSTOKEN_LOG_ERROR(LABEL, "get api version error");
        return INVALID_OPER;
    }
    ACCESSTOKEN_LOG_INFO(LABEL, "callingTokenID: %{public}d, apiVersion: %{public}d", callingTokenID, apiVersion);

    bool needRes = false;
    std::vector<PermissionStateFull> permsList;
    int retUserGrant = PermissionManager::GetInstance().GetReqPermissions(callingTokenID, permsList, false);
    int retSysGrant = PermissionManager::GetInstance().GetReqPermissions(callingTokenID, permsList, true);
    if ((retSysGrant != RET_SUCCESS) || (retUserGrant != RET_SUCCESS)) {
        ACCESSTOKEN_LOG_ERROR(LABEL,
            "GetReqPermissions failed, retUserGrant:%{public}d, retSysGrant:%{public}d",
            retUserGrant, retSysGrant);
        return INVALID_OPER;
    }

    uint32_t vagueIndex = ELEMENT_NOT_FOUND;
    uint32_t accurateIndex = ELEMENT_NOT_FOUND;

    if (apiVersion >= ACCURATE_LOCATION_API_VERSION) {
        if (PermissionManager::GetInstance().GetLocationPermissionIndex(reqPermList, vagueIndex, accurateIndex)) {
            needRes = PermissionManager::GetInstance().LocationPermissionSpecialHandle(reqPermList, apiVersion,
                permsList, vagueIndex, accurateIndex); // api9 location permission handle here
        }
    }

    uint32_t size = reqPermList.size();
    for (uint32_t i = 0; i < size; i++) {
        if (((reqPermList[i].permsState.permissionName == VAGUE_LOCATION_PERMISSION_NAME) ||
            (reqPermList[i].permsState.permissionName == ACCURATE_LOCATION_PERMISSION_NAME)) &&
            (apiVersion >= ACCURATE_LOCATION_API_VERSION)) {
            continue; // api9 location permission special handle above
        }

        PermissionManager::GetInstance().GetSelfPermissionState(permsList, reqPermList[i].permsState, apiVersion);
        if (static_cast<PermissionOper>(reqPermList[i].permsState.state) == DYNAMIC_OPER) {
            needRes = true;
        }
        ACCESSTOKEN_LOG_INFO(LABEL, "perm: 0x%{public}s, state: 0x%{public}d",
            reqPermList[i].permsState.permissionName.c_str(), reqPermList[i].permsState.state);
    }
    if (needRes) {
        return DYNAMIC_OPER;
    } else {
        if ((vagueIndex == ELEMENT_NOT_FOUND) && (accurateIndex != ELEMENT_NOT_FOUND)) {
            // only accurate location permission without other DYNAMIC_OPER state return INVALID_OPER
            return INVALID_OPER;
        }
    }
    return PASS_OPER;
}

int AccessTokenManagerService::GetPermissionFlag(AccessTokenID tokenID, const std::string& permissionName, int& flag)
{
    ACCESSTOKEN_LOG_INFO(LABEL, "tokenID: 0x%{public}x, permission: %{public}s",
        tokenID, permissionName.c_str());
    return PermissionManager::GetInstance().GetPermissionFlag(tokenID, permissionName, flag);
}

int AccessTokenManagerService::GrantPermission(AccessTokenID tokenID, const std::string& permissionName, int flag)
{
    ACCESSTOKEN_LOG_INFO(LABEL, "tokenID: 0x%{public}x, permission: %{public}s, flag: %{public}d",
        tokenID, permissionName.c_str(), flag);
    PermissionManager::GetInstance().GrantPermission(tokenID, permissionName, flag);
    AccessTokenInfoManager::GetInstance().RefreshTokenInfoIfNeeded();
    return RET_SUCCESS;
}

int AccessTokenManagerService::RevokePermission(AccessTokenID tokenID, const std::string& permissionName, int flag)
{
    ACCESSTOKEN_LOG_INFO(LABEL, "tokenID: 0x%{public}x, permission: %{public}s, flag: %{public}d",
        tokenID, permissionName.c_str(), flag);
    PermissionManager::GetInstance().RevokePermission(tokenID, permissionName, flag);
    AccessTokenInfoManager::GetInstance().RefreshTokenInfoIfNeeded();
    return RET_SUCCESS;
}

int AccessTokenManagerService::ClearUserGrantedPermissionState(AccessTokenID tokenID)
{
    ACCESSTOKEN_LOG_INFO(LABEL, "tokenID: 0x%{public}x", tokenID);
    PermissionManager::GetInstance().ClearUserGrantedPermissionState(tokenID);
    AccessTokenInfoManager::GetInstance().RefreshTokenInfoIfNeeded();
    PrivacyKit::RemovePermissionUsedRecords(tokenID, "");
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
    ACCESSTOKEN_LOG_INFO(LABEL, "called!");
    AccessTokenIDEx tokenIdEx;
    tokenIdEx.tokenIDEx = 0LL;

    int ret = AccessTokenInfoManager::GetInstance().CreateHapTokenInfo(
        info.hapInfoParameter, policy.hapPolicyParameter, tokenIdEx);
    if (ret != RET_SUCCESS) {
        ACCESSTOKEN_LOG_INFO(LABEL, "hap token info create failed");
    }
    return tokenIdEx;
}

int AccessTokenManagerService::DeleteToken(AccessTokenID tokenID)
{
    ACCESSTOKEN_LOG_INFO(LABEL, "tokenID: 0x%{public}x", tokenID);
    PrivacyKit::RemovePermissionUsedRecords(tokenID, "");
    // only support hap token deletion
    return AccessTokenInfoManager::GetInstance().RemoveHapTokenInfo(tokenID);
}

int AccessTokenManagerService::GetTokenType(AccessTokenID tokenID)
{
    ACCESSTOKEN_LOG_INFO(LABEL, "tokenID: 0x%{public}x", tokenID);
    return AccessTokenIDManager::GetInstance().GetTokenIdType(tokenID);
}

int AccessTokenManagerService::CheckNativeDCap(AccessTokenID tokenID, const std::string& dcap)
{
    ACCESSTOKEN_LOG_INFO(LABEL, "tokenID: 0x%{public}x, dcap: %{public}s",
        tokenID, dcap.c_str());
    return AccessTokenInfoManager::GetInstance().CheckNativeDCap(tokenID, dcap);
}

AccessTokenID AccessTokenManagerService::GetHapTokenID(int userID, const std::string& bundleName, int instIndex)
{
    ACCESSTOKEN_LOG_INFO(LABEL, "userID: %{public}d, bundle: %{public}s, instIndex: %{public}d",
        userID, bundleName.c_str(), instIndex);
    return AccessTokenInfoManager::GetInstance().GetHapTokenID(userID, bundleName, instIndex);
}

AccessTokenID AccessTokenManagerService::AllocLocalTokenID(
    const std::string& remoteDeviceID, AccessTokenID remoteTokenID)
{
    ACCESSTOKEN_LOG_INFO(LABEL, "remoteDeviceID: %{public}s, remoteTokenID: %{public}d",
        ConstantCommon::EncryptDevId(remoteDeviceID).c_str(), remoteTokenID);
    return AccessTokenInfoManager::GetInstance().AllocLocalTokenID(remoteDeviceID, remoteTokenID);
}

int AccessTokenManagerService::UpdateHapToken(
    AccessTokenID tokenID, const std::string& appIDDesc, int32_t apiVersion, const HapPolicyParcel& policyParcel)
{
    ACCESSTOKEN_LOG_INFO(LABEL, "tokenID: 0x%{public}x", tokenID);
    return AccessTokenInfoManager::GetInstance().UpdateHapToken(tokenID, appIDDesc, apiVersion,
        policyParcel.hapPolicyParameter);
}

int AccessTokenManagerService::GetHapTokenInfo(AccessTokenID tokenID, HapTokenInfoParcel& infoParcel)
{
    ACCESSTOKEN_LOG_INFO(LABEL, "tokenID: 0x%{public}x", tokenID);

    return AccessTokenInfoManager::GetInstance().GetHapTokenInfo(tokenID, infoParcel.hapTokenInfoParams);
}

int AccessTokenManagerService::GetNativeTokenInfo(AccessTokenID tokenID, NativeTokenInfoParcel& infoParcel)
{
    ACCESSTOKEN_LOG_INFO(LABEL, "tokenID: 0x%{public}x", tokenID);

    return AccessTokenInfoManager::GetInstance().GetNativeTokenInfo(tokenID, infoParcel.nativeTokenInfoParams);
}

int32_t AccessTokenManagerService::ReloadNativeTokenInfo()
{
    return NativeTokenReceptor::GetInstance().Init();
}

AccessTokenID AccessTokenManagerService::GetNativeTokenId(const std::string& processName)
{
    return AccessTokenInfoManager::GetInstance().GetNativeTokenId(processName);
}

#ifdef TOKEN_SYNC_ENABLE
int AccessTokenManagerService::GetHapTokenInfoFromRemote(AccessTokenID tokenID,
    HapTokenInfoForSyncParcel& hapSyncParcel)
{
    ACCESSTOKEN_LOG_INFO(LABEL, "tokenID: 0x%{public}x", tokenID);

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

    return AccessTokenInfoManager::GetInstance().SetRemoteHapTokenInfo(deviceID,
        hapSyncParcel.hapTokenInfoForSyncParams);
}

int AccessTokenManagerService::SetRemoteNativeTokenInfo(const std::string& deviceID,
    std::vector<NativeTokenInfoForSyncParcel>& nativeTokenInfoForSyncParcel)
{
    ACCESSTOKEN_LOG_INFO(LABEL, "deviceID: %{public}s", ConstantCommon::EncryptDevId(deviceID).c_str());

    std::vector<NativeTokenInfoForSync> nativeList;
    std::transform(nativeTokenInfoForSyncParcel.begin(),
        nativeTokenInfoForSyncParcel.end(), std::back_inserter(nativeList),
        [](const auto& nativeParcel) { return nativeParcel.nativeTokenInfoForSyncParams; });

    return AccessTokenInfoManager::GetInstance().SetRemoteNativeTokenInfo(deviceID, nativeList);
}

int AccessTokenManagerService::DeleteRemoteToken(const std::string& deviceID, AccessTokenID tokenID)
{
    ACCESSTOKEN_LOG_INFO(LABEL, "deviceID: %{public}s, token id %{public}d",
        ConstantCommon::EncryptDevId(deviceID).c_str(), tokenID);

    return AccessTokenInfoManager::GetInstance().DeleteRemoteToken(deviceID, tokenID);
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

    return AccessTokenInfoManager::GetInstance().DeleteRemoteDeviceTokens(deviceID);
}
#endif

void AccessTokenManagerService::DumpTokenInfo(AccessTokenID tokenID, std::string& dumpInfo)
{
    ACCESSTOKEN_LOG_INFO(LABEL, "called");

    AccessTokenInfoManager::GetInstance().DumpTokenInfo(tokenID, dumpInfo);
}
#ifdef TOKEN_SYNC_ENABLE
void AccessTokenManagerService::CreateDeviceListener()
{
    static const int32_t RETRY_SLEEP_TIME_MS = 1000;
    static const int32_t DM_INIT_RETRY_TIMES = 30;
    std::function<void()> runner = [&]() {
        auto retrySleepTime = std::chrono::milliseconds(RETRY_SLEEP_TIME_MS);
        int32_t count = 0;
        while (1) {
            if (count >= DM_INIT_RETRY_TIMES) {
                ACCESSTOKEN_LOG_INFO(LABEL, "retry times has reach the max, break the loop.");
                break;
            }

            count++;

            std::unique_lock<std::mutex> lock(mutex_);

            std::string packageName = ACCESS_TOKEN_PACKAGE_NAME;
            std::shared_ptr<AtmDmInitCallback> ptrDmInitCallback = std::make_shared<AtmDmInitCallback>();

            int32_t ret =
                DistributedHardware::DeviceManager::GetInstance().InitDeviceManager(packageName, ptrDmInitCallback);
            if (ret != RET_SUCCESS) {
                ACCESSTOKEN_LOG_ERROR(LABEL, "Initialize: InitDeviceManager error, result: %{public}d", ret);
                std::this_thread::sleep_for(retrySleepTime);
                continue;
            }

            ACCESSTOKEN_LOG_INFO(LABEL, "device manager init success.");

            std::string extra = "";
            std::shared_ptr<AtmDeviceStateCallback> ptrAtmDeviceStateCallback =
                std::make_shared<AtmDeviceStateCallback>();
            ret = DistributedHardware::DeviceManager::GetInstance().RegisterDevStateCallback(packageName, extra,
                ptrAtmDeviceStateCallback);
            if (ret != RET_SUCCESS) {
                ACCESSTOKEN_LOG_ERROR(LABEL, "Initialize: RegisterDevStateCallback error, result: %{public}d", ret);
                std::this_thread::sleep_for(retrySleepTime);
                continue;
            }

            isListened_ = true;

            ACCESSTOKEN_LOG_INFO(LABEL, "device state Listener register success.");

            return;
        }
    };

    std::thread initThread(runner);
    initThread.detach();

    ACCESSTOKEN_LOG_DEBUG(LABEL, "start a thread to listen device state.");
}

void AccessTokenManagerService::DestroyDeviceListener()
{
    ACCESSTOKEN_LOG_DEBUG(LABEL, "destroy, init: %{public}d", isListened_);

    std::unique_lock<std::mutex> lock(mutex_);

    if (!isListened_) {
        ACCESSTOKEN_LOG_DEBUG(LABEL, "not listened, skip");
        return;
    }

    std::string packageName = ACCESS_TOKEN_PACKAGE_NAME;

    int32_t ret = DistributedHardware::DeviceManager::GetInstance().UnRegisterDevStateCallback(packageName);
    if (ret != RET_SUCCESS) {
        ACCESSTOKEN_LOG_ERROR(LABEL, "UnRegisterDevStateCallback failed, code: %{public}d", ret);
    }

    ret = DistributedHardware::DeviceManager::GetInstance().UnInitDeviceManager(packageName);
    if (ret != RET_SUCCESS) {
        ACCESSTOKEN_LOG_ERROR(LABEL, "UnInitDeviceManager failed, code: %{public}d", ret);
    }

    isListened_ = false;

    ACCESSTOKEN_LOG_INFO(LABEL, "device state listener unregister success.");
}
#endif

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
        std::string dumpStr;
        DumpTokenInfo(static_cast<AccessTokenID>(tokenID), dumpStr);
        dprintf(fd, "%s\n", dumpStr.c_str());
    }  else if (arg0.compare("-a") == 0 || arg0 == "") {
        std::string dumpStr;
        DumpTokenInfo(static_cast<AccessTokenID>(0), dumpStr);
        dprintf(fd, "%s\n", dumpStr.c_str());
    }
    return ERR_OK;
}

bool AccessTokenManagerService::Initialize()
{
    AccessTokenInfoManager::GetInstance().Init();
    NativeTokenReceptor::GetInstance().Init();
#ifdef TOKEN_SYNC_ENABLE
    CreateDeviceListener(); // for start tokensync when remote devivce online
#endif
#ifdef SUPPORT_SANDBOX_APP
    DlpPermissionSetParser::GetInstance().Init();
#endif
    HiviewDFX::HiSysEvent::Write(HiviewDFX::HiSysEvent::Domain::ACCESS_TOKEN, "PERMISSION_CHECK_EVENT",
        HiviewDFX::HiSysEvent::EventType::BEHAVIOR, "CODE", ACCESS_TOKEN_SERVICE_INIT_EVENT,
        "PID_INFO", getpid());
    return true;
}
} // namespace AccessToken
} // namespace Security
} // namespace OHOS
