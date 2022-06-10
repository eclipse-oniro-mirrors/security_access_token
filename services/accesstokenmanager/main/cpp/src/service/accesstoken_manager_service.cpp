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

#include <thread>

#include "access_token.h"
#include "accesstoken_id_manager.h"
#include "accesstoken_info_manager.h"
#include "accesstoken_log.h"
#include "device_manager.h"
#include "hap_token_info.h"
#include "hap_token_info_inner.h"
#include "ipc_skeleton.h"
#include "native_token_info_inner.h"
#include "native_token_receptor.h"
#include "permission_list_state.h"
#include "permission_manager.h"
#include "permission_record_manager.h"

namespace OHOS {
namespace Security {
namespace AccessToken {
namespace {
static constexpr OHOS::HiviewDFX::HiLogLabel LABEL = {
    LOG_CORE, SECURITY_DOMAIN_ACCESSTOKEN, "AccessTokenManagerService"
};
}

const bool REGISTER_RESULT =
    SystemAbility::MakeAndRegisterAbility(DelayedSingleton<AccessTokenManagerService>::GetInstance().get());

const int32_t RETRY_SLEEP_TIME_MS = 1000;

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
    DestroyDeviceListenner();
}

int AccessTokenManagerService::VerifyAccessToken(AccessTokenID tokenID, const std::string& permissionName)
{
    ACCESSTOKEN_LOG_INFO(LABEL, "called, tokenID: 0x%{public}x, permissionName: %{public}s",
        tokenID, permissionName.c_str());
    int isGranted = PermissionManager::GetInstance().VerifyAccessToken(tokenID, permissionName);
    if (isGranted != PERMISSION_GRANTED) {
        PermissionRecordManager::GetInstance().AddPermissionUsedRecord(tokenID, permissionName, 0, 1);
    } else {
        PermissionRecordManager::GetInstance().AddPermissionUsedRecord(tokenID, permissionName, 1, 0);
    }
    return isGranted;
}

int AccessTokenManagerService::VerifyNativeToken(AccessTokenID tokenID, const std::string& permissionName)
{
    ACCESSTOKEN_LOG_INFO(LABEL, "called, tokenID: 0x%{public}x, permissionName: %{public}s",
        tokenID, permissionName.c_str());
    return PermissionManager::GetInstance().VerifyNativeToken(tokenID, permissionName);
}

int AccessTokenManagerService::GetDefPermission(
    const std::string& permissionName, PermissionDefParcel& permissionDefResult)
{
    ACCESSTOKEN_LOG_INFO(LABEL, "called, permissionName: %{public}s", permissionName.c_str());
    return PermissionManager::GetInstance().GetDefPermission(permissionName, permissionDefResult.permissionDef);
}

int AccessTokenManagerService::GetDefPermissions(AccessTokenID tokenID, std::vector<PermissionDefParcel>& permList)
{
    ACCESSTOKEN_LOG_INFO(LABEL, "called, tokenID: 0x%{public}x", tokenID);
    std::vector<PermissionDef> permVec;
    int ret = PermissionManager::GetInstance().GetDefPermissions(tokenID, permVec);
    for (auto perm : permVec) {
        PermissionDefParcel permPrcel;
        permPrcel.permissionDef = perm;
        permList.emplace_back(permPrcel);
    }
    return ret;
}

int AccessTokenManagerService::GetReqPermissions(
    AccessTokenID tokenID, std::vector<PermissionStateFullParcel>& reqPermList, bool isSystemGrant)
{
    ACCESSTOKEN_LOG_INFO(LABEL, "called, tokenID: 0x%{public}x, isSystemGrant: %{public}d", tokenID, isSystemGrant);

    std::vector<PermissionStateFull> permList;
    int ret = PermissionManager::GetInstance().GetReqPermissions(tokenID, permList, isSystemGrant);

    for (auto& perm : permList) {
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
    ACCESSTOKEN_LOG_INFO(LABEL, "callingTokenID: %{public}d", callingTokenID);

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

    uint32_t size = reqPermList.size();
    ACCESSTOKEN_LOG_INFO(LABEL, "reqPermList size: 0x%{public}x", size);
    for (uint32_t i = 0; i < size; i++) {
        PermissionManager::GetInstance().GetSelfPermissionState(
            permsList, reqPermList[i].permsState);
        if (reqPermList[i].permsState.state == DYNAMIC_OPER) {
            needRes = true;
        }
    }
    if (needRes) {
        return DYNAMIC_OPER;
    }
    return PASS_OPER;
}

int AccessTokenManagerService::GetPermissionFlag(AccessTokenID tokenID, const std::string& permissionName)
{
    ACCESSTOKEN_LOG_INFO(LABEL, "called, tokenID: 0x%{public}x, permissionName: %{public}s",
        tokenID, permissionName.c_str());
    return PermissionManager::GetInstance().GetPermissionFlag(tokenID, permissionName);
}

int AccessTokenManagerService::GrantPermission(AccessTokenID tokenID, const std::string& permissionName, int flag)
{
    ACCESSTOKEN_LOG_INFO(LABEL, "called, tokenID: 0x%{public}x, permissionName: %{public}s, flag: %{public}d",
        tokenID, permissionName.c_str(), flag);
    PermissionManager::GetInstance().GrantPermission(tokenID, permissionName, flag);
    AccessTokenInfoManager::GetInstance().RefreshTokenInfoIfNeeded();
    return RET_SUCCESS;
}

int AccessTokenManagerService::RevokePermission(AccessTokenID tokenID, const std::string& permissionName, int flag)
{
    ACCESSTOKEN_LOG_INFO(LABEL, "called, tokenID: 0x%{public}x, permissionName: %{public}s, flag: %{public}d",
        tokenID, permissionName.c_str(), flag);
    PermissionManager::GetInstance().RevokePermission(tokenID, permissionName, flag);
    AccessTokenInfoManager::GetInstance().RefreshTokenInfoIfNeeded();
    return RET_SUCCESS;
}

int AccessTokenManagerService::ClearUserGrantedPermissionState(AccessTokenID tokenID)
{
    ACCESSTOKEN_LOG_INFO(LABEL, "called, tokenID: 0x%{public}x", tokenID);
    PermissionManager::GetInstance().ClearUserGrantedPermissionState(tokenID);
    AccessTokenInfoManager::GetInstance().RefreshTokenInfoIfNeeded();
    PermissionRecordManager::GetInstance().RemovePermissionUsedRecords(tokenID, "");
    return RET_SUCCESS;
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
    ACCESSTOKEN_LOG_INFO(LABEL, "called, tokenID: 0x%{public}x", tokenID);
    PermissionRecordManager::GetInstance().RemovePermissionUsedRecords(tokenID, "");
    // only support hap token deletion
    return AccessTokenInfoManager::GetInstance().RemoveHapTokenInfo(tokenID);
}

int AccessTokenManagerService::GetTokenType(AccessTokenID tokenID)
{
    ACCESSTOKEN_LOG_INFO(LABEL, "called, tokenID: 0x%{public}x", tokenID);
    return AccessTokenIDManager::GetInstance().GetTokenIdType(tokenID);
}

int AccessTokenManagerService::CheckNativeDCap(AccessTokenID tokenID, const std::string& dcap)
{
    ACCESSTOKEN_LOG_INFO(LABEL, "called, tokenID: 0x%{public}x, dcap: %{public}s",
        tokenID, dcap.c_str());
    return AccessTokenInfoManager::GetInstance().CheckNativeDCap(tokenID, dcap);
}

AccessTokenID AccessTokenManagerService::GetHapTokenID(int userID, const std::string& bundleName, int instIndex)
{
    ACCESSTOKEN_LOG_INFO(LABEL, "called, userID: %{public}d, bundleName: %{public}s, instIndex: %{public}d",
        userID, bundleName.c_str(), instIndex);
    return AccessTokenInfoManager::GetInstance().GetHapTokenID(userID, bundleName, instIndex);
}

AccessTokenID AccessTokenManagerService::AllocLocalTokenID(
    const std::string& remoteDeviceID, AccessTokenID remoteTokenID)
{
    ACCESSTOKEN_LOG_INFO(LABEL, "called, remoteDeviceID: %{public}s, remoteTokenID: %{public}d",
        remoteDeviceID.c_str(), remoteTokenID);
    return AccessTokenInfoManager::GetInstance().AllocLocalTokenID(remoteDeviceID, remoteTokenID);
}

int AccessTokenManagerService::UpdateHapToken(AccessTokenID tokenID, const std::string& appIDDesc,
    const HapPolicyParcel& policyParcel)
{
    ACCESSTOKEN_LOG_INFO(LABEL, "called, tokenID: 0x%{public}x", tokenID);

    return AccessTokenInfoManager::GetInstance().UpdateHapToken(tokenID, appIDDesc,
        policyParcel.hapPolicyParameter);
}

int AccessTokenManagerService::GetHapTokenInfo(AccessTokenID tokenID, HapTokenInfoParcel& InfoParcel)
{
    ACCESSTOKEN_LOG_INFO(LABEL, "called, tokenID: 0x%{public}x", tokenID);

    return AccessTokenInfoManager::GetInstance().GetHapTokenInfo(tokenID, InfoParcel.hapTokenInfoParams);
}

int AccessTokenManagerService::GetNativeTokenInfo(AccessTokenID tokenID, NativeTokenInfoParcel& InfoParcel)
{
    ACCESSTOKEN_LOG_INFO(LABEL, "called, tokenID: 0x%{public}x", tokenID);

    return AccessTokenInfoManager::GetInstance().GetNativeTokenInfo(tokenID, InfoParcel.nativeTokenInfoParams);
}

#ifdef TOKEN_SYNC_ENABLE
int AccessTokenManagerService::GetHapTokenInfoFromRemote(AccessTokenID tokenID,
    HapTokenInfoForSyncParcel& hapSyncParcel)
{
    ACCESSTOKEN_LOG_INFO(LABEL, "called, tokenID: 0x%{public}x", tokenID);

    return AccessTokenInfoManager::GetInstance().GetHapTokenInfoFromRemote(tokenID,
        hapSyncParcel.hapTokenInfoForSyncParams);
}

int AccessTokenManagerService::GetAllNativeTokenInfo(std::vector<NativeTokenInfoForSyncParcel>& nativeTokenInfosRes)
{
    ACCESSTOKEN_LOG_INFO(LABEL, "called");

    std::vector<NativeTokenInfoForSync> nativeVec;
    AccessTokenInfoManager::GetInstance().GetAllNativeTokenInfo(nativeVec);
    for (auto& native : nativeVec) {
        NativeTokenInfoForSyncParcel nativeParcel;
        nativeParcel.nativeTokenInfoForSyncParams = native;
        nativeTokenInfosRes.emplace_back(nativeParcel);
    }

    return RET_SUCCESS;
}

int AccessTokenManagerService::SetRemoteHapTokenInfo(const std::string& deviceID,
    HapTokenInfoForSyncParcel& hapSyncParcel)
{
    ACCESSTOKEN_LOG_INFO(LABEL, "called, deviceID: %{public}s", deviceID.c_str());

    return AccessTokenInfoManager::GetInstance().SetRemoteHapTokenInfo(deviceID,
        hapSyncParcel.hapTokenInfoForSyncParams);
}

int AccessTokenManagerService::SetRemoteNativeTokenInfo(const std::string& deviceID,
    std::vector<NativeTokenInfoForSyncParcel>& nativeTokenInfoForSyncParcel)
{
    ACCESSTOKEN_LOG_INFO(LABEL, "called, deviceID: %{public}s", deviceID.c_str());

    std::vector<NativeTokenInfoForSync> nativeList;

    for (auto& nativeParcel : nativeTokenInfoForSyncParcel) {
        nativeList.emplace_back(nativeParcel.nativeTokenInfoForSyncParams);
    }

    return AccessTokenInfoManager::GetInstance().SetRemoteNativeTokenInfo(deviceID, nativeList);
}

int AccessTokenManagerService::DeleteRemoteToken(const std::string& deviceID, AccessTokenID tokenID)
{
    ACCESSTOKEN_LOG_INFO(LABEL, "called, deviceID: %{public}s, token id %{public}d",
        deviceID.c_str(), tokenID);

    return AccessTokenInfoManager::GetInstance().DeleteRemoteToken(deviceID, tokenID);
}

AccessTokenID AccessTokenManagerService::GetRemoteNativeTokenID(const std::string& deviceID,
    AccessTokenID tokenID)
{
    ACCESSTOKEN_LOG_INFO(LABEL, "called, deviceID: %{public}s, token id %{public}d",
        deviceID.c_str(), tokenID);

    return AccessTokenInfoManager::GetInstance().GetRemoteNativeTokenID(deviceID, tokenID);
}

int AccessTokenManagerService::DeleteRemoteDeviceTokens(const std::string& deviceID)
{
    ACCESSTOKEN_LOG_INFO(LABEL, "called, deviceID: %{public}s", deviceID.c_str());

    return AccessTokenInfoManager::GetInstance().DeleteRemoteDeviceTokens(deviceID);
}
#endif

void AccessTokenManagerService::DumpTokenInfo(std::string& dumpInfo)
{
    ACCESSTOKEN_LOG_INFO(LABEL, "called");

    AccessTokenInfoManager::GetInstance().DumpTokenInfo(dumpInfo);
}

void AccessTokenManagerService::CreateDeviceListenner()
{
    std::function<void()> runner = [&]() {
        auto retrySleepTime = std::chrono::milliseconds(RETRY_SLEEP_TIME_MS);
        while (1) {
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

            ACCESSTOKEN_LOG_INFO(LABEL, "device state listenner register success.");

            return;
        }
    };

    std::thread initThread(runner);
    initThread.detach();

    ACCESSTOKEN_LOG_DEBUG(LABEL, "start a thread to listen device state.");
}

void AccessTokenManagerService::DestroyDeviceListenner()
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

    ACCESSTOKEN_LOG_INFO(LABEL, "device state listenner unregister success.");
}

bool AccessTokenManagerService::Initialize()
{
    AccessTokenInfoManager::GetInstance().Init();
    NativeTokenReceptor::GetInstance().Init();
    CreateDeviceListenner(); // for start tokensync when remote devivce online
    return true;
}
} // namespace AccessToken
} // namespace Security
} // namespace OHOS
