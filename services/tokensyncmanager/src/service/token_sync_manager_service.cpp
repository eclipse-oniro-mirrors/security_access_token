/*
 * Copyright (c) 2022 Huawei Device Co., Ltd.
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

#include "token_sync_manager_service.h"

#include <securec.h>

#include "accesstoken_common_log.h"
#include "constant_common.h"
#include "device_info_repository.h"
#include "device_info.h"
#include "remote_command_manager.h"
#include "soft_bus_manager.h"
#include "system_ability_definition.h"
#ifdef MEMORY_MANAGER_ENABLE
#include "mem_mgr_client.h"
#endif

namespace OHOS {
namespace Security {
namespace AccessToken {
#ifdef MEMORY_MANAGER_ENABLE
namespace {
static constexpr int32_t SA_TYPE = 1;
static constexpr int32_t SA_START = 1;
static constexpr int32_t SA_STOP = 0;
}
#endif

const bool REGISTER_RESULT =
    SystemAbility::MakeAndRegisterAbility(DelayedSingleton<TokenSyncManagerService>::GetInstance().get());

TokenSyncManagerService::TokenSyncManagerService()
    : SystemAbility(SA_ID_TOKENSYNC_MANAGER_SERVICE, false), state_(ServiceRunningState::STATE_NOT_START)
{
    LOGI(ATM_DOMAIN, ATM_TAG, "TokenSyncManagerService()");
}

TokenSyncManagerService::~TokenSyncManagerService()
{
    LOGI(ATM_DOMAIN, ATM_TAG, "~TokenSyncManagerService()");
}

void TokenSyncManagerService::OnStart()
{
    std::lock_guard<std::mutex> lock(stateMutex_);
    if (state_ == ServiceRunningState::STATE_RUNNING) {
        LOGI(ATM_DOMAIN, ATM_TAG, "TokenSyncManagerService has already started!");
        return;
    }
    LOGI(ATM_DOMAIN, ATM_TAG, "TokenSyncManagerService is starting");
    if (!Initialize()) {
        LOGE(ATM_DOMAIN, ATM_TAG, "Failed to initialize");
        return;
    }
    state_ = ServiceRunningState::STATE_RUNNING;
    bool ret = Publish(DelayedSingleton<TokenSyncManagerService>::GetInstance().get());
    if (!ret) {
        LOGE(ATM_DOMAIN, ATM_TAG, "Failed to publish service!");
        return;
    }
    (void)AddSystemAbilityListener(DISTRIBUTED_HARDWARE_DEVICEMANAGER_SA_ID);
#ifdef MEMORY_MANAGER_ENABLE
    int32_t pid = getpid();
    Memory::MemMgrClient::GetInstance().NotifyProcessStatus(pid, SA_TYPE, SA_START, SA_ID_TOKENSYNC_MANAGER_SERVICE);
    Memory::MemMgrClient::GetInstance().SetCritical(pid, true, SA_ID_TOKENSYNC_MANAGER_SERVICE);
#endif
    LOGI(ATM_DOMAIN, ATM_TAG, "Congratulations, TokenSyncManagerService start successfully!");
}

void TokenSyncManagerService::OnStop()
{
    LOGI(ATM_DOMAIN, ATM_TAG, "Stop service");
    std::lock_guard<std::mutex> lock(stateMutex_);
    state_ = ServiceRunningState::STATE_NOT_START;
    SoftBusManager::GetInstance().Destroy();
#ifdef MEMORY_MANAGER_ENABLE
    Memory::MemMgrClient::GetInstance().NotifyProcessStatus(
        getpid(), SA_TYPE, SA_STOP, SA_ID_TOKENSYNC_MANAGER_SERVICE);
#endif
}

void TokenSyncManagerService::OnAddSystemAbility(int32_t systemAbilityId, const std::string& deviceId)
{
    if (systemAbilityId == DISTRIBUTED_HARDWARE_DEVICEMANAGER_SA_ID) {
        SoftBusManager::GetInstance().Initialize();
    }
}

#ifdef EVENTHANDLER_ENABLE
std::shared_ptr<AccessEventHandler> TokenSyncManagerService::GetSendEventHandler() const
{
    return sendHandler_;
}

std::shared_ptr<AccessEventHandler> TokenSyncManagerService::GetRecvEventHandler() const
{
    return recvHandler_;
}
#endif

int TokenSyncManagerService::GetRemoteHapTokenInfo(const std::string& deviceID, AccessTokenID tokenID)
{
    if (!DataValidator::IsDeviceIdValid(deviceID) || tokenID == 0) {
        LOGI(ATM_DOMAIN, ATM_TAG, "Params is wrong.");
        return TOKEN_SYNC_PARAMS_INVALID;
    }
    DeviceInfo devInfo;
    bool result = DeviceInfoRepository::GetInstance().FindDeviceInfo(deviceID, DeviceIdType::UNKNOWN, devInfo);
    if (!result) {
        LOGI(ATM_DOMAIN, ATM_TAG, "FindDeviceInfo failed");
        return TOKEN_SYNC_REMOTE_DEVICE_INVALID;
    }
    std::string udid = devInfo.deviceId.uniqueDeviceId;
    const std::shared_ptr<SyncRemoteHapTokenCommand> syncRemoteHapTokenCommand =
        RemoteCommandFactory::GetInstance().NewSyncRemoteHapTokenCommand(ConstantCommon::GetLocalDeviceId(),
        deviceID, tokenID);

    const int32_t resultCode = RemoteCommandManager::GetInstance().ExecuteCommand(udid, syncRemoteHapTokenCommand);
    if (resultCode != Constant::SUCCESS) {
        LOGI(ATM_DOMAIN, ATM_TAG,
            "RemoteExecutorManager executeCommand SyncRemoteHapTokenCommand failed, return %{public}d", resultCode);
        return TOKEN_SYNC_COMMAND_EXECUTE_FAILED;
    }
    LOGI(ATM_DOMAIN, ATM_TAG, "Get resultCode: %{public}d", resultCode);
    return TOKEN_SYNC_SUCCESS;
}

int TokenSyncManagerService::DeleteRemoteHapTokenInfo(AccessTokenID tokenID)
{
    if (tokenID == 0) {
        LOGI(ATM_DOMAIN, ATM_TAG, "Params is wrong, token id is invalid.");
        return TOKEN_SYNC_PARAMS_INVALID;
    }

    std::vector<DeviceInfo> devices = DeviceInfoRepository::GetInstance().ListDeviceInfo();
    std::string localUdid = ConstantCommon::GetLocalDeviceId();
    for (const DeviceInfo& device : devices) {
        if (device.deviceId.uniqueDeviceId == localUdid) {
            LOGI(ATM_DOMAIN, ATM_TAG, "No need notify local device");
            continue;
        }
        const std::shared_ptr<DeleteRemoteTokenCommand> deleteRemoteTokenCommand =
            RemoteCommandFactory::GetInstance().NewDeleteRemoteTokenCommand(ConstantCommon::GetLocalDeviceId(),
            device.deviceId.uniqueDeviceId, tokenID);

        const int32_t resultCode = RemoteCommandManager::GetInstance().ExecuteCommand(
            device.deviceId.uniqueDeviceId, deleteRemoteTokenCommand);
        if (resultCode != Constant::SUCCESS) {
            LOGI(ATM_DOMAIN, ATM_TAG,
                "RemoteExecutorManager executeCommand DeleteRemoteTokenCommand failed, return %{public}d", resultCode);
            continue;
        }
        LOGI(ATM_DOMAIN, ATM_TAG, "Get resultCode: %{public}d", resultCode);
    }
    return TOKEN_SYNC_SUCCESS;
}

int TokenSyncManagerService::UpdateRemoteHapTokenInfo(const HapTokenInfoForSync& tokenInfo)
{
    std::vector<DeviceInfo> devices = DeviceInfoRepository::GetInstance().ListDeviceInfo();
    std::string localUdid = ConstantCommon::GetLocalDeviceId();
    for (const DeviceInfo& device : devices) {
        if (device.deviceId.uniqueDeviceId == localUdid) {
            LOGI(ATM_DOMAIN, ATM_TAG, "No need notify local device");
            continue;
        }

        const std::shared_ptr<UpdateRemoteHapTokenCommand> updateRemoteHapTokenCommand =
            RemoteCommandFactory::GetInstance().NewUpdateRemoteHapTokenCommand(ConstantCommon::GetLocalDeviceId(),
            device.deviceId.uniqueDeviceId, tokenInfo);

        const int32_t resultCode = RemoteCommandManager::GetInstance().ExecuteCommand(
            device.deviceId.uniqueDeviceId, updateRemoteHapTokenCommand);
        if (resultCode != Constant::SUCCESS) {
            LOGI(ATM_DOMAIN, ATM_TAG,
                "RemoteExecutorManager executeCommand updateRemoteHapTokenCommand failed, return %{public}d",
                resultCode);
            continue;
        }
        LOGI(ATM_DOMAIN, ATM_TAG, "Get resultCode: %{public}d", resultCode);
    }

    return TOKEN_SYNC_SUCCESS;
}

bool TokenSyncManagerService::Initialize()
{
#ifdef EVENTHANDLER_ENABLE
    sendRunner_ = AppExecFwk::EventRunner::Create(true, AppExecFwk::ThreadMode::FFRT);
    if (!sendRunner_) {
        LOGE(ATM_DOMAIN, ATM_TAG, "Failed to create a sendRunner.");
        return false;
    }

    sendHandler_ = std::make_shared<AccessEventHandler>(sendRunner_);
    recvRunner_ = AppExecFwk::EventRunner::Create(true, AppExecFwk::ThreadMode::FFRT);
    if (!recvRunner_) {
        LOGE(ATM_DOMAIN, ATM_TAG, "Failed to create a recvRunner.");
        return false;
    }

    recvHandler_ = std::make_shared<AccessEventHandler>(recvRunner_);
#endif
    return true;
}
} // namespace AccessToken
} // namespace Security
} // namespace OHOS
