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

#include "accesstoken_log.h"
#include "constant_common.h"
#include "device_info_repository.h"
#include "device_info.h"
#include "remote_command_manager.h"
#include "soft_bus_manager.h"

namespace OHOS {
namespace Security {
namespace AccessToken {
namespace {
const bool REGISTER_RESULT =
    SystemAbility::MakeAndRegisterAbility(DelayedSingleton<TokenSyncManagerService>::GetInstance().get());
}

TokenSyncManagerService::TokenSyncManagerService()
    : SystemAbility(SA_ID_TOKENSYNC_MANAGER_SERVICE, false), state_(ServiceRunningState::STATE_NOT_START)
{
    LOGI(AT_DOMAIN, AT_TAG, "TokenSyncManagerService()");
}

TokenSyncManagerService::~TokenSyncManagerService()
{
    LOGI(AT_DOMAIN, AT_TAG, "~TokenSyncManagerService()");
}

void TokenSyncManagerService::OnStart()
{
    if (state_ == ServiceRunningState::STATE_RUNNING) {
        LOGI(AT_DOMAIN, AT_TAG, "TokenSyncManagerService has already started!");
        return;
    }
    LOGI(AT_DOMAIN, AT_TAG, "TokenSyncManagerService is starting");
    if (!Initialize()) {
        LOGE(AT_DOMAIN, AT_TAG, "Failed to initialize");
        return;
    }
    state_ = ServiceRunningState::STATE_RUNNING;
    bool ret = Publish(DelayedSingleton<TokenSyncManagerService>::GetInstance().get());
    if (!ret) {
        LOGE(AT_DOMAIN, AT_TAG, "Failed to publish service!");
        return;
    }
    LOGI(AT_DOMAIN, AT_TAG, "Congratulations, TokenSyncManagerService start successfully!");
}

void TokenSyncManagerService::OnStop()
{
    LOGI(AT_DOMAIN, AT_TAG, "Stop service");
    state_ = ServiceRunningState::STATE_NOT_START;
    SoftBusManager::GetInstance().Destroy();
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
        LOGI(AT_DOMAIN, AT_TAG, "Params is wrong.");
        return TOKEN_SYNC_PARAMS_INVALID;
    }
    DeviceInfo devInfo;
    bool result = DeviceInfoRepository::GetInstance().FindDeviceInfo(deviceID, DeviceIdType::UNKNOWN, devInfo);
    if (!result) {
        LOGI(AT_DOMAIN, AT_TAG, "FindDeviceInfo failed");
        return TOKEN_SYNC_REMOTE_DEVICE_INVALID;
    }
    std::string udid = devInfo.deviceId.uniqueDeviceId;
    const std::shared_ptr<SyncRemoteHapTokenCommand> syncRemoteHapTokenCommand =
        RemoteCommandFactory::GetInstance().NewSyncRemoteHapTokenCommand(ConstantCommon::GetLocalDeviceId(),
        deviceID, tokenID);

    const int32_t resultCode = RemoteCommandManager::GetInstance().ExecuteCommand(udid, syncRemoteHapTokenCommand);
    if (resultCode != Constant::SUCCESS) {
        LOGI(AT_DOMAIN, AT_TAG,
            "RemoteExecutorManager executeCommand SyncRemoteHapTokenCommand failed, return %{public}d", resultCode);
        return TOKEN_SYNC_COMMAND_EXECUTE_FAILED;
    }
    LOGI(AT_DOMAIN, AT_TAG, "Get resultCode: %{public}d", resultCode);
    return TOKEN_SYNC_SUCCESS;
}

int TokenSyncManagerService::DeleteRemoteHapTokenInfo(AccessTokenID tokenID)
{
    if (tokenID == 0) {
        LOGI(AT_DOMAIN, AT_TAG, "Params is wrong, token id is invalid.");
        return TOKEN_SYNC_PARAMS_INVALID;
    }

    std::vector<DeviceInfo> devices = DeviceInfoRepository::GetInstance().ListDeviceInfo();
    std::string localUdid = ConstantCommon::GetLocalDeviceId();
    for (const DeviceInfo& device : devices) {
        if (device.deviceId.uniqueDeviceId == localUdid) {
            LOGI(AT_DOMAIN, AT_TAG, "No need notify local device");
            continue;
        }
        const std::shared_ptr<DeleteRemoteTokenCommand> deleteRemoteTokenCommand =
            RemoteCommandFactory::GetInstance().NewDeleteRemoteTokenCommand(ConstantCommon::GetLocalDeviceId(),
            device.deviceId.uniqueDeviceId, tokenID);

        const int32_t resultCode = RemoteCommandManager::GetInstance().ExecuteCommand(
            device.deviceId.uniqueDeviceId, deleteRemoteTokenCommand);
        if (resultCode != Constant::SUCCESS) {
            LOGI(AT_DOMAIN, AT_TAG,
                "RemoteExecutorManager executeCommand DeleteRemoteTokenCommand failed, return %{public}d", resultCode);
            continue;
        }
        LOGI(AT_DOMAIN, AT_TAG, "Get resultCode: %{public}d", resultCode);
    }
    return TOKEN_SYNC_SUCCESS;
}

int TokenSyncManagerService::UpdateRemoteHapTokenInfo(const HapTokenInfoForSync& tokenInfo)
{
    std::vector<DeviceInfo> devices = DeviceInfoRepository::GetInstance().ListDeviceInfo();
    std::string localUdid = ConstantCommon::GetLocalDeviceId();
    for (const DeviceInfo& device : devices) {
        if (device.deviceId.uniqueDeviceId == localUdid) {
            LOGI(AT_DOMAIN, AT_TAG, "No need notify local device");
            continue;
        }

        const std::shared_ptr<UpdateRemoteHapTokenCommand> updateRemoteHapTokenCommand =
            RemoteCommandFactory::GetInstance().NewUpdateRemoteHapTokenCommand(ConstantCommon::GetLocalDeviceId(),
            device.deviceId.uniqueDeviceId, tokenInfo);

        const int32_t resultCode = RemoteCommandManager::GetInstance().ExecuteCommand(
            device.deviceId.uniqueDeviceId, updateRemoteHapTokenCommand);
        if (resultCode != Constant::SUCCESS) {
            LOGI(AT_DOMAIN, AT_TAG,
                "RemoteExecutorManager executeCommand updateRemoteHapTokenCommand failed, return %{public}d",
                resultCode);
            continue;
        }
        LOGI(AT_DOMAIN, AT_TAG, "Get resultCode: %{public}d", resultCode);
    }

    return TOKEN_SYNC_SUCCESS;
}

bool TokenSyncManagerService::Initialize()
{
#ifdef EVENTHANDLER_ENABLE
    sendRunner_ = AppExecFwk::EventRunner::Create(true, AppExecFwk::ThreadMode::FFRT);
    if (!sendRunner_) {
        LOGE(AT_DOMAIN, AT_TAG, "Failed to create a sendRunner.");
        return false;
    }

    sendHandler_ = std::make_shared<AccessEventHandler>(sendRunner_);
    recvRunner_ = AppExecFwk::EventRunner::Create(true, AppExecFwk::ThreadMode::FFRT);
    if (!recvRunner_) {
        LOGE(AT_DOMAIN, AT_TAG, "Failed to create a recvRunner.");
        return false;
    }

    recvHandler_ = std::make_shared<AccessEventHandler>(recvRunner_);
#endif
    SoftBusManager::GetInstance().Initialize();
    return true;
}
} // namespace AccessToken
} // namespace Security
} // namespace OHOS
