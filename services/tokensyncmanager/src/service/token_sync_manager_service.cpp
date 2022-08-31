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
static constexpr OHOS::HiviewDFX::HiLogLabel LABEL = {LOG_CORE, SECURITY_DOMAIN_ACCESSTOKEN, "TokenSyncManagerService"};
}

const bool REGISTER_RESULT =
    SystemAbility::MakeAndRegisterAbility(DelayedSingleton<TokenSyncManagerService>::GetInstance().get());

TokenSyncManagerService::TokenSyncManagerService()
    : SystemAbility(SA_ID_TOKENSYNC_MANAGER_SERVICE, false), state_(ServiceRunningState::STATE_NOT_START)
{
    ACCESSTOKEN_LOG_INFO(LABEL, "TokenSyncManagerService()");
}

TokenSyncManagerService::~TokenSyncManagerService()
{
    ACCESSTOKEN_LOG_INFO(LABEL, "~TokenSyncManagerService()");
}

void TokenSyncManagerService::OnStart()
{
    if (state_ == ServiceRunningState::STATE_RUNNING) {
        ACCESSTOKEN_LOG_INFO(LABEL, "TokenSyncManagerService has already started!");
        return;
    }
    ACCESSTOKEN_LOG_INFO(LABEL, "TokenSyncManagerService is starting");
    if (!Initialize()) {
        ACCESSTOKEN_LOG_ERROR(LABEL, "Failed to initialize");
        return;
    }
    state_ = ServiceRunningState::STATE_RUNNING;
    bool ret = Publish(DelayedSingleton<TokenSyncManagerService>::GetInstance().get());
    if (!ret) {
        ACCESSTOKEN_LOG_ERROR(LABEL, "Failed to publish service!");
        return;
    }
    ACCESSTOKEN_LOG_INFO(LABEL, "Congratulations, TokenSyncManagerService start successfully!");
}

void TokenSyncManagerService::OnStop()
{
    ACCESSTOKEN_LOG_INFO(LABEL, "stop service");
    state_ = ServiceRunningState::STATE_NOT_START;
    SoftBusManager::GetInstance().Destroy();
}

std::shared_ptr<TokenSyncEventHandler> TokenSyncManagerService::GetSendEventHandler() const
{
    return sendHandler_;
}

std::shared_ptr<TokenSyncEventHandler> TokenSyncManagerService::GetRecvEventHandler() const
{
    return recvHandler_;
}

int TokenSyncManagerService::GetRemoteHapTokenInfo(const std::string& deviceID, AccessTokenID tokenID)
{
    if (!DataValidator::IsDeviceIdValid(deviceID) || tokenID == 0) {
        ACCESSTOKEN_LOG_INFO(LABEL, "Params is wrong.");
        return TOKEN_SYNC_PARAMS_INVALID;
    }
    DeviceInfo devInfo;
    bool result = DeviceInfoRepository::GetInstance().FindDeviceInfo(deviceID, DeviceIdType::UNKNOWN, devInfo);
    if (!result) {
        ACCESSTOKEN_LOG_INFO(LABEL, "FindDeviceInfo failed");
        return TOKEN_SYNC_REMOTE_DEVICE_INVALID;
    }
    std::string udid = devInfo.deviceId.uniqueDeviceId;
    const std::shared_ptr<SyncRemoteHapTokenCommand> syncRemoteHapTokenCommand =
        RemoteCommandFactory::GetInstance().NewSyncRemoteHapTokenCommand(ConstantCommon::GetLocalDeviceId(),
        deviceID, tokenID);

    const int32_t resultCode = RemoteCommandManager::GetInstance().ExecuteCommand(udid, syncRemoteHapTokenCommand);
    if (resultCode != Constant::SUCCESS) {
        ACCESSTOKEN_LOG_INFO(LABEL,
            "RemoteExecutorManager executeCommand SyncRemoteHapTokenCommand failed, return %{public}d", resultCode);
        return TOKEN_SYNC_COMMAND_EXECUTE_FAILED;
    }
    ACCESSTOKEN_LOG_INFO(LABEL, "get resultCode: %{public}d", resultCode);
    return TOKEN_SYNC_SUCCESS;
}

int TokenSyncManagerService::DeleteRemoteHapTokenInfo(AccessTokenID tokenID)
{
    if (tokenID == 0) {
        ACCESSTOKEN_LOG_INFO(LABEL, "Params is wrong, token id is invalid.");
        return TOKEN_SYNC_PARAMS_INVALID;
    }

    std::vector<DeviceInfo> devices = DeviceInfoRepository::GetInstance().ListDeviceInfo();
    std::string localUdid = ConstantCommon::GetLocalDeviceId();
    for (const DeviceInfo& device : devices) {
        if (device.deviceId.uniqueDeviceId == localUdid) {
            ACCESSTOKEN_LOG_INFO(LABEL, "no need notify local device");
            continue;
        }
        const std::shared_ptr<DeleteRemoteTokenCommand> deleteRemoteTokenCommand =
            RemoteCommandFactory::GetInstance().NewDeleteRemoteTokenCommand(ConstantCommon::GetLocalDeviceId(),
            device.deviceId.uniqueDeviceId, tokenID);

        const int32_t resultCode = RemoteCommandManager::GetInstance().ExecuteCommand(
            device.deviceId.uniqueDeviceId, deleteRemoteTokenCommand);
        if (resultCode != Constant::SUCCESS) {
            ACCESSTOKEN_LOG_INFO(LABEL,
                "RemoteExecutorManager executeCommand DeleteRemoteTokenCommand failed, return %{public}d", resultCode);
            continue;
        }
        ACCESSTOKEN_LOG_INFO(LABEL, "get resultCode: %{public}d", resultCode);
    }
    return TOKEN_SYNC_SUCCESS;
}

int TokenSyncManagerService::UpdateRemoteHapTokenInfo(const HapTokenInfoForSync& tokenInfo)
{
    std::vector<DeviceInfo> devices = DeviceInfoRepository::GetInstance().ListDeviceInfo();
    std::string localUdid = ConstantCommon::GetLocalDeviceId();
    for (const DeviceInfo& device : devices) {
        if (device.deviceId.uniqueDeviceId == localUdid) {
            ACCESSTOKEN_LOG_INFO(LABEL, "no need notify local device");
            continue;
        }

        const std::shared_ptr<UpdateRemoteHapTokenCommand> updateRemoteHapTokenCommand =
            RemoteCommandFactory::GetInstance().NewUpdateRemoteHapTokenCommand(ConstantCommon::GetLocalDeviceId(),
            device.deviceId.uniqueDeviceId, tokenInfo);

        const int32_t resultCode = RemoteCommandManager::GetInstance().ExecuteCommand(
            device.deviceId.uniqueDeviceId, updateRemoteHapTokenCommand);
        if (resultCode != Constant::SUCCESS) {
            ACCESSTOKEN_LOG_INFO(LABEL,
                "RemoteExecutorManager executeCommand updateRemoteHapTokenCommand failed, return %{public}d",
                resultCode);
            continue;
        }
        ACCESSTOKEN_LOG_INFO(LABEL, "get resultCode: %{public}d", resultCode);
    }

    return TOKEN_SYNC_SUCCESS;
}

bool TokenSyncManagerService::Initialize()
{
    sendRunner_ = AppExecFwk::EventRunner::Create(true);
    if (!sendRunner_) {
        ACCESSTOKEN_LOG_ERROR(LABEL, "failed to create a sendRunner.");
        return false;
    }

    sendHandler_ = std::make_shared<TokenSyncEventHandler>(sendRunner_);
    if (!sendHandler_) {
        ACCESSTOKEN_LOG_ERROR(LABEL, "sendHandler_ is nullptr.");
        return false;
    }

    recvRunner_ = AppExecFwk::EventRunner::Create(true);
    if (!recvRunner_) {
        ACCESSTOKEN_LOG_ERROR(LABEL, "failed to create a recvRunner.");
        return false;
    }

    recvHandler_ = std::make_shared<TokenSyncEventHandler>(recvRunner_);
    if (!recvHandler_) {
        ACCESSTOKEN_LOG_ERROR(LABEL, "recvHandler_ is nullptr.");
        return false;
    }

    SoftBusManager::GetInstance().Initialize();
    return true;
}
} // namespace AccessToken
} // namespace Security
} // namespace OHOS
