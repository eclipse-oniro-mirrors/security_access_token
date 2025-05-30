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

#include "remote_command_executor.h"
#ifdef EVENTHANDLER_ENABLE
#include "access_event_handler.h"
#endif
#include "constant_common.h"
#include "device_info_manager.h"
#include "singleton.h"
#include "soft_bus_channel.h"
#include "soft_bus_manager.h"
#include "token_sync_manager_service.h"

namespace OHOS {
namespace Security {
namespace AccessToken {
namespace {
static const std::string TASK_NAME = "RemoteCommandExecutor::ProcessBufferedCommandsWithThread";
}  // namespace
RemoteCommandExecutor::RemoteCommandExecutor(const std::string &targetNodeId)
    : targetNodeId_(targetNodeId), ptrChannel_(nullptr), mutex_(), commands_(), running_(false)
{
    LOGD(ATM_DOMAIN, ATM_TAG, "RemoteCommandExecutor()");
}

RemoteCommandExecutor::~RemoteCommandExecutor()
{
    LOGD(ATM_DOMAIN, ATM_TAG, "~RemoteCommandExecutor() begin");
    running_ = false;
}

const std::shared_ptr<RpcChannel> RemoteCommandExecutor::CreateChannel(const std::string &targetNodeId)
{
    LOGD(ATM_DOMAIN, ATM_TAG, "CreateChannel: targetNodeId=%{public}s",
        ConstantCommon::EncryptDevId(targetNodeId).c_str());
    // only consider SoftBusChannel
    std::shared_ptr<RpcChannel> ptrChannel = std::make_shared<SoftBusChannel>(targetNodeId);
    return ptrChannel;
}

/*
 * called by RemoteCommandExecutor, RemoteCommandManager
 */
int RemoteCommandExecutor::ProcessOneCommand(const std::shared_ptr<BaseRemoteCommand>& ptrCommand)
{
    if (ptrCommand == nullptr) {
        LOGW(ATM_DOMAIN, ATM_TAG, "TargetNodeId %{public}s, attempt to process on null command.",
            ConstantCommon::EncryptDevId(targetNodeId_).c_str());
        return Constant::SUCCESS;
    }
    const std::string uniqueId = ptrCommand->remoteProtocol_.uniqueId;
    LOGI(ATM_DOMAIN, ATM_TAG, "TargetNodeId %{public}s, process one command start, uniqueId: %{public}s",
        ConstantCommon::EncryptDevId(targetNodeId_).c_str(), uniqueId.c_str());

    ptrCommand->Prepare();
    int status = ptrCommand->remoteProtocol_.statusCode;
    if (status != Constant::SUCCESS) {
        LOGE(ATM_DOMAIN, ATM_TAG,
            "targetNodeId %{public}s, process one command error, uniqueId: %{public}s, message: "
            "prepare failure code %{public}d", ConstantCommon::EncryptDevId(targetNodeId_).c_str(),
            uniqueId.c_str(), status);
        return status;
    }

    std::string localUdid = ConstantCommon::GetLocalDeviceId();
    if (targetNodeId_ == localUdid) {
        return ExecuteRemoteCommand(ptrCommand, false);
    }

    // otherwise a remote device
    CreateChannelIfNeeded();
    if (ptrChannel_ == nullptr) {
        LOGE(ATM_DOMAIN, ATM_TAG, "TargetNodeId %{public}s, channel is null.",
            ConstantCommon::EncryptDevId(targetNodeId_).c_str());
        return Constant::FAILURE;
    }
    if (ptrChannel_->BuildConnection() != Constant::SUCCESS) {
        LOGE(ATM_DOMAIN, ATM_TAG, "TargetNodeId %{public}s, channel is not ready.",
            ConstantCommon::EncryptDevId(targetNodeId_).c_str());
        return Constant::FAILURE;
    }

    return ExecuteRemoteCommand(ptrCommand, true);
}

/*
 * called by RemoteCommandManager
 */
int RemoteCommandExecutor::AddCommand(const std::shared_ptr<BaseRemoteCommand>& ptrCommand)
{
    if (ptrCommand == nullptr) {
        LOGD(ATM_DOMAIN, ATM_TAG, "TargetNodeId %{public}s, attempt to add an empty command.",
            ConstantCommon::EncryptDevId(targetNodeId_).c_str());
        return Constant::INVALID_COMMAND;
    }

    const std::string uniqueId = ptrCommand->remoteProtocol_.uniqueId;
    LOGD(ATM_DOMAIN, ATM_TAG, "TargetNodeId %{public}s, add uniqueId %{public}s",
        ConstantCommon::EncryptDevId(targetNodeId_).c_str(), uniqueId.c_str());

    std::unique_lock<std::recursive_mutex> lock(mutex_);

    // make sure do not have the same command in the command buffer
    if (std::any_of(commands_.begin(), commands_.end(),
        [uniqueId](const auto& buffCommand) {return buffCommand->remoteProtocol_.uniqueId == uniqueId; })) {
            LOGW(ATM_DOMAIN, ATM_TAG,
                "targetNodeId %{public}s, add uniqueId %{public}s, already exist in the buffer, skip",
                ConstantCommon::EncryptDevId(targetNodeId_).c_str(),
                uniqueId.c_str());
            return Constant::SUCCESS;
    }

    commands_.push_back(ptrCommand);
    return Constant::SUCCESS;
}

/*
 * called by RemoteCommandExecutor.ProcessCommandThread, RemoteCommandManager
 */
int RemoteCommandExecutor::ProcessBufferedCommands(bool standalone)
{
    LOGI(ATM_DOMAIN, ATM_TAG, "Begin, targetNodeId: %{public}s, standalone: %{public}d",
        ConstantCommon::EncryptDevId(targetNodeId_).c_str(), standalone);

    std::unique_lock<std::recursive_mutex> lock(mutex_);

    if (commands_.empty()) {
        LOGW(ATM_DOMAIN, ATM_TAG, "No command, targetNodeId %{public}s",
            ConstantCommon::EncryptDevId(targetNodeId_).c_str());
        running_ = false;
        return Constant::SUCCESS;
    }

    running_ = true;
    while (true) {
        // interrupt
        if (!running_) {
            LOGI(ATM_DOMAIN, ATM_TAG, "End with running flag == false, targetNodeId: %{public}s",
                ConstantCommon::EncryptDevId(targetNodeId_).c_str());
            return Constant::FAILURE;
        }
        // end
        if (commands_.empty()) {
            running_ = false;
            LOGI(ATM_DOMAIN, ATM_TAG, "End, no command left, targetNodeId: %{public}s",
                ConstantCommon::EncryptDevId(targetNodeId_).c_str());
            return Constant::SUCCESS;
        }

        // consume queue to execute
        const std::shared_ptr<BaseRemoteCommand> bufferedCommand = commands_.front();
        int status = ProcessOneCommand(bufferedCommand);
        if (status == Constant::SUCCESS) {
            commands_.pop_front();
            continue;
        } else if (status == Constant::FAILURE_BUT_CAN_RETRY) {
            LOGW(ATM_DOMAIN, ATM_TAG,
                "execute failed and wait to retry, targetNodeId: %{public}s, message: %{public}s, and will retry ",
                ConstantCommon::EncryptDevId(targetNodeId_).c_str(),
                bufferedCommand->remoteProtocol_.message.c_str());

            // now, the retry at once will have no effective because the network problem
            // so if the before the step, one command is added, and run this function
            // it should also not need to restart to process the commands buffer at once.
            running_ = false;
            return Constant::FAILURE;
        } else {
            // this command failed, move on to execute next command
            commands_.pop_front();
            LOGE(ATM_DOMAIN, ATM_TAG,
                "execute failed, targetNodeId: %{public}s, commandName: %{public}s, message: %{public}s",
                ConstantCommon::EncryptDevId(targetNodeId_).c_str(),
                bufferedCommand->remoteProtocol_.commandName.c_str(),
                bufferedCommand->remoteProtocol_.message.c_str());
        }
    }
}

/*
 * called by RemoteCommandManager
 */
void RemoteCommandExecutor::ProcessBufferedCommandsWithThread()
{
    LOGI(ATM_DOMAIN, ATM_TAG, "Begin, targetNodeId: %{public}s", ConstantCommon::EncryptDevId(targetNodeId_).c_str());

    std::unique_lock<std::recursive_mutex> lock(mutex_);

    if (commands_.empty()) {
        LOGI(ATM_DOMAIN, ATM_TAG, "No buffered commands. targetNodeId: %{public}s",
            ConstantCommon::EncryptDevId(targetNodeId_).c_str());
        return;
    }
    if (running_) {
        // task is running, do not need to start one more
        LOGW(ATM_DOMAIN, ATM_TAG, "Task busy. targetNodeId: %{public}s",
            ConstantCommon::EncryptDevId(targetNodeId_).c_str());
        return;
    }

    running_ = true;
    const std::function<void()> runner = [weak = weak_from_this()]() {
        auto self = weak.lock();
        if (self == nullptr) {
            LOGE(ATM_DOMAIN, ATM_TAG, "RemoteCommandExecutor is nullptr");
            return;
        }
        self->ProcessBufferedCommands(true);
    };

#ifdef EVENTHANDLER_ENABLE
    std::shared_ptr<AccessEventHandler> handler =
        DelayedSingleton<TokenSyncManagerService>::GetInstance()->GetSendEventHandler();
    if (handler == nullptr) {
        LOGE(ATM_DOMAIN, ATM_TAG, "Fail to get EventHandler");
        return;
    }
    bool result = handler->ProxyPostTask(runner, TASK_NAME);
    if (!result) {
        LOGE(ATM_DOMAIN, ATM_TAG, "Post task failed, targetNodeId: %{public}s",
            ConstantCommon::EncryptDevId(targetNodeId_).c_str());
    }
#endif
    LOGI(ATM_DOMAIN, ATM_TAG,
        "post task succeed, targetNodeId: %{public}s, taskName: %{public}s",
        ConstantCommon::EncryptDevId(targetNodeId_).c_str(),
        TASK_NAME.c_str());
}

int RemoteCommandExecutor::ExecuteRemoteCommand(
    const std::shared_ptr<BaseRemoteCommand>& ptrCommand, const bool isRemote)
{
    std::string uniqueId = ptrCommand->remoteProtocol_.uniqueId;
    LOGI(ATM_DOMAIN, ATM_TAG, "TargetNodeId %{public}s, uniqueId %{public}s, remote %{public}d: start to execute.",
        ConstantCommon::EncryptDevId(targetNodeId_).c_str(), uniqueId.c_str(), isRemote);

    ptrCommand->remoteProtocol_.statusCode = Constant::STATUS_CODE_BEFORE_RPC;

    if (!isRemote) {
        // Local device, play myself.
        ptrCommand->Execute();
        int code = ClientProcessResult(ptrCommand);
        LOGD(ATM_DOMAIN, ATM_TAG, "Command finished with status: %{public}d, message: %{public}s.",
            ptrCommand->remoteProtocol_.statusCode, ptrCommand->remoteProtocol_.message.c_str());
        return code;
    }

    LOGI(ATM_DOMAIN, ATM_TAG, "Command executed uniqueId %{public}s.", uniqueId.c_str());

    std::string responseString;
    int32_t repeatTimes = SoftBusManager::GetInstance().GetRepeatTimes(); // repeat 5 times if responseString empty
    for (int32_t i = 0; i < repeatTimes; ++i) {
        responseString = ptrChannel_->ExecuteCommand(ptrCommand->remoteProtocol_.commandName,
            ptrCommand->ToJsonPayload());
        if (!responseString.empty()) {
            break; // when responseString is not empty, break the loop
        }

        LOGW(ATM_DOMAIN, ATM_TAG,
            "TargetNodeId %{public}s, uniqueId %{public}s, execute remote command error, response is empty.",
            ConstantCommon::EncryptDevId(targetNodeId_).c_str(), uniqueId.c_str());
    }
    
    if (responseString.empty()) {
        if (commands_.empty()) {
            ptrChannel_->CloseConnection(); // if command send failed, also try to close session
        }
        return Constant::FAILURE;
    }

    std::shared_ptr<BaseRemoteCommand> ptrResponseCommand =
        RemoteCommandFactory::GetInstance().NewRemoteCommandFromJson(
            ptrCommand->remoteProtocol_.commandName, responseString);
    if (ptrResponseCommand == nullptr) {
        LOGE(ATM_DOMAIN, ATM_TAG, "TargetNodeId %{public}s, get null response command!",
            ConstantCommon::EncryptDevId(targetNodeId_).c_str());
        return Constant::FAILURE;
    }
    int32_t result = ClientProcessResult(ptrResponseCommand);
    if (commands_.empty()) {
        ptrChannel_->CloseConnection();
    }
    LOGD(ATM_DOMAIN, ATM_TAG, "Command finished with status: %{public}d, message: %{public}s.",
        ptrResponseCommand->remoteProtocol_.statusCode, ptrResponseCommand->remoteProtocol_.message.c_str());
    return result;
}

void RemoteCommandExecutor::CreateChannelIfNeeded()
{
    std::unique_lock<std::recursive_mutex> lock(mutex_);
    if (ptrChannel_ != nullptr) {
        LOGI(ATM_DOMAIN, ATM_TAG, "TargetNodeId %{public}s, channel is exist.",
            ConstantCommon::EncryptDevId(targetNodeId_).c_str());
        return;
    }

    ptrChannel_ = CreateChannel(targetNodeId_);
}

int RemoteCommandExecutor::ClientProcessResult(const std::shared_ptr<BaseRemoteCommand>& ptrCommand)
{
    std::string uniqueId = ptrCommand->remoteProtocol_.uniqueId;
    if (ptrCommand->remoteProtocol_.statusCode == Constant::STATUS_CODE_BEFORE_RPC) {
        LOGE(ATM_DOMAIN, ATM_TAG,
            "targetNodeId %{public}s, uniqueId %{public}s, status code after RPC is same as before, the remote side "
            "may not "
            "support this command",
            ConstantCommon::EncryptDevId(targetNodeId_).c_str(),
            uniqueId.c_str());
        return Constant::FAILURE;
    }

    ptrCommand->Finish();
    int status = ptrCommand->remoteProtocol_.statusCode;
    if (status != Constant::SUCCESS) {
        LOGE(ATM_DOMAIN, ATM_TAG,
            "targetNodeId %{public}s, uniqueId %{public}s, execute failed, message: %{public}s",
            ConstantCommon::EncryptDevId(targetNodeId_).c_str(),
            uniqueId.c_str(),
            ptrCommand->remoteProtocol_.message.c_str());
    } else {
        LOGI(ATM_DOMAIN, ATM_TAG,
            "targetNodeId %{public}s, uniqueId %{public}s, execute succeed.",
            ConstantCommon::EncryptDevId(targetNodeId_).c_str(),
            uniqueId.c_str());
    }
    return status;
}
}  // namespace AccessToken
}  // namespace Security
}  // namespace OHOS
