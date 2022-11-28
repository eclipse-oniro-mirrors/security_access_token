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

#include "remote_command_manager.h"
#include <thread>
#include "device_info_manager.h"
#include "sync_remote_native_token_command.h"
#include "remote_command_factory.h"
#include "token_sync_event_handler.h"
#include "token_sync_manager_service.h"
#include "accesstoken_kit.h"
#include "constant_common.h"

namespace OHOS {
namespace Security {
namespace AccessToken {
namespace {
static constexpr OHOS::HiviewDFX::HiLogLabel LABEL = {LOG_CORE, SECURITY_DOMAIN_ACCESSTOKEN, "RemoteCommandManager"};
}
RemoteCommandManager::RemoteCommandManager() : executors_(), mutex_()
{
    ACCESSTOKEN_LOG_DEBUG(LABEL, "RemoteCommandManager()");
}

RemoteCommandManager::~RemoteCommandManager()
{
    ACCESSTOKEN_LOG_DEBUG(LABEL, "~RemoteCommandManager()");
}

RemoteCommandManager &RemoteCommandManager::GetInstance()
{
    static RemoteCommandManager instance;
    return instance;
}

void RemoteCommandManager::Init()
{
    ACCESSTOKEN_LOG_DEBUG(LABEL, "Init()");
}

int RemoteCommandManager::AddCommand(const std::string &udid, const std::shared_ptr<BaseRemoteCommand>& command)
{
    if (udid.empty() || command == nullptr) {
        ACCESSTOKEN_LOG_WARN(LABEL, "invalid udid, or null command");
        return Constant::FAILURE;
    }
    ACCESSTOKEN_LOG_INFO(LABEL, "add uniqueId");

    std::shared_ptr<RemoteCommandExecutor> executor = GetOrCreateRemoteCommandExecutor(udid);
    if (executor == nullptr) {
        ACCESSTOKEN_LOG_ERROR(LABEL, "cannot get or create remote command executor");
        return Constant::FAILURE;
    }

    int result = executor->AddCommand(command);
    ACCESSTOKEN_LOG_INFO(LABEL, "add command result: %{public}d ", result);
    return result;
}

void RemoteCommandManager::RemoveCommand(const std::string &udid)
{
    ACCESSTOKEN_LOG_INFO(LABEL, "remove command");
    executors_.erase(udid);
}

int RemoteCommandManager::ExecuteCommand(const std::string &udid, const std::shared_ptr<BaseRemoteCommand>& command)
{
    if (udid.empty() || command == nullptr) {
        ACCESSTOKEN_LOG_WARN(LABEL, "invalid udid: %{public}s, or null command",
            ConstantCommon::EncryptDevId(udid).c_str());
        return Constant::FAILURE;
    }
    std::string uniqueId = command->remoteProtocol_.uniqueId;
    ACCESSTOKEN_LOG_INFO(LABEL, "start with udid: %{public}s , uniqueId: %{public}s ",
        ConstantCommon::EncryptDevId(udid).c_str(), uniqueId.c_str());

    std::shared_ptr<RemoteCommandExecutor> executor = GetOrCreateRemoteCommandExecutor(udid);
    if (executor == nullptr) {
        ACCESSTOKEN_LOG_ERROR(LABEL, "cannot get or create remote command executor");
        return Constant::FAILURE;
    }

    int result = executor->ProcessOneCommand(command);
    ACCESSTOKEN_LOG_INFO(LABEL, "remoteCommandExecutor processOneCommand result:%{public}d ", result);
    return result;
}

int RemoteCommandManager::ProcessDeviceCommandImmediately(const std::string &udid)
{
    if (udid.empty()) {
        ACCESSTOKEN_LOG_WARN(LABEL, "invalid udid: %{public}s", ConstantCommon::EncryptDevId(udid).c_str());
        return Constant::FAILURE;
    }
    ACCESSTOKEN_LOG_INFO(LABEL, "start with udid:%{public}s ", ConstantCommon::EncryptDevId(udid).c_str());
    auto executorIt = executors_.find(udid);
    if (executorIt == executors_.end()) {
        ACCESSTOKEN_LOG_ERROR(LABEL, "no executor found, udid:%{public}s", ConstantCommon::EncryptDevId(udid).c_str());
        return Constant::FAILURE;
    }

    auto executor = executorIt->second;
    if (executor == nullptr) {
        ACCESSTOKEN_LOG_INFO(LABEL, "RemoteCommandExecutor is null for udid %{public}s ",
            ConstantCommon::EncryptDevId(udid).c_str());
        return Constant::FAILURE;
    }

    int result = executor->ProcessBufferedCommands();
    ACCESSTOKEN_LOG_INFO(LABEL, "processBufferedCommands result: %{public}d", result);
    return result;
}

int RemoteCommandManager::Loop()
{
    ACCESSTOKEN_LOG_INFO(LABEL, "start");
    for (auto it = executors_.begin(); it != executors_.end(); it++) {
        ACCESSTOKEN_LOG_INFO(LABEL, "udid:%{public}s", ConstantCommon::EncryptDevId(it->first).c_str());
        (*it).second->ProcessBufferedCommandsWithThread();
    }
    return Constant::SUCCESS;
}

/**
 * caller: service connection listener
 */
void RemoteCommandManager::Clear()
{
    ACCESSTOKEN_LOG_INFO(LABEL, "remove all remote command executors.");

    std::map<std::string, std::shared_ptr<RemoteCommandExecutor>> dummy;
    executors_.swap(dummy);
    executors_.clear();
}

/**
 * caller: device listener
 */
int RemoteCommandManager::NotifyDeviceOnline(const std::string &nodeId)
{
    if (!DataValidator::IsDeviceIdValid(nodeId)) {
        ACCESSTOKEN_LOG_INFO(LABEL, "invalid nodeId: %{public}s", ConstantCommon::EncryptDevId(nodeId).c_str());
        return Constant::FAILURE;
    }
    ACCESSTOKEN_LOG_INFO(LABEL, "operation start with nodeId:  %{public}s",
        ConstantCommon::EncryptDevId(nodeId).c_str());

    auto executor = GetOrCreateRemoteCommandExecutor(nodeId);
    std::unique_lock<std::mutex> lock(mutex_);
    if (executor == nullptr) {
        ACCESSTOKEN_LOG_ERROR(LABEL, "cannot get or create remote command executor");
        return Constant::FAILURE;
    }

    if (executor->GetChannel() == nullptr) {
        auto channel = RemoteCommandExecutor::CreateChannel(nodeId);
        if (channel == nullptr) {
            ACCESSTOKEN_LOG_ERROR(LABEL, "create channel failed.");
            return Constant::FAILURE;
        }
        executor->SetChannel(channel);
    }

    lock.unlock();

    std::function<void()> delayed = ([=]() {
        const std::shared_ptr<SyncRemoteNativeTokenCommand> syncRemoteNativeTokenCommand =
            RemoteCommandFactory::GetInstance().NewSyncRemoteNativeTokenCommand(ConstantCommon::GetLocalDeviceId(),
            nodeId);

        const int32_t resultCode = RemoteCommandManager::GetInstance().ExecuteCommand(
            nodeId, syncRemoteNativeTokenCommand);
        if (resultCode != Constant::SUCCESS) {
            ACCESSTOKEN_LOG_INFO(LABEL,
                "%{public}s: RemoteExecutorManager executeCommand syncRemoteNativeTokenCommand failed, return %d",
                __func__, resultCode);
            return;
        }
    });

    std::shared_ptr<TokenSyncEventHandler> handler =
        DelayedSingleton<TokenSyncManagerService>::GetInstance()->GetSendEventHandler();
    if (handler == nullptr) {
        ACCESSTOKEN_LOG_ERROR(LABEL, "fail to get EventHandler");
        return Constant::FAILURE;
    }
    handler->ProxyPostTask(delayed, "HandleDeviceOnline", Constant::DELAY_SYNC_TOKEN_MS);

    return Constant::SUCCESS;
}

/**
 * caller: device listener
 */
int RemoteCommandManager::NotifyDeviceOffline(const std::string &nodeId)
{
    if (!DataValidator::IsDeviceIdValid(nodeId)) {
        ACCESSTOKEN_LOG_INFO(LABEL, "invalid nodeId: %{public}s", ConstantCommon::EncryptDevId(nodeId).c_str());
        return Constant::FAILURE;
    }
    ACCESSTOKEN_LOG_INFO(LABEL, "operation start with nodeId:  %{public}s",
        ConstantCommon::EncryptDevId(nodeId).c_str());

    auto channel = GetExecutorChannel(nodeId);
    if (channel != nullptr) {
        channel->Release();
    }

    std::unique_lock<std::mutex> lock(mutex_);
    RemoveCommand(nodeId);
    lock.unlock();

    DeviceInfo devInfo;
    bool result = DeviceInfoManager::GetInstance().GetDeviceInfo(nodeId, DeviceIdType::UNKNOWN, devInfo);
    if (!result) {
        ACCESSTOKEN_LOG_INFO(LABEL, "get remote networkId failed");
        return Constant::FAILURE;
    }
    std::string uniqueDeviceId = devInfo.deviceId.uniqueDeviceId;
    std::function<void()> delayed = ([=]() {
        AccessTokenKit::DeleteRemoteDeviceTokens(uniqueDeviceId);
    });

    std::shared_ptr<TokenSyncEventHandler> handler =
        DelayedSingleton<TokenSyncManagerService>::GetInstance()->GetSendEventHandler();
    if (handler == nullptr) {
        ACCESSTOKEN_LOG_ERROR(LABEL, "fail to get EventHandler");
        return Constant::FAILURE;
    }
    handler->ProxyPostTask(delayed, "HandleDeviceOffline");

    ACCESSTOKEN_LOG_INFO(LABEL, "complete");
    return Constant::SUCCESS;
}

std::shared_ptr<RemoteCommandExecutor> RemoteCommandManager::GetOrCreateRemoteCommandExecutor(const std::string &nodeId)
{
    ACCESSTOKEN_LOG_DEBUG(LABEL, "begin, nodeId %{public}s", ConstantCommon::EncryptDevId(nodeId).c_str());

    std::unique_lock<std::mutex> lock(mutex_);
    auto executorIter = executors_.find(nodeId);
    if (executorIter != executors_.end()) {
        return executorIter->second;
    }

    auto executor = std::make_shared<RemoteCommandExecutor>(nodeId);
    if (executor == nullptr) {
        ACCESSTOKEN_LOG_INFO(LABEL, "cannot create remote command executor, nodeId: %{public}s",
            ConstantCommon::EncryptDevId(nodeId).c_str());
        return nullptr;
    }

    executors_.insert(std::pair<std::string, std::shared_ptr<RemoteCommandExecutor>>(nodeId, executor));
    ACCESSTOKEN_LOG_DEBUG(LABEL, "executor added, nodeId: %{public}s", ConstantCommon::EncryptDevId(nodeId).c_str());
    return executor;
}

/**
 * caller: session listener(onBytesReceived), device listener(offline)
 */
std::shared_ptr<RpcChannel> RemoteCommandManager::GetExecutorChannel(const std::string &nodeId)
{
    ACCESSTOKEN_LOG_DEBUG(LABEL, "convert udid start, nodeId:%{public}s", ConstantCommon::EncryptDevId(nodeId).c_str());
    std::string udid = DeviceInfoManager::GetInstance().ConvertToUniqueDeviceIdOrFetch(nodeId);
    if (!DataValidator::IsDeviceIdValid(udid)) {
        ACCESSTOKEN_LOG_WARN(
            LABEL, "converted udid is invalid, nodeId:%{public}s", ConstantCommon::EncryptDevId(nodeId).c_str());
        return nullptr;
    }
    std::map<std::string, std::shared_ptr<RemoteCommandExecutor>>::iterator iter = executors_.find(udid);
    if (iter == executors_.end()) {
        ACCESSTOKEN_LOG_INFO(LABEL, "executor not found");
        return nullptr;
    }
    std::shared_ptr<RemoteCommandExecutor> executor = iter->second;
    if (executor == nullptr) {
        ACCESSTOKEN_LOG_INFO(LABEL, "executor is null");
        return nullptr;
    }
    return executor->GetChannel();
}
}  // namespace AccessToken
}  // namespace Security
}  // namespace OHOS
