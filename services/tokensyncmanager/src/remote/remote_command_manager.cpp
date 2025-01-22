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
#ifdef EVENTHANDLER_ENABLE
#include "access_event_handler.h"
#endif
#include "device_info_manager.h"
#include "remote_command_factory.h"
#include "token_sync_manager_service.h"
#include "accesstoken_kit.h"
#include "constant_common.h"

namespace OHOS {
namespace Security {
namespace AccessToken {
namespace {
std::recursive_mutex g_instanceMutex;
}
RemoteCommandManager::RemoteCommandManager() : executors_(), mutex_()
{
    LOGD(ATM_DOMAIN, ATM_TAG, "RemoteCommandManager()");
}

RemoteCommandManager::~RemoteCommandManager()
{
    LOGD(ATM_DOMAIN, ATM_TAG, "~RemoteCommandManager()");
}

RemoteCommandManager &RemoteCommandManager::GetInstance()
{
    static RemoteCommandManager* instance = nullptr;
    if (instance == nullptr) {
        std::lock_guard<std::recursive_mutex> lock(g_instanceMutex);
        if (instance == nullptr) {
            RemoteCommandManager* tmp = new RemoteCommandManager();
            instance = std::move(tmp);
        }
    }
    return *instance;
}

void RemoteCommandManager::Init()
{
    LOGD(ATM_DOMAIN, ATM_TAG, "Init()");
}

int RemoteCommandManager::AddCommand(const std::string &udid, const std::shared_ptr<BaseRemoteCommand>& command)
{
    if (udid.empty() || command == nullptr) {
        LOGW(ATM_DOMAIN, ATM_TAG, "Invalid udid, or null command");
        return Constant::FAILURE;
    }
    LOGI(ATM_DOMAIN, ATM_TAG, "Add uniqueId");

    std::shared_ptr<RemoteCommandExecutor> executor = GetOrCreateRemoteCommandExecutor(udid);
    if (executor == nullptr) {
        LOGE(ATM_DOMAIN, ATM_TAG, "Cannot get or create remote command executor");
        return Constant::FAILURE;
    }

    int result = executor->AddCommand(command);
    LOGI(ATM_DOMAIN, ATM_TAG, "Add command result: %{public}d ", result);
    return result;
}

void RemoteCommandManager::RemoveCommand(const std::string &udid)
{
    LOGI(ATM_DOMAIN, ATM_TAG, "Remove command");
    executors_.erase(udid);
}

int RemoteCommandManager::ExecuteCommand(const std::string &udid, const std::shared_ptr<BaseRemoteCommand>& command)
{
    if (udid.empty() || command == nullptr) {
        LOGW(ATM_DOMAIN, ATM_TAG, "Invalid udid: %{public}s, or null command",
            ConstantCommon::EncryptDevId(udid).c_str());
        return Constant::FAILURE;
    }
    std::string uniqueId = command->remoteProtocol_.uniqueId;
    LOGI(ATM_DOMAIN, ATM_TAG, "Start with udid: %{public}s , uniqueId: %{public}s ",
        ConstantCommon::EncryptDevId(udid).c_str(), ConstantCommon::EncryptDevId(uniqueId).c_str());

    std::shared_ptr<RemoteCommandExecutor> executor = GetOrCreateRemoteCommandExecutor(udid);
    if (executor == nullptr) {
        LOGE(ATM_DOMAIN, ATM_TAG, "Cannot get or create remote command executor");
        return Constant::FAILURE;
    }

    int result = executor->ProcessOneCommand(command);
    LOGI(ATM_DOMAIN, ATM_TAG, "RemoteCommandExecutor processOneCommand result:%{public}d ", result);
    return result;
}

int RemoteCommandManager::ProcessDeviceCommandImmediately(const std::string &udid)
{
    if (udid.empty()) {
        LOGW(ATM_DOMAIN, ATM_TAG, "Invalid udid: %{public}s", ConstantCommon::EncryptDevId(udid).c_str());
        return Constant::FAILURE;
    }
    LOGI(ATM_DOMAIN, ATM_TAG, "Start with udid:%{public}s ", ConstantCommon::EncryptDevId(udid).c_str());

    std::unique_lock<std::mutex> lock(mutex_);
    auto executorIt = executors_.find(udid);
    if (executorIt == executors_.end()) {
        LOGE(ATM_DOMAIN, ATM_TAG, "No executor found, udid:%{public}s", ConstantCommon::EncryptDevId(udid).c_str());
        return Constant::FAILURE;
    }

    auto executor = executorIt->second;
    if (executor == nullptr) {
        LOGI(ATM_DOMAIN, ATM_TAG, "RemoteCommandExecutor is null for udid %{public}s ",
            ConstantCommon::EncryptDevId(udid).c_str());
        return Constant::FAILURE;
    }

    int result = executor->ProcessBufferedCommands();
    LOGI(ATM_DOMAIN, ATM_TAG, "ProcessBufferedCommands result: %{public}d", result);
    return result;
}

int RemoteCommandManager::Loop()
{
    LOGI(ATM_DOMAIN, ATM_TAG, "Start");
    std::unique_lock<std::mutex> lock(mutex_);
    for (auto it = executors_.begin(); it != executors_.end(); it++) {
        LOGI(ATM_DOMAIN, ATM_TAG, "Udid:%{public}s", ConstantCommon::EncryptDevId(it->first).c_str());
        (*it).second->ProcessBufferedCommandsWithThread();
    }
    return Constant::SUCCESS;
}

/**
 * caller: service connection listener
 */
void RemoteCommandManager::Clear()
{
    LOGI(ATM_DOMAIN, ATM_TAG, "Remove all remote command executors.");

    std::map<std::string, std::shared_ptr<RemoteCommandExecutor>> dummy;
    std::unique_lock<std::mutex> lock(mutex_);
    executors_.swap(dummy);
    executors_.clear();
}

/**
 * caller: device listener
 */
int RemoteCommandManager::NotifyDeviceOnline(const std::string &nodeId)
{
    if (!DataValidator::IsDeviceIdValid(nodeId)) {
        LOGI(ATM_DOMAIN, ATM_TAG, "Invalid nodeId: %{public}s", ConstantCommon::EncryptDevId(nodeId).c_str());
        return Constant::FAILURE;
    }
    LOGI(ATM_DOMAIN, ATM_TAG, "Operation start with nodeId:  %{public}s",
        ConstantCommon::EncryptDevId(nodeId).c_str());

    auto executor = GetOrCreateRemoteCommandExecutor(nodeId);
    std::unique_lock<std::mutex> lock(mutex_);
    if (executor == nullptr) {
        LOGE(ATM_DOMAIN, ATM_TAG, "Cannot get or create remote command executor");
        return Constant::FAILURE;
    }

    if (executor->GetChannel() == nullptr) {
        auto channel = RemoteCommandExecutor::CreateChannel(nodeId);
        if (channel == nullptr) {
            LOGE(ATM_DOMAIN, ATM_TAG, "Create channel failed.");
            return Constant::FAILURE;
        }
        executor->SetChannel(channel);
    }

    lock.unlock();

    return Constant::SUCCESS;
}

/**
 * caller: device listener
 */
int RemoteCommandManager::NotifyDeviceOffline(const std::string &nodeId)
{
    if (!DataValidator::IsDeviceIdValid(nodeId)) {
        LOGI(ATM_DOMAIN, ATM_TAG, "Invalid nodeId: %{public}s", ConstantCommon::EncryptDevId(nodeId).c_str());
        return Constant::FAILURE;
    }
    LOGI(ATM_DOMAIN, ATM_TAG, "Operation start with nodeId:  %{public}s",
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
        LOGI(ATM_DOMAIN, ATM_TAG, "Get remote networkId failed");
        return Constant::FAILURE;
    }
    std::string uniqueDeviceId = devInfo.deviceId.uniqueDeviceId;
    std::function<void()> delayed = ([uniqueDeviceId]() {
        AccessTokenKit::DeleteRemoteDeviceTokens(uniqueDeviceId);
    });

#ifdef EVENTHANDLER_ENABLE
    std::shared_ptr<AccessEventHandler> handler =
        DelayedSingleton<TokenSyncManagerService>::GetInstance()->GetSendEventHandler();
    if (handler == nullptr) {
        LOGE(ATM_DOMAIN, ATM_TAG, "Fail to get EventHandler");
        return Constant::FAILURE;
    }
    handler->ProxyPostTask(delayed, "HandleDeviceOffline");
#endif

    LOGI(ATM_DOMAIN, ATM_TAG, "Complete");
    return Constant::SUCCESS;
}

std::shared_ptr<RemoteCommandExecutor> RemoteCommandManager::GetOrCreateRemoteCommandExecutor(const std::string &nodeId)
{
    LOGD(ATM_DOMAIN, ATM_TAG, "Begin, nodeId %{public}s", ConstantCommon::EncryptDevId(nodeId).c_str());

    std::unique_lock<std::mutex> lock(mutex_);
    auto executorIter = executors_.find(nodeId);
    if (executorIter != executors_.end()) {
        return executorIter->second;
    }

    auto executor = std::make_shared<RemoteCommandExecutor>(nodeId);
    executors_.insert(std::pair<std::string, std::shared_ptr<RemoteCommandExecutor>>(nodeId, executor));
    LOGD(ATM_DOMAIN, ATM_TAG, "Executor added, nodeId: %{public}s", ConstantCommon::EncryptDevId(nodeId).c_str());
    return executor;
}

/**
 * caller: session listener(OnBytes)
 */
std::shared_ptr<RpcChannel> RemoteCommandManager::GetExecutorChannel(const std::string &nodeId)
{
    LOGD(ATM_DOMAIN, ATM_TAG, "Convert udid start, nodeId:%{public}s", ConstantCommon::EncryptDevId(nodeId).c_str());
    std::string udid = DeviceInfoManager::GetInstance().ConvertToUniqueDeviceIdOrFetch(nodeId);
    if (!DataValidator::IsDeviceIdValid(udid)) {
        LOGW(ATM_DOMAIN, ATM_TAG, "Converted udid is invalid, nodeId:%{public}s",
            ConstantCommon::EncryptDevId(nodeId).c_str());
        return nullptr;
    }

    std::unique_lock<std::mutex> lock(mutex_);
    std::map<std::string, std::shared_ptr<RemoteCommandExecutor>>::iterator iter = executors_.find(udid);
    if (iter == executors_.end()) {
        LOGI(ATM_DOMAIN, ATM_TAG, "Executor not found");
        return nullptr;
    }
    std::shared_ptr<RemoteCommandExecutor> executor = iter->second;
    if (executor == nullptr) {
        LOGI(ATM_DOMAIN, ATM_TAG, "Executor is null");
        return nullptr;
    }
    return executor->GetChannel();
}
}  // namespace AccessToken
}  // namespace Security
}  // namespace OHOS
