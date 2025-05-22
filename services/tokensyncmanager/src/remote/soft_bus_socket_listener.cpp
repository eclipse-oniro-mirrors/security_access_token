/*
 * Copyright (c) 2023-2024 Huawei Device Co., Ltd.
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

#include "soft_bus_socket_listener.h"

#include "accesstoken_common_log.h"
#include "constant.h"
#include "remote_command_manager.h"
#include "socket.h"
#include "soft_bus_manager.h"

namespace OHOS {
namespace Security {
namespace AccessToken {
namespace {
static const int32_t MAX_ONBYTES_RECEIVED_DATA_LEN = 1024 * 1024 * 10;
static const std::string TOKEN_SYNC_PACKAGE_NAME = "ohos.security.distributed_access_token";
static const std::string TOKEN_SYNC_SOCKET_NAME = "ohos.security.atm_channel.";
} // namespace

std::mutex SoftBusSocketListener::socketMutex_;
std::map<int32_t, std::string> SoftBusSocketListener::socketBindMap_;

void SoftBusSocketListener::OnBind(int32_t socket, PeerSocketInfo info)
{
    LOGI(ATM_DOMAIN, ATM_TAG, "Socket fd is %{public}d.", socket);

    if (socket <= Constant::INVALID_SOCKET_FD) {
        LOGE(ATM_DOMAIN, ATM_TAG, "Socket fd invalid.");
        return;
    }
    std::string peerSessionName(info.name);
    if (peerSessionName.find(TOKEN_SYNC_SOCKET_NAME) != 0) {
        LOGE(ATM_DOMAIN, ATM_TAG, "Peer session name(%{public}s) is invalid.", info.name);
        return;
    }
    std::string packageName(info.pkgName);
    if (packageName != TOKEN_SYNC_PACKAGE_NAME) {
        LOGE(ATM_DOMAIN, ATM_TAG, "Peer pkgname(%{public}s) is invalid.", info.pkgName);
        return;
    }

    std::string peerNetworkId(info.networkId);
    std::lock_guard<std::mutex> guard(socketMutex_);
    auto iter = socketBindMap_.find(socket);
    if (iter == socketBindMap_.end()) {
        socketBindMap_.insert(std::pair<int32_t, std::string>(socket, peerNetworkId));
    } else {
        iter->second = peerNetworkId;
    }
}

void SoftBusSocketListener::OnShutdown(int32_t socket, ShutdownReason reason)
{
    LOGI(ATM_DOMAIN, ATM_TAG, "Socket fd %{public}d shutdown because %{public}u.", socket, reason);

    if (socket <= Constant::INVALID_SOCKET_FD) {
        LOGE(ATM_DOMAIN, ATM_TAG, "Socket fd invalid.");
        return;
    }

    // clear sessionId state
    std::lock_guard<std::mutex> guard(socketMutex_);
    auto iter = socketBindMap_.find(socket);
    if (iter != socketBindMap_.end()) {
        socketBindMap_.erase(iter);
    }
}

bool SoftBusSocketListener::GetNetworkIdBySocket(const int32_t socket, std::string& networkId)
{
    if (socket <= Constant::INVALID_SOCKET_FD) {
        LOGE(ATM_DOMAIN, ATM_TAG, "Socket fd invalid.");
        return false;
    }

    std::lock_guard<std::mutex> guard(socketMutex_);
    auto iter = socketBindMap_.find(socket);
    if (iter != socketBindMap_.end()) {
        networkId = iter->second;
        return true;
    }
    return false;
}

void SoftBusSocketListener::OnClientBytes(int32_t socket, const void *data, uint32_t dataLen)
{
    LOGI(ATM_DOMAIN, ATM_TAG, "Socket fd %{public}d, recv len %{public}d.", socket, dataLen);

    if ((socket <= Constant::INVALID_SOCKET_FD) || (data == nullptr) ||
        (dataLen == 0) || (dataLen > MAX_ONBYTES_RECEIVED_DATA_LEN)) {
        LOGE(ATM_DOMAIN, ATM_TAG, "Params invalid.");
        return;
    }

    std::string networkId;
    if (!GetNetworkIdBySocket(socket, networkId)) {
        LOGE(ATM_DOMAIN, ATM_TAG, "Socket invalid, bind service first.");
        return;
    }

    // channel create in SoftBusDeviceConnectionListener::OnDeviceOnline->RemoteCommandManager::NotifyDeviceOnline
    auto channel = RemoteCommandManager::GetInstance().GetExecutorChannel(networkId);
    if (channel == nullptr) {
        LOGE(ATM_DOMAIN, ATM_TAG, "GetExecutorChannel failed");
        return;
    }
    channel->HandleDataReceived(socket, static_cast<unsigned char *>(const_cast<void *>(data)), dataLen);
}

void SoftBusSocketListener::OnServiceBytes(int32_t socket, const void *data, uint32_t dataLen)
{
    LOGI(ATM_DOMAIN, ATM_TAG, "Socket fd %{public}d, recv len %{public}d.", socket, dataLen);

    if ((socket <= Constant::INVALID_SOCKET_FD) || (data == nullptr) ||
        (dataLen == 0) || (dataLen > MAX_ONBYTES_RECEIVED_DATA_LEN)) {
        LOGE(ATM_DOMAIN, ATM_TAG, "Params invalid.");
        return;
    }

    std::string networkId;
    if (SoftBusManager::GetInstance().GetNetworkIdBySocket(socket, networkId)) {
        // channel create in SoftBusDeviceConnectionListener::OnDeviceOnline->RemoteCommandManager::NotifyDeviceOnline
        auto channel = RemoteCommandManager::GetInstance().GetExecutorChannel(networkId);
        if (channel == nullptr) {
            LOGE(ATM_DOMAIN, ATM_TAG, "GetExecutorChannel failed");
            return;
        }
        channel->HandleDataReceived(socket, static_cast<unsigned char *>(const_cast<void *>(data)), dataLen);
    } else {
        LOGE(ATM_DOMAIN, ATM_TAG, "Unkonow socket.");
    }
}

void SoftBusSocketListener::CleanUpAllBindSocket()
{
    std::lock_guard<std::mutex> guard(socketMutex_);
    for (auto it = socketBindMap_.begin(); it != socketBindMap_.end();) {
        ::Shutdown(it->first);
        it = socketBindMap_.erase(it);
    }
}
} // namespace AccessToken
} // namespace Security
} // namespace OHOS
