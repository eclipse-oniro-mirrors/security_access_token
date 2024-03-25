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

#include "accesstoken_log.h"
#include "constant.h"
#include "remote_command_manager.h"
#include "socket.h"
#include "soft_bus_manager.h"

namespace OHOS {
namespace Security {
namespace AccessToken {
namespace {
static constexpr OHOS::HiviewDFX::HiLogLabel LABEL = {LOG_CORE, SECURITY_DOMAIN_ACCESSTOKEN, "SoftBusSocketListener"};
}
namespace {
static const int32_t MAX_ONBYTES_RECEIVED_DATA_LEN = 1024 * 1024 * 10;
} // namespace

std::mutex SoftBusSocketListener::socketMutex_;
std::map<int32_t, std::string> SoftBusSocketListener::socketBindMap_;

void SoftBusSocketListener::OnBind(int32_t socket, PeerSocketInfo info)
{
    ACCESSTOKEN_LOG_INFO(LABEL, "socket fd is %{public}d.", socket);

    if (socket <= Constant::INVALID_SOCKET_FD) {
        ACCESSTOKEN_LOG_ERROR(LABEL, "socket fb invalid.");
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
    ACCESSTOKEN_LOG_INFO(LABEL, "socket fd %{public}d shutdown because %{public}u.", socket, reason);

    if (socket <= Constant::INVALID_SOCKET_FD) {
        ACCESSTOKEN_LOG_ERROR(LABEL, "socket fb invalid.");
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
        ACCESSTOKEN_LOG_ERROR(LABEL, "socket fb invalid.");
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
    ACCESSTOKEN_LOG_INFO(LABEL, "socket fd %{public}d, recv len %{public}d.", socket, dataLen);

    if ((socket <= Constant::INVALID_SOCKET_FD) || (data == nullptr) ||
        (dataLen == 0) || (dataLen > MAX_ONBYTES_RECEIVED_DATA_LEN)) {
        ACCESSTOKEN_LOG_ERROR(LABEL, "params invalid.");
        return;
    }

    std::string networkId;
    if (!GetNetworkIdBySocket(socket, networkId)) {
        ACCESSTOKEN_LOG_ERROR(LABEL, "socket invalid, bind service first.");
        return;
    }

    // channel create in SoftBusDeviceConnectionListener::OnDeviceOnline->RemoteCommandManager::NotifyDeviceOnline
    auto channel = RemoteCommandManager::GetInstance().GetExecutorChannel(networkId);
    if (channel == nullptr) {
        ACCESSTOKEN_LOG_ERROR(LABEL, "GetExecutorChannel failed");
        return;
    }
    channel->HandleDataReceived(socket, static_cast<unsigned char *>(const_cast<void *>(data)), dataLen);
}

void SoftBusSocketListener::OnServiceBytes(int32_t socket, const void *data, uint32_t dataLen)
{
    ACCESSTOKEN_LOG_INFO(LABEL, "socket fd %{public}d, recv len %{public}d.", socket, dataLen);

    if ((socket <= Constant::INVALID_SOCKET_FD) || (data == nullptr) ||
        (dataLen == 0) || (dataLen > MAX_ONBYTES_RECEIVED_DATA_LEN)) {
        ACCESSTOKEN_LOG_ERROR(LABEL, "params invalid.");
        return;
    }

    std::string networkId;
    if (SoftBusManager::GetInstance().GetNetworkIdBySocket(socket, networkId)) {
        // channel create in SoftBusDeviceConnectionListener::OnDeviceOnline->RemoteCommandManager::NotifyDeviceOnline
        auto channel = RemoteCommandManager::GetInstance().GetExecutorChannel(networkId);
        if (channel == nullptr) {
            ACCESSTOKEN_LOG_ERROR(LABEL, "GetExecutorChannel failed");
            return;
        }
        channel->HandleDataReceived(socket, static_cast<unsigned char *>(const_cast<void *>(data)), dataLen);
    } else {
        ACCESSTOKEN_LOG_ERROR(LABEL, "unkonow socket.");
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
