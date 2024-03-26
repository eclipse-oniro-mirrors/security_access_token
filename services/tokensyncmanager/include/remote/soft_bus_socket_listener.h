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

#ifndef SOFT_BUS_SOCKET_LISTENER_H
#define SOFT_BUS_SOCKET_LISTENER_H

#include <map>
#include <mutex>
#include <string>

#include "socket.h"

namespace OHOS {
namespace Security {
namespace AccessToken {
class SoftBusSocketListener final {
public:
    static void OnBind(int32_t socket, PeerSocketInfo info);
    static void OnShutdown(int32_t socket, ShutdownReason reason);
    static void OnClientBytes(int32_t socket, const void *data, uint32_t dataLen);
    static void OnServiceBytes(int32_t socket, const void *data, uint32_t dataLen);
    // this callback softbus not ready
    static void OnQos(int32_t socket, QoSEvent eventId, const QosTV *qos, uint32_t qosCount) {};
    static void CleanUpAllBindSocket();

private:
    static std::mutex socketMutex_;
    static std::map<int32_t, std::string> socketBindMap_;

    static bool GetNetworkIdBySocket(const int32_t socket, std::string& networkId);
};
} // namespace AccessToken
} // namespace Security
} // namespace OHOS
#endif // SOFT_BUS_SOCKET_LISTENER_H
