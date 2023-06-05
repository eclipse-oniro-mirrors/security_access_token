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

#include "soft_bus_session_listener.h"
#include "remote_command_manager.h"
#include "soft_bus_manager.h"

namespace OHOS {
namespace Security {
namespace AccessToken {
namespace {
static constexpr OHOS::HiviewDFX::HiLogLabel LABEL = {LOG_CORE, SECURITY_DOMAIN_ACCESSTOKEN, "SoftBusSessionListener"};
}
namespace {
//  Indicates the pointer to the session name, which is the unique ID of the session server. The value cannot be empty
//  and can contain a maximum of 64 characters.
static const int32_t SESSION_NAME_MAXLENGTH = 64;
static const int32_t SESSION_ACCEPTED = 0;
static const int32_t SESSION_REFUSED = -1;
} // namespace

std::mutex SoftBusSessionListener::g_SessionMutex_;
std::map<int32_t, int64_t> SoftBusSessionListener::g_SessionOpenedMap_;

int32_t SoftBusSessionListener::OnSessionOpened(int32_t session, int32_t result)
{
    if (result != Constant::SUCCESS) {
        ACCESSTOKEN_LOG_ERROR(LABEL, "OnSessionOpened, result: %{public}d", result);
        return SESSION_REFUSED;
    }

    int32_t len = SESSION_NAME_MAXLENGTH + 1;
    char contents[len];
    int32_t resultCode = ::GetPeerSessionName(session, contents, len);
    if (resultCode != Constant::SUCCESS) {
        ACCESSTOKEN_LOG_ERROR(LABEL, "OnSessionOpened, GetPeerSessionName failed, result: %{public}d", resultCode);
        return SESSION_REFUSED;
    }
    std::string peerSessionName(contents);
    if (SoftBusManager::SESSION_NAME != peerSessionName) {
        ACCESSTOKEN_LOG_ERROR(LABEL, "OnSessionOpened, unknown session name.");
        return SESSION_REFUSED;
    }

    ACCESSTOKEN_LOG_INFO(LABEL, "OnSessionOpened, id = %{public}d", session);

    // store session state: opening
    std::lock_guard<std::mutex> guard(g_SessionMutex_);
    auto iter = g_SessionOpenedMap_.find(session);
    if (iter == g_SessionOpenedMap_.end()) {
        g_SessionOpenedMap_.insert(std::pair<int32_t, int64_t>(session, (int64_t) 1));
    } else {
        iter->second = iter->second + 1;
    }

    return SESSION_ACCEPTED;
}

void SoftBusSessionListener::OnSessionClosed(int32_t session)
{
    ACCESSTOKEN_LOG_DEBUG(LABEL, "OnSessionClosed");

    // clear session state
    std::lock_guard<std::mutex> guard(g_SessionMutex_);
    auto iter = g_SessionOpenedMap_.find(session);
    if (iter != g_SessionOpenedMap_.end()) {
        g_SessionOpenedMap_.erase(iter);
    }
}

void SoftBusSessionListener::OnMessageReceived(int32_t sessionId, const void *data, uint32_t dataLen)
{
    (void)data;
    ACCESSTOKEN_LOG_DEBUG(LABEL, "OnMessageReceived: data length = %{public}u", dataLen);
}

void SoftBusSessionListener::OnBytesReceived(int32_t sessionId, const void *data, uint32_t dataLen)
{
    if ((sessionId == Constant::INVALID_SESSION) || (dataLen == 0) ||
        (dataLen > MAX_ONBYTES_RECEIVED_DATA_LEN) || (data == nullptr)) {
        ACCESSTOKEN_LOG_ERROR(LABEL, "params invalid, data length: %{public}u", dataLen);
        return;
    }

    int32_t len = SESSION_NAME_MAXLENGTH + 1;
    char contents[len];
    int32_t resultCode = ::GetPeerDeviceId(sessionId, contents, len);
    if (resultCode != Constant::SUCCESS) {
        ACCESSTOKEN_LOG_ERROR(LABEL, "GetPeerDeviceId, failed, result: %{public}d", resultCode);
        return;
    }
    std::string networkId(contents);
    ACCESSTOKEN_LOG_INFO(LABEL, "data length = %{public}u", dataLen);
    auto channel = RemoteCommandManager::GetInstance().GetExecutorChannel(networkId);
    if (channel == nullptr) {
        ACCESSTOKEN_LOG_ERROR(LABEL, "GetExecutorChannel failed");
        return;
    }
    channel->HandleDataReceived(sessionId, static_cast<unsigned char *>(const_cast<void *>(data)), dataLen);
}

int64_t SoftBusSessionListener::GetSessionState(int32_t sessionId)
{
    // get session state
    std::lock_guard<std::mutex> guard(g_SessionMutex_);
    auto iter = g_SessionOpenedMap_.find(sessionId);
    if (iter == g_SessionOpenedMap_.end()) {
        return STATE_NOTFOUND;
    }
    return iter->second;
}

void SoftBusSessionListener::DeleteSessionIdFromMap(int32_t sessionID)
{
    ACCESSTOKEN_LOG_DEBUG(LABEL, "DeleteSessionIdFromMap");
    // delete sessionId in map
    std::lock_guard<std::mutex> guard(g_SessionMutex_);
    auto iter = g_SessionOpenedMap_.find(sessionID);
    if (iter != g_SessionOpenedMap_.end()) {
        g_SessionOpenedMap_.erase(iter);
    }
}
} // namespace AccessToken
} // namespace Security
} // namespace OHOS
