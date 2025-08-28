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
#include "soft_bus_channel.h"

#include <securec.h>

#include "constant_common.h"
#include "device_info_manager.h"
#ifdef EVENTHANDLER_ENABLE
#include "access_event_handler.h"
#endif
#include "token_sync_manager_service.h"
#include "singleton.h"
#include "soft_bus_manager.h"

namespace OHOS {
namespace Security {
namespace AccessToken {
namespace {
static const std::string REQUEST_TYPE = "request";
static const std::string RESPONSE_TYPE = "response";
static const std::string TASK_NAME_CLOSE_SESSION = "atm_soft_bus_channel_close_session";
static const int32_t EXECUTE_COMMAND_TIME_OUT = 3000;
static const int32_t WAIT_SESSION_CLOSE_MILLISECONDS = 5 * 1000;
// send buf size for header
static const int RPC_TRANSFER_HEAD_BYTES_LENGTH = 1024 * 256;
// decompress buf size
static const int RPC_TRANSFER_BYTES_MAX_LENGTH = 1024 * 1024;
} // namespace
SoftBusChannel::SoftBusChannel(const std::string &deviceId)
    : deviceId_(deviceId), mutex_(), callbacks_(), responseResult_(""), loadedCond_()
{
    LOGD(ATM_DOMAIN, ATM_TAG, "SoftBusChannel(deviceId)");
    isDelayClosing_ = false;
    socketFd_ = Constant::INVALID_SOCKET_FD;
    isSocketUsing_ = false;
}

SoftBusChannel::~SoftBusChannel()
{
    LOGD(ATM_DOMAIN, ATM_TAG, "~SoftBusChannel()");
}

int SoftBusChannel::BuildConnection()
{
    CancelCloseConnectionIfNeeded();

    std::unique_lock<std::mutex> lock(socketMutex_);
    if (socketFd_ != Constant::INVALID_SOCKET_FD) {
        LOGI(ATM_DOMAIN, ATM_TAG, "Socket is exist, no need open again.");
        return Constant::SUCCESS;
    }

    if (socketFd_ == Constant::INVALID_SOCKET_FD) {
        LOGI(ATM_DOMAIN, ATM_TAG, "Bind service with device: %{public}s",
            ConstantCommon::EncryptDevId(deviceId_).c_str());
        int socket = SoftBusManager::GetInstance().BindService(deviceId_);
        if (socket == Constant::INVALID_SOCKET_FD) {
            LOGE(ATM_DOMAIN, ATM_TAG, "Bind service failed.");
            return Constant::FAILURE;
        }
        socketFd_ = socket;
    }
    return Constant::SUCCESS;
}

#ifdef EVENTHANDLER_ENABLE
static bool GetSendEventHandler(std::shared_ptr<AccessEventHandler>& handler)
{
    auto tokenSyncManagerService = DelayedSingleton<TokenSyncManagerService>::GetInstance();
    if (tokenSyncManagerService == nullptr) {
        LOGE(ATM_DOMAIN, ATM_TAG, "TokenSyncManagerService is null.");
        return false;
    }
    handler = tokenSyncManagerService->GetSendEventHandler();
    if (handler == nullptr) {
        LOGE(ATM_DOMAIN, ATM_TAG, "Fail to get EventHandler");
        return false;
    }

    return true;
}
#endif

void SoftBusChannel::CloseConnection()
{
    LOGD(ATM_DOMAIN, ATM_TAG, "Close connection");
    std::unique_lock<std::mutex> lock(mutex_);
    if (isDelayClosing_) {
        return;
    }

#ifdef EVENTHANDLER_ENABLE
    std::shared_ptr<AccessEventHandler> handler = nullptr;
    if (!GetSendEventHandler(handler)) {
        LOGE(ATM_DOMAIN, ATM_TAG, "Fail to get EventHandler");
        return;
    }
#endif
    std::weak_ptr<SoftBusChannel> weakPtr = shared_from_this();
    std::function<void()> delayed = ([weakPtr]() {
        auto self = weakPtr.lock();
        if (self == nullptr) {
            LOGE(ATM_DOMAIN, ATM_TAG, "SoftBusChannel is nullptr");
            return;
        }
        std::unique_lock<std::mutex> lock(self->socketMutex_);
        if (self->isSocketUsing_) {
            LOGD(ATM_DOMAIN, ATM_TAG, "Socket is in using, cancel close socket");
        } else {
            SoftBusManager::GetInstance().CloseSocket(self->socketFd_);
            self->socketFd_ = Constant::INVALID_SESSION;
            LOGI(ATM_DOMAIN, ATM_TAG, "Close socket for device: %{public}s",
                ConstantCommon::EncryptDevId(self->deviceId_).c_str());
        }
        self->isDelayClosing_ = false;
    });

    LOGD(ATM_DOMAIN, ATM_TAG, "Close socket after %{public}d ms", WAIT_SESSION_CLOSE_MILLISECONDS);
#ifdef EVENTHANDLER_ENABLE
    handler->ProxyPostTask(delayed, TASK_NAME_CLOSE_SESSION, WAIT_SESSION_CLOSE_MILLISECONDS);
#endif

    isDelayClosing_ = true;
}

void SoftBusChannel::Release()
{
#ifdef EVENTHANDLER_ENABLE
    std::shared_ptr<AccessEventHandler> handler = nullptr;
    if (!GetSendEventHandler(handler)) {
        LOGE(ATM_DOMAIN, ATM_TAG, "Fail to get EventHandler");
        return;
    }
    handler->ProxyRemoveTask(TASK_NAME_CLOSE_SESSION);
#endif
}

std::string SoftBusChannel::GetUuid()
{
    // to use a lib like libuuid
    int uuidStrLen = 37; // 32+4+1
    char uuidbuf[uuidStrLen];
    RandomUuid(uuidbuf, uuidStrLen);
    std::string uuid(uuidbuf);
    LOGD(ATM_DOMAIN, ATM_TAG, "Generated message uuid: %{public}s", ConstantCommon::EncryptDevId(uuid).c_str());

    return uuid;
}

void SoftBusChannel::InsertCallback(int result, std::string &uuid)
{
    std::unique_lock<std::mutex> lock(socketMutex_);
    std::function<void(const std::string &)> callback = [this](const std::string &result) {
        responseResult_ = std::string(result);
        loadedCond_.notify_all();
        LOGD(ATM_DOMAIN, ATM_TAG, "OnResponse called end");
    };
    callbacks_.insert(std::pair<std::string, std::function<void(std::string)>>(uuid, callback));

    isSocketUsing_ = true;
    lock.unlock();
}

std::string SoftBusChannel::ExecuteCommand(const std::string &commandName, const std::string &jsonPayload)
{
    if (commandName.empty() || jsonPayload.empty()) {
        LOGE(ATM_DOMAIN, ATM_TAG, "Invalid params, commandName: %{public}s", commandName.c_str());
        return "";
    }

    std::string uuid = GetUuid();

    int len = static_cast<int32_t>(RPC_TRANSFER_HEAD_BYTES_LENGTH + jsonPayload.length());
    unsigned char* buf = new (std::nothrow) unsigned char[len + 1];
    if (buf == nullptr) {
        LOGE(ATM_DOMAIN, ATM_TAG, "No enough memory: %{public}d", len);
        return "";
    }
    (void)memset_s(buf, len + 1, 0, len + 1);
    BytesInfo info;
    info.bytes = buf;
    info.bytesLength = len;
    int result = PrepareBytes(REQUEST_TYPE, uuid, commandName, jsonPayload, info);
    if (result != Constant::SUCCESS) {
        delete[] buf;
        return "";
    }
    InsertCallback(result, uuid);
    int retCode = SendRequestBytes(buf, info.bytesLength);
    delete[] buf;

    std::unique_lock<std::mutex> lock2(socketMutex_);
    if (retCode != Constant::SUCCESS) {
        LOGE(ATM_DOMAIN, ATM_TAG, "Send request data failed: %{public}d ", retCode);
        callbacks_.erase(uuid);
        isSocketUsing_ = false;
        return "";
    }

    LOGD(ATM_DOMAIN, ATM_TAG, "Wait command response");
    if (loadedCond_.wait_for(lock2, std::chrono::milliseconds(EXECUTE_COMMAND_TIME_OUT)) == std::cv_status::timeout) {
        LOGW(ATM_DOMAIN, ATM_TAG, "Time out to wait response.");
        callbacks_.erase(uuid);
        isSocketUsing_ = false;
        return "";
    }

    isSocketUsing_ = false;
    return responseResult_;
}

void SoftBusChannel::HandleDataReceived(int socket, const unsigned char* bytes, int length)
{
    LOGD(ATM_DOMAIN, ATM_TAG, "HandleDataReceived");
#ifdef DEBUG_API_PERFORMANCE
    LOGI(ATM_DOMAIN, ATM_TAG, "Api_performance:recieve message from softbus");
#endif
    if (socket <= 0 || length <= 0) {
        LOGE(ATM_DOMAIN, ATM_TAG, "Invalid params: socket: %{public}d, data length: %{public}d", socket, length);
        return;
    }
    std::string receiveData = Decompress(bytes, length);
    if (receiveData.empty()) {
        LOGE(ATM_DOMAIN, ATM_TAG, "Invalid parameter bytes");
        return;
    }
    std::shared_ptr<SoftBusMessage> message = SoftBusMessage::FromJson(receiveData);
    if (message == nullptr) {
        LOGD(ATM_DOMAIN, ATM_TAG, "Invalid json string");
        return;
    }
    if (!message->IsValid()) {
        LOGD(ATM_DOMAIN, ATM_TAG, "Invalid data, has empty field");
        return;
    }

    std::string type = message->GetType();
    if (REQUEST_TYPE == (type)) {
        std::function<void()> delayed = ([weak = weak_from_this(), socket, message]() {
            auto self = weak.lock();
            if (self == nullptr) {
                LOGE(ATM_DOMAIN, ATM_TAG, "SoftBusChannel is nullptr");
                return;
            }
            self->HandleRequest(socket, message->GetId(), message->GetCommandName(), message->GetJsonPayload());
        });

#ifdef EVENTHANDLER_ENABLE
        std::shared_ptr<AccessEventHandler> handler = nullptr;
        if (!GetSendEventHandler(handler)) {
            LOGE(ATM_DOMAIN, ATM_TAG, "Fail to get EventHandler");
            return;
        }
        handler->ProxyPostTask(delayed, "HandleDataReceived_HandleRequest");
#endif
    } else if (RESPONSE_TYPE == (type)) {
        HandleResponse(message->GetId(), message->GetJsonPayload());
    } else {
        LOGE(ATM_DOMAIN, ATM_TAG, "Invalid type: %{public}s ", type.c_str());
    }
}

int SoftBusChannel::PrepareBytes(const std::string &type, const std::string &id, const std::string &commandName,
    const std::string &jsonPayload, BytesInfo &info)
{
    SoftBusMessage messageEntity(type, id, commandName, jsonPayload);
    std::string json = messageEntity.ToJson();
    return Compress(json, info.bytes, info.bytesLength);
}

int SoftBusChannel::Compress(const std::string &json, const unsigned char* compressedBytes, int &compressedLength)
{
    uLong len = compressBound(json.size());
    // length will not so that long
    if (compressedLength > 0 && static_cast<int32_t>(len) > compressedLength) {
        LOGE(ATM_DOMAIN, ATM_TAG,
            "compress error. data length overflow, bound length: %{public}d, buffer length: %{public}d",
            static_cast<int32_t>(len), compressedLength);
        return Constant::FAILURE;
    }

    int result = compress(const_cast<Byte*>(compressedBytes), &len,
        reinterpret_cast<unsigned char*>(const_cast<char*>(json.c_str())), json.size() + 1);
    if (result != Z_OK) {
        LOGE(ATM_DOMAIN, ATM_TAG, "Compress failed! error code: %{public}d", result);
        return result;
    }
    LOGD(ATM_DOMAIN, ATM_TAG, "Compress complete. compress %{public}d bytes to %{public}d", compressedLength,
        static_cast<int32_t>(len));
    compressedLength = static_cast<int32_t>(len);
    return Constant::SUCCESS;
}

std::string SoftBusChannel::Decompress(const unsigned char* bytes, const int length)
{
    LOGD(ATM_DOMAIN, ATM_TAG, "Input length: %{public}d", length);
    uLong len = RPC_TRANSFER_BYTES_MAX_LENGTH;
    unsigned char* buf = new (std::nothrow) unsigned char[len + 1];
    if (buf == nullptr) {
        LOGE(ATM_DOMAIN, ATM_TAG, "No enough memory!");
        return "";
    }
    (void)memset_s(buf, len + 1, 0, len + 1);
    int result = uncompress(buf, &len, const_cast<unsigned char*>(bytes), length);
    if (result != Z_OK) {
        LOGE(ATM_DOMAIN, ATM_TAG,
            "uncompress failed, error code: %{public}d, bound length: %{public}d, buffer length: %{public}d", result,
            static_cast<int32_t>(len), length);
        delete[] buf;
        return "";
    }
    buf[len] = '\0';
    std::string str(reinterpret_cast<char*>(buf));
    delete[] buf;
    return str;
}

int SoftBusChannel::SendRequestBytes(const unsigned char* bytes, const int bytesLength)
{
    if (bytesLength == 0) {
        LOGE(ATM_DOMAIN, ATM_TAG, "Bytes data is invalid.");
        return Constant::FAILURE;
    }

    std::unique_lock<std::mutex> lock(socketMutex_);
    if (CheckSessionMayReopenLocked() != Constant::SUCCESS) {
        LOGE(ATM_DOMAIN, ATM_TAG, "Socket invalid and reopen failed!");
        return Constant::FAILURE;
    }

    LOGD(ATM_DOMAIN, ATM_TAG, "Send len (after compress len)= %{public}d", bytesLength);
#ifdef DEBUG_API_PERFORMANCE
    LOGI(ATM_DOMAIN, ATM_TAG, "Api_performance:send command to softbus");
#endif
    int result = ::SendBytes(socketFd_, bytes, bytesLength);
    if (result != Constant::SUCCESS) {
        LOGE(ATM_DOMAIN, ATM_TAG, "Fail to send! result= %{public}d", result);
        return Constant::FAILURE;
    }
    LOGD(ATM_DOMAIN, ATM_TAG, "Send successfully.");
    return Constant::SUCCESS;
}

int SoftBusChannel::CheckSessionMayReopenLocked()
{
    // when socket is opened, we got a valid sessionid, when socket closed, we will reset sessionid.
    if (IsSessionAvailable()) {
        return Constant::SUCCESS;
    }
    int socket = SoftBusManager::GetInstance().BindService(deviceId_);
    if (socket != Constant::INVALID_SESSION) {
        socketFd_ = socket;
        return Constant::SUCCESS;
    }
    return Constant::FAILURE;
}

bool SoftBusChannel::IsSessionAvailable()
{
    return socketFd_ > Constant::INVALID_SESSION;
}

void SoftBusChannel::CancelCloseConnectionIfNeeded()
{
    std::unique_lock<std::mutex> lock(mutex_);
    if (!isDelayClosing_) {
        return;
    }
    LOGD(ATM_DOMAIN, ATM_TAG, "Cancel close connection");

    Release();
    isDelayClosing_ = false;
}

void SoftBusChannel::HandleRequest(int socket, const std::string &id, const std::string &commandName,
    const std::string &jsonPayload)
{
    std::shared_ptr<BaseRemoteCommand> command =
        RemoteCommandFactory::GetInstance().NewRemoteCommandFromJson(commandName, jsonPayload);
    if (command == nullptr) {
        // send result back directly
        LOGW(ATM_DOMAIN, ATM_TAG, "Command %{public}s cannot get from json", commandName.c_str());

        int sendlen = static_cast<int32_t>(RPC_TRANSFER_HEAD_BYTES_LENGTH + jsonPayload.length());
        unsigned char* sendbuf = new (std::nothrow) unsigned char[sendlen + 1];
        if (sendbuf == nullptr) {
            LOGE(ATM_DOMAIN, ATM_TAG, "No enough memory: %{public}d", sendlen);
            return;
        }
        (void)memset_s(sendbuf, sendlen + 1, 0, sendlen + 1);
        BytesInfo info;
        info.bytes = sendbuf;
        info.bytesLength = sendlen;
        int sendResult = PrepareBytes(RESPONSE_TYPE, id, commandName, jsonPayload, info);
        if (sendResult != Constant::SUCCESS) {
            delete[] sendbuf;
            return;
        }
        int sendResultCode = SendResponseBytes(socket, sendbuf, info.bytesLength);
        delete[] sendbuf;
        LOGD(ATM_DOMAIN, ATM_TAG, "Send response result= %{public}d ", sendResultCode);
        return;
    }

    // execute command
    command->Execute();
    LOGD(ATM_DOMAIN, ATM_TAG, "Command uniqueId: %{public}s, finish with status: %{public}d, message: %{public}s",
        ConstantCommon::EncryptDevId(command->remoteProtocol_.uniqueId).c_str(), command->remoteProtocol_.statusCode,
        command->remoteProtocol_.message.c_str());

    // send result back
    std::string resultJsonPayload = command->ToJsonPayload();
    int len = static_cast<int32_t>(RPC_TRANSFER_HEAD_BYTES_LENGTH + resultJsonPayload.length());
    unsigned char* buf = new (std::nothrow) unsigned char[len + 1];
    if (buf == nullptr) {
        LOGE(ATM_DOMAIN, ATM_TAG, "No enough memory: %{public}d", len);
        return;
    }
    (void)memset_s(buf, len + 1, 0, len + 1);
    BytesInfo info;
    info.bytes = buf;
    info.bytesLength = len;
    int result = PrepareBytes(RESPONSE_TYPE, id, commandName, resultJsonPayload, info);
    if (result != Constant::SUCCESS) {
        delete[] buf;
        return;
    }
    int retCode = SendResponseBytes(socket, buf, info.bytesLength);
    delete[] buf;
    LOGD(ATM_DOMAIN, ATM_TAG, "Send response result= %{public}d", retCode);
}

void SoftBusChannel::HandleResponse(const std::string &id, const std::string &jsonPayload)
{
    std::unique_lock<std::mutex> lock(socketMutex_);
    auto callback = callbacks_.find(id);
    if (callback != callbacks_.end()) {
        (callback->second)(jsonPayload);
        callbacks_.erase(callback);
    }
}

int SoftBusChannel::SendResponseBytes(int socket, const unsigned char* bytes, const int bytesLength)
{
    LOGD(ATM_DOMAIN, ATM_TAG, "Send len (after compress len)= %{public}d", bytesLength);
    int result = ::SendBytes(socket, bytes, bytesLength);
    if (result != Constant::SUCCESS) {
        LOGE(ATM_DOMAIN, ATM_TAG, "Fail to send! result= %{public}d", result);
        return Constant::FAILURE;
    }
    LOGD(ATM_DOMAIN, ATM_TAG, "Send successfully.");
    return Constant::SUCCESS;
}

std::shared_ptr<SoftBusMessage> SoftBusMessage::FromJson(const std::string &jsonString)
{
    CJsonUnique json = CreateJsonFromString(jsonString);
    if (json == nullptr || cJSON_IsObject(json.get()) == false) {
        LOGE(ATM_DOMAIN, ATM_TAG, "Failed to parse jsonString");
        return nullptr;
    }

    std::string type;
    std::string id;
    std::string commandName;
    std::string jsonPayload;
    GetStringFromJson(json.get(), "type", type);
    GetStringFromJson(json.get(), "id", id);
    GetStringFromJson(json.get(), "commandName", commandName);
    GetStringFromJson(json.get(), "jsonPayload", jsonPayload);
    std::shared_ptr<SoftBusMessage> message = std::make_shared<SoftBusMessage>(type, id, commandName, jsonPayload);
    return message;
}
} // namespace AccessToken
} // namespace Security
} // namespace OHOS
