/*
 * Copyright (c) 2024 Huawei Device Co., Ltd.
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

#include "background_task_manager_access_proxy.h"
#include "accesstoken_log.h"
#include "errors.h"

namespace OHOS {
namespace Security {
namespace AccessToken {
namespace {
constexpr HiviewDFX::HiLogLabel LABEL = {LOG_CORE, SECURITY_DOMAIN_PRIVACY, "BackgroundTaskManagerAccessProxy"};
static constexpr int32_t ERROR = -1;
static constexpr int32_t MAX_CALLBACK_NUM = 10 * 1024;
}

int32_t BackgroundTaskManagerAccessProxy::SubscribeBackgroundTask(const sptr<IBackgroundTaskSubscriber>& subscriber)
{
    MessageParcel data;
    MessageParcel reply;
    MessageOption option;
    if (!data.WriteInterfaceToken(GetDescriptor())) {
        ACCESSTOKEN_LOG_ERROR(LABEL, "WriteInterfaceToken failed.");
        return ERROR;
    }
    if (!data.WriteRemoteObject(subscriber->AsObject())) {
        ACCESSTOKEN_LOG_ERROR(LABEL, "Write callerToken failed.");
        return ERROR;
    }
    int32_t error = Remote()->SendRequest(
        static_cast<uint32_t>(IBackgroundTaskMgr::Message::SUBSCRIBE_BACKGROUND_TASK), data, reply, option);
    if (error != ERR_NONE) {
        ACCESSTOKEN_LOG_ERROR(LABEL, "Regist background task observer failed, error: %{public}d", error);
        return ERROR;
    }
    int32_t result;
    if (!reply.ReadInt32(result)) {
        ACCESSTOKEN_LOG_ERROR(LABEL, "ReadInt32 failed.");
        return ERROR;
    }
    return result;
}

int32_t BackgroundTaskManagerAccessProxy::UnsubscribeBackgroundTask(const sptr<IBackgroundTaskSubscriber>& subscriber)
{
    MessageParcel data;
    MessageParcel reply;
    MessageOption option;
    if (!data.WriteInterfaceToken(GetDescriptor())) {
        ACCESSTOKEN_LOG_ERROR(LABEL, "WriteInterfaceToken failed.");
        return ERROR;
    }
    if (!data.WriteRemoteObject(subscriber->AsObject())) {
        ACCESSTOKEN_LOG_ERROR(LABEL, "Write callerToken failed.");
        return ERROR;
    }
    int32_t error = Remote()->SendRequest(
        static_cast<uint32_t>(IBackgroundTaskMgr::Message::UNSUBSCRIBE_BACKGROUND_TASK), data, reply, option);
    if (error != ERR_NONE) {
        ACCESSTOKEN_LOG_ERROR(LABEL, "Unregist background task observer failed, error: %d", error);
        return error;
    }
    int32_t result;
    if (!reply.ReadInt32(result)) {
        ACCESSTOKEN_LOG_ERROR(LABEL, "ReadInt32 failed.");
        return ERROR;
    }
    return result;
}

int32_t BackgroundTaskManagerAccessProxy::GetContinuousTaskApps(
    std::vector<std::shared_ptr<ContinuousTaskCallbackInfo>> &list)
{
    MessageParcel data;
    MessageParcel reply;
    MessageOption option;
    if (!data.WriteInterfaceToken(GetDescriptor())) {
        ACCESSTOKEN_LOG_ERROR(LABEL, "WriteInterfaceToken failed");
        return ERROR;
    }
    int32_t error = Remote()->SendRequest(
        static_cast<uint32_t>(IBackgroundTaskMgr::Message::GET_CONTINUOUS_TASK_APPS), data, reply, option);
    if (error != ERR_NONE) {
        ACCESSTOKEN_LOG_ERROR(LABEL, "Get continuous task apps failed, error: %{public}d", error);
        return ERROR;
    }
    int32_t result;
    if (!reply.ReadInt32(result)) {
        ACCESSTOKEN_LOG_ERROR(LABEL, "ReadInt32 failed.");
        return ERROR;
    }

    if (result != ERR_OK) {
        ACCESSTOKEN_LOG_ERROR(LABEL, "GetContinuousTaskApps failed.");
        return result;
    }
    int32_t infoSize = reply.ReadInt32();
    if ((infoSize < 0) || (infoSize > MAX_CALLBACK_NUM)) {
        ACCESSTOKEN_LOG_ERROR(LABEL, "InfoSize:%{public}d invalid.", infoSize);
        return ERROR;
    }

    for (int32_t i = 0; i < infoSize; i++) {
        auto info = ContinuousTaskCallbackInfo::Unmarshalling(reply);
        if (info == nullptr) {
            ACCESSTOKEN_LOG_ERROR(LABEL, "Failed to Read Parcelable infos.");
            return ERROR;
        }
        list.emplace_back(info);
    }
    return result;
}
} // namespace AccessToken
} // namespace Security
} // namespace OHOS
