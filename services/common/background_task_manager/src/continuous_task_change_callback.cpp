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

#include "continuous_task_change_callback.h"
#include "access_token.h"
#include "accesstoken_log.h"
#include "access_token_error.h"


namespace OHOS {
namespace Security {
namespace AccessToken {
BackgroundTaskSubscriberStub::BackgroundTaskSubscriberStub()
{
    LOGI(AT_DOMAIN, AT_TAG, "BackgroundTaskSubscriberStub Instance create.");
}

BackgroundTaskSubscriberStub::~BackgroundTaskSubscriberStub()
{
    LOGI(AT_DOMAIN, AT_TAG, "BackgroundTaskSubscriberStub Instance destroy.");
}

int32_t BackgroundTaskSubscriberStub::OnRemoteRequest(
    uint32_t code, MessageParcel &data, MessageParcel &reply, MessageOption &option)
{
    if (data.ReadInterfaceToken() != GetDescriptor()) {
        LOGE(AT_DOMAIN, AT_TAG, "BackgroundTaskSubscriberStub: ReadInterfaceToken failed.");
        return ERROR_IPC_REQUEST_FAIL;
    }
    switch (static_cast<IBackgroundTaskSubscriber::Message>(code)) {
        case IBackgroundTaskSubscriber::Message::ON_CONTINUOUS_TASK_START: {
            HandleOnContinuousTaskStart(data, reply);
            return NO_ERROR;
        }
        case IBackgroundTaskSubscriber::Message::ON_CONTINUOUS_TASK_STOP: {
            HandleOnContinuousTaskStop(data, reply);
            return NO_ERROR;
        }
        default: {
            LOGD(AT_DOMAIN, AT_TAG, "Default case code: %{public}d.", code);
            return IPCObjectStub::OnRemoteRequest(code, data, reply, option);
        }
    }
    return NO_ERROR;
}

void BackgroundTaskSubscriberStub::HandleOnContinuousTaskStart(MessageParcel &data, MessageParcel &reply)
{
    std::shared_ptr<ContinuousTaskCallbackInfo> continuousTaskCallbackInfo(
        data.ReadParcelable<ContinuousTaskCallbackInfo>());
    if (continuousTaskCallbackInfo == nullptr) {
        LOGE(AT_DOMAIN, AT_TAG, "ReadParcelable failed.");
        return;
    }
    OnContinuousTaskStart(continuousTaskCallbackInfo);
}

void BackgroundTaskSubscriberStub::HandleOnContinuousTaskStop(MessageParcel &data, MessageParcel &reply)
{
    std::shared_ptr<ContinuousTaskCallbackInfo> continuousTaskCallbackInfo(
        data.ReadParcelable<ContinuousTaskCallbackInfo>());
    if (continuousTaskCallbackInfo == nullptr) {
        LOGE(AT_DOMAIN, AT_TAG, "ReadParcelable failed.");
        return;
    }
    OnContinuousTaskStop(continuousTaskCallbackInfo);
}
} // namespace AccessToken
} // namespace Security
} // namespace OHOS
