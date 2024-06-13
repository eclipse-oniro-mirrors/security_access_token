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

#ifndef ACCESS_CONTINUOUS_TASK_CHANGE_CALLBACK_H
#define ACCESS_CONTINUOUS_TASK_CHANGE_CALLBACK_H

#include "background_task_manager_access_proxy.h"
#include "iremote_stub.h"
#include "nocopyable.h"

namespace OHOS {
namespace Security {
namespace AccessToken {
class BackgroundTaskSubscriberStub : public IRemoteStub<IBackgroundTaskSubscriber> {
public:
    BackgroundTaskSubscriberStub();
    virtual ~BackgroundTaskSubscriberStub() override;

    virtual int OnRemoteRequest(
        uint32_t code, MessageParcel &data, MessageParcel &reply, MessageOption &option) override;

    virtual void OnContinuousTaskStart(
        const std::shared_ptr<ContinuousTaskCallbackInfo> &continuousTaskCallbackInfo) override {}

    virtual void OnContinuousTaskStop(
        const std::shared_ptr<ContinuousTaskCallbackInfo> &continuousTaskCallbackInfo) override {}

    DISALLOW_COPY_AND_MOVE(BackgroundTaskSubscriberStub);
private:
    void HandleOnContinuousTaskStart(MessageParcel &data, MessageParcel &reply);
    void HandleOnContinuousTaskStop(MessageParcel &data, MessageParcel &reply);
};
} // namespace AccessToken
} // namespace Security
} // namespace OHOS
#endif // ACCESS_CONTINUOUS_TASK_CHANGE_CALLBACK_H
