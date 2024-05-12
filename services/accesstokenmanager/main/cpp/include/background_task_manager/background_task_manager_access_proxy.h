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

#ifndef ACCESS_BACKGROUND_TASK_MANAGER_ACCESS_PROXY_H
#define ACCESS_BACKGROUND_TASK_MANAGER_ACCESS_PROXY_H

#include <iremote_proxy.h>

#include "continuous_task_callback_info.h"
#include "service_ipc_interface_code.h"

namespace OHOS {
namespace Security {
namespace AccessToken {
class IBackgroundTaskSubscriber : public IRemoteBroker {
public:
    DECLARE_INTERFACE_DESCRIPTOR(u"ohos.resourceschedule.IBackgroundTaskSubscriber");

    virtual void OnContinuousTaskStart(
        const std::shared_ptr<ContinuousTaskCallbackInfo> &continuousTaskCallbackInfo) = 0;

    virtual void OnContinuousTaskStop(
        const std::shared_ptr<ContinuousTaskCallbackInfo> &continuousTaskCallbackInfo) = 0;

    enum class Message {
        ON_CONTINUOUS_TASK_START = 7,
        ON_CONTINUOUS_TASK_STOP = 9,
    };
};

class IBackgroundTaskMgr : public IRemoteBroker {
public:
    DECLARE_INTERFACE_DESCRIPTOR(u"ohos.resourceschedule.IBackgroundTaskMgr");

    virtual int32_t SubscribeBackgroundTask(const sptr<IBackgroundTaskSubscriber> &subscriber) = 0;
    virtual int32_t UnsubscribeBackgroundTask(const sptr<IBackgroundTaskSubscriber> &subscriber) = 0;
    virtual int32_t GetContinuousTaskApps(std::vector<std::shared_ptr<ContinuousTaskCallbackInfo>> &list) = 0;

    enum class Message {
        SUBSCRIBE_BACKGROUND_TASK = 7,
        UNSUBSCRIBE_BACKGROUND_TASK = 8,
        GET_CONTINUOUS_TASK_APPS = 10,
    };
};

class BackgroundTaskManagerAccessProxy : public IRemoteProxy<IBackgroundTaskMgr> {
public:
    explicit BackgroundTaskManagerAccessProxy(
        const sptr<IRemoteObject>& impl) : IRemoteProxy<IBackgroundTaskMgr>(impl) {}

    virtual ~BackgroundTaskManagerAccessProxy() = default;

    int32_t SubscribeBackgroundTask(const sptr<IBackgroundTaskSubscriber>& subscriber) override;
    int32_t UnsubscribeBackgroundTask(const sptr<IBackgroundTaskSubscriber>& subscriber) override;
    int32_t GetContinuousTaskApps(std::vector<std::shared_ptr<ContinuousTaskCallbackInfo>> &list) override;
private:
    static inline BrokerDelegator<BackgroundTaskManagerAccessProxy> delegator_;
};
} // namespace AccessToken
} // namespace Security
} // namespace OHOS
#endif // ACCESS_BACKGROUND_TASK_MANAGER_ACCESS_PROXY_H
