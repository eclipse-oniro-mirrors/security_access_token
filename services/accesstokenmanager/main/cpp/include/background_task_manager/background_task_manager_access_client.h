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

#ifndef ACCESS_BACKGROUND_TASK_MANAGER_ACCESS_CLIENT_H
#define ACCESS_BACKGROUND_TASK_MANAGER_ACCESS_CLIENT_H

#include <mutex>
#include <string>

#include "continuous_task_change_callback.h"
#include "background_task_manager_death_recipient.h"
#include "background_task_manager_access_proxy.h"
#include "nocopyable.h"

namespace OHOS {
namespace Security {
namespace AccessToken {
class BackgourndTaskManagerAccessClient final {
public:
    static BackgourndTaskManagerAccessClient& GetInstance();
    virtual ~BackgourndTaskManagerAccessClient();

    int32_t SubscribeBackgroundTask(const sptr<IBackgroundTaskSubscriber>& subscriber);
    int32_t UnsubscribeBackgroundTask(const sptr<IBackgroundTaskSubscriber>& subscriber);
    int32_t GetContinuousTaskApps(std::vector<std::shared_ptr<ContinuousTaskCallbackInfo>> &list);
    void OnRemoteDiedHandle();

private:
    BackgourndTaskManagerAccessClient();
    DISALLOW_COPY_AND_MOVE(BackgourndTaskManagerAccessClient);

    void InitProxy();
    sptr<IBackgroundTaskMgr> GetProxy();

    sptr<BackgroundTaskMgrDeathRecipient> serviceDeathObserver_ = nullptr;
    std::mutex proxyMutex_;
    sptr<IBackgroundTaskMgr> proxy_ = nullptr;
};
} // namespace AccessToken
} // namespace Security
} // namespace OHOS
#endif // ACCESS_BACKGROUND_TASK_MANAGER_ACCESS_CLIENT_H

