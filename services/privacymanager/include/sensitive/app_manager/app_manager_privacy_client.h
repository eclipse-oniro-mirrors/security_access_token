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

#ifndef APP_MANAGER_PRIVACY_CLIENT_H
#define APP_MANAGER_PRIVACY_CLIENT_H

#include <mutex>
#include <string>

#include "app_status_change_callback.h"
#include "app_manager_death_recipient.h"
#include "app_manager_privacy_proxy.h"
#include "nocopyable.h"

namespace OHOS {
namespace Security {
namespace AccessToken {
class AppManagerPrivacyClient final {
public:
    static AppManagerPrivacyClient& GetInstance();
    virtual ~AppManagerPrivacyClient();

    int32_t RegisterApplicationStateObserver(const sptr<IApplicationStateObserver>& observer);
    int32_t UnregisterApplicationStateObserver(const sptr<IApplicationStateObserver>& observer);
    int32_t GetForegroundApplications(std::vector<AppStateData>& list);

    void OnRemoteDiedHandle();

private:
    AppManagerPrivacyClient();
    DISALLOW_COPY_AND_MOVE(AppManagerPrivacyClient);

    void InitProxy();
    sptr<IAppMgr> GetProxy();

    sptr<AppMgrDeathRecipient> serviceDeathObserver_ = nullptr;
    std::mutex proxyMutex_;
    sptr<IAppMgr> proxy_ = nullptr;
};
} // namespace AccessToken
} // namespace Security
} // namespace OHOS
#endif // APP_MANAGER_PRIVACY_CLIENT_H

