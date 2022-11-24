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

#ifndef OHOS_APP_MANAGER_PRIVACY_PROXY_H
#define OHOS_APP_MANAGER_PRIVACY_PROXY_H

#include <iremote_proxy.h>
#include "app_state_data.h"

namespace OHOS {
namespace Security {
namespace AccessToken {
class IApplicationStateObserver : public IRemoteBroker {
public:
    DECLARE_INTERFACE_DESCRIPTOR(u"ohos.appexecfwk.IApplicationStateObserver");

    virtual void OnForegroundApplicationChanged(const AppStateData &appStateData) = 0;

    enum class Message {
        TRANSACT_ON_FOREGROUND_APPLICATION_CHANGED = 0,
    };
};

class IAppMgr : public IRemoteBroker {
public:
    DECLARE_INTERFACE_DESCRIPTOR(u"ohos.appexecfwk.AppMgr");

    virtual int32_t RegisterApplicationStateObserver(const sptr<IApplicationStateObserver>& observer,
        const std::vector<std::string>& bundleNameList = {}) = 0;
    virtual int32_t UnregisterApplicationStateObserver(const sptr<IApplicationStateObserver>& observer) = 0;
    virtual int32_t GetForegroundApplications(std::vector<AppStateData>& list) = 0;

    enum class Message {
        REGISTER_APPLICATION_STATE_OBSERVER = 12,
        UNREGISTER_APPLICATION_STATE_OBSERVER = 13,
        GET_FOREGROUND_APPLICATIONS = 14,
    };
};

class AppManagerPrivacyProxy : public IRemoteProxy<IAppMgr> {
public:
    explicit AppManagerPrivacyProxy(const sptr<IRemoteObject>& impl) : IRemoteProxy<IAppMgr>(impl) {};

    virtual ~AppManagerPrivacyProxy() = default;

    int32_t RegisterApplicationStateObserver(const sptr<IApplicationStateObserver>& observer,
        const std::vector<std::string> &bundleNameList = {}) override;
    int32_t UnregisterApplicationStateObserver(const sptr<IApplicationStateObserver>& observer) override;
    int32_t GetForegroundApplications(std::vector<AppStateData>& list) override;
private:
    static inline BrokerDelegator<AppManagerPrivacyProxy> delegator_;
};
}
}
}
#endif // OHOS_APP_MANAGER_PRIVACY_PROXY_H
