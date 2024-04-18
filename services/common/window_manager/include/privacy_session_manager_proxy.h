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

#ifndef PRIVACY_SESSION_MANAGER_PROXY_H
#define PRIVACY_SESSION_MANAGER_PROXY_H

#include <iremote_proxy.h>

namespace OHOS {
namespace Security {
namespace AccessToken {
class ISessionManagerService : public IRemoteBroker {
public:
    DECLARE_INTERFACE_DESCRIPTOR(u"OHOS.ISessionManagerService");

    enum class SessionManagerServiceMessage : uint32_t {
        TRANS_ID_GET_SCENE_SESSION_MANAGER = 0,
        TRANS_ID_GET_SCENE_SESSION_MANAGER_LITE = 1,
    };

    virtual sptr<IRemoteObject> GetSceneSessionManager() = 0;
    virtual sptr<IRemoteObject> GetSceneSessionManagerLite() = 0;
};

class PrivacySessionManagerProxy : public IRemoteProxy<ISessionManagerService> {
public:
    explicit PrivacySessionManagerProxy(const sptr<IRemoteObject>& object)
        : IRemoteProxy<ISessionManagerService>(object) {}
    virtual ~PrivacySessionManagerProxy() = default;

    sptr<IRemoteObject> GetSceneSessionManager() override;
    sptr<IRemoteObject> GetSceneSessionManagerLite() override;

private:
    static inline BrokerDelegator<PrivacySessionManagerProxy> delegator_;
};
}
}
}
#endif // PRIVACY_SESSION_MANAGER_PROXY_H
