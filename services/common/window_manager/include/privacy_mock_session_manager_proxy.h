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

#ifndef PRIVACY_MOCK_SESSION_MANAGER_PROXY_H
#define PRIVACY_MOCK_SESSION_MANAGER_PROXY_H

#include <iremote_proxy.h>

namespace OHOS {
namespace Security {
namespace AccessToken {
class IMockSessionManagerInterface : public IRemoteBroker {
public:
    DECLARE_INTERFACE_DESCRIPTOR(u"OHOS.IMockSessionManager");
    enum class MockSessionManagerServiceMessage : uint32_t {
        TRANS_ID_GET_SESSION_MANAGER_SERVICE = 0,
    };

    virtual sptr<IRemoteObject> GetSessionManagerService() = 0;
};

class PrivacyMockSessionManagerProxy : public IRemoteProxy<IMockSessionManagerInterface> {
public:
    explicit PrivacyMockSessionManagerProxy(const sptr<IRemoteObject>& impl)
        : IRemoteProxy<IMockSessionManagerInterface>(impl) {}
    ~PrivacyMockSessionManagerProxy() {}
    sptr<IRemoteObject> GetSessionManagerService() override;
private:
    static inline BrokerDelegator<PrivacyMockSessionManagerProxy> delegator_;
};
}
}
}
#endif // PRIVACY_MOCK_SESSION_MANAGER_PROXY_H