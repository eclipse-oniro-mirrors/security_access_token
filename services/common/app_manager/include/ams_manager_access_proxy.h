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

#ifndef ACCESS_AMS_MANAGER_ACCESS_PROXY_H
#define ACCESS_AMS_MANAGER_ACCESS_PROXY_H

#include <iremote_proxy.h>

#include "app_state_data.h"
#include "process_data.h"
#include "service_ipc_interface_code.h"

namespace OHOS {
namespace Security {
namespace AccessToken {
class IAmsMgr : public IRemoteBroker {
public:
    DECLARE_INTERFACE_DESCRIPTOR(u"ohos.appexecfwk.IAmsMgr");

    virtual int32_t KillProcessesByAccessTokenId(const uint32_t accessTokenId) = 0;

    enum class Message {
        FORCE_KILL_APPLICATION_BY_ACCESS_TOKEN_ID = 49,
    };
};

class AmsManagerAccessProxy : public IRemoteProxy<IAmsMgr> {
public:
    explicit AmsManagerAccessProxy(const sptr<IRemoteObject>& impl) : IRemoteProxy<IAmsMgr>(impl) {}

    virtual ~AmsManagerAccessProxy() = default;

    int32_t KillProcessesByAccessTokenId(const uint32_t accessTokenId) override;
private:
    static inline BrokerDelegator<AmsManagerAccessProxy> delegator_;
};
} // namespace AccessToken
} // namespace Security
} // namespace OHOS
#endif // ACCESS_AMS_MANAGER_ACCESS_PROXY_H
