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

#ifndef ACCESS_POWER_MANAGER_ACCESS_PROXY_H
#define ACCESS_POWER_MANAGER_ACCESS_PROXY_H

#include <iremote_proxy.h>

namespace OHOS {
namespace Security {
namespace AccessToken {
class IPowerMgr : public IRemoteBroker {
public:
    DECLARE_INTERFACE_DESCRIPTOR(u"ohos.powermgr.IPowerMgr");
    enum class Message {
        IS_SCREEN_ON = 16,
    };

    virtual bool IsScreenOn() = 0;
};

class PowerMgrProxy : public IRemoteProxy<IPowerMgr> {
public:
    explicit PowerMgrProxy(const sptr<IRemoteObject>& impl)
        : IRemoteProxy<IPowerMgr>(impl) {}
    ~PowerMgrProxy() = default;
    DISALLOW_COPY_AND_MOVE(PowerMgrProxy);

    virtual bool IsScreenOn() override;
private:
    static inline BrokerDelegator<PowerMgrProxy> delegator_;
};
} // namespace AccessToken
} // namespace Security
} // namespace OHOS
#endif // ACCESS_POWER_MANAGER_ACCESS_PROXY_H
