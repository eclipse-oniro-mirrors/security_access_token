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

#ifndef ACCESS_POWER_MANAGER_ACCESS_CLIENT_H
#define ACCESS_POWER_MANAGER_ACCESS_CLIENT_H

#include <mutex>
#include "nocopyable.h"
#include "power_manager_proxy.h"

namespace OHOS {
namespace Security {
namespace AccessToken {
class PowerMgrDeathRecipient : public IRemoteObject::DeathRecipient {
public:
    PowerMgrDeathRecipient() {}
    virtual ~PowerMgrDeathRecipient() override = default;
    void OnRemoteDied(const wptr<IRemoteObject>& object) override;
};

class PowerMgrClient final {
public:
    static PowerMgrClient& GetInstance();
    virtual ~PowerMgrClient();
    bool IsScreenOn();

    void OnRemoteDiedHandle();
private:
    PowerMgrClient();
    DISALLOW_COPY_AND_MOVE(PowerMgrClient);

    void InitProxy();
    sptr<IPowerMgr> GetProxy();
    void ReleaseProxy();

    sptr<PowerMgrDeathRecipient> serviceDeathObserver_ = nullptr;
    std::mutex proxyMutex_;
    sptr<IPowerMgr> proxy_ = nullptr;
};
} // namespace AccessToken
} // namespace Security
} // namespace OHOS
#endif // ACCESS_POWER_MANAGER_ACCESS_CLIENT_H
