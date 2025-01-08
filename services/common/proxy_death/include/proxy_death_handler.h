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


#ifndef PROXY_DEATH_HANDLER_H
#define PROXY_DEATH_HANDLER_H

#include <map>
#include <mutex>
#include <utility>
#include "iremote_object.h"
#include "proxy_death_param.h"

namespace OHOS {
namespace Security {
namespace AccessToken {
class ProxyDeathHandler {
public:
    ProxyDeathHandler() {}
    ~ProxyDeathHandler() = default;

    void AddProxyStub(const sptr<IRemoteObject>& proxyStub, std::shared_ptr<ProxyDeathParam>& param);
    void HandleRemoteDied(const sptr<IRemoteObject>& object);
    void ReleaseProxyByParam(const std::shared_ptr<ProxyDeathParam>& param);

protected:
    void ReleaseProxies();
    void ProcessProxyData(const std::shared_ptr<ProxyDeathParam>& param);

private:
    std::mutex proxyLock_;
    using RecipientAndParam = std::pair<sptr<IRemoteObject::DeathRecipient>, std::shared_ptr<ProxyDeathParam>>;
    std::map<sptr<IRemoteObject>, RecipientAndParam> proxyStubAndRecipientMap_;
};
}  // namespace AccessToken
} // namespace Security
}  // namespace OHOS
#endif  // PROXY_DEATH_HANDLER_H

