/*
 * Copyright (c) 2021 Huawei Device Co., Ltd.
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

#ifndef ACCESSTOKEN_MANAGER_PROXY_H
#define ACCESSTOKEN_MANAGER_PROXY_H

#include "i_accesstoken_manager.h"

#include "iremote_proxy.h"

namespace OHOS {
namespace Security {
namespace AccessToken {
class AccessTokenManagerProxy : public IRemoteProxy<IAccessTokenManager> {
public:
    explicit AccessTokenManagerProxy(const sptr<IRemoteObject>& impl);
    virtual ~AccessTokenManagerProxy() override;

    int VerifyAccesstoken(AccessTokenID tokenID, const std::string& permissionName) override;
private:
    static inline BrokerDelegator<AccessTokenManagerProxy> delegator_;
};
} // namespace AccessToken
} // namespace Security
} // namespace OHOS
#endif // ACCESSTOKEN_MANAGER_PROXY_H
