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

#ifndef PERMISSION_STATE_CHANGE_CALLBACK_PROXY_H
#define PERMISSION_STATE_CHANGE_CALLBACK_PROXY_H

#include "i_token_callback.h"

#include "iremote_proxy.h"
#include "nocopyable.h"

namespace OHOS {
namespace Security {
namespace AccessToken {
class TokenCallbackProxy : public IRemoteProxy<ITokenCallback> {
public:
    explicit TokenCallbackProxy(const sptr<IRemoteObject>& impl);
    ~TokenCallbackProxy() override;

    virtual void GrantResultsCallback(
        const std::vector<std::string> &permissions, const std::vector<int32_t> &grantResults) override;

private:
    static inline BrokerDelegator<TokenCallbackProxy> delegator_;
};
} // namespace AccessToken
} // namespace Security
} // namespace OHOS
#endif // PERMISSION_STATE_CHANGE_CALLBACK_PROXY_H