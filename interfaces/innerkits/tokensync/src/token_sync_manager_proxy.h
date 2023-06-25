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

#ifndef TOKENSYNC_MANAGER_PROXY_H
#define TOKENSYNC_MANAGER_PROXY_H

#include <string>

#include "access_token.h"
#include "hap_token_info_for_sync_parcel.h"
#include "i_token_sync_manager.h"
#include "iremote_broker.h"
#include "iremote_proxy.h"

namespace OHOS {
namespace Security {
namespace AccessToken {
class TokenSyncManagerProxy : public IRemoteProxy<ITokenSyncManager> {
public:
    explicit TokenSyncManagerProxy(const sptr<IRemoteObject>& impl);
    ~TokenSyncManagerProxy() override;

    int GetRemoteHapTokenInfo(const std::string& deviceID, AccessTokenID tokenID) override;
    int DeleteRemoteHapTokenInfo(AccessTokenID tokenID) override;
    int UpdateRemoteHapTokenInfo(const HapTokenInfoForSync& tokenInfo) override;

private:
    static inline BrokerDelegator<TokenSyncManagerProxy> delegator_;
};
} // namespace AccessToken
} // namespace Security
} // namespace OHOS
#endif // TOKENSYNC_MANAGER_PROXY_H
