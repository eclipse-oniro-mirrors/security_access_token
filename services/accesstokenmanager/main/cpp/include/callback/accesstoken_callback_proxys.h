/*
 * Copyright (c) 2022-2024 Huawei Device Co., Ltd.
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

#ifndef ACCESSTOKEN_CALLBACK_PROXYS_H
#define ACCESSTOKEN_CALLBACK_PROXYS_H

#include "i_permission_state_callback.h"
#ifdef TOKEN_SYNC_ENABLE
#include "i_token_sync_callback.h"
#endif // TOKEN_SYNC_ENABLE

#include "iremote_proxy.h"
#include "nocopyable.h"
#include "permission_state_change_info.h"

namespace OHOS {
namespace Security {
namespace AccessToken {
class PermissionStateChangeCallbackProxy : public IRemoteProxy<IPermissionStateCallback> {
public:
    explicit PermissionStateChangeCallbackProxy(const sptr<IRemoteObject>& impl);
    ~PermissionStateChangeCallbackProxy() override;
    virtual void PermStateChangeCallback(PermStateChangeInfo& result) override;

private:
    static inline BrokerDelegator<PermissionStateChangeCallbackProxy> delegator_;
};

#ifdef TOKEN_SYNC_ENABLE
class TokenSyncCallbackProxy : public IRemoteProxy<ITokenSyncCallback> {
public:
    explicit TokenSyncCallbackProxy(const sptr<IRemoteObject>& impl);
    ~TokenSyncCallbackProxy() override;
    int32_t GetRemoteHapTokenInfo(const std::string& deviceID, AccessTokenID tokenID) override;
    int32_t DeleteRemoteHapTokenInfo(AccessTokenID tokenID) override;
    int32_t UpdateRemoteHapTokenInfo(const HapTokenInfoForSync& tokenInfo) override;

private:
    static inline BrokerDelegator<TokenSyncCallbackProxy> delegator_;
};
#endif // TOKEN_SYNC_ENABLE
} // namespace AccessToken
} // namespace Security
} // namespace OHOS
#endif // ACCESSTOKEN_CALLBACK_PROXYS_H
