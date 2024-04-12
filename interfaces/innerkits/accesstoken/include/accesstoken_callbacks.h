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

#ifndef ACCESSTOKEN_CALLBACKS_H
#define ACCESSTOKEN_CALLBACKS_H


#include "accesstoken_callback_stubs.h"
#include "perm_state_change_callback_customize.h"
#ifdef TOKEN_SYNC_ENABLE
#include "token_sync_kit_interface.h"
#endif // TOKEN_SYNC_ENABLE

namespace OHOS {
namespace Security {
namespace AccessToken {
class PermissionStateChangeCallback : public PermissionStateChangeCallbackStub {
public:
    explicit PermissionStateChangeCallback(const std::shared_ptr<PermStateChangeCallbackCustomize>& customizedCallback);
    ~PermissionStateChangeCallback() override;

    void PermStateChangeCallback(PermStateChangeInfo& result) override;

    void Stop();

private:
    std::shared_ptr<PermStateChangeCallbackCustomize> customizedCallback_;
};

#ifdef TOKEN_SYNC_ENABLE
class TokenSyncCallback : public TokenSyncCallbackStub {
public:
    explicit TokenSyncCallback(const std::shared_ptr<TokenSyncKitInterface>& tokenSyncCallback);
    ~TokenSyncCallback() override;

    int32_t GetRemoteHapTokenInfo(const std::string& deviceID, AccessTokenID tokenID) override;
    int32_t DeleteRemoteHapTokenInfo(AccessTokenID tokenID) override;
    int32_t UpdateRemoteHapTokenInfo(const HapTokenInfoForSync& tokenInfo) override;

private:
    std::shared_ptr<TokenSyncKitInterface> tokenSyncCallback_;
};
#endif // TOKEN_SYNC_ENABLE
} // namespace AccessToken
} // namespace Security
} // namespace OHOS
#endif // ACCESSTOKEN_CALLBACKS_H
