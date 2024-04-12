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

#ifndef ACCESSTOKEN_CALLBACK_STUBS_H
#define ACCESSTOKEN_CALLBACK_STUBS_H


#include "i_permission_state_callback.h"
#ifdef TOKEN_SYNC_ENABLE
#include "i_token_sync_callback.h"
#endif // TOKEN_SYNC_ENABLE
#include "iremote_stub.h"
#include "nocopyable.h"

namespace OHOS {
namespace Security {
namespace AccessToken {
class PermissionStateChangeCallbackStub : public IRemoteStub<IPermissionStateCallback> {
public:
    PermissionStateChangeCallbackStub() = default;
    virtual ~PermissionStateChangeCallbackStub() = default;

    int32_t OnRemoteRequest(uint32_t code, MessageParcel& data, MessageParcel& reply, MessageOption& option) override;
};

#ifdef TOKEN_SYNC_ENABLE
class TokenSyncCallbackStub : public IRemoteStub<ITokenSyncCallback> {
public:
    TokenSyncCallbackStub() = default;
    virtual ~TokenSyncCallbackStub() = default;

    int32_t OnRemoteRequest(uint32_t code, MessageParcel& data, MessageParcel& reply, MessageOption& option) override;
private:
    void GetRemoteHapTokenInfoInner(MessageParcel& data, MessageParcel& reply);
    void DeleteRemoteHapTokenInfoInner(MessageParcel& data, MessageParcel& reply);
    void UpdateRemoteHapTokenInfoInner(MessageParcel& data, MessageParcel& reply);
    bool IsAccessTokenCalling() const;
};
#endif // TOKEN_SYNC_ENABLE
} // namespace AccessToken
} // namespace Security
} // namespace OHOS
#endif // ACCESSTOKEN_CALLBACK_STUBS_H
