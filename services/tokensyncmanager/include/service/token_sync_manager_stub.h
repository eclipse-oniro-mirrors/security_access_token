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

#ifndef TOKEN_SYNC_MANAGER_STUB_H
#define TOKEN_SYNC_MANAGER_STUB_H

#include "i_token_sync_manager.h"
#include "iremote_stub.h"
#include "nocopyable.h"

namespace OHOS {
namespace Security {
namespace AccessToken {
class TokenSyncManagerStub : public IRemoteStub<ITokenSyncManager> {
public:
    TokenSyncManagerStub() = default;
    virtual ~TokenSyncManagerStub() = default;

    int OnRemoteRequest(uint32_t code, MessageParcel& data, MessageParcel& reply, MessageOption& options) override;

private:
    void GetRemoteHapTokenInfoInner(MessageParcel& data, MessageParcel& reply);
    void DeleteRemoteHapTokenInfoInner(MessageParcel& data, MessageParcel& reply);
    void UpdateRemoteHapTokenInfoInner(MessageParcel& data, MessageParcel& reply);

    bool IsNativeProcessCalling() const;
    bool IsRootCalling() const;
};
} // namespace AccessToken
} // namespace Security
} // namespace OHOS
#endif // TOKEN_SYNC_MANAGER_STUB_H
