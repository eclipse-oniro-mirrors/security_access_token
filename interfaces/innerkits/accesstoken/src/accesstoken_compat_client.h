/*
 * Copyright (c) 2025 Huawei Device Co., Ltd.
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

#ifndef ACCESSTOKEN_COMPAT_CLIENT_H
#define ACCESSTOKEN_COMPAT_CLIENT_H

#include <mutex>
#include <string>

#include "access_token.h"
#include "accesstoken_compat_proxy.h"
#include "iremote_object.h"
#include "nocopyable.h"

namespace OHOS {
namespace Security {
namespace AccessToken {
class AccessTokenCompatClient final {
public:
    static AccessTokenCompatClient& GetInstance();
    virtual ~AccessTokenCompatClient();

    int32_t GetPermissionCode(const std::string& permission, uint32_t& opCode);
    int32_t GetHapTokenInfo(AccessTokenID tokenID, HapTokenInfoCompatParcel& hapTokenInfoIdl);
    PermissionState VerifyAccessToken(AccessTokenID tokenID, const std::string& permission);
    AccessTokenID GetNativeTokenId(const std::string& processName);

private:
    AccessTokenCompatClient();
    void OnRemoteDiedHandle();

    DISALLOW_COPY_AND_MOVE(AccessTokenCompatClient);

    class AccessTokenCompatDeathRecipient : public IRemoteObject::DeathRecipient {
    public:
        AccessTokenCompatDeathRecipient() {}
        ~AccessTokenCompatDeathRecipient() override = default;
        void OnRemoteDied(const wptr<IRemoteObject>& object) override;
    };
    std::mutex proxyMutex_;
    sptr<IAccessTokenManager> proxy_ = nullptr;
    sptr<AccessTokenCompatDeathRecipient> serviceDeathObserver_ = nullptr;
    void InitProxy();
    sptr<IAccessTokenManager> GetProxy();
    void ReleaseProxy();
};
} // namespace AccessToken
} // namespace Security
} // namespace OHOS
#endif // ACCESSTOKEN_COMPAT_CLIENT_H
