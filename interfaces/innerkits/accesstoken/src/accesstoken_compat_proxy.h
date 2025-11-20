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

#ifndef OHOS_SECURITY_ACCESSTOKEN_COMPAT_PROXY_H
#define OHOS_SECURITY_ACCESSTOKEN_COMPAT_PROXY_H

#include <iremote_proxy.h>
#include "accesstoken_compat_parcel.h"

namespace OHOS {
namespace Security {
namespace AccessToken {
using namespace OHOS::Security::AccessToken;
enum class IAccessTokenManagerIpcCode {
    COMMAND_VERIFY_ACCESS_TOKEN = 1,
    COMMAND_GET_NATIVE_TOKEN_ID = 54,
    COMMAND_GET_HAP_TOKEN_INFO_IN_UNSIGNED_INT_OUT_HAPTOKENINFOCOMPATIDL = 200,
    COMMAND_GET_PERMISSION_CODE = 201,
};

class IAccessTokenManager : public IRemoteBroker {
public:
    DECLARE_INTERFACE_DESCRIPTOR(u"OHOS.Security.AccessToken.IAccessTokenManager");
    virtual int32_t VerifyAccessToken(uint32_t tokenID, const std::string& permissionName, int32_t& state) = 0;
    virtual int32_t GetNativeTokenId(const std::string& processName, uint32_t& tokenID) = 0;
    virtual int32_t GetHapTokenInfo(uint32_t tokenID, HapTokenInfoCompatParcel& hapTokenInfo) = 0;
    virtual int32_t GetPermissionCode(const std::string& permission, uint32_t& permCode) = 0;
};

class AccessTokenCompatProxy : public IRemoteProxy<IAccessTokenManager> {
public:
    explicit AccessTokenCompatProxy(
        const sptr<IRemoteObject>& remote)
        : IRemoteProxy<IAccessTokenManager>(remote)
    {}

    virtual ~AccessTokenCompatProxy()
    {}

    int32_t VerifyAccessToken(uint32_t tokenID, const std::string& permissionName, int32_t& state) override;
    int32_t GetNativeTokenId(const std::string& processName, uint32_t& tokenID) override;
    int32_t GetHapTokenInfo(uint32_t tokenID, HapTokenInfoCompatParcel& hapTokenInfo) override;
    int32_t GetPermissionCode(const std::string& permission, uint32_t& permCode) override;

private:
    static inline BrokerDelegator<AccessTokenCompatProxy> delegator_;
};
} // namespace AccessToken
} // namespace Security
} // namespace OHOS
#endif // OHOS_SECURITY_ACCESSTOKEN_COMPAT_PROXY_H

