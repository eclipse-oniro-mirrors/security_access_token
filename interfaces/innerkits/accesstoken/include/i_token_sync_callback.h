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

#ifndef I_TOKEN_SYNC_CALLBACK_H
#define I_TOKEN_SYNC_CALLBACK_H

#include <string>

#include "iremote_broker.h"
#include "errors.h"

#include "access_token.h"
#include "hap_token_info_for_sync_parcel.h"
#include "tokensync_callback_ipc_interface_code.h"

namespace OHOS {
namespace Security {
namespace AccessToken {

class ITokenSyncCallback : public IRemoteBroker {
public:
    DECLARE_INTERFACE_DESCRIPTOR(u"ohos.security.accesstoken.ITokenSyncCallback");

    virtual int32_t GetRemoteHapTokenInfo(const std::string& deviceID, AccessTokenID tokenID) = 0;
    virtual int32_t DeleteRemoteHapTokenInfo(AccessTokenID tokenID) = 0;
    virtual int32_t UpdateRemoteHapTokenInfo(const HapTokenInfoForSync& tokenInfo) = 0;
};
} // namespace AccessToken
} // namespace Security
} // namespace OHOS
#endif // I_TOKEN_SYNC_CALLBACK_H