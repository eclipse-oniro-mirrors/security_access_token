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

#ifndef ACCESSTOKEN_SYNC_KIT_INTERFACE_H
#define ACCESSTOKEN_SYNC_KIT_INTERFACE_H

#include <string>

#include "access_token.h"
#include "hap_token_info.h"

namespace OHOS {
namespace Security {
namespace AccessToken {
enum TokenSyncError {
    TOKEN_SYNC_SUCCESS = 0,
    TOKEN_SYNC_IPC_ERROR,
    TOKEN_SYNC_PARAMS_INVALID,
    TOKEN_SYNC_REMOTE_DEVICE_INVALID,
    TOKEN_SYNC_COMMAND_EXECUTE_FAILED,
    TOKEN_SYNC_OPENSOURCE_DEVICE,
};

class TokenSyncKitInterface {
public:
    TokenSyncKitInterface() {};
    virtual ~TokenSyncKitInterface() {};
    virtual int32_t GetRemoteHapTokenInfo(const std::string& deviceID, AccessTokenID tokenID) const = 0;
    virtual int32_t DeleteRemoteHapTokenInfo(AccessTokenID tokenID) const = 0;
    virtual int32_t UpdateRemoteHapTokenInfo(const HapTokenInfoForSync& tokenInfo) const = 0;
};
} // namespace AccessToken
} // namespace Security
} // namespace OHOS
#endif // ACCESSTOKEN_SYNC_KIT_INTERFACE_H