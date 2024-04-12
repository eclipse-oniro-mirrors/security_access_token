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

#ifndef ACCESSTOKEN_SYNC_KIT_LOADER_H
#define ACCESSTOKEN_SYNC_KIT_LOADER_H

#include "token_sync_kit_interface.h"

namespace OHOS {
namespace Security {
namespace AccessToken {
const static std::string TOKEN_SYNC_LIBPATH = "libtokensync_sdk.z.so";

class TokenSyncManagerLoader final : public TokenSyncKitInterface {
    int32_t GetRemoteHapTokenInfo(const std::string& deviceID, AccessTokenID tokenID) const override;
    int32_t DeleteRemoteHapTokenInfo(AccessTokenID tokenID) const override;
    int32_t UpdateRemoteHapTokenInfo(const HapTokenInfoForSync& tokenInfo) const override;
};

extern "C" {
    void* Create();
    void Destroy(void* loaderPtr);
};
} // namespace AccessToken
} // namespace Security
} // namespace OHOS
#endif // ACCESSTOKEN_SYNC_KIT_LOADER_H
