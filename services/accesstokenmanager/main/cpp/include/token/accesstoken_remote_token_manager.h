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

#ifndef ACCESSTOKEN_TOKEN_REMOTE_TOKEN_MANAGER_H
#define ACCESSTOKEN_TOKEN_REMOTE_TOKEN_MANAGER_H

#include <map>
#include <memory>
#include <vector>

#include "access_token.h"
#include "hap_token_info.h"
#include "hap_token_info_inner.h"
#include "native_token_info.h"
#include "native_token_info_inner.h"
#include "nocopyable.h"
#include "rwlock.h"
#include "thread_pool.h"

namespace OHOS {
namespace Security {
namespace AccessToken {
class AccessTokenRemoteDevice final {
public:
    std::string DeviceID_; // networkID
    std::map<AccessTokenID, AccessTokenID> MappingTokenIDPairMap_;
};

class AccessTokenRemoteTokenManager final {
public:
    static AccessTokenRemoteTokenManager& GetInstance();
    ~AccessTokenRemoteTokenManager();
    AccessTokenID MapRemoteDeviceTokenToLocal(const std::string& deviceID, AccessTokenID remoteID);
    int GetDeviceAllRemoteTokenID(const std::string& deviceID, std::vector<AccessTokenID>& mapIDs);
    AccessTokenID GetDeviceMappingTokenID(const std::string& deviceID, AccessTokenID remoteID);
    int RemoveDeviceMappingTokenID(const std::string& deviceID, AccessTokenID remoteID);

private:
    AccessTokenRemoteTokenManager();
    DISALLOW_COPY_AND_MOVE(AccessTokenRemoteTokenManager);

    OHOS::Utils::RWLock remoteDeviceLock_;
    std::map<std::string, AccessTokenRemoteDevice> remoteDeviceMap_;
};
} // namespace AccessToken
} // namespace Security
} // namespace OHOS
#endif // ACCESSTOKEN_TOKEN_REMOTE_TOKEN_MANAGER_H

