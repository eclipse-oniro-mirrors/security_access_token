/*
 * Copyright (c) 2021 Huawei Device Co., Ltd.
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

#ifndef ACCESSTOKEN_MANAGER_CLIENT_H
#define ACCESSTOKEN_MANAGER_CLIENT_H

#include <string>

#include "i_accesstoken_manager.h"
#include "nocopyable.h"

namespace OHOS {
namespace Security {
namespace AccessToken {
class AccessTokenManagerClient final {
public:
    static AccessTokenManagerClient& GetInstance();

    virtual ~AccessTokenManagerClient();

    int VerifyAccesstoken(AccessTokenID tokenID, const std::string& permissionName) const;
private:
    AccessTokenManagerClient();

    DISALLOW_COPY_AND_MOVE(AccessTokenManagerClient);

    sptr<IAccessTokenManager> GetProxy() const;
};
} // namespace AccessToken
} // namespace Security
} // namespace OHOS
#endif // ACCESSTOKEN_MANAGER_CLIENT_H
