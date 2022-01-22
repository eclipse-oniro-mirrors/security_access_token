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

#include "i_tokensync_manager.h"

#include "nocopyable.h"

namespace OHOS {
namespace Security {
namespace AccessToken {
class TokenSyncManagerClient final {
public:
    static TokenSyncManagerClient& GetInstance();

    virtual ~TokenSyncManagerClient();

    int VerifyPermission(const std::string& bundleName, const std::string& permissionName, int userId) const;

private:
    TokenSyncManagerClient();

    DISALLOW_COPY_AND_MOVE(TokenSyncManagerClient);

    sptr<ITokenSyncManager> GetProxy() const;
};
} // namespace AccessToken
} // namespace Security
} // namespace OHOS
#endif // ACCESSTOKEN_MANAGER_CLIENT_H
