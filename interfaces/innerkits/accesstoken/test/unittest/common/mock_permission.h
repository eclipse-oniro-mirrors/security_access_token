/*
 * Copyright (c) 2026 Huawei Device Co., Ltd.
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

#ifndef PRIVACY_TEST_MOCK_PERMISSION_H
#define PRIVACY_TEST_MOCK_PERMISSION_H

#include <cstdint>
#include <string>
#include <vector>
#include <unistd.h>

#include "access_token.h"

namespace OHOS {
namespace Security {
namespace AccessToken {
uid_t MockAccessTokenUid();
void RestoreUid(uid_t originalEuid);
AccessTokenID TransfterStrToAccesstokenID(const std::string& numStr);
AccessTokenID GetTokenByProcessName(AccessTokenID shellToken, const std::string& processName);

class MockToken final {
public:
    MockToken(AccessTokenID shellToken, const std::string processName, bool isSystemApp);
    ~MockToken();

    MockToken(const MockToken&) = delete;
    MockToken& operator=(const MockToken&) = delete;

    AccessTokenID GetTokenId() const;
    std::string GetMockErrorMsg() const;
    void Grant(const std::string& permission);
    void Revoke(const std::string& permission);

private:
    void SetPermission(const std::string& permission, bool status);

    AccessTokenID tokenId_ = INVALID_TOKENID;
    uint64_t selfToken_ = 0;
    std::vector<std::string> oriPermissionList_;
    std::vector<bool> oriStatusList_;
    std::string errMsg_ = "";
};
} // namespace AccessToken
} // namespace Security
} // namespace OHOS
#endif // PRIVACY_TEST_MOCK_PERMISSION_H
