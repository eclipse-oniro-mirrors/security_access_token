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

#ifndef ACCESS_TOKEN_TEST_MOCK_OS_ACCOUNT_MANAGER_LITE_H
#define ACCESS_TOKEN_TEST_MOCK_OS_ACCOUNT_MANAGER_LITE_H

#include <cstdint>

#include "errors.h"

namespace OHOS {
namespace AccountSA {
class OsAccountManagerLite final {
public:
    static ErrCode GetForegroundOsAccountLocalId(int32_t& localId);
    static ErrCode GetOsAccountForegroundSubProfileId(int32_t osAccountLocalId, int32_t& subProfileId);
    static ErrCode GetOsAccountLocalIdForSubProfile(int32_t subProfileId, int32_t& localId);
    static ErrCode GetOsAccountSubProfileIndex(int32_t osAccountLocalId, int32_t subProfileId, int32_t& appIndex);
    static ErrCode GetOsAccountSubProfileId(int32_t osAccountLocalId, int32_t appIndex, int32_t& subProfileId);
};
} // namespace AccountSA
} // namespace OHOS

namespace OHOS {
namespace Security {
namespace AccessToken {
void SetMockForegroundOsAccountLocalId(int32_t localId, int32_t ret);
int32_t GetMockForegroundOsAccountLocalId();
void SetMockOsAccountForegroundSubProfileId(int32_t subProfileId, int32_t ret);
void SetMockOsAccountLocalIdForSubProfile(int32_t localId, int32_t ret);
void SetMockOsAccountSubProfileIndex(int32_t appIndex, int32_t ret);
void SetMockOsAccountSubProfileId(int32_t subProfileId, int32_t ret);
void ResetMockOsAccountManagerLite();
} // namespace AccessToken
} // namespace Security
} // namespace OHOS

#endif // ACCESS_TOKEN_TEST_MOCK_OS_ACCOUNT_MANAGER_LITE_H
