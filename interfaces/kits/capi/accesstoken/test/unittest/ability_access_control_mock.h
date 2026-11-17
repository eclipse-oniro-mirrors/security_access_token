/*
 * Copyright (c) 2026 Huawei Device Co., Ltd.
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 *
 * http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 */

#ifndef ABILITY_ACCESS_CONTROL_MOCK_H
#define ABILITY_ACCESS_CONTROL_MOCK_H

#include <string>
#include <vector>

#include "accesstoken_kit.h"
#include "want.h"

namespace OHOS {
namespace Security {
namespace AccessToken {
struct MockState {
    bool dialogEnabled;
    uint64_t selfTokenId;
    bool isBinToken;
    bool grantInfoValid;
    PermissionOper oper;
    PermissionOper permState;
    PermissionErrorReason reason;
    int verifyResult;
    int startAbilityErr;
    int startAbilityCount;
    std::vector<sptr<IRemoteObject>> receivers;
};

extern MockState g_mockState;

void ResetMockState();
} // namespace AccessToken
} // namespace Security
} // namespace OHOS

#endif // ABILITY_ACCESS_CONTROL_MOCK_H
