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

#ifndef ACCESS_TOKEN_FAKE_TOKEN_SETPROC_H
#define ACCESS_TOKEN_FAKE_TOKEN_SETPROC_H

#include <vector>

#include "access_token.h"

namespace OHOS {
namespace Security {
namespace AccessToken {
struct FakeSpmKernelState final {
    uint8_t addIdxErr = 0;
    uint8_t setIdxErr = 0;
    int32_t addRet = 0;
    int32_t setRet = 0;
    int32_t getVersionRet = 0;
    int32_t getRetOnCall0 = 0;
    int32_t getRetOnCall1 = 0;
    int32_t removeRet = 0;
    int32_t addPermRet = 0;
    int32_t removePermRet = 0;
    int addCallCount = 0;
    int setCallCount = 0;
    int getCallCount = 0;
    int removeCallCount = 0;
    int addPermCallCount = 0;
    int removePermCallCount = 0;
    std::vector<int32_t> addPermRetSequence;
    std::vector<int32_t> addRetSequence;
    std::vector<int32_t> setRetSequence;
    std::vector<int32_t> getRetSequence;
    std::vector<AccessTokenID> addPermTokenIds;
    std::vector<AccessTokenID> removePermTokenIds;
    std::vector<std::vector<AccessTokenID>> setTokenBatches;
    std::vector<AccessTokenID> removedTokenIds;
};

FakeSpmKernelState& GetFakeSpmKernelState();
void ResetFakeSpmKernelState();
} // namespace AccessToken
} // namespace Security
} // namespace OHOS

#endif // ACCESS_TOKEN_FAKE_TOKEN_SETPROC_H
