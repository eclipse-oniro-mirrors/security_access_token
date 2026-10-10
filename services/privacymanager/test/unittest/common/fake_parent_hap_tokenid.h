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

#ifndef ACCESS_TOKEN_FAKE_PARENT_HAP_TOKENID_H
#define ACCESS_TOKEN_FAKE_PARENT_HAP_TOKENID_H

#include <cstdint>

namespace OHOS {
namespace Security {
namespace AccessToken {
struct FakeParentHapTokenIdState final {
    int32_t ret = 0;
    uint64_t parentHapTokenID = 0;
    int32_t callCount = 0;
    uint32_t lastBinTokenID = 0;
};

FakeParentHapTokenIdState& GetFakeParentHapTokenIdState();
void ResetFakeParentHapTokenIdState();
} // namespace AccessToken
} // namespace Security
} // namespace OHOS

#ifdef __cplusplus
extern "C" {
#endif

int32_t GetParentHapTokenID(uint32_t bin, uint64_t *parent);

#ifdef __cplusplus
}
#endif

#endif // ACCESS_TOKEN_FAKE_PARENT_HAP_TOKENID_H
