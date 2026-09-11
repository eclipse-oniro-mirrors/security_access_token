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

#include "fake_parent_hap_tokenid.h"
#include "token_setproc.h"

namespace OHOS {
namespace Security {
namespace AccessToken {
namespace {
constexpr uint32_t INVAL_TOKEN_ID = 0;
}

FakeParentHapTokenIdState g_fakeParentHapTokenIdState;

FakeParentHapTokenIdState& GetFakeParentHapTokenIdState()
{
    return g_fakeParentHapTokenIdState;
}

void ResetFakeParentHapTokenIdState()
{
    g_fakeParentHapTokenIdState = {};
}

} // namespace AccessToken
} // namespace Security
} // namespace OHOS

using OHOS::Security::AccessToken::INVAL_TOKEN_ID;

extern "C" int32_t GetParentHapTokenID(uint32_t bin, uint64_t *parent)
{
    if (bin == INVAL_TOKEN_ID || parent == nullptr) {
        return ACCESS_TOKEN_PARAM_INVALID;
    }

    auto& state = OHOS::Security::AccessToken::GetFakeParentHapTokenIdState();
    state.callCount++;
    state.lastBinTokenID = bin;
    if (state.ret == 0) {
        *parent = state.parentHapTokenID;
    }
    return state.ret;
}
