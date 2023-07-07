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

#include "tokenid_kit.h"

#include <cinttypes>

#include "accesstoken_log.h"
#include "access_token.h"

namespace OHOS {
namespace Security {
namespace AccessToken {
namespace {
static constexpr OHOS::HiviewDFX::HiLogLabel LABEL = {LOG_CORE, SECURITY_DOMAIN_ACCESSTOKEN, "TokenIdKit"};
static const uint64_t SYSTEM_APP_MASK = (static_cast<uint64_t>(1) << 32);
static const uint64_t TOKEN_ID_LOWMASK = 0xffffffff;
}
bool TokenIdKit::IsSystemAppByFullTokenID(uint64_t tokenId)
{
    ACCESSTOKEN_LOG_DEBUG(LABEL, "called, tokenId=%{public}" PRId64, tokenId);
    return (tokenId & SYSTEM_APP_MASK) == SYSTEM_APP_MASK;
}
uint64_t TokenIdKit::GetRenderTokenID(uint64_t tokenId)
{
    AccessTokenID id = tokenId & TOKEN_ID_LOWMASK;
    if (id == INVALID_TOKENID) {
        ACCESSTOKEN_LOG_ERROR(LABEL, "tokenID is invalid");
        return tokenId;
    }
    AccessTokenIDInner *idInner = reinterpret_cast<AccessTokenIDInner *>(&id);
    idInner->renderFlag = 1;

    id = *reinterpret_cast<AccessTokenID *>(idInner);
    return static_cast<uint64_t>(id);
}
}  // namespace AccessToken
}  // namespace Security
}  // namespace OHOS
