/*
 * Copyright (c) 2025 Huawei Device Co., Ltd.
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

#include "tokenid_attributes.h"

namespace OHOS {
namespace Security {
namespace AccessToken {
namespace {
static const uint64_t SYSTEM_APP_MASK = (static_cast<uint64_t>(1) << 32);
}
ATokenTypeEnum TokenIDAttributes::GetTokenIdTypeEnum(AccessTokenID id)
{
    AccessTokenIDInner* idInner = reinterpret_cast<AccessTokenIDInner*>(&id);
    return static_cast<ATokenTypeEnum>(idInner->type);
}

int TokenIDAttributes::GetTokenIdDlpFlag(AccessTokenID id)
{
    AccessTokenIDInner* idInner = reinterpret_cast<AccessTokenIDInner*>(&id);
    return idInner->dlpFlag;
}

int TokenIDAttributes::GetTokenIdCloneFlag(AccessTokenID id)
{
    AccessTokenIDInner* idInner = reinterpret_cast<AccessTokenIDInner*>(&id);
    return idInner->cloneFlag;
}

bool TokenIDAttributes::IsSystemApp(uint64_t id)
{
    return (id & SYSTEM_APP_MASK) == SYSTEM_APP_MASK;
}
} // namespace AccessToken
} // namespace Security
} // namespace OHOS
