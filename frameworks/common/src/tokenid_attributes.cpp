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
static constexpr uint32_t TOKEN_ID_LOW_BITS = 32;
static constexpr uint32_t SYSTEM_APP_ATTR_INDEX = 0;
static constexpr uint32_t DEBUG_APP_ATTR_INDEX = 3;

static constexpr uint64_t GetFullTokenAttrMask(uint32_t attrIndex)
{
    return static_cast<uint64_t>(1) << (TOKEN_ID_LOW_BITS + attrIndex);
}

static constexpr uint32_t GetTokenAttrMask(uint32_t attrIndex)
{
    return static_cast<uint32_t>(1) << attrIndex;
}

static constexpr uint64_t SYSTEM_APP_MASK = GetFullTokenAttrMask(SYSTEM_APP_ATTR_INDEX);
static constexpr uint64_t DEBUG_APP_MASK = GetFullTokenAttrMask(DEBUG_APP_ATTR_INDEX);
static constexpr uint32_t DEBUG_APP_ATTR_MASK = GetTokenAttrMask(DEBUG_APP_ATTR_INDEX);
}
ATokenTypeEnum TokenIDAttributes::GetTokenIdTypeEnum(AccessTokenID id)
{
    AccessTokenIDInner* idInner = reinterpret_cast<AccessTokenIDInner*>(&id);
    return static_cast<ATokenTypeEnum>(idInner->type);
}

bool TokenIDAttributes::IsToolTokenId(AccessTokenID id)
{
    AccessTokenIDInner* idInner = reinterpret_cast<AccessTokenIDInner*>(&id);
    return idInner->toolFlag == 1;
}

bool TokenIDAttributes::IsDebugApp(FullTokenID fullTokenId)
{
    return (fullTokenId & DEBUG_APP_MASK) == DEBUG_APP_MASK;
}

bool TokenIDAttributes::IsDebugAppAttr(AccessTokenAttr tokenAttr)
{
    return (static_cast<uint32_t>(tokenAttr) & DEBUG_APP_ATTR_MASK) == DEBUG_APP_ATTR_MASK;
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
