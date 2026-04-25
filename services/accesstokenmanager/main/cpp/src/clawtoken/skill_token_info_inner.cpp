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

#include "skill_token_info_inner.h"

namespace OHOS {
namespace Security {
namespace AccessToken {
int32_t SkillTokenInfoInner::Init(const ClawTokenBaseInfo& baseInfo, const SkillInfo& info,
    const std::vector<PermissionStatus>& permStateList)
{
    int32_t ret = InitBaseInfo(baseInfo);
    if (ret != RET_SUCCESS) {
        return ret;
    }
    info_ = info;
    return InitPermissionData(permStateList);
}

ClawTokenType SkillTokenInfoInner::GetType() const
{
    return ClawTokenType::SKILL;
}

void SkillTokenInfoInner::GetTokenInfo(SkillTokenInfo& info) const
{
    info.hostTokenId = GetHostTokenId();
    info.userId = GetUserId();
    info.skillName = info_.skillName;
    info.bundleName = info_.bundleName;
    info.moduleName = info_.moduleName;
}
} // namespace AccessToken
} // namespace Security
} // namespace OHOS
