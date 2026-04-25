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

#ifndef ACCESS_TOKEN_CLAW_TOKEN_INFO_INNER_BASE_H
#define ACCESS_TOKEN_CLAW_TOKEN_INFO_INNER_BASE_H

#include <vector>

#include "claw_token_info_def.h"
#include "permission_data_brief.h"

namespace OHOS {
namespace Security {
namespace AccessToken {
class ClawTokenInfoInnerBase {
public:
    virtual ~ClawTokenInfoInnerBase();

    virtual ClawTokenType GetType() const = 0;
    virtual int32_t VerifyAccessToken(const std::string& permissionName) const;

    AccessTokenID GetTokenId() const;
    AccessTokenID GetHostTokenId() const;
    int32_t GetUserId() const;
    int32_t GetCallerPid() const;

protected:
    ClawTokenInfoInnerBase() = default;

    int32_t InitBaseInfo(const ClawTokenBaseInfo& baseInfo);
    int32_t InitPermissionData(const std::vector<PermissionStatus>& permStateList);

    ClawTokenBaseInfo baseInfo_;
};
} // namespace AccessToken
} // namespace Security
} // namespace OHOS

#endif // ACCESS_TOKEN_CLAW_TOKEN_INFO_INNER_BASE_H
