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

#include "claw_token_info_inner_base.h"

#include "access_token_error.h"
#include "permission_validator.h"

namespace OHOS {
namespace Security {
namespace AccessToken {
ClawTokenInfoInnerBase::~ClawTokenInfoInnerBase()
{
    if (baseInfo_.tokenId != INVALID_TOKENID) {
        (void)PermissionDataBrief::GetInstance().DeleteBriefPermDataByTokenId(baseInfo_.tokenId);
    }
}

int32_t ClawTokenInfoInnerBase::VerifyAccessToken(const std::string& permissionName) const
{
    return PermissionDataBrief::GetInstance().VerifyPermissionStatus(baseInfo_.tokenId, permissionName);
}

int32_t ClawTokenInfoInnerBase::UpdateRestrictedFlag(
    uint32_t permCode, bool isRestricted, bool& hasFlagChanged) const
{
    hasFlagChanged = false;
    PermissionDataBrief::PermissionStatusChangeType changeType =
        PermissionDataBrief::PermissionStatusChangeType::NO_CHANGE;
    int32_t ret = PermissionDataBrief::GetInstance().UpdatePermissionFlag(
        baseInfo_.tokenId, permCode, PERMISSION_RESTRICTED_BY_ADMIN, isRestricted, changeType);
    if (ret != RET_SUCCESS) {
        return ret;
    }
    hasFlagChanged = changeType != PermissionDataBrief::PermissionStatusChangeType::NO_CHANGE;
    return RET_SUCCESS;
}

AccessTokenID ClawTokenInfoInnerBase::GetTokenId() const
{
    return baseInfo_.tokenId;
}

AccessTokenID ClawTokenInfoInnerBase::GetHostTokenId() const
{
    return baseInfo_.hostTokenId;
}

int32_t ClawTokenInfoInnerBase::GetUserId() const
{
    return baseInfo_.userId;
}

int32_t ClawTokenInfoInnerBase::GetCallerPid() const
{
    return baseInfo_.callerPid;
}

int32_t ClawTokenInfoInnerBase::InitBaseInfo(const ClawTokenBaseInfo& baseInfo)
{
    baseInfo_ = baseInfo;
    return RET_SUCCESS;
}

int32_t ClawTokenInfoInnerBase::InitPermissionData(const std::vector<PermissionStatus>& permStateList)
{
    PermissionDataBrief::GetInstance().AddPermToBriefPermission(baseInfo_.tokenId, permStateList, true);
    return RET_SUCCESS;
}
} // namespace AccessToken
} // namespace Security
} // namespace OHOS
