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

#ifndef ACCESS_TOKEN_CLAW_TOKEN_INFO_MANAGER_H
#define ACCESS_TOKEN_CLAW_TOKEN_INFO_MANAGER_H

#include <memory>
#include <shared_mutex>
#include <unordered_map>
#include <unordered_set>
#include <vector>

#include "claw_token_info_inner_base.h"
#include "nocopyable.h"

namespace OHOS {
namespace Security {
namespace AccessToken {
class ToolTokenInfoManager final {
public:
    static ToolTokenInfoManager& GetInstance();
    ~ToolTokenInfoManager() = default;

    int32_t InitCliToken(const CliInitInfo& info,
        int32_t callerPid, AccessTokenIDEx& tokenIdEx, std::vector<std::string>& kernelPermList);
    int32_t InitSkillToken(const SkillInitInfo& info,
        int32_t callerPid, AccessTokenIDEx& tokenIdEx, std::vector<std::string>& kernelPermList);
    int32_t DeleteToolTokenByPid(int32_t pid);

    bool IsToolToken(AccessTokenID tokenId) const;
    int32_t GetHostTokenId(AccessTokenID toolTokenId, AccessTokenID& hostTokenId) const;
    int32_t VerifyToolAccessToken(AccessTokenID tokenId, const std::string& permissionName) const;
    int32_t GetCliTokenInfo(AccessTokenID tokenId, CliTokenInfo& info) const;
    int32_t GetSkillTokenInfo(AccessTokenID tokenId, SkillTokenInfo& info) const;

private:
    ToolTokenInfoManager() = default;
    DISALLOW_COPY_AND_MOVE(ToolTokenInfoManager);

    bool CheckCliInfo(const CliInfo& info) const;
    bool CheckSkillInfo(const SkillInfo& info) const;
    int32_t GetUserIdByHostTokenId(AccessTokenID hostTokenId, int32_t& userId) const;
    int32_t VerifyCliInitInputAndTicket(const CliInitInfo& info, int32_t callerPid,
        std::vector<PermissionStatus>& permStateList) const;
    int32_t VerifySkillInitInputAndTicket(const SkillInitInfo& info, int32_t callerPid,
        std::vector<PermissionStatus>& permStateList) const;
    AccessTokenIDEx CreateToolTokenId(ToolTokenType type) const;
    int32_t BuildToolTokenBaseInfo(AccessTokenID hostTokenId, int32_t callerPid, ToolTokenType type,
        const std::string& challenge, AccessTokenIDEx& tokenIdEx, ClawTokenBaseInfo& baseInfo) const;
    int32_t FinalizeToolTokenInit(const std::shared_ptr<ClawTokenInfoInnerBase>& inner,
        const ClawTokenBaseInfo& baseInfo, const std::vector<PermissionStatus>& permStateList,
        std::vector<std::string>& kernelPermList);
    int32_t AddToolTokenInfoLocked(const std::shared_ptr<ClawTokenInfoInnerBase>& inner);
    std::shared_ptr<ClawTokenInfoInnerBase> RemoveToolTokenInfoLocked(AccessTokenID tokenId);
    std::shared_ptr<ClawTokenInfoInnerBase> RemoveToolTokenInfoByPidLocked(int32_t pid);

    mutable std::shared_mutex lock_;
    std::unordered_map<AccessTokenID, std::shared_ptr<ClawTokenInfoInnerBase>> toolTokenInfoMap_;
    std::unordered_map<AccessTokenID, std::unordered_set<AccessTokenID>> hostToolTokenMap_;
    std::unordered_map<int32_t, AccessTokenID> pidToolTokenMap_;
};
} // namespace AccessToken
} // namespace Security
} // namespace OHOS

#endif // ACCESS_TOKEN_CLAW_TOKEN_INFO_MANAGER_H
