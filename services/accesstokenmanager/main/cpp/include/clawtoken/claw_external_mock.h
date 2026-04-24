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

#ifndef SERVICES_ACCESSTOKENMANAGER_CLAW_EXTERNAL_MOCK_H
#define SERVICES_ACCESSTOKENMANAGER_CLAW_EXTERNAL_MOCK_H

#include <cstddef>
#include <cstdint>
#include <mutex>
#include <string>
#include <vector>

#include "access_token.h"
#include "claw_permission_info.h"

namespace OHOS {
namespace Security {
namespace AccessToken {
struct CommandInfo {
    std::string cmdName;
    std::string subCmd;
};

struct CommandPermissionInfo {
    CommandInfo cmd;
    std::vector<std::string> permissions;
    int32_t queryRet = 0;
};

int32_t BatchQueryCommandPermission(
    const std::vector<CommandInfo>& cmds, std::vector<CommandPermissionInfo>& permissionInfos);

    struct VerifyTicketInfo {
    std::string message;
    std::string challenge;
    std::string ticket;
};

int32_t BatchGenerateTicket(uint32_t osAccountId, AccessTokenID callerId,
    const std::vector<std::string>& messages, std::vector<VerifyTicketInfo>& tickets);

int32_t BatchVerifyTicket(uint32_t osAccountId, AccessTokenID callerId,
    const std::vector<VerifyTicketInfo>& verifyInfos, std::vector<int32_t>& verifyRes);
} // namespace AccessToken
} // namespace Security

namespace AppExecFwk {
using ErrCode = int32_t;
static constexpr ErrCode ERR_OK = 0;

struct SkillInfo {
    std::string bundleName;
    std::string moduleName;
    std::string skillName;
    int32_t skillId = 0;
    std::string hapPath;
    std::string abilityName;
    std::string description;
    std::vector<std::string> srcEntries;
    std::vector<std::string> permissions;
    std::vector<std::string> requestPermissions;
};

class SkillManager {
public:
    ErrCode GetSkillInfo(const std::string& bundleName, const std::string& moduleName,
        const std::string& skillName, uint32_t flags, int32_t userId, SkillInfo& skillInfo);
};
} // namespace AppExecFwk
} // namespace OHOS

#endif // SERVICES_ACCESSTOKENMANAGER_CLAW_EXTERNAL_MOCK_H
