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

#ifndef MOCK_SAF_AGENT_FENCE_H
#define MOCK_SAF_AGENT_FENCE_H

#include <cstdint>
#include <string>
#include <vector>

namespace SAF {
struct VerifyTicketInfo {
    std::string message;
    std::string challenge;
    std::string ticket;
};

class SafAgentFence {
public:
    SafAgentFence() = default;
    ~SafAgentFence() = default;

    int32_t BatchGenerateTicket(int32_t userId, const std::string& callerId,
        const std::vector<std::string>& messages, std::vector<VerifyTicketInfo>& tickets);

    int32_t BatchVerifyTicket(int32_t userId, const std::string& callerId,
        const std::vector<VerifyTicketInfo>& verifyInfos, std::vector<int32_t>& verifyRes);
};
} // namespace SAF

namespace OHOS {
namespace Security {
namespace AccessToken {

void SetMockGenerateTicketResult(std::vector<SAF::VerifyTicketInfo> tickets, int32_t ret);
void SetMockVerifyTicketResult(std::vector<int32_t> verifyRes, int32_t ret);
void ResetMockCounter();

} // namespace AccessToken
} // namespace Security
} // namespace OHOS
#endif // MOCK_SAF_AGENT_FENCE_H