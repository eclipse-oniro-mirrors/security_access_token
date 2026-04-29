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

#include "saf_agent_fence.h"

namespace {
int g_generateCounter = 0;
int g_verifyCounter = 0;

std::vector<SAF::VerifyTicketInfo> g_generateTickets;
int32_t g_generateRet = 0;
bool g_generateConfigured = false;

std::vector<int32_t> g_verifyRes;
int32_t g_verifyRet = 0;
bool g_verifyConfigured = false;
} // anonymous namespace

namespace SAF {
int32_t SafAgentFence::BatchGenerateTicket(int32_t userId, const std::string& callerId,
    const std::vector<std::string>& messages, std::vector<VerifyTicketInfo>& tickets)
{
    if (g_generateConfigured) {
        tickets = g_generateTickets;
        g_generateConfigured = false;
        return g_generateRet;
    }

    for (size_t i = 0; i < messages.size(); ++i) {
        ++g_generateCounter;
        VerifyTicketInfo info;
        info.message = messages[i];
        info.challenge = "mock_challenge_" + std::to_string(g_generateCounter);
        info.ticket = "mock_ticket_" + std::to_string(g_generateCounter);
        tickets.emplace_back(info);
    }

    return 0;
}

int32_t SafAgentFence::BatchVerifyTicket(int32_t userId, const std::string& callerId,
    const std::vector<VerifyTicketInfo>& verifyInfos, std::vector<int32_t>& verifyRes)
{
    if (g_verifyConfigured) {
        verifyRes = g_verifyRes;
        g_verifyConfigured = false;
        return g_verifyRet;
    }

    for (size_t i = 0; i < verifyInfos.size(); ++i) {
        ++g_verifyCounter;
        verifyRes.emplace_back(0);
    }

    return 0;
}
} // namespace SAF

namespace OHOS {
namespace Security {
namespace AccessToken {
void SetMockGenerateTicketResult(std::vector<SAF::VerifyTicketInfo> tickets, int32_t ret)
{
    g_generateTickets = tickets;
    g_generateRet = ret;
    g_generateConfigured = true;
}

void SetMockVerifyTicketResult(std::vector<int32_t> verifyRes, int32_t ret)
{
    g_verifyRes = verifyRes;
    g_verifyRet = ret;
    g_verifyConfigured = true;
}

void ResetMockCounter()
{
    g_generateCounter = 0;
    g_verifyCounter = 0;
}
} // namespace AccessToken
} // namespace Security
} // namespace OHOS