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

#ifndef CLAW_TICKET_MANAGER_TEST_H
#define CLAW_TICKET_MANAGER_TEST_H

#include <gtest/gtest.h>
#include <memory>
#include <string>
#include <vector>

#define private public
#include "accesstoken_manager_service.h"
#include "accesstoken_info_manager.h"
#undef private

#include "claw_ticket_manager.h"
#include "claw_external_mock.h"

namespace OHOS {
namespace Security {
namespace AccessToken {

class ClawTicketManagerTest : public testing::Test {
public:
    static void SetUpTestCase();

    static void TearDownTestCase();

    void SetUp();

    void TearDown();

    AccessTokenID CreateTestHapToken();
    void DeleteTestHapToken(AccessTokenID tokenId);
    std::string GenerateTestCliTicket(AccessTokenID tokenId);
    std::string GenerateTestSkillTicket(AccessTokenID tokenId);

    AccessTokenID testTokenId_ = INVALID_TOKENID;
    std::vector<std::string> testChallenges_;
};

} // namespace AccessToken
} // namespace Security
} // namespace OHOS
#endif // CLAW_TICKET_MANAGER_TEST_H