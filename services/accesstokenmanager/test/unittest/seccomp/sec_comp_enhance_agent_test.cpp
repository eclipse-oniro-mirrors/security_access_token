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

#include "access_token_error.h"
#include "sec_comp_enhance_agent_test.h"

using namespace testing::ext;
using namespace OHOS;

namespace OHOS {
namespace Security {
namespace AccessToken {

void SecCompEnhanceAgentTest::SetUpTestCase()
{
}

void SecCompEnhanceAgentTest::TearDownTestCase()
{
}

void SecCompEnhanceAgentTest::SetUp()
{
}

void SecCompEnhanceAgentTest::TearDown()
{
}

/**
 * @tc.name: ProcessFromForegroundList001
 * @tc.desc: Monitor foreground list for process after process state changed
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(SecCompEnhanceAgentTest, ProcessFromForegroundList001, TestSize.Level1)
{
    SecCompEnhanceData data;
    data.callback = nullptr;
    data.challenge = 0;
    data.seqNum = 0;

    SecCompEnhanceData data1;

    EXPECT_EQ(AccessTokenError::ERR_PARAM_INVALID,
        SecCompEnhanceAgent::GetInstance().GetSecCompEnhance(getpid(), data1));

    EXPECT_EQ(RET_SUCCESS, SecCompEnhanceAgent::GetInstance().RegisterSecCompEnhance(data));
    EXPECT_EQ(RET_SUCCESS, SecCompEnhanceAgent::GetInstance().GetSecCompEnhance(getpid(), data1));
    EXPECT_EQ(1, data1.count);

    SecCompEnhanceAgent::GetInstance().RemoveSecCompEnhance(data1.pid, data1.token);
    EXPECT_EQ(AccessTokenError::ERR_PARAM_INVALID,
        SecCompEnhanceAgent::GetInstance().GetSecCompEnhance(getpid(), data1));
}

/**
 * @tc.name: ProcessFromForegroundList002
 * @tc.desc: Monitor foreground list for process after process state changed
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(SecCompEnhanceAgentTest, ProcessFromForegroundList002, TestSize.Level1)
{
    SecCompEnhanceData data;
    data.callback = nullptr;
    data.challenge = 0;
    data.seqNum = 0;

    EXPECT_EQ(RET_SUCCESS, SecCompEnhanceAgent::GetInstance().RegisterSecCompEnhance(data));

    SecCompEnhanceData data1;
    EXPECT_EQ(RET_SUCCESS, SecCompEnhanceAgent::GetInstance().GetSecCompEnhance(getpid(), data1));
    EXPECT_EQ(1, data1.count);

    EXPECT_EQ(ERR_CALLBACK_ALREADY_EXIST, SecCompEnhanceAgent::GetInstance().RegisterSecCompEnhance(data));
    EXPECT_EQ(RET_SUCCESS, SecCompEnhanceAgent::GetInstance().GetSecCompEnhance(getpid(), data1));
    EXPECT_EQ(2, data1.count);

    SecCompEnhanceAgent::GetInstance().RemoveSecCompEnhance(data1.pid, data1.token);
    EXPECT_EQ(RET_SUCCESS, SecCompEnhanceAgent::GetInstance().GetSecCompEnhance(getpid(), data1));
    EXPECT_EQ(1, data1.count);

    SecCompEnhanceAgent::GetInstance().RemoveSecCompEnhance(data1.pid, data1.token);
    EXPECT_EQ(AccessTokenError::ERR_PARAM_INVALID,
        SecCompEnhanceAgent::GetInstance().GetSecCompEnhance(getpid(), data1));
}
} // namespace AccessToken
} // namespace Security
} // namespace OHOS
