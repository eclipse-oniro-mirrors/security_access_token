/*
 * Copyright (c) 2024 Huawei Device Co., Ltd.
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

#include <gtest/gtest.h>
#include <vector>

#ifdef SECURITY_COMPONENT_ENHANCE_ENABLE
#include "privacy_sec_comp_enhance_agent.h"
#include "privacy_error.h"
#endif

using namespace testing::ext;

namespace OHOS {
namespace Security {
namespace AccessToken {

class PrivacySecCompEnhanceAgentTest : public testing::Test {
public:
    static void SetUpTestCase();

    static void TearDownTestCase();

    void SetUp();

    void TearDown();
};

void PrivacySecCompEnhanceAgentTest::SetUpTestCase()
{
}

void PrivacySecCompEnhanceAgentTest::TearDownTestCase()
{
}

void PrivacySecCompEnhanceAgentTest::SetUp()
{
}

void PrivacySecCompEnhanceAgentTest::TearDown()
{
}

/**
 * @tc.name: PrivacySecCompEnhanceAgentTest001
 * @tc.desc: test PrivacySecCompEnhanceAgent: recover in diff situation (notExistPid / in recover)
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(PrivacySecCompEnhanceAgentTest, PrivacySecCompEnhanceAgentTest001, TestSize.Level1)
{
    PrivacySecCompAppManagerDeathCallback privacySecCallback;
    privacySecCallback.NotifyAppManagerDeath();
    PrivacySecCompEnhanceAgent::GetInstance().OnAppMgrRemoteDiedHandle();
    // recover
    std::vector<SecCompEnhanceData> enhanceList;
    PrivacySecCompEnhanceAgent::GetInstance().RecoverSecCompEnhance(enhanceList);

    int notExistPid = 0xffffffff; // not exist pid
    PrivacySecCompEnhanceAgent::GetInstance().RemoveSecCompEnhance(notExistPid);
    
    SecCompEnhanceData data = {
        .callback = nullptr,
        .pid = notExistPid,
    };
    EXPECT_EQ(PrivacyError::ERR_CALLBACK_REGIST_REDIRECT,
        PrivacySecCompEnhanceAgent::GetInstance().RegisterSecCompEnhance(data));

    // recover env
    PrivacySecCompEnhanceAgent::GetInstance().DepositSecCompEnhance(enhanceList);
    
    // add record for notExistPid
    EXPECT_EQ(RET_SUCCESS, PrivacySecCompEnhanceAgent::GetInstance().RegisterSecCompEnhance(data));
    EXPECT_EQ(PrivacyError::ERR_CALLBACK_ALREADY_EXIST,
        PrivacySecCompEnhanceAgent::GetInstance().RegisterSecCompEnhance(data));
    
    // recover env
    PrivacySecCompEnhanceAgent::GetInstance().DepositSecCompEnhance(enhanceList);
}
} // namespace AccessToken
} // namespace Security
} // namespace OHOS