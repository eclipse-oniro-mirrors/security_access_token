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

#include <gtest/gtest.h>
#include <unistd.h>

#include "access_token.h"
#include "access_token_error.h"
#include "accesstoken_kit.h"
#include "claw_permission_info.h"
#include "test_common.h"
#include "token_setproc.h"

using namespace testing::ext;

namespace OHOS {
namespace Security {
namespace AccessToken {
namespace {
static constexpr const char* MANAGE_TOOL_CALLER_PROCESS = "foundation";
uint64_t g_selfTokenId = 0;
uint64_t g_rootCallerTokenId = 0;
uint64_t g_manageToolCallerTokenId = 0;
uint64_t g_shellToken = 0;
static const int32_t AIMGR_UID = 3092;

CliInfo BuildCliInfo()
{
    return {
        .cliName = "camera",
        .subCliName = "capture"
    };
}

SkillInfo BuildSkillInfo()
{
    return {
        .skillName = "cameraSkill",
        .bundleName = "com.ohos.tool.demo",
        .moduleName = "entry"
    };
}

void SwitchToRootCaller()
{
    EXPECT_EQ(0, SetSelfTokenID(g_rootCallerTokenId));
}

void SwitchToManageToolCaller()
{
    EXPECT_EQ(0, SetSelfTokenID(g_manageToolCallerTokenId));
}

int32_t InitCliToolTokenWithEmptyChallenge(AccessTokenID hostTokenId, const CliInfo& cliInfo,
    AccessTokenIDEx& tokenIdEx, std::vector<PermissionWithValue>& kernelPermList)
{
    AccessTokenID callerTokenId = GetSelfTokenID();
    uint32_t callerUid = getuid();
    SwitchToRootCaller();
    EXPECT_EQ(0, setuid(AIMGR_UID));
    CliInitInfo initInfo = {
        .hostTokenId = hostTokenId,
        .challenge = "",
        .cliInfo = cliInfo,
    };
    int32_t ret = AccessTokenKit::InitCliToken(initInfo, tokenIdEx, kernelPermList);
    EXPECT_EQ(0, setuid(callerUid));
    EXPECT_EQ(0, SetSelfTokenID(callerTokenId));
    return ret;
}

int32_t InitSkillToolTokenWithEmptyChallenge(AccessTokenID hostTokenId, const SkillInfo& skillInfo,
    AccessTokenIDEx& tokenIdEx, std::vector<PermissionWithValue>& kernelPermList)
{
    AccessTokenID callerTokenId = GetSelfTokenID();
    uint32_t callerUid = getuid();
    SwitchToRootCaller();
    EXPECT_EQ(0, setuid(AIMGR_UID));
    SkillInitInfo initInfo = {
        .hostTokenId = hostTokenId,
        .challenge = "",
        .skillInfo = skillInfo,
    };
    int32_t ret = AccessTokenKit::InitSkillToken(initInfo, tokenIdEx, kernelPermList);
    EXPECT_EQ(0, setuid(callerUid));
    EXPECT_EQ(0, SetSelfTokenID(callerTokenId));
    return ret;
}

int32_t DeleteToolTokenByCurrentPid()
{
    uint64_t callerTokenId = GetSelfTokenID();
    EXPECT_EQ(0, SetSelfTokenID(g_shellToken));
    int32_t ret = AccessTokenKit::DeleteToolTokenByPid(getpid());
    EXPECT_EQ(0, SetSelfTokenID(callerTokenId));
    return ret;
}

class ToolTokenGuard final {
public:
    ToolTokenGuard() = default;
    ~ToolTokenGuard()
    {
        if (armed_) {
            (void)DeleteToolTokenByCurrentPid();
        }
    }

    void Arm()
    {
        armed_ = true;
    }

    void Disarm()
    {
        armed_ = false;
    }

private:
    bool armed_ = false;
};
}

class ToolTokenAccessTest : public testing::Test {
public:
    static void SetUpTestCase()
    {
        g_selfTokenId = GetSelfTokenID();
        TestCommon::SetTestEvironment(g_selfTokenId);
        g_rootCallerTokenId = TestCommon::GetShellTokenId();
        g_shellToken = g_selfTokenId;
        g_manageToolCallerTokenId = TestCommon::GetNativeTokenIdFromProcess(MANAGE_TOOL_CALLER_PROCESS);
    }

    static void TearDownTestCase()
    {
        SetSelfTokenID(g_selfTokenId);
        TestCommon::ResetTestEvironment();
    }

    void SetUp() override
    {
        g_selfTokenId = GetSelfTokenID();
    }

    void TearDown() override
    {
        EXPECT_EQ(0, SetSelfTokenID(g_selfTokenId));
    }
};

/**
 * @tc.name: GetHostTokenId001
 * @tc.desc: GetHostTokenId returns host token for cli tool token created with empty challenge.
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(ToolTokenAccessTest, GetHostTokenId001, TestSize.Level4)
{
    ToolTokenGuard guard;
    AccessTokenIDEx tokenIdEx = {0};
    std::vector<PermissionWithValue> kernelPermList;
    CliTokenInfo tokenInfo;
    AccessTokenID queriedHostTokenId = INVALID_TOKENID;
    CliInfo cliInfo = BuildCliInfo();
    {
        MockHapToken hostToken("GetHostTokenId001", {}, true);
        AccessTokenID hostTokenId = hostToken.GetTokenID();
        ASSERT_NE(INVALID_TOKENID, hostTokenId);

        ASSERT_EQ(RET_SUCCESS, InitCliToolTokenWithEmptyChallenge(hostTokenId, cliInfo, tokenIdEx, kernelPermList));
        ASSERT_NE(INVALID_TOKENID, tokenIdEx.tokenIdExStruct.tokenID);
        guard.Arm();

        SwitchToManageToolCaller();
        ASSERT_EQ(RET_SUCCESS, AccessTokenKit::GetHostTokenId(tokenIdEx.tokenIdExStruct.tokenID, queriedHostTokenId));
        EXPECT_EQ(hostTokenId, queriedHostTokenId);

        ASSERT_EQ(RET_SUCCESS, AccessTokenKit::GetCliTokenInfo(tokenIdEx.tokenIdExStruct.tokenID, tokenInfo));
        EXPECT_EQ(hostTokenId, tokenInfo.hostTokenId);
        EXPECT_EQ(cliInfo.cliName, tokenInfo.cliName);
        EXPECT_EQ(cliInfo.subCliName, tokenInfo.subCliName);
    }
}

/**
 * @tc.name: GetHostTokenId002
 * @tc.desc: GetHostTokenId returns host token for skill tool token created with empty challenge.
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(ToolTokenAccessTest, GetHostTokenId002, TestSize.Level4)
{
    ToolTokenGuard guard;
    AccessTokenIDEx tokenIdEx = {0};
    std::vector<PermissionWithValue> kernelPermList;
    SkillTokenInfo tokenInfo;
    AccessTokenID queriedHostTokenId = INVALID_TOKENID;
    SkillInfo skillInfo = BuildSkillInfo();
    {
        MockHapToken hostToken("GetHostTokenId002", {}, true);
        AccessTokenID hostTokenId = hostToken.GetTokenID();
        ASSERT_NE(INVALID_TOKENID, hostTokenId);

        ASSERT_EQ(RET_SUCCESS, InitSkillToolTokenWithEmptyChallenge(hostTokenId, skillInfo, tokenIdEx, kernelPermList));
        ASSERT_NE(INVALID_TOKENID, tokenIdEx.tokenIdExStruct.tokenID);
        guard.Arm();

        SwitchToManageToolCaller();
        ASSERT_EQ(RET_SUCCESS, AccessTokenKit::GetHostTokenId(tokenIdEx.tokenIdExStruct.tokenID, queriedHostTokenId));
        EXPECT_EQ(hostTokenId, queriedHostTokenId);

        ASSERT_EQ(RET_SUCCESS, AccessTokenKit::GetSkillTokenInfo(tokenIdEx.tokenIdExStruct.tokenID, tokenInfo));
        EXPECT_EQ(hostTokenId, tokenInfo.hostTokenId);
        EXPECT_EQ(skillInfo.skillName, tokenInfo.skillName);
        EXPECT_EQ(skillInfo.bundleName, tokenInfo.bundleName);
        EXPECT_EQ(skillInfo.moduleName, tokenInfo.moduleName);
    }
}

/**
 * @tc.name: GetHostTokenId003
 * @tc.desc: GetHostTokenId returns invalid-param when input token exists but is not tool token.
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(ToolTokenAccessTest, GetHostTokenId003, TestSize.Level4)
{
    AccessTokenID queriedHostTokenId = INVALID_TOKENID;
    MockHapToken hostToken("GetHostTokenId003", {}, true);
    AccessTokenID hostTokenId = hostToken.GetTokenID();
    ASSERT_NE(INVALID_TOKENID, hostTokenId);

    SwitchToManageToolCaller();
    EXPECT_EQ(AccessTokenError::ERR_PARAM_INVALID, AccessTokenKit::GetHostTokenId(hostTokenId, queriedHostTokenId));
    EXPECT_EQ(INVALID_TOKENID, queriedHostTokenId);
}

/**
 * @tc.name: GetHostTokenId004
 * @tc.desc: GetHostTokenId returns token-not-exist after tool token is deleted.
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(ToolTokenAccessTest, GetHostTokenId004, TestSize.Level4)
{
    ToolTokenGuard guard;
    AccessTokenIDEx tokenIdEx = {0};
    std::vector<PermissionWithValue> kernelPermList;
    AccessTokenID queriedHostTokenId = INVALID_TOKENID;
    {
        MockHapToken hostToken("GetHostTokenId004", {}, true);
        AccessTokenID hostTokenId = hostToken.GetTokenID();
        ASSERT_NE(INVALID_TOKENID, hostTokenId);

        ASSERT_EQ(RET_SUCCESS,
            InitCliToolTokenWithEmptyChallenge(hostTokenId, BuildCliInfo(), tokenIdEx, kernelPermList));
        ASSERT_NE(INVALID_TOKENID, tokenIdEx.tokenIdExStruct.tokenID);
        guard.Arm();
    }

    ASSERT_EQ(RET_SUCCESS, DeleteToolTokenByCurrentPid());
    guard.Disarm();
    SwitchToManageToolCaller();
    EXPECT_EQ(AccessTokenError::ERR_TOKENID_NOT_EXIST,
        AccessTokenKit::GetHostTokenId(tokenIdEx.tokenIdExStruct.tokenID, queriedHostTokenId));
    EXPECT_EQ(INVALID_TOKENID, queriedHostTokenId);
}

/**
 * @tc.name: GetHostTokenId005
 * @tc.desc: GetHostTokenId returns invalid-param for invalid token id.
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(ToolTokenAccessTest, GetHostTokenId005, TestSize.Level4)
{
    AccessTokenID queriedHostTokenId = INVALID_TOKENID;
    EXPECT_EQ(AccessTokenError::ERR_PARAM_INVALID, AccessTokenKit::GetHostTokenId(INVALID_TOKENID, queriedHostTokenId));
    EXPECT_EQ(INVALID_TOKENID, queriedHostTokenId);
}
} // namespace AccessToken
} // namespace Security
} // namespace OHOS
