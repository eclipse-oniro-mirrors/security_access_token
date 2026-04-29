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
#include <string>
#include <unistd.h>
#include <vector>

#include "access_token.h"
#include "access_token_error.h"
#include "accesstoken_kit.h"
#include "test_common.h"
#include "token_setproc.h"

using namespace testing::ext;

namespace OHOS {
namespace Security {
namespace AccessToken {
namespace {
static constexpr int32_t TEST_USER_ID = 0;
static constexpr const char* KERNEL_PERMISSION_SUPPORT_PLUGIN = "ohos.permission.kernel.SUPPORT_PLUGIN";
static constexpr const char* KERNEL_PERMISSION_DISABLE_CODE_MEMORY_PROTECTION =
    "ohos.permission.kernel.DISABLE_CODE_MEMORY_PROTECTION";
static constexpr const char* NORMAL_PERMISSION_CAMERA = "ohos.permission.CAMERA";
static constexpr const char* SET_CLAW_PERMISSION = "ohos.permission.SET_CLAW_PERMISSION";
static constexpr const char* MANAGE_CLAW_CALLER_PROCESS = "foundation";
uint64_t g_selfTokenId = 0;
uint64_t g_rootCallerTokenId = 0;
uint64_t g_manageClawCallerTokenId = 0;

CliInfo BuildCliInfo()
{
    return {
        .cliName = "camera",
        .subCliName = "capture"
    };
}

CliAuthInfo BuildCliAuthInfo()
{
    CliAuthInfo authInfo;
    authInfo.cliInfo = BuildCliInfo();
    authInfo.permissionNames = {"ohos.permission.CAMERA"};
    authInfo.authorizationResults = {false};
    return authInfo;
}

SkillInfo BuildSkillInfo()
{
    return {
        .skillName = "cameraSkill",
        .bundleName = "com.ohos.claw.demo",
        .moduleName = "entry"
    };
}

SkillAuthInfo BuildSkillAuthInfo()
{
    SkillAuthInfo authInfo;
    authInfo.skillInfo = BuildSkillInfo();
    authInfo.permissionNames = {"ohos.permission.CAMERA"};
    authInfo.authorizationResults = {false};
    return authInfo;
}

bool HasKernelPermission(const std::vector<PermissionWithValue>& kernelPermList, const std::string& permissionName)
{
    for (const auto& item : kernelPermList) {
        if (item.permissionName == permissionName) {
            return true;
        }
    }
    return false;
}

int32_t GenerateCliTokenChallengeWithCaller(AccessTokenID hostTokenId, const std::vector<CliAuthInfo>& authInfoList,
    ClawTokenChallenge& challengeResult)
{
    MockHapToken generateCaller("GenerateCliTokenChallengeCaller", {SET_CLAW_PERMISSION}, true);
    return AccessTokenKit::GenerateCliTokenChallenge(hostTokenId, authInfoList, challengeResult);
}

int32_t GenerateSkillTokenChallengeWithCaller(AccessTokenID hostTokenId,
    const std::vector<SkillAuthInfo>& authInfoList, ClawTokenChallenge& challengeResult)
{
    MockHapToken generateCaller("GenerateSkillTokenChallengeCaller", {SET_CLAW_PERMISSION}, true);
    return AccessTokenKit::GenerateSkillTokenChallenge(hostTokenId, authInfoList, challengeResult);
}

void SwitchToManageClawCaller()
{
    EXPECT_EQ(0, SetSelfTokenID(g_manageClawCallerTokenId));
}

void SwitchToRootCaller()
{
    EXPECT_EQ(0, SetSelfTokenID(g_rootCallerTokenId));
}

int32_t InitCliClawTokenWithManageCaller(const CliInitInfo& info,
    AccessTokenIDEx& tokenIdEx, std::vector<PermissionWithValue>& kernelPermList)
{
    SwitchToRootCaller();
    return AccessTokenKit::InitCliToken(info, tokenIdEx, kernelPermList);
}

int32_t InitCliClawTokenWithManageCaller(AccessTokenID hostTokenId, const std::string& challenge,
    const CliInfo& cliInfo, AccessTokenIDEx& tokenIdEx, std::vector<PermissionWithValue>& kernelPermList)
{
    CliInitInfo initInfo = {
        .hostTokenId = hostTokenId,
        .challenge = challenge,
        .cliInfo = cliInfo,
    };
    return InitCliClawTokenWithManageCaller(initInfo, tokenIdEx, kernelPermList);
}

int32_t InitSkillClawTokenWithManageCaller(const SkillInitInfo& info, AccessTokenIDEx& tokenIdEx,
    std::vector<PermissionWithValue>& kernelPermList)
{
    SwitchToRootCaller();
    return AccessTokenKit::InitSkillToken(info, tokenIdEx, kernelPermList);
}

int32_t InitSkillClawTokenWithManageCaller(AccessTokenID hostTokenId, const std::string& challenge,
    const SkillInfo& skillInfo, AccessTokenIDEx& tokenIdEx, std::vector<PermissionWithValue>& kernelPermList)
{
    SkillInitInfo initInfo = {
        .hostTokenId = hostTokenId,
        .challenge = challenge,
        .skillInfo = skillInfo,
    };
    return InitSkillClawTokenWithManageCaller(initInfo, tokenIdEx, kernelPermList);
}

int32_t CreateCliClawToken(AccessTokenIDEx& tokenIdEx)
{
    MockHapToken ownerToken("CreateCliClawToken", {}, true);
    AccessTokenID hostTokenId = ownerToken.GetTokenID();
    if (hostTokenId == INVALID_TOKENID) {
        return RET_FAILED;
    }

    ClawTokenChallenge challengeResult;
    int32_t ret = GenerateCliTokenChallengeWithCaller(hostTokenId, {BuildCliAuthInfo()}, challengeResult);
    if (ret != RET_SUCCESS || challengeResult.challenges.empty()) {
        return ret;
    }

    std::vector<PermissionWithValue> kernelPermList;
    CliInitInfo initInfo = {
        .hostTokenId = hostTokenId,
        .challenge = challengeResult.challenges[0],
        .cliInfo = BuildCliInfo(),
    };
    return InitCliClawTokenWithManageCaller(initInfo, tokenIdEx, kernelPermList);
}

void DeleteClawTokenByCurrentPid()
{
    SwitchToManageClawCaller();
    (void)AccessTokenKit::DeleteToolTokenByPid(getpid());
}
}

class AccessTokenClawTokenTest : public testing::Test {
public:
    static void SetUpTestCase()
    {
        g_selfTokenId = GetSelfTokenID();
        TestCommon::SetTestEvironment(g_selfTokenId);
        g_rootCallerTokenId = TestCommon::GetShellTokenId();
        g_manageClawCallerTokenId = TestCommon::GetNativeTokenIdFromProcess(MANAGE_CLAW_CALLER_PROCESS);
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
 * @tc.name: InitCliToken_001
 * @tc.desc: InitCliToken creates CLI claw token through AccessTokenKit successfully.
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(AccessTokenClawTokenTest, InitCliToken001, TestSize.Level4)
{
    AccessTokenID hostTokenId = INVALID_TOKENID;
    ClawTokenChallenge challengeResult;
    {
        MockHapToken ownerToken("InitCliTokenKitTest", {}, true);
        hostTokenId = ownerToken.GetTokenID();
        ASSERT_NE(INVALID_TOKENID, hostTokenId);

        ASSERT_EQ(RET_SUCCESS,
            GenerateCliTokenChallengeWithCaller(hostTokenId, {BuildCliAuthInfo()}, challengeResult));
        ASSERT_EQ(1, static_cast<int32_t>(challengeResult.challenges.size()));
        ASSERT_FALSE(challengeResult.challenges[0].empty());

        AccessTokenIDEx tokenIdEx = {0};
        std::vector<PermissionWithValue> kernelPermList;
        CliInfo cliInfo = BuildCliInfo();
        ASSERT_EQ(RET_SUCCESS, InitCliClawTokenWithManageCaller(
            hostTokenId, challengeResult.challenges[0], cliInfo, tokenIdEx, kernelPermList));
        ASSERT_NE(INVALID_TOKENID, tokenIdEx.tokenIdExStruct.tokenID);
        ASSERT_TRUE(kernelPermList.empty());

        CliTokenInfo tokenInfo;
        SwitchToManageClawCaller();
        ASSERT_EQ(RET_SUCCESS, AccessTokenKit::GetCliTokenInfo(tokenIdEx.tokenIdExStruct.tokenID, tokenInfo));
        EXPECT_EQ(hostTokenId, tokenInfo.hostTokenId);
        EXPECT_EQ(TEST_USER_ID, tokenInfo.userId);
        EXPECT_EQ(cliInfo.cliName, tokenInfo.cliName);
        EXPECT_EQ(cliInfo.subCliName, tokenInfo.subCliName);

        SwitchToManageClawCaller();
        ASSERT_EQ(RET_SUCCESS, AccessTokenKit::DeleteToolTokenByPid(getpid()));
        SwitchToManageClawCaller();
        EXPECT_EQ(AccessTokenError::ERR_TOKENID_NOT_EXIST,
            AccessTokenKit::GetCliTokenInfo(tokenIdEx.tokenIdExStruct.tokenID, tokenInfo));
    }
}

/**
 * @tc.name: InitCliToken_002
 * @tc.desc: InitCliToken returns token-not-exist when challenge is not generated.
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(AccessTokenClawTokenTest, InitCliToken002, TestSize.Level4)
{
    MockHapToken ownerToken("InitCliTokenKitTest002", {}, true);
    AccessTokenID hostTokenId = ownerToken.GetTokenID();
    ASSERT_NE(INVALID_TOKENID, hostTokenId);

    AccessTokenIDEx tokenIdEx = {0};
    std::vector<PermissionWithValue> kernelPermList;
    EXPECT_EQ(AccessTokenError::ERR_TOKENID_NOT_EXIST, InitCliClawTokenWithManageCaller(
        hostTokenId, "not_exist_cli_challenge", BuildCliInfo(), tokenIdEx, kernelPermList));
    EXPECT_EQ(INVALID_TOKENID, tokenIdEx.tokenIdExStruct.tokenID);
    EXPECT_TRUE(kernelPermList.empty());
}

/**
 * @tc.name: InitCliToken_003
 * @tc.desc: InitCliToken returns invalid-param when cli info mismatches cached message.
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(AccessTokenClawTokenTest, InitCliToken003, TestSize.Level4)
{
    MockHapToken ownerToken("InitCliTokenKitTest003", {}, true);
    AccessTokenID hostTokenId = ownerToken.GetTokenID();
    ASSERT_NE(INVALID_TOKENID, hostTokenId);

    ClawTokenChallenge challengeResult;
    ASSERT_EQ(RET_SUCCESS,
        GenerateCliTokenChallengeWithCaller(hostTokenId, {BuildCliAuthInfo()}, challengeResult));
    ASSERT_FALSE(challengeResult.challenges.empty());

    CliInfo mismatchInfo = BuildCliInfo();
    mismatchInfo.cliName = "mismatchCamera";
    AccessTokenIDEx tokenIdEx = {0};
    std::vector<PermissionWithValue> kernelPermList;
    int32_t ret = InitCliClawTokenWithManageCaller(
        hostTokenId, challengeResult.challenges[0], mismatchInfo, tokenIdEx, kernelPermList);
    EXPECT_EQ(AccessTokenError::ERR_PARAM_INVALID, ret);
    if (ret == RET_SUCCESS) {
        DeleteClawTokenByCurrentPid();
    } else {
        AccessTokenIDEx cleanupTokenIdEx = {0};
        std::vector<PermissionWithValue> cleanupKernelPermList;
        if (InitCliClawTokenWithManageCaller(hostTokenId, challengeResult.challenges[0], BuildCliInfo(),
            cleanupTokenIdEx, cleanupKernelPermList) == RET_SUCCESS) {
            DeleteClawTokenByCurrentPid();
        }
    }
}

/**
 * @tc.name: InitCliToken_004
 * @tc.desc: InitCliToken returns permission-denied when caller has no claw-token permission.
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(AccessTokenClawTokenTest, InitCliToken004, TestSize.Level4)
{
    MockHapToken ownerToken("InitCliTokenKitTest004Owner", {}, true);
    AccessTokenID hostTokenId = ownerToken.GetTokenID();
    ASSERT_NE(INVALID_TOKENID, hostTokenId);

    ClawTokenChallenge challengeResult;
    ASSERT_EQ(RET_SUCCESS,
        GenerateCliTokenChallengeWithCaller(hostTokenId, {BuildCliAuthInfo()}, challengeResult));
    ASSERT_FALSE(challengeResult.challenges.empty());

    AccessTokenIDEx tokenIdEx = {0};
    std::vector<PermissionWithValue> kernelPermList;
    int32_t ret = RET_FAILED;
    {
        MockHapToken noPermissionCaller("InitCliTokenKitTest004Caller", {}, false);
        CliInitInfo initInfo = {
            .hostTokenId = hostTokenId,
            .challenge = challengeResult.challenges[0],
            .cliInfo = BuildCliInfo(),
        };
        ret = AccessTokenKit::InitCliToken(initInfo, tokenIdEx, kernelPermList);
    }
    EXPECT_EQ(AccessTokenError::ERR_PERMISSION_DENIED, ret);
    if (ret == RET_SUCCESS) {
        DeleteClawTokenByCurrentPid();
        return;
    }
    EXPECT_EQ(INVALID_TOKENID, tokenIdEx.tokenIdExStruct.tokenID);

    ASSERT_EQ(RET_SUCCESS, InitCliClawTokenWithManageCaller(
        hostTokenId, challengeResult.challenges[0], BuildCliInfo(), tokenIdEx, kernelPermList));
    DeleteClawTokenByCurrentPid();
}

/**
 * @tc.name: InitCliToken_005
 * @tc.desc: InitCliToken returns all granted kernel permissions in success case.
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(AccessTokenClawTokenTest, InitCliToken005, TestSize.Level4)
{
    MockHapToken ownerToken("InitCliTokenKitTest005Owner", {}, true);
    AccessTokenID hostTokenId = ownerToken.GetTokenID();
    ASSERT_NE(INVALID_TOKENID, hostTokenId);

    CliAuthInfo authInfo;
    authInfo.cliInfo = BuildCliInfo();
    authInfo.permissionNames = {
        KERNEL_PERMISSION_SUPPORT_PLUGIN,
        KERNEL_PERMISSION_DISABLE_CODE_MEMORY_PROTECTION,
        NORMAL_PERMISSION_CAMERA
    };
    authInfo.permissionStatus = {true, true, true};

    ClawTokenChallenge challengeResult;
    ASSERT_EQ(RET_SUCCESS, GenerateCliTokenChallengeWithCaller(hostTokenId, {authInfo}, challengeResult));
    ASSERT_EQ(1, static_cast<int32_t>(challengeResult.challenges.size()));
    ASSERT_FALSE(challengeResult.challenges[0].empty());

    AccessTokenIDEx tokenIdEx = {0};
    std::vector<PermissionWithValue> kernelPermList;
    ASSERT_EQ(RET_SUCCESS, InitCliClawTokenWithManageCaller(
        hostTokenId, challengeResult.challenges[0], BuildCliInfo(), tokenIdEx, kernelPermList));
    ASSERT_EQ(2, static_cast<int32_t>(kernelPermList.size()));
    EXPECT_TRUE(HasKernelPermission(kernelPermList, KERNEL_PERMISSION_SUPPORT_PLUGIN));
    EXPECT_TRUE(HasKernelPermission(kernelPermList, KERNEL_PERMISSION_DISABLE_CODE_MEMORY_PROTECTION));
    EXPECT_FALSE(HasKernelPermission(kernelPermList, NORMAL_PERMISSION_CAMERA));

    DeleteClawTokenByCurrentPid();
}

/**
 * @tc.name: InitCliToken_006
 * @tc.desc: InitCliToken filters out kernel permissions that are not granted.
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(AccessTokenClawTokenTest, InitCliToken006, TestSize.Level4)
{
    MockHapToken ownerToken("InitCliTokenKitTest006Owner", {}, true);
    AccessTokenID hostTokenId = ownerToken.GetTokenID();
    ASSERT_NE(INVALID_TOKENID, hostTokenId);

    CliAuthInfo authInfo;
    authInfo.cliInfo = BuildCliInfo();
    authInfo.permissionNames = {
        KERNEL_PERMISSION_SUPPORT_PLUGIN,
        KERNEL_PERMISSION_DISABLE_CODE_MEMORY_PROTECTION,
        NORMAL_PERMISSION_CAMERA
    };
    authInfo.permissionStatus = {true, false, true};

    ClawTokenChallenge challengeResult;
    ASSERT_EQ(RET_SUCCESS, GenerateCliTokenChallengeWithCaller(hostTokenId, {authInfo}, challengeResult));
    ASSERT_EQ(1, static_cast<int32_t>(challengeResult.challenges.size()));
    ASSERT_FALSE(challengeResult.challenges[0].empty());

    AccessTokenIDEx tokenIdEx = {0};
    std::vector<PermissionWithValue> kernelPermList;
    ASSERT_EQ(RET_SUCCESS, InitCliClawTokenWithManageCaller(
        hostTokenId, challengeResult.challenges[0], BuildCliInfo(), tokenIdEx, kernelPermList));
    ASSERT_EQ(1, static_cast<int32_t>(kernelPermList.size()));
    EXPECT_TRUE(HasKernelPermission(kernelPermList, KERNEL_PERMISSION_SUPPORT_PLUGIN));
    EXPECT_FALSE(HasKernelPermission(kernelPermList, KERNEL_PERMISSION_DISABLE_CODE_MEMORY_PROTECTION));
    EXPECT_FALSE(HasKernelPermission(kernelPermList, NORMAL_PERMISSION_CAMERA));

    DeleteClawTokenByCurrentPid();
}

/**
 * @tc.name: InitCliToken_007
 * @tc.desc: InitCliToken allows empty subCliName in success case.
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(AccessTokenClawTokenTest, InitCliToken007, TestSize.Level4)
{
    MockHapToken ownerToken("InitCliTokenKitTest007Owner", {}, true);
    AccessTokenID hostTokenId = ownerToken.GetTokenID();
    ASSERT_NE(INVALID_TOKENID, hostTokenId);

    CliAuthInfo authInfo = BuildCliAuthInfo();
    authInfo.cliInfo.subCliName = "";

    ClawTokenChallenge challengeResult;
    ASSERT_EQ(RET_SUCCESS, GenerateCliTokenChallengeWithCaller(hostTokenId, {authInfo}, challengeResult));
    ASSERT_EQ(1, static_cast<int32_t>(challengeResult.challenges.size()));
    ASSERT_FALSE(challengeResult.challenges[0].empty());

    CliInfo cliInfo = BuildCliInfo();
    cliInfo.subCliName = "";
    AccessTokenIDEx tokenIdEx = {0};
    std::vector<PermissionWithValue> kernelPermList;
    ASSERT_EQ(RET_SUCCESS, InitCliClawTokenWithManageCaller(
        hostTokenId, challengeResult.challenges[0], cliInfo, tokenIdEx, kernelPermList));
    ASSERT_NE(INVALID_TOKENID, tokenIdEx.tokenIdExStruct.tokenID);

    CliTokenInfo tokenInfo;
    SwitchToManageClawCaller();
    ASSERT_EQ(RET_SUCCESS, AccessTokenKit::GetCliTokenInfo(tokenIdEx.tokenIdExStruct.tokenID, tokenInfo));
    EXPECT_EQ(cliInfo.cliName, tokenInfo.cliName);
    EXPECT_TRUE(tokenInfo.subCliName.empty());

    DeleteClawTokenByCurrentPid();
}

/**
 * @tc.name: InitSkillToken_001
 * @tc.desc: InitSkillToken creates skill claw token through AccessTokenKit successfully.
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(AccessTokenClawTokenTest, InitSkillToken001, TestSize.Level4)
{
    MockHapToken ownerToken("InitSkillTokenKitTest001", {}, true);
    AccessTokenID hostTokenId = ownerToken.GetTokenID();
    ASSERT_NE(INVALID_TOKENID, hostTokenId);

    ClawTokenChallenge challengeResult;
    ASSERT_EQ(RET_SUCCESS,
        GenerateSkillTokenChallengeWithCaller(hostTokenId, {BuildSkillAuthInfo()}, challengeResult));
    ASSERT_EQ(1, static_cast<int32_t>(challengeResult.challenges.size()));
    ASSERT_FALSE(challengeResult.challenges[0].empty());

    AccessTokenIDEx tokenIdEx = {0};
    std::vector<PermissionWithValue> kernelPermList;
    SkillInfo skillInfo = BuildSkillInfo();
    ASSERT_EQ(RET_SUCCESS, InitSkillClawTokenWithManageCaller(
        hostTokenId, challengeResult.challenges[0], skillInfo, tokenIdEx, kernelPermList));
    ASSERT_NE(INVALID_TOKENID, tokenIdEx.tokenIdExStruct.tokenID);
    ASSERT_TRUE(kernelPermList.empty());

    SkillTokenInfo tokenInfo;
    SwitchToManageClawCaller();
    ASSERT_EQ(RET_SUCCESS, AccessTokenKit::GetSkillTokenInfo(tokenIdEx.tokenIdExStruct.tokenID, tokenInfo));
    EXPECT_EQ(hostTokenId, tokenInfo.hostTokenId);
    EXPECT_EQ(TEST_USER_ID, tokenInfo.userId);
    EXPECT_EQ(skillInfo.skillName, tokenInfo.skillName);
    EXPECT_EQ(skillInfo.bundleName, tokenInfo.bundleName);
    EXPECT_EQ(skillInfo.moduleName, tokenInfo.moduleName);

    DeleteClawTokenByCurrentPid();
}

/**
 * @tc.name: InitSkillToken_002
 * @tc.desc: InitSkillToken returns token-not-exist when challenge is not generated.
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(AccessTokenClawTokenTest, InitSkillToken002, TestSize.Level4)
{
    MockHapToken ownerToken("InitSkillTokenKitTest002", {}, true);
    AccessTokenID hostTokenId = ownerToken.GetTokenID();
    ASSERT_NE(INVALID_TOKENID, hostTokenId);

    AccessTokenIDEx tokenIdEx = {0};
    std::vector<PermissionWithValue> kernelPermList;
    EXPECT_EQ(AccessTokenError::ERR_TOKENID_NOT_EXIST, InitSkillClawTokenWithManageCaller(
        hostTokenId, "not_exist_skill_challenge", BuildSkillInfo(), tokenIdEx, kernelPermList));
    EXPECT_EQ(INVALID_TOKENID, tokenIdEx.tokenIdExStruct.tokenID);
    EXPECT_TRUE(kernelPermList.empty());
}

/**
 * @tc.name: InitSkillToken_003
 * @tc.desc: InitSkillToken returns invalid-param when skill info mismatches cached message.
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(AccessTokenClawTokenTest, InitSkillToken003, TestSize.Level4)
{
    MockHapToken ownerToken("InitSkillTokenKitTest003", {}, true);
    AccessTokenID hostTokenId = ownerToken.GetTokenID();
    ASSERT_NE(INVALID_TOKENID, hostTokenId);

    ClawTokenChallenge challengeResult;
    ASSERT_EQ(RET_SUCCESS,
        GenerateSkillTokenChallengeWithCaller(hostTokenId, {BuildSkillAuthInfo()}, challengeResult));
    ASSERT_FALSE(challengeResult.challenges.empty());

    SkillInfo mismatchInfo = BuildSkillInfo();
    mismatchInfo.skillName = "mismatchSkill";
    AccessTokenIDEx tokenIdEx = {0};
    std::vector<PermissionWithValue> kernelPermList;
    int32_t ret = InitSkillClawTokenWithManageCaller(
        hostTokenId, challengeResult.challenges[0], mismatchInfo, tokenIdEx, kernelPermList);
    EXPECT_EQ(AccessTokenError::ERR_PARAM_INVALID, ret);
    if (ret == RET_SUCCESS) {
        DeleteClawTokenByCurrentPid();
    } else {
        AccessTokenIDEx cleanupTokenIdEx = {0};
        std::vector<PermissionWithValue> cleanupKernelPermList;
        if (InitSkillClawTokenWithManageCaller(hostTokenId, challengeResult.challenges[0], BuildSkillInfo(),
            cleanupTokenIdEx, cleanupKernelPermList) == RET_SUCCESS) {
            DeleteClawTokenByCurrentPid();
        }
    }
}

/**
 * @tc.name: InitSkillToken_004
 * @tc.desc: InitSkillToken returns permission-denied when caller has no claw-token permission.
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(AccessTokenClawTokenTest, InitSkillToken004, TestSize.Level4)
{
    MockHapToken ownerToken("InitSkillTokenKitTest004Owner", {}, true);
    AccessTokenID hostTokenId = ownerToken.GetTokenID();
    ASSERT_NE(INVALID_TOKENID, hostTokenId);

    ClawTokenChallenge challengeResult;
    ASSERT_EQ(RET_SUCCESS,
        GenerateSkillTokenChallengeWithCaller(hostTokenId, {BuildSkillAuthInfo()}, challengeResult));
    ASSERT_FALSE(challengeResult.challenges.empty());

    AccessTokenIDEx tokenIdEx = {0};
    std::vector<PermissionWithValue> kernelPermList;
    int32_t ret = RET_FAILED;
    {
        MockHapToken noPermissionCaller("InitSkillTokenKitTest004Caller", {}, false);
        SkillInitInfo initInfo = {
            .hostTokenId = hostTokenId,
            .challenge = challengeResult.challenges[0],
            .skillInfo = BuildSkillInfo(),
        };
        ret = AccessTokenKit::InitSkillToken(initInfo, tokenIdEx, kernelPermList);
    }
    EXPECT_EQ(AccessTokenError::ERR_PERMISSION_DENIED, ret);
    if (ret == RET_SUCCESS) {
        DeleteClawTokenByCurrentPid();
        return;
    }
    EXPECT_EQ(INVALID_TOKENID, tokenIdEx.tokenIdExStruct.tokenID);

    ASSERT_EQ(RET_SUCCESS, InitSkillClawTokenWithManageCaller(
        hostTokenId, challengeResult.challenges[0], BuildSkillInfo(), tokenIdEx, kernelPermList));
    DeleteClawTokenByCurrentPid();
}

/**
 * @tc.name: InitSkillToken_005
 * @tc.desc: InitSkillToken returns all granted kernel permissions in success case.
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(AccessTokenClawTokenTest, InitSkillToken005, TestSize.Level4)
{
    MockHapToken ownerToken("InitSkillTokenKitTest005Owner", {}, true);
    AccessTokenID hostTokenId = ownerToken.GetTokenID();
    ASSERT_NE(INVALID_TOKENID, hostTokenId);

    SkillAuthInfo authInfo;
    authInfo.skillInfo = BuildSkillInfo();
    authInfo.permissionNames = {
        KERNEL_PERMISSION_SUPPORT_PLUGIN,
        KERNEL_PERMISSION_DISABLE_CODE_MEMORY_PROTECTION,
        NORMAL_PERMISSION_CAMERA
    };
    authInfo.permissionStatus = {true, true, true};

    ClawTokenChallenge challengeResult;
    ASSERT_EQ(RET_SUCCESS, GenerateSkillTokenChallengeWithCaller(hostTokenId, {authInfo}, challengeResult));
    ASSERT_EQ(1, static_cast<int32_t>(challengeResult.challenges.size()));
    ASSERT_FALSE(challengeResult.challenges[0].empty());

    AccessTokenIDEx tokenIdEx = {0};
    std::vector<PermissionWithValue> kernelPermList;
    ASSERT_EQ(RET_SUCCESS, InitSkillClawTokenWithManageCaller(
        hostTokenId, challengeResult.challenges[0], BuildSkillInfo(), tokenIdEx, kernelPermList));
    ASSERT_EQ(2, static_cast<int32_t>(kernelPermList.size()));
    EXPECT_TRUE(HasKernelPermission(kernelPermList, KERNEL_PERMISSION_SUPPORT_PLUGIN));
    EXPECT_TRUE(HasKernelPermission(kernelPermList, KERNEL_PERMISSION_DISABLE_CODE_MEMORY_PROTECTION));
    EXPECT_FALSE(HasKernelPermission(kernelPermList, NORMAL_PERMISSION_CAMERA));

    DeleteClawTokenByCurrentPid();
}

/**
 * @tc.name: InitSkillToken_006
 * @tc.desc: InitSkillToken filters out kernel permissions that are not granted.
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(AccessTokenClawTokenTest, InitSkillToken006, TestSize.Level4)
{
    MockHapToken ownerToken("InitSkillTokenKitTest006Owner", {}, true);
    AccessTokenID hostTokenId = ownerToken.GetTokenID();
    ASSERT_NE(INVALID_TOKENID, hostTokenId);

    SkillAuthInfo authInfo;
    authInfo.skillInfo = BuildSkillInfo();
    authInfo.permissionNames = {
        KERNEL_PERMISSION_SUPPORT_PLUGIN,
        KERNEL_PERMISSION_DISABLE_CODE_MEMORY_PROTECTION,
        NORMAL_PERMISSION_CAMERA
    };
    authInfo.permissionStatus = {true, false, true};

    ClawTokenChallenge challengeResult;
    ASSERT_EQ(RET_SUCCESS, GenerateSkillTokenChallengeWithCaller(hostTokenId, {authInfo}, challengeResult));
    ASSERT_EQ(1, static_cast<int32_t>(challengeResult.challenges.size()));
    ASSERT_FALSE(challengeResult.challenges[0].empty());

    AccessTokenIDEx tokenIdEx = {0};
    std::vector<PermissionWithValue> kernelPermList;
    ASSERT_EQ(RET_SUCCESS, InitSkillClawTokenWithManageCaller(
        hostTokenId, challengeResult.challenges[0], BuildSkillInfo(), tokenIdEx, kernelPermList));
    ASSERT_EQ(1, static_cast<int32_t>(kernelPermList.size()));
    EXPECT_TRUE(HasKernelPermission(kernelPermList, KERNEL_PERMISSION_SUPPORT_PLUGIN));
    EXPECT_FALSE(HasKernelPermission(kernelPermList, KERNEL_PERMISSION_DISABLE_CODE_MEMORY_PROTECTION));
    EXPECT_FALSE(HasKernelPermission(kernelPermList, NORMAL_PERMISSION_CAMERA));

    DeleteClawTokenByCurrentPid();
}

/**
 * @tc.name: DeleteClawToken_001
 * @tc.desc: DeleteToolTokenByPid returns invalid-param when pid is -1.
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(AccessTokenClawTokenTest, DeleteClawToken001, TestSize.Level4)
{
    SwitchToManageClawCaller();
    EXPECT_EQ(AccessTokenError::ERR_PARAM_INVALID, AccessTokenKit::DeleteToolTokenByPid(-1));
}

/**
 * @tc.name: DeleteClawToken_002
 * @tc.desc: DeleteToolTokenByPid deletes current pid claw token successfully.
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(AccessTokenClawTokenTest, DeleteClawToken002, TestSize.Level4)
{
    AccessTokenIDEx tokenIdEx = {0};
    ASSERT_EQ(RET_SUCCESS, CreateCliClawToken(tokenIdEx));
    SwitchToManageClawCaller();
    ASSERT_EQ(RET_SUCCESS, AccessTokenKit::DeleteToolTokenByPid(getpid()));

    CliTokenInfo tokenInfo;
    SwitchToManageClawCaller();
    EXPECT_EQ(AccessTokenError::ERR_TOKENID_NOT_EXIST,
        AccessTokenKit::GetCliTokenInfo(tokenIdEx.tokenIdExStruct.tokenID, tokenInfo));
}

/**
 * @tc.name: DeleteClawToken_003
 * @tc.desc: DeleteToolTokenByPid returns token-not-exist when deleting same pid repeatedly.
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(AccessTokenClawTokenTest, DeleteClawToken003, TestSize.Level4)
{
    AccessTokenIDEx tokenIdEx = {0};
    ASSERT_EQ(RET_SUCCESS, CreateCliClawToken(tokenIdEx));
    SwitchToManageClawCaller();
    ASSERT_EQ(RET_SUCCESS, AccessTokenKit::DeleteToolTokenByPid(getpid()));
    SwitchToManageClawCaller();
    EXPECT_EQ(AccessTokenError::ERR_TOKENID_NOT_EXIST, AccessTokenKit::DeleteToolTokenByPid(getpid()));
}

/**
 * @tc.name: DeleteClawToken_004
 * @tc.desc: DeleteToolTokenByPid returns permission-denied and keeps token when caller has no claw-token permission.
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(AccessTokenClawTokenTest, DeleteClawToken004, TestSize.Level4)
{
    AccessTokenIDEx tokenIdEx = {0};
    ASSERT_EQ(RET_SUCCESS, CreateCliClawToken(tokenIdEx));
    {
        MockHapToken noPermissionCaller("DeleteClawTokenKitTest004Caller", {}, false);
        EXPECT_EQ(AccessTokenError::ERR_PERMISSION_DENIED, AccessTokenKit::DeleteToolTokenByPid(getpid()));
    }

    SwitchToManageClawCaller();
    CliTokenInfo tokenInfo;
    ASSERT_EQ(RET_SUCCESS, AccessTokenKit::GetCliTokenInfo(tokenIdEx.tokenIdExStruct.tokenID, tokenInfo));
    SwitchToManageClawCaller();
    ASSERT_EQ(RET_SUCCESS, AccessTokenKit::DeleteToolTokenByPid(getpid()));
}

/**
 * @tc.name: DeleteClawToken_005
 * @tc.desc: DeleteToolTokenByPid allows privileged caller to delete token by arbitrary pid.
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(AccessTokenClawTokenTest, DeleteClawToken005, TestSize.Level4)
{
    AccessTokenIDEx tokenIdEx = {0};
    ASSERT_EQ(RET_SUCCESS, CreateCliClawToken(tokenIdEx));

    SwitchToManageClawCaller();
    ASSERT_EQ(RET_SUCCESS, AccessTokenKit::DeleteToolTokenByPid(getpid()));

    CliTokenInfo tokenInfo;
    SwitchToManageClawCaller();
    EXPECT_EQ(AccessTokenError::ERR_TOKENID_NOT_EXIST,
        AccessTokenKit::GetCliTokenInfo(tokenIdEx.tokenIdExStruct.tokenID, tokenInfo));
}

/**
 * @tc.name: ClawToken_001
 * @tc.desc: Claw token generate-init-delete full flow succeeds.
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(AccessTokenClawTokenTest, ClawToken001, TestSize.Level4)
{
    MockHapToken ownerToken("ClawTokenKitTest001", {}, true);
    AccessTokenID hostTokenId = ownerToken.GetTokenID();
    ASSERT_NE(INVALID_TOKENID, hostTokenId);

    ClawTokenChallenge challengeResult;
    ASSERT_EQ(RET_SUCCESS,
        GenerateCliTokenChallengeWithCaller(hostTokenId, {BuildCliAuthInfo()}, challengeResult));
    ASSERT_FALSE(challengeResult.challenges.empty());

    AccessTokenIDEx tokenIdEx = {0};
    std::vector<PermissionWithValue> kernelPermList;
    ASSERT_EQ(RET_SUCCESS, InitCliClawTokenWithManageCaller(
        hostTokenId, challengeResult.challenges[0], BuildCliInfo(), tokenIdEx, kernelPermList));
    ASSERT_NE(INVALID_TOKENID, tokenIdEx.tokenIdExStruct.tokenID);
    SwitchToManageClawCaller();
    ASSERT_EQ(RET_SUCCESS, AccessTokenKit::DeleteToolTokenByPid(getpid()));
}

/**
 * @tc.name: ClawToken_002
 * @tc.desc: Reusing consumed challenge returns token-not-exist.
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(AccessTokenClawTokenTest, ClawToken002, TestSize.Level4)
{
    MockHapToken ownerToken("ClawTokenKitTest002", {}, true);
    AccessTokenID hostTokenId = ownerToken.GetTokenID();
    ASSERT_NE(INVALID_TOKENID, hostTokenId);

    ClawTokenChallenge challengeResult;
    ASSERT_EQ(RET_SUCCESS,
        GenerateCliTokenChallengeWithCaller(hostTokenId, {BuildCliAuthInfo()}, challengeResult));
    ASSERT_FALSE(challengeResult.challenges.empty());

    AccessTokenIDEx tokenIdEx = {0};
    std::vector<PermissionWithValue> kernelPermList;
    ASSERT_EQ(RET_SUCCESS, InitCliClawTokenWithManageCaller(
        hostTokenId, challengeResult.challenges[0], BuildCliInfo(), tokenIdEx, kernelPermList));

    AccessTokenIDEx secondTokenIdEx = {0};
    std::vector<PermissionWithValue> secondKernelPermList;
    EXPECT_EQ(AccessTokenError::ERR_TOKENID_NOT_EXIST, InitCliClawTokenWithManageCaller(
        hostTokenId, challengeResult.challenges[0], BuildCliInfo(), secondTokenIdEx, secondKernelPermList));
    DeleteClawTokenByCurrentPid();
}

/**
 * @tc.name: ClawToken_003
 * @tc.desc: Multiple challenges generated in one request can be consumed one by one.
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(AccessTokenClawTokenTest, ClawToken003, TestSize.Level4)
{
    MockHapToken ownerToken("ClawTokenKitTest003", {}, true);
    AccessTokenID hostTokenId = ownerToken.GetTokenID();
    ASSERT_NE(INVALID_TOKENID, hostTokenId);

    CliAuthInfo firstAuthInfo = BuildCliAuthInfo();
    CliAuthInfo secondAuthInfo = BuildCliAuthInfo();
    secondAuthInfo.cliInfo.subCliName = "record";
    ClawTokenChallenge challengeResult;
    ASSERT_EQ(RET_SUCCESS,
        GenerateCliTokenChallengeWithCaller(hostTokenId, {firstAuthInfo, secondAuthInfo}, challengeResult));
    EXPECT_GT(challengeResult.challenges.size(), 1U);

    for (size_t i = 0; i < challengeResult.challenges.size(); ++i) {
        CliInfo cliInfo = (i == 0) ? firstAuthInfo.cliInfo : secondAuthInfo.cliInfo;
        AccessTokenIDEx tokenIdEx = {0};
        std::vector<PermissionWithValue> kernelPermList;
        ASSERT_EQ(RET_SUCCESS, InitCliClawTokenWithManageCaller(
            hostTokenId, challengeResult.challenges[i], cliInfo, tokenIdEx, kernelPermList));
        ASSERT_NE(INVALID_TOKENID, tokenIdEx.tokenIdExStruct.tokenID);
        DeleteClawTokenByCurrentPid();
    }
}
} // namespace AccessToken
} // namespace Security
} // namespace OHOS
