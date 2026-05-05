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
static constexpr int32_t AIMGR_UID = 3092;
static const std::string DEFAULT_AGENT_ID = "1001";
static const std::string LOCATION_PERMISSION = "ohos.permission.LOCATION";
static constexpr const char* MANAGE_TOOL_CALLER_PROCESS = "aimgr";
uint64_t g_selfTokenId = 0;
uint64_t g_manageToolCallerTokenId = 0;
uint64_t g_shellTokenId = 0;

CliInfo BuildCliInfo()
{
    return {
        .cliName = "camera",
        .subCliName = "capture",
    };
}

std::vector<CliAuthInfo> BuildEmptyPermissionCliAuthInfos()
{
    return {CliAuthInfo {
        .cliInfo = BuildCliInfo(),
        .permissionNames = {},
        .authorizationResults = {},
    }};
}

class ScopedManageRuntimeCaller final {
public:
    explicit ScopedManageRuntimeCaller(const std::string& bundleName)
    {
        selfTokenId_ = GetSelfTokenID();
        HapInfoParams info;
        HapPolicyParams policy;
        TestCommon::GetHapParams(info, policy);
        info.bundleName = bundleName;
        info.appIDDesc = bundleName;
        info.isSystemApp = true;
        policy.permStateList = {BuildGrantedPermissionState()};
        tokenIdEx_ = TestCommon::AllocAndGrantHapTokenByTest(info, policy);
        EXPECT_NE(INVALID_TOKENID, tokenIdEx_.tokenIdExStruct.tokenID);
        EXPECT_EQ(0, SetSelfTokenID(tokenIdEx_.tokenIDEx));
    }

    ~ScopedManageRuntimeCaller()
    {
        EXPECT_EQ(0, SetSelfTokenID(selfTokenId_));
        if (tokenIdEx_.tokenIdExStruct.tokenID != INVALID_TOKENID) {
            EXPECT_EQ(RET_SUCCESS, TestCommon::DeleteTestHapToken(tokenIdEx_.tokenIdExStruct.tokenID));
        }
    }

private:
    static PermissionStateFull BuildGrantedPermissionState()
    {
        return {
            .permissionName = "ohos.permission.MANAGE_TOOL_RUNTIME_PERMISSIONS",
            .isGeneral = true,
            .resDeviceID = {"local"},
            .grantStatus = {PermissionState::PERMISSION_GRANTED},
            .grantFlags = {PermissionFlag::PERMISSION_USER_SET},
        };
    }

    uint64_t selfTokenId_ = 0;
    AccessTokenIDEx tokenIdEx_ = {0};
};

int32_t GenerateEmptyPermissionCliAuthResult(AccessTokenID hostTokenId, ToolAuthResult& authResult)
{
    ScopedManageRuntimeCaller caller("tool_token_auth_caller");
    return AccessTokenKit::GenerateCliAuthResult(
        hostTokenId, DEFAULT_AGENT_ID, BuildEmptyPermissionCliAuthInfos(), authResult);
}

int32_t InitCliToolTokenWithChallenge(AccessTokenID hostTokenId, const std::string& challenge,
    const CliInfo& cliInfo, AccessTokenIDEx& tokenIdEx, std::vector<PermissionWithValue>& kernelPermList)
{
    uint64_t callerTokenId = GetSelfTokenID();
    uint32_t callerUid = getuid();
    EXPECT_EQ(0, SetSelfTokenID(g_shellTokenId));
    EXPECT_EQ(0, setuid(AIMGR_UID));
    CliInitInfo initInfo = {
        .hostTokenId = hostTokenId,
        .challenge = challenge,
        .cliInfo = cliInfo,
    };
    int32_t ret = AccessTokenKit::InitCliToken(initInfo, tokenIdEx, kernelPermList);
    EXPECT_EQ(0, setuid(callerUid));
    EXPECT_EQ(0, SetSelfTokenID(callerTokenId));
    return ret;
}

int32_t InitCliToolTokenWithEmptyPermissionAuth(AccessTokenID hostTokenId, AccessTokenIDEx& tokenIdEx,
    std::vector<PermissionWithValue>& kernelPermList, std::string& challenge)
{
    ToolAuthResult authResult;
    int32_t ret = GenerateEmptyPermissionCliAuthResult(hostTokenId, authResult);
    if ((ret != RET_SUCCESS) || authResult.authResults.empty() || authResult.authResults[0].empty()) {
        return (ret == RET_SUCCESS) ? RET_FAILED : ret;
    }
    challenge = authResult.authResults[0];
    return InitCliToolTokenWithChallenge(hostTokenId, challenge, BuildCliInfo(), tokenIdEx, kernelPermList);
}

void SwitchToManageToolCaller()
{
    EXPECT_EQ(0, SetSelfTokenID(g_manageToolCallerTokenId));
}

int32_t DeleteToolTokenByCurrentPid()
{
    uint64_t callerTokenId = GetSelfTokenID();
    uint32_t callerUid = getuid();
    EXPECT_EQ(0, SetSelfTokenID(g_manageToolCallerTokenId));
    EXPECT_EQ(0, setuid(AIMGR_UID));
    int32_t ret = AccessTokenKit::DeleteToolTokenByPid(getpid());
    EXPECT_EQ(0, setuid(callerUid));
    EXPECT_EQ(0, SetSelfTokenID(callerTokenId));
    return ret;
}

void VerifyNoPermissionToken(AccessTokenID tokenId, const std::vector<PermissionWithValue>& kernelPermList)
{
    EXPECT_TRUE(kernelPermList.empty());
    EXPECT_EQ(PERMISSION_DENIED, AccessTokenKit::VerifyAccessToken(tokenId, LOCATION_PERMISSION));
}

class ToolTokenGuard final {
public:
    ToolTokenGuard() = default;
    ~ToolTokenGuard()
    {
        if (armed_) {
            EXPECT_EQ(RET_SUCCESS, DeleteToolTokenByCurrentPid());
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
} // namespace

class ToolTokenTest : public testing::Test {
public:
    static void SetUpTestCase()
    {
        g_selfTokenId = GetSelfTokenID();
        TestCommon::SetTestEvironment(g_selfTokenId);
        g_shellTokenId = g_selfTokenId;
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
 * @tc.name: InitCliToken001
 * @tc.desc: InitCliToken consumes non-empty challenge with empty permission list and creates no-permission token.
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(ToolTokenTest, InitCliToken001, TestSize.Level4)
{
    ToolTokenGuard guard;
    AccessTokenIDEx tokenIdEx = {0};
    std::vector<PermissionWithValue> kernelPermList;
    std::string challenge;
    MockHapToken hostToken("InitCliToken001", {}, true, 100);
    AccessTokenID hostTokenId = hostToken.GetTokenID();

    ASSERT_EQ(RET_SUCCESS, InitCliToolTokenWithEmptyPermissionAuth(
        hostTokenId, tokenIdEx, kernelPermList, challenge));
    ASSERT_FALSE(challenge.empty());
    ASSERT_NE(INVALID_TOKENID, tokenIdEx.tokenIdExStruct.tokenID);
    guard.Arm();
    VerifyNoPermissionToken(tokenIdEx.tokenIdExStruct.tokenID, kernelPermList);
}

/**
 * @tc.name: InitCliToken002
 * @tc.desc: GetCliTokenInfo and GetHostTokenId succeed for no-permission tool token.
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(ToolTokenTest, InitCliToken002, TestSize.Level4)
{
    ToolTokenGuard guard;
    AccessTokenIDEx tokenIdEx = {0};
    std::vector<PermissionWithValue> kernelPermList;
    std::string challenge;
    CliTokenInfo tokenInfo;
    AccessTokenID queriedHostTokenId = INVALID_TOKENID;
    MockHapToken hostToken("InitCliToken002", {}, true, 100);
    AccessTokenID hostTokenId = hostToken.GetTokenID();

    ASSERT_EQ(RET_SUCCESS, InitCliToolTokenWithEmptyPermissionAuth(
        hostTokenId, tokenIdEx, kernelPermList, challenge));
    guard.Arm();
    SwitchToManageToolCaller();
    ASSERT_EQ(RET_SUCCESS, AccessTokenKit::GetCliTokenInfo(tokenIdEx.tokenIdExStruct.tokenID, tokenInfo));
    EXPECT_EQ(hostTokenId, tokenInfo.hostTokenId);
    EXPECT_EQ(BuildCliInfo().cliName, tokenInfo.cliName);
    EXPECT_EQ(BuildCliInfo().subCliName, tokenInfo.subCliName);
    ASSERT_EQ(RET_SUCCESS, AccessTokenKit::GetHostTokenId(tokenIdEx.tokenIdExStruct.tokenID, queriedHostTokenId));
    EXPECT_EQ(hostTokenId, queriedHostTokenId);
}

/**
 * @tc.name: InitCliToken003
 * @tc.desc: InitCliToken returns already-exist when creating second CLI token in same pid.
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(ToolTokenTest, InitCliToken003, TestSize.Level4)
{
    ToolTokenGuard guard;
    AccessTokenIDEx firstTokenIdEx = {0};
    AccessTokenIDEx secondTokenIdEx = {0};
    std::vector<PermissionWithValue> kernelPermList;
    std::string firstChallenge;
    std::string secondChallenge;
    MockHapToken hostToken("InitCliToken003", {}, true, 100);
    AccessTokenID hostTokenId = hostToken.GetTokenID();

    ASSERT_EQ(RET_SUCCESS, InitCliToolTokenWithEmptyPermissionAuth(
        hostTokenId, firstTokenIdEx, kernelPermList, firstChallenge));
    guard.Arm();
    ToolAuthResult authResult;
    ASSERT_EQ(RET_SUCCESS, GenerateEmptyPermissionCliAuthResult(hostTokenId, authResult));
    ASSERT_FALSE(authResult.authResults.empty());
    secondChallenge = authResult.authResults[0];
    EXPECT_EQ(AccessTokenError::ERR_TOOL_TOKEN_ALREADY_EXIST,
        InitCliToolTokenWithChallenge(
            hostTokenId, secondChallenge, BuildCliInfo(), secondTokenIdEx, kernelPermList));
    SwitchToManageToolCaller();
    AccessTokenID queriedHostTokenId = INVALID_TOKENID;
    EXPECT_EQ(RET_SUCCESS, AccessTokenKit::GetHostTokenId(firstTokenIdEx.tokenIdExStruct.tokenID, queriedHostTokenId));
    EXPECT_EQ(hostTokenId, queriedHostTokenId);
}

/**
 * @tc.name: InitCliToken004
 * @tc.desc: DeleteToolTokenByPid deletes no-permission token and allows recreate in same pid.
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(ToolTokenTest, InitCliToken004, TestSize.Level4)
{
    ToolTokenGuard guard;
    AccessTokenIDEx firstTokenIdEx = {0};
    AccessTokenIDEx secondTokenIdEx = {0};
    std::vector<PermissionWithValue> kernelPermList;
    std::string challenge;
    MockHapToken hostToken("InitCliToken004", {}, true, 100);
    AccessTokenID hostTokenId = hostToken.GetTokenID();

    ASSERT_EQ(RET_SUCCESS, InitCliToolTokenWithEmptyPermissionAuth(
        hostTokenId, firstTokenIdEx, kernelPermList, challenge));
    guard.Arm();
    ASSERT_EQ(RET_SUCCESS, DeleteToolTokenByCurrentPid());
    guard.Disarm();
    challenge.clear();
    kernelPermList.clear();
    ASSERT_EQ(RET_SUCCESS, InitCliToolTokenWithEmptyPermissionAuth(
        hostTokenId, secondTokenIdEx, kernelPermList, challenge));
    ASSERT_FALSE(challenge.empty());
    ASSERT_NE(INVALID_TOKENID, secondTokenIdEx.tokenIdExStruct.tokenID);
    guard.Arm();
    VerifyNoPermissionToken(secondTokenIdEx.tokenIdExStruct.tokenID, kernelPermList);
}

/**
 * @tc.name: InitCliToken005
 * @tc.desc: InitCliToken keeps challenge after invalid uid failure and succeeds on AIMGR_UID retry.
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(ToolTokenTest, InitCliToken005, TestSize.Level4)
{
    ToolTokenGuard guard;
    AccessTokenIDEx tokenIdEx = {0};
    std::vector<PermissionWithValue> kernelPermList;
    ToolAuthResult authResult;
    MockHapToken hostToken("InitCliToken005", {}, true, 100);
    AccessTokenID hostTokenId = hostToken.GetTokenID();
    ASSERT_EQ(RET_SUCCESS, GenerateEmptyPermissionCliAuthResult(hostTokenId, authResult));
    ASSERT_FALSE(authResult.authResults.empty());
    ASSERT_FALSE(authResult.authResults[0].empty());

    uint32_t callerUid = getuid();
    EXPECT_EQ(0, SetSelfTokenID(g_shellTokenId));
    EXPECT_EQ(0, setuid(1234));
    CliInitInfo initInfo = {
        .hostTokenId = hostTokenId,
        .challenge = authResult.authResults[0],
        .cliInfo = BuildCliInfo(),
    };
    EXPECT_EQ(AccessTokenError::ERR_PERMISSION_DENIED,
        AccessTokenKit::InitCliToken(initInfo, tokenIdEx, kernelPermList));
    EXPECT_EQ(0, setuid(callerUid));
    ASSERT_EQ(RET_SUCCESS, InitCliToolTokenWithChallenge(
        hostTokenId, authResult.authResults[0], BuildCliInfo(), tokenIdEx, kernelPermList));
    guard.Arm();
    VerifyNoPermissionToken(tokenIdEx.tokenIdExStruct.tokenID, kernelPermList);
}

/**
 * @tc.name: InitCliToken006
 * @tc.desc: InitCliToken fails on invalid challenge or mismatched cliInfo and keeps challenge for retry.
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(ToolTokenTest, InitCliToken006, TestSize.Level4)
{
    ToolTokenGuard guard;
    AccessTokenIDEx tokenIdEx = {0};
    std::vector<PermissionWithValue> kernelPermList;
    ToolAuthResult authResult;
    MockHapToken hostToken("InitCliToken006", {}, true, 100);
    AccessTokenID hostTokenId = hostToken.GetTokenID();

    EXPECT_EQ(AccessTokenError::ERR_PARAM_INVALID, InitCliToolTokenWithChallenge(
        hostTokenId, "invalid_challenge", BuildCliInfo(), tokenIdEx, kernelPermList));
    ASSERT_EQ(RET_SUCCESS, GenerateEmptyPermissionCliAuthResult(hostTokenId, authResult));
    ASSERT_FALSE(authResult.authResults.empty());
    CliInfo wrongCliInfo = {
        .cliName = "wrong",
        .subCliName = "capture",
    };
    EXPECT_EQ(AccessTokenError::ERR_PARAM_INVALID, InitCliToolTokenWithChallenge(
        hostTokenId, authResult.authResults[0], wrongCliInfo, tokenIdEx, kernelPermList));
    ASSERT_EQ(RET_SUCCESS, InitCliToolTokenWithChallenge(
        hostTokenId, authResult.authResults[0], BuildCliInfo(), tokenIdEx, kernelPermList));
    guard.Arm();
    VerifyNoPermissionToken(tokenIdEx.tokenIdExStruct.tokenID, kernelPermList);
}

/**
 * @tc.name: DeleteToolTokenByPid001
 * @tc.desc: DeleteToolTokenByPid removes token and query interfaces return token-not-exist.
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(ToolTokenTest, DeleteToolTokenByPid001, TestSize.Level4)
{
    ToolTokenGuard guard;
    AccessTokenIDEx tokenIdEx = {0};
    std::vector<PermissionWithValue> kernelPermList;
    std::string challenge;
    CliTokenInfo tokenInfo;
    AccessTokenID queriedHostTokenId = INVALID_TOKENID;
    MockHapToken hostToken("DeleteToolTokenByPid001", {}, true, 100);
    AccessTokenID hostTokenId = hostToken.GetTokenID();

    ASSERT_EQ(RET_SUCCESS, InitCliToolTokenWithEmptyPermissionAuth(
        hostTokenId, tokenIdEx, kernelPermList, challenge));
    guard.Arm();
    ASSERT_EQ(RET_SUCCESS, DeleteToolTokenByCurrentPid());
    guard.Disarm();
    SwitchToManageToolCaller();
    EXPECT_EQ(AccessTokenError::ERR_TOKENID_NOT_EXIST,
        AccessTokenKit::GetCliTokenInfo(tokenIdEx.tokenIdExStruct.tokenID, tokenInfo));
    EXPECT_EQ(AccessTokenError::ERR_TOKENID_NOT_EXIST,
        AccessTokenKit::GetHostTokenId(tokenIdEx.tokenIdExStruct.tokenID, queriedHostTokenId));
    EXPECT_EQ(PERMISSION_DENIED,
        AccessTokenKit::VerifyAccessToken(tokenIdEx.tokenIdExStruct.tokenID, LOCATION_PERMISSION));
}

/**
 * @tc.name: DeleteToolTokenByPid002
 * @tc.desc: DeleteToolTokenByPid returns permission denied for unprivileged caller and token stays valid.
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(ToolTokenTest, DeleteToolTokenByPid002, TestSize.Level4)
{
    ToolTokenGuard guard;
    AccessTokenIDEx tokenIdEx = {0};
    std::vector<PermissionWithValue> kernelPermList;
    std::string challenge;
    MockHapToken hostToken("DeleteToolTokenByPid002", {}, true, 100);
    AccessTokenID hostTokenId = hostToken.GetTokenID();

    ASSERT_EQ(RET_SUCCESS, InitCliToolTokenWithEmptyPermissionAuth(
        hostTokenId, tokenIdEx, kernelPermList, challenge));
    guard.Arm();
    {
        MockHapToken caller("DeleteToolTokenByPid002Caller", {}, true, 100);
        EXPECT_EQ(AccessTokenError::ERR_PERMISSION_DENIED, AccessTokenKit::DeleteToolTokenByPid(getpid()));
    }
    SwitchToManageToolCaller();
    AccessTokenID queriedHostTokenId = INVALID_TOKENID;
    EXPECT_EQ(RET_SUCCESS, AccessTokenKit::GetHostTokenId(tokenIdEx.tokenIdExStruct.tokenID, queriedHostTokenId));
    EXPECT_EQ(hostTokenId, queriedHostTokenId);
}

/**
 * @tc.name: GetCliTokenInfo001
 * @tc.desc: GetCliTokenInfo returns token-not-exist for deleted or invalid tool token.
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(ToolTokenTest, GetCliTokenInfo001, TestSize.Level4)
{
    ToolTokenGuard guard;
    AccessTokenIDEx tokenIdEx = {0};
    std::vector<PermissionWithValue> kernelPermList;
    std::string challenge;
    CliTokenInfo tokenInfo;
    MockHapToken hostToken("GetCliTokenInfo001", {}, true, 100);
    AccessTokenID hostTokenId = hostToken.GetTokenID();

    ASSERT_EQ(RET_SUCCESS, InitCliToolTokenWithEmptyPermissionAuth(
        hostTokenId, tokenIdEx, kernelPermList, challenge));
    guard.Arm();
    ASSERT_EQ(RET_SUCCESS, DeleteToolTokenByCurrentPid());
    guard.Disarm();
    SwitchToManageToolCaller();
    EXPECT_EQ(AccessTokenError::ERR_TOKENID_NOT_EXIST,
        AccessTokenKit::GetCliTokenInfo(tokenIdEx.tokenIdExStruct.tokenID, tokenInfo));
    EXPECT_EQ(AccessTokenError::ERR_PARAM_INVALID, AccessTokenKit::GetCliTokenInfo(INVALID_TOKENID, tokenInfo));
}

/**
 * @tc.name: GetHostTokenId001
 * @tc.desc: GetHostTokenId returns original host token for no-permission tool token.
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(ToolTokenTest, GetHostTokenId001, TestSize.Level4)
{
    ToolTokenGuard guard;
    AccessTokenIDEx tokenIdEx = {0};
    std::vector<PermissionWithValue> kernelPermList;
    std::string challenge;
    AccessTokenID queriedHostTokenId = INVALID_TOKENID;
    MockHapToken hostToken("GetHostTokenId001", {}, true, 100);
    AccessTokenID hostTokenId = hostToken.GetTokenID();

    ASSERT_EQ(RET_SUCCESS, InitCliToolTokenWithEmptyPermissionAuth(
        hostTokenId, tokenIdEx, kernelPermList, challenge));
    guard.Arm();
    SwitchToManageToolCaller();
    ASSERT_EQ(RET_SUCCESS, AccessTokenKit::GetHostTokenId(tokenIdEx.tokenIdExStruct.tokenID, queriedHostTokenId));
    EXPECT_EQ(hostTokenId, queriedHostTokenId);
}

/**
 * @tc.name: GetHostTokenId002
 * @tc.desc: GetHostTokenId returns invalid-param for non-tool token.
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(ToolTokenTest, GetHostTokenId002, TestSize.Level4)
{
    MockHapToken hostToken("GetHostTokenId002", {}, true, 100);
    AccessTokenID queriedHostTokenId = INVALID_TOKENID;

    SwitchToManageToolCaller();
    EXPECT_EQ(AccessTokenError::ERR_PARAM_INVALID,
        AccessTokenKit::GetHostTokenId(hostToken.GetTokenID(), queriedHostTokenId));
}

/**
 * @tc.name: GetHostTokenId003
 * @tc.desc: GetHostTokenId returns token-not-exist after tool token is deleted.
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(ToolTokenTest, GetHostTokenId003, TestSize.Level4)
{
    ToolTokenGuard guard;
    AccessTokenIDEx tokenIdEx = {0};
    std::vector<PermissionWithValue> kernelPermList;
    std::string challenge;
    AccessTokenID queriedHostTokenId = INVALID_TOKENID;
    MockHapToken hostToken("GetHostTokenId003", {}, true, 100);

    ASSERT_EQ(RET_SUCCESS, InitCliToolTokenWithEmptyPermissionAuth(
        hostToken.GetTokenID(), tokenIdEx, kernelPermList, challenge));
    guard.Arm();
    ASSERT_EQ(RET_SUCCESS, DeleteToolTokenByCurrentPid());
    guard.Disarm();
    SwitchToManageToolCaller();
    EXPECT_EQ(AccessTokenError::ERR_TOKENID_NOT_EXIST,
        AccessTokenKit::GetHostTokenId(tokenIdEx.tokenIdExStruct.tokenID, queriedHostTokenId));
}
} // namespace AccessToken
} // namespace Security
} // namespace OHOS
