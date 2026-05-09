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
static constexpr int32_t DEFAULT_USER_ID = 0;
static constexpr int32_t DEFAULT_INST_INDEX = 0;
static constexpr int32_t DEFAULT_API_VERSION = 12;
static const std::string DEFAULT_AGENT_ID = "1001";
uint64_t g_selfShellTokenId = 0;

PermissionStateFull BuildPermissionState(
    const std::string& permissionName, int32_t grantStatus, uint32_t grantFlag)
{
    PermissionStateFull state;
    state.permissionName = permissionName;
    state.isGeneral = true;
    state.resDeviceID = {"local"};
    state.grantStatus = {grantStatus};
    state.grantFlags = {grantFlag};
    return state;
}

PermissionStateFull BuildGrantedPermissionState(const std::string& permissionName)
{
    return BuildPermissionState(
        permissionName, PermissionState::PERMISSION_GRANTED, PermissionFlag::PERMISSION_USER_SET);
}

std::vector<PermissionStateFull> BuildClawQueryAndManagePermissionStates()
{
    return {
        BuildGrantedPermissionState("ohos.permission.QUERY_TOOL_PERMISSIONS"),
        BuildGrantedPermissionState("ohos.permission.MANAGE_TOOL_RUNTIME_PERMISSIONS"),
    };
}

std::vector<CliInfo> BuildCliInfos()
{
    return {CliInfo {.cliName = "camera", .subCliName = "capture"}};
}

std::vector<CliInfo> BuildUnknownCliInfos()
{
    return {CliInfo {.cliName = "unknown", .subCliName = "run"}};
}

std::vector<SkillInfo> BuildSkillInfos()
{
    return {SkillInfo {.skillName = "cameraSkill", .bundleName = "com.ohos.claw.demo", .moduleName = "entry"}};
}

std::vector<CliAuthInfo> BuildCliAuthInfos()
{
    return {CliAuthInfo {
        .cliInfo = {.cliName = "camera", .subCliName = "capture"},
        .permissionNames = {"ohos.permission.POWER_MANAGER"},
        .authorizationResults = {true},
    }};
}

std::vector<SkillAuthInfo> BuildSkillAuthInfos()
{
    return {SkillAuthInfo {
        .skillInfo = {.skillName = "cameraSkill", .bundleName = "com.ohos.claw.demo", .moduleName = "entry"},
        .permissionNames = {"ohos.permission.CAMERA"},
        .authorizationResults = {true},
    }};
}

class ScopedClawCaller final {
public:
    ScopedClawCaller(
        const std::string& bundleName, bool isSystemApp, const std::vector<PermissionStateFull>& permStateList)
    {
        HapInfoParams info;
        HapPolicyParams policy;
        TestCommon::GetHapParams(info, policy);
        info.userID = DEFAULT_USER_ID;
        info.bundleName = bundleName;
        info.instIndex = DEFAULT_INST_INDEX;
        info.appIDDesc = bundleName;
        info.apiVersion = DEFAULT_API_VERSION;
        info.isSystemApp = isSystemApp;

        policy.apl = APL_SYSTEM_BASIC;
        policy.domain = "claw_permission_test_domain";
        policy.permStateList = permStateList;

        tokenIdEx_ = TestCommon::AllocAndGrantHapTokenByTest(info, policy);
        tokenId_ = tokenIdEx_.tokenIdExStruct.tokenID;
        EXPECT_NE(INVALID_TOKENID, tokenId_);
        EXPECT_EQ(0, SetSelfTokenID(tokenIdEx_.tokenIDEx));
    }

    ~ScopedClawCaller()
    {
        EXPECT_EQ(0, SetSelfTokenID(g_selfShellTokenId));
        if (tokenId_ != INVALID_TOKENID) {
            EXPECT_EQ(RET_SUCCESS, TestCommon::DeleteTestHapToken(tokenId_));
        }
    }

    AccessTokenID GetTokenId() const
    {
        return tokenId_;
    }

private:
    AccessTokenIDEx tokenIdEx_ = {0};
    AccessTokenID tokenId_ = INVALID_TOKENID;
};
} // namespace

class ClawPermissionKitTest : public testing::Test {
public:
    static void SetUpTestCase()
    {
        g_selfShellTokenId = GetSelfTokenID();
        TestCommon::SetTestEvironment(g_selfShellTokenId);
    }

    static void TearDownTestCase()
    {
        SetSelfTokenID(g_selfShellTokenId);
        TestCommon::ResetTestEvironment();
    }

    void TearDown() override
    {
        EXPECT_EQ(0, SetSelfTokenID(g_selfShellTokenId));
    }
};


/**
 * @tc.name: ClawPermissionKitNonSystem001
 * @tc.desc: CLAW kit APIs return not system app for valid non-system caller.
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(ClawPermissionKitTest, ClawPermissionKitNonSystem001, TestSize.Level3)
{
    ScopedClawCaller caller("claw_non_system_kit_test", false, {});

    PermissionDialogResult dialogResult;
    EXPECT_EQ(AccessTokenError::ERR_NOT_SYSTEM_APP,
        AccessTokenKit::GetCliPermissionRequestInfo(DEFAULT_AGENT_ID, BuildCliInfos(), dialogResult));
    EXPECT_EQ(AccessTokenError::ERR_NOT_SYSTEM_APP,
        AccessTokenKit::GetSkillPermissionRequestInfo(DEFAULT_AGENT_ID, BuildSkillInfos(), dialogResult));

    CliPermissionsResult cliPermissionsResult;
    EXPECT_EQ(AccessTokenError::ERR_NOT_SYSTEM_APP,
        AccessTokenKit::GetCliPermissions(
            caller.GetTokenId(), DEFAULT_AGENT_ID, BuildCliInfos(), cliPermissionsResult));

    SkillPermissionsResult skillPermissionsResult;
    EXPECT_EQ(AccessTokenError::ERR_NOT_SYSTEM_APP,
        AccessTokenKit::GetSkillPermissions(
            caller.GetTokenId(), DEFAULT_AGENT_ID, BuildSkillInfos(), skillPermissionsResult));

    ToolAuthResult authResult;
    EXPECT_EQ(AccessTokenError::ERR_NOT_SYSTEM_APP,
        AccessTokenKit::GenerateCliAuthResult(
            caller.GetTokenId(), DEFAULT_AGENT_ID, BuildCliAuthInfos(), authResult));
    EXPECT_EQ(AccessTokenError::ERR_NOT_SYSTEM_APP,
        AccessTokenKit::GenerateSkillAuthResult(
            caller.GetTokenId(), DEFAULT_AGENT_ID, BuildSkillAuthInfos(), authResult));
}

/**
 * @tc.name: ClawPermissionKitServiceError001
 * @tc.desc: CLAW kit APIs return ERR_PARAM_INVALID when CLI metadata queryRet is not success.
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(ClawPermissionKitTest, ClawPermissionKitServiceError001, TestSize.Level3)
{
    ScopedClawCaller caller("claw_service_error_kit_test", true, BuildClawQueryAndManagePermissionStates());

    PermissionDialogResult dialogResult;
    ASSERT_EQ(AccessTokenError::ERR_PARAM_INVALID,
        AccessTokenKit::GetCliPermissionRequestInfo(DEFAULT_AGENT_ID, BuildUnknownCliInfos(), dialogResult));

    CliPermissionsResult permissionsResult;
    ASSERT_EQ(AccessTokenError::ERR_PARAM_INVALID,
        AccessTokenKit::GetCliPermissions(
            caller.GetTokenId(), DEFAULT_AGENT_ID, BuildUnknownCliInfos(), permissionsResult));
}

} // namespace AccessToken
} // namespace Security
} // namespace OHOS
