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

std::vector<PermissionStateFull> BuildClawManagePermissionStates()
{
    return {BuildGrantedPermissionState("ohos.permission.MANAGE_TOOL_RUNTIME_PERMISSIONS")};
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

std::vector<CliInfo> BuildMissingMappingCliInfos()
{
    return {CliInfo {.cliName = "missingmap", .subCliName = "run"}};
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
 * @tc.name: GetCliPermissionRequestInfoKit001
 * @tc.desc: CLAW CLI request info and CLI permissions go through normal kit and client path.
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(ClawPermissionKitTest, DISABLED_GetCliPermissionRequestInfoKit001, TestSize.Level3)
{
    auto permStates = BuildClawQueryAndManagePermissionStates();
    permStates.emplace_back(BuildGrantedPermissionState("ohos.permission.POWER_MANAGER"));
    ScopedClawCaller caller("claw_cli_kit_test", true, permStates);

    PermissionDialogResult dialogResult;
    ASSERT_EQ(RET_SUCCESS,
        AccessTokenKit::GetCliPermissionRequestInfo(DEFAULT_AGENT_ID, BuildCliInfos(), dialogResult));
    ASSERT_EQ(1, static_cast<int32_t>(dialogResult.detailList.size()));
    EXPECT_FALSE(dialogResult.detailList[0].needPermissionDialog);
    EXPECT_FALSE(dialogResult.detailList[0].authResult.empty());

    CliPermissionsResult permissionsResult;
    ASSERT_EQ(RET_SUCCESS,
        AccessTokenKit::GetCliPermissions(
            caller.GetTokenId(), DEFAULT_AGENT_ID, BuildCliInfos(), permissionsResult));
    ASSERT_EQ(1, static_cast<int32_t>(permissionsResult.permList.size()));
    ASSERT_EQ(1, static_cast<int32_t>(permissionsResult.permList[0].requiredCliPermissions.size()));

    const auto& detail = permissionsResult.permList[0].requiredCliPermissions[0];
    EXPECT_EQ("ohos.permission.POWER_MANAGER", detail.requiredCliPermission);
    EXPECT_EQ(PermissionDecisionStatus::NO_DIALOG_GRANTED, detail.cliPermissionStatus);
    ASSERT_EQ(1, static_cast<int32_t>(detail.usedPermissions.size()));
    EXPECT_EQ("ohos.permission.POWER_MANAGER", detail.usedPermissions[0]);
}

/**
 * @tc.name: GetSkillPermissionRequestInfoKit001
 * @tc.desc: CLAW skill request info and skill permissions go through normal kit and client path.
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(ClawPermissionKitTest, DISABLED_GetSkillPermissionRequestInfoKit001, TestSize.Level3)
{
    auto permStates = BuildClawQueryAndManagePermissionStates();
    permStates.emplace_back(BuildGrantedPermissionState("ohos.permission.CAMERA"));
    ScopedClawCaller caller("claw_skill_kit_test", true, permStates);

    PermissionDialogResult dialogResult;
    ASSERT_EQ(RET_SUCCESS,
        AccessTokenKit::GetSkillPermissionRequestInfo(DEFAULT_AGENT_ID, BuildSkillInfos(), dialogResult));
    ASSERT_EQ(1, static_cast<int32_t>(dialogResult.detailList.size()));
    EXPECT_FALSE(dialogResult.detailList[0].needPermissionDialog);
    EXPECT_FALSE(dialogResult.detailList[0].authResult.empty());

    SkillPermissionsResult permissionsResult;
    ASSERT_EQ(RET_SUCCESS,
        AccessTokenKit::GetSkillPermissions(
            caller.GetTokenId(), DEFAULT_AGENT_ID, BuildSkillInfos(), permissionsResult));
    ASSERT_EQ(1, static_cast<int32_t>(permissionsResult.permList.size()));
    ASSERT_EQ(1, static_cast<int32_t>(permissionsResult.permList[0].usedPermissions.size()));
    ASSERT_EQ(1, static_cast<int32_t>(permissionsResult.permList[0].statusList.size()));
    EXPECT_EQ("ohos.permission.CAMERA", permissionsResult.permList[0].usedPermissions[0]);
    EXPECT_EQ(PermissionDecisionStatus::NO_DIALOG_GRANTED, permissionsResult.permList[0].statusList[0]);
}

/**
 * @tc.name: GenerateClawAuthResultKit001
 * @tc.desc: CLAW auth result APIs go through normal kit and client path.
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(ClawPermissionKitTest, DISABLED_GenerateClawAuthResultKit001, TestSize.Level3)
{
    ScopedClawCaller caller("claw_auth_result_kit_test", true, BuildClawManagePermissionStates());

    ToolAuthResult cliAuthResult;
    ASSERT_EQ(RET_SUCCESS,
        AccessTokenKit::GenerateCliAuthResult(
            caller.GetTokenId(), DEFAULT_AGENT_ID, BuildCliAuthInfos(), cliAuthResult));
    ASSERT_EQ(1, static_cast<int32_t>(cliAuthResult.authResults.size()));
    EXPECT_EQ("authResult_" + std::to_string(caller.GetTokenId()) + "_0",
        cliAuthResult.authResults[0]);

    ToolAuthResult skillAuthResult;
    ASSERT_EQ(RET_SUCCESS,
        AccessTokenKit::GenerateSkillAuthResult(
            caller.GetTokenId(), DEFAULT_AGENT_ID, BuildSkillAuthInfos(), skillAuthResult));
    ASSERT_EQ(1, static_cast<int32_t>(skillAuthResult.authResults.size()));
    EXPECT_EQ("authResult_" + std::to_string(caller.GetTokenId()) + "_0",
        skillAuthResult.authResults[0]);
}

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
 * @tc.desc: CLAW kit APIs skip unknown CLI when metadata queryRet is not success.
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(ClawPermissionKitTest, DISABLED_ClawPermissionKitServiceError001, TestSize.Level3)
{
    ScopedClawCaller caller("claw_service_error_kit_test", true, BuildClawQueryAndManagePermissionStates());

    PermissionDialogResult dialogResult;
    ASSERT_EQ(RET_SUCCESS,
        AccessTokenKit::GetCliPermissionRequestInfo(DEFAULT_AGENT_ID, BuildUnknownCliInfos(), dialogResult));
    ASSERT_EQ(1, static_cast<int32_t>(dialogResult.detailList.size()));
    EXPECT_FALSE(dialogResult.detailList[0].needPermissionDialog);
    EXPECT_TRUE(dialogResult.detailList[0].permissionNameList.empty());
    EXPECT_TRUE(dialogResult.detailList[0].statusList.empty());
    EXPECT_FALSE(dialogResult.detailList[0].authResult.empty());

    CliPermissionsResult permissionsResult;
    ASSERT_EQ(RET_SUCCESS,
        AccessTokenKit::GetCliPermissions(
            caller.GetTokenId(), DEFAULT_AGENT_ID, BuildUnknownCliInfos(), permissionsResult));
    ASSERT_EQ(1, static_cast<int32_t>(permissionsResult.permList.size()));
    EXPECT_TRUE(permissionsResult.permList[0].requiredCliPermissions.empty());
}

/**
 * @tc.name: ClawPermissionKitServiceError002
 * @tc.desc: CLAW kit APIs treat missing CLI mapping as self-mapped permission.
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(ClawPermissionKitTest, ClawPermissionKitServiceError002, TestSize.Level3)
{
    ScopedClawCaller caller("claw_mapping_error_kit_test", true, BuildClawQueryAndManagePermissionStates());

    PermissionDialogResult dialogResult;
    ASSERT_EQ(RET_SUCCESS,
        AccessTokenKit::GetCliPermissionRequestInfo(
            DEFAULT_AGENT_ID, BuildMissingMappingCliInfos(), dialogResult));
    ASSERT_EQ(1, static_cast<int32_t>(dialogResult.detailList.size()));
    EXPECT_TRUE(dialogResult.detailList[0].needPermissionDialog);
    EXPECT_TRUE(dialogResult.detailList[0].permissionNameList.empty());
    EXPECT_TRUE(dialogResult.detailList[0].statusList.empty());
}

} // namespace AccessToken
} // namespace Security
} // namespace OHOS
