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
#include <vector>

#include "access_token.h"
#include "access_token_error.h"
#include "accesstoken_info_manager.h"
#include "claw_permission_decision_engine.h"
#include "claw_permission_metadata_provider.h"
#include "constant_common.h"
#include "generic_values.h"
#include "hap_token_info.h"

using namespace testing::ext;

namespace OHOS {
namespace Security {
namespace AccessToken {
namespace {
static constexpr int32_t TEST_USER_ID = 100;
static constexpr int32_t TEST_INST_INDEX = 0;

AccessTokenID CreateHapToken(const std::string& bundleName, const std::vector<PermissionStatus>& permStateList)
{
    HapInfoParams hapInfo = {
        .userID = TEST_USER_ID,
        .bundleName = bundleName,
        .instIndex = TEST_INST_INDEX,
        .appIDDesc = bundleName
    };
    HapPolicy hapPolicy = {
        .apl = APL_NORMAL,
        .domain = "test.domain",
        .permList = {},
        .permStateList = permStateList
    };

    AccessTokenIDEx tokenIdEx = {0};
    std::vector<GenericValues> undefValues;
    int32_t ret = AccessTokenInfoManager::GetInstance().CreateHapTokenInfo(
        hapInfo, hapPolicy, tokenIdEx, undefValues);
    if (ret != RET_SUCCESS) {
        return INVALID_TOKENID;
    }
    return tokenIdEx.tokenIdExStruct.tokenID;
}

AccessTokenID CreateEmptyHapToken(const std::string& bundleName)
{
    return CreateHapToken(bundleName, {});
}
}

class ClawPermissionDecisionEngineTest : public testing::Test {
public:
    void TearDown() override
    {
        if (tokenId_ != INVALID_TOKENID) {
            (void)AccessTokenInfoManager::GetInstance().RemoveHapTokenInfo(tokenId_);
            tokenId_ = INVALID_TOKENID;
        }
    }

    AccessTokenID tokenId_ = INVALID_TOKENID;
};

/**
 * @tc.name: BuildCliPermissionDialogInfo001
 * @tc.desc: Undeclared CLI permission should return NO_DIALOG_NOT_DECLARED and no dialog.
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(ClawPermissionDecisionEngineTest, BuildCliPermissionDialogInfo001, TestSize.Level0)
{
    tokenId_ = CreateEmptyHapToken("claw_permission_cli_dialog_test");
    ASSERT_NE(INVALID_TOKENID, tokenId_);

    std::vector<CliInfo> cliInfoList = {{
        .cliName = "camera",
        .subCliName = "capture"
    }};
    PermissionDialogResult result;
    ASSERT_EQ(RET_SUCCESS, ClawPermissionDecisionEngine::GetInstance().BuildCliPermissionDialogInfo(
        tokenId_, cliInfoList, result));
    ASSERT_EQ(1, static_cast<int32_t>(result.detailList.size()));
    EXPECT_FALSE(result.detailList[0].needPermissionDialog);
    ASSERT_EQ(1, static_cast<int32_t>(result.detailList[0].permissionNameList.size()));
    EXPECT_EQ("ohos.permission.POWER_MANAGER", result.detailList[0].permissionNameList[0]);
    ASSERT_EQ(1, static_cast<int32_t>(result.detailList[0].statusList.size()));
    EXPECT_EQ(PermissionDecisionStatus::NO_DIALOG_NOT_DECLARED, result.detailList[0].statusList[0]);
}

/**
 * @tc.name: BuildCliPermissionDialogInfo001_001
 * @tc.desc: CLI with empty required permission list should not require dialog.
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(ClawPermissionDecisionEngineTest, BuildCliPermissionDialogInfo001_001, TestSize.Level0)
{
    tokenId_ = CreateEmptyHapToken("claw_permission_cli_no_required_permission_test");
    ASSERT_NE(INVALID_TOKENID, tokenId_);

    std::vector<CliInfo> cliInfoList = {{
        .cliName = "empty",
        .subCliName = "run"
    }};
    PermissionDialogResult result;
    ASSERT_EQ(RET_SUCCESS, ClawPermissionDecisionEngine::GetInstance().BuildCliPermissionDialogInfo(
        tokenId_, cliInfoList, result));
    ASSERT_EQ(1, static_cast<int32_t>(result.detailList.size()));
    EXPECT_FALSE(result.detailList[0].needPermissionDialog);
    EXPECT_TRUE(result.detailList[0].permissionNameList.empty());
    EXPECT_TRUE(result.detailList[0].statusList.empty());
}

/**
 * @tc.name: BuildCliPermissionDialogInfo002
 * @tc.desc: Persistent granted required permission should not check used permissions for dialog.
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(ClawPermissionDecisionEngineTest, BuildCliPermissionDialogInfo002, TestSize.Level0)
{
    PermissionStatus cliState = {
        .permissionName = "ohos.permission.POWER_MANAGER",
        .grantStatus = PERMISSION_GRANTED,
        .grantFlag = PERMISSION_USER_SET
    };
    tokenId_ = CreateHapToken("claw_permission_cli_persistent_test", {cliState});
    ASSERT_NE(INVALID_TOKENID, tokenId_);

    std::vector<CliInfo> cliInfoList = {{
        .cliName = "camera",
        .subCliName = "capture"
    }};
    PermissionDialogResult result;
    ASSERT_EQ(RET_SUCCESS, ClawPermissionDecisionEngine::GetInstance().BuildCliPermissionDialogInfo(
        tokenId_, cliInfoList, result));
    ASSERT_EQ(1, static_cast<int32_t>(result.detailList.size()));
    EXPECT_FALSE(result.detailList[0].needPermissionDialog);
    EXPECT_TRUE(result.detailList[0].permissionNameList.empty());
    EXPECT_TRUE(result.detailList[0].statusList.empty());
}

/**
 * @tc.name: BuildCliPermissionDialogInfo003
 * @tc.desc: Undecided required CLI permission should still require dialog when one mapped permission is undecided.
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(ClawPermissionDecisionEngineTest, BuildCliPermissionDialogInfo003, TestSize.Level0)
{
    PermissionStatus cliState = {
        .permissionName = "ohos.permission.APPROXIMATELY_LOCATION",
        .grantStatus = PERMISSION_DENIED,
        .grantFlag = PERMISSION_DEFAULT_FLAG
    };
    PermissionStatus locationState = {
        .permissionName = "ohos.permission.LOCATION",
        .grantStatus = PERMISSION_GRANTED,
        .grantFlag = PERMISSION_USER_SET
    };
    tokenId_ = CreateHapToken("claw_permission_cli_required_need_dialog_test", {cliState, locationState});
    ASSERT_NE(INVALID_TOKENID, tokenId_);

    std::vector<CliInfo> cliInfoList = {{
        .cliName = "location",
        .subCliName = "query"
    }};
    PermissionDialogResult result;
    ASSERT_EQ(RET_SUCCESS, ClawPermissionDecisionEngine::GetInstance().BuildCliPermissionDialogInfo(
        tokenId_, cliInfoList, result));
    ASSERT_EQ(1, static_cast<int32_t>(result.detailList.size()));
    EXPECT_TRUE(result.detailList[0].needPermissionDialog);
    EXPECT_TRUE(result.detailList[0].permissionNameList.empty());
    EXPECT_TRUE(result.detailList[0].statusList.empty());
}

/**
 * @tc.name: BuildCliPermissionDialogInfo004
 * @tc.desc: Denied required CLI permission should be returned in detail and still evaluate used permission.
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(ClawPermissionDecisionEngineTest, BuildCliPermissionDialogInfo004, TestSize.Level0)
{
    PermissionStatus cliState = {
        .permissionName = "ohos.permission.APPROXIMATELY_LOCATION",
        .grantStatus = PERMISSION_DENIED,
        .grantFlag = PERMISSION_USER_FIXED
    };
    PermissionStatus locationState = {
        .permissionName = "ohos.permission.LOCATION",
        .grantStatus = PERMISSION_DENIED,
        .grantFlag = PERMISSION_DEFAULT_FLAG
    };
    tokenId_ = CreateHapToken("claw_permission_cli_denied_continue_test", {cliState, locationState});
    ASSERT_NE(INVALID_TOKENID, tokenId_);

    std::vector<CliInfo> cliInfoList = {{
        .cliName = "location",
        .subCliName = "query"
    }};
    PermissionDialogResult result;
    ASSERT_EQ(RET_SUCCESS, ClawPermissionDecisionEngine::GetInstance().BuildCliPermissionDialogInfo(
        tokenId_, cliInfoList, result));
    ASSERT_EQ(1, static_cast<int32_t>(result.detailList.size()));
    EXPECT_FALSE(result.detailList[0].needPermissionDialog);
    ASSERT_EQ(1, static_cast<int32_t>(result.detailList[0].permissionNameList.size()));
    EXPECT_EQ("ohos.permission.APPROXIMATELY_LOCATION", result.detailList[0].permissionNameList[0]);
    ASSERT_EQ(1, static_cast<int32_t>(result.detailList[0].statusList.size()));
    EXPECT_EQ(PermissionDecisionStatus::NO_DIALOG_DENIED, result.detailList[0].statusList[0]);
}

/**
 * @tc.name: BuildCliPermissionDialogInfo005
 * @tc.desc: Restricted required CLI permission should be returned without dialog if used permission is granted.
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(ClawPermissionDecisionEngineTest, BuildCliPermissionDialogInfo005, TestSize.Level0)
{
    PermissionStatus cliState = {
        .permissionName = "ohos.permission.APPROXIMATELY_LOCATION",
        .grantStatus = PERMISSION_DENIED,
        .grantFlag = PERMISSION_SYSTEM_FIXED
    };
    PermissionStatus locationState = {
        .permissionName = "ohos.permission.LOCATION",
        .grantStatus = PERMISSION_GRANTED,
        .grantFlag = PERMISSION_USER_SET
    };
    tokenId_ = CreateHapToken("claw_permission_cli_restricted_test", {cliState, locationState});
    ASSERT_NE(INVALID_TOKENID, tokenId_);

    std::vector<CliInfo> cliInfoList = {{
        .cliName = "location",
        .subCliName = "query"
    }};
    PermissionDialogResult result;
    ASSERT_EQ(RET_SUCCESS, ClawPermissionDecisionEngine::GetInstance().BuildCliPermissionDialogInfo(
        tokenId_, cliInfoList, result));
    ASSERT_EQ(1, static_cast<int32_t>(result.detailList.size()));
    EXPECT_FALSE(result.detailList[0].needPermissionDialog);
    ASSERT_EQ(1, static_cast<int32_t>(result.detailList[0].permissionNameList.size()));
    EXPECT_EQ("ohos.permission.APPROXIMATELY_LOCATION", result.detailList[0].permissionNameList[0]);
    ASSERT_EQ(1, static_cast<int32_t>(result.detailList[0].statusList.size()));
    EXPECT_EQ(PermissionDecisionStatus::NO_DIALOG_RESTRICTED, result.detailList[0].statusList[0]);
}

/**
 * @tc.name: BuildCliPermissionDialogInfo006
 * @tc.desc: Used permission granted this time should not affect CLI dialog requirement.
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(ClawPermissionDecisionEngineTest, BuildCliPermissionDialogInfo006, TestSize.Level0)
{
    PermissionStatus cliState = {
        .permissionName = "ohos.permission.APPROXIMATELY_LOCATION",
        .grantStatus = PERMISSION_DENIED,
        .grantFlag = PERMISSION_SYSTEM_FIXED
    };
    PermissionStatus locationState = {
        .permissionName = "ohos.permission.LOCATION",
        .grantStatus = PERMISSION_GRANTED,
        .grantFlag = PERMISSION_ALLOW_THIS_TIME
    };
    tokenId_ = CreateHapToken("claw_permission_cli_mapped_once_test", {cliState, locationState});
    ASSERT_NE(INVALID_TOKENID, tokenId_);

    std::vector<CliInfo> cliInfoList = {{
        .cliName = "location",
        .subCliName = "query"
    }};
    PermissionDialogResult result;
    ASSERT_EQ(RET_SUCCESS, ClawPermissionDecisionEngine::GetInstance().BuildCliPermissionDialogInfo(
        tokenId_, cliInfoList, result));
    ASSERT_EQ(1, static_cast<int32_t>(result.detailList.size()));
    EXPECT_FALSE(result.detailList[0].needPermissionDialog);
    ASSERT_EQ(1, static_cast<int32_t>(result.detailList[0].permissionNameList.size()));
    EXPECT_EQ("ohos.permission.APPROXIMATELY_LOCATION", result.detailList[0].permissionNameList[0]);
    ASSERT_EQ(1, static_cast<int32_t>(result.detailList[0].statusList.size()));
    EXPECT_EQ(PermissionDecisionStatus::NO_DIALOG_RESTRICTED, result.detailList[0].statusList[0]);
}

/**
 * @tc.name: BuildCliPermissionDialogInfo007
 * @tc.desc: Self-mapped restricted permission should be returned as restricted without dialog.
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(ClawPermissionDecisionEngineTest, BuildCliPermissionDialogInfo007, TestSize.Level0)
{
    PermissionStatus cliState = {
        .permissionName = "ohos.permission.POWER_MANAGER",
        .grantStatus = PERMISSION_DENIED,
        .grantFlag = PERMISSION_SYSTEM_FIXED
    };
    tokenId_ = CreateHapToken("claw_permission_cli_mapped_mixed_test", {cliState});
    ASSERT_NE(INVALID_TOKENID, tokenId_);

    std::vector<CliInfo> cliInfoList = {{
        .cliName = "camera",
        .subCliName = "capture"
    }};
    PermissionDialogResult result;
    ASSERT_EQ(RET_SUCCESS, ClawPermissionDecisionEngine::GetInstance().BuildCliPermissionDialogInfo(
        tokenId_, cliInfoList, result));
    ASSERT_EQ(1, static_cast<int32_t>(result.detailList.size()));
    EXPECT_FALSE(result.detailList[0].needPermissionDialog);
    ASSERT_EQ(1, static_cast<int32_t>(result.detailList[0].permissionNameList.size()));
    EXPECT_EQ("ohos.permission.POWER_MANAGER", result.detailList[0].permissionNameList[0]);
    ASSERT_EQ(1, static_cast<int32_t>(result.detailList[0].statusList.size()));
    EXPECT_EQ(PermissionDecisionStatus::NO_DIALOG_RESTRICTED, result.detailList[0].statusList[0]);
}

/**
 * @tc.name: BuildCliPermissionDialogInfo008
 * @tc.desc: CLI required permissions can contain both cli_xx and system permissions.
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(ClawPermissionDecisionEngineTest, BuildCliPermissionDialogInfo008, TestSize.Level0)
{
    tokenId_ = CreateEmptyHapToken("claw_permission_cli_mixed_required_dialog_test");
    ASSERT_NE(INVALID_TOKENID, tokenId_);

    std::vector<CliInfo> cliInfoList = {{
        .cliName = "mixed",
        .subCliName = "run"
    }};
    PermissionDialogResult result;
    ASSERT_EQ(RET_SUCCESS, ClawPermissionDecisionEngine::GetInstance().BuildCliPermissionDialogInfo(
        tokenId_, cliInfoList, result));
    ASSERT_EQ(1, static_cast<int32_t>(result.detailList.size()));
    EXPECT_FALSE(result.detailList[0].needPermissionDialog);
    ASSERT_EQ(2, static_cast<int32_t>(result.detailList[0].permissionNameList.size()));
    EXPECT_EQ("ohos.permission.APPROXIMATELY_LOCATION", result.detailList[0].permissionNameList[0]);
    EXPECT_EQ("ohos.permission.CAMERA", result.detailList[0].permissionNameList[1]);
    ASSERT_EQ(2, static_cast<int32_t>(result.detailList[0].statusList.size()));
    EXPECT_EQ(PermissionDecisionStatus::NO_DIALOG_NOT_DECLARED, result.detailList[0].statusList[0]);
    EXPECT_EQ(PermissionDecisionStatus::NO_DIALOG_NOT_DECLARED, result.detailList[0].statusList[1]);
}

/**
 * @tc.name: BuildCliPermissionDialogInfo009
 * @tc.desc: Undecided required CLI permission should still require dialog when mapped permission is undeclared.
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(ClawPermissionDecisionEngineTest, BuildCliPermissionDialogInfo009, TestSize.Level0)
{
    PermissionStatus cliState = {
        .permissionName = "ohos.permission.APPROXIMATELY_LOCATION",
        .grantStatus = PERMISSION_DENIED,
        .grantFlag = PERMISSION_DEFAULT_FLAG
    };
    tokenId_ = CreateHapToken("claw_permission_cli_required_need_dialog_with_undeclared_used_test", {cliState});
    ASSERT_NE(INVALID_TOKENID, tokenId_);

    std::vector<CliInfo> cliInfoList = {{
        .cliName = "location",
        .subCliName = "query"
    }};
    PermissionDialogResult result;
    ASSERT_EQ(RET_SUCCESS, ClawPermissionDecisionEngine::GetInstance().BuildCliPermissionDialogInfo(
        tokenId_, cliInfoList, result));
    ASSERT_EQ(1, static_cast<int32_t>(result.detailList.size()));
    EXPECT_TRUE(result.detailList[0].needPermissionDialog);
    EXPECT_TRUE(result.detailList[0].permissionNameList.empty());
    EXPECT_TRUE(result.detailList[0].statusList.empty());
}

/**
 * @tc.name: BuildCliPermissions001
 * @tc.desc: System API CLI result should return required CLI permission status and used permissions.
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(ClawPermissionDecisionEngineTest, BuildCliPermissions001, TestSize.Level0)
{
    PermissionStatus cliState = {
        .permissionName = "ohos.permission.POWER_MANAGER",
        .grantStatus = PERMISSION_GRANTED,
        .grantFlag = PERMISSION_USER_SET
    };
    tokenId_ = CreateHapToken("claw_permission_cli_result_test", {cliState});
    ASSERT_NE(INVALID_TOKENID, tokenId_);

    std::vector<CliInfo> cliInfoList = {{
        .cliName = "camera",
        .subCliName = "capture"
    }};
    CliPermissionsResult result;
    ASSERT_EQ(RET_SUCCESS, ClawPermissionDecisionEngine::GetInstance().BuildCliPermissions(
        tokenId_, cliInfoList, result));
    ASSERT_EQ(1, static_cast<int32_t>(result.permList.size()));
    ASSERT_EQ(1, static_cast<int32_t>(result.permList[0].requiredCliPermissions.size()));
    const auto& detail = result.permList[0].requiredCliPermissions[0];
    EXPECT_EQ("ohos.permission.POWER_MANAGER", detail.requiredCliPermission);
    EXPECT_EQ(PermissionDecisionStatus::NO_DIALOG_GRANTED, detail.cliPermissionStatus);
    ASSERT_EQ(1, static_cast<int32_t>(detail.usedPermissions.size()));
    EXPECT_EQ("ohos.permission.POWER_MANAGER", detail.usedPermissions[0]);
}

/**
 * @tc.name: BuildCliPermissions002
 * @tc.desc: System API CLI result should mark undeclared required permission as NO_DIALOG_NOT_DECLARED.
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(ClawPermissionDecisionEngineTest, BuildCliPermissions002, TestSize.Level0)
{
    tokenId_ = CreateEmptyHapToken("claw_permission_cli_not_declared_result_test");
    ASSERT_NE(INVALID_TOKENID, tokenId_);

    std::vector<CliInfo> cliInfoList = {{
        .cliName = "camera",
        .subCliName = "capture"
    }};
    CliPermissionsResult result;
    ASSERT_EQ(RET_SUCCESS, ClawPermissionDecisionEngine::GetInstance().BuildCliPermissions(
        tokenId_, cliInfoList, result));
    ASSERT_EQ(1, static_cast<int32_t>(result.permList.size()));
    ASSERT_EQ(1, static_cast<int32_t>(result.permList[0].requiredCliPermissions.size()));
    const auto& detail = result.permList[0].requiredCliPermissions[0];
    EXPECT_EQ("ohos.permission.POWER_MANAGER", detail.requiredCliPermission);
    EXPECT_EQ(PermissionDecisionStatus::NO_DIALOG_NOT_DECLARED, detail.cliPermissionStatus);
    EXPECT_TRUE(detail.usedPermissions.empty());
}

/**
 * @tc.name: BuildCliPermissions003
 * @tc.desc: System API CLI result should treat one-time required CLI permission as needing dialog.
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(ClawPermissionDecisionEngineTest, BuildCliPermissions003, TestSize.Level0)
{
    PermissionStatus cliState = {
        .permissionName = "ohos.permission.POWER_MANAGER",
        .grantStatus = PERMISSION_GRANTED,
        .grantFlag = PERMISSION_ALLOW_THIS_TIME
    };
    tokenId_ = CreateHapToken("claw_permission_cli_once_result_test", {cliState});
    ASSERT_NE(INVALID_TOKENID, tokenId_);

    std::vector<CliInfo> cliInfoList = {{
        .cliName = "camera",
        .subCliName = "capture"
    }};
    CliPermissionsResult result;
    ASSERT_EQ(RET_SUCCESS, ClawPermissionDecisionEngine::GetInstance().BuildCliPermissions(
        tokenId_, cliInfoList, result));
    ASSERT_EQ(1, static_cast<int32_t>(result.permList.size()));
    ASSERT_EQ(1, static_cast<int32_t>(result.permList[0].requiredCliPermissions.size()));
    EXPECT_EQ(PermissionDecisionStatus::NEED_PERMISSION_DIALOG,
        result.permList[0].requiredCliPermissions[0].cliPermissionStatus);
}

/**
 * @tc.name: BuildCliPermissions004
 * @tc.desc: System API CLI result should return denied required CLI permission status.
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(ClawPermissionDecisionEngineTest, BuildCliPermissions004, TestSize.Level0)
{
    PermissionStatus cliState = {
        .permissionName = "ohos.permission.APPROXIMATELY_LOCATION",
        .grantStatus = PERMISSION_DENIED,
        .grantFlag = PERMISSION_USER_FIXED
    };
    tokenId_ = CreateHapToken("claw_permission_cli_denied_result_test", {cliState});
    ASSERT_NE(INVALID_TOKENID, tokenId_);

    std::vector<CliInfo> cliInfoList = {{
        .cliName = "location",
        .subCliName = "query"
    }};
    CliPermissionsResult result;
    ASSERT_EQ(RET_SUCCESS, ClawPermissionDecisionEngine::GetInstance().BuildCliPermissions(
        tokenId_, cliInfoList, result));
    ASSERT_EQ(1, static_cast<int32_t>(result.permList.size()));
    ASSERT_EQ(1, static_cast<int32_t>(result.permList[0].requiredCliPermissions.size()));
    const auto& detail = result.permList[0].requiredCliPermissions[0];
    EXPECT_EQ("ohos.permission.APPROXIMATELY_LOCATION", detail.requiredCliPermission);
    EXPECT_EQ(PermissionDecisionStatus::NO_DIALOG_DENIED, detail.cliPermissionStatus);
    ASSERT_EQ(2, static_cast<int32_t>(detail.usedPermissions.size()));
    EXPECT_EQ("ohos.permission.LOCATION", detail.usedPermissions[0]);
    EXPECT_EQ("ohos.permission.APPROXIMATELY_LOCATION", detail.usedPermissions[1]);
}

/**
 * @tc.name: BuildCliPermissions005
 * @tc.desc: System API CLI result should support mapped and direct system permissions together.
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(ClawPermissionDecisionEngineTest, BuildCliPermissions005, TestSize.Level0)
{
    tokenId_ = CreateEmptyHapToken("claw_permission_cli_mixed_required_result_test");
    ASSERT_NE(INVALID_TOKENID, tokenId_);

    std::vector<CliInfo> cliInfoList = {{
        .cliName = "mixed",
        .subCliName = "run"
    }};
    CliPermissionsResult result;
    ASSERT_EQ(RET_SUCCESS, ClawPermissionDecisionEngine::GetInstance().BuildCliPermissions(
        tokenId_, cliInfoList, result));
    ASSERT_EQ(1, static_cast<int32_t>(result.permList.size()));
    ASSERT_EQ(2, static_cast<int32_t>(result.permList[0].requiredCliPermissions.size()));

    const auto& cliDetail = result.permList[0].requiredCliPermissions[0];
    EXPECT_EQ("ohos.permission.APPROXIMATELY_LOCATION", cliDetail.requiredCliPermission);
    EXPECT_EQ(PermissionDecisionStatus::NO_DIALOG_NOT_DECLARED, cliDetail.cliPermissionStatus);
    EXPECT_TRUE(cliDetail.usedPermissions.empty());

    const auto& systemDetail = result.permList[0].requiredCliPermissions[1];
    EXPECT_EQ("ohos.permission.CAMERA", systemDetail.requiredCliPermission);
    EXPECT_EQ(PermissionDecisionStatus::NO_DIALOG_NOT_DECLARED, systemDetail.cliPermissionStatus);
    EXPECT_TRUE(systemDetail.usedPermissions.empty());
}

/**
 * @tc.name: BuildCliPermissions006
 * @tc.desc: System API CLI result should support multiple required permissions.
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(ClawPermissionDecisionEngineTest, BuildCliPermissions006, TestSize.Level0)
{
    tokenId_ = CreateEmptyHapToken("claw_permission_cli_multi_required_result_test");
    ASSERT_NE(INVALID_TOKENID, tokenId_);

    std::vector<CliInfo> cliInfoList = {{
        .cliName = "multi",
        .subCliName = "run"
    }};
    CliPermissionsResult result;
    ASSERT_EQ(RET_SUCCESS, ClawPermissionDecisionEngine::GetInstance().BuildCliPermissions(
        tokenId_, cliInfoList, result));
    ASSERT_EQ(1, static_cast<int32_t>(result.permList.size()));
    ASSERT_EQ(2, static_cast<int32_t>(result.permList[0].requiredCliPermissions.size()));
    EXPECT_EQ("ohos.permission.APPROXIMATELY_LOCATION",
        result.permList[0].requiredCliPermissions[0].requiredCliPermission);
    EXPECT_EQ("ohos.permission.POWER_MANAGER",
        result.permList[0].requiredCliPermissions[1].requiredCliPermission);
    ASSERT_EQ(0, static_cast<int32_t>(result.permList[0].requiredCliPermissions[0].usedPermissions.size()));
    ASSERT_EQ(0, static_cast<int32_t>(result.permList[0].requiredCliPermissions[1].usedPermissions.size()));
}

/**
 * @tc.name: BuildCliPermissions008
 * @tc.desc: Undefined required CLI permission should stay not declared even if mapped used permission is granted.
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(ClawPermissionDecisionEngineTest, BuildCliPermissions008, TestSize.Level0)
{
    PermissionStatus cliState = {
        .permissionName = "ohos.permission.cli.resolved",
        .grantStatus = PERMISSION_DENIED,
        .grantFlag = PERMISSION_DEFAULT_FLAG
    };
    PermissionStatus usedState = {
        .permissionName = "ohos.permission.CAMERA",
        .grantStatus = PERMISSION_GRANTED,
        .grantFlag = PERMISSION_USER_SET
    };
    tokenId_ = CreateHapToken("claw_permission_cli_resolved_result_test", {cliState, usedState});
    ASSERT_NE(INVALID_TOKENID, tokenId_);

    std::vector<CliInfo> cliInfoList = {{
        .cliName = "resolved",
        .subCliName = "run"
    }};
    CliPermissionsResult result;
    ASSERT_EQ(RET_SUCCESS, ClawPermissionDecisionEngine::GetInstance().BuildCliPermissions(
        tokenId_, cliInfoList, result));
    ASSERT_EQ(1, static_cast<int32_t>(result.permList.size()));
    ASSERT_EQ(1, static_cast<int32_t>(result.permList[0].requiredCliPermissions.size()));
    const auto& detail = result.permList[0].requiredCliPermissions[0];
    EXPECT_EQ("ohos.permission.cli.resolved", detail.requiredCliPermission);
    EXPECT_EQ(PermissionDecisionStatus::NO_DIALOG_NOT_DECLARED, detail.cliPermissionStatus);
    EXPECT_TRUE(detail.usedPermissions.empty());
}

/**
 * @tc.name: ValidateClawCliAccess001
 * @tc.desc: Invalid claw token should fail CLI control permission check.
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(ClawPermissionDecisionEngineTest, ValidateClawCliAccess001, TestSize.Level0)
{
    std::vector<CliInfo> cliInfoList = {{
        .cliName = "camera",
        .subCliName = "capture"
    }};
    EXPECT_EQ(AccessTokenError::ERR_PERMISSION_DENIED,
        ClawPermissionDecisionEngine::GetInstance().ValidateClawCliAccess(INVALID_TOKENID, cliInfoList));
}

/**
 * @tc.name: ClawPermissionMetadataProvider001
 * @tc.desc: Metadata provider should return CLI callable permissions in input order.
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(ClawPermissionDecisionEngineTest, ClawPermissionMetadataProvider001, TestSize.Level0)
{
    std::vector<CliInfo> cliInfoList = {
        {.cliName = "camera", .subCliName = "capture"},
        {.cliName = "duplicate", .subCliName = "run"},
        {.cliName = "mixed", .subCliName = "run"},
        {.cliName = "multi", .subCliName = "run"},
        {.cliName = "location", .subCliName = "query"}
    };
    std::vector<std::vector<std::string>> cliPermissions;
    ASSERT_EQ(RET_SUCCESS, ClawPermissionMetadataProvider::GetInstance().GetCliCallablePermissions(
        cliInfoList, cliPermissions));
    ASSERT_EQ(5, static_cast<int32_t>(cliPermissions.size()));
    ASSERT_EQ(1, static_cast<int32_t>(cliPermissions[0].size()));
    EXPECT_EQ("ohos.permission.POWER_MANAGER", cliPermissions[0][0]);
    ASSERT_EQ(1, static_cast<int32_t>(cliPermissions[1].size()));
    EXPECT_EQ("ohos.permission.APPROXIMATELY_LOCATION", cliPermissions[1][0]);
    ASSERT_EQ(2, static_cast<int32_t>(cliPermissions[2].size()));
    EXPECT_EQ("ohos.permission.APPROXIMATELY_LOCATION", cliPermissions[2][0]);
    EXPECT_EQ("ohos.permission.CAMERA", cliPermissions[2][1]);
    ASSERT_EQ(2, static_cast<int32_t>(cliPermissions[3].size()));
    EXPECT_EQ("ohos.permission.APPROXIMATELY_LOCATION", cliPermissions[3][0]);
    EXPECT_EQ("ohos.permission.POWER_MANAGER", cliPermissions[3][1]);
    ASSERT_EQ(1, static_cast<int32_t>(cliPermissions[4].size()));
    EXPECT_EQ("ohos.permission.APPROXIMATELY_LOCATION", cliPermissions[4][0]);
}

/**
 * @tc.name: ClawPermissionMetadataProvider002
 * @tc.desc: Metadata provider should return ERR_PARAM_INVALID when CLI metadata queryRet is not success.
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(ClawPermissionDecisionEngineTest, ClawPermissionMetadataProvider002, TestSize.Level0)
{
    std::vector<std::string> permissions;
    EXPECT_EQ(AccessTokenError::ERR_QUERY_PERMISSION_FAILED,
        ClawPermissionMetadataProvider::GetInstance().GetRequiredCliPermissions({"", "capture"}, permissions));
    EXPECT_TRUE(permissions.empty());
    EXPECT_EQ(AccessTokenError::ERR_QUERY_PERMISSION_FAILED,
        ClawPermissionMetadataProvider::GetInstance().GetRequiredCliPermissions({"unknown", "cmd"}, permissions));
    EXPECT_TRUE(permissions.empty());
    EXPECT_EQ(AccessTokenError::ERR_PARAM_INVALID,
        ClawPermissionMetadataProvider::GetInstance().GetUsedPermissionsByCliPermission("", permissions));
    EXPECT_EQ(AccessTokenError::ERR_PERMISSION_NOT_EXIST,
        ClawPermissionMetadataProvider::GetInstance().GetUsedPermissionsByCliPermission(
            "ohos.permission.cli.unknown", permissions));
    EXPECT_TRUE(permissions.empty());
    EXPECT_EQ(RET_SUCCESS,
        ClawPermissionMetadataProvider::GetInstance().GetUsedPermissionsByCliPermission(
            "ohos.permission.CAMERA", permissions));
    ASSERT_EQ(1, static_cast<int32_t>(permissions.size()));
    EXPECT_EQ("ohos.permission.CAMERA", permissions[0]);
    EXPECT_EQ(RET_SUCCESS,
        ClawPermissionMetadataProvider::GetInstance().GetRequiredCliPermissions({"empty", "run"}, permissions));
    EXPECT_TRUE(permissions.empty());
    EXPECT_EQ(AccessTokenError::ERR_QUERY_PERMISSION_FAILED,
        ClawPermissionMetadataProvider::GetInstance().GetRequiredCliPermissions({"abnormal", "run"}, permissions));
    EXPECT_TRUE(permissions.empty());
    tokenId_ = CreateEmptyHapToken("claw_permission_cli_missing_mapping_test");
    ASSERT_NE(INVALID_TOKENID, tokenId_);
    CliPermissionsResult cliResult;
    EXPECT_EQ(AccessTokenError::ERR_PERMISSION_NOT_EXIST,
        ClawPermissionDecisionEngine::GetInstance().BuildCliPermissions(
        tokenId_, std::vector<CliInfo>{{"missingmap", "run"}}, cliResult));
}

/**
 * @tc.name: ClawPermissionMetadataProvider003
 * @tc.desc: Non-success queryRet should return ERR_QUERY_PERMISSION_FAILED.
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(ClawPermissionDecisionEngineTest, ClawPermissionMetadataProvider003, TestSize.Level0)
{
    std::vector<CliInfo> cliInfoList = {
        {.cliName = "unknown", .subCliName = "cmd"},
        {.cliName = "abnormal", .subCliName = "run"},
        {.cliName = "camera", .subCliName = "capture"},
    };
    std::vector<std::vector<std::string>> cliPermissions;
    ASSERT_EQ(AccessTokenError::ERR_QUERY_PERMISSION_FAILED,
        ClawPermissionMetadataProvider::GetInstance().GetCliCallablePermissions(
        cliInfoList, cliPermissions));
    EXPECT_TRUE(cliPermissions.empty());
}

/**
 * @tc.name: BuildCliPermissions007
 * @tc.desc: CLI with empty required permission list should return empty requiredCliPermissions.
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(ClawPermissionDecisionEngineTest, BuildCliPermissions007, TestSize.Level0)
{
    tokenId_ = CreateEmptyHapToken("claw_permission_cli_empty_result_test");
    ASSERT_NE(INVALID_TOKENID, tokenId_);

    CliPermissionsResult result;
    ASSERT_EQ(RET_SUCCESS, ClawPermissionDecisionEngine::GetInstance().BuildCliPermissions(
        tokenId_, std::vector<CliInfo>{{"empty", "run"}}, result));
    ASSERT_EQ(1, static_cast<int32_t>(result.permList.size()));
    EXPECT_TRUE(result.permList[0].requiredCliPermissions.empty());
}

/**
 * @tc.name: TransferQueryRetTest001
 * @tc.desc: Test TransferQueryRet with queryRet=1 returns ERR_PARAM_INVALID
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(ClawPermissionDecisionEngineTest, TransferQueryRetTest001, TestSize.Level2)
{
    CliInfo cliInfo = {.cliName = "test", .subCliName = "cmd"};
    int32_t ret = ClawPermissionMetadataProvider::GetInstance().TransferQueryRet(cliInfo, 1);
    EXPECT_EQ(AccessTokenError::ERR_PARAM_INVALID, ret);
}

/**
 * @tc.name: TransferQueryRetTest002
 * @tc.desc: Test TransferQueryRet with non-success non-1 queryRet returns ERR_QUERY_PERMISSION_FAILED
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(ClawPermissionDecisionEngineTest, TransferQueryRetTest002, TestSize.Level2)
{
    CliInfo cliInfo = {.cliName = "test", .subCliName = "cmd"};
    int32_t ret = ClawPermissionMetadataProvider::GetInstance().TransferQueryRet(cliInfo, -1);
    EXPECT_EQ(AccessTokenError::ERR_QUERY_PERMISSION_FAILED, ret);

    ret = ClawPermissionMetadataProvider::GetInstance().TransferQueryRet(cliInfo, 2);
    EXPECT_EQ(AccessTokenError::ERR_QUERY_PERMISSION_FAILED, ret);
}

/**
 * @tc.name: TransferQueryRetTest003
 * @tc.desc: Test TransferQueryRet with RET_SUCCESS returns ERR_QUERY_PERMISSION_FAILED
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(ClawPermissionDecisionEngineTest, TransferQueryRetTest003, TestSize.Level2)
{
    CliInfo cliInfo = {.cliName = "test", .subCliName = "cmd"};
    int32_t ret = ClawPermissionMetadataProvider::GetInstance().TransferQueryRet(cliInfo, RET_SUCCESS);
    EXPECT_EQ(AccessTokenError::ERR_QUERY_PERMISSION_FAILED, ret);
}

} // namespace AccessToken
} // namespace Security
} // namespace OHOS
