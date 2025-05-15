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

#include "set_perm_dialog_cap_test.h"
#include "gtest/gtest.h"
#include <thread>
#include <unistd.h>

#include "access_token.h"
#include "access_token_error.h"
#include "accesstoken_common_log.h"
#include "permission_grant_info.h"
#include "permission_state_change_info_parcel.h"
#include "string_ex.h"
#include "test_common.h"
#include "tokenid_kit.h"
#include "token_setproc.h"

using namespace testing::ext;
namespace OHOS {
namespace Security {
namespace AccessToken {
namespace {
static uint64_t g_selfTokenId = 0;
PermissionStateFull g_permTestState = {
    .permissionName = "ohos.permission.LOCATION",
    .isGeneral = true,
    .resDeviceID = {"local"},
    .grantStatus = {PermissionState::PERMISSION_DENIED},
    .grantFlags = {PermissionFlag::PERMISSION_DEFAULT_FLAG},
};

HapInfoParams g_infoManager = {
    .userID = 1,
    .bundleName = "accesstoken_test",
    .instIndex = 0,
    .appIDDesc = "test2",
    .apiVersion = 8  // 8: api version
};

HapPolicyParams g_policy = {
    .apl = APL_NORMAL,
    .domain = "domain",
    .permStateList = {g_permTestState}
};
}

void SetPermDialogCapTest::SetUpTestCase()
{
    g_selfTokenId = GetSelfTokenID();
    TestCommon::SetTestEvironment(g_selfTokenId);
}

void SetPermDialogCapTest::TearDownTestCase()
{
    SetSelfTokenID(g_selfTokenId);
    TestCommon::ResetTestEvironment();
}

void SetPermDialogCapTest::SetUp()
{
}

void SetPermDialogCapTest::TearDown()
{
}

/**
 * @tc.name: SetPermDialogCapAbnormalTest001
 * @tc.desc: Set permission dialog capability with noexist app.
 * @tc.type: FUNC
 * @tc.require: Issue Number
 */
HWTEST_F(SetPermDialogCapTest, SetPermDialogCapAbnormalTest001, TestSize.Level0)
{
    std::vector<std::string> reqPerm;
    reqPerm.emplace_back("ohos.permission.DISABLE_PERMISSION_DIALOG");
    MockHapToken mock("SetPermDialogCapAbnormalTest001", reqPerm, true);

    LOGI(ATM_DOMAIN, ATM_TAG, "SetPermDialogCapAbnormalTest001");
    HapBaseInfo hapBaseInfo = {
        .userID = 111, // 111: user id
        .bundleName = "noexist bundle",
        .instIndex = 0,
    };

    HapTokenInfo hapInfo;
    ASSERT_EQ(ERR_TOKENID_NOT_EXIST, AccessTokenKit::SetPermDialogCap(hapBaseInfo, true));
}

/**
 * @tc.name: SetPermDialogCapFuncTest001
 * @tc.desc: Set permission dialog capability, and get set permissionState.
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(SetPermDialogCapTest, SetPermDialogCapFuncTest001, TestSize.Level0)
{
    std::vector<std::string> reqPerm;
    reqPerm.emplace_back("ohos.permission.DISABLE_PERMISSION_DIALOG");
    MockHapToken mock("SetPermDialogCapFuncTest001", reqPerm, true);
    uint64_t selfToken = GetSelfTokenID();

    LOGI(ATM_DOMAIN, ATM_TAG, "SetPermDialogCapFuncTest001");
    AccessTokenIDEx tokenIdEx = {0};
    ASSERT_EQ(RET_SUCCESS, TestCommon::AllocTestHapToken(g_infoManager, g_policy, tokenIdEx));
    ASSERT_NE(INVALID_TOKENID, tokenIdEx.tokenIDEx);
    HapBaseInfo hapBaseInfo = {
        .userID = g_infoManager.userID,
        .bundleName = g_infoManager.bundleName,
        .instIndex = g_infoManager.instIndex,
    };

    std::vector<PermissionListState> permsList;
    PermissionListState tmp = {
        .permissionName = g_policy.permStateList[0].permissionName,
        .state = PASS_OPER
    };
    permsList.emplace_back(tmp);

    // test dialog is forbiddedn
    EXPECT_EQ(RET_SUCCESS, AccessTokenKit::SetPermDialogCap(hapBaseInfo, true));
    EXPECT_EQ(RET_SUCCESS, SetSelfTokenID(tokenIdEx.tokenIDEx));
    PermissionGrantInfo info;
    EXPECT_EQ(FORBIDDEN_OPER, AccessTokenKit::GetSelfPermissionsState(permsList, info));
    EXPECT_EQ(RET_SUCCESS, SetSelfTokenID(selfToken));

    // test dialog is not forbiddedn
    EXPECT_EQ(RET_SUCCESS, AccessTokenKit::SetPermDialogCap(hapBaseInfo, false));
    EXPECT_EQ(RET_SUCCESS, SetSelfTokenID(tokenIdEx.tokenIDEx));
    ASSERT_NE(FORBIDDEN_OPER, AccessTokenKit::GetSelfPermissionsState(permsList, info));
    EXPECT_EQ(RET_SUCCESS, SetSelfTokenID(selfToken));

    EXPECT_EQ(RET_SUCCESS, TestCommon::DeleteTestHapToken(tokenIdEx.tokenIdExStruct.tokenID));
}
} // namespace AccessToken
} // namespace Security
} // namespace OHOS