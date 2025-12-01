/*
 * Copyright (c) 2025 Huawei Device Co., Ltd.
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
#include "get_self_permission_status_test.h"
#include "access_token_error.h"
#include "nativetoken_kit.h"
#include "test_common.h"
#include "token_setproc.h"

namespace OHOS {
namespace Security {
namespace AccessToken {
using namespace testing::ext;
namespace {
static const std::string TEST_BUNDLE_NAME = "ohos";
static const int TEST_USER_ID = 0;
static const std::string APPROXIMATELY_LOCATION_PERMISSION = "ohos.permission.APPROXIMATELY_LOCATION";
static const std::string LOCATION_PERMISSION = "ohos.permission.LOCATION";

PermissionStateFull g_permTestState1 = {
    .permissionName = APPROXIMATELY_LOCATION_PERMISSION,
    .isGeneral = true,
    .resDeviceID = {"local"},
    .grantStatus = {PermissionState::PERMISSION_DENIED},
    .grantFlags = {PermissionFlag::PERMISSION_DEFAULT_FLAG},
};

PermissionStateFull g_permTestState2 = {
    .permissionName = "ohos.permission.MICROPHONE",
    .isGeneral = true,
    .resDeviceID = {"local"},
    .grantStatus = {PermissionState::PERMISSION_DENIED},
    .grantFlags = {PermissionFlag::PERMISSION_USER_SET}
};

PermissionStateFull g_permTestState3 = {
    .permissionName = "ohos.permission.WRITE_CALENDAR",
    .isGeneral = true,
    .resDeviceID = {"local"},
    .grantStatus = {PermissionState::PERMISSION_DENIED},
    .grantFlags = {PermissionFlag::PERMISSION_USER_FIXED}
};

PermissionStateFull g_permTestState4 = {
    .permissionName = "ohos.permission.READ_IMAGEVIDEO",
    .isGeneral = true,
    .resDeviceID = {"local"},
    .grantStatus = {PermissionState::PERMISSION_GRANTED},
    .grantFlags = {PermissionFlag::PERMISSION_USER_SET}
};

PermissionStateFull g_permTestState5 = {
    .permissionName = LOCATION_PERMISSION,
    .isGeneral = true,
    .resDeviceID = {"local"},
    .grantStatus = {PermissionState::PERMISSION_DENIED},
    .grantFlags = {PermissionFlag::PERMISSION_DEFAULT_FLAG},
};

PermissionStateFull g_permTestState6 = {
    .permissionName = "ohos.permission.READ_CALENDAR",
    .isGeneral = true,
    .resDeviceID = {"local"},
    .grantStatus = {PermissionState::PERMISSION_DENIED},
    .grantFlags = {PermissionFlag::PERMISSION_DEFAULT_FLAG},
};

HapPolicyParams g_policy = {
    .apl = APL_NORMAL,
    .domain = "domain",
    .permStateList = {g_permTestState1, g_permTestState2, g_permTestState3, g_permTestState4, g_permTestState5,
        g_permTestState6}
};

static uint64_t g_selfTokenId = 0;
}

void GetSelfPermissionStatusTest::SetUpTestCase()
{
    g_selfTokenId = GetSelfTokenID();
    TestCommon::SetTestEvironment(g_selfTokenId);
}

void GetSelfPermissionStatusTest::TearDownTestCase()
{
    ASSERT_EQ(RET_SUCCESS, SetSelfTokenID(g_selfTokenId));
    TestCommon::ResetTestEvironment();
}

void GetSelfPermissionStatusTest::SetUp()
{
    HapInfoParams info = {
        .userID = TEST_USER_ID,
        .bundleName = TEST_BUNDLE_NAME,
        .instIndex = 0,
        .appIDDesc = "appIDDesc",
        .apiVersion = 20 // 20: api version
    };

    AccessTokenIDEx tokenIdEx = TestCommon::AllocAndGrantHapTokenByTest(info, g_policy);
    AccessTokenID tokenId = tokenIdEx.tokenIdExStruct.tokenID;
    ASSERT_NE(tokenId, INVALID_TOKENID);
    ASSERT_EQ(RET_SUCCESS, SetSelfTokenID(tokenIdEx.tokenIDEx));
}

void GetSelfPermissionStatusTest::TearDown()
{
    AccessTokenIDEx tokenIdEx = TestCommon::GetHapTokenIdFromBundle(TEST_USER_ID, TEST_BUNDLE_NAME, 0);
    AccessTokenID tokenId = tokenIdEx.tokenIdExStruct.tokenID;
    if (tokenId != INVALID_TOKENID) {
        EXPECT_EQ(RET_SUCCESS, TestCommon::DeleteTestHapToken(tokenId));
    }
}

/**
 * @tc.name: GetSelfPermissionStatus001
 * @tc.desc: default permission status
 * @tc.type: FUNC
 * @tc.require: Issue Number
 */
HWTEST_F(GetSelfPermissionStatusTest, GetSelfPermissionStatus001, TestSize.Level0)
{
    AccessTokenIDEx tokenIdEx = TestCommon::GetHapTokenIdFromBundle(TEST_USER_ID, TEST_BUNDLE_NAME, 0);
    AccessTokenID tokenID = tokenIdEx.tokenIdExStruct.tokenID;
    ASSERT_NE(INVALID_TOKENID, tokenID);

    // default flag, user not operation
    PermissionOper status;
    int32_t ret = AccessTokenKit::GetSelfPermissionStatus(APPROXIMATELY_LOCATION_PERMISSION, status);
    EXPECT_EQ(RET_SUCCESS, ret);
    EXPECT_EQ(DYNAMIC_OPER, status);

    // user set DENIED
    ret = AccessTokenKit::GetSelfPermissionStatus("ohos.permission.MICROPHONE", status);
    EXPECT_EQ(RET_SUCCESS, ret);
    EXPECT_EQ(DYNAMIC_OPER, status);

    // user fixed DENIED
    ret = AccessTokenKit::GetSelfPermissionStatus("ohos.permission.WRITE_CALENDAR", status);
    EXPECT_EQ(RET_SUCCESS, ret);
    EXPECT_EQ(SETTING_OPER, status);

    // user set GRANTED
    ret = AccessTokenKit::GetSelfPermissionStatus("ohos.permission.READ_IMAGEVIDEO", status);
    EXPECT_EQ(RET_SUCCESS, ret);
    EXPECT_EQ(PASS_OPER, status);

    // not request permission CAMERA
    ret = AccessTokenKit::GetSelfPermissionStatus("ohos.permission.CAMERA", status);
    EXPECT_EQ(RET_SUCCESS, ret);
    EXPECT_EQ(INVALID_OPER, status);
}

/**
 * @tc.name: GetSelfPermissionStatus002
 * @tc.desc: forbidden permission status
 * @tc.type: FUNC
 * @tc.require: Issue Number
 */
HWTEST_F(GetSelfPermissionStatusTest, GetSelfPermissionStatus002, TestSize.Level0)
{
    AccessTokenIDEx tokenIdEx = TestCommon::GetHapTokenIdFromBundle(TEST_USER_ID, TEST_BUNDLE_NAME, 0);
    AccessTokenID tokenID = tokenIdEx.tokenIdExStruct.tokenID;
    ASSERT_NE(INVALID_TOKENID, tokenID);

    {
        std::vector<std::string> reqPerm;
        reqPerm.emplace_back("ohos.permission.DISABLE_PERMISSION_DIALOG");
        MockHapToken mock("GetSelfPermissionStatus002", reqPerm, true);

        HapBaseInfo hapBaseInfo = {
            .userID = TEST_USER_ID,
            .bundleName = TEST_BUNDLE_NAME,
            .instIndex = 0,
        };

        ASSERT_EQ(0, AccessTokenKit::SetPermDialogCap(hapBaseInfo, true));
    }

    // default flag, user not operation
    PermissionOper status;
    int32_t ret = AccessTokenKit::GetSelfPermissionStatus(APPROXIMATELY_LOCATION_PERMISSION, status);
    EXPECT_EQ(RET_SUCCESS, ret);
    EXPECT_EQ(FORBIDDEN_OPER, status);

    // user set DENIED
    ret = AccessTokenKit::GetSelfPermissionStatus("ohos.permission.MICROPHONE", status);
    EXPECT_EQ(RET_SUCCESS, ret);
    EXPECT_EQ(FORBIDDEN_OPER, status);

    // user fixed DENIED
    ret = AccessTokenKit::GetSelfPermissionStatus("ohos.permission.WRITE_CALENDAR", status);
    EXPECT_EQ(RET_SUCCESS, ret);
    EXPECT_EQ(FORBIDDEN_OPER, status);

    // user set GRANTED
    ret = AccessTokenKit::GetSelfPermissionStatus("ohos.permission.READ_IMAGEVIDEO", status);
    EXPECT_EQ(RET_SUCCESS, ret);
    EXPECT_EQ(FORBIDDEN_OPER, status);

    // not request permission CAMERA
    ret = AccessTokenKit::GetSelfPermissionStatus("ohos.permission.CAMERA", status);
    EXPECT_EQ(RET_SUCCESS, ret);
    EXPECT_EQ(INVALID_OPER, status);
}

/**
 * @tc.name: GetSelfPermissionStatus003
 * @tc.desc: grant permission status
 * @tc.type: FUNC
 * @tc.require: Issue Number
 */
HWTEST_F(GetSelfPermissionStatusTest, GetSelfPermissionStatus003, TestSize.Level0)
{
    AccessTokenIDEx tokenIdEx = TestCommon::GetHapTokenIdFromBundle(TEST_USER_ID, TEST_BUNDLE_NAME, 0);
    AccessTokenID tokenID = tokenIdEx.tokenIdExStruct.tokenID;
    ASSERT_NE(INVALID_TOKENID, tokenID);

    {
        std::vector<std::string> reqPerm;
        reqPerm.emplace_back("ohos.permission.GRANT_SENSITIVE_PERMISSIONS");
        MockHapToken mock("GetSelfPermissionStatus003", reqPerm, true);

        // grant user set
        ASSERT_EQ(0, AccessTokenKit::GrantPermission(tokenID, APPROXIMATELY_LOCATION_PERMISSION, PERMISSION_USER_SET));
    }

    // grant permission
    PermissionOper status;
    int32_t ret = AccessTokenKit::GetSelfPermissionStatus(APPROXIMATELY_LOCATION_PERMISSION, status);
    EXPECT_EQ(RET_SUCCESS, ret);
    EXPECT_EQ(PASS_OPER, status);

    // user set DENIED
    ret = AccessTokenKit::GetSelfPermissionStatus("ohos.permission.MICROPHONE", status);
    EXPECT_EQ(RET_SUCCESS, ret);
    EXPECT_EQ(DYNAMIC_OPER, status);

    // user fixed DENIED
    ret = AccessTokenKit::GetSelfPermissionStatus("ohos.permission.WRITE_CALENDAR", status);
    EXPECT_EQ(RET_SUCCESS, ret);
    EXPECT_EQ(SETTING_OPER, status);

    // user set GRANTED
    ret = AccessTokenKit::GetSelfPermissionStatus("ohos.permission.READ_IMAGEVIDEO", status);
    EXPECT_EQ(RET_SUCCESS, ret);
    EXPECT_EQ(PASS_OPER, status);

    // not request permission CAMERA
    ret = AccessTokenKit::GetSelfPermissionStatus("ohos.permission.CAMERA", status);
    EXPECT_EQ(RET_SUCCESS, ret);
    EXPECT_EQ(INVALID_OPER, status);
}

/**
 * @tc.name: GetSelfPermissionStatus004
 * @tc.desc: revoke user set permission status
 * @tc.type: FUNC
 * @tc.require: Issue Number
 */
HWTEST_F(GetSelfPermissionStatusTest, GetSelfPermissionStatus004, TestSize.Level0)
{
    AccessTokenIDEx tokenIdEx = TestCommon::GetHapTokenIdFromBundle(TEST_USER_ID, TEST_BUNDLE_NAME, 0);
    AccessTokenID tokenID = tokenIdEx.tokenIdExStruct.tokenID;
    ASSERT_NE(INVALID_TOKENID, tokenID);

    {
        std::vector<std::string> reqPerm;
        reqPerm.emplace_back("ohos.permission.REVOKE_SENSITIVE_PERMISSIONS");
        MockHapToken mock("GetSelfPermissionStatus004", reqPerm, true);

        // revoke user set
        ASSERT_EQ(0, AccessTokenKit::RevokePermission(tokenID, "ohos.permission.READ_IMAGEVIDEO", PERMISSION_USER_SET));
    }

    // default flag, user not operation
    PermissionOper status;
    int32_t ret = AccessTokenKit::GetSelfPermissionStatus(APPROXIMATELY_LOCATION_PERMISSION, status);
    EXPECT_EQ(RET_SUCCESS, ret);
    EXPECT_EQ(DYNAMIC_OPER, status);

    // user set DENIED
    ret = AccessTokenKit::GetSelfPermissionStatus("ohos.permission.MICROPHONE", status);
    EXPECT_EQ(RET_SUCCESS, ret);
    EXPECT_EQ(DYNAMIC_OPER, status);

    // user fixed DENIED
    ret = AccessTokenKit::GetSelfPermissionStatus("ohos.permission.WRITE_CALENDAR", status);
    EXPECT_EQ(RET_SUCCESS, ret);
    EXPECT_EQ(SETTING_OPER, status);

    // revoke user set
    ret = AccessTokenKit::GetSelfPermissionStatus("ohos.permission.READ_IMAGEVIDEO", status);
    EXPECT_EQ(RET_SUCCESS, ret);
    EXPECT_EQ(DYNAMIC_OPER, status);

    // not request permission CAMERA
    ret = AccessTokenKit::GetSelfPermissionStatus("ohos.permission.CAMERA", status);
    EXPECT_EQ(RET_SUCCESS, ret);
    EXPECT_EQ(INVALID_OPER, status);
}

/**
 * @tc.name: GetSelfPermissionStatus005
 * @tc.desc: revoke user fixed permission status
 * @tc.type: FUNC
 * @tc.require: Issue Number
 */
HWTEST_F(GetSelfPermissionStatusTest, GetSelfPermissionStatus005, TestSize.Level0)
{
    AccessTokenIDEx tokenIdEx = TestCommon::GetHapTokenIdFromBundle(TEST_USER_ID, TEST_BUNDLE_NAME, 0);
    AccessTokenID tokenID = tokenIdEx.tokenIdExStruct.tokenID;
    ASSERT_NE(INVALID_TOKENID, tokenID);

    {
        std::vector<std::string> reqPerm;
        reqPerm.emplace_back("ohos.permission.REVOKE_SENSITIVE_PERMISSIONS");
        MockHapToken mock("GetSelfPermissionStatus005", reqPerm, true);

        // revoke user fixed
        ASSERT_EQ(0,
            AccessTokenKit::RevokePermission(tokenID, "ohos.permission.READ_IMAGEVIDEO", PERMISSION_USER_FIXED));
    }

    // default flag, user not operation
    PermissionOper status;
    int32_t ret = AccessTokenKit::GetSelfPermissionStatus(APPROXIMATELY_LOCATION_PERMISSION, status);
    EXPECT_EQ(RET_SUCCESS, ret);
    EXPECT_EQ(DYNAMIC_OPER, status);

    // user set DENIED
    ret = AccessTokenKit::GetSelfPermissionStatus("ohos.permission.MICROPHONE", status);
    EXPECT_EQ(RET_SUCCESS, ret);
    EXPECT_EQ(DYNAMIC_OPER, status);

    // user fixed DENIED
    ret = AccessTokenKit::GetSelfPermissionStatus("ohos.permission.WRITE_CALENDAR", status);
    EXPECT_EQ(RET_SUCCESS, ret);
    EXPECT_EQ(SETTING_OPER, status);

    // revoke user fixed
    ret = AccessTokenKit::GetSelfPermissionStatus("ohos.permission.READ_IMAGEVIDEO", status);
    EXPECT_EQ(RET_SUCCESS, ret);
    EXPECT_EQ(SETTING_OPER, status);

    // not request permission CAMERA
    ret = AccessTokenKit::GetSelfPermissionStatus("ohos.permission.CAMERA", status);
    EXPECT_EQ(RET_SUCCESS, ret);
    EXPECT_EQ(INVALID_OPER, status);
}

/**
 * @tc.name: GetSelfPermissionStatus006
 * @tc.desc: invalid permission
 * @tc.type: FUNC
 * @tc.require: Issue Number
 */
HWTEST_F(GetSelfPermissionStatusTest, GetSelfPermissionStatus006, TestSize.Level0)
{
    AccessTokenIDEx tokenIdEx = TestCommon::GetHapTokenIdFromBundle(TEST_USER_ID, TEST_BUNDLE_NAME, 0);
    AccessTokenID tokenID = tokenIdEx.tokenIdExStruct.tokenID;
    ASSERT_NE(INVALID_TOKENID, tokenID);

    PermissionOper status;
    // invalid permission
    int32_t ret = AccessTokenKit::GetSelfPermissionStatus("ohos.permission.TTTTT", status);
    EXPECT_EQ(RET_SUCCESS, ret);
    EXPECT_EQ(INVALID_OPER, status);

    // not request permission
    ret = AccessTokenKit::GetSelfPermissionStatus("ohos.permission.ACCESS_NEARLINK", status);
    EXPECT_EQ(RET_SUCCESS, ret);
    EXPECT_EQ(INVALID_OPER, status);

    // empty permission
    std::string testPerm1;
    ret = AccessTokenKit::GetSelfPermissionStatus(testPerm1, status);
    EXPECT_EQ(ERR_PARAM_INVALID, ret);

    // oversize permission
    std::string testPerm2(257, 'a');
    ret = AccessTokenKit::GetSelfPermissionStatus(testPerm2, status);
    EXPECT_EQ(ERR_PARAM_INVALID, ret);
}

/**
 * @tc.name: GetSelfPermissionStatus007
 * @tc.desc: location permission test
 * @tc.type: FUNC
 * @tc.require: Issue Number
 */
HWTEST_F(GetSelfPermissionStatusTest, GetSelfPermissionStatus007, TestSize.Level0)
{
    AccessTokenIDEx tokenIdEx = TestCommon::GetHapTokenIdFromBundle(TEST_USER_ID, TEST_BUNDLE_NAME, 0);
    AccessTokenID tokenID = tokenIdEx.tokenIdExStruct.tokenID;
    ASSERT_NE(INVALID_TOKENID, tokenID);

    // default flag, user not operation
    PermissionOper status;
    int32_t ret = AccessTokenKit::GetSelfPermissionStatus(APPROXIMATELY_LOCATION_PERMISSION, status);
    EXPECT_EQ(RET_SUCCESS, ret);
    EXPECT_EQ(DYNAMIC_OPER, status);

    // APPROXIMATELY_LOCATION not set, LOCATION status is INVALID_OPER
    ret = AccessTokenKit::GetSelfPermissionStatus(LOCATION_PERMISSION, status);
    EXPECT_EQ(RET_SUCCESS, ret);
    EXPECT_EQ(INVALID_OPER, status);

    {
        std::vector<std::string> reqPerm;
        reqPerm.emplace_back("ohos.permission.GRANT_SENSITIVE_PERMISSIONS");
        MockHapToken mock("GetSelfPermissionStatus0071", reqPerm, true);

        // grant user set
        ASSERT_EQ(0, AccessTokenKit::GrantPermission(tokenID, APPROXIMATELY_LOCATION_PERMISSION, PERMISSION_USER_SET));
    }

    // grant permission
    ret = AccessTokenKit::GetSelfPermissionStatus(APPROXIMATELY_LOCATION_PERMISSION, status);
    EXPECT_EQ(RET_SUCCESS, ret);
    EXPECT_EQ(PASS_OPER, status);

    // APPROXIMATELY_LOCATION already set, LOCATION status is DYNAMIC_OPER
    ret = AccessTokenKit::GetSelfPermissionStatus(LOCATION_PERMISSION, status);
    EXPECT_EQ(RET_SUCCESS, ret);
    EXPECT_EQ(DYNAMIC_OPER, status);

    {
        std::vector<std::string> reqPerm;
        reqPerm.emplace_back("ohos.permission.GRANT_SENSITIVE_PERMISSIONS");
        MockHapToken mock("GetSelfPermissionStatus0072", reqPerm, true);

        // grant user set
        ASSERT_EQ(0, AccessTokenKit::GrantPermission(tokenID, LOCATION_PERMISSION, PERMISSION_USER_SET));
    }

    // grant permission
    ret = AccessTokenKit::GetSelfPermissionStatus(LOCATION_PERMISSION, status);
    EXPECT_EQ(RET_SUCCESS, ret);
    EXPECT_EQ(PASS_OPER, status);
}

/**
 * @tc.name: GetSelfPermissionStatus008
 * @tc.desc: only change flag
 * @tc.type: FUNC
 * @tc.require: Issue Number
 */
HWTEST_F(GetSelfPermissionStatusTest, GetSelfPermissionStatus008, TestSize.Level0)
{
    AccessTokenIDEx tokenIdEx = TestCommon::GetHapTokenIdFromBundle(TEST_USER_ID, TEST_BUNDLE_NAME, 0);
    AccessTokenID tokenID = tokenIdEx.tokenIdExStruct.tokenID;
    ASSERT_NE(INVALID_TOKENID, tokenID);

    // default flag, user not operation
    PermissionOper status;
    int32_t ret = AccessTokenKit::GetSelfPermissionStatus(APPROXIMATELY_LOCATION_PERMISSION, status);
    EXPECT_EQ(RET_SUCCESS, ret);
    EXPECT_EQ(DYNAMIC_OPER, status);

    {
        std::vector<std::string> reqPerm;
        reqPerm.emplace_back("ohos.permission.GRANT_SENSITIVE_PERMISSIONS");
        MockHapToken mock("GetSelfPermissionStatus0081", reqPerm, true);

        // grant user set
        ASSERT_EQ(0, AccessTokenKit::GrantPermission(tokenID, APPROXIMATELY_LOCATION_PERMISSION, PERMISSION_USER_SET));
    }

    // grant permission
    ret = AccessTokenKit::GetSelfPermissionStatus(APPROXIMATELY_LOCATION_PERMISSION, status);
    EXPECT_EQ(RET_SUCCESS, ret);
    EXPECT_EQ(PASS_OPER, status);

    {
        std::vector<std::string> reqPerm;
        reqPerm.emplace_back("ohos.permission.REVOKE_SENSITIVE_PERMISSIONS");
        MockHapToken mock("GetSelfPermissionStatus0082", reqPerm, true);

        // revoke user fixed
        ASSERT_EQ(0, AccessTokenKit::RevokePermission(
            tokenID, APPROXIMATELY_LOCATION_PERMISSION, PERMISSION_USER_FIXED));
    }

    // revoke permission
    ret = AccessTokenKit::GetSelfPermissionStatus(APPROXIMATELY_LOCATION_PERMISSION, status);
    EXPECT_EQ(RET_SUCCESS, ret);
    EXPECT_EQ(SETTING_OPER, status);

    {
        std::vector<std::string> reqPerm;
        reqPerm.emplace_back("ohos.permission.REVOKE_SENSITIVE_PERMISSIONS");
        MockHapToken mock("GetSelfPermissionStatus0083", reqPerm, true);

        // revoke to default flag
        ASSERT_EQ(0, AccessTokenKit::RevokePermission(
            tokenID, APPROXIMATELY_LOCATION_PERMISSION, PERMISSION_DEFAULT_FLAG));
    }

    ret = AccessTokenKit::GetSelfPermissionStatus(APPROXIMATELY_LOCATION_PERMISSION, status);
    EXPECT_EQ(RET_SUCCESS, ret);
    EXPECT_EQ(DYNAMIC_OPER, status);
}

/**
 * @tc.name: GetSelfPermissionStatus009
 * @tc.desc: test permission group
 * @tc.type: FUNC
 * @tc.require: Issue Number
 */
HWTEST_F(GetSelfPermissionStatusTest, GetSelfPermissionStatus009, TestSize.Level0)
{
    AccessTokenIDEx tokenIdEx = TestCommon::GetHapTokenIdFromBundle(TEST_USER_ID, TEST_BUNDLE_NAME, 0);
    AccessTokenID tokenID = tokenIdEx.tokenIdExStruct.tokenID;
    ASSERT_NE(INVALID_TOKENID, tokenID);

    PermissionOper status;
    
    // default
    int32_t ret = AccessTokenKit::GetSelfPermissionStatus("ohos.permission.READ_CALENDAR", status);
    EXPECT_EQ(RET_SUCCESS, ret);
    EXPECT_EQ(DYNAMIC_OPER, status);

    // default denied
    ret = AccessTokenKit::GetSelfPermissionStatus("ohos.permission.WRITE_CALENDAR", status);
    EXPECT_EQ(RET_SUCCESS, ret);
    EXPECT_EQ(SETTING_OPER, status);

    {
        std::vector<std::string> reqPerm;
        reqPerm.emplace_back("ohos.permission.GRANT_SENSITIVE_PERMISSIONS");
        MockHapToken mock("GetSelfPermissionStatus009", reqPerm, true);

        // grant user set
        ASSERT_EQ(0, AccessTokenKit::GrantPermission(tokenID, "ohos.permission.WRITE_CALENDAR", PERMISSION_USER_SET));
    }

    ret = AccessTokenKit::GetSelfPermissionStatus("ohos.permission.READ_CALENDAR", status);
    EXPECT_EQ(RET_SUCCESS, ret);
    EXPECT_EQ(DYNAMIC_OPER, status);

    // no change
    ret = AccessTokenKit::GetSelfPermissionStatus("ohos.permission.WRITE_CALENDAR", status);
    EXPECT_EQ(RET_SUCCESS, ret);
    EXPECT_EQ(PASS_OPER, status);
}

/**
 * @tc.name: GetSelfPermissionStatusWithManualTest001
 * @tc.desc: GetSelfPermissionStatus with MANUAL_SETTINGS permission
 * @tc.type: FUNC
 * @tc.require: Issue Number
 */
HWTEST_F(GetSelfPermissionStatusTest, GetSelfPermissionStatusWithManualTest001, TestSize.Level0)
{
    AccessTokenIDEx fullTokenId;
    AccessTokenID tokenID;
    {
        MockNativeToken mock("foundation");

        HapInfoParams infoParams;
        HapPolicyParams policyParams;
        TestCommon::GetHapParams(infoParams, policyParams);
        policyParams.apl = APL_NORMAL;
        TestCommon::TestPrepareManualPermissionStatus(policyParams);

        ASSERT_EQ(RET_SUCCESS, AccessTokenKit::InitHapToken(infoParams, policyParams, fullTokenId));
        tokenID = fullTokenId.tokenIdExStruct.tokenID;
        ASSERT_NE(INVALID_TOKENID, tokenID);
    }

    EXPECT_EQ(0, SetSelfTokenID(tokenID));
    PermissionOper status;
    int32_t ret = AccessTokenKit::GetSelfPermissionStatus("ohos.permission.MANUAL_ATM_SELF_USE", status);
    EXPECT_EQ(RET_SUCCESS, ret);
    EXPECT_EQ(INVALID_OPER, status);

    {
        std::vector<std::string> reqPerm;
        reqPerm.emplace_back("ohos.permission.GRANT_SENSITIVE_PERMISSIONS");
        MockHapToken mock("GetSelfPermissionStatusWithManualTest0012", reqPerm, true);

        // grant MANUAL_SETTINGS permission
        ASSERT_EQ(0, AccessTokenKit::GrantPermission(
            tokenID, "ohos.permission.MANUAL_ATM_SELF_USE", PERMISSION_USER_SET, OPERABLE_PERM));
    }

    EXPECT_EQ(0, SetSelfTokenID(tokenID));
    ret = AccessTokenKit::GetSelfPermissionStatus("ohos.permission.MANUAL_ATM_SELF_USE", status);
    EXPECT_EQ(RET_SUCCESS, ret);
    EXPECT_EQ(PASS_OPER, status);

    EXPECT_EQ(RET_SUCCESS, TestCommon::DeleteTestHapToken(tokenID));
}
} // namespace AccessToken
} // namespace Security
} // namespace OHOS
