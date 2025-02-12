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

#include "get_permissions_status_test.h"
#include "gtest/gtest.h"
#include <thread>
#include <unistd.h>

#include "access_token.h"
#include "access_token_error.h"
#include "accesstoken_common_log.h"
#include "accesstoken_service_ipc_interface_code.h"
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
static AccessTokenID g_selfTokenId = 0;
static const std::string TEST_BUNDLE_NAME = "ohos";
static const int TEST_USER_ID = 0;
static constexpr int32_t DEFAULT_API_VERSION = 8;
static constexpr int32_t TOKENID_NOT_EXIST = 123;
static const std::string TEST_PERMISSION_NAME_BETA = "ohos.permission.BETA";
HapInfoParams g_infoManagerTestNormalInfoParms = TestCommon::GetInfoManagerTestNormalInfoParms();
HapInfoParams g_infoManagerTestSystemInfoParms = TestCommon::GetInfoManagerTestSystemInfoParms();
HapInfoParams g_infoManagerTestInfoParms = TestCommon::GetInfoManagerTestInfoParms();
HapPolicyParams g_infoManagerTestPolicyPrams = TestCommon::GetInfoManagerTestPolicyPrams();
};

void GetPermissionsStatusTest::SetUpTestCase()
{
    g_selfTokenId = GetSelfTokenID();

    // clean up test cases
    AccessTokenID tokenId = AccessTokenKit::GetHapTokenID(g_infoManagerTestInfoParms.userID,
                                                          g_infoManagerTestInfoParms.bundleName,
                                                          g_infoManagerTestInfoParms.instIndex);
    AccessTokenKit::DeleteToken(tokenId);

    tokenId = AccessTokenKit::GetHapTokenID(g_infoManagerTestNormalInfoParms.userID,
                                            g_infoManagerTestNormalInfoParms.bundleName,
                                            g_infoManagerTestNormalInfoParms.instIndex);
    AccessTokenKit::DeleteToken(tokenId);

    tokenId = AccessTokenKit::GetHapTokenID(g_infoManagerTestSystemInfoParms.userID,
                                            g_infoManagerTestSystemInfoParms.bundleName,
                                            g_infoManagerTestSystemInfoParms.instIndex);
    AccessTokenKit::DeleteToken(tokenId);

    tokenId = AccessTokenKit::GetHapTokenID(TEST_USER_ID, TEST_BUNDLE_NAME, 0);
    AccessTokenKit::DeleteToken(tokenId);

    TestCommon::GetNativeTokenTest();
}

void GetPermissionsStatusTest::TearDownTestCase()
{
    SetSelfTokenID(g_selfTokenId);
}

void PreparePermStateListExt1(HapPolicyParams &policy)
{
    PermissionStateFull permStatBeta = {
        .permissionName = "ohos.permission.BETA",
        .isGeneral = true,
        .resDeviceID = {"device"},
        .grantStatus = {PermissionState::PERMISSION_GRANTED},
        .grantFlags = {PermissionFlag::PERMISSION_SYSTEM_FIXED}
    };

    PermissionStateFull permTestState5 = {
        .permissionName = "ohos.permission.GET_SENSITIVE_PERMISSIONS",
        .isGeneral = true,
        .resDeviceID = {"local"},
        .grantStatus = {PermissionState::PERMISSION_GRANTED},
        .grantFlags = {PermissionFlag::PERMISSION_SYSTEM_FIXED}
    };

    PermissionStateFull permTestState6 = {
        .permissionName = "ohos.permission.DISABLE_PERMISSION_DIALOG",
        .isGeneral = true,
        .resDeviceID = {"local"},
        .grantStatus = {PermissionState::PERMISSION_GRANTED},
        .grantFlags = {PermissionFlag::PERMISSION_SYSTEM_FIXED}
    };
    policy.permStateList.emplace_back(permStatBeta);
    policy.permStateList.emplace_back(permTestState5);
    policy.permStateList.emplace_back(permTestState6);
}

void PreparePermStateList1(HapPolicyParams &policy)
{
    PermissionStateFull permTestState1 = {
        .permissionName = "ohos.permission.LOCATION",
        .isGeneral = true,
        .resDeviceID = {"local"},
        .grantStatus = {PermissionState::PERMISSION_DENIED},
        .grantFlags = {PermissionFlag::PERMISSION_DEFAULT_FLAG},
    };

    PermissionStateFull permTestState3 = {
        .permissionName = "ohos.permission.WRITE_CALENDAR",
        .isGeneral = true,
        .resDeviceID = {"local"},
        .grantStatus = {PermissionState::PERMISSION_DENIED},
        .grantFlags = {PermissionFlag::PERMISSION_USER_FIXED}
    };

    policy.permStateList.emplace_back(permTestState1);
    policy.permStateList.emplace_back(permTestState3);
    PreparePermStateListExt1(policy);
}

void PreparePermDefList1(HapPolicyParams &policy)
{
    PermissionDef permissionDefBeta;
    permissionDefBeta.permissionName = "ohos.permission.BETA";
    permissionDefBeta.bundleName = TEST_BUNDLE_NAME;
    permissionDefBeta.grantMode = GrantMode::SYSTEM_GRANT;
    permissionDefBeta.availableLevel = APL_NORMAL;
    permissionDefBeta.provisionEnable = false;
    permissionDefBeta.distributedSceneEnable = false;

    policy.permList.emplace_back(permissionDefBeta);
}

void GetPermissionsStatusTest::SetUp()
{
    selfTokenId_ = GetSelfTokenID();
    HapInfoParams info = {
        .userID = TEST_USER_ID,
        .bundleName = TEST_BUNDLE_NAME,
        .instIndex = 0,
        .appIDDesc = "appIDDesc",
        .apiVersion = DEFAULT_API_VERSION,
        .isSystemApp = true
    };

    HapPolicyParams policy = {
        .apl = APL_NORMAL,
        .domain = "domain"
    };
    PreparePermDefList1(policy);
    PreparePermStateList1(policy);
    AccessTokenKit::AllocHapToken(info, policy);
    AccessTokenID tokenID = AccessTokenKit::GetHapTokenID(g_infoManagerTestInfoParms.userID,
                                                          g_infoManagerTestInfoParms.bundleName,
                                                          g_infoManagerTestInfoParms.instIndex);
    AccessTokenKit::DeleteToken(tokenID);
}

void GetPermissionsStatusTest::TearDown()
{
    AccessTokenID tokenId = AccessTokenKit::GetHapTokenID(TEST_USER_ID, TEST_BUNDLE_NAME, 0);
    AccessTokenKit::DeleteToken(tokenId);
    tokenId = AccessTokenKit::GetHapTokenID(g_infoManagerTestNormalInfoParms.userID,
                                            g_infoManagerTestNormalInfoParms.bundleName,
                                            g_infoManagerTestNormalInfoParms.instIndex);
    AccessTokenKit::DeleteToken(tokenId);

    tokenId = AccessTokenKit::GetHapTokenID(g_infoManagerTestSystemInfoParms.userID,
                                            g_infoManagerTestSystemInfoParms.bundleName,
                                            g_infoManagerTestSystemInfoParms.instIndex);
    AccessTokenKit::DeleteToken(tokenId);
    EXPECT_EQ(0, SetSelfTokenID(selfTokenId_));
}

/**
 * @tc.name: GetPermissionsStatusFuncTest001
 * @tc.desc: get different permissions status
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(GetPermissionsStatusTest, GetPermissionsStatusFuncTest001, TestSize.Level1)
{
    AccessTokenIDEx tokenIDEx = AccessTokenKit::GetHapTokenIDEx(TEST_USER_ID, TEST_BUNDLE_NAME, 0);
    AccessTokenID tokenID = tokenIDEx.tokenIdExStruct.tokenID;
    ASSERT_NE(INVALID_TOKENID, tokenID);
    EXPECT_EQ(0, SetSelfTokenID(tokenIDEx.tokenIDEx));

    std::vector<PermissionListState> permsList;
    PermissionListState tmpA = {
        .permissionName = "ohos.permission.LOCATION",
        .state = SETTING_OPER
    };
    PermissionListState tmpB = {
        .permissionName = "ohos.permission.WRITE_CALENDAR",
        .state = SETTING_OPER
    };
    PermissionListState tmpC = {
        .permissionName = "ohos.permission.BETA",
        .state = SETTING_OPER
    };
    PermissionListState tmpD = {
        .permissionName = "ohos.permission.xxx",
        .state = SETTING_OPER
    };
    PermissionListState tmpE = {
        .permissionName = "ohos.permission.CAMERA",
        .state = SETTING_OPER
    };

    permsList.emplace_back(tmpA);
    permsList.emplace_back(tmpB);
    permsList.emplace_back(tmpC);
    permsList.emplace_back(tmpD);
    permsList.emplace_back(tmpE);
    ASSERT_EQ(RET_SUCCESS, AccessTokenKit::GetPermissionsStatus(tokenID, permsList));
    ASSERT_EQ(DYNAMIC_OPER, permsList[0].state);
    ASSERT_EQ(SETTING_OPER, permsList[1].state);
    ASSERT_EQ(INVALID_OPER, permsList[2].state);
    ASSERT_EQ(INVALID_OPER, permsList[3].state);
    ASSERT_EQ(INVALID_OPER, permsList[4].state);
}

/**
 * @tc.name: GetPermissionsStatusFuncTest002
 * @tc.desc: get different permissions status after set perm dialog cap
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(GetPermissionsStatusTest, GetPermissionsStatusFuncTest002, TestSize.Level1)
{
    AccessTokenIDEx tokenIDEx = AccessTokenKit::GetHapTokenIDEx(TEST_USER_ID, TEST_BUNDLE_NAME, 0);
    AccessTokenID tokenID = tokenIDEx.tokenIdExStruct.tokenID;
    ASSERT_NE(INVALID_TOKENID, tokenID);
    EXPECT_EQ(0, SetSelfTokenID(tokenIDEx.tokenIDEx));

    std::vector<PermissionListState> permsList;
    PermissionListState tmpA = {
        .permissionName = "ohos.permission.LOCATION",
        .state = SETTING_OPER
    };
    PermissionListState tmpB = {
        .permissionName = "ohos.permission.WRITE_CALENDAR",
        .state = SETTING_OPER
    };
    PermissionListState tmpC = {
        .permissionName = "ohos.permission.BETA",
        .state = SETTING_OPER
    };
    PermissionListState tmpD = {
        .permissionName = "ohos.permission.xxx",
        .state = SETTING_OPER
    };
    PermissionListState tmpE = {
        .permissionName = "ohos.permission.CAMERA",
        .state = SETTING_OPER
    };

    permsList.emplace_back(tmpA);
    permsList.emplace_back(tmpB);
    permsList.emplace_back(tmpC);
    permsList.emplace_back(tmpD);
    permsList.emplace_back(tmpE);

    HapBaseInfo hapBaseInfo = {
        .userID = TEST_USER_ID,
        .bundleName = TEST_BUNDLE_NAME,
        .instIndex = 0
    };
    ASSERT_EQ(RET_SUCCESS, AccessTokenKit::SetPermDialogCap(hapBaseInfo, true));
    ASSERT_EQ(RET_SUCCESS, AccessTokenKit::GetPermissionsStatus(tokenID, permsList));
    ASSERT_EQ(FORBIDDEN_OPER, permsList[0].state);
    ASSERT_EQ(FORBIDDEN_OPER, permsList[1].state);
    ASSERT_EQ(INVALID_OPER, permsList[2].state);
    ASSERT_EQ(INVALID_OPER, permsList[3].state);
    ASSERT_EQ(INVALID_OPER, permsList[4].state);
    ASSERT_EQ(RET_SUCCESS, AccessTokenKit::SetPermDialogCap(hapBaseInfo, false));
}

/**
 * @tc.name: GetPermissionsStatusAbnormalTest001
 * @tc.desc: invalid input param: tokenID is 0 or permissionList is empty
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(GetPermissionsStatusTest, GetPermissionsStatusAbnormalTest001, TestSize.Level1)
{
    AccessTokenIDEx tokenIDEx = AccessTokenKit::GetHapTokenIDEx(TEST_USER_ID, TEST_BUNDLE_NAME, 0);
    AccessTokenID tokenID = tokenIDEx.tokenIdExStruct.tokenID;
    ASSERT_NE(INVALID_TOKENID, tokenID);
    EXPECT_EQ(0, SetSelfTokenID(tokenIDEx.tokenIDEx));

    std::vector<PermissionListState> permsList;
    ASSERT_EQ(ERR_PARAM_INVALID, AccessTokenKit::GetPermissionsStatus(tokenID, permsList));
    PermissionListState tmpA = {
        .permissionName = "ohos.permission.testPermDef1",
        .state = SETTING_OPER
    };
    permsList.emplace_back(tmpA);

    ASSERT_EQ(ERR_PARAM_INVALID, AccessTokenKit::GetPermissionsStatus(0, permsList));
    ASSERT_EQ(SETTING_OPER, permsList[0].state);
}

/**
 * @tc.name: GetPermissionsStatusAbnormalTest002
 * @tc.desc: tokenID not exit
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(GetPermissionsStatusTest, GetPermissionsStatusAbnormalTest002, TestSize.Level1)
{
    std::vector<PermissionListState> permsList;
    PermissionListState tmpA = {
        .permissionName = "ohos.permission.testPermDef1",
        .state = SETTING_OPER
    };
    permsList.emplace_back(tmpA);

    ASSERT_EQ(ERR_TOKENID_NOT_EXIST, AccessTokenKit::GetPermissionsStatus(TOKENID_NOT_EXIST, permsList));
    ASSERT_EQ(SETTING_OPER, permsList[0].state);
}

/**
 * @tc.name: GetPermissionsStatusAbnormalTest003
 * @tc.desc: callling without permission
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(GetPermissionsStatusTest, GetPermissionsStatusAbnormalTest003, TestSize.Level1)
{
    AccessTokenIDEx tokenIDEx = {0};
    tokenIDEx = AccessTokenKit::AllocHapToken(g_infoManagerTestSystemInfoParms, g_infoManagerTestPolicyPrams);
    AccessTokenID tokenID = tokenIDEx.tokenIdExStruct.tokenID;
    ASSERT_NE(INVALID_TOKENID, tokenID);
    EXPECT_EQ(0, SetSelfTokenID(tokenIDEx.tokenIDEx));

    std::vector<PermissionListState> permsList;
    PermissionListState tmpA = {
        .permissionName = "ohos.permission.testPermDef1",
        .state = SETTING_OPER
    };

    permsList.emplace_back(tmpA);
    int32_t selfUid = getuid();
    setuid(10001); // 10001： UID

    ASSERT_EQ(ERR_PERMISSION_DENIED, AccessTokenKit::GetPermissionsStatus(tokenID, permsList));
    ASSERT_EQ(SETTING_OPER, permsList[0].state);
    setuid(selfUid);
}

/**
 * @tc.name: GetPermissionsStatusSpecTest001
 * @tc.desc: callling is normal hap
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(GetPermissionsStatusTest, GetPermissionsStatusSpecTest001, TestSize.Level1)
{
    AccessTokenIDEx tokenIDEx = {0};
    tokenIDEx = AccessTokenKit::AllocHapToken(g_infoManagerTestNormalInfoParms, g_infoManagerTestPolicyPrams);
    AccessTokenID tokenID = tokenIDEx.tokenIdExStruct.tokenID;
    ASSERT_NE(INVALID_TOKENID, tokenID);
    EXPECT_EQ(0, SetSelfTokenID(tokenIDEx.tokenIDEx));

    std::vector<PermissionListState> permsList;
    PermissionListState tmpA = {
        .permissionName = "ohos.permission.testPermDef1",
        .state = SETTING_OPER
    };

    permsList.emplace_back(tmpA);

    ASSERT_EQ(ERR_NOT_SYSTEM_APP, AccessTokenKit::GetPermissionsStatus(tokenID, permsList));
    ASSERT_EQ(SETTING_OPER, permsList[0].state);
}

/**
 * @tc.name: GetPermissionsStatusSpecTest002
 * @tc.desc: callling is native SA
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(GetPermissionsStatusTest, GetPermissionsStatusSpecTest002, TestSize.Level1)
{
    AccessTokenID tokenID = AccessTokenKit::GetHapTokenID(TEST_USER_ID, TEST_BUNDLE_NAME, 0);
    ASSERT_NE(INVALID_TOKENID, tokenID);

    std::vector<PermissionListState> permsList;
    PermissionListState tmpA = {
        .permissionName = "ohos.permission.LOCATION",
        .state = SETTING_OPER
    };

    permsList.emplace_back(tmpA);

    ASSERT_EQ(RET_SUCCESS, AccessTokenKit::GetPermissionsStatus(tokenID, permsList));
    ASSERT_EQ(DYNAMIC_OPER, permsList[0].state);
}
} // namespace AccessToken
} // namespace Security
} // namespace OHOS