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

#include "get_permission_test.h"
#include "gtest/gtest.h"
#include <thread>

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
static const int INVALID_PERMNAME_LEN = 260;
static const unsigned int TEST_TOKENID_INVALID = 0;
static const int CYCLE_TIMES = 100;
static const int TEST_USER_ID = 0;
static constexpr int32_t DEFAULT_API_VERSION = 8;
HapInfoParams g_infoManagerTestInfoParms = TestCommon::GetInfoManagerTestInfoParms();
HapPolicyParams g_infoManagerTestPolicyPrams = TestCommon::GetInfoManagerTestPolicyPrams();
}

void GetPermissionTest::SetUpTestCase()
{
    g_selfTokenId = GetSelfTokenID();

    // clean up test cases
    AccessTokenID tokenID = AccessTokenKit::GetHapTokenID(TEST_USER_ID, TEST_BUNDLE_NAME, 0);
    AccessTokenKit::DeleteToken(tokenID);

    tokenID = AccessTokenKit::GetHapTokenID(g_infoManagerTestInfoParms.userID,
                                            g_infoManagerTestInfoParms.bundleName,
                                            g_infoManagerTestInfoParms.instIndex);
    AccessTokenKit::DeleteToken(tokenID);

    AccessTokenIDEx tokenIdEx = AccessTokenKit::AllocHapToken(g_infoManagerTestInfoParms,
                                                              TestCommon::GetTestPolicyParams());
    SetSelfTokenID(tokenIdEx.tokenIDEx);
}

void GetPermissionTest::TearDownTestCase()
{
    AccessTokenID tokenID = AccessTokenKit::GetHapTokenID(TEST_USER_ID, TEST_BUNDLE_NAME, 0);
    AccessTokenKit::DeleteToken(tokenID);

    tokenID = AccessTokenKit::GetHapTokenID(g_infoManagerTestInfoParms.userID,
                                            g_infoManagerTestInfoParms.bundleName,
                                            g_infoManagerTestInfoParms.instIndex);
    AccessTokenKit::DeleteToken(tokenID);

    SetSelfTokenID(g_selfTokenId);
}

void GetPermissionTest::SetUp()
{
    LOGI(ATM_DOMAIN, ATM_TAG, "SetUp ok.");

    setuid(0);
    HapInfoParams info = {
        .userID = TEST_USER_ID,
        .bundleName = TEST_BUNDLE_NAME,
        .instIndex = 0,
        .appIDDesc = "appIDDesc",
        .apiVersion = DEFAULT_API_VERSION
    };

    HapPolicyParams policy = {
        .apl = APL_NORMAL,
        .domain = "domain"
    };
    TestCommon::TestPreparePermDefList(policy);
    TestCommon::TestPreparePermStateList(policy);

    AccessTokenKit::AllocHapToken(info, policy);
}

void GetPermissionTest::TearDown()
{
}

/**
 * @tc.name: GetPermissionUsedTypeAbnormalTest001
 * @tc.desc: Get hap permission visit type return invalid.
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(GetPermissionTest, GetPermissionUsedTypeAbnormalTest001, TestSize.Level1)
{
    LOGI(ATM_DOMAIN, ATM_TAG, "GetPermissionUsedTypeAbnormalTest001");

    std::string accessBluetooth = "ohos.permission.ACCESS_BLUETOOTH";

    EXPECT_EQ(PermUsedTypeEnum::INVALID_USED_TYPE,
        AccessTokenKit::GetPermissionUsedType(g_selfTokenId, accessBluetooth));
    AccessTokenID tokenID = TestCommon::AllocTestToken(g_infoManagerTestInfoParms, g_infoManagerTestPolicyPrams);
    ASSERT_NE(INVALID_TOKENID, tokenID);

    EXPECT_EQ(PermUsedTypeEnum::INVALID_USED_TYPE,
        AccessTokenKit::GetPermissionUsedType(0, accessBluetooth));

    EXPECT_EQ(PermUsedTypeEnum::INVALID_USED_TYPE,
        AccessTokenKit::GetPermissionUsedType(tokenID, "ohos.permission.ACCELEROMETER"));

    EXPECT_EQ(PermUsedTypeEnum::INVALID_USED_TYPE,
        AccessTokenKit::GetPermissionUsedType(tokenID, "ohos.permission.xxxxx"));

    EXPECT_EQ(PermUsedTypeEnum::INVALID_USED_TYPE,
        AccessTokenKit::GetPermissionUsedType(tokenID, accessBluetooth));

    ASSERT_EQ(RET_SUCCESS, AccessTokenKit::DeleteToken(tokenID));
}

/**
 * @tc.name: GetPermissionUsedTypeFuncTest001
 * @tc.desc: Different grant permission modes get different visit type.
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(GetPermissionTest, GetPermissionUsedTypeFuncTest001, TestSize.Level1)
{
    LOGI(ATM_DOMAIN, ATM_TAG, "GetPermissionUsedTypeFuncTest001");

    std::string accessBluetooth = "ohos.permission.ACCESS_BLUETOOTH";
    std::string sendMessages = "ohos.permission.SEND_MESSAGES";
    std::string writeCalendar = "ohos.permission.WRITE_CALENDAR";
    PermissionStateFull testState1 = {
        .permissionName = accessBluetooth,
        .isGeneral = true,
        .resDeviceID = {"local3"},
        .grantStatus = {PermissionState::PERMISSION_GRANTED},
        .grantFlags = {PermissionFlag::PERMISSION_COMPONENT_SET}
    };
    PermissionStateFull testState2 = {
        .permissionName = sendMessages,
        .isGeneral = true,
        .resDeviceID = {"local3"},
        .grantStatus = {PermissionState::PERMISSION_GRANTED},
        .grantFlags = {1}
    };
    PermissionStateFull testState3 = {
        .permissionName = writeCalendar,
        .isGeneral = false,
        .resDeviceID = {"local3"},
        .grantStatus = {PermissionState::PERMISSION_GRANTED},
        .grantFlags = {1}
    };
    HapPolicyParams testPolicyPrams = {
        .apl = APL_NORMAL,
        .domain = "test.domain3",
        .permStateList = {testState1, testState2, testState3}
    };
    AccessTokenID tokenID = TestCommon::AllocTestToken(g_infoManagerTestInfoParms, testPolicyPrams);
    ASSERT_NE(INVALID_TOKENID, tokenID);

    EXPECT_EQ(PermUsedTypeEnum::SEC_COMPONENT_TYPE,
        AccessTokenKit::GetPermissionUsedType(tokenID, accessBluetooth));

    EXPECT_EQ(PermUsedTypeEnum::NORMAL_TYPE, AccessTokenKit::GetPermissionUsedType(tokenID, sendMessages));

    int32_t selfUid = getuid();
    EXPECT_EQ(0, SetSelfTokenID(tokenID));
    setuid(1);
    EXPECT_EQ(PermUsedTypeEnum::INVALID_USED_TYPE,
        AccessTokenKit::GetPermissionUsedType(tokenID, writeCalendar));
    setuid(selfUid);
    ASSERT_EQ(0, SetSelfTokenID(g_selfTokenId));
}

/**
 * @tc.name: GetDefPermissionFuncTest001
 * @tc.desc: Get permission definition info after AllocHapToken function has been invoked.
 * @tc.type: FUNC
 * @tc.require: Issue Number
 */
HWTEST_F(GetPermissionTest, GetDefPermissionFuncTest001, TestSize.Level1)
{
    LOGI(ATM_DOMAIN, ATM_TAG, "GetDefPermissionFuncTest001");

    PermissionDef permDef;
    // permission name is empty
    ASSERT_EQ(AccessTokenError::ERR_PARAM_INVALID, AccessTokenKit::GetDefPermission("", permDef));

    // permission name oversize
    std::string invalidPerm(INVALID_PERMNAME_LEN, 'a');
    ASSERT_EQ(AccessTokenError::ERR_PARAM_INVALID, AccessTokenKit::GetDefPermission(invalidPerm, permDef));

    ASSERT_EQ(AccessTokenError::ERR_PERMISSION_NOT_EXIST, AccessTokenKit::GetDefPermission(
        "ohos.permission.ALPHA", permDef));
    ASSERT_EQ(AccessTokenError::ERR_PERMISSION_NOT_EXIST, AccessTokenKit::GetDefPermission(
        "ohos.permission.BETA", permDef));
    ASSERT_EQ(AccessTokenError::ERR_PERMISSION_NOT_EXIST, AccessTokenKit::GetDefPermission(
        "ohos.permission.GAMMA", permDef));

    // get user grant permission define
    ASSERT_EQ(0, AccessTokenKit::GetDefPermission("ohos.permission.CAMERA", permDef));
    ASSERT_EQ("ohos.permission.CAMERA", permDef.permissionName);

    // get system grant permission define
    ASSERT_EQ(0, AccessTokenKit::GetDefPermission("ohos.permission.PERMISSION_USED_STATS", permDef));
    ASSERT_EQ("ohos.permission.PERMISSION_USED_STATS", permDef.permissionName);
}

/**
 * @tc.name: GetReqPermissionsFuncTest001
 * @tc.desc: Get user granted permission state info.
 * @tc.type: FUNC
 * @tc.require: Issue Number
 */
HWTEST_F(GetPermissionTest, GetReqPermissionsFuncTest001, TestSize.Level1)
{
    LOGI(ATM_DOMAIN, ATM_TAG, "GetReqPermissionsFuncTest001");

    AccessTokenID tokenID = AccessTokenKit::GetHapTokenID(TEST_USER_ID, TEST_BUNDLE_NAME, 0);
    ASSERT_NE(INVALID_TOKENID, tokenID);
    std::vector<PermissionStateFull> permStatList;
    int res = AccessTokenKit::GetReqPermissions(tokenID, permStatList, false);
    ASSERT_EQ(RET_SUCCESS, res);
    ASSERT_EQ(static_cast<uint32_t>(1), permStatList.size());
    ASSERT_EQ("ohos.permission.MICROPHONE", permStatList[0].permissionName);

    res = AccessTokenKit::VerifyAccessToken(tokenID, "ohos.permission.MICROPHONE", false);
    ASSERT_EQ(res, permStatList[0].grantStatus[0]);

    ASSERT_EQ(RET_SUCCESS, AccessTokenKit::DeleteToken(tokenID));
}

/**
 * @tc.name: GetReqPermissionsFuncTest002
 * @tc.desc: Get system granted permission state info.
 * @tc.type: FUNC
 * @tc.require: Issue Number
 */
HWTEST_F(GetPermissionTest, GetReqPermissionsFuncTest002, TestSize.Level1)
{
    LOGI(ATM_DOMAIN, ATM_TAG, "GetReqPermissionsFuncTest002");

    AccessTokenID tokenID = AccessTokenKit::GetHapTokenID(TEST_USER_ID, TEST_BUNDLE_NAME, 0);
    ASSERT_NE(INVALID_TOKENID, tokenID);
    std::vector<PermissionStateFull> permStatList;
    int ret = AccessTokenKit::GetReqPermissions(tokenID, permStatList, true);
    ASSERT_EQ(RET_SUCCESS, ret);
    ASSERT_EQ(static_cast<uint32_t>(1), permStatList.size());
    ASSERT_EQ("ohos.permission.SET_WIFI_INFO", permStatList[0].permissionName);

    ret = AccessTokenKit::VerifyAccessToken(tokenID, "ohos.permission.SET_WIFI_INFO", false);
    ASSERT_EQ(ret, permStatList[0].grantStatus[0]);

    ASSERT_EQ(RET_SUCCESS, AccessTokenKit::DeleteToken(tokenID));
}

/**
 * @tc.name: GetReqPermissionsFuncTest003
 * @tc.desc: Get user granted permission state info after clear request permission list.
 * @tc.type: FUNC
 * @tc.require: Issue Number
 */
HWTEST_F(GetPermissionTest, GetReqPermissionsFuncTest003, TestSize.Level1)
{
    LOGI(ATM_DOMAIN, ATM_TAG, "GetReqPermissionsFuncTest003");

    AccessTokenIDEx tokenIdEx = AccessTokenKit::GetHapTokenIDEx(TEST_USER_ID, TEST_BUNDLE_NAME, 0);
    AccessTokenID tokenID = tokenIdEx.tokenIdExStruct.tokenID;
    ASSERT_NE(INVALID_TOKENID, tokenID);

    HapTokenInfo hapInfo;
    int ret = AccessTokenKit::GetHapTokenInfo(tokenID, hapInfo);
    ASSERT_EQ(RET_SUCCESS, ret);

    HapPolicyParams policy = {
        .apl = APL_NORMAL,
        .domain = "domain"
    };
    policy.permStateList.clear();
    UpdateHapInfoParams info;
    info.appIDDesc = g_infoManagerTestInfoParms.appIDDesc;
    info.apiVersion = DEFAULT_API_VERSION;
    info.isSystemApp = false;
    ret = AccessTokenKit::UpdateHapToken(tokenIdEx, info, policy);
    ASSERT_EQ(RET_SUCCESS, ret);

    std::vector<PermissionStateFull> permStatUserList;
    ret = AccessTokenKit::GetReqPermissions(tokenID, permStatUserList, false);
    ASSERT_EQ(RET_SUCCESS, ret);
    ASSERT_EQ(static_cast<uint32_t>(0), permStatUserList.size());

    std::vector<PermissionStateFull> permStatSystemList;
    ret = AccessTokenKit::GetReqPermissions(tokenID, permStatSystemList, true);
    ASSERT_EQ(RET_SUCCESS, ret);
    ASSERT_EQ(static_cast<uint32_t>(0), permStatSystemList.size());

    ASSERT_EQ(RET_SUCCESS, AccessTokenKit::DeleteToken(tokenID));
}

/**
 * @tc.name: GetReqPermissionsAbnormalTest001
 * @tc.desc: Get permission state info list that tokenID is invalid.
 * @tc.type: FUNC
 * @tc.require: Issue Number
 */
HWTEST_F(GetPermissionTest, GetReqPermissionsAbnormalTest001, TestSize.Level1)
{
    LOGI(ATM_DOMAIN, ATM_TAG, "GetReqPermissionsAbnormalTest001");

    AccessTokenID tokenID = AccessTokenKit::GetHapTokenID(TEST_USER_ID, TEST_BUNDLE_NAME, 0);
    ASSERT_NE(INVALID_TOKENID, tokenID);

    std::vector<PermissionStateFull> permStatList;
    int ret = AccessTokenKit::GetReqPermissions(TEST_TOKENID_INVALID, permStatList, false);
    ASSERT_EQ(AccessTokenError::ERR_PARAM_INVALID, ret);

    AccessTokenKit::DeleteToken(tokenID);

    ret = AccessTokenKit::GetReqPermissions(tokenID, permStatList, false);
    ASSERT_EQ(ERR_TOKENID_NOT_EXIST, ret);
    ASSERT_EQ(static_cast<uint32_t>(0), permStatList.size());
}

/**
 * @tc.name: GetReqPermissionsSpecTest001
 * @tc.desc: GetReqPermissions is invoked multiple times.
 * @tc.type: FUNC
 * @tc.require: Issue Number
 */
HWTEST_F(GetPermissionTest, GetReqPermissionsSpecTest001, TestSize.Level0)
{
    LOGI(ATM_DOMAIN, ATM_TAG, "GetReqPermissionsSpecTest001");

    AccessTokenID tokenID = AccessTokenKit::GetHapTokenID(TEST_USER_ID, TEST_BUNDLE_NAME, 0);
    ASSERT_NE(INVALID_TOKENID, tokenID);
    for (int i = 0; i < CYCLE_TIMES; i++) {
        std::vector<PermissionStateFull> permStatList;
        int32_t ret = AccessTokenKit::GetReqPermissions(tokenID, permStatList, false);
        ASSERT_EQ(RET_SUCCESS, ret);
        ASSERT_EQ(static_cast<uint32_t>(1), permStatList.size());
        ASSERT_EQ("ohos.permission.MICROPHONE", permStatList[0].permissionName);
    }
    ASSERT_EQ(RET_SUCCESS, AccessTokenKit::DeleteToken(tokenID));
}

/**
 * @tc.name: GetReqPermissions001
 * @tc.desc: GetReqPermissions call failure.
 * @tc.type: FUNC
 * @tc.require: Issue Number
 */
HWTEST_F(GetPermissionTest, GetReqPermissions001, TestSize.Level0)
{
    AccessTokenIDEx tokenIdEx = {0};
    HapPolicyParams policy = {
        .apl = APL_NORMAL,
        .domain = "test.GetReqPermissions",
        .permList = {},
        .permStateList = {}
    };
    HapInfoParams info = {
        .userID = 100,
        .bundleName = "test.GetReqPermissions.normal",
        .instIndex = 0,
        .appIDDesc = "test3",
        .apiVersion = DEFAULT_API_VERSION,
        .isSystemApp = false
    };

    tokenIdEx = AccessTokenKit::AllocHapToken(info, policy);
    AccessTokenID tokenID = tokenIdEx.tokenIdExStruct.tokenID;
    ASSERT_NE(INVALID_TOKENID, tokenIdEx.tokenIDEx);
    int32_t selfUid = getuid();

    setuid(0);
    std::vector<PermissionStateFull> permStatList;
    EXPECT_EQ(0, SetSelfTokenID(TestCommon::GetNativeToken("GetReqPermissions", nullptr, 0)));
    setuid(1);
    int32_t ret = AccessTokenKit::GetReqPermissions(tokenID, permStatList, false);
    ASSERT_EQ(AccessTokenError::ERR_PERMISSION_DENIED, ret);

    setuid(0);
    EXPECT_EQ(0, SetSelfTokenID(tokenIdEx.tokenIDEx));
    ret = AccessTokenKit::GetReqPermissions(tokenID, permStatList, false);
    ASSERT_EQ(ERR_NOT_SYSTEM_APP, ret);

    ASSERT_EQ(RET_SUCCESS, AccessTokenKit::DeleteToken(tokenID));
    setuid(selfUid);
    ASSERT_EQ(0, SetSelfTokenID(g_selfTokenId));
}

/**
 * @tc.name: GetPermissionManagerInfoFuncTest001
 * @tc.desc:
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(GetPermissionTest, GetPermissionManagerInfoFuncTest001, TestSize.Level1)
{
    LOGI(ATM_DOMAIN, ATM_TAG, "GetPermissionManagerInfoFuncTest001");

    PermissionGrantInfo info;
    AccessTokenKit::GetPermissionManagerInfo(info);
    ASSERT_EQ(false, info.grantBundleName.empty());
}

/**
 * @tc.name: GetKernelPermissionTest001
 * @tc.desc:
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(GetPermissionTest, GetKernelPermissionTest001, TestSize.Level1)
{
    setuid(1);
    std::vector<PermissionWithValue> kernelPermList;
    int32_t ret = AccessTokenKit::GetKernelPermissions(123, kernelPermList);
    EXPECT_EQ(AccessTokenError::ERR_PERMISSION_DENIED, ret);
    setuid(0);

    SetSelfTokenID(g_selfTokenId);
    ret = AccessTokenKit::GetKernelPermissions(123, kernelPermList);
    EXPECT_EQ(AccessTokenError::ERR_TOKEN_INVALID, ret);

    ret = AccessTokenKit::GetKernelPermissions(123, kernelPermList);
    EXPECT_EQ(AccessTokenError::ERR_TOKEN_INVALID, ret);

    AccessTokenID tokenID = AccessTokenKit::GetHapTokenID(TEST_USER_ID, TEST_BUNDLE_NAME, 0);
    ret = AccessTokenKit::GetKernelPermissions(tokenID, kernelPermList);
    EXPECT_EQ(RET_SUCCESS, ret);
    EXPECT_EQ(0, kernelPermList.size());
}

/**
 * @tc.name: GetReqPermissionByNameTest001
 * @tc.desc: test Ge
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(GetPermissionTest, GetReqPermissionByNameTest001, TestSize.Level1)
{
    setuid(1);
    std::string value;
    int32_t ret = AccessTokenKit::GetReqPermissionByName(123, "ohos.permission.test1", value);
    EXPECT_EQ(AccessTokenError::ERR_PERMISSION_DENIED, ret);
    setuid(0);

    SetSelfTokenID(g_selfTokenId);
    ret = AccessTokenKit::GetReqPermissionByName(123, "ohos.permission.test1", value);
    EXPECT_EQ(AccessTokenError::ERR_TOKEN_INVALID, ret);

    AccessTokenID tokenID = AccessTokenKit::GetHapTokenID(TEST_USER_ID, TEST_BUNDLE_NAME, 0);
    ret = AccessTokenKit::GetReqPermissionByName(tokenID, "ohos.permission.test1", value);
    EXPECT_EQ(AccessTokenError::ERR_PERMISSION_NOT_EXIST, ret);

    ret = AccessTokenKit::GetReqPermissionByName(tokenID, "ohos.permission.MANAGE_HAP_TOKENID", value);
    EXPECT_EQ(AccessTokenError::ERR_PERMISSION_WITHOUT_VALUE, ret);
}
} // namespace AccessToken
} // namespace Security
} // namespace OHOS