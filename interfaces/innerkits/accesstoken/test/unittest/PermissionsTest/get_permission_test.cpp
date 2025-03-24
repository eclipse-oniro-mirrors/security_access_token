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
static uint64_t g_selfTokenId = 0;
static const std::string TEST_BUNDLE_NAME = "ohos";
static const int INVALID_PERMNAME_LEN = 260;
static const unsigned int TEST_TOKENID_INVALID = 0;
static const int CYCLE_TIMES = 100;
static const int TEST_USER_ID = 0;
static constexpr int32_t DEFAULT_API_VERSION = 8;
static const std::string TEST_PERMISSION = "ohos.permission.ALPHA";
HapInfoParams g_infoManagerTestInfoParms = TestCommon::GetInfoManagerTestInfoParms();
HapPolicyParams g_infoManagerTestPolicyPrams = TestCommon::GetInfoManagerTestPolicyPrams();
HapInfoParams g_infoManager = {
    .userID = 1,
    .bundleName = "accesstoken_test",
    .instIndex = 0,
    .appIDDesc = "test2",
    .apiVersion = 8  // 8: api version
};
}

void GetPermissionTest::SetUpTestCase()
{
    g_selfTokenId = GetSelfTokenID();
    TestCommon::SetTestEvironment(g_selfTokenId);

    // clean up test cases
    AccessTokenIDEx tokenIdEx = TestCommon::GetHapTokenIdFromBundle(TEST_USER_ID, TEST_BUNDLE_NAME, 0);
    AccessTokenID tokenID = tokenIdEx.tokenIdExStruct.tokenID;
    TestCommon::DeleteTestHapToken(tokenID);
}

void GetPermissionTest::TearDownTestCase()
{
    AccessTokenID tokenID = AccessTokenKit::GetHapTokenID(TEST_USER_ID, TEST_BUNDLE_NAME, 0);
    AccessTokenKit::DeleteToken(tokenID);

    EXPECT_EQ(0, SetSelfTokenID(g_selfTokenId));
    TestCommon::ResetTestEvironment();
}

void GetPermissionTest::SetUp()
{
    LOGI(ATM_DOMAIN, ATM_TAG, "SetUp ok.");

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
    TestCommon::TestPreparePermStateList(policy);
    AccessTokenIDEx tokenIdEx = {0};
    ASSERT_EQ(RET_SUCCESS, TestCommon::AllocTestHapToken(info, policy, tokenIdEx));
    ASSERT_NE(INVALID_TOKENID, tokenIdEx.tokenIdExStruct.tokenID);
}

void GetPermissionTest::TearDown()
{
    AccessTokenID tokenID = AccessTokenKit::GetHapTokenID(TEST_USER_ID, TEST_BUNDLE_NAME, 0);
    AccessTokenKit::DeleteToken(tokenID);
}

/**
 * @tc.name: GetPermissionUsedTypeAbnormalTest001
 * @tc.desc: call GetPermissionUsedType by shell token(permission denied).
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(GetPermissionTest, GetPermissionUsedTypeAbnormalTest001, TestSize.Level1)
{
    LOGI(ATM_DOMAIN, ATM_TAG, "GetPermissionUsedTypeAbnormalTest001");
    std::string permisson = "ohos.permission.CAMERA";
    // caller is not native, IsPrivilegedCalling return false(uid != accesstoken_uid)
    int32_t selfUid = getuid();
    setuid(1);
    EXPECT_EQ(PermUsedTypeEnum::INVALID_USED_TYPE, AccessTokenKit::GetPermissionUsedType(g_selfTokenId, permisson));
    setuid(selfUid);
}

/**
 * @tc.name: GetPermissionUsedTypeAbnormalTest002
 * @tc.desc: Get hap permission visit type return invalid.
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(GetPermissionTest, GetPermissionUsedTypeAbnormalTest002, TestSize.Level1)
{
    LOGI(ATM_DOMAIN, ATM_TAG, "GetPermissionUsedTypeAbnormalTest002");

    std::string accessBluetooth = "ohos.permission.ACCESS_BLUETOOTH";
    std::vector<std::string> reqPerm;
    reqPerm.emplace_back(accessBluetooth);
    MockHapToken mockHap("GetPermissionUsedTypeAbnormalTest002", reqPerm, true);
    AccessTokenID tokenID = GetSelfTokenID(); // get hap tokenId
    ASSERT_NE(INVALID_TOKENID, tokenID);

    MockNativeToken mock("accesstoken_service"); // set native for self

    // token is not hap
    EXPECT_EQ(
        PermUsedTypeEnum::INVALID_USED_TYPE, AccessTokenKit::GetPermissionUsedType(g_selfTokenId, accessBluetooth));

    // invalid tokenid
    EXPECT_EQ(PermUsedTypeEnum::INVALID_USED_TYPE, AccessTokenKit::GetPermissionUsedType(0, accessBluetooth));

    // permission is not reuqest
    EXPECT_EQ(PermUsedTypeEnum::INVALID_USED_TYPE,
        AccessTokenKit::GetPermissionUsedType(tokenID, "ohos.permission.ACCELEROMETER"));

    // permission is not defined
    EXPECT_EQ(
        PermUsedTypeEnum::INVALID_USED_TYPE, AccessTokenKit::GetPermissionUsedType(tokenID, "ohos.permission.test"));

    // permission is request, but not grant
    EXPECT_EQ(PermUsedTypeEnum::INVALID_USED_TYPE, AccessTokenKit::GetPermissionUsedType(tokenID, accessBluetooth));
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
    AccessTokenIDEx tokenIdEx = TestCommon::AllocAndGrantHapTokenByTest(g_infoManager, testPolicyPrams);
    AccessTokenID tokenID = tokenIdEx.tokenIdExStruct.tokenID;
    ASSERT_NE(INVALID_TOKENID, tokenID);

    MockNativeToken mock("accesstoken_service"); // set native for self
    EXPECT_EQ(PermUsedTypeEnum::SEC_COMPONENT_TYPE, AccessTokenKit::GetPermissionUsedType(tokenID, accessBluetooth));
    EXPECT_EQ(PermUsedTypeEnum::NORMAL_TYPE, AccessTokenKit::GetPermissionUsedType(tokenID, sendMessages));

    ASSERT_EQ(RET_SUCCESS, TestCommon::DeleteTestHapToken(tokenID));
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
    std::vector<std::string> reqPerm;
    reqPerm.emplace_back("ohos.permission.GET_SENSITIVE_PERMISSIONS");
    MockHapToken mockHap("GetReqPermissionsFuncTest001", reqPerm, true);

    AccessTokenIDEx tokenIdEx = TestCommon::GetHapTokenIdFromBundle(TEST_USER_ID, TEST_BUNDLE_NAME, 0);
    AccessTokenID tokenID = tokenIdEx.tokenIdExStruct.tokenID;
    ASSERT_NE(INVALID_TOKENID, tokenID);
    std::vector<PermissionStateFull> permStatList;
    int res = AccessTokenKit::GetReqPermissions(tokenID, permStatList, false);
    ASSERT_EQ(RET_SUCCESS, res);
    ASSERT_EQ(static_cast<uint32_t>(1), permStatList.size());
    ASSERT_EQ("ohos.permission.MICROPHONE", permStatList[0].permissionName);

    res = AccessTokenKit::VerifyAccessToken(tokenID, "ohos.permission.MICROPHONE", false);
    ASSERT_EQ(res, permStatList[0].grantStatus[0]);
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
    std::vector<std::string> reqPerm;
    reqPerm.emplace_back("ohos.permission.GET_SENSITIVE_PERMISSIONS");
    MockHapToken mockHap("GetReqPermissionsFuncTest002", reqPerm, true);

    AccessTokenIDEx tokenIdEx = TestCommon::GetHapTokenIdFromBundle(TEST_USER_ID, TEST_BUNDLE_NAME, 0);
    AccessTokenID tokenID = tokenIdEx.tokenIdExStruct.tokenID;
    ASSERT_NE(INVALID_TOKENID, tokenID);
    std::vector<PermissionStateFull> permStatList;
    int ret = AccessTokenKit::GetReqPermissions(tokenID, permStatList, true);
    ASSERT_EQ(RET_SUCCESS, ret);
    ASSERT_EQ(static_cast<uint32_t>(1), permStatList.size());
    ASSERT_EQ("ohos.permission.SET_WIFI_INFO", permStatList[0].permissionName);

    ret = AccessTokenKit::VerifyAccessToken(tokenID, "ohos.permission.SET_WIFI_INFO", false);
    ASSERT_EQ(ret, permStatList[0].grantStatus[0]);
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
    std::vector<std::string> reqPerm;
    reqPerm.emplace_back("ohos.permission.GET_SENSITIVE_PERMISSIONS");
    MockHapToken mockHap("GetReqPermissionsFuncTest003", reqPerm, true);

    AccessTokenIDEx tokenIdEx = TestCommon::GetHapTokenIdFromBundle(TEST_USER_ID, TEST_BUNDLE_NAME, 0);
    AccessTokenID tokenID = tokenIdEx.tokenIdExStruct.tokenID;
    ASSERT_NE(INVALID_TOKENID, tokenID);

    std::vector<PermissionStateFull> permStatList;
    ASSERT_EQ(RET_SUCCESS, AccessTokenKit::GetReqPermissions(tokenID, permStatList, false));
    ASSERT_NE(static_cast<uint32_t>(0), permStatList.size());

    HapPolicyParams policy = {
        .apl = APL_NORMAL,
        .domain = "domain"
    };
    policy.permStateList.clear();
    UpdateHapInfoParams info;
    info.appIDDesc = g_infoManager.appIDDesc;
    info.apiVersion = DEFAULT_API_VERSION;
    info.isSystemApp = false;
    {
        MockNativeToken mock1("foundation");
        ASSERT_EQ(RET_SUCCESS, AccessTokenKit::UpdateHapToken(tokenIdEx, info, policy));
    }

    std::vector<PermissionStateFull> permStatUserList;
    ASSERT_EQ(RET_SUCCESS, AccessTokenKit::GetReqPermissions(tokenID, permStatUserList, false));
    ASSERT_EQ(static_cast<uint32_t>(0), permStatUserList.size());

    std::vector<PermissionStateFull> permStatSystemList;
    ASSERT_EQ(RET_SUCCESS, AccessTokenKit::GetReqPermissions(tokenID, permStatSystemList, true));
    ASSERT_EQ(static_cast<uint32_t>(0), permStatSystemList.size());
}

/**
 * @tc.name: GetReqPermissionsFuncTest004
 * @tc.desc: GetReqPermissions call failure.
 * @tc.type: FUNC
 * @tc.require: Issue Number
 */
HWTEST_F(GetPermissionTest, GetReqPermissionsFuncTest004, TestSize.Level0)
{
    int32_t selfUid = getuid();
    std::vector<PermissionStateFull> permStatList;
    {
        // mock native token with no permission
        MockNativeToken mock("accesstoken_service");
        setuid(1);
        ASSERT_EQ(ERR_PERMISSION_DENIED, AccessTokenKit::GetReqPermissions(GetSelfTokenID(), permStatList, false));
    }

    setuid(selfUid);
    {
        // mock hap token whit non system app
        std::vector<std::string> reqPerm;
        reqPerm.emplace_back("ohos.permission.GET_SENSITIVE_PERMISSIONS");
        MockHapToken mock("GetReqPermissionsFuncTest004", reqPerm, false);
        ASSERT_EQ(ERR_NOT_SYSTEM_APP, AccessTokenKit::GetReqPermissions(GetSelfTokenID(), permStatList, false));
    }
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
    std::vector<std::string> reqPerm;
    reqPerm.emplace_back("ohos.permission.GET_SENSITIVE_PERMISSIONS");
    MockHapToken mockHap("GetReqPermissionsAbnormalTest001", reqPerm, true);

    AccessTokenIDEx tokenIdEx = TestCommon::GetHapTokenIdFromBundle(TEST_USER_ID, TEST_BUNDLE_NAME, 0);
    AccessTokenID tokenID = tokenIdEx.tokenIdExStruct.tokenID;
    ASSERT_NE(INVALID_TOKENID, tokenID);

    std::vector<PermissionStateFull> permStatList;
    int ret = AccessTokenKit::GetReqPermissions(TEST_TOKENID_INVALID, permStatList, false);
    ASSERT_EQ(AccessTokenError::ERR_PARAM_INVALID, ret);

    TestCommon::DeleteTestHapToken(tokenID);

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
    std::vector<std::string> reqPerm;
    reqPerm.emplace_back("ohos.permission.GET_SENSITIVE_PERMISSIONS");
    MockHapToken mockHap("GetReqPermissionsSpecTest001", reqPerm, true);

    AccessTokenIDEx tokenIdEx = TestCommon::GetHapTokenIdFromBundle(TEST_USER_ID, TEST_BUNDLE_NAME, 0);
    AccessTokenID tokenID = tokenIdEx.tokenIdExStruct.tokenID;
    ASSERT_NE(INVALID_TOKENID, tokenID);
    for (int i = 0; i < CYCLE_TIMES; i++) {
        std::vector<PermissionStateFull> permStatList;
        int32_t ret = AccessTokenKit::GetReqPermissions(tokenID, permStatList, false);
        ASSERT_EQ(RET_SUCCESS, ret);
        ASSERT_EQ(static_cast<uint32_t>(1), permStatList.size());
        ASSERT_EQ("ohos.permission.MICROPHONE", permStatList[0].permissionName);
    }
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
 * @tc.name: GetTokenIDByUserID001
 * @tc.desc: Get token id by user id.
 * @tc.type: FUNC
 * @tc.require: Issue Number
 */
HWTEST_F(GetPermissionTest, GetTokenIDByUserID001, TestSize.Level1)
{
    MockNativeToken mock("accesstoken_service");
    int32_t userID = -1;
    std::unordered_set<AccessTokenID> tokenIdList;
    int32_t ret = AccessTokenKit::GetTokenIDByUserID(userID, tokenIdList);
    EXPECT_EQ(AccessTokenError::ERR_PARAM_INVALID, ret);

    userID = 100;
    ret = AccessTokenKit::GetTokenIDByUserID(userID, tokenIdList);
    EXPECT_EQ(RET_SUCCESS, ret);
    EXPECT_NE(static_cast<uint32_t>(0), tokenIdList.size());
}

/**
 * @tc.name: ReloadNativeTokenInfo001
 * @tc.desc: test ReloadNativeTokenInfo.
 * @tc.type: FUNC
 * @tc.require: Issue Number
 */
HWTEST_F(GetPermissionTest, ReloadNativeTokenInfo001, TestSize.Level1)
{
    int32_t ret = AccessTokenKit::ReloadNativeTokenInfo();
    ASSERT_EQ(RET_SUCCESS, ret);
}

/**
 * @tc.name: GetKernelPermissionTest001
 * @tc.desc:
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(GetPermissionTest, GetKernelPermissionTest001, TestSize.Level1)
{
    std::vector<PermissionWithValue> kernelPermList;
    {
        // shell process， uid != 0
        MockNativeToken mock("hdcd"); // set shell for self
        setuid(1);
        EXPECT_EQ(AccessTokenError::ERR_PERMISSION_DENIED, AccessTokenKit::GetKernelPermissions(123, kernelPermList));
        setuid(0);
    }

    // native process
    MockNativeToken mock("accesstoken_service");
    EXPECT_EQ(AccessTokenError::ERR_TOKEN_INVALID, AccessTokenKit::GetKernelPermissions(123, kernelPermList));

    AccessTokenID tokenID = AccessTokenKit::GetHapTokenID(TEST_USER_ID, TEST_BUNDLE_NAME, 0);
    EXPECT_EQ(RET_SUCCESS, AccessTokenKit::GetKernelPermissions(tokenID, kernelPermList));
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
    std::string value;
    std::vector<PermissionWithValue> kernelPermList;
    {
        // shell process， uid != 0
        MockNativeToken mock("hdcd"); // set shell for self
        setuid(1);
        EXPECT_EQ(AccessTokenError::ERR_PERMISSION_DENIED,
            AccessTokenKit::GetReqPermissionByName(123, "ohos.permission.test1", value));
        setuid(0);
    }

    // native process， uid != 0
    MockNativeToken mock("accesstoken_service");
    EXPECT_EQ(AccessTokenError::ERR_TOKEN_INVALID,
        AccessTokenKit::GetReqPermissionByName(123, "ohos.permission.test1", value));

    AccessTokenID tokenID = AccessTokenKit::GetHapTokenID(TEST_USER_ID, TEST_BUNDLE_NAME, 0);
    EXPECT_EQ(AccessTokenError::ERR_PERMISSION_NOT_EXIST,
        AccessTokenKit::GetReqPermissionByName(tokenID, "ohos.permission.test1", value));

    EXPECT_EQ(AccessTokenError::ERR_PERMISSION_WITHOUT_VALUE,
        AccessTokenKit::GetReqPermissionByName(tokenID, "ohos.permission.MANAGE_HAP_TOKENID", value));
}
} // namespace AccessToken
} // namespace Security
} // namespace OHOS