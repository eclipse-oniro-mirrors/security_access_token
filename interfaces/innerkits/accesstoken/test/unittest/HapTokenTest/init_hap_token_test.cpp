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

#include "init_hap_token_test.h"
#include "gtest/gtest.h"
#include <thread>

#include "access_token.h"
#include "access_token_error.h"
#include "accesstoken_common_log.h"
#include "iaccess_token_manager.h"
#include "nativetoken_kit.h"
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
static constexpr uint32_t NUMBER_ONE = 1;
static constexpr uint32_t NUMBER_TWO = 2;
static constexpr uint32_t NUMBER_THREE = 3;
static uint64_t g_selfTokenId = 0;
static constexpr int32_t THIRTY_TIME_CYCLES = 30;
static constexpr int32_t MAX_EXTENDED_MAP_SIZE = 512;
static constexpr int32_t MAX_VALUE_LENGTH = 1024;
const std::string APP_DISTRIBUTION_TYPE_ENTERPRISE_MDM = "enterprise_mdm";
const std::string APP_DISTRIBUTION_TYPE_NONE = "none";
const std::string OVER_SIZE_STR =
    "AAANSUhEUgAAABUAAAAXCAIAAABrvZPKAAAACXBIWXMAAA7EAAAOxAGVKw4bAAAAEXRFWHRTb2Z0d2FyZQBTbmlwYXN0ZV0Xzt0A"
    "FBSURBVDiN7ZQ/S8NQFMVPxU/QCx06GBzrkqUZ42rBbHWUBDqYxSnUoTxXydCSycVsgltfBiFDR8HNdHGxY4nQQAPvMzwHsWn+KM"
    "vj3He5vIaUEjV0UAfe85X83KMBT7N75JEXVdSlfEAVfPRyZ5yfIrBoUkVlMU82Hkp8wu9ddt1vFew4sIiIiKwgzcXIvN7GTZOvpZ"
    "D3I1NZvmdCXz+XOv5wJANKHOVYjRTAghxIyh0FHKb+0QQH5+kXf2zkYGAG0oFr5RfnK8DAGkwY19wliRT2L448vjv0YGQFVa8VKd";

PermissionStateFull g_infoManagerManageHapState = {
    .permissionName = "ohos.permission.MANAGE_HAP_TOKENID",
    .isGeneral = true,
    .resDeviceID = {"test_device"},
    .grantStatus = {PermissionState::PERMISSION_GRANTED},
    .grantFlags = {PermissionFlag::PERMISSION_SYSTEM_FIXED}
};

PermissionStateFull g_infoManagerCameraState = {
    .permissionName = "ohos.permission.CAMERA",
    .isGeneral = true,
    .resDeviceID = {"local2"},
    .grantStatus = {PermissionState::PERMISSION_DENIED},
    .grantFlags = {0}
};

PermissionStateFull g_infoManagerMicrophoneState = {
    .permissionName = "ohos.permission.MICROPHONE",
    .isGeneral = true,
    .resDeviceID = {"local2"},
    .grantStatus = {PermissionState::PERMISSION_DENIED},
    .grantFlags = {0}
};

PermissionStateFull g_infoManagerCertState = {
    .permissionName = "ohos.permission.ACCESS_CERT_MANAGER",
    .isGeneral = true,
    .resDeviceID = {"local3"},
    .grantStatus = {PermissionState::PERMISSION_DENIED},
    .grantFlags = {0}
};

HapInfoParams g_testHapInfoParams = {
    .userID = 0,
    .bundleName = "InitHapTokenTest",
    .instIndex = 0,
    .appIDDesc = "InitHapTokenTest",
    .apiVersion = TestCommon::DEFAULT_API_VERSION,
    .isSystemApp = false,
    .appDistributionType = ""
};

HapPolicyParams g_testPolicyParams = {
    .apl = APL_SYSTEM_CORE,
    .domain = "test_domain",
    .permStateList = { g_infoManagerManageHapState },
    .aclRequestedList = {},
    .preAuthorizationInfo = {}
};
static MockNativeToken* g_mock;
};

void InitHapTokenTest::SetUpTestCase()
{
    g_selfTokenId = GetSelfTokenID();
    TestCommon::SetTestEvironment(g_selfTokenId);

    // native process with MANAGER_HAP_ID
    g_mock = new (std::nothrow) MockNativeToken("foundation");
}

void InitHapTokenTest::TearDownTestCase()
{
    if (g_mock != nullptr) {
        delete g_mock;
        g_mock = nullptr;
    }
    EXPECT_EQ(0, SetSelfTokenID(g_selfTokenId));
    TestCommon::ResetTestEvironment();
}

void InitHapTokenTest::SetUp()
{
    LOGI(ATM_DOMAIN, ATM_TAG, "SetUp ok.");
}

void InitHapTokenTest::TearDown()
{
}

/**
 * @tc.name: InitHapTokenFuncTest001
 * @tc.desc: Install normal applications(isSystemApp = false).
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(InitHapTokenTest, InitHapTokenFuncTest001, TestSize.Level0)
{
    LOGI(ATM_DOMAIN, ATM_TAG, "InitHapTokenFuncTest001");
    MockNativeToken mock("foundation");

    HapInfoParams infoParams;
    HapPolicyParams policyParams;
    TestCommon::GetHapParams(infoParams, policyParams);
    infoParams.isSystemApp = false;
    AccessTokenIDEx fullTokenId;
    ASSERT_EQ(RET_SUCCESS, AccessTokenKit::InitHapToken(infoParams, policyParams, fullTokenId));
    AccessTokenID tokenID = fullTokenId.tokenIdExStruct.tokenID;
    ASSERT_NE(INVALID_TOKENID, tokenID);

    ASSERT_FALSE(AccessTokenKit::IsSystemAppByFullTokenID(fullTokenId.tokenIDEx));

    HapTokenInfo hapInfo;
    ASSERT_EQ(RET_SUCCESS, AccessTokenKit::GetHapTokenInfo(tokenID, hapInfo));
    EXPECT_EQ(infoParams.userID, hapInfo.userID);
    EXPECT_EQ(infoParams.bundleName, hapInfo.bundleName);
    EXPECT_EQ(infoParams.apiVersion, hapInfo.apiVersion);
    EXPECT_EQ(infoParams.instIndex, hapInfo.instIndex);
    EXPECT_EQ(tokenID, hapInfo.tokenID);

    HapTokenInfoExt hapInfoExt;
    ASSERT_EQ(RET_SUCCESS, AccessTokenKit::GetHapTokenInfoExtension(tokenID, hapInfoExt));
    EXPECT_EQ(infoParams.appIDDesc, hapInfoExt.appID);

    ASSERT_EQ(RET_SUCCESS, AccessTokenKit::DeleteToken(tokenID));
}

/**
 * @tc.name: InitHapTokenFuncTest002
 * @tc.desc: Install systrem applications(isSystemApp = true).
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(InitHapTokenTest, InitHapTokenFuncTest002, TestSize.Level0)
{
    LOGI(ATM_DOMAIN, ATM_TAG, "InitHapTokenFuncTest002");
    MockNativeToken mock("foundation");

    HapInfoParams infoParams;
    HapPolicyParams policyParams;
    TestCommon::GetHapParams(infoParams, policyParams);
    infoParams.isSystemApp = true;
    AccessTokenIDEx fullTokenId;
    ASSERT_EQ(RET_SUCCESS, AccessTokenKit::InitHapToken(infoParams, policyParams, fullTokenId));
    AccessTokenID tokenID = fullTokenId.tokenIdExStruct.tokenID;
    ASSERT_NE(INVALID_TOKENID, tokenID);

    ASSERT_TRUE(AccessTokenKit::IsSystemAppByFullTokenID(fullTokenId.tokenIDEx));

    HapTokenInfo hapInfo;
    ASSERT_EQ(RET_SUCCESS, AccessTokenKit::GetHapTokenInfo(tokenID, hapInfo));
    EXPECT_EQ(infoParams.userID, hapInfo.userID);
    EXPECT_EQ(infoParams.bundleName, hapInfo.bundleName);
    EXPECT_EQ(infoParams.apiVersion, hapInfo.apiVersion);
    EXPECT_EQ(infoParams.instIndex, hapInfo.instIndex);
    EXPECT_EQ(tokenID, hapInfo.tokenID);

    HapTokenInfoExt hapInfoExt;
    ASSERT_EQ(RET_SUCCESS, AccessTokenKit::GetHapTokenInfoExtension(tokenID, hapInfoExt));
    EXPECT_EQ(infoParams.appIDDesc, hapInfoExt.appID);

    ASSERT_EQ(RET_SUCCESS, AccessTokenKit::DeleteToken(tokenID));
}

/**
 * @tc.name: InitHapTokenFuncTest003
 * @tc.desc: Test the isGeneral field in the permission authorization list(isGeneral is false or true).
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(InitHapTokenTest, InitHapTokenFuncTest003, TestSize.Level0)
{
    LOGI(ATM_DOMAIN, ATM_TAG, "InitHapTokenFuncTest003");
    MockNativeToken mock("foundation");

    HapInfoParams infoParams;
    HapPolicyParams policyParams;
    TestCommon::GetHapParams(infoParams, policyParams);
    policyParams.apl = APL_SYSTEM_CORE;

    PermissionStateFull permissionStateFull001 = {
        .permissionName = "ohos.permission.ACCESS_CERT_MANAGER",
        .isGeneral = false,
        .resDeviceID = {"local"},
        .grantStatus = {PERMISSION_GRANTED},
        .grantFlags = {PERMISSION_SYSTEM_FIXED}
    };

    PermissionStateFull permissionStateFull002 = {
        .permissionName = "ohos.permission.ACCESS_CERT_MANAGER_INTERNAL",
        .isGeneral = true,
        .resDeviceID = {"local"},
        .grantStatus = {PERMISSION_GRANTED},
        .grantFlags = {PERMISSION_SYSTEM_FIXED}
    };
    policyParams.permStateList = {permissionStateFull001, permissionStateFull002};
    AccessTokenIDEx fullTokenId;
    ASSERT_EQ(RET_SUCCESS, AccessTokenKit::InitHapToken(infoParams, policyParams, fullTokenId));
    AccessTokenID tokenID = fullTokenId.tokenIdExStruct.tokenID;
    ASSERT_NE(INVALID_TOKENID, tokenID);

    EXPECT_EQ(PERMISSION_GRANTED,
        AccessTokenKit::VerifyAccessToken(tokenID, "ohos.permission.ACCESS_CERT_MANAGER"));
    EXPECT_EQ(PERMISSION_GRANTED,
        AccessTokenKit::VerifyAccessToken(tokenID, "ohos.permission.ACCESS_CERT_MANAGER_INTERNAL"));

    ASSERT_EQ(RET_SUCCESS, AccessTokenKit::DeleteToken(tokenID));
}

/**
 * @tc.name: InitHapTokenFuncTest004
 * @tc.desc:Init a tokenId successfully, delete it successfully the first time and fail to delete it again.
 * @tc.type: FUNC
 * @tc.require: Issue Number
 */
HWTEST_F(InitHapTokenTest, InitHapTokenFuncTest004, TestSize.Level0)
{
    LOGI(ATM_DOMAIN, ATM_TAG, "InitHapTokenFuncTest004");
    MockNativeToken mock("foundation");

    AccessTokenIDEx fullTokenId;
    EXPECT_EQ(RET_SUCCESS, AccessTokenKit::InitHapToken(g_testHapInfoParams, g_testPolicyParams, fullTokenId));
    ASSERT_EQ(RET_SUCCESS, AccessTokenKit::DeleteToken(fullTokenId.tokenIdExStruct.tokenID));
    ASSERT_NE(RET_SUCCESS, AccessTokenKit::DeleteToken(fullTokenId.tokenIdExStruct.tokenID));
}

/**
 * @tc.name: InitHapTokenFuncTest005
 * @tc.desc: InitHapToken with dlp type.
 * @tc.type: FUNC
 * @tc.require: Issue Number
 */
HWTEST_F(InitHapTokenTest, InitHapTokenFuncTest005, TestSize.Level0)
{
    LOGI(ATM_DOMAIN, ATM_TAG, "InitHapTokenFuncTest005");
    MockNativeToken mock("foundation");

    HapInfoParams infoParams;
    HapPolicyParams policyParams;
    TestCommon::GetHapParams(infoParams, policyParams);
    policyParams.apl = APL_SYSTEM_BASIC;
    policyParams.permStateList  = { g_infoManagerCameraState, g_infoManagerMicrophoneState, g_infoManagerCertState };

    AccessTokenIDEx fullTokenId;
    EXPECT_EQ(RET_SUCCESS, AccessTokenKit::InitHapToken(infoParams, policyParams, fullTokenId));

    HapInfoParams infoParams1 = infoParams;
    infoParams1.dlpType = DLP_FULL_CONTROL;
    infoParams1.instIndex++;
    AccessTokenIDEx dlpFullTokenId1;
    EXPECT_EQ(RET_SUCCESS, AccessTokenKit::InitHapToken(infoParams1, policyParams, dlpFullTokenId1));

    int32_t res = AccessTokenKit::VerifyAccessToken(
        dlpFullTokenId1.tokenIdExStruct.tokenID, g_infoManagerCameraState.permissionName);
    EXPECT_EQ(res, PERMISSION_DENIED);

    (void)AccessTokenKit::GrantPermission(
        fullTokenId.tokenIdExStruct.tokenID, g_infoManagerCameraState.permissionName, PERMISSION_USER_SET);
    (void)AccessTokenKit::RevokePermission(
        fullTokenId.tokenIdExStruct.tokenID, g_infoManagerMicrophoneState.permissionName, PERMISSION_USER_SET);

    infoParams1.instIndex++;
    AccessTokenIDEx dlpFullTokenId2;
    EXPECT_EQ(RET_SUCCESS, AccessTokenKit::InitHapToken(infoParams1, policyParams, dlpFullTokenId2));
    res = AccessTokenKit::VerifyAccessToken(
        dlpFullTokenId2.tokenIdExStruct.tokenID, g_infoManagerCameraState.permissionName);
    EXPECT_EQ(res, PERMISSION_GRANTED);
    res = AccessTokenKit::VerifyAccessToken(
        dlpFullTokenId1.tokenIdExStruct.tokenID, g_infoManagerCameraState.permissionName);
    EXPECT_EQ(res, PERMISSION_GRANTED);

    std::vector<PermissionStateFull> permStatList1;
    res = AccessTokenKit::GetReqPermissions(fullTokenId.tokenIdExStruct.tokenID, permStatList1, false);
    ASSERT_EQ(RET_SUCCESS, res);
    std::vector<PermissionStateFull> permStatList2;
    res = AccessTokenKit::GetReqPermissions(dlpFullTokenId2.tokenIdExStruct.tokenID, permStatList2, false);
    ASSERT_EQ(permStatList2.size(), permStatList1.size());
    EXPECT_EQ("ohos.permission.CAMERA", permStatList2[0].permissionName);
    EXPECT_EQ(permStatList2[0].grantStatus[0], PERMISSION_GRANTED);
    EXPECT_EQ(permStatList2[0].grantFlags[0], PERMISSION_USER_SET);
    EXPECT_EQ("ohos.permission.MICROPHONE", permStatList2[1].permissionName);
    EXPECT_EQ(permStatList2[1].grantStatus[0], PERMISSION_DENIED);
    EXPECT_EQ(permStatList2[1].grantFlags[0], PERMISSION_USER_SET);
    ASSERT_EQ(RET_SUCCESS, res);

    ASSERT_EQ(RET_SUCCESS, AccessTokenKit::DeleteToken(fullTokenId.tokenIdExStruct.tokenID));
    ASSERT_EQ(RET_SUCCESS, AccessTokenKit::DeleteToken(dlpFullTokenId1.tokenIdExStruct.tokenID));
    ASSERT_EQ(RET_SUCCESS, AccessTokenKit::DeleteToken(dlpFullTokenId2.tokenIdExStruct.tokenID));
}

/**
 * @tc.name: InitHapTokenFuncTest006
 * @tc.desc: Install normal app success with input param result
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(InitHapTokenTest, InitHapTokenFuncTest006, TestSize.Level0)
{
    LOGI(ATM_DOMAIN, ATM_TAG, "InitHapTokenFuncTest006");
    MockNativeToken mock("foundation");

    HapInfoParams infoParams;
    HapPolicyParams policyParams;
    TestCommon::GetHapParams(infoParams, policyParams);
    infoParams.isSystemApp = false;
    AccessTokenIDEx fullTokenId;
    HapInfoCheckResult result;
    result.permCheckResult.permissionName = "test"; // invalid Name
    result.permCheckResult.rule = static_cast<PermissionRulesEnum>(-1); // invalid reasan
    ASSERT_EQ(RET_SUCCESS, AccessTokenKit::InitHapToken(infoParams, policyParams, fullTokenId, result));
    AccessTokenID tokenID = fullTokenId.tokenIdExStruct.tokenID;
    ASSERT_NE(INVALID_TOKENID, tokenID);
    ASSERT_EQ(result.permCheckResult.permissionName, "test");
    ASSERT_EQ(result.permCheckResult.rule, -1);

    ASSERT_EQ(RET_SUCCESS, AccessTokenKit::DeleteToken(tokenID));
}

/**
 * @tc.name: InitHapTokenFuncTest007
 * @tc.desc: Install normal app ignore acl check.
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(InitHapTokenTest, InitHapTokenFuncTest007, TestSize.Level0)
{
    LOGI(ATM_DOMAIN, ATM_TAG, "InitHapTokenFuncTest007");
    MockNativeToken mock("foundation");

    HapInfoParams infoParams;
    HapPolicyParams policyParams;
    TestCommon::GetHapParams(infoParams, policyParams);
    PermissionStateFull permStatDump = {
        .permissionName = "ohos.permission.DUMP",
        .isGeneral = true,
        .resDeviceID = {"device3"},
        .grantStatus = {PermissionState::PERMISSION_DENIED},
        .grantFlags = {PermissionFlag::PERMISSION_SYSTEM_FIXED}
    };
    policyParams.permStateList.emplace_back(permStatDump);

    // init fail, acl check fail
    AccessTokenIDEx fullTokenId;
    ASSERT_EQ(ERR_PERM_REQUEST_CFG_FAILED, AccessTokenKit::InitHapToken(infoParams, policyParams, fullTokenId));

    policyParams.checkIgnore = HapPolicyCheckIgnore::ACL_IGNORE_CHECK;
    ASSERT_EQ(RET_SUCCESS, AccessTokenKit::InitHapToken(infoParams, policyParams, fullTokenId));
    AccessTokenID tokenID = fullTokenId.tokenIdExStruct.tokenID;
    ASSERT_EQ(RET_SUCCESS, AccessTokenKit::DeleteToken(tokenID));
}

/**
 * @tc.name: InitHapTokenFuncTest008
 * @tc.desc: Install atomic app success
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(InitHapTokenTest, InitHapTokenFuncTest008, TestSize.Level0)
{
    LOGI(ATM_DOMAIN, ATM_TAG, "InitHapTokenFuncTest008");
    MockNativeToken mock("foundation");

    HapInfoParams infoParams;
    HapPolicyParams policyParams;
    TestCommon::GetHapParams(infoParams, policyParams);
    infoParams.isSystemApp = false;
    infoParams.isAtomicService = true;
    infoParams.bundleName = "install.atomic.service.test";
    AccessTokenIDEx fullTokenId;
    HapInfoCheckResult result;
    ASSERT_EQ(RET_SUCCESS, AccessTokenKit::InitHapToken(infoParams, policyParams, fullTokenId, result));
    ASSERT_TRUE(AccessTokenKit::IsAtomicServiceByFullTokenID(static_cast<uint64_t>(fullTokenId.tokenIDEx)));

    AccessTokenIDEx tokenIDEx = AccessTokenKit::GetHapTokenIDEx(
        infoParams.userID, infoParams.bundleName, infoParams.instIndex);
    ASSERT_TRUE(AccessTokenKit::IsAtomicServiceByFullTokenID(static_cast<uint64_t>(tokenIDEx.tokenIDEx)));
    EXPECT_EQ(tokenIDEx.tokenIDEx, fullTokenId.tokenIDEx);

    AccessTokenID tokenID = fullTokenId.tokenIdExStruct.tokenID;
    HapTokenInfo hapTokenInfoRes;
    ASSERT_EQ(RET_SUCCESS, AccessTokenKit::GetHapTokenInfo(tokenID, hapTokenInfoRes));
    EXPECT_EQ(NUMBER_TWO, hapTokenInfoRes.tokenAttr);

    ASSERT_EQ(RET_SUCCESS, AccessTokenKit::DeleteToken(tokenID));
}

/**
 * @tc.name: InitHapTokenFuncTest009
 * @tc.desc: Install the system service app and update it as a atomic service
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(InitHapTokenTest, InitHapTokenFuncTest009, TestSize.Level0)
{
    LOGI(ATM_DOMAIN, ATM_TAG, "InitHapTokenFuncTest009");
    MockNativeToken mock("foundation");

    HapInfoParams infoParams;
    HapPolicyParams policyParams;
    TestCommon::GetHapParams(infoParams, policyParams);
    infoParams.isSystemApp = true;
    infoParams.bundleName = "update.atomic.service.test";
    AccessTokenIDEx fullTokenId;
    HapInfoCheckResult result;
    ASSERT_EQ(RET_SUCCESS, AccessTokenKit::InitHapToken(infoParams, policyParams, fullTokenId, result));
    ASSERT_TRUE(AccessTokenKit::IsSystemAppByFullTokenID(static_cast<uint64_t>(fullTokenId.tokenIDEx)));
    ASSERT_FALSE(AccessTokenKit::IsAtomicServiceByFullTokenID(static_cast<uint64_t>(fullTokenId.tokenIDEx)));

    UpdateHapInfoParams info;
    info.appIDDesc = infoParams.appIDDesc;
    info.apiVersion = infoParams.apiVersion;
    info.isSystemApp = infoParams.isSystemApp;
    info.appDistributionType = infoParams.appDistributionType;
    info.isAtomicService = true;
    ASSERT_EQ(RET_SUCCESS, AccessTokenKit::UpdateHapToken(fullTokenId, info, policyParams));
    ASSERT_TRUE(AccessTokenKit::IsSystemAppByFullTokenID(static_cast<uint64_t>(fullTokenId.tokenIDEx)));
    ASSERT_TRUE(AccessTokenKit::IsAtomicServiceByFullTokenID(static_cast<uint64_t>(fullTokenId.tokenIDEx)));

    AccessTokenID tokenID = fullTokenId.tokenIdExStruct.tokenID;
    HapTokenInfo hapTokenInfoRes;
    ASSERT_EQ(RET_SUCCESS, AccessTokenKit::GetHapTokenInfo(tokenID, hapTokenInfoRes));
    EXPECT_EQ(NUMBER_THREE, hapTokenInfoRes.tokenAttr);

    info.isAtomicService = false;
    ASSERT_EQ(RET_SUCCESS, AccessTokenKit::UpdateHapToken(fullTokenId, info, policyParams));
    ASSERT_TRUE(AccessTokenKit::IsSystemAppByFullTokenID(static_cast<uint64_t>(fullTokenId.tokenIDEx)));
    ASSERT_FALSE(AccessTokenKit::IsAtomicServiceByFullTokenID(static_cast<uint64_t>(fullTokenId.tokenIDEx)));
    ASSERT_EQ(RET_SUCCESS, AccessTokenKit::GetHapTokenInfo(tokenID, hapTokenInfoRes));
    EXPECT_EQ(NUMBER_ONE, hapTokenInfoRes.tokenAttr);

    ASSERT_EQ(RET_SUCCESS, AccessTokenKit::DeleteToken(tokenID));
}

/**
 * @tc.name: InitHapTokenSpecsTest001
 * @tc.desc: Test  request the high-level permission authorized by acl.
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(InitHapTokenTest, InitHapTokenSpecsTest001, TestSize.Level0)
{
    LOGI(ATM_DOMAIN, ATM_TAG, "InitHapTokenSpecsTest001");
    MockNativeToken mock("foundation");

    HapInfoParams infoParams;
    HapPolicyParams policyParams;
    TestCommon::GetHapParams(infoParams, policyParams);
    policyParams.apl = APL_NORMAL;

    PermissionStateFull permissionStateFull001 = {
        .permissionName = "ohos.permission.RUN_DYN_CODE",
        .isGeneral = true,
        .resDeviceID = {"local"},
        .grantStatus = {PERMISSION_DENIED},
        .grantFlags = {PERMISSION_SYSTEM_FIXED}
    };

    PermissionStateFull permissionStateFull002 = {
        .permissionName = "ohos.permission.ACCESS_DDK_USB",
        .isGeneral = true,
        .resDeviceID = {"local"},
        .grantStatus = {PERMISSION_DENIED},
        .grantFlags = {PERMISSION_SYSTEM_FIXED}
    };

    policyParams.permStateList = {permissionStateFull001, permissionStateFull002};
    policyParams.aclRequestedList = {"ohos.permission.ACCESS_DDK_USB"};
    AccessTokenIDEx fullTokenId;
    ASSERT_EQ(RET_SUCCESS, AccessTokenKit::InitHapToken(infoParams, policyParams, fullTokenId));
    AccessTokenID tokenID = fullTokenId.tokenIdExStruct.tokenID;

    int32_t ret = AccessTokenKit::VerifyAccessToken(tokenID, "ohos.permission.RUN_DYN_CODE");
    EXPECT_EQ(PERMISSION_GRANTED, ret);
    ret = AccessTokenKit::VerifyAccessToken(tokenID, "ohos.permission.ACCESS_DDK_USB");
    EXPECT_EQ(PERMISSION_GRANTED, ret);

    ASSERT_EQ(RET_SUCCESS, AccessTokenKit::DeleteToken(tokenID));
}

/**
 * @tc.name: InitHapTokenSpecsTest002
 * @tc.desc: Test apl level does not match application level.
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(InitHapTokenTest, InitHapTokenSpecsTest002, TestSize.Level0)
{
    LOGI(ATM_DOMAIN, ATM_TAG, "InitHapTokenSpecsTest002");
    MockNativeToken mock("foundation");

    HapInfoParams infoParams;
    HapPolicyParams policyParams;
    TestCommon::GetHapParams(infoParams, policyParams);
    policyParams.apl = APL_NORMAL;

    PermissionStateFull permissionStateFull001 = {
        .permissionName = "ohos.permission.RUN_DYN_CODE",
        .isGeneral = true,
        .resDeviceID = {"local"},
        .grantStatus = {PERMISSION_DENIED},
        .grantFlags = {PERMISSION_SYSTEM_FIXED}
    };

    PermissionStateFull permissionStateFull002 = {
        .permissionName = "ohos.permission.ACCESS_DDK_USB",
        .isGeneral = true,
        .resDeviceID = {"local"},
        .grantStatus = {PERMISSION_DENIED},
        .grantFlags = {PERMISSION_SYSTEM_FIXED}
    };

    policyParams.permStateList = {permissionStateFull001, permissionStateFull002};
    AccessTokenIDEx fullTokenId;
    HapInfoCheckResult result;
    ASSERT_EQ(ERR_PERM_REQUEST_CFG_FAILED, AccessTokenKit::InitHapToken(infoParams, policyParams, fullTokenId, result));
    ASSERT_EQ(result.permCheckResult.permissionName, "ohos.permission.ACCESS_DDK_USB");
    ASSERT_EQ(result.permCheckResult.rule, PERMISSION_ACL_RULE);
}

/**
 * @tc.name: InitHapTokenSpecsTest003
 * @tc.desc: Initialize system_grant&&user_grant permission.
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(InitHapTokenTest, InitHapTokenSpecsTest003, TestSize.Level0)
{
    LOGI(ATM_DOMAIN, ATM_TAG, "InitHapTokenSpecsTest003");
    MockNativeToken mock("foundation");

    HapInfoParams infoParams;
    HapPolicyParams policyParams;
    TestCommon::GetHapParams(infoParams, policyParams);
    policyParams.apl = APL_SYSTEM_CORE;

    PermissionStateFull permissionStateFull001 = {
        .permissionName = "ohos.permission.READ_HEALTH_MOTION",
        .isGeneral = true,
        .resDeviceID = {"local"},
        .grantStatus = {PERMISSION_DENIED},
        .grantFlags = {PERMISSION_SYSTEM_FIXED}
    };

    PermissionStateFull permissionStateFull002 = {
        .permissionName = "ohos.permission.READ_WRITE_DESKTOP_DIRECTORY",
        .isGeneral = true,
        .resDeviceID = {"local"},
        .grantStatus = {PERMISSION_DENIED},
        .grantFlags = {PERMISSION_SYSTEM_FIXED}
    };

    policyParams.permStateList = {permissionStateFull001, permissionStateFull002};

    AccessTokenIDEx fullTokenId;
    ASSERT_EQ(RET_SUCCESS, AccessTokenKit::InitHapToken(infoParams, policyParams, fullTokenId));
    AccessTokenID tokenID = fullTokenId.tokenIdExStruct.tokenID;

    int32_t ret = AccessTokenKit::VerifyAccessToken(tokenID, "ohos.permission.READ_HEALTH_MOTION");
    EXPECT_EQ(PERMISSION_GRANTED, ret);
    ret = AccessTokenKit::VerifyAccessToken(tokenID, "ohos.permission.READ_WRITE_DESKTOP_DIRECTORY");
    EXPECT_EQ(PERMISSION_DENIED, ret);

    uint32_t flag;
    ret = AccessTokenKit::GetPermissionFlag(tokenID, "ohos.permission.READ_HEALTH_MOTION", flag);
    EXPECT_EQ(RET_SUCCESS, ret);
    EXPECT_EQ(PERMISSION_SYSTEM_FIXED, flag);
    ret = AccessTokenKit::GetPermissionFlag(tokenID, "ohos.permission.READ_WRITE_DESKTOP_DIRECTORY", flag);
    EXPECT_EQ(RET_SUCCESS, ret);
    EXPECT_EQ(PERMISSION_DEFAULT_FLAG, flag);

    ASSERT_EQ(RET_SUCCESS, AccessTokenKit::DeleteToken(tokenID));
}

/**
 * @tc.name: InitHapTokenSpecsTest004
 * @tc.desc: Initialize cancelable/un-cancelable permission.
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(InitHapTokenTest, InitHapTokenSpecsTest004, TestSize.Level0)
{
    LOGI(ATM_DOMAIN, ATM_TAG, "InitHapTokenSpecsTest004");
    MockNativeToken mock("foundation");

    HapInfoParams infoParams;
    HapPolicyParams policyParams;
    TestCommon::GetHapParams(infoParams, policyParams);
    policyParams.apl = APL_SYSTEM_CORE;

    PermissionStateFull permissionStateFull001 = {
        .permissionName = "ohos.permission.ACCESS_NEARLINK",
        .isGeneral = true,
        .resDeviceID = {"local"},
        .grantStatus = {PERMISSION_DENIED},
        .grantFlags = {PERMISSION_SYSTEM_FIXED}
    };

    PermissionStateFull permissionStateFull002 = {
        .permissionName = "ohos.permission.READ_WRITE_DESKTOP_DIRECTORY",
        .isGeneral = true,
        .resDeviceID = {"local"},
        .grantStatus = {PERMISSION_DENIED},
        .grantFlags = {PERMISSION_SYSTEM_FIXED}
    };

    policyParams.permStateList = {permissionStateFull001, permissionStateFull002};
    PreAuthorizationInfo preAuthorizationInfo001 = {
        .permissionName = "ohos.permission.ACCESS_NEARLINK",
        .userCancelable = true
    };
    PreAuthorizationInfo preAuthorizationInfo002 = {
        .permissionName = "ohos.permission.READ_WRITE_DESKTOP_DIRECTORY",
        .userCancelable = false
    };
    policyParams.preAuthorizationInfo = {preAuthorizationInfo001, preAuthorizationInfo002};
    AccessTokenIDEx fullTokenId;
    ASSERT_EQ(RET_SUCCESS, AccessTokenKit::InitHapToken(infoParams, policyParams, fullTokenId));
    AccessTokenID tokenID = fullTokenId.tokenIdExStruct.tokenID;

    int32_t ret = AccessTokenKit::VerifyAccessToken(tokenID, "ohos.permission.ACCESS_NEARLINK");
    EXPECT_EQ(PERMISSION_GRANTED, ret);
    ret = AccessTokenKit::VerifyAccessToken(tokenID, "ohos.permission.READ_WRITE_DESKTOP_DIRECTORY");
    EXPECT_EQ(PERMISSION_GRANTED, ret);

    std::vector<PermissionStateFull> permStatList;
    ASSERT_EQ(RET_SUCCESS, AccessTokenKit::GetReqPermissions(tokenID, permStatList, false));
    ASSERT_EQ(static_cast<uint32_t>(2), permStatList.size());
    ASSERT_EQ("ohos.permission.ACCESS_NEARLINK", permStatList[0].permissionName);
    EXPECT_EQ(permStatList[0].grantStatus[0], PERMISSION_GRANTED);
    EXPECT_EQ(permStatList[0].grantFlags[0], PERMISSION_PRE_AUTHORIZED_CANCELABLE);
    ASSERT_EQ("ohos.permission.READ_WRITE_DESKTOP_DIRECTORY", permStatList[1].permissionName);
    EXPECT_EQ(permStatList[1].grantStatus[0], PERMISSION_GRANTED);
    EXPECT_EQ(permStatList[1].grantFlags[0], PERMISSION_SYSTEM_FIXED);

    ASSERT_EQ(RET_SUCCESS, AccessTokenKit::DeleteToken(tokenID));
}

/**
 * @tc.name: InitHapTokenSpecsTest005
 * @tc.desc: User grant permission not pre-authorized, grant state is PERMISSION_DENIED
 * @tc.type: FUNC
 * @tc.require: Issue Number
 */
HWTEST_F(InitHapTokenTest, InitHapTokenSpecsTest005, TestSize.Level0)
{
    LOGI(ATM_DOMAIN, ATM_TAG, "InitHapTokenSpecsTest005");
    MockNativeToken mock("foundation");

    HapInfoParams infoParams;
    HapPolicyParams policyParams;
    TestCommon::GetHapParams(infoParams, policyParams);
    policyParams.apl = APL_NORMAL;
    policyParams.permStateList = { g_infoManagerMicrophoneState };
    AccessTokenIDEx fullTokenId;
    int32_t res = AccessTokenKit::InitHapToken(infoParams, policyParams, fullTokenId);
    EXPECT_EQ(RET_SUCCESS, res);
    int32_t ret = AccessTokenKit::VerifyAccessToken(
        fullTokenId.tokenIdExStruct.tokenID, "ohos.permission.MICROPHONE");
    EXPECT_EQ(ret, PERMISSION_DENIED);
    uint32_t flag;
    AccessTokenKit::GetPermissionFlag(
        fullTokenId.tokenIdExStruct.tokenID, "ohos.permission.MICROPHONE", flag);
    EXPECT_EQ(flag, PERMISSION_DEFAULT_FLAG);
    ASSERT_EQ(RET_SUCCESS, AccessTokenKit::DeleteToken(fullTokenId.tokenIdExStruct.tokenID));
}

/**
 * @tc.name: InitHapTokenSpecsTest006
 * @tc.desc: Initialize MDM permission for a MDM hap.
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(InitHapTokenTest, InitHapTokenSpecsTest006, TestSize.Level0)
{
    LOGI(ATM_DOMAIN, ATM_TAG, "InitHapTokenSpecsTest006");
    MockNativeToken mock("foundation");

    HapInfoParams infoParams;
    HapPolicyParams policyParams;
    TestCommon::GetHapParams(infoParams, policyParams);
    policyParams.apl = APL_SYSTEM_CORE;
    infoParams.appDistributionType = APP_DISTRIBUTION_TYPE_ENTERPRISE_MDM;
    PermissionStateFull permissionStateFull001 = {
        .permissionName = "ohos.permission.ENTERPRISE_MANAGE_SETTINGS",
        .isGeneral = true,
        .resDeviceID = {"local"},
        .grantStatus = {PERMISSION_DENIED},
        .grantFlags = {PERMISSION_SYSTEM_FIXED}
    };
    policyParams.permStateList = {permissionStateFull001};
    AccessTokenIDEx fullTokenId;
    int32_t ret = AccessTokenKit::InitHapToken(infoParams, policyParams, fullTokenId);
    AccessTokenID tokenID = fullTokenId.tokenIdExStruct.tokenID;
    ASSERT_EQ(RET_SUCCESS, ret);

    ret = AccessTokenKit::VerifyAccessToken(tokenID, "ohos.permission.ENTERPRISE_MANAGE_SETTINGS");
    EXPECT_EQ(PERMISSION_GRANTED, ret);

    uint32_t flag;
    ret = AccessTokenKit::GetPermissionFlag(tokenID, "ohos.permission.ENTERPRISE_MANAGE_SETTINGS", flag);
    EXPECT_EQ(RET_SUCCESS, ret);
    EXPECT_EQ(PERMISSION_SYSTEM_FIXED, flag);

    ASSERT_EQ(RET_SUCCESS, AccessTokenKit::DeleteToken(tokenID));
}

/**
 * @tc.name: InitHapTokenSpecsTest007
 * @tc.desc: Initialize MDM permission for a Non-MDM hap.
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(InitHapTokenTest, InitHapTokenSpecsTest007, TestSize.Level0)
{
    LOGI(ATM_DOMAIN, ATM_TAG, "InitHapTokenSpecsTest007");
    MockNativeToken mock("foundation");

    HapInfoParams infoParams;
    HapPolicyParams policyParams;
    TestCommon::GetHapParams(infoParams, policyParams);

    PermissionStateFull permissionStateFull001 = {
        .permissionName = "ohos.permission.ENTERPRISE_MANAGE_SETTINGS",
        .isGeneral = true,
        .resDeviceID = {"local"},
        .grantStatus = {PERMISSION_DENIED},
        .grantFlags = {PERMISSION_SYSTEM_FIXED}
    };
    policyParams.permStateList = {permissionStateFull001};
    policyParams.aclRequestedList = { "ohos.permission.ENTERPRISE_MANAGE_SETTINGS" };
    AccessTokenIDEx fullTokenId;
    int32_t ret = AccessTokenKit::InitHapToken(infoParams, policyParams, fullTokenId);
    AccessTokenID tokenID = fullTokenId.tokenIdExStruct.tokenID;
    ASSERT_EQ(ERR_PERM_REQUEST_CFG_FAILED, ret);

    HapInfoCheckResult result;
    ret = AccessTokenKit::InitHapToken(infoParams, policyParams, fullTokenId, result);
    ASSERT_EQ(ERR_PERM_REQUEST_CFG_FAILED, ret);
    ASSERT_EQ(result.permCheckResult.permissionName, "ohos.permission.ENTERPRISE_MANAGE_SETTINGS");
    ASSERT_EQ(result.permCheckResult.rule, PERMISSION_EDM_RULE);

    ret = AccessTokenKit::VerifyAccessToken(tokenID, "ohos.permission.ENTERPRISE_MANAGE_SETTINGS");
    EXPECT_EQ(PERMISSION_DENIED, ret);
}

/**
 * @tc.name: InitHapTokenSpecsTest008
 * @tc.desc: Initialize MDM permission for a debug hap.
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(InitHapTokenTest, InitHapTokenSpecsTest008, TestSize.Level0)
{
    LOGI(ATM_DOMAIN, ATM_TAG, "InitHapTokenSpecsTest008");
    MockNativeToken mock("foundation");

    HapInfoParams infoParams;
    HapPolicyParams policyParams;
    TestCommon::GetHapParams(infoParams, policyParams);
    policyParams.apl = APL_SYSTEM_CORE;
    infoParams.appDistributionType = APP_DISTRIBUTION_TYPE_NONE;
    PermissionStateFull permissionStateFull001 = {
        .permissionName = "ohos.permission.ENTERPRISE_MANAGE_SETTINGS",
        .isGeneral = true,
        .resDeviceID = {"local"},
        .grantStatus = {PERMISSION_DENIED},
        .grantFlags = {PERMISSION_SYSTEM_FIXED}
    };
    policyParams.permStateList = {permissionStateFull001};
    AccessTokenIDEx fullTokenId;
    int32_t ret = AccessTokenKit::InitHapToken(infoParams, policyParams, fullTokenId);
    AccessTokenID tokenID = fullTokenId.tokenIdExStruct.tokenID;
    ASSERT_EQ(RET_SUCCESS, ret);

    ret = AccessTokenKit::VerifyAccessToken(tokenID, "ohos.permission.ENTERPRISE_MANAGE_SETTINGS");
    EXPECT_EQ(PERMISSION_GRANTED, ret);

    uint32_t flag;
    ret = AccessTokenKit::GetPermissionFlag(tokenID, "ohos.permission.ENTERPRISE_MANAGE_SETTINGS", flag);
    EXPECT_EQ(RET_SUCCESS, ret);
    EXPECT_EQ(PERMISSION_SYSTEM_FIXED, flag);

    ASSERT_EQ(RET_SUCCESS, AccessTokenKit::DeleteToken(tokenID));
}

/**
 * @tc.name: InitHapTokenSpecsTest009
 * @tc.desc: InitHapToken isRestore with real token
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(InitHapTokenTest, InitHapTokenSpecsTest009, TestSize.Level0)
{
    MockNativeToken mock("foundation");
    HapInfoParams infoParams;
    HapPolicyParams policyParams;
    TestCommon::GetHapParams(infoParams, policyParams);
    policyParams.apl = APL_SYSTEM_CORE;

    PermissionStateFull permissionStateFull001 = {
        .permissionName = "ohos.permission.ACCESS_CERT_MANAGER",
        .isGeneral = false,
        .resDeviceID = {"local"},
        .grantStatus = {PERMISSION_GRANTED},
        .grantFlags = {PERMISSION_SYSTEM_FIXED}
    };

    policyParams.permStateList = {permissionStateFull001, g_infoManagerCameraState};
    AccessTokenIDEx fullTokenId;
    int32_t ret = AccessTokenKit::InitHapToken(infoParams, policyParams, fullTokenId);
    AccessTokenID tokenID = fullTokenId.tokenIdExStruct.tokenID;
    ASSERT_EQ(RET_SUCCESS, ret);

    ret = AccessTokenKit::VerifyAccessToken(tokenID, "ohos.permission.ACCESS_CERT_MANAGER");
    EXPECT_EQ(PERMISSION_GRANTED, ret);

    (void)AccessTokenKit::GrantPermission(tokenID, "ohos.permission.CAMERA", PERMISSION_USER_SET);
    ret = AccessTokenKit::VerifyAccessToken(tokenID, "ohos.permission.CAMERA");
    EXPECT_EQ(ret, PERMISSION_GRANTED);

    ret = AccessTokenKit::DeleteToken(tokenID);
    EXPECT_EQ(RET_SUCCESS, ret);

    infoParams.isRestore = true;
    infoParams.tokenID = tokenID;
    ret = AccessTokenKit::InitHapToken(infoParams, policyParams, fullTokenId);
    EXPECT_EQ(RET_SUCCESS, ret);

    ret = AccessTokenKit::VerifyAccessToken(tokenID, "ohos.permission.ACCESS_CERT_MANAGER");
    EXPECT_EQ(PERMISSION_GRANTED, ret);

    ret = AccessTokenKit::VerifyAccessToken(tokenID, "ohos.permission.CAMERA");
    EXPECT_EQ(ret, PERMISSION_DENIED);

    ASSERT_EQ(RET_SUCCESS, AccessTokenKit::DeleteToken(tokenID));
}

/**
 * @tc.name: InitHapTokenSpecsTest010
 * @tc.desc: aclExtendedMap size test
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(InitHapTokenTest, InitHapTokenSpecsTest010, TestSize.Level0)
{
    HapInfoParams infoParams;
    HapPolicyParams policyParams;
    TestCommon::GetHapParams(infoParams, policyParams);
    policyParams.apl = APL_SYSTEM_CORE;

    AccessTokenIDEx fullTokenId;
    int32_t ret = AccessTokenKit::InitHapToken(infoParams, policyParams, fullTokenId);
    ASSERT_EQ(RET_SUCCESS, ret);

    for (size_t i = 0; i < MAX_EXTENDED_MAP_SIZE - 1; i++) {
        policyParams.aclExtendedMap[std::to_string(i)] = std::to_string(i);
    }
    ret = AccessTokenKit::InitHapToken(infoParams, policyParams, fullTokenId);
    ASSERT_EQ(RET_SUCCESS, ret);

    policyParams.aclExtendedMap[std::to_string(MAX_EXTENDED_MAP_SIZE - 1)] =
        std::to_string(MAX_EXTENDED_MAP_SIZE - 1);
    ret = AccessTokenKit::InitHapToken(infoParams, policyParams, fullTokenId);
    ASSERT_EQ(RET_SUCCESS, ret);

    policyParams.aclExtendedMap[std::to_string(MAX_EXTENDED_MAP_SIZE)] =
        std::to_string(MAX_EXTENDED_MAP_SIZE);
    ret = AccessTokenKit::InitHapToken(infoParams, policyParams, fullTokenId);
    ASSERT_EQ(AccessTokenError::ERR_PARAM_INVALID, ret);
    AccessTokenID tokenID = fullTokenId.tokenIdExStruct.tokenID;
    ret = AccessTokenKit::DeleteToken(tokenID);
    EXPECT_EQ(RET_SUCCESS, ret);
}

/**
 * @tc.name: InitHapTokenSpecsTest011
 * @tc.desc: aclExtendedMap content size test
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(InitHapTokenTest, InitHapTokenSpecsTest011, TestSize.Level0)
{
    HapInfoParams infoParams;
    HapPolicyParams policyParams;
    TestCommon::GetHapParams(infoParams, policyParams);
    policyParams.apl = APL_SYSTEM_CORE;

    AccessTokenIDEx fullTokenId;
    policyParams.aclExtendedMap["ohos.permission.ACCESS_CERT_MANAGER"] = "";
    int32_t ret = AccessTokenKit::InitHapToken(infoParams, policyParams, fullTokenId);
    ASSERT_EQ(AccessTokenError::ERR_PARAM_INVALID, ret);

    std::string testValue(MAX_VALUE_LENGTH - 1, '1');
    policyParams.aclExtendedMap["ohos.permission.ACCESS_CERT_MANAGER"] = testValue;
    ret = AccessTokenKit::InitHapToken(infoParams, policyParams, fullTokenId);
    ASSERT_EQ(RET_SUCCESS, ret);

    testValue.push_back('1');
    policyParams.aclExtendedMap["ohos.permission.ACCESS_CERT_MANAGER"] = testValue;
    ret = AccessTokenKit::InitHapToken(infoParams, policyParams, fullTokenId);
    ASSERT_EQ(RET_SUCCESS, ret);
    AccessTokenID tokenID = fullTokenId.tokenIdExStruct.tokenID;

    testValue.push_back('1');
    policyParams.aclExtendedMap["ohos.permission.ACCESS_CERT_MANAGER"] = testValue;
    ret = AccessTokenKit::InitHapToken(infoParams, policyParams, fullTokenId);
    ASSERT_EQ(AccessTokenError::ERR_PARAM_INVALID, ret);

    ret = AccessTokenKit::DeleteToken(tokenID);
    EXPECT_EQ(RET_SUCCESS, ret);
}

/**
 * @tc.name: InitHapTokenSpecsTest012
 * @tc.desc: InitHapToken permission with value
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(InitHapTokenTest, InitHapTokenSpecsTest012, TestSize.Level0)
{
    HapInfoParams infoParams;
    HapPolicyParams policyParams;
    TestCommon::GetHapParams(infoParams, policyParams);
    policyParams.apl = APL_SYSTEM_CORE;
    TestCommon::TestPrepareKernelPermissionStatus(policyParams);
    AccessTokenIDEx fullTokenId;
    ASSERT_EQ(RET_SUCCESS, AccessTokenKit::InitHapToken(infoParams, policyParams, fullTokenId));
    AccessTokenID tokenID = fullTokenId.tokenIdExStruct.tokenID;

    std::vector<PermissionWithValue> kernelPermList;
    EXPECT_EQ(RET_SUCCESS, AccessTokenKit::GetKernelPermissions(tokenID, kernelPermList));
    EXPECT_EQ(1, kernelPermList.size());

    std::string value;
    EXPECT_EQ(RET_SUCCESS, AccessTokenKit::GetReqPermissionByName(
        tokenID, "ohos.permission.KERNEL_ATM_SELF_USE", value));
    EXPECT_EQ("123", value);

    EXPECT_EQ(AccessTokenError::ERR_PERMISSION_WITHOUT_VALUE, AccessTokenKit::GetReqPermissionByName(
        tokenID, "ohos.permission.MICROPHONE", value));
    EXPECT_EQ(AccessTokenError::ERR_PERMISSION_WITHOUT_VALUE, AccessTokenKit::GetReqPermissionByName(
        tokenID, "ohos.permission.CAMERA", value));

    ASSERT_EQ(RET_SUCCESS, AccessTokenKit::DeleteToken(tokenID));
}

/**
 * @tc.name: InitHapTokenSpecsTest013
 * @tc.desc: InitHapToken is called repeatly, tokenId will change
 *          1. first tokenId is delete; 2. second token is valid
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(InitHapTokenTest, InitHapTokenSpecsTest013, TestSize.Level0)
{
    MockNativeToken mock("foundation");
    HapInfoParams infoParams;
    HapPolicyParams policyParams;
    TestCommon::GetHapParams(infoParams, policyParams);
    AccessTokenIDEx tokenIdEx1;
    ASSERT_EQ(RET_SUCCESS, AccessTokenKit::InitHapToken(infoParams, policyParams, tokenIdEx1));

    AccessTokenIDEx tokenIdEx2;
    ASSERT_EQ(RET_SUCCESS, AccessTokenKit::InitHapToken(infoParams, policyParams, tokenIdEx2));

    ASSERT_NE(tokenIdEx1.tokenIdExStruct.tokenID, tokenIdEx2.tokenIdExStruct.tokenID);

    HapTokenInfo hapInfo;
    ASSERT_EQ(ERR_TOKENID_NOT_EXIST, AccessTokenKit::GetHapTokenInfo(tokenIdEx1.tokenIdExStruct.tokenID, hapInfo));
    ASSERT_EQ(RET_SUCCESS, AccessTokenKit::GetHapTokenInfo(tokenIdEx2.tokenIdExStruct.tokenID, hapInfo));

    EXPECT_EQ(ERR_PARAM_INVALID, AccessTokenKit::DeleteToken(tokenIdEx1.tokenIdExStruct.tokenID));
    EXPECT_EQ(RET_SUCCESS, AccessTokenKit::DeleteToken(tokenIdEx2.tokenIdExStruct.tokenID));
}

/**
 * @tc.name: InitHapTokenSpecsTest014
 * @tc.desc: app.apl > policy.apl, extended permission not in aclExtendedMap
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(InitHapTokenTest, InitHapTokenSpecsTest014, TestSize.Level0)
{
    HapInfoParams infoParams;
    HapPolicyParams policyParams;
    TestCommon::GetHapParams(infoParams, policyParams);
    policyParams.apl = APL_SYSTEM_CORE;
    TestCommon::TestPrepareKernelPermissionStatus(policyParams);
    policyParams.aclExtendedMap.erase("ohos.permission.KERNEL_ATM_SELF_USE");
    AccessTokenIDEx fullTokenId;
    ASSERT_EQ(RET_SUCCESS, AccessTokenKit::InitHapToken(infoParams, policyParams, fullTokenId));
    AccessTokenID tokenID = fullTokenId.tokenIdExStruct.tokenID;

    std::vector<PermissionWithValue> kernelPermList;
    EXPECT_EQ(RET_SUCCESS, AccessTokenKit::GetKernelPermissions(tokenID, kernelPermList));
    EXPECT_EQ(1, kernelPermList.size());

    std::string value;
    EXPECT_EQ(RET_SUCCESS, AccessTokenKit::GetReqPermissionByName(
        tokenID, "ohos.permission.KERNEL_ATM_SELF_USE", value));
    EXPECT_EQ("", value);

    EXPECT_EQ(PERMISSION_GRANTED, AccessTokenKit::VerifyAccessToken(
        tokenID, "ohos.permission.KERNEL_ATM_SELF_USE"));

    ASSERT_EQ(RET_SUCCESS, AccessTokenKit::DeleteToken(tokenID));
}

/**
 * @tc.name: InitHapTokenAbnormalTest001
 * @tc.desc: Invaild HapInfoParams.
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(InitHapTokenTest, InitHapTokenAbnormalTest001, TestSize.Level0)
{
    LOGI(ATM_DOMAIN, ATM_TAG, "InitHapTokenAbnormalTest001");

    HapInfoParams infoParams;
    HapPolicyParams policyParams;
    TestCommon::GetHapParams(infoParams, policyParams);
    infoParams.userID = -1;
    AccessTokenIDEx fullTokenId;
    int32_t ret = AccessTokenKit::InitHapToken(infoParams, policyParams, fullTokenId);
    EXPECT_EQ(ERR_PARAM_INVALID, ret);

    TestCommon::GetHapParams(infoParams, policyParams);
    infoParams.bundleName = "";
    ret = AccessTokenKit::InitHapToken(infoParams, policyParams, fullTokenId);
    EXPECT_EQ(ERR_PARAM_INVALID, ret);

    TestCommon::GetHapParams(infoParams, policyParams);
    infoParams.bundleName = OVER_SIZE_STR;
    ret = AccessTokenKit::InitHapToken(infoParams, policyParams, fullTokenId);
    EXPECT_EQ(ERR_PARAM_INVALID, ret);

    TestCommon::GetHapParams(infoParams, policyParams);
    for (int i = 0; i < THIRTY_TIME_CYCLES; i++) {
        infoParams.appIDDesc += OVER_SIZE_STR;
    }
    ret = AccessTokenKit::InitHapToken(infoParams, policyParams, fullTokenId);
    EXPECT_EQ(ERR_PARAM_INVALID, ret);
}

/**
 * @tc.name: InitHapTokenAbnormalTest002
 * @tc.desc: Invaild HapPolicyParams.
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(InitHapTokenTest, InitHapTokenAbnormalTest002, TestSize.Level0)
{
    LOGI(ATM_DOMAIN, ATM_TAG, "InitHapTokenAbnormalTest002");

    HapInfoParams infoParams;
    HapPolicyParams policyParams;
    TestCommon::GetHapParams(infoParams, policyParams);
    policyParams.apl = static_cast<AccessToken::TypeATokenAplEnum>(-1);
    AccessTokenIDEx fullTokenId;
    int32_t ret = AccessTokenKit::InitHapToken(infoParams, policyParams, fullTokenId);
    EXPECT_EQ(ERR_PARAM_INVALID, ret);

    TestCommon::GetHapParams(infoParams, policyParams);
    policyParams.apl = APL_ENUM_BUTT;
    ret = AccessTokenKit::InitHapToken(infoParams, policyParams, fullTokenId);
    EXPECT_EQ(ERR_PARAM_INVALID, ret);

    TestCommon::GetHapParams(infoParams, policyParams);
    policyParams.domain = "";
    ret = AccessTokenKit::InitHapToken(infoParams, policyParams, fullTokenId);
    EXPECT_EQ(ERR_PARAM_INVALID, ret);

    TestCommon::GetHapParams(infoParams, policyParams);
    policyParams.domain = OVER_SIZE_STR;
    ret = AccessTokenKit::InitHapToken(infoParams, policyParams, fullTokenId);
    EXPECT_EQ(ERR_PARAM_INVALID, ret);
}

/**
 * @tc.name: InitHapTokenAbnormalTest003
 * @tc.desc: Invaild permStateList.
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(InitHapTokenTest, InitHapTokenAbnormalTest003, TestSize.Level0)
{
    LOGI(ATM_DOMAIN, ATM_TAG, "InitHapTokenAbnormalTest003");

    HapInfoParams infoParams;
    HapPolicyParams policyParams;
    TestCommon::GetHapParams(infoParams, policyParams);

    PermissionStateFull permissionStateFull001 = {
        .permissionName = "",
        .isGeneral = true,
        .resDeviceID = {"local"},
        .grantStatus = {PERMISSION_DENIED},
        .grantFlags = {PERMISSION_SYSTEM_FIXED}
    };
    PermissionStateFull permissionStateFull002 = {
        .permissionName = "ohos.permission.test",
        .isGeneral = true,
        .resDeviceID = {"local"},
        .grantStatus = {PERMISSION_DENIED},
        .grantFlags = {PERMISSION_SYSTEM_FIXED}
    };
    policyParams.permStateList.emplace_back(permissionStateFull001);
    policyParams.permStateList.emplace_back(permissionStateFull002);
    AccessTokenIDEx fullTokenId;
    ASSERT_EQ(RET_SUCCESS, AccessTokenKit::InitHapToken(infoParams, policyParams, fullTokenId));
    AccessTokenID tokenID = fullTokenId.tokenIdExStruct.tokenID;
    ASSERT_NE(INVALID_TOKENID, tokenID);

    std::vector<PermissionStateFull> reqPermList;
    ASSERT_EQ(RET_SUCCESS, AccessTokenKit::GetReqPermissions(tokenID, reqPermList, false));
    EXPECT_TRUE(reqPermList.empty());

    ASSERT_EQ(RET_SUCCESS, AccessTokenKit::DeleteToken(tokenID));
}

/**
 * @tc.name: InitHapTokenAbnormalTest004
 * @tc.desc: Invaild aclRequestedList.
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(InitHapTokenTest, InitHapTokenAbnormalTest004, TestSize.Level0)
{
    LOGI(ATM_DOMAIN, ATM_TAG, "InitHapTokenAbnormalTest004");

    HapInfoParams infoParams;
    HapPolicyParams policyParams;
    TestCommon::GetHapParams(infoParams, policyParams);

    PermissionStateFull permissionStateFull001 = {
        .permissionName = "ohos.permission.AGENT_REQUIRE_FORM",
        .isGeneral = true,
        .resDeviceID = {"local"},
        .grantStatus = {PERMISSION_DENIED},
        .grantFlags = {PERMISSION_SYSTEM_FIXED}
    };
    PermissionStateFull permissionStateFull002 = {
        .permissionName = "ohos.permission.ACCESS_EXTENSIONAL_DEVICE_DRIVER",
        .isGeneral = true,
        .resDeviceID = {"local"},
        .grantStatus = {PERMISSION_DENIED},
        .grantFlags = {PERMISSION_SYSTEM_FIXED}
    };
    policyParams.aclRequestedList = {""};
    AccessTokenIDEx fullTokenId;
    EXPECT_EQ(RET_SUCCESS, AccessTokenKit::InitHapToken(infoParams, policyParams, fullTokenId));
    AccessTokenID tokenID = fullTokenId.tokenIdExStruct.tokenID;
    EXPECT_NE(INVALID_TOKENID, tokenID);
    int32_t ret = AccessTokenKit::VerifyAccessToken(tokenID, "");
    EXPECT_EQ(PERMISSION_DENIED, ret);

    policyParams.aclRequestedList = {"ohos.permission.test"};
    EXPECT_EQ(RET_SUCCESS, AccessTokenKit::InitHapToken(infoParams, policyParams, fullTokenId));
    EXPECT_NE(INVALID_TOKENID, fullTokenId.tokenIdExStruct.tokenID);
    EXPECT_NE(tokenID, fullTokenId.tokenIdExStruct.tokenID);
    tokenID = fullTokenId.tokenIdExStruct.tokenID;
    ret = AccessTokenKit::VerifyAccessToken(tokenID, "ohos.permission.test");
    EXPECT_EQ(PERMISSION_DENIED, ret);

    policyParams.aclRequestedList = {"ohos.permission.AGENT_REQUIRE_FORM"};
    ASSERT_EQ(RET_SUCCESS, AccessTokenKit::InitHapToken(infoParams, policyParams, fullTokenId));
    EXPECT_NE(INVALID_TOKENID, fullTokenId.tokenIdExStruct.tokenID);
    EXPECT_NE(tokenID, fullTokenId.tokenIdExStruct.tokenID);
    tokenID = fullTokenId.tokenIdExStruct.tokenID;
    ret = AccessTokenKit::VerifyAccessToken(tokenID, "ohos.permission.AGENT_REQUIRE_FORM");
    EXPECT_EQ(PERMISSION_DENIED, ret);

    policyParams.permStateList.emplace_back(permissionStateFull002);
    policyParams.aclRequestedList.emplace_back("ohos.permission.ACCESS_EXTENSIONAL_DEVICE_DRIVER");

    ASSERT_EQ(RET_SUCCESS, AccessTokenKit::InitHapToken(infoParams, policyParams, fullTokenId));
    EXPECT_NE(INVALID_TOKENID, fullTokenId.tokenIdExStruct.tokenID);
    EXPECT_NE(tokenID, fullTokenId.tokenIdExStruct.tokenID);
    tokenID = fullTokenId.tokenIdExStruct.tokenID;
    ret = AccessTokenKit::VerifyAccessToken(tokenID, "ohos.permission.ACCESS_EXTENSIONAL_DEVICE_DRIVER");
    EXPECT_EQ(PERMISSION_GRANTED, ret);

    ASSERT_EQ(RET_SUCCESS, AccessTokenKit::DeleteToken(tokenID));
}

/**
 * @tc.name: InitHapTokenAbnormalTest005
 * @tc.desc: Invaild preAuthorizationInfo.
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(InitHapTokenTest, InitHapTokenAbnormalTest005, TestSize.Level0)
{
    LOGI(ATM_DOMAIN, ATM_TAG, "InitHapTokenAbnormalTest005");

    HapInfoParams infoParams;
    HapPolicyParams policyParams;
    TestCommon::GetHapParams(infoParams, policyParams);

    PreAuthorizationInfo preAuthorizationInfo;
    preAuthorizationInfo.permissionName = "";
    policyParams.preAuthorizationInfo = {preAuthorizationInfo};
    AccessTokenIDEx fullTokenId;
    EXPECT_EQ(RET_SUCCESS, AccessTokenKit::InitHapToken(infoParams, policyParams, fullTokenId));
    AccessTokenID tokenID = fullTokenId.tokenIdExStruct.tokenID;
    EXPECT_NE(INVALID_TOKENID, tokenID);
    EXPECT_EQ(PERMISSION_DENIED, AccessTokenKit::VerifyAccessToken(tokenID, ""));

    preAuthorizationInfo.permissionName = "ohos.permission.test";
    policyParams.preAuthorizationInfo = {preAuthorizationInfo};
    EXPECT_EQ(RET_SUCCESS, AccessTokenKit::InitHapToken(infoParams, policyParams, fullTokenId));
    EXPECT_NE(INVALID_TOKENID, fullTokenId.tokenIdExStruct.tokenID);
    EXPECT_NE(tokenID, fullTokenId.tokenIdExStruct.tokenID);
    tokenID = fullTokenId.tokenIdExStruct.tokenID;
    int32_t  ret = AccessTokenKit::VerifyAccessToken(tokenID, "ohos.permission.test");
    EXPECT_EQ(PERMISSION_DENIED, ret);

    preAuthorizationInfo.permissionName = "ohos.permission.AGENT_REQUIRE_FORM";
    policyParams.preAuthorizationInfo = {preAuthorizationInfo};
    ASSERT_EQ(RET_SUCCESS, AccessTokenKit::InitHapToken(infoParams, policyParams, fullTokenId));
    EXPECT_NE(INVALID_TOKENID, fullTokenId.tokenIdExStruct.tokenID);
    EXPECT_NE(tokenID, fullTokenId.tokenIdExStruct.tokenID);
    tokenID = fullTokenId.tokenIdExStruct.tokenID;
    ret = AccessTokenKit::VerifyAccessToken(tokenID, "ohos.permission.AGENT_REQUIRE_FORM");
    EXPECT_EQ(PERMISSION_DENIED, ret);

    ASSERT_EQ(RET_SUCCESS, AccessTokenKit::DeleteToken(fullTokenId.tokenIdExStruct.tokenID));
}

/**
 * @tc.name: InitHapTokenAbnormalTest006
 * @tc.desc: InitHapToken isRestore with INVALID_TOKENID
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(InitHapTokenTest, InitHapTokenAbnormalTest006, TestSize.Level0)
{
    HapInfoParams infoParams;
    HapPolicyParams policyParams;
    TestCommon::GetHapParams(infoParams, policyParams);

    infoParams.isRestore = true;
    infoParams.tokenID = INVALID_TOKENID;

    PreAuthorizationInfo preAuthorizationInfo;
    preAuthorizationInfo.permissionName = "";
    policyParams.preAuthorizationInfo = {preAuthorizationInfo};
    AccessTokenIDEx fullTokenId;
    int32_t ret = AccessTokenKit::InitHapToken(infoParams, policyParams, fullTokenId);
    EXPECT_EQ(ERR_PARAM_INVALID, ret);
}
} // namespace AccessToken
} // namespace Security
} // namespace OHOS