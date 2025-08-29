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

#include "update_hap_token_test.h"
#include "gtest/gtest.h"
#include <thread>

#include "access_token.h"
#include "access_token_error.h"
#include "accesstoken_common_log.h"
#include "iaccess_token_manager.h"
#include "nativetoken_kit.h"
#include "parameter.h"
#include "parameters.h"
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
static const char* ENTERPRISE_NORMAL_CHECK = "accesstoken.enterprise_normal_check";
static const std::string TEST_BUNDLE_NAME = "ohos";
static const int TEST_USER_ID = 0;
static const int THREAD_NUM = 3;
static constexpr int32_t CYCLE_TIMES = 100;
static const int INVALID_APPIDDESC_LEN = 10244;
static const int32_t INDEX_ZERO = 0;
static const int32_t INDEX_THREE = 3;
static uint64_t g_selfTokenId = 0;
static constexpr int32_t API_VERSION_EIGHT = 8;
const std::string APP_DISTRIBUTION_TYPE_ENTERPRISE_MDM = "enterprise_mdm";
const std::string APP_DISTRIBUTION_TYPE_ENTERPRISE_NORMAL = "enterprise_normal";
const std::string APP_DISTRIBUTION_TYPE_NONE = "none";
const std::string OVER_SIZE_STR =
    "AAANSUhEUgAAABUAAAAXCAIAAABrvZPKAAAACXBIWXMAAA7EAAAOxAGVKw4bAAAAEXRFWHRTb2Z0d2FyZQBTbmlwYXN0ZV0Xzt0A"
    "FBSURBVDiN7ZQ/S8NQFMVPxU/QCx06GBzrkqUZ42rBbHWUBDqYxSnUoTxXydCSycVsgltfBiFDR8HNdHGxY4nQQAPvMzwHsWn+KM"
    "vj3He5vIaUEjV0UAfe85X83KMBT7N75JEXVdSlfEAVfPRyZ5yfIrBoUkVlMU82Hkp8wu9ddt1vFew4sIiIiKwgzcXIvN7GTZOvpZ"
    "D3I1NZvmdCXz+XOv5wJANKHOVYjRTAghxIyh0FHKb+0QQH5+kXf2zkYGAG0oFr5RfnK8DAGkwY19wliRT2L448vjv0YGQFVa8VKd";
static MockNativeToken* g_mock;

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

HapInfoParams g_testHapInfoParams = {
    .userID = 0,
    .bundleName = "UpdateHapTokenTest",
    .instIndex = 0,
    .appIDDesc = "UpdateHapTokenTest",
    .apiVersion = TestCommon::DEFAULT_API_VERSION,
    .isSystemApp = true,
    .appDistributionType = ""
};

PermissionDef g_permDef = {
    .permissionName = "ohos.permission.test1",
    .bundleName = "accesstoken_test",
    .grantMode = 1,
    .availableLevel = APL_NORMAL,
    .label = "label3",
    .labelId = 1,
    .description = "open the door",
    .descriptionId = 1,
    .availableType = MDM
};

HapPolicyParams g_testPolicyParams = {
    .apl = APL_SYSTEM_CORE,
    .domain = "test_domain",
    .permList = { g_permDef },
    .permStateList = { g_infoManagerCameraState, g_infoManagerMicrophoneState },
    .aclRequestedList = {},
    .preAuthorizationInfo = {}
};
};

void UpdateHapTokenTest::SetUpTestCase()
{
    g_selfTokenId = GetSelfTokenID();
    TestCommon::SetTestEvironment(g_selfTokenId);

    // native process with MANAGER_HAP_ID
    g_mock = new (std::nothrow) MockNativeToken("foundation");
}

void UpdateHapTokenTest::TearDownTestCase()
{
    AccessTokenID tokenID = AccessTokenKit::GetHapTokenID(TEST_USER_ID, TEST_BUNDLE_NAME, 0);
    AccessTokenKit::DeleteToken(tokenID);

    tokenID = AccessTokenKit::GetHapTokenID(
        g_testHapInfoParams.userID, g_testHapInfoParams.bundleName, g_testHapInfoParams.instIndex);
    AccessTokenKit::DeleteToken(tokenID);

    if (g_mock != nullptr) {
        delete g_mock;
        g_mock = nullptr;
    }
    EXPECT_EQ(0, SetSelfTokenID(g_selfTokenId));
    TestCommon::ResetTestEvironment();
}

void UpdateHapTokenTest::SetUp()
{
    LOGI(ATM_DOMAIN, ATM_TAG, "SetUp ok.");
    HapInfoParams info = {
        .userID = TEST_USER_ID,
        .bundleName = TEST_BUNDLE_NAME,
        .instIndex = 0,
        .appIDDesc = "appIDDesc",
        .apiVersion = TestCommon::DEFAULT_API_VERSION
    };

    HapPolicyParams policy = {
        .apl = APL_NORMAL,
        .domain = "domain"
    };
    policy.permStateList.emplace_back(g_infoManagerCameraState);
    policy.permStateList.emplace_back(g_infoManagerMicrophoneState);

    AccessTokenIDEx tokenIdEx = {0};
    EXPECT_EQ(RET_SUCCESS, TestCommon::AllocTestHapToken(info, policy, tokenIdEx));
    ASSERT_NE(INVALID_TOKENID, tokenIdEx.tokenIDEx);
}

void UpdateHapTokenTest::TearDown()
{
}

/**
 * @tc.name: UpdateHapTokenFuncTest001
 * @tc.desc: test update appIDDesc
 *           1.appIDDesc = AccessTokenTestAppID.
 *           2.appIDDesc = HapTokenTestAppID_1, Update success.
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(UpdateHapTokenTest, UpdateHapTokenFuncTest001, TestSize.Level0)
{
    LOGI(ATM_DOMAIN, ATM_TAG, "UpdateHapTokenFuncTest001");

    HapInfoParams infoParams;
    HapPolicyParams policyParams;
    TestCommon::GetHapParams(infoParams, policyParams);
    AccessTokenIDEx fullTokenId;
    ASSERT_EQ(RET_SUCCESS, AccessTokenKit::InitHapToken(infoParams, policyParams, fullTokenId));
    AccessTokenID tokenID = fullTokenId.tokenIdExStruct.tokenID;
    ASSERT_NE(INVALID_TOKENID, tokenID);
    UpdateHapInfoParams updateHapInfoParams = {
        .appIDDesc = "HapTokenTestAppID_1",
        .apiVersion = infoParams.apiVersion,
        .isSystemApp = infoParams.isSystemApp,
        .appDistributionType = infoParams.appDistributionType
    };

    ASSERT_EQ(RET_SUCCESS, AccessTokenKit::UpdateHapToken(fullTokenId, updateHapInfoParams, policyParams));

    HapTokenInfo hapInfo;
    AccessTokenKit::GetHapTokenInfo(tokenID, hapInfo);
    EXPECT_EQ(0, hapInfo.userID);
    EXPECT_EQ("com.ohos.AccessTokenTestBundle", hapInfo.bundleName);
    EXPECT_EQ(TestCommon::DEFAULT_API_VERSION, hapInfo.apiVersion);
    EXPECT_EQ(0, hapInfo.instIndex);
    EXPECT_EQ(tokenID, hapInfo.tokenID);
    EXPECT_EQ(1, hapInfo.tokenAttr);

    HapTokenInfoExt hapInfoExt;
    AccessTokenKit::GetHapTokenInfoExtension(tokenID, hapInfoExt);
    EXPECT_EQ("HapTokenTestAppID_1", hapInfoExt.appID);

    EXPECT_EQ(RET_SUCCESS, AccessTokenKit::DeleteToken(tokenID));
}

/**
 * @tc.name: UpdateHapTokenFuncTest002
 * @tc.desc: test update apiVersion
 *           1.apiVersion = DEFAULT_API_VERSION.
 *           2.apiVersion = API_VERSION_EIGHT, Update success.
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(UpdateHapTokenTest, UpdateHapTokenFuncTest002, TestSize.Level0)
{
    LOGI(ATM_DOMAIN, ATM_TAG, "UpdateHapTokenFuncTest002");

    HapInfoParams infoParams;
    HapPolicyParams policyParams;
    TestCommon::GetHapParams(infoParams, policyParams);
    AccessTokenIDEx fullTokenId;
    ASSERT_EQ(RET_SUCCESS, AccessTokenKit::InitHapToken(infoParams, policyParams, fullTokenId));
    AccessTokenID tokenID = fullTokenId.tokenIdExStruct.tokenID;
    UpdateHapInfoParams updateHapInfoParams = {
        .appIDDesc = infoParams.appIDDesc,
        .apiVersion = API_VERSION_EIGHT,
        .isSystemApp = infoParams.isSystemApp,
        .appDistributionType = infoParams.appDistributionType
    };

    ASSERT_EQ(RET_SUCCESS, AccessTokenKit::UpdateHapToken(fullTokenId, updateHapInfoParams, policyParams));

    HapTokenInfo hapInfo;
    AccessTokenKit::GetHapTokenInfo(tokenID, hapInfo);
    EXPECT_EQ(0, hapInfo.userID);
    EXPECT_EQ("com.ohos.AccessTokenTestBundle", hapInfo.bundleName);
    EXPECT_EQ(API_VERSION_EIGHT, hapInfo.apiVersion);
    EXPECT_EQ(0, hapInfo.instIndex);
    EXPECT_EQ(tokenID, hapInfo.tokenID);
    EXPECT_EQ(1, hapInfo.tokenAttr);

    HapTokenInfoExt hapInfoExt;
    AccessTokenKit::GetHapTokenInfoExtension(tokenID, hapInfoExt);
    EXPECT_EQ("AccessTokenTestAppID", hapInfoExt.appID);

    EXPECT_EQ(RET_SUCCESS, AccessTokenKit::DeleteToken(tokenID));
}

/**
 * @tc.name: UpdateHapTokenFuncTest003
 * @tc.desc: test update isSystemApp
 *           1.isSystemApp = true.
 *           2.isSystemApp = false, Update success.
 *           3.isSystemApp = true, Update success.
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(UpdateHapTokenTest, UpdateHapTokenFuncTest003, TestSize.Level0)
{
    LOGI(ATM_DOMAIN, ATM_TAG, "UpdateHapTokenFuncTest003");

    HapInfoParams infoParams;
    HapPolicyParams policyParams;
    TestCommon::GetHapParams(infoParams, policyParams);
    AccessTokenIDEx fullTokenId;
    ASSERT_EQ(RET_SUCCESS, AccessTokenKit::InitHapToken(infoParams, policyParams, fullTokenId));
    AccessTokenID tokenID = fullTokenId.tokenIdExStruct.tokenID;
    UpdateHapInfoParams updateHapInfoParams = {
        .appIDDesc = infoParams.appIDDesc,
        .apiVersion = infoParams.apiVersion,
        .isSystemApp = false,
        .appDistributionType = infoParams.appDistributionType
    };

    ASSERT_EQ(RET_SUCCESS, AccessTokenKit::UpdateHapToken(fullTokenId, updateHapInfoParams, policyParams));

    HapTokenInfo hapInfo;
    AccessTokenKit::GetHapTokenInfo(tokenID, hapInfo);
    EXPECT_EQ(0, hapInfo.userID);
    EXPECT_EQ("com.ohos.AccessTokenTestBundle", hapInfo.bundleName);
    EXPECT_EQ(TestCommon::DEFAULT_API_VERSION, hapInfo.apiVersion);
    EXPECT_EQ(0, hapInfo.instIndex);
    EXPECT_EQ(tokenID, hapInfo.tokenID);
    EXPECT_EQ(0, hapInfo.tokenAttr);

    HapTokenInfoExt hapInfoExt;
    AccessTokenKit::GetHapTokenInfoExtension(tokenID, hapInfoExt);
    EXPECT_EQ("AccessTokenTestAppID", hapInfoExt.appID);

    updateHapInfoParams.isSystemApp = true;
    ASSERT_EQ(RET_SUCCESS, AccessTokenKit::UpdateHapToken(fullTokenId, updateHapInfoParams, policyParams));

    ASSERT_EQ(RET_SUCCESS, AccessTokenKit::GetHapTokenInfo(tokenID, hapInfo));
    EXPECT_EQ(1, hapInfo.tokenAttr);

    EXPECT_EQ(RET_SUCCESS, AccessTokenKit::DeleteToken(tokenID));
}

void GetPermissions(string permissionName, PermissionStateFull& stateFull, PreAuthorizationInfo& info)
{
    stateFull = {
        .permissionName = permissionName,
        .isGeneral = true,
        .resDeviceID = {"local"},
        .grantStatus = {PERMISSION_DENIED},
        .grantFlags = {PERMISSION_SYSTEM_FIXED}
    };

    info = {
        .permissionName = permissionName,
        .userCancelable = false
    };
}
/**
 * @tc.name: UpdateHapTokenFuncTest004
 * @tc.desc: test permission list number is increased from 0 to 2.
 *           1.permStateList = {}.
 *           2.permStateList = {permissionStateFull001, permissionStateFull002}, Update success.
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(UpdateHapTokenTest, UpdateHapTokenFuncTest004, TestSize.Level0)
{
    LOGI(ATM_DOMAIN, ATM_TAG, "UpdateHapTokenFuncTest004");

    HapInfoParams infoParams;
    HapPolicyParams policyParams;
    TestCommon::GetHapParams(infoParams, policyParams);
    policyParams.apl = APL_SYSTEM_CORE;
    AccessTokenIDEx fullTokenId;
    ASSERT_EQ(RET_SUCCESS, AccessTokenKit::InitHapToken(infoParams, policyParams, fullTokenId));
    AccessTokenID tokenID = fullTokenId.tokenIdExStruct.tokenID;
    EXPECT_EQ(PERMISSION_DENIED, AccessTokenKit::VerifyAccessToken(tokenID, "ohos.permission.RECEIVE_SMS"));
    EXPECT_EQ(PERMISSION_DENIED, AccessTokenKit::VerifyAccessToken(tokenID, "ohos.permission.RECEIVE_MMS"));
    UpdateHapInfoParams updateHapInfoParams = {
        .appIDDesc = infoParams.appIDDesc,
        .apiVersion = infoParams.apiVersion,
        .isSystemApp = false,
        .appDistributionType = infoParams.appDistributionType
    };

    PermissionStateFull permissionStateFull001;
    PermissionStateFull permissionStateFull002;
    PreAuthorizationInfo info1;
    PreAuthorizationInfo info2;
    GetPermissions("ohos.permission.RECEIVE_SMS", permissionStateFull001, info1);
    GetPermissions("ohos.permission.RECEIVE_MMS", permissionStateFull002, info2);

    policyParams.permStateList = {permissionStateFull001, permissionStateFull002};
    policyParams.preAuthorizationInfo = {info1, info2};

    ASSERT_EQ(RET_SUCCESS, AccessTokenKit::UpdateHapToken(fullTokenId, updateHapInfoParams, policyParams));
    std::vector<PermissionStateFull> permStatList;
    ASSERT_EQ(RET_SUCCESS, AccessTokenKit::GetReqPermissions(tokenID, permStatList, false));
    EXPECT_EQ(static_cast<uint32_t>(2), permStatList.size());
    EXPECT_EQ("ohos.permission.RECEIVE_SMS", permStatList[0].permissionName);
    EXPECT_EQ(permStatList[0].grantStatus[0], PERMISSION_GRANTED);
    EXPECT_EQ(permStatList[0].grantFlags[0], PERMISSION_SYSTEM_FIXED);
    EXPECT_EQ("ohos.permission.RECEIVE_MMS", permStatList[1].permissionName);
    EXPECT_EQ(permStatList[1].grantStatus[0], PERMISSION_GRANTED);
    EXPECT_EQ(permStatList[1].grantFlags[0], PERMISSION_SYSTEM_FIXED);

    EXPECT_EQ(RET_SUCCESS, AccessTokenKit::DeleteToken(tokenID));
}

/**
 * @tc.name: UpdateHapTokenFuncTest005
 * @tc.desc: test permission list number is decreased from 2 to 0.
 *           1.permStateList = {permissionStateFull001, permissionStateFull002}.
 *           2.permStateList={}, Update success.
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(UpdateHapTokenTest, UpdateHapTokenFuncTest005, TestSize.Level0)
{
    LOGI(ATM_DOMAIN, ATM_TAG, "UpdateHapTokenFuncTest005");

    HapInfoParams infoParams;
    HapPolicyParams policyParams;
    TestCommon::GetHapParams(infoParams, policyParams);
    policyParams.apl = APL_SYSTEM_CORE;
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
    ASSERT_EQ(RET_SUCCESS, AccessTokenKit::InitHapToken(infoParams, policyParams, fullTokenId));
    AccessTokenID tokenID = fullTokenId.tokenIdExStruct.tokenID;

    EXPECT_EQ(PERMISSION_GRANTED, AccessTokenKit::VerifyAccessToken(tokenID, "ohos.permission.RUN_DYN_CODE"));
    EXPECT_EQ(PERMISSION_GRANTED, AccessTokenKit::VerifyAccessToken(tokenID, "ohos.permission.ACCESS_DDK_USB"));

    UpdateHapInfoParams updateHapInfoParams = {
        .appIDDesc = infoParams.appIDDesc,
        .apiVersion = infoParams.apiVersion,
        .isSystemApp = false,
        .appDistributionType = infoParams.appDistributionType
    };
    policyParams.permStateList = {};

    ASSERT_EQ(RET_SUCCESS, AccessTokenKit::UpdateHapToken(fullTokenId, updateHapInfoParams, policyParams));

    EXPECT_EQ(PERMISSION_DENIED, AccessTokenKit::VerifyAccessToken(tokenID, "ohos.permission.RUN_DYN_CODE"));
    EXPECT_EQ(PERMISSION_DENIED, AccessTokenKit::VerifyAccessToken(tokenID, "ohos.permission.ACCESS_DDK_USB"));

    ASSERT_EQ(RET_SUCCESS, AccessTokenKit::DeleteToken(tokenID));
}

/**
 * @tc.name: UpdateHapTokenFuncTest006
 * @tc.desc: test permission list number is changed from permissionStateFull001 to permissionStateFull003.
 *           1.permStateList = {permissionStateFull001}
 *           2.permStateList = {permissionStateFull003}, Update success.
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(UpdateHapTokenTest, UpdateHapTokenFuncTest006, TestSize.Level0)
{
    LOGI(ATM_DOMAIN, ATM_TAG, "UpdateHapTokenFuncTest006");

    HapInfoParams infoParams;
    HapPolicyParams policyParams;
    TestCommon::GetHapParams(infoParams, policyParams);
    PermissionStateFull permissionStateFull001 = {
        .permissionName = "ohos.permission.RUN_DYN_CODE",
        .isGeneral = true,
        .resDeviceID = {"local"},
        .grantStatus = {PERMISSION_DENIED},
        .grantFlags = {PERMISSION_SYSTEM_FIXED}
    };

    policyParams.permStateList = {permissionStateFull001};
    AccessTokenIDEx fullTokenId = {0};
    ASSERT_EQ(RET_SUCCESS, AccessTokenKit::InitHapToken(infoParams, policyParams, fullTokenId));
    AccessTokenID tokenID = fullTokenId.tokenIdExStruct.tokenID;
    ASSERT_NE(INVALID_TOKENID, tokenID);

    EXPECT_EQ(PERMISSION_GRANTED, AccessTokenKit::VerifyAccessToken(tokenID, "ohos.permission.RUN_DYN_CODE"));
    EXPECT_EQ(PERMISSION_DENIED,
        AccessTokenKit::VerifyAccessToken(tokenID, "ohos.permission.ACCESS_EXTENSIONAL_DEVICE_DRIVER"));
    UpdateHapInfoParams updateHapInfoParams = {
        .appIDDesc = infoParams.appIDDesc,
        .apiVersion = infoParams.apiVersion,
        .isSystemApp = false,
        .appDistributionType = infoParams.appDistributionType
    };
    PermissionStateFull permissionStateFull003 = {
        .permissionName = "ohos.permission.ACCESS_EXTENSIONAL_DEVICE_DRIVER",
        .isGeneral = true,
        .resDeviceID = {"local"},
        .grantStatus = {PERMISSION_DENIED},
        .grantFlags = {PERMISSION_SYSTEM_FIXED}
    };

    policyParams.permStateList = { permissionStateFull003 };
    ASSERT_EQ(RET_SUCCESS, AccessTokenKit::UpdateHapToken(fullTokenId, updateHapInfoParams, policyParams));

    EXPECT_EQ(PERMISSION_DENIED, AccessTokenKit::VerifyAccessToken(tokenID, "ohos.permission.RUN_DYN_CODE"));
    EXPECT_EQ(PERMISSION_GRANTED,
        AccessTokenKit::VerifyAccessToken(tokenID, "ohos.permission.ACCESS_EXTENSIONAL_DEVICE_DRIVER"));

    ASSERT_EQ(RET_SUCCESS, AccessTokenKit::DeleteToken(tokenID));
}

static bool ExistInVector(vector<unsigned int> array, unsigned int value)
{
    vector<unsigned int>::iterator it = find(array.begin(), array.end(), value);
    if (it != array.end()) {
        return true;
    } else {
        return false;
    }
}

/**
 * @tc.name: UpdateHapTokenFuncTest007
 * @tc.desc: update a batch of tokenId.
 * @tc.type: FUNC
 * @tc.require: Issue Number
 */
HWTEST_F(UpdateHapTokenTest, UpdateHapTokenFuncTest007, TestSize.Level0)
{
    int allocFlag = 0;
    int updateFlag = 0;
    int deleteFlag = 0;
    AccessTokenIDEx tokenIdEx = {0};
    vector<AccessTokenID> obj;
    bool exist;
    HapInfoParams testInfo = g_testHapInfoParams;
    HapPolicyParams testPolicy = g_testPolicyParams;

    for (int i = 0; i < CYCLE_TIMES; i++) {
        ASSERT_EQ(RET_SUCCESS, AccessTokenKit::InitHapToken(testInfo, testPolicy, tokenIdEx));
        AccessTokenID tokenID = tokenIdEx.tokenIdExStruct.tokenID;
        ASSERT_NE(INVALID_TOKENID, tokenID);

        exist = ExistInVector(obj, tokenID);
        if (exist) {
            allocFlag = 1;
            break;
        }
        obj.push_back(tokenID);
        testInfo.userID++;
    }

    testInfo.instIndex = 1;
    testPolicy.apl = APL_SYSTEM_BASIC;
    UpdateHapInfoParams info;
    info.appIDDesc = g_testHapInfoParams.appIDDesc;
    info.apiVersion = TestCommon::DEFAULT_API_VERSION;
    info.appDistributionType = "enterprise_mdm";
    info.isSystemApp = false;
    for (size_t i = 0; i < obj.size(); i++) {
        AccessTokenIDEx idEx = {
            .tokenIdExStruct.tokenID = obj[i],
            .tokenIdExStruct.tokenAttr = 0,
        };
        int ret = AccessTokenKit::UpdateHapToken(idEx, info, testPolicy);
        if (RET_SUCCESS != ret) {
            updateFlag = 1;
            break;
        }
    }
    testPolicy.apl = APL_NORMAL;

    for (size_t i = 0; i < obj.size(); i++) {
        int ret = AccessTokenKit::DeleteToken(obj[i]);
        if (RET_SUCCESS != ret) {
            deleteFlag = 1;
        }
    }
    EXPECT_EQ(allocFlag, 0);
    EXPECT_EQ(updateFlag, 0);
    EXPECT_EQ(deleteFlag, 0);
}

/**
 * @tc.name: UpdateHapTokenFuncTest008
 * @tc.desc: add new permissdef.
 * @tc.type: FUNC
 * @tc.require: Issue Number
 */
HWTEST_F(UpdateHapTokenTest, UpdateHapTokenFuncTest008, TestSize.Level0)
{
    AccessTokenIDEx tokenIdEx = {0};
    ASSERT_EQ(RET_SUCCESS, AccessTokenKit::InitHapToken(g_testHapInfoParams, g_testPolicyParams, tokenIdEx));
    AccessTokenID tokenID = tokenIdEx.tokenIdExStruct.tokenID;
    ASSERT_NE(INVALID_TOKENID, tokenID);

    PermissionDef permDefResult;
    /* check permission define before update */
    int32_t ret = AccessTokenKit::GetDefPermission("ohos.permission.test3", permDefResult);
    ASSERT_EQ(AccessTokenError::ERR_PERMISSION_NOT_EXIST, ret);

    std::string backUp = g_testPolicyParams.permList[INDEX_ZERO].permissionName;
    g_testPolicyParams.permList[INDEX_ZERO].permissionName = "ohos.permission.test3";
    UpdateHapInfoParams info;
    info.appIDDesc = g_testHapInfoParams.appIDDesc;
    info.apiVersion = TestCommon::DEFAULT_API_VERSION;
    info.isSystemApp = false;
    info.appDistributionType = "enterprise_mdm";
    ret = AccessTokenKit::UpdateHapToken(tokenIdEx, info, g_testPolicyParams);
    ASSERT_EQ(RET_SUCCESS, ret);
    g_testPolicyParams.permList[INDEX_ZERO].permissionName = backUp;

    GTEST_LOG_(INFO) << "permissionName :" << g_testPolicyParams.permList[INDEX_ZERO].permissionName;

    ret = AccessTokenKit::GetDefPermission("ohos.permission.test3", permDefResult);
    ASSERT_EQ(AccessTokenError::ERR_PERMISSION_NOT_EXIST, ret);
    EXPECT_NE("ohos.permission.test3", permDefResult.permissionName);

    EXPECT_EQ(RET_SUCCESS, AccessTokenKit::DeleteToken(tokenID));
}
/**
 * @tc.name: UpdateHapTokenFuncTest009
 * @tc.desc: modify permissdef's grantMode.
 * @tc.type: FUNC
 * @tc.require: Issue Number
 */
HWTEST_F(UpdateHapTokenTest, UpdateHapTokenFuncTest009, TestSize.Level0)
{
    const std::string appIDDesc = g_testHapInfoParams.appIDDesc;
    int backupMode = g_testPolicyParams.permList[INDEX_ZERO].grantMode;
    std::string backupLable = g_testPolicyParams.permList[INDEX_ZERO].label;

    AccessTokenIDEx tokenIdEx = {0};
    ASSERT_EQ(RET_SUCCESS, AccessTokenKit::InitHapToken(g_testHapInfoParams, g_testPolicyParams, tokenIdEx));
    AccessTokenID tokenID = tokenIdEx.tokenIdExStruct.tokenID;
    ASSERT_NE(INVALID_TOKENID, tokenID);

    PermissionDef permDefResult;
    /* check permission define before update */
    int32_t ret = AccessTokenKit::GetDefPermission(
        g_testPolicyParams.permList[INDEX_ZERO].permissionName, permDefResult);
    ASSERT_EQ(AccessTokenError::ERR_PERMISSION_NOT_EXIST, ret);

    g_testPolicyParams.permList[INDEX_ZERO].grantMode = 0;
    g_testPolicyParams.permList[INDEX_ZERO].label = "updated label";
    UpdateHapInfoParams info;
    info.appIDDesc = appIDDesc;
    info.apiVersion = TestCommon::DEFAULT_API_VERSION;
    info.isSystemApp = false;
    info.appDistributionType = "enterprise_mdm";
    ret = AccessTokenKit::UpdateHapToken(tokenIdEx, info, g_testPolicyParams);
    ASSERT_EQ(RET_SUCCESS, ret);

    /* check permission define after update */
    ret = AccessTokenKit::GetDefPermission(
        g_testPolicyParams.permList[INDEX_ZERO].permissionName, permDefResult);
    ASSERT_EQ(AccessTokenError::ERR_PERMISSION_NOT_EXIST, ret);

    g_testPolicyParams.permList[INDEX_ZERO].label = backupLable;
    g_testPolicyParams.permList[INDEX_ZERO].grantMode = backupMode;
    ASSERT_EQ(RET_SUCCESS, AccessTokenKit::DeleteToken(tokenID));
}

/**
 * @tc.name: UpdateHapTokenFuncTest010
 * @tc.desc: old permission will not update its grantStatus.
 * @tc.type: FUNC
 * @tc.require: Issue Number
 */
HWTEST_F(UpdateHapTokenTest, UpdateHapTokenFuncTest010, TestSize.Level0)
{
    const std::string appIDDesc = g_testHapInfoParams.appIDDesc;
    std::string permission = g_infoManagerCameraState.permissionName;

    AccessTokenIDEx tokenIdEx = {0};
    ASSERT_EQ(RET_SUCCESS, AccessTokenKit::InitHapToken(g_testHapInfoParams, g_testPolicyParams, tokenIdEx));
    AccessTokenID tokenID = tokenIdEx.tokenIdExStruct.tokenID;
    ASSERT_NE(INVALID_TOKENID, tokenID);

    ASSERT_EQ(RET_SUCCESS, AccessTokenKit::GrantPermission(tokenID, permission, PERMISSION_USER_FIXED));

    ASSERT_EQ(PERMISSION_GRANTED, AccessTokenKit::VerifyAccessToken(tokenID, permission, false));

    HapPolicyParams infoManagerTestPolicyPrams = {
        .apl = APL_NORMAL,
        .domain = "test.domain",
        .permStateList = {g_infoManagerCameraState}
    };
    UpdateHapInfoParams info;
    info.appIDDesc = appIDDesc;
    info.apiVersion = TestCommon::DEFAULT_API_VERSION;
    info.isSystemApp = false;
    info.appDistributionType = "enterprise_mdm";
    ASSERT_EQ(RET_SUCCESS, AccessTokenKit::UpdateHapToken(tokenIdEx, info, infoManagerTestPolicyPrams));

    ASSERT_EQ(PERMISSION_GRANTED, AccessTokenKit::VerifyAccessToken(tokenID, permission, false));

    ASSERT_EQ(RET_SUCCESS, AccessTokenKit::DeleteToken(tokenID));
}

/**
 * @tc.name: UpdateHapTokenFuncTest011
 * @tc.desc: update api version.
 * @tc.type: FUNC
 * @tc.require:Issue Number
 */
HWTEST_F(UpdateHapTokenTest, UpdateHapTokenFuncTest011, TestSize.Level0)
{
    const std::string appIDDesc = g_testHapInfoParams.appIDDesc;
    AccessTokenIDEx tokenIdEx = {0};
    ASSERT_EQ(RET_SUCCESS, AccessTokenKit::InitHapToken(g_testHapInfoParams, g_testPolicyParams, tokenIdEx));
    AccessTokenID tokenID = tokenIdEx.tokenIdExStruct.tokenID;
    ASSERT_NE(INVALID_TOKENID, tokenID);

    UpdateHapInfoParams info;
    info.appIDDesc = appIDDesc;
    info.isSystemApp = false;
    info.appDistributionType = "enterprise_mdm";

    info.apiVersion = TestCommon::DEFAULT_API_VERSION - 1;
    ASSERT_EQ(RET_SUCCESS, AccessTokenKit::UpdateHapToken(tokenIdEx, info, g_testPolicyParams));

    HapTokenInfo hapTokenInfoRes;
    ASSERT_EQ(RET_SUCCESS, AccessTokenKit::GetHapTokenInfo(tokenID, hapTokenInfoRes));
    ASSERT_EQ(info.apiVersion, hapTokenInfoRes.apiVersion);

    info.apiVersion = TestCommon::DEFAULT_API_VERSION + 1;
    ASSERT_EQ(RET_SUCCESS, AccessTokenKit::UpdateHapToken(tokenIdEx, info, g_testPolicyParams));

    ASSERT_EQ(RET_SUCCESS, AccessTokenKit::GetHapTokenInfo(tokenID, hapTokenInfoRes));
    EXPECT_EQ(info.apiVersion, hapTokenInfoRes.apiVersion);

    EXPECT_EQ(RET_SUCCESS, AccessTokenKit::DeleteToken(tokenID));
}

/**
 * @tc.name: UpdateHapTokenFuncTest012
 * @tc.desc: AccessTokenKit::UpdateHapToken function test
 * @tc.type: FUNC
 * @tc.require: issueI61A6M
 */
HWTEST_F(UpdateHapTokenTest, UpdateHapTokenFuncTest012, TestSize.Level0)
{
    AccessTokenIDEx tokenID = {0};
    HapPolicyParams policy;
    UpdateHapInfoParams info;
    info.appIDDesc = std::string("updateFailed");
    info.apiVersion = 0;
    info.isSystemApp = false;
    EXPECT_EQ(AccessTokenError::ERR_PARAM_INVALID,
        AccessTokenKit::UpdateHapToken(tokenID, info, policy));
}

static void *ThreadTestFunc01(void *args)
{
    ATokenTypeEnum type;
    AccessTokenID tokenID;

    for (int i = 0; i < CYCLE_TIMES; i++) {
        tokenID = AccessTokenKit::AccessTokenKit::GetHapTokenID(TEST_USER_ID, TEST_BUNDLE_NAME, 0);
        type = AccessTokenKit::GetTokenType(tokenID);
        if (type != TOKEN_HAP) {
            GTEST_LOG_(INFO) << "ThreadTestFunc01 failed" << tokenID;
        }
    }
    return nullptr;
}

static void *ThreadTestFunc02(void *args)
{
    int ret;
    AccessTokenID tokenID;
    HapTokenInfo hapTokenInfoRes;

    for (int i = 0; i < CYCLE_TIMES; i++) {
        tokenID = AccessTokenKit::AccessTokenKit::GetHapTokenID(TEST_USER_ID, TEST_BUNDLE_NAME, 0);
        ret = AccessTokenKit::GetHapTokenInfo(tokenID, hapTokenInfoRes);
        if (ret != RET_SUCCESS) {
            GTEST_LOG_(INFO) << "ThreadTestFunc02 failed" << tokenID;
        }
    }
    return nullptr;
}

/**
 * @tc.name: AllocHapToken011
 * @tc.desc: Mulitpulthread test.
 * @tc.type: FUNC
 * @tc.require: Issue Number
 */
HWTEST_F(UpdateHapTokenTest, Mulitpulthread001, TestSize.Level0)
{
    AccessTokenID tokenID = AccessTokenKit::GetHapTokenID(TEST_USER_ID, TEST_BUNDLE_NAME, 0);
    ASSERT_NE(INVALID_TOKENID, tokenID);
    pthread_t tid[2];
    (void)pthread_create(&tid[0], nullptr, &ThreadTestFunc01, nullptr);
    (void)pthread_create(&tid[1], nullptr, &ThreadTestFunc01, nullptr);
    (void)pthread_join(tid[0], nullptr);
    (void)pthread_join(tid[1], nullptr);

    (void)pthread_create(&tid[0], nullptr, &ThreadTestFunc02, nullptr);
    (void)pthread_create(&tid[1], nullptr, &ThreadTestFunc02, nullptr);
    (void)pthread_join(tid[0], nullptr);
    (void)pthread_join(tid[1], nullptr);
}

void ConcurrencyTask(unsigned int tokenID)
{
    uint32_t flag;
    for (int i = 0; i < CYCLE_TIMES; i++) {
        AccessTokenKit::GrantPermission(tokenID, g_infoManagerMicrophoneState.permissionName, PERMISSION_USER_FIXED);
        AccessTokenKit::GetPermissionFlag(tokenID, g_infoManagerMicrophoneState.permissionName, flag);
        AccessTokenKit::VerifyAccessToken(tokenID, g_infoManagerMicrophoneState.permissionName, false);

        AccessTokenKit::RevokePermission(tokenID, g_infoManagerMicrophoneState.permissionName, PERMISSION_USER_SET);
        AccessTokenKit::GetPermissionFlag(tokenID, g_infoManagerMicrophoneState.permissionName, flag);
        AccessTokenKit::VerifyAccessToken(tokenID, g_infoManagerMicrophoneState.permissionName, false);
    }
}

/**
 * @tc.name: ConcurrencyTest001
 * @tc.desc: Concurrency testing
 * @tc.type: FUNC
 * @tc.require: Issue Number
 */
HWTEST_F(UpdateHapTokenTest, ConcurrencyTest001, TestSize.Level0)
{
    AccessTokenID tokenID = AccessTokenKit::GetHapTokenID(TEST_USER_ID, TEST_BUNDLE_NAME, 0);
    ASSERT_NE(INVALID_TOKENID, tokenID);
    std::vector<std::thread> threadVec;
    for (int i = 0; i < THREAD_NUM; i++) {
        threadVec.emplace_back(std::thread(ConcurrencyTask, tokenID));
    }
    for (auto it = threadVec.begin(); it != threadVec.end(); it++) {
        it->join();
    }
}

/**
 * @tc.name: UpdateHapTokenSpecsTest001
 * @tc.desc: test aclRequestedList does not exist before update and add one after update.
 *           1.aclRequestedList = {}.
 *           2.aclRequestedList = {"ohos.permission.ACCESS_DDK_USB"}, Update success.
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(UpdateHapTokenTest, UpdateHapTokenSpecsTest001, TestSize.Level0)
{
    LOGI(ATM_DOMAIN, ATM_TAG, "UpdateHapTokenSpecsTest001");

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
    policyParams.permStateList = {permissionStateFull001};
    AccessTokenIDEx fullTokenId;
    ASSERT_EQ(RET_SUCCESS, AccessTokenKit::InitHapToken(infoParams, policyParams, fullTokenId));
    AccessTokenID tokenID = fullTokenId.tokenIdExStruct.tokenID;

    EXPECT_EQ(PERMISSION_GRANTED, AccessTokenKit::VerifyAccessToken(tokenID, "ohos.permission.RUN_DYN_CODE"));

    UpdateHapInfoParams updateHapInfoParams = {
        .appIDDesc = infoParams.appIDDesc,
        .apiVersion = infoParams.apiVersion,
        .isSystemApp = false,
        .appDistributionType = infoParams.appDistributionType
    };
    policyParams.permStateList = {permissionStateFull001, permissionStateFull002};
    policyParams.aclRequestedList = {"ohos.permission.ACCESS_DDK_USB"};
    ASSERT_EQ(RET_SUCCESS, AccessTokenKit::UpdateHapToken(fullTokenId, updateHapInfoParams, policyParams));
    tokenID = fullTokenId.tokenIdExStruct.tokenID;

    EXPECT_EQ(PERMISSION_GRANTED, AccessTokenKit::VerifyAccessToken(tokenID, "ohos.permission.RUN_DYN_CODE"));
    EXPECT_EQ(PERMISSION_GRANTED, AccessTokenKit::VerifyAccessToken(tokenID, "ohos.permission.ACCESS_DDK_USB"));

    ASSERT_EQ(RET_SUCCESS, AccessTokenKit::DeleteToken(tokenID));
}

/**
 * @tc.name: UpdateHapTokenSpecsTest002
 * @tc.desc: test aclRequestedList exist before update and remove after update.
 *           1.aclRequestedList = {"ohos.permission.ACCESS_DDK_USB"}
 *           2.aclRequestedList = {}, Update failed.
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(UpdateHapTokenTest, UpdateHapTokenSpecsTest002, TestSize.Level0)
{
    LOGI(ATM_DOMAIN, ATM_TAG, "UpdateHapTokenSpecsTest002");

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
    EXPECT_EQ(PERMISSION_GRANTED, AccessTokenKit::VerifyAccessToken(tokenID, "ohos.permission.RUN_DYN_CODE"));
    EXPECT_EQ(PERMISSION_GRANTED, AccessTokenKit::VerifyAccessToken(tokenID, "ohos.permission.ACCESS_DDK_USB"));

    UpdateHapInfoParams updateHapInfoParams = {
        .appIDDesc = infoParams.appIDDesc,
        .apiVersion = infoParams.apiVersion,
        .isSystemApp = false,
        .appDistributionType = infoParams.appDistributionType
    };
    policyParams.aclRequestedList = {};
    ASSERT_EQ(
        ERR_PERM_REQUEST_CFG_FAILED, AccessTokenKit::UpdateHapToken(fullTokenId, updateHapInfoParams, policyParams));
    tokenID = fullTokenId.tokenIdExStruct.tokenID;

    ASSERT_EQ(RET_SUCCESS, AccessTokenKit::DeleteToken(tokenID));
}

/**
 * @tc.name: UpdateHapTokenSpecsTest003
 * @tc.desc: test permission not available after apl update from APL_SYSTEM_CORE to APL_NORMAL.
 *           1.apl = APL_SYSTEM_CORE.
 *           2.apl = APL_NORMAL, Update failed.
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(UpdateHapTokenTest, UpdateHapTokenSpecsTest003, TestSize.Level0)
{
    LOGI(ATM_DOMAIN, ATM_TAG, "UpdateHapTokenSpecsTest003");

    HapInfoParams infoParams;
    HapPolicyParams policyParams;
    TestCommon::GetHapParams(infoParams, policyParams);
    policyParams.apl = APL_SYSTEM_CORE;
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
    ASSERT_EQ(RET_SUCCESS, AccessTokenKit::InitHapToken(infoParams, policyParams, fullTokenId));
    AccessTokenID tokenID = fullTokenId.tokenIdExStruct.tokenID;
    EXPECT_EQ(PERMISSION_GRANTED, AccessTokenKit::VerifyAccessToken(tokenID, "ohos.permission.RUN_DYN_CODE"));
    EXPECT_EQ(PERMISSION_GRANTED, AccessTokenKit::VerifyAccessToken(tokenID, "ohos.permission.ACCESS_DDK_USB"));

    UpdateHapInfoParams updateHapInfoParams = {
        .appIDDesc = infoParams.appIDDesc,
        .apiVersion = infoParams.apiVersion,
        .isSystemApp = false,
        .appDistributionType = infoParams.appDistributionType
    };
    policyParams.apl = APL_NORMAL;
    ASSERT_EQ(
        ERR_PERM_REQUEST_CFG_FAILED, AccessTokenKit::UpdateHapToken(fullTokenId, updateHapInfoParams, policyParams));
    tokenID = fullTokenId.tokenIdExStruct.tokenID;

    ASSERT_EQ(RET_SUCCESS, AccessTokenKit::DeleteToken(tokenID));
}

/**
 * @tc.name: UpdateHapTokenSpecsTest004
 * @tc.desc: Update to a MDM app, system permission is unavailable.
 *           1.appDistributionType = ""
 *           2.appDistributionType = APP_DISTRIBUTION_TYPE_ENTERPRISE_MDM, Update success
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(UpdateHapTokenTest, UpdateHapTokenSpecsTest004, TestSize.Level0)
{
    LOGI(ATM_DOMAIN, ATM_TAG, "UpdateHapTokenSpecsTest004");

    HapInfoParams infoParams;
    HapPolicyParams policyParams;
    TestCommon::GetHapParams(infoParams, policyParams);
    policyParams.apl = APL_SYSTEM_CORE;
    PermissionStateFull permissionStateFull001 = {
        .permissionName = "ohos.permission.MANAGE_FINGERPRINT_AUTH",
        .isGeneral = true,
        .resDeviceID = {"local"},
        .grantStatus = {PERMISSION_DENIED},
        .grantFlags = {PERMISSION_SYSTEM_FIXED}
    };
    policyParams.permStateList = {permissionStateFull001};
    AccessTokenIDEx fullTokenId;
    ASSERT_EQ(RET_SUCCESS, AccessTokenKit::InitHapToken(infoParams, policyParams, fullTokenId));
    AccessTokenID tokenID = fullTokenId.tokenIdExStruct.tokenID;
    EXPECT_EQ(
        PERMISSION_GRANTED, AccessTokenKit::VerifyAccessToken(tokenID, "ohos.permission.MANAGE_FINGERPRINT_AUTH"));

    UpdateHapInfoParams updateHapInfoParams = {
        .appIDDesc = infoParams.appIDDesc,
        .apiVersion = infoParams.apiVersion,
        .isSystemApp = false,
        .appDistributionType = APP_DISTRIBUTION_TYPE_ENTERPRISE_MDM
    };

    ASSERT_EQ(RET_SUCCESS, AccessTokenKit::UpdateHapToken(fullTokenId, updateHapInfoParams, policyParams));
    tokenID = fullTokenId.tokenIdExStruct.tokenID;
    // MDM Control not apply, verify result is PERMISSION_GRANTED
    EXPECT_EQ(
        PERMISSION_GRANTED, AccessTokenKit::VerifyAccessToken(tokenID, "ohos.permission.MANAGE_FINGERPRINT_AUTH"));

    ASSERT_EQ(RET_SUCCESS, AccessTokenKit::DeleteToken(tokenID));
}

/**
 * @tc.name: UpdateHapTokenSpecsTest005
 * @tc.desc: Update to a non-MDM app, MDM permission is unavailable.
 *           1.appDistributionType = APP_DISTRIBUTION_TYPE_ENTERPRISE_MDM, permission is GRANTED.
 *           2.appDistributionType ="", Update failed.
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(UpdateHapTokenTest, UpdateHapTokenSpecsTest005, TestSize.Level0)
{
    LOGI(ATM_DOMAIN, ATM_TAG, "UpdateHapTokenSpecsTest005");

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
    PermissionStateFull permissionStateFull002 = {
        .permissionName = "ohos.permission.MANAGE_FINGERPRINT_AUTH",
        .isGeneral = true,
        .resDeviceID = {"local"},
        .grantStatus = {PERMISSION_DENIED},
        .grantFlags = {PERMISSION_SYSTEM_FIXED}
    };
    policyParams.permStateList = {permissionStateFull001, permissionStateFull002};
    AccessTokenIDEx fullTokenId;
    ASSERT_EQ(RET_SUCCESS, AccessTokenKit::InitHapToken(infoParams, policyParams, fullTokenId));
    AccessTokenID tokenID = fullTokenId.tokenIdExStruct.tokenID;
    // MDM Control not apply, verify result is PERMISSION_GRANTED
    EXPECT_EQ(
        PERMISSION_GRANTED, AccessTokenKit::VerifyAccessToken(tokenID, "ohos.permission.ENTERPRISE_MANAGE_SETTINGS"));
    EXPECT_EQ(
        PERMISSION_GRANTED, AccessTokenKit::VerifyAccessToken(tokenID, "ohos.permission.MANAGE_FINGERPRINT_AUTH"));

    UpdateHapInfoParams updateHapInfoParams = {
        .appIDDesc = infoParams.appIDDesc,
        .apiVersion = infoParams.apiVersion,
        .isSystemApp = false,
        .appDistributionType = ""
    };
    ASSERT_EQ(
        ERR_PERM_REQUEST_CFG_FAILED, AccessTokenKit::UpdateHapToken(fullTokenId, updateHapInfoParams, policyParams));

    HapInfoCheckResult result;
    ASSERT_EQ(ERR_PERM_REQUEST_CFG_FAILED,
        AccessTokenKit::UpdateHapToken(fullTokenId, updateHapInfoParams, policyParams, result));
    EXPECT_EQ(result.permCheckResult.permissionName, "ohos.permission.ENTERPRISE_MANAGE_SETTINGS");
    EXPECT_EQ(result.permCheckResult.rule, PERMISSION_EDM_RULE);
    EXPECT_EQ(RET_SUCCESS, AccessTokenKit::DeleteToken(tokenID));
}

/**
 * @tc.name: UpdateHapTokenSpecsTest006
 * @tc.desc: App user_grant permission has not been operated, update with pre-authorization.
 *           1.preAuthorizationInfo = {info1}, pre-authorization update success
 *           2.GetReqPermissions success. permission is GRANTED.
 * @tc.type: FUNC
 * @tc.require: Issue Number
 */
HWTEST_F(UpdateHapTokenTest, UpdateHapTokenSpecsTest006, TestSize.Level0)
{
    LOGI(ATM_DOMAIN, ATM_TAG, "UpdateHapTokenSpecsTest006");

    HapPolicyParams testPolicyParams1 = {
        .apl = APL_NORMAL,
        .domain = "test.domain2",
        .permStateList = {g_infoManagerCameraState}
    };
    AccessTokenIDEx fullTokenId;
    EXPECT_EQ(RET_SUCCESS, AccessTokenKit::InitHapToken(g_testHapInfoParams, testPolicyParams1, fullTokenId));

    UpdateHapInfoParams info;
    info.appIDDesc = "TEST";
    info.apiVersion = TestCommon::DEFAULT_API_VERSION;
    info.isSystemApp = true;
    PreAuthorizationInfo info1 = {
        .permissionName = "ohos.permission.CAMERA",
        .userCancelable = false
    };
    HapPolicyParams testPolicyParams2 = {
        .apl = APL_NORMAL,
        .domain = "test.domain2",
        .permStateList = {g_infoManagerCameraState},
        .preAuthorizationInfo = {info1}
    };
    ASSERT_EQ(RET_SUCCESS, AccessTokenKit::UpdateHapToken(fullTokenId, info, testPolicyParams2));
    std::vector<PermissionStateFull> state;
    ASSERT_EQ(RET_SUCCESS, AccessTokenKit::GetReqPermissions(fullTokenId.tokenIdExStruct.tokenID, state, false));
    EXPECT_EQ(static_cast<uint32_t>(1), state.size());
    EXPECT_EQ("ohos.permission.CAMERA", state[0].permissionName);
    EXPECT_EQ(state[0].grantStatus[0], PERMISSION_GRANTED);
    EXPECT_EQ(state[0].grantFlags[0], PERMISSION_SYSTEM_FIXED);

    EXPECT_EQ(RET_SUCCESS, AccessTokenKit::DeleteToken(fullTokenId.tokenIdExStruct.tokenID));
}

/**
 * @tc.name: UpdateHapTokenSpecsTest007
 * @tc.desc: App user_grant permission has been granted or revoked by user, update with pre-authorization
 *           1.user_grant permission1 has been granted.
 *           2.user_grant permission2 has been revoked.
 *           3.preAuthorizationInfo = {info1, info2}, update pre-authorization success.
 *           4.GetReqPermissions success. permission1 is GRANTED, permission2 is DENIED.
 * @tc.type: FUNC
 * @tc.require: Issue Number
 */
HWTEST_F(UpdateHapTokenTest, UpdateHapTokenSpecsTest007, TestSize.Level0)
{
    LOGI(ATM_DOMAIN, ATM_TAG, "UpdateHapTokenSpecsTest007");

    HapPolicyParams testPolicyParams1 = {
        .apl = APL_NORMAL,
        .domain = "test.domain2",
        .permStateList = {g_infoManagerCameraState, g_infoManagerMicrophoneState}
    };
    AccessTokenIDEx fullTokenId;
    int32_t ret = AccessTokenKit::InitHapToken(g_testHapInfoParams, testPolicyParams1, fullTokenId);
    EXPECT_EQ(RET_SUCCESS, ret);

    ret = AccessTokenKit::GrantPermission(
        fullTokenId.tokenIdExStruct.tokenID, "ohos.permission.CAMERA", PERMISSION_USER_FIXED);
    EXPECT_EQ(RET_SUCCESS, ret);
    ret = AccessTokenKit::RevokePermission(
        fullTokenId.tokenIdExStruct.tokenID, "ohos.permission.MICROPHONE", PERMISSION_USER_FIXED);
    EXPECT_EQ(RET_SUCCESS, ret);

    UpdateHapInfoParams info;
    info.appIDDesc = "TEST";
    info.apiVersion = TestCommon::DEFAULT_API_VERSION;
    info.isSystemApp = true;
    PreAuthorizationInfo info1 = {
        .permissionName = "ohos.permission.CAMERA",
        .userCancelable = false
    };
    PreAuthorizationInfo info2 = {
        .permissionName = "ohos.permission.MICROPHONE",
        .userCancelable = false
    };
    HapPolicyParams testPolicyParams2 = {
        .apl = APL_NORMAL,
        .domain = "test.domain2",
        .permStateList = {g_infoManagerCameraState, g_infoManagerMicrophoneState},
        .preAuthorizationInfo = {info1, info2}
    };
    ret = AccessTokenKit::UpdateHapToken(fullTokenId, info, testPolicyParams2);
    ASSERT_EQ(RET_SUCCESS, ret);
    std::vector<PermissionStateFull> state;
    AccessTokenKit::GetReqPermissions(fullTokenId.tokenIdExStruct.tokenID, state, false);
    EXPECT_EQ(static_cast<uint32_t>(2), state.size());
    EXPECT_EQ("ohos.permission.CAMERA", state[0].permissionName);
    EXPECT_EQ(state[0].grantStatus[0], PERMISSION_GRANTED);
    EXPECT_EQ(state[0].grantFlags[0], PERMISSION_USER_FIXED);
    EXPECT_EQ("ohos.permission.MICROPHONE", state[1].permissionName);
    EXPECT_EQ(state[1].grantStatus[0], PERMISSION_DENIED);
    EXPECT_EQ(state[1].grantFlags[0], PERMISSION_USER_FIXED);

    EXPECT_EQ(RET_SUCCESS, AccessTokenKit::DeleteToken(fullTokenId.tokenIdExStruct.tokenID));
}

/**
 * @tc.name: UpdateHapTokenSpecsTest008
 * @tc.desc: App user_grant permission has been pre-authorized with userUnCancelable flag,
 *           update with userCancelable pre-authorization.
 *           1.userCancelable = false.
 *           2.userCancelable = true, update pre-authorization success, GetReqPermissions success.
 * @tc.type: FUNC
 * @tc.require: Issue Number
 */
HWTEST_F(UpdateHapTokenTest, UpdateHapTokenSpecsTest008, TestSize.Level0)
{
    LOGI(ATM_DOMAIN, ATM_TAG, "UpdateHapTokenSpecsTest008");

    PreAuthorizationInfo info1 = {
        .permissionName = "ohos.permission.CAMERA",
        .userCancelable = false
    };
    PreAuthorizationInfo info2 = {
        .permissionName = "ohos.permission.MICROPHONE",
        .userCancelable = false
    };
    HapPolicyParams testPolicyParams1 = {
        .apl = APL_NORMAL,
        .domain = "test.domain2",
        .permStateList = {g_infoManagerCameraState, g_infoManagerMicrophoneState},
        .preAuthorizationInfo = {info1, info2}
    };
    AccessTokenIDEx fullTokenId;
    int32_t ret = AccessTokenKit::InitHapToken(g_testHapInfoParams, testPolicyParams1, fullTokenId);
    EXPECT_EQ(RET_SUCCESS, ret);

    ret = AccessTokenKit::GrantPermission(
        fullTokenId.tokenIdExStruct.tokenID, "ohos.permission.CAMERA", PERMISSION_USER_FIXED);
    EXPECT_NE(RET_SUCCESS, ret);
    ret = AccessTokenKit::RevokePermission(
        fullTokenId.tokenIdExStruct.tokenID, "ohos.permission.MICROPHONE", PERMISSION_USER_FIXED);
    EXPECT_NE(RET_SUCCESS, ret);

    UpdateHapInfoParams info;
    info.appIDDesc = "TEST";
    info.apiVersion = TestCommon::DEFAULT_API_VERSION;
    info.isSystemApp = true;
    info1.userCancelable = true;
    testPolicyParams1.preAuthorizationInfo = {info1};

    ret = AccessTokenKit::UpdateHapToken(fullTokenId, info, testPolicyParams1);
    ASSERT_EQ(RET_SUCCESS, ret);
    std::vector<PermissionStateFull> state;
    AccessTokenKit::GetReqPermissions(fullTokenId.tokenIdExStruct.tokenID, state, false);
    EXPECT_EQ(static_cast<uint32_t>(2), state.size());
    EXPECT_EQ(state[0].grantStatus[0], PERMISSION_GRANTED);
    EXPECT_EQ(state[0].grantFlags[0], PERMISSION_PRE_AUTHORIZED_CANCELABLE);
    EXPECT_EQ(state[1].grantStatus[0], PERMISSION_DENIED);
    EXPECT_EQ(state[1].grantFlags[0], PERMISSION_DEFAULT_FLAG);

    EXPECT_EQ(RET_SUCCESS, AccessTokenKit::DeleteToken(fullTokenId.tokenIdExStruct.tokenID));
}

/**
 * @tc.name: UpdateHapTokenSpecsTest009
 * @tc.desc: App user_grant permission has been pre-authorized with userCancelable flag,
 *           update with userCancelable pre-authorization.
 *           1.userCancelable = true.
 *           2.userCancelable = false, update success, GetReqPermissions success.
 * @tc.type: FUNC
 * @tc.require: Issue Number
 */
HWTEST_F(UpdateHapTokenTest, UpdateHapTokenSpecsTest009, TestSize.Level0)
{
    LOGI(ATM_DOMAIN, ATM_TAG, "UpdateHapTokenSpecsTest009");

    PreAuthorizationInfo info1 = {
        .permissionName = "ohos.permission.CAMERA",
        .userCancelable = true
    };
    PreAuthorizationInfo info2 = {
        .permissionName = "ohos.permission.MICROPHONE",
        .userCancelable = true
    };
    HapPolicyParams testPolicyParams1 = {
        .apl = APL_NORMAL,
        .domain = "test.domain2",
        .permStateList = {g_infoManagerCameraState, g_infoManagerMicrophoneState},
        .preAuthorizationInfo = {info1, info2}
    };
    AccessTokenIDEx fullTokenId;
    int32_t ret = AccessTokenKit::InitHapToken(g_testHapInfoParams, testPolicyParams1, fullTokenId);
    EXPECT_EQ(RET_SUCCESS, ret);

    ret = AccessTokenKit::RevokePermission(
        fullTokenId.tokenIdExStruct.tokenID, "ohos.permission.MICROPHONE", PERMISSION_USER_FIXED);
    EXPECT_EQ(RET_SUCCESS, ret);

    UpdateHapInfoParams info;
    info.appIDDesc = "TEST";
    info.apiVersion = TestCommon::DEFAULT_API_VERSION;
    info.isSystemApp = true;
    info1.userCancelable = false;
    testPolicyParams1.preAuthorizationInfo = {info1};

    ret = AccessTokenKit::UpdateHapToken(fullTokenId, info, testPolicyParams1);
    ASSERT_EQ(RET_SUCCESS, ret);
    std::vector<PermissionStateFull> state;
    AccessTokenKit::GetReqPermissions(fullTokenId.tokenIdExStruct.tokenID, state, false);
    EXPECT_EQ(static_cast<uint32_t>(2), state.size());
    EXPECT_EQ(state[0].grantStatus[0], PERMISSION_GRANTED);
    EXPECT_EQ(state[0].grantFlags[0], PERMISSION_SYSTEM_FIXED);
    EXPECT_EQ(state[1].grantStatus[0], PERMISSION_DENIED);
    EXPECT_EQ(state[1].grantFlags[0], PERMISSION_USER_FIXED | PERMISSION_PRE_AUTHORIZED_CANCELABLE);

    EXPECT_EQ(RET_SUCCESS, AccessTokenKit::DeleteToken(fullTokenId.tokenIdExStruct.tokenID));
}

/**
 * @tc.name: UpdateHapTokenSpecsTest010
 * @tc.desc: test aclRequestedList exist before update and remove after update.
 *           1.aclRequestedList = {"ohos.permission.ACCESS_DDK_USB"}
 *           2.aclRequestedList = {}, Update failed.
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(UpdateHapTokenTest, UpdateHapTokenSpecsTest010, TestSize.Level0)
{
    LOGI(ATM_DOMAIN, ATM_TAG, "UpdateHapTokenSpecsTest010");

    HapInfoParams infoParams;
    HapPolicyParams policyParams;
    TestCommon::GetHapParams(infoParams, policyParams);
    policyParams.apl = APL_NORMAL;

    PermissionStateFull permissionStateFull001 = {
        .permissionName = "ohos.permission.ACCESS_DDK_USB",
        .isGeneral = true,
        .resDeviceID = {"local"},
        .grantStatus = {PERMISSION_DENIED},
        .grantFlags = {PERMISSION_SYSTEM_FIXED}
    };

    policyParams.permStateList = {permissionStateFull001};
    policyParams.aclRequestedList = {"ohos.permission.ACCESS_DDK_USB"};
    AccessTokenIDEx fullTokenId;
    int32_t ret = AccessTokenKit::InitHapToken(infoParams, policyParams, fullTokenId);
    AccessTokenID tokenID = fullTokenId.tokenIdExStruct.tokenID;
    ASSERT_EQ(RET_SUCCESS, ret);

    UpdateHapInfoParams updateHapInfoParams = {
        .appIDDesc = infoParams.appIDDesc,
        .apiVersion = infoParams.apiVersion,
        .isSystemApp = false,
        .appDistributionType = infoParams.appDistributionType
    };
    policyParams.aclRequestedList = {};
    HapInfoCheckResult result;
    ret = AccessTokenKit::UpdateHapToken(fullTokenId, updateHapInfoParams, policyParams, result);
    ASSERT_EQ(ERR_PERM_REQUEST_CFG_FAILED, ret);
    EXPECT_EQ(result.permCheckResult.permissionName, "ohos.permission.ACCESS_DDK_USB");
    EXPECT_EQ(result.permCheckResult.rule, PERMISSION_ACL_RULE);

    result.permCheckResult.permissionName = "test"; // invalid Name
    result.permCheckResult.rule = static_cast<PermissionRulesEnum>(-1); // invalid reasan
    policyParams.aclRequestedList = { "ohos.permission.ACCESS_DDK_USB" };
    ret = AccessTokenKit::UpdateHapToken(fullTokenId, updateHapInfoParams, policyParams, result);
    ASSERT_EQ(RET_SUCCESS, ret);
    EXPECT_EQ(result.permCheckResult.permissionName, "test");
    EXPECT_EQ(result.permCheckResult.rule, -1);
    EXPECT_EQ(RET_SUCCESS, AccessTokenKit::DeleteToken(tokenID));
}

/**
 * @tc.name: UpdateHapTokenSpecsTest011
 * @tc.desc: UpdateHapToken permission with value
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(UpdateHapTokenTest, UpdateHapTokenSpecsTest011, TestSize.Level0)
{
    HapInfoParams infoParams;
    HapPolicyParams policyParams;
    TestCommon::GetHapParams(infoParams, policyParams);
    policyParams.apl = APL_SYSTEM_CORE;
    TestCommon::TestPrepareKernelPermissionStatus(policyParams);
    AccessTokenIDEx fullTokenId;
    ASSERT_EQ(RET_SUCCESS, AccessTokenKit::InitHapToken(infoParams, policyParams, fullTokenId));
    AccessTokenID tokenID = fullTokenId.tokenIdExStruct.tokenID;

    policyParams.aclExtendedMap["ohos.permission.KERNEL_ATM_SELF_USE"] = "1"; // modified value

    UpdateHapInfoParams updateInfoParams = {
        .appIDDesc = "AccessTokenTestAppID",
        .apiVersion = TestCommon::DEFAULT_API_VERSION,
        .isSystemApp = true,
        .appDistributionType = "",
    };
    EXPECT_EQ(RET_SUCCESS, AccessTokenKit::UpdateHapToken(fullTokenId, updateInfoParams, policyParams));

    std::vector<PermissionWithValue> kernelPermList;
    EXPECT_EQ(RET_SUCCESS, AccessTokenKit::GetKernelPermissions(tokenID, kernelPermList));
    EXPECT_EQ(1, kernelPermList.size());

    std::string value;
    EXPECT_EQ(RET_SUCCESS, AccessTokenKit::GetReqPermissionByName(
        tokenID, "ohos.permission.KERNEL_ATM_SELF_USE", value));
    EXPECT_EQ("1", value);

    EXPECT_EQ(AccessTokenError::ERR_PERMISSION_WITHOUT_VALUE, AccessTokenKit::GetReqPermissionByName(
        tokenID, "ohos.permission.MICROPHONE", value));
    EXPECT_EQ(AccessTokenError::ERR_PERMISSION_WITHOUT_VALUE, AccessTokenKit::GetReqPermissionByName(
        tokenID, "ohos.permission.CAMERA", value));

    EXPECT_EQ(RET_SUCCESS, AccessTokenKit::DeleteToken(tokenID));
}

/**
 * @tc.name: UpdateHapTokenSpecsTest012
 * @tc.desc: Update to a enterprise_normal app, system ENTERPRISE_NORMAL permission is available.
 *           1.appDistributionType = APP_DISTRIBUTION_TYPE_ENTERPRISE_MDM
 *           2.appDistributionType = APP_DISTRIBUTION_TYPE_ENTERPRISE_NORMAL, Update success
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(UpdateHapTokenTest, UpdateHapTokenSpecsTest012, TestSize.Level0)
{
    LOGI(ATM_DOMAIN, ATM_TAG, "UpdateHapTokenSpecsTest012");

    HapInfoParams infoParams;
    HapPolicyParams policyParams;
    TestCommon::GetHapParams(infoParams, policyParams);
    policyParams.apl = APL_SYSTEM_CORE;
    infoParams.isSystemApp = false;
    infoParams.appDistributionType = APP_DISTRIBUTION_TYPE_ENTERPRISE_MDM;
    PermissionStateFull permissionStateFull001 = {
        .permissionName = "ohos.permission.FILE_GUARD_MANAGER",
        .isGeneral = true,
        .resDeviceID = {"local"},
        .grantStatus = {PERMISSION_DENIED},
        .grantFlags = {PERMISSION_SYSTEM_FIXED}
    };
    policyParams.permStateList = {permissionStateFull001};
    AccessTokenIDEx fullTokenId;
    ASSERT_EQ(RET_SUCCESS, AccessTokenKit::InitHapToken(infoParams, policyParams, fullTokenId));
    AccessTokenID tokenID = fullTokenId.tokenIdExStruct.tokenID;
    EXPECT_EQ(PERMISSION_GRANTED, AccessTokenKit::VerifyAccessToken(tokenID, "ohos.permission.FILE_GUARD_MANAGER"));

    UpdateHapInfoParams updateHapInfoParams = {
        .appIDDesc = infoParams.appIDDesc,
        .apiVersion = infoParams.apiVersion,
        .isSystemApp = false,
        .appDistributionType = APP_DISTRIBUTION_TYPE_ENTERPRISE_NORMAL
    };
    ASSERT_EQ(RET_SUCCESS, AccessTokenKit::UpdateHapToken(fullTokenId, updateHapInfoParams, policyParams));
    tokenID = fullTokenId.tokenIdExStruct.tokenID;
    EXPECT_EQ(PERMISSION_GRANTED, AccessTokenKit::VerifyAccessToken(tokenID, "ohos.permission.FILE_GUARD_MANAGER"));
    ASSERT_EQ(RET_SUCCESS, AccessTokenKit::DeleteToken(tokenID));
}

/**
 * @tc.name: UpdateHapTokenSpecsTest013
 * @tc.desc: Update to a system app, system ENTERPRISE_NORMAL permission is available.
 *           1.appDistributionType = APP_DISTRIBUTION_TYPE_ENTERPRISE_MDM
 *           2.appDistributionType = "", isSystemApp = true, Update success
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(UpdateHapTokenTest, UpdateHapTokenSpecsTest013, TestSize.Level0)
{
    LOGI(ATM_DOMAIN, ATM_TAG, "UpdateHapTokenSpecsTest013");

    HapInfoParams infoParams;
    HapPolicyParams policyParams;
    TestCommon::GetHapParams(infoParams, policyParams);
    policyParams.apl = APL_SYSTEM_CORE;
    infoParams.isSystemApp = false;
    infoParams.appDistributionType = APP_DISTRIBUTION_TYPE_ENTERPRISE_MDM;
    PermissionStateFull permissionStateFull001 = {
        .permissionName = "ohos.permission.FILE_GUARD_MANAGER",
        .isGeneral = true,
        .resDeviceID = {"local"},
        .grantStatus = {PERMISSION_DENIED},
        .grantFlags = {PERMISSION_SYSTEM_FIXED}
    };
    policyParams.permStateList = {permissionStateFull001};
    AccessTokenIDEx fullTokenId;
    ASSERT_EQ(RET_SUCCESS, AccessTokenKit::InitHapToken(infoParams, policyParams, fullTokenId));
    AccessTokenID tokenID = fullTokenId.tokenIdExStruct.tokenID;
    EXPECT_EQ(PERMISSION_GRANTED, AccessTokenKit::VerifyAccessToken(tokenID, "ohos.permission.FILE_GUARD_MANAGER"));

    UpdateHapInfoParams updateHapInfoParams = {
        .appIDDesc = infoParams.appIDDesc,
        .apiVersion = infoParams.apiVersion,
        .isSystemApp = true,
        .appDistributionType = ""
    };
    ASSERT_EQ(RET_SUCCESS, AccessTokenKit::UpdateHapToken(fullTokenId, updateHapInfoParams, policyParams));
    tokenID = fullTokenId.tokenIdExStruct.tokenID;
    EXPECT_EQ(PERMISSION_GRANTED, AccessTokenKit::VerifyAccessToken(tokenID, "ohos.permission.FILE_GUARD_MANAGER"));
    ASSERT_EQ(RET_SUCCESS, AccessTokenKit::DeleteToken(tokenID));
}

/**
 * @tc.name: UpdateHapTokenSpecsTest014
 * @tc.desc: Update to a debug app, system ENTERPRISE_NORMAL permission is available.
 *           1.appDistributionType = APP_DISTRIBUTION_TYPE_ENTERPRISE_MDM
 *           2.appDistributionType = APP_DISTRIBUTION_TYPE_NONE, Update success
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(UpdateHapTokenTest, UpdateHapTokenSpecsTest014, TestSize.Level0)
{
    LOGI(ATM_DOMAIN, ATM_TAG, "UpdateHapTokenSpecsTest014");

    HapInfoParams infoParams;
    HapPolicyParams policyParams;
    TestCommon::GetHapParams(infoParams, policyParams);
    policyParams.apl = APL_SYSTEM_CORE;
    infoParams.isSystemApp = false;
    infoParams.appDistributionType = APP_DISTRIBUTION_TYPE_ENTERPRISE_MDM;
    PermissionStateFull permissionStateFull001 = {
        .permissionName = "ohos.permission.FILE_GUARD_MANAGER",
        .isGeneral = true,
        .resDeviceID = {"local"},
        .grantStatus = {PERMISSION_DENIED},
        .grantFlags = {PERMISSION_SYSTEM_FIXED}
    };
    policyParams.permStateList = {permissionStateFull001};
    AccessTokenIDEx fullTokenId;
    ASSERT_EQ(RET_SUCCESS, AccessTokenKit::InitHapToken(infoParams, policyParams, fullTokenId));
    AccessTokenID tokenID = fullTokenId.tokenIdExStruct.tokenID;
    EXPECT_EQ(PERMISSION_GRANTED, AccessTokenKit::VerifyAccessToken(tokenID, "ohos.permission.FILE_GUARD_MANAGER"));

    UpdateHapInfoParams updateHapInfoParams = {
        .appIDDesc = infoParams.appIDDesc,
        .apiVersion = infoParams.apiVersion,
        .isSystemApp = false,
        .appDistributionType = APP_DISTRIBUTION_TYPE_NONE
    };
    ASSERT_EQ(RET_SUCCESS, AccessTokenKit::UpdateHapToken(fullTokenId, updateHapInfoParams, policyParams));
    tokenID = fullTokenId.tokenIdExStruct.tokenID;
    EXPECT_EQ(PERMISSION_GRANTED, AccessTokenKit::VerifyAccessToken(tokenID, "ohos.permission.FILE_GUARD_MANAGER"));
    ASSERT_EQ(RET_SUCCESS, AccessTokenKit::DeleteToken(tokenID));
}

/**
 * @tc.name: UpdateHapTokenSpecsTest015
 * @tc.desc: Update to a non enterprise/system/debug app, ENTERPRISE_NORMAL permission is unavailable.
 *           1.appDistributionType = APP_DISTRIBUTION_TYPE_ENTERPRISE_MDM, permission is GRANTED.
 *           2.appDistributionType ="", Update failed.
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(UpdateHapTokenTest, UpdateHapTokenSpecsTest015, TestSize.Level0)
{
    LOGI(ATM_DOMAIN, ATM_TAG, "UpdateHapTokenSpecsTest015");

    HapInfoParams infoParams;
    HapPolicyParams policyParams;
    TestCommon::GetHapParams(infoParams, policyParams);
    policyParams.apl = APL_SYSTEM_CORE;
    infoParams.isSystemApp = false;
    infoParams.appDistributionType = APP_DISTRIBUTION_TYPE_ENTERPRISE_MDM;
    PermissionStateFull permissionStateFull001 = {
        .permissionName = "ohos.permission.FILE_GUARD_MANAGER",
        .isGeneral = true,
        .resDeviceID = {"local"},
        .grantStatus = {PERMISSION_DENIED},
        .grantFlags = {PERMISSION_SYSTEM_FIXED}
    };
    policyParams.permStateList = {permissionStateFull001};
    AccessTokenIDEx fullTokenId;
    ASSERT_EQ(RET_SUCCESS, AccessTokenKit::InitHapToken(infoParams, policyParams, fullTokenId));
    AccessTokenID tokenID = fullTokenId.tokenIdExStruct.tokenID;
    EXPECT_EQ(PERMISSION_GRANTED, AccessTokenKit::VerifyAccessToken(tokenID, "ohos.permission.FILE_GUARD_MANAGER"));

    UpdateHapInfoParams updateHapInfoParams = {
        .appIDDesc = infoParams.appIDDesc,
        .apiVersion = infoParams.apiVersion,
        .isSystemApp = false,
        .appDistributionType = ""
    };
    bool isEnterpriseNormal = OHOS::system::GetBoolParameter(ENTERPRISE_NORMAL_CHECK, false);
    if (isEnterpriseNormal) {
        ASSERT_EQ(ERR_PERM_REQUEST_CFG_FAILED,
            AccessTokenKit::UpdateHapToken(fullTokenId, updateHapInfoParams, policyParams));
        HapInfoCheckResult result;
        ASSERT_EQ(ERR_PERM_REQUEST_CFG_FAILED,
            AccessTokenKit::UpdateHapToken(fullTokenId, updateHapInfoParams, policyParams, result));
        EXPECT_EQ(result.permCheckResult.permissionName, "ohos.permission.FILE_GUARD_MANAGER");
        EXPECT_EQ(result.permCheckResult.rule, PERMISSION_ENTERPRISE_NORMAL_RULE);
    } else {
        ASSERT_EQ(RET_SUCCESS, AccessTokenKit::UpdateHapToken(fullTokenId, updateHapInfoParams, policyParams));
        HapInfoCheckResult result;
        ASSERT_EQ(RET_SUCCESS, AccessTokenKit::UpdateHapToken(fullTokenId, updateHapInfoParams, policyParams, result));
    }
    EXPECT_EQ(RET_SUCCESS, AccessTokenKit::DeleteToken(tokenID));
}

/**
 * @tc.name: UpdateHapTokenSpecsTest016
 * @tc.desc: Update to a non enterprise/system/debug app, ENTERPRISE_NORMAL permission is unavailable.
 *           1.appDistributionType = APP_DISTRIBUTION_TYPE_ENTERPRISE_MDM, permission is GRANTED.
 *           2.appDistributionType ="", dataRefresh = true, Update success.
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(UpdateHapTokenTest, UpdateHapTokenSpecsTest016, TestSize.Level0)
{
    LOGI(ATM_DOMAIN, ATM_TAG, "UpdateHapTokenSpecsTest016");

    HapInfoParams infoParams;
    HapPolicyParams policyParams;
    TestCommon::GetHapParams(infoParams, policyParams);
    policyParams.apl = APL_SYSTEM_CORE;
    infoParams.isSystemApp = false;
    infoParams.appDistributionType = APP_DISTRIBUTION_TYPE_ENTERPRISE_MDM;
    PermissionStateFull permissionStateFull001 = {
        .permissionName = "ohos.permission.FILE_GUARD_MANAGER",
        .isGeneral = true,
        .resDeviceID = {"local"},
        .grantStatus = {PERMISSION_DENIED},
        .grantFlags = {PERMISSION_SYSTEM_FIXED}
    };
    policyParams.permStateList = {permissionStateFull001};
    AccessTokenIDEx fullTokenId;
    ASSERT_EQ(RET_SUCCESS, AccessTokenKit::InitHapToken(infoParams, policyParams, fullTokenId));
    AccessTokenID tokenID = fullTokenId.tokenIdExStruct.tokenID;
    EXPECT_EQ(PERMISSION_GRANTED, AccessTokenKit::VerifyAccessToken(tokenID, "ohos.permission.FILE_GUARD_MANAGER"));

    UpdateHapInfoParams updateHapInfoParams = {
        .appIDDesc = infoParams.appIDDesc,
        .apiVersion = infoParams.apiVersion,
        .isSystemApp = false,
        .appDistributionType = "",
        .dataRefresh = true
    };
    ASSERT_EQ(RET_SUCCESS, AccessTokenKit::UpdateHapToken(fullTokenId, updateHapInfoParams, policyParams));
    EXPECT_EQ(RET_SUCCESS, AccessTokenKit::DeleteToken(tokenID));
}

/**
 * @tc.name: UpdateHapTokenAbnormalTest001
 * @tc.desc: cannot update hap token info with invalid appIDDesc.
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(UpdateHapTokenTest, UpdateHapTokenAbnormalTest001, TestSize.Level0)
{
    LOGI(ATM_DOMAIN, ATM_TAG, "UpdateHapTokenAbnormalTest001");

    HapInfoParams infoParams;
    HapPolicyParams policyParams;
    TestCommon::GetHapParams(infoParams, policyParams);
    AccessTokenIDEx fullTokenId;
    int32_t ret = AccessTokenKit::InitHapToken(infoParams, policyParams, fullTokenId);
    ASSERT_EQ(RET_SUCCESS, ret);

    const std::string appIDDesc (INVALID_APPIDDESC_LEN, 'x');
    UpdateHapInfoParams updateHapInfoParams = {
        .appIDDesc = appIDDesc,
        .apiVersion = infoParams.apiVersion,
        .isSystemApp = infoParams.isSystemApp,
        .appDistributionType = infoParams.appDistributionType
    };

    ret = AccessTokenKit::UpdateHapToken(fullTokenId, updateHapInfoParams, policyParams);
    EXPECT_EQ(ERR_PARAM_INVALID, ret);

    EXPECT_EQ(RET_SUCCESS, AccessTokenKit::DeleteToken(fullTokenId.tokenIdExStruct.tokenID));
}

/**
 * @tc.name: UpdateHapTokenAbnormalTest002
 * @tc.desc: cannot update a tokenId with invalid apl.
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(UpdateHapTokenTest, UpdateHapTokenAbnormalTest002, TestSize.Level0)
{
    LOGI(ATM_DOMAIN, ATM_TAG, "UpdateHapTokenAbnormalTest002");

    HapInfoParams infoParams;
    HapPolicyParams policyParams;
    TestCommon::GetHapParams(infoParams, policyParams);
    AccessTokenIDEx fullTokenId;
    int32_t ret = AccessTokenKit::InitHapToken(infoParams, policyParams, fullTokenId);
    ASSERT_EQ(RET_SUCCESS, ret);

    UpdateHapInfoParams updateHapInfoParams = {
        .appIDDesc = infoParams.appIDDesc,
        .apiVersion = infoParams.apiVersion,
        .isSystemApp = false,
        .appDistributionType = infoParams.appDistributionType
    };
    policyParams.apl = static_cast<AccessToken::TypeATokenAplEnum>(-1);
    ret = AccessTokenKit::UpdateHapToken(fullTokenId, updateHapInfoParams, policyParams);
    EXPECT_EQ(ERR_PARAM_INVALID, ret);

    TestCommon::GetHapParams(infoParams, policyParams);
    policyParams.apl = APL_ENUM_BUTT;
    ret = AccessTokenKit::UpdateHapToken(fullTokenId, updateHapInfoParams, policyParams);
    EXPECT_EQ(ERR_PARAM_INVALID, ret);

    EXPECT_EQ(RET_SUCCESS, AccessTokenKit::DeleteToken(fullTokenId.tokenIdExStruct.tokenID));
}

/**
 * @tc.name: UpdateHapTokenAbnormalTest003
 * @tc.desc: cannot update a tokenId with invalid string value.
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(UpdateHapTokenTest, UpdateHapTokenAbnormalTest003, TestSize.Level0)
{
    LOGI(ATM_DOMAIN, ATM_TAG, "UpdateHapTokenAbnormalTest003");
    std::string backUpPermission = g_testPolicyParams.permList[INDEX_ZERO].permissionName;
    PermissionDef permDefResult;

    AccessTokenIDEx tokenIdEx = {0};
    ASSERT_EQ(RET_SUCCESS, AccessTokenKit::InitHapToken(g_testHapInfoParams, g_testPolicyParams, tokenIdEx));
    ASSERT_NE(INVALID_TOKENID, tokenIdEx.tokenIdExStruct.tokenID);

    UpdateHapInfoParams info;
    info.appIDDesc = g_testHapInfoParams.appIDDesc;
    info.apiVersion = TestCommon::DEFAULT_API_VERSION;
    info.appDistributionType = "enterprise_mdm";
    info.isSystemApp = false;

    std::string backup = g_testPolicyParams.permList[INDEX_ZERO].permissionName;
    g_testPolicyParams.permList[INDEX_ZERO].permissionName = "";
    ASSERT_EQ(RET_SUCCESS, AccessTokenKit::UpdateHapToken(tokenIdEx, info, g_testPolicyParams));
    ASSERT_EQ(AccessTokenError::ERR_PARAM_INVALID,
        AccessTokenKit::GetDefPermission(g_testPolicyParams.permList[INDEX_ZERO].permissionName, permDefResult));
    g_testPolicyParams.permList[INDEX_ZERO].permissionName = backup;

    g_testPolicyParams.permList[INDEX_ZERO].permissionName = "ohos.permission.testtmp11";
    backup = g_testPolicyParams.permList[INDEX_ZERO].bundleName;
    g_testPolicyParams.permList[INDEX_ZERO].bundleName = "";
    ASSERT_EQ(RET_SUCCESS, AccessTokenKit::UpdateHapToken(tokenIdEx, info, g_testPolicyParams));
    ASSERT_EQ(AccessTokenError::ERR_PERMISSION_NOT_EXIST,
        AccessTokenKit::GetDefPermission(g_testPolicyParams.permList[INDEX_ZERO].permissionName, permDefResult));
    g_testPolicyParams.permList[INDEX_ZERO].bundleName = backup;
    g_testPolicyParams.permList[INDEX_ZERO].permissionName = backUpPermission;

    g_testPolicyParams.permList[INDEX_ZERO].permissionName = "ohos.permission.testtmp12";
    backup = g_testPolicyParams.permList[INDEX_ZERO].label;
    g_testPolicyParams.permList[INDEX_ZERO].label = "";
    ASSERT_EQ(RET_SUCCESS, AccessTokenKit::UpdateHapToken(tokenIdEx, info, g_testPolicyParams));
    ASSERT_EQ(AccessTokenError::ERR_PERMISSION_NOT_EXIST,
        AccessTokenKit::GetDefPermission(g_testPolicyParams.permList[INDEX_ZERO].permissionName, permDefResult));
    g_testPolicyParams.permList[INDEX_ZERO].label = backup;
    g_testPolicyParams.permList[INDEX_ZERO].permissionName = backUpPermission;

    g_testPolicyParams.permList[INDEX_ZERO].permissionName = "ohos.permission.testtmp13";
    backup = g_testPolicyParams.permList[INDEX_ZERO].description;
    g_testPolicyParams.permList[INDEX_ZERO].description = "";
    ASSERT_EQ(RET_SUCCESS, AccessTokenKit::UpdateHapToken(tokenIdEx, info, g_testPolicyParams));
    ASSERT_EQ(AccessTokenError::ERR_PERMISSION_NOT_EXIST,
        AccessTokenKit::GetDefPermission(g_testPolicyParams.permList[INDEX_ZERO].permissionName, permDefResult));
    g_testPolicyParams.permList[INDEX_ZERO].description = backup;
    g_testPolicyParams.permList[INDEX_ZERO].permissionName = backUpPermission;

    ASSERT_EQ(RET_SUCCESS, AccessTokenKit::DeleteToken(tokenIdEx.tokenIdExStruct.tokenID));
}

/**
 * @tc.name: UpdateHapTokenAbnormalTest004
 * @tc.desc: test invaild aclRequestedList.
 *          1.aclRequestedList is empty, update success, virify is DENIED.
 *          2.aclRequestedList is invaild, update success, virify is DENIED.
 *          3.aclRequestedList is not in permStateList, update success, virify is DENIED.
 *          4.aclRequestedList does not support acl, update failed.
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(UpdateHapTokenTest, UpdateHapTokenAbnormalTest004, TestSize.Level0)
{
    LOGI(ATM_DOMAIN, ATM_TAG, "UpdateHapTokenAbnormalTest004");

    HapInfoParams infoParams;
    HapPolicyParams policyParams;
    TestCommon::GetHapParams(infoParams, policyParams);
    policyParams.apl = APL_NORMAL;
    AccessTokenIDEx fullTokenId;
    ASSERT_EQ(RET_SUCCESS, AccessTokenKit::InitHapToken(infoParams, policyParams, fullTokenId));
    AccessTokenID tokenID = fullTokenId.tokenIdExStruct.tokenID;

    UpdateHapInfoParams updateHapInfoParams = {
        .appIDDesc = infoParams.appIDDesc,
        .apiVersion = infoParams.apiVersion,
        .isSystemApp = infoParams.isSystemApp,
        .appDistributionType = infoParams.appDistributionType
    };

    PermissionStateFull permissionStateFull001 = {
        .permissionName = "ohos.permission.AGENT_REQUIRE_FORM",
        .isGeneral = true,
        .resDeviceID = {"local"},
        .grantStatus = {PERMISSION_DENIED},
        .grantFlags = {PERMISSION_SYSTEM_FIXED}
    };
    PermissionStateFull permissionStateFull002 = {
        .permissionName = "ohos.permission.MANAGE_DEVICE_AUTH_CRED",
        .isGeneral = true,
        .resDeviceID = {"local"},
        .grantStatus = {PERMISSION_DENIED},
        .grantFlags = {PERMISSION_SYSTEM_FIXED}
    };
    policyParams.aclRequestedList = {""};
    EXPECT_EQ(RET_SUCCESS, AccessTokenKit::UpdateHapToken(fullTokenId, updateHapInfoParams, policyParams));
    tokenID = fullTokenId.tokenIdExStruct.tokenID;
    EXPECT_EQ(PERMISSION_DENIED, AccessTokenKit::VerifyAccessToken(tokenID, ""));

    policyParams.aclRequestedList = {"ohos.permission.test"};
    EXPECT_EQ(RET_SUCCESS, AccessTokenKit::UpdateHapToken(fullTokenId, updateHapInfoParams, policyParams));
    EXPECT_EQ(PERMISSION_DENIED, AccessTokenKit::VerifyAccessToken(tokenID, "ohos.permission.test"));

    policyParams.aclRequestedList = {"ohos.permission.AGENT_REQUIRE_FORM"};
    ASSERT_EQ(RET_SUCCESS, AccessTokenKit::UpdateHapToken(fullTokenId, updateHapInfoParams, policyParams));
    EXPECT_EQ(PERMISSION_DENIED, AccessTokenKit::VerifyAccessToken(tokenID, "ohos.permission.AGENT_REQUIRE_FORM"));

    policyParams.permStateList.emplace_back(permissionStateFull002);
    policyParams.aclRequestedList.emplace_back("ohos.permission.MANAGE_DEVICE_AUTH_CRED");

    ASSERT_EQ(ERR_PERM_REQUEST_CFG_FAILED,
              AccessTokenKit::UpdateHapToken(fullTokenId, updateHapInfoParams, policyParams));

    ASSERT_EQ(RET_SUCCESS, AccessTokenKit::DeleteToken(tokenID));
}

/**
 * @tc.name: UpdateHapTokenAbnormalTest005
 * @tc.desc: test invaild preAuthorizationInfo.permissionName
 *           1.preAuthorizationInfo.permissionName is empty, update success, virify is DENIED.
 *           2.preAuthorizationInfo.permissionName is invaild, update success, virify is DENIED.
 *           3.preAuthorizationInfo.permissionName is not in permStateList, update success, virify is DENIED.
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(UpdateHapTokenTest, UpdateHapTokenAbnormalTest005, TestSize.Level0)
{
    LOGI(ATM_DOMAIN, ATM_TAG, "UpdateHapTokenAbnormalTest005");

    HapInfoParams infoParams;
    HapPolicyParams policyParams;
    TestCommon::GetHapParams(infoParams, policyParams);
    AccessTokenIDEx fullTokenId;
    int32_t ret = AccessTokenKit::InitHapToken(infoParams, policyParams, fullTokenId);
    AccessTokenID tokenID = fullTokenId.tokenIdExStruct.tokenID;
    ASSERT_EQ(RET_SUCCESS, ret);

    UpdateHapInfoParams updateHapInfoParams = {
        .appIDDesc = infoParams.appIDDesc,
        .apiVersion = infoParams.apiVersion,
        .isSystemApp = infoParams.isSystemApp,
        .appDistributionType = infoParams.appDistributionType
    };
    PreAuthorizationInfo preAuthorizationInfo;
    preAuthorizationInfo.permissionName = "";
    policyParams.preAuthorizationInfo = {preAuthorizationInfo};
    ret = AccessTokenKit::UpdateHapToken(fullTokenId, updateHapInfoParams, policyParams);
    EXPECT_EQ(RET_SUCCESS, ret);
    tokenID = fullTokenId.tokenIdExStruct.tokenID;
    ret = AccessTokenKit::VerifyAccessToken(tokenID, "");
    EXPECT_EQ(PERMISSION_DENIED, ret);

    preAuthorizationInfo.permissionName = "ohos.permission.test";
    policyParams.preAuthorizationInfo = {preAuthorizationInfo};
    ret = AccessTokenKit::UpdateHapToken(fullTokenId, updateHapInfoParams, policyParams);
    EXPECT_EQ(RET_SUCCESS, ret);
    ret = AccessTokenKit::VerifyAccessToken(tokenID, "ohos.permission.test");
    EXPECT_EQ(PERMISSION_DENIED, ret);

    preAuthorizationInfo.permissionName = "ohos.permission.AGENT_REQUIRE_FORM";
    policyParams.preAuthorizationInfo = {preAuthorizationInfo};
    ret = AccessTokenKit::UpdateHapToken(fullTokenId, updateHapInfoParams, policyParams);
    ASSERT_EQ(RET_SUCCESS, ret);
    ret = AccessTokenKit::VerifyAccessToken(tokenID, "ohos.permission.AGENT_REQUIRE_FORM");
    EXPECT_EQ(PERMISSION_DENIED, ret);

    EXPECT_EQ(RET_SUCCESS, AccessTokenKit::DeleteToken(tokenID));
}

/**
 * @tc.name: UpdateHapTokenAbnormalTest005
 * @tc.desc: cannot update hap token info with invalid userId.
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(UpdateHapTokenTest, UpdateHapTokenAbnormalTest006, TestSize.Level0)
{
    AccessTokenIDEx tokenIdEx = {
        .tokenIdExStruct.tokenID = INVALID_TOKENID,
        .tokenIdExStruct.tokenAttr = 0,
    };
    UpdateHapInfoParams info;
    info.appIDDesc = "appIDDesc";
    info.apiVersion = TestCommon::DEFAULT_API_VERSION;
    info.isSystemApp = false;
    int ret = AccessTokenKit::UpdateHapToken(
        tokenIdEx, info, g_testPolicyParams);
    EXPECT_EQ(AccessTokenError::ERR_PARAM_INVALID, ret);
}

/**
 * @tc.name: UpdateHapTokenWithManualTest001
 * @tc.desc: UpdateHapToken with MANUAL_SETTINGS permission
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(UpdateHapTokenTest, UpdateHapTokenWithManualTest001, TestSize.Level0)
{
    LOGI(ATM_DOMAIN, ATM_TAG, "UpdateHapTokenWithManualTest001");
    
    HapInfoParams infoParams;
    HapPolicyParams policyParams;
    TestCommon::GetHapParams(infoParams, policyParams);
    policyParams.apl = APL_NORMAL;
    AccessTokenIDEx fullTokenId;
    ASSERT_EQ(RET_SUCCESS, AccessTokenKit::InitHapToken(infoParams, policyParams, fullTokenId));
    AccessTokenID tokenID = fullTokenId.tokenIdExStruct.tokenID;
    ASSERT_NE(INVALID_TOKENID, tokenID);

    std::vector<PermissionStateFull> reqPermList;
    EXPECT_EQ(RET_SUCCESS, AccessTokenKit::GetReqPermissions(tokenID, reqPermList, true));
    EXPECT_EQ(reqPermList.size(), 0);

    std::vector<PermissionStateFull> reqPermList2;
    EXPECT_EQ(RET_SUCCESS, AccessTokenKit::GetReqPermissions(tokenID, reqPermList2, false));
    EXPECT_EQ(reqPermList2.size(), 0);

    UpdateHapInfoParams updateInfoParams = {
        .appIDDesc = infoParams.appIDDesc,
        .apiVersion = infoParams.apiVersion,
        .isSystemApp = false,
        .appDistributionType = ""
    };
    TestCommon::TestPrepareManualPermissionStatus(policyParams);

    EXPECT_EQ(RET_SUCCESS, AccessTokenKit::UpdateHapToken(fullTokenId, updateInfoParams, policyParams));

    std::vector<PermissionStateFull> reqPermList3;
    EXPECT_EQ(RET_SUCCESS, AccessTokenKit::GetReqPermissions(tokenID, reqPermList3, false));
    EXPECT_EQ(reqPermList3.size(), INDEX_THREE);

    for (auto permState : reqPermList3) {
        EXPECT_EQ(PERMISSION_DENIED, AccessTokenKit::VerifyAccessToken(tokenID, permState.permissionName));
    }

    EXPECT_EQ(RET_SUCCESS, AccessTokenKit::DeleteToken(tokenID));
}

/**
 * @tc.name: UpdateHapTokenWithManualTest002
 * @tc.desc: UpdateHapToken with MANUAL_SETTINGS permission
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(UpdateHapTokenTest, UpdateHapTokenWithManualTest002, TestSize.Level0)
{
    LOGI(ATM_DOMAIN, ATM_TAG, "UpdateHapTokenWithManualTest002");
    
    HapInfoParams infoParams;
    HapPolicyParams policyParams;
    TestCommon::GetHapParams(infoParams, policyParams);
    policyParams.apl = APL_NORMAL;
    TestCommon::TestPrepareManualPermissionStatus(policyParams);
    AccessTokenIDEx fullTokenId;
    ASSERT_EQ(RET_SUCCESS, AccessTokenKit::InitHapToken(infoParams, policyParams, fullTokenId));
    AccessTokenID tokenID = fullTokenId.tokenIdExStruct.tokenID;
    ASSERT_NE(INVALID_TOKENID, tokenID);

    std::vector<PermissionStateFull> reqPermList;
    EXPECT_EQ(RET_SUCCESS, AccessTokenKit::GetReqPermissions(tokenID, reqPermList, true));
    EXPECT_EQ(reqPermList.size(), 0);

    std::vector<PermissionStateFull> reqPermList2;
    EXPECT_EQ(RET_SUCCESS, AccessTokenKit::GetReqPermissions(tokenID, reqPermList2, false));
    EXPECT_EQ(reqPermList2.size(), INDEX_THREE);

    for (auto permState : reqPermList2) {
        EXPECT_EQ(PERMISSION_DENIED, AccessTokenKit::VerifyAccessToken(tokenID, permState.permissionName));
    }

    UpdateHapInfoParams updateInfoParams = {
        .appIDDesc = infoParams.appIDDesc,
        .apiVersion = infoParams.apiVersion,
        .isSystemApp = false,
        .appDistributionType = ""
    };

    HapPolicyParams policyParams2;
    TestCommon::GetHapParams(infoParams, policyParams2);
    policyParams2.apl = APL_NORMAL;

    EXPECT_EQ(RET_SUCCESS, AccessTokenKit::UpdateHapToken(fullTokenId, updateInfoParams, policyParams2));

    std::vector<PermissionStateFull> reqPermList3;
    EXPECT_EQ(RET_SUCCESS, AccessTokenKit::GetReqPermissions(tokenID, reqPermList3, false));
    EXPECT_EQ(reqPermList3.size(), 0);

    EXPECT_EQ(RET_SUCCESS, AccessTokenKit::DeleteToken(tokenID));
}
} // namespace AccessToken
} // namespace Security
} // namespace OHOS