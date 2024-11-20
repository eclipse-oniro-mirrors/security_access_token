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
#include "accesstoken_log.h"
#include "accesstoken_service_ipc_interface_code.h"
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
static AccessTokenID g_selfTokenId = 0;
static constexpr int32_t API_VERSION_EIGHT = 8;
static constexpr int32_t THIRTY_TIME_CYCLES = 30;
const std::string APP_DISTRIBUTION_TYPE_ENTERPRISE_MDM = "enterprise_mdm";
const std::string OVER_SIZE_STR =
    "AAANSUhEUgAAABUAAAAXCAIAAABrvZPKAAAACXBIWXMAAA7EAAAOxAGVKw4bAAAAEXRFWHRTb2Z0d2FyZQBTbmlwYXN0ZV0Xzt0A"
    "FBSURBVDiN7ZQ/S8NQFMVPxU/QCx06GBzrkqUZ42rBbHWUBDqYxSnUoTxXydCSycVsgltfBiFDR8HNdHGxY4nQQAPvMzwHsWn+KM"
    "vj3He5vIaUEjV0UAfe85X83KMBT7N75JEXVdSlfEAVfPRyZ5yfIrBoUkVlMU82Hkp8wu9ddt1vFew4sIiIiKwgzcXIvN7GTZOvpZ"
    "D3I1NZvmdCXz+XOv5wJANKHOVYjRTAghxIyh0FHKb+0QQH5+kXf2zkYGAG0oFr5RfnK8DAGkwY19wliRT2L448vjv0YGQFVa8VKd";

PermissionStateFull g_testPermReq = {
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
    .bundleName = "UpdateHapTokenTest",
    .instIndex = 0,
    .appIDDesc = "UpdateHapTokenTest",
    .apiVersion = TestCommon::DEFAULT_API_VERSION,
    .isSystemApp = true,
    .appDistributionType = ""
};

HapPolicyParams g_testPolicyParams = {
    .apl = APL_SYSTEM_CORE,
    .domain = "test_domain",
    .permList = {},
    .permStateList = { g_testPermReq },
    .aclRequestedList = {},
    .preAuthorizationInfo = {}
};
};

void UpdateHapTokenTest::SetUpTestCase()
{
    g_selfTokenId = GetSelfTokenID();
    // clean up test cases
    AccessTokenID tokenId = AccessTokenKit::GetHapTokenID(g_testHapInfoParams.userID,
        g_testHapInfoParams.bundleName,
        g_testHapInfoParams.instIndex);
    AccessTokenKit::DeleteToken(tokenId);
    AccessTokenIDEx tokenIdEx = AccessTokenKit::AllocHapToken(g_testHapInfoParams, g_testPolicyParams);
    SetSelfTokenID(tokenIdEx.tokenIDEx);
}

void UpdateHapTokenTest::TearDownTestCase()
{
    AccessTokenID tokenId = AccessTokenKit::GetHapTokenID(g_testHapInfoParams.userID,
        g_testHapInfoParams.bundleName,
        g_testHapInfoParams.instIndex);
    AccessTokenKit::DeleteToken(tokenId);
    SetSelfTokenID(g_selfTokenId);
}

void UpdateHapTokenTest::SetUp()
{
    LOGI(AT_DOMAIN, AT_TAG, "SetUp ok.");
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
HWTEST_F(UpdateHapTokenTest, UpdateHapTokenFuncTest001, TestSize.Level1)
{
    HapInfoParams infoParams;
    HapPolicyParams policyParams;
    TestCommon::GetHapParams(infoParams, policyParams);
    AccessTokenIDEx fullTokenId;
    int32_t ret = AccessTokenKit::InitHapToken(infoParams, policyParams, fullTokenId);
    AccessTokenID tokenID = fullTokenId.tokenIdExStruct.tokenID;
    GTEST_LOG_(INFO) << "tokenID :" << tokenID;
    ASSERT_EQ(RET_SUCCESS, ret);
    UpdateHapInfoParams updateHapInfoParams = {
        .appIDDesc = "HapTokenTestAppID_1",
        .apiVersion = infoParams.apiVersion,
        .isSystemApp = infoParams.isSystemApp,
        .appDistributionType = infoParams.appDistributionType
    };

    ret = AccessTokenKit::UpdateHapToken(fullTokenId, updateHapInfoParams, policyParams);
    ASSERT_EQ(RET_SUCCESS, ret);

    HapTokenInfo hapInfo;
    AccessTokenKit::GetHapTokenInfo(tokenID, hapInfo);
    EXPECT_EQ(APL_NORMAL, hapInfo.apl);
    EXPECT_EQ(0, hapInfo.userID);
    EXPECT_EQ("com.ohos.AccessTokenTestBundle", hapInfo.bundleName);
    EXPECT_EQ(TestCommon::DEFAULT_API_VERSION, hapInfo.apiVersion);
    EXPECT_EQ(0, hapInfo.instIndex);
    EXPECT_EQ("HapTokenTestAppID_1", hapInfo.appID);
    EXPECT_EQ(tokenID, hapInfo.tokenID);
    EXPECT_EQ(1, hapInfo.tokenAttr);
}

/**
 * @tc.name: UpdateHapTokenFuncTest002
 * @tc.desc: test update apiVersion
 *           1.apiVersion = DEFAULT_API_VERSION.
 *           2.apiVersion = API_VERSION_EIGHT, Update success.
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(UpdateHapTokenTest, UpdateHapTokenFuncTest002, TestSize.Level1)
{
    HapInfoParams infoParams;
    HapPolicyParams policyParams;
    TestCommon::GetHapParams(infoParams, policyParams);
    AccessTokenIDEx fullTokenId;
    int32_t ret = AccessTokenKit::InitHapToken(infoParams, policyParams, fullTokenId);
    AccessTokenID tokenID = fullTokenId.tokenIdExStruct.tokenID;
    GTEST_LOG_(INFO) << "tokenID :" << tokenID;
    ASSERT_EQ(RET_SUCCESS, ret);
    UpdateHapInfoParams updateHapInfoParams = {
        .appIDDesc = infoParams.appIDDesc,
        .apiVersion = API_VERSION_EIGHT,
        .isSystemApp = infoParams.isSystemApp,
        .appDistributionType = infoParams.appDistributionType
    };

    ret = AccessTokenKit::UpdateHapToken(fullTokenId, updateHapInfoParams, policyParams);
    ASSERT_EQ(RET_SUCCESS, ret);

    HapTokenInfo hapInfo;
    AccessTokenKit::GetHapTokenInfo(tokenID, hapInfo);
    EXPECT_EQ(APL_NORMAL, hapInfo.apl);
    EXPECT_EQ(0, hapInfo.userID);
    EXPECT_EQ("com.ohos.AccessTokenTestBundle", hapInfo.bundleName);
    EXPECT_EQ(API_VERSION_EIGHT, hapInfo.apiVersion);
    EXPECT_EQ(0, hapInfo.instIndex);
    EXPECT_EQ("AccessTokenTestAppID", hapInfo.appID);
    EXPECT_EQ(tokenID, hapInfo.tokenID);
    EXPECT_EQ(1, hapInfo.tokenAttr);
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
HWTEST_F(UpdateHapTokenTest, UpdateHapTokenFuncTest003, TestSize.Level1)
{
    HapInfoParams infoParams;
    HapPolicyParams policyParams;
    TestCommon::GetHapParams(infoParams, policyParams);
    AccessTokenIDEx fullTokenId;
    int32_t ret = AccessTokenKit::InitHapToken(infoParams, policyParams, fullTokenId);
    AccessTokenID tokenID = fullTokenId.tokenIdExStruct.tokenID;
    GTEST_LOG_(INFO) << "tokenID :" << tokenID;
    ASSERT_EQ(RET_SUCCESS, ret);
    UpdateHapInfoParams updateHapInfoParams = {
        .appIDDesc = infoParams.appIDDesc,
        .apiVersion = infoParams.apiVersion,
        .isSystemApp = false,
        .appDistributionType = infoParams.appDistributionType
    };

    ret = AccessTokenKit::UpdateHapToken(fullTokenId, updateHapInfoParams, policyParams);
    ASSERT_EQ(RET_SUCCESS, ret);

    HapTokenInfo hapInfo;
    AccessTokenKit::GetHapTokenInfo(tokenID, hapInfo);
    EXPECT_EQ(APL_NORMAL, hapInfo.apl);
    EXPECT_EQ(0, hapInfo.userID);
    EXPECT_EQ("com.ohos.AccessTokenTestBundle", hapInfo.bundleName);
    EXPECT_EQ(TestCommon::DEFAULT_API_VERSION, hapInfo.apiVersion);
    EXPECT_EQ(0, hapInfo.instIndex);
    EXPECT_EQ("AccessTokenTestAppID", hapInfo.appID);
    EXPECT_EQ(tokenID, hapInfo.tokenID);
    EXPECT_EQ(0, hapInfo.tokenAttr);

    updateHapInfoParams.isSystemApp = true;
    ret = AccessTokenKit::UpdateHapToken(fullTokenId, updateHapInfoParams, policyParams);
    ASSERT_EQ(RET_SUCCESS, ret);

    AccessTokenKit::GetHapTokenInfo(tokenID, hapInfo);
    EXPECT_EQ(1, hapInfo.tokenAttr);
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
HWTEST_F(UpdateHapTokenTest, UpdateHapTokenFuncTest004, TestSize.Level1)
{
    HapInfoParams infoParams;
    HapPolicyParams policyParams;
    TestCommon::GetHapParams(infoParams, policyParams);
    policyParams.apl = APL_SYSTEM_CORE;
    AccessTokenIDEx fullTokenId;
    int32_t ret = AccessTokenKit::InitHapToken(infoParams, policyParams, fullTokenId);
    AccessTokenID tokenID = fullTokenId.tokenIdExStruct.tokenID;
    GTEST_LOG_(INFO) << "tokenID :" << tokenID;
    ASSERT_EQ(RET_SUCCESS, ret);
    ret = AccessTokenKit::VerifyAccessToken(tokenID, "ohos.permission.RECEIVE_SMS");
    EXPECT_EQ(PERMISSION_DENIED, ret);
    ret = AccessTokenKit::VerifyAccessToken(tokenID, "ohos.permission.RECEIVE_MMS");
    EXPECT_EQ(PERMISSION_DENIED, ret);
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

    ret = AccessTokenKit::UpdateHapToken(fullTokenId, updateHapInfoParams, policyParams);
    ASSERT_EQ(RET_SUCCESS, ret);
    std::vector<PermissionStateFull> permStatList;
    int32_t res = AccessTokenKit::GetReqPermissions(tokenID, permStatList, false);
    ASSERT_EQ(RET_SUCCESS, res);
    ASSERT_EQ(static_cast<uint32_t>(2), permStatList.size());
    ASSERT_EQ("ohos.permission.RECEIVE_SMS", permStatList[0].permissionName);
    EXPECT_EQ(permStatList[0].grantStatus[0], PERMISSION_GRANTED);
    EXPECT_EQ(permStatList[0].grantFlags[0], PERMISSION_SYSTEM_FIXED);
    ASSERT_EQ("ohos.permission.RECEIVE_MMS", permStatList[1].permissionName);
    EXPECT_EQ(permStatList[1].grantStatus[0], PERMISSION_GRANTED);
    EXPECT_EQ(permStatList[1].grantFlags[0], PERMISSION_SYSTEM_FIXED);
}

/**
 * @tc.name: UpdateHapTokenFuncTest005
 * @tc.desc: test permission list number is decreased from 2 to 0.
 *           1.permStateList = {permissionStateFull001, permissionStateFull002}.
 *           2.permStateList={}, Update success.
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(UpdateHapTokenTest, UpdateHapTokenFuncTest005, TestSize.Level1)
{
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
    int32_t ret = AccessTokenKit::InitHapToken(infoParams, policyParams, fullTokenId);
    AccessTokenID tokenID = fullTokenId.tokenIdExStruct.tokenID;
    GTEST_LOG_(INFO) << "tokenID :" << tokenID;
    ASSERT_EQ(RET_SUCCESS, ret);

    ret = AccessTokenKit::VerifyAccessToken(tokenID, "ohos.permission.RUN_DYN_CODE");
    EXPECT_EQ(PERMISSION_GRANTED, ret);
    ret = AccessTokenKit::VerifyAccessToken(tokenID, "ohos.permission.ACCESS_DDK_USB");
    EXPECT_EQ(PERMISSION_GRANTED, ret);

    UpdateHapInfoParams updateHapInfoParams = {
        .appIDDesc = infoParams.appIDDesc,
        .apiVersion = infoParams.apiVersion,
        .isSystemApp = false,
        .appDistributionType = infoParams.appDistributionType
    };
    policyParams.permStateList = {};

    ret = AccessTokenKit::UpdateHapToken(fullTokenId, updateHapInfoParams, policyParams);
    ASSERT_EQ(RET_SUCCESS, ret);

    ret = AccessTokenKit::VerifyAccessToken(tokenID, "ohos.permission.RUN_DYN_CODE");
    EXPECT_EQ(PERMISSION_DENIED, ret);
    ret = AccessTokenKit::VerifyAccessToken(tokenID, "ohos.permission.ACCESS_DDK_USB");
    EXPECT_EQ(PERMISSION_DENIED, ret);
}

/**
 * @tc.name: UpdateHapTokenFuncTest006
 * @tc.desc: test permission list number is changed from permissionStateFull001 to permissionStateFull003.
 *           1.permStateList = {permissionStateFull001}
 *           2.permStateList = {permissionStateFull003}, Update success.
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(UpdateHapTokenTest, UpdateHapTokenFuncTest006, TestSize.Level1)
{
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
    AccessTokenIDEx fullTokenId;
    int32_t ret = AccessTokenKit::InitHapToken(infoParams, policyParams, fullTokenId);
    AccessTokenID tokenID = fullTokenId.tokenIdExStruct.tokenID;
    GTEST_LOG_(INFO) << "tokenID :" << tokenID;
    ASSERT_EQ(RET_SUCCESS, ret);

    ret = AccessTokenKit::VerifyAccessToken(tokenID, "ohos.permission.RUN_DYN_CODE");
    EXPECT_EQ(PERMISSION_GRANTED, ret);
    ret = AccessTokenKit::VerifyAccessToken(tokenID, "ohos.permission.ACCESS_EXTENSIONAL_DEVICE_DRIVER");
    EXPECT_EQ(PERMISSION_DENIED, ret);
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
    ret = AccessTokenKit::UpdateHapToken(fullTokenId, updateHapInfoParams, policyParams);
    ASSERT_EQ(RET_SUCCESS, ret);

    ret = AccessTokenKit::VerifyAccessToken(tokenID, "ohos.permission.RUN_DYN_CODE");
    EXPECT_EQ(PERMISSION_DENIED, ret);
    ret = AccessTokenKit::VerifyAccessToken(tokenID, "ohos.permission.ACCESS_EXTENSIONAL_DEVICE_DRIVER");
    EXPECT_EQ(PERMISSION_GRANTED, ret);
}

/**
 * @tc.name: UpdateHapTokenSpecsTest001
 * @tc.desc: test aclRequestedList does not exist before update and add one after update.
 *           1.aclRequestedList = {}.
 *           2.aclRequestedList = {"ohos.permission.ACCESS_DDK_USB"}, Update success.
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(UpdateHapTokenTest, UpdateHapTokenSpecsTest001, TestSize.Level1)
{
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
    int32_t ret = AccessTokenKit::InitHapToken(infoParams, policyParams, fullTokenId);
    AccessTokenID tokenID = fullTokenId.tokenIdExStruct.tokenID;
    GTEST_LOG_(INFO) << "tokenID :" << tokenID;
    ASSERT_EQ(RET_SUCCESS, ret);

    ret = AccessTokenKit::VerifyAccessToken(tokenID, "ohos.permission.RUN_DYN_CODE");
    EXPECT_EQ(PERMISSION_GRANTED, ret);

    UpdateHapInfoParams updateHapInfoParams = {
        .appIDDesc = infoParams.appIDDesc,
        .apiVersion = infoParams.apiVersion,
        .isSystemApp = false,
        .appDistributionType = infoParams.appDistributionType
    };
    policyParams.permStateList = {permissionStateFull001, permissionStateFull002};
    policyParams.aclRequestedList = {"ohos.permission.ACCESS_DDK_USB"};
    ret = AccessTokenKit::UpdateHapToken(fullTokenId, updateHapInfoParams, policyParams);
    tokenID = fullTokenId.tokenIdExStruct.tokenID;
    GTEST_LOG_(INFO) << "tokenID :" << tokenID;
    ASSERT_EQ(RET_SUCCESS, ret);

    ret = AccessTokenKit::VerifyAccessToken(tokenID, "ohos.permission.RUN_DYN_CODE");
    EXPECT_EQ(PERMISSION_GRANTED, ret);
    ret = AccessTokenKit::VerifyAccessToken(tokenID, "ohos.permission.ACCESS_DDK_USB");
    EXPECT_EQ(PERMISSION_GRANTED, ret);
}

/**
 * @tc.name: UpdateHapTokenSpecsTest002
 * @tc.desc: test aclRequestedList exist before update and remove after update.
 *           1.aclRequestedList = {"ohos.permission.ACCESS_DDK_USB"}
 *           2.aclRequestedList = {}, Update failed.
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(UpdateHapTokenTest, UpdateHapTokenSpecsTest002, TestSize.Level1)
{
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
    int32_t ret = AccessTokenKit::InitHapToken(infoParams, policyParams, fullTokenId);
    AccessTokenID tokenID = fullTokenId.tokenIdExStruct.tokenID;
    GTEST_LOG_(INFO) << "tokenID :" << tokenID;
    ASSERT_EQ(RET_SUCCESS, ret);
    ret = AccessTokenKit::VerifyAccessToken(tokenID, "ohos.permission.RUN_DYN_CODE");
    EXPECT_EQ(PERMISSION_GRANTED, ret);
    ret = AccessTokenKit::VerifyAccessToken(tokenID, "ohos.permission.ACCESS_DDK_USB");
    EXPECT_EQ(PERMISSION_GRANTED, ret);

    UpdateHapInfoParams updateHapInfoParams = {
        .appIDDesc = infoParams.appIDDesc,
        .apiVersion = infoParams.apiVersion,
        .isSystemApp = false,
        .appDistributionType = infoParams.appDistributionType
    };
    policyParams.aclRequestedList = {};
    ret = AccessTokenKit::UpdateHapToken(fullTokenId, updateHapInfoParams, policyParams);
    tokenID = fullTokenId.tokenIdExStruct.tokenID;
    GTEST_LOG_(INFO) << "tokenID :" << tokenID;
    ASSERT_EQ(ERR_PERM_REQUEST_CFG_FAILED, ret);
}

/**
 * @tc.name: UpdateHapTokenSpecsTest003
 * @tc.desc: test permission not available after apl update from APL_SYSTEM_CORE to APL_NORMAL.
 *           1.apl = APL_SYSTEM_CORE.
 *           2.apl = APL_NORMAL, Update failed.
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(UpdateHapTokenTest, UpdateHapTokenSpecsTest003, TestSize.Level1)
{
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
    int32_t ret = AccessTokenKit::InitHapToken(infoParams, policyParams, fullTokenId);
    AccessTokenID tokenID = fullTokenId.tokenIdExStruct.tokenID;
    GTEST_LOG_(INFO) << "tokenID :" << tokenID;
    ASSERT_EQ(RET_SUCCESS, ret);
    ret = AccessTokenKit::VerifyAccessToken(tokenID, "ohos.permission.RUN_DYN_CODE");
    EXPECT_EQ(PERMISSION_GRANTED, ret);
    ret = AccessTokenKit::VerifyAccessToken(tokenID, "ohos.permission.ACCESS_DDK_USB");
    EXPECT_EQ(PERMISSION_GRANTED, ret);

    UpdateHapInfoParams updateHapInfoParams = {
        .appIDDesc = infoParams.appIDDesc,
        .apiVersion = infoParams.apiVersion,
        .isSystemApp = false,
        .appDistributionType = infoParams.appDistributionType
    };
    policyParams.apl = APL_NORMAL;
    ret = AccessTokenKit::UpdateHapToken(fullTokenId, updateHapInfoParams, policyParams);
    tokenID = fullTokenId.tokenIdExStruct.tokenID;
    GTEST_LOG_(INFO) << "tokenID :" << tokenID;
    ASSERT_EQ(ERR_PERM_REQUEST_CFG_FAILED, ret);
}

/**
 * @tc.name: UpdateHapTokenSpecsTest004
 * @tc.desc: Update to a MDM app, system permission is unavailable.
 *           1.appDistributionType = ""
 *           2.appDistributionType = APP_DISTRIBUTION_TYPE_ENTERPRISE_MDM, Update success
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(UpdateHapTokenTest, UpdateHapTokenSpecsTest004, TestSize.Level1)
{
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
    int32_t ret = AccessTokenKit::InitHapToken(infoParams, policyParams, fullTokenId);
    AccessTokenID tokenID = fullTokenId.tokenIdExStruct.tokenID;
    GTEST_LOG_(INFO) << "tokenID :" << tokenID;
    ASSERT_EQ(RET_SUCCESS, ret);
    ret = AccessTokenKit::VerifyAccessToken(tokenID, "ohos.permission.MANAGE_FINGERPRINT_AUTH");
    EXPECT_EQ(PERMISSION_GRANTED, ret);

    UpdateHapInfoParams updateHapInfoParams = {
        .appIDDesc = infoParams.appIDDesc,
        .apiVersion = infoParams.apiVersion,
        .isSystemApp = false,
        .appDistributionType = APP_DISTRIBUTION_TYPE_ENTERPRISE_MDM
    };

    ret = AccessTokenKit::UpdateHapToken(fullTokenId, updateHapInfoParams, policyParams);
    tokenID = fullTokenId.tokenIdExStruct.tokenID;
    GTEST_LOG_(INFO) << "tokenID :" << tokenID;
    ASSERT_EQ(RET_SUCCESS, ret);
    // MDM Control not apply, verify result is PERMISSION_GRANTED
    ret = AccessTokenKit::VerifyAccessToken(tokenID, "ohos.permission.MANAGE_FINGERPRINT_AUTH");
    EXPECT_EQ(PERMISSION_GRANTED, ret);
}

/**
 * @tc.name: UpdateHapTokenSpecsTest005
 * @tc.desc: Update to a non-MDM app, MDM permission is unavailable.
 *           1.appDistributionType = APP_DISTRIBUTION_TYPE_ENTERPRISE_MDM, permission is GRANTED.
 *           2.appDistributionType ="", Update failed.
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(UpdateHapTokenTest, UpdateHapTokenSpecsTest005, TestSize.Level1)
{
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
    int32_t ret = AccessTokenKit::InitHapToken(infoParams, policyParams, fullTokenId);
    AccessTokenID tokenID = fullTokenId.tokenIdExStruct.tokenID;
    GTEST_LOG_(INFO) << "tokenID :" << tokenID;
    ASSERT_EQ(RET_SUCCESS, ret);
    // MDM Control not apply, verify result is PERMISSION_GRANTED
    ret = AccessTokenKit::VerifyAccessToken(tokenID, "ohos.permission.ENTERPRISE_MANAGE_SETTINGS");
    EXPECT_EQ(PERMISSION_GRANTED, ret);
    ret = AccessTokenKit::VerifyAccessToken(tokenID, "ohos.permission.MANAGE_FINGERPRINT_AUTH");
    EXPECT_EQ(PERMISSION_GRANTED, ret);

    UpdateHapInfoParams updateHapInfoParams = {
        .appIDDesc = infoParams.appIDDesc,
        .apiVersion = infoParams.apiVersion,
        .isSystemApp = false,
        .appDistributionType = ""
    };
    ret = AccessTokenKit::UpdateHapToken(fullTokenId, updateHapInfoParams, policyParams);
    tokenID = fullTokenId.tokenIdExStruct.tokenID;
    GTEST_LOG_(INFO) << "tokenID :" << tokenID;
    ASSERT_EQ(ERR_PERM_REQUEST_CFG_FAILED, ret);
}

/**
 * @tc.name: UpdateHapTokenSpecsTest006
 * @tc.desc: App user_grant permission has not been operated, update with pre-authorization.
 *           1.preAuthorizationInfo = {info1}, pre-authorization update success
 *           2.GetReqPermissions success. permission is GRANTED.
 * @tc.type: FUNC
 * @tc.require: Issue Number
 */
HWTEST_F(UpdateHapTokenTest, UpdateHapTokenSpecsTest006, TestSize.Level1)
{
    HapPolicyParams testPolicyParams1 = {
        .apl = APL_NORMAL,
        .domain = "test.domain2",
        .permStateList = {g_infoManagerCameraState}
    };
    AccessTokenIDEx fullTokenId;
    int32_t ret = AccessTokenKit::InitHapToken(g_testHapInfoParams, testPolicyParams1, fullTokenId);
    GTEST_LOG_(INFO) << "tokenID :" << fullTokenId.tokenIdExStruct.tokenID;
    EXPECT_EQ(RET_SUCCESS, ret);

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
    ret = AccessTokenKit::UpdateHapToken(fullTokenId, info, testPolicyParams2);
    ASSERT_EQ(RET_SUCCESS, ret);
    std::vector<PermissionStateFull> state;
    int32_t res = AccessTokenKit::GetReqPermissions(fullTokenId.tokenIdExStruct.tokenID, state, false);
    ASSERT_EQ(RET_SUCCESS, res);
    ASSERT_EQ(static_cast<uint32_t>(1), state.size());
    ASSERT_EQ("ohos.permission.CAMERA", state[0].permissionName);
    EXPECT_EQ(state[0].grantStatus[0], PERMISSION_GRANTED);
    EXPECT_EQ(state[0].grantFlags[0], PERMISSION_SYSTEM_FIXED);

    ASSERT_EQ(RET_SUCCESS, AccessTokenKit::DeleteToken(fullTokenId.tokenIdExStruct.tokenID));
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
HWTEST_F(UpdateHapTokenTest, UpdateHapTokenSpecsTest007, TestSize.Level1)
{
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
    ASSERT_EQ(static_cast<uint32_t>(2), state.size());
    ASSERT_EQ("ohos.permission.CAMERA", state[0].permissionName);
    EXPECT_EQ(state[0].grantStatus[0], PERMISSION_GRANTED);
    EXPECT_EQ(state[0].grantFlags[0], PERMISSION_USER_FIXED);
    ASSERT_EQ("ohos.permission.MICROPHONE", state[1].permissionName);
    EXPECT_EQ(state[1].grantStatus[0], PERMISSION_DENIED);
    EXPECT_EQ(state[1].grantFlags[0], PERMISSION_USER_FIXED);

    ASSERT_EQ(RET_SUCCESS, AccessTokenKit::DeleteToken(fullTokenId.tokenIdExStruct.tokenID));
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
HWTEST_F(UpdateHapTokenTest, UpdateHapTokenSpecsTest008, TestSize.Level1)
{
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
    ASSERT_EQ(static_cast<uint32_t>(2), state.size());
    EXPECT_EQ(state[0].grantStatus[0], PERMISSION_GRANTED);
    EXPECT_EQ(state[0].grantFlags[0], PERMISSION_GRANTED_BY_POLICY);
    EXPECT_EQ(state[1].grantStatus[0], PERMISSION_DENIED);
    EXPECT_EQ(state[1].grantFlags[0], PERMISSION_DEFAULT_FLAG);

    ASSERT_EQ(RET_SUCCESS, AccessTokenKit::DeleteToken(fullTokenId.tokenIdExStruct.tokenID));
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
HWTEST_F(UpdateHapTokenTest, UpdateHapTokenSpecsTest009, TestSize.Level1)
{
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
    ASSERT_EQ(static_cast<uint32_t>(2), state.size());
    EXPECT_EQ(state[0].grantStatus[0], PERMISSION_GRANTED);
    EXPECT_EQ(state[0].grantFlags[0], PERMISSION_SYSTEM_FIXED);
    EXPECT_EQ(state[1].grantStatus[0], PERMISSION_DENIED);
    EXPECT_EQ(state[1].grantFlags[0], PERMISSION_USER_FIXED | PERMISSION_GRANTED_BY_POLICY);

    ASSERT_EQ(RET_SUCCESS, AccessTokenKit::DeleteToken(fullTokenId.tokenIdExStruct.tokenID));
}

/**
 * @tc.name: UpdateHapTokenAbnormalTest001
 * @tc.desc: test invaild UpdateHapInfoParams.appIDDesc
 *           1.appIDDesc is too long
 *           2.update failed.
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(UpdateHapTokenTest, UpdateHapTokenAbnormalTest001, TestSize.Level1)
{
    HapInfoParams infoParams;
    HapPolicyParams policyParams;
    TestCommon::GetHapParams(infoParams, policyParams);
    AccessTokenIDEx fullTokenId;
    int32_t ret = AccessTokenKit::InitHapToken(infoParams, policyParams, fullTokenId);
    AccessTokenID tokenID = fullTokenId.tokenIdExStruct.tokenID;
    GTEST_LOG_(INFO) << "tokenID :" << tokenID;
    ASSERT_EQ(RET_SUCCESS, ret);
    UpdateHapInfoParams updateHapInfoParams = {
        .appIDDesc = infoParams.appIDDesc,
        .apiVersion = infoParams.apiVersion,
        .isSystemApp = infoParams.isSystemApp,
        .appDistributionType = infoParams.appDistributionType
    };

    for (int i = 0; i < THIRTY_TIME_CYCLES; i++) {
        updateHapInfoParams.appIDDesc += OVER_SIZE_STR;
    }

    ret = AccessTokenKit::UpdateHapToken(fullTokenId, updateHapInfoParams, policyParams);
    EXPECT_EQ(ERR_PARAM_INVALID, ret);
}

/**
 * @tc.name: UpdateHapTokenAbnormalTest002
 * @tc.desc: test invaild HapPolicyParams.apl
 *           1.apl is invaild.
 *           2.update failed.
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(UpdateHapTokenTest, UpdateHapTokenAbnormalTest002, TestSize.Level1)
{
    HapInfoParams infoParams;
    HapPolicyParams policyParams;
    TestCommon::GetHapParams(infoParams, policyParams);
    AccessTokenIDEx fullTokenId;
    int32_t ret = AccessTokenKit::InitHapToken(infoParams, policyParams, fullTokenId);
    AccessTokenID tokenID = fullTokenId.tokenIdExStruct.tokenID;
    GTEST_LOG_(INFO) << "tokenID :" << tokenID;
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
}

/**
 * @tc.name: UpdateHapTokenAbnormalTest003
 * @tc.desc: test invaild permStateList.permissionName
 *           1.permissionName is empty.
 *           2.permissionName is invaild.
 *           3.update success, GetReqPermissions is empty.
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(UpdateHapTokenTest, UpdateHapTokenAbnormalTest003, TestSize.Level1)
{
    HapInfoParams infoParams;
    HapPolicyParams policyParams;
    TestCommon::GetHapParams(infoParams, policyParams);
    AccessTokenIDEx fullTokenId;
    int32_t ret = AccessTokenKit::InitHapToken(infoParams, policyParams, fullTokenId);
    AccessTokenID tokenID = fullTokenId.tokenIdExStruct.tokenID;
    GTEST_LOG_(INFO) << "tokenID :" << tokenID;
    ASSERT_EQ(RET_SUCCESS, ret);

    UpdateHapInfoParams updateHapInfoParams = {
        .appIDDesc = infoParams.appIDDesc,
        .apiVersion = infoParams.apiVersion,
        .isSystemApp = infoParams.isSystemApp,
        .appDistributionType = infoParams.appDistributionType
    };

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
    ret = AccessTokenKit::UpdateHapToken(fullTokenId, updateHapInfoParams, policyParams);
    ASSERT_EQ(RET_SUCCESS, ret);
    tokenID = fullTokenId.tokenIdExStruct.tokenID;
    std::vector<PermissionStateFull> reqPermList;
    ret = AccessTokenKit::GetReqPermissions(tokenID, reqPermList, false);
    EXPECT_TRUE(reqPermList.empty());
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
HWTEST_F(UpdateHapTokenTest, UpdateHapTokenAbnormalTest004, TestSize.Level1)
{
    HapInfoParams infoParams;
    HapPolicyParams policyParams;
    TestCommon::GetHapParams(infoParams, policyParams);
    policyParams.apl = APL_NORMAL;
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
    ret = AccessTokenKit::UpdateHapToken(fullTokenId, updateHapInfoParams, policyParams);
    EXPECT_EQ(RET_SUCCESS, ret);
    tokenID = fullTokenId.tokenIdExStruct.tokenID;
    ret = AccessTokenKit::VerifyAccessToken(tokenID, "");
    EXPECT_EQ(PERMISSION_DENIED, ret);

    policyParams.aclRequestedList = {"ohos.permission.test"};
    ret = AccessTokenKit::UpdateHapToken(fullTokenId, updateHapInfoParams, policyParams);
    EXPECT_EQ(RET_SUCCESS, ret);
    ret = AccessTokenKit::VerifyAccessToken(tokenID, "ohos.permission.test");
    EXPECT_EQ(PERMISSION_DENIED, ret);

    policyParams.aclRequestedList = {"ohos.permission.AGENT_REQUIRE_FORM"};
    ret = AccessTokenKit::UpdateHapToken(fullTokenId, updateHapInfoParams, policyParams);
    ASSERT_EQ(RET_SUCCESS, ret);
    ret = AccessTokenKit::VerifyAccessToken(tokenID, "ohos.permission.AGENT_REQUIRE_FORM");
    EXPECT_EQ(PERMISSION_DENIED, ret);

    policyParams.permStateList.emplace_back(permissionStateFull002);
    policyParams.aclRequestedList.emplace_back("ohos.permission.MANAGE_DEVICE_AUTH_CRED");

    ret = AccessTokenKit::UpdateHapToken(fullTokenId, updateHapInfoParams, policyParams);
    ASSERT_EQ(ERR_PERM_REQUEST_CFG_FAILED, ret);
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
HWTEST_F(UpdateHapTokenTest, UpdateHapTokenAbnormalTest005, TestSize.Level1)
{
    HapInfoParams infoParams;
    HapPolicyParams policyParams;
    TestCommon::GetHapParams(infoParams, policyParams);
    AccessTokenIDEx fullTokenId;
    int32_t ret = AccessTokenKit::InitHapToken(infoParams, policyParams, fullTokenId);
    AccessTokenID tokenID = fullTokenId.tokenIdExStruct.tokenID;
    GTEST_LOG_(INFO) << "tokenID :" << tokenID;
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
}
} // namespace AccessToken
} // namespace Security
} // namespace OHOS