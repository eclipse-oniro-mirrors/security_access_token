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
static constexpr int32_t THIRTY_TIME_CYCLES = 30;
const std::string APP_DISTRIBUTION_TYPE_ENTERPRISE_MDM = "enterprise_mdm";
const std::string APP_DISTRIBUTION_TYPE_NONE = "none";
const std::string OVER_SIZE_STR =
    "AAANSUhEUgAAABUAAAAXCAIAAABrvZPKAAAACXBIWXMAAA7EAAAOxAGVKw4bAAAAEXRFWHRTb2Z0d2FyZQBTbmlwYXN0ZV0Xzt0A"
    "FBSURBVDiN7ZQ/S8NQFMVPxU/QCx06GBzrkqUZ42rBbHWUBDqYxSnUoTxXydCSycVsgltfBiFDR8HNdHGxY4nQQAPvMzwHsWn+KM"
    "vj3He5vIaUEjV0UAfe85X83KMBT7N75JEXVdSlfEAVfPRyZ5yfIrBoUkVlMU82Hkp8wu9ddt1vFew4sIiIiKwgzcXIvN7GTZOvpZ"
    "D3I1NZvmdCXz+XOv5wJANKHOVYjRTAghxIyh0FHKb+0QQH5+kXf2zkYGAG0oFr5RfnK8DAGkwY19wliRT2L448vjv0YGQFVa8VKd";
static constexpr OHOS::HiviewDFX::HiLogLabel LABEL = {LOG_CORE,
    SECURITY_DOMAIN_ACCESSTOKEN, "InitHapTokenTest"};

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
    .isSystemApp = true,
    .appDistributionType = ""
};

HapPolicyParams g_testPolicyParams = {
    .apl = APL_SYSTEM_CORE,
    .domain = "test_domain",
    .permList = {},
    .permStateList = { g_infoManagerManageHapState },
    .aclRequestedList = {},
    .preAuthorizationInfo = {}
};
};

void InitHapTokenTest::SetUpTestCase()
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

void InitHapTokenTest::TearDownTestCase()
{
    AccessTokenID tokenId = AccessTokenKit::GetHapTokenID(g_testHapInfoParams.userID,
        g_testHapInfoParams.bundleName,
        g_testHapInfoParams.instIndex);
    AccessTokenKit::DeleteToken(tokenId);
    SetSelfTokenID(g_selfTokenId);
}

void InitHapTokenTest::SetUp()
{
    ACCESSTOKEN_LOG_INFO(LABEL, "SetUp ok.");
    setuid(0);
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
HWTEST_F(InitHapTokenTest, InitHapTokenFuncTest001, TestSize.Level1)
{
    ACCESSTOKEN_LOG_INFO(LABEL, "InitHapTokenFuncTest001");

    HapInfoParams infoParams;
    HapPolicyParams policyParams;
    TestCommon::GetHapParams(infoParams, policyParams);
    infoParams.isSystemApp = false;
    AccessTokenIDEx fullTokenId;
    int32_t ret = AccessTokenKit::InitHapToken(infoParams, policyParams, fullTokenId);
    AccessTokenID tokenID = fullTokenId.tokenIdExStruct.tokenID;
    ASSERT_EQ(RET_SUCCESS, ret);

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

    ASSERT_EQ(RET_SUCCESS, AccessTokenKit::DeleteToken(tokenID));
}

/**
 * @tc.name: InitHapTokenFuncTest002
 * @tc.desc: Install systrem applications(isSystemApp = true).
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(InitHapTokenTest, InitHapTokenFuncTest002, TestSize.Level1)
{
    ACCESSTOKEN_LOG_INFO(LABEL, "InitHapTokenFuncTest002");

    HapInfoParams infoParams;
    HapPolicyParams policyParams;
    TestCommon::GetHapParams(infoParams, policyParams);
    AccessTokenIDEx fullTokenId;
    int32_t ret = AccessTokenKit::InitHapToken(infoParams, policyParams, fullTokenId);
    AccessTokenID tokenID = fullTokenId.tokenIdExStruct.tokenID;
    ASSERT_EQ(RET_SUCCESS, ret);

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
    EXPECT_EQ("AccessTokenTestAppID", hapInfoExt.appID);

    ASSERT_EQ(RET_SUCCESS, AccessTokenKit::DeleteToken(tokenID));
}

/**
 * @tc.name: InitHapTokenFuncTest003
 * @tc.desc: Test the isGeneral field in the permission authorization list(isGeneral is false or true).
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(InitHapTokenTest, InitHapTokenFuncTest003, TestSize.Level1)
{
    ACCESSTOKEN_LOG_INFO(LABEL, "InitHapTokenFuncTest003");

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
    int32_t ret = AccessTokenKit::InitHapToken(infoParams, policyParams, fullTokenId);
    AccessTokenID tokenID = fullTokenId.tokenIdExStruct.tokenID;
    ASSERT_EQ(RET_SUCCESS, ret);
    ret = AccessTokenKit::VerifyAccessToken(tokenID, "ohos.permission.ACCESS_CERT_MANAGER");
    EXPECT_EQ(PERMISSION_GRANTED, ret);
    ret = AccessTokenKit::VerifyAccessToken(tokenID, "ohos.permission.ACCESS_CERT_MANAGER_INTERNAL");
    EXPECT_EQ(PERMISSION_GRANTED, ret);

    ASSERT_EQ(RET_SUCCESS, AccessTokenKit::DeleteToken(tokenID));
}

/**
 * @tc.name: InitHapTokenFuncTest004
 * @tc.desc:Init a tokenId successfully, delete it successfully the first time and fail to delete it again.
 * @tc.type: FUNC
 * @tc.require: Issue Number
 */
HWTEST_F(InitHapTokenTest, InitHapTokenFuncTest004, TestSize.Level1)
{
    ACCESSTOKEN_LOG_INFO(LABEL, "InitHapTokenFuncTest004");

    AccessTokenIDEx fullTokenId;
    int32_t ret = AccessTokenKit::InitHapToken(g_testHapInfoParams, g_testPolicyParams, fullTokenId);
    EXPECT_EQ(RET_SUCCESS, ret);
    ASSERT_EQ(RET_SUCCESS, AccessTokenKit::DeleteToken(fullTokenId.tokenIdExStruct.tokenID));
    ASSERT_NE(RET_SUCCESS, AccessTokenKit::DeleteToken(fullTokenId.tokenIdExStruct.tokenID));
}

/**
 * @tc.name: InitHapTokenFuncTest005
 * @tc.desc: InitHapToken with dlp type.
 * @tc.type: FUNC
 * @tc.require: Issue Number
 */
HWTEST_F(InitHapTokenTest, InitHapTokenFuncTest005, TestSize.Level1)
{
    ACCESSTOKEN_LOG_INFO(LABEL, "InitHapTokenFuncTest005");

    HapInfoParams infoParams;
    HapPolicyParams policyParams;
    TestCommon::GetHapParams(infoParams, policyParams);
    policyParams.apl = APL_SYSTEM_BASIC;
    policyParams.permStateList  = { g_infoManagerCameraState, g_infoManagerMicrophoneState, g_infoManagerCertState };

    AccessTokenIDEx fullTokenId;
    int32_t res = AccessTokenKit::InitHapToken(infoParams, policyParams, fullTokenId);
    EXPECT_EQ(RET_SUCCESS, res);

    HapInfoParams infoParams1 = infoParams;
    infoParams1.dlpType = DLP_FULL_CONTROL;
    infoParams1.instIndex++;
    AccessTokenIDEx dlpFullTokenId1;
    res = AccessTokenKit::InitHapToken(infoParams1, policyParams, dlpFullTokenId1);
    EXPECT_EQ(RET_SUCCESS, res);

    res = AccessTokenKit::VerifyAccessToken(dlpFullTokenId1.tokenIdExStruct.tokenID, "ohos.permission.CAMERA");
    EXPECT_EQ(res, PERMISSION_DENIED);

    (void)AccessTokenKit::GrantPermission(
        fullTokenId.tokenIdExStruct.tokenID, "ohos.permission.CAMERA", PERMISSION_USER_SET);
    (void)AccessTokenKit::RevokePermission(
        fullTokenId.tokenIdExStruct.tokenID, "ohos.permission.MICROPHONE", PERMISSION_USER_SET);

    infoParams1.instIndex++;
    AccessTokenIDEx dlpFullTokenId2;
    res = AccessTokenKit::InitHapToken(infoParams1, policyParams, dlpFullTokenId2);
    EXPECT_EQ(RET_SUCCESS, res);
    res = AccessTokenKit::VerifyAccessToken(dlpFullTokenId2.tokenIdExStruct.tokenID, "ohos.permission.CAMERA");
    EXPECT_EQ(res, PERMISSION_GRANTED);
    res = AccessTokenKit::VerifyAccessToken(dlpFullTokenId1.tokenIdExStruct.tokenID, "ohos.permission.CAMERA");
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
 * @tc.name: InitHapTokenSpecsTest001
 * @tc.desc: Test the high-level permission authorized by acl.
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(InitHapTokenTest, InitHapTokenSpecsTest001, TestSize.Level1)
{
    ACCESSTOKEN_LOG_INFO(LABEL, "InitHapTokenSpecsTest001");

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
    ASSERT_EQ(RET_SUCCESS, ret);

    ret = AccessTokenKit::VerifyAccessToken(tokenID, "ohos.permission.RUN_DYN_CODE");
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
HWTEST_F(InitHapTokenTest, InitHapTokenSpecsTest002, TestSize.Level1)
{
    ACCESSTOKEN_LOG_INFO(LABEL, "InitHapTokenSpecsTest002");

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
    int32_t ret = AccessTokenKit::InitHapToken(infoParams, policyParams, fullTokenId);
    ASSERT_EQ(ERR_PERM_REQUEST_CFG_FAILED, ret);
}

/**
 * @tc.name: InitHapTokenSpecsTest003
 * @tc.desc: Initialize system_grant&&user_grant permission.
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(InitHapTokenTest, InitHapTokenSpecsTest003, TestSize.Level1)
{
    ACCESSTOKEN_LOG_INFO(LABEL, "InitHapTokenSpecsTest003");

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
    int32_t ret = AccessTokenKit::InitHapToken(infoParams, policyParams, fullTokenId);
    AccessTokenID tokenID = fullTokenId.tokenIdExStruct.tokenID;
    ASSERT_EQ(RET_SUCCESS, ret);

    ret = AccessTokenKit::VerifyAccessToken(tokenID, "ohos.permission.READ_HEALTH_MOTION");
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
HWTEST_F(InitHapTokenTest, InitHapTokenSpecsTest004, TestSize.Level1)
{
    ACCESSTOKEN_LOG_INFO(LABEL, "InitHapTokenSpecsTest004");

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
    int32_t ret = AccessTokenKit::InitHapToken(infoParams, policyParams, fullTokenId);
    AccessTokenID tokenID = fullTokenId.tokenIdExStruct.tokenID;
    ASSERT_EQ(RET_SUCCESS, ret);

    ret = AccessTokenKit::VerifyAccessToken(tokenID, "ohos.permission.ACCESS_NEARLINK");
    EXPECT_EQ(PERMISSION_GRANTED, ret);
    ret = AccessTokenKit::VerifyAccessToken(tokenID, "ohos.permission.READ_WRITE_DESKTOP_DIRECTORY");
    EXPECT_EQ(PERMISSION_GRANTED, ret);

    std::vector<PermissionStateFull> permStatList;
    ASSERT_EQ(RET_SUCCESS, AccessTokenKit::GetReqPermissions(tokenID, permStatList, false));
    ASSERT_EQ(static_cast<uint32_t>(2), permStatList.size());
    ASSERT_EQ("ohos.permission.ACCESS_NEARLINK", permStatList[0].permissionName);
    EXPECT_EQ(permStatList[0].grantStatus[0], PERMISSION_GRANTED);
    EXPECT_EQ(permStatList[0].grantFlags[0], PERMISSION_GRANTED_BY_POLICY);
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
HWTEST_F(InitHapTokenTest, InitHapTokenSpecsTest005, TestSize.Level1)
{
    ACCESSTOKEN_LOG_INFO(LABEL, "InitHapTokenSpecsTest005");

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
HWTEST_F(InitHapTokenTest, InitHapTokenSpecsTest006, TestSize.Level1)
{
    ACCESSTOKEN_LOG_INFO(LABEL, "InitHapTokenSpecsTest006");

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
HWTEST_F(InitHapTokenTest, InitHapTokenSpecsTest007, TestSize.Level1)
{
    ACCESSTOKEN_LOG_INFO(LABEL, "InitHapTokenSpecsTest007");

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
    AccessTokenIDEx fullTokenId;
    int32_t ret = AccessTokenKit::InitHapToken(infoParams, policyParams, fullTokenId);
    AccessTokenID tokenID = fullTokenId.tokenIdExStruct.tokenID;
    ASSERT_EQ(ERR_PERM_REQUEST_CFG_FAILED, ret);

    ret = AccessTokenKit::VerifyAccessToken(tokenID, "ohos.permission.ENTERPRISE_MANAGE_SETTINGS");
    EXPECT_EQ(PERMISSION_DENIED, ret);
}

/**
 * @tc.name: InitHapTokenSpecsTest008
 * @tc.desc: Initialize MDM permission for a debug hap.
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(InitHapTokenTest, InitHapTokenSpecsTest008, TestSize.Level1)
{
    ACCESSTOKEN_LOG_INFO(LABEL, "InitHapTokenSpecsTest008");

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
 * @tc.name: InitHapTokenAbnormalTest001
 * @tc.desc: Invaild HapInfoParams.
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(InitHapTokenTest, InitHapTokenAbnormalTest001, TestSize.Level1)
{
    ACCESSTOKEN_LOG_INFO(LABEL, "InitHapTokenAbnormalTest001");

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
HWTEST_F(InitHapTokenTest, InitHapTokenAbnormalTest002, TestSize.Level1)
{
    ACCESSTOKEN_LOG_INFO(LABEL, "InitHapTokenAbnormalTest002");

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
HWTEST_F(InitHapTokenTest, InitHapTokenAbnormalTest003, TestSize.Level1)
{
    ACCESSTOKEN_LOG_INFO(LABEL, "InitHapTokenAbnormalTest003");

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
    int32_t ret = AccessTokenKit::InitHapToken(infoParams, policyParams, fullTokenId);
    ASSERT_EQ(RET_SUCCESS, ret);
    AccessTokenID tokenID = fullTokenId.tokenIdExStruct.tokenID;
    std::vector<PermissionStateFull> reqPermList;
    ret = AccessTokenKit::GetReqPermissions(tokenID, reqPermList, false);
    EXPECT_TRUE(reqPermList.empty());

    ASSERT_EQ(RET_SUCCESS, AccessTokenKit::DeleteToken(tokenID));
}

/**
 * @tc.name: InitHapTokenAbnormalTest004
 * @tc.desc: Invaild aclRequestedList.
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(InitHapTokenTest, InitHapTokenAbnormalTest004, TestSize.Level1)
{
    ACCESSTOKEN_LOG_INFO(LABEL, "InitHapTokenAbnormalTest004");

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
    int32_t ret = AccessTokenKit::InitHapToken(infoParams, policyParams, fullTokenId);
    EXPECT_EQ(RET_SUCCESS, ret);
    AccessTokenID tokenID = fullTokenId.tokenIdExStruct.tokenID;
    ret = AccessTokenKit::VerifyAccessToken(tokenID, "");
    EXPECT_EQ(PERMISSION_DENIED, ret);

    policyParams.aclRequestedList = {"ohos.permission.test"};
    ret = AccessTokenKit::InitHapToken(infoParams, policyParams, fullTokenId);
    EXPECT_EQ(RET_SUCCESS, ret);
    ret = AccessTokenKit::VerifyAccessToken(tokenID, "ohos.permission.test");
    EXPECT_EQ(PERMISSION_DENIED, ret);

    policyParams.aclRequestedList = {"ohos.permission.AGENT_REQUIRE_FORM"};
    ret = AccessTokenKit::InitHapToken(infoParams, policyParams, fullTokenId);
    ASSERT_EQ(RET_SUCCESS, ret);
    ret = AccessTokenKit::VerifyAccessToken(tokenID, "ohos.permission.AGENT_REQUIRE_FORM");
    EXPECT_EQ(PERMISSION_DENIED, ret);

    policyParams.permStateList.emplace_back(permissionStateFull002);
    policyParams.aclRequestedList.emplace_back("ohos.permission.ACCESS_EXTENSIONAL_DEVICE_DRIVER");

    ret = AccessTokenKit::InitHapToken(infoParams, policyParams, fullTokenId);
    ASSERT_EQ(RET_SUCCESS, ret);
    ret = AccessTokenKit::VerifyAccessToken(tokenID, "ohos.permission.ACCESS_EXTENSIONAL_DEVICE_DRIVER");
    EXPECT_EQ(PERMISSION_DENIED, ret);
}

/**
 * @tc.name: InitHapTokenAbnormalTest005
 * @tc.desc: Invaild preAuthorizationInfo.
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(InitHapTokenTest, InitHapTokenAbnormalTest005, TestSize.Level1)
{
    ACCESSTOKEN_LOG_INFO(LABEL, "InitHapTokenAbnormalTest005");

    HapInfoParams infoParams;
    HapPolicyParams policyParams;
    TestCommon::GetHapParams(infoParams, policyParams);

    PreAuthorizationInfo preAuthorizationInfo;
    preAuthorizationInfo.permissionName = "";
    policyParams.preAuthorizationInfo = {preAuthorizationInfo};
    AccessTokenIDEx fullTokenId;
    int32_t ret = AccessTokenKit::InitHapToken(infoParams, policyParams, fullTokenId);
    EXPECT_EQ(RET_SUCCESS, ret);
    AccessTokenID tokenID = fullTokenId.tokenIdExStruct.tokenID;
    ret = AccessTokenKit::VerifyAccessToken(tokenID, "");
    EXPECT_EQ(PERMISSION_DENIED, ret);

    preAuthorizationInfo.permissionName = "ohos.permission.test";
    policyParams.preAuthorizationInfo = {preAuthorizationInfo};
    ret = AccessTokenKit::InitHapToken(infoParams, policyParams, fullTokenId);
    EXPECT_EQ(RET_SUCCESS, ret);
    ret = AccessTokenKit::VerifyAccessToken(tokenID, "ohos.permission.test");
    EXPECT_EQ(PERMISSION_DENIED, ret);

    preAuthorizationInfo.permissionName = "ohos.permission.AGENT_REQUIRE_FORM";
    policyParams.preAuthorizationInfo = {preAuthorizationInfo};
    ret = AccessTokenKit::InitHapToken(infoParams, policyParams, fullTokenId);
    ASSERT_EQ(RET_SUCCESS, ret);
    ret = AccessTokenKit::VerifyAccessToken(tokenID, "ohos.permission.AGENT_REQUIRE_FORM");
    EXPECT_EQ(PERMISSION_DENIED, ret);
}
} // namespace AccessToken
} // namespace Security
} // namespace OHOS