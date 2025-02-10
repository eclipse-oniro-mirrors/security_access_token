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
#include "tokenid_kit.h"
#include "token_setproc.h"

using namespace testing::ext;
namespace OHOS {
namespace Security {
namespace AccessToken {
namespace {
static AccessTokenID g_selfTokenId = 0;
static constexpr int32_t  DEFAULT_API_VERSION = 12;

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

HapInfoParams g_testHapInfoParams = {
    .userID = 0,
    .bundleName = "InitHapTokenTest",
    .instIndex = 0,
    .appIDDesc = "InitHapTokenTest",
    .apiVersion = DEFAULT_API_VERSION,
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
    setuid(0);
}

void InitHapTokenTest::TearDown()
{
}

void InitHapTokenTest::GetHapParams(HapInfoParams& infoParams, HapPolicyParams& policyParams)
{
    infoParams.userID = 0;
    infoParams.bundleName = "com.ohos.AccessTokenTestBundle";
    infoParams.instIndex = 0;
    infoParams.appIDDesc = "AccessTokenTestAppID";
    infoParams.apiVersion = DEFAULT_API_VERSION;
    infoParams.isSystemApp = true;
    infoParams.appDistributionType = "";

    policyParams.apl = APL_NORMAL;
    policyParams.domain = "accesstoken_test_domain";
    policyParams.permList = {};
    policyParams.permStateList = {};
    policyParams.aclRequestedList = {};
    policyParams.preAuthorizationInfo = {};
}

/**
 * @tc.name: InitHapTokenAbnormalTest006
 * @tc.desc: InitHapToken isRestore with INVALID_TOKENID
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(InitHapTokenTest, InitHapTokenAbnormalTest006, TestSize.Level1)
{
    HapInfoParams infoParams;
    HapPolicyParams policyParams;
    GetHapParams(infoParams, policyParams);

    infoParams.isRestore = true;
    infoParams.tokenID = INVALID_TOKENID;

    PreAuthorizationInfo preAuthorizationInfo;
    preAuthorizationInfo.permissionName = "";
    policyParams.preAuthorizationInfo = {preAuthorizationInfo};
    AccessTokenIDEx fullTokenId;
    int32_t ret = AccessTokenKit::InitHapToken(infoParams, policyParams, fullTokenId);
    EXPECT_EQ(ERR_PARAM_INVALID, ret);
}

/**
 * @tc.name: InitHapTokenSpecsTest009
 * @tc.desc: InitHapToken isRestore with real token
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(InitHapTokenTest, InitHapTokenSpecsTest009, TestSize.Level1)
{
    HapInfoParams infoParams;
    HapPolicyParams policyParams;
    GetHapParams(infoParams, policyParams);
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
}
} // namespace AccessToken
} // namespace Security
} // namespace OHOS