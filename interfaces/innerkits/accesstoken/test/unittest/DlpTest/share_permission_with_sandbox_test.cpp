/*
 * Copyright (c) 2023 Huawei Device Co., Ltd.
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

#include "share_permission_with_sandbox_test.h"
#include <thread>

#include "accesstoken_kit.h"
#include "accesstoken_common_log.h"
#include "access_token_error.h"
#include "nativetoken_kit.h"
#include "test_common.h"
#include "token_setproc.h"
#include "tokenid_kit.h"

using namespace testing::ext;
using namespace OHOS::Security::AccessToken;

namespace {
static const std::string PERMISSION_ALL = "ohos.permission.APP_TRACKING_CONSENT";
static const std::string PERMISSION_FULL_CONTROL = "ohos.permission.PRINT";
static const std::string PERMISSION_NONE = "ohos.permission.INTERNET";
static const std::string PERMISSION_NOT_DISPLAYED = "ohos.permission.ANSWER_CALL";
static const std::string TEST_PERMISSION_GRANT = "ohos.permission.GRANT_SENSITIVE_PERMISSIONS";
static const std::string TEST_PERMISSION_REVOKE = "ohos.permission.REVOKE_SENSITIVE_PERMISSIONS";
static uint64_t g_selfTokenId = 0;

HapInfoParams g_infoParmsCommon = {
    .userID = 1,
    .bundleName = "PermissionShareTest",
    .instIndex = 0,
    .dlpType = DLP_COMMON,
    .appIDDesc = "PermissionShareTest"
};

HapInfoParams g_infoParmsFullControl = {
    .userID = 1,
    .bundleName = "PermissionShareTest",
    .instIndex = 1,
    .dlpType = DLP_FULL_CONTROL,
    .appIDDesc = "PermissionShareTest"
};

HapInfoParams g_infoParmsReadOnly = {
    .userID = 1,
    .bundleName = "PermissionShareTest",
    .instIndex = 2,
    .dlpType = DLP_READ,
    .appIDDesc = "PermissionShareTest"
};

PermissionStateFull g_stateFullControl = {
    .permissionName = "ohos.permission.PRINT",
    .isGeneral = true,
    .resDeviceID = {"local"},
    .grantStatus = {PermissionState::PERMISSION_DENIED},
    .grantFlags = {0}
};

PermissionStateFull g_stateNone = {
    .permissionName = "ohos.permission.INTERNET",
    .isGeneral = true,
    .resDeviceID = {"local"},
    .grantStatus = {PermissionState::PERMISSION_DENIED},
    .grantFlags = {0}
};

PermissionStateFull g_stateAll = {
    .permissionName = PERMISSION_ALL,
    .isGeneral = true,
    .resDeviceID = {"local"},
    .grantStatus = {PermissionState::PERMISSION_DENIED},
    .grantFlags = {0}
};

PermissionStateFull g_stateNotDisplayed = {
    .permissionName = "ohos.permission.ANSWER_CALL",
    .isGeneral = true,
    .resDeviceID = {"local"},
    .grantStatus = {PermissionState::PERMISSION_DENIED},
    .grantFlags = {0}
};

HapPolicyParams g_policyParams = {
    .apl = APL_NORMAL,
    .domain = "test.domain",
    .permStateList = {g_stateFullControl, g_stateNone, g_stateAll, g_stateNotDisplayed}
};

}

void SharePermissionTest::SetUpTestCase()
{
    g_selfTokenId = GetSelfTokenID();
    TestCommon::SetTestEvironment(g_selfTokenId);

    HapInfoParams infoParmsEnvironment = {
        .userID = 1,
        .bundleName = "PermissionEnvironment",
        .instIndex = 0,
        .dlpType = DLP_COMMON,
        .appIDDesc = "PermissionEnvironment",
        .isSystemApp = true
    };
    PermissionStateFull stateGrant = {
        .permissionName = TEST_PERMISSION_GRANT,
        .isGeneral = true,
        .resDeviceID = {"local"},
        .grantStatus = {PermissionState::PERMISSION_GRANTED},
        .grantFlags = {0}
    };
    PermissionStateFull stateRevoke = {
        .permissionName = TEST_PERMISSION_REVOKE,
        .isGeneral = true,
        .resDeviceID = {"local"},
        .grantStatus = {PermissionState::PERMISSION_GRANTED},
        .grantFlags = {0}
    };
    HapPolicyParams policyParams = {
        .apl = APL_NORMAL,
        .domain = "test.domain",
        .permStateList = {stateGrant, stateRevoke}
    };
    AccessTokenIDEx tokenIdEx = {0};
    EXPECT_EQ(RET_SUCCESS, TestCommon::AllocTestHapToken(infoParmsEnvironment, policyParams, tokenIdEx));
    EXPECT_NE(0, tokenIdEx.tokenIdExStruct.tokenID);
    EXPECT_EQ(true,  TokenIdKit::IsSystemAppByFullTokenID(tokenIdEx.tokenIDEx));
    EXPECT_EQ(0, SetSelfTokenID(tokenIdEx.tokenIDEx));
    LOGI(ATM_DOMAIN, ATM_TAG, "SetUpTestCase ok.");
}

void SharePermissionTest::TearDownTestCase()
{
    EXPECT_EQ(0, SetSelfTokenID(g_selfTokenId));
    TestCommon::ResetTestEvironment();

    AccessTokenIDEx tokenIdEx = TestCommon::GetHapTokenIdFromBundle(1, "PermissionEnvironment", 0);
    AccessTokenID tokenId = tokenIdEx.tokenIdExStruct.tokenID;
    if (tokenId != INVALID_TOKENID) {
        EXPECT_EQ(RET_SUCCESS, TestCommon::DeleteTestHapToken(tokenId));
    }
}

void SharePermissionTest::SetUp()
{
    LOGI(ATM_DOMAIN, ATM_TAG, "SetUp ok.");
}

void SharePermissionTest::TearDown()
{
}

static AccessTokenID AllocHapTokenId(HapInfoParams info, HapPolicyParams policy)
{
    MockNativeToken mock("foundation");
    AccessTokenIDEx tokenIdEx = AccessTokenKit::AllocHapToken(info, policy);
    AccessTokenID tokenId = tokenIdEx.tokenIdExStruct.tokenID;
    EXPECT_NE(0, tokenId);
    int ret = AccessTokenKit::VerifyAccessToken(tokenId, PERMISSION_FULL_CONTROL, false);
    EXPECT_EQ(ret, PermissionState::PERMISSION_DENIED);
    ret = AccessTokenKit::VerifyAccessToken(tokenId, PERMISSION_ALL, false);
    EXPECT_EQ(ret, PermissionState::PERMISSION_DENIED);
    ret = AccessTokenKit::VerifyAccessToken(tokenId, PERMISSION_NONE, false);
    EXPECT_EQ(ret, PermissionState::PERMISSION_DENIED);
    return tokenId;
}

/**
 * @tc.name: SharePermissionTest001
 * @tc.desc: .
 * @tc.type: FUNC
 * @tc.require:Issue Number
 */
HWTEST_F(SharePermissionTest, PermissionShareTest001, TestSize.Level0)
{
    int ret;
    AccessTokenID tokenCommon = AllocHapTokenId(g_infoParmsCommon, g_policyParams);
    AccessTokenID tokenFullControl = AllocHapTokenId(g_infoParmsFullControl, g_policyParams);
    AccessTokenID tokenFullRead = AllocHapTokenId(g_infoParmsReadOnly, g_policyParams);

    // grant common app
    ret = TestCommon::GrantPermissionByTest(tokenCommon, PERMISSION_ALL, PERMISSION_USER_FIXED);
    EXPECT_EQ(RET_SUCCESS, ret);
    ret = AccessTokenKit::VerifyAccessToken(tokenCommon, PERMISSION_ALL, false);
    EXPECT_EQ(ret, PermissionState::PERMISSION_GRANTED);
    ret = AccessTokenKit::VerifyAccessToken(tokenFullControl, PERMISSION_ALL, false);
    EXPECT_EQ(ret, PermissionState::PERMISSION_GRANTED);
    ret = AccessTokenKit::VerifyAccessToken(tokenFullRead, PERMISSION_ALL, false);
    EXPECT_EQ(ret, PermissionState::PERMISSION_GRANTED);

    // grant common app
    ret = TestCommon::GrantPermissionByTest(tokenCommon, PERMISSION_FULL_CONTROL, PERMISSION_USER_FIXED);
    EXPECT_EQ(RET_SUCCESS, ret);
    ret = AccessTokenKit::VerifyAccessToken(tokenCommon, PERMISSION_FULL_CONTROL, false);
    EXPECT_EQ(ret, PermissionState::PERMISSION_GRANTED);
    ret = AccessTokenKit::VerifyAccessToken(tokenFullControl, PERMISSION_FULL_CONTROL, false);
    EXPECT_EQ(ret, PermissionState::PERMISSION_GRANTED);
    ret = AccessTokenKit::VerifyAccessToken(tokenFullRead, PERMISSION_FULL_CONTROL, false);
    EXPECT_EQ(ret, PermissionState::PERMISSION_DENIED);

    // grant common app
    ret = TestCommon::GrantPermissionByTest(tokenCommon, PERMISSION_NONE, PERMISSION_USER_FIXED);
    EXPECT_EQ(RET_SUCCESS, ret);
    ret = AccessTokenKit::VerifyAccessToken(tokenCommon, PERMISSION_NONE, false);
    EXPECT_EQ(ret, PermissionState::PERMISSION_GRANTED);
    ret = AccessTokenKit::VerifyAccessToken(tokenFullControl, PERMISSION_NONE, false);
    EXPECT_EQ(ret, PermissionState::PERMISSION_DENIED);
    ret = AccessTokenKit::VerifyAccessToken(tokenFullRead, PERMISSION_NONE, false);
    EXPECT_EQ(ret, PermissionState::PERMISSION_DENIED);

    EXPECT_EQ(RET_SUCCESS, TestCommon::DeleteTestHapToken(tokenCommon));
    EXPECT_EQ(RET_SUCCESS, TestCommon::DeleteTestHapToken(tokenFullControl));
    EXPECT_EQ(RET_SUCCESS, TestCommon::DeleteTestHapToken(tokenFullRead));
}

/**
 * @tc.name: SharePermissionTest002
 * @tc.desc: .
 * @tc.type: FUNC
 * @tc.require:Issue Number
 */
HWTEST_F(SharePermissionTest, PermissionShareTest002, TestSize.Level0)
{
    int ret;
    AccessTokenID tokenCommon = AllocHapTokenId(g_infoParmsCommon, g_policyParams);
    AccessTokenID tokenFullControl = AllocHapTokenId(g_infoParmsFullControl, g_policyParams);
    AccessTokenID tokenFullRead = AllocHapTokenId(g_infoParmsReadOnly, g_policyParams);

    // grant common app
    ret = TestCommon::GrantPermissionByTest(tokenFullControl, PERMISSION_ALL, PERMISSION_USER_FIXED);
    EXPECT_EQ(RET_SUCCESS, ret);
    ret = AccessTokenKit::VerifyAccessToken(tokenCommon, PERMISSION_ALL, false);
    EXPECT_EQ(ret, PermissionState::PERMISSION_GRANTED);
    ret = AccessTokenKit::VerifyAccessToken(tokenFullControl, PERMISSION_ALL, false);
    EXPECT_EQ(ret, PermissionState::PERMISSION_GRANTED);
    ret = AccessTokenKit::VerifyAccessToken(tokenFullRead, PERMISSION_ALL, false);
    EXPECT_EQ(ret, PermissionState::PERMISSION_GRANTED);

    // grant common app
    ret = TestCommon::GrantPermissionByTest(tokenFullControl, PERMISSION_FULL_CONTROL, PERMISSION_USER_FIXED);
    EXPECT_EQ(RET_SUCCESS, ret);
    ret = AccessTokenKit::VerifyAccessToken(tokenCommon, PERMISSION_FULL_CONTROL, false);
    EXPECT_EQ(ret, PermissionState::PERMISSION_GRANTED);
    ret = AccessTokenKit::VerifyAccessToken(tokenFullControl, PERMISSION_FULL_CONTROL, false);
    EXPECT_EQ(ret, PermissionState::PERMISSION_GRANTED);
    ret = AccessTokenKit::VerifyAccessToken(tokenFullRead, PERMISSION_FULL_CONTROL, false);
    EXPECT_EQ(ret, PermissionState::PERMISSION_DENIED);

    // grant common app
    ret = TestCommon::GrantPermissionByTest(tokenFullControl, PERMISSION_NONE, PERMISSION_USER_FIXED);
    EXPECT_NE(RET_SUCCESS, ret);
    ret = AccessTokenKit::VerifyAccessToken(tokenCommon, PERMISSION_NONE, false);
    EXPECT_EQ(ret, PermissionState::PERMISSION_DENIED);
    ret = AccessTokenKit::VerifyAccessToken(tokenFullControl, PERMISSION_NONE, false);
    EXPECT_EQ(ret, PermissionState::PERMISSION_DENIED);
    ret = AccessTokenKit::VerifyAccessToken(tokenFullRead, PERMISSION_NONE, false);
    EXPECT_EQ(ret, PermissionState::PERMISSION_DENIED);

    EXPECT_EQ(RET_SUCCESS, TestCommon::DeleteTestHapToken(tokenCommon));
    EXPECT_EQ(RET_SUCCESS, TestCommon::DeleteTestHapToken(tokenFullControl));
    EXPECT_EQ(RET_SUCCESS, TestCommon::DeleteTestHapToken(tokenFullRead));
}

/**
 * @tc.name: PermissionShareClearUserGrantTest001
 * @tc.desc: .
 * @tc.type: FUNC
 * @tc.require:Issue Number
 */
HWTEST_F(SharePermissionTest, PermissionShareClearUserGrantTest001, TestSize.Level0)
{
    int ret;
    AccessTokenID tokenCommon = AllocHapTokenId(g_infoParmsCommon, g_policyParams);
    AccessTokenID tokenFullControl = AllocHapTokenId(g_infoParmsFullControl, g_policyParams);
    AccessTokenID tokenFullRead = AllocHapTokenId(g_infoParmsReadOnly, g_policyParams);

    // grant pre-authorization
    ret = TestCommon::GrantPermissionByTest(tokenFullControl, PERMISSION_ALL, PERMISSION_PRE_AUTHORIZED_CANCELABLE);
    EXPECT_EQ(RET_SUCCESS, ret);
    uint32_t flag;
    EXPECT_EQ(RET_SUCCESS, TestCommon::GetPermissionFlagByTest(tokenCommon, PERMISSION_ALL, flag));
    EXPECT_EQ(flag, PERMISSION_DEFAULT_FLAG);
    EXPECT_EQ(RET_SUCCESS, TestCommon::GetPermissionFlagByTest(tokenFullControl, PERMISSION_ALL, flag));
    EXPECT_EQ(flag, PERMISSION_DEFAULT_FLAG);
    EXPECT_EQ(RET_SUCCESS, TestCommon::GetPermissionFlagByTest(tokenFullRead, PERMISSION_ALL, flag));
    EXPECT_EQ(flag, PERMISSION_DEFAULT_FLAG);

    ret = AccessTokenKit::RevokePermission(tokenFullControl, PERMISSION_ALL, PERMISSION_USER_FIXED);
    EXPECT_EQ(RET_SUCCESS, ret);

    ret = AccessTokenKit::ClearUserGrantedPermissionState(tokenFullRead);
    EXPECT_EQ(RET_SUCCESS, ret);
    ret = AccessTokenKit::VerifyAccessToken(tokenCommon, PERMISSION_ALL, false);
    EXPECT_EQ(ret, PermissionState::PERMISSION_GRANTED);
    ret = AccessTokenKit::VerifyAccessToken(tokenFullControl, PERMISSION_ALL, false);
    EXPECT_EQ(ret, PermissionState::PERMISSION_GRANTED);
    ret = AccessTokenKit::VerifyAccessToken(tokenFullRead, PERMISSION_ALL, false);
    EXPECT_EQ(ret, PermissionState::PERMISSION_GRANTED);

    EXPECT_EQ(RET_SUCCESS, TestCommon::DeleteTestHapToken(tokenCommon));
    EXPECT_EQ(RET_SUCCESS, TestCommon::DeleteTestHapToken(tokenFullControl));
    EXPECT_EQ(RET_SUCCESS, TestCommon::DeleteTestHapToken(tokenFullRead));
}

/**
 * @tc.name: PermissionShareClearUserGrantTest002
 * @tc.desc: .
 * @tc.type: FUNC
 * @tc.require:Issue Number
 */
HWTEST_F(SharePermissionTest, PermissionShareClearUserGrantTest002, TestSize.Level0)
{
    int ret;
    AccessTokenID tokenCommon = AllocHapTokenId(g_infoParmsCommon, g_policyParams);
    AccessTokenID tokenFullControl = AllocHapTokenId(g_infoParmsFullControl, g_policyParams);
    AccessTokenID tokenFullRead = AllocHapTokenId(g_infoParmsReadOnly, g_policyParams);

    // grant pre-authorization
    ret = TestCommon::GrantPermissionByTest(tokenFullControl, PERMISSION_FULL_CONTROL, PERMISSION_USER_FIXED);
    EXPECT_EQ(RET_SUCCESS, ret);
    uint32_t flag;
    EXPECT_EQ(RET_SUCCESS, TestCommon::GetPermissionFlagByTest(tokenCommon, PERMISSION_FULL_CONTROL, flag));
    EXPECT_EQ(flag, PERMISSION_USER_FIXED);
    EXPECT_EQ(RET_SUCCESS, TestCommon::GetPermissionFlagByTest(tokenFullControl, PERMISSION_FULL_CONTROL, flag));
    EXPECT_EQ(flag, PERMISSION_USER_FIXED);
    EXPECT_EQ(RET_SUCCESS, TestCommon::GetPermissionFlagByTest(tokenFullRead, PERMISSION_FULL_CONTROL, flag));
    EXPECT_EQ(flag, PERMISSION_DEFAULT_FLAG);

    ret = AccessTokenKit::RevokePermission(tokenFullControl, PERMISSION_FULL_CONTROL, PERMISSION_USER_FIXED);
    EXPECT_EQ(RET_SUCCESS, ret);
    EXPECT_EQ(RET_SUCCESS, TestCommon::GetPermissionFlagByTest(tokenCommon, PERMISSION_FULL_CONTROL, flag));
    EXPECT_EQ(flag, PERMISSION_USER_FIXED);
    EXPECT_EQ(RET_SUCCESS, TestCommon::GetPermissionFlagByTest(tokenFullControl, PERMISSION_FULL_CONTROL, flag));
    EXPECT_EQ(flag, PERMISSION_USER_FIXED);
    EXPECT_EQ(RET_SUCCESS, TestCommon::GetPermissionFlagByTest(tokenFullRead, PERMISSION_FULL_CONTROL, flag));
    EXPECT_EQ(flag, PERMISSION_DEFAULT_FLAG);

    ret = AccessTokenKit::ClearUserGrantedPermissionState(tokenCommon);
    EXPECT_EQ(RET_SUCCESS, ret);
    EXPECT_EQ(RET_SUCCESS, TestCommon::GetPermissionFlagByTest(tokenCommon, PERMISSION_FULL_CONTROL, flag));
    EXPECT_EQ(flag, PERMISSION_DEFAULT_FLAG);
    EXPECT_EQ(RET_SUCCESS, TestCommon::GetPermissionFlagByTest(tokenFullControl, PERMISSION_FULL_CONTROL, flag));
    EXPECT_EQ(flag, PERMISSION_DEFAULT_FLAG);
    EXPECT_EQ(RET_SUCCESS, TestCommon::GetPermissionFlagByTest(tokenFullRead, PERMISSION_FULL_CONTROL, flag));
    EXPECT_EQ(flag, PERMISSION_DEFAULT_FLAG);
    ret = AccessTokenKit::VerifyAccessToken(tokenCommon, PERMISSION_FULL_CONTROL, false);
    EXPECT_EQ(ret, PermissionState::PERMISSION_DENIED);
    ret = AccessTokenKit::VerifyAccessToken(tokenFullControl, PERMISSION_FULL_CONTROL, false);
    EXPECT_EQ(ret, PermissionState::PERMISSION_DENIED);
    ret = AccessTokenKit::VerifyAccessToken(tokenFullRead, PERMISSION_FULL_CONTROL, false);
    EXPECT_EQ(ret, PermissionState::PERMISSION_DENIED);

    EXPECT_EQ(RET_SUCCESS, TestCommon::DeleteTestHapToken(tokenCommon));
    EXPECT_EQ(RET_SUCCESS, TestCommon::DeleteTestHapToken(tokenFullControl));
    EXPECT_EQ(RET_SUCCESS, TestCommon::DeleteTestHapToken(tokenFullRead));
}

/**
 * @tc.name: SharePermissionTest003
 * @tc.desc: .
 * @tc.type: FUNC
 * @tc.require:Issue Number
 */
HWTEST_F(SharePermissionTest, PermissionShareTest03, TestSize.Level0)
{
    uint64_t tokenId = GetSelfTokenID();
    AccessTokenID tokenCommon = AllocHapTokenId(g_infoParmsCommon, g_policyParams);
    ASSERT_EQ(0, SetSelfTokenID(tokenCommon));

    int32_t ret = AccessTokenKit::VerifyAccessToken(tokenId, PERMISSION_NOT_DISPLAYED, false);
    EXPECT_EQ(ret, PermissionState::PERMISSION_DENIED);

    std::vector<PermissionListState> permsList;
    PermissionListState perm = {
        .permissionName = PERMISSION_NOT_DISPLAYED,
        .state = SETTING_OPER,
    };
    permsList.emplace_back(perm);
    PermissionGrantInfo info;
    AccessTokenKit::GetSelfPermissionsState(permsList, info);
    EXPECT_EQ(permsList[0].state, INVALID_OPER);

    EXPECT_EQ(RET_SUCCESS, TestCommon::DeleteTestHapToken(tokenCommon));
    ASSERT_EQ(0, SetSelfTokenID(tokenId));
}

static void SetPermList(std::vector<PermissionListState> &permsList)
{
    PermissionListState permAll = {
        .permissionName = PERMISSION_ALL,
        .state = SETTING_OPER,
    };
    PermissionListState permFullControl = {
        .permissionName = PERMISSION_FULL_CONTROL,
        .state = SETTING_OPER,
    };
    PermissionListState permNone = {
        .permissionName = PERMISSION_NONE,
        .state = SETTING_OPER,
    };
    permsList.emplace_back(permAll);
    permsList.emplace_back(permFullControl);
    permsList.emplace_back(permNone);
}

/**
 * @tc.name: SharePermissionTest004
 * @tc.desc: .
 * @tc.type: FUNC
 * @tc.require:Issue Number
 */
HWTEST_F(SharePermissionTest, PermissionShareTest004, TestSize.Level0)
{
    AccessTokenID tokenCommon = AllocHapTokenId(g_infoParmsCommon, g_policyParams);
    AccessTokenID tokenFullControl = AllocHapTokenId(g_infoParmsFullControl, g_policyParams);
    AccessTokenID tokenFullRead = AllocHapTokenId(g_infoParmsReadOnly, g_policyParams);

    std::vector<PermissionListState> permsList;
    SetPermList(permsList);

    uint64_t tokenId = GetSelfTokenID();
    PermissionGrantInfo info;

    ASSERT_EQ(0, SetSelfTokenID(tokenFullControl));
    AccessTokenKit::GetSelfPermissionsState(permsList, info);
    EXPECT_EQ(permsList[0].state, DYNAMIC_OPER);
    ASSERT_EQ(0, SetSelfTokenID(tokenFullRead));
    AccessTokenKit::GetSelfPermissionsState(permsList, info);
    EXPECT_EQ(permsList[0].state, DYNAMIC_OPER);

    ASSERT_EQ(0, SetSelfTokenID(tokenId));
    (void)AccessTokenKit::RevokePermission(tokenCommon, PERMISSION_ALL, PERMISSION_USER_FIXED);

    ASSERT_EQ(0, SetSelfTokenID(tokenFullControl));
    AccessTokenKit::GetSelfPermissionsState(permsList, info);
    EXPECT_EQ(permsList[0].state, SETTING_OPER);
    ASSERT_EQ(0, SetSelfTokenID(tokenFullRead));
    AccessTokenKit::GetSelfPermissionsState(permsList, info);
    EXPECT_EQ(permsList[0].state, SETTING_OPER);

    ASSERT_EQ(0, SetSelfTokenID(tokenId));
    (void)AccessTokenKit::RevokePermission(tokenCommon, PERMISSION_FULL_CONTROL, PERMISSION_USER_FIXED);

    ASSERT_EQ(0, SetSelfTokenID(tokenFullControl));
    AccessTokenKit::GetSelfPermissionsState(permsList, info);
    EXPECT_EQ(permsList[1].state, SETTING_OPER);
    ASSERT_EQ(0, SetSelfTokenID(tokenFullRead));
    AccessTokenKit::GetSelfPermissionsState(permsList, info);
    EXPECT_EQ(permsList[1].state, INVALID_OPER);

    ASSERT_EQ(0, SetSelfTokenID(tokenId));
    EXPECT_EQ(RET_SUCCESS, AccessTokenKit::RevokePermission(tokenCommon, PERMISSION_NONE, PERMISSION_USER_FIXED));

    ASSERT_EQ(0, SetSelfTokenID(tokenCommon));
    AccessTokenKit::GetSelfPermissionsState(permsList, info);
    EXPECT_EQ(permsList[2].state, SETTING_OPER);
    ASSERT_EQ(0, SetSelfTokenID(tokenFullControl));
    AccessTokenKit::GetSelfPermissionsState(permsList, info);
    EXPECT_EQ(permsList[2].state, INVALID_OPER);
    ASSERT_EQ(0, SetSelfTokenID(tokenFullRead));
    AccessTokenKit::GetSelfPermissionsState(permsList, info);
    EXPECT_EQ(permsList[2].state, INVALID_OPER);

    EXPECT_EQ(RET_SUCCESS, TestCommon::DeleteTestHapToken(tokenCommon));
    EXPECT_EQ(RET_SUCCESS, TestCommon::DeleteTestHapToken(tokenFullControl));
    EXPECT_EQ(RET_SUCCESS, TestCommon::DeleteTestHapToken(tokenFullRead));
    ASSERT_EQ(0, SetSelfTokenID(tokenId));
}

/**
 * @tc.name: SharePermissionTest005
 * @tc.desc: .
 * @tc.type: FUNC
 * @tc.require:Issue Number
 */
HWTEST_F(SharePermissionTest, PermissionShareTest005, TestSize.Level0)
{
    AccessTokenID tokenCommon = AllocHapTokenId(g_infoParmsCommon, g_policyParams);
    AccessTokenID tokenFullControl = AllocHapTokenId(g_infoParmsFullControl, g_policyParams);
    AccessTokenID tokenFullRead = AllocHapTokenId(g_infoParmsReadOnly, g_policyParams);

    std::vector<PermissionListState> permsList;
    PermissionListState permAll = {
        .permissionName = PERMISSION_ALL,
        .state = SETTING_OPER,
    };
    PermissionListState permFullControl = {
        .permissionName = PERMISSION_FULL_CONTROL,
        .state = SETTING_OPER,
    };
    permsList.emplace_back(permAll);
    permsList.emplace_back(permFullControl);

    uint64_t tokenId = GetSelfTokenID();

    ASSERT_EQ(0, SetSelfTokenID(tokenCommon));
    PermissionGrantInfo info;
    AccessTokenKit::GetSelfPermissionsState(permsList, info);
    EXPECT_EQ(permsList[1].state, DYNAMIC_OPER);
    ASSERT_EQ(0, SetSelfTokenID(tokenFullControl));
    AccessTokenKit::GetSelfPermissionsState(permsList, info);
    EXPECT_EQ(permsList[1].state, DYNAMIC_OPER);
    ASSERT_EQ(0, SetSelfTokenID(tokenFullRead));
    AccessTokenKit::GetSelfPermissionsState(permsList, info);
    EXPECT_EQ(permsList[1].state, INVALID_OPER);

    ASSERT_EQ(0, SetSelfTokenID(tokenId));
    AccessTokenKit::RevokePermission(tokenFullControl, PERMISSION_ALL, PERMISSION_USER_FIXED);

    ASSERT_EQ(0, SetSelfTokenID(tokenCommon));
    AccessTokenKit::GetSelfPermissionsState(permsList, info);
    EXPECT_EQ(permsList[0].state, SETTING_OPER);
    ASSERT_EQ(0, SetSelfTokenID(tokenFullControl));
    AccessTokenKit::GetSelfPermissionsState(permsList, info);
    EXPECT_EQ(permsList[0].state, SETTING_OPER);

    ASSERT_EQ(0, SetSelfTokenID(tokenId));
    AccessTokenKit::RevokePermission(tokenFullControl, PERMISSION_FULL_CONTROL, PERMISSION_USER_FIXED);

    ASSERT_EQ(0, SetSelfTokenID(tokenCommon));
    AccessTokenKit::GetSelfPermissionsState(permsList, info);
    EXPECT_EQ(permsList[1].state, SETTING_OPER);
    ASSERT_EQ(0, SetSelfTokenID(tokenFullControl));
    AccessTokenKit::GetSelfPermissionsState(permsList, info);
    EXPECT_EQ(permsList[1].state, SETTING_OPER);
    
    EXPECT_EQ(RET_SUCCESS, TestCommon::DeleteTestHapToken(tokenCommon));
    EXPECT_EQ(RET_SUCCESS, TestCommon::DeleteTestHapToken(tokenFullControl));
    EXPECT_EQ(RET_SUCCESS, TestCommon::DeleteTestHapToken(tokenFullRead));
    ASSERT_EQ(0, SetSelfTokenID(tokenId));
}

/**
 * @tc.name: SharePermissionTest006
 * @tc.desc: .
 * @tc.type: FUNC
 * @tc.require:Issue Number
 */
HWTEST_F(SharePermissionTest, PermissionShareTest006, TestSize.Level0)
{
    int ret;
    AccessTokenID tokenCommon = AllocHapTokenId(g_infoParmsCommon, g_policyParams);
    AccessTokenID tokenFullControl = AllocHapTokenId(g_infoParmsFullControl, g_policyParams);
    AccessTokenID tokenFullRead = AllocHapTokenId(g_infoParmsReadOnly, g_policyParams);

    // revoke common app
    ret = AccessTokenKit::RevokePermission(tokenCommon, PERMISSION_ALL, PERMISSION_USER_FIXED);
    EXPECT_EQ(RET_SUCCESS, ret);
    ret = AccessTokenKit::VerifyAccessToken(tokenCommon, PERMISSION_ALL, false);
    EXPECT_EQ(ret, PermissionState::PERMISSION_DENIED);
    ret = AccessTokenKit::VerifyAccessToken(tokenFullControl, PERMISSION_ALL, false);
    EXPECT_EQ(ret, PermissionState::PERMISSION_DENIED);
    ret = AccessTokenKit::VerifyAccessToken(tokenFullRead, PERMISSION_ALL, false);
    EXPECT_EQ(ret, PermissionState::PERMISSION_DENIED);

    uint32_t flag;
    // revoke common app
    ret = AccessTokenKit::RevokePermission(tokenCommon, PERMISSION_FULL_CONTROL, PERMISSION_USER_FIXED);
    EXPECT_EQ(RET_SUCCESS, ret);
    EXPECT_EQ(RET_SUCCESS, TestCommon::GetPermissionFlagByTest(tokenCommon, PERMISSION_FULL_CONTROL, flag));
    EXPECT_EQ(flag, PERMISSION_USER_FIXED);
    EXPECT_EQ(RET_SUCCESS, TestCommon::GetPermissionFlagByTest(tokenFullControl, PERMISSION_FULL_CONTROL, flag));
    EXPECT_EQ(flag, PERMISSION_USER_FIXED);
    EXPECT_EQ(RET_SUCCESS, TestCommon::GetPermissionFlagByTest(tokenFullRead, PERMISSION_FULL_CONTROL, flag));
    EXPECT_EQ(flag, PERMISSION_DEFAULT_FLAG);

    // revoke common app
    ret = TestCommon::GrantPermissionByTest(tokenCommon, PERMISSION_NONE, PERMISSION_USER_FIXED);
    EXPECT_EQ(RET_SUCCESS, ret);
    EXPECT_EQ(RET_SUCCESS, TestCommon::GetPermissionFlagByTest(tokenCommon, PERMISSION_NONE, flag));
    EXPECT_EQ(flag, PERMISSION_USER_FIXED);
    EXPECT_EQ(RET_SUCCESS, TestCommon::GetPermissionFlagByTest(tokenFullControl, PERMISSION_NONE, flag));
    EXPECT_EQ(flag, PERMISSION_DEFAULT_FLAG);
    EXPECT_EQ(RET_SUCCESS, TestCommon::GetPermissionFlagByTest(tokenFullRead, PERMISSION_NONE, flag));
    EXPECT_EQ(flag, PERMISSION_DEFAULT_FLAG);

    EXPECT_EQ(RET_SUCCESS, TestCommon::DeleteTestHapToken(tokenCommon));
    EXPECT_EQ(RET_SUCCESS, TestCommon::DeleteTestHapToken(tokenFullControl));
    EXPECT_EQ(RET_SUCCESS, TestCommon::DeleteTestHapToken(tokenFullRead));
}

/**
 * @tc.name: SharePermissionTest007
 * @tc.desc: .
 * @tc.type: FUNC
 * @tc.require:Issue Number
 */
HWTEST_F(SharePermissionTest, PermissionShareTest007, TestSize.Level0)
{
    int ret;
    uint32_t flag;
    AccessTokenID tokenCommon = AllocHapTokenId(g_infoParmsCommon, g_policyParams);
    AccessTokenID tokenFullControl = AllocHapTokenId(g_infoParmsFullControl, g_policyParams);
    AccessTokenID tokenFullRead = AllocHapTokenId(g_infoParmsReadOnly, g_policyParams);

    // revoke full control app
    ret = AccessTokenKit::RevokePermission(tokenFullControl, PERMISSION_ALL, PERMISSION_USER_SET);
    EXPECT_EQ(RET_SUCCESS, ret);
    EXPECT_EQ(RET_SUCCESS, TestCommon::GetPermissionFlagByTest(tokenCommon, PERMISSION_ALL, flag));
    EXPECT_EQ(flag, PERMISSION_USER_SET);
    EXPECT_EQ(RET_SUCCESS, TestCommon::GetPermissionFlagByTest(tokenFullControl, PERMISSION_ALL, flag));
    EXPECT_EQ(flag, PERMISSION_USER_SET);
    EXPECT_EQ(RET_SUCCESS, TestCommon::GetPermissionFlagByTest(tokenFullRead, PERMISSION_ALL, flag));
    EXPECT_EQ(flag, PERMISSION_USER_SET);

    // revoke full control app
    ret = TestCommon::RevokePermissionByTest(tokenFullControl, PERMISSION_FULL_CONTROL, PERMISSION_USER_FIXED);
    EXPECT_EQ(RET_SUCCESS, ret);
    EXPECT_EQ(RET_SUCCESS, TestCommon::GetPermissionFlagByTest(tokenCommon, PERMISSION_FULL_CONTROL, flag));
    EXPECT_EQ(flag, PERMISSION_USER_FIXED);
    EXPECT_EQ(RET_SUCCESS, TestCommon::GetPermissionFlagByTest(tokenFullControl, PERMISSION_FULL_CONTROL, flag));
    EXPECT_EQ(flag, PERMISSION_USER_FIXED);
    EXPECT_EQ(RET_SUCCESS, TestCommon::GetPermissionFlagByTest(tokenFullRead, PERMISSION_FULL_CONTROL, flag));
    EXPECT_EQ(flag, PERMISSION_DEFAULT_FLAG);

    EXPECT_EQ(RET_SUCCESS, TestCommon::DeleteTestHapToken(tokenCommon));
    EXPECT_EQ(RET_SUCCESS, TestCommon::DeleteTestHapToken(tokenFullControl));
    EXPECT_EQ(RET_SUCCESS, TestCommon::DeleteTestHapToken(tokenFullRead));
}