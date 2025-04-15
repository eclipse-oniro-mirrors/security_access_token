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

#include "clone_app_permission_test.h"
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
static const std::string PERMISSION_FULL_CONTROL = "ohos.permission.WRITE_MEDIA";
static const std::string PERMISSION_NOT_DISPLAYED = "ohos.permission.ANSWER_CALL";
static const std::string TEST_PERMISSION_GRANT = "ohos.permission.GRANT_SENSITIVE_PERMISSIONS";
static const std::string TEST_PERMISSION_REVOKE = "ohos.permission.REVOKE_SENSITIVE_PERMISSIONS";
static uint64_t g_selfTokenId = 0;

HapInfoParams g_infoParmsCommon = {
    .userID = 1,
    .bundleName = "CloneAppPermissionTest",
    .instIndex = 0,
    .dlpType = DLP_COMMON,
    .appIDDesc = "CloneAppPermissionTest"
};

HapInfoParams g_infoParmsCommonClone1 = {
    .userID = 1,
    .bundleName = "CloneAppPermissionTest",
    .instIndex = 5, // clone app index is 5
    .dlpType = DLP_COMMON,
    .appIDDesc = "CloneAppPermissionTest"
};

HapInfoParams g_infoParmsCommonClone2 = {
    .userID = 1,
    .bundleName = "CloneAppPermissionTest",
    .instIndex = 6, // clone app index is 6
    .dlpType = DLP_COMMON,
    .appIDDesc = "CloneAppPermissionTest"
};

HapInfoParams g_infoParmsFullControl = {
    .userID = 1,
    .bundleName = "CloneAppPermissionTest",
    .instIndex = 1,
    .dlpType = DLP_FULL_CONTROL,
    .appIDDesc = "CloneAppPermissionTest"
};

HapInfoParams g_infoParmsReadOnly = {
    .userID = 1,
    .bundleName = "CloneAppPermissionTest",
    .instIndex = 2,
    .dlpType = DLP_READ,
    .appIDDesc = "CloneAppPermissionTest"
};

PermissionStateFull g_stateFullControl = {
    .permissionName = "ohos.permission.WRITE_MEDIA",
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

HapPolicyParams g_policyParams = {
    .apl = APL_NORMAL,
    .domain = "test.domain",
    .permStateList = {g_stateFullControl, g_stateAll}
};

}

void CloneAppPermissionTest::TearDownTestCase()
{
    EXPECT_EQ(0, SetSelfTokenID(g_selfTokenId));
    TestCommon::ResetTestEvironment();

    AccessTokenIDEx tokenIdEx = TestCommon::GetHapTokenIdFromBundle(1, "PermissionEnvironment", 0);
    AccessTokenID tokenId = tokenIdEx.tokenIdExStruct.tokenID;
    if (tokenId != INVALID_TOKENID) {
        EXPECT_EQ(RET_SUCCESS, TestCommon::DeleteTestHapToken(tokenId));
    }
}

void CloneAppPermissionTest::SetUp()
{
    LOGI(ATM_DOMAIN, ATM_TAG, "SetUp ok.");
}

void CloneAppPermissionTest::TearDown()
{
}

void CloneAppPermissionTest::SetUpTestCase()
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

static AccessTokenID AllocHapTokenId(HapInfoParams info, HapPolicyParams policy)
{
    AccessTokenIDEx tokenIdEx = {0};
    EXPECT_EQ(RET_SUCCESS, TestCommon::AllocTestHapToken(info, policy, tokenIdEx));
    AccessTokenID tokenId = tokenIdEx.tokenIdExStruct.tokenID;
    EXPECT_NE(INVALID_TOKENID, tokenId);
    int ret = AccessTokenKit::VerifyAccessToken(tokenId, PERMISSION_FULL_CONTROL, false);
    EXPECT_EQ(ret, PermissionState::PERMISSION_DENIED);
    ret = AccessTokenKit::VerifyAccessToken(tokenId, PERMISSION_ALL, false);
    EXPECT_EQ(ret, PermissionState::PERMISSION_DENIED);
    uint32_t flag;
    ret = AccessTokenKit::GetPermissionFlag(tokenId, PERMISSION_FULL_CONTROL, flag);
    EXPECT_EQ(flag, PERMISSION_DEFAULT_FLAG);
    EXPECT_EQ(ret, RET_SUCCESS);
    ret = AccessTokenKit::GetPermissionFlag(tokenId, PERMISSION_ALL, flag);
    EXPECT_EQ(flag, PERMISSION_DEFAULT_FLAG);
    EXPECT_EQ(ret, RET_SUCCESS);
    return tokenId;
}

/**
 * @tc.name: OriginApp01
 * @tc.desc: main app grant permission.
 * @tc.type: FUNC
 * @tc.require:Issue Number
 */
HWTEST_F(CloneAppPermissionTest, OriginApp01, TestSize.Level1)
{
    int ret;
    auto policyParams = g_policyParams;
    AccessTokenID tokenCommon = AllocHapTokenId(g_infoParmsCommon, policyParams);
    AccessTokenID tokenFullControl = AllocHapTokenId(g_infoParmsFullControl, policyParams);
    AccessTokenID tokenRead = AllocHapTokenId(g_infoParmsReadOnly, policyParams);
    AccessTokenID tokenClone1 = AllocHapTokenId(g_infoParmsCommonClone1, policyParams);
    AccessTokenID tokenClone2 = AllocHapTokenId(g_infoParmsCommonClone2, policyParams);

    // grant common app
    ret = AccessTokenKit::GrantPermission(tokenCommon, PERMISSION_ALL, PERMISSION_USER_FIXED);
    EXPECT_EQ(RET_SUCCESS, ret);
    ret = AccessTokenKit::VerifyAccessToken(tokenCommon, PERMISSION_ALL);
    EXPECT_EQ(ret, PermissionState::PERMISSION_GRANTED);
    ret = AccessTokenKit::VerifyAccessToken(tokenFullControl, PERMISSION_ALL);
    EXPECT_EQ(ret, PermissionState::PERMISSION_GRANTED);
    ret = AccessTokenKit::VerifyAccessToken(tokenRead, PERMISSION_ALL);
    EXPECT_EQ(ret, PermissionState::PERMISSION_GRANTED);
    ret = AccessTokenKit::VerifyAccessToken(tokenClone1, PERMISSION_ALL);
    EXPECT_EQ(ret, PermissionState::PERMISSION_DENIED);
    ret = AccessTokenKit::VerifyAccessToken(tokenClone2, PERMISSION_ALL);
    EXPECT_EQ(ret, PermissionState::PERMISSION_DENIED);

    ret = TestCommon::DeleteTestHapToken(tokenCommon);
    EXPECT_EQ(RET_SUCCESS, ret);
    ret = TestCommon::DeleteTestHapToken(tokenFullControl);
    EXPECT_EQ(RET_SUCCESS, ret);
    ret = TestCommon::DeleteTestHapToken(tokenRead);
    EXPECT_EQ(RET_SUCCESS, ret);
    ret = TestCommon::DeleteTestHapToken(tokenClone1);
    EXPECT_EQ(RET_SUCCESS, ret);
    ret = TestCommon::DeleteTestHapToken(tokenClone2);
    EXPECT_EQ(RET_SUCCESS, ret);
}

/**
 * @tc.name: OriginApp02
 * @tc.desc: main app revoke permission.
 * @tc.type: FUNC
 * @tc.require:Issue Number
 */
HWTEST_F(CloneAppPermissionTest, OriginApp02, TestSize.Level1)
{
    int ret;
    auto policyParams = g_policyParams;
    AccessTokenID tokenCommon = AllocHapTokenId(g_infoParmsCommon, policyParams);
    AccessTokenID tokenFullControl = AllocHapTokenId(g_infoParmsFullControl, policyParams);
    AccessTokenID tokenRead = AllocHapTokenId(g_infoParmsReadOnly, policyParams);
    AccessTokenID tokenClone1 = AllocHapTokenId(g_infoParmsCommonClone1, policyParams);
    AccessTokenID tokenClone2 = AllocHapTokenId(g_infoParmsCommonClone2, policyParams);

    // grant common app
    ret = AccessTokenKit::RevokePermission(tokenCommon, PERMISSION_ALL, PERMISSION_USER_FIXED);
    EXPECT_EQ(RET_SUCCESS, ret);
    ret = AccessTokenKit::VerifyAccessToken(tokenCommon, PERMISSION_ALL);
    EXPECT_EQ(ret, PermissionState::PERMISSION_DENIED);
    ret = AccessTokenKit::VerifyAccessToken(tokenFullControl, PERMISSION_ALL);
    EXPECT_EQ(ret, PermissionState::PERMISSION_DENIED);
    ret = AccessTokenKit::VerifyAccessToken(tokenRead, PERMISSION_ALL);
    EXPECT_EQ(ret, PermissionState::PERMISSION_DENIED);
    ret = AccessTokenKit::VerifyAccessToken(tokenClone1, PERMISSION_ALL);
    EXPECT_EQ(ret, PermissionState::PERMISSION_DENIED);
    ret = AccessTokenKit::VerifyAccessToken(tokenClone2, PERMISSION_ALL);
    EXPECT_EQ(ret, PermissionState::PERMISSION_DENIED);
    uint32_t flag;
    ret = AccessTokenKit::GetPermissionFlag(tokenCommon, PERMISSION_ALL, flag);
    EXPECT_EQ(flag, PERMISSION_USER_FIXED);
    EXPECT_EQ(ret, RET_SUCCESS);

    ret = AccessTokenKit::GetPermissionFlag(tokenFullControl, PERMISSION_ALL, flag);
    EXPECT_EQ(flag, PERMISSION_USER_FIXED);
    EXPECT_EQ(ret, RET_SUCCESS);

    ret = AccessTokenKit::GetPermissionFlag(tokenRead, PERMISSION_ALL, flag);
    EXPECT_EQ(flag, PERMISSION_USER_FIXED);
    EXPECT_EQ(ret, RET_SUCCESS);

    ret = AccessTokenKit::GetPermissionFlag(tokenClone1, PERMISSION_ALL, flag);
    EXPECT_EQ(flag, 0);
    EXPECT_EQ(ret, RET_SUCCESS);

    ret = AccessTokenKit::GetPermissionFlag(tokenClone2, PERMISSION_ALL, flag);
    EXPECT_EQ(flag, 0);
    EXPECT_EQ(ret, RET_SUCCESS);

    ret = TestCommon::DeleteTestHapToken(tokenCommon);
    EXPECT_EQ(RET_SUCCESS, ret);
    ret = TestCommon::DeleteTestHapToken(tokenFullControl);
    EXPECT_EQ(RET_SUCCESS, ret);
    ret = TestCommon::DeleteTestHapToken(tokenRead);
    EXPECT_EQ(RET_SUCCESS, ret);
    ret = TestCommon::DeleteTestHapToken(tokenClone1);
    EXPECT_EQ(RET_SUCCESS, ret);
    ret = TestCommon::DeleteTestHapToken(tokenClone2);
    EXPECT_EQ(RET_SUCCESS, ret);
}

/**
 * @tc.name: OriginApp03
 * @tc.desc: main app clear permission.
 * @tc.type: FUNC
 * @tc.require:Issue Number
 */
HWTEST_F(CloneAppPermissionTest, OriginApp03, TestSize.Level1)
{
    int ret;
    auto policyParams = g_policyParams;
    AccessTokenID tokenCommon = AllocHapTokenId(g_infoParmsCommon, policyParams);
    AccessTokenID tokenFullControl = AllocHapTokenId(g_infoParmsFullControl, policyParams);
    AccessTokenID tokenRead = AllocHapTokenId(g_infoParmsReadOnly, policyParams);
    AccessTokenID tokenClone1 = AllocHapTokenId(g_infoParmsCommonClone1, policyParams);
    AccessTokenID tokenClone2 = AllocHapTokenId(g_infoParmsCommonClone2, policyParams);

    AccessTokenKit::GrantPermission(tokenCommon, PERMISSION_ALL, PERMISSION_USER_FIXED);
    AccessTokenKit::GrantPermission(tokenClone1, PERMISSION_ALL, PERMISSION_USER_FIXED);
    AccessTokenKit::GrantPermission(tokenClone2, PERMISSION_ALL, PERMISSION_USER_FIXED);

    ret = AccessTokenKit::VerifyAccessToken(tokenFullControl, PERMISSION_ALL);
    EXPECT_EQ(ret, PermissionState::PERMISSION_GRANTED);
    ret = AccessTokenKit::VerifyAccessToken(tokenRead, PERMISSION_ALL);
    EXPECT_EQ(ret, PermissionState::PERMISSION_GRANTED);
    ret = AccessTokenKit::VerifyAccessToken(tokenClone1, PERMISSION_ALL);
    EXPECT_EQ(ret, PermissionState::PERMISSION_GRANTED);
    ret = AccessTokenKit::VerifyAccessToken(tokenClone2, PERMISSION_ALL);
    EXPECT_EQ(ret, PermissionState::PERMISSION_GRANTED);


    ret = AccessTokenKit::ClearUserGrantedPermissionState(tokenCommon);
    EXPECT_EQ(ret, RET_SUCCESS);

    ret = AccessTokenKit::VerifyAccessToken(tokenCommon, PERMISSION_ALL);
    EXPECT_EQ(ret, PermissionState::PERMISSION_DENIED);
    ret = AccessTokenKit::VerifyAccessToken(tokenFullControl, PERMISSION_ALL);
    EXPECT_EQ(ret, PermissionState::PERMISSION_DENIED);
    ret = AccessTokenKit::VerifyAccessToken(tokenRead, PERMISSION_ALL);
    EXPECT_EQ(ret, PermissionState::PERMISSION_DENIED);
    ret = AccessTokenKit::VerifyAccessToken(tokenClone1, PERMISSION_ALL);
    EXPECT_EQ(ret, PermissionState::PERMISSION_GRANTED);
    ret = AccessTokenKit::VerifyAccessToken(tokenClone2, PERMISSION_ALL);
    EXPECT_EQ(ret, PermissionState::PERMISSION_GRANTED);

    uint32_t flag;
    ret = AccessTokenKit::GetPermissionFlag(tokenFullControl, PERMISSION_ALL, flag);
    EXPECT_EQ(flag, 0);
    EXPECT_EQ(ret, RET_SUCCESS);

    ret = AccessTokenKit::GetPermissionFlag(tokenRead, PERMISSION_ALL, flag);
    EXPECT_EQ(flag, 0);
    EXPECT_EQ(ret, RET_SUCCESS);

    ret = AccessTokenKit::GetPermissionFlag(tokenClone1, PERMISSION_ALL, flag);
    EXPECT_EQ(flag, PERMISSION_USER_FIXED);
    EXPECT_EQ(ret, RET_SUCCESS);

    ret = AccessTokenKit::GetPermissionFlag(tokenClone2, PERMISSION_ALL, flag);
    EXPECT_EQ(flag, PERMISSION_USER_FIXED);
    EXPECT_EQ(ret, RET_SUCCESS);

    EXPECT_EQ(RET_SUCCESS, TestCommon::DeleteTestHapToken(tokenCommon));
    EXPECT_EQ(RET_SUCCESS, TestCommon::DeleteTestHapToken(tokenFullControl));
    EXPECT_EQ(RET_SUCCESS, TestCommon::DeleteTestHapToken(tokenRead));
    EXPECT_EQ(RET_SUCCESS, TestCommon::DeleteTestHapToken(tokenClone1));
    EXPECT_EQ(RET_SUCCESS, TestCommon::DeleteTestHapToken(tokenClone2));
}

/**
 * @tc.name: ReadDlp01
 * @tc.desc: read mode dlp app grant permission.
 * @tc.type: FUNC
 * @tc.require:Issue Number
 */
HWTEST_F(CloneAppPermissionTest, ReadDlp01, TestSize.Level1)
{
    int ret;
    auto policyParams = g_policyParams;
    AccessTokenID tokenCommon = AllocHapTokenId(g_infoParmsCommon, policyParams);
    AccessTokenID tokenFullControl = AllocHapTokenId(g_infoParmsFullControl, policyParams);
    AccessTokenID tokenRead = AllocHapTokenId(g_infoParmsReadOnly, policyParams);
    AccessTokenID tokenClone1 = AllocHapTokenId(g_infoParmsCommonClone1, policyParams);
    AccessTokenID tokenClone2 = AllocHapTokenId(g_infoParmsCommonClone2, policyParams);

    // grant common app
    ret = AccessTokenKit::GrantPermission(tokenRead, PERMISSION_ALL, PERMISSION_USER_FIXED);
    EXPECT_EQ(RET_SUCCESS, ret);
    ret = AccessTokenKit::VerifyAccessToken(tokenCommon, PERMISSION_ALL);
    EXPECT_EQ(ret, PermissionState::PERMISSION_GRANTED);
    ret = AccessTokenKit::VerifyAccessToken(tokenFullControl, PERMISSION_ALL);
    EXPECT_EQ(ret, PermissionState::PERMISSION_GRANTED);
    ret = AccessTokenKit::VerifyAccessToken(tokenRead, PERMISSION_ALL);
    EXPECT_EQ(ret, PermissionState::PERMISSION_GRANTED);
    ret = AccessTokenKit::VerifyAccessToken(tokenClone1, PERMISSION_ALL);
    EXPECT_EQ(ret, PermissionState::PERMISSION_DENIED);
    ret = AccessTokenKit::VerifyAccessToken(tokenClone2, PERMISSION_ALL);
    EXPECT_EQ(ret, PermissionState::PERMISSION_DENIED);

    ret = TestCommon::DeleteTestHapToken(tokenCommon);
    EXPECT_EQ(RET_SUCCESS, ret);
    ret = TestCommon::DeleteTestHapToken(tokenFullControl);
    EXPECT_EQ(RET_SUCCESS, ret);
    ret = TestCommon::DeleteTestHapToken(tokenRead);
    EXPECT_EQ(RET_SUCCESS, ret);
    ret = TestCommon::DeleteTestHapToken(tokenClone1);
    EXPECT_EQ(RET_SUCCESS, ret);
    ret = TestCommon::DeleteTestHapToken(tokenClone2);
    EXPECT_EQ(RET_SUCCESS, ret);
}

/**
 * @tc.name: ReadDlp02
 * @tc.desc: read mode dlp app revoke permission.
 * @tc.type: FUNC
 * @tc.require:Issue Number
 */
HWTEST_F(CloneAppPermissionTest, ReadDlp02, TestSize.Level1)
{
    int ret;
    auto policyParams = g_policyParams;
    AccessTokenID tokenCommon = AllocHapTokenId(g_infoParmsCommon, policyParams);
    AccessTokenID tokenFullControl = AllocHapTokenId(g_infoParmsFullControl, policyParams);
    AccessTokenID tokenRead = AllocHapTokenId(g_infoParmsReadOnly, policyParams);
    AccessTokenID tokenClone1 = AllocHapTokenId(g_infoParmsCommonClone1, policyParams);
    AccessTokenID tokenClone2 = AllocHapTokenId(g_infoParmsCommonClone2, policyParams);

    // grant common app
    ret = AccessTokenKit::RevokePermission(tokenRead, PERMISSION_ALL, PERMISSION_USER_FIXED);
    EXPECT_EQ(RET_SUCCESS, ret);
    ret = AccessTokenKit::VerifyAccessToken(tokenCommon, PERMISSION_ALL);
    EXPECT_EQ(ret, PermissionState::PERMISSION_DENIED);
    ret = AccessTokenKit::VerifyAccessToken(tokenFullControl, PERMISSION_ALL);
    EXPECT_EQ(ret, PermissionState::PERMISSION_DENIED);
    ret = AccessTokenKit::VerifyAccessToken(tokenRead, PERMISSION_ALL);
    EXPECT_EQ(ret, PermissionState::PERMISSION_DENIED);
    ret = AccessTokenKit::VerifyAccessToken(tokenClone1, PERMISSION_ALL);
    EXPECT_EQ(ret, PermissionState::PERMISSION_DENIED);
    ret = AccessTokenKit::VerifyAccessToken(tokenClone2, PERMISSION_ALL);
    EXPECT_EQ(ret, PermissionState::PERMISSION_DENIED);

    uint32_t flag;
    ret = AccessTokenKit::GetPermissionFlag(tokenCommon, PERMISSION_ALL, flag);
    EXPECT_EQ(flag, PERMISSION_USER_FIXED);
    EXPECT_EQ(ret, RET_SUCCESS);

    ret = AccessTokenKit::GetPermissionFlag(tokenFullControl, PERMISSION_ALL, flag);
    EXPECT_EQ(flag, PERMISSION_USER_FIXED);
    EXPECT_EQ(ret, RET_SUCCESS);

    ret = AccessTokenKit::GetPermissionFlag(tokenRead, PERMISSION_ALL, flag);
    EXPECT_EQ(flag, PERMISSION_USER_FIXED);
    EXPECT_EQ(ret, RET_SUCCESS);

    ret = AccessTokenKit::GetPermissionFlag(tokenClone1, PERMISSION_ALL, flag);
    EXPECT_EQ(flag, 0);
    EXPECT_EQ(ret, RET_SUCCESS);

    ret = AccessTokenKit::GetPermissionFlag(tokenClone2, PERMISSION_ALL, flag);
    EXPECT_EQ(flag, 0);
    EXPECT_EQ(ret, RET_SUCCESS);

    ret = TestCommon::DeleteTestHapToken(tokenCommon);
    EXPECT_EQ(RET_SUCCESS, ret);
    ret = TestCommon::DeleteTestHapToken(tokenFullControl);
    EXPECT_EQ(RET_SUCCESS, ret);
    ret = TestCommon::DeleteTestHapToken(tokenRead);
    EXPECT_EQ(RET_SUCCESS, ret);
    ret = TestCommon::DeleteTestHapToken(tokenClone1);
    EXPECT_EQ(RET_SUCCESS, ret);
    ret = TestCommon::DeleteTestHapToken(tokenClone2);
    EXPECT_EQ(RET_SUCCESS, ret);
}

/**
 * @tc.name: ReadDlp03
 * @tc.desc: read mode dlp app clear permission.
 * @tc.type: FUNC
 * @tc.require:Issue Number
 */
HWTEST_F(CloneAppPermissionTest, ReadDlp03, TestSize.Level1)
{
    int ret;
    auto policyParams = g_policyParams;
    AccessTokenID tokenCommon = AllocHapTokenId(g_infoParmsCommon, policyParams);
    AccessTokenID tokenFullControl = AllocHapTokenId(g_infoParmsFullControl, policyParams);
    AccessTokenID tokenRead = AllocHapTokenId(g_infoParmsReadOnly, policyParams);
    AccessTokenID tokenClone1 = AllocHapTokenId(g_infoParmsCommonClone1, policyParams);
    AccessTokenID tokenClone2 = AllocHapTokenId(g_infoParmsCommonClone2, policyParams);

    AccessTokenKit::GrantPermission(tokenRead, PERMISSION_ALL, PERMISSION_USER_FIXED);
    AccessTokenKit::GrantPermission(tokenClone1, PERMISSION_ALL, PERMISSION_USER_FIXED);
    AccessTokenKit::GrantPermission(tokenClone2, PERMISSION_ALL, PERMISSION_USER_FIXED);

    ret = AccessTokenKit::VerifyAccessToken(tokenFullControl, PERMISSION_ALL);
    EXPECT_EQ(ret, PermissionState::PERMISSION_GRANTED);
    ret = AccessTokenKit::VerifyAccessToken(tokenCommon, PERMISSION_ALL);
    EXPECT_EQ(ret, PermissionState::PERMISSION_GRANTED);
    ret = AccessTokenKit::VerifyAccessToken(tokenClone1, PERMISSION_ALL);
    EXPECT_EQ(ret, PermissionState::PERMISSION_GRANTED);
    ret = AccessTokenKit::VerifyAccessToken(tokenClone2, PERMISSION_ALL);
    EXPECT_EQ(ret, PermissionState::PERMISSION_GRANTED);


    ret = AccessTokenKit::ClearUserGrantedPermissionState(tokenRead);
    EXPECT_EQ(ret, RET_SUCCESS);
    ret = AccessTokenKit::VerifyAccessToken(tokenCommon, PERMISSION_ALL);
    EXPECT_EQ(ret, PermissionState::PERMISSION_DENIED);
    ret = AccessTokenKit::VerifyAccessToken(tokenFullControl, PERMISSION_ALL);
    EXPECT_EQ(ret, PermissionState::PERMISSION_DENIED);
    ret = AccessTokenKit::VerifyAccessToken(tokenRead, PERMISSION_ALL);
    EXPECT_EQ(ret, PermissionState::PERMISSION_DENIED);
    ret = AccessTokenKit::VerifyAccessToken(tokenClone1, PERMISSION_ALL);
    EXPECT_EQ(ret, PermissionState::PERMISSION_GRANTED);
    ret = AccessTokenKit::VerifyAccessToken(tokenClone2, PERMISSION_ALL);
    EXPECT_EQ(ret, PermissionState::PERMISSION_GRANTED);
    uint32_t flag;
    ret = AccessTokenKit::GetPermissionFlag(tokenFullControl, PERMISSION_ALL, flag);
    EXPECT_EQ(flag, 0);
    EXPECT_EQ(ret, RET_SUCCESS);

    ret = AccessTokenKit::GetPermissionFlag(tokenCommon, PERMISSION_ALL, flag);
    EXPECT_EQ(flag, 0);
    EXPECT_EQ(ret, RET_SUCCESS);

    ret = AccessTokenKit::GetPermissionFlag(tokenClone1, PERMISSION_ALL, flag);
    EXPECT_EQ(flag, PERMISSION_USER_FIXED);
    EXPECT_EQ(ret, RET_SUCCESS);

    ret = AccessTokenKit::GetPermissionFlag(tokenClone2, PERMISSION_ALL, flag);
    EXPECT_EQ(flag, PERMISSION_USER_FIXED);
    EXPECT_EQ(ret, RET_SUCCESS);

    EXPECT_EQ(RET_SUCCESS, TestCommon::DeleteTestHapToken(tokenCommon));
    EXPECT_EQ(RET_SUCCESS, TestCommon::DeleteTestHapToken(tokenFullControl));
    EXPECT_EQ(RET_SUCCESS, TestCommon::DeleteTestHapToken(tokenRead));
    EXPECT_EQ(RET_SUCCESS, TestCommon::DeleteTestHapToken(tokenClone1));
    EXPECT_EQ(RET_SUCCESS, TestCommon::DeleteTestHapToken(tokenClone2));
}


/**
 * @tc.name: CloneApp01
 * @tc.desc: clone app grant permission.
 * @tc.type: FUNC
 * @tc.require:Issue Number
 */
HWTEST_F(CloneAppPermissionTest, CloneApp01, TestSize.Level1)
{
    int ret;
    auto policyParams = g_policyParams;
    AccessTokenID tokenCommon = AllocHapTokenId(g_infoParmsCommon, policyParams);
    AccessTokenID tokenFullControl = AllocHapTokenId(g_infoParmsFullControl, policyParams);
    AccessTokenID tokenRead = AllocHapTokenId(g_infoParmsReadOnly, policyParams);
    AccessTokenID tokenClone1 = AllocHapTokenId(g_infoParmsCommonClone1, policyParams);
    AccessTokenID tokenClone2 = AllocHapTokenId(g_infoParmsCommonClone2, policyParams);

    // grant common app
    ret = AccessTokenKit::GrantPermission(tokenClone1, PERMISSION_ALL, PERMISSION_USER_FIXED);
    EXPECT_EQ(RET_SUCCESS, ret);
    ret = AccessTokenKit::VerifyAccessToken(tokenCommon, PERMISSION_ALL);
    EXPECT_EQ(ret, PermissionState::PERMISSION_DENIED);
    ret = AccessTokenKit::VerifyAccessToken(tokenFullControl, PERMISSION_ALL);
    EXPECT_EQ(ret, PermissionState::PERMISSION_DENIED);
    ret = AccessTokenKit::VerifyAccessToken(tokenRead, PERMISSION_ALL);
    EXPECT_EQ(ret, PermissionState::PERMISSION_DENIED);
    ret = AccessTokenKit::VerifyAccessToken(tokenClone1, PERMISSION_ALL);
    EXPECT_EQ(ret, PermissionState::PERMISSION_GRANTED);
    ret = AccessTokenKit::VerifyAccessToken(tokenClone2, PERMISSION_ALL);
    EXPECT_EQ(ret, PermissionState::PERMISSION_DENIED);

    ret = TestCommon::DeleteTestHapToken(tokenCommon);
    EXPECT_EQ(RET_SUCCESS, ret);
    ret = TestCommon::DeleteTestHapToken(tokenFullControl);
    EXPECT_EQ(RET_SUCCESS, ret);
    ret = TestCommon::DeleteTestHapToken(tokenRead);
    EXPECT_EQ(RET_SUCCESS, ret);
    ret = TestCommon::DeleteTestHapToken(tokenClone1);
    EXPECT_EQ(RET_SUCCESS, ret);
    ret = TestCommon::DeleteTestHapToken(tokenClone2);
    EXPECT_EQ(RET_SUCCESS, ret);
}

/**
 * @tc.name: CloneApp02
 * @tc.desc: clone app grant permission.
 * @tc.type: FUNC
 * @tc.require:Issue Number
 */
HWTEST_F(CloneAppPermissionTest, CloneApp02, TestSize.Level1)
{
    int ret;
    auto policyParams = g_policyParams;
    AccessTokenID tokenCommon = AllocHapTokenId(g_infoParmsCommon, policyParams);
    AccessTokenID tokenFullControl = AllocHapTokenId(g_infoParmsFullControl, policyParams);
    AccessTokenID tokenRead = AllocHapTokenId(g_infoParmsReadOnly, policyParams);
    AccessTokenID tokenClone1 = AllocHapTokenId(g_infoParmsCommonClone1, policyParams);
    AccessTokenID tokenClone2 = AllocHapTokenId(g_infoParmsCommonClone2, policyParams);

    // grant common app
    ret = AccessTokenKit::RevokePermission(tokenClone1, PERMISSION_ALL, PERMISSION_USER_FIXED);
    EXPECT_EQ(RET_SUCCESS, ret);
    uint32_t flag;
    ret = AccessTokenKit::GetPermissionFlag(tokenCommon, PERMISSION_ALL, flag);
    EXPECT_EQ(flag, 0);
    EXPECT_EQ(ret, RET_SUCCESS);

    ret = AccessTokenKit::GetPermissionFlag(tokenFullControl, PERMISSION_ALL, flag);
    EXPECT_EQ(flag, 0);
    EXPECT_EQ(ret, RET_SUCCESS);

    ret = AccessTokenKit::GetPermissionFlag(tokenRead, PERMISSION_ALL, flag);
    EXPECT_EQ(flag, 0);
    EXPECT_EQ(ret, RET_SUCCESS);

    ret = AccessTokenKit::GetPermissionFlag(tokenClone1, PERMISSION_ALL, flag);
    EXPECT_EQ(flag, PERMISSION_USER_FIXED);
    EXPECT_EQ(ret, RET_SUCCESS);

    ret = AccessTokenKit::GetPermissionFlag(tokenClone2, PERMISSION_ALL, flag);
    EXPECT_EQ(flag, 0);
    EXPECT_EQ(ret, RET_SUCCESS);

    ret = TestCommon::DeleteTestHapToken(tokenCommon);
    EXPECT_EQ(RET_SUCCESS, ret);
    ret = TestCommon::DeleteTestHapToken(tokenFullControl);
    EXPECT_EQ(RET_SUCCESS, ret);
    ret = TestCommon::DeleteTestHapToken(tokenRead);
    EXPECT_EQ(RET_SUCCESS, ret);
    ret = TestCommon::DeleteTestHapToken(tokenClone1);
    EXPECT_EQ(RET_SUCCESS, ret);
    ret = TestCommon::DeleteTestHapToken(tokenClone2);
    EXPECT_EQ(RET_SUCCESS, ret);
}

/**
 * @tc.name: CloneApp03
 * @tc.desc: clone app clear permission.
 * @tc.type: FUNC
 * @tc.require:Issue Number
 */
HWTEST_F(CloneAppPermissionTest, CloneApp03, TestSize.Level1)
{
    int ret;
    auto policyParams = g_policyParams;
    AccessTokenID tokenCommon = AllocHapTokenId(g_infoParmsCommon, policyParams);
    AccessTokenID tokenFullControl = AllocHapTokenId(g_infoParmsFullControl, policyParams);
    AccessTokenID tokenRead = AllocHapTokenId(g_infoParmsReadOnly, policyParams);
    AccessTokenID tokenClone1 = AllocHapTokenId(g_infoParmsCommonClone1, policyParams);
    AccessTokenID tokenClone2 = AllocHapTokenId(g_infoParmsCommonClone2, policyParams);

    AccessTokenKit::GrantPermission(tokenRead, PERMISSION_ALL, PERMISSION_USER_FIXED);
    AccessTokenKit::GrantPermission(tokenClone1, PERMISSION_ALL, PERMISSION_USER_FIXED);
    AccessTokenKit::GrantPermission(tokenClone2, PERMISSION_ALL, PERMISSION_USER_FIXED);

    ret = AccessTokenKit::VerifyAccessToken(tokenFullControl, PERMISSION_ALL);
    EXPECT_EQ(ret, PermissionState::PERMISSION_GRANTED);
    ret = AccessTokenKit::VerifyAccessToken(tokenCommon, PERMISSION_ALL);
    EXPECT_EQ(ret, PermissionState::PERMISSION_GRANTED);
    ret = AccessTokenKit::VerifyAccessToken(tokenClone1, PERMISSION_ALL);
    EXPECT_EQ(ret, PermissionState::PERMISSION_GRANTED);
    ret = AccessTokenKit::VerifyAccessToken(tokenClone2, PERMISSION_ALL);
    EXPECT_EQ(ret, PermissionState::PERMISSION_GRANTED);


    ret = AccessTokenKit::ClearUserGrantedPermissionState(tokenClone1);
    EXPECT_EQ(ret, RET_SUCCESS);
    ret = AccessTokenKit::VerifyAccessToken(tokenCommon, PERMISSION_ALL);
    EXPECT_EQ(ret, PermissionState::PERMISSION_GRANTED);
    ret = AccessTokenKit::VerifyAccessToken(tokenFullControl, PERMISSION_ALL);
    EXPECT_EQ(ret, PermissionState::PERMISSION_GRANTED);
    ret = AccessTokenKit::VerifyAccessToken(tokenRead, PERMISSION_ALL);
    EXPECT_EQ(ret, PermissionState::PERMISSION_GRANTED);
    ret = AccessTokenKit::VerifyAccessToken(tokenClone1, PERMISSION_ALL);
    EXPECT_EQ(ret, PermissionState::PERMISSION_DENIED);
    ret = AccessTokenKit::VerifyAccessToken(tokenClone2, PERMISSION_ALL);
    EXPECT_EQ(ret, PermissionState::PERMISSION_GRANTED);
    uint32_t flag;
    ret = AccessTokenKit::GetPermissionFlag(tokenCommon, PERMISSION_ALL, flag);
    EXPECT_EQ(flag, PERMISSION_USER_FIXED);
    EXPECT_EQ(ret, RET_SUCCESS);

    ret = AccessTokenKit::GetPermissionFlag(tokenFullControl, PERMISSION_ALL, flag);
    EXPECT_EQ(flag, PERMISSION_USER_FIXED);
    EXPECT_EQ(ret, RET_SUCCESS);

    ret = AccessTokenKit::GetPermissionFlag(tokenClone1, PERMISSION_ALL, flag);
    EXPECT_EQ(flag, 0);
    EXPECT_EQ(ret, RET_SUCCESS);

    ret = AccessTokenKit::GetPermissionFlag(tokenClone2, PERMISSION_ALL, flag);
    EXPECT_EQ(flag, PERMISSION_USER_FIXED);
    EXPECT_EQ(ret, RET_SUCCESS);

    EXPECT_EQ(RET_SUCCESS, TestCommon::DeleteTestHapToken(tokenCommon));
    EXPECT_EQ(RET_SUCCESS, TestCommon::DeleteTestHapToken(tokenFullControl));
    EXPECT_EQ(RET_SUCCESS, TestCommon::DeleteTestHapToken(tokenRead));
    EXPECT_EQ(RET_SUCCESS, TestCommon::DeleteTestHapToken(tokenClone1));
    EXPECT_EQ(RET_SUCCESS, TestCommon::DeleteTestHapToken(tokenClone2));
}


/**
 * @tc.name: CloneApp04
 * @tc.desc: The permissions of the clone application do not inherit the permissions of the main application
 * @tc.type: FUNC
 * @tc.require:Issue Number
 */
HWTEST_F(CloneAppPermissionTest, CloneApp04, TestSize.Level1)
{
    int ret;
    uint32_t flag;
    auto policyParams = g_policyParams;
    AccessTokenID tokenCommon = AllocHapTokenId(g_infoParmsCommon, policyParams);
    ret = AccessTokenKit::GrantPermission(tokenCommon, PERMISSION_ALL, PERMISSION_USER_FIXED);
    EXPECT_EQ(RET_SUCCESS, ret);
    ret = AccessTokenKit::VerifyAccessToken(tokenCommon, PERMISSION_ALL);
    EXPECT_EQ(ret, PermissionState::PERMISSION_GRANTED);
    ret = AccessTokenKit::GetPermissionFlag(tokenCommon, PERMISSION_ALL, flag);
    EXPECT_EQ(flag, PERMISSION_USER_FIXED);
    EXPECT_EQ(ret, RET_SUCCESS);

    AccessTokenID tokenClone1 = AllocHapTokenId(g_infoParmsCommonClone1, policyParams);
    ret = AccessTokenKit::VerifyAccessToken(tokenClone1, PERMISSION_ALL);
    EXPECT_EQ(ret, PermissionState::PERMISSION_DENIED);
    ret = AccessTokenKit::GetPermissionFlag(tokenClone1, PERMISSION_ALL, flag);
    EXPECT_EQ(flag, 0);
    EXPECT_EQ(ret, RET_SUCCESS);

    ret = AccessTokenKit::RevokePermission(tokenCommon, PERMISSION_ALL, PERMISSION_USER_FIXED);
    EXPECT_EQ(RET_SUCCESS, ret);
    ret = AccessTokenKit::VerifyAccessToken(tokenCommon, PERMISSION_ALL);
    EXPECT_EQ(ret, PermissionState::PERMISSION_DENIED);
    ret = AccessTokenKit::GetPermissionFlag(tokenCommon, PERMISSION_ALL, flag);
    EXPECT_EQ(flag, PERMISSION_USER_FIXED);
    EXPECT_EQ(ret, RET_SUCCESS);

    AccessTokenID tokenClone2 = AllocHapTokenId(g_infoParmsCommonClone2, policyParams);
    ret = AccessTokenKit::VerifyAccessToken(tokenClone2, PERMISSION_ALL);
    EXPECT_EQ(ret, PermissionState::PERMISSION_DENIED);
    ret = AccessTokenKit::GetPermissionFlag(tokenClone1, PERMISSION_ALL, flag);
    EXPECT_EQ(flag, 0);
    EXPECT_EQ(ret, RET_SUCCESS);

    ret = TestCommon::DeleteTestHapToken(tokenCommon);
    EXPECT_EQ(RET_SUCCESS, ret);
    ret = TestCommon::DeleteTestHapToken(tokenClone1);
    EXPECT_EQ(RET_SUCCESS, ret);
    ret = TestCommon::DeleteTestHapToken(tokenClone2);
    EXPECT_EQ(RET_SUCCESS, ret);
}

/**
 * @tc.name: CloneApp05
 * @tc.desc: create a clone app
 * @tc.type: FUNC
 * @tc.require:Issue Number
 */
HWTEST_F(CloneAppPermissionTest, CloneApp05, TestSize.Level1)
{
    int ret;
    auto policyParams = g_policyParams;
    int32_t cloneFlag;
    int32_t dlpFlag;
    AccessTokenIDInner *idInner = nullptr;
    AccessTokenID tokenCommon = AllocHapTokenId(g_infoParmsCommon, policyParams);
    AccessTokenID tokenFullControl = AllocHapTokenId(g_infoParmsFullControl, policyParams);
    AccessTokenID tokenRead = AllocHapTokenId(g_infoParmsReadOnly, policyParams);
    AccessTokenID tokenClone1 = AllocHapTokenId(g_infoParmsCommonClone1, policyParams);
    AccessTokenID tokenClone2 = AllocHapTokenId(g_infoParmsCommonClone2, policyParams);

    idInner = reinterpret_cast<AccessTokenIDInner *>(&tokenCommon);
    cloneFlag = static_cast<int32_t>(idInner->cloneFlag);
    EXPECT_EQ(cloneFlag, 0);
    dlpFlag = static_cast<int32_t>(idInner->dlpFlag);
    EXPECT_EQ(dlpFlag, 0);

    idInner = reinterpret_cast<AccessTokenIDInner *>(&tokenFullControl);
    cloneFlag = static_cast<int32_t>(idInner->cloneFlag);
    EXPECT_EQ(cloneFlag, 0);
    dlpFlag = static_cast<int32_t>(idInner->dlpFlag);
    EXPECT_EQ(dlpFlag, 1);

    idInner = reinterpret_cast<AccessTokenIDInner *>(&tokenRead);
    cloneFlag = static_cast<int32_t>(idInner->cloneFlag);
    EXPECT_EQ(cloneFlag, 0);
    dlpFlag = static_cast<int32_t>(idInner->dlpFlag);
    EXPECT_EQ(dlpFlag, 1);

    idInner = reinterpret_cast<AccessTokenIDInner *>(&tokenClone1);
    cloneFlag = static_cast<int32_t>(idInner->cloneFlag);
    EXPECT_EQ(cloneFlag, 1);
    dlpFlag = static_cast<int32_t>(idInner->dlpFlag);
    EXPECT_EQ(dlpFlag, 0);

    idInner = reinterpret_cast<AccessTokenIDInner *>(&tokenClone2);
    cloneFlag = static_cast<int32_t>(idInner->cloneFlag);
    EXPECT_EQ(cloneFlag, 1);
    dlpFlag = static_cast<int32_t>(idInner->dlpFlag);
    EXPECT_EQ(dlpFlag, 0);

    ret = TestCommon::DeleteTestHapToken(tokenCommon);
    EXPECT_EQ(RET_SUCCESS, ret);
    ret = TestCommon::DeleteTestHapToken(tokenFullControl);
    EXPECT_EQ(RET_SUCCESS, ret);
    ret = TestCommon::DeleteTestHapToken(tokenRead);
    EXPECT_EQ(RET_SUCCESS, ret);
    ret = TestCommon::DeleteTestHapToken(tokenClone1);
    EXPECT_EQ(RET_SUCCESS, ret);
    ret = TestCommon::DeleteTestHapToken(tokenClone2);
    EXPECT_EQ(RET_SUCCESS, ret);
}