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

#include "grant_permission_for_specified_time_test.h"
#include "accesstoken_kit.h"
#include "access_token_error.h"
#include "accesstoken_common_log.h"
#include "nativetoken_kit.h"
#include "token_setproc.h"
#include "test_common.h"

namespace OHOS {
namespace Security {
namespace AccessToken {
namespace {
static const int32_t INDEX_ZERO = 0;
static AccessTokenID g_selfTokenId = 0;
static int32_t g_selfUid;
static std::string SHORT_TEMP_PERMISSION = "ohos.permission.SHORT_TERM_WRITE_IMAGEVIDEO";
static PermissionStateFull g_permiState = {
    .permissionName = SHORT_TEMP_PERMISSION,
    .isGeneral = true,
    .resDeviceID = {"localC"},
    .grantStatus = {PermissionState::PERMISSION_GRANTED},
    .grantFlags = {1}
};

static HapPolicyParams g_policyPrams = {
    .apl = APL_NORMAL,
    .domain = "test.domain",
    .permStateList = {g_permiState}
};

static HapInfoParams g_infoParms = {
    .userID = 1,
    .bundleName = "GrantPermissionForSpecifiedTimeTest",
    .instIndex = 0,
    .appIDDesc = "test.bundle",
    .isSystemApp = true
};
}

static void NativeTokenGet()
{
    uint64_t tokenID;
    const char **perms = new const char *[1]; // 1: array size
    perms[INDEX_ZERO] = "ohos.permission.DISTRIBUTED_DATASYNC";

    tokenID = TestCommon::GetNativeToken("GrantPermissionForSpecifiedTimeTest", perms, 1); // 1: array size
    EXPECT_EQ(0, SetSelfTokenID(tokenID));
    delete[] perms;
}

using namespace testing::ext;

void GrantPermissionForSpecifiedTimeTest::SetUpTestCase()
{
    g_selfTokenId = GetSelfTokenID();
    g_selfUid = getuid();

    NativeTokenGet();
}

void GrantPermissionForSpecifiedTimeTest::TearDownTestCase()
{
    setuid(g_selfUid);
    EXPECT_EQ(0, SetSelfTokenID(g_selfTokenId));
}

void GrantPermissionForSpecifiedTimeTest::SetUp()
{
    setuid(0);
    AccessTokenID tokenID = AccessTokenKit::GetHapTokenID(g_infoParms.userID,
                                                          g_infoParms.bundleName,
                                                          g_infoParms.instIndex);
    AccessTokenKit::DeleteToken(tokenID);

    AccessTokenKit::AllocHapToken(g_infoParms, g_policyPrams);
}

void GrantPermissionForSpecifiedTimeTest::TearDown()
{
    AccessTokenID tokenID = AccessTokenKit::GetHapTokenID(g_infoParms.userID,
                                                          g_infoParms.bundleName,
                                                          g_infoParms.instIndex);
    AccessTokenKit::DeleteToken(tokenID);
}

/**
 * @tc.name: GrantPermissionForSpecifiedTimeAbnormalTest001
 * @tc.desc: GrantPermissionForSpecifiedTime without invalid parameter.
 * @tc.type: FUNC
 * @tc.require:Issue Number
 */
HWTEST_F(GrantPermissionForSpecifiedTimeTest, GrantPermissionForSpecifiedTimeAbnormalTest001, TestSize.Level1)
{
    LOGI(ATM_DOMAIN, ATM_TAG, "GrantPermissionForSpecifiedTimeAbnormalTest001");
    AccessTokenID tokenId = INVALID_TOKENID;
    uint32_t onceTime = 0;

    /* 0 is invalid token id */
    ASSERT_EQ(AccessTokenError::ERR_PARAM_INVALID,
        AccessTokenKit::GrantPermissionForSpecifiedTime(tokenId, "permission", onceTime));

    tokenId = 123;
    /* 0 is invalid permissionName length */
    const std::string invalidPerm1 = "";
    ASSERT_EQ(AccessTokenError::ERR_PARAM_INVALID,
        AccessTokenKit::GrantPermissionForSpecifiedTime(tokenId, invalidPerm1, onceTime));

    /* 256 is invalid permissionName length */
    const std::string invalidPerm2 (257, 'x');
    ASSERT_EQ(AccessTokenError::ERR_PARAM_INVALID,
        AccessTokenKit::GrantPermissionForSpecifiedTime(tokenId, invalidPerm2, onceTime));

    /* 0 is invalid time */
    uint32_t invalidOnceTime1 = 0;
    ASSERT_EQ(AccessTokenError::ERR_PARAM_INVALID,
        AccessTokenKit::GrantPermissionForSpecifiedTime(tokenId, SHORT_TEMP_PERMISSION, invalidOnceTime1));

    /* 301 is invalid time */
    uint32_t invalidOnceTime2 = 301;
    ASSERT_EQ(AccessTokenError::ERR_PARAM_INVALID,
        AccessTokenKit::GrantPermissionForSpecifiedTime(tokenId, SHORT_TEMP_PERMISSION, invalidOnceTime2));
}

/**
 * @tc.name: GrantPermissionForSpecifiedTimeAbnormalTest002
 * @tc.desc: permission is not request.
 * @tc.type: FUNC
 * @tc.require:Issue Number
 */
HWTEST_F(GrantPermissionForSpecifiedTimeTest, GrantPermissionForSpecifiedTimeAbnormalTest002, TestSize.Level1)
{
    LOGI(ATM_DOMAIN, ATM_TAG, "GrantPermissionForSpecifiedTimeAbnormalTest002");
    HapPolicyParams policyPrams = g_policyPrams;
    HapInfoParams infoParms = g_infoParms;
    policyPrams.permStateList.clear();

    AccessTokenKit::AllocHapToken(infoParms, policyPrams);
    AccessTokenID tokenID = AccessTokenKit::GetHapTokenID(infoParms.userID,
                                                          infoParms.bundleName,
                                                          infoParms.instIndex);
    ASSERT_NE(INVALID_TOKENID, tokenID);
    uint32_t onceTime = 10; // 10: 10s

    ASSERT_EQ(AccessTokenError::ERR_PARAM_INVALID,
        AccessTokenKit::GrantPermissionForSpecifiedTime(tokenID, SHORT_TEMP_PERMISSION, onceTime));
}

/**
 * @tc.name: GrantPermissionForSpecifiedTimeAbnormalTest003
 * @tc.desc: test unsupport permission.
 * @tc.type: FUNC
 * @tc.require:Issue Number
 */
HWTEST_F(GrantPermissionForSpecifiedTimeTest, GrantPermissionForSpecifiedTimeAbnormalTest003, TestSize.Level1)
{
    LOGI(ATM_DOMAIN, ATM_TAG, "GrantPermissionForSpecifiedTimeAbnormalTest003");
    AccessTokenID tokenID = AccessTokenKit::GetHapTokenID(g_infoParms.userID,
                                                          g_infoParms.bundleName,
                                                          g_infoParms.instIndex);
    ASSERT_NE(INVALID_TOKENID, tokenID);
    uint32_t onceTime = 10; // 10: 10s
    std::string permission = "ohos.permission.CAMERA";

    ASSERT_EQ(AccessTokenError::ERR_PARAM_INVALID,
        AccessTokenKit::GrantPermissionForSpecifiedTime(tokenID, permission, onceTime));
}

/**
 * @tc.name: GrantPermissionForSpecifiedTimeAbnormalTest004
 * @tc.desc: GrantPermissionForSpecifiedTime with no permission
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(GrantPermissionForSpecifiedTimeTest, GrantPermissionForSpecifiedTimeAbnormalTest004, TestSize.Level1)
{
    LOGI(ATM_DOMAIN, ATM_TAG, "GrantPermissionForSpecifiedTimeAbnormalTest004");
    setuid(1234);
    AccessTokenID tokenId = 123;
    std::string permission = "permission";
    uint32_t onceTime = 1;
    ASSERT_EQ(AccessTokenError::ERR_PERMISSION_DENIED,
        AccessTokenKit::GrantPermissionForSpecifiedTime(tokenId, permission, onceTime));
    setuid(g_selfUid);
}

/**
 * @tc.name: GrantPermissionForSpecifiedTimeSpecsTest001
 * @tc.desc: 1. The permission is granted when onceTime is not reached;
 *           2. The permission is revoked after onceTime is reached.
 * @tc.type: FUNC
 * @tc.require:Issue Number
 */
HWTEST_F(GrantPermissionForSpecifiedTimeTest, GrantPermissionForSpecifiedTimeSpecsTest001, TestSize.Level1)
{
    LOGI(ATM_DOMAIN, ATM_TAG, "GrantPermissionForSpecifiedTimeSpecsTest001");
    AccessTokenID tokenID = AccessTokenKit::GetHapTokenID(g_infoParms.userID,
                                                          g_infoParms.bundleName,
                                                          g_infoParms.instIndex);
    ASSERT_NE(INVALID_TOKENID, tokenID);
    uint32_t onceTime = 2;

    ASSERT_EQ(RET_SUCCESS,
        AccessTokenKit::GrantPermissionForSpecifiedTime(tokenID, SHORT_TEMP_PERMISSION, onceTime));

    ASSERT_EQ(PermissionState::PERMISSION_GRANTED, AccessTokenKit::VerifyAccessToken(tokenID, SHORT_TEMP_PERMISSION));

    sleep(onceTime);

    ASSERT_EQ(PermissionState::PERMISSION_DENIED,
        AccessTokenKit::VerifyAccessToken(tokenID, SHORT_TEMP_PERMISSION, true));
}

/**
 * @tc.name: GrantPermissionForSpecifiedTimeSpecsTest002
 * @tc.desc: 1. The permission is granted when onceTime is not reached;
 *           2. onceTime is update when GrantPermissionForSpecifiedTime is called twice.
 * @tc.type: FUNC
 * @tc.require:Issue Number
 */
HWTEST_F(GrantPermissionForSpecifiedTimeTest, GrantPermissionForSpecifiedTimeSpecsTest002, TestSize.Level1)
{
    LOGI(ATM_DOMAIN, ATM_TAG, "GrantPermissionForSpecifiedTimeSpecsTest002");
    AccessTokenID tokenID = AccessTokenKit::GetHapTokenID(g_infoParms.userID,
                                                          g_infoParms.bundleName,
                                                          g_infoParms.instIndex);
    ASSERT_NE(INVALID_TOKENID, tokenID);
    uint32_t onceTime = 3;

    ASSERT_EQ(RET_SUCCESS,
        AccessTokenKit::GrantPermissionForSpecifiedTime(tokenID, SHORT_TEMP_PERMISSION, onceTime));
    sleep(onceTime - 1);
    ASSERT_EQ(PermissionState::PERMISSION_GRANTED, AccessTokenKit::VerifyAccessToken(tokenID, SHORT_TEMP_PERMISSION));

    // update onceTime
    onceTime = 5;
    ASSERT_EQ(RET_SUCCESS,
        AccessTokenKit::GrantPermissionForSpecifiedTime(tokenID, SHORT_TEMP_PERMISSION, onceTime));

    // first onceTime is reached, permission is not revoked
    sleep(1);
    ASSERT_EQ(PermissionState::PERMISSION_GRANTED, AccessTokenKit::VerifyAccessToken(tokenID, SHORT_TEMP_PERMISSION));

    // second onceTime is reached, permission is revoked
    sleep(onceTime);
    ASSERT_EQ(PermissionState::PERMISSION_DENIED, AccessTokenKit::VerifyAccessToken(tokenID, SHORT_TEMP_PERMISSION));
}
} // namespace AccessToken
} // namespace Security
} // namespace OHOS