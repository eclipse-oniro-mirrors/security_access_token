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

#include "accesstoken_short_time_permission_test.h"
#include "accesstoken_kit.h"
#include "access_token_error.h"
#include "nativetoken_kit.h"
#include "token_setproc.h"

namespace OHOS {
namespace Security {
namespace AccessToken {
namespace {
static const int32_t INDEX_ZERO = 0;
static std::string SHORT_TEMP_PERMISSION = "ohos.permission.SHORT_TERM_WRITE_IMAGEVIDEO"; // todo
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
    .bundleName = "AccessTokenShortTimePermTest",
    .instIndex = 0,
    .appIDDesc = "test.bundle",
    .isSystemApp = true
};
}

static uint64_t GetNativeTokenTest(const char *processName, const char **perms, int32_t permNum)
{
    uint64_t tokenId;
    NativeTokenInfoParams infoInstance = {
        .dcapsNum = 0,
        .permsNum = permNum,
        .aclsNum = 0,
        .dcaps = nullptr,
        .perms = perms,
        .acls = nullptr,
        .aplStr = "system_core",
        .processName = processName,
    };

    tokenId = GetAccessTokenId(&infoInstance);
    AccessTokenKit::ReloadNativeTokenInfo();
    return tokenId;
}

static void NativeTokenGet()
{
    uint64_t tokenID;
    const char **perms = new const char *[1]; // 1: array size
    // todo
    perms[INDEX_ZERO] = "ohos.permission.DISTRIBUTED_DATASYNC";

    tokenID = GetNativeTokenTest("AccessTokenShortTimePermTest", perms, 1); // 1: array size
    EXPECT_EQ(0, SetSelfTokenID(tokenID));
    delete[] perms;
}

using namespace testing::ext;

void AccessTokenShortTimePermTest::SetUpTestCase()
{
    NativeTokenGet();
    GTEST_LOG_(INFO) << "tokenID is " << GetSelfTokenID();
    GTEST_LOG_(INFO) << "uid is " << getuid();
}

void AccessTokenShortTimePermTest::TearDownTestCase()
{
}

void AccessTokenShortTimePermTest::SetUp()
{
    AccessTokenID tokenID = AccessTokenKit::GetHapTokenID(g_infoParms.userID,
                                                          g_infoParms.bundleName,
                                                          g_infoParms.instIndex);
    AccessTokenKit::DeleteToken(tokenID);

    AccessTokenKit::AllocHapToken(g_infoParms, g_policyPrams);
}

void AccessTokenShortTimePermTest::TearDown()
{
    AccessTokenID tokenID = AccessTokenKit::GetHapTokenID(g_infoParms.userID,
                                                          g_infoParms.bundleName,
                                                          g_infoParms.instIndex);
    AccessTokenKit::DeleteToken(tokenID);
}

/**
 * @tc.name: GrantPermissionForSpecifiedTime001
 * @tc.desc: GrantPermissionForSpecifiedTime without invalid parameter.
 * @tc.type: FUNC
 * @tc.require:Issue Number
 */
HWTEST_F(AccessTokenShortTimePermTest, GrantPermissionForSpecifiedTime001, TestSize.Level1)
{
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
 * @tc.name: GrantPermissionForSpecifiedTime003
 * @tc.desc: permission is not request.
 * @tc.type: FUNC
 * @tc.require:Issue Number
 */
HWTEST_F(AccessTokenShortTimePermTest, GrantPermissionForSpecifiedTime003, TestSize.Level1)
{
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
 * @tc.name: GrantPermissionForSpecifiedTime002
 * @tc.desc: test unsupport permission.
 * @tc.type: FUNC
 * @tc.require:Issue Number
 */
HWTEST_F(AccessTokenShortTimePermTest, GrantPermissionForSpecifiedTime002, TestSize.Level1)
{
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
 * @tc.name: GrantPermissionForSpecifiedTime004
 * @tc.desc: 1. The permission is granted when onceTime is not reached;
 *           2. The permission is revoked after onceTime is reached.
 * @tc.type: FUNC
 * @tc.require:Issue Number
 */
HWTEST_F(AccessTokenShortTimePermTest, GrantPermissionForSpecifiedTime004, TestSize.Level1)
{
    AccessTokenID tokenID = AccessTokenKit::GetHapTokenID(g_infoParms.userID,
                                                          g_infoParms.bundleName,
                                                          g_infoParms.instIndex);
    ASSERT_NE(INVALID_TOKENID, tokenID);
    uint32_t onceTime = 2;

    ASSERT_EQ(RET_SUCCESS,
        AccessTokenKit::GrantPermissionForSpecifiedTime(tokenID, SHORT_TEMP_PERMISSION, onceTime));

    ASSERT_EQ(PermissionState::PERMISSION_GRANTED, AccessTokenKit::VerifyAccessToken(tokenID, SHORT_TEMP_PERMISSION));

    sleep(onceTime + 1);

    ASSERT_EQ(PermissionState::PERMISSION_DENIED,
        AccessTokenKit::VerifyAccessToken(tokenID, SHORT_TEMP_PERMISSION, true));
}

/**
 * @tc.name: GrantPermissionForSpecifiedTime005
 * @tc.desc: 1. The permission is granted when onceTime is not reached;
 *           2. onceTime is update when GrantPermissionForSpecifiedTime is called twice.
 * @tc.type: FUNC
 * @tc.require:Issue Number
 */
HWTEST_F(AccessTokenShortTimePermTest, GrantPermissionForSpecifiedTime005, TestSize.Level1)
{
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