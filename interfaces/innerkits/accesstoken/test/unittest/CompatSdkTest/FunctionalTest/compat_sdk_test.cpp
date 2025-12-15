/*
 * Copyright (c) 2025 Huawei Device Co., Ltd.
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

#include <gtest/gtest.h>

#include "accesstoken_compat_kit.h"
#include "accesstoken_kit.h"
#include "access_token_error.h"
#include "iaccess_token_manager.h"
#include "compat_test_common.h"
#include "test_common.h"
#include "tokenid_kit.h"
#include "token_setproc.h"

using namespace testing::ext;

namespace OHOS {
namespace Security {
namespace AccessToken {
namespace {
// Cannot be modified
static constexpr uint32_t COMMAND_VERIFY_ACCESS_TOKEN = 1;
static constexpr uint32_t COMMAND_GET_NATIVE_TOKEN_ID = 54;
static constexpr uint32_t COMMAND_GET_HAP_TOKEN_INFO_IN_UNSIGNED_INT_OUT_HAPTOKENINFOCOMPATIDL = 200;
static constexpr uint32_t COMMAND_GET_PERMISSION_CODE = 201;

static uint64_t g_selfUid = 0;
const std::string TEST_NATIVE_PROCESS_NAME = "accesstoken_service";
const std::string TEST_SHELL_PROCESS_NAME = "hdcd";
const std::string TEST_HAP_PROCESS_NAME = "ohos.global.systemres";
static constexpr uint32_t TEST_HAP_TOKEN = 537919487; // 537919486: 001 00 0 000000 11111111111111111111
static uint64_t g_selfShellTokenId = 0;
static AccessTokenID g_nativeTokenId = 0;
static AccessTokenID g_hapTokenId = 0;
static AccessTokenID g_renderTokenId = 0;
static const std::string TEST_BUNDLE_NAME = "ohos";
static const int32_t TEST_USER_ID = 0;
static constexpr int32_t DEFAULT_API_VERSION = 8;
constexpr const int32_t VERIFY_THRESHOLD = 50;
}

class ATCompatSdkTest : public testing::Test {
public:
    static void SetUpTestCase();
    static void TearDownTestCase();
    void SetUp();
    void TearDown();
};

void ATCompatSdkTest::SetUpTestCase()
{
    g_selfShellTokenId = GetSelfTokenID();
    g_selfUid = getuid();

    g_nativeTokenId = GetNativeTokenId(TEST_NATIVE_PROCESS_NAME);
    g_hapTokenId = GetHapTokenId(TEST_HAP_PROCESS_NAME);
    g_renderTokenId = TokenIdKit::GetRenderTokenID(TEST_HAP_TOKEN);
    GTEST_LOG_(INFO) << "selfShellTokenId: " << g_selfShellTokenId;
    GTEST_LOG_(INFO) << "nativeTokenId: " << g_nativeTokenId;
    GTEST_LOG_(INFO) << "hapTokenId: " << g_hapTokenId;
    GTEST_LOG_(INFO) << "renderTokenId: " << g_renderTokenId;
}

void ATCompatSdkTest::TearDownTestCase()
{
    SetSelfTokenID(g_selfShellTokenId);
}

void ATCompatSdkTest::SetUp()
{
}

void ATCompatSdkTest::TearDown()
{
    SetSelfTokenID(g_selfShellTokenId);
    setuid(g_selfUid);
}

/**
 * @tc.name: CompatiableTest001
 * @tc.desc: Test ipc code and description
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(ATCompatSdkTest, CompatiableTest001, TestSize.Level0)
{
    EXPECT_EQ(COMMAND_VERIFY_ACCESS_TOKEN,
        static_cast<uint32_t>(IAccessTokenManagerIpcCode::COMMAND_VERIFY_ACCESS_TOKEN));
    EXPECT_EQ(COMMAND_GET_NATIVE_TOKEN_ID,
        static_cast<uint32_t>(IAccessTokenManagerIpcCode::COMMAND_GET_NATIVE_TOKEN_ID));
    EXPECT_EQ(COMMAND_GET_HAP_TOKEN_INFO_IN_UNSIGNED_INT_OUT_HAPTOKENINFOCOMPATIDL, static_cast<uint32_t>(
        IAccessTokenManagerIpcCode::COMMAND_GET_HAP_TOKEN_INFO_IN_UNSIGNED_INT_OUT_HAPTOKENINFOCOMPATIDL));
    EXPECT_EQ(COMMAND_GET_PERMISSION_CODE,
        static_cast<uint32_t>(IAccessTokenManagerIpcCode::COMMAND_GET_PERMISSION_CODE));
}

/**
 * @tc.name: GetTokenTypeFlagTest001
 * @tc.desc: GetTokenTypeFlag with invalid token id
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(ATCompatSdkTest, GetTokenTypeFlagTest001, TestSize.Level0)
{
    // token is is 0
    EXPECT_EQ(TOKEN_INVALID, AccessTokenCompatKit::GetTokenTypeFlag(INVALID_TOKENID));

    // hap token
    EXPECT_EQ(TOKEN_HAP, AccessTokenCompatKit::GetTokenTypeFlag(g_hapTokenId));

    // native token
    EXPECT_EQ(TOKEN_NATIVE, AccessTokenCompatKit::GetTokenTypeFlag(g_nativeTokenId));

    // shell token
    EXPECT_EQ(TOKEN_SHELL, AccessTokenCompatKit::GetTokenTypeFlag(g_selfShellTokenId));
}

/**
 * @tc.name: GetNativeTokenIdTest001
 * @tc.desc: GetNativeTokenId with invalid process name
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(ATCompatSdkTest, GetNativeTokenIdTest001, TestSize.Level0)
{
    // process name is empty
    EXPECT_EQ(INVALID_TOKENID, AccessTokenCompatKit::GetNativeTokenId(""));

    // process name is oversize
    const std::string invalidProcess (257, 'x'); // 257: lengh
    EXPECT_EQ(INVALID_TOKENID, AccessTokenCompatKit::GetNativeTokenId(invalidProcess));

    {
        uint64_t selfTokenId = GetSelfTokenID();
        SetSelfTokenID(g_nativeTokenId);

        // noexist process name
        EXPECT_EQ(INVALID_TOKENID, AccessTokenCompatKit::GetNativeTokenId("noexist_process"));

        // exist hap process name
        EXPECT_EQ(INVALID_TOKENID, AccessTokenCompatKit::GetNativeTokenId(TEST_HAP_PROCESS_NAME));

        SetSelfTokenID(selfTokenId);
    }
}

/**
 * @tc.name: GetNativeTokenIdTest002
 * @tc.desc: GetNativeTokenId with permission deny
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(ATCompatSdkTest, GetNativeTokenIdTest002, TestSize.Level0)
{
    uint64_t selfTokenId = GetSelfTokenID();
    int32_t selfUid = getuid();
    {
        // shell process: deny
        SetSelfTokenID(g_selfShellTokenId);
        setuid(123); // 123: uid
        EXPECT_EQ(INVALID_TOKENID, AccessTokenCompatKit::GetNativeTokenId(TEST_NATIVE_PROCESS_NAME));
        setuid(selfUid);
        SetSelfTokenID(selfTokenId);
    }
    {
        // hap: deny
        SetSelfTokenID(g_hapTokenId);
        setuid(123); // 123: uid
        EXPECT_EQ(INVALID_TOKENID, AccessTokenCompatKit::GetNativeTokenId(TEST_NATIVE_PROCESS_NAME));
        setuid(selfUid);
        SetSelfTokenID(selfTokenId);
    }
    // restore environment
    setuid(selfUid);
    SetSelfTokenID(selfTokenId);
}

/**
 * @tc.name: GetNativeTokenIdTest003
 * @tc.desc: GetNativeTokenId with valid native process name
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(ATCompatSdkTest, GetNativeTokenIdTest003, TestSize.Level0)
{
    uint64_t selfTokenId = GetSelfTokenID();
    SetSelfTokenID(g_nativeTokenId);
    AccessTokenID tokenID = AccessTokenCompatKit::GetNativeTokenId(TEST_NATIVE_PROCESS_NAME);
    GTEST_LOG_(INFO) << "tokenID :" << tokenID;
    EXPECT_NE(INVALID_TOKENID, tokenID);

    EXPECT_EQ(TOKEN_NATIVE, AccessTokenCompatKit::GetTokenTypeFlag(tokenID));

    SetSelfTokenID(selfTokenId);
}

/**
 * @tc.name: GetHapTokenInfoTest001
 * @tc.desc: GetHapTokenInfo with invalid token id
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(ATCompatSdkTest, GetHapTokenInfoTest001, TestSize.Level0)
{
    HapTokenInfoCompat hapInfo;

    // token id is 0
    EXPECT_EQ(ERR_PARAM_INVALID, AccessTokenCompatKit::GetHapTokenInfo(INVALID_TOKENID, hapInfo));

    // has permission: native process
    uint64_t selfTokenId = GetSelfTokenID();
    SetSelfTokenID(g_nativeTokenId);

    // token id is native process
    EXPECT_EQ(ERR_PARAM_INVALID, AccessTokenCompatKit::GetHapTokenInfo(g_nativeTokenId, hapInfo));

    // token id is shell process
    EXPECT_EQ(ERR_PARAM_INVALID, AccessTokenCompatKit::GetHapTokenInfo(g_selfShellTokenId, hapInfo));

    // token id is render process
    EXPECT_EQ(ERR_TOKENID_NOT_EXIST, AccessTokenCompatKit::GetHapTokenInfo(g_renderTokenId, hapInfo));

    SetSelfTokenID(selfTokenId);
}

/**
 * @tc.name: GetHapTokenInfoTest002
 * @tc.desc: GetHapTokenInfo with permission deny
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(ATCompatSdkTest, GetHapTokenInfoTest002, TestSize.Level0)
{
    uint64_t selfTokenId = GetSelfTokenID();
    HapTokenInfoCompat hapInfo;
    {
        // shell process: deny
        SetSelfTokenID(g_selfShellTokenId);
        EXPECT_EQ(ERR_PERMISSION_DENIED, AccessTokenCompatKit::GetHapTokenInfo(g_hapTokenId, hapInfo));
        SetSelfTokenID(selfTokenId);
    }
    {
        // hap: deny
        SetSelfTokenID(g_hapTokenId);
        EXPECT_EQ(ERR_PERMISSION_DENIED, AccessTokenCompatKit::GetHapTokenInfo(g_hapTokenId, hapInfo));
        SetSelfTokenID(selfTokenId);
    }
    // restore environment
    SetSelfTokenID(selfTokenId);
}

/**
 * @tc.name: GetHapTokenInfoTest003
 * @tc.desc: GetHapTokenInfo with valid hap token id
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(ATCompatSdkTest, GetHapTokenInfoTest003, TestSize.Level0)
{
    uint64_t selfTokenId = GetSelfTokenID();
    SetSelfTokenID(g_nativeTokenId);
    HapTokenInfoCompat hapInfo;

    // non exist hap token id
    AccessTokenID nonExistTokenId = 537919487;
    EXPECT_EQ(ERR_TOKENID_NOT_EXIST, AccessTokenCompatKit::GetHapTokenInfo(nonExistTokenId, hapInfo));

    // exist hap token id
    EXPECT_EQ(RET_SUCCESS, AccessTokenCompatKit::GetHapTokenInfo(g_hapTokenId, hapInfo));
    EXPECT_EQ(TEST_HAP_PROCESS_NAME, hapInfo.bundleName);

    // tokenId is render process
    EXPECT_EQ(ERR_TOKENID_NOT_EXIST, AccessTokenCompatKit::GetHapTokenInfo(g_renderTokenId, hapInfo));

    SetSelfTokenID(selfTokenId);
}

/**
 * @tc.name: VerifyAccessTokenTest001
 * @tc.desc: VerifyAccessToken with invalid token id and permission name
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(ATCompatSdkTest, VerifyAccessTokenTest001, TestSize.Level0)
{
    // token id is 0
    EXPECT_EQ(PERMISSION_DENIED, AccessTokenCompatKit::VerifyAccessToken(0, "ohos.permission.CAMERA"));

    // token is is render process
    EXPECT_EQ(PERMISSION_DENIED, AccessTokenCompatKit::VerifyAccessToken(g_renderTokenId, "ohos.permission.CAMERA"));

    // tokenId is not exist
    AccessTokenID tokenId = 123; // 123: tokenId
    EXPECT_EQ(PERMISSION_DENIED, AccessTokenCompatKit::VerifyAccessToken(tokenId, "ohos.permission.CAMERA"));

    // permision is empty
    EXPECT_EQ(PERMISSION_DENIED, AccessTokenCompatKit::VerifyAccessToken(g_nativeTokenId, ""));

    // permission is oversize
    const std::string invalidPerm (257, 'x'); // 257: lengh
    EXPECT_EQ(PERMISSION_DENIED, AccessTokenCompatKit::VerifyAccessToken(g_nativeTokenId, invalidPerm));

    // permission is non exist
    EXPECT_EQ(PERMISSION_DENIED, AccessTokenCompatKit::VerifyAccessToken(g_nativeTokenId, "test"));
}

/**
 * @tc.name: VerifyAccessTokenTest002
 * @tc.desc: VerifyAccessToken with valid token id and permission name
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(ATCompatSdkTest, VerifyAccessTokenTest002, TestSize.Level0)
{
    uint64_t selfTokenId = GetSelfTokenID();
    HapInfoParams infoParams = {
        .userID = 0,
        .bundleName = "VerifyAccessTokenTest002",
        .instIndex = 0,
        .appIDDesc = "VerifyAccessTokenTest002",
        .apiVersion = 8, // 8: API VERSION
    };

    HapPolicyParams policyParams = {
        .apl = APL_SYSTEM_CORE,
        .domain = "VerifyAccessTokenTest002",
    };
    PermissionStateFull sysPerm = {
        .permissionName = "ohos.permission.GRANT_SENSITIVE_PERMISSIONS",
    };
    PermissionStateFull userPerm = {
        .permissionName = "ohos.permission.CAMERA",
    };
    policyParams.permStateList.emplace_back(sysPerm);
    policyParams.permStateList.emplace_back(userPerm);

    AccessTokenID mockToken = GetNativeTokenId("foundation");
    SetSelfTokenID(mockToken);

    AccessTokenIDEx tokenIdEx = {0};
    EXPECT_EQ(RET_SUCCESS, AccessTokenKit::InitHapToken(infoParams, policyParams, tokenIdEx));
    EXPECT_NE(INVALID_TOKENID, tokenIdEx.tokenIdExStruct.tokenID);

    EXPECT_EQ(PERMISSION_GRANTED,
        AccessTokenCompatKit::VerifyAccessToken(tokenIdEx.tokenIdExStruct.tokenID, sysPerm.permissionName));
    EXPECT_EQ(PERMISSION_DENIED,
        AccessTokenCompatKit::VerifyAccessToken(tokenIdEx.tokenIdExStruct.tokenID, userPerm.permissionName));
    EXPECT_EQ(PERMISSION_DENIED,
        AccessTokenCompatKit::VerifyAccessToken(tokenIdEx.tokenIdExStruct.tokenID, "ohos.permission.LOCATION"));
    EXPECT_EQ(PERMISSION_DENIED,
        AccessTokenCompatKit::VerifyAccessToken(tokenIdEx.tokenIdExStruct.tokenID, "ohos.permission.test"));

    EXPECT_EQ(RET_SUCCESS, AccessTokenKit::DeleteToken(tokenIdEx.tokenIdExStruct.tokenID));
    SetSelfTokenID(selfTokenId);
}

/**
 * @tc.name: VerifyAccessTokenMonitorTestFunc001
 * @tc.desc: Verify user granted permission.
 * @tc.type: FUNC
 * @tc.require: Issue Number
 */
HWTEST_F(ATCompatSdkTest, VerifyAccessTokenMonitorTestFunc001, TestSize.Level1)
{
    setuid(0);
    AccessTokenIDEx tokenIdEx1 = TestCommon::GetHapTokenIdFromBundle(TEST_USER_ID, TEST_BUNDLE_NAME, 0);
    AccessTokenID tokenID1 = tokenIdEx1.tokenIdExStruct.tokenID;
    TestCommon::DeleteTestHapToken(tokenID1);
    HapInfoParams info = {
        .userID = TEST_USER_ID,
        .bundleName = TEST_BUNDLE_NAME,
        .instIndex = 0,
        .appIDDesc = "VerifyAccessTokenMonitorTest",
        .apiVersion = DEFAULT_API_VERSION,
        .isSystemApp = false
    };

    HapPolicyParams policy = {
        .apl = APL_NORMAL,
        .domain = "VerifyAccessTokenMonitorTest",
        .permStateList = {},
    };

    AccessTokenIDEx tokenIdEx = {0};
    ASSERT_EQ(RET_SUCCESS, TestCommon::AllocTestHapToken(info, policy, tokenIdEx));
    ASSERT_NE(tokenIdEx.tokenIdExStruct.tokenID, INVALID_TOKENID);

    SetSelfTokenID(tokenIdEx.tokenIDEx);
    int32_t ret = AccessTokenCompatKit::VerifyAccessToken(
        static_cast<AccessTokenID>(g_selfShellTokenId), "ohos.permission.DUMP");
    EXPECT_EQ(PERMISSION_GRANTED, ret);

    for (int32_t i = 1; i < VERIFY_THRESHOLD + 1; ++i) {
        EXPECT_EQ(AccessTokenCompatKit::VerifyAccessToken(i, "ohos.permission.MICROPHONE"), PERMISSION_DENIED);
    }

    ret = AccessTokenCompatKit::VerifyAccessToken(
        static_cast<AccessTokenID>(g_selfShellTokenId), "ohos.permission.DUMP");
    EXPECT_EQ(PERMISSION_DENIED, ret);

    TestCommon::DeleteTestHapToken(tokenIdEx.tokenIdExStruct.tokenID);
    SetSelfTokenID(g_selfShellTokenId);
}
}  // namespace AccessToken
}  // namespace Security
}
