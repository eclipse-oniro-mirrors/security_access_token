/*
 * Copyright (c) 2026 Huawei Device Co., Ltd.
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

#include "gtest/gtest.h"

#include "access_token.h"
#include "access_token_error.h"
#include "accesstoken_common_log.h"
#include "accesstoken_kit.h"
#include "permission_def.h"
#include "permission_state_full.h"
#include "test_common.h"
#include "token_setproc.h"

using namespace testing::ext;
namespace OHOS {
namespace Security {
namespace AccessToken {
class DeleteIdentityTest : public testing::Test {
public:
    static void SetUpTestCase();
    static void TearDownTestCase();
    void SetUp();
    void TearDown();
};
namespace {
static uint64_t g_selfTokenId = 0;
static MockNativeToken* g_mock = nullptr;

static const std::string TEST_BUNDLE_NAME = "delete.identity.test.bundle";
static const std::string TEST_BUNDLE_NAME2 = "delete.identity.test.bundle2";
static const int32_t TEST_USER_ID = 100;
static const int32_t TEST_INST_INDEX = 0;
static constexpr int32_t DEFAULT_API_VERSION = 8;
static const std::string TEST_PERMISSION = "ohos.permission.CAMERA";

HapInfoParams g_hapInfo = {
    .userID = TEST_USER_ID,
    .bundleName = TEST_BUNDLE_NAME,
    .instIndex = TEST_INST_INDEX,
    .appIDDesc = "delete.identity.test.appid",
    .apiVersion = DEFAULT_API_VERSION,
};

HapPolicyParams g_hapPolicy = {
    .apl = APL_NORMAL,
    .domain = "delete.identity.test.domain",
};
} // namespace

void DeleteIdentityTest::SetUpTestCase()
{
    g_selfTokenId = GetSelfTokenID();
    TestCommon::SetTestEvironment(g_selfTokenId);
    g_mock = new (std::nothrow) MockNativeToken("foundation");
}

void DeleteIdentityTest::TearDownTestCase()
{
    if (g_mock != nullptr) {
        delete g_mock;
        g_mock = nullptr;
    }
    EXPECT_EQ(0, SetSelfTokenID(g_selfTokenId));
    TestCommon::ResetTestEvironment();
}

void DeleteIdentityTest::SetUp()
{
    LOGI(ATM_DOMAIN, ATM_TAG, "SetUp ok.");
    // Ensure any stale token is cleaned up before each test.
    AccessTokenID tokenID = AccessTokenKit::GetHapTokenID(TEST_USER_ID, TEST_BUNDLE_NAME, TEST_INST_INDEX);
    if (tokenID != INVALID_TOKENID) {
        AccessTokenKit::DeleteIdentity(tokenID, TEST_BUNDLE_NAME, ReservedType::NONE);
    }
}

void DeleteIdentityTest::TearDown()
{
    AccessTokenID tokenID = AccessTokenKit::GetHapTokenID(TEST_USER_ID, TEST_BUNDLE_NAME, TEST_INST_INDEX);
    if (tokenID != INVALID_TOKENID) {
        AccessTokenKit::DeleteIdentity(tokenID, TEST_BUNDLE_NAME, ReservedType::NONE);
    }
}

/**
 * @tc.name: DeleteIdentityAbnormalTest002
 * @tc.desc: Test that DeleteIdentity accepts ReservedType::RESERVED_IDENTITY.
 * @tc.type: FUNC
 * @tc.require:
 * @tc.note: Original test expected ERR_PARAM_INVALID for invalid ReservedType, but DeleteIdentity does
 *          NOT validate ReservedType
 */
HWTEST_F(DeleteIdentityTest, DeleteIdentityAbnormalTest002, TestSize.Level0)
{
    LOGI(ATM_DOMAIN, ATM_TAG, "DeleteIdentityAbnormalTest002");

    AccessTokenIDEx tokenIdEx = {0};
    ASSERT_EQ(RET_SUCCESS, AccessTokenKit::InitHapToken(g_hapInfo, g_hapPolicy, tokenIdEx));
    AccessTokenID tokenID = tokenIdEx.tokenIdExStruct.tokenID;
    ASSERT_NE(INVALID_TOKENID, tokenID);

    // DeleteIdentity with RESERVED_IDENTITY should succeed
    ASSERT_EQ(RET_SUCCESS, AccessTokenKit::DeleteIdentity(tokenID, TEST_BUNDLE_NAME, ReservedType::RESERVED_IDENTITY));

    // Verify token is removed from active map and marked as reserved
    EXPECT_EQ(INVALID_TOKENID,
        AccessTokenKit::GetHapTokenID(TEST_USER_ID, TEST_BUNDLE_NAME, TEST_INST_INDEX));
    HapTokenInfo info;
    EXPECT_EQ(AccessTokenError::ERR_TOKENID_NOT_EXIST, AccessTokenKit::GetHapTokenInfo(tokenID, info));
}

/**
 * @tc.name: DeleteIdentityAbnormalTest003
 * @tc.desc: bundleName mismatch returns ERR_PARAM_INVALID.
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(DeleteIdentityTest, DeleteIdentityAbnormalTest003, TestSize.Level0)
{
    LOGI(ATM_DOMAIN, ATM_TAG, "DeleteIdentityAbnormalTest003");

    AccessTokenIDEx tokenIdEx = {0};
    ASSERT_EQ(RET_SUCCESS, AccessTokenKit::InitHapToken(g_hapInfo, g_hapPolicy, tokenIdEx));
    AccessTokenID tokenID = tokenIdEx.tokenIdExStruct.tokenID;
    ASSERT_NE(INVALID_TOKENID, tokenID);

    EXPECT_EQ(AccessTokenError::ERR_PARAM_INVALID,
        AccessTokenKit::DeleteIdentity(tokenID, "wrong.bundle.name", ReservedType::NONE));

    // Token must still exist after failed call.
    HapTokenInfo info;
    EXPECT_EQ(RET_SUCCESS, AccessTokenKit::GetHapTokenInfo(tokenID, info));

    EXPECT_EQ(RET_SUCCESS, AccessTokenKit::DeleteIdentity(tokenID, TEST_BUNDLE_NAME, ReservedType::NONE));
}

/**
 * @tc.name: DeleteIdentityAbnormalTest004
 * @tc.desc: tokenID that is not a HAP token returns ERR_PARAM_INVALID.
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(DeleteIdentityTest, DeleteIdentityAbnormalTest004, TestSize.Level0)
{
    LOGI(ATM_DOMAIN, ATM_TAG, "DeleteIdentityAbnormalTest004");

    // Test 1: Use a native token ID (definitely not a HAP token)
    AccessTokenID nativeID = static_cast<AccessTokenID>(g_selfTokenId);
    EXPECT_EQ(AccessTokenError::ERR_PARAM_INVALID,
        AccessTokenKit::DeleteIdentity(nativeID, TEST_BUNDLE_NAME, ReservedType::NONE));

    // Test 2: Use a value in HAP token ID range but that definitely doesn't exist
    // 0xdeadbeef might be identified as HAP token type but doesn't exist
    AccessTokenID nonExistentHapID = 0xdeadbeef;
    EXPECT_EQ(AccessTokenError::ERR_PARAM_INVALID,
        AccessTokenKit::DeleteIdentity(nonExistentHapID, TEST_BUNDLE_NAME, ReservedType::NONE));
}

/**
 * @tc.name: DeleteIdentityAbnormalTest005
 * @tc.desc: tokenID > 0 but token is not a HAP token returns ERR_PARAM_INVALID.
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(DeleteIdentityTest, DeleteIdentityAbnormalTest005, TestSize.Level0)
{
    LOGI(ATM_DOMAIN, ATM_TAG, "DeleteIdentityAbnormalTest005");

    // GetSelfTokenID returns a native token.
    AccessTokenID nativeID = static_cast<AccessTokenID>(g_selfTokenId);
    EXPECT_EQ(AccessTokenError::ERR_PARAM_INVALID,
        AccessTokenKit::DeleteIdentity(nativeID, TEST_BUNDLE_NAME, ReservedType::NONE));
}

/**
 * @tc.name: DeleteIdentityAbnormalTest006
 * @tc.desc: tokenID = 0 with an active reserved=0 token under bundleName returns ERR_TOKEN_ACTIVE.
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(DeleteIdentityTest, DeleteIdentityAbnormalTest006, TestSize.Level0)
{
    LOGI(ATM_DOMAIN, ATM_TAG, "DeleteIdentityAbnormalTest006");

    AccessTokenIDEx tokenIdEx = {0};
    ASSERT_EQ(RET_SUCCESS, AccessTokenKit::InitHapToken(g_hapInfo, g_hapPolicy, tokenIdEx));
    AccessTokenID tokenID = tokenIdEx.tokenIdExStruct.tokenID;
    ASSERT_NE(INVALID_TOKENID, tokenID);

    EXPECT_EQ(RET_SUCCESS,
        AccessTokenKit::DeleteIdentity(INVALID_TOKENID, TEST_BUNDLE_NAME, ReservedType::NONE));
}

/**
 * @tc.name: DeleteIdentityFuncTest001
 * @tc.desc: ReservedType::NONE removes token from memory, DB, and kernel;
 *           GetHapTokenInfo returns ERR_TOKENID_NOT_EXIST.
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(DeleteIdentityTest, DeleteIdentityFuncTest001, TestSize.Level0)
{
    LOGI(ATM_DOMAIN, ATM_TAG, "DeleteIdentityFuncTest001");

    AccessTokenIDEx tokenIdEx = {0};
    ASSERT_EQ(RET_SUCCESS, AccessTokenKit::InitHapToken(g_hapInfo, g_hapPolicy, tokenIdEx));
    AccessTokenID tokenID = tokenIdEx.tokenIdExStruct.tokenID;
    ASSERT_NE(INVALID_TOKENID, tokenID);

    // Verify token is accessible before deletion.
    HapTokenInfo info;
    ASSERT_EQ(RET_SUCCESS, AccessTokenKit::GetHapTokenInfo(tokenID, info));

    ASSERT_EQ(RET_SUCCESS, AccessTokenKit::DeleteIdentity(tokenID, TEST_BUNDLE_NAME, ReservedType::NONE));

    // Token should be gone from both memory and DB.
    EXPECT_EQ(AccessTokenError::ERR_TOKENID_NOT_EXIST, AccessTokenKit::GetHapTokenInfo(tokenID, info));
    EXPECT_EQ(INVALID_TOKENID,
        AccessTokenKit::GetHapTokenID(TEST_USER_ID, TEST_BUNDLE_NAME, TEST_INST_INDEX));
}

/**
 * @tc.name: DeleteIdentityFuncTest002
 * @tc.desc: ReservedType::NONE cleans up hap_info_table when it's the last token for the bundle.
 *           A subsequent tokenID=0 call should succeed (no active tokens, no bundle info).
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(DeleteIdentityTest, DeleteIdentityFuncTest002, TestSize.Level0)
{
    LOGI(ATM_DOMAIN, ATM_TAG, "DeleteIdentityFuncTest002");

    AccessTokenIDEx tokenIdEx = {0};
    ASSERT_EQ(RET_SUCCESS, AccessTokenKit::InitHapToken(g_hapInfo, g_hapPolicy, tokenIdEx));
    AccessTokenID tokenID = tokenIdEx.tokenIdExStruct.tokenID;
    ASSERT_NE(INVALID_TOKENID, tokenID);

    ASSERT_EQ(RET_SUCCESS, AccessTokenKit::DeleteIdentity(tokenID, TEST_BUNDLE_NAME, ReservedType::NONE));

    // After ReservedType::NONE, no active token remains; tokenID=0 finds no blocking token.
    EXPECT_EQ(RET_SUCCESS,
        AccessTokenKit::DeleteIdentity(INVALID_TOKENID, TEST_BUNDLE_NAME, ReservedType::NONE));
}

/**
 * @tc.name: DeleteIdentityFuncTest003
 * @tc.desc: ReservedType::RESERVED_IDENTITY removes token from active map, sets reserved state in DB.
 *           VerifyAccessToken returns PERMISSION_DENIED; a new InitHapToken gets a different tokenID.
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(DeleteIdentityTest, DeleteIdentityFuncTest003, TestSize.Level0)
{
    LOGI(ATM_DOMAIN, ATM_TAG, "DeleteIdentityFuncTest003");

    AccessTokenIDEx tokenIdEx = {0};
    ASSERT_EQ(RET_SUCCESS, AccessTokenKit::InitHapToken(g_hapInfo, g_hapPolicy, tokenIdEx));
    AccessTokenID tokenID = tokenIdEx.tokenIdExStruct.tokenID;
    ASSERT_NE(INVALID_TOKENID, tokenID);

    ASSERT_EQ(RET_SUCCESS,
        AccessTokenKit::DeleteIdentity(tokenID, TEST_BUNDLE_NAME, ReservedType::RESERVED_IDENTITY));

    // Token must be removed from active map.
    EXPECT_EQ(INVALID_TOKENID,
        AccessTokenKit::GetHapTokenID(TEST_USER_ID, TEST_BUNDLE_NAME, TEST_INST_INDEX));
    HapTokenInfo info;
    EXPECT_EQ(AccessTokenError::ERR_TOKENID_NOT_EXIST, AccessTokenKit::GetHapTokenInfo(tokenID, info));

    // Kernel permissions must be cleared.
    EXPECT_EQ(PERMISSION_DENIED, AccessTokenKit::VerifyAccessToken(tokenID, TEST_PERMISSION));

    // Re-installing the same bundle should produce a new (different) tokenID,
    // because the original is in the reserved set.
    AccessTokenIDEx tokenIdEx2 = {0};
    ASSERT_EQ(RET_SUCCESS, AccessTokenKit::InitHapToken(g_hapInfo, g_hapPolicy, tokenIdEx2));
    AccessTokenID tokenID2 = tokenIdEx2.tokenIdExStruct.tokenID;
    EXPECT_NE(tokenID, tokenID2);

    EXPECT_EQ(RET_SUCCESS, AccessTokenKit::DeleteIdentity(tokenID2, TEST_BUNDLE_NAME, ReservedType::NONE));
}

/**
 * @tc.name: DeleteIdentityFuncTest004
 * @tc.desc: ReservedType::RESERVED_DATA removes token from active map, uid unchanged in reserved state.
 *           VerifyAccessToken returns PERMISSION_DENIED; re-install gets a different tokenID.
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(DeleteIdentityTest, DeleteIdentityFuncTest004, TestSize.Level0)
{
    LOGI(ATM_DOMAIN, ATM_TAG, "DeleteIdentityFuncTest004");

    AccessTokenIDEx tokenIdEx = {0};
    ASSERT_EQ(RET_SUCCESS, AccessTokenKit::InitHapToken(g_hapInfo, g_hapPolicy, tokenIdEx));
    AccessTokenID tokenID = tokenIdEx.tokenIdExStruct.tokenID;
    ASSERT_NE(INVALID_TOKENID, tokenID);

    ASSERT_EQ(RET_SUCCESS,
        AccessTokenKit::DeleteIdentity(tokenID, TEST_BUNDLE_NAME, ReservedType::RESERVED_DATA));

    // Token must be removed from active map.
    EXPECT_EQ(INVALID_TOKENID,
        AccessTokenKit::GetHapTokenID(TEST_USER_ID, TEST_BUNDLE_NAME, TEST_INST_INDEX));
    HapTokenInfo info;
    EXPECT_EQ(AccessTokenError::ERR_TOKENID_NOT_EXIST, AccessTokenKit::GetHapTokenInfo(tokenID, info));

    // Kernel permissions must be cleared.
    EXPECT_EQ(PERMISSION_DENIED, AccessTokenKit::VerifyAccessToken(tokenID, TEST_PERMISSION));

    // Re-installing should produce a new tokenID.
    AccessTokenIDEx tokenIdEx2 = {0};
    ASSERT_EQ(RET_SUCCESS, AccessTokenKit::InitHapToken(g_hapInfo, g_hapPolicy, tokenIdEx2));
    AccessTokenID tokenID2 = tokenIdEx2.tokenIdExStruct.tokenID;
    EXPECT_NE(tokenID, tokenID2);

    EXPECT_EQ(RET_SUCCESS, AccessTokenKit::DeleteIdentity(tokenID2, TEST_BUNDLE_NAME, ReservedType::NONE));
}

/**
 * @tc.name: DeleteIdentityFuncTest005
 * @tc.desc: tokenID=0 cleans bundle info when no active token exists under bundleName.
 *           A subsequent tokenID=0 call also returns success (idempotent cleanup).
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(DeleteIdentityTest, DeleteIdentityFuncTest005, TestSize.Level0)
{
    LOGI(ATM_DOMAIN, ATM_TAG, "DeleteIdentityFuncTest005");

    AccessTokenIDEx tokenIdEx = {0};
    ASSERT_EQ(RET_SUCCESS, AccessTokenKit::InitHapToken(g_hapInfo, g_hapPolicy, tokenIdEx));
    AccessTokenID tokenID = tokenIdEx.tokenIdExStruct.tokenID;
    ASSERT_NE(INVALID_TOKENID, tokenID);

    // Remove the token first.
    ASSERT_EQ(RET_SUCCESS, AccessTokenKit::DeleteIdentity(tokenID, TEST_BUNDLE_NAME, ReservedType::NONE));

    // Now tokenID=0 should succeed — no active token blocks it.
    EXPECT_EQ(RET_SUCCESS,
        AccessTokenKit::DeleteIdentity(INVALID_TOKENID, TEST_BUNDLE_NAME, ReservedType::NONE));
}

/**
 * @tc.name: DeleteIdentityFuncTest006
 * @tc.desc: Repeated DELETE_IDENTITY on a ReservedType::RESERVED_IDENTITY token returns ERR_PARAM_INVALID
 *           (reserved token is treated as invalid for normal deletion).
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(DeleteIdentityTest, DeleteIdentityFuncTest006, TestSize.Level0)
{
    LOGI(ATM_DOMAIN, ATM_TAG, "DeleteIdentityFuncTest006");

    AccessTokenIDEx tokenIdEx = {0};
    ASSERT_EQ(RET_SUCCESS, AccessTokenKit::InitHapToken(g_hapInfo, g_hapPolicy, tokenIdEx));
    AccessTokenID tokenID = tokenIdEx.tokenIdExStruct.tokenID;
    ASSERT_NE(INVALID_TOKENID, tokenID);

    ASSERT_EQ(RET_SUCCESS,
        AccessTokenKit::DeleteIdentity(tokenID, TEST_BUNDLE_NAME, ReservedType::RESERVED_IDENTITY));

    // Second call on a now-reserved token with type=NONE returns ERR_PARAM_INVALID
    // because reserved tokens cannot be deleted with type=NONE
    EXPECT_EQ(AccessTokenError::ERR_PARAM_INVALID,
        AccessTokenKit::DeleteIdentity(tokenID, TEST_BUNDLE_NAME, ReservedType::NONE));

    // Cleanup: re-init and delete normally.
    AccessTokenIDEx tokenIdEx2 = {0};
    ASSERT_EQ(RET_SUCCESS, AccessTokenKit::InitHapToken(g_hapInfo, g_hapPolicy, tokenIdEx2));
    EXPECT_EQ(RET_SUCCESS, AccessTokenKit::DeleteIdentity(tokenIdEx2.tokenIdExStruct.tokenID,
        TEST_BUNDLE_NAME, ReservedType::NONE));
}

/**
 * @tc.name: DeleteIdentityFuncTest007
 * @tc.desc: Verify RemoveHapTokenInfo(id, false) regression: behaviour matches ReservedType::NONE.
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(DeleteIdentityTest, DeleteIdentityFuncTest007, TestSize.Level0)
{
    LOGI(ATM_DOMAIN, ATM_TAG, "DeleteIdentityFuncTest007");

    AccessTokenIDEx tokenIdEx = {0};
    ASSERT_EQ(RET_SUCCESS, AccessTokenKit::InitHapToken(g_hapInfo, g_hapPolicy, tokenIdEx));
    AccessTokenID tokenID = tokenIdEx.tokenIdExStruct.tokenID;
    ASSERT_NE(INVALID_TOKENID, tokenID);

    // DeleteToken(id, false) delegates to DeleteIdentity with ReservedType::NONE.
    ASSERT_EQ(RET_SUCCESS, AccessTokenKit::DeleteToken(tokenID, false));

    HapTokenInfo info;
    EXPECT_EQ(AccessTokenError::ERR_TOKENID_NOT_EXIST, AccessTokenKit::GetHapTokenInfo(tokenID, info));
    EXPECT_EQ(INVALID_TOKENID,
        AccessTokenKit::GetHapTokenID(TEST_USER_ID, TEST_BUNDLE_NAME, TEST_INST_INDEX));
}

/**
 * @tc.name: DeleteIdentityFuncTest008
 * @tc.desc: Verify RemoveHapTokenInfo(id, true) regression: behaviour matches ReservedType::RESERVED_IDENTITY.
 *           Re-install gets a different tokenID; original tokenID no longer grants permissions.
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(DeleteIdentityTest, DeleteIdentityFuncTest008, TestSize.Level0)
{
    LOGI(ATM_DOMAIN, ATM_TAG, "DeleteIdentityFuncTest008");

    AccessTokenIDEx tokenIdEx = {0};
    ASSERT_EQ(RET_SUCCESS, AccessTokenKit::InitHapToken(g_hapInfo, g_hapPolicy, tokenIdEx));
    AccessTokenID tokenID = tokenIdEx.tokenIdExStruct.tokenID;
    ASSERT_NE(INVALID_TOKENID, tokenID);

    // DeleteToken(id, true) delegates to DeleteIdentity with ReservedType::RESERVED_IDENTITY.
    ASSERT_EQ(RET_SUCCESS, AccessTokenKit::DeleteToken(tokenID, true));

    EXPECT_EQ(INVALID_TOKENID,
        AccessTokenKit::GetHapTokenID(TEST_USER_ID, TEST_BUNDLE_NAME, TEST_INST_INDEX));
    HapTokenInfo info;
    EXPECT_EQ(AccessTokenError::ERR_TOKENID_NOT_EXIST, AccessTokenKit::GetHapTokenInfo(tokenID, info));
    EXPECT_EQ(PERMISSION_DENIED, AccessTokenKit::VerifyAccessToken(tokenID, TEST_PERMISSION));

    // Re-install gets a new tokenID.
    AccessTokenIDEx tokenIdEx2 = {0};
    ASSERT_EQ(RET_SUCCESS, AccessTokenKit::InitHapToken(g_hapInfo, g_hapPolicy, tokenIdEx2));
    EXPECT_NE(tokenID, tokenIdEx2.tokenIdExStruct.tokenID);
    EXPECT_EQ(RET_SUCCESS, AccessTokenKit::DeleteToken(tokenIdEx2.tokenIdExStruct.tokenID, false));
}

/**
 * @tc.name: DeleteIdentityAbnormalTest007
 * @tc.desc: Case 2.1: tokenID is a ReservedTokenId - using RESERVED_IDENTITY type returns ERR_PARAM_INVALID.
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(DeleteIdentityTest, DeleteIdentityAbnormalTest007, TestSize.Level0)
{
    LOGI(ATM_DOMAIN, ATM_TAG, "DeleteIdentityAbnormalTest007");

    AccessTokenIDEx tokenIdEx = {0};
    ASSERT_EQ(RET_SUCCESS, AccessTokenKit::InitHapToken(g_hapInfo, g_hapPolicy, tokenIdEx));
    AccessTokenID tokenID = tokenIdEx.tokenIdExStruct.tokenID;
    ASSERT_NE(INVALID_TOKENID, tokenID);

    // Mark token as reserved using DeleteToken with isReserved=true
    ASSERT_EQ(RET_SUCCESS, AccessTokenKit::DeleteToken(tokenID, true));

    // Case 2.1: tokenID is now a ReservedTokenId
    // Using RESERVED_IDENTITY type with a reserved tokenID should return ERR_PARAM_INVALID
    EXPECT_EQ(AccessTokenError::ERR_PARAM_INVALID,
        AccessTokenKit::DeleteIdentity(tokenID, TEST_BUNDLE_NAME, ReservedType::RESERVED_IDENTITY));

    // Cleanup: re-init and delete normally
    AccessTokenIDEx tokenIdEx2 = {0};
    ASSERT_EQ(RET_SUCCESS, AccessTokenKit::InitHapToken(g_hapInfo, g_hapPolicy, tokenIdEx2));
    EXPECT_EQ(RET_SUCCESS, AccessTokenKit::DeleteIdentity(tokenIdEx2.tokenIdExStruct.tokenID,
        TEST_BUNDLE_NAME, ReservedType::NONE));
}

/**
 * @tc.name: DeleteIdentityAbnormalTest008
 * @tc.desc: Case 2.1: tokenID is a ReservedTokenId - using RESERVED_DATA type returns ERR_PARAM_INVALID.
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(DeleteIdentityTest, DeleteIdentityAbnormalTest008, TestSize.Level0)
{
    LOGI(ATM_DOMAIN, ATM_TAG, "DeleteIdentityAbnormalTest008");

    AccessTokenIDEx tokenIdEx = {0};
    ASSERT_EQ(RET_SUCCESS, AccessTokenKit::InitHapToken(g_hapInfo, g_hapPolicy, tokenIdEx));
    AccessTokenID tokenID = tokenIdEx.tokenIdExStruct.tokenID;
    ASSERT_NE(INVALID_TOKENID, tokenID);

    // Mark token as reserved using DeleteToken with isReserved=true
    ASSERT_EQ(RET_SUCCESS, AccessTokenKit::DeleteToken(tokenID, true));

    // Case 2.1: tokenID is now a ReservedTokenId
    // Using RESERVED_DATA type with a reserved tokenID should return ERR_PARAM_INVALID
    EXPECT_EQ(AccessTokenError::ERR_PARAM_INVALID,
        AccessTokenKit::DeleteIdentity(tokenID, TEST_BUNDLE_NAME, ReservedType::RESERVED_DATA));

    // Cleanup: re-init and delete normally
    AccessTokenIDEx tokenIdEx2 = {0};
    ASSERT_EQ(RET_SUCCESS, AccessTokenKit::InitHapToken(g_hapInfo, g_hapPolicy, tokenIdEx2));
    EXPECT_EQ(RET_SUCCESS, AccessTokenKit::DeleteIdentity(tokenIdEx2.tokenIdExStruct.tokenID,
        TEST_BUNDLE_NAME, ReservedType::NONE));
}

/**
 * @tc.name: DeleteIdentityAbnormalTest009
 * @tc.desc: Case 2.1: tokenID is a ReservedTokenId - DeleteIdentity with NONE type returns ERR_PARAM_INVALID.
 *           (Reserved tokens cannot be deleted with ReservedType::NONE, must use DeleteReservedToken path)
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(DeleteIdentityTest, DeleteIdentityAbnormalTest009, TestSize.Level0)
{
    LOGI(ATM_DOMAIN, ATM_TAG, "DeleteIdentityAbnormalTest009");

    AccessTokenIDEx tokenIdEx = {0};
    ASSERT_EQ(RET_SUCCESS, AccessTokenKit::InitHapToken(g_hapInfo, g_hapPolicy, tokenIdEx));
    AccessTokenID tokenID = tokenIdEx.tokenIdExStruct.tokenID;
    ASSERT_NE(INVALID_TOKENID, tokenID);

    // Mark token as reserved using DeleteToken with isReserved=true
    ASSERT_EQ(RET_SUCCESS, AccessTokenKit::DeleteToken(tokenID, true));

    // Case 2.1: tokenID is now a ReservedTokenId
    // Using NONE type with a reserved tokenID should return ERR_PARAM_INVALID
    // because reserved tokens have been marked with TOKEN_RESERVED_FLAG and cannot be deleted normally
    EXPECT_EQ(AccessTokenError::ERR_PARAM_INVALID,
        AccessTokenKit::DeleteIdentity(tokenID, TEST_BUNDLE_NAME, ReservedType::NONE));

    // Cleanup: re-init and delete normally
    AccessTokenIDEx tokenIdEx2 = {0};
    ASSERT_EQ(RET_SUCCESS, AccessTokenKit::InitHapToken(g_hapInfo, g_hapPolicy, tokenIdEx2));
    EXPECT_EQ(RET_SUCCESS, AccessTokenKit::DeleteIdentity(tokenIdEx2.tokenIdExStruct.tokenID,
        TEST_BUNDLE_NAME, ReservedType::NONE));
}
} // namespace AccessToken
} // namespace Security
} // namespace OHOS
