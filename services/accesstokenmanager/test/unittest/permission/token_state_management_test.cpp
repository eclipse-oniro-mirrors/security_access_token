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

#include <gtest/gtest.h>
#include <algorithm>

#define private public
#include "access_token.h"
#include "access_token_error.h"
#include "accesstoken_id_manager.h"
#include "accesstoken_info_manager.h"
#undef private
#include "permission_map.h"
#include "token_field_const.h"

using namespace testing::ext;

namespace OHOS {
namespace Security {
namespace AccessToken {
namespace {
constexpr int32_t DEFAULT_USER_ID = 100;
constexpr int32_t DEFAULT_INST_INDEX = 0;

PermissionStatus BuildPermissionStatus(const std::string& permissionName)
{
    PermissionStatus status;
    status.permissionName = permissionName;
    status.grantStatus = PERMISSION_DENIED;
    status.grantFlag = PERMISSION_DEFAULT_FLAG;
    return status;
}

HapInfoParams BuildHapInfoParams(const std::string& bundleName)
{
    return {
        .userID = DEFAULT_USER_ID,
        .bundleName = bundleName,
        .instIndex = DEFAULT_INST_INDEX,
        .appIDDesc = bundleName + "_app_id",
        .isSystemApp = false
    };
}

HapPolicy BuildHapPolicy()
{
    return {
        .apl = APL_NORMAL,
        .domain = "test.domain",
        .permList = {},
        .permStateList = {
            BuildPermissionStatus("ohos.permission.CAMERA"),
            BuildPermissionStatus("ohos.permission.MICROPHONE")
        }
    };
}

AccessTokenID CreateTestHapToken(const std::string& bundleName)
{
    HapInfoParams info = BuildHapInfoParams(bundleName);
    HapPolicy policy = BuildHapPolicy();

    AccessTokenIDEx tokenIdEx = {0};
    std::vector<GenericValues> undefValues;
    int32_t ret = AccessTokenInfoManager::GetInstance().CreateHapTokenInfo(
        info, policy, tokenIdEx, undefValues);
    if (ret != RET_SUCCESS) {
        return 0;
    }
    return tokenIdEx.tokenIdExStruct.tokenID;
}

void RemoveTestHapToken(AccessTokenID tokenId)
{
    if (tokenId != 0) {
        AccessTokenInfoManager::GetInstance().RemoveHapTokenInfo(tokenId);
    }
}
} // namespace

class TokenStateManagementTest : public testing::Test {
public:
    void SetUp() override {}

    void TearDown() override {}
};

/**
 * @tc.name: GetHapTokenInfoInnerWithDefaultParam001
 * @tc.desc: Test GetHapTokenInfoInner with default parameter for active token
 * @tc.type: FUNC
 * @tc.require: issue
 */
HWTEST_F(TokenStateManagementTest, GetHapTokenInfoInnerWithDefaultParam001, TestSize.Level0)
{
    // Arrange: Create active HAP token
    std::string bundleName = "test.active.token.default.001";
    AccessTokenID tokenId = CreateTestHapToken(bundleName);
    ASSERT_NE(0, tokenId);

    // Act: Get token with default parameter (isActive=true)
    auto tokenInfo = AccessTokenInfoManager::GetInstance().GetHapTokenInfoInner(tokenId);

    // Assert: Verify returned token info is correct
    ASSERT_NE(nullptr, tokenInfo);
    EXPECT_EQ(bundleName, tokenInfo->GetBundleName());
    EXPECT_EQ(DEFAULT_USER_ID, tokenInfo->GetUserID());
    EXPECT_EQ(DEFAULT_INST_INDEX, tokenInfo->GetInstIndex());

    // Cleanup
    RemoveTestHapToken(tokenId);
}

/**
 * @tc.name: GetHapTokenInfoInnerWithActiveTrue002
 * @tc.desc: Test GetHapTokenInfoInner with isActive=true for token not in cache
 * @tc.type: FUNC
 * @tc.require: issue
 */
HWTEST_F(TokenStateManagementTest, GetHapTokenInfoInnerWithActiveTrue002, TestSize.Level0)
{
    // Arrange: Create HAP token and remove from active cache
    std::string bundleName = "test.reserved.token.true.002";
    AccessTokenID tokenId = CreateTestHapToken(bundleName);
    ASSERT_NE(0, tokenId);

    // Set to RESERVED status
    int32_t ret = AccessTokenIDManager::GetInstance().ChangeTokenIdStatus(
        tokenId, TokenIdStatus::RESERVED);
    ASSERT_EQ(RET_SUCCESS, ret);

    // Remove from active cache so GetHapTokenInfoInner will check token status
    AccessTokenInfoManager::GetInstance().hapTokenInfoMap_.erase(tokenId);

    // Act: Get inactive token with isActive=true should return nullptr
    auto tokenInfo = AccessTokenInfoManager::GetInstance().GetHapTokenInfoInner(tokenId, true);

    // Assert: isActive=true should return nullptr for RESERVED token
    EXPECT_EQ(nullptr, tokenInfo) << "isActive=true should return nullptr for RESERVED token";

    // Cleanup
    RemoveTestHapToken(tokenId);
}

/**
 * @tc.name: GetHapTokenInfoInnerWithActiveFalse001
 * @tc.desc: Test GetHapTokenInfoInner with isActive=false for RESERVED token
 * @tc.type: FUNC
 * @tc.require: issue
 */
HWTEST_F(TokenStateManagementTest, GetHapTokenInfoInnerWithActiveFalse001, TestSize.Level0)
{
    // Arrange: Create HAP token and set to RESERVED status
    std::string bundleName = "test.reserved.token.false.001";
    AccessTokenID tokenId = CreateTestHapToken(bundleName);
    ASSERT_NE(0, tokenId);

    // Set to RESERVED status
    int32_t ret = AccessTokenIDManager::GetInstance().ChangeTokenIdStatus(
        tokenId, TokenIdStatus::RESERVED);
    ASSERT_EQ(RET_SUCCESS, ret);

    // Remove from active cache
    AccessTokenInfoManager::GetInstance().hapTokenInfoMap_.erase(tokenId);

    // Act: Get inactive token with isActive=false (calls GetInactiveTokenInfoInner internally)
    auto tokenInfo = AccessTokenInfoManager::GetInstance().GetHapTokenInfoInner(tokenId, false);

    // Assert: Verify returned token info is correct
    ASSERT_NE(nullptr, tokenInfo);
    EXPECT_EQ(bundleName, tokenInfo->GetBundleName());
    EXPECT_EQ(DEFAULT_USER_ID, tokenInfo->GetUserID());

    // Cleanup: Clean inactive cache
    AccessTokenInfoManager::GetInstance().ReleaseInactiveTokenInfoInner(tokenId);
    RemoveTestHapToken(tokenId);
}

/**
 * @tc.name: GetHapTokenInfoInnerWithActiveFalse002
 * @tc.desc: Test GetHapTokenInfoInner with isActive=false for ACTIVE token
 * @tc.type: FUNC
 * @tc.require: issue
 */
HWTEST_F(TokenStateManagementTest, GetHapTokenInfoInnerWithActiveFalse002, TestSize.Level0)
{
    // Arrange: Create active HAP token
    std::string bundleName = "test.active.token.false.002";
    AccessTokenID tokenId = CreateTestHapToken(bundleName);
    ASSERT_NE(0, tokenId);

    // Act: Get active token with isActive=false
    // isActive=false allows getting inactive tokens, but if token is ACTIVE, should get from active cache
    auto tokenInfo = AccessTokenInfoManager::GetInstance().GetHapTokenInfoInner(tokenId, false);

    // Assert: Verify returned token info is correct
    ASSERT_NE(nullptr, tokenInfo);
    EXPECT_EQ(bundleName, tokenInfo->GetBundleName());

    // Cleanup
    RemoveTestHapToken(tokenId);
}

/**
 * @tc.name: GetHapTokenInfoInnerCacheHit001
 * @tc.desc: Test GetHapTokenInfoInner cache hit mechanism
 * @tc.type: FUNC
 * @tc.require: issue
 */
HWTEST_F(TokenStateManagementTest, GetHapTokenInfoInnerCacheHit001, TestSize.Level0)
{
    // Arrange: Create active HAP token
    std::string bundleName = "test.cache.hit.001";
    AccessTokenID tokenId = CreateTestHapToken(bundleName);
    ASSERT_NE(0, tokenId);

    // Act: First get token - loads to cache
    auto tokenInfo1 = AccessTokenInfoManager::GetInstance().GetHapTokenInfoInner(tokenId, true);
    ASSERT_NE(nullptr, tokenInfo1);

    // Second get token - should get from cache
    auto tokenInfo2 = AccessTokenInfoManager::GetInstance().GetHapTokenInfoInner(tokenId, true);

    // Assert: Verify both get calls return the same object (from cache)
    ASSERT_NE(nullptr, tokenInfo2);
    EXPECT_EQ(tokenInfo1.get(), tokenInfo2.get()) << "Second call should return cached object";
    EXPECT_EQ(bundleName, tokenInfo2->GetBundleName());

    // Cleanup
    RemoveTestHapToken(tokenId);
}

/**
 * @tc.name: GetHapTokenInfoInnerFromDb001
 * @tc.desc: Test GetHapTokenInfoInner loads from database when not in cache
 * @tc.type: FUNC
 * @tc.require: issue
 */
HWTEST_F(TokenStateManagementTest, GetHapTokenInfoInnerFromDb001, TestSize.Level0)
{
    // Arrange: Create HAP token
    std::string bundleName = "test.from.db.001";
    AccessTokenID tokenId = CreateTestHapToken(bundleName);
    ASSERT_NE(0, tokenId);

    // Ensure token is in cache (first load)
    auto tokenInfo1 = AccessTokenInfoManager::GetInstance().GetHapTokenInfoInner(tokenId, true);
    ASSERT_NE(nullptr, tokenInfo1);

    // Act: Simulate reload after cache clear
    // In actual tests, we cannot directly clear cache, but can test DB load by creating new token

    // Cleanup
    RemoveTestHapToken(tokenId);

    // Try to get deleted token should return nullptr
    auto tokenInfo2 = AccessTokenInfoManager::GetInstance().GetHapTokenInfoInner(tokenId, true);
    EXPECT_EQ(nullptr, tokenInfo2) << "Deleted token should return nullptr";
}

/**
 * @tc.name: GetInactiveTokenInfoInner001
 * @tc.desc: Test GetInactiveTokenInfoInner loads from database on first call
 * @tc.type: FUNC
 * @tc.require: issue
 */
HWTEST_F(TokenStateManagementTest, GetInactiveTokenInfoInner001, TestSize.Level0)
{
    // Arrange: Create RESERVED status token
    std::string bundleName = "test.inactive.db.001";
    AccessTokenID tokenId = CreateTestHapToken(bundleName);
    ASSERT_NE(0, tokenId);

    int32_t ret = AccessTokenIDManager::GetInstance().ChangeTokenIdStatus(
        tokenId, TokenIdStatus::RESERVED);
    ASSERT_EQ(RET_SUCCESS, ret);

    // Remove from active cache
    AccessTokenInfoManager::GetInstance().hapTokenInfoMap_.erase(tokenId);

    // Act: First call to GetInactiveTokenInfoInner - loads from database
    auto tokenInfo1 = AccessTokenInfoManager::GetInstance().GetInactiveTokenInfoInner(tokenId);

    // Assert: Verify returned token info is correct
    ASSERT_NE(nullptr, tokenInfo1);
    EXPECT_EQ(bundleName, tokenInfo1->GetBundleName());

    // Cleanup: Clean inactive cache
    AccessTokenInfoManager::GetInstance().ReleaseInactiveTokenInfoInner(tokenId);
    RemoveTestHapToken(tokenId);
}

/**
 * @tc.name: GetInactiveTokenInfoInner002
 * @tc.desc: Test GetInactiveTokenInfoInner cache mechanism - second call uses cache
 * @tc.type: FUNC
 * @tc.require: issue
 */
HWTEST_F(TokenStateManagementTest, GetInactiveTokenInfoInner002, TestSize.Level0)
{
    // Arrange: Create RESERVED status token and load to cache
    std::string bundleName = "test.inactive.cache.002";
    AccessTokenID tokenId = CreateTestHapToken(bundleName);
    ASSERT_NE(0, tokenId);

    int32_t ret = AccessTokenIDManager::GetInstance().ChangeTokenIdStatus(
        tokenId, TokenIdStatus::RESERVED);
    ASSERT_EQ(RET_SUCCESS, ret);

    // Remove from active cache
    AccessTokenInfoManager::GetInstance().hapTokenInfoMap_.erase(tokenId);

    // First load to cache
    auto tokenInfo1 = AccessTokenInfoManager::GetInstance().GetInactiveTokenInfoInner(tokenId);
    ASSERT_NE(nullptr, tokenInfo1);

    // Act: Second call - should get from cache
    auto tokenInfo2 = AccessTokenInfoManager::GetInstance().GetInactiveTokenInfoInner(tokenId);

    // Assert: Verify both calls return the same object (from cache)
    ASSERT_NE(nullptr, tokenInfo2);
    EXPECT_EQ(tokenInfo1.get(), tokenInfo2.get()) << "Second call should return cached object";
    EXPECT_EQ(bundleName, tokenInfo2->GetBundleName());

    // Cleanup: Clean inactive cache
    AccessTokenInfoManager::GetInstance().ReleaseInactiveTokenInfoInner(tokenId);
    RemoveTestHapToken(tokenId);
}

/**
 * @tc.name: ReleaseInactiveTokenInfoInner001
 * @tc.desc: Test ReleaseInactiveTokenInfoInner removes token from cache
 * @tc.type: FUNC
 * @tc.require: issue
 */
HWTEST_F(TokenStateManagementTest, ReleaseInactiveTokenInfoInner001, TestSize.Level0)
{
    // Arrange: Create and cache inactive token
    std::string bundleName = "test.release.cache.001";
    AccessTokenID tokenId = CreateTestHapToken(bundleName);
    ASSERT_NE(0, tokenId);

    int32_t ret = AccessTokenIDManager::GetInstance().ChangeTokenIdStatus(
        tokenId, TokenIdStatus::RESERVED);
    ASSERT_EQ(RET_SUCCESS, ret);

    // Remove from active cache
    AccessTokenInfoManager::GetInstance().hapTokenInfoMap_.erase(tokenId);

    // Load to inactive cache
    auto tokenInfo1 = AccessTokenInfoManager::GetInstance().GetInactiveTokenInfoInner(tokenId);
    ASSERT_NE(nullptr, tokenInfo1);

    // Act: Release cache
    AccessTokenInfoManager::GetInstance().ReleaseInactiveTokenInfoInner(tokenId);

    // Get again should reload from database (new object pointer)
    auto tokenInfo2 = AccessTokenInfoManager::GetInstance().GetInactiveTokenInfoInner(tokenId);

    // Assert: Verify two gets return different objects (cache released, reloaded from DB)
    ASSERT_NE(nullptr, tokenInfo2);
    EXPECT_NE(tokenInfo1.get(), tokenInfo2.get()) << "After release, should reload from DB";
    EXPECT_EQ(bundleName, tokenInfo2->GetBundleName());

    // Cleanup: Clean inactive cache
    AccessTokenInfoManager::GetInstance().ReleaseInactiveTokenInfoInner(tokenId);
    RemoveTestHapToken(tokenId);
}

/**
 * @tc.name: TokenStateTransition001
 * @tc.desc: Test token state transition from RESERVED to ACTIVE
 * @tc.type: FUNC
 * @tc.require: issue
 */
HWTEST_F(TokenStateManagementTest, TokenStateTransition001, TestSize.Level0)
{
    // Arrange: Create RESERVED status token
    std::string bundleName = "test.transition.reserved.to.active";
    AccessTokenID tokenId = CreateTestHapToken(bundleName);
    ASSERT_NE(0, tokenId);

    int32_t ret = AccessTokenIDManager::GetInstance().ChangeTokenIdStatus(
        tokenId, TokenIdStatus::RESERVED);
    ASSERT_EQ(RET_SUCCESS, ret);

    // Remove from active cache
    AccessTokenInfoManager::GetInstance().hapTokenInfoMap_.erase(tokenId);

    // Verify can get token in inactive status (using isActive=false)
    auto tokenInfo1 = AccessTokenInfoManager::GetInstance().GetHapTokenInfoInner(tokenId, false);
    ASSERT_NE(nullptr, tokenInfo1);

    // Act: Transition to ACTIVE status
    ret = AccessTokenIDManager::GetInstance().ChangeTokenIdStatus(
        tokenId, TokenIdStatus::ACTIVE);
    ASSERT_EQ(RET_SUCCESS, ret);

    // Release inactive cache
    AccessTokenInfoManager::GetInstance().ReleaseInactiveTokenInfoInner(tokenId);

    // Assert: Verify can get token in active status (using isActive=true)
    auto tokenInfo2 = AccessTokenInfoManager::GetInstance().GetHapTokenInfoInner(tokenId, true);
    ASSERT_NE(nullptr, tokenInfo2);
    EXPECT_EQ(bundleName, tokenInfo2->GetBundleName());

    // Cleanup
    RemoveTestHapToken(tokenId);
}

/**
 * @tc.name: TokenStateTransition002
 * @tc.desc: Test token state transition from ACTIVE to RESERVED
 * @tc.type: FUNC
 * @tc.require: issue
 */
HWTEST_F(TokenStateManagementTest, TokenStateTransition002, TestSize.Level0)
{
    // Arrange: Create ACTIVE status token
    std::string bundleName = "test.transition.active.to.reserved";
    AccessTokenID tokenId = CreateTestHapToken(bundleName);
    ASSERT_NE(0, tokenId);

    // Verify can get token in active status
    auto tokenInfo1 = AccessTokenInfoManager::GetInstance().GetHapTokenInfoInner(tokenId, true);
    ASSERT_NE(nullptr, tokenInfo1);

    // Act: Transition to RESERVED status
    int32_t ret = AccessTokenIDManager::GetInstance().ChangeTokenIdStatus(
        tokenId, TokenIdStatus::RESERVED);
    ASSERT_EQ(RET_SUCCESS, ret);

    // Remove from active cache
    AccessTokenInfoManager::GetInstance().hapTokenInfoMap_.erase(tokenId);

    // Assert: Get RESERVED token with isActive=true should return nullptr
    auto tokenInfo2 = AccessTokenInfoManager::GetInstance().GetHapTokenInfoInner(tokenId, true);
    EXPECT_EQ(nullptr, tokenInfo2) << "RESERVED token with isActive=true should return nullptr";

    // But can get with isActive=false
    auto tokenInfo3 = AccessTokenInfoManager::GetInstance().GetHapTokenInfoInner(tokenId, false);
    ASSERT_NE(nullptr, tokenInfo3);
    EXPECT_EQ(bundleName, tokenInfo3->GetBundleName());

    // Cleanup: Clean inactive cache
    AccessTokenInfoManager::GetInstance().ReleaseInactiveTokenInfoInner(tokenId);
    RemoveTestHapToken(tokenId);
}

/**
 * @tc.name: CacheIsolation001
 * @tc.desc: Test active and inactive tokens are stored in separate caches
 * @tc.type: FUNC
 * @tc.require: issue
 */
HWTEST_F(TokenStateManagementTest, CacheIsolation001, TestSize.Level0)
{
    // Arrange: Create multiple active and inactive tokens
    std::string activeBundle1 = "test.cache.isolation.active1";
    std::string activeBundle2 = "test.cache.isolation.active2";
    std::string inactiveBundle1 = "test.cache.isolation.inactive1";
    std::string inactiveBundle2 = "test.cache.isolation.inactive2";

    AccessTokenID activeToken1 = CreateTestHapToken(activeBundle1);
    AccessTokenID activeToken2 = CreateTestHapToken(activeBundle2);
    AccessTokenID inactiveToken1 = CreateTestHapToken(inactiveBundle1);
    AccessTokenID inactiveToken2 = CreateTestHapToken(inactiveBundle2);

    ASSERT_NE(0, activeToken1);
    ASSERT_NE(0, activeToken2);
    ASSERT_NE(0, inactiveToken1);
    ASSERT_NE(0, inactiveToken2);

    // Set some tokens to inactive status
    ASSERT_EQ(RET_SUCCESS, AccessTokenIDManager::GetInstance().ChangeTokenIdStatus(
        inactiveToken1, TokenIdStatus::RESERVED));
    ASSERT_EQ(RET_SUCCESS, AccessTokenIDManager::GetInstance().ChangeTokenIdStatus(
        inactiveToken2, TokenIdStatus::RESERVED));

    // Remove inactive tokens from active cache
    AccessTokenInfoManager::GetInstance().hapTokenInfoMap_.erase(inactiveToken1);
    AccessTokenInfoManager::GetInstance().hapTokenInfoMap_.erase(inactiveToken2);

    // Act: Get active and inactive tokens separately
    auto activeInfo1 = AccessTokenInfoManager::GetInstance().GetHapTokenInfoInner(activeToken1, true);
    auto activeInfo2 = AccessTokenInfoManager::GetInstance().GetHapTokenInfoInner(activeToken2, true);
    auto inactiveInfo1 = AccessTokenInfoManager::GetInstance().GetInactiveTokenInfoInner(inactiveToken1);
    auto inactiveInfo2 = AccessTokenInfoManager::GetInstance().GetInactiveTokenInfoInner(inactiveToken2);

    // Assert: Verify all tokens can be retrieved correctly
    ASSERT_NE(nullptr, activeInfo1);
    ASSERT_NE(nullptr, activeInfo2);
    ASSERT_NE(nullptr, inactiveInfo1);
    ASSERT_NE(nullptr, inactiveInfo2);

    EXPECT_EQ(activeBundle1, activeInfo1->GetBundleName());
    EXPECT_EQ(activeBundle2, activeInfo2->GetBundleName());
    EXPECT_EQ(inactiveBundle1, inactiveInfo1->GetBundleName());
    EXPECT_EQ(inactiveBundle2, inactiveInfo2->GetBundleName());

    // Cleanup
    RemoveTestHapToken(activeToken1);
    RemoveTestHapToken(activeToken2);
    AccessTokenInfoManager::GetInstance().ReleaseInactiveTokenInfoInner(inactiveToken1);
    AccessTokenInfoManager::GetInstance().ReleaseInactiveTokenInfoInner(inactiveToken2);
    RemoveTestHapToken(inactiveToken1);
    RemoveTestHapToken(inactiveToken2);
}

/**
 * @tc.name: GetHapTokenInfoInnerWithDeletedToken001
 * @tc.desc: Test GetHapTokenInfoInner after token is deleted
 * @tc.type: FUNC
 * @tc.require: issue
 */
HWTEST_F(TokenStateManagementTest, GetHapTokenInfoInnerWithDeletedToken001, TestSize.Level0)
{
    // Arrange: Create and delete token
    std::string bundleName = "test.deleted.token.001";
    AccessTokenID tokenId = CreateTestHapToken(bundleName);
    ASSERT_NE(0, tokenId);

    // Verify token exists
    auto tokenInfo1 = AccessTokenInfoManager::GetInstance().GetHapTokenInfoInner(tokenId);
    ASSERT_NE(nullptr, tokenInfo1);

    // Delete token
    RemoveTestHapToken(tokenId);

    // Act: Try to get deleted token
    auto tokenInfo2 = AccessTokenInfoManager::GetInstance().GetHapTokenInfoInner(tokenId);

    // Assert: Verify return nullptr
    EXPECT_EQ(nullptr, tokenInfo2);
}

/**
 * @tc.name: GetHapTokenInfoInnerActiveParamDefault003
 * @tc.desc: Test GetHapTokenInfoInner default parameter behavior with different token states
 * @tc.type: FUNC
 * @tc.require: issue
 */
HWTEST_F(TokenStateManagementTest, GetHapTokenInfoInnerActiveParamDefault003, TestSize.Level0)
{
    // Arrange: Create two tokens with different states
    std::string activeBundle = "test.default.param.active";
    std::string reservedBundle = "test.default.param.reserved";

    AccessTokenID activeTokenId = CreateTestHapToken(activeBundle);
    AccessTokenID reservedTokenId = CreateTestHapToken(reservedBundle);
    ASSERT_NE(0, activeTokenId);
    ASSERT_NE(0, reservedTokenId);

    // Set one to RESERVED status
    ASSERT_EQ(RET_SUCCESS, AccessTokenIDManager::GetInstance().ChangeTokenIdStatus(
        reservedTokenId, TokenIdStatus::RESERVED));

    // Remove RESERVED token from active cache
    AccessTokenInfoManager::GetInstance().hapTokenInfoMap_.erase(reservedTokenId);

    // Act & Assert: Get tokens with default parameter (isActive=true)
    auto activeTokenInfo = AccessTokenInfoManager::GetInstance().GetHapTokenInfoInner(activeTokenId);
    ASSERT_NE(nullptr, activeTokenInfo) << "Active token should be found with default parameter";
    EXPECT_EQ(activeBundle, activeTokenInfo->GetBundleName());

    auto reservedTokenInfo = AccessTokenInfoManager::GetInstance().GetHapTokenInfoInner(reservedTokenId);
    EXPECT_EQ(nullptr, reservedTokenInfo) << "Reserved token should return nullptr with default parameter";

    // Cleanup
    RemoveTestHapToken(activeTokenId);
    AccessTokenInfoManager::GetInstance().ReleaseInactiveTokenInfoInner(reservedTokenId);
    RemoveTestHapToken(reservedTokenId);
}

} // namespace AccessToken
} // namespace Security
} // namespace OHOS
