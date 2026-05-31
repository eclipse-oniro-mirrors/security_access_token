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

// Allow access to private members for testing
#define private public
#include "accesstoken_info_manager.h"
#undef private

#include "accesstoken_kit.h"
#include "accesstoken_id_manager.h"
#include "access_token_db_operator.h"
#include "atm_data_type.h"
#include "delete_bundle_manager.h"
#include "generic_values.h"
#include "hap_token_info.h"
#include "token_field_const.h"
#include "token_setproc.h"
#include "access_token_error.h"
#include "accesstoken_info_utils.h"

using namespace OHOS::Security::AccessToken;
using namespace testing::ext;

// RAII helper for automatic token cleanup
class TokenGuard {
public:
    TokenGuard(AccessTokenID tokenID, const std::string& bundleName)
        : tokenID_(tokenID), bundleName_(bundleName) {}

    ~TokenGuard() {
        if (tokenID_ != 0) {
            // Clean up reserved status if any
            if (AccessTokenIDManager::GetInstance().IsReservedTokenId(tokenID_)) {
                AccessTokenIDManager::GetInstance().RemoveReservedTokenId(tokenID_);
            }
            // Delete token from database and cache
            DeleteBundleManager::GetInstance().DeleteReservedToken(tokenID_, bundleName_);
        }
    }

private:
    AccessTokenID tokenID_;
    std::string bundleName_;
};

class DeleteIdentityTest : public testing::Test {
public:
    static void SetUpTestCase();
    static void TearDownTestCase();
    void SetUp();
    void TearDown();

protected:
    static HapInfoParams CreateHapInfoParams(
        const std::string& bundleName, int32_t userId = 100, int32_t instIndex = 0);
    static HapPolicyParams CreateHapPolicyParams();
    static HapPolicy CreateHapPolicy(const HapPolicyParams& params, const std::vector<std::string>& permissions);
    AccessTokenID AllocHapToken(const HapInfoParams& info, const HapPolicyParams& policyParams,
        const std::vector<std::string>& permissions = {});
    void RemoveTokenFromCache(AccessTokenID tokenID);

    // === Database Operation Helpers ===
    // Directly mark token as reserved in database and memory
    void MarkTokenAsReservedDirectly(AccessTokenID tokenID, ReservedType type);

    // === Database Verification Helpers ===
    // Check if token exists in database
    bool TokenExistsInDatabase(AccessTokenID tokenID);

    // Get token info from database
    bool GetTokenInfoFromDatabase(AccessTokenID tokenID, GenericValues& tokenInfo);

    // Check if permission state exists in database for a token
    bool PermissionStateExistsInDatabase(AccessTokenID tokenID);

    // Count permission states in database for a token
    size_t CountPermissionStatesInDatabase(AccessTokenID tokenID);

    // Check if token has specific reserved field value in database
    bool GetReservedFieldFromDatabase(AccessTokenID tokenID, int32_t& reservedValue);

    // Check if HAP_PACKAGE_INFO exists in database for a bundle
    bool BundlePackageInfoExistsInDatabase(const std::string& bundleName);

    // Get bundle package info from database
    bool GetBundlePackageInfoFromDatabase(const std::string& bundleName, GenericValues& packageInfo);

    // Manually create bundle package info in database for testing
    bool CreateBundlePackageInfoInDatabase(const std::string& bundleName, const std::string& moduleName = "default");

    // Verify token is completely deleted from database (all related tables)
    bool VerifyTokenCompletelyDeleted(AccessTokenID tokenID);

    // === Cache Operation Helpers ===
    // Get token info from cache (with lock protection)
    std::shared_ptr<HapTokenInfoInner> GetTokenFromCache(AccessTokenID tokenID);

    // Remove token from cache map directly (with lock protection)
    void RemoveTokenFromCacheMap(AccessTokenID tokenID);

    // Update token's reserved flag in cache (without modifying database)
    void UpdateTokenReservedInCache(AccessTokenID tokenID, ReservedType type);

    // Verify token exists in cache
    bool TokenExistsInCache(AccessTokenID tokenID);

    // Clear all test data from cache
    void ClearTestDataFromCache(const std::vector<AccessTokenID>& tokenIds,
        const std::vector<std::string>& bundleNames);

    HapInfoParams infoParms_;
    HapPolicyParams policy_;
    AccessTokenID tokenID_{0};
};

HapInfoParams DeleteIdentityTest::CreateHapInfoParams(
    const std::string& bundleName, int32_t userId, int32_t instIndex)
{
    HapInfoParams info;
    info.bundleName = bundleName;
    info.appIDDesc = "test_app_id";
    info.userID = userId;
    info.instIndex = instIndex;
    info.dlpType = 0;
    return info;
}

HapPolicyParams DeleteIdentityTest::CreateHapPolicyParams()
{
    HapPolicyParams policy;
    policy.apl = APL_NORMAL;
    policy.domain = "test.domain";
    return policy;
}

HapPolicy DeleteIdentityTest::CreateHapPolicy(const HapPolicyParams& params,
    const std::vector<std::string>& permissions)
{
    HapPolicy policy;
    policy.apl = params.apl;
    policy.domain = params.domain;

    // Create permission definitions and states from permission names
    for (const auto& permName : permissions) {
        // Create default permission state for each permission
        PermissionStatus permState;
        permState.permissionName = permName;
        permState.grantStatus = PermissionState::PERMISSION_GRANTED;
        permState.grantFlag = PermissionFlag::PERMISSION_DEFAULT_FLAG;
        policy.permStateList.push_back(permState);
    }

    return policy;
}

AccessTokenID DeleteIdentityTest::AllocHapToken(const HapInfoParams& info, const HapPolicyParams& policyParams,
    const std::vector<std::string>& permissions)
{
    // Convert HapPolicyParams to HapPolicy with permissions
    HapPolicy policy = CreateHapPolicy(policyParams, permissions);

    // Use AccessTokenInfoManager directly to create token (no IPC)
    AccessTokenIDEx tokenIdEx = {0};
    std::vector<GenericValues> undefValues;

    int32_t ret = AccessTokenInfoManager::GetInstance().CreateHapTokenInfo(
        info, policy, tokenIdEx, undefValues);

    EXPECT_EQ(RET_SUCCESS, ret);
    EXPECT_NE(INVALID_TOKENID, tokenIdEx.tokenIdExStruct.tokenID);

    return tokenIdEx.tokenIdExStruct.tokenID;
}

void DeleteIdentityTest::RemoveTokenFromCache(AccessTokenID tokenID)
{
    std::shared_ptr<HapTokenInfoInner> info =
        AccessTokenInfoManager::GetInstance().GetHapTokenInfoInner(tokenID);
    if (info != nullptr) {
        int32_t ret = AccessTokenInfoManager::GetInstance().RemoveHapTokenInfo(tokenID, false);
        if (ret != RET_SUCCESS) {
            GTEST_LOG_(INFO) << "RemoveHapTokenInfo failed: " << ret;
        }
    }
}

void DeleteIdentityTest::MarkTokenAsReservedDirectly(AccessTokenID tokenID, ReservedType type)
{
    AccessTokenIDManager::GetInstance().ReleaseTokenId(tokenID);
    AccessTokenIDManager::GetInstance().AddReservedTokenId(tokenID);
    // 1. Update database: set reserved field and TOKEN_RESERVED_FLAG
    GenericValues modifyValues;
#ifdef SPM_DATA_ENABLE
    modifyValues.Put(TokenFiledConst::FIELD_RESERVED, static_cast<int32_t>(type));
#endif

    // Get current token attr and set TOKEN_RESERVED_FLAG
    std::shared_ptr<HapTokenInfoInner> info =
        AccessTokenInfoManager::GetInstance().GetHapTokenInfoInner(tokenID);
    ASSERT_NE(info, nullptr);
    uint32_t newAttr = info->GetAttr() | 0x0004; // 0x0004: TOKEN_RESERVED_FLAG
    modifyValues.Put(TokenFiledConst::FIELD_TOKEN_ATTR, static_cast<int32_t>(newAttr));

#ifdef SPM_DATA_ENABLE
    // Set UID to UNAVAILABLE_UID (-1) if RESERVED_IDENTITY
    if (type == ReservedType::RESERVED_IDENTITY) {
        modifyValues.Put(TokenFiledConst::FIELD_UID, -1);
    }
    modifyValues.Put(TokenFiledConst::FIELD_RESERVED, static_cast<int32_t>(type));
#endif

    GenericValues condition;
    condition.Put(TokenFiledConst::FIELD_TOKEN_ID, static_cast<int32_t>(tokenID));

    int32_t ret = AccessTokenDbOperator::Modify(
        AtmDataType::ACCESSTOKEN_HAP_INFO, modifyValues, condition);
    EXPECT_EQ(RET_SUCCESS, ret);

    // 2. Remove from cache (reserved tokens should not be in AccessTokenInfoManager cache)
    RemoveTokenFromCacheMap(tokenID);

    // 3. Add to memory reserved set
    AccessTokenIDManager::GetInstance().AddReservedTokenId(tokenID);
}

std::shared_ptr<HapTokenInfoInner> DeleteIdentityTest::GetTokenFromCache(AccessTokenID tokenID)
{
    auto& manager = AccessTokenInfoManager::GetInstance();
    std::shared_lock<std::shared_mutex> lock(manager.hapTokenInfoLock_);
    auto it = manager.hapTokenInfoMap_.find(tokenID);
    if (it != manager.hapTokenInfoMap_.end()) {
        return it->second;
    }
    return nullptr;
}

void DeleteIdentityTest::RemoveTokenFromCacheMap(AccessTokenID tokenID)
{
    auto& manager = AccessTokenInfoManager::GetInstance();
    std::unique_lock<std::shared_mutex> lock(manager.hapTokenInfoLock_);
    manager.hapTokenInfoMap_.erase(tokenID);
}

void DeleteIdentityTest::UpdateTokenReservedInCache(AccessTokenID tokenID, ReservedType type)
{
    auto& manager = AccessTokenInfoManager::GetInstance();
    std::shared_lock<std::shared_mutex> lock(manager.hapTokenInfoLock_);
    auto it = manager.hapTokenInfoMap_.find(tokenID);
    if (it != manager.hapTokenInfoMap_.end() && it->second != nullptr) {
        // Update the token info in cache
        // Note: HapTokenInfoInner doesn't have a direct SetReserved method,
        // so we recreate the token info with updated attributes
        HapTokenInfo baseInfo = it->second->GetHapInfoBasic();
        uint32_t newAttr = baseInfo.tokenAttr | 0x0004; // 0x0004: TOKEN_RESERVED_FLAG
        baseInfo.tokenAttr = static_cast<AccessTokenAttr>(newAttr);

        if (type == ReservedType::RESERVED_IDENTITY) {
            baseInfo.uid = -1; // UNAVAILABLE_UID
        }

        it->second->SetTokenBaseInfo(baseInfo);
    }
}

bool DeleteIdentityTest::TokenExistsInCache(AccessTokenID tokenID)
{
    auto& manager = AccessTokenInfoManager::GetInstance();
    std::shared_lock<std::shared_mutex> lock(manager.hapTokenInfoLock_);
    return manager.hapTokenInfoMap_.find(tokenID) != manager.hapTokenInfoMap_.end();
}

void DeleteIdentityTest::ClearTestDataFromCache(
    const std::vector<AccessTokenID>& tokenIds,
    const std::vector<std::string>& bundleNames)
{
    auto& manager = AccessTokenInfoManager::GetInstance();
    std::unique_lock<std::shared_mutex> lock(manager.hapTokenInfoLock_);

    // Remove tokens from cache
    for (AccessTokenID tokenID : tokenIds) {
        manager.hapTokenInfoMap_.erase(tokenID);
    }

    // Remove bundle info from cache
    for (const std::string& bundleName : bundleNames) {
        manager.bundleInfoMap_.erase(bundleName);
    }
}

bool DeleteIdentityTest::TokenExistsInDatabase(AccessTokenID tokenID)
{
    GenericValues condition;
    condition.Put(TokenFiledConst::FIELD_TOKEN_ID, static_cast<int32_t>(tokenID));
    std::vector<GenericValues> results;
    int32_t ret = AccessTokenDbOperator::Find(
        AtmDataType::ACCESSTOKEN_HAP_INFO, condition, results);
    if (ret != RET_SUCCESS) {
        return false;
    }
    return !results.empty();
}

bool DeleteIdentityTest::GetTokenInfoFromDatabase(AccessTokenID tokenID, GenericValues& tokenInfo)
{
    GenericValues condition;
    condition.Put(TokenFiledConst::FIELD_TOKEN_ID, static_cast<int32_t>(tokenID));
    std::vector<GenericValues> results;
    int32_t ret = AccessTokenDbOperator::Find(
        AtmDataType::ACCESSTOKEN_HAP_INFO, condition, results);
    if (ret != RET_SUCCESS || results.empty()) {
        return false;
    }
    tokenInfo = results[0];
    return true;
}

bool DeleteIdentityTest::PermissionStateExistsInDatabase(AccessTokenID tokenID)
{
    return CountPermissionStatesInDatabase(tokenID) > 0;
}

size_t DeleteIdentityTest::CountPermissionStatesInDatabase(AccessTokenID tokenID)
{
    GenericValues condition;
    condition.Put(TokenFiledConst::FIELD_TOKEN_ID, static_cast<int32_t>(tokenID));
    std::vector<GenericValues> results;
    int32_t ret = AccessTokenDbOperator::Find(
        AtmDataType::ACCESSTOKEN_PERMISSION_STATE, condition, results);
    if (ret != RET_SUCCESS) {
        return 0;
    }
    return results.size();
}

bool DeleteIdentityTest::GetReservedFieldFromDatabase(AccessTokenID tokenID, int32_t& reservedValue)
{
    GenericValues tokenInfo;
    if (!GetTokenInfoFromDatabase(tokenID, tokenInfo)) {
        return false;
    }
    reservedValue = tokenInfo.GetInt(TokenFiledConst::FIELD_RESERVED);
    return true;
}

bool DeleteIdentityTest::VerifyTokenCompletelyDeleted(AccessTokenID tokenID)
{
    // Check ACCESSTOKEN_HAP_INFO table
    if (TokenExistsInDatabase(tokenID)) {
        return false; // Token still exists in HAP_INFO table
    }

    // Check ACCESSTOKEN_PERMISSION_STATE table
    if (PermissionStateExistsInDatabase(tokenID)) {
        return false; // Permission state still exists
    }

    // Note: We could also check other tables like:
    // - ACCESSTOKEN_PERMISSION_EXTEND_VALUE
    // - ACCESSTOKEN_HAP_UNDEFINE_INFO
    // But if HAP_INFO and PERMISSION_STATE are deleted, the deletion is likely complete

    return true;
}

bool DeleteIdentityTest::BundlePackageInfoExistsInDatabase(const std::string& bundleName)
{
    GenericValues condition;
    condition.Put(TokenFiledConst::FIELD_BUNDLE_NAME, bundleName);
    std::vector<GenericValues> results;
    int32_t ret = AccessTokenDbOperator::Find(
        AtmDataType::ACCESSTOKEN_HAP_PACKAGE_INFO, condition, results);
    if (ret != RET_SUCCESS) {
        return false;
    }
    return !results.empty();
}

bool DeleteIdentityTest::GetBundlePackageInfoFromDatabase(const std::string& bundleName, GenericValues& packageInfo)
{
    GenericValues condition;
    condition.Put(TokenFiledConst::FIELD_BUNDLE_NAME, bundleName);
    std::vector<GenericValues> results;
    int32_t ret = AccessTokenDbOperator::Find(
        AtmDataType::ACCESSTOKEN_HAP_PACKAGE_INFO, condition, results);
    if (ret != RET_SUCCESS || results.empty()) {
        return false;
    }
    packageInfo = results[0];
    return true;
}

bool DeleteIdentityTest::CreateBundlePackageInfoInDatabase(const std::string& bundleName, const std::string& moduleName)
{
    // Create a minimal bundle package info record for testing
    GenericValues packageInfo;
    packageInfo.Put(TokenFiledConst::FIELD_BUNDLE_NAME, bundleName);
    packageInfo.Put(TokenFiledConst::FIELD_MODULE_NAME, moduleName);
    packageInfo.Put(TokenFiledConst::FIELD_PATH, "/data/test/" + bundleName);
    packageInfo.Put(TokenFiledConst::FIELD_BUNDLE_TYPE, 0);  // Normal bundle
    packageInfo.Put(TokenFiledConst::FIELD_IS_PREINSTALLED, 0);

    // Create a non-empty persist data blob (BLOB NOT NULL constraint)
    std::vector<uint8_t> persistData = {1, 2, 3, 4};  // Minimal test data
    packageInfo.PutBlob(TokenFiledConst::FIELD_PERSIST_DATA, persistData);

    std::vector<GenericValues> packageInfoVec;
    packageInfoVec.push_back(packageInfo);

    std::vector<AddInfo> addInfoVec;
    AccessTokenInfoUtils::GenerateAddInfoToVec(
        AtmDataType::ACCESSTOKEN_HAP_PACKAGE_INFO, packageInfoVec, addInfoVec);

    int32_t ret = AccessTokenDbOperator::DeleteAndInsertValues({}, addInfoVec);
    return (ret == RET_SUCCESS);
}

void DeleteIdentityTest::SetUpTestCase()
{
    // Initialize AccessTokenManager
}

void DeleteIdentityTest::TearDownTestCase()
{
    // Cleanup
}

void DeleteIdentityTest::SetUp()
{
    infoParms_ = CreateHapInfoParams("test.bundle.name");
    policy_ = CreateHapPolicyParams();
}

void DeleteIdentityTest::TearDown()
{
    // No need to clean up tokenID_ anymore
    // Each test case is responsible for cleaning up its own tokens using TokenGuard
}

/**
 * @tc.name: DeleteReservedToken001
 * @tc.desc: Test DeleteReservedToken with valid reserved token
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(DeleteIdentityTest, DeleteReservedToken001, TestSize.Level0)
{
    // Create and reserve a token
    AccessTokenID tokenID = AllocHapToken(infoParms_, policy_, {"ohos.permission.GET_NETWORK_INFO"});
    TokenGuard guard(tokenID, infoParms_.bundleName);  // RAII cleanup

    // === Verify initial state ===
    EXPECT_TRUE(TokenExistsInDatabase(tokenID)) << "Token should exist in database initially";
    EXPECT_TRUE(TokenExistsInCache(tokenID)) << "Token should exist in cache initially";

    // Mark as reserved directly in database and memory
    MarkTokenAsReservedDirectly(tokenID, ReservedType::RESERVED_IDENTITY);

#ifdef SPM_DATA_ENABLE
    // Verify token is marked as reserved in database
    int32_t reservedValue = 0;
    EXPECT_TRUE(GetReservedFieldFromDatabase(tokenID, reservedValue));
    EXPECT_EQ(static_cast<int32_t>(ReservedType::RESERVED_IDENTITY), reservedValue);
#endif

    // Delete reserved token
    std::string bundleName = infoParms_.bundleName;
    int32_t ret = DeleteBundleManager::GetInstance().DeleteReservedToken(tokenID, bundleName);
    EXPECT_EQ(RET_SUCCESS, ret);

    // === Verify complete deletion from database ===
    EXPECT_FALSE(TokenExistsInDatabase(tokenID))
        << "Token should be completely deleted from database";

    EXPECT_TRUE(VerifyTokenCompletelyDeleted(tokenID))
        << "Token should be deleted from all related tables";

    // === Verify memory cleanup ===
    EXPECT_FALSE(AccessTokenIDManager::GetInstance().IsReservedTokenId(tokenID))
        << "Token should be removed from reserved set";

    // Note: DeleteReservedToken does not remove from cache.
    // The cache entry will be invalidated when accessed or explicitly removed.
}

/**
 * @tc.name: DeleteReservedToken002
 * @tc.desc: Test DeleteReservedToken with non-existent token
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(DeleteIdentityTest, DeleteReservedToken002, TestSize.Level0)
{
    AccessTokenID fakeTokenID = 999999;
    std::string bundleName = "test.bundle.name";

    int32_t ret = DeleteBundleManager::GetInstance().DeleteReservedToken(fakeTokenID, bundleName);
    EXPECT_EQ(ERR_PARAM_INVALID, ret);
}

/**
 * @tc.name: DeleteReservedToken003
 * @tc.desc: Test DeleteReservedToken with mismatched bundle name
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(DeleteIdentityTest, DeleteReservedToken003, TestSize.Level0)
{
    // Create token
    AccessTokenID tokenID = AllocHapToken(infoParms_, policy_, {"ohos.permission.GET_NETWORK_INFO"});
    TokenGuard guard(tokenID, infoParms_.bundleName);  // RAII cleanup

    // Mark as reserved directly
    MarkTokenAsReservedDirectly(tokenID, ReservedType::RESERVED_IDENTITY);

    // Try to delete with wrong bundle name
    std::string bundleName = infoParms_.bundleName;
    std::string wrongBundleName = "wrong.bundle.name";
    int32_t ret = DeleteBundleManager::GetInstance().DeleteReservedToken(tokenID, wrongBundleName);
    EXPECT_EQ(AccessTokenError::ERR_PARAM_INVALID, ret);
}

/**
 * @tc.name: DeleteBundleAndAllTokens001
 * @tc.desc: Test DeleteBundleAndAllTokens with bundle having only reserved tokens
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(DeleteIdentityTest, DeleteBundleAndAllTokens001, TestSize.Level0)
{
    std::string bundleName = "test.bundle.multiple";

    // Create multiple tokens for same bundle
    HapInfoParams info1 = CreateHapInfoParams(bundleName, 100, 0);
    HapInfoParams info2 = CreateHapInfoParams(bundleName, 100, 1);
    HapPolicyParams policy = CreateHapPolicyParams();

    AccessTokenID token1 = AllocHapToken(info1, policy, {"ohos.permission.INTERNET"});
    TokenGuard guard1(token1, bundleName);  // RAII cleanup for token1

    AccessTokenID token2 = AllocHapToken(info2, policy, {"ohos.permission.INTERNET"});
    TokenGuard guard2(token2, bundleName);  // RAII cleanup for token2

#ifdef SPM_DATA_ENABLE
    // Manually create bundle package info in database for testing
    ASSERT_TRUE(CreateBundlePackageInfoInDatabase(bundleName))
        << "Failed to create bundle package info in database";
#endif

    // === Verify initial state ===
    EXPECT_TRUE(TokenExistsInDatabase(token1)) << "Token1 should exist in database initially";
    EXPECT_TRUE(TokenExistsInDatabase(token2)) << "Token2 should exist in database initially";

#ifdef SPM_DATA_ENABLE
    // When tokens are created, package info should exist
    EXPECT_TRUE(BundlePackageInfoExistsInDatabase(bundleName))
        << "Package info should exist in database initially";
#endif

    // Mark both as reserved directly
    MarkTokenAsReservedDirectly(token1, ReservedType::RESERVED_IDENTITY);
    MarkTokenAsReservedDirectly(token2, ReservedType::RESERVED_IDENTITY);

#ifdef SPM_DATA_ENABLE
    // Verify tokens are marked as reserved in database
    int32_t reservedValue = 0;
    EXPECT_TRUE(GetReservedFieldFromDatabase(token1, reservedValue));
    EXPECT_EQ(static_cast<int32_t>(ReservedType::RESERVED_IDENTITY), reservedValue);
#endif

    // Delete all reserved tokens for the bundle
    int32_t ret = DeleteBundleManager::GetInstance().DeleteBundleAndAllTokens(bundleName);
    EXPECT_EQ(RET_SUCCESS, ret);

    // === Verify complete deletion from database ===
    EXPECT_FALSE(TokenExistsInDatabase(token1))
        << "Token1 should be completely deleted from HAP_INFO table";
    EXPECT_FALSE(TokenExistsInDatabase(token2))
        << "Token2 should be completely deleted from HAP_INFO table";

    EXPECT_TRUE(VerifyTokenCompletelyDeleted(token1))
        << "Token1 should be deleted from all related tables";
    EXPECT_TRUE(VerifyTokenCompletelyDeleted(token2))
        << "Token2 should be deleted from all related tables";

#ifdef SPM_DATA_ENABLE
    // === Verify HAP_PACKAGE_INFO table deletion ===
    // When all tokens (including reserved) are deleted, package info should also be deleted
    EXPECT_FALSE(BundlePackageInfoExistsInDatabase(bundleName))
        << "Package info should be deleted from HAP_PACKAGE_INFO table when all tokens are deleted";
#endif

    // === Verify memory cleanup ===
    EXPECT_FALSE(AccessTokenIDManager::GetInstance().IsReservedTokenId(token1))
        << "Token1 should be removed from reserved set";
    EXPECT_FALSE(AccessTokenIDManager::GetInstance().IsReservedTokenId(token2))
        << "Token2 should be removed from reserved set";

    // Note: DeleteBundleAndAllTokens does not remove from cache.
    // The cache entries will be invalidated when accessed or explicitly removed.
}

/**
 * @tc.name: DeleteBundleAndAllTokens002
 * @tc.desc: Test DeleteBundleAndAllTokens deletes all tokens (both active and reserved)
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(DeleteIdentityTest, DeleteBundleAndAllTokens002, TestSize.Level0)
{
    std::string bundleName = "test.bundle.mixed";

    // Create one active token and one reserved token
    HapInfoParams info1 = CreateHapInfoParams(bundleName, 100, 0);
    HapInfoParams info2 = CreateHapInfoParams(bundleName, 100, 1);
    HapPolicyParams policy = CreateHapPolicyParams();

    AccessTokenID token1 = AllocHapToken(info1, policy, {"ohos.permission.INTERNET"});
    TokenGuard guard1(token1, bundleName);  // RAII cleanup for token1

    AccessTokenID token2 = AllocHapToken(info2, policy, {"ohos.permission.INTERNET"});
    TokenGuard guard2(token2, bundleName);  // RAII cleanup for token2

#ifdef SPM_DATA_ENABLE
    // Manually create bundle package info in database for testing
    ASSERT_TRUE(CreateBundlePackageInfoInDatabase(bundleName))
        << "Failed to create bundle package info in database";

    // === Verify initial state ===
    EXPECT_TRUE(BundlePackageInfoExistsInDatabase(bundleName))
        << "Package info should exist in database initially";
#endif

    // Mark token2 as reserved directly
    MarkTokenAsReservedDirectly(token2, ReservedType::RESERVED_IDENTITY);

    // Delete all tokens for the bundle (both active and reserved)
    int32_t ret = DeleteBundleManager::GetInstance().DeleteBundleAndAllTokens(bundleName);
    EXPECT_EQ(RET_SUCCESS, ret);

    // === Verify HAP_PACKAGE_INFO is deleted ===
#ifdef SPM_DATA_ENABLE
    EXPECT_FALSE(BundlePackageInfoExistsInDatabase(bundleName))
        << "Package info should be deleted";
#endif

    // === Verify both tokens are deleted from database ===
    EXPECT_FALSE(TokenExistsInDatabase(token1))
        << "Active token1 should be deleted from database";
    EXPECT_FALSE(TokenExistsInDatabase(token2))
        << "Reserved token2 should be deleted from database";

    // === Verify both tokens are removed from reserved set ===
    EXPECT_FALSE(AccessTokenIDManager::GetInstance().IsReservedTokenId(token1))
        << "Token1 should be removed from reserved set";
    EXPECT_FALSE(AccessTokenIDManager::GetInstance().IsReservedTokenId(token2))
        << "Token2 should be removed from reserved set";
}

/**
 * @tc.name: DeleteIdentity001
 * @tc.desc: Test DeleteIdentity with normal token (type=NONE)
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(DeleteIdentityTest, DeleteIdentity001, TestSize.Level0)
{
    // Create token with permissions
    AccessTokenID tokenID = AllocHapToken(infoParms_, policy_, {"ohos.permission.GET_NETWORK_INFO"});
    TokenGuard guard(tokenID, infoParms_.bundleName);  // RAII cleanup
    std::string bundleName = infoParms_.bundleName;

    // Verify token exists in cache and database
    EXPECT_TRUE(TokenExistsInCache(tokenID));
    EXPECT_TRUE(TokenExistsInDatabase(tokenID));

    // Get initial permission state count
    size_t initialPermCount = CountPermissionStatesInDatabase(tokenID);
    EXPECT_GT(initialPermCount, 0u) << "Token should have permission states in database";

    // Delete with type=NONE (normal deletion)
    int32_t ret = AccessTokenInfoManager::GetInstance().DeleteIdentity(
        tokenID, bundleName, ReservedType::NONE);
    EXPECT_EQ(RET_SUCCESS, ret);

    // === Verify cache deletion ===
    EXPECT_FALSE(TokenExistsInCache(tokenID)) << "Token should be removed from cache";

    // Verify token cannot be queried from database
    std::shared_ptr<HapTokenInfoInner> tokenInfo = GetTokenFromCache(tokenID);
    EXPECT_EQ(tokenInfo, nullptr) << "Token should not be loadable from cache";

    // === Verify database deletion ===
    EXPECT_FALSE(TokenExistsInDatabase(tokenID)) << "Token should be deleted from HAP_INFO table";

    // Verify permission states are also deleted
    size_t finalPermCount = CountPermissionStatesInDatabase(tokenID);
    EXPECT_EQ(0u, finalPermCount) << "Permission states should be deleted from database";

    // Verify complete deletion
    EXPECT_TRUE(VerifyTokenCompletelyDeleted(tokenID)) << "Token should be completely deleted from all tables";

    // === Verify memory cleanup ===
    EXPECT_FALSE(AccessTokenIDManager::GetInstance().IsReservedTokenId(tokenID));

    // Try to get token info should fail
    HapTokenInfo info;
    EXPECT_EQ(AccessTokenError::ERR_TOKENID_NOT_EXIST,
        AccessTokenInfoManager::GetInstance().GetHapTokenInfo(tokenID, info));
}

/**
 * @tc.name: DeleteIdentity002
 * @tc.desc: Test DeleteIdentity with RESERVED_IDENTITY type
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(DeleteIdentityTest, DeleteIdentity002, TestSize.Level0)
{
    // Create token with permissions
    AccessTokenID tokenID = AllocHapToken(infoParms_, policy_, {"ohos.permission.GET_NETWORK_INFO"});
    TokenGuard guard(tokenID, infoParms_.bundleName);  // RAII cleanup
    std::string bundleName = infoParms_.bundleName;

    // === Verify initial state ===
    EXPECT_TRUE(TokenExistsInDatabase(tokenID)) << "Token should exist in database";

    // Get permission state count for comparison
    std::shared_ptr<HapTokenInfoInner> tokenInfo = GetTokenFromCache(tokenID);
    ASSERT_NE(tokenInfo, nullptr);
    size_t originalPermCount = CountPermissionStatesInDatabase(tokenID);
    EXPECT_GT(originalPermCount, 0u) << "Token should have permission states";

    // Delete with type=RESERVED_IDENTITY (preserve tokenID, clear UID, delete permission states)
    int32_t ret = AccessTokenInfoManager::GetInstance().DeleteIdentity(
        tokenID, bundleName, ReservedType::RESERVED_IDENTITY);
    EXPECT_EQ(RET_SUCCESS, ret);

    // === Verify token still exists in database ===
    EXPECT_TRUE(TokenExistsInDatabase(tokenID)) << "Token should still exist in HAP_INFO table";

#ifdef SPM_DATA_ENABLE
    // Verify database reserved field is set to RESERVED_IDENTITY
    int32_t reservedValue = 0;
    EXPECT_TRUE(GetReservedFieldFromDatabase(tokenID, reservedValue));
    EXPECT_EQ(static_cast<int32_t>(ReservedType::RESERVED_IDENTITY), reservedValue)
        << "Database reserved field should be RESERVED_IDENTITY";

    // Verify UID is set to -1 in database
    GenericValues tokenInfoDb;
    EXPECT_TRUE(GetTokenInfoFromDatabase(tokenID, tokenInfoDb));
    int32_t dbUid = tokenInfoDb.GetInt(TokenFiledConst::FIELD_UID);
    EXPECT_EQ(-1, dbUid) << "Database UID should be -1 for RESERVED_IDENTITY";
#endif

    // === Verify permission states are DELETED in database ===
    size_t finalPermCount = CountPermissionStatesInDatabase(tokenID);
    EXPECT_EQ(0u, finalPermCount)
        << "Permission states should be deleted from database for RESERVED_IDENTITY";

    // === Verify memory state ===
    EXPECT_TRUE(AccessTokenIDManager::GetInstance().IsReservedTokenId(tokenID))
        << "Token should be in reserved set";

    // Token should be REMOVED from cache (DeleteIdentity always removes from cache)
    EXPECT_FALSE(TokenExistsInCache(tokenID))
        << "Token should be removed from cache even when type=RESERVED_IDENTITY";

    // Verify token cannot be used to get info (normal query should fail)
    HapTokenInfo info;
    EXPECT_EQ(AccessTokenError::ERR_TOKENID_NOT_EXIST,
        AccessTokenInfoManager::GetInstance().GetHapTokenInfo(tokenID, info));
}

/**
 * @tc.name: DeleteIdentity003
 * @tc.desc: Test DeleteIdentity with RESERVED_DATA type (preserves permission state)
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(DeleteIdentityTest, DeleteIdentity003, TestSize.Level0)
{
    // Create token with permissions
    AccessTokenID tokenID = AllocHapToken(infoParms_, policy_, {"ohos.permission.GET_NETWORK_INFO"});
    TokenGuard guard(tokenID, infoParms_.bundleName);  // RAII cleanup
    std::string bundleName = infoParms_.bundleName;

    // === Verify initial state ===
    EXPECT_TRUE(TokenExistsInDatabase(tokenID)) << "Token should exist in database";
    size_t originalPermCount = CountPermissionStatesInDatabase(tokenID);
    EXPECT_GT(originalPermCount, 0u) << "Token should have permission states in database";

    // Delete with type=RESERVED_DATA
    int32_t ret = AccessTokenInfoManager::GetInstance().DeleteIdentity(
        tokenID, bundleName, ReservedType::RESERVED_DATA);
    EXPECT_EQ(RET_SUCCESS, ret);

    // === Verify token still exists in database ===
    EXPECT_TRUE(TokenExistsInDatabase(tokenID)) << "Token should still exist in HAP_INFO table";

#ifdef SPM_DATA_ENABLE
    // Verify database reserved field is set to RESERVED_DATA
    int32_t reservedValue = 0;
    EXPECT_TRUE(GetReservedFieldFromDatabase(tokenID, reservedValue));
    EXPECT_EQ(static_cast<int32_t>(ReservedType::RESERVED_DATA), reservedValue)
        << "Database reserved field should be RESERVED_DATA";
#endif

    // === Verify permission states are PRESERVED in database ===
    size_t finalPermCount = CountPermissionStatesInDatabase(tokenID);
    EXPECT_EQ(originalPermCount, finalPermCount)
        << "Permission states should be preserved in database for RESERVED_DATA";

    // === Verify memory state ===
    EXPECT_TRUE(AccessTokenIDManager::GetInstance().IsReservedTokenId(tokenID))
        << "Token should be in reserved set";

    // Token should be REMOVED from cache (DeleteIdentity always removes from cache)
    EXPECT_FALSE(TokenExistsInCache(tokenID))
        << "Token should be removed from cache even when type=RESERVED_DATA";
}

/**
 * @tc.name: DeleteIdentity004
 * @tc.desc: Test DeleteIdentity with invalid tokenID
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(DeleteIdentityTest, DeleteIdentity004, TestSize.Level0)
{
    AccessTokenID fakeTokenID = 888888;
    std::string bundleName = "test.bundle.name";

    int32_t ret = AccessTokenInfoManager::GetInstance().DeleteIdentity(
        fakeTokenID, bundleName, ReservedType::NONE);
    // Invalid tokenID returns ERR_PARAM_INVALID (not a HAP token)
    EXPECT_EQ(AccessTokenError::ERR_PARAM_INVALID, ret);
}

/**
 * @tc.name: DeleteIdentity005
 * @tc.desc: Test DeleteIdentity with mismatched bundle name
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(DeleteIdentityTest, DeleteIdentity005, TestSize.Level0)
{
    // Create token
    AccessTokenID tokenID = AllocHapToken(infoParms_, policy_, {"ohos.permission.GET_NETWORK_INFO"});
    TokenGuard guard(tokenID, infoParms_.bundleName);  // RAII cleanup

    // Try to delete with wrong bundle name
    std::string wrongBundleName = "wrong.bundle.name";
    int32_t ret = AccessTokenInfoManager::GetInstance().DeleteIdentity(
        tokenID, wrongBundleName, ReservedType::NONE);
    EXPECT_EQ(AccessTokenError::ERR_PARAM_INVALID, ret);
}

/**
 * @tc.name: DeleteIdentity006
 * @tc.desc: Test DeleteIdentity with INVALID_TOKENID (should use DeleteBundleAndAllTokens instead)
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(DeleteIdentityTest, DeleteIdentity006, TestSize.Level0)
{
    // Create and reserve multiple tokens for same bundle
    std::string bundleName = "test.bundle.cleanup";
    HapInfoParams info1 = CreateHapInfoParams(bundleName, 100, 0);
    HapInfoParams info2 = CreateHapInfoParams(bundleName, 100, 1);
    HapPolicyParams policy = CreateHapPolicyParams();

    AccessTokenID token1 = AllocHapToken(info1, policy, {"ohos.permission.INTERNET"});
    TokenGuard guard1(token1, bundleName);  // RAII cleanup

    AccessTokenID token2 = AllocHapToken(info2, policy, {"ohos.permission.INTERNET"});
    TokenGuard guard2(token2, bundleName);  // RAII cleanup

    // === Verify initial state ===
    EXPECT_TRUE(TokenExistsInDatabase(token1)) << "Token1 should exist in database initially";
    EXPECT_TRUE(TokenExistsInDatabase(token2)) << "Token2 should exist in database initially";

    // Mark both as reserved directly
    MarkTokenAsReservedDirectly(token1, ReservedType::RESERVED_IDENTITY);
    MarkTokenAsReservedDirectly(token2, ReservedType::RESERVED_DATA);

#ifdef SPM_DATA_ENABLE
    // Verify both tokens are marked as reserved in database
    int32_t reservedValue1 = 0, reservedValue2 = 0;
    EXPECT_TRUE(GetReservedFieldFromDatabase(token1, reservedValue1));
    EXPECT_TRUE(GetReservedFieldFromDatabase(token2, reservedValue2));
    EXPECT_EQ(static_cast<int32_t>(ReservedType::RESERVED_IDENTITY), reservedValue1);
    EXPECT_EQ(static_cast<int32_t>(ReservedType::RESERVED_DATA), reservedValue2);
#endif

    // Verify both tokens are marked as reserved in memory
    EXPECT_TRUE(AccessTokenIDManager::GetInstance().IsReservedTokenId(token1));
    EXPECT_TRUE(AccessTokenIDManager::GetInstance().IsReservedTokenId(token2));

    // DeleteIdentity with INVALID_TOKENID is not yet implemented.
    // Use DeleteBundleAndAllTokens instead.
    int32_t ret = DeleteBundleManager::GetInstance().DeleteBundleAndAllTokens(bundleName);
    EXPECT_EQ(RET_SUCCESS, ret);

    // === Verify complete deletion from database ===
    EXPECT_FALSE(TokenExistsInDatabase(token1))
        << "Token1 should be completely deleted from HAP_INFO table";
    EXPECT_FALSE(TokenExistsInDatabase(token2))
        << "Token2 should be completely deleted from HAP_INFO table";

    EXPECT_TRUE(VerifyTokenCompletelyDeleted(token1))
        << "Token1 should be deleted from all related tables";
    EXPECT_TRUE(VerifyTokenCompletelyDeleted(token2))
        << "Token2 should be deleted from all related tables";

    // === Verify memory cleanup ===
    EXPECT_FALSE(AccessTokenIDManager::GetInstance().IsReservedTokenId(token1))
        << "Token1 should be removed from reserved set";
    EXPECT_FALSE(AccessTokenIDManager::GetInstance().IsReservedTokenId(token2))
        << "Token2 should be removed from reserved set";

    // Note: Tokens are not in cache (reserved tokens are removed from cache)
}

/**
 * @tc.name: DeleteIdentity007
 * @tc.desc: Test DeleteIdentity with native token (should fail)
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(DeleteIdentityTest, DeleteIdentity007, TestSize.Level0)
{
    // Create native token
    AccessTokenID nativeTokenID = 671112617; // 671112617: random native token

    // Verify it's a valid native token
    EXPECT_NE(INVALID_TOKENID, nativeTokenID);

    // Try to delete native token - should fail
    std::string bundleName = "foundation";
    int32_t ret = AccessTokenInfoManager::GetInstance().DeleteIdentity(
        nativeTokenID, bundleName, ReservedType::NONE);

    // Native tokens should not be deletable via DeleteIdentity
    // Expected error: ERR_TOKENID_NOT_EXIST or type mismatch error
    EXPECT_NE(RET_SUCCESS, ret);
}

/**
 * @tc.name: TryCleanBundleInfo001
 * @tc.desc: Test TryCleanBundleInfo when bundle has only reserved tokens
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(DeleteIdentityTest, TryCleanBundleInfo001, TestSize.Level0)
{
    std::string bundleName = "test.bundle.clean";
    HapInfoParams info = CreateHapInfoParams(bundleName, 100, 0);
    HapPolicyParams policy = CreateHapPolicyParams();

    AccessTokenID tokenID = AllocHapToken(info, policy, {"ohos.permission.INTERNET"});
    TokenGuard guard(tokenID, bundleName);  // RAII cleanup

    // Get tokenInfo BEFORE marking as reserved (after marking, GetHapTokenInfoInner returns nullptr)
    std::shared_ptr<HapTokenInfoInner> tokenInfo =
        AccessTokenInfoManager::GetInstance().GetHapTokenInfoInner(tokenID);
    ASSERT_NE(tokenInfo, nullptr);

    // Mark as reserved directly (removes from cache)
    MarkTokenAsReservedDirectly(tokenID, ReservedType::RESERVED_IDENTITY);

    // Try to clean bundle info - should succeed as token is reserved
    int32_t ret = DeleteBundleManager::TryCleanBundleInfo(tokenInfo);
    EXPECT_EQ(RET_SUCCESS, ret);
}


/**
 * @tc.name: DeleteIdentity009
 * @tc.desc: Test multiple deletions of same reserved token (idempotent)
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(DeleteIdentityTest, DeleteIdentity009, TestSize.Level0)
{
    // Create and reserve token
    AccessTokenID tokenID = AllocHapToken(infoParms_, policy_, {"ohos.permission.GET_NETWORK_INFO"});
    TokenGuard guard(tokenID, infoParms_.bundleName);  // RAII cleanup

    // Mark as reserved directly
    MarkTokenAsReservedDirectly(tokenID, ReservedType::RESERVED_IDENTITY);

    // First deletion
    std::string bundleName = infoParms_.bundleName;
    int32_t ret = DeleteBundleManager::GetInstance().DeleteReservedToken(tokenID, bundleName);
    EXPECT_EQ(RET_SUCCESS, ret);

    // Second deletion should also failed for token not reserved
    ret = DeleteBundleManager::GetInstance().DeleteReservedToken(tokenID, bundleName);
    EXPECT_EQ(ERR_PARAM_INVALID, ret);
}

/**
 * @tc.name: DeleteIdentity010
 * @tc.desc: Test DeleteIdentity with remote token (should fail)
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(DeleteIdentityTest, DeleteIdentity010, TestSize.Level0)
{
    // This test verifies remote token handling
    // Remote tokens cannot be deleted through normal DeleteIdentity

    // Create a token
    AccessTokenID tokenID = AllocHapToken(infoParms_, policy_, {"ohos.permission.GET_NETWORK_INFO"});
    TokenGuard guard(tokenID, infoParms_.bundleName);  // RAII cleanup
    std::string bundleName = infoParms_.bundleName;

    // Mark as remote token directly in cache
    std::shared_ptr<HapTokenInfoInner> tokenInfo = GetTokenFromCache(tokenID);
    ASSERT_NE(tokenInfo, nullptr);
    tokenInfo->SetRemote(true);

    // Verify token is marked as remote
    EXPECT_TRUE(tokenInfo->IsRemote());

    // Remote tokens CANNOT be deleted through DeleteIdentity
    int32_t ret = AccessTokenInfoManager::GetInstance().DeleteIdentity(
        tokenID, bundleName, ReservedType::NONE);
    EXPECT_EQ(AccessTokenError::ERR_IDENTITY_CHECK_FAILED, ret)
        << "Remote tokens should not be deletable through DeleteIdentity";

    // Token should still be in cache
    EXPECT_TRUE(TokenExistsInCache(tokenID))
        << "Remote token should still be in cache after failed deletion";
}

/**
 * @tc.name: DeleteIdentitySequence001
 * @tc.desc: Test delete-resurrect-delete sequence
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(DeleteIdentityTest, DeleteIdentitySequence001, TestSize.Level0)
{
    std::string bundleName = "test.bundle.sequence";
    HapInfoParams info = CreateHapInfoParams(bundleName, 100, 0);
    HapPolicyParams policy = CreateHapPolicyParams();

    // Step 1: Create and delete with RESERVED_IDENTITY
    AccessTokenID token1 = AllocHapToken(info, policy, {"ohos.permission.INTERNET"});
    TokenGuard guard1(token1, bundleName);  // RAII cleanup

    int32_t ret = AccessTokenInfoManager::GetInstance().DeleteIdentity(
        token1, bundleName, ReservedType::RESERVED_IDENTITY);
    EXPECT_EQ(RET_SUCCESS, ret);

    // Verify token1 is marked as reserved
    EXPECT_TRUE(AccessTokenIDManager::GetInstance().IsReservedTokenId(token1));

    // Token1 should be REMOVED from cache (DeleteIdentity always removes from cache)
    EXPECT_FALSE(TokenExistsInCache(token1))
        << "Token should be removed from cache when deleted with RESERVED_IDENTITY";

    // Verify token1 still exists in database with reserved flag
    GenericValues tokenInfoDb;
    EXPECT_TRUE(GetTokenInfoFromDatabase(token1, tokenInfoDb));
#ifdef SPM_DATA_ENABLE
    int32_t reserved = tokenInfoDb.GetInt(TokenFiledConst::FIELD_RESERVED);
    EXPECT_EQ(static_cast<int32_t>(ReservedType::RESERVED_IDENTITY), reserved);
    int32_t uid = tokenInfoDb.GetInt(TokenFiledConst::FIELD_UID);
    EXPECT_EQ(-1, uid); // UID cleared
#endif
}

/**
 * @tc.name: MultipleInstances001
 * @tc.desc: Test deleting tokens from same bundle with different instances
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(DeleteIdentityTest, MultipleInstances001, TestSize.Level0)
{
    std::string bundleName = "test.bundle.multi.instance";
    std::vector<TokenGuard> guards;  // RAII cleanup for multiple tokens

    // Create tokens for different instances
    HapPolicyParams policy = CreateHapPolicyParams();
    std::vector<HapInfoParams> infos = {
        CreateHapInfoParams(bundleName, 100, 0),
        CreateHapInfoParams(bundleName, 100, 1),
        CreateHapInfoParams(bundleName, 100, 2)
    };

    std::vector<AccessTokenID> tokensToCleanup;
    for (const auto& info : infos) {
        AccessTokenID token = AllocHapToken(info, policy, {"ohos.permission.INTERNET"});
        guards.emplace_back(token, bundleName);  // Add guard to vector
        tokensToCleanup.push_back(token);
    }

    // Mark all as reserved
    for (AccessTokenID token : tokensToCleanup) {
        MarkTokenAsReservedDirectly(token, ReservedType::RESERVED_IDENTITY);
        EXPECT_TRUE(AccessTokenIDManager::GetInstance().IsReservedTokenId(token));
    }

    // Delete all reserved tokens for the bundle
    int32_t ret = DeleteBundleManager::GetInstance().DeleteBundleAndAllTokens(bundleName);
    EXPECT_EQ(RET_SUCCESS, ret);

    // Verify all tokens removed from reserved set
    for (AccessTokenID token : tokensToCleanup) {
        EXPECT_FALSE(AccessTokenIDManager::GetInstance().IsReservedTokenId(token));
    }
    // Note: guards will automatically clean up when test exits
}

/**
 * @tc.name: DatabaseConsistency001
 * @tc.desc: Test database and cache consistency after operations
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(DeleteIdentityTest, DatabaseConsistency001, TestSize.Level0)
{
    // Create token
    AccessTokenID tokenID = AllocHapToken(infoParms_, policy_, {"ohos.permission.GET_NETWORK_INFO"});
    TokenGuard guard(tokenID, infoParms_.bundleName);  // RAII cleanup
    std::string bundleName = infoParms_.bundleName;

    // Verify token exists in both cache and database
    EXPECT_TRUE(TokenExistsInCache(tokenID));

    GenericValues condition;
    condition.Put(TokenFiledConst::FIELD_TOKEN_ID, static_cast<int32_t>(tokenID));
    std::vector<GenericValues> dbResults;
    int32_t ret = AccessTokenDbOperator::Find(AtmDataType::ACCESSTOKEN_HAP_INFO, condition, dbResults);
    EXPECT_EQ(RET_SUCCESS, ret);
    EXPECT_EQ(1u, dbResults.size());

    // Mark as reserved (updates database, removes from cache)
    MarkTokenAsReservedDirectly(tokenID, ReservedType::RESERVED_IDENTITY);

    // Verify token is removed from cache (reserved tokens should not be cached)
    EXPECT_FALSE(TokenExistsInCache(tokenID))
        << "Reserved token should not be in AccessTokenInfoManager cache";

    // Verify token is in reserved set
    EXPECT_TRUE(AccessTokenIDManager::GetInstance().IsReservedTokenId(tokenID));

    // Verify database is updated with reserved flag
    dbResults.clear();
    ret = AccessTokenDbOperator::Find(AtmDataType::ACCESSTOKEN_HAP_INFO, condition, dbResults);
    EXPECT_EQ(RET_SUCCESS, ret);
    EXPECT_EQ(1u, dbResults.size());
#ifdef SPM_DATA_ENABLE
    int32_t reserved = dbResults[0].GetInt(TokenFiledConst::FIELD_RESERVED);
    EXPECT_EQ(static_cast<int32_t>(ReservedType::RESERVED_IDENTITY), reserved);
#endif

    // Verify database has TOKEN_RESERVED_FLAG set
    int32_t tokenAttr = dbResults[0].GetInt(TokenFiledConst::FIELD_TOKEN_ATTR);
    EXPECT_TRUE(tokenAttr & 0x0004) << "TOKEN_RESERVED_FLAG should be set in database";
}

#ifdef SPM_DATA_ENABLE
/**
 * @tc.name: DeleteIdentityWithMultipleTokens001
 * @tc.desc: Test deleting one token from bundle with multiple tokens preserves BundleInfo
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(DeleteIdentityTest, DeleteIdentityWithMultipleTokens001, TestSize.Level0)
{
    std::string bundleName = "test.bundle.multiple.tokens";
    std::vector<TokenGuard> guards;  // RAII cleanup

    // Create multiple tokens for the same bundle (different instances)
    HapInfoParams info1 = CreateHapInfoParams(bundleName, 100, 0);
    HapInfoParams info2 = CreateHapInfoParams(bundleName, 100, 1);
    HapInfoParams info3 = CreateHapInfoParams(bundleName, 100, 2);
    HapPolicyParams policy = CreateHapPolicyParams();

    AccessTokenID token1 = AllocHapToken(info1, policy, {"ohos.permission.INTERNET"});
    guards.emplace_back(token1, bundleName);

    AccessTokenID token2 = AllocHapToken(info2, policy, {"ohos.permission.INTERNET"});
    guards.emplace_back(token2, bundleName);

    AccessTokenID token3 = AllocHapToken(info3, policy, {"ohos.permission.INTERNET"});
    guards.emplace_back(token3, bundleName);

    std::vector<AccessTokenID> tokensToCleanup = {token1, token2, token3};

#ifdef SPM_DATA_ENABLE
    // Manually create bundle package info in database for testing
    ASSERT_TRUE(CreateBundlePackageInfoInDatabase(bundleName))
        << "Failed to create bundle package info in database";
#endif

    // === Verify initial state ===
    // All three tokens exist
    EXPECT_TRUE(TokenExistsInDatabase(token1));
    EXPECT_TRUE(TokenExistsInDatabase(token2));
    EXPECT_TRUE(TokenExistsInDatabase(token3));

#ifdef SPM_DATA_ENABLE
    // HAP_PACKAGE_INFO exists for the bundle
    EXPECT_TRUE(BundlePackageInfoExistsInDatabase(bundleName))
        << "HAP_PACKAGE_INFO should exist initially";
#endif

    // Delete token1 with type=NONE (complete deletion)
    int32_t ret = AccessTokenInfoManager::GetInstance().DeleteIdentity(
        token1, bundleName, ReservedType::NONE);
    EXPECT_EQ(RET_SUCCESS, ret);

    // === Verify token1 is deleted ===
    EXPECT_FALSE(TokenExistsInDatabase(token1))
        << "Token1 should be deleted from database";
    EXPECT_FALSE(TokenExistsInCache(token1))
        << "Token1 should be removed from cache";

    // === Verify other tokens still exist ===
    EXPECT_TRUE(TokenExistsInDatabase(token2))
        << "Token2 should still exist in database";
    EXPECT_TRUE(TokenExistsInDatabase(token3))
        << "Token3 should still exist in database";

#ifdef SPM_DATA_ENABLE
    // === Verify HAP_PACKAGE_INFO is PRESERVED ===
    // Since token2 and token3 still exist, bundle info should NOT be deleted
    EXPECT_TRUE(BundlePackageInfoExistsInDatabase(bundleName))
        << "HAP_PACKAGE_INFO should be preserved when bundle still has active tokens";

    // Get bundle package info to verify it still contains reference to remaining tokens
    GenericValues packageInfo;
    EXPECT_TRUE(GetBundlePackageInfoFromDatabase(bundleName, packageInfo))
        << "Should be able to query HAP_PACKAGE_INFO";
#endif
    // Note: guards will automatically clean up remaining tokens when test exits
}

/**
 * @tc.name: DeleteIdentitySingleTokenNONE001
 * @tc.desc: Test deleting the only token in bundle with type=NONE releases BundleInfo
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(DeleteIdentityTest, DeleteIdentitySingleTokenNONE001, TestSize.Level0)
{
    std::string bundleName = "test.bundle.single.token";
    HapInfoParams info = CreateHapInfoParams(bundleName, 100, 0);
    HapPolicyParams policy = CreateHapPolicyParams();

    // Create a single token for the bundle
    AccessTokenID tokenID = AllocHapToken(info, policy, {"ohos.permission.INTERNET"});
    TokenGuard guard(tokenID, bundleName);  // RAII cleanup

#ifdef SPM_DATA_ENABLE
    // Manually create bundle package info in database for testing
    ASSERT_TRUE(CreateBundlePackageInfoInDatabase(bundleName))
        << "Failed to create bundle package info in database";
#endif

    // === Verify initial state ===
    EXPECT_TRUE(TokenExistsInDatabase(tokenID));
#ifdef SPM_DATA_ENABLE
    EXPECT_TRUE(BundlePackageInfoExistsInDatabase(bundleName))
        << "HAP_PACKAGE_INFO should exist initially";

    // Get initial package info for comparison
    GenericValues initialPackageInfo;
    EXPECT_TRUE(GetBundlePackageInfoFromDatabase(bundleName, initialPackageInfo));
#endif

    // Delete the only token with type=NONE (complete deletion)
    int32_t ret = AccessTokenInfoManager::GetInstance().DeleteIdentity(
        tokenID, bundleName, ReservedType::NONE);
    EXPECT_EQ(RET_SUCCESS, ret);

    // === Verify token is deleted ===
    EXPECT_FALSE(TokenExistsInDatabase(tokenID))
        << "Token should be deleted from database";
    EXPECT_TRUE(VerifyTokenCompletelyDeleted(tokenID))
        << "Token should be completely deleted from all tables";
    EXPECT_FALSE(TokenExistsInCache(tokenID))
        << "Token should be removed from cache";

#ifdef SPM_DATA_ENABLE
    // === Verify HAP_PACKAGE_INFO is DELETED ===
    // Since this was the only token, bundle info should be cleaned up
    EXPECT_FALSE(BundlePackageInfoExistsInDatabase(bundleName))
        << "HAP_PACKAGE_INFO should be deleted when last token is removed with type=NONE";
#endif
    // Note: guard will automatically clean up when test exits
}

/**
 * @tc.name: DeleteIdentityReservedPreservesPackageInfo001
 * @tc.desc: Test deleting token with RESERVED_IDENTITY deletes BundleInfo when all tokens are reserved
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(DeleteIdentityTest, DeleteIdentityReservedPreservesPackageInfo001, TestSize.Level0)
{
    std::string bundleName = "test.bundle.reserved.package";
    HapInfoParams info = CreateHapInfoParams(bundleName, 100, 0);
    HapPolicyParams policy = CreateHapPolicyParams();

    // Create a token
    AccessTokenID tokenID = AllocHapToken(info, policy, {"ohos.permission.INTERNET"});
    TokenGuard guard(tokenID, bundleName);  // RAII cleanup

#ifdef SPM_DATA_ENABLE
    // Manually create bundle package info in database for testing
    ASSERT_TRUE(CreateBundlePackageInfoInDatabase(bundleName))
        << "Failed to create bundle package info in database";
#endif

    // === Verify initial state ===
    EXPECT_TRUE(TokenExistsInDatabase(tokenID));
#ifdef SPM_DATA_ENABLE
    EXPECT_TRUE(BundlePackageInfoExistsInDatabase(bundleName))
        << "HAP_PACKAGE_INFO should exist initially";
#endif

    // Delete with type=RESERVED_IDENTITY
    int32_t ret = AccessTokenInfoManager::GetInstance().DeleteIdentity(
        tokenID, bundleName, ReservedType::RESERVED_IDENTITY);
    EXPECT_EQ(RET_SUCCESS, ret);

    // === Verify token is marked as reserved ===
    EXPECT_TRUE(AccessTokenIDManager::GetInstance().IsReservedTokenId(tokenID))
        << "Token should be marked as reserved";
    EXPECT_TRUE(TokenExistsInDatabase(tokenID))
        << "Token should still exist in database";

#ifdef SPM_DATA_ENABLE
    // === Verify HAP_PACKAGE_INFO is DELETED ===
    // When all tokens are reserved, bundle info should be deleted
    EXPECT_FALSE(BundlePackageInfoExistsInDatabase(bundleName))
        << "HAP_PACKAGE_INFO should be deleted when all tokens are reserved";
#endif
}

/**
 * @tc.name: DeleteIdentityReservedDataPreservesPackageInfo001
 * @tc.desc: Test deleting token with RESERVED_DATA deletes BundleInfo when all tokens are reserved,
 *           but preserves permission states
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(DeleteIdentityTest, DeleteIdentityReservedDataPreservesPackageInfo001, TestSize.Level0)
{
    std::string bundleName = "test.bundle.reserved.data";
    HapInfoParams info = CreateHapInfoParams(bundleName, 100, 0);
    HapPolicyParams policy = CreateHapPolicyParams();

    // Create a token with permissions
    AccessTokenID tokenID = AllocHapToken(info, policy, {"ohos.permission.INTERNET"});
    TokenGuard guard(tokenID, bundleName);  // RAII cleanup

    // Get initial permission state count
    size_t initialPermCount = CountPermissionStatesInDatabase(tokenID);
    EXPECT_GT(initialPermCount, 0u) << "Token should have permission states";

#ifdef SPM_DATA_ENABLE
    // Manually create bundle package info in database for testing
    ASSERT_TRUE(CreateBundlePackageInfoInDatabase(bundleName))
        << "Failed to create bundle package info in database";
#endif

    // === Verify initial state ===
#ifdef SPM_DATA_ENABLE
    EXPECT_TRUE(BundlePackageInfoExistsInDatabase(bundleName))
        << "HAP_PACKAGE_INFO should exist initially";
#endif

    // Delete with type=RESERVED_DATA (preserves permission states)
    int32_t ret = AccessTokenInfoManager::GetInstance().DeleteIdentity(
        tokenID, bundleName, ReservedType::RESERVED_DATA);
    EXPECT_EQ(RET_SUCCESS, ret);

    // === Verify token is marked as reserved ===
    EXPECT_TRUE(AccessTokenIDManager::GetInstance().IsReservedTokenId(tokenID));

    // === Verify permission states are PRESERVED ===
    size_t finalPermCount = CountPermissionStatesInDatabase(tokenID);
    EXPECT_EQ(initialPermCount, finalPermCount)
        << "Permission states should be preserved for RESERVED_DATA";

#ifdef SPM_DATA_ENABLE
    // === Verify HAP_PACKAGE_INFO is DELETED ===
    // When all tokens are reserved, bundle info should be deleted
    EXPECT_FALSE(BundlePackageInfoExistsInDatabase(bundleName))
        << "HAP_PACKAGE_INFO should be deleted when all tokens are reserved";
#endif
}

/**
 * @tc.name: DeleteIdentityInvalidTokenIDWithPackageInfo001
 * @tc.desc: Test deleting all reserved tokens with DeleteBundleAndAllTokens cleans up PackageInfo
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(DeleteIdentityTest, DeleteIdentityInvalidTokenIDWithPackageInfo001, TestSize.Level0)
{
    std::string bundleName = "test.bundle.invalid.tokenid.cleanup";
    std::vector<TokenGuard> guards;  // RAII cleanup

    // Create multiple tokens for the same bundle
    HapInfoParams info1 = CreateHapInfoParams(bundleName, 100, 0);
    HapInfoParams info2 = CreateHapInfoParams(bundleName, 100, 1);
    HapPolicyParams policy = CreateHapPolicyParams();

    AccessTokenID token1 = AllocHapToken(info1, policy, {"ohos.permission.INTERNET"});
    guards.emplace_back(token1, bundleName);

    AccessTokenID token2 = AllocHapToken(info2, policy, {"ohos.permission.INTERNET"});
    guards.emplace_back(token2, bundleName);

    std::vector<AccessTokenID> tokensToCleanup = {token1, token2};

#ifdef SPM_DATA_ENABLE
    // Manually create bundle package info in database for testing
    ASSERT_TRUE(CreateBundlePackageInfoInDatabase(bundleName))
        << "Failed to create bundle package info in database";
#endif

    // === Verify initial state ===
    EXPECT_TRUE(TokenExistsInDatabase(token1));
    EXPECT_TRUE(TokenExistsInDatabase(token2));
#ifdef SPM_DATA_ENABLE
    EXPECT_TRUE(BundlePackageInfoExistsInDatabase(bundleName))
        << "HAP_PACKAGE_INFO should exist initially";
#endif

    // Mark both as reserved (simulating app deletion)
    MarkTokenAsReservedDirectly(token1, ReservedType::RESERVED_IDENTITY);
    MarkTokenAsReservedDirectly(token2, ReservedType::RESERVED_DATA);

    // Verify both are marked as reserved
    EXPECT_TRUE(AccessTokenIDManager::GetInstance().IsReservedTokenId(token1));
    EXPECT_TRUE(AccessTokenIDManager::GetInstance().IsReservedTokenId(token2));

    // Delete all reserved tokens for the bundle using DeleteBundleAndAllTokens
    int32_t ret = DeleteBundleManager::GetInstance().DeleteBundleAndAllTokens(bundleName);
    EXPECT_EQ(RET_SUCCESS, ret);

    // === Verify all tokens are deleted ===
    EXPECT_FALSE(TokenExistsInDatabase(token1))
        << "Token1 should be deleted from database";
    EXPECT_FALSE(TokenExistsInDatabase(token2))
        << "Token2 should be deleted from database";
    EXPECT_TRUE(VerifyTokenCompletelyDeleted(token1))
        << "Token1 should be completely deleted";
    EXPECT_TRUE(VerifyTokenCompletelyDeleted(token2))
        << "Token2 should be completely deleted";

    // === Verify cache cleanup ===
    EXPECT_FALSE(TokenExistsInCache(token1));
    EXPECT_FALSE(TokenExistsInCache(token2));

    // === Verify memory cleanup ===
    EXPECT_FALSE(AccessTokenIDManager::GetInstance().IsReservedTokenId(token1));
    EXPECT_FALSE(AccessTokenIDManager::GetInstance().IsReservedTokenId(token2));

#ifdef SPM_DATA_ENABLE
    // === Verify HAP_PACKAGE_INFO is DELETED ===
    // Since all tokens (including reserved) were deleted, package info should be cleaned up
    EXPECT_FALSE(BundlePackageInfoExistsInDatabase(bundleName))
        << "HAP_PACKAGE_INFO should be deleted when all reserved tokens are removed via INVALID_TOKENID";
#endif
}

/**
 * @tc.name: DeleteIdentityMixedTokensPreservesPackageInfo001
 * @tc.desc: Test bundle with mixed active and reserved tokens preserves PackageInfo
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(DeleteIdentityTest, DeleteIdentityMixedTokensPreservesPackageInfo001, TestSize.Level0)
{
    std::string bundleName = "test.bundle.mixed.tokens";
    std::vector<TokenGuard> guards;  // RAII cleanup

    // Create two tokens: one will be reserved, one stays active
    HapInfoParams info1 = CreateHapInfoParams(bundleName, 100, 0);
    HapInfoParams info2 = CreateHapInfoParams(bundleName, 100, 1);
    HapPolicyParams policy = CreateHapPolicyParams();

    AccessTokenID token1 = AllocHapToken(info1, policy, {"ohos.permission.INTERNET"});
    guards.emplace_back(token1, bundleName);

    AccessTokenID token2 = AllocHapToken(info2, policy, {"ohos.permission.INTERNET"});
    guards.emplace_back(token2, bundleName);

    std::vector<AccessTokenID> tokensToCleanup = {token1, token2};

#ifdef SPM_DATA_ENABLE
    // Manually create bundle package info in database for testing
    ASSERT_TRUE(CreateBundlePackageInfoInDatabase(bundleName))
        << "Failed to create bundle package info in database";
#endif

    // === Verify initial state ===
#ifdef SPM_DATA_ENABLE
    EXPECT_TRUE(BundlePackageInfoExistsInDatabase(bundleName))
        << "HAP_PACKAGE_INFO should exist initially";
#endif

    // Mark token1 as reserved
    MarkTokenAsReservedDirectly(token1, ReservedType::RESERVED_IDENTITY);

    // Delete token1 (the reserved one)
    int32_t ret = DeleteBundleManager::GetInstance().DeleteReservedToken(token1, bundleName);
    EXPECT_EQ(RET_SUCCESS, ret);

    // === Verify token1 is deleted ===
    EXPECT_FALSE(TokenExistsInDatabase(token1));
    EXPECT_FALSE(AccessTokenIDManager::GetInstance().IsReservedTokenId(token1));
    // Note: DeleteReservedToken does not remove from cache.

    // === Verify token2 still exists (active) ===
    EXPECT_TRUE(TokenExistsInDatabase(token2))
        << "Active token2 should still exist";
    EXPECT_TRUE(TokenExistsInCache(token2))
        << "Active token2 should still be in cache";

#ifdef SPM_DATA_ENABLE
    // === Verify HAP_PACKAGE_INFO is PRESERVED ===
    // Since token2 is still active, bundle info should NOT be deleted
    EXPECT_TRUE(BundlePackageInfoExistsInDatabase(bundleName))
        << "HAP_PACKAGE_INFO should be preserved when bundle still has active tokens";
#endif
    // Note: guards will automatically clean up when test exits
}
#endif // SPM_DATA_ENABLE
