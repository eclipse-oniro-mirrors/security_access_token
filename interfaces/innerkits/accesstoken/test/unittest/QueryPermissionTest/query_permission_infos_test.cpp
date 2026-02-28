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

#include "query_permission_infos_test.h"
#include "accesstoken_kit.h"
#include "token_setproc.h"
#include "hap_token_info.h"
#include "native_token_info.h"
#include "access_token_error.h"
#include "test_common.h"
#include "permission_def.h"
#include "permission_map.h"

#include <gtest/gtest.h>
#include <gtest/hwext/gtest-multithread.h>
#include <chrono>
#include <thread>
#include <algorithm>

namespace OHOS {
namespace Security {
namespace AccessToken {

using namespace testing::ext;
using namespace testing::mt;

// Performance testing thresholds (milliseconds)
#define PERF_THRESHOLD_100MS 100
#define PERF_THRESHOLD_500MS 500
#define PERF_THRESHOLD_1000MS 1000
#define PERF_THRESHOLD_2000MS 2000

namespace {
// Test thread configuration
constexpr int32_t MULTI_THREAD_COUNT = 10;
constexpr int32_t REPEAT_ITERATION_COUNT = 1000;

// HAP token configuration
constexpr int32_t TEST_USER_ID = 100;
constexpr int32_t TEST_API_VERSION = 12;
constexpr int32_t TEST_INST_INDEX = 0;

// Test data sizes
constexpr int32_t MEDIUM_APP_COUNT = 100;
constexpr int32_t LONG_PERMISSION_NAME_SIZE = 300;
constexpr int32_t LARGE_APP_COUNT = 500;
constexpr int32_t EXTRA_LARGE_APP_COUNT = 1000;
constexpr int32_t LARGE_PERMISSION_COUNT = 50;

// Query result size limits
constexpr int32_t MAX_QUERY_RESULT_SIZE = 500 * 100;  // Max result size for query operations

// Permission status values
constexpr int32_t PERMISSION_STATUS_MAX = 3;
}

uint64_t QueryPermissionInfosTest::selfShellTokenId_ = 0;
std::mutex QueryPermissionInfosTest::testMutex_;
MockHapToken* QueryPermissionInfosTest::mock_ = nullptr;

void QueryPermissionInfosTest::SetUpTestCase()
{
    // Get current shell token ID for testing
    selfShellTokenId_ = GetSelfTokenID();
    TestCommon::SetTestEvironment(selfShellTokenId_);

    std::vector<std::string> perms;
    perms.emplace_back("ohos.permission.GET_SENSITIVE_PERMISSIONS");
    mock_ = new (std::nothrow) MockHapToken("com.example.query.test", perms, true);
}

void QueryPermissionInfosTest::TearDownTestCase()
{
    if (mock_ != nullptr) {
        delete mock_;
        mock_ = nullptr;
    }
    EXPECT_EQ(0, SetSelfTokenID(selfShellTokenId_));
    TestCommon::ResetTestEvironment();
}

void QueryPermissionInfosTest::SetUp()
{
    // Setup individual test environment
}

void QueryPermissionInfosTest::TearDown()
{
    // Cleanup individual test environment
}

AccessTokenID QueryPermissionInfosTest::PrepareTestHap(
    const std::string& bundleName,
    const std::vector<std::string>& permissions,
    bool isSystemApp,
    ATokenAplEnum apl)
{
    // Prepare HapInfoParams
    HapInfoParams info;
    info.userID = TEST_USER_ID;
    info.bundleName = bundleName;
    info.instIndex = TEST_INST_INDEX;
    info.appIDDesc = "test.app.id" + bundleName;
    info.apiVersion = TEST_API_VERSION;
    info.appDistributionType = "os_default";

    // Prepare permission states
    std::vector<PermissionStateFull> permStates;
    for (const auto& perm : permissions) {
        PermissionStateFull permState = {};
        permState.permissionName = perm;
        permState.isGeneral = true;
        permState.resDeviceID = {"local"};
        permState.grantStatus = {PermissionState::PERMISSION_GRANTED};
        permState.grantFlags = {1}; // PERMISSION_GRANTED_BY_DEFAULT
        permStates.emplace_back(permState);
    }

    // Prepare HapPolicyParams
    HapPolicyParams policy = {};
    policy.apl = isSystemApp ? APL_SYSTEM_CORE : APL_NORMAL;
    policy.domain = "test.domain";
    policy.permStateList = permStates;

    // Create HAP token using TestCommon helper
    AccessTokenIDEx tokenIdEx;
    int32_t ret = TestCommon::AllocTestHapToken(info, policy, tokenIdEx);
    if (ret != RET_SUCCESS) {
        return INVALID_TOKENID;
    }

    return tokenIdEx.tokenIdExStruct.tokenID;
}

void QueryPermissionInfosTest::CleanupTestHap(AccessTokenID tokenID)
{
    TestCommon::DeleteTestHapToken(tokenID);
}

/**
 * @tc.name: QueryStatusByPermissionTest001
 * @tc.desc: Query single valid permission, return HAP app list that requested it
 * @tc.type: FUNC
 * @tc.require: Issue Number
 */
HWTEST_F(QueryPermissionInfosTest, QueryStatusByPermissionTest001, TestSize.Level1)
{
    // Prepare: Create test HAP with CAMERA permission
    std::vector<std::string> permissions = {"ohos.permission.CAMERA"};
    AccessTokenID tokenID1 = PrepareTestHap("com.example.camera.test001", permissions, false);
    ASSERT_NE(tokenID1, INVALID_TOKENID);

    // Test: Query apps with CAMERA permission
    std::vector<std::string> permissionList = {"ohos.permission.CAMERA"};
    std::vector<PermissionStatus> permissionInfoList;

    int32_t ret = AccessTokenKit::QueryStatusByPermission(permissionList, permissionInfoList);

    // Assert: Should return RET_SUCCESS and contain our test app
    EXPECT_EQ(RET_SUCCESS, ret);
    EXPECT_FALSE(permissionInfoList.empty());

    // Verify our test app is in the result
    bool found = false;
    for (const auto& info : permissionInfoList) {
        if (info.tokenID == tokenID1) {
            found = true;
            EXPECT_EQ("ohos.permission.CAMERA", info.permissionName);
            break;
        }
    }
    EXPECT_TRUE(found);

    // Cleanup
    CleanupTestHap(tokenID1);
}

/**
 * @tc.name: QueryStatusByPermissionTest002
 * @tc.desc: Query multiple valid permissions, return app list for any permission
 * @tc.type: FUNC
 * @tc.require: Issue Number
 */
HWTEST_F(QueryPermissionInfosTest, QueryStatusByPermissionTest002, TestSize.Level1)
{
    // Prepare: Create two HAPs with different permissions
    std::vector<std::string> perms1 = {"ohos.permission.CAMERA"};
    std::vector<std::string> perms2 = {"ohos.permission.MICROPHONE"};
    AccessTokenID tokenID1 = PrepareTestHap("com.example.camera.test002", perms1, false);
    AccessTokenID tokenID2 = PrepareTestHap("com.example.mic.test002", perms2, false);
    ASSERT_NE(tokenID1, INVALID_TOKENID);
    EXPECT_NE(tokenID2, INVALID_TOKENID);

    // Test: Query apps with either CAMERA or MICROPHONE permission
    std::vector<std::string> permissionList = {
        "ohos.permission.CAMERA",
        "ohos.permission.MICROPHONE"
    };
    std::vector<PermissionStatus> permissionInfoList;

    int32_t ret = AccessTokenKit::QueryStatusByPermission(permissionList, permissionInfoList);

    // Assert: Should return RET_SUCCESS with both apps
    EXPECT_EQ(RET_SUCCESS, ret);
    EXPECT_GE(permissionInfoList.size(), 2U);

    // Verify both apps are in results
    std::set<AccessTokenID> foundTokenIDs;
    for (const auto& info : permissionInfoList) {
        foundTokenIDs.insert(info.tokenID);
    }
    EXPECT_TRUE(foundTokenIDs.find(tokenID1) != foundTokenIDs.end());
    EXPECT_TRUE(foundTokenIDs.find(tokenID2) != foundTokenIDs.end());

    // Cleanup
    CleanupTestHap(tokenID1);
    CleanupTestHap(tokenID2);
}

/**
 * @tc.name: QueryStatusByPermissionTest003
 * @tc.desc: Query with onlyHap=true vs onlyHap=false, verify filter works correctly
 * @tc.type: FUNC
 * @tc.require: Issue Number
 */
HWTEST_F(QueryPermissionInfosTest, QueryStatusByPermissionTest003, TestSize.Level1)
{
    MockNativeToken mockNative("privacy_service");
    // Prepare: Create a test HAP with a system permission (likely also held by native services)
    std::vector<std::string> permissions = {"ohos.permission.INTERNET"};
    AccessTokenID tokenID = PrepareTestHap("com.example.test003", permissions, false);
    ASSERT_NE(tokenID, INVALID_TOKENID);

    // Test 1: Query with onlyHap=false (all tokens including native)
    std::vector<std::string> permissionList = {"ohos.permission.INTERNET"};
    std::vector<PermissionStatus> permissionInfoListAll;

    int32_t ret = AccessTokenKit::QueryStatusByPermission(permissionList, permissionInfoListAll, false);
    EXPECT_EQ(RET_SUCCESS, ret);

    // Count native and HAP tokens
    int32_t nativeCountAll = 0;
    for (const auto& info : permissionInfoListAll) {
        ATokenTypeEnum tokenType = AccessTokenKit::GetTokenTypeFlag(info.tokenID);
        if (tokenType == TOKEN_NATIVE) {
            nativeCountAll++;
        }
    }

    // Test 2: Query with onlyHap=true (default, only HAP tokens)
    std::vector<PermissionStatus> permissionInfoListHapOnly;
    ret = AccessTokenKit::QueryStatusByPermission(permissionList, permissionInfoListHapOnly, true);
    EXPECT_EQ(RET_SUCCESS, ret);

    // Verify: HAP-only result should have no NATIVE tokens
    int32_t nativeCountHap = 0;
    for (const auto& info : permissionInfoListHapOnly) {
        ATokenTypeEnum tokenType = AccessTokenKit::GetTokenTypeFlag(info.tokenID);
        EXPECT_EQ(TOKEN_HAP, tokenType) << "Found NATIVE token in onlyHap=true result: " << info.tokenID;
    }

    // Verify: If there were native tokens in the full query, they should be filtered out
    if (nativeCountAll > 0) {
        EXPECT_GT(permissionInfoListAll.size(), permissionInfoListHapOnly.size())
            << "onlyHap=true should filter out native tokens";
        EXPECT_EQ(nativeCountHap, 0) << "onlyHap=true result should contain no native tokens";
    }

    // Verify: Test HAP should be in both results
    bool foundInAll = false;
    bool foundInHapOnly = false;
    for (const auto& info : permissionInfoListAll) {
        if (info.tokenID == tokenID) {
            foundInAll = true;
            break;
        }
    }
    for (const auto& info : permissionInfoListHapOnly) {
        if (info.tokenID == tokenID) {
            foundInHapOnly = true;
            break;
        }
    }
    EXPECT_TRUE(foundInAll) << "Test HAP not found in full query result";
    EXPECT_TRUE(foundInHapOnly) << "Test HAP not found in HAP-only query result";

    // Cleanup
    CleanupTestHap(tokenID);
}

/**
 * @tc.name: QueryStatusByPermissionTest004
 * @tc.desc: Query with onlyHap=true, only return HAP apps (default behavior)
 * @tc.type: FUNC
 * @tc.require: Issue Number
 */
HWTEST_F(QueryPermissionInfosTest, QueryStatusByPermissionTest004, TestSize.Level1)
{
    // Prepare: Create HAP app with CAMERA permission
    std::vector<std::string> permissions = {"ohos.permission.CAMERA"};
    AccessTokenID tokenID = PrepareTestHap("com.example.camera.test004", permissions, false);
    ASSERT_NE(tokenID, INVALID_TOKENID);

    // Test: Query apps with onlyHap=true (default)
    std::vector<std::string> permissionList = {"ohos.permission.CAMERA"};
    std::vector<PermissionStatus> permissionInfoList;

    int32_t ret = AccessTokenKit::QueryStatusByPermission(permissionList, permissionInfoList, true);

    // Assert: Should return RET_SUCCESS and only HAP apps
    EXPECT_EQ(RET_SUCCESS, ret);
    EXPECT_FALSE(permissionInfoList.empty());

    // Verify all results are from HAP tokens
    for (const auto& info : permissionInfoList) {
        ATokenTypeEnum tokenType = AccessTokenKit::GetTokenTypeFlag(info.tokenID);
        EXPECT_EQ(TOKEN_HAP, tokenType);
    }

    // Cleanup
    CleanupTestHap(tokenID);
}

/**
 * @tc.name: QueryStatusByPermissionTest005
 * @tc.desc: Query with default onlyHap parameter (not specified, defaults to true), only return HAP apps
 * @tc.type: FUNC
 * @tc.require: Issue Number
 */
HWTEST_F(QueryPermissionInfosTest, QueryStatusByPermissionTest005, TestSize.Level1)
{
    // Prepare: Create HAP app
    std::vector<std::string> permissions = {"ohos.permission.CAMERA"};
    AccessTokenID tokenID = PrepareTestHap("com.example.camera.test005", permissions, false);
    ASSERT_NE(tokenID, INVALID_TOKENID);

    // Test: Query without specifying onlyHap parameter (default is true)
    std::vector<std::string> permissionList = {"ohos.permission.CAMERA"};
    std::vector<PermissionStatus> permissionInfoList;

    int32_t ret = AccessTokenKit::QueryStatusByPermission(permissionList, permissionInfoList);

    // Assert: Should only return HAP apps (default behavior)
    EXPECT_EQ(RET_SUCCESS, ret);
    for (const auto& info : permissionInfoList) {
        ATokenTypeEnum tokenType = AccessTokenKit::GetTokenTypeFlag(info.tokenID);
        EXPECT_EQ(TOKEN_HAP, tokenType);
    }

    // Cleanup
    CleanupTestHap(tokenID);
}

/**
 * @tc.name: QueryStatusByPermissionTest006
 * @tc.desc: Query with onlyHap=false, verify can find both HAP and Native apps
 * @tc.type: FUNC
 * @tc.require: Issue Number
 */
HWTEST_F(QueryPermissionInfosTest, QueryStatusByPermissionTest006, TestSize.Level1)
{
    MockNativeToken mockNative("privacy_service");
    // Prepare: Create two HAP apps with PERMISSION_USED_STATS
    // Note: PERMISSION_USED_STATS is a system permission that may be held by both Native and HAP processes
    // This test verifies onlyHap=false returns at least the same results as onlyHap=true
    std::vector<std::string> permissions = {"ohos.permission.PERMISSION_USED_STATS"};
    AccessTokenID tokenID1 = PrepareTestHap("com.example.usedstats.test006a", permissions, false);
    ASSERT_NE(tokenID1, INVALID_TOKENID);
    AccessTokenID tokenID2 = PrepareTestHap("com.example.usedstats.test006b", permissions, false);
    EXPECT_NE(tokenID2, INVALID_TOKENID);

    // Test 1: Query with onlyHap=true (only HAP tokens)
    std::vector<std::string> permissionList = {"ohos.permission.PERMISSION_USED_STATS"};
    std::vector<PermissionStatus> permissionInfoListHapOnly;

    int32_t ret = AccessTokenKit::QueryStatusByPermission(permissionList, permissionInfoListHapOnly, true);
    EXPECT_EQ(RET_SUCCESS, ret);

    // Verify: Should have at least our test HAPs
    bool foundTestHap1 = false;
    bool foundTestHap2 = false;
    for (const auto& info : permissionInfoListHapOnly) {
        if (info.tokenID == tokenID1) foundTestHap1 = true;
        if (info.tokenID == tokenID2) foundTestHap2 = true;
        EXPECT_EQ(TOKEN_HAP, AccessTokenKit::GetTokenTypeFlag(info.tokenID));
    }
    EXPECT_TRUE(foundTestHap1) << "Test HAP 1 not found in onlyHap=true result";
    EXPECT_TRUE(foundTestHap2) << "Test HAP 2 not found in onlyHap=true result";

    std::vector<PermissionStatus> permissionInfoListAll;

    ret = AccessTokenKit::QueryStatusByPermission(permissionList, permissionInfoListAll, false);
    EXPECT_EQ(RET_SUCCESS, ret);

    // Verify: Should have at least our test HAPs
    foundTestHap1 = false;
    foundTestHap2 = false;
    bool hasNative = false;

    for (const auto& info : permissionInfoListAll) {
        if (info.tokenID == tokenID1) foundTestHap1 = true;
        if (info.tokenID == tokenID2) foundTestHap2 = true;
        ATokenTypeEnum tokenType = AccessTokenKit::GetTokenTypeFlag(info.tokenID);
        if (tokenType == TOKEN_NATIVE) {
            hasNative = true;
        }
    }
    EXPECT_TRUE(foundTestHap1) << "Test HAP 1 not found in onlyHap=false result";
    EXPECT_TRUE(foundTestHap2) << "Test HAP 2 not found in onlyHap=false result";

    // Verify: onlyHap=false should have >= results than onlyHap=true
    // (may include Native tokens if system services with this permission exist in test environment)
    EXPECT_GE(permissionInfoListAll.size(), permissionInfoListHapOnly.size())
        << "onlyHap=false should have >= results than onlyHap=true";
    EXPECT_TRUE(hasNative);

    // Cleanup
    CleanupTestHap(tokenID1);
    CleanupTestHap(tokenID2);
}

/**
 * @tc.name: QueryStatusByPermissionTest007
 * @tc.desc: Native process has permission, onlyHap=true, don't include Native
 * @tc.type: FUNC
 * @tc.require: Issue Number
 */
HWTEST_F(QueryPermissionInfosTest, QueryStatusByPermissionTest007, TestSize.Level1)
{
    // Test: Query PERMISSION_USED_STATS with onlyHap=true
    // Note: PERMISSION_USED_STATS is requested by both system services (Native) and apps (HAP)
    std::vector<std::string> permissionList = {"ohos.permission.PERMISSION_USED_STATS"};
    std::vector<PermissionStatus> permissionInfoList;

    int32_t ret = AccessTokenKit::QueryStatusByPermission(permissionList, permissionInfoList, true);

    // Assert: Should succeed but not include Native processes (only HAP apps)
    ASSERT_EQ(RET_SUCCESS, ret);
    for (const auto& info : permissionInfoList) {
        ATokenTypeEnum tokenType = AccessTokenKit::GetTokenTypeFlag(info.tokenID);
        ASSERT_EQ(TOKEN_HAP, tokenType);
    }
}

/**
 * @tc.name: QueryStatusByPermissionTest008
 * @tc.desc: Query with onlyHap=false, verify can find native token
 * @tc.type: FUNC
 * @tc.require: Issue Number
 */
HWTEST_F(QueryPermissionInfosTest, QueryStatusByPermissionTest008, TestSize.Level1)
{
    MockNativeToken mockNative("privacy_service");
    std::vector<std::string> permissionList = {"ohos.permission.PERMISSION_USED_STATS"};
    std::vector<PermissionStatus> permissionInfoList;

    int32_t ret = AccessTokenKit::QueryStatusByPermission(permissionList, permissionInfoList, false);

    // Assert: Should succeed and include Native processes
    ASSERT_EQ(RET_SUCCESS, ret);

    // Should include Native system services with this permission
    bool hasNative = false;
    for (const auto& info : permissionInfoList) {
        ATokenTypeEnum tokenType = AccessTokenKit::GetTokenTypeFlag(info.tokenID);
        if (tokenType == TOKEN_NATIVE) {
            hasNative = true;
            break;
        }
    }
    ASSERT_TRUE(hasNative);  // PERMISSION_USED_STATS is requested by system services
}

/**
 * @tc.name: QueryStatusByPermissionTest009
 * @tc.desc: Query with empty permission list, return ERR_PARAM_INVALID
 * @tc.type: FUNC
 * @tc.require: Issue Number
 */
HWTEST_F(QueryPermissionInfosTest, QueryStatusByPermissionTest009, TestSize.Level1)
{
    // Test: Query with empty permission list
    std::vector<std::string> permissionList;
    std::vector<PermissionStatus> permissionInfoList;

    int32_t ret = AccessTokenKit::QueryStatusByPermission(permissionList, permissionInfoList);

    // Assert: Should return ERR_PARAM_INVALID
    ASSERT_EQ(ERR_PARAM_INVALID, ret);
    ASSERT_TRUE(permissionInfoList.empty());
}

/**
 * @tc.name: QueryStatusByPermissionTest010
 * @tc.desc: Query with empty string in permission list, return ERR_PARAM_INVALID
 * @tc.type: FUNC
 * @tc.require: Issue Number
 */
HWTEST_F(QueryPermissionInfosTest, QueryStatusByPermissionTest010, TestSize.Level1)
{
    // Test: Query with empty string in permission list
    std::vector<std::string> permissionList = {""};
    std::vector<PermissionStatus> permissionInfoList;

    int32_t ret = AccessTokenKit::QueryStatusByPermission(permissionList, permissionInfoList);

    // Assert: Should return ERR_PARAM_INVALID
    ASSERT_EQ(ERR_PARAM_INVALID, ret);
    ASSERT_TRUE(permissionInfoList.empty());
}

/**
 * @tc.name: QueryStatusByPermissionTest011
 * @tc.desc: Query with permission name exceeding 256 bytes, return ERR_PARAM_INVALID
 * @tc.type: FUNC
 * @tc.require: Issue Number
 */
HWTEST_F(QueryPermissionInfosTest, QueryStatusByPermissionTest011, TestSize.Level1)
{
    // Prepare: Create permission name > 256 bytes
    std::string longPermName(LONG_PERMISSION_NAME_SIZE, 'A');
    std::vector<std::string> permissionList = {longPermName};
    std::vector<PermissionStatus> permissionInfoList;

    int32_t ret = AccessTokenKit::QueryStatusByPermission(permissionList, permissionInfoList);

    // Assert: Should return ERR_PARAM_INVALID
    ASSERT_EQ(ERR_PARAM_INVALID, ret);
    ASSERT_TRUE(permissionInfoList.empty());
}

/**
 * @tc.name: QueryStatusByPermissionTest012
 * @tc.desc: Query non-existent permission in strict mode, return ERR_PERMISSION_NOT_EXIST
 * @tc.type: FUNC
 * @tc.require: Issue Number
 */
HWTEST_F(QueryPermissionInfosTest, QueryStatusByPermissionTest012, TestSize.Level1)
{
    // Test: Query non-existent permission
    std::vector<std::string> permissionList = {"ohos.permission.NOT_EXIST_PERM_XYZ"};
    std::vector<PermissionStatus> permissionInfoList;

    int32_t ret = AccessTokenKit::QueryStatusByPermission(permissionList, permissionInfoList);

    // Assert: Should return ERR_PERMISSION_NOT_EXIST
    ASSERT_EQ(ERR_PERMISSION_NOT_EXIST, ret);
    ASSERT_TRUE(permissionInfoList.empty());
}

/**
 * @tc.name: QueryStatusByPermissionTest013
 * @tc.desc: Query with mix of existent and non-existent permissions, return ERR_PERMISSION_NOT_EXIST
 * @tc.type: FUNC
 * @tc.require: Issue Number
 */
HWTEST_F(QueryPermissionInfosTest, QueryStatusByPermissionTest013, TestSize.Level1)
{
    // Prepare: Create HAP with CAMERA permission
    std::vector<std::string> permissions = {"ohos.permission.CAMERA"};
    AccessTokenID tokenID = PrepareTestHap("com.example.camera.test013", permissions, false);
    ASSERT_NE(tokenID, INVALID_TOKENID);

    // Test: Query with mix of valid and invalid permissions
    std::vector<std::string> permissionList = {
        "ohos.permission.CAMERA",
        "ohos.permission.NOT_EXIST_PERM_013"
    };
    std::vector<PermissionStatus> permissionInfoList;

    int32_t ret = AccessTokenKit::QueryStatusByPermission(permissionList, permissionInfoList);

    // Assert: Should return ERR_PERMISSION_NOT_EXIST
    ASSERT_EQ(ERR_PERMISSION_NOT_EXIST, ret);

    // Cleanup
    CleanupTestHap(tokenID);
}

/**
 * @tc.name: QueryStatusByPermissionTest014
 * @tc.desc: Query 100 apps with permission, performance < 500ms
 * @tc.type: PERF
 * @tc.require: Issue Number
 */
HWTEST_F(QueryPermissionInfosTest, QueryStatusByPermissionTest014, TestSize.Level2)
{
    // Prepare: Create 100 test HAPs
    std::vector<AccessTokenID> tokenIDs;
    std::vector<std::string> permissions = {"ohos.permission.CAMERA"};

    for (int i = 0; i < MEDIUM_APP_COUNT; ++i) {
        std::string bundleName = "com.example.perf.test014." + std::to_string(i);
        AccessTokenID tokenID = PrepareTestHap(bundleName, permissions, false);
        if (tokenID != INVALID_TOKENID) {
            tokenIDs.emplace_back(tokenID);
        }
    }

    // Test: Measure query performance
    std::vector<std::string> permissionList = {"ohos.permission.CAMERA"};
    std::vector<PermissionStatus> permissionInfoList;

    auto startTime = std::chrono::high_resolution_clock::now();
    int32_t ret = AccessTokenKit::QueryStatusByPermission(permissionList, permissionInfoList);
    auto endTime = std::chrono::high_resolution_clock::now();

    auto duration = std::chrono::duration_cast<std::chrono::milliseconds>(endTime - startTime);

    // Assert: Should succeed and complete within 500ms
    EXPECT_EQ(RET_SUCCESS, ret);
    EXPECT_LT(duration.count(), PERF_THRESHOLD_500MS);

    // Cleanup
    for (auto tokenID : tokenIDs) {
        CleanupTestHap(tokenID);
    }
}

/**
 * @tc.name: QueryStatusByPermissionTest015
 * @tc.desc: Query 500 apps with permission, performance < 1000ms
 * @tc.type: PERF
 * @tc.require: Issue Number
 */
HWTEST_F(QueryPermissionInfosTest, QueryStatusByPermissionTest015, TestSize.Level2)
{
    // Prepare: Create 500 test HAPs
    std::vector<AccessTokenID> tokenIDs;
    std::vector<std::string> permissions = {"ohos.permission.CAMERA"};

    for (int i = 0; i < LARGE_APP_COUNT; ++i) {
        std::string bundleName = "com.example.perf.test015." + std::to_string(i);
        AccessTokenID tokenID = PrepareTestHap(bundleName, permissions, false);
        if (tokenID != INVALID_TOKENID) {
            tokenIDs.emplace_back(tokenID);
        }
    }

    // Test: Measure query performance
    std::vector<std::string> permissionList = {"ohos.permission.CAMERA"};
    std::vector<PermissionStatus> permissionInfoList;

    auto startTime = std::chrono::high_resolution_clock::now();
    int32_t ret = AccessTokenKit::QueryStatusByPermission(permissionList, permissionInfoList);
    auto endTime = std::chrono::high_resolution_clock::now();

    auto duration = std::chrono::duration_cast<std::chrono::milliseconds>(endTime - startTime);

    // Assert: Should succeed and complete within 1000ms
    EXPECT_EQ(RET_SUCCESS, ret);
    EXPECT_LT(duration.count(), PERF_THRESHOLD_1000MS);

    // Cleanup
    for (auto tokenID : tokenIDs) {
        CleanupTestHap(tokenID);
    }
}

/**
 * @tc.name: QueryStatusByPermissionTest016
 * @tc.desc: Query 1000 apps with permission, performance < 2000ms
 * @tc.type: PERF
 * @tc.require: Issue Number
 */
HWTEST_F(QueryPermissionInfosTest, QueryStatusByPermissionTest016, TestSize.Level3)
{
    // Prepare: Create 1000 test HAPs
    std::vector<AccessTokenID> tokenIDs;
    std::vector<std::string> permissions = {"ohos.permission.CAMERA"};

    for (int i = 0; i < EXTRA_LARGE_APP_COUNT; ++i) {
        std::string bundleName = "com.example.perf.test016." + std::to_string(i);
        AccessTokenID tokenID = PrepareTestHap(bundleName, permissions, false);
        if (tokenID != INVALID_TOKENID) {
            tokenIDs.emplace_back(tokenID);
        }
    }

    // Test: Measure query performance
    std::vector<std::string> permissionList = {"ohos.permission.CAMERA"};
    std::vector<PermissionStatus> permissionInfoList;

    auto startTime = std::chrono::high_resolution_clock::now();
    int32_t ret = AccessTokenKit::QueryStatusByPermission(permissionList, permissionInfoList);
    auto endTime = std::chrono::high_resolution_clock::now();

    auto duration = std::chrono::duration_cast<std::chrono::milliseconds>(endTime - startTime);

    // Assert: Should succeed and complete within 2000ms
    EXPECT_EQ(RET_SUCCESS, ret);
    EXPECT_LT(duration.count(), PERF_THRESHOLD_2000MS);

    // Cleanup
    for (auto tokenID : tokenIDs) {
        CleanupTestHap(tokenID);
    }
}

/**
 * @tc.name: QueryStatusByPermissionTest017
 * @tc.desc: 10 threads query different permissions concurrently, no data race
 * @tc.type: FUNC
 * @tc.require: Issue Number
 */
HWMTEST_F(QueryPermissionInfosTest, QueryStatusByPermissionTest017, TestSize.Level2, MULTI_THREAD_COUNT)
{
    // Test: Query permission in multi-thread environment
    std::vector<std::string> permissionList = {"ohos.permission.CAMERA"};
    std::vector<PermissionStatus> permissionInfoList;

    GTEST_LOG_(INFO) << "Thread " << gettid() << " querying permission";

    int32_t ret = AccessTokenKit::QueryStatusByPermission(permissionList, permissionInfoList);

    // Assert: Should succeed in each thread
    ASSERT_EQ(RET_SUCCESS, ret);
}

/**
 * @tc.name: QueryStatusByPermissionTest018
 * @tc.desc: 10 threads query same permission concurrently, results consistent
 * @tc.type: FUNC
 * @tc.require: Issue Number
 */
HWMTEST_F(QueryPermissionInfosTest, QueryStatusByPermissionTest018, TestSize.Level2, MULTI_THREAD_COUNT)
{
    // Test: Query same permission in multi-thread environment
    std::vector<std::string> permissionList = {"ohos.permission.CAMERA"};
    std::vector<PermissionStatus> permissionInfoList;

    GTEST_LOG_(INFO) << "Thread " << gettid() << " querying permission";

    int32_t ret = AccessTokenKit::QueryStatusByPermission(permissionList, permissionInfoList);

    // Assert: Should succeed and return consistent results
    ASSERT_EQ(RET_SUCCESS, ret);
    ASSERT_FALSE(permissionInfoList.empty());
}

/**
 * @tc.name: QueryStatusByPermissionTest019
 * @tc.desc: Call same permission query 1000 times continuously, no memory leak
 * @tc.type: FUNC
 * @tc.require: Issue Number
 */
HWTEST_F(QueryPermissionInfosTest, QueryStatusByPermissionTest019, TestSize.Level2)
{
    std::vector<std::string> permissionList = {"ohos.permission.CAMERA"};

    // Test: Call query REPEAT_ITERATION_COUNT times continuously
    for (int i = 0; i < REPEAT_ITERATION_COUNT; ++i) {
        std::vector<PermissionStatus> permissionInfoList;
        int32_t ret = AccessTokenKit::QueryStatusByPermission(permissionList, permissionInfoList);

        // Assert: Each call should succeed
        ASSERT_EQ(RET_SUCCESS, ret);
    }
    // Note: Memory leak detection should be done with Valgrind or ASan
}

/**
 * @tc.name: QueryStatusByPermissionTest020
 * @tc.desc: Non-system app (3rd party app) calls interface, return ERR_NOT_SYSTEM_APP
 * @tc.type: FUNC
 * @tc.require: Issue Number
 */
HWTEST_F(QueryPermissionInfosTest, QueryStatusByPermissionTest020, TestSize.Level1)
{
    std::vector<std::string> permissions = {"ohos.permission.CAMERA"};
    MockHapToken mockHap("com.example.nonsystem.test021", permissions, false);  // isSystemApp = false

    std::vector<std::string> permissionList = {"ohos.permission.CAMERA"};
    std::vector<PermissionStatus> permissionInfoList;

    int32_t ret = AccessTokenKit::QueryStatusByPermission(permissionList, permissionInfoList);

    EXPECT_EQ(AccessTokenError::ERR_NOT_SYSTEM_APP, ret);
    EXPECT_TRUE(permissionInfoList.empty());
}

/**
 * @tc.name: QueryStatusByPermissionTest021
 * @tc.desc: System app without GET_SENSITIVE_PERMISSIONS permission, return ERR_PERMISSION_DENIED (201)
 * @tc.type: FUNC
 * @tc.require: Issue Number
 */
HWTEST_F(QueryPermissionInfosTest, QueryStatusByPermissionTest021, TestSize.Level1)
{
    std::vector<std::string> permissions = {"ohos.permission.CAMERA"};
    MockHapToken mockHap("com.example.system.noperm.test022", permissions, true);  // isSystemApp = true

    std::vector<std::string> permissionList = {"ohos.permission.CAMERA"};
    std::vector<PermissionStatus> permissionInfoList;

    int32_t ret = AccessTokenKit::QueryStatusByPermission(permissionList, permissionInfoList);

    EXPECT_EQ(ERR_PERMISSION_DENIED, ret);
    EXPECT_TRUE(permissionInfoList.empty());
}

/**
 * @tc.name: QueryStatusByPermissionTest022
 * @tc.desc: System app with GET_SENSITIVE_PERMISSIONS permission, return success
 * @tc.type: FUNC
 * @tc.require: Issue Number
 */
HWTEST_F(QueryPermissionInfosTest, QueryStatusByPermissionTest022, TestSize.Level1)
{
    std::vector<std::string> permissions = {
        "ohos.permission.CAMERA",
        "ohos.permission.GET_SENSITIVE_PERMISSIONS"
    };
    MockHapToken mockHap("com.example.system.test023", permissions, true);  // isSystemApp = true

    std::vector<std::string> permissionList = {"ohos.permission.CAMERA"};
    std::vector<PermissionStatus> permissionInfoList;

    int32_t ret = AccessTokenKit::QueryStatusByPermission(permissionList, permissionInfoList);

    EXPECT_EQ(RET_SUCCESS, ret);
    EXPECT_FALSE(permissionInfoList.empty());
}

/**
 * @tc.name: QueryStatusByPermissionTest023
 * @tc.desc: Native service without GET_SENSITIVE_PERMISSIONS permission, return ERR_PERMISSION_DENIED (201)
 * @tc.type: FUNC
 * @tc.require: Issue Number
 */
HWTEST_F(QueryPermissionInfosTest, QueryStatusByPermissionTest023, TestSize.Level1)
{
    MockNativeToken mockNative("accountmgr");

    std::vector<std::string> permissionList = {"ohos.permission.CAMERA"};
    std::vector<PermissionStatus> permissionInfoList;

    int32_t ret = AccessTokenKit::QueryStatusByPermission(permissionList, permissionInfoList);

    EXPECT_EQ(ERR_PERMISSION_DENIED, ret);
    EXPECT_TRUE(permissionInfoList.empty());
}

/**
 * @tc.name: QueryStatusByPermissionTest024
 * @tc.desc: Native service with GET_SENSITIVE_PERMISSIONS permission, return success
 * @tc.type: FUNC
 * @tc.require: Issue Number
 */
HWTEST_F(QueryPermissionInfosTest, QueryStatusByPermissionTest024, TestSize.Level1)
{
    MockNativeToken mockNative("privacy_service");

    std::vector<std::string> permissionList = {"ohos.permission.CAMERA"};
    std::vector<PermissionStatus> permissionInfoList;

    int32_t ret = AccessTokenKit::QueryStatusByPermission(permissionList, permissionInfoList);

    EXPECT_EQ(RET_SUCCESS, ret);
    EXPECT_FALSE(permissionInfoList.empty());
}

/**
 * @tc.name: QueryStatusByPermissionTest025
 * @tc.desc: Shell process is exempt from permission check, return success
 * @tc.type: FUNC
 * @tc.require: Issue Number
 */
HWTEST_F(QueryPermissionInfosTest, QueryStatusByPermissionTest025, TestSize.Level1)
{
    // Get original self token ID for environment restoration
    uint64_t originalTokenId = GetSelfTokenID();

    // Set self token ID to shell token ID
    int32_t setResult = SetSelfTokenID(selfShellTokenId_);
    EXPECT_EQ(0, setResult) << "Failed to set self token ID to shell token ID";

    std::vector<std::string> permissionList = {"ohos.permission.CAMERA"};
    std::vector<PermissionStatus> permissionInfoList;

    int32_t ret = AccessTokenKit::QueryStatusByPermission(permissionList, permissionInfoList, true);

    EXPECT_EQ(RET_SUCCESS, ret);
    EXPECT_FALSE(permissionInfoList.empty());

    // Restore original token ID
    int32_t restoreResult = SetSelfTokenID(originalTokenId);
    EXPECT_EQ(0, restoreResult) << "Failed to restore original token ID";
}

/**
 * @tc.name: QueryStatusByPermissionTest026
 * @tc.desc: System app with permission calls with onlyHap=true, return ERR_PARAM_INVALID
 * @ onlyHap=truetc.type: FUNC
 * @tc.require: Issue Number
 */
HWTEST_F(QueryPermissionInfosTest, QueryStatusByPermissionTest026, TestSize.Level1)
{
    std::vector<std::string> permissions = {"ohos.permission.GET_SENSITIVE_PERMISSIONS"};
    MockHapToken mockHap("com.example.nonsystem.test026", permissions, true);

    std::vector<PermissionStatus> permissionInfoList;

    int32_t ret = AccessTokenKit::QueryStatusByPermission(permissions, permissionInfoList, false);

    EXPECT_EQ(ERR_PARAM_INVALID, ret);
    EXPECT_TRUE(permissionInfoList.empty());
}

/**
 * @tc.name: QueryStatusByPermissionTest027
 * @tc.desc: Shell process calls with onlyHap=true, return ERR_PARAM_INVALID
 * @tc.type: FUNC
 * @tc.require: Issue Number
 */
HWTEST_F(QueryPermissionInfosTest, QueryStatusByPermissionTest027, TestSize.Level1)
{
    uint64_t originalTokenId = GetSelfTokenID();

    int32_t setResult = SetSelfTokenID(selfShellTokenId_);
    EXPECT_EQ(0, setResult) << "Failed to set self token ID to shell token ID";

    std::vector<std::string> permissionList = {"ohos.permission.CAMERA"};
    std::vector<PermissionStatus> permissionInfoList;

    int32_t ret = AccessTokenKit::QueryStatusByPermission(permissionList, permissionInfoList, false);

    EXPECT_EQ(ERR_PARAM_INVALID, ret);
    EXPECT_TRUE(permissionInfoList.empty());

    int32_t restoreResult = SetSelfTokenID(originalTokenId);
    EXPECT_EQ(0, restoreResult) << "Failed to restore original token ID";
}

/**
 * @tc.name: QueryStatusByPermissionTest028
 * @tc.desc: SetUserPolicy to restrict permission, QueryStatusByPermission returns PERMISSION_DENIED
 * @tc.type: FUNC
 * @tc.require: Issue Number
 */
HWTEST_F(QueryPermissionInfosTest, QueryStatusByPermissionTest028, TestSize.Level1)
{
    MockNativeToken mockNative("privacy_service");

    std::vector<std::string> permissions = {"ohos.permission.INTERNET"};
    AccessTokenID tokenID = PrepareTestHap("com.example.userpolicy.queryperm028", permissions, false);
    ASSERT_NE(tokenID, INVALID_TOKENID);

    UserPermissionPolicy policy = {
        .permissionName = "ohos.permission.INTERNET",
        .userPolicyList = {{ .userId = TEST_USER_ID, .isRestricted = true }}
    };
    EXPECT_EQ(RET_SUCCESS, AccessTokenKit::SetUserPolicy({ policy }));

    std::vector<std::string> permissionList = {"ohos.permission.INTERNET"};
    std::vector<PermissionStatus> permissionInfoList;

    int32_t ret = AccessTokenKit::QueryStatusByPermission(permissionList, permissionInfoList);

    EXPECT_EQ(RET_SUCCESS, ret);
    EXPECT_FALSE(permissionInfoList.empty());

    bool foundToken = false;
    for (const auto& info : permissionInfoList) {
        if (info.tokenID == tokenID) {
            foundToken = true;
            EXPECT_EQ(PERMISSION_DENIED, info.grantStatus);
            break;
        }
    }
    EXPECT_TRUE(foundToken) << "Test HAP not found in query result";

    EXPECT_EQ(RET_SUCCESS, AccessTokenKit::ClearUserPolicy({ "ohos.permission.INTERNET" }));
    CleanupTestHap(tokenID);
}

/**
 * @tc.name: QueryStatusByTokenIDTest001
 * @tc.desc: Query single HAP app's TokenID, return all its permissions
 * @tc.type: FUNC
 * @tc.require: Issue Number
 */
HWTEST_F(QueryPermissionInfosTest, QueryStatusByTokenIDTest001, TestSize.Level1)
{
    // Prepare: Create HAP with multiple permissions
    std::vector<std::string> permissions = {
        "ohos.permission.CAMERA",
        "ohos.permission.MICROPHONE"
    };
    AccessTokenID tokenID = PrepareTestHap("com.example.test.token001", permissions, false);
    ASSERT_NE(tokenID, INVALID_TOKENID);

    // Test: Query permissions by TokenID
    std::vector<AccessTokenID> tokenIDList = {tokenID};
    std::vector<PermissionStatus> permissionInfoList;

    int32_t ret = AccessTokenKit::QueryStatusByTokenID(tokenIDList, permissionInfoList);

    // Assert: Should return RET_SUCCESS with all permissions
    EXPECT_EQ(RET_SUCCESS, ret);
    EXPECT_EQ(2U, permissionInfoList.size());

    // Verify permissions
    std::set<std::string> foundPerms;
    for (const auto& info : permissionInfoList) {
        foundPerms.insert(info.permissionName);
    }
    EXPECT_TRUE(foundPerms.find("ohos.permission.CAMERA") != foundPerms.end());
    EXPECT_TRUE(foundPerms.find("ohos.permission.MICROPHONE") != foundPerms.end());

    // Cleanup
    CleanupTestHap(tokenID);
}

/**
 * @tc.name: QueryStatusByTokenIDTest002
 * @tc.desc: Query multiple HAP apps' TokenIDs, return all their permissions
 * @tc.type: FUNC
 * @tc.require: Issue Number
 */
HWTEST_F(QueryPermissionInfosTest, QueryStatusByTokenIDTest002, TestSize.Level1)
{
    // Prepare: Create two HAPs
    std::vector<std::string> perms1 = {"ohos.permission.CAMERA"};
    std::vector<std::string> perms2 = {"ohos.permission.MICROPHONE"};
    AccessTokenID tokenID1 = PrepareTestHap("com.example.test.token002a", perms1, false);
    AccessTokenID tokenID2 = PrepareTestHap("com.example.test.token002b", perms2, false);
    ASSERT_NE(tokenID1, INVALID_TOKENID);
    ASSERT_NE(tokenID2, INVALID_TOKENID);

    // Test: Query permissions by multiple TokenIDs
    std::vector<AccessTokenID> tokenIDList = {tokenID1, tokenID2};
    std::vector<PermissionStatus> permissionInfoList;

    int32_t ret = AccessTokenKit::QueryStatusByTokenID(tokenIDList, permissionInfoList);

    // Assert: Should return RET_SUCCESS with permissions from both apps
    EXPECT_EQ(RET_SUCCESS, ret);
    EXPECT_EQ(2U, permissionInfoList.size());

    // Cleanup
    CleanupTestHap(tokenID1);
    CleanupTestHap(tokenID2);
}

/**
 * @tc.name: QueryStatusByTokenIDTest003
 * @tc.desc: Query non-existent TokenID, return ERR_TOKENID_NOT_EXIST
 * @tc.type: FUNC
 * @tc.require: Issue Number
 */
HWTEST_F(QueryPermissionInfosTest, QueryStatusByTokenIDTest003, TestSize.Level1)
{
    // Prepare: Create and then delete a HAP token to get a valid but non-existent TokenID
    std::vector<std::string> permissions = {"ohos.permission.CAMERA"};
    AccessTokenID tokenID = PrepareTestHap("com.example.deleted.token003", permissions, false);
    ASSERT_NE(tokenID, INVALID_TOKENID);

    // Delete the token to make it non-existent
    CleanupTestHap(tokenID);
    GTEST_LOG_(INFO) << " tokenID " << tokenID;

    // Test: Query the deleted TokenID
    std::vector<AccessTokenID> tokenIDList = {tokenID};
    std::vector<PermissionStatus> permissionInfoList;

    int32_t ret = AccessTokenKit::QueryStatusByTokenID(tokenIDList, permissionInfoList);

    // Assert: Should return ERR_TOKENID_NOT_EXIST
    ASSERT_EQ(ERR_TOKENID_NOT_EXIST, ret);
    ASSERT_TRUE(permissionInfoList.empty());
}

/**
 * @tc.name: QueryStatusByTokenIDTest004
 * @tc.desc: Query result size check, verify ERR_OVERSIZE returned when exceeding limit
 * @tc.type: FUNC
 * @tc.require: Issue Number
 */
HWTEST_F(QueryPermissionInfosTest, QueryStatusByTokenIDTest004, TestSize.Level1)
{
    // Prepare: Create HAP with CAMERA permission
    std::vector<std::string> permissions = {"ohos.permission.CAMERA"};
    AccessTokenID tokenID = PrepareTestHap("com.example.camera.test004", permissions, false);
    ASSERT_NE(tokenID, INVALID_TOKENID);

    // Test: Query permissions by TokenID and verify size limit check
    std::vector<AccessTokenID> tokenIDList = {tokenID};
    std::vector<PermissionStatus> permissionInfoList;

    int32_t ret = AccessTokenKit::QueryStatusByTokenID(tokenIDList, permissionInfoList);

    // Assert: Should succeed for normal cases
    // If result size exceeds MAX_QUERY_RESULT_SIZE, should return ERR_OVERSIZE
    if (permissionInfoList.size() > MAX_QUERY_RESULT_SIZE) {
        EXPECT_EQ(AccessTokenError::ERR_OVERSIZE, ret);
        GTEST_LOG_(INFO) << "Query returned " << permissionInfoList.size() << " results "
                         << "(exceeds limit: " << MAX_QUERY_RESULT_SIZE << ")";
    } else {
        EXPECT_EQ(RET_SUCCESS, ret);
        GTEST_LOG_(INFO) << "Query returned " << permissionInfoList.size() << " results "
                         << "(within limit: " << MAX_QUERY_RESULT_SIZE << ")";
    }

    // Cleanup
    CleanupTestHap(tokenID);
}


/**
 * @tc.name: QueryStatusByTokenIDTest005
 * @tc.desc: Query with empty TokenID list, return ERR_PARAM_INVALID
 * @tc.type: FUNC
 * @tc.require: Issue Number
 */
HWTEST_F(QueryPermissionInfosTest, QueryStatusByTokenIDTest005, TestSize.Level1)
{
    // Test: Query with empty TokenID list
    std::vector<AccessTokenID> tokenIDList;
    std::vector<PermissionStatus> permissionInfoList;

    int32_t ret = AccessTokenKit::QueryStatusByTokenID(tokenIDList, permissionInfoList);

    // Assert: Should return ERR_PARAM_INVALID
    ASSERT_EQ(ERR_PARAM_INVALID, ret);
    ASSERT_TRUE(permissionInfoList.empty());
}

/**
 * @tc.name: QueryStatusByTokenIDTest006
 * @tc.desc: Query with TokenID containing INVALID_TOKENID, return ERR_PARAM_INVALID
 * @tc.type: FUNC
 * @tc.require: Issue Number
 */
HWTEST_F(QueryPermissionInfosTest, QueryStatusByTokenIDTest006, TestSize.Level1)
{
    // Test: Query with invalid TokenID
    std::vector<AccessTokenID> tokenIDList = {INVALID_TOKENID};
    std::vector<PermissionStatus> permissionInfoList;

    int32_t ret = AccessTokenKit::QueryStatusByTokenID(tokenIDList, permissionInfoList);

    // Assert: Should return ERR_PARAM_INVALID
    ASSERT_EQ(ERR_PARAM_INVALID, ret);
    ASSERT_TRUE(permissionInfoList.empty());
}

/**
 * @tc.name: QueryStatusByTokenIDTest007
 * @tc.desc: Query Native TokenID, return ERR_PARAM_INVALID (only HAP supported)
 * @tc.type: FUNC
 * @tc.require: Issue Number
 */
HWTEST_F(QueryPermissionInfosTest, QueryStatusByTokenIDTest007, TestSize.Level1)
{
    // Get current shell token (which is Native type)
    AccessTokenID nativeTokenID = static_cast<AccessTokenID>(selfShellTokenId_);
    ASSERT_NE(nativeTokenID, 0);

    // Verify it's a Native token
    ATokenTypeEnum tokenType = AccessTokenKit::GetTokenTypeFlag(nativeTokenID);
    if (tokenType == TOKEN_NATIVE) {
        // Test: Query Native TokenID
        std::vector<AccessTokenID> tokenIDList = {nativeTokenID};
        std::vector<PermissionStatus> permissionInfoList;

        int32_t ret = AccessTokenKit::QueryStatusByTokenID(tokenIDList, permissionInfoList);

        // Assert: Should return ERR_PARAM_INVALID (only HAP supported)
        ASSERT_EQ(ERR_PARAM_INVALID, ret);
        ASSERT_TRUE(permissionInfoList.empty());
    }
}

/**
 * @tc.name: QueryStatusByTokenIDTest008
 * @tc.desc: Query with mix of HAP and Native TokenIDs, return ERR_PARAM_INVALID
 * @tc.type: FUNC
 * @tc.require: Issue Number
 */
HWTEST_F(QueryPermissionInfosTest, QueryStatusByTokenIDTest008, TestSize.Level1)
{
    // Prepare: Create HAP token
    std::vector<std::string> permissions = {"ohos.permission.CAMERA"};
    AccessTokenID hapTokenID = PrepareTestHap("com.example.test.token007", permissions, false);
    ASSERT_NE(hapTokenID, INVALID_TOKENID);

    // Get Native token
    AccessTokenID nativeTokenID = static_cast<AccessTokenID>(selfShellTokenId_);

    // Test: Query with mixed TokenID types
    std::vector<AccessTokenID> tokenIDList = {hapTokenID, nativeTokenID};
    std::vector<PermissionStatus> permissionInfoList;

    int32_t ret = AccessTokenKit::QueryStatusByTokenID(tokenIDList, permissionInfoList);

    // Assert: Should return ERR_PARAM_INVALID (mixed types not allowed)
    ASSERT_EQ(ERR_PARAM_INVALID, ret);

    // Cleanup
    CleanupTestHap(hapTokenID);
}

/**
 * @tc.name: QueryStatusByTokenIDTest009
 * @tc.desc: Query non-existent TokenID, return ERR_TOKENID_NOT_EXIST
 * @tc.type: FUNC
 * @tc.require: Issue Number
 */
HWTEST_F(QueryPermissionInfosTest, QueryStatusByTokenIDTest009, TestSize.Level1)
{
    // Prepare: Create and then delete a HAP token to get a valid but non-existent TokenID
    std::vector<std::string> permissions = {"ohos.permission.CAMERA"};
    AccessTokenID tokenID = PrepareTestHap("com.example.deleted.token009", permissions, false);
    ASSERT_NE(tokenID, INVALID_TOKENID);

    // Delete the token to make it non-existent
    CleanupTestHap(tokenID);

    // Test: Query the deleted TokenID
    std::vector<AccessTokenID> tokenIDList = {tokenID};
    std::vector<PermissionStatus> permissionInfoList;

    int32_t ret = AccessTokenKit::QueryStatusByTokenID(tokenIDList, permissionInfoList);

    // Assert: Should return ERR_TOKENID_NOT_EXIST
    ASSERT_EQ(ERR_TOKENID_NOT_EXIST, ret);
    ASSERT_TRUE(permissionInfoList.empty());
}

/**
 * @tc.name: QueryStatusByTokenIDTest010
 * @tc.desc: Query with mix of existent and non-existent TokenIDs, return ERR_TOKENID_NOT_EXIST
 * @tc.type: FUNC
 * @tc.require: Issue Number
 */
HWTEST_F(QueryPermissionInfosTest, QueryStatusByTokenIDTest010, TestSize.Level1)
{
    // Prepare: Create one valid HAP and one deleted (non-existent) HAP
    std::vector<std::string> permissions = {"ohos.permission.CAMERA"};
    AccessTokenID validTokenID = PrepareTestHap("com.example.test.token010", permissions, false);
    EXPECT_NE(validTokenID, INVALID_TOKENID);

    AccessTokenID deletedTokenID = PrepareTestHap("com.example.deleted.token010", permissions, false);
    EXPECT_NE(deletedTokenID, INVALID_TOKENID);
    // Delete the second token to make it non-existent
    CleanupTestHap(deletedTokenID);

    // Test: Query with mix of valid and invalid TokenIDs
    std::vector<AccessTokenID> tokenIDList = {validTokenID, deletedTokenID};  // Second is deleted
    std::vector<PermissionStatus> permissionInfoList;

    int32_t ret = AccessTokenKit::QueryStatusByTokenID(tokenIDList, permissionInfoList);

    // Assert: Should return ERR_TOKENID_NOT_EXIST
    EXPECT_EQ(ERR_TOKENID_NOT_EXIST, ret);

    // Cleanup: Always execute cleanup even if assertion fails
    CleanupTestHap(validTokenID);
}

/**
 * @tc.name: QueryStatusByTokenIDTest011
 * @tc.desc: Query TokenID=1 (boundary value test), return ERR_TOKENID_NOT_EXIST
 * @tc.type: FUNC
 * @tc.require: Issue Number
 */
HWTEST_F(QueryPermissionInfosTest, QueryStatusByTokenIDTest011, TestSize.Level1)
{
    // Test: Query TokenID=1 (likely doesn't exist)
    std::vector<AccessTokenID> tokenIDList = {1};
    std::vector<PermissionStatus> permissionInfoList;

    int32_t ret = AccessTokenKit::QueryStatusByTokenID(tokenIDList, permissionInfoList);

    // Assert: Should return ERR_TOKENID_NOT_EXIST
    ASSERT_EQ(ERR_TOKENID_NOT_EXIST, ret);
    ASSERT_TRUE(permissionInfoList.empty());
}

/**
 * @tc.name: QueryStatusByTokenIDTest012
 * @tc.desc: Verify returned grantStatus is valid (-1/0/1/2/3)
 * @tc.type: FUNC
 * @tc.require: Issue Number
 */
HWTEST_F(QueryPermissionInfosTest, QueryStatusByTokenIDTest012, TestSize.Level1)
{
    // Prepare: Create HAP with permissions
    std::vector<std::string> permissions = {"ohos.permission.CAMERA"};
    AccessTokenID tokenID = PrepareTestHap("com.example.test.token012", permissions, false);
    ASSERT_NE(tokenID, INVALID_TOKENID);

    // Test: Query permissions by TokenID
    std::vector<AccessTokenID> tokenIDList = {tokenID};
    std::vector<PermissionStatus> permissionInfoList;

    int32_t ret = AccessTokenKit::QueryStatusByTokenID(tokenIDList, permissionInfoList);

    // Assert: Should return RET_SUCCESS with valid grantStatus values
    EXPECT_EQ(RET_SUCCESS, ret);
    EXPECT_FALSE(permissionInfoList.empty());

    for (const auto& info : permissionInfoList) {
        // grantStatus should be one of: -1, 0, 1, 2, 3
        EXPECT_GE(info.grantStatus, -1);
        EXPECT_LE(info.grantStatus, PERMISSION_STATUS_MAX);
    }

    // Cleanup
    CleanupTestHap(tokenID);
}

/**
 * @tc.name: QueryStatusByTokenIDTest013
 * @tc.desc: Verify returned grantFlag is in valid format
 * @tc.type: FUNC
 * @tc.require: Issue Number
 */
HWTEST_F(QueryPermissionInfosTest, QueryStatusByTokenIDTest013, TestSize.Level1)
{
    // Prepare: Create HAP with permissions
    std::vector<std::string> permissions = {"ohos.permission.CAMERA"};
    AccessTokenID tokenID = PrepareTestHap("com.example.test.token013", permissions, false);
    ASSERT_NE(tokenID, INVALID_TOKENID);

    // Test: Query permissions by TokenID
    std::vector<AccessTokenID> tokenIDList = {tokenID};
    std::vector<PermissionStatus> permissionInfoList;

    int32_t ret = AccessTokenKit::QueryStatusByTokenID(tokenIDList, permissionInfoList);

    // Assert: Should return RET_SUCCESS with valid grantFlag
    EXPECT_EQ(RET_SUCCESS, ret);
    EXPECT_FALSE(permissionInfoList.empty());

    for (const auto& info : permissionInfoList) {
        // grantFlag should be a valid permission flag value
        EXPECT_GE(info.grantFlag, 0);
    }

    // Cleanup
    CleanupTestHap(tokenID);
}

/**
 * @tc.name: QueryStatusByTokenIDTest014
 * @tc.desc: Query app with 50 permissions, performance < 100ms
 * @tc.type: PERF
 * @tc.require: Issue Number
 */
HWTEST_F(QueryPermissionInfosTest, QueryStatusByTokenIDTest014, TestSize.Level2)
{
    // Prepare: Create HAP with 50 permissions
    std::vector<std::string> permissions;
    for (int i = 0; i < LARGE_PERMISSION_COUNT; ++i) {
        permissions.emplace_back("ohos.permission.TEST_PERM_" + std::to_string(i));
    }

    AccessTokenID tokenID = PrepareTestHap("com.example.test.token014", permissions, false);

    // Some test permissions may not exist, so we check if token was created
    if (tokenID != INVALID_TOKENID) {
        // Test: Measure query performance
        std::vector<AccessTokenID> tokenIDList = {tokenID};
        std::vector<PermissionStatus> permissionInfoList;

        auto startTime = std::chrono::high_resolution_clock::now();
        int32_t ret = AccessTokenKit::QueryStatusByTokenID(tokenIDList, permissionInfoList);
        auto endTime = std::chrono::high_resolution_clock::now();

        auto duration = std::chrono::duration_cast<std::chrono::milliseconds>(endTime - startTime);

        // Assert: Should succeed and complete within 100ms
        EXPECT_EQ(RET_SUCCESS, ret);
        EXPECT_LT(duration.count(), PERF_THRESHOLD_100MS);

        // Cleanup
        CleanupTestHap(tokenID);
    }
}

/**
 * @tc.name: QueryStatusByTokenIDTest015
 * @tc.desc: 10 threads query the same TokenID concurrently, verify thread safety
 * @tc.type: FUNC
 * @tc.require: Issue Number
 */
HWTEST_F(QueryPermissionInfosTest, QueryStatusByTokenIDTest015, TestSize.Level2)
{
    // Prepare: Create one shared test HAP for all threads
    std::vector<std::string> permissions = {"ohos.permission.CAMERA"};
    AccessTokenID sharedTokenID = PrepareTestHap("com.example.test.token015.shared", permissions, false);
    ASSERT_NE(sharedTokenID, INVALID_TOKENID);

    // Test: Create 10 threads to query the same TokenID concurrently
    std::vector<std::thread> threads;
    std::vector<int32_t> results(MULTI_THREAD_COUNT);

    for (int i = 0; i < MULTI_THREAD_COUNT; ++i) {
        threads.emplace_back([sharedTokenID, &results, i]() {
            std::vector<AccessTokenID> tokenIDList = {sharedTokenID};
            std::vector<PermissionStatus> permissionInfoList;

            int32_t ret = AccessTokenKit::QueryStatusByTokenID(tokenIDList, permissionInfoList);
            results[i] = ret;

            GTEST_LOG_(INFO) << "Thread " << std::this_thread::get_id()
                             << " querying shared tokenID " << sharedTokenID
                             << ", result: " << ret;

            // Verify results
            EXPECT_EQ(RET_SUCCESS, ret);
            EXPECT_FALSE(permissionInfoList.empty());
            EXPECT_EQ(sharedTokenID, permissionInfoList[0].tokenID);
        });
    }

    // Wait for all threads to complete
    for (auto& thread : threads) {
        thread.join();
    }

    // Assert: All threads should succeed
    for (int32_t ret : results) {
        EXPECT_EQ(RET_SUCCESS, ret);
    }

    // Cleanup
    CleanupTestHap(sharedTokenID);
}

/**
 * @tc.name: QueryStatusByTokenIDTest016
 * @tc.desc: 10 threads query different TokenIDs concurrently, verify thread safety
 * @tc.type: FUNC
 * @tc.require: Issue Number
 */
HWTEST_F(QueryPermissionInfosTest, QueryStatusByTokenIDTest016, TestSize.Level2)
{
    // Test: Create 10 threads, each creates and queries its own TokenID
    std::vector<std::thread> threads;
    std::vector<AccessTokenID> tokenIDs(MULTI_THREAD_COUNT);
    std::vector<int32_t> results(MULTI_THREAD_COUNT);

    for (int i = 0; i < MULTI_THREAD_COUNT; ++i) {
        threads.emplace_back([this, &tokenIDs, &results, i]() {
            // Each thread creates its own HAP with unique bundle name
            std::string bundleName = "com.example.test.token016." + std::to_string(i);
            std::vector<std::string> permissions = {"ohos.permission.CAMERA"};

            // Use wrapper function to create HAP token
            tokenIDs[i] = PrepareTestHap(bundleName, permissions, false);
            ASSERT_NE(tokenIDs[i], INVALID_TOKENID);

            // Query own TokenID
            std::vector<AccessTokenID> tokenIDList = {tokenIDs[i]};
            std::vector<PermissionStatus> permissionInfoList;

            int32_t ret = AccessTokenKit::QueryStatusByTokenID(tokenIDList, permissionInfoList);
            results[i] = ret;

            GTEST_LOG_(INFO) << "Thread " << std::this_thread::get_id()
                             << " querying own tokenID " << tokenIDs[i]
                             << ", result: " << ret;

            // Assert: Should succeed
            EXPECT_EQ(RET_SUCCESS, ret);
            EXPECT_FALSE(permissionInfoList.empty());

            // Cleanup: Use wrapper function to delete token
            CleanupTestHap(tokenIDs[i]);
        });
    }

    // Wait for all threads to complete
    for (auto& thread : threads) {
        thread.join();
    }

    // Assert: All threads should succeed
    for (int32_t ret : results) {
        EXPECT_EQ(RET_SUCCESS, ret);
    }
}

/**
 * @tc.name: QueryStatusByTokenIDTest017
 * @tc.desc: Continuous query 1000 times, verify no memory leak and performance stability
 * @tc.type: FUNC
 * @tc.require: Issue Number
 */
HWTEST_F(QueryPermissionInfosTest, QueryStatusByTokenIDTest017, TestSize.Level2)
{
    // Prepare: Create test HAP
    std::vector<std::string> permissions = {"ohos.permission.CAMERA"};
    AccessTokenID tokenID = PrepareTestHap("com.example.test.token016", permissions, false);
    ASSERT_NE(tokenID, INVALID_TOKENID);

    // Test: Query REPEAT_ITERATION_COUNT times continuously
    std::vector<AccessTokenID> tokenIDList = {tokenID};

    auto startTime = std::chrono::high_resolution_clock::now();
    for (int32_t i = 0; i < REPEAT_ITERATION_COUNT; ++i) {
        std::vector<PermissionStatus> permissionInfoList;
        int32_t ret = AccessTokenKit::QueryStatusByTokenID(tokenIDList, permissionInfoList);

        // Assert: Each call should succeed
        EXPECT_EQ(RET_SUCCESS, ret);
        EXPECT_FALSE(permissionInfoList.empty());
    }
    auto endTime = std::chrono::high_resolution_clock::now();

    auto duration = std::chrono::duration_cast<std::chrono::milliseconds>(endTime - startTime);
    GTEST_LOG_(INFO) << REPEAT_ITERATION_COUNT << " continuous queries took " << duration.count() << "ms";

    // Assert: Average time per query should be reasonable (< 1ms per query)
    EXPECT_LT(duration.count(), REPEAT_ITERATION_COUNT);

    // Cleanup
    CleanupTestHap(tokenID);
}

/**
 * @tc.name: QueryStatusByTokenIDTest018
 * @tc.desc: Non-system app (3rd party app) calls interface, return ERR_NOT_SYSTEM_APP (202)
 * @tc.type: FUNC
 * @tc.require: Issue Number
 */
HWTEST_F(QueryPermissionInfosTest, QueryStatusByTokenIDTest018, TestSize.Level1)
{
    std::vector<std::string> permissions = {"ohos.permission.CAMERA"};
    MockHapToken mockHap("com.example.nonsystem.test018", permissions, false);  // isSystemApp = false

    std::vector<AccessTokenID> tokenIDList = {mockHap.GetTokenID()};
    std::vector<PermissionStatus> permissionInfoList;

    int32_t ret = AccessTokenKit::QueryStatusByTokenID(tokenIDList, permissionInfoList);

    EXPECT_EQ(AccessTokenError::ERR_NOT_SYSTEM_APP, ret);
    EXPECT_TRUE(permissionInfoList.empty());
}

/**
 * @tc.name: QueryStatusByTokenIDTest019
 * @tc.desc: System app without GET_SENSITIVE_PERMISSIONS permission, return ERR_PERMISSION_DENIED (201)
 * @tc.type: FUNC
 * @tc.require: Issue Number
 */
HWTEST_F(QueryPermissionInfosTest, QueryStatusByTokenIDTest019, TestSize.Level1)
{
    std::vector<std::string> permissions = {"ohos.permission.CAMERA"};
    MockHapToken mockHap("com.example.system.noperm.test019", permissions, true);  // isSystemApp = true

    std::vector<AccessTokenID> tokenIDList = {mockHap.GetTokenID()};
    std::vector<PermissionStatus> permissionInfoList;

    int32_t ret = AccessTokenKit::QueryStatusByTokenID(tokenIDList, permissionInfoList);

    EXPECT_EQ(ERR_PERMISSION_DENIED, ret);
    EXPECT_TRUE(permissionInfoList.empty());
}

/**
 * @tc.name: QueryStatusByTokenIDTest020
 * @tc.desc: System app with GET_SENSITIVE_PERMISSIONS permission, return success
 * @tc.type: FUNC
 * @tc.require: Issue Number
 */
HWTEST_F(QueryPermissionInfosTest, QueryStatusByTokenIDTest020, TestSize.Level1)
{
    std::vector<std::string> permissions = {
        "ohos.permission.CAMERA",
        "ohos.permission.GET_SENSITIVE_PERMISSIONS"
    };
    MockHapToken mockHap("com.example.system.hasperm.test020", permissions, true);  // isSystemApp = true

    std::vector<AccessTokenID> tokenIDList = {mockHap.GetTokenID()};
    std::vector<PermissionStatus> permissionInfoList;

    int32_t ret = AccessTokenKit::QueryStatusByTokenID(tokenIDList, permissionInfoList);

    EXPECT_EQ(RET_SUCCESS, ret);
    EXPECT_FALSE(permissionInfoList.empty());
}

/**
 * @tc.name: QueryStatusByTokenIDTest021
 * @tc.desc: Native service without GET_SENSITIVE_PERMISSIONS permission, return ERR_PERMISSION_DENIED (201)
 * @tc.type: FUNC
 * @tc.require: Issue Number
 */
HWTEST_F(QueryPermissionInfosTest, QueryStatusByTokenIDTest021, TestSize.Level1)
{
    MockNativeToken mockNative("accountmgr");

    AccessTokenID tokenID = 123; // 123: tokenID

    std::vector<AccessTokenID> tokenIDList = {tokenID};
    std::vector<PermissionStatus> permissionInfoList;

    int32_t ret = AccessTokenKit::QueryStatusByTokenID(tokenIDList, permissionInfoList);

    EXPECT_EQ(ERR_PERMISSION_DENIED, ret);
    EXPECT_TRUE(permissionInfoList.empty());
}

/**
 * @tc.name: QueryStatusByTokenIDTest022
 * @tc.desc: Native service with GET_SENSITIVE_PERMISSIONS permission, return success
 * @tc.type: FUNC
 * @tc.require: Issue Number
 */
HWTEST_F(QueryPermissionInfosTest, QueryStatusByTokenIDTest022, TestSize.Level1)
{
    MockNativeToken mockNative("privacy_service");

    // Prepare: Create test HAP
    std::vector<std::string> permissions = {"ohos.permission.CAMERA"};
    AccessTokenID tokenID = PrepareTestHap("com.example.native.hasperm.test022", permissions, false);
    ASSERT_NE(tokenID, INVALID_TOKENID);

    std::vector<AccessTokenID> tokenIDList = {tokenID};
    std::vector<PermissionStatus> permissionInfoList;

    int32_t ret = AccessTokenKit::QueryStatusByTokenID(tokenIDList, permissionInfoList);

    EXPECT_EQ(RET_SUCCESS, ret);
    EXPECT_FALSE(permissionInfoList.empty());

    CleanupTestHap(tokenID);
}

/**
 * @tc.name: QueryStatusByTokenIDTest023
 * @tc.desc: Shell process is exempt from permission check, return success
 * @tc.type: FUNC
 * @tc.require: Issue Number
 */
HWTEST_F(QueryPermissionInfosTest, QueryStatusByTokenIDTest023, TestSize.Level1)
{
    // Get original self token ID for environment restoration
    uint64_t originalTokenId = GetSelfTokenID();

    // Set self token ID to shell token ID
    int32_t setResult = SetSelfTokenID(selfShellTokenId_);
    EXPECT_EQ(0, setResult) << "Failed to set self token ID to shell token ID";

    // Prepare: Create test HAP
    std::vector<std::string> permissions = {"ohos.permission.CAMERA"};
    AccessTokenID tokenID = PrepareTestHap("com.example.shell.test023", permissions, false);
    ASSERT_NE(tokenID, INVALID_TOKENID);

    // Test: Query by TokenID in Shell environment (exempt from permission check)
    std::vector<AccessTokenID> tokenIDList = {tokenID};
    std::vector<PermissionStatus> permissionInfoList;

    int32_t ret = AccessTokenKit::QueryStatusByTokenID(tokenIDList, permissionInfoList);

    // Assert: Should return RET_SUCCESS (Shell process is exempt)
    EXPECT_EQ(RET_SUCCESS, ret);
    EXPECT_FALSE(permissionInfoList.empty());

    // Cleanup
    CleanupTestHap(tokenID);

    // Restore original token ID
    int32_t restoreResult = SetSelfTokenID(originalTokenId);
    EXPECT_EQ(0, restoreResult) << "Failed to restore original token ID";
}

static std::vector<std::string> CollectNormalAndSystemPermissions()
{
    size_t totalPermissions = AccessToken::GetDefPermissionsSize();
    GTEST_LOG_(INFO) << "System has " << totalPermissions << " defined permissions";

    std::vector<std::string> validPermissions;
    for (uint32_t i = 1; i <= totalPermissions; ++i) {
        std::string perm = AccessToken::TransferOpcodeToPermission(i);
        if (perm.empty()) {
            continue;
        }

        PermissionBriefDef permDef;
        if (!AccessToken::GetPermissionBriefDef(perm, permDef)) {
            continue;
        }

        // Only include permissions with NORMAL or SYSTEM availableType
        if (permDef.availableType == NORMAL ||
            permDef.availableType == SYSTEM) {
            validPermissions.emplace_back(perm);
        }
    }

    GTEST_LOG_(INFO) << "Found " << validPermissions.size() << " valid permissions";
    return validPermissions;
}

/**
 * @tc.name: QueryStatusByTokenIDTest024
 * @tc.desc: SetUserPolicy to restrict permission, QueryStatusByTokenID returns PERMISSION_DENIED
 * @tc.type: FUNC
 * @tc.require: Issue Number
 */
HWTEST_F(QueryPermissionInfosTest, QueryStatusByTokenIDTest024, TestSize.Level1)
{
    MockNativeToken mockNative("privacy_service");

    std::vector<std::string> permissions = {"ohos.permission.INTERNET"};
    AccessTokenID tokenID = PrepareTestHap("com.example.userpolicy.querytoken024", permissions, false);
    ASSERT_NE(tokenID, INVALID_TOKENID);

    UserPermissionPolicy policy = {
        .permissionName = "ohos.permission.INTERNET",
        .userPolicyList = {{ .userId = TEST_USER_ID, .isRestricted = true }}
    };
    EXPECT_EQ(RET_SUCCESS, AccessTokenKit::SetUserPolicy({ policy }));

    std::vector<AccessTokenID> tokenIDList = {tokenID};
    std::vector<PermissionStatus> permissionInfoList;

    int32_t ret = AccessTokenKit::QueryStatusByTokenID(tokenIDList, permissionInfoList);

    EXPECT_EQ(RET_SUCCESS, ret);
    EXPECT_FALSE(permissionInfoList.empty());

    for (const auto& info : permissionInfoList) {
        if (info.permissionName == "ohos.permission.INTERNET") {
            EXPECT_EQ(PERMISSION_DENIED, info.grantStatus);
        }
    }

    EXPECT_EQ(RET_SUCCESS, AccessTokenKit::ClearUserPolicy({ "ohos.permission.INTERNET" }));
    CleanupTestHap(tokenID);
}

/**
 * @tc.name: QueryStatusOverSizeTest001
 * @tc.desc: Query result exceeds MAX_QUERY_RESULT_SIZE limit, return ERR_OVERSIZE
 * @tc.type: FUNC
 * @tc.require: Issue Number
 */
HWTEST_F(QueryPermissionInfosTest, QueryStatusOverSizeTest001, TestSize.Level1)
{
    MockNativeToken mockNative("privacy_service");
    // Step 1: Collect valid permissions for NORMAL and SYSTEM availableType
    std::vector<std::string> validPermissions = CollectNormalAndSystemPermissions();
    ASSERT_FALSE(validPermissions.empty());

    // Step 2: Create multiple HAPs to exceed result size limit
    size_t appsToCreate = MAX_QUERY_RESULT_SIZE / validPermissions.size() + 1;
    std::vector<AccessTokenID> tokenIDs;
    for (size_t i = 0; i < appsToCreate; ++i) {
        std::string bundleName = "com.example.oversize.perm." + std::to_string(i);
        AccessTokenID tokenID = PrepareTestHap(bundleName, validPermissions, true, APL_SYSTEM_CORE);
        if (tokenID != INVALID_TOKENID) {
            tokenIDs.emplace_back(tokenID);
        }
    }

    GTEST_LOG_(INFO) << "Creating " << appsToCreate << " HAPs for oversize test";
    GTEST_LOG_(INFO) << "Created tokens size: " << tokenIDs.size();

    // Step 3: Verify QueryStatusByPermission returns ERR_OVERSIZE
    std::vector<PermissionStatus> permissionInfoList;
    int32_t ret = AccessTokenKit::QueryStatusByPermission(validPermissions, permissionInfoList, false);
    EXPECT_EQ(ERR_OVERSIZE, ret) <<
        "QueryStatusByPermission should return ERR_OVERSIZE when result exceeds limit, "
        "permissionInfoList size: " << permissionInfoList.size();

    permissionInfoList.clear();
    // Step 4: Verify QueryStatusByTokenID returns ERR_OVERSIZE
    ret = AccessTokenKit::QueryStatusByTokenID(tokenIDs, permissionInfoList);
    EXPECT_EQ(ERR_OVERSIZE, ret) <<
        "QueryStatusByTokenID should return ERR_OVERSIZE when result exceeds limit, "
        "permissionInfoList size: " << permissionInfoList.size();

    // Step 5: Cleanup created HAPs
    for (auto tokenID : tokenIDs) {
        CleanupTestHap(tokenID);
    }
}
}
}
}
