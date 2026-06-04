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

#include "access_token.h"
#include "access_token_error.h"
#define private public
#include "accesstoken_id_manager.h"
#undef private

using namespace testing::ext;

namespace OHOS {
namespace Security {
namespace AccessToken {
namespace {
constexpr AccessTokenID TEST_TOKEN_ID = 0x20000001;
constexpr AccessTokenID TEST_TOKEN_ID_2 = 0x20000002;
}

class AccessTokenIdManagerCoverageTest : public testing::Test {
public:
    static void SetUpTestCase() {}
    static void TearDownTestCase() {}

    void SetUp()
    {
        AccessTokenIDManager::GetInstance().tokenIdSet_.clear();
        AccessTokenIDManager::GetInstance().reservedTokenIdSet_.clear();
        AccessTokenIDManager::GetInstance().untrustedTokenIdSet_.clear();
        AccessTokenIDManager::GetInstance().bundleIdSet_.clear();
        // Reset migration done flag for test isolation
        {
            std::unique_lock<std::mutex> lock(AccessTokenIDManager::GetInstance().migrationLock_);
            AccessTokenIDManager::GetInstance().migrationDone_ = false;
        }
    }

    void TearDown()
    {
        AccessTokenIDManager::GetInstance().tokenIdSet_.clear();
        AccessTokenIDManager::GetInstance().reservedTokenIdSet_.clear();
        AccessTokenIDManager::GetInstance().untrustedTokenIdSet_.clear();
        AccessTokenIDManager::GetInstance().bundleIdSet_.clear();
        // Reset migration done flag after test
        {
            std::unique_lock<std::mutex> lock(AccessTokenIDManager::GetInstance().migrationLock_);
            AccessTokenIDManager::GetInstance().migrationDone_ = false;
        }
    }
};

/*
 * @tc.name: InitSingleBundleIdCache001
 * @tc.desc: Valid uid is extracted and inserted into bundleIdSet_
 * @tc.type: FUNC
 * @tc.require: TDD
 */
HWTEST_F(AccessTokenIdManagerCoverageTest, InitSingleBundleIdCache001, TestSize.Level4)
{
    // uid=10000, bundleId = 10000 % 200000 = 10000 (valid range [10000, 65535])
    AccessTokenIDManager::GetInstance().InitSingleBundleIdCache(10000);
    ASSERT_EQ(1U, AccessTokenIDManager::GetInstance().bundleIdSet_.size());
    ASSERT_EQ(1U, AccessTokenIDManager::GetInstance().bundleIdSet_.count(10000));
}

/*
 * @tc.name: InitSingleBundleIdCache002
 * @tc.desc: Negative uid is rejected; bundleIdSet_ remains empty
 * @tc.type: FUNC
 * @tc.require: TDD
 */
HWTEST_F(AccessTokenIdManagerCoverageTest, InitSingleBundleIdCache002, TestSize.Level4)
{
    AccessTokenIDManager::GetInstance().InitSingleBundleIdCache(-1);
    ASSERT_TRUE(AccessTokenIDManager::GetInstance().bundleIdSet_.empty());
}

/*
 * @tc.name: InitSingleBundleIdCache003
 * @tc.desc: uid whose bundleId falls below BUNDLE_ID_MIN(10000) is rejected
 * @tc.type: FUNC
 * @tc.require: TDD
 */
HWTEST_F(AccessTokenIdManagerCoverageTest, InitSingleBundleIdCache003, TestSize.Level4)
{
    // uid=5000, bundleId = 5000 < 10000 → invalid
    AccessTokenIDManager::GetInstance().InitSingleBundleIdCache(5000);
    ASSERT_TRUE(AccessTokenIDManager::GetInstance().bundleIdSet_.empty());
}

/*
 * @tc.name: ImportInitialUids001
 * @tc.desc: Import valid uids into empty cache succeeds and populates bundleIdSet_
 * @tc.type: FUNC
 * @tc.require: TDD
 */
HWTEST_F(AccessTokenIdManagerCoverageTest, ImportInitialUids001, TestSize.Level4)
{
    std::vector<int32_t> uids = {10000, 10001, 10002};
    ASSERT_EQ(RET_SUCCESS, AccessTokenIDManager::GetInstance().ImportInitialUids(uids));
    ASSERT_EQ(3U, AccessTokenIDManager::GetInstance().bundleIdSet_.size());
    ASSERT_EQ(1U, AccessTokenIDManager::GetInstance().bundleIdSet_.count(10000));
    ASSERT_EQ(1U, AccessTokenIDManager::GetInstance().bundleIdSet_.count(10001));
    ASSERT_EQ(1U, AccessTokenIDManager::GetInstance().bundleIdSet_.count(10002));
}

/*
 * @tc.name: ImportInitialUids002
 * @tc.desc: Mixed valid/invalid uids: invalid ones are silently skipped
 * @tc.type: FUNC
 * @tc.require: TDD
 */
HWTEST_F(AccessTokenIdManagerCoverageTest, ImportInitialUids002, TestSize.Level4)
{
    // -1: negative; 5000: bundleId < 10000; 10000, 10001: valid
    std::vector<int32_t> uids = {-1, 5000, 10000, 10001};
    ASSERT_EQ(RET_SUCCESS, AccessTokenIDManager::GetInstance().ImportInitialUids(uids));
    ASSERT_EQ(2U, AccessTokenIDManager::GetInstance().bundleIdSet_.size());
    ASSERT_EQ(1U, AccessTokenIDManager::GetInstance().bundleIdSet_.count(10000));
    ASSERT_EQ(1U, AccessTokenIDManager::GetInstance().bundleIdSet_.count(10001));
}

/*
 * @tc.name: RemoveBundleId001
 * @tc.desc: Remove existing bundleId succeeds and removes it from cache
 * @tc.type: FUNC
 * @tc.require: TDD
 */
HWTEST_F(AccessTokenIdManagerCoverageTest, RemoveBundleId001, TestSize.Level4)
{
    AccessTokenIDManager::GetInstance().bundleIdSet_.insert(10000);
    ASSERT_EQ(RET_SUCCESS, AccessTokenIDManager::GetInstance().RemoveBundleId(10000));
    ASSERT_TRUE(AccessTokenIDManager::GetInstance().bundleIdSet_.empty());
}

/*
 * @tc.name: RemoveBundleId002
 * @tc.desc: Remove absent bundleId returns RET_SUCCESS (lenient policy)
 * @tc.type: FUNC
 * @tc.require: TDD
 */
HWTEST_F(AccessTokenIdManagerCoverageTest, RemoveBundleId002, TestSize.Level4)
{
    ASSERT_EQ(RET_SUCCESS, AccessTokenIDManager::GetInstance().RemoveBundleId(10000));
}

/*
 * @tc.name: RemoveBundleId003
 * @tc.desc: Invalid uid returns ERR_PARAM_INVALID
 * @tc.type: FUNC
 * @tc.require: TDD
 */
HWTEST_F(AccessTokenIdManagerCoverageTest, RemoveBundleId003, TestSize.Level4)
{
    ASSERT_EQ(ERR_PARAM_INVALID, AccessTokenIDManager::GetInstance().RemoveBundleId(-1));
}

/*
 * @tc.name: TranslateUid001
 * @tc.desc: Valid srcUid is translated to correct outUid for dstLocalId
 * @tc.type: FUNC
 * @tc.require: TDD
 */
HWTEST_F(AccessTokenIdManagerCoverageTest, TranslateUid001, TestSize.Level4)
{
    // Extract bundleId(10000) from srcUid(20010000),
    // then compute new uid using dstLocalId(101): 101*200000+10000=20210000
    int32_t outUid = 0;
    ASSERT_EQ(RET_SUCCESS, AccessTokenIDManager::GetInstance().TranslateUid(20010000, 101, outUid));
    ASSERT_EQ(20210000, outUid);
}

/*
 * @tc.name: TranslateUid002
 * @tc.desc: Invalid srcUid (negative) returns ERR_PARAM_INVALID
 * @tc.type: FUNC
 * @tc.require: TDD
 */
HWTEST_F(AccessTokenIdManagerCoverageTest, TranslateUid002, TestSize.Level4)
{
    int32_t outUid = 0;
    ASSERT_EQ(ERR_PARAM_INVALID, AccessTokenIDManager::GetInstance().TranslateUid(-1, 101, outUid));
}

/*
 * @tc.name: AllocUid001
 * @tc.desc: All bundleIds exhausted returns ERR_OVERSIZE without kernel call
 * @tc.type: FUNC
 * @tc.require: TDD
 */
HWTEST_F(AccessTokenIdManagerCoverageTest, AllocUid001, TestSize.Level4)
{
    // Fill the entire bundleId range [10000, 65535]; AllocUid skips kernel call for occupied entries
    for (int32_t bundleId = 10000; bundleId <= 65535; ++bundleId) {
        AccessTokenIDManager::GetInstance().bundleIdSet_.insert(bundleId);
    }
    int32_t outUid = 0;
    AccessTokenIDManager::GetInstance().SetMigrationDone();
    ASSERT_EQ(ERR_OVERSIZE, AccessTokenIDManager::GetInstance().AllocUid(100, outUid));
}

#ifdef SPM_DATA_ENABLE
/*
 * @tc.name: AllocUid002
 * @tc.desc: Alloc without migration done return ERR_PARAM_INVALID
 * @tc.type: FUNC
 * @tc.require: TDD
 */
HWTEST_F(AccessTokenIdManagerCoverageTest, AllocUid002, TestSize.Level4)
{
    // Fill the entire bundleId range [10000, 65535]; AllocUid skips kernel call for occupied entries
    AccessTokenIDManager::GetInstance().migrationDone_ = false;
    int32_t outUid = 0;
    ASSERT_EQ(ERR_PARAM_INVALID, AccessTokenIDManager::GetInstance().AllocUid(100, outUid));
}
#endif

/*
 * @tc.name: SetMigrationDone001
 * @tc.desc: SetMigrationDone sets the migration flag to true
 * @tc.type: FUNC
 * @tc.require: TDD
 */
HWTEST_F(AccessTokenIdManagerCoverageTest, SetMigrationDone001, TestSize.Level4)
{
    // Initially false
    {
        std::unique_lock<std::mutex> lock(AccessTokenIDManager::GetInstance().migrationLock_);
        ASSERT_FALSE(AccessTokenIDManager::GetInstance().migrationDone_);
    }

    // Call SetMigrationDone
    AccessTokenIDManager::GetInstance().SetMigrationDone();

    // Now should be true
    {
        std::unique_lock<std::mutex> lock(AccessTokenIDManager::GetInstance().migrationLock_);
        ASSERT_TRUE(AccessTokenIDManager::GetInstance().migrationDone_);
    }
}

/*
 * @tc.name: GetTokenIdStatusLocked001
 * @tc.desc: Return UNTRUSTED when token exists only in untrustedTokenIdSet_
 * @tc.type: FUNC
 * @tc.require: TDD
 */
HWTEST_F(AccessTokenIdManagerCoverageTest, GetTokenIdStatusLocked001, TestSize.Level4)
{
    auto& manager = AccessTokenIDManager::GetInstance();
    manager.untrustedTokenIdSet_.insert(TEST_TOKEN_ID);

    TokenIdStatus status = TokenIdStatus::ACTIVE;
    ASSERT_EQ(RET_SUCCESS, manager.GetTokenIdStatusLocked(TEST_TOKEN_ID, status));
    ASSERT_EQ(TokenIdStatus::UNTRUSTED, status);
}

/*
 * @tc.name: ChangeTokenIdStatus001
 * @tc.desc: Return ERR_TOKENID_NOT_EXIST when token is absent from all sets
 * @tc.type: FUNC
 * @tc.require: TDD
 */
HWTEST_F(AccessTokenIdManagerCoverageTest, ChangeTokenIdStatus001, TestSize.Level4)
{
    ASSERT_EQ(ERR_TOKENID_NOT_EXIST,
        AccessTokenIDManager::GetInstance().ChangeTokenIdStatus(TEST_TOKEN_ID, TokenIdStatus::ACTIVE));
}

/*
 * @tc.name: ChangeTokenIdStatus002
 * @tc.desc: Move token from untrustedTokenIdSet_ to tokenIdSet_
 * @tc.type: FUNC
 * @tc.require: TDD
 */
HWTEST_F(AccessTokenIdManagerCoverageTest, ChangeTokenIdStatus002, TestSize.Level4)
{
    auto& manager = AccessTokenIDManager::GetInstance();
    manager.untrustedTokenIdSet_.insert(TEST_TOKEN_ID);

    ASSERT_EQ(RET_SUCCESS, manager.ChangeTokenIdStatus(TEST_TOKEN_ID, TokenIdStatus::ACTIVE));
    ASSERT_EQ(1U, manager.tokenIdSet_.count(TEST_TOKEN_ID));
    ASSERT_EQ(0U, manager.untrustedTokenIdSet_.count(TEST_TOKEN_ID));
}

/*
 * @tc.name: ChangeTokenIdStatus003
 * @tc.desc: Return success when current status already equals target status
 * @tc.type: FUNC
 * @tc.require: TDD
 */
HWTEST_F(AccessTokenIdManagerCoverageTest, ChangeTokenIdStatus003, TestSize.Level4)
{
    auto& manager = AccessTokenIDManager::GetInstance();
    manager.tokenIdSet_.insert(TEST_TOKEN_ID);

    ASSERT_EQ(RET_SUCCESS, manager.ChangeTokenIdStatus(TEST_TOKEN_ID, TokenIdStatus::ACTIVE));
    ASSERT_EQ(1U, manager.tokenIdSet_.count(TEST_TOKEN_ID));
    ASSERT_TRUE(manager.reservedTokenIdSet_.empty());
    ASSERT_TRUE(manager.untrustedTokenIdSet_.empty());
}

/*
 * @tc.name: ChangeTokenIdStatus004
 * @tc.desc: Move token from tokenIdSet_ to untrustedTokenIdSet_
 * @tc.type: FUNC
 * @tc.require: TDD
 */
HWTEST_F(AccessTokenIdManagerCoverageTest, ChangeTokenIdStatus004, TestSize.Level4)
{
    auto& manager = AccessTokenIDManager::GetInstance();
    manager.tokenIdSet_.insert(TEST_TOKEN_ID);

    ASSERT_EQ(RET_SUCCESS, manager.ChangeTokenIdStatus(TEST_TOKEN_ID, TokenIdStatus::UNTRUSTED));
    ASSERT_EQ(0U, manager.tokenIdSet_.count(TEST_TOKEN_ID));
    ASSERT_EQ(1U, manager.untrustedTokenIdSet_.count(TEST_TOKEN_ID));
}

/*
 * @tc.name: ChangeTokenIdStatus005
 * @tc.desc: Cover ACTIVE->RESERVED and RESERVED->ACTIVE branches
 * @tc.type: FUNC
 * @tc.require: TDD
 */
HWTEST_F(AccessTokenIdManagerCoverageTest, ChangeTokenIdStatus005, TestSize.Level4)
{
    auto& manager = AccessTokenIDManager::GetInstance();
    manager.tokenIdSet_.insert(TEST_TOKEN_ID);
    manager.reservedTokenIdSet_.insert(TEST_TOKEN_ID_2);

    ASSERT_EQ(RET_SUCCESS, manager.ChangeTokenIdStatus(TEST_TOKEN_ID, TokenIdStatus::RESERVED));
    ASSERT_EQ(0U, manager.tokenIdSet_.count(TEST_TOKEN_ID));
    ASSERT_EQ(1U, manager.reservedTokenIdSet_.count(TEST_TOKEN_ID));

    ASSERT_EQ(RET_SUCCESS, manager.ChangeTokenIdStatus(TEST_TOKEN_ID_2, TokenIdStatus::ACTIVE));
    ASSERT_EQ(0U, manager.reservedTokenIdSet_.count(TEST_TOKEN_ID_2));
    ASSERT_EQ(1U, manager.tokenIdSet_.count(TEST_TOKEN_ID_2));
}

/*
 * @tc.name: ChangeTokenIdStatus006
 * @tc.desc: Return ERR_PARAM_INVALID when target status is invalid
 * @tc.type: FUNC
 * @tc.require: TDD
 */
HWTEST_F(AccessTokenIdManagerCoverageTest, ChangeTokenIdStatus006, TestSize.Level4)
{
    auto& manager = AccessTokenIDManager::GetInstance();
    manager.tokenIdSet_.insert(TEST_TOKEN_ID);

    ASSERT_EQ(ERR_PARAM_INVALID, manager.ChangeTokenIdStatus(TEST_TOKEN_ID, static_cast<TokenIdStatus>(100)));
    ASSERT_EQ(0U, manager.tokenIdSet_.count(TEST_TOKEN_ID));
    ASSERT_TRUE(manager.reservedTokenIdSet_.empty());
    ASSERT_TRUE(manager.untrustedTokenIdSet_.empty());
}

} // namespace AccessToken
} // namespace Security
} // namespace OHOS
