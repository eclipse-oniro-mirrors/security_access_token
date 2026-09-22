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

#include <cerrno>

#include "access_token.h"
#include "access_token_error.h"
#include "access_token_db.h"
#include "access_token_db_operator.h"
#include "json_parse_loader.h"
#include "token_field_const.h"
#include "fake_parent_hap_tokenid.h"
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
constexpr int32_t BUNDLE_ID_MAX_FOR_TEST = 65535;
constexpr int32_t TEST_BUNDLE_ID_BASE = 10000;
constexpr int32_t TEST_BUNDLE_ID_1 = 10001;
constexpr int32_t TEST_BUNDLE_ID_2 = 10002;
constexpr int32_t TEST_BUNDLE_ID_3 = 10003;
constexpr int32_t TEST_BUNDLE_ID_4 = 10004;
constexpr int32_t TEST_BUNDLE_ID_5 = 10005;
constexpr int32_t TEST_UID_BASE = 20010000;
constexpr int32_t TEST_TRANSLATED_UID = 20210000;
constexpr int32_t INVALID_BUNDLE_ID_BELOW_MIN = 5000;
constexpr int32_t TEST_LOCAL_ID = 100;
constexpr int32_t TEST_TRANSLATE_LOCAL_ID = 101;
constexpr int32_t SCAN_START_INIT_VALUE = -1;
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
        AccessTokenIDManager::GetInstance().reservedBundleIdSet_.clear();
        AccessTokenIDManager::GetInstance().scanStartBundleId_ = SCAN_START_INIT_VALUE;
        g_spmRefCntForceRet = -1;
        g_spmRefCntForceValue = 0;
        g_spmRefCntFailRemaining = 0;
        std::shared_ptr<NativeRdb::RdbStore> db = AccessTokenDb::GetInstance()->GetRdb();
        if (db != nullptr) {
            db->queryByStepRowsData_.clear();
            db->queryColumnNames_.clear();
            db->queryByStepRowsDataErr_ = 0;
            db->queryByStepColumnNamesErr_ = 0;
        }
    }

    void TearDown()
    {
        AccessTokenIDManager::GetInstance().tokenIdSet_.clear();
        AccessTokenIDManager::GetInstance().reservedTokenIdSet_.clear();
        AccessTokenIDManager::GetInstance().untrustedTokenIdSet_.clear();
        AccessTokenIDManager::GetInstance().bundleIdSet_.clear();
        AccessTokenIDManager::GetInstance().reservedBundleIdSet_.clear();
        AccessTokenIDManager::GetInstance().scanStartBundleId_ = SCAN_START_INIT_VALUE;
        g_spmRefCntForceRet = -1;
        g_spmRefCntForceValue = 0;
        g_spmRefCntFailRemaining = 0;
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
    ASSERT_EQ(RET_SUCCESS, AccessTokenIDManager::GetInstance().InitSingleBundleIdCache(TEST_BUNDLE_ID_BASE));
    ASSERT_EQ(1U, AccessTokenIDManager::GetInstance().bundleIdSet_.size());
    ASSERT_EQ(1U, AccessTokenIDManager::GetInstance().bundleIdSet_.count(TEST_BUNDLE_ID_BASE));
}

/*
 * @tc.name: InitSingleBundleIdCache002
 * @tc.desc: Negative uid is rejected; bundleIdSet_ remains empty
 * @tc.type: FUNC
 * @tc.require: TDD
 */
HWTEST_F(AccessTokenIdManagerCoverageTest, InitSingleBundleIdCache002, TestSize.Level4)
{
    ASSERT_EQ(ERR_PARAM_INVALID, AccessTokenIDManager::GetInstance().InitSingleBundleIdCache(SCAN_START_INIT_VALUE));
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
    ASSERT_EQ(ERR_PARAM_INVALID,
        AccessTokenIDManager::GetInstance().InitSingleBundleIdCache(INVALID_BUNDLE_ID_BELOW_MIN));
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
    std::vector<int32_t> uids = {TEST_BUNDLE_ID_BASE, TEST_BUNDLE_ID_1, TEST_BUNDLE_ID_2};
    ASSERT_EQ(RET_SUCCESS, AccessTokenIDManager::GetInstance().ImportInitialUids(uids));
    ASSERT_EQ(3U, AccessTokenIDManager::GetInstance().bundleIdSet_.size());
    ASSERT_EQ(1U, AccessTokenIDManager::GetInstance().bundleIdSet_.count(TEST_BUNDLE_ID_BASE));
    ASSERT_EQ(1U, AccessTokenIDManager::GetInstance().bundleIdSet_.count(TEST_BUNDLE_ID_1));
    ASSERT_EQ(1U, AccessTokenIDManager::GetInstance().bundleIdSet_.count(TEST_BUNDLE_ID_2));
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
    std::vector<int32_t> uids =
        {SCAN_START_INIT_VALUE, INVALID_BUNDLE_ID_BELOW_MIN, TEST_BUNDLE_ID_BASE, TEST_BUNDLE_ID_1};
    ASSERT_EQ(RET_SUCCESS, AccessTokenIDManager::GetInstance().ImportInitialUids(uids));
    ASSERT_EQ(2U, AccessTokenIDManager::GetInstance().bundleIdSet_.size());
    ASSERT_EQ(1U, AccessTokenIDManager::GetInstance().bundleIdSet_.count(TEST_BUNDLE_ID_BASE));
    ASSERT_EQ(1U, AccessTokenIDManager::GetInstance().bundleIdSet_.count(TEST_BUNDLE_ID_1));
}

/*
 * @tc.name: RemoveBundleId001
 * @tc.desc: Remove existing bundleId succeeds and removes it from cache
 * @tc.type: FUNC
 * @tc.require: TDD
 */
HWTEST_F(AccessTokenIdManagerCoverageTest, RemoveBundleId001, TestSize.Level4)
{
    AccessTokenIDManager::GetInstance().bundleIdSet_.insert(TEST_BUNDLE_ID_BASE);
    ASSERT_EQ(RET_SUCCESS, AccessTokenIDManager::GetInstance().RemoveBundleId(10000, false));
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
    ASSERT_EQ(RET_SUCCESS, AccessTokenIDManager::GetInstance().RemoveBundleId(10000, false));
}

/*
 * @tc.name: RemoveBundleId003
 * @tc.desc: Invalid uid returns ERR_PARAM_INVALID
 * @tc.type: FUNC
 * @tc.require: TDD
 */
HWTEST_F(AccessTokenIdManagerCoverageTest, RemoveBundleId003, TestSize.Level4)
{
    ASSERT_EQ(ERR_PARAM_INVALID, AccessTokenIDManager::GetInstance().RemoveBundleId(SCAN_START_INIT_VALUE, false));
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
    ASSERT_EQ(RET_SUCCESS,
        AccessTokenIDManager::GetInstance().TranslateUid(TEST_UID_BASE, TEST_TRANSLATE_LOCAL_ID, outUid));
    ASSERT_EQ(TEST_TRANSLATED_UID, outUid);
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
    ASSERT_EQ(ERR_PARAM_INVALID, AccessTokenIDManager::GetInstance().TranslateUid(SCAN_START_INIT_VALUE, 101, outUid));
}

/*
 * @tc.name: AllocUid001
 * @tc.desc: All bundleIds exhausted returns ERR_OVERSIZE without kernel call
 * @tc.type: FUNC
 * @tc.require: TDD
 */
HWTEST_F(AccessTokenIdManagerCoverageTest, AllocUid001, TestSize.Level4)
{
#ifdef SPM_DATA_ENABLE
    // AllocUid checks migrationDone_ first; must be true to reach bundleId exhaustion path
    AccessTokenIDManager::GetInstance().migrationDone_ = true;
#endif
    // Fill the entire bundleId range [10000, 65535]; AllocUid skips kernel call for occupied entries
    for (int32_t bundleId = TEST_BUNDLE_ID_BASE; bundleId <= BUNDLE_ID_MAX_FOR_TEST; ++bundleId) {
        AccessTokenIDManager::GetInstance().bundleIdSet_.insert(bundleId);
    }
    int32_t outUid = 0;
    ASSERT_EQ(ERR_OVERSIZE, AccessTokenIDManager::GetInstance().AllocUid(TEST_LOCAL_ID, outUid));
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
    ASSERT_EQ(ERR_PARAM_INVALID, AccessTokenIDManager::GetInstance().AllocUid(TEST_LOCAL_ID, outUid));
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
        std::unique_lock<std::shared_mutex> lock(AccessTokenIDManager::GetInstance().migrationLock_);
        ASSERT_FALSE(AccessTokenIDManager::GetInstance().migrationDone_);
    }

    // Call SetMigrationDone
    AccessTokenIDManager::GetInstance().SetMigrationDone();

    // Now should be true
    {
        std::unique_lock<std::shared_mutex> lock(AccessTokenIDManager::GetInstance().migrationLock_);
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

/*
 * @tc.name: ReclaimBundleId_001
 * @tc.desc: Reclaim valid uid erases from bundleIdSet_ and rolls back scanStartBundleId_
 * @tc.type: FUNC
 * @tc.require: TDD
 */
HWTEST_F(AccessTokenIdManagerCoverageTest, ReclaimBundleId001, TestSize.Level4)
{
    auto& manager = AccessTokenIDManager::GetInstance();
    // uid=20010000 → bundleId=10000
    manager.bundleIdSet_.insert(TEST_BUNDLE_ID_BASE);
    manager.scanStartBundleId_ = TEST_BUNDLE_ID_1;
    ASSERT_EQ(RET_SUCCESS, manager.RemoveBundleId(TEST_UID_BASE, true));
    ASSERT_EQ(0U, manager.bundleIdSet_.count(TEST_BUNDLE_ID_BASE));
    ASSERT_EQ(TEST_BUNDLE_ID_BASE, manager.scanStartBundleId_);
}

/*
 * @tc.name: ReclaimBundleId_002
 * @tc.desc: Invalid uid returns ERR_PARAM_INVALID
 * @tc.type: FUNC
 * @tc.require: TDD
 */
HWTEST_F(AccessTokenIdManagerCoverageTest, ReclaimBundleId002, TestSize.Level4)
{
    ASSERT_EQ(ERR_PARAM_INVALID, AccessTokenIDManager::GetInstance().RemoveBundleId(SCAN_START_INIT_VALUE, true));
}

/*
 * @tc.name: ReclaimBundleId_003
 * @tc.desc: Reclaim does not roll back when bundleId is ahead of scanStartBundleId_
 * @tc.type: FUNC
 * @tc.require: TDD
 */
HWTEST_F(AccessTokenIdManagerCoverageTest, ReclaimBundleId003, TestSize.Level4)
{
    auto& manager = AccessTokenIDManager::GetInstance();
    // uid=20010005 → bundleId=10005, scanStartBundleId_ = TEST_BUNDLE_ID_3 (ahead)
    manager.bundleIdSet_.insert(TEST_BUNDLE_ID_5);
    manager.scanStartBundleId_ = TEST_BUNDLE_ID_3;
    ASSERT_EQ(RET_SUCCESS, manager.RemoveBundleId(TEST_UID_BASE + 5, true));
    ASSERT_EQ(0U, manager.bundleIdSet_.count(TEST_BUNDLE_ID_5));
    // bundleId 10005 > scanStartBundleId_ 10003, condition not met, no rollback
    ASSERT_EQ(TEST_BUNDLE_ID_3, manager.scanStartBundleId_);
}

/*
 * @tc.name: RemoveReservedBundleId_001
 * @tc.desc: Valid uid removes from both bundleIdSet_ and reservedBundleIdSet_
 * @tc.type: FUNC
 * @tc.require: TDD
 */
HWTEST_F(AccessTokenIdManagerCoverageTest, RemoveReservedBundleId001, TestSize.Level4)
{
    auto& manager = AccessTokenIDManager::GetInstance();
    // Pre-populate both sets
    manager.bundleIdSet_.insert(TEST_BUNDLE_ID_BASE);
    manager.reservedBundleIdSet_.insert(TEST_BUNDLE_ID_BASE);
    // uid=20010000 → bundleId=10000
    // DB persist may fail in test env; verify memory state regardless of return
    (void)manager.RemoveReservedBundleId(TEST_UID_BASE);
    ASSERT_EQ(0U, manager.bundleIdSet_.count(TEST_BUNDLE_ID_BASE));
    ASSERT_EQ(0U, manager.reservedBundleIdSet_.count(TEST_BUNDLE_ID_BASE));
}

/*
 * @tc.name: RemoveReservedBundleId_002
 * @tc.desc: Invalid uid returns ERR_PARAM_INVALID
 * @tc.type: FUNC
 * @tc.require: TDD
 */
HWTEST_F(AccessTokenIdManagerCoverageTest, RemoveReservedBundleId002, TestSize.Level4)
{
    ASSERT_EQ(ERR_PARAM_INVALID, AccessTokenIDManager::GetInstance().RemoveReservedBundleId(SCAN_START_INIT_VALUE));
}

/*
 * @tc.name: IsReservedBundleId_001
 * @tc.desc: Reserved bundleId returns true
 * @tc.type: FUNC
 * @tc.require: TDD
 */
HWTEST_F(AccessTokenIdManagerCoverageTest, IsReservedBundleId001, TestSize.Level4)
{
    auto& manager = AccessTokenIDManager::GetInstance();
    manager.reservedBundleIdSet_.insert(TEST_BUNDLE_ID_BASE);
    // uid=20010000 → bundleId=10000
    ASSERT_TRUE(manager.IsReservedBundleId(TEST_UID_BASE));
}

/*
 * @tc.name: IsReservedBundleId_002
 * @tc.desc: Non-reserved bundleId returns false
 * @tc.type: FUNC
 * @tc.require: TDD
 */
HWTEST_F(AccessTokenIdManagerCoverageTest, IsReservedBundleId002, TestSize.Level4)
{
    // uid=20010000 → bundleId=10000, not in reserved set
    ASSERT_FALSE(AccessTokenIDManager::GetInstance().IsReservedBundleId(TEST_UID_BASE));
}

/*
 * @tc.name: IsReservedBundleId_003
 * @tc.desc: Invalid uid returns false
 * @tc.type: FUNC
 * @tc.require: TDD
 */
HWTEST_F(AccessTokenIdManagerCoverageTest, IsReservedBundleId003, TestSize.Level4)
{
    ASSERT_FALSE(AccessTokenIDManager::GetInstance().IsReservedBundleId(-1));
}

/*
 * @tc.name: IsUidReusable001
 * @tc.desc: uid whose bundleId is in use returns false (not reusable)
 * @tc.type: FUNC
 * @tc.require: TDD
 */
HWTEST_F(AccessTokenIdManagerCoverageTest, IsUidReusable001, TestSize.Level4)
{
    auto& manager = AccessTokenIDManager::GetInstance();
    // uid=10000 → bundleId=10000, insert into set → not reusable
    manager.bundleIdSet_.insert(TEST_BUNDLE_ID_BASE);
    bool reusable = false;
    ASSERT_EQ(RET_SUCCESS, manager.IsUidReusable(10000, reusable));
    ASSERT_FALSE(reusable);
}

/*
 * @tc.name: IsUidReusable002
 * @tc.desc: uid whose bundleId is not in use returns true (reusable)
 * @tc.type: FUNC
 * @tc.require: TDD
 */
HWTEST_F(AccessTokenIdManagerCoverageTest, IsUidReusable002, TestSize.Level4)
{
    // uid=10000 → bundleId=10000, not in set → reusable
    bool reusable = false;
    ASSERT_EQ(RET_SUCCESS, AccessTokenIDManager::GetInstance().IsUidReusable(10000, reusable));
    ASSERT_TRUE(reusable);
}

/*
 * @tc.name: IsUidReusable003
 * @tc.desc: Invalid uid returns false (not reusable)
 * @tc.type: FUNC
 * @tc.require: TDD
 */
HWTEST_F(AccessTokenIdManagerCoverageTest, IsUidReusable003, TestSize.Level4)
{
    bool reusable = false;
    ASSERT_NE(RET_SUCCESS, AccessTokenIDManager::GetInstance().IsUidReusable(SCAN_START_INIT_VALUE, reusable));
    ASSERT_FALSE(reusable);
}

/*
 * @tc.name: RemoveBundleId_004
 * @tc.desc: RemoveBundleId does not roll back scanStartBundleId_
 * @tc.type: FUNC
 * @tc.require: TDD
 */
HWTEST_F(AccessTokenIdManagerCoverageTest, RemoveBundleId004, TestSize.Level4)
{
    auto& manager = AccessTokenIDManager::GetInstance();
    manager.bundleIdSet_.insert(TEST_BUNDLE_ID_BASE);
    manager.scanStartBundleId_ = TEST_BUNDLE_ID_1;
    // uid=20010000 → bundleId=10000
    ASSERT_EQ(RET_SUCCESS, manager.RemoveBundleId(TEST_UID_BASE, false));
    ASSERT_EQ(0U, manager.bundleIdSet_.count(TEST_BUNDLE_ID_BASE));
    // scanStartBundleId_ should NOT change (RemoveBundleId does not roll back)
    ASSERT_EQ(TEST_BUNDLE_ID_1, manager.scanStartBundleId_);
}

/*
 * @tc.name: AddReservedTokenId001
 * @tc.desc: ID not in any set is inserted into reservedTokenIdSet_
 * @tc.type: FUNC
 * @tc.require: TDD
 */
HWTEST_F(AccessTokenIdManagerCoverageTest, AddReservedTokenId001, TestSize.Level4)
{
    auto& manager = AccessTokenIDManager::GetInstance();
    manager.AddReservedTokenId(TEST_TOKEN_ID);
    ASSERT_EQ(1U, manager.reservedTokenIdSet_.count(TEST_TOKEN_ID));
}

/*
 * @tc.name: AddReservedTokenId002
 * @tc.desc: ID already in reservedTokenIdSet_ is rejected with no duplicate insert
 * @tc.type: FUNC
 * @tc.require: TDD
 */
HWTEST_F(AccessTokenIdManagerCoverageTest, AddReservedTokenId002, TestSize.Level4)
{
    auto& manager = AccessTokenIDManager::GetInstance();
    manager.reservedTokenIdSet_.insert(TEST_TOKEN_ID);
    manager.AddReservedTokenId(TEST_TOKEN_ID);
    ASSERT_EQ(1U, manager.reservedTokenIdSet_.count(TEST_TOKEN_ID));
}

/*
 * @tc.name: AddReservedTokenId003
 * @tc.desc: ID already in tokenIdSet_ is rejected to maintain mutual exclusivity
 * @tc.type: FUNC
 * @tc.require: TDD
 */
HWTEST_F(AccessTokenIdManagerCoverageTest, AddReservedTokenId003, TestSize.Level4)
{
    auto& manager = AccessTokenIDManager::GetInstance();
    manager.tokenIdSet_.insert(TEST_TOKEN_ID);
    manager.AddReservedTokenId(TEST_TOKEN_ID);
    ASSERT_EQ(0U, manager.reservedTokenIdSet_.count(TEST_TOKEN_ID));
    ASSERT_EQ(1U, manager.tokenIdSet_.count(TEST_TOKEN_ID));
}

/*
 * @tc.name: AddReservedTokenId004
 * @tc.desc: ID already in untrustedTokenIdSet_ is rejected to maintain mutual exclusivity
 * @tc.type: FUNC
 * @tc.require: TDD
 */
HWTEST_F(AccessTokenIdManagerCoverageTest, AddReservedTokenId004, TestSize.Level4)
{
    auto& manager = AccessTokenIDManager::GetInstance();
    manager.untrustedTokenIdSet_.insert(TEST_TOKEN_ID);
    manager.AddReservedTokenId(TEST_TOKEN_ID);
    ASSERT_EQ(0U, manager.reservedTokenIdSet_.count(TEST_TOKEN_ID));
    ASSERT_EQ(1U, manager.untrustedTokenIdSet_.count(TEST_TOKEN_ID));
}

/*
 * @tc.name: ReclaimBundleId004
 * @tc.desc: Non-adjacent bundleId does not roll back scanStartBundleId_
 * @tc.type: FUNC
 * @tc.require: TDD
 */
HWTEST_F(AccessTokenIdManagerCoverageTest, ReclaimBundleId004, TestSize.Level4)
{
    auto& manager = AccessTokenIDManager::GetInstance();
    // uid=20010000 → bundleId=10000, scanStartBundleId_ = TEST_BUNDLE_ID_3 (gap > 1)
    manager.bundleIdSet_.insert(TEST_BUNDLE_ID_BASE);
    manager.scanStartBundleId_ = TEST_BUNDLE_ID_3;
    ASSERT_EQ(RET_SUCCESS, manager.RemoveBundleId(TEST_UID_BASE, true));
    ASSERT_EQ(0U, manager.bundleIdSet_.count(TEST_BUNDLE_ID_BASE));
    ASSERT_EQ(TEST_BUNDLE_ID_3, manager.scanStartBundleId_);
}

/*
 * @tc.name: SetScanStartBundleId001
 * @tc.desc: Refresh scan-start hint to max+1 from non-empty bundleIdSet_
 * @tc.type: FUNC
 * @tc.require: TDD
 */
HWTEST_F(AccessTokenIdManagerCoverageTest, SetScanStartBundleId001, TestSize.Level4)
{
    auto& manager = AccessTokenIDManager::GetInstance();
    manager.bundleIdSet_.insert(TEST_BUNDLE_ID_BASE);
    manager.bundleIdSet_.insert(TEST_BUNDLE_ID_1);
    manager.bundleIdSet_.insert(TEST_BUNDLE_ID_3);
    manager.scanStartBundleId_ = manager.InitScanStartBundleIdFromCache();
    ASSERT_EQ(TEST_BUNDLE_ID_4, manager.scanStartBundleId_);
}

/*
 * @tc.name: SetScanStartBundleId002
 * @tc.desc: Empty bundleIdSet_ sets scanStartBundleId_ to GetBundleIdMin()
 * @tc.type: FUNC
 * @tc.require: TDD
 */
HWTEST_F(AccessTokenIdManagerCoverageTest, SetScanStartBundleId002, TestSize.Level4)
{
    auto& manager = AccessTokenIDManager::GetInstance();
    manager.scanStartBundleId_ = manager.InitScanStartBundleIdFromCache();
    ASSERT_EQ(manager.GetBundleIdMin(), manager.scanStartBundleId_);
}

/*
 * @tc.name: SetScanStartBundleId003
 * @tc.desc: Max bundleId at BUNDLE_ID_MAX wraps scanStartBundleId_ to GetBundleIdMin()
 * @tc.type: FUNC
 * @tc.require: TDD
 */
HWTEST_F(AccessTokenIdManagerCoverageTest, SetScanStartBundleId003, TestSize.Level4)
{
    auto& manager = AccessTokenIDManager::GetInstance();
    manager.bundleIdSet_.insert(BUNDLE_ID_MAX_FOR_TEST);
    manager.scanStartBundleId_ = manager.InitScanStartBundleIdFromCache();
    ASSERT_EQ(manager.GetBundleIdMin(), manager.scanStartBundleId_);
}

/*
 * @tc.name: RemoveReservedBundleId003
 * @tc.desc: bundleId not in reserved set is no-op erase, returns RET_SUCCESS
 * @tc.type: FUNC
 * @tc.require: TDD
 */
HWTEST_F(AccessTokenIdManagerCoverageTest, RemoveReservedBundleId003, TestSize.Level4)
{
    auto& manager = AccessTokenIDManager::GetInstance();
    // uid=20010000 → bundleId=10000, not in any set
    ASSERT_EQ(RET_SUCCESS, manager.RemoveReservedBundleId(TEST_UID_BASE));
    ASSERT_EQ(0U, manager.bundleIdSet_.count(TEST_BUNDLE_ID_BASE));
    ASSERT_EQ(0U, manager.reservedBundleIdSet_.count(TEST_BUNDLE_ID_BASE));
}

/*
 * @tc.name: GetReservedBundleIdSetPersistInfo001
 * @tc.desc: Construct DB info when reserved set non-empty after removal; memory unchanged
 * @tc.type: FUNC
 * @tc.require: TDD
 */
HWTEST_F(AccessTokenIdManagerCoverageTest, GetReservedBundleIdSetPersistInfo001, TestSize.Level4)
{
    auto& manager = AccessTokenIDManager::GetInstance();
    // bundleId=10000 in reserved set, 10001 also in reserved (non-empty after removal)
    manager.reservedBundleIdSet_.insert(TEST_BUNDLE_ID_BASE);
    manager.reservedBundleIdSet_.insert(TEST_BUNDLE_ID_1);
    manager.bundleIdSet_.insert(TEST_BUNDLE_ID_BASE);
    manager.bundleIdSet_.insert(TEST_BUNDLE_ID_1);
    std::vector<DelInfo> delInfoVec;
    std::vector<AddInfo> addInfoVec;
    ASSERT_EQ(RET_SUCCESS, manager.GetReservedBundleIdSetPersistInfo(TEST_BUNDLE_ID_BASE, delInfoVec, addInfoVec));
    ASSERT_EQ(1U, delInfoVec.size());
    ASSERT_EQ(1U, addInfoVec.size());
    ASSERT_EQ(1U, manager.reservedBundleIdSet_.count(TEST_BUNDLE_ID_BASE));
    ASSERT_EQ(1U, manager.bundleIdSet_.count(TEST_BUNDLE_ID_BASE));
}

/*
 * @tc.name: GetReservedBundleIdSetPersistInfo002
 * @tc.desc: Construct DB info when reserved set becomes empty; addInfoVec empty
 * @tc.type: FUNC
 * @tc.require: TDD
 */
HWTEST_F(AccessTokenIdManagerCoverageTest, GetReservedBundleIdSetPersistInfo002, TestSize.Level4)
{
    auto& manager = AccessTokenIDManager::GetInstance();
    manager.reservedBundleIdSet_.insert(TEST_BUNDLE_ID_BASE);
    manager.bundleIdSet_.insert(TEST_BUNDLE_ID_BASE);
    std::vector<DelInfo> delInfoVec;
    std::vector<AddInfo> addInfoVec;
    ASSERT_EQ(RET_SUCCESS, manager.GetReservedBundleIdSetPersistInfo(TEST_BUNDLE_ID_BASE, delInfoVec, addInfoVec));
    ASSERT_EQ(1U, delInfoVec.size());
    ASSERT_TRUE(addInfoVec.empty());
    ASSERT_EQ(1U, manager.reservedBundleIdSet_.count(TEST_BUNDLE_ID_BASE));
    ASSERT_EQ(1U, manager.bundleIdSet_.count(TEST_BUNDLE_ID_BASE));
}

/*
 * @tc.name: GetReservedBundleIdSetPersistInfo003
 * @tc.desc: bundleId not in reserved set returns empty vectors
 * @tc.type: FUNC
 * @tc.require: TDD
 */
HWTEST_F(AccessTokenIdManagerCoverageTest, GetReservedBundleIdSetPersistInfo003, TestSize.Level4)
{
    auto& manager = AccessTokenIDManager::GetInstance();
    std::vector<DelInfo> delInfoVec;
    std::vector<AddInfo> addInfoVec;
    ASSERT_EQ(RET_SUCCESS, manager.GetReservedBundleIdSetPersistInfo(TEST_BUNDLE_ID_BASE, delInfoVec, addInfoVec));
    ASSERT_TRUE(delInfoVec.empty());
    ASSERT_TRUE(addInfoVec.empty());
}

/*
 * @tc.name: GetReservedBundleIdSetPersistInfo004
 * @tc.desc: Memory unchanged after GetReservedBundleIdSetPersistInfo (rollback safety)
 * @tc.type: FUNC
 * @tc.require: TDD
 */
HWTEST_F(AccessTokenIdManagerCoverageTest, GetReservedBundleIdSetPersistInfo004, TestSize.Level4)
{
    auto& manager = AccessTokenIDManager::GetInstance();
    manager.reservedBundleIdSet_.insert(TEST_BUNDLE_ID_BASE);
    manager.reservedBundleIdSet_.insert(TEST_BUNDLE_ID_1);
    manager.bundleIdSet_.insert(TEST_BUNDLE_ID_BASE);
    manager.bundleIdSet_.insert(TEST_BUNDLE_ID_1);
    std::vector<DelInfo> delInfoVec;
    std::vector<AddInfo> addInfoVec;
    (void)manager.GetReservedBundleIdSetPersistInfo(TEST_BUNDLE_ID_BASE, delInfoVec, addInfoVec);
    ASSERT_EQ(2U, manager.reservedBundleIdSet_.size());
    ASSERT_EQ(2U, manager.bundleIdSet_.size());
}

/*
 * @tc.name: GetReservedBundleIdSetPersistInfo005
 * @tc.desc: Caller calls RemoveReservedBundleId after DB success to commit memory
 * @tc.type: FUNC
 * @tc.require: TDD
 */
HWTEST_F(AccessTokenIdManagerCoverageTest, GetReservedBundleIdSetPersistInfo005, TestSize.Level4)
{
    auto& manager = AccessTokenIDManager::GetInstance();
    manager.reservedBundleIdSet_.insert(TEST_BUNDLE_ID_BASE);
    manager.reservedBundleIdSet_.insert(TEST_BUNDLE_ID_1);
    manager.bundleIdSet_.insert(TEST_BUNDLE_ID_BASE);
    manager.bundleIdSet_.insert(TEST_BUNDLE_ID_1);
    std::vector<DelInfo> delInfoVec;
    std::vector<AddInfo> addInfoVec;
    ASSERT_EQ(RET_SUCCESS, manager.GetReservedBundleIdSetPersistInfo(TEST_BUNDLE_ID_BASE, delInfoVec, addInfoVec));
    // Simulate DB success, then commit memory
    ASSERT_EQ(RET_SUCCESS, manager.RemoveReservedBundleId(TEST_UID_BASE));
    ASSERT_EQ(0U, manager.reservedBundleIdSet_.count(TEST_BUNDLE_ID_BASE));
    ASSERT_EQ(0U, manager.bundleIdSet_.count(TEST_BUNDLE_ID_BASE));
    ASSERT_EQ(1U, manager.reservedBundleIdSet_.count(TEST_BUNDLE_ID_1));
}

/*
 * @tc.name: GetReservedBundleIdSetPersistInfo006
 * @tc.desc: Caller skips RemoveReservedBundleId after DB failure; memory unchanged
 * @tc.type: FUNC
 * @tc.require: TDD
 */
HWTEST_F(AccessTokenIdManagerCoverageTest, GetReservedBundleIdSetPersistInfo006, TestSize.Level4)
{
    auto& manager = AccessTokenIDManager::GetInstance();
    manager.reservedBundleIdSet_.insert(TEST_BUNDLE_ID_BASE);
    manager.bundleIdSet_.insert(TEST_BUNDLE_ID_BASE);
    std::vector<DelInfo> delInfoVec;
    std::vector<AddInfo> addInfoVec;
    ASSERT_EQ(RET_SUCCESS, manager.GetReservedBundleIdSetPersistInfo(TEST_BUNDLE_ID_BASE, delInfoVec, addInfoVec));
    // Simulate DB failure: do NOT call RemoveReservedBundleId
    ASSERT_EQ(1U, manager.reservedBundleIdSet_.count(TEST_BUNDLE_ID_BASE));
    ASSERT_EQ(1U, manager.bundleIdSet_.count(TEST_BUNDLE_ID_BASE));
}

/*
 * @tc.name: IsUidReusable004
 * @tc.desc: bundleId in reservedBundleIdSet_ is reusable
 * @tc.type: FUNC
 * @tc.require: TDD
 */
HWTEST_F(AccessTokenIdManagerCoverageTest, IsUidReusable004, TestSize.Level4)
{
    auto& manager = AccessTokenIDManager::GetInstance();
    // uid=20010000 → bundleId=10000, in reservedBundleIdSet_ → reusable
    manager.reservedBundleIdSet_.insert(TEST_BUNDLE_ID_BASE);
    bool reusable = false;
    ASSERT_EQ(RET_SUCCESS, manager.IsUidReusable(TEST_UID_BASE, reusable));
    ASSERT_TRUE(reusable);
}

/*
 * @tc.name: AllocUidScanStart001
 * @tc.desc: First allocation with scanStartBundleId_=-1 starts from GetBundleIdMin()
 * @tc.type: FUNC
 * @tc.require: TDD
 */
HWTEST_F(AccessTokenIdManagerCoverageTest, AllocUidScanStart001, TestSize.Level4)
{
#ifdef SPM_DATA_ENABLE
    AccessTokenIDManager::GetInstance().migrationDone_ = true;
#endif
    auto& manager = AccessTokenIDManager::GetInstance();
    manager.scanStartBundleId_ = SCAN_START_INIT_VALUE;
    int32_t outUid = 0;
    ASSERT_EQ(RET_SUCCESS, manager.AllocUid(TEST_LOCAL_ID, outUid));
    ASSERT_EQ(manager.GetBundleIdMin() + 1, manager.scanStartBundleId_);
}

/*
 * @tc.name: AllocUidScanStart002
 * @tc.desc: After successful allocation scanStartBundleId_ advances to candidate+1
 * @tc.type: FUNC
 * @tc.require: TDD
 */
HWTEST_F(AccessTokenIdManagerCoverageTest, AllocUidScanStart002, TestSize.Level4)
{
#ifdef SPM_DATA_ENABLE
    AccessTokenIDManager::GetInstance().migrationDone_ = true;
#endif
    auto& manager = AccessTokenIDManager::GetInstance();
    manager.scanStartBundleId_ = TEST_BUNDLE_ID_BASE;
    int32_t outUid = 0;
    ASSERT_EQ(RET_SUCCESS, manager.AllocUid(TEST_LOCAL_ID, outUid));
    ASSERT_EQ(TEST_BUNDLE_ID_1, manager.scanStartBundleId_);
}

/*
 * @tc.name: AllocUidScanStart003
 * @tc.desc: scanStartBundleId_ above BUNDLE_ID_MAX wraps to GetBundleIdMin()
 * @tc.type: FUNC
 * @tc.require: TDD
 */
HWTEST_F(AccessTokenIdManagerCoverageTest, AllocUidScanStart003, TestSize.Level4)
{
#ifdef SPM_DATA_ENABLE
    AccessTokenIDManager::GetInstance().migrationDone_ = true;
#endif
    auto& manager = AccessTokenIDManager::GetInstance();
    manager.scanStartBundleId_ = BUNDLE_ID_MAX_FOR_TEST + 1;
    int32_t outUid = 0;
    ASSERT_EQ(RET_SUCCESS, manager.AllocUid(TEST_LOCAL_ID, outUid));
    ASSERT_EQ(manager.GetBundleIdMin() + 1, manager.scanStartBundleId_);
}

/*
 * @tc.name: AllocUidScanStart004
 * @tc.desc: scanStartBundleId_ below GetBundleIdMin() is corrected to GetBundleIdMin()
 * @tc.type: FUNC
 * @tc.require: TDD
 */
HWTEST_F(AccessTokenIdManagerCoverageTest, AllocUidScanStart004, TestSize.Level4)
{
#ifdef SPM_DATA_ENABLE
    AccessTokenIDManager::GetInstance().migrationDone_ = true;
#endif
    auto& manager = AccessTokenIDManager::GetInstance();
    manager.scanStartBundleId_ = 0;
    int32_t outUid = 0;
    ASSERT_EQ(RET_SUCCESS, manager.AllocUid(TEST_LOCAL_ID, outUid));
    ASSERT_EQ(manager.GetBundleIdMin() + 1, manager.scanStartBundleId_);
}

/*
 * @tc.name: AllocUidScanStart005
 * @tc.desc: Two-pass scan: [startId, MAX] occupied, wraps to [MIN, startId-1]
 * @tc.type: FUNC
 * @tc.require: TDD
 */
HWTEST_F(AccessTokenIdManagerCoverageTest, AllocUidScanStart005, TestSize.Level4)
{
#ifdef SPM_DATA_ENABLE
    AccessTokenIDManager::GetInstance().migrationDone_ = true;
#endif
    auto& manager = AccessTokenIDManager::GetInstance();
    // Occupy 65535 so scan from 65535 finds it occupied, wraps to 10000
    manager.bundleIdSet_.insert(BUNDLE_ID_MAX_FOR_TEST);
    manager.scanStartBundleId_ = BUNDLE_ID_MAX_FOR_TEST;
    int32_t outUid = 0;
    ASSERT_EQ(RET_SUCCESS, manager.AllocUid(TEST_LOCAL_ID, outUid));
    // Should wrap and find 10000
    ASSERT_EQ(1U, manager.bundleIdSet_.count(TEST_BUNDLE_ID_BASE));
    ASSERT_EQ(TEST_BUNDLE_ID_1, manager.scanStartBundleId_);
}

/*
 * @tc.name: AllocUidKernelError001
 * @tc.desc: SpmGetUidRefCntWithRetry retries succeed, allocates first candidate
 * @tc.type: FUNC
 * @tc.require: TDD
 */
HWTEST_F(AccessTokenIdManagerCoverageTest, AllocUidKernelError001, TestSize.Level4)
{
#ifdef SPM_DATA_ENABLE
    AccessTokenIDManager::GetInstance().migrationDone_ = true;
#endif
    g_spmRefCntFailRemaining = 2;
    auto& manager = AccessTokenIDManager::GetInstance();
    manager.scanStartBundleId_ = TEST_BUNDLE_ID_BASE;
    int32_t outUid = 0;
    ASSERT_EQ(RET_SUCCESS, manager.AllocUid(TEST_LOCAL_ID, outUid));
    ASSERT_EQ(1U, manager.bundleIdSet_.count(TEST_BUNDLE_ID_BASE));
    ASSERT_EQ(TEST_BUNDLE_ID_1, manager.scanStartBundleId_);
}

/*
 * @tc.name: AllocUidKernelError002
 * @tc.desc: Retry exhausted after 3 failures, abort with ERR_KERNEL_COMMON_FAILED
 * @tc.type: FUNC
 * @tc.require: TDD
 */
HWTEST_F(AccessTokenIdManagerCoverageTest, AllocUidKernelError002, TestSize.Level4)
{
#ifdef SPM_DATA_ENABLE
    AccessTokenIDManager::GetInstance().migrationDone_ = true;
#endif
    g_spmRefCntFailRemaining = 4;
    auto& manager = AccessTokenIDManager::GetInstance();
    manager.scanStartBundleId_ = TEST_BUNDLE_ID_BASE;
    int32_t outUid = 0;
    ASSERT_EQ(ERR_KERNEL_COMMON_FAILED, manager.AllocUid(TEST_LOCAL_ID, outUid));
}

/*
 * @tc.name: AllocUidKernelError003
 * @tc.desc: ENOTSUP retried 3 times, all fail with ERR_KERNEL_COMMON_FAILED
 * @tc.type: FUNC
 * @tc.require: TDD
 */
HWTEST_F(AccessTokenIdManagerCoverageTest, AllocUidKernelError003, TestSize.Level4)
{
#ifdef SPM_DATA_ENABLE
    AccessTokenIDManager::GetInstance().migrationDone_ = true;
#endif
    g_spmRefCntForceRet = ENOTSUP;
    auto& manager = AccessTokenIDManager::GetInstance();
    manager.scanStartBundleId_ = TEST_BUNDLE_ID_BASE;
    int32_t outUid = 0;
    ASSERT_EQ(ERR_KERNEL_COMMON_FAILED, manager.AllocUid(TEST_LOCAL_ID, outUid));
}

/*
 * @tc.name: IsUidReusable005
 * @tc.desc: kernel refcnt > 0 makes uid not reusable
 * @tc.type: FUNC
 * @tc.require: TDD
 */
HWTEST_F(AccessTokenIdManagerCoverageTest, IsUidReusable005, TestSize.Level4)
{
    auto& manager = AccessTokenIDManager::GetInstance();
    g_spmRefCntForceValue = 1;
    bool reusable = true;
    ASSERT_EQ(RET_SUCCESS, manager.IsUidReusable(TEST_UID_BASE, reusable));
    ASSERT_FALSE(reusable);
}

/*
 * @tc.name: IsUidReusable006
 * @tc.desc: SpmGetUidRefCntWithRetry succeeds after retries, uid is reusable
 * @tc.type: FUNC
 * @tc.require: TDD
 */
HWTEST_F(AccessTokenIdManagerCoverageTest, IsUidReusable006, TestSize.Level4)
{
    auto& manager = AccessTokenIDManager::GetInstance();
    g_spmRefCntFailRemaining = 2;
    bool reusable = false;
    ASSERT_EQ(RET_SUCCESS, manager.IsUidReusable(TEST_UID_BASE, reusable));
    ASSERT_TRUE(reusable);
}

/*
 * @tc.name: IsUidReusable007
 * @tc.desc: kernel error returns ERR_KERNEL_COMMON_FAILED with reusable=false (fail-closed)
 * @tc.type: FUNC
 * @tc.require: TDD
 */
HWTEST_F(AccessTokenIdManagerCoverageTest, IsUidReusable007, TestSize.Level4)
{
    auto& manager = AccessTokenIDManager::GetInstance();
    g_spmRefCntFailRemaining = 4;
    bool reusable = true;
    ASSERT_EQ(ERR_KERNEL_COMMON_FAILED, manager.IsUidReusable(TEST_UID_BASE, reusable));
    ASSERT_FALSE(reusable);
}

/*
 * @tc.name: InitBundleIdConfig001
 * @tc.desc: InitBundleIdConfig loads reserved set from DB successfully
 * @tc.type: FUNC
 * @tc.require: TDD
 */
HWTEST_F(AccessTokenIdManagerCoverageTest, InitBundleIdConfig001, TestSize.Level4)
{
    std::shared_ptr<NativeRdb::RdbStore> db = AccessTokenDb::GetInstance()->GetRdb();
    ASSERT_NE(nullptr, db);
    db->queryColumnNames_ = { TokenFiledConst::FIELD_NAME, TokenFiledConst::FIELD_VALUE };
    db->queryByStepRowsData_ = {{
        NativeRdb::ValueObject(std::string("reserved_bundle_id_list")),
        NativeRdb::ValueObject(std::string("{\"list\":[10000,10001]}"))
    }};

    auto& manager = AccessTokenIDManager::GetInstance();
    ASSERT_EQ(RET_SUCCESS, manager.InitBundleIdConfig());
    ASSERT_EQ(1U, manager.reservedBundleIdSet_.count(TEST_BUNDLE_ID_BASE));
    ASSERT_EQ(1U, manager.reservedBundleIdSet_.count(TEST_BUNDLE_ID_1));
    ASSERT_EQ(1U, manager.bundleIdSet_.count(TEST_BUNDLE_ID_BASE));
    ASSERT_EQ(1U, manager.bundleIdSet_.count(TEST_BUNDLE_ID_1));
}

/*
 * @tc.name: InitBundleIdConfig002
 * @tc.desc: InitBundleIdConfig with empty DB returns success with empty reserved set
 * @tc.type: FUNC
 * @tc.require: TDD
 */
HWTEST_F(AccessTokenIdManagerCoverageTest, InitBundleIdConfig002, TestSize.Level4)
{
    auto& manager = AccessTokenIDManager::GetInstance();
    ASSERT_EQ(RET_SUCCESS, manager.InitBundleIdConfig());
    ASSERT_TRUE(manager.reservedBundleIdSet_.empty());
    ASSERT_EQ(manager.GetBundleIdMin(), manager.scanStartBundleId_);
}

/*
 * @tc.name: InitBundleIdConfig003
 * @tc.desc: InitBundleIdConfig with invalid JSON in DB returns failure
 * @tc.type: FUNC
 * @tc.require: TDD
 */
HWTEST_F(AccessTokenIdManagerCoverageTest, InitBundleIdConfig003, TestSize.Level4)
{
    std::shared_ptr<NativeRdb::RdbStore> db = AccessTokenDb::GetInstance()->GetRdb();
    ASSERT_NE(nullptr, db);
    db->queryColumnNames_ = { TokenFiledConst::FIELD_NAME, TokenFiledConst::FIELD_VALUE };
    db->queryByStepRowsData_ = {{
        NativeRdb::ValueObject(std::string("reserved_bundle_id_list")),
        NativeRdb::ValueObject(std::string("invalid json"))
    }};

    auto& manager = AccessTokenIDManager::GetInstance();
    ASSERT_NE(RET_SUCCESS, manager.InitBundleIdConfig());
}

/*
 * @tc.name: RefreshReservedBundleIdSet001
 * @tc.desc: RefreshReservedBundleIdSet updates DB and memory atomically
 * @tc.type: FUNC
 * @tc.require: TDD
 */
HWTEST_F(AccessTokenIdManagerCoverageTest, RefreshReservedBundleIdSet001, TestSize.Level4)
{
    // Pre-insert old reserved set
    GenericValues addValue;
    addValue.Put(TokenFiledConst::FIELD_NAME, "reserved_bundle_id_list");
    addValue.Put(TokenFiledConst::FIELD_VALUE, std::string("{\"list\":[10000,10001]}"));
    AddInfo addInfo;
    addInfo.addType = AtmDataType::ACCESSTOKEN_SYSTEM_CONFIG;
    addInfo.addValues.emplace_back(addValue);
    DelInfo delInfo;
    delInfo.delType = AtmDataType::ACCESSTOKEN_SYSTEM_CONFIG;
    ASSERT_EQ(RET_SUCCESS, AccessTokenDbOperator::DeleteAndInsertValues({ delInfo }, { addInfo }));

    auto& manager = AccessTokenIDManager::GetInstance();
    std::set<int32_t> newSet = { TEST_BUNDLE_ID_BASE, TEST_BUNDLE_ID_2 };
    ASSERT_EQ(RET_SUCCESS, manager.RefreshReservedBundleIdSet(newSet));
    ASSERT_EQ(1U, manager.reservedBundleIdSet_.count(TEST_BUNDLE_ID_BASE));
    ASSERT_EQ(1U, manager.reservedBundleIdSet_.count(10002));
    ASSERT_EQ(0U, manager.reservedBundleIdSet_.count(TEST_BUNDLE_ID_1));
    ASSERT_EQ(1U, manager.bundleIdSet_.count(TEST_BUNDLE_ID_BASE));
    ASSERT_EQ(1U, manager.bundleIdSet_.count(TEST_BUNDLE_ID_2));
    ASSERT_EQ(0U, manager.bundleIdSet_.count(TEST_BUNDLE_ID_1));

    // Cleanup DB
    ASSERT_EQ(RET_SUCCESS, AccessTokenDbOperator::DeleteAndInsertValues({ delInfo }, {}));
}

/*
 * @tc.name: RefreshReservedBundleIdSet002
 * @tc.desc: RefreshReservedBundleIdSet with empty set clears DB and memory
 * @tc.type: FUNC
 * @tc.require: TDD
 */
HWTEST_F(AccessTokenIdManagerCoverageTest, RefreshReservedBundleIdSet002, TestSize.Level4)
{
    auto& manager = AccessTokenIDManager::GetInstance();
    std::set<int32_t> emptySet;
    ASSERT_EQ(RET_SUCCESS, manager.RefreshReservedBundleIdSet(emptySet));
    ASSERT_TRUE(manager.reservedBundleIdSet_.empty());

    DelInfo delInfo;
    delInfo.delType = AtmDataType::ACCESSTOKEN_SYSTEM_CONFIG;
    ASSERT_EQ(RET_SUCCESS, AccessTokenDbOperator::DeleteAndInsertValues({ delInfo }, {}));
}

/*
 * @tc.name: RefreshReservedBundleIdSet003
 * @tc.desc: RefreshReservedBundleIdSet memory unchanged on DB write failure
 * @tc.type: FUNC
 * @tc.require: TDD
 */
HWTEST_F(AccessTokenIdManagerCoverageTest, RefreshReservedBundleIdSet003, TestSize.Level4)
{
    auto& manager = AccessTokenIDManager::GetInstance();
    manager.reservedBundleIdSet_.insert(TEST_BUNDLE_ID_BASE);
    manager.bundleIdSet_.insert(TEST_BUNDLE_ID_BASE);
    std::shared_ptr<NativeRdb::RdbStore> db = AccessTokenDb::GetInstance()->GetRdb();
    ASSERT_NE(nullptr, db);
    db->createTransFlag_ = NativeRdb::RdbStore::RdbStoreOperationResult::RESULT_FAIL;
    std::set<int32_t> newSet = { TEST_BUNDLE_ID_1 };
    ASSERT_NE(RET_SUCCESS, manager.RefreshReservedBundleIdSet(newSet));
    ASSERT_EQ(1U, manager.reservedBundleIdSet_.count(TEST_BUNDLE_ID_BASE));
    ASSERT_EQ(1U, manager.bundleIdSet_.count(TEST_BUNDLE_ID_BASE));
    db->createTransFlag_ = 0;
}

/*
 * @tc.name: GetReservedBundleIdList001
 * @tc.desc: Parse valid JSON list into set
 * @tc.type: FUNC
 * @tc.require: TDD
 */
HWTEST_F(AccessTokenIdManagerCoverageTest, GetReservedBundleIdList001, TestSize.Level4)
{
    ConfigPolicLoader loader;
    std::set<int32_t> bundleList;
    ASSERT_EQ(RET_SUCCESS, loader.GetReservedBundleIdList("{\"list\":[10000,10001,10002]}", bundleList));
    ASSERT_EQ(3U, bundleList.size());
    ASSERT_EQ(1U, bundleList.count(TEST_BUNDLE_ID_BASE));
    ASSERT_EQ(1U, bundleList.count(TEST_BUNDLE_ID_1));
    ASSERT_EQ(1U, bundleList.count(TEST_BUNDLE_ID_2));
}

/*
 * @tc.name: GetReservedBundleIdList002
 * @tc.desc: Empty string returns empty set
 * @tc.type: FUNC
 * @tc.require: TDD
 */
HWTEST_F(AccessTokenIdManagerCoverageTest, GetReservedBundleIdList002, TestSize.Level4)
{
    ConfigPolicLoader loader;
    std::set<int32_t> bundleList;
    ASSERT_EQ(RET_SUCCESS, loader.GetReservedBundleIdList("", bundleList));
    ASSERT_TRUE(bundleList.empty());
}

/*
 * @tc.name: GetReservedBundleIdList003
 * @tc.desc: Invalid JSON returns ERR_PARAM_INVALID
 * @tc.type: FUNC
 * @tc.require: TDD
 */
HWTEST_F(AccessTokenIdManagerCoverageTest, GetReservedBundleIdList003, TestSize.Level4)
{
    ConfigPolicLoader loader;
    std::set<int32_t> bundleList;
    ASSERT_EQ(ERR_PARAM_INVALID, loader.GetReservedBundleIdList("invalid json", bundleList));
}

/*
 * @tc.name: GetReservedBundleIdList004
 * @tc.desc: JSON missing list field returns ERR_PARAM_INVALID
 * @tc.type: FUNC
 * @tc.require: TDD
 */
HWTEST_F(AccessTokenIdManagerCoverageTest, GetReservedBundleIdList004, TestSize.Level4)
{
    ConfigPolicLoader loader;
    std::set<int32_t> bundleList;
    ASSERT_EQ(ERR_PARAM_INVALID, loader.GetReservedBundleIdList("{\"other\":[]}", bundleList));
}

/*
 * @tc.name: GetReservedBundleIdList005
 * @tc.desc: List containing non-number item returns ERR_PARAM_INVALID
 * @tc.type: FUNC
 * @tc.require: TDD
 */
HWTEST_F(AccessTokenIdManagerCoverageTest, GetReservedBundleIdList005, TestSize.Level4)
{
    ConfigPolicLoader loader;
    std::set<int32_t> bundleList;
    ASSERT_EQ(ERR_PARAM_INVALID, loader.GetReservedBundleIdList("{\"list\":[10000,\"abc\"]}", bundleList));
}

/*
 * @tc.name: BuildReservedBundleIdList001
 * @tc.desc: Build JSON from non-empty set
 * @tc.type: FUNC
 * @tc.require: TDD
 */
HWTEST_F(AccessTokenIdManagerCoverageTest, BuildReservedBundleIdList001, TestSize.Level4)
{
    ConfigPolicLoader loader;
    std::set<int32_t> bundleList = { TEST_BUNDLE_ID_BASE, TEST_BUNDLE_ID_1 };
    std::string result = loader.BuildReservedBundleIdList(bundleList);
    ASSERT_FALSE(result.empty());
    // Verify round-trip: parse the built JSON
    std::set<int32_t> parsed;
    ASSERT_EQ(RET_SUCCESS, loader.GetReservedBundleIdList(result, parsed));
    ASSERT_EQ(2U, parsed.size());
    ASSERT_EQ(1U, parsed.count(TEST_BUNDLE_ID_BASE));
    ASSERT_EQ(1U, parsed.count(TEST_BUNDLE_ID_1));
}

/*
 * @tc.name: BuildReservedBundleIdList002
 * @tc.desc: Build JSON from empty set returns valid empty list
 * @tc.type: FUNC
 * @tc.require: TDD
 */
HWTEST_F(AccessTokenIdManagerCoverageTest, BuildReservedBundleIdList002, TestSize.Level4)
{
    ConfigPolicLoader loader;
    std::set<int32_t> emptyList;
    std::string result = loader.BuildReservedBundleIdList(emptyList);
    ASSERT_FALSE(result.empty());
    // Verify round-trip: parse the built JSON
    std::set<int32_t> parsed;
    ASSERT_EQ(RET_SUCCESS, loader.GetReservedBundleIdList(result, parsed));
    ASSERT_TRUE(parsed.empty());
}

/*
 * @tc.name: ConfigPolicyLoaderDefault001
 * @tc.desc: Base class default implementation returns empty results
 * @tc.type: FUNC
 * @tc.require: TDD
 */
HWTEST_F(AccessTokenIdManagerCoverageTest, ConfigPolicyLoaderDefault001, TestSize.Level4)
{
    ConfigPolicLoader loader;
    std::set<int32_t> bundleList = { TEST_BUNDLE_ID_BASE };
    ASSERT_EQ(RET_SUCCESS, loader.ConfigPolicyLoaderInterface::GetReservedBundleIdList("any", bundleList));
    ASSERT_TRUE(bundleList.empty());
    ASSERT_TRUE(loader.ConfigPolicyLoaderInterface::BuildReservedBundleIdList({ 10000 }).empty());
}
} // namespace AccessToken
} // namespace Security
} // namespace OHOS
