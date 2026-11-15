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
#include <gtest/hwext/gtest-tag.h>

#include <vector>

#include "access_token_error.h"
#include "atm_bundle_recovery_info.h"
#include "mock_access_token_db_operator.h"
#define private public
#include "rebuild_database_scheduler.h"
#undef private

using namespace testing::ext;

namespace OHOS {
namespace Security {
namespace AccessToken {

class RebuildDatabaseSchedulerTest : public testing::Test {
public:
    void SetUp() override
    {
        auto& scheduler = RebuildDatabaseScheduler::GetInstance();
        scheduler.addInfoVec_.clear();
        scheduler.addedTokenId_.clear();
        scheduler.addedHapTokenKey_.clear();
        scheduler.addedBundleKey_.clear();
        scheduler.hasTestQueryResult_ = false;
        ResetMockDbState();
    }
};

/**
 * @tc.name: PersistRebuildDatabase001
 * @tc.desc: Verify PersistRebuildDatabase returns success when no record to persist.
 * @tc.type: FUNC
 */
HWTEST_F(RebuildDatabaseSchedulerTest, PersistRebuildDatabase001, TestSize.Level1)
{
    auto& scheduler = RebuildDatabaseScheduler::GetInstance();
    scheduler.addInfoVec_.clear();
    EXPECT_EQ(0, scheduler.PersistRebuildDatabase());
}

/**
 * @tc.name: RebuildOneBundleStatFail001
 * @tc.desc: Verify RebuildOneBundle returns RET_SUCCESS when the sandbox data dir does not exist
 *           (ResolveUidByFstat stat fails, uid keeps -1 and rebuild continues).
 * @tc.type: FUNC
 */
HWTEST_F(RebuildDatabaseSchedulerTest, RebuildOneBundleStatFail001, TestSize.Level1)
{
    auto& scheduler = RebuildDatabaseScheduler::GetInstance();
    RebuildDatabaseItem item;
    item.info.bundleName = "com.example.nonexistent";
    item.info.appIndex = 0;
    item.info.userId = 100;

    EXPECT_EQ(RET_SUCCESS, scheduler.RebuildOneBundle(item));
}

/**
 * @tc.name: PersistRebuildDatabaseFail001
 * @tc.desc: Verify PersistRebuildDatabase returns the database error when the write transaction fails.
 * @tc.type: FUNC
 */
HWTEST_F(RebuildDatabaseSchedulerTest, PersistRebuildDatabaseFail001, TestSize.Level1)
{
    auto& scheduler = RebuildDatabaseScheduler::GetInstance();
    AddInfo addInfo;
    addInfo.addType = AtmDataType::ACCESSTOKEN_HAP_TOKEN_INFO;
    scheduler.addInfoVec_.emplace_back(addInfo);
    GetMockDbState().deleteAndInsertRet = AccessTokenError::ERR_DATABASE_OPERATE_FAILED;

    EXPECT_EQ(AccessTokenError::ERR_DATABASE_OPERATE_FAILED, scheduler.PersistRebuildDatabase());
}

/**
 * @tc.name: StartRebuildDatabaseFetchFail001
 * @tc.desc: Verify StartRebuildDatabase returns the query error when fetching the app info list fails.
 * @tc.type: FUNC
 */
HWTEST_F(RebuildDatabaseSchedulerTest, StartRebuildDatabaseFetchFail001, TestSize.Level1)
{
    auto& scheduler = RebuildDatabaseScheduler::GetInstance();
    AppExecFwk::AtmBundleRecoveryResult result;
    result.code = AccessTokenError::ERR_DATABASE_OPERATE_FAILED;
    scheduler.SetQueryResult(result);

    RebuildDatabaseData rebuildDatabaseData;
    EXPECT_EQ(AccessTokenError::ERR_DATABASE_OPERATE_FAILED,
        scheduler.StartRebuildDatabase(rebuildDatabaseData));
}

/**
 * @tc.name: StartRebuildDatabaseEmpty001
 * @tc.desc: Verify StartRebuildDatabase returns success when the app info list is empty.
 * @tc.type: FUNC
 */
HWTEST_F(RebuildDatabaseSchedulerTest, StartRebuildDatabaseEmpty001, TestSize.Level1)
{
    auto& scheduler = RebuildDatabaseScheduler::GetInstance();
    AppExecFwk::AtmBundleRecoveryResult result;
    result.code = 0;
    scheduler.SetQueryResult(result);

    RebuildDatabaseData rebuildDatabaseData;
    EXPECT_EQ(0, scheduler.StartRebuildDatabase(rebuildDatabaseData));
}

/**
 * @tc.name: StartRebuildDatabasePersistFailWithThreadMsg001
 * @tc.desc: StartRebuildDatabase reports thread error message when persist fails and a LOGC was triggered.
 * @tc.type: FUNC
 */
HWTEST_F(RebuildDatabaseSchedulerTest, StartRebuildDatabasePersistFailWithThreadMsg001, TestSize.Level1)
{
    auto& scheduler = RebuildDatabaseScheduler::GetInstance();
    AppExecFwk::AtmBundleRecoveryResult result;
    result.code = 0;
    AppExecFwk::AtmBundleRecoveryInfo info;
    info.bundleName = "com.example.nonexistent";
    info.accessTokenId = 0x20000001;
    info.userId = 100;
    info.appIndex = 0;
    result.infos = { info };
    scheduler.SetQueryResult(result);
    GetMockDbState().deleteAndInsertRet = AccessTokenError::ERR_DATABASE_OPERATE_FAILED;

    RebuildDatabaseData rebuildDatabaseData;
    EXPECT_EQ(AccessTokenError::ERR_DATABASE_OPERATE_FAILED,
        scheduler.StartRebuildDatabase(rebuildDatabaseData));
}

/**
 * @tc.name: FillRebuildDatabaseDataDefault001
 * @tc.desc: FillRebuildDatabaseData ignores add infos whose type is neither hap token nor hap package.
 * @tc.type: FUNC
 */
HWTEST_F(RebuildDatabaseSchedulerTest, FillRebuildDatabaseDataDefault001, TestSize.Level1)
{
    auto& scheduler = RebuildDatabaseScheduler::GetInstance();
    AddInfo addInfo;
    addInfo.addType = AtmDataType::ACCESSTOKEN_PERMISSION_STATE;
    scheduler.addInfoVec_ = { addInfo };

    RebuildDatabaseData rebuildDatabaseData;
    scheduler.FillRebuildDatabaseData(rebuildDatabaseData);
    EXPECT_TRUE(rebuildDatabaseData.hapTokenInfoRes.empty());
    EXPECT_TRUE(rebuildDatabaseData.hapSignInfoRes.empty());
}

/**
 * @tc.name: RebuildOneBundleNotUninstalled001
 * @tc.desc: RebuildOneBundle builds hap info record when the app is not uninstalled.
 * @tc.type: FUNC
 */
HWTEST_F(RebuildDatabaseSchedulerTest, RebuildOneBundleNotUninstalled001, TestSize.Level1)
{
    auto& scheduler = RebuildDatabaseScheduler::GetInstance();
    RebuildDatabaseItem item;
    item.info.bundleName = "com.example.notuninstalled";
    item.info.accessTokenId = 0x20000001;
    item.info.userId = 100;
    item.info.appIndex = 0;
    item.info.isUninstalled = false;
    item.info.hapPaths = { "/data/test_temp/test.hap" };

    EXPECT_EQ(RET_SUCCESS, scheduler.RebuildOneBundle(item));
    bool hasTokenInfo = false;
    bool hasPackageInfo = false;
    for (const auto& addInfo : scheduler.addInfoVec_) {
        if (addInfo.addType == AtmDataType::ACCESSTOKEN_HAP_TOKEN_INFO) {
            hasTokenInfo = true;
        }
        if (addInfo.addType == AtmDataType::ACCESSTOKEN_HAP_PACKAGE_INFO) {
            hasPackageInfo = true;
        }
    }
    EXPECT_TRUE(hasTokenInfo);
    EXPECT_TRUE(hasPackageInfo);
}

/**
 * @tc.name: BuildHapTokenRecordDuplicateToken001
 * @tc.desc: BuildHapTokenRecord skips duplicated accessTokenId.
 * @tc.type: FUNC
 */
HWTEST_F(RebuildDatabaseSchedulerTest, BuildHapTokenRecordDuplicateToken001, TestSize.Level1)
{
    auto& scheduler = RebuildDatabaseScheduler::GetInstance();
    RebuildDatabaseItem item;
    item.info.bundleName = "com.example.duptoken";
    item.info.accessTokenId = 0x20000001;
    item.info.userId = 100;
    item.info.appIndex = 0;

    scheduler.BuildHapTokenRecord(item, -1);
    scheduler.BuildHapTokenRecord(item, -1);
    EXPECT_EQ(1U, scheduler.addedTokenId_.size());
    EXPECT_EQ(1U, scheduler.addInfoVec_.size());
}

/**
 * @tc.name: BuildHapTokenRecordDuplicateKey001
 * @tc.desc: BuildHapTokenRecord skips duplicated bundleName+userId+instIndex key.
 * @tc.type: FUNC
 */
HWTEST_F(RebuildDatabaseSchedulerTest, BuildHapTokenRecordDuplicateKey001, TestSize.Level1)
{
    auto& scheduler = RebuildDatabaseScheduler::GetInstance();
    RebuildDatabaseItem item1;
    item1.info.bundleName = "com.example.dupkey";
    item1.info.accessTokenId = 0x20000001;
    item1.info.userId = 100;
    item1.info.appIndex = 0;

    RebuildDatabaseItem item2 = item1;
    item2.info.accessTokenId = 0x20000002;

    scheduler.BuildHapTokenRecord(item1, -1);
    scheduler.BuildHapTokenRecord(item2, -1);
    EXPECT_EQ(2U, scheduler.addedTokenId_.size());
    EXPECT_EQ(1U, scheduler.addedHapTokenKey_.size());
    EXPECT_EQ(1U, scheduler.addInfoVec_.size());
}

/**
 * @tc.name: BuildHapInfoRecordDuplicate001
 * @tc.desc: BuildHapInfoRecord skips duplicated bundleKey.
 * @tc.type: FUNC
 */
HWTEST_F(RebuildDatabaseSchedulerTest, BuildHapInfoRecordDuplicate001, TestSize.Level1)
{
    auto& scheduler = RebuildDatabaseScheduler::GetInstance();
    RebuildDatabaseItem item;
    item.info.bundleName = "com.example.dupbundle";
    item.info.appIndex = 0;
    item.info.hapPaths = { "/data/test_temp/test.hap" };

    scheduler.BuildHapInfoRecord(item);
    scheduler.BuildHapInfoRecord(item);
    EXPECT_EQ(1U, scheduler.addedBundleKey_.size());
    EXPECT_EQ(1U, scheduler.addInfoVec_.size());
}
} // namespace AccessToken
} // namespace Security
} // namespace OHOS