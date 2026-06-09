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
#include <gtest/hwext/gtest-tag.h>
#include <string>

#include "access_token_error.h"
#include "accesstoken_kit.h"
#include "nativetoken_kit.h"
#include "token_setproc.h"
#include "test_common.h"

using namespace testing::ext;

namespace OHOS {
namespace Security {
namespace AccessToken {
namespace {
static uint64_t g_selfTokenId = 0;
static MockNativeToken* g_mock = nullptr;
}

class MigrateInstalledBundlesTest : public testing::Test {
public:
    static void SetUpTestCase()
    {
        g_selfTokenId = GetSelfTokenID();
        TestCommon::SetTestEvironment(g_selfTokenId);
        g_mock = new (std::nothrow) MockNativeToken("foundation");
    }

    static void TearDownTestCase()
    {
        if (g_mock != nullptr) {
            delete g_mock;
            g_mock = nullptr;
        }
        SetSelfTokenID(g_selfTokenId);
        TestCommon::ResetTestEvironment();
    }
};

HWTEST_F(MigrateInstalledBundlesTest, PreMigrateUIDList001, TestSize.Level1)
{
    EXPECT_EQ(AccessTokenError::ERR_PARAM_INVALID, AccessTokenKit::PreMigrateUIDList({}));
}

/**
 * @tc.name: PreMigrateUIDList002
 * @tc.desc: PreMigrateUIDList with duplicate values returns ERR_MIGRATION_UID_DUPLICATED.
 * @tc.type: FUNC
 */
HWTEST_F(MigrateInstalledBundlesTest, PreMigrateUIDList002, TestSize.Level1)
{
    int32_t ret = AccessTokenKit::PreMigrateUIDList({ 200001, 200001 });
    bool pass = ret == AccessTokenError::ERR_MIGRATION_UID_DUPLICATED ||
                ret == AccessTokenError::ERR_MIGRATION_COMPLETED;
    EXPECT_TRUE(pass);
}


static constexpr size_t MAX_MIGRATED_INFO_SIZE = 50;
/**
 * @tc.name: MigrateInstalledBundles001
 * @tc.desc: MigrateInstalledBundles with list size exceeding MAX_MIGRATED_INFO_SIZE returns ERR_PARAM_INVALID.
 *           Validated at kit layer before IPC.
 * @tc.type: FUNC
 */
HWTEST_F(MigrateInstalledBundlesTest, MigrateInstalledBundles001, TestSize.Level1)
{
    std::vector<MigratedInfo> migratedInfoList(MAX_MIGRATED_INFO_SIZE + 1);
    for (size_t i = 0; i < migratedInfoList.size(); ++i) {
        migratedInfoList[i].bundleName = "com.example.bundle" + std::to_string(i);
    }

    std::vector<BundleMigrateResult> results;
    EXPECT_EQ(AccessTokenError::ERR_PARAM_INVALID, AccessTokenKit::MigrateInstalledBundles(migratedInfoList, results));
    EXPECT_TRUE(results.empty());
}

/**
 * @tc.name: MigrateInstalledBundles002
 * @tc.desc: Kit-layer validation: empty list passes size check, goes to IPC;
 *           service returns RET_SUCCESS with empty results.
 * @tc.type: FUNC
 */
HWTEST_F(MigrateInstalledBundlesTest, MigrateInstalledBundles002, TestSize.Level1)
{
    std::vector<MigratedInfo> emptyList;
    std::vector<BundleMigrateResult> results;
    int32_t ret = AccessTokenKit::MigrateInstalledBundles(emptyList, results);
    // Depending on whether migration has been finished in the test environment
    bool pass = ret == RET_SUCCESS || ret == ERR_MIGRATION_COMPLETED;
    EXPECT_TRUE(pass);
}

/**
 * @tc.name: MigrateInstalledBundles003
 * @tc.desc: Kit-layer validation: single entry with missing hapBaseInfoList reaches
 *           service, service validates shape and returns per-item ERR_PARAM_INVALID.
 * @tc.type: FUNC
 */
HWTEST_F(MigrateInstalledBundlesTest, MigrateInstalledBundles003, TestSize.Level1)
{
    MigratedInfo migratedInfo;
    migratedInfo.bundleName = "com.example.bundle";
    migratedInfo.pathList.hapPaths = {"/data/test.hap"};
    migratedInfo.pathList.isPreInstalled = false;
    migratedInfo.uidList = {100};
    migratedInfo.reservedTypeList = {ReservedType::RESERVED_IDENTITY};

    std::vector<BundleMigrateResult> results;
    int32_t ret = AccessTokenKit::MigrateInstalledBundles({ migratedInfo }, results);
    bool pass = ret == RET_SUCCESS || ret == ERR_MIGRATION_COMPLETED;
    EXPECT_TRUE(pass);
    if (ret == RET_SUCCESS) {
        ASSERT_EQ(1u, results.size());
        EXPECT_EQ(AccessTokenError::ERR_PARAM_INVALID, results[0].errcode);
    }
}

/**
 * @tc.name: MigrateInstalledBundles004
 * @tc.desc: MigrateInstalledBundles after FinishMigration returns ERR_MIGRATION_COMPLETED with empty results.
 * @tc.type: FUNC
 */
HWTEST_F(MigrateInstalledBundlesTest, MigrateInstalledBundles004, TestSize.Level1)
{
    std::vector<MigratedInfo> emptyList;
    std::vector<BundleMigrateResult> results;
    (void)AccessTokenKit::FinishMigration();
    int32_t ret = AccessTokenKit::MigrateInstalledBundles(emptyList, results);
    EXPECT_EQ(ret, ERR_MIGRATION_COMPLETED);
}

/**
* @tc.name: FinishMigration001
* @tc.desc: FinishMigration returns RET_SUCCESS or ERR_MIGRATION_COMPLETED on first call via IPC to service.
* @tc.type: FUNC
*/
HWTEST_F(MigrateInstalledBundlesTest, FinishMigration001, TestSize.Level1)
{
    int32_t ret = AccessTokenKit::FinishMigration();
    bool pass = ret == RET_SUCCESS || ret == ERR_MIGRATION_COMPLETED;
    EXPECT_TRUE(pass);
    EXPECT_EQ(AccessTokenKit::FinishMigration(), ERR_MIGRATION_COMPLETED);
}
} // namespace AccessToken
} // namespace Security
} // namespace OHOS
