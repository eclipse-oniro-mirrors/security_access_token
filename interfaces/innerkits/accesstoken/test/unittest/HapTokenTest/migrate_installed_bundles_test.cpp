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
        g_mock = new (std::nothrow) MockNativeToken("foundation");
    }

    static void TearDownTestCase()
    {
        if (g_mock != nullptr) {
            delete g_mock;
            g_mock = nullptr;
        }
        SetSelfTokenID(g_selfTokenId);
    }
};

HWTEST_F(MigrateInstalledBundlesTest, PreMigrateUIDList001, TestSize.Level1)
{
    EXPECT_EQ(AccessTokenError::ERR_PARAM_INVALID, AccessTokenKit::PreMigrateUIDList({}));
}

/**
 * @tc.name: PreMigrateUIDList002
 * @tc.desc: PreMigrateUIDList with list size exceeding MAX_LIST_SIZE (1024) returns ERR_PARAM_INVALID.
 *           Validated at kit layer before IPC.
 * @tc.type: FUNC
 */
HWTEST_F(MigrateInstalledBundlesTest, PreMigrateUIDList002, TestSize.Level1)
{
    std::vector<int32_t> largeList(1025, 200001);
    EXPECT_EQ(AccessTokenError::ERR_PARAM_INVALID, AccessTokenKit::PreMigrateUIDList(largeList));
}

HWTEST_F(MigrateInstalledBundlesTest, MigrateInstalledBundles001, TestSize.Level1)
{
    std::vector<MigratedInfo> migratedInfoList(51);
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
    EXPECT_EQ(RET_SUCCESS, AccessTokenKit::MigrateInstalledBundles(emptyList, results));
    EXPECT_TRUE(results.empty());
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
    EXPECT_EQ(RET_SUCCESS, AccessTokenKit::MigrateInstalledBundles({migratedInfo}, results));
    ASSERT_EQ(1u, results.size());
    EXPECT_EQ(AccessTokenError::ERR_PARAM_INVALID, results[0].errcode);
}

/**
 * @tc.name: FinishMigration001
 * @tc.desc: FinishMigration returns RET_SUCCESS on first call via IPC to service.
 * @tc.type: FUNC
 */
HWTEST_F(MigrateInstalledBundlesTest, FinishMigration001, TestSize.Level1)
{
    EXPECT_EQ(RET_SUCCESS, AccessTokenKit::FinishMigration());
}
} // namespace AccessToken
} // namespace Security
} // namespace OHOS
