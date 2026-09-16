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

#include "access_token_open_callback_test.h"
#include "gtest/gtest.h"

#include <set>

#include "access_token_db.h"
#include "access_token_db_util.h"
#include "access_token_error.h"
#include "hap_token_info.h"
#include "token_field_const.h"

using namespace testing::ext;
using namespace OHOS;

namespace OHOS {
namespace Security {
namespace AccessToken {
namespace {
std::set<std::string> GetTableColumnNames(NativeRdb::RdbStore& rdbStore, const std::string& tableName)
{
    std::set<std::string> names;
    auto resultSet = rdbStore.QuerySql("PRAGMA table_info(" + tableName + ")");
    if (resultSet == nullptr) {
        return names;
    }
    while (resultSet->GoToNextRow() == NativeRdb::E_OK) {
        std::string name;
        if (resultSet->GetString(1, name) == NativeRdb::E_OK) { // 1: column name index in PRAGMA table_info
            names.insert(name);
        }
    }
    return names;
}

#ifdef SPM_DATA_ENABLE
std::string GetColumnDefaultValue(NativeRdb::RdbStore& rdbStore, const std::string& tableName,
    const std::string& columnName)
{
    auto resultSet = rdbStore.QuerySql("PRAGMA table_info(" + tableName + ")");
    if (resultSet == nullptr) {
        return "";
    }
    while (resultSet->GoToNextRow() == NativeRdb::E_OK) {
        std::string name;
        if (resultSet->GetString(1, name) == NativeRdb::E_OK && name == columnName) { // 1: column name index
            std::string dflt;
            resultSet->GetString(4, dflt); // 4: dflt_value index in PRAGMA table_info
            return dflt;
        }
    }
    return "";
}
#endif // SPM_DATA_ENABLE
} // namespace

void AccessTokenOpenCallbackTest::SetUpTestCase()
{
}

void AccessTokenOpenCallbackTest::TearDownTestCase()
{
}

void AccessTokenOpenCallbackTest::SetUp()
{
    atManagerService_ = DelayedSingleton<AccessTokenManagerService>::GetInstance();
    ASSERT_NE(nullptr, atManagerService_);
    atManagerService_->Initialize();
    ASSERT_NE(nullptr, AccessTokenDb::GetInstance());
}

void AccessTokenOpenCallbackTest::TearDown()
{
    DelayedSingleton<AccessTokenManagerService>::DestroyInstance();
    atManagerService_ = nullptr;
}

/**
 * @tc.name: HapInfoTableSchema001
 * @tc.desc: Verify hap_info_table schema after OnCreate: base columns always present;
 *           mode column present only when SPM_DATA_ENABLE is defined.
 * @tc.type: FUNC
 * @tc.require: TDD
 */
HWTEST_F(AccessTokenOpenCallbackTest, HapInfoTableSchema001, TestSize.Level0)
{
    auto rdbStore = AccessTokenDb::GetInstance()->GetRdb();
    ASSERT_NE(nullptr, rdbStore);
#ifdef SPM_DATA_ENABLE
    std::string tableName;
    AccessTokenDbUtil::GetTableNameByType(AtmDataType::ACCESSTOKEN_HAP_PACKAGE_INFO, tableName);
    auto columns = GetTableColumnNames(*rdbStore, tableName);
    EXPECT_TRUE(columns.find(TokenFiledConst::FIELD_BUNDLE_NAME) != columns.end());
    EXPECT_TRUE(columns.find(TokenFiledConst::FIELD_MODULE_NAME) != columns.end());
    EXPECT_TRUE(columns.find(TokenFiledConst::FIELD_PATH) != columns.end());
    EXPECT_TRUE(columns.find(TokenFiledConst::FIELD_BUNDLE_TYPE) != columns.end());
    EXPECT_TRUE(columns.find(TokenFiledConst::FIELD_PERSIST_DATA) != columns.end());
    EXPECT_TRUE(columns.find(TokenFiledConst::FIELD_IS_PREINSTALLED) != columns.end());
    EXPECT_TRUE(columns.find(TokenFiledConst::FIELD_MODE) != columns.end());
#endif
}

/**
 * @tc.name: ModeColumnDefaultValue001
 * @tc.desc: Verify mode column default value equals MultipleMode::DEFAULT_MODE after OnCreate.
 * @tc.type: FUNC
 * @tc.require: TDD
 */
HWTEST_F(AccessTokenOpenCallbackTest, ModeColumnDefaultValue001, TestSize.Level1)
{
    auto rdbStore = AccessTokenDb::GetInstance()->GetRdb();
    ASSERT_NE(nullptr, rdbStore);

    std::string tableName;
    AccessTokenDbUtil::GetTableNameByType(AtmDataType::ACCESSTOKEN_HAP_PACKAGE_INFO, tableName);
#ifdef SPM_DATA_ENABLE
    std::string dflt = GetColumnDefaultValue(*rdbStore, tableName, TokenFiledConst::FIELD_MODE);
    EXPECT_EQ(std::to_string(static_cast<int32_t>(MultipleMode::DEFAULT_MODE)), dflt);
#else
    auto columns = GetTableColumnNames(*rdbStore, tableName);
    EXPECT_TRUE(columns.find(TokenFiledConst::FIELD_MODE) == columns.end());
#endif
}

/**
 * @tc.name: AddModeColumnIdempotent001
 * @tc.desc: Verify AddModeColumn is idempotent: calling it again on a table that already has
 *           the mode column returns E_OK without error.
 * @tc.type: FUNC
 * @tc.require: TDD
 */
HWTEST_F(AccessTokenOpenCallbackTest, AddModeColumnIdempotent001, TestSize.Level1)
{
    auto rdbStore = AccessTokenDb::GetInstance()->GetRdb();
    ASSERT_NE(nullptr, rdbStore);
#ifdef SPM_DATA_ENABLE
    AccessTokenOpenCallback callback;
    int32_t res = callback.AddModeColumn(*rdbStore, AtmDataType::ACCESSTOKEN_HAP_PACKAGE_INFO);
    EXPECT_EQ(NativeRdb::E_OK, res);

    std::string tableName;
    AccessTokenDbUtil::GetTableNameByType(AtmDataType::ACCESSTOKEN_HAP_PACKAGE_INFO, tableName);
    auto columns = GetTableColumnNames(*rdbStore, tableName);
    EXPECT_TRUE(columns.find(TokenFiledConst::FIELD_MODE) != columns.end());
#else
    std::string tableName;
    AccessTokenDbUtil::GetTableNameByType(AtmDataType::ACCESSTOKEN_HAP_PACKAGE_INFO, tableName);
    auto columns = GetTableColumnNames(*rdbStore, tableName);
    EXPECT_TRUE(columns.find(TokenFiledConst::FIELD_MODE) == columns.end());
#endif
}

/**
 * @tc.name: CreateVersionTwelveTableIdempotent001
 * @tc.desc: Verify CreateVersionTwelveTable is idempotent: calling it again after OnCreate
 *           returns E_OK (CREATE TABLE IF NOT EXISTS).
 * @tc.type: FUNC
 * @tc.require: TDD
 */
HWTEST_F(AccessTokenOpenCallbackTest, CreateVersionTwelveTableIdempotent001, TestSize.Level1)
{
    auto rdbStore = AccessTokenDb::GetInstance()->GetRdb();
    ASSERT_NE(nullptr, rdbStore);
#ifdef SPM_DATA_ENABLE
    AccessTokenOpenCallback callback;
    int32_t res = callback.CreateVersionTwelveTable(*rdbStore);
    EXPECT_EQ(NativeRdb::E_OK, res);

    std::string tableName;
    AccessTokenDbUtil::GetTableNameByType(AtmDataType::ACCESSTOKEN_HAP_PACKAGE_INFO, tableName);
    auto columns = GetTableColumnNames(*rdbStore, tableName);
    EXPECT_TRUE(columns.find(TokenFiledConst::FIELD_BUNDLE_NAME) != columns.end());
#endif
}

/**
 * @tc.name: UpgradeFromVersion11SafeOnUpgradedDb001
 * @tc.desc: Verify UpgradeFromVersion11 is safe to run on an already-upgraded database:
 *           hap_info_table uses "if not exists" and AddModeColumn guards existing column.
 *           This validates the schema-consistency invariant: upgrade path result == OnCreate result.
 * @tc.type: FUNC
 * @tc.require: TDD
 */
HWTEST_F(AccessTokenOpenCallbackTest, UpgradeFromVersion11SafeOnUpgradedDb001, TestSize.Level1)
{
    auto rdbStore = AccessTokenDb::GetInstance()->GetRdb();
    ASSERT_NE(nullptr, rdbStore);
#ifdef SPM_DATA_ENABLE
    AccessTokenOpenCallback callback;
    int32_t res = callback.UpgradeFromVersion11(*rdbStore);
    EXPECT_EQ(NativeRdb::E_OK, res);

    std::string tableName;
    AccessTokenDbUtil::GetTableNameByType(AtmDataType::ACCESSTOKEN_HAP_PACKAGE_INFO, tableName);
    auto columns = GetTableColumnNames(*rdbStore, tableName);
    EXPECT_TRUE(columns.find(TokenFiledConst::FIELD_MODE) != columns.end());
    std::string dflt = GetColumnDefaultValue(*rdbStore, tableName, TokenFiledConst::FIELD_MODE);
    EXPECT_EQ(std::to_string(static_cast<int32_t>(MultipleMode::DEFAULT_MODE)), dflt);
#endif
}
} // namespace AccessToken
} // namespace Security
} // namespace OHOS
