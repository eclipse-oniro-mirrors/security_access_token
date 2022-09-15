/*
 * Copyright (c) 2022 Huawei Device Co., Ltd.
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
#include <memory>
#include <string>
#include "sqlite_storage.h"
#include "generic_values.h"
#include "variant_value.h"

using namespace testing::ext;

namespace OHOS {
namespace Security {
namespace AccessToken {
namespace {
static constexpr int32_t GET_INT64_TRUE_VALUE = -1;
static constexpr int32_t ROLLBACK_TRANSACTION_RESULT_ABNORMAL = -1;
static constexpr int32_t EXECUTESQL_RESULT_ABNORMAL = -1;
static const int32_t DEFAULT_VALUE = -1;
} // namespace
class DatabaseTest : public testing::Test {
public:
    static void SetUpTestCase(void);
    static void TearDownTestCase(void);
    void SetUp();
    void TearDown();
};

void DatabaseTest::SetUpTestCase(void)
{}
void DatabaseTest::TearDownTestCase(void)
{}
void DatabaseTest::SetUp(void)
{}
void DatabaseTest::TearDown(void)
{}

/**
 * @tc.name: PutInt64001
 * @tc.desc: Verify the GenericValues put and get int64 value function.
 * @tc.type: FUNC
 * @tc.require: Issue Number
 */
HWTEST_F(DatabaseTest, PutInt64001, TestSize.Level1)
{
    GenericValues outGenericValues;
    std::string key = "databasetest";
    int64_t data = 1;
    outGenericValues.Put(key, data);
    int64_t outdata = outGenericValues.GetInt64(key);
    EXPECT_EQ(outdata, data);
    outGenericValues.Remove(key);
    outdata = outGenericValues.GetInt64(key);
    EXPECT_EQ(GET_INT64_TRUE_VALUE, outdata);
}

/**
 * @tc.name: RollbackTransaction001
 * @tc.desc: RollbackTransaction001 Abnormal branch res != SQLITE_OK
 * @tc.type: FUNC
 * @tc.require: Issue Number
 */
HWTEST_F(DatabaseTest, RollbackTransaction001, TestSize.Level1)
{
    int32_t result = SqliteStorage::GetInstance().RollbackTransaction();
    EXPECT_EQ(result, ROLLBACK_TRANSACTION_RESULT_ABNORMAL);
}

/**
 * @tc.name: RollbackTransaction002
 * @tc.desc: RollbackTransaction002 Abnormal branch db_ = nullptr
 * @tc.type: FUNC
 * @tc.require: Issue Number
 */
HWTEST_F(DatabaseTest, RollbackTransaction002, TestSize.Level1)
{
    SqliteStorage::GetInstance().Close();
    EXPECT_EQ(SqliteStorage::GetInstance().RollbackTransaction(), ROLLBACK_TRANSACTION_RESULT_ABNORMAL);
}

/**
 * @tc.name: ExecuteSql001
 * @tc.desc: ExecuteSql001 Abnormal branch res != SQLITE_OK
 * @tc.type: FUNC
 * @tc.require: Issue Number
 */
HWTEST_F(DatabaseTest, ExecuteSql001, TestSize.Level1)
{
    std::string testSql = "test";
    EXPECT_EQ(SqliteStorage::GetInstance().ExecuteSql(testSql), EXECUTESQL_RESULT_ABNORMAL);
}

/**
 * @tc.name: ExecuteSql002
 * @tc.desc: ExecuteSql002 Abnormal branch db_ = nullptr
 * @tc.type: FUNC
 * @tc.require: Issue Number
 */
HWTEST_F(DatabaseTest, ExecuteSql002, TestSize.Level1)
{
    std::string testSql = "test";
    SqliteStorage::GetInstance().Close();
    EXPECT_EQ(SqliteStorage::GetInstance().ExecuteSql(testSql), EXECUTESQL_RESULT_ABNORMAL);
}

/**
 * @tc.name: SpitError001
 * @tc.desc: SpitError001 Abnormal branch db_ = nullptr
 * @tc.type: FUNC
 * @tc.require: Issue Number
 */
HWTEST_F(DatabaseTest, SpitError001, TestSize.Level1)
{
    SqliteStorage::GetInstance().Close();
    std::string result = SqliteStorage::GetInstance().SpitError().c_str();
    EXPECT_EQ(result.empty(), true);
}

/**
 * @tc.name: SpitError002
 * @tc.desc: SpitError002 use SpitError
 * @tc.type: FUNC
 * @tc.require: Issue Number
 */
HWTEST_F(DatabaseTest, SpitError002, TestSize.Level1)
{
    SqliteStorage::GetInstance().Open();
    std::string result = SqliteStorage::GetInstance().SpitError().c_str();
    EXPECT_EQ(result.length() > 0, true);
}

/**
 * @tc.name: VariantValue64001
 * @tc.desc: VariantValue64001 use VariantValue
 * @tc.type: FUNC
 * @tc.require: Issue Number
 */
HWTEST_F(DatabaseTest, VariantValue64001, TestSize.Level1)
{
    int64_t testValue = 1;
    VariantValue Test(testValue);
    EXPECT_EQ(Test.GetInt64(), testValue);
}

/**
 * @tc.name: VariantValue64002
 * @tc.desc: VariantValue64002 getint and getint64 Abnormal branch
 * @tc.type: FUNC
 * @tc.require: Issue Number
 */
HWTEST_F(DatabaseTest, VariantValue64002, TestSize.Level1)
{
    int32_t ntestValue = 1;
    VariantValue Ntest(ntestValue);
    EXPECT_EQ(DEFAULT_VALUE, Ntest.GetInt64());
    int64_t testValue = 1;
    VariantValue Test(testValue);
    EXPECT_EQ(DEFAULT_VALUE, Test.GetInt());
}
} // namespace AccessToken
} // namespace Security
} // namespace OHOS