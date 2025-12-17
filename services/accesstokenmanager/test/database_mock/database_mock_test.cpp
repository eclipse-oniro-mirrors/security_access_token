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

#define private public
#include "access_token_db.h"
#undef private
#include "access_token_error.h"
#include "token_field_const.h"

using namespace testing::ext;

namespace OHOS {
namespace Security {
namespace AccessToken {
namespace {
static int32_t INVALID_NUM = -1;
}

class AccessTokenDatabaseMockTest : public testing::Test {
public:
    static void SetUpTestCase();

    static void TearDownTestCase();

    void SetUp();

    void TearDown();
};

void AccessTokenDatabaseMockTest::SetUpTestCase() {}

void AccessTokenDatabaseMockTest::TearDownTestCase() {}

void AccessTokenDatabaseMockTest::SetUp() {}

void AccessTokenDatabaseMockTest::TearDown() {}

/*
 * @tc.name: AddValuesTest001
 * @tc.desc: test AddValues
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(AccessTokenDatabaseMockTest, AddValuesTest001, TestSize.Level4)
{
    AccessTokenDb accessTokenDb;
    auto rdb = accessTokenDb.GetRdb();
    ASSERT_NE(nullptr, rdb);
    auto [errcode, transaction] = rdb->CreateTransaction(NativeRdb::Transaction::TransactionType::DEFERRED);
    ASSERT_NE(nullptr, transaction);
    AddInfo addInfo;
    addInfo.addType = static_cast<AtmDataType>(INVALID_NUM);

    std::vector<AddInfo> addInfoVec;
    addInfoVec.push_back(addInfo);
    // invalid tableName
    EXPECT_EQ(AccessTokenError::ERR_PARAM_INVALID, accessTokenDb.AddValues(addInfoVec, transaction));

    addInfo.addType = ACCESSTOKEN_HAP_INFO;
    std::vector<AddInfo> addInfoVec2;
    addInfoVec2.push_back(addInfo);
    // empty addValues
    accessTokenDb.AddValues(addInfoVec2, transaction);

    GenericValues value;
    value.Put(TokenFiledConst::FIELD_PROCESS_NAME, "hdcd");
    addInfo.addValues.push_back(value);
    std::vector<AddInfo> addInfoVec3;
    addInfoVec3.push_back(addInfo);
    // outInsertNum is zero
    EXPECT_EQ(AccessTokenError::ERR_DATABASE_OPERATE_FAILED, accessTokenDb.AddValues(addInfoVec3, transaction));

    // BatchInsert return err
    transaction->insertFlag_ = NativeRdb::Transaction::TransactionOperationResult::OPERATION_FAIL;
    EXPECT_NE(NativeRdb::E_OK, accessTokenDb.AddValues(addInfoVec3, transaction));
}

/*
 * @tc.name: RemoveValuesTest001
 * @tc.desc: test RemoveValues
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(AccessTokenDatabaseMockTest, RemoveValuesTest001, TestSize.Level4)
{
    AccessTokenDb accessTokenDb;
    auto rdb = accessTokenDb.GetRdb();
    ASSERT_NE(nullptr, rdb);
    auto [errcode, transaction] = rdb->CreateTransaction(NativeRdb::Transaction::TransactionType::DEFERRED);
    ASSERT_NE(nullptr, transaction);
    DelInfo delInfo;
    delInfo.delType = static_cast<AtmDataType>(INVALID_NUM);

    std::vector<DelInfo> delInfoVec;
    delInfoVec.push_back(delInfo);
    // invalid tableName
    EXPECT_EQ(AccessTokenError::ERR_PARAM_INVALID, accessTokenDb.RemoveValues(delInfoVec, transaction));

    GenericValues value;
    value.Put(TokenFiledConst::FIELD_PROCESS_NAME, "hdcd");
    delInfo.delType = ACCESSTOKEN_HAP_INFO;
    delInfo.delValue = value;
    std::vector<DelInfo> delInfoVec2;
    delInfoVec2.push_back(delInfo);
    transaction->deleteFlag_ = NativeRdb::Transaction::TransactionOperationResult::OPERATION_FAIL;
    // RemoveValues return err
    EXPECT_NE(NativeRdb::E_OK, accessTokenDb.RemoveValues(delInfoVec2, transaction));
}

/*
 * @tc.name: DeleteAndInsertValuesInnerTest001
 * @tc.desc: test DeleteAndInsertValuesInner
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(AccessTokenDatabaseMockTest, DeleteAndInsertValuesInnerTest001, TestSize.Level4)
{
    AccessTokenDb accessTokenDb;
    auto rdb = accessTokenDb.GetRdb();
    ASSERT_NE(nullptr, rdb);
    std::vector<DelInfo> delInfoVec;
    std::vector<AddInfo> addInfoVec;

    // CreateTransaction return err
    rdb->createTransFlag_ = NativeRdb::RdbStore::RdbStoreOperationResult::RESULT_FAIL;
    EXPECT_NE(NativeRdb::E_OK, accessTokenDb.DeleteAndInsertValuesInner(delInfoVec, addInfoVec));

    // CreateTransaction transaction is nullptr
    rdb->createTransFlag_ = NativeRdb::RdbStore::RdbStoreOperationResult::TRANSACTION_NULL;
    EXPECT_NE(NativeRdb::E_OK, accessTokenDb.DeleteAndInsertValuesInner(delInfoVec, addInfoVec));
}

/*
 * @tc.name: DeleteAndInsertValuesInnerTest002
 * @tc.desc: test DeleteAndInsertValuesInner
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(AccessTokenDatabaseMockTest, DeleteAndInsertValuesInnerTest002, TestSize.Level4)
{
    AccessTokenDb accessTokenDb;
    auto rdb = accessTokenDb.GetRdb();
    ASSERT_NE(nullptr, rdb);
    std::vector<DelInfo> delInfoVec;
    std::vector<AddInfo> addInfoVec;

    DelInfo delInfo;
    delInfo.delType = static_cast<AtmDataType>(INVALID_NUM);
    delInfoVec.push_back(delInfo);

    // RemoveValues return err
    EXPECT_EQ(AccessTokenError::ERR_PARAM_INVALID, accessTokenDb.DeleteAndInsertValuesInner(delInfoVec, addInfoVec));
}

/*
 * @tc.name: DeleteAndInsertValuesInnerTest003
 * @tc.desc: test DeleteAndInsertValuesInner
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(AccessTokenDatabaseMockTest, DeleteAndInsertValuesInnerTest003, TestSize.Level4)
{
    AccessTokenDb accessTokenDb;
    auto rdb = accessTokenDb.GetRdb();
    ASSERT_NE(nullptr, rdb);
    std::vector<DelInfo> delInfoVec;
    std::vector<AddInfo> addInfoVec;

    AddInfo addInfo;
    addInfo.addType = static_cast<AtmDataType>(INVALID_NUM);
    addInfoVec.push_back(addInfo);

    // AddValues return err
    EXPECT_EQ(AccessTokenError::ERR_PARAM_INVALID, accessTokenDb.DeleteAndInsertValuesInner(delInfoVec, addInfoVec));
}

/*
 * @tc.name: DeleteAndInsertValuesInnerTest004
 * @tc.desc: test DeleteAndInsertValuesInner
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(AccessTokenDatabaseMockTest, DeleteAndInsertValuesInnerTest004, TestSize.Level4)
{
    AccessTokenDb accessTokenDb;
    auto rdb = accessTokenDb.GetRdb();
    ASSERT_NE(nullptr, rdb);
    auto [errcode, transaction] = rdb->CreateTransaction(NativeRdb::Transaction::TransactionType::DEFERRED);
    ASSERT_NE(nullptr, transaction);

    std::vector<DelInfo> delInfoVec;
    std::vector<AddInfo> addInfoVec;

    transaction->commitFlag_ = NativeRdb::Transaction::TransactionOperationResult::OPERATION_FAIL;
    // commit return err
    EXPECT_NE(NativeRdb::E_OK, accessTokenDb.DeleteAndInsertValuesInner(delInfoVec, addInfoVec));
}

/*
 * @tc.name: RestoreDatabaseTest001
 * @tc.desc: test RestoreDatabase
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(AccessTokenDatabaseMockTest, RestoreDatabaseTest001, TestSize.Level4)
{
    AccessTokenDb accessTokenDb;
    auto rdb = accessTokenDb.GetRdb();
    ASSERT_NE(nullptr, rdb);
    rdb->restoreFlag_ = NativeRdb::RdbStore::RdbStoreOperationResult::RESULT_FAIL;
    // restore return err
    accessTokenDb.RestoreDatabase(NativeRdb::E_SQLITE_CORRUPT);
}
} // namespace AccessToken
} // namespace Security
} // namespace OHOS
