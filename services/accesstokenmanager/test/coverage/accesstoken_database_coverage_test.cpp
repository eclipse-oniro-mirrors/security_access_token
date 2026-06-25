/*
 * Copyright (c) 2024 Huawei Device Co., Ltd.
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

#include "access_token_error.h"
#include "access_token.h"
#define private public
#include "access_token_db.h"
#include "access_token_open_callback.h"
#undef private
#include "data_translator.h"
#include "token_field_const.h"

using namespace testing::ext;

namespace OHOS {
namespace Security {
namespace AccessToken {
namespace {
static constexpr uint32_t NOT_EXSIT_ATM_TYPE = 999;
}
class AccessTokenDatabaseCoverageTest : public testing::Test {
public:
    static void SetUpTestCase();

    static void TearDownTestCase();

    void SetUp();

    void TearDown();
};

void AccessTokenDatabaseCoverageTest::SetUpTestCase() {}

void AccessTokenDatabaseCoverageTest::TearDownTestCase() {}

void AccessTokenDatabaseCoverageTest::SetUp()
{
    std::shared_ptr<NativeRdb::RdbStore> db = AccessTokenDb::GetInstance()->GetRdb();
    ASSERT_NE(nullptr, db);
    db->createTransFlag_ = 0;
    db->restoreFlag_ = 0;
    db->updateFlag_ = 0;
    db->queryFlag_ = 0;
    db->executeSqlResults_.clear();
    db->executeSqlIndex_ = 0;
    db->queryColumnNames_.clear();
    db->queryColumnType_ = NativeRdb::ColumnType::TYPE_INTEGER;
    db->queryBlobData_.clear();
    if (db->transaction_ != nullptr) {
        db->transaction_->commitFlag_ = 0;
        db->transaction_->insertFlag_ = 0;
        db->transaction_->deleteFlag_ = 0;
        db->transaction_->updateFlag_ = 0;
        db->transaction_->insertRows_ = 1;
    }
}

void AccessTokenDatabaseCoverageTest::TearDown() {}

/*
 * @tc.name: ToRdbValueBuckets001
 * @tc.desc: AccessTokenDbUtil::ToRdbValueBuckets
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(AccessTokenDatabaseCoverageTest, ToRdbValueBuckets001, TestSize.Level4)
{
    std::vector<GenericValues> values;
    GenericValues value;
    values.emplace_back(value);
    std::vector<NativeRdb::ValuesBucket> buckets;
    AccessTokenDbUtil::ToRdbValueBuckets(values, buckets);
    ASSERT_EQ(true, buckets.empty());
}

/*
 * @tc.name: TranslationIntoPermissionStatus001
 * @tc.desc: DataTranslator::TranslationIntoPermissionStatus
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(AccessTokenDatabaseCoverageTest, TranslationIntoPermissionStatus001, TestSize.Level4)
{
    GenericValues value;
    value.Put(TokenFiledConst::FIELD_GRANT_IS_GENERAL, 1);
    value.Put(TokenFiledConst::FIELD_PERMISSION_NAME, "ohos.permission.ACTIVITY_MOTION");
    value.Put(TokenFiledConst::FIELD_DEVICE_ID, "local");
    value.Put(TokenFiledConst::FIELD_GRANT_FLAG, static_cast<int32_t>(PermissionFlag::PERMISSION_ALLOW_THIS_TIME));
    value.Put(TokenFiledConst::FIELD_GRANT_STATE, static_cast<int32_t>(PermissionState::PERMISSION_GRANTED));
    ASSERT_EQ(static_cast<int32_t>(PermissionState::PERMISSION_GRANTED),
        value.GetInt(TokenFiledConst::FIELD_GRANT_STATE));

    PermissionStatus permissionState;
    DataTranslator::TranslationIntoPermissionStatus(value, permissionState);
    ASSERT_EQ(static_cast<int32_t>(PermissionState::PERMISSION_DENIED), permissionState.grantStatus);
}

/*
 * @tc.name: OnCreate001
 * @tc.desc: AccessTokenOpenCallback::OnCreate
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(AccessTokenDatabaseCoverageTest, OnCreate001, TestSize.Level4)
{
    std::shared_ptr<NativeRdb::RdbStore> db = AccessTokenDb::GetInstance()->GetRdb();
    AccessTokenOpenCallback callback;
    ASSERT_EQ(NativeRdb::E_OK, callback.OnCreate(*(db.get())));
}

/*
 * @tc.name: OnUpgrade001
 * @tc.desc: AccessTokenOpenCallback::OnUpgrade
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(AccessTokenDatabaseCoverageTest, OnUpgrade001, TestSize.Level4)
{
    std::shared_ptr<NativeRdb::RdbStore> db = AccessTokenDb::GetInstance()->GetRdb();
    AccessTokenOpenCallback callback;
    ASSERT_EQ(NativeRdb::E_OK, callback.OnUpgrade(*(db.get()), DATABASE_VERSION_1, DATABASE_VERSION_2));
    ASSERT_EQ(NativeRdb::E_OK, callback.OnUpgrade(*(db.get()), DATABASE_VERSION_1, DATABASE_VERSION_3));
    ASSERT_EQ(NativeRdb::E_OK, callback.OnUpgrade(*(db.get()), DATABASE_VERSION_1, DATABASE_VERSION_4));
    ASSERT_EQ(NativeRdb::E_OK, callback.OnUpgrade(*(db.get()), DATABASE_VERSION_1, DATABASE_VERSION_5));
    ASSERT_EQ(NativeRdb::E_OK, callback.OnUpgrade(*(db.get()), DATABASE_VERSION_1, DATABASE_VERSION_6));

    ASSERT_EQ(NativeRdb::E_OK, callback.OnUpgrade(*(db.get()), DATABASE_VERSION_2, DATABASE_VERSION_3));
    ASSERT_EQ(NativeRdb::E_OK, callback.OnUpgrade(*(db.get()), DATABASE_VERSION_2, DATABASE_VERSION_4));
    ASSERT_EQ(NativeRdb::E_OK, callback.OnUpgrade(*(db.get()), DATABASE_VERSION_2, DATABASE_VERSION_5));
    ASSERT_EQ(NativeRdb::E_OK, callback.OnUpgrade(*(db.get()), DATABASE_VERSION_2, DATABASE_VERSION_6));

    ASSERT_EQ(NativeRdb::E_OK, callback.OnUpgrade(*(db.get()), DATABASE_VERSION_3, DATABASE_VERSION_4));
    ASSERT_EQ(NativeRdb::E_OK, callback.OnUpgrade(*(db.get()), DATABASE_VERSION_3, DATABASE_VERSION_5));
    ASSERT_EQ(NativeRdb::E_OK, callback.OnUpgrade(*(db.get()), DATABASE_VERSION_3, DATABASE_VERSION_6));

    ASSERT_EQ(NativeRdb::E_OK, callback.OnUpgrade(*(db.get()), DATABASE_VERSION_4, DATABASE_VERSION_5));
    ASSERT_EQ(NativeRdb::E_OK, callback.OnUpgrade(*(db.get()), DATABASE_VERSION_4, DATABASE_VERSION_6));

    ASSERT_EQ(NativeRdb::E_OK, callback.OnUpgrade(*(db.get()), DATABASE_VERSION_5, DATABASE_VERSION_6));
}

/*
 * @tc.name: AddTimestampColumn001
 * @tc.desc: AccessTokenOpenCallback::AddTimestampColumn
 * @tc.type: FUNC
 * @tc.require: TDD
 */
HWTEST_F(AccessTokenDatabaseCoverageTest, AddTimestampColumn001, TestSize.Level4)
{
    std::shared_ptr<NativeRdb::RdbStore> db = AccessTokenDb::GetInstance()->GetRdb();
    AccessTokenOpenCallback callback;

    ASSERT_EQ(NativeRdb::E_OK, callback.AddTimestampColumn(*(db.get())));
}

/*
 * @tc.name: AddTimestampColumn002
 * @tc.desc: AccessTokenOpenCallback::AddTimestampColumn upgrade path success
 * @tc.type: FUNC
 * @tc.require: TDD
 */
HWTEST_F(AccessTokenDatabaseCoverageTest, AddTimestampColumn002, TestSize.Level4)
{
    std::shared_ptr<NativeRdb::RdbStore> db = AccessTokenDb::GetInstance()->GetRdb();
    AccessTokenOpenCallback callback;

    db->executeSqlResults_ = {NativeRdb::E_SQLITE_CORRUPT, NativeRdb::E_OK, NativeRdb::E_OK};
    db->executeSqlIndex_ = 0;
    ASSERT_EQ(NativeRdb::E_OK, callback.AddTimestampColumn(*(db.get())));
}

/*
 * @tc.name: AddTimestampColumn003
 * @tc.desc: AccessTokenOpenCallback::AddTimestampColumn alter table failed
 * @tc.type: FUNC
 * @tc.require: TDD
 */
HWTEST_F(AccessTokenDatabaseCoverageTest, AddTimestampColumn003, TestSize.Level4)
{
    std::shared_ptr<NativeRdb::RdbStore> db = AccessTokenDb::GetInstance()->GetRdb();
    AccessTokenOpenCallback callback;

    db->executeSqlResults_ = {NativeRdb::E_SQLITE_CORRUPT, NativeRdb::E_SQLITE_CORRUPT};
    db->executeSqlIndex_ = 0;
    ASSERT_EQ(NativeRdb::E_SQLITE_CORRUPT, callback.AddTimestampColumn(*(db.get())));
}

/*
 * @tc.name: AddTimestampColumn004
 * @tc.desc: AccessTokenOpenCallback::AddTimestampColumn update failed
 * @tc.type: FUNC
 * @tc.require: TDD
 */
HWTEST_F(AccessTokenDatabaseCoverageTest, AddTimestampColumn004, TestSize.Level4)
{
    std::shared_ptr<NativeRdb::RdbStore> db = AccessTokenDb::GetInstance()->GetRdb();
    AccessTokenOpenCallback callback;

    db->executeSqlResults_ = {NativeRdb::E_SQLITE_CORRUPT, NativeRdb::E_OK, NativeRdb::E_SQLITE_CORRUPT};
    db->executeSqlIndex_ = 0;
    ASSERT_EQ(NativeRdb::E_SQLITE_CORRUPT, callback.AddTimestampColumn(*(db.get())));
}

/*
 * @tc.name: OnUpgrade002
 * @tc.desc: AccessTokenOpenCallback::OnUpgrade repeat timestamp upgrade
 * @tc.type: FUNC
 * @tc.require: TDD
 */
HWTEST_F(AccessTokenDatabaseCoverageTest, OnUpgrade002, TestSize.Level4)
{
    std::shared_ptr<NativeRdb::RdbStore> db = AccessTokenDb::GetInstance()->GetRdb();
    AccessTokenOpenCallback callback;

    ASSERT_EQ(NativeRdb::E_OK, callback.OnUpgrade(*(db.get()), DATABASE_VERSION_6, DATABASE_VERSION_7));
    ASSERT_EQ(NativeRdb::E_OK, callback.OnUpgrade(*(db.get()), DATABASE_VERSION_6, DATABASE_VERSION_7));
    ASSERT_EQ(NativeRdb::E_OK, callback.OnUpgrade(*(db.get()), DATABASE_VERSION_7, DATABASE_VERSION_7));
}

/*
 * @tc.name: Modify001
 * @tc.desc: AccessTokenDb::Modify
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(AccessTokenDatabaseCoverageTest, Modify001, TestSize.Level4)
{
    AtmDataType type = static_cast<AtmDataType>(NOT_EXSIT_ATM_TYPE);
    GenericValues modifyValue;
    GenericValues conditionValue;
    ASSERT_EQ(AccessTokenError::ERR_PARAM_INVALID,
        AccessTokenDb::GetInstance()->Modify(type, modifyValue, conditionValue));

    type = AtmDataType::ACCESSTOKEN_HAP_TOKEN_INFO;
    ASSERT_EQ(AccessTokenError::ERR_PARAM_INVALID,
        AccessTokenDb::GetInstance()->Modify(type, modifyValue, conditionValue));

    modifyValue.Put(TokenFiledConst::FIELD_PROCESS_NAME, "hdcd");
    std::shared_ptr<NativeRdb::RdbStore> db = AccessTokenDb::GetInstance()->GetRdb();
    db->updateFlag_ = NativeRdb::RdbStore::RdbStoreOperationResult::RESULT_FAIL;
    ASSERT_EQ(NativeRdb::E_SQLITE_CORRUPT, AccessTokenDb::GetInstance()->Modify(type, modifyValue, conditionValue));
    db->updateFlag_ = 0;

    conditionValue.Put(TokenFiledConst::FIELD_PROCESS_NAME, "hdcd");
    db->updateFlag_ = NativeRdb::RdbStore::RdbStoreOperationResult::RESULT_FAIL;
    ASSERT_NE(NativeRdb::E_OK, AccessTokenDb::GetInstance()->Modify(type, modifyValue, conditionValue));
    db->updateFlag_ = 0;

    int32_t resultCode = NativeRdb::E_SQLITE_CORRUPT;
    int32_t changedRows = 0;
    NativeRdb::ValuesBucket bucket;
    AccessTokenDbUtil::ToRdbValueBucket(modifyValue, bucket);
    NativeRdb::RdbPredicates predicates("hap_token_info_table");
    AccessTokenDbUtil::ToRdbPredicates(conditionValue, predicates);
    db->updateFlag_ = NativeRdb::RdbStore::RdbStoreOperationResult::RESULT_FAIL;
    ASSERT_EQ(NativeRdb::E_SQLITE_CORRUPT,
        AccessTokenDb::GetInstance()->RestoreAndUpdateIfCorrupt(resultCode, changedRows, bucket, predicates, db));
    db->updateFlag_ = 0;

    resultCode = NativeRdb::E_SQLITE_CORRUPT;
    db->restoreFlag_ = NativeRdb::RdbStore::RdbStoreOperationResult::RESULT_FAIL;
    ASSERT_EQ(NativeRdb::E_SQLITE_CORRUPT,
        AccessTokenDb::GetInstance()->RestoreAndUpdateIfCorrupt(resultCode, changedRows, bucket, predicates, db));
    db->restoreFlag_ = 0;
}

/*
 * @tc.name: Modify002
 * @tc.desc: AccessTokenDb::Modify with empty table name
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(AccessTokenDatabaseCoverageTest, Modify002, TestSize.Level4)
{
    AtmDataType type = static_cast<AtmDataType>(NOT_EXSIT_ATM_TYPE);
    GenericValues modifyValue;
    GenericValues conditionValue;
    ASSERT_EQ(AccessTokenError::ERR_PARAM_INVALID,
        AccessTokenDb::GetInstance()->Modify(type, modifyValue, conditionValue));
}

/*
 * @tc.name: Modify003
 * @tc.desc: AccessTokenDb::Modify (vector) with size mismatch
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(AccessTokenDatabaseCoverageTest, Modify003, TestSize.Level4)
{
    AtmDataType type = AtmDataType::ACCESSTOKEN_HAP_TOKEN_INFO;
    std::vector<GenericValues> modifyValues;
    GenericValues modifyValue;
    modifyValue.Put(TokenFiledConst::FIELD_PROCESS_NAME, "hdcd");
    modifyValues.emplace_back(modifyValue);
    std::vector<GenericValues> conditions;
    ASSERT_EQ(AccessTokenError::ERR_PARAM_INVALID,
        AccessTokenDb::GetInstance()->Modify(type, modifyValues, conditions));
}

/*
 * @tc.name: Modify004
 * @tc.desc: AccessTokenDb::Modify (vector) with invalid table type triggers retry without restore
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(AccessTokenDatabaseCoverageTest, Modify004, TestSize.Level4)
{
    AtmDataType type = static_cast<AtmDataType>(NOT_EXSIT_ATM_TYPE);
    std::vector<GenericValues> modifyValues(1);
    std::vector<GenericValues> conditions(1);
    ASSERT_EQ(AccessTokenError::ERR_PARAM_INVALID,
        AccessTokenDb::GetInstance()->Modify(type, modifyValues, conditions));
}

/*
 * @tc.name: Modify005
 * @tc.desc: AccessTokenDb::Modify (vector) with CreateTransaction returning error
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(AccessTokenDatabaseCoverageTest, Modify005, TestSize.Level4)
{
    AtmDataType type = AtmDataType::ACCESSTOKEN_HAP_TOKEN_INFO;
    std::vector<GenericValues> modifyValues(1);
    std::vector<GenericValues> conditions(1);
    std::shared_ptr<NativeRdb::RdbStore> db = AccessTokenDb::GetInstance()->GetRdb();
    db->createTransFlag_ = NativeRdb::RdbStore::RdbStoreOperationResult::RESULT_FAIL;
    ASSERT_EQ(AccessTokenError::ERR_DATABASE_OPERATE_FAILED,
        AccessTokenDb::GetInstance()->Modify(type, modifyValues, conditions));
    db->createTransFlag_ = 0;
}

/*
 * @tc.name: Modify006
 * @tc.desc: AccessTokenDb::Modify (vector) with CreateTransaction returning nullptr transaction
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(AccessTokenDatabaseCoverageTest, Modify006, TestSize.Level4)
{
    AtmDataType type = AtmDataType::ACCESSTOKEN_HAP_TOKEN_INFO;
    std::vector<GenericValues> modifyValues(1);
    std::vector<GenericValues> conditions(1);
    std::shared_ptr<NativeRdb::RdbStore> db = AccessTokenDb::GetInstance()->GetRdb();
    db->createTransFlag_ = NativeRdb::RdbStore::RdbStoreOperationResult::TRANSACTION_NULL;
    ASSERT_EQ(AccessTokenError::ERR_DATABASE_OPERATE_FAILED,
        AccessTokenDb::GetInstance()->Modify(type, modifyValues, conditions));
    db->createTransFlag_ = 0;
}

/*
 * @tc.name: Modify007
 * @tc.desc: AccessTokenDb::Modify (vector) with Update failure triggers RestoreDatabase and retry
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(AccessTokenDatabaseCoverageTest, Modify007, TestSize.Level4)
{
    AtmDataType type = AtmDataType::ACCESSTOKEN_HAP_TOKEN_INFO;
    std::vector<GenericValues> modifyValues(1);
    std::vector<GenericValues> conditions(1);
    std::shared_ptr<NativeRdb::RdbStore> db = AccessTokenDb::GetInstance()->GetRdb();
    ASSERT_NE(nullptr, db->transaction_);
    db->transaction_->updateFlag_ = NativeRdb::Transaction::TransactionOperationResult::OPERATION_FAIL;
    ASSERT_EQ(NativeRdb::E_SQLITE_CORRUPT,
        AccessTokenDb::GetInstance()->Modify(type, modifyValues, conditions));
    db->transaction_->updateFlag_ = 0;
}

/*
 * @tc.name: Modify008
 * @tc.desc: AccessTokenDb::Modify (vector) with Commit failure
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(AccessTokenDatabaseCoverageTest, Modify008, TestSize.Level4)
{
    AtmDataType type = AtmDataType::ACCESSTOKEN_HAP_TOKEN_INFO;
    std::vector<GenericValues> modifyValues(1);
    std::vector<GenericValues> conditions(1);
    std::shared_ptr<NativeRdb::RdbStore> db = AccessTokenDb::GetInstance()->GetRdb();
    ASSERT_NE(nullptr, db->transaction_);
    db->transaction_->commitFlag_ = NativeRdb::Transaction::TransactionOperationResult::OPERATION_FAIL;
    ASSERT_EQ(NativeRdb::E_SQLITE_CORRUPT,
        AccessTokenDb::GetInstance()->Modify(type, modifyValues, conditions));
    db->transaction_->commitFlag_ = 0;
}

/*
 * @tc.name: Modify009
 * @tc.desc: AccessTokenDb::Modify (vector) success path with multiple values
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(AccessTokenDatabaseCoverageTest, Modify009, TestSize.Level4)
{
    AtmDataType type = AtmDataType::ACCESSTOKEN_HAP_TOKEN_INFO;
    std::vector<GenericValues> modifyValues(2);
    modifyValues[0].Put(TokenFiledConst::FIELD_PROCESS_NAME, "hdcd");
    modifyValues[1].Put(TokenFiledConst::FIELD_PROCESS_NAME, "foundation");
    std::vector<GenericValues> conditions(2);
    conditions[0].Put(TokenFiledConst::FIELD_TOKEN_ID, 1);
    conditions[1].Put(TokenFiledConst::FIELD_TOKEN_ID, 2);
    ASSERT_EQ(NativeRdb::E_OK,
        AccessTokenDb::GetInstance()->Modify(type, modifyValues, conditions));
}

/*
 * @tc.name: Find001
 * @tc.desc: AccessTokenDb::Find
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(AccessTokenDatabaseCoverageTest, Find001, TestSize.Level4)
{
    AtmDataType type = static_cast<AtmDataType>(NOT_EXSIT_ATM_TYPE);
    GenericValues conditionValue;
    std::vector<GenericValues> results;
    ASSERT_EQ(AccessTokenError::ERR_PARAM_INVALID,
        AccessTokenDb::GetInstance()->Find(type, conditionValue, results));

    type = AtmDataType::ACCESSTOKEN_HAP_TOKEN_INFO;
    ASSERT_EQ(NativeRdb::E_OK, AccessTokenDb::GetInstance()->Find(type, conditionValue, results));

    conditionValue.Put(TokenFiledConst::FIELD_PROCESS_NAME, "hdcd");
    std::shared_ptr<NativeRdb::RdbStore> db = AccessTokenDb::GetInstance()->GetRdb();
    db->queryFlag_ = NativeRdb::RdbStore::RdbStoreOperationResult::RESULT_FAIL;
    ASSERT_EQ(AccessTokenError::ERR_DATABASE_OPERATE_FAILED,
        AccessTokenDb::GetInstance()->Find(type, conditionValue, results));
    db->queryFlag_ = 0;
}

/*
 * @tc.name: Find002
 * @tc.desc: AccessTokenDb::Find with empty table name
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(AccessTokenDatabaseCoverageTest, Find002, TestSize.Level4)
{
    AtmDataType type = static_cast<AtmDataType>(NOT_EXSIT_ATM_TYPE);
    GenericValues conditionValue;
    std::vector<GenericValues> results;
    ASSERT_EQ(AccessTokenError::ERR_PARAM_INVALID,
        AccessTokenDb::GetInstance()->Find(type, conditionValue, results));
}

/*
 * @tc.name: FindByColumnValues001
 * @tc.desc: AccessTokenDb::Find with single column values and invalid table name
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(AccessTokenDatabaseCoverageTest, FindByColumnValues001, TestSize.Level4)
{
    AtmDataType type = static_cast<AtmDataType>(NOT_EXSIT_ATM_TYPE);
    std::vector<VariantValue> values;
    std::vector<GenericValues> results;
    ASSERT_EQ(AccessTokenError::ERR_PARAM_INVALID,
        AccessTokenDb::GetInstance()->Find(type, TokenFiledConst::FIELD_PERMISSION_NAME, values, results));
}

/*
 * @tc.name: OnUpgrade003
 * @tc.desc: AccessTokenOpenCallback::OnUpgrade version 7->8 creates hap_info_table
 * @tc.type: FUNC
 * @tc.require: TDD
 */
HWTEST_F(AccessTokenDatabaseCoverageTest, OnUpgrade003, TestSize.Level4)
{
    std::shared_ptr<NativeRdb::RdbStore> db = AccessTokenDb::GetInstance()->GetRdb();
    AccessTokenOpenCallback callback;

    ASSERT_EQ(NativeRdb::E_OK, callback.OnUpgrade(*(db.get()), DATABASE_VERSION_7, DATABASE_VERSION_8));
    ASSERT_EQ(NativeRdb::E_OK, callback.OnUpgrade(*(db.get()), DATABASE_VERSION_7, DATABASE_VERSION_8));
    ASSERT_EQ(NativeRdb::E_OK, callback.OnUpgrade(*(db.get()), DATABASE_VERSION_8, DATABASE_VERSION_8));
}

/*
 * @tc.name: AddUidMigratedReservedColumns001
 * @tc.desc: AccessTokenOpenCallback::AddUidMigratedReservedColumns success
 * @tc.type: FUNC
 * @tc.require: TDD
 */
HWTEST_F(AccessTokenDatabaseCoverageTest, AddUidMigratedReservedColumns001, TestSize.Level4)
{
    std::shared_ptr<NativeRdb::RdbStore> db = AccessTokenDb::GetInstance()->GetRdb();
    AccessTokenOpenCallback callback;

    // PRAGMA table_info returns all columns already exist
    db->querySqlResults_ = {{{
        {"0", "token_id", "INTEGER", "1", "", "1"},
        {"1", "uid", "INTEGER", "1", "-1", "0"},
        {"2", "migrated", "INTEGER", "1", "0", "0"},
        {"3", "reserved", "INTEGER", "1", "0", "0"}
    }}};
    db->querySqlIndex_ = 0;
    ASSERT_EQ(NativeRdb::E_OK, callback.AddUidMigratedReservedColumns(*(db.get())));
}

/*
 * @tc.name: AddUidMigratedReservedColumns002
 * @tc.desc: AccessTokenOpenCallback::AddUidMigratedReservedColumns repeat add columns
 * @tc.type: FUNC
 * @tc.require: TDD
 */
HWTEST_F(AccessTokenDatabaseCoverageTest, AddUidMigratedReservedColumns002, TestSize.Level4)
{
    std::shared_ptr<NativeRdb::RdbStore> db = AccessTokenDb::GetInstance()->GetRdb();
    AccessTokenOpenCallback callback;

    // All columns exist, no ALTER needed
    db->querySqlResults_ = {{{
        {"0", "token_id", "INTEGER", "1", "", "1"},
        {"1", "uid", "INTEGER", "1", "-1", "0"},
        {"2", "migrated", "INTEGER", "1", "0", "0"},
        {"3", "reserved", "INTEGER", "1", "0", "0"}
    }}};
    db->querySqlIndex_ = 0;
    ASSERT_EQ(NativeRdb::E_OK, callback.AddUidMigratedReservedColumns(*(db.get())));
}

/*
 * @tc.name: AddUidMigratedReservedColumns003
 * @tc.desc: AccessTokenOpenCallback::AddUidMigratedReservedColumns add uid column failed
 * @tc.type: FUNC
 * @tc.require: TDD
 */
HWTEST_F(AccessTokenDatabaseCoverageTest, AddUidMigratedReservedColumns003, TestSize.Level4)
{
    std::shared_ptr<NativeRdb::RdbStore> db = AccessTokenDb::GetInstance()->GetRdb();
    AccessTokenOpenCallback callback;

    // No columns exist, QuerySql succeeds but ALTER uid fails
    db->querySqlResults_ = {{{{"0", "token_id", "INTEGER", "1", "", "1"}}}};
    db->querySqlIndex_ = 0;
    db->executeSqlResults_ = {NativeRdb::E_SQLITE_CORRUPT};
    db->executeSqlIndex_ = 0;
    ASSERT_EQ(NativeRdb::E_SQLITE_CORRUPT, callback.AddUidMigratedReservedColumns(*(db.get())));
}

/*
 * @tc.name: CreateHapInfoTable001
 * @tc.desc: AccessTokenOpenCallback::CreateHapInfoTable success
 * @tc.type: FUNC
 * @tc.require: TDD
 */
HWTEST_F(AccessTokenDatabaseCoverageTest, CreateHapInfoTable001, TestSize.Level4)
{
    std::shared_ptr<NativeRdb::RdbStore> db = AccessTokenDb::GetInstance()->GetRdb();
    AccessTokenOpenCallback callback;

    ASSERT_EQ(NativeRdb::E_OK, callback.CreateHapInfoTable(*(db.get())));
}

/*
 * @tc.name: UpgradeFromVersion8001
 * @tc.desc: AccessTokenOpenCallback::UpgradeFromVersion8 success
 * @tc.type: FUNC
 * @tc.require: TDD
 */
HWTEST_F(AccessTokenDatabaseCoverageTest, UpgradeFromVersion8001, TestSize.Level4)
{
    std::shared_ptr<NativeRdb::RdbStore> db = AccessTokenDb::GetInstance()->GetRdb();
    AccessTokenOpenCallback callback;

    ASSERT_EQ(NativeRdb::E_OK, callback.UpgradeFromVersion8(*(db.get())));
}

/*
 * @tc.name: UpgradeFromVersion8002
 * @tc.desc: AccessTokenOpenCallback::UpgradeFromVersion8 fails when CreateHapInfoTable fails
 * @tc.type: FUNC
 * @tc.require: TDD
 */
HWTEST_F(AccessTokenDatabaseCoverageTest, UpgradeFromVersion8002, TestSize.Level4)
{
    std::shared_ptr<NativeRdb::RdbStore> db = AccessTokenDb::GetInstance()->GetRdb();
    AccessTokenOpenCallback callback;

    // CreateHapInfoTable calls ExecuteSql once; make it fail
    db->executeSqlResults_ = {NativeRdb::E_SQLITE_CORRUPT};
    db->executeSqlIndex_ = 0;
    ASSERT_EQ(NativeRdb::E_SQLITE_CORRUPT, callback.UpgradeFromVersion8(*(db.get())));
}

/*
 * @tc.name: UpgradeFromVersion8003
 * @tc.desc: AccessTokenOpenCallback::UpgradeFromVersion8 fails when AddUidMigratedReservedColumns fails
 * @tc.type: FUNC
 * @tc.require: TDD
 */
HWTEST_F(AccessTokenDatabaseCoverageTest, UpgradeFromVersion8003, TestSize.Level4)
{
    std::shared_ptr<NativeRdb::RdbStore> db = AccessTokenDb::GetInstance()->GetRdb();
    AccessTokenOpenCallback callback;

    // CreateHapInfoTable succeeds, then uid column check fails and ALTER uid also fails
    db->executeSqlResults_ = {NativeRdb::E_OK, NativeRdb::E_SQLITE_CORRUPT, NativeRdb::E_SQLITE_CORRUPT};
    db->executeSqlIndex_ = 0;
    ASSERT_EQ(NativeRdb::E_SQLITE_CORRUPT, callback.UpgradeFromVersion8(*(db.get())));
}

/*
 * @tc.name: AddUidMigratedReservedColumns004
 * @tc.desc: AccessTokenOpenCallback::AddUidMigratedReservedColumns partial migration recovery:
 *           uid column exists, migrated and reserved columns are missing (previous upgrade was interrupted)
 * @tc.type: FUNC
 * @tc.require: TDD
 */
HWTEST_F(AccessTokenDatabaseCoverageTest, AddUidMigratedReservedColumns004, TestSize.Level4)
{
    std::shared_ptr<NativeRdb::RdbStore> db = AccessTokenDb::GetInstance()->GetRdb();
    AccessTokenOpenCallback callback;

    // Only uid column exists in PRAGMA result; migrated and reserved need to be added
    db->querySqlResults_ = {{{{"0", "token_id", "INTEGER", "1", "", "1"}, {"1", "uid", "INTEGER", "1", "-1", "0"}}}};
    db->querySqlIndex_ = 0;
    // ALTER migrated: E_OK; ALTER reserved: E_OK; UPDATE reserved: E_OK
    db->executeSqlResults_ = {NativeRdb::E_OK, NativeRdb::E_OK, NativeRdb::E_OK};
    db->executeSqlIndex_ = 0;
    ASSERT_EQ(NativeRdb::E_OK, callback.AddUidMigratedReservedColumns(*(db.get())));
}

/*
 * @tc.name: AddUidMigratedReservedColumns005
 * @tc.desc: AccessTokenOpenCallback::AddUidMigratedReservedColumns fails when ALTER migrated column fails
 * @tc.type: FUNC
 * @tc.require: TDD
 */
HWTEST_F(AccessTokenDatabaseCoverageTest, AddUidMigratedReservedColumns005, TestSize.Level4)
{
    std::shared_ptr<NativeRdb::RdbStore> db = AccessTokenDb::GetInstance()->GetRdb();
    AccessTokenOpenCallback callback;

    // Only uid exists; migrated and reserved are missing
    db->querySqlResults_ = {{{{"0", "token_id", "INTEGER", "1", "", "1"}, {"1", "uid", "INTEGER", "1", "-1", "0"}}}};
    db->querySqlIndex_ = 0;
    // ALTER migrated fails
    db->executeSqlResults_ = {NativeRdb::E_SQLITE_CORRUPT};
    db->executeSqlIndex_ = 0;
    ASSERT_EQ(NativeRdb::E_SQLITE_CORRUPT, callback.AddUidMigratedReservedColumns(*(db.get())));
}

/*
 * @tc.name: AddUidMigratedReservedColumns006
 * @tc.desc: AccessTokenOpenCallback::AddUidMigratedReservedColumns fails when ALTER reserved column fails
 * @tc.type: FUNC
 * @tc.require: TDD
 */
HWTEST_F(AccessTokenDatabaseCoverageTest, AddUidMigratedReservedColumns006, TestSize.Level4)
{
    std::shared_ptr<NativeRdb::RdbStore> db = AccessTokenDb::GetInstance()->GetRdb();
    AccessTokenOpenCallback callback;

    // uid and migrated exist; reserved is missing
    db->querySqlResults_ = {{{{"0", "token_id", "INTEGER", "1", "", "1"},
        {"1", "uid", "INTEGER", "1", "-1", "0"}, {"2", "migrated", "INTEGER", "1", "0", "0"}}}};
    db->querySqlIndex_ = 0;
    // ALTER reserved fails
    db->executeSqlResults_ = {NativeRdb::E_SQLITE_CORRUPT};
    db->executeSqlIndex_ = 0;
    ASSERT_EQ(NativeRdb::E_SQLITE_CORRUPT, callback.AddUidMigratedReservedColumns(*(db.get())));
}

/*
 * @tc.name: AddUidMigratedReservedColumns007
 * @tc.desc: AccessTokenOpenCallback::AddUidMigratedReservedColumns fails when UPDATE reserved from token_attr fails
 * @tc.type: FUNC
 * @tc.require: TDD
 */
HWTEST_F(AccessTokenDatabaseCoverageTest, AddUidMigratedReservedColumns007, TestSize.Level4)
{
    std::shared_ptr<NativeRdb::RdbStore> db = AccessTokenDb::GetInstance()->GetRdb();
    AccessTokenOpenCallback callback;

    // uid and migrated exist; reserved is missing
    db->querySqlResults_ = {{{{"0", "token_id", "INTEGER", "1", "", "1"},
        {"1", "uid", "INTEGER", "1", "-1", "0"}, {"2", "migrated", "INTEGER", "1", "0", "0"}}}};
    db->querySqlIndex_ = 0;
    // ALTER reserved: E_OK; UPDATE reserved: CORRUPT (fail)
    db->executeSqlResults_ = {NativeRdb::E_OK, NativeRdb::E_SQLITE_CORRUPT};
    db->executeSqlIndex_ = 0;
    ASSERT_EQ(NativeRdb::E_SQLITE_CORRUPT, callback.AddUidMigratedReservedColumns(*(db.get())));
}

/*
 * @tc.name: AddUidMigratedReservedColumns008
 * @tc.desc: AccessTokenOpenCallback::AddUidMigratedReservedColumns fails when QuerySql returns nullptr
 * @tc.type: FUNC
 * @tc.require: TDD
 */
HWTEST_F(AccessTokenDatabaseCoverageTest, AddUidMigratedReservedColumns008, TestSize.Level4)
{
    std::shared_ptr<NativeRdb::RdbStore> db = AccessTokenDb::GetInstance()->GetRdb();
    AccessTokenOpenCallback callback;

    // QuerySql fails and returns nullptr
    db->queryFlag_ = NativeRdb::RdbStore::RESULT_FAIL;
    ASSERT_EQ(ERR_DATABASE_OPERATE_FAILED, callback.AddUidMigratedReservedColumns(*(db.get())));
    db->queryFlag_ = 0;
}

/*
 * @tc.name: ToRdbValueBuckets002
 * @tc.desc: AccessTokenDbUtil::ToRdbValueBuckets covers the PutBlob branch
 * @tc.type: FUNC
 * @tc.require: TDD
 */
HWTEST_F(AccessTokenDatabaseCoverageTest, ToRdbValueBuckets002, TestSize.Level4)
{
    GenericValues value;
    std::vector<uint8_t> blobData = {0x01, 0x02, 0x03};
    value.PutBlob(TokenFiledConst::FIELD_PERSIST_DATA, blobData);

    std::vector<GenericValues> values = {value};
    std::vector<NativeRdb::ValuesBucket> buckets;
    AccessTokenDbUtil::ToRdbValueBuckets(values, buckets);
    ASSERT_EQ(1U, buckets.size());
}

/*
 * @tc.name: GetBlob001
 * @tc.desc: GenericValues::PutBlob and GetBlob round-trip; key-not-found returns empty vector
 * @tc.type: FUNC
 * @tc.require: TDD
 */
HWTEST_F(AccessTokenDatabaseCoverageTest, GetBlob001, TestSize.Level4)
{
    GenericValues value;
    std::vector<uint8_t> blobData = {0x10, 0x20, 0x30};
    value.PutBlob(TokenFiledConst::FIELD_PERSIST_DATA, blobData);

    ASSERT_EQ(blobData, value.GetBlob(TokenFiledConst::FIELD_PERSIST_DATA));
    ASSERT_TRUE(value.GetBlob("non_existent_key").empty());
}

/*
 * @tc.name: OnUpgrade004
 * @tc.desc: AccessTokenOpenCallback::OnUpgrade version 8->9
 * @tc.type: FUNC
 * @tc.require: TDD
 */
HWTEST_F(AccessTokenDatabaseCoverageTest, OnUpgrade004, TestSize.Level4)
{
    std::shared_ptr<NativeRdb::RdbStore> db = AccessTokenDb::GetInstance()->GetRdb();
    AccessTokenOpenCallback callback;

    ASSERT_EQ(NativeRdb::E_OK, callback.OnUpgrade(*(db.get()), DATABASE_VERSION_8, DATABASE_VERSION_9));
    ASSERT_EQ(NativeRdb::E_OK, callback.OnUpgrade(*(db.get()), DATABASE_VERSION_8, DATABASE_VERSION_9));
    ASSERT_EQ(NativeRdb::E_OK, callback.OnUpgrade(*(db.get()), DATABASE_VERSION_9, DATABASE_VERSION_9));
}

} // namespace AccessToken
} // namespace Security
} // namespace OHOS
