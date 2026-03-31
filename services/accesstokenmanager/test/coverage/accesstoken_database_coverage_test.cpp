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
static constexpr uint32_t NOT_EXSIT_ATM_TYPE = 9;
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
    if (db->transaction_ != nullptr) {
        db->transaction_->commitFlag_ = 0;
        db->transaction_->insertFlag_ = 0;
        db->transaction_->deleteFlag_ = 0;
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

    type = AtmDataType::ACCESSTOKEN_HAP_INFO;
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

    type = AtmDataType::ACCESSTOKEN_HAP_INFO;
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
} // namespace AccessToken
} // namespace Security
} // namespace OHOS
