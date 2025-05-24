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

void AccessTokenDatabaseCoverageTest::SetUp() {}

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
    value.Put(TokenFiledConst::FIELD_PERMISSION_NAME, "ohos.permission.READ_MEDIA");
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
    std::shared_ptr<NativeRdb::RdbStore> db = AccessTokenDb::GetInstance().GetRdb();
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
    std::shared_ptr<NativeRdb::RdbStore> db = AccessTokenDb::GetInstance().GetRdb();
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
        AccessTokenDb::GetInstance().Modify(type, modifyValue, conditionValue));

    type = AtmDataType::ACCESSTOKEN_HAP_INFO;
    ASSERT_EQ(AccessTokenError::ERR_PARAM_INVALID,
        AccessTokenDb::GetInstance().Modify(type, modifyValue, conditionValue));

    modifyValue.Put(TokenFiledConst::FIELD_PROCESS_NAME, "hdcd");
    ASSERT_EQ(NativeRdb::E_SQLITE_ERROR, AccessTokenDb::GetInstance().Modify(type, modifyValue, conditionValue));

    conditionValue.Put(TokenFiledConst::FIELD_PROCESS_NAME, "hdcd");
    ASSERT_NE(NativeRdb::E_OK, AccessTokenDb::GetInstance().Modify(type, modifyValue, conditionValue));

    int32_t resultCode = NativeRdb::E_SQLITE_ERROR;
    int32_t changedRows = 0;
    NativeRdb::ValuesBucket bucket;
    AccessTokenDbUtil::ToRdbValueBucket(modifyValue, bucket);
    NativeRdb::RdbPredicates predicates("hap_token_info_table");
    AccessTokenDbUtil::ToRdbPredicates(conditionValue, predicates);
    std::shared_ptr<NativeRdb::RdbStore> db = AccessTokenDb::GetInstance().GetRdb();
    ASSERT_EQ(NativeRdb::E_SQLITE_ERROR,
        AccessTokenDb::GetInstance().RestoreAndUpdateIfCorrupt(resultCode, changedRows, bucket, predicates, db));

    resultCode = NativeRdb::E_SQLITE_CORRUPT;
    ASSERT_NE(NativeRdb::E_OK,
        AccessTokenDb::GetInstance().RestoreAndUpdateIfCorrupt(resultCode, changedRows, bucket, predicates, db));
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
        AccessTokenDb::GetInstance().Find(type, conditionValue, results));

    type = AtmDataType::ACCESSTOKEN_HAP_INFO;
    ASSERT_EQ(NativeRdb::E_OK, AccessTokenDb::GetInstance().Find(type, conditionValue, results));

    conditionValue.Put(TokenFiledConst::FIELD_PROCESS_NAME, "hdcd");
    ASSERT_EQ(AccessTokenError::ERR_DATABASE_OPERATE_FAILED,
        AccessTokenDb::GetInstance().Find(type, conditionValue, results));
}
} // namespace AccessToken
} // namespace Security
} // namespace OHOS
