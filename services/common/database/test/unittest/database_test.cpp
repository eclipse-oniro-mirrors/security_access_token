/*
 * Copyright (c) 2022-2024 Huawei Device Co., Ltd.
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
#include "accesstoken_common_log.h"
#include "access_token.h"
#define private public
#include "access_token_db.h"
#include "access_token_open_callback.h"
#undef private
#include "access_token_error.h"
#include "data_translator.h"
#include "permission_def.h"
#include "generic_values.h"
#include "token_field_const.h"
#include "variant_value.h"

using namespace testing::ext;

namespace OHOS {
namespace Security {
namespace AccessToken {
namespace {
static constexpr int32_t GET_INT64_TRUE_VALUE = -1;
static const int32_t DEFAULT_VALUE = -1;
static const int32_t TEST_TOKEN_ID = 100;
} // namespace
class DatabaseTest : public testing::Test {
public:
    static void SetUpTestCase(void);
    static void TearDownTestCase(void);
    void SetUp();
    void TearDown();
};

void DatabaseTest::SetUpTestCase() {}
void DatabaseTest::TearDownTestCase() {}
void DatabaseTest::SetUp() {}
void DatabaseTest::TearDown() {}

/**
 * @tc.name: PutInt64001
 * @tc.desc: Verify the GenericValues put and get int64 value function.
 * @tc.type: FUNC
 * @tc.require: Issue Number
 */
HWTEST_F(DatabaseTest, PutInt64001, TestSize.Level1)
{
    GenericValues genericValues;
    std::string key = "databasetest";
    int64_t data = 1;
    genericValues.Put(key, data);
    int64_t outdata = genericValues.GetInt64(key);
    EXPECT_EQ(outdata, data);
    genericValues.Remove(key);
    outdata = genericValues.GetInt64(key);
    EXPECT_EQ(GET_INT64_TRUE_VALUE, outdata);
}

/**
 * @tc.name: PutVariant001
 * @tc.desc: Verify the GenericValues put and get variant value function.
 * @tc.type: FUNC
 * @tc.require: Issue Number
 */
HWTEST_F(DatabaseTest, PutVariant001, TestSize.Level1)
{
    GenericValues genericValues;
    std::string key = "databasetest";
    int64_t testValue = 1;
    VariantValue Test(testValue);
    genericValues.Put(key, Test);
    VariantValue outdata = genericValues.Get(key);
    EXPECT_EQ(outdata.GetInt64(), testValue);
    outdata = genericValues.Get("key");
    EXPECT_EQ(DEFAULT_VALUE, outdata.GetInt64());
    genericValues.Remove(key);
    genericValues.Remove("key");
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

/**
 * @tc.name: VariantValue001
 * @tc.desc: VariantValue001 getstring
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(DatabaseTest, VariantValue001, TestSize.Level1)
{
    VariantValue Test;
    Test.GetString();
    EXPECT_EQ(ValueType::TYPE_NULL, Test.GetType());
}

static void RemoveTestTokenHapInfo()
{
    GenericValues condition;
    condition.Put(TokenFiledConst::FIELD_TOKEN_ID, static_cast<int32_t>(TEST_TOKEN_ID));
    std::vector<AtmDataType> deleteDataTypes;
    std::vector<GenericValues> deleteValues;
    deleteDataTypes.emplace_back(AtmDataType::ACCESSTOKEN_HAP_INFO);
    deleteValues.emplace_back(condition);

    std::vector<AtmDataType> addDataTypes;
    std::vector<std::vector<GenericValues>> addValues;
    AccessTokenDb::GetInstance().DeleteAndInsertValues(deleteDataTypes, deleteValues, addDataTypes, addValues);
}

/*
 * @tc.name: SqliteStorageModifyTest001
 * @tc.desc: Modify function test
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(DatabaseTest, SqliteStorageModifyTest001, TestSize.Level1)
{
    LOGI(ATM_DOMAIN, ATM_TAG, "SqliteStorageModifyTest001 begin");

    RemoveTestTokenHapInfo();

    GenericValues genericValues;
    genericValues.Put(TokenFiledConst::FIELD_TOKEN_ID, TEST_TOKEN_ID);
    genericValues.Put(TokenFiledConst::FIELD_USER_ID, 100);
    genericValues.Put(TokenFiledConst::FIELD_BUNDLE_NAME, "test_bundle_name");
    genericValues.Put(TokenFiledConst::FIELD_API_VERSION, 9);
    genericValues.Put(TokenFiledConst::FIELD_INST_INDEX, 0);
    genericValues.Put(TokenFiledConst::FIELD_DLP_TYPE, 0);
    genericValues.Put(TokenFiledConst::FIELD_APP_ID, "test_app_id");
    genericValues.Put(TokenFiledConst::FIELD_DEVICE_ID, "test_device_id");
    genericValues.Put(TokenFiledConst::FIELD_APL, ATokenAplEnum::APL_NORMAL);
    genericValues.Put(TokenFiledConst::FIELD_TOKEN_VERSION, 0);
    genericValues.Put(TokenFiledConst::FIELD_TOKEN_ATTR, 0);
    genericValues.Put(TokenFiledConst::FIELD_FORBID_PERM_DIALOG, "test_perm_dialog_cap_state");

    std::vector<AtmDataType> deleteDataTypes;
    std::vector<GenericValues> deleteValues;

    std::vector<AtmDataType> addDataTypes;
    std::vector<std::vector<GenericValues>> addValues;
    std::vector<GenericValues> value;
    addDataTypes.emplace_back(AtmDataType::ACCESSTOKEN_HAP_INFO);
    value.emplace_back(genericValues);
    addValues.emplace_back(value);
    EXPECT_EQ(0,
        AccessTokenDb::GetInstance().DeleteAndInsertValues(deleteDataTypes, deleteValues, addDataTypes, addValues));

    GenericValues modifyValues;
    modifyValues.Put(TokenFiledConst::FIELD_BUNDLE_NAME, "test_bundle_name_modified");

    GenericValues conditions;
    conditions.Put(TokenFiledConst::FIELD_TOKEN_ID, TEST_TOKEN_ID);
    conditions.Put(TokenFiledConst::FIELD_USER_ID, 100);

    ASSERT_EQ(0, AccessTokenDb::GetInstance().Modify(AtmDataType::ACCESSTOKEN_HAP_INFO, modifyValues, conditions));

    bool modifySuccess = false;
    GenericValues conditionValue;
    std::vector<GenericValues> hapInfoResults;
    AccessTokenDb::GetInstance().Find(AtmDataType::ACCESSTOKEN_HAP_INFO, conditionValue, hapInfoResults);
    for (GenericValues hapInfoValue : hapInfoResults) {
        AccessTokenID tokenId = (AccessTokenID)hapInfoValue.GetInt(TokenFiledConst::FIELD_TOKEN_ID);
        if (tokenId == TEST_TOKEN_ID) {
            ASSERT_EQ("test_bundle_name_modified", hapInfoValue.GetString(TokenFiledConst::FIELD_BUNDLE_NAME));
            modifySuccess = true;
            break;
        }
    }
    EXPECT_TRUE(modifySuccess);
    LOGI(ATM_DOMAIN, ATM_TAG, "SqliteStorageModifyTest001 end");
}

/*
 * @tc.name: DataTranslatorTranslationIntoPermissionDef001
 * @tc.desc: TranslationIntoPermissionDef function test
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(DatabaseTest, DataTranslatorTranslationIntoPermissionDef001, TestSize.Level1)
{
    LOGI(ATM_DOMAIN, ATM_TAG, "DataTranslatorTranslationIntoPermissionDefTest001 begin");

    RemoveTestTokenHapInfo();

    GenericValues genericValues;
    genericValues.Put(TokenFiledConst::FIELD_TOKEN_ID, TEST_TOKEN_ID);
    genericValues.Put(TokenFiledConst::FIELD_AVAILABLE_LEVEL, ATokenAplEnum::APL_INVALID);

    PermissionDef outPermissionDef;
    ASSERT_NE(RET_SUCCESS, DataTranslator::TranslationIntoPermissionDef(genericValues, outPermissionDef));
    LOGI(ATM_DOMAIN, ATM_TAG, "DataTranslatorTranslationIntoPermissionDefTest001 end");
}

/*
 * @tc.name: DataTranslatorTranslationIntoPermissionStatus001
 * @tc.desc: TranslationIntoPermissionStatus function test
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(DatabaseTest, DataTranslatorTranslationIntoPermissionStatus001, TestSize.Level1)
{
    LOGI(ATM_DOMAIN, ATM_TAG, "DataTranslatorTranslationIntoPermissionStatus001 begin");

    PermissionStatus outPermissionState;

    GenericValues inGenericValues;
    inGenericValues.Put(TokenFiledConst::FIELD_GRANT_IS_GENERAL, 1);
    inGenericValues.Put(TokenFiledConst::FIELD_PERMISSION_NAME, "");

    PermissionDef outPermissionDef;
    ASSERT_NE(RET_SUCCESS, DataTranslator::TranslationIntoPermissionStatus(inGenericValues, outPermissionState));
    LOGI(ATM_DOMAIN, ATM_TAG, "DataTranslatorTranslationIntoPermissionStatus001 end");
}

/*
 * @tc.name: DataTranslatorTranslationIntoPermissionStatus002
 * @tc.desc: TranslationIntoPermissionStatus function test
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(DatabaseTest, DataTranslatorTranslationIntoPermissionStatus002, TestSize.Level1)
{
    LOGI(ATM_DOMAIN, ATM_TAG, "DataTranslatorTranslationIntoPermissionStatus002 begin");

    PermissionStatus outPermissionState;

    GenericValues inGenericValues;
    inGenericValues.Put(TokenFiledConst::FIELD_GRANT_IS_GENERAL, 1);
    inGenericValues.Put(TokenFiledConst::FIELD_PERMISSION_NAME, "test_permission_name");
    inGenericValues.Put(TokenFiledConst::FIELD_DEVICE_ID, "");

    PermissionDef outPermissionDef;
    ASSERT_NE(RET_SUCCESS, DataTranslator::TranslationIntoPermissionStatus(inGenericValues, outPermissionState));
    LOGI(ATM_DOMAIN, ATM_TAG, "DataTranslatorTranslationIntoPermissionStatus002 end");
}

/*
 * @tc.name: DataTranslatorTranslationIntoPermissionStatus003
 * @tc.desc: TranslationIntoPermissionStatus function test
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(DatabaseTest, DataTranslatorTranslationIntoPermissionStatus003, TestSize.Level1)
{
    LOGI(ATM_DOMAIN, ATM_TAG, "DataTranslatorTranslationIntoPermissionStatus003 begin");

    PermissionStatus outPermissionState;

    GenericValues inGenericValues;
    inGenericValues.Put(TokenFiledConst::FIELD_GRANT_IS_GENERAL, 1);
    inGenericValues.Put(TokenFiledConst::FIELD_PERMISSION_NAME, "test_permission_name");
    inGenericValues.Put(TokenFiledConst::FIELD_DEVICE_ID, "test_device_id");
    inGenericValues.Put(TokenFiledConst::FIELD_GRANT_STATE, 100);

    PermissionDef outPermissionDef;
    ASSERT_NE(RET_SUCCESS, DataTranslator::TranslationIntoPermissionStatus(inGenericValues, outPermissionState));
    LOGI(ATM_DOMAIN, ATM_TAG, "DataTranslatorTranslationIntoPermissionStatus003 end");
}

/*
 * @tc.name: DataTranslatorTranslationIntoPermissionStatus004
 * @tc.desc: TranslationIntoPermissionStatus function test
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(DatabaseTest, DataTranslatorTranslationIntoPermissionStatus004, TestSize.Level1)
{
    LOGI(ATM_DOMAIN, ATM_TAG, "DataTranslatorTranslationIntoPermissionStatus004 begin");

    PermissionStatus outPermissionState;

    GenericValues inGenericValues;
    inGenericValues.Put(TokenFiledConst::FIELD_GRANT_IS_GENERAL, 1);
    inGenericValues.Put(TokenFiledConst::FIELD_PERMISSION_NAME, "test_permission_name");
    inGenericValues.Put(TokenFiledConst::FIELD_DEVICE_ID, "test_device_id");
    inGenericValues.Put(TokenFiledConst::FIELD_GRANT_STATE, PermissionState::PERMISSION_GRANTED);
    inGenericValues.Put(TokenFiledConst::FIELD_GRANT_FLAG, 100);

    PermissionDef outPermissionDef;
    ASSERT_NE(RET_SUCCESS, DataTranslator::TranslationIntoPermissionStatus(inGenericValues, outPermissionState));
    LOGI(ATM_DOMAIN, ATM_TAG, "DataTranslatorTranslationIntoPermissionStatus004 end");
}
} // namespace AccessToken
} // namespace Security
} // namespace OHOS
