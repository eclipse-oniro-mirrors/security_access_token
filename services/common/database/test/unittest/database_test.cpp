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
#include "accesstoken_log.h"
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
static constexpr OHOS::HiviewDFX::HiLogLabel LABEL = {LOG_CORE, SECURITY_DOMAIN_ACCESSTOKEN, "DatabaseTest"};
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
    GenericValues conditionValue;
    std::vector<GenericValues> hapInfoResults;
    AccessTokenDb::GetInstance().Find(AtmDataType::ACCESSTOKEN_HAP_INFO, conditionValue, hapInfoResults);
    for (GenericValues hapInfoValue : hapInfoResults) {
        AccessTokenID tokenId = (AccessTokenID)hapInfoValue.GetInt(TokenFiledConst::FIELD_TOKEN_ID);
        if (tokenId == TEST_TOKEN_ID) {
            ASSERT_EQ(0, AccessTokenDb::GetInstance().Remove(AtmDataType::ACCESSTOKEN_HAP_INFO, hapInfoValue));
            break;
        }
    }
}

/*
 * @tc.name: SqliteStorageAddTest001
 * @tc.desc: Add function test
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(DatabaseTest, SqliteStorageAddTest001, TestSize.Level1)
{
    ACCESSTOKEN_LOG_INFO(LABEL, "SqliteStorageAddTest001 begin");

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

    std::vector<GenericValues> values;
    values.emplace_back(genericValues);
    EXPECT_EQ(0, AccessTokenDb::GetInstance().Add(AtmDataType::ACCESSTOKEN_HAP_INFO, values));
    ACCESSTOKEN_LOG_INFO(LABEL, "SqliteStorageAddTest001 end");
}

/*
 * @tc.name: SqliteStorageAddTest002
 * @tc.desc: Add function test failed
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(DatabaseTest, SqliteStorageAddTest002, TestSize.Level1)
{
    ACCESSTOKEN_LOG_INFO(LABEL, "SqliteStorageAddTest002 begin");

    RemoveTestTokenHapInfo();

    GenericValues genericValues;
    genericValues.Put(TokenFiledConst::FIELD_TOKEN_ID, TEST_TOKEN_ID);

    std::vector<GenericValues> values;
    values.emplace_back(genericValues);
    EXPECT_EQ(AccessTokenError::ERR_DATABASE_OPERATE_FAILED,
        AccessTokenDb::GetInstance().Add(AtmDataType::ACCESSTOKEN_HAP_INFO, values));
    ACCESSTOKEN_LOG_INFO(LABEL, "SqliteStorageAddTest002 end");
}

/*
 * @tc.name: SqliteStorageModifyTest001
 * @tc.desc: Modify function test
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(DatabaseTest, SqliteStorageModifyTest001, TestSize.Level1)
{
    ACCESSTOKEN_LOG_INFO(LABEL, "SqliteStorageModifyTest001 begin");

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

    std::vector<GenericValues> values;
    values.emplace_back(genericValues);
    EXPECT_EQ(0, AccessTokenDb::GetInstance().Add(AtmDataType::ACCESSTOKEN_HAP_INFO, values));

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
    ACCESSTOKEN_LOG_INFO(LABEL, "SqliteStorageModifyTest001 end");
}

/*
 * @tc.name: DataTranslatorTranslationIntoPermissionDef001
 * @tc.desc: TranslationIntoPermissionDef function test
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(DatabaseTest, DataTranslatorTranslationIntoPermissionDef001, TestSize.Level1)
{
    ACCESSTOKEN_LOG_INFO(LABEL, "DataTranslatorTranslationIntoPermissionDefTest001 begin");

    RemoveTestTokenHapInfo();

    GenericValues genericValues;
    genericValues.Put(TokenFiledConst::FIELD_TOKEN_ID, TEST_TOKEN_ID);
    genericValues.Put(TokenFiledConst::FIELD_AVAILABLE_LEVEL, ATokenAplEnum::APL_INVALID);

    PermissionDef outPermissionDef;
    ASSERT_NE(RET_SUCCESS, DataTranslator::TranslationIntoPermissionDef(genericValues, outPermissionDef));
    ACCESSTOKEN_LOG_INFO(LABEL, "DataTranslatorTranslationIntoPermissionDefTest001 end");
}

/*
 * @tc.name: DataTranslatorTranslationIntoGenericValues001
 * @tc.desc: DataTranslatorTranslationIntoGenericValues function test
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(DatabaseTest, DataTranslatorTranslationIntoGenericValues001, TestSize.Level1)
{
    ACCESSTOKEN_LOG_INFO(LABEL, "DataTranslatorTranslationIntoGenericValues001 begin");
    PermissionStateFull grantPermissionReq = {
        .permissionName = "ohos.permission.GRANT_SENSITIVE_PERMISSIONS",
        .isGeneral = true,
        .resDeviceID = {"device1"},
        .grantStatus = {PermissionState::PERMISSION_GRANTED},
        .grantFlags = {PermissionFlag::PERMISSION_SYSTEM_FIXED}
    };
    int grantIndex = 1;
    GenericValues genericValues;
    ASSERT_NE(RET_SUCCESS,
        DataTranslator::TranslationIntoGenericValues(grantPermissionReq, grantIndex, genericValues));
    ACCESSTOKEN_LOG_INFO(LABEL, "DataTranslatorTranslationIntoGenericValues001 end");
}

/*
 * @tc.name: DataTranslatorTranslationIntoGenericValues002
 * @tc.desc: DataTranslatorTranslationIntoGenericValues function test
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(DatabaseTest, DataTranslatorTranslationIntoGenericValues002, TestSize.Level1)
{
    ACCESSTOKEN_LOG_INFO(LABEL, "DataTranslatorTranslationIntoGenericValues002 begin");
    PermissionStateFull grantPermissionReq = {
        .permissionName = "ohos.permission.GRANT_SENSITIVE_PERMISSIONS",
        .isGeneral = true,
        .resDeviceID = {"device1", "device2"},
        .grantStatus = {PermissionState::PERMISSION_GRANTED},
        .grantFlags = {PermissionFlag::PERMISSION_SYSTEM_FIXED}
    };
    int grantIndex = 1;
    GenericValues genericValues;
    ASSERT_NE(RET_SUCCESS,
        DataTranslator::TranslationIntoGenericValues(grantPermissionReq, grantIndex, genericValues));
    ACCESSTOKEN_LOG_INFO(LABEL, "DataTranslatorTranslationIntoGenericValues002 end");
}

/*
 * @tc.name: DataTranslatorTranslationIntoGenericValues003
 * @tc.desc: DataTranslatorTranslationIntoGenericValues function test
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(DatabaseTest, DataTranslatorTranslationIntoGenericValues003, TestSize.Level1)
{
    ACCESSTOKEN_LOG_INFO(LABEL, "DataTranslatorTranslationIntoGenericValues003 begin");
    PermissionStateFull grantPermissionReq = {
        .permissionName = "ohos.permission.GRANT_SENSITIVE_PERMISSIONS",
        .isGeneral = true,
        .resDeviceID = {"device1", "device2"},
        .grantStatus = {PermissionState::PERMISSION_GRANTED, PermissionState::PERMISSION_GRANTED},
        .grantFlags = {PermissionFlag::PERMISSION_SYSTEM_FIXED}
    };
    int grantIndex = 1;
    GenericValues genericValues;
    ASSERT_NE(RET_SUCCESS,
        DataTranslator::TranslationIntoGenericValues(grantPermissionReq, grantIndex, genericValues));
    ACCESSTOKEN_LOG_INFO(LABEL, "DataTranslatorTranslationIntoGenericValues003 end");
}

/*
 * @tc.name: DataTranslatorTranslationIntoPermissionStateFull001
 * @tc.desc: TranslationIntoPermissionStateFull function test
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(DatabaseTest, DataTranslatorTranslationIntoPermissionStateFull001, TestSize.Level1)
{
    ACCESSTOKEN_LOG_INFO(LABEL, "DataTranslatorTranslationIntoPermissionStateFullTest001 begin");

    PermissionStateFull outPermissionState;

    GenericValues inGenericValues;
    inGenericValues.Put(TokenFiledConst::FIELD_GRANT_IS_GENERAL, 1);
    inGenericValues.Put(TokenFiledConst::FIELD_PERMISSION_NAME, "");

    PermissionDef outPermissionDef;
    ASSERT_NE(RET_SUCCESS, DataTranslator::TranslationIntoPermissionStateFull(inGenericValues, outPermissionState));
    ACCESSTOKEN_LOG_INFO(LABEL, "DataTranslatorTranslationIntoPermissionStateFullTest001 end");
}

/*
 * @tc.name: DataTranslatorTranslationIntoPermissionStateFull002
 * @tc.desc: TranslationIntoPermissionStateFull function test
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(DatabaseTest, DataTranslatorTranslationIntoPermissionStateFull002, TestSize.Level1)
{
    ACCESSTOKEN_LOG_INFO(LABEL, "DataTranslatorTranslationIntoPermissionStateFullTest002 begin");

    PermissionStateFull outPermissionState;

    GenericValues inGenericValues;
    inGenericValues.Put(TokenFiledConst::FIELD_GRANT_IS_GENERAL, 1);
    inGenericValues.Put(TokenFiledConst::FIELD_PERMISSION_NAME, "test_permission_name");
    inGenericValues.Put(TokenFiledConst::FIELD_DEVICE_ID, "");

    PermissionDef outPermissionDef;
    ASSERT_NE(RET_SUCCESS, DataTranslator::TranslationIntoPermissionStateFull(inGenericValues, outPermissionState));
    ACCESSTOKEN_LOG_INFO(LABEL, "DataTranslatorTranslationIntoPermissionStateFullTest002 end");
}

/*
 * @tc.name: DataTranslatorTranslationIntoPermissionStateFull003
 * @tc.desc: TranslationIntoPermissionStateFull function test
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(DatabaseTest, DataTranslatorTranslationIntoPermissionStateFull003, TestSize.Level1)
{
    ACCESSTOKEN_LOG_INFO(LABEL, "DataTranslatorTranslationIntoPermissionStateFullTest003 begin");

    PermissionStateFull outPermissionState;

    GenericValues inGenericValues;
    inGenericValues.Put(TokenFiledConst::FIELD_GRANT_IS_GENERAL, 1);
    inGenericValues.Put(TokenFiledConst::FIELD_PERMISSION_NAME, "test_permission_name");
    inGenericValues.Put(TokenFiledConst::FIELD_DEVICE_ID, "test_device_id");
    inGenericValues.Put(TokenFiledConst::FIELD_GRANT_STATE, 100);

    PermissionDef outPermissionDef;
    ASSERT_NE(RET_SUCCESS, DataTranslator::TranslationIntoPermissionStateFull(inGenericValues, outPermissionState));
    ACCESSTOKEN_LOG_INFO(LABEL, "DataTranslatorTranslationIntoPermissionStateFullTest003 end");
}

/*
 * @tc.name: DataTranslatorTranslationIntoPermissionStateFull004
 * @tc.desc: TranslationIntoPermissionStateFull function test
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(DatabaseTest, DataTranslatorTranslationIntoPermissionStateFull004, TestSize.Level1)
{
    ACCESSTOKEN_LOG_INFO(LABEL, "DataTranslatorTranslationIntoPermissionStateFullTest004 begin");

    PermissionStateFull outPermissionState;

    GenericValues inGenericValues;
    inGenericValues.Put(TokenFiledConst::FIELD_GRANT_IS_GENERAL, 1);
    inGenericValues.Put(TokenFiledConst::FIELD_PERMISSION_NAME, "test_permission_name");
    inGenericValues.Put(TokenFiledConst::FIELD_DEVICE_ID, "test_device_id");
    inGenericValues.Put(TokenFiledConst::FIELD_GRANT_STATE, PermissionState::PERMISSION_GRANTED);
    inGenericValues.Put(TokenFiledConst::FIELD_GRANT_FLAG, 100);

    PermissionDef outPermissionDef;
    ASSERT_NE(RET_SUCCESS, DataTranslator::TranslationIntoPermissionStateFull(inGenericValues, outPermissionState));
    ACCESSTOKEN_LOG_INFO(LABEL, "DataTranslatorTranslationIntoPermissionStateFullTest004 end");
}
} // namespace AccessToken
} // namespace Security
} // namespace OHOS
