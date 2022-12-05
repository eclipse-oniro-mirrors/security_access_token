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
#include "constant.h"
#include "data_translator.h"
#include "active_change_response_info.h"
#include "privacy_field_const.h"
#define private public
#include "permission_used_record_db.h"
#undef private

using namespace testing::ext;

namespace OHOS {
namespace Security {
namespace AccessToken {
class PermissionRecordDBTest : public testing::Test {
public:
    static void SetUpTestCase();
    static void TearDownTestCase();
    void SetUp();
    void TearDown();
};

void PermissionRecordDBTest::SetUpTestCase()
{
}

void PermissionRecordDBTest::TearDownTestCase()
{
}

void PermissionRecordDBTest::SetUp()
{
}

void PermissionRecordDBTest::TearDown()
{
}

/*
 * @tc.name: CreateInsertPrepareSqlCmd001
 * @tc.desc: PermissionUsedRecordDb::CreateInsertPrepareSqlCmd function test type not found
 * @tc.type: FUNC
 * @tc.require: issueI5YL6H
 */
HWTEST_F(PermissionRecordDBTest, CreateInsertPrepareSqlCmd001, TestSize.Level1)
{
    PermissionUsedRecordDb::DataType type = static_cast<PermissionUsedRecordDb::DataType>(100);
    ASSERT_EQ("", PermissionUsedRecordDb::GetInstance().CreateInsertPrepareSqlCmd(type));
}

/*
 * @tc.name: CreateInsertPrepareSqlCmd002
 * @tc.desc: PermissionUsedRecordDb::CreateInsertPrepareSqlCmd function test
 * @tc.type: FUNC
 * @tc.require: issueI5YL6H
 */
HWTEST_F(PermissionRecordDBTest, CreateInsertPrepareSqlCmd002, TestSize.Level1)
{
    PermissionUsedRecordDb::DataType type = PermissionUsedRecordDb::PERMISSION_RECORD;
    ASSERT_NE("", PermissionUsedRecordDb::GetInstance().CreateInsertPrepareSqlCmd(type));
}

/*
 * @tc.name: CreateDeletePrepareSqlCmd001
 * @tc.desc: PermissionUsedRecordDb::CreateDeletePrepareSqlCmd function test type not found
 * @tc.type: FUNC
 * @tc.require: issueI5YL6H
 */
HWTEST_F(PermissionRecordDBTest, CreateDeletePrepareSqlCmd001, TestSize.Level1)
{
    PermissionUsedRecordDb::DataType type = static_cast<PermissionUsedRecordDb::DataType>(100);
    std::vector<std::string> columnNames;
    ASSERT_EQ("", PermissionUsedRecordDb::GetInstance().CreateDeletePrepareSqlCmd(type, columnNames));
}

/*
 * @tc.name: CreateUpdatePrepareSqlCmd001
 * @tc.desc: PermissionUsedRecordDb::CreateUpdatePrepareSqlCmd function test modifyColumns empty
 * @tc.type: FUNC
 * @tc.require: issueI5YL6H
 */
HWTEST_F(PermissionRecordDBTest, CreateUpdatePrepareSqlCmd001, TestSize.Level1)
{
    PermissionUsedRecordDb::DataType type = PermissionUsedRecordDb::PERMISSION_RECORD;
    std::vector<std::string> modifyColumns;
    std::vector<std::string> conditionColumns;
    ASSERT_EQ("", PermissionUsedRecordDb::GetInstance().CreateUpdatePrepareSqlCmd(type, modifyColumns,
        conditionColumns));
}

/*
 * @tc.name: CreateUpdatePrepareSqlCmd002
 * @tc.desc: PermissionUsedRecordDb::CreateUpdatePrepareSqlCmd function test type not found
 * @tc.type: FUNC
 * @tc.require: issueI5YL6H
 */
HWTEST_F(PermissionRecordDBTest, CreateUpdatePrepareSqlCmd002, TestSize.Level1)
{
    PermissionUsedRecordDb::DataType type = static_cast<PermissionUsedRecordDb::DataType>(100);
    std::vector<std::string> modifyColumns;
    modifyColumns.emplace_back(PrivacyFiledConst::FIELD_TOKEN_ID);
    std::vector<std::string> conditionColumns;
    ASSERT_EQ("", PermissionUsedRecordDb::GetInstance().CreateUpdatePrepareSqlCmd(type, modifyColumns,
        conditionColumns));
}

/*
 * @tc.name: CreateUpdatePrepareSqlCmd003
 * @tc.desc: PermissionUsedRecordDb::CreateUpdatePrepareSqlCmd function test conditionColumns empty
 * @tc.type: FUNC
 * @tc.require: issueI5YL6H
 */
HWTEST_F(PermissionRecordDBTest, CreateUpdatePrepareSqlCmd003, TestSize.Level1)
{
    PermissionUsedRecordDb::DataType type = PermissionUsedRecordDb::PERMISSION_RECORD;
    std::vector<std::string> modifyColumns;
    modifyColumns.emplace_back(PrivacyFiledConst::FIELD_TOKEN_ID);
    modifyColumns.emplace_back(PrivacyFiledConst::FIELD_TIMESTAMP);
    std::vector<std::string> conditionColumns;
    ASSERT_NE("", PermissionUsedRecordDb::GetInstance().CreateUpdatePrepareSqlCmd(type, modifyColumns,
        conditionColumns));
}

/*
 * @tc.name: CreateUpdatePrepareSqlCmd004
 * @tc.desc: PermissionUsedRecordDb::CreateUpdatePrepareSqlCmd function test conditionColumns empty
 * @tc.type: FUNC
 * @tc.require: issueI5YL6H
 */
HWTEST_F(PermissionRecordDBTest, CreateUpdatePrepareSqlCmd004, TestSize.Level1)
{
    PermissionUsedRecordDb::DataType type = PermissionUsedRecordDb::PERMISSION_RECORD;
    std::vector<std::string> modifyColumns;
    modifyColumns.emplace_back(PrivacyFiledConst::FIELD_TOKEN_ID);
    modifyColumns.emplace_back(PrivacyFiledConst::FIELD_TIMESTAMP);
    std::vector<std::string> conditionColumns;
    ASSERT_NE("", PermissionUsedRecordDb::GetInstance().CreateUpdatePrepareSqlCmd(type, modifyColumns,
        conditionColumns));
}

/*
 * @tc.name: CreateUpdatePrepareSqlCmd005
 * @tc.desc: PermissionUsedRecordDb::CreateUpdatePrepareSqlCmd function test
 * @tc.type: FUNC
 * @tc.require: issueI5YL6H
 */
HWTEST_F(PermissionRecordDBTest, CreateUpdatePrepareSqlCmd005, TestSize.Level1)
{
    PermissionUsedRecordDb::DataType type = PermissionUsedRecordDb::PERMISSION_RECORD;
    std::vector<std::string> modifyColumns;
    modifyColumns.emplace_back(PrivacyFiledConst::FIELD_TOKEN_ID);
    modifyColumns.emplace_back(PrivacyFiledConst::FIELD_TIMESTAMP);
    std::vector<std::string> conditionColumns;
    modifyColumns.emplace_back(PrivacyFiledConst::FIELD_STATUS);
    ASSERT_NE("", PermissionUsedRecordDb::GetInstance().CreateUpdatePrepareSqlCmd(type, modifyColumns,
        conditionColumns));
}

/*
 * @tc.name: CreateSelectByConditionPrepareSqlCmd001
 * @tc.desc: PermissionUsedRecordDb::CreateSelectByConditionPrepareSqlCmd function test type not found
 * @tc.type: FUNC
 * @tc.require: issueI5YL6H
 */
HWTEST_F(PermissionRecordDBTest, CreateSelectByConditionPrepareSqlCmd001, TestSize.Level1)
{
    PermissionUsedRecordDb::DataType type = static_cast<PermissionUsedRecordDb::DataType>(100);
    std::vector<std::string> andColumns;
    std::vector<std::string> orColumns;
    ASSERT_EQ("", PermissionUsedRecordDb::GetInstance().CreateSelectByConditionPrepareSqlCmd(type, andColumns,
        orColumns));
}

/*
 * @tc.name: CreateSelectByConditionPrepareSqlCmd002
 * @tc.desc: PermissionUsedRecordDb::CreateSelectByConditionPrepareSqlCmd function test
 * @tc.type: FUNC
 * @tc.require: issueI5YL6H
 */
HWTEST_F(PermissionRecordDBTest, CreateSelectByConditionPrepareSqlCmd002, TestSize.Level1)
{
    PermissionUsedRecordDb::DataType type = PermissionUsedRecordDb::PERMISSION_RECORD;
    std::vector<std::string> andColumns;
    andColumns.emplace_back(PrivacyFiledConst::FIELD_TIMESTAMP_BEGIN);
    std::vector<std::string> orColumns;
    orColumns.emplace_back(PrivacyFiledConst::FIELD_TIMESTAMP);
    ASSERT_NE("", PermissionUsedRecordDb::GetInstance().CreateSelectByConditionPrepareSqlCmd(type, andColumns,
        orColumns));
}

/*
 * @tc.name: CreateCountPrepareSqlCmd001
 * @tc.desc: PermissionUsedRecordDb::CreateCountPrepareSqlCmd function test type not found
 * @tc.type: FUNC
 * @tc.require: issueI5YL6H
 */
HWTEST_F(PermissionRecordDBTest, CreateCountPrepareSqlCmd001, TestSize.Level1)
{
    PermissionUsedRecordDb::DataType type = static_cast<PermissionUsedRecordDb::DataType>(100);
    ASSERT_EQ("", PermissionUsedRecordDb::GetInstance().CreateCountPrepareSqlCmd(type));
}

/*
 * @tc.name: CreateDeleteExpireRecordsPrepareSqlCmd001
 * @tc.desc: PermissionUsedRecordDb::CreateDeleteExpireRecordsPrepareSqlCmd function test
 * @tc.type: FUNC
 * @tc.require: issueI5YL6H
 */
HWTEST_F(PermissionRecordDBTest, CreateDeleteExpireRecordsPrepareSqlCmd001, TestSize.Level1)
{
    PermissionUsedRecordDb::DataType type = static_cast<PermissionUsedRecordDb::DataType>(100); // type not found
    std::vector<std::string> andColumns;
    ASSERT_EQ("", PermissionUsedRecordDb::GetInstance().CreateDeleteExpireRecordsPrepareSqlCmd(type, andColumns));

    type = PermissionUsedRecordDb::PERMISSION_RECORD; // field timestamp_begin and timestamp_end
    andColumns.emplace_back(PrivacyFiledConst::FIELD_TIMESTAMP_BEGIN);
    andColumns.emplace_back(PrivacyFiledConst::FIELD_TIMESTAMP_END);
    ASSERT_NE("", PermissionUsedRecordDb::GetInstance().CreateDeleteExpireRecordsPrepareSqlCmd(type, andColumns));
}

/*
 * @tc.name: CreateDeleteExcessiveRecordsPrepareSqlCmd001
 * @tc.desc: PermissionUsedRecordDb::CreateDeleteExcessiveRecordsPrepareSqlCmd function test type not found
 * @tc.type: FUNC
 * @tc.require: issueI5YL6H
 */
HWTEST_F(PermissionRecordDBTest, CreateDeleteExcessiveRecordsPrepareSqlCmd001, TestSize.Level1)
{
    PermissionUsedRecordDb::DataType type = static_cast<PermissionUsedRecordDb::DataType>(100);
    uint32_t excessiveSize = 10;
    ASSERT_EQ("", PermissionUsedRecordDb::GetInstance().CreateDeleteExcessiveRecordsPrepareSqlCmd(type, excessiveSize));
}

/*
 * @tc.name: CreateDeleteExcessiveRecordsPrepareSqlCmd002
 * @tc.desc: PermissionUsedRecordDb::CreateDeleteExcessiveRecordsPrepareSqlCmd function test
 * @tc.type: FUNC
 * @tc.require: issueI5YL6H
 */
HWTEST_F(PermissionRecordDBTest, CreateDeleteExcessiveRecordsPrepareSqlCmd002, TestSize.Level1)
{
    PermissionUsedRecordDb::DataType type = PermissionUsedRecordDb::PERMISSION_RECORD;
    uint32_t excessiveSize = 10;
    ASSERT_NE("", PermissionUsedRecordDb::GetInstance().CreateDeleteExcessiveRecordsPrepareSqlCmd(type, excessiveSize));
}

/*
 * @tc.name: CreateGetDistinctValue001
 * @tc.desc: PermissionUsedRecordDb::CreateGetDistinctValue function test type not found
 * @tc.type: FUNC
 * @tc.require: issueI5YL6H
 */
HWTEST_F(PermissionRecordDBTest, CreateGetDistinctValue001, TestSize.Level1)
{
    PermissionUsedRecordDb::DataType type = static_cast<PermissionUsedRecordDb::DataType>(100);
    std::string conditionColumns;
    ASSERT_EQ("", PermissionUsedRecordDb::GetInstance().CreateGetDistinctValue(type, conditionColumns));
}

/*
 * @tc.name: CreatePermissionRecordTable001
 * @tc.desc: PermissionUsedRecordDb::CreatePermissionRecordTable function test
 * @tc.type: FUNC
 * @tc.require: issueI5YL6H
 */
HWTEST_F(PermissionRecordDBTest, CreatePermissionRecordTable001, TestSize.Level1)
{
    ASSERT_EQ(0, PermissionUsedRecordDb::GetInstance().CreatePermissionRecordTable());

    std::map<PermissionUsedRecordDb::DataType, SqliteTable> dataTypeToSqlTable;
    dataTypeToSqlTable = PermissionUsedRecordDb::GetInstance().dataTypeToSqlTable_; // backup
    PermissionUsedRecordDb::GetInstance().dataTypeToSqlTable_.clear();

    ASSERT_EQ(Constant::FAILURE, PermissionUsedRecordDb::GetInstance().CreatePermissionRecordTable());
    PermissionUsedRecordDb::GetInstance().dataTypeToSqlTable_ = dataTypeToSqlTable; // recovery
}

/*
 * @tc.name: TranslationIntoGenericValues001
 * @tc.desc: DataTranslator::TranslationIntoGenericValues function test
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(PermissionRecordDBTest, TranslationIntoGenericValues001, TestSize.Level1)
{
    PermissionUsedRequest request;
    GenericValues andGenericValues;
    GenericValues orGenericValues;

    request.beginTimeMillis = -1;
    // begin < 0
    ASSERT_EQ(Constant::FAILURE,
        DataTranslator::TranslationIntoGenericValues(request, andGenericValues, orGenericValues));
    
    request.beginTimeMillis = 10;
    request.endTimeMillis = -1;
    // begin > 0 + end < 0
    ASSERT_EQ(Constant::FAILURE,
        DataTranslator::TranslationIntoGenericValues(request, andGenericValues, orGenericValues));

    request.endTimeMillis = 1;
    // begin > 0 + end > 0 + begin > end
    ASSERT_EQ(Constant::FAILURE,
        DataTranslator::TranslationIntoGenericValues(request, andGenericValues, orGenericValues));

    request.beginTimeMillis = 10; // begin != 0
    request.endTimeMillis = 20; // end != 0
    request.flag = static_cast<PermissionUsageFlag>(2);
    // begin > 0 + end > 0 + begin < end + flag = 2
    ASSERT_EQ(Constant::FAILURE,
        DataTranslator::TranslationIntoGenericValues(request, andGenericValues, orGenericValues));

    request.flag = PermissionUsageFlag::FLAG_PERMISSION_USAGE_DETAIL;
    request.permissionList.emplace_back("ohos.com.CAMERA");
    // begin > 0 + end > 0 + begin < end + flag = 1 + TransferPermissionToOpcode true
    ASSERT_EQ(Constant::SUCCESS,
        DataTranslator::TranslationIntoGenericValues(request, andGenericValues, orGenericValues));
}

/*
 * @tc.name: TranslationGenericValuesIntoPermissionUsedRecord001
 * @tc.desc: DataTranslator::TranslationGenericValuesIntoPermissionUsedRecord function test
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(PermissionRecordDBTest, TranslationGenericValuesIntoPermissionUsedRecord001, TestSize.Level1)
{
    GenericValues inGenericValues;
    PermissionUsedRecord permissionRecord;

    int32_t opCode = static_cast<int32_t>(Constant::OpCode::OP_INVALID);
    inGenericValues.Put(PrivacyFiledConst::FIELD_OP_CODE, opCode);
    // TransferOpcodeToPermission fail
    ASSERT_EQ(Constant::FAILURE,
        DataTranslator::TranslationGenericValuesIntoPermissionUsedRecord(inGenericValues, permissionRecord));
    inGenericValues.Remove(PrivacyFiledConst::FIELD_OP_CODE);

    opCode = static_cast<int32_t>(Constant::OpCode::OP_CAMERA);
    inGenericValues.Put(PrivacyFiledConst::FIELD_OP_CODE, opCode);
    inGenericValues.Put(PrivacyFiledConst::FIELD_TIMESTAMP, 10);
    inGenericValues.Put(PrivacyFiledConst::FIELD_REJECT_COUNT, 1);
    inGenericValues.Put(PrivacyFiledConst::FIELD_FLAG, 1);
    // lastRejectTime > 0
    ASSERT_EQ(Constant::SUCCESS,
        DataTranslator::TranslationGenericValuesIntoPermissionUsedRecord(inGenericValues, permissionRecord));
}

/*
 * @tc.name: Add001
 * @tc.desc: PermissionUsedRecordDb::Add function test miss not null field
 * @tc.type: FUNC
 * @tc.require: issueI5YL6H
 */
HWTEST_F(PermissionRecordDBTest, Add001, TestSize.Level1)
{
    GenericValues value1;
    value1.Put(PrivacyFiledConst::FIELD_TOKEN_ID, 0);
    value1.Put(PrivacyFiledConst::FIELD_OP_CODE, Constant::OP_MICROPHONE);
    value1.Put(PrivacyFiledConst::FIELD_STATUS, ActiveChangeType::PERM_ACTIVE_IN_FOREGROUND);
    value1.Put(PrivacyFiledConst::FIELD_TIMESTAMP, 123); // 123 is random input
    value1.Put(PrivacyFiledConst::FIELD_REJECT_COUNT, 0);

    GenericValues value2;
    value2.Put(PrivacyFiledConst::FIELD_TOKEN_ID, 0);
    value2.Put(PrivacyFiledConst::FIELD_OP_CODE, Constant::OP_MICROPHONE);
    value2.Put(PrivacyFiledConst::FIELD_STATUS, ActiveChangeType::PERM_ACTIVE_IN_FOREGROUND);
    value1.Put(PrivacyFiledConst::FIELD_TIMESTAMP, 123); // 123 is random input
    value1.Put(PrivacyFiledConst::FIELD_ACCESS_COUNT, 1);

    PermissionUsedRecordDb::DataType type = PermissionUsedRecordDb::PERMISSION_RECORD;
    std::vector<GenericValues> values;
    values.emplace_back(value1);
    values.emplace_back(value2);
    ASSERT_NE(0, PermissionUsedRecordDb::GetInstance().Add(type, values));
}

/*
 * @tc.name: Add002
 * @tc.desc: PermissionUsedRecordDb::Add function test
 * @tc.type: FUNC
 * @tc.require: issueI5YL6H
 */
HWTEST_F(PermissionRecordDBTest, Add002, TestSize.Level1)
{
    GenericValues value1;
    value1.Put(PrivacyFiledConst::FIELD_TOKEN_ID, 0);
    value1.Put(PrivacyFiledConst::FIELD_OP_CODE, Constant::OP_MICROPHONE);
    value1.Put(PrivacyFiledConst::FIELD_STATUS, ActiveChangeType::PERM_ACTIVE_IN_FOREGROUND);
    value1.Put(PrivacyFiledConst::FIELD_TIMESTAMP, 123); // 123 is random input
    value1.Put(PrivacyFiledConst::FIELD_ACCESS_DURATION, 123); // 123 is random input
    value1.Put(PrivacyFiledConst::FIELD_ACCESS_COUNT, 1);
    value1.Put(PrivacyFiledConst::FIELD_REJECT_COUNT, 0);

    GenericValues value2;
    value2.Put(PrivacyFiledConst::FIELD_TOKEN_ID, 1);
    value2.Put(PrivacyFiledConst::FIELD_OP_CODE, Constant::OP_MICROPHONE);
    value2.Put(PrivacyFiledConst::FIELD_STATUS, ActiveChangeType::PERM_ACTIVE_IN_FOREGROUND);
    value1.Put(PrivacyFiledConst::FIELD_TIMESTAMP, 123); // 123 is random input
    value1.Put(PrivacyFiledConst::FIELD_ACCESS_DURATION, 123); // 123 is random input
    value1.Put(PrivacyFiledConst::FIELD_ACCESS_COUNT, 1);
    value1.Put(PrivacyFiledConst::FIELD_REJECT_COUNT, 0);

    PermissionUsedRecordDb::DataType type = PermissionUsedRecordDb::PERMISSION_RECORD;
    std::vector<GenericValues> values;
    values.emplace_back(value1);
    values.emplace_back(value2);
    ASSERT_EQ(0, PermissionUsedRecordDb::GetInstance().Add(type, values));
    ASSERT_EQ(0, PermissionUsedRecordDb::GetInstance().Remove(type, value1));
    ASSERT_EQ(0, PermissionUsedRecordDb::GetInstance().Remove(type, value2));
}

/*
 * @tc.name: Add003
 * @tc.desc: PermissionUsedRecordDb::Add function test
 * @tc.type: FUNC
 * @tc.require: issueI5RWXF
 */
HWTEST_F(PermissionRecordDBTest, Add003, TestSize.Level1)
{
    std::vector<GenericValues> values;
    PermissionUsedRecordDb::DataType type = PermissionUsedRecordDb::PERMISSION_RECORD;
    PermissionUsedRecordDb::GetInstance().Add(type, values);
}

/*
 * @tc.name: Modify001
 * @tc.desc: PermissionUsedRecordDb::Modify function test
 * @tc.type: FUNC
 * @tc.require: issueI5YL6H
 */
HWTEST_F(PermissionRecordDBTest, Modify001, TestSize.Level1)
{
    GenericValues modifyValues;
    modifyValues.Put(PrivacyFiledConst::FIELD_STATUS, ActiveChangeType::PERM_ACTIVE_IN_FOREGROUND);

    GenericValues conditions;
    conditions.Put(PrivacyFiledConst::FIELD_TOKEN_ID, 0);
    conditions.Put(PrivacyFiledConst::FIELD_OP_CODE, Constant::OP_MICROPHONE);
    conditions.Put(PrivacyFiledConst::FIELD_STATUS, ActiveChangeType::PERM_ACTIVE_IN_FOREGROUND);
    conditions.Put(PrivacyFiledConst::FIELD_ACCESS_COUNT, 1);

    PermissionUsedRecordDb::DataType type = PermissionUsedRecordDb::PERMISSION_RECORD;
    ASSERT_EQ(0, PermissionUsedRecordDb::GetInstance().Modify(type, modifyValues, conditions));
}

/*
 * @tc.name: FindByConditions001
 * @tc.desc: PermissionUsedRecordDb::FindByConditions function test
 * @tc.type: FUNC
 * @tc.require: issueI5YL6H
 */
HWTEST_F(PermissionRecordDBTest, FindByConditions001, TestSize.Level1)
{
    GenericValues value;
    value.Put(PrivacyFiledConst::FIELD_TOKEN_ID, 0);
    value.Put(PrivacyFiledConst::FIELD_OP_CODE, Constant::OP_MICROPHONE);
    value.Put(PrivacyFiledConst::FIELD_STATUS, ActiveChangeType::PERM_ACTIVE_IN_FOREGROUND);
    value.Put(PrivacyFiledConst::FIELD_TIMESTAMP, 123); // 123 is random input
    value.Put(PrivacyFiledConst::FIELD_ACCESS_DURATION, 123); // 123 is random input
    value.Put(PrivacyFiledConst::FIELD_ACCESS_COUNT, 1);
    value.Put(PrivacyFiledConst::FIELD_REJECT_COUNT, 0);

    PermissionUsedRecordDb::DataType type = PermissionUsedRecordDb::PERMISSION_RECORD;
    std::vector<GenericValues> values;
    values.emplace_back(value);
    ASSERT_EQ(0, PermissionUsedRecordDb::GetInstance().Add(type, values));

    GenericValues orConditions;
    std::vector<GenericValues> results;

    GenericValues andConditions; // no column
    ASSERT_EQ(0, PermissionUsedRecordDb::GetInstance().FindByConditions(type, andConditions, orConditions, results));

    GenericValues andConditions1; // field timestamp
    andConditions1.Put(PrivacyFiledConst::FIELD_TIMESTAMP, 0);

    ASSERT_EQ(0, PermissionUsedRecordDb::GetInstance().FindByConditions(type, andConditions1, orConditions, results));

    GenericValues andConditions2; // field access_duration
    andConditions2.Put(PrivacyFiledConst::FIELD_ACCESS_DURATION, 0);
    ASSERT_EQ(0, PermissionUsedRecordDb::GetInstance().FindByConditions(type, andConditions2, orConditions, results));

    GenericValues andConditions3; // field not timestamp or access_duration
    andConditions3.Put(PrivacyFiledConst::FIELD_STATUS, ActiveChangeType::PERM_ACTIVE_IN_FOREGROUND);
    ASSERT_EQ(0, PermissionUsedRecordDb::GetInstance().FindByConditions(type, andConditions3, orConditions, results));

    ASSERT_EQ(0, PermissionUsedRecordDb::GetInstance().Remove(type, value));
}

/*
 * @tc.name: GetDistinctValue001
 * @tc.desc: PermissionUsedRecordDb::GetDistinctValue function test no column
 * @tc.type: FUNC
 * @tc.require: issueI5YL6H
 */
HWTEST_F(PermissionRecordDBTest, GetDistinctValue001, TestSize.Level1)
{
    PermissionUsedRecordDb::DataType type = PermissionUsedRecordDb::PERMISSION_RECORD;
    std::string condition;
    std::vector<GenericValues> results;
    ASSERT_EQ(0, PermissionUsedRecordDb::GetInstance().GetDistinctValue(type, condition, results));
}

/*
 * @tc.name: GetDistinctValue002
 * @tc.desc: PermissionUsedRecordDb::GetDistinctValue function test field token_id
 * @tc.type: FUNC
 * @tc.require: issueI5YL6H
 */
HWTEST_F(PermissionRecordDBTest, GetDistinctValue002, TestSize.Level1)
{
    GenericValues value;
    value.Put(PrivacyFiledConst::FIELD_TOKEN_ID, 0);
    value.Put(PrivacyFiledConst::FIELD_OP_CODE, Constant::OP_MICROPHONE);
    value.Put(PrivacyFiledConst::FIELD_STATUS, ActiveChangeType::PERM_ACTIVE_IN_FOREGROUND);
    value.Put(PrivacyFiledConst::FIELD_TIMESTAMP, 123); // 123 is random input
    value.Put(PrivacyFiledConst::FIELD_ACCESS_DURATION, 123); // 123 is random input
    value.Put(PrivacyFiledConst::FIELD_ACCESS_COUNT, 1);
    value.Put(PrivacyFiledConst::FIELD_REJECT_COUNT, 0);

    PermissionUsedRecordDb::DataType type = PermissionUsedRecordDb::PERMISSION_RECORD;
    std::vector<GenericValues> values;
    values.emplace_back(value);
    ASSERT_EQ(0, PermissionUsedRecordDb::GetInstance().Add(type, values));

    std::string condition = PrivacyFiledConst::FIELD_TOKEN_ID;
    std::vector<GenericValues> results;
    ASSERT_EQ(0, PermissionUsedRecordDb::GetInstance().GetDistinctValue(type, condition, results));
    results.clear();

    condition = PrivacyFiledConst::FIELD_TIMESTAMP;
    ASSERT_EQ(0, PermissionUsedRecordDb::GetInstance().GetDistinctValue(type, condition, results));
    ASSERT_EQ(0, PermissionUsedRecordDb::GetInstance().Remove(type, value));
}

/*
 * @tc.name: DeleteExpireRecords001
 * @tc.desc: PermissionUsedRecordDb::DeleteExpireRecords function test andColumns empty
 * @tc.type: FUNC
 * @tc.require: issueI5YL6H
 */
HWTEST_F(PermissionRecordDBTest, DeleteExpireRecords001, TestSize.Level1)
{
    PermissionUsedRecordDb::DataType type = PermissionUsedRecordDb::PERMISSION_RECORD;
    GenericValues andConditions;
    ASSERT_EQ(0, PermissionUsedRecordDb::GetInstance().DeleteExpireRecords(type, andConditions));
}

/*
 * @tc.name: DeleteExcessiveRecords001
 * @tc.desc: PermissionUsedRecordDb::DeleteExcessiveRecords function test
 * @tc.type: FUNC
 * @tc.require: issueI5YL6H
 */
HWTEST_F(PermissionRecordDBTest, DeleteExcessiveRecords001, TestSize.Level1)
{
    PermissionUsedRecordDb::DataType type = PermissionUsedRecordDb::PERMISSION_RECORD;
    uint32_t excessiveSize = 10;
    ASSERT_EQ(0, PermissionUsedRecordDb::GetInstance().DeleteExcessiveRecords(type, excessiveSize));
}
} // namespace AccessToken
} // namespace Security
} // namespace OHOS
