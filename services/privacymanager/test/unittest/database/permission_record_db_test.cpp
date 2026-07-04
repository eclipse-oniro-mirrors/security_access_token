/*
 * Copyright (c) 2022-2026 Huawei Device Co., Ltd.
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
#include "privacy_error.h"
#include "privacy_field_const.h"
#include "privacy_test_common.h"
#define private public
#include "permission_used_record_db.h"
#ifdef REMOTE_PRIVACY_ENABLE
#include "remote_permission_used_record_db.h"
#endif
#undef private
#include "permission_used_type.h"

using namespace testing::ext;

namespace OHOS {
namespace Security {
namespace AccessToken {
namespace {
static const int32_t NOT_EXSIT_TYPE = 9;
static const int32_t PERMISSION_USED_TYPE_VALUE = 1;
static const int32_t PICKER_TYPE_VALUE = 2;
static const int32_t RANDOM_TOKENID = 123;
static const int32_t INVALID_DB_TYPE = 100;
static const int32_t DEFAULT_ACCESS_DURATION = 123;
#ifdef REMOTE_PRIVACY_ENABLE
static const int32_t USER_ID_100 = 100;
static const int32_t USER_ID_INVALID = 12345;
const std::string DB_PATH = "/data/123456";
const std::string DB_NAME = "test.db";
#endif
}

class PermissionRecordDBTest : public testing::Test {
public:
    static void SetUpTestCase();
    static void TearDownTestCase();
    void SetUp();
    void TearDown();
};

static AccessTokenID g_selfTokenId = 0;

void PermissionRecordDBTest::SetUpTestCase()
{
    g_selfTokenId = GetSelfTokenID();
    PrivacyTestCommon::SetTestEvironment(g_selfTokenId);
}

void PermissionRecordDBTest::TearDownTestCase()
{
    SetSelfTokenID(g_selfTokenId);
    PrivacyTestCommon::ResetTestEvironment();
}

void PermissionRecordDBTest::SetUp()
{
}

void PermissionRecordDBTest::TearDown()
{
}

static GenericValues BuildPermissionRecordValue(AccessTokenID tokenId, int64_t timestamp,
    LockScreenStatusChangeType lockScreenStatus, PermissionUsedType usedType, const std::string& enhancedIdentity)
{
    GenericValues value;
    value.Put(PrivacyFiledConst::FIELD_TOKEN_ID, static_cast<int32_t>(tokenId));
    value.Put(PrivacyFiledConst::FIELD_OP_CODE, Constant::OP_MICROPHONE);
    value.Put(PrivacyFiledConst::FIELD_STATUS, ActiveChangeType::PERM_ACTIVE_IN_FOREGROUND);
    value.Put(PrivacyFiledConst::FIELD_TIMESTAMP, timestamp);
    value.Put(PrivacyFiledConst::FIELD_ACCESS_DURATION, DEFAULT_ACCESS_DURATION);
    value.Put(PrivacyFiledConst::FIELD_ACCESS_COUNT, 1);
    value.Put(PrivacyFiledConst::FIELD_REJECT_COUNT, 0);
    value.Put(PrivacyFiledConst::FIELD_LOCKSCREEN_STATUS, lockScreenStatus);
    value.Put(PrivacyFiledConst::FIELD_USED_TYPE, static_cast<int>(usedType));
    value.Put(PrivacyFiledConst::FIELD_ENHANCED_IDENTITY, enhancedIdentity);
    return value;
}

static GenericValues BuildPermissionRecordKey(AccessTokenID tokenId, int32_t opCode, int32_t status,
    int64_t timestamp, PermissionUsedType usedType, const std::string& enhancedIdentity)
{
    GenericValues value;
    value.Put(PrivacyFiledConst::FIELD_TOKEN_ID, static_cast<int32_t>(tokenId));
    value.Put(PrivacyFiledConst::FIELD_OP_CODE, opCode);
    value.Put(PrivacyFiledConst::FIELD_STATUS, status);
    value.Put(PrivacyFiledConst::FIELD_TIMESTAMP, timestamp);
    value.Put(PrivacyFiledConst::FIELD_USED_TYPE, static_cast<int>(usedType));
    value.Put(PrivacyFiledConst::FIELD_ENHANCED_IDENTITY, enhancedIdentity);
    return value;
}

/*
 * @tc.name: CreateInsertPrepareSqlCmd001
 * @tc.desc: PermissionUsedRecordDb::CreateInsertPrepareSqlCmd function test type not found
 * @tc.type: FUNC
 * @tc.require: issueI5YL6H
 */
HWTEST_F(PermissionRecordDBTest, CreateInsertPrepareSqlCmd001, TestSize.Level0)
{
    PermissionUsedRecordDb::DataType type = static_cast<PermissionUsedRecordDb::DataType>(INVALID_DB_TYPE);
    ASSERT_EQ("", PermissionUsedRecordDb::GetInstance().CreateInsertPrepareSqlCmd(type));
}

/*
 * @tc.name: CreateInsertPrepareSqlCmd002
 * @tc.desc: PermissionUsedRecordDb::CreateInsertPrepareSqlCmd function test
 * @tc.type: FUNC
 * @tc.require: issueI5YL6H
 */
HWTEST_F(PermissionRecordDBTest, CreateInsertPrepareSqlCmd002, TestSize.Level0)
{
    PermissionUsedRecordDb::DataType type = PermissionUsedRecordDb::PERMISSION_RECORD;
    ASSERT_NE("", PermissionUsedRecordDb::GetInstance().CreateInsertPrepareSqlCmd(type));
}

/*
 * @tc.name: CreateInsertPrepareSqlCmd003
 * @tc.desc: PermissionUsedRecordDb::CreateInsertPrepareSqlCmd contains enhanced_identity field
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(PermissionRecordDBTest, CreateInsertPrepareSqlCmd003, TestSize.Level0)
{
    PermissionUsedRecordDb::DataType type = PermissionUsedRecordDb::PERMISSION_RECORD;
    std::string sql = PermissionUsedRecordDb::GetInstance().CreateInsertPrepareSqlCmd(type);
    ASSERT_NE(std::string::npos, sql.find(PrivacyFiledConst::FIELD_ENHANCED_IDENTITY));
}

/*
 * @tc.name: CreateDeletePrepareSqlCmd001
 * @tc.desc: PermissionUsedRecordDb::CreateDeletePrepareSqlCmd function test type not found
 * @tc.type: FUNC
 * @tc.require: issueI5YL6H
 */
HWTEST_F(PermissionRecordDBTest, CreateDeletePrepareSqlCmd001, TestSize.Level0)
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
HWTEST_F(PermissionRecordDBTest, CreateUpdatePrepareSqlCmd001, TestSize.Level0)
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
HWTEST_F(PermissionRecordDBTest, CreateUpdatePrepareSqlCmd002, TestSize.Level0)
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
HWTEST_F(PermissionRecordDBTest, CreateUpdatePrepareSqlCmd003, TestSize.Level0)
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
HWTEST_F(PermissionRecordDBTest, CreateUpdatePrepareSqlCmd004, TestSize.Level0)
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
HWTEST_F(PermissionRecordDBTest, CreateUpdatePrepareSqlCmd005, TestSize.Level0)
{
    PermissionUsedRecordDb::DataType type = PermissionUsedRecordDb::PERMISSION_RECORD;
    std::vector<std::string> modifyColumns;
    modifyColumns.emplace_back(PrivacyFiledConst::FIELD_TOKEN_ID);
    modifyColumns.emplace_back(PrivacyFiledConst::FIELD_TIMESTAMP);
    std::vector<std::string> conditionColumns;
    conditionColumns.emplace_back(PrivacyFiledConst::FIELD_STATUS);
    ASSERT_NE("", PermissionUsedRecordDb::GetInstance().CreateUpdatePrepareSqlCmd(type, modifyColumns,
        conditionColumns));
}

/*
 * @tc.name: CreateSelectByConditionPrepareSqlCmd001
 * @tc.desc: PermissionUsedRecordDb::CreateSelectByConditionPrepareSqlCmd function test type not found
 * @tc.type: FUNC
 * @tc.require: issueI5YL6H
 */
HWTEST_F(PermissionRecordDBTest, CreateSelectByConditionPrepareSqlCmd001, TestSize.Level0)
{
    PermissionUsedRecordDb::DataType type = static_cast<PermissionUsedRecordDb::DataType>(100);
    std::set<int32_t> opCodeList;
    std::vector<std::string> andColumns;
    ASSERT_EQ("", PermissionUsedRecordDb::GetInstance().CreateSelectByConditionPrepareSqlCmd(0, type, opCodeList,
        andColumns, 10));
}

/*
 * @tc.name: CreateSelectByConditionPrepareSqlCmd002
 * @tc.desc: PermissionUsedRecordDb::CreateSelectByConditionPrepareSqlCmd function test
 * @tc.type: FUNC
 * @tc.require: issueI5YL6H
 */
HWTEST_F(PermissionRecordDBTest, CreateSelectByConditionPrepareSqlCmd002, TestSize.Level0)
{
    PermissionUsedRecordDb::DataType type = PermissionUsedRecordDb::PERMISSION_RECORD;
    std::set<int32_t> opCodeList;
    opCodeList.insert(static_cast<int32_t>(Constant::OP_LOCATION));
    std::vector<std::string> andColumns;
    andColumns.emplace_back(PrivacyFiledConst::FIELD_TIMESTAMP_BEGIN);
    std::vector<std::string> orColumns;
    orColumns.emplace_back(PrivacyFiledConst::FIELD_TIMESTAMP);
    ASSERT_NE("", PermissionUsedRecordDb::GetInstance().CreateSelectByConditionPrepareSqlCmd(0, type, opCodeList,
        andColumns, 10));
}

/*
 * @tc.name: CreateSelectByConditionPrepareSqlCmd003
 * @tc.desc: PermissionUsedRecordDb::CreateSelectByConditionPrepareSqlCmd function test for FIELD_USED_TYPE
 * @tc.type: FUNC
 * @tc.require:
*/
HWTEST_F(PermissionRecordDBTest, CreateSelectByConditionPrepareSqlCmd003, TestSize.Level0)
{
    PermissionUsedRecordDb::DataType type = PermissionUsedRecordDb::PERMISSION_RECORD;
    std::set<int32_t> opCodeList;
    std::vector<std::string> andColumns;
    andColumns.emplace_back(PrivacyFiledConst::FIELD_USED_TYPE);

    std::string sql = PermissionUsedRecordDb::GetInstance().CreateSelectByConditionPrepareSqlCmd(
        0, type, opCodeList, andColumns, 10);
    ASSERT_NE("", sql);

    ASSERT_TRUE(sql.find("in (") != std::string::npos);
    ASSERT_TRUE(sql.find(std::to_string(static_cast<int32_t>(PermissionUsedType::PICKER_TYPE))) != std::string::npos);
    ASSERT_TRUE(sql.find(std::to_string(static_cast<int32_t>(PermissionUsedType::SECURITY_COMPONENT_TYPE))) !=
        std::string::npos);
}

/*
 * @tc.name: CreateCountPrepareSqlCmd001
 * @tc.desc: PermissionUsedRecordDb::CreateCountPrepareSqlCmd function test type not found
 * @tc.type: FUNC
 * @tc.require: issueI5YL6H
 */
HWTEST_F(PermissionRecordDBTest, CreateCountPrepareSqlCmd001, TestSize.Level0)
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
HWTEST_F(PermissionRecordDBTest, CreateDeleteExpireRecordsPrepareSqlCmd001, TestSize.Level0)
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
 * @tc.name: DeleteHistoryRecordsInTables001
 * @tc.desc: PermissionUsedRecordDb::DeleteHistoryRecordsInTables function test
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(PermissionRecordDBTest, DeleteHistoryRecordsInTables001, TestSize.Level0)
{
    std::vector<PermissionUsedRecordDb::DataType> dataTypes;
    dataTypes.emplace_back(PermissionUsedRecordDb::DataType::PERMISSION_RECORD);
    dataTypes.emplace_back(PermissionUsedRecordDb::DataType::PERMISSION_USED_TYPE);
    std::unordered_set<AccessTokenID> tokenIDList;
    tokenIDList.emplace(RANDOM_TOKENID);
    EXPECT_EQ(0, PermissionUsedRecordDb::GetInstance().DeleteHistoryRecordsInTables(dataTypes, tokenIDList));
}

/*
 * @tc.name: CreateDeleteHistoryRecordsPrepareSqlCmd001
 * @tc.desc: PermissionUsedRecordDb::CreateDeleteHistoryRecordsPrepareSqlCmd function test
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(PermissionRecordDBTest, CreateDeleteHistoryRecordsPrepareSqlCmd001, TestSize.Level0)
{
    PermissionUsedRecordDb::DataType type = static_cast<PermissionUsedRecordDb::DataType>(100); // type not found
    std::unordered_set<AccessTokenID> tokenIDList;
    EXPECT_EQ("", PermissionUsedRecordDb::GetInstance().CreateDeleteHistoryRecordsPrepareSqlCmd(type, tokenIDList));

    type = PermissionUsedRecordDb::PERMISSION_RECORD;
    tokenIDList.emplace(RANDOM_TOKENID);
    EXPECT_NE("", PermissionUsedRecordDb::GetInstance().CreateDeleteHistoryRecordsPrepareSqlCmd(type, tokenIDList));
}

/*
 * @tc.name: CreateDeleteExcessiveRecordsPrepareSqlCmd001
 * @tc.desc: PermissionUsedRecordDb::CreateDeleteExcessiveRecordsPrepareSqlCmd function test type not found
 * @tc.type: FUNC
 * @tc.require: issueI5YL6H
 */
HWTEST_F(PermissionRecordDBTest, CreateDeleteExcessiveRecordsPrepareSqlCmd001, TestSize.Level0)
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
HWTEST_F(PermissionRecordDBTest, CreateDeleteExcessiveRecordsPrepareSqlCmd002, TestSize.Level0)
{
    PermissionUsedRecordDb::DataType type = PermissionUsedRecordDb::PERMISSION_RECORD;
    uint32_t excessiveSize = 10;
    ASSERT_NE("", PermissionUsedRecordDb::GetInstance().CreateDeleteExcessiveRecordsPrepareSqlCmd(type, excessiveSize));
}

/*
 * @tc.name: CreatePermissionRecordTable001
 * @tc.desc: PermissionUsedRecordDb::CreatePermissionRecordTable function test
 * @tc.type: FUNC
 * @tc.require: issueI5YL6H
 */
HWTEST_F(PermissionRecordDBTest, CreatePermissionRecordTable001, TestSize.Level0)
{
    ASSERT_EQ(0, PermissionUsedRecordDb::GetInstance().CreatePermissionRecordTable());

    std::map<PermissionUsedRecordDb::DataType, SqliteTable> dataTypeToSqlTable;
    dataTypeToSqlTable = PermissionUsedRecordDb::GetInstance().dataTypeToSqlTable_; // backup
    PermissionUsedRecordDb::GetInstance().dataTypeToSqlTable_.clear();

    ASSERT_EQ(PrivacyError::ERR_DATABASE_OPERATE_FAILED,
        PermissionUsedRecordDb::GetInstance().CreatePermissionRecordTable());
    PermissionUsedRecordDb::GetInstance().dataTypeToSqlTable_ = dataTypeToSqlTable; // recovery
}

/*
 * @tc.name: InsertLockScreenStatusColumn001
 * @tc.desc: PermissionUsedRecordDb::InsertLockScreenStatusColumn function test
 * @tc.type: FUNC
 * @tc.require: issueI5YL6H
 */
HWTEST_F(PermissionRecordDBTest, InsertLockScreenStatusColumn001, TestSize.Level0)
{
    ASSERT_EQ(Constant::SUCCESS, PermissionUsedRecordDb::GetInstance().InsertLockScreenStatusColumn());

    std::map<PermissionUsedRecordDb::DataType, SqliteTable> dataTypeToSqlTable;
    dataTypeToSqlTable = PermissionUsedRecordDb::GetInstance().dataTypeToSqlTable_; // backup
    PermissionUsedRecordDb::GetInstance().dataTypeToSqlTable_.clear();

    ASSERT_EQ(PrivacyError::ERR_DATABASE_OPERATE_FAILED,
        PermissionUsedRecordDb::GetInstance().InsertLockScreenStatusColumn());
    PermissionUsedRecordDb::GetInstance().dataTypeToSqlTable_ = dataTypeToSqlTable; // recovery
}

/*
 * @tc.name: InsertEnhancedIdentityColumn001
 * @tc.desc: PermissionUsedRecordDb::InsertEnhancedIdentityColumn function test
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(PermissionRecordDBTest, InsertEnhancedIdentityColumn001, TestSize.Level0)
{
    ASSERT_EQ(Constant::SUCCESS, PermissionUsedRecordDb::GetInstance().InsertEnhancedIdentityColumn());

    std::map<PermissionUsedRecordDb::DataType, SqliteTable> dataTypeToSqlTable;
    dataTypeToSqlTable = PermissionUsedRecordDb::GetInstance().dataTypeToSqlTable_; // backup
    PermissionUsedRecordDb::GetInstance().dataTypeToSqlTable_.clear();

    ASSERT_EQ(PrivacyError::ERR_DATABASE_OPERATE_FAILED,
        PermissionUsedRecordDb::GetInstance().InsertEnhancedIdentityColumn());
    PermissionUsedRecordDb::GetInstance().dataTypeToSqlTable_ = dataTypeToSqlTable; // recovery
}

/*
 * @tc.name: TranslationIntoGenericValues001
 * @tc.desc: DataTranslator::TranslationIntoGenericValues function test
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(PermissionRecordDBTest, TranslationIntoGenericValues001, TestSize.Level0)
{
    PermissionUsedRequest request;
    GenericValues andGenericValues;

    request.beginTimeMillis = -1;
    // begin < 0
    ASSERT_EQ(Constant::FAILURE,
        DataTranslator::TranslationIntoGenericValues(request, andGenericValues));

    request.beginTimeMillis = 10;
    request.endTimeMillis = -1;
    // begin > 0 + end < 0
    ASSERT_EQ(Constant::FAILURE,
        DataTranslator::TranslationIntoGenericValues(request, andGenericValues));

    request.endTimeMillis = 1;
    // begin > 0 + end > 0 + begin > end
    ASSERT_EQ(Constant::FAILURE,
        DataTranslator::TranslationIntoGenericValues(request, andGenericValues));

    request.beginTimeMillis = 10; // begin != 0
    request.endTimeMillis = 20; // end != 0
    request.flag = static_cast<PermissionUsageFlag>(9);
    // begin > 0 + end > 0 + begin < end + flag = 9
    ASSERT_EQ(Constant::FAILURE,
        DataTranslator::TranslationIntoGenericValues(request, andGenericValues));

    request.flag = PermissionUsageFlag::FLAG_PERMISSION_USAGE_DETAIL;
    request.permissionList.emplace_back("ohos.com.CAMERA");
    // begin > 0 + end > 0 + begin < end + flag = 1 + TransferPermissionToOpcode true
    ASSERT_EQ(Constant::SUCCESS,
        DataTranslator::TranslationIntoGenericValues(request, andGenericValues));
}

/*
 * @tc.name: TranslationIntoGenericValues002
 * @tc.desc: DataTranslator::TranslationIntoGenericValues function test for FLAG_PERMISSION_SECURITY_ACCESS_DETAIL
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(PermissionRecordDBTest, TranslationIntoGenericValues002, TestSize.Level0)
{
    PermissionUsedRequest request;
    GenericValues andGenericValues;

    request.beginTimeMillis = 10;
    request.endTimeMillis = 20;
    request.flag = PermissionUsageFlag::FLAG_PERMISSION_SECURITY_ACCESS_DETAIL;

    ASSERT_EQ(Constant::SUCCESS,
        DataTranslator::TranslationIntoGenericValues(request, andGenericValues));

    int32_t usedType = andGenericValues.GetInt(PrivacyFiledConst::FIELD_USED_TYPE);
    ASSERT_EQ(usedType, static_cast<int32_t>(PermissionUsedType::NORMAL_TYPE));
}

/*
 * @tc.name: TranslationGenericValuesIntoPermissionUsedRecord001
 * @tc.desc: DataTranslator::TranslationGenericValuesIntoPermissionUsedRecord function test
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(PermissionRecordDBTest, TranslationGenericValuesIntoPermissionUsedRecord001, TestSize.Level0)
{
    GenericValues inGenericValues;
    PermissionUsedRecord permissionRecord;

    int32_t opCode = static_cast<int32_t>(Constant::OpCode::OP_INVALID);
    inGenericValues.Put(PrivacyFiledConst::FIELD_OP_CODE, opCode);
    // TransferOpcodeToPermission fail
    ASSERT_EQ(Constant::FAILURE,
        DataTranslator::TranslationGenericValuesIntoPermissionUsedRecord(
        FLAG_PERMISSION_USAGE_SUMMARY, inGenericValues, permissionRecord));
    inGenericValues.Remove(PrivacyFiledConst::FIELD_OP_CODE);

    opCode = static_cast<int32_t>(Constant::OpCode::OP_CAMERA);
    inGenericValues.Put(PrivacyFiledConst::FIELD_OP_CODE, opCode);
    inGenericValues.Put(PrivacyFiledConst::FIELD_TIMESTAMP, 10);
    inGenericValues.Put(PrivacyFiledConst::FIELD_REJECT_COUNT, 1);
    inGenericValues.Put(PrivacyFiledConst::FIELD_FLAG, 1);
    // lastRejectTime > 0
    ASSERT_EQ(Constant::SUCCESS, DataTranslator::TranslationGenericValuesIntoPermissionUsedRecord(
        FLAG_PERMISSION_USAGE_DETAIL, inGenericValues, permissionRecord));
}

#ifdef REMOTE_PRIVACY_ENABLE
/*
 * @tc.name: TranslationRemoteRequestIntoGenericValues001
 * @tc.desc: DataTranslator::TranslationRemoteRequestIntoGenericValues function test
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(PermissionRecordDBTest, TranslationRemoteRequestIntoGenericValues001, TestSize.Level0)
{
    PermissionUsedRequest request;
    GenericValues andGenericValues;

    request.beginTimeMillis = -1;
    // begin < 0
    ASSERT_EQ(Constant::FAILURE,
        DataTranslator::TranslationRemoteRequestIntoGenericValues(request, andGenericValues));

    request.beginTimeMillis = 10;
    request.endTimeMillis = -1;
    // begin > 0 + end < 0
    ASSERT_EQ(Constant::FAILURE,
        DataTranslator::TranslationRemoteRequestIntoGenericValues(request, andGenericValues));

    request.endTimeMillis = 1;
    // begin > 0 + end > 0 + begin > end
    ASSERT_EQ(Constant::FAILURE,
        DataTranslator::TranslationRemoteRequestIntoGenericValues(request, andGenericValues));

    request.beginTimeMillis = 0; // begin == 0
    request.endTimeMillis = 20; // end != 0
    ASSERT_EQ(Constant::SUCCESS,
        DataTranslator::TranslationRemoteRequestIntoGenericValues(request, andGenericValues));

    request.beginTimeMillis = 10;
    ASSERT_EQ(Constant::SUCCESS,
        DataTranslator::TranslationRemoteRequestIntoGenericValues(request, andGenericValues));
}

/*
 * @tc.name: TranslationGenericValuesIntoRemotePermissionRecord001
 * @tc.desc: DataTranslator::TranslationGenericValuesIntoRemotePermissionRecord function test
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(PermissionRecordDBTest, TranslationGenericValuesIntoRemotePermissionRecord001, TestSize.Level0)
{
    GenericValues inGenericValues;
    PermissionUsedRecord permissionRecord;

    int32_t opCode = static_cast<int32_t>(Constant::OpCode::OP_INVALID);
    inGenericValues.Put(PrivacyFiledConst::FIELD_OP_CODE, opCode);
    // TransferOpcodeToPermission fail
    ASSERT_EQ(Constant::FAILURE,
        DataTranslator::TranslationGenericValuesIntoRemotePermissionRecord(
        FLAG_PERMISSION_USAGE_SUMMARY, inGenericValues, permissionRecord));
    inGenericValues.Remove(PrivacyFiledConst::FIELD_OP_CODE);

    opCode = static_cast<int32_t>(Constant::OpCode::OP_CAMERA);
    inGenericValues.Put(PrivacyFiledConst::FIELD_OP_CODE, opCode);
    inGenericValues.Put(PrivacyFiledConst::FIELD_TIMESTAMP, 10);
    inGenericValues.Put(PrivacyFiledConst::FIELD_ACCESS_COUNT, 0);
    inGenericValues.Put(PrivacyFiledConst::FIELD_REJECT_COUNT, 0);
    inGenericValues.Put(PrivacyFiledConst::FIELD_FLAG, 1);
    ASSERT_EQ(Constant::SUCCESS, DataTranslator::TranslationGenericValuesIntoRemotePermissionRecord(
        FLAG_PERMISSION_USAGE_DETAIL, inGenericValues, permissionRecord));

    inGenericValues.Remove(PrivacyFiledConst::FIELD_REJECT_COUNT);
    inGenericValues.Put(PrivacyFiledConst::FIELD_REJECT_COUNT, 1);
    ASSERT_EQ(Constant::SUCCESS, DataTranslator::TranslationGenericValuesIntoRemotePermissionRecord(
        FLAG_PERMISSION_USAGE_DETAIL, inGenericValues, permissionRecord));
}

/*
 * @tc.name: RemotePermUsedRecordDbManagerTest001
 * @tc.desc: RemotePermUsedRecordDbManager function test
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(PermissionRecordDBTest, RemotePermUsedRecordDbManagerTest001, TestSize.Level0)
{
    std::shared_ptr<RemotePermissionUsedRecordDb> db = RemotePermUsedRecordDbManager::GetInstance().GetDatabase(
        USER_ID_INVALID, false);
    EXPECT_EQ(nullptr, db);

    db = RemotePermUsedRecordDbManager::GetInstance().GetDatabase(USER_ID_100, false);

    std::vector<GenericValues> values;
    EXPECT_EQ(PrivacyError::ERR_FILE_OPERATE_FAILED,
        RemotePermUsedRecordDbManager::GetInstance().Add(USER_ID_INVALID, values));
    GenericValues value;
    EXPECT_EQ(Constant::SUCCESS,
        RemotePermUsedRecordDbManager::GetInstance().Remove(USER_ID_INVALID, value));
    
    std::set<int32_t> opCodeList;
    GenericValues andConditions;
    std::vector<GenericValues> results;
    int32_t databaseQueryCount = 0;
    EXPECT_EQ(Constant::SUCCESS, RemotePermUsedRecordDbManager::GetInstance().FindByConditions(
        USER_ID_INVALID, opCodeList, andConditions, results, databaseQueryCount));
    
    EXPECT_EQ(0, RemotePermUsedRecordDbManager::GetInstance().Count(USER_ID_INVALID));
    EXPECT_EQ(Constant::SUCCESS,
        RemotePermUsedRecordDbManager::GetInstance().DeleteExpireRecords(USER_ID_INVALID, value));
    EXPECT_EQ(Constant::SUCCESS,
        RemotePermUsedRecordDbManager::GetInstance().DeleteExcessiveRecords(USER_ID_INVALID, 1));
    EXPECT_EQ(PrivacyError::ERR_FILE_OPERATE_FAILED,
        RemotePermUsedRecordDbManager::GetInstance().Update(USER_ID_INVALID, value, value));
}

/*
 * @tc.name: RemotePermUsedRecordDbManagerTest002
 * @tc.desc: Test Count
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(PermissionRecordDBTest, RemotePermUsedRecordDbManagerTest002, TestSize.Level0)
{
    std::shared_ptr<RemotePermissionUsedRecordDb> db = RemotePermUsedRecordDbManager::GetInstance().GetDatabase(
        USER_ID_100, true);
    ASSERT_NE(nullptr, db);
    
    RemotePermUsedRecordDbManager::GetInstance().Count(USER_ID_100);

    GenericValues value;
    RemotePermUsedRecordDbManager::GetInstance().DeleteExpireRecords(USER_ID_100, value);

    value.Put(PrivacyFiledConst::FIELD_TIMESTAMP_BEGIN, 0);
    value.Put(PrivacyFiledConst::FIELD_TIMESTAMP_END, 1);
    value.Put(PrivacyFiledConst::FIELD_OP_CODE, static_cast<int32_t>(Constant::OpCode::OP_ANSWER_CALL));
    RemotePermUsedRecordDbManager::GetInstance().DeleteExpireRecords(USER_ID_100, value);

    RemotePermUsedRecordDbManager::GetInstance().DeleteExcessiveRecords(USER_ID_100, 1);

    GenericValues value2;
    value2.Put(PrivacyFiledConst::FIELD_DEVICE_ID, "ididid");
    value2.Put(PrivacyFiledConst::FIELD_DEVICE_NAME, "namename");
    value2.Put(PrivacyFiledConst::FIELD_OP_CODE, static_cast<int32_t>(Constant::OpCode::OP_ANSWER_CALL));
    value2.Put(PrivacyFiledConst::FIELD_TIMESTAMP, 1);
    value2.Put(PrivacyFiledConst::FIELD_ACCESS_COUNT, 1);
    value2.Put(PrivacyFiledConst::FIELD_REJECT_COUNT, 0);
    std::vector<GenericValues> values;
    values.push_back(value2);
    RemotePermUsedRecordDbManager::GetInstance().Add(USER_ID_100, values);
    RemotePermUsedRecordDbManager::GetInstance().DeleteExcessiveRecords(USER_ID_100, 1);
}

/*
 * @tc.name: RemotePermUsedRecordDbManagerTest003
 * @tc.desc: Test Count
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(PermissionRecordDBTest, RemotePermUsedRecordDbManagerTest003, TestSize.Level0)
{
    RemotePermissionUsedRecordDb db(DB_PATH, DB_NAME);
    std::vector<std::string> modifyColumns;
    std::vector<std::string> conditionColumns;
    std::string sql = db.CreateUpdatePrepareSqlCmd(modifyColumns, conditionColumns);
    EXPECT_TRUE(sql.empty());

    modifyColumns.push_back("abcde");
    modifyColumns.push_back("fghij");
    std::string sql2 = db.CreateUpdatePrepareSqlCmd(modifyColumns, conditionColumns);
    EXPECT_FALSE(sql2.empty());

    std::set<int32_t> opCodeList;
    std::vector<std::string> andColumns;
    int32_t databaseQueryCount = 0;
    andColumns.push_back("timestamp_begin");
    andColumns.push_back("timestamp_end");
    andColumns.push_back("abcde");
    std::string sql3 = db.CreateSelectByConditionPrepareSqlCmd(opCodeList, andColumns, databaseQueryCount);
    EXPECT_FALSE(sql3.empty());

    opCodeList.insert(static_cast<int32_t>(Constant::OpCode::OP_ANSWER_CALL));
    opCodeList.insert(static_cast<int32_t>(Constant::OpCode::OP_INVALID));
    std::string sql4 = db.CreateSelectByConditionPrepareSqlCmd(opCodeList, andColumns, databaseQueryCount);
    EXPECT_FALSE(sql4.empty());
}
#endif

/*
 * @tc.name: Add001
 * @tc.desc: PermissionUsedRecordDb::Add function test miss not null field
 * @tc.type: FUNC
 * @tc.require: issueI5YL6H
 */
HWTEST_F(PermissionRecordDBTest, Add001, TestSize.Level0)
{
    GenericValues value1;
    value1.Put(PrivacyFiledConst::FIELD_TOKEN_ID, 200);
    value1.Put(PrivacyFiledConst::FIELD_OP_CODE, Constant::OP_MICROPHONE);
    value1.Put(PrivacyFiledConst::FIELD_STATUS, ActiveChangeType::PERM_ACTIVE_IN_FOREGROUND);
    value1.Put(PrivacyFiledConst::FIELD_TIMESTAMP, 201); // 201 is random input
    value1.Put(PrivacyFiledConst::FIELD_REJECT_COUNT, 0);
    value1.Put(PrivacyFiledConst::FIELD_LOCKSCREEN_STATUS, LockScreenStatusChangeType::PERM_ACTIVE_IN_UNLOCKED);
    value1.Put(PrivacyFiledConst::FIELD_USED_TYPE, static_cast<int>(PermissionUsedType::NORMAL_TYPE));

    GenericValues value2;
    value2.Put(PrivacyFiledConst::FIELD_TOKEN_ID, 0);
    value2.Put(PrivacyFiledConst::FIELD_OP_CODE, Constant::OP_MICROPHONE);
    value2.Put(PrivacyFiledConst::FIELD_STATUS, ActiveChangeType::PERM_ACTIVE_IN_FOREGROUND);
    value2.Put(PrivacyFiledConst::FIELD_TIMESTAMP, 123); // 123 is random input
    value2.Put(PrivacyFiledConst::FIELD_ACCESS_COUNT, 1);
    value2.Put(PrivacyFiledConst::FIELD_LOCKSCREEN_STATUS, LockScreenStatusChangeType::PERM_ACTIVE_IN_UNLOCKED);
    value2.Put(PrivacyFiledConst::FIELD_USED_TYPE, static_cast<int>(PermissionUsedType::NORMAL_TYPE));

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
HWTEST_F(PermissionRecordDBTest, Add002, TestSize.Level0)
{
    GenericValues value1;
    value1.Put(PrivacyFiledConst::FIELD_TOKEN_ID, 200);
    value1.Put(PrivacyFiledConst::FIELD_OP_CODE, Constant::OP_MICROPHONE);
    value1.Put(PrivacyFiledConst::FIELD_STATUS, ActiveChangeType::PERM_ACTIVE_IN_FOREGROUND);
    value1.Put(PrivacyFiledConst::FIELD_TIMESTAMP, 201); // 201 is random input
    value1.Put(PrivacyFiledConst::FIELD_ACCESS_DURATION, 123); // 123 is random input
    value1.Put(PrivacyFiledConst::FIELD_ACCESS_COUNT, 1);
    value1.Put(PrivacyFiledConst::FIELD_REJECT_COUNT, 0);
    value1.Put(PrivacyFiledConst::FIELD_LOCKSCREEN_STATUS, LockScreenStatusChangeType::PERM_ACTIVE_IN_UNLOCKED);
    value1.Put(PrivacyFiledConst::FIELD_USED_TYPE, static_cast<int>(PermissionUsedType::NORMAL_TYPE));
    value1.Put(PrivacyFiledConst::FIELD_ENHANCED_IDENTITY, "");

    GenericValues value2;
    value2.Put(PrivacyFiledConst::FIELD_TOKEN_ID, 201);
    value2.Put(PrivacyFiledConst::FIELD_OP_CODE, Constant::OP_MICROPHONE);
    value2.Put(PrivacyFiledConst::FIELD_STATUS, ActiveChangeType::PERM_ACTIVE_IN_FOREGROUND);
    value2.Put(PrivacyFiledConst::FIELD_TIMESTAMP, 202); // 202 is random input
    value2.Put(PrivacyFiledConst::FIELD_ACCESS_DURATION, 123); // 123 is random input
    value2.Put(PrivacyFiledConst::FIELD_ACCESS_COUNT, 1);
    value2.Put(PrivacyFiledConst::FIELD_REJECT_COUNT, 0);
    value2.Put(PrivacyFiledConst::FIELD_LOCKSCREEN_STATUS, LockScreenStatusChangeType::PERM_ACTIVE_IN_UNLOCKED);
    value2.Put(PrivacyFiledConst::FIELD_USED_TYPE, static_cast<int>(PermissionUsedType::NORMAL_TYPE));
    value2.Put(PrivacyFiledConst::FIELD_ENHANCED_IDENTITY, "");

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
HWTEST_F(PermissionRecordDBTest, Add003, TestSize.Level0)
{
    std::vector<GenericValues> values;
    PermissionUsedRecordDb::DataType type = PermissionUsedRecordDb::PERMISSION_RECORD;
    ASSERT_EQ(0, PermissionUsedRecordDb::GetInstance().Add(type, values));
}

/*
 * @tc.name: Add004
 * @tc.desc: PermissionUsedRecordDb::Add function test
 * @tc.type: FUNC
 * @tc.require: issueI5RWXF
 */
HWTEST_F(PermissionRecordDBTest, Add004, TestSize.Level0)
{
    GenericValues value1;
    value1.Put(PrivacyFiledConst::FIELD_TOKEN_ID, 300);
    value1.Put(PrivacyFiledConst::FIELD_OP_CODE, Constant::OP_MICROPHONE);
    value1.Put(PrivacyFiledConst::FIELD_STATUS, ActiveChangeType::PERM_ACTIVE_IN_FOREGROUND);
    value1.Put(PrivacyFiledConst::FIELD_TIMESTAMP, 301); // 301 is random input
    value1.Put(PrivacyFiledConst::FIELD_ACCESS_DURATION, 123); // 123 is random input
    value1.Put(PrivacyFiledConst::FIELD_ACCESS_COUNT, 1);
    value1.Put(PrivacyFiledConst::FIELD_REJECT_COUNT, 0);
    value1.Put(PrivacyFiledConst::FIELD_LOCKSCREEN_STATUS, LockScreenStatusChangeType::PERM_ACTIVE_IN_UNLOCKED);
    value1.Put(PrivacyFiledConst::FIELD_USED_TYPE, static_cast<int>(PermissionUsedType::NORMAL_TYPE));
    value1.Put(PrivacyFiledConst::FIELD_ENHANCED_IDENTITY, "");

    GenericValues value2; // only used_type diff from value1
    value2.Put(PrivacyFiledConst::FIELD_TOKEN_ID, 300);
    value2.Put(PrivacyFiledConst::FIELD_OP_CODE, Constant::OP_MICROPHONE);
    value2.Put(PrivacyFiledConst::FIELD_STATUS, ActiveChangeType::PERM_ACTIVE_IN_FOREGROUND);
    value2.Put(PrivacyFiledConst::FIELD_TIMESTAMP, 302); // 302 is random input
    value2.Put(PrivacyFiledConst::FIELD_ACCESS_DURATION, 123); // 123 is random input
    value2.Put(PrivacyFiledConst::FIELD_ACCESS_COUNT, 1);
    value2.Put(PrivacyFiledConst::FIELD_REJECT_COUNT, 0);
    value2.Put(PrivacyFiledConst::FIELD_LOCKSCREEN_STATUS, LockScreenStatusChangeType::PERM_ACTIVE_IN_UNLOCKED);
    value2.Put(PrivacyFiledConst::FIELD_USED_TYPE, static_cast<int>(PermissionUsedType::PICKER_TYPE));
    value2.Put(PrivacyFiledConst::FIELD_ENHANCED_IDENTITY, "");

    PermissionUsedRecordDb::DataType type = PermissionUsedRecordDb::PERMISSION_RECORD;
    std::vector<GenericValues> values;
    values.emplace_back(value1);
    values.emplace_back(value2);

    // if primary key do not add used_type, this place should be wrong
    ASSERT_EQ(0, PermissionUsedRecordDb::GetInstance().Add(type, values));
    ASSERT_EQ(0, PermissionUsedRecordDb::GetInstance().Remove(type, value1));
    ASSERT_EQ(0, PermissionUsedRecordDb::GetInstance().Remove(type, value2));
}

/*
 * @tc.name: Add005
 * @tc.desc: PermissionUsedRecordDb::Add function test with same base key and different enhanced identity
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(PermissionRecordDBTest, Add005, TestSize.Level0)
{
    constexpr AccessTokenID TOKEN_ID = 1000;
    constexpr int64_t TIMESTAMP = 1005;
    GenericValues value1;
    value1.Put(PrivacyFiledConst::FIELD_TOKEN_ID, static_cast<int32_t>(TOKEN_ID));
    value1.Put(PrivacyFiledConst::FIELD_OP_CODE, Constant::OP_MICROPHONE);
    value1.Put(PrivacyFiledConst::FIELD_STATUS, ActiveChangeType::PERM_ACTIVE_IN_FOREGROUND);
    value1.Put(PrivacyFiledConst::FIELD_TIMESTAMP, TIMESTAMP);
    value1.Put(PrivacyFiledConst::FIELD_ACCESS_DURATION, 123);
    value1.Put(PrivacyFiledConst::FIELD_ACCESS_COUNT, 1);
    value1.Put(PrivacyFiledConst::FIELD_REJECT_COUNT, 0);
    value1.Put(PrivacyFiledConst::FIELD_LOCKSCREEN_STATUS, LockScreenStatusChangeType::PERM_ACTIVE_IN_UNLOCKED);
    value1.Put(PrivacyFiledConst::FIELD_USED_TYPE, static_cast<int>(PermissionUsedType::NORMAL_TYPE));
    value1.Put(PrivacyFiledConst::FIELD_ENHANCED_IDENTITY, "agentA");

    GenericValues value2 = BuildPermissionRecordValue(TOKEN_ID, TIMESTAMP,
        LockScreenStatusChangeType::PERM_ACTIVE_IN_UNLOCKED, PermissionUsedType::NORMAL_TYPE, "agentB");

    PermissionUsedRecordDb::DataType type = PermissionUsedRecordDb::PERMISSION_RECORD;
    std::vector<GenericValues> values;
    values.emplace_back(value1);
    values.emplace_back(value2);
    GenericValues key1 = BuildPermissionRecordKey(TOKEN_ID, Constant::OP_MICROPHONE,
        ActiveChangeType::PERM_ACTIVE_IN_FOREGROUND, TIMESTAMP, PermissionUsedType::NORMAL_TYPE, "agentA");
    GenericValues key2 = BuildPermissionRecordKey(TOKEN_ID, Constant::OP_MICROPHONE,
        ActiveChangeType::PERM_ACTIVE_IN_FOREGROUND, TIMESTAMP, PermissionUsedType::NORMAL_TYPE, "agentB");

    PermissionUsedRecordDb::GetInstance().Remove(type, key1);
    PermissionUsedRecordDb::GetInstance().Remove(type, key2);
    ASSERT_EQ(0, PermissionUsedRecordDb::GetInstance().Add(type, values));
    ASSERT_EQ(0, PermissionUsedRecordDb::GetInstance().Remove(type, key1));
    ASSERT_EQ(0, PermissionUsedRecordDb::GetInstance().Remove(type, key2));
}

/*
 * @tc.name: OnUpdate006
 * @tc.desc: Verify 6->7 migration updates primary key to include enhanced_identity
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(PermissionRecordDBTest, OnUpdate006, TestSize.Level0)
{
    constexpr AccessTokenID TOKEN_ID = 1200;
    constexpr int64_t TIMESTAMP = 1203;
    auto& db = PermissionUsedRecordDb::GetInstance();
    ASSERT_EQ(0, db.ExecuteSql("drop table if exists permission_record_table"));
    ASSERT_EQ(0, db.ExecuteSql("drop table if exists permission_record_table_new"));
    ASSERT_EQ(0, db.ExecuteSql("create table permission_record_table ("
        "token_id integer,"
        "op_code integer,"
        "status integer,"
        "timestamp integer,"
        "access_duration integer,"
        "access_count integer,"
        "reject_count integer,"
        "lockscreen_status integer,"
        "used_type integer,"
        "primary key(token_id,op_code,status,timestamp,used_type))"));

    int32_t version = 6;
    db.OnUpdate(version);

    GenericValues value1 = BuildPermissionRecordValue(TOKEN_ID, TIMESTAMP,
        LockScreenStatusChangeType::PERM_ACTIVE_IN_LOCKED, PermissionUsedType::NORMAL_TYPE, "agentA");
    GenericValues value2 = BuildPermissionRecordValue(TOKEN_ID, TIMESTAMP,
        LockScreenStatusChangeType::PERM_ACTIVE_IN_LOCKED, PermissionUsedType::NORMAL_TYPE, "agentB");
    GenericValues key1 = BuildPermissionRecordKey(TOKEN_ID, Constant::OP_MICROPHONE,
        ActiveChangeType::PERM_ACTIVE_IN_FOREGROUND, TIMESTAMP, PermissionUsedType::NORMAL_TYPE, "agentA");
    GenericValues key2 = BuildPermissionRecordKey(TOKEN_ID, Constant::OP_MICROPHONE,
        ActiveChangeType::PERM_ACTIVE_IN_FOREGROUND, TIMESTAMP, PermissionUsedType::NORMAL_TYPE, "agentB");

    PermissionUsedRecordDb::DataType type = PermissionUsedRecordDb::PERMISSION_RECORD;
    std::vector<GenericValues> values = {value1, value2};
    db.Remove(type, key1);
    db.Remove(type, key2);
    ASSERT_EQ(0, db.Add(type, values));

    std::set<int32_t> opCodeList;
    GenericValues andConditions;
    andConditions.Put(PrivacyFiledConst::FIELD_TOKEN_ID, static_cast<int32_t>(TOKEN_ID));
    std::vector<GenericValues> results;
    ASSERT_EQ(0, db.FindByConditions(type, opCodeList, andConditions, results, 10));
    ASSERT_EQ(2, static_cast<int32_t>(results.size()));

    ASSERT_EQ(0, db.Remove(type, key1));
    ASSERT_EQ(0, db.Remove(type, key2));
}

/*
 * @tc.name: OnUpdate007
 * @tc.desc: Verify 6->7 migration fills legacy records with empty enhanced_identity by default
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(PermissionRecordDBTest, OnUpdate007, TestSize.Level0)
{
    auto& db = PermissionUsedRecordDb::GetInstance();
    ASSERT_EQ(0, db.ExecuteSql("drop table if exists permission_record_table"));
    ASSERT_EQ(0, db.ExecuteSql("drop table if exists permission_record_table_new"));
    ASSERT_EQ(0, db.ExecuteSql("create table permission_record_table ("
        "token_id integer,"
        "op_code integer,"
        "status integer,"
        "timestamp integer,"
        "access_duration integer,"
        "access_count integer,"
        "reject_count integer,"
        "lockscreen_status integer,"
        "used_type integer,"
        "primary key(token_id,op_code,status,timestamp,used_type))"));
    ASSERT_EQ(0, db.ExecuteSql("insert into permission_record_table values("
        "1300, 1, 1, 1303, 123, 1, 0, 1, 0)"));

    db.OnUpdate(6);

    auto stmt = db.Prepare("pragma table_info(permission_record_table)");
    bool foundEnhancedIdentity = false;
    while (stmt.Step() == Statement::State::ROW) {
        if (stmt.GetColumnString(1) == PrivacyFiledConst::FIELD_ENHANCED_IDENTITY) {
            foundEnhancedIdentity = true;
            EXPECT_EQ("", stmt.GetColumnString(4));
        }
    }
    EXPECT_TRUE(foundEnhancedIdentity);

    std::set<int32_t> opCodeList;
    GenericValues andConditions;
    andConditions.Put(PrivacyFiledConst::FIELD_TOKEN_ID, 1300);
    std::vector<GenericValues> results;
    ASSERT_EQ(0, db.FindByConditions(PermissionUsedRecordDb::PERMISSION_RECORD, opCodeList, andConditions,
        results, 10));
    ASSERT_EQ(1, static_cast<int32_t>(results.size()));
    EXPECT_EQ("", results[0].GetString(PrivacyFiledConst::FIELD_ENHANCED_IDENTITY));
}

/*
 * @tc.name: FindByConditions001
 * @tc.desc: PermissionUsedRecordDb::FindByConditions function test
 * @tc.type: FUNC
 * @tc.require: issueI5YL6H
 */
HWTEST_F(PermissionRecordDBTest, FindByConditions001, TestSize.Level0)
{
    GenericValues value;
    std::set<int32_t> opCodeList;
    value.Put(PrivacyFiledConst::FIELD_TOKEN_ID, 400);
    value.Put(PrivacyFiledConst::FIELD_OP_CODE, Constant::OP_MICROPHONE);
    value.Put(PrivacyFiledConst::FIELD_STATUS, ActiveChangeType::PERM_ACTIVE_IN_FOREGROUND);
    value.Put(PrivacyFiledConst::FIELD_TIMESTAMP, 401); // 401 is random input
    value.Put(PrivacyFiledConst::FIELD_ACCESS_DURATION, 123); // 123 is random input
    value.Put(PrivacyFiledConst::FIELD_ACCESS_COUNT, 1);
    value.Put(PrivacyFiledConst::FIELD_REJECT_COUNT, 0);
    value.Put(PrivacyFiledConst::FIELD_LOCKSCREEN_STATUS, LockScreenStatusChangeType::PERM_ACTIVE_IN_LOCKED);
    value.Put(PrivacyFiledConst::FIELD_USED_TYPE, static_cast<int>(PermissionUsedType::NORMAL_TYPE));
    value.Put(PrivacyFiledConst::FIELD_ENHANCED_IDENTITY, "");

    PermissionUsedRecordDb::DataType type = PermissionUsedRecordDb::PERMISSION_RECORD;
    std::vector<GenericValues> values;
    values.emplace_back(value);
    ASSERT_EQ(0, PermissionUsedRecordDb::GetInstance().Add(type, values));

    GenericValues orConditions;
    std::vector<GenericValues> results;

    GenericValues andConditions; // no column
    ASSERT_EQ(0, PermissionUsedRecordDb::GetInstance().FindByConditions(type, opCodeList, andConditions, results, 10));

    GenericValues andConditions1; // field timestamp
    andConditions1.Put(PrivacyFiledConst::FIELD_TIMESTAMP, 0);

    ASSERT_EQ(0, PermissionUsedRecordDb::GetInstance().FindByConditions(type, opCodeList, andConditions1, results, 10));

    GenericValues andConditions2; // field access_duration
    andConditions2.Put(PrivacyFiledConst::FIELD_ACCESS_DURATION, 0);
    ASSERT_EQ(0, PermissionUsedRecordDb::GetInstance().FindByConditions(type, opCodeList, andConditions2, results, 10));

    GenericValues andConditions3; // field not timestamp or access_duration
    andConditions3.Put(PrivacyFiledConst::FIELD_STATUS, ActiveChangeType::PERM_ACTIVE_IN_FOREGROUND);
    ASSERT_EQ(0, PermissionUsedRecordDb::GetInstance().FindByConditions(type, opCodeList, andConditions3, results, 10));

    GenericValues andConditions4;
    andConditions4.Put(PrivacyFiledConst::FIELD_LOCKSCREEN_STATUS, LockScreenStatusChangeType::PERM_ACTIVE_IN_LOCKED);
    ASSERT_EQ(0, PermissionUsedRecordDb::GetInstance().FindByConditions(type, opCodeList, andConditions4, results, 10));

    ASSERT_EQ(0, PermissionUsedRecordDb::GetInstance().Remove(type, value));
}

/*
 * @tc.name: FindByConditions003
 * @tc.desc: PermissionUsedRecordDb::FindByConditions function test with enhanced_identity filter
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(PermissionRecordDBTest, FindByConditions003, TestSize.Level0)
{
    constexpr AccessTokenID TOKEN_ID = 1100;
    constexpr int64_t TIMESTAMP = 1103;
    GenericValues value1;
    value1.Put(PrivacyFiledConst::FIELD_TOKEN_ID, static_cast<int32_t>(TOKEN_ID));
    value1.Put(PrivacyFiledConst::FIELD_OP_CODE, Constant::OP_MICROPHONE);
    value1.Put(PrivacyFiledConst::FIELD_STATUS, ActiveChangeType::PERM_ACTIVE_IN_FOREGROUND);
    value1.Put(PrivacyFiledConst::FIELD_TIMESTAMP, TIMESTAMP);
    value1.Put(PrivacyFiledConst::FIELD_ACCESS_DURATION, 123);
    value1.Put(PrivacyFiledConst::FIELD_ACCESS_COUNT, 1);
    value1.Put(PrivacyFiledConst::FIELD_REJECT_COUNT, 0);
    value1.Put(PrivacyFiledConst::FIELD_LOCKSCREEN_STATUS, LockScreenStatusChangeType::PERM_ACTIVE_IN_LOCKED);
    value1.Put(PrivacyFiledConst::FIELD_USED_TYPE, static_cast<int>(PermissionUsedType::NORMAL_TYPE));
    value1.Put(PrivacyFiledConst::FIELD_ENHANCED_IDENTITY, "agentA");

    GenericValues value2 = BuildPermissionRecordValue(TOKEN_ID, TIMESTAMP,
        LockScreenStatusChangeType::PERM_ACTIVE_IN_LOCKED, PermissionUsedType::NORMAL_TYPE, "agentB");

    PermissionUsedRecordDb::DataType type = PermissionUsedRecordDb::PERMISSION_RECORD;
    std::vector<GenericValues> values;
    values.emplace_back(value1);
    values.emplace_back(value2);
    GenericValues key1 = BuildPermissionRecordKey(TOKEN_ID, Constant::OP_MICROPHONE,
        ActiveChangeType::PERM_ACTIVE_IN_FOREGROUND, TIMESTAMP, PermissionUsedType::NORMAL_TYPE, "agentA");
    GenericValues key2 = BuildPermissionRecordKey(TOKEN_ID, Constant::OP_MICROPHONE,
        ActiveChangeType::PERM_ACTIVE_IN_FOREGROUND, TIMESTAMP, PermissionUsedType::NORMAL_TYPE, "agentB");
    PermissionUsedRecordDb::GetInstance().Remove(type, key1);
    PermissionUsedRecordDb::GetInstance().Remove(type, key2);
    ASSERT_EQ(0, PermissionUsedRecordDb::GetInstance().Add(type, values));

    std::set<int32_t> opCodeList;
    GenericValues andConditions;
    andConditions.Put(PrivacyFiledConst::FIELD_TOKEN_ID, static_cast<int32_t>(TOKEN_ID));
    andConditions.Put(PrivacyFiledConst::FIELD_ENHANCED_IDENTITY, "agentA");
    std::vector<GenericValues> results;
    ASSERT_EQ(0, PermissionUsedRecordDb::GetInstance().FindByConditions(type, opCodeList, andConditions, results, 10));
    ASSERT_EQ(1, static_cast<int32_t>(results.size()));
    EXPECT_EQ("agentA", results[0].GetString(PrivacyFiledConst::FIELD_ENHANCED_IDENTITY));

    ASSERT_EQ(0, PermissionUsedRecordDb::GetInstance().Remove(type, key1));
    ASSERT_EQ(0, PermissionUsedRecordDb::GetInstance().Remove(type, key2));
}

/*
 * @tc.name: FindByConditions002
 * @tc.desc: PermissionUsedRecordDb::FindByConditions function test
 * @tc.type: FUNC
 * @tc.require: issueI5YL6H
 */
HWTEST_F(PermissionRecordDBTest, FindByConditions002, TestSize.Level0)
{
    GenericValues value1 = BuildPermissionRecordValue(1, 123, LockScreenStatusChangeType::PERM_ACTIVE_IN_LOCKED,
        PermissionUsedType::NORMAL_TYPE, "");
    GenericValues value2 = BuildPermissionRecordValue(2, 123, LockScreenStatusChangeType::PERM_ACTIVE_IN_LOCKED,
        PermissionUsedType::NORMAL_TYPE, "");
    GenericValues value3 = BuildPermissionRecordValue(3, 123, LockScreenStatusChangeType::PERM_ACTIVE_IN_LOCKED,
        PermissionUsedType::NORMAL_TYPE, "");

    PermissionUsedRecordDb::DataType type = PermissionUsedRecordDb::PERMISSION_RECORD;
    std::vector<GenericValues> values;
    values.emplace_back(value1);
    values.emplace_back(value2);
    values.emplace_back(value3);
    ASSERT_EQ(0, PermissionUsedRecordDb::GetInstance().Add(type, values));

    std::set<int32_t> opCodeList;
    GenericValues andConditions;
    std::vector<GenericValues> results;
    andConditions.Put(PrivacyFiledConst::FIELD_OP_CODE, Constant::OP_MICROPHONE);
    andConditions.Put(PrivacyFiledConst::FIELD_STATUS, ActiveChangeType::PERM_ACTIVE_IN_FOREGROUND);
    ASSERT_EQ(0, PermissionUsedRecordDb::GetInstance().FindByConditions(type, opCodeList, andConditions, results, 2));
    ASSERT_EQ(static_cast<size_t>(2), results.size());

    ASSERT_EQ(0, PermissionUsedRecordDb::GetInstance().Remove(type, value1));
    ASSERT_EQ(0, PermissionUsedRecordDb::GetInstance().Remove(type, value2));
    ASSERT_EQ(0, PermissionUsedRecordDb::GetInstance().Remove(type, value3));
}

/*
 * @tc.name: DeleteExpireRecords001
 * @tc.desc: PermissionUsedRecordDb::DeleteExpireRecords function test andColumns empty
 * @tc.type: FUNC
 * @tc.require: issueI5YL6H
 */
HWTEST_F(PermissionRecordDBTest, DeleteExpireRecords001, TestSize.Level0)
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
HWTEST_F(PermissionRecordDBTest, DeleteExcessiveRecords001, TestSize.Level0)
{
    PermissionUsedRecordDb::DataType type = PermissionUsedRecordDb::PERMISSION_RECORD;
    uint32_t excessiveSize = 10;
    ASSERT_EQ(0, PermissionUsedRecordDb::GetInstance().DeleteExcessiveRecords(type, excessiveSize));
}

/*
 * @tc.name: CreateQueryPrepareSqlCmd001
 * @tc.desc: PermissionUsedRecordDb::CreateQueryPrepareSqlCmd function test
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(PermissionRecordDBTest, CreateQueryPrepareSqlCmd001, TestSize.Level0)
{
    PermissionUsedRecordDb::DataType type = PermissionUsedRecordDb::PERMISSION_USED_TYPE;
    std::vector<std::string> conditionColumns;
    ASSERT_NE("", PermissionUsedRecordDb::GetInstance().CreateQueryPrepareSqlCmd(
        type, conditionColumns));

    type = static_cast<PermissionUsedRecordDb::DataType>(NOT_EXSIT_TYPE);
    ASSERT_EQ("", PermissionUsedRecordDb::GetInstance().CreateQueryPrepareSqlCmd(
        type, conditionColumns));
}

/*
 * @tc.name: Query001
 * @tc.desc: PermissionUsedRecordDb::Query function test
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(PermissionRecordDBTest, Query001, TestSize.Level0)
{
    PermissionUsedRecordDb::DataType type = PermissionUsedRecordDb::PERMISSION_USED_TYPE;
    GenericValues conditionValue;
    conditionValue.Put(PrivacyFiledConst::FIELD_TOKEN_ID, RANDOM_TOKENID);
    conditionValue.Put(PrivacyFiledConst::FIELD_PERMISSION_CODE,
        static_cast<int32_t>(Constant::OpCode::OP_ANSWER_CALL));
    std::vector<GenericValues> results;
    ASSERT_EQ(PermissionUsedRecordDb::ExecuteResult::SUCCESS,
        PermissionUsedRecordDb::GetInstance().Query(type, conditionValue, results));
    for (const auto& result : results) {
        // no record with token 123 before add
        ASSERT_NE(RANDOM_TOKENID, result.GetInt(PrivacyFiledConst::FIELD_TOKEN_ID));
    }
    results.clear();

    GenericValues value;
    value.Put(PrivacyFiledConst::FIELD_TOKEN_ID, RANDOM_TOKENID);
    value.Put(PrivacyFiledConst::FIELD_PERMISSION_CODE, static_cast<int32_t>(Constant::OpCode::OP_ANSWER_CALL));
    value.Put(PrivacyFiledConst::FIELD_USED_TYPE, PERMISSION_USED_TYPE_VALUE);
    std::vector<GenericValues> values;
    values.emplace_back(value);
    // add a record: 123-0-1
    ASSERT_EQ(PermissionUsedRecordDb::ExecuteResult::SUCCESS, PermissionUsedRecordDb::GetInstance().Add(type, values));

    ASSERT_EQ(PermissionUsedRecordDb::ExecuteResult::SUCCESS,
        PermissionUsedRecordDb::GetInstance().Query(type, conditionValue, results));
    ASSERT_EQ(false, results.empty());
    for (const auto& result : results) {
        // query result success, when tokenId is 123, permission_code is 0 and used_type is 1
        if (RANDOM_TOKENID == result.GetInt(PrivacyFiledConst::FIELD_TOKEN_ID)) {
            ASSERT_EQ(static_cast<int32_t>(Constant::OpCode::OP_ANSWER_CALL),
                result.GetInt(PrivacyFiledConst::FIELD_PERMISSION_CODE));
            ASSERT_EQ(PERMISSION_USED_TYPE_VALUE, result.GetInt(PrivacyFiledConst::FIELD_USED_TYPE));
            break;
        }
    }

    ASSERT_EQ(PermissionUsedRecordDb::ExecuteResult::SUCCESS, PermissionUsedRecordDb::GetInstance().Remove(
        type, conditionValue));
}

/*
 * @tc.name: Update001
 * @tc.desc: PermissionUsedRecordDb::Update function test
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(PermissionRecordDBTest, Update001, TestSize.Level0)
{
    PermissionUsedRecordDb::DataType type = PermissionUsedRecordDb::PERMISSION_USED_TYPE;
    GenericValues conditionValue;
    conditionValue.Put(PrivacyFiledConst::FIELD_TOKEN_ID, RANDOM_TOKENID);
    conditionValue.Put(PrivacyFiledConst::FIELD_PERMISSION_CODE,
        static_cast<int32_t>(Constant::OpCode::OP_ANSWER_CALL));

    GenericValues value;
    value.Put(PrivacyFiledConst::FIELD_TOKEN_ID, RANDOM_TOKENID);
    value.Put(PrivacyFiledConst::FIELD_PERMISSION_CODE, static_cast<int32_t>(Constant::OpCode::OP_ANSWER_CALL));
    value.Put(PrivacyFiledConst::FIELD_USED_TYPE, PERMISSION_USED_TYPE_VALUE);
    std::vector<GenericValues> values;
    values.emplace_back(value);
    // add a record: 123-0-1
    ASSERT_EQ(PermissionUsedRecordDb::ExecuteResult::SUCCESS, PermissionUsedRecordDb::GetInstance().Add(type, values));

    std::vector<GenericValues> results;
    ASSERT_EQ(PermissionUsedRecordDb::ExecuteResult::SUCCESS,
        PermissionUsedRecordDb::GetInstance().Query(type, conditionValue, results));
    ASSERT_EQ(false, results.empty());
    for (const auto& result : results) {
        // query result success, when tokenId is 123, permission_code is 0 and used_type is 1
        if (RANDOM_TOKENID == result.GetInt(PrivacyFiledConst::FIELD_TOKEN_ID)) {
            ASSERT_EQ(static_cast<int32_t>(Constant::OpCode::OP_ANSWER_CALL),
                result.GetInt(PrivacyFiledConst::FIELD_PERMISSION_CODE));
            ASSERT_EQ(PERMISSION_USED_TYPE_VALUE, result.GetInt(PrivacyFiledConst::FIELD_USED_TYPE));
            break;
        }
    }
    results.clear();

    GenericValues modifyValue;
    modifyValue.Put(PrivacyFiledConst::FIELD_USED_TYPE, PICKER_TYPE_VALUE);
    // update record 123-0-1 to 123-0-2
    ASSERT_EQ(PermissionUsedRecordDb::ExecuteResult::SUCCESS, PermissionUsedRecordDb::GetInstance().Update(
        type, modifyValue, conditionValue));
    ASSERT_EQ(PermissionUsedRecordDb::ExecuteResult::SUCCESS,
        PermissionUsedRecordDb::GetInstance().Query(type, conditionValue, results));
    ASSERT_EQ(false, results.empty());
    for (const auto& result : results) {
        // query result success, when tokenId is 123, permission_code is 0 and used_type is 2
        if (RANDOM_TOKENID == result.GetInt(PrivacyFiledConst::FIELD_TOKEN_ID)) {
            ASSERT_EQ(static_cast<int32_t>(Constant::OpCode::OP_ANSWER_CALL),
                result.GetInt(PrivacyFiledConst::FIELD_PERMISSION_CODE));
            ASSERT_EQ(PICKER_TYPE_VALUE, result.GetInt(PrivacyFiledConst::FIELD_USED_TYPE));
            break;
        }
    }

    ASSERT_EQ(PermissionUsedRecordDb::ExecuteResult::SUCCESS, PermissionUsedRecordDb::GetInstance().Remove(
        type, conditionValue));
}
} // namespace AccessToken
} // namespace Security
} // namespace OHOS
