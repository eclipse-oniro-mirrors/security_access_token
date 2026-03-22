/*
 * Copyright (c) 2021-2024 Huawei Device Co., Ltd.
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

#include "access_token_db_util.h"

#include <map>

#include "token_field_const.h"

namespace OHOS {
namespace Security {
namespace AccessToken {
namespace {
static const std::vector<std::string> g_StringTypeColumns = {
    "description", "permission_name", "device_id", "bundle_name", "app_id",
    "process_name", "dcap", "native_acls", "label", "value", "name", "app_distribution_type"
};

static const std::map<AtmDataType, std::string> g_DateTypeToTableName = {
    {AtmDataType::ACCESSTOKEN_HAP_INFO, "hap_token_info_table"},
    {AtmDataType::ACCESSTOKEN_NATIVE_INFO, "native_token_info_table"},
    {AtmDataType::ACCESSTOKEN_PERMISSION_DEF, "permission_definition_table"},
    {AtmDataType::ACCESSTOKEN_PERMISSION_STATE, "permission_state_table"},
    {AtmDataType::ACCESSTOKEN_PERMISSION_REQUEST_TOGGLE_STATUS, "permission_request_toggle_status_table"},
    {AtmDataType::ACCESSTOKEN_PERMISSION_EXTEND_VALUE, "permission_extend_value_table"},
    {AtmDataType::ACCESSTOKEN_HAP_UNDEFINE_INFO, "hap_undefine_info_table"},
    {AtmDataType::ACCESSTOKEN_SYSTEM_CONFIG, "system_config_table"},
};

void AddStringInPredicate(const DbQueryCondition& condition, NativeRdb::RdbPredicates& predicates)
{
    std::vector<std::string> values;
    values.reserve(condition.values.size());
    for (const auto& value : condition.values) {
        values.emplace_back(value.GetString());
    }
    predicates.In(condition.column, values);
}

void AddNumericInPredicate(const DbQueryCondition& condition, NativeRdb::RdbPredicates& predicates)
{
    std::vector<NativeRdb::ValueObject> values;
    values.reserve(condition.values.size());
    for (const auto& value : condition.values) {
        if (value.GetType() == ValueType::TYPE_INT64) {
            values.emplace_back(static_cast<int64_t>(value.GetInt64()));
            continue;
        }
        values.emplace_back(value.GetInt());
    }
    predicates.In(condition.column, values);
}
}

void AccessTokenDbUtil::GetTableNameByType(const AtmDataType type, std::string& tableName)
{
    auto iterator = g_DateTypeToTableName.find(type);
    if (iterator != g_DateTypeToTableName.end()) {
        tableName = iterator->second;
    }
}

bool AccessTokenDbUtil::IsColumnStringType(const std::string& column)
{
    auto iterator = std::find(g_StringTypeColumns.begin(), g_StringTypeColumns.end(), column);
    if (iterator != g_StringTypeColumns.end()) {
        return true;
    }

    return false;
}

void AccessTokenDbUtil::ToRdbValueBucket(const GenericValues& value, NativeRdb::ValuesBucket& bucket)
{
    std::vector<std::string> columnNames = value.GetAllKeys();
    uint32_t size = columnNames.size(); // size 0 means insert or update nonthing, this should ignore

    for (uint32_t i = 0; i < size; ++i) {
        std::string column = columnNames[i];

        if (IsColumnStringType(column)) {
            bucket.PutString(column, value.GetString(column));
        } else if (column == TokenFiledConst::FIELD_TIMESTAMP) {
            bucket.PutLong(column, value.GetInt64(column));
        } else {
            bucket.PutInt(column, value.GetInt(column));
        }
    }
}

void AccessTokenDbUtil::ToRdbValueBuckets(const std::vector<GenericValues>& values,
    std::vector<NativeRdb::ValuesBucket>& buckets)
{
    for (const auto& value : values) {
        NativeRdb::ValuesBucket bucket;

        ToRdbValueBucket(value, bucket);
        if (bucket.IsEmpty()) {
            continue;
        }
        buckets.emplace_back(bucket);
    }
}

void AccessTokenDbUtil::ToRdbPredicates(const GenericValues& conditionValue, NativeRdb::RdbPredicates& predicates)
{
    std::vector<std::string> columnNames = conditionValue.GetAllKeys();
    uint32_t size = columnNames.size(); // size 0 is possible, maybe delete or query or update all records
    for (uint32_t i = 0; i < size; ++i) {
        std::string column = columnNames[i];

        if (IsColumnStringType(column)) {
            predicates.EqualTo(column, conditionValue.GetString(column));
        } else {
            predicates.EqualTo(column, conditionValue.GetInt(column));
        }

        if (i != size - 1) {
            predicates.And();
        }
    }
}

void AccessTokenDbUtil::ToRdbPredicatesByConditions(const std::vector<GenericValues>& conditionValues,
    NativeRdb::RdbPredicates& predicates)
{
    for (uint32_t i = 0; i < conditionValues.size(); ++i) {
        predicates.BeginWrap();
        ToRdbPredicates(conditionValues[i], predicates);
        predicates.EndWrap();
        if (i != conditionValues.size() - 1) {
            predicates.Or();
        }
    }
}

void AccessTokenDbUtil::ToRdbPredicatesByConditionItems(const std::vector<DbQueryCondition>& conditionItems,
    NativeRdb::RdbPredicates& predicates)
{
    bool hasAddedCondition = false;
    for (const auto& condition : conditionItems) {
        if (condition.values.empty()) {
            continue;
        }
        if (hasAddedCondition) {
            predicates.And();
        }

        if (IsColumnStringType(condition.column)) {
            AddStringInPredicate(condition, predicates);
        } else {
            AddNumericInPredicate(condition, predicates);
        }
        hasAddedCondition = true;
    }
}

void AccessTokenDbUtil::ResultToGenericValues(const std::shared_ptr<NativeRdb::ResultSet>& resultSet,
    GenericValues& value)
{
    if (resultSet == nullptr) {
        return;
    }
    std::vector<std::string> columnNames;
    resultSet->GetAllColumnNames(columnNames);
    uint32_t size = columnNames.size(); // size 0 means insert or update nonthing, this should ignore
    
    for (uint32_t i = 0; i < size; ++i) {
        std::string columnName = columnNames[i];
        int32_t columnIndex = 0;
        resultSet->GetColumnIndex(columnName, columnIndex);

        NativeRdb::ColumnType type;
        resultSet->GetColumnType(columnIndex, type);

        if (type == NativeRdb::ColumnType::TYPE_INTEGER) {
            if (columnName == TokenFiledConst::FIELD_TIMESTAMP) {
                int64_t data = 0;
                resultSet->GetLong(columnIndex, data);
                value.Put(columnName, data);
            } else {
                int32_t data = 0;
                resultSet->GetInt(columnIndex, data);
                value.Put(columnName, data);
            }
        } else if (type == NativeRdb::ColumnType::TYPE_STRING) {
            std::string data;
            resultSet->GetString(columnIndex, data);
            value.Put(columnName, data);
        }
    }
}
} // namespace AccessToken
} // namespace Security
} // namespace OHOS
