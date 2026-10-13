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

#include "mock_access_token_db_operator.h"

#include "token_field_const.h"

namespace OHOS {
namespace Security {
namespace AccessToken {

namespace {
MockDbState g_mockDbState;
}

MockDbState& GetMockDbState()
{
    return g_mockDbState;
}

void ResetMockDbState()
{
    g_mockDbState = MockDbState {};
}

void SetMockDbFindResult(AtmDataType type, int32_t ret, const std::vector<GenericValues>& values)
{
    g_mockDbState.findResults[type] = MockDbFindResult { ret, values };
}

int32_t AccessTokenDbOperator::Modify(const AtmDataType type, const GenericValues& modifyValue,
    const GenericValues& conditionValue)
{
    (void)type;
    (void)modifyValue;
    (void)conditionValue;
    ++g_mockDbState.modifyCallCount;
    return g_mockDbState.modifyRet;
}

namespace {
// Fields stored as integers in the token table rows; everything else compares
// as a string. Only the fields the delete chain filters on are classified.
bool IsIntField(const std::string& key)
{
    return (key == TokenFiledConst::FIELD_TOKEN_ID) || (key == TokenFiledConst::FIELD_USER_ID) ||
        (key == TokenFiledConst::FIELD_INST_INDEX) || (key == TokenFiledConst::FIELD_UID) ||
        (key == TokenFiledConst::FIELD_RESERVED);
}

bool RowMatches(const GenericValues& row, const GenericValues& condition)
{
    for (const auto& key : condition.GetAllKeys()) {
        if (IsIntField(key)) {
            if (row.GetInt(key) != condition.GetInt(key)) {
                return false;
            }
        } else if (row.GetString(key) != condition.GetString(key)) {
            return false;
        }
    }
    return true;
}
} // namespace

int32_t AccessTokenDbOperator::Find(AtmDataType type, const GenericValues& conditionValue,
    std::vector<GenericValues>& results)
{
    ++g_mockDbState.findCallCount;
    auto iter = g_mockDbState.findResults.find(type);
    if (iter == g_mockDbState.findResults.end()) {
        results.clear();
        return RET_SUCCESS;
    }
    results = iter->second.values;
    // Faithful condition filtering: keep only rows matching every key the
    // caller put into the condition, mirroring the real column WHERE clause.
    if (!conditionValue.GetAllKeys().empty()) {
        std::vector<GenericValues> filtered;
        for (const auto& row : results) {
            if (RowMatches(row, conditionValue)) {
                filtered.push_back(row);
            }
        }
        results = filtered;
    }
    return iter->second.ret;
}

int32_t AccessTokenDbOperator::Find(AtmDataType type, const std::string& column,
    const std::vector<VariantValue>& values, std::vector<GenericValues>& results)
{
    (void)column;
    (void)values;
    return Find(type, GenericValues(), results);
}

int32_t AccessTokenDbOperator::DeleteAndInsertValues(const std::vector<DelInfo>& delInfoVec,
    const std::vector<AddInfo>& addInfoVec)
{
    ++g_mockDbState.deleteAndInsertCallCount;
    g_mockDbState.lastDeleteInfos = delInfoVec;
    g_mockDbState.lastAddInfos = addInfoVec;
    return g_mockDbState.deleteAndInsertRet;
}

} // namespace AccessToken
} // namespace Security
} // namespace OHOS
