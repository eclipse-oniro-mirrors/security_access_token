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
    return RET_SUCCESS;
}

int32_t AccessTokenDbOperator::Modify(const AtmDataType type,
    const std::vector<GenericValues>& modifyValues,
    const std::vector<GenericValues>& conditions)
{
    (void)type;
    (void)modifyValues;
    (void)conditions;
    return RET_SUCCESS;
}

int32_t AccessTokenDbOperator::Find(AtmDataType type, const GenericValues& conditionValue,
    std::vector<GenericValues>& results)
{
    (void)conditionValue;
    ++g_mockDbState.findCallCount;
    auto iter = g_mockDbState.findResults.find(type);
    if (iter == g_mockDbState.findResults.end()) {
        results.clear();
        return RET_SUCCESS;
    }
    results = iter->second.values;
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
