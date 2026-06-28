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

#ifndef ACCESS_TOKEN_MOCK_ACCESS_TOKEN_DB_OPERATOR_H
#define ACCESS_TOKEN_MOCK_ACCESS_TOKEN_DB_OPERATOR_H

#include <map>
#include <string>
#include <vector>

#include "access_token_db_operator.h"

namespace OHOS {
namespace Security {
namespace AccessToken {

struct MockDbFindResult final {
    int32_t ret = RET_SUCCESS;
    std::vector<GenericValues> values;
};

struct MockDbState final {
    std::map<AtmDataType, MockDbFindResult> findResults;
    int32_t modifyRet = RET_SUCCESS;
    int32_t deleteAndInsertRet = RET_SUCCESS;
    std::vector<DelInfo> lastDeleteInfos;
    std::vector<AddInfo> lastAddInfos;
    uint32_t findCallCount = 0;
    uint32_t modifyCallCount = 0;
    uint32_t deleteAndInsertCallCount = 0;
};

MockDbState& GetMockDbState();
void ResetMockDbState();
void SetMockDbFindResult(AtmDataType type, int32_t ret, const std::vector<GenericValues>& values);

} // namespace AccessToken
} // namespace Security
} // namespace OHOS

#endif // ACCESS_TOKEN_MOCK_ACCESS_TOKEN_DB_OPERATOR_H
