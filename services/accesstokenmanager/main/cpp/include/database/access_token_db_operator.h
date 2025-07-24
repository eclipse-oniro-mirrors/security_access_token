/*
 * Copyright (c) 2025 Huawei Device Co., Ltd.
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

#ifndef ACCESS_TOKEN_DB_OPERATOR_H
#define ACCESS_TOKEN_DB_OPERATOR_H

#include <vector>

#include "atm_data_type.h"
#include "generic_values.h"

namespace OHOS {
namespace Security {
namespace AccessToken {
static constexpr const char* PERM_DEF_VERSION = "permission_definition_version";

class AccessTokenDbOperator {
public:
    static int32_t Modify(const AtmDataType type, const GenericValues& modifyValue,
        const GenericValues& conditionValue);
    static int32_t Find(AtmDataType type, const GenericValues& conditionValue,
        std::vector<GenericValues>& results);
    static int32_t DeleteAndInsertValues(const std::vector<DelInfo>& delInfoVec,
        const std::vector<AddInfo>& addInfoVec);
};
} // namespace AccessToken
} // namespace Security
} // namespace OHOS
#endif // ACCESS_TOKEN_DB_OPERATOR_H
