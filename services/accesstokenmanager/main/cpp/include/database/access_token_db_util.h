/*
 * Copyright (c) 2024-2025 Huawei Device Co., Ltd.
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

#ifndef SECURITY_ACCESS_TOKEN_DB_UTIL_H
#define SECURITY_ACCESS_TOKEN_DB_UTIL_H

#include <string>
#include <vector>

#include "access_token.h"
#include "atm_data_type.h"
#include "generic_values.h"
#include "rdb_predicates.h"
#include "result_set.h"
#include "values_bucket.h"

namespace OHOS {
namespace Security {
namespace AccessToken {
class AccessTokenDbUtil final {
public:
    static void GetTableNameByType(const AtmDataType type, std::string& tableName);
    static bool IsColumnStringType(const std::string& column);
    static void ToRdbValueBucket(const GenericValues& value, NativeRdb::ValuesBucket& bucket);
    static void ToRdbValueBuckets(const std::vector<GenericValues>& values,
        std::vector<NativeRdb::ValuesBucket>& buckets);
    static void ToRdbPredicates(const GenericValues& conditionValue, NativeRdb::RdbPredicates& predicates);
    static void ResultToGenericValues(const std::shared_ptr<NativeRdb::ResultSet>& resultSet, GenericValues& value);
};
} // namespace AccessToken
} // namespace Security
} // namespace OHOS

#endif // SECURITY_ACCESS_TOKEN_DB_UTIL_H
