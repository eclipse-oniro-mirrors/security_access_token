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

#ifndef ACCESS_TOKEN_DB_H
#define ACCESS_TOKEN_DB_H

#include <vector>

#include "access_token.h"

#include "access_token_db_util.h"
#include "generic_values.h"
#include "nocopyable.h"
#include "rdb_predicates.h"
#include "rdb_store.h"
#include "rwlock.h"

namespace OHOS {
namespace Security {
namespace AccessToken {
class AccessTokenDb final {
public:
    static AccessTokenDb& GetInstance();
    virtual ~AccessTokenDb() = default;

    int32_t Add(const AtmDataType type, const std::vector<GenericValues>& values);
    int32_t Remove(const AtmDataType type, const GenericValues& conditionValue);
    int32_t Modify(const AtmDataType type, const GenericValues& modifyValue, const GenericValues& conditionValue);
    int32_t Find(AtmDataType type, const GenericValues& conditionValue, std::vector<GenericValues>& results);
    int32_t DeleteAndInsertHap(AccessTokenID tokenId, const std::vector<GenericValues>& hapInfoValues,
        const std::vector<GenericValues>& permDefValues, const std::vector<GenericValues>& permStateValues);

private:
    AccessTokenDb();
    DISALLOW_COPY_AND_MOVE(AccessTokenDb);

    int32_t RestoreAndInsertIfCorrupt(const int32_t resultCode, int64_t& outInsertNum,
        const std::string& tableName, const std::vector<NativeRdb::ValuesBucket>& buckets);
    int32_t RestoreAndDeleteIfCorrupt(const int32_t resultCode, int32_t& deletedRows,
        const NativeRdb::RdbPredicates& predicates);
    int32_t RestoreAndUpdateIfCorrupt(const int32_t resultCode, int32_t& changedRows,
        const NativeRdb::ValuesBucket& bucket, const NativeRdb::RdbPredicates& predicates);
    int32_t RestoreAndQueryIfCorrupt(const NativeRdb::RdbPredicates& predicates,
        const std::vector<std::string>& columns, std::shared_ptr<NativeRdb::AbsSharedResultSet>& queryResultSet);
    int32_t DeleteAndAddSingleTable(const GenericValues delCondition, const std::string& tableName,
        const std::vector<GenericValues>& addValues);
    int32_t DeleteAndAddRecord(AccessTokenID tokenId, const std::vector<GenericValues>& hapInfoValues,
        const std::vector<GenericValues>& permDefValues, const std::vector<GenericValues>& permStateValues);

    OHOS::Utils::RWLock rwLock_;
    std::shared_ptr<NativeRdb::RdbStore> db_ = nullptr;
};
} // namespace AccessToken
} // namespace Security
} // namespace OHOS

#endif // ACCESS_TOKEN_DB_H
