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
#include <map>

#include "access_token.h"
#include "generic_values.h"
#include "nocopyable.h"
#include "rwlock.h"
#include "sqlite_helper.h"
#include "token_field_const.h"

namespace OHOS {
namespace Security {
namespace AccessToken {
class AccessTokenDb : public SqliteHelper {
public:
    enum ExecuteResult { FAILURE = -1, SUCCESS };
    struct SqliteTable {
    public:
        std::string tableName_;
        std::vector<std::string> tableColumnNames_;
    };
    enum DataType {
        ACCESSTOKEN_HAP_INFO,
        ACCESSTOKEN_NATIVE_INFO,
        ACCESSTOKEN_PERMISSION_DEF,
        ACCESSTOKEN_PERMISSION_STATE,
        ACCESSTOKEN_PERMISSION_REQUEST_TOGGLE_STATUS,
    };

    static AccessTokenDb& GetInstance();

    ~AccessTokenDb() override;

    int Add(const DataType type, const std::vector<GenericValues>& values);

    int Remove(const DataType type, const GenericValues& conditions);

    int Modify(const DataType type, const GenericValues& modifyValues, const GenericValues& conditions);

    int Find(const DataType type, std::vector<GenericValues>& results);

    int RefreshAll(const DataType type, const std::vector<GenericValues>& values);

    void OnCreate() override;
    void OnUpdate(int32_t version) override;

private:
    int CreateHapTokenInfoTable() const;
    int CreateNativeTokenInfoTable() const;
    int CreatePermissionDefinitionTable() const;
    int CreatePermissionStateTable() const;
    int32_t CreatePermissionRequestToggleStatusTable() const;

    std::string CreateInsertPrepareSqlCmd(const DataType type) const;
    std::string CreateDeletePrepareSqlCmd(
        const DataType type, const std::vector<std::string>& columnNames = std::vector<std::string>()) const;
    std::string CreateUpdatePrepareSqlCmd(const DataType type, const std::vector<std::string>& modifyColumns,
        const std::vector<std::string>& conditionColumns) const;
    std::string CreateSelectPrepareSqlCmd(const DataType type) const;
    int32_t AddAvailableTypeColumn() const;
    int32_t AddPermDialogCapColumn() const;

    AccessTokenDb();
    DISALLOW_COPY_AND_MOVE(AccessTokenDb);

    std::map<DataType, SqliteTable> dataTypeToSqlTable_;
    OHOS::Utils::RWLock rwLock_;
    inline static const std::string HAP_TOKEN_INFO_TABLE = "hap_token_info_table";
    inline static const std::string NATIVE_TOKEN_INFO_TABLE = "native_token_info_table";
    inline static const std::string PERMISSION_DEF_TABLE = "permission_definition_table";
    inline static const std::string PERMISSION_STATE_TABLE = "permission_state_table";
    inline static const std::string PERMISSION_REQUEST_TOGGLE_STATUS_TABLE = "permission_request_toggle_status_table";
    inline static const std::string DATABASE_NAME = "access_token.db";
    inline static const std::string DATABASE_PATH = "/data/service/el1/public/access_token/";
    static const int DATABASE_VERSION = 3;
};
} // namespace AccessToken
} // namespace Security
} // namespace OHOS

#endif // ACCESS_TOKEN_DB_H
