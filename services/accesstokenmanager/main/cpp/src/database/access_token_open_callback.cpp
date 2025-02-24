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

#include "access_token_open_callback.h"

#include "access_token_error.h"
#include "access_token.h"
#include "accesstoken_common_log.h"
#include "token_field_const.h"

namespace OHOS {
namespace Security {
namespace AccessToken {
namespace {
constexpr const char*  INTEGER_STR = " integer not null,";
constexpr const char*  TEXT_STR = " text not null,";
// back up name is xxx_slave fixed, can not be changed
constexpr const char* DATABASE_NAME_BACK = "access_token_slave.db";

constexpr const uint32_t FLAG_HANDLE_FROM_ONE_TO_TWO = 1;
constexpr const uint32_t FLAG_HANDLE_FROM_TWO_TO_THREE = 1 << 1;
constexpr const uint32_t FLAG_HANDLE_FROM_THREE_TO_FOUR = 1 << 2;
constexpr const uint32_t FLAG_HANDLE_FROM_FOUR_TO_FIVE = 1 << 3;
}

int32_t AccessTokenOpenCallback::CreateHapTokenInfoTable(NativeRdb::RdbStore& rdbStore)
{
    std::string tableName;
    AccessTokenDbUtil::GetTableNameByType(AtmDataType::ACCESSTOKEN_HAP_INFO, tableName);

    std::string sql = "create table if not exists " + tableName;
    sql.append(" (")
        .append(TokenFiledConst::FIELD_TOKEN_ID)
        .append(INTEGER_STR)
        .append(TokenFiledConst::FIELD_USER_ID)
        .append(INTEGER_STR)
        .append(TokenFiledConst::FIELD_BUNDLE_NAME)
        .append(TEXT_STR)
        .append(TokenFiledConst::FIELD_INST_INDEX)
        .append(INTEGER_STR)
        .append(TokenFiledConst::FIELD_DLP_TYPE)
        .append(INTEGER_STR)
        .append(TokenFiledConst::FIELD_APP_ID)
        .append(TEXT_STR)
        .append(TokenFiledConst::FIELD_DEVICE_ID)
        .append(TEXT_STR)
        .append(TokenFiledConst::FIELD_APL)
        .append(INTEGER_STR)
        .append(TokenFiledConst::FIELD_TOKEN_VERSION)
        .append(INTEGER_STR)
        .append(TokenFiledConst::FIELD_TOKEN_ATTR)
        .append(INTEGER_STR)
        .append(TokenFiledConst::FIELD_API_VERSION)
        .append(INTEGER_STR)
        .append(TokenFiledConst::FIELD_FORBID_PERM_DIALOG)
        .append(INTEGER_STR)
        .append("primary key(")
        .append(TokenFiledConst::FIELD_TOKEN_ID)
        .append("))");

    return rdbStore.ExecuteSql(sql);
}

int32_t AccessTokenOpenCallback::CreatePermissionDefinitionTable(NativeRdb::RdbStore& rdbStore)
{
    std::string tableName;
    AccessTokenDbUtil::GetTableNameByType(AtmDataType::ACCESSTOKEN_PERMISSION_DEF, tableName);

    std::string sql = "create table if not exists " + tableName;
    sql.append(" (")
        .append(TokenFiledConst::FIELD_TOKEN_ID)
        .append(INTEGER_STR)
        .append(TokenFiledConst::FIELD_PERMISSION_NAME)
        .append(TEXT_STR)
        .append(TokenFiledConst::FIELD_BUNDLE_NAME)
        .append(TEXT_STR)
        .append(TokenFiledConst::FIELD_GRANT_MODE)
        .append(INTEGER_STR)
        .append(TokenFiledConst::FIELD_AVAILABLE_LEVEL)
        .append(INTEGER_STR)
        .append(TokenFiledConst::FIELD_PROVISION_ENABLE)
        .append(INTEGER_STR)
        .append(TokenFiledConst::FIELD_DISTRIBUTED_SCENE_ENABLE)
        .append(INTEGER_STR)
        .append(TokenFiledConst::FIELD_LABEL)
        .append(TEXT_STR)
        .append(TokenFiledConst::FIELD_LABEL_ID)
        .append(INTEGER_STR)
        .append(TokenFiledConst::FIELD_DESCRIPTION)
        .append(TEXT_STR)
        .append(TokenFiledConst::FIELD_DESCRIPTION_ID)
        .append(INTEGER_STR)
        .append(TokenFiledConst::FIELD_AVAILABLE_TYPE)
        .append(INTEGER_STR)
        .append(TokenFiledConst::FIELD_KERNEL_EFFECT)
        .append(" integer, ")
        .append(TokenFiledConst::FIELD_HAS_VALUE)
        .append(" integer, ")
        .append("primary key(")
        .append(TokenFiledConst::FIELD_TOKEN_ID)
        .append(",")
        .append(TokenFiledConst::FIELD_PERMISSION_NAME)
        .append("))");

    return rdbStore.ExecuteSql(sql);
}

int32_t AccessTokenOpenCallback::CreatePermissionStateTable(NativeRdb::RdbStore& rdbStore)
{
    std::string tableName;
    AccessTokenDbUtil::GetTableNameByType(AtmDataType::ACCESSTOKEN_PERMISSION_STATE, tableName);

    std::string sql = "create table if not exists " + tableName;
    sql.append(" (")
        .append(TokenFiledConst::FIELD_TOKEN_ID)
        .append(INTEGER_STR)
        .append(TokenFiledConst::FIELD_PERMISSION_NAME)
        .append(TEXT_STR)
        .append(TokenFiledConst::FIELD_DEVICE_ID)
        .append(TEXT_STR)
        .append(TokenFiledConst::FIELD_GRANT_STATE)
        .append(INTEGER_STR)
        .append(TokenFiledConst::FIELD_GRANT_FLAG)
        .append(INTEGER_STR)
        .append("primary key(")
        .append(TokenFiledConst::FIELD_TOKEN_ID)
        .append(",")
        .append(TokenFiledConst::FIELD_PERMISSION_NAME)
        .append(",")
        .append(TokenFiledConst::FIELD_DEVICE_ID)
        .append("))");

    return rdbStore.ExecuteSql(sql);
}

int32_t AccessTokenOpenCallback::CreatePermissionRequestToggleStatusTable(NativeRdb::RdbStore& rdbStore)
{
    std::string tableName;
    AccessTokenDbUtil::GetTableNameByType(AtmDataType::ACCESSTOKEN_PERMISSION_REQUEST_TOGGLE_STATUS, tableName);

    std::string sql = "create table if not exists " + tableName;
    sql.append(" (")
        .append(TokenFiledConst::FIELD_USER_ID)
        .append(INTEGER_STR)
        .append(TokenFiledConst::FIELD_PERMISSION_NAME)
        .append(TEXT_STR)
        .append(TokenFiledConst::FIELD_REQUEST_TOGGLE_STATUS)
        .append(INTEGER_STR)
        .append("primary key(")
        .append(TokenFiledConst::FIELD_USER_ID)
        .append(",")
        .append(TokenFiledConst::FIELD_PERMISSION_NAME)
        .append("))");

    return rdbStore.ExecuteSql(sql);
}

int32_t AccessTokenOpenCallback::CreatePermissionExtendValueTable(NativeRdb::RdbStore& rdbStore)
{
    std::string tableName;
    AccessTokenDbUtil::GetTableNameByType(AtmDataType::ACCESSTOKEN_PERMISSION_EXTEND_VALUE, tableName);

    std::string sql = "create table if not exists " + tableName;
    sql.append(" (")
        .append(TokenFiledConst::FIELD_TOKEN_ID)
        .append(INTEGER_STR)
        .append(TokenFiledConst::FIELD_PERMISSION_NAME)
        .append(TEXT_STR)
        .append(TokenFiledConst::FIELD_VALUE)
        .append(TEXT_STR)
        .append("primary key(")
        .append(TokenFiledConst::FIELD_TOKEN_ID)
        .append(",")
        .append(TokenFiledConst::FIELD_PERMISSION_NAME)
        .append(",")
        .append(TokenFiledConst::FIELD_VALUE)
        .append("))");

    return rdbStore.ExecuteSql(sql);
}

int32_t AccessTokenOpenCallback::OnCreate(NativeRdb::RdbStore& rdbStore)
{
    LOGI(ATM_DOMAIN, ATM_TAG, "DB OnCreate.");

    int32_t res = CreateHapTokenInfoTable(rdbStore);
    if (res != NativeRdb::E_OK) {
        LOGE(ATM_DOMAIN, ATM_TAG, "Failed to create table hap_token_info_table.");
        return res;
    }

    res = CreatePermissionDefinitionTable(rdbStore);
    if (res != NativeRdb::E_OK) {
        LOGE(ATM_DOMAIN, ATM_TAG, "Failed to create table permission_definition_table.");
        return res;
    }
    
    res = CreatePermissionStateTable(rdbStore);
    if (res != NativeRdb::E_OK) {
        LOGE(ATM_DOMAIN, ATM_TAG, "Failed to create table permission_state_table.");
        return res;
    }
    
    res = CreatePermissionRequestToggleStatusTable(rdbStore);
    if (res != NativeRdb::E_OK) {
        LOGE(ATM_DOMAIN, ATM_TAG, "Failed to create table permission_request_toggle_status_table.");
        return res;
    }

    res = CreatePermissionExtendValueTable(rdbStore);
    if (res != NativeRdb::E_OK) {
        LOGE(ATM_DOMAIN, ATM_TAG, "Failed to create table permission_extend_value_table.");
        return res;
    }

    std::string dbBackPath = std::string(DATABASE_PATH) + std::string(DATABASE_NAME_BACK);
    if (access(dbBackPath.c_str(), NativeRdb::E_OK) != 0) {
        return 0;
    }

    // if OnCreate solution found back up db, restore from backup, may be origin db has lost
    LOGW(ATM_DOMAIN, ATM_TAG, "Detech origin database disappear, restore from backup!");

    res = rdbStore.Restore("");
    if (res != NativeRdb::E_OK) {
        LOGE(ATM_DOMAIN, ATM_TAG, "Db restore failed, res is %{public}d.", res);
    }

    LOGW(ATM_DOMAIN, ATM_TAG, "Database restore from backup success!");

    return 0;
}

int32_t AccessTokenOpenCallback::AddAvailableTypeColumn(NativeRdb::RdbStore& rdbStore)
{
    std::string tableName;
    AccessTokenDbUtil::GetTableNameByType(AtmDataType::ACCESSTOKEN_PERMISSION_DEF, tableName);

    // check if column available_type exsit
    std::string checkSql = "SELECT 1 FROM " + tableName + " WHERE " +
        TokenFiledConst::FIELD_AVAILABLE_TYPE + "=" + std::to_string(ATokenAvailableTypeEnum::NORMAL);

    int32_t checkRes = rdbStore.ExecuteSql(checkSql);
    LOGI(ATM_DOMAIN, ATM_TAG, "Check result is %{public}d.", checkRes);
    if (checkRes == NativeRdb::E_OK) {
        // success means there exsit column available_type in table
        return NativeRdb::E_OK;
    }

    // alter table add column
    std::string sql = "alter table " + tableName + " add column " +
        TokenFiledConst::FIELD_AVAILABLE_TYPE + " integer default " + std::to_string(ATokenAvailableTypeEnum::NORMAL);

    int32_t res = rdbStore.ExecuteSql(sql);
    LOGI(ATM_DOMAIN, ATM_TAG, "Insert column result is %{public}d.", res);

    return res;
}

int32_t AccessTokenOpenCallback::AddRequestToggleStatusColumn(NativeRdb::RdbStore& rdbStore)
{
    std::string tableName;
    AccessTokenDbUtil::GetTableNameByType(AtmDataType::ACCESSTOKEN_PERMISSION_REQUEST_TOGGLE_STATUS, tableName);

    // check if column status exsit
    std::string checkSql = "SELECT 1 FROM " + tableName + " WHERE " +
        TokenFiledConst::FIELD_REQUEST_TOGGLE_STATUS + "=" + std::to_string(0);

    int32_t checkRes = rdbStore.ExecuteSql(checkSql);
    LOGI(ATM_DOMAIN, ATM_TAG, "Check result is %{public}d.", checkRes);
    if (checkRes == NativeRdb::E_OK) {
        // success means there exsit column status in table
        return NativeRdb::E_OK;
    }

    // alter table add column
    std::string sql = "alter table " + tableName + " add column " +
        TokenFiledConst::FIELD_REQUEST_TOGGLE_STATUS + " integer default " + std::to_string(0); // 0: close

    int32_t res = rdbStore.ExecuteSql(sql);
    LOGI(ATM_DOMAIN, ATM_TAG, "Insert column result is %{public}d.", res);

    return res;
}

int32_t AccessTokenOpenCallback::AddPermDialogCapColumn(NativeRdb::RdbStore& rdbStore)
{
    std::string tableName;
    AccessTokenDbUtil::GetTableNameByType(AtmDataType::ACCESSTOKEN_HAP_INFO, tableName);

    // check if column perm_dialog_cap_state exsit
    std::string checkSql = "SELECT 1 FROM " + tableName + " WHERE " +
        TokenFiledConst::FIELD_FORBID_PERM_DIALOG + "=" + std::to_string(0);

    int32_t checkRes = rdbStore.ExecuteSql(checkSql);
    LOGI(ATM_DOMAIN, ATM_TAG, "Check result is %{public}d.", checkRes);
    if (checkRes == NativeRdb::E_OK) {
        // success means there exsit column perm_dialog_cap_state in table
        return NativeRdb::E_OK;
    }

    // alter table add column
    std::string sql = "alter table " + tableName + " add column " +
        TokenFiledConst::FIELD_FORBID_PERM_DIALOG + " integer default " + std::to_string(false);

    int32_t res = rdbStore.ExecuteSql(sql);
    LOGI(ATM_DOMAIN, ATM_TAG, "Insert column result is %{public}d.", res);

    return res;
}

static void CreateNewPermissionStateTable(std::string& newTableName, std::string& newCreateSql)
{
    newCreateSql = "create table if not exists " + newTableName;
    newCreateSql.append(" (")
        .append(TokenFiledConst::FIELD_TOKEN_ID)
        .append(INTEGER_STR)
        .append(TokenFiledConst::FIELD_PERMISSION_NAME)
        .append(TEXT_STR)
        .append(TokenFiledConst::FIELD_DEVICE_ID)
        .append(TEXT_STR)
        .append(TokenFiledConst::FIELD_GRANT_STATE)
        .append(INTEGER_STR)
        .append(TokenFiledConst::FIELD_GRANT_FLAG)
        .append(INTEGER_STR)
        .append("primary key(")
        .append(TokenFiledConst::FIELD_TOKEN_ID)
        .append(",")
        .append(TokenFiledConst::FIELD_PERMISSION_NAME)
        .append(",")
        .append(TokenFiledConst::FIELD_DEVICE_ID)
        .append("))");
}

int32_t AccessTokenOpenCallback::RemoveIsGeneralFromPermissionState(NativeRdb::RdbStore& rdbStore)
{
    std::string tableName = "permission_state_table";
    AccessTokenDbUtil::GetTableNameByType(AtmDataType::ACCESSTOKEN_PERMISSION_STATE, tableName);
    std::string newTableName = tableName + "_new";
    std::string newCreateSql;

    CreateNewPermissionStateTable(newTableName, newCreateSql);

    // 1. create new permission_state_table without column is_general
    int32_t res = rdbStore.ExecuteSql(newCreateSql);
    if (res != NativeRdb::E_OK) {
        LOGE(ATM_DOMAIN, ATM_TAG, "Failed to create table %{public}s, errCode is %{public}d.",
            newCreateSql.c_str(), res);
        return res;
    }

    // 2. copy data from permission_state_table to permission_state_table_new
    std::string copyDataSql = "insert into " + newTableName + " select ";
    copyDataSql.append(TokenFiledConst::FIELD_TOKEN_ID + ", ");
    copyDataSql.append(TokenFiledConst::FIELD_PERMISSION_NAME + ", ");
    copyDataSql.append(TokenFiledConst::FIELD_DEVICE_ID + ", ");
    copyDataSql.append(TokenFiledConst::FIELD_GRANT_STATE + ", ");
    copyDataSql.append(TokenFiledConst::FIELD_GRANT_FLAG + " from " + tableName);
    res = rdbStore.ExecuteSql(copyDataSql);
    if (res != NativeRdb::E_OK) {
        LOGE(ATM_DOMAIN, ATM_TAG, "Failed to copy data from old table to new, errCode is %{public}d.", res);
        return res;
    }

    // 3. drop permission_state_table
    std::string dropOldSql = "drop table " + tableName;
    res = rdbStore.ExecuteSql(dropOldSql);
    if (res != NativeRdb::E_OK) {
        LOGE(ATM_DOMAIN, ATM_TAG, "Failed to drop table %{public}s, errCode is %{public}d.", tableName.c_str(), res);
        return res;
    }

    // 4. rename permission_state_table_new to permission_state_table
    std::string renameSql = "alter table " + newTableName + " rename to " + tableName;
    res = rdbStore.ExecuteSql(renameSql);
    if (res != NativeRdb::E_OK) {
        LOGE(ATM_DOMAIN, ATM_TAG, "Failed to rename new table to old, errCode is %{public}d.", res);
        return res;
    }

    return NativeRdb::E_OK;
}

// remove is_general from permission_state_table and remove native_token_info_table
int32_t AccessTokenOpenCallback::RemoveUnusedTableAndColumn(NativeRdb::RdbStore& rdbStore)
{
    rdbStore.BeginTransaction();

    int32_t res = RemoveIsGeneralFromPermissionState(rdbStore);
    if (res != NativeRdb::E_OK) {
        rdbStore.RollBack();
        return res;
    }

    // drop native_token_info_table
    std::string dropOldSql = "drop table native_token_info_table";
    res = rdbStore.ExecuteSql(dropOldSql);
    if (res != NativeRdb::E_OK) {
        LOGE(ATM_DOMAIN, ATM_TAG, "Failed to drop native_token_info_table, errCode is %{public}d.", res);
        rdbStore.RollBack();
        return res;
    }

    res = rdbStore.Commit();
    if (res != NativeRdb::E_OK) {
        LOGE(ATM_DOMAIN, ATM_TAG, "Failed to commit, errCode is %{public}d.", res);
        if (res != NativeRdb::E_SQLITE_CORRUPT) {
            return res;
        }

        LOGW(ATM_DOMAIN, ATM_TAG, "Detech database corrupt, restore from backup!");
        int32_t res = rdbStore.Restore("");
        if (res != NativeRdb::E_OK) {
            LOGE(ATM_DOMAIN, ATM_TAG, "Db restore failed, res is %{public}d.", res);
            return res;
        }

        res = rdbStore.Commit();
        if (res != NativeRdb::E_OK) {
            LOGE(ATM_DOMAIN, ATM_TAG, "Failed to commit again, res is %{public}d.", res);
            return res;
        }
    }

    return NativeRdb::E_OK;
}

int32_t AccessTokenOpenCallback::AddKernelEffectAndHasValueColumn(NativeRdb::RdbStore& rdbStore)
{
    std::string tableName;
    AccessTokenDbUtil::GetTableNameByType(AtmDataType::ACCESSTOKEN_PERMISSION_DEF, tableName);

    // check if column kernel_effect exsit
    std::string checkSql = "SELECT 1 FROM " + tableName + " WHERE " + TokenFiledConst::FIELD_KERNEL_EFFECT + "=" +
        std::to_string(0);

    int32_t checkRes = rdbStore.ExecuteSql(checkSql);
    if (checkRes == NativeRdb::E_OK) {
        return NativeRdb::E_OK; // success means there exsit column kernel_effect in table
    }

    // alter table add column kernel_effect
    std::string executeSql = "alter table " + tableName + " add column " + TokenFiledConst::FIELD_KERNEL_EFFECT +
        " integer default " + std::to_string(false);

    int32_t executeRes = rdbStore.ExecuteSql(executeSql);
    if (executeRes != NativeRdb::E_OK) {
        LOGE(ATM_DOMAIN, ATM_TAG, "Failed to add column kernel_effect to table %{public}s, errCode is %{public}d.",
            tableName.c_str(), executeRes);
        return executeRes;
    }

    LOGI(ATM_DOMAIN, ATM_TAG, "Success to add column kernel_effect to permission_definition_table.");

    // check if column has_value exsit
    checkSql = "SELECT 1 FROM " + tableName + " WHERE " + TokenFiledConst::FIELD_HAS_VALUE + "=" + std::to_string(0);

    checkRes = rdbStore.ExecuteSql(checkSql);
    if (checkRes == NativeRdb::E_OK) {
        return NativeRdb::E_OK; // success means there exsit column has_value in table
    }

    // alter table add column has_value
    executeSql = "alter table " + tableName + " add column " + TokenFiledConst::FIELD_HAS_VALUE +
        " integer default " + std::to_string(0);

    executeRes = rdbStore.ExecuteSql(executeSql);
    if (executeRes != NativeRdb::E_OK) {
        LOGE(ATM_DOMAIN, ATM_TAG, "Failed to add column has_value to table %{public}s, errCode is %{public}d.",
            tableName.c_str(), executeRes);
        return executeRes;
    }

    LOGI(ATM_DOMAIN, ATM_TAG, "Success to add column has_value to permission_definition_table.");

    return NativeRdb::E_OK;
}

int32_t AccessTokenOpenCallback::HandleUpdateWithFlag(NativeRdb::RdbStore& rdbStore, uint32_t flag)
{
    int32_t res = NativeRdb::E_OK;

    if ((flag & FLAG_HANDLE_FROM_ONE_TO_TWO) == FLAG_HANDLE_FROM_ONE_TO_TWO) {
        res = AddAvailableTypeColumn(rdbStore);
        if (res != NativeRdb::E_OK) {
            LOGE(ATM_DOMAIN, ATM_TAG, "Failed to add column available_type.");
            return res;
        }

        res = AddPermDialogCapColumn(rdbStore);
        if (res != NativeRdb::E_OK) {
            LOGE(ATM_DOMAIN, ATM_TAG, "Failed to add column perm_dialog_cap_state.");
            return res;
        }
    }

    if ((flag & FLAG_HANDLE_FROM_TWO_TO_THREE) == FLAG_HANDLE_FROM_TWO_TO_THREE) {
        res = CreatePermissionRequestToggleStatusTable(rdbStore);
        if (res != NativeRdb::E_OK) {
            LOGE(ATM_DOMAIN, ATM_TAG, "Failed to create table permission_request_toggle_status_table.");
            return res;
        }
    }

    if ((flag & FLAG_HANDLE_FROM_THREE_TO_FOUR) == FLAG_HANDLE_FROM_THREE_TO_FOUR) {
        res = AddRequestToggleStatusColumn(rdbStore);
        if (res != NativeRdb::E_OK) {
            LOGE(ATM_DOMAIN, ATM_TAG, "Failed to add column status.");
            return res;
        }
    }

    if ((flag & FLAG_HANDLE_FROM_FOUR_TO_FIVE) == FLAG_HANDLE_FROM_FOUR_TO_FIVE) {
        res = CreatePermissionExtendValueTable(rdbStore);
        if (res != NativeRdb::E_OK) {
            LOGE(ATM_DOMAIN, ATM_TAG, "Failed to create table permission_extend_bool_table.");
            return res;
        }

        res = RemoveUnusedTableAndColumn(rdbStore);
        if (res != NativeRdb::E_OK) {
            return res;
        }

        return AddKernelEffectAndHasValueColumn(rdbStore);
    }

    return res;
}

int32_t AccessTokenOpenCallback::UpdateFromVersionOne(NativeRdb::RdbStore& rdbStore, int32_t targetVersion)
{
    int32_t res = 0;
    uint32_t flag = 0;

    switch (targetVersion) {
        case DATABASE_VERSION_2:
            flag = FLAG_HANDLE_FROM_ONE_TO_TWO;
            res = HandleUpdateWithFlag(rdbStore, flag);
            if (res != NativeRdb::E_OK) {
                return res;
            }
            break;

        case DATABASE_VERSION_3:
            flag = FLAG_HANDLE_FROM_ONE_TO_TWO + FLAG_HANDLE_FROM_TWO_TO_THREE;
            res = HandleUpdateWithFlag(rdbStore, flag);
            if (res != NativeRdb::E_OK) {
                return res;
            }
            break;

        case DATABASE_VERSION_4:
            flag = FLAG_HANDLE_FROM_ONE_TO_TWO + FLAG_HANDLE_FROM_TWO_TO_THREE + FLAG_HANDLE_FROM_THREE_TO_FOUR;
            res = HandleUpdateWithFlag(rdbStore, flag);
            if (res != NativeRdb::E_OK) {
                return res;
            }
            break;

        case DATABASE_VERSION_5:
            flag = FLAG_HANDLE_FROM_ONE_TO_TWO + FLAG_HANDLE_FROM_TWO_TO_THREE + FLAG_HANDLE_FROM_THREE_TO_FOUR +
                FLAG_HANDLE_FROM_FOUR_TO_FIVE;
            res = HandleUpdateWithFlag(rdbStore, flag);
            if (res != NativeRdb::E_OK) {
                return res;
            }
            break;

        default:
            break;
    }

    return res;
}

int32_t AccessTokenOpenCallback::UpdateFromVersionTwo(NativeRdb::RdbStore& rdbStore, int32_t targetVersion)
{
    int32_t res = 0;
    uint32_t flag = 0;

    switch (targetVersion) {
        case DATABASE_VERSION_3:
            flag = FLAG_HANDLE_FROM_TWO_TO_THREE;
            res = HandleUpdateWithFlag(rdbStore, flag);
            if (res != NativeRdb::E_OK) {
                return res;
            }
            break;

        case DATABASE_VERSION_4:
            flag = FLAG_HANDLE_FROM_TWO_TO_THREE + FLAG_HANDLE_FROM_THREE_TO_FOUR;
            res = HandleUpdateWithFlag(rdbStore, flag);
            if (res != NativeRdb::E_OK) {
                return res;
            }
            break;

        case DATABASE_VERSION_5:
            flag = FLAG_HANDLE_FROM_TWO_TO_THREE + FLAG_HANDLE_FROM_THREE_TO_FOUR + FLAG_HANDLE_FROM_FOUR_TO_FIVE;
            res = HandleUpdateWithFlag(rdbStore, flag);
            if (res != NativeRdb::E_OK) {
                return res;
            }
            break;

        default:
            break;
    }

    return res;
}

int32_t AccessTokenOpenCallback::UpdateFromVersionThree(NativeRdb::RdbStore& rdbStore, int32_t targetVersion)
{
    int32_t res = 0;
    uint32_t flag = 0;

    switch (targetVersion) {
        case DATABASE_VERSION_4:
            flag = FLAG_HANDLE_FROM_THREE_TO_FOUR;
            res = HandleUpdateWithFlag(rdbStore, flag);
            if (res != NativeRdb::E_OK) {
                return res;
            }
            break;

        case DATABASE_VERSION_5:
            flag = FLAG_HANDLE_FROM_THREE_TO_FOUR + FLAG_HANDLE_FROM_FOUR_TO_FIVE;
            res = HandleUpdateWithFlag(rdbStore, flag);
            if (res != NativeRdb::E_OK) {
                return res;
            }
            break;

        default:
            break;
    }

    return res;
}

int32_t AccessTokenOpenCallback::UpdateFromVersionFour(NativeRdb::RdbStore& rdbStore, int32_t targetVersion)
{
    int32_t res = 0;
    uint32_t flag = 0;

    switch (targetVersion) {
        case DATABASE_VERSION_5:
            flag = FLAG_HANDLE_FROM_FOUR_TO_FIVE;
            res = HandleUpdateWithFlag(rdbStore, flag);
            if (res != NativeRdb::E_OK) {
                return res;
            }
            break;

        default:
            break;
    }

    return res;
}

int32_t AccessTokenOpenCallback::OnUpgrade(NativeRdb::RdbStore& rdbStore, int32_t currentVersion, int32_t targetVersion)
{
    LOGI(ATM_DOMAIN, ATM_TAG, "DB OnUpgrade from currentVersion %{public}d to targetVersion %{public}d.",
        currentVersion, targetVersion);

    int32_t res = 0;

    switch (currentVersion) {
        case DATABASE_VERSION_1:
            res = UpdateFromVersionOne(rdbStore, targetVersion);
            if (res != 0) {
                return res;
            }
            break;

        case DATABASE_VERSION_2:
            res = UpdateFromVersionTwo(rdbStore, targetVersion);
            if (res != 0) {
                return res;
            }
            break;

        case DATABASE_VERSION_3:
            res = UpdateFromVersionThree(rdbStore, targetVersion);
            if (res != 0) {
                return res;
            }
            break;

        case DATABASE_VERSION_4:
            res = UpdateFromVersionFour(rdbStore, targetVersion);
            if (res != 0) {
                return res;
            }
            break;

        default:
            break;
    }

    return res;
}
} // namespace AccessToken
} // namespace Security
} // namespace OHOS
