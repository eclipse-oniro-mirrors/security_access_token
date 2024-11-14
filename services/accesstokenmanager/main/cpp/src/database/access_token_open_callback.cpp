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
#include "accesstoken_log.h"
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

int32_t AccessTokenOpenCallback::CreateNativeTokenInfoTable(NativeRdb::RdbStore& rdbStore)
{
    std::string tableName;
    AccessTokenDbUtil::GetTableNameByType(AtmDataType::ACCESSTOKEN_NATIVE_INFO, tableName);

    std::string sql = "create table if not exists " + tableName;
    sql.append(" (")
        .append(TokenFiledConst::FIELD_TOKEN_ID)
        .append(INTEGER_STR)
        .append(TokenFiledConst::FIELD_PROCESS_NAME)
        .append(TEXT_STR)
        .append(TokenFiledConst::FIELD_TOKEN_VERSION)
        .append(INTEGER_STR)
        .append(TokenFiledConst::FIELD_TOKEN_ATTR)
        .append(INTEGER_STR)
        .append(TokenFiledConst::FIELD_DCAP)
        .append(TEXT_STR)
        .append(TokenFiledConst::FIELD_NATIVE_ACLS)
        .append(TEXT_STR)
        .append(TokenFiledConst::FIELD_APL)
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
        .append(TokenFiledConst::FIELD_GRANT_IS_GENERAL)
        .append(INTEGER_STR)
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

int32_t AccessTokenOpenCallback::OnCreate(NativeRdb::RdbStore& rdbStore)
{
    LOGI(AT_DOMAIN, AT_TAG, "DB OnCreate.");

    int32_t res = CreateHapTokenInfoTable(rdbStore);
    if (res != NativeRdb::E_OK) {
        LOGE(AT_DOMAIN, AT_TAG, "Failed to create table hap_token_info_table.");
        return res;
    }

    res = CreateNativeTokenInfoTable(rdbStore);
    if (res != NativeRdb::E_OK) {
        LOGE(AT_DOMAIN, AT_TAG, "Failed to create table native_token_info_table.");
        return res;
    }
    
    res = CreatePermissionDefinitionTable(rdbStore);
    if (res != NativeRdb::E_OK) {
        LOGE(AT_DOMAIN, AT_TAG, "Failed to create table permission_definition_table.");
        return res;
    }
    
    res = CreatePermissionStateTable(rdbStore);
    if (res != NativeRdb::E_OK) {
        LOGE(AT_DOMAIN, AT_TAG, "Failed to create table permission_state_table.");
        return res;
    }
    
    res = CreatePermissionRequestToggleStatusTable(rdbStore);
    if (res != NativeRdb::E_OK) {
        LOGE(AT_DOMAIN, AT_TAG, "Failed to create table permission_request_toggle_status_table.");
        return res;
    }

    std::string dbBackPath = std::string(DATABASE_PATH) + std::string(DATABASE_NAME_BACK);
    if (access(dbBackPath.c_str(), NativeRdb::E_OK) != 0) {
        return 0;
    }

    // if OnCreate solution found back up db, restore from backup, may be origin db has lost
    LOGW(AT_DOMAIN, AT_TAG, "Detech origin database disappear, restore from backup!");

    res = rdbStore.Restore("");
    if (res != NativeRdb::E_OK) {
        LOGE(AT_DOMAIN, AT_TAG, "Db restore failed, res is %{public}d.", res);
    }

    LOGW(AT_DOMAIN, AT_TAG, "Database restore from backup success!");

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
    LOGI(AT_DOMAIN, AT_TAG, "Check result is %{public}d.", checkRes);
    if (checkRes == NativeRdb::E_OK) {
        // success means there exsit column available_type in table
        return NativeRdb::E_OK;
    }

    // alter table add column
    std::string sql = "alter table " + tableName + " add column " +
        TokenFiledConst::FIELD_AVAILABLE_TYPE + " integer default " + std::to_string(ATokenAvailableTypeEnum::NORMAL);

    int32_t res = rdbStore.ExecuteSql(sql);
    LOGI(AT_DOMAIN, AT_TAG, "Insert column result is %{public}d.", res);

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
    LOGI(AT_DOMAIN, AT_TAG, "Check result is %{public}d.", checkRes);
    if (checkRes == NativeRdb::E_OK) {
        // success means there exsit column status in table
        return NativeRdb::E_OK;
    }

    // alter table add column
    std::string sql = "alter table " + tableName + " add column " +
        TokenFiledConst::FIELD_REQUEST_TOGGLE_STATUS + " integer default " + std::to_string(0); // 0: close

    int32_t res = rdbStore.ExecuteSql(sql);
    LOGI(AT_DOMAIN, AT_TAG, "Insert column result is %{public}d.", res);

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
    LOGI(AT_DOMAIN, AT_TAG, "Check result is %{public}d.", checkRes);
    if (checkRes == NativeRdb::E_OK) {
        // success means there exsit column perm_dialog_cap_state in table
        return NativeRdb::E_OK;
    }

    // alter table add column
    std::string sql = "alter table " + tableName + " add column " +
        TokenFiledConst::FIELD_FORBID_PERM_DIALOG + " integer default " + std::to_string(false);

    int32_t res = rdbStore.ExecuteSql(sql);
    LOGI(AT_DOMAIN, AT_TAG, "Insert column result is %{public}d.", res);

    return res;
}

int32_t AccessTokenOpenCallback::HandleUpdateWithFlag(NativeRdb::RdbStore& rdbStore, uint32_t flag)
{
    int32_t res = NativeRdb::E_OK;

    if ((flag & FLAG_HANDLE_FROM_ONE_TO_TWO) == FLAG_HANDLE_FROM_ONE_TO_TWO) {
        res = AddAvailableTypeColumn(rdbStore);
        if (res != NativeRdb::E_OK) {
            LOGE(AT_DOMAIN, AT_TAG, "Failed to add column available_type.");
            return res;
        }

        res = AddPermDialogCapColumn(rdbStore);
        if (res != NativeRdb::E_OK) {
            LOGE(AT_DOMAIN, AT_TAG, "Failed to add column perm_dialog_cap_state.");
            return res;
        }
    }

    if ((flag & FLAG_HANDLE_FROM_TWO_TO_THREE) == FLAG_HANDLE_FROM_TWO_TO_THREE) {
        res = CreatePermissionRequestToggleStatusTable(rdbStore);
        if (res != NativeRdb::E_OK) {
            LOGE(AT_DOMAIN, AT_TAG, "Failed to create table permission_request_toggle_status_table.");
            return res;
        }
    }

    if ((flag & FLAG_HANDLE_FROM_THREE_TO_FOUR) == FLAG_HANDLE_FROM_THREE_TO_FOUR) {
        res = AddRequestToggleStatusColumn(rdbStore);
        if (res != NativeRdb::E_OK) {
            LOGE(AT_DOMAIN, AT_TAG, "Failed to add column status.");
            return res;
        }
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

        default:
            break;
    }

    return res;
}

int32_t AccessTokenOpenCallback::OnUpgrade(NativeRdb::RdbStore& rdbStore, int32_t currentVersion, int32_t targetVersion)
{
    LOGI(AT_DOMAIN, AT_TAG,
        "DB OnUpgrade from currentVersion %{public}d to targetVersion %{public}d.", currentVersion, targetVersion);

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

        default:
            break;
    }

    return res;
}
} // namespace AccessToken
} // namespace Security
} // namespace OHOS
