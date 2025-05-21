/*
 * Copyright (c) 2024 Huawei Device Co., Ltd.
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

#ifndef SECURITY_ACCESS_TOKEN_OPEN_CALLBACK_H
#define SECURITY_ACCESS_TOKEN_OPEN_CALLBACK_H

#include "access_token_db_util.h"
#include "rdb_open_callback.h"
#include "rdb_store.h"

namespace OHOS {
namespace Security {
namespace AccessToken {

static constexpr const char* DATABASE_PATH = "/data/service/el1/public/access_token/";

static constexpr const int32_t DATABASE_VERSION_1 = 1;
static constexpr const int32_t DATABASE_VERSION_2 = 2;
static constexpr const int32_t DATABASE_VERSION_3 = 3;
static constexpr const int32_t DATABASE_VERSION_4 = 4;
static constexpr const int32_t DATABASE_VERSION_5 = 5;
static constexpr const int32_t DATABASE_VERSION_6 = 6;

class AccessTokenOpenCallback : public NativeRdb::RdbOpenCallback {
public:
    /**
     * Called when the database associate with this RdbStore is created with the first time.
     * This is where the creation of tables and insert the initial data of tables should happen.
     *
     * param store The RdbStore object.
     */
    int32_t OnCreate(NativeRdb::RdbStore& rdbStore) override;
    /**
     * Called when the database associate whit this RdbStore needs to be upgrade.
     *
     * param store The RdbStore object.
     * param oldVersion The old database version.
     * param newVersion The new database version.
     */
    int32_t OnUpgrade(NativeRdb::RdbStore& rdbStore, int32_t currentVersion, int32_t targetVersion) override;

private:
    // OnCreate
    int32_t CreateHapTokenInfoTable(NativeRdb::RdbStore& rdbStore);
    int32_t CreateNativeTokenInfoTable(NativeRdb::RdbStore& rdbStore);
    int32_t CreatePermissionDefinitionTable(NativeRdb::RdbStore& rdbStore);
    int32_t CreatePermissionStateTable(NativeRdb::RdbStore& rdbStore);
    int32_t CreateVersionOneTable(NativeRdb::RdbStore& rdbStore);
    int32_t CreatePermissionRequestToggleStatusTable(NativeRdb::RdbStore& rdbStore);
    int32_t CreateVersionThreeTable(NativeRdb::RdbStore& rdbStore);
    int32_t CreatePermissionExtendValueTable(NativeRdb::RdbStore& rdbStore);
    int32_t CreateVersionFiveTable(NativeRdb::RdbStore& rdbStore);
    int32_t CreateHapUndefineInfoTable(NativeRdb::RdbStore& rdbStore);
    int32_t CreateSystemConfigTable(NativeRdb::RdbStore& rdbStore);
    int32_t CreateVersionSixTable(NativeRdb::RdbStore& rdbStore);

    // OnUpgrade
    int32_t AddAvailableTypeColumn(NativeRdb::RdbStore& rdbStore);
    int32_t AddRequestToggleStatusColumn(NativeRdb::RdbStore& rdbStore);
    int32_t AddPermDialogCapColumn(NativeRdb::RdbStore& rdbStore);
    int32_t AddKernelEffectAndHasValueColumn(NativeRdb::RdbStore& rdbStore);
    void GetUpgradeFlag(int32_t currentVersion, int32_t targetVersion, uint32_t& flag);
    int32_t HandleUpgradeWithFlag(NativeRdb::RdbStore& rdbStore, uint32_t flag);
};
} // namespace AccessToken
} // namespace Security
} // namespace OHOS

#endif // SECURITY_ACCESS_TOKEN_OPEN_CALLBACK_H
