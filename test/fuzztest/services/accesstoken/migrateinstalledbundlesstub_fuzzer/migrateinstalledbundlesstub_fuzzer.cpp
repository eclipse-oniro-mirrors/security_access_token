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

#include "migrateinstalledbundlesstub_fuzzer.h"

#undef private
#define private public
#include "accesstoken_manager_service.h"
#undef private
#include "access_token_db_operator.h"
#include "fuzzer/FuzzedDataProvider.h"
#include "iaccess_token_manager.h"
#include "idl_common.h"
#include "token_field_const.h"

using namespace OHOS::Security::AccessToken;

namespace {
constexpr int32_t MAX_MIGRATED_INFO_LIST_SIZE = 8;
constexpr int32_t MAX_HAP_PATH_LIST_SIZE = 4;
constexpr int32_t MAX_UID_LIST_SIZE = 4;
constexpr int32_t MAX_STRING_SIZE = 128;
const std::string BMS_MIGRATE_COMPLETED = "bms_migrate_completed";

void ClearMigrationCompletedRecord()
{
    GenericValues delValue;
    delValue.Put(TokenFiledConst::FIELD_NAME, BMS_MIGRATE_COMPLETED);
    DelInfo delInfo;
    delInfo.delType = AtmDataType::ACCESSTOKEN_SYSTEM_CONFIG;
    delInfo.delValue = delValue;
    std::vector<DelInfo> delInfoVec = { delInfo };
    std::vector<AddInfo> addInfoVec;
    (void)AccessTokenDbOperator::DeleteAndInsertValues(delInfoVec, addInfoVec);
}

std::string ConsumeMigrationString(FuzzedDataProvider& provider)
{
    if (provider.ConsumeBool()) {
        return provider.ConsumeRandomLengthString(MAX_STRING_SIZE);
    }
    return "com.example.migration.fuzz";
}

ReservedTypeIdl ConsumeReservedType(FuzzedDataProvider& provider)
{
    int32_t reserved = provider.ConsumeIntegralInRange<int32_t>(-1, 4);
    return static_cast<ReservedTypeIdl>(reserved);
}

MigratedInfoIdl ConsumeMigratedInfo(FuzzedDataProvider& provider)
{
    MigratedInfoIdl migratedInfo;
    migratedInfo.bundleName = ConsumeMigrationString(provider);
    int32_t pathSize = provider.ConsumeIntegralInRange<int32_t>(0, MAX_HAP_PATH_LIST_SIZE);
    for (int32_t i = 0; i < pathSize; ++i) {
        migratedInfo.pathList.hapPaths.emplace_back(ConsumeMigrationString(provider));
    }
    migratedInfo.pathList.isPreInstalled = provider.ConsumeBool();

    int32_t uidSize = provider.ConsumeIntegralInRange<int32_t>(0, MAX_UID_LIST_SIZE);
    for (int32_t i = 0; i < uidSize; ++i) {
        migratedInfo.uidList.emplace_back(provider.ConsumeIntegral<int32_t>());
    }

    int32_t reservedSize = provider.ConsumeIntegralInRange<int32_t>(0, MAX_UID_LIST_SIZE + 1);
    for (int32_t i = 0; i < reservedSize; ++i) {
        migratedInfo.reservedTypeList.emplace_back(ConsumeReservedType(provider));
    }
    return migratedInfo;
}
} // namespace

namespace OHOS {
bool MigrateInstalledBundlesStubFuzzTest(const uint8_t* data, size_t size)
{
    if ((data == nullptr) || (size == 0)) {
        return false;
    }

    FuzzedDataProvider provider(data, size);
    MessageParcel datas;
    datas.WriteInterfaceToken(IAccessTokenManager::GetDescriptor());

    bool writeMalformedParcel = provider.ConsumeBool();
    int32_t migratedInfoListSize = provider.ConsumeIntegralInRange<int32_t>(-1, MAX_MIGRATED_INFO_LIST_SIZE);
    if (!datas.WriteInt32(migratedInfoListSize)) {
        return false;
    }
    if (!writeMalformedParcel) {
        for (int32_t i = 0; i < migratedInfoListSize; ++i) {
            MigratedInfoIdl migratedInfo = ConsumeMigratedInfo(provider);
            if (MigratedInfoIdlBlockMarshalling(datas, migratedInfo) != ERR_NONE) {
                return false;
            }
        }
    }

    uint32_t code = static_cast<uint32_t>(IAccessTokenManagerIpcCode::COMMAND_MIGRATE_INSTALLED_BUNDLES);
    MessageParcel reply;
    MessageOption option;
    ClearMigrationCompletedRecord();
    DelayedSingleton<AccessTokenManagerService>::GetInstance()->OnRemoteRequest(code, datas, reply, option);
    ClearMigrationCompletedRecord();
    return true;
}

void Initialize()
{
    DelayedSingleton<AccessTokenManagerService>::GetInstance()->Initialize();
}
} // namespace OHOS

extern "C" int LLVMFuzzerInitialize(int *argc, char ***argv)
{
    OHOS::Initialize();
    return 0;
}

extern "C" int LLVMFuzzerTestOneInput(const uint8_t* data, size_t size)
{
    OHOS::MigrateInstalledBundlesStubFuzzTest(data, size);
    return 0;
}
