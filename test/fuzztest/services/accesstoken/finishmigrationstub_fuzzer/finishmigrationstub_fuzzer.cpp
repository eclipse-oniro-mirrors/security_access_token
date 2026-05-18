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

#include "finishmigrationstub_fuzzer.h"

#undef private
#define private public
#include "accesstoken_manager_service.h"
#undef private
#include "access_token_db_operator.h"
#include "fuzzer/FuzzedDataProvider.h"
#include "iaccess_token_manager.h"
#include "token_field_const.h"

using namespace OHOS::Security::AccessToken;

namespace {
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
} // namespace

namespace OHOS {
bool FinishMigrationStubFuzzTest(const uint8_t* data, size_t size)
{
    if ((data == nullptr) || (size == 0)) {
        return false;
    }

    FuzzedDataProvider provider(data, size);
    MessageParcel datas;
    datas.WriteInterfaceToken(IAccessTokenManager::GetDescriptor());

    if (provider.ConsumeBool()) {
        (void)datas.WriteInt32(provider.ConsumeIntegral<int32_t>());
        (void)datas.WriteString(provider.ConsumeRandomLengthString());
    }

    uint32_t code = static_cast<uint32_t>(IAccessTokenManagerIpcCode::COMMAND_FINISH_MIGRATION);
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
    OHOS::FinishMigrationStubFuzzTest(data, size);
    return 0;
}
