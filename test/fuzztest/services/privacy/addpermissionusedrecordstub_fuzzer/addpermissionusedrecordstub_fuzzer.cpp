/*
 * Copyright (c) 2023-2025 Huawei Device Co., Ltd.
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

#include "addpermissionusedrecordstub_fuzzer.h"

#include <chrono>
#include <cstdlib>
#include <string>
#include <thread>
#include <vector>

#undef private
#include "accesstoken_fuzzdata.h"
#include "fuzzer/FuzzedDataProvider.h"
#include "iprivacy_manager.h"
#include "privacy_manager_service.h"

using namespace std;
using namespace OHOS::Security::AccessToken;

static constexpr int32_t SLEEP_TIME = 5;

namespace OHOS {
    bool AddPermissionUsedRecordStubFuzzTest(const uint8_t* data, size_t size)
    {
        if ((data == nullptr) || (size == 0)) {
            return false;
        }

        FuzzedDataProvider provider(data, size);

        MessageParcel datas;
        datas.WriteInterfaceToken(IPrivacyManager::GetDescriptor());

        AddPermParamInfoParcel infoParcel;
        infoParcel.info.tokenId = ConsumeTokenId(provider);
        infoParcel.info.permissionName = ConsumePermissionName(provider);
        infoParcel.info.successCount = provider.ConsumeIntegral<int32_t>();
        infoParcel.info.failCount = provider.ConsumeIntegral<int32_t>();
        infoParcel.info.type = static_cast<PermissionUsedType>(provider.ConsumeIntegralInRange<uint32_t>(
            0, static_cast<uint32_t>(PermissionUsedType::PERM_USED_TYPE_BUTT)));
        if (!datas.WriteParcelable(&infoParcel)) {
            return false;
        }

        uint32_t code = static_cast<uint32_t>(IPrivacyManagerIpcCode::COMMAND_ADD_PERMISSION_USED_RECORD);

        MessageParcel reply;
        MessageOption option;
        DelayedSingleton<PrivacyManagerService>::GetInstance()->OnRemoteRequest(code, datas, reply, option);

        return true;
    }
} // namespace OHOS

void BeforeExit()
{
    std::this_thread::sleep_for(std::chrono::seconds(SLEEP_TIME));
}

extern "C" int LLVMFuzzerInitialize(int *argc, char ***argv)
{
    (void)atexit(BeforeExit);
    return 0;
}

/* Fuzzer entry point */
extern "C" int LLVMFuzzerTestOneInput(const uint8_t* data, size_t size)
{
    /* Run your code on data */
    OHOS::AddPermissionUsedRecordStubFuzzTest(data, size);
    return 0;
}
