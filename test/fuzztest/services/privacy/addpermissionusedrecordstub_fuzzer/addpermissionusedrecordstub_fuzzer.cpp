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

#include <string>
#include <thread>
#include <vector>

#undef private
#include "fuzzer/FuzzedDataProvider.h"
#include "iprivacy_manager.h"
#include "privacy_manager_service.h"

using namespace std;
using namespace OHOS::Security::AccessToken;

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
        infoParcel.info.tokenId = provider.ConsumeIntegral<AccessTokenID>();
        infoParcel.info.permissionName = provider.ConsumeRandomLengthString();
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

/* Fuzzer entry point */
extern "C" int LLVMFuzzerTestOneInput(const uint8_t* data, size_t size)
{
    /* Run your code on data */
    OHOS::AddPermissionUsedRecordStubFuzzTest(data, size);
    return 0;
}
