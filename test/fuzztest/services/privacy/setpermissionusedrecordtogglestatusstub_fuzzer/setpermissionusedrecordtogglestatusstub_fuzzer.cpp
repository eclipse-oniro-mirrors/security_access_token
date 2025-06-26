/*
 * Copyright (c) 2025 Huawei Device Co., Ltd.
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

#include "setpermissionusedrecordtogglestatusstub_fuzzer.h"

#undef private
#include "fuzzer/FuzzedDataProvider.h"
#include "iprivacy_manager.h"
#include "privacy_manager_service.h"

using namespace std;
using namespace OHOS::Security::AccessToken;
const int CONSTANTS_NUMBER_TWO = 2;
static const int32_t ROOT_UID = 0;

namespace OHOS {
    bool SetPermissionUsedRecordToggleStatusStubFuzzTest(const uint8_t* data, size_t size)
    {
        if ((data == nullptr) || (size == 0)) {
            return false;
        }

        FuzzedDataProvider provider(data, size);

        MessageParcel datas;
        datas.WriteInterfaceToken(IPrivacyManager::GetDescriptor());

        int32_t userID = provider.ConsumeIntegral<int32_t>();
        bool status = provider.ConsumeBool();
        if (!datas.WriteInt32(userID) || !datas.WriteInt32(status ? 1 : 0)) {
            return false;
        }

        uint32_t code = static_cast<uint32_t>(IPrivacyManagerIpcCode::COMMAND_SET_PERMISSION_USED_RECORD_TOGGLE_STATUS);

        MessageParcel reply;
        MessageOption option;
        bool enable = ((size % CONSTANTS_NUMBER_TWO) == 0);
        if (enable) {
            setuid(CONSTANTS_NUMBER_TWO);
        }
        DelayedSingleton<PrivacyManagerService>::GetInstance()->OnRemoteRequest(code, datas, reply, option);
        setuid(ROOT_UID);

        return true;
    }
} // namespace OHOS

/* Fuzzer entry point */
extern "C" int LLVMFuzzerTestOneInput(const uint8_t* data, size_t size)
{
    /* Run your code on data */
    OHOS::SetPermissionUsedRecordToggleStatusStubFuzzTest(data, size);
    return 0;
}
