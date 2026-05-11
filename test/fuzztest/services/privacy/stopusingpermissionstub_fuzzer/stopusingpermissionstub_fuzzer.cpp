/*
 * Copyright (c) 2023-2026 Huawei Device Co., Ltd.
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

#include "stopusingpermissionstub_fuzzer.h"

#include <string>
#include <thread>
#include <vector>

#undef private
#include "accesstoken_fuzzdata.h"
#include "add_perm_param_info.h"
#include "fuzzer/FuzzedDataProvider.h"
#include "iprivacy_manager.h"
#include "mock_permission.h"
#include "privacy_manager_service.h"

using namespace std;
using namespace OHOS::Security::AccessToken;

namespace OHOS {
    bool StopUsingPermissionStubFuzzTest(const uint8_t* data, size_t size)
    {
        if ((data == nullptr) || (size == 0)) {
            return false;
        }

        FuzzedDataProvider provider(data, size);

        MessageParcel datas;
        AccessTokenID tokenID = ConsumeTokenId(provider);
        std::string permissionName = ConsumePermissionName(provider);
        std::string enhancedIdentity = provider.ConsumeRandomLengthString(
            provider.ConsumeIntegralInRange<size_t>(0, MAX_ENHANCED_IDENTITY_LENGTH + 1));
        datas.WriteInterfaceToken(IPrivacyManager::GetDescriptor());
        if (!datas.WriteUint32(tokenID)) {
            return false;
        }
        if (!datas.WriteInt32(provider.ConsumeIntegral<int32_t>())) {
            return false;
        }
        if (!datas.WriteString(permissionName)) {
            return false;
        }
        if (!datas.WriteString(enhancedIdentity)) {
            return false;
        }

        uint32_t code = static_cast<uint32_t>(IPrivacyManagerIpcCode::COMMAND_STOP_USING_PERMISSION);

        MessageParcel reply;
        MessageOption option;
        MockToken mock({ "ohos.permission.PERMISSION_USED_STATS" }, true, true);
        DelayedSingleton<PrivacyManagerService>::GetInstance()->OnRemoteRequest(code, datas, reply, option);

        return true;
    }
} // namespace OHOS

/* Fuzzer entry point */
extern "C" int LLVMFuzzerTestOneInput(const uint8_t* data, size_t size)
{
    /* Run your code on data */
    OHOS::StopUsingPermissionStubFuzzTest(data, size);
    return 0;
}
