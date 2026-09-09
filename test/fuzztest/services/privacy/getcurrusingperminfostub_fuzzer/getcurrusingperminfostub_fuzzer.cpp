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

#include "getcurrusingperminfostub_fuzzer.h"

#include <string>

#undef private
#include "accesstoken_fuzzdata.h"
#include "accesstoken_kit.h"
#include "mock_permission.h"
#include "fuzzer/FuzzedDataProvider.h"
#include "iprivacy_manager.h"
#include "privacy_manager_service.h"

using namespace std;
using namespace OHOS::Security::AccessToken;

namespace OHOS {
    bool GetCurrUsingPermInfoStubFuzzTest(const uint8_t* data, size_t size)
    {
        if ((data == nullptr) || (size == 0)) {
            return false;
        }

        FuzzedDataProvider provider(data, size);
        (void)provider;

        MessageParcel datas;
        datas.WriteInterfaceToken(IPrivacyManager::GetDescriptor());

        uint32_t code = static_cast<uint32_t>(
            IPrivacyManagerIpcCode::COMMAND_GET_CURR_USING_PERM_INFO);

        MessageParcel reply;
        MessageOption option;
        MockToken mock({ "ohos.permission.PERMISSION_USED_STATS" }, false, false);
        (void)DelayedSingleton<PrivacyManagerService>::GetInstance()->OnRemoteRequest(code, datas, reply, option);
        return true;
    }
} // namespace OHOS

/* Fuzzer entry point */
extern "C" int LLVMFuzzerTestOneInput(const uint8_t* data, size_t size)
{
    /* Run your code on data */
    OHOS::GetCurrUsingPermInfoStubFuzzTest(data, size);
    return 0;
}
