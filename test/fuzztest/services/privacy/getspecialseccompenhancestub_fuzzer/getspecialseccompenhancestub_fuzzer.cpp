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

#include "getspecialseccompenhancestub_fuzzer.h"

#include <string>
#include <thread>
#include <vector>
#undef private
#include "errors.h"
#include "i_privacy_manager.h"
#include "on_permission_used_record_callback_stub.h"
#include "permission_used_request.h"
#include "permission_used_request_parcel.h"
#include "privacy_manager_service.h"

using namespace std;
using namespace OHOS::Security::AccessToken;

namespace OHOS {
    bool GetSpecialSecCompEnhanceStubFuzzTest(const uint8_t* data, size_t size)
    {
        if ((data == nullptr) || (size == 0)) {
            return false;
        }

        std::string bundleName(reinterpret_cast<const char*>(data), size);

        MessageParcel datas;
        datas.WriteInterfaceToken(IPrivacyManager::GetDescriptor());
        if (!datas.WriteString(bundleName)) {
            return false;
        }

        uint32_t code = static_cast<uint32_t>(PrivacyInterfaceCode::GET_SPECIAL_SEC_COMP_ENHANCE);

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
    OHOS::GetSpecialSecCompEnhanceStubFuzzTest(data, size);
    return 0;
}
