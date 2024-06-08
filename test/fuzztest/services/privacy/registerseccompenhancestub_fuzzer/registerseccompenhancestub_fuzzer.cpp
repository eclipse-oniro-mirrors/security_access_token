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

#include "registerseccompenhancestub_fuzzer.h"

#include <string>
#include <thread>
#include <vector>

#include "accesstoken_fuzzdata.h"
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
    bool RegisterSecCompEnhanceStubFuzzTest(const uint8_t* data, size_t size)
    {
        if ((data == nullptr) || (size == 0)) {
            return false;
        }

        AccessTokenFuzzData fuzzData(data, size);

        SecCompEnhanceData secData;
        secData.callback = nullptr;
        secData.pid = fuzzData.GetData<int32_t>();
        secData.token = static_cast<AccessTokenID>(fuzzData.GetData<uint32_t>());
        secData.challenge = fuzzData.GetData<uint64_t>();
        secData.sessionId = fuzzData.GetData<uint32_t>();
        secData.seqNum = fuzzData.GetData<uint32_t>();

        SecCompEnhanceDataParcel enhance;
        enhance.enhanceData = secData;

        MessageParcel datas;
        datas.WriteInterfaceToken(IPrivacyManager::GetDescriptor());
        if (!datas.WriteParcelable(&enhance)) {
            return false;
        }

        uint32_t code = static_cast<uint32_t>(PrivacyInterfaceCode::REGISTER_SEC_COMP_ENHANCE);

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
    OHOS::RegisterSecCompEnhanceStubFuzzTest(data, size);
    return 0;
}
