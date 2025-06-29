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

#include "startusingpermissioncallbackstub_fuzzer.h"

#include <string>
#include <thread>
#include <vector>

#undef private
#include "fuzzer/FuzzedDataProvider.h"
#include "iprivacy_manager.h"
#include "state_change_callback.h"
#include "state_customized_cbk.h"
#include "privacy_manager_service.h"

using namespace std;
using namespace OHOS::Security::AccessToken;

class CbCustomizeTest : public StateCustomizedCbk {
public:
    explicit CbCustomizeTest() : StateCustomizedCbk()
    {
    }

    ~CbCustomizeTest()
    {}

    virtual void StateChangeNotify(AccessTokenID tokenId,  bool isShowing)
    {
        isShowing_ = true;
    }

    bool isShowing_ = false;
};

namespace OHOS {
    bool StartUsingPermissionCallbackStubFuzzTest(const uint8_t* data, size_t size)
    {
        if ((data == nullptr) || (size == 0)) {
            return false;
        }

        FuzzedDataProvider provider(data, size);

        sptr<StateChangeCallback> callbackWrap = nullptr;
        auto callback = std::make_shared<CbCustomizeTest>();
        callbackWrap = new (std::nothrow) StateChangeCallback(callback);

        MessageParcel datas;
        datas.WriteInterfaceToken(IPrivacyManager::GetDescriptor());
        if (!datas.WriteUint32(provider.ConsumeIntegral<AccessTokenID>())) {
            return false;
        }
        if (!datas.WriteString(provider.ConsumeRandomLengthString())) {
            return false;
        }
        if (!datas.WriteInt32(provider.ConsumeIntegral<int32_t>())) {
            return false;
        }
        uint32_t type = static_cast<uint32_t>(provider.ConsumeIntegralInRange<uint32_t>(
            0, static_cast<uint32_t>(PermissionUsedType::PERM_USED_TYPE_BUTT)));
        if (!datas.WriteUint32(type)) {
            return false;
        }
        if (!datas.WriteRemoteObject(callbackWrap->AsObject())) {
            return false;
        }

        uint32_t code = static_cast<uint32_t>(IPrivacyManagerIpcCode::COMMAND_START_USING_PERMISSION_CALLBACK);

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
    OHOS::StartUsingPermissionCallbackStubFuzzTest(data, size);
    return 0;
}
