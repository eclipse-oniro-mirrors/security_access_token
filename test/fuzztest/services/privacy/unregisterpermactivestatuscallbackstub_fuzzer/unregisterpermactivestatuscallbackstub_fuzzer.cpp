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

#include "unregisterpermactivestatuscallbackstub_fuzzer.h"

#include <string>
#include <thread>
#include <vector>

#undef private
#include "accesstoken_fuzzdata.h"
#include "fuzzer/FuzzedDataProvider.h"
#include "iprivacy_manager.h"
#include "perm_active_status_change_callback.h"
#include "perm_active_status_customized_cbk.h"
#include "privacy_manager_service.h"

using namespace std;
using namespace OHOS::Security::AccessToken;

class RegisterActiveFuzzTest : public PermActiveStatusCustomizedCbk {
public:
    explicit RegisterActiveFuzzTest(const std::vector<std::string> &permList)
        : PermActiveStatusCustomizedCbk(permList)
    {}

    ~RegisterActiveFuzzTest()
    {}

    virtual void ActiveStatusChangeCallback(ActiveChangeResponse& result)
    {
        type_ = result.type;
        return;
    }

    ActiveChangeType type_ = PERM_INACTIVE;
};

namespace OHOS {
    bool UnRegisterPermActiveStatusCallbackStubFuzzTest(const uint8_t* data, size_t size)
    {
        if ((data == nullptr) || (size == 0)) {
            return false;
        }

        FuzzedDataProvider provider(data, size);

        MessageParcel datas;
        datas.WriteInterfaceToken(IPrivacyManager::GetDescriptor());

        std::vector<std::string> permList = {ConsumePermissionName(provider)};
        auto callback = std::make_shared<RegisterActiveFuzzTest>(permList);
        callback->type_ = PERM_INACTIVE;

        sptr<PermActiveStatusChangeCallback> callbackWrap = nullptr;
        callbackWrap = new (std::nothrow) PermActiveStatusChangeCallback(callback);
        if (!datas.WriteRemoteObject(callbackWrap->AsObject())) {
            return false;
        }

        uint32_t code = static_cast<uint32_t>(IPrivacyManagerIpcCode::COMMAND_UN_REGISTER_PERM_ACTIVE_STATUS_CALLBACK);

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
    OHOS::UnRegisterPermActiveStatusCallbackStubFuzzTest(data, size);
    return 0;
}
