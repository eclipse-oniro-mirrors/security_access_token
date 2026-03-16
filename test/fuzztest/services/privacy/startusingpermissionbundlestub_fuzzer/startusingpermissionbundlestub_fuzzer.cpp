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

#include "startusingpermissionbundlestub_fuzzer.h"

#include <string>

#include "accesstoken_fuzzdata.h"
#include "fuzzer/FuzzedDataProvider.h"
#include "iprivacy_manager.h"
#include "privacy_manager_service.h"
#include "proxy_death_callback_stub.h"

using namespace OHOS::Security::AccessToken;

namespace OHOS {
void StartUsingPermissionBundleStub(const std::string& bundleName, const std::string& permissionName)
{
    MessageParcel data;
    if (!data.WriteInterfaceToken(IPrivacyManager::GetDescriptor())) {
        return;
    }
    auto anonyStub = sptr<ProxyDeathCallBackStub>::MakeSptr();
    if (!data.WriteString(bundleName)) {
        return;
    }
    if (!data.WriteString(permissionName)) {
        return;
    }
    if (!data.WriteRemoteObject(anonyStub)) {
        return;
    }

    MessageParcel reply;
    MessageOption option(MessageOption::TF_SYNC);
    DelayedSingleton<PrivacyManagerService>::GetInstance()->OnRemoteRequest(
        static_cast<uint32_t>(IPrivacyManagerIpcCode::COMMAND_START_USING_PERMISSION),
        data, reply, option);
}

bool StartUsingPermissionBundleStubFuzzTest(const uint8_t* data, size_t size)
{
    if ((data == nullptr) || (size == 0)) {
        return false;
    }

    FuzzedDataProvider provider(data, size);
    StartUsingPermissionBundleStub(provider.ConsumeRandomLengthString(), ConsumePermissionName(provider));
    return true;
}
} // namespace OHOS

extern "C" int LLVMFuzzerTestOneInput(const uint8_t* data, size_t size)
{
    OHOS::StartUsingPermissionBundleStubFuzzTest(data, size);
    return 0;
}
