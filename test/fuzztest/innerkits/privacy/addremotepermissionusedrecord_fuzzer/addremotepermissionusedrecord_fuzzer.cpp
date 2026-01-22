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

#include "addremotepermissionusedrecord_fuzzer.h"

#include "fuzzer/FuzzedDataProvider.h"
#include "privacy_kit.h"

using namespace OHOS::Security::AccessToken;

namespace OHOS {
bool AddRemotePermissionUsedRecordFuzzTest(const uint8_t* data, size_t size)
{
    if ((data == nullptr) || (size == 0)) {
        return false;
    }

    FuzzedDataProvider provider(data, size);

    RemoteCallerInfo info;
    info.remoteDeviceId = provider.ConsumeRandomLengthString();
    info.remoteDeviceName = provider.ConsumeRandomLengthString();

    return PrivacyKit::AddRemotePermissionUsedRecord(info,
        provider.ConsumeRandomLengthString(), provider.ConsumeIntegral<int32_t>(),
        provider.ConsumeIntegral<int32_t>(), provider.ConsumeBool()) == 0;
}
}

/* Fuzzer entry point */
extern "C" int LLVMFuzzerTestOneInput(const uint8_t* data, size_t size)
{
    /* Run your code on data */
    OHOS::AddRemotePermissionUsedRecordFuzzTest(data, size);
    return 0;
}
