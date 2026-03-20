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

#include "stopusingpermissionbundle_fuzzer.h"

#include <string>

#include "accesstoken_fuzzdata.h"
#include "fuzzer/FuzzedDataProvider.h"
#undef private
#include "privacy_kit.h"

using namespace OHOS::Security::AccessToken;

namespace OHOS {
bool StopUsingPermissionBundleFuzzTest(const uint8_t* data, size_t size)
{
    if ((data == nullptr) || (size == 0)) {
        return false;
    }

    FuzzedDataProvider provider(data, size);
    return PrivacyKit::StopUsingPermission(
        provider.ConsumeRandomLengthString(), ConsumePermissionName(provider)) == 0;
}
} // namespace OHOS

extern "C" int LLVMFuzzerTestOneInput(const uint8_t* data, size_t size)
{
    OHOS::StopUsingPermissionBundleFuzzTest(data, size);
    return 0;
}
