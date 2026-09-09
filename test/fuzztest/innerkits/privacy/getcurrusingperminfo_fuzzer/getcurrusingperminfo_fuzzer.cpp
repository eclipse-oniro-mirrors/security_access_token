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

#include "getcurrusingperminfo_fuzzer.h"

#include <string>
#include <vector>

#include "accesstoken_fuzzdata.h"
#include "fuzzer/FuzzedDataProvider.h"
#include "mock_permission.h"
#undef private
#include "privacy_kit.h"

using namespace std;
using namespace OHOS::Security::AccessToken;

namespace OHOS {
    bool GetCurrUsingPermInfoFuzzTest(const uint8_t* data, size_t size)
    {
        if ((data == nullptr) || (size == 0)) {
            return false;
        }

        MockToken mock({ "ohos.permission.PERMISSION_USED_STATS" }, false, false);
        FuzzedDataProvider provider(data, size);
        (void)provider;

        std::vector<CurrUsingPermInfo> infoList;
        int32_t ret = PrivacyKit::GetCurrUsingPermInfo(infoList);
        (void)ret;
        return true;
    }
} // namespace OHOS

/* Fuzzer entry point */
extern "C" int LLVMFuzzerTestOneInput(const uint8_t* data, size_t size)
{
    /* Run your code on data */
    OHOS::GetCurrUsingPermInfoFuzzTest(data, size);
    return 0;
}
