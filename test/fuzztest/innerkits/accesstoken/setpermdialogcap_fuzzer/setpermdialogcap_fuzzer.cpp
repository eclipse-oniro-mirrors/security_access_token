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

#include "setpermdialogcap_fuzzer.h"

#include <climits>
#include <string>
#include <thread>
#include <vector>

#undef private
#include "accesstoken_fuzzdata.h"
#include "accesstoken_kit.h"
#include "fuzzer/FuzzedDataProvider.h"
#include "mock_permission.h"

using namespace std;
using namespace OHOS::Security::AccessToken;

namespace OHOS {
    bool SetPermDialogCapFuzzTest(const uint8_t* data, size_t size)
    {
        if ((data == nullptr) || (size == 0)) {
            return false;
        }

        MockToken mock({ "ohos.permission.DISABLE_PERMISSION_DIALOG" });
        FuzzedDataProvider provider(data, size);
        HapBaseInfo baseInfo;
        baseInfo.userID = provider.ConsumeIntegralInRange<int32_t>(-1, INT_MAX);
        baseInfo.bundleName = provider.ConsumeRandomLengthString();
        baseInfo.instIndex = provider.ConsumeIntegral<int32_t>();

        return AccessTokenKit::SetPermDialogCap(baseInfo, provider.ConsumeBool()) == RET_SUCCESS;
    }
}

/* Fuzzer entry point */
extern "C" int LLVMFuzzerTestOneInput(const uint8_t* data, size_t size)
{
    /* Run your code on data */
    OHOS::SetPermDialogCapFuzzTest(data, size);
    return 0;
}
