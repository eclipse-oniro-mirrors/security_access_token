/*
 * Copyright (c) 2023 Huawei Device Co., Ltd.
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

#include "getaccesstokenid_fuzzer.h"

#include <securec.h>
#include <string>
#include <thread>
#include <vector>
#undef private

#include "fuzzer/FuzzedDataProvider.h"
#include "nativetoken.h"
#include "nativetoken_kit.h"

using namespace std;

namespace OHOS {
    bool GetAccessTokenIdFuzzTest(const uint8_t* data, size_t size)
    {
        if ((data == nullptr) || (size == 0)) {
            return false;
        }

        FuzzedDataProvider provider(data, size);
        NativeTokenInfoParams infoInstance = {
            .permsNum = 0,
            .aclsNum = 0,
            .dcaps = nullptr,
            .perms = nullptr,
            .aplStr = "system_core",
        };
        infoInstance.dcapsNum = 0;
        std::string processName = provider.ConsumeRandomLengthString();
        char name[MAX_PROCESS_NAME_LEN] = { 0 };
        if (strcpy_s(name, MAX_PROCESS_NAME_LEN, processName.c_str()) != EOK) {
            return false;
        }
        infoInstance.processName = name;
        GetAccessTokenId(&infoInstance);

        return true;
    }
} // namespace OHOS

/* Fuzzer entry point */
extern "C" int LLVMFuzzerTestOneInput(const uint8_t* data, size_t size)
{
    /* Run your code on data */
    OHOS::GetAccessTokenIdFuzzTest(data, size);
    return 0;
}
