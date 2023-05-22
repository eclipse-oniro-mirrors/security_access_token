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

#include <string>
#include <thread>
#include <vector>
#undef private
#include "nativetoken.h"
#include "nativetoken_kit.h"

using namespace std;

namespace OHOS {
    bool GetAccessTokenIdFuzzTest(const uint8_t* data, size_t size)
    {
        if ((data == nullptr) || (size == 0)) {
            return false;
        }

        const char **dcaps = new (std::nothrow) const char *[2];
        dcaps[0] = "AT_CAP";
        dcaps[1] = "ST_CAP";
        int32_t dcapNum = 2;
        NativeTokenInfoParams infoInstance = {
            .permsNum = 0,
            .aclsNum = 0,
            .dcaps = dcaps,
            .perms = nullptr,
            .aplStr = "system_core",
        };
        infoInstance.dcapsNum = dcapNum;
        infoInstance.processName = "GetAccessTokenIdFuzzTest";
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
