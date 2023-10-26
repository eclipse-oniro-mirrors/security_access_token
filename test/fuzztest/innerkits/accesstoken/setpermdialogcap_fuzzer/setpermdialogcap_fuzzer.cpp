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

#include "setpermdialogcap_fuzzer.h"

#include <string>
#include <thread>
#include <vector>
#undef private
#include "accesstoken_kit.h"

using namespace std;
using namespace OHOS::Security::AccessToken;

namespace OHOS {
    bool SetPermDialogCapFuzzTest(const uint8_t* data, size_t size)
    {
        if ((data == nullptr) || (size == 0)) {
            return false;
        }
        std::string testName(reinterpret_cast<const char*>(data), size);
        HapBaseInfo baseInfo;
        baseInfo.userID = static_cast<int32_t>(size);
        baseInfo.bundleName = testName;
        baseInfo.instIndex = static_cast<int32_t>(size);

        int32_t result = AccessTokenKit::SetPermDialogCap(baseInfo, false);

        return result == RET_SUCCESS;
    }
}

/* Fuzzer entry point */
extern "C" int LLVMFuzzerTestOneInput(const uint8_t* data, size_t size)
{
    /* Run your code on data */
    OHOS::SetPermDialogCapFuzzTest(data, size);
    return 0;
}
