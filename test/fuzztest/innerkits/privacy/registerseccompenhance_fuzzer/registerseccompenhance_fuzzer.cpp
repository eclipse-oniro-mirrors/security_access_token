/*
 * Copyright (c) 2024 Huawei Device Co., Ltd.
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

#include "registerseccompenhance_fuzzer.h"

#include <iostream>
#include <thread>
#include <string>
#include <vector>
#undef private
#include "privacy_kit.h"

using namespace std;
using namespace OHOS::Security::AccessToken;

namespace OHOS {
    bool RegisterSecCompEnhanceFuzzTest(const uint8_t* data, size_t size)
    {
        if ((data == nullptr) || (size == 0)) {
            return false;
        }

        SecCompEnhanceData secData;
        secData.callback = nullptr;
        secData.pid = static_cast<int32_t>(size);
        secData.token = static_cast<AccessTokenID>(size);
        secData.challenge = static_cast<uint64_t>(size);
        secData.sessionId = static_cast<int32_t>(size);
        secData.seqNum = static_cast<int32_t>(size);

        int32_t result = PrivacyKit::RegisterSecCompEnhance(secData);
        return result == RET_SUCCESS;
    }
}

/* Fuzzer entry point */
extern "C" int LLVMFuzzerTestOneInput(const uint8_t* data, size_t size)
{
    /* Run your code on data */
    OHOS::RegisterSecCompEnhanceFuzzTest(data, size);
    return 0;
}
