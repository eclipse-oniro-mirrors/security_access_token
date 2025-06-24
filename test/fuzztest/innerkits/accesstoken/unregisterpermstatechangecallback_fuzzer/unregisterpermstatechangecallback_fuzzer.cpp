/*
 * Copyright (c) 2022-2024 Huawei Device Co., Ltd.
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

#include "unregisterpermstatechangecallback_fuzzer.h"

#include <string>
#include <vector>
#include <thread>

#include "accesstoken_kit.h"
#include "fuzzer/FuzzedDataProvider.h"

using namespace std;
using namespace OHOS::Security::AccessToken;

class CbCustomizeTest1 : public PermStateChangeCallbackCustomize {
public:
    explicit CbCustomizeTest1(const PermStateChangeScope &scopeInfo)
        : PermStateChangeCallbackCustomize(scopeInfo)
    {
    }

    ~CbCustomizeTest1()
    {}

    virtual void PermStateChangeCallback(PermStateChangeInfo& result)
    {
        ready_ = true;
    }

    bool ready_ = false;
};

namespace OHOS {
    bool UnRegisterPermStateChangeCallbackFuzzTest(const uint8_t* data, size_t size)
    {
        if ((data == nullptr) || (size == 0)) {
            return false;
        }

        FuzzedDataProvider provider(data, size);
        PermStateChangeScope scopeInfos;
        scopeInfos.tokenIDs = {provider.ConsumeIntegral<AccessTokenID>()};
        scopeInfos.permList = {provider.ConsumeRandomLengthString()};
        auto callbackPtr = std::make_shared<CbCustomizeTest1>(scopeInfos);
        return AccessTokenKit::UnRegisterPermStateChangeCallback(callbackPtr) == RET_SUCCESS;
    }
}

/* Fuzzer entry point */
extern "C" int LLVMFuzzerTestOneInput(const uint8_t* data, size_t size)
{
    /* Run your code on data */
    OHOS::UnRegisterPermStateChangeCallbackFuzzTest(data, size);
    return 0;
}
