/*
 * Copyright (c) 2022 Huawei Device Co., Ltd.
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

        PermStateChangeScope scopeInfos;
        std::string testName(reinterpret_cast<const char*>(data), size);
        AccessTokenID tokenId = static_cast<AccessTokenID>(size);
        scopeInfos.permList = { testName };
        scopeInfos.tokenIDs = { tokenId };
        auto callbackPtr = std::make_shared<CbCustomizeTest1>(scopeInfos);
        int32_t result = AccessTokenKit::UnRegisterPermStateChangeCallback(callbackPtr);

        return result == RET_SUCCESS;
    }
}

/* Fuzzer entry point */
extern "C" int LLVMFuzzerTestOneInput(const uint8_t* data, size_t size)
{
    /* Run your code on data */
    OHOS::UnRegisterPermStateChangeCallbackFuzzTest(data, size);
    return 0;
}