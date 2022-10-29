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

#include "registerpermstatechangecallback_fuzzer.h"

#include <string>
#include <vector>
#include <thread>
#include "accesstoken_kit.h"

using namespace std;
using namespace OHOS::Security::AccessToken;

class CbCustomizeTest2 : public PermStateChangeCallbackCustomize {
public:
    explicit CbCustomizeTest2(const PermStateChangeScope &scopeInfo)
        : PermStateChangeCallbackCustomize(scopeInfo)
    {
    }

    ~CbCustomizeTest2()
    {}

    virtual void PermStateChangeCallback(PermStateChangeInfo& result)
    {
        ready_ = true;
    }

    bool ready_ = false;
};

namespace OHOS {
    bool RegisterPermStateChangeCallbackFuzzTest(const uint8_t* data, size_t size)
    {
        int32_t result = RET_FAILED;
        if ((data == nullptr) || (size == 0)) {
            return false;
        }

        PermStateChangeScope scopeInfo;
        std::string testName(reinterpret_cast<const char*>(data), size);
        AccessTokenID TOKENID = static_cast<AccessTokenID>(size);
        scopeInfo.permList = { testName };
        scopeInfo.tokenIDs = { TOKENID };
        auto callbackPtr = std::make_shared<CbCustomizeTest2>(scopeInfo);
        result = AccessTokenKit::RegisterPermStateChangeCallback(callbackPtr);

        return result == RET_SUCCESS;
    }
}

/* Fuzzer entry point */
extern "C" int LLVMFuzzerTestOneInput(const uint8_t* data, size_t size)
{
    /* Run your code on data */
    OHOS::RegisterPermStateChangeCallbackFuzzTest(data, size);
    return 0;
}
