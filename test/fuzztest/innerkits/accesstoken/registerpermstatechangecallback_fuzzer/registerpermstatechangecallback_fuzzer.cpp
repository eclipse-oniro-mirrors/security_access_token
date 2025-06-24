/*
 * Copyright (c) 2022-2025 Huawei Device Co., Ltd.
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

#include "accesstoken_callbacks.h"
#include "accesstoken_kit.h"
#define private public
#include "accesstoken_manager_client.h"
#undef private
#include "fuzzer/FuzzedDataProvider.h"

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
        if ((data == nullptr) || (size == 0)) {
            return false;
        }

        FuzzedDataProvider provider(data, size);
        PermStateChangeScope scopeInfo;
        scopeInfo.permList = { provider.ConsumeRandomLengthString() };
        scopeInfo.tokenIDs = { provider.ConsumeIntegral<AccessTokenID>() };
        auto callbackPtr = std::make_shared<CbCustomizeTest2>(scopeInfo);
        AccessTokenKit::RegisterPermStateChangeCallback(callbackPtr);
        auto callback = new (std::nothrow) PermissionStateChangeCallback(callbackPtr);
        if (callback == nullptr) {
            return true;
        }
        AccessTokenManagerClient::GetInstance().callbackMap_[callbackPtr] = callback;
        AccessTokenKit::UnRegisterPermStateChangeCallback(callbackPtr);
        auto callbackPtr2 = std::make_shared<CbCustomizeTest2>(scopeInfo);
        AccessTokenKit::RegisterSelfPermStateChangeCallback(callbackPtr2);
        AccessTokenKit::UnRegisterSelfPermStateChangeCallback(callbackPtr);

        return true;
    }
}

/* Fuzzer entry point */
extern "C" int LLVMFuzzerTestOneInput(const uint8_t* data, size_t size)
{
    /* Run your code on data */
    OHOS::RegisterPermStateChangeCallbackFuzzTest(data, size);
    return 0;
}
