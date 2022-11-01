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

#include "startusingpermission001_fuzzer.h"

#include <iostream>
#include <thread>
#include <string>
#include <vector>
#undef private
#include "privacy_kit.h"

using namespace std;
using namespace OHOS::Security::AccessToken;

class CbCustomizeTest : public StateCustomizedCbk {
public:
    explicit CbCustomizeTest() : StateCustomizedCbk()
    {
    }

    ~CbCustomizeTest()
    {}

    virtual void StateChangeNotify(AccessTokenID tokenId, bool isShowing)
    {
        isShowing_ = true;
    }

    bool isShowing_ = false;
};

namespace OHOS {
    bool StartUsingPermission001FuzzTest(const uint8_t* data, size_t size)
    {
        int32_t result = RET_FAILED;
        if ((data == nullptr) || (size == 0)) {
            return false;
        }

        AccessTokenID tokenId = static_cast<AccessTokenID>(size);
        std::string testName(reinterpret_cast<const char*>(data), size);
        auto callback = std::make_shared<CbCustomizeTest>();

        result = PrivacyKit::StartUsingPermission(tokenId, testName, callback);

        return result == RET_SUCCESS;
    }
}

/* Fuzzer entry point */
extern "C" int LLVMFuzzerTestOneInput(const uint8_t* data, size_t size)
{
    /* Run your code on data */
    OHOS::StartUsingPermission001FuzzTest(data, size);
    return 0;
}
