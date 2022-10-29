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

#include "registerpermactivestatuscallback_fuzzer.h"

#include <iostream>
#include <thread>
#include <string>
#include <vector>
#undef private
#include "privacy_kit.h"

using namespace std;
using namespace OHOS::Security::AccessToken;

class RegisterActiveFuzzTest : public PermActiveStatusCustomizedCbk {
public:
    explicit RegisterActiveFuzzTest(const std::vector<std::string> &permList)
        : PermActiveStatusCustomizedCbk(permList)
    {}

    ~RegisterActiveFuzzTest()
    {}

    virtual void ActiveStatusChangeCallback(ActiveChangeResponse& result)
    {
        type_ = result.type;
        return;
    }

    ActiveChangeType type_ = PERM_INACTIVE;
};

namespace OHOS {
    bool RegisterPermActiveStatusCallbackFuzzTest(const uint8_t* data, size_t size)
    {
        int32_t result = RET_FAILED;
        if ((data == nullptr) || (size == 0)) {
            return false;
        }

        std::string testName(reinterpret_cast<const char*>(data), size);
        std::vector<std::string> permList = {testName};
        auto callback = std::make_shared<RegisterActiveFuzzTest>(permList);
        callback->type_ = PERM_INACTIVE;

        result = PrivacyKit::RegisterPermActiveStatusCallback(callback);

        return result == RET_SUCCESS;
    }
}

/* Fuzzer entry point */
extern "C" int LLVMFuzzerTestOneInput(const uint8_t* data, size_t size)
{
    /* Run your code on data */
    OHOS::RegisterPermActiveStatusCallbackFuzzTest(data, size);
    return 0;
}
