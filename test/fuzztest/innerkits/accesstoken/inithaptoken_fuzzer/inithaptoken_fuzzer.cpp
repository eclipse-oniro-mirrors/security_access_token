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

#include "inithaptoken_fuzzer.h"

#include <sys/types.h>
#include <unistd.h>
#include <iostream>
#include <thread>
#include <string>
#include <vector>
#undef private
#include "accesstoken_kit.h"

using namespace std;
using namespace OHOS::Security::AccessToken;
const int CONSTANTS_NUMBER_TWO = 2;
static const int32_t ROOT_UID = 0;

namespace OHOS {
    bool InitHapTokenFuzzTest(const uint8_t* data, size_t size)
    {
        AccessTokenIDEx tokenIdEx = {0};
        if ((data == nullptr) || (size == 0)) {
            return false;
        }

        std::string testName(reinterpret_cast<const char*>(data), size);
        PermissionDef testPermDef;
        testPermDef.permissionName = testName;
        testPermDef.bundleName = testName;
        testPermDef.grantMode = 1;
        testPermDef.availableLevel = APL_NORMAL;
        testPermDef.label = testName;
        testPermDef.labelId = 1;
        testPermDef.description = testName;
        testPermDef.descriptionId = 1;

        PermissionStateFull testState;
        testState.permissionName = testName;
        testState.isGeneral = true;
        testState.resDeviceID = {testName};
        testState.grantStatus = {PermissionState::PERMISSION_GRANTED};
        testState.grantFlags = {1};
        HapInfoParams TestInfoParms = {
            .userID = 1,
            .bundleName = testName,
            .instIndex = 0,
            .appIDDesc = testName
        };
        HapPolicyParams TestPolicyPrams = {
            .apl = APL_NORMAL,
            .domain = testName,
            .permList = {testPermDef},
            .permStateList = {testState}
        };

        bool enable = ((size % CONSTANTS_NUMBER_TWO) == 0);
        if (enable) {
            setuid(CONSTANTS_NUMBER_TWO);
        }
        int32_t res = AccessTokenKit::InitHapToken(TestInfoParms, TestPolicyPrams, tokenIdEx);
        setuid(ROOT_UID);

        return res == 0;
    }
}

/* Fuzzer entry point */
extern "C" int LLVMFuzzerTestOneInput(const uint8_t* data, size_t size)
{
    /* Run your code on data */
    OHOS::InitHapTokenFuzzTest(data, size);
    return 0;
}
