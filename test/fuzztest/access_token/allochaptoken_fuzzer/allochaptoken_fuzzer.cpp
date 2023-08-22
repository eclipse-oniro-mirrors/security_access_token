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

#include "allochaptoken_fuzzer.h"

#include <iostream>
#include <thread>
#include <string>
#include <vector>
#undef private
#include "accesstoken_kit.h"

using namespace std;
using namespace OHOS::Security::AccessToken;

namespace OHOS {
    bool AllocHapTokenFuzzTest(const uint8_t* data, size_t size)
    {
        AccessTokenIDEx tokenIdEx = {0};
        if ((data == nullptr) || (size == 0)) {
            return false;
        }

        std::string testName(reinterpret_cast<const char*>(data), size);
        PermissionDef TestPermDef;
        PermissionDef.permissionName = testName;
        PermissionDef.bundleName = testName;
        PermissionDef.grantMode = 1;
        PermissionDef.availableLevel = APL_NORMAL;
        PermissionDef.label = testName;
        PermissionDef.labelId = 1;
        PermissionDef.description = testName;
        PermissionDef.descriptionId = 1;

        PermissionStateFull TestState;
        TestState.permissionName = testName;
        TestState.isGeneral = true;
        TestState.resDeviceID = {testName};
        TestState.grantStatus = {PermissionState::PERMISSION_GRANTED};
        TestState.grantFlags = {1};
        HapInfoParams TestInfoParms = {
            .userID = 1,
            .bundleName = testName,
            .instIndex = 0,
            .appIDDesc = testName
        };
        HapPolicyParams TestPolicyPrams = {
            .apl = APL_NORMAL,
            .domain = testName,
            .permList = {TestPermDef},
            .permStateList = {TestState}
        };

        tokenIdEx = AccessTokenKit::AllocHapToken(TestInfoParms, TestPolicyPrams);

        return tokenIdEx.tokenIdExStruct.tokenID != 0;
    }
}

/* Fuzzer entry point */
extern "C" int LLVMFuzzerTestOneInput(const uint8_t* data, size_t size)
{
    /* Run your code on data */
    OHOS::AllocHapTokenFuzzTest(data, size);
    return 0;
}
