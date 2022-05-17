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

#include <string>
#include <vector>
#include <thread>
#undef private
#include "accesstoken_kit.h"

using namespace std;
using namespace OHOS::Security::AccessToken;

namespace OHOS {
    bool AllocHapTokenFuzzTest(const uint8_t* data, size_t size)
    {
        bool result = false;
        std::string testdata;
        AccessTokenIDEx tokenIdEx = {0};
        if ((data == nullptr) || (size <= 0)) {
            return result;
        }
        if (size > 0) {
            testdata = reinterpret_cast<const char*>(data);
            PermissionDef TestPermDef = {
                .permissionName = testdata,
                .bundleName = testdata,
                .grantMode = 1,
                .availableLevel = APL_NORMAL,
                .label = testdata,
                .labelId = 1,
                .description = testdata,
                .descriptionId = 1
            };
            PermissionStateFull TestState = {
                .permissionName = testdata,
                .isGeneral = true,
                .resDeviceID = {testdata},
                .grantStatus = {PermissionState::PERMISSION_GRANTED},
                .grantFlags = {1},
            };
            HapInfoParams TestInfoParms = {
                .userID = 1,
                .bundleName = testdata,
                .instIndex = 0,
                .appIDDesc = testdata
            };
            HapPolicyParams TestPolicyPrams = {
                .apl = APL_NORMAL,
                .domain = testdata,
                .permList = {TestPermDef},
                .permStateList = {TestState}
            };

            tokenIdEx = AccessTokenKit::AllocHapToken(TestInfoParms, TestPolicyPrams);
        }
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
