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

#include "updatehaptoken_fuzzer.h"

#include <string>
#include <vector>
#include <thread>
#undef private
#include "accesstoken_kit.h"

using namespace std;
using namespace OHOS::Security::AccessToken;

namespace OHOS {
    bool UpdateHapTokenFuzzTest(const uint8_t* data, size_t size)
    {
        bool result = false;
        std::string testdata;
        if ((data == nullptr) || (size <= 0)) {
            return result;
        }
        if (size > 0) {
            AccessTokenID TOKENID = static_cast<AccessTokenID>(size);
            testdata = reinterpret_cast<const char*>(data);
            PermissionDef TestPermDef1 = {
                .permissionName = testdata,
                .bundleName = testdata,
                .grantMode = 1,
                .availableLevel = APL_NORMAL,
                .label = testdata,
                .labelId = 1,
                .description = testdata,
                .descriptionId = 1
            };

            PermissionDef TestPermDef2 = {
                .permissionName = testdata,
                .bundleName = testdata,
                .grantMode = 1,
                .availableLevel = APL_NORMAL,
                .label = testdata,
                .labelId = 1,
                .description = testdata,
                .descriptionId = 1,

            };

            PermissionStateFull TestState1 = {
                .permissionName = testdata,
                .isGeneral = true,
                .resDeviceID = {testdata},
                .grantStatus = {PermissionState::PERMISSION_GRANTED},
                .grantFlags = {1},
            };

            PermissionStateFull TestState2 = {
                .permissionName = testdata,
                .isGeneral = false,
                .resDeviceID = {testdata, testdata},
                .grantStatus = {PermissionState::PERMISSION_GRANTED, PermissionState::PERMISSION_GRANTED},
                .grantFlags = {1, 2}
            };

            HapPolicyParams TestPolicyPrams = {
                .apl = APL_NORMAL,
                .domain = testdata,
                .permList = {TestPermDef1, TestPermDef2},
                .permStateList = {TestState1, TestState2}
            };

            result = AccessTokenKit::UpdateHapToken(TOKENID, testdata, TestPolicyPrams);
        }
        return result;
    }
}

/* Fuzzer entry point */
extern "C" int LLVMFuzzerTestOneInput(const uint8_t* data, size_t size)
{
    /* Run your code on data */
    OHOS::UpdateHapTokenFuzzTest(data, size);
    return 0;
}
