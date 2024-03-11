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
        if ((data == nullptr) || (size == 0)) {
            return false;
        }

        AccessTokenIDEx tokenIDex = {
            .tokenIdExStruct.tokenID = static_cast<AccessTokenID>(size),
            .tokenIdExStruct.tokenAttr = static_cast<AccessTokenAttr>(size),
        };

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
        HapPolicyParams TestPolicyParams = {
            .apl = APL_NORMAL,
            .domain = testName,
            .permList = {testPermDef},
            .permStateList = {testState}
        };
        UpdateHapInfoParams info;
        info.appIDDesc = testName;
        info.apiVersion = 8; // 8 means the version
        info.isSystemApp = false;

        int32_t result = AccessTokenKit::UpdateHapToken(
            tokenIDex, info, TestPolicyParams);

        return result == RET_SUCCESS;
    }
}

/* Fuzzer entry point */
extern "C" int LLVMFuzzerTestOneInput(const uint8_t* data, size_t size)
{
    /* Run your code on data */
    OHOS::UpdateHapTokenFuzzTest(data, size);
    return 0;
}
