/*
 * Copyright (c) 2023-2024 Huawei Device Co., Ltd.
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

#include "allochaptokenstub_fuzzer.h"
#include <sys/types.h>
#include <unistd.h>
#include <iostream>
#include <string>
#include <thread>
#include <vector>
#undef private
#include "accesstoken_manager_service.h"
#include "hap_info_parcel.h"
#include "i_accesstoken_manager.h"

using namespace std;
using namespace OHOS::Security::AccessToken;
const int CONSTANTS_NUMBER_TWO = 2;
static const int32_t ROOT_UID = 0;

namespace OHOS {
    void ConstructorParam(const std::string& testName, HapInfoParcel& hapInfoParcel, HapPolicyParcel& hapPolicyParcel)
    {
        PermissionDef testPermDef = {
            .permissionName = testName,
            .bundleName = testName,
            .grantMode = 1,
            .availableLevel = APL_NORMAL,
            .label = testName,
            .labelId = 1,
            .description = testName,
            .descriptionId = 1};
        PermissionStateFull TestState = {
            .permissionName = testName,
            .isGeneral = true,
            .resDeviceID = {testName},
            .grantStatus = {PermissionState::PERMISSION_GRANTED},
            .grantFlags = {1},
        };
        HapInfoParams TestInfoParms = {
            .userID = 1,
            .bundleName = testName,
            .instIndex = 0,
            .appIDDesc = testName};
        PreAuthorizationInfo info1 = {
            .permissionName = testName,
            .userCancelable = true
        };
        HapPolicyParams TestPolicyPrams = {
            .apl = APL_NORMAL,
            .domain = testName,
            .permList = {testPermDef},
            .permStateList = {TestState},
            .aclRequestedList = {testName},
            .preAuthorizationInfo = {info1}
        };

        hapInfoParcel.hapInfoParameter = TestInfoParms;
        hapPolicyParcel.hapPolicyParameter = TestPolicyPrams;
    }

    bool AllocHapTokenStubFuzzTest(const uint8_t* data, size_t size)
    {
        if ((data == nullptr) || (size == 0)) {
            return false;
        }

        std::string testName(reinterpret_cast<const char *>(data), size);
        HapInfoParcel hapInfoParcel;
        HapPolicyParcel hapPolicyParcel;
        ConstructorParam(testName, hapInfoParcel, hapPolicyParcel);

        MessageParcel datas;
        datas.WriteInterfaceToken(IAccessTokenManager::GetDescriptor());
        if (!datas.WriteParcelable(&hapInfoParcel)) {
            return false;
        }
        if (!datas.WriteParcelable(&hapPolicyParcel)) {
            return false;
        }

        uint32_t code = static_cast<uint32_t>(
            AccessTokenInterfaceCode::ALLOC_TOKEN_HAP);

        MessageParcel reply;
        MessageOption option;
        bool enable = ((size % CONSTANTS_NUMBER_TWO) == 0);
        if (enable) {
            setuid(CONSTANTS_NUMBER_TWO);
        }
        DelayedSingleton<AccessTokenManagerService>::GetInstance()->OnRemoteRequest(code, datas, reply, option);
        setuid(ROOT_UID);

        return true;
    }
} // namespace OHOS

/* Fuzzer entry point */
extern "C" int LLVMFuzzerTestOneInput(const uint8_t* data, size_t size)
{
    /* Run your code on data */
    OHOS::AllocHapTokenStubFuzzTest(data, size);
    return 0;
}
