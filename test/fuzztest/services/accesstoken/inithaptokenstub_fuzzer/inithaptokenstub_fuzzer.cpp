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

#include "inithaptokenstub_fuzzer.h"
#include <sys/types.h>
#include <unistd.h>
#include <iostream>
#include <string>
#include <thread>
#include <vector>
#include "accesstoken_fuzzdata.h"
#undef private
#include "accesstoken_manager_service.h"
#include "hap_info_parcel.h"
#include "i_accesstoken_manager.h"

using namespace std;
using namespace OHOS::Security::AccessToken;
const int CONSTANTS_NUMBER_TWO = 2;
static const int32_t ROOT_UID = 0;

namespace OHOS {
    void ConstructorParam(AccessTokenFuzzData& fuzzData, HapInfoParcel& hapInfoParcel, HapPolicyParcel& hapPolicyParcel)
    {
        std::string permissionName = fuzzData.GenerateRandomString();
        std::string bundleName = fuzzData.GenerateRandomString();
        PermissionDef testPermDef = {
            .permissionName = permissionName,
            .bundleName = bundleName,
            .grantMode = 1,
            .availableLevel = APL_NORMAL,
            .label = fuzzData.GenerateRandomString(),
            .labelId = 1,
            .description = fuzzData.GenerateRandomString(),
            .descriptionId = 1};
        PermissionStateFull TestState = {
            .permissionName = permissionName,
            .isGeneral = true,
            .resDeviceID = {fuzzData.GenerateRandomString()},
            .grantStatus = {PermissionState::PERMISSION_GRANTED},
            .grantFlags = {1},
        };
        HapInfoParams TestInfoParms = {
            .userID = 1,
            .bundleName = bundleName,
            .instIndex = 0,
            .appIDDesc = fuzzData.GenerateRandomString()};
        PreAuthorizationInfo info1 = {
            .permissionName = permissionName,
            .userCancelable = true
        };
        HapPolicyParams TestPolicyPrams = {
            .apl = APL_NORMAL,
            .domain = fuzzData.GenerateRandomString(),
            .permList = {testPermDef},
            .permStateList = {TestState},
            .aclRequestedList = {permissionName},
            .preAuthorizationInfo = {info1}
        };

        hapInfoParcel.hapInfoParameter = TestInfoParms;
        hapPolicyParcel.hapPolicyParameter = TestPolicyPrams;
    }

    bool InitHapTokenStubFuzzTest(const uint8_t* data, size_t size)
    {
        if ((data == nullptr) || (size == 0)) {
            return false;
        }

        AccessTokenFuzzData fuzzData(data, size);
        HapInfoParcel hapInfoParcel;
        HapPolicyParcel hapPolicyParcel;
        ConstructorParam(fuzzData, hapInfoParcel, hapPolicyParcel);

        MessageParcel datas;
        datas.WriteInterfaceToken(IAccessTokenManager::GetDescriptor());
        if (!datas.WriteParcelable(&hapInfoParcel)) {
            return false;
        }
        if (!datas.WriteParcelable(&hapPolicyParcel)) {
            return false;
        }

        uint32_t code = static_cast<uint32_t>(
            AccessTokenInterfaceCode::INIT_TOKEN_HAP);

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
    OHOS::InitHapTokenStubFuzzTest(data, size);
    return 0;
}
