/*
 * Copyright (c) 2025 Huawei Device Co., Ltd.
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

#include "allochaptokenservice_fuzzer.h"
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
#include "iaccess_token_manager.h"

using namespace std;
using namespace OHOS::Security::AccessToken;
const int CONSTANTS_NUMBER_TEN = 10;
static const int32_t ROOT_UID = 0;
static const vector<PermissionState> STATU_LIST = {
    PERMISSION_GRANTED,
    PERMISSION_DENIED
};
static const vector<uint32_t> FLAG_LIST = {
    static_cast<uint32_t>(0),
    static_cast<uint32_t>(2),
    static_cast<uint32_t>(4)
};
static const uint32_t FLAG_LIST_SIZE = 3;
static const uint32_t STATU_LIST_SIZE = 2;

static const vector<ATokenAplEnum> APL_LIST = {
    APL_NORMAL,
    APL_SYSTEM_BASIC,
    APL_SYSTEM_CORE,
};
static const uint32_t APL_LIST_SIZE = 3;

namespace OHOS {
void ConstructorParam(AccessTokenFuzzData& fuzzData, HapInfoParcel& hapInfoParcel, HapPolicyParcel& hapPolicyParcel)
{
    std::string permissionName = fuzzData.GenerateStochasticString();
    std::string bundleName = fuzzData.GenerateStochasticString();

    uint32_t flagIndex = fuzzData.GetData<uint32_t>() % FLAG_LIST_SIZE;
    uint32_t statusIndex = 1;
    if (flagIndex != 0) {
        statusIndex = fuzzData.GetData<uint32_t>() % STATU_LIST_SIZE;
    }
    PermissionStatus testState = {
        .permissionName = permissionName,
        .grantStatus = STATU_LIST[statusIndex],
        .grantFlag = FLAG_LIST[flagIndex],
    };
    HapInfoParams testInfoParms = {
        .userID = fuzzData.GetData<int32_t>(),
        .bundleName = bundleName,
        .instIndex = 0,
        .appIDDesc = fuzzData.GenerateStochasticString()
    };
    PreAuthorizationInfo info1 = {
        .permissionName = permissionName,
        .userCancelable = fuzzData.GenerateStochasticBool()
    };

    uint32_t aplIndex = fuzzData.GetData<uint32_t>() % APL_LIST_SIZE;
    HapPolicy testPolicy = {
        .apl = APL_LIST[aplIndex],
        .domain = fuzzData.GenerateStochasticString(),
        .permStateList = {testState},
        .aclRequestedList = {permissionName},
        .preAuthorizationInfo = {info1}
    };

    hapInfoParcel.hapInfoParameter = testInfoParms;
    hapPolicyParcel.hapPolicy = testPolicy;
}

bool AllocHapTokenServiceFuzzTest(const uint8_t* data, size_t size)
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
        IAccessTokenManagerIpcCode::COMMAND_ALLOC_HAP_TOKEN);

    MessageParcel reply;
    MessageOption option;
    bool enable = ((size % CONSTANTS_NUMBER_TEN) == 0);
    if (enable) {
        setuid(CONSTANTS_NUMBER_TEN);
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
    OHOS::AllocHapTokenServiceFuzzTest(data, size);
    return 0;
}
