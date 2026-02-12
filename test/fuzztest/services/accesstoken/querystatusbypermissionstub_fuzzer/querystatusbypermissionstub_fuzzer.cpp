/*
 * Copyright (c) 2026 Huawei Device Co., Ltd.
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

#include "querystatusbypermissionstub_fuzzer.h"

#include <sys/types.h>
#include <unistd.h>
#include <string>
#include <thread>
#include <vector>
#undef private
#include "access_token.h"
#include "accesstoken_fuzzdata.h"
#include "accesstoken_kit.h"
#define private public
#include "accesstoken_manager_service.h"
#undef private
#include "fuzzer/FuzzedDataProvider.h"
#include "iaccess_token_manager.h"
#include "nativetoken_kit.h"
#include "securec.h"
#include "token_setproc.h"

using namespace std;
using namespace OHOS;
using namespace OHOS::Security::AccessToken;
static constexpr int32_t CONSTANTS_NUMBER_TWO = 2;
static constexpr int32_t ROOT_UID = 0;

namespace OHOS {
bool QueryStatusByPermissionStubFuzzTest(const uint8_t* data, size_t size)
{
    if ((data == nullptr) || (size == 0)) {
        return false;
    }

    FuzzedDataProvider provider(data, size);

    // Prepare IPC data parcel
    MessageParcel datas;
    datas.WriteInterfaceToken(IAccessTokenManager::GetDescriptor());

    // Generate permission list with random size (0 to 1025 to test boundary)
    size_t permListSize = provider.ConsumeIntegralInRange<size_t>(0, 1025);
    if (!datas.WriteUint32(permListSize)) {
        return false;
    }

    for (size_t i = 0; i < permListSize; i++) {
        std::string permName = ConsumePermissionName(provider);
        if (!datas.WriteString(permName)) {
            return false;
        }
    }

    // Write onlyHap flag
    bool onlyHap = provider.ConsumeBool();
    if (!datas.WriteBool(onlyHap)) {
        return false;
    }

    // Get IPC command code
    uint32_t code = static_cast<uint32_t>(
        IAccessTokenManagerIpcCode::COMMAND_QUERY_STATUS_BY_PERMISSION);

    MessageParcel reply;
    MessageOption option;

    // Optionally change UID to test different permission scenarios
    bool enable = ((provider.ConsumeIntegral<int32_t>() % CONSTANTS_NUMBER_TWO) == 0);
    if (enable) {
        setuid(CONSTANTS_NUMBER_TWO);
    }

    DelayedSingleton<AccessTokenManagerService>::GetInstance()->OnRemoteRequest(
        code, datas, reply, option);

    setuid(ROOT_UID);
    return true;
}

void Initialize()
{
    DelayedSingleton<AccessTokenManagerService>::GetInstance()->Initialize();
}
}

extern "C" int LLVMFuzzerInitialize(int *argc, char ***argv)
{
    uint64_t tokenId;
    const char** perms = new (std::nothrow) const char *[1];
    if (perms == nullptr) {
        return -1;
    }

    perms[0] = "ohos.permission.GET_SENSITIVE_PERMISSIONS";

    NativeTokenInfoParams infoInstance = {
        .dcapsNum = 0,
        .permsNum = 1,
        .aclsNum = 0,
        .dcaps = nullptr,
        .perms = perms,
        .acls = nullptr,
        .processName = "querystatusbypermissionstub_fuzzer_test",
        .aplStr = "system_core",
    };

    tokenId = GetAccessTokenId(&infoInstance);
    SetSelfTokenID(tokenId);
    AccessTokenKit::ReloadNativeTokenInfo();
    delete[] perms;

    OHOS::Initialize();
    return 0;
}

/* Fuzzer entry point */
extern "C" int LLVMFuzzerTestOneInput(const uint8_t* data, size_t size)
{
    /* Run your code on data */
    OHOS::QueryStatusByPermissionStubFuzzTest(data, size);
    return 0;
}
