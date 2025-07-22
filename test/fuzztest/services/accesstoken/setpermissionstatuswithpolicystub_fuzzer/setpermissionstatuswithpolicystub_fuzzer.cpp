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

#include "setpermissionstatuswithpolicystub_fuzzer.h"

#include <vector>

#include "access_token.h"
#include "accesstoken_manager_service.h"
#include "fuzzer/FuzzedDataProvider.h"
#include "iaccess_token_manager.h"

using namespace std;
using namespace OHOS::Security::AccessToken;

const int CONSTANTS_NUMBER_ONE = 1;
const int CONSTANTS_NUMBER_TEN = 10;
const uint32_t MAX_PERMISSION_LIST_SIZE = 1024;
static const int32_t ROOT_UID = 0;

namespace OHOS {
bool SetPermissionStatusWithPolicyStubFuzzTest(const uint8_t* data, size_t size)
{
    if ((data == nullptr) || (size == 0)) {
        return false;
    }

    FuzzedDataProvider provider(data, size);
    AccessTokenID tokenId = provider.ConsumeIntegral<AccessTokenID>();
    uint32_t permListSize =
        provider.ConsumeIntegralInRange<uint32_t>(CONSTANTS_NUMBER_ONE, MAX_PERMISSION_LIST_SIZE);
    std::vector<std::string> permissionList;
    for (size_t i = 0; i < permListSize; i++) {
        std::string permission = provider.ConsumeRandomLengthString();
        if (!permission.empty()) {
            permissionList.push_back(permission);
        }
    }
    uint32_t flag = static_cast<uint32_t>(TypePermissionFlag::PERMISSION_FIXED_BY_ADMIN_POLICY);
    int32_t status = TypePermissionState::PERMISSION_DENIED;
    MessageParcel datas;
    if (!datas.WriteInterfaceToken(IAccessTokenManager::GetDescriptor())) {
        return false;
    }
    if (!datas.WriteUint32(tokenId) || !datas.WriteStringVector(permissionList) ||
        !datas.WriteUint32(status) || !datas.WriteInt32(flag)) {
        return false;
    }

    uint32_t code = static_cast<uint32_t>(IAccessTokenManagerIpcCode::COMMAND_SET_PERMISSION_STATUS_WITH_POLICY);

    MessageParcel reply;
    MessageOption option;
    if (((provider.ConsumeIntegral<int32_t>() % CONSTANTS_NUMBER_TEN) == 0)) {
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
    OHOS::SetPermissionStatusWithPolicyStubFuzzTest(data, size);
    return 0;
}
