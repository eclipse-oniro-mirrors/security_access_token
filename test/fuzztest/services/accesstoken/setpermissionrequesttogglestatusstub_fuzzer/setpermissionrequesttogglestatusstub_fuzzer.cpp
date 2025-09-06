/*
 * Copyright (c) 2024-2025 Huawei Device Co., Ltd.
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

#include "setpermissionrequesttogglestatusstub_fuzzer.h"

#include <sys/types.h>
#include <unistd.h>
#include <string>
#include <thread>
#include <vector>

#undef private
#include "accesstoken_fuzzdata.h"
#include "accesstoken_manager_service.h"
#include "fuzzer/FuzzedDataProvider.h"
#include "iaccess_token_manager.h"

using namespace std;
using namespace OHOS::Security::AccessToken;
const int CONSTANTS_NUMBER_TWO = 2;
static const int32_t ROOT_UID = 0;
static const int STATUS_MAX = 2;

namespace OHOS {
    bool SetPermissionRequestToggleStatusStubFuzzTest(const uint8_t* data, size_t size)
    {
        if ((data == nullptr) || (size == 0)) {
            return false;
        }

        FuzzedDataProvider provider(data, size);
        std::string permissionName = ConsumePermissionName(provider);
        uint32_t status = provider.ConsumeIntegral<uint32_t>() % STATUS_MAX;
        int32_t userID = provider.ConsumeIntegral<int32_t>();
        MessageParcel sendData;
        if (!sendData.WriteInterfaceToken(IAccessTokenManager::GetDescriptor()) ||
            !sendData.WriteString(permissionName) || !sendData.WriteUint32(status) ||
            !sendData.WriteInt32(userID)) {
            return false;
        }

        uint32_t code = static_cast<uint32_t>(
            IAccessTokenManagerIpcCode::COMMAND_SET_PERMISSION_REQUEST_TOGGLE_STATUS);

        MessageParcel reply;
        MessageOption option;
        bool enable = ((provider.ConsumeIntegral<int32_t>() % CONSTANTS_NUMBER_TWO) == 0);
        if (enable) {
            setuid(CONSTANTS_NUMBER_TWO);
        }
        DelayedSingleton<AccessTokenManagerService>::GetInstance()->OnRemoteRequest(code, sendData, reply, option);
        setuid(ROOT_UID);

        return true;
    }
} // namespace OHOS

/* Fuzzer entry point */
extern "C" int LLVMFuzzerTestOneInput(const uint8_t* data, size_t size)
{
    /* Run your code on data */
    OHOS::SetPermissionRequestToggleStatusStubFuzzTest(data, size);
    return 0;
}
