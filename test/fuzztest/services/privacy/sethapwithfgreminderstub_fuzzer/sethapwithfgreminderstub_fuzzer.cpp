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

#include "sethapwithfgreminderstub_fuzzer.h"

#include <string>
#include <thread>
#include <vector>

#include "accesstoken_fuzzdata.h"
#undef private
#include "accesstoken_kit.h"
#include "i_privacy_manager.h"
#include "privacy_manager_service.h"
#include "nativetoken_kit.h"
#include "token_setproc.h"

using namespace std;
using namespace OHOS::Security::AccessToken;
const int CONSTANTS_NUMBER_TWO = 2;
static const int32_t ROOT_UID = 0;

namespace OHOS {
const uint8_t *g_baseFuzzData = nullptr;
size_t g_baseFuzzSize = 0;
size_t g_baseFuzzPos = 0;
    void GetNativeToken()
    {
        uint64_t tokenId;
        const char **perms = new const char *[1];
        perms[0] = "ohos.permission.SET_FOREGROUND_HAP_REMINDER"; // 3 means the third permission

        NativeTokenInfoParams infoInstance = {
            .dcapsNum = 0,
            .permsNum = 1,
            .aclsNum = 0,
            .dcaps = nullptr,
            .perms = perms,
            .acls = nullptr,
            .processName = "sethapwithfgreminderstub_fuzzer_test",
            .aplStr = "system_core",
        };

        tokenId = GetAccessTokenId(&infoInstance);
        SetSelfTokenID(tokenId);
        AccessTokenKit::ReloadNativeTokenInfo();
        delete[] perms;
    }

    bool SetHapWithFGReminderStubFuzzTest(const uint8_t* data, size_t size)
    {
        if ((data == nullptr) || (size == 0)) {
            return false;
        }
        GetNativeToken();
        AccessTokenFuzzData fuzzData(data, size);

        if (size > sizeof(uint32_t) + sizeof(bool)) {
            uint32_t tokenId = fuzzData.GetData<uint32_t>();
            bool isAllowed = fuzzData.GenerateRandomBool();

            MessageParcel datas;
            datas.WriteInterfaceToken(IPrivacyManager::GetDescriptor());
            if (!datas.WriteUint32(tokenId)) {
                return false;
            }
            if (!datas.WriteBool(isAllowed)) {
                return false;
            }

            uint32_t code = static_cast<uint32_t>(
                PrivacyInterfaceCode::SET_HAP_WITH_FOREGROUND_REMINDER);

            MessageParcel reply;
            MessageOption option;
            bool enable = ((size % CONSTANTS_NUMBER_TWO) == 0);
            if (enable) {
                setuid(CONSTANTS_NUMBER_TWO);
            }
            DelayedSingleton<PrivacyManagerService>::GetInstance()->OnRemoteRequest(code, datas, reply, option);
            setuid(ROOT_UID);
        }
        return true;
    }
} // namespace OHOS

/* Fuzzer entry point */
extern "C" int LLVMFuzzerTestOneInput(const uint8_t* data, size_t size)
{
    /* Run your code on data */
    OHOS::SetHapWithFGReminderStubFuzzTest(data, size);
    return 0;
}
