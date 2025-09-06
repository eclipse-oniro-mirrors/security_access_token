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

#include "sethapwithfgreminderstub_fuzzer.h"

#include <string>
#include <thread>
#include <vector>

#undef private
#include "accesstoken_fuzzdata.h"
#include "accesstoken_kit.h"
#include "fuzzer/FuzzedDataProvider.h"
#include "iprivacy_manager.h"
#include "privacy_manager_service.h"
#include "nativetoken_kit.h"
#include "token_setproc.h"

using namespace std;
using namespace OHOS::Security::AccessToken;
const int CONSTANTS_NUMBER_TWO = 2;
static const int32_t ROOT_UID = 0;

namespace OHOS {
    void GetNativeToken()
    {
        uint64_t tokenId;
        const char** perms = new (std::nothrow) const char *[1];
        if (perms == nullptr) {
            return;
        }

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

        FuzzedDataProvider provider(data, size);
        GetNativeToken();

        if (size > sizeof(uint32_t) + sizeof(bool)) {
            AccessTokenID tokenId = ConsumeTokenId(provider);
            bool isAllowed = provider.ConsumeBool();

            MessageParcel datas;
            datas.WriteInterfaceToken(IPrivacyManager::GetDescriptor());
            if (!datas.WriteUint32(tokenId)) {
                return false;
            }
            if (!datas.WriteInt32(isAllowed ? 1 : 0)) {
                return false;
            }

            uint32_t code = static_cast<uint32_t>(
                IPrivacyManagerIpcCode::COMMAND_SET_HAP_WITH_F_G_REMINDER);

            MessageParcel reply;
            MessageOption option;
            bool enable = ((provider.ConsumeIntegral<int32_t>() % CONSTANTS_NUMBER_TWO) == 0);
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
