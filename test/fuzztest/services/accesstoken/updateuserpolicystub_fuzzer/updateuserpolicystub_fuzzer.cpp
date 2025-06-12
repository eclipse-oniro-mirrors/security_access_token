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

#include "updateuserpolicystub_fuzzer.h"

#include <string>
#include <thread>
#include <vector>
#undef private
#include "access_token.h"
#include "accesstoken_fuzzdata.h"
#include "accesstoken_kit.h"
#include "accesstoken_manager_service.h"
#include "iaccess_token_manager.h"
#include "nativetoken_kit.h"
#include "token_setproc.h"

using namespace std;
using namespace OHOS::Security::AccessToken;
static AccessTokenID g_selfTokenId = 0;
static uint64_t g_mockTokenId = 0;
const int32_t CONSTANTS_NUMBER_TWO = 2;

namespace OHOS {
    void GetNativeToken()
    {
        if (g_mockTokenId != 0) {
            SetSelfTokenID(g_mockTokenId);
            return;
        }
        const char** perms = new (std::nothrow) const char *[1];
        if (perms == nullptr) {
            return;
        }

        perms[0] = "ohos.permission.GET_SENSITIVE_PERMISSIONS";

        NativeTokenInfoParams infoInstance = {
            .dcapsNum = 0,
            .permsNum = 1,
            .aclsNum = 0,
            .dcaps = nullptr,
            .perms = perms,
            .acls = nullptr,
            .processName = "updateuserpolicystub_fuzzer_test",
            .aplStr = "system_core",
        };

        g_mockTokenId = GetAccessTokenId(&infoInstance);
        g_selfTokenId = GetSelfTokenID();
        SetSelfTokenID(g_mockTokenId);
        AccessTokenKit::ReloadNativeTokenInfo();
        delete[] perms;
    }
    bool UpdateUserPolicyStubFuzzTest(const uint8_t* data, size_t size)
    {
        if ((data == nullptr) || (size == 0)) {
            return false;
        }

        AccessTokenFuzzData fuzzData(data, size);

        UserState userList;
        userList.userId = fuzzData.GetData<int32_t>();
        userList.isActive = fuzzData.GenerateStochasticBool();

        MessageParcel datas;
        datas.WriteInterfaceToken(IAccessTokenManager::GetDescriptor());
        if (!datas.WriteUint32(1)) {
            return false;
        }
        if (!datas.WriteInt32(userList.userId)) {
            return false;
        }
        if (!datas.WriteBool(userList.isActive)) {
            return false;
        }

        uint32_t code = static_cast<uint32_t>(
            IAccessTokenManagerIpcCode::COMMAND_UPDATE_USER_POLICY);

        MessageParcel reply;
        MessageOption option;
        bool enable = ((size % CONSTANTS_NUMBER_TWO) == 0);
        if (enable) {
            GetNativeToken();
        } else {
            SetSelfTokenID(g_selfTokenId);
        }
        DelayedSingleton<AccessTokenManagerService>::GetInstance()->OnRemoteRequest(code, datas, reply, option);

        return true;
    }
} // namespace OHOS

/* Fuzzer entry point */
extern "C" int LLVMFuzzerTestOneInput(const uint8_t* data, size_t size)
{
    /* Run your code on data */
    OHOS::UpdateUserPolicyStubFuzzTest(data, size);
    return 0;
}
