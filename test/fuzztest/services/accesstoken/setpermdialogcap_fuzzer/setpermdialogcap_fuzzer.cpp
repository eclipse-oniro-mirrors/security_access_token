/*
 * Copyright (c) 2023-2025 Huawei Device Co., Ltd.
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

#include "setpermdialogcap_fuzzer.h"

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
#include "securec.h"
#include "token_setproc.h"

using namespace std;
using namespace OHOS::Security::AccessToken;

namespace OHOS {
    void GetNativeToken()
    {
        uint64_t tokenId;
        const char** perms = new (std::nothrow) const char *[1];
        if (perms == nullptr) {
            return;
        }

        perms[0] = "ohos.permission.DISABLE_PERMISSION_DIALOG"; // 3 means the third permission

        NativeTokenInfoParams infoInstance = {
            .dcapsNum = 0,
            .permsNum = 1,
            .aclsNum = 0,
            .dcaps = nullptr,
            .perms = perms,
            .acls = nullptr,
            .processName = "setpermdialogcap_fuzzer",
            .aplStr = "system_core",
        };

        tokenId = GetAccessTokenId(&infoInstance);
        SetSelfTokenID(tokenId);
        AccessTokenKit::ReloadNativeTokenInfo();
        delete[] perms;
    }

    bool SetPermDialogCapFuzzTest(const uint8_t* data, size_t size)
    {
        if ((data == nullptr) || (size == 0)) {
            return false;
        }

        AccessTokenFuzzData fuzzData(data, size);
        HapBaseInfoParcel baseInfoParcel;
        baseInfoParcel.hapBaseInfo.userID = fuzzData.GetData<int32_t>();
        baseInfoParcel.hapBaseInfo.bundleName = fuzzData.GenerateStochasticString();
        baseInfoParcel.hapBaseInfo.instIndex = fuzzData.GetData<int32_t>();

        MessageParcel datas;
        datas.WriteInterfaceToken(IAccessTokenManager::GetDescriptor());
        if (!datas.WriteParcelable(&baseInfoParcel)) {
            return false;
        }
        uint32_t code = static_cast<uint32_t>(IAccessTokenManagerIpcCode::COMMAND_SET_PERM_DIALOG_CAP);

        MessageParcel reply;
        MessageOption option;

        DelayedSingleton<AccessTokenManagerService>::GetInstance()->OnRemoteRequest(code, datas, reply, option);
        return true;
    }
}

/* Fuzzer entry point */
extern "C" int LLVMFuzzerTestOneInput(const uint8_t* data, size_t size)
{
    /* Run your code on data */
    OHOS::GetNativeToken();
    OHOS::SetPermDialogCapFuzzTest(data, size);
    return 0;
}
