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

#include "grantpermissionstub_fuzzer.h"

#include <sys/types.h>
#include <unistd.h>
#include <string>
#include <thread>
#include <vector>
#undef private
#include "access_token.h"
#include "accesstoken_fuzzdata.h"
#include "accesstoken_info_manager.h"
#include "accesstoken_kit.h"
#include "accesstoken_manager_service.h"
#include "iaccess_token_manager.h"
#include "token_setproc.h"

using namespace std;
using namespace OHOS::Security::AccessToken;
static HapInfoParams g_InfoParms = {
    .userID = 1,
    .bundleName = "GrantPermissionStubFuzzTest",
    .instIndex = 0,
    .appIDDesc = "test.bundle",
    .isSystemApp = false
};
static HapPolicyParams g_PolicyPrams = {
    .apl = APL_NORMAL,
    .domain = "test.domain",
    .permList = {},
    .permStateList = {}
};
const int CONSTANTS_NUMBER_TWO = 2;
const int CONSTANTS_NUMBER_THREE = 3;
static const int32_t ROOT_UID = 0;

namespace OHOS {
    bool GrantPermissionStubFuzzTest(const uint8_t* data, size_t size)
    {
        if ((data == nullptr) || (size == 0)) {
            return false;
        }
        AccessTokenFuzzData fuzzData(data, size);
        AccessTokenID tokenId = fuzzData.GetData<AccessTokenID>();
        std::string testName(fuzzData.GenerateStochasticString());
        MessageParcel datas;
        datas.WriteInterfaceToken(IAccessTokenManager::GetDescriptor());
        if (!datas.WriteUint32(tokenId) || !datas.WriteString(testName) ||
            !datas.WriteInt32(PERMISSION_USER_SET)) {
            return false;
        }

        uint32_t code = static_cast<uint32_t>(
            IAccessTokenManagerIpcCode::COMMAND_GRANT_PERMISSION);

        MessageParcel reply;
        MessageOption option;
        AccessTokenID tokenIdHap;
        bool enable2 = ((size % CONSTANTS_NUMBER_THREE) == 0);
        if (enable2) {
            AccessTokenIDEx tokenIdEx = AccessTokenKit::AllocHapToken(g_InfoParms, g_PolicyPrams);
            tokenIdHap = tokenIdEx.tokenIDEx;
            SetSelfTokenID(tokenIdHap);
            uint32_t hapSize = 0;
            uint32_t nativeSize = 0;
            uint32_t pefDefSize = 0;
            uint32_t dlpSize = 0;
            AccessTokenInfoManager::GetInstance().Init(hapSize, nativeSize, pefDefSize, dlpSize);
        }
        bool enable = ((size % CONSTANTS_NUMBER_TWO) == 0);
        if (enable) {
            setuid(CONSTANTS_NUMBER_TWO);
        }
        DelayedSingleton<AccessTokenManagerService>::GetInstance()->OnRemoteRequest(code, datas, reply, option);
        setuid(ROOT_UID);
        if (enable2) {
            AccessTokenKit::DeleteToken(tokenIdHap);
            AccessTokenID hdcd = AccessTokenKit::GetNativeTokenId("hdcd");
            SetSelfTokenID(hdcd);
        }

        return true;
    }
} // namespace OHOS

/* Fuzzer entry point */
extern "C" int LLVMFuzzerTestOneInput(const uint8_t* data, size_t size)
{
    /* Run your code on data */
    OHOS::GrantPermissionStubFuzzTest(data, size);
    return 0;
}
