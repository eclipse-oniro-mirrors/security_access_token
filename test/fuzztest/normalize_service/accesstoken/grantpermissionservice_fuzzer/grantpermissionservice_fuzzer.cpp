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

#include "grantpermissionservice_fuzzer.h"

#include <sys/types.h>
#include <unistd.h>
#include <string>
#include <thread>
#include <vector>

#undef private
#include "access_token.h"
#include "accesstoken_info_manager.h"
#include "accesstoken_kit.h"
#include "accesstoken_manager_service.h"
#include "fuzzer/FuzzedDataProvider.h"
#include "iaccess_token_manager.h"
#include "token_setproc.h"

using namespace std;
using namespace OHOS::Security::AccessToken;
static HapInfoParams g_InfoParms = {
    .userID = 1,
    .bundleName = "GrantPermissionServiceFuzzTest",
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
const int CONSTANTS_NUMBER_FIVE = 5;
const int CONSTANTS_NUMBER_TEN = 10;
static const int32_t ROOT_UID = 0;
static const vector<PermissionFlag> FLAG_LIST = {
    PERMISSION_DEFAULT_FLAG,
    PERMISSION_USER_SET,
    PERMISSION_USER_FIXED,
    PERMISSION_SYSTEM_FIXED,
    PERMISSION_PRE_AUTHORIZED_CANCELABLE,
    PERMISSION_COMPONENT_SET,
    PERMISSION_FIXED_FOR_SECURITY_POLICY,
    PERMISSION_ALLOW_THIS_TIME
};
static const uint32_t FLAG_LIST_SIZE = 8;

namespace OHOS {
bool GrantPermissionServiceFuzzTest(const uint8_t* data, size_t size)
{
    if ((data == nullptr) || (size == 0)) {
        return false;
    }

    FuzzedDataProvider provider(data, size);
    AccessTokenID tokenId = provider.ConsumeIntegral<AccessTokenID>();
    std::string permissionName = provider.ConsumeRandomLengthString();
    uint32_t flagIndex = provider.ConsumeIntegral<uint32_t>() % FLAG_LIST_SIZE;
    PermissionFlag flag = FLAG_LIST[flagIndex];

    MessageParcel datas;
    datas.WriteInterfaceToken(IAccessTokenManager::GetDescriptor());
    if (!datas.WriteUint32(tokenId) || !datas.WriteString(permissionName) ||
        !datas.WriteInt32(flag)) {
        return false;
    }

    uint32_t code = static_cast<uint32_t>(
        IAccessTokenManagerIpcCode::COMMAND_GRANT_PERMISSION);

    MessageParcel reply;
    MessageOption option;
    AccessTokenID tokenIdHap;
    bool enable2 = ((provider.ConsumeIntegral<int32_t>() % CONSTANTS_NUMBER_TEN) > 0);
    if (enable2) {
        AccessTokenIDEx tokenIdEx = AccessTokenKit::AllocHapToken(g_InfoParms, g_PolicyPrams);
        tokenIdHap = tokenIdEx.tokenIDEx;
        SetSelfTokenID(tokenIdHap);
        uint32_t hapSize = 0;
        uint32_t nativeSize = 0;
        uint32_t pefDefSize = 0;
        uint32_t dlpSize = 0;
        std::map<int32_t, TokenIdInfo> tokenIdAplMap;
        AccessTokenInfoManager::GetInstance().Init(hapSize, nativeSize, pefDefSize, dlpSize, tokenIdAplMap);
    }
    bool enable = ((provider.ConsumeIntegral<int32_t>() % CONSTANTS_NUMBER_FIVE) == 0);
    if (enable) {
        setuid(CONSTANTS_NUMBER_FIVE);
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
    OHOS::GrantPermissionServiceFuzzTest(data, size);
    return 0;
}
