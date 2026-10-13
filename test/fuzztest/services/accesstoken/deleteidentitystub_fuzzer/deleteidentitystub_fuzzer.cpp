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

#include "deleteidentitystub_fuzzer.h"

#include <sys/types.h>
#include <unistd.h>
#include <cstddef>
#include <cstdint>
#include <map>
#include <string>
#include <vector>

#undef private
#include "access_token.h"
#include "accesstoken_fuzzdata.h"
#include "accesstoken_info_manager.h"
#include "accesstoken_kit.h"
#define private public
#include "accesstoken_manager_service.h"
#undef private
#include "fuzzer/FuzzedDataProvider.h"
#include "iaccess_token_manager.h"
#include "token_setproc.h"

using namespace std;
using namespace OHOS::Security::AccessToken;

namespace {
const int32_t ROOT_UID = 0;
const int32_t CONSTANTS_NUMBER_TWO = 2;
const int32_t CONSTANTS_NUMBER_THREE = 3;

// ReservedType::NONE(0) ~ ReservedType::RESERVED_DATA(2):
// cover valid values and sentinel values to test boundary validation
const int32_t RESERVED_TYPE_MIN = -2;
const int32_t RESERVED_TYPE_MAX = 4;

static HapInfoParams g_InfoParms = {
    .userID = 1,
    .bundleName = "deleteidentitystub.fuzztest.bundle",
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
} // namespace

namespace OHOS {
    bool DeleteIdentityStubFuzzTest(const uint8_t* data, size_t size)
    {
#ifdef SPM_DATA_ENABLE
        if ((data == nullptr) || (size == 0)) {
            return false;
        }

        FuzzedDataProvider provider(data, size);

        // tokenID: mix real tokenID=0 (bundle-only path), random ids, and valid existing ids
        AccessTokenID tokenId;
        int32_t tokenIdMode = provider.ConsumeIntegralInRange<int32_t>(0, 2);
        if (tokenIdMode == 0) {
            tokenId = 0; // trigger bundle-only cleanup path
        } else {
            tokenId = ConsumeTokenId(provider);
        }

        // bundleName: mix empty, random, and well-formed names
        std::string bundleName;
        int32_t nameMode = provider.ConsumeIntegralInRange<int32_t>(0, 2);
        if (nameMode == 0) {
            bundleName = ""; // empty bundleName: triggers ERR_PARAM_INVALID
        } else if (nameMode == 1) {
            bundleName = "deleteidentitystub.fuzztest.bundle";
        } else {
            bundleName = provider.ConsumeRandomLengthString();
        }

        // type: cover valid (ReservedType::NONE=0, ReservedType::RESERVED_IDENTITY=1,
        // ReservedType::RESERVED_DATA=2) and invalid (sentinel values and out-of-range)
        int32_t type = provider.ConsumeIntegralInRange<int32_t>(RESERVED_TYPE_MIN, RESERVED_TYPE_MAX);

        MessageParcel datas;
        datas.WriteInterfaceToken(IAccessTokenManager::GetDescriptor());
        if (!datas.WriteUint32(tokenId) || !datas.WriteString(bundleName) || !datas.WriteInt32(type)) {
            return false;
        }

        uint32_t code = static_cast<uint32_t>(IAccessTokenManagerIpcCode::COMMAND_DELETE_IDENTITY);

        MessageParcel reply;
        MessageOption option;

        // Occasionally allocate a real HAP token so some calls hit valid-token paths
        AccessTokenID tokenIdHap = 0;
        bool enableHap = ((provider.ConsumeIntegral<int32_t>() % CONSTANTS_NUMBER_THREE) == 0);
        if (enableHap) {
            AccessTokenIDEx tokenIdEx = AccessTokenKit::AllocHapToken(g_InfoParms, g_PolicyPrams);
            tokenIdHap = tokenIdEx.tokenIDEx;
            if (tokenIdHap != 0) {
                SetSelfTokenID(tokenIdHap);
                uint32_t hapSize = 0;
                uint32_t nativeSize = 0;
                uint32_t pefDefSize = 0;
                uint32_t dlpSize = 0;
                std::map<int32_t, TokenIdInfo> tokenIdAplMap;
                AccessTokenInfoManager::GetInstance().Init(hapSize, nativeSize, pefDefSize, dlpSize, tokenIdAplMap);
            } else {
                enableHap = false; // allocation failed: skip the cleanup branch below
            }
        }

        // Occasionally drop to non-root uid to exercise permission denial path
        bool enableNonRoot = ((provider.ConsumeIntegral<int32_t>() % CONSTANTS_NUMBER_TWO) == 0);
        if (enableNonRoot) {
            setuid(CONSTANTS_NUMBER_TWO);
        }
        DelayedSingleton<AccessTokenManagerService>::GetInstance()->OnRemoteRequest(code, datas, reply, option);
        setuid(ROOT_UID);

        if (enableHap) {
            AccessTokenKit::DeleteToken(tokenIdHap);
            AccessTokenID hdcd = AccessTokenKit::GetNativeTokenId("hdcd");
            SetSelfTokenID(hdcd);
        }
#else
        (void)data;
        (void)size;
#endif
        return true;
    }

void Initialize()
{
#ifdef SPM_DATA_ENABLE
    DelayedSingleton<AccessTokenManagerService>::GetInstance()->Initialize();
#endif
}
} // namespace OHOS

extern "C" int LLVMFuzzerInitialize(int *argc, char ***argv)
{
    OHOS::Initialize();
    return 0;
}

/* Fuzzer entry point */
extern "C" int LLVMFuzzerTestOneInput(const uint8_t* data, size_t size)
{
    /* Run your code on data */
    OHOS::DeleteIdentityStubFuzzTest(data, size);
    return 0;
}
