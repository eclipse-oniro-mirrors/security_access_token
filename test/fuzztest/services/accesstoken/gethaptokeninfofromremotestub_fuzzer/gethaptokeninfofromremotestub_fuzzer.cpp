/*
 * Copyright (c) 2023-2026 Huawei Device Co., Ltd.
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

#include "gethaptokeninfofromremotestub_fuzzer.h"

#include <string>
#include <thread>
#include <vector>
#undef private
#include "accesstoken_fuzzdata.h"
#include "accesstoken_info_manager.h"
#include "accesstoken_kit.h"
#define private public
#include "accesstoken_manager_service.h"
#undef private
#include "mock_permission.h"
#include "fuzzer/FuzzedDataProvider.h"
#include "iaccess_token_manager.h"

using namespace std;
using namespace OHOS::Security::AccessToken;
namespace OHOS {
namespace {
#ifdef TOKEN_SYNC_ENABLE
const std::string TEST_REMOTE_DEVICE_ID = "fuzz_remote_device";
const std::string TEST_NETWORK_ID = "fuzz_network_id";
constexpr AccessTokenID TEST_REMOTE_TOKEN_ID = 0x20100000;
#endif
}

#ifdef TOKEN_SYNC_ENABLE
AccessTokenID EnsureRemoteMapTokenId()
{
    static AccessTokenID mapTokenId = INVALID_TOKENID;
    if (mapTokenId != INVALID_TOKENID) {
        return mapTokenId;
    }

    HapTokenInfoForSync remoteTokenInfo = {
        .baseInfo = {
            .ver = 1,
            .userID = 1,
            .bundleName = "fuzz.remote.bundle",
            .apiVersion = 8,
            .instIndex = 0,
            .dlpType = static_cast<int32_t>(HapDlpType::DLP_COMMON),
            .tokenID = TEST_REMOTE_TOKEN_ID,
            .tokenAttr = 0,
        },
        .permStateList = {
            {
                .permissionName = "ohos.permission.INTERNET",
                .grantStatus = PermissionState::PERMISSION_GRANTED,
                .grantFlag = PermissionFlag::PERMISSION_USER_SET
            }
        }
    };

    int32_t ret = AccessTokenInfoManager::GetInstance().SetRemoteHapTokenInfo(
        TEST_REMOTE_DEVICE_ID, remoteTokenInfo);
    if (ret != RET_SUCCESS) {
        return INVALID_TOKENID;
    }

    uint64_t fullTokenId = AccessTokenInfoManager::GetInstance().AllocLocalTokenID(
        TEST_NETWORK_ID, TEST_REMOTE_TOKEN_ID);
    if (fullTokenId == 0) {
        return INVALID_TOKENID;
    }
    AccessTokenIDEx tokenIdEx = { .tokenIDEx = fullTokenId };
    mapTokenId = tokenIdEx.tokenIdExStruct.tokenID;
    return mapTokenId;
}
#endif

    bool GetHapTokenInfoFromRemoteStubFuzzTest(const uint8_t* data, size_t size)
    {
    #ifdef TOKEN_SYNC_ENABLE
        if ((data == nullptr) || (size == 0)) {
            return false;
        }

        MockToken mock({}, false);
        FuzzedDataProvider provider(data, size);
        AccessTokenID validTokenId = EnsureRemoteMapTokenId();
        if (validTokenId == INVALID_TOKENID) {
            return false;
        }
        AccessTokenID tokenId = provider.ConsumeBool() ? validTokenId : ConsumeTokenId(provider);

        MessageParcel datas;
        datas.WriteInterfaceToken(IAccessTokenManager::GetDescriptor());
        if (!datas.WriteUint32(tokenId)) {
            return false;
        }

        uint32_t code = static_cast<uint32_t>(
            IAccessTokenManagerIpcCode::COMMAND_GET_HAP_TOKEN_INFO_FROM_REMOTE);

        MessageParcel reply;
        MessageOption option;
        DelayedSingleton<AccessTokenManagerService>::GetInstance()->OnRemoteRequest(code, datas, reply, option);

        return true;
    #else
        return true;
    #endif
    }

void Initialize()
{
    DelayedSingleton<AccessTokenManagerService>::GetInstance()->Initialize();
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
    OHOS::GetHapTokenInfoFromRemoteStubFuzzTest(data, size);
    return 0;
}
