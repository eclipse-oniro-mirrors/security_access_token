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

#include "deleteremotetokenstub_fuzzer.h"

#include <string>
#include <thread>
#include <vector>

#undef private
#include "accesstoken_fuzzdata.h"
#include "accesstoken_info_manager.h"
#include "accesstoken_kit.h"
#include "device_manager.h"
#define private public
#include "accesstoken_manager_service.h"
#undef private
#include "mock_permission.h"
#include "fuzzer/FuzzedDataProvider.h"
#include "iaccess_token_manager.h"
#include "token_setproc.h"
using namespace std;
using namespace OHOS::Security::AccessToken;

namespace OHOS {
namespace {
#ifdef TOKEN_SYNC_ENABLE
class TestDmInitCallback final : public OHOS::DistributedHardware::DmInitCallback {
public:
    void OnRemoteDied() override
    {}
};

const std::string TEST_PKG_NAME = "com.softbus.test";
constexpr AccessTokenID TEST_REMOTE_TOKEN_ID = 0x20100000;
std::string g_remoteDeviceId;
std::string g_remoteNetworkId;
AccessTokenID g_tokenSyncTokenId = INVALID_TOKENID;
AccessTokenID g_hdcdTokenId = INVALID_TOKENID;
std::shared_ptr<TestDmInitCallback> g_dmInitCallback = std::make_shared<TestDmInitCallback>();

bool SetTokenSyncToken()
{
    if (g_tokenSyncTokenId == INVALID_TOKENID) {
        MockToken mock({}, false);
        g_tokenSyncTokenId = AccessTokenKit::GetNativeTokenId("token_sync_service");
        g_hdcdTokenId = AccessTokenKit::GetNativeTokenId("hdcd");
    }
    if (g_tokenSyncTokenId == INVALID_TOKENID) {
        return false;
    }
    return SetSelfTokenID(g_tokenSyncTokenId) == 0;
}
#endif
}

#ifdef TOKEN_SYNC_ENABLE
bool InitRemoteDeviceInfo()
{
    if (!g_remoteDeviceId.empty() && !g_remoteNetworkId.empty()) {
        return true;
    }
    if (DistributedHardware::DeviceManager::GetInstance().InitDeviceManager(
        TEST_PKG_NAME, g_dmInitCallback) != RET_SUCCESS) {
        return false;
    }

    DistributedHardware::DmDeviceInfo deviceInfo;
    if (DistributedHardware::DeviceManager::GetInstance().GetLocalDeviceInfo(
        TEST_PKG_NAME, deviceInfo) != RET_SUCCESS) {
        return false;
    }
    g_remoteNetworkId = std::string(deviceInfo.networkId);
    if (g_remoteNetworkId.empty()) {
        return false;
    }

    if (DistributedHardware::DeviceManager::GetInstance().GetUdidByNetworkId(
        TEST_PKG_NAME, g_remoteNetworkId, g_remoteDeviceId) != RET_SUCCESS) {
        return false;
    }
    return !g_remoteDeviceId.empty();
}

AccessTokenID EnsureRemoteMapTokenId()
{
    static AccessTokenID mapTokenId = INVALID_TOKENID;
    if (mapTokenId != INVALID_TOKENID) {
        return mapTokenId;
    }
    if (!InitRemoteDeviceInfo()) {
        return INVALID_TOKENID;
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
        g_remoteDeviceId, remoteTokenInfo);
    if (ret != RET_SUCCESS) {
        return INVALID_TOKENID;
    }

    uint64_t fullTokenId = AccessTokenInfoManager::GetInstance().AllocLocalTokenID(
        g_remoteNetworkId, TEST_REMOTE_TOKEN_ID);
    if (fullTokenId == 0) {
        return INVALID_TOKENID;
    }
    AccessTokenIDEx tokenIdEx = { .tokenIDEx = fullTokenId };
    mapTokenId = tokenIdEx.tokenIdExStruct.tokenID;
    return mapTokenId;
}
#endif

    bool DeleteRemoteTokenStubFuzzTest(const uint8_t* data, size_t size)
    {
    #ifdef TOKEN_SYNC_ENABLE
        if ((data == nullptr) || (size == 0)) {
            return false;
        }
        if (!SetTokenSyncToken()) {
            return false;
        }

        FuzzedDataProvider provider(data, size);
        AccessTokenID validTokenId = EnsureRemoteMapTokenId();
        if (validTokenId == INVALID_TOKENID) {
            return false;
        }
        std::string deviceID = provider.ConsumeBool() ? g_remoteDeviceId : provider.ConsumeRandomLengthString();
        AccessTokenID tokenId = provider.ConsumeBool() ? TEST_REMOTE_TOKEN_ID : ConsumeTokenId(provider);

        MessageParcel datas;
        datas.WriteInterfaceToken(IAccessTokenManager::GetDescriptor());
        if (!datas.WriteString(deviceID)) {
            return false;
        }
        if (!datas.WriteUint32(tokenId)) {
            return false;
        }
       
        uint32_t code = static_cast<uint32_t>(
            IAccessTokenManagerIpcCode::COMMAND_DELETE_REMOTE_TOKEN);

        MessageParcel reply;
        MessageOption option;
        DelayedSingleton<AccessTokenManagerService>::GetInstance()->OnRemoteRequest(code, datas, reply, option);
        if (g_hdcdTokenId != INVALID_TOKENID) {
            (void)SetSelfTokenID(g_hdcdTokenId);
        }

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
    OHOS::DeleteRemoteTokenStubFuzzTest(data, size);
    return 0;
}
