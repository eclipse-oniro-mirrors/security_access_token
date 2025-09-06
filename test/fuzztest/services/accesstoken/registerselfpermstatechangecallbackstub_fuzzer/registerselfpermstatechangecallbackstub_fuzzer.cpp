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

#include "registerselfpermstatechangecallbackstub_fuzzer.h"

#include <string>
#include <thread>
#include <vector>

#undef private
#include "access_token.h"
#define private public
#include "accesstoken_fuzzdata.h"
#include "accesstoken_id_manager.h"
#include "accesstoken_kit.h"
#include "accesstoken_manager_client.h"
#define private public
#include "accesstoken_manager_service.h"
#undef private
#include "fuzzer/FuzzedDataProvider.h"
#include "iaccess_token_manager.h"
#include "token_setproc.h"

using namespace std;
using namespace OHOS::Security::AccessToken;
static uint64_t g_selfTokenId = 0;
static uint64_t g_mockTokenId = 0;
const int32_t CONSTANTS_NUMBER_TWO = 2;

class CbCustomizeTest2 : public PermStateChangeCallbackCustomize {
public:
    explicit CbCustomizeTest2(const PermStateChangeScope &scopeInfo)
        : PermStateChangeCallbackCustomize(scopeInfo)
    {
    }

    ~CbCustomizeTest2()
    {}

    virtual void PermStateChangeCallback(PermStateChangeInfo& result)
    {
        ready_ = true;
    }

    bool ready_ = false;
};

namespace OHOS {
    void GetHapToken()
    {
        if (g_mockTokenId != 0) {
            SetSelfTokenID(g_mockTokenId);
            return;
        }
        HapInfoParams infoParams = {
            .userID = 0,
            .bundleName = "registerselfpermstatechangecallbackstub.fuzzer",
            .instIndex = 0,
            .appIDDesc = "fuzzer",
            .apiVersion = 8
        };

        HapPolicyParams policyParams = {
            .apl = APL_SYSTEM_CORE,
            .domain = "test_domain"
        };

        AccessTokenIDEx fullTokenId = AccessTokenKit::AllocHapToken(infoParams, policyParams);
        g_mockTokenId = fullTokenId.tokenIDEx;
        SetSelfTokenID(g_mockTokenId);
        AccessTokenIDManager::GetInstance().tokenIdSet_.insert(fullTokenId.tokenIdExStruct.tokenID);
    }

    bool RegisterSelfPermStateChangeCallbackStubFuzzTest(const uint8_t* data, size_t size)
    {
        if ((data == nullptr) || (size == 0)) {
            return false;
        }

        FuzzedDataProvider provider(data, size);
        AccessTokenID tokenId = ConsumeTokenId(provider);
        std::string permissionName = ConsumePermissionName(provider);

        PermStateChangeScope scopeInfo;
        scopeInfo.permList = { permissionName };
        scopeInfo.tokenIDs = { tokenId };
        auto callbackPtr = std::make_shared<CbCustomizeTest2>(scopeInfo);

        PermStateChangeScopeParcel scopeParcel;
        scopeParcel.scope = scopeInfo;

        sptr<PermissionStateChangeCallback> callback;
        callback = new (std::nothrow) PermissionStateChangeCallback(callbackPtr);

        MessageParcel datas;
        datas.WriteInterfaceToken(IAccessTokenManager::GetDescriptor());
        if (!datas.WriteParcelable(&scopeParcel)) {
                return false;
        }
        if (!datas.WriteRemoteObject(callback->AsObject())) {
            return false;
        }

        uint32_t code = static_cast<uint32_t>(
            IAccessTokenManagerIpcCode::COMMAND_REGISTER_SELF_PERM_STATE_CHANGE_CALLBACK);

        MessageParcel reply;
        MessageOption option;
        bool enable = ((provider.ConsumeIntegral<int32_t>() % CONSTANTS_NUMBER_TWO) == 0);
        if (enable) {
            GetHapToken();
        } else {
            SetSelfTokenID(g_selfTokenId);
        }
        DelayedSingleton<AccessTokenManagerService>::GetInstance()->OnRemoteRequest(code, datas, reply, option);

        code = static_cast<uint32_t>(
            IAccessTokenManagerIpcCode::COMMAND_UN_REGISTER_SELF_PERM_STATE_CHANGE_CALLBACK);
        MessageParcel datas2;
        datas2.WriteInterfaceToken(IAccessTokenManager::GetDescriptor());
        DelayedSingleton<AccessTokenManagerService>::GetInstance()->OnRemoteRequest(code, datas2, reply, option);

        return true;
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
    OHOS::RegisterSelfPermStateChangeCallbackStubFuzzTest(data, size);
    return 0;
}
