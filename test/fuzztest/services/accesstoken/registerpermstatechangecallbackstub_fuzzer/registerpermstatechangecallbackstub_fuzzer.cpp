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

#include "registerpermstatechangecallbackstub_fuzzer.h"

#include <string>
#include <thread>
#include <vector>

#undef private
#include "accesstoken_manager_client.h"
#include "accesstoken_manager_service.h"
#include "fuzzer/FuzzedDataProvider.h"
#include "iaccess_token_manager.h"

using namespace std;
using namespace OHOS::Security::AccessToken;

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
    bool RegisterPermStateChangeCallbackStubFuzzTest(const uint8_t* data, size_t size)
    {
        if ((data == nullptr) || (size == 0)) {
            return false;
        }

        FuzzedDataProvider provider(data, size);
        AccessTokenID tokenId = provider.ConsumeIntegral<AccessTokenID>();
        std::string permissionName = provider.ConsumeRandomLengthString();

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
            IAccessTokenManagerIpcCode::COMMAND_REGISTER_PERM_STATE_CHANGE_CALLBACK);

        MessageParcel reply;
        MessageOption option;
        DelayedSingleton<AccessTokenManagerService>::GetInstance()->OnRemoteRequest(code, datas, reply, option);

        MessageParcel datas2;
        datas2.WriteInterfaceToken(IAccessTokenManager::GetDescriptor());
        DelayedSingleton<AccessTokenManagerService>::GetInstance()->OnRemoteRequest(
            static_cast<uint32_t>(IAccessTokenManagerIpcCode::COMMAND_UN_REGISTER_PERM_STATE_CHANGE_CALLBACK),
            datas2, reply, option);

        return true;
    }
} // namespace OHOS

/* Fuzzer entry point */
extern "C" int LLVMFuzzerTestOneInput(const uint8_t* data, size_t size)
{
    /* Run your code on data */
    OHOS::RegisterPermStateChangeCallbackStubFuzzTest(data, size);
    return 0;
}
