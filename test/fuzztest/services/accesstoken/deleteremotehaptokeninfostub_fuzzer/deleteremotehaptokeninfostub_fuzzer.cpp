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

#include "deleteremotehaptokeninfostub_fuzzer.h"

#include "fuzzer/FuzzedDataProvider.h"
#include "hap_token_info_for_sync_parcel.h"
#include "i_token_sync_manager.h"
#include "token_sync_manager_service.h"

using namespace std;
using namespace OHOS::Security::AccessToken;

namespace OHOS {
void UpdateRemoteHapTokenInfo()
{
    MessageParcel data;
    if (!data.WriteInterfaceToken(ITokenSyncManager::GetDescriptor())) {
        return;
    }
    HapTokenInfoForSyncParcel tokenInfoParcel;

    if (!data.WriteParcelable(&tokenInfoParcel)) {
        return;
    }

    MessageParcel reply;
    MessageOption option(MessageOption::TF_SYNC);
    DelayedSingleton<TokenSyncManagerService>::GetInstance()->SendRequest(static_cast<uint32_t>(
        TokenSyncInterfaceCode::UPDATE_REMOTE_HAP_TOKEN_INFO), data, reply, option);
}

bool DeleteRemoteHapTokenInfoStubFuzzTest(const uint8_t* data, size_t size)
{
    if ((data == nullptr) || (size == 0)) {
        return false;
    }

    FuzzedDataProvider provider(data, size);
    AccessTokenID tokenID = provider.ConsumeIntegral<AccessTokenID>();
    
    UpdateRemoteHapTokenInfo();

    MessageParcel datas;
    if (!datas.WriteInterfaceToken(ITokenSyncManager::GetDescriptor())) {
        return false;
    }

    if (!datas.WriteUint32(tokenID)) {
        return false;
    }
    
    uint32_t code = static_cast<uint32_t>(
        TokenSyncInterfaceCode::DELETE_REMOTE_HAP_TOKEN_INFO);

    MessageParcel reply;
    MessageOption option(MessageOption::TF_SYNC);

    DelayedSingleton<TokenSyncManagerService>::GetInstance()->OnRemoteRequest(code, datas, reply, option);

    return true;
}
} // namespace OHOS

/* Fuzzer entry point */
extern "C" int LLVMFuzzerTestOneInput(const uint8_t* data, size_t size)
{
    /* Run your code on data */
    OHOS::DeleteRemoteHapTokenInfoStubFuzzTest(data, size);
    return 0;
}
