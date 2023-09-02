/*
 * Copyright (c) 2023 Huawei Device Co., Ltd.
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

#include <string>
#include <thread>
#include <vector>
#undef private
#include "i_token_sync_manager.h"
#include "token_sync_manager_service.h"

using namespace std;
using namespace OHOS::Security::AccessToken;

namespace OHOS {
    bool DeleteRemoteHapTokenInfoStubFuzzTest(const uint8_t* data, size_t size)
    {
        if ((data == nullptr) || (size == 0)) {
            return false;
        }

        AccessTokenID TOKENID = static_cast<AccessTokenID>(size);
        
        MessageParcel datas;
        datas.WriteInterfaceToken(ITokenSyncManager::GetDescriptor());

        if (!datas.WriteUint32(TOKENID)) {
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
