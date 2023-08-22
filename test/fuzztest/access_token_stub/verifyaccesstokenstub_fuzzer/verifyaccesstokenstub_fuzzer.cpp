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

#include "verifyaccesstokenstub_fuzzer.h"

#include <string>
#include <thread>
#include <vector>
#undef private
#include "accesstoken_manager_service.h"
#include "i_accesstoken_manager.h"

using namespace std;
using namespace OHOS::Security::AccessToken;

namespace OHOS {
    bool VerifyAccessTokenStubFuzzTest(const uint8_t* data, size_t size)
    {
        if ((data == nullptr) || (size == 0)) {
            return false;
        }

        AccessTokenID tokenId = static_cast<AccessTokenID>(size);
        std::string testName(reinterpret_cast<const char *>(data), size);

        MessageParcel datas;
        datas.WriteInterfaceToken(IAccessTokenManager::GetDescriptor());
        if (!datas.WriteUint32(tokenId) || !datas.WriteString(testName)) {
            return false;
        }

        uint32_t code = static_cast<uint32_t>(
            AccessTokenInterfaceCode::VERIFY_ACCESSTOKEN);

        MessageParcel reply;
        MessageOption option;
        DelayedSingleton<AccessTokenManagerService>::GetInstance()->OnRemoteRequest(code, datas, reply, option);

        return true;
    }
} // namespace OHOS

/* Fuzzer entry point */
extern "C" int LLVMFuzzerTestOneInput(const uint8_t* data, size_t size)
{
    /* Run your code on data */
    OHOS::VerifyAccessTokenStubFuzzTest(data, size);
    return 0;
}
