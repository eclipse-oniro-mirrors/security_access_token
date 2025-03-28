/*
 * Copyright (c) 2024-2025 Huawei Device Co., Ltd.
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

#include "verifyaccesstokenwithliststub_fuzzer.h"

#include <string>
#include <thread>
#include <vector>
#undef private
#include "accesstoken_fuzzdata.h"
#include "accesstoken_manager_service.h"
#include "iaccess_token_manager.h"

using namespace std;
using namespace OHOS::Security::AccessToken;
const int32_t MAX_PERMISSION_SIZE = 1100;

namespace OHOS {
    bool VerifyAccessTokenWithListStubFuzzTest(const uint8_t* data, size_t size)
    {
        if ((data == nullptr) || (size == 0)) {
            return false;
        }

        AccessTokenFuzzData fuzzData(data, size);
        AccessTokenID tokenId = fuzzData.GetData<AccessTokenID>();

        int permSize = fuzzData.GetData<int>() % MAX_PERMISSION_SIZE;
        std::vector<std::string> permissionList;
        for (int i = 0; i < permSize; i++) {
            permissionList.emplace_back(fuzzData.GenerateStochasticString());
        }
        MessageParcel datas;
        datas.WriteInterfaceToken(IAccessTokenManager::GetDescriptor());
        if (!datas.WriteUint32(tokenId) || !datas.WriteStringVector(permissionList)) {
            return false;
        }

        uint32_t code = static_cast<uint32_t>(
            IAccessTokenManagerIpcCode::COMMAND_VERIFY_ACCESS_TOKEN_IN_UNSIGNED_INT_IN_LIST_STRING_OUT_LIST_INT);

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
    OHOS::VerifyAccessTokenWithListStubFuzzTest(data, size);
    return 0;
}
