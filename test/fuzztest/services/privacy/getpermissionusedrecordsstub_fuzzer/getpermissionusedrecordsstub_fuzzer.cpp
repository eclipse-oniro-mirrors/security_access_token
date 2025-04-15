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

#include "getpermissionusedrecordsstub_fuzzer.h"

#include <string>
#include <thread>
#include <vector>

#include "accesstoken_fuzzdata.h"
#undef private
#include "iprivacy_manager.h"
#include "permission_used_request.h"
#include "permission_used_request_parcel.h"
#include "privacy_manager_service.h"

using namespace std;
using namespace OHOS::Security::AccessToken;

namespace OHOS {
    bool GetPermissionUsedRecordsStubFuzzTest(const uint8_t* data, size_t size)
    {
        if ((data == nullptr) || (size == 0)) {
            return false;
        }

        AccessTokenFuzzData fuzzData(data, size);

        std::vector<std::string> permissionList = {fuzzData.GenerateStochasticString()};

        PermissionUsedRequest request = {
            .tokenId = static_cast<AccessTokenID>(fuzzData.GetData<uint32_t>()),
            .isRemote = fuzzData.GenerateStochasticBool(),
            .deviceId = fuzzData.GenerateStochasticString(),
            .bundleName = fuzzData.GenerateStochasticString(),
            .permissionList = permissionList,
            .beginTimeMillis = fuzzData.GetData<int64_t>(),
            .endTimeMillis = fuzzData.GetData<int64_t>(),
            .flag = fuzzData.GenerateStochasticEnmu<PermissionUsageFlag>(
                FLAG_PERMISSION_USAGE_SUMMARY_IN_APP_FOREGROUND)
        };
        PermissionUsedRequestParcel requestParcel;
        requestParcel.request = request;

        MessageParcel datas;
        datas.WriteInterfaceToken(IPrivacyManager::GetDescriptor());
        if (!datas.WriteParcelable(&requestParcel)) {
            return false;
        }

        uint32_t code = static_cast<uint32_t>(IPrivacyManagerIpcCode::COMMAND_GET_PERMISSION_USED_RECORDS);

        MessageParcel reply;
        MessageOption option;
        DelayedSingleton<PrivacyManagerService>::GetInstance()->OnRemoteRequest(code, datas, reply, option);

        return true;
    }
} // namespace OHOS

/* Fuzzer entry point */
extern "C" int LLVMFuzzerTestOneInput(const uint8_t* data, size_t size)
{
    /* Run your code on data */
    OHOS::GetPermissionUsedRecordsStubFuzzTest(data, size);
    return 0;
}
