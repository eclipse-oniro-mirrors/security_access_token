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

#include "addpermissionusedrecordstub_fuzzer.h"

#include <string>
#include <thread>
#include <vector>

#include "accesstoken_fuzzdata.h"
#undef private
#include "i_privacy_manager.h"
#include "privacy_manager_service.h"

using namespace std;
using namespace OHOS::Security::AccessToken;

namespace OHOS {
    bool AddPermissionUsedRecordStubFuzzTest(const uint8_t* data, size_t size)
    {
        if ((data == nullptr) || (size == 0)) {
            return false;
        }

        AccessTokenFuzzData fuzzData(data, size);

        MessageParcel datas;
        datas.WriteInterfaceToken(IPrivacyManager::GetDescriptor());

        AddPermParamInfoParcel infoParcel;
        infoParcel.info.tokenId = static_cast<AccessTokenID>(fuzzData.GetData<uint32_t>());
        infoParcel.info.permissionName = fuzzData.GenerateRandomString();
        infoParcel.info.successCount = fuzzData.GetData<int32_t>();
        infoParcel.info.failCount = fuzzData.GetData<int32_t>();
        if (!datas.WriteParcelable(&infoParcel)) {
            return false;
        }

        uint32_t code = static_cast<uint32_t>(PrivacyInterfaceCode::ADD_PERMISSION_USED_RECORD);

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
    OHOS::AddPermissionUsedRecordStubFuzzTest(data, size);
    return 0;
}
