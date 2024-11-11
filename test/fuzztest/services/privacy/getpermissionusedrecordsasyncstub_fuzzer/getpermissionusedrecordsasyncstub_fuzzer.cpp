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

#include "getpermissionusedrecordsasyncstub_fuzzer.h"

#include <string>
#include <thread>
#include <vector>

#include "accesstoken_fuzzdata.h"
#undef private
#include "errors.h"
#include "i_privacy_manager.h"
#include "on_permission_used_record_callback_stub.h"
#include "permission_used_request.h"
#include "privacy_manager_service.h"

using namespace std;
using namespace OHOS::Security::AccessToken;

class TestCallBack : public OnPermissionUsedRecordCallbackStub {
public:
    TestCallBack() = default;
    virtual ~TestCallBack() = default;

    void OnQueried(OHOS::ErrCode code, PermissionUsedResult& result)
    {}
};
namespace OHOS {
    bool GetPermissionUsedRecordsAsyncStubFuzzTest(const uint8_t* data, size_t size)
    {
        if ((data == nullptr) || (size == 0)) {
            return false;
        }

        AccessTokenFuzzData fuzzData(data, size);

        std::vector<std::string> permissionList = {fuzzData.GenerateRandomString()};

        PermissionUsedRequest request = {
            .tokenId = static_cast<AccessTokenID>(fuzzData.GetData<uint32_t>()),
            .isRemote = fuzzData.GenerateRandomBool(),
            .deviceId = fuzzData.GenerateRandomString(),
            .bundleName = fuzzData.GenerateRandomString(),
            .permissionList = permissionList,
            .beginTimeMillis = fuzzData.GetData<int64_t>(),
            .endTimeMillis = fuzzData.GetData<int64_t>(),
            .flag = fuzzData.GenerateRandomEnmu<PermissionUsageFlag>(FLAG_PERMISSION_USAGE_SUMMARY_IN_APP_FOREGROUND)
        };
        MessageParcel datas;
        if (!datas.WriteInterfaceToken(IPrivacyManager::GetDescriptor()) || !datas.WriteUint32(request.tokenId) ||
            !datas.WriteString(request.deviceId) || !datas.WriteString(request.bundleName) ||
            !datas.WriteUint32(request.permissionList.size())) {
            return false;
        }
        for (const auto& permission : request.permissionList) {
            if (!datas.WriteString(permission)) {
                return false;
            }
        }
        if (!datas.WriteInt64(request.beginTimeMillis) || !datas.WriteInt64(request.endTimeMillis) ||
            !datas.WriteInt32(request.flag) || !datas.WriteString(request.bundleName) ||
            !datas.WriteUint32(request.permissionList.size())) {
            return false;
        }
        sptr<TestCallBack> callback(new TestCallBack());
        if (!datas.WriteRemoteObject(callback->AsObject())) {
            return false;
        }
        uint32_t code = static_cast<uint32_t>(PrivacyInterfaceCode::GET_PERMISSION_USED_RECORDS_ASYNC);

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
    OHOS::GetPermissionUsedRecordsAsyncStubFuzzTest(data, size);
    return 0;
}
