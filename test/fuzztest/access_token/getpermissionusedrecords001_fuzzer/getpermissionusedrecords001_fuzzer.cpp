/*
 * Copyright (c) 2022 Huawei Device Co., Ltd.
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

#include "getpermissionusedrecords001_fuzzer.h"

#include <iostream>
#include <thread>
#include <string>
#include <vector>
#undef private
#include "on_permission_used_record_callback_stub.h"
#include "privacy_kit.h"

using namespace std;
using namespace OHOS::Security::AccessToken;

class TestCallBack : public OnPermissionUsedRecordCallbackStub {
public:
    TestCallBack() = default;
    virtual ~TestCallBack() = default;

    void OnQueried(OHOS::ErrCode code, PermissionUsedResult& result)
    {
        return;
    }
};

namespace OHOS {
    bool GetPermissionUsedRecords001FuzzTest(const uint8_t* data, size_t size)
    {
        int32_t result = RET_FAILED;
        if ((data == nullptr) || (size == 0)) {
            return false;
        }

        AccessTokenID tokenId = static_cast<AccessTokenID>(size);
        std::string testName(reinterpret_cast<const char*>(data), size);
        std::vector<std::string> permissionList;
        permissionList.emplace_back(testName);
        int64_t beginTimeMillis = static_cast<int64_t>(size);
        int64_t endTimeMillis = static_cast<int64_t>(size);

        PermissionUsedRequest request = {
            .tokenId = tokenId,
            .isRemote = false,
            .deviceId = testName,
            .bundleName = testName,
            .permissionList = permissionList,
            .beginTimeMillis = beginTimeMillis,
            .endTimeMillis = endTimeMillis,
            .flag = FLAG_PERMISSION_USAGE_SUMMARY
        };

        PermissionUsedResult res;
        OHOS::sptr<TestCallBack> callback(new TestCallBack());

        result = PrivacyKit::GetPermissionUsedRecords(request, callback);

        return result == RET_SUCCESS;
    }
}

/* Fuzzer entry point */
extern "C" int LLVMFuzzerTestOneInput(const uint8_t* data, size_t size)
{
    /* Run your code on data */
    OHOS::GetPermissionUsedRecords001FuzzTest(data, size);
    return 0;
}
