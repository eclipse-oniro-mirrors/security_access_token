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

#ifndef PRIVACY_KIT_TEST_H
#define PRIVACY_KIT_TEST_H

#include <gtest/gtest.h>
#include <cstdint>

#include "on_permission_used_record_callback_stub.h"
#include "permission_used_request.h"
#include "permission_used_result.h"

namespace OHOS {
namespace Security {
namespace AccessToken {
class PrivacyKitTest : public testing::Test {
public:
    static void SetUpTestCase();

    static void TearDownTestCase();

    void SetUp();

    void TearDown();

    class TestCallBack : public OnPermissionUsedRecordCallbackStub {
    public:
        TestCallBack() = default;
        virtual ~TestCallBack() = default;

        void OnQueried(ErrCode code, PermissionUsedResult& result)
        {
            GTEST_LOG_(INFO) << "TestCallBack, code :" << code << ", bundleSize :" << result.bundleRecords.size();
        }
    };
    std::string GetLocalDeviceUdid();
    void BuildQueryRequest(AccessTokenID tokenId, const std::string& deviceId, const std::string& bundleName,
        const std::vector<std::string>& permissionList, PermissionUsedRequest& request);
    void CheckPermissionUsedResult(const PermissionUsedRequest& request, const PermissionUsedResult& result,
        int32_t permRecordSize, int32_t totalSuccessCount, int32_t totalFailCount);
};
} // namespace AccessToken
} // namespace Security
} // namespace OHOS
#endif // PRIVACY_KIT_TEST_H
