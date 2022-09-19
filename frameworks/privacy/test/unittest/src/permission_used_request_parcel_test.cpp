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
 
#include <gtest/gtest.h>
#include <memory>
#include <string>
#include "permission_used_request_parcel.h"
#include "parcel.h"

using namespace testing::ext;

namespace OHOS {
namespace Security {
namespace AccessToken {
class PermissionUsedRequestParcelTest : public testing::Test  {
public:
    static void SetUpTestCase(void);
    static void TearDownTestCase(void);
    void SetUp();
    void TearDown();
};

void PermissionUsedRequestParcelTest::SetUpTestCase(void) {}
void PermissionUsedRequestParcelTest::TearDownTestCase(void) {}
void PermissionUsedRequestParcelTest::SetUp(void) {}
void PermissionUsedRequestParcelTest::TearDown(void) {}

/**
 * @tc.name: PermissionUsedRequestParcel001
 * @tc.desc: Verify the PermissionUsedRequestParcel Marshalling and Unmarshalling function.
 * @tc.type: FUNC
 * @tc.require: issueI5RUP1
 */
HWTEST_F(PermissionUsedRequestParcelTest, PermissionUsedRequestParcel001, TestSize.Level1)
{
    PermissionUsedRequestParcel permissionUsedRequestParcel;

    permissionUsedRequestParcel.request = {
        .tokenId = 100,
        .isRemote = false,
        .deviceId = "you guess",
        .bundleName = "com.ohos.permissionmanager",
        .beginTimeMillis = 0L,
        .endTimeMillis = 0L,
        .flag = FLAG_PERMISSION_USAGE_SUMMARY,
    };
    permissionUsedRequestParcel.request.permissionList.emplace_back("ohos.permission.CAMERA");
    permissionUsedRequestParcel.request.permissionList.emplace_back("ohos.permission.LOCATION");

    Parcel parcel;
    EXPECT_EQ(true, permissionUsedRequestParcel.Marshalling(parcel));

    std::shared_ptr<PermissionUsedRequestParcel> readedData(PermissionUsedRequestParcel::Unmarshalling(parcel));
    EXPECT_EQ(true, readedData != nullptr);

    EXPECT_EQ(permissionUsedRequestParcel.request.tokenId, readedData->request.tokenId);
    EXPECT_EQ(permissionUsedRequestParcel.request.isRemote, readedData->request.isRemote);
    EXPECT_EQ(permissionUsedRequestParcel.request.deviceId, readedData->request.deviceId);
    EXPECT_EQ(permissionUsedRequestParcel.request.bundleName, readedData->request.bundleName);
    EXPECT_EQ(permissionUsedRequestParcel.request.beginTimeMillis, readedData->request.beginTimeMillis);
    EXPECT_EQ(permissionUsedRequestParcel.request.endTimeMillis, readedData->request.endTimeMillis);
    EXPECT_EQ(permissionUsedRequestParcel.request.flag, readedData->request.flag);

    for(uint32_t i = 0; i < permissionUsedRequestParcel.request.permissionList.size(); i++) {
        EXPECT_EQ(permissionUsedRequestParcel.request.permissionList[i], readedData->request.permissionList[i]);
    }
}
} // namespace AccessToken
} // namespace Security
} // namespace OHOS
