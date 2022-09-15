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
#include "parcel.h"
#include "permission_state_change_info_parcel.h"
#include "permission_state_change_info.h"

using namespace testing::ext;

namespace OHOS {
namespace Security {
namespace AccessToken {
namespace {
static constexpr int32_t TEST_PERMSTATE_CHANGE_TYPE = 10001;
static constexpr AccessTokenID TEST_TOKEN_ID = 10002;
static const std::string TEST_PERMISSION_NAME = "ohos.permission.PERMISSION_STATE_CHANGE_INFO";
}
class PermissionStateChangeInfoParcelTest : public testing::Test  {
public:
    static void SetUpTestCase(void);
    static void TearDownTestCase(void);
    void SetUp();
    void TearDown();
};

void PermissionStateChangeInfoParcelTest::SetUpTestCase(void) {}
void PermissionStateChangeInfoParcelTest::TearDownTestCase(void) {}
void PermissionStateChangeInfoParcelTest::SetUp(void) {}
void PermissionStateChangeInfoParcelTest::TearDown(void) {}

/**
 * @tc.name: PermissionStateChangeInfoParcel001
 * @tc.desc: Verify the CreateHapTokenInfo add one hap token function.
 * @tc.type: FUNC
 * @tc.require: I5QKZF
 */
HWTEST_F(PermissionStateChangeInfoParcelTest, PermissionStateChangeInfoParcel001, TestSize.Level1)
{
    PermissionStateChangeInfoParcel permissionStateParcel;
    permissionStateParcel.changeInfo.PermStateChangeType = TEST_PERMSTATE_CHANGE_TYPE;
    permissionStateParcel.changeInfo.tokenID = TEST_TOKEN_ID;
    permissionStateParcel.changeInfo.permissionName = TEST_PERMISSION_NAME;

    Parcel parcel;
    EXPECT_EQ(true, permissionStateParcel.Marshalling(parcel));

    std::shared_ptr<PermissionStateChangeInfoParcel> readedData(PermissionStateChangeInfoParcel::Unmarshalling(parcel));
    EXPECT_EQ(true, readedData != nullptr);
    EXPECT_EQ(permissionStateParcel.changeInfo.PermStateChangeType, readedData->changeInfo.PermStateChangeType);
    EXPECT_EQ(permissionStateParcel.changeInfo.tokenID, readedData->changeInfo.tokenID);
    EXPECT_EQ(permissionStateParcel.changeInfo.permissionName, readedData->changeInfo.permissionName);
}
}
}
}