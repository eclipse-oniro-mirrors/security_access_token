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
#include "perm_active_response_parcel.h"
#include "parcel.h"

using namespace testing::ext;

namespace OHOS {
namespace Security {
namespace AccessToken {
namespace {

}
class ActiveChangeResponseParcelTest : public testing::Test  {
public:
    static void SetUpTestCase(void);
    static void TearDownTestCase(void);
    void SetUp();
    void TearDown();
};

void ActiveChangeResponseParcelTest::SetUpTestCase(void) {}
void ActiveChangeResponseParcelTest::TearDownTestCase(void) {}
void ActiveChangeResponseParcelTest::SetUp(void) {}
void ActiveChangeResponseParcelTest::TearDown(void) {}

/**
 * @tc.name: ActiveChangeResponseParcel001
 * @tc.desc: Verify ActiveChangeResponseParcel Marshalling and Unmarshalling function.
 * @tc.type: FUNC
 * @tc.require: issueI5RRLJ
 */
HWTEST_F(ActiveChangeResponseParcelTest, ActiveChangeResponseParcel001, TestSize.Level1)
{
    ActiveChangeResponseParcel activeChangeResponseParcel;

    activeChangeResponseParcel.changeResponse = {
        .tokenID = 100,
        .permissionName = "ohos.permission.CAMERA",
        .deviceId = "you guess",
        .type = PERM_INACTIVE,
    };

    Parcel parcel;
    EXPECT_EQ(true, activeChangeResponseParcel.Marshalling(parcel));

    std::shared_ptr<ActiveChangeResponseParcel> readedData(ActiveChangeResponseParcel::Unmarshalling(parcel));
    EXPECT_EQ(true, readedData != nullptr);

    EXPECT_EQ(activeChangeResponseParcel.changeResponse.tokenID, readedData->changeResponse.tokenID);
    EXPECT_EQ(activeChangeResponseParcel.changeResponse.permissionName, readedData->changeResponse.permissionName);
    EXPECT_EQ(activeChangeResponseParcel.changeResponse.deviceId, readedData->changeResponse.deviceId);
    EXPECT_EQ(activeChangeResponseParcel.changeResponse.type, readedData->changeResponse.type);
}
} // namespace AccessToken
} // namespace Security
} // namespace OHOS
