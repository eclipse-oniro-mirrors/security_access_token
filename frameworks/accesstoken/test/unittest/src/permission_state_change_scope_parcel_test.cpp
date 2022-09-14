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
#include "accesstoken_log.h"
#include "parcel.h"
#include "permission_state_change_scope_parcel.h"

using namespace testing::ext;

namespace OHOS {
namespace Security {
namespace AccessToken {
namespace {
static constexpr AccessTokenID TEST_TOKEN_ID = 10002;
static const std::string TEST_PERMISSION_NAME = "ohos.permission.PERMISSION_STATE_CHANGE_INFO";
}
class PermStateChangeScopeParcelTest : public testing::Test  {
public:
    static void SetUpTestCase(void);
    static void TearDownTestCase(void);
    void SetUp();
    void TearDown();
};

void PermStateChangeScopeParcelTest::SetUpTestCase(void) {}
void PermStateChangeScopeParcelTest::TearDownTestCase(void) {}
void PermStateChangeScopeParcelTest::SetUp(void) {}
void PermStateChangeScopeParcelTest::TearDown(void) {}

/**
 * @tc.name: PermStateChangeScopeParcel001
 * @tc.desc: Verify the CreateHapTokenInfo add one hap token function.
 * @tc.type: FUNC
 * @tc.require: I5QKZF
 */
HWTEST_F(PermStateChangeScopeParcelTest, PermStateChangeScopeParcel001, TestSize.Level1)
{
    PermStateChangeScopeParcel permStateChangeScopeParcel;
    permStateChangeScopeParcel.scope.tokenIDs.emplace_back(TEST_TOKEN_ID);
    permStateChangeScopeParcel.scope.permList.emplace_back(TEST_PERMISSION_NAME);

    Parcel parcel;
    EXPECT_EQ(true, permStateChangeScopeParcel.Marshalling(parcel));

    std::shared_ptr<PermStateChangeScopeParcel> readedData(PermStateChangeScopeParcel::Unmarshalling(parcel));
    EXPECT_EQ(true, readedData != nullptr);
    
    EXPECT_EQ(true,  readedData->scope.tokenIDs.size() != 0);
    EXPECT_EQ(true,  readedData->scope.permList.size() != 0);

    for(int32_t i = 0; i < readedData->scope.tokenIDs.size(); i++) {
        EXPECT_EQ(permStateChangeScopeParcel.scope.tokenIDs[i], readedData->scope.tokenIDs[i]);
    }
    for(int32_t i = 0;i < readedData->scope.permList.size(); i++) {
        EXPECT_EQ(true, permStateChangeScopeParcel.scope.permList[i] == readedData->scope.permList[i]);
    } 
}
}
}
}