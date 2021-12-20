/*
 * Copyright (c) 2021 Huawei Device Co., Ltd.
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

#include "accesstoken_kit_test.h"

#include "accesstoken_kit.h"

using namespace testing::ext;
using namespace OHOS::Security::AccessToken;

void AccessTokenKitTest::SetUpTestCase()
{}

void AccessTokenKitTest::TearDownTestCase()
{}

void AccessTokenKitTest::SetUp()
{}

void AccessTokenKitTest::TearDown()
{}

/**
 * @tc.name: VerifyAccesstokenn001
 * @tc.desc: Verify user granted permission
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(AccessTokenKitTest, VerifyAccesstokenn001, TestSize.Level0)
{
    AccessTokenID tokenID = 1;
    const std::string TEST_PERMISSION_NAME = "ohos.permission.TEST";

    int ret = AccessTokenKit::VerifyAccesstoken(tokenID, TEST_PERMISSION_NAME);
    ASSERT_EQ(PERMISSION_GRANTED, ret);

}