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

#include "tokensync_kit_test.h"

#include "tokensync_kit.h"

using namespace testing::ext;
using namespace OHOS::Security::TokenSync;

void TokenSyncKitTest::SetUpTestCase()
{}

void TokenSyncKitTest::TearDownTestCase()
{
}

void TokenSyncKitTest::SetUp()
{
}

void TokenSyncKitTest::TearDown()
{}

/**
 * @tc.name: VerifyPermission001
 * @tc.desc: Verify user granted permission
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(TokenSyncKitTest, VerifyPermission001, TestSize.Level1)
{
    const std::string testBundleName = "ohos";
    const std::string testPermissionNameAlpha = "ohos.permission.ALPHA";
    const int testUserId = 0;
    int ret = TokenSyncKit::VerifyPermission(testBundleName, testPermissionNameAlpha, testUserId);

    ASSERT_EQ(0, ret);
}

