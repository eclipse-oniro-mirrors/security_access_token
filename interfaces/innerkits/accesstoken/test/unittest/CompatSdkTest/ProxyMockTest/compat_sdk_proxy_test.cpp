/*
 * Copyright (c) 2025 Huawei Device Co., Ltd.
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

#include "accesstoken_compat_kit.h"
#include "access_token_error.h"
#include "iservice_registry.h"

using namespace testing::ext;

namespace OHOS {
namespace Security {
namespace AccessToken {
class ATCompatMockTest : public testing::Test {
public:
    static void SetUpTestCase();
    static void TearDownTestCase();
    void SetUp();
    void TearDown();
};

void ATCompatMockTest::SetUpTestCase()
{
}

void ATCompatMockTest::TearDownTestCase()
{
}

void ATCompatMockTest::SetUp()
{
}

void ATCompatMockTest::TearDown()
{
}

/**
 * @tc.name: VerifyAccessTokenTest001
 * @tc.desc: VerifyAccessToken with proxy is null
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(ATCompatMockTest, VerifyAccessTokenTest001, TestSize.Level4)
{
    AccessTokenID tokenID = 123; // 123: tokenid
    ASSERT_EQ(PERMISSION_DENIED, AccessTokenCompatKit::VerifyAccessToken(tokenID, "ohos.permission.CAMERA"));
}

/**
 * @tc.name: GetHapTokenInfoTest001
 * @tc.desc: VerifyAccessToken with proxy is null
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(ATCompatMockTest, GetHapTokenInfoTest001, TestSize.Level4)
{
    AccessTokenID tokenID = 123; // 123: tokenid
    HapTokenInfoCompat hapInfo;
    ASSERT_EQ(ERR_SERVICE_ABNORMAL, AccessTokenCompatKit::GetHapTokenInfo(tokenID, hapInfo));
}

/**
 * @tc.name: GetNativeTokenIdTest001
 * @tc.desc: GetNativeTokenId with proxy is null
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(ATCompatMockTest, GetNativeTokenIdTest001, TestSize.Level4)
{
    ASSERT_EQ(INVALID_TOKENID, AccessTokenCompatKit::GetNativeTokenId("accesstoken_service"));
}
}  // namespace AccessToken
}  // namespace Security
}
