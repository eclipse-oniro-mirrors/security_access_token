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
#define private public
#include "accesstoken_compat_client.h"
#undef private
#include "token_setproc.h"

using namespace testing::ext;

namespace OHOS {
namespace Security {
namespace AccessToken {
namespace {
static AccessTokenID g_selfShellTokenId = 0;
}
class ATCompatCoverageTest : public testing::Test {
public:
    static void SetUpTestCase();
    static void TearDownTestCase();
    void SetUp();
    void TearDown();
};

void ATCompatCoverageTest::SetUpTestCase()
{
    g_selfShellTokenId = GetSelfTokenID();
    AccessTokenCompatClient::GetInstance().InitProxy();
}

void ATCompatCoverageTest::TearDownTestCase()
{
    SetSelfTokenID(g_selfShellTokenId);
}

void ATCompatCoverageTest::SetUp()
{
}

void ATCompatCoverageTest::TearDown()
{
    SetSelfTokenID(g_selfShellTokenId);
}

/**
 * @tc.name: InitProxyTes001
 * @tc.desc: AccessTokenCompatClient::InitProxy function test
 * @tc.type: FUNC
 * @tc.require: issueI61A6M
 */
HWTEST_F(ATCompatCoverageTest, InitProxyTes001, TestSize.Level4)
{
    ASSERT_NE(nullptr, AccessTokenCompatClient::GetInstance().proxy_);
    OHOS::sptr<IAccessTokenManager> proxy = AccessTokenCompatClient::GetInstance().proxy_; // backup
    AccessTokenCompatClient::GetInstance().proxy_ = nullptr;
    ASSERT_EQ(nullptr, AccessTokenCompatClient::GetInstance().proxy_);
    AccessTokenCompatClient::GetInstance().InitProxy(); // proxy_ is null
    AccessTokenCompatClient::GetInstance().proxy_ = proxy; // recovery
}

/**
 * @tc.name: ReleaseProxyTes001
 * @tc.desc: AccessTokenCompatClient::ReleaseProxy function test
 * @tc.type: FUNC
 * @tc.require: issueI61A6M
 */
HWTEST_F(ATCompatCoverageTest, ReleaseProxyTes001, TestSize.Level4)
{
    ASSERT_NE(nullptr, AccessTokenCompatClient::GetInstance().proxy_);
    OHOS::sptr<IAccessTokenManager> proxy = AccessTokenCompatClient::GetInstance().proxy_; // backup
    AccessTokenCompatClient::GetInstance().proxy_ = nullptr;
    ASSERT_EQ(nullptr, AccessTokenCompatClient::GetInstance().proxy_);
    AccessTokenCompatClient::GetInstance().ReleaseProxy(); // proxy_ is null
    AccessTokenCompatClient::GetInstance().proxy_ = proxy; // recovery
}
}  // namespace AccessToken
}  // namespace Security
}
