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
#include "accesstoken_compat_client.h"

using namespace testing::ext;

namespace OHOS {
namespace Security {
namespace AccessToken {
namespace {
static constexpr uint32_t TEST_NATIVE_TOKEN = 672137215; // 672137215: 001 01 0 000000 11111111111111111111
static constexpr uint32_t TEST_HAP_TOKEN = 537919487; // 537919486: 001 00 0 000000 11111111111111111111
}
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
 * @tc.require: issueI61A6M
 */
HWTEST_F(ATCompatMockTest, VerifyAccessTokenTest001, TestSize.Level4)
{
    std::string permission = "ohos.permission.CAMERA";

    // first call: ret < 0(GetParameter)
    ASSERT_EQ(PERMISSION_DENIED,
        AccessTokenCompatClient::GetInstance().VerifyAccessToken(TEST_NATIVE_TOKEN, permission));

    // second call: ret > 0(GetParameter), (static_cast<uint64_t>(std::atoll(value)) != 0
    ASSERT_EQ(PERMISSION_DENIED,
        AccessTokenCompatClient::GetInstance().VerifyAccessToken(TEST_NATIVE_TOKEN, permission));

    // third call: ret > 0(GetParameter), (static_cast<uint64_t>(std::atoll(value)) == 0
    // token id is native, granted
    ASSERT_EQ(PERMISSION_GRANTED,
        AccessTokenCompatClient::GetInstance().VerifyAccessToken(TEST_NATIVE_TOKEN, permission));

    // fouth call: ret > 0(GetParameter), (static_cast<uint64_t>(std::atoll(value)) == 0
    // token is is hap, denied
    ASSERT_EQ(PERMISSION_DENIED,
        AccessTokenCompatClient::GetInstance().VerifyAccessToken(TEST_HAP_TOKEN, permission));
}

/**
 * @tc.name: GetPermissionCodeTest001
 * @tc.desc: GetPermissionCode with proxy is null
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(ATCompatMockTest, GetPermissionCodeTest001, TestSize.Level4)
{
    uint32_t code;
    ASSERT_EQ(ERR_SERVICE_ABNORMAL,
        AccessTokenCompatClient::GetInstance().GetPermissionCode("ohos.permission.CAMERA", code));
}

/**
 * @tc.name: GetHapTokenInfoTest001
 * @tc.desc: VerifyAccessToken with proxy is null
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(ATCompatMockTest, GetHapTokenInfoTest001, TestSize.Level4)
{
    HapTokenInfoCompatParcel hapInfo;
    ASSERT_EQ(ERR_SERVICE_ABNORMAL, AccessTokenCompatClient::GetInstance().GetHapTokenInfo(TEST_HAP_TOKEN, hapInfo));
}

/**
 * @tc.name: GetNativeTokenIdTest001
 * @tc.desc: GetNativeTokenId with proxy is null
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(ATCompatMockTest, GetNativeTokenIdTest001, TestSize.Level4)
{
    ASSERT_EQ(INVALID_TOKENID, AccessTokenCompatClient::GetInstance().GetNativeTokenId("accesstoken_service"));
}
}  // namespace AccessToken
}  // namespace Security
}
