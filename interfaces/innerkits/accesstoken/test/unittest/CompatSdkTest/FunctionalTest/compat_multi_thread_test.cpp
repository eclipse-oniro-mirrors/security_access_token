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

#include <gtest/hwext/gtest-multithread.h>

#include "accesstoken_compat_kit.h"
#include "access_token_error.h"
#include "test_common.h"
#include "token_setproc.h"

using namespace testing::ext;
using namespace testing::mt;

namespace OHOS {
namespace Security {
namespace AccessToken {
namespace {
constexpr int32_t MULTIPLE_COUNT = 10;
std::vector<TokenInfoForTest> g_allTokenInfos;
static AccessTokenID g_selfTokenId = 0;
static AccessTokenID g_nativeTokenId = 0;
}

class CompatMultiThreadTest : public testing::Test {
public:
    static void SetUpTestCase();
    static void TearDownTestCase();
    void SetUp();
    void TearDown();
};

void CompatMultiThreadTest::SetUpTestCase()
{
    g_selfTokenId = GetSelfTokenID();
    g_nativeTokenId = GetNativeTokenId("accesstoken_service");
    g_allTokenInfos = GetAllTokenId();
    GTEST_LOG_(INFO) << "selfTokenId: " << g_selfTokenId;
    GTEST_LOG_(INFO) << "nativeTokenId: " << g_nativeTokenId;
    GTEST_LOG_(INFO) << "size: " << g_allTokenInfos.size();
}

void CompatMultiThreadTest::TearDownTestCase()
{
    SetSelfTokenID(g_selfTokenId);
}

void CompatMultiThreadTest::SetUp()
{
}

void CompatMultiThreadTest::TearDown()
{
}

/**
 * @tc.name: CompatMultiThreadTest
 * @tc.desc: test GetNativeTokenId, GetHapTokenInfo
 * @tc.type: FUNC
 * @tc.require:
 */
HWMTEST_F(CompatMultiThreadTest, CompatMultiThreadTest, TestSize.Level1, MULTIPLE_COUNT)
{
    SetSelfTokenID(g_nativeTokenId);
    GTEST_LOG_(INFO) << "tokenID: " << GetSelfTokenID() << ", tid: " << gettid();
    for (size_t i = 0; i < g_allTokenInfos.size(); ++i) {
        AccessTokenID tokenID = g_allTokenInfos[i].tokenID;
        std::string name = g_allTokenInfos[i].name;
        ATokenTypeEnum type = AccessTokenCompatKit::GetTokenTypeFlag(tokenID);
        if ((type == TOKEN_NATIVE) || (type == TOKEN_SHELL)) {
            EXPECT_EQ(tokenID, AccessTokenCompatKit::GetNativeTokenId(name));
        } else if (type == TOKEN_HAP) {
            HapTokenInfoCompat hapInfo;
            EXPECT_EQ(RET_SUCCESS, AccessTokenCompatKit::GetHapTokenInfo(tokenID, hapInfo));
            EXPECT_EQ(name, hapInfo.bundleName);
        }
    }
}
}  // namespace SecurityComponent
}  // namespace Security
}  // namespace OHOS