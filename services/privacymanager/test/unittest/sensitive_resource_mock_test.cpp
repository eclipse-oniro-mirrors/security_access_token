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

#include <cstddef>
#include <gtest/gtest.h>
#include "active_change_response_info.h"
#include "mock_test.h"
#define private public
#include "sensitive_resource_manager.h"
#undef private

using namespace testing;
using namespace testing::ext;
using namespace OHOS;

namespace OHOS {
namespace Security {
namespace AccessToken {
uint32_t g_tokenId = 0;
int32_t g_status = INACTIVE;

class SensitiveResourceMockTest : public testing::Test {
public:
    static void SetUpTestCase();
    static void TearDownTestCase();
    void SetUp();
    void TearDown();
};

void SensitiveResourceMockTest::SetUpTestCase()
{
}

void SensitiveResourceMockTest::TearDownTestCase()
{
}

void SensitiveResourceMockTest::SetUp()
{
}

void SensitiveResourceMockTest::TearDown()
{
}

static void ResetProxy(uint32_t flag)
{
    SensitiveResourceManager::GetInstance().appMgrProxy_ = nullptr;
    SetAppProxyFlag(flag);
}

/**
 * @tc.name: GetAppStatus001
 * @tc.desc: Test GetAppStatus.
 * @tc.type: FUNC
 * @tc.require: issueI5RWXA issueI5RWXF
 */
HWTEST_F(SensitiveResourceMockTest, GetAppStatus001, TestSize.Level1)
{
    std::string bundleName = "ohos.test.access_token";
    int32_t status = 0;

    ResetProxy(0); // proxy is null
    ASSERT_FALSE(SensitiveResourceManager::GetInstance().GetAppStatus(bundleName, status));
    ASSERT_EQ(status, 0);

    ResetProxy(1); // GetSystemAbility fail
    ASSERT_FALSE(SensitiveResourceManager::GetInstance().GetAppStatus(bundleName, status));
    ASSERT_EQ(status, 0);

    ResetProxy(2);
    ASSERT_TRUE(SensitiveResourceManager::GetInstance().GetAppStatus(bundleName, status));
    ASSERT_EQ(status, PERM_ACTIVE_IN_FOREGROUND);
}

void AppStatusChangeCallback(uint32_t tokenId, int32_t status)
{
    GTEST_LOG_(INFO) << "tokenId: " << tokenId << ", status: " << status;
    g_tokenId = tokenId;
    g_status = status;
}

/**
 * @tc.name: RegisterAppStatusChangeCallback001
 * @tc.desc: Test RegisterAppStatusChangeCallback.
 * @tc.type: FUNC
 * @tc.require: issueI5RWXA issueI5RWXF
 */
HWTEST_F(SensitiveResourceMockTest, RegisterAppStatusChangeCallback001, TestSize.Level1)
{
    ResetProxy(0); // proxy is null
    ASSERT_FALSE(
        SensitiveResourceManager::GetInstance().RegisterAppStatusChangeCallback(123, AppStatusChangeCallback));
}

/**
 * @tc.name: UnRegisterAppStatusChangeCallback001
 * @tc.desc: Test UnRegisterAppStatusChangeCallback.
 * @tc.type: FUNC
 * @tc.require: issueI5RWXA issueI5RWXF
 */
HWTEST_F(SensitiveResourceMockTest, UnRegisterAppStatusChangeCallback001, TestSize.Level1)
{
    ResetProxy(2);
    uint32_t tokenId = 123;

    // register with valid
    ASSERT_TRUE(
        SensitiveResourceManager::GetInstance().RegisterAppStatusChangeCallback(tokenId, AppStatusChangeCallback));

    // unregister with proxy is null
    ResetProxy(0);
    ASSERT_FALSE(
        SensitiveResourceManager::GetInstance().UnRegisterAppStatusChangeCallback(tokenId, AppStatusChangeCallback));

    // clear environment
    ResetProxy(2);
    ASSERT_TRUE(
        SensitiveResourceManager::GetInstance().UnRegisterAppStatusChangeCallback(tokenId, AppStatusChangeCallback));
}

/**
 * @tc.name: UnRegisterAppStatusChangeCallback002
 * @tc.desc: Test UnRegisterAppStatusChangeCallback.
 * @tc.type: FUNC
 * @tc.require: issueI5RWXA issueI5RWXF
 */
HWTEST_F(SensitiveResourceMockTest, UnRegisterAppStatusChangeCallback002, TestSize.Level1)
{
    ResetProxy(2);
    uint32_t tokenId = 123;

    // register with valid
    ASSERT_TRUE(
        SensitiveResourceManager::GetInstance().RegisterAppStatusChangeCallback(tokenId, AppStatusChangeCallback));

    SwitchForeOrBackGround(tokenId, ACTIVE_FOREGROUND);
    ASSERT_EQ(tokenId, g_tokenId);
    ASSERT_EQ(ACTIVE_FOREGROUND, g_status);

    g_tokenId = 0;
    g_status = 0;
    SwitchForeOrBackGround(tokenId, ACTIVE_BACKGROUND);
    ASSERT_EQ(tokenId, g_tokenId);
    ASSERT_EQ(ACTIVE_BACKGROUND, g_status);

    // clear environment
    ResetProxy(2);
    ASSERT_TRUE(
        SensitiveResourceManager::GetInstance().UnRegisterAppStatusChangeCallback(tokenId, AppStatusChangeCallback));
}
} // namespace AccessToken
} // namespace Security
} // namespace OHOS
