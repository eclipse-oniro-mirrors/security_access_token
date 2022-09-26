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

#include "accesstoken_kit.h"
#include "audio_system_manager.h"
#include "sensitive_resource_manager.h"
#include "token_setproc.h"

using namespace testing;
using namespace testing::ext;
using namespace OHOS;
using namespace OHOS::AudioStandard;

namespace OHOS {
namespace Security {
namespace AccessToken {
namespace {
static const size_t MAX_CALLBACK_SIZE = 200;
static uint32_t g_tokenId = 0;
static int32_t g_status = 0;
}
class SensitiveResourceManagerTest : public testing::Test {
public:
    static void SetUpTestCase();
    static void TearDownTestCase();
    void SetUp();
    void TearDown();

    uint32_t tokenId_;
};

void SensitiveResourceManagerTest::SetUpTestCase()
{
}

void SensitiveResourceManagerTest::TearDownTestCase()
{
}

void SensitiveResourceManagerTest::SetUp()
{
    tokenId_ = AccessTokenKit::GetHapTokenID(100, "com.ohos.permissionmanager", 0); // 100 is userID
    SensitiveResourceManager::GetInstance().Init();
}

void SensitiveResourceManagerTest::TearDown()
{
}

void AppStatusChangeCallback(uint32_t tokenId, int32_t status)
{
    g_tokenId = tokenId;
    g_status = status;
}

void AppStatusChangeCallback1(uint32_t tokenId, int32_t status)
{
    GTEST_LOG_(INFO) << "tokenId: " << tokenId << "status: " << status;
}

/**
 * @tc.name: RegisterAppStatusChangeCallback001
 * @tc.desc: Test RegisterAppStatusChangeCallback with invalid parameter.
 * @tc.type: FUNC
 * @tc.require: issueI5RWXA issueI5RWXF
 */
HWTEST_F(SensitiveResourceManagerTest, RegisterAppStatusChangeCallback001, TestSize.Level1)
{
    ASSERT_EQ(false,
        SensitiveResourceManager::GetInstance().RegisterAppStatusChangeCallback(0, AppStatusChangeCallback));
    ASSERT_EQ(false,
        SensitiveResourceManager::GetInstance().RegisterAppStatusChangeCallback(tokenId_, nullptr));
}

/**
 * @tc.name: RegisterAppStatusChangeCallback002
 * @tc.desc: Test RegisterAppStatusChangeCallback with same callback duplicate.
 * @tc.type: FUNC
 * @tc.require: issueI5RWXA issueI5RWXF
 */
HWTEST_F(SensitiveResourceManagerTest, RegisterAppStatusChangeCallback002, TestSize.Level1)
{
    uint32_t tokenId1 = 123;
    uint32_t tokenId2 = 456;
    ASSERT_EQ(true,
        SensitiveResourceManager::GetInstance().RegisterAppStatusChangeCallback(tokenId1, AppStatusChangeCallback));
    ASSERT_EQ(true,
        SensitiveResourceManager::GetInstance().RegisterAppStatusChangeCallback(tokenId1, AppStatusChangeCallback));
    ASSERT_EQ(true,
        SensitiveResourceManager::GetInstance().RegisterAppStatusChangeCallback(tokenId2, AppStatusChangeCallback));
    ASSERT_EQ(true,
        SensitiveResourceManager::GetInstance().RegisterAppStatusChangeCallback(tokenId1, AppStatusChangeCallback1));
    ASSERT_EQ(true,
        SensitiveResourceManager::GetInstance().RegisterAppStatusChangeCallback(tokenId2, AppStatusChangeCallback1));

    SensitiveResourceManager::GetInstance().UnRegisterAppStatusChangeCallback(tokenId1, AppStatusChangeCallback);
    SensitiveResourceManager::GetInstance().UnRegisterAppStatusChangeCallback(tokenId2, AppStatusChangeCallback);
    SensitiveResourceManager::GetInstance().UnRegisterAppStatusChangeCallback(tokenId1, AppStatusChangeCallback1);
    SensitiveResourceManager::GetInstance().UnRegisterAppStatusChangeCallback(tokenId2, AppStatusChangeCallback1);
}

typedef void (*AppChangeCallback)(uint32_t tokenId, int32_t status);
std::map<uint32_t, uint32_t> g_listers;
static bool RegisterAppStatusChangeCallbackTest(uint32_t tokenId, uint32_t cbAddr)
{
    AppChangeCallback callback = (AppChangeCallback)cbAddr;
    g_listers[tokenId] = (uint32_t)callback;
    return SensitiveResourceManager::GetInstance().RegisterAppStatusChangeCallback(tokenId, callback);
}

static bool UnregisterAppStatusChangeCallbackTest(uint32_t tokenId)
{
    AppChangeCallback callback = (AppChangeCallback)g_listers[tokenId];
    return SensitiveResourceManager::GetInstance().UnRegisterAppStatusChangeCallback(tokenId, callback);
}

/**
 * @tc.name: RegisterAppStatusChangeCallback003
 * @tc.desc: Test RegisterAppStatusChangeCallback oversize.
 * @tc.type: FUNC
 * @tc.require: issueI5RWXA issueI5RWXF
 */
HWTEST_F(SensitiveResourceManagerTest, RegisterAppStatusChangeCallback003, TestSize.Level1)
{
    uint32_t tokenId = 1; // 1: tokenId
    uint32_t addr = 0x12345678; // 0x12345678: simulated address
    for (size_t i = 0; i < MAX_CALLBACK_SIZE; i++) {
        ASSERT_EQ(true, RegisterAppStatusChangeCallbackTest(tokenId, addr));
        tokenId++;
        addr++;
    }
    ASSERT_EQ(false, RegisterAppStatusChangeCallbackTest(tokenId, addr));

    tokenId = 1; // 1: tokenId
    for (size_t i = 0; i < MAX_CALLBACK_SIZE; i++) {
        ASSERT_EQ(true, UnregisterAppStatusChangeCallbackTest(tokenId));
        tokenId++;
    }
}

/**
 * @tc.name: UnRegisterAppStatusChangeCallback001
 * @tc.desc: Test UnRegisterAppStatusChangeCallback wit invalid parameter.
 * @tc.type: FUNC
 * @tc.require: issueI5RWXA issueI5RWXF
 */
HWTEST_F(SensitiveResourceManagerTest, UnRegisterAppStatusChangeCallback001, TestSize.Level1)
{
    ASSERT_EQ(false,
        SensitiveResourceManager::GetInstance().UnRegisterAppStatusChangeCallback(0, AppStatusChangeCallback));
    ASSERT_EQ(false,
        SensitiveResourceManager::GetInstance().UnRegisterAppStatusChangeCallback(tokenId_, nullptr));
    ASSERT_EQ(false,
        SensitiveResourceManager::GetInstance().UnRegisterAppStatusChangeCallback(tokenId_, AppStatusChangeCallback));
}

/**
 * @tc.name: UnRegisterAppStatusChangeCallback002
 * @tc.desc: Test UnRegisterAppStatusChangeCallback wit invalid parameter.
 * @tc.type: FUNC
 * @tc.require: issueI5RWXA issueI5RWXF
 */
HWTEST_F(SensitiveResourceManagerTest, UnRegisterAppStatusChangeCallback002, TestSize.Level1)
{
    ASSERT_EQ(false,
        SensitiveResourceManager::GetInstance().UnRegisterAppStatusChangeCallback(0, AppStatusChangeCallback));
    ASSERT_EQ(false,
        SensitiveResourceManager::GetInstance().UnRegisterAppStatusChangeCallback(tokenId_, nullptr));
    ASSERT_EQ(false,
        SensitiveResourceManager::GetInstance().UnRegisterAppStatusChangeCallback(tokenId_, AppStatusChangeCallback));
}

/**
 * @tc.name: GetGlobalSwitchTest001
 * @tc.desc: Verify the GetGlobalSwitch with valid ResourceType.
 * @tc.type: FUNC
 * @tc.require: issueI5RWXA issueI5RWXF
 */
HWTEST_F(SensitiveResourceManagerTest, GetGlobalSwitchTest001, TestSize.Level1)
{
    SensitiveResourceManager::GetInstance().SetGlobalSwitch(ResourceType::MICROPHONE, true);
    usleep(500000); // 500000us = 0.5s
    ASSERT_EQ(true, SensitiveResourceManager::GetInstance().GetGlobalSwitch(ResourceType::MICROPHONE));

    SensitiveResourceManager::GetInstance().SetGlobalSwitch(ResourceType::MICROPHONE, false);
    usleep(500000); // 500000us = 0.5s
    ASSERT_EQ(false, SensitiveResourceManager::GetInstance().GetGlobalSwitch(ResourceType::MICROPHONE));
}

/**
 * @tc.name: GetGlobalSwitchTest002
 * @tc.desc: Verify the GetGlobalSwitch abnormal branch ResourceType is invalid.
 * @tc.type: FUNC
 * @tc.require: issueI5RWXA issueI5RWXF
 */
HWTEST_F(SensitiveResourceManagerTest, GetGlobalSwitchTest002, TestSize.Level1)
{
    ASSERT_EQ(true, SensitiveResourceManager::GetInstance().GetGlobalSwitch(ResourceType::INVALID));
}

/**
 * @tc.name: SetGlobalSwitchTest001
 * @tc.desc: Verify the SetGlobalSwitch with valid ResourceType.
 * @tc.type: FUNC
 * @tc.require: issueI5RWXA issueI5RWXF
 */
HWTEST_F(SensitiveResourceManagerTest, SetGlobalSwitchTest001, TestSize.Level1)
{
    SensitiveResourceManager::GetInstance().SetGlobalSwitch(ResourceType::CAMERA, true);
    usleep(500000); // 500000us = 0.5s
    ASSERT_EQ(true, SensitiveResourceManager::GetInstance().GetGlobalSwitch(ResourceType::CAMERA));

    SensitiveResourceManager::GetInstance().SetGlobalSwitch(ResourceType::CAMERA, false);
    usleep(500000); // 500000us = 0.5s
    ASSERT_EQ(false, SensitiveResourceManager::GetInstance().GetGlobalSwitch(ResourceType::CAMERA));
}

/**
 * @tc.name: SetGlobalSwitchTest002
 * @tc.desc: Verify the SetGlobalSwitch abnormal branch ResourceType is invalid.
 * @tc.type: FUNC
 * @tc.require: issueI5RWXA issueI5RWXF
 */
HWTEST_F(SensitiveResourceManagerTest, SetGlobalSwitchTest002, TestSize.Level1)
{
    bool isMicrophoneMute = AudioStandard::AudioSystemManager::GetInstance()->IsMicrophoneMute();

    SensitiveResourceManager::GetInstance().SetGlobalSwitch(ResourceType::INVALID, true);
    usleep(500000); // 500000us = 0.5s
    ASSERT_EQ(isMicrophoneMute, SensitiveResourceManager::GetInstance().GetGlobalSwitch(ResourceType::MICROPHONE));

    SensitiveResourceManager::GetInstance().SetGlobalSwitch(ResourceType::INVALID, false);
    usleep(500000); // 500000us = 0.5s
    ASSERT_EQ(isMicrophoneMute, SensitiveResourceManager::GetInstance().GetGlobalSwitch(ResourceType::MICROPHONE));
}
} // namespace AccessToken
} // namespace Security
} // namespace OHOS
