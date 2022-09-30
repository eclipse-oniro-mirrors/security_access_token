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
#include "privacy_error.h"
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


static bool g_micStatus = false;
static void OnChangeMicGlobalSwitch(bool isMute)
{
    GTEST_LOG_(INFO) << " OnChangeMicGlobalSwitch mic_isMute_before_set: " << g_micStatus;
    g_micStatus = !(isMute);
    GTEST_LOG_(INFO) << " OnChangeMicGlobalSwitch mic_isMute_after_set: " << g_micStatus;
}

static void ResetEnv()
{
    g_micStatus = false;
}

/**
 * @tc.name: RegisterAppStatusChangeCallback001
 * @tc.desc: Test RegisterAppStatusChangeCallback with invalid parameter.
 * @tc.type: FUNC
 * @tc.require: issueI5RWXA issueI5RWXF
 */
HWTEST_F(SensitiveResourceManagerTest, RegisterAppStatusChangeCallback001, TestSize.Level1)
{
    ASSERT_EQ(PrivacyError::ERR_PARAM_INVALID,
        SensitiveResourceManager::GetInstance().RegisterAppStatusChangeCallback(0, AppStatusChangeCallback));
    ASSERT_EQ(PrivacyError::ERR_PARAM_INVALID,
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
    ASSERT_EQ(RET_SUCCESS,
        SensitiveResourceManager::GetInstance().RegisterAppStatusChangeCallback(tokenId1, AppStatusChangeCallback));
    ASSERT_EQ(RET_SUCCESS,
        SensitiveResourceManager::GetInstance().RegisterAppStatusChangeCallback(tokenId1, AppStatusChangeCallback));
    ASSERT_EQ(RET_SUCCESS,
        SensitiveResourceManager::GetInstance().RegisterAppStatusChangeCallback(tokenId2, AppStatusChangeCallback));
    ASSERT_EQ(RET_SUCCESS,
        SensitiveResourceManager::GetInstance().RegisterAppStatusChangeCallback(tokenId1, AppStatusChangeCallback1));
    ASSERT_EQ(RET_SUCCESS,
        SensitiveResourceManager::GetInstance().RegisterAppStatusChangeCallback(tokenId2, AppStatusChangeCallback1));

    SensitiveResourceManager::GetInstance().UnRegisterAppStatusChangeCallback(tokenId1, AppStatusChangeCallback);
    SensitiveResourceManager::GetInstance().UnRegisterAppStatusChangeCallback(tokenId2, AppStatusChangeCallback);
    SensitiveResourceManager::GetInstance().UnRegisterAppStatusChangeCallback(tokenId1, AppStatusChangeCallback1);
    SensitiveResourceManager::GetInstance().UnRegisterAppStatusChangeCallback(tokenId2, AppStatusChangeCallback1);
}

typedef void (*AppChangeCallback)(uint32_t tokenId, int32_t status);
std::map<uint32_t, uint64_t> g_listers;
static int32_t RegisterAppStatusChangeCallbackTest(uint32_t tokenId, uint64_t cbAddr)
{
    AppChangeCallback callback = (AppChangeCallback)cbAddr;
    g_listers[tokenId] = cbAddr;
    return SensitiveResourceManager::GetInstance().RegisterAppStatusChangeCallback(tokenId, callback);
}

static int32_t UnregisterAppStatusChangeCallbackTest(uint32_t tokenId)
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
    uint64_t addr = 0x12345678; // 0x12345678: simulated address
    for (size_t i = 0; i < MAX_CALLBACK_SIZE; i++) {
        ASSERT_EQ(RET_SUCCESS, RegisterAppStatusChangeCallbackTest(tokenId, addr));
        tokenId++;
        addr++;
    }
    ASSERT_EQ(PrivacyError::ERR_CALLBACKS_EXCEED_LIMITATION, RegisterAppStatusChangeCallbackTest(tokenId, addr));

    tokenId = 1; // 1: tokenId
    for (size_t i = 0; i < MAX_CALLBACK_SIZE; i++) {
        ASSERT_EQ(RET_SUCCESS, UnregisterAppStatusChangeCallbackTest(tokenId));
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
    ASSERT_EQ(PrivacyError::ERR_PARAM_INVALID,
        SensitiveResourceManager::GetInstance().UnRegisterAppStatusChangeCallback(0, AppStatusChangeCallback));
    ASSERT_EQ(PrivacyError::ERR_PARAM_INVALID,
        SensitiveResourceManager::GetInstance().UnRegisterAppStatusChangeCallback(tokenId_, nullptr));
    ASSERT_EQ(PrivacyError::ERR_CALLBACK_NOT_EXIST,
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
    bool microphoneStatus = SensitiveResourceManager::GetInstance().GetGlobalSwitch(ResourceType::MICROPHONE);

    SensitiveResourceManager::GetInstance().SetGlobalSwitch(ResourceType::INVALID, true);
    usleep(500000); // 500000us = 0.5s
    ASSERT_EQ(microphoneStatus, SensitiveResourceManager::GetInstance().GetGlobalSwitch(ResourceType::MICROPHONE));

    SensitiveResourceManager::GetInstance().SetGlobalSwitch(ResourceType::INVALID, false);
    usleep(500000); // 500000us = 0.5s
    ASSERT_EQ(microphoneStatus, SensitiveResourceManager::GetInstance().GetGlobalSwitch(ResourceType::MICROPHONE));
}

/**
 * @tc.name: FlowWindowStatusTest001
 * @tc.desc: Verify the SetFlowWindowStatus IsFlowWindowShow.
 * @tc.type: FUNC
 * @tc.require: issueI5RWX5
 */
HWTEST_F(SensitiveResourceManagerTest, FlowWindowStatusTest001, TestSize.Level1)
{
    SensitiveResourceManager::GetInstance().SetFlowWindowStatus(true);

    ASSERT_TRUE(SensitiveResourceManager::GetInstance().IsFlowWindowShow());

    SensitiveResourceManager::GetInstance().SetFlowWindowStatus(false);

    ASSERT_FALSE(SensitiveResourceManager::GetInstance().IsFlowWindowShow());
}

/**
 * @tc.name: RegisterMicGlobalSwitchChangeCallbackTest001
 * @tc.desc: call RegisterMicGlobalSwitchChangeCallback ShowDialog once.
 * @tc.type: FUNC
 * @tc.require: issueI5RWX8
 */
HWTEST_F(SensitiveResourceManagerTest, RegisterMicGlobalSwitchChangeCallbackTest001, TestSize.Level1)
{
    SensitiveResourceManager::GetInstance().RegisterMicGlobalSwitchChangeCallback(OnChangeMicGlobalSwitch);

    bool isMute = AudioStandard::AudioSystemManager::GetInstance()->IsMicrophoneMute();

    ResetEnv();

    AudioStandard::AudioSystemManager::GetInstance()->SetMicrophoneMute(true);
    usleep(500000); // 500000us = 0.5s
    ASSERT_TRUE(g_micStatus);

    ResetEnv();

    AudioStandard::AudioSystemManager::GetInstance()->SetMicrophoneMute(false);
    usleep(500000); // 500000us = 0.5s
    ASSERT_FALSE(g_micStatus);
    
    ResetEnv();
    AudioStandard::AudioSystemManager::GetInstance()->SetMicrophoneMute(isMute);
    SensitiveResourceManager::GetInstance().UnRegisterMicGlobalSwitchChangeCallback(OnChangeMicGlobalSwitch);
}


/**
 * @tc.name: RegisterMicGlobalSwitchChangeCallbackTest002
 * @tc.desc: Verify the RegisterMicGlobalSwitchChangeCallback abnormal branch callback is invalid.
 * @tc.type: FUNC
 * @tc.require: issueI5RWX8
 */
HWTEST_F(SensitiveResourceManagerTest, RegisterMicGlobalSwitchChangeCallbackTest002, TestSize.Level1)
{
    EXPECT_EQ(ERR_CALLBACK_NOT_EXIST,
        SensitiveResourceManager::GetInstance().RegisterMicGlobalSwitchChangeCallback(nullptr));

    ASSERT_EQ(RET_SUCCESS,
        SensitiveResourceManager::GetInstance().RegisterMicGlobalSwitchChangeCallback(OnChangeMicGlobalSwitch));
    ASSERT_EQ(ERR_CALLBACK_ALREADY_EXIST,
        SensitiveResourceManager::GetInstance().RegisterMicGlobalSwitchChangeCallback(OnChangeMicGlobalSwitch));

    SensitiveResourceManager::GetInstance().UnRegisterMicGlobalSwitchChangeCallback(OnChangeMicGlobalSwitch);
}

/**
 * @tc.name: UnRegisterMicGlobalSwitchChangeCallbackTest001
 * @tc.desc: Verify the UnRegisterMicGlobalSwitchChangeCallback with vaild callback.
 * @tc.type: FUNC
 * @tc.require: issueI5RWX8
 */
HWTEST_F(SensitiveResourceManagerTest, UnRegisterMicGlobalSwitchChangeCallbackTest001, TestSize.Level1)
{
    ASSERT_EQ(RET_SUCCESS,
        SensitiveResourceManager::GetInstance().RegisterMicGlobalSwitchChangeCallback(OnChangeMicGlobalSwitch));
    ASSERT_EQ(RET_SUCCESS,
        SensitiveResourceManager::GetInstance().UnRegisterMicGlobalSwitchChangeCallback(OnChangeMicGlobalSwitch));
}

/**
 * @tc.name: UnRegisterMicGlobalSwitchChangeCallbackTest002
 * @tc.desc: Verify the UnRegisterMicGlobalSwitchChangeCallback abnormal branch callback is invalid.
 * @tc.type: FUNC
 * @tc.require: issueI5RWX8
 */
HWTEST_F(SensitiveResourceManagerTest, UnRegisterMicGlobalSwitchChangeCallbackTest002, TestSize.Level1)
{
    EXPECT_EQ(ERR_CALLBACK_NOT_EXIST,
        SensitiveResourceManager::GetInstance().UnRegisterMicGlobalSwitchChangeCallback(nullptr));
    EXPECT_EQ(ERR_CALLBACK_NOT_EXIST,
        SensitiveResourceManager::GetInstance().UnRegisterMicGlobalSwitchChangeCallback(OnChangeMicGlobalSwitch));
}

/**
 * @tc.name: ShowDialogTest001
 * @tc.desc: call ShowDialog once with valid ResourceType.
 * @tc.type: FUNC
 * @tc.require: issueI5RWXF issueI5RWXA
 */
HWTEST_F(SensitiveResourceManagerTest, ShowDialogTest001, TestSize.Level1)
{
    EXPECT_EQ(RET_SUCCESS, SensitiveResourceManager::GetInstance().ShowDialog(ResourceType::MICROPHONE));
    sleep(3);
    EXPECT_EQ(RET_SUCCESS, SensitiveResourceManager::GetInstance().ShowDialog(ResourceType::CAMERA));
}

/**
 * @tc.name: ShowDialogTest002
 * @tc.desc: Verify the ShowDialog abnormal branch with invalid ResourceType.
 * @tc.type: FUNC
 * @tc.require: issueI5RWXF issueI5RWXA
 */
HWTEST_F(SensitiveResourceManagerTest, ShowDialogTest002, TestSize.Level1)
{
    EXPECT_EQ(ERR_PARAM_INVALID, SensitiveResourceManager::GetInstance().ShowDialog(ResourceType::INVALID));
}
} // namespace AccessToken
} // namespace Security
} // namespace OHOS
