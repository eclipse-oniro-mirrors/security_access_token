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
#include "ability_context_impl.h"
#include "accesstoken_kit.h"
#include "audio_system_manager.h"
#include "sensitive_resource_manager.h"
#include "token_setproc.h"
#include "window.h"
#include "window_scene.h"
#include "wm_common.h"

using namespace testing;
using namespace testing::ext;
using namespace OHOS;
using namespace OHOS::Security::AccessToken;

class SensitiveResourceManagerTest : public testing::Test {
public:
    static void SetUpTestCase();
    static void TearDownTestCase();
    void SetUp();
    void TearDown();
};

void SensitiveResourceManagerTest::SetUpTestCase()
{ 
}

void SensitiveResourceManagerTest::TearDownTestCase()
{
}

void SensitiveResourceManagerTest::SetUp()
{
    SensitiveResourceManager::GetInstance().Init();
}

void SensitiveResourceManagerTest::TearDown()
{
}

/**
 * @tc.name: GetGlobalSwitchTest_001
 * @tc.desc: Verify the GetGlobalSwitch with vaild ResourceType.
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(SensitiveResourceManagerTest, GetGlobalSwitchTest_001, TestSize.Level1)
{
    SensitiveResourceManager::GetInstance().SetGlobalSwitch(ResourceType::MICROPHONE, true);
    usleep(500000); // 500000us = 0.5s
    ASSERT_EQ(true, SensitiveResourceManager::GetInstance().GetGlobalSwitch(ResourceType::MICROPHONE));

    SensitiveResourceManager::GetInstance().SetGlobalSwitch(ResourceType::MICROPHONE, false);
    usleep(500000); // 500000us = 0.5s
    ASSERT_EQ(false, SensitiveResourceManager::GetInstance().GetGlobalSwitch(ResourceType::MICROPHONE));
}

/**
 * @tc.name: GetGlobalSwitchTest_002
 * @tc.desc: Verify the GetGlobalSwitch abnormal branch ResourceType is invalid.
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(SensitiveResourceManagerTest, GetGlobalSwitchTest_002, TestSize.Level1)
{
    SensitiveResourceManager::GetInstance().SetGlobalSwitch(ResourceType::CAMERA, true);
    usleep(500000); // 500000us = 0.5s
    ASSERT_EQ(true, SensitiveResourceManager::GetInstance().GetGlobalSwitch(ResourceType::INVALID));

    SensitiveResourceManager::GetInstance().SetGlobalSwitch(ResourceType::CAMERA, false);
    usleep(500000); // 500000us = 0.5s
    ASSERT_EQ(true, SensitiveResourceManager::GetInstance().GetGlobalSwitch(ResourceType::INVALID));
}

/**
 * @tc.name: SetGlobalSwitchTest_001
 * @tc.desc: Verify the SetGlobalSwitch with vaild ResourceType.
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(SensitiveResourceManagerTest, SetGlobalSwitchTest_001, TestSize.Level1)
{
    SensitiveResourceManager::GetInstance().SetGlobalSwitch(ResourceType::CAMERA, true);
    usleep(500000); // 500000us = 0.5s
    ASSERT_EQ(true, SensitiveResourceManager::GetInstance().GetGlobalSwitch(ResourceType::CAMERA));

    SensitiveResourceManager::GetInstance().SetGlobalSwitch(ResourceType::CAMERA, false);
    usleep(500000); // 500000us = 0.5s
    ASSERT_EQ(false, SensitiveResourceManager::GetInstance().GetGlobalSwitch(ResourceType::CAMERA));
}

/**
 * @tc.name: SetGlobalSwitchTest_002
 * @tc.desc: Verify the SetGlobalSwitch abnormal branch ResourceType is invalid.
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(SensitiveResourceManagerTest, SetGlobalSwitchTest_002, TestSize.Level1)
{
    bool isMicrophoneMute = AudioStandard::AudioSystemManager::GetInstance()->IsMicrophoneMute();

    SensitiveResourceManager::GetInstance().SetGlobalSwitch(ResourceType::INVALID, true);
    usleep(500000); // 500000us = 0.5s
    ASSERT_EQ(isMicrophoneMute, SensitiveResourceManager::GetInstance().GetGlobalSwitch(ResourceType::MICROPHONE));

    SensitiveResourceManager::GetInstance().SetGlobalSwitch(ResourceType::INVALID, false);
    usleep(500000); // 500000us = 0.5s
    ASSERT_EQ(isMicrophoneMute, SensitiveResourceManager::GetInstance().GetGlobalSwitch(ResourceType::MICROPHONE));
}

