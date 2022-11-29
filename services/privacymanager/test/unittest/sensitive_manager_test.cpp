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

#include "ability_manager_privacy_client.h"
#include "ability_manager_privacy_proxy.h"
#include "accesstoken_kit.h"
#include "app_manager_privacy_client.h"
#include "app_manager_privacy_proxy.h"
#include "audio_manager_privacy_client.h"
#include "audio_manager_privacy_proxy.h"
#include "camera_manager_privacy_client.h"
#include "camera_manager_privacy_proxy.h"
#include "camera_service_callback_stub.h"
#include "token_setproc.h"
#include "window_manager_privacy_agent.h"
#include "window_manager_privacy_client.h"
#include "window_manager_privacy_proxy.h"
using namespace testing::ext;

namespace OHOS {
namespace Security {
namespace AccessToken {
class SensitiveManagerServiceTest : public testing::Test {
public:
    static void SetUpTestCase();
    static void TearDownTestCase();
    void SetUp();
    void TearDown();
};
static AccessTokenID g_selfTokenId = 0;
static PermissionStateFull g_testState1 = {
    .permissionName = "ohos.permission.RUNNING_STATE_OBSERVER",
    .isGeneral = true,
    .resDeviceID = {"local"},
    .grantStatus = {PermissionState::PERMISSION_GRANTED},
    .grantFlags = {1}
};

static PermissionStateFull g_testState2 = {
    .permissionName = "ohos.permission.MANAGE_CAMERA_CONFIG",
    .isGeneral = true,
    .resDeviceID = {"local"},
    .grantStatus = {PermissionState::PERMISSION_GRANTED},
    .grantFlags = {1}
};

static PermissionStateFull g_testState3 = {
    .permissionName = "ohos.permission.GET_RUNNING_INFO",
    .isGeneral = true,
    .resDeviceID = {"local"},
    .grantStatus = {PermissionState::PERMISSION_GRANTED},
    .grantFlags = {1}
};

static HapPolicyParams g_PolicyPrams1 = {
    .apl = APL_NORMAL,
    .domain = "test.domain.A",
    .permList = {},
    .permStateList = {g_testState1, g_testState2, g_testState3}
};

static HapInfoParams g_InfoParms1 = {
    .userID = 1,
    .bundleName = "ohos.privacy_test.bundleA",
    .instIndex = 0,
    .appIDDesc = "privacy_test.bundleA"
};
void SensitiveManagerServiceTest::SetUpTestCase()
{
    g_selfTokenId = GetSelfTokenID();
}

void SensitiveManagerServiceTest::TearDownTestCase()
{
}

void SensitiveManagerServiceTest::SetUp()
{
    AccessTokenKit::AllocHapToken(g_InfoParms1, g_PolicyPrams1);
    AccessTokenID tokenId = AccessTokenKit::GetHapTokenID(g_InfoParms1.userID,
                                                          g_InfoParms1.bundleName,
                                                          g_InfoParms1.instIndex);
    SetSelfTokenID(tokenId);
}

void SensitiveManagerServiceTest::TearDown()
{
    SetSelfTokenID(g_selfTokenId);
}

/*
 * @tc.name: AudioManagerPrivacyTest001
 * @tc.desc: test api function
 * @tc.type: FUNC
 * @tc.require: issueI5RWXF
 */
HWTEST_F(SensitiveManagerServiceTest, AudioManagerPrivacyTest001, TestSize.Level1)
{
    sptr<AudioRoutingManagerListenerStub> listener = new (std::nothrow) AudioRoutingManagerListenerStub();
    ASSERT_NE(listener, nullptr);
    ASSERT_NE(0, AudioManagerPrivacyClient::GetInstance().SetMicStateChangeCallback(nullptr));
    ASSERT_EQ(0, AudioManagerPrivacyClient::GetInstance().SetMicStateChangeCallback(listener));
    bool initMute = AudioManagerPrivacyClient::GetInstance().IsMicrophoneMute();

    AudioManagerPrivacyClient::GetInstance().SetMicrophoneMute(false);
    EXPECT_EQ(false, AudioManagerPrivacyClient::GetInstance().IsMicrophoneMute());

    AudioManagerPrivacyClient::GetInstance().SetMicrophoneMute(true);
    EXPECT_EQ(true, AudioManagerPrivacyClient::GetInstance().IsMicrophoneMute());

    AudioManagerPrivacyClient::GetInstance().SetMicrophoneMute(false);
    EXPECT_EQ(false, AudioManagerPrivacyClient::GetInstance().IsMicrophoneMute());

    AudioManagerPrivacyClient::GetInstance().SetMicrophoneMute(initMute);
}

/*
 * @tc.name: CameraManagerPrivacyTest001
 * @tc.desc: test api function
 * @tc.type: FUNC
 * @tc.require: issueI5RWXF
 */
HWTEST_F(SensitiveManagerServiceTest, CameraManagerPrivacyTest001, TestSize.Level1)
{
    sptr<CameraServiceCallbackStub> listener = new (std::nothrow) CameraServiceCallbackStub();
    ASSERT_NE(listener, nullptr);
    ASSERT_NE(0, CameraManagerPrivacyClient::GetInstance().SetMuteCallback(nullptr));
    ASSERT_EQ(0, CameraManagerPrivacyClient::GetInstance().SetMuteCallback(listener));
    bool initMute = CameraManagerPrivacyClient::GetInstance().IsCameraMuted();

    CameraManagerPrivacyClient::GetInstance().MuteCamera(false);
    EXPECT_EQ(false, CameraManagerPrivacyClient::GetInstance().IsCameraMuted());

    CameraManagerPrivacyClient::GetInstance().MuteCamera(true);
    EXPECT_EQ(true, CameraManagerPrivacyClient::GetInstance().IsCameraMuted());

    CameraManagerPrivacyClient::GetInstance().MuteCamera(false);
    EXPECT_EQ(false, CameraManagerPrivacyClient::GetInstance().IsCameraMuted());

    CameraManagerPrivacyClient::GetInstance().MuteCamera(initMute);
}

/*
 * @tc.name: AppManagerPrivacyTest001
 * @tc.desc: test api function
 * @tc.type: FUNC
 * @tc.require: issueI5RWXF
 */
HWTEST_F(SensitiveManagerServiceTest, AppManagerPrivacyTest001, TestSize.Level1)
{
    sptr<ApplicationStateObserverStub> listener = new(std::nothrow) ApplicationStateObserverStub();
    ASSERT_NE(listener, nullptr);
    ASSERT_NE(0, AppManagerPrivacyClient::GetInstance().RegisterApplicationStateObserver(nullptr));
    ASSERT_EQ(0, AppManagerPrivacyClient::GetInstance().RegisterApplicationStateObserver(listener));

    std::vector<AppStateData> list;
    ASSERT_EQ(0, AppManagerPrivacyClient::GetInstance().GetForegroundApplications(list));

    ASSERT_NE(0, AppManagerPrivacyClient::GetInstance().UnregisterApplicationStateObserver(nullptr));
    ASSERT_EQ(0, AppManagerPrivacyClient::GetInstance().UnregisterApplicationStateObserver(listener));
}

/*
 * @tc.name: AbilityManagerPrivacyTest001
 * @tc.desc: test api function
 * @tc.type: FUNC
 * @tc.require: issueI5RWXF
 */
HWTEST_F(SensitiveManagerServiceTest, AbilityManagerPrivacyTest001, TestSize.Level1)
{
    const std::string bundleName = "com.ohos.permissionmanager";
    const std::string abilityName = "com.ohos.permissionmanager.GlobalExtAbility";
    const std::string resourceKey = "ohos.sensitive.resource";
    std::string resource = "resource";
    AAFwk::Want want;
    want.SetElementName(bundleName, abilityName);
    want.SetParam(resourceKey, resource);
    ASSERT_NE(0, AbilityManagerPrivacyClient::GetInstance().StartAbility(want, nullptr));
}

/*
 * @tc.name: WindowManagerPrivacyTest001
 * @tc.desc: test api function
 * @tc.type: FUNC
 * @tc.require: issueI5RWXF
 */
HWTEST_F(SensitiveManagerServiceTest, WindowManagerPrivacyTest001, TestSize.Level1)
{
    sptr<WindowManagerPrivacyAgent> listener = new(std::nothrow) WindowManagerPrivacyAgent();
    ASSERT_NE(listener, nullptr);
    ASSERT_EQ(true, WindowManagerPrivacyClient::GetInstance().RegisterWindowManagerAgent(
        WindowManagerAgentType::WINDOW_MANAGER_AGENT_TYPE_CAMERA_FLOAT, listener));
    ASSERT_EQ(true, WindowManagerPrivacyClient::GetInstance().UnregisterWindowManagerAgent(
        WindowManagerAgentType::WINDOW_MANAGER_AGENT_TYPE_CAMERA_FLOAT, listener));
}
} // namespace AccessToken
} // namespace Security
} // namespace OHOS
