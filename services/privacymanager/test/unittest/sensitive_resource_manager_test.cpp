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

#include "ability_context_impl.h"
#include "accesstoken_kit.h"
#include "audio_system_manager.h"
#include "constant.h"
#define private public
#include "permission_record_manager.h"
#undef private
#include "privacy_error.h"
#include "sensitive_resource_manager.h"
#include "token_setproc.h"
#include "window.h"
#include "window_scene.h"
#include "wm_common.h"

using namespace testing;
using namespace testing::ext;
using namespace OHOS;
using namespace OHOS::Rosen;
using namespace OHOS::AudioStandard;
using namespace OHOS::CameraStandard;
using namespace OHOS::Security::AccessToken;

namespace OHOS {
namespace Security {
namespace AccessToken {
namespace {
static const size_t MAX_CALLBACK_SIZE = 200;
static uint32_t g_tokenId = 0;
static int32_t g_status = 0;
static bool g_micStatus = false;
static bool g_isShowing = false;
static bool g_cameraStauts = false;

static PermissionStateFull g_testState = {
    .permissionName = "ohos.permission.MANAGE_CAMERA_CONFIG",
    .isGeneral = true,
    .resDeviceID = {"local"},
    .grantStatus = {PermissionState::PERMISSION_GRANTED},
    .grantFlags = {1}
};

static HapPolicyParams g_PolicyPrams1 = {
    .apl = APL_NORMAL,
    .domain = "test.domain.A",
    .permList = {},
    .permStateList = {g_testState}
};

static HapInfoParams g_InfoParms1 = {
    .userID = 1,
    .bundleName = "ohos.privacy_test.bundleA",
    .instIndex = 0,
    .appIDDesc = "privacy_test.bundleA"
};
}
class SensitiveResourceManagerTest : public testing::Test {
public:
    static void SetUpTestCase();
    static void TearDownTestCase();
    void SetUp();
    void TearDown();

    uint32_t tokenId_;
    uint64_t selfTokenId_;
};


static void OnChangeCameraFloatWindow(AccessTokenID tokenId, bool isShowing)
{
    GTEST_LOG_(INFO) << " OnChangeCameraFloatWindow isShowing_beforeSet:" << g_isShowing;
    g_isShowing = isShowing;
    GTEST_LOG_(INFO) << " OnChangeCameraFloatWindow isShowing_afterSet:" << g_isShowing;
}

static void OnChangeMicGlobalSwitch(bool isMute)
{
    GTEST_LOG_(INFO) << " OnChangeMicGlobalSwitch mic_isMute_before_set: " << g_micStatus;
    g_micStatus = !(isMute);
    GTEST_LOG_(INFO) << " OnChangeMicGlobalSwitch mic_isMute_after_set: " << g_micStatus;
}

static void OnChangeCameraGlobalSwitch(bool isMute)
{
    GTEST_LOG_(INFO) << " OnChangeMicGlobalSwitch camera_status_before_set: " << g_cameraStauts;
    g_cameraStauts = isMute;
    GTEST_LOG_(INFO) << " OnChangeMicGlobalSwitch camera_status_after_set: " << g_cameraStauts;
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

static void ResetEnv()
{
    g_micStatus = false;
    g_isShowing = false;
    g_cameraStauts = false;
    g_status = 0;
    g_tokenId = 0;
}

void SensitiveResourceManagerTest::SetUpTestCase()
{
}

void SensitiveResourceManagerTest::TearDownTestCase()
{
}

void SensitiveResourceManagerTest::SetUp()
{
    AccessTokenKit::AllocHapToken(g_InfoParms1, g_PolicyPrams1);

    selfTokenId_ = GetSelfTokenID();
    tokenId_ = AccessTokenKit::GetHapTokenID(100, "com.ohos.permissionmanager", 0); // 100 is userID
}

void SensitiveResourceManagerTest::TearDown()
{
    SensitiveResourceManager::GetInstance().UnRegisterCameraFloatWindowChangeCallback(OnChangeCameraFloatWindow);
    SensitiveResourceManager::GetInstance().UnRegisterMicGlobalSwitchChangeCallback(OnChangeMicGlobalSwitch);
    SensitiveResourceManager::GetInstance().UnRegisterCameraGlobalSwitchChangeCallback(OnChangeCameraGlobalSwitch);
    SensitiveResourceManager::GetInstance().UnRegisterAppStatusChangeCallback(tokenId_, AppStatusChangeCallback);

    AccessTokenID tokenId = AccessTokenKit::GetHapTokenID(g_InfoParms1.userID, g_InfoParms1.bundleName,
        g_InfoParms1.instIndex);
    AccessTokenKit::DeleteToken(tokenId);

    SetSelfTokenID(selfTokenId_);
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
 * @tc.name: FlowWindowStatusTest001
 * @tc.desc: Verify the SetFlowWindowStatus IsFlowWindowShow.
 * @tc.type: FUNC
 * @tc.require: issueI5RWX5
 */
HWTEST_F(SensitiveResourceManagerTest, FlowWindowStatusTest001, TestSize.Level1)
{
    SensitiveResourceManager::GetInstance().SetFlowWindowStatus(tokenId_, true);

    ASSERT_TRUE(SensitiveResourceManager::GetInstance().IsFlowWindowShow(tokenId_));

    SensitiveResourceManager::GetInstance().SetFlowWindowStatus(tokenId_, false);

    ASSERT_FALSE(SensitiveResourceManager::GetInstance().IsFlowWindowShow(tokenId_));
}

/**
 * @tc.name: IsFlowWindowShowTest001
 * @tc.desc: Verify the IsFlowWindowShow abnormal branch tokenId is invalid.
 * @tc.type: FUNC
 * @tc.require: issueI5RWX5
 */
HWTEST_F(SensitiveResourceManagerTest, IsFlowWindowShowTest001, TestSize.Level1)
{
    uint32_t tokenId1 = 123;

    SensitiveResourceManager::GetInstance().SetFlowWindowStatus(tokenId_, true);

    ASSERT_TRUE(SensitiveResourceManager::GetInstance().IsFlowWindowShow(tokenId_));

    ASSERT_FALSE(SensitiveResourceManager::GetInstance().IsFlowWindowShow(tokenId1));
}

/**
 * @tc.name: SetFlowWindowStatusTest001
 * @tc.desc: Verify the SetFlowWindowStatus abnormal branch tokenId is invalid.
 * @tc.type: FUNC
 * @tc.require: issueI5RWX5
 */
HWTEST_F(SensitiveResourceManagerTest, SetFlowWindowStatusTest001, TestSize.Level1)
{
    uint32_t tokenId1 = 123;

    SensitiveResourceManager::GetInstance().SetFlowWindowStatus(tokenId1, true);

    ASSERT_FALSE(SensitiveResourceManager::GetInstance().IsFlowWindowShow(tokenId_));
}

/**
 * @tc.name: RegisterMicGlobalSwitchChangeCallbackTest001
 * @tc.desc: call RegisterMicGlobalSwitchChangeCallback once.
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
 * @tc.name: RegisterCameraGlobalSwitchChangeCallbackTest001
 * @tc.desc: call RegisterMicGlobalSwitchChangeCallback once.
 * @tc.type: FUNC
 * @tc.require: issueI5RWXA
 */
HWTEST_F(SensitiveResourceManagerTest, RegisterCameraGlobalSwitchChangeCallbackTest001, TestSize.Level1)
{
    AccessTokenID tokenId = AccessTokenKit::GetHapTokenID(g_InfoParms1.userID, g_InfoParms1.bundleName,
        g_InfoParms1.instIndex);

    SetSelfTokenID(tokenId);

    ASSERT_EQ(RET_SUCCESS,
        SensitiveResourceManager::GetInstance().RegisterCameraGlobalSwitchChangeCallback(OnChangeCameraGlobalSwitch));

    bool isMute = CameraManager::GetInstance()->IsCameraMuted();

    CameraManager::GetInstance()->MuteCamera(false);
    ResetEnv();
    usleep(500000); // 500000us = 0.5s

    CameraManager::GetInstance()->MuteCamera(true);
    usleep(500000); // 500000us = 0.5s
    ASSERT_FALSE(g_cameraStauts);

    ResetEnv();

    CameraManager::GetInstance()->MuteCamera(false);
    usleep(500000); // 500000us = 0.5s
    ASSERT_TRUE(g_cameraStauts);
    
    ResetEnv();
    CameraManager::GetInstance()->MuteCamera(isMute);
    SensitiveResourceManager::GetInstance().UnRegisterCameraGlobalSwitchChangeCallback(OnChangeCameraGlobalSwitch);
}

/**
 * @tc.name: GetGlobalSwitchTest001
 * @tc.desc: Verify the GetGlobalSwitch with valid ResourceType.
 * @tc.type: FUNC
 * @tc.require: issueI5RWXA issueI5RWXF
 */
HWTEST_F(SensitiveResourceManagerTest, GetGlobalSwitchTest001, TestSize.Level1)
{
    bool micStatus = !(AudioSystemManager::GetInstance()->IsMicrophoneMute());
    bool cameraStatus = !(CameraManager::GetInstance()->IsCameraMuted());
    usleep(500000); // 500000us = 0.5s
    EXPECT_EQ(micStatus, SensitiveResourceManager::GetInstance().GetGlobalSwitch(ResourceType::MICROPHONE));
    EXPECT_EQ(cameraStatus, SensitiveResourceManager::GetInstance().GetGlobalSwitch(ResourceType::CAMERA));
}

/**
 * @tc.name: RegisterCameraGlobalSwitchChangeCallbackTest002
 * @tc.desc: Verify the RegisterCameraGlobalSwitchChangeCallback abnormal branch callback is invalid.
 * @tc.type: FUNC
 * @tc.require: issueI5RWXA
 */
HWTEST_F(SensitiveResourceManagerTest, RegisterCameraGlobalSwitchChangeCallbackTest002, TestSize.Level1)
{
    EXPECT_EQ(ERR_CALLBACK_NOT_EXIST,
        SensitiveResourceManager::GetInstance().RegisterCameraGlobalSwitchChangeCallback(nullptr));

    ASSERT_EQ(RET_SUCCESS,
        SensitiveResourceManager::GetInstance().RegisterCameraGlobalSwitchChangeCallback(OnChangeCameraGlobalSwitch));
    ASSERT_EQ(ERR_CALLBACK_ALREADY_EXIST,
        SensitiveResourceManager::GetInstance().RegisterCameraGlobalSwitchChangeCallback(OnChangeCameraGlobalSwitch));

    SensitiveResourceManager::GetInstance().UnRegisterCameraGlobalSwitchChangeCallback(OnChangeCameraGlobalSwitch);
}

/**
 * @tc.name: UnRegisterCameraGlobalSwitchChangeCallbackTest001
 * @tc.desc: Verify the UnRegisterCameraGlobalSwitchChangeCallback with vaild callback.
 * @tc.type: FUNC
 * @tc.require: issueI5RWXA
 */
HWTEST_F(SensitiveResourceManagerTest, UnRegisterCameraGlobalSwitchChangeCallbackTest001, TestSize.Level1)
{
    ASSERT_EQ(RET_SUCCESS,
        SensitiveResourceManager::GetInstance().RegisterCameraGlobalSwitchChangeCallback(OnChangeCameraGlobalSwitch));
    ASSERT_EQ(RET_SUCCESS,
        SensitiveResourceManager::GetInstance().UnRegisterCameraGlobalSwitchChangeCallback(OnChangeCameraGlobalSwitch));
}

/**
 * @tc.name: UnRegisterCameraGlobalSwitchChangeCallbackTest002
 * @tc.desc: Verify the UnRegisterCameraGlobalSwitchChangeCallback abnormal branch callback is invalid.
 * @tc.type: FUNC
 * @tc.require: issueI5RWXA
 */
HWTEST_F(SensitiveResourceManagerTest, UnRegisterCameraGlobalSwitchChangeCallbackTest002, TestSize.Level1)
{
    EXPECT_EQ(ERR_CALLBACK_NOT_EXIST,
        SensitiveResourceManager::GetInstance().UnRegisterCameraGlobalSwitchChangeCallback(nullptr));
    EXPECT_EQ(ERR_CALLBACK_NOT_EXIST,
        SensitiveResourceManager::GetInstance().UnRegisterCameraGlobalSwitchChangeCallback(OnChangeCameraGlobalSwitch));
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

/**
 * @tc.name: RegisterCameraFloatWindowChangeCallbackTest001
 * @tc.desc: Verify the RegisterCameraFloatWindowChangeCallback.
 * @tc.type: FUNC
 * @tc.require: issueI5RWX5
 */
HWTEST_F(SensitiveResourceManagerTest, RegisterCameraFloatWindowChangeCallbackTest001, TestSize.Level1)
{
    ASSERT_EQ(RET_SUCCESS,
        SensitiveResourceManager::GetInstance().RegisterCameraFloatWindowChangeCallback(OnChangeCameraFloatWindow));
}

/**
 * @tc.name: RegisterCameraFloatWindowChangeCallbackTest002
 * @tc.desc: Verify the RegisterCameraFloatWindowChangeCallback abnormal branch callback is nullptr.
 * @tc.type: FUNC
 * @tc.require: issueI5RWX5
 */
HWTEST_F(SensitiveResourceManagerTest, RegisterCameraFloatWindowChangeCallbackTest002, TestSize.Level1)
{
    ASSERT_EQ(ERR_CALLBACK_NOT_EXIST,
        SensitiveResourceManager::GetInstance().RegisterCameraFloatWindowChangeCallback(nullptr));

    ASSERT_EQ(RET_SUCCESS,
        SensitiveResourceManager::GetInstance().RegisterCameraFloatWindowChangeCallback(OnChangeCameraFloatWindow));
    ASSERT_EQ(ERR_CALLBACK_ALREADY_EXIST,
        SensitiveResourceManager::GetInstance().RegisterCameraFloatWindowChangeCallback(OnChangeCameraFloatWindow));
}

/**
 * @tc.name: UnRegisterCameraFloatWindowChangeCallbackTest_001
 * @tc.desc: Verify the UnRegisterCameraFloatWindowChangeCallback with vaild callback.
 * @tc.type: FUNC
 * @tc.require: issueI5RWX5
 */
HWTEST_F(SensitiveResourceManagerTest, UnRegisterCameraFloatWindowChangeCallbackTest_001, TestSize.Level1)
{
    ASSERT_EQ(RET_SUCCESS,
        SensitiveResourceManager::GetInstance().RegisterCameraFloatWindowChangeCallback(OnChangeCameraFloatWindow));
    ASSERT_EQ(RET_SUCCESS,
        SensitiveResourceManager::GetInstance().UnRegisterCameraFloatWindowChangeCallback(OnChangeCameraFloatWindow));
}

/**
 * @tc.name: UnRegisterCameraFloatWindowChangeCallbackTest_002
 * @tc.desc: Verify the UnRegisterCameraFloatWindowChangeCallback abnormal branch callback is nullptr.
 * @tc.type: FUNC
 * @tc.require: issueI5RWX5
 */
HWTEST_F(SensitiveResourceManagerTest, UnRegisterCameraFloatWindowChangeCallbackTest_002, TestSize.Level1)
{
    ASSERT_EQ(ERR_CALLBACK_NOT_EXIST,
        SensitiveResourceManager::GetInstance().UnRegisterCameraFloatWindowChangeCallback(nullptr));
    ASSERT_EQ(ERR_CALLBACK_NOT_EXIST,
        SensitiveResourceManager::GetInstance().UnRegisterCameraFloatWindowChangeCallback(OnChangeCameraFloatWindow));
}
} // namespace AccessToken
} // namespace Security
} // namespace OHOS
