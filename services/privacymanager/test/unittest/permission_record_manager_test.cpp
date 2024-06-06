/*
 * Copyright (c) 2022-2024 Huawei Device Co., Ltd.
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

#include <cstdint>
#include <gtest/gtest.h>

#include "ability_manager_access_loader.h"
#include "access_token.h"
#include "accesstoken_kit.h"
#include "accesstoken_log.h"
#include "audio_manager_privacy_client.h"
#include "camera_manager_privacy_client.h"
#include "constant.h"
#include "data_translator.h"
#include "permission_record.h"
#define private public
#include "active_status_callback_manager.h"
#include "libraryloader.h"
#include "permission_record_manager.h"
#include "permission_record_repository.h"
#include "permission_used_record_cache.h"
#include "permission_used_record_db.h"
#undef private
#include "perm_active_status_change_callback_stub.h"
#include "privacy_error.h"
#include "privacy_field_const.h"
#include "privacy_kit.h"
#include "state_change_callback.h"
#include "time_util.h"
#include "token_setproc.h"

using namespace testing;
using namespace testing::ext;
using namespace OHOS;

namespace OHOS {
namespace Security {
namespace AccessToken {
namespace {
static AccessTokenID g_selfTokenId = 0;
static AccessTokenID g_nativeToken = 0;
constexpr const char* CAMERA_PERMISSION_NAME = "ohos.permission.CAMERA";
constexpr const char* MICROPHONE_PERMISSION_NAME = "ohos.permission.MICROPHONE";
constexpr const char* LOCATION_PERMISSION_NAME = "ohos.permission.LOCATION";
static constexpr uint32_t MAX_CALLBACK_SIZE = 1024;
static constexpr int32_t RANDOM_TOKENID = 123;
static constexpr int32_t FIRST_INDEX = 0;
static const int32_t NORMAL_TYPE_ADD_VALUE = 1;
static const int32_t PICKER_TYPE_ADD_VALUE = 2;
static const int32_t SEC_COMPONENT_TYPE_ADD_VALUE = 4;
static const int32_t EDM_POLICY_TYPE = 0;
static const int32_t PRIVACY_POLICY_TYPE = 1;
static const int32_t TEMPORARY_POLICY_TYPE = 2;
static const int32_t MICROPHONE_CALLER_TYPE = 0;
static PermissionStateFull g_testState1 = {
    .permissionName = "ohos.permission.CAMERA",
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
    .permissionName = "ohos.permission.MANAGE_AUDIO_CONFIG",
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

static HapPolicyParams g_PolicyPrams2 = {
    .apl = APL_NORMAL,
    .domain = "test.domain.B",
    .permList = {},
    .permStateList = {g_testState1}
};

static HapInfoParams g_InfoParms2 = {
    .userID = 1,
    .bundleName = "ohos.privacy_test.bundleB",
    .instIndex = 0,
    .appIDDesc = "privacy_test.bundleB"
};
}
class PermissionRecordManagerTest : public testing::Test {
public:
    static void SetUpTestCase();

    static void TearDownTestCase();

    void SetUp();

    void TearDown();
};

void PermissionRecordManagerTest::SetUpTestCase()
{
    PermissionRecordManager::GetInstance().Init();

    g_selfTokenId = GetSelfTokenID();
    g_nativeToken = AccessTokenKit::GetNativeTokenId("privacy_service");
}

void PermissionRecordManagerTest::TearDownTestCase() {}
void PermissionRecordManagerTest::SetUp()
{
    PermissionRecordManager::GetInstance().Init();
    PermissionRecordManager::GetInstance().Register();

    AccessTokenKit::AllocHapToken(g_InfoParms1, g_PolicyPrams1);
    AccessTokenKit::AllocHapToken(g_InfoParms2, g_PolicyPrams2);
}

void PermissionRecordManagerTest::TearDown()
{
    AccessTokenID tokenId = AccessTokenKit::GetHapTokenID(g_InfoParms1.userID, g_InfoParms1.bundleName,
        g_InfoParms1.instIndex);
    AccessTokenKit::DeleteToken(tokenId);
    PrivacyKit::RemovePermissionUsedRecords(tokenId, "");
    tokenId = AccessTokenKit::GetHapTokenID(g_InfoParms2.userID, g_InfoParms2.bundleName,
        g_InfoParms2.instIndex);
    AccessTokenKit::DeleteToken(tokenId);
    PrivacyKit::RemovePermissionUsedRecords(tokenId, "");
    EXPECT_EQ(0, SetSelfTokenID(g_selfTokenId));
}

class CbCustomizeTest1 : public StateCustomizedCbk {
public:
    CbCustomizeTest1()
    {}

    ~CbCustomizeTest1()
    {}

    virtual void StateChangeNotify(AccessTokenID tokenId, bool isShow)
    {}

    void Stop()
    {}
};

/**
 * @tc.name: RegisterPermActiveStatusCallback001
 * @tc.desc: RegisterPermActiveStatusCallback with invalid parameter.
 * @tc.type: FUNC
 * @tc.require: issueI5RWX8
 */
HWTEST_F(PermissionRecordManagerTest, RegisterPermActiveStatusCallback001, TestSize.Level1)
{
    std::vector<std::string> permList = {"ohos.permission.CAMERA"};
    ASSERT_EQ(PrivacyError::ERR_PARAM_INVALID,
            PermissionRecordManager::GetInstance().RegisterPermActiveStatusCallback(permList, nullptr));
}


class PermActiveStatusChangeCallback : public PermActiveStatusChangeCallbackStub {
public:
    PermActiveStatusChangeCallback() = default;
    virtual ~PermActiveStatusChangeCallback() = default;

    void ActiveStatusChangeCallback(ActiveChangeResponse& result)
    {
        type_ = result.type;
        GTEST_LOG_(INFO) << "PermActiveStatusChangeCallback ActiveChangeResponse";
        GTEST_LOG_(INFO) << "PermActiveStatusChangeCallback tokenid " << result.tokenID;
        GTEST_LOG_(INFO) << "PermActiveStatusChangeCallback permissionName " << result.permissionName;
        GTEST_LOG_(INFO) << "PermActiveStatusChangeCallback deviceId " << result.deviceId;
        GTEST_LOG_(INFO) << "PermActiveStatusChangeCallback type " << result.type;
    }

    ActiveChangeType type_ = PERM_INACTIVE;
};

/**
 * @tc.name: RegisterPermActiveStatusCallback002
 * @tc.desc: RegisterPermActiveStatusCallback with exceed limitation.
 * @tc.type: FUNC
 * @tc.require: issueI5RWX8
 */
HWTEST_F(PermissionRecordManagerTest, RegisterPermActiveStatusCallback002, TestSize.Level1)
{
    std::vector<std::string> permList = {"ohos.permission.CAMERA"};
    std::vector<sptr<PermActiveStatusChangeCallback>> callbacks;

    for (size_t i = 0; i < MAX_CALLBACK_SIZE; ++i) {
        sptr<PermActiveStatusChangeCallback> callback = new (std::nothrow) PermActiveStatusChangeCallback();
        ASSERT_NE(nullptr, callback);
        ASSERT_EQ(RET_SUCCESS,
            PermissionRecordManager::GetInstance().RegisterPermActiveStatusCallback(permList, callback->AsObject()));
        callbacks.emplace_back(callback);
    }

    sptr<PermActiveStatusChangeCallback> callback = new (std::nothrow) PermActiveStatusChangeCallback();
    ASSERT_NE(nullptr, callback);
    ASSERT_EQ(PrivacyError::ERR_CALLBACKS_EXCEED_LIMITATION,
        PermissionRecordManager::GetInstance().RegisterPermActiveStatusCallback(permList, callback->AsObject()));

    for (size_t i = 0; i < callbacks.size(); ++i) {
        ASSERT_EQ(RET_SUCCESS,
            PermissionRecordManager::GetInstance().UnRegisterPermActiveStatusCallback(callbacks[i]->AsObject()));
    }
}

/**
 * @tc.name: UnRegisterPermActiveStatusCallback001
 * @tc.desc: UnRegisterPermActiveStatusCallback with invalid parameter.
 * @tc.type: FUNC
 * @tc.require: issueI5RWX8
 */
HWTEST_F(PermissionRecordManagerTest, UnRegisterPermActiveStatusCallback001, TestSize.Level1)
{
    std::vector<std::string> permList = {"ohos.permission.CAMERA"};
    ASSERT_EQ(PrivacyError::ERR_PARAM_INVALID,
            PermissionRecordManager::GetInstance().RegisterPermActiveStatusCallback(permList, nullptr));
}

/*
 * @tc.name: StartUsingPermissionTest001
 * @tc.desc: StartUsingPermission function test with invaild tokenId.
 * @tc.type: FUNC
 * @tc.require: issueI5RWX5 issueI5RWX3 issueI5RWXA
 */
HWTEST_F(PermissionRecordManagerTest, StartUsingPermissionTest001, TestSize.Level1)
{
    std::string permissionName = "ohos.permission.CAMERA";
    auto callbackPtr = std::make_shared<CbCustomizeTest1>();
    auto callbackWrap = new (std::nothrow) StateChangeCallback(callbackPtr);
    ASSERT_NE(nullptr, callbackPtr);
    ASSERT_NE(nullptr, callbackWrap);
    AccessTokenID tokenId = AccessTokenKit::GetHapTokenID(g_InfoParms1.userID, g_InfoParms1.bundleName,
        g_InfoParms1.instIndex);
    ASSERT_NE(INVALID_TOKENID, tokenId);
    ASSERT_EQ(ERR_PARAM_INVALID,
        PermissionRecordManager::GetInstance().StartUsingPermission(0, permissionName, callbackWrap->AsObject()));
}

/*
 * @tc.name: StartUsingPermissionTest002
 * @tc.desc: StartUsingPermission function test with invaild permissionName.
 * @tc.type: FUNC
 * @tc.require: issueI5RWXF
 */
HWTEST_F(PermissionRecordManagerTest, StartUsingPermissionTest002, TestSize.Level1)
{
    EXPECT_EQ(0, SetSelfTokenID(g_nativeToken));

    auto callbackPtr = std::make_shared<CbCustomizeTest1>();
    auto callbackWrap = new (std::nothrow) StateChangeCallback(callbackPtr);
    ASSERT_NE(nullptr, callbackPtr);
    ASSERT_NE(nullptr, callbackWrap);
    AccessTokenID tokenId = AccessTokenKit::GetHapTokenID(g_InfoParms1.userID, g_InfoParms1.bundleName,
        g_InfoParms1.instIndex);
    ASSERT_NE(INVALID_TOKENID, tokenId);
    ASSERT_EQ(ERR_PARAM_INVALID, PermissionRecordManager::GetInstance().StartUsingPermission(
        tokenId, "ohos.permission.LOCATION", callbackWrap->AsObject()));

    // tokenId invaild
    ASSERT_EQ(PrivacyError::ERR_PARAM_INVALID, PermissionRecordManager::GetInstance().StartUsingPermission(
        g_nativeToken, "ohos.permission.CAMERA", nullptr));
    
    ASSERT_EQ(Constant::SUCCESS, PermissionRecordManager::GetInstance().StartUsingPermission(
        tokenId, "ohos.permission.CAMERA", nullptr));
    ASSERT_EQ(PrivacyError::ERR_PERMISSION_ALREADY_START_USING,
        PermissionRecordManager::GetInstance().StartUsingPermission(tokenId, "ohos.permission.CAMERA", nullptr));

    ASSERT_EQ(Constant::SUCCESS,
        PermissionRecordManager::GetInstance().StopUsingPermission(tokenId, "ohos.permission.CAMERA"));
}
/*
 * @tc.name: StartUsingPermissionTest003
 * @tc.desc:
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(PermissionRecordManagerTest, StartUsingPermissionTest003, TestSize.Level1)
{
    bool isMicEdmMute = PermissionRecordManager::GetInstance().isMicEdmMute_;
    bool isMicMixMute = PermissionRecordManager::GetInstance().isMicMixMute_;

    EXPECT_EQ(RET_SUCCESS, PrivacyKit::SetMutePolicy(EDM_POLICY_TYPE, MICROPHONE_CALLER_TYPE, true));
    EXPECT_EQ(RET_SUCCESS, PrivacyKit::SetMutePolicy(PRIVACY_POLICY_TYPE, MICROPHONE_CALLER_TYPE, true));

    AccessTokenID tokenId = AccessTokenKit::GetHapTokenID(g_InfoParms1.userID, g_InfoParms1.bundleName,
        g_InfoParms1.instIndex);
    ASSERT_NE(static_cast<AccessTokenID>(0), tokenId);
    std::string permissionName = "ohos.permission.MICROPHONE";
    ASSERT_EQ(PrivacyError::ERR_EDM_POLICY_CHECK_FAILED, PrivacyKit::StartUsingPermission(tokenId, permissionName));

    PermissionRecordManager::GetInstance().isMicEdmMute_ = isMicEdmMute;
    PermissionRecordManager::GetInstance().isMicMixMute_ = isMicMixMute;
}

class CbCustomizeTest2 : public PermActiveStatusCustomizedCbk {
public:
    explicit CbCustomizeTest2(const std::vector<std::string> &permList)
        : PermActiveStatusCustomizedCbk(permList)
    {
        GTEST_LOG_(INFO) << "CbCustomizeTest2 create";
    }

    ~CbCustomizeTest2()
    {}

    virtual void ActiveStatusChangeCallback(ActiveChangeResponse& result)
    {
        type_ = result.type;
        GTEST_LOG_(INFO) << "CbCustomizeTest2 ActiveChangeResponse";
        GTEST_LOG_(INFO) << "CbCustomizeTest2 tokenid " << result.tokenID;
        GTEST_LOG_(INFO) << "CbCustomizeTest2 permissionName " << result.permissionName;
        GTEST_LOG_(INFO) << "CbCustomizeTest2 deviceId " << result.deviceId;
        GTEST_LOG_(INFO) << "CbCustomizeTest2 type " << result.type;
    }

    ActiveChangeType type_ = PERM_INACTIVE;
};

/*
 * @tc.name: StartUsingPermissionTest004
 * @tc.desc:
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(PermissionRecordManagerTest, StartUsingPermissionTest004, TestSize.Level1)
{
    bool isMicEdmMute = PermissionRecordManager::GetInstance().isMicEdmMute_;
    bool isMicMixMute = PermissionRecordManager::GetInstance().isMicMixMute_;

    EXPECT_EQ(RET_SUCCESS, PrivacyKit::SetMutePolicy(EDM_POLICY_TYPE, MICROPHONE_CALLER_TYPE, false));
    EXPECT_EQ(RET_SUCCESS, PrivacyKit::SetMutePolicy(PRIVACY_POLICY_TYPE, MICROPHONE_CALLER_TYPE, true));

    std::vector<std::string> permList = {"ohos.permission.MICROPHONE"};
    auto callback = std::make_shared<CbCustomizeTest2>(permList);
    ASSERT_EQ(RET_SUCCESS, PrivacyKit::RegisterPermActiveStatusCallback(callback));

    AccessTokenID tokenId = AccessTokenKit::GetHapTokenID(g_InfoParms1.userID, g_InfoParms1.bundleName,
        g_InfoParms1.instIndex);
    ASSERT_NE(static_cast<AccessTokenID>(0), tokenId);
    std::string permissionName = "ohos.permission.MICROPHONE";
    ASSERT_EQ(RET_SUCCESS, PrivacyKit::StartUsingPermission(tokenId, permissionName));

    usleep(500000); // 500000us = 0.5s
    ASSERT_EQ(PERM_INACTIVE, callback->type_);
    ASSERT_EQ(Constant::SUCCESS, PrivacyKit::StopUsingPermission(tokenId, permissionName));
    PermissionRecordManager::GetInstance().isMicEdmMute_ = isMicEdmMute;
    PermissionRecordManager::GetInstance().isMicMixMute_ = isMicMixMute;
}

/*
 * @tc.name: StartUsingPermissionTest005
 * @tc.desc:
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(PermissionRecordManagerTest, StartUsingPermissionTest005, TestSize.Level1)
{
    bool isMicEdmMute = PermissionRecordManager::GetInstance().isMicEdmMute_;
    bool isMicMixMute = PermissionRecordManager::GetInstance().isMicMixMute_;

    EXPECT_EQ(RET_SUCCESS, PrivacyKit::SetMutePolicy(EDM_POLICY_TYPE, MICROPHONE_CALLER_TYPE, false));
    EXPECT_EQ(RET_SUCCESS, PrivacyKit::SetMutePolicy(PRIVACY_POLICY_TYPE, MICROPHONE_CALLER_TYPE, false));

    std::vector<std::string> permList = {"ohos.permission.MICROPHONE"};
    auto callback = std::make_shared<CbCustomizeTest2>(permList);
    ASSERT_EQ(RET_SUCCESS, PrivacyKit::RegisterPermActiveStatusCallback(callback));

    AccessTokenID tokenId = AccessTokenKit::GetHapTokenID(g_InfoParms1.userID, g_InfoParms1.bundleName,
        g_InfoParms1.instIndex);
    ASSERT_NE(static_cast<AccessTokenID>(0), tokenId);
    std::string permissionName = "ohos.permission.MICROPHONE";
    ASSERT_EQ(RET_SUCCESS, PrivacyKit::StartUsingPermission(tokenId, permissionName));

    usleep(500000); // 500000us = 0.5s
    ASSERT_EQ(PERM_ACTIVE_IN_BACKGROUND, callback->type_);
    ASSERT_EQ(Constant::SUCCESS, PrivacyKit::StopUsingPermission(tokenId, permissionName));
    PermissionRecordManager::GetInstance().isMicEdmMute_ = isMicEdmMute;
    PermissionRecordManager::GetInstance().isMicMixMute_ = isMicMixMute;
}

/*
 * @tc.name: StartUsingPermissionTest006
 * @tc.desc:
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(PermissionRecordManagerTest, StartUsingPermissionTest006, TestSize.Level1)
{
    bool isMicEdmMute = PermissionRecordManager::GetInstance().isMicEdmMute_;
    bool isMicMixMute = PermissionRecordManager::GetInstance().isMicMixMute_;

    EXPECT_EQ(RET_SUCCESS, PrivacyKit::SetMutePolicy(EDM_POLICY_TYPE, MICROPHONE_CALLER_TYPE, true));
    EXPECT_EQ(RET_SUCCESS, PrivacyKit::SetMutePolicy(PRIVACY_POLICY_TYPE, MICROPHONE_CALLER_TYPE, true));

    std::vector<std::string> permList = {"ohos.permission.LOCATION"};
    auto callback = std::make_shared<CbCustomizeTest2>(permList);
    ASSERT_EQ(RET_SUCCESS, PrivacyKit::RegisterPermActiveStatusCallback(callback));

    AccessTokenID tokenId = AccessTokenKit::GetHapTokenID(g_InfoParms1.userID, g_InfoParms1.bundleName,
        g_InfoParms1.instIndex);
    ASSERT_NE(static_cast<AccessTokenID>(0), tokenId);
    std::string permissionName = "ohos.permission.LOCATION";
    ASSERT_EQ(RET_SUCCESS, PrivacyKit::StartUsingPermission(tokenId, permissionName));

    usleep(500000); // 500000us = 0.5s
    ASSERT_EQ(PERM_ACTIVE_IN_BACKGROUND, callback->type_);
    ASSERT_EQ(Constant::SUCCESS, PrivacyKit::StopUsingPermission(tokenId, permissionName));
    PermissionRecordManager::GetInstance().isMicEdmMute_ = isMicEdmMute;
    PermissionRecordManager::GetInstance().isMicMixMute_ = isMicMixMute;
}

/*
 * @tc.name: ShowGlobalDialog001
 * @tc.desc: ShowGlobalDialog function test
 * @tc.type: FUNC
 * @tc.require: issueI5RWXF
 */
HWTEST_F(PermissionRecordManagerTest, ShowGlobalDialog001, TestSize.Level1)
{
    EXPECT_EQ(0, SetSelfTokenID(g_nativeToken));

    ASSERT_EQ(true, PermissionRecordManager::GetInstance().ShowGlobalDialog(CAMERA_PERMISSION_NAME));
    sleep(3); // wait for dialog disappear
    ASSERT_EQ(true, PermissionRecordManager::GetInstance().ShowGlobalDialog(MICROPHONE_PERMISSION_NAME));
    sleep(3); // wait for dialog disappear
    ASSERT_EQ(true, PermissionRecordManager::GetInstance().ShowGlobalDialog(LOCATION_PERMISSION_NAME)); // no dialog
}

/*
 * @tc.name: MicSwitchChangeListener001
 * @tc.desc: NotifyMicChange function test mic global switch is open
 * @tc.type: FUNC
 * @tc.require: issueI5RWXF
 */
HWTEST_F(PermissionRecordManagerTest, MicSwitchChangeListener001, TestSize.Level1)
{
    EXPECT_EQ(0, SetSelfTokenID(g_nativeToken));

    bool isMuteMic = AudioManagerPrivacyClient::GetInstance().IsMicrophoneMute();
    AudioManagerPrivacyClient::GetInstance().SetMicrophoneMute(false); // false means open
    AccessTokenID tokenId = AccessTokenKit::GetHapTokenID(g_InfoParms1.userID, g_InfoParms1.bundleName,
        g_InfoParms1.instIndex);
    ASSERT_EQ(0, PermissionRecordManager::GetInstance().StartUsingPermission(tokenId, CAMERA_PERMISSION_NAME));

    PermissionRecordManager::GetInstance().NotifyMicChange(true); // fill opCode not mic branch
    ASSERT_EQ(0, PermissionRecordManager::GetInstance().StopUsingPermission(tokenId, CAMERA_PERMISSION_NAME));
    AudioManagerPrivacyClient::GetInstance().SetMicrophoneMute(isMuteMic);
}

/*
 * @tc.name: MicSwitchChangeListener002
 * @tc.desc: NotifyMicChange function test mic global switch is open
 * @tc.type: FUNC
 * @tc.require: issueI5RWXF
 */
HWTEST_F(PermissionRecordManagerTest, MicSwitchChangeListener002, TestSize.Level1)
{
    EXPECT_EQ(0, SetSelfTokenID(g_nativeToken));

    bool isMuteMic = AudioManagerPrivacyClient::GetInstance().IsMicrophoneMute();
    AudioManagerPrivacyClient::GetInstance().SetMicrophoneMute(false); // false means open
    AccessTokenID tokenId = AccessTokenKit::GetHapTokenID(g_InfoParms1.userID, g_InfoParms1.bundleName,
        g_InfoParms1.instIndex);
    // status is background
    ASSERT_EQ(0, PermissionRecordManager::GetInstance().StartUsingPermission(tokenId, MICROPHONE_PERMISSION_NAME));
    PermissionRecordManager::GetInstance().NotifyMicChange(true); // fill true status is not inactive branch
    ASSERT_EQ(0, PermissionRecordManager::GetInstance().StopUsingPermission(tokenId, MICROPHONE_PERMISSION_NAME));
    AudioManagerPrivacyClient::GetInstance().SetMicrophoneMute(isMuteMic);
}

/*
 * @tc.name: MicSwitchChangeListener003
 * @tc.desc: NotifyMicChange function test mic global switch is close
 * @tc.type: FUNC
 * @tc.require: issueI5RWXF
 */
HWTEST_F(PermissionRecordManagerTest, MicSwitchChangeListener003, TestSize.Level1)
{
    EXPECT_EQ(0, SetSelfTokenID(g_nativeToken));

    bool isMuteMic = AudioManagerPrivacyClient::GetInstance().IsMicrophoneMute();
    AudioManagerPrivacyClient::GetInstance().SetMicrophoneMute(true); // true means close
    AccessTokenID tokenId = AccessTokenKit::GetHapTokenID(g_InfoParms1.userID, g_InfoParms1.bundleName,
        g_InfoParms1.instIndex);
    // status is inactive
    ASSERT_EQ(0, PermissionRecordManager::GetInstance().StartUsingPermission(tokenId, MICROPHONE_PERMISSION_NAME));
    sleep(3); // wait for dialog disappear
    PermissionRecordManager::GetInstance().NotifyMicChange(true); // fill true status is inactive branch
    ASSERT_EQ(0, PermissionRecordManager::GetInstance().StopUsingPermission(tokenId, MICROPHONE_PERMISSION_NAME));
    AudioManagerPrivacyClient::GetInstance().SetMicrophoneMute(isMuteMic);
}

/*
 * @tc.name: MicSwitchChangeListener004
 * @tc.desc: NotifyMicChange function test mic global switch is close
 * @tc.type: FUNC
 * @tc.require: issueI5RWXF
 */
HWTEST_F(PermissionRecordManagerTest, MicSwitchChangeListener004, TestSize.Level1)
{
    EXPECT_EQ(0, SetSelfTokenID(g_nativeToken));

    bool isMuteMic = AudioManagerPrivacyClient::GetInstance().IsMicrophoneMute();
    AudioManagerPrivacyClient::GetInstance().SetMicrophoneMute(true); // true means close
    AccessTokenID tokenId = AccessTokenKit::GetHapTokenID(g_InfoParms1.userID, g_InfoParms1.bundleName,
        g_InfoParms1.instIndex);
    // status is inactive
    ASSERT_EQ(0, PermissionRecordManager::GetInstance().StartUsingPermission(tokenId, MICROPHONE_PERMISSION_NAME));
    sleep(3); // wait for dialog disappear
    PermissionRecordManager::GetInstance().NotifyMicChange(false); // fill false status is inactive branch
    ASSERT_EQ(0, PermissionRecordManager::GetInstance().StopUsingPermission(tokenId, MICROPHONE_PERMISSION_NAME));
    AudioManagerPrivacyClient::GetInstance().SetMicrophoneMute(isMuteMic);
}

/*
 * @tc.name: AppStateChangeListener001
 * @tc.desc: AppStateChange function test mic global switch is close
 * @tc.type: FUNC
 * @tc.require: issueI5RWXF
 */
HWTEST_F(PermissionRecordManagerTest, AppStateChangeListener001, TestSize.Level1)
{
    EXPECT_EQ(0, SetSelfTokenID(g_nativeToken));

    bool isMuteMic = AudioManagerPrivacyClient::GetInstance().IsMicrophoneMute();
    AudioManagerPrivacyClient::GetInstance().SetMicrophoneMute(true); // true means close
    AccessTokenID tokenId = AccessTokenKit::GetHapTokenID(g_InfoParms1.userID, g_InfoParms1.bundleName,
        g_InfoParms1.instIndex);
    // status is inactive
    ASSERT_EQ(0, PermissionRecordManager::GetInstance().StartUsingPermission(tokenId, MICROPHONE_PERMISSION_NAME));
    sleep(3); // wait for dialog disappear
    PermissionRecordManager::GetInstance().NotifyAppStateChange(tokenId, PERM_ACTIVE_IN_BACKGROUND);
    ASSERT_EQ(0, PermissionRecordManager::GetInstance().StopUsingPermission(tokenId, MICROPHONE_PERMISSION_NAME));
    AudioManagerPrivacyClient::GetInstance().SetMicrophoneMute(isMuteMic);
}

/*
 * @tc.name: TransferOpcodeToPermission001
 * @tc.desc: Constant::TransferOpcodeToPermission function test return false
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(PermissionRecordManagerTest, TransferOpcodeToPermission001, TestSize.Level1)
{
    int32_t opCode = static_cast<int32_t>(Constant::OpCode::OP_INVALID);
    std::string permissionName;
    ASSERT_EQ(false, Constant::TransferOpcodeToPermission(opCode, permissionName));
}

/*
 * @tc.name: AddPermissionUsedRecord001
 * @tc.desc: PermissionRecordManager::AddPermissionUsedRecord function test
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(PermissionRecordManagerTest, AddPermissionUsedRecord001, TestSize.Level1)
{
    AccessTokenID tokenId = AccessTokenKit::GetHapTokenID(g_InfoParms1.userID, g_InfoParms1.bundleName,
        g_InfoParms1.instIndex);
    ASSERT_NE(static_cast<AccessTokenID>(0), tokenId);

    AddPermParamInfo info;
    info.tokenId = tokenId;
    info.permissionName = "com.ohos.test";
    info.successCount = 1;
    info.failCount = 0;

    ASSERT_EQ(PrivacyError::ERR_PERMISSION_NOT_EXIST, PermissionRecordManager::GetInstance().AddPermissionUsedRecord(
        info)); // invaild permission error

    info.type = PermissionUsedType::PICKER_TYPE;
    ASSERT_EQ(PrivacyError::ERR_PERMISSION_NOT_EXIST, PermissionRecordManager::GetInstance().AddPermissionUsedRecord(
        info)); // invaild permission error

    info.type = PermissionUsedType::SECURITY_COMPONENT_TYPE;
    ASSERT_EQ(PrivacyError::ERR_PERMISSION_NOT_EXIST, PermissionRecordManager::GetInstance().AddPermissionUsedRecord(
        info)); // invaild permission error
}

/*
 * @tc.name: AddPermissionUsedRecord002
 * @tc.desc: PermissionRecordManager::AddPermissionUsedRecord function test
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(PermissionRecordManagerTest, AddPermissionUsedRecord002, TestSize.Level1)
{
    AccessTokenID tokenId = AccessTokenKit::GetHapTokenID(g_InfoParms1.userID, g_InfoParms1.bundleName,
        g_InfoParms1.instIndex);
    ASSERT_NE(static_cast<AccessTokenID>(0), tokenId);

    AddPermParamInfo info;
    info.tokenId = tokenId;
    info.permissionName = "com.permission.READ_MEDIA";
    info.successCount = 0;
    info.failCount = 0;
    ASSERT_EQ(PrivacyError::ERR_PARAM_INVALID, PermissionRecordManager::GetInstance().AddPermissionUsedRecord(info));
}

/*
 * @tc.name: RemovePermissionUsedRecords001
 * @tc.desc: PermissionRecordManager::RemovePermissionUsedRecords function test
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(PermissionRecordManagerTest, RemovePermissionUsedRecords001, TestSize.Level1)
{
    AccessTokenID tokenId = AccessTokenKit::GetHapTokenID(g_InfoParms1.userID, g_InfoParms1.bundleName,
        g_InfoParms1.instIndex);
    ASSERT_NE(static_cast<AccessTokenID>(0), tokenId);

    std::string deviceID;
    PermissionRecordManager::GetInstance().RemovePermissionUsedRecords(tokenId, deviceID); // deviceID is empty

    deviceID = "what's is";
    // deviceID is not empty, but device which deps on tokenID is empty not equals deviceID
    PermissionRecordManager::GetInstance().RemovePermissionUsedRecords(static_cast<AccessTokenID>(123), deviceID);

    deviceID = "0";
    // deviceID is not empty, device which deps on tokenID is not empty and equals deviceID
    PermissionRecordManager::GetInstance().RemovePermissionUsedRecords(tokenId, deviceID);
}

/*
 * @tc.name: StartUsingPermission001
 * @tc.desc: PermissionRecordManager::StartUsingPermission function test
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(PermissionRecordManagerTest, StartUsingPermission001, TestSize.Level1)
{
    AccessTokenID tokenId = AccessTokenKit::GetHapTokenID(g_InfoParms1.userID, g_InfoParms1.bundleName,
        g_InfoParms1.instIndex);
    ASSERT_NE(static_cast<AccessTokenID>(0), tokenId);

    // tokenId invaild
    ASSERT_EQ(PrivacyError::ERR_PARAM_INVALID, PermissionRecordManager::GetInstance().StartUsingPermission(
        g_nativeToken, "ohos.permission.READ_MEDIA"));

    ASSERT_EQ(Constant::SUCCESS, PermissionRecordManager::GetInstance().StartUsingPermission(
        tokenId, "ohos.permission.READ_MEDIA"));
    ASSERT_EQ(PrivacyError::ERR_PERMISSION_ALREADY_START_USING,
        PermissionRecordManager::GetInstance().StartUsingPermission(tokenId, "ohos.permission.READ_MEDIA"));

    ASSERT_EQ(Constant::SUCCESS,
        PermissionRecordManager::GetInstance().StopUsingPermission(tokenId, "ohos.permission.READ_MEDIA"));
}

/*
 * @tc.name: StopUsingPermission001
 * @tc.desc: PermissionRecordManager::StopUsingPermission function test
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(PermissionRecordManagerTest, StopUsingPermission001, TestSize.Level1)
{
    AccessTokenID tokenId = AccessTokenKit::GetHapTokenID(g_InfoParms1.userID, g_InfoParms1.bundleName,
        g_InfoParms1.instIndex);
    ASSERT_NE(static_cast<AccessTokenID>(0), tokenId);

    // tokenId invaild
    ASSERT_EQ(PrivacyError::ERR_PARAM_INVALID, PermissionRecordManager::GetInstance().StopUsingPermission(
        static_cast<AccessTokenID>(0), "ohos.permission.READ_MEDIA"));

    // permission invaild
    ASSERT_EQ(PrivacyError::ERR_PERMISSION_NOT_EXIST, PermissionRecordManager::GetInstance().StopUsingPermission(
        tokenId, "ohos.permission.test"));

    // not start using
    ASSERT_EQ(PrivacyError::ERR_PERMISSION_NOT_START_USING,
        PermissionRecordManager::GetInstance().StopUsingPermission(tokenId, "ohos.permission.READ_MEDIA"));
}

/*
 * @tc.name: RegisterPermActiveStatusCallback003
 * @tc.desc: PermissionRecordManager::RegisterPermActiveStatusCallback function test
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(PermissionRecordManagerTest, RegisterPermActiveStatusCallback003, TestSize.Level1)
{
    std::vector<std::string> permList;

    permList.emplace_back("com.ohos.TEST");
    // GetDefPermission != Constant::SUCCESS && listRes is empty && listSrc is not empty
    ASSERT_EQ(PrivacyError::ERR_PARAM_INVALID,
        PermissionRecordManager::GetInstance().RegisterPermActiveStatusCallback(permList, nullptr));
}

/*
 * @tc.name: GetPermissionUsedType001
 * @tc.desc: PermissionRecordManager::GetPermissionUsedType function test
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(PermissionRecordManagerTest, GetPermissionUsedType001, TestSize.Level1)
{
    int32_t tokenId = RANDOM_TOKENID;
    std::string permissionName = "ohos.permission.PERMISSION_RECORD_MANAGER_TEST";
    std::vector<PermissionUsedTypeInfo> results;
    // tokenId is not exsit
    ASSERT_EQ(PrivacyError::ERR_TOKENID_NOT_EXIST,
        PermissionRecordManager::GetInstance().GetPermissionUsedTypeInfos(tokenId, permissionName, results));

    tokenId = 0;
    // permissionName is not exsit
    ASSERT_EQ(PrivacyError::ERR_PERMISSION_NOT_EXIST,
        PermissionRecordManager::GetInstance().GetPermissionUsedTypeInfos(tokenId, permissionName, results));

    permissionName = "ohos.permission.CAMERA";
    ASSERT_EQ(0, PermissionRecordManager::GetInstance().GetPermissionUsedTypeInfos(tokenId, permissionName, results));
}

/**
 * @tc.name: Dlopen001
 * @tc.desc: Open a not exist lib & not exist func
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(PermissionRecordManagerTest, Dlopen001, TestSize.Level1)
{
    LibraryLoader loader1("libnotexist.z.so"); // is a not exist path
    EXPECT_EQ(nullptr, loader1.handle_);

    LibraryLoader loader2("libaccesstoken_manager_service.z.so"); // is a exist lib without create func
    EXPECT_EQ(nullptr, loader2.instance_);
    EXPECT_NE(nullptr, loader2.handle_);
}

/*
 * @tc.name: AddDataValueToResults001
 * @tc.desc: PermissionRecordManager::AddDataValueToResults function test
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(PermissionRecordManagerTest, AddDataValueToResults001, TestSize.Level1)
{
    GenericValues value;
    value.Put(PrivacyFiledConst::FIELD_TOKEN_ID, RANDOM_TOKENID);
    value.Put(PrivacyFiledConst::FIELD_USED_TYPE, NORMAL_TYPE_ADD_VALUE);
    std::vector<PermissionUsedTypeInfo> results;

    PermissionRecordManager::GetInstance().AddDataValueToResults(value, results);
    ASSERT_EQ(PermissionUsedType::NORMAL_TYPE, results[FIRST_INDEX].type);
}

/*
 * @tc.name: AddDataValueToResults002
 * @tc.desc: PermissionRecordManager::AddDataValueToResults function test
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(PermissionRecordManagerTest, AddDataValueToResults002, TestSize.Level1)
{
    GenericValues value;
    value.Put(PrivacyFiledConst::FIELD_TOKEN_ID, RANDOM_TOKENID);
    value.Put(PrivacyFiledConst::FIELD_USED_TYPE, PICKER_TYPE_ADD_VALUE);
    std::vector<PermissionUsedTypeInfo> results;

    PermissionRecordManager::GetInstance().AddDataValueToResults(value, results);
    ASSERT_EQ(PermissionUsedType::PICKER_TYPE, results[FIRST_INDEX].type);
}

/*
 * @tc.name: AddDataValueToResults003
 * @tc.desc: PermissionRecordManager::AddDataValueToResults function test
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(PermissionRecordManagerTest, AddDataValueToResults003, TestSize.Level1)
{
    GenericValues value;
    value.Put(PrivacyFiledConst::FIELD_TOKEN_ID, RANDOM_TOKENID);
    value.Put(PrivacyFiledConst::FIELD_USED_TYPE, SEC_COMPONENT_TYPE_ADD_VALUE);
    std::vector<PermissionUsedTypeInfo> results;

    PermissionRecordManager::GetInstance().AddDataValueToResults(value, results);
    ASSERT_EQ(PermissionUsedType::SECURITY_COMPONENT_TYPE, results[FIRST_INDEX].type);
    ASSERT_EQ(0, GetFirstCallerTokenID());
}

/*
 * @tc.name: SetMutePolicyTest001
 * @tc.desc:
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(PermissionRecordManagerTest, SetMutePolicyTest001, TestSize.Level1)
{
    bool isMicEdmMute = PermissionRecordManager::GetInstance().isMicEdmMute_;
    bool isMicMixMute = PermissionRecordManager::GetInstance().isMicMixMute_;

    EXPECT_EQ(RET_SUCCESS, PrivacyKit::SetMutePolicy(EDM_POLICY_TYPE, MICROPHONE_CALLER_TYPE, true));
    EXPECT_EQ(RET_SUCCESS, PrivacyKit::SetMutePolicy(PRIVACY_POLICY_TYPE, MICROPHONE_CALLER_TYPE, true));
    EXPECT_EQ(RET_SUCCESS, PrivacyKit::SetMutePolicy(EDM_POLICY_TYPE, MICROPHONE_CALLER_TYPE, true));

    EXPECT_EQ(RET_SUCCESS, PrivacyKit::SetMutePolicy(EDM_POLICY_TYPE, MICROPHONE_CALLER_TYPE, true));
    EXPECT_EQ(RET_SUCCESS, PrivacyKit::SetMutePolicy(PRIVACY_POLICY_TYPE, MICROPHONE_CALLER_TYPE, true));
    EXPECT_EQ(RET_SUCCESS, PrivacyKit::SetMutePolicy(EDM_POLICY_TYPE, MICROPHONE_CALLER_TYPE, false));

    PermissionRecordManager::GetInstance().isMicEdmMute_ = isMicEdmMute;
    PermissionRecordManager::GetInstance().isMicMixMute_ = isMicMixMute;
}

/*
 * @tc.name: SetMutePolicyTest002
 * @tc.desc:
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(PermissionRecordManagerTest, SetMutePolicyTest002, TestSize.Level1)
{
    bool isMicEdmMute = PermissionRecordManager::GetInstance().isMicEdmMute_;
    bool isMicMixMute = PermissionRecordManager::GetInstance().isMicMixMute_;

    EXPECT_EQ(RET_SUCCESS, PrivacyKit::SetMutePolicy(EDM_POLICY_TYPE, MICROPHONE_CALLER_TYPE, false));
    EXPECT_EQ(RET_SUCCESS, PrivacyKit::SetMutePolicy(PRIVACY_POLICY_TYPE, MICROPHONE_CALLER_TYPE, true));
    EXPECT_EQ(RET_SUCCESS, PrivacyKit::SetMutePolicy(EDM_POLICY_TYPE, MICROPHONE_CALLER_TYPE, true));

    EXPECT_EQ(RET_SUCCESS, PrivacyKit::SetMutePolicy(EDM_POLICY_TYPE, MICROPHONE_CALLER_TYPE, false));
    EXPECT_EQ(RET_SUCCESS, PrivacyKit::SetMutePolicy(PRIVACY_POLICY_TYPE, MICROPHONE_CALLER_TYPE, true));
    EXPECT_EQ(RET_SUCCESS, PrivacyKit::SetMutePolicy(EDM_POLICY_TYPE, MICROPHONE_CALLER_TYPE, false));

    PermissionRecordManager::GetInstance().isMicEdmMute_ = isMicEdmMute;
    PermissionRecordManager::GetInstance().isMicMixMute_ = isMicMixMute;
}

/*
 * @tc.name: SetMutePolicyTest003
 * @tc.desc:
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(PermissionRecordManagerTest, SetMutePolicyTest003, TestSize.Level1)
{
    bool isMicEdmMute = PermissionRecordManager::GetInstance().isMicEdmMute_;
    bool isMicMixMute = PermissionRecordManager::GetInstance().isMicMixMute_;

    EXPECT_EQ(RET_SUCCESS, PrivacyKit::SetMutePolicy(EDM_POLICY_TYPE, MICROPHONE_CALLER_TYPE, false));
    EXPECT_EQ(RET_SUCCESS, PrivacyKit::SetMutePolicy(PRIVACY_POLICY_TYPE, MICROPHONE_CALLER_TYPE, false));
    EXPECT_EQ(RET_SUCCESS, PrivacyKit::SetMutePolicy(EDM_POLICY_TYPE, MICROPHONE_CALLER_TYPE, true));

    EXPECT_EQ(RET_SUCCESS, PrivacyKit::SetMutePolicy(EDM_POLICY_TYPE, MICROPHONE_CALLER_TYPE, false));
    EXPECT_EQ(RET_SUCCESS, PrivacyKit::SetMutePolicy(PRIVACY_POLICY_TYPE, MICROPHONE_CALLER_TYPE, false));
    EXPECT_EQ(RET_SUCCESS, PrivacyKit::SetMutePolicy(EDM_POLICY_TYPE, MICROPHONE_CALLER_TYPE, false));

    PermissionRecordManager::GetInstance().isMicEdmMute_ = isMicEdmMute;
    PermissionRecordManager::GetInstance().isMicMixMute_ = isMicMixMute;
}

/*
 * @tc.name: SetMutePolicyTest004
 * @tc.desc:
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(PermissionRecordManagerTest, SetMutePolicyTest004, TestSize.Level1)
{
    bool isMicEdmMute = PermissionRecordManager::GetInstance().isMicEdmMute_;
    bool isMicMixMute = PermissionRecordManager::GetInstance().isMicMixMute_;

    EXPECT_EQ(RET_SUCCESS, PrivacyKit::SetMutePolicy(EDM_POLICY_TYPE, MICROPHONE_CALLER_TYPE, true));
    EXPECT_EQ(RET_SUCCESS, PrivacyKit::SetMutePolicy(PRIVACY_POLICY_TYPE, MICROPHONE_CALLER_TYPE, true));
    EXPECT_EQ(RET_SUCCESS, PrivacyKit::SetMutePolicy(PRIVACY_POLICY_TYPE, MICROPHONE_CALLER_TYPE, true));

    EXPECT_EQ(RET_SUCCESS, PrivacyKit::SetMutePolicy(EDM_POLICY_TYPE, MICROPHONE_CALLER_TYPE, true));
    EXPECT_EQ(RET_SUCCESS, PrivacyKit::SetMutePolicy(PRIVACY_POLICY_TYPE, MICROPHONE_CALLER_TYPE, true));
    EXPECT_EQ(ERR_EDM_POLICY_CHECK_FAILED,
        PrivacyKit::SetMutePolicy(PRIVACY_POLICY_TYPE, MICROPHONE_CALLER_TYPE, false));

    PermissionRecordManager::GetInstance().isMicEdmMute_ = isMicEdmMute;
    PermissionRecordManager::GetInstance().isMicMixMute_ = isMicMixMute;
}

/*
 * @tc.name: SetMutePolicyTest005
 * @tc.desc:
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(PermissionRecordManagerTest, SetMutePolicyTest005, TestSize.Level1)
{
    bool isMicEdmMute = PermissionRecordManager::GetInstance().isMicEdmMute_;
    bool isMicMixMute = PermissionRecordManager::GetInstance().isMicMixMute_;

    EXPECT_EQ(RET_SUCCESS, PrivacyKit::SetMutePolicy(EDM_POLICY_TYPE, MICROPHONE_CALLER_TYPE, false));
    EXPECT_EQ(RET_SUCCESS, PrivacyKit::SetMutePolicy(PRIVACY_POLICY_TYPE, MICROPHONE_CALLER_TYPE, true));
    EXPECT_EQ(RET_SUCCESS, PrivacyKit::SetMutePolicy(PRIVACY_POLICY_TYPE, MICROPHONE_CALLER_TYPE, true));

    EXPECT_EQ(RET_SUCCESS, PrivacyKit::SetMutePolicy(EDM_POLICY_TYPE, MICROPHONE_CALLER_TYPE, false));
    EXPECT_EQ(RET_SUCCESS, PrivacyKit::SetMutePolicy(PRIVACY_POLICY_TYPE, MICROPHONE_CALLER_TYPE, true));
    EXPECT_EQ(RET_SUCCESS, PrivacyKit::SetMutePolicy(PRIVACY_POLICY_TYPE, MICROPHONE_CALLER_TYPE, false));

    PermissionRecordManager::GetInstance().isMicEdmMute_ = isMicEdmMute;
    PermissionRecordManager::GetInstance().isMicMixMute_ = isMicMixMute;
}

/*
 * @tc.name: SetMutePolicyTest006
 * @tc.desc:
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(PermissionRecordManagerTest, SetMutePolicyTest006, TestSize.Level1)
{
    bool isMicEdmMute = PermissionRecordManager::GetInstance().isMicEdmMute_;
    bool isMicMixMute = PermissionRecordManager::GetInstance().isMicMixMute_;

    EXPECT_EQ(RET_SUCCESS, PrivacyKit::SetMutePolicy(EDM_POLICY_TYPE, MICROPHONE_CALLER_TYPE, false));
    EXPECT_EQ(RET_SUCCESS, PrivacyKit::SetMutePolicy(PRIVACY_POLICY_TYPE, MICROPHONE_CALLER_TYPE, false));
    EXPECT_EQ(RET_SUCCESS, PrivacyKit::SetMutePolicy(PRIVACY_POLICY_TYPE, MICROPHONE_CALLER_TYPE, true));

    EXPECT_EQ(RET_SUCCESS, PrivacyKit::SetMutePolicy(EDM_POLICY_TYPE, MICROPHONE_CALLER_TYPE, false));
    EXPECT_EQ(RET_SUCCESS, PrivacyKit::SetMutePolicy(PRIVACY_POLICY_TYPE, MICROPHONE_CALLER_TYPE, false));
    EXPECT_EQ(RET_SUCCESS, PrivacyKit::SetMutePolicy(PRIVACY_POLICY_TYPE, MICROPHONE_CALLER_TYPE, false));

    PermissionRecordManager::GetInstance().isMicEdmMute_ = isMicEdmMute;
    PermissionRecordManager::GetInstance().isMicMixMute_ = isMicMixMute;
}

/*
 * @tc.name: SetMutePolicyTest007
 * @tc.desc:
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(PermissionRecordManagerTest, SetMutePolicyTest007, TestSize.Level1)
{
    bool isMicEdmMute = PermissionRecordManager::GetInstance().isMicEdmMute_;
    bool isMicMixMute = PermissionRecordManager::GetInstance().isMicMixMute_;

    EXPECT_EQ(RET_SUCCESS, PrivacyKit::SetMutePolicy(EDM_POLICY_TYPE, MICROPHONE_CALLER_TYPE, true));
    EXPECT_EQ(RET_SUCCESS, PrivacyKit::SetMutePolicy(PRIVACY_POLICY_TYPE, MICROPHONE_CALLER_TYPE, true));
    EXPECT_EQ(RET_SUCCESS, PrivacyKit::SetMutePolicy(TEMPORARY_POLICY_TYPE, MICROPHONE_CALLER_TYPE, true));

    EXPECT_EQ(RET_SUCCESS, PrivacyKit::SetMutePolicy(EDM_POLICY_TYPE, MICROPHONE_CALLER_TYPE, true));
    EXPECT_EQ(RET_SUCCESS, PrivacyKit::SetMutePolicy(PRIVACY_POLICY_TYPE, MICROPHONE_CALLER_TYPE, true));
    EXPECT_EQ(ERR_EDM_POLICY_CHECK_FAILED,
        PrivacyKit::SetMutePolicy(TEMPORARY_POLICY_TYPE, MICROPHONE_CALLER_TYPE, false));

    PermissionRecordManager::GetInstance().isMicEdmMute_ = isMicEdmMute;
    PermissionRecordManager::GetInstance().isMicMixMute_ = isMicMixMute;
}

/*
 * @tc.name: SetMutePolicyTest008
 * @tc.desc:
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(PermissionRecordManagerTest, SetMutePolicyTest008, TestSize.Level1)
{
    bool isMicEdmMute = PermissionRecordManager::GetInstance().isMicEdmMute_;
    bool isMicMixMute = PermissionRecordManager::GetInstance().isMicMixMute_;

    EXPECT_EQ(RET_SUCCESS, PrivacyKit::SetMutePolicy(EDM_POLICY_TYPE, MICROPHONE_CALLER_TYPE, false));
    EXPECT_EQ(RET_SUCCESS, PrivacyKit::SetMutePolicy(PRIVACY_POLICY_TYPE, MICROPHONE_CALLER_TYPE, true));
    EXPECT_EQ(RET_SUCCESS, PrivacyKit::SetMutePolicy(TEMPORARY_POLICY_TYPE, MICROPHONE_CALLER_TYPE, true));

    EXPECT_EQ(RET_SUCCESS, PrivacyKit::SetMutePolicy(EDM_POLICY_TYPE, MICROPHONE_CALLER_TYPE, false));
    EXPECT_EQ(RET_SUCCESS, PrivacyKit::SetMutePolicy(PRIVACY_POLICY_TYPE, MICROPHONE_CALLER_TYPE, true));
    EXPECT_EQ(ERR_PRIVACY_POLICY_CHECK_FAILED,
        PrivacyKit::SetMutePolicy(TEMPORARY_POLICY_TYPE, MICROPHONE_CALLER_TYPE, false));

    PermissionRecordManager::GetInstance().isMicEdmMute_ = isMicEdmMute;
    PermissionRecordManager::GetInstance().isMicMixMute_ = isMicMixMute;
}

/*
 * @tc.name: SetMutePolicyTest009
 * @tc.desc:
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(PermissionRecordManagerTest, SetMutePolicyTest009, TestSize.Level1)
{
    bool isMicEdmMute = PermissionRecordManager::GetInstance().isMicEdmMute_;
    bool isMicMixMute = PermissionRecordManager::GetInstance().isMicMixMute_;

    EXPECT_EQ(RET_SUCCESS, PrivacyKit::SetMutePolicy(EDM_POLICY_TYPE, MICROPHONE_CALLER_TYPE, false));
    EXPECT_EQ(RET_SUCCESS, PrivacyKit::SetMutePolicy(PRIVACY_POLICY_TYPE, MICROPHONE_CALLER_TYPE, false));
    EXPECT_EQ(RET_SUCCESS, PrivacyKit::SetMutePolicy(TEMPORARY_POLICY_TYPE, MICROPHONE_CALLER_TYPE, true));

    EXPECT_EQ(RET_SUCCESS, PrivacyKit::SetMutePolicy(EDM_POLICY_TYPE, MICROPHONE_CALLER_TYPE, false));
    EXPECT_EQ(RET_SUCCESS, PrivacyKit::SetMutePolicy(PRIVACY_POLICY_TYPE, MICROPHONE_CALLER_TYPE, false));
    EXPECT_EQ(RET_SUCCESS, PrivacyKit::SetMutePolicy(TEMPORARY_POLICY_TYPE, MICROPHONE_CALLER_TYPE, false));

    PermissionRecordManager::GetInstance().isMicEdmMute_ = isMicEdmMute;
    PermissionRecordManager::GetInstance().isMicMixMute_ = isMicMixMute;
}
} // namespace AccessToken
} // namespace Security
} // namespace OHOS
