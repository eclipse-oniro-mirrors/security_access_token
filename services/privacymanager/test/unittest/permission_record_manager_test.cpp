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
static constexpr int32_t MAX_DETAIL_NUM = 500;
static constexpr int32_t DEEP_COPY_NUM = 10;
static constexpr int64_t ONE_SECOND = 1000;
static constexpr int64_t TWO_SECOND = 2000;
static constexpr int64_t THREE_SECOND = 3000;
static constexpr int32_t PERMISSION_USED_TYPE_VALUE = 1;
static constexpr int32_t PICKER_TYPE_VALUE = 2;
static constexpr int32_t PERMISSION_USED_TYPE_WITH_PICKER_TYPE_VALUE = 3;
static constexpr int32_t RANDOM_TOKENID = 123;
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

static HapPolicyParams g_PolicyPrams1 = {
    .apl = APL_NORMAL,
    .domain = "test.domain.A",
    .permList = {},
    .permStateList = {g_testState1, g_testState2}
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

static PermissionRecord g_recordA1 = {
    .opCode = Constant::OP_CAMERA,
    .status = ActiveChangeType::PERM_ACTIVE_IN_BACKGROUND,
    .timestamp = 0L,
    .accessDuration = 0L,
    .accessCount = 1,
    .rejectCount = 0,
    .lockScreenStatus = LockScreenStatusChangeType::PERM_ACTIVE_IN_UNLOCKED
};

static PermissionRecord g_recordA2 = {
    .opCode = Constant::OP_MICROPHONE,
    .status = ActiveChangeType::PERM_ACTIVE_IN_BACKGROUND,
    .timestamp = 0L,
    .accessDuration = 0L,
    .accessCount = 1,
    .rejectCount = 0,
    .lockScreenStatus = LockScreenStatusChangeType::PERM_ACTIVE_IN_UNLOCKED
};

static PermissionRecord g_recordB1 = {
    .opCode = Constant::OP_CAMERA,
    .status = ActiveChangeType::PERM_ACTIVE_IN_BACKGROUND,
    .timestamp = 0L,
    .accessDuration = 0L,
    .accessCount = 1,
    .rejectCount = 0,
    .lockScreenStatus = LockScreenStatusChangeType::PERM_ACTIVE_IN_UNLOCKED
};

static PermissionRecord g_recordB2 = {
    .opCode = Constant::OP_MICROPHONE,
    .status = ActiveChangeType::PERM_ACTIVE_IN_BACKGROUND,
    .timestamp = 0L,
    .accessDuration = 0L,
    .accessCount = 1,
    .rejectCount = 0,
    .lockScreenStatus = LockScreenStatusChangeType::PERM_ACTIVE_IN_UNLOCKED
};

static PermissionRecord g_record = {
    .tokenId = 123,
    .opCode = static_cast<int32_t>(Constant::OpCode::OP_READ_CALENDAR),
    .status = static_cast<int32_t>(ActiveChangeType::PERM_ACTIVE_IN_FOREGROUND),
    .lockScreenStatus = static_cast<int32_t>(LockScreenStatusChangeType::PERM_ACTIVE_IN_UNLOCKED),
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
    g_selfTokenId = GetSelfTokenID();
    g_nativeToken = AccessTokenKit::GetNativeTokenId("privacy_service");
}

void PermissionRecordManagerTest::TearDownTestCase() {}

void PermissionRecordManagerTest::SetUp()
{
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

class CbCustomizeTest2 : public IRemoteObject {
public:
    CbCustomizeTest2()
    {}

    ~CbCustomizeTest2()
    {}
};


/**
 * @tc.name: OnForegroundApplicationChanged001
 * @tc.desc: RegisterPermActiveStatusCallback with invalid parameter.
 * @tc.type: FUNC
 * @tc.require: issueI5RWX8
 */
HWTEST_F(PermissionRecordManagerTest, OnForegroundApplicationChanged001, TestSize.Level1)
{
    PrivacyAppStateObserver observer;
    AppStateData appStateData;
    appStateData.state = static_cast<int32_t>(ApplicationState::APP_STATE_FOREGROUND);
    observer.OnForegroundApplicationChanged(appStateData);
    appStateData.state = static_cast<int32_t>(ApplicationState::APP_STATE_BACKGROUND);
    observer.OnForegroundApplicationChanged(appStateData);
    ASSERT_EQ(static_cast<int32_t>(ApplicationState::APP_STATE_BACKGROUND), appStateData.state);
}

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

    void ActiveStatusChangeCallback(ActiveChangeResponse& result) {}
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
 * @tc.name: AppStatusListener001
 * @tc.desc: register and startusing permissions then use NotifyAppStateChange
 * @tc.type: FUNC
 * @tc.require: issueI5SZHG
 */
HWTEST_F(PermissionRecordManagerTest, AppStatusListener001, TestSize.Level1)
{
    AccessTokenID tokenId1 = AccessTokenKit::GetHapTokenID(g_InfoParms1.userID, g_InfoParms1.bundleName,
        g_InfoParms1.instIndex);
    ASSERT_NE(static_cast<AccessTokenID>(0), tokenId1);
    AccessTokenID tokenId2 = AccessTokenKit::GetHapTokenID(g_InfoParms2.userID, g_InfoParms2.bundleName,
        g_InfoParms2.instIndex);
    ASSERT_NE(static_cast<AccessTokenID>(0), tokenId2);

    g_recordA1.tokenId = tokenId1;
    g_recordA2.tokenId = tokenId1;
    g_recordB1.tokenId = tokenId2;
    g_recordB2.tokenId = tokenId2;
    PermissionRecordManager::GetInstance().startRecordList_.emplace_back(g_recordA1);
    PermissionRecordManager::GetInstance().startRecordList_.emplace_back(g_recordA2);
    PermissionRecordManager::GetInstance().startRecordList_.emplace_back(g_recordB1);
    PermissionRecordManager::GetInstance().startRecordList_.emplace_back(g_recordB2);

    PermissionRecordManager::GetInstance().NotifyAppStateChange(tokenId1, PERM_ACTIVE_IN_FOREGROUND);
    PermissionRecordManager::GetInstance().NotifyAppStateChange(tokenId2, PERM_ACTIVE_IN_FOREGROUND);
    PermissionRecordManager::GetInstance().NotifyAppStateChange(tokenId1, PERM_ACTIVE_IN_FOREGROUND);
    PermissionRecordManager::GetInstance().NotifyAppStateChange(tokenId2, PERM_ACTIVE_IN_FOREGROUND);
    PermissionRecordManager::GetInstance().NotifyAppStateChange(tokenId1, PERM_ACTIVE_IN_BACKGROUND);
    PermissionRecordManager::GetInstance().NotifyAppStateChange(tokenId2, PERM_ACTIVE_IN_BACKGROUND);
    PermissionRecordManager::GetInstance().NotifyAppStateChange(tokenId1, PERM_ACTIVE_IN_BACKGROUND);
    PermissionRecordManager::GetInstance().NotifyAppStateChange(tokenId2, PERM_ACTIVE_IN_BACKGROUND);
}

/*
 * @tc.name: FindRecordsToUpdateAndExecutedTest001
 * @tc.desc: FindRecordsToUpdateAndExecuted function test with invaild tokenId or permissionName or callback.
 * @tc.type: FUNC
 * @tc.require: issueI5RWX5 issueI5RWX3 issueI5RWXA
 */
HWTEST_F(PermissionRecordManagerTest, FindRecordsToUpdateAndExecutedTest001, TestSize.Level1)
{
    AccessTokenID tokenId = AccessTokenKit::GetHapTokenID(g_InfoParms1.userID, g_InfoParms1.bundleName,
        g_InfoParms1.instIndex);
    ASSERT_NE(INVALID_TOKENID, tokenId);

    EXPECT_EQ(0, SetSelfTokenID(tokenId));

    ActiveChangeType status = PERM_ACTIVE_IN_BACKGROUND;

    PermissionRecord record1 = {
        .tokenId = tokenId,
        .opCode = Constant::OP_CAMERA,
    };
    CameraManagerPrivacyClient::GetInstance().MuteCamera(false);
    PermissionRecordManager::GetInstance().AddRecordToStartList(record1);
#ifdef CAMERA_FLOAT_WINDOW_ENABLE
    PermissionRecordManager::GetInstance().NotifyCameraFloatWindowChange(tokenId, false);
#endif
    PermissionRecordManager::GetInstance().ExecuteAndUpdateRecord(tokenId, status);
    PermissionRecordManager::GetInstance().NotifyAppStateChange(tokenId, status);

    PermissionRecord record;
    PermissionRecordManager::GetInstance().GetRecordFromStartList(record1.tokenId, record1.opCode, record);

    ASSERT_EQ(record1.tokenId, tokenId);
}

/*
 * @tc.name: FindRecordsToUpdateAndExecutedTest002
 * @tc.desc: FindRecordsToUpdateAndExecuted function test with invaild tokenId or permissionName or callback.
 * @tc.type: FUNC
 * @tc.require: issueI5RWX5 issueI5RWX3 issueI5RWXA
 */
HWTEST_F(PermissionRecordManagerTest, FindRecordsToUpdateAndExecutedTest002, TestSize.Level1)
{
    AccessTokenID tokenId = AccessTokenKit::GetHapTokenID(g_InfoParms1.userID, g_InfoParms1.bundleName,
        g_InfoParms1.instIndex);
    ASSERT_NE(INVALID_TOKENID, tokenId);
    ActiveChangeType status = PERM_ACTIVE_IN_BACKGROUND;

    PermissionRecord record1 = {
        .tokenId = tokenId,
        .opCode = Constant::OP_MICROPHONE,
    };
    PermissionRecordManager::GetInstance().AddRecordToStartList(record1);
#ifdef CAMERA_FLOAT_WINDOW_ENABLE
    PermissionRecordManager::GetInstance().NotifyCameraFloatWindowChange(tokenId, false);
#endif
    PermissionRecordManager::GetInstance().ExecuteAndUpdateRecord(tokenId, status);
    PermissionRecordManager::GetInstance().NotifyAppStateChange(tokenId, status);

    PermissionRecord record;
    PermissionRecordManager::GetInstance().GetRecordFromStartList(record1.tokenId, record1.opCode, record);
    ASSERT_EQ(record1.tokenId, tokenId);
}

/*
 * @tc.name: FindRecordsToUpdateAndExecutedTest003
 * @tc.desc: FindRecordsToUpdateAndExecuted function test with invaild tokenId or permissionName or callback.
 * @tc.type: FUNC
 * @tc.require: issueI5RWX5 issueI5RWX3 issueI5RWXA
 */
HWTEST_F(PermissionRecordManagerTest, FindRecordsToUpdateAndExecutedTest003, TestSize.Level1)
{
    AccessTokenID tokenId = AccessTokenKit::GetHapTokenID(g_InfoParms1.userID, g_InfoParms1.bundleName,
        g_InfoParms1.instIndex);
    ASSERT_NE(INVALID_TOKENID, tokenId);
    ActiveChangeType status = PERM_ACTIVE_IN_FOREGROUND;

    PermissionRecord record1 = {
        .tokenId = tokenId,
        .opCode = Constant::OP_CAMERA,
    };
    PermissionRecordManager::GetInstance().AddRecordToStartList(record1);
#ifdef CAMERA_FLOAT_WINDOW_ENABLE
    PermissionRecordManager::GetInstance().NotifyCameraFloatWindowChange(tokenId, false);
#endif
    PermissionRecordManager::GetInstance().ExecuteAndUpdateRecord(tokenId, status);

    PermissionRecord record;
    PermissionRecordManager::GetInstance().GetRecordFromStartList(record1.tokenId, record1.opCode, record);

    ASSERT_EQ(record1.tokenId, tokenId);
}

/*
 * @tc.name: FindRecordsToUpdateAndExecutedTest004
 * @tc.desc: FindRecordsToUpdateAndExecuted function test with invaild tokenId or permissionName or callback.
 * @tc.type: FUNC
 * @tc.require: issueI5RWX5 issueI5RWX3 issueI5RWXA
 */
HWTEST_F(PermissionRecordManagerTest, FindRecordsToUpdateAndExecutedTest004, TestSize.Level1)
{
    AccessTokenID tokenId = AccessTokenKit::GetHapTokenID(g_InfoParms1.userID, g_InfoParms1.bundleName,
        g_InfoParms1.instIndex);
    ASSERT_NE(INVALID_TOKENID, tokenId);
    ActiveChangeType status = PERM_ACTIVE_IN_BACKGROUND;

    PermissionRecord record1 = {
        .tokenId = tokenId,
        .opCode = Constant::OP_CAMERA,
    };
    PermissionRecordManager::GetInstance().AddRecordToStartList(record1);
#ifdef CAMERA_FLOAT_WINDOW_ENABLE
    PermissionRecordManager::GetInstance().NotifyCameraFloatWindowChange(tokenId, true);
#endif
    PermissionRecordManager::GetInstance().ExecuteAndUpdateRecord(tokenId, status);

    PermissionRecord record;
    PermissionRecordManager::GetInstance().GetRecordFromStartList(record1.tokenId, record1.opCode, record);
    ASSERT_EQ(record1.tokenId, tokenId);
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
    AccessTokenID tokenID = AccessTokenKit::GetNativeTokenId("privacy_service");
    ASSERT_NE(static_cast<AccessTokenID>(0), tokenID);
    EXPECT_EQ(0, SetSelfTokenID(tokenID));

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
 * @tc.name: ExecuteCameraCallbackAsyncTest001
 * @tc.desc: Verify the ExecuteCameraCallbackAsync abnormal branch function test with.
 * @tc.type: FUNC
 * @tc.require: issueI5RWX5 issueI5RWX3 issueI5RWXA
 */
HWTEST_F(PermissionRecordManagerTest, ExecuteCameraCallbackAsyncTest001, TestSize.Level1)
{
    AccessTokenID tokenId = AccessTokenKit::GetHapTokenID(g_InfoParms1.userID, g_InfoParms1.bundleName,
        g_InfoParms1.instIndex);
    ASSERT_NE(INVALID_TOKENID, tokenId);

    auto callbackPtr = std::make_shared<CbCustomizeTest1>();
    auto callbackWrap = new (std::nothrow) StateChangeCallback(callbackPtr);
    ASSERT_NE(nullptr, callbackPtr);
    ASSERT_NE(nullptr, callbackWrap);
    PermissionRecordManager::GetInstance().SetCameraCallback(nullptr);
    PermissionRecordManager::GetInstance().ExecuteCameraCallbackAsync(tokenId);

    PermissionRecordManager::GetInstance().SetCameraCallback(callbackWrap->AsObject());
    PermissionRecordManager::GetInstance().ExecuteCameraCallbackAsync(tokenId);
}

/*
 * @tc.name: GetGlobalSwitchStatus001
 * @tc.desc: GetGlobalSwitchStatus function test
 * @tc.type: FUNC
 * @tc.require: issueI5RWXF
 */
HWTEST_F(PermissionRecordManagerTest, GetGlobalSwitchStatus001, TestSize.Level1)
{
    bool isMuteMic = AudioManagerPrivacyClient::GetInstance().IsMicrophoneMute();
    AudioManagerPrivacyClient::GetInstance().SetMicrophoneMute(false); // false means open
    ASSERT_EQ(false, AudioManagerPrivacyClient::GetInstance().IsMicrophoneMute());
    ASSERT_EQ(true, PermissionRecordManager::GetInstance().GetGlobalSwitchStatus(MICROPHONE_PERMISSION_NAME));
    AudioManagerPrivacyClient::GetInstance().SetMicrophoneMute(isMuteMic);

    bool isMuteCam = CameraManagerPrivacyClient::GetInstance().IsCameraMuted();
    CameraManagerPrivacyClient::GetInstance().MuteCamera(false);
    ASSERT_EQ(false, CameraManagerPrivacyClient::GetInstance().IsCameraMuted());
    ASSERT_EQ(true, PermissionRecordManager::GetInstance().GetGlobalSwitchStatus(CAMERA_PERMISSION_NAME));
    CameraManagerPrivacyClient::GetInstance().MuteCamera(isMuteCam);

    // microphone is not sure
    ASSERT_EQ(true, PermissionRecordManager::GetInstance().GetGlobalSwitchStatus(LOCATION_PERMISSION_NAME));
}

/*
 * @tc.name: ShowGlobalDialog001
 * @tc.desc: ShowGlobalDialog function test
 * @tc.type: FUNC
 * @tc.require: issueI5RWXF
 */
HWTEST_F(PermissionRecordManagerTest, ShowGlobalDialog001, TestSize.Level1)
{
    AccessTokenID tokenID = AccessTokenKit::GetNativeTokenId("privacy_service");
    ASSERT_NE(static_cast<AccessTokenID>(0), tokenID);
    EXPECT_EQ(0, SetSelfTokenID(tokenID));

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
    AccessTokenID tokenID = AccessTokenKit::GetNativeTokenId("privacy_service");
    ASSERT_NE(static_cast<AccessTokenID>(0), tokenID);
    EXPECT_EQ(0, SetSelfTokenID(tokenID));

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
    AccessTokenID tokenID = AccessTokenKit::GetNativeTokenId("privacy_service");
    ASSERT_NE(static_cast<AccessTokenID>(0), tokenID);
    EXPECT_EQ(0, SetSelfTokenID(tokenID));

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
    AccessTokenID tokenID = AccessTokenKit::GetNativeTokenId("privacy_service");
    ASSERT_NE(static_cast<AccessTokenID>(0), tokenID);
    EXPECT_EQ(0, SetSelfTokenID(tokenID));

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
 * @tc.name: MicSwitchChangeListener005
 * @tc.desc: NotifyMicChange function test mic global switch is close
 * @tc.type: FUNC
 * @tc.require: issueI5RWXF
 */
HWTEST_F(PermissionRecordManagerTest, MicSwitchChangeListener005, TestSize.Level1)
{
    AccessTokenID tokenID = AccessTokenKit::GetNativeTokenId("privacy_service");
    ASSERT_NE(static_cast<AccessTokenID>(0), tokenID);
    EXPECT_EQ(0, SetSelfTokenID(tokenID));

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

class PermActiveStatusChangeCallbackTest : public PermActiveStatusChangeCallbackStub {
public:
    PermActiveStatusChangeCallbackTest() = default;
    virtual ~PermActiveStatusChangeCallbackTest() = default;

    void ActiveStatusChangeCallback(ActiveChangeResponse& result) override;
};

void PermActiveStatusChangeCallbackTest::ActiveStatusChangeCallback(ActiveChangeResponse& result)
{
}

/*
 * @tc.name: OnRemoteDied001
 * @tc.desc: PermActiveStatusCallbackDeathRecipient::OnRemoteDied function test
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(PermissionRecordManagerTest, OnRemoteDied001, TestSize.Level1)
{
    auto recipient = std::make_shared<PermActiveStatusCallbackDeathRecipient>();
    ASSERT_NE(nullptr, recipient);

    recipient->OnRemoteDied(nullptr); // remote is nullptr

    // backup
    std::vector<CallbackData> callbackDataList = ActiveStatusCallbackManager::GetInstance().callbackDataList_;
    ActiveStatusCallbackManager::GetInstance().callbackDataList_.clear();

    std::vector<std::string> permList;
    sptr<IRemoteObject> callback;
    permList.emplace_back("ohos.permission.CAMERA");
    wptr<IRemoteObject> remote = new (std::nothrow) PermActiveStatusChangeCallbackTest();
    callback = remote.promote();
    ActiveStatusCallbackManager::GetInstance().AddCallback(permList, callback);
    ASSERT_EQ(static_cast<uint32_t>(1), ActiveStatusCallbackManager::GetInstance().callbackDataList_.size());
    recipient->OnRemoteDied(remote); // remote is not nullptr
    ASSERT_EQ(static_cast<uint32_t>(0), ActiveStatusCallbackManager::GetInstance().callbackDataList_.size());

    // recovery
    ActiveStatusCallbackManager::GetInstance().callbackDataList_ = callbackDataList;
}

/*
 * @tc.name: RemoveCallback001
 * @tc.desc: ActiveStatusCallbackManager::RemoveCallback function test
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(PermissionRecordManagerTest, RemoveCallback001, TestSize.Level1)
{
    std::vector<std::string> permList;
    sptr<IRemoteObject> callback;

    // callback is null
    ASSERT_EQ(PrivacyError::ERR_PARAM_INVALID, ActiveStatusCallbackManager::GetInstance().RemoveCallback(nullptr));

    // backup
    std::vector<CallbackData> callbackDataList = ActiveStatusCallbackManager::GetInstance().callbackDataList_;
    sptr<IRemoteObject::DeathRecipient> callbackDeathRecipient =
        ActiveStatusCallbackManager::GetInstance().callbackDeathRecipient_;
    ActiveStatusCallbackManager::GetInstance().callbackDataList_.clear();
    ActiveStatusCallbackManager::GetInstance().callbackDeathRecipient_ = nullptr;

    sptr<PermActiveStatusChangeCallbackTest> callback1 = new (std::nothrow) PermActiveStatusChangeCallbackTest();
    ASSERT_NE(nullptr, callback1);
    sptr<PermActiveStatusChangeCallbackTest> callback2 = new (std::nothrow) PermActiveStatusChangeCallbackTest();
    ASSERT_NE(nullptr, callback2);
    permList.emplace_back("ohos.permission.CAMERA");
    callback = callback1->AsObject();
    CallbackData data;
    data.permList_ = permList;
    data.callbackObject_ = callback;
    ActiveStatusCallbackManager::GetInstance().callbackDataList_.emplace_back(data);
    // callback != callbackObject_
    ASSERT_EQ(RET_SUCCESS, ActiveStatusCallbackManager::GetInstance().RemoveCallback(callback2->AsObject()));

    // callback == callbackObject_ + callbackDeathRecipient_ is null
    ASSERT_EQ(RET_SUCCESS, ActiveStatusCallbackManager::GetInstance().RemoveCallback(callback));

    // recovery
    ActiveStatusCallbackManager::GetInstance().callbackDataList_ = callbackDataList;
    ActiveStatusCallbackManager::GetInstance().callbackDeathRecipient_ = callbackDeathRecipient;
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
 * @tc.name: UpdateRecords001
 * @tc.desc: PermissionRecordManager::UpdateRecords function test
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(PermissionRecordManagerTest, UpdateRecords001, TestSize.Level1)
{
    AccessTokenID tokenId = AccessTokenKit::GetHapTokenID(g_InfoParms1.userID, g_InfoParms1.bundleName,
        g_InfoParms1.instIndex);
    ASSERT_NE(static_cast<AccessTokenID>(0), tokenId);

    int32_t flag = 0;
    PermissionUsedRecord inBundleRecord;
    PermissionUsedRecord outBundleRecord;

    inBundleRecord.lastAccessTime = 1000;
    outBundleRecord.lastAccessTime = 900;
    // inBundleRecord.lastAccessTime > outBundleRecord.lastAccessTime && flag == 0
    PermissionRecordManager::GetInstance().UpdateRecords(flag, inBundleRecord, outBundleRecord);

    UsedRecordDetail detail;
    detail.accessDuration = 10;
    detail.status = PERM_ACTIVE_IN_FOREGROUND;
    detail.timestamp = 10000;
    flag = 1;
    inBundleRecord.lastRejectTime = 1000;
    inBundleRecord.accessRecords.emplace_back(detail);
    inBundleRecord.rejectRecords.emplace_back(detail);
    // flag != 0 && inBundleRecord.lastRejectTime > 0 && outBundleRecord.accessRecords.size() < 10
    // && inBundleRecord.lastRejectTime > 0 && outBundleRecord.rejectRecords.size() < 10
    PermissionRecordManager::GetInstance().UpdateRecords(flag, inBundleRecord, outBundleRecord);

    std::vector<UsedRecordDetail> accessRecords(11, detail);
    outBundleRecord.accessRecords = accessRecords;
    outBundleRecord.rejectRecords = accessRecords;
    // flag != 0 && inBundleRecord.lastRejectTime > 0 && outBundleRecord.accessRecords.size() >= 10
    // && inBundleRecord.lastRejectTime > 0 && outBundleRecord.rejectRecords.size() >= 10
    PermissionRecordManager::GetInstance().UpdateRecords(flag, inBundleRecord, outBundleRecord);

    inBundleRecord.lastAccessTime = 0;
    inBundleRecord.lastRejectTime = 0;
    // flag != 0 && inBundleRecord.lastRejectTime <= 0 && outBundleRecord.accessRecords.size() >= 10
    // && inBundleRecord.lastRejectTime <= 0 && outBundleRecord.rejectRecords.size() >= 10
    PermissionRecordManager::GetInstance().UpdateRecords(flag, inBundleRecord, outBundleRecord);
}

/*
 * @tc.name: RemoveRecordFromStartList001
 * @tc.desc: PermissionRecordManager::RemoveRecordFromStartList function test
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(PermissionRecordManagerTest, RemoveRecordFromStartList001, TestSize.Level1)
{
    AccessTokenID tokenId = AccessTokenKit::GetHapTokenID(g_InfoParms1.userID, g_InfoParms1.bundleName,
        g_InfoParms1.instIndex);
    ASSERT_NE(static_cast<AccessTokenID>(0), tokenId);

    ASSERT_EQ(Constant::SUCCESS,
        PermissionRecordManager::GetInstance().StartUsingPermission(tokenId, "ohos.permission.READ_MEDIA"));
    PermissionRecord record;
    record.tokenId = tokenId;
    record.opCode = Constant::OP_READ_MEDIA;
    // it->opcode == record.opcode && it->tokenId == record.tokenId
    PermissionRecordManager::GetInstance().RemoveRecordFromStartList(record); // record in cache has delete

    ASSERT_EQ(Constant::SUCCESS,
        PermissionRecordManager::GetInstance().StartUsingPermission(tokenId, "ohos.permission.READ_MEDIA"));
    record.tokenId = 123; // 123 is random input
    // it->opcode == record.opcode && it->tokenId != record.tokenId
    PermissionRecordManager::GetInstance().RemoveRecordFromStartList(record);

    record.opCode = Constant::OP_MICROPHONE;
    // it->opcode != record.opcode && it->tokenId != record.tokenId
    PermissionRecordManager::GetInstance().RemoveRecordFromStartList(record);

    ASSERT_EQ(Constant::SUCCESS,
        PermissionRecordManager::GetInstance().StopUsingPermission(tokenId, "ohos.permission.READ_MEDIA"));
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
 * @tc.name: PermissionListFilter001
 * @tc.desc: PermissionRecordManager::PermissionListFilter function test
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(PermissionRecordManagerTest, PermissionListFilter001, TestSize.Level1)
{
    std::vector<std::string> listSrc;
    std::vector<std::string> listRes;

    listSrc.emplace_back("com.ohos.TEST");
    // GetDefPermission != Constant::SUCCESS && listRes is empty && listSrc is not empty
    ASSERT_EQ(PrivacyError::ERR_PARAM_INVALID,
        PermissionRecordManager::GetInstance().PermissionListFilter(listSrc, listRes));

    listRes.emplace_back("com.ohos.TEST");
    // listRes is not empty
    ASSERT_EQ(Constant::SUCCESS, PermissionRecordManager::GetInstance().PermissionListFilter(listSrc, listRes));

    listSrc.clear();
    listRes.clear();
    // listRes is empty && listSrc is empty
    ASSERT_EQ(Constant::SUCCESS, PermissionRecordManager::GetInstance().PermissionListFilter(listSrc, listRes));
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
 * @tc.name: Unregister001
 * @tc.desc: PermissionRecordManager::Unregister function test
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(PermissionRecordManagerTest, Unregister001, TestSize.Level1)
{
    AccessTokenID tokenId = AccessTokenKit::GetHapTokenID(g_InfoParms1.userID, g_InfoParms1.bundleName,
        g_InfoParms1.instIndex);
    ASSERT_NE(static_cast<AccessTokenID>(0), tokenId);

    ASSERT_EQ(Constant::SUCCESS, PermissionRecordManager::GetInstance().StartUsingPermission(
        tokenId, "ohos.permission.READ_MEDIA"));

    PermissionRecordManager::GetInstance().Unregister();
    PermissionRecordManager::GetInstance().Unregister();

    ASSERT_EQ(Constant::SUCCESS, PermissionRecordManager::GetInstance().StopUsingPermission(
        tokenId, "ohos.permission.READ_MEDIA"));
}

/*
 * @tc.name: TranslationIntoPermissionRecord001
 * @tc.desc: PermissionRecord::TranslationIntoPermissionRecord function test
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(PermissionRecordManagerTest, TranslationIntoPermissionRecord001, TestSize.Level1)
{
    GenericValues values;
    values.Put(PrivacyFiledConst::FIELD_TOKEN_ID, static_cast<int32_t>(10086));
    values.Put(PrivacyFiledConst::FIELD_OP_CODE, 0);
    values.Put(PrivacyFiledConst::FIELD_STATUS, 0);
    values.Put(PrivacyFiledConst::FIELD_TIMESTAMP, static_cast<int64_t>(20210109));
    values.Put(PrivacyFiledConst::FIELD_ACCESS_DURATION, static_cast<int64_t>(1));
    values.Put(PrivacyFiledConst::FIELD_ACCESS_COUNT, 10);
    values.Put(PrivacyFiledConst::FIELD_REJECT_COUNT, 100);
    values.Put(PrivacyFiledConst::FIELD_LOCKSCREEN_STATUS, LockScreenStatusChangeType::PERM_ACTIVE_IN_UNLOCKED);
    PermissionRecord record;
    PermissionRecord::TranslationIntoPermissionRecord(values, record);
    ASSERT_EQ(static_cast<int32_t>(10086), record.tokenId);
    ASSERT_EQ(10, record.accessCount);
    ASSERT_EQ(100, record.rejectCount);
    ASSERT_EQ(static_cast<int64_t>(20210109), record.timestamp);
    ASSERT_EQ(static_cast<int64_t>(1), record.accessDuration);
    ASSERT_EQ(LockScreenStatusChangeType::PERM_ACTIVE_IN_UNLOCKED, record.lockScreenStatus);
}

/*
 * @tc.name: RecordMergeCheck001
 * @tc.desc: PermissionUsedRecordCache::RecordMergeCheck function test
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(PermissionRecordManagerTest, RecordMergeCheck001, TestSize.Level1)
{
    AccessTokenID tokenID1 = 123; // random input
    AccessTokenID tokenID2 = 124; // random input
    int32_t opCode1 = static_cast<int32_t>(Constant::OpCode::OP_READ_CALENDAR);
    int32_t opCode2 = static_cast<int32_t>(Constant::OpCode::OP_WRITE_CALENDAR);
    int32_t status1 = static_cast<int32_t>(ActiveChangeType::PERM_ACTIVE_IN_FOREGROUND);
    int32_t status2 = static_cast<int32_t>(ActiveChangeType::PERM_ACTIVE_IN_BACKGROUND);
    int32_t lockScreenStatus1 = static_cast<int32_t>(LockScreenStatusChangeType::PERM_ACTIVE_IN_UNLOCKED);
    int32_t lockScreenStatus2 = static_cast<int32_t>(LockScreenStatusChangeType::PERM_ACTIVE_IN_LOCKED);

    int64_t timestamp1 = TimeUtil::GetCurrentTimestamp();
    PermissionRecord record1 = {
        .timestamp = timestamp1,
    };
    int64_t timestamp2 = timestamp1 + 61 * 1000; // more than 1 min
    PermissionRecord record2 = {
        .timestamp = timestamp2,
    };

    // not in the same minute
    ASSERT_EQ(false, PermissionUsedRecordCache::GetInstance().RecordMergeCheck(record1, record2));

    record2.timestamp = timestamp1; // set the same timestamp to make sure the same minute
    record1.tokenId = tokenID1;
    record2.tokenId = tokenID2;
    // same minute + different tokenID
    ASSERT_EQ(false, PermissionUsedRecordCache::GetInstance().RecordMergeCheck(record1, record2));

    record2.tokenId = tokenID1;
    record1.opCode = opCode1;
    record2.opCode = opCode2;
    // same minute + same tokenID + different opcode
    ASSERT_EQ(false, PermissionUsedRecordCache::GetInstance().RecordMergeCheck(record1, record2));

    record2.opCode = opCode1;
    record1.status = status1;
    record2.status = status2;
    // same minute + same tokenID + same opcode + different status
    ASSERT_EQ(false, PermissionUsedRecordCache::GetInstance().RecordMergeCheck(record1, record2));

    record2.status = status1;
    record1.lockScreenStatus = lockScreenStatus1;
    record2.lockScreenStatus = lockScreenStatus2;
    // same minute + same tokenID + same opcode + same status + different lockScreenStatus
    ASSERT_EQ(false, PermissionUsedRecordCache::GetInstance().RecordMergeCheck(record1, record2));
}

/*
 * @tc.name: RecordMergeCheck002
 * @tc.desc: PermissionUsedRecordCache::RecordMergeCheck function test
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(PermissionRecordManagerTest, RecordMergeCheck002, TestSize.Level1)
{
    int32_t accessCount1 = 10; // random input
    int32_t accessCount2 = 0;
    int32_t accessCount3 = 9; // random input, diff from accessCount1
    int32_t rejectCount1 = 11; // random input
    int32_t rejectCount2 = 0;
    int32_t rejectCount3 = 8; // random input, diff from accessCount1

    int64_t timestamp = TimeUtil::GetCurrentTimestamp();

    // same minute + same tokenID + same opcode + same status + same lockScreenStatus
    PermissionRecord record1 = g_record;
    record1.timestamp = timestamp;
    PermissionRecord record2 = g_record;
    record2.timestamp = timestamp + 1;

    record1.accessCount = accessCount1;
    record2.accessCount = accessCount2;
    // different accessCount type
    ASSERT_EQ(false, PermissionUsedRecordCache::GetInstance().RecordMergeCheck(record1, record2));

    record1.accessCount = accessCount2;
    record2.accessCount = accessCount1;
    // different accessCount type
    ASSERT_EQ(false, PermissionUsedRecordCache::GetInstance().RecordMergeCheck(record1, record2));

    record2.accessCount = accessCount2;
    record1.rejectCount = rejectCount1;
    record2.rejectCount = rejectCount2;
    // different rejectCount type
    ASSERT_EQ(false, PermissionUsedRecordCache::GetInstance().RecordMergeCheck(record1, record2));

    record1.rejectCount = rejectCount2;
    record2.rejectCount = rejectCount1;
    // different rejectCount type
    ASSERT_EQ(false, PermissionUsedRecordCache::GetInstance().RecordMergeCheck(record1, record2));

    record2.rejectCount = rejectCount2;
    // same accessCount type + same rejectCount type
    ASSERT_EQ(true, PermissionUsedRecordCache::GetInstance().RecordMergeCheck(record1, record2));

    record1.accessCount = accessCount1;
    record2.accessCount = accessCount3;
    record1.rejectCount = rejectCount2;
    record2.rejectCount = rejectCount2;
    // same accessCount type + same rejectCount type
    ASSERT_EQ(true, PermissionUsedRecordCache::GetInstance().RecordMergeCheck(record1, record2));

    record1.accessCount = accessCount2;
    record2.accessCount = accessCount2;
    record1.rejectCount = rejectCount1;
    record2.rejectCount = rejectCount3;
    // same accessCount type + same rejectCount type
    ASSERT_EQ(true, PermissionUsedRecordCache::GetInstance().RecordMergeCheck(record1, record2));

    record1.accessCount = accessCount1;
    record2.accessCount = accessCount3;
    record1.rejectCount = rejectCount1;
    record2.rejectCount = rejectCount3;
    // same accessCount type + same rejectCount type
    ASSERT_EQ(true, PermissionUsedRecordCache::GetInstance().RecordMergeCheck(record1, record2));
}

/*
 * @tc.name: GetRecords001
 * @tc.desc: PermissionUsedRecordCache::GetRecords function test
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(PermissionRecordManagerTest, GetRecords001, TestSize.Level1)
{
    AccessTokenID tokenId = AccessTokenKit::GetHapTokenID(g_InfoParms1.userID, g_InfoParms1.bundleName,
        g_InfoParms1.instIndex);
    ASSERT_NE(static_cast<AccessTokenID>(0), tokenId);
    g_record.tokenId = tokenId;
    PermissionUsedRecordCache::GetInstance().AddRecordToBuffer(g_record);
    std::vector<std::string> permissionList;
    GenericValues andConditionValues;
    std::vector<GenericValues> findRecordsValues;
    PermissionUsedRecordCache::GetInstance().GetRecords(permissionList, andConditionValues, findRecordsValues, 0);
    ASSERT_EQ(static_cast<size_t>(0), findRecordsValues.size());
}

void AddRecord(int32_t num, std::vector<GenericValues>& values)
{
    for (int32_t i = 0; i < num; i++) {
        GenericValues value;
        value.Put(PrivacyFiledConst::FIELD_TOKEN_ID, i);
        value.Put(PrivacyFiledConst::FIELD_OP_CODE, Constant::OP_LOCATION);
        value.Put(PrivacyFiledConst::FIELD_STATUS, ActiveChangeType::PERM_ACTIVE_IN_BACKGROUND);
        value.Put(PrivacyFiledConst::FIELD_TIMESTAMP, i);
        value.Put(PrivacyFiledConst::FIELD_ACCESS_DURATION, i);
        value.Put(PrivacyFiledConst::FIELD_ACCESS_COUNT, 1);
        value.Put(PrivacyFiledConst::FIELD_REJECT_COUNT, 0);
        value.Put(PrivacyFiledConst::FIELD_LOCKSCREEN_STATUS, LockScreenStatusChangeType::PERM_ACTIVE_IN_UNLOCKED);
        value.Put(PrivacyFiledConst::FIELD_USED_TYPE, static_cast<int>(PermissionUsedType::NORMAL_TYPE));
        values.emplace_back(value);
    }

    ASSERT_EQ(static_cast<size_t>(num), values.size());
    PermissionUsedRecordDb::DataType type = PermissionUsedRecordDb::PERMISSION_RECORD;
    ASSERT_EQ(0, PermissionUsedRecordDb::GetInstance().Add(type, values));
    sleep(1); // wait record store in database
}

/**
 * @tc.name: GetRecords003
 * @tc.desc: test query record return max count 500.
 * @tc.type: FUNC
 * @tc.require: issueI5P4IU
 */
HWTEST_F(PermissionRecordManagerTest, GetRecords003, TestSize.Level1)
{
    std::vector<GenericValues> values;
    int32_t num = MAX_DETAIL_NUM + 1;
    AddRecord(num, values);

    PermissionUsedRequest request;
    request.isRemote = false;
    request.flag = PermissionUsageFlag::FLAG_PERMISSION_USAGE_DETAIL;

    GenericValues andConditionValues;
    std::vector<GenericValues> findRecordsValues;
    PermissionUsedRecordCache::GetInstance().GetRecords(request.permissionList, andConditionValues, findRecordsValues,
        MAX_DETAIL_NUM);
    EXPECT_EQ(static_cast<size_t>(MAX_DETAIL_NUM), findRecordsValues.size());

    PermissionUsedRecordDb::DataType type = PermissionUsedRecordDb::PERMISSION_RECORD;
    for (const auto& value : values) {
        ASSERT_EQ(0, PermissionUsedRecordDb::GetInstance().Remove(type, value));
    }
}

static void GeneratePermissionRecord(AccessTokenID tokenID)
{
    int64_t timestamp = TimeUtil::GetCurrentTimestamp();

    std::vector<GenericValues> values;
    GenericValues value;
    value.Put(PrivacyFiledConst::FIELD_TOKEN_ID, static_cast<int32_t>(tokenID));
    value.Put(PrivacyFiledConst::FIELD_OP_CODE, Constant::OP_LOCATION);
    value.Put(PrivacyFiledConst::FIELD_STATUS, ActiveChangeType::PERM_ACTIVE_IN_BACKGROUND);
    value.Put(PrivacyFiledConst::FIELD_TIMESTAMP, timestamp - THREE_SECOND);
    value.Put(PrivacyFiledConst::FIELD_ACCESS_DURATION, 1);
    value.Put(PrivacyFiledConst::FIELD_ACCESS_COUNT, 1);
    value.Put(PrivacyFiledConst::FIELD_REJECT_COUNT, 0);
    value.Put(PrivacyFiledConst::FIELD_LOCKSCREEN_STATUS, LockScreenStatusChangeType::PERM_ACTIVE_IN_UNLOCKED);
    value.Put(PrivacyFiledConst::FIELD_USED_TYPE, static_cast<int>(PermissionUsedType::NORMAL_TYPE));
    values.emplace_back(value); // background + unlock + normal

    value.Remove(PrivacyFiledConst::FIELD_TIMESTAMP);
    value.Put(PrivacyFiledConst::FIELD_TIMESTAMP, timestamp - TWO_SECOND);
    value.Remove(PrivacyFiledConst::FIELD_LOCKSCREEN_STATUS);
    value.Put(PrivacyFiledConst::FIELD_LOCKSCREEN_STATUS, LockScreenStatusChangeType::PERM_ACTIVE_IN_LOCKED);
    values.emplace_back(value); // background + lock + normal

    value.Remove(PrivacyFiledConst::FIELD_STATUS);
    value.Put(PrivacyFiledConst::FIELD_STATUS, ActiveChangeType::PERM_ACTIVE_IN_FOREGROUND);
    value.Remove(PrivacyFiledConst::FIELD_TIMESTAMP);
    value.Put(PrivacyFiledConst::FIELD_TIMESTAMP, timestamp - ONE_SECOND);
    value.Remove(PrivacyFiledConst::FIELD_LOCKSCREEN_STATUS);
    value.Put(PrivacyFiledConst::FIELD_LOCKSCREEN_STATUS, LockScreenStatusChangeType::PERM_ACTIVE_IN_UNLOCKED);
    values.emplace_back(value); // foreground + unlock + normal

    value.Remove(PrivacyFiledConst::FIELD_TIMESTAMP);
    value.Put(PrivacyFiledConst::FIELD_TIMESTAMP, timestamp);
    value.Remove(PrivacyFiledConst::FIELD_LOCKSCREEN_STATUS);
    value.Put(PrivacyFiledConst::FIELD_LOCKSCREEN_STATUS, LockScreenStatusChangeType::PERM_ACTIVE_IN_LOCKED);
    values.emplace_back(value); // foreground + lock + normal

    PermissionUsedRecordDb::DataType type = PermissionUsedRecordDb::PERMISSION_RECORD;
    ASSERT_EQ(0, PermissionUsedRecordDb::GetInstance().Add(type, values));
    sleep(1); // wait record store in database
}

/**
 * @tc.name: GetRecords004
 * @tc.desc: test query record flag 2 | 3 | 4 | 5
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(PermissionRecordManagerTest, GetRecords004, TestSize.Level1)
{
    AccessTokenID tokenID = AccessTokenKit::GetHapTokenID(g_InfoParms1.userID, g_InfoParms1.bundleName,
        g_InfoParms1.instIndex);
    ASSERT_NE(static_cast<AccessTokenID>(0), tokenID);

    GeneratePermissionRecord(tokenID);
    PermissionRecordManager::GetInstance().SetDefaultConfigValue();

    PermissionUsedRequest request;
    request.tokenId = tokenID;
    request.isRemote = false;
    request.flag = PermissionUsageFlag::FLAG_PERMISSION_USAGE_SUMMARY_IN_SCREEN_LOCKED;

    PermissionUsedResult result1;
    EXPECT_EQ(Constant::SUCCESS, PermissionRecordManager::GetInstance().GetPermissionUsedRecords(request, result1));
    EXPECT_EQ(static_cast<size_t>(1), result1.bundleRecords.size());
    EXPECT_EQ(static_cast<uint32_t>(tokenID), result1.bundleRecords[0].tokenId);
    EXPECT_EQ(static_cast<size_t>(1), result1.bundleRecords[0].permissionRecords.size());
    EXPECT_EQ(2, result1.bundleRecords[0].permissionRecords[0].accessCount);

    PermissionUsedResult result2;
    request.flag = PermissionUsageFlag::FLAG_PERMISSION_USAGE_SUMMARY_IN_SCREEN_UNLOCKED;
    EXPECT_EQ(Constant::SUCCESS, PermissionRecordManager::GetInstance().GetPermissionUsedRecords(request, result2));
    EXPECT_EQ(static_cast<size_t>(1), result2.bundleRecords.size());
    EXPECT_EQ(static_cast<uint32_t>(tokenID), result2.bundleRecords[0].tokenId);
    EXPECT_EQ(static_cast<size_t>(1), result2.bundleRecords[0].permissionRecords.size());
    EXPECT_EQ(2, result2.bundleRecords[0].permissionRecords[0].accessCount);

    PermissionUsedResult result3;
    request.flag = PermissionUsageFlag::FLAG_PERMISSION_USAGE_SUMMARY_IN_APP_FOREGROUND;
    EXPECT_EQ(Constant::SUCCESS, PermissionRecordManager::GetInstance().GetPermissionUsedRecords(request, result3));
    EXPECT_EQ(static_cast<size_t>(1), result3.bundleRecords.size());
    EXPECT_EQ(static_cast<uint32_t>(tokenID), result3.bundleRecords[0].tokenId);
    EXPECT_EQ(static_cast<size_t>(1), result3.bundleRecords[0].permissionRecords.size());
    EXPECT_EQ(2, result3.bundleRecords[0].permissionRecords[0].accessCount);

    PermissionUsedResult result4;
    request.flag = PermissionUsageFlag::FLAG_PERMISSION_USAGE_SUMMARY_IN_APP_BACKGROUND;
    EXPECT_EQ(Constant::SUCCESS, PermissionRecordManager::GetInstance().GetPermissionUsedRecords(request, result4));
    EXPECT_EQ(static_cast<size_t>(1), result4.bundleRecords.size());
    EXPECT_EQ(static_cast<uint32_t>(tokenID), result4.bundleRecords[0].tokenId);
    EXPECT_EQ(static_cast<size_t>(1), result4.bundleRecords[0].permissionRecords.size());
    EXPECT_EQ(2, result4.bundleRecords[0].permissionRecords[0].accessCount);
}

/*
 * @tc.name: GetFromPersistQueueAndDatabase001
 * @tc.desc: PermissionUsedRecordCache::GetFromPersistQueueAndDatabase function test
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(PermissionRecordManagerTest, GetFromPersistQueueAndDatabase001, TestSize.Level1)
{
    const std::set<int32_t> opCodeList;
    const GenericValues andConditionValues;
    std::vector<GenericValues> findRecordsValues;
    PermissionUsedRecordCache::GetInstance().GetFromPersistQueueAndDatabase(
        opCodeList, andConditionValues, findRecordsValues, 0);
    ASSERT_EQ(static_cast<size_t>(0), findRecordsValues.size());
}

/*
 * @tc.name: DeepCopyFromHead001
 * @tc.desc: PermissionUsedRecordCache::DeepCopyFromHead function test
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(PermissionRecordManagerTest, DeepCopyFromHead001, TestSize.Level1)
{
    std::shared_ptr<PermissionUsedRecordNode> head = std::make_shared<PermissionUsedRecordNode>();
    std::shared_ptr<PermissionUsedRecordNode> node1 = std::make_shared<PermissionUsedRecordNode>();
    std::shared_ptr<PermissionUsedRecordNode> node2 = std::make_shared<PermissionUsedRecordNode>();
    std::shared_ptr<PermissionUsedRecordNode> node3 = std::make_shared<PermissionUsedRecordNode>();
    std::shared_ptr<PermissionUsedRecordNode> node4 = std::make_shared<PermissionUsedRecordNode>();

    head->next = node1;

    node1->pre.lock() = head;
    node1->next = node2;
    node1->record = g_recordA1;

    node2->pre.lock() = node1;
    node2->next = node3;
    node2->record = g_recordA2;

    node3->pre.lock() = node2;
    node3->next = node4;
    node3->record = g_recordB1;

    node4->pre.lock() = node3;
    node4->next = nullptr;
    node4->record = g_recordB2;

    ASSERT_EQ(head->next->record.opCode, g_recordA1.opCode);
    ASSERT_EQ(head->next->next->record.opCode, g_recordA2.opCode);
    ASSERT_EQ(head->next->next->next->record.opCode, g_recordB1.opCode);
    ASSERT_EQ(head->next->next->next->next->record.opCode, g_recordB2.opCode);

    std::shared_ptr<PermissionUsedRecordNode> copyHead = std::make_shared<PermissionUsedRecordNode>();
    PermissionUsedRecordCache::GetInstance().DeepCopyFromHead(nullptr, copyHead, DEEP_COPY_NUM);
    ASSERT_EQ(copyHead->next, nullptr);
    PermissionUsedRecordCache::GetInstance().DeepCopyFromHead(head, copyHead, 0);
    ASSERT_EQ(copyHead->next, nullptr);

    PermissionUsedRecordCache::GetInstance().DeepCopyFromHead(head, copyHead, DEEP_COPY_NUM);

    ASSERT_EQ(copyHead->record.opCode, head->record.opCode);
    ASSERT_EQ(copyHead->next->record.opCode, g_recordA1.opCode);
    ASSERT_EQ(copyHead->next->next->record.opCode, g_recordA2.opCode);
    ASSERT_EQ(copyHead->next->next->next->record.opCode, g_recordB1.opCode);
    ASSERT_EQ(copyHead->next->next->next->next->record.opCode, g_recordB2.opCode);
}

/*
 * @tc.name: RecordManagerTest001
 * @tc.desc: GetAllRecordValuesByKey normal case
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(PermissionRecordManagerTest, RecordManagerTest001, TestSize.Level1)
{
    std::vector<GenericValues> resultValues;
    EXPECT_EQ(true, PermissionRecordRepository::GetInstance().GetAllRecordValuesByKey(
        PrivacyFiledConst::FIELD_TOKEN_ID, resultValues));
}

/*
 * @tc.name: PermissionUsedRecordCacheTest001
 * @tc.desc: PermissionUsedRecordCache Func test
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(PermissionRecordManagerTest, PermissionUsedRecordCacheTest001, TestSize.Level1)
{
    std::set<AccessTokenID> tokenIdList;
    PermissionUsedRecordCache::GetInstance().FindTokenIdList(tokenIdList);
    PermissionRecordManager::GetInstance().GetLocalRecordTokenIdList(tokenIdList);
    std::set<int32_t> opCodeList;
    GenericValues andConditionValues;
    std::vector<GenericValues> findRecordsValues;
    int32_t cache2QueryCount = 0; // 0 is a invalid input
    PermissionUsedRecordCache::GetInstance().GetFromPersistQueueAndDatabase(opCodeList,
        andConditionValues, findRecordsValues, cache2QueryCount);
    
    opCodeList.insert(0); // 0 is a test opcode
    PermissionRecord record = {
        .tokenId = g_selfTokenId,
        .opCode = -1, // -1 is a test opcode
    };
    EXPECT_FALSE(PermissionUsedRecordCache::GetInstance().RecordCompare(g_selfTokenId,
        opCodeList, andConditionValues, record));
}

/**
 * @tc.name: GetRecordsFromLocalDBTest001
 * @tc.desc: test GetRecordsFromLocalDB: token = 0
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(PermissionRecordManagerTest, GetRecordsFromLocalDBTest001, TestSize.Level1)
{
    PermissionUsedRequest request;
    request.tokenId = g_selfTokenId;
    request.isRemote = false;
    request.flag = PermissionUsageFlag::FLAG_PERMISSION_USAGE_SUMMARY_IN_SCREEN_LOCKED;
    PermissionUsedResult result;
    EXPECT_TRUE(PermissionRecordManager::GetInstance().GetRecordsFromLocalDB(request, result));
}

/**
 * @tc.name: GetRecordsFromLocalDBTest002
 * @tc.desc: test GetRecordsFromLocalDB: beginTimeMillis = -1
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(PermissionRecordManagerTest, GetRecordsFromLocalDBTest002, TestSize.Level1)
{
    PermissionUsedRequest request;
    request.tokenId = g_selfTokenId;
    request.isRemote = false;
    request.flag = PermissionUsageFlag::FLAG_PERMISSION_USAGE_SUMMARY_IN_SCREEN_LOCKED;
    request.beginTimeMillis = -1; // -1 is a invalid input
    PermissionUsedResult result;
    EXPECT_EQ(false, PermissionRecordManager::GetInstance().GetRecordsFromLocalDB(request, result));
}

/**
 * @tc.name: GetRecordsFromLocalDBTest003
 * @tc.desc: test GetRecords: not exist OpCode
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(PermissionRecordManagerTest, RecordConverage011, TestSize.Level1)
{
    PermissionUsedRequest request;
    request.tokenId = g_selfTokenId;
    request.isRemote = false;
    request.flag = PermissionUsageFlag::FLAG_PERMISSION_USAGE_SUMMARY_IN_SCREEN_LOCKED;
    request.beginTimeMillis = -1; // -1 is a invalid input

    std::vector<GenericValues> recordValues;
    GenericValues tmp;
    int64_t val = 1; // 1 is a test value
    int32_t notExistOpCode = -2; // -2 is a not exist OpCode
    tmp.Put(PrivacyFiledConst::FIELD_TIMESTAMP, val);
    tmp.Put(PrivacyFiledConst::FIELD_OP_CODE, notExistOpCode);
    recordValues.emplace_back(tmp);
    int32_t flag = 1; // 1 is a test flag
    BundleUsedRecord bundleRecord;
    PermissionUsedResult result;
    PermissionRecordManager::GetInstance().GetRecords(flag, recordValues, bundleRecord, result);
}

/*
 * @tc.name: Query001
 * @tc.desc: PermissionRecordRepository::Query function test
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(PermissionRecordManagerTest, Query001, TestSize.Level1)
{
    PermissionUsedRecordDb::DataType type = PermissionUsedRecordDb::PERMISSION_USED_TYPE;
    GenericValues conditionValue;
    conditionValue.Put(PrivacyFiledConst::FIELD_TOKEN_ID, RANDOM_TOKENID);
    conditionValue.Put(PrivacyFiledConst::FIELD_PERMISSION_CODE,
        static_cast<int32_t>(Constant::OpCode::OP_ANSWER_CALL));
    std::vector<GenericValues> results;
    ASSERT_EQ(true, PermissionRecordRepository::GetInstance().Query(type, conditionValue, results));
    for (const auto& result : results) {
        // no record with token 123 before add
        ASSERT_NE(RANDOM_TOKENID, result.GetInt(PrivacyFiledConst::FIELD_TOKEN_ID));
    }
    results.clear();

    GenericValues value;
    value.Put(PrivacyFiledConst::FIELD_TOKEN_ID, RANDOM_TOKENID);
    value.Put(PrivacyFiledConst::FIELD_PERMISSION_CODE, static_cast<int32_t>(Constant::OpCode::OP_ANSWER_CALL));
    value.Put(PrivacyFiledConst::FIELD_USED_TYPE, PERMISSION_USED_TYPE_VALUE);
    std::vector<GenericValues> values;
    values.emplace_back(value);
    // add a record: 123-0-1
    ASSERT_EQ(true, PermissionRecordRepository::GetInstance().Add(type, values));

    ASSERT_EQ(true, PermissionRecordRepository::GetInstance().Query(type, conditionValue, results));
    ASSERT_EQ(false, results.empty());
    for (const auto& result : results) {
        // query result success, when tokenId is 123, permission_code is 0 and used_type is 1
        if (RANDOM_TOKENID == result.GetInt(PrivacyFiledConst::FIELD_TOKEN_ID)) {
            ASSERT_EQ(static_cast<int32_t>(Constant::OpCode::OP_ANSWER_CALL),
                result.GetInt(PrivacyFiledConst::FIELD_PERMISSION_CODE));
            ASSERT_EQ(PERMISSION_USED_TYPE_VALUE, result.GetInt(PrivacyFiledConst::FIELD_USED_TYPE));
            break;
        }
    }
    results.clear();

    ASSERT_EQ(true, PermissionRecordRepository::GetInstance().Remove(type, conditionValue));
}

/*
 * @tc.name: Update001
 * @tc.desc: PermissionRecordRepository::Update function test
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(PermissionRecordManagerTest, Update001, TestSize.Level1)
{
    PermissionUsedRecordDb::DataType type = PermissionUsedRecordDb::PERMISSION_USED_TYPE;
    GenericValues conditionValue;
    conditionValue.Put(PrivacyFiledConst::FIELD_TOKEN_ID, RANDOM_TOKENID);
    conditionValue.Put(PrivacyFiledConst::FIELD_PERMISSION_CODE,
        static_cast<int32_t>(Constant::OpCode::OP_ANSWER_CALL));

    GenericValues value;
    value.Put(PrivacyFiledConst::FIELD_TOKEN_ID, RANDOM_TOKENID);
    value.Put(PrivacyFiledConst::FIELD_PERMISSION_CODE, static_cast<int32_t>(Constant::OpCode::OP_ANSWER_CALL));
    value.Put(PrivacyFiledConst::FIELD_USED_TYPE, PERMISSION_USED_TYPE_VALUE);
    std::vector<GenericValues> values;
    values.emplace_back(value);
    // add a record: 123-0-1
    ASSERT_EQ(true, PermissionRecordRepository::GetInstance().Add(type, values));

    std::vector<GenericValues> results;
    ASSERT_EQ(true, PermissionRecordRepository::GetInstance().Query(type, conditionValue, results));
    ASSERT_EQ(false, results.empty());
    for (const auto& result : results) {
        // query result success, when tokenId is 123, permission_code is 0 and used_type is 1
        if (RANDOM_TOKENID == result.GetInt(PrivacyFiledConst::FIELD_TOKEN_ID)) {
            ASSERT_EQ(static_cast<int32_t>(Constant::OpCode::OP_ANSWER_CALL),
                result.GetInt(PrivacyFiledConst::FIELD_PERMISSION_CODE));
            ASSERT_EQ(PERMISSION_USED_TYPE_VALUE, result.GetInt(PrivacyFiledConst::FIELD_USED_TYPE));
            break;
        }
    }
    results.clear();

    GenericValues modifyValue;
    modifyValue.Put(PrivacyFiledConst::FIELD_USED_TYPE, PICKER_TYPE_VALUE);
    // update record 123-0-1 to 123-0-2
    ASSERT_EQ(true, PermissionRecordRepository::GetInstance().Update(type, modifyValue, conditionValue));
    ASSERT_EQ(true, PermissionRecordRepository::GetInstance().Query(type, conditionValue, results));
    ASSERT_EQ(false, results.empty());
    for (const auto& result : results) {
        // query result success, when tokenId is 123, permission_code is 0 and used_type is 2
        if (RANDOM_TOKENID == result.GetInt(PrivacyFiledConst::FIELD_TOKEN_ID)) {
            ASSERT_EQ(static_cast<int32_t>(Constant::OpCode::OP_ANSWER_CALL),
                result.GetInt(PrivacyFiledConst::FIELD_PERMISSION_CODE));
            ASSERT_EQ(PICKER_TYPE_VALUE, result.GetInt(PrivacyFiledConst::FIELD_USED_TYPE));
            break;
        }
    }

    ASSERT_EQ(true, PermissionRecordRepository::GetInstance().Remove(type, conditionValue));
}

/*
 * @tc.name: AddOrUpdateUsedTypeIfNeeded001
 * @tc.desc: PermissionRecordManager::AddOrUpdateUsedTypeIfNeeded function test
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(PermissionRecordManagerTest, AddOrUpdateUsedTypeIfNeeded001, TestSize.Level1)
{
    int32_t tokenId = RANDOM_TOKENID;
    int32_t opCode = static_cast<int32_t>(Constant::OpCode::OP_ANSWER_CALL);
    PermissionUsedType visitType = PermissionUsedType::NORMAL_TYPE;
    PermissionUsedRecordDb::DataType type = PermissionUsedRecordDb::PERMISSION_USED_TYPE;
    GenericValues conditionValue;
    conditionValue.Put(PrivacyFiledConst::FIELD_TOKEN_ID, RANDOM_TOKENID);
    conditionValue.Put(PrivacyFiledConst::FIELD_PERMISSION_CODE, opCode);

    // query result empty, add input type
    ASSERT_EQ(true, PermissionRecordManager::GetInstance().AddOrUpdateUsedTypeIfNeeded(tokenId, opCode, visitType));
    std::vector<GenericValues> results;
    ASSERT_EQ(true, PermissionRecordRepository::GetInstance().Query(type, conditionValue, results));
    ASSERT_EQ(false, results.empty());
    for (const auto& result : results) {
        if (RANDOM_TOKENID == result.GetInt(PrivacyFiledConst::FIELD_TOKEN_ID)) {
            ASSERT_EQ(static_cast<int32_t>(Constant::OpCode::OP_ANSWER_CALL),
                result.GetInt(PrivacyFiledConst::FIELD_PERMISSION_CODE));
            ASSERT_EQ(PERMISSION_USED_TYPE_VALUE, result.GetInt(PrivacyFiledConst::FIELD_USED_TYPE));
            break;
        }
    }
    results.clear();

    // uesd type exsit and same to input type, return
    ASSERT_EQ(true, PermissionRecordManager::GetInstance().AddOrUpdateUsedTypeIfNeeded(tokenId, opCode, visitType));
    ASSERT_EQ(true, PermissionRecordRepository::GetInstance().Query(type, conditionValue, results));
    for (const auto& result : results) {
        if (RANDOM_TOKENID == result.GetInt(PrivacyFiledConst::FIELD_TOKEN_ID)) {
            ASSERT_EQ(static_cast<int32_t>(Constant::OpCode::OP_ANSWER_CALL),
                result.GetInt(PrivacyFiledConst::FIELD_PERMISSION_CODE));
            ASSERT_EQ(PERMISSION_USED_TYPE_VALUE, result.GetInt(PrivacyFiledConst::FIELD_USED_TYPE));
            break;
        }
    }
    results.clear();

    visitType = PermissionUsedType::PICKER_TYPE;
    // used type exsit and diff from input type, update the type
    ASSERT_EQ(true, PermissionRecordManager::GetInstance().AddOrUpdateUsedTypeIfNeeded(tokenId, opCode, visitType));
    ASSERT_EQ(true, PermissionRecordRepository::GetInstance().Query(type, conditionValue, results));
    for (const auto& result : results) {
        if (RANDOM_TOKENID == result.GetInt(PrivacyFiledConst::FIELD_TOKEN_ID)) {
            ASSERT_EQ(static_cast<int32_t>(Constant::OpCode::OP_ANSWER_CALL),
                result.GetInt(PrivacyFiledConst::FIELD_PERMISSION_CODE));
            ASSERT_EQ(PERMISSION_USED_TYPE_WITH_PICKER_TYPE_VALUE, result.GetInt(PrivacyFiledConst::FIELD_USED_TYPE));
            break;
        }
    }

    ASSERT_EQ(true, PermissionRecordRepository::GetInstance().Remove(type, conditionValue));
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

/**
 * @tc.name: Dlopen002
 * @tc.desc: Open a exist lib & exist func
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(PermissionRecordManagerTest, Dlopen002, TestSize.Level1)
{
    LibraryLoader loader(LibAbilityMngPath);
    AbilityManagerAccessLoaderInterface* abilityManagerAccessLoader =
        loader.GetObject<AbilityManagerAccessLoaderInterface>();
    EXPECT_NE(nullptr, loader.handle_);
    EXPECT_NE(nullptr, abilityManagerAccessLoader);
}
} // namespace AccessToken
} // namespace Security
} // namespace OHOS
