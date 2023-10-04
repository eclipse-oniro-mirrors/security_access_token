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

#include "access_token.h"
#include "accesstoken_kit.h"
#include "accesstoken_log.h"
#include "audio_manager_privacy_client.h"
#include "camera_manager_privacy_client.h"
#include "constant.h"
#include "permission_record.h"
#define private public
#include "active_status_callback_manager.h"
#include "permission_record_manager.h"
#undef private
#include "perm_active_status_change_callback_stub.h"
#include "privacy_error.h"
#include "privacy_kit.h"
#include "state_change_callback.h"
#include "token_setproc.h"

using namespace testing;
using namespace testing::ext;
using namespace OHOS;

namespace OHOS {
namespace Security {
namespace AccessToken {
namespace {
static AccessTokenID g_selfTokenId = 0;
constexpr const char* CAMERA_PERMISSION_NAME = "ohos.permission.CAMERA";
constexpr const char* MICROPHONE_PERMISSION_NAME = "ohos.permission.MICROPHONE";
constexpr const char* LOCATION_PERMISSION_NAME = "ohos.permission.LOCATION";
static constexpr uint32_t MAX_CALLBACK_SIZE = 1024;
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
    .rejectCount = 0
};

static PermissionRecord g_recordA2 = {
    .opCode = Constant::OP_MICROPHONE,
    .status = ActiveChangeType::PERM_ACTIVE_IN_BACKGROUND,
    .timestamp = 0L,
    .accessDuration = 0L,
    .accessCount = 1,
    .rejectCount = 0
};

static PermissionRecord g_recordB1 = {
    .opCode = Constant::OP_CAMERA,
    .status = ActiveChangeType::PERM_ACTIVE_IN_BACKGROUND,
    .timestamp = 0L,
    .accessDuration = 0L,
    .accessCount = 1,
    .rejectCount = 0
};

static PermissionRecord g_recordB2 = {
    .opCode = Constant::OP_MICROPHONE,
    .status = ActiveChangeType::PERM_ACTIVE_IN_BACKGROUND,
    .timestamp = 0L,
    .accessDuration = 0L,
    .accessCount = 1,
    .rejectCount = 0
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
    tokenId = AccessTokenKit::GetHapTokenID(g_InfoParms2.userID, g_InfoParms2.bundleName,
        g_InfoParms2.instIndex);
    AccessTokenKit::DeleteToken(tokenId);
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
    PermissionRecordManager::GetInstance().AddRecordIfNotStarted(record1);
#ifdef CAMERA_FLOAT_WINDOW_ENABLE
    PermissionRecordManager::GetInstance().NotifyCameraFloatWindowChange(tokenId, false);
#endif
    PermissionRecordManager::GetInstance().FindRecordsToUpdateAndExecuted(tokenId, status);
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
    PermissionRecordManager::GetInstance().AddRecordIfNotStarted(record1);
#ifdef CAMERA_FLOAT_WINDOW_ENABLE
    PermissionRecordManager::GetInstance().NotifyCameraFloatWindowChange(tokenId, false);
#endif
    PermissionRecordManager::GetInstance().FindRecordsToUpdateAndExecuted(tokenId, status);
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
    PermissionRecordManager::GetInstance().AddRecordIfNotStarted(record1);
#ifdef CAMERA_FLOAT_WINDOW_ENABLE
    PermissionRecordManager::GetInstance().NotifyCameraFloatWindowChange(tokenId, false);
#endif
    PermissionRecordManager::GetInstance().FindRecordsToUpdateAndExecuted(tokenId, status);

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
    PermissionRecordManager::GetInstance().AddRecordIfNotStarted(record1);
#ifdef CAMERA_FLOAT_WINDOW_ENABLE
    PermissionRecordManager::GetInstance().NotifyCameraFloatWindowChange(tokenId, true);
#endif
    PermissionRecordManager::GetInstance().FindRecordsToUpdateAndExecuted(tokenId, status);

    PermissionRecord record;
    PermissionRecordManager::GetInstance().GetRecordFromStartList(record1.tokenId, record1.opCode, record);
    ASSERT_EQ(record1.tokenId, tokenId);
}

/*
 * @tc.name: LockscreenStatusListener001
 * @tc.desc: register and startusing permissions then use NotifyLockscreenStatusChange
 * @tc.type: FUNC
 * @tc.require: issueI5SZHG
 */
HWTEST_F(PermissionRecordManagerTest, LockscreenStatusListener001, TestSize.Level1)
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

    PermissionRecordManager::GetInstance().NotifyLockscreenStatusChange(PERM_ACTIVE_IN_UNLOCK);
    PermissionRecordManager::GetInstance().NotifyLockscreenStatusChange(PERM_ACTIVE_IN_UNLOCK);
    PermissionRecordManager::GetInstance().NotifyLockscreenStatusChange(PERM_ACTIVE_IN_UNLOCK);
    PermissionRecordManager::GetInstance().NotifyLockscreenStatusChange(PERM_ACTIVE_IN_UNLOCK);
    PermissionRecordManager::GetInstance().NotifyLockscreenStatusChange(PERM_ACTIVE_IN_LOCKED);
    PermissionRecordManager::GetInstance().NotifyLockscreenStatusChange(PERM_ACTIVE_IN_LOCKED);
    PermissionRecordManager::GetInstance().NotifyLockscreenStatusChange(PERM_ACTIVE_IN_LOCKED);
    PermissionRecordManager::GetInstance().NotifyLockscreenStatusChange(PERM_ACTIVE_IN_LOCKED);
}

/*
 * @tc.name: GenerateRecordsWhenScreenStatusChangedTest001
 * @tc.desc: FindRecordsToUpdateAndExecuted function test with invaild tokenId or permissionName or callback.
 * @tc.type: FUNC
 * @tc.require: issueI5RWX5 issueI5RWX3 issueI5RWXA
 */
HWTEST_F(PermissionRecordManagerTest, GenerateRecordsWhenScreenStatusChangedTest001, TestSize.Level1)
{
    AccessTokenID tokenId = AccessTokenKit::GetHapTokenID(g_InfoParms1.userID, g_InfoParms1.bundleName,
        g_InfoParms1.instIndex);
    ASSERT_NE(INVALID_TOKENID, tokenId);

    EXPECT_EQ(0, SetSelfTokenID(tokenId));

    LockscreenStatusChangeType lockscreenStatus = PERM_ACTIVE_IN_LOCKED;

    PermissionRecord record1 = {
        .tokenId = tokenId,
        .opCode = Constant::OP_CAMERA,
    };
    CameraManagerPrivacyClient::GetInstance().MuteCamera(false);
    PermissionRecordManager::GetInstance().AddRecordIfNotStarted(record1);
#ifdef CAMERA_FLOAT_WINDOW_ENABLE
    PermissionRecordManager::GetInstance().NotifyCameraFloatWindowChange(tokenId, false);
#endif
    PermissionRecordManager::GetInstance().GenerateRecordsWhenScreenStatusChanged(lockscreenStatus);
    PermissionRecordManager::GetInstance().NotifyLockscreenStatusChange(lockscreenStatus);

    PermissionRecord record;
    PermissionRecordManager::GetInstance().GetRecordFromStartList(record1.tokenId, record1.opCode, record);

    ASSERT_EQ(record1.tokenId, tokenId);
}

/*
 * @tc.name: GenerateRecordsWhenScreenStatusChangedTest002
 * @tc.desc: FindRecordsToUpdateAndExecuted function test with invaild tokenId or permissionName or callback.
 * @tc.type: FUNC
 * @tc.require: issueI5RWX5 issueI5RWX3 issueI5RWXA
 */
HWTEST_F(PermissionRecordManagerTest, GenerateRecordsWhenScreenStatusChangedTest002, TestSize.Level1)
{
    AccessTokenID tokenId = AccessTokenKit::GetHapTokenID(g_InfoParms1.userID, g_InfoParms1.bundleName,
        g_InfoParms1.instIndex);
    ASSERT_NE(INVALID_TOKENID, tokenId);
    LockscreenStatusChangeType lockscreenStatus = PERM_ACTIVE_IN_LOCKED;

    PermissionRecord record1 = {
        .tokenId = tokenId,
        .opCode = Constant::OP_MICROPHONE,
    };
    PermissionRecordManager::GetInstance().AddRecordIfNotStarted(record1);
#ifdef CAMERA_FLOAT_WINDOW_ENABLE
    PermissionRecordManager::GetInstance().NotifyCameraFloatWindowChange(tokenId, false);
#endif
    PermissionRecordManager::GetInstance().GenerateRecordsWhenScreenStatusChanged(lockscreenStatus);
    PermissionRecordManager::GetInstance().NotifyLockscreenStatusChange(lockscreenStatus);

    PermissionRecord record;
    PermissionRecordManager::GetInstance().GetRecordFromStartList(record1.tokenId, record1.opCode, record);
    ASSERT_EQ(record1.tokenId, tokenId);
}

/*
 * @tc.name: GenerateRecordsWhenScreenStatusChangedTest003
 * @tc.desc: FindRecordsToUpdateAndExecuted function test with invaild tokenId or permissionName or callback.
 * @tc.type: FUNC
 * @tc.require: issueI5RWX5 issueI5RWX3 issueI5RWXA
 */
HWTEST_F(PermissionRecordManagerTest, GenerateRecordsWhenScreenStatusChangedTest003, TestSize.Level1)
{
    AccessTokenID tokenId = AccessTokenKit::GetHapTokenID(g_InfoParms1.userID, g_InfoParms1.bundleName,
        g_InfoParms1.instIndex);
    ASSERT_NE(INVALID_TOKENID, tokenId);
    LockscreenStatusChangeType lockscreenStatus = PERM_ACTIVE_IN_LOCKED;

    PermissionRecord record1 = {
        .tokenId = tokenId,
        .opCode = Constant::OP_CAMERA,
    };
    PermissionRecordManager::GetInstance().AddRecordIfNotStarted(record1);
#ifdef CAMERA_FLOAT_WINDOW_ENABLE
    PermissionRecordManager::GetInstance().NotifyCameraFloatWindowChange(tokenId, false);
#endif
    PermissionRecordManager::GetInstance().GenerateRecordsWhenScreenStatusChanged(lockscreenStatus);

    PermissionRecord record;
    PermissionRecordManager::GetInstance().GetRecordFromStartList(record1.tokenId, record1.opCode, record);

    ASSERT_EQ(record1.tokenId, tokenId);
}

/*
 * @tc.name: GenerateRecordsWhenScreenStatusChangedTest004
 * @tc.desc: FindRecordsToUpdateAndExecuted function test with invaild tokenId or permissionName or callback.
 * @tc.type: FUNC
 * @tc.require: issueI5RWX5 issueI5RWX3 issueI5RWXA
 */
HWTEST_F(PermissionRecordManagerTest, GenerateRecordsWhenScreenStatusChangedTest004, TestSize.Level1)
{
    AccessTokenID tokenId = AccessTokenKit::GetHapTokenID(g_InfoParms1.userID, g_InfoParms1.bundleName,
        g_InfoParms1.instIndex);
    ASSERT_NE(INVALID_TOKENID, tokenId);
    LockscreenStatusChangeType lockscreenStatus = PERM_ACTIVE_IN_LOCKED;

    PermissionRecord record1 = {
        .tokenId = tokenId,
        .opCode = Constant::OP_CAMERA,
    };
    PermissionRecordManager::GetInstance().AddRecordIfNotStarted(record1);
#ifdef CAMERA_FLOAT_WINDOW_ENABLE
    PermissionRecordManager::GetInstance().NotifyCameraFloatWindowChange(tokenId, true);
#endif
    PermissionRecordManager::GetInstance().GenerateRecordsWhenScreenStatusChanged(lockscreenStatus);

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
    ASSERT_EQ(ERR_TOKENID_NOT_EXIST,
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
    ASSERT_EQ(PrivacyError::ERR_TOKENID_NOT_EXIST, PermissionRecordManager::GetInstance().StartUsingPermission(
        static_cast<AccessTokenID>(123), "ohos.permission.CAMERA", nullptr));
    
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
    AudioManagerPrivacyClient::GetInstance().SetMicrophoneMute(false); // false means open
    AccessTokenID tokenId = AccessTokenKit::GetHapTokenID(g_InfoParms1.userID, g_InfoParms1.bundleName,
        g_InfoParms1.instIndex);
    ASSERT_EQ(0, PermissionRecordManager::GetInstance().StartUsingPermission(tokenId, CAMERA_PERMISSION_NAME));

    PermissionRecordManager::GetInstance().NotifyMicChange(true); // fill opCode not mic branch
    ASSERT_EQ(0, PermissionRecordManager::GetInstance().StopUsingPermission(tokenId, CAMERA_PERMISSION_NAME));
}

/*
 * @tc.name: MicSwitchChangeListener002
 * @tc.desc: NotifyMicChange function test mic global switch is open
 * @tc.type: FUNC
 * @tc.require: issueI5RWXF
 */
HWTEST_F(PermissionRecordManagerTest, MicSwitchChangeListener002, TestSize.Level1)
{
    AudioManagerPrivacyClient::GetInstance().SetMicrophoneMute(false); // false means open
    AccessTokenID tokenId = AccessTokenKit::GetHapTokenID(g_InfoParms1.userID, g_InfoParms1.bundleName,
        g_InfoParms1.instIndex);
    // status is background
    ASSERT_EQ(0, PermissionRecordManager::GetInstance().StartUsingPermission(tokenId, MICROPHONE_PERMISSION_NAME));
    PermissionRecordManager::GetInstance().NotifyMicChange(true); // fill true status is not inactive branch
    ASSERT_EQ(0, PermissionRecordManager::GetInstance().StopUsingPermission(tokenId, MICROPHONE_PERMISSION_NAME));
}

/*
 * @tc.name: MicSwitchChangeListener003
 * @tc.desc: NotifyMicChange function test mic global switch is close
 * @tc.type: FUNC
 * @tc.require: issueI5RWXF
 */
HWTEST_F(PermissionRecordManagerTest, MicSwitchChangeListener003, TestSize.Level1)
{
    AudioManagerPrivacyClient::GetInstance().SetMicrophoneMute(true); // true means close
    AccessTokenID tokenId = AccessTokenKit::GetHapTokenID(g_InfoParms1.userID, g_InfoParms1.bundleName,
        g_InfoParms1.instIndex);
    // status is inactive
    ASSERT_EQ(0, PermissionRecordManager::GetInstance().StartUsingPermission(tokenId, MICROPHONE_PERMISSION_NAME));
    sleep(3); // wait for dialog disappear
    PermissionRecordManager::GetInstance().NotifyMicChange(true); // fill true status is inactive branch
    ASSERT_EQ(0, PermissionRecordManager::GetInstance().StopUsingPermission(tokenId, MICROPHONE_PERMISSION_NAME));
}

/*
 * @tc.name: MicSwitchChangeListener005
 * @tc.desc: NotifyMicChange function test mic global switch is close
 * @tc.type: FUNC
 * @tc.require: issueI5RWXF
 */
HWTEST_F(PermissionRecordManagerTest, MicSwitchChangeListener005, TestSize.Level1)
{
    AudioManagerPrivacyClient::GetInstance().SetMicrophoneMute(true); // true means close
    AccessTokenID tokenId = AccessTokenKit::GetHapTokenID(g_InfoParms1.userID, g_InfoParms1.bundleName,
        g_InfoParms1.instIndex);
    // status is inactive
    ASSERT_EQ(0, PermissionRecordManager::GetInstance().StartUsingPermission(tokenId, MICROPHONE_PERMISSION_NAME));
    sleep(3); // wait for dialog disappear
    PermissionRecordManager::GetInstance().NotifyMicChange(false); // fill false status is inactive branch
    ASSERT_EQ(0, PermissionRecordManager::GetInstance().StopUsingPermission(tokenId, MICROPHONE_PERMISSION_NAME));
    AudioManagerPrivacyClient::GetInstance().SetMicrophoneMute(false); // false means open
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

    std::string permissionName = "com.ohos.test";
    int32_t successCount = 1;
    int32_t failCount = 0;

    ASSERT_EQ(PrivacyError::ERR_PERMISSION_NOT_EXIST, PermissionRecordManager::GetInstance().AddPermissionUsedRecord(
        tokenId, permissionName, successCount, failCount)); // invaild permission error
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

    std::string permissionName = "ohos.permission.READ_MEDIA";
    int32_t successCount = 0;
    int32_t failCount = 0;

    ASSERT_EQ(PrivacyError::ERR_PARAM_INVALID, PermissionRecordManager::GetInstance().AddPermissionUsedRecord(
        tokenId, permissionName, successCount, failCount));
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
    ASSERT_EQ(PrivacyError::ERR_TOKENID_NOT_EXIST, PermissionRecordManager::GetInstance().StartUsingPermission(
        static_cast<AccessTokenID>(123), "ohos.permission.READ_MEDIA"));
    
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
    ASSERT_EQ(PrivacyError::ERR_TOKENID_NOT_EXIST, PermissionRecordManager::GetInstance().StopUsingPermission(
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
} // namespace AccessToken
} // namespace Security
} // namespace OHOS
