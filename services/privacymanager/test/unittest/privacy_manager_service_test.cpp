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

#include "accesstoken_kit.h"
#include "audio_policy_manager.h"
#include "camera_manager_privacy_client.h"
#include "constant.h"
#include "data_translator.h"
#include "field_const.h"
#define private public
#include "permission_record_manager.h"
#include "permission_used_record_db.h"
#undef private
#include "perm_active_status_change_callback_stub.h"
#include "privacy_error.h"
#include "privacy_manager_service.h"
#include "string_ex.h"
#include "token_setproc.h"

using namespace testing::ext;

namespace OHOS {
namespace Security {
namespace AccessToken {
namespace {
static constexpr int32_t PERMISSION_USAGE_RECORDS_MAX_NUM = 10;
static constexpr uint32_t MAX_CALLBACK_SIZE = 200;
constexpr const char* CAMERA_PERMISSION_NAME = "ohos.permission.CAMERA";
constexpr const char* MICROPHONE_PERMISSION_NAME = "ohos.permission.MICROPHONE";
constexpr const char* LOCATION_PERMISSION_NAME = "ohos.permission.LOCATION";
static PermissionStateFull g_testState = {
    .permissionName = "ohos.permission.CAMERA",
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

static HapPolicyParams g_PolicyPrams2 = {
    .apl = APL_NORMAL,
    .domain = "test.domain.B",
    .permList = {},
    .permStateList = {g_testState}
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

class PrivacyManagerServiceTest : public testing::Test {
public:
    static void SetUpTestCase();

    static void TearDownTestCase();

    void SetUp();

    void TearDown();
    std::shared_ptr<PrivacyManagerService> privacyManagerService_;
    uint64_t selfTokenId_;
};

void PrivacyManagerServiceTest::SetUpTestCase()
{
}

void PrivacyManagerServiceTest::TearDownTestCase()
{
}

void PrivacyManagerServiceTest::SetUp()
{
    privacyManagerService_ = DelayedSingleton<PrivacyManagerService>::GetInstance();
    PermissionRecordManager::GetInstance().Register();
    EXPECT_NE(nullptr, privacyManagerService_);
    AccessTokenKit::AllocHapToken(g_InfoParms1, g_PolicyPrams1);
    AccessTokenKit::AllocHapToken(g_InfoParms2, g_PolicyPrams2);
    selfTokenId_ = GetSelfTokenID();
}

void PrivacyManagerServiceTest::TearDown()
{
    privacyManagerService_ = nullptr;
    AccessTokenID tokenId = AccessTokenKit::GetHapTokenID(g_InfoParms1.userID, g_InfoParms1.bundleName,
        g_InfoParms1.instIndex);
    AccessTokenKit::DeleteToken(tokenId);
    tokenId = AccessTokenKit::GetHapTokenID(g_InfoParms2.userID, g_InfoParms2.bundleName,
        g_InfoParms2.instIndex);
    AccessTokenKit::DeleteToken(tokenId);
    SetSelfTokenID(selfTokenId_);
}

/**
 * @tc.name: Dump001
 * @tc.desc: Dump record info.
 * @tc.type: FUNC
 * @tc.require: issueI4V02P
 */
HWTEST_F(PrivacyManagerServiceTest, Dump001, TestSize.Level1)
{
    int32_t fd = -1;
    std::vector<std::u16string> args;

    // fd is 0
    ASSERT_NE(RET_SUCCESS, privacyManagerService_->Dump(fd, args));

    fd = 1; // 1: std output

    // hidumper
    ASSERT_EQ(RET_SUCCESS, privacyManagerService_->Dump(fd, args));

    // hidumper -h
    args.emplace_back(Str8ToStr16("-h"));
    ASSERT_EQ(RET_SUCCESS, privacyManagerService_->Dump(fd, args));

    args.clear();
    // hidumper -t
    args.emplace_back(Str8ToStr16("-t"));
    ASSERT_NE(RET_SUCCESS, privacyManagerService_->Dump(fd, args));

    args.clear();
    // hidumper -t
    args.emplace_back(Str8ToStr16("-t"));
    args.emplace_back(Str8ToStr16("-1")); // illegal tokenId
    ASSERT_NE(RET_SUCCESS, privacyManagerService_->Dump(fd, args));

    args.clear();
    // hidumper -t
    args.emplace_back(Str8ToStr16("-s"));
    ASSERT_NE(RET_SUCCESS, privacyManagerService_->Dump(fd, args));

    args.clear();
    // hidumper -t
    args.emplace_back(Str8ToStr16("-t"));
    args.emplace_back(Str8ToStr16("123")); // 123: invalid tokenId
    ASSERT_EQ(RET_SUCCESS, privacyManagerService_->Dump(fd, args));
}

/**
 * @tc.name: Dump002
 * @tc.desc: Dump record info.
 * @tc.type: FUNC
 * @tc.require: issueI4V02P
 */
HWTEST_F(PrivacyManagerServiceTest, Dump002, TestSize.Level1)
{
    int32_t fd = 123; // 123: invalid fd
    std::vector<std::u16string> args;
    AccessTokenID tokenId = AccessTokenKit::GetHapTokenID(g_InfoParms1.userID, g_InfoParms1.bundleName,
        g_InfoParms1.instIndex);
    args.emplace_back(Str8ToStr16("-t"));
    std::string tokenIdStr = std::to_string(tokenId);
    args.emplace_back(Str8ToStr16(tokenIdStr));

    ASSERT_EQ(RET_SUCCESS, privacyManagerService_->Dump(fd, args));

    std::string permission = "ohos.permission.CAMERA";
    for (int32_t i = 0; i < PERMISSION_USAGE_RECORDS_MAX_NUM; i++) {
        privacyManagerService_->AddPermissionUsedRecord(tokenId, permission, 1, 0);
    }

    ASSERT_EQ(RET_SUCCESS, privacyManagerService_->Dump(fd, args));

    privacyManagerService_->AddPermissionUsedRecord(tokenId, permission, 1, 0);
    ASSERT_EQ(RET_SUCCESS, privacyManagerService_->Dump(fd, args));
}

class PermActiveStatusChangeCallback : public PermActiveStatusChangeCallbackStub {
public:
    PermActiveStatusChangeCallback() = default;
    virtual ~PermActiveStatusChangeCallback() = default;

    void ActiveStatusChangeCallback(ActiveChangeResponse& result) override;
};

void PermActiveStatusChangeCallback::ActiveStatusChangeCallback(ActiveChangeResponse& result)
{
}

/**
 * @tc.name: RegisterPermActiveStatusCallback001
 * @tc.desc: RegisterPermActiveStatusCallback with invalid parameter.
 * @tc.type: FUNC
 * @tc.require: issueI5RWX8
 */
HWTEST_F(PrivacyManagerServiceTest, RegisterPermActiveStatusCallback001, TestSize.Level1)
{
    std::vector<std::string> permList = {"ohos.permission.CAMERA"};
    ASSERT_EQ(PrivacyError::ERR_PARAM_INVALID,
            PermissionRecordManager::GetInstance().RegisterPermActiveStatusCallback(permList, nullptr));
}

/**
 * @tc.name: RegisterPermActiveStatusCallback002
 * @tc.desc: RegisterPermActiveStatusCallback with exceed limitation.
 * @tc.type: FUNC
 * @tc.require: issueI5RWX8
 */
HWTEST_F(PrivacyManagerServiceTest, RegisterPermActiveStatusCallback002, TestSize.Level1)
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
HWTEST_F(PrivacyManagerServiceTest, UnRegisterPermActiveStatusCallback001, TestSize.Level1)
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
HWTEST_F(PrivacyManagerServiceTest, AppStatusListener001, TestSize.Level1)
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
 * @tc.name: IsAllowedUsingPermission001
 * @tc.desc: IsAllowedUsingPermission function test permissionName branch
 * @tc.type: FUNC
 * @tc.require: issueI5UPRK
 */
HWTEST_F(PrivacyManagerServiceTest, IsAllowedUsingPermission001, TestSize.Level1)
{
    AccessTokenID tokenId = AccessTokenKit::GetNativeTokenId("privacy_service");
    ASSERT_NE(static_cast<AccessTokenID>(0), tokenId);
    SetSelfTokenID(tokenId);
    tokenId = AccessTokenKit::GetHapTokenID(g_InfoParms1.userID, g_InfoParms1.bundleName,
        g_InfoParms1.instIndex);
    ASSERT_NE(static_cast<AccessTokenID>(0), tokenId);
    PermissionRecordManager::GetInstance().NotifyCameraFloatWindowChange(tokenId, false);
    ASSERT_EQ(false, privacyManagerService_->IsAllowedUsingPermission(tokenId, CAMERA_PERMISSION_NAME));
    PermissionRecordManager::GetInstance().NotifyCameraFloatWindowChange(tokenId, true);
    ASSERT_EQ(true, privacyManagerService_->IsAllowedUsingPermission(tokenId, CAMERA_PERMISSION_NAME));
    ASSERT_EQ(false, privacyManagerService_->IsAllowedUsingPermission(tokenId, MICROPHONE_PERMISSION_NAME));
    ASSERT_EQ(false, privacyManagerService_->IsAllowedUsingPermission(tokenId, LOCATION_PERMISSION_NAME));
}

/*
 * @tc.name: IsAllowedUsingPermission002
 * @tc.desc: IsAllowedUsingPermission function test invalid tokenId
 * @tc.type: FUNC
 * @tc.require: issueI5UPRK
 */
HWTEST_F(PrivacyManagerServiceTest, IsAllowedUsingPermission002, TestSize.Level1)
{
    ASSERT_EQ(false, privacyManagerService_->IsAllowedUsingPermission(0, CAMERA_PERMISSION_NAME));
    ASSERT_EQ(false, privacyManagerService_->IsAllowedUsingPermission(0, "test"));
}

/*
 * @tc.name: GetGlobalSwitchStatus001
 * @tc.desc: GetGlobalSwitchStatus function test
 * @tc.type: FUNC
 * @tc.require: issueI5RWXF
 */
HWTEST_F(PrivacyManagerServiceTest, GetGlobalSwitchStatus001, TestSize.Level1)
{
    bool isMuteMic = AudioStandard::AudioSystemManager::GetInstance()->IsMicrophoneMute();
    OHOS::AudioStandard::AudioSystemManager::GetInstance()->SetMicrophoneMute(false); // false means open
    ASSERT_EQ(false, AudioStandard::AudioSystemManager::GetInstance()->IsMicrophoneMute());
    ASSERT_EQ(true, PermissionRecordManager::GetInstance().GetGlobalSwitchStatus(MICROPHONE_PERMISSION_NAME));
    OHOS::AudioStandard::AudioSystemManager::GetInstance()->SetMicrophoneMute(isMuteMic);

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
HWTEST_F(PrivacyManagerServiceTest, ShowGlobalDialog001, TestSize.Level1)
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
HWTEST_F(PrivacyManagerServiceTest, MicSwitchChangeListener001, TestSize.Level1)
{
    OHOS::AudioStandard::AudioSystemManager::GetInstance()->SetMicrophoneMute(false); // false means open
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
HWTEST_F(PrivacyManagerServiceTest, MicSwitchChangeListener002, TestSize.Level1)
{
    OHOS::AudioStandard::AudioSystemManager::GetInstance()->SetMicrophoneMute(false); // false means open
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
HWTEST_F(PrivacyManagerServiceTest, MicSwitchChangeListener003, TestSize.Level1)
{
    OHOS::AudioStandard::AudioSystemManager::GetInstance()->SetMicrophoneMute(true); // true means close
    AccessTokenID tokenId = AccessTokenKit::GetHapTokenID(g_InfoParms1.userID, g_InfoParms1.bundleName,
        g_InfoParms1.instIndex);
    // status is inactive
    ASSERT_EQ(0, PermissionRecordManager::GetInstance().StartUsingPermission(tokenId, MICROPHONE_PERMISSION_NAME));
    sleep(3); // wait for dialog disappear
    PermissionRecordManager::GetInstance().NotifyMicChange(true); // fill true status is inactive branch
    ASSERT_EQ(0, PermissionRecordManager::GetInstance().StopUsingPermission(tokenId, MICROPHONE_PERMISSION_NAME));
}

/*
 * @tc.name: MicSwitchChangeListener004
 * @tc.desc: NotifyMicChange function test mic global switch is open
 * @tc.type: FUNC
 * @tc.require: issueI5RWXF
 */
HWTEST_F(PrivacyManagerServiceTest, MicSwitchChangeListener004, TestSize.Level1)
{
    std::vector<GenericValues> values;
    PermissionUsedRecordDb::DataType type = PermissionUsedRecordDb::PERMISSION_RECORD;
    PermissionUsedRecordDb::GetInstance().Add(type, values);
}

/*
 * @tc.name: MicSwitchChangeListener005
 * @tc.desc: NotifyMicChange function test mic global switch is close
 * @tc.type: FUNC
 * @tc.require: issueI5RWXF
 */
HWTEST_F(PrivacyManagerServiceTest, MicSwitchChangeListener005, TestSize.Level1)
{
    OHOS::AudioStandard::AudioSystemManager::GetInstance()->SetMicrophoneMute(true); // true means close
    AccessTokenID tokenId = AccessTokenKit::GetHapTokenID(g_InfoParms1.userID, g_InfoParms1.bundleName,
        g_InfoParms1.instIndex);
    // status is inactive
    ASSERT_EQ(0, PermissionRecordManager::GetInstance().StartUsingPermission(tokenId, MICROPHONE_PERMISSION_NAME));
    sleep(3); // wait for dialog disappear
    PermissionRecordManager::GetInstance().NotifyMicChange(false); // fill false status is inactive branch
    ASSERT_EQ(0, PermissionRecordManager::GetInstance().StopUsingPermission(tokenId, MICROPHONE_PERMISSION_NAME));
    OHOS::AudioStandard::AudioSystemManager::GetInstance()->SetMicrophoneMute(false); // false means open
}

/*
 * @tc.name: Add001
 * @tc.desc: PermissionUsedRecordDb::Add function test miss not null field
 * @tc.type: FUNC
 * @tc.require: issueI5YL6H
 */
HWTEST_F(PrivacyManagerServiceTest, Add001, TestSize.Level1)
{
    GenericValues value1;
    value1.Put(FIELD_TOKEN_ID, 0);
    value1.Put(FIELD_OP_CODE, Constant::OP_MICROPHONE);
    value1.Put(FIELD_STATUS, ActiveChangeType::PERM_ACTIVE_IN_FOREGROUND);
    value1.Put(FIELD_TIMESTAMP, 123); // 123 is random input
    value1.Put(FIELD_REJECT_COUNT, 0);

    GenericValues value2;
    value2.Put(FIELD_TOKEN_ID, 0);
    value2.Put(FIELD_OP_CODE, Constant::OP_MICROPHONE);
    value2.Put(FIELD_STATUS, ActiveChangeType::PERM_ACTIVE_IN_FOREGROUND);
    value1.Put(FIELD_TIMESTAMP, 123); // 123 is random input
    value1.Put(FIELD_ACCESS_COUNT, 1);

    PermissionUsedRecordDb::DataType type = PermissionUsedRecordDb::PERMISSION_RECORD;
    std::vector<GenericValues> values;
    values.emplace_back(value1);
    values.emplace_back(value2);
    ASSERT_NE(0, PermissionUsedRecordDb::GetInstance().Add(type, values));
}

/*
 * @tc.name: Add002
 * @tc.desc: PermissionUsedRecordDb::Add function test
 * @tc.type: FUNC
 * @tc.require: issueI5YL6H
 */
HWTEST_F(PrivacyManagerServiceTest, Add002, TestSize.Level1)
{
    GenericValues value1;
    value1.Put(FIELD_TOKEN_ID, 0);
    value1.Put(FIELD_OP_CODE, Constant::OP_MICROPHONE);
    value1.Put(FIELD_STATUS, ActiveChangeType::PERM_ACTIVE_IN_FOREGROUND);
    value1.Put(FIELD_TIMESTAMP, 123); // 123 is random input
    value1.Put(FIELD_ACCESS_DURATION, 123); // 123 is random input
    value1.Put(FIELD_ACCESS_COUNT, 1);
    value1.Put(FIELD_REJECT_COUNT, 0);

    GenericValues value2;
    value2.Put(FIELD_TOKEN_ID, 1);
    value2.Put(FIELD_OP_CODE, Constant::OP_MICROPHONE);
    value2.Put(FIELD_STATUS, ActiveChangeType::PERM_ACTIVE_IN_FOREGROUND);
    value1.Put(FIELD_TIMESTAMP, 123); // 123 is random input
    value1.Put(FIELD_ACCESS_DURATION, 123); // 123 is random input
    value1.Put(FIELD_ACCESS_COUNT, 1);
    value1.Put(FIELD_REJECT_COUNT, 0);

    PermissionUsedRecordDb::DataType type = PermissionUsedRecordDb::PERMISSION_RECORD;
    std::vector<GenericValues> values;
    values.emplace_back(value1);
    values.emplace_back(value2);
    ASSERT_EQ(0, PermissionUsedRecordDb::GetInstance().Add(type, values));
    ASSERT_EQ(0, PermissionUsedRecordDb::GetInstance().Remove(type, value1));
    ASSERT_EQ(0, PermissionUsedRecordDb::GetInstance().Remove(type, value2));
}

/*
 * @tc.name: Modify001
 * @tc.desc: PermissionUsedRecordDb::Modify function test
 * @tc.type: FUNC
 * @tc.require: issueI5YL6H
 */
HWTEST_F(PrivacyManagerServiceTest, Modify001, TestSize.Level1)
{
    GenericValues modifyValues;
    modifyValues.Put(FIELD_STATUS, ActiveChangeType::PERM_ACTIVE_IN_FOREGROUND);

    GenericValues conditions;
    conditions.Put(FIELD_TOKEN_ID, 0);
    conditions.Put(FIELD_OP_CODE, Constant::OP_MICROPHONE);
    conditions.Put(FIELD_STATUS, ActiveChangeType::PERM_ACTIVE_IN_FOREGROUND);
    conditions.Put(FIELD_ACCESS_COUNT, 1);

    PermissionUsedRecordDb::DataType type = PermissionUsedRecordDb::PERMISSION_RECORD;
    ASSERT_EQ(0, PermissionUsedRecordDb::GetInstance().Modify(type, modifyValues, conditions));
}

/*
 * @tc.name: FindByConditions001
 * @tc.desc: PermissionUsedRecordDb::FindByConditions function test
 * @tc.type: FUNC
 * @tc.require: issueI5YL6H
 */
HWTEST_F(PrivacyManagerServiceTest, FindByConditions001, TestSize.Level1)
{
    GenericValues value;
    value.Put(FIELD_TOKEN_ID, 0);
    value.Put(FIELD_OP_CODE, Constant::OP_MICROPHONE);
    value.Put(FIELD_STATUS, ActiveChangeType::PERM_ACTIVE_IN_FOREGROUND);
    value.Put(FIELD_TIMESTAMP, 123); // 123 is random input
    value.Put(FIELD_ACCESS_DURATION, 123); // 123 is random input
    value.Put(FIELD_ACCESS_COUNT, 1);
    value.Put(FIELD_REJECT_COUNT, 0);

    PermissionUsedRecordDb::DataType type = PermissionUsedRecordDb::PERMISSION_RECORD;
    std::vector<GenericValues> values;
    values.emplace_back(value);
    ASSERT_EQ(0, PermissionUsedRecordDb::GetInstance().Add(type, values));

    GenericValues orConditions;
    std::vector<GenericValues> results;

    GenericValues andConditions; // no column
    ASSERT_EQ(0, PermissionUsedRecordDb::GetInstance().FindByConditions(type, andConditions, orConditions, results));

    GenericValues andConditions1; // field timestamp
    andConditions1.Put(FIELD_TIMESTAMP, 0);

    ASSERT_EQ(0, PermissionUsedRecordDb::GetInstance().FindByConditions(type, andConditions1, orConditions, results));

    GenericValues andConditions2; // field access_duration
    andConditions2.Put(FIELD_ACCESS_DURATION, 0);
    ASSERT_EQ(0, PermissionUsedRecordDb::GetInstance().FindByConditions(type, andConditions2, orConditions, results));

    GenericValues andConditions3; // field not timestamp or access_duration
    andConditions3.Put(FIELD_STATUS, ActiveChangeType::PERM_ACTIVE_IN_FOREGROUND);
    ASSERT_EQ(0, PermissionUsedRecordDb::GetInstance().FindByConditions(type, andConditions3, orConditions, results));

    ASSERT_EQ(0, PermissionUsedRecordDb::GetInstance().Remove(type, value));
}

/*
 * @tc.name: GetDistinctValue001
 * @tc.desc: PermissionUsedRecordDb::GetDistinctValue function test no column
 * @tc.type: FUNC
 * @tc.require: issueI5YL6H
 */
HWTEST_F(PrivacyManagerServiceTest, GetDistinctValue001, TestSize.Level1)
{
    PermissionUsedRecordDb::DataType type = PermissionUsedRecordDb::PERMISSION_RECORD;
    std::string condition;
    std::vector<GenericValues> results;
    ASSERT_EQ(0, PermissionUsedRecordDb::GetInstance().GetDistinctValue(type, condition, results));
}

/*
 * @tc.name: GetDistinctValue002
 * @tc.desc: PermissionUsedRecordDb::GetDistinctValue function test field token_id
 * @tc.type: FUNC
 * @tc.require: issueI5YL6H
 */
HWTEST_F(PrivacyManagerServiceTest, GetDistinctValue002, TestSize.Level1)
{
    GenericValues value;
    value.Put(FIELD_TOKEN_ID, 0);
    value.Put(FIELD_OP_CODE, Constant::OP_MICROPHONE);
    value.Put(FIELD_STATUS, ActiveChangeType::PERM_ACTIVE_IN_FOREGROUND);
    value.Put(FIELD_TIMESTAMP, 123); // 123 is random input
    value.Put(FIELD_ACCESS_DURATION, 123); // 123 is random input
    value.Put(FIELD_ACCESS_COUNT, 1);
    value.Put(FIELD_REJECT_COUNT, 0);

    PermissionUsedRecordDb::DataType type = PermissionUsedRecordDb::PERMISSION_RECORD;
    std::vector<GenericValues> values;
    values.emplace_back(value);
    ASSERT_EQ(0, PermissionUsedRecordDb::GetInstance().Add(type, values));

    std::string condition = FIELD_TOKEN_ID;
    std::vector<GenericValues> results;
    ASSERT_EQ(0, PermissionUsedRecordDb::GetInstance().GetDistinctValue(type, condition, results));
    results.clear();

    condition = FIELD_TIMESTAMP;
    ASSERT_EQ(0, PermissionUsedRecordDb::GetInstance().GetDistinctValue(type, condition, results));
    ASSERT_EQ(0, PermissionUsedRecordDb::GetInstance().Remove(type, value));
}

/*
 * @tc.name: DeleteExpireRecords001
 * @tc.desc: PermissionUsedRecordDb::DeleteExpireRecords function test andColumns empty
 * @tc.type: FUNC
 * @tc.require: issueI5YL6H
 */
HWTEST_F(PrivacyManagerServiceTest, DeleteExpireRecords001, TestSize.Level1)
{
    PermissionUsedRecordDb::DataType type = PermissionUsedRecordDb::PERMISSION_RECORD;
    GenericValues andConditions;
    ASSERT_EQ(0, PermissionUsedRecordDb::GetInstance().DeleteExpireRecords(type, andConditions));
}

/*
 * @tc.name: DeleteExcessiveRecords001
 * @tc.desc: PermissionUsedRecordDb::DeleteExcessiveRecords function test
 * @tc.type: FUNC
 * @tc.require: issueI5YL6H
 */
HWTEST_F(PrivacyManagerServiceTest, DeleteExcessiveRecords001, TestSize.Level1)
{
    PermissionUsedRecordDb::DataType type = PermissionUsedRecordDb::PERMISSION_RECORD;
    uint32_t excessiveSize = 10;
    ASSERT_EQ(0, PermissionUsedRecordDb::GetInstance().DeleteExcessiveRecords(type, excessiveSize));
}

/*
 * @tc.name: CreateInsertPrepareSqlCmd001
 * @tc.desc: PermissionUsedRecordDb::CreateInsertPrepareSqlCmd function test type not found
 * @tc.type: FUNC
 * @tc.require: issueI5YL6H
 */
HWTEST_F(PrivacyManagerServiceTest, CreateInsertPrepareSqlCmd001, TestSize.Level1)
{
    PermissionUsedRecordDb::DataType type = static_cast<PermissionUsedRecordDb::DataType>(100);
    ASSERT_EQ("", PermissionUsedRecordDb::GetInstance().CreateInsertPrepareSqlCmd(type));
}

/*
 * @tc.name: CreateInsertPrepareSqlCmd002
 * @tc.desc: PermissionUsedRecordDb::CreateInsertPrepareSqlCmd function test
 * @tc.type: FUNC
 * @tc.require: issueI5YL6H
 */
HWTEST_F(PrivacyManagerServiceTest, CreateInsertPrepareSqlCmd002, TestSize.Level1)
{
    PermissionUsedRecordDb::DataType type = PermissionUsedRecordDb::PERMISSION_RECORD;
    ASSERT_NE("", PermissionUsedRecordDb::GetInstance().CreateInsertPrepareSqlCmd(type));
}

/*
 * @tc.name: CreateDeletePrepareSqlCmd001
 * @tc.desc: PermissionUsedRecordDb::CreateDeletePrepareSqlCmd function test type not found
 * @tc.type: FUNC
 * @tc.require: issueI5YL6H
 */
HWTEST_F(PrivacyManagerServiceTest, CreateDeletePrepareSqlCmd001, TestSize.Level1)
{
    PermissionUsedRecordDb::DataType type = static_cast<PermissionUsedRecordDb::DataType>(100);
    std::vector<std::string> columnNames;
    ASSERT_EQ("", PermissionUsedRecordDb::GetInstance().CreateDeletePrepareSqlCmd(type, columnNames));
}

/*
 * @tc.name: CreateUpdatePrepareSqlCmd001
 * @tc.desc: PermissionUsedRecordDb::CreateUpdatePrepareSqlCmd function test modifyColumns empty
 * @tc.type: FUNC
 * @tc.require: issueI5YL6H
 */
HWTEST_F(PrivacyManagerServiceTest, CreateUpdatePrepareSqlCmd001, TestSize.Level1)
{
    PermissionUsedRecordDb::DataType type = PermissionUsedRecordDb::PERMISSION_RECORD;
    std::vector<std::string> modifyColumns;
    std::vector<std::string> conditionColumns;
    ASSERT_EQ("", PermissionUsedRecordDb::GetInstance().CreateUpdatePrepareSqlCmd(type, modifyColumns,
        conditionColumns));
}

/*
 * @tc.name: CreateUpdatePrepareSqlCmd002
 * @tc.desc: PermissionUsedRecordDb::CreateUpdatePrepareSqlCmd function test type not found
 * @tc.type: FUNC
 * @tc.require: issueI5YL6H
 */
HWTEST_F(PrivacyManagerServiceTest, CreateUpdatePrepareSqlCmd002, TestSize.Level1)
{
    PermissionUsedRecordDb::DataType type = static_cast<PermissionUsedRecordDb::DataType>(100);
    std::vector<std::string> modifyColumns;
    modifyColumns.emplace_back(FIELD_TOKEN_ID);
    std::vector<std::string> conditionColumns;
    ASSERT_EQ("", PermissionUsedRecordDb::GetInstance().CreateUpdatePrepareSqlCmd(type, modifyColumns,
        conditionColumns));
}

/*
 * @tc.name: CreateUpdatePrepareSqlCmd003
 * @tc.desc: PermissionUsedRecordDb::CreateUpdatePrepareSqlCmd function test conditionColumns empty
 * @tc.type: FUNC
 * @tc.require: issueI5YL6H
 */
HWTEST_F(PrivacyManagerServiceTest, CreateUpdatePrepareSqlCmd003, TestSize.Level1)
{
    PermissionUsedRecordDb::DataType type = PermissionUsedRecordDb::PERMISSION_RECORD;
    std::vector<std::string> modifyColumns;
    modifyColumns.emplace_back(FIELD_TOKEN_ID);
    modifyColumns.emplace_back(FIELD_TIMESTAMP);
    std::vector<std::string> conditionColumns;
    ASSERT_NE("", PermissionUsedRecordDb::GetInstance().CreateUpdatePrepareSqlCmd(type, modifyColumns,
        conditionColumns));
}

/*
 * @tc.name: CreateUpdatePrepareSqlCmd004
 * @tc.desc: PermissionUsedRecordDb::CreateUpdatePrepareSqlCmd function test conditionColumns empty
 * @tc.type: FUNC
 * @tc.require: issueI5YL6H
 */
HWTEST_F(PrivacyManagerServiceTest, CreateUpdatePrepareSqlCmd004, TestSize.Level1)
{
    PermissionUsedRecordDb::DataType type = PermissionUsedRecordDb::PERMISSION_RECORD;
    std::vector<std::string> modifyColumns;
    modifyColumns.emplace_back(FIELD_TOKEN_ID);
    modifyColumns.emplace_back(FIELD_TIMESTAMP);
    std::vector<std::string> conditionColumns;
    ASSERT_NE("", PermissionUsedRecordDb::GetInstance().CreateUpdatePrepareSqlCmd(type, modifyColumns,
        conditionColumns));
}

/*
 * @tc.name: CreateUpdatePrepareSqlCmd005
 * @tc.desc: PermissionUsedRecordDb::CreateUpdatePrepareSqlCmd function test
 * @tc.type: FUNC
 * @tc.require: issueI5YL6H
 */
HWTEST_F(PrivacyManagerServiceTest, CreateUpdatePrepareSqlCmd005, TestSize.Level1)
{
    PermissionUsedRecordDb::DataType type = PermissionUsedRecordDb::PERMISSION_RECORD;
    std::vector<std::string> modifyColumns;
    modifyColumns.emplace_back(FIELD_TOKEN_ID);
    modifyColumns.emplace_back(FIELD_TIMESTAMP);
    std::vector<std::string> conditionColumns;
    modifyColumns.emplace_back(FIELD_STATUS);
    ASSERT_NE("", PermissionUsedRecordDb::GetInstance().CreateUpdatePrepareSqlCmd(type, modifyColumns,
        conditionColumns));
}

/*
 * @tc.name: CreateSelectByConditionPrepareSqlCmd001
 * @tc.desc: PermissionUsedRecordDb::CreateSelectByConditionPrepareSqlCmd function test type not found
 * @tc.type: FUNC
 * @tc.require: issueI5YL6H
 */
HWTEST_F(PrivacyManagerServiceTest, CreateSelectByConditionPrepareSqlCmd001, TestSize.Level1)
{
    PermissionUsedRecordDb::DataType type = static_cast<PermissionUsedRecordDb::DataType>(100);
    std::vector<std::string> andColumns;
    std::vector<std::string> orColumns;
    ASSERT_EQ("", PermissionUsedRecordDb::GetInstance().CreateSelectByConditionPrepareSqlCmd(type, andColumns,
        orColumns));
}

/*
 * @tc.name: CreateSelectByConditionPrepareSqlCmd002
 * @tc.desc: PermissionUsedRecordDb::CreateSelectByConditionPrepareSqlCmd function test
 * @tc.type: FUNC
 * @tc.require: issueI5YL6H
 */
HWTEST_F(PrivacyManagerServiceTest, CreateSelectByConditionPrepareSqlCmd002, TestSize.Level1)
{
    PermissionUsedRecordDb::DataType type = PermissionUsedRecordDb::PERMISSION_RECORD;
    std::vector<std::string> andColumns;
    andColumns.emplace_back(FIELD_TIMESTAMP_BEGIN);
    std::vector<std::string> orColumns;
    orColumns.emplace_back(FIELD_TIMESTAMP);
    ASSERT_NE("", PermissionUsedRecordDb::GetInstance().CreateSelectByConditionPrepareSqlCmd(type, andColumns,
        orColumns));
}

/*
 * @tc.name: CreateCountPrepareSqlCmd001
 * @tc.desc: PermissionUsedRecordDb::CreateCountPrepareSqlCmd function test type not found
 * @tc.type: FUNC
 * @tc.require: issueI5YL6H
 */
HWTEST_F(PrivacyManagerServiceTest, CreateCountPrepareSqlCmd001, TestSize.Level1)
{
    PermissionUsedRecordDb::DataType type = static_cast<PermissionUsedRecordDb::DataType>(100);
    ASSERT_EQ("", PermissionUsedRecordDb::GetInstance().CreateCountPrepareSqlCmd(type));
}

/*
 * @tc.name: CreateDeleteExpireRecordsPrepareSqlCmd001
 * @tc.desc: PermissionUsedRecordDb::CreateDeleteExpireRecordsPrepareSqlCmd function test
 * @tc.type: FUNC
 * @tc.require: issueI5YL6H
 */
HWTEST_F(PrivacyManagerServiceTest, CreateDeleteExpireRecordsPrepareSqlCmd001, TestSize.Level1)
{
    PermissionUsedRecordDb::DataType type = static_cast<PermissionUsedRecordDb::DataType>(100); // type not found
    std::vector<std::string> andColumns;
    ASSERT_EQ("", PermissionUsedRecordDb::GetInstance().CreateDeleteExpireRecordsPrepareSqlCmd(type, andColumns));

    type = PermissionUsedRecordDb::PERMISSION_RECORD; // field timestamp_begin and timestamp_end
    andColumns.emplace_back(FIELD_TIMESTAMP_BEGIN);
    andColumns.emplace_back(FIELD_TIMESTAMP_END);
    ASSERT_NE("", PermissionUsedRecordDb::GetInstance().CreateDeleteExpireRecordsPrepareSqlCmd(type, andColumns));
}

/*
 * @tc.name: CreateDeleteExcessiveRecordsPrepareSqlCmd001
 * @tc.desc: PermissionUsedRecordDb::CreateDeleteExcessiveRecordsPrepareSqlCmd function test type not found
 * @tc.type: FUNC
 * @tc.require: issueI5YL6H
 */
HWTEST_F(PrivacyManagerServiceTest, CreateDeleteExcessiveRecordsPrepareSqlCmd001, TestSize.Level1)
{
    PermissionUsedRecordDb::DataType type = static_cast<PermissionUsedRecordDb::DataType>(100);
    uint32_t excessiveSize = 10;
    ASSERT_EQ("", PermissionUsedRecordDb::GetInstance().CreateDeleteExcessiveRecordsPrepareSqlCmd(type, excessiveSize));
}

/*
 * @tc.name: CreateDeleteExcessiveRecordsPrepareSqlCmd002
 * @tc.desc: PermissionUsedRecordDb::CreateDeleteExcessiveRecordsPrepareSqlCmd function test
 * @tc.type: FUNC
 * @tc.require: issueI5YL6H
 */
HWTEST_F(PrivacyManagerServiceTest, CreateDeleteExcessiveRecordsPrepareSqlCmd002, TestSize.Level1)
{
    PermissionUsedRecordDb::DataType type = PermissionUsedRecordDb::PERMISSION_RECORD;
    uint32_t excessiveSize = 10;
    ASSERT_NE("", PermissionUsedRecordDb::GetInstance().CreateDeleteExcessiveRecordsPrepareSqlCmd(type, excessiveSize));
}

/*
 * @tc.name: CreateGetDistinctValue001
 * @tc.desc: PermissionUsedRecordDb::CreateGetDistinctValue function test type not found
 * @tc.type: FUNC
 * @tc.require: issueI5YL6H
 */
HWTEST_F(PrivacyManagerServiceTest, CreateGetDistinctValue001, TestSize.Level1)
{
    PermissionUsedRecordDb::DataType type = static_cast<PermissionUsedRecordDb::DataType>(100);
    std::string conditionColumns;
    ASSERT_EQ("", PermissionUsedRecordDb::GetInstance().CreateGetDistinctValue(type, conditionColumns));
}

/*
 * @tc.name: CreatePermissionRecordTable001
 * @tc.desc: PermissionUsedRecordDb::CreatePermissionRecordTable function test
 * @tc.type: FUNC
 * @tc.require: issueI5YL6H
 */
HWTEST_F(PrivacyManagerServiceTest, CreatePermissionRecordTable001, TestSize.Level1)
{
    ASSERT_EQ(0, PermissionUsedRecordDb::GetInstance().CreatePermissionRecordTable());
}

/*
 * @tc.name: TransferOpcodeToPermission001
 * @tc.desc: Constant::TransferOpcodeToPermission function test return false
 * @tc.type: FUNC
 * @tc.require: issueI6024A
 */
HWTEST_F(PrivacyManagerServiceTest, TransferOpcodeToPermission001, TestSize.Level1)
{
    int32_t opCode = static_cast<int32_t>(Constant::OpCode::OP_INVALID);
    std::string permissionName;
    ASSERT_EQ(false, Constant::TransferOpcodeToPermission(opCode, permissionName));
}

/*
 * @tc.name: OnCameraMute001
 * @tc.desc: CameraServiceCallbackStub::OnCameraMute function test callback_ is null
 * @tc.type: FUNC
 * @tc.require: issueI6024A
 */
HWTEST_F(PrivacyManagerServiceTest, OnCameraMute001, TestSize.Level1)
{
    bool muteMode = false;
    ASSERT_EQ(false, muteMode);

    std::shared_ptr<CameraServiceCallbackStub> callback = std::make_shared<CameraServiceCallbackStub>(
        CameraServiceCallbackStub());
    callback->OnCameraMute(muteMode);
}

/*
 * @tc.name: OnMicStateUpdated001
 * @tc.desc: MicGlobalSwitchChangeCallback::OnMicStateUpdated function test callback_ is null
 * @tc.type: FUNC
 * @tc.require: issueI6024A
 */
HWTEST_F(PrivacyManagerServiceTest, OnMicStateUpdated001, TestSize.Level1)
{
    AudioStandard::MicStateChangeEvent micStateChangeEvent;
    micStateChangeEvent.mute = false;
    ASSERT_EQ(false, micStateChangeEvent.mute);

    std::shared_ptr<MicGlobalSwitchChangeCallback> callback = std::make_shared<MicGlobalSwitchChangeCallback>(
        MicGlobalSwitchChangeCallback());
    callback->OnMicStateUpdated(micStateChangeEvent);
}

/*
 * @tc.name: TranslationIntoGenericValues001
 * @tc.desc: DataTranslator::TranslationIntoGenericValues function test
 * @tc.type: FUNC
 * @tc.require: issueI6024A
 */
HWTEST_F(PrivacyManagerServiceTest, TranslationIntoGenericValues001, TestSize.Level1)
{
    PermissionUsedRequest request = {
        .beginTimeMillis = -1, // begin < 0
        .endTimeMillis = -2 // end < 0
    };
    GenericValues andGenericValues;
    GenericValues orGenericValues;
    ASSERT_EQ(Constant::FAILURE,
        DataTranslator::TranslationIntoGenericValues(request, andGenericValues, orGenericValues));

    request.beginTimeMillis = 10; // begin != 0
    request.endTimeMillis = 20; // end != 0
    request.flag = static_cast<PermissionUsageFlag>(2); // request.flag != FLAG_PERMISSION_USAGE_DETAIL
    ASSERT_EQ(Constant::FAILURE,
        DataTranslator::TranslationIntoGenericValues(request, andGenericValues, orGenericValues));

    request.flag = FLAG_PERMISSION_USAGE_DETAIL;
    request.permissionList.emplace_back("ohos.com.CAMERA"); // Constant::TransferPermissionToOpcode(perm, opCode) true
    ASSERT_EQ(Constant::SUCCESS,
        DataTranslator::TranslationIntoGenericValues(request, andGenericValues, orGenericValues));
}

/*
 * @tc.name: TranslationGenericValuesIntoPermissionUsedRecord001
 * @tc.desc: DataTranslator::TranslationGenericValuesIntoPermissionUsedRecord function test
 * @tc.type: FUNC
 * @tc.require: issueI6024A
 */
HWTEST_F(PrivacyManagerServiceTest, TranslationGenericValuesIntoPermissionUsedRecord001, TestSize.Level1)
{
    GenericValues inGenericValues;
    // !Constant::TransferOpcodeToPermission(opCode, permission) false
    inGenericValues.Put(FIELD_OP_CODE, static_cast<int32_t>(Constant::OpCode::OP_CAMERA));
    PermissionUsedRecord permissionRecord;
    permissionRecord.lastAccessTime = 0; // permissionRecord.lastAccessTime > 0 false
    permissionRecord.lastRejectTime = 10; // permissionRecord.lastRejectTime > 0
    ASSERT_EQ(Constant::SUCCESS,
        DataTranslator::TranslationGenericValuesIntoPermissionUsedRecord(inGenericValues, permissionRecord));
}

/*
 * @tc.name: OnForegroundApplicationChanged001
 * @tc.desc: ApplicationStatusChangeCallback::OnForegroundApplicationChanged function test
 * @tc.type: FUNC
 * @tc.require: issueI60IB3
 */
HWTEST_F(PrivacyManagerServiceTest, OnForegroundApplicationChanged001, TestSize.Level1)
{
    OHOS::AppExecFwk::AppStateData appStateData;
    appStateData.bundleName = "com.ohos.photo";
    appStateData.uid = 0;
    appStateData.state = static_cast<int32_t>(AppExecFwk::ApplicationState::APP_STATE_FOREGROUND);
    ASSERT_EQ(0, appStateData.uid);

    sptr<ApplicationStatusChangeCallback> callback = new (std::nothrow) ApplicationStatusChangeCallback();
    callback->OnForegroundApplicationChanged(appStateData); // state == APP_STATE_FOREGROUND

    appStateData.state = static_cast<int32_t>(AppExecFwk::ApplicationState::APP_STATE_BACKGROUND);
    callback->OnForegroundApplicationChanged(appStateData); // state == APP_STATE_BACKGROUND
}
} // namespace AccessToken
} // namespace Security
} // namespace OHOS
