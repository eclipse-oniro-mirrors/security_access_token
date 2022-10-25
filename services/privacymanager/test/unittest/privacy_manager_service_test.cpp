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
#include "constant.h"
#define private public
#include "permission_record_manager.h"
#undef private
#include "perm_active_status_change_callback_stub.h"
#include "privacy_error.h"
#include "privacy_manager_service.h"
#include "sensitive_resource_manager.h"
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
 * @tc.desc: register and startusing permissions then use AppStatusListener
 * @tc.type: FUNC
 * @tc.require: issueI5SZHG
 */
HWTEST_F(PrivacyManagerServiceTest, AppStatusListener001, TestSize.Level1)
{
    AccessTokenID tokenId1 = AccessTokenKit::GetHapTokenID(g_InfoParms1.userID, g_InfoParms1.bundleName,
        g_InfoParms1.instIndex);
    ASSERT_NE(0, tokenId1);
    AccessTokenID tokenId2 = AccessTokenKit::GetHapTokenID(g_InfoParms2.userID, g_InfoParms2.bundleName,
        g_InfoParms2.instIndex);
    ASSERT_NE(0, tokenId2);

    g_recordA1.tokenId = tokenId1;
    g_recordA2.tokenId = tokenId1;
    g_recordB1.tokenId = tokenId2;
    g_recordB2.tokenId = tokenId2;
    PermissionRecordManager::GetInstance().startRecordList_.emplace_back(g_recordA1);
    PermissionRecordManager::GetInstance().startRecordList_.emplace_back(g_recordA2);
    PermissionRecordManager::GetInstance().startRecordList_.emplace_back(g_recordB1);
    PermissionRecordManager::GetInstance().startRecordList_.emplace_back(g_recordB2);

    PermissionRecordManager::AppStatusListener(tokenId1, APP_FOREGROUND);
    PermissionRecordManager::AppStatusListener(tokenId2, APP_FOREGROUND);
    PermissionRecordManager::AppStatusListener(tokenId1, APP_FOREGROUND);
    PermissionRecordManager::AppStatusListener(tokenId2, APP_FOREGROUND);
    PermissionRecordManager::AppStatusListener(tokenId1, APP_BACKGROUND);
    PermissionRecordManager::AppStatusListener(tokenId2, APP_BACKGROUND);
    PermissionRecordManager::AppStatusListener(tokenId1, APP_BACKGROUND);
    PermissionRecordManager::AppStatusListener(tokenId2, APP_BACKGROUND);
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
    ASSERT_NE(0, tokenId);
    SetSelfTokenID(tokenId);
    tokenId = AccessTokenKit::GetHapTokenID(g_InfoParms1.userID, g_InfoParms1.bundleName,
        g_InfoParms1.instIndex);
    ASSERT_NE(0, tokenId);
    ASSERT_EQ(false, privacyManagerService_->IsAllowedUsingPermission(tokenId, CAMERA_PERMISSION_NAME));
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
}

/*
 * @tc.name: GetGlobalSwitchStatus001
 * @tc.desc: GetGlobalSwitchStatus function test
 * @tc.type: FUNC
 * @tc.require: issueI5RWXF
 */
HWTEST_F(PrivacyManagerServiceTest, GetGlobalSwitchStatus001, TestSize.Level1)
{
    ASSERT_EQ(true, PermissionRecordManager::GetInstance().GetGlobalSwitchStatus(CAMERA_PERMISSION_NAME));

    // microphone is not sure
    ASSERT_EQ(true, PermissionRecordManager::GetInstance().GetGlobalSwitchStatus(LOCATION_PERMISSION_NAME));
}

/*
 * @tc.name: ShowPermissionDialog001
 * @tc.desc: ShowPermissionDialog function test
 * @tc.type: FUNC
 * @tc.require: issueI5RWXF
 */
HWTEST_F(PrivacyManagerServiceTest, ShowPermissionDialog001, TestSize.Level1)
{
    ASSERT_EQ(0, PermissionRecordManager::GetInstance().ShowPermissionDialog(CAMERA_PERMISSION_NAME));
    sleep(3); // wait for dialog disappear
    ASSERT_EQ(0, PermissionRecordManager::GetInstance().ShowPermissionDialog(MICROPHONE_PERMISSION_NAME));
    sleep(3); // wait for dialog disappear
    ASSERT_EQ(0, PermissionRecordManager::GetInstance().ShowPermissionDialog(LOCATION_PERMISSION_NAME)); // no dialog
}

/*
 * @tc.name: MicSwitchChangeListener001
 * @tc.desc: MicSwitchChangeListener function test mic global switch is open
 * @tc.type: FUNC
 * @tc.require: issueI5RWXF
 */
HWTEST_F(PrivacyManagerServiceTest, MicSwitchChangeListener001, TestSize.Level1)
{
    OHOS::AudioStandard::AudioSystemManager::GetInstance()->SetMicrophoneMute(false); // false means open
    AccessTokenID tokenId = AccessTokenKit::GetHapTokenID(g_InfoParms1.userID, g_InfoParms1.bundleName,
        g_InfoParms1.instIndex);
    ASSERT_EQ(0, PermissionRecordManager::GetInstance().StartUsingPermission(tokenId, CAMERA_PERMISSION_NAME));

    PermissionRecordManager::MicSwitchChangeListener(true); // fill opCode not mic branch
    ASSERT_EQ(0, PermissionRecordManager::GetInstance().StopUsingPermission(tokenId, CAMERA_PERMISSION_NAME));
}

/*
 * @tc.name: MicSwitchChangeListener002
 * @tc.desc: MicSwitchChangeListener function test mic global switch is open
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
    PermissionRecordManager::MicSwitchChangeListener(true); // fill true status is not inactive branch
    ASSERT_EQ(0, PermissionRecordManager::GetInstance().StopUsingPermission(tokenId, MICROPHONE_PERMISSION_NAME));
}

/*
 * @tc.name: MicSwitchChangeListener003
 * @tc.desc: MicSwitchChangeListener function test mic global switch is close
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
    PermissionRecordManager::MicSwitchChangeListener(true); // fill true status is inactive branch
    ASSERT_EQ(0, PermissionRecordManager::GetInstance().StopUsingPermission(tokenId, MICROPHONE_PERMISSION_NAME));
}

/*
 * @tc.name: MicSwitchChangeListener004
 * @tc.desc: MicSwitchChangeListener function test mic global switch is open
 * @tc.type: FUNC
 * @tc.require: issueI5RWXF
 */
HWTEST_F(PrivacyManagerServiceTest, MicSwitchChangeListener004, TestSize.Level1)
{
    OHOS::AudioStandard::AudioSystemManager::GetInstance()->SetMicrophoneMute(false); // false means open
    AccessTokenID tokenId = AccessTokenKit::GetHapTokenID(g_InfoParms1.userID, g_InfoParms1.bundleName,
        g_InfoParms1.instIndex);
    // status is background
    ASSERT_EQ(0, PermissionRecordManager::GetInstance().StartUsingPermission(tokenId, MICROPHONE_PERMISSION_NAME));
    PermissionRecordManager::MicSwitchChangeListener(false); // fill false status is not inactive branch
    ASSERT_EQ(0, PermissionRecordManager::GetInstance().StopUsingPermission(tokenId, MICROPHONE_PERMISSION_NAME));
}

/*
 * @tc.name: MicSwitchChangeListener005
 * @tc.desc: MicSwitchChangeListener function test mic global switch is close
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
    PermissionRecordManager::MicSwitchChangeListener(false); // fill false status is inactive branch
    ASSERT_EQ(0, PermissionRecordManager::GetInstance().StopUsingPermission(tokenId, MICROPHONE_PERMISSION_NAME));
    OHOS::AudioStandard::AudioSystemManager::GetInstance()->SetMicrophoneMute(false); // false means open
}
} // namespace AccessToken
} // namespace Security
} // namespace OHOS
