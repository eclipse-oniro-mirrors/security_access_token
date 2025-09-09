/*
 * Copyright (c) 2022-2025 Huawei Device Co., Ltd.
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
#include <string>

#include "access_token.h"
#include "accesstoken_kit.h"
#include "active_change_response_info.h"
#include "audio_manager_adapter.h"
#include "constant.h"
#include "data_translator.h"
#include "permission_record.h"
#define private public
#include "active_status_callback_manager.h"
#include "libraryloader.h"
#include "permission_record_manager.h"
#include "permission_used_record_db.h"
#include "privacy_manager_service.h"
#include "privacy_manager_proxy_death_param.h"
#include "proxy_death_callback_stub.h"
#undef private
#include "parameter.h"
#include "perm_active_status_change_callback_stub.h"
#include "privacy_error.h"
#include "privacy_field_const.h"
#include "privacy_kit.h"
#include "privacy_test_common.h"
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
static int32_t PID = -1;
static int32_t TEST_PID_1 = 1;
static int32_t TEST_PID_2 = 2;
static int32_t TEST_PID_3 = 3;
static constexpr int32_t CALLER_PID = 11;
static constexpr int32_t CALLER_PID2 = 12;
static AccessTokenID g_selfTokenId = 0;
static AccessTokenID g_nativeToken = 0;
static bool g_isMicEdmMute = false;
static bool g_isMicMixMute = false;
static bool g_isMicMute = false;
static constexpr int32_t TEST_USER_ID_10 = 10;
static constexpr int32_t TEST_INVALID_USER_ID = -1;
static constexpr int32_t TEST_INVALID_USER_ID_20000 = 20000;
static constexpr uint32_t MAX_CALLBACK_SIZE = 1024;
static constexpr uint32_t RANDOM_TOKENID = 123;
static constexpr int32_t FIRST_INDEX = 0;
static const int32_t NORMAL_TYPE_ADD_VALUE = 1;
static const int32_t PICKER_TYPE_ADD_VALUE = 2;
static const int32_t SEC_COMPONENT_TYPE_ADD_VALUE = 4;
static const int32_t VALUE_MAX_LEN = 32;
const static uint32_t TEST_MAX_PERMISSION_USED_TYPE_SIZE = 20;
static const char* EDM_MIC_MUTE_KEY = "persist.edm.mic_disable";
static MockNativeToken* g_mock = nullptr;
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

static PermissionStateFull g_testState4 = {
    .permissionName = "ohos.permission.CAMERA",
    .isGeneral = true,
    .resDeviceID = {"local"},
    .grantStatus = {PermissionState::PERMISSION_GRANTED},
    .grantFlags = {4}
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

static PreAuthorizationInfo g_preAuthInfo1 = {
    .permissionName = "ohos.permission.CAMERA",
    .userCancelable = false
};

static HapPolicyParams g_PolicyPrams3 = {
    .apl = APL_NORMAL,
    .domain = "test.domain.C",
    .permList = {},
    .permStateList = {g_testState4},
    .preAuthorizationInfo = {g_preAuthInfo1}
};

static HapInfoParams g_InfoParms3 = {
    .userID = 1,
    .bundleName = "ohos.privacy_test.bundleC",
    .instIndex = 0,
    .appIDDesc = "privacy_test.bundleC"
};
}
class PermissionRecordManagerTest : public testing::Test {
public:
    static void SetUpTestCase();

    static void TearDownTestCase();

    void SetUp();

    void TearDown();

    std::shared_ptr<PrivacyAppStateObserver> appStateObserver_ = nullptr;
};

void PermissionRecordManagerTest::SetUpTestCase()
{
    g_selfTokenId = GetSelfTokenID();
    PrivacyTestCommon::SetTestEvironment(g_selfTokenId);
    g_mock = new (std::nothrow) MockNativeToken("privacy_service");

    DelayedSingleton<PrivacyManagerService>::GetInstance()->Initialize();
    PermissionRecordManager::GetInstance().Init();

    g_nativeToken = PrivacyTestCommon::GetNativeTokenIdFromProcess("privacy_service");
    g_isMicEdmMute = PermissionRecordManager::GetInstance().isMicEdmMute_;
    g_isMicMixMute = PermissionRecordManager::GetInstance().isMicMixMute_;
    PermissionRecordManager::GetInstance().isMicEdmMute_ = false;
    PermissionRecordManager::GetInstance().isMicMixMute_ = false;
    g_isMicMute = AudioManagerAdapter::GetInstance().GetPersistentMicMuteState();
}

void PermissionRecordManagerTest::TearDownTestCase()
{
    PermissionRecordManager::GetInstance().isMicEdmMute_ = g_isMicEdmMute;
    PermissionRecordManager::GetInstance().isMicMixMute_ = g_isMicMixMute;
    PrivacyTestCommon::ResetTestEvironment();
    if (g_mock != nullptr) {
        delete g_mock;
        g_mock = nullptr;
    }
}

void PermissionRecordManagerTest::SetUp()
{
    PermissionRecordManager::GetInstance().Init();
    PermissionRecordManager::GetInstance().Register();

    AccessTokenIDEx tokenIdEx = PrivacyTestCommon::AllocTestHapToken(g_InfoParms1, g_PolicyPrams1);
    ASSERT_NE(tokenIdEx.tokenIdExStruct.tokenID, INVALID_TOKENID);
    tokenIdEx = PrivacyTestCommon::AllocTestHapToken(g_InfoParms2, g_PolicyPrams2);
    ASSERT_NE(tokenIdEx.tokenIdExStruct.tokenID, INVALID_TOKENID);
    PermissionRecordManager::GetInstance().SetMutePolicy(PolicyType::PRIVACY, CallerType::MICROPHONE, false,
        RANDOM_TOKENID);
    if (appStateObserver_ != nullptr) {
        return;
    }
    appStateObserver_ = std::make_shared<PrivacyAppStateObserver>();
}

void PermissionRecordManagerTest::TearDown()
{
    PermissionRecordManager::GetInstance().SetMutePolicy(PolicyType::PRIVACY, CallerType::MICROPHONE, g_isMicMute,
        RANDOM_TOKENID);
    AccessTokenIDEx tokenIdEx = PrivacyTestCommon::GetHapTokenIdFromBundle(g_InfoParms1.userID, g_InfoParms1.bundleName,
        g_InfoParms1.instIndex);
    PrivacyTestCommon::DeleteTestHapToken(tokenIdEx.tokenIdExStruct.tokenID);
    PrivacyKit::RemovePermissionUsedRecords(tokenIdEx.tokenIdExStruct.tokenID);
    tokenIdEx = PrivacyTestCommon::GetHapTokenIdFromBundle(g_InfoParms2.userID, g_InfoParms2.bundleName,
        g_InfoParms2.instIndex);
    PrivacyTestCommon::DeleteTestHapToken(tokenIdEx.tokenIdExStruct.tokenID);
    PrivacyKit::RemovePermissionUsedRecords(tokenIdEx.tokenIdExStruct.tokenID);
    appStateObserver_ = nullptr;
}

class PermissionRecordManagerTestCb1 : public StateCustomizedCbk {
public:
    PermissionRecordManagerTestCb1()
    {}

    ~PermissionRecordManagerTestCb1()
    {}

    void StateChangeNotify(AccessTokenID tokenId, bool isShow)
    {
        GTEST_LOG_(INFO) << "PermissionRecordManagerTestCb1 isShow" << isShow;
        isShow_ = isShow;
    }

    void Stop()
    {}

    bool isShow_ = true;
};

static PermissionUsedTypeInfo MakeInfo(AccessTokenID tokenId, int32_t pid, const std::string &permission,
    PermissionUsedType type = PermissionUsedType::NORMAL_TYPE)
{
    PermissionUsedTypeInfo info = {
        .tokenId = tokenId,
        .pid = pid,
        .permissionName = permission,
        .type = type
    };
    return info;
}

/**
 * @tc.name: RegisterPermActiveStatusCallback001
 * @tc.desc: RegisterPermActiveStatusCallback with invalid parameter.
 * @tc.type: FUNC
 * @tc.require: issueI5RWX8
 */
HWTEST_F(PermissionRecordManagerTest, RegisterPermActiveStatusCallback001, TestSize.Level0)
{
    std::vector<std::string> permList = {"ohos.permission.CAMERA"};
    ASSERT_EQ(PrivacyError::ERR_PARAM_INVALID, PermissionRecordManager::GetInstance().RegisterPermActiveStatusCallback(
        GetSelfTokenID(), permList, nullptr));
}


class PermActiveStatusChangeCallback : public PermActiveStatusChangeCallbackStub {
public:
    PermActiveStatusChangeCallback() = default;
    virtual ~PermActiveStatusChangeCallback() = default;

    bool AddDeathRecipient(const sptr<IRemoteObject::DeathRecipient>& deathRecipient) override
    {
        return true;
    }

    void ActiveStatusChangeCallback(ActiveChangeResponse& result) override
    {
        type_ = result.type;
        GTEST_LOG_(INFO) << "ActiveStatusChange tokenid " << result.tokenID <<
            ", permission " << result.permissionName << ", type " << result.type;
    }

    ActiveChangeType type_ = PERM_INACTIVE;
};

/**
 * @tc.name: RegisterPermActiveStatusCallback002
 * @tc.desc: RegisterPermActiveStatusCallback with exceed limitation.
 * @tc.type: FUNC
 * @tc.require: issueI5RWX8
 */
HWTEST_F(PermissionRecordManagerTest, RegisterPermActiveStatusCallback002, TestSize.Level0)
{
    std::vector<std::string> permList = {"ohos.permission.CAMERA"};
    std::vector<sptr<PermActiveStatusChangeCallback>> callbacks;

    for (size_t i = 0; i < MAX_CALLBACK_SIZE; ++i) {
        sptr<PermActiveStatusChangeCallback> callback = new (std::nothrow) PermActiveStatusChangeCallback();
        ASSERT_NE(nullptr, callback);
        ASSERT_EQ(RET_SUCCESS, PermissionRecordManager::GetInstance().RegisterPermActiveStatusCallback(
            GetSelfTokenID(), permList, callback->AsObject()));
        callbacks.emplace_back(callback);
    }

    sptr<PermActiveStatusChangeCallback> callback = new (std::nothrow) PermActiveStatusChangeCallback();
    ASSERT_NE(nullptr, callback);
    ASSERT_EQ(PrivacyError::ERR_CALLBACKS_EXCEED_LIMITATION,
        PermissionRecordManager::GetInstance().RegisterPermActiveStatusCallback(
            GetSelfTokenID(), permList, callback->AsObject()));

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
HWTEST_F(PermissionRecordManagerTest, UnRegisterPermActiveStatusCallback001, TestSize.Level0)
{
    std::vector<std::string> permList = {"ohos.permission.CAMERA"};
    ASSERT_EQ(PrivacyError::ERR_PARAM_INVALID, PermissionRecordManager::GetInstance().RegisterPermActiveStatusCallback(
        GetSelfTokenID(), permList, nullptr));
}

/*
 * @tc.name: StartUsingPermissionTest001
 * @tc.desc: StartUsingPermission function test with invaild tokenId.
 * @tc.type: FUNC
 * @tc.require: issueI5RWX5 issueI5RWX3 issueI5RWXA
 */
HWTEST_F(PermissionRecordManagerTest, StartUsingPermissionTest001, TestSize.Level0)
{
    std::string permissionName = "ohos.permission.CAMERA";
    auto callbackPtr = std::make_shared<PermissionRecordManagerTestCb1>();
    auto callbackWrap = new (std::nothrow) StateChangeCallback(callbackPtr);
    ASSERT_NE(nullptr, callbackPtr);
    ASSERT_NE(nullptr, callbackWrap);
    ASSERT_EQ(ERR_PARAM_INVALID, PermissionRecordManager::GetInstance().StartUsingPermission(
        MakeInfo(0, PID, permissionName), callbackWrap->AsObject(), CALLER_PID));
}

/*
 * @tc.name: StartUsingPermissionTest002
 * @tc.desc: StartUsingPermission function test with invaild permissionName.
 * @tc.type: FUNC
 * @tc.require: issueI5RWXF
 */
HWTEST_F(PermissionRecordManagerTest, StartUsingPermissionTest002, TestSize.Level0)
{
    auto callbackPtr = std::make_shared<PermissionRecordManagerTestCb1>();
    auto callbackWrap = new (std::nothrow) StateChangeCallback(callbackPtr);
    ASSERT_NE(nullptr, callbackPtr);
    ASSERT_NE(nullptr, callbackWrap);
    AccessTokenIDEx tokenIdEx = PrivacyTestCommon::GetHapTokenIdFromBundle(g_InfoParms1.userID, g_InfoParms1.bundleName,
        g_InfoParms1.instIndex);
    AccessTokenID tokenId = tokenIdEx.tokenIdExStruct.tokenID;
    ASSERT_NE(INVALID_TOKENID, tokenId);
    ASSERT_EQ(ERR_PARAM_INVALID, PermissionRecordManager::GetInstance().StartUsingPermission(
        MakeInfo(tokenId, PID, "ohos.permission.LOCATION"), callbackWrap->AsObject(), CALLER_PID));

    // tokenId invaild
    ASSERT_EQ(PrivacyError::ERR_PARAM_INVALID, PermissionRecordManager::GetInstance().StartUsingPermission(
        MakeInfo(g_nativeToken, PID, "ohos.permission.CAMERA"), nullptr, CALLER_PID));
    
    ASSERT_EQ(Constant::SUCCESS, PermissionRecordManager::GetInstance().StartUsingPermission(
        MakeInfo(tokenId, PID, "ohos.permission.CAMERA"), nullptr, CALLER_PID));
    ASSERT_EQ(PrivacyError::ERR_PERMISSION_ALREADY_START_USING,
        PermissionRecordManager::GetInstance().StartUsingPermission(
        MakeInfo(tokenId, PID, "ohos.permission.CAMERA"), nullptr, CALLER_PID));

    ASSERT_EQ(Constant::SUCCESS,
        PermissionRecordManager::GetInstance().StopUsingPermission(tokenId, PID, "ohos.permission.CAMERA", CALLER_PID));
}

/*
 * @tc.name: StartUsingPermissionTest003
 * @tc.desc:
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(PermissionRecordManagerTest, StartUsingPermissionTest003, TestSize.Level0)
{
    char value[VALUE_MAX_LEN] = {0};
    GetParameter(EDM_MIC_MUTE_KEY, "", value, VALUE_MAX_LEN - 1);
    GTEST_LOG_(INFO) << "value:" << value;

    bool isMute = strncmp(value, "true", VALUE_MAX_LEN) == 0;
    SetParameter(EDM_MIC_MUTE_KEY, "true");

    AccessTokenIDEx tokenIdEx = PrivacyTestCommon::GetHapTokenIdFromBundle(g_InfoParms1.userID, g_InfoParms1.bundleName,
        g_InfoParms1.instIndex);
    AccessTokenID tokenId = tokenIdEx.tokenIdExStruct.tokenID;
    ASSERT_NE(INVALID_TOKENID, tokenId);
    std::string permissionName = "ohos.permission.MICROPHONE";
    ASSERT_EQ(PrivacyError::ERR_EDM_POLICY_CHECK_FAILED,
        PermissionRecordManager::GetInstance().StartUsingPermission(
        MakeInfo(tokenId, PID, permissionName), CALLER_PID));
    std::string str = isMute ? "true" : "false";
    SetParameter(EDM_MIC_MUTE_KEY, str.c_str());
}

/*
 * @tc.name: StartUsingPermissionTest004
 * @tc.desc:
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(PermissionRecordManagerTest, StartUsingPermissionTest004, TestSize.Level0)
{
    char value[VALUE_MAX_LEN] = {0};
    GetParameter(EDM_MIC_MUTE_KEY, "", value, VALUE_MAX_LEN - 1);
    GTEST_LOG_(INFO) << "value:" << value;

    bool isMute = strncmp(value, "true", VALUE_MAX_LEN) == 0;
    SetParameter(EDM_MIC_MUTE_KEY, "false");

    ASSERT_EQ(RET_SUCCESS, PermissionRecordManager::GetInstance().SetMutePolicy(
        PolicyType::PRIVACY, CallerType::MICROPHONE, true, RANDOM_TOKENID));

    std::vector<std::string> permList = {"ohos.permission.READ_MEDIA"};
    sptr<PermActiveStatusChangeCallback> callback = new (std::nothrow) PermActiveStatusChangeCallback();
    ASSERT_NE(nullptr, callback);
    ASSERT_EQ(RET_SUCCESS, PermissionRecordManager::GetInstance().RegisterPermActiveStatusCallback(
        GetSelfTokenID(), permList, callback->AsObject()));

    AccessTokenIDEx tokenIdEx = PrivacyTestCommon::GetHapTokenIdFromBundle(g_InfoParms1.userID, g_InfoParms1.bundleName,
        g_InfoParms1.instIndex);
    AccessTokenID tokenId = tokenIdEx.tokenIdExStruct.tokenID;
    ASSERT_NE(INVALID_TOKENID, tokenId);
    std::string permissionName = "ohos.permission.READ_MEDIA";
    ASSERT_EQ(RET_SUCCESS,
        PermissionRecordManager::GetInstance().StartUsingPermission(
        MakeInfo(tokenId, PID, permissionName), CALLER_PID));

    usleep(1000000); // 1000000us = 1s
    ASSERT_EQ(PERM_ACTIVE_IN_BACKGROUND, callback->type_);
    ASSERT_EQ(Constant::SUCCESS,
        PermissionRecordManager::GetInstance().StopUsingPermission(tokenId, PID, permissionName, CALLER_PID));
    std::string str = isMute ? "true" : "false";
    SetParameter(EDM_MIC_MUTE_KEY, str.c_str());
}

/*
 * @tc.name: StartUsingPermissionTest005
 * @tc.desc:
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(PermissionRecordManagerTest, StartUsingPermissionTest005, TestSize.Level0)
{
    char value[VALUE_MAX_LEN] = {0};
    GetParameter(EDM_MIC_MUTE_KEY, "", value, VALUE_MAX_LEN - 1);
    GTEST_LOG_(INFO) << "value:" << value;

    bool isMute = strncmp(value, "true", VALUE_MAX_LEN) == 0;
    SetParameter(EDM_MIC_MUTE_KEY, "false");

    PermissionRecordManager::GetInstance().SetMutePolicy(PolicyType::PRIVACY, CallerType::MICROPHONE, false,
        RANDOM_TOKENID);
    std::vector<std::string> permList = {"ohos.permission.READ_MEDIA"};
    sptr<PermActiveStatusChangeCallback> callback = new (std::nothrow) PermActiveStatusChangeCallback();
    ASSERT_NE(nullptr, callback);
    ASSERT_EQ(RET_SUCCESS, PermissionRecordManager::GetInstance().RegisterPermActiveStatusCallback(
        GetSelfTokenID(), permList, callback->AsObject()));

    AccessTokenIDEx tokenIdEx = PrivacyTestCommon::GetHapTokenIdFromBundle(g_InfoParms1.userID, g_InfoParms1.bundleName,
        g_InfoParms1.instIndex);
    AccessTokenID tokenId = tokenIdEx.tokenIdExStruct.tokenID;
    ASSERT_NE(INVALID_TOKENID, tokenId);
    std::string permissionName = "ohos.permission.READ_MEDIA";
    ASSERT_EQ(RET_SUCCESS,
        PermissionRecordManager::GetInstance().StartUsingPermission(
        MakeInfo(tokenId, PID, permissionName), CALLER_PID));

    usleep(1000000); // 1000000us = 1s
    ASSERT_EQ(PERM_ACTIVE_IN_BACKGROUND, callback->type_);
    ASSERT_EQ(Constant::SUCCESS,
        PermissionRecordManager::GetInstance().StopUsingPermission(tokenId, PID, permissionName, CALLER_PID));

    std::string str = isMute ? "true" : "false";
    SetParameter(EDM_MIC_MUTE_KEY, str.c_str());
}

/*
 * @tc.name: StartUsingPermissionTest006
 * @tc.desc:
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(PermissionRecordManagerTest, StartUsingPermissionTest006, TestSize.Level0)
{
    char value[VALUE_MAX_LEN] = {0};
    GetParameter(EDM_MIC_MUTE_KEY, "", value, VALUE_MAX_LEN - 1);
    GTEST_LOG_(INFO) << "value:" << value;

    bool isMute = strncmp(value, "true", VALUE_MAX_LEN) == 0;
    SetParameter(EDM_MIC_MUTE_KEY, "true");

    PermissionRecordManager::GetInstance().SetMutePolicy(PolicyType::PRIVACY, CallerType::MICROPHONE, true,
        RANDOM_TOKENID);
    std::vector<std::string> permList = {"ohos.permission.LOCATION"};
    sptr<PermActiveStatusChangeCallback> callback = new (std::nothrow) PermActiveStatusChangeCallback();
    ASSERT_NE(nullptr, callback);
    ASSERT_EQ(RET_SUCCESS, PermissionRecordManager::GetInstance().RegisterPermActiveStatusCallback(
        GetSelfTokenID(), permList, callback->AsObject()));

    AccessTokenIDEx tokenIdEx = PrivacyTestCommon::GetHapTokenIdFromBundle(g_InfoParms1.userID, g_InfoParms1.bundleName,
        g_InfoParms1.instIndex);
    AccessTokenID tokenId = tokenIdEx.tokenIdExStruct.tokenID;
    ASSERT_NE(INVALID_TOKENID, tokenId);
    std::string permissionName = "ohos.permission.LOCATION";
    ASSERT_EQ(RET_SUCCESS,
        PermissionRecordManager::GetInstance().StartUsingPermission(
        MakeInfo(tokenId, PID, permissionName), CALLER_PID));

    usleep(500000); // 500000us = 0.5s
    ASSERT_EQ(PERM_ACTIVE_IN_BACKGROUND, callback->type_);
    ASSERT_EQ(Constant::SUCCESS,
        PermissionRecordManager::GetInstance().StopUsingPermission(tokenId, PID, permissionName, CALLER_PID));

    std::string str = isMute ? "true" : "false";
    SetParameter(EDM_MIC_MUTE_KEY, str.c_str());
}

/*
 * @tc.name: StartUsingPermissionTest007
 * @tc.desc: PermissionRecordManager::StartUsingPermission function test
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(PermissionRecordManagerTest, StartUsingPermissionTest007, TestSize.Level0)
{
    AccessTokenIDEx tokenIdEx = PrivacyTestCommon::GetHapTokenIdFromBundle(g_InfoParms1.userID, g_InfoParms1.bundleName,
        g_InfoParms1.instIndex);
    AccessTokenID tokenId = tokenIdEx.tokenIdExStruct.tokenID;
    ASSERT_NE(INVALID_TOKENID, tokenId);

    // tokenId invaild
    ASSERT_EQ(PrivacyError::ERR_PARAM_INVALID, PermissionRecordManager::GetInstance().StartUsingPermission(
        MakeInfo(g_nativeToken, PID, "ohos.permission.READ_MEDIA"), CALLER_PID));

    ASSERT_EQ(Constant::SUCCESS, PermissionRecordManager::GetInstance().StartUsingPermission(
        MakeInfo(tokenId, PID, "ohos.permission.READ_MEDIA"), CALLER_PID));
    ASSERT_EQ(PrivacyError::ERR_PERMISSION_ALREADY_START_USING,
        PermissionRecordManager::GetInstance().StartUsingPermission(
        MakeInfo(tokenId, PID, "ohos.permission.READ_MEDIA"), CALLER_PID));

    ASSERT_EQ(Constant::SUCCESS,
        PermissionRecordManager::GetInstance().StopUsingPermission(
        tokenId, PID, "ohos.permission.READ_MEDIA", CALLER_PID));
}

/*
 * @tc.name: StartUsingPermissionTest008
 * @tc.desc: Test multiple process start using permission
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(PermissionRecordManagerTest, StartUsingPermissionTest008, TestSize.Level0)
{
    std::vector<std::string> permList = {"ohos.permission.CAMERA"};
    sptr<PermActiveStatusChangeCallback> callback = new (std::nothrow) PermActiveStatusChangeCallback();
    ASSERT_NE(nullptr, callback);
    ASSERT_EQ(RET_SUCCESS, PermissionRecordManager::GetInstance().RegisterPermActiveStatusCallback(
        GetSelfTokenID(), permList, callback->AsObject()));

    AccessTokenIDEx tokenIdEx = PrivacyTestCommon::GetHapTokenIdFromBundle(g_InfoParms1.userID, g_InfoParms1.bundleName,
        g_InfoParms1.instIndex);
    AccessTokenID tokenId = tokenIdEx.tokenIdExStruct.tokenID;
    ASSERT_NE(INVALID_TOKENID, tokenId);
    std::string permissionName = "ohos.permission.CAMERA";
    ASSERT_EQ(RET_SUCCESS,
        PermissionRecordManager::GetInstance().StartUsingPermission(
        MakeInfo(tokenId, TEST_PID_1, permissionName), CALLER_PID));
    ASSERT_EQ(RET_SUCCESS,
        PermissionRecordManager::GetInstance().StartUsingPermission(
        MakeInfo(tokenId, TEST_PID_3, permissionName), CALLER_PID));
    ProcessData processData;
    processData.accessTokenId = tokenId;
    processData.pid = TEST_PID_1;
    appStateObserver_->OnProcessDied(processData);
    usleep(500000); // 500000us = 0.5s
    ASSERT_EQ(PERM_ACTIVE_IN_BACKGROUND, callback->type_);

    processData.pid = TEST_PID_2;
    appStateObserver_->OnProcessDied(processData);
    usleep(500000); // 500000us = 0.5s
    ASSERT_EQ(PERM_ACTIVE_IN_BACKGROUND, callback->type_);

    processData.pid = TEST_PID_3;
    appStateObserver_->OnProcessDied(processData);
    usleep(500000); // 500000us = 0.5s
    ASSERT_EQ(PERM_INACTIVE, callback->type_);
}

#ifdef CAMERA_FRAMEWORK_ENABLE
/*
 * @tc.name: StartUsingPermissionTest009
 * @tc.desc: Test multiple process start using permission
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(PermissionRecordManagerTest, StartUsingPermissionTest009, TestSize.Level0)
{
    auto cameraCallbackMap = PermissionRecordManager::GetInstance().cameraCallbackMap_; // backup
    PermissionRecordManager::GetInstance().cameraCallbackMap_.EnsureInsert(
        PermissionRecordManager::GetInstance().GetUniqueId(RANDOM_TOKENID, -1), nullptr);

    auto callbackPtr1 = std::make_shared<PermissionRecordManagerTestCb1>();
    auto callbackWrap1 = new (std::nothrow) StateChangeCallback(callbackPtr1);
    ASSERT_NE(nullptr, callbackPtr1);
    ASSERT_NE(nullptr, callbackWrap1);

    auto callbackPtr2 = std::make_shared<PermissionRecordManagerTestCb1>();
    auto callbackWrap2 = new (std::nothrow) StateChangeCallback(callbackPtr2);
    ASSERT_NE(nullptr, callbackPtr2);
    ASSERT_NE(nullptr, callbackWrap2);

    AccessTokenIDEx tokenIdEx = PrivacyTestCommon::GetHapTokenIdFromBundle(g_InfoParms1.userID, g_InfoParms1.bundleName,
        g_InfoParms1.instIndex);
    AccessTokenID tokenId = tokenIdEx.tokenIdExStruct.tokenID;
    ASSERT_NE(INVALID_TOKENID, tokenId);
    std::string permissionName = "ohos.permission.CAMERA";
    PermissionRecordManager::GetInstance().cameraCallbackMap_.EnsureInsert(
        PermissionRecordManager::GetInstance().GetUniqueId(tokenId, -1), nullptr);

    ASSERT_EQ(RET_SUCCESS, PermissionRecordManager::GetInstance().StartUsingPermission(
        MakeInfo(tokenId, TEST_PID_1, permissionName), callbackWrap1->AsObject(), CALLER_PID));
    ASSERT_EQ(RET_SUCCESS, PermissionRecordManager::GetInstance().StartUsingPermission(
        MakeInfo(tokenId, TEST_PID_2, permissionName), callbackWrap2->AsObject(), CALLER_PID));

#ifdef CAMERA_FLOAT_WINDOW_ENABLE
    AppStateData appStateData;
    appStateData.accessTokenId = tokenId;
    appStateData.state = static_cast<int32_t>(ApplicationState::APP_STATE_FOREGROUND);
    appStateData.pid = TEST_PID_1;
    appStateObserver_->OnAppStateChanged(appStateData);
    appStateData.pid = TEST_PID_2;
    appStateObserver_->OnAppStateChanged(appStateData);

    appStateData.state = static_cast<int32_t>(ApplicationState::APP_STATE_BACKGROUND);
    appStateData.pid = TEST_PID_1;
    appStateObserver_->OnAppStateChanged(appStateData);
    usleep(500000); // 500000us = 0.5s
    ASSERT_FALSE(callbackPtr1->isShow_);
    ASSERT_FALSE(callbackPtr2->isShow_);

    callbackPtr1->isShow_ = true;
    callbackPtr2->isShow_ = true;
    appStateData.pid = TEST_PID_2;
    appStateObserver_->OnAppStateChanged(appStateData);
    usleep(500000); // 500000us = 0.5s
    ASSERT_FALSE(callbackPtr1->isShow_);
    ASSERT_FALSE(callbackPtr2->isShow_);
#endif
    PermissionRecordManager::GetInstance().cameraCallbackMap_ = cameraCallbackMap; // recovery
}
#endif

/*
 * @tc.name: StartUsingPermissionTest010
 * @tc.desc: Test multiple process start using permission
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(PermissionRecordManagerTest, StartUsingPermissionTest010, TestSize.Level0)
{
    std::vector<std::string> permList = {"ohos.permission.CAMERA"};
    sptr<PermActiveStatusChangeCallback> callback = new (std::nothrow) PermActiveStatusChangeCallback();
    ASSERT_NE(nullptr, callback);
    ASSERT_EQ(RET_SUCCESS, PermissionRecordManager::GetInstance().RegisterPermActiveStatusCallback(
        GetSelfTokenID(), permList, callback->AsObject()));

    AccessTokenIDEx tokenIdEx = PrivacyTestCommon::GetHapTokenIdFromBundle(g_InfoParms1.userID, g_InfoParms1.bundleName,
        g_InfoParms1.instIndex);
    AccessTokenID tokenId = tokenIdEx.tokenIdExStruct.tokenID;
    ASSERT_NE(INVALID_TOKENID, tokenId);
    std::string permissionName = "ohos.permission.CAMERA";
    ASSERT_EQ(RET_SUCCESS,
        PermissionRecordManager::GetInstance().StartUsingPermission(
        MakeInfo(tokenId, TEST_PID_1, permissionName), CALLER_PID));
    ASSERT_EQ(RET_SUCCESS,
        PermissionRecordManager::GetInstance().StartUsingPermission(
        MakeInfo(tokenId, TEST_PID_2, permissionName), CALLER_PID));

    ASSERT_EQ(Constant::SUCCESS,
        PermissionRecordManager::GetInstance().StopUsingPermission(
        tokenId, TEST_PID_2, "ohos.permission.CAMERA", CALLER_PID));
    usleep(500000); // 500000us = 0.5s
    ASSERT_EQ(PERM_ACTIVE_IN_BACKGROUND, callback->type_);

    ASSERT_EQ(Constant::SUCCESS,
        PermissionRecordManager::GetInstance().StopUsingPermission(
        tokenId, TEST_PID_1, "ohos.permission.CAMERA", CALLER_PID));
    usleep(500000); // 500000us = 0.5s
    ASSERT_EQ(PERM_INACTIVE, callback->type_);
}

/*
 * @tc.name: StartUsingPermissionTest011
 * @tc.desc: Test default pid -1 start using permission and OnProcessDied
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(PermissionRecordManagerTest, StartUsingPermissionTest011, TestSize.Level0)
{
    std::vector<std::string> permList = {"ohos.permission.CAMERA"};
    sptr<PermActiveStatusChangeCallback> callback = new (std::nothrow) PermActiveStatusChangeCallback();
    ASSERT_NE(nullptr, callback);
    ASSERT_EQ(RET_SUCCESS, PermissionRecordManager::GetInstance().RegisterPermActiveStatusCallback(
        GetSelfTokenID(), permList, callback->AsObject()));
    AccessTokenIDEx tokenIdEx = PrivacyTestCommon::GetHapTokenIdFromBundle(g_InfoParms1.userID, g_InfoParms1.bundleName,
        g_InfoParms1.instIndex);
    AccessTokenID tokenId = tokenIdEx.tokenIdExStruct.tokenID;
    ASSERT_NE(INVALID_TOKENID, tokenId);
    std::string permissionName = "ohos.permission.CAMERA";
    ASSERT_EQ(RET_SUCCESS,
        PermissionRecordManager::GetInstance().StartUsingPermission(
        MakeInfo(tokenId, PID, permissionName), CALLER_PID));
    ASSERT_EQ(PrivacyError::ERR_PERMISSION_ALREADY_START_USING,
        PermissionRecordManager::GetInstance().StartUsingPermission(
        MakeInfo(tokenId, PID, permissionName), CALLER_PID));

    // makesure callback end
    usleep(500000); // 500000us = 0.5s
    callback->type_ = PERM_TEMPORARY_CALL;
    ProcessData processData;
    processData.accessTokenId = tokenId;
    processData.pid = 100; // random pid
    appStateObserver_->OnProcessDied(processData);
    usleep(500000);
    ASSERT_EQ(PERM_TEMPORARY_CALL, callback->type_);
}

#ifndef APP_SECURITY_PRIVACY_SERVICE
/*
 * @tc.name: ShowGlobalDialog001
 * @tc.desc: ShowGlobalDialog function test
 * @tc.type: FUNC
 * @tc.require: issueI5RWXF
 */
HWTEST_F(PermissionRecordManagerTest, ShowGlobalDialog001, TestSize.Level0)
{
    ASSERT_EQ(true, PermissionRecordManager::GetInstance().ShowGlobalDialog("ohos.permission.CAMERA"));
    sleep(3); // wait for dialog disappear
    ASSERT_EQ(true, PermissionRecordManager::GetInstance().ShowGlobalDialog("ohos.permission.MICROPHONE"));
    sleep(3); // wait for dialog disappear
    ASSERT_EQ(true, PermissionRecordManager::GetInstance().ShowGlobalDialog("ohos.permission.LOCATION")); // no dialog
}
#endif

/*
 * @tc.name: AppStateChangeListener001
 * @tc.desc: AppStateChange function test mic global switch is close
 * @tc.type: FUNC
 * @tc.require: issueI5RWXF
 */
HWTEST_F(PermissionRecordManagerTest, AppStateChangeListener001, TestSize.Level0)
{
    char value[VALUE_MAX_LEN] = {0};
    GetParameter(EDM_MIC_MUTE_KEY, "", value, VALUE_MAX_LEN - 1);
    GTEST_LOG_(INFO) << "value:" << value;

    bool isMute = strncmp(value, "true", VALUE_MAX_LEN) == 0;
    SetParameter(EDM_MIC_MUTE_KEY, std::to_string(false).c_str());

    bool isMuteMic = AudioManagerAdapter::GetInstance().GetPersistentMicMuteState();
    PermissionRecordManager::GetInstance().SetMutePolicy(PolicyType::PRIVACY, CallerType::MICROPHONE, true,
        RANDOM_TOKENID);
    AccessTokenIDEx tokenIdEx = PrivacyTestCommon::GetHapTokenIdFromBundle(g_InfoParms1.userID, g_InfoParms1.bundleName,
        g_InfoParms1.instIndex);
    AccessTokenID tokenId = tokenIdEx.tokenIdExStruct.tokenID;
    ASSERT_NE(INVALID_TOKENID, tokenId);
    // status is inactive
    ASSERT_EQ(RET_SUCCESS,
        PermissionRecordManager::GetInstance().StartUsingPermission(
        MakeInfo(tokenId, PID, "ohos.permission.MICROPHONE"), CALLER_PID));
    sleep(3); // wait for dialog disappear
    PermissionRecordManager::GetInstance().NotifyAppStateChange(tokenId, PID, PERM_ACTIVE_IN_BACKGROUND);
    ASSERT_EQ(RET_SUCCESS,
        PermissionRecordManager::GetInstance().StopUsingPermission(tokenId, PID,
        "ohos.permission.MICROPHONE", CALLER_PID));
    PermissionRecordManager::GetInstance().SetMutePolicy(PolicyType::PRIVACY, CallerType::MICROPHONE, isMuteMic,
        RANDOM_TOKENID);
    std::string str = isMute ? "true" : "false";
    SetParameter(EDM_MIC_MUTE_KEY, str.c_str());
}

/*
 * @tc.name: TransferOpcodeToPermission001
 * @tc.desc: Constant::TransferOpcodeToPermission function test return false
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(PermissionRecordManagerTest, TransferOpcodeToPermission001, TestSize.Level0)
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
HWTEST_F(PermissionRecordManagerTest, AddPermissionUsedRecord001, TestSize.Level0)
{
    MockNativeToken mock("audio_server"); // native process with have add permission
    AccessTokenIDEx tokenIdEx = PrivacyTestCommon::GetHapTokenIdFromBundle(g_InfoParms1.userID, g_InfoParms1.bundleName,
        g_InfoParms1.instIndex);
    AccessTokenID tokenId = tokenIdEx.tokenIdExStruct.tokenID;
    ASSERT_NE(INVALID_TOKENID, tokenId);

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
HWTEST_F(PermissionRecordManagerTest, AddPermissionUsedRecord002, TestSize.Level0)
{
    MockNativeToken mock("audio_server"); // native process with have permission
    AccessTokenIDEx tokenIdEx = PrivacyTestCommon::GetHapTokenIdFromBundle(g_InfoParms1.userID, g_InfoParms1.bundleName,
        g_InfoParms1.instIndex);
    AccessTokenID tokenId = tokenIdEx.tokenIdExStruct.tokenID;
    ASSERT_NE(INVALID_TOKENID, tokenId);

    AddPermParamInfo info;
    info.tokenId = tokenId;
    info.permissionName = "com.permission.READ_MEDIA";
    info.successCount = 0;
    info.failCount = 0;
    ASSERT_EQ(PrivacyError::ERR_PARAM_INVALID, PermissionRecordManager::GetInstance().AddPermissionUsedRecord(info));
}

/*
 * @tc.name:SetPermissionUsedRecordToggleStatus001
 * @tc.desc: PermissionRecordManager::SetPermissionUsedRecordToggleStatus function test
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(PermissionRecordManagerTest, SetPermissionUsedRecordToggleStatus001, TestSize.Level0)
{
    int32_t ret = PermissionRecordManager::GetInstance().SetPermissionUsedRecordToggleStatus(
        TEST_INVALID_USER_ID, true);
    EXPECT_EQ(ret, PrivacyError::ERR_PARAM_INVALID);

    ret = PermissionRecordManager::GetInstance().SetPermissionUsedRecordToggleStatus(
        TEST_INVALID_USER_ID_20000, true);
    EXPECT_EQ(ret, PrivacyError::ERR_PARAM_INVALID);
}

/*
 * @tc.name:GetPermissionUsedRecordToggleStatus001
 * @tc.desc: PermissionRecordManager::GetPermissionUsedRecordToggleStatus function test
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(PermissionRecordManagerTest, GetPermissionUsedRecordToggleStatus001, TestSize.Level0)
{
    bool status = true;
    int32_t ret = PermissionRecordManager::GetInstance().GetPermissionUsedRecordToggleStatus(
        TEST_INVALID_USER_ID, status);
    EXPECT_EQ(ret, PrivacyError::ERR_PARAM_INVALID);

    ret = PermissionRecordManager::GetInstance().GetPermissionUsedRecordToggleStatus(
        TEST_INVALID_USER_ID_20000, status);
    EXPECT_EQ(ret, PrivacyError::ERR_PARAM_INVALID);
}

/*
 * @tc.name:UpdatePermUsedRecToggleStatusMap001
 * @tc.desc: PermissionRecordManager::test UpdatePermUsedRecToggleStatusMap and CheckPermissionUsedRecordToggleStatus
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(PermissionRecordManagerTest, UpdatePermUsedRecToggleStatusMap001, TestSize.Level0)
{
    bool checkStatus = PermissionRecordManager::GetInstance().CheckPermissionUsedRecordToggleStatus(TEST_USER_ID_10);
    EXPECT_TRUE(checkStatus);

    bool ret = PermissionRecordManager::GetInstance().UpdatePermUsedRecToggleStatusMap(TEST_USER_ID_10, false);
    checkStatus = PermissionRecordManager::GetInstance().CheckPermissionUsedRecordToggleStatus(TEST_USER_ID_10);
    EXPECT_TRUE(ret);
    EXPECT_FALSE(checkStatus);

    ret = PermissionRecordManager::GetInstance().UpdatePermUsedRecToggleStatusMap(TEST_USER_ID_10, false);
    EXPECT_FALSE(ret);

    ret = PermissionRecordManager::GetInstance().UpdatePermUsedRecToggleStatusMap(TEST_USER_ID_10, true);
    checkStatus = PermissionRecordManager::GetInstance().CheckPermissionUsedRecordToggleStatus(TEST_USER_ID_10);
    EXPECT_TRUE(ret);
    EXPECT_TRUE(checkStatus);
}

/*
 * @tc.name: StopUsingPermission001
 * @tc.desc: PermissionRecordManager::StopUsingPermission function test
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(PermissionRecordManagerTest, StopUsingPermission001, TestSize.Level0)
{
    AccessTokenIDEx tokenIdEx = PrivacyTestCommon::GetHapTokenIdFromBundle(g_InfoParms1.userID, g_InfoParms1.bundleName,
        g_InfoParms1.instIndex);
    AccessTokenID tokenId = tokenIdEx.tokenIdExStruct.tokenID;
    ASSERT_NE(INVALID_TOKENID, tokenId);

    // tokenId invaild
    ASSERT_EQ(PrivacyError::ERR_PARAM_INVALID, PermissionRecordManager::GetInstance().StopUsingPermission(
        static_cast<AccessTokenID>(0), PID, "ohos.permission.READ_MEDIA", CALLER_PID));

    // permission invaild
    ASSERT_EQ(PrivacyError::ERR_PERMISSION_NOT_EXIST, PermissionRecordManager::GetInstance().StopUsingPermission(
        tokenId, PID, "ohos.permission.test", CALLER_PID));

    // not start using
    ASSERT_EQ(PrivacyError::ERR_PERMISSION_NOT_START_USING,
        PermissionRecordManager::GetInstance().StopUsingPermission(
        tokenId, PID, "ohos.permission.READ_MEDIA", CALLER_PID));
}

/*
 * @tc.name: RegisterPermActiveStatusCallback003
 * @tc.desc: PermissionRecordManager::RegisterPermActiveStatusCallback function test
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(PermissionRecordManagerTest, RegisterPermActiveStatusCallback003, TestSize.Level0)
{
    std::vector<std::string> permList;

    permList.emplace_back("com.ohos.TEST");
    // GetDefPermission != Constant::SUCCESS && listRes is empty && listSrc is not empty
    ASSERT_EQ(PrivacyError::ERR_PARAM_INVALID, PermissionRecordManager::GetInstance().RegisterPermActiveStatusCallback(
        GetSelfTokenID(), permList, nullptr));
}

/*
 * @tc.name: GetPermissionUsedTypeInfos001
 * @tc.desc: PermissionRecordManager::GetPermissionUsedTypeInfos001 function test
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(PermissionRecordManagerTest, GetPermissionUsedTypeInfos001, TestSize.Level0)
{
    uint32_t tokenId = RANDOM_TOKENID;
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

/*
 * @tc.name: GetPermissionUsedTypeInfos002
 * @tc.desc: PrivacyKit::GetPermissionUsedTypeInfos function test
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(PermissionRecordManagerTest, GetPermissionUsedType002, TestSize.Level0)
{
    MockNativeToken mock("audio_server"); // set self tokenID to audio_service with PERMISSION_USED_STATS
    // add 21 permission used type record
    std::vector<AccessTokenID> tokenIdList;
    uint32_t count = TEST_MAX_PERMISSION_USED_TYPE_SIZE + 1;
    for (uint32_t i = 0; i < count; i++) {
        HapInfoParams infoParms = g_InfoParms1;
        HapPolicyParams policyPrams = g_PolicyPrams1;
        infoParms.bundleName = infoParms.bundleName + std::to_string(i);

        AccessTokenIDEx tokenIdEx = PrivacyTestCommon::AllocTestHapToken(infoParms, policyPrams);
        AccessTokenID tokenId = tokenIdEx.tokenIdExStruct.tokenID;
        EXPECT_NE(INVALID_TOKENID, tokenId);
        tokenIdList.emplace_back(tokenId);

        AddPermParamInfo info;
        info.tokenId = tokenId;
        info.permissionName = "ohos.permission.READ_MESSAGES";
        info.successCount = 1;
        info.failCount = 0;
        EXPECT_EQ(RET_SUCCESS, PrivacyKit::AddPermissionUsedRecord(info));
    }

    AccessTokenID tokenId = 0;
    std::string permissionName = "ohos.permission.READ_MESSAGES";
    std::vector<PermissionUsedTypeInfo> results;
    // record over size
    EXPECT_EQ(PrivacyError::ERR_OVERSIZE,
        PermissionRecordManager::GetInstance().GetPermissionUsedTypeInfos(tokenId, permissionName, results));

    for (const auto& id : tokenIdList) {
        EXPECT_EQ(RET_SUCCESS, PrivacyKit::RemovePermissionUsedRecords(id));
        EXPECT_EQ(RET_SUCCESS, PrivacyTestCommon::DeleteTestHapToken(id));
    }
}

/*
 * @tc.name: AddDataValueToResults001
 * @tc.desc: PermissionRecordManager::AddDataValueToResults function test
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(PermissionRecordManagerTest, AddDataValueToResults001, TestSize.Level0)
{
    GenericValues value;
    value.Put(PrivacyFiledConst::FIELD_TOKEN_ID, static_cast<int32_t>(RANDOM_TOKENID));
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
HWTEST_F(PermissionRecordManagerTest, AddDataValueToResults002, TestSize.Level0)
{
    GenericValues value;
    value.Put(PrivacyFiledConst::FIELD_TOKEN_ID, static_cast<int32_t>(RANDOM_TOKENID));
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
HWTEST_F(PermissionRecordManagerTest, AddDataValueToResults003, TestSize.Level0)
{
    GenericValues value;
    value.Put(PrivacyFiledConst::FIELD_TOKEN_ID, static_cast<int32_t>(RANDOM_TOKENID));
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
HWTEST_F(PermissionRecordManagerTest, SetMutePolicyTest001, TestSize.Level0)
{
    uint32_t tokenID = PrivacyTestCommon::GetNativeTokenIdFromProcess("edm");
    PermissionRecordManager::GetInstance().SetMutePolicy(PolicyType::EDM, CallerType::MICROPHONE, true, tokenID);
    PermissionRecordManager::GetInstance().SetMutePolicy(PolicyType::PRIVACY, CallerType::MICROPHONE, true,
        RANDOM_TOKENID);
    EXPECT_EQ(RET_SUCCESS,
        PermissionRecordManager::GetInstance().SetMutePolicy(PolicyType::EDM, CallerType::MICROPHONE, true, tokenID));

    PermissionRecordManager::GetInstance().SetMutePolicy(PolicyType::EDM, CallerType::MICROPHONE, true, tokenID);
    PermissionRecordManager::GetInstance().SetMutePolicy(PolicyType::PRIVACY, CallerType::MICROPHONE, true,
        RANDOM_TOKENID);
    EXPECT_EQ(ERR_PRIVACY_POLICY_CHECK_FAILED,
        PermissionRecordManager::GetInstance().SetMutePolicy(PolicyType::EDM, CallerType::MICROPHONE, false, tokenID));
}

/*
 * @tc.name: SetMutePolicyTest002
 * @tc.desc:
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(PermissionRecordManagerTest, SetMutePolicyTest002, TestSize.Level0)
{
    uint32_t tokenID = PrivacyTestCommon::GetNativeTokenIdFromProcess("edm");
    PermissionRecordManager::GetInstance().SetMutePolicy(PolicyType::EDM, CallerType::MICROPHONE, false, tokenID);
    PermissionRecordManager::GetInstance().SetMutePolicy(PolicyType::PRIVACY, CallerType::MICROPHONE, true,
        RANDOM_TOKENID);
    EXPECT_EQ(RET_SUCCESS,
        PermissionRecordManager::GetInstance().SetMutePolicy(PolicyType::EDM, CallerType::MICROPHONE, true, tokenID));

    PermissionRecordManager::GetInstance().SetMutePolicy(PolicyType::EDM, CallerType::MICROPHONE, false, tokenID);
    PermissionRecordManager::GetInstance().SetMutePolicy(PolicyType::PRIVACY, CallerType::MICROPHONE, true,
        RANDOM_TOKENID);
    EXPECT_EQ(ERR_PRIVACY_POLICY_CHECK_FAILED,
        PermissionRecordManager::GetInstance().SetMutePolicy(PolicyType::EDM, CallerType::MICROPHONE, false, tokenID));
}

/*
 * @tc.name: SetMutePolicyTest003
 * @tc.desc:
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(PermissionRecordManagerTest, SetMutePolicyTest003, TestSize.Level0)
{
    uint32_t tokenID = PrivacyTestCommon::GetNativeTokenIdFromProcess("edm");
    PermissionRecordManager::GetInstance().SetMutePolicy(PolicyType::EDM, CallerType::MICROPHONE, false, tokenID);
    PermissionRecordManager::GetInstance().SetMutePolicy(PolicyType::PRIVACY, CallerType::MICROPHONE, false,
        RANDOM_TOKENID);
    EXPECT_EQ(RET_SUCCESS,
        PermissionRecordManager::GetInstance().SetMutePolicy(PolicyType::EDM, CallerType::MICROPHONE, true, tokenID));

    PermissionRecordManager::GetInstance().SetMutePolicy(PolicyType::EDM, CallerType::MICROPHONE, false, tokenID);
    PermissionRecordManager::GetInstance().SetMutePolicy(PolicyType::PRIVACY, CallerType::MICROPHONE, false,
        RANDOM_TOKENID);
    EXPECT_EQ(RET_SUCCESS,
        PermissionRecordManager::GetInstance().SetMutePolicy(PolicyType::EDM, CallerType::MICROPHONE, false, tokenID));
}

/*
 * @tc.name: SetMutePolicyTest004
 * @tc.desc:
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(PermissionRecordManagerTest, SetMutePolicyTest004, TestSize.Level0)
{
    uint32_t tokenID = PrivacyTestCommon::GetNativeTokenIdFromProcess("edm");
    PermissionRecordManager::GetInstance().SetMutePolicy(PolicyType::EDM, CallerType::MICROPHONE, true, tokenID);
    PermissionRecordManager::GetInstance().SetMutePolicy(PolicyType::PRIVACY, CallerType::MICROPHONE, true,
        RANDOM_TOKENID);
    EXPECT_EQ(RET_SUCCESS, PermissionRecordManager::GetInstance().SetMutePolicy(
        PolicyType::PRIVACY, CallerType::MICROPHONE, true, RANDOM_TOKENID));

    PermissionRecordManager::GetInstance().SetMutePolicy(PolicyType::EDM, CallerType::MICROPHONE, true, tokenID);
    PermissionRecordManager::GetInstance().SetMutePolicy(PolicyType::PRIVACY, CallerType::MICROPHONE, true,
        RANDOM_TOKENID);
    EXPECT_EQ(ERR_EDM_POLICY_CHECK_FAILED,
        PermissionRecordManager::GetInstance().SetMutePolicy(PolicyType::PRIVACY, CallerType::MICROPHONE, false,
        RANDOM_TOKENID));
}

/*
 * @tc.name: SetMutePolicyTest005
 * @tc.desc:
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(PermissionRecordManagerTest, SetMutePolicyTest005, TestSize.Level0)
{
    uint32_t tokenID = PrivacyTestCommon::GetNativeTokenIdFromProcess("edm");
    PermissionRecordManager::GetInstance().SetMutePolicy(PolicyType::EDM, CallerType::MICROPHONE, false, tokenID);
    PermissionRecordManager::GetInstance().SetMutePolicy(PolicyType::PRIVACY, CallerType::MICROPHONE, true,
        RANDOM_TOKENID);
    EXPECT_EQ(RET_SUCCESS, PermissionRecordManager::GetInstance().SetMutePolicy(
        PolicyType::PRIVACY, CallerType::MICROPHONE, true, RANDOM_TOKENID));

    PermissionRecordManager::GetInstance().SetMutePolicy(PolicyType::EDM, CallerType::MICROPHONE, false, tokenID);
    PermissionRecordManager::GetInstance().SetMutePolicy(PolicyType::PRIVACY, CallerType::MICROPHONE, true,
        RANDOM_TOKENID);
    EXPECT_EQ(RET_SUCCESS, PermissionRecordManager::GetInstance().SetMutePolicy(
        PolicyType::PRIVACY, CallerType::MICROPHONE, false, RANDOM_TOKENID));
}

/*
 * @tc.name: SetMutePolicyTest006
 * @tc.desc:
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(PermissionRecordManagerTest, SetMutePolicyTest006, TestSize.Level0)
{
    uint32_t tokenID = PrivacyTestCommon::GetNativeTokenIdFromProcess("edm");
    PermissionRecordManager::GetInstance().SetMutePolicy(PolicyType::EDM, CallerType::MICROPHONE, false, tokenID);
    PermissionRecordManager::GetInstance().SetMutePolicy(PolicyType::PRIVACY, CallerType::MICROPHONE, false,
        RANDOM_TOKENID);
    EXPECT_EQ(RET_SUCCESS, PermissionRecordManager::GetInstance().SetMutePolicy(
        PolicyType::PRIVACY, CallerType::MICROPHONE, true, RANDOM_TOKENID));

    PermissionRecordManager::GetInstance().SetMutePolicy(PolicyType::EDM, CallerType::MICROPHONE, false, tokenID);
    PermissionRecordManager::GetInstance().SetMutePolicy(PolicyType::PRIVACY, CallerType::MICROPHONE, false,
        RANDOM_TOKENID);
    EXPECT_EQ(RET_SUCCESS, PermissionRecordManager::GetInstance().SetMutePolicy(
        PolicyType::PRIVACY, CallerType::MICROPHONE, false, RANDOM_TOKENID));
}

/*
 * @tc.name: SetMutePolicyTest007
 * @tc.desc:
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(PermissionRecordManagerTest, SetMutePolicyTest007, TestSize.Level0)
{
    uint32_t tokenID = PrivacyTestCommon::GetNativeTokenIdFromProcess("edm");
    PermissionRecordManager::GetInstance().SetMutePolicy(PolicyType::EDM, CallerType::MICROPHONE, true, tokenID);
    PermissionRecordManager::GetInstance().SetMutePolicy(PolicyType::PRIVACY, CallerType::MICROPHONE, true,
        RANDOM_TOKENID);
    EXPECT_EQ(RET_SUCCESS, PermissionRecordManager::GetInstance().SetMutePolicy(
        PolicyType::TEMPORARY, CallerType::MICROPHONE, true, RANDOM_TOKENID));

    PermissionRecordManager::GetInstance().SetMutePolicy(PolicyType::EDM, CallerType::MICROPHONE, true, tokenID);
    PermissionRecordManager::GetInstance().SetMutePolicy(PolicyType::PRIVACY, CallerType::MICROPHONE, true,
        RANDOM_TOKENID);
    EXPECT_EQ(ERR_EDM_POLICY_CHECK_FAILED, PermissionRecordManager::GetInstance().SetMutePolicy(
        PolicyType::TEMPORARY, CallerType::MICROPHONE, false, RANDOM_TOKENID));
}

#ifndef APP_SECURITY_PRIVACY_SERVICE
/*
 * @tc.name: SetMutePolicyTest008
 * @tc.desc:
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(PermissionRecordManagerTest, SetMutePolicyTest008, TestSize.Level0)
{
    uint32_t tokenID = PrivacyTestCommon::GetNativeTokenIdFromProcess("edm");
    PermissionRecordManager::GetInstance().SetMutePolicy(PolicyType::EDM, CallerType::MICROPHONE, false, tokenID);
    PermissionRecordManager::GetInstance().SetMutePolicy(PolicyType::PRIVACY, CallerType::MICROPHONE, true,
        RANDOM_TOKENID);
    EXPECT_EQ(RET_SUCCESS, PermissionRecordManager::GetInstance().SetMutePolicy(
        PolicyType::TEMPORARY, CallerType::MICROPHONE, true, RANDOM_TOKENID));

    PermissionRecordManager::GetInstance().SetMutePolicy(PolicyType::EDM, CallerType::MICROPHONE, false, tokenID);
    PermissionRecordManager::GetInstance().SetMutePolicy(PolicyType::PRIVACY, CallerType::MICROPHONE, true,
        RANDOM_TOKENID);
    EXPECT_EQ(ERR_PRIVACY_POLICY_CHECK_FAILED, PermissionRecordManager::GetInstance().SetMutePolicy(
        PolicyType::TEMPORARY, CallerType::MICROPHONE, false, RANDOM_TOKENID));
}
#endif

/*
 * @tc.name: SetMutePolicyTest009
 * @tc.desc:
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(PermissionRecordManagerTest, SetMutePolicyTest009, TestSize.Level0)
{
    uint32_t tokenID = PrivacyTestCommon::GetNativeTokenIdFromProcess("edm");
    PermissionRecordManager::GetInstance().SetMutePolicy(PolicyType::EDM, CallerType::MICROPHONE, false, tokenID);
    PermissionRecordManager::GetInstance().SetMutePolicy(PolicyType::PRIVACY, CallerType::MICROPHONE, false,
        RANDOM_TOKENID);
    EXPECT_EQ(RET_SUCCESS, PermissionRecordManager::GetInstance().SetMutePolicy(
        PolicyType::TEMPORARY, CallerType::MICROPHONE, true, RANDOM_TOKENID));

    PermissionRecordManager::GetInstance().SetMutePolicy(PolicyType::EDM, CallerType::MICROPHONE, false, tokenID);
    PermissionRecordManager::GetInstance().SetMutePolicy(PolicyType::PRIVACY, CallerType::MICROPHONE, false,
        RANDOM_TOKENID);
    EXPECT_EQ(RET_SUCCESS, PermissionRecordManager::GetInstance().SetMutePolicy(
        PolicyType::TEMPORARY, CallerType::MICROPHONE, false, RANDOM_TOKENID));
}

class DiedProxyMaker {
public:
    DiedProxyMaker()
    {
        handler_ = std::make_shared<ProxyDeathHandler>();
    }

    void AddRecipient(int callerPid)
    {
        std::shared_ptr<ProxyDeathParam> param = std::make_shared<PrivacyManagerProxyDeathParam>(callerPid);
        auto anonyStub = sptr<ProxyDeathCallBackStub>::MakeSptr();
        handler_->AddProxyStub(anonyStub, param);
    }

    void TestDie(int32_t callerPid)
    {
        auto map = handler_->proxyStubAndRecipientMap_;
        auto param = reinterpret_cast<ProxyDeathParam*>(new (std::nothrow) PrivacyManagerProxyDeathParam(callerPid));
        for (auto iter = map.begin(); iter != map.end(); ++iter) {
            if (iter->second.second->IsEqual(param)) {
                iter->second.first->OnRemoteDied(iter->first);
            }
        }
    }

    std::shared_ptr<ProxyDeathHandler> handler_ = nullptr;
};

/*
 * @tc.name: PermissionRecordManagerTest
 * @tc.desc: ProxyDeathTest test
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(PermissionRecordManagerTest, ProxyDeathTest001, TestSize.Level0)
{
    DiedProxyMaker init;
    init.AddRecipient(CALLER_PID);
    init.TestDie(CALLER_PID);
    ASSERT_EQ(0, PermissionRecordManager::GetInstance().startRecordList_.size());

    AccessTokenIDEx tokenIdEx = PrivacyTestCommon::GetHapTokenIdFromBundle(g_InfoParms1.userID, g_InfoParms1.bundleName,
        g_InfoParms1.instIndex);
    AccessTokenID tokenId1 = tokenIdEx.tokenIdExStruct.tokenID;
    ASSERT_NE(INVALID_TOKENID, tokenId1);
    std::string permissionName = "ohos.permission.CAMERA";
    ASSERT_EQ(RET_SUCCESS,
        PermissionRecordManager::GetInstance().StartUsingPermission(
        MakeInfo(tokenId1, TEST_PID_1, permissionName), CALLER_PID));

    tokenIdEx = PrivacyTestCommon::GetHapTokenIdFromBundle(g_InfoParms1.userID, g_InfoParms1.bundleName,
        g_InfoParms1.instIndex);
    AccessTokenID tokenId2 = tokenIdEx.tokenIdExStruct.tokenID;
    ASSERT_NE(INVALID_TOKENID, tokenId2);
    ASSERT_EQ(RET_SUCCESS,
        PermissionRecordManager::GetInstance().StartUsingPermission(
        MakeInfo(tokenId2, TEST_PID_2, permissionName), CALLER_PID));
    ASSERT_EQ(2, PermissionRecordManager::GetInstance().startRecordList_.size());

    DiedProxyMaker maker;
    maker.AddRecipient(CALLER_PID);
    maker.TestDie(CALLER_PID);
    ASSERT_EQ(0, PermissionRecordManager::GetInstance().startRecordList_.size());
}

/*
 * @tc.name: PermissionRecordManagerTest
 * @tc.desc: ProxyDeathTest test
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(PermissionRecordManagerTest, ProxyDeathTest002, TestSize.Level0)
{
    DiedProxyMaker init;
    init.AddRecipient(CALLER_PID);
    init.TestDie(CALLER_PID);
    AccessTokenIDEx tokenIdEx = PrivacyTestCommon::GetHapTokenIdFromBundle(g_InfoParms1.userID, g_InfoParms1.bundleName,
        g_InfoParms1.instIndex);
    AccessTokenID tokenId1 = tokenIdEx.tokenIdExStruct.tokenID;
    ASSERT_NE(INVALID_TOKENID, tokenId1);
    std::string permissionName = "ohos.permission.CAMERA";
    ASSERT_EQ(RET_SUCCESS,
        PermissionRecordManager::GetInstance().StartUsingPermission(
        MakeInfo(tokenId1, TEST_PID_1, permissionName), CALLER_PID));

    tokenIdEx = PrivacyTestCommon::GetHapTokenIdFromBundle(g_InfoParms1.userID, g_InfoParms1.bundleName,
        g_InfoParms1.instIndex);
    AccessTokenID tokenId2 = tokenIdEx.tokenIdExStruct.tokenID;
    ASSERT_NE(INVALID_TOKENID, tokenId2);
    ASSERT_EQ(RET_SUCCESS,
        PermissionRecordManager::GetInstance().StartUsingPermission(
        MakeInfo(tokenId2, TEST_PID_2, permissionName), CALLER_PID2));
    ASSERT_EQ(2, PermissionRecordManager::GetInstance().startRecordList_.size());

    DiedProxyMaker maker;
    maker.AddRecipient(CALLER_PID);
    maker.TestDie(CALLER_PID);
    ASSERT_EQ(1, PermissionRecordManager::GetInstance().startRecordList_.size());

    ASSERT_EQ(RET_SUCCESS,
        PermissionRecordManager::GetInstance().StopUsingPermission(tokenId2, TEST_PID_2, permissionName, CALLER_PID2));
}

/*
 * @tc.name: PermissionRecordManagerTest
 * @tc.desc: HasCallerInStartList test
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(PermissionRecordManagerTest, HasCallerInStartList001, TestSize.Level0)
{
    DiedProxyMaker init;
    init.AddRecipient(CALLER_PID);
    init.TestDie(CALLER_PID);
    AccessTokenIDEx tokenIdEx = PrivacyTestCommon::GetHapTokenIdFromBundle(g_InfoParms1.userID, g_InfoParms1.bundleName,
        g_InfoParms1.instIndex);
    AccessTokenID tokenId1 = tokenIdEx.tokenIdExStruct.tokenID;
    ASSERT_NE(INVALID_TOKENID, tokenId1);
    std::string permissionName = "ohos.permission.CAMERA";
    ASSERT_EQ(RET_SUCCESS,
        PermissionRecordManager::GetInstance().StartUsingPermission(
        MakeInfo(tokenId1, TEST_PID_1, permissionName), CALLER_PID));
    ASSERT_TRUE(PermissionRecordManager::GetInstance().HasCallerInStartList(CALLER_PID));
    ASSERT_FALSE(PermissionRecordManager::GetInstance().HasCallerInStartList(CALLER_PID2));
    ASSERT_EQ(RET_SUCCESS,
        PermissionRecordManager::GetInstance().StopUsingPermission(tokenId1, TEST_PID_1, permissionName, CALLER_PID));
    ASSERT_FALSE(PermissionRecordManager::GetInstance().HasCallerInStartList(CALLER_PID));
}

/*
 * @tc.name: AddPermissionUsedRecordTest001
 * @tc.desc: AddPermissionUsedRecord function test
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(PermissionRecordManagerTest, AddPermissionUsedRecordTest001, TestSize.Level0)
{
    AccessTokenIDEx tokenIdEx = PrivacyTestCommon::GetHapTokenIdFromBundle(g_InfoParms1.userID, g_InfoParms1.bundleName,
        g_InfoParms1.instIndex);
    AccessTokenID tokenId = tokenIdEx.tokenIdExStruct.tokenID;
    ASSERT_NE(INVALID_TOKENID, tokenId);
    
    AddPermParamInfo info;
    info.tokenId = tokenId;
    info.permissionName = "ohos.permission.CAMERA";
    info.successCount = 0;
    info.failCount = 1;
    info.type = NORMAL_TYPE;
    ASSERT_EQ(RET_SUCCESS, PermissionRecordManager::GetInstance().AddPermissionUsedRecord(info));

    info.tokenId = RANDOM_TOKENID;
    ASSERT_NE(RET_SUCCESS, PermissionRecordManager::GetInstance().AddPermissionUsedRecord(info));
}

/*
 * @tc.name: AddPermissionUsedRecordTest002
 * @tc.desc: AddPermissionUsedRecord function test
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(PermissionRecordManagerTest, AddPermissionUsedRecordTest002, TestSize.Level0)
{
    AccessTokenIDEx tokenIdEx = PrivacyTestCommon::AllocTestHapToken(g_InfoParms3, g_PolicyPrams3);
    AccessTokenID tokenId = tokenIdEx.tokenIdExStruct.tokenID;
    ASSERT_NE(INVALID_TOKENID, tokenId);

    AddPermParamInfo info;
    info.tokenId = tokenId;
    info.permissionName = "ohos.permission.CAMERA";
    info.successCount = 1;
    info.failCount = 0;
    info.type = NORMAL_TYPE;
    EXPECT_EQ(RET_SUCCESS, PermissionRecordManager::GetInstance().AddPermissionUsedRecord(info));

    std::vector<std::string> permissionList;
    permissionList.push_back("ohos.permission.CAMERA");
    PermissionUsedRequest request;
    request.tokenId = tokenId;
    request.isRemote = false;
    request.deviceId = "";
    request.bundleName = g_InfoParms3.bundleName;
    request.permissionList = permissionList;
    request.beginTimeMillis = 0;
    request.endTimeMillis = 0;
    request.flag = FLAG_PERMISSION_USAGE_SUMMARY;

    PermissionUsedResult result;
    EXPECT_EQ(RET_SUCCESS, PermissionRecordManager::GetInstance().GetPermissionUsedRecords(request, result));
    EXPECT_EQ(0, result.bundleRecords.size());

    EXPECT_EQ(RET_SUCCESS, PrivacyTestCommon::DeleteTestHapToken(tokenId));
}
} // namespace AccessToken
} // namespace Security
} // namespace OHOS
