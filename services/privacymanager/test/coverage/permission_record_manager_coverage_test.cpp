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

#include "access_token.h"
#include "accesstoken_kit.h"
#include "camera_manager_adapter.h"
#include "constant.h"
#include "data_translator.h"
#include "permission_record.h"
#define private public
#include "active_status_callback_manager.h"
#include "permission_record_manager.h"
#include "permission_used_record_db.h"
#undef private
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
static constexpr int32_t CALLER_PID = 10;
static AccessTokenID g_selfTokenId = 0;
static AccessTokenID g_nativeToken = 0;
static constexpr int32_t MAX_DETAIL_NUM = 500;
static constexpr int64_t ONE_SECOND = 1000;
static constexpr int64_t TWO_SECOND = 2000;
static constexpr int64_t THREE_SECOND = 3000;
static constexpr int32_t PERMISSION_USED_TYPE_VALUE = 1;
static constexpr int32_t PERMISSION_USED_TYPE_WITH_PICKER_TYPE_VALUE = 3;
static constexpr uint32_t RANDOM_TOKENID = 123;
static constexpr int32_t TEST_USER_ID_11 = 11;
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
    PrivacyTestCommon::SetTestEvironment(g_selfTokenId);

    g_nativeToken = PrivacyTestCommon::GetNativeTokenIdFromProcess("privacy_service");
}

void PermissionRecordManagerTest::TearDownTestCase()
{
    PrivacyTestCommon::ResetTestEvironment();
}

void PermissionRecordManagerTest::SetUp()
{
    PermissionRecordManager::GetInstance().Register();

    PrivacyTestCommon::AllocTestHapToken(g_InfoParms1, g_PolicyPrams1);
    PrivacyTestCommon::AllocTestHapToken(g_InfoParms2, g_PolicyPrams2);
}

void PermissionRecordManagerTest::TearDown()
{
    AccessTokenIDEx tokenIdEx = PrivacyTestCommon::GetHapTokenIdFromBundle(
        g_InfoParms1.userID, g_InfoParms1.bundleName, g_InfoParms1.instIndex);
    PrivacyTestCommon::DeleteTestHapToken(tokenIdEx.tokenIdExStruct.tokenID);
    tokenIdEx = PrivacyTestCommon::GetHapTokenIdFromBundle(
        g_InfoParms2.userID, g_InfoParms2.bundleName, g_InfoParms2.instIndex);
    PrivacyTestCommon::DeleteTestHapToken(tokenIdEx.tokenIdExStruct.tokenID);
}

class PermissionRecordManagerCoverTestCb1 : public StateCustomizedCbk {
public:
    PermissionRecordManagerCoverTestCb1()
    {}

    ~PermissionRecordManagerCoverTestCb1()
    {}

    virtual void StateChangeNotify(AccessTokenID tokenId, bool isShow)
    {}

    void Stop()
    {}
};

class PermissionRecordManagerCoverTestCb2 : public IRemoteObject {
public:
    PermissionRecordManagerCoverTestCb2()
    {}

    ~PermissionRecordManagerCoverTestCb2()
    {}
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
 * @tc.name: OnAppStateChanged001
 * @tc.desc: RegisterPermActiveStatusCallback with invalid parameter.
 * @tc.type: FUNC
 * @tc.require: issueI5RWX8
 */
HWTEST_F(PermissionRecordManagerTest, OnAppStateChanged001, TestSize.Level1)
{
    PrivacyAppStateObserver observer;
    AppStateData appStateData;
    appStateData.state = static_cast<int32_t>(ApplicationState::APP_STATE_FOREGROUND);
    observer.OnAppStateChanged(appStateData);
    appStateData.state = static_cast<int32_t>(ApplicationState::APP_STATE_BACKGROUND);
    observer.OnAppStateChanged(appStateData);
    ASSERT_EQ(static_cast<int32_t>(ApplicationState::APP_STATE_BACKGROUND), appStateData.state);
}

/*
 * @tc.name: AppStatusListener001
 * @tc.desc: register and startusing permissions then use NotifyAppStateChange
 * @tc.type: FUNC
 * @tc.require: issueI5SZHG
 */
HWTEST_F(PermissionRecordManagerTest, AppStatusListener001, TestSize.Level1)
{
    AccessTokenIDEx tokenIdEx1 = PrivacyTestCommon::GetHapTokenIdFromBundle(
        g_InfoParms1.userID, g_InfoParms1.bundleName, g_InfoParms1.instIndex);
    AccessTokenID tokenId1 = tokenIdEx1.tokenIdExStruct.tokenID;
    ASSERT_NE(static_cast<AccessTokenID>(0), tokenId1);

    AccessTokenIDEx tokenIdEx2 = PrivacyTestCommon::GetHapTokenIdFromBundle(
        g_InfoParms2.userID, g_InfoParms2.bundleName, g_InfoParms2.instIndex);
    AccessTokenID tokenId2 = tokenIdEx2.tokenIdExStruct.tokenID;
    ASSERT_NE(static_cast<AccessTokenID>(0), tokenId2);

    ContinusPermissionRecord recordA1 = {
        .tokenId = tokenId1,
        .opCode = Constant::OP_CAMERA,
        .status = ActiveChangeType::PERM_ACTIVE_IN_BACKGROUND,
    };

    ContinusPermissionRecord recordA2 = {
        .tokenId = tokenId1,
        .opCode = Constant::OP_MICROPHONE,
        .status = ActiveChangeType::PERM_ACTIVE_IN_BACKGROUND,
    };

    ContinusPermissionRecord recordB1 = {
        .tokenId = tokenId2,
        .opCode = Constant::OP_CAMERA,
        .status = ActiveChangeType::PERM_ACTIVE_IN_BACKGROUND,
    };

    ContinusPermissionRecord recordB2 = {
        .tokenId = tokenId2,
        .opCode = Constant::OP_MICROPHONE,
        .status = ActiveChangeType::PERM_ACTIVE_IN_BACKGROUND,
    };

    PermissionRecordManager::GetInstance().startRecordList_.emplace(recordA1);
    PermissionRecordManager::GetInstance().startRecordList_.emplace(recordA2);
    PermissionRecordManager::GetInstance().startRecordList_.emplace(recordB1);
    PermissionRecordManager::GetInstance().startRecordList_.emplace(recordB2);

    PermissionRecordManager::GetInstance().NotifyAppStateChange(tokenId1, PID, PERM_ACTIVE_IN_FOREGROUND);
    PermissionRecordManager::GetInstance().NotifyAppStateChange(tokenId2, PID, PERM_ACTIVE_IN_FOREGROUND);
    PermissionRecordManager::GetInstance().NotifyAppStateChange(tokenId1, PID, PERM_ACTIVE_IN_FOREGROUND);
    PermissionRecordManager::GetInstance().NotifyAppStateChange(tokenId2, PID, PERM_ACTIVE_IN_FOREGROUND);
    PermissionRecordManager::GetInstance().NotifyAppStateChange(tokenId1, PID, PERM_ACTIVE_IN_BACKGROUND);
    PermissionRecordManager::GetInstance().NotifyAppStateChange(tokenId2, PID, PERM_ACTIVE_IN_BACKGROUND);
    PermissionRecordManager::GetInstance().NotifyAppStateChange(tokenId1, PID, PERM_ACTIVE_IN_BACKGROUND);
    PermissionRecordManager::GetInstance().NotifyAppStateChange(tokenId2, PID, PERM_ACTIVE_IN_BACKGROUND);
}

/*
 * @tc.name: FindRecordsToUpdateAndExecutedTest001
 * @tc.desc: FindRecordsToUpdateAndExecuted function test with invaild tokenId or permissionName or callback.
 * @tc.type: FUNC
 * @tc.require: issueI5RWX5 issueI5RWX3 issueI5RWXA
 */
HWTEST_F(PermissionRecordManagerTest, FindRecordsToUpdateAndExecutedTest001, TestSize.Level1)
{
    std::vector<std::string> reqPerm;
    reqPerm.emplace_back("ohos.permission.CAMERA");
    reqPerm.emplace_back("ohos.permission.MANAGE_CAMERA_CONFIG");
    MockHapToken mock("FindRecordsToUpdateAndExecutedTest001", reqPerm, false);

    AccessTokenID tokenId = GetSelfTokenID();;
    ASSERT_NE(INVALID_TOKENID, tokenId);

    ActiveChangeType status = PERM_ACTIVE_IN_BACKGROUND;
    std::string permission = "ohos.permission.CAMERA";
    PermissionRecordManager::GetInstance().SetMutePolicy(PolicyType::PRIVACY, CallerType::CAMERA, false,
        RANDOM_TOKENID);
    PermissionRecordManager::GetInstance().AddRecordToStartList(MakeInfo(tokenId, PID, permission), status, CALLER_PID);
#ifdef CAMERA_FLOAT_WINDOW_ENABLE
    PermissionRecordManager::GetInstance().NotifyCameraWindowChange(false, tokenId, false);
    PermissionRecordManager::GetInstance().NotifyCameraWindowChange(true, tokenId, false);
#endif
    PermissionRecordManager::GetInstance().ExecuteAndUpdateRecord(tokenId, PID, status);
    PermissionRecordManager::GetInstance().NotifyAppStateChange(tokenId, PID, status);

    ASSERT_EQ(RET_SUCCESS, PermissionRecordManager::GetInstance().RemoveRecordFromStartList(
        tokenId, PID, permission, CALLER_PID));
}

/*
 * @tc.name: FindRecordsToUpdateAndExecutedTest002
 * @tc.desc: FindRecordsToUpdateAndExecuted function test with invaild tokenId or permissionName or callback.
 * @tc.type: FUNC
 * @tc.require: issueI5RWX5 issueI5RWX3 issueI5RWXA
 */
HWTEST_F(PermissionRecordManagerTest, FindRecordsToUpdateAndExecutedTest002, TestSize.Level1)
{
    AccessTokenIDEx tokenIdEx = PrivacyTestCommon::GetHapTokenIdFromBundle(
        g_InfoParms1.userID, g_InfoParms1.bundleName, g_InfoParms1.instIndex);
    AccessTokenID tokenId = tokenIdEx.tokenIdExStruct.tokenID;
    ASSERT_NE(INVALID_TOKENID, tokenId);
    ActiveChangeType status = PERM_ACTIVE_IN_BACKGROUND;
    std::string permission = "ohos.permission.MICROPHONE";
    PermissionRecordManager::GetInstance().AddRecordToStartList(MakeInfo(tokenId, PID, permission), status, CALLER_PID);
#ifdef CAMERA_FLOAT_WINDOW_ENABLE
    PermissionRecordManager::GetInstance().NotifyCameraWindowChange(false, tokenId, false);
    PermissionRecordManager::GetInstance().NotifyCameraWindowChange(true, tokenId, false);
#endif
    PermissionRecordManager::GetInstance().ExecuteAndUpdateRecord(tokenId, PID, status);
    PermissionRecordManager::GetInstance().NotifyAppStateChange(tokenId, PID, status);

    ASSERT_EQ(RET_SUCCESS, PermissionRecordManager::GetInstance().RemoveRecordFromStartList(
        tokenId, PID, permission, CALLER_PID));
}

/*
 * @tc.name: FindRecordsToUpdateAndExecutedTest003
 * @tc.desc: FindRecordsToUpdateAndExecuted function test with invaild tokenId or permissionName or callback.
 * @tc.type: FUNC
 * @tc.require: issueI5RWX5 issueI5RWX3 issueI5RWXA
 */
HWTEST_F(PermissionRecordManagerTest, FindRecordsToUpdateAndExecutedTest003, TestSize.Level1)
{
    AccessTokenIDEx tokenIdEx = PrivacyTestCommon::GetHapTokenIdFromBundle(
        g_InfoParms1.userID, g_InfoParms1.bundleName, g_InfoParms1.instIndex);
    AccessTokenID tokenId = tokenIdEx.tokenIdExStruct.tokenID;
    ASSERT_NE(INVALID_TOKENID, tokenId);
    ActiveChangeType status = PERM_ACTIVE_IN_FOREGROUND;
    std::string permission = "ohos.permission.CAMERA";
    PermissionRecordManager::GetInstance().AddRecordToStartList(MakeInfo(tokenId, PID, permission), status, CALLER_PID);
#ifdef CAMERA_FLOAT_WINDOW_ENABLE
    PermissionRecordManager::GetInstance().NotifyCameraWindowChange(false, tokenId, false);
    PermissionRecordManager::GetInstance().NotifyCameraWindowChange(true, tokenId, false);
#endif
    PermissionRecordManager::GetInstance().ExecuteAndUpdateRecord(tokenId, PID, status);

    ASSERT_EQ(RET_SUCCESS, PermissionRecordManager::GetInstance().RemoveRecordFromStartList(
        tokenId, PID, permission, CALLER_PID));
}

/*
 * @tc.name: FindRecordsToUpdateAndExecutedTest004
 * @tc.desc: FindRecordsToUpdateAndExecuted function test with invaild tokenId or permissionName or callback.
 * @tc.type: FUNC
 * @tc.require: issueI5RWX5 issueI5RWX3 issueI5RWXA
 */
HWTEST_F(PermissionRecordManagerTest, FindRecordsToUpdateAndExecutedTest004, TestSize.Level1)
{
    AccessTokenIDEx tokenIdEx = PrivacyTestCommon::GetHapTokenIdFromBundle(
        g_InfoParms1.userID, g_InfoParms1.bundleName, g_InfoParms1.instIndex);
    AccessTokenID tokenId = tokenIdEx.tokenIdExStruct.tokenID;
    ASSERT_NE(INVALID_TOKENID, tokenId);
    ActiveChangeType status = PERM_ACTIVE_IN_BACKGROUND;
    std::string permission = "ohos.permission.CAMERA";
    PermissionRecordManager::GetInstance().AddRecordToStartList(MakeInfo(tokenId, PID, permission), status, CALLER_PID);
#ifdef CAMERA_FLOAT_WINDOW_ENABLE
    PermissionRecordManager::GetInstance().NotifyCameraWindowChange(false, tokenId, false);
    PermissionRecordManager::GetInstance().NotifyCameraWindowChange(true, tokenId, false);
#endif
    PermissionRecordManager::GetInstance().ExecuteAndUpdateRecord(tokenId, PID, status);

    ASSERT_EQ(RET_SUCCESS, PermissionRecordManager::GetInstance().RemoveRecordFromStartList(
        tokenId, PID, permission, CALLER_PID));
}

/*
 * @tc.name: ExecuteCameraCallbackAsyncTest001
 * @tc.desc: Verify the ExecuteCameraCallbackAsync abnormal branch function test with.
 * @tc.type: FUNC
 * @tc.require: issueI5RWX5 issueI5RWX3 issueI5RWXA
 */
HWTEST_F(PermissionRecordManagerTest, ExecuteCameraCallbackAsyncTest001, TestSize.Level1)
{
    AccessTokenIDEx tokenIdEx = PrivacyTestCommon::GetHapTokenIdFromBundle(
        g_InfoParms1.userID, g_InfoParms1.bundleName, g_InfoParms1.instIndex);
    AccessTokenID tokenId = tokenIdEx.tokenIdExStruct.tokenID;
    ASSERT_NE(INVALID_TOKENID, tokenId);

    auto callbackPtr = std::make_shared<PermissionRecordManagerCoverTestCb1>();
    auto callbackWrap = new (std::nothrow) StateChangeCallback(callbackPtr);
    ASSERT_NE(nullptr, callbackPtr);
    ASSERT_NE(nullptr, callbackWrap);
    PermissionRecordManager::GetInstance().ExecuteCameraCallbackAsync(tokenId, PID);

    PermissionRecordManager::GetInstance().ExecuteCameraCallbackAsync(tokenId, PID);
}

class PermActiveStatusChangeCallbackTest : public PermActiveStatusChangeCallbackStub {
public:
    PermActiveStatusChangeCallbackTest() = default;
    virtual ~PermActiveStatusChangeCallbackTest() = default;

    void ActiveStatusChangeCallback(ActiveChangeResponse& result) override;
    bool AddDeathRecipient(const sptr<IRemoteObject::DeathRecipient>& deathRecipient) override;
};

void PermActiveStatusChangeCallbackTest::ActiveStatusChangeCallback(ActiveChangeResponse& result)
{
}

bool PermActiveStatusChangeCallbackTest::AddDeathRecipient(const sptr<IRemoteObject::DeathRecipient>& deathRecipient)
{
    return true;
}

class PermissionRecordManagerCoverTestCb3 : public PermActiveStatusCustomizedCbk {
public:
    explicit PermissionRecordManagerCoverTestCb3(const std::vector<std::string> &permList)
        : PermActiveStatusCustomizedCbk(permList)
    {
        GTEST_LOG_(INFO) << "PermissionRecordManagerCoverTestCb3 create";
    }

    ~PermissionRecordManagerCoverTestCb3()
    {}

    virtual void ActiveStatusChangeCallback(ActiveChangeResponse& result)
    {
        type_ = result.type;
    }

    ActiveChangeType type_ = PERM_INACTIVE;
};

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
    ActiveStatusCallbackManager::GetInstance().AddCallback(GetSelfTokenID(), permList, callback);
    ASSERT_EQ(static_cast<uint32_t>(1), ActiveStatusCallbackManager::GetInstance().callbackDataList_.size());
    recipient->OnRemoteDied(remote); // remote is not nullptr
    ASSERT_EQ(static_cast<uint32_t>(0), ActiveStatusCallbackManager::GetInstance().callbackDataList_.size());

    // recovery
    ActiveStatusCallbackManager::GetInstance().callbackDataList_ = callbackDataList;
}

/**
 * @tc.name: OnApplicationStateChanged001
 * @tc.desc: Test app state changed to APP_STATE_TERMINATED.
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(PermissionRecordManagerTest, OnApplicationStateChanged001, TestSize.Level1)
{
    AccessTokenIDEx tokenIdEx = PrivacyTestCommon::GetHapTokenIdFromBundle(
        g_InfoParms1.userID, g_InfoParms1.bundleName, g_InfoParms1.instIndex);
    AccessTokenID tokenId = tokenIdEx.tokenIdExStruct.tokenID;
    ASSERT_NE(INVALID_TOKENID, tokenId);

    PrivacyAppStateObserver observer;
    std::vector<std::string> permList = {"ohos.permission.CAMERA"};

    auto callbackPtr = std::make_shared<PermissionRecordManagerCoverTestCb3>(permList);
    callbackPtr->type_ = PERM_ACTIVE_IN_FOREGROUND;

    ASSERT_EQ(RET_SUCCESS, PrivacyKit::RegisterPermActiveStatusCallback(callbackPtr));
    ASSERT_EQ(RET_SUCCESS, PrivacyKit::StartUsingPermission(tokenId, "ohos.permission.CAMERA"));
    AppStateData appStateData;
    appStateData.state = static_cast<int32_t>(ApplicationState::APP_STATE_TERMINATED);
    appStateData.accessTokenId = tokenId;
    observer.OnAppStopped(appStateData);

    usleep(500000); // 500000us = 0.5s
    ASSERT_EQ(PERM_ACTIVE_IN_BACKGROUND, callbackPtr->type_);

    ASSERT_EQ(RET_SUCCESS, PrivacyKit::StopUsingPermission(tokenId, "ohos.permission.CAMERA"));
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
 * @tc.name: UpdateRecords001
 * @tc.desc: PermissionRecordManager::UpdateRecords function test
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(PermissionRecordManagerTest, UpdateRecords001, TestSize.Level1)
{
    AccessTokenIDEx tokenIdEx = PrivacyTestCommon::GetHapTokenIdFromBundle(
        g_InfoParms1.userID, g_InfoParms1.bundleName, g_InfoParms1.instIndex);
    AccessTokenID tokenId = tokenIdEx.tokenIdExStruct.tokenID;
    ASSERT_NE(INVALID_TOKENID, tokenId);

    PermissionUsageFlag flag = FLAG_PERMISSION_USAGE_SUMMARY;
    PermissionUsedRecord inBundleRecord;
    PermissionUsedRecord outBundleRecord;

    inBundleRecord.lastAccessTime = 1000;
    outBundleRecord.lastAccessTime = 900;
    // inBundleRecord.lastAccessTime > outBundleRecord.lastAccessTime && flag == 0
    PermissionRecordManager::GetInstance().MergeSamePermission(flag, inBundleRecord, outBundleRecord);

    UsedRecordDetail detail;
    detail.accessDuration = 10;
    detail.status = PERM_ACTIVE_IN_FOREGROUND;
    detail.timestamp = 10000;
    flag = FLAG_PERMISSION_USAGE_DETAIL;
    inBundleRecord.lastRejectTime = 1000;
    inBundleRecord.accessRecords.emplace_back(detail);
    inBundleRecord.rejectRecords.emplace_back(detail);
    // flag != 0 && inBundleRecord.lastRejectTime > 0 && outBundleRecord.accessRecords.size() < 10
    // && inBundleRecord.lastRejectTime > 0 && outBundleRecord.rejectRecords.size() < 10
    PermissionRecordManager::GetInstance().MergeSamePermission(flag, inBundleRecord, outBundleRecord);

    std::vector<UsedRecordDetail> accessRecords(11, detail);
    outBundleRecord.accessRecords = accessRecords;
    outBundleRecord.rejectRecords = accessRecords;
    // flag != 0 && inBundleRecord.lastRejectTime > 0 && outBundleRecord.accessRecords.size() >= 10
    // && inBundleRecord.lastRejectTime > 0 && outBundleRecord.rejectRecords.size() >= 10
    PermissionRecordManager::GetInstance().MergeSamePermission(flag, inBundleRecord, outBundleRecord);

    inBundleRecord.lastAccessTime = 0;
    inBundleRecord.lastRejectTime = 0;
    // flag != 0 && inBundleRecord.lastRejectTime <= 0 && outBundleRecord.accessRecords.size() >= 10
    // && inBundleRecord.lastRejectTime <= 0 && outBundleRecord.rejectRecords.size() >= 10
    PermissionRecordManager::GetInstance().MergeSamePermission(flag, inBundleRecord, outBundleRecord);
}

/*
 * @tc.name: RemoveRecordFromStartList001
 * @tc.desc: PermissionRecordManager::RemoveRecordFromStartList function test
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(PermissionRecordManagerTest, RemoveRecordFromStartList001, TestSize.Level1)
{
    AccessTokenIDEx tokenIdEx = PrivacyTestCommon::GetHapTokenIdFromBundle(
        g_InfoParms1.userID, g_InfoParms1.bundleName, g_InfoParms1.instIndex);
    AccessTokenID tokenId = tokenIdEx.tokenIdExStruct.tokenID;
    ASSERT_NE(INVALID_TOKENID, tokenId);

    std::string permission = "ohos.permission.READ_MEDIA";
    ASSERT_EQ(Constant::SUCCESS,
        PermissionRecordManager::GetInstance().StartUsingPermission(
        MakeInfo(tokenId, PID, "ohos.permission.READ_MEDIA"), CALLER_PID));
    // it->opcode == record.opcode && it->tokenId == record.tokenId
    PermissionRecordManager::GetInstance().RemoveRecordFromStartList(
        tokenId, PID, "ohos.permission.READ_MEDIA", CALLER_PID);

    ASSERT_EQ(Constant::SUCCESS,
        PermissionRecordManager::GetInstance().StartUsingPermission(
        MakeInfo(tokenId, PID, "ohos.permission.READ_MEDIA"), CALLER_PID));
    // it->opcode == record.opcode && it->tokenId != record.tokenId
    PermissionRecordManager::GetInstance().RemoveRecordFromStartList(
        RANDOM_TOKENID, PID, "ohos.permission.READ_MEDIA", CALLER_PID);

    // it->opcode != record.opcode && it->tokenId != record.tokenId
    PermissionRecordManager::GetInstance().RemoveRecordFromStartList(
        tokenId, PID, "ohos.permission.MICROPHONE", CALLER_PID);

    ASSERT_EQ(Constant::SUCCESS,
        PermissionRecordManager::GetInstance().StopUsingPermission(
        tokenId, PID, "ohos.permission.READ_MEDIA", CALLER_PID));
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
 * @tc.name: Unregister001
 * @tc.desc: PermissionRecordManager::Unregister function test
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(PermissionRecordManagerTest, Unregister001, TestSize.Level1)
{
    AccessTokenIDEx tokenIdEx = PrivacyTestCommon::GetHapTokenIdFromBundle(
        g_InfoParms1.userID, g_InfoParms1.bundleName, g_InfoParms1.instIndex);
    AccessTokenID tokenId = tokenIdEx.tokenIdExStruct.tokenID;
    ASSERT_NE(INVALID_TOKENID, tokenId);

    ASSERT_EQ(Constant::SUCCESS, PermissionRecordManager::GetInstance().StartUsingPermission(
        MakeInfo(tokenId, PID, "ohos.permission.READ_MEDIA"), CALLER_PID));

    PermissionRecordManager::GetInstance().Unregister();
    PermissionRecordManager::GetInstance().Unregister();

    ASSERT_EQ(Constant::SUCCESS, PermissionRecordManager::GetInstance().StopUsingPermission(
        tokenId, PID, "ohos.permission.READ_MEDIA", CALLER_PID));
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
 * @tc.name: GetRecords002
 * @tc.desc: test query record return max count 500.
 * @tc.type: FUNC
 * @tc.require: issueI5P4IU
 */
HWTEST_F(PermissionRecordManagerTest, GetRecords002, TestSize.Level1)
{
    std::vector<GenericValues> values;
    int32_t num = MAX_DETAIL_NUM + 1;
    AddRecord(num, values);

    PermissionUsedRequest request;
    request.isRemote = false;
    request.flag = PermissionUsageFlag::FLAG_PERMISSION_USAGE_DETAIL;

    std::set<int32_t> opCodeList;
    GenericValues andConditionValues;
    std::vector<GenericValues> findRecordsValues;
    PermissionUsedRecordDb::GetInstance().FindByConditions(PermissionUsedRecordDb::DataType::PERMISSION_RECORD,
        opCodeList, andConditionValues, findRecordsValues, MAX_DETAIL_NUM);
    EXPECT_EQ(static_cast<size_t>(MAX_DETAIL_NUM), findRecordsValues.size());

    PermissionUsedRecordDb::DataType type = PermissionUsedRecordDb::PERMISSION_RECORD;
    for (const auto& value : values) {
        ASSERT_EQ(0, PermissionUsedRecordDb::GetInstance().Remove(type, value));
    }
}

static void GeneratePermissionRecord(AccessTokenID tokenID)
{
    int64_t timestamp = AccessToken::TimeUtil::GetCurrentTimestamp();

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
 * @tc.name: GetRecords003
 * @tc.desc: test query record flag 2 | 3 | 4 | 5
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(PermissionRecordManagerTest, GetRecords003, TestSize.Level1)
{
    MockNativeToken mock("privacy_service");
    AccessTokenIDEx tokenIdEx = PrivacyTestCommon::GetHapTokenIdFromBundle(
        g_InfoParms1.userID, g_InfoParms1.bundleName, g_InfoParms1.instIndex);
    AccessTokenID tokenID = tokenIdEx.tokenIdExStruct.tokenID;
    ASSERT_NE(INVALID_TOKENID, tokenID);

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

/**
 * @tc.name: GetRecords004
 * @tc.desc: test query record from local dd failed
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(PermissionRecordManagerTest, GetRecords004, TestSize.Level1)
{
    AccessTokenIDEx tokenIdEx = PrivacyTestCommon::GetHapTokenIdFromBundle(
        g_InfoParms1.userID, g_InfoParms1.bundleName, g_InfoParms1.instIndex);
    AccessTokenID tokenID = tokenIdEx.tokenIdExStruct.tokenID;
    ASSERT_NE(INVALID_TOKENID, tokenID);

    GeneratePermissionRecord(tokenID);
    PermissionRecordManager::GetInstance().SetDefaultConfigValue();

    PermissionUsedRequest request;
    request.tokenId = tokenID;
    request.isRemote = false;
    request.beginTimeMillis = -1;

    PermissionUsedResult result;
    EXPECT_EQ(ERR_PARAM_INVALID, PermissionRecordManager::GetInstance().GetPermissionUsedRecords(request, result));
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
    request.tokenId = 0;
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

/*
 * @tc.name: AddOrUpdateUsedStatusIfNeeded001
 * @tc.desc: PermissionRecordManager::AddOrUpdateUsedStatusIfNeeded function test
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(PermissionRecordManagerTest, AddOrUpdateUsedStatusIfNeeded001, TestSize.Level1)
{
    PermissionUsedRecordDb::DataType type = PermissionUsedRecordDb::DataType::PERMISSION_USED_RECORD_TOGGLE_STATUS;
    bool ret = PermissionRecordManager::GetInstance().AddOrUpdateUsedStatusIfNeeded(TEST_USER_ID_11, false);
    EXPECT_TRUE(ret);

    GenericValues conditionValue;
    conditionValue.Put(PrivacyFiledConst::FIELD_USER_ID, TEST_USER_ID_11);
    std::vector<GenericValues> results;
    ASSERT_EQ(0, PermissionUsedRecordDb::GetInstance().Query(type, conditionValue, results));
    ASSERT_FALSE(results.empty());
    for (const auto& result : results) {
        if (TEST_USER_ID_11 == result.GetInt(PrivacyFiledConst::FIELD_USER_ID)) {
            ASSERT_FALSE(static_cast<bool>(result.GetInt(PrivacyFiledConst::FIELD_STATUS)));
            break;
        }
    }
    results.clear();

    ret = PermissionRecordManager::GetInstance().AddOrUpdateUsedStatusIfNeeded(TEST_USER_ID_11, true);
    EXPECT_TRUE(ret);
    ASSERT_EQ(0, PermissionUsedRecordDb::GetInstance().Query(type, conditionValue, results));
    ASSERT_FALSE(results.empty());
    for (const auto& result : results) {
        if (TEST_USER_ID_11 == result.GetInt(PrivacyFiledConst::FIELD_USER_ID)) {
            ASSERT_TRUE(static_cast<bool>(result.GetInt(PrivacyFiledConst::FIELD_STATUS)));
            break;
        }
    }
}

/*
 * @tc.name: AddOrUpdateUsedTypeIfNeeded001
 * @tc.desc: PermissionRecordManager::AddOrUpdateUsedTypeIfNeeded function test
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(PermissionRecordManagerTest, AddOrUpdateUsedTypeIfNeeded001, TestSize.Level1)
{
    int32_t tokenId = static_cast<int32_t>(RANDOM_TOKENID);
    int32_t opCode = static_cast<int32_t>(Constant::OpCode::OP_ANSWER_CALL);
    PermissionUsedType visitType = PermissionUsedType::NORMAL_TYPE;
    PermissionUsedRecordDb::DataType type = PermissionUsedRecordDb::PERMISSION_USED_TYPE;
    GenericValues conditionValue;
    conditionValue.Put(PrivacyFiledConst::FIELD_TOKEN_ID, tokenId);
    conditionValue.Put(PrivacyFiledConst::FIELD_PERMISSION_CODE, opCode);

    // query result empty, add input type
    ASSERT_EQ(true, PermissionRecordManager::GetInstance().AddOrUpdateUsedTypeIfNeeded(
        RANDOM_TOKENID, opCode, visitType));
    std::vector<GenericValues> results;
    ASSERT_EQ(0, PermissionUsedRecordDb::GetInstance().Query(type, conditionValue, results));
    ASSERT_EQ(false, results.empty());
    for (const auto& result : results) {
        if (tokenId == result.GetInt(PrivacyFiledConst::FIELD_TOKEN_ID)) {
            ASSERT_EQ(static_cast<int32_t>(Constant::OpCode::OP_ANSWER_CALL),
                result.GetInt(PrivacyFiledConst::FIELD_PERMISSION_CODE));
            ASSERT_EQ(PERMISSION_USED_TYPE_VALUE, result.GetInt(PrivacyFiledConst::FIELD_USED_TYPE));
            break;
        }
    }
    results.clear();

    // uesd type exsit and same to input type, return
    ASSERT_EQ(true, PermissionRecordManager::GetInstance().AddOrUpdateUsedTypeIfNeeded(
        RANDOM_TOKENID, opCode, visitType));
    ASSERT_EQ(0, PermissionUsedRecordDb::GetInstance().Query(type, conditionValue, results));
    for (const auto& result : results) {
        if (tokenId == result.GetInt(PrivacyFiledConst::FIELD_TOKEN_ID)) {
            ASSERT_EQ(static_cast<int32_t>(Constant::OpCode::OP_ANSWER_CALL),
                result.GetInt(PrivacyFiledConst::FIELD_PERMISSION_CODE));
            ASSERT_EQ(PERMISSION_USED_TYPE_VALUE, result.GetInt(PrivacyFiledConst::FIELD_USED_TYPE));
            break;
        }
    }
    results.clear();

    visitType = PermissionUsedType::PICKER_TYPE;
    // used type exsit and diff from input type, update the type
    ASSERT_EQ(true, PermissionRecordManager::GetInstance().AddOrUpdateUsedTypeIfNeeded(
        RANDOM_TOKENID, opCode, visitType));
    ASSERT_EQ(0, PermissionUsedRecordDb::GetInstance().Query(type, conditionValue, results));
    for (const auto& result : results) {
        if (tokenId == result.GetInt(PrivacyFiledConst::FIELD_TOKEN_ID)) {
            ASSERT_EQ(static_cast<int32_t>(Constant::OpCode::OP_ANSWER_CALL),
                result.GetInt(PrivacyFiledConst::FIELD_PERMISSION_CODE));
            ASSERT_EQ(PERMISSION_USED_TYPE_WITH_PICKER_TYPE_VALUE, result.GetInt(PrivacyFiledConst::FIELD_USED_TYPE));
            break;
        }
    }

    ASSERT_EQ(0, PermissionUsedRecordDb::GetInstance().Remove(type, conditionValue));
}

/**
 * @tc.name: DeletePermissionRecord001
 * @tc.desc: delete permission record when records excessive.
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(PermissionRecordManagerTest, DeletePermissionRecord001, TestSize.Level1)
{
    int32_t recordSize = PermissionRecordManager::GetInstance().recordSizeMaximum_;
    PermissionRecordManager::GetInstance().recordSizeMaximum_ = MAX_DETAIL_NUM;
    std::vector<GenericValues> values;
    int32_t num = MAX_DETAIL_NUM + 1;
    AddRecord(num, values);

    EXPECT_EQ(Constant::SUCCESS, PermissionRecordManager::GetInstance().DeletePermissionRecord(1));
    PermissionUsedRecordDb::DataType type = PermissionUsedRecordDb::PERMISSION_RECORD;
    EXPECT_NE(num, PermissionUsedRecordDb::GetInstance().Count(type));
    for (const auto& value : values) {
        EXPECT_EQ(0, PermissionUsedRecordDb::GetInstance().Remove(type, value));
    }
    PermissionRecordManager::GetInstance().recordSizeMaximum_ = recordSize;
}

/*
 * @tc.name: RemoveRecordFromStartListTest001
 * @tc.desc: remove record from start list test
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(PermissionRecordManagerTest, RemoveRecordFromStartListTest001, TestSize.Level1)
{
    std::set<ContinusPermissionRecord> startRecordList = PermissionRecordManager::GetInstance().startRecordList_;
    PermissionRecordManager::GetInstance().startRecordList_.clear();
    std::vector<std::string> reqPerm;
    reqPerm.emplace_back("ohos.permission.CAMERA");
    reqPerm.emplace_back("ohos.permission.MANAGE_CAMERA_CONFIG");
    MockHapToken mock("RemoveRecordFromStartListTest001", reqPerm, false);

    AccessTokenID tokenId = GetSelfTokenID();;

    ActiveChangeType status = PERM_ACTIVE_IN_FOREGROUND;
    PermissionRecordManager::GetInstance().AddRecordToStartList(
        MakeInfo(tokenId, PID, "ohos.permission.CAMERA"), status, CALLER_PID);
    PermissionRecordManager::GetInstance().AddRecordToStartList(
        MakeInfo(0, PID, "ohos.permission.MICROPHONE"), status, CALLER_PID);
    PermissionRecordManager::GetInstance().RemoveRecordFromStartListByToken(tokenId);
    ASSERT_EQ(1, PermissionRecordManager::GetInstance().startRecordList_.size());
    PermissionRecordManager::GetInstance().startRecordList_ = startRecordList;
}

/*
 * @tc.name: StartUsingPermissionTest001
 * @tc.desc: start using camera permission when camera global switch is close
 * @tc.type: FUNC
 * @tc.require: issueI5RWXF
 */
HWTEST_F(PermissionRecordManagerTest, StartUsingPermissionTest001, TestSize.Level1)
{
    EXPECT_EQ(0, SetSelfTokenID(g_nativeToken));

    // true means close
    PermissionRecordManager::GetInstance().SetMutePolicy(PolicyType::PRIVACY, CallerType::CAMERA, true, RANDOM_TOKENID);

    auto callbackPtr = std::make_shared<PermissionRecordManagerCoverTestCb1>();
    auto callbackWrap = new (std::nothrow) StateChangeCallback(callbackPtr);
    ASSERT_NE(nullptr, callbackPtr);
    ASSERT_NE(nullptr, callbackWrap);
    AccessTokenID tokenId = AccessTokenKit::GetHapTokenID(g_InfoParms1.userID, g_InfoParms1.bundleName,
        g_InfoParms1.instIndex);
    ASSERT_NE(INVALID_TOKENID, tokenId);
    ASSERT_EQ(RET_SUCCESS, PermissionRecordManager::GetInstance().StartUsingPermission(
        MakeInfo(tokenId, PID, "ohos.permission.CAMERA"), callbackWrap->AsObject(), CALLER_PID));
    sleep(3); // wait for dialog disappear
    ASSERT_EQ(0, PermissionRecordManager::GetInstance().StopUsingPermission(
        tokenId, PID, "ohos.permission.CAMERA", CALLER_PID));
}

/*
 * @tc.name: CreatePermissionUsedTypeTable001
 * @tc.desc: PermissionUsedRecordDb::CreatePermissionUsedTypeTable function test
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(PermissionRecordManagerTest, CreatePermissionUsedTypeTable001, TestSize.Level1)
{
    ASSERT_EQ(0, PermissionUsedRecordDb::GetInstance().CreatePermissionUsedTypeTable());

    std::map<PermissionUsedRecordDb::DataType, SqliteTable> dataTypeToSqlTable;
    dataTypeToSqlTable = PermissionUsedRecordDb::GetInstance().dataTypeToSqlTable_; // backup
    PermissionUsedRecordDb::GetInstance().dataTypeToSqlTable_.clear();

    ASSERT_EQ(Constant::FAILURE, PermissionUsedRecordDb::GetInstance().CreatePermissionUsedTypeTable());
    PermissionUsedRecordDb::GetInstance().dataTypeToSqlTable_ = dataTypeToSqlTable; // recovery
}

/*
 * @tc.name: InsertPermissionUsedTypeColumn001
 * @tc.desc: PermissionUsedRecordDb::InsertPermissionUsedTypeColumn function test
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(PermissionRecordManagerTest, InsertPermissionUsedTypeColumn001, TestSize.Level1)
{
    ASSERT_EQ(Constant::SUCCESS, PermissionUsedRecordDb::GetInstance().InsertPermissionUsedTypeColumn());

    std::map<PermissionUsedRecordDb::DataType, SqliteTable> dataTypeToSqlTable;
    dataTypeToSqlTable = PermissionUsedRecordDb::GetInstance().dataTypeToSqlTable_; // backup
    PermissionUsedRecordDb::GetInstance().dataTypeToSqlTable_.clear();

    ASSERT_EQ(Constant::FAILURE, PermissionUsedRecordDb::GetInstance().InsertPermissionUsedTypeColumn());
    PermissionUsedRecordDb::GetInstance().dataTypeToSqlTable_ = dataTypeToSqlTable; // recovery
}
} // namespace AccessToken
} // namespace Security
} // namespace OHOS
