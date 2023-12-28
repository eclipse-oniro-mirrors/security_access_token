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
#include "data_translator.h"
#include "permission_record.h"
#define private public
#include "active_status_callback_manager.h"
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
constexpr const char* CAMERA_PERMISSION_NAME = "ohos.permission.CAMERA";
constexpr const char* MICROPHONE_PERMISSION_NAME = "ohos.permission.MICROPHONE";
constexpr const char* LOCATION_PERMISSION_NAME = "ohos.permission.LOCATION";
static constexpr uint32_t MAX_CALLBACK_SIZE = 1024;
static constexpr int32_t MAX_DETAIL_NUM = 500;
static constexpr int64_t ONE_SECOND = 1000;
static constexpr int64_t TWO_SECOND = 2000;
static constexpr int64_t THREE_SECOND = 3000;
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
 * @tc.name: FindRecordsToUpdateAndExecutedTest005
 * @tc.desc: FindRecordsToUpdateAndExecuted function test with invaild tokenId or permissionName or callback.
 * @tc.type: FUNC
 * @tc.require: issueI5RWX5 issueI5RWX3 issueI5RWXA
 */
HWTEST_F(PermissionRecordManagerTest, FindRecordsToUpdateAndExecutedTest005, TestSize.Level1)
{
    AccessTokenID tokenId = AccessTokenKit::GetHapTokenID(g_InfoParms1.userID, g_InfoParms1.bundleName,
        g_InfoParms1.instIndex);
    ASSERT_NE(INVALID_TOKENID, tokenId);
    ActiveChangeType status = PERM_ACTIVE_IN_BACKGROUND;

    PermissionRecord record1 = {
        .tokenId = tokenId,
        .opCode = Constant::OP_MICROPHONE,
        .status = PERM_ACTIVE_IN_FOREGROUND,
        .timestamp = TimeUtil::GetCurrentTimestamp(),
        .accessCount = 1,
        .lockScreenStatus = PERM_ACTIVE_IN_LOCKED,
    };
    PermissionRecordManager::GetInstance().startRecordList_.emplace_back(record1);

    PermissionRecordManager::GetInstance().FindRecordsToUpdateAndExecuted(tokenId, status);

    std::string permissionName = MICROPHONE_PERMISSION_NAME;
    std::vector<std::string> permissionList;
    permissionList.emplace_back(permissionName);
    PermissionUsedRequest request = {
        .tokenId = tokenId,
        .permissionList = permissionList,
        .flag = FLAG_PERMISSION_USAGE_DETAIL
    };

    PermissionUsedResult queryResult;
    PermissionRecordManager::GetInstance().GetPermissionUsedRecords(request, queryResult);
    ASSERT_NE(queryResult.bundleRecords.size(), 0);
    auto bundleRecordIter = std::find_if(queryResult.bundleRecords.begin(), queryResult.bundleRecords.end(),
        [tokenId](const BundleUsedRecord& bur) {
            return tokenId == bur.tokenId;
        });
    ASSERT_NE(bundleRecordIter, queryResult.bundleRecords.end());

    auto permissionRecordIter = std::find_if(bundleRecordIter->permissionRecords.begin(),
        bundleRecordIter->permissionRecords.end(),
        [permissionName](const PermissionUsedRecord& prs) {
            return permissionName == prs.permissionName;
        });
    ASSERT_NE(permissionRecordIter, bundleRecordIter->permissionRecords.end());

    ASSERT_EQ(1, permissionRecordIter->accessRecords.size());
    ASSERT_EQ(PERM_ACTIVE_IN_BACKGROUND, permissionRecordIter->accessRecords[0].status);
    ASSERT_EQ(PERM_ACTIVE_IN_UNLOCKED, permissionRecordIter->accessRecords[0].lockScreenStatus);
}

PermissionUsedRequest GenerateRequest(AccessTokenID tokenId, std::string permissionName)
{
    std::vector<std::string> permissionList;
    permissionList.emplace_back(permissionName);
    PermissionUsedRequest request = {
        .tokenId = tokenId,
        .permissionList = permissionList,
        .flag = FLAG_PERMISSION_USAGE_DETAIL
    };
    return request;
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

    PermissionRecord record = {
        .tokenId = tokenId,
        .opCode = Constant::OP_MICROPHONE,
        .status = PERM_ACTIVE_IN_FOREGROUND,
        .timestamp = TimeUtil::GetCurrentTimestamp(),
        .accessCount = 1,
        .lockScreenStatus = PERM_ACTIVE_IN_UNLOCKED
    };
    PermissionRecordManager::GetInstance().startRecordList_.emplace_back(record);
    LockScreenStatusChangeType screenLocked = PERM_ACTIVE_IN_LOCKED;
    PermissionRecordManager::GetInstance().NotifyLockScreenStatusChange(screenLocked);

    std::string permissionName = MICROPHONE_PERMISSION_NAME;
    PermissionUsedRequest request = GenerateRequest(tokenId, permissionName);

    PermissionUsedResult result;
    PermissionRecordManager::GetInstance().GetPermissionUsedRecords(request, result);
    auto bundleRecordIter = std::find_if(result.bundleRecords.begin(), result.bundleRecords.end(),
        [tokenId](const BundleUsedRecord& bur) {
            return tokenId == bur.tokenId;
        });
    ASSERT_NE(bundleRecordIter, result.bundleRecords.end());

    auto permissionRecordIter = std::find_if(bundleRecordIter->permissionRecords.begin(),
        bundleRecordIter->permissionRecords.end(),
        [permissionName](const PermissionUsedRecord& prs) {
            return permissionName == prs.permissionName;
        });
    ASSERT_NE(permissionRecordIter, bundleRecordIter->permissionRecords.end());

    ASSERT_EQ(1, permissionRecordIter->accessRecords.size());
    ASSERT_EQ(PERM_ACTIVE_IN_FOREGROUND, permissionRecordIter->accessRecords[0].status);
    ASSERT_EQ(PERM_ACTIVE_IN_UNLOCKED, permissionRecordIter->accessRecords[0].lockScreenStatus);
}

void GenerateLockScreenPerUsedRecord(AccessTokenID tokenId1, AccessTokenID tokenId2)
{
    PermissionRecord record1 = {
        .tokenId = tokenId1,
        .opCode = Constant::OP_MICROPHONE,
        .status = PERM_ACTIVE_IN_FOREGROUND,
        .timestamp = TimeUtil::GetCurrentTimestamp(),
        .accessCount = 1,
        .lockScreenStatus = PERM_ACTIVE_IN_UNLOCKED
    };

    PermissionRecord record2 = {
        .tokenId = tokenId2,
        .opCode = Constant::OP_MICROPHONE,
        .status = PERM_ACTIVE_IN_BACKGROUND,
        .timestamp = TimeUtil::GetCurrentTimestamp(),
        .accessCount = 1,
        .lockScreenStatus = PERM_ACTIVE_IN_UNLOCKED
    };
    PermissionRecordManager::GetInstance().startRecordList_.emplace_back(record1);
    PermissionRecordManager::GetInstance().startRecordList_.emplace_back(record2);
    LockScreenStatusChangeType screenLocked = PERM_ACTIVE_IN_LOCKED;
    PermissionRecordManager::GetInstance().GenerateRecordsWhenScreenStatusChanged(screenLocked);
}

/*
 * @tc.name: GenerateRecordsWhenScreenStatusChangedTest002
 * @tc.desc: FindRecordsToUpdateAndExecuted function test with invaild tokenId or permissionName or callback.
 * @tc.type: FUNC
 * @tc.require: issueI5RWX5 issueI5RWX3 issueI5RWXA
 */
HWTEST_F(PermissionRecordManagerTest, GenerateRecordsWhenScreenStatusChangedTest002, TestSize.Level1)
{
    AccessTokenID tokenId1 = AccessTokenKit::GetHapTokenID(g_InfoParms1.userID, g_InfoParms1.bundleName,
        g_InfoParms1.instIndex);
    ASSERT_NE(INVALID_TOKENID, tokenId1);
    EXPECT_EQ(0, SetSelfTokenID(tokenId1));

    AccessTokenID tokenId2 = AccessTokenKit::GetHapTokenID(g_InfoParms2.userID, g_InfoParms2.bundleName,
        g_InfoParms2.instIndex);
    ASSERT_NE(INVALID_TOKENID, tokenId2);
    EXPECT_EQ(0, SetSelfTokenID(tokenId2));

    GenerateLockScreenPerUsedRecord(tokenId1, tokenId2);

    std::string permissionName = MICROPHONE_PERMISSION_NAME;
    PermissionUsedRequest request1 = GenerateRequest(tokenId1, permissionName);
    PermissionUsedResult result1;
    PermissionRecordManager::GetInstance().GetPermissionUsedRecords(request1, result1);
    auto bundleRecordIter1 = std::find_if(result1.bundleRecords.begin(), result1.bundleRecords.end(),
        [tokenId1](const BundleUsedRecord& bur) {
            return tokenId1 == bur.tokenId;
        });
    ASSERT_NE(bundleRecordIter1, result1.bundleRecords.end());

    auto permissionRecordIter1 = std::find_if(bundleRecordIter1->permissionRecords.begin(),
        bundleRecordIter1->permissionRecords.end(),
        [permissionName](const PermissionUsedRecord& prs) {
            return permissionName == prs.permissionName;
        });
    ASSERT_NE(permissionRecordIter1, bundleRecordIter1->permissionRecords.end());

    ASSERT_EQ(1, permissionRecordIter1->accessRecords.size());
    ASSERT_EQ(PERM_ACTIVE_IN_FOREGROUND, permissionRecordIter1->accessRecords[0].status);
    ASSERT_EQ(PERM_ACTIVE_IN_UNLOCKED, permissionRecordIter1->accessRecords[0].lockScreenStatus);

    PermissionUsedRequest request2 = GenerateRequest(tokenId2, permissionName);
    PermissionUsedResult result2;
    PermissionRecordManager::GetInstance().GetPermissionUsedRecords(request2, result2);
    auto bundleRecordIter2 = std::find_if(result2.bundleRecords.begin(), result2.bundleRecords.end(),
        [tokenId2](const BundleUsedRecord& bur) {
            return tokenId2 == bur.tokenId;
        });
    ASSERT_NE(bundleRecordIter2, result2.bundleRecords.end());

    auto permissionRecordIter2 = std::find_if(bundleRecordIter2->permissionRecords.begin(),
        bundleRecordIter2->permissionRecords.end(),
        [permissionName](const PermissionUsedRecord& prs) {
            return permissionName == prs.permissionName;
        });
    ASSERT_NE(permissionRecordIter2, bundleRecordIter2->permissionRecords.end());

    ASSERT_EQ(1, permissionRecordIter2->accessRecords.size());
    ASSERT_EQ(PERM_ACTIVE_IN_BACKGROUND, permissionRecordIter2->accessRecords[0].status);
    ASSERT_EQ(PERM_ACTIVE_IN_UNLOCKED, permissionRecordIter2->accessRecords[0].lockScreenStatus);
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
    EXPECT_EQ(0, SetSelfTokenID(tokenId));

    PermissionRecord record = {
        .tokenId = tokenId,
        .opCode = Constant::OP_MICROPHONE,
        .status = PERM_ACTIVE_IN_BACKGROUND,
        .timestamp = TimeUtil::GetCurrentTimestamp(),
        .accessCount = 1,
        .lockScreenStatus = PERM_ACTIVE_IN_UNLOCKED
    };

    PermissionRecordManager::GetInstance().startRecordList_.emplace_back(record);
    LockScreenStatusChangeType screenLocked = PERM_ACTIVE_IN_LOCKED;
    PermissionRecordManager::GetInstance().GenerateRecordsWhenScreenStatusChanged(screenLocked);

    std::string permissionName = MICROPHONE_PERMISSION_NAME;
    PermissionUsedRequest request = GenerateRequest(tokenId, permissionName);
    PermissionUsedResult result;
    PermissionRecordManager::GetInstance().GetPermissionUsedRecords(request, result);
    auto bundleRecordIter = std::find_if(result.bundleRecords.begin(), result.bundleRecords.end(),
        [tokenId](const BundleUsedRecord& bur) {
            return tokenId == bur.tokenId;
        });
    ASSERT_NE(bundleRecordIter, result.bundleRecords.end());

    auto permissionRecordIter = std::find_if(bundleRecordIter->permissionRecords.begin(),
        bundleRecordIter->permissionRecords.end(),
        [permissionName](const PermissionUsedRecord& prs) {
            return permissionName == prs.permissionName;
        });
    ASSERT_NE(permissionRecordIter, bundleRecordIter->permissionRecords.end());

    ASSERT_EQ(1, permissionRecordIter->accessRecords.size());
    ASSERT_EQ(PERM_ACTIVE_IN_BACKGROUND, permissionRecordIter->accessRecords[0].status);
    ASSERT_EQ(PERM_ACTIVE_IN_UNLOCKED, permissionRecordIter->accessRecords[0].lockScreenStatus);
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
    EXPECT_EQ(0, SetSelfTokenID(tokenId));

    PermissionRecord record = {
        .tokenId = tokenId,
        .opCode = Constant::OP_MICROPHONE,
        .status = PERM_ACTIVE_IN_FOREGROUND,
        .timestamp = TimeUtil::GetCurrentTimestamp(),
        .accessCount = 1,
        .lockScreenStatus = PERM_ACTIVE_IN_LOCKED
    };

    PermissionRecordManager::GetInstance().startRecordList_.emplace_back(record);
    LockScreenStatusChangeType screenUnLocked = PERM_ACTIVE_IN_UNLOCKED;
    PermissionRecordManager::GetInstance().GenerateRecordsWhenScreenStatusChanged(screenUnLocked);

    std::string permissionName = MICROPHONE_PERMISSION_NAME;
    PermissionUsedRequest request = GenerateRequest(tokenId, permissionName);
    PermissionUsedResult result;
    PermissionRecordManager::GetInstance().GetPermissionUsedRecords(request, result);
    auto bundleRecordIter = std::find_if(result.bundleRecords.begin(), result.bundleRecords.end(),
        [tokenId](const BundleUsedRecord& bur) {
            return tokenId == bur.tokenId;
        });
    ASSERT_NE(bundleRecordIter, result.bundleRecords.end());

    auto permissionRecordIter = std::find_if(bundleRecordIter->permissionRecords.begin(),
        bundleRecordIter->permissionRecords.end(),
        [permissionName](const PermissionUsedRecord& prs) {
            return permissionName == prs.permissionName;
        });
    ASSERT_NE(permissionRecordIter, bundleRecordIter->permissionRecords.end());

    ASSERT_EQ(1, permissionRecordIter->accessRecords.size());
    ASSERT_EQ(PERM_ACTIVE_IN_BACKGROUND, permissionRecordIter->accessRecords[0].status);
    ASSERT_EQ(PERM_ACTIVE_IN_UNLOCKED, permissionRecordIter->accessRecords[0].lockScreenStatus);
}

void GenerateUnLockScreenPerUsedRecord(AccessTokenID tokenId1, AccessTokenID tokenId2)
{
    PermissionRecord record1 = {
        .tokenId = tokenId1,
        .opCode = Constant::OP_MICROPHONE,
        .status = PERM_ACTIVE_IN_FOREGROUND,
        .timestamp = TimeUtil::GetCurrentTimestamp(),
        .accessCount = 1,
        .lockScreenStatus = PERM_ACTIVE_IN_LOCKED
    };

    PermissionRecord record2 = {
        .tokenId = tokenId2,
        .opCode = Constant::OP_MICROPHONE,
        .status = PERM_ACTIVE_IN_BACKGROUND,
        .timestamp = TimeUtil::GetCurrentTimestamp(),
        .accessCount = 1,
        .lockScreenStatus = PERM_ACTIVE_IN_LOCKED
    };
    PermissionRecordManager::GetInstance().startRecordList_.emplace_back(record1);
    PermissionRecordManager::GetInstance().startRecordList_.emplace_back(record2);
    LockScreenStatusChangeType screenUnLocked = PERM_ACTIVE_IN_UNLOCKED;
    PermissionRecordManager::GetInstance().GenerateRecordsWhenScreenStatusChanged(screenUnLocked);
}

/*
 * @tc.name: GenerateRecordsWhenScreenStatusChangedTest005
 * @tc.desc: FindRecordsToUpdateAndExecuted function test with invaild tokenId or permissionName or callback.
 * @tc.type: FUNC
 * @tc.require: issueI5RWX5 issueI5RWX3 issueI5RWXA
 */
HWTEST_F(PermissionRecordManagerTest, GenerateRecordsWhenScreenStatusChangedTest005, TestSize.Level1)
{
    AccessTokenID tokenId1 = AccessTokenKit::GetHapTokenID(g_InfoParms1.userID, g_InfoParms1.bundleName,
        g_InfoParms1.instIndex);
    ASSERT_NE(INVALID_TOKENID, tokenId1);
    EXPECT_EQ(0, SetSelfTokenID(tokenId1));

    AccessTokenID tokenId2 = AccessTokenKit::GetHapTokenID(g_InfoParms2.userID, g_InfoParms2.bundleName,
        g_InfoParms2.instIndex);
    ASSERT_NE(INVALID_TOKENID, tokenId2);
    EXPECT_EQ(0, SetSelfTokenID(tokenId2));

    GenerateUnLockScreenPerUsedRecord(tokenId1, tokenId2);
    std::string permissionName = MICROPHONE_PERMISSION_NAME;
    PermissionUsedRequest request1 = GenerateRequest(tokenId1, permissionName);
    PermissionUsedResult result1;
    PermissionRecordManager::GetInstance().GetPermissionUsedRecords(request1, result1);
    auto bundleRecordIter1 = std::find_if(result1.bundleRecords.begin(), result1.bundleRecords.end(),
        [tokenId1](const BundleUsedRecord& bur) {
            return tokenId1 == bur.tokenId;
        });
    ASSERT_NE(bundleRecordIter1, result1.bundleRecords.end());

    auto permissionRecordIter1 = std::find_if(bundleRecordIter1->permissionRecords.begin(),
        bundleRecordIter1->permissionRecords.end(),
        [permissionName](const PermissionUsedRecord& prs) {
            return permissionName == prs.permissionName;
        });
    ASSERT_NE(permissionRecordIter1, bundleRecordIter1->permissionRecords.end());

    ASSERT_EQ(1, permissionRecordIter1->accessRecords.size());
    ASSERT_EQ(PERM_ACTIVE_IN_BACKGROUND, permissionRecordIter1->accessRecords[0].status);
    ASSERT_EQ(PERM_ACTIVE_IN_UNLOCKED, permissionRecordIter1->accessRecords[0].lockScreenStatus);

    PermissionUsedRequest request2 = GenerateRequest(tokenId2, permissionName);
    PermissionUsedResult result2;
    PermissionRecordManager::GetInstance().GetPermissionUsedRecords(request2, result2);
    auto bundleRecordIter2 = std::find_if(result2.bundleRecords.begin(), result2.bundleRecords.end(),
        [tokenId2](const BundleUsedRecord& bur) {
            return tokenId2 == bur.tokenId;
        });
    ASSERT_NE(bundleRecordIter2, result2.bundleRecords.end());

    auto permissionRecordIter2 = std::find_if(bundleRecordIter2->permissionRecords.begin(),
        bundleRecordIter2->permissionRecords.end(),
        [permissionName](const PermissionUsedRecord& prs) {
            return permissionName == prs.permissionName;
        });
    ASSERT_NE(permissionRecordIter2, bundleRecordIter2->permissionRecords.end());

    ASSERT_EQ(1, permissionRecordIter2->accessRecords.size());
    ASSERT_EQ(PERM_ACTIVE_IN_BACKGROUND, permissionRecordIter2->accessRecords[0].status);
    ASSERT_EQ(PERM_ACTIVE_IN_LOCKED, permissionRecordIter2->accessRecords[0].lockScreenStatus);
}

/*
 * @tc.name: GenerateRecordsWhenScreenStatusChangedTest006
 * @tc.desc: FindRecordsToUpdateAndExecuted function test with invaild tokenId or permissionName or callback.
 * @tc.type: FUNC
 * @tc.require: issueI5RWX5 issueI5RWX3 issueI5RWXA
 */
HWTEST_F(PermissionRecordManagerTest, GenerateRecordsWhenScreenStatusChangedTest006, TestSize.Level1)
{
    AccessTokenID tokenId = AccessTokenKit::GetHapTokenID(g_InfoParms1.userID, g_InfoParms1.bundleName,
        g_InfoParms1.instIndex);
    ASSERT_NE(INVALID_TOKENID, tokenId);
    EXPECT_EQ(0, SetSelfTokenID(tokenId));

    PermissionRecord record = {
        .tokenId = tokenId,
        .opCode = Constant::OP_MICROPHONE,
        .status = PERM_ACTIVE_IN_BACKGROUND,
        .timestamp = TimeUtil::GetCurrentTimestamp(),
        .accessCount = 1,
        .lockScreenStatus = PERM_ACTIVE_IN_LOCKED
    };
    PermissionRecordManager::GetInstance().startRecordList_.emplace_back(record);
    LockScreenStatusChangeType screenUnLocked = PERM_ACTIVE_IN_UNLOCKED;
    PermissionRecordManager::GetInstance().GenerateRecordsWhenScreenStatusChanged(screenUnLocked);

    std::string permissionName = MICROPHONE_PERMISSION_NAME;
    PermissionUsedRequest request = GenerateRequest(tokenId, permissionName);
    PermissionUsedResult result;
    PermissionRecordManager::GetInstance().GetPermissionUsedRecords(request, result);
    auto bundleRecordIter = std::find_if(result.bundleRecords.begin(), result.bundleRecords.end(),
        [tokenId](const BundleUsedRecord& bur) {
            return tokenId == bur.tokenId;
        });
    ASSERT_NE(bundleRecordIter, result.bundleRecords.end());

    auto permissionRecordIter = std::find_if(bundleRecordIter->permissionRecords.begin(),
        bundleRecordIter->permissionRecords.end(),
        [permissionName](const PermissionUsedRecord& prs) {
            return permissionName == prs.permissionName;
        });
    ASSERT_NE(permissionRecordIter, bundleRecordIter->permissionRecords.end());

    ASSERT_EQ(1, permissionRecordIter->accessRecords.size());
    ASSERT_EQ(PERM_ACTIVE_IN_BACKGROUND, permissionRecordIter->accessRecords[0].status);
    ASSERT_EQ(PERM_ACTIVE_IN_LOCKED, permissionRecordIter->accessRecords[0].lockScreenStatus);
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

    GenericValues value1;
    value1.Put(PrivacyFiledConst::FIELD_TOKEN_ID, static_cast<int32_t>(tokenID));
    value1.Put(PrivacyFiledConst::FIELD_OP_CODE, Constant::OP_LOCATION);
    value1.Put(PrivacyFiledConst::FIELD_STATUS, ActiveChangeType::PERM_ACTIVE_IN_BACKGROUND);
    value1.Put(PrivacyFiledConst::FIELD_TIMESTAMP, timestamp - THREE_SECOND);
    value1.Put(PrivacyFiledConst::FIELD_ACCESS_DURATION, 1);
    value1.Put(PrivacyFiledConst::FIELD_ACCESS_COUNT, 1);
    value1.Put(PrivacyFiledConst::FIELD_REJECT_COUNT, 0);
    value1.Put(PrivacyFiledConst::FIELD_LOCKSCREEN_STATUS, LockScreenStatusChangeType::PERM_ACTIVE_IN_UNLOCKED);
    GenericValues value2;
    value1.Put(PrivacyFiledConst::FIELD_TOKEN_ID, static_cast<int32_t>(tokenID));
    value2.Put(PrivacyFiledConst::FIELD_OP_CODE, Constant::OP_LOCATION);
    value2.Put(PrivacyFiledConst::FIELD_STATUS, ActiveChangeType::PERM_ACTIVE_IN_FOREGROUND);
    value2.Put(PrivacyFiledConst::FIELD_TIMESTAMP, timestamp - TWO_SECOND);
    value2.Put(PrivacyFiledConst::FIELD_ACCESS_DURATION, 1);
    value2.Put(PrivacyFiledConst::FIELD_ACCESS_COUNT, 1);
    value2.Put(PrivacyFiledConst::FIELD_REJECT_COUNT, 0);
    value2.Put(PrivacyFiledConst::FIELD_LOCKSCREEN_STATUS, LockScreenStatusChangeType::PERM_ACTIVE_IN_UNLOCKED);
    GenericValues value3;
    value1.Put(PrivacyFiledConst::FIELD_TOKEN_ID, static_cast<int32_t>(tokenID));
    value3.Put(PrivacyFiledConst::FIELD_OP_CODE, Constant::OP_LOCATION);
    value3.Put(PrivacyFiledConst::FIELD_STATUS, ActiveChangeType::PERM_ACTIVE_IN_BACKGROUND);
    value3.Put(PrivacyFiledConst::FIELD_TIMESTAMP, timestamp - ONE_SECOND);
    value3.Put(PrivacyFiledConst::FIELD_ACCESS_DURATION, 1);
    value3.Put(PrivacyFiledConst::FIELD_ACCESS_COUNT, 1);
    value3.Put(PrivacyFiledConst::FIELD_REJECT_COUNT, 0);
    value3.Put(PrivacyFiledConst::FIELD_LOCKSCREEN_STATUS, LockScreenStatusChangeType::PERM_ACTIVE_IN_LOCKED);
    GenericValues value4;
    value1.Put(PrivacyFiledConst::FIELD_TOKEN_ID, static_cast<int32_t>(tokenID));
    value4.Put(PrivacyFiledConst::FIELD_OP_CODE, Constant::OP_LOCATION);
    value4.Put(PrivacyFiledConst::FIELD_STATUS, ActiveChangeType::PERM_ACTIVE_IN_FOREGROUND);
    value4.Put(PrivacyFiledConst::FIELD_TIMESTAMP, timestamp);
    value4.Put(PrivacyFiledConst::FIELD_ACCESS_DURATION, 1);
    value4.Put(PrivacyFiledConst::FIELD_ACCESS_COUNT, 1);
    value4.Put(PrivacyFiledConst::FIELD_REJECT_COUNT, 0);
    value4.Put(PrivacyFiledConst::FIELD_LOCKSCREEN_STATUS, LockScreenStatusChangeType::PERM_ACTIVE_IN_LOCKED);

    std::vector<GenericValues> values;
    values.emplace_back(value1);
    values.emplace_back(value2);
    values.emplace_back(value3);
    values.emplace_back(value4);

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
    EXPECT_EQ(static_cast<int32_t>(tokenID), result1.bundleRecords[0].tokenId);
    EXPECT_EQ(static_cast<size_t>(1), result1.bundleRecords[0].permissionRecords.size());
    EXPECT_EQ(2, result1.bundleRecords[0].permissionRecords[0].accessCount);

    PermissionUsedResult result2;
    request.flag = PermissionUsageFlag::FLAG_PERMISSION_USAGE_SUMMARY_IN_SCREEN_UNLOCKED;
    EXPECT_EQ(Constant::SUCCESS, PermissionRecordManager::GetInstance().GetPermissionUsedRecords(request, result2));
    EXPECT_EQ(static_cast<size_t>(1), result2.bundleRecords.size());
    EXPECT_EQ(static_cast<int32_t>(tokenID), result2.bundleRecords[0].tokenId);
    EXPECT_EQ(static_cast<size_t>(1), result2.bundleRecords[0].permissionRecords.size());
    EXPECT_EQ(2, result2.bundleRecords[0].permissionRecords[0].accessCount);

    PermissionUsedResult result3;
    request.flag = PermissionUsageFlag::FLAG_PERMISSION_USAGE_SUMMARY_IN_APP_FOREGROUND;
    EXPECT_EQ(Constant::SUCCESS, PermissionRecordManager::GetInstance().GetPermissionUsedRecords(request, result3));
    EXPECT_EQ(static_cast<size_t>(1), result3.bundleRecords.size());
    EXPECT_EQ(static_cast<int32_t>(tokenID), result3.bundleRecords[0].tokenId);
    EXPECT_EQ(static_cast<size_t>(1), result3.bundleRecords[0].permissionRecords.size());
    EXPECT_EQ(2, result3.bundleRecords[0].permissionRecords[0].accessCount);

    PermissionUsedResult result4;
    request.flag = PermissionUsageFlag::FLAG_PERMISSION_USAGE_SUMMARY_IN_APP_BACKGROUND;
    EXPECT_EQ(Constant::SUCCESS, PermissionRecordManager::GetInstance().GetPermissionUsedRecords(request, result4));
    EXPECT_EQ(static_cast<size_t>(1), result4.bundleRecords.size());
    EXPECT_EQ(static_cast<int32_t>(tokenID), result4.bundleRecords[0].tokenId);
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
    PermissionUsedRecordCache::GetInstance().DeepCopyFromHead(nullptr, copyHead);
    ASSERT_EQ(copyHead->next, nullptr);

    PermissionUsedRecordCache::GetInstance().DeepCopyFromHead(head, copyHead);

    ASSERT_EQ(copyHead->record.opCode, head->record.opCode);
    ASSERT_EQ(copyHead->next->record.opCode, g_recordA1.opCode);
    ASSERT_EQ(copyHead->next->next->record.opCode, g_recordA2.opCode);
    ASSERT_EQ(copyHead->next->next->next->record.opCode, g_recordB1.opCode);
    ASSERT_EQ(copyHead->next->next->next->next->record.opCode, g_recordB2.opCode);
}
} // namespace AccessToken
} // namespace Security
} // namespace OHOS
