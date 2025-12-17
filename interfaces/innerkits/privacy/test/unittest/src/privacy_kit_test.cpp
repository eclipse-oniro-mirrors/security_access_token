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

#include "privacy_kit_test.h"

#include <chrono>

#include "access_token.h"
#include "accesstoken_kit.h"
#ifdef AUDIO_FRAMEWORK_ENABLE
#include "audio_system_manager.h"
#endif
#include "app_manager_access_client.h"
#include "nativetoken_kit.h"
#include "on_permission_used_record_callback_stub.h"
#include "parameter.h"
#define private public
#include "perm_active_status_change_callback.h"
#include "privacy_manager_client.h"
#include "state_change_callback.h"
#undef private
#include "permission_map.h"
#include "active_change_response_parcel.h"
#include "perm_active_status_change_callback_stub.h"
#include "perm_setproc.h"
#include "privacy_error.h"
#include "privacy_kit.h"
#include "privacy_test_common.h"
#include "state_change_callback_stub.h"
#include "string_ex.h"
#include "token_setproc.h"

using namespace testing::ext;
using namespace OHOS::Security::AccessToken;

const static int32_t RET_NO_ERROR = 0;
static AccessTokenID g_nativeToken = 0;
static AccessTokenID g_shellToken = 0;
static MockHapToken* g_mock = nullptr;
#ifdef AUDIO_FRAMEWORK_ENABLE
static bool g_isMicMute = false;
#endif
static constexpr uint32_t RANDOM_TOKENID = 123;
static constexpr uint32_t RANDOM_PID = 123;
static constexpr int32_t INVALID_PERMISSIONAME_LENGTH = 257;
static constexpr int32_t FIRST_INDEX = 0;
static constexpr int32_t SECOND_INDEX = 1;
static constexpr int32_t THIRD_INDEX = 2;
static constexpr int32_t RESULT_NUM_ONE = 1;
static constexpr int32_t RESULT_NUM_TWO = 2;
static constexpr int32_t RESULT_NUM_THREE = 3;
static constexpr int32_t MAX_DISABLE_CALLBACK_TEST_SIZE = 20;
static constexpr int32_t MAX_PERM_LIST_TEST_SIZE = 1024;
const static int32_t NOT_EXSIT_PID = 99999999;
const static int32_t INVALID_USER_ID = -1;
const static int32_t USER_ID_2 = 2;

static PermissionStateFull g_infoManagerTestStateA = {
    .permissionName = "ohos.permission.CAMERA",
    .isGeneral = true,
    .resDeviceID = {"local"},
    .grantStatus = {PermissionState::PERMISSION_GRANTED},
    .grantFlags = {1}
};
static HapPolicyParams g_policyPramsA = {
    .apl = APL_NORMAL,
    .domain = "test.domain.A",
};
static HapInfoParams g_infoParmsA = {
    .userID = 1,
    .bundleName = "ohos.privacy_test.bundleA",
    .instIndex = 0,
    .appIDDesc = "privacy_test.bundleA"
};

static PermissionStateFull g_infoManagerTestStateB = {
    .permissionName = "ohos.permission.MICROPHONE",
    .isGeneral = true,
    .resDeviceID = {"local"},
    .grantStatus = {PermissionState::PERMISSION_GRANTED},
    .grantFlags = {1}
};
static HapPolicyParams g_policyPramsB = {
    .apl = APL_NORMAL,
    .domain = "test.domain.B",
};
static HapInfoParams g_infoParmsB = {
    .userID = 1,
    .bundleName = "ohos.privacy_test.bundleB",
    .instIndex = 0,
    .appIDDesc = "privacy_test.bundleB"
};

static PermissionStateFull g_infoManagerTestStateC = {
    .permissionName = "ohos.permission.PERMISSION_USED_STATS",
    .isGeneral = true,
    .resDeviceID = {"localC"},
    .grantStatus = {PermissionState::PERMISSION_GRANTED},
    .grantFlags = {1}
};
static HapInfoParams g_infoParmsC = {
    .userID = 1,
    .bundleName = "ohos.privacy_test.bundleC",
    .instIndex = 0,
    .appIDDesc = "privacy_test.bundleC",
    .isSystemApp = true,
};
static HapPolicyParams g_policyPramsC = {
    .apl = APL_NORMAL,
    .domain = "test.domain.C",
    .permList = {},
    .permStateList = {g_infoManagerTestStateC}
};

static HapInfoParams g_infoParmsD = {
    .userID = 1,
    .bundleName = "ohos.privacy_test.bundleD",
    .instIndex = 0,
    .appIDDesc = "privacy_test.bundleD",
    .isSystemApp = true,
};
static HapPolicyParams g_policyPramsD = {
    .apl = APL_NORMAL,
    .domain = "test.domain.C",
    .permList = {},
    .permStateList = {g_infoManagerTestStateA, g_infoManagerTestStateB}
};

static HapPolicyParams g_policyPramsE = {
    .apl = APL_NORMAL,
    .domain = "test.domain",
    .permList = {},
    .permStateList = {g_infoManagerTestStateA, g_infoManagerTestStateB}
};
static HapInfoParams g_infoParmsE = {
    .userID = 1,
    .bundleName = "ohos.privacy_test.bundleE",
    .instIndex = 0,
    .appIDDesc = "privacy_test.bundleE"
};

static HapPolicyParams g_policyPramsF = {
    .apl = APL_NORMAL,
    .domain = "test.domain",
    .permList = {},
    .permStateList = {g_infoManagerTestStateA, g_infoManagerTestStateB}
};
static HapInfoParams g_infoParmsF = {
    .userID = 1,
    .bundleName = "ohos.privacy_test.bundleF",
    .instIndex = 0,
    .appIDDesc = "privacy_test.bundleF"
};

static HapPolicyParams g_policyPramsG = {
    .apl = APL_NORMAL,
    .domain = "test.domain.G",
};
static HapInfoParams g_infoParmsG = {
    .userID = 2,
    .bundleName = "ohos.privacy_test.bundleG",
    .instIndex = 0,
    .appIDDesc = "privacy_test.bundleG"
};

static UsedRecordDetail g_usedRecordDetail = {
    .status = 2,
    .timestamp = 2L,
    .accessDuration = 2L,
};
static PermissionUsedRecord g_permissionUsedRecord = {
    .permissionName = "ohos.permission.CAMERA",
    .accessCount = 2,
    .rejectCount = 2,
    .lastAccessTime = 0L,
    .lastRejectTime = 0L,
    .lastAccessDuration = 0L,
};
static BundleUsedRecord g_bundleUsedRecord = {
    .tokenId = 100,
    .isRemote = false,
    .deviceId = "you guess",
    .bundleName = "com.ohos.test",
};

PermissionStateFull g_infoManagerTestStateD = {
    .permissionName = "ohos.permission.MICROPHONE_BACKGROUND",
    .isGeneral = true,
    .resDeviceID = {"localC"},
    .grantStatus = {PermissionState::PERMISSION_GRANTED},
    .grantFlags = {1}
};

static AccessTokenID g_selfTokenId = 0;
static AccessTokenID g_tokenIdA = 0;
static AccessTokenID g_tokenIdB = 0;
static AccessTokenID g_tokenIdC = 0;
static AccessTokenID g_tokenIdE = 0;
static AccessTokenID g_tokenIdF = 0;
static AccessTokenID g_tokenIdG = 0;

static void DeleteTestToken()
{
    AccessTokenIDEx tokenIdEx = PrivacyTestCommon::GetHapTokenIdFromBundle(
        g_infoParmsA.userID, g_infoParmsA.bundleName, g_infoParmsA.instIndex);
    PrivacyTestCommon::DeleteTestHapToken(tokenIdEx.tokenIdExStruct.tokenID);
    PrivacyKit::RemovePermissionUsedRecords(tokenIdEx.tokenIdExStruct.tokenID);

    tokenIdEx = PrivacyTestCommon::GetHapTokenIdFromBundle(
        g_infoParmsB.userID, g_infoParmsB.bundleName, g_infoParmsB.instIndex);
    PrivacyTestCommon::DeleteTestHapToken(tokenIdEx.tokenIdExStruct.tokenID);
    PrivacyKit::RemovePermissionUsedRecords(tokenIdEx.tokenIdExStruct.tokenID);

    tokenIdEx = PrivacyTestCommon::GetHapTokenIdFromBundle(
        g_infoParmsC.userID, g_infoParmsC.bundleName, g_infoParmsC.instIndex);
    PrivacyTestCommon::DeleteTestHapToken(tokenIdEx.tokenIdExStruct.tokenID);
    PrivacyKit::RemovePermissionUsedRecords(tokenIdEx.tokenIdExStruct.tokenID);

    tokenIdEx = PrivacyTestCommon::GetHapTokenIdFromBundle(
        g_infoParmsE.userID, g_infoParmsE.bundleName, g_infoParmsE.instIndex);
    PrivacyTestCommon::DeleteTestHapToken(tokenIdEx.tokenIdExStruct.tokenID);
    PrivacyKit::RemovePermissionUsedRecords(tokenIdEx.tokenIdExStruct.tokenID);

    tokenIdEx = PrivacyTestCommon::GetHapTokenIdFromBundle(
        g_infoParmsF.userID, g_infoParmsF.bundleName, g_infoParmsF.instIndex);
    PrivacyTestCommon::DeleteTestHapToken(tokenIdEx.tokenIdExStruct.tokenID);
    PrivacyKit::RemovePermissionUsedRecords(tokenIdEx.tokenIdExStruct.tokenID);

    tokenIdEx = PrivacyTestCommon::GetHapTokenIdFromBundle(
        g_infoParmsG.userID, g_infoParmsG.bundleName, g_infoParmsG.instIndex);
    PrivacyTestCommon::DeleteTestHapToken(tokenIdEx.tokenIdExStruct.tokenID);
    PrivacyKit::RemovePermissionUsedRecords(tokenIdEx.tokenIdExStruct.tokenID);
}

void PrivacyKitTest::SetUpTestCase()
{
    g_selfTokenId = GetSelfTokenID();
    PrivacyTestCommon::SetTestEvironment(g_selfTokenId);

    std::vector<std::string> reqPerm;
    reqPerm.emplace_back("ohos.permission.PERMISSION_USED_STATS");
    g_mock = new (std::nothrow) MockHapToken("PrivacyKitMockTest", reqPerm, true);

    g_nativeToken = PrivacyTestCommon::GetNativeTokenIdFromProcess("privacy_service");
    g_shellToken = PrivacyTestCommon::GetNativeTokenIdFromProcess("hdcd");

    DeleteTestToken();
#ifdef AUDIO_FRAMEWORK_ENABLE
    auto audioGroupManager = OHOS::AudioStandard::AudioSystemManager::GetInstance()->GetGroupManager(
        OHOS::AudioStandard::DEFAULT_VOLUME_GROUP_ID);
    if (audioGroupManager != nullptr) {
        g_isMicMute = audioGroupManager->GetPersistentMicMuteState();
    }
#endif
}

void PrivacyKitTest::TearDownTestCase()
{
    if (g_mock != nullptr) {
        delete g_mock;
        g_mock = nullptr;
    }
    SetSelfTokenID(g_selfTokenId);
    PrivacyTestCommon::ResetTestEvironment();
}

void PrivacyKitTest::SetUp()
{
#ifdef AUDIO_FRAMEWORK_ENABLE
    auto audioGroupManager = OHOS::AudioStandard::AudioSystemManager::GetInstance()->GetGroupManager(
        OHOS::AudioStandard::DEFAULT_VOLUME_GROUP_ID);
    if (audioGroupManager != nullptr) {
        audioGroupManager->SetMicrophoneMutePersistent(false, OHOS::AudioStandard::PolicyType::PRIVACY_POLCIY_TYPE);
    }
#endif
    AccessTokenIDEx tokenIdEx = {0};
    tokenIdEx = PrivacyTestCommon::AllocTestHapToken(g_infoParmsA, g_policyPramsA);
    g_tokenIdA = tokenIdEx.tokenIdExStruct.tokenID;
    EXPECT_NE(INVALID_TOKENID, g_tokenIdA);

    tokenIdEx = PrivacyTestCommon::AllocTestHapToken(g_infoParmsB, g_policyPramsB);
    g_tokenIdB = tokenIdEx.tokenIdExStruct.tokenID;
    EXPECT_NE(INVALID_TOKENID, g_tokenIdB);

    tokenIdEx = PrivacyTestCommon::AllocTestHapToken(g_infoParmsC, g_policyPramsC);
    g_tokenIdC = tokenIdEx.tokenIdExStruct.tokenID;
    EXPECT_NE(INVALID_TOKENID, g_tokenIdC);

    tokenIdEx = PrivacyTestCommon::AllocTestHapToken(g_infoParmsE, g_policyPramsE);
    g_tokenIdE = tokenIdEx.tokenIdExStruct.tokenID;
    EXPECT_NE(INVALID_TOKENID, g_tokenIdE);

    tokenIdEx = PrivacyTestCommon::AllocTestHapToken(g_infoParmsF, g_policyPramsF);
    g_tokenIdF = tokenIdEx.tokenIdExStruct.tokenID;
    EXPECT_NE(INVALID_TOKENID, g_tokenIdF);

    tokenIdEx = PrivacyTestCommon::AllocTestHapToken(g_infoParmsG, g_policyPramsG);
    g_tokenIdG = tokenIdEx.tokenIdExStruct.tokenID;
    EXPECT_NE(INVALID_TOKENID, g_tokenIdG);
}

void PrivacyKitTest::TearDown()
{
#ifdef AUDIO_FRAMEWORK_ENABLE
    auto audioGroupManager = OHOS::AudioStandard::AudioSystemManager::GetInstance()->GetGroupManager(
        OHOS::AudioStandard::DEFAULT_VOLUME_GROUP_ID);
    if (audioGroupManager != nullptr) {
        audioGroupManager->SetMicrophoneMutePersistent(g_isMicMute,
            OHOS::AudioStandard::PolicyType::PRIVACY_POLCIY_TYPE);
    }
#endif
    DeleteTestToken();
}

void PrivacyKitTest::BuildQueryRequest(AccessTokenID tokenId,
    const std::string &bundleName, const std::vector<std::string> &permissionList, PermissionUsedRequest &request)
{
    request.tokenId = tokenId;
    request.isRemote = false;
    request.deviceId = "";
    request.bundleName = bundleName;
    request.permissionList = permissionList;
    request.beginTimeMillis = 0;
    request.endTimeMillis = 0;
    request.flag = FLAG_PERMISSION_USAGE_SUMMARY;
}

void PrivacyKitTest::CheckPermissionUsedResult(const PermissionUsedRequest& request, const PermissionUsedResult& result,
    int32_t permRecordSize, int32_t totalSuccessCount, int32_t totalFailCount)
{
    int32_t successCount = 0;
    int32_t failCount = 0;
    EXPECT_EQ(request.tokenId, result.bundleRecords[0].tokenId);
    EXPECT_EQ(request.isRemote, result.bundleRecords[0].isRemote);
    EXPECT_EQ(request.deviceId, result.bundleRecords[0].deviceId);
    EXPECT_EQ(request.bundleName, result.bundleRecords[0].bundleName);
    EXPECT_EQ(permRecordSize, static_cast<int32_t>(result.bundleRecords[0].permissionRecords.size()));
    for (int32_t i = 0; i < permRecordSize; i++) {
        successCount += result.bundleRecords[0].permissionRecords[i].accessCount;
        failCount += result.bundleRecords[0].permissionRecords[i].rejectCount;
    }
    EXPECT_EQ(totalSuccessCount, successCount);
    EXPECT_EQ(totalFailCount, failCount);
}

static void SleepUtilMinuteEnd()
{
    std::chrono::milliseconds ms = std::chrono::duration_cast<std::chrono::milliseconds>(
        std::chrono::system_clock::now().time_since_epoch()
    );

    int64_t timestampMs = ms.count();
    time_t timestampS = static_cast<time_t>(timestampMs / 1000);
    struct tm t = {0};
    // localtime is not thread safe, localtime_r first param unit is second, timestamp unit is ms, so divided by 1000
    localtime_r(&timestampS, &t);
    uint32_t sleepSeconds = static_cast<uint32_t>(60 - t.tm_sec);

    GTEST_LOG_(INFO) << "current time is " << timestampMs << ", " << t.tm_hour << ":" << t.tm_min << ":" << t.tm_sec;
    GTEST_LOG_(INFO) << "need to sleep " << sleepSeconds << " seconds";
    sleep(sleepSeconds);
}

/**
 * @tc.name: AddPermissionUsedRecord001
 * @tc.desc: cannot AddPermissionUsedRecord with illegal tokenId and permission.
 * @tc.type: FUNC
 * @tc.require: issueI5P4IU
 */
HWTEST_F(PrivacyKitTest, AddPermissionUsedRecord001, TestSize.Level0)
{
    AddPermParamInfo info;
    info.tokenId = 0;
    info.permissionName = "ohos.permission.READ_CONTACTS";
    info.successCount = 1;
    info.failCount = 0;
    EXPECT_EQ(PrivacyError::ERR_PARAM_INVALID, PrivacyKit::AddPermissionUsedRecord(info));

    info.tokenId = g_tokenIdA;
    info.permissionName = "";
    EXPECT_EQ(PrivacyError::ERR_PARAM_INVALID, PrivacyKit::AddPermissionUsedRecord(info));

    info.permissionName = "ohos.permission.READ_CONTACTS";
    info.successCount = -1;
    EXPECT_EQ(PrivacyError::ERR_PARAM_INVALID, PrivacyKit::AddPermissionUsedRecord(info));

    PermissionUsedRequest request;
    PermissionUsedResult result;
    std::vector<std::string> permissionList;
    BuildQueryRequest(g_tokenIdA, g_infoParmsA.bundleName, permissionList, request);
    EXPECT_EQ(RET_NO_ERROR, PrivacyKit::GetPermissionUsedRecords(request, result));
    EXPECT_TRUE(result.bundleRecords.empty());
}

/**
 * @tc.name: AddPermissionUsedRecord002
 * @tc.desc: cannot AddPermissionUsedRecord with invalid tokenId and permission.
 * @tc.type: FUNC
 * @tc.require: issueI5P4IU
 */
HWTEST_F(PrivacyKitTest, AddPermissionUsedRecord002, TestSize.Level0)
{
    AddPermParamInfo info;
    info.tokenId = g_tokenIdA;
    info.permissionName = "ohos.permission.test";
    info.successCount = 1;
    info.failCount = 0;
    EXPECT_EQ(PrivacyError::ERR_PERMISSION_NOT_EXIST, PrivacyKit::AddPermissionUsedRecord(info));

    info.tokenId = 672137215; // 672137215 is max native tokenId: 001 01 0 000000 11111111111111111111
    info.permissionName = "ohos.permission.CAMERA";
    EXPECT_EQ(PrivacyError::ERR_PARAM_INVALID, PrivacyKit::AddPermissionUsedRecord(info));

    info.tokenId = g_tokenIdA;
    info.permissionName = "ohos.permission.READ_CONTACTS";
    info.successCount = 0;
    EXPECT_EQ(PrivacyError::ERR_PARAM_INVALID, PrivacyKit::AddPermissionUsedRecord(info));

    PermissionUsedRequest request;
    PermissionUsedResult result;
    std::vector<std::string> permissionList;
    BuildQueryRequest(g_nativeToken, "", permissionList, request);
    EXPECT_EQ(RET_NO_ERROR, PrivacyKit::GetPermissionUsedRecords(request, result));
    EXPECT_TRUE(result.bundleRecords.empty());

    BuildQueryRequest(g_tokenIdA, g_infoParmsA.bundleName, permissionList, request);
    EXPECT_EQ(RET_NO_ERROR, PrivacyKit::GetPermissionUsedRecords(request, result));
    EXPECT_TRUE(result.bundleRecords.empty());
}

/**
 * @tc.name: AddPermissionUsedRecord003
 * @tc.desc: cannot AddPermissionUsedRecord with native tokenId.
 * @tc.type: FUNC
 * @tc.require: issueI5P4IU
 */
HWTEST_F(PrivacyKitTest, AddPermissionUsedRecord003, TestSize.Level0)
{
    AddPermParamInfo info;
    info.tokenId = g_nativeToken;
    info.permissionName = "ohos.permission.READ_CONTACTS";
    info.successCount = 1;
    info.failCount = 0;
    EXPECT_EQ(PrivacyError::ERR_PARAM_INVALID, PrivacyKit::AddPermissionUsedRecord(info));

    PermissionUsedRequest request;
    PermissionUsedResult result;
    std::vector<std::string> permissionList;
    BuildQueryRequest(g_nativeToken, "", permissionList, request);

    EXPECT_EQ(RET_NO_ERROR, PrivacyKit::GetPermissionUsedRecords(request, result));
    EXPECT_TRUE(result.bundleRecords.empty());
}

/**
 * @tc.name: AddPermissionUsedRecord004
 * @tc.desc: AddPermissionUsedRecord user_grant permission.
 * @tc.type: FUNC
 * @tc.require: issueI5P4IU
 */
HWTEST_F(PrivacyKitTest, AddPermissionUsedRecord004, TestSize.Level0)
{
    AddPermParamInfo info;
    info.tokenId = g_tokenIdA;
    info.permissionName = "ohos.permission.READ_CONTACTS";
    info.successCount = 1;
    info.failCount = 0;
    EXPECT_EQ(RET_NO_ERROR, PrivacyKit::AddPermissionUsedRecord(info));

    info.permissionName = "ohos.permission.WRITE_CONTACTS";
    info.successCount = 0;
    info.failCount = 1;
    EXPECT_EQ(RET_NO_ERROR, PrivacyKit::AddPermissionUsedRecord(info));

    info.permissionName = "ohos.permission.LOCATION";
    info.successCount = 1;
    EXPECT_EQ(RET_NO_ERROR, PrivacyKit::AddPermissionUsedRecord(info));

    PermissionUsedRequest request;
    PermissionUsedResult result;
    std::vector<std::string> permissionList;
    BuildQueryRequest(g_tokenIdA, g_infoParmsA.bundleName, permissionList, request);
    EXPECT_EQ(RET_NO_ERROR, PrivacyKit::GetPermissionUsedRecords(request, result));

    EXPECT_EQ(static_cast<uint32_t>(1), result.bundleRecords.size());
    CheckPermissionUsedResult(request, result, 3, 2, 2);
}

/**
 * @tc.name: AddPermissionUsedRecord005
 * @tc.desc: AddPermissionUsedRecord user_grant permission.
 * @tc.type: FUNC
 * @tc.require: issueI5P4IU
 */
HWTEST_F(PrivacyKitTest, AddPermissionUsedRecord005, TestSize.Level0)
{
    AddPermParamInfo info;
    info.tokenId = g_tokenIdA;
    info.permissionName = "ohos.permission.READ_CONTACTS";
    info.successCount = 1;
    info.failCount = 0;
    EXPECT_EQ(RET_NO_ERROR, PrivacyKit::AddPermissionUsedRecord(info));

    info.permissionName = "ohos.permission.LOCATION";
    info.successCount = 0;
    info.failCount = 1;
    EXPECT_EQ(RET_NO_ERROR, PrivacyKit::AddPermissionUsedRecord(info));

    info.tokenId = g_tokenIdB;
    info.permissionName = "ohos.permission.READ_CONTACTS";
    EXPECT_EQ(RET_NO_ERROR, PrivacyKit::AddPermissionUsedRecord(info));

    info.permissionName = "ohos.permission.LOCATION";
    info.successCount = 1;
    info.failCount = 0;
    EXPECT_EQ(RET_NO_ERROR, PrivacyKit::AddPermissionUsedRecord(info));

    PermissionUsedRequest request;
    PermissionUsedResult result;
    std::vector<std::string> permissionList;
    BuildQueryRequest(g_tokenIdA, g_infoParmsA.bundleName, permissionList, request);
    EXPECT_EQ(RET_NO_ERROR, PrivacyKit::GetPermissionUsedRecords(request, result));

    EXPECT_EQ(static_cast<uint32_t>(1), result.bundleRecords.size());
    CheckPermissionUsedResult(request, result, 2, 1, 1);

    BuildQueryRequest(g_tokenIdB, g_infoParmsB.bundleName, permissionList, request);
    EXPECT_EQ(RET_NO_ERROR, PrivacyKit::GetPermissionUsedRecords(request, result));

    EXPECT_EQ(static_cast<uint32_t>(1), result.bundleRecords.size());
    CheckPermissionUsedResult(request, result, 2, 1, 1);

    request.flag = FLAG_PERMISSION_USAGE_SUMMARY_IN_SCREEN_LOCKED;
    EXPECT_EQ(RET_NO_ERROR, PrivacyKit::GetPermissionUsedRecords(request, result));

    request.flag = FLAG_PERMISSION_USAGE_SUMMARY_IN_SCREEN_UNLOCKED;
    EXPECT_EQ(RET_NO_ERROR, PrivacyKit::GetPermissionUsedRecords(request, result));

    request.flag = FLAG_PERMISSION_USAGE_SUMMARY_IN_APP_FOREGROUND;
    EXPECT_EQ(RET_NO_ERROR, PrivacyKit::GetPermissionUsedRecords(request, result));

    request.flag = FLAG_PERMISSION_USAGE_SUMMARY_IN_APP_BACKGROUND;
    EXPECT_EQ(RET_NO_ERROR, PrivacyKit::GetPermissionUsedRecords(request, result));
}

/**
 * @tc.name: AddPermissionUsedRecord006
 * @tc.desc: AddPermissionUsedRecord permission combine and not combine records.
 * @tc.type: FUNC
 * @tc.require: issueI5P4IU
 */
HWTEST_F(PrivacyKitTest, AddPermissionUsedRecord006, TestSize.Level0)
{
    AddPermParamInfo info;
    info.tokenId = g_tokenIdA;
    info.permissionName = "ohos.permission.READ_CONTACTS";
    info.successCount = 1;
    info.failCount = 0;
    EXPECT_EQ(RET_NO_ERROR, PrivacyKit::AddPermissionUsedRecord(info)); // record1
    SleepUtilMinuteEnd();
    EXPECT_EQ(RET_NO_ERROR, PrivacyKit::AddPermissionUsedRecord(info)); // record2 not combine with record1

    PermissionUsedRequest request;
    PermissionUsedResult result1;
    std::vector<std::string> permissionList;
    BuildQueryRequest(g_tokenIdA, g_infoParmsA.bundleName, permissionList, request);
    request.flag = FLAG_PERMISSION_USAGE_DETAIL;
    EXPECT_EQ(RET_NO_ERROR, PrivacyKit::GetPermissionUsedRecords(request, result1));
    EXPECT_EQ(static_cast<uint32_t>(1), result1.bundleRecords.size());
    EXPECT_EQ(static_cast<uint32_t>(1), result1.bundleRecords[0].permissionRecords.size());
    // record cross minute not combine
    EXPECT_EQ(static_cast<uint32_t>(2), result1.bundleRecords[0].permissionRecords[0].accessRecords.size());
    CheckPermissionUsedResult(request, result1, 1, 2, 0);

    // <200ms, record is dropped
    EXPECT_EQ(RET_NO_ERROR, PrivacyKit::AddPermissionUsedRecord(info)); // record3 drop
    EXPECT_EQ(RET_NO_ERROR, PrivacyKit::AddPermissionUsedRecord(info)); // record4 drop
    usleep(200000); // 200000us = 200ms
    EXPECT_EQ(RET_NO_ERROR, PrivacyKit::AddPermissionUsedRecord(info)); // record5 combine with record2
    usleep(200000); // 200000us = 200ms
    EXPECT_EQ(RET_NO_ERROR, PrivacyKit::AddPermissionUsedRecord(info)); // record6 combine with record2

    PermissionUsedResult result2;
    EXPECT_EQ(RET_NO_ERROR, PrivacyKit::GetPermissionUsedRecords(request, result2));
    EXPECT_EQ(static_cast<uint32_t>(1), result2.bundleRecords.size());
    EXPECT_EQ(static_cast<uint32_t>(1), result2.bundleRecords[0].permissionRecords.size());
    // records in the same minute combine to one
    EXPECT_EQ(static_cast<uint32_t>(2), result2.bundleRecords[0].permissionRecords[0].accessRecords.size());
    CheckPermissionUsedResult(request, result2, 1, 4, 0);
}

/**
 * @tc.name: AddPermissionUsedRecord007
 * @tc.desc: AddPermissionUsedRecord caller is normal app.
 * @tc.type: FUNC
 * @tc.require: issueI66BH3
 */
HWTEST_F(PrivacyKitTest, AddPermissionUsedRecord007, TestSize.Level0)
{
    std::vector<std::string> reqPerm;
    reqPerm.emplace_back("ohos.permission.PERMISSION_USED_STATS");
    MockHapToken mock("AddPermissionUsedRecord007", reqPerm, false);

    AddPermParamInfo info;
    info.tokenId = g_tokenIdA;
    info.permissionName = "ohos.permission.READ_CONTACTS";
    info.successCount = 1;
    info.failCount = 0;
    EXPECT_EQ(PrivacyError::ERR_NOT_SYSTEM_APP, PrivacyKit::AddPermissionUsedRecord(info));
    EXPECT_EQ(0, PrivacyKit::AddPermissionUsedRecord(info, true));
}

/**
 * @tc.name: AddPermissionUsedRecord008
 * @tc.desc: query permission record detail count.
 * @tc.type: FUNC
 * @tc.require: issueI5P4IU
 */
HWTEST_F(PrivacyKitTest, AddPermissionUsedRecord008, TestSize.Level0)
{
    int32_t permRecordSize = 0;

    AddPermParamInfo info;
    info.tokenId = g_tokenIdA;
    info.permissionName = "ohos.permission.READ_CONTACTS";
    info.successCount = 1;
    info.failCount = 0;
    EXPECT_EQ(RET_NO_ERROR, PrivacyKit::AddPermissionUsedRecord(info));
    permRecordSize++;

    info.permissionName = "ohos.permission.WRITE_CONTACTS";
    info.successCount = 0;
    info.failCount = 2;
    EXPECT_EQ(RET_NO_ERROR, PrivacyKit::AddPermissionUsedRecord(info));
    permRecordSize++;

    info.permissionName = "ohos.permission.LOCATION";
    info.successCount = 3;
    info.failCount = 3;
    EXPECT_EQ(RET_NO_ERROR, PrivacyKit::AddPermissionUsedRecord(info));
    permRecordSize++;

    PermissionUsedRequest request;
    PermissionUsedResult result;
    std::vector<std::string> permissionList;
    BuildQueryRequest(g_tokenIdA, g_infoParmsA.bundleName, permissionList, request);
    request.flag = FLAG_PERMISSION_USAGE_DETAIL;
    EXPECT_EQ(RET_NO_ERROR, PrivacyKit::GetPermissionUsedRecords(request, result));

    EXPECT_EQ(static_cast<uint32_t>(1), result.bundleRecords.size());
    EXPECT_EQ(permRecordSize, static_cast<int32_t>(result.bundleRecords[0].permissionRecords.size()));
    for (int32_t i = 0; i < permRecordSize; i++) {
        if (result.bundleRecords[0].permissionRecords[i].permissionName == "ohos.permission.READ_CONTACTS") {
            EXPECT_EQ(static_cast<uint32_t>(1), result.bundleRecords[0].permissionRecords[i].accessRecords.size());
            EXPECT_EQ(static_cast<uint32_t>(0), result.bundleRecords[0].permissionRecords[i].rejectRecords.size());
            EXPECT_EQ(1, result.bundleRecords[0].permissionRecords[i].accessRecords[0].count);
        } else if (result.bundleRecords[0].permissionRecords[i].permissionName == "ohos.permission.WRITE_CONTACTS") {
            EXPECT_EQ(static_cast<uint32_t>(0), result.bundleRecords[0].permissionRecords[i].accessRecords.size());
            EXPECT_EQ(static_cast<uint32_t>(1), result.bundleRecords[0].permissionRecords[i].rejectRecords.size());
            EXPECT_EQ(2, result.bundleRecords[0].permissionRecords[i].rejectRecords[0].count);
        } else if (result.bundleRecords[0].permissionRecords[i].permissionName == "ohos.permission.LOCATION") {
            EXPECT_EQ(static_cast<uint32_t>(1), result.bundleRecords[0].permissionRecords[i].accessRecords.size());
            EXPECT_EQ(static_cast<uint32_t>(1), result.bundleRecords[0].permissionRecords[i].rejectRecords.size());
            EXPECT_EQ(3, result.bundleRecords[0].permissionRecords[i].accessRecords[0].count);
            EXPECT_EQ(3, result.bundleRecords[0].permissionRecords[i].rejectRecords[0].count);
        }
    }
}

/**
 * @tc.name: RemovePermissionUsedRecords001
 * @tc.desc: cannot RemovePermissionUsedRecords with illegal tokenId.
 * @tc.type: FUNC
 * @tc.require: issueI5P4IU
 */
HWTEST_F(PrivacyKitTest, RemovePermissionUsedRecords001, TestSize.Level0)
{
    EXPECT_EQ(PrivacyError::ERR_PARAM_INVALID, PrivacyKit::RemovePermissionUsedRecords(0));
}

/**
 * @tc.name: RemovePermissionUsedRecords002
 * @tc.desc: RemovePermissionUsedRecords with invalid tokenId.
 * @tc.type: FUNC
 * @tc.require: issueI5P4IU
 */
HWTEST_F(PrivacyKitTest, RemovePermissionUsedRecords002, TestSize.Level0)
{
    AddPermParamInfo info;
    info.tokenId = g_tokenIdA;
    info.permissionName = "ohos.permission.READ_CONTACTS";
    info.successCount = 1;
    info.failCount = 0;
    EXPECT_EQ(RET_NO_ERROR, PrivacyKit::AddPermissionUsedRecord(info));
    PermissionUsedRequest request;
    PermissionUsedResult result;
    std::vector<std::string> permissionList;
    BuildQueryRequest(g_tokenIdA, g_infoParmsA.bundleName, permissionList, request);

    EXPECT_EQ(RET_NO_ERROR, PrivacyKit::RemovePermissionUsedRecords(g_tokenIdA));
    EXPECT_EQ(RET_NO_ERROR, PrivacyKit::GetPermissionUsedRecords(request, result));
    EXPECT_TRUE(result.bundleRecords.empty());
}

/**
 * @tc.name: RemovePermissionUsedRecords003
 * @tc.desc: RemovePermissionUsedRecords caller is normal app.
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(PrivacyKitTest, RemovePermissionUsedRecords003, TestSize.Level0)
{
    std::vector<std::string> reqPerm;
    reqPerm.emplace_back("ohos.permission.PERMISSION_USED_STATS");
    MockHapToken mock("RemovePermissionUsedRecords003", reqPerm, false);
    AccessTokenID tokenID = GetSelfTokenID();
    EXPECT_EQ(PrivacyError::ERR_NOT_SYSTEM_APP, PrivacyKit::RemovePermissionUsedRecords(tokenID));
}

/**
 * @tc.name: RemovePermissionUsedRecords004
 * @tc.desc: cannot RemovePermissionUsedRecords function test.
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(PrivacyKitTest, RemovePermissionUsedRecords004, TestSize.Level0)
{
    EXPECT_EQ(RET_SUCCESS, PrivacyKit::RemovePermissionUsedRecords(g_nativeToken));
    EXPECT_EQ(PrivacyError::ERR_PARAM_INVALID, PrivacyKit::RemovePermissionUsedRecords(g_shellToken));
}

/**
 * @tc.name: GetPermissionUsedRecords001
 * @tc.desc: cannot GetPermissionUsedRecords with invalid query time and flag.
 * @tc.type: FUNC
 * @tc.require: issueI5P4IU
 */
HWTEST_F(PrivacyKitTest, GetPermissionUsedRecords001, TestSize.Level0)
{
    AddPermParamInfo info;
    info.tokenId = g_tokenIdA;
    info.permissionName = "ohos.permission.READ_CONTACTS";
    info.successCount = 1;
    info.failCount = 0;
    EXPECT_EQ(RET_NO_ERROR, PrivacyKit::AddPermissionUsedRecord(info));
    PermissionUsedRequest request;
    PermissionUsedResult result;
    std::vector<std::string> permissionList;
    BuildQueryRequest(g_tokenIdA, g_infoParmsA.bundleName, permissionList, request);
    request.beginTimeMillis = -1;
    request.endTimeMillis = -1;
    EXPECT_EQ(PrivacyError::ERR_PARAM_INVALID, PrivacyKit::GetPermissionUsedRecords(request, result));

    request.beginTimeMillis = 3;
    request.endTimeMillis = 1;
    EXPECT_EQ(PrivacyError::ERR_PARAM_INVALID, PrivacyKit::GetPermissionUsedRecords(request, result));

    request.flag = (PermissionUsageFlag)-1;
    EXPECT_EQ(PrivacyError::ERR_PARAM_INVALID, PrivacyKit::GetPermissionUsedRecords(request, result));
}

/**
 * @tc.name: GetPermissionUsedRecords002
 * @tc.desc: cannot GetPermissionUsedRecords with valid query time.
 * @tc.type: FUNC
 * @tc.require: issueI5P4IU
 */
HWTEST_F(PrivacyKitTest, GetPermissionUsedRecords002, TestSize.Level0)
{
    AddPermParamInfo info;
    info.tokenId = g_tokenIdA;
    info.permissionName = "ohos.permission.READ_MEDIA";
    info.successCount = 1;
    info.failCount = 0;
    EXPECT_EQ(RET_NO_ERROR, PrivacyKit::AddPermissionUsedRecord(info));

    info.permissionName = "ohos.permission.READ_CONTACTS";
    EXPECT_EQ(RET_NO_ERROR, PrivacyKit::AddPermissionUsedRecord(info));

    info.permissionName = "ohos.permission.READ_CALENDAR";
    EXPECT_EQ(RET_NO_ERROR, PrivacyKit::AddPermissionUsedRecord(info));

    PermissionUsedRequest request;
    PermissionUsedResult result;
    std::vector<std::string> permissionList;
    // query by tokenId
    BuildQueryRequest(g_tokenIdA, "", permissionList, request);
    EXPECT_EQ(RET_NO_ERROR, PrivacyKit::GetPermissionUsedRecords(request, result));
    EXPECT_EQ(static_cast<uint32_t>(1), result.bundleRecords.size());
    request.deviceId = "";
    request.bundleName = g_infoParmsA.bundleName;
    CheckPermissionUsedResult(request, result, 3, 3, 0);

    // query by unmatched tokenId, deviceId and bundle Name
    BuildQueryRequest(123, g_infoParmsA.bundleName, permissionList, request);
    EXPECT_EQ(RET_NO_ERROR, PrivacyKit::GetPermissionUsedRecords(request, result));
    EXPECT_TRUE(result.bundleRecords.empty());

    // query by invalid permission Name, results is empty
    permissionList.clear();
    permissionList.emplace_back("invalid permission");
    BuildQueryRequest(g_tokenIdA, g_infoParmsA.bundleName, permissionList, request);
    EXPECT_EQ(RET_NO_ERROR, PrivacyKit::GetPermissionUsedRecords(request, result));
    EXPECT_TRUE(result.bundleRecords.empty());
}

/**
 * @tc.name: GetPermissionUsedRecords003
 * @tc.desc: can GetPermissionUsedRecords with valid query time.
 * @tc.type: FUNC
 * @tc.require: issueI5P4IU
 */
HWTEST_F(PrivacyKitTest, GetPermissionUsedRecords003, TestSize.Level0)
{
    AddPermParamInfo info;
    info.tokenId = g_tokenIdA;
    info.permissionName = "ohos.permission.READ_MEDIA";
    info.successCount = 1;
    info.failCount = 0;
    EXPECT_EQ(RET_NO_ERROR, PrivacyKit::AddPermissionUsedRecord(info));
    usleep(200000); // 200000us = 200ms
    EXPECT_EQ(RET_NO_ERROR, PrivacyKit::AddPermissionUsedRecord(info));
    usleep(200000); // 200000us = 200ms
    EXPECT_EQ(RET_NO_ERROR, PrivacyKit::AddPermissionUsedRecord(info));
    usleep(200000); // 200000us = 200ms
    EXPECT_EQ(RET_NO_ERROR, PrivacyKit::AddPermissionUsedRecord(info));

    PermissionUsedRequest request;
    PermissionUsedResult result;
    std::vector<std::string> permissionList;
    BuildQueryRequest(g_tokenIdA, g_infoParmsA.bundleName, permissionList, request);
    EXPECT_EQ(RET_NO_ERROR, PrivacyKit::GetPermissionUsedRecords(request, result));
    EXPECT_EQ(static_cast<uint32_t>(1), result.bundleRecords.size());
    CheckPermissionUsedResult(request, result, 1, 4, 0);

    usleep(200000); // 200000us = 200ms
    info.permissionName = "ohos.permission.READ_CONTACTS";
    EXPECT_EQ(RET_NO_ERROR, PrivacyKit::AddPermissionUsedRecord(info));

    usleep(200000); // 200000us = 200ms
    info.permissionName = "ohos.permission.READ_CALENDAR";
    EXPECT_EQ(RET_NO_ERROR, PrivacyKit::AddPermissionUsedRecord(info));

    usleep(200000); // 200000us = 200ms
    info.permissionName = "ohos.permission.WRITE_CALENDAR";
    EXPECT_EQ(RET_NO_ERROR, PrivacyKit::AddPermissionUsedRecord(info));

    BuildQueryRequest(g_tokenIdA, g_infoParmsA.bundleName, permissionList, request);
    EXPECT_EQ(RET_NO_ERROR, PrivacyKit::GetPermissionUsedRecords(request, result));
    EXPECT_EQ(static_cast<uint32_t>(1), result.bundleRecords.size());
    CheckPermissionUsedResult(request, result, 4, 7, 0);
}

/**
 * @tc.name: GetPermissionUsedRecords004
 * @tc.desc: can GetPermissionUsedRecords with valid query time.
 * @tc.type: FUNC
 * @tc.require: issueI5P4IU
 */
HWTEST_F(PrivacyKitTest, GetPermissionUsedRecords004, TestSize.Level0)
{
    AddPermParamInfo info;
    info.tokenId = g_tokenIdA;
    info.permissionName = "ohos.permission.READ_CONTACTS";
    info.successCount = 1;
    info.failCount = 0;
    EXPECT_EQ(RET_NO_ERROR, PrivacyKit::AddPermissionUsedRecord(info));

    info.permissionName = "ohos.permission.READ_CALENDAR";
    EXPECT_EQ(RET_NO_ERROR, PrivacyKit::AddPermissionUsedRecord(info));

    info.tokenId = g_tokenIdB;
    info.permissionName = "ohos.permission.READ_CONTACTS";
    EXPECT_EQ(RET_NO_ERROR, PrivacyKit::AddPermissionUsedRecord(info));

    info.permissionName = "ohos.permission.READ_CALENDAR";
    EXPECT_EQ(RET_NO_ERROR, PrivacyKit::AddPermissionUsedRecord(info));

    PermissionUsedRequest request;
    PermissionUsedResult result;
    std::vector<std::string> permissionList;
    BuildQueryRequest(0, "", permissionList, request);

    EXPECT_EQ(RET_NO_ERROR, PrivacyKit::GetPermissionUsedRecords(request, result));
    if (result.bundleRecords.size() < static_cast<uint32_t>(2)) {
        EXPECT_TRUE(false);
    }
}

/**
 * @tc.name: GetPermissionUsedRecords005
 * @tc.desc: GetPermissionUsedRecords005 caller is normal app.
 * @tc.type: FUNC
 * @tc.require: issueI66BH3
 */
HWTEST_F(PrivacyKitTest, GetPermissionUsedRecords005, TestSize.Level0)
{
    std::vector<std::string> reqPerm;
    reqPerm.emplace_back("ohos.permission.PERMISSION_USED_STATS");
    MockHapToken mock("GetPermissionUsedRecords005", reqPerm, false);
    AccessTokenID tokenID = GetSelfTokenID();

    PermissionUsedRequest request;
    PermissionUsedResult result;
    std::vector<std::string> permissionList;
    // query by tokenId
    BuildQueryRequest(tokenID, "", permissionList, request);
    EXPECT_EQ(PrivacyError::ERR_NOT_SYSTEM_APP, PrivacyKit::GetPermissionUsedRecords(request, result));
}

/**
 * @tc.name: GetPermissionUsedRecords006
 * @tc.desc: GetPermissionUsedRecords with 200ms.
 * @tc.type: FUNC
 * @tc.require: issueI66BH3
 */
HWTEST_F(PrivacyKitTest, GetPermissionUsedRecords006, TestSize.Level0)
{
    AddPermParamInfo info;
    info.tokenId = g_tokenIdA;
    info.permissionName = "ohos.permission.READ_MEDIA";
    info.successCount = 0;
    info.failCount = 1;
    EXPECT_EQ(RET_NO_ERROR, PrivacyKit::AddPermissionUsedRecord(info)); // fail:1, success:0

    PermissionUsedRequest request;
    PermissionUsedResult result1;
    std::vector<std::string> permissionList;
    // query by tokenId
    BuildQueryRequest(g_tokenIdA, "", permissionList, request);
    EXPECT_EQ(RET_NO_ERROR, PrivacyKit::GetPermissionUsedRecords(request, result1));
    EXPECT_EQ(static_cast<uint32_t>(1), result1.bundleRecords.size());
    request.deviceId = "";
    request.bundleName = g_infoParmsA.bundleName;
    CheckPermissionUsedResult(request, result1, 1, 0, 1);

    usleep(200000); // 200000us = 200ms
    info.permissionName = "ohos.permission.READ_CONTACTS";
    EXPECT_EQ(RET_NO_ERROR, PrivacyKit::AddPermissionUsedRecord(info)); // fail:1, success:0
    info.successCount = 1;
    info.failCount = 0;
    EXPECT_EQ(RET_NO_ERROR, PrivacyKit::AddPermissionUsedRecord(info)); // fail:0, success:1
    PermissionUsedResult result2;
    EXPECT_EQ(RET_NO_ERROR, PrivacyKit::GetPermissionUsedRecords(request, result2));
    EXPECT_EQ(static_cast<uint32_t>(1), result2.bundleRecords.size());
    CheckPermissionUsedResult(request, result2, 2, 1, 2);
}

/**
 * @tc.name: GetPermissionUsedRecordsAsync001
 * @tc.desc: cannot GetPermissionUsedRecordsAsync with invalid query time.
 * @tc.type: FUNC
 * @tc.require: issueI5P4IU
 */
HWTEST_F(PrivacyKitTest, GetPermissionUsedRecordsAsync001, TestSize.Level0)
{
    AddPermParamInfo info;
    info.tokenId = g_tokenIdA;
    info.permissionName = "ohos.permission.READ_CONTACTS";
    info.successCount = 1;
    info.failCount = 0;
    EXPECT_EQ(RET_NO_ERROR, PrivacyKit::AddPermissionUsedRecord(info));
    PermissionUsedRequest request;
    std::vector<std::string> permissionList;
    BuildQueryRequest(g_tokenIdA, "", permissionList, request);
    request.beginTimeMillis = -1;
    request.endTimeMillis = -1;
    OHOS::sptr<TestCallBack> callback(new TestCallBack());
    EXPECT_EQ(PrivacyError::ERR_PARAM_INVALID, PrivacyKit::GetPermissionUsedRecords(request, callback));
}

/**
 * @tc.name: GetPermissionUsedRecordsAsync002
 * @tc.desc: cannot GetPermissionUsedRecordsAsync with valid query time.
 * @tc.type: FUNC
 * @tc.require: issueI5P4IU
 */
HWTEST_F(PrivacyKitTest, GetPermissionUsedRecordsAsync002, TestSize.Level0)
{
    AddPermParamInfo info;
    info.tokenId = g_tokenIdA;
    info.permissionName = "ohos.permission.READ_CONTACTS";
    info.successCount = 1;
    info.failCount = 0;
    EXPECT_EQ(RET_NO_ERROR, PrivacyKit::AddPermissionUsedRecord(info));
    PermissionUsedRequest request;
    std::vector<std::string> permissionList;
    BuildQueryRequest(g_tokenIdA, "", permissionList, request);
    OHOS::sptr<TestCallBack> callback(new TestCallBack());
    EXPECT_EQ(RET_NO_ERROR, PrivacyKit::GetPermissionUsedRecords(request, callback));
}

/**
 * @tc.name: GetPermissionUsedRecordsAsync003
 * @tc.desc: cannot GetPermissionUsedRecordsAsync without permission.
 * @tc.type: FUNC
 * @tc.require: issueI5P4IU
 */
HWTEST_F(PrivacyKitTest, GetPermissionUsedRecordsAsync003, TestSize.Level0)
{
    std::vector<std::string> reqPerm;
    MockHapToken mock("GetPermissionUsedRecordsAsync003", reqPerm, true);
    AccessTokenID tokenID = GetSelfTokenID();

    PermissionUsedRequest request;
    std::vector<std::string> permissionList;
    BuildQueryRequest(tokenID, "", permissionList, request);
    OHOS::sptr<TestCallBack> callback(new TestCallBack());
    EXPECT_EQ(ERR_PERMISSION_DENIED, PrivacyKit::GetPermissionUsedRecords(request, callback));
}

/**
 * @tc.name: GetPermissionUsedRecordsAsync004
 * @tc.desc: cannot GetPermissionUsedRecordsAsync caller is normal app.
 * @tc.type: FUNC
 * @tc.require: issueI5P4IU
 */
HWTEST_F(PrivacyKitTest, GetPermissionUsedRecordsAsync004, TestSize.Level0)
{
    std::vector<std::string> reqPerm;
    MockHapToken mock("GetPermissionUsedRecordsAsync004", reqPerm, false);
    AccessTokenID tokenID = GetSelfTokenID();

    PermissionUsedRequest request;
    std::vector<std::string> permissionList;
    BuildQueryRequest(tokenID, "", permissionList, request);
    OHOS::sptr<TestCallBack> callback(new TestCallBack());
    EXPECT_EQ(PrivacyError::ERR_NOT_SYSTEM_APP, PrivacyKit::GetPermissionUsedRecords(request, callback));
}

class CbCustomizeTest1 : public PermActiveStatusCustomizedCbk {
public:
    explicit CbCustomizeTest1(const std::vector<std::string> &permList)
        : PermActiveStatusCustomizedCbk(permList)
    {
        GTEST_LOG_(INFO) << "CbCustomizeTest1 create";
    }

    ~CbCustomizeTest1()
    {}

    virtual void ActiveStatusChangeCallback(ActiveChangeResponse& result)
    {
        type_ = result.type;
        GTEST_LOG_(INFO) << "CbCustomizeTest1 ActiveChangeResponse";
        GTEST_LOG_(INFO) << "CbCustomizeTest1 tokenid " << result.tokenID;
        GTEST_LOG_(INFO) << "CbCustomizeTest1 permissionName " << result.permissionName;
        GTEST_LOG_(INFO) << "CbCustomizeTest1 deviceId " << result.deviceId;
        GTEST_LOG_(INFO) << "CbCustomizeTest1 type " << result.type;
    }

    ActiveChangeType type_ = PERM_INACTIVE;
};

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

    ActiveChangeType type_;
};

/**
 * @tc.name: RegisterPermActiveStatusCallback001
 * @tc.desc: RegisterPermActiveStatusCallback with valid permission.
 * @tc.type: FUNC
 * @tc.require: issueI5NT1X issueI5P4IU issueI5P530
 */
HWTEST_F(PrivacyKitTest, RegisterPermActiveStatusCallback001, TestSize.Level0)
{
    std::vector<std::string> permList = {"ohos.permission.READ_MEDIA"};

    auto callbackPtr = std::make_shared<CbCustomizeTest1>(permList);
    callbackPtr->type_ = PERM_TEMPORARY_CALL;

    EXPECT_EQ(RET_NO_ERROR, PrivacyKit::RegisterPermActiveStatusCallback(callbackPtr));
    EXPECT_EQ(RET_NO_ERROR, PrivacyKit::StartUsingPermission(g_tokenIdE, "ohos.permission.READ_MEDIA"));

    usleep(1000000); // 1000000us = 1s
    EXPECT_EQ(PERM_ACTIVE_IN_BACKGROUND, callbackPtr->type_);

    EXPECT_EQ(RET_NO_ERROR, PrivacyKit::StopUsingPermission(g_tokenIdE, "ohos.permission.READ_MEDIA"));

    usleep(1000000); // 1000000us = 1s
    EXPECT_EQ(PERM_INACTIVE, callbackPtr->type_);

    EXPECT_EQ(RET_NO_ERROR, PrivacyKit::UnRegisterPermActiveStatusCallback(callbackPtr));
    callbackPtr->type_ = PERM_TEMPORARY_CALL;

    EXPECT_EQ(RET_NO_ERROR, PrivacyKit::StartUsingPermission(g_tokenIdE, "ohos.permission.READ_MEDIA"));
    EXPECT_NE(PERM_INACTIVE, callbackPtr->type_);
    EXPECT_NE(PERM_ACTIVE_IN_FOREGROUND, callbackPtr->type_);
    EXPECT_NE(PERM_ACTIVE_IN_BACKGROUND, callbackPtr->type_);

    EXPECT_EQ(RET_NO_ERROR, PrivacyKit::StopUsingPermission(g_tokenIdE, "ohos.permission.READ_MEDIA"));
    EXPECT_NE(PERM_INACTIVE, callbackPtr->type_);
    EXPECT_NE(PERM_ACTIVE_IN_FOREGROUND, callbackPtr->type_);
    EXPECT_NE(PERM_ACTIVE_IN_BACKGROUND, callbackPtr->type_);
}

class CbCustomizeTest3 : public PermActiveStatusCustomizedCbk {
public:
    explicit CbCustomizeTest3(const std::vector<std::string> &permList)
        : PermActiveStatusCustomizedCbk(permList)
    {}
    ~CbCustomizeTest3()
    {}
    virtual void ActiveStatusChangeCallback(ActiveChangeResponse& result)
    {
        type_ = result.type;
    }
    ActiveChangeType type_ = PERM_INACTIVE;
};

class CbCustomizeTest4 : public StateCustomizedCbk {
public:
    CbCustomizeTest4()
    {}

    ~CbCustomizeTest4()
    {}

    virtual void StateChangeNotify(AccessTokenID tokenId, bool isShow)
    {}
};

/**
 * @tc.name: RegisterPermActiveStatusCallback002
 * @tc.desc: RegisterPermActiveStatusCallback with valid permission.
 * @tc.type: FUNC
 * @tc.require: issueI5NT1X issueI5P4IU issueI5P530
 */
HWTEST_F(PrivacyKitTest, RegisterPermActiveStatusCallback002, TestSize.Level0)
{
    std::vector<std::string> permList1 = {"ohos.permission.READ_CONTACTS"};
    auto callbackPtr1 = std::make_shared<CbCustomizeTest1>(permList1);
    callbackPtr1->type_ = PERM_TEMPORARY_CALL;

    std::vector<std::string> permList2 = {"ohos.permission.READ_MEDIA"};
    auto callbackPtr2 = std::make_shared<CbCustomizeTest2>(permList2);
    callbackPtr2->type_ = PERM_TEMPORARY_CALL;

    std::vector<std::string> permList3 = {};
    auto callbackPtr3 = std::make_shared<CbCustomizeTest2>(permList3);
    callbackPtr3->type_ = PERM_TEMPORARY_CALL;

    EXPECT_EQ(RET_NO_ERROR, PrivacyKit::RegisterPermActiveStatusCallback(callbackPtr1));
    EXPECT_EQ(RET_NO_ERROR, PrivacyKit::RegisterPermActiveStatusCallback(callbackPtr2));
    EXPECT_EQ(RET_NO_ERROR, PrivacyKit::RegisterPermActiveStatusCallback(callbackPtr3));

    EXPECT_EQ(RET_NO_ERROR, PrivacyKit::StartUsingPermission(g_tokenIdE, "ohos.permission.READ_CONTACTS"));

    usleep(1000000); // 1000000us = 1s
    EXPECT_EQ(PERM_ACTIVE_IN_BACKGROUND, callbackPtr1->type_);
    EXPECT_EQ(PERM_ACTIVE_IN_BACKGROUND, callbackPtr3->type_);

    EXPECT_EQ(RET_NO_ERROR, PrivacyKit::StopUsingPermission(g_tokenIdE, "ohos.permission.READ_CONTACTS"));

    usleep(1000000); // 1000000us = 1s
    EXPECT_EQ(PERM_INACTIVE, callbackPtr1->type_);
    EXPECT_EQ(PERM_INACTIVE, callbackPtr3->type_);

    EXPECT_EQ(RET_NO_ERROR, PrivacyKit::StartUsingPermission(g_tokenIdE, "ohos.permission.READ_MEDIA"));

    usleep(1000000); // 1000000us = 1s
    EXPECT_EQ(PERM_ACTIVE_IN_BACKGROUND, callbackPtr2->type_);
    EXPECT_EQ(PERM_ACTIVE_IN_BACKGROUND, callbackPtr3->type_);

    EXPECT_EQ(RET_NO_ERROR, PrivacyKit::StopUsingPermission(g_tokenIdE, "ohos.permission.READ_MEDIA"));

    usleep(1000000); // 1000000us = 1s
    EXPECT_EQ(PERM_INACTIVE, callbackPtr2->type_);
    EXPECT_EQ(PERM_INACTIVE, callbackPtr3->type_);

    EXPECT_EQ(RET_NO_ERROR, PrivacyKit::UnRegisterPermActiveStatusCallback(callbackPtr1));
    EXPECT_EQ(RET_NO_ERROR, PrivacyKit::UnRegisterPermActiveStatusCallback(callbackPtr2));
    EXPECT_EQ(RET_NO_ERROR, PrivacyKit::UnRegisterPermActiveStatusCallback(callbackPtr3));
}

/**
 * @tc.name: RegisterPermActiveStatusCallback003
 * @tc.desc: Register callback with permList which contains 1025 permissions.
 * @tc.type: FUNC
 * @tc.require: issueI5NT1X
 */
HWTEST_F(PrivacyKitTest, RegisterPermActiveStatusCallback003, TestSize.Level0)
{
    std::vector<std::string> permList;
    for (int32_t i = 0; i < 1024; i++) { // 1024 is the limitation
        permList.emplace_back("ohos.permission.CAMERA");
    }
    auto callbackPtr1 = std::make_shared<CbCustomizeTest3>(permList);
    EXPECT_EQ(RET_NO_ERROR, PrivacyKit::RegisterPermActiveStatusCallback(callbackPtr1));
    EXPECT_EQ(RET_NO_ERROR, PrivacyKit::UnRegisterPermActiveStatusCallback(callbackPtr1));

    permList.emplace_back("ohos.permission.MICROPHONE");
    auto callbackPtr = std::make_shared<CbCustomizeTest3>(permList);
    EXPECT_EQ(PrivacyError::ERR_PARAM_INVALID, PrivacyKit::RegisterPermActiveStatusCallback(callbackPtr));
}

/**
 * @tc.name: RegisterPermActiveStatusCallback004
 * @tc.desc: Register callback 201 times.
 * @tc.type: FUNC
 * @tc.require: issueI5NT1X
 */
HWTEST_F(PrivacyKitTest, RegisterPermActiveStatusCallback004, TestSize.Level0)
{
    std::vector<std::string> permList = {"ohos.permission.CAMERA"};
    std::vector<std::shared_ptr<CbCustomizeTest3>> callbackList;

    for (int32_t i = 0; i <= 200; i++) { // 200 is the max size
        if (i == 200) { // 200 is the max size
            auto callbackPtr = std::make_shared<CbCustomizeTest3>(permList);
            EXPECT_EQ(PrivacyError::ERR_CALLBACKS_EXCEED_LIMITATION,
                PrivacyKit::RegisterPermActiveStatusCallback(callbackPtr));
            break;
        }
        auto callbackPtr = std::make_shared<CbCustomizeTest3>(permList);
        EXPECT_EQ(RET_NO_ERROR, PrivacyKit::RegisterPermActiveStatusCallback(callbackPtr));
        callbackList.emplace_back(callbackPtr);
    }
    for (int32_t i = 0; i < 200; i++) { // release 200 callback
        auto callbackPtr = callbackList[i];
        EXPECT_EQ(RET_NO_ERROR, PrivacyKit::UnRegisterPermActiveStatusCallback(callbackPtr));
    }
    callbackList.clear();
}

/**
 * @tc.name: RegisterPermActiveStatusCallback005
 * @tc.desc: RegisterPermActiveStatusCallback with valid permission.
 * @tc.type: FUNC
 * @tc.require: issueI5NT1X
 */
HWTEST_F(PrivacyKitTest, RegisterPermActiveStatusCallback005, TestSize.Level0)
{
    std::vector<std::string> permList = {"ohos.permission.INVALD"};

    auto callbackPtr = std::make_shared<CbCustomizeTest3>(permList);
    EXPECT_EQ(PrivacyError::ERR_PARAM_INVALID, PrivacyKit::RegisterPermActiveStatusCallback(callbackPtr));

    std::vector<std::string> permList1 = {"ohos.permission.INVALD", "ohos.permission.CAMERA"};
    auto callbackPtr1 = std::make_shared<CbCustomizeTest3>(permList1);
    EXPECT_EQ(RET_NO_ERROR, PrivacyKit::RegisterPermActiveStatusCallback(callbackPtr1));
    EXPECT_EQ(RET_NO_ERROR, PrivacyKit::UnRegisterPermActiveStatusCallback(callbackPtr1));
}

/**
 * @tc.name: RegisterPermActiveStatusCallback006
 * @tc.desc: UnRegisterPermActiveStatusCallback with invalid callback.
 * @tc.type: FUNC
 * @tc.require: issueI5NT1X
 */
HWTEST_F(PrivacyKitTest, RegisterPermActiveStatusCallback006, TestSize.Level0)
{
    std::vector<std::string> permList = {"ohos.permission.CAMERA"};
    auto callbackPtr = std::make_shared<CbCustomizeTest3>(permList);
    EXPECT_EQ(PrivacyError::ERR_CALLBACK_NOT_EXIST, PrivacyKit::UnRegisterPermActiveStatusCallback(callbackPtr));
}

/**
 * @tc.name: RegisterPermActiveStatusCallback007
 * @tc.desc: RegisterPermActiveStatusCallback with valid permission repeatedly.
 * @tc.type: FUNC
 * @tc.require: issueI5NT1X
 */
HWTEST_F(PrivacyKitTest, RegisterPermActiveStatusCallback007, TestSize.Level0)
{
    std::vector<std::string> permList = {"ohos.permission.CAMERA"};
    auto callbackPtr = std::make_shared<CbCustomizeTest3>(permList);
    EXPECT_EQ(RET_NO_ERROR, PrivacyKit::RegisterPermActiveStatusCallback(callbackPtr));
    EXPECT_EQ(PrivacyError::ERR_CALLBACK_ALREADY_EXIST, PrivacyKit::RegisterPermActiveStatusCallback(callbackPtr));
    EXPECT_EQ(RET_NO_ERROR, PrivacyKit::UnRegisterPermActiveStatusCallback(callbackPtr));
    EXPECT_EQ(PrivacyError::ERR_CALLBACK_NOT_EXIST, PrivacyKit::UnRegisterPermActiveStatusCallback(callbackPtr));
}

/**
 * @tc.name: RegisterPermActiveStatusCallback008
 * @tc.desc: register and startusing three permission.
 * @tc.type: FUNC
 * @tc.require: issueI5SZHG
 */
HWTEST_F(PrivacyKitTest, RegisterPermActiveStatusCallback008, TestSize.Level0)
{
    std::vector<std::string> permList = {
        "ohos.permission.INVALID",
        "ohos.permission.CAMERA",
        "ohos.permission.CAMERA",
        "ohos.permission.MICROPHONE",
        "ohos.permission.LOCATION"
    };
    auto callbackPtr = std::make_shared<CbCustomizeTest3>(permList);
    int32_t res = PrivacyKit::RegisterPermActiveStatusCallback(callbackPtr);
    EXPECT_EQ(RET_NO_ERROR, res);
    res = PrivacyKit::StartUsingPermission(g_tokenIdE, "ohos.permission.CAMERA");
    EXPECT_EQ(RET_NO_ERROR, res);
    res = PrivacyKit::StartUsingPermission(g_tokenIdE, "ohos.permission.MICROPHONE");
    EXPECT_EQ(RET_NO_ERROR, res);
    res = PrivacyKit::StartUsingPermission(g_tokenIdE, "ohos.permission.LOCATION");
    EXPECT_EQ(RET_NO_ERROR, res);
    res = PrivacyKit::StopUsingPermission(g_tokenIdE, "ohos.permission.CAMERA");
    EXPECT_EQ(RET_NO_ERROR, res);
    res = PrivacyKit::StopUsingPermission(g_tokenIdE, "ohos.permission.MICROPHONE");
    EXPECT_EQ(RET_NO_ERROR, res);
    res = PrivacyKit::StopUsingPermission(g_tokenIdE, "ohos.permission.LOCATION");
    EXPECT_EQ(RET_NO_ERROR, res);
    res = PrivacyKit::UnRegisterPermActiveStatusCallback(callbackPtr);
    EXPECT_EQ(RET_NO_ERROR, res);
}

/**
 * @tc.name: RegisterPermActiveStatusCallback009
 * @tc.desc: PrivacyManagerClient::RegisterPermActiveStatusCallback function test
 * @tc.type: FUNC
 * @tc.require: issueI61A6M
 */
HWTEST_F(PrivacyKitTest, RegisterPermActiveStatusCallback009, TestSize.Level0)
{
    std::shared_ptr<PermActiveStatusCustomizedCbk> callback = nullptr;
    EXPECT_EQ(nullptr, callback);
    PrivacyManagerClient::GetInstance().RegisterPermActiveStatusCallback(callback); // callback is null
}

/**
 * @tc.name: RegisterPermActiveStatusCallback010
 * @tc.desc: RegisterPermActiveStatusCallback caller is normal app.
 * @tc.type: FUNC
 * @tc.require: issueI66BH3
 */
HWTEST_F(PrivacyKitTest, RegisterPermActiveStatusCallback010, TestSize.Level0)
{
    std::vector<std::string> reqPerm;
    MockHapToken mock("RegisterPermActiveStatusCallback010", reqPerm, false);

    std::vector<std::string> permList1 = {"ohos.permission.CAMERA"};
    auto callbackPtr = std::make_shared<CbCustomizeTest3>(permList1);
    EXPECT_EQ(PrivacyError::ERR_NOT_SYSTEM_APP, PrivacyKit::RegisterPermActiveStatusCallback(callbackPtr));
}

/**
 * @tc.name: RegisterPermActiveStatusCallback011
 * @tc.desc: UnRegisterPermActiveStatusCallback caller is normal app.
 * @tc.type: FUNC
 * @tc.require: issueI66BH3
 */
HWTEST_F(PrivacyKitTest, RegisterPermActiveStatusCallback011, TestSize.Level0)
{
    std::vector<std::string> permList1 = {"ohos.permission.CAMERA"};
    auto callbackPtr1 = std::make_shared<CbCustomizeTest3>(permList1);
    EXPECT_EQ(RET_NO_ERROR, PrivacyKit::RegisterPermActiveStatusCallback(callbackPtr1));
    {
        std::vector<std::string> reqPerm;
        MockHapToken mockTmp("RegisterPermActiveStatusCallback011_1", reqPerm, false);
        EXPECT_EQ(PrivacyError::ERR_NOT_SYSTEM_APP, PrivacyKit::UnRegisterPermActiveStatusCallback(callbackPtr1));
    }
    EXPECT_EQ(RET_NO_ERROR, PrivacyKit::UnRegisterPermActiveStatusCallback(callbackPtr1));
}

class CbCustomizeTest5 : public PermActiveStatusCustomizedCbk {
public:
    explicit CbCustomizeTest5(const std::vector<std::string> &permList)
        : PermActiveStatusCustomizedCbk(permList)
    {}
    ~CbCustomizeTest5()
    {}

    // change callingTokenID_ and usedType_ to result
    virtual void ActiveStatusChangeCallback(ActiveChangeResponse& result)
    {
        callingTokenID_ = result.callingTokenID;
        usedType_ = result.usedType;
        pid_ = result.pid;
    }

    AccessTokenID callingTokenID_ = INVALID_TOKENID;
    PermissionUsedType usedType_ = INVALID_USED_TYPE;
    int32_t pid_ = NOT_EXSIT_PID;
};

/**
 * @tc.name: RegisterPermActiveStatusCallback012
 * @tc.desc: detect callback modify private member.
 * @tc.type: FUNC
 * @tc.require: issueI66BH3
 */
HWTEST_F(PrivacyKitTest, RegisterPermActiveStatusCallback012, TestSize.Level0)
{
    std::vector<std::string> permList = {"ohos.permission.READ_CALL_LOG"};
    auto callbackPtr = std::make_shared<CbCustomizeTest5>(permList);
    EXPECT_EQ(RET_NO_ERROR, PrivacyKit::RegisterPermActiveStatusCallback(callbackPtr));

    EXPECT_EQ(RET_NO_ERROR, PrivacyKit::StartUsingPermission(g_tokenIdE, "ohos.permission.READ_CALL_LOG"));

    usleep(1000000); // 1000000us = 1s
    EXPECT_NE(INVALID_TOKENID, callbackPtr->callingTokenID_);
    EXPECT_NE(INVALID_USED_TYPE, callbackPtr->usedType_);
    EXPECT_NE(NOT_EXSIT_PID, callbackPtr->pid_);

    EXPECT_EQ(RET_NO_ERROR, PrivacyKit::StopUsingPermission(g_tokenIdE, "ohos.permission.READ_CALL_LOG"));
    usleep(1000000); // 1000000us = 1s

    EXPECT_EQ(RET_NO_ERROR, PrivacyKit::StartUsingPermission(
        g_tokenIdE, "ohos.permission.READ_CALL_LOG", NOT_EXSIT_PID));
    usleep(1000000); // 1000000us = 1s

    EXPECT_EQ(NOT_EXSIT_PID, callbackPtr->pid_);

    EXPECT_EQ(RET_NO_ERROR, PrivacyKit::StopUsingPermission(
        g_tokenIdE, "ohos.permission.READ_CALL_LOG", NOT_EXSIT_PID));

    EXPECT_EQ(RET_NO_ERROR, PrivacyKit::UnRegisterPermActiveStatusCallback(callbackPtr));
}

/**
 * @tc.name: IsAllowedUsingPermission001
 * @tc.desc: IsAllowedUsingPermission with invalid tokenId or permission.
 * @tc.type: FUNC
 * @tc.require: issueI5RWX3 issueI5RWX8
 */
HWTEST_F(PrivacyKitTest, IsAllowedUsingPermission001, TestSize.Level0)
{
    std::string permissionName = "ohos.permission.CAMERA";
    EXPECT_EQ(false, PrivacyKit::IsAllowedUsingPermission(g_tokenIdE, permissionName));
    EXPECT_EQ(false, PrivacyKit::IsAllowedUsingPermission(0, permissionName));
    EXPECT_EQ(false, PrivacyKit::IsAllowedUsingPermission(g_tokenIdE, ""));
    EXPECT_EQ(false, PrivacyKit::IsAllowedUsingPermission(0, ""));
}

/**
 * @tc.name: IsAllowedUsingPermission002
 * @tc.desc: IsAllowedUsingPermission with no permission.
 * @tc.type: FUNC
 * @tc.require: issueI5RWX3 issueI5RWX8
 */
HWTEST_F(PrivacyKitTest, IsAllowedUsingPermission002, TestSize.Level0)
{
    std::vector<std::string> reqPerm;
    MockHapToken mock("IsAllowedUsingPermission002", reqPerm, true);
    std::string permissionName = "ohos.permission.CAMERA";
    EXPECT_EQ(false, PrivacyKit::IsAllowedUsingPermission(g_tokenIdE, permissionName));
}

/**
 * @tc.name: IsAllowedUsingPermission003
 * @tc.desc: IsAllowedUsingPermission with no permission.
 * @tc.type: FUNC
 * @tc.require: issueI5RWX3 issueI5RWX8
 */
HWTEST_F(PrivacyKitTest, IsAllowedUsingPermission003, TestSize.Level0)
{
    std::vector<std::string> reqPerm;
    MockHapToken mock("IsAllowedUsingPermission003", reqPerm, true);

    std::string permissionName = "ohos.permission.CAMERA";
    EXPECT_EQ(false, PrivacyKit::IsAllowedUsingPermission(g_tokenIdE, permissionName));
}


/**
 * @tc.name: IsAllowedUsingPermission004
 * @tc.desc: IsAllowedUsingPermission with valid tokenId.
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(PrivacyKitTest, IsAllowedUsingPermission004, TestSize.Level0)
{
    std::string permissionName = "ohos.permission.MICROPHONE";
    std::vector<AppStateData> list;
    int32_t ret = AppManagerAccessClient::GetInstance().GetForegroundApplications(list);
    EXPECT_EQ(0, ret);
    if (list.empty()) {
        GTEST_LOG_(INFO) << "GetForegroundApplications empty ";
    } else {
        uint32_t tokenIdForeground = list[0].accessTokenId;
        EXPECT_EQ(true, PrivacyKit::IsAllowedUsingPermission(tokenIdForeground, permissionName));
    }
}

/**
 * @tc.name: IsAllowedUsingPermission005
 * @tc.desc: IsAllowedUsingPermission with valid pid.
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(PrivacyKitTest, IsAllowedUsingPermission005, TestSize.Level0)
{
    std::vector<AppStateData> list;
    EXPECT_EQ(0, AppManagerAccessClient::GetInstance().GetForegroundApplications(list));
    if (list.empty()) {
        GTEST_LOG_(INFO) << "GetForegroundApplications empty ";
    } else {
        uint32_t tokenIdForeground = list[0].accessTokenId;
        int32_t pidForground = list[0].pid;
        std::string permissionName = "ohos.permission.MICROPHONE";
        EXPECT_EQ(false, PrivacyKit::IsAllowedUsingPermission(tokenIdForeground, permissionName, NOT_EXSIT_PID));
        EXPECT_EQ(true, PrivacyKit::IsAllowedUsingPermission(tokenIdForeground, permissionName, pidForground));

        permissionName = "ohos.permission.CAMERA";
        EXPECT_EQ(false, PrivacyKit::IsAllowedUsingPermission(tokenIdForeground, permissionName, NOT_EXSIT_PID));
        EXPECT_EQ(true, PrivacyKit::IsAllowedUsingPermission(tokenIdForeground, permissionName, pidForground));
    }
}

/**
 * @tc.name: IsAllowedUsingPermission006
 * @tc.desc: IsAllowedUsingPermission with MICROPHONE_BACKGROUND permission.
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(PrivacyKitTest, IsAllowedUsingPermission006, TestSize.Level0)
{
    std::string permissionName = "ohos.permission.MICROPHONE";
    EXPECT_EQ(false, PrivacyKit::IsAllowedUsingPermission(g_tokenIdE, permissionName));

    HapInfoParams info = {
        .userID = 1,
        .bundleName = "ohos.privacy_test.microphone",
        .instIndex = 0,
        .appIDDesc = "privacy_test.microphone"
    };

    HapPolicyParams policy = {
        .apl = APL_NORMAL,
        .domain = "test.domain",
        .permList = {},
        .permStateList = {g_infoManagerTestStateD}
    };

    AccessTokenIDEx tokenIdEx = PrivacyTestCommon::AllocTestHapToken(info, policy);
    AccessTokenID tokenId = tokenIdEx.tokenIdExStruct.tokenID;
    EXPECT_NE(0, tokenId); // hap MICROPHONE_BACKGROUND permission
    EXPECT_EQ(true, PrivacyKit::IsAllowedUsingPermission(tokenId, permissionName)); // background hap

    {
        MockNativeToken mock("audio_server");

        // callkit set hap to foreground with MICROPHONE_BACKGROUND
        EXPECT_EQ(0, PrivacyKit::SetHapWithFGReminder(tokenId, true));
        EXPECT_EQ(true, PrivacyKit::IsAllowedUsingPermission(tokenId, permissionName));

        // callkit set g_tokenIdE to foreground without MICROPHONE_BACKGROUND
        EXPECT_EQ(0, PrivacyKit::SetHapWithFGReminder(g_tokenIdE, true));
        EXPECT_EQ(true, PrivacyKit::IsAllowedUsingPermission(g_tokenIdE, permissionName));

        EXPECT_EQ(0, PrivacyKit::SetHapWithFGReminder(tokenId, false));
        EXPECT_EQ(0, PrivacyKit::SetHapWithFGReminder(g_tokenIdE, false));
    }

    EXPECT_EQ(0, PrivacyTestCommon::DeleteTestHapToken(tokenId));
}

/**
 * @tc.name: IsAllowedUsingPermission007
 * @tc.desc: IsAllowedUsingPermission with not system app.
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(PrivacyKitTest, IsAllowedUsingPermission007, TestSize.Level0)
{
    std::vector<std::string> reqPerm;
    reqPerm.emplace_back("ohos.permission.PERMISSION_USED_STATS");
    MockHapToken mock("SetPermissionUsedRecordToggleStatus004", reqPerm, false);

    std::string permissionName = "ohos.permission.MICROPHONE";
    EXPECT_EQ(false, PrivacyKit::IsAllowedUsingPermission(g_tokenIdE, permissionName));
}

/**
 * @tc.name: StartUsingPermission001
 * @tc.desc: StartUsingPermission with invalid tokenId or permission or usedType.
 * @tc.type: FUNC
 * @tc.require: issueI5NT1X issueI5P4IU issueI5P530
 */
HWTEST_F(PrivacyKitTest, StartUsingPermission001, TestSize.Level0)
{
    EXPECT_EQ(PrivacyError::ERR_PARAM_INVALID, PrivacyKit::StartUsingPermission(0, "ohos.permission.CAMERA"));
    EXPECT_EQ(PrivacyError::ERR_PARAM_INVALID, PrivacyKit::StartUsingPermission(0, "permissionName"));
    EXPECT_EQ(PrivacyError::ERR_PARAM_INVALID, PrivacyKit::StartUsingPermission(
        g_tokenIdE, "ohos.permission.READ_CALL_LOG", -1, PermissionUsedType::INVALID_USED_TYPE));
}

/**
 * @tc.name: StartUsingPermission002
 * @tc.desc: StartUsingPermission is called twice with same permission.
 * @tc.type: FUNC
 * @tc.require: issueI5NT1X issueI5P4IU issueI5P530
 */
HWTEST_F(PrivacyKitTest, StartUsingPermission002, TestSize.Level0)
{
    std::string permissionName = "ohos.permission.CAMERA";
    EXPECT_EQ(RET_NO_ERROR, PrivacyKit::StartUsingPermission(g_tokenIdE, permissionName));
    EXPECT_EQ(PrivacyError::ERR_PERMISSION_ALREADY_START_USING,
        PrivacyKit::StartUsingPermission(g_tokenIdE, permissionName));
    EXPECT_EQ(RET_NO_ERROR, PrivacyKit::StopUsingPermission(g_tokenIdE, permissionName));
}

/**
 * @tc.name: StopUsingPermission003
 * @tc.desc: Add record when StopUsingPermission is called.
 * @tc.type: FUNC
 * @tc.require: issueI5NT1X issueI5P4IU issueI5P530
 */
HWTEST_F(PrivacyKitTest, StartUsingPermission003, TestSize.Level0)
{
    std::string permissionName = "ohos.permission.READ_CONTACTS";
    EXPECT_EQ(RET_NO_ERROR, PrivacyKit::StartUsingPermission(g_tokenIdE, permissionName));
    EXPECT_EQ(RET_NO_ERROR, PrivacyKit::AddPermissionUsedRecord(g_tokenIdE, permissionName, 1, 0));

    usleep(1000000); // 1000000us = 1s
    EXPECT_EQ(RET_NO_ERROR, PrivacyKit::StopUsingPermission(g_tokenIdE, permissionName));

    PermissionUsedRequest request;
    PermissionUsedResult result;
    std::vector<std::string> permissionList;
    BuildQueryRequest(g_tokenIdE, g_infoParmsE.bundleName, permissionList, request);
    EXPECT_EQ(RET_NO_ERROR, PrivacyKit::GetPermissionUsedRecords(request, result));
    EXPECT_EQ(static_cast<uint32_t>(1), result.bundleRecords.size());
    EXPECT_EQ(g_tokenIdE, result.bundleRecords[0].tokenId);
    EXPECT_EQ(g_infoParmsE.bundleName, result.bundleRecords[0].bundleName);
    EXPECT_EQ(static_cast<uint32_t>(1), result.bundleRecords[0].permissionRecords.size());
    EXPECT_EQ(1, result.bundleRecords[0].permissionRecords[0].accessCount);
}

/**
 * @tc.name: StartUsingPermission004
 * @tc.desc: StartUsingPermission basic functional verification
 * @tc.type: FUNC
 * @tc.require: issueI5NT1X issueI5P4IU issueI5P530
 */
HWTEST_F(PrivacyKitTest, StartUsingPermission004, TestSize.Level0)
{
    std::string permissionName = "ohos.permission.CAMERA";
    EXPECT_EQ(RET_NO_ERROR, PrivacyKit::StartUsingPermission(g_tokenIdE, permissionName));
    EXPECT_EQ(RET_NO_ERROR, PrivacyKit::StopUsingPermission(g_tokenIdE, permissionName));
}

/**
 * @tc.name: StartUsingPermission005
 * @tc.desc: StartUsingPermission with invalid tokenId or permission.
 * @tc.type: FUNC
 * @tc.require: issueI5NT1X issueI5P4IU issueI5P530
 */
HWTEST_F(PrivacyKitTest, StartUsingPermission005, TestSize.Level0)
{
    std::string permissionName = "ohos.permission.UtTestInvalidPermission";
    EXPECT_EQ(PrivacyError::ERR_PERMISSION_NOT_EXIST, PrivacyKit::StartUsingPermission(g_tokenIdE, permissionName));
    EXPECT_EQ(PrivacyError::ERR_PARAM_INVALID, PrivacyKit::StartUsingPermission(0, "ohos.permission.CAMERA"));
    EXPECT_EQ(
        PrivacyError::ERR_PARAM_INVALID, PrivacyKit::StartUsingPermission(g_nativeToken, "ohos.permission.CAMERA"));
}

/**
 * @tc.name: StartUsingPermission006
 * @tc.desc: StartUsingPermission with invalid tokenId or permission or callback or usedType.
 * @tc.type: FUNC
 * @tc.require: issueI5RWX5 issueI5RWX3 issueI5RWXA
 */
HWTEST_F(PrivacyKitTest, StartUsingPermission006, TestSize.Level0)
{
    auto callbackPtr = std::make_shared<CbCustomizeTest4>();
    EXPECT_EQ(PrivacyError::ERR_PARAM_INVALID,
        PrivacyKit::StartUsingPermission(0, "ohos.permission.CAMERA", callbackPtr));
    EXPECT_EQ(PrivacyError::ERR_PARAM_INVALID,
        PrivacyKit::StartUsingPermission(g_tokenIdE, "", callbackPtr));
    EXPECT_EQ(PrivacyError::ERR_PARAM_INVALID,
        PrivacyKit::StartUsingPermission(g_tokenIdE, "ohos.permission.CAMERA", nullptr));
    EXPECT_EQ(PrivacyError::ERR_PARAM_INVALID, PrivacyKit::StartUsingPermission(
        g_tokenIdE, "ohos.permission.READ_CALL_LOG", callbackPtr, -1, PermissionUsedType::INVALID_USED_TYPE));
    EXPECT_EQ(PrivacyError::ERR_PARAM_INVALID,
        PrivacyKit::StartUsingPermission(g_tokenIdE, "permissionName", callbackPtr));
}

/**
 * @tc.name: StartUsingPermission007
 * @tc.desc: StartUsingPermission is called twice with same callback.
 * @tc.type: FUNC
 * @tc.require: issueI5RWX5 issueI5RWX3 issueI5RWXA
 */
HWTEST_F(PrivacyKitTest, StartUsingPermission007, TestSize.Level0)
{
    std::string permissionName = "ohos.permission.CAMERA";
    auto callbackPtr = std::make_shared<CbCustomizeTest4>();
    EXPECT_EQ(RET_NO_ERROR, PrivacyKit::StartUsingPermission(g_tokenIdE, permissionName, callbackPtr));
    EXPECT_EQ(PrivacyError::ERR_CALLBACK_ALREADY_EXIST,
        PrivacyKit::StartUsingPermission(g_tokenIdE, permissionName, callbackPtr));
    EXPECT_EQ(RET_NO_ERROR, PrivacyKit::StopUsingPermission(g_tokenIdE, permissionName));
}

/**
 * @tc.name: StartUsingPermission008
 * @tc.desc: PrivacyKit:: function test input invalid
 * @tc.type: FUNC
 * @tc.require: issueI61A6M
 */
HWTEST_F(PrivacyKitTest, StartUsingPermission008, TestSize.Level0)
{
    AccessTokenID tokenId = 0;
    std::string permissionName;
    EXPECT_EQ(PrivacyError::ERR_PARAM_INVALID, PrivacyKit::StartUsingPermission(tokenId, permissionName));
    EXPECT_EQ(PrivacyError::ERR_PARAM_INVALID, PrivacyKit::StopUsingPermission(tokenId, permissionName));
    EXPECT_EQ(PrivacyError::ERR_PARAM_INVALID, PrivacyKit::RemovePermissionUsedRecords(tokenId));
    EXPECT_EQ(false, PrivacyKit::IsAllowedUsingPermission(tokenId, permissionName));
}

/**
 * @tc.name: StartUsingPermission009
 * @tc.desc: StartUsingPermission basic functional verification
 * @tc.type: FUNC
 * @tc.require: issueI5RWX5 issueI5RWX3 issueI5RWXA
 */
HWTEST_F(PrivacyKitTest, StartUsingPermission009, TestSize.Level0)
{
    std::string permissionName = "ohos.permission.CAMERA";
    auto callbackPtr = std::make_shared<CbCustomizeTest4>();
    EXPECT_EQ(RET_NO_ERROR, PrivacyKit::StartUsingPermission(g_tokenIdE, permissionName, callbackPtr));
    EXPECT_EQ(RET_NO_ERROR, PrivacyKit::StartUsingPermission(g_tokenIdF, permissionName, callbackPtr));
    EXPECT_EQ(RET_NO_ERROR, PrivacyKit::StopUsingPermission(g_tokenIdE, permissionName));
    EXPECT_EQ(RET_NO_ERROR, PrivacyKit::StopUsingPermission(g_tokenIdF, permissionName));
}

/**
 * @tc.name: StartUsingPermission010
 * @tc.desc: StartUsingPermission caller is normal app.
 * @tc.type: FUNC
 * @tc.require: issueI66BH3
 */
HWTEST_F(PrivacyKitTest, StartUsingPermission010, TestSize.Level0)
{
    std::vector<std::string> reqPerm;
    reqPerm.emplace_back("ohos.permission.PERMISSION_USED_STATS");
    MockHapToken mock("StartUsingPermission010", reqPerm, false);

    std::string permissionName = "ohos.permission.CAMERA";
    EXPECT_EQ(PrivacyError::ERR_NOT_SYSTEM_APP, PrivacyKit::StartUsingPermission(g_tokenIdE, permissionName));
}

/**
 * @tc.name: StartUsingPermission011
 * @tc.desc: StartUsingPermission with differet tokenId and pid.
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(PrivacyKitTest, StartUsingPermission011, TestSize.Level0)
{
    std::string permissionName = "ohos.permission.CAMERA";
    int32_t pid1 = 1001;
    int32_t pid2 = 1002;
    EXPECT_EQ(RET_SUCCESS, PrivacyKit::StartUsingPermission(g_tokenIdE, permissionName, pid1));
    EXPECT_EQ(RET_SUCCESS, PrivacyKit::StartUsingPermission(g_tokenIdF, permissionName, pid2));

    EXPECT_EQ(RET_SUCCESS, PrivacyKit::StopUsingPermission(g_tokenIdE, permissionName, pid1));
    EXPECT_EQ(RET_SUCCESS, PrivacyKit::StopUsingPermission(g_tokenIdF, permissionName, pid2));
}

/**
 * @tc.name: StartUsingPermission012
 * @tc.desc: StartUsingPermission with same tokenId and differet pid.
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(PrivacyKitTest, StartUsingPermission012, TestSize.Level0)
{
    std::string permissionName = "ohos.permission.CAMERA";
    int32_t pid1 = 1001;
    int32_t pid2 = 1002;
    EXPECT_EQ(RET_SUCCESS, PrivacyKit::StartUsingPermission(g_tokenIdE, permissionName, pid1));
    EXPECT_EQ(RET_SUCCESS, PrivacyKit::StartUsingPermission(g_tokenIdE, permissionName, pid2));

    EXPECT_EQ(RET_SUCCESS, PrivacyKit::StopUsingPermission(g_tokenIdE, permissionName, pid1));
    EXPECT_EQ(RET_SUCCESS, PrivacyKit::StopUsingPermission(g_tokenIdE, permissionName, pid2));
}

/**
 * @tc.name: StartUsingPermission013
 * @tc.desc: StartUsingPermission with same tokenId and pid.
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(PrivacyKitTest, StartUsingPermission013, TestSize.Level0)
{
    std::string permissionName = "ohos.permission.CAMERA";
    int32_t pid1 = 1001;
    EXPECT_EQ(RET_SUCCESS, PrivacyKit::StartUsingPermission(g_tokenIdE, permissionName, pid1));
    EXPECT_EQ(PrivacyError::ERR_PERMISSION_ALREADY_START_USING,
        PrivacyKit::StartUsingPermission(g_tokenIdE, permissionName, pid1));

    EXPECT_EQ(RET_SUCCESS, PrivacyKit::StopUsingPermission(g_tokenIdE, permissionName, pid1));
    EXPECT_EQ(PrivacyError::ERR_PERMISSION_NOT_START_USING,
        PrivacyKit::StopUsingPermission(g_tokenIdE, permissionName, pid1));
    EXPECT_EQ(PrivacyError::ERR_PERMISSION_NOT_START_USING,
        PrivacyKit::StopUsingPermission(g_tokenIdF, permissionName, pid1));
}

/**
 * @tc.name: StartUsingPermission014
 * @tc.desc: StartUsingPermission caller is normal app.
 * @tc.type: FUNC
 * @tc.require: issueI5RWX5 issueI5RWX3 issueI5RWXA
 */
HWTEST_F(PrivacyKitTest, StartUsingPermission014, TestSize.Level0)
{
    std::vector<std::string> reqPerm;
    reqPerm.emplace_back("ohos.permission.PERMISSION_USED_STATS");
    MockHapToken mock("StartUsingPermission014", reqPerm, false);

    std::string permissionName = "ohos.permission.CAMERA";
    auto callbackPtr = std::make_shared<CbCustomizeTest4>();
    EXPECT_EQ(PrivacyError::ERR_NOT_SYSTEM_APP,
        PrivacyKit::StartUsingPermission(g_tokenIdE, permissionName, callbackPtr));
}

/**
 * @tc.name: StartUsingPermission015
 * @tc.desc: StartUsingPermission function test.
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(PrivacyKitTest, StartUsingPermission015, TestSize.Level0)
{
    std::string permissionName = "ohos.permission.CAMERA";
    auto callbackPtr = std::make_shared<CbCustomizeTest4>();

    EXPECT_EQ(PrivacyError::ERR_PARAM_INVALID,
        PrivacyKit::StartUsingPermission(g_nativeToken, permissionName, callbackPtr));

    permissionName = "ohos.permission.MICROPHONE";
    EXPECT_EQ(PrivacyError::ERR_PARAM_INVALID,
        PrivacyKit::StartUsingPermission(g_nativeToken, permissionName, callbackPtr));

    EXPECT_EQ(PrivacyError::ERR_PARAM_INVALID,
        PrivacyKit::StartUsingPermission(g_shellToken, permissionName, callbackPtr));
}

/**
 * @tc.name: StartUsingPermission016
 * @tc.desc: StartUsingPermission caller is shell.
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(PrivacyKitTest, StartUsingPermission016, TestSize.Level0)
{
    std::string permissionName = "ohos.permission.CAMERA";

    EXPECT_EQ(PrivacyError::ERR_PARAM_INVALID, PrivacyKit::StartUsingPermission(g_nativeToken, permissionName));

    permissionName = "ohos.permission.MICROPHONE";
    EXPECT_EQ(PrivacyError::ERR_PARAM_INVALID, PrivacyKit::StartUsingPermission(g_nativeToken, permissionName));

    EXPECT_EQ(PrivacyError::ERR_PARAM_INVALID, PrivacyKit::StartUsingPermission(g_shellToken, permissionName));
}

/**
 * @tc.name: StopUsingPermission001
 * @tc.desc: StopUsingPermission with invalid tokenId or permission.
 * @tc.type: FUNC
 * @tc.require: issueI5NT1X issueI5P4IU issueI5P530
 */
HWTEST_F(PrivacyKitTest, StopUsingPermission001, TestSize.Level0)
{
    EXPECT_EQ(PrivacyError::ERR_PARAM_INVALID, PrivacyKit::StopUsingPermission(0, "ohos.permission.CAMERA"));
    EXPECT_EQ(PrivacyError::ERR_PARAM_INVALID, PrivacyKit::StopUsingPermission(0, "permissionName"));
}

/**
 * @tc.name: StopUsingPermission002
 * @tc.desc: StopUsingPermission cancel permissions that you haven't started using
 * @tc.type: FUNC
 * @tc.require: issueI5NT1X issueI5P4IU issueI5P530
 */
HWTEST_F(PrivacyKitTest, StopUsingPermission002, TestSize.Level0)
{
    std::string permissionName = "ohos.permission.CAMERA";
    EXPECT_EQ(
        PrivacyError::ERR_PERMISSION_NOT_START_USING, PrivacyKit::StopUsingPermission(g_tokenIdE, permissionName));
}

/**
 * @tc.name: StopUsingPermission003
 * @tc.desc: StopUsingPermission invalid tokenid, permission
 * @tc.type: FUNC
 * @tc.require: issueI5NT1X issueI5P4IU issueI5P530
 */
HWTEST_F(PrivacyKitTest, StopUsingPermission003, TestSize.Level0)
{
    std::string permissionName = "ohos.permission.CAMERA";
    EXPECT_EQ(RET_NO_ERROR, PrivacyKit::StartUsingPermission(g_tokenIdE, permissionName));
    EXPECT_EQ(PrivacyError::ERR_PERMISSION_NOT_EXIST,
        PrivacyKit::StopUsingPermission(g_tokenIdE, "ohos.permission.uttestpermission"));
    EXPECT_EQ(PrivacyError::ERR_PARAM_INVALID, PrivacyKit::StopUsingPermission(0, permissionName));
    EXPECT_EQ(RET_NO_ERROR, PrivacyKit::StopUsingPermission(g_tokenIdE, permissionName));
}

/**
 * @tc.name: StopUsingPermission004
 * @tc.desc: StopUsingPermission stop a use repeatedly
 * @tc.type: FUNC
 * @tc.require: issueI5NT1X issueI5P4IU issueI5P530
 */
HWTEST_F(PrivacyKitTest, StopUsingPermission004, TestSize.Level0)
{
    std::string permissionName = "ohos.permission.CAMERA";
    EXPECT_EQ(RET_NO_ERROR, PrivacyKit::StartUsingPermission(g_tokenIdE, permissionName));
    EXPECT_EQ(RET_NO_ERROR, PrivacyKit::StopUsingPermission(g_tokenIdE, permissionName));
    EXPECT_EQ(
        PrivacyError::ERR_PERMISSION_NOT_START_USING, PrivacyKit::StopUsingPermission(g_tokenIdE, permissionName));
}

/**
 * @tc.name: StopUsingPermission005
 * @tc.desc: stop use with native token
 * @tc.type: FUNC
 * @tc.require: issueI5SZHG
 */
HWTEST_F(PrivacyKitTest, StopUsingPermission005, TestSize.Level0)
{
    EXPECT_EQ(
        PrivacyError::ERR_PARAM_INVALID, PrivacyKit::StopUsingPermission(g_nativeToken, "ohos.permission.CAMERA"));
}

/**
 * @tc.name: StopUsingPermission006
 * @tc.desc: StopUsingPermission caller is normal app.
 * @tc.type: FUNC
 * @tc.require: issueI66BH3
 */
HWTEST_F(PrivacyKitTest, StopUsingPermission006, TestSize.Level0)
{
    std::vector<std::string> reqPerm;
    reqPerm.emplace_back("ohos.permission.PERMISSION_USED_STATS");
    MockHapToken mock("StopUsingPermission006", reqPerm, false);

    std::string permissionName = "ohos.permission.CAMERA";
    EXPECT_EQ(PrivacyError::ERR_NOT_SYSTEM_APP, PrivacyKit::StopUsingPermission(g_tokenIdE, permissionName));
}

/**
 * @tc.name: StopUsingPermission007
 * @tc.desc: Add record when StopUsingPermission is called.
 * @tc.type: FUNC
 * @tc.require: issueI5RWX5 issueI5RWX3 issueI5RWXA
 */
HWTEST_F(PrivacyKitTest, StopUsingPermission007, TestSize.Level0)
{
    std::string permissionName = "ohos.permission.READ_CONTACTS";
    auto callbackPtr = std::make_shared<CbCustomizeTest4>();
    EXPECT_EQ(RET_NO_ERROR, PrivacyKit::StartUsingPermission(g_tokenIdE, permissionName));
    EXPECT_EQ(RET_NO_ERROR, PrivacyKit::AddPermissionUsedRecord(g_tokenIdE, permissionName, 1, 0));

    usleep(1000000); // 1000000us = 1s
    EXPECT_EQ(RET_NO_ERROR, PrivacyKit::StopUsingPermission(g_tokenIdE, permissionName));

    PermissionUsedRequest request;
    PermissionUsedResult result;
    std::vector<std::string> permissionList;
    BuildQueryRequest(g_tokenIdE, g_infoParmsE.bundleName, permissionList, request);
    EXPECT_EQ(RET_NO_ERROR, PrivacyKit::GetPermissionUsedRecords(request, result));
    EXPECT_EQ(static_cast<uint32_t>(1), result.bundleRecords.size());
    EXPECT_EQ(g_tokenIdE, result.bundleRecords[0].tokenId);
    EXPECT_EQ(g_infoParmsE.bundleName, result.bundleRecords[0].bundleName);
    EXPECT_EQ(static_cast<uint32_t>(1), result.bundleRecords[0].permissionRecords.size());
    EXPECT_EQ(1, result.bundleRecords[0].permissionRecords[0].accessCount);
}

/**
 * @tc.name: StopUsingPermission008
 * @tc.desc: StopUsingPermission test with shell tokenid.
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(PrivacyKitTest, StopUsingPermission008, TestSize.Level0)
{
    std::string permissionName = "ohos.permission.CAMERA";

    EXPECT_EQ(PrivacyError::ERR_PARAM_INVALID, PrivacyKit::StopUsingPermission(g_nativeToken, permissionName));

    permissionName = "ohos.permission.MICROPHONE";
    EXPECT_EQ(PrivacyError::ERR_PARAM_INVALID, PrivacyKit::StopUsingPermission(g_nativeToken, permissionName));

    EXPECT_EQ(PrivacyError::ERR_PARAM_INVALID, PrivacyKit::StopUsingPermission(g_shellToken, permissionName));
}

/**
 * @tc.name: StopUsingPermission009
 * @tc.desc: StopUsingPermission test with different pid.
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(PrivacyKitTest, StopUsingPermission009, TestSize.Level0)
{
    auto callbackPtr = std::make_shared<CbCustomizeTest4>();
    EXPECT_EQ(0, PrivacyKit::StartUsingPermission(g_tokenIdE, "ohos.permission.CAMERA", callbackPtr));
    EXPECT_EQ(0, PrivacyKit::StopUsingPermission(g_tokenIdE, "ohos.permission.CAMERA"));
    EXPECT_EQ(0, PrivacyKit::StartUsingPermission(g_tokenIdE, "ohos.permission.CAMERA", callbackPtr, RANDOM_PID));
    EXPECT_EQ(0, PrivacyKit::StopUsingPermission(g_tokenIdE, "ohos.permission.CAMERA", RANDOM_PID));

    EXPECT_EQ(0, PrivacyKit::StartUsingPermission(g_tokenIdE, "ohos.permission.MICROPHONE"));
    EXPECT_EQ(0, PrivacyKit::StopUsingPermission(g_tokenIdE, "ohos.permission.MICROPHONE"));
    EXPECT_EQ(0, PrivacyKit::StartUsingPermission(g_tokenIdE, "ohos.permission.MICROPHONE", RANDOM_PID));
    EXPECT_EQ(0, PrivacyKit::StopUsingPermission(g_tokenIdE, "ohos.permission.MICROPHONE", RANDOM_PID));

    EXPECT_EQ(0, PrivacyKit::StartUsingPermission(g_tokenIdE, "ohos.permission.CAMERA"));
    EXPECT_EQ(0, PrivacyKit::StopUsingPermission(g_tokenIdE, "ohos.permission.CAMERA"));
    EXPECT_EQ(0, PrivacyKit::StartUsingPermission(g_tokenIdE, "ohos.permission.CAMERA", RANDOM_PID));
    EXPECT_EQ(0, PrivacyKit::StopUsingPermission(g_tokenIdE, "ohos.permission.CAMERA", RANDOM_PID));
}

class TestCallBack1 : public StateChangeCallbackStub {
public:
    TestCallBack1() = default;
    virtual ~TestCallBack1() = default;

    void StateChangeNotify(AccessTokenID tokenId, bool isShowing)
    {
        GTEST_LOG_(INFO) << "StateChangeNotify,  tokenId is " << tokenId << ", isShowing is " << isShowing;
    }
};

/**
 * @tc.name: OnRemoteRequest001
 * @tc.desc: StateChangeCallbackStub::OnRemoteRequest function test
 * @tc.type: FUNC
 * @tc.require: issueI61A6M
 */
HWTEST_F(PrivacyKitTest, OnRemoteRequest001, TestSize.Level0)
{
    AccessTokenID tokenId = 123; // 123 is random input
    bool isShowing = false;

    TestCallBack1 callback;
    OHOS::MessageParcel data;
    ASSERT_EQ(true, data.WriteInterfaceToken(IStateChangeCallback::GetDescriptor()));
    ASSERT_EQ(true, data.WriteUint32(tokenId));
    ASSERT_EQ(true, data.WriteBool(isShowing));

    OHOS::MessageParcel reply;
    OHOS::MessageOption option(OHOS::MessageOption::TF_SYNC);
    ASSERT_EQ(0, callback.OnRemoteRequest(static_cast<uint32_t>(IStateChangeCallback::STATE_CHANGE_CALLBACK),
        data, reply, option)); // descriptor true + msgCode true

    ASSERT_EQ(true, data.WriteInterfaceToken(IStateChangeCallback::GetDescriptor()));
    ASSERT_EQ(true, data.WriteUint32(tokenId));
    ASSERT_EQ(true, data.WriteBool(isShowing));
    uint32_t code = 10;
    ASSERT_NE(0, callback.OnRemoteRequest(code, data, reply, option)); // descriptor true + msgCode false

    std::string descriptor = "I don't know";
    data.WriteInterfaceToken(OHOS::Str8ToStr16(descriptor));
    ASSERT_EQ(true, data.WriteUint32(tokenId));
    ASSERT_EQ(true, data.WriteBool(isShowing));
    ASSERT_NE(0, callback.OnRemoteRequest(static_cast<uint32_t>(IStateChangeCallback::STATE_CHANGE_CALLBACK),
        data, reply, option)); // descriptor flase + msgCode true
}

class TestCallBack2 : public OnPermissionUsedRecordCallbackStub {
public:
    TestCallBack2() = default;
    virtual ~TestCallBack2() = default;

    void OnQueried(OHOS::ErrCode code, PermissionUsedResult& result)
    {
        GTEST_LOG_(INFO) << "OnQueried,  code is " << code;
    }
};

/**
 * @tc.name: OnRemoteRequest002
 * @tc.desc: OnPermissionUsedRecordCallbackStub::OnRemoteRequest function test
 * @tc.type: FUNC
 * @tc.require: issueI61A6M
 */
HWTEST_F(PrivacyKitTest, OnRemoteRequest002, TestSize.Level0)
{
    g_permissionUsedRecord.accessRecords.emplace_back(g_usedRecordDetail);
    g_bundleUsedRecord.permissionRecords.emplace_back(g_permissionUsedRecord);

    int32_t errCode = 123; // 123 is random input
    PermissionUsedResultParcel resultParcel;
    resultParcel.result = {
        .beginTimeMillis = 0L,
        .endTimeMillis = 0L,
    };
    resultParcel.result.bundleRecords.emplace_back(g_bundleUsedRecord);

    TestCallBack2 callback;
    OHOS::MessageParcel data;
    std::string descriptor = "I don't know";
    data.WriteInterfaceToken(OHOS::Str8ToStr16(descriptor));
    ASSERT_EQ(true, data.ReadInt32(errCode));
    ASSERT_EQ(true, data.WriteParcelable(&resultParcel));

    OHOS::MessageParcel reply;
    OHOS::MessageOption option(OHOS::MessageOption::TF_SYNC);
    ASSERT_NE(0, callback.OnRemoteRequest(static_cast<uint32_t>(PrivacyPermissionRecordInterfaceCode::ON_QUERIED),
        data, reply, option)); // descriptor false

    ASSERT_EQ(true, data.WriteInterfaceToken(OnPermissionUsedRecordCallback::GetDescriptor()));
    ASSERT_EQ(true, data.ReadInt32(errCode));
    ASSERT_EQ(true, data.WriteParcelable(&resultParcel));
    uint32_t code = 10;
    ASSERT_NE(0, callback.OnRemoteRequest(code, data, reply, option)); // descriptor true + msgCode false

    ASSERT_EQ(true, data.WriteInterfaceToken(OnPermissionUsedRecordCallback::GetDescriptor()));
    ASSERT_EQ(true, data.ReadInt32(errCode));
    ASSERT_EQ(true, data.WriteParcelable(&resultParcel));
    ASSERT_NE(0, callback.OnRemoteRequest(static_cast<uint32_t>(PrivacyPermissionRecordInterfaceCode::ON_QUERIED),
        data, reply, option)); // descriptor flase + msgCode true + error != 0
}

class TestCallBack3 : public PermActiveStatusChangeCallbackStub {
public:
    TestCallBack3() = default;
    virtual ~TestCallBack3() = default;

    void ActiveStatusChangeCallback(ActiveChangeResponse& result)
    {
        GTEST_LOG_(INFO) << "ActiveStatusChangeCallback,  result is " << result.type;
    }
};

/**
 * @tc.name: OnRemoteRequest003
 * @tc.desc: PermActiveStatusChangeCallbackStub::OnRemoteRequest function test
 * @tc.type: FUNC
 * @tc.require: issueI61A6M
 */
HWTEST_F(PrivacyKitTest, OnRemoteRequest003, TestSize.Level0)
{
    ActiveChangeResponse response = {
        .tokenID = 123,
        .permissionName = "ohos.permission.CAMERA",
        .deviceId = "I don't know",
        .type = ActiveChangeType::PERM_INACTIVE
    };

    ActiveChangeResponseParcel responseParcel;
    responseParcel.changeResponse = response;

    TestCallBack3 callback;
    OHOS::MessageParcel data;
    std::string descriptor = "I don't know";
    data.WriteInterfaceToken(OHOS::Str8ToStr16(descriptor));
    ASSERT_EQ(true, data.WriteParcelable(&responseParcel));

    OHOS::MessageParcel reply;
    OHOS::MessageOption option(OHOS::MessageOption::TF_SYNC);
    ASSERT_NE(0, callback.OnRemoteRequest(static_cast<uint32_t>(
        PrivacyActiveChangeInterfaceCode::PERM_ACTIVE_STATUS_CHANGE), data, reply, option)); // descriptor false

    ASSERT_EQ(true, data.WriteInterfaceToken(IPermActiveStatusCallback::GetDescriptor()));
    ASSERT_EQ(true, data.WriteParcelable(&responseParcel));
    uint32_t code = 10;
    ASSERT_NE(0, callback.OnRemoteRequest(code, data, reply, option)); // descriptor true + msgCode false
}

/**
 * @tc.name: ActiveStatusChangeCallback001
 * @tc.desc: PermActiveStatusChangeCallback::ActiveStatusChangeCallback function test
 * @tc.type: FUNC
 * @tc.require: issueI61A6M
 */
HWTEST_F(PrivacyKitTest, ActiveStatusChangeCallback001, TestSize.Level0)
{
    ActiveChangeResponse response = {
        .tokenID = 123,
        .permissionName = "ohos.permission.CAMERA",
        .deviceId = "I don't know",
        .type = ActiveChangeType::PERM_INACTIVE
    };
    std::vector<std::string> permList = {"ohos.permission.CAMERA"};
    std::shared_ptr<PermActiveStatusCustomizedCbk> callbackPtr = std::make_shared<CbCustomizeTest1>(permList);
    OHOS::sptr<PermActiveStatusChangeCallback> callback = new (
        std::nothrow) PermActiveStatusChangeCallback(callbackPtr);
    EXPECT_NE(nullptr, callback);
    callback->ActiveStatusChangeCallback(response); // customizedCallback_ is null
}

/**
 * @tc.name: StateChangeNotify001
 * @tc.desc: StateChangeCallback::StateChangeNotify function test
 * @tc.type: FUNC
 * @tc.require: issueI61A6M
 */
HWTEST_F(PrivacyKitTest, StateChangeNotify001, TestSize.Level0)
{
    AccessTokenID tokenId = 123; // 123 is random input
    bool isShowing = false;
    std::shared_ptr<StateCustomizedCbk> callbackPtr = std::make_shared<CbCustomizeTest4>();
    OHOS::sptr<StateChangeCallback> callback = new (std::nothrow) StateChangeCallback(callbackPtr);
    EXPECT_NE(nullptr, callback);
    callback->StateChangeNotify(tokenId, isShowing); // customizedCallback_ is null
}

/**
 * @tc.name: InitProxy001
 * @tc.desc: PrivacyManagerClient::InitProxy function test
 * @tc.type: FUNC
 * @tc.require: issueI61A6M
 */
HWTEST_F(PrivacyKitTest, InitProxy001, TestSize.Level0)
{
    EXPECT_NE(nullptr, PrivacyManagerClient::GetInstance().proxy_);
    OHOS::sptr<IPrivacyManager> proxy = PrivacyManagerClient::GetInstance().proxy_; // backup
    PrivacyManagerClient::GetInstance().proxy_ = nullptr;
    EXPECT_EQ(nullptr, PrivacyManagerClient::GetInstance().proxy_);
    PrivacyManagerClient::GetInstance().InitProxy(); // proxy_ is null
    PrivacyManagerClient::GetInstance().proxy_ = proxy; // recovery
}

/**
 * @tc.name: AddPermissionUsedRecord011
 * @tc.desc: Test AddPermissionUsedRecord with default normal used type
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(PrivacyKitTest, AddPermissionUsedRecord011, TestSize.Level0)
{
    AddPermParamInfo info;
    info.tokenId = g_tokenIdA;
    info.permissionName = "ohos.permission.READ_CONTACTS";
    info.successCount = 1;
    info.failCount = 0;
    EXPECT_EQ(RET_SUCCESS, PrivacyKit::AddPermissionUsedRecord(info)); // add normal used type

    std::vector<PermissionUsedTypeInfo> results;
    EXPECT_EQ(RET_SUCCESS, PrivacyKit::GetPermissionUsedTypeInfos(g_tokenIdA, "ohos.permission.READ_CONTACTS",
        results));
    EXPECT_EQ(static_cast<size_t>(RESULT_NUM_ONE), results.size());
    EXPECT_EQ(PermissionUsedType::NORMAL_TYPE, results[FIRST_INDEX].type); // only normal type
    results.clear();

    EXPECT_EQ(RET_SUCCESS, PrivacyKit::AddPermissionUsedRecord(info)); // repeat
    EXPECT_EQ(RET_SUCCESS, PrivacyKit::GetPermissionUsedTypeInfos(g_tokenIdA, "ohos.permission.READ_CONTACTS",
        results));
    EXPECT_EQ(static_cast<size_t>(RESULT_NUM_ONE), results.size());
    EXPECT_EQ(PermissionUsedType::NORMAL_TYPE, results[FIRST_INDEX].type); // results remain
}

/**
 * @tc.name: AddPermissionUsedRecord012
 * @tc.desc: Test AddPermissionUsedRecord with picker used type
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(PrivacyKitTest, AddPermissionUsedRecord012, TestSize.Level0)
{
    AddPermParamInfo info;
    info.tokenId = g_tokenIdA;
    info.permissionName = "ohos.permission.READ_CONTACTS";
    info.successCount = 1;
    info.failCount = 0;
    info.type = PermissionUsedType::PICKER_TYPE;
    EXPECT_EQ(RET_SUCCESS, PrivacyKit::AddPermissionUsedRecord(info)); // add picker used type

    std::vector<PermissionUsedTypeInfo> results;
    EXPECT_EQ(RET_SUCCESS, PrivacyKit::GetPermissionUsedTypeInfos(g_tokenIdA, "ohos.permission.READ_CONTACTS",
        results));
    EXPECT_EQ(static_cast<size_t>(RESULT_NUM_ONE), results.size());
    EXPECT_EQ(PermissionUsedType::PICKER_TYPE, results[FIRST_INDEX].type); // only picker type
    results.clear();

    EXPECT_EQ(RET_SUCCESS, PrivacyKit::AddPermissionUsedRecord(info)); // repeat
    EXPECT_EQ(RET_SUCCESS, PrivacyKit::GetPermissionUsedTypeInfos(g_tokenIdA, "ohos.permission.READ_CONTACTS",
        results));
    EXPECT_EQ(static_cast<size_t>(RESULT_NUM_ONE), results.size());
    EXPECT_EQ(PermissionUsedType::PICKER_TYPE, results[FIRST_INDEX].type); // results remain
}

/**
 * @tc.name: AddPermissionUsedRecord013
 * @tc.desc: Test AddPermissionUsedRecord with security component used type
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(PrivacyKitTest, AddPermissionUsedRecord013, TestSize.Level0)
{
    AddPermParamInfo info;
    info.tokenId = g_tokenIdA;
    info.permissionName = "ohos.permission.READ_CONTACTS";
    info.successCount = 1;
    info.failCount = 0;
    info.type = PermissionUsedType::SECURITY_COMPONENT_TYPE;
    EXPECT_EQ(RET_SUCCESS, PrivacyKit::AddPermissionUsedRecord(info)); // add security component used type

    std::vector<PermissionUsedTypeInfo> results;
    EXPECT_EQ(RET_SUCCESS, PrivacyKit::GetPermissionUsedTypeInfos(g_tokenIdA, "ohos.permission.READ_CONTACTS",
        results));
    EXPECT_EQ(static_cast<size_t>(RESULT_NUM_ONE), results.size());
    EXPECT_EQ(PermissionUsedType::SECURITY_COMPONENT_TYPE, results[FIRST_INDEX].type); // only security component type
    results.clear();

    EXPECT_EQ(RET_SUCCESS, PrivacyKit::AddPermissionUsedRecord(info)); // repeat
    EXPECT_EQ(RET_SUCCESS, PrivacyKit::GetPermissionUsedTypeInfos(g_tokenIdA, "ohos.permission.READ_CONTACTS",
        results));
    EXPECT_EQ(static_cast<size_t>(RESULT_NUM_ONE), results.size());
    EXPECT_EQ(PermissionUsedType::SECURITY_COMPONENT_TYPE, results[FIRST_INDEX].type); // results remain
}

/**
 * @tc.name: AddPermissionUsedRecord014
 * @tc.desc: Test AddPermissionUsedRecord with default normal and picker used type
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(PrivacyKitTest, AddPermissionUsedRecord014, TestSize.Level0)
{
    AddPermParamInfo info;
    info.tokenId = g_tokenIdA;
    info.permissionName = "ohos.permission.READ_CONTACTS";
    info.successCount = 1;
    info.failCount = 0;
    EXPECT_EQ(RET_SUCCESS, PrivacyKit::AddPermissionUsedRecord(info)); // add normal used type

    info.type = PermissionUsedType::PICKER_TYPE;
    EXPECT_EQ(RET_SUCCESS, PrivacyKit::AddPermissionUsedRecord(info)); // add picker used type

    std::vector<PermissionUsedTypeInfo> results;
    EXPECT_EQ(RET_SUCCESS, PrivacyKit::GetPermissionUsedTypeInfos(g_tokenIdA, "ohos.permission.READ_CONTACTS",
        results));
    EXPECT_EQ(static_cast<size_t>(RESULT_NUM_TWO), results.size());
    EXPECT_EQ(NORMAL_TYPE, results[FIRST_INDEX].type); // contain normal type
    EXPECT_EQ(PICKER_TYPE, results[SECOND_INDEX].type); // contain picker type
}

/**
 * @tc.name: AddPermissionUsedRecord015
 * @tc.desc: Test AddPermissionUsedRecord with default normal and security component used type
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(PrivacyKitTest, AddPermissionUsedRecord015, TestSize.Level0)
{
    AddPermParamInfo info;
    info.tokenId = g_tokenIdA;
    info.permissionName = "ohos.permission.READ_CONTACTS";
    info.successCount = 1;
    info.failCount = 0;
    EXPECT_EQ(RET_SUCCESS, PrivacyKit::AddPermissionUsedRecord(info)); // add normal used type

    info.type = PermissionUsedType::SECURITY_COMPONENT_TYPE;
    EXPECT_EQ(RET_SUCCESS, PrivacyKit::AddPermissionUsedRecord(info)); // add security component used type

    std::vector<PermissionUsedTypeInfo> results;
    EXPECT_EQ(RET_SUCCESS, PrivacyKit::GetPermissionUsedTypeInfos(g_tokenIdA, "ohos.permission.READ_CONTACTS",
        results));
    EXPECT_EQ(static_cast<size_t>(RESULT_NUM_TWO), results.size());
    EXPECT_EQ(NORMAL_TYPE, results[FIRST_INDEX].type); // contain normal type
    EXPECT_EQ(SECURITY_COMPONENT_TYPE, results[SECOND_INDEX].type); // contain security component type
}

/**
 * @tc.name: AddPermissionUsedRecord016
 * @tc.desc: Test AddPermissionUsedRecord with picker and security component used type
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(PrivacyKitTest, AddPermissionUsedRecord016, TestSize.Level0)
{
    AddPermParamInfo info;
    info.tokenId = g_tokenIdA;
    info.permissionName = "ohos.permission.READ_CONTACTS";
    info.successCount = 1;
    info.failCount = 0;
    info.type = PermissionUsedType::PICKER_TYPE;
    EXPECT_EQ(RET_SUCCESS, PrivacyKit::AddPermissionUsedRecord(info)); // add picker used type

    info.type = PermissionUsedType::SECURITY_COMPONENT_TYPE;
    EXPECT_EQ(RET_SUCCESS, PrivacyKit::AddPermissionUsedRecord(info)); // add security component used type

    std::vector<PermissionUsedTypeInfo> results;
    EXPECT_EQ(RET_SUCCESS, PrivacyKit::GetPermissionUsedTypeInfos(g_tokenIdA, "ohos.permission.READ_CONTACTS",
        results));
    EXPECT_EQ(static_cast<size_t>(RESULT_NUM_TWO), results.size());
    EXPECT_EQ(PICKER_TYPE, results[FIRST_INDEX].type); // contain picker type
    EXPECT_EQ(SECURITY_COMPONENT_TYPE, results[SECOND_INDEX].type); // contain security component type
}

/**
 * @tc.name: AddPermissionUsedRecord017
 * @tc.desc: Test AddPermissionUsedRecord with all used type
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(PrivacyKitTest, AddPermissionUsedRecord017, TestSize.Level0)
{
    AddPermParamInfo info;
    info.tokenId = g_tokenIdA;
    info.permissionName = "ohos.permission.READ_CONTACTS";
    info.successCount = 1;
    info.failCount = 0;
    EXPECT_EQ(RET_SUCCESS, PrivacyKit::AddPermissionUsedRecord(info)); // add normal used type

    info.type = PermissionUsedType::PICKER_TYPE;
    EXPECT_EQ(RET_SUCCESS, PrivacyKit::AddPermissionUsedRecord(info)); // add picker used type

    info.type = PermissionUsedType::SECURITY_COMPONENT_TYPE;
    EXPECT_EQ(RET_SUCCESS, PrivacyKit::AddPermissionUsedRecord(info)); // add security component used type

    std::vector<PermissionUsedTypeInfo> results;
    EXPECT_EQ(RET_SUCCESS, PrivacyKit::GetPermissionUsedTypeInfos(g_tokenIdA, "ohos.permission.READ_CONTACTS",
        results));
    EXPECT_EQ(static_cast<size_t>(RESULT_NUM_THREE), results.size());
    EXPECT_EQ(NORMAL_TYPE, results[FIRST_INDEX].type); // contain normal type
    EXPECT_EQ(PICKER_TYPE, results[SECOND_INDEX].type); // contain picker type
    EXPECT_EQ(SECURITY_COMPONENT_TYPE, results[THIRD_INDEX].type); // contain security component type
}

/**
 * @tc.name: AddPermissionUsedRecord018
 * @tc.desc: Test AddPermissionUsedRecord with invalid used type
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(PrivacyKitTest, AddPermissionUsedRecord018, TestSize.Level0)
{
    AddPermParamInfo info;
    info.tokenId = g_tokenIdA;
    info.permissionName = "ohos.permission.READ_CONTACTS";
    info.successCount = 1;
    info.failCount = 0;
    info.type = PermissionUsedType::INVALID_USED_TYPE;
    EXPECT_EQ(PrivacyError::ERR_PARAM_INVALID, PrivacyKit::AddPermissionUsedRecord(info)); // add invalid used type
}

/**
 * @tc.name: AddPermissionUsedRecord019
 * @tc.desc: Test AddPermissionUsedRecord with shell token
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(PrivacyKitTest, AddPermissionUsedRecord019, TestSize.Level0)
{
    AddPermParamInfo info;
    info.tokenId = g_nativeToken;
    info.permissionName = "ohos.permission.CAMERA";
    info.successCount = 1;
    info.failCount = 0;
    info.type = NORMAL_TYPE;
    EXPECT_EQ(PrivacyError::ERR_PARAM_INVALID, PrivacyKit::AddPermissionUsedRecord(info));

    info.permissionName = "ohos.permission.MICROPHONE";
    EXPECT_EQ(PrivacyError::ERR_PARAM_INVALID, PrivacyKit::AddPermissionUsedRecord(info));

    info.tokenId = g_shellToken;
    EXPECT_EQ(PrivacyError::ERR_PARAM_INVALID, PrivacyKit::AddPermissionUsedRecord(info));
}

/**
 * @tc.name: AddPermissionUsedRecord020
 * @tc.desc: Test AddPermissionUsedRecord failed twice in 200ms
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(PrivacyKitTest, AddPermissionUsedRecord020, TestSize.Level0)
{
    MockNativeToken mock("accesstoken_service"); // accesstoken_service without PERMISSION_USED_STATS
    AddPermParamInfo info;
    info.tokenId = g_nativeToken;
    info.permissionName = "ohos.permission.CAMERA";
    info.successCount = 1;
    info.failCount = 0;
    EXPECT_EQ(PrivacyError::ERR_PERMISSION_DENIED, PrivacyKit::AddPermissionUsedRecord(info));
    EXPECT_EQ(PrivacyError::ERR_PERMISSION_DENIED, PrivacyKit::AddPermissionUsedRecord(info));
}

/**
 * @tc.name: GetPermissionUsedTypeInfos001
 * @tc.desc: Test GetPermissionUsedTypeInfos with default input
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(PrivacyKitTest, GetPermissionUsedTypeInfos001, TestSize.Level0)
{
    AddPermParamInfo info;
    info.tokenId = g_tokenIdA;
    info.permissionName = "ohos.permission.READ_CONTACTS";
    info.successCount = 1;
    info.failCount = 0;
    // g_tokenIdA add normal used type
    EXPECT_EQ(RET_SUCCESS, PrivacyKit::AddPermissionUsedRecord(info));

    info.tokenId = g_tokenIdB;
    info.type = PermissionUsedType::PICKER_TYPE;
    // g_tokenIdB add picker used type
    EXPECT_EQ(RET_SUCCESS, PrivacyKit::AddPermissionUsedRecord(info));

    info.tokenId = g_tokenIdC;
    info.type = PermissionUsedType::SECURITY_COMPONENT_TYPE;
    // g_tokenIdC add security component used type
    EXPECT_EQ(RET_SUCCESS, PrivacyKit::AddPermissionUsedRecord(info));

    std::string permissionName;
    std::vector<PermissionUsedTypeInfo> results;
    EXPECT_EQ(RET_SUCCESS, PrivacyKit::GetPermissionUsedTypeInfos(0, permissionName, results));
    // results size may more than 3
    for (const PermissionUsedTypeInfo& result : results) {
        if (result.tokenId == g_tokenIdA) {
            EXPECT_EQ(PermissionUsedType::NORMAL_TYPE, result.type); // g_tokenIdA only normal type
        } else if (result.tokenId == g_tokenIdB) {
            EXPECT_EQ(PermissionUsedType::PICKER_TYPE, result.type); // g_tokenIdB only picker type
        } else if (result.tokenId == g_tokenIdC) {
            // g_tokenIdC only security component type
            EXPECT_EQ(PermissionUsedType::SECURITY_COMPONENT_TYPE, result.type);
        }
    }
}

/**
 * @tc.name: GetPermissionUsedTypeInfos002
 * @tc.desc: Test GetPermissionUsedTypeInfos with default tokenId
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(PrivacyKitTest, GetPermissionUsedTypeInfos002, TestSize.Level0)
{
    AddPermParamInfo info;
    info.tokenId = g_tokenIdA;
    info.permissionName = "ohos.permission.READ_CONTACTS";
    info.successCount = 1;
    info.failCount = 0;
    // READ_CONTACTS add normal used type
    EXPECT_EQ(RET_SUCCESS, PrivacyKit::AddPermissionUsedRecord(info));

    info.permissionName = "ohos.permission.LOCATION";
    info.type = PermissionUsedType::PICKER_TYPE;
    // LOCATION add picker used type
    EXPECT_EQ(RET_SUCCESS, PrivacyKit::AddPermissionUsedRecord(info));

    info.permissionName = "ohos.permission.MICROPHONE";
    info.type = PermissionUsedType::SECURITY_COMPONENT_TYPE;
    // MICROPHONE add security component used type
    EXPECT_EQ(RET_SUCCESS, PrivacyKit::AddPermissionUsedRecord(info));

    std::vector<PermissionUsedTypeInfo> results1;
    EXPECT_EQ(RET_SUCCESS, PrivacyKit::GetPermissionUsedTypeInfos(0, "ohos.permission.READ_CONTACTS", results1));
    // result1 size may more than one
    for (const auto& result : results1) {
        if (g_tokenIdA == result.tokenId) {
            EXPECT_EQ(PermissionUsedType::NORMAL_TYPE, result.type); // g_tokenIdA only normal type
        }
    }

    std::vector<PermissionUsedTypeInfo> results2;
    EXPECT_EQ(RET_SUCCESS, PrivacyKit::GetPermissionUsedTypeInfos(0, "ohos.permission.LOCATION", results2));
    // result2 size may more than one
    for (const auto& result : results2) {
        if (g_tokenIdA == result.tokenId) {
            EXPECT_EQ(PermissionUsedType::PICKER_TYPE, result.type); // g_tokenIdA only picker type
        }
    }

    std::vector<PermissionUsedTypeInfo> results3;
    EXPECT_EQ(RET_SUCCESS, PrivacyKit::GetPermissionUsedTypeInfos(0, "ohos.permission.MICROPHONE", results3));
    // result3 size may more than one
    for (const auto& result : results3) {
        if (g_tokenIdA == result.tokenId) {
            // g_tokenIdA only security component type
            EXPECT_EQ(PermissionUsedType::SECURITY_COMPONENT_TYPE, result.type);
        }
    }
}

/**
 * @tc.name: GetPermissionUsedTypeInfos003
 * @tc.desc: Test GetPermissionUsedTypeInfos with default permissionName
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(PrivacyKitTest, GetPermissionUsedTypeInfos003, TestSize.Level0)
{
    AddPermParamInfo info;
    info.tokenId = g_tokenIdA;
    info.permissionName = "ohos.permission.READ_CONTACTS";
    info.successCount = 1;
    info.failCount = 0;
    // g_tokenIdA add normal used type
    EXPECT_EQ(RET_SUCCESS, PrivacyKit::AddPermissionUsedRecord(info));

    info.tokenId = g_tokenIdB;
    info.type = PermissionUsedType::PICKER_TYPE;
    // g_tokenIdB add picker used type
    EXPECT_EQ(RET_SUCCESS, PrivacyKit::AddPermissionUsedRecord(info));

    info.tokenId = g_tokenIdC;
    info.type = PermissionUsedType::SECURITY_COMPONENT_TYPE;
    // g_tokenIdC add security component used type
    EXPECT_EQ(RET_SUCCESS, PrivacyKit::AddPermissionUsedRecord(info));

    std::string permissionName;
    std::vector<PermissionUsedTypeInfo> results1;
    EXPECT_EQ(RET_SUCCESS, PrivacyKit::GetPermissionUsedTypeInfos(g_tokenIdA, permissionName, results1));
    EXPECT_EQ(static_cast<size_t>(RESULT_NUM_ONE), results1.size()); // only g_tokenIdA
    EXPECT_EQ(g_tokenIdA, results1[FIRST_INDEX].tokenId);
    EXPECT_EQ(PermissionUsedType::NORMAL_TYPE, results1[FIRST_INDEX].type); // normal type

    std::vector<PermissionUsedTypeInfo> results2;
    EXPECT_EQ(RET_SUCCESS, PrivacyKit::GetPermissionUsedTypeInfos(g_tokenIdB, permissionName, results2));
    EXPECT_EQ(static_cast<size_t>(RESULT_NUM_ONE), results2.size()); // only g_tokenIdB
    EXPECT_EQ(g_tokenIdB, results2[FIRST_INDEX].tokenId);
    EXPECT_EQ(PermissionUsedType::PICKER_TYPE, results2[FIRST_INDEX].type); // picker type

    std::vector<PermissionUsedTypeInfo> results3;
    EXPECT_EQ(RET_SUCCESS, PrivacyKit::GetPermissionUsedTypeInfos(g_tokenIdC, permissionName, results3));
    EXPECT_EQ(static_cast<size_t>(RESULT_NUM_ONE), results3.size()); // only g_tokenIdC
    EXPECT_EQ(g_tokenIdC, results3[FIRST_INDEX].tokenId);
    EXPECT_EQ(PermissionUsedType::SECURITY_COMPONENT_TYPE, results3[FIRST_INDEX].type); // security component type
}

/**
 * @tc.name: GetPermissionUsedTypeInfos004
 * @tc.desc: Test GetPermissionUsedTypeInfos with invalid input param
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(PrivacyKitTest, GetPermissionUsedTypeInfos004, TestSize.Level0)
{
    std::vector<PermissionUsedTypeInfo> results;
    // tokenId invalid
    EXPECT_EQ(PrivacyError::ERR_TOKENID_NOT_EXIST, PrivacyKit::GetPermissionUsedTypeInfos(RANDOM_TOKENID,
        "ohos.permission.READ_CONTACTS", results));

    std::string permissionName;
    for (int32_t i = 0; i < INVALID_PERMISSIONAME_LENGTH; i++) { // 257
        permissionName.append("a");
    }

    // permissionName over length
    EXPECT_EQ(PrivacyError::ERR_PARAM_INVALID, PrivacyKit::GetPermissionUsedTypeInfos(0, permissionName, results));
    EXPECT_EQ(PrivacyError::ERR_PERMISSION_NOT_EXIST, PrivacyKit::GetPermissionUsedTypeInfos(0,
        "ohos.permission.TEST", results)); // permissionName invalid
}

/**
 * @tc.name: GetPermissionUsedTypeInfos005
 * @tc.desc: Test GetPermissionUsedTypeInfos as normal hap or system hap without PERMISSION_USED_STATE
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(PrivacyKitTest, GetPermissionUsedTypeInfos005, TestSize.Level0)
{
    std::vector<std::string> reqPerm;
    std::string permissionName;
    std::vector<PermissionUsedTypeInfo> results;

    {
        // as a normal hap without PERMISSION_USED_STATE
        MockHapToken mock("GetPermissionUsedTypeInfos005", reqPerm, false);
        EXPECT_EQ(PrivacyError::ERR_NOT_SYSTEM_APP, PrivacyKit::GetPermissionUsedTypeInfos(0, permissionName, results));
    }

    {
        // as a system hap without PERMISSION_USED_STATE
        MockHapToken mock("GetPermissionUsedTypeInfos005", reqPerm, true);
        EXPECT_EQ(PrivacyError::ERR_PERMISSION_DENIED, PrivacyKit::GetPermissionUsedTypeInfos(
            0, permissionName, results));
    }
}

/**
 * @tc.name: SetMutePolicyTest001
 * @tc.desc: Test SetMutePolicy with invalid param
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(PrivacyKitTest, SetMutePolicyTest001, TestSize.Level0)
{
    EXPECT_EQ(PrivacyError::ERR_PARAM_INVALID,
        PrivacyKit::SetMutePolicy(PolicyType::EDM - 1, CallerType::MICROPHONE, true, RANDOM_TOKENID));
    EXPECT_EQ(PrivacyError::ERR_PARAM_INVALID,
        PrivacyKit::SetMutePolicy(PolicyType::MIXED, CallerType::MICROPHONE, true, RANDOM_TOKENID));
    EXPECT_EQ(PrivacyError::ERR_PARAM_INVALID,
        PrivacyKit::SetMutePolicy(PolicyType::EDM, CallerType::MICROPHONE - 1, true, RANDOM_TOKENID));
    EXPECT_EQ(PrivacyError::ERR_PARAM_INVALID,
        PrivacyKit::SetMutePolicy(PolicyType::EDM, CallerType::CAMERA + 1, true, RANDOM_TOKENID));
    EXPECT_EQ(PrivacyError::ERR_PARAM_INVALID,
        PrivacyKit::SetMutePolicy(PolicyType::EDM, CallerType::CAMERA, true, 0));
}

/**
 * @tc.name: SetMutePolicyTest002
 * @tc.desc: Test SetMutePolicy without SET_MUTE_POLICY
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(PrivacyKitTest, SetMutePolicyTest002, TestSize.Level0)
{
    MockNativeToken mock("accesstoken_service"); // as a sa without SET_MUTE_POLICY
    EXPECT_EQ(PrivacyError::ERR_PERMISSION_DENIED,
        PrivacyKit::SetMutePolicy(PolicyType::EDM, CallerType::MICROPHONE, true, RANDOM_TOKENID));
}

/**
 * @tc.name: SetMutePolicyTest003
 * @tc.desc: Test SetMutePolicy with not edm
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(PrivacyKitTest, SetMutePolicyTest003, TestSize.Level0)
{
    MockNativeToken mock("audio_server"); // as a system service with SET_MUTE_POLICY

    EXPECT_EQ(PrivacyError::ERR_FIRST_CALLER_NOT_EDM,
        PrivacyKit::SetMutePolicy(PolicyType::EDM, CallerType::MICROPHONE, true, RANDOM_TOKENID));
}

/**
 * @tc.name: SetMutePolicyTest004
 * @tc.desc: Test SetMutePolicy with not permission
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(PrivacyKitTest, SetMutePolicyTest004, TestSize.Level0)
{
    std::vector<std::string> reqPerm;
    MockHapToken mock("SetMutePolicyTest004", reqPerm, true); // as a system hap
    EXPECT_EQ(PrivacyError::ERR_PERMISSION_DENIED,
        PrivacyKit::SetMutePolicy(PolicyType::EDM, CallerType::MICROPHONE, true, RANDOM_TOKENID));
}

/**
 * @tc.name: SetMutePolicyTest005
 * @tc.desc: hdcd without SET_MUTE_POLICY permission
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(PrivacyKitTest, SetMutePolicyTest005, TestSize.Level0)
{
    MockNativeToken mock("hdcd");
    EXPECT_EQ(PrivacyError::ERR_PERMISSION_DENIED,
        PrivacyKit::SetMutePolicy(PolicyType::EDM, CallerType::MICROPHONE, true, RANDOM_TOKENID));
}

/**
 * @tc.name: SetHapWithFGReminder01
 * @tc.desc: SetHapWithFGReminder with valid tokenId.
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(PrivacyKitTest, SetHapWithFGReminder01, TestSize.Level0)
{
    MockNativeToken mock("audio_server");

    std::string permissionName = "ohos.permission.MICROPHONE";
    EXPECT_EQ(false, PrivacyKit::IsAllowedUsingPermission(g_tokenIdE, permissionName));
    EXPECT_EQ(RET_SUCCESS, PrivacyKit::SetHapWithFGReminder(g_tokenIdE, true));
    EXPECT_EQ(true, PrivacyKit::IsAllowedUsingPermission(g_tokenIdE, permissionName));
    EXPECT_EQ(RET_SUCCESS, PrivacyKit::SetHapWithFGReminder(g_tokenIdE, false));
}

/**
 * @tc.name: SetHapWithFGReminder02
 * @tc.desc: SetHapWithFGReminder with valid tokenId.
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(PrivacyKitTest, SetHapWithFGReminder02, TestSize.Level0)
{
    MockNativeToken mock("audio_server");

    EXPECT_EQ(RET_SUCCESS, PrivacyKit::SetHapWithFGReminder(g_tokenIdE, true));
    EXPECT_EQ(PrivacyKit::SetHapWithFGReminder(g_tokenIdE, true), PrivacyError::ERR_PARAM_INVALID);
    EXPECT_EQ(PrivacyKit::SetHapWithFGReminder(g_tokenIdE, false), 0);
    EXPECT_EQ(PrivacyKit::SetHapWithFGReminder(g_tokenIdE, false), PrivacyError::ERR_PARAM_INVALID);
}

/**
 * @tc.name: SetHapWithFGReminder03
 * @tc.desc: SetHapWithFGReminder with native tokenId.
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(PrivacyKitTest, SetHapWithFGReminder03, TestSize.Level0)
{
    MockNativeToken mock("audio_server");

    uint32_t nativeTokenId = 672137215; // 672137215 is a native token
    EXPECT_EQ(PrivacyKit::SetHapWithFGReminder(nativeTokenId, true), PrivacyError::ERR_PARAM_INVALID);

    uint32_t invalidTokenId = 0;
    EXPECT_EQ(PrivacyKit::SetHapWithFGReminder(invalidTokenId, true), PrivacyError::ERR_PARAM_INVALID);
}

/**
 * @tc.name: SetPermissionUsedRecordToggleStatus001
 * @tc.desc: SetPermissionUsedRecordToggleStatus and GetPermissionUsedRecordToggleStatus with invalid userID.
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(PrivacyKitTest, SetPermissionUsedRecordToggleStatus001, TestSize.Level0)
{
    bool status = true;
    int32_t resSet = PrivacyKit::SetPermissionUsedRecordToggleStatus(INVALID_USER_ID, status);
    int32_t resGet = PrivacyKit::GetPermissionUsedRecordToggleStatus(INVALID_USER_ID, status);
    EXPECT_EQ(resSet, PrivacyError::ERR_PARAM_INVALID);
    EXPECT_EQ(resGet, PrivacyError::ERR_PARAM_INVALID);
}

/**
 * @tc.name: SetPermissionUsedRecordToggleStatus002
 * @tc.desc: SetPermissionUsedRecordToggleStatus with true status and false status.
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(PrivacyKitTest, SetPermissionUsedRecordToggleStatus002, TestSize.Level0)
{
    std::vector<std::string> reqPerm;
    reqPerm.emplace_back("ohos.permission.ERR_PERMISSION_DENIED");
    reqPerm.emplace_back("ohos.permission.PERMISSION_USED_STATS");
    MockHapToken mock("SetPermissionUsedRecordToggleStatus002", reqPerm, true);

    int32_t permRecordSize = 0;
    bool status = true;

    EXPECT_EQ(RET_SUCCESS, PrivacyKit::SetPermissionUsedRecordToggleStatus(USER_ID_2, true));
    EXPECT_EQ(RET_SUCCESS, PrivacyKit::GetPermissionUsedRecordToggleStatus(USER_ID_2, status));
    EXPECT_TRUE(status);

    AddPermParamInfo info;
    info.tokenId = g_tokenIdG;
    info.permissionName = "ohos.permission.READ_CONTACTS";
    info.successCount = 1;
    info.failCount = 0;
    EXPECT_EQ(RET_NO_ERROR, PrivacyKit::AddPermissionUsedRecord(info));
    permRecordSize++;

    info.permissionName = "ohos.permission.WRITE_CONTACTS";
    EXPECT_EQ(RET_NO_ERROR, PrivacyKit::AddPermissionUsedRecord(info));
    permRecordSize++;

    PermissionUsedRequest request;
    PermissionUsedResult result;
    std::vector<std::string> permissionList;
    BuildQueryRequest(g_tokenIdG, g_infoParmsG.bundleName, permissionList, request);

    request.flag = FLAG_PERMISSION_USAGE_DETAIL;
    EXPECT_EQ(RET_NO_ERROR, PrivacyKit::GetPermissionUsedRecords(request, result));
    EXPECT_EQ(1, static_cast<int32_t>(result.bundleRecords.size()));
    EXPECT_EQ(permRecordSize, static_cast<int32_t>(result.bundleRecords[0].permissionRecords.size()));

    EXPECT_EQ(RET_NO_ERROR, PrivacyKit::SetPermissionUsedRecordToggleStatus(USER_ID_2, false));
    EXPECT_EQ(RET_NO_ERROR, PrivacyKit::GetPermissionUsedRecords(request, result));
    EXPECT_EQ(0, static_cast<int32_t>(result.bundleRecords.size()));

    EXPECT_EQ(RET_NO_ERROR, PrivacyKit::AddPermissionUsedRecord(info));
    info.permissionName = "ohos.permission.READ_CONTACTS";
    EXPECT_EQ(RET_NO_ERROR, PrivacyKit::AddPermissionUsedRecord(info));

    EXPECT_EQ(RET_NO_ERROR, PrivacyKit::GetPermissionUsedRecords(request, result));
    EXPECT_EQ(0, static_cast<int32_t>(result.bundleRecords.size()));

    EXPECT_EQ(RET_NO_ERROR, PrivacyKit::SetPermissionUsedRecordToggleStatus(USER_ID_2, true));
    EXPECT_EQ(RET_NO_ERROR, PrivacyKit::RemovePermissionUsedRecords(info.tokenId));
}

/**
 * @tc.name: SetPermissionUsedRecordToggleStatus003
 * @tc.desc: SetPermissionUsedRecordToggleStatus with false status and true status.
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(PrivacyKitTest, SetPermissionUsedRecordToggleStatus003, TestSize.Level0)
{
    std::vector<std::string> reqPerm;
    reqPerm.emplace_back("ohos.permission.ERR_PERMISSION_DENIED");
    reqPerm.emplace_back("ohos.permission.PERMISSION_USED_STATS");
    MockHapToken mock("SetPermissionUsedRecordToggleStatus003", reqPerm, true);

    int32_t permRecordSize = 0;
    bool status = true;

    EXPECT_EQ(RET_NO_ERROR, PrivacyKit::SetPermissionUsedRecordToggleStatus(USER_ID_2, false));
    EXPECT_EQ(RET_NO_ERROR, PrivacyKit::GetPermissionUsedRecordToggleStatus(USER_ID_2, status));
    EXPECT_FALSE(status);

    AddPermParamInfo info;
    info.tokenId = g_tokenIdG;
    info.permissionName = "ohos.permission.READ_CONTACTS";
    info.successCount = 1;
    info.failCount = 0;
    EXPECT_EQ(RET_NO_ERROR, PrivacyKit::AddPermissionUsedRecord(info));

    info.permissionName = "ohos.permission.WRITE_CONTACTS";
    EXPECT_EQ(RET_NO_ERROR, PrivacyKit::AddPermissionUsedRecord(info));

    PermissionUsedRequest request;
    PermissionUsedResult result;
    std::vector<std::string> permissionList;
    BuildQueryRequest(g_tokenIdG, g_infoParmsG.bundleName, permissionList, request);
    request.flag = FLAG_PERMISSION_USAGE_DETAIL;

    EXPECT_EQ(RET_NO_ERROR, PrivacyKit::GetPermissionUsedRecords(request, result));
    EXPECT_TRUE(result.bundleRecords.empty());

    EXPECT_EQ(RET_NO_ERROR, PrivacyKit::SetPermissionUsedRecordToggleStatus(USER_ID_2, true));
    EXPECT_EQ(RET_NO_ERROR, PrivacyKit::GetPermissionUsedRecordToggleStatus(USER_ID_2, status));
    EXPECT_TRUE(status);

    EXPECT_EQ(RET_NO_ERROR, PrivacyKit::AddPermissionUsedRecord(info));
    permRecordSize++;

    info.permissionName = "ohos.permission.READ_CONTACTS";
    EXPECT_EQ(RET_NO_ERROR, PrivacyKit::AddPermissionUsedRecord(info));
    permRecordSize++;

    EXPECT_EQ(RET_NO_ERROR, PrivacyKit::GetPermissionUsedRecords(request, result));
    EXPECT_EQ(1, static_cast<int32_t>(result.bundleRecords.size()));
    EXPECT_EQ(permRecordSize, static_cast<int32_t>(result.bundleRecords[0].permissionRecords.size()));

    EXPECT_EQ(RET_NO_ERROR, PrivacyKit::RemovePermissionUsedRecords(info.tokenId));
}

/**
 * @tc.name: SetPermissionUsedRecordToggleStatus004
 * @tc.desc: SetPermissionUsedRecordToggleStatus with not system app.
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(PrivacyKitTest, SetPermissionUsedRecordToggleStatus004, TestSize.Level0)
{
    std::vector<std::string> reqPerm;
    reqPerm.emplace_back("ohos.permission.PERMISSION_USED_STATS");
    MockHapToken mock("SetPermissionUsedRecordToggleStatus004", reqPerm, false);

    bool status = true;
    EXPECT_EQ(PrivacyError::ERR_NOT_SYSTEM_APP, PrivacyKit::SetPermissionUsedRecordToggleStatus(USER_ID_2, true));
    EXPECT_EQ(PrivacyError::ERR_NOT_SYSTEM_APP, PrivacyKit::GetPermissionUsedRecordToggleStatus(USER_ID_2, status));
}

int32_t PrivacyKitTest::SetDisablePolicy(const std::string& permissionName, bool isDisable)
{
    MockNativeToken mock("edm");

    return PrivacyKit::SetDisablePolicy(permissionName, isDisable);
}

/**
 * @tc.name: SetDisablePolicy001
 * @tc.desc: PrivacyKit::SetDisablePolicy test invalid perm and no MANAGE_EDM_POLICY permission.
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(PrivacyKitTest, SetDisablePolicy001, TestSize.Level0)
{
    bool isDisable = false;
    EXPECT_EQ(PrivacyError::ERR_PARAM_INVALID, PrivacyKit::SetDisablePolicy("", isDisable)); // perm empty

    std::string permissionName (257, 'x');
    EXPECT_EQ(PrivacyError::ERR_PARAM_INVALID, PrivacyKit::SetDisablePolicy(permissionName, isDisable)); // perm 257
    
    // perm deny
    EXPECT_EQ(PrivacyError::ERR_PERMISSION_DENIED, PrivacyKit::SetDisablePolicy("ohos.permission.INVALID", isDisable));

    // perm not exsit
    EXPECT_EQ(PrivacyError::ERR_PERMISSION_NOT_EXIST, SetDisablePolicy("ohos.permission.INVALID", isDisable));

    // perm not support
    EXPECT_EQ(PrivacyError::ERR_PERMISSION_NOT_SUPPORT, SetDisablePolicy("ohos.permission.LOCATION", isDisable));
}

/**
 * @tc.name: SetDisablePolicy002
 * @tc.desc: PrivacyKit::SetDisablePolicy test get correct disable policy after set.
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(PrivacyKitTest, SetDisablePolicy002, TestSize.Level0)
{
    MockNativeToken mock("accesstoken_service");

    // backup origin disable policy
    bool camDisable = false;
    bool micDisable = false;
    EXPECT_EQ(0, PrivacyKit::GetDisablePolicy("ohos.permission.CAMERA", camDisable));
    EXPECT_EQ(0, PrivacyKit::GetDisablePolicy("ohos.permission.MICROPHONE", micDisable));

    // set cam + micro disable
    EXPECT_EQ(0, SetDisablePolicy("ohos.permission.CAMERA", true));
    EXPECT_EQ(0, SetDisablePolicy("ohos.permission.MICROPHONE", true));

    // get cam + micro policy to compare
    bool isCamDisable = false;
    bool isMicDisable = false;
    EXPECT_EQ(0, PrivacyKit::GetDisablePolicy("ohos.permission.CAMERA", isCamDisable));
    EXPECT_EQ(0, PrivacyKit::GetDisablePolicy("ohos.permission.MICROPHONE", isMicDisable));
    EXPECT_EQ(true, isCamDisable);
    EXPECT_EQ(true, isMicDisable);

    // set cam + micro enable
    EXPECT_EQ(0, SetDisablePolicy("ohos.permission.CAMERA", false));
    EXPECT_EQ(0, SetDisablePolicy("ohos.permission.MICROPHONE", false));

    // get cam + micro policy to compare
    isCamDisable = true;
    isMicDisable = true;
    EXPECT_EQ(0, PrivacyKit::GetDisablePolicy("ohos.permission.CAMERA", isCamDisable));
    EXPECT_EQ(0, PrivacyKit::GetDisablePolicy("ohos.permission.MICROPHONE", isMicDisable));
    EXPECT_EQ(false, isCamDisable);
    EXPECT_EQ(false, isMicDisable);

    // recovery origin disable policy
    EXPECT_EQ(0, SetDisablePolicy("ohos.permission.CAMERA", camDisable));
    EXPECT_EQ(0, SetDisablePolicy("ohos.permission.MICROPHONE", micDisable));
}

/**
 * @tc.name: GetDisablePolicy001
 * @tc.desc: PrivacyKit::GetDisablePolicy test invalid perm and no GET_PERMISSION_POLICY permission.
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(PrivacyKitTest, GetDisablePolicy001, TestSize.Level0)
{
    bool isDisable = false;
    EXPECT_EQ(PrivacyError::ERR_PARAM_INVALID, PrivacyKit::GetDisablePolicy("", isDisable)); // perm empty

    std::string permissionName (257, 'x');
    EXPECT_EQ(PrivacyError::ERR_PARAM_INVALID, PrivacyKit::GetDisablePolicy(permissionName, isDisable)); // perm 257

    // perm deny
    EXPECT_EQ(PrivacyError::ERR_PERMISSION_DENIED, PrivacyKit::GetDisablePolicy("ohos.permission.INVALID", isDisable));

    MockNativeToken mock("accesstoken_service");
    EXPECT_EQ(PrivacyError::ERR_PERMISSION_NOT_EXIST, PrivacyKit::GetDisablePolicy("ohos.permission.INVALID",
        isDisable)); // perm not exsit

    EXPECT_EQ(PrivacyError::ERR_PERMISSION_NOT_SUPPORT, PrivacyKit::GetDisablePolicy("ohos.permission.LOCATION",
        isDisable)); // perm not support
}

class DisablePolicyChangeCallbackTest : public DisablePolicyChangeCallback {
public:
    explicit DisablePolicyChangeCallbackTest(const std::vector<std::string> &permList)
        : DisablePolicyChangeCallback(permList)
    {
        GTEST_LOG_(INFO) << "DisablePolicyChangeCallbackTest create";
    }

    ~DisablePolicyChangeCallbackTest()
    {}

    virtual void PermDisablePolicyCallback(const PermDisablePolicyInfo& info)
    {
        permissionName_ = info.permissionName;
        isDisable_ = info.isDisable;

        GTEST_LOG_(INFO) << "Receive callback: " << permissionName_ << " set to " << (isDisable_? "true" : "false");
    }

    std::string permissionName_ = "ohos.permission.INVALID";
    bool isDisable_ = true;
};

/**
 * @tc.name: RegisterPermDisablePolicyCallback001
 * @tc.desc: PrivacyKit::RegisterPermDisablePolicyCallback test perm oversize and no GET_PERMISSION_POLICY permission.
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(PrivacyKitTest, RegisterPermDisablePolicyCallback001, TestSize.Level0)
{
    std::shared_ptr<DisablePolicyChangeCallbackTest> callback1 = nullptr;
    OHOS::sptr<PermDisablePolicyChangeCallback> callbackWrap = nullptr;

    // callback nullptr
    EXPECT_EQ(PrivacyError::ERR_PARAM_INVALID, PrivacyKit::RegisterPermDisablePolicyCallback(callback1));
    EXPECT_EQ(PrivacyError::ERR_PARAM_INVALID,
        PrivacyManagerClient::GetInstance().RegisterPermDisablePolicyCallback(callback1));
    EXPECT_EQ(PrivacyError::ERR_PARAM_INVALID,
        PrivacyManagerClient::GetInstance().CreatePermDisablePolicyCbk(callback1, callbackWrap));

    std::vector<std::string> permList1;
    for (int32_t i = 0; i <= MAX_PERM_LIST_TEST_SIZE; ++i) {
        permList1.emplace_back("ohos.permission.CAMERA");
    }
    callback1 = std::make_shared<DisablePolicyChangeCallbackTest>(permList1);
    EXPECT_EQ(PrivacyError::ERR_OVERSIZE, PrivacyKit::RegisterPermDisablePolicyCallback(callback1)); // perm oversize

    std::vector<std::string> permList2 = { "ohos.permission.CAMERA" };
    auto callback2 = std::make_shared<DisablePolicyChangeCallbackTest>(permList2);
    // perm deny
    EXPECT_EQ(PrivacyError::ERR_PERMISSION_DENIED, PrivacyKit::RegisterPermDisablePolicyCallback(callback2));
}

/**
 * @tc.name: RegisterPermDisablePolicyCallback002
 * @tc.desc: PrivacyKit::RegisterPermDisablePolicyCallback test permList has invalid perm.
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(PrivacyKitTest, RegisterPermDisablePolicyCallback002, TestSize.Level0)
{
    MockNativeToken mock("accesstoken_service");

    std::vector<std::string> permList1;
    permList1.emplace_back("ohos.permission.INVALIDA");
    permList1.emplace_back("ohos.permission.INVALIDB");

    auto callback1 = std::make_shared<DisablePolicyChangeCallbackTest>(permList1);
    // permList with only invalid perm
    EXPECT_EQ(PrivacyError::ERR_PARAM_INVALID, PrivacyKit::RegisterPermDisablePolicyCallback(callback1));

    permList1.emplace_back("ohos.permission.CAMERA");
    auto callback2 = std::make_shared<DisablePolicyChangeCallbackTest>(permList1);
    // permList with invalid perm and valid perm
    EXPECT_EQ(PrivacyError::ERR_PARAM_INVALID, PrivacyKit::RegisterPermDisablePolicyCallback(callback2));

    std::vector<std::string> permList2;
    permList2.emplace_back("ohos.permission.LOCATION");
    auto callback3 = std::make_shared<DisablePolicyChangeCallbackTest>(permList2);
    // perm not support
    EXPECT_EQ(PrivacyError::ERR_PERMISSION_NOT_SUPPORT, PrivacyKit::RegisterPermDisablePolicyCallback(callback3));
}

/**
 * @tc.name: RegisterPermDisablePolicyCallback003
 * @tc.desc: PrivacyKit::RegisterPermDisablePolicyCallback test client callback oversize and callback register twice.
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(PrivacyKitTest, RegisterPermDisablePolicyCallback003, TestSize.Level0)
{
    MockNativeToken mock("accesstoken_service");

    std::vector<std::string> permList = {"ohos.permission.CAMERA"};
    std::vector<std::shared_ptr<DisablePolicyChangeCallbackTest>> callbackList;

    for (int32_t i = 0; i <= MAX_DISABLE_CALLBACK_TEST_SIZE; ++i) {
        auto callbackPtr = std::make_shared<DisablePolicyChangeCallbackTest>(permList);

        if (i == MAX_DISABLE_CALLBACK_TEST_SIZE) { // 20 is the max size
            EXPECT_EQ(PrivacyError::ERR_CALLBACKS_EXCEED_LIMITATION,
                PrivacyKit::RegisterPermDisablePolicyCallback(callbackPtr)); // over 20 limit
            break;
        }

        EXPECT_EQ(0, PrivacyKit::RegisterPermDisablePolicyCallback(callbackPtr));
        callbackList.emplace_back(callbackPtr);
    }

    for (int32_t i = 0; i < MAX_DISABLE_CALLBACK_TEST_SIZE; ++i) { // release 20 callback
        auto callbackPtr = callbackList[i];
        EXPECT_EQ(0, PrivacyKit::UnRegisterPermDisablePolicyCallback(callbackPtr));
    }

    auto callback = std::make_shared<DisablePolicyChangeCallbackTest>(permList);
    EXPECT_EQ(0, PrivacyKit::RegisterPermDisablePolicyCallback(callback));
    // callback repeat register
    EXPECT_EQ(PrivacyError::ERR_CALLBACK_ALREADY_EXIST, PrivacyKit::RegisterPermDisablePolicyCallback(callback));

    EXPECT_EQ(0, PrivacyKit::UnRegisterPermDisablePolicyCallback(callback));
}

/**
 * @tc.name: RegisterPermDisablePolicyCallback004
 * @tc.desc: PrivacyKit::RegisterPermDisablePolicyCallback permList empty receive cam and micro callback.
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(PrivacyKitTest, RegisterPermDisablePolicyCallback004, TestSize.Level0)
{
    MockNativeToken mock("accesstoken_service");

    // backup origin disable policy
    bool camDisable = false;
    bool micDisable = false;
    EXPECT_EQ(0, PrivacyKit::GetDisablePolicy("ohos.permission.CAMERA", camDisable));
    EXPECT_EQ(0, PrivacyKit::GetDisablePolicy("ohos.permission.MICROPHONE", micDisable));

    std::vector<std::string> permList;
    auto callback = std::make_shared<DisablePolicyChangeCallbackTest>(permList);

    EXPECT_EQ(0, SetDisablePolicy("ohos.permission.CAMERA", false)); // set camera enable
    EXPECT_EQ(0, SetDisablePolicy("ohos.permission.MICROPHONE", false)); // set micro enable
    EXPECT_EQ("ohos.permission.INVALID", callback->permissionName_); // can't receive callback without register
    EXPECT_EQ(true, callback->isDisable_);

    EXPECT_EQ(0, PrivacyKit::RegisterPermDisablePolicyCallback(callback));
    EXPECT_EQ(0, SetDisablePolicy("ohos.permission.CAMERA", false)); // set camera enable
    EXPECT_EQ(0, SetDisablePolicy("ohos.permission.MICROPHONE", false)); // set micro enable
    EXPECT_EQ("ohos.permission.INVALID", callback->permissionName_); // not send callback when set the same policy
    EXPECT_EQ(true, callback->isDisable_);

    EXPECT_EQ(0, SetDisablePolicy("ohos.permission.CAMERA", true)); // set camera disable
    usleep(1000000); // 1000000us = 1s
    EXPECT_EQ("ohos.permission.CAMERA", callback->permissionName_); // receive camera disable callback
    EXPECT_EQ(true, callback->isDisable_);

    EXPECT_EQ(0, SetDisablePolicy("ohos.permission.MICROPHONE", true)); // set micro disable
    usleep(1000000); // 1000000us = 1s
    EXPECT_EQ("ohos.permission.MICROPHONE", callback->permissionName_);
    EXPECT_EQ(true, callback->isDisable_);

    // unregister callback
    EXPECT_EQ(0, PrivacyKit::UnRegisterPermDisablePolicyCallback(callback));

    // recovery origin disable policy
    EXPECT_EQ(0, SetDisablePolicy("ohos.permission.CAMERA", camDisable));
    EXPECT_EQ(0, SetDisablePolicy("ohos.permission.MICROPHONE", micDisable));
}

/**
 * @tc.name: RegisterPermDisablePolicyCallback005
 * @tc.desc: PrivacyKit::RegisterPermDisablePolicyCallback register or unregister cam can or can't receive cam callback
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(PrivacyKitTest, RegisterPermDisablePolicyCallback005, TestSize.Level0)
{
    MockNativeToken mock("accesstoken_service");

    // backup origin disable policy
    bool camDisable = false;
    EXPECT_EQ(0, PrivacyKit::GetDisablePolicy("ohos.permission.CAMERA", camDisable));

    EXPECT_EQ(0, SetDisablePolicy("ohos.permission.CAMERA", true)); // set camera disable
    
    std::vector<std::string> permList = { "ohos.permission.CAMERA" };
    auto callback = std::make_shared<DisablePolicyChangeCallbackTest>(permList);
    EXPECT_EQ(0, PrivacyKit::RegisterPermDisablePolicyCallback(callback));

    EXPECT_EQ(0, SetDisablePolicy("ohos.permission.CAMERA", false)); // set camera enable
    usleep(1000000); // 1000000us = 1s
    EXPECT_EQ("ohos.permission.CAMERA", callback->permissionName_);
    EXPECT_EQ(false, callback->isDisable_);

    // unregister callback
    EXPECT_EQ(0, PrivacyKit::UnRegisterPermDisablePolicyCallback(callback));

    EXPECT_EQ(0, SetDisablePolicy("ohos.permission.CAMERA", true)); // set camera disable
    EXPECT_EQ("ohos.permission.CAMERA", callback->permissionName_);
    EXPECT_EQ(false, callback->isDisable_);

    // recovery origin disable policy
    EXPECT_EQ(0, SetDisablePolicy("ohos.permission.CAMERA", camDisable));
}

/**
 * @tc.name: RegisterPermDisablePolicyCallback006
 * @tc.desc: PrivacyKit::RegisterPermDisablePolicyCallback register cam can't receive micro callback
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(PrivacyKitTest, RegisterPermDisablePolicyCallback006, TestSize.Level0)
{
    MockNativeToken mock("accesstoken_service");

    // backup origin disable policy
    bool micDisable = false;
    EXPECT_EQ(0, PrivacyKit::GetDisablePolicy("ohos.permission.MICROPHONE", micDisable));

    EXPECT_EQ(0, SetDisablePolicy("ohos.permission.MICROPHONE", true)); // set micro disable
    
    std::vector<std::string> permList = { "ohos.permission.CAMERA" };
    auto callback = std::make_shared<DisablePolicyChangeCallbackTest>(permList);
    EXPECT_EQ(0, PrivacyKit::RegisterPermDisablePolicyCallback(callback));

    EXPECT_EQ(0, SetDisablePolicy("ohos.permission.MICROPHONE", false)); // set micro enable
    EXPECT_EQ("ohos.permission.INVALID", callback->permissionName_); // can't receive micro callback
    EXPECT_EQ(true, callback->isDisable_);

    // unregister callback
    EXPECT_EQ(0, PrivacyKit::UnRegisterPermDisablePolicyCallback(callback));

    // recovery origin disable policy
    EXPECT_EQ(0, SetDisablePolicy("ohos.permission.MICROPHONE", micDisable));
}

/**
 * @tc.name: RegisterPermDisablePolicyCallback007
 * @tc.desc: PrivacyKit::RegisterPermDisablePolicyCallback multy register only receive own callback
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(PrivacyKitTest, RegisterPermDisablePolicyCallback007, TestSize.Level0)
{
    MockNativeToken mock("accesstoken_service");

    // backup origin disable policy
    bool camDisable = false;
    bool micDisable = false;
    EXPECT_EQ(0, PrivacyKit::GetDisablePolicy("ohos.permission.CAMERA", camDisable));
    EXPECT_EQ(0, PrivacyKit::GetDisablePolicy("ohos.permission.MICROPHONE", micDisable));

    EXPECT_EQ(0, SetDisablePolicy("ohos.permission.CAMERA", true)); // set camera disable
    EXPECT_EQ(0, SetDisablePolicy("ohos.permission.MICROPHONE", true)); // set micro disable
    
    std::vector<std::string> permList1 = { "ohos.permission.CAMERA" };
    auto callback1 = std::make_shared<DisablePolicyChangeCallbackTest>(permList1);
    EXPECT_EQ(0, PrivacyKit::RegisterPermDisablePolicyCallback(callback1));

    std::vector<std::string> permList2 = { "ohos.permission.MICROPHONE" };
    auto callback2 = std::make_shared<DisablePolicyChangeCallbackTest>(permList2);
    EXPECT_EQ(0, PrivacyKit::RegisterPermDisablePolicyCallback(callback2));

    EXPECT_EQ(0, SetDisablePolicy("ohos.permission.CAMERA", false)); // set camera enable
    usleep(1000000); // 1000000us = 1s
    EXPECT_EQ("ohos.permission.CAMERA", callback1->permissionName_); // callback1 receive camera callback
    EXPECT_EQ(false, callback1->isDisable_);
    EXPECT_EQ("ohos.permission.INVALID", callback2->permissionName_); // callback2 can't receive camera callback
    EXPECT_EQ(true, callback2->isDisable_);

    callback1->permissionName_ = "ohos.permission.INVALID";
    callback1->isDisable_ = true;
    EXPECT_EQ(0, SetDisablePolicy("ohos.permission.MICROPHONE", false)); // set micro enable
    usleep(1000000); // 1000000us = 1s
    EXPECT_EQ("ohos.permission.INVALID", callback1->permissionName_); // callback1 can't receive micro callback
    EXPECT_EQ(true, callback1->isDisable_);
    EXPECT_EQ("ohos.permission.MICROPHONE", callback2->permissionName_); // callback2 receive micro callback
    EXPECT_EQ(false, callback2->isDisable_);

    // unregister callback
    EXPECT_EQ(0, PrivacyKit::UnRegisterPermDisablePolicyCallback(callback1));
    EXPECT_EQ(0, PrivacyKit::UnRegisterPermDisablePolicyCallback(callback2));

    // recovery origin disable policy
    EXPECT_EQ(0, SetDisablePolicy("ohos.permission.CAMERA", camDisable));
    ASSERT_EQ(0, SetDisablePolicy("ohos.permission.MICROPHONE", micDisable));
}

/**
 * @tc.name: UnRegisterPermDisablePolicyCallback001
 * @tc.desc: PrivacyKit::UnRegisterPermDisablePolicyCallback test perm oversize and no GET_PERMISSION_POLICY permission.
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(PrivacyKitTest, UnRegisterPermDisablePolicyCallback001, TestSize.Level0)
{
    auto disableCbkMap = PrivacyManagerClient::GetInstance().disableCbkMap_;

    std::shared_ptr<DisablePolicyChangeCallbackTest> callback = nullptr;

    auto permCallback = std::make_shared<PermDisablePolicyChangeCallback>(callback);
    PermDisablePolicyInfo info;
    permCallback->PermDisablePolicyCallback(info); // customizedCallback_ nullptr

    // callback nullptr
    EXPECT_EQ(PrivacyError::ERR_PARAM_INVALID, PrivacyKit::UnRegisterPermDisablePolicyCallback(callback));
    EXPECT_EQ(PrivacyError::ERR_PARAM_INVALID,
        PrivacyManagerClient::GetInstance().UnRegisterPermDisablePolicyCallback(callback));

    std::vector<std::string> permList = { "ohos.permission.CAMERA" };
    callback = std::make_shared<DisablePolicyChangeCallbackTest>(permList);
    EXPECT_EQ(PrivacyError::ERR_CALLBACK_NOT_EXIST, PrivacyKit::UnRegisterPermDisablePolicyCallback(callback));

    OHOS::sptr<PermDisablePolicyChangeCallback> callbackWrap = nullptr;
    PrivacyManagerClient::GetInstance().disableCbkMap_[callback] = callbackWrap;
    EXPECT_EQ(PrivacyError::ERR_CALLBACK_NOT_EXIST, PrivacyKit::UnRegisterPermDisablePolicyCallback(callback));

    callbackWrap = new (std::nothrow) PermDisablePolicyChangeCallback(callback);
    EXPECT_NE(nullptr, callbackWrap);
    PrivacyManagerClient::GetInstance().disableCbkMap_[callback] = callbackWrap;
    // perm deny
    EXPECT_EQ(PrivacyError::ERR_PERMISSION_DENIED, PrivacyKit::UnRegisterPermDisablePolicyCallback(callback));

    PrivacyManagerClient::GetInstance().disableCbkMap_ = disableCbkMap;
}

/**
 * @tc.name: StartUsingPermission017
 * @tc.desc:
 * @tc.type: FUNC
 * @tc.require: issue2901
 */
HWTEST_F(PrivacyKitTest, StartUsingPermission017, TestSize.Level0)
{
    auto callbackPtr = std::make_shared<CbCustomizeTest4>();
    EXPECT_EQ(0, PrivacyKit::StartUsingPermission(g_tokenIdE, "ohos.permission.CAMERA", callbackPtr, RANDOM_PID));
    EXPECT_EQ(0, PrivacyKit::StopUsingPermission(g_tokenIdE, "ohos.permission.CAMERA", RANDOM_PID));

    MockNativeToken mock("audio_server");
    std::vector<CurrUsingPermInfo> infoList;
    EXPECT_EQ(0, PrivacyKit::GetCurrUsingPermInfo(infoList));
    GTEST_LOG_(INFO) << "infoList.size() " << infoList.size() << " expect 0 without Influenced by the environment.";
    size_t i = 0;
    bool found = false;
    while (i < infoList.size()) {
        if ((infoList[i].tokenID == g_tokenIdE) && (infoList[i].permissionName == "ohos.permission.CAMERA") &&
            (infoList[i].pid == RANDOM_PID)) {
            found = true;
            break;
        }
        i++;
    }
    EXPECT_EQ(false, found);
}

/**
 * @tc.name: StartUsingPermission018
 * @tc.desc:
 * @tc.type: FUNC
 * @tc.require: issue2901
 */
HWTEST_F(PrivacyKitTest, StartUsingPermission018, TestSize.Level0)
{
    AccessTokenIDEx idEx = {0};
    idEx.tokenIDEx = GetSelfTokenID();
    auto callbackPtr = std::make_shared<CbCustomizeTest4>();
    EXPECT_EQ(0, PrivacyKit::StartUsingPermission(g_tokenIdE, "ohos.permission.CAMERA", callbackPtr, RANDOM_PID));

    MockNativeToken mock("audio_server");
    std::vector<CurrUsingPermInfo> infoList;
    EXPECT_EQ(0, PrivacyKit::GetCurrUsingPermInfo(infoList));

    GTEST_LOG_(INFO) << "infoList.size() " << infoList.size() << " expect 1 without Influenced by the environment.";
    size_t i = 0;
    bool found = false;
    while (i < infoList.size()) {
        if ((infoList[i].tokenID == g_tokenIdE) && (infoList[i].permissionName == "ohos.permission.CAMERA") &&
            (infoList[i].pid == RANDOM_PID)) {
            found = true;
            break;
        }
        i++;
    }
    EXPECT_EQ(true, found);
    if (found == true) {
        EXPECT_EQ(infoList[i].callingTokenID, idEx.tokenIdExStruct.tokenID);
        EXPECT_EQ(infoList[i].tokenID, g_tokenIdE);
        EXPECT_EQ(infoList[i].permissionName, "ohos.permission.CAMERA");
        EXPECT_EQ(infoList[i].pid, RANDOM_PID);
        EXPECT_EQ(infoList[i].deviceId, "");
        EXPECT_EQ(infoList[i].usedType, NORMAL_TYPE);
    }

    SetSelfTokenID(idEx.tokenIDEx);
    EXPECT_EQ(0, PrivacyKit::StopUsingPermission(g_tokenIdE, "ohos.permission.CAMERA", RANDOM_PID));
}

static void CheckInfo()
{
    AccessTokenIDEx idEx = {0};
    idEx.tokenIDEx = GetSelfTokenID();
    MockNativeToken mock("audio_server");
    std::vector<CurrUsingPermInfo> infoList;
    EXPECT_EQ(0, PrivacyKit::GetCurrUsingPermInfo(infoList));

    GTEST_LOG_(INFO) << "infoList.size() " << infoList.size() << " expect 2 without Influenced by the environment.";
    size_t i = 0;
    bool foundIdA = false;
    bool foundIdB = false;
    size_t indexA = 0;
    size_t indexB = 0;
    while (i < infoList.size()) {
        if ((infoList[i].tokenID == g_tokenIdA) && (infoList[i].permissionName == "ohos.permission.CAMERA") &&
            (infoList[i].pid == -1)) {
            foundIdA = true;
            indexA = i;
        }
        if ((infoList[i].tokenID == g_tokenIdB) && (infoList[i].permissionName == "ohos.permission.CAMERA") &&
            (infoList[i].pid == RANDOM_PID)) {
            foundIdB = true;
            indexB = i;
        }
        if (foundIdA && foundIdB) {
            break;
        }
        i++;
    }
    EXPECT_EQ(true, foundIdA);
    if (foundIdA == true) {
        EXPECT_EQ(infoList[indexA].callingTokenID, idEx.tokenIdExStruct.tokenID);
        EXPECT_EQ(infoList[indexA].tokenID, g_tokenIdA);
        EXPECT_EQ(infoList[indexA].permissionName, "ohos.permission.CAMERA");
        EXPECT_EQ(infoList[indexA].pid, -1);
        EXPECT_EQ(infoList[indexA].deviceId, "");
        EXPECT_EQ(infoList[indexA].usedType, NORMAL_TYPE);
    }

    EXPECT_EQ(true, foundIdB);
    if (foundIdB == true) {
        EXPECT_EQ(infoList[indexB].callingTokenID, idEx.tokenIdExStruct.tokenID);
        EXPECT_EQ(infoList[indexB].tokenID, g_tokenIdB);
        EXPECT_EQ(infoList[indexB].permissionName, "ohos.permission.CAMERA");
        EXPECT_EQ(infoList[indexB].pid, RANDOM_PID);
        EXPECT_EQ(infoList[indexB].deviceId, "");
        EXPECT_EQ(infoList[indexB].usedType, PICKER_TYPE);
    }
}

/**
 * @tc.name: StartUsingPermission019
 * @tc.desc:
 * @tc.type: FUNC
 * @tc.require: issue2901
 */
HWTEST_F(PrivacyKitTest, StartUsingPermission019, TestSize.Level0)
{
    AccessTokenIDEx idEx = {0};
    idEx.tokenIDEx = GetSelfTokenID();
    auto callbackPtr = std::make_shared<CbCustomizeTest4>();
    EXPECT_EQ(0, PrivacyKit::StartUsingPermission(g_tokenIdA, "ohos.permission.CAMERA", callbackPtr));
    
    EXPECT_EQ(0, PrivacyKit::StartUsingPermission(
        g_tokenIdB, "ohos.permission.CAMERA", callbackPtr, RANDOM_PID, PICKER_TYPE));

    CheckInfo();
    SetSelfTokenID(idEx.tokenIDEx);
    EXPECT_EQ(0, PrivacyKit::StopUsingPermission(g_tokenIdA, "ohos.permission.CAMERA"));

    MockNativeToken mock("audio_server");
    std::vector<CurrUsingPermInfo> infoList;
    EXPECT_EQ(0, PrivacyKit::GetCurrUsingPermInfo(infoList));
    GTEST_LOG_(INFO) << "infoList.size() " << infoList.size() << " expect 1 without Influenced by the environment.";
    size_t i = 0;
    bool found = false;
    while (i < infoList.size()) {
        if ((infoList[i].tokenID == g_tokenIdB) && (infoList[i].permissionName == "ohos.permission.CAMERA") &&
            (infoList[i].pid == RANDOM_PID)) {
            found = true;
            break;
        }
        i++;
    }
    EXPECT_EQ(true, found);
    if (found == true) {
        EXPECT_EQ(infoList[i].callingTokenID, idEx.tokenIdExStruct.tokenID);
        EXPECT_EQ(infoList[i].tokenID, g_tokenIdB);
        EXPECT_EQ(infoList[i].permissionName, "ohos.permission.CAMERA");
        EXPECT_EQ(infoList[i].pid, RANDOM_PID);
        EXPECT_EQ(infoList[i].deviceId, "");
        EXPECT_EQ(infoList[i].usedType, PICKER_TYPE);
    }

    SetSelfTokenID(idEx.tokenIDEx);
    EXPECT_EQ(0, PrivacyKit::StopUsingPermission(g_tokenIdB, "ohos.permission.CAMERA", RANDOM_PID));
}

/**
 * @tc.name: StartUsingPermission020
 * @tc.desc:
 * @tc.type: FUNC
 * @tc.require: issue2901
 */
HWTEST_F(PrivacyKitTest, StartUsingPermission020, TestSize.Level0)
{
    auto callbackPtr = std::make_shared<CbCustomizeTest4>();
    EXPECT_EQ(PrivacyError::ERR_PARAM_INVALID,
        PrivacyKit::StartUsingPermission(g_tokenIdE, "ohos.permission.MICROPHONE", callbackPtr, RANDOM_PID));
}
