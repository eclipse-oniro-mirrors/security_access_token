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

#include "privacy_kit_test.h"

#include <chrono>

#include "access_token.h"
#include "accesstoken_kit.h"
#include "nativetoken_kit.h"
#include "on_permission_used_record_callback_stub.h"
#include "parameter.h"
#define private public
#include "perm_active_status_change_callback.h"
#include "privacy_manager_client.h"
#include "state_change_callback.h"
#undef private
#include "perm_active_response_parcel.h"
#include "perm_active_status_change_callback_stub.h"
#include "privacy_error.h"
#include "privacy_kit.h"
#include "state_change_callback_stub.h"
#include "string_ex.h"
#include "token_setproc.h"

using namespace testing::ext;
using namespace OHOS::Security::AccessToken;

const static int32_t RET_NO_ERROR = 0;
static constexpr int32_t DEFAULT_API_VERSION = 8;
static AccessTokenID g_nativeToken = 0;
static constexpr int32_t RANDOM_TOKENID = 123;
static constexpr int32_t INVALID_PERMISSIONAME_LENGTH = 257;
static constexpr int32_t FIRST_INDEX = 0;
static constexpr int32_t SECOND_INDEX = 1;
static constexpr int32_t THIRD_INDEX = 2;
static constexpr int32_t RESULT_NUM_ONE = 1;
static constexpr int32_t RESULT_NUM_TWO = 2;
static constexpr int32_t RESULT_NUM_THREE = 3;
// if change this, origin value in privacy_manager_proxy.cpp should change together
const static uint32_t MAX_PERMISSION_USED_TYPE_SIZE = 2000;

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

static PermissionDef g_infoManagerTestPermDefC = {
    .permissionName = "ohos.permission.PERMISSION_USED_STATS",
    .bundleName = "ohos.privacy_test.bundleC",
    .grantMode = 1,
    .availableLevel = APL_NORMAL,
    .label = "labelC",
    .labelId = 1,
    .description = "break the door",
    .descriptionId = 1
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
    .permList = {g_infoManagerTestPermDefC},
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
    .permStateList = {}
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

static HapInfoParams g_normalInfoParms = {
    .userID = 1,
    .bundleName = "accesstoken_test",
    .instIndex = 0,
    .appIDDesc = "testtesttesttest",
    .apiVersion = DEFAULT_API_VERSION,
    .isSystemApp = false
};
static HapInfoParams g_systemInfoParms = {
    .userID = 1,
    .bundleName = "accesstoken_test",
    .instIndex = 0,
    .appIDDesc = "testtesttesttest",
    .apiVersion = DEFAULT_API_VERSION,
    .isSystemApp = true
};

static AccessTokenID g_selfTokenId = 0;
static AccessTokenID g_tokenIdA = 0;
static AccessTokenID g_tokenIdB = 0;
static AccessTokenIDEx g_tokenIdC = {0};
static AccessTokenID g_tokenIdE = 0;

static void DeleteTestToken()
{
    AccessTokenID tokenId = AccessTokenKit::GetHapTokenID(g_infoParmsA.userID,
                                                          g_infoParmsA.bundleName,
                                                          g_infoParmsA.instIndex);
    AccessTokenKit::DeleteToken(tokenId);
    PrivacyKit::RemovePermissionUsedRecords(tokenId, "");

    tokenId = AccessTokenKit::GetHapTokenID(g_infoParmsB.userID,
                                            g_infoParmsB.bundleName,
                                            g_infoParmsB.instIndex);
    AccessTokenKit::DeleteToken(tokenId);
    PrivacyKit::RemovePermissionUsedRecords(tokenId, "");

    tokenId = AccessTokenKit::GetHapTokenID(g_infoParmsC.userID,
                                            g_infoParmsC.bundleName,
                                            g_infoParmsC.instIndex);
    AccessTokenKit::DeleteToken(tokenId);
    PrivacyKit::RemovePermissionUsedRecords(tokenId, "");

    tokenId = AccessTokenKit::GetHapTokenID(g_infoParmsE.userID,
                                            g_infoParmsE.bundleName,
                                            g_infoParmsE.instIndex);
    AccessTokenKit::DeleteToken(tokenId);
    PrivacyKit::RemovePermissionUsedRecords(tokenId, "");

    tokenId = AccessTokenKit::GetHapTokenID(g_normalInfoParms.userID,
                                            g_normalInfoParms.bundleName,
                                            g_normalInfoParms.instIndex);
    AccessTokenKit::DeleteToken(tokenId);
    PrivacyKit::RemovePermissionUsedRecords(tokenId, "");

    tokenId = AccessTokenKit::GetHapTokenID(g_systemInfoParms.userID,
                                            g_systemInfoParms.bundleName,
                                            g_systemInfoParms.instIndex);
    AccessTokenKit::DeleteToken(tokenId);
    PrivacyKit::RemovePermissionUsedRecords(tokenId, "");
}

void PrivacyKitTest::SetUpTestCase()
{
    DeleteTestToken();
    g_selfTokenId = GetSelfTokenID();
    g_nativeToken = AccessTokenKit::GetNativeTokenId("privacy_service");
}

void PrivacyKitTest::TearDownTestCase()
{
}

void PrivacyKitTest::SetUp()
{
    AccessTokenKit::AllocHapToken(g_infoParmsA, g_policyPramsA);
    AccessTokenKit::AllocHapToken(g_infoParmsB, g_policyPramsB);
    AccessTokenKit::AllocHapToken(g_infoParmsC, g_policyPramsC);
    AccessTokenKit::AllocHapToken(g_infoParmsE, g_policyPramsE);

    g_tokenIdA = AccessTokenKit::GetHapTokenID(g_infoParmsA.userID, g_infoParmsA.bundleName, g_infoParmsA.instIndex);
    g_tokenIdB = AccessTokenKit::GetHapTokenID(g_infoParmsB.userID, g_infoParmsB.bundleName, g_infoParmsB.instIndex);
    g_tokenIdC = AccessTokenKit::GetHapTokenIDEx(g_infoParmsC.userID, g_infoParmsC.bundleName, g_infoParmsC.instIndex);
    g_tokenIdE = AccessTokenKit::GetHapTokenID(g_infoParmsE.userID, g_infoParmsE.bundleName, g_infoParmsE.instIndex);
}

void PrivacyKitTest::TearDown()
{
    EXPECT_EQ(0, SetSelfTokenID(g_selfTokenId));
    DeleteTestToken();
}

std::string PrivacyKitTest::GetLocalDeviceUdid()
{
    const int32_t DEVICE_UUID_LENGTH = 65;
    char udid[DEVICE_UUID_LENGTH] = {0};
    GetDevUdid(udid, DEVICE_UUID_LENGTH);
    return udid;
}

void PrivacyKitTest::BuildQueryRequest(AccessTokenID tokenId, const std::string &deviceId,
    const std::string &bundleName, const std::vector<std::string> &permissionList, PermissionUsedRequest &request)
{
    request.tokenId = tokenId;
    request.isRemote = false;
    request.deviceId = deviceId;
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
    ASSERT_EQ(request.tokenId, result.bundleRecords[0].tokenId);
    ASSERT_EQ(request.isRemote, result.bundleRecords[0].isRemote);
    ASSERT_EQ(request.deviceId, result.bundleRecords[0].deviceId);
    ASSERT_EQ(request.bundleName, result.bundleRecords[0].bundleName);
    ASSERT_EQ(permRecordSize, static_cast<int32_t>(result.bundleRecords[0].permissionRecords.size()));
    for (int32_t i = 0; i < permRecordSize; i++) {
        successCount += result.bundleRecords[0].permissionRecords[i].accessCount;
        failCount += result.bundleRecords[0].permissionRecords[i].rejectCount;
    }
    ASSERT_EQ(totalSuccessCount, successCount);
    ASSERT_EQ(totalFailCount, failCount);
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
HWTEST_F(PrivacyKitTest, AddPermissionUsedRecord001, TestSize.Level1)
{
    AddPermParamInfo info;
    info.tokenId = 0;
    info.permissionName = "ohos.permission.READ_CONTACTS";
    info.successCount = 1;
    info.failCount = 0;
    ASSERT_EQ(PrivacyError::ERR_PARAM_INVALID, PrivacyKit::AddPermissionUsedRecord(info));

    info.tokenId = g_tokenIdA;
    info.permissionName = "";
    ASSERT_EQ(PrivacyError::ERR_PARAM_INVALID, PrivacyKit::AddPermissionUsedRecord(info));

    info.permissionName = "ohos.permission.READ_CONTACTS";
    info.successCount = -1;
    ASSERT_EQ(PrivacyError::ERR_PARAM_INVALID, PrivacyKit::AddPermissionUsedRecord(info));

    PermissionUsedRequest request;
    PermissionUsedResult result;
    std::vector<std::string> permissionList;
    BuildQueryRequest(g_tokenIdA, GetLocalDeviceUdid(), g_infoParmsA.bundleName, permissionList, request);
    ASSERT_EQ(RET_NO_ERROR, PrivacyKit::GetPermissionUsedRecords(request, result));
    ASSERT_EQ(static_cast<uint32_t>(0), result.bundleRecords.size());
}

/**
 * @tc.name: AddPermissionUsedRecord002
 * @tc.desc: cannot AddPermissionUsedRecord with invalid tokenId and permission.
 * @tc.type: FUNC
 * @tc.require: issueI5P4IU
 */
HWTEST_F(PrivacyKitTest, AddPermissionUsedRecord002, TestSize.Level1)
{
    AddPermParamInfo info;
    info.tokenId = g_tokenIdA;
    info.permissionName = "ohos.permission.test";
    info.successCount = 1;
    info.failCount = 0;
    ASSERT_EQ(PrivacyError::ERR_PERMISSION_NOT_EXIST, PrivacyKit::AddPermissionUsedRecord(info));

    info.tokenId = 672137215; // 672137215 is max native tokenId: 001 01 0 000000 11111111111111111111
    info.permissionName = "ohos.permission.CAMERA";
    ASSERT_EQ(PrivacyError::ERR_PARAM_INVALID, PrivacyKit::AddPermissionUsedRecord(info));

    info.tokenId = g_tokenIdA;
    info.permissionName = "ohos.permission.READ_CONTACTS";
    info.successCount = 0;
    ASSERT_EQ(PrivacyError::ERR_PARAM_INVALID, PrivacyKit::AddPermissionUsedRecord(info));

    PermissionUsedRequest request;
    PermissionUsedResult result;
    std::vector<std::string> permissionList;
    BuildQueryRequest(g_nativeToken, "", "", permissionList, request);
    ASSERT_EQ(RET_NO_ERROR, PrivacyKit::GetPermissionUsedRecords(request, result));
    ASSERT_EQ(static_cast<uint32_t>(0), result.bundleRecords.size());

    BuildQueryRequest(g_tokenIdA, GetLocalDeviceUdid(), g_infoParmsA.bundleName, permissionList, request);
    ASSERT_EQ(RET_NO_ERROR, PrivacyKit::GetPermissionUsedRecords(request, result));
    ASSERT_EQ(static_cast<uint32_t>(0), result.bundleRecords.size());
}

/**
 * @tc.name: AddPermissionUsedRecord003
 * @tc.desc: cannot AddPermissionUsedRecord with native tokenId.
 * @tc.type: FUNC
 * @tc.require: issueI5P4IU
 */
HWTEST_F(PrivacyKitTest, AddPermissionUsedRecord003, TestSize.Level1)
{
    const char **dcaps = new const char *[2];
    dcaps[0] = "AT_CAP";
    dcaps[1] = "ST_CAP";
    uint64_t tokenId;
    const char **acls = new const char *[2];
    acls[0] = "ohos.permission.test1";
    acls[1] = "ohos.permission.test2";
    const char **perms = new const char *[2];
    perms[0] = "ohos.permission.test1";
    perms[1] = "ohos.permission.test2";
    NativeTokenInfoParams infoInstance = {
        .dcapsNum = 2,
        .permsNum = 2,
        .aclsNum = 2,
        .dcaps = dcaps,
        .perms = perms,
        .acls = acls,
        .processName = "GetAccessTokenId008",
        .aplStr = "system_core",
    };
    tokenId = GetAccessTokenId(&infoInstance);
    ASSERT_NE(tokenId, static_cast<uint32_t>(0));

    delete[] perms;
    delete[] dcaps;
    delete[] acls;

    AddPermParamInfo info;
    info.tokenId = tokenId;
    info.permissionName = "ohos.permission.READ_CONTACTS";
    info.successCount = 1;
    info.failCount = 0;
    ASSERT_EQ(PrivacyError::ERR_PARAM_INVALID, PrivacyKit::AddPermissionUsedRecord(info));

    PermissionUsedRequest request;
    PermissionUsedResult result;
    std::vector<std::string> permissionList;
    BuildQueryRequest(tokenId, "", "", permissionList, request);

    ASSERT_EQ(RET_NO_ERROR, PrivacyKit::GetPermissionUsedRecords(request, result));
    ASSERT_EQ(static_cast<uint32_t>(0), result.bundleRecords.size());
}

/**
 * @tc.name: AddPermissionUsedRecord004
 * @tc.desc: AddPermissionUsedRecord user_grant permission.
 * @tc.type: FUNC
 * @tc.require: issueI5P4IU
 */
HWTEST_F(PrivacyKitTest, AddPermissionUsedRecord004, TestSize.Level1)
{
    AddPermParamInfo info;
    info.tokenId = g_tokenIdA;
    info.permissionName = "ohos.permission.CAMERA";
    info.successCount = 1;
    info.failCount = 0;
    ASSERT_EQ(RET_NO_ERROR, PrivacyKit::AddPermissionUsedRecord(info));

    info.permissionName = "ohos.permission.WRITE_CONTACTS";
    info.successCount = 0;
    info.failCount = 1;
    ASSERT_EQ(RET_NO_ERROR, PrivacyKit::AddPermissionUsedRecord(info));

    info.permissionName = "ohos.permission.LOCATION";
    info.successCount = 1;
    ASSERT_EQ(RET_NO_ERROR, PrivacyKit::AddPermissionUsedRecord(info));

    PermissionUsedRequest request;
    PermissionUsedResult result;
    std::vector<std::string> permissionList;
    BuildQueryRequest(g_tokenIdA, GetLocalDeviceUdid(), g_infoParmsA.bundleName, permissionList, request);
    ASSERT_EQ(RET_NO_ERROR, PrivacyKit::GetPermissionUsedRecords(request, result));

    ASSERT_EQ(static_cast<uint32_t>(1), result.bundleRecords.size());
    CheckPermissionUsedResult(request, result, 3, 2, 2);
}

/**
 * @tc.name: AddPermissionUsedRecord005
 * @tc.desc: AddPermissionUsedRecord user_grant permission.
 * @tc.type: FUNC
 * @tc.require: issueI5P4IU
 */
HWTEST_F(PrivacyKitTest, AddPermissionUsedRecord005, TestSize.Level1)
{
    AddPermParamInfo info;
    info.tokenId = g_tokenIdA;
    info.permissionName = "ohos.permission.CAMERA";
    info.successCount = 1;
    info.failCount = 0;
    ASSERT_EQ(RET_NO_ERROR, PrivacyKit::AddPermissionUsedRecord(info));

    info.permissionName = "ohos.permission.LOCATION";
    info.successCount = 0;
    info.failCount = 1;
    ASSERT_EQ(RET_NO_ERROR, PrivacyKit::AddPermissionUsedRecord(info));

    info.tokenId = g_tokenIdB;
    info.permissionName = "ohos.permission.CAMERA";
    ASSERT_EQ(RET_NO_ERROR, PrivacyKit::AddPermissionUsedRecord(info));

    info.permissionName = "ohos.permission.LOCATION";
    info.successCount = 1;
    info.failCount = 0;
    ASSERT_EQ(RET_NO_ERROR, PrivacyKit::AddPermissionUsedRecord(info));

    PermissionUsedRequest request;
    PermissionUsedResult result;
    std::vector<std::string> permissionList;
    BuildQueryRequest(g_tokenIdA, GetLocalDeviceUdid(), g_infoParmsA.bundleName, permissionList, request);
    ASSERT_EQ(RET_NO_ERROR, PrivacyKit::GetPermissionUsedRecords(request, result));

    ASSERT_EQ(static_cast<uint32_t>(1), result.bundleRecords.size());
    CheckPermissionUsedResult(request, result, 2, 1, 1);

    BuildQueryRequest(g_tokenIdB, GetLocalDeviceUdid(), g_infoParmsB.bundleName, permissionList, request);
    ASSERT_EQ(RET_NO_ERROR, PrivacyKit::GetPermissionUsedRecords(request, result));

    ASSERT_EQ(static_cast<uint32_t>(1), result.bundleRecords.size());
    CheckPermissionUsedResult(request, result, 2, 1, 1);

    request.flag = FLAG_PERMISSION_USAGE_SUMMARY_IN_SCREEN_LOCKED;
    ASSERT_EQ(RET_NO_ERROR, PrivacyKit::GetPermissionUsedRecords(request, result));

    request.flag = FLAG_PERMISSION_USAGE_SUMMARY_IN_SCREEN_UNLOCKED;
    ASSERT_EQ(RET_NO_ERROR, PrivacyKit::GetPermissionUsedRecords(request, result));

    request.flag = FLAG_PERMISSION_USAGE_SUMMARY_IN_APP_FOREGROUND;
    ASSERT_EQ(RET_NO_ERROR, PrivacyKit::GetPermissionUsedRecords(request, result));

    request.flag = FLAG_PERMISSION_USAGE_SUMMARY_IN_APP_BACKGROUND;
    ASSERT_EQ(RET_NO_ERROR, PrivacyKit::GetPermissionUsedRecords(request, result));
}

/**
 * @tc.name: AddPermissionUsedRecord006
 * @tc.desc: AddPermissionUsedRecord permission combine records.
 * @tc.type: FUNC
 * @tc.require: issueI5P4IU
 */
HWTEST_F(PrivacyKitTest, AddPermissionUsedRecord006, TestSize.Level1)
{
    SleepUtilMinuteEnd();
    AddPermParamInfo info;
    info.tokenId = g_tokenIdA;
    info.permissionName = "ohos.permission.CAMERA";
    info.successCount = 1;
    info.failCount = 0;

    ASSERT_EQ(RET_NO_ERROR, PrivacyKit::AddPermissionUsedRecord(info));
    ASSERT_EQ(RET_NO_ERROR, PrivacyKit::AddPermissionUsedRecord(info));
    ASSERT_EQ(RET_NO_ERROR, PrivacyKit::AddPermissionUsedRecord(info));
    ASSERT_EQ(RET_NO_ERROR, PrivacyKit::AddPermissionUsedRecord(info));

    PermissionUsedRequest request;
    PermissionUsedResult result;
    std::vector<std::string> permissionList;
    BuildQueryRequest(g_tokenIdA, GetLocalDeviceUdid(), g_infoParmsA.bundleName, permissionList, request);
    request.flag = FLAG_PERMISSION_USAGE_DETAIL;
    ASSERT_EQ(RET_NO_ERROR, PrivacyKit::GetPermissionUsedRecords(request, result));

    ASSERT_EQ(static_cast<uint32_t>(1), result.bundleRecords.size());
    ASSERT_EQ(static_cast<uint32_t>(1), result.bundleRecords[0].permissionRecords.size());
    ASSERT_EQ(static_cast<uint32_t>(1), result.bundleRecords[0].permissionRecords[0].accessRecords.size());
    CheckPermissionUsedResult(request, result, 1, 4, 0); // records in the same minute combine to one
}

/**
 * @tc.name: AddPermissionUsedRecord008
 * @tc.desc: AddPermissionUsedRecord caller is normal app.
 * @tc.type: FUNC
 * @tc.require: issueI66BH3
 */
HWTEST_F(PrivacyKitTest, AddPermissionUsedRecord008, TestSize.Level1)
{
    AccessTokenIDEx tokenIdEx = {0};
    tokenIdEx = AccessTokenKit::AllocHapToken(g_normalInfoParms, g_policyPramsA);
    ASSERT_NE(INVALID_TOKENID, tokenIdEx.tokenIDEx);
    EXPECT_EQ(0, SetSelfTokenID(tokenIdEx.tokenIDEx));

    AddPermParamInfo info;
    info.tokenId = g_tokenIdA;
    info.permissionName = "ohos.permission.CAMERA";
    info.successCount = 1;
    info.failCount = 0;
    ASSERT_EQ(PrivacyError::ERR_NOT_SYSTEM_APP, PrivacyKit::AddPermissionUsedRecord(info));
    ASSERT_EQ(0, PrivacyKit::AddPermissionUsedRecord(info, true));
}

/**
 * @tc.name: AddPermissionUsedRecord009
 * @tc.desc: query permission record detail count.
 * @tc.type: FUNC
 * @tc.require: issueI5P4IU
 */
HWTEST_F(PrivacyKitTest, AddPermissionUsedRecord009, TestSize.Level1)
{
    int32_t permRecordSize = 0;

    AddPermParamInfo info;
    info.tokenId = g_tokenIdA;
    info.permissionName = "ohos.permission.CAMERA";
    info.successCount = 1;
    info.failCount = 0;
    ASSERT_EQ(RET_NO_ERROR, PrivacyKit::AddPermissionUsedRecord(info));
    permRecordSize++;

    info.permissionName = "ohos.permission.WRITE_CONTACTS";
    info.successCount = 0;
    info.failCount = 2;
    ASSERT_EQ(RET_NO_ERROR, PrivacyKit::AddPermissionUsedRecord(info));
    permRecordSize++;

    info.permissionName = "ohos.permission.LOCATION";
    info.successCount = 3;
    info.failCount = 3;
    ASSERT_EQ(RET_NO_ERROR, PrivacyKit::AddPermissionUsedRecord(info));
    permRecordSize++;

    PermissionUsedRequest request;
    PermissionUsedResult result;
    std::vector<std::string> permissionList;
    BuildQueryRequest(g_tokenIdA, GetLocalDeviceUdid(), g_infoParmsA.bundleName, permissionList, request);
    request.flag = FLAG_PERMISSION_USAGE_DETAIL;
    ASSERT_EQ(RET_NO_ERROR, PrivacyKit::GetPermissionUsedRecords(request, result));

    ASSERT_EQ(static_cast<uint32_t>(1), result.bundleRecords.size());
    ASSERT_EQ(permRecordSize, static_cast<int32_t>(result.bundleRecords[0].permissionRecords.size()));
    for (int32_t i = 0; i < permRecordSize; i++) {
        if (result.bundleRecords[0].permissionRecords[i].permissionName == "ohos.permission.CAMERA") {
            ASSERT_EQ(static_cast<uint32_t>(1), result.bundleRecords[0].permissionRecords[i].accessRecords.size());
            ASSERT_EQ(static_cast<uint32_t>(0), result.bundleRecords[0].permissionRecords[i].rejectRecords.size());
            ASSERT_EQ(1, result.bundleRecords[0].permissionRecords[i].accessRecords[0].count);
        } else if (result.bundleRecords[0].permissionRecords[i].permissionName == "ohos.permission.WRITE_CONTACTS") {
            ASSERT_EQ(static_cast<uint32_t>(0), result.bundleRecords[0].permissionRecords[i].accessRecords.size());
            ASSERT_EQ(static_cast<uint32_t>(1), result.bundleRecords[0].permissionRecords[i].rejectRecords.size());
            ASSERT_EQ(2, result.bundleRecords[0].permissionRecords[i].rejectRecords[0].count);
        } else if (result.bundleRecords[0].permissionRecords[i].permissionName == "ohos.permission.LOCATION") {
            ASSERT_EQ(static_cast<uint32_t>(1), result.bundleRecords[0].permissionRecords[i].accessRecords.size());
            ASSERT_EQ(static_cast<uint32_t>(1), result.bundleRecords[0].permissionRecords[i].rejectRecords.size());
            ASSERT_EQ(3, result.bundleRecords[0].permissionRecords[i].accessRecords[0].count);
            ASSERT_EQ(3, result.bundleRecords[0].permissionRecords[i].rejectRecords[0].count);
        }
    }
}

/**
 * @tc.name: AddPermissionUsedRecord010
 * @tc.desc: test record cross minute not merge.
 * @tc.type: FUNC
 * @tc.require: issueI5P4IU
 */
HWTEST_F(PrivacyKitTest, AddPermissionUsedRecord010, TestSize.Level1)
{
    AddPermParamInfo info;
    info.tokenId = g_tokenIdA;
    info.permissionName = "ohos.permission.CAMERA";
    info.successCount = 1;
    info.failCount = 0;
    ASSERT_EQ(RET_NO_ERROR, PrivacyKit::AddPermissionUsedRecord(info));
    SleepUtilMinuteEnd();
    ASSERT_EQ(RET_NO_ERROR, PrivacyKit::AddPermissionUsedRecord(info));

    PermissionUsedRequest request;
    PermissionUsedResult result;
    std::vector<std::string> permissionList;
    BuildQueryRequest(g_tokenIdA, GetLocalDeviceUdid(), g_infoParmsA.bundleName, permissionList, request);
    request.flag = FLAG_PERMISSION_USAGE_DETAIL;
    ASSERT_EQ(RET_NO_ERROR, PrivacyKit::GetPermissionUsedRecords(request, result));

    ASSERT_EQ(static_cast<uint32_t>(1), result.bundleRecords.size());
    ASSERT_EQ(static_cast<uint32_t>(1), result.bundleRecords[0].permissionRecords.size());
    ASSERT_EQ(static_cast<uint32_t>(2), result.bundleRecords[0].permissionRecords[0].accessRecords.size());
}

/**
 * @tc.name: RemovePermissionUsedRecords001
 * @tc.desc: cannot RemovePermissionUsedRecords with illegal tokenId and deviceID.
 * @tc.type: FUNC
 * @tc.require: issueI5P4IU
 */
HWTEST_F(PrivacyKitTest, RemovePermissionUsedRecords001, TestSize.Level1)
{
    ASSERT_EQ(PrivacyError::ERR_PARAM_INVALID, PrivacyKit::RemovePermissionUsedRecords(0, ""));
}

/**
 * @tc.name: RemovePermissionUsedRecords002
 * @tc.desc: RemovePermissionUsedRecords with invalid tokenId and deviceID.
 * @tc.type: FUNC
 * @tc.require: issueI5P4IU
 */
HWTEST_F(PrivacyKitTest, RemovePermissionUsedRecords002, TestSize.Level1)
{
    AddPermParamInfo info;
    info.tokenId = g_tokenIdA;
    info.permissionName = "ohos.permission.CAMERA";
    info.successCount = 1;
    info.failCount = 0;
    ASSERT_EQ(RET_NO_ERROR, PrivacyKit::AddPermissionUsedRecord(info));
    PermissionUsedRequest request;
    PermissionUsedResult result;
    std::vector<std::string> permissionList;
    BuildQueryRequest(g_tokenIdA, GetLocalDeviceUdid(), g_infoParmsA.bundleName, permissionList, request);

    ASSERT_EQ(RET_NO_ERROR, PrivacyKit::RemovePermissionUsedRecords(g_tokenIdA, "invalid_device"));
    ASSERT_EQ(RET_NO_ERROR, PrivacyKit::GetPermissionUsedRecords(request, result));
    ASSERT_EQ(static_cast<uint32_t>(1), result.bundleRecords.size());

    ASSERT_EQ(RET_NO_ERROR, PrivacyKit::RemovePermissionUsedRecords(123, GetLocalDeviceUdid()));
    ASSERT_EQ(RET_NO_ERROR, PrivacyKit::GetPermissionUsedRecords(request, result));
    ASSERT_EQ(static_cast<uint32_t>(1), result.bundleRecords.size());
}

/**
 * @tc.name: RemovePermissionUsedRecords003
 * @tc.desc: RemovePermissionUsedRecords with valid tokenId and deviceID.
 * @tc.type: FUNC
 * @tc.require: issueI5P4IU
 */
HWTEST_F(PrivacyKitTest, RemovePermissionUsedRecords003, TestSize.Level1)
{
    AddPermParamInfo info;
    info.tokenId = g_tokenIdA;
    info.permissionName = "ohos.permission.CAMERA";
    info.successCount = 1;
    info.failCount = 0;
    ASSERT_EQ(RET_NO_ERROR, PrivacyKit::AddPermissionUsedRecord(info));
    PermissionUsedRequest request;
    PermissionUsedResult result;
    std::vector<std::string> permissionList;
    BuildQueryRequest(g_tokenIdA, GetLocalDeviceUdid(), g_infoParmsA.bundleName, permissionList, request);

    ASSERT_EQ(RET_NO_ERROR, PrivacyKit::RemovePermissionUsedRecords(g_tokenIdA, ""));
    ASSERT_EQ(RET_NO_ERROR, PrivacyKit::GetPermissionUsedRecords(request, result));
    ASSERT_EQ(static_cast<uint32_t>(0), result.bundleRecords.size());
}

/**
 * @tc.name: GetPermissionUsedRecords001
 * @tc.desc: cannot GetPermissionUsedRecords with invalid query time and flag.
 * @tc.type: FUNC
 * @tc.require: issueI5P4IU
 */
HWTEST_F(PrivacyKitTest, GetPermissionUsedRecords001, TestSize.Level1)
{
    AddPermParamInfo info;
    info.tokenId = g_tokenIdA;
    info.permissionName = "ohos.permission.MICROPHONE";
    info.successCount = 1;
    info.failCount = 0;
    ASSERT_EQ(RET_NO_ERROR, PrivacyKit::AddPermissionUsedRecord(info));
    PermissionUsedRequest request;
    PermissionUsedResult result;
    std::vector<std::string> permissionList;
    BuildQueryRequest(g_tokenIdA, GetLocalDeviceUdid(), g_infoParmsA.bundleName, permissionList, request);
    request.beginTimeMillis = -1;
    request.endTimeMillis = -1;
    ASSERT_EQ(PrivacyError::ERR_PARAM_INVALID, PrivacyKit::GetPermissionUsedRecords(request, result));

    request.beginTimeMillis = 3;
    request.endTimeMillis = 1;
    ASSERT_EQ(PrivacyError::ERR_PARAM_INVALID, PrivacyKit::GetPermissionUsedRecords(request, result));

    request.flag = (PermissionUsageFlag)-1;
    ASSERT_EQ(PrivacyError::ERR_PARAM_INVALID, PrivacyKit::GetPermissionUsedRecords(request, result));
}

/**
 * @tc.name: GetPermissionUsedRecords002
 * @tc.desc: cannot GetPermissionUsedRecords with valid query time.
 * @tc.type: FUNC
 * @tc.require: issueI5P4IU
 */
HWTEST_F(PrivacyKitTest, GetPermissionUsedRecords002, TestSize.Level1)
{
    AddPermParamInfo info;
    info.tokenId = g_tokenIdA;
    info.permissionName = "ohos.permission.MICROPHONE";
    info.successCount = 1;
    info.failCount = 0;
    ASSERT_EQ(RET_NO_ERROR, PrivacyKit::AddPermissionUsedRecord(info));

    info.permissionName = "ohos.permission.CAMERA";
    ASSERT_EQ(RET_NO_ERROR, PrivacyKit::AddPermissionUsedRecord(info));

    info.permissionName = "ohos.permission.READ_CALENDAR";
    ASSERT_EQ(RET_NO_ERROR, PrivacyKit::AddPermissionUsedRecord(info));

    PermissionUsedRequest request;
    PermissionUsedResult result;
    std::vector<std::string> permissionList;
    // query by tokenId
    BuildQueryRequest(g_tokenIdA, "", "", permissionList, request);
    ASSERT_EQ(RET_NO_ERROR, PrivacyKit::GetPermissionUsedRecords(request, result));
    ASSERT_EQ(static_cast<uint32_t>(1), result.bundleRecords.size());
    request.deviceId = GetLocalDeviceUdid();
    request.bundleName = g_infoParmsA.bundleName;
    CheckPermissionUsedResult(request, result, 3, 3, 0);

    // query by unmatched tokenId, deviceId and bundle Name
    BuildQueryRequest(123, GetLocalDeviceUdid(), g_infoParmsA.bundleName, permissionList, request);
    ASSERT_EQ(RET_NO_ERROR, PrivacyKit::GetPermissionUsedRecords(request, result));
    ASSERT_EQ(static_cast<uint32_t>(0), result.bundleRecords.size());

    // query by invalid permission Name
    permissionList.clear();
    permissionList.emplace_back("invalid permission");
    BuildQueryRequest(g_tokenIdA, GetLocalDeviceUdid(), g_infoParmsA.bundleName, permissionList, request);
    ASSERT_EQ(RET_NO_ERROR, PrivacyKit::GetPermissionUsedRecords(request, result));
    ASSERT_EQ(static_cast<uint32_t>(0), result.bundleRecords.size());
}

/**
 * @tc.name: GetPermissionUsedRecords003
 * @tc.desc: can GetPermissionUsedRecords with valid query time.
 * @tc.type: FUNC
 * @tc.require: issueI5P4IU
 */
HWTEST_F(PrivacyKitTest, GetPermissionUsedRecords003, TestSize.Level1)
{
    AddPermParamInfo info;
    info.tokenId = g_tokenIdA;
    info.permissionName = "ohos.permission.MICROPHONE";
    info.successCount = 1;
    info.failCount = 0;
    ASSERT_EQ(RET_NO_ERROR, PrivacyKit::AddPermissionUsedRecord(info));
    ASSERT_EQ(RET_NO_ERROR, PrivacyKit::AddPermissionUsedRecord(info));
    ASSERT_EQ(RET_NO_ERROR, PrivacyKit::AddPermissionUsedRecord(info));
    ASSERT_EQ(RET_NO_ERROR, PrivacyKit::AddPermissionUsedRecord(info));

    PermissionUsedRequest request;
    PermissionUsedResult result;
    std::vector<std::string> permissionList;
    BuildQueryRequest(g_tokenIdA, GetLocalDeviceUdid(), g_infoParmsA.bundleName, permissionList, request);
    ASSERT_EQ(RET_NO_ERROR, PrivacyKit::GetPermissionUsedRecords(request, result));
    ASSERT_EQ(static_cast<uint32_t>(1), result.bundleRecords.size());
    CheckPermissionUsedResult(request, result, 1, 4, 0);

    info.permissionName = "ohos.permission.CAMERA";
    ASSERT_EQ(RET_NO_ERROR, PrivacyKit::AddPermissionUsedRecord(info));

    info.permissionName = "ohos.permission.READ_CALENDAR";
    ASSERT_EQ(RET_NO_ERROR, PrivacyKit::AddPermissionUsedRecord(info));

    info.permissionName = "ohos.permission.WRITE_CALENDAR";
    ASSERT_EQ(RET_NO_ERROR, PrivacyKit::AddPermissionUsedRecord(info));

    BuildQueryRequest(g_tokenIdA, GetLocalDeviceUdid(), g_infoParmsA.bundleName, permissionList, request);
    ASSERT_EQ(RET_NO_ERROR, PrivacyKit::GetPermissionUsedRecords(request, result));
    ASSERT_EQ(static_cast<uint32_t>(1), result.bundleRecords.size());
    CheckPermissionUsedResult(request, result, 4, 7, 0);
}

/**
 * @tc.name: GetPermissionUsedRecords004
 * @tc.desc: can GetPermissionUsedRecords with valid query time.
 * @tc.type: FUNC
 * @tc.require: issueI5P4IU
 */
HWTEST_F(PrivacyKitTest, GetPermissionUsedRecords004, TestSize.Level1)
{
    AddPermParamInfo info;
    info.tokenId = g_tokenIdA;
    info.permissionName = "ohos.permission.CAMERA";
    info.successCount = 1;
    info.failCount = 0;
    ASSERT_EQ(RET_NO_ERROR, PrivacyKit::AddPermissionUsedRecord(info));

    info.permissionName = "ohos.permission.READ_CALENDAR";
    ASSERT_EQ(RET_NO_ERROR, PrivacyKit::AddPermissionUsedRecord(info));

    info.tokenId = g_tokenIdB;
    info.permissionName = "ohos.permission.CAMERA";
    ASSERT_EQ(RET_NO_ERROR, PrivacyKit::AddPermissionUsedRecord(info));

    info.permissionName = "ohos.permission.READ_CALENDAR";
    ASSERT_EQ(RET_NO_ERROR, PrivacyKit::AddPermissionUsedRecord(info));

    PermissionUsedRequest request;
    PermissionUsedResult result;
    std::vector<std::string> permissionList;
    BuildQueryRequest(0, GetLocalDeviceUdid(), "", permissionList, request);

    ASSERT_EQ(RET_NO_ERROR, PrivacyKit::GetPermissionUsedRecords(request, result));
    if (result.bundleRecords.size() < static_cast<uint32_t>(2)) {
        ASSERT_TRUE(false);
    }
}

/**
 * @tc.name: GetPermissionUsedRecords005
 * @tc.desc: GetPermissionUsedRecords005 caller is normal app.
 * @tc.type: FUNC
 * @tc.require: issueI66BH3
 */
HWTEST_F(PrivacyKitTest, GetPermissionUsedRecords005, TestSize.Level1)
{
    AccessTokenIDEx tokenIdEx = {0};
    tokenIdEx = AccessTokenKit::AllocHapToken(g_normalInfoParms, g_policyPramsA);
    ASSERT_NE(INVALID_TOKENID, tokenIdEx.tokenIDEx);
    EXPECT_EQ(0, SetSelfTokenID(tokenIdEx.tokenIDEx));

    PermissionUsedRequest request;
    PermissionUsedResult result;
    std::vector<std::string> permissionList;
    // query by tokenId
    BuildQueryRequest(g_tokenIdA, "", "", permissionList, request);
    ASSERT_EQ(PrivacyError::ERR_NOT_SYSTEM_APP, PrivacyKit::GetPermissionUsedRecords(request, result));
}

/**
 * @tc.name: GetPermissionUsedRecordsAsync001
 * @tc.desc: cannot GetPermissionUsedRecordsAsync with invalid query time.
 * @tc.type: FUNC
 * @tc.require: issueI5P4IU
 */
HWTEST_F(PrivacyKitTest, GetPermissionUsedRecordsAsync001, TestSize.Level1)
{
    AddPermParamInfo info;
    info.tokenId = g_tokenIdA;
    info.permissionName = "ohos.permission.CAMERA";
    info.successCount = 1;
    info.failCount = 0;
    ASSERT_EQ(RET_NO_ERROR, PrivacyKit::AddPermissionUsedRecord(info));
    PermissionUsedRequest request;
    std::vector<std::string> permissionList;
    BuildQueryRequest(g_tokenIdA, GetLocalDeviceUdid(), "", permissionList, request);
    request.beginTimeMillis = -1;
    request.endTimeMillis = -1;
    OHOS::sptr<TestCallBack> callback(new TestCallBack());
    ASSERT_EQ(PrivacyError::ERR_PARAM_INVALID, PrivacyKit::GetPermissionUsedRecords(request, callback));
}

/**
 * @tc.name: GetPermissionUsedRecordsAsync002
 * @tc.desc: cannot GetPermissionUsedRecordsAsync with valid query time.
 * @tc.type: FUNC
 * @tc.require: issueI5P4IU
 */
HWTEST_F(PrivacyKitTest, GetPermissionUsedRecordsAsync002, TestSize.Level1)
{
    AddPermParamInfo info;
    info.tokenId = g_tokenIdA;
    info.permissionName = "ohos.permission.CAMERA";
    info.successCount = 1;
    info.failCount = 0;
    ASSERT_EQ(RET_NO_ERROR, PrivacyKit::AddPermissionUsedRecord(info));
    PermissionUsedRequest request;
    std::vector<std::string> permissionList;
    BuildQueryRequest(g_tokenIdA, GetLocalDeviceUdid(), "", permissionList, request);
    OHOS::sptr<TestCallBack> callback(new TestCallBack());
    ASSERT_EQ(RET_NO_ERROR, PrivacyKit::GetPermissionUsedRecords(request, callback));
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
HWTEST_F(PrivacyKitTest, RegisterPermActiveStatusCallback001, TestSize.Level1)
{
    std::vector<std::string> permList = {"ohos.permission.CAMERA"};

    auto callbackPtr = std::make_shared<CbCustomizeTest1>(permList);
    callbackPtr->type_ = PERM_INACTIVE;

    ASSERT_EQ(RET_NO_ERROR, PrivacyKit::RegisterPermActiveStatusCallback(callbackPtr));

    ASSERT_EQ(RET_NO_ERROR, PrivacyKit::StartUsingPermission(g_tokenIdE, "ohos.permission.CAMERA"));

    usleep(500000); // 500000us = 0.5s
    ASSERT_EQ(PERM_ACTIVE_IN_BACKGROUND, callbackPtr->type_);

    ASSERT_EQ(RET_NO_ERROR, PrivacyKit::StopUsingPermission(g_tokenIdE, "ohos.permission.CAMERA"));

    usleep(500000); // 500000us = 0.5s
    ASSERT_EQ(PERM_INACTIVE, callbackPtr->type_);

    ASSERT_EQ(RET_NO_ERROR, PrivacyKit::UnRegisterPermActiveStatusCallback(callbackPtr));
    callbackPtr->type_ = PERM_INACTIVE;

    ASSERT_EQ(RET_NO_ERROR, PrivacyKit::StartUsingPermission(g_tokenIdE, "ohos.permission.CAMERA"));
    ASSERT_EQ(PERM_INACTIVE, callbackPtr->type_);

    ASSERT_EQ(RET_NO_ERROR, PrivacyKit::StopUsingPermission(g_tokenIdE, "ohos.permission.CAMERA"));
    ASSERT_EQ(PERM_INACTIVE, callbackPtr->type_);
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
HWTEST_F(PrivacyKitTest, RegisterPermActiveStatusCallback002, TestSize.Level1)
{
    std::vector<std::string> permList1 = {"ohos.permission.CAMERA"};
    auto callbackPtr1 = std::make_shared<CbCustomizeTest1>(permList1);
    callbackPtr1->type_ = PERM_INACTIVE;

    std::vector<std::string> permList2 = {"ohos.permission.MICROPHONE"};
    auto callbackPtr2 = std::make_shared<CbCustomizeTest2>(permList2);
    callbackPtr2->type_ = PERM_INACTIVE;

    std::vector<std::string> permList3 = {};
    auto callbackPtr3 = std::make_shared<CbCustomizeTest2>(permList3);
    callbackPtr3->type_ = PERM_INACTIVE;

    ASSERT_EQ(RET_NO_ERROR, PrivacyKit::RegisterPermActiveStatusCallback(callbackPtr1));
    ASSERT_EQ(RET_NO_ERROR, PrivacyKit::RegisterPermActiveStatusCallback(callbackPtr2));
    ASSERT_EQ(RET_NO_ERROR, PrivacyKit::RegisterPermActiveStatusCallback(callbackPtr3));

    ASSERT_EQ(RET_NO_ERROR, PrivacyKit::StartUsingPermission(g_tokenIdE, "ohos.permission.CAMERA"));

    usleep(500000); // 500000us = 0.5s
    ASSERT_EQ(PERM_ACTIVE_IN_BACKGROUND, callbackPtr1->type_);
    ASSERT_EQ(PERM_INACTIVE, callbackPtr2->type_);
    ASSERT_EQ(PERM_ACTIVE_IN_BACKGROUND, callbackPtr3->type_);

    ASSERT_EQ(RET_NO_ERROR, PrivacyKit::StopUsingPermission(g_tokenIdE, "ohos.permission.CAMERA"));

    usleep(500000); // 500000us = 0.5s
    ASSERT_EQ(PERM_INACTIVE, callbackPtr1->type_);
    ASSERT_EQ(PERM_INACTIVE, callbackPtr3->type_);

    ASSERT_EQ(RET_NO_ERROR, PrivacyKit::StartUsingPermission(g_tokenIdE, "ohos.permission.MICROPHONE"));

    usleep(500000); // 500000us = 0.5s
    ASSERT_EQ(PERM_INACTIVE, callbackPtr1->type_);
    ASSERT_EQ(PERM_ACTIVE_IN_BACKGROUND, callbackPtr2->type_);

    ASSERT_EQ(RET_NO_ERROR, PrivacyKit::StopUsingPermission(g_tokenIdE, "ohos.permission.MICROPHONE"));

    usleep(500000); // 500000us = 0.5s
    ASSERT_EQ(PERM_INACTIVE, callbackPtr2->type_);

    ASSERT_EQ(RET_NO_ERROR, PrivacyKit::UnRegisterPermActiveStatusCallback(callbackPtr1));
    ASSERT_EQ(RET_NO_ERROR, PrivacyKit::UnRegisterPermActiveStatusCallback(callbackPtr2));
    ASSERT_EQ(RET_NO_ERROR, PrivacyKit::UnRegisterPermActiveStatusCallback(callbackPtr3));
}

/**
 * @tc.name: RegisterPermActiveStatusCallback003
 * @tc.desc: Register callback with permList which contains 1025 permissions.
 * @tc.type: FUNC
 * @tc.require: issueI5NT1X
 */
HWTEST_F(PrivacyKitTest, RegisterPermActiveStatusCallback003, TestSize.Level1)
{
    std::vector<std::string> permList;
    for (int32_t i = 0; i < 1024; i++) { // 1024 is the limitation
        permList.emplace_back("ohos.permission.CAMERA");
    }
    auto callbackPtr1 = std::make_shared<CbCustomizeTest3>(permList);
    ASSERT_EQ(RET_NO_ERROR, PrivacyKit::RegisterPermActiveStatusCallback(callbackPtr1));
    ASSERT_EQ(RET_NO_ERROR, PrivacyKit::UnRegisterPermActiveStatusCallback(callbackPtr1));

    permList.emplace_back("ohos.permission.MICROPHONE");
    auto callbackPtr = std::make_shared<CbCustomizeTest3>(permList);
    ASSERT_EQ(PrivacyError::ERR_PARAM_INVALID, PrivacyKit::RegisterPermActiveStatusCallback(callbackPtr));
}

/**
 * @tc.name: RegisterPermActiveStatusCallback004
 * @tc.desc: Register callback 201 times.
 * @tc.type: FUNC
 * @tc.require: issueI5NT1X
 */
HWTEST_F(PrivacyKitTest, RegisterPermActiveStatusCallback004, TestSize.Level1)
{
    std::vector<std::string> permList = {"ohos.permission.CAMERA"};
    std::vector<std::shared_ptr<CbCustomizeTest3>> callbackList;

    for (int32_t i = 0; i <= 200; i++) { // 200 is the max size
        if (i == 200) { // 200 is the max size
            auto callbackPtr = std::make_shared<CbCustomizeTest3>(permList);
            ASSERT_EQ(PrivacyError::ERR_CALLBACKS_EXCEED_LIMITATION,
                PrivacyKit::RegisterPermActiveStatusCallback(callbackPtr));
            break;
        }
        auto callbackPtr = std::make_shared<CbCustomizeTest3>(permList);
        ASSERT_EQ(RET_NO_ERROR, PrivacyKit::RegisterPermActiveStatusCallback(callbackPtr));
        callbackList.emplace_back(callbackPtr);
    }
    for (int32_t i = 0; i < 200; i++) { // release 200 callback
        auto callbackPtr = callbackList[i];
        ASSERT_EQ(RET_NO_ERROR, PrivacyKit::UnRegisterPermActiveStatusCallback(callbackPtr));
    }
    callbackList.clear();
}

/**
 * @tc.name: RegisterPermActiveStatusCallback005
 * @tc.desc: RegisterPermActiveStatusCallback with valid permission.
 * @tc.type: FUNC
 * @tc.require: issueI5NT1X
 */
HWTEST_F(PrivacyKitTest, RegisterPermActiveStatusCallback005, TestSize.Level1)
{
    std::vector<std::string> permList = {"ohos.permission.INVALD"};

    auto callbackPtr = std::make_shared<CbCustomizeTest3>(permList);
    ASSERT_EQ(PrivacyError::ERR_PARAM_INVALID, PrivacyKit::RegisterPermActiveStatusCallback(callbackPtr));

    std::vector<std::string> permList1 = {"ohos.permission.INVALD", "ohos.permission.CAMERA"};
    auto callbackPtr1 = std::make_shared<CbCustomizeTest3>(permList1);
    ASSERT_EQ(RET_NO_ERROR, PrivacyKit::RegisterPermActiveStatusCallback(callbackPtr1));
    ASSERT_EQ(RET_NO_ERROR, PrivacyKit::UnRegisterPermActiveStatusCallback(callbackPtr1));
}

/**
 * @tc.name: RegisterPermActiveStatusCallback006
 * @tc.desc: UnRegisterPermActiveStatusCallback with invalid callback.
 * @tc.type: FUNC
 * @tc.require: issueI5NT1X
 */
HWTEST_F(PrivacyKitTest, RegisterPermActiveStatusCallback006, TestSize.Level1)
{
    std::vector<std::string> permList = {"ohos.permission.CAMERA"};
    auto callbackPtr = std::make_shared<CbCustomizeTest3>(permList);
    ASSERT_EQ(PrivacyError::ERR_CALLBACK_NOT_EXIST, PrivacyKit::UnRegisterPermActiveStatusCallback(callbackPtr));
}

/**
 * @tc.name: RegisterPermActiveStatusCallback007
 * @tc.desc: RegisterPermActiveStatusCallback with valid permission repeatedly.
 * @tc.type: FUNC
 * @tc.require: issueI5NT1X
 */
HWTEST_F(PrivacyKitTest, RegisterPermActiveStatusCallback007, TestSize.Level1)
{
    std::vector<std::string> permList = {"ohos.permission.CAMERA"};
    auto callbackPtr = std::make_shared<CbCustomizeTest3>(permList);
    ASSERT_EQ(RET_NO_ERROR, PrivacyKit::RegisterPermActiveStatusCallback(callbackPtr));
    ASSERT_EQ(PrivacyError::ERR_CALLBACK_ALREADY_EXIST, PrivacyKit::RegisterPermActiveStatusCallback(callbackPtr));
    ASSERT_EQ(RET_NO_ERROR, PrivacyKit::UnRegisterPermActiveStatusCallback(callbackPtr));
    ASSERT_EQ(PrivacyError::ERR_CALLBACK_NOT_EXIST, PrivacyKit::UnRegisterPermActiveStatusCallback(callbackPtr));
}

/**
 * @tc.name: RegisterPermActiveStatusCallback008
 * @tc.desc: register and startusing three permission.
 * @tc.type: FUNC
 * @tc.require: issueI5SZHG
 */
HWTEST_F(PrivacyKitTest, RegisterPermActiveStatusCallback008, TestSize.Level1)
{
    std::vector<std::string> permList = {
        "ohos.permission.CAMERA",
        "ohos.permission.MICROPHONE",
        "ohos.permission.LOCATION"
    };
    auto callbackPtr = std::make_shared<CbCustomizeTest3>(permList);
    int32_t res = PrivacyKit::RegisterPermActiveStatusCallback(callbackPtr);
    ASSERT_EQ(RET_NO_ERROR, res);
    res = PrivacyKit::StartUsingPermission(g_tokenIdE, "ohos.permission.CAMERA");
    ASSERT_EQ(RET_NO_ERROR, res);
    res = PrivacyKit::StartUsingPermission(g_tokenIdE, "ohos.permission.MICROPHONE");
    ASSERT_EQ(RET_NO_ERROR, res);
    res = PrivacyKit::StartUsingPermission(g_tokenIdE, "ohos.permission.LOCATION");
    ASSERT_EQ(RET_NO_ERROR, res);
    res = PrivacyKit::StopUsingPermission(g_tokenIdE, "ohos.permission.CAMERA");
    ASSERT_EQ(RET_NO_ERROR, res);
    res = PrivacyKit::StopUsingPermission(g_tokenIdE, "ohos.permission.MICROPHONE");
    ASSERT_EQ(RET_NO_ERROR, res);
    res = PrivacyKit::StopUsingPermission(g_tokenIdE, "ohos.permission.LOCATION");
    ASSERT_EQ(RET_NO_ERROR, res);
    res = PrivacyKit::UnRegisterPermActiveStatusCallback(callbackPtr);
    ASSERT_EQ(RET_NO_ERROR, res);
}

/**
 * @tc.name: RegisterPermActiveStatusCallback009
 * @tc.desc: PrivacyManagerClient::RegisterPermActiveStatusCallback function test
 * @tc.type: FUNC
 * @tc.require: issueI61A6M
 */
HWTEST_F(PrivacyKitTest, RegisterPermActiveStatusCallback009, TestSize.Level1)
{
    std::shared_ptr<PermActiveStatusCustomizedCbk> callback = nullptr;
    ASSERT_EQ(nullptr, callback);
    PrivacyManagerClient::GetInstance().RegisterPermActiveStatusCallback(callback); // callback is null
}

/**
 * @tc.name: RegisterPermActiveStatusCallback010
 * @tc.desc: RegisterPermActiveStatusCallback caller is normal app.
 * @tc.type: FUNC
 * @tc.require: issueI66BH3
 */
HWTEST_F(PrivacyKitTest, RegisterPermActiveStatusCallback010, TestSize.Level1)
{
    AccessTokenIDEx tokenIdEx = {0};
    tokenIdEx = AccessTokenKit::AllocHapToken(g_normalInfoParms, g_policyPramsA);
    ASSERT_NE(INVALID_TOKENID, tokenIdEx.tokenIDEx);
    EXPECT_EQ(0, SetSelfTokenID(tokenIdEx.tokenIDEx));

    std::vector<std::string> permList1 = {"ohos.permission.CAMERA"};
    auto callbackPtr = std::make_shared<CbCustomizeTest3>(permList1);
    ASSERT_EQ(PrivacyError::ERR_NOT_SYSTEM_APP, PrivacyKit::RegisterPermActiveStatusCallback(callbackPtr));
}

/**
 * @tc.name: RegisterPermActiveStatusCallback011
 * @tc.desc: UnRegisterPermActiveStatusCallback caller is normal app.
 * @tc.type: FUNC
 * @tc.require: issueI66BH3
 */
HWTEST_F(PrivacyKitTest, RegisterPermActiveStatusCallback011, TestSize.Level1)
{
    std::vector<std::string> permList1 = {"ohos.permission.CAMERA"};
    auto callbackPtr1 = std::make_shared<CbCustomizeTest3>(permList1);
    ASSERT_EQ(RET_NO_ERROR, PrivacyKit::RegisterPermActiveStatusCallback(callbackPtr1));

    AccessTokenIDEx tokenIdEx = {0};
    tokenIdEx = AccessTokenKit::AllocHapToken(g_normalInfoParms, g_policyPramsA);
    ASSERT_NE(INVALID_TOKENID, tokenIdEx.tokenIDEx);
    EXPECT_EQ(0, SetSelfTokenID(tokenIdEx.tokenIDEx));
    ASSERT_EQ(PrivacyError::ERR_NOT_SYSTEM_APP, PrivacyKit::UnRegisterPermActiveStatusCallback(callbackPtr1));

    EXPECT_EQ(0, SetSelfTokenID(g_selfTokenId));
    ASSERT_EQ(RET_NO_ERROR, PrivacyKit::UnRegisterPermActiveStatusCallback(callbackPtr1));
}

/**
 * @tc.name: IsAllowedUsingPermission001
 * @tc.desc: IsAllowedUsingPermission with invalid tokenId or permission.
 * @tc.type: FUNC
 * @tc.require: issueI5RWX3 issueI5RWX8
 */
HWTEST_F(PrivacyKitTest, IsAllowedUsingPermission001, TestSize.Level1)
{
    std::string permissionName = "ohos.permission.CAMERA";
    ASSERT_EQ(false, PrivacyKit::IsAllowedUsingPermission(g_tokenIdE, permissionName));
    ASSERT_EQ(false, PrivacyKit::IsAllowedUsingPermission(0, permissionName));
    ASSERT_EQ(false, PrivacyKit::IsAllowedUsingPermission(g_tokenIdE, ""));
}

/**
 * @tc.name: IsAllowedUsingPermission002
 * @tc.desc: IsAllowedUsingPermission with no permission.
 * @tc.type: FUNC
 * @tc.require: issueI5RWX3 issueI5RWX8
 */
HWTEST_F(PrivacyKitTest, IsAllowedUsingPermission002, TestSize.Level1)
{
    EXPECT_EQ(0, SetSelfTokenID(g_selfTokenId));
    std::string permissionName = "ohos.permission.CAMERA";
    ASSERT_EQ(false, PrivacyKit::IsAllowedUsingPermission(g_tokenIdE, permissionName));
}
/**
 * @tc.name: StartUsingPermission001
 * @tc.desc: StartUsingPermission with invalid tokenId or permission.
 * @tc.type: FUNC
 * @tc.require: issueI5NT1X issueI5P4IU issueI5P530
 */
HWTEST_F(PrivacyKitTest, StartUsingPermission001, TestSize.Level1)
{
    ASSERT_EQ(PrivacyError::ERR_PARAM_INVALID, PrivacyKit::StartUsingPermission(0, "ohos.permission.CAMERA"));
    ASSERT_EQ(PrivacyError::ERR_PARAM_INVALID, PrivacyKit::StartUsingPermission(0, "permissionName"));
}

/**
 * @tc.name: StartUsingPermission002
 * @tc.desc: StartUsingPermission is called twice with same permission.
 * @tc.type: FUNC
 * @tc.require: issueI5NT1X issueI5P4IU issueI5P530
 */
HWTEST_F(PrivacyKitTest, StartUsingPermission002, TestSize.Level1)
{
    std::string permissionName = "ohos.permission.CAMERA";
    ASSERT_EQ(RET_NO_ERROR, PrivacyKit::StartUsingPermission(g_tokenIdE, permissionName));
    ASSERT_EQ(PrivacyError::ERR_PERMISSION_ALREADY_START_USING,
        PrivacyKit::StartUsingPermission(g_tokenIdE, permissionName));
    ASSERT_EQ(RET_NO_ERROR, PrivacyKit::StopUsingPermission(g_tokenIdE, permissionName));
}

/**
 * @tc.name: StopUsingPermission003
 * @tc.desc: Add record when StopUsingPermission is called.
 * @tc.type: FUNC
 * @tc.require: issueI5NT1X issueI5P4IU issueI5P530
 */
HWTEST_F(PrivacyKitTest, StartUsingPermission003, TestSize.Level1)
{
    std::string permissionName = "ohos.permission.CAMERA";
    ASSERT_EQ(RET_NO_ERROR, PrivacyKit::StartUsingPermission(g_tokenIdE, permissionName));
    ASSERT_EQ(RET_NO_ERROR, PrivacyKit::AddPermissionUsedRecord(g_tokenIdE, permissionName, 1, 0));

    usleep(500000); // 500000us = 0.5s
    ASSERT_EQ(RET_NO_ERROR, PrivacyKit::StopUsingPermission(g_tokenIdE, permissionName));

    PermissionUsedRequest request;
    PermissionUsedResult result;
    std::vector<std::string> permissionList;
    BuildQueryRequest(g_tokenIdE, GetLocalDeviceUdid(), g_infoParmsE.bundleName, permissionList, request);
    ASSERT_EQ(RET_NO_ERROR, PrivacyKit::GetPermissionUsedRecords(request, result));
    ASSERT_EQ(static_cast<uint32_t>(1), result.bundleRecords.size());
    ASSERT_EQ(g_tokenIdE, result.bundleRecords[0].tokenId);
    ASSERT_EQ(g_infoParmsE.bundleName, result.bundleRecords[0].bundleName);
    ASSERT_EQ(static_cast<uint32_t>(1), result.bundleRecords[0].permissionRecords.size());
    ASSERT_EQ(1, result.bundleRecords[0].permissionRecords[0].accessCount);
}

/**
 * @tc.name: StartUsingPermission004
 * @tc.desc: StartUsingPermission basic functional verification
 * @tc.type: FUNC
 * @tc.require: issueI5NT1X issueI5P4IU issueI5P530
 */
HWTEST_F(PrivacyKitTest, StartUsingPermission004, TestSize.Level1)
{
    std::string permissionName = "ohos.permission.CAMERA";
    ASSERT_EQ(RET_NO_ERROR, PrivacyKit::StartUsingPermission(g_tokenIdE, permissionName));
    ASSERT_EQ(RET_NO_ERROR, PrivacyKit::StopUsingPermission(g_tokenIdE, permissionName));
}

/**
 * @tc.name: StartUsingPermission005
 * @tc.desc: StartUsingPermission with invalid tokenId or permission.
 * @tc.type: FUNC
 * @tc.require: issueI5NT1X issueI5P4IU issueI5P530
 */
HWTEST_F(PrivacyKitTest, StartUsingPermission005, TestSize.Level1)
{
    std::string permissionName = "ohos.permission.UtTestInvalidPermission";
    ASSERT_EQ(PrivacyError::ERR_PERMISSION_NOT_EXIST, PrivacyKit::StartUsingPermission(g_tokenIdE, permissionName));
    ASSERT_EQ(PrivacyError::ERR_PARAM_INVALID, PrivacyKit::StartUsingPermission(0, "ohos.permission.CAMERA"));
    ASSERT_EQ(
        PrivacyError::ERR_PARAM_INVALID, PrivacyKit::StartUsingPermission(g_nativeToken, "ohos.permission.CAMERA"));
}

/**
 * @tc.name: StartUsingPermission006
 * @tc.desc: StartUsingPermission with invalid tokenId or permission or callback.
 * @tc.type: FUNC
 * @tc.require: issueI5RWX5 issueI5RWX3 issueI5RWXA
 */
HWTEST_F(PrivacyKitTest, StartUsingPermission006, TestSize.Level1)
{
    auto callbackPtr = std::make_shared<CbCustomizeTest4>();
    ASSERT_EQ(PrivacyError::ERR_PARAM_INVALID,
        PrivacyKit::StartUsingPermission(0, "ohos.permission.CAMERA", callbackPtr));
    ASSERT_EQ(PrivacyError::ERR_PARAM_INVALID,
        PrivacyKit::StartUsingPermission(g_tokenIdE, "", callbackPtr));
    ASSERT_EQ(PrivacyError::ERR_PARAM_INVALID,
        PrivacyKit::StartUsingPermission(g_tokenIdE, "ohos.permission.CAMERA", nullptr));
    ASSERT_EQ(PrivacyError::ERR_PARAM_INVALID,
        PrivacyKit::StartUsingPermission(g_tokenIdE, "permissionName", callbackPtr));
}

/**
 * @tc.name: StartUsingPermission007
 * @tc.desc: StartUsingPermission is called twice with same callback.
 * @tc.type: FUNC
 * @tc.require: issueI5RWX5 issueI5RWX3 issueI5RWXA
 */
HWTEST_F(PrivacyKitTest, StartUsingPermission007, TestSize.Level1)
{
    std::string permissionName = "ohos.permission.CAMERA";
    auto callbackPtr = std::make_shared<CbCustomizeTest4>();
    ASSERT_EQ(RET_NO_ERROR, PrivacyKit::StartUsingPermission(g_tokenIdE, permissionName, callbackPtr));
    ASSERT_EQ(PrivacyError::ERR_CALLBACK_ALREADY_EXIST,
        PrivacyKit::StartUsingPermission(g_tokenIdE, permissionName, callbackPtr));
    ASSERT_EQ(RET_NO_ERROR, PrivacyKit::StopUsingPermission(g_tokenIdE, permissionName));
}

/**
 * @tc.name: StopUsingPermission008
 * @tc.desc: Add record when StopUsingPermission is called.
 * @tc.type: FUNC
 * @tc.require: issueI5RWX5 issueI5RWX3 issueI5RWXA
 */
HWTEST_F(PrivacyKitTest, StopUsingPermission008, TestSize.Level1)
{
    std::string permissionName = "ohos.permission.CAMERA";
    auto callbackPtr = std::make_shared<CbCustomizeTest4>();
    ASSERT_EQ(RET_NO_ERROR, PrivacyKit::StartUsingPermission(g_tokenIdE, permissionName, callbackPtr));
    ASSERT_EQ(RET_NO_ERROR, PrivacyKit::AddPermissionUsedRecord(g_tokenIdE, permissionName, 1, 0));

    usleep(500000); // 500000us = 0.5s
    ASSERT_EQ(RET_NO_ERROR, PrivacyKit::StopUsingPermission(g_tokenIdE, permissionName));

    PermissionUsedRequest request;
    PermissionUsedResult result;
    std::vector<std::string> permissionList;
    BuildQueryRequest(g_tokenIdE, GetLocalDeviceUdid(), g_infoParmsE.bundleName, permissionList, request);
    ASSERT_EQ(RET_NO_ERROR, PrivacyKit::GetPermissionUsedRecords(request, result));
    ASSERT_EQ(static_cast<uint32_t>(1), result.bundleRecords.size());
    ASSERT_EQ(g_tokenIdE, result.bundleRecords[0].tokenId);
    ASSERT_EQ(g_infoParmsE.bundleName, result.bundleRecords[0].bundleName);
    ASSERT_EQ(static_cast<uint32_t>(1), result.bundleRecords[0].permissionRecords.size());
    ASSERT_EQ(1, result.bundleRecords[0].permissionRecords[0].accessCount);
}

/**
 * @tc.name: StartUsingPermission009
 * @tc.desc: StartUsingPermission basic functional verification
 * @tc.type: FUNC
 * @tc.require: issueI5RWX5 issueI5RWX3 issueI5RWXA
 */
HWTEST_F(PrivacyKitTest, StartUsingPermission009, TestSize.Level1)
{
    std::string permissionName = "ohos.permission.CAMERA";
    auto callbackPtr = std::make_shared<CbCustomizeTest4>();
    ASSERT_EQ(RET_NO_ERROR, PrivacyKit::StartUsingPermission(g_tokenIdE, permissionName, callbackPtr));
    ASSERT_EQ(RET_NO_ERROR, PrivacyKit::StopUsingPermission(g_tokenIdE, permissionName));
}

/**
 * @tc.name: StartUsingPermission010
 * @tc.desc: StartUsingPermission caller is normal app.
 * @tc.type: FUNC
 * @tc.require: issueI66BH3
 */
HWTEST_F(PrivacyKitTest, StartUsingPermission010, TestSize.Level1)
{
    g_policyPramsA.permStateList.emplace_back(g_infoManagerTestStateC);
    AccessTokenIDEx tokenIdEx = {0};
    tokenIdEx = AccessTokenKit::AllocHapToken(g_normalInfoParms, g_policyPramsA);
    ASSERT_NE(INVALID_TOKENID, tokenIdEx.tokenIDEx);
    EXPECT_EQ(0, SetSelfTokenID(tokenIdEx.tokenIDEx));

    std::string permissionName = "ohos.permission.CAMERA";
    ASSERT_EQ(PrivacyError::ERR_NOT_SYSTEM_APP, PrivacyKit::StartUsingPermission(g_tokenIdE, permissionName));
}

/**
 * @tc.name: StopUsingPermission001
 * @tc.desc: StopUsingPermission with invalid tokenId or permission.
 * @tc.type: FUNC
 * @tc.require: issueI5NT1X issueI5P4IU issueI5P530
 */
HWTEST_F(PrivacyKitTest, StopUsingPermission001, TestSize.Level1)
{
    ASSERT_EQ(PrivacyError::ERR_PARAM_INVALID, PrivacyKit::StopUsingPermission(0, "ohos.permission.CAMERA"));
    ASSERT_EQ(PrivacyError::ERR_PARAM_INVALID, PrivacyKit::StopUsingPermission(0, "permissionName"));
}

/**
 * @tc.name: StopUsingPermission002
 * @tc.desc: StopUsingPermission cancel permissions that you haven't started using
 * @tc.type: FUNC
 * @tc.require: issueI5NT1X issueI5P4IU issueI5P530
 */
HWTEST_F(PrivacyKitTest, StopUsingPermission002, TestSize.Level1)
{
    std::string permissionName = "ohos.permission.CAMERA";
    ASSERT_EQ(
        PrivacyError::ERR_PERMISSION_NOT_START_USING, PrivacyKit::StopUsingPermission(g_tokenIdE, permissionName));
}

/**
 * @tc.name: StopUsingPermission003
 * @tc.desc: StopUsingPermission invalid tokenid, permission
 * @tc.type: FUNC
 * @tc.require: issueI5NT1X issueI5P4IU issueI5P530
 */
HWTEST_F(PrivacyKitTest, StopUsingPermission003, TestSize.Level1)
{
    std::string permissionName = "ohos.permission.CAMERA";
    ASSERT_EQ(RET_NO_ERROR, PrivacyKit::StartUsingPermission(g_tokenIdE, permissionName));
    ASSERT_EQ(PrivacyError::ERR_PERMISSION_NOT_EXIST,
        PrivacyKit::StopUsingPermission(g_tokenIdE, "ohos.permission.uttestpermission"));
    ASSERT_EQ(PrivacyError::ERR_PARAM_INVALID, PrivacyKit::StopUsingPermission(0, permissionName));
    ASSERT_EQ(RET_NO_ERROR, PrivacyKit::StopUsingPermission(g_tokenIdE, permissionName));
}

/**
 * @tc.name: StopUsingPermission004
 * @tc.desc: StopUsingPermission stop a use repeatedly
 * @tc.type: FUNC
 * @tc.require: issueI5NT1X issueI5P4IU issueI5P530
 */
HWTEST_F(PrivacyKitTest, StopUsingPermission004, TestSize.Level1)
{
    std::string permissionName = "ohos.permission.CAMERA";
    ASSERT_EQ(RET_NO_ERROR, PrivacyKit::StartUsingPermission(g_tokenIdE, permissionName));
    ASSERT_EQ(RET_NO_ERROR, PrivacyKit::StopUsingPermission(g_tokenIdE, permissionName));
    ASSERT_EQ(
        PrivacyError::ERR_PERMISSION_NOT_START_USING, PrivacyKit::StopUsingPermission(g_tokenIdE, permissionName));
}

/**
 * @tc.name: StopUsingPermission005
 * @tc.desc: stop use whith native token
 * @tc.type: FUNC
 * @tc.require: issueI5SZHG
 */
HWTEST_F(PrivacyKitTest, StopUsingPermission005, TestSize.Level1)
{
    ASSERT_EQ(
        PrivacyError::ERR_PARAM_INVALID, PrivacyKit::StopUsingPermission(g_nativeToken, "ohos.permission.CAMERA"));
}

/**
 * @tc.name: StopUsingPermission006
 * @tc.desc: StopUsingPermission caller is normal app.
 * @tc.type: FUNC
 * @tc.require: issueI66BH3
 */
HWTEST_F(PrivacyKitTest, StopUsingPermission006, TestSize.Level1)
{
    AccessTokenIDEx tokenIdEx = {0};
    tokenIdEx = AccessTokenKit::AllocHapToken(g_normalInfoParms, g_policyPramsA);
    ASSERT_NE(INVALID_TOKENID, tokenIdEx.tokenIDEx);
    EXPECT_EQ(0, SetSelfTokenID(tokenIdEx.tokenIDEx));

    std::string permissionName = "ohos.permission.CAMERA";
    ASSERT_EQ(PrivacyError::ERR_NOT_SYSTEM_APP, PrivacyKit::StopUsingPermission(g_tokenIdE, permissionName));
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
HWTEST_F(PrivacyKitTest, OnRemoteRequest001, TestSize.Level1)
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
HWTEST_F(PrivacyKitTest, OnRemoteRequest002, TestSize.Level1)
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
HWTEST_F(PrivacyKitTest, OnRemoteRequest003, TestSize.Level1)
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
HWTEST_F(PrivacyKitTest, ActiveStatusChangeCallback001, TestSize.Level1)
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
    ASSERT_NE(nullptr, callback);
    callback->ActiveStatusChangeCallback(response); // customizedCallback_ is null
}

/**
 * @tc.name: StateChangeNotify001
 * @tc.desc: StateChangeCallback::StateChangeNotify function test
 * @tc.type: FUNC
 * @tc.require: issueI61A6M
 */
HWTEST_F(PrivacyKitTest, StateChangeNotify001, TestSize.Level1)
{
    AccessTokenID tokenId = 123; // 123 is random input
    bool isShowing = false;
    std::shared_ptr<StateCustomizedCbk> callbackPtr = std::make_shared<CbCustomizeTest4>();
    OHOS::sptr<StateChangeCallback> callback = new (std::nothrow) StateChangeCallback(callbackPtr);
    ASSERT_NE(nullptr, callback);
    callback->StateChangeNotify(tokenId, isShowing); // customizedCallback_ is null
}

/**
 * @tc.name: InitProxy001
 * @tc.desc: PrivacyManagerClient::InitProxy function test
 * @tc.type: FUNC
 * @tc.require: issueI61A6M
 */
HWTEST_F(PrivacyKitTest, InitProxy001, TestSize.Level1)
{
    ASSERT_NE(nullptr, PrivacyManagerClient::GetInstance().proxy_);
    OHOS::sptr<IPrivacyManager> proxy = PrivacyManagerClient::GetInstance().proxy_; // backup
    PrivacyManagerClient::GetInstance().proxy_ = nullptr;
    ASSERT_EQ(nullptr, PrivacyManagerClient::GetInstance().proxy_);
    PrivacyManagerClient::GetInstance().InitProxy(); // proxy_ is null
    PrivacyManagerClient::GetInstance().proxy_ = proxy; // recovery
}

/**
 * @tc.name: StartUsingPermission008
 * @tc.desc: PrivacyKit:: function test input invalid
 * @tc.type: FUNC
 * @tc.require: issueI61A6M
 */
HWTEST_F(PrivacyKitTest, StartUsingPermission008, TestSize.Level1)
{
    AccessTokenID tokenId = 0;
    std::string permissionName;
    ASSERT_EQ(PrivacyError::ERR_PARAM_INVALID, PrivacyKit::StartUsingPermission(tokenId, permissionName));
    ASSERT_EQ(PrivacyError::ERR_PARAM_INVALID, PrivacyKit::StopUsingPermission(tokenId, permissionName));
    ASSERT_EQ(PrivacyError::ERR_PARAM_INVALID, PrivacyKit::RemovePermissionUsedRecords(tokenId, permissionName));
    ASSERT_EQ(false, PrivacyKit::IsAllowedUsingPermission(tokenId, permissionName));
}

#ifdef SECURITY_COMPONENT_ENHANCE_ENABLE
/**
 * @tc.name: StartUsingPermission008
 * @tc.desc: PrivacyKit:: function test register enhance data
 * @tc.type: FUNC
 * @tc.require: issueI7MXZ
 */
HWTEST_F(PrivacyKitTest, RegisterSecCompEnhance001, TestSize.Level1)
{
    SetSelfTokenID(g_tokenIdA);
    SecCompEnhanceData data;
    data.callback = nullptr;
    data.challenge = 0;
    data.seqNum = 0;
    EXPECT_EQ(PrivacyError::ERR_WRITE_PARCEL_FAILED, PrivacyKit::RegisterSecCompEnhance(data));

    // StateChangeCallback is not the real callback of SecCompEnhance, but it does not effect the final result.
    auto callbackPtr = std::make_shared<CbCustomizeTest4>();
    data.callback = new (std::nothrow) StateChangeCallback(callbackPtr);
    EXPECT_EQ(RET_SUCCESS, PrivacyKit::RegisterSecCompEnhance(data));

    AccessTokenID secCompId = AccessTokenKit::GetNativeTokenId("security_component_service");
    EXPECT_EQ(0, SetSelfTokenID(secCompId));
    SecCompEnhanceData data1;
    EXPECT_EQ(RET_SUCCESS, PrivacyKit::GetSecCompEnhance(getpid(), data1));
    EXPECT_NE(RET_SUCCESS, PrivacyKit::GetSecCompEnhance(0, data1));
    EXPECT_EQ(RET_SUCCESS, PrivacyKit::UpdateSecCompEnhance(getpid(), 1));
    EXPECT_NE(RET_SUCCESS, PrivacyKit::UpdateSecCompEnhance(0, 1));
}

/**
 * @tc.name: GetSpecialSecCompEnhance001
 * @tc.desc: PrivacyKit:: function test Get Special enhance
 * @tc.type: FUNC
 * @tc.require: issueI7MXZ
 */
HWTEST_F(PrivacyKitTest, GetSpecialSecCompEnhance001, TestSize.Level1)
{
    AccessTokenID secCompId = AccessTokenKit::GetNativeTokenId("security_component_service");
    EXPECT_EQ(0, SetSelfTokenID(secCompId));

    std::vector<SecCompEnhanceData> res;
    ASSERT_EQ(RET_SUCCESS, PrivacyKit::GetSpecialSecCompEnhance("", res));
    ASSERT_EQ(static_cast<int32_t>(res.size()), 0);
    ASSERT_EQ(RET_SUCCESS, PrivacyKit::GetSpecialSecCompEnhance(g_infoParmsA.bundleName, res));
}
#endif

/**
 * @tc.name: AddPermissionUsedRecord011
 * @tc.desc: Test AddPermissionUsedRecord with default normal used type
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(PrivacyKitTest, AddPermissionUsedRecord011, TestSize.Level1)
{
    AddPermParamInfo info;
    info.tokenId = g_tokenIdA;
    info.permissionName = "ohos.permission.CAMERA";
    info.successCount = 1;
    info.failCount = 0;
    ASSERT_EQ(RET_SUCCESS, PrivacyKit::AddPermissionUsedRecord(info)); // add normal used type

    std::vector<PermissionUsedTypeInfo> results;
    ASSERT_EQ(RET_SUCCESS, PrivacyKit::GetPermissionUsedTypeInfos(g_tokenIdA, "ohos.permission.CAMERA", results));
    ASSERT_EQ(static_cast<size_t>(RESULT_NUM_ONE), results.size());
    ASSERT_EQ(PermissionUsedType::NORMAL_TYPE, results[FIRST_INDEX].type); // only normal type
    results.clear();

    ASSERT_EQ(RET_SUCCESS, PrivacyKit::AddPermissionUsedRecord(info)); // repeat
    ASSERT_EQ(RET_SUCCESS, PrivacyKit::GetPermissionUsedTypeInfos(g_tokenIdA, "ohos.permission.CAMERA", results));
    ASSERT_EQ(static_cast<size_t>(RESULT_NUM_ONE), results.size());
    ASSERT_EQ(PermissionUsedType::NORMAL_TYPE, results[FIRST_INDEX].type); // results remain
}

/**
 * @tc.name: AddPermissionUsedRecord012
 * @tc.desc: Test AddPermissionUsedRecord with picker used type
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(PrivacyKitTest, AddPermissionUsedRecord012, TestSize.Level1)
{
    AddPermParamInfo info;
    info.tokenId = g_tokenIdA;
    info.permissionName = "ohos.permission.CAMERA";
    info.successCount = 1;
    info.failCount = 0;
    info.type = PermissionUsedType::PICKER_TYPE;
    ASSERT_EQ(RET_SUCCESS, PrivacyKit::AddPermissionUsedRecord(info)); // add picker used type

    std::vector<PermissionUsedTypeInfo> results;
    ASSERT_EQ(RET_SUCCESS, PrivacyKit::GetPermissionUsedTypeInfos(g_tokenIdA, "ohos.permission.CAMERA", results));
    ASSERT_EQ(static_cast<size_t>(RESULT_NUM_ONE), results.size());
    ASSERT_EQ(PermissionUsedType::PICKER_TYPE, results[FIRST_INDEX].type); // only picker type
    results.clear();

    ASSERT_EQ(RET_SUCCESS, PrivacyKit::AddPermissionUsedRecord(info)); // repeat
    ASSERT_EQ(RET_SUCCESS, PrivacyKit::GetPermissionUsedTypeInfos(g_tokenIdA, "ohos.permission.CAMERA", results));
    ASSERT_EQ(static_cast<size_t>(RESULT_NUM_ONE), results.size());
    ASSERT_EQ(PermissionUsedType::PICKER_TYPE, results[FIRST_INDEX].type); // results remain
}

/**
 * @tc.name: AddPermissionUsedRecord013
 * @tc.desc: Test AddPermissionUsedRecord with security component used type
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(PrivacyKitTest, AddPermissionUsedRecord013, TestSize.Level1)
{
    AddPermParamInfo info;
    info.tokenId = g_tokenIdA;
    info.permissionName = "ohos.permission.CAMERA";
    info.successCount = 1;
    info.failCount = 0;
    info.type = PermissionUsedType::SECURITY_COMPONENT_TYPE;
    ASSERT_EQ(RET_SUCCESS, PrivacyKit::AddPermissionUsedRecord(info)); // add security component used type

    std::vector<PermissionUsedTypeInfo> results;
    ASSERT_EQ(RET_SUCCESS, PrivacyKit::GetPermissionUsedTypeInfos(g_tokenIdA, "ohos.permission.CAMERA", results));
    ASSERT_EQ(static_cast<size_t>(RESULT_NUM_ONE), results.size());
    ASSERT_EQ(PermissionUsedType::SECURITY_COMPONENT_TYPE, results[FIRST_INDEX].type); // only security component type
    results.clear();

    ASSERT_EQ(RET_SUCCESS, PrivacyKit::AddPermissionUsedRecord(info)); // repeat
    ASSERT_EQ(RET_SUCCESS, PrivacyKit::GetPermissionUsedTypeInfos(g_tokenIdA, "ohos.permission.CAMERA", results));
    ASSERT_EQ(static_cast<size_t>(RESULT_NUM_ONE), results.size());
    ASSERT_EQ(PermissionUsedType::SECURITY_COMPONENT_TYPE, results[FIRST_INDEX].type); // results remain
}

/**
 * @tc.name: AddPermissionUsedRecord014
 * @tc.desc: Test AddPermissionUsedRecord with default normal and picker used type
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(PrivacyKitTest, AddPermissionUsedRecord014, TestSize.Level1)
{
    AddPermParamInfo info;
    info.tokenId = g_tokenIdA;
    info.permissionName = "ohos.permission.CAMERA";
    info.successCount = 1;
    info.failCount = 0;
    ASSERT_EQ(RET_SUCCESS, PrivacyKit::AddPermissionUsedRecord(info)); // add normal used type

    info.type = PermissionUsedType::PICKER_TYPE;
    ASSERT_EQ(RET_SUCCESS, PrivacyKit::AddPermissionUsedRecord(info)); // add picker used type

    std::vector<PermissionUsedTypeInfo> results;
    ASSERT_EQ(RET_SUCCESS, PrivacyKit::GetPermissionUsedTypeInfos(g_tokenIdA, "ohos.permission.CAMERA", results));
    ASSERT_EQ(static_cast<size_t>(RESULT_NUM_TWO), results.size());
    ASSERT_EQ(NORMAL_TYPE, results[FIRST_INDEX].type); // contain normal type
    ASSERT_EQ(PICKER_TYPE, results[SECOND_INDEX].type); // contain picker type
}

/**
 * @tc.name: AddPermissionUsedRecord015
 * @tc.desc: Test AddPermissionUsedRecord with default normal and security component used type
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(PrivacyKitTest, AddPermissionUsedRecord015, TestSize.Level1)
{
    AddPermParamInfo info;
    info.tokenId = g_tokenIdA;
    info.permissionName = "ohos.permission.CAMERA";
    info.successCount = 1;
    info.failCount = 0;
    ASSERT_EQ(RET_SUCCESS, PrivacyKit::AddPermissionUsedRecord(info)); // add normal used type

    info.type = PermissionUsedType::SECURITY_COMPONENT_TYPE;
    ASSERT_EQ(RET_SUCCESS, PrivacyKit::AddPermissionUsedRecord(info)); // add security component used type

    std::vector<PermissionUsedTypeInfo> results;
    ASSERT_EQ(RET_SUCCESS, PrivacyKit::GetPermissionUsedTypeInfos(g_tokenIdA, "ohos.permission.CAMERA", results));
    ASSERT_EQ(static_cast<size_t>(RESULT_NUM_TWO), results.size());
    ASSERT_EQ(NORMAL_TYPE, results[FIRST_INDEX].type); // contain normal type
    ASSERT_EQ(SECURITY_COMPONENT_TYPE, results[SECOND_INDEX].type); // contain security component type
}

/**
 * @tc.name: AddPermissionUsedRecord016
 * @tc.desc: Test AddPermissionUsedRecord with picker and security component used type
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(PrivacyKitTest, AddPermissionUsedRecord016, TestSize.Level1)
{
    AddPermParamInfo info;
    info.tokenId = g_tokenIdA;
    info.permissionName = "ohos.permission.CAMERA";
    info.successCount = 1;
    info.failCount = 0;
    info.type = PermissionUsedType::PICKER_TYPE;
    ASSERT_EQ(RET_SUCCESS, PrivacyKit::AddPermissionUsedRecord(info)); // add picker used type

    info.type = PermissionUsedType::SECURITY_COMPONENT_TYPE;
    ASSERT_EQ(RET_SUCCESS, PrivacyKit::AddPermissionUsedRecord(info)); // add security component used type

    std::vector<PermissionUsedTypeInfo> results;
    ASSERT_EQ(RET_SUCCESS, PrivacyKit::GetPermissionUsedTypeInfos(g_tokenIdA, "ohos.permission.CAMERA", results));
    ASSERT_EQ(static_cast<size_t>(RESULT_NUM_TWO), results.size());
    ASSERT_EQ(PICKER_TYPE, results[FIRST_INDEX].type); // contain picker type
    ASSERT_EQ(SECURITY_COMPONENT_TYPE, results[SECOND_INDEX].type); // contain security component type
}

/**
 * @tc.name: AddPermissionUsedRecord017
 * @tc.desc: Test AddPermissionUsedRecord with all used type
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(PrivacyKitTest, AddPermissionUsedRecord017, TestSize.Level1)
{
    AddPermParamInfo info;
    info.tokenId = g_tokenIdA;
    info.permissionName = "ohos.permission.CAMERA";
    info.successCount = 1;
    info.failCount = 0;
    ASSERT_EQ(RET_SUCCESS, PrivacyKit::AddPermissionUsedRecord(info)); // add normal used type

    info.type = PermissionUsedType::PICKER_TYPE;
    ASSERT_EQ(RET_SUCCESS, PrivacyKit::AddPermissionUsedRecord(info)); // add picker used type

    info.type = PermissionUsedType::SECURITY_COMPONENT_TYPE;
    ASSERT_EQ(RET_SUCCESS, PrivacyKit::AddPermissionUsedRecord(info)); // add security component used type

    std::vector<PermissionUsedTypeInfo> results;
    ASSERT_EQ(RET_SUCCESS, PrivacyKit::GetPermissionUsedTypeInfos(g_tokenIdA, "ohos.permission.CAMERA", results));
    ASSERT_EQ(static_cast<size_t>(RESULT_NUM_THREE), results.size());
    ASSERT_EQ(NORMAL_TYPE, results[FIRST_INDEX].type); // contain normal type
    ASSERT_EQ(PICKER_TYPE, results[SECOND_INDEX].type); // contain picker type
    ASSERT_EQ(SECURITY_COMPONENT_TYPE, results[THIRD_INDEX].type); // contain security component type
}

/**
 * @tc.name: AddPermissionUsedRecord018
 * @tc.desc: Test AddPermissionUsedRecord with invalid used type
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(PrivacyKitTest, AddPermissionUsedRecord018, TestSize.Level1)
{
    AddPermParamInfo info;
    info.tokenId = g_tokenIdA;
    info.permissionName = "ohos.permission.CAMERA";
    info.successCount = 1;
    info.failCount = 0;
    info.type = PermissionUsedType::INVALID_USED_TYPE;
    ASSERT_EQ(PrivacyError::ERR_PARAM_INVALID, PrivacyKit::AddPermissionUsedRecord(info)); // add invalid used type
}

/**
 * @tc.name: GetPermissionUsedTypeInfos001
 * @tc.desc: Test GetPermissionUsedTypeInfos with default input
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(PrivacyKitTest, GetPermissionUsedTypeInfos001, TestSize.Level1)
{
    AddPermParamInfo info;
    info.tokenId = g_tokenIdA;
    info.permissionName = "ohos.permission.CAMERA";
    info.successCount = 1;
    info.failCount = 0;
    // g_tokenIdA add normal used type
    ASSERT_EQ(RET_SUCCESS, PrivacyKit::AddPermissionUsedRecord(info));

    info.tokenId = g_tokenIdB;
    info.type = PermissionUsedType::PICKER_TYPE;
    // g_tokenIdB add picker used type
    ASSERT_EQ(RET_SUCCESS, PrivacyKit::AddPermissionUsedRecord(info));

    info.tokenId = g_tokenIdC.tokenIdExStruct.tokenID;
    info.type = PermissionUsedType::SECURITY_COMPONENT_TYPE;
    // g_tokenIdC add security component used type
    ASSERT_EQ(RET_SUCCESS, PrivacyKit::AddPermissionUsedRecord(info));

    std::string permissionName;
    std::vector<PermissionUsedTypeInfo> results;
    ASSERT_EQ(RET_SUCCESS, PrivacyKit::GetPermissionUsedTypeInfos(0, permissionName, results));
    // results size may more than 3
    for (PermissionUsedTypeInfo& result : results) {
        if (result.tokenId == g_tokenIdA) {
            ASSERT_EQ(PermissionUsedType::NORMAL_TYPE, result.type); // g_tokenIdA only normal type
        } else if (result.tokenId == g_tokenIdB) {
            ASSERT_EQ(PermissionUsedType::PICKER_TYPE, result.type); // g_tokenIdB only picker type
        } else if (result.tokenId == g_tokenIdC.tokenIdExStruct.tokenID) {
            // g_tokenIdC only security component type
            ASSERT_EQ(PermissionUsedType::SECURITY_COMPONENT_TYPE, result.type);
        }
    }
}

/**
 * @tc.name: GetPermissionUsedTypeInfos002
 * @tc.desc: Test GetPermissionUsedTypeInfos with default tokenId
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(PrivacyKitTest, GetPermissionUsedTypeInfos002, TestSize.Level1)
{
    AddPermParamInfo info;
    info.tokenId = g_tokenIdA;
    info.permissionName = "ohos.permission.CAMERA";
    info.successCount = 1;
    info.failCount = 0;
    // CAMERA add normal used type
    ASSERT_EQ(RET_SUCCESS, PrivacyKit::AddPermissionUsedRecord(info));

    info.permissionName = "ohos.permission.LOCATION";
    info.type = PermissionUsedType::PICKER_TYPE;
    // LOCATION add picker used type
    ASSERT_EQ(RET_SUCCESS, PrivacyKit::AddPermissionUsedRecord(info));

    info.permissionName = "ohos.permission.MICROPHONE";
    info.type = PermissionUsedType::SECURITY_COMPONENT_TYPE;
    // MICROPHONE add security component used type
    ASSERT_EQ(RET_SUCCESS, PrivacyKit::AddPermissionUsedRecord(info));

    std::vector<PermissionUsedTypeInfo> results1;
    ASSERT_EQ(RET_SUCCESS, PrivacyKit::GetPermissionUsedTypeInfos(0, "ohos.permission.CAMERA", results1));
    // result1 size may more than one
    for (const auto& result : results1) {
        if (g_tokenIdA == result.tokenId) {
            ASSERT_EQ(PermissionUsedType::NORMAL_TYPE, result.type); // g_tokenIdA only normal type
        }
    }

    std::vector<PermissionUsedTypeInfo> results2;
    ASSERT_EQ(RET_SUCCESS, PrivacyKit::GetPermissionUsedTypeInfos(0, "ohos.permission.LOCATION", results2));
    // result2 size may more than one
    for (const auto& result : results2) {
        if (g_tokenIdA == result.tokenId) {
            ASSERT_EQ(PermissionUsedType::PICKER_TYPE, result.type); // g_tokenIdA only picker type
        }
    }

    std::vector<PermissionUsedTypeInfo> results3;
    ASSERT_EQ(RET_SUCCESS, PrivacyKit::GetPermissionUsedTypeInfos(0, "ohos.permission.MICROPHONE", results3));
    // result3 size may more than one
    for (const auto& result : results3) {
        if (g_tokenIdA == result.tokenId) {
            // g_tokenIdA only security component type
            ASSERT_EQ(PermissionUsedType::SECURITY_COMPONENT_TYPE, result.type);
        }
    }
}

/**
 * @tc.name: GetPermissionUsedTypeInfos003
 * @tc.desc: Test GetPermissionUsedTypeInfos with default permissionName
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(PrivacyKitTest, GetPermissionUsedTypeInfos003, TestSize.Level1)
{
    AddPermParamInfo info;
    info.tokenId = g_tokenIdA;
    info.permissionName = "ohos.permission.CAMERA";
    info.successCount = 1;
    info.failCount = 0;
    // g_tokenIdA add normal used type
    ASSERT_EQ(RET_SUCCESS, PrivacyKit::AddPermissionUsedRecord(info));

    info.tokenId = g_tokenIdB;
    info.type = PermissionUsedType::PICKER_TYPE;
    // g_tokenIdB add picker used type
    ASSERT_EQ(RET_SUCCESS, PrivacyKit::AddPermissionUsedRecord(info));

    info.tokenId = g_tokenIdC.tokenIdExStruct.tokenID;
    info.type = PermissionUsedType::SECURITY_COMPONENT_TYPE;
    // g_tokenIdC add security component used type
    ASSERT_EQ(RET_SUCCESS, PrivacyKit::AddPermissionUsedRecord(info));

    std::string permissionName;
    std::vector<PermissionUsedTypeInfo> results1;
    ASSERT_EQ(RET_SUCCESS, PrivacyKit::GetPermissionUsedTypeInfos(g_tokenIdA, permissionName, results1));
    ASSERT_EQ(static_cast<size_t>(RESULT_NUM_ONE), results1.size()); // only g_tokenIdA
    ASSERT_EQ(g_tokenIdA, results1[FIRST_INDEX].tokenId);
    ASSERT_EQ(PermissionUsedType::NORMAL_TYPE, results1[FIRST_INDEX].type); // normal type

    std::vector<PermissionUsedTypeInfo> results2;
    ASSERT_EQ(RET_SUCCESS, PrivacyKit::GetPermissionUsedTypeInfos(g_tokenIdB, permissionName, results2));
    ASSERT_EQ(static_cast<size_t>(RESULT_NUM_ONE), results2.size()); // only g_tokenIdB
    ASSERT_EQ(g_tokenIdB, results2[FIRST_INDEX].tokenId);
    ASSERT_EQ(PermissionUsedType::PICKER_TYPE, results2[FIRST_INDEX].type); // picker type

    std::vector<PermissionUsedTypeInfo> results3;
    ASSERT_EQ(RET_SUCCESS, PrivacyKit::GetPermissionUsedTypeInfos(g_tokenIdC.tokenIdExStruct.tokenID,
        permissionName, results3));
    ASSERT_EQ(static_cast<size_t>(RESULT_NUM_ONE), results3.size()); // only g_tokenIdC
    ASSERT_EQ(g_tokenIdC.tokenIdExStruct.tokenID, results3[FIRST_INDEX].tokenId);
    ASSERT_EQ(PermissionUsedType::SECURITY_COMPONENT_TYPE, results3[FIRST_INDEX].type); // security component type
}

/**
 * @tc.name: GetPermissionUsedTypeInfos004
 * @tc.desc: Test GetPermissionUsedTypeInfos with invalid input param
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(PrivacyKitTest, GetPermissionUsedTypeInfos004, TestSize.Level1)
{
    std::vector<PermissionUsedTypeInfo> results;
    // tokenId invalid
    ASSERT_EQ(PrivacyError::ERR_TOKENID_NOT_EXIST, PrivacyKit::GetPermissionUsedTypeInfos(RANDOM_TOKENID,
        "ohos.permission.CAMERA", results));

    std::string permissionName;
    for (int32_t i = 0; i < INVALID_PERMISSIONAME_LENGTH; i++) { // 257
        permissionName.append("a");
    }

    // permissionName over length
    ASSERT_EQ(PrivacyError::ERR_PARAM_INVALID, PrivacyKit::GetPermissionUsedTypeInfos(0, permissionName, results));
    ASSERT_EQ(PrivacyError::ERR_PERMISSION_NOT_EXIST, PrivacyKit::GetPermissionUsedTypeInfos(0,
        "ohos.permission.TEST", results)); // permissionName invalid
}

/**
 * @tc.name: GetPermissionUsedTypeInfos005
 * @tc.desc: Test GetPermissionUsedTypeInfos as normal hap or system hap without PERMISSION_USED_STATE
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(PrivacyKitTest, GetPermissionUsedTypeInfos005, TestSize.Level1)
{
    EXPECT_EQ(0, SetSelfTokenID(g_tokenIdA)); // g_tokenIdA is a normal hap

    std::string permissionName;
    std::vector<PermissionUsedTypeInfo> results;
    ASSERT_EQ(PrivacyError::ERR_NOT_SYSTEM_APP, PrivacyKit::GetPermissionUsedTypeInfos(0, permissionName, results));

    AccessTokenIDEx tokenIdEx = {0};
    tokenIdEx = AccessTokenKit::AllocHapToken(g_infoParmsD, g_policyPramsD);
    ASSERT_NE(INVALID_TOKENID, tokenIdEx.tokenIDEx);
    EXPECT_EQ(0, SetSelfTokenID(tokenIdEx.tokenIDEx)); // as a system hap without PERMISSION_USED_STATE
    ASSERT_EQ(PrivacyError::ERR_PERMISSION_DENIED, PrivacyKit::GetPermissionUsedTypeInfos(
        0, permissionName, results));

    PrivacyKit::RemovePermissionUsedRecords(tokenIdEx.tokenIdExStruct.tokenID, "");
    EXPECT_EQ(0, AccessTokenKit::DeleteToken(tokenIdEx.tokenIdExStruct.tokenID)); // delete test hap
}

/*
 * @tc.name: GetPermissionUsedTypeInfos006
 * @tc.desc: PrivacyKit::GetPermissionUsedTypeInfos function test
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(PrivacyKitTest, GetPermissionUsedTypeInfos006, TestSize.Level1)
{
    uint32_t count = MAX_PERMISSION_USED_TYPE_SIZE + 1;

    // set callertoken to system app
    ASSERT_EQ(0, SetSelfTokenID(g_tokenIdC.tokenIDEx));

    // add 2001 permission used type record
    std::vector<AccessTokenID> tokenIdList;
    std::string tmpBundleName = g_infoParmsC.bundleName;

    for (uint32_t i = 0; i < count; i++) {
        std::string bundleName = tmpBundleName + std::to_string(i);
        g_infoParmsC.bundleName = bundleName;
        AccessTokenIDEx tokenIdEx = AccessTokenKit::AllocHapToken(g_infoParmsC, g_policyPramsC);
        AccessTokenID tokenId = tokenIdEx.tokenIdExStruct.tokenID;
        ASSERT_NE(tokenId, INVALID_TOKENID);
        tokenIdList.emplace_back(tokenId);

        AddPermParamInfo info;
        info.tokenId = tokenId;
        info.permissionName = "ohos.permission.CAMERA";
        info.successCount = 1;
        info.failCount = 0;
        ASSERT_EQ(RET_NO_ERROR, PrivacyKit::AddPermissionUsedRecord(info));
    }

    AccessTokenID tokenId = 0;
    std::string permissionName;
    std::vector<PermissionUsedTypeInfo> results;
    // record over size
    ASSERT_EQ(PrivacyError::ERR_OVERSIZE, PrivacyKit::GetPermissionUsedTypeInfos(tokenId, permissionName, results));

    for (const auto& id : tokenIdList) {
        PrivacyKit::RemovePermissionUsedRecords(id, "");
        ASSERT_EQ(0, AccessTokenKit::DeleteToken(id));
    }

    g_infoParmsC.bundleName = tmpBundleName;
}
