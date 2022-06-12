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

#include "privacy_kit_test.h"

#include "accesstoken_kit.h"
#include "nativetoken_kit.h"
#include "parameter.h"
#include "privacy_kit.h"
#include "token_setproc.h"

using namespace testing::ext;
using namespace OHOS::Security::AccessToken;

const static int32_t RET_NO_ERROR = 0;
const static int32_t RET_ERROR = -1;

static HapPolicyParams g_PolicyPramsTest = {
    .apl = APL_NORMAL,
    .domain = "test.domain.privacy",
};

static HapInfoParams g_InfoParmsTest = {
    .userID = 1,
    .bundleName = "ohos.privacy_test.privacy",
    .instIndex = 0,
    .appIDDesc = "privacy_test.privacy"
};

static PermissionStateFull g_grantPermissionReq = {
    .permissionName = "ohos.permission.PERMISSION_USED_STATS",
    .isGeneral = true,
    .resDeviceID = {"device"},
    .grantStatus = {PermissionState::PERMISSION_GRANTED},
    .grantFlags = {PermissionFlag::PERMISSION_SYSTEM_FIXED}
};

static HapPolicyParams g_PolicyPramsA = {
    .apl = APL_NORMAL,
    .domain = "test.domain.A",
};

static HapInfoParams g_InfoParmsA = {
    .userID = 1,
    .bundleName = "ohos.privacy_test.bundleA",
    .instIndex = 0,
    .appIDDesc = "privacy_test.bundleA"
};

static HapPolicyParams g_PolicyPramsB = {
    .apl = APL_NORMAL,
    .domain = "test.domain.B",
};

static HapInfoParams g_InfoParmsB = {
    .userID = 1,
    .bundleName = "ohos.privacy_test.bundleB",
    .instIndex = 0,
    .appIDDesc = "privacy_test.bundleB"
};

void PrivacyKitTest::SetUpTestCase()
{
    uint64_t tokenId;
    const char **perms = new const char *[1];
    perms[0] = "ohos.permission.PERMISSION_USED_STATS";
    NativeTokenInfoParams infoInstance = {
        .dcapsNum = 0,
        .permsNum = 1,
        .aclsNum = 0,
        .dcaps = nullptr,
        .perms = perms,
        .acls = nullptr,
        .processName = "PrivacyKitTest",
        .aplStr = "system_core",
    };
    tokenId = GetAccessTokenId(&infoInstance);
    SetSelfTokenID(tokenId);

    GTEST_LOG_(INFO) << "tokenId :" << tokenId << ", type: " << AccessTokenKit::GetTokenTypeFlag(tokenId);
    delete[] perms;
}

void PrivacyKitTest::TearDownTestCase()
{
}

void PrivacyKitTest::SetUp()
{
    AccessTokenKit::AllocHapToken(g_InfoParmsA, g_PolicyPramsA);
    AccessTokenKit::AllocHapToken(g_InfoParmsB, g_PolicyPramsB);
}

void PrivacyKitTest::TearDown()
{
    AccessTokenID tokenId = AccessTokenKit::GetHapTokenID(g_InfoParmsA.userID,
                                                          g_InfoParmsA.bundleName,
                                                          g_InfoParmsA.instIndex);
    AccessTokenKit::DeleteToken(tokenId);

    tokenId = AccessTokenKit::GetHapTokenID(g_InfoParmsB.userID,
                                            g_InfoParmsB.bundleName,
                                            g_InfoParmsB.instIndex);
    AccessTokenKit::DeleteToken(tokenId);
}

std::string PrivacyKitTest::GetLocalDeviceUdid()
{
    const int32_t DEVICE_UUID_LENGTH = 65;
    char udid[DEVICE_UUID_LENGTH] = {0};
    GetDevUdid(udid, DEVICE_UUID_LENGTH);
    return udid;
}

void PrivacyKitTest::BuildQueryRequest(AccessTokenID tokenId, const std::string deviceId, const std::string& bundleName,
    const std::vector<std::string> permissionList, PermissionUsedRequest& request)
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
    ASSERT_EQ(permRecordSize, result.bundleRecords[0].permissionRecords.size());
    for (int32_t i = 0; i < permRecordSize; i++) {
        successCount += result.bundleRecords[0].permissionRecords[i].accessCount;
        failCount += result.bundleRecords[0].permissionRecords[i].rejectCount;
    }
    ASSERT_EQ(totalSuccessCount, successCount);
    ASSERT_EQ(totalFailCount, failCount);
}

/**
 * @tc.name: AddPermissionUsedRecord001
 * @tc.desc: cannot AddPermissionUsedRecord with illegal tokenId and permission.
 * @tc.type: FUNC
 * @tc.require:Issue Number
 */
HWTEST_F(PrivacyKitTest, AddPermissionUsedRecord001, TestSize.Level1)
{
    int32_t successCount = 1;
    int32_t failCount = 0;
    AccessTokenID tokenId = AccessTokenKit::GetHapTokenID(g_InfoParmsA.userID,
                                                          g_InfoParmsA.bundleName,
                                                          g_InfoParmsA.instIndex);
    ASSERT_NE(0, tokenId);
    ASSERT_EQ(RET_ERROR, PrivacyKit::AddPermissionUsedRecord(
        0, "ohos.permission.READ_CONTACTS", successCount, failCount));
    ASSERT_EQ(RET_ERROR, PrivacyKit::AddPermissionUsedRecord(tokenId, "", successCount, failCount));
    ASSERT_EQ(RET_ERROR, PrivacyKit::AddPermissionUsedRecord(
        tokenId, "ohos.permission.READ_CONTACTS", -1, failCount));

    PermissionUsedRequest request;
    PermissionUsedResult result;
    std::vector<std::string> permissionList;
    BuildQueryRequest(tokenId, GetLocalDeviceUdid(), g_InfoParmsA.bundleName, permissionList, request);
    ASSERT_EQ(RET_NO_ERROR, PrivacyKit::GetPermissionUsedRecords(request, result));
    ASSERT_EQ(0, result.bundleRecords.size());
}

/**
 * @tc.name: AddPermissionUsedRecord002
 * @tc.desc: cannot AddPermissionUsedRecord with invalid tokenId and permission.
 * @tc.type: FUNC
 * @tc.require:Issue Number
 */
HWTEST_F(PrivacyKitTest, AddPermissionUsedRecord002, TestSize.Level1)
{
    int32_t successCount = 1;
    int32_t failCount = 0;
    AccessTokenID tokenId = AccessTokenKit::GetHapTokenID(g_InfoParmsA.userID,
                                                          g_InfoParmsA.bundleName,
                                                          g_InfoParmsA.instIndex);
    ASSERT_NE(0, tokenId);
    
    ASSERT_EQ(RET_ERROR, PrivacyKit::AddPermissionUsedRecord(
        tokenId, "ohos.permission.test", successCount, failCount));
    ASSERT_EQ(RET_ERROR, PrivacyKit::AddPermissionUsedRecord(123, "ohos.permission.CAMERA", successCount, failCount));
    ASSERT_EQ(RET_ERROR, PrivacyKit::AddPermissionUsedRecord(tokenId, "ohos.permission.READ_CONTACTS", 0, 0));

    PermissionUsedRequest request;
    PermissionUsedResult result;
    std::vector<std::string> permissionList;
    BuildQueryRequest(123, "", "", permissionList, request);
    ASSERT_EQ(RET_NO_ERROR, PrivacyKit::GetPermissionUsedRecords(request, result));
    ASSERT_EQ(0, result.bundleRecords.size());

    BuildQueryRequest(tokenId, GetLocalDeviceUdid(), g_InfoParmsA.bundleName, permissionList, request);
    ASSERT_EQ(RET_NO_ERROR, PrivacyKit::GetPermissionUsedRecords(request, result));
    ASSERT_EQ(0, result.bundleRecords.size());
}

/**
 * @tc.name: AddPermissionUsedRecord003
 * @tc.desc: cannot AddPermissionUsedRecord with native tokenId.
 * @tc.type: FUNC
 * @tc.require:Issue Number
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
    ASSERT_NE(tokenId, 0);

    delete[] perms;
    delete[] dcaps;
    delete[] acls;

    int32_t successCount = 1;
    int32_t failCount = 0;
    ASSERT_EQ(RET_NO_ERROR, PrivacyKit::AddPermissionUsedRecord(
        tokenId, "ohos.permission.READ_CONTACTS", successCount, failCount));

    PermissionUsedRequest request;
    PermissionUsedResult result;
    std::vector<std::string> permissionList;
    BuildQueryRequest(tokenId, "", "", permissionList, request);

    ASSERT_EQ(RET_NO_ERROR, PrivacyKit::GetPermissionUsedRecords(request, result));
    ASSERT_EQ(0, result.bundleRecords.size());
}

/**
 * @tc.name: AddPermissionUsedRecord004
 * @tc.desc: AddPermissionUsedRecord user_grant permission.
 * @tc.type: FUNC
 * @tc.require:Issue Number
 */
HWTEST_F(PrivacyKitTest, AddPermissionUsedRecord004, TestSize.Level1)
{
    int32_t count_0 = 0;
    int32_t count_1 = 1;
    AccessTokenID tokenId = AccessTokenKit::GetHapTokenID(g_InfoParmsA.userID,
                                                          g_InfoParmsA.bundleName,
                                                          g_InfoParmsA.instIndex);
    ASSERT_NE(0, tokenId);
    ASSERT_EQ(RET_NO_ERROR, PrivacyKit::AddPermissionUsedRecord(tokenId, "ohos.permission.CAMERA", count_1, count_0));
    ASSERT_EQ(RET_NO_ERROR, PrivacyKit::AddPermissionUsedRecord(
        tokenId, "ohos.permission.WRITE_CONTACTS", count_0, count_1));
    ASSERT_EQ(RET_NO_ERROR, PrivacyKit::AddPermissionUsedRecord(tokenId, "ohos.permission.LOCATION", count_1, count_1));

    PermissionUsedRequest request;
    PermissionUsedResult result;
    std::vector<std::string> permissionList;
    BuildQueryRequest(tokenId, GetLocalDeviceUdid(), g_InfoParmsA.bundleName, permissionList, request);
    ASSERT_EQ(RET_NO_ERROR, PrivacyKit::GetPermissionUsedRecords(request, result));

    ASSERT_EQ(1, result.bundleRecords.size());
    CheckPermissionUsedResult(request, result, 3, 2, 2);
}

/**
 * @tc.name: AddPermissionUsedRecord005
 * @tc.desc: AddPermissionUsedRecord user_grant permission.
 * @tc.type: FUNC
 * @tc.require:Issue Number
 */
HWTEST_F(PrivacyKitTest, AddPermissionUsedRecord005, TestSize.Level1)
{
    int32_t count_0 = 0;
    int32_t count_1 = 1;
    AccessTokenID tokenId1 = AccessTokenKit::GetHapTokenID(g_InfoParmsA.userID,
                                                          g_InfoParmsA.bundleName,
                                                          g_InfoParmsA.instIndex);
    ASSERT_NE(0, tokenId1);
    ASSERT_EQ(RET_NO_ERROR, PrivacyKit::AddPermissionUsedRecord(tokenId1, "ohos.permission.CAMERA", count_1, count_0));
    ASSERT_EQ(RET_NO_ERROR, PrivacyKit::AddPermissionUsedRecord(
        tokenId1, "ohos.permission.LOCATION", count_0, count_1));

    AccessTokenID tokenId2 = AccessTokenKit::GetHapTokenID(g_InfoParmsB.userID,
                                            g_InfoParmsB.bundleName,
                                            g_InfoParmsB.instIndex);
    ASSERT_NE(0, tokenId2);
    ASSERT_EQ(RET_NO_ERROR, PrivacyKit::AddPermissionUsedRecord(tokenId2,  "ohos.permission.CAMERA", count_0, count_1));
    ASSERT_EQ(RET_NO_ERROR, PrivacyKit::AddPermissionUsedRecord(
        tokenId2,  "ohos.permission.LOCATION", count_1, count_0));


    PermissionUsedRequest request;
    PermissionUsedResult result;
    std::vector<std::string> permissionList;
    BuildQueryRequest(tokenId1, GetLocalDeviceUdid(), g_InfoParmsA.bundleName, permissionList, request);
    ASSERT_EQ(RET_NO_ERROR, PrivacyKit::GetPermissionUsedRecords(request, result));

    ASSERT_EQ(1, result.bundleRecords.size());
    CheckPermissionUsedResult(request, result, 2, 1, 1);

    BuildQueryRequest(tokenId2, GetLocalDeviceUdid(), g_InfoParmsB.bundleName, permissionList, request);
    ASSERT_EQ(RET_NO_ERROR, PrivacyKit::GetPermissionUsedRecords(request, result));

    ASSERT_EQ(1, result.bundleRecords.size());
    CheckPermissionUsedResult(request, result, 2, 1, 1);
}

/**
 * @tc.name: AddPermissionUsedRecord006
 * @tc.desc: AddPermissionUsedRecord permission combine records.
 * @tc.type: FUNC
 * @tc.require:Issue Number
 */
HWTEST_F(PrivacyKitTest, AddPermissionUsedRecord006, TestSize.Level1)
{
    int32_t count_0 = 0;
    int32_t count_1 = 1;
    AccessTokenID tokenId = AccessTokenKit::GetHapTokenID(g_InfoParmsA.userID,
                                                          g_InfoParmsA.bundleName,
                                                          g_InfoParmsA.instIndex);
    ASSERT_NE(0, tokenId);
    ASSERT_EQ(RET_NO_ERROR, PrivacyKit::AddPermissionUsedRecord(tokenId, "ohos.permission.CAMERA", count_1, count_0));
    ASSERT_EQ(RET_NO_ERROR, PrivacyKit::AddPermissionUsedRecord(tokenId, "ohos.permission.CAMERA", count_1, count_0));
    ASSERT_EQ(RET_NO_ERROR, PrivacyKit::AddPermissionUsedRecord(tokenId, "ohos.permission.CAMERA", count_1, count_0));
    ASSERT_EQ(RET_NO_ERROR, PrivacyKit::AddPermissionUsedRecord(tokenId, "ohos.permission.CAMERA", count_1, count_0));

    PermissionUsedRequest request;
    PermissionUsedResult result;
    std::vector<std::string> permissionList;
    BuildQueryRequest(tokenId, GetLocalDeviceUdid(), g_InfoParmsA.bundleName, permissionList, request);
    request.flag = FLAG_PERMISSION_USAGE_DETAIL;
    ASSERT_EQ(RET_NO_ERROR, PrivacyKit::GetPermissionUsedRecords(request, result));

    ASSERT_EQ(1, result.bundleRecords.size());
    ASSERT_EQ(1, result.bundleRecords[0].permissionRecords.size());
    ASSERT_EQ(1, result.bundleRecords[0].permissionRecords[0].accessRecords.size());
    CheckPermissionUsedResult(request, result, 1, 4, 0);

    sleep(61);
    ASSERT_EQ(RET_NO_ERROR, PrivacyKit::AddPermissionUsedRecord(tokenId, "ohos.permission.CAMERA", count_1, count_0));
   
    ASSERT_EQ(RET_NO_ERROR, PrivacyKit::GetPermissionUsedRecords(request, result));

    ASSERT_EQ(RET_NO_ERROR, PrivacyKit::GetPermissionUsedRecords(request, result));
    ASSERT_EQ(1, result.bundleRecords.size());
    ASSERT_EQ(1, result.bundleRecords[0].permissionRecords.size());
    ASSERT_EQ(2, result.bundleRecords[0].permissionRecords[0].accessRecords.size());
    CheckPermissionUsedResult(request, result, 1, 5, 0);
}

/**
 * @tc.name: RemovePermissionUsedRecords001
 * @tc.desc: cannot RemovePermissionUsedRecords with illegal tokenId and deviceID.
 * @tc.type: FUNC
 * @tc.require:Issue Number
 */
HWTEST_F(PrivacyKitTest, RemovePermissionUsedRecords001, TestSize.Level1)
{
    ASSERT_EQ(RET_ERROR, PrivacyKit::RemovePermissionUsedRecords(0, ""));
}

/**
 * @tc.name: RemovePermissionUsedRecords002
 * @tc.desc: RemovePermissionUsedRecords with invalid tokenId and deviceID.
 * @tc.type: FUNC
 * @tc.require:Issue Number
 */
HWTEST_F(PrivacyKitTest, RemovePermissionUsedRecords002, TestSize.Level1)
{
    int32_t successCount = 1;
    int32_t failCount = 0;
    AccessTokenID tokenId = AccessTokenKit::GetHapTokenID(g_InfoParmsA.userID,
                                                          g_InfoParmsA.bundleName,
                                                          g_InfoParmsA.instIndex);
    ASSERT_NE(0, tokenId);
    ASSERT_EQ(RET_NO_ERROR, PrivacyKit::AddPermissionUsedRecord(
        tokenId, "ohos.permission.CAMERA", successCount, failCount));
    PermissionUsedRequest request;
    PermissionUsedResult result;
    std::vector<std::string> permissionList;
    BuildQueryRequest(tokenId, GetLocalDeviceUdid(), g_InfoParmsA.bundleName, permissionList, request);

    ASSERT_EQ(RET_NO_ERROR, PrivacyKit::RemovePermissionUsedRecords(tokenId, "invalid_device"));
    ASSERT_EQ(RET_NO_ERROR, PrivacyKit::GetPermissionUsedRecords(request, result));
    ASSERT_EQ(1, result.bundleRecords.size());

    ASSERT_EQ(RET_NO_ERROR, PrivacyKit::RemovePermissionUsedRecords(123, GetLocalDeviceUdid()));
    ASSERT_EQ(RET_NO_ERROR, PrivacyKit::GetPermissionUsedRecords(request, result));
    ASSERT_EQ(1, result.bundleRecords.size());
}

/**
 * @tc.name: RemovePermissionUsedRecords003
 * @tc.desc: RemovePermissionUsedRecords with valid tokenId and deviceID.
 * @tc.type: FUNC
 * @tc.require:Issue Number
 */
HWTEST_F(PrivacyKitTest, RemovePermissionUsedRecords003, TestSize.Level1)
{
    int32_t successCount = 1;
    int32_t failCount = 0;
    AccessTokenID tokenId = AccessTokenKit::GetHapTokenID(g_InfoParmsA.userID,
                                                          g_InfoParmsA.bundleName,
                                                          g_InfoParmsA.instIndex);
    ASSERT_NE(0, tokenId);
    ASSERT_EQ(RET_NO_ERROR, PrivacyKit::AddPermissionUsedRecord(
        tokenId, "ohos.permission.CAMERA", successCount, failCount));
    PermissionUsedRequest request;
    PermissionUsedResult result;
    std::vector<std::string> permissionList;
    BuildQueryRequest(tokenId, GetLocalDeviceUdid(), g_InfoParmsA.bundleName, permissionList, request);

    ASSERT_EQ(RET_NO_ERROR, PrivacyKit::RemovePermissionUsedRecords(tokenId, ""));
    ASSERT_EQ(RET_NO_ERROR, PrivacyKit::GetPermissionUsedRecords(request, result));
    ASSERT_EQ(0, result.bundleRecords.size());
}

/**
 * @tc.name: GetPermissionUsedRecords001
 * @tc.desc: cannot GetPermissionUsedRecords with invalid query time.
 * @tc.type: FUNC
 * @tc.require:Issue Number
 */
HWTEST_F(PrivacyKitTest, GetPermissionUsedRecords001, TestSize.Level1)
{
    int32_t successCount = 1;
    int32_t failCount = 0;
    AccessTokenID tokenId = AccessTokenKit::GetHapTokenID(g_InfoParmsA.userID,
                                                          g_InfoParmsA.bundleName,
                                                          g_InfoParmsA.instIndex);
    ASSERT_NE(0, tokenId);
    ASSERT_EQ(RET_NO_ERROR, PrivacyKit::AddPermissionUsedRecord(
        tokenId, "ohos.permission.MICROPHONE", successCount, failCount));
    PermissionUsedRequest request;
    PermissionUsedResult result;
    std::vector<std::string> permissionList;
    BuildQueryRequest(tokenId, GetLocalDeviceUdid(), g_InfoParmsA.bundleName, permissionList, request);
    request.beginTimeMillis = -1;
    request.endTimeMillis = -1;
    ASSERT_EQ(RET_ERROR, PrivacyKit::GetPermissionUsedRecords(request, result));

    request.beginTimeMillis = 3;
    request.endTimeMillis = 1;
    ASSERT_EQ(RET_ERROR, PrivacyKit::GetPermissionUsedRecords(request, result));
}

/**
 * @tc.name: GetPermissionUsedRecords002
 * @tc.desc: cannot GetPermissionUsedRecords with valid query time.
 * @tc.type: FUNC
 * @tc.require:Issue Number
 */
HWTEST_F(PrivacyKitTest, GetPermissionUsedRecords002, TestSize.Level1)
{
    int32_t successCount = 1;
    int32_t failCount = 0;
    AccessTokenID tokenId = AccessTokenKit::GetHapTokenID(g_InfoParmsA.userID,
                                                          g_InfoParmsA.bundleName,
                                                          g_InfoParmsA.instIndex);
    ASSERT_NE(0, tokenId);
    ASSERT_EQ(RET_NO_ERROR, PrivacyKit::AddPermissionUsedRecord(
        tokenId, "ohos.permission.MICROPHONE", successCount, failCount));
    ASSERT_EQ(RET_NO_ERROR, PrivacyKit::AddPermissionUsedRecord(
        tokenId, "ohos.permission.CAMERA", successCount, failCount));
    ASSERT_EQ(RET_NO_ERROR, PrivacyKit::AddPermissionUsedRecord(
        tokenId, "ohos.permission.READ_CALENDAR", successCount, failCount));

    PermissionUsedRequest request;
    PermissionUsedResult result;
    std::vector<std::string> permissionList;
    // query by tokenId
    BuildQueryRequest(tokenId, "", "", permissionList, request);
    ASSERT_EQ(RET_NO_ERROR, PrivacyKit::GetPermissionUsedRecords(request, result));
    ASSERT_EQ(1, result.bundleRecords.size());
    request.deviceId = GetLocalDeviceUdid();
    request.bundleName = g_InfoParmsA.bundleName;
    CheckPermissionUsedResult(request, result, 3, 3, 0);

    // query by deviceId and bundle Name
    BuildQueryRequest(0, GetLocalDeviceUdid(), g_InfoParmsA.bundleName, permissionList, request);
    ASSERT_EQ(RET_NO_ERROR, PrivacyKit::GetPermissionUsedRecords(request, result));
    ASSERT_EQ(1, result.bundleRecords.size());
    request.tokenId = tokenId;
    CheckPermissionUsedResult(request, result, 3, 3, 0);

    // query by unmatched tokenId, deviceId and bundle Name
    BuildQueryRequest(123, GetLocalDeviceUdid(), g_InfoParmsA.bundleName, permissionList, request);
    ASSERT_EQ(RET_NO_ERROR, PrivacyKit::GetPermissionUsedRecords(request, result));
    ASSERT_EQ(0, result.bundleRecords.size());

    // query by unmatched tokenId, deviceId and bundle Name
    BuildQueryRequest(tokenId, "local device", g_InfoParmsA.bundleName, permissionList, request);
    ASSERT_EQ(RET_NO_ERROR, PrivacyKit::GetPermissionUsedRecords(request, result));
    ASSERT_EQ(0, result.bundleRecords.size());

    // query by unmatched tokenId, deviceId and bundle Name
    BuildQueryRequest(tokenId, GetLocalDeviceUdid(), "bundleA", permissionList, request);
    ASSERT_EQ(RET_NO_ERROR, PrivacyKit::GetPermissionUsedRecords(request, result));
    ASSERT_EQ(0, result.bundleRecords.size());
}

/**
 * @tc.name: GetPermissionUsedRecords003
 * @tc.desc: cannot GetPermissionUsedRecords with valid query time.
 * @tc.type: FUNC
 * @tc.require:Issue Number
 */
HWTEST_F(PrivacyKitTest, GetPermissionUsedRecords003, TestSize.Level1)
{
    int32_t successCount = 1;
    int32_t failCount = 0;
    AccessTokenID tokenId = AccessTokenKit::GetHapTokenID(g_InfoParmsA.userID,
                                                          g_InfoParmsA.bundleName,
                                                          g_InfoParmsA.instIndex);
    ASSERT_NE(0, tokenId);
    ASSERT_EQ(RET_NO_ERROR, PrivacyKit::AddPermissionUsedRecord(
        tokenId, "ohos.permission.MICROPHONE", successCount, failCount));
    ASSERT_EQ(RET_NO_ERROR, PrivacyKit::AddPermissionUsedRecord(
        tokenId, "ohos.permission.MICROPHONE", successCount, failCount));
    ASSERT_EQ(RET_NO_ERROR, PrivacyKit::AddPermissionUsedRecord(
        tokenId, "ohos.permission.MICROPHONE", successCount, failCount));
    ASSERT_EQ(RET_NO_ERROR, PrivacyKit::AddPermissionUsedRecord(
        tokenId, "ohos.permission.MICROPHONE", successCount, failCount));

    PermissionUsedRequest request;
    PermissionUsedResult result;
    std::vector<std::string> permissionList;
    BuildQueryRequest(tokenId, GetLocalDeviceUdid(), g_InfoParmsA.bundleName, permissionList, request);
    ASSERT_EQ(RET_NO_ERROR, PrivacyKit::GetPermissionUsedRecords(request, result));
    ASSERT_EQ(1, result.bundleRecords.size());
    CheckPermissionUsedResult(request, result, 1, 4, 0);

    ASSERT_EQ(RET_NO_ERROR, PrivacyKit::AddPermissionUsedRecord(
        tokenId, "ohos.permission.CAMERA", successCount, failCount));
    ASSERT_EQ(RET_NO_ERROR, PrivacyKit::AddPermissionUsedRecord(
        tokenId, "ohos.permission.READ_CALENDAR", successCount, failCount));
    ASSERT_EQ(RET_NO_ERROR, PrivacyKit::AddPermissionUsedRecord(
        tokenId, "ohos.permission.WRITE_CALENDAR", successCount, failCount));

    BuildQueryRequest(tokenId, GetLocalDeviceUdid(), g_InfoParmsA.bundleName, permissionList, request);
    ASSERT_EQ(RET_NO_ERROR, PrivacyKit::GetPermissionUsedRecords(request, result));
    ASSERT_EQ(1, result.bundleRecords.size());
    CheckPermissionUsedResult(request, result, 4, 7, 0);
}

/**
 * @tc.name: GetPermissionUsedRecords004
 * @tc.desc: cannot GetPermissionUsedRecords with valid query time.
 * @tc.type: FUNC
 * @tc.require:Issue Number
 */
HWTEST_F(PrivacyKitTest, GetPermissionUsedRecords004, TestSize.Level1)
{
    int32_t successCount = 1;
    int32_t failCount = 0;
    AccessTokenID tokenId1 = AccessTokenKit::GetHapTokenID(g_InfoParmsA.userID,
                                                          g_InfoParmsA.bundleName,
                                                          g_InfoParmsA.instIndex);
    AccessTokenID tokenId2 = AccessTokenKit::GetHapTokenID(g_InfoParmsB.userID,
                                                          g_InfoParmsB.bundleName,
                                                          g_InfoParmsB.instIndex);
    ASSERT_EQ(RET_NO_ERROR, PrivacyKit::AddPermissionUsedRecord(
        tokenId1, "ohos.permission.CAMERA", successCount, failCount));
    ASSERT_EQ(RET_NO_ERROR, PrivacyKit::AddPermissionUsedRecord(
        tokenId1, "ohos.permission.READ_CALENDAR", successCount, failCount));
    ASSERT_EQ(RET_NO_ERROR, PrivacyKit::AddPermissionUsedRecord(
        tokenId2, "ohos.permission.CAMERA", successCount, failCount));
    ASSERT_EQ(RET_NO_ERROR, PrivacyKit::AddPermissionUsedRecord(
        tokenId2, "ohos.permission.READ_CALENDAR", successCount, failCount));

    PermissionUsedRequest request;
    PermissionUsedResult result;
    std::vector<std::string> permissionList;
    BuildQueryRequest(0, GetLocalDeviceUdid(), "", permissionList, request);

    ASSERT_EQ(RET_NO_ERROR, PrivacyKit::GetPermissionUsedRecords(request, result));
    if (result.bundleRecords.size() < 2) {
        ASSERT_EQ(RET_NO_ERROR, RET_ERROR);
    }
}

/**
 * @tc.name: GetPermissionUsedRecordsAsync001
 * @tc.desc: cannot GetPermissionUsedRecordsAsync with invalid query time.
 * @tc.type: FUNC
 * @tc.require:Issue Number
 */
HWTEST_F(PrivacyKitTest, GetPermissionUsedRecordsAsync001, TestSize.Level1)
{
    int32_t successCount = 1;
    int32_t failCount = 0;
    std::string permission = "ohos.permission.CAMERA";
    AccessTokenID tokenID = AccessTokenKit::GetHapTokenID(g_InfoParmsA.userID,
                                                          g_InfoParmsA.bundleName,
                                                          g_InfoParmsA.instIndex);
    ASSERT_EQ(RET_NO_ERROR, PrivacyKit::AddPermissionUsedRecord(tokenID, permission, successCount, failCount));
    PermissionUsedRequest request;
    std::vector<std::string> permissionList;
    BuildQueryRequest(tokenID, GetLocalDeviceUdid(), "", permissionList, request);
    request.beginTimeMillis = -1;
    request.endTimeMillis = -1;
    OHOS::sptr<TestCallBack> callback(new TestCallBack());
    ASSERT_EQ(RET_NO_ERROR, PrivacyKit::GetPermissionUsedRecords(request, callback));
}

/**
 * @tc.name: GetPermissionUsedRecordsAsync002
 * @tc.desc: cannot GetPermissionUsedRecordsAsync with valid query time.
 * @tc.type: FUNC
 * @tc.require:Issue Number
 */
HWTEST_F(PrivacyKitTest, GetPermissionUsedRecordsAsync002, TestSize.Level1)
{
    int32_t successCount = 1;
    int32_t failCount = 0;
    std::string permission = "ohos.permission.CAMERA";
    AccessTokenID tokenID = AccessTokenKit::GetHapTokenID(g_InfoParmsA.userID,
                                                          g_InfoParmsA.bundleName,
                                                          g_InfoParmsA.instIndex);
    ASSERT_EQ(RET_NO_ERROR, PrivacyKit::AddPermissionUsedRecord(tokenID, permission, successCount, failCount));
    PermissionUsedRequest request;
    std::vector<std::string> permissionList;
    BuildQueryRequest(tokenID, GetLocalDeviceUdid(), "", permissionList, request);
    OHOS::sptr<TestCallBack> callback(new TestCallBack());
    ASSERT_EQ(RET_NO_ERROR, PrivacyKit::GetPermissionUsedRecords(request, callback));
}