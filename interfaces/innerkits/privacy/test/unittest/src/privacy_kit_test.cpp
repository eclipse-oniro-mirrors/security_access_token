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

static PermissionStateFull g_infoManagerTestStateA = {
    .permissionName = "ohos.permission.CAMERA",
    .grantFlags = {1},
    .grantStatus = {PermissionState::PERMISSION_GRANTED},
    .isGeneral = true,
    .resDeviceID = {"local"}
};

static PermissionStateFull g_infoManagerTestStateB = {
    .permissionName = "ohos.permission.MICROPHONE",
    .grantFlags = {1},
    .grantStatus = {PermissionState::PERMISSION_GRANTED},
    .isGeneral = true,
    .resDeviceID = {"local"}
};
static HapPolicyParams g_PolicyPramsE = {
    .apl = APL_NORMAL,
    .domain = "test.domain",
    .permList = {},
    .permStateList = {g_infoManagerTestStateA, g_infoManagerTestStateB}
};
static HapInfoParams g_InfoParmsE = {
    .userID = 1,
    .bundleName = "ohos.privacy_test.bundleE",
    .instIndex = 0,
    .appIDDesc = "privacy_test.bundleE"
};

static AccessTokenID g_selfTokenId = 0;
static AccessTokenID g_TokenId_A = 0;
static AccessTokenID g_TokenId_B = 0;
static AccessTokenID g_TokenId_E = 0;


static void DeleteTestToken()
{
    AccessTokenID tokenId = AccessTokenKit::GetHapTokenID(g_InfoParmsA.userID,
                                                          g_InfoParmsA.bundleName,
                                                          g_InfoParmsA.instIndex);
    AccessTokenKit::DeleteToken(tokenId);

    tokenId = AccessTokenKit::GetHapTokenID(g_InfoParmsB.userID,
                                            g_InfoParmsB.bundleName,
                                            g_InfoParmsB.instIndex);
    AccessTokenKit::DeleteToken(tokenId);

    tokenId = AccessTokenKit::GetHapTokenID(g_InfoParmsE.userID,
                                            g_InfoParmsE.bundleName,
                                            g_InfoParmsE.instIndex);
    AccessTokenKit::DeleteToken(tokenId);
}

void PrivacyKitTest::SetUpTestCase()
{
    DeleteTestToken();
    g_selfTokenId = GetSelfTokenID();
}

void PrivacyKitTest::TearDownTestCase()
{
}

void PrivacyKitTest::SetUp()
{
    AccessTokenKit::AllocHapToken(g_InfoParmsA, g_PolicyPramsA);
    AccessTokenKit::AllocHapToken(g_InfoParmsB, g_PolicyPramsB);
    AccessTokenKit::AllocHapToken(g_InfoParmsE, g_PolicyPramsE);

    g_TokenId_A = AccessTokenKit::GetHapTokenID(g_InfoParmsA.userID,
                                                g_InfoParmsA.bundleName,
                                                g_InfoParmsA.instIndex);
    g_TokenId_B = AccessTokenKit::GetHapTokenID(g_InfoParmsB.userID,
                                                g_InfoParmsB.bundleName,
                                                g_InfoParmsB.instIndex);
    g_TokenId_E = AccessTokenKit::GetHapTokenID(g_InfoParmsE.userID,
                                                g_InfoParmsE.bundleName,
                                                g_InfoParmsE.instIndex);

    AccessTokenID tokenId = AccessTokenKit::GetHapTokenID(100, "com.ohos.permissionmanager", 0); // 100 is userID
    SetSelfTokenID(tokenId);
}

void PrivacyKitTest::TearDown()
{
    SetSelfTokenID(g_selfTokenId);
    DeleteTestToken();
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

static void SetTokenID(std::vector<HapInfoParams>& g_InfoParms_List,
    std::vector<AccessTokenID>& g_TokenId_List, int32_t number)
{
    SetSelfTokenID(g_selfTokenId);
    for (int32_t i = 0; i < number; i++) {
        HapInfoParams g_InfoParmsTmp = {
            .userID = i,
            .bundleName = "ohos.privacy_test.bundle" + std::to_string(i),
            .instIndex = i,
            .appIDDesc = "privacy_test.bundle" + std::to_string(i)
        };
        g_InfoParms_List.push_back(g_InfoParmsTmp);
        HapPolicyParams g_PolicyPramsTmp = {
            .apl = APL_NORMAL,
            .domain = "test.domain." + std::to_string(i)
        };
        AccessTokenKit::AllocHapToken(g_InfoParmsTmp, g_PolicyPramsTmp);
        AccessTokenID g_TokenId_Tmp = AccessTokenKit::GetHapTokenID(g_InfoParmsTmp.userID,
                                                                    g_InfoParmsTmp.bundleName,
                                                                    g_InfoParmsTmp.instIndex);
        g_TokenId_List.push_back(g_TokenId_Tmp);
    }
    AccessTokenID tokenId = AccessTokenKit::GetHapTokenID(100, "com.ohos.permissionmanager", 0);
    SetSelfTokenID(tokenId);
}

static void DeleteTokenID(std::vector<HapInfoParams>& g_InfoParms_List)
{
    SetSelfTokenID(g_selfTokenId);
    for (size_t i = 0; i < g_InfoParms_List.size(); i++) {
        AccessTokenID g_TokenId_Tmp = AccessTokenKit::GetHapTokenID(g_InfoParms_List[i].userID,
                                                                    g_InfoParms_List[i].bundleName,
                                                                    g_InfoParms_List[i].instIndex);
        AccessTokenKit::DeleteToken(g_TokenId_Tmp);
    }
    AccessTokenID tokenId = AccessTokenKit::GetHapTokenID(100, "com.ohos.permissionmanager", 0);
    SetSelfTokenID(tokenId);
}

/**
 * @tc.name: AddPermissionUsedRecord001
 * @tc.desc: cannot AddPermissionUsedRecord with illegal tokenId and permission.
 * @tc.type: FUNC
 * @tc.require: issueI5P4IU
 */
HWTEST_F(PrivacyKitTest, AddPermissionUsedRecord001, TestSize.Level1)
{
    ASSERT_EQ(RET_ERROR, PrivacyKit::AddPermissionUsedRecord(
        0, "ohos.permission.READ_CONTACTS", 1, 0));
    ASSERT_EQ(RET_ERROR, PrivacyKit::AddPermissionUsedRecord(g_TokenId_A, "", 1, 0));
    ASSERT_EQ(RET_ERROR, PrivacyKit::AddPermissionUsedRecord(
        g_TokenId_A, "ohos.permission.READ_CONTACTS", -1, 0));

    PermissionUsedRequest request;
    PermissionUsedResult result;
    std::vector<std::string> permissionList;
    BuildQueryRequest(g_TokenId_A, GetLocalDeviceUdid(), g_InfoParmsA.bundleName, permissionList, request);
    ASSERT_EQ(RET_NO_ERROR, PrivacyKit::GetPermissionUsedRecords(request, result));
    ASSERT_EQ(0, result.bundleRecords.size());
}

/**
 * @tc.name: AddPermissionUsedRecord002
 * @tc.desc: cannot AddPermissionUsedRecord with invalid tokenId and permission.
 * @tc.type: FUNC
 * @tc.require: issueI5P4IU
 */
HWTEST_F(PrivacyKitTest, AddPermissionUsedRecord002, TestSize.Level1)
{
    ASSERT_EQ(RET_ERROR, PrivacyKit::AddPermissionUsedRecord(g_TokenId_A, "ohos.permission.test", 1, 0));
    ASSERT_EQ(RET_ERROR, PrivacyKit::AddPermissionUsedRecord(123, "ohos.permission.CAMERA", 1, 0));
    ASSERT_EQ(RET_ERROR, PrivacyKit::AddPermissionUsedRecord(g_TokenId_A, "ohos.permission.READ_CONTACTS", 0, 0));

    PermissionUsedRequest request;
    PermissionUsedResult result;
    std::vector<std::string> permissionList;
    BuildQueryRequest(123, "", "", permissionList, request);
    ASSERT_EQ(RET_NO_ERROR, PrivacyKit::GetPermissionUsedRecords(request, result));
    ASSERT_EQ(0, result.bundleRecords.size());

    BuildQueryRequest(g_TokenId_A, GetLocalDeviceUdid(), g_InfoParmsA.bundleName, permissionList, request);
    ASSERT_EQ(RET_NO_ERROR, PrivacyKit::GetPermissionUsedRecords(request, result));
    ASSERT_EQ(0, result.bundleRecords.size());
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
    ASSERT_NE(tokenId, 0);

    delete[] perms;
    delete[] dcaps;
    delete[] acls;

    ASSERT_EQ(RET_ERROR, PrivacyKit::AddPermissionUsedRecord(
        tokenId, "ohos.permission.READ_CONTACTS", 1, 0));

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
 * @tc.require: issueI5P4IU
 */
HWTEST_F(PrivacyKitTest, AddPermissionUsedRecord004, TestSize.Level1)
{
    ASSERT_EQ(RET_NO_ERROR, PrivacyKit::AddPermissionUsedRecord(g_TokenId_A, "ohos.permission.CAMERA", 1, 0));
    ASSERT_EQ(RET_NO_ERROR, PrivacyKit::AddPermissionUsedRecord(g_TokenId_A, "ohos.permission.WRITE_CONTACTS", 0, 1));
    ASSERT_EQ(RET_NO_ERROR, PrivacyKit::AddPermissionUsedRecord(g_TokenId_A, "ohos.permission.LOCATION", 1, 1));

    PermissionUsedRequest request;
    PermissionUsedResult result;
    std::vector<std::string> permissionList;
    BuildQueryRequest(g_TokenId_A, GetLocalDeviceUdid(), g_InfoParmsA.bundleName, permissionList, request);
    ASSERT_EQ(RET_NO_ERROR, PrivacyKit::GetPermissionUsedRecords(request, result));

    ASSERT_EQ(1, result.bundleRecords.size());
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
    ASSERT_EQ(RET_NO_ERROR, PrivacyKit::AddPermissionUsedRecord(g_TokenId_A, "ohos.permission.CAMERA", 1, 0));
    ASSERT_EQ(RET_NO_ERROR, PrivacyKit::AddPermissionUsedRecord(g_TokenId_A, "ohos.permission.LOCATION", 0, 1));

    ASSERT_EQ(RET_NO_ERROR, PrivacyKit::AddPermissionUsedRecord(g_TokenId_B,  "ohos.permission.CAMERA", 0, 1));
    ASSERT_EQ(RET_NO_ERROR, PrivacyKit::AddPermissionUsedRecord(g_TokenId_B,  "ohos.permission.LOCATION", 1, 0));


    PermissionUsedRequest request;
    PermissionUsedResult result;
    std::vector<std::string> permissionList;
    BuildQueryRequest(g_TokenId_A, GetLocalDeviceUdid(), g_InfoParmsA.bundleName, permissionList, request);
    ASSERT_EQ(RET_NO_ERROR, PrivacyKit::GetPermissionUsedRecords(request, result));

    ASSERT_EQ(1, result.bundleRecords.size());
    CheckPermissionUsedResult(request, result, 2, 1, 1);

    BuildQueryRequest(g_TokenId_B, GetLocalDeviceUdid(), g_InfoParmsB.bundleName, permissionList, request);
    ASSERT_EQ(RET_NO_ERROR, PrivacyKit::GetPermissionUsedRecords(request, result));

    ASSERT_EQ(1, result.bundleRecords.size());
    CheckPermissionUsedResult(request, result, 2, 1, 1);
}

/**
 * @tc.name: AddPermissionUsedRecord006
 * @tc.desc: AddPermissionUsedRecord permission combine records.
 * @tc.type: FUNC
 * @tc.require: issueI5P4IU
 */
HWTEST_F(PrivacyKitTest, AddPermissionUsedRecord006, TestSize.Level1)
{
    ASSERT_EQ(RET_NO_ERROR, PrivacyKit::AddPermissionUsedRecord(g_TokenId_A, "ohos.permission.CAMERA", 1, 0));
    ASSERT_EQ(RET_NO_ERROR, PrivacyKit::AddPermissionUsedRecord(g_TokenId_A, "ohos.permission.CAMERA", 1, 0));
    ASSERT_EQ(RET_NO_ERROR, PrivacyKit::AddPermissionUsedRecord(g_TokenId_A, "ohos.permission.CAMERA", 1, 0));
    ASSERT_EQ(RET_NO_ERROR, PrivacyKit::AddPermissionUsedRecord(g_TokenId_A, "ohos.permission.CAMERA", 1, 0));

    PermissionUsedRequest request;
    PermissionUsedResult result;
    std::vector<std::string> permissionList;
    BuildQueryRequest(g_TokenId_A, GetLocalDeviceUdid(), g_InfoParmsA.bundleName, permissionList, request);
    request.flag = FLAG_PERMISSION_USAGE_DETAIL;
    ASSERT_EQ(RET_NO_ERROR, PrivacyKit::GetPermissionUsedRecords(request, result));

    ASSERT_EQ(1, result.bundleRecords.size());
    ASSERT_EQ(1, result.bundleRecords[0].permissionRecords.size());
    ASSERT_EQ(1, result.bundleRecords[0].permissionRecords[0].accessRecords.size());
    CheckPermissionUsedResult(request, result, 1, 4, 0);

    sleep(61);
    ASSERT_EQ(RET_NO_ERROR, PrivacyKit::AddPermissionUsedRecord(g_TokenId_A, "ohos.permission.CAMERA", 1, 0));
   
    ASSERT_EQ(RET_NO_ERROR, PrivacyKit::GetPermissionUsedRecords(request, result));

    ASSERT_EQ(RET_NO_ERROR, PrivacyKit::GetPermissionUsedRecords(request, result));
    ASSERT_EQ(1, result.bundleRecords.size());
    ASSERT_EQ(1, result.bundleRecords[0].permissionRecords.size());
    ASSERT_EQ(2, result.bundleRecords[0].permissionRecords[0].accessRecords.size());
    CheckPermissionUsedResult(request, result, 1, 5, 0);
}

/**
 * @tc.name: AddPermissionUsedRecord007
 * @tc.desc: AddPermissionUsedRecord user_grant permission.
 * @tc.type: FUNC
 * @tc.require: issueI5P4IU
 */
HWTEST_F(PrivacyKitTest, AddPermissionUsedRecord007, TestSize.Level1)
{
    std::vector<HapInfoParams> g_InfoParms_List;
    std::vector<AccessTokenID> g_TokenId_List;
    SetTokenID(g_InfoParms_List, g_TokenId_List, 100);
    std::vector<std::string> addPermissionList = {
        "ohos.permission.ANSWER_CALL",
        "ohos.permission.READ_CALENDAR",
    };
    for (int32_t i = 0; i < 200; i++) {
        ASSERT_EQ(RET_NO_ERROR, PrivacyKit::AddPermissionUsedRecord(g_TokenId_List[i % 100],
            addPermissionList[i % 2], 1, 0));

        PermissionUsedRequest request;
        PermissionUsedResult result;
        std::vector<std::string> permissionList;
        BuildQueryRequest(g_TokenId_List[i % 100], GetLocalDeviceUdid(),
            g_InfoParms_List[i % 100].bundleName, permissionList, request);
        request.flag = FLAG_PERMISSION_USAGE_DETAIL;
        ASSERT_EQ(RET_NO_ERROR, PrivacyKit::GetPermissionUsedRecords(request, result));
    }
    sleep(70);
    for (int32_t i = 0; i < 100; i++) {
        PermissionUsedRequest request;
        PermissionUsedResult result;
        std::vector<std::string> permissionList;
        BuildQueryRequest(g_TokenId_List[i], GetLocalDeviceUdid(),
            g_InfoParms_List[i].bundleName, permissionList, request);
        request.flag = FLAG_PERMISSION_USAGE_DETAIL;
        
        ASSERT_EQ(RET_NO_ERROR, PrivacyKit::GetPermissionUsedRecords(request, result));
        ASSERT_EQ(1, result.bundleRecords.size());
        ASSERT_EQ(1, result.bundleRecords[0].permissionRecords.size());
        ASSERT_EQ(1, result.bundleRecords[0].permissionRecords[0].accessRecords.size());
        CheckPermissionUsedResult(request, result, 1, 2, 0);
    }
    DeleteTokenID(g_InfoParms_List);
}

/**
 * @tc.name: RemovePermissionUsedRecords001
 * @tc.desc: cannot RemovePermissionUsedRecords with illegal tokenId and deviceID.
 * @tc.type: FUNC
 * @tc.require: issueI5P4IU
 */
HWTEST_F(PrivacyKitTest, RemovePermissionUsedRecords001, TestSize.Level1)
{
    ASSERT_EQ(RET_ERROR, PrivacyKit::RemovePermissionUsedRecords(0, ""));
}

/**
 * @tc.name: RemovePermissionUsedRecords002
 * @tc.desc: RemovePermissionUsedRecords with invalid tokenId and deviceID.
 * @tc.type: FUNC
 * @tc.require: issueI5P4IU
 */
HWTEST_F(PrivacyKitTest, RemovePermissionUsedRecords002, TestSize.Level1)
{
    ASSERT_EQ(RET_NO_ERROR, PrivacyKit::AddPermissionUsedRecord(g_TokenId_A, "ohos.permission.CAMERA", 1, 0));
    PermissionUsedRequest request;
    PermissionUsedResult result;
    std::vector<std::string> permissionList;
    BuildQueryRequest(g_TokenId_A, GetLocalDeviceUdid(), g_InfoParmsA.bundleName, permissionList, request);

    ASSERT_EQ(RET_NO_ERROR, PrivacyKit::RemovePermissionUsedRecords(g_TokenId_A, "invalid_device"));
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
 * @tc.require: issueI5P4IU
 */
HWTEST_F(PrivacyKitTest, RemovePermissionUsedRecords003, TestSize.Level1)
{
    ASSERT_EQ(RET_NO_ERROR, PrivacyKit::AddPermissionUsedRecord(g_TokenId_A, "ohos.permission.CAMERA", 1, 0));
    PermissionUsedRequest request;
    PermissionUsedResult result;
    std::vector<std::string> permissionList;
    BuildQueryRequest(g_TokenId_A, GetLocalDeviceUdid(), g_InfoParmsA.bundleName, permissionList, request);

    ASSERT_EQ(RET_NO_ERROR, PrivacyKit::RemovePermissionUsedRecords(g_TokenId_A, ""));
    ASSERT_EQ(RET_NO_ERROR, PrivacyKit::GetPermissionUsedRecords(request, result));
    ASSERT_EQ(0, result.bundleRecords.size());
}

/**
 * @tc.name: GetPermissionUsedRecords001
 * @tc.desc: cannot GetPermissionUsedRecords with invalid query time.
 * @tc.type: FUNC
 * @tc.require: issueI5P4IU
 */
HWTEST_F(PrivacyKitTest, GetPermissionUsedRecords001, TestSize.Level1)
{
    ASSERT_EQ(RET_NO_ERROR, PrivacyKit::AddPermissionUsedRecord(g_TokenId_A, "ohos.permission.MICROPHONE", 1, 0));
    PermissionUsedRequest request;
    PermissionUsedResult result;
    std::vector<std::string> permissionList;
    BuildQueryRequest(g_TokenId_A, GetLocalDeviceUdid(), g_InfoParmsA.bundleName, permissionList, request);
    request.beginTimeMillis = -1;
    request.endTimeMillis = -1;
    ASSERT_EQ(RET_ERROR, PrivacyKit::GetPermissionUsedRecords(request, result));

    request.beginTimeMillis = 3;
    request.endTimeMillis = 1;
    ASSERT_EQ(RET_ERROR, PrivacyKit::GetPermissionUsedRecords(request, result));

    request.flag = (PermissionUsageFlag)-1;
    ASSERT_EQ(RET_ERROR, PrivacyKit::GetPermissionUsedRecords(request, result));
}

/**
 * @tc.name: GetPermissionUsedRecords002
 * @tc.desc: cannot GetPermissionUsedRecords with valid query time.
 * @tc.type: FUNC
 * @tc.require: issueI5P4IU
 */
HWTEST_F(PrivacyKitTest, GetPermissionUsedRecords002, TestSize.Level1)
{
    ASSERT_EQ(RET_NO_ERROR, PrivacyKit::AddPermissionUsedRecord(g_TokenId_A, "ohos.permission.MICROPHONE", 1, 0));
    ASSERT_EQ(RET_NO_ERROR, PrivacyKit::AddPermissionUsedRecord(g_TokenId_A, "ohos.permission.CAMERA", 1, 0));
    ASSERT_EQ(RET_NO_ERROR, PrivacyKit::AddPermissionUsedRecord(g_TokenId_A, "ohos.permission.READ_CALENDAR", 1, 0));

    PermissionUsedRequest request;
    PermissionUsedResult result;
    std::vector<std::string> permissionList;
    // query by tokenId
    BuildQueryRequest(g_TokenId_A, "", "", permissionList, request);
    ASSERT_EQ(RET_NO_ERROR, PrivacyKit::GetPermissionUsedRecords(request, result));
    ASSERT_EQ(1, result.bundleRecords.size());
    request.deviceId = GetLocalDeviceUdid();
    request.bundleName = g_InfoParmsA.bundleName;
    CheckPermissionUsedResult(request, result, 3, 3, 0);

    // query by unmatched tokenId, deviceId and bundle Name
    BuildQueryRequest(123, GetLocalDeviceUdid(), g_InfoParmsA.bundleName, permissionList, request);
    ASSERT_EQ(RET_NO_ERROR, PrivacyKit::GetPermissionUsedRecords(request, result));
    ASSERT_EQ(0, result.bundleRecords.size());

    // query by invalid permission Name
    permissionList.clear();
    permissionList.emplace_back("invalid permission");
    BuildQueryRequest(g_TokenId_A, GetLocalDeviceUdid(), g_InfoParmsA.bundleName, permissionList, request);
    ASSERT_EQ(RET_NO_ERROR, PrivacyKit::GetPermissionUsedRecords(request, result));
    ASSERT_EQ(0, result.bundleRecords.size());
}

/**
 * @tc.name: GetPermissionUsedRecords003
 * @tc.desc: can GetPermissionUsedRecords with valid query time.
 * @tc.type: FUNC
 * @tc.require: issueI5P4IU
 */
HWTEST_F(PrivacyKitTest, GetPermissionUsedRecords003, TestSize.Level1)
{
    ASSERT_EQ(RET_NO_ERROR, PrivacyKit::AddPermissionUsedRecord(g_TokenId_A, "ohos.permission.MICROPHONE", 1, 0));
    ASSERT_EQ(RET_NO_ERROR, PrivacyKit::AddPermissionUsedRecord(g_TokenId_A, "ohos.permission.MICROPHONE", 1, 0));
    ASSERT_EQ(RET_NO_ERROR, PrivacyKit::AddPermissionUsedRecord(g_TokenId_A, "ohos.permission.MICROPHONE", 1, 0));
    ASSERT_EQ(RET_NO_ERROR, PrivacyKit::AddPermissionUsedRecord(g_TokenId_A, "ohos.permission.MICROPHONE", 1, 0));

    PermissionUsedRequest request;
    PermissionUsedResult result;
    std::vector<std::string> permissionList;
    BuildQueryRequest(g_TokenId_A, GetLocalDeviceUdid(), g_InfoParmsA.bundleName, permissionList, request);
    ASSERT_EQ(RET_NO_ERROR, PrivacyKit::GetPermissionUsedRecords(request, result));
    ASSERT_EQ(1, result.bundleRecords.size());
    CheckPermissionUsedResult(request, result, 1, 4, 0);

    ASSERT_EQ(RET_NO_ERROR, PrivacyKit::AddPermissionUsedRecord(g_TokenId_A, "ohos.permission.CAMERA", 1, 0));
    ASSERT_EQ(RET_NO_ERROR, PrivacyKit::AddPermissionUsedRecord(g_TokenId_A, "ohos.permission.READ_CALENDAR", 1, 0));
    ASSERT_EQ(RET_NO_ERROR, PrivacyKit::AddPermissionUsedRecord(g_TokenId_A, "ohos.permission.WRITE_CALENDAR", 1, 0));

    BuildQueryRequest(g_TokenId_A, GetLocalDeviceUdid(), g_InfoParmsA.bundleName, permissionList, request);
    ASSERT_EQ(RET_NO_ERROR, PrivacyKit::GetPermissionUsedRecords(request, result));
    ASSERT_EQ(1, result.bundleRecords.size());
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
    ASSERT_EQ(RET_NO_ERROR, PrivacyKit::AddPermissionUsedRecord(g_TokenId_A, "ohos.permission.CAMERA", 1, 0));
    ASSERT_EQ(RET_NO_ERROR, PrivacyKit::AddPermissionUsedRecord(g_TokenId_A, "ohos.permission.READ_CALENDAR", 1, 0));
    ASSERT_EQ(RET_NO_ERROR, PrivacyKit::AddPermissionUsedRecord(g_TokenId_B, "ohos.permission.CAMERA", 1, 0));
    ASSERT_EQ(RET_NO_ERROR, PrivacyKit::AddPermissionUsedRecord(g_TokenId_B, "ohos.permission.READ_CALENDAR", 1, 0));

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
 * @tc.require: issueI5P4IU
 */
HWTEST_F(PrivacyKitTest, GetPermissionUsedRecordsAsync001, TestSize.Level1)
{
    std::string permission = "ohos.permission.CAMERA";
    ASSERT_EQ(RET_NO_ERROR, PrivacyKit::AddPermissionUsedRecord(g_TokenId_A, permission, 1, 0));
    PermissionUsedRequest request;
    std::vector<std::string> permissionList;
    BuildQueryRequest(g_TokenId_A, GetLocalDeviceUdid(), "", permissionList, request);
    request.beginTimeMillis = -1;
    request.endTimeMillis = -1;
    OHOS::sptr<TestCallBack> callback(new TestCallBack());
    ASSERT_EQ(RET_NO_ERROR, PrivacyKit::GetPermissionUsedRecords(request, callback));
}

/**
 * @tc.name: GetPermissionUsedRecordsAsync002
 * @tc.desc: cannot GetPermissionUsedRecordsAsync with valid query time.
 * @tc.type: FUNC
 * @tc.require: issueI5P4IU
 */
HWTEST_F(PrivacyKitTest, GetPermissionUsedRecordsAsync002, TestSize.Level1)
{
    std::string permission = "ohos.permission.CAMERA";
    ASSERT_EQ(RET_NO_ERROR, PrivacyKit::AddPermissionUsedRecord(g_TokenId_A, permission, 1, 0));
    PermissionUsedRequest request;
    std::vector<std::string> permissionList;
    BuildQueryRequest(g_TokenId_A, GetLocalDeviceUdid(), "", permissionList, request);
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
 * @tc.require: issueI5NT1X issueI5P4IU
 */
HWTEST_F(PrivacyKitTest, RegisterPermActiveStatusCallback001, TestSize.Level1)
{
    std::vector<std::string> permList = {"ohos.permission.CAMERA"};

    auto callbackPtr = std::make_shared<CbCustomizeTest1>(permList);
    callbackPtr->type_ = PERM_INACTIVE;

    int32_t res = PrivacyKit::RegisterPermActiveStatusCallback(callbackPtr);

    res = PrivacyKit::StartUsingPermission(g_TokenId_E, "ohos.permission.CAMERA");
    ASSERT_EQ(RET_NO_ERROR, res);

    usleep(500000); // 500000us = 0.5s
    ASSERT_EQ(PERM_ACTIVE_IN_BACKGROUND, callbackPtr->type_);

    res = PrivacyKit::StopUsingPermission(g_TokenId_E, "ohos.permission.CAMERA");
    ASSERT_EQ(RET_NO_ERROR, res);

    usleep(500000); // 500000us = 0.5s
    ASSERT_EQ(PERM_INACTIVE, callbackPtr->type_);

    res = PrivacyKit::UnRegisterPermActiveStatusCallback(callbackPtr);
    ASSERT_EQ(RET_NO_ERROR, res);
    callbackPtr->type_ = PERM_INACTIVE;

    res = PrivacyKit::StartUsingPermission(g_TokenId_E, "ohos.permission.CAMERA");
    ASSERT_EQ(RET_NO_ERROR, res);
    ASSERT_EQ(PERM_INACTIVE, callbackPtr->type_);

    res = PrivacyKit::StopUsingPermission(g_TokenId_E, "ohos.permission.CAMERA");
    ASSERT_EQ(RET_NO_ERROR, res);
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

/**
 * @tc.name: RegisterPermActiveStatusCallback002
 * @tc.desc: RegisterPermActiveStatusCallback with valid permission.
 * @tc.type: FUNC
 * @tc.require: issueI5NT1X issueI5P4IU
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

    int32_t res = PrivacyKit::RegisterPermActiveStatusCallback(callbackPtr1);
    res = PrivacyKit::RegisterPermActiveStatusCallback(callbackPtr2);
    res = PrivacyKit::RegisterPermActiveStatusCallback(callbackPtr3);

    res = PrivacyKit::StartUsingPermission(g_TokenId_E, "ohos.permission.CAMERA");
    ASSERT_EQ(RET_NO_ERROR, res);

    usleep(500000); // 500000us = 0.5s
    ASSERT_EQ(PERM_ACTIVE_IN_BACKGROUND, callbackPtr1->type_);
    ASSERT_EQ(PERM_INACTIVE, callbackPtr2->type_);
    ASSERT_EQ(PERM_ACTIVE_IN_BACKGROUND, callbackPtr3->type_);

    res = PrivacyKit::StopUsingPermission(g_TokenId_E, "ohos.permission.CAMERA");
    ASSERT_EQ(RET_NO_ERROR, res);

    usleep(500000); // 500000us = 0.5s
    ASSERT_EQ(PERM_INACTIVE, callbackPtr1->type_);
    ASSERT_EQ(PERM_INACTIVE, callbackPtr3->type_);

    res = PrivacyKit::StartUsingPermission(g_TokenId_E, "ohos.permission.MICROPHONE");
    ASSERT_EQ(RET_NO_ERROR, res);

    usleep(500000); // 500000us = 0.5s
    ASSERT_EQ(PERM_INACTIVE, callbackPtr1->type_);
    ASSERT_EQ(PERM_ACTIVE_IN_BACKGROUND, callbackPtr2->type_);

    res = PrivacyKit::StopUsingPermission(g_TokenId_E, "ohos.permission.MICROPHONE");
    ASSERT_EQ(RET_NO_ERROR, res);

    usleep(500000); // 500000us = 0.5s
    ASSERT_EQ(PERM_INACTIVE, callbackPtr2->type_);

    res = PrivacyKit::UnRegisterPermActiveStatusCallback(callbackPtr1);
    ASSERT_EQ(RET_NO_ERROR, res);
    res = PrivacyKit::UnRegisterPermActiveStatusCallback(callbackPtr2);
    ASSERT_EQ(RET_NO_ERROR, res);
    res = PrivacyKit::UnRegisterPermActiveStatusCallback(callbackPtr3);
    ASSERT_EQ(RET_NO_ERROR, res);
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
    int32_t res = PrivacyKit::RegisterPermActiveStatusCallback(callbackPtr1);
    ASSERT_EQ(RET_NO_ERROR, res);
    res = PrivacyKit::UnRegisterPermActiveStatusCallback(callbackPtr1);
    ASSERT_EQ(RET_NO_ERROR, res);

    permList.emplace_back("ohos.permission.MICROPHONE");
    auto callbackPtr = std::make_shared<CbCustomizeTest3>(permList);
    res = PrivacyKit::RegisterPermActiveStatusCallback(callbackPtr);
    ASSERT_EQ(RET_ERROR, res);
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
            int32_t res = PrivacyKit::RegisterPermActiveStatusCallback(callbackPtr);
            ASSERT_EQ(RET_ERROR, res);
            break;
        }
        auto callbackPtr = std::make_shared<CbCustomizeTest3>(permList);
        int32_t res = PrivacyKit::RegisterPermActiveStatusCallback(callbackPtr);
        ASSERT_EQ(RET_NO_ERROR, res);
        callbackList.emplace_back(callbackPtr);
    }
    for (int32_t i = 0; i < 200; i++) { // release 200 callback
        auto callbackPtr = callbackList[i];
        int32_t res = PrivacyKit::UnRegisterPermActiveStatusCallback(callbackPtr);
        ASSERT_EQ(RET_NO_ERROR, res);
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
    int32_t res = PrivacyKit::RegisterPermActiveStatusCallback(callbackPtr);
    ASSERT_EQ(RET_ERROR, res);

    std::vector<std::string> permList1 = {"ohos.permission.INVALD", "ohos.permission.CAMERA"};
    auto callbackPtr1 = std::make_shared<CbCustomizeTest3>(permList1);
    res = PrivacyKit::RegisterPermActiveStatusCallback(callbackPtr1);
    ASSERT_EQ(RET_NO_ERROR, res);
    res = PrivacyKit::UnRegisterPermActiveStatusCallback(callbackPtr1);
    ASSERT_EQ(RET_NO_ERROR, res);
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
    int32_t res = PrivacyKit::UnRegisterPermActiveStatusCallback(callbackPtr);
    ASSERT_EQ(RET_ERROR, res);
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
    int32_t res = PrivacyKit::RegisterPermActiveStatusCallback(callbackPtr);
    ASSERT_EQ(RET_NO_ERROR, res);
    res = PrivacyKit::RegisterPermActiveStatusCallback(callbackPtr);
    ASSERT_EQ(RET_ERROR, res);
    res = PrivacyKit::UnRegisterPermActiveStatusCallback(callbackPtr);
    ASSERT_EQ(RET_NO_ERROR, res);
    res = PrivacyKit::UnRegisterPermActiveStatusCallback(callbackPtr);
    ASSERT_EQ(RET_ERROR, res);
}

/**
 * @tc.name: StartUsingPermission001
 * @tc.desc: StartUsingPermission with invalid tokenId or permission.
 * @tc.type: FUNC
 * @tc.require: issueI5NT1X issueI5P4IU
 */
HWTEST_F(PrivacyKitTest, StartUsingPermission001, TestSize.Level1)
{
    std::string permissionName = "ohos.permission.CAMERA";
    int32_t ret = PrivacyKit::StartUsingPermission(0, permissionName);
    ASSERT_EQ(RET_ERROR, ret);

    ret = PrivacyKit::StartUsingPermission(0, "permissionName");
    ASSERT_EQ(RET_ERROR, ret);
}

/**
 * @tc.name: StartUsingPermission002
 * @tc.desc: StartUsingPermission is called twice with same permission.
 * @tc.type: FUNC
 * @tc.require: issueI5NT1X issueI5P4IU
 */
HWTEST_F(PrivacyKitTest, StartUsingPermission002, TestSize.Level1)
{
    std::string permissionName = "ohos.permission.CAMERA";
    int32_t ret = PrivacyKit::StartUsingPermission(g_TokenId_E, permissionName);
    ASSERT_EQ(RET_NO_ERROR, ret);

    ret = PrivacyKit::StartUsingPermission(g_TokenId_E, permissionName);
    ASSERT_EQ(RET_ERROR, ret);

    ret = PrivacyKit::StopUsingPermission(g_TokenId_E, permissionName);
    ASSERT_EQ(RET_NO_ERROR, ret);
}


/**
 * @tc.name: StopUsingPermission003
 * @tc.desc: Add record when StopUsingPermission is called.
 * @tc.type: FUNC
 * @tc.require: issueI5NT1X issueI5P4IU
 */
HWTEST_F(PrivacyKitTest, StartUsingPermission003, TestSize.Level1)
{
    std::string permissionName = "ohos.permission.CAMERA";
    int32_t ret = PrivacyKit::StartUsingPermission(g_TokenId_E, permissionName);
    ASSERT_EQ(RET_NO_ERROR, ret);

    usleep(500000); // 500000us = 0.5s
    ret = PrivacyKit::StopUsingPermission(g_TokenId_E, permissionName);
    ASSERT_EQ(RET_NO_ERROR, ret);

    PermissionUsedRequest request;
    PermissionUsedResult result;
    std::vector<std::string> permissionList;
    BuildQueryRequest(g_TokenId_E, GetLocalDeviceUdid(), g_InfoParmsE.bundleName, permissionList, request);
    ASSERT_EQ(RET_NO_ERROR, PrivacyKit::GetPermissionUsedRecords(request, result));
    ASSERT_EQ(1, result.bundleRecords.size());
    ASSERT_EQ(g_TokenId_E, result.bundleRecords[0].tokenId);
    ASSERT_EQ(g_InfoParmsE.bundleName, result.bundleRecords[0].bundleName);
    ASSERT_EQ(1, result.bundleRecords[0].permissionRecords.size());
    ASSERT_EQ(1, result.bundleRecords[0].permissionRecords[0].accessCount);
}

/**
 * @tc.name: StartUsingPermission004
 * @tc.desc: StartUsingPermission basic functional verification
 * @tc.type: FUNC
 * @tc.require: issueI5NT1X issueI5P4IU
 */
HWTEST_F(PrivacyKitTest, StartUsingPermission004, TestSize.Level1)
{
    std::string permissionName = "ohos.permission.CAMERA";
    int32_t ret = PrivacyKit::StartUsingPermission(g_TokenId_E, permissionName);
    ASSERT_EQ(RET_NO_ERROR, ret);
    ret = PrivacyKit::StopUsingPermission(g_TokenId_E, permissionName);
    ASSERT_EQ(RET_NO_ERROR, ret);
}

/**
 * @tc.name: StartUsingPermission005
 * @tc.desc: StartUsingPermission with invalid tokenId or permission.
 * @tc.type: FUNC
 * @tc.require: issueI5NT1X issueI5P4IU
 */
HWTEST_F(PrivacyKitTest, StartUsingPermission005, TestSize.Level1)
{
    std::string permissionName = "ohos.permission.UtTestInvalidPermission";
    int32_t ret = PrivacyKit::StartUsingPermission(g_TokenId_E, permissionName);
    ASSERT_EQ(RET_ERROR, ret);
    ret = PrivacyKit::StartUsingPermission(0, "ohos.permission.CAMERA");
    ASSERT_EQ(RET_ERROR, ret);
    ret = PrivacyKit::StartUsingPermission(1, "ohos.permission.CAMERA");
    ASSERT_EQ(RET_ERROR, ret);
}

/**
 * @tc.name: StopUsingPermission001
 * @tc.desc: StopUsingPermission with invalid tokenId or permission.
 * @tc.type: FUNC
 * @tc.require: issueI5NT1X issueI5P4IU
 */
HWTEST_F(PrivacyKitTest, StopUsingPermission001, TestSize.Level1)
{
    std::string permissionName = "ohos.permission.CAMERA";
    int32_t ret = PrivacyKit::StopUsingPermission(0, permissionName);
    ASSERT_EQ(RET_ERROR, ret);
    ret = PrivacyKit::StopUsingPermission(0, "permissionName");
    ASSERT_EQ(RET_ERROR, ret);
}

/**
 * @tc.name: StopUsingPermission002
 * @tc.desc: StopUsingPermission cancel permissions that you haven't started using
 * @tc.type: FUNC
 * @tc.require: issueI5NT1X issueI5P4IU
 */
HWTEST_F(PrivacyKitTest, StopUsingPermission002, TestSize.Level1)
{
    std::string permissionName = "ohos.permission.CAMERA";
    int32_t ret = PrivacyKit::StopUsingPermission(g_TokenId_E, permissionName);
    ASSERT_EQ(RET_ERROR, ret);
}

/**
 * @tc.name: StopUsingPermission003
 * @tc.desc: StopUsingPermission invalid tokenid, permission
 * @tc.type: FUNC
 * @tc.require: issueI5NT1X issueI5P4IU
 */
HWTEST_F(PrivacyKitTest, StopUsingPermission003, TestSize.Level1)
{
    std::string permissionName = "ohos.permission.CAMERA";
    int32_t ret = PrivacyKit::StartUsingPermission(g_TokenId_E, permissionName);
    ASSERT_EQ(RET_NO_ERROR, ret);
    ret = PrivacyKit::StopUsingPermission(g_TokenId_E, "ohos.permission.uttestpermission");
    ASSERT_EQ(RET_ERROR, ret);
    ret = PrivacyKit::StopUsingPermission(0, permissionName);
    ASSERT_EQ(RET_ERROR, ret);
    ret = PrivacyKit::StopUsingPermission(g_TokenId_E, permissionName);
    ASSERT_EQ(RET_NO_ERROR, ret);
}

/**
 * @tc.name: StopUsingPermission004
 * @tc.desc: StopUsingPermission stop a use repeatedly
 * @tc.type: FUNC
 * @tc.require: issueI5NT1X issueI5P4IU
 */
HWTEST_F(PrivacyKitTest, StopUsingPermission004, TestSize.Level1)
{
    std::string permissionName = "ohos.permission.CAMERA";
    int32_t ret = PrivacyKit::StartUsingPermission(g_TokenId_E, permissionName);
    ASSERT_EQ(RET_NO_ERROR, ret);
    ret = PrivacyKit::StopUsingPermission(g_TokenId_E, permissionName);
    ASSERT_EQ(RET_NO_ERROR, ret);
    ret = PrivacyKit::StopUsingPermission(g_TokenId_E, permissionName);
    ASSERT_EQ(RET_ERROR, ret);
}