/*
 * Copyright (c) 2025-2026 Huawei Device Co., Ltd.
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

#include "access_token_monitor_test.h"

#define private public
#include "accesstoken_info_manager.h"
#include "permission_manager.h"
#include "verify_accesstoken_monitor.h"
#undef private
#include "token_setproc.h"
#include "time_util.h"

using namespace testing::ext;
using namespace OHOS;

namespace OHOS {
namespace Security {
namespace AccessToken {
namespace {
constexpr const int32_t MAX_RECORD_HAP_NUM_MAX = 512;
constexpr const int32_t MAX_RECORD_TOKENID_NUM_MAX = 80;
constexpr const int32_t MAX_REPORT_TOKENID_NUM_MAX = 40;
constexpr const int32_t VERIFY_THRESHOLD = 50;
constexpr const int32_t REPORT_THRESHOLD = 5;
constexpr const int64_t REPORT_TIME_WINDOW = 5; // 5s
constexpr const int64_t MONITOR_TIME_WINDOW = 2; // 2s
constexpr const int64_t DENIED_TIME_WINDOW = 3; // 3s
static AccessTokenID g_selfTokenId = 0;
static PermissionDef g_infoManagerTestPermDef1 = {
    .permissionName = "open the door",
    .bundleName = "accesstoken_test",
    .grantMode = 1,
    .availableLevel = APL_NORMAL,
    .provisionEnable = false,
    .distributedSceneEnable = false,
    .label = "label",
    .labelId = 1,
    .description = "open the door",
    .descriptionId = 1
};

static PermissionDef g_infoManagerTestPermDef2 = {
    .permissionName = "break the door",
    .bundleName = "accesstoken_test",
    .grantMode = 1,
    .availableLevel = APL_NORMAL,
    .provisionEnable = false,
    .distributedSceneEnable = false,
    .label = "label",
    .labelId = 1,
    .description = "break the door",
    .descriptionId = 1
};

static PermissionStatus g_infoManagerTestState1 = {
    .permissionName = "ohos.permission.REPORT_SECURITY_EVENT",
    .grantStatus = 0,
    .grantFlag = 4
};

static PermissionStatus g_infoManagerTestState2 = {
    .permissionName = "ohos.permission.securityguard.REPORT_SECURITY_INFO",
    .grantStatus = 0,
    .grantFlag = 4
};

static HapInfoParams g_infoManagerTestInfoParms = {
    .userID = 1,
    .bundleName = "accesstoken_test",
    .instIndex = 0,
    .appIDDesc = "testtesttesttest",
    .isSystemApp = false
};

static HapInfoParams g_infoManagerTestInfoParms2 = {
    .userID = 1,
    .bundleName = "accesstoken_info_manager_test2",
    .instIndex = 0,
    .appIDDesc = "testtesttesttest",
    .isSystemApp = true
};

static HapInfoParams g_infoManagerTestInfoParms3 = {
    .userID = 1,
    .bundleName = "accesstoken_test_3",
    .instIndex = 0,
    .appIDDesc = "testtesttesttest",
    .isSystemApp = false
};

static HapPolicy g_infoManagerTestPolicyPrams1 = {
    .apl = APL_SYSTEM_BASIC,
    .domain = "test.domain",
    .permList = {g_infoManagerTestPermDef1, g_infoManagerTestPermDef2},
    .permStateList = {g_infoManagerTestState1, g_infoManagerTestState2}
};
}

void AccessTokenMonitorTest::SetUpTestCase()
{
    g_selfTokenId = GetSelfTokenID();
    uint32_t hapSize = 0;
    uint32_t nativeSize = 0;
    uint32_t pefDefSize = 0;
    uint32_t dlpSize = 0;
    std::map<int32_t, TokenIdInfo> tokenIdAplMap;
    AccessTokenInfoManager::GetInstance().Init(hapSize, nativeSize, pefDefSize, dlpSize, tokenIdAplMap);
}

void AccessTokenMonitorTest::TearDownTestCase()
{
    sleep(3); // delay 3s
    SetSelfTokenID(g_selfTokenId);
}

void AccessTokenMonitorTest::SetUp()
{
    atManagerService_ = DelayedSingleton<AccessTokenManagerService>::GetInstance();
    EXPECT_NE(nullptr, atManagerService_);
    AccessTokenInfoManager::GetInstance().tokenMonitor_->monitoredHapTokenMap_.clear();
    AccessTokenInfoManager::GetInstance().tokenMonitor_->isNeedReport_ = false;
    AccessTokenInfoManager::GetInstance().tokenMonitor_->lastReportTime_ = 0;
}

void AccessTokenMonitorTest::TearDown()
{
    atManagerService_ = nullptr;
}

/**
 * @tc.name: VerifyAccessTokenTest001
 * @tc.desc: normal hap verify access token test
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(AccessTokenMonitorTest, VerifyAccessTokenTest001, TestSize.Level1)
{
    AccessTokenIDEx tokenIdEx = {0};
    std::vector<GenericValues> undefValues;
    int32_t ret = AccessTokenInfoManager::GetInstance().CreateHapTokenInfo(g_infoManagerTestInfoParms,
        g_infoManagerTestPolicyPrams1, tokenIdEx, undefValues);
    EXPECT_EQ(RET_SUCCESS, ret);
    AccessTokenID tokenId = tokenIdEx.tokenIdExStruct.tokenID;
    GTEST_LOG_(INFO) << "add hap1 token " << tokenId;
    std::shared_ptr<HapTokenInfoInner> tokenInfo;
    tokenInfo = AccessTokenInfoManager::GetInstance().GetHapTokenInfoInner(tokenId);
    EXPECT_NE(nullptr, tokenInfo);

    AccessTokenIDEx tokenIdEx2 = {0};
    ret = AccessTokenInfoManager::GetInstance().CreateHapTokenInfo(g_infoManagerTestInfoParms3,
        g_infoManagerTestPolicyPrams1, tokenIdEx2, undefValues);
    EXPECT_EQ(RET_SUCCESS, ret);
    AccessTokenID tokenId2 = tokenIdEx2.tokenIdExStruct.tokenID;
    GTEST_LOG_(INFO) << "add hap2 token " << tokenId2;
    EXPECT_NE(nullptr, AccessTokenInfoManager::GetInstance().GetHapTokenInfoInner(tokenId2));

    PermissionManager::GetInstance().GrantPermission(tokenId2, "ohos.permission.LOCATION", PERMISSION_COMPONENT_SET);

    int64_t shellTokenId = GetSelfTokenID();
    SetSelfTokenID(tokenIdEx.tokenIDEx);
    EXPECT_EQ(PERMISSION_GRANTED,
        AccessTokenInfoManager::GetInstance().VerifyAccessToken(tokenId2, "ohos.permission.LOCATION"));

    for (int32_t i = 1; i < VERIFY_THRESHOLD + 1; i++) {
        AccessTokenInfoManager::GetInstance().VerifyAccessToken(i, "ohos.permission.test");
    }

    EXPECT_EQ(PERMISSION_DENIED,
        AccessTokenInfoManager::GetInstance().VerifyAccessToken(tokenId2, "ohos.permission.LOCATION"));
    // pass denied time
    sleep(DENIED_TIME_WINDOW + 1);
    EXPECT_EQ(PERMISSION_GRANTED,
        AccessTokenInfoManager::GetInstance().VerifyAccessToken(tokenId2, "ohos.permission.LOCATION"));
    EXPECT_EQ(PERMISSION_DENIED,
        AccessTokenInfoManager::GetInstance().VerifyAccessToken(tokenId2, "ohos.permission.test"));
    EXPECT_EQ(PERMISSION_DENIED,
        AccessTokenInfoManager::GetInstance().VerifyAccessToken(123, "ohos.permission.LOCATION"));
    EXPECT_EQ(PERMISSION_DENIED,
        AccessTokenInfoManager::GetInstance().VerifyAccessToken(123, "ohos.permission.test"));

    // pass report time
    sleep(REPORT_TIME_WINDOW - DENIED_TIME_WINDOW);

    ret = AccessTokenInfoManager::GetInstance().RemoveHapTokenInfo(tokenId);
    EXPECT_EQ(RET_SUCCESS, ret);
    ret = AccessTokenInfoManager::GetInstance().RemoveHapTokenInfo(tokenId2);
    EXPECT_EQ(RET_SUCCESS, ret);
    
    GTEST_LOG_(INFO) << "remove the token info";
    SetSelfTokenID(shellTokenId);
}

/**
 * @tc.name: VerifyAccessTokenTest002
 * @tc.desc: normal hap verify access token test
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(AccessTokenMonitorTest, VerifyAccessTokenTest002, TestSize.Level1)
{
    AccessTokenIDEx tokenIdEx = {0};
    std::vector<GenericValues> undefValues;
    int32_t ret = AccessTokenInfoManager::GetInstance().CreateHapTokenInfo(g_infoManagerTestInfoParms,
        g_infoManagerTestPolicyPrams1, tokenIdEx, undefValues);
    EXPECT_EQ(RET_SUCCESS, ret);
    AccessTokenID tokenId = tokenIdEx.tokenIdExStruct.tokenID;
    GTEST_LOG_(INFO) << "add a hap token " << tokenId;

    std::shared_ptr<HapTokenInfoInner> tokenInfo;
    tokenInfo = AccessTokenInfoManager::GetInstance().GetHapTokenInfoInner(tokenId);
    EXPECT_NE(nullptr, tokenInfo);
    PermissionManager::GetInstance().GrantPermission(tokenId, "ohos.permission.LOCATION", PERMISSION_COMPONENT_SET);

    // verify accesstoken when self's tokenID is shell's tokenID
    EXPECT_EQ(PERMISSION_GRANTED,
        AccessTokenInfoManager::GetInstance().VerifyAccessToken(tokenId, "ohos.permission.LOCATION"));
    GTEST_LOG_(INFO) << "remove the token info";
    ret = AccessTokenInfoManager::GetInstance().RemoveHapTokenInfo(tokenIdEx.tokenIdExStruct.tokenID);
    EXPECT_EQ(RET_SUCCESS, ret);
    int64_t shellTokenId = GetSelfTokenID();
    SetSelfTokenID(tokenIdEx.tokenIDEx);

    // verify accesstoken caller hap is not exist
    EXPECT_EQ(PERMISSION_DENIED,
        AccessTokenInfoManager::GetInstance().VerifyAccessToken(123, "ohos.permission.LOCATION"));

    SetSelfTokenID(shellTokenId);
}

/**
 * @tc.name: VerifyAccessTokenTest003
 * @tc.desc: system hap verify access token test
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(AccessTokenMonitorTest, VerifyAccessTokenTest003, TestSize.Level1)
{
    AccessTokenIDEx tokenIdEx = {0};
    std::vector<GenericValues> undefValues;
    int32_t ret = AccessTokenInfoManager::GetInstance().CreateHapTokenInfo(g_infoManagerTestInfoParms2,
        g_infoManagerTestPolicyPrams1, tokenIdEx, undefValues);
    EXPECT_EQ(RET_SUCCESS, ret);
    AccessTokenID tokenId = tokenIdEx.tokenIdExStruct.tokenID;
    GTEST_LOG_(INFO) << "add a hap token " << tokenId;

    std::shared_ptr<HapTokenInfoInner> tokenInfo;
    tokenInfo = AccessTokenInfoManager::GetInstance().GetHapTokenInfoInner(tokenId);
    EXPECT_NE(nullptr, tokenInfo);
    

    AccessTokenIDEx tokenIdEx2 = {0};
    ret = AccessTokenInfoManager::GetInstance().CreateHapTokenInfo(g_infoManagerTestInfoParms3,
        g_infoManagerTestPolicyPrams1, tokenIdEx2, undefValues);
    EXPECT_EQ(RET_SUCCESS, ret);
    AccessTokenID tokenId2 = tokenIdEx2.tokenIdExStruct.tokenID;
    GTEST_LOG_(INFO) << "add hap2 token " << tokenId2;
    EXPECT_NE(nullptr, AccessTokenInfoManager::GetInstance().GetHapTokenInfoInner(tokenId2));

    PermissionManager::GetInstance().GrantPermission(tokenId2, "ohos.permission.LOCATION", PERMISSION_COMPONENT_SET);

    int64_t shellTokenId = GetSelfTokenID();
    SetSelfTokenID(tokenIdEx.tokenIDEx);

    EXPECT_EQ(PERMISSION_GRANTED,
        AccessTokenInfoManager::GetInstance().VerifyAccessToken(tokenId2, "ohos.permission.LOCATION"));

    for (int32_t i = 1; i < VERIFY_THRESHOLD + 1; i++) {
        AccessTokenInfoManager::GetInstance().VerifyAccessToken(i, "ohos.permission.test");
    }
    EXPECT_EQ(AccessTokenInfoManager::GetInstance().tokenMonitor_->monitoredHapTokenMap_.size(), 0);
    EXPECT_EQ(PERMISSION_GRANTED,
        AccessTokenInfoManager::GetInstance().VerifyAccessToken(tokenId2, "ohos.permission.LOCATION"));

    ret = AccessTokenInfoManager::GetInstance().RemoveHapTokenInfo(tokenId);
    EXPECT_EQ(RET_SUCCESS, ret);
    ret = AccessTokenInfoManager::GetInstance().RemoveHapTokenInfo(tokenId2);
    EXPECT_EQ(RET_SUCCESS, ret);
    GTEST_LOG_(INFO) << "remove the token info";

    SetSelfTokenID(shellTokenId);
}

static void ChecReportAmount(AccessTokenID tokenId, int32_t expectReportNum)
{
    auto& map = AccessTokenInfoManager::GetInstance().tokenMonitor_->monitoredHapTokenMap_;
    auto it = map.find(tokenId);
    ASSERT_NE(it, map.end());
    int64_t currentTimeStamp = TimeUtil::GetCurrentTimestamp();

    CJsonUnique hapTokenReportJson =
        AccessTokenInfoManager::GetInstance().tokenMonitor_->ToReportHapInfoJson(
            it->first, it->second, currentTimeStamp);
    EXPECT_NE(hapTokenReportJson, nullptr);
    CJson* extraInfoJson = GetObjFromJson(hapTokenReportJson, "extra_info");
    EXPECT_NE(extraInfoJson, nullptr);
    CJson* tokenIdArray = GetArrayFromJson(extraInfoJson, "tokenid_list");
    EXPECT_NE(tokenIdArray, nullptr);
    int32_t tokenIdSize = cJSON_GetArraySize(tokenIdArray);
    EXPECT_EQ(tokenIdSize, expectReportNum);
}

/**
 * @tc.name: VerifyAccessTokenTest004
 * @tc.desc: normal hap verify access token test
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(AccessTokenMonitorTest, VerifyAccessTokenTest004, TestSize.Level1)
{
    AccessTokenIDEx tokenIdEx = {0};
    std::vector<GenericValues> undefValues;
    int32_t ret = AccessTokenInfoManager::GetInstance().CreateHapTokenInfo(g_infoManagerTestInfoParms,
        g_infoManagerTestPolicyPrams1, tokenIdEx, undefValues);
    EXPECT_EQ(RET_SUCCESS, ret);
    AccessTokenID tokenId = tokenIdEx.tokenIdExStruct.tokenID;
    GTEST_LOG_(INFO) << "add a hap token " << tokenId;

    std::shared_ptr<HapTokenInfoInner> tokenInfo;
    tokenInfo = AccessTokenInfoManager::GetInstance().GetHapTokenInfoInner(tokenId);
    EXPECT_NE(nullptr, tokenInfo);
    PermissionManager::GetInstance().GrantPermission(tokenId, "ohos.permission.LOCATION", PERMISSION_COMPONENT_SET);
    EXPECT_EQ(PERMISSION_GRANTED,
        AccessTokenInfoManager::GetInstance().VerifyAccessToken(tokenId, "ohos.permission.LOCATION"));

    int64_t shellTokenId = GetSelfTokenID();
    SetSelfTokenID(tokenIdEx.tokenIDEx);

    for (int32_t i = 1; i < MAX_RECORD_TOKENID_NUM_MAX; i++) {
        AccessTokenInfoManager::GetInstance().VerifyAccessToken(i, "ohos.permission.test");
    }
    auto& map = AccessTokenInfoManager::GetInstance().tokenMonitor_->monitoredHapTokenMap_;
    auto it = map.find(tokenId);
    ASSERT_NE(it, map.end());
    EXPECT_EQ(it->second.verifyTokenRecords.size(), MAX_RECORD_TOKENID_NUM_MAX - 1);

    AccessTokenInfoManager::GetInstance().VerifyAccessToken(MAX_RECORD_TOKENID_NUM_MAX, "ohos.permission.test");
    EXPECT_EQ(it->second.verifyTokenRecords.size(), MAX_RECORD_TOKENID_NUM_MAX);
    AccessTokenInfoManager::GetInstance().VerifyAccessToken(MAX_RECORD_TOKENID_NUM_MAX + 1, "ohos.permission.test");
    EXPECT_EQ(it->second.verifyTokenRecords.size(), MAX_RECORD_TOKENID_NUM_MAX);

    ret = AccessTokenInfoManager::GetInstance().RemoveHapTokenInfo(tokenIdEx.tokenIdExStruct.tokenID);

    // pass report time
    sleep(REPORT_TIME_WINDOW);

    EXPECT_EQ(RET_SUCCESS, ret);
    GTEST_LOG_(INFO) << "remove the token info";
    SetSelfTokenID(shellTokenId);
}

/**
 * @tc.name: VerifyAccessTokenTest005
 * @tc.desc: normal hap verify access token test
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(AccessTokenMonitorTest, VerifyAccessTokenTest005, TestSize.Level1)
{
    AccessTokenIDEx tokenIdEx = {0};
    std::vector<GenericValues> undefValues;
    int32_t ret = AccessTokenInfoManager::GetInstance().CreateHapTokenInfo(g_infoManagerTestInfoParms,
        g_infoManagerTestPolicyPrams1, tokenIdEx, undefValues);
    EXPECT_EQ(RET_SUCCESS, ret);
    AccessTokenID tokenId = tokenIdEx.tokenIdExStruct.tokenID;
    GTEST_LOG_(INFO) << "add a hap token " << tokenId;

    std::shared_ptr<HapTokenInfoInner> tokenInfo;
    tokenInfo = AccessTokenInfoManager::GetInstance().GetHapTokenInfoInner(tokenId);
    EXPECT_NE(nullptr, tokenInfo);
    PermissionManager::GetInstance().GrantPermission(tokenId, "ohos.permission.LOCATION", PERMISSION_COMPONENT_SET);
    EXPECT_EQ(PERMISSION_GRANTED,
        AccessTokenInfoManager::GetInstance().VerifyAccessToken(tokenId, "ohos.permission.LOCATION"));

    int64_t shellTokenId = GetSelfTokenID();
    SetSelfTokenID(tokenIdEx.tokenIDEx);

    // trigger first report
    for (int32_t i = 1; i < REPORT_THRESHOLD + 2; i++) {
        AccessTokenInfoManager::GetInstance().VerifyAccessToken(i, "ohos.permission.test");
    };
    AccessTokenInfoManager::GetInstance().tokenMonitor_->monitoredHapTokenMap_.clear();

    for (int32_t i = 1; i < MAX_REPORT_TOKENID_NUM_MAX; i++) {
        AccessTokenInfoManager::GetInstance().VerifyAccessToken(i, "ohos.permission.test");
    };
    ChecReportAmount(tokenId, MAX_REPORT_TOKENID_NUM_MAX - 1);

    AccessTokenInfoManager::GetInstance().VerifyAccessToken(MAX_REPORT_TOKENID_NUM_MAX, "ohos.permission.test");
    ChecReportAmount(tokenId, MAX_REPORT_TOKENID_NUM_MAX);
    AccessTokenInfoManager::GetInstance().VerifyAccessToken(MAX_REPORT_TOKENID_NUM_MAX + 1, "ohos.permission.test");
    ChecReportAmount(tokenId, MAX_REPORT_TOKENID_NUM_MAX);

    GTEST_LOG_(INFO) << "remove the token info";
    ret = AccessTokenInfoManager::GetInstance().RemoveHapTokenInfo(tokenIdEx.tokenIdExStruct.tokenID);
    EXPECT_EQ(RET_SUCCESS, ret);

    // pass report time
    sleep(REPORT_TIME_WINDOW);
    SetSelfTokenID(shellTokenId);
}

/**
 * @tc.name: VerifyAccessTokenTest006
 * @tc.desc: normal hap verify access token test
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(AccessTokenMonitorTest, VerifyAccessTokenTest006, TestSize.Level1)
{
    HapTokenInfo baseInfo = {
        .ver = 1,
        .userID = 1,
        .bundleName = "com.ohos.access_token",
        .instIndex = 1,
        .tokenID = 0,
        .tokenAttr = 0
    };

    // record MAX_RECORD_HAP_NUM_MAX -1 times
    for (int32_t i = 0; i < MAX_RECORD_HAP_NUM_MAX -1; i++) {
        baseInfo.tokenID = i;
        AccessTokenInfoManager::GetInstance().tokenMonitor_->RecordExceptionalBehavior(
            baseInfo, i, "ohos.permissionName.test");
    }
    EXPECT_EQ(AccessTokenInfoManager::GetInstance().tokenMonitor_->monitoredHapTokenMap_.size(),
        MAX_RECORD_HAP_NUM_MAX - 1);

    // record MAX_RECORD_HAP_NUM_MAXth time
    baseInfo.tokenID = MAX_RECORD_HAP_NUM_MAX -1;
    AccessTokenInfoManager::GetInstance().tokenMonitor_->RecordExceptionalBehavior(
        baseInfo, MAX_RECORD_HAP_NUM_MAX -1, "ohos.permissionName.test");
    // wait async thread finished
    sleep(1);
    EXPECT_EQ(
        AccessTokenInfoManager::GetInstance().tokenMonitor_->monitoredHapTokenMap_.size() < MAX_RECORD_HAP_NUM_MAX,
        true);
}

/**
 * @tc.name: VerifyAccessTokenTest007
 * @tc.desc: normal hap verify access token test
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(AccessTokenMonitorTest, VerifyAccessTokenTest007, TestSize.Level1)
{
    AccessTokenIDEx tokenIdEx = {0};
    std::vector<GenericValues> undefValues;
    int32_t ret = AccessTokenInfoManager::GetInstance().CreateHapTokenInfo(g_infoManagerTestInfoParms,
        g_infoManagerTestPolicyPrams1, tokenIdEx, undefValues);
    EXPECT_EQ(RET_SUCCESS, ret);
    AccessTokenID tokenId = tokenIdEx.tokenIdExStruct.tokenID;
    std::shared_ptr<HapTokenInfoInner> tokenInfo;
    tokenInfo = AccessTokenInfoManager::GetInstance().GetHapTokenInfoInner(tokenId);
    EXPECT_NE(nullptr, tokenInfo);

    AccessTokenIDEx tokenIdEx2 = {0};
    ret = AccessTokenInfoManager::GetInstance().CreateHapTokenInfo(g_infoManagerTestInfoParms3,
        g_infoManagerTestPolicyPrams1, tokenIdEx2, undefValues);
    EXPECT_EQ(RET_SUCCESS, ret);
    AccessTokenID tokenId2 = tokenIdEx2.tokenIdExStruct.tokenID;
    GTEST_LOG_(INFO) << "add hap2 token " << tokenId2;
    EXPECT_NE(nullptr, AccessTokenInfoManager::GetInstance().GetHapTokenInfoInner(tokenId2));

    PermissionManager::GetInstance().GrantPermission(tokenId2, "ohos.permission.LOCATION", PERMISSION_COMPONENT_SET);

    int64_t shellTokenId = GetSelfTokenID();
    SetSelfTokenID(tokenIdEx.tokenIDEx);
    EXPECT_EQ(PERMISSION_GRANTED,
        AccessTokenInfoManager::GetInstance().VerifyAccessToken(tokenId2, "ohos.permission.LOCATION"));

    // record VERIFY_THRESHOLD -1 times
    for (int32_t i = 1; i < VERIFY_THRESHOLD; i++) {
        AccessTokenInfoManager::GetInstance().VerifyAccessToken(i, "ohos.permission.test");
    }

    EXPECT_EQ(PERMISSION_GRANTED,
        AccessTokenInfoManager::GetInstance().VerifyAccessToken(tokenId2, "ohos.permission.LOCATION"));
    // pass monitor time
    sleep(MONITOR_TIME_WINDOW);

    // record VERIFY_THRESHOLDth time but it is not in monitor time
    AccessTokenInfoManager::GetInstance().VerifyAccessToken(VERIFY_THRESHOLD, "ohos.permission.test");
    EXPECT_EQ(PERMISSION_GRANTED,
        AccessTokenInfoManager::GetInstance().VerifyAccessToken(tokenId2, "ohos.permission.LOCATION"));

    // pass report time
    sleep(REPORT_TIME_WINDOW - DENIED_TIME_WINDOW);

    ret = AccessTokenInfoManager::GetInstance().RemoveHapTokenInfo(tokenId);
    EXPECT_EQ(RET_SUCCESS, ret);
    ret = AccessTokenInfoManager::GetInstance().RemoveHapTokenInfo(tokenId2);
    EXPECT_EQ(RET_SUCCESS, ret);
    
    GTEST_LOG_(INFO) << "remove the token info";
    SetSelfTokenID(shellTokenId);
}

/**
 * @tc.name: VerifyAccessTokenTest008
 * @tc.desc: normal hap verify access token test
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(AccessTokenMonitorTest, VerifyAccessTokenTest008, TestSize.Level1)
{
    AccessTokenIDEx tokenIdEx = {0};
    std::vector<GenericValues> undefValues;
    int32_t ret = AccessTokenInfoManager::GetInstance().CreateHapTokenInfo(g_infoManagerTestInfoParms,
        g_infoManagerTestPolicyPrams1, tokenIdEx, undefValues);
    EXPECT_EQ(RET_SUCCESS, ret);
    AccessTokenID tokenId = tokenIdEx.tokenIdExStruct.tokenID;
    GTEST_LOG_(INFO) << "add a hap token " << tokenId;

    std::shared_ptr<HapTokenInfoInner> tokenInfo;
    tokenInfo = AccessTokenInfoManager::GetInstance().GetHapTokenInfoInner(tokenId);
    EXPECT_NE(nullptr, tokenInfo);
    PermissionManager::GetInstance().GrantPermission(tokenId, "ohos.permission.LOCATION", PERMISSION_COMPONENT_SET);
    EXPECT_EQ(PERMISSION_GRANTED,
        AccessTokenInfoManager::GetInstance().VerifyAccessToken(tokenId, "ohos.permission.LOCATION"));

    int64_t shellTokenId = GetSelfTokenID();
    SetSelfTokenID(tokenIdEx.tokenIDEx);

    // trigger first report
    for (int32_t i = 1; i < REPORT_THRESHOLD + 2; i++) {
        AccessTokenInfoManager::GetInstance().VerifyAccessToken(i, "ohos.permission.test");
    }
    AccessTokenInfoManager::GetInstance().tokenMonitor_->monitoredHapTokenMap_.clear();

    // record REPORT_THRESHOLD times
    for (int32_t i = 1; i < REPORT_THRESHOLD + 1; i++) {
        AccessTokenInfoManager::GetInstance().VerifyAccessToken(i, "ohos.permission.test");
    }
    ChecReportAmount(tokenId, REPORT_THRESHOLD);
    // pass 1st report time
    sleep(REPORT_TIME_WINDOW);

    // trigger report operation
    EXPECT_EQ(PERMISSION_DENIED,
        AccessTokenInfoManager::GetInstance().VerifyAccessToken(
            static_cast<AccessTokenID>(shellTokenId), "ohos.permission.test"));

    // record REPORT_THRESHOLD + 1 times, don't report when in second report time
    for (int32_t i = 1; i < REPORT_THRESHOLD + 2; i++) {
        AccessTokenInfoManager::GetInstance().VerifyAccessToken(i, "ohos.permission.test");
    }
    ChecReportAmount(tokenId, REPORT_THRESHOLD + 1);
    sleep(REPORT_TIME_WINDOW);
    EXPECT_EQ(PERMISSION_DENIED,
        AccessTokenInfoManager::GetInstance().VerifyAccessToken(
            static_cast<AccessTokenID>(shellTokenId), "ohos.permission.test"));

    GTEST_LOG_(INFO) << "remove the token info";
    ret = AccessTokenInfoManager::GetInstance().RemoveHapTokenInfo(tokenIdEx.tokenIdExStruct.tokenID);
    EXPECT_EQ(RET_SUCCESS, ret);

    SetSelfTokenID(shellTokenId);
}

/**
 * @tc.name: VerifyAccessTokenTest009
 * @tc.desc: two normal haps verify access token test
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(AccessTokenMonitorTest, VerifyAccessTokenTest009, TestSize.Level1)
{
    AccessTokenIDEx tokenIdEx = {0};
    std::vector<GenericValues> undefValues;
    int32_t ret = AccessTokenInfoManager::GetInstance().CreateHapTokenInfo(g_infoManagerTestInfoParms,
        g_infoManagerTestPolicyPrams1, tokenIdEx, undefValues);
    EXPECT_EQ(RET_SUCCESS, ret);
    AccessTokenID tokenId1 = tokenIdEx.tokenIdExStruct.tokenID;
    GTEST_LOG_(INFO) << "add hap1 token " << tokenId1;

    std::shared_ptr<HapTokenInfoInner> tokenInfo;
    tokenInfo = AccessTokenInfoManager::GetInstance().GetHapTokenInfoInner(tokenId1);
    EXPECT_NE(nullptr, tokenInfo);

    int64_t shellTokenId = GetSelfTokenID();
    SetSelfTokenID(tokenIdEx.tokenIDEx);

    // record REPORT_THRESHOLD times
    for (int32_t i = 1; i < REPORT_THRESHOLD + 1; i++) {
        AccessTokenInfoManager::GetInstance().VerifyAccessToken(i, "ohos.permission.test");
    }

    AccessTokenIDEx tokenIdEx2 = {0};
    ret = AccessTokenInfoManager::GetInstance().CreateHapTokenInfo(g_infoManagerTestInfoParms3,
        g_infoManagerTestPolicyPrams1, tokenIdEx2, undefValues);
    EXPECT_EQ(RET_SUCCESS, ret);
    AccessTokenID tokenId2 = tokenIdEx2.tokenIdExStruct.tokenID;
    GTEST_LOG_(INFO) << "add hap2 token " << tokenId2;

    tokenInfo = AccessTokenInfoManager::GetInstance().GetHapTokenInfoInner(tokenId2);
    EXPECT_NE(nullptr, tokenInfo);

    SetSelfTokenID(tokenIdEx2.tokenIDEx);

    // record REPORT_THRESHOLD + 1 times
    for (int32_t i = 1; i < REPORT_THRESHOLD + 2; i++) {
        AccessTokenInfoManager::GetInstance().VerifyAccessToken(i, "ohos.permission.test");
    }
    // pass 1st report time
    sleep(REPORT_TIME_WINDOW);

    // trigger report operation
    EXPECT_EQ(PERMISSION_DENIED,
        AccessTokenInfoManager::GetInstance().VerifyAccessToken(123, "ohos.permission.LOCATION"));
    sleep(1);
    EXPECT_EQ(AccessTokenInfoManager::GetInstance().tokenMonitor_->monitoredHapTokenMap_.size() < 2, true);

    EXPECT_EQ(RET_SUCCESS, ret);
    GTEST_LOG_(INFO) << "remove the token info";
    ret = AccessTokenInfoManager::GetInstance().RemoveHapTokenInfo(tokenId1);
    EXPECT_EQ(RET_SUCCESS, ret);
    ret = AccessTokenInfoManager::GetInstance().RemoveHapTokenInfo(tokenId2);
    EXPECT_EQ(RET_SUCCESS, ret);

    SetSelfTokenID(shellTokenId);
}
} // namespace AccessToken
} // namespace Security
} // namespace OHOS