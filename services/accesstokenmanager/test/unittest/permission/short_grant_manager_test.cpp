/*
 * Copyright (c) 2024-2026 Huawei Device Co., Ltd.
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

#include "short_grant_manager_test.h"

#include "access_token.h"
#include "access_token_error.h"
#include "accesstoken_info_manager.h"
#define private public
#include "short_grant_manager.h"
#undef private

using namespace testing::ext;
using namespace OHOS;

namespace OHOS {
namespace Security {
namespace AccessToken {
namespace {
static constexpr uint32_t DEFAULT_TEST_MAX_TIME = 30 * 60; // seconds
static constexpr uint32_t DEFAULT_TEST_ONCE_TIME = 10; // seconds
static std::string SHORT_TEMP_PERMISSION = "ohos.permission.SHORT_TERM_WRITE_IMAGEVIDEO";
static PermissionStatus g_permiState = {
    .permissionName = SHORT_TEMP_PERMISSION,
    .grantStatus = PermissionState::PERMISSION_DENIED,
    .grantFlag = 1
};

static HapPolicy g_policyParams = {
    .apl = APL_NORMAL,
    .domain = "test.domain",
    .permStateList = {g_permiState}
};

static HapInfoParams g_infoParms = {
    .userID = 1,
    .bundleName = "AccessTokenShortTimePermTest",
    .instIndex = 0,
    .appIDDesc = "test.bundle",
    .isSystemApp = true
};
}

void ShortGrantManagerTest::SetUpTestCase()
{
}

void ShortGrantManagerTest::TearDownTestCase()
{
}

void ShortGrantManagerTest::SetUp()
{
#ifdef EVENTHANDLER_ENABLE
    ShortGrantManager::GetInstance().InitEventHandler();
#endif
}

void ShortGrantManagerTest::TearDown()
{
    ShortGrantManager::GetInstance().maxTime_ = DEFAULT_TEST_MAX_TIME;
    ShortGrantManager::GetInstance().UnRegisterAppStopListener();
    ShortGrantManager::GetInstance().shortGrantData_.clear();
    ShortGrantManager::GetInstance().appStopCallBack_ = nullptr;
    ShortGrantManager::GetInstance().appManagerDeathCallback_ = nullptr;
}

/**
 * @tc.name: RefreshPermission001
 * @tc.desc: Verify short-term permission grant and timeout revoke.
 * @tc.type: FUNC
 * @tc.require:Issue Number
 */
HWTEST_F(ShortGrantManagerTest, RefreshPermission001, TestSize.Level0)
{
    AccessTokenIDEx tokenIdEx = {0};
    std::vector<GenericValues> undefValues;
    int32_t ret = AccessTokenInfoManager::GetInstance().CreateHapTokenInfo(g_infoParms, g_policyParams, tokenIdEx,
        undefValues);
    ASSERT_EQ(RET_SUCCESS, ret);

    AccessTokenID tokenID = tokenIdEx.tokenIdExStruct.tokenID;
    ASSERT_NE(INVALID_TOKENID, tokenID);
    uint32_t onceTime = DEFAULT_TEST_ONCE_TIME;

    ret = ShortGrantManager::GetInstance().RefreshPermission(tokenID, SHORT_TEMP_PERMISSION, onceTime);
    EXPECT_EQ(RET_SUCCESS, ret);

    EXPECT_EQ(PERMISSION_GRANTED,
        AccessTokenInfoManager::GetInstance().VerifyAccessToken(tokenID, SHORT_TEMP_PERMISSION));

    sleep(onceTime + 1);
    EXPECT_EQ(PERMISSION_DENIED,
        AccessTokenInfoManager::GetInstance().VerifyAccessToken(tokenID, SHORT_TEMP_PERMISSION));

    EXPECT_EQ(RET_SUCCESS, AccessTokenInfoManager::GetInstance().RemoveHapTokenInfo(tokenID));
}

/**
 * @tc.name: RefreshPermission002
 * @tc.desc: Verify onceTime boundary at maxTime.
 * @tc.type: FUNC
 * @tc.require:Issue Number
 */
HWTEST_F(ShortGrantManagerTest, RefreshPermission002, TestSize.Level0)
{
    const uint32_t maxTime = DEFAULT_TEST_ONCE_TIME;
    ShortGrantManager::GetInstance().maxTime_ = maxTime;
    AccessTokenIDEx tokenIdEx = {0};
    std::vector<GenericValues> undefValues;
    int32_t ret = AccessTokenInfoManager::GetInstance().CreateHapTokenInfo(g_infoParms, g_policyParams, tokenIdEx,
        undefValues);
    ASSERT_EQ(RET_SUCCESS, ret);

    AccessTokenID tokenID = tokenIdEx.tokenIdExStruct.tokenID;
    ASSERT_NE(INVALID_TOKENID, tokenID);

    // onceTime = maxTime
    ret = ShortGrantManager::GetInstance().RefreshPermission(tokenID, SHORT_TEMP_PERMISSION, maxTime);
    EXPECT_EQ(RET_SUCCESS, ret);

    sleep(maxTime - 1);
    EXPECT_EQ(PERMISSION_GRANTED,
        AccessTokenInfoManager::GetInstance().VerifyAccessToken(tokenID, SHORT_TEMP_PERMISSION));

    sleep(1 + 1);
    EXPECT_EQ(PERMISSION_DENIED,
        AccessTokenInfoManager::GetInstance().VerifyAccessToken(tokenID, SHORT_TEMP_PERMISSION));

    // onceTime = maxTime + 1
    ret = ShortGrantManager::GetInstance().RefreshPermission(tokenID, SHORT_TEMP_PERMISSION, maxTime + 1);
    EXPECT_EQ(AccessTokenError::ERR_PARAM_INVALID, ret);

    sleep(maxTime + 2);
    EXPECT_EQ(PERMISSION_DENIED,
        AccessTokenInfoManager::GetInstance().VerifyAccessToken(tokenID, SHORT_TEMP_PERMISSION));

    EXPECT_EQ(RET_SUCCESS, AccessTokenInfoManager::GetInstance().RemoveHapTokenInfo(tokenID));
}

/**
 * @tc.name: RefreshPermission003
 * @tc.desc: Verify repeated refresh within remaining time.
 * @tc.type: FUNC
 * @tc.require:Issue Number
 */
HWTEST_F(ShortGrantManagerTest, RefreshPermission003, TestSize.Level0)
{
    const uint32_t maxTime = DEFAULT_TEST_ONCE_TIME;
    ShortGrantManager::GetInstance().maxTime_ = maxTime;
    AccessTokenIDEx tokenIdEx = {0};
    std::vector<GenericValues> undefValues;
    int32_t ret = AccessTokenInfoManager::GetInstance().CreateHapTokenInfo(g_infoParms, g_policyParams, tokenIdEx,
        undefValues);
    ASSERT_EQ(RET_SUCCESS, ret);

    AccessTokenID tokenID = tokenIdEx.tokenIdExStruct.tokenID;
    ASSERT_NE(INVALID_TOKENID, tokenID);

    uint32_t onceTime = 3; // 3s: repeated refresh interval for remaining-time test.
    ret = ShortGrantManager::GetInstance().RefreshPermission(tokenID, SHORT_TEMP_PERMISSION, onceTime);
    EXPECT_EQ(RET_SUCCESS, ret);

    sleep(onceTime - 1);
    EXPECT_EQ(PERMISSION_GRANTED,
        AccessTokenInfoManager::GetInstance().VerifyAccessToken(tokenID, SHORT_TEMP_PERMISSION));

    ret = ShortGrantManager::GetInstance().RefreshPermission(tokenID, SHORT_TEMP_PERMISSION, onceTime);
    EXPECT_EQ(RET_SUCCESS, ret);

    // second set 3s
    ret = ShortGrantManager::GetInstance().RefreshPermission(tokenID, SHORT_TEMP_PERMISSION, onceTime);
    EXPECT_EQ(RET_SUCCESS, ret);

    sleep(onceTime - 1);
    EXPECT_EQ(PERMISSION_GRANTED,
        AccessTokenInfoManager::GetInstance().VerifyAccessToken(tokenID, SHORT_TEMP_PERMISSION));

    // thirdth set 3s
    ret = ShortGrantManager::GetInstance().RefreshPermission(tokenID, SHORT_TEMP_PERMISSION, onceTime);
    EXPECT_EQ(RET_SUCCESS, ret);

    sleep(onceTime - 1);
    EXPECT_EQ(PERMISSION_GRANTED,
        AccessTokenInfoManager::GetInstance().VerifyAccessToken(tokenID, SHORT_TEMP_PERMISSION));

    // fourth set 5s
    ret = ShortGrantManager::GetInstance().RefreshPermission(tokenID, SHORT_TEMP_PERMISSION, onceTime);
    EXPECT_EQ(RET_SUCCESS, ret);

    sleep(onceTime + 1);
    EXPECT_EQ(PERMISSION_DENIED,
        AccessTokenInfoManager::GetInstance().VerifyAccessToken(tokenID, SHORT_TEMP_PERMISSION));

    EXPECT_EQ(RET_SUCCESS, AccessTokenInfoManager::GetInstance().RemoveHapTokenInfo(tokenID));
}

/**
 * @tc.name: RefreshPermission004
 * @tc.desc: Verify permission revoke after app stop.
 * @tc.type: FUNC
 * @tc.require:Issue Number
 */
HWTEST_F(ShortGrantManagerTest, RefreshPermission004, TestSize.Level0)
{
    AccessTokenIDEx tokenIdEx = {0};
    std::vector<GenericValues> undefValues;
    int32_t ret = AccessTokenInfoManager::GetInstance().CreateHapTokenInfo(g_infoParms, g_policyParams, tokenIdEx,
        undefValues);
    ASSERT_EQ(RET_SUCCESS, ret);

    AccessTokenID tokenID = tokenIdEx.tokenIdExStruct.tokenID;
    ASSERT_NE(INVALID_TOKENID, tokenID);
    uint32_t onceTime = DEFAULT_TEST_ONCE_TIME;

    ret = ShortGrantManager::GetInstance().RefreshPermission(tokenID, SHORT_TEMP_PERMISSION, onceTime);
    EXPECT_EQ(RET_SUCCESS, ret);

    EXPECT_EQ(PERMISSION_GRANTED,
        AccessTokenInfoManager::GetInstance().VerifyAccessToken(tokenID, SHORT_TEMP_PERMISSION));

    if (appStateObserver_ == nullptr) {
        appStateObserver_ = sptr<ShortPermAppStateObserver>::MakeSptr();
        AppStateData appStateData;
        appStateData.state = static_cast<int32_t>(ApplicationState::APP_STATE_TERMINATED);
        appStateData.accessTokenId = tokenID;
        appStateObserver_->OnAppStopped(appStateData);

        EXPECT_EQ(PERMISSION_DENIED,
            AccessTokenInfoManager::GetInstance().VerifyAccessToken(tokenID, SHORT_TEMP_PERMISSION));

        EXPECT_EQ(RET_SUCCESS, AccessTokenInfoManager::GetInstance().RemoveHapTokenInfo(tokenID));
    }
}

/**
 * @tc.name: RefreshPermission005
 * @tc.desc: Verify invalid RefreshPermission input handling.
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(ShortGrantManagerTest, RefreshPermission005, TestSize.Level0)
{
    constexpr AccessTokenID invalidTokenID = 123; // 123: non-existent tokenID for invalid input test.
    constexpr uint32_t exceededOnceTime = 5 * 60 + 1; // seconds, exceed default single grant upper bound.
    EXPECT_EQ(AccessTokenError::ERR_PARAM_INVALID,
        ShortGrantManager::GetInstance().RefreshPermission(0, SHORT_TEMP_PERMISSION, DEFAULT_TEST_ONCE_TIME));
    EXPECT_EQ(AccessTokenError::ERR_PARAM_INVALID,
        ShortGrantManager::GetInstance().RefreshPermission(invalidTokenID, SHORT_TEMP_PERMISSION, 0));
    EXPECT_EQ(AccessTokenError::ERR_PARAM_INVALID,
        ShortGrantManager::GetInstance().RefreshPermission(invalidTokenID, SHORT_TEMP_PERMISSION, exceededOnceTime));
}

/**
 * @tc.name: RefreshPermission006
 * @tc.desc: Verify unsupported permission is rejected.
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(ShortGrantManagerTest, RefreshPermission006, TestSize.Level0)
{
    AccessTokenIDEx tokenIdEx = {0};
    std::vector<GenericValues> undefValues;
    int32_t ret = AccessTokenInfoManager::GetInstance().CreateHapTokenInfo(g_infoParms, g_policyParams, tokenIdEx,
        undefValues);
    ASSERT_EQ(RET_SUCCESS, ret);

    AccessTokenID tokenID = tokenIdEx.tokenIdExStruct.tokenID;
    ASSERT_NE(INVALID_TOKENID, tokenID);

    ret = ShortGrantManager::GetInstance().RefreshPermission(tokenID, "ohos.permission.CAMERA", DEFAULT_TEST_ONCE_TIME);
    EXPECT_EQ(AccessTokenError::ERR_PARAM_INVALID, ret);
    EXPECT_TRUE(ShortGrantManager::GetInstance().shortGrantData_.empty());

    EXPECT_EQ(RET_SUCCESS, AccessTokenInfoManager::GetInstance().RemoveHapTokenInfo(tokenID));
}

/**
 * @tc.name: RefreshPermission007
 * @tc.desc: Verify refresh uses remaining max time after revoke expiry.
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(ShortGrantManagerTest, RefreshPermission007, TestSize.Level0)
{
    constexpr uint32_t initialExpiredOnceTime = 2; // 2s: initial onceTime before forcing expiry.
    constexpr uint32_t shortRetryOnceTime = 3; // 3s: retry onceTime for remaining-time refresh test.
    const uint32_t maxTime = 4; // 4s: small maxTime window for remaining-time branch test.
    ShortGrantManager::GetInstance().maxTime_ = maxTime;
    AccessTokenIDEx tokenIdEx = {0};
    std::vector<GenericValues> undefValues;
    int32_t ret = AccessTokenInfoManager::GetInstance().CreateHapTokenInfo(g_infoParms, g_policyParams, tokenIdEx,
        undefValues);
    ASSERT_EQ(RET_SUCCESS, ret);

    AccessTokenID tokenID = tokenIdEx.tokenIdExStruct.tokenID;
    ASSERT_NE(INVALID_TOKENID, tokenID);

    ret = ShortGrantManager::GetInstance().RefreshPermission(tokenID, SHORT_TEMP_PERMISSION, initialExpiredOnceTime);
    EXPECT_EQ(RET_SUCCESS, ret);
    EXPECT_EQ(1, static_cast<int32_t>(ShortGrantManager::GetInstance().shortGrantData_.size()));

    uint32_t currentTime = ShortGrantManager::GetInstance().GetCurrentTime();
    ShortGrantManager::GetInstance().shortGrantData_[0].firstGrantTimes = currentTime - shortRetryOnceTime;
    ShortGrantManager::GetInstance().shortGrantData_[0].revokeTimes = currentTime - 1;

    ret = ShortGrantManager::GetInstance().RefreshPermission(tokenID, SHORT_TEMP_PERMISSION, shortRetryOnceTime);
    EXPECT_EQ(RET_SUCCESS, ret);
    EXPECT_EQ(PERMISSION_GRANTED,
        AccessTokenInfoManager::GetInstance().VerifyAccessToken(tokenID, SHORT_TEMP_PERMISSION));

    sleep(2);
    EXPECT_EQ(PERMISSION_DENIED,
        AccessTokenInfoManager::GetInstance().VerifyAccessToken(tokenID, SHORT_TEMP_PERMISSION));

    EXPECT_EQ(RET_SUCCESS, AccessTokenInfoManager::GetInstance().RemoveHapTokenInfo(tokenID));
}

/**
 * @tc.name: IsShortGrantPermission001
 * @tc.desc: Verify short grant permission identification.
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(ShortGrantManagerTest, IsShortGrantPermission001, TestSize.Level1)
{
    EXPECT_TRUE(ShortGrantManager::GetInstance().IsShortGrantPermission(SHORT_TEMP_PERMISSION));
    EXPECT_FALSE(ShortGrantManager::GetInstance().IsShortGrantPermission("ohos.permission.CAMERA"));
}

/**
 * @tc.name: OnAppStopped001
 * @tc.desc: Verify non-terminated app state keeps short grant data.
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(ShortGrantManagerTest, OnAppStopped001, TestSize.Level1)
{
    PermTimerData data = {
        .tokenID = 2024, // 2024: in-memory tokenID for observer branch test.
        .permissionName = SHORT_TEMP_PERMISSION,
        .firstGrantTimes = 1, // 1s: mock first grant time for in-memory observer test.
        .revokeTimes = 11 // 11s: mock revoke time for in-memory observer test.
    };
    ShortGrantManager::GetInstance().shortGrantData_.emplace_back(data);

    AppStateData appStateData;
    appStateData.state = static_cast<int32_t>(ApplicationState::APP_STATE_CREATE);
    appStateData.accessTokenId = data.tokenID;
    ShortPermAppStateObserver observer;
    observer.OnAppStopped(appStateData);

    ASSERT_EQ(1, static_cast<int32_t>(ShortGrantManager::GetInstance().shortGrantData_.size()));
    EXPECT_EQ(data.tokenID, ShortGrantManager::GetInstance().shortGrantData_[0].tokenID);
}

/**
 * @tc.name: OnAppMgrRemoteDiedHandle001
 * @tc.desc: Verify app manager death clears one short grant record.
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(ShortGrantManagerTest, OnAppMgrRemoteDiedHandle001, TestSize.Level0)
{
    AccessTokenIDEx tokenIdEx = {0};
    std::vector<GenericValues> undefValues;
    int32_t ret = AccessTokenInfoManager::GetInstance().CreateHapTokenInfo(g_infoParms, g_policyParams, tokenIdEx,
        undefValues);
    ASSERT_EQ(RET_SUCCESS, ret);

    AccessTokenID tokenID = tokenIdEx.tokenIdExStruct.tokenID;
    ASSERT_NE(INVALID_TOKENID, tokenID);
    ret = ShortGrantManager::GetInstance().RefreshPermission(tokenID, SHORT_TEMP_PERMISSION, DEFAULT_TEST_ONCE_TIME);
    EXPECT_EQ(RET_SUCCESS, ret);
    EXPECT_FALSE(ShortGrantManager::GetInstance().shortGrantData_.empty());
    ShortGrantManager::GetInstance().appStopCallBack_ = sptr<ShortPermAppStateObserver>::MakeSptr();

    ShortGrantManager::GetInstance().OnAppMgrRemoteDiedHandle();

    EXPECT_TRUE(ShortGrantManager::GetInstance().shortGrantData_.empty());
    EXPECT_EQ(nullptr, ShortGrantManager::GetInstance().appStopCallBack_);
    EXPECT_EQ(PERMISSION_DENIED,
        AccessTokenInfoManager::GetInstance().VerifyAccessToken(tokenID, SHORT_TEMP_PERMISSION));

    EXPECT_EQ(RET_SUCCESS, AccessTokenInfoManager::GetInstance().RemoveHapTokenInfo(tokenID));
}

/**
 * @tc.name: NotifyAppManagerDeath001
 * @tc.desc: Verify NotifyAppManagerDeath clears short grant data.
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(ShortGrantManagerTest, NotifyAppManagerDeath001, TestSize.Level0)
{
    AccessTokenIDEx tokenIdEx = {0};
    std::vector<GenericValues> undefValues;
    int32_t ret = AccessTokenInfoManager::GetInstance().CreateHapTokenInfo(g_infoParms, g_policyParams, tokenIdEx,
        undefValues);
    ASSERT_EQ(RET_SUCCESS, ret);

    AccessTokenID tokenID = tokenIdEx.tokenIdExStruct.tokenID;
    ASSERT_NE(INVALID_TOKENID, tokenID);

    ret = ShortGrantManager::GetInstance().RefreshPermission(tokenID, SHORT_TEMP_PERMISSION, DEFAULT_TEST_ONCE_TIME);
    EXPECT_EQ(RET_SUCCESS, ret);
    EXPECT_FALSE(ShortGrantManager::GetInstance().shortGrantData_.empty());

    ShortPermAppManagerDeathCallback callback;
    callback.NotifyAppManagerDeath();

    EXPECT_TRUE(ShortGrantManager::GetInstance().shortGrantData_.empty());
    EXPECT_EQ(PERMISSION_DENIED,
        AccessTokenInfoManager::GetInstance().VerifyAccessToken(tokenID, SHORT_TEMP_PERMISSION));

    EXPECT_EQ(RET_SUCCESS, AccessTokenInfoManager::GetInstance().RemoveHapTokenInfo(tokenID));
}
/**
 * @tc.name: ClearShortPermissionData001
 * @tc.desc: Verify clearing non-existent short grant data keeps records unchanged.
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(ShortGrantManagerTest, ClearShortPermissionData001, TestSize.Level1)
{
    PermTimerData dataOne = {
        .tokenID = 3001, // 3001: first in-memory tokenID for data retention test.
        .permissionName = SHORT_TEMP_PERMISSION,
        .firstGrantTimes = 1, // 1s: mock first grant time for in-memory data retention test.
        .revokeTimes = 10 // 10s: mock revoke time for first in-memory record.
    };
    PermTimerData dataTwo = {
        .tokenID = 3002, // 3002: second in-memory tokenID for data retention test.
        .permissionName = SHORT_TEMP_PERMISSION,
        .firstGrantTimes = 2, // 2s: mock first grant time for second in-memory record.
        .revokeTimes = 11 // 11s: mock revoke time for second in-memory data retention test.
    };
    ShortGrantManager::GetInstance().shortGrantData_.emplace_back(dataOne);
    ShortGrantManager::GetInstance().shortGrantData_.emplace_back(dataTwo);

    ShortGrantManager::GetInstance().ClearShortPermissionData(9999, SHORT_TEMP_PERMISSION);

    ASSERT_EQ(2, static_cast<int32_t>(ShortGrantManager::GetInstance().shortGrantData_.size()));
    EXPECT_EQ(dataOne.tokenID, ShortGrantManager::GetInstance().shortGrantData_[0].tokenID);
    EXPECT_EQ(dataTwo.tokenID, ShortGrantManager::GetInstance().shortGrantData_[1].tokenID);
}

/**
 * @tc.name: ClearShortPermissionData002
 * @tc.desc: Verify ClearShortPermissionData removes only target record.
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(ShortGrantManagerTest, ClearShortPermissionData002, TestSize.Level0)
{
    AccessTokenIDEx tokenIdExOne = {0};
    AccessTokenIDEx tokenIdExTwo = {0};
    HapInfoParams infoParmsOne = g_infoParms;
    HapInfoParams infoParmsTwo = g_infoParms;
    infoParmsTwo.bundleName = "AccessTokenShortTimePermTest_002";
    infoParmsTwo.appIDDesc = "test.bundle.002";
    infoParmsTwo.instIndex = 1;
    std::vector<GenericValues> undefValues;
    int32_t ret = AccessTokenInfoManager::GetInstance().CreateHapTokenInfo(infoParmsOne, g_policyParams, tokenIdExOne,
        undefValues);
    ASSERT_EQ(RET_SUCCESS, ret);
    ret = AccessTokenInfoManager::GetInstance().CreateHapTokenInfo(infoParmsTwo, g_policyParams, tokenIdExTwo,
        undefValues);
    ASSERT_EQ(RET_SUCCESS, ret);

    AccessTokenID tokenIDOne = tokenIdExOne.tokenIdExStruct.tokenID;
    AccessTokenID tokenIDTwo = tokenIdExTwo.tokenIdExStruct.tokenID;
    ASSERT_NE(INVALID_TOKENID, tokenIDOne);
    ASSERT_NE(INVALID_TOKENID, tokenIDTwo);

    ret = ShortGrantManager::GetInstance().RefreshPermission(tokenIDOne, SHORT_TEMP_PERMISSION, DEFAULT_TEST_ONCE_TIME);
    EXPECT_EQ(RET_SUCCESS, ret);
    ret = ShortGrantManager::GetInstance().RefreshPermission(tokenIDTwo, SHORT_TEMP_PERMISSION, DEFAULT_TEST_ONCE_TIME);
    EXPECT_EQ(RET_SUCCESS, ret);
    EXPECT_EQ(2, static_cast<int32_t>(ShortGrantManager::GetInstance().shortGrantData_.size()));

    ShortGrantManager::GetInstance().ClearShortPermissionData(tokenIDOne, SHORT_TEMP_PERMISSION);

    EXPECT_EQ(1, static_cast<int32_t>(ShortGrantManager::GetInstance().shortGrantData_.size()));
    EXPECT_EQ(tokenIDTwo, ShortGrantManager::GetInstance().shortGrantData_[0].tokenID);
    EXPECT_NE(nullptr, ShortGrantManager::GetInstance().appStopCallBack_);
    EXPECT_EQ(PERMISSION_DENIED,
        AccessTokenInfoManager::GetInstance().VerifyAccessToken(tokenIDOne, SHORT_TEMP_PERMISSION));
    EXPECT_EQ(PERMISSION_GRANTED,
        AccessTokenInfoManager::GetInstance().VerifyAccessToken(tokenIDTwo, SHORT_TEMP_PERMISSION));

    EXPECT_EQ(RET_SUCCESS, AccessTokenInfoManager::GetInstance().RemoveHapTokenInfo(tokenIDOne));
    EXPECT_EQ(RET_SUCCESS, AccessTokenInfoManager::GetInstance().RemoveHapTokenInfo(tokenIDTwo));
}

/**
 * @tc.name: ClearShortPermissionByTokenID001
 * @tc.desc: Verify ClearShortPermissionByTokenID removes matching token data.
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(ShortGrantManagerTest, ClearShortPermissionByTokenID001, TestSize.Level0)
{
    AccessTokenIDEx tokenIdExOne = {0};
    AccessTokenIDEx tokenIdExTwo = {0};
    HapInfoParams infoParmsOne = g_infoParms;
    HapInfoParams infoParmsTwo = g_infoParms;
    infoParmsTwo.bundleName = "AccessTokenShortTimePermTest_003";
    infoParmsTwo.appIDDesc = "test.bundle.003";
    infoParmsTwo.instIndex = 1;
    std::vector<GenericValues> undefValues;
    int32_t ret = AccessTokenInfoManager::GetInstance().CreateHapTokenInfo(infoParmsOne, g_policyParams, tokenIdExOne,
        undefValues);
    ASSERT_EQ(RET_SUCCESS, ret);
    ret = AccessTokenInfoManager::GetInstance().CreateHapTokenInfo(infoParmsTwo, g_policyParams, tokenIdExTwo,
        undefValues);
    ASSERT_EQ(RET_SUCCESS, ret);

    AccessTokenID tokenIDOne = tokenIdExOne.tokenIdExStruct.tokenID;
    AccessTokenID tokenIDTwo = tokenIdExTwo.tokenIdExStruct.tokenID;
    ASSERT_NE(INVALID_TOKENID, tokenIDOne);
    ASSERT_NE(INVALID_TOKENID, tokenIDTwo);

    ret = ShortGrantManager::GetInstance().RefreshPermission(tokenIDOne, SHORT_TEMP_PERMISSION, DEFAULT_TEST_ONCE_TIME);
    EXPECT_EQ(RET_SUCCESS, ret);
    ret = ShortGrantManager::GetInstance().RefreshPermission(tokenIDTwo, SHORT_TEMP_PERMISSION, DEFAULT_TEST_ONCE_TIME);
    EXPECT_EQ(RET_SUCCESS, ret);
    EXPECT_EQ(2, static_cast<int32_t>(ShortGrantManager::GetInstance().shortGrantData_.size()));

    ShortGrantManager::GetInstance().ClearShortPermissionByTokenID(tokenIDTwo);

    EXPECT_EQ(1, static_cast<int32_t>(ShortGrantManager::GetInstance().shortGrantData_.size()));
    EXPECT_EQ(tokenIDOne, ShortGrantManager::GetInstance().shortGrantData_[0].tokenID);
    EXPECT_EQ(PERMISSION_GRANTED,
        AccessTokenInfoManager::GetInstance().VerifyAccessToken(tokenIDOne, SHORT_TEMP_PERMISSION));
    EXPECT_EQ(PERMISSION_DENIED,
        AccessTokenInfoManager::GetInstance().VerifyAccessToken(tokenIDTwo, SHORT_TEMP_PERMISSION));

    EXPECT_EQ(RET_SUCCESS, AccessTokenInfoManager::GetInstance().RemoveHapTokenInfo(tokenIDOne));
    EXPECT_EQ(RET_SUCCESS, AccessTokenInfoManager::GetInstance().RemoveHapTokenInfo(tokenIDTwo));
}

/**
 * @tc.name: UnRegisterAppStopListener001
 * @tc.desc: Verify UnRegisterAppStopListener handles null callback.
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(ShortGrantManagerTest, UnRegisterAppStopListener001, TestSize.Level1)
{
    ShortGrantManager::GetInstance().appStopCallBack_ = nullptr;
    ShortGrantManager::GetInstance().UnRegisterAppStopListener();
    EXPECT_EQ(nullptr, ShortGrantManager::GetInstance().appStopCallBack_);
}

/**
 * @tc.name: OnAppMgrRemoteDiedHandle002
 * @tc.desc: Verify app manager death clears multiple short grant records.
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(ShortGrantManagerTest, OnAppMgrRemoteDiedHandle002, TestSize.Level0)
{
    AccessTokenIDEx tokenIdExOne = {0};
    AccessTokenIDEx tokenIdExTwo = {0};
    HapInfoParams infoParmsOne = g_infoParms;
    HapInfoParams infoParmsTwo = g_infoParms;
    infoParmsTwo.bundleName = "AccessTokenShortTimePermTest_004";
    infoParmsTwo.appIDDesc = "test.bundle.004";
    infoParmsTwo.instIndex = 1;
    std::vector<GenericValues> undefValues;
    int32_t ret = AccessTokenInfoManager::GetInstance().CreateHapTokenInfo(infoParmsOne, g_policyParams, tokenIdExOne,
        undefValues);
    ASSERT_EQ(RET_SUCCESS, ret);
    ret = AccessTokenInfoManager::GetInstance().CreateHapTokenInfo(infoParmsTwo, g_policyParams, tokenIdExTwo,
        undefValues);
    ASSERT_EQ(RET_SUCCESS, ret);

    AccessTokenID tokenIDOne = tokenIdExOne.tokenIdExStruct.tokenID;
    AccessTokenID tokenIDTwo = tokenIdExTwo.tokenIdExStruct.tokenID;
    ASSERT_NE(INVALID_TOKENID, tokenIDOne);
    ASSERT_NE(INVALID_TOKENID, tokenIDTwo);

    ret = ShortGrantManager::GetInstance().RefreshPermission(tokenIDOne, SHORT_TEMP_PERMISSION, DEFAULT_TEST_ONCE_TIME);
    EXPECT_EQ(RET_SUCCESS, ret);
    ret = ShortGrantManager::GetInstance().RefreshPermission(tokenIDTwo, SHORT_TEMP_PERMISSION, DEFAULT_TEST_ONCE_TIME);
    EXPECT_EQ(RET_SUCCESS, ret);
    EXPECT_EQ(2, static_cast<int32_t>(ShortGrantManager::GetInstance().shortGrantData_.size()));

    ShortGrantManager::GetInstance().OnAppMgrRemoteDiedHandle();

    EXPECT_TRUE(ShortGrantManager::GetInstance().shortGrantData_.empty());
    EXPECT_EQ(PERMISSION_DENIED,
        AccessTokenInfoManager::GetInstance().VerifyAccessToken(tokenIDOne, SHORT_TEMP_PERMISSION));
    EXPECT_EQ(PERMISSION_DENIED,
        AccessTokenInfoManager::GetInstance().VerifyAccessToken(tokenIDTwo, SHORT_TEMP_PERMISSION));

    EXPECT_EQ(RET_SUCCESS, AccessTokenInfoManager::GetInstance().RemoveHapTokenInfo(tokenIDOne));
    EXPECT_EQ(RET_SUCCESS, AccessTokenInfoManager::GetInstance().RemoveHapTokenInfo(tokenIDTwo));
}

/**
 * @tc.name: ClearShortPermissionByTokenID002
 * @tc.desc: Verify non-matching token does not clear short grant data.
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(ShortGrantManagerTest, ClearShortPermissionByTokenID002, TestSize.Level1)
{
    AccessTokenIDEx tokenIdEx = {0};
    std::vector<GenericValues> undefValues;
    int32_t ret = AccessTokenInfoManager::GetInstance().CreateHapTokenInfo(g_infoParms, g_policyParams, tokenIdEx,
        undefValues);
    ASSERT_EQ(RET_SUCCESS, ret);

    AccessTokenID tokenID = tokenIdEx.tokenIdExStruct.tokenID;
    ASSERT_NE(INVALID_TOKENID, tokenID);

    ret = ShortGrantManager::GetInstance().RefreshPermission(tokenID, SHORT_TEMP_PERMISSION, DEFAULT_TEST_ONCE_TIME);
    EXPECT_EQ(RET_SUCCESS, ret);
    EXPECT_EQ(1, static_cast<int32_t>(ShortGrantManager::GetInstance().shortGrantData_.size()));

    constexpr AccessTokenID invalidTokenID = 1001; // 1001: tokenID not created in this test.
    ShortGrantManager::GetInstance().ClearShortPermissionByTokenID(invalidTokenID);

    EXPECT_EQ(1, static_cast<int32_t>(ShortGrantManager::GetInstance().shortGrantData_.size()));
    EXPECT_EQ(tokenID, ShortGrantManager::GetInstance().shortGrantData_[0].tokenID);
    EXPECT_EQ(PERMISSION_GRANTED,
        AccessTokenInfoManager::GetInstance().VerifyAccessToken(tokenID, SHORT_TEMP_PERMISSION));

    EXPECT_EQ(RET_SUCCESS, AccessTokenInfoManager::GetInstance().RemoveHapTokenInfo(tokenID));
}
} // namespace AccessToken
} // namespace Security
} // namespace OHOS
