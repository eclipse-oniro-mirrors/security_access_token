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
}

/**
 * @tc.name: RefreshPermission001
 * @tc.desc: 1. The permission is granted when onceTime is not reached;
 *           2. The permission is revoked after onceTime is reached.
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
    uint32_t onceTime = 10;

    ret = ShortGrantManager::GetInstance().RefreshPermission(tokenID, SHORT_TEMP_PERMISSION, onceTime);
    ASSERT_EQ(RET_SUCCESS, ret);

    ASSERT_EQ(PERMISSION_GRANTED,
        AccessTokenInfoManager::GetInstance().VerifyAccessToken(tokenID, SHORT_TEMP_PERMISSION));

    sleep(onceTime + 1);
    EXPECT_EQ(PERMISSION_DENIED,
        AccessTokenInfoManager::GetInstance().VerifyAccessToken(tokenID, SHORT_TEMP_PERMISSION));

    ret = AccessTokenInfoManager::GetInstance().RemoveHapTokenInfo(tokenID);
    ASSERT_EQ(RET_SUCCESS, ret);
}

/**
 * @tc.name: RefreshPermission002
 * @tc.desc: 1. set onceTime is equal to maxTime;
 *           2. set onceTime is over maxTime.
 * @tc.type: FUNC
 * @tc.require:Issue Number
 */
HWTEST_F(ShortGrantManagerTest, RefreshPermission002, TestSize.Level0)
{
    const uint32_t maxTime = 10; // 10s
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
    ASSERT_EQ(RET_SUCCESS, ret);

    sleep(maxTime - 1);
    ASSERT_EQ(PERMISSION_GRANTED,
        AccessTokenInfoManager::GetInstance().VerifyAccessToken(tokenID, SHORT_TEMP_PERMISSION));

    sleep(1 + 1);
    ASSERT_EQ(PERMISSION_DENIED,
        AccessTokenInfoManager::GetInstance().VerifyAccessToken(tokenID, SHORT_TEMP_PERMISSION));

    // onceTime = maxTime + 1
    ret = ShortGrantManager::GetInstance().RefreshPermission(tokenID, SHORT_TEMP_PERMISSION, maxTime + 1);
    ASSERT_EQ(AccessTokenError::ERR_PARAM_INVALID, ret);

    sleep(maxTime + 2);
    ASSERT_EQ(PERMISSION_DENIED,
        AccessTokenInfoManager::GetInstance().VerifyAccessToken(tokenID, SHORT_TEMP_PERMISSION));

    ret = AccessTokenInfoManager::GetInstance().RemoveHapTokenInfo(tokenID);
    ASSERT_EQ(RET_SUCCESS, ret);
}

/**
 * @tc.name: RefreshPermission003
 * @tc.desc: 1. remaminTime is less
 * @tc.type: FUNC
 * @tc.require:Issue Number
 */
HWTEST_F(ShortGrantManagerTest, RefreshPermission003, TestSize.Level0)
{
    const uint32_t maxTime = 10; // 10s
    ShortGrantManager::GetInstance().maxTime_ = maxTime;
    AccessTokenIDEx tokenIdEx = {0};
    std::vector<GenericValues> undefValues;
    int32_t ret = AccessTokenInfoManager::GetInstance().CreateHapTokenInfo(g_infoParms, g_policyParams, tokenIdEx,
        undefValues);
    ASSERT_EQ(RET_SUCCESS, ret);

    AccessTokenID tokenID = tokenIdEx.tokenIdExStruct.tokenID;
    ASSERT_NE(INVALID_TOKENID, tokenID);

    // first set 3s
    uint32_t onceTime = 3;
    ret = ShortGrantManager::GetInstance().RefreshPermission(tokenID, SHORT_TEMP_PERMISSION, onceTime);
    ASSERT_EQ(RET_SUCCESS, ret);

    sleep(onceTime - 1);
    ASSERT_EQ(PERMISSION_GRANTED,
        AccessTokenInfoManager::GetInstance().VerifyAccessToken(tokenID, SHORT_TEMP_PERMISSION));

    ret = ShortGrantManager::GetInstance().RefreshPermission(tokenID, SHORT_TEMP_PERMISSION, onceTime);
    ASSERT_EQ(RET_SUCCESS, ret);

    // second set 3s
    ret = ShortGrantManager::GetInstance().RefreshPermission(tokenID, SHORT_TEMP_PERMISSION, onceTime);
    ASSERT_EQ(RET_SUCCESS, ret);

    sleep(onceTime - 1);
    ASSERT_EQ(PERMISSION_GRANTED,
        AccessTokenInfoManager::GetInstance().VerifyAccessToken(tokenID, SHORT_TEMP_PERMISSION));

    // thirdth set 3s
    ret = ShortGrantManager::GetInstance().RefreshPermission(tokenID, SHORT_TEMP_PERMISSION, onceTime);
    ASSERT_EQ(RET_SUCCESS, ret);

    sleep(onceTime - 1);
    ASSERT_EQ(PERMISSION_GRANTED,
        AccessTokenInfoManager::GetInstance().VerifyAccessToken(tokenID, SHORT_TEMP_PERMISSION));

    // fourth set 5s
    ret = ShortGrantManager::GetInstance().RefreshPermission(tokenID, SHORT_TEMP_PERMISSION, onceTime);
    ASSERT_EQ(RET_SUCCESS, ret);

    sleep(onceTime + 1);
    ASSERT_EQ(PERMISSION_DENIED,
        AccessTokenInfoManager::GetInstance().VerifyAccessToken(tokenID, SHORT_TEMP_PERMISSION));

    ret = AccessTokenInfoManager::GetInstance().RemoveHapTokenInfo(tokenID);
    ASSERT_EQ(RET_SUCCESS, ret);
}

/**
 * @tc.name: RefreshPermission004
 * @tc.desc: 1. The permission is granted when onceTime is not reached;
 *           2. The permission is revoked after app is stopped.
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
    uint32_t onceTime = 10;

    ret = ShortGrantManager::GetInstance().RefreshPermission(tokenID, SHORT_TEMP_PERMISSION, onceTime);
    ASSERT_EQ(RET_SUCCESS, ret);

    ASSERT_EQ(PERMISSION_GRANTED,
        AccessTokenInfoManager::GetInstance().VerifyAccessToken(tokenID, SHORT_TEMP_PERMISSION));

    if (appStateObserver_ == nullptr) {
        appStateObserver_ = sptr<ShortPermAppStateObserver>::MakeSptr();
        AppStateData appStateData;
        appStateData.state = static_cast<int32_t>(ApplicationState::APP_STATE_TERMINATED);
        appStateData.accessTokenId = tokenID;
        appStateObserver_->OnAppStopped(appStateData);

        EXPECT_EQ(PERMISSION_DENIED,
            AccessTokenInfoManager::GetInstance().VerifyAccessToken(tokenID, SHORT_TEMP_PERMISSION));

        ret = AccessTokenInfoManager::GetInstance().RemoveHapTokenInfo(tokenID);
        ASSERT_EQ(RET_SUCCESS, ret);
    }
}
} // namespace AccessToken
} // namespace Security
} // namespace OHOS
