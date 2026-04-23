/*
 * Copyright (c) 2021-2026 Huawei Device Co., Ltd.
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

#include "permission_manager_test.h"

#include "access_token.h"
#include "access_token_error.h"
#define private public
#include "accesstoken_info_manager.h"
#undef private
#define private public
#include "temp_permission_observer.h"
#undef private
#ifdef BGTASKMGR_CONTINUOUS_TASK_ENABLE
#include "continuous_task_callback_info.h"
#endif

using namespace testing::ext;
using namespace OHOS;

namespace OHOS {
namespace Security {
namespace AccessToken {
namespace {
static constexpr int32_t USER_ID = 100;

static AccessTokenID CreateTempHapTokenInfo()
{
    PermissionStatus stateA = {
        .permissionName = "ohos.permission.APPROXIMATELY_LOCATION",
        .grantStatus = PERMISSION_DENIED,
        .grantFlag = 1
    };
    PermissionStatus stateB = {
        .permissionName = "ohos.permission.READ_PASTEBOARD",
        .grantStatus = PERMISSION_DENIED,
        .grantFlag = 1
    };
    PermissionStatus stateC = {
        .permissionName = "ohos.permission.CAMERA",
        .grantStatus = PERMISSION_DENIED,
        .grantFlag = 1
    };
    PermissionStatus stateD = {
        .permissionName = "ohos.permission.MICROPHONE",
        .grantStatus = PERMISSION_DENIED,
        .grantFlag = 1
    };
    PermissionStatus stateE = {
        .permissionName = "ohos.permission.CUSTOM_SCREEN_CAPTURE",
        .grantStatus = PERMISSION_DENIED,
        .grantFlag = 1
    };
    HapPolicy policy = {
        .apl = APL_NORMAL,
        .domain = "test.domain",
        .permList = {},
        .permStateList = { stateA, stateB, stateC, stateD, stateE }
    };
    HapInfoParams info = {
        .userID = USER_ID,
        .bundleName = "GrantTempPermission",
        .instIndex = 0,
        .dlpType = DLP_COMMON,
        .appIDDesc = "GrantTempPermission"
    };
    AccessTokenIDEx tokenIdEx = {0};
    std::vector<GenericValues> undefValues;
    AccessTokenInfoManager::GetInstance().CreateHapTokenInfo(info, policy, tokenIdEx, undefValues);
    AccessTokenID tokenID = tokenIdEx.tokenIdExStruct.tokenID;
    GTEST_LOG_(INFO) << "add a hap token " << tokenID;
    return tokenID;
}

#ifdef BGTASKMGR_CONTINUOUS_TASK_ENABLE
static std::shared_ptr<ContinuousTaskCallbackInfo> CreateContinuousTaskInfo(
    AccessTokenID tokenID, int32_t continuousTaskId, std::initializer_list<BackgroundMode> modes)
{
    auto info = std::make_shared<ContinuousTaskCallbackInfo>();
    if (modes.size() > 0) {
        info->typeId_ = static_cast<uint32_t>(*modes.begin());
    }
    for (const auto& mode : modes) {
        info->typeIds_.emplace_back(static_cast<uint32_t>(mode));
    }
    info->tokenId_ = tokenID;
    info->SetContinuousTaskId(continuousTaskId);
    return info;
}
#endif
} // namespace

/**
 * @tc.name: GrantTempPermission001
 * @tc.desc: Test grant temp permission revoke permission after switching to background
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(PermissionManagerTest, GrantTempPermission001, TestSize.Level0)
{
    accessTokenService_->state_ = ServiceRunningState::STATE_RUNNING;
    accessTokenService_->Initialize();
    AccessTokenID tokenID = CreateTempHapTokenInfo();
    TempPermissionObserver::GetInstance().RegisterCallback();
    // change to foreground
    TempPermissionObserver::GetInstance().ModifyAppState(tokenID, 0, true);
    // grant temp permission
    EXPECT_EQ(RET_SUCCESS, PermissionManager::GetInstance().GrantPermission(tokenID,
        "ohos.permission.APPROXIMATELY_LOCATION", PERMISSION_ALLOW_THIS_TIME));
    EXPECT_EQ(PERMISSION_GRANTED,
        AccessTokenInfoManager::GetInstance().VerifyAccessToken(tokenID, "ohos.permission.APPROXIMATELY_LOCATION"));
    // change to background
    AppStateData appStateData;
    appStateData.state = static_cast<int32_t>(ApplicationState::APP_STATE_BACKGROUND);
    appStateData.accessTokenId = tokenID;
    appStateObserver_->OnAppStateChanged(appStateData);
    EXPECT_EQ(PERMISSION_GRANTED,
        AccessTokenInfoManager::GetInstance().VerifyAccessToken(tokenID, "ohos.permission.APPROXIMATELY_LOCATION"));
    TempPermissionObserver::GetInstance().UnRegisterCallback();
    // UnRegisterCallback twice
    TempPermissionObserver::GetInstance().UnRegisterCallback();
    // remove hap
    int32_t ret = AccessTokenInfoManager::GetInstance().RemoveHapTokenInfo(tokenID);
    ASSERT_EQ(RET_SUCCESS, ret);
    GTEST_LOG_(INFO) << "remove the token info";
}

/**
 * @tc.name: GrantTempPermission002
 * @tc.desc: Test grant temp permission switching to background and to foreground again
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(PermissionManagerTest, GrantTempPermission002, TestSize.Level0)
{
    accessTokenService_->state_ = ServiceRunningState::STATE_RUNNING;
    accessTokenService_->Initialize();
    AccessTokenID tokenID = CreateTempHapTokenInfo();
    EXPECT_EQ(RET_SUCCESS, PermissionManager::GetInstance().GrantPermission(tokenID,
        "ohos.permission.APPROXIMATELY_LOCATION", PERMISSION_ALLOW_THIS_TIME));
    EXPECT_EQ(PERMISSION_GRANTED,
        AccessTokenInfoManager::GetInstance().VerifyAccessToken(tokenID, "ohos.permission.APPROXIMATELY_LOCATION"));
    // change to background
    AppStateData appStateData;
    appStateData.state = static_cast<int32_t>(ApplicationState::APP_STATE_BACKGROUND);
    appStateData.accessTokenId = tokenID;
    appStateObserver_->OnAppStateChanged(appStateData);
    EXPECT_EQ(PERMISSION_GRANTED,
        AccessTokenInfoManager::GetInstance().VerifyAccessToken(tokenID, "ohos.permission.APPROXIMATELY_LOCATION"));
    // change to foreground
    appStateData.state = static_cast<int32_t>(ApplicationState::APP_STATE_FOREGROUND);
    appStateObserver_->OnAppStateChanged(appStateData);
    sleep(11);
    EXPECT_EQ(PERMISSION_GRANTED,
        AccessTokenInfoManager::GetInstance().VerifyAccessToken(tokenID, "ohos.permission.APPROXIMATELY_LOCATION"));
    // remove hap
    int32_t ret = AccessTokenInfoManager::GetInstance().RemoveHapTokenInfo(tokenID);
    ASSERT_EQ(RET_SUCCESS, ret);
    GTEST_LOG_(INFO) << "remove the token info";
}

/**
 * @tc.name: GrantTempPermission003
 * @tc.desc: Test grant temp permission switching to background and has a form
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(PermissionManagerTest, GrantTempPermission003, TestSize.Level0)
{
    accessTokenService_->state_ = ServiceRunningState::STATE_RUNNING;
    accessTokenService_->Initialize();
    AccessTokenID tokenID = CreateTempHapTokenInfo();
    EXPECT_EQ(RET_SUCCESS, PermissionManager::GetInstance().GrantPermission(tokenID,
        "ohos.permission.APPROXIMATELY_LOCATION", PERMISSION_ALLOW_THIS_TIME));
    EXPECT_EQ(PERMISSION_GRANTED,
        AccessTokenInfoManager::GetInstance().VerifyAccessToken(tokenID, "ohos.permission.APPROXIMATELY_LOCATION"));
    // create a form
    FormInstance formInstance;
    formInstance.bundleName_ = "GrantTempPermission";
    formInstance.appIndex_ = 0;
    formInstance.userId_ = USER_ID;
    formInstance.formVisiblity_ = FormVisibilityType::VISIBLE;
    std::vector<FormInstance> formInstances;
    formInstances.emplace_back(formInstance);
    formStateObserver_->NotifyWhetherFormsVisible(FormVisibilityType::VISIBLE, "#1", formInstances);
    // change to background
    AppStateData appStateData;
    appStateData.state = static_cast<int32_t>(ApplicationState::APP_STATE_BACKGROUND);
    appStateData.accessTokenId = tokenID;
    appStateObserver_->OnAppStateChanged(appStateData);
    EXPECT_EQ(PERMISSION_GRANTED,
        AccessTokenInfoManager::GetInstance().VerifyAccessToken(tokenID, "ohos.permission.APPROXIMATELY_LOCATION"));
    sleep(11);
    EXPECT_EQ(PERMISSION_GRANTED,
        AccessTokenInfoManager::GetInstance().VerifyAccessToken(tokenID, "ohos.permission.APPROXIMATELY_LOCATION"));
    // remove hap
    int32_t ret = AccessTokenInfoManager::GetInstance().RemoveHapTokenInfo(tokenID);
    ASSERT_EQ(RET_SUCCESS, ret);
    GTEST_LOG_(INFO) << "remove the token info";
}

/**
 * @tc.name: GrantTempPermission004
 * @tc.desc: Test grant temp permission switching to background and create a form
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(PermissionManagerTest, GrantTempPermission004, TestSize.Level0)
{
    accessTokenService_->state_ = ServiceRunningState::STATE_RUNNING;
    accessTokenService_->Initialize();
    AccessTokenID tokenID = CreateTempHapTokenInfo();
    EXPECT_EQ(RET_SUCCESS, PermissionManager::GetInstance().GrantPermission(tokenID,
        "ohos.permission.APPROXIMATELY_LOCATION", PERMISSION_ALLOW_THIS_TIME));
    EXPECT_EQ(PERMISSION_GRANTED,
        AccessTokenInfoManager::GetInstance().VerifyAccessToken(tokenID, "ohos.permission.APPROXIMATELY_LOCATION"));
    // change to background
    AppStateData appStateData;
    appStateData.state = static_cast<int32_t>(ApplicationState::APP_STATE_BACKGROUND);
    appStateData.accessTokenId = tokenID;
    appStateObserver_->OnAppStateChanged(appStateData);
    EXPECT_EQ(PERMISSION_GRANTED,
        AccessTokenInfoManager::GetInstance().VerifyAccessToken(tokenID, "ohos.permission.APPROXIMATELY_LOCATION"));
    // create a form
    FormInstance formInstance;
    formInstance.bundleName_ = "GrantTempPermission";
    formInstance.appIndex_ = 0;
    formInstance.userId_ = USER_ID;
    formInstance.formVisiblity_ = FormVisibilityType::VISIBLE;
    std::vector<FormInstance> formInstances;
    formInstances.emplace_back(formInstance);
    formStateObserver_->NotifyWhetherFormsVisible(FormVisibilityType::VISIBLE, "#1", formInstances);
    sleep(11);
    EXPECT_EQ(PERMISSION_GRANTED,
        AccessTokenInfoManager::GetInstance().VerifyAccessToken(tokenID, "ohos.permission.APPROXIMATELY_LOCATION"));
    // remove hap
    int32_t ret = AccessTokenInfoManager::GetInstance().RemoveHapTokenInfo(tokenID);
    ASSERT_EQ(RET_SUCCESS, ret);
    GTEST_LOG_(INFO) << "remove the token info";
}

/**
 * @tc.name: GrantTempPermission005
 * @tc.desc: Test grant temp permission switching to background and form change to invisible
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(PermissionManagerTest, GrantTempPermission005, TestSize.Level0)
{
    accessTokenService_->state_ = ServiceRunningState::STATE_RUNNING;
    accessTokenService_->Initialize();
    AccessTokenID tokenID = CreateTempHapTokenInfo();
    EXPECT_EQ(RET_SUCCESS, PermissionManager::GetInstance().GrantPermission(tokenID,
        "ohos.permission.APPROXIMATELY_LOCATION", PERMISSION_ALLOW_THIS_TIME));
    EXPECT_EQ(PERMISSION_GRANTED,
        AccessTokenInfoManager::GetInstance().VerifyAccessToken(tokenID, "ohos.permission.APPROXIMATELY_LOCATION"));
    // change to background
    AppStateData appStateData;
    appStateData.state = static_cast<int32_t>(ApplicationState::APP_STATE_BACKGROUND);
    appStateData.accessTokenId = tokenID;
    appStateObserver_->OnAppStateChanged(appStateData);
    EXPECT_EQ(PERMISSION_GRANTED,
        AccessTokenInfoManager::GetInstance().VerifyAccessToken(tokenID, "ohos.permission.APPROXIMATELY_LOCATION"));
    // create a form
    FormInstance formInstance;
    formInstance.bundleName_ = "GrantTempPermission";
    formInstance.appIndex_ = 0;
    formInstance.userId_ = USER_ID;
    formInstance.formVisiblity_ = FormVisibilityType::VISIBLE;
    std::vector<FormInstance> formInstances;
    formInstances.emplace_back(formInstance);
    formStateObserver_->NotifyWhetherFormsVisible(FormVisibilityType::VISIBLE, "#1", formInstances);
    EXPECT_EQ(PERMISSION_GRANTED,
        AccessTokenInfoManager::GetInstance().VerifyAccessToken(tokenID, "ohos.permission.APPROXIMATELY_LOCATION"));
    // form invisible
    formInstances.clear();
    formInstance.formVisiblity_ = FormVisibilityType::INVISIBLE;
    formInstances.emplace_back(formInstance);
    formStateObserver_->NotifyWhetherFormsVisible(FormVisibilityType::INVISIBLE, "#1", formInstances);
    sleep(11);
    EXPECT_EQ(PERMISSION_DENIED,
        AccessTokenInfoManager::GetInstance().VerifyAccessToken(tokenID, "ohos.permission.APPROXIMATELY_LOCATION"));
    // remove hap
    int32_t ret = AccessTokenInfoManager::GetInstance().RemoveHapTokenInfo(tokenID);
    ASSERT_EQ(RET_SUCCESS, ret);
    GTEST_LOG_(INFO) << "remove the token info";
}

#ifdef BGTASKMGR_CONTINUOUS_TASK_ENABLE
/**
 * @tc.name: GrantTempPermission006
 * @tc.desc: Test grant temp permission switching to background and have a background task
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(PermissionManagerTest, GrantTempPermission006, TestSize.Level0)
{
    accessTokenService_->state_ = ServiceRunningState::STATE_RUNNING;
    accessTokenService_->Initialize();
    AccessTokenID tokenID = CreateTempHapTokenInfo();
    EXPECT_EQ(RET_SUCCESS, PermissionManager::GetInstance().GrantPermission(tokenID,
        "ohos.permission.APPROXIMATELY_LOCATION", PERMISSION_ALLOW_THIS_TIME));
    EXPECT_EQ(PERMISSION_GRANTED,
        AccessTokenInfoManager::GetInstance().VerifyAccessToken(tokenID, "ohos.permission.APPROXIMATELY_LOCATION"));
    // Use a fixed test-only continuous task id to verify location task keeps permission while app is background.
    auto continuousTaskCallbackInfo = CreateContinuousTaskInfo(tokenID, 2001, {BackgroundMode::LOCATION});
    backgroundTaskObserver_->OnContinuousTaskStart(continuousTaskCallbackInfo);
    // change to background
    AppStateData appStateData;
    appStateData.state = static_cast<int32_t>(ApplicationState::APP_STATE_BACKGROUND);
    appStateData.accessTokenId = tokenID;
    appStateObserver_->OnAppStateChanged(appStateData);
    EXPECT_EQ(PERMISSION_GRANTED,
        AccessTokenInfoManager::GetInstance().VerifyAccessToken(tokenID, "ohos.permission.APPROXIMATELY_LOCATION"));
    sleep(11);
    EXPECT_EQ(PERMISSION_GRANTED,
        AccessTokenInfoManager::GetInstance().VerifyAccessToken(tokenID, "ohos.permission.APPROXIMATELY_LOCATION"));
    // remove hap
    int32_t ret = AccessTokenInfoManager::GetInstance().RemoveHapTokenInfo(tokenID);
    ASSERT_EQ(RET_SUCCESS, ret);
    GTEST_LOG_(INFO) << "remove the token info";
}

/**
 * @tc.name: GrantTempPermission007
 * @tc.desc: Test grant temp permission switching to background and create a background task
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(PermissionManagerTest, GrantTempPermission007, TestSize.Level0)
{
    accessTokenService_->state_ = ServiceRunningState::STATE_RUNNING;
    accessTokenService_->Initialize();
    AccessTokenID tokenID = CreateTempHapTokenInfo();
    EXPECT_EQ(RET_SUCCESS, PermissionManager::GetInstance().GrantPermission(tokenID,
        "ohos.permission.APPROXIMATELY_LOCATION", PERMISSION_ALLOW_THIS_TIME));
    EXPECT_EQ(PERMISSION_GRANTED,
        AccessTokenInfoManager::GetInstance().VerifyAccessToken(tokenID, "ohos.permission.APPROXIMATELY_LOCATION"));
    // change to background
    AppStateData appStateData;
    appStateData.state = static_cast<int32_t>(ApplicationState::APP_STATE_BACKGROUND);
    appStateData.accessTokenId = tokenID;
    appStateObserver_->OnAppStateChanged(appStateData);
    // Use a fixed test-only continuous task id to verify location task start after background transition.
    auto continuousTaskCallbackInfo = CreateContinuousTaskInfo(tokenID, 2002, {BackgroundMode::LOCATION});
    backgroundTaskObserver_->OnContinuousTaskStart(continuousTaskCallbackInfo);
    EXPECT_EQ(PERMISSION_GRANTED,
        AccessTokenInfoManager::GetInstance().VerifyAccessToken(tokenID, "ohos.permission.APPROXIMATELY_LOCATION"));
    sleep(11);
    EXPECT_EQ(PERMISSION_GRANTED,
        AccessTokenInfoManager::GetInstance().VerifyAccessToken(tokenID, "ohos.permission.APPROXIMATELY_LOCATION"));
    // remove hap
    int32_t ret = AccessTokenInfoManager::GetInstance().RemoveHapTokenInfo(tokenID);
    ASSERT_EQ(RET_SUCCESS, ret);
    GTEST_LOG_(INFO) << "remove the token info";
}

/**
 * @tc.name: GrantTempPermission008
 * @tc.desc: Test grant temp permission switching to background and remove a background task
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(PermissionManagerTest, GrantTempPermission008, TestSize.Level0)
{
    accessTokenService_->state_ = ServiceRunningState::STATE_RUNNING;
    accessTokenService_->Initialize();
    AccessTokenID tokenID = CreateTempHapTokenInfo();
    EXPECT_EQ(RET_SUCCESS, PermissionManager::GetInstance().GrantPermission(tokenID,
        "ohos.permission.APPROXIMATELY_LOCATION", PERMISSION_ALLOW_THIS_TIME));
    EXPECT_EQ(PERMISSION_GRANTED,
        AccessTokenInfoManager::GetInstance().VerifyAccessToken(tokenID, "ohos.permission.APPROXIMATELY_LOCATION"));
    // Use a fixed test-only continuous task id to verify location task stop revokes permission.
    auto continuousTaskCallbackInfo = CreateContinuousTaskInfo(tokenID, 2003, {BackgroundMode::LOCATION});
    backgroundTaskObserver_->OnContinuousTaskStart(continuousTaskCallbackInfo);
    // change to background
    AppStateData appStateData;
    appStateData.state = static_cast<int32_t>(ApplicationState::APP_STATE_BACKGROUND);
    appStateData.accessTokenId = tokenID;
    appStateObserver_->OnAppStateChanged(appStateData);
    EXPECT_EQ(PERMISSION_GRANTED,
        AccessTokenInfoManager::GetInstance().VerifyAccessToken(tokenID, "ohos.permission.APPROXIMATELY_LOCATION"));
    // remove background task
    backgroundTaskObserver_->OnContinuousTaskStop(continuousTaskCallbackInfo);
    sleep(11);
    EXPECT_EQ(PERMISSION_DENIED,
        AccessTokenInfoManager::GetInstance().VerifyAccessToken(tokenID, "ohos.permission.APPROXIMATELY_LOCATION"));
    // remove hap
    int32_t ret = AccessTokenInfoManager::GetInstance().RemoveHapTokenInfo(tokenID);
    ASSERT_EQ(RET_SUCCESS, ret);
    GTEST_LOG_(INFO) << "remove the token info";
}

/**
 * @tc.name: GrantTempPermission009
 * @tc.desc: Test grant temp permission switching to background and has a background task and a form
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(PermissionManagerTest, GrantTempPermission009, TestSize.Level0)
{
    accessTokenService_->state_ = ServiceRunningState::STATE_RUNNING;
    accessTokenService_->Initialize();
    AccessTokenID tokenID = CreateTempHapTokenInfo();
    EXPECT_EQ(RET_SUCCESS, PermissionManager::GetInstance().GrantPermission(tokenID,
        "ohos.permission.APPROXIMATELY_LOCATION", PERMISSION_ALLOW_THIS_TIME));
    EXPECT_EQ(PERMISSION_GRANTED,
        AccessTokenInfoManager::GetInstance().VerifyAccessToken(tokenID, "ohos.permission.APPROXIMATELY_LOCATION"));
    // Use a fixed test-only continuous task id to verify location task and form can both keep permission alive.
    auto continuousTaskCallbackInfo = CreateContinuousTaskInfo(tokenID, 2004, {BackgroundMode::LOCATION});
    backgroundTaskObserver_->OnContinuousTaskStart(continuousTaskCallbackInfo);
    // create a form
    FormInstance formInstance;
    formInstance.bundleName_ = "GrantTempPermission";
    formInstance.appIndex_ = 0;
    formInstance.userId_ = USER_ID;
    formInstance.formVisiblity_ = FormVisibilityType::VISIBLE;
    std::vector<FormInstance> formInstances;
    formInstances.emplace_back(formInstance);
    formStateObserver_->NotifyWhetherFormsVisible(FormVisibilityType::VISIBLE, "#1", formInstances);
    // change to background
    AppStateData appStateData;
    appStateData.state = static_cast<int32_t>(ApplicationState::APP_STATE_BACKGROUND);
    appStateData.accessTokenId = tokenID;
    appStateObserver_->OnAppStateChanged(appStateData);
    EXPECT_EQ(PERMISSION_GRANTED,
        AccessTokenInfoManager::GetInstance().VerifyAccessToken(tokenID, "ohos.permission.APPROXIMATELY_LOCATION"));
    sleep(11);
    EXPECT_EQ(PERMISSION_GRANTED,
        AccessTokenInfoManager::GetInstance().VerifyAccessToken(tokenID, "ohos.permission.APPROXIMATELY_LOCATION"));
    // remove hap
    int32_t ret = AccessTokenInfoManager::GetInstance().RemoveHapTokenInfo(tokenID);
    ASSERT_EQ(RET_SUCCESS, ret);
    GTEST_LOG_(INFO) << "remove the token info";
}

/**
 * @tc.name: GrantTempPermission010
 * @tc.desc: Test grant temp permission switching to background and has a background task and a form, remove form
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(PermissionManagerTest, GrantTempPermission010, TestSize.Level0)
{
    accessTokenService_->state_ = ServiceRunningState::STATE_RUNNING;
    accessTokenService_->Initialize();
    AccessTokenID tokenID = CreateTempHapTokenInfo();
    EXPECT_EQ(RET_SUCCESS, PermissionManager::GetInstance().GrantPermission(tokenID,
        "ohos.permission.APPROXIMATELY_LOCATION", PERMISSION_ALLOW_THIS_TIME));
    EXPECT_EQ(PERMISSION_GRANTED,
        AccessTokenInfoManager::GetInstance().VerifyAccessToken(tokenID, "ohos.permission.APPROXIMATELY_LOCATION"));
    // Use a fixed test-only continuous task id to verify form invisible does not revoke while task remains.
    auto continuousTaskCallbackInfo = CreateContinuousTaskInfo(tokenID, 2005, {BackgroundMode::LOCATION});
    backgroundTaskObserver_->OnContinuousTaskStart(continuousTaskCallbackInfo);
    // create a form
    FormInstance formInstance;
    formInstance.bundleName_ = "GrantTempPermission";
    formInstance.appIndex_ = 0;
    formInstance.userId_ = USER_ID;
    formInstance.formVisiblity_ = FormVisibilityType::VISIBLE;
    std::vector<FormInstance> formInstances;
    formInstances.emplace_back(formInstance);
    formStateObserver_->NotifyWhetherFormsVisible(FormVisibilityType::VISIBLE, "#1", formInstances);
    // change to background
    AppStateData appStateData;
    appStateData.state = static_cast<int32_t>(ApplicationState::APP_STATE_BACKGROUND);
    appStateData.accessTokenId = tokenID;
    appStateObserver_->OnAppStateChanged(appStateData);
    EXPECT_EQ(PERMISSION_GRANTED,
        AccessTokenInfoManager::GetInstance().VerifyAccessToken(tokenID, "ohos.permission.APPROXIMATELY_LOCATION"));
    // form change to invisible
    formInstances.clear();
    formInstance.formVisiblity_ = FormVisibilityType::INVISIBLE;
    formInstances.emplace_back(formInstance);
    formStateObserver_->NotifyWhetherFormsVisible(FormVisibilityType::INVISIBLE, "#1", formInstances);
    sleep(11);
    EXPECT_EQ(PERMISSION_GRANTED,
        AccessTokenInfoManager::GetInstance().VerifyAccessToken(tokenID, "ohos.permission.APPROXIMATELY_LOCATION"));
    // remove hap
    int32_t ret = AccessTokenInfoManager::GetInstance().RemoveHapTokenInfo(tokenID);
    ASSERT_EQ(RET_SUCCESS, ret);
    GTEST_LOG_(INFO) << "remove the token info";
}

/**
 * @tc.name: GrantTempPermission011
 * @tc.desc: Test grant temp permission switching to background and has a background task and a form, remove task
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(PermissionManagerTest, GrantTempPermission011, TestSize.Level0)
{
    accessTokenService_->state_ = ServiceRunningState::STATE_RUNNING;
    accessTokenService_->Initialize();
    AccessTokenID tokenID = CreateTempHapTokenInfo();
    EXPECT_EQ(RET_SUCCESS, PermissionManager::GetInstance().GrantPermission(tokenID,
        "ohos.permission.APPROXIMATELY_LOCATION", PERMISSION_ALLOW_THIS_TIME));
    EXPECT_EQ(PERMISSION_GRANTED,
        AccessTokenInfoManager::GetInstance().VerifyAccessToken(tokenID, "ohos.permission.APPROXIMATELY_LOCATION"));
    // Use a fixed test-only continuous task id to verify task stop still keeps permission while form remains visible.
    auto continuousTaskCallbackInfo = CreateContinuousTaskInfo(tokenID, 2006, {BackgroundMode::LOCATION});
    backgroundTaskObserver_->OnContinuousTaskStart(continuousTaskCallbackInfo);
    // create a form
    FormInstance formInstance;
    formInstance.bundleName_ = "GrantTempPermission";
    formInstance.appIndex_ = 0;
    formInstance.userId_ = USER_ID;
    formInstance.formVisiblity_ = FormVisibilityType::VISIBLE;
    std::vector<FormInstance> formInstances;
    formInstances.emplace_back(formInstance);
    formStateObserver_->NotifyWhetherFormsVisible(FormVisibilityType::VISIBLE, "#1", formInstances);
    // change to background
    AppStateData appStateData;
    appStateData.state = static_cast<int32_t>(ApplicationState::APP_STATE_BACKGROUND);
    appStateData.accessTokenId = tokenID;
    appStateObserver_->OnAppStateChanged(appStateData);
    EXPECT_EQ(PERMISSION_GRANTED,
        AccessTokenInfoManager::GetInstance().VerifyAccessToken(tokenID, "ohos.permission.APPROXIMATELY_LOCATION"));
    // remove background tast
    backgroundTaskObserver_->OnContinuousTaskStop(continuousTaskCallbackInfo);
    sleep(11);
    EXPECT_EQ(PERMISSION_GRANTED,
        AccessTokenInfoManager::GetInstance().VerifyAccessToken(tokenID, "ohos.permission.APPROXIMATELY_LOCATION"));
    // remove hap
    int32_t ret = AccessTokenInfoManager::GetInstance().RemoveHapTokenInfo(tokenID);
    ASSERT_EQ(RET_SUCCESS, ret);
    GTEST_LOG_(INFO) << "remove the token info";
}

/**
 * @tc.name: GrantTempPermission012
 * @tc.desc: Test grant temp permission switching to background and has a background task and a form, remove form&task
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(PermissionManagerTest, GrantTempPermission012, TestSize.Level0)
{
    accessTokenService_->state_ = ServiceRunningState::STATE_RUNNING;
    accessTokenService_->Initialize();
    AccessTokenID tokenID = CreateTempHapTokenInfo();
    EXPECT_EQ(RET_SUCCESS, PermissionManager::GetInstance().GrantPermission(tokenID,
        "ohos.permission.APPROXIMATELY_LOCATION", PERMISSION_ALLOW_THIS_TIME));
    EXPECT_EQ(PERMISSION_GRANTED,
        AccessTokenInfoManager::GetInstance().VerifyAccessToken(tokenID, "ohos.permission.APPROXIMATELY_LOCATION"));
    // Use a fixed test-only continuous task id to verify form removal plus task stop revokes permission.
    auto continuousTaskCallbackInfo = CreateContinuousTaskInfo(tokenID, 2007, {BackgroundMode::LOCATION});
    backgroundTaskObserver_->OnContinuousTaskStart(continuousTaskCallbackInfo);
    // create a form
    FormInstance formInstance;
    formInstance.bundleName_ = "GrantTempPermission";
    formInstance.appIndex_ = 0;
    formInstance.userId_ = USER_ID;
    formInstance.formVisiblity_ = FormVisibilityType::VISIBLE;
    std::vector<FormInstance> formInstances;
    formInstances.emplace_back(formInstance);
    formStateObserver_->NotifyWhetherFormsVisible(FormVisibilityType::VISIBLE, "#1", formInstances);
    // change to background
    AppStateData appStateData;
    appStateData.state = static_cast<int32_t>(ApplicationState::APP_STATE_BACKGROUND);
    appStateData.accessTokenId = tokenID;
    appStateObserver_->OnAppStateChanged(appStateData);
    EXPECT_EQ(PERMISSION_GRANTED,
        AccessTokenInfoManager::GetInstance().VerifyAccessToken(tokenID, "ohos.permission.APPROXIMATELY_LOCATION"));
    // remove form
    formInstances.clear();
    formInstance.formVisiblity_ = FormVisibilityType::INVISIBLE;
    formInstances.emplace_back(formInstance);
    formStateObserver_->NotifyWhetherFormsVisible(FormVisibilityType::INVISIBLE, "#1", formInstances);
    sleep(11);
    EXPECT_EQ(PERMISSION_GRANTED,
        AccessTokenInfoManager::GetInstance().VerifyAccessToken(tokenID, "ohos.permission.APPROXIMATELY_LOCATION"));
    // remove background tast
    backgroundTaskObserver_->OnContinuousTaskStop(continuousTaskCallbackInfo);
    sleep(11);
    EXPECT_EQ(PERMISSION_DENIED,
        AccessTokenInfoManager::GetInstance().VerifyAccessToken(tokenID, "ohos.permission.APPROXIMATELY_LOCATION"));
    // remove hap
    int32_t ret = AccessTokenInfoManager::GetInstance().RemoveHapTokenInfo(tokenID);
    ASSERT_EQ(RET_SUCCESS, ret);
    GTEST_LOG_(INFO) << "remove the token info";
}

/**
 * @tc.name: GrantTempPermission013
 * @tc.desc: Test grant temp permission, Create multiple continuous task
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(PermissionManagerTest, GrantTempPermission013, TestSize.Level0)
{
    accessTokenService_->state_ = ServiceRunningState::STATE_RUNNING;
    accessTokenService_->Initialize();
    AccessTokenID tokenID = CreateTempHapTokenInfo();
    EXPECT_EQ(RET_SUCCESS, PermissionManager::GetInstance().GrantPermission(tokenID,
        "ohos.permission.APPROXIMATELY_LOCATION", PERMISSION_ALLOW_THIS_TIME));
    EXPECT_EQ(PERMISSION_GRANTED,
        AccessTokenInfoManager::GetInstance().VerifyAccessToken(tokenID, "ohos.permission.APPROXIMATELY_LOCATION"));
    // Use fixed test-only continuous task ids to verify unrelated and related tasks are tracked independently.
    auto continuousTaskCallbackInfo = CreateContinuousTaskInfo(tokenID, 2008, {BackgroundMode::DATA_TRANSFER});
    backgroundTaskObserver_->OnContinuousTaskStart(continuousTaskCallbackInfo);

    auto continuousTaskCallbackInfo1 = CreateContinuousTaskInfo(tokenID, 2009, {BackgroundMode::LOCATION});
    backgroundTaskObserver_->OnContinuousTaskStart(continuousTaskCallbackInfo1);

    // change to background
    AppStateData appStateData;
    appStateData.state = static_cast<int32_t>(ApplicationState::APP_STATE_BACKGROUND);
    appStateData.accessTokenId = tokenID;
    appStateObserver_->OnAppStateChanged(appStateData);
    EXPECT_EQ(PERMISSION_GRANTED,
        AccessTokenInfoManager::GetInstance().VerifyAccessToken(tokenID, "ohos.permission.APPROXIMATELY_LOCATION"));

    // remove background tast
    backgroundTaskObserver_->OnContinuousTaskStop(continuousTaskCallbackInfo);
    sleep(11);
    EXPECT_EQ(PERMISSION_GRANTED,
        AccessTokenInfoManager::GetInstance().VerifyAccessToken(tokenID, "ohos.permission.APPROXIMATELY_LOCATION"));
    // remove background tast
    backgroundTaskObserver_->OnContinuousTaskStop(continuousTaskCallbackInfo1);
    sleep(11);
    EXPECT_EQ(PERMISSION_DENIED,
        AccessTokenInfoManager::GetInstance().VerifyAccessToken(tokenID, "ohos.permission.APPROXIMATELY_LOCATION"));
    // remove hap
    int32_t ret = AccessTokenInfoManager::GetInstance().RemoveHapTokenInfo(tokenID);
    ASSERT_EQ(RET_SUCCESS, ret);
    GTEST_LOG_(INFO) << "remove the token info";
}

/**
 * @tc.name: GrantTempPermission014
 * @tc.desc: Test grant temp permission, Create multiple continuous task
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(PermissionManagerTest, GrantTempPermission014, TestSize.Level0)
{
    accessTokenService_->state_ = ServiceRunningState::STATE_RUNNING;
    accessTokenService_->Initialize();
    AccessTokenID tokenID = CreateTempHapTokenInfo();
    EXPECT_EQ(RET_SUCCESS, PermissionManager::GetInstance().GrantPermission(tokenID,
        "ohos.permission.APPROXIMATELY_LOCATION", PERMISSION_ALLOW_THIS_TIME));
    EXPECT_EQ(RET_SUCCESS, PermissionManager::GetInstance().GrantPermission(tokenID,
        "ohos.permission.READ_PASTEBOARD", PERMISSION_ALLOW_THIS_TIME));
    EXPECT_EQ(PERMISSION_GRANTED,
        AccessTokenInfoManager::GetInstance().VerifyAccessToken(tokenID, "ohos.permission.APPROXIMATELY_LOCATION"));
    EXPECT_EQ(PERMISSION_GRANTED,
        AccessTokenInfoManager::GetInstance().VerifyAccessToken(tokenID, "ohos.permission.READ_PASTEBOARD"));
    // Use a fixed test-only continuous task id to verify one task can keep multiple location-type permissions alive.
    auto continuousTaskCallbackInfo = CreateContinuousTaskInfo(tokenID, 2010, {BackgroundMode::LOCATION});
    backgroundTaskObserver_->OnContinuousTaskStart(continuousTaskCallbackInfo);

    // change to background
    AppStateData appStateData;
    appStateData.state = static_cast<int32_t>(ApplicationState::APP_STATE_BACKGROUND);
    appStateData.accessTokenId = tokenID;
    appStateObserver_->OnAppStateChanged(appStateData);
    sleep(11);
    EXPECT_EQ(PERMISSION_GRANTED,
        AccessTokenInfoManager::GetInstance().VerifyAccessToken(tokenID, "ohos.permission.APPROXIMATELY_LOCATION"));
    EXPECT_EQ(PERMISSION_DENIED,
        AccessTokenInfoManager::GetInstance().VerifyAccessToken(tokenID, "ohos.permission.READ_PASTEBOARD"));
    // remove background tast
    backgroundTaskObserver_->OnContinuousTaskStop(continuousTaskCallbackInfo);
    sleep(11);
    EXPECT_EQ(PERMISSION_DENIED,
        AccessTokenInfoManager::GetInstance().VerifyAccessToken(tokenID, "ohos.permission.APPROXIMATELY_LOCATION"));
    EXPECT_EQ(PERMISSION_DENIED,
        AccessTokenInfoManager::GetInstance().VerifyAccessToken(tokenID, "ohos.permission.READ_PASTEBOARD"));
    // remove hap
    int32_t ret = AccessTokenInfoManager::GetInstance().RemoveHapTokenInfo(tokenID);
    ASSERT_EQ(RET_SUCCESS, ret);
    GTEST_LOG_(INFO) << "remove the token info";
}

/**
 * @tc.name: GrantTempPermission015
 * @tc.desc: Test grant temp permission switching to background and have a background task with 2 typeId
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(PermissionManagerTest, GrantTempPermission015, TestSize.Level0)
{
    accessTokenService_->state_ = ServiceRunningState::STATE_RUNNING;
    accessTokenService_->Initialize();
    AccessTokenID tokenID = CreateTempHapTokenInfo();
    EXPECT_EQ(RET_SUCCESS, PermissionManager::GetInstance().GrantPermission(tokenID,
        "ohos.permission.APPROXIMATELY_LOCATION", PERMISSION_ALLOW_THIS_TIME));
    EXPECT_EQ(PERMISSION_GRANTED,
        AccessTokenInfoManager::GetInstance().VerifyAccessToken(tokenID, "ohos.permission.APPROXIMATELY_LOCATION"));
    // Use a fixed test-only continuous task id to verify mixed typeIds containing location are matched.
    auto continuousTaskCallbackInfo = CreateContinuousTaskInfo(
        tokenID, 2011, {BackgroundMode::DATA_TRANSFER, BackgroundMode::LOCATION});
    backgroundTaskObserver_->OnContinuousTaskStart(continuousTaskCallbackInfo);
    // change to background
    AppStateData appStateData;
    appStateData.state = static_cast<int32_t>(ApplicationState::APP_STATE_BACKGROUND);
    appStateData.accessTokenId = tokenID;
    appStateObserver_->OnAppStateChanged(appStateData);
    EXPECT_EQ(PERMISSION_GRANTED,
        AccessTokenInfoManager::GetInstance().VerifyAccessToken(tokenID, "ohos.permission.APPROXIMATELY_LOCATION"));
    sleep(11);
    EXPECT_EQ(PERMISSION_GRANTED,
        AccessTokenInfoManager::GetInstance().VerifyAccessToken(tokenID, "ohos.permission.APPROXIMATELY_LOCATION"));

    // change to foreground
    appStateData.state = static_cast<int32_t>(ApplicationState::APP_STATE_FOREGROUND);
    appStateObserver_->OnAppStateChanged(appStateData);
    sleep(1);
    // stop background task
    backgroundTaskObserver_->OnContinuousTaskStop(continuousTaskCallbackInfo);
    // change to background
    appStateData.state = static_cast<int32_t>(ApplicationState::APP_STATE_BACKGROUND);
    appStateObserver_->OnAppStateChanged(appStateData);
    EXPECT_EQ(PERMISSION_GRANTED,
        AccessTokenInfoManager::GetInstance().VerifyAccessToken(tokenID, "ohos.permission.APPROXIMATELY_LOCATION"));
    sleep(11);
    EXPECT_EQ(PERMISSION_DENIED,
        AccessTokenInfoManager::GetInstance().VerifyAccessToken(tokenID, "ohos.permission.APPROXIMATELY_LOCATION"));

    // remove hap
    int32_t ret = AccessTokenInfoManager::GetInstance().RemoveHapTokenInfo(tokenID);
    ASSERT_EQ(RET_SUCCESS, ret);
    GTEST_LOG_(INFO) << "remove the token info";
}

/**
 * @tc.name: GrantTempPermission016
 * @tc.desc: Test tokenID not in the list
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(PermissionManagerTest, GrantTempPermission016, TestSize.Level0)
{
    accessTokenService_->state_ = ServiceRunningState::STATE_RUNNING;
    accessTokenService_->Initialize();
    AccessTokenID tokenID = CreateTempHapTokenInfo();
    EXPECT_EQ(RET_SUCCESS, PermissionManager::GetInstance().GrantPermission(tokenID,
        "ohos.permission.APPROXIMATELY_LOCATION", PERMISSION_SYSTEM_FIXED));

    TempPermissionObserver::GetInstance().ModifyAppState(tokenID, 0, false);
    // Use a fixed test-only continuous task id to verify callbacks ignore non-temp permission tokens.
    auto continuousTaskCallbackInfo = CreateContinuousTaskInfo(tokenID, 2012, {BackgroundMode::LOCATION});
    backgroundTaskObserver_->OnContinuousTaskStart(continuousTaskCallbackInfo);
    EXPECT_EQ(PERMISSION_GRANTED,
        AccessTokenInfoManager::GetInstance().VerifyAccessToken(tokenID, "ohos.permission.APPROXIMATELY_LOCATION"));

    // remove background tast
    backgroundTaskObserver_->OnContinuousTaskStop(continuousTaskCallbackInfo);
    EXPECT_EQ(PERMISSION_GRANTED,
        AccessTokenInfoManager::GetInstance().VerifyAccessToken(tokenID, "ohos.permission.APPROXIMATELY_LOCATION"));

    TempPermissionObserver::GetInstance().RevokeAllTempPermission(tokenID);
    EXPECT_EQ(PERMISSION_GRANTED,
        AccessTokenInfoManager::GetInstance().VerifyAccessToken(tokenID, "ohos.permission.APPROXIMATELY_LOCATION"));
    // remove hap
    int32_t ret = AccessTokenInfoManager::GetInstance().RemoveHapTokenInfo(tokenID);
    ASSERT_EQ(RET_SUCCESS, ret);
    GTEST_LOG_(INFO) << "remove the token info";
}
#endif
/**
 * @tc.name: GrantTempPermission017
 * @tc.desc: Test grant temp permission process died
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(PermissionManagerTest, GrantTempPermission017, TestSize.Level0)
{
    accessTokenService_->state_ = ServiceRunningState::STATE_RUNNING;
    accessTokenService_->Initialize();
    AccessTokenID tokenID = CreateTempHapTokenInfo();
    EXPECT_EQ(RET_SUCCESS, PermissionManager::GetInstance().GrantPermission(tokenID,
        "ohos.permission.APPROXIMATELY_LOCATION", PERMISSION_ALLOW_THIS_TIME));
    EXPECT_EQ(PERMISSION_GRANTED,
        AccessTokenInfoManager::GetInstance().VerifyAccessToken(tokenID, "ohos.permission.APPROXIMATELY_LOCATION"));
    AppStateData appStateData;
    appStateData.state = static_cast<int32_t>(ApplicationState::APP_STATE_TERMINATED);
    appStateData.accessTokenId = tokenID;
    appStateObserver_->OnAppStopped(appStateData);
    EXPECT_EQ(PERMISSION_DENIED,
        AccessTokenInfoManager::GetInstance().VerifyAccessToken(tokenID, "ohos.permission.APPROXIMATELY_LOCATION"));
    // remove hap
    int32_t ret = AccessTokenInfoManager::GetInstance().RemoveHapTokenInfo(tokenID);
    ASSERT_EQ(RET_SUCCESS, ret);
    GTEST_LOG_(INFO) << "remove the token info";
}

/**
 * @tc.name: GrantTempPermission018
 * @tc.desc: Test grant & revoke temp permission
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(PermissionManagerTest, GrantTempPermission018, TestSize.Level0)
{
    accessTokenService_->state_ = ServiceRunningState::STATE_RUNNING;
    accessTokenService_->Initialize();
    AccessTokenID tokenID = CreateTempHapTokenInfo();
    EXPECT_EQ(RET_SUCCESS, PermissionManager::GetInstance().GrantPermission(tokenID,
        "ohos.permission.APPROXIMATELY_LOCATION", PERMISSION_ALLOW_THIS_TIME));
    EXPECT_EQ(PERMISSION_GRANTED,
        AccessTokenInfoManager::GetInstance().VerifyAccessToken(tokenID, "ohos.permission.APPROXIMATELY_LOCATION"));
    EXPECT_EQ(RET_SUCCESS, PermissionManager::GetInstance().RevokePermission(tokenID,
        "ohos.permission.APPROXIMATELY_LOCATION", PERMISSION_ALLOW_THIS_TIME));
    EXPECT_EQ(PERMISSION_DENIED,
        AccessTokenInfoManager::GetInstance().VerifyAccessToken(tokenID, "ohos.permission.APPROXIMATELY_LOCATION"));
    // remove hap
    int32_t ret = AccessTokenInfoManager::GetInstance().RemoveHapTokenInfo(tokenID);
    ASSERT_EQ(RET_SUCCESS, ret);
    GTEST_LOG_(INFO) << "remove the token info";
}

/**
 * @tc.name: GrantTempPermission019
 * @tc.desc: Test grant temp permission not root
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(PermissionManagerTest, GrantTempPermission019, TestSize.Level0)
{
    accessTokenService_->state_ = ServiceRunningState::STATE_RUNNING;
    accessTokenService_->Initialize();
    AccessTokenID tokenID = CreateTempHapTokenInfo();
    setuid(100);
    EXPECT_EQ(ERR_IDENTITY_CHECK_FAILED, PermissionManager::GetInstance().GrantPermission(tokenID,
        "ohos.permission.APPROXIMATELY_LOCATION", PERMISSION_ALLOW_THIS_TIME));
    // remove hap
    int32_t ret = AccessTokenInfoManager::GetInstance().RemoveHapTokenInfo(tokenID);
    ASSERT_EQ(RET_SUCCESS, ret);
    GTEST_LOG_(INFO) << "remove the token info";
    setuid(0);
}

/**
 * @tc.name: GrantTempPermission020
 * @tc.desc: Test tokenID not in the list
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(PermissionManagerTest, GrantTempPermission020, TestSize.Level0)
{
    accessTokenService_->state_ = ServiceRunningState::STATE_RUNNING;
    accessTokenService_->Initialize();
    AccessTokenID tokenID = CreateTempHapTokenInfo();
    EXPECT_EQ(RET_SUCCESS, PermissionManager::GetInstance().GrantPermission(tokenID,
        "ohos.permission.APPROXIMATELY_LOCATION", PERMISSION_SYSTEM_FIXED));

    // change to background
    AppStateData appStateData;
    appStateData.state = static_cast<int32_t>(ApplicationState::APP_STATE_BACKGROUND);
    appStateData.accessTokenId = tokenID;
    appStateObserver_->OnAppStateChanged(appStateData);
    EXPECT_EQ(PERMISSION_GRANTED,
        AccessTokenInfoManager::GetInstance().VerifyAccessToken(tokenID, "ohos.permission.APPROXIMATELY_LOCATION"));
    FormInstance formInstance;
    formInstance.bundleName_ = "GrantTempPermission";
    formInstance.appIndex_ = 0;
    formInstance.userId_ = USER_ID;
    formInstance.formVisiblity_ = FormVisibilityType::INVISIBLE;
    std::vector<FormInstance> formInstances;
    formInstances.emplace_back(formInstance);
    EXPECT_EQ(RET_SUCCESS,
        formStateObserver_->NotifyWhetherFormsVisible(FormVisibilityType::INVISIBLE, "#1", formInstances));
    EXPECT_EQ(PERMISSION_GRANTED,
        AccessTokenInfoManager::GetInstance().VerifyAccessToken(tokenID, "ohos.permission.APPROXIMATELY_LOCATION"));

    EXPECT_EQ(RET_SUCCESS,
        formStateObserver_->NotifyWhetherFormsVisible(FormVisibilityType::INVISIBLE, "#1", formInstances));
    EXPECT_EQ(PERMISSION_GRANTED,
        AccessTokenInfoManager::GetInstance().VerifyAccessToken(tokenID, "ohos.permission.APPROXIMATELY_LOCATION"));

    // remove hap
    int32_t ret = AccessTokenInfoManager::GetInstance().RemoveHapTokenInfo(tokenID);
    ASSERT_EQ(RET_SUCCESS, ret);
    GTEST_LOG_(INFO) << "remove the token info";
}

/**
 * @tc.name: GrantTempPermission021
 * @tc.desc: Test microphone temp permission can be granted
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(PermissionManagerTest, GrantTempPermission021, TestSize.Level0)
{
    accessTokenService_->state_ = ServiceRunningState::STATE_RUNNING;
    accessTokenService_->Initialize();
    AccessTokenID tokenID = CreateTempHapTokenInfo();
    EXPECT_EQ(RET_SUCCESS, PermissionManager::GetInstance().GrantPermission(tokenID,
        "ohos.permission.MICROPHONE", PERMISSION_ALLOW_THIS_TIME));
    EXPECT_EQ(PERMISSION_GRANTED,
        AccessTokenInfoManager::GetInstance().VerifyAccessToken(tokenID, "ohos.permission.MICROPHONE"));
    TempPermissionObserver::GetInstance().UnRegisterCallback();
    // remove hap
    int32_t ret = AccessTokenInfoManager::GetInstance().RemoveHapTokenInfo(tokenID);
    ASSERT_EQ(RET_SUCCESS, ret);
    GTEST_LOG_(INFO) << "remove the token info";
}

/**
 * @tc.name: GrantTempPermission022
 * @tc.desc: Test camera temp permission revoke after switching to background
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(PermissionManagerTest, GrantTempPermission022, TestSize.Level0)
{
    accessTokenService_->state_ = ServiceRunningState::STATE_RUNNING;
    accessTokenService_->Initialize();
    TempPermissionObserver::GetInstance().SetCancelTime(200);
    AccessTokenID tokenID = CreateTempHapTokenInfo();
    EXPECT_EQ(RET_SUCCESS, PermissionManager::GetInstance().GrantPermission(tokenID,
        "ohos.permission.CAMERA", PERMISSION_ALLOW_THIS_TIME));

    AppStateData appStateData;
    appStateData.state = static_cast<int32_t>(ApplicationState::APP_STATE_BACKGROUND);
    appStateData.accessTokenId = tokenID;
    appStateObserver_->OnAppStateChanged(appStateData);
    sleep(1);

    EXPECT_EQ(PERMISSION_DENIED,
        AccessTokenInfoManager::GetInstance().VerifyAccessToken(tokenID, "ohos.permission.CAMERA"));
    int32_t ret = AccessTokenInfoManager::GetInstance().RemoveHapTokenInfo(tokenID);
    ASSERT_EQ(RET_SUCCESS, ret);
}

#ifdef BGTASKMGR_CONTINUOUS_TASK_ENABLE
/**
 * @tc.name: GrantTempPermission023
 * @tc.desc: Test microphone temp permission keep with audio task and revoke after task stops
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(PermissionManagerTest, GrantTempPermission023, TestSize.Level0)
{
    accessTokenService_->state_ = ServiceRunningState::STATE_RUNNING;
    accessTokenService_->Initialize();
    TempPermissionObserver::GetInstance().SetCancelTime(200);
    AccessTokenID tokenID = CreateTempHapTokenInfo();
    EXPECT_EQ(RET_SUCCESS, PermissionManager::GetInstance().GrantPermission(tokenID,
        "ohos.permission.MICROPHONE", PERMISSION_ALLOW_THIS_TIME));

    // Use a fixed test-only continuous task id to verify task association lifecycle.
    auto continuousTaskCallbackInfo = CreateContinuousTaskInfo(tokenID, 1001, {BackgroundMode::AUDIO_RECORDING});
    backgroundTaskObserver_->OnContinuousTaskStart(continuousTaskCallbackInfo);

    AppStateData appStateData;
    appStateData.state = static_cast<int32_t>(ApplicationState::APP_STATE_BACKGROUND);
    appStateData.accessTokenId = tokenID;
    appStateObserver_->OnAppStateChanged(appStateData);
    sleep(1);

    EXPECT_EQ(PERMISSION_GRANTED,
        AccessTokenInfoManager::GetInstance().VerifyAccessToken(tokenID, "ohos.permission.MICROPHONE"));

    backgroundTaskObserver_->OnContinuousTaskStop(continuousTaskCallbackInfo);
    sleep(1);

    EXPECT_EQ(PERMISSION_DENIED,
        AccessTokenInfoManager::GetInstance().VerifyAccessToken(tokenID, "ohos.permission.MICROPHONE"));
    int32_t ret = AccessTokenInfoManager::GetInstance().RemoveHapTokenInfo(tokenID);
    ASSERT_EQ(RET_SUCCESS, ret);
}

/**
 * @tc.name: GrantTempPermission039
 * @tc.desc: Test pasteboard temp permission is not associated with location continuous task
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(PermissionManagerTest, GrantTempPermission039, TestSize.Level0)
{
    accessTokenService_->state_ = ServiceRunningState::STATE_RUNNING;
    accessTokenService_->Initialize();
    TempPermissionObserver::GetInstance().SetCancelTime(200);
    AccessTokenID tokenID = CreateTempHapTokenInfo();
    EXPECT_EQ(RET_SUCCESS, PermissionManager::GetInstance().GrantPermission(tokenID,
        "ohos.permission.READ_PASTEBOARD", PERMISSION_ALLOW_THIS_TIME));

    // Use a fixed test-only continuous task id to verify location task does not keep pasteboard permission alive.
    auto taskInfo = CreateContinuousTaskInfo(tokenID, 1014, {BackgroundMode::LOCATION});
    backgroundTaskObserver_->OnContinuousTaskStart(taskInfo);
    EXPECT_EQ(TempPermissionObserver::GetInstance().continuousTaskIdMap_.end(),
        TempPermissionObserver::GetInstance().continuousTaskIdMap_.find(tokenID));

    AppStateData appStateData;
    appStateData.state = static_cast<int32_t>(ApplicationState::APP_STATE_BACKGROUND);
    appStateData.accessTokenId = tokenID;
    appStateObserver_->OnAppStateChanged(appStateData);
    sleep(1);

    EXPECT_EQ(PERMISSION_DENIED,
        AccessTokenInfoManager::GetInstance().VerifyAccessToken(tokenID, "ohos.permission.READ_PASTEBOARD"));
    int32_t ret = AccessTokenInfoManager::GetInstance().RemoveHapTokenInfo(tokenID);
    ASSERT_EQ(RET_SUCCESS, ret);
}
#endif

/**
 * @tc.name: GrantTempPermission024
 * @tc.desc: Test screen capture temp permission only revoke when app stops
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(PermissionManagerTest, GrantTempPermission024, TestSize.Level0)
{
    accessTokenService_->state_ = ServiceRunningState::STATE_RUNNING;
    accessTokenService_->Initialize();
    TempPermissionObserver::GetInstance().SetCancelTime(200);
    AccessTokenID tokenID = CreateTempHapTokenInfo();
    EXPECT_EQ(RET_SUCCESS, PermissionManager::GetInstance().GrantPermission(tokenID,
        "ohos.permission.CUSTOM_SCREEN_CAPTURE", PERMISSION_ALLOW_THIS_TIME));

    AppStateData appStateData;
    appStateData.state = static_cast<int32_t>(ApplicationState::APP_STATE_BACKGROUND);
    appStateData.accessTokenId = tokenID;
    appStateObserver_->OnAppStateChanged(appStateData);
    sleep(1);

    EXPECT_EQ(PERMISSION_GRANTED,
        AccessTokenInfoManager::GetInstance().VerifyAccessToken(tokenID, "ohos.permission.CUSTOM_SCREEN_CAPTURE"));

    appStateData.state = static_cast<int32_t>(ApplicationState::APP_STATE_TERMINATED);
    appStateObserver_->OnAppStopped(appStateData);
    EXPECT_EQ(PERMISSION_DENIED,
        AccessTokenInfoManager::GetInstance().VerifyAccessToken(tokenID, "ohos.permission.CUSTOM_SCREEN_CAPTURE"));
    int32_t ret = AccessTokenInfoManager::GetInstance().RemoveHapTokenInfo(tokenID);
    ASSERT_EQ(RET_SUCCESS, ret);
}

#ifdef BGTASKMGR_CONTINUOUS_TASK_ENABLE
/**
 * @tc.name: GrantTempPermission025
 * @tc.desc: Test microphone temp permission reacts to continuous task update
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(PermissionManagerTest, GrantTempPermission025, TestSize.Level0)
{
    accessTokenService_->state_ = ServiceRunningState::STATE_RUNNING;
    accessTokenService_->Initialize();
    TempPermissionObserver::GetInstance().SetCancelTime(200);
    AccessTokenID tokenID = CreateTempHapTokenInfo();
    EXPECT_EQ(RET_SUCCESS, PermissionManager::GetInstance().GrantPermission(tokenID,
        "ohos.permission.MICROPHONE", PERMISSION_ALLOW_THIS_TIME));

    // Use a fixed test-only continuous task id to verify task update behavior.
    auto continuousTaskCallbackInfo = CreateContinuousTaskInfo(tokenID, 1002, {BackgroundMode::DATA_TRANSFER});
    backgroundTaskObserver_->OnContinuousTaskStart(continuousTaskCallbackInfo);

    AppStateData appStateData;
    appStateData.state = static_cast<int32_t>(ApplicationState::APP_STATE_BACKGROUND);
    appStateData.accessTokenId = tokenID;
    appStateObserver_->OnAppStateChanged(appStateData);
    sleep(1);
    EXPECT_EQ(PERMISSION_DENIED,
        AccessTokenInfoManager::GetInstance().VerifyAccessToken(tokenID, "ohos.permission.MICROPHONE"));

    EXPECT_EQ(RET_SUCCESS, PermissionManager::GetInstance().GrantPermission(tokenID,
        "ohos.permission.MICROPHONE", PERMISSION_ALLOW_THIS_TIME));
    continuousTaskCallbackInfo->typeIds_.clear();
    continuousTaskCallbackInfo->typeIds_.emplace_back(static_cast<uint32_t>(BackgroundMode::AUDIO_RECORDING));
    continuousTaskCallbackInfo->typeId_ = static_cast<uint32_t>(BackgroundMode::AUDIO_RECORDING);
    backgroundTaskObserver_->OnContinuousTaskUpdate(continuousTaskCallbackInfo);
    sleep(1);
    EXPECT_EQ(PERMISSION_GRANTED,
        AccessTokenInfoManager::GetInstance().VerifyAccessToken(tokenID, "ohos.permission.MICROPHONE"));

    continuousTaskCallbackInfo->typeIds_.clear();
    continuousTaskCallbackInfo->typeIds_.emplace_back(static_cast<uint32_t>(BackgroundMode::DATA_TRANSFER));
    continuousTaskCallbackInfo->typeId_ = static_cast<uint32_t>(BackgroundMode::DATA_TRANSFER);
    backgroundTaskObserver_->OnContinuousTaskUpdate(continuousTaskCallbackInfo);
    sleep(1);
    EXPECT_EQ(PERMISSION_DENIED,
        AccessTokenInfoManager::GetInstance().VerifyAccessToken(tokenID, "ohos.permission.MICROPHONE"));

    backgroundTaskObserver_->OnContinuousTaskStop(continuousTaskCallbackInfo);
    int32_t ret = AccessTokenInfoManager::GetInstance().RemoveHapTokenInfo(tokenID);
    ASSERT_EQ(RET_SUCCESS, ret);
}

/**
 * @tc.name: GrantTempPermission026
 * @tc.desc: Test unrelated task start is not associated for microphone temp permission
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(PermissionManagerTest, GrantTempPermission026, TestSize.Level0)
{
    accessTokenService_->state_ = ServiceRunningState::STATE_RUNNING;
    accessTokenService_->Initialize();
    TempPermissionObserver::GetInstance().SetCancelTime(200);
    AccessTokenID tokenID = CreateTempHapTokenInfo();
    EXPECT_EQ(RET_SUCCESS, PermissionManager::GetInstance().GrantPermission(tokenID,
        "ohos.permission.MICROPHONE", PERMISSION_ALLOW_THIS_TIME));

    // Use a fixed test-only continuous task id to verify unrelated task start is not associated.
    auto taskInfo = CreateContinuousTaskInfo(tokenID, 1003, {BackgroundMode::DATA_TRANSFER});
    backgroundTaskObserver_->OnContinuousTaskStart(taskInfo);
    EXPECT_EQ(TempPermissionObserver::GetInstance().continuousTaskIdMap_.end(),
        TempPermissionObserver::GetInstance().continuousTaskIdMap_.find(tokenID));

    AppStateData appStateData;
    appStateData.state = static_cast<int32_t>(ApplicationState::APP_STATE_BACKGROUND);
    appStateData.accessTokenId = tokenID;
    appStateObserver_->OnAppStateChanged(appStateData);
    sleep(1);

    EXPECT_EQ(PERMISSION_DENIED,
        AccessTokenInfoManager::GetInstance().VerifyAccessToken(tokenID, "ohos.permission.MICROPHONE"));
    int32_t ret = AccessTokenInfoManager::GetInstance().RemoveHapTokenInfo(tokenID);
    ASSERT_EQ(RET_SUCCESS, ret);
}

/**
 * @tc.name: GrantTempPermission027
 * @tc.desc: Test related task start is associated for microphone temp permission
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(PermissionManagerTest, GrantTempPermission027, TestSize.Level0)
{
    accessTokenService_->state_ = ServiceRunningState::STATE_RUNNING;
    accessTokenService_->Initialize();
    TempPermissionObserver::GetInstance().SetCancelTime(200);
    AccessTokenID tokenID = CreateTempHapTokenInfo();
    EXPECT_EQ(RET_SUCCESS, PermissionManager::GetInstance().GrantPermission(tokenID,
        "ohos.permission.MICROPHONE", PERMISSION_ALLOW_THIS_TIME));

    // Use a fixed test-only continuous task id to verify related task start is associated.
    auto taskInfo = CreateContinuousTaskInfo(tokenID, 1004, {BackgroundMode::VOIP});
    backgroundTaskObserver_->OnContinuousTaskStart(taskInfo);
    auto tokenIter = TempPermissionObserver::GetInstance().continuousTaskIdMap_.find(tokenID);
    ASSERT_NE(TempPermissionObserver::GetInstance().continuousTaskIdMap_.end(), tokenIter);
    EXPECT_NE(tokenIter->second.end(), tokenIter->second.find(1004));

    AppStateData appStateData;
    appStateData.state = static_cast<int32_t>(ApplicationState::APP_STATE_BACKGROUND);
    appStateData.accessTokenId = tokenID;
    appStateObserver_->OnAppStateChanged(appStateData);
    sleep(1);

    EXPECT_EQ(PERMISSION_GRANTED,
        AccessTokenInfoManager::GetInstance().VerifyAccessToken(tokenID, "ohos.permission.MICROPHONE"));
    int32_t ret = AccessTokenInfoManager::GetInstance().RemoveHapTokenInfo(tokenID);
    ASSERT_EQ(RET_SUCCESS, ret);
}

/**
 * @tc.name: GrantTempPermission028
 * @tc.desc: Test task update can associate an unassociated task to microphone temp permission
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(PermissionManagerTest, GrantTempPermission028, TestSize.Level0)
{
    accessTokenService_->state_ = ServiceRunningState::STATE_RUNNING;
    accessTokenService_->Initialize();
    TempPermissionObserver::GetInstance().SetCancelTime(200);
    AccessTokenID tokenID = CreateTempHapTokenInfo();
    EXPECT_EQ(RET_SUCCESS, PermissionManager::GetInstance().GrantPermission(tokenID,
        "ohos.permission.MICROPHONE", PERMISSION_ALLOW_THIS_TIME));

    // Use a fixed test-only continuous task id to verify update can associate an existing task.
    auto taskInfo = CreateContinuousTaskInfo(tokenID, 1005, {BackgroundMode::DATA_TRANSFER});
    backgroundTaskObserver_->OnContinuousTaskStart(taskInfo);
    EXPECT_EQ(TempPermissionObserver::GetInstance().continuousTaskIdMap_.end(),
        TempPermissionObserver::GetInstance().continuousTaskIdMap_.find(tokenID));

    taskInfo->typeIds_.clear();
    taskInfo->typeIds_.emplace_back(static_cast<uint32_t>(BackgroundMode::AUDIO_RECORDING));
    taskInfo->typeId_ = static_cast<uint32_t>(BackgroundMode::AUDIO_RECORDING);
    backgroundTaskObserver_->OnContinuousTaskUpdate(taskInfo);
    auto tokenIter = TempPermissionObserver::GetInstance().continuousTaskIdMap_.find(tokenID);
    ASSERT_NE(TempPermissionObserver::GetInstance().continuousTaskIdMap_.end(), tokenIter);
    EXPECT_NE(tokenIter->second.end(), tokenIter->second.find(1005));

    AppStateData appStateData;
    appStateData.state = static_cast<int32_t>(ApplicationState::APP_STATE_BACKGROUND);
    appStateData.accessTokenId = tokenID;
    appStateObserver_->OnAppStateChanged(appStateData);
    sleep(1);

    EXPECT_EQ(PERMISSION_GRANTED,
        AccessTokenInfoManager::GetInstance().VerifyAccessToken(tokenID, "ohos.permission.MICROPHONE"));
    int32_t ret = AccessTokenInfoManager::GetInstance().RemoveHapTokenInfo(tokenID);
    ASSERT_EQ(RET_SUCCESS, ret);
}

/**
 * @tc.name: GrantTempPermission029
 * @tc.desc: Test task stop removes association and then revokes microphone temp permission
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(PermissionManagerTest, GrantTempPermission029, TestSize.Level0)
{
    accessTokenService_->state_ = ServiceRunningState::STATE_RUNNING;
    accessTokenService_->Initialize();
    TempPermissionObserver::GetInstance().SetCancelTime(200);
    AccessTokenID tokenID = CreateTempHapTokenInfo();
    EXPECT_EQ(RET_SUCCESS, PermissionManager::GetInstance().GrantPermission(tokenID,
        "ohos.permission.MICROPHONE", PERMISSION_ALLOW_THIS_TIME));

    // Use a fixed test-only continuous task id to verify stop removes the associated task.
    auto taskInfo = CreateContinuousTaskInfo(tokenID, 1006, {BackgroundMode::AUDIO_RECORDING});
    backgroundTaskObserver_->OnContinuousTaskStart(taskInfo);

    AppStateData appStateData;
    appStateData.state = static_cast<int32_t>(ApplicationState::APP_STATE_BACKGROUND);
    appStateData.accessTokenId = tokenID;
    appStateObserver_->OnAppStateChanged(appStateData);
    sleep(1);
    EXPECT_EQ(PERMISSION_GRANTED,
        AccessTokenInfoManager::GetInstance().VerifyAccessToken(tokenID, "ohos.permission.MICROPHONE"));

    backgroundTaskObserver_->OnContinuousTaskStop(taskInfo);
    auto tokenIter = TempPermissionObserver::GetInstance().continuousTaskIdMap_.find(tokenID);
    EXPECT_TRUE(tokenIter == TempPermissionObserver::GetInstance().continuousTaskIdMap_.end() ||
        tokenIter->second.find(1006) == tokenIter->second.end());
    sleep(1);

    EXPECT_EQ(PERMISSION_DENIED,
        AccessTokenInfoManager::GetInstance().VerifyAccessToken(tokenID, "ohos.permission.MICROPHONE"));
    int32_t ret = AccessTokenInfoManager::GetInstance().RemoveHapTokenInfo(tokenID);
    ASSERT_EQ(RET_SUCCESS, ret);
}

/**
 * @tc.name: GrantTempPermission030
 * @tc.desc: Test microphone temp permission revoke after background without continuous task
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(PermissionManagerTest, GrantTempPermission030, TestSize.Level0)
{
    accessTokenService_->state_ = ServiceRunningState::STATE_RUNNING;
    accessTokenService_->Initialize();
    TempPermissionObserver::GetInstance().SetCancelTime(200);
    AccessTokenID tokenID = CreateTempHapTokenInfo();
    EXPECT_EQ(RET_SUCCESS, PermissionManager::GetInstance().GrantPermission(tokenID,
        "ohos.permission.MICROPHONE", PERMISSION_ALLOW_THIS_TIME));

    AppStateData appStateData;
    appStateData.state = static_cast<int32_t>(ApplicationState::APP_STATE_BACKGROUND);
    appStateData.accessTokenId = tokenID;
    appStateObserver_->OnAppStateChanged(appStateData);
    sleep(1);

    EXPECT_EQ(PERMISSION_DENIED,
        AccessTokenInfoManager::GetInstance().VerifyAccessToken(tokenID, "ohos.permission.MICROPHONE"));
    int32_t ret = AccessTokenInfoManager::GetInstance().RemoveHapTokenInfo(tokenID);
    ASSERT_EQ(RET_SUCCESS, ret);
}

/**
 * @tc.name: GrantTempPermission031
 * @tc.desc: Test microphone temp permission keep after second related task starts and first task stops
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(PermissionManagerTest, GrantTempPermission031, TestSize.Level0)
{
    accessTokenService_->state_ = ServiceRunningState::STATE_RUNNING;
    accessTokenService_->Initialize();
    TempPermissionObserver::GetInstance().SetCancelTime(200);
    AccessTokenID tokenID = CreateTempHapTokenInfo();
    EXPECT_EQ(RET_SUCCESS, PermissionManager::GetInstance().GrantPermission(tokenID,
        "ohos.permission.MICROPHONE", PERMISSION_ALLOW_THIS_TIME));

    // Use fixed test-only continuous task ids to verify multiple related tasks keep permission alive.
    auto audioTaskInfo = CreateContinuousTaskInfo(tokenID, 1007, {BackgroundMode::AUDIO_RECORDING});
    backgroundTaskObserver_->OnContinuousTaskStart(audioTaskInfo);
    auto voipTaskInfo = CreateContinuousTaskInfo(tokenID, 1008, {BackgroundMode::VOIP});
    backgroundTaskObserver_->OnContinuousTaskStart(voipTaskInfo);

    AppStateData appStateData;
    appStateData.state = static_cast<int32_t>(ApplicationState::APP_STATE_BACKGROUND);
    appStateData.accessTokenId = tokenID;
    appStateObserver_->OnAppStateChanged(appStateData);
    sleep(1);

    EXPECT_EQ(PERMISSION_GRANTED,
        AccessTokenInfoManager::GetInstance().VerifyAccessToken(tokenID, "ohos.permission.MICROPHONE"));

    backgroundTaskObserver_->OnContinuousTaskStop(audioTaskInfo);
    auto tokenIter = TempPermissionObserver::GetInstance().continuousTaskIdMap_.find(tokenID);
    ASSERT_NE(TempPermissionObserver::GetInstance().continuousTaskIdMap_.end(), tokenIter);
    EXPECT_EQ(tokenIter->second.end(), tokenIter->second.find(1007));
    EXPECT_NE(tokenIter->second.end(), tokenIter->second.find(1008));
    sleep(1);

    EXPECT_EQ(PERMISSION_GRANTED,
        AccessTokenInfoManager::GetInstance().VerifyAccessToken(tokenID, "ohos.permission.MICROPHONE"));

    backgroundTaskObserver_->OnContinuousTaskStop(voipTaskInfo);
    sleep(1);
    EXPECT_EQ(PERMISSION_DENIED,
        AccessTokenInfoManager::GetInstance().VerifyAccessToken(tokenID, "ohos.permission.MICROPHONE"));
    int32_t ret = AccessTokenInfoManager::GetInstance().RemoveHapTokenInfo(tokenID);
    ASSERT_EQ(RET_SUCCESS, ret);
}

/**
 * @tc.name: GrantTempPermission032
 * @tc.desc: Test location temp permission start with related task is associated and kept in background
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(PermissionManagerTest, GrantTempPermission032, TestSize.Level0)
{
    accessTokenService_->state_ = ServiceRunningState::STATE_RUNNING;
    accessTokenService_->Initialize();
    TempPermissionObserver::GetInstance().SetCancelTime(200);
    AccessTokenID tokenID = CreateTempHapTokenInfo();
    EXPECT_EQ(RET_SUCCESS, PermissionManager::GetInstance().GrantPermission(tokenID,
        "ohos.permission.APPROXIMATELY_LOCATION", PERMISSION_ALLOW_THIS_TIME));

    // Use a fixed test-only continuous task id to verify related location task start is associated.
    auto taskInfo = CreateContinuousTaskInfo(tokenID, 1009, {BackgroundMode::LOCATION});
    backgroundTaskObserver_->OnContinuousTaskStart(taskInfo);
    auto tokenIter = TempPermissionObserver::GetInstance().continuousTaskIdMap_.find(tokenID);
    ASSERT_NE(TempPermissionObserver::GetInstance().continuousTaskIdMap_.end(), tokenIter);
    EXPECT_NE(tokenIter->second.end(), tokenIter->second.find(1009));

    AppStateData appStateData;
    appStateData.state = static_cast<int32_t>(ApplicationState::APP_STATE_BACKGROUND);
    appStateData.accessTokenId = tokenID;
    appStateObserver_->OnAppStateChanged(appStateData);
    sleep(1);

    EXPECT_EQ(PERMISSION_GRANTED,
        AccessTokenInfoManager::GetInstance().VerifyAccessToken(tokenID, "ohos.permission.APPROXIMATELY_LOCATION"));
    int32_t ret = AccessTokenInfoManager::GetInstance().RemoveHapTokenInfo(tokenID);
    ASSERT_EQ(RET_SUCCESS, ret);
}

/**
 * @tc.name: GrantTempPermission033
 * @tc.desc: Test location temp permission update associates task and stop removes it
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(PermissionManagerTest, GrantTempPermission033, TestSize.Level0)
{
    accessTokenService_->state_ = ServiceRunningState::STATE_RUNNING;
    accessTokenService_->Initialize();
    TempPermissionObserver::GetInstance().SetCancelTime(200);
    AccessTokenID tokenID = CreateTempHapTokenInfo();
    EXPECT_EQ(RET_SUCCESS, PermissionManager::GetInstance().GrantPermission(tokenID,
        "ohos.permission.APPROXIMATELY_LOCATION", PERMISSION_ALLOW_THIS_TIME));

    // Use a fixed test-only continuous task id to verify location task update and stop behavior.
    auto taskInfo = CreateContinuousTaskInfo(tokenID, 1010, {BackgroundMode::DATA_TRANSFER});
    backgroundTaskObserver_->OnContinuousTaskStart(taskInfo);
    EXPECT_EQ(TempPermissionObserver::GetInstance().continuousTaskIdMap_.end(),
        TempPermissionObserver::GetInstance().continuousTaskIdMap_.find(tokenID));

    taskInfo->typeIds_.clear();
    taskInfo->typeIds_.emplace_back(static_cast<uint32_t>(BackgroundMode::LOCATION));
    taskInfo->typeId_ = static_cast<uint32_t>(BackgroundMode::LOCATION);
    backgroundTaskObserver_->OnContinuousTaskUpdate(taskInfo);
    auto tokenIter = TempPermissionObserver::GetInstance().continuousTaskIdMap_.find(tokenID);
    ASSERT_NE(TempPermissionObserver::GetInstance().continuousTaskIdMap_.end(), tokenIter);
    EXPECT_NE(tokenIter->second.end(), tokenIter->second.find(1010));

    AppStateData appStateData;
    appStateData.state = static_cast<int32_t>(ApplicationState::APP_STATE_BACKGROUND);
    appStateData.accessTokenId = tokenID;
    appStateObserver_->OnAppStateChanged(appStateData);
    sleep(1);
    EXPECT_EQ(PERMISSION_GRANTED,
        AccessTokenInfoManager::GetInstance().VerifyAccessToken(tokenID, "ohos.permission.APPROXIMATELY_LOCATION"));

    backgroundTaskObserver_->OnContinuousTaskStop(taskInfo);
    tokenIter = TempPermissionObserver::GetInstance().continuousTaskIdMap_.find(tokenID);
    EXPECT_TRUE(tokenIter == TempPermissionObserver::GetInstance().continuousTaskIdMap_.end() ||
        tokenIter->second.find(1010) == tokenIter->second.end());
    sleep(1);
    EXPECT_EQ(PERMISSION_DENIED,
        AccessTokenInfoManager::GetInstance().VerifyAccessToken(tokenID, "ohos.permission.APPROXIMATELY_LOCATION"));
    int32_t ret = AccessTokenInfoManager::GetInstance().RemoveHapTokenInfo(tokenID);
    ASSERT_EQ(RET_SUCCESS, ret);
}

/**
 * @tc.name: GrantTempPermission034
 * @tc.desc: Test location unrelated task start is not associated and permission is revoked in background
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(PermissionManagerTest, GrantTempPermission034, TestSize.Level0)
{
    accessTokenService_->state_ = ServiceRunningState::STATE_RUNNING;
    accessTokenService_->Initialize();
    TempPermissionObserver::GetInstance().SetCancelTime(200);
    AccessTokenID tokenID = CreateTempHapTokenInfo();
    EXPECT_EQ(RET_SUCCESS, PermissionManager::GetInstance().GrantPermission(tokenID,
        "ohos.permission.APPROXIMATELY_LOCATION", PERMISSION_ALLOW_THIS_TIME));

    // Use a fixed test-only continuous task id to verify unrelated location task is not associated.
    auto taskInfo = CreateContinuousTaskInfo(tokenID, 1011, {BackgroundMode::DATA_TRANSFER});
    backgroundTaskObserver_->OnContinuousTaskStart(taskInfo);
    EXPECT_EQ(TempPermissionObserver::GetInstance().continuousTaskIdMap_.end(),
        TempPermissionObserver::GetInstance().continuousTaskIdMap_.find(tokenID));

    AppStateData appStateData;
    appStateData.state = static_cast<int32_t>(ApplicationState::APP_STATE_BACKGROUND);
    appStateData.accessTokenId = tokenID;
    appStateObserver_->OnAppStateChanged(appStateData);
    sleep(1);

    EXPECT_EQ(PERMISSION_DENIED,
        AccessTokenInfoManager::GetInstance().VerifyAccessToken(tokenID, "ohos.permission.APPROXIMATELY_LOCATION"));
    int32_t ret = AccessTokenInfoManager::GetInstance().RemoveHapTokenInfo(tokenID);
    ASSERT_EQ(RET_SUCCESS, ret);
}

/**
 * @tc.name: GrantTempPermission035
 * @tc.desc: Test continuous task callbacks ignore nullptr input
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(PermissionManagerTest, GrantTempPermission035, TestSize.Level0)
{
    accessTokenService_->state_ = ServiceRunningState::STATE_RUNNING;
    accessTokenService_->Initialize();
    AccessTokenID tokenID = CreateTempHapTokenInfo();
    EXPECT_EQ(RET_SUCCESS, PermissionManager::GetInstance().GrantPermission(tokenID,
        "ohos.permission.MICROPHONE", PERMISSION_ALLOW_THIS_TIME));

    backgroundTaskObserver_->OnContinuousTaskStart(nullptr);
    backgroundTaskObserver_->OnContinuousTaskUpdate(nullptr);
    backgroundTaskObserver_->OnContinuousTaskStop(nullptr);

    EXPECT_EQ(TempPermissionObserver::GetInstance().continuousTaskIdMap_.end(),
        TempPermissionObserver::GetInstance().continuousTaskIdMap_.find(tokenID));
    EXPECT_EQ(PERMISSION_GRANTED,
        AccessTokenInfoManager::GetInstance().VerifyAccessToken(tokenID, "ohos.permission.MICROPHONE"));

    int32_t ret = AccessTokenInfoManager::GetInstance().RemoveHapTokenInfo(tokenID);
    ASSERT_EQ(RET_SUCCESS, ret);
}

/**
 * @tc.name: GrantTempPermission036
 * @tc.desc: Test continuous task callbacks ignore token not tracked by temp permission observer
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(PermissionManagerTest, GrantTempPermission036, TestSize.Level0)
{
    accessTokenService_->state_ = ServiceRunningState::STATE_RUNNING;
    accessTokenService_->Initialize();
    AccessTokenID tokenID = CreateTempHapTokenInfo();

    // Use a fixed test-only continuous task id to verify callbacks ignore tokens without temp permission state.
    auto taskInfo = CreateContinuousTaskInfo(tokenID, 1012, {BackgroundMode::AUDIO_RECORDING});
    backgroundTaskObserver_->OnContinuousTaskStart(taskInfo);
    backgroundTaskObserver_->OnContinuousTaskUpdate(taskInfo);
    backgroundTaskObserver_->OnContinuousTaskStop(taskInfo);

    EXPECT_EQ(TempPermissionObserver::GetInstance().continuousTaskIdMap_.end(),
        TempPermissionObserver::GetInstance().continuousTaskIdMap_.find(tokenID));
    EXPECT_EQ(PERMISSION_DENIED,
        AccessTokenInfoManager::GetInstance().VerifyAccessToken(tokenID, "ohos.permission.MICROPHONE"));

    int32_t ret = AccessTokenInfoManager::GetInstance().RemoveHapTokenInfo(tokenID);
    ASSERT_EQ(RET_SUCCESS, ret);
}

/**
 * @tc.name: GrantTempPermission037
 * @tc.desc: Test form invisible does not revoke location temp permission while app is still foreground
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(PermissionManagerTest, GrantTempPermission037, TestSize.Level0)
{
    accessTokenService_->state_ = ServiceRunningState::STATE_RUNNING;
    accessTokenService_->Initialize();
    TempPermissionObserver::GetInstance().SetCancelTime(200);
    AccessTokenID tokenID = CreateTempHapTokenInfo();
    EXPECT_EQ(RET_SUCCESS, PermissionManager::GetInstance().GrantPermission(tokenID,
        "ohos.permission.APPROXIMATELY_LOCATION", PERMISSION_ALLOW_THIS_TIME));

    AppStateData appStateData;
    appStateData.state = static_cast<int32_t>(ApplicationState::APP_STATE_FOREGROUND);
    appStateData.accessTokenId = tokenID;
    appStateObserver_->OnAppStateChanged(appStateData);

    FormInstance formInstance;
    formInstance.bundleName_ = "GrantTempPermission";
    formInstance.appIndex_ = 0;
    formInstance.userId_ = USER_ID;
    formInstance.formVisiblity_ = FormVisibilityType::INVISIBLE;
    std::vector<FormInstance> formInstances;
    formInstances.emplace_back(formInstance);
    EXPECT_EQ(RET_SUCCESS,
        formStateObserver_->NotifyWhetherFormsVisible(FormVisibilityType::INVISIBLE, "#1", formInstances));
    sleep(1);

    EXPECT_EQ(PERMISSION_GRANTED,
        AccessTokenInfoManager::GetInstance().VerifyAccessToken(tokenID, "ohos.permission.APPROXIMATELY_LOCATION"));
    int32_t ret = AccessTokenInfoManager::GetInstance().RemoveHapTokenInfo(tokenID);
    ASSERT_EQ(RET_SUCCESS, ret);
}

/**
 * @tc.name: GrantTempPermission038
 * @tc.desc: Test form invisible does not revoke location temp permission while location task still exists
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(PermissionManagerTest, GrantTempPermission038, TestSize.Level0)
{
    accessTokenService_->state_ = ServiceRunningState::STATE_RUNNING;
    accessTokenService_->Initialize();
    TempPermissionObserver::GetInstance().SetCancelTime(200);
    AccessTokenID tokenID = CreateTempHapTokenInfo();
    EXPECT_EQ(RET_SUCCESS, PermissionManager::GetInstance().GrantPermission(tokenID,
        "ohos.permission.APPROXIMATELY_LOCATION", PERMISSION_ALLOW_THIS_TIME));

    // Use a fixed test-only continuous task id to verify form invisible keeps permission while location task exists.
    auto taskInfo = CreateContinuousTaskInfo(tokenID, 1013, {BackgroundMode::LOCATION});
    backgroundTaskObserver_->OnContinuousTaskStart(taskInfo);

    AppStateData appStateData;
    appStateData.state = static_cast<int32_t>(ApplicationState::APP_STATE_BACKGROUND);
    appStateData.accessTokenId = tokenID;
    appStateObserver_->OnAppStateChanged(appStateData);

    FormInstance formInstance;
    formInstance.bundleName_ = "GrantTempPermission";
    formInstance.appIndex_ = 0;
    formInstance.userId_ = USER_ID;
    formInstance.formVisiblity_ = FormVisibilityType::INVISIBLE;
    std::vector<FormInstance> formInstances;
    formInstances.emplace_back(formInstance);
    EXPECT_EQ(RET_SUCCESS,
        formStateObserver_->NotifyWhetherFormsVisible(FormVisibilityType::INVISIBLE, "#1", formInstances));
    sleep(1);

    EXPECT_EQ(PERMISSION_GRANTED,
        AccessTokenInfoManager::GetInstance().VerifyAccessToken(tokenID, "ohos.permission.APPROXIMATELY_LOCATION"));
    auto tokenIter = TempPermissionObserver::GetInstance().continuousTaskIdMap_.find(tokenID);
    ASSERT_NE(TempPermissionObserver::GetInstance().continuousTaskIdMap_.end(), tokenIter);
    EXPECT_NE(tokenIter->second.end(), tokenIter->second.find(1013));

    backgroundTaskObserver_->OnContinuousTaskStop(taskInfo);
    sleep(1);
    EXPECT_EQ(PERMISSION_DENIED,
        AccessTokenInfoManager::GetInstance().VerifyAccessToken(tokenID, "ohos.permission.APPROXIMATELY_LOCATION"));

    int32_t ret = AccessTokenInfoManager::GetInstance().RemoveHapTokenInfo(tokenID);
    ASSERT_EQ(RET_SUCCESS, ret);
}
#endif
} // namespace AccessToken
} // namespace Security
} // namespace OHOS
