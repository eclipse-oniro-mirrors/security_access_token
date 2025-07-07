/*
 * Copyright (c) 2021-2024 Huawei Device Co., Ltd.
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
#include "callback_manager.h"
#ifdef SUPPORT_SANDBOX_APP
#define private public
#include "dlp_permission_set_manager.h"
#undef private
#endif
#define private public
#include "accesstoken_info_manager.h"
#undef private
#include "accesstoken_callback_stubs.h"
#include "callback_death_recipients.h"
#ifdef BGTASKMGR_CONTINUOUS_TASK_ENABLE
#include "background_task_manager_access_client.h"
#include "continuous_task_callback_info.h"
#endif

using namespace testing::ext;
using namespace OHOS;

namespace OHOS {
namespace Security {
namespace AccessToken {
namespace {
static constexpr uint32_t MAX_CALLBACK_SIZE = 1024;
static constexpr int32_t USER_ID = 100;
static constexpr int32_t INST_INDEX = 0;
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
    .permissionName = "open the door",
    .grantStatus = 1,
    .grantFlag = 1
};

static PermissionStatus g_infoManagerTestState2 = {
    .permissionName = "break the door",
    .grantStatus = 1,
    .grantFlag = 1
};

static HapInfoParams g_infoManagerTestInfoParms = {
    .userID = 1,
    .bundleName = "accesstoken_test",
    .instIndex = 0,
    .appIDDesc = "testtesttesttest"
};

static HapPolicy g_infoManagerTestPolicyPrams1 = {
    .apl = APL_NORMAL,
    .domain = "test.domain",
    .permList = {g_infoManagerTestPermDef1, g_infoManagerTestPermDef2},
    .permStateList = {g_infoManagerTestState1, g_infoManagerTestState2}
};

static PermissionStatus g_infoManagerTestStateA = {
    .grantStatus = PERMISSION_GRANTED,
    .grantFlag = 1
};

static PermissionStatus g_infoManagerTestStateB = {
    .grantStatus = PERMISSION_GRANTED,
    .grantFlag = 1
};

static PermissionStatus g_infoManagerTestStateC = {
    .grantStatus = PERMISSION_GRANTED,
    .grantFlag = 1
};

static PermissionStatus g_infoManagerTestStateD = {
    .grantStatus = PERMISSION_GRANTED,
    .grantFlag = 1
};

static PermissionStatus g_permState1 = {
    .permissionName = "ohos.permission.TEST",
    .grantStatus = PermissionState::PERMISSION_DENIED,
    .grantFlag = PermissionFlag::PERMISSION_SYSTEM_FIXED
};

static PermissionStatus g_permState2 = {
    .permissionName = "ohos.permission.CAMERA",
    .grantStatus = PermissionState::PERMISSION_DENIED,
    .grantFlag = PermissionFlag::PERMISSION_SYSTEM_FIXED
};

static PermissionStatus g_permState6 = {
    .permissionName = "ohos.permission.CAMERA",
    .grantStatus = PermissionState::PERMISSION_DENIED,
    .grantFlag = PermissionFlag::PERMISSION_FIXED_FOR_SECURITY_POLICY
};

static PermissionStatus g_permState7 = {
    .permissionName = "ohos.permission.CAMERA",
    .grantStatus = PermissionState::PERMISSION_GRANTED,
    .grantFlag = PermissionFlag::PERMISSION_FIXED_FOR_SECURITY_POLICY
};

static PermissionStatus g_permState8 = {
    .permissionName = "ohos.permission.CAMERA",
    .grantStatus = PermissionState::PERMISSION_DENIED,
    .grantFlag = PermissionFlag::PERMISSION_FIXED_FOR_SECURITY_POLICY | PermissionFlag::PERMISSION_USER_SET
};

static PermissionStatus g_permState9 = {
    .permissionName = "ohos.permission.CAMERA",
    .grantStatus = PermissionState::PERMISSION_GRANTED,
    .grantFlag = PermissionFlag::PERMISSION_FIXED_FOR_SECURITY_POLICY | PermissionFlag::PERMISSION_USER_SET
};

static PermissionStatus g_permState10 = {
    .permissionName = "ohos.permission.CAMERA",
    .grantStatus = PermissionState::PERMISSION_DENIED,
    .grantFlag = PermissionFlag::PERMISSION_FIXED_BY_ADMIN_POLICY
};

static PermissionStatus g_permState11 = {
    .permissionName = "ohos.permission.CAMERA",
    .grantStatus = PermissionState::PERMISSION_DENIED,
    .grantFlag = PermissionFlag::PERMISSION_ADMIN_POLICIES_CANCEL
};

static PermissionStatus g_permState12 = {
    .permissionName = "ohos.permission.CAMERA",
    .grantStatus = PermissionState::PERMISSION_DENIED,
    .grantFlag = PermissionFlag::PERMISSION_DEFAULT_FLAG
};

static PermissionStatus g_permState13 = {
    .permissionName = "ohos.permission.CAMERA",
    .grantStatus = PermissionState::PERMISSION_DENIED,
    .grantFlag = PermissionFlag::PERMISSION_USER_FIXED
};

static PermissionDef g_infoManagerPermDef1 = {
    .permissionName = "ohos.permission.MEDIA_LOCATION",
    .bundleName = "accesstoken_test",
    .grantMode = USER_GRANT,
    .availableLevel = APL_NORMAL,
    .provisionEnable = false,
    .distributedSceneEnable = false,
    .label = "label",
    .labelId = 1,
    .description = "MEDIA_LOCATION",
    .descriptionId = 1
};

static PermissionDef g_infoManagerPermDef2 = {
    .permissionName = "ohos.permission.MICROPHONE",
    .bundleName = "accesstoken_test",
    .grantMode = USER_GRANT,
    .availableLevel = APL_NORMAL,
    .provisionEnable = false,
    .distributedSceneEnable = false,
    .label = "label",
    .labelId = 1,
    .description = "MICROPHONE",
    .descriptionId = 1
};

static PermissionDef g_infoManagerPermDef3 = {
    .permissionName = "ohos.permission.READ_CALENDAR",
    .bundleName = "accesstoken_test",
    .grantMode = USER_GRANT,
    .availableLevel = APL_NORMAL,
    .provisionEnable = false,
    .distributedSceneEnable = false,
    .label = "label",
    .labelId = 1,
    .description = "READ_CALENDAR",
    .descriptionId = 1
};

static PermissionDef g_infoManagerPermDef4 = {
    .permissionName = "ohos.permission.READ_CALL_LOG",
    .bundleName = "accesstoken_test",
    .grantMode = USER_GRANT,
    .availableLevel = APL_NORMAL,
    .provisionEnable = false,
    .distributedSceneEnable = false,
    .label = "label",
    .labelId = 1,
    .description = "READ_CALL_LOG",
    .descriptionId = 1
};
}

void PermissionManagerTest::SetUpTestCase()
{
}

void PermissionManagerTest::TearDownTestCase()
{
    sleep(3); // delay 3 minutes
}

void PermissionManagerTest::SetUp()
{
    if (accessTokenService_ != nullptr) {
        return;
    }
    AccessTokenManagerService* ptr = new (std::nothrow) AccessTokenManagerService();
    accessTokenService_ = sptr<AccessTokenManagerService>(ptr);
    ASSERT_NE(nullptr, accessTokenService_);
    if (appStateObserver_ != nullptr) {
        return;
    }
    appStateObserver_ = std::make_shared<PermissionAppStateObserver>();
#ifdef BGTASKMGR_CONTINUOUS_TASK_ENABLE
    if (backgroundTaskObserver_ != nullptr) {
        return;
    }
    backgroundTaskObserver_ = std::make_shared<PermissionBackgroundTaskObserver>();
#endif
    if (formStateObserver_ != nullptr) {
        return;
    }
    formStateObserver_ = std::make_shared<PermissionFormStateObserver>();
}

void PermissionManagerTest::TearDown()
{
    accessTokenService_ = nullptr;
    appStateObserver_ = nullptr;
}

static AccessTokenID CreateTempHapTokenInfo()
{
    g_infoManagerTestStateA.permissionName = "ohos.permission.APPROXIMATELY_LOCATION";
    g_infoManagerTestStateA.grantStatus = PERMISSION_DENIED;
    g_infoManagerTestStateB.permissionName = "ohos.permission.READ_PASTEBOARD";
    g_infoManagerTestStateB.grantStatus = PERMISSION_DENIED;
    static HapPolicy infoManagerTestPolicyPrams = {
        .apl = APL_NORMAL,
        .domain = "test.domain",
        .permList = {},
        .permStateList = { g_infoManagerTestStateA, g_infoManagerTestStateB}
    };
    static HapInfoParams infoManagerTestInfoParms = {
        .userID = USER_ID,
        .bundleName = "GrantTempPermission",
        .instIndex = 0,
        .dlpType = DLP_COMMON,
        .appIDDesc = "GrantTempPermission"
    };
    // install hap
    AccessTokenIDEx tokenIdEx = {0};
    std::vector<GenericValues> undefValues;
    AccessTokenInfoManager::GetInstance().CreateHapTokenInfo(
        infoManagerTestInfoParms, infoManagerTestPolicyPrams, tokenIdEx, undefValues);
    GTEST_LOG_(INFO) << "add a hap token";
    AccessTokenID tokenID = tokenIdEx.tokenIdExStruct.tokenID;
    return tokenID;
}

/**
 * @tc.name: ScopeFilter001
 * @tc.desc: Test filter scopes.
 * @tc.type: FUNC
 * @tc.require: issueI4V02P
 */
HWTEST_F(PermissionManagerTest, ScopeFilter001, TestSize.Level0)
{
    AccessTokenIDEx tokenIdEx = {0};
    std::vector<GenericValues> undefValues;
    AccessTokenInfoManager::GetInstance().CreateHapTokenInfo(g_infoManagerTestInfoParms,
        g_infoManagerTestPolicyPrams1, tokenIdEx, undefValues);

    tokenIdEx = AccessTokenInfoManager::GetInstance().GetHapTokenID(g_infoManagerTestInfoParms.userID,
        g_infoManagerTestInfoParms.bundleName, g_infoManagerTestInfoParms.instIndex);
    AccessTokenID tokenId = tokenIdEx.tokenIdExStruct.tokenID;
    EXPECT_NE(0, static_cast<int32_t>(tokenId));
    PermStateChangeScope inScopeInfo;
    PermStateChangeScope outScopeInfo;
    PermStateChangeScope emptyScopeInfo;

    // both empty
    inScopeInfo.permList = {};
    inScopeInfo.tokenIDs = {};
    EXPECT_EQ(RET_SUCCESS, PermissionManager::GetInstance().ScopeFilter(inScopeInfo, outScopeInfo));

    outScopeInfo = emptyScopeInfo;
    inScopeInfo.tokenIDs = {123};
    EXPECT_EQ(ERR_PARAM_INVALID,
        PermissionManager::GetInstance().ScopeFilter(inScopeInfo, outScopeInfo));
    EXPECT_EQ(true, outScopeInfo.tokenIDs.empty());

    outScopeInfo = emptyScopeInfo;
    inScopeInfo.tokenIDs.clear();
    inScopeInfo.tokenIDs = {123, tokenId, tokenId};
    EXPECT_EQ(RET_SUCCESS, PermissionManager::GetInstance().ScopeFilter(inScopeInfo, outScopeInfo));
    EXPECT_EQ(1, static_cast<int32_t>(outScopeInfo.tokenIDs.size()));

    outScopeInfo = emptyScopeInfo;
    inScopeInfo.tokenIDs.clear();
    inScopeInfo.permList = {"ohos.permission.test_scopeFilter"};
    EXPECT_EQ(ERR_PARAM_INVALID,
        PermissionManager::GetInstance().ScopeFilter(inScopeInfo, outScopeInfo));
    EXPECT_EQ(true, outScopeInfo.permList.empty());

    outScopeInfo = emptyScopeInfo;
    inScopeInfo.permList.clear();
    inScopeInfo.permList = {"ohos.permission.test_scopeFilter", "ohos.permission.CAMERA", "ohos.permission.CAMERA"};
    EXPECT_EQ(RET_SUCCESS, PermissionManager::GetInstance().ScopeFilter(inScopeInfo, outScopeInfo));
    EXPECT_EQ(1, static_cast<int32_t>(outScopeInfo.permList.size()));

    outScopeInfo = emptyScopeInfo;
    inScopeInfo.permList.clear();
    inScopeInfo.tokenIDs = {123, tokenId, tokenId};
    inScopeInfo.permList = {"ohos.permission.test_scopeFilter", "ohos.permission.CAMERA", "ohos.permission.CAMERA"};
    EXPECT_EQ(RET_SUCCESS, PermissionManager::GetInstance().ScopeFilter(inScopeInfo, outScopeInfo));
    EXPECT_EQ(1, static_cast<int32_t>(outScopeInfo.tokenIDs.size()));
    EXPECT_EQ(1, static_cast<int32_t>(outScopeInfo.permList.size()));

    ASSERT_EQ(RET_SUCCESS, AccessTokenInfoManager::GetInstance().RemoveHapTokenInfo(tokenId));
}

/**
 * @tc.name: AddPermStateChangeCallback001
 * @tc.desc: Test AddPermStateChangeCallback.
 * @tc.type: FUNC
 * @tc.require: issueI4V02P
 */
HWTEST_F(PermissionManagerTest, AddPermStateChangeCallback001, TestSize.Level0)
{
    PermStateChangeScope inScopeInfo;
    inScopeInfo.tokenIDs = {123};

    EXPECT_EQ(ERR_PARAM_INVALID,
        PermissionManager::GetInstance().AddPermStateChangeCallback(inScopeInfo, nullptr));

    inScopeInfo.permList = {"ohos.permission.CAMERA"};
    EXPECT_EQ(ERR_PARAM_INVALID,
        PermissionManager::GetInstance().AddPermStateChangeCallback(inScopeInfo, nullptr));
    EXPECT_EQ(ERR_PARAM_INVALID,
        PermissionManager::GetInstance().RemovePermStateChangeCallback(nullptr));
}

class PermChangeCallback : public PermissionStateChangeCallbackStub {
public:
    PermChangeCallback() = default;
    virtual ~PermChangeCallback() = default;

    void PermStateChangeCallback(PermStateChangeInfo& result) override;
    bool AddDeathRecipient(const sptr<IRemoteObject::DeathRecipient>& deathRecipient) override;
};

void PermChangeCallback::PermStateChangeCallback(PermStateChangeInfo& result)
{
}

bool PermChangeCallback::AddDeathRecipient(const sptr<IRemoteObject::DeathRecipient>& deathRecipient)
{
    return true;
}

/**
 * @tc.name: AddPermStateChangeCallback002
 * @tc.desc: Test AddPermStateChangeCallback with exceed limitation.
 * @tc.type: FUNC
 * @tc.require: issueI4V02P
 */
HWTEST_F(PermissionManagerTest, AddPermStateChangeCallback002, TestSize.Level0)
{
    PermStateChangeScope inScopeInfo;
    inScopeInfo.tokenIDs = {};
    inScopeInfo.permList = {"ohos.permission.CAMERA"};
    std::vector<sptr<PermChangeCallback>> callbacks;

    for (size_t i = 0; i < MAX_CALLBACK_SIZE; ++i) {
        sptr<PermChangeCallback> callback = new (std::nothrow) PermChangeCallback();
        ASSERT_NE(nullptr, callback);
        ASSERT_EQ(RET_SUCCESS,
            PermissionManager::GetInstance().AddPermStateChangeCallback(inScopeInfo, callback->AsObject()));
        callbacks.emplace_back(callback);
    }

    sptr<PermChangeCallback> callback = new (std::nothrow) PermChangeCallback();
    ASSERT_NE(nullptr, callback);
    ASSERT_NE(RET_SUCCESS,
        PermissionManager::GetInstance().AddPermStateChangeCallback(inScopeInfo, callback->AsObject()));

    for (size_t i = 0; i < callbacks.size(); ++i) {
        ASSERT_EQ(RET_SUCCESS,
            PermissionManager::GetInstance().RemovePermStateChangeCallback(callbacks[i]->AsObject()));
    }
}

/**
 * @tc.name: GrantPermission001
 * @tc.desc: Test GrantPermission abnormal branch.
 * @tc.type: FUNC
 * @tc.require: issueI5SSXG
 */
HWTEST_F(PermissionManagerTest, GrantPermission001, TestSize.Level0)
{
    int32_t ret;
    AccessTokenID tokenID = 0;
    ret = PermissionManager::GetInstance().GrantPermission(tokenID, "", PERMISSION_USER_FIXED);
    ASSERT_EQ(ERR_PARAM_INVALID, ret);
    ret = PermissionManager::GetInstance().GrantPermission(tokenID, "ohos.perm", PERMISSION_USER_FIXED);
    ASSERT_EQ(ERR_PERMISSION_NOT_EXIST, ret);
    uint32_t invalidFlag = -1;
    ret = PermissionManager::GetInstance().GrantPermission(tokenID, "ohos.permission.CAMERA", invalidFlag);
    ASSERT_EQ(ERR_PARAM_INVALID, ret);
}

/**
 * @tc.name: RevokePermission001
 * @tc.desc: Test RevokePermission abnormal branch.
 * @tc.type: FUNC
 * @tc.require: issueI5SSXG
 */
HWTEST_F(PermissionManagerTest, RevokePermission001, TestSize.Level0)
{
    int32_t ret;
    AccessTokenID tokenID = 0;
    ret = PermissionManager::GetInstance().RevokePermission(tokenID, "", PERMISSION_USER_FIXED);
    ASSERT_EQ(ERR_PARAM_INVALID, ret);
    ret = PermissionManager::GetInstance().RevokePermission(tokenID, "ohos.perm", PERMISSION_USER_FIXED);
    ASSERT_EQ(ERR_PERMISSION_NOT_EXIST, ret);
    uint32_t invalidFlag = -1;
    ret = PermissionManager::GetInstance().RevokePermission(tokenID, "ohos.permission.CAMERA", invalidFlag);
    ASSERT_EQ(ERR_PARAM_INVALID, ret);
}

/**
 * @tc.name: GetReqPermissions001
 * @tc.desc: GetReqPermissions with invalid tokenid
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(PermissionManagerTest, GetReqPermissions001, TestSize.Level0)
{
    std::vector<PermissionStatus> result;

    // permissionName is empty
    ASSERT_EQ(ERR_TOKENID_NOT_EXIST, PermissionManager::GetInstance().GetReqPermissions(0, result, true));
    ASSERT_TRUE(result.empty());
}

/**
 * @tc.name: GetReqPermissions002
 * @tc.desc: GetReqPermissions with valid tokenid
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(PermissionManagerTest, GetReqPermissions002, TestSize.Level0)
{
    AccessTokenIDEx tokenIdEx = {0};
    std::vector<GenericValues> undefValues;
    int32_t ret = AccessTokenInfoManager::GetInstance().CreateHapTokenInfo(g_infoManagerTestInfoParms,
        g_infoManagerTestPolicyPrams1, tokenIdEx, undefValues);
    ASSERT_EQ(RET_SUCCESS, ret);

    std::vector<PermissionStatus> result;
    AccessTokenID tokenId = tokenIdEx.tokenIdExStruct.tokenID;
    // permissionName is empty
    ASSERT_EQ(RET_SUCCESS, PermissionManager::GetInstance().GetReqPermissions(tokenId, result, true));

    ret = AccessTokenInfoManager::GetInstance().RemoveHapTokenInfo(tokenIdEx.tokenIdExStruct.tokenID);
    ASSERT_EQ(RET_SUCCESS, ret);
}

/**
 * @tc.name: GetSelfPermissionState001
 * @tc.desc: PermissionManager::GetSelfPermissionState function test
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(PermissionManagerTest, GetSelfPermissionState001, TestSize.Level0)
{
    std::vector<PermissionStatus> permsList1;
    permsList1.emplace_back(g_permState1);
    PermissionListState permState1;
    permState1.permissionName = "ohos.permission.GetSelfPermissionStateTest";
    int32_t apiVersion = ACCURATE_LOCATION_API_VERSION;

    // permissionName no definition
    PermissionManager::GetInstance().GetSelfPermissionState(permsList1, permState1, apiVersion);
    ASSERT_EQ(PermissionOper::INVALID_OPER, permState1.state);

    std::vector<PermissionStatus> permsList2;
    permsList2.emplace_back(g_permState2);
    PermissionListState permState2;
    permState2.permissionName = "ohos.permission.CAMERA";

    // flag not PERMISSION_DEFAULT_FLAG、PERMISSION_USER_SET or PERMISSION_USER_FIXED
    PermissionManager::GetInstance().GetSelfPermissionState(permsList2, permState2, apiVersion);
    ASSERT_EQ(PermissionOper::PASS_OPER, permState2.state);
}

/**
 * @tc.name: GetSelfPermissionState002
 * @tc.desc: PermissionManager::GetSelfPermissionState function test
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(PermissionManagerTest, GetSelfPermissionState002, TestSize.Level0)
{
    std::vector<PermissionStatus> permsList1;
    permsList1.emplace_back(g_permState6);
    PermissionListState permState1;
    permState1.permissionName = "ohos.permission.CAMERA";
    int32_t apiVersion = ACCURATE_LOCATION_API_VERSION;

    // flag is PERMISSION_FIXED_FOR_SECURITY_POLICY and state is denied, return SETTING_OPER
    PermissionManager::GetInstance().GetSelfPermissionState(permsList1, permState1, apiVersion);
    ASSERT_EQ(PermissionOper::SETTING_OPER, permState1.state);

    std::vector<PermissionStatus> permsList2;
    permsList2.emplace_back(g_permState7);
    PermissionListState permState2;
    permState2.permissionName = "ohos.permission.CAMERA";

    // flag is PERMISSION_FIXED_FOR_SECURITY_POLICY and state is granted, return PASS_OPER
    PermissionManager::GetInstance().GetSelfPermissionState(permsList2, permState2, apiVersion);
    ASSERT_EQ(PermissionOper::PASS_OPER, permState2.state);

    std::vector<PermissionStatus> permsList3;
    permsList3.emplace_back(g_permState8);
    PermissionListState permState3;
    permState3.permissionName = "ohos.permission.CAMERA";

    // flag is PERMISSION_FIXED_FOR_SECURITY_POLICY | PERMISSION_USER_SET and state is denied, return SETTING_OPER
    PermissionManager::GetInstance().GetSelfPermissionState(permsList3, permState3, apiVersion);
    ASSERT_EQ(PermissionOper::SETTING_OPER, permState3.state);

    std::vector<PermissionStatus> permsList4;
    permsList4.emplace_back(g_permState9);
    PermissionListState permState4;
    permState4.permissionName = "ohos.permission.CAMERA";

    // flag is PERMISSION_FIXED_FOR_SECURITY_POLICY | PERMISSION_USER_SET and state is granted, return PASS_OPER
    PermissionManager::GetInstance().GetSelfPermissionState(permsList4, permState4, apiVersion);
    ASSERT_EQ(PermissionOper::PASS_OPER, permState4.state);
}

/**
 * @tc.name: GetSelfPermissionState003
 * @tc.desc: PermissionManager::GetSelfPermissionState function test
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(PermissionManagerTest, GetSelfPermissionState003, TestSize.Level0)
{
    std::vector<PermissionStatus> permsList1;
    permsList1.emplace_back(g_permState2);
    std::string permissionName = "ohos.permission.CAMERA";
    uint32_t oriStatus;
    AccessTokenInfoManager::GetInstance().GetPermissionRequestToggleStatus(permissionName, oriStatus, 0);

    AccessTokenInfoManager::GetInstance().SetPermissionRequestToggleStatus(permissionName,
        PermissionRequestToggleStatus::CLOSED, 0);
    uint32_t status;
    AccessTokenInfoManager::GetInstance().GetPermissionRequestToggleStatus(permissionName, status, 0);
    ASSERT_EQ(PermissionRequestToggleStatus::CLOSED, status);

    AccessTokenInfoManager::GetInstance().SetPermissionRequestToggleStatus(permissionName, oriStatus, 0);
}

/**
 * @tc.name: GetSelfPermissionState004
 * @tc.desc: PermissionManager::GetSelfPermissionState function test
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(PermissionManagerTest, GetSelfPermissionState004, TestSize.Level0)
{
    std::vector<PermissionStatus> permsList1;
    permsList1.emplace_back(g_permState10);
    PermissionListState permState1;
    permState1.permissionName = "ohos.permission.CAMERA";
    int32_t apiVersion = ACCURATE_LOCATION_API_VERSION;

    PermissionManager::GetInstance().GetSelfPermissionState(permsList1, permState1, apiVersion);
    ASSERT_EQ(PermissionOper::INVALID_OPER, permState1.state);

    std::vector<PermissionStatus> permsList2;
    permsList2.emplace_back(g_permState11);
    PermissionListState permState2;
    permState2.permissionName = "ohos.permission.CAMERA";

    PermissionManager::GetInstance().GetSelfPermissionState(permsList2, permState2, apiVersion);
    ASSERT_EQ(PermissionOper::SETTING_OPER, permState2.state);

    std::vector<PermissionStatus> permsList3;
    permsList3.emplace_back(g_permState12);
    PermissionListState permState3;
    permState3.permissionName = "ohos.permission.CAMERA";

    PermissionManager::GetInstance().GetSelfPermissionState(permsList3, permState3, apiVersion);
    ASSERT_EQ(PermissionOper::DYNAMIC_OPER, permState3.state);

    std::vector<PermissionStatus> permsList4;
    permsList4.emplace_back(g_permState13);
    PermissionListState permState4;
    permState4.permissionName = "ohos.permission.CAMERA";

    PermissionManager::GetInstance().GetSelfPermissionState(permsList4, permState4, apiVersion);
    ASSERT_EQ(PermissionOper::SETTING_OPER, permState4.state);
}

/**
 * @tc.name: GetPermissionFlag001
 * @tc.desc: PermissionManager::GetPermissionFlag function test
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(PermissionManagerTest, GetPermissionFlag001, TestSize.Level0)
{
    AccessTokenID tokenID = 123; // 123 is random input
    std::string permissionName;
    uint32_t flag = 0;
    PermissionDataBrief::GetInstance().DeleteBriefPermDataByTokenId(tokenID);
    // permissionName invalid
    ASSERT_EQ(ERR_PARAM_INVALID, PermissionManager::GetInstance().GetPermissionFlag(tokenID,
        permissionName, flag));

    permissionName = "ohos.permission.invalid";
    // permissionName is not defined
    ASSERT_EQ(ERR_PERMISSION_NOT_EXIST, PermissionManager::GetInstance().GetPermissionFlag(tokenID,
        permissionName, flag));

    permissionName = "ohos.permission.CAMERA";
    // tokenid in not exits
    ASSERT_EQ(ERR_TOKENID_NOT_EXIST, PermissionManager::GetInstance().GetPermissionFlag(tokenID,
        permissionName, flag));
}

/**
 * @tc.name: GetPermissionFlag002
 * @tc.desc: PermissionManager::GetPermissionFlag function test
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(PermissionManagerTest, GetPermissionFlag002, TestSize.Level0)
{
    HapInfoParams infoParms = {
        .userID = 1,
        .bundleName = "accesstoken_test",
        .instIndex = 0,
        .appIDDesc = "testtesttesttest"
    };
    PermissionStatus permStat = {
        .permissionName = "ohos.permission.CAMERA",
        .grantStatus = PermissionState::PERMISSION_DENIED,
        .grantFlag = PermissionFlag::PERMISSION_SYSTEM_FIXED
    };
    HapPolicy policyPrams = {
        .apl = APL_NORMAL,
        .domain = "test.domain",
        .permList = {},
        .permStateList = {permStat}
    };
    AccessTokenIDEx tokenIdEx = {0};
    std::vector<GenericValues> undefValues;
    int32_t ret = AccessTokenInfoManager::GetInstance().CreateHapTokenInfo(infoParms, policyPrams, tokenIdEx,
        undefValues);
    ASSERT_EQ(RET_SUCCESS, ret);
    AccessTokenID tokenId = tokenIdEx.tokenIdExStruct.tokenID;
    uint32_t flag;
    ASSERT_EQ(ERR_PERMISSION_NOT_EXIST,
        PermissionManager::GetInstance().GetPermissionFlag(tokenId, "ohos.permission.LOCATION", flag));

    ASSERT_EQ(RET_SUCCESS,
        PermissionManager::GetInstance().GetPermissionFlag(tokenId, permStat.permissionName, flag));

    // delete test token
    ASSERT_EQ(RET_SUCCESS, AccessTokenInfoManager::GetInstance().RemoveHapTokenInfo(tokenId));
}

/**
 * @tc.name: UpdateTokenPermissionState002
 * @tc.desc: PermissionManager::UpdateTokenPermissionState function test
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(PermissionManagerTest, UpdateTokenPermissionState002, TestSize.Level0)
{
    AccessTokenID tokenId = 123; // random input
    std::string permissionName = "ohos.permission.DUMP";
    bool isGranted = false;
    uint32_t flag = 0;
    // tokenId invalid
    ASSERT_EQ(AccessTokenError::ERR_TOKENID_NOT_EXIST, PermissionManager::GetInstance().UpdateTokenPermissionState(
        tokenId, permissionName, isGranted, flag, true));

    HapInfoParams info = {
        .userID = USER_ID,
        .bundleName = "permission_manager_test",
        .instIndex = INST_INDEX,
        .appIDDesc = "permission_manager_test"
    };
    HapPolicy policy = {
        .apl = APL_NORMAL,
        .domain = "domain"
    };
    AccessTokenIDEx tokenIdEx = {0};
    std::vector<GenericValues> undefValues;
    ASSERT_EQ(RET_SUCCESS, AccessTokenInfoManager::GetInstance().CreateHapTokenInfo(info, policy, tokenIdEx,
        undefValues));
    ASSERT_NE(static_cast<AccessTokenID>(0), tokenIdEx.tokenIdExStruct.tokenID);
    tokenId = tokenIdEx.tokenIdExStruct.tokenID;

    std::shared_ptr<HapTokenInfoInner> infoPtr = AccessTokenInfoManager::GetInstance().GetHapTokenInfoInner(tokenId);
    infoPtr->SetRemote(true);
    // remote token is true
    ASSERT_EQ(AccessTokenError::ERR_IDENTITY_CHECK_FAILED, PermissionManager::GetInstance().UpdateTokenPermissionState(
        tokenId, permissionName, isGranted, flag, true));
    infoPtr->SetRemote(false);

    // permission not in list
    ASSERT_EQ(ERR_PARAM_INVALID, PermissionManager::GetInstance().UpdateTokenPermissionState(tokenId,
        permissionName, isGranted, flag, true));

    ASSERT_EQ(RET_SUCCESS, AccessTokenInfoManager::GetInstance().RemoveHapTokenInfo(tokenId));
}

/**
 * @tc.name: UpdateTokenPermissionState003
 * @tc.desc: PermissionManager::UpdateTokenPermissionState function test
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(PermissionManagerTest, UpdateTokenPermissionState003, TestSize.Level0)
{
    std::string permissionName = "ohos.permission.DUMP";
    uint32_t flag = 0;

    HapInfoParams info = {
        .userID = USER_ID,
        .bundleName = "permission_manager_test",
        .instIndex = INST_INDEX,
        .appIDDesc = "permission_manager_test"
    };
    PermissionStatus permStat = {
        .permissionName = permissionName,
        .grantStatus = PermissionState::PERMISSION_DENIED,
        .grantFlag = PermissionFlag::PERMISSION_DEFAULT_FLAG
    };
    HapPolicy policy = {
        .apl = APL_NORMAL,
        .domain = "domain",
        .permStateList = {permStat}
    };
    AccessTokenIDEx tokenIdEx = {0};
    std::vector<GenericValues> undefValues;
    ASSERT_EQ(RET_SUCCESS, AccessTokenInfoManager::GetInstance().CreateHapTokenInfo(info, policy, tokenIdEx,
        undefValues));
    ASSERT_NE(static_cast<AccessTokenID>(0), tokenIdEx.tokenIdExStruct.tokenID);
    AccessTokenID tokenId = tokenIdEx.tokenIdExStruct.tokenID;

    flag = PERMISSION_ALLOW_THIS_TIME;
    ASSERT_EQ(RET_SUCCESS, PermissionManager::GetInstance().UpdateTokenPermissionState(
        tokenId, permissionName, false, flag, true));

    flag = PERMISSION_COMPONENT_SET;
    ASSERT_EQ(RET_SUCCESS, PermissionManager::GetInstance().UpdateTokenPermissionState(
        tokenId, permissionName, false, flag, true));

    flag = PERMISSION_USER_FIXED;
    ASSERT_EQ(RET_SUCCESS, PermissionManager::GetInstance().UpdateTokenPermissionState(
        tokenId, permissionName, false, flag, true));

    ASSERT_EQ(RET_SUCCESS, AccessTokenInfoManager::GetInstance().RemoveHapTokenInfo(tokenId));
}

/**
 * @tc.name: IsAllowGrantTempPermission001
 * @tc.desc: PermissionManager::IsAllowGrantTempPermission function test
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(PermissionManagerTest, IsAllowGrantTempPermission001, TestSize.Level0)
{
    AccessTokenID tokenId = 123; // random input
    std::string permissionName = "";
    // tokenId invalid
    ASSERT_EQ(false, TempPermissionObserver::GetInstance().IsAllowGrantTempPermission(tokenId, permissionName));
}

/**
 * @tc.name: IsPermissionVaild001
 * @tc.desc: PermissionManager::IsPermissionVaild function test
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(PermissionManagerTest, IsPermissionVaild001, TestSize.Level0)
{
    std::string permissionName;
    // permissionName invalid
    ASSERT_EQ(false, PermissionManager::GetInstance().IsPermissionVaild(permissionName));

    permissionName = "ohos.permission.PERMISSION_MANAGR_TEST";
    // no definition
    ASSERT_EQ(false, PermissionManager::GetInstance().IsPermissionVaild(permissionName));

    permissionName = "ohos.permission.CAMERA";
    ASSERT_EQ(true, PermissionManager::GetInstance().IsPermissionVaild(permissionName));
}

/**
 * @tc.name: GetPermissionState001
 * @tc.desc: TempPermissionObserver::GetPermissionState function test
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(PermissionManagerTest, GetPermissionState001, TestSize.Level0)
{
    AccessTokenID tokenId = 123; // random input
    std::vector<PermissionStatus> permissionStateList;
    // tokenId invalid
    ASSERT_EQ(false, TempPermissionObserver::GetInstance().GetPermissionState(tokenId, permissionStateList));

    HapInfoParams info = {
        .userID = USER_ID,
        .bundleName = "permission_manager_test",
        .instIndex = INST_INDEX,
        .appIDDesc = "permission_manager_test"
    };
    HapPolicy policy = {
        .apl = APL_NORMAL,
        .domain = "domain"
    };
    AccessTokenIDEx tokenIdEx = {0};
    std::vector<GenericValues> undefValues;
    ASSERT_EQ(RET_SUCCESS, AccessTokenInfoManager::GetInstance().CreateHapTokenInfo(info, policy, tokenIdEx,
        undefValues));
    ASSERT_NE(static_cast<AccessTokenID>(0), tokenIdEx.tokenIdExStruct.tokenID);
    tokenId = tokenIdEx.tokenIdExStruct.tokenID;

    std::shared_ptr<HapTokenInfoInner> infoPtr = AccessTokenInfoManager::GetInstance().GetHapTokenInfoInner(tokenId);
    infoPtr->SetRemote(true);
    // remote token is true
    ASSERT_EQ(false, TempPermissionObserver::GetInstance().GetPermissionState(tokenId, permissionStateList));
    infoPtr->SetRemote(false);

    ASSERT_EQ(RET_SUCCESS, AccessTokenInfoManager::GetInstance().RemoveHapTokenInfo(tokenId));
}

/**
 * @tc.name: GetApiVersionByTokenId001
 * @tc.desc: PermissionManager::GetApiVersionByTokenId function test
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(PermissionManagerTest, GetApiVersionByTokenId001, TestSize.Level0)
{
    AccessTokenID tokenId = 940572671; // 940572671 is max butt tokenId: 001 11 0 000000 11111111111111111111
    int32_t apiVersion = 0;

    // type TOKEN_TYPE_BUTT
    ASSERT_EQ(false, PermissionManager::GetInstance().GetApiVersionByTokenId(tokenId, apiVersion));

    tokenId = 537919487; // 537919487 is max hap tokenId: 001 00 0 000000 11111111111111111111
    // get token info err
    ASSERT_EQ(false, PermissionManager::GetInstance().GetApiVersionByTokenId(tokenId, apiVersion));
}

/**
 * @tc.name: VerifyHapAccessToken001
 * @tc.desc: PermissionManager::VerifyHapAccessToken function test
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(PermissionManagerTest, VerifyHapAccessToken001, TestSize.Level0)
{
    AccessTokenID tokenId = 123; // 123 is random input
    std::string permissionName;

    std::shared_ptr<HapTokenInfoInner> hap = std::make_shared<HapTokenInfoInner>();
    ASSERT_NE(nullptr, hap);
    AccessTokenInfoManager::GetInstance().hapTokenInfoMap_[tokenId] = hap;

    ASSERT_EQ(PermissionState::PERMISSION_DENIED,
        PermissionManager::GetInstance().VerifyHapAccessToken(tokenId, permissionName)); // permPolicySet is null

    AccessTokenInfoManager::GetInstance().hapTokenInfoMap_.erase(tokenId);
}

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
    AppStateData appStateData;
    appStateData.state = static_cast<int32_t>(ApplicationState::APP_STATE_FOREGROUND);
    appStateData.accessTokenId = tokenID;
    appStateObserver_->OnAppStateChanged(appStateData);
    // grant temp permission
    EXPECT_EQ(RET_SUCCESS, PermissionManager::GetInstance().GrantPermission(tokenID,
        "ohos.permission.APPROXIMATELY_LOCATION", PERMISSION_ALLOW_THIS_TIME));
    EXPECT_EQ(PERMISSION_GRANTED,
        AccessTokenInfoManager::GetInstance().VerifyAccessToken(tokenID, "ohos.permission.APPROXIMATELY_LOCATION"));
    // change to background
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
    // create background task
    std::shared_ptr<ContinuousTaskCallbackInfo> continuousTaskCallbackInfo
        = std::make_shared<ContinuousTaskCallbackInfo>();
    continuousTaskCallbackInfo->typeId_ = static_cast<uint32_t>(BackgroundMode::LOCATION);
    continuousTaskCallbackInfo->typeIds_.emplace_back(static_cast<uint32_t>(BackgroundMode::LOCATION));
    continuousTaskCallbackInfo->tokenId_ = tokenID;
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
    // create background task
    std::shared_ptr<ContinuousTaskCallbackInfo> continuousTaskCallbackInfo
        = std::make_shared<ContinuousTaskCallbackInfo>();
    continuousTaskCallbackInfo->typeId_ = static_cast<uint32_t>(BackgroundMode::LOCATION);
    continuousTaskCallbackInfo->typeIds_.emplace_back(static_cast<uint32_t>(BackgroundMode::LOCATION));
    continuousTaskCallbackInfo->tokenId_ = tokenID;
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
    // create background task
    std::shared_ptr<ContinuousTaskCallbackInfo> continuousTaskCallbackInfo
        = std::make_shared<ContinuousTaskCallbackInfo>();
    continuousTaskCallbackInfo->typeId_ = static_cast<uint32_t>(BackgroundMode::LOCATION);
    continuousTaskCallbackInfo->typeIds_.emplace_back(static_cast<uint32_t>(BackgroundMode::LOCATION));
    continuousTaskCallbackInfo->tokenId_ = tokenID;
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
    // create background task
    std::shared_ptr<ContinuousTaskCallbackInfo> continuousTaskCallbackInfo
        = std::make_shared<ContinuousTaskCallbackInfo>();
    continuousTaskCallbackInfo->typeId_ = static_cast<uint32_t>(BackgroundMode::LOCATION);
    continuousTaskCallbackInfo->typeIds_.emplace_back(static_cast<uint32_t>(BackgroundMode::LOCATION));
    continuousTaskCallbackInfo->tokenId_ = tokenID;
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
    // create background task
    std::shared_ptr<ContinuousTaskCallbackInfo> continuousTaskCallbackInfo
        = std::make_shared<ContinuousTaskCallbackInfo>();
    continuousTaskCallbackInfo->typeId_ = static_cast<uint32_t>(BackgroundMode::LOCATION);
    continuousTaskCallbackInfo->typeIds_.emplace_back(static_cast<uint32_t>(BackgroundMode::LOCATION));
    continuousTaskCallbackInfo->tokenId_ = tokenID;
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
    // create background task
    std::shared_ptr<ContinuousTaskCallbackInfo> continuousTaskCallbackInfo
        = std::make_shared<ContinuousTaskCallbackInfo>();
    continuousTaskCallbackInfo->typeId_ = static_cast<uint32_t>(BackgroundMode::LOCATION);
    continuousTaskCallbackInfo->typeIds_.emplace_back(static_cast<uint32_t>(BackgroundMode::LOCATION));
    continuousTaskCallbackInfo->tokenId_ = tokenID;
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
    // create background task
    std::shared_ptr<ContinuousTaskCallbackInfo> continuousTaskCallbackInfo
        = std::make_shared<ContinuousTaskCallbackInfo>();
    continuousTaskCallbackInfo->typeId_ = static_cast<uint32_t>(BackgroundMode::LOCATION);
    continuousTaskCallbackInfo->typeIds_.emplace_back(static_cast<uint32_t>(BackgroundMode::LOCATION));
    continuousTaskCallbackInfo->tokenId_ = tokenID;
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
    // create background task
    std::shared_ptr<ContinuousTaskCallbackInfo> continuousTaskCallbackInfo
        = std::make_shared<ContinuousTaskCallbackInfo>();
    continuousTaskCallbackInfo->typeId_ = static_cast<uint32_t>(BackgroundMode::DATA_TRANSFER);
    continuousTaskCallbackInfo->typeIds_.emplace_back(static_cast<uint32_t>(BackgroundMode::DATA_TRANSFER));
    continuousTaskCallbackInfo->tokenId_ = tokenID;
    backgroundTaskObserver_->OnContinuousTaskStart(continuousTaskCallbackInfo);

    // create background task
    std::shared_ptr<ContinuousTaskCallbackInfo> continuousTaskCallbackInfo1
        = std::make_shared<ContinuousTaskCallbackInfo>();
    continuousTaskCallbackInfo1->typeId_ = static_cast<uint32_t>(BackgroundMode::LOCATION);
    continuousTaskCallbackInfo1->typeIds_.emplace_back(static_cast<uint32_t>(BackgroundMode::LOCATION));
    continuousTaskCallbackInfo1->tokenId_ = tokenID;
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
    // create background task
    std::shared_ptr<ContinuousTaskCallbackInfo> continuousTaskCallbackInfo
        = std::make_shared<ContinuousTaskCallbackInfo>();
    continuousTaskCallbackInfo->typeId_ = static_cast<uint32_t>(BackgroundMode::LOCATION);
    continuousTaskCallbackInfo->typeIds_.emplace_back(static_cast<uint32_t>(BackgroundMode::LOCATION));
    continuousTaskCallbackInfo->tokenId_ = tokenID;
    backgroundTaskObserver_->OnContinuousTaskStart(continuousTaskCallbackInfo);

    // change to background
    AppStateData appStateData;
    appStateData.state = static_cast<int32_t>(ApplicationState::APP_STATE_BACKGROUND);
    appStateData.accessTokenId = tokenID;
    appStateObserver_->OnAppStateChanged(appStateData);
    sleep(11);
    EXPECT_EQ(PERMISSION_GRANTED,
        AccessTokenInfoManager::GetInstance().VerifyAccessToken(tokenID, "ohos.permission.APPROXIMATELY_LOCATION"));
    EXPECT_EQ(PERMISSION_GRANTED,
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
 * @tc.name: GrantTempPermission021
 * @tc.desc: Test grant temp permission switching to background and have a background task with 2 typeId
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(PermissionManagerTest, GrantTempPermission021, TestSize.Level0)
{
    accessTokenService_->state_ = ServiceRunningState::STATE_RUNNING;
    accessTokenService_->Initialize();
    AccessTokenID tokenID = CreateTempHapTokenInfo();
    EXPECT_EQ(RET_SUCCESS, PermissionManager::GetInstance().GrantPermission(tokenID,
        "ohos.permission.APPROXIMATELY_LOCATION", PERMISSION_ALLOW_THIS_TIME));
    EXPECT_EQ(PERMISSION_GRANTED,
        AccessTokenInfoManager::GetInstance().VerifyAccessToken(tokenID, "ohos.permission.APPROXIMATELY_LOCATION"));
    // create background task
    std::shared_ptr<ContinuousTaskCallbackInfo> continuousTaskCallbackInfo
        = std::make_shared<ContinuousTaskCallbackInfo>();
    continuousTaskCallbackInfo->typeId_ = static_cast<uint32_t>(BackgroundMode::DATA_TRANSFER);
    continuousTaskCallbackInfo->typeIds_.emplace_back(static_cast<uint32_t>(BackgroundMode::DATA_TRANSFER));
    continuousTaskCallbackInfo->typeIds_.emplace_back(static_cast<uint32_t>(BackgroundMode::LOCATION));
    continuousTaskCallbackInfo->tokenId_ = tokenID;
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
#endif
/**
 * @tc.name: GrantTempPermission015
 * @tc.desc: Test grant temp permission process died
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
 * @tc.name: GrantTempPermission016
 * @tc.desc: Test grant & revoke temp permission
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(PermissionManagerTest, GrantTempPermission016, TestSize.Level0)
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
 * @tc.name: GrantTempPermission017
 * @tc.desc: Test grant temp permission not root
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(PermissionManagerTest, GrantTempPermission017, TestSize.Level0)
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
}

/**
 * @tc.name: GrantTempPermission018
 * @tc.desc: Test tokenID not in the list
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(PermissionManagerTest, GrantTempPermission018, TestSize.Level0)
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
#ifdef BGTASKMGR_CONTINUOUS_TASK_ENABLE
/**
 * @tc.name: GrantTempPermission019
 * @tc.desc: Test tokenID not in the list
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(PermissionManagerTest, GrantTempPermission019, TestSize.Level0)
{
    accessTokenService_->state_ = ServiceRunningState::STATE_RUNNING;
    accessTokenService_->Initialize();
    AccessTokenID tokenID = CreateTempHapTokenInfo();
    EXPECT_EQ(RET_SUCCESS, PermissionManager::GetInstance().GrantPermission(tokenID,
        "ohos.permission.APPROXIMATELY_LOCATION", PERMISSION_SYSTEM_FIXED));

    TempPermissionObserver::GetInstance().ModifyAppState(tokenID, 0, false);
    // create background task
    std::shared_ptr<ContinuousTaskCallbackInfo> continuousTaskCallbackInfo
        = std::make_shared<ContinuousTaskCallbackInfo>();
    continuousTaskCallbackInfo->typeId_ = static_cast<uint32_t>(BackgroundMode::LOCATION);
    continuousTaskCallbackInfo->typeIds_.emplace_back(static_cast<uint32_t>(BackgroundMode::LOCATION));
    continuousTaskCallbackInfo->tokenId_ = tokenID;
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
 * @tc.name: GrantTempPermission020
 * @tc.desc: Test invalid permissionName
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(PermissionManagerTest, GrantTempPermission020, TestSize.Level0)
{
    accessTokenService_->state_ = ServiceRunningState::STATE_RUNNING;
    accessTokenService_->Initialize();
    AccessTokenID tokenID = CreateTempHapTokenInfo();
    EXPECT_EQ(ERR_IDENTITY_CHECK_FAILED, PermissionManager::GetInstance().GrantPermission(tokenID,
        "ohos.permission.MICROPHONE", PERMISSION_ALLOW_THIS_TIME));
    TempPermissionObserver::GetInstance().UnRegisterCallback();
    // remove hap
    int32_t ret = AccessTokenInfoManager::GetInstance().RemoveHapTokenInfo(tokenID);
    ASSERT_EQ(RET_SUCCESS, ret);
    GTEST_LOG_(INFO) << "remove the token info";
}

/**
 * @tc.name: SetPermissionStatusWithPolicy001
 * @tc.desc: SetPermissionStatusWithPolicy test.
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(PermissionManagerTest, SetPermissionStatusWithPolicy001, TestSize.Level0)
{
    accessTokenService_->state_ = ServiceRunningState::STATE_RUNNING;
    accessTokenService_->Initialize();
    AccessTokenID tokenID = CreateTempHapTokenInfo();
    TempPermissionObserver::GetInstance().RegisterCallback();

    std::vector<std::string> permList = {"ohos.permission.APPROXIMATELY_LOCATION"};
    EXPECT_EQ(RET_SUCCESS, PermissionManager::GetInstance().SetPermissionStatusWithPolicy(
        tokenID, permList, PERMISSION_GRANTED, PERMISSION_FIXED_BY_ADMIN_POLICY));

    EXPECT_EQ(ERR_PARAM_INVALID, PermissionManager::GetInstance().SetPermissionStatusWithPolicy(
        tokenID, permList, PERMISSION_GRANTED, PERMISSION_ALLOW_THIS_TIME));

    EXPECT_EQ(ERR_PERMISSION_NOT_EXIST, PermissionManager::GetInstance().SetPermissionStatusWithPolicy(
        tokenID, {"ohos.permission.test123"}, PERMISSION_GRANTED, PERMISSION_FIXED_BY_ADMIN_POLICY));
    
    EXPECT_EQ(ERR_PARAM_INVALID, PermissionManager::GetInstance().SetPermissionStatusWithPolicy(
        tokenID, {"ohos.permission.MANAGE_INPUT_INFRARED_EMITTER"},
        PERMISSION_GRANTED, PERMISSION_FIXED_BY_ADMIN_POLICY));
}

/**
 * @tc.name: newUpdateTokenPermissionState003
 * @tc.desc: PermissionManager::UpdateTokenPermissionState function test
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(PermissionManagerTest, newUpdateTokenPermissionState003, TestSize.Level0)
{
    std::string permissionName = "ohos.permission.DUMP";
    uint32_t flag = 0;

    HapInfoParams info = {
        .userID = USER_ID,
        .bundleName = "permission_manager_test",
        .instIndex = INST_INDEX,
        .appIDDesc = "permission_manager_test"
    };
    PermissionStatus permStat = {
        .permissionName = permissionName,
        .grantStatus = PermissionState::PERMISSION_DENIED,
        .grantFlag = PermissionFlag::PERMISSION_DEFAULT_FLAG
    };
    HapPolicy policy = {
        .apl = APL_NORMAL,
        .domain = "domain",
        .permStateList = {permStat}
    };
    AccessTokenIDEx tokenIdEx = {0};
    std::vector<GenericValues> undefValues;
    ASSERT_EQ(RET_SUCCESS, AccessTokenInfoManager::GetInstance().CreateHapTokenInfo(info, policy, tokenIdEx,
        undefValues));
    ASSERT_NE(static_cast<AccessTokenID>(0), tokenIdEx.tokenIdExStruct.tokenID);
    AccessTokenID tokenId = tokenIdEx.tokenIdExStruct.tokenID;

    std::shared_ptr<HapTokenInfoInner> infoPtr = AccessTokenInfoManager::GetInstance().GetHapTokenInfoInner(tokenId);

    flag = PERMISSION_ALLOW_THIS_TIME;
    ASSERT_EQ(RET_SUCCESS, PermissionManager::GetInstance().UpdateTokenPermissionState(
        infoPtr, tokenId, permissionName, false, flag, true));

    flag = PERMISSION_COMPONENT_SET;
    ASSERT_EQ(RET_SUCCESS, PermissionManager::GetInstance().UpdateTokenPermissionState(
        infoPtr, tokenId, permissionName, false, flag, true));

    flag = PERMISSION_USER_FIXED;
    ASSERT_EQ(RET_SUCCESS, PermissionManager::GetInstance().UpdateTokenPermissionState(
        infoPtr, tokenId, permissionName, false, flag, true));

    ASSERT_EQ(RET_SUCCESS, AccessTokenInfoManager::GetInstance().RemoveHapTokenInfo(tokenId));
}

/**
 * @tc.name: UpdateMultiTokenPermissionState001
 * @tc.desc: PermissionManager::UpdateMultiTokenPermissionState function test
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(PermissionManagerTest, UpdateMultiTokenPermissionState001, TestSize.Level0)
{
    std::string permissionName = "ohos.permission.DUMP";
    uint32_t flag = 0;

    HapInfoParams info = {
        .userID = USER_ID,
        .bundleName = "permission_manager_test",
        .instIndex = INST_INDEX,
        .appIDDesc = "permission_manager_test",
        .dlpType = DLP_FULL_CONTROL
    };
    PermissionStatus permStat = {
        .permissionName = permissionName,
        .grantStatus = PermissionState::PERMISSION_DENIED,
        .grantFlag = PermissionFlag::PERMISSION_DEFAULT_FLAG
    };
    HapPolicy policy = {
        .apl = APL_NORMAL,
        .domain = "domain",
        .permStateList = {permStat}
    };
    AccessTokenIDEx tokenIdEx = {0};
    std::vector<GenericValues> undefValues;
    ASSERT_EQ(RET_SUCCESS, AccessTokenInfoManager::GetInstance().CreateHapTokenInfo(info, policy, tokenIdEx,
        undefValues));
    ASSERT_NE(static_cast<AccessTokenID>(0), tokenIdEx.tokenIdExStruct.tokenID);
    AccessTokenID tokenId = tokenIdEx.tokenIdExStruct.tokenID;

    std::vector<std::string> permList;
    ASSERT_EQ(RET_SUCCESS, PermissionManager::GetInstance().UpdateMultiPermissionStatus(
        tokenId, permList, PERMISSION_DENIED, flag));

    ASSERT_EQ(ERR_TOKENID_NOT_EXIST, PermissionManager::GetInstance().UpdateMultiPermissionStatus(
        0, permList, PERMISSION_DENIED, flag));

    std::shared_ptr<HapTokenInfoInner> infoPtr = AccessTokenInfoManager::GetInstance().GetHapTokenInfoInner(tokenId);
    infoPtr->SetRemote(true);
    ASSERT_EQ(ERR_IDENTITY_CHECK_FAILED, PermissionManager::GetInstance().UpdateMultiPermissionStatus(
        tokenId, permList, PERMISSION_DENIED, flag));
    infoPtr->SetRemote(false);
}

 /**
 * @tc.name: PermissionCallbackTest001
 * @tc.desc: Test nullptr input for callback
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(PermissionManagerTest, PermissionCallbackTest001, TestSize.Level0)
{
    PermStateChangeScope scope;
    EXPECT_EQ(AccessTokenError::ERR_PARAM_INVALID, CallbackManager::GetInstance().AddCallback(scope, nullptr));
}

#ifdef BGTASKMGR_CONTINUOUS_TASK_ENABLE
/*
 * @tc.name: ContinuousTaskCallbackInfoParcel001
 * @tc.desc: ContinuousTaskCallbackInfo::Marshalling | Unmarshalling
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(PermissionManagerTest, ContinuousTaskCallbackInfoParcel001, TestSize.Level0)
{
    ContinuousTaskCallbackInfo info;
    Parcel parcel;
    EXPECT_EQ(true, info.Marshalling(parcel));

    auto p = ContinuousTaskCallbackInfo::Unmarshalling(parcel);
    EXPECT_NE(nullptr, p);
    EXPECT_EQ(info.typeId_, p->typeId_);
    EXPECT_EQ(info.creatorUid_, p->creatorUid_);
    EXPECT_EQ(info.creatorPid_, p->creatorPid_);
    EXPECT_EQ(info.abilityName_, p->abilityName_);
    EXPECT_EQ(info.isFromWebview_, p->isFromWebview_);
    EXPECT_EQ(info.isBatchApi_, p->isBatchApi_);
    EXPECT_EQ(info.typeIds_, p->typeIds_);
    EXPECT_EQ(info.abilityId_, p->abilityId_);
    EXPECT_EQ(info.tokenId_, p->tokenId_);
}

/*
 * @tc.name: ContinuousTaskCallbackCall001
 * @tc.desc: test call interface code success
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(PermissionManagerTest, ContinuousTaskCallbackCall001, TestSize.Level1)
{
    sptr<PermissionBackgroundTaskObserver> backgroundTaskObserver =
        new (std::nothrow) PermissionBackgroundTaskObserver();
    ASSERT_EQ(RET_SUCCESS,
        BackgroundTaskManagerAccessClient::GetInstance().SubscribeBackgroundTask(backgroundTaskObserver));
    ASSERT_EQ(RET_SUCCESS,
        BackgroundTaskManagerAccessClient::GetInstance().UnsubscribeBackgroundTask(backgroundTaskObserver));
    std::vector<std::shared_ptr<ContinuousTaskCallbackInfo>> list;
    ASSERT_EQ(RET_SUCCESS, BackgroundTaskManagerAccessClient::GetInstance().GetContinuousTaskApps(list));
}
#endif
} // namespace AccessToken
} // namespace Security
} // namespace OHOS
