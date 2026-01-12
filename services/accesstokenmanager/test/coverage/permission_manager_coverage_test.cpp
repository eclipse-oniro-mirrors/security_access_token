/*
 * Copyright (c) 2024 Huawei Device Co., Ltd.
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

#include <cstdint>
#include <gtest/gtest.h>

#include "access_token.h"
#include "access_token_db_operator.h"
#include "access_token_db.h"
#include "accesstoken_kit.h"
#include "access_token_error.h"
#define private public
#include "accesstoken_info_manager.h"
#include "accesstoken_manager_service.h"
#include "form_manager_access_client.h"
#include "permission_manager.h"
#undef private
#include "accesstoken_callback_stubs.h"
#include "callback_death_recipients.h"
#include "parameters.h"
#include "permission_data_brief.h"
#include "token_field_const.h"
#include "token_setproc.h"

using namespace OHOS;
using namespace testing::ext;

namespace OHOS {
namespace Security {
namespace AccessToken {
namespace {
static const char* ENTERPRISE_NORMAL_CHECK = "accesstoken.enterprise_normal_check";
static const std::string FORM_VISIBLE_NAME = "#1";
static constexpr int USER_ID = 100;
static constexpr int INST_INDEX = 0;
static constexpr int32_t RANDOM_TOKENID = 123;
static constexpr int INVALID_IPC_CODE = 0;
static constexpr int32_t DELAY_TIME = 10;

static PermissionStatus g_permState = {
    .permissionName = "ohos.permission.CAMERA",
    .grantStatus = PermissionState::PERMISSION_DENIED,
    .grantFlag = PermissionFlag::PERMISSION_DEFAULT_FLAG
};

static HapInfoParams g_info = {
    .userID = USER_ID,
    .bundleName = "accesstoken_test",
    .instIndex = INST_INDEX,
    .appIDDesc = "testtesttesttest"
};

static HapPolicy g_policy = {
    .apl = APL_NORMAL,
    .domain = "test.domain",
    .permStateList = {g_permState}
};
}
class PermissionManagerCoverageTest : public testing::Test {
public:
    static void SetUpTestCase();
    static void TearDownTestCase();
    void SetUp();
    void TearDown();
};

void PermissionManagerCoverageTest::SetUpTestCase()
{
    uint32_t hapSize = 0;
    uint32_t nativeSize = 0;
    uint32_t pefDefSize = 0;
    uint32_t dlpSize = 0;
    std::map<int32_t, TokenIdInfo> tokenIdAplMap;
    AccessTokenInfoManager::GetInstance().Init(hapSize, nativeSize, pefDefSize, dlpSize, tokenIdAplMap);
}

void PermissionManagerCoverageTest::TearDownTestCase() {}

void PermissionManagerCoverageTest::SetUp() {}

void PermissionManagerCoverageTest::TearDown() {}

/*
 * @tc.name: RegisterAddObserverTest001
 * @tc.desc: regist form observer
 * @tc.type: FUNC
 * @tc.require: issueI5RWXF
 */
HWTEST_F(PermissionManagerCoverageTest, RegisterAddObserverTest001, TestSize.Level4)
{
    AccessTokenID selfTokenId = GetSelfTokenID();
    AccessTokenID nativeToken = AccessTokenInfoManager::GetInstance().GetNativeTokenId("privacy_service");
    EXPECT_EQ(RET_SUCCESS, SetSelfTokenID(nativeToken));
    sptr<FormStateObserverStub> formStateObserver = new (std::nothrow) FormStateObserverStub();
    EXPECT_NE(formStateObserver, nullptr);
    EXPECT_EQ(RET_SUCCESS,
        FormManagerAccessClient::GetInstance().RegisterAddObserver(FORM_VISIBLE_NAME, formStateObserver));
    EXPECT_EQ(RET_FAILED,
        FormManagerAccessClient::GetInstance().RegisterAddObserver(FORM_VISIBLE_NAME, nullptr));

    EXPECT_EQ(RET_FAILED,
        FormManagerAccessClient::GetInstance().RegisterRemoveObserver(FORM_VISIBLE_NAME, nullptr));
    EXPECT_EQ(RET_SUCCESS,
        FormManagerAccessClient::GetInstance().RegisterRemoveObserver(FORM_VISIBLE_NAME, formStateObserver));
    EXPECT_EQ(RET_SUCCESS, SetSelfTokenID(selfTokenId));
}

/*
 * @tc.name: FormMgrDiedHandle001
 * @tc.desc: test form manager remote die
 * @tc.type: FUNC
 * @tc.require: issueI5RWXF
 */
HWTEST_F(PermissionManagerCoverageTest, FormMgrDiedHandle001, TestSize.Level4)
{
    FormManagerAccessClient::GetInstance().OnRemoteDiedHandle();
    ASSERT_EQ(nullptr, FormManagerAccessClient::GetInstance().proxy_);
    ASSERT_EQ(nullptr, FormManagerAccessClient::GetInstance().serviceDeathObserver_);
}

class PermissionRecordManagerCoverTestCb1 : public FormStateObserverStub {
public:
    PermissionRecordManagerCoverTestCb1()
    {}

    ~PermissionRecordManagerCoverTestCb1()
    {}

    virtual int32_t NotifyWhetherFormsVisible(const FormVisibilityType visibleType,
        const std::string &bundleName, std::vector<FormInstance> &formInstances) override
    {
        return 0;
    }
};

/**
 * @tc.name: OnRemoteRequest001
 * @tc.desc: FormStateObserverStub::OnRemoteRequest function test
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(PermissionManagerCoverageTest, OnRemoteRequest001, TestSize.Level4)
{
    PermissionRecordManagerCoverTestCb1 callback;

    OHOS::MessageParcel reply;
    OHOS::MessageOption option(OHOS::MessageOption::TF_SYNC);

    OHOS::MessageParcel data1;
    ASSERT_EQ(true, data1.WriteInterfaceToken(IJsFormStateObserver::GetDescriptor()));
    EXPECT_EQ(RET_SUCCESS, callback.OnRemoteRequest(static_cast<uint32_t>(
        IJsFormStateObserver::Message::FORM_STATE_OBSERVER_NOTIFY_WHETHER_FORMS_VISIBLE), data1, reply, option));

    OHOS::MessageParcel data2;
    ASSERT_EQ(true, data2.WriteInterfaceToken(IJsFormStateObserver::GetDescriptor()));
    EXPECT_NE(RET_SUCCESS, callback.OnRemoteRequest(static_cast<uint32_t>(INVALID_IPC_CODE), data2, reply, option));

    MessageParcel data3;
    data3.WriteInterfaceToken(IJsFormStateObserver::GetDescriptor());
    data3.WriteInt32(0);
    ASSERT_EQ(true, data3.WriteString(FORM_VISIBLE_NAME));
    std::vector<FormInstance> formInstances;
    FormInstance formInstance;
    formInstances.emplace_back(formInstance);
    ASSERT_EQ(true, data3.WriteInt32(formInstances.size()));
    for (auto &parcelable: formInstances) {
        ASSERT_EQ(true, data3.WriteParcelable(&parcelable));
    }
    EXPECT_EQ(RET_SUCCESS, callback.OnRemoteRequest(static_cast<uint32_t>(
        IJsFormStateObserver::Message::FORM_STATE_OBSERVER_NOTIFY_WHETHER_FORMS_VISIBLE), data3, reply, option));

    uint32_t code = -1;
    EXPECT_NE(RET_SUCCESS, callback.OnRemoteRequest(code, data3, reply, option));
}

/**
 * @tc.name: UpdateCapStateToDatabase001
 * @tc.desc: Test AccessTokenInfoManager::UpdateCapStateToDatabase
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(PermissionManagerCoverageTest, UpdateCapStateToDatabase001, TestSize.Level4)
{
    AccessTokenIDEx tokenIdEx = {0};
    std::vector<GenericValues> undefValues;
    ASSERT_EQ(RET_SUCCESS, AccessTokenInfoManager::GetInstance().CreateHapTokenInfo(g_info, g_policy, tokenIdEx,
        undefValues));

    AccessTokenID tokenId = tokenIdEx.tokenIdExStruct.tokenID;
    ASSERT_NE(INVALID_TOKENID, tokenId);
    ASSERT_EQ(true, AccessTokenInfoManager::GetInstance().UpdateCapStateToDatabase(tokenId, false));

    AccessTokenInfoManager::GetInstance().RemoveHapTokenInfo(tokenId);
}

/**
 * @tc.name: RestorePermissionPolicy001
 * @tc.desc: PermissionPolicySet::RestorePermissionPolicy function test
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(PermissionManagerCoverageTest, RestorePermissionPolicy001, TestSize.Level4)
{
    GenericValues value1;
    value1.Put(TokenFiledConst::FIELD_TOKEN_ID, RANDOM_TOKENID);
    value1.Put(TokenFiledConst::FIELD_PERMISSION_NAME, "ohos.permission.CAMERA");
    value1.Put(TokenFiledConst::FIELD_GRANT_STATE, static_cast<PermissionState>(3));
    value1.Put(TokenFiledConst::FIELD_GRANT_FLAG, PermissionFlag::PERMISSION_DEFAULT_FLAG);

    AccessTokenID tokenId = RANDOM_TOKENID;
    std::vector<GenericValues> permStateRes1;
    permStateRes1.emplace_back(value1);
    std::vector<GenericValues> extendedPermRes1;
    PermissionDataBrief::GetInstance().RestorePermissionBriefData(
        tokenId, permStateRes1, extendedPermRes1); // ret != RET_SUCCESS
    std::vector<BriefPermData> briefPermDataList;
    ASSERT_EQ(RET_SUCCESS, PermissionDataBrief::GetInstance().GetBriefPermDataByTokenId(tokenId, briefPermDataList));

    GenericValues value2;
    value2.Put(TokenFiledConst::FIELD_TOKEN_ID, RANDOM_TOKENID);
    value2.Put(TokenFiledConst::FIELD_PERMISSION_NAME, "ohos.permission.CAMERA");
    value2.Put(TokenFiledConst::FIELD_GRANT_STATE, PermissionState::PERMISSION_DENIED);
    value2.Put(TokenFiledConst::FIELD_GRANT_FLAG, PermissionFlag::PERMISSION_DEFAULT_FLAG);
    GenericValues value3;
    value3.Put(TokenFiledConst::FIELD_TOKEN_ID, RANDOM_TOKENID);
    value3.Put(TokenFiledConst::FIELD_PERMISSION_NAME, "ohos.permission.MICROPHONE");
    value3.Put(TokenFiledConst::FIELD_GRANT_STATE, PermissionState::PERMISSION_DENIED);
    value3.Put(TokenFiledConst::FIELD_GRANT_FLAG, PermissionFlag::PERMISSION_DEFAULT_FLAG);

    std::vector<GenericValues> permStateRes2;
    permStateRes2.emplace_back(value2);
    permStateRes2.emplace_back(value3);
    briefPermDataList.clear();
    PermissionDataBrief::GetInstance().RestorePermissionBriefData(tokenId,
        permStateRes2, extendedPermRes1); // state.permissionName == iter->permissionName
    ASSERT_EQ(RET_SUCCESS, PermissionDataBrief::GetInstance().GetBriefPermDataByTokenId(tokenId, briefPermDataList));
    ASSERT_EQ(static_cast<uint32_t>(2), briefPermDataList.size());
}

/**
 * @tc.name: AddBriefPermData001
 * @tc.desc: PermissionDataBrief::AddBriefPermData function test
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(PermissionManagerCoverageTest, AddBriefPermData001, TestSize.Level4)
{
    PermissionDataBrief::GetInstance().DeleteBriefPermDataByTokenId(RANDOM_TOKENID);
    std::string permissionName = "ohos.permission.INVALID";
    PermissionState grantStatus = PermissionState::PERMISSION_DENIED;
    PermissionFlag grantFlag = PermissionFlag::PERMISSION_DEFAULT_FLAG;
    std::string value = "test";
    ASSERT_EQ(AccessTokenError::ERR_PERMISSION_NOT_EXIST, PermissionDataBrief::GetInstance().AddBriefPermData(
        RANDOM_TOKENID, permissionName, grantStatus, grantFlag, value));

    permissionName = "ohos.permission.ACTIVITY_MOTION";
    ASSERT_EQ(AccessTokenError::ERR_TOKEN_INVALID, PermissionDataBrief::GetInstance().AddBriefPermData(
        RANDOM_TOKENID, permissionName, grantStatus, grantFlag, value));
}

/**
 * @tc.name: GetMasterAppUndValues001
 * @tc.desc: PermissionManager::GetMasterAppUndValues function test
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(PermissionManagerCoverageTest, GetMasterAppUndValues001, TestSize.Level4)
{
    AccessTokenID tokenID = RANDOM_TOKENID;
    std::vector<GenericValues> undefValues;
    PermissionManager::GetInstance().GetMasterAppUndValues(tokenID, undefValues);
    ASSERT_EQ(true, undefValues.empty());
}

/**
 * @tc.name: InitPermissionList001
 * @tc.desc: PermissionManager::InitPermissionList function test
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(PermissionManagerCoverageTest, InitPermissionList001, TestSize.Level4)
{
    PermissionStatus status1; // user grant permission ohos.permission.ACTIVITY_MOTION with pre-authorization
    status1.permissionName = "ohos.permission.ACTIVITY_MOTION";
    status1.grantStatus = static_cast<int32_t>(PermissionState::PERMISSION_DENIED);
    status1.grantFlag = static_cast<uint32_t>(PermissionFlag::PERMISSION_DEFAULT_FLAG);
    PermissionStatus status2; // user grant permission ohos.permission.ACCESS_BLUETOOTH without pre-authorization
    status2.permissionName = "ohos.permission.ACCESS_BLUETOOTH";
    status2.grantStatus = static_cast<int32_t>(PermissionState::PERMISSION_DENIED);
    status2.grantFlag = static_cast<uint32_t>(PermissionFlag::PERMISSION_DEFAULT_FLAG);
    PreAuthorizationInfo info;
    info.permissionName = "ohos.permission.ACTIVITY_MOTION";

    HapPolicy policy;
    policy.apl = ATokenAplEnum::APL_SYSTEM_BASIC;
    policy.permStateList.emplace_back(status1);
    policy.permStateList.emplace_back(status2);
    policy.preAuthorizationInfo.emplace_back(info);

    HapInfoParams param;
    param.appDistributionType = "os_integration";

    HapInitInfo initInfo;
    initInfo.policy = policy;
    initInfo.installInfo = param;
    std::vector<PermissionStatus> initializedList;
    HapInfoCheckResult result;
    std::vector<GenericValues> undefValues;
    ASSERT_EQ(true, PermissionManager::GetInstance().InitPermissionList(
        initInfo, initializedList, result, undefValues));
    ASSERT_EQ(2, initializedList.size());
    for (const auto& status : initializedList) {
        if (status.permissionName == "ohos.permission.ACTIVITY_MOTION") {
            ASSERT_EQ(static_cast<uint32_t>(PermissionFlag::PERMISSION_SYSTEM_FIXED), status.grantFlag);
        }
    }
    ASSERT_EQ(true, undefValues.empty());
}

/**
 * @tc.name: UpdateUndefinedInfo001
 * @tc.desc: AccessTokenManagerService::UpdateUndefinedInfo function test
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(PermissionManagerCoverageTest, UpdateUndefinedInfo001, TestSize.Level4)
{
    AccessTokenIDEx tokenIdEx = {0};
    std::vector<GenericValues> undefValues;
    ASSERT_EQ(RET_SUCCESS, AccessTokenInfoManager::GetInstance().CreateHapTokenInfo(g_info, g_policy, tokenIdEx,
        undefValues));
    AccessTokenID tokenId = tokenIdEx.tokenIdExStruct.tokenID;
    ASSERT_NE(INVALID_TOKENID, tokenId);

    GenericValues value1;
    value1.Put(TokenFiledConst::FIELD_TOKEN_ID, static_cast<int32_t>(tokenId)); // permissionName invalid
    value1.Put(TokenFiledConst::FIELD_PERMISSION_NAME, "ohos.permission.INVALID");
    value1.Put(TokenFiledConst::FIELD_ACL, 0);
    GenericValues value2;
    value2.Put(TokenFiledConst::FIELD_TOKEN_ID, RANDOM_TOKENID); // tokenID invalid
    value2.Put(TokenFiledConst::FIELD_PERMISSION_NAME, "ohos.permission.ACTIVITY_MOTION");
    value2.Put(TokenFiledConst::FIELD_ACL, 0);
    GenericValues value3;
    value2.Put(TokenFiledConst::FIELD_TOKEN_ID, RANDOM_TOKENID); // tokenID invalid
    value3.Put(TokenFiledConst::FIELD_PERMISSION_NAME, "ohos.permission.MANUAL_ATM_SELF_USE");
    value3.Put(TokenFiledConst::FIELD_ACL, 0);
    std::vector<GenericValues> validValueList;
    validValueList.emplace_back(value1);
    validValueList.emplace_back(value2);
    validValueList.emplace_back(value3);

    PermissionDataBrief::GetInstance().DeleteBriefPermDataByTokenId(RANDOM_TOKENID);
    std::shared_ptr<AccessTokenManagerService> atManagerService =
        DelayedSingleton<AccessTokenManagerService>::GetInstance();
    ASSERT_NE(nullptr, atManagerService);

    std::vector<GenericValues> stateValues;
    std::vector<GenericValues> extendValues;
    atManagerService->UpdateUndefinedInfoCache(validValueList, stateValues, extendValues);
    ASSERT_EQ(true, stateValues.empty());
    ASSERT_EQ(true, extendValues.empty());
    ASSERT_EQ(RET_SUCCESS, atManagerService->DeleteToken(tokenId));
    atManagerService = nullptr;
}

void BackupAndDelOriData(AtmDataType type, std::vector<GenericValues>& oriData)
{
    GenericValues conditionValue;
    // store origin data for backup
    ASSERT_EQ(RET_SUCCESS, AccessTokenDb::GetInstance()->Find(type, conditionValue, oriData));

    DelInfo delInfo;
    delInfo.delType = type;

    std::vector<DelInfo> delInfoVec;
    delInfoVec.emplace_back(delInfo);
    std::vector<AddInfo> addInfoVec;
    // delete origin data from db
    ASSERT_EQ(RET_SUCCESS, AccessTokenDb::GetInstance()->DeleteAndInsertValues(delInfoVec, addInfoVec));
}

void DelTestDataAndRestoreOri(AtmDataType type, const std::vector<GenericValues>& oriData)
{
    DelInfo delInfo;
    delInfo.delType = type;

    AddInfo addInfo;
    addInfo.addType = type;
    addInfo.addValues = oriData;

    std::vector<DelInfo> delInfoVec;
    delInfoVec.emplace_back(delInfo);
    std::vector<AddInfo> addInfoVec;
    addInfoVec.emplace_back(addInfo);
    // delete test data and restore origin data from backup
    ASSERT_EQ(RET_SUCCESS, AccessTokenDb::GetInstance()->DeleteAndInsertValues(delInfoVec, addInfoVec));
}

/**
 * @tc.name: HandleHapUndefinedInfo001
 * @tc.desc: AccessTokenManagerService::HandleHapUndefinedInfo function test
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(PermissionManagerCoverageTest, HandleHapUndefinedInfo001, TestSize.Level4)
{
    AtmDataType type = AtmDataType::ACCESSTOKEN_HAP_UNDEFINE_INFO;
    std::vector<GenericValues> oriData;
    BackupAndDelOriData(type, oriData);

    std::shared_ptr<AccessTokenManagerService> atManagerService =
        DelayedSingleton<AccessTokenManagerService>::GetInstance();
    EXPECT_NE(nullptr, atManagerService);

    std::map<int32_t, TokenIdInfo> tokenIdAplMap;
    std::vector<DelInfo> delInfoVec;
    std::vector<AddInfo> addInfoVec;
    atManagerService->HandleHapUndefinedInfo(tokenIdAplMap, delInfoVec, addInfoVec);

    DelTestDataAndRestoreOri(type, oriData);
    atManagerService = nullptr;
}

/**
 * @tc.name: HandleHapUndefinedInfo002
 * @tc.desc: AccessTokenManagerService::HandleHapUndefinedInfo function test
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(PermissionManagerCoverageTest, HandleHapUndefinedInfo002, TestSize.Level4)
{
    AtmDataType type = AtmDataType::ACCESSTOKEN_HAP_UNDEFINE_INFO;
    std::vector<GenericValues> oriData;
    BackupAndDelOriData(type, oriData);

    GenericValues value;
    value.Put(TokenFiledConst::FIELD_TOKEN_ID, RANDOM_TOKENID);
    value.Put(TokenFiledConst::FIELD_PERMISSION_NAME, "ohos.permission.SET_ENTERPRISE_INFO"); // mdm permission
    value.Put(TokenFiledConst::FIELD_ACL, 0);
    value.Put(TokenFiledConst::FIELD_APP_DISTRIBUTION_TYPE, "os_integration");
    AddInfo addInfo;
    addInfo.addType = type;
    addInfo.addValues.emplace_back(value);

    std::vector<DelInfo> delInfoVec;
    std::vector<AddInfo> addInfoVec;
    addInfoVec.emplace_back(addInfo);
    // add test data
    EXPECT_EQ(RET_SUCCESS, AccessTokenDb::GetInstance()->DeleteAndInsertValues(delInfoVec, addInfoVec));

    std::shared_ptr<AccessTokenManagerService> atManagerService =
        DelayedSingleton<AccessTokenManagerService>::GetInstance();
    EXPECT_NE(nullptr, atManagerService);

    std::map<int32_t, TokenIdInfo> tokenIdAplMap;
    std::vector<DelInfo> delInfoVec2;
    std::vector<AddInfo> addInfoVec2;
    atManagerService->HandleHapUndefinedInfo(tokenIdAplMap, delInfoVec2, addInfoVec2);

    DelTestDataAndRestoreOri(type, oriData);
    atManagerService = nullptr;
}

/**
 * @tc.name: HandleHapUndefinedInfo003
 * @tc.desc: AccessTokenManagerService::HandleHapUndefinedInfo function test
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(PermissionManagerCoverageTest, HandleHapUndefinedInfo003, TestSize.Level4)
{
    AtmDataType type = AtmDataType::ACCESSTOKEN_HAP_UNDEFINE_INFO;
    std::vector<GenericValues> oriData;
    BackupAndDelOriData(type, oriData);

    GenericValues value;
    value.Put(TokenFiledConst::FIELD_TOKEN_ID, RANDOM_TOKENID);
    // enterprise_normal permission
    value.Put(TokenFiledConst::FIELD_PERMISSION_NAME, "ohos.permission.FILE_GUARD_MANAGER");
    value.Put(TokenFiledConst::FIELD_ACL, 0);
    value.Put(TokenFiledConst::FIELD_APP_DISTRIBUTION_TYPE, "os_integration");
    AddInfo addInfo;
    addInfo.addType = type;
    addInfo.addValues.emplace_back(value);

    std::vector<DelInfo> delInfoVec;
    std::vector<AddInfo> addInfoVec;
    addInfoVec.emplace_back(addInfo);
    // add test data
    EXPECT_EQ(RET_SUCCESS, AccessTokenDb::GetInstance()->DeleteAndInsertValues(delInfoVec, addInfoVec));

    std::shared_ptr<AccessTokenManagerService> atManagerService =
        DelayedSingleton<AccessTokenManagerService>::GetInstance();
    EXPECT_NE(nullptr, atManagerService);

    std::map<int32_t, TokenIdInfo> tokenIdAplMap;
    std::vector<DelInfo> delInfoVec2;
    std::vector<AddInfo> addInfoVec2;
    atManagerService->HandleHapUndefinedInfo(tokenIdAplMap, delInfoVec2, addInfoVec2);

    DelTestDataAndRestoreOri(type, oriData);
    atManagerService = nullptr;
}

/**
 * @tc.name: HandlePermDefUpdate001
 * @tc.desc: AccessTokenManagerService::HandlePermDefUpdate function test
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(PermissionManagerCoverageTest, HandlePermDefUpdate001, TestSize.Level4)
{
    AtmDataType type = AtmDataType::ACCESSTOKEN_SYSTEM_CONFIG;
    std::vector<GenericValues> oriData;
    BackupAndDelOriData(type, oriData);

    std::shared_ptr<AccessTokenManagerService> atManagerService =
        DelayedSingleton<AccessTokenManagerService>::GetInstance();
    EXPECT_NE(nullptr, atManagerService);
 
    std::map<int32_t, TokenIdInfo> tokenIdAplMap;
    atManagerService->HandlePermDefUpdate(tokenIdAplMap); // dbPermDefVersion is empty

    DelTestDataAndRestoreOri(type, oriData);
    sleep(2);
    atManagerService = nullptr;
}

/**
 * @tc.name: HandlePermDefUpdate002
 * @tc.desc: AccessTokenManagerService::HandlePermDefUpdate function test
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(PermissionManagerCoverageTest, HandlePermDefUpdate002, TestSize.Level4)
{
    AtmDataType type = AtmDataType::ACCESSTOKEN_SYSTEM_CONFIG;
    std::vector<GenericValues> oriData;
    BackupAndDelOriData(type, oriData);

    GenericValues addValue;
    addValue.Put(TokenFiledConst::FIELD_NAME, PERM_DEF_VERSION);
    addValue.Put(TokenFiledConst::FIELD_VALUE, "sfdsfdsfsf"); // random input
    AddInfo addInfo;
    addInfo.addType = type;
    addInfo.addValues.emplace_back(addValue);

    std::vector<DelInfo> delInfoVec;
    std::vector<AddInfo> addInfoVec;
    addInfoVec.emplace_back(addInfo);
    // update permission define version in db to test data
    EXPECT_EQ(RET_SUCCESS, AccessTokenDb::GetInstance()->DeleteAndInsertValues(delInfoVec, addInfoVec));

    std::shared_ptr<AccessTokenManagerService> atManagerService =
        DelayedSingleton<AccessTokenManagerService>::GetInstance();
    EXPECT_NE(nullptr, atManagerService);
 
    std::map<int32_t, TokenIdInfo> tokenIdAplMap;
    atManagerService->HandlePermDefUpdate(tokenIdAplMap); // dbPermDefVersion is not empty

    DelTestDataAndRestoreOri(type, oriData);
    sleep(2);
    atManagerService = nullptr;
}

/**
 * @tc.name: IsPermAvailableRangeSatisfied001
 * @tc.desc: PermissionManager::IsPermAvailableRangeSatisfied function test
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(PermissionManagerCoverageTest, IsPermAvailableRangeSatisfied001, TestSize.Level4)
{
    PermissionBriefDef briefDef;
    briefDef.availableType = ATokenAvailableTypeEnum::ENTERPRISE_NORMAL;
    char permissionName[] = "ohos.permission.FILE_GUARD_MANAGER";
    briefDef.permissionName = permissionName;
    std::string appDistributionType = "os_integration";
    bool isSystemApp = false;
    PermissionRulesEnum rule;
    HapInitInfo initInfo;
    system::SetBoolParameter(ENTERPRISE_NORMAL_CHECK, true);
    ASSERT_FALSE(PermissionManager::GetInstance().IsPermAvailableRangeSatisfied(
        briefDef, appDistributionType, isSystemApp, rule, initInfo));
    system::SetBoolParameter(ENTERPRISE_NORMAL_CHECK, false);
    ASSERT_TRUE(PermissionManager::GetInstance().IsPermAvailableRangeSatisfied(
        briefDef, appDistributionType, isSystemApp, rule, initInfo));
}

/**
 * @tc.name: SetFlagIfNeedTest001
 * @tc.desc: AccessTokenManagerService::SetFlagIfNeed function test
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(PermissionManagerCoverageTest, SetFlagIfNeedTest001, TestSize.Level4)
{
    std::shared_ptr<AccessTokenManagerService> atManagerService =
        DelayedSingleton<AccessTokenManagerService>::GetInstance();
    EXPECT_NE(nullptr, atManagerService);

    AccessTokenServiceConfig config;
    int32_t cancelTime = 0;
    uint32_t parseConfigFlag = 0;
    atManagerService->SetFlagIfNeed(config, cancelTime, parseConfigFlag);
    EXPECT_EQ(parseConfigFlag, 0);

    config.grantBundleName = "ability";
    config.grantAbilityName = "ability";
    config.grantServiceAbilityName = "ability";
    config.permStateAbilityName = "ability";
    config.globalSwitchAbilityName = "ability";
    config.cancelTime = DELAY_TIME;
    config.applicationSettingAbilityName = "ability";
    config.openSettingAbilityName = "ability";

    int32_t cancelTime2 = 10;
    uint32_t parseConfigFlag2 = 0;
    atManagerService->SetFlagIfNeed(config, cancelTime2, parseConfigFlag2);
    EXPECT_NE(parseConfigFlag2, 0);

    atManagerService = nullptr;
}
} // namespace AccessToken
} // namespace Security
} // namespace OHOS
