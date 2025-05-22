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
#include "accesstoken_kit.h"
#include "access_token_error.h"
#define private public
#include "accesstoken_info_manager.h"
#include "form_manager_access_client.h"
#include "permission_manager.h"
#undef private
#include "accesstoken_callback_stubs.h"
#include "callback_death_recipients.h"
#include "token_field_const.h"
#include "token_setproc.h"
#include "permission_data_brief.h"

using namespace testing::ext;

namespace OHOS {
namespace Security {
namespace AccessToken {
namespace {
static const std::string FORM_VISIBLE_NAME = "#1";
static constexpr int USER_ID = 100;
static constexpr int INST_INDEX = 0;
static constexpr int32_t RANDOM_TOKENID = 123;
static constexpr int INVALID_IPC_CODE = 0;

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
    std::map<int32_t, int32_t> tokenId2apl;
    AccessTokenInfoManager::GetInstance().Init(hapSize, nativeSize, pefDefSize, dlpSize, tokenId2apl);
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
    ASSERT_NE(formStateObserver, nullptr);
    ASSERT_EQ(RET_SUCCESS,
        FormManagerAccessClient::GetInstance().RegisterAddObserver(FORM_VISIBLE_NAME, formStateObserver));
    ASSERT_EQ(RET_FAILED,
        FormManagerAccessClient::GetInstance().RegisterAddObserver(FORM_VISIBLE_NAME, nullptr));

    ASSERT_EQ(RET_FAILED,
        FormManagerAccessClient::GetInstance().RegisterRemoveObserver(FORM_VISIBLE_NAME, nullptr));
    ASSERT_EQ(RET_SUCCESS,
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

    permissionName = "ohos.permission.READ_MEDIA";
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
 * @tc.name: FillDelValues001
 * @tc.desc: AccessTokenInfoManager::FillDelValues function test
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(PermissionManagerCoverageTest, FillDelValues001, TestSize.Level4)
{
    AccessTokenID tokenID = RANDOM_TOKENID;
    bool isSystemRes = false;
    std::vector<GenericValues> permExtendValues;
    std::vector<GenericValues> undefValues;
    std::vector<GenericValues> deleteValues;
    AccessTokenInfoManager::GetInstance().FillDelValues(tokenID, isSystemRes, permExtendValues, undefValues,
        deleteValues);
    ASSERT_EQ(2, deleteValues.size());

    isSystemRes = true;
    std::vector<GenericValues> deleteValues2;
    AccessTokenInfoManager::GetInstance().FillDelValues(tokenID, isSystemRes, permExtendValues, undefValues,
        deleteValues2);
    ASSERT_EQ(3, deleteValues2.size());

    GenericValues conditionValue;
    conditionValue.Put(TokenFiledConst::FIELD_TOKEN_ID, static_cast<int32_t>(tokenID));
    permExtendValues.emplace_back(conditionValue);
    std::vector<GenericValues> deleteValues3;
    AccessTokenInfoManager::GetInstance().FillDelValues(tokenID, isSystemRes, permExtendValues, undefValues,
        deleteValues3);
    ASSERT_EQ(4, deleteValues3.size());

    undefValues.emplace_back(conditionValue);
    std::vector<GenericValues> deleteValues4;
    AccessTokenInfoManager::GetInstance().FillDelValues(tokenID, isSystemRes, permExtendValues, undefValues,
        deleteValues4);
    ASSERT_EQ(5, deleteValues4.size());
}
} // namespace AccessToken
} // namespace Security
} // namespace OHOS
