/*
 * Copyright (c) 2025 Huawei Device Co., Ltd.
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

#include "accesstoken_manager_service_test.h"
#include "gtest/gtest.h"
#include <gtest/hwext/gtest-multithread.h>

#include "access_token_db_operator.h"
#include "access_token_db.h"
#include "access_token_error.h"
#include "atm_tools_param_info_parcel.h"
#include "parameters.h"
#include "permission_map.h"
#include "token_field_const.h"
const char* DEVELOPER_MODE_STATE = "const.security.developermode.state";


using namespace testing::ext;
using namespace testing::mt;
using namespace OHOS;

namespace OHOS {
namespace Security {
namespace AccessToken {
namespace {
static constexpr int32_t USER_ID = 100;
static constexpr int32_t INST_INDEX = 0;
static constexpr int32_t API_VERSION_9 = 9;
static constexpr int32_t RANDOM_TOKENID = 123;
static constexpr int32_t MULTIPLE_COUNT = 10;

static PermissionStatus g_state1 = { // kernel permission
    .permissionName = "ohos.permission.KERNEL_ATM_SELF_USE",
    .grantStatus = static_cast<int32_t>(PermissionState::PERMISSION_GRANTED),
    .grantFlag = static_cast<uint32_t>(PermissionFlag::PERMISSION_SYSTEM_FIXED)
};

static PermissionStatus g_state2 = { // invalid permission
    .permissionName = "ohos.permission.INVALIDA",
    .grantStatus = PermissionState::PERMISSION_DENIED,
    .grantFlag = PermissionFlag::PERMISSION_DEFAULT_FLAG
};

static PermissionStatus g_state3 = { // invalid permission
    .permissionName = "ohos.permission.INVALIDB",
    .grantStatus = PermissionState::PERMISSION_DENIED,
    .grantFlag = PermissionFlag::PERMISSION_DEFAULT_FLAG
};

static PermissionStatus g_state4 = { // user grant permission
    .permissionName = "ohos.permission.READ_MEDIA",
    .grantStatus = static_cast<int32_t>(PermissionState::PERMISSION_GRANTED),
    .grantFlag = static_cast<uint32_t>(PermissionFlag::PERMISSION_USER_FIXED)
};

static PermissionStatus g_state5 = { // system grant permission
    .permissionName = "ohos.permission.REFRESH_USER_ACTION",
    .grantStatus = static_cast<int32_t>(PermissionState::PERMISSION_DENIED),
    .grantFlag = static_cast<uint32_t>(PermissionFlag::PERMISSION_DEFAULT_FLAG)
};

static PermissionStatus g_state6 = { // system core
    .permissionName = "ohos.permission.POWER_MANAGER",
    .grantStatus = static_cast<int32_t>(PermissionState::PERMISSION_DENIED),
    .grantFlag = static_cast<uint32_t>(PermissionFlag::PERMISSION_DEFAULT_FLAG)
};

static HapInfoParams g_info = {
    .userID = USER_ID,
    .bundleName = "accesstoken_manager_service_test",
    .instIndex = INST_INDEX,
    .dlpType = static_cast<int>(HapDlpType::DLP_COMMON),
    .apiVersion = API_VERSION_9,
    .isSystemApp = false,
    .appIDDesc = "accesstoken_manager_service_test",
};

static HapPolicy g_policy = {
    .apl = ATokenAplEnum::APL_SYSTEM_BASIC,
    .domain = "test.domain",
    .permStateList = {g_state1, g_state2},
    .aclRequestedList = { "ohos.permission.INVALIDA" }, // kernel permission with value no need acl
    .aclExtendedMap = { std::make_pair("ohos.permission.KERNEL_ATM_SELF_USE", "test") },
};
}

void AccessTokenManagerServiceTest::SetUpTestCase()
{
}

void AccessTokenManagerServiceTest::TearDownTestCase()
{
}

void AccessTokenManagerServiceTest::SetUp()
{
    atManagerService_ = DelayedSingleton<AccessTokenManagerService>::GetInstance();
    EXPECT_NE(nullptr, atManagerService_);
}

void AccessTokenManagerServiceTest::TearDown()
{
    atManagerService_ = nullptr;
}

/**
 * @tc.name: DumpTokenInfoFuncTest001
 * @tc.desc: test DumpTokenInfo with DEVELOPER_MODE_STATE
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(AccessTokenManagerServiceTest, DumpTokenInfoFuncTest001, TestSize.Level1)
{
    std::string dumpInfo;
    AtmToolsParamInfoParcel infoParcel;
    infoParcel.info.processName = "hdcd";

    bool state = system::GetBoolParameter(DEVELOPER_MODE_STATE, false);

    system::SetBoolParameter(DEVELOPER_MODE_STATE, false);
    bool ret = system::GetBoolParameter(DEVELOPER_MODE_STATE, false);
    EXPECT_FALSE(ret);

    std::shared_ptr<AccessTokenManagerService> atManagerService_ =
        DelayedSingleton<AccessTokenManagerService>::GetInstance();
    atManagerService_->DumpTokenInfo(infoParcel, dumpInfo);
    EXPECT_EQ("Developer mode not support.", dumpInfo);

    system::SetBoolParameter(DEVELOPER_MODE_STATE, true);
    ret = system::GetBoolParameter(DEVELOPER_MODE_STATE, false);
    EXPECT_TRUE(ret);
    atManagerService_->DumpTokenInfo(infoParcel, dumpInfo);
    EXPECT_NE("", dumpInfo);

    system::SetBoolParameter(DEVELOPER_MODE_STATE, state);
}

void AccessTokenManagerServiceTest::CreateHapToken(const HapInfoParcel& infoParCel, const HapPolicyParcel& policyParcel,
    AccessTokenID& tokenId, std::map<int32_t, TokenIdInfo>& tokenIdAplMap, bool hasInit)
{
    if (!hasInit) {
        atManagerService_->Initialize();
    }

    uint64_t fullTokenId;
    HapInfoCheckResultIdl result;
    int32_t res = atManagerService_->InitHapToken(infoParCel, policyParcel, fullTokenId, result);
    ASSERT_EQ(RET_SUCCESS, res);

    AccessTokenIDEx tokenIDEx;
    tokenIDEx.tokenIDEx = fullTokenId;
    tokenId = tokenIDEx.tokenIdExStruct.tokenID;
    ASSERT_NE(INVALID_TOKENID, tokenId);
    tokenIdAplMap[static_cast<int32_t>(tokenId)].apl = g_policy.apl;
}

/**
 * @tc.name: SystemConfigTest001
 * @tc.desc: test permission define version from db same with permission define version from rodata
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(AccessTokenManagerServiceTest, SystemConfigTest001, TestSize.Level0)
{
    GenericValues conditionValue;
    conditionValue.Put(TokenFiledConst::FIELD_NAME, PERM_DEF_VERSION);
    std::vector<GenericValues> results;
    ASSERT_EQ(0, AccessTokenDb::GetInstance()->Find(AtmDataType::ACCESSTOKEN_SYSTEM_CONFIG, conditionValue, results));
    ASSERT_EQ(false, results.empty());

    std::string dbPermDefVersion = results[0].GetString(TokenFiledConst::FIELD_VALUE);
    const char* curPermDefVersion = GetPermDefVersion();
    ASSERT_EQ(true, dbPermDefVersion == curPermDefVersion);
}

/**
 * @tc.name: InitHapTokenTest001
 * @tc.desc: test insert or remove data to undefine table when install or uninstall hap
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(AccessTokenManagerServiceTest, InitHapTokenTest001, TestSize.Level0)
{
    HapInfoParcel infoParCel;
    infoParCel.hapInfoParameter = g_info;
    HapPolicyParcel policyParcel;
    policyParcel.hapPolicy = g_policy; // KERNEL_ATM_SELF_USE(hasValue is true) + INVALIDA
    AccessTokenID tokenId;
    std::map<int32_t, TokenIdInfo> tokenIdAplMap;
    CreateHapToken(infoParCel, policyParcel, tokenId, tokenIdAplMap);

    // query undefine table
    GenericValues conditionValue;
    conditionValue.Put(TokenFiledConst::FIELD_TOKEN_ID, static_cast<int32_t>(tokenId));
    std::vector<GenericValues> results;
    ASSERT_EQ(0, AccessTokenDb::GetInstance()->Find(
        AtmDataType::ACCESSTOKEN_HAP_UNDEFINE_INFO, conditionValue, results));
    ASSERT_EQ(1, results.size());
    ASSERT_EQ(static_cast<int32_t>(tokenId), results[0].GetInt(TokenFiledConst::FIELD_TOKEN_ID));
    ASSERT_EQ(g_state2.permissionName, results[0].GetString(TokenFiledConst::FIELD_PERMISSION_NAME));
    ASSERT_EQ(1, results[0].GetInt(TokenFiledConst::FIELD_ACL));
    ASSERT_EQ(g_policy.aclExtendedMap[g_state2.permissionName], results[0].GetString(TokenFiledConst::FIELD_VALUE));

    ASSERT_EQ(0, atManagerService_->DeleteToken(tokenId)); // delete token

    // after delete token, data remove from undefine table
    std::vector<GenericValues> results1;
    ASSERT_EQ(0, AccessTokenDb::GetInstance()->Find(
        AtmDataType::ACCESSTOKEN_HAP_UNDEFINE_INFO, conditionValue, results1));
    ASSERT_EQ(0, results1.size());
}

/**
 * @tc.name: InitHapTokenTest002
 * @tc.desc: test dlp app has same undefined info with the master app
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(AccessTokenManagerServiceTest, InitHapTokenTest002, TestSize.Level0)
{
    HapInfoParcel infoParCel;
    infoParCel.hapInfoParameter = g_info;
    HapPolicyParcel policyParcel;
    policyParcel.hapPolicy = g_policy; // KERNEL_ATM_SELF_USE + INVALIDA
    AccessTokenID tokenId;
    std::map<int32_t, TokenIdInfo> tokenIdAplMap;
    CreateHapToken(infoParCel, policyParcel, tokenId, tokenIdAplMap); // create master app

    HapInfoParcel infoParCel2;
    infoParCel2.hapInfoParameter = g_info;
    infoParCel2.hapInfoParameter.instIndex = INST_INDEX + 1;
    infoParCel2.hapInfoParameter.dlpType = static_cast<int>(HapDlpType::DLP_FULL_CONTROL);
    HapPolicyParcel policyParcel2;
    policyParcel2.hapPolicy = g_policy;  // KERNEL_ATM_SELF_USE + INVALIDB, INVALIDB diff from INVALIDA in master app
    policyParcel2.hapPolicy.permStateList = {g_state1, g_state3};
    AccessTokenID tokenId2;
    CreateHapToken(infoParCel2, policyParcel2, tokenId2, tokenIdAplMap, true); // create dlp app

    // query undefine table for dlp app
    GenericValues conditionValue;
    conditionValue.Put(TokenFiledConst::FIELD_TOKEN_ID, static_cast<int32_t>(tokenId2));
    std::vector<GenericValues> results;
    ASSERT_EQ(0, AccessTokenDb::GetInstance()->Find(
        AtmDataType::ACCESSTOKEN_HAP_UNDEFINE_INFO, conditionValue, results));
    ASSERT_EQ(1, results.size());
    ASSERT_EQ(static_cast<int32_t>(tokenId2), results[0].GetInt(TokenFiledConst::FIELD_TOKEN_ID));
    // dlp app has the same undefine data with mater app, INVALIDB change to INVALIDA
    ASSERT_EQ(g_state2.permissionName, results[0].GetString(TokenFiledConst::FIELD_PERMISSION_NAME));

    ASSERT_EQ(0, atManagerService_->DeleteToken(tokenId));
    ASSERT_EQ(0, atManagerService_->DeleteToken(tokenId2));
}

/**
 * @tc.name: UpdateHapTokenTest001
 * @tc.desc: test update undefine permission change
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(AccessTokenManagerServiceTest, UpdateHapTokenTest001, TestSize.Level0)
{
    HapInfoParcel infoParCel;
    infoParCel.hapInfoParameter = g_info;
    HapPolicyParcel policyParcel;
    policyParcel.hapPolicy = g_policy; // KERNEL_ATM_SELF_USE + INVALIDA
    AccessTokenID tokenId;
    std::map<int32_t, TokenIdInfo> tokenIdAplMap;
    CreateHapToken(infoParCel, policyParcel, tokenId, tokenIdAplMap);

    // query undefine table
    GenericValues conditionValue;
    conditionValue.Put(TokenFiledConst::FIELD_TOKEN_ID, static_cast<int32_t>(tokenId));
    std::vector<GenericValues> results;
    ASSERT_EQ(0, AccessTokenDb::GetInstance()->Find(
        AtmDataType::ACCESSTOKEN_HAP_UNDEFINE_INFO, conditionValue, results));
    ASSERT_EQ(1, results.size());
    ASSERT_EQ(g_state2.permissionName, results[0].GetString(TokenFiledConst::FIELD_PERMISSION_NAME)); // INVALIDA

    // update hap
    uint64_t fullTokenId;
    AccessTokenIDEx tokenIDEx;
    tokenIDEx.tokenIdExStruct.tokenID = tokenId;
    fullTokenId = tokenIDEx.tokenIDEx;
    policyParcel.hapPolicy.permStateList = {g_state1, g_state3}; // KERNEL_ATM_SELF_USE + INVALIDB
    UpdateHapInfoParamsIdl infoIdl;
    infoIdl.appIDDesc = g_info.appIDDesc;
    infoIdl.apiVersion = g_info.apiVersion;
    infoIdl.isSystemApp = g_info.isSystemApp;
    infoIdl.appDistributionType = g_info.appDistributionType;
    infoIdl.isAtomicService = g_info.isAtomicService;
    HapInfoCheckResultIdl resultInfoIdl;
    ASSERT_EQ(0, atManagerService_->UpdateHapToken(fullTokenId, infoIdl, policyParcel, resultInfoIdl));

    std::vector<GenericValues> results2;
    ASSERT_EQ(0, AccessTokenDb::GetInstance()->Find(
        AtmDataType::ACCESSTOKEN_HAP_UNDEFINE_INFO, conditionValue, results2));
    ASSERT_EQ(1, results2.size());
    ASSERT_EQ(static_cast<int32_t>(tokenId), results2[0].GetInt(TokenFiledConst::FIELD_TOKEN_ID));
    // undefine permission change from INVALIDA to INVALIDB
    ASSERT_EQ(g_state3.permissionName, results2[0].GetString(TokenFiledConst::FIELD_PERMISSION_NAME));

    ASSERT_EQ(0, atManagerService_->DeleteToken(tokenId));
}

/**
 * @tc.name: UpdateHapTokenTest002
 * @tc.desc: test ota update acl check fail return false
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(AccessTokenManagerServiceTest, UpdateHapTokenTest002, TestSize.Level0)
{
    HapInfoParcel infoParCel;
    infoParCel.hapInfoParameter = g_info;
    HapPolicyParcel policyParcel;
    policyParcel.hapPolicy = g_policy; // KERNEL_ATM_SELF_USE + INVALIDA
    AccessTokenID tokenId;
    std::map<int32_t, TokenIdInfo> tokenIdAplMap;
    CreateHapToken(infoParCel, policyParcel, tokenId, tokenIdAplMap);

    // update hap
    uint64_t fullTokenId;
    AccessTokenIDEx tokenIDEx;
    tokenIDEx.tokenIdExStruct.tokenID = tokenId;
    fullTokenId = tokenIDEx.tokenIDEx;
    policyParcel.hapPolicy.aclExtendedMap = {};
    UpdateHapInfoParamsIdl infoIdl;
    infoIdl.appIDDesc = g_info.appIDDesc;
    infoIdl.apiVersion = g_info.apiVersion;
    infoIdl.isSystemApp = g_info.isSystemApp;
    infoIdl.appDistributionType = g_info.appDistributionType;
    infoIdl.isAtomicService = g_info.isAtomicService;
    infoIdl.dataRefresh = false;
    HapInfoCheckResultIdl resultInfoIdl;
    ASSERT_EQ(0, atManagerService_->UpdateHapToken(fullTokenId, infoIdl, policyParcel, resultInfoIdl));
    ASSERT_EQ(PermissionRulesEnumIdl::PERMISSION_ACL_RULE, resultInfoIdl.rule);

    ASSERT_EQ(0, atManagerService_->DeleteToken(tokenId));
}

/**
 * @tc.name: UpdateHapTokenTest003
 * @tc.desc: test ota update acl check fail return success and permission store in undefine table
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(AccessTokenManagerServiceTest, UpdateHapTokenTest003, TestSize.Level0)
{
    HapInfoParcel infoParCel;
    infoParCel.hapInfoParameter = g_info;
    HapPolicyParcel policyParcel;
    policyParcel.hapPolicy = g_policy; // KERNEL_ATM_SELF_USE + INVALIDA
    AccessTokenID tokenId;
    std::map<int32_t, TokenIdInfo> tokenIdAplMap;
    CreateHapToken(infoParCel, policyParcel, tokenId, tokenIdAplMap);

    // query undefine table
    GenericValues conditionValue;
    conditionValue.Put(TokenFiledConst::FIELD_TOKEN_ID, static_cast<int32_t>(tokenId));
    std::vector<GenericValues> results;
    ASSERT_EQ(0, AccessTokenDb::GetInstance()->Find(
        AtmDataType::ACCESSTOKEN_HAP_UNDEFINE_INFO, conditionValue, results));
    ASSERT_EQ(1, results.size());
    ASSERT_EQ(g_state2.permissionName, results[0].GetString(TokenFiledConst::FIELD_PERMISSION_NAME)); // INVALIDA

    // update hap
    uint64_t fullTokenId;
    AccessTokenIDEx tokenIDEx;
    tokenIDEx.tokenIdExStruct.tokenID = tokenId;
    fullTokenId = tokenIDEx.tokenIDEx;
    policyParcel.hapPolicy.permStateList = {g_state1}; // KERNEL_ATM_SELF_USE support value without value need acl
    policyParcel.hapPolicy.aclExtendedMap = {}; // without value
    UpdateHapInfoParamsIdl infoIdl;
    infoIdl.appIDDesc = g_info.appIDDesc;
    infoIdl.apiVersion = g_info.apiVersion;
    infoIdl.isSystemApp = g_info.isSystemApp;
    infoIdl.appDistributionType = g_info.appDistributionType;
    infoIdl.isAtomicService = g_info.isAtomicService;
    infoIdl.dataRefresh = true;
    HapInfoCheckResultIdl resultInfoIdl;
    ASSERT_EQ(0, atManagerService_->UpdateHapToken(fullTokenId, infoIdl, policyParcel, resultInfoIdl));

    std::vector<GenericValues> results2;
    ASSERT_EQ(0, AccessTokenDb::GetInstance()->Find(
        AtmDataType::ACCESSTOKEN_HAP_UNDEFINE_INFO, conditionValue, results2));
    ASSERT_EQ(1, results2.size());
    ASSERT_EQ(static_cast<int32_t>(tokenId), results2[0].GetInt(TokenFiledConst::FIELD_TOKEN_ID));
    // undefine permission change from INVALIDA to INVALIDB
    ASSERT_EQ(g_state1.permissionName, results2[0].GetString(TokenFiledConst::FIELD_PERMISSION_NAME));

    ASSERT_EQ(0, atManagerService_->DeleteToken(tokenId));
}

void BackupAndDelOriData(std::vector<GenericValues>& oriData)
{
    GenericValues conditionValue;
    // store origin data for backup
    ASSERT_EQ(RET_SUCCESS, AccessTokenDb::GetInstance()->Find(AtmDataType::ACCESSTOKEN_HAP_UNDEFINE_INFO,
        conditionValue, oriData));

    DelInfo delInfo;
    delInfo.delType = AtmDataType::ACCESSTOKEN_HAP_UNDEFINE_INFO;

    std::vector<DelInfo> delInfoVec;
    delInfoVec.emplace_back(delInfo);
    std::vector<AddInfo> addInfoVec;
    // delete origin data from db
    ASSERT_EQ(RET_SUCCESS, AccessTokenDb::GetInstance()->DeleteAndInsertValues(delInfoVec, addInfoVec));
}

void AccessTokenManagerServiceTest::DelTestDataAndRestoreOri(AccessTokenID tokenId,
    const std::vector<GenericValues>& oriData)
{
    EXPECT_EQ(0, atManagerService_->DeleteToken(tokenId));

    DelInfo delInfo;
    delInfo.delType = AtmDataType::ACCESSTOKEN_HAP_UNDEFINE_INFO;

    AddInfo addInfo;
    addInfo.addType = AtmDataType::ACCESSTOKEN_HAP_UNDEFINE_INFO;
    addInfo.addValues = oriData;

    std::vector<DelInfo> delInfoVec;
    delInfoVec.emplace_back(delInfo);
    std::vector<AddInfo> addInfoVec;
    addInfoVec.emplace_back(addInfo);
    // delete test data and restore origin data from backup
    ASSERT_EQ(RET_SUCCESS, AccessTokenDb::GetInstance()->DeleteAndInsertValues(delInfoVec, addInfoVec));
}

/**
 * @tc.name: OTATest001
 * @tc.desc: test after ota invalid tokenId remain
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(AccessTokenManagerServiceTest, OTATest001, TestSize.Level0)
{
    AtmDataType type = AtmDataType::ACCESSTOKEN_HAP_UNDEFINE_INFO;
    std::vector<GenericValues> oriData;
    BackupAndDelOriData(oriData);

    HapInfoParcel infoParCel;
    infoParCel.hapInfoParameter = g_info;
    HapPolicyParcel policyParcel;
    policyParcel.hapPolicy = g_policy;
    policyParcel.hapPolicy.permStateList = {g_state4};
    policyParcel.hapPolicy.aclExtendedMap = {};
    AccessTokenID tokenId;
    std::map<int32_t, TokenIdInfo> tokenIdAplMap;
    CreateHapToken(infoParCel, policyParcel, tokenId, tokenIdAplMap);

    GenericValues value; // system grant
    value.Put(TokenFiledConst::FIELD_TOKEN_ID, RANDOM_TOKENID);
    value.Put(TokenFiledConst::FIELD_PERMISSION_NAME, g_state2.permissionName); // INVALIDA
    value.Put(TokenFiledConst::FIELD_ACL, 0);
    AddInfo addInfo;
    addInfo.addType = type;
    addInfo.addValues.emplace_back(value);

    std::vector<DelInfo> delInfoVec;
    std::vector<AddInfo> addInfoVec;
    addInfoVec.emplace_back(addInfo);
    EXPECT_EQ(0, AccessTokenDb::GetInstance()->DeleteAndInsertValues(delInfoVec, addInfoVec)); // add test data

    std::vector<DelInfo> delInfoVec2;
    std::vector<AddInfo> addInfoVec2;
    atManagerService_->HandleHapUndefinedInfo(tokenIdAplMap, delInfoVec2, addInfoVec2);
    EXPECT_EQ(0, AccessTokenDb::GetInstance()->DeleteAndInsertValues(delInfoVec2, addInfoVec2));

    GenericValues conditionValue;
    conditionValue.Put(TokenFiledConst::FIELD_TOKEN_ID, RANDOM_TOKENID);
    std::vector<GenericValues> results;
    EXPECT_EQ(0, AccessTokenDb::GetInstance()->Find(type, conditionValue, results));
    EXPECT_EQ(false, results.empty()); // undefine table is not empty

    DelTestDataAndRestoreOri(tokenId, oriData);
}

/**
 * @tc.name: OTATest002
 * @tc.desc: test after ota invalid permission remain
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(AccessTokenManagerServiceTest, OTATest002, TestSize.Level0)
{
    AtmDataType type = AtmDataType::ACCESSTOKEN_HAP_UNDEFINE_INFO;
    std::vector<GenericValues> oriData;
    BackupAndDelOriData(oriData);

    HapInfoParcel infoParCel;
    infoParCel.hapInfoParameter = g_info;
    HapPolicyParcel policyParcel;
    policyParcel.hapPolicy = g_policy;
    policyParcel.hapPolicy.permStateList = {g_state4};
    policyParcel.hapPolicy.aclExtendedMap = {};
    AccessTokenID tokenId;
    std::map<int32_t, TokenIdInfo> tokenIdAplMap;
    CreateHapToken(infoParCel, policyParcel, tokenId, tokenIdAplMap);

    GenericValues value; // system grant
    value.Put(TokenFiledConst::FIELD_TOKEN_ID, static_cast<int32_t>(tokenId));
    value.Put(TokenFiledConst::FIELD_PERMISSION_NAME, g_state2.permissionName); // INVALIDA
    value.Put(TokenFiledConst::FIELD_ACL, 0);
    AddInfo addInfo;
    addInfo.addType = type;
    addInfo.addValues.emplace_back(value);

    std::vector<DelInfo> delInfoVec;
    std::vector<AddInfo> addInfoVec;
    addInfoVec.emplace_back(addInfo);
    EXPECT_EQ(0, AccessTokenDb::GetInstance()->DeleteAndInsertValues(delInfoVec, addInfoVec)); // add test data

    std::vector<DelInfo> delInfoVec2;
    std::vector<AddInfo> addInfoVec2;
    atManagerService_->HandleHapUndefinedInfo(tokenIdAplMap, delInfoVec2, addInfoVec2);
    EXPECT_EQ(0, AccessTokenDb::GetInstance()->DeleteAndInsertValues(delInfoVec2, addInfoVec2));

    GenericValues conditionValue;
    conditionValue.Put(TokenFiledConst::FIELD_TOKEN_ID, static_cast<int32_t>(tokenId));
    std::vector<GenericValues> results;
    EXPECT_EQ(0, AccessTokenDb::GetInstance()->Find(type, conditionValue, results));
    EXPECT_EQ(false, results.empty()); // undefine table is not empty

    std::vector<GenericValues> results2;
    EXPECT_EQ(0, AccessTokenDb::GetInstance()->Find(
        AtmDataType::ACCESSTOKEN_PERMISSION_STATE, conditionValue, results2));
    for (const auto& value : results2) {
        EXPECT_NE(value.GetString(TokenFiledConst::FIELD_PERMISSION_NAME), g_state2.permissionName);
    }

    std::vector<GenericValues> results3;
    ASSERT_EQ(0, AccessTokenDb::GetInstance()->Find(
        AtmDataType::ACCESSTOKEN_PERMISSION_EXTEND_VALUE, conditionValue, results3));
    EXPECT_EQ(true, results3.empty()); // extend table is empty

    DelTestDataAndRestoreOri(tokenId, oriData);
}

void SetValues003(AccessTokenID tokenId, std::vector<GenericValues>& values)
{
    GenericValues value1; // user grant
    value1.Put(TokenFiledConst::FIELD_TOKEN_ID, static_cast<int32_t>(tokenId));
    value1.Put(TokenFiledConst::FIELD_PERMISSION_NAME, g_state4.permissionName);
    value1.Put(TokenFiledConst::FIELD_ACL, 0);
    GenericValues value2; // system grant
    value2.Put(TokenFiledConst::FIELD_TOKEN_ID, static_cast<int32_t>(tokenId));
    value2.Put(TokenFiledConst::FIELD_PERMISSION_NAME, g_state5.permissionName);
    value2.Put(TokenFiledConst::FIELD_ACL, 0);
    values.emplace_back(value1);
    values.emplace_back(value2);
}

/**
 * @tc.name: OTATest003
 * @tc.desc: test after ota valid user grant and system grant permissions move from undefine to permission state
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(AccessTokenManagerServiceTest, OTATest003, TestSize.Level0)
{
    AtmDataType type = AtmDataType::ACCESSTOKEN_HAP_UNDEFINE_INFO;
    std::vector<GenericValues> oriData;
    BackupAndDelOriData(oriData);

    HapInfoParcel infoParCel;
    infoParCel.hapInfoParameter = g_info;
    HapPolicyParcel policyParcel;
    policyParcel.hapPolicy = g_policy;
    policyParcel.hapPolicy.permStateList = {g_state1}; // KERNEL_ATM_SELF_USE
    AccessTokenID tokenId;
    std::map<int32_t, TokenIdInfo> tokenIdAplMap;
    CreateHapToken(infoParCel, policyParcel, tokenId, tokenIdAplMap);

    std::vector<GenericValues> values;
    SetValues003(tokenId, values);
    AddInfo addInfo;
    addInfo.addType = type;
    addInfo.addValues = values;

    std::vector<DelInfo> delInfoVec;
    std::vector<AddInfo> addInfoVec;
    addInfoVec.emplace_back(addInfo);
    EXPECT_EQ(0, AccessTokenDb::GetInstance()->DeleteAndInsertValues(delInfoVec, addInfoVec)); // add test data

    std::vector<DelInfo> delInfoVec2;
    std::vector<AddInfo> addInfoVec2;
    atManagerService_->HandleHapUndefinedInfo(tokenIdAplMap, delInfoVec2, addInfoVec2);
    EXPECT_EQ(0, AccessTokenDb::GetInstance()->DeleteAndInsertValues(delInfoVec2, addInfoVec2));

    GenericValues conditionValue;
    conditionValue.Put(TokenFiledConst::FIELD_TOKEN_ID, static_cast<int32_t>(tokenId));
    std::vector<GenericValues> results;
    EXPECT_EQ(0, AccessTokenDb::GetInstance()->Find(type, conditionValue, results));
    EXPECT_EQ(true, results.empty()); // undefine table is empty

    EXPECT_EQ(0, AccessTokenDb::GetInstance()->Find(AtmDataType::ACCESSTOKEN_PERMISSION_STATE, conditionValue,
        results));

    for (const auto& value : results) {
        int32_t state = value.GetInt(TokenFiledConst::FIELD_GRANT_STATE);
        int32_t flag = value.GetInt(TokenFiledConst::FIELD_GRANT_FLAG);
        if (value.GetString(TokenFiledConst::FIELD_PERMISSION_NAME) == g_state4.permissionName) { // user grant
            EXPECT_EQ(state, static_cast<int32_t>(PermissionState::PERMISSION_DENIED)); // state: 0 -> -1
            EXPECT_EQ(flag, static_cast<int32_t>(PermissionFlag::PERMISSION_DEFAULT_FLAG)); // flag: 4 -> 0
        } else if (value.GetString(TokenFiledConst::FIELD_PERMISSION_NAME) == g_state5.permissionName) { // system grant
            EXPECT_EQ(state, static_cast<int32_t>(PermissionState::PERMISSION_GRANTED)); // state: -1 -> 0
            EXPECT_EQ(flag, static_cast<int32_t>(PermissionFlag::PERMISSION_SYSTEM_FIXED)); // flag: 0 -> 4
        }
    }

    DelTestDataAndRestoreOri(tokenId, oriData);
}

/**
 * @tc.name: OTATest004
 * @tc.desc: test after ota valid system core permission without acl remain in undefine table
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(AccessTokenManagerServiceTest, OTATest004, TestSize.Level0)
{
    AtmDataType type = AtmDataType::ACCESSTOKEN_HAP_UNDEFINE_INFO;
    std::vector<GenericValues> oriData;
    BackupAndDelOriData(oriData);

    HapInfoParcel infoParCel;
    infoParCel.hapInfoParameter = g_info;
    HapPolicyParcel policyParcel;
    policyParcel.hapPolicy = g_policy;
    policyParcel.hapPolicy.permStateList = {g_state1}; // KERNEL_ATM_SELF_USE
    AccessTokenID tokenId;
    std::map<int32_t, TokenIdInfo> tokenIdAplMap;
    CreateHapToken(infoParCel, policyParcel, tokenId, tokenIdAplMap);

    GenericValues value; // system grant
    value.Put(TokenFiledConst::FIELD_TOKEN_ID, static_cast<int32_t>(tokenId));
    value.Put(TokenFiledConst::FIELD_PERMISSION_NAME, g_state6.permissionName);
    value.Put(TokenFiledConst::FIELD_ACL, 0); // system core permission without acl
    AddInfo addInfo;
    addInfo.addType = type;
    addInfo.addValues.emplace_back(value);

    std::vector<DelInfo> delInfoVec;
    std::vector<AddInfo> addInfoVec;
    addInfoVec.emplace_back(addInfo);
    EXPECT_EQ(0, AccessTokenDb::GetInstance()->DeleteAndInsertValues(delInfoVec, addInfoVec)); // add test data

    std::vector<DelInfo> delInfoVec2;
    std::vector<AddInfo> addInfoVec2;
    atManagerService_->HandleHapUndefinedInfo(tokenIdAplMap, delInfoVec2, addInfoVec2);
    EXPECT_EQ(0, AccessTokenDb::GetInstance()->DeleteAndInsertValues(delInfoVec2, addInfoVec2));

    GenericValues conditionValue;
    conditionValue.Put(TokenFiledConst::FIELD_TOKEN_ID, static_cast<int32_t>(tokenId));
    std::vector<GenericValues> results;
    EXPECT_EQ(0, AccessTokenDb::GetInstance()->Find(type, conditionValue, results));
    EXPECT_EQ(false, results.empty()); // undefine table not empty

    std::vector<GenericValues> results2;
    EXPECT_EQ(0, AccessTokenDb::GetInstance()->Find(
        AtmDataType::ACCESSTOKEN_PERMISSION_STATE, conditionValue, results2));
    for (const auto& value : results2) {
        EXPECT_NE(value.GetString(TokenFiledConst::FIELD_PERMISSION_NAME), g_state6.permissionName);
    }

    DelTestDataAndRestoreOri(tokenId, oriData);
}

/**
 * @tc.name: OTATest005
 * @tc.desc: test after ota valid system core permission with acl move from undefine to permission state
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(AccessTokenManagerServiceTest, OTATest005, TestSize.Level0)
{
    AtmDataType type = AtmDataType::ACCESSTOKEN_HAP_UNDEFINE_INFO;
    std::vector<GenericValues> oriData;
    BackupAndDelOriData(oriData);

    HapInfoParcel infoParCel;
    infoParCel.hapInfoParameter = g_info;
    HapPolicyParcel policyParcel;
    policyParcel.hapPolicy = g_policy;
    policyParcel.hapPolicy.permStateList = {g_state1}; // KERNEL_ATM_SELF_USE
    policyParcel.hapPolicy.aclRequestedList = { g_state6.permissionName };
    AccessTokenID tokenId;
    std::map<int32_t, TokenIdInfo> tokenIdAplMap;
    CreateHapToken(infoParCel, policyParcel, tokenId, tokenIdAplMap);

    GenericValues value; // system grant
    value.Put(TokenFiledConst::FIELD_TOKEN_ID, static_cast<int32_t>(tokenId));
    value.Put(TokenFiledConst::FIELD_PERMISSION_NAME, g_state6.permissionName);
    value.Put(TokenFiledConst::FIELD_ACL, 1); // system core permission with acl
    AddInfo addInfo;
    addInfo.addType = type;
    addInfo.addValues.emplace_back(value);

    std::vector<DelInfo> delInfoVec;
    std::vector<AddInfo> addInfoVec;
    addInfoVec.emplace_back(addInfo);
    EXPECT_EQ(0, AccessTokenDb::GetInstance()->DeleteAndInsertValues(delInfoVec, addInfoVec)); // add test data

    std::vector<DelInfo> delInfoVec2;
    std::vector<AddInfo> addInfoVec2;
    atManagerService_->HandleHapUndefinedInfo(tokenIdAplMap, delInfoVec2, addInfoVec2);
    EXPECT_EQ(0, AccessTokenDb::GetInstance()->DeleteAndInsertValues(delInfoVec2, addInfoVec2));

    GenericValues conditionValue;
    conditionValue.Put(TokenFiledConst::FIELD_TOKEN_ID, static_cast<int32_t>(tokenId));
    std::vector<GenericValues> results;
    EXPECT_EQ(0, AccessTokenDb::GetInstance()->Find(type, conditionValue, results));
    EXPECT_EQ(true, results.empty()); // undefine table is empty

    EXPECT_EQ(0, AccessTokenDb::GetInstance()->Find(AtmDataType::ACCESSTOKEN_PERMISSION_STATE, conditionValue,
        results));
    for (const auto& value : results) {
        std::string permissionName = value.GetString(TokenFiledConst::FIELD_PERMISSION_NAME);
        int32_t state = value.GetInt(TokenFiledConst::FIELD_GRANT_STATE);
        int32_t flag = value.GetInt(TokenFiledConst::FIELD_GRANT_FLAG);
        if (permissionName == g_state6.permissionName) {
            EXPECT_EQ(state, static_cast<int32_t>(PermissionState::PERMISSION_GRANTED)); // state: -1 -> 0
            EXPECT_EQ(flag, static_cast<int32_t>(PermissionFlag::PERMISSION_SYSTEM_FIXED)); // flag: 0 -> 4
        }
    }

    DelTestDataAndRestoreOri(tokenId, oriData);
}

void SetValues006(AccessTokenID tokenId, std::vector<GenericValues>& values)
{
    GenericValues value; // system grant
    value.Put(TokenFiledConst::FIELD_TOKEN_ID, static_cast<int32_t>(tokenId));
    value.Put(TokenFiledConst::FIELD_PERMISSION_NAME, g_state6.permissionName);
    value.Put(TokenFiledConst::FIELD_ACL, 1); // system core permission with acl
    value.Put(TokenFiledConst::FIELD_VALUE, "test"); // system core permission with acl
    values.emplace_back(value);
}

/**
 * @tc.name: OTATest006
 * @tc.desc: test after ota valid permission which hasValue is false
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(AccessTokenManagerServiceTest, OTATest006, TestSize.Level0)
{
    AtmDataType type = AtmDataType::ACCESSTOKEN_HAP_UNDEFINE_INFO;
    std::vector<GenericValues> oriData;
    BackupAndDelOriData(oriData);

    HapInfoParcel infoParCel;
    infoParCel.hapInfoParameter = g_info;
    HapPolicyParcel policyParcel;
    policyParcel.hapPolicy = g_policy;
    policyParcel.hapPolicy.permStateList = {g_state4};
    policyParcel.hapPolicy.aclRequestedList = { g_state6.permissionName }; // POWER_MANAGER, hasValue is false
    policyParcel.hapPolicy.aclExtendedMap = { std::make_pair(g_state6.permissionName, "test") };
    AccessTokenID tokenId;
    std::map<int32_t, TokenIdInfo> tokenIdAplMap;
    CreateHapToken(infoParCel, policyParcel, tokenId, tokenIdAplMap);

    std::vector<GenericValues> values;
    SetValues006(tokenId, values);
    AddInfo addInfo;
    addInfo.addType = type;
    addInfo.addValues = values;

    std::vector<DelInfo> delInfoVec;
    std::vector<AddInfo> addInfoVec;
    addInfoVec.emplace_back(addInfo);
    EXPECT_EQ(0, AccessTokenDb::GetInstance()->DeleteAndInsertValues(delInfoVec, addInfoVec)); // add test data

    std::vector<DelInfo> delInfoVec2;
    std::vector<AddInfo> addInfoVec2;
    atManagerService_->HandleHapUndefinedInfo(tokenIdAplMap, delInfoVec2, addInfoVec2);
    EXPECT_EQ(0, AccessTokenDb::GetInstance()->DeleteAndInsertValues(delInfoVec2, addInfoVec2));

    GenericValues conditionValue;
    conditionValue.Put(TokenFiledConst::FIELD_TOKEN_ID, static_cast<int32_t>(tokenId));
    std::vector<GenericValues> results;
    EXPECT_EQ(0, AccessTokenDb::GetInstance()->Find(type, conditionValue, results));
    EXPECT_EQ(true, results.empty()); // undefine table is empty

    EXPECT_EQ(0, AccessTokenDb::GetInstance()->Find(AtmDataType::ACCESSTOKEN_PERMISSION_STATE, conditionValue,
        results));
    for (const auto& value : results) {
        std::string permissionName = value.GetString(TokenFiledConst::FIELD_PERMISSION_NAME);
        int32_t state = value.GetInt(TokenFiledConst::FIELD_GRANT_STATE);
        int32_t flag = value.GetInt(TokenFiledConst::FIELD_GRANT_FLAG);
        if (permissionName == g_state6.permissionName) {
            EXPECT_EQ(state, static_cast<int32_t>(PermissionState::PERMISSION_GRANTED)); // state: -1 -> 0
            EXPECT_EQ(flag, static_cast<int32_t>(PermissionFlag::PERMISSION_SYSTEM_FIXED)); // flag: 0 -> 4
        }
    }

    std::vector<GenericValues> results2;
    ASSERT_EQ(0, AccessTokenDb::GetInstance()->Find(
        AtmDataType::ACCESSTOKEN_PERMISSION_EXTEND_VALUE, conditionValue, results2));
    EXPECT_EQ(true, results2.empty()); // undefine table is empty

    DelTestDataAndRestoreOri(tokenId, oriData);
}

void SetValues007(AccessTokenID tokenId, std::vector<GenericValues>& values)
{
    GenericValues value; // system grant
    value.Put(TokenFiledConst::FIELD_TOKEN_ID, static_cast<int32_t>(tokenId));
    value.Put(TokenFiledConst::FIELD_PERMISSION_NAME, g_state1.permissionName);
    value.Put(TokenFiledConst::FIELD_ACL, 0); // system core permission without acl
    value.Put(TokenFiledConst::FIELD_VALUE, "test"); // permission has value
    values.emplace_back(value);
}

/**
 * @tc.name: OTATest007
 * @tc.desc: test after ota valid permission which hasValue is true with value
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(AccessTokenManagerServiceTest, OTATest007, TestSize.Level0)
{
    AtmDataType type = AtmDataType::ACCESSTOKEN_HAP_UNDEFINE_INFO;
    std::vector<GenericValues> oriData;
    BackupAndDelOriData(oriData);

    HapInfoParcel infoParCel;
    infoParCel.hapInfoParameter = g_info;
    HapPolicyParcel policyParcel;
    policyParcel.hapPolicy = g_policy;
    policyParcel.hapPolicy.permStateList = {g_state4};
    policyParcel.hapPolicy.aclExtendedMap = {};
    AccessTokenID tokenId;
    std::map<int32_t, TokenIdInfo> tokenIdAplMap;
    CreateHapToken(infoParCel, policyParcel, tokenId, tokenIdAplMap); // KERNEL_ATM_SELF_USE, hasValue is true

    std::vector<GenericValues> values;
    SetValues007(tokenId, values);
    AddInfo addInfo;
    addInfo.addType = type;
    addInfo.addValues = values;

    std::vector<DelInfo> delInfoVec;
    std::vector<AddInfo> addInfoVec;
    addInfoVec.emplace_back(addInfo);
    EXPECT_EQ(0, AccessTokenDb::GetInstance()->DeleteAndInsertValues(delInfoVec, addInfoVec)); // add test data

    std::vector<DelInfo> delInfoVec2;
    std::vector<AddInfo> addInfoVec2;
    atManagerService_->HandleHapUndefinedInfo(tokenIdAplMap, delInfoVec2, addInfoVec2);
    EXPECT_EQ(0, AccessTokenDb::GetInstance()->DeleteAndInsertValues(delInfoVec2, addInfoVec2));

    GenericValues conditionValue;
    conditionValue.Put(TokenFiledConst::FIELD_TOKEN_ID, static_cast<int32_t>(tokenId));
    std::vector<GenericValues> results;
    EXPECT_EQ(0, AccessTokenDb::GetInstance()->Find(type, conditionValue, results));
    EXPECT_EQ(true, results.empty()); // undefine table is empty

    EXPECT_EQ(0, AccessTokenDb::GetInstance()->Find(AtmDataType::ACCESSTOKEN_PERMISSION_STATE, conditionValue,
        results));
    for (const auto& value : results) {
        std::string permissionName = value.GetString(TokenFiledConst::FIELD_PERMISSION_NAME);
        int32_t state = value.GetInt(TokenFiledConst::FIELD_GRANT_STATE);
        int32_t flag = value.GetInt(TokenFiledConst::FIELD_GRANT_FLAG);
        if (permissionName == g_state1.permissionName) {
            EXPECT_EQ(state, static_cast<int32_t>(PermissionState::PERMISSION_GRANTED)); // state: -1 -> 0
            EXPECT_EQ(flag, static_cast<int32_t>(PermissionFlag::PERMISSION_SYSTEM_FIXED)); // flag: 0 -> 4
        }
    }

    std::vector<GenericValues> results2;
    ASSERT_EQ(0, AccessTokenDb::GetInstance()->Find(
        AtmDataType::ACCESSTOKEN_PERMISSION_EXTEND_VALUE, conditionValue, results2));
    EXPECT_EQ(false, results2.empty()); // extend table is not empty
    EXPECT_EQ(g_state1.permissionName, results2[0].GetString(TokenFiledConst::FIELD_PERMISSION_NAME));

    DelTestDataAndRestoreOri(tokenId, oriData);
}

/**
 * @tc.name: OTATest008
 * @tc.desc: test after ota valid permission which hasValue is true without value
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(AccessTokenManagerServiceTest, OTATest008, TestSize.Level0)
{
    AtmDataType type = AtmDataType::ACCESSTOKEN_HAP_UNDEFINE_INFO;
    std::vector<GenericValues> oriData;
    BackupAndDelOriData(oriData);

    HapInfoParcel infoParCel;
    infoParCel.hapInfoParameter = g_info;
    HapPolicyParcel policyParcel;
    policyParcel.hapPolicy = g_policy;
    policyParcel.hapPolicy.permStateList = {g_state4};
    policyParcel.hapPolicy.aclExtendedMap = {};
    AccessTokenID tokenId;
    std::map<int32_t, TokenIdInfo> tokenIdAplMap;
    CreateHapToken(infoParCel, policyParcel, tokenId, tokenIdAplMap);

    GenericValues value; // system grant
    value.Put(TokenFiledConst::FIELD_TOKEN_ID, static_cast<int32_t>(tokenId));
    value.Put(TokenFiledConst::FIELD_PERMISSION_NAME, g_state1.permissionName);
    value.Put(TokenFiledConst::FIELD_ACL, 0); // system core permission without acl and without value
    AddInfo addInfo;
    addInfo.addType = type;
    addInfo.addValues.emplace_back(value);

    std::vector<DelInfo> delInfoVec;
    std::vector<AddInfo> addInfoVec;
    addInfoVec.emplace_back(addInfo);
    EXPECT_EQ(0, AccessTokenDb::GetInstance()->DeleteAndInsertValues(delInfoVec, addInfoVec)); // add test data

    std::vector<DelInfo> delInfoVec2;
    std::vector<AddInfo> addInfoVec2;
    atManagerService_->HandleHapUndefinedInfo(tokenIdAplMap, delInfoVec2, addInfoVec2);
    EXPECT_EQ(0, AccessTokenDb::GetInstance()->DeleteAndInsertValues(delInfoVec2, addInfoVec2));

    GenericValues conditionValue;
    conditionValue.Put(TokenFiledConst::FIELD_TOKEN_ID, static_cast<int32_t>(tokenId));
    std::vector<GenericValues> results;
    ASSERT_EQ(0, AccessTokenDb::GetInstance()->Find(
        AtmDataType::ACCESSTOKEN_HAP_UNDEFINE_INFO, conditionValue, results));
    EXPECT_EQ(false, results.empty()); // undefine table is not empty

    std::vector<GenericValues> results2;
    ASSERT_EQ(0, AccessTokenDb::GetInstance()->Find(
        AtmDataType::ACCESSTOKEN_PERMISSION_STATE, conditionValue, results2));
    for (const auto& value : results2) {
        EXPECT_NE(value.GetString(TokenFiledConst::FIELD_PERMISSION_NAME), g_state1.permissionName);
    }

    std::vector<GenericValues> results3;
    ASSERT_EQ(0, AccessTokenDb::GetInstance()->Find(
        AtmDataType::ACCESSTOKEN_PERMISSION_EXTEND_VALUE, conditionValue, results3));
    EXPECT_EQ(true, results3.empty()); // extend table is empty

    DelTestDataAndRestoreOri(tokenId, oriData);
}

/**
 * @tc.name: SetPermissionStatusWithPolicy001
 * @tc.desc: AccessTokenManagerService SetPermissionStatusWithPolicy test.
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(AccessTokenManagerServiceTest, SetPermissionStatusWithPolicy001, TestSize.Level0)
{
    std::vector<std::string> permList;
    uint32_t ret = atManagerService_->SetPermissionStatusWithPolicy(
        0, permList, 0, PERMISSION_FIXED_BY_ADMIN_POLICY);
    ASSERT_EQ(ERR_PARAM_INVALID, ret);

    permList.resize(1024 + 1);
    ret = atManagerService_->SetPermissionStatusWithPolicy(
        0, permList, 0, PERMISSION_FIXED_BY_ADMIN_POLICY);
    ASSERT_EQ(ERR_PARAM_INVALID, ret);
}

/**
 * @tc.name: OnRemoteRequestTest001
 * @tc.desc: OnRemoteRequest test.
 * @tc.type: FUNC
 * @tc.require:
 */
HWMTEST_F(AccessTokenManagerServiceTest, OnRemoteRequestTest001, TestSize.Level1, MULTIPLE_COUNT)
{
    uint32_t code = 0;
    MessageParcel data;
    MessageParcel reply;
    MessageOption option;
    std::shared_ptr<AccessTokenManagerService> atService = DelayedSingleton<AccessTokenManagerService>::GetInstance();
    ASSERT_NE(nullptr, atService);
    int32_t ret = atService->OnRemoteRequest(code, data, reply, option);
    EXPECT_NE(ERR_OK, ret);
    atService = nullptr;
}

/**
 * @tc.name: CallbackEnterAndExitTest001
 * @tc.desc: CallbackEnter & CallbackExit test.
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(AccessTokenManagerServiceTest, CallbackEnterAndExitTest001, TestSize.Level0)
{
    // stack empty
    int32_t ret = atManagerService_->CallbackExit(0, 0);
    EXPECT_EQ(ERR_OK, ret);
    // normal
    ret = atManagerService_->CallbackEnter(0);
    EXPECT_EQ(ERR_OK, ret);
    ret = atManagerService_->CallbackExit(0, 0);
    EXPECT_EQ(ERR_OK, ret);
    // ipc twice
    ret = atManagerService_->CallbackEnter(0);
    EXPECT_EQ(ERR_OK, ret);
    ret = atManagerService_->CallbackEnter(0);
    EXPECT_EQ(ERR_OK, ret);
    ret = atManagerService_->CallbackExit(0, 0);
    EXPECT_EQ(ERR_OK, ret);
    ret = atManagerService_->CallbackExit(0, 0);
    EXPECT_EQ(ERR_OK, ret);
}
} // namespace AccessToken
} // namespace Security
} // namespace OHOS
