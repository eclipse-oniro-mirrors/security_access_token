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

#include "accesstoken_manager_service_test.h"
#include "gtest/gtest.h"
#include <gtest/hwext/gtest-multithread.h>

#include "accesstoken_callbacks.h"
#include "accesstoken_info_manager.h"
#include "accesstoken_kit.h"
#include "access_token_db_operator.h"
#include "access_token_db.h"
#include "access_token_error.h"
#include "atm_tools_param_info_parcel.h"
#include "claw_auth_info_parcel.h"
#include "claw_ticket_manager.h"
#include "claw_token_challenge_parcel.h"
#include "cli_info_parcel.h"
#include "cli_permissions_result_parcel.h"
#include "hap_info_parcel.h"
#include "hap_policy_parcel.h"
#include "permission_dialog_result_parcel.h"
#include "parameters.h"
#include "permission_feature_manager.h"
#include "permission_map.h"
#include "permission_manager.h"
#include "perm_state_change_callback_customize.h"
#include "skill_info_parcel.h"
#include "skill_permissions_result_parcel.h"
#include "token_field_const.h"
#include "token_setproc.h"

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
static constexpr int32_t INDEX_ONE = 1;
static constexpr int32_t INDEX_TWO = 2;
static constexpr int32_t INDEX_THREE = 3;
static constexpr int32_t MAX_PERMISSION_SIZE = 1024;
static constexpr int32_t API_VERSION_9 = 9;
static constexpr int32_t RANDOM_TOKENID = 123;
static const std::string DEFAULT_AGENT_ID = "1001";
static const unsigned int DEBUG_APP_FLAG = 0x0008;
static uint64_t g_selfShellTokenId = 0;

std::vector<VariantValue> BuildPermissionStatePermissionQueryValues()
{
    return {VariantValue(std::string("ohos.permission.CAMERA")),
        VariantValue(std::string("ohos.permission.MICROPHONE"))};
}

void AssertPermissionStateQueryResults(const std::vector<GenericValues>& results, AccessTokenID tokenId1,
    AccessTokenID tokenId2)
{
    int32_t token1Count = 0;
    int32_t token2Count = 0;
    for (const auto& value : results) {
        const auto tokenId = static_cast<AccessTokenID>(value.GetInt(TokenFiledConst::FIELD_TOKEN_ID));
        const std::string permissionName = value.GetString(TokenFiledConst::FIELD_PERMISSION_NAME);
        EXPECT_TRUE(permissionName == "ohos.permission.CAMERA" || permissionName == "ohos.permission.MICROPHONE");
        EXPECT_TRUE(tokenId == tokenId1 || tokenId == tokenId2);
        if (tokenId == tokenId1) {
            ++token1Count;
        } else if (tokenId == tokenId2) {
            ++token2Count;
        }
    }
    EXPECT_EQ(2, token1Count); // 2: count of permissions queried for tokenId1
    EXPECT_EQ(2, token2Count); // 2: count of permissions queried for tokenId1
}

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
    .permissionName = "ohos.permission.ACTIVITY_MOTION",
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

static PermissionStatus g_state7 = { // permission without feature
    .permissionName = "ohos.permission.CAMERA",
    .grantStatus = PermissionState::PERMISSION_DENIED,
    .grantFlag = PermissionFlag::PERMISSION_DEFAULT_FLAG,
    .feature = ""
};

static PermissionStatus g_state8 = { // permission with feature
    .permissionName = "ohos.permission.MICROPHONE",
    .grantStatus = PermissionState::PERMISSION_DENIED,
    .grantFlag = PermissionFlag::PERMISSION_DEFAULT_FLAG,
    .feature = "service_test_feature"
};

static PermissionStatus g_state9 = { // permission with feature2
    .permissionName = "ohos.permission.POWER_MANAGER",
    .grantStatus = PermissionState::PERMISSION_GRANTED,
    .grantFlag = PermissionFlag::PERMISSION_SYSTEM_FIXED,
    .feature = "service_test_feature2"
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

uint64_t CreateClawServiceTestToken(
    const std::string& bundleName, bool isSystemApp, const std::vector<PermissionStatus>& permStateList,
    AccessTokenID& tokenId)
{
    HapInfoParams hapInfo = {
        .userID = USER_ID,
        .bundleName = bundleName,
        .instIndex = INST_INDEX,
        .dlpType = static_cast<int>(HapDlpType::DLP_COMMON),
        .apiVersion = API_VERSION_9,
        .isSystemApp = isSystemApp,
        .appIDDesc = bundleName,
    };
    HapPolicy hapPolicy = {
        .apl = APL_SYSTEM_BASIC,
        .domain = "test.domain",
        .permStateList = permStateList,
    };

    AccessTokenIDEx tokenIdEx = {0};
    std::vector<GenericValues> undefValues;
    int32_t ret = AccessTokenInfoManager::GetInstance().CreateHapTokenInfo(
        hapInfo, hapPolicy, tokenIdEx, undefValues);
    if (ret != RET_SUCCESS) {
        tokenId = INVALID_TOKENID;
        return 0;
    }
    tokenId = tokenIdEx.tokenIdExStruct.tokenID;
    return tokenIdEx.tokenIDEx;
}

PermissionStatus BuildGrantedPermissionStatus(const std::string& permissionName)
{
    return {
        .permissionName = permissionName,
        .grantStatus = PermissionState::PERMISSION_GRANTED,
        .grantFlag = PermissionFlag::PERMISSION_SYSTEM_FIXED
    };
}

std::vector<PermissionStatus> BuildClawQueryPermissionStates()
{
    return {BuildGrantedPermissionStatus("ohos.permission.QUERY_TOOL_PERMISSIONS")};
}

std::vector<PermissionStatus> BuildClawManagePermissionStates()
{
    return {BuildGrantedPermissionStatus("ohos.permission.MANAGE_TOOL_RUNTIME_PERMISSIONS")};
}

std::vector<PermissionStatus> BuildClawQueryAndManagePermissionStates()
{
    return {
        BuildGrantedPermissionStatus("ohos.permission.QUERY_TOOL_PERMISSIONS"),
        BuildGrantedPermissionStatus("ohos.permission.MANAGE_TOOL_RUNTIME_PERMISSIONS")
    };
}

std::vector<CliInfoParcel> BuildCliInfoParcels()
{
    CliInfoParcel cliInfoParcel;
    cliInfoParcel.cliInfo = {
        .cliName = "camera",
        .subCliName = "capture"
    };
    return {cliInfoParcel};
}

std::vector<CliInfoParcel> BuildMixedDialogCliInfoParcels()
{
    CliInfoParcel locationInfoParcel;
    locationInfoParcel.cliInfo = {
        .cliName = "location",
        .subCliName = "query"
    };
    CliInfoParcel cameraInfoParcel;
    cameraInfoParcel.cliInfo = {
        .cliName = "camera",
        .subCliName = "capture"
    };
    return {locationInfoParcel, cameraInfoParcel};
}

std::vector<CliInfoParcel> BuildUnknownCliInfoParcels()
{
    CliInfoParcel cliInfoParcel;
    cliInfoParcel.cliInfo = {
        .cliName = "unknown",
        .subCliName = "cmd"
    };
    return {cliInfoParcel};
}

std::vector<CliInfoParcel> BuildMissingMappingCliInfoParcels()
{
    CliInfoParcel cliInfoParcel;
    cliInfoParcel.cliInfo = {
        .cliName = "missingmap",
        .subCliName = "run"
    };
    return {cliInfoParcel};
}

std::vector<CliInfoParcel> BuildEmptyPermissionCliInfoParcels()
{
    CliInfoParcel cliInfoParcel;
    cliInfoParcel.cliInfo = {
        .cliName = "empty",
        .subCliName = "run"
    };
    return {cliInfoParcel};
}

std::vector<SkillInfoParcel> BuildSkillInfoParcels()
{
    SkillInfoParcel skillInfoParcel;
    skillInfoParcel.skillInfo = {
        .skillName = "cameraSkill",
        .bundleName = "com.ohos.claw.demo",
        .moduleName = "entry"
    };
    return {skillInfoParcel};
}

std::vector<SkillInfoParcel> BuildMixedDialogSkillInfoParcels()
{
    SkillInfoParcel cameraSkillInfoParcel;
    cameraSkillInfoParcel.skillInfo = {
        .skillName = "cameraSkill",
        .bundleName = "com.ohos.claw.demo",
        .moduleName = "entry"
    };
    SkillInfoParcel locationSkillInfoParcel;
    locationSkillInfoParcel.skillInfo = {
        .skillName = "locationSkill",
        .bundleName = "com.ohos.claw.demo",
        .moduleName = "entry"
    };
    return {cameraSkillInfoParcel, locationSkillInfoParcel};
}
}

void AccessTokenManagerServiceTest::SetUpTestCase()
{
    g_selfShellTokenId = GetSelfTokenID();
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
    DelayedSingleton<AccessTokenManagerService>::DestroyInstance();
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
 * @tc.name: PermissionStateQueryTest001
 * @tc.desc: test query permission_state_table by token_id in (...) and permission_name in (...)
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(AccessTokenManagerServiceTest, PermissionStateQueryTest001, TestSize.Level0)
{
    HapInfoParcel infoParcel1;
    infoParcel1.hapInfoParameter = g_info;
    infoParcel1.hapInfoParameter.bundleName = "accesstoken_manager_service_test_query_1";
    infoParcel1.hapInfoParameter.instIndex = 10;

    HapInfoParcel infoParcel2;
    infoParcel2.hapInfoParameter = g_info;
    infoParcel2.hapInfoParameter.bundleName = "accesstoken_manager_service_test_query_2";
    infoParcel2.hapInfoParameter.instIndex = 11;

    PermissionStatus cameraState = {
        .permissionName = "ohos.permission.CAMERA",
        .grantStatus = PermissionState::PERMISSION_DENIED,
        .grantFlag = PermissionFlag::PERMISSION_DEFAULT_FLAG
    };
    PermissionStatus microphoneState = {
        .permissionName = "ohos.permission.MICROPHONE",
        .grantStatus = PermissionState::PERMISSION_DENIED,
        .grantFlag = PermissionFlag::PERMISSION_DEFAULT_FLAG
    };
    PermissionStatus motionState = {
        .permissionName = "ohos.permission.ACTIVITY_MOTION",
        .grantStatus = PermissionState::PERMISSION_DENIED,
        .grantFlag = PermissionFlag::PERMISSION_DEFAULT_FLAG
    };

    HapPolicyParcel policyParcel;
    policyParcel.hapPolicy.apl = APL_NORMAL;
    policyParcel.hapPolicy.domain = "test.domain.query";
    policyParcel.hapPolicy.permStateList = {cameraState, microphoneState, motionState};

    AccessTokenID tokenId1 = INVALID_TOKENID;
    AccessTokenID tokenId2 = INVALID_TOKENID;
    std::map<int32_t, TokenIdInfo> tokenIdAplMap;
    CreateHapToken(infoParcel1, policyParcel, tokenId1, tokenIdAplMap);
    CreateHapToken(infoParcel2, policyParcel, tokenId2, tokenIdAplMap, true);

    std::vector<GenericValues> results;
    ASSERT_EQ(RET_SUCCESS, AccessTokenDbOperator::Find(
        AtmDataType::ACCESSTOKEN_PERMISSION_STATE, TokenFiledConst::FIELD_PERMISSION_NAME,
        BuildPermissionStatePermissionQueryValues(), results));
    results.erase(std::remove_if(results.begin(), results.end(),
        [tokenId1, tokenId2](const GenericValues& value) {
            const auto tokenId = static_cast<AccessTokenID>(value.GetInt(TokenFiledConst::FIELD_TOKEN_ID));
            return tokenId != tokenId1 && tokenId != tokenId2;
        }), results.end());
    ASSERT_EQ(4, results.size()); // 4: size
    AssertPermissionStateQueryResults(results, tokenId1, tokenId2);

    ASSERT_EQ(RET_SUCCESS, atManagerService_->DeleteToken(tokenId1, false));
    ASSERT_EQ(RET_SUCCESS, atManagerService_->DeleteToken(tokenId2, false));
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

    ASSERT_EQ(0, atManagerService_->DeleteToken(tokenId, false)); // delete token

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

    ASSERT_EQ(0, atManagerService_->DeleteToken(tokenId, false));
    ASSERT_EQ(0, atManagerService_->DeleteToken(tokenId2, false));
}

/**
 * @tc.name: InitHapTokenTest003
 * @tc.desc: test InitHapToken returns success and skips token creation when hap is skill
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(AccessTokenManagerServiceTest, InitHapTokenTest003, TestSize.Level0)
{
    atManagerService_->Initialize();

    HapInfoParams info = g_info;
    info.bundleName = "InitHapTokenTest003";
    info.appIDDesc = "InitHapTokenTest003";
    info.isSkillHap = true;
    HapInfoParcel infoParCel;
    infoParCel.hapInfoParameter = info;
    HapPolicyParcel policyParcel;
    policyParcel.hapPolicy = g_policy;

    uint64_t fullTokenId = RANDOM_TOKENID;
    HapInfoCheckResultIdl result;
    ASSERT_EQ(RET_SUCCESS, atManagerService_->InitHapToken(infoParCel, policyParcel, fullTokenId, result));
    ASSERT_EQ(static_cast<uint64_t>(INVALID_TOKENID), fullTokenId);

    uint64_t queryFullTokenId = RANDOM_TOKENID;
    ASSERT_EQ(RET_SUCCESS, atManagerService_->GetHapTokenID(info.userID, info.bundleName, info.instIndex,
        queryFullTokenId));
    AccessTokenIDEx tokenIdEx;
    tokenIdEx.tokenIDEx = queryFullTokenId;
    ASSERT_EQ(INVALID_TOKENID, tokenIdEx.tokenIdExStruct.tokenID);
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

    ASSERT_EQ(0, atManagerService_->DeleteToken(tokenId, false));
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

    ASSERT_EQ(0, atManagerService_->DeleteToken(tokenId, false));
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

    ASSERT_EQ(0, atManagerService_->DeleteToken(tokenId, false));
}

/**
 * @tc.name: UpdateHapTokenTest004
 * @tc.desc: test UpdateHapToken returns success and skips token update when hap is skill
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(AccessTokenManagerServiceTest, UpdateHapTokenTest004, TestSize.Level0)
{
    uint64_t fullTokenId = RANDOM_TOKENID;
    UpdateHapInfoParamsIdl infoIdl;
    infoIdl.appIDDesc = g_info.appIDDesc;
    infoIdl.apiVersion = g_info.apiVersion;
    infoIdl.isSystemApp = g_info.isSystemApp;
    infoIdl.appDistributionType = g_info.appDistributionType;
    infoIdl.isAtomicService = g_info.isAtomicService;
    infoIdl.isSkillHap = true;
    HapPolicyParcel policyParcel;
    policyParcel.hapPolicy = g_policy;
    HapInfoCheckResultIdl resultInfoIdl;

    ASSERT_EQ(RET_SUCCESS, atManagerService_->UpdateHapToken(fullTokenId, infoIdl, policyParcel, resultInfoIdl));
    ASSERT_EQ(static_cast<uint64_t>(INVALID_TOKENID), fullTokenId);
    ASSERT_EQ(ERR_OK, resultInfoIdl.realResult);
}

/**
 * @tc.name: UpdateHapTokenTest005
 * @tc.desc: test UpdateHapToken returns permission check failure when skill hap permission config is invalid
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(AccessTokenManagerServiceTest, UpdateHapTokenTest005, TestSize.Level0)
{
    uint64_t fullTokenId = RANDOM_TOKENID;
    UpdateHapInfoParamsIdl infoIdl;
    infoIdl.appIDDesc = g_info.appIDDesc;
    infoIdl.apiVersion = g_info.apiVersion;
    infoIdl.isSystemApp = false;
    infoIdl.appDistributionType = g_info.appDistributionType;
    infoIdl.isAtomicService = g_info.isAtomicService;
    infoIdl.isSkillHap = true;
    HapPolicyParcel policyParcel;
    policyParcel.hapPolicy = g_policy;
    policyParcel.hapPolicy.apl = APL_NORMAL;
    policyParcel.hapPolicy.permStateList = {g_state6};
    policyParcel.hapPolicy.aclRequestedList = {};
    policyParcel.hapPolicy.aclExtendedMap = {};
    HapInfoCheckResultIdl resultInfoIdl;

    ASSERT_EQ(RET_SUCCESS, atManagerService_->UpdateHapToken(fullTokenId, infoIdl, policyParcel, resultInfoIdl));
    ASSERT_NE(ERR_OK, resultInfoIdl.realResult);
    ASSERT_EQ(PermissionRulesEnumIdl::PERMISSION_ACL_RULE, resultInfoIdl.rule);
    ASSERT_EQ(g_state6.permissionName, resultInfoIdl.permissionName);
}

void AccessTokenManagerServiceTest::InstallHapWithProvisionType(
    AccessTokenIDEx& tokenIdEx, const std::string& appProvisionType, bool isDebugGrant)
{
    HapInfoParams info = {
        .userID = USER_ID,
        .bundleName = "accesstoken_manager_service_test",
        .instIndex = INST_INDEX,
        .dlpType = static_cast<int>(HapDlpType::DLP_COMMON),
        .apiVersion = API_VERSION_9,
        .isSystemApp = false,
        .appIDDesc = "accesstoken_manager_service_test",
        .appProvisionType = appProvisionType
    };
    PermissionStatus permStat = {
        .permissionName = "ohos.permission.CAMERA",
        .grantStatus = PermissionState::PERMISSION_DENIED,
        .grantFlag = PermissionFlag::PERMISSION_DEFAULT_FLAG
    };
    HapPolicy policy = {
        .apl = APL_NORMAL,
        .domain = "domain",
        .permStateList = {permStat},
        .isDebugGrant = isDebugGrant
    };

    HapInfoParcel infoParCel;
    infoParCel.hapInfoParameter = info;
    HapPolicyParcel policyParcel;
    policyParcel.hapPolicy = policy;

    uint64_t fullTokenId;
    HapInfoCheckResultIdl result;
    int32_t ret = atManagerService_->InitHapToken(infoParCel, policyParcel, fullTokenId, result);
    ASSERT_EQ(RET_SUCCESS, ret);

    tokenIdEx.tokenIDEx = fullTokenId;
}

void AccessTokenManagerServiceTest::UpdateHapWithProvisionType(AccessTokenIDEx& tokenIdEx,
    const std::string& appProvisionType, bool isDebugGrant)
{
    PermissionStatus permStatCamera = {
        .permissionName = "ohos.permission.CAMERA",
        .grantStatus = PermissionState::PERMISSION_DENIED,
        .grantFlag = PermissionFlag::PERMISSION_DEFAULT_FLAG
    };
    PermissionStatus permStatActive = {
        .permissionName = "ohos.permission.ACTIVITY_MOTION",
        .grantStatus = PermissionState::PERMISSION_DENIED,
        .grantFlag = PermissionFlag::PERMISSION_DEFAULT_FLAG
    };

    HapPolicyParcel policyParcel;
    policyParcel.hapPolicy.apl = APL_NORMAL;
    policyParcel.hapPolicy.domain = "domain";
    policyParcel.hapPolicy.permStateList = {permStatCamera, permStatActive};
    policyParcel.hapPolicy.isDebugGrant = isDebugGrant;

    HapInfoParams info = {
        .userID = USER_ID,
        .bundleName = "accesstoken_manager_service_test",
        .instIndex = INST_INDEX,
        .dlpType = static_cast<int>(HapDlpType::DLP_COMMON),
        .apiVersion = API_VERSION_9,
        .isSystemApp = false,
        .appIDDesc = "accesstoken_manager_service_test",
        .appProvisionType = appProvisionType
    };

    uint64_t fullTokenId = tokenIdEx.tokenIDEx;
    UpdateHapInfoParamsIdl infoIdl;
    infoIdl.appIDDesc = info.appIDDesc;
    infoIdl.apiVersion = info.apiVersion;
    infoIdl.isSystemApp = info.isSystemApp;
    infoIdl.appDistributionType = info.appDistributionType;
    infoIdl.isAtomicService = info.isAtomicService;
    infoIdl.dataRefresh = true;
    infoIdl.appProvisionType = appProvisionType;
    HapInfoCheckResultIdl resultInfoIdl;
    ASSERT_EQ(RET_SUCCESS, atManagerService_->UpdateHapToken(fullTokenId, infoIdl, policyParcel, resultInfoIdl));
    tokenIdEx.tokenIDEx = fullTokenId;
}

/**
 * @tc.name: UpdateHapTokenWithProvisionTypeTest001
 * @tc.desc: test update hap from release to debug with isDebugGrant true
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(AccessTokenManagerServiceTest, UpdateHapTokenWithProvisionTypeTest001, TestSize.Level0)
{
    AccessTokenIDEx tokenIdEx = {0};

    // Step 1: install release hap
    InstallHapWithProvisionType(tokenIdEx, "release", false);
    AccessTokenID tokenID = tokenIdEx.tokenIdExStruct.tokenID;
    ASSERT_EQ(PERMISSION_DENIED,
        AccessTokenInfoManager::GetInstance().VerifyAccessToken(tokenID, "ohos.permission.CAMERA"));
    ASSERT_EQ(0, tokenIdEx.tokenIdExStruct.tokenAttr & DEBUG_APP_FLAG);

    // Step 2: update to debug hap with isDebugGrant true
    UpdateHapWithProvisionType(tokenIdEx, "debug", true);

    ASSERT_EQ(PERMISSION_GRANTED,
        AccessTokenInfoManager::GetInstance().VerifyAccessToken(tokenID, "ohos.permission.CAMERA"));
    ASSERT_EQ(PERMISSION_GRANTED,
        AccessTokenInfoManager::GetInstance().VerifyAccessToken(tokenID, "ohos.permission.ACTIVITY_MOTION"));
    ASSERT_EQ(DEBUG_APP_FLAG, tokenIdEx.tokenIdExStruct.tokenAttr & DEBUG_APP_FLAG);

    ASSERT_EQ(0, atManagerService_->DeleteToken(tokenID, false));
}

/**
 * @tc.name: UpdateHapTokenWithProvisionTypeTest002
 * @tc.desc: test update hap from release to debug with isDebugGrant false
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(AccessTokenManagerServiceTest, UpdateHapTokenWithProvisionTypeTest002, TestSize.Level0)
{
    AccessTokenIDEx tokenIdEx = {0};

    // Step 1: install release hap
    InstallHapWithProvisionType(tokenIdEx, "release", false);
    AccessTokenID tokenID = tokenIdEx.tokenIdExStruct.tokenID;
    ASSERT_EQ(PERMISSION_DENIED,
        AccessTokenInfoManager::GetInstance().VerifyAccessToken(tokenID, "ohos.permission.CAMERA"));
    ASSERT_EQ(0, tokenIdEx.tokenIdExStruct.tokenAttr & DEBUG_APP_FLAG);

    // Step 2: update to debug hap with isDebugGrant false
    UpdateHapWithProvisionType(tokenIdEx, "debug", false);

    ASSERT_EQ(PERMISSION_DENIED,
        AccessTokenInfoManager::GetInstance().VerifyAccessToken(tokenID, "ohos.permission.CAMERA"));
    ASSERT_EQ(PERMISSION_DENIED,
        AccessTokenInfoManager::GetInstance().VerifyAccessToken(tokenID, "ohos.permission.ACTIVITY_MOTION"));
    ASSERT_EQ(DEBUG_APP_FLAG, tokenIdEx.tokenIdExStruct.tokenAttr & DEBUG_APP_FLAG);

    ASSERT_EQ(0, atManagerService_->DeleteToken(tokenID, false));
}

/**
 * @tc.name: UpdateHapTokenWithProvisionTypeTest003
 * @tc.desc: test update hap from debug to debug with isDebugGrant from false to true
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(AccessTokenManagerServiceTest, UpdateHapTokenWithProvisionTypeTest003, TestSize.Level0)
{
    AccessTokenIDEx tokenIdEx = {0};

    // Step 1: install debug hap with isDebugGrant false
    InstallHapWithProvisionType(tokenIdEx, "debug", false);
    AccessTokenID tokenID = tokenIdEx.tokenIdExStruct.tokenID;
    ASSERT_EQ(PERMISSION_DENIED,
        AccessTokenInfoManager::GetInstance().VerifyAccessToken(tokenID, "ohos.permission.CAMERA"));
    ASSERT_EQ(DEBUG_APP_FLAG, tokenIdEx.tokenIdExStruct.tokenAttr & DEBUG_APP_FLAG);

    // Step 2: update to debug hap with isDebugGrant true
    UpdateHapWithProvisionType(tokenIdEx, "debug", true);

    ASSERT_EQ(PERMISSION_GRANTED,
        AccessTokenInfoManager::GetInstance().VerifyAccessToken(tokenID, "ohos.permission.CAMERA"));
    ASSERT_EQ(PERMISSION_GRANTED,
        AccessTokenInfoManager::GetInstance().VerifyAccessToken(tokenID, "ohos.permission.ACTIVITY_MOTION"));
    ASSERT_EQ(DEBUG_APP_FLAG, tokenIdEx.tokenIdExStruct.tokenAttr & DEBUG_APP_FLAG);

    ASSERT_EQ(0, atManagerService_->DeleteToken(tokenID, false));
}

/**
 * @tc.name: UpdateHapTokenWithProvisionTypeTest004
 * @tc.desc: test update hap from debug to debug with isDebugGrant from true to true
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(AccessTokenManagerServiceTest, UpdateHapTokenWithProvisionTypeTest004, TestSize.Level0)
{
    AccessTokenIDEx tokenIdEx = {0};

    // Step 1: install debug hap with isDebugGrant true
    InstallHapWithProvisionType(tokenIdEx, "debug", true);
    AccessTokenID tokenID = tokenIdEx.tokenIdExStruct.tokenID;
    ASSERT_EQ(PERMISSION_GRANTED,
        AccessTokenInfoManager::GetInstance().VerifyAccessToken(tokenID, "ohos.permission.CAMERA"));
    ASSERT_EQ(DEBUG_APP_FLAG, tokenIdEx.tokenIdExStruct.tokenAttr & DEBUG_APP_FLAG);

    ASSERT_EQ(0, atManagerService_->RevokePermission(
        tokenID, "ohos.permission.CAMERA", PERMISSION_USER_FIXED, USER_GRANTED_PERM));
    ASSERT_EQ(PERMISSION_DENIED,
        AccessTokenInfoManager::GetInstance().VerifyAccessToken(tokenID, "ohos.permission.CAMERA"));

    // Step 2: update to debug hap with isDebugGrant true
    UpdateHapWithProvisionType(tokenIdEx, "debug", true);

    ASSERT_EQ(PERMISSION_GRANTED,
        AccessTokenInfoManager::GetInstance().VerifyAccessToken(tokenID, "ohos.permission.CAMERA"));
    ASSERT_EQ(PERMISSION_GRANTED,
        AccessTokenInfoManager::GetInstance().VerifyAccessToken(tokenID, "ohos.permission.ACTIVITY_MOTION"));
    ASSERT_EQ(DEBUG_APP_FLAG, tokenIdEx.tokenIdExStruct.tokenAttr & DEBUG_APP_FLAG);

    ASSERT_EQ(0, atManagerService_->DeleteToken(tokenID, false));
}

/**
 * @tc.name: UpdateHapTokenWithProvisionTypeTest005
 * @tc.desc: test update hap from debug to debug with isDebugGrant from true to false
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(AccessTokenManagerServiceTest, UpdateHapTokenWithProvisionTypeTest005, TestSize.Level0)
{
    AccessTokenIDEx tokenIdEx = {0};

    // Step 1: install release hap with isDebugGrant true
    InstallHapWithProvisionType(tokenIdEx, "debug", true);
    AccessTokenID tokenID = tokenIdEx.tokenIdExStruct.tokenID;
    ASSERT_EQ(PERMISSION_GRANTED,
        AccessTokenInfoManager::GetInstance().VerifyAccessToken(tokenID, "ohos.permission.CAMERA"));
    ASSERT_EQ(DEBUG_APP_FLAG, tokenIdEx.tokenIdExStruct.tokenAttr & DEBUG_APP_FLAG);

    // Step 2: update to debug hap with isDebugGrant false
    UpdateHapWithProvisionType(tokenIdEx, "debug", false);

    ASSERT_EQ(PERMISSION_GRANTED,
        AccessTokenInfoManager::GetInstance().VerifyAccessToken(tokenID, "ohos.permission.CAMERA"));
    ASSERT_EQ(PERMISSION_DENIED,
        AccessTokenInfoManager::GetInstance().VerifyAccessToken(tokenID, "ohos.permission.ACTIVITY_MOTION"));
    ASSERT_EQ(DEBUG_APP_FLAG, tokenIdEx.tokenIdExStruct.tokenAttr & DEBUG_APP_FLAG);

    ASSERT_EQ(0, atManagerService_->DeleteToken(tokenID, false));
}

/**
 * @tc.name: UpdateHapTokenWithProvisionTypeTest006
 * @tc.desc: test update hap from debug to debug with isDebugGrant from false to false
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(AccessTokenManagerServiceTest, UpdateHapTokenWithProvisionTypeTest006, TestSize.Level0)
{
    AccessTokenIDEx tokenIdEx = {0};

    // Step 1: install debug hap with isDebugGrant false
    InstallHapWithProvisionType(tokenIdEx, "debug", false);
    AccessTokenID tokenID = tokenIdEx.tokenIdExStruct.tokenID;
    ASSERT_EQ(PERMISSION_DENIED,
        AccessTokenInfoManager::GetInstance().VerifyAccessToken(tokenID, "ohos.permission.CAMERA"));
    ASSERT_EQ(DEBUG_APP_FLAG, tokenIdEx.tokenIdExStruct.tokenAttr & DEBUG_APP_FLAG);

    ASSERT_EQ(0, atManagerService_->GrantPermission(
        tokenID, "ohos.permission.CAMERA", PERMISSION_USER_FIXED, USER_GRANTED_PERM));
    ASSERT_EQ(PERMISSION_GRANTED,
        AccessTokenInfoManager::GetInstance().VerifyAccessToken(tokenID, "ohos.permission.CAMERA"));

    // Step 2: update to debug hap with isDebugGrant false
    UpdateHapWithProvisionType(tokenIdEx, "debug", false);

    ASSERT_EQ(PERMISSION_GRANTED,
        AccessTokenInfoManager::GetInstance().VerifyAccessToken(tokenID, "ohos.permission.CAMERA"));
    ASSERT_EQ(PERMISSION_DENIED,
        AccessTokenInfoManager::GetInstance().VerifyAccessToken(tokenID, "ohos.permission.ACTIVITY_MOTION"));
    ASSERT_EQ(DEBUG_APP_FLAG, tokenIdEx.tokenIdExStruct.tokenAttr & DEBUG_APP_FLAG);

    ASSERT_EQ(0, atManagerService_->DeleteToken(tokenID, false));
}

/**
 * @tc.name: UpdateHapTokenWithProvisionTypeTest007
 * @tc.desc: test update hap from debug with isDebugGrant true to release
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(AccessTokenManagerServiceTest, UpdateHapTokenWithProvisionTypeTest007, TestSize.Level0)
{
    AccessTokenIDEx tokenIdEx = {0};

    // Step 1: install debug hap with isDebugGrant true
    InstallHapWithProvisionType(tokenIdEx, "debug", true);
    AccessTokenID tokenID = tokenIdEx.tokenIdExStruct.tokenID;
    ASSERT_EQ(PERMISSION_GRANTED,
        AccessTokenInfoManager::GetInstance().VerifyAccessToken(tokenID, "ohos.permission.CAMERA"));
    ASSERT_EQ(DEBUG_APP_FLAG, tokenIdEx.tokenIdExStruct.tokenAttr & DEBUG_APP_FLAG);

    // Step 2: update to release hap
    UpdateHapWithProvisionType(tokenIdEx, "release", false);

    ASSERT_EQ(PERMISSION_DENIED,
        AccessTokenInfoManager::GetInstance().VerifyAccessToken(tokenID, "ohos.permission.CAMERA"));
    ASSERT_EQ(PERMISSION_DENIED,
        AccessTokenInfoManager::GetInstance().VerifyAccessToken(tokenID, "ohos.permission.ACTIVITY_MOTION"));
    ASSERT_EQ(0, tokenIdEx.tokenIdExStruct.tokenAttr & DEBUG_APP_FLAG);

    ASSERT_EQ(0, atManagerService_->DeleteToken(tokenID, false));
}

/**
 * @tc.name: UpdateHapTokenWithProvisionTypeTest008
 * @tc.desc: test update hap from debug with isDebugGrant false to release
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(AccessTokenManagerServiceTest, UpdateHapTokenWithProvisionTypeTest008, TestSize.Level0)
{
    AccessTokenIDEx tokenIdEx = {0};

    // Step 1: install debug hap with isDebugGrant false
    InstallHapWithProvisionType(tokenIdEx, "debug", false);
    AccessTokenID tokenID = tokenIdEx.tokenIdExStruct.tokenID;
    ASSERT_EQ(PERMISSION_DENIED,
        AccessTokenInfoManager::GetInstance().VerifyAccessToken(tokenID, "ohos.permission.CAMERA"));
    ASSERT_EQ(DEBUG_APP_FLAG, tokenIdEx.tokenIdExStruct.tokenAttr & DEBUG_APP_FLAG);

    // Step 2: update to release hap
    UpdateHapWithProvisionType(tokenIdEx, "release", false);

    ASSERT_EQ(PERMISSION_DENIED,
        AccessTokenInfoManager::GetInstance().VerifyAccessToken(tokenID, "ohos.permission.CAMERA"));
    ASSERT_EQ(PERMISSION_DENIED,
        AccessTokenInfoManager::GetInstance().VerifyAccessToken(tokenID, "ohos.permission.ACTIVITY_MOTION"));
    ASSERT_EQ(0, tokenIdEx.tokenIdExStruct.tokenAttr & DEBUG_APP_FLAG);

    ASSERT_EQ(0, atManagerService_->DeleteToken(tokenID, false));
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
    EXPECT_EQ(0, atManagerService_->DeleteToken(tokenId, false));

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
    AddInfo addInfo = { .addType = type, .addValues = values};

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
    if (!results2.empty()) {
        EXPECT_EQ(g_state1.permissionName, results2[0].GetString(TokenFiledConst::FIELD_PERMISSION_NAME));
    }

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
HWTEST_F(AccessTokenManagerServiceTest, OnRemoteRequestTest001, TestSize.Level1)
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

class CbCustomizeTest : public PermStateChangeCallbackCustomize {
public:
    explicit CbCustomizeTest(const PermStateChangeScope &scopeInfo)
        : PermStateChangeCallbackCustomize(scopeInfo)
    {
    }

    ~CbCustomizeTest()
    {}

    virtual void PermStateChangeCallback(PermStateChangeInfo& result)
    {
        ready_ = true;
    }

    bool ready_;
};

/**
 * @tc.name: RegisterSelfPermStateChangeCallback001
 * @tc.desc: Test RegisterSelfPermStateChangeCallback with different tokenID scope
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(AccessTokenManagerServiceTest, RegisterSelfPermStateChangeCallback001, TestSize.Level0)
{
    HapInfoParcel infoParCel;
    infoParCel.hapInfoParameter = g_info;
    HapPolicyParcel policyParcel;
    policyParcel.hapPolicy = g_policy;
    AccessTokenID tokenId;
    std::map<int32_t, TokenIdInfo> tokenIdAplMap;
    CreateHapToken(infoParCel, policyParcel, tokenId, tokenIdAplMap);

    SetSelfTokenID(tokenId);

    PermStateChangeScopeParcel scope;
    scope.scope.tokenIDs = {tokenId};
    scope.scope.permList = {"ohos.permission.CAMERA"};
    auto callbackPtr = std::make_shared<CbCustomizeTest>(scope.scope);
    auto callback = new (std::nothrow) PermissionStateChangeCallback(callbackPtr);

    int32_t ret = atManagerService_->RegisterSelfPermStateChangeCallback(scope, callback->AsObject());
    EXPECT_EQ(RET_SUCCESS, ret);

    scope.scope.tokenIDs = {tokenId + 1};
    ret = atManagerService_->RegisterSelfPermStateChangeCallback(scope, callback->AsObject());
    EXPECT_EQ(AccessTokenError::ERR_PARAM_INVALID, ret);

    scope.scope.tokenIDs = {};
    ret = atManagerService_->RegisterSelfPermStateChangeCallback(scope, callback->AsObject());
    EXPECT_EQ(AccessTokenError::ERR_PARAM_INVALID, ret);

    // Clean up
    atManagerService_->UnRegisterSelfPermStateChangeCallback(callback->AsObject());
    DelTestDataAndRestoreOri(tokenId, {});
    SetSelfTokenID(g_selfShellTokenId);
}

/**
 * @tc.name: QueryStatusByTokenIDServiceTest001
 * @tc.desc: Test QueryStatusByTokenID with tokenIDList size exceeding limit (1025), return ERR_PARAM_INVALID
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(AccessTokenManagerServiceTest, QueryStatusByTokenIDServiceTest001, TestSize.Level1)
{
    // Arrange: Create a valid HAP token
    atManagerService_->Initialize();
    HapInfoParcel infoParcel;
    infoParcel.hapInfoParameter = g_info;

    HapPolicyParcel policyParcel;
    policyParcel.hapPolicy = g_policy;

    AccessTokenID tokenId;
    std::map<int32_t, TokenIdInfo> tokenIdAplMap;
    CreateHapToken(infoParcel, policyParcel, tokenId, tokenIdAplMap, true);
    EXPECT_NE(INVALID_TOKENID, tokenId);

    // Act: Create tokenIDList with size exceeding MAX_PERMISSION_LIST_SIZE (1024)
    std::vector<AccessTokenID> tokenIDList;
    tokenIDList.emplace_back(tokenId);  // Add valid tokenID first
    // Fill remaining 1024 entries with dummy tokenIDs
    for (int32_t i = 0; i < 1024; ++i) { // 1024: size
        tokenIDList.emplace_back(1000000 + i);  // 1000000: Use large numbers unlikely to be valid tokenIDs
    }

    std::vector<PermissionStatusIdl> permissionInfoList;
    ErrCode ret = atManagerService_->QueryStatusByTokenID(tokenIDList, permissionInfoList);

    // Assert: Should return ERR_PARAM_INVALID due to size exceeding limit
    EXPECT_EQ(AccessTokenError::ERR_PARAM_INVALID, ret);
    EXPECT_TRUE(permissionInfoList.empty());

    // Cleanup: Always execute cleanup to ensure resources are released
    int32_t result = atManagerService_->DeleteToken(tokenId, false);
    EXPECT_EQ(RET_SUCCESS, result);
}

/**
 * @tc.name: QueryStatusByTokenIDServiceTest002
 * @tc.desc: Test QueryStatusByTokenID with empty tokenIDList, return ERR_PARAM_INVALID
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(AccessTokenManagerServiceTest, QueryStatusByTokenIDServiceTest002, TestSize.Level1)
{
    // Arrange: Create empty tokenIDList
    std::vector<AccessTokenID> tokenIDList;
    std::vector<PermissionStatusIdl> permissionInfoList;

    // Act: Query with empty tokenIDList
    atManagerService_->Initialize();
    ErrCode ret = atManagerService_->QueryStatusByTokenID(tokenIDList, permissionInfoList);

    // Assert: Should return ERR_PARAM_INVALID due to empty list
    ASSERT_EQ(AccessTokenError::ERR_PARAM_INVALID, ret);
    ASSERT_TRUE(permissionInfoList.empty());
}

/**
 * @tc.name: QueryStatusByTokenIDServiceTest003
 * @tc.desc: Test QueryStatusByTokenID with tokenID=0, return ERR_PARAM_INVALID
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(AccessTokenManagerServiceTest, QueryStatusByTokenIDServiceTest003, TestSize.Level1)
{
    // Arrange: Create tokenIDList with tokenID=0
    std::vector<AccessTokenID> tokenIDList = {0};
    std::vector<PermissionStatusIdl> permissionInfoList;

    // Act: Query with tokenID=0
    atManagerService_->Initialize();
    ErrCode ret = atManagerService_->QueryStatusByTokenID(tokenIDList, permissionInfoList);

    // Assert: Should return ERR_PARAM_INVALID due to tokenID=0
    ASSERT_EQ(AccessTokenError::ERR_PARAM_INVALID, ret);
    ASSERT_TRUE(permissionInfoList.empty());
}

/**
 * @tc.name: QueryStatusByPermissionOverSizeTest001
 * @tc.desc: Test oversize scenario with maxQueryResultSize for testing
 * @tc.require:
 * @tc.type: FUNC
 */
HWTEST_F(AccessTokenManagerServiceTest, QueryStatusByPermissionOverSizeTest001, TestSize.Level1)
{
    std::string permission = "ohos.permission.GET_SENSITIVE_PERMISSIONS";
    uint32_t opCdde;
    (void)TransferPermissionToOpcode(permission, opCdde);
    // Prepare: Create a HAP with permissions
    HapInfoParcel infoParcel;
    infoParcel.hapInfoParameter.userID = USER_ID;
    infoParcel.hapInfoParameter.bundleName = "com.example.oversize.test";
    infoParcel.hapInfoParameter.instIndex = INST_INDEX;
    infoParcel.hapInfoParameter.dlpType = static_cast<int>(HapDlpType::DLP_COMMON);
    infoParcel.hapInfoParameter.apiVersion = 9; // 9: api version
    infoParcel.hapInfoParameter.isSystemApp = false;
    infoParcel.hapInfoParameter.appIDDesc = "com.example.oversize.test";

    HapPolicyParcel policyParcel;
    policyParcel.hapPolicy.apl = APL_SYSTEM_BASIC;
    policyParcel.hapPolicy.domain = "test.domain";

    // Add INTERNET permission (opcode=1) to the HAP
    std::vector<PermissionStatus> permStates;
    PermissionStatus permState;
    permState.permissionName = permission;
    permState.grantFlag = static_cast<uint32_t>(PermissionFlag::PERMISSION_USER_FIXED);
    permState.grantStatus = static_cast<int32_t>(PermissionState::PERMISSION_GRANTED);
    permStates.emplace_back(permState);
    policyParcel.hapPolicy.permStateList = permStates;

    // Create a HAP token
    std::map<int32_t, TokenIdInfo> tokenIdAplMap;
    AccessTokenID tokenID;
    CreateHapToken(infoParcel, policyParcel, tokenID, tokenIdAplMap);

    size_t originalMaxSize = AccessTokenInfoManager::GetInstance().GetMaxQueryResultSize();
    AccessTokenInfoManager::GetInstance().SetMaxQueryResultSize(0); // 0: Set small max size for testing and query
    std::vector<uint32_t> permCodeList;
    ASSERT_TRUE(TransferPermissionToOpcode("ohos.permission.CAMERA", opCdde));
    permCodeList.emplace_back(opCdde);
    std::vector<PermissionStatusIdl> permissionInfoList;
    ErrCode errCode = atManagerService_->QueryStatusByPermission(permCodeList, permissionInfoList, true);

    // Assert: Should return ERR_OVERSIZE since result exceeds limit
    EXPECT_EQ(AccessTokenError::ERR_OVERSIZE, errCode);
    EXPECT_TRUE(permissionInfoList.empty());

    // Cleanup
    AccessTokenInfoManager::GetInstance().SetMaxQueryResultSize(originalMaxSize);
    EXPECT_EQ(RET_SUCCESS, atManagerService_->DeleteToken(tokenID, false));
}

/**
 * @tc.name: QueryStatusByPermissionServiceTest001
 * @tc.desc: Test QueryStatusByPermission with empty permissionList, return ERR_PARAM_INVALID
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(AccessTokenManagerServiceTest, QueryStatusByPermissionServiceTest001, TestSize.Level1)
{
    // Arrange: Create empty permissionList
    std::vector<uint32_t> permCodeList;
    std::vector<PermissionStatusIdl> permissionInfoList;

    // Act: Query with empty permissionList
    atManagerService_->Initialize();
    ErrCode ret = atManagerService_->QueryStatusByPermission(permCodeList, permissionInfoList, true);

    // Assert: Should return ERR_PARAM_INVALID due to empty list
    ASSERT_EQ(AccessTokenError::ERR_PARAM_INVALID, ret);
    ASSERT_TRUE(permissionInfoList.empty());
}

/**
 * @tc.name: QueryStatusByPermissionServiceTest002
 * @tc.desc: Test QueryStatusByPermission with permissionList size exceeding limit (1025), return ERR_PARAM_INVALID
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(AccessTokenManagerServiceTest, QueryStatusByPermissionServiceTest002, TestSize.Level1)
{
    // Prepare: Create a HAP with permissions
    atManagerService_->Initialize();
    HapInfoParcel infoParcel;
    infoParcel.hapInfoParameter = g_info;

    HapPolicyParcel policyParcel;
    policyParcel.hapPolicy = g_policy;

    AccessTokenID tokenId;
    std::map<int32_t, TokenIdInfo> tokenIdAplMap;
    CreateHapToken(infoParcel, policyParcel, tokenId, tokenIdAplMap, true);
    EXPECT_NE(INVALID_TOKENID, tokenId);

    // Act: Create permissionList with size exceeding MAX_PERMISSION_LIST_SIZE (1024)
    std::vector<uint32_t> permCodeList;
    uint32_t permCode = 0;
    ASSERT_TRUE(TransferPermissionToOpcode("ohos.permission.CAMERA", permCode));
    permCodeList.emplace_back(permCode);
    // Fill remaining 1024 entries with dummy permission names
    for (int32_t i = 0; i < 1024; ++i) { // 1024: size
        permCodeList.emplace_back(1000000 + i);
    }

    std::vector<PermissionStatusIdl> permissionInfoList;
    ErrCode ret = atManagerService_->QueryStatusByPermission(permCodeList, permissionInfoList, true);

    // Assert: Should return ERR_PARAM_INVALID due to size exceeding limit
    EXPECT_EQ(AccessTokenError::ERR_PARAM_INVALID, ret);
    EXPECT_TRUE(permissionInfoList.empty());

    // Cleanup: Always execute cleanup to ensure resources are released
    int32_t result = atManagerService_->DeleteToken(tokenId, false);
    EXPECT_EQ(RET_SUCCESS, result);
}

/**
 * @tc.name: QueryStatusByPermissionServiceTest003
 * @tc.desc: Test QueryStatusByPermission with valid permissionList, return RET_SUCCESS
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(AccessTokenManagerServiceTest, QueryStatusByPermissionServiceTest003, TestSize.Level1)
{
    // Prepare: Create a HAP with permissions
    atManagerService_->Initialize();
    HapInfoParcel infoParcel;
    infoParcel.hapInfoParameter.userID = USER_ID;
    infoParcel.hapInfoParameter.bundleName = "com.example.query.test";
    infoParcel.hapInfoParameter.instIndex = INST_INDEX;
    infoParcel.hapInfoParameter.dlpType = static_cast<int>(HapDlpType::DLP_COMMON);
    infoParcel.hapInfoParameter.apiVersion = API_VERSION_9;
    infoParcel.hapInfoParameter.isSystemApp = false;
    infoParcel.hapInfoParameter.appIDDesc = "com.example.query.test";

    HapPolicyParcel policyParcel;
    policyParcel.hapPolicy.apl = APL_NORMAL;
    policyParcel.hapPolicy.domain = "test.domain";

    // Add CAMERA permission to the HAP
    std::vector<PermissionStatus> permStates;
    PermissionStatus permState;
    permState.permissionName = "ohos.permission.CAMERA";
    permState.grantFlag = static_cast<uint32_t>(PermissionFlag::PERMISSION_USER_FIXED);
    permState.grantStatus = static_cast<int32_t>(PermissionState::PERMISSION_GRANTED);
    permStates.emplace_back(permState);
    policyParcel.hapPolicy.permStateList = permStates;

    // Create a HAP token
    std::map<int32_t, TokenIdInfo> tokenIdAplMap;
    AccessTokenID tokenID;
    CreateHapToken(infoParcel, policyParcel, tokenID, tokenIdAplMap, true);
    EXPECT_NE(INVALID_TOKENID, tokenID);

    // Act: Query with valid permissionList
    std::vector<uint32_t> permCodeList;
    uint32_t permCode = 0;
    ASSERT_TRUE(TransferPermissionToOpcode("ohos.permission.CAMERA", permCode));
    permCodeList.emplace_back(permCode);
    std::vector<PermissionStatusIdl> permissionInfoList;
    ErrCode ret = atManagerService_->QueryStatusByPermission(permCodeList, permissionInfoList, true);

    // Assert: Should return RET_SUCCESS
    EXPECT_EQ(RET_SUCCESS, ret);
    EXPECT_FALSE(permissionInfoList.empty());

    // Cleanup
    EXPECT_EQ(RET_SUCCESS, atManagerService_->DeleteToken(tokenID, false));
}

/**
 * @tc.name: QueryStatusByPermissionServiceTest004
 * @tc.desc: Test QueryStatusByPermission with invalid permCode, return ERR_PERMISSION_NOT_EXIST
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(AccessTokenManagerServiceTest, QueryStatusByPermissionServiceTest004, TestSize.Level1)
{
    atManagerService_->Initialize();

    std::vector<uint32_t> permCodeList = { 1000000 };
    std::vector<PermissionStatusIdl> permissionInfoList;
    ErrCode ret = atManagerService_->QueryStatusByPermission(permCodeList, permissionInfoList, true);

    EXPECT_EQ(AccessTokenError::ERR_PERMISSION_NOT_EXIST, ret);
    EXPECT_TRUE(permissionInfoList.empty());
}

/**
 * @tc.name: QueryStatusByTokenIDOverSizeTest001
 * @tc.desc: Test oversize scenario with maxQueryResultSize for testing
 * @tc.require:
 * @tc.type: FUNC
 */
HWTEST_F(AccessTokenManagerServiceTest, QueryStatusByTokenIDOverSizeTest001, TestSize.Level1)
{
    // Prepare: Create a HAP with multiple permissions
    HapInfoParcel infoParcel;
    infoParcel.hapInfoParameter.userID = USER_ID;
    infoParcel.hapInfoParameter.bundleName = "com.example.oversize.token.test";
    infoParcel.hapInfoParameter.instIndex = INST_INDEX;
    infoParcel.hapInfoParameter.dlpType = static_cast<int>(HapDlpType::DLP_COMMON);
    infoParcel.hapInfoParameter.apiVersion = 9; // 9: api version
    infoParcel.hapInfoParameter.isSystemApp = false;
    infoParcel.hapInfoParameter.appIDDesc = "com.example.oversize.token.test";

    HapPolicyParcel policyParcel;
    policyParcel.hapPolicy.apl = APL_SYSTEM_BASIC;
    policyParcel.hapPolicy.domain = "test.domain";
    std::vector<PermissionStatus> permStates;
    PermissionStatus permState;
    permState.permissionName = "ohos.permission.INTERNET";
    permState.grantFlag = static_cast<uint32_t>(PermissionFlag::PERMISSION_USER_FIXED);
    permState.grantStatus = static_cast<int32_t>(PermissionState::PERMISSION_GRANTED);
    permStates.emplace_back(permState);
    policyParcel.hapPolicy.permStateList = permStates;

    // Create a HAP token
    std::map<int32_t, TokenIdInfo> tokenIdAplMap;
    AccessTokenID tokenID;
    CreateHapToken(infoParcel, policyParcel, tokenID, tokenIdAplMap);

    size_t originalMaxSize = AccessTokenInfoManager::GetInstance().GetMaxQueryResultSize();
    AccessTokenInfoManager::GetInstance().SetMaxQueryResultSize(0); // 0: Set small max size for testing and query
    std::vector<AccessTokenID> tokenIDList = {static_cast<uint32_t>(tokenID)};
    std::vector<PermissionStatusIdl> permissionInfoList;
    ErrCode errCode = atManagerService_->QueryStatusByTokenID(tokenIDList, permissionInfoList);

    // Assert: Should return ERR_OVERSIZE since result exceeds limit
    EXPECT_EQ(AccessTokenError::ERR_OVERSIZE, errCode);
    EXPECT_TRUE(permissionInfoList.empty());

    // Cleanup
    AccessTokenInfoManager::GetInstance().SetMaxQueryResultSize(originalMaxSize);
    EXPECT_EQ(RET_SUCCESS, atManagerService_->DeleteToken(tokenID, false));
}

/**
 * @tc.name: FilterPermFeatureTest001
 * @tc.desc: Test FilterPermFeature with features_ empty and normal app
 * @tc.require:
 * @tc.type: FUNC
 */
HWTEST_F(AccessTokenManagerServiceTest, FilterPermFeatureTest001, TestSize.Level1)
{
    atManagerService_->Initialize();
    HapPolicy policy1;
    policy1.permStateList.push_back(g_state7);
    policy1.permStateList.push_back(g_state8);
    policy1.permStateList.push_back(g_state9);

    PermissionFeatureManager::GetInstance().SetFeatures({});

    atManagerService_->FilterPermFeature(false, policy1);
    EXPECT_EQ(INDEX_THREE, policy1.permStateList.size());
}

/**
 * @tc.name: FilterPermFeatureTest002
 * @tc.desc: Test FilterPermFeature with features_ empty and system app
 * @tc.require:
 * @tc.type: FUNC
 */
HWTEST_F(AccessTokenManagerServiceTest, FilterPermFeatureTest002, TestSize.Level1)
{
    atManagerService_->Initialize();
    HapPolicy policy1;
    policy1.permStateList.push_back(g_state7);
    policy1.permStateList.push_back(g_state8);
    policy1.permStateList.push_back(g_state9);

    PermissionFeatureManager::GetInstance().SetFeatures({});

    atManagerService_->FilterPermFeature(true, policy1);
    EXPECT_EQ(INDEX_ONE, policy1.permStateList.size());
}

/**
 * @tc.name: FilterPermFeatureTest003
 * @tc.desc: Test FilterPermFeature with features_ not empty and system app
 * @tc.require:
 * @tc.type: FUNC
 */
HWTEST_F(AccessTokenManagerServiceTest, FilterPermFeatureTest003, TestSize.Level1)
{
    atManagerService_->Initialize();
    HapPolicy policy1;
    policy1.permStateList.push_back(g_state7);
    policy1.permStateList.push_back(g_state8);
    policy1.permStateList.push_back(g_state9);

    PermissionFeatureManager::GetInstance().SetFeatures({"service_test_feature"});

    atManagerService_->FilterPermFeature(true, policy1);
    EXPECT_EQ(INDEX_TWO, policy1.permStateList.size());
    PermissionFeatureManager::GetInstance().SetFeatures({});
}

/**
 * @tc.name: FilterPermFeatureTest004
 * @tc.desc: Test FilterPermFeature with features_ not empty2 and system app
 * @tc.require:
 * @tc.type: FUNC
 */
HWTEST_F(AccessTokenManagerServiceTest, FilterPermFeatureTest004, TestSize.Level2)
{
    atManagerService_->Initialize();
    HapPolicy policy1;
    policy1.permStateList.push_back(g_state7);
    policy1.permStateList.push_back(g_state8);
    policy1.permStateList.push_back(g_state9);

    PermissionFeatureManager::GetInstance().SetFeatures({"service_test_feature", "service_test_feature2"});

    atManagerService_->FilterPermFeature(true, policy1);
    EXPECT_EQ(INDEX_THREE, policy1.permStateList.size());
    PermissionFeatureManager::GetInstance().SetFeatures({});
}

/**
 * @tc.name: FilterPermFeatureTest005
 * @tc.desc: Test FilterPermFeature with features_ not empty3 and system app
 * @tc.require:
 * @tc.type: FUNC
 */
HWTEST_F(AccessTokenManagerServiceTest, FilterPermFeatureTest005, TestSize.Level2)
{
    atManagerService_->Initialize();
    HapPolicy policy1;
    policy1.permStateList.push_back(g_state7);
    policy1.permStateList.push_back(g_state8);
    policy1.permStateList.push_back(g_state9);

    PermissionFeatureManager::GetInstance().SetFeatures({"service_test_feature", "service_test_feature666"});

    atManagerService_->FilterPermFeature(true, policy1);
    EXPECT_EQ(INDEX_TWO, policy1.permStateList.size());
    PermissionFeatureManager::GetInstance().SetFeatures({});
}

/**
 * @tc.name: FilterPermFeatureTest006
 * @tc.desc: Test InitHapToken with features_ not empty
 * @tc.require:
 * @tc.type: FUNC
 */
HWTEST_F(AccessTokenManagerServiceTest, FilterPermFeatureTest006, TestSize.Level1)
{
    atManagerService_->Initialize();
    HapInfoParams info = {
        .userID = USER_ID,
        .bundleName = "FilterPermFeatureTest006",
        .instIndex = INST_INDEX,
        .dlpType = static_cast<int>(HapDlpType::DLP_COMMON),
        .apiVersion = API_VERSION_9,
        .isSystemApp = true,
        .appIDDesc = "FilterPermFeatureTest006"
    };

    HapPolicy policy = {
        .apl = APL_SYSTEM_CORE,
        .domain = "domain",
        .permStateList = {g_state7, g_state8, g_state9}
    };

    PermissionFeatureManager::GetInstance().SetFeatures({"service_test_feature"});

    HapInfoParcel infoParCel;
    infoParCel.hapInfoParameter = info;
    HapPolicyParcel policyParcel;
    policyParcel.hapPolicy = policy;

    AccessTokenIDEx tokenIdEx;
    HapInfoCheckResultIdl result;
    uint64_t fullTokenId;
    int32_t ret = atManagerService_->InitHapToken(infoParCel, policyParcel, fullTokenId, result);
    tokenIdEx.tokenIDEx = fullTokenId;
    ASSERT_EQ(RET_SUCCESS, ret);

    std::vector<PermissionStatusParcel> reqPermList;
    EXPECT_EQ(RET_SUCCESS, atManagerService_->GetReqPermissions(tokenIdEx.tokenIdExStruct.tokenID, reqPermList, true));
    EXPECT_EQ(RET_SUCCESS, atManagerService_->GetReqPermissions(tokenIdEx.tokenIdExStruct.tokenID, reqPermList, false));

    EXPECT_EQ(INDEX_TWO, reqPermList.size());

    EXPECT_EQ(RET_SUCCESS, atManagerService_->DeleteToken(tokenIdEx.tokenIdExStruct.tokenID, false));
    PermissionFeatureManager::GetInstance().SetFeatures({});
}

/**
 * @tc.name: FilterPermFeatureTest007
 * @tc.desc: Test AllocHapToken with features_ not empty
 * @tc.require:
 * @tc.type: FUNC
 */
HWTEST_F(AccessTokenManagerServiceTest, FilterPermFeatureTest007, TestSize.Level2)
{
    atManagerService_->Initialize();
    HapInfoParams info = {
        .userID = USER_ID,
        .bundleName = "FilterPermFeatureTest007",
        .instIndex = INST_INDEX,
        .dlpType = static_cast<int>(HapDlpType::DLP_COMMON),
        .apiVersion = API_VERSION_9,
        .isSystemApp = true,
        .appIDDesc = "FilterPermFeatureTest007"
    };

    HapPolicy policy = {
        .apl = APL_SYSTEM_CORE,
        .domain = "domain",
        .permStateList = {g_state7, g_state8, g_state9}
    };

    PermissionFeatureManager::GetInstance().SetFeatures({});

    HapInfoParcel infoParCel;
    infoParCel.hapInfoParameter = info;
    HapPolicyParcel policyParcel;
    policyParcel.hapPolicy = policy;

    AccessTokenIDEx tokenIdEx;
    uint64_t fullTokenId;
    atManagerService_->AllocHapToken(infoParCel, policyParcel, fullTokenId);
    tokenIdEx.tokenIDEx = fullTokenId;
    ASSERT_NE(0, tokenIdEx.tokenIDEx);

    std::vector<PermissionStatusParcel> reqPermList;
    EXPECT_EQ(RET_SUCCESS, atManagerService_->GetReqPermissions(tokenIdEx.tokenIdExStruct.tokenID, reqPermList, true));
    EXPECT_EQ(RET_SUCCESS, atManagerService_->GetReqPermissions(tokenIdEx.tokenIdExStruct.tokenID, reqPermList, false));

    EXPECT_EQ(INDEX_ONE, reqPermList.size());

    EXPECT_EQ(RET_SUCCESS, atManagerService_->DeleteToken(tokenIdEx.tokenIdExStruct.tokenID, false));
    PermissionFeatureManager::GetInstance().SetFeatures({});
}

/**
 * @tc.name: FilterPermFeatureTest008
 * @tc.desc: Test UpdateHapToken with features_ not empty
 * @tc.require:
 * @tc.type: FUNC
 */
HWTEST_F(AccessTokenManagerServiceTest, FilterPermFeatureTest008, TestSize.Level1)
{
    atManagerService_->Initialize();
    HapInfoParams info = {
        .userID = USER_ID,
        .bundleName = "FilterPermFeatureTest008",
        .instIndex = INST_INDEX,
        .dlpType = static_cast<int>(HapDlpType::DLP_COMMON),
        .apiVersion = API_VERSION_9,
        .isSystemApp = true,
        .appIDDesc = "FilterPermFeatureTest008"
    };

    HapPolicy policy = {
        .apl = APL_SYSTEM_CORE,
        .domain = "domain",
        .permStateList = {g_state7, g_state8, g_state9}
    };

    PermissionFeatureManager::GetInstance().SetFeatures({"service_test_feature"});

    HapInfoParcel infoParCel;
    infoParCel.hapInfoParameter = info;
    HapPolicyParcel policyParcel;
    policyParcel.hapPolicy = policy;

    AccessTokenIDEx tokenIdEx;
    HapInfoCheckResultIdl result;
    uint64_t fullTokenId;
    int32_t ret = atManagerService_->InitHapToken(infoParCel, policyParcel, fullTokenId, result);
    tokenIdEx.tokenIDEx = fullTokenId;
    ASSERT_EQ(RET_SUCCESS, ret);

    PermissionFeatureManager::GetInstance().SetFeatures({"service_test_feature", "service_test_feature2"});
    UpdateHapInfoParamsIdl updateInfoParams = {
        .appIDDesc = "FilterPermFeatureTest008",
        .apiVersion = API_VERSION_9,
        .isSystemApp = true,
        .appDistributionType = "",
    };
    uint64_t fullTokenId2 = tokenIdEx.tokenIDEx;
    EXPECT_EQ(RET_SUCCESS,
        atManagerService_->UpdateHapToken(fullTokenId2, updateInfoParams, policyParcel, result));
    tokenIdEx.tokenIDEx = fullTokenId2;

    std::vector<PermissionStatusParcel> reqPermList;
    EXPECT_EQ(RET_SUCCESS, atManagerService_->GetReqPermissions(tokenIdEx.tokenIdExStruct.tokenID, reqPermList, true));
    EXPECT_EQ(RET_SUCCESS, atManagerService_->GetReqPermissions(tokenIdEx.tokenIdExStruct.tokenID, reqPermList, false));

    EXPECT_EQ(INDEX_THREE, reqPermList.size());

    EXPECT_EQ(RET_SUCCESS, atManagerService_->DeleteToken(tokenIdEx.tokenIdExStruct.tokenID, false));
    PermissionFeatureManager::GetInstance().SetFeatures({});
}

/**
 * @tc.name: FilterPermFeatureTest009
 * @tc.desc: Test UpdateHapToken with features_ not empty2
 * @tc.require:
 * @tc.type: FUNC
 */
HWTEST_F(AccessTokenManagerServiceTest, FilterPermFeatureTest009, TestSize.Level2)
{
    atManagerService_->Initialize();
    HapInfoParams info = {
        .userID = USER_ID,
        .bundleName = "FilterPermFeatureTest009",
        .instIndex = INST_INDEX,
        .dlpType = static_cast<int>(HapDlpType::DLP_COMMON),
        .apiVersion = API_VERSION_9,
        .isSystemApp = true,
        .appIDDesc = "FilterPermFeatureTest009"
    };

    HapPolicy policy = {
        .apl = APL_SYSTEM_CORE,
        .domain = "domain",
        .permStateList = {g_state7, g_state8, g_state9}
    };

    PermissionFeatureManager::GetInstance().SetFeatures({"service_test_feature"});

    HapInfoParcel infoParCel;
    infoParCel.hapInfoParameter = info;
    HapPolicyParcel policyParcel;
    policyParcel.hapPolicy = policy;

    AccessTokenIDEx tokenIdEx;
    HapInfoCheckResultIdl result;
    uint64_t fullTokenId;
    int32_t ret = atManagerService_->InitHapToken(infoParCel, policyParcel, fullTokenId, result);
    tokenIdEx.tokenIDEx = fullTokenId;
    ASSERT_EQ(RET_SUCCESS, ret);

    PermissionFeatureManager::GetInstance().SetFeatures({"service_test_feature9999999", "service_test_feature2"});
    UpdateHapInfoParamsIdl updateInfoParams = {
        .appIDDesc = "FilterPermFeatureTest009",
        .apiVersion = API_VERSION_9,
        .isSystemApp = true,
        .appDistributionType = "",
    };
    uint64_t fullTokenId2 = tokenIdEx.tokenIDEx;
    EXPECT_EQ(RET_SUCCESS,
        atManagerService_->UpdateHapToken(fullTokenId2, updateInfoParams, policyParcel, result));
    tokenIdEx.tokenIDEx = fullTokenId2;

    std::vector<PermissionStatusParcel> reqPermList;
    EXPECT_EQ(RET_SUCCESS, atManagerService_->GetReqPermissions(tokenIdEx.tokenIdExStruct.tokenID, reqPermList, true));
    EXPECT_EQ(RET_SUCCESS, atManagerService_->GetReqPermissions(tokenIdEx.tokenIdExStruct.tokenID, reqPermList, false));

    EXPECT_EQ(INDEX_TWO, reqPermList.size());

    EXPECT_EQ(RET_SUCCESS, atManagerService_->DeleteToken(tokenIdEx.tokenIdExStruct.tokenID, false));
    PermissionFeatureManager::GetInstance().SetFeatures({});
}

/**
 * @tc.name: AccessTokenServiceCoverageTest001
 * @tc.desc: AccessTokenServiceCoverageTest
 * @tc.require:
 * @tc.type: FUNC
 */
HWTEST_F(AccessTokenManagerServiceTest, AccessTokenServiceCoverageTest001, TestSize.Level4)
{
    atManagerService_->OnRemoveSystemAbility(RANDOM_TOKENID, "device_id");

    PermissionDefParcel permissionDefResult;
    int32_t ret = atManagerService_->GetDefPermission("", permissionDefResult);
    EXPECT_EQ(AccessTokenError::ERR_PARAM_INVALID, ret);

    ret = atManagerService_->GetDefPermission("PERMISSION_NOT_EXIST", permissionDefResult);
    EXPECT_EQ(AccessTokenError::ERR_PERMISSION_NOT_EXIST, ret);

    ret = atManagerService_->GetDefPermission("ohos.permission.GRANT_SENSITIVE_PERMISSIONS", permissionDefResult);
    EXPECT_EQ(RET_SUCCESS, ret);

    PermissionListStateParcel parcel;
    std::vector<PermissionListStateParcel> reqPermList(MAX_PERMISSION_SIZE + 1, parcel);
    ret = atManagerService_->GetPermissionsStatus(RANDOM_TOKENID, reqPermList);
    EXPECT_NE(RET_SUCCESS, ret);
}

/**
 * @tc.name: ClawPermissionServiceTest001
 * @tc.desc: Test CLAW permission service APIs with empty list params.
 * @tc.require:
 * @tc.type: FUNC
 */
HWTEST_F(AccessTokenManagerServiceTest, ClawPermissionServiceTest001, TestSize.Level1)
{
    PermissionDialogResultParcel dialogResult;
    EXPECT_EQ(AccessTokenError::ERR_PARAM_INVALID,
        atManagerService_->GetCliPermissionRequestInfo(DEFAULT_AGENT_ID, {}, dialogResult));
    EXPECT_EQ(AccessTokenError::ERR_PARAM_INVALID,
        atManagerService_->GetSkillPermissionRequestInfo(DEFAULT_AGENT_ID, {}, dialogResult));

    CliPermissionsResultParcel cliPermissionsResult;
    SkillPermissionsResultParcel skillPermissionsResult;
    EXPECT_EQ(AccessTokenError::ERR_PARAM_INVALID,
        atManagerService_->GetCliPermissions(
            INVALID_TOKENID, DEFAULT_AGENT_ID, BuildCliInfoParcels(), cliPermissionsResult));
    EXPECT_EQ(AccessTokenError::ERR_PARAM_INVALID,
        atManagerService_->GetSkillPermissions(
            INVALID_TOKENID, DEFAULT_AGENT_ID, BuildSkillInfoParcels(), skillPermissionsResult));
}

/**
 * @tc.name: ClawPermissionServiceTest002
 * @tc.desc: Test CLAW permission service APIs reject non-system callers.
 * @tc.require:
 * @tc.type: FUNC
 */
HWTEST_F(AccessTokenManagerServiceTest, ClawPermissionServiceTest002, TestSize.Level1)
{
    AccessTokenID tokenId = INVALID_TOKENID;
    uint64_t fullTokenId = CreateClawServiceTestToken("claw_permission_non_system_test", false, {}, tokenId);
    ASSERT_NE(0, fullTokenId);
    SetSelfTokenID(fullTokenId);

    PermissionDialogResultParcel dialogResult;
    EXPECT_EQ(AccessTokenError::ERR_NOT_SYSTEM_APP,
        atManagerService_->GetCliPermissionRequestInfo(DEFAULT_AGENT_ID, BuildCliInfoParcels(), dialogResult));
    EXPECT_EQ(AccessTokenError::ERR_NOT_SYSTEM_APP,
        atManagerService_->GetSkillPermissionRequestInfo(DEFAULT_AGENT_ID, BuildSkillInfoParcels(), dialogResult));

    CliPermissionsResultParcel cliPermissionsResult;
    EXPECT_EQ(AccessTokenError::ERR_NOT_SYSTEM_APP,
        atManagerService_->GetCliPermissions(
            tokenId, DEFAULT_AGENT_ID, BuildCliInfoParcels(), cliPermissionsResult));

    SetSelfTokenID(g_selfShellTokenId);
    (void)AccessTokenInfoManager::GetInstance().RemoveHapTokenInfo(tokenId);
}

/**
 * @tc.name: ClawPermissionServiceTest002_001
 * @tc.desc: Test CLAW permission service APIs reject system callers without required interface permission.
 * @tc.require:
 * @tc.type: FUNC
 */
HWTEST_F(AccessTokenManagerServiceTest, ClawPermissionServiceTest002_001, TestSize.Level1)
{
    AccessTokenID tokenId = INVALID_TOKENID;
    uint64_t fullTokenId = CreateClawServiceTestToken("claw_permission_no_api_permission_test", true, {}, tokenId);
    ASSERT_NE(0, fullTokenId);
    SetSelfTokenID(fullTokenId);

    PermissionDialogResultParcel dialogResult;
    EXPECT_EQ(AccessTokenError::ERR_PERMISSION_DENIED,
        atManagerService_->GetCliPermissionRequestInfo(DEFAULT_AGENT_ID, BuildCliInfoParcels(), dialogResult));
    EXPECT_EQ(AccessTokenError::ERR_PERMISSION_DENIED,
        atManagerService_->GetSkillPermissionRequestInfo(DEFAULT_AGENT_ID, BuildSkillInfoParcels(), dialogResult));

    CliPermissionsResultParcel cliPermissionsResult;
    EXPECT_EQ(AccessTokenError::ERR_PERMISSION_DENIED,
        atManagerService_->GetCliPermissions(
            tokenId, DEFAULT_AGENT_ID, BuildCliInfoParcels(), cliPermissionsResult));

    SkillPermissionsResultParcel skillPermissionsResult;
    EXPECT_EQ(AccessTokenError::ERR_PERMISSION_DENIED,
        atManagerService_->GetSkillPermissions(
            tokenId, DEFAULT_AGENT_ID, BuildSkillInfoParcels(), skillPermissionsResult));

    CliAuthInfoParcel cliAuthInfoParcel;
    cliAuthInfoParcel.info.cliInfo = BuildCliInfoParcels()[0].cliInfo;
    cliAuthInfoParcel.info.permissionNames = {"ohos.permission.POWER_MANAGER"};
    cliAuthInfoParcel.info.authorizationResults = {false};
    ToolAuthResultParcel authResult;
    EXPECT_EQ(AccessTokenError::ERR_PERMISSION_DENIED,
        atManagerService_->GenerateCliAuthResult(tokenId, DEFAULT_AGENT_ID, {cliAuthInfoParcel}, authResult));

    SkillAuthInfoParcel skillAuthInfoParcel;
    skillAuthInfoParcel.info.skillInfo = BuildSkillInfoParcels()[0].skillInfo;
    skillAuthInfoParcel.info.permissionNames = {"ohos.permission.CAMERA"};
    skillAuthInfoParcel.info.authorizationResults = {false};
    EXPECT_EQ(AccessTokenError::ERR_PERMISSION_DENIED,
        atManagerService_->GenerateSkillAuthResult(tokenId, DEFAULT_AGENT_ID, {skillAuthInfoParcel}, authResult));

    SetSelfTokenID(g_selfShellTokenId);
    (void)AccessTokenInfoManager::GetInstance().RemoveHapTokenInfo(tokenId);
}

/**
 * @tc.name: ClawPermissionServiceTest003
 * @tc.desc: Test CLAW permission service APIs return basic success result for system caller.
 * @tc.require:
 * @tc.type: FUNC
 */
HWTEST_F(AccessTokenManagerServiceTest, ClawPermissionServiceTest003, TestSize.Level1)
{
    PermissionStatus cliState = {
        .permissionName = "ohos.permission.POWER_MANAGER",
        .grantStatus = PermissionState::PERMISSION_GRANTED,
        .grantFlag = PermissionFlag::PERMISSION_USER_SET
    };
    auto permStates = BuildClawQueryAndManagePermissionStates();
    permStates.emplace_back(cliState);
    AccessTokenID tokenId = INVALID_TOKENID;
    uint64_t fullTokenId = CreateClawServiceTestToken(
        "claw_permission_system_service_test", true, permStates, tokenId);
    ASSERT_NE(0, fullTokenId);
    SetSelfTokenID(fullTokenId);

    PermissionDialogResultParcel dialogResult;
    ASSERT_EQ(RET_SUCCESS,
        atManagerService_->GetCliPermissionRequestInfo(DEFAULT_AGENT_ID, BuildCliInfoParcels(), dialogResult));
    ASSERT_EQ(1, static_cast<int32_t>(dialogResult.result.detailList.size()));
    EXPECT_FALSE(dialogResult.result.detailList[0].needPermissionDialog);
    EXPECT_FALSE(dialogResult.result.detailList[0].authResult.empty());

    CliPermissionsResultParcel cliPermissionsResult;
    ASSERT_EQ(RET_SUCCESS,
        atManagerService_->GetCliPermissions(
            tokenId, DEFAULT_AGENT_ID, BuildCliInfoParcels(), cliPermissionsResult));
    ASSERT_EQ(1, static_cast<int32_t>(cliPermissionsResult.result.permList.size()));

    SetSelfTokenID(g_selfShellTokenId);
    (void)AccessTokenInfoManager::GetInstance().RemoveHapTokenInfo(tokenId);
}

/**
 * @tc.name: ClawPermissionServiceTest004
 * @tc.desc: Test skill service path returns empty metadata results and still generates challenge strings.
 * @tc.require:
 * @tc.type: FUNC
 */
HWTEST_F(AccessTokenManagerServiceTest, ClawPermissionServiceTest004, TestSize.Level1)
{
    AccessTokenID tokenId = INVALID_TOKENID;
    uint64_t fullTokenId = CreateClawServiceTestToken(
        "claw_permission_skill_service_test", true, BuildClawQueryAndManagePermissionStates(), tokenId);
    ASSERT_NE(0, fullTokenId);
    SetSelfTokenID(fullTokenId);

    PermissionDialogResultParcel dialogResult;
    ASSERT_EQ(RET_SUCCESS,
        atManagerService_->GetSkillPermissionRequestInfo(DEFAULT_AGENT_ID, BuildSkillInfoParcels(), dialogResult));
    ASSERT_EQ(1, static_cast<int32_t>(dialogResult.result.detailList.size()));
    EXPECT_FALSE(dialogResult.result.detailList[0].needPermissionDialog);
    EXPECT_FALSE(dialogResult.result.detailList[0].authResult.empty());

    SkillPermissionsResultParcel skillPermissionsResult;
    ASSERT_EQ(RET_SUCCESS,
        atManagerService_->GetSkillPermissions(
            tokenId, DEFAULT_AGENT_ID, BuildSkillInfoParcels(), skillPermissionsResult));
    ASSERT_EQ(1, static_cast<int32_t>(skillPermissionsResult.result.permList.size()));
    EXPECT_TRUE(skillPermissionsResult.result.permList[0].usedPermissions.empty());
    EXPECT_TRUE(skillPermissionsResult.result.permList[0].statusList.empty());

    SkillAuthInfoParcel authInfoParcel;
    authInfoParcel.info.skillInfo = BuildSkillInfoParcels()[0].skillInfo;
    authInfoParcel.info.permissionNames = {"ohos.permission.CAMERA"};
    authInfoParcel.info.authorizationResults = {false};
    ToolAuthResultParcel authResult;
    ASSERT_EQ(RET_SUCCESS,
        atManagerService_->GenerateSkillAuthResult(tokenId, DEFAULT_AGENT_ID, {authInfoParcel}, authResult));
    ASSERT_EQ(1, static_cast<int32_t>(authResult.result.authResults.size()));
    EXPECT_FALSE(authResult.result.authResults[0].empty());

    SetSelfTokenID(g_selfShellTokenId);
    (void)AccessTokenInfoManager::GetInstance().RemoveHapTokenInfo(tokenId);
}

/**
 * @tc.name: ClawPermissionServiceTest005
 * @tc.desc: Test CLI token challenge generation validates auth info shape and creates challenge.
 * @tc.require:
 * @tc.type: FUNC
 */
HWTEST_F(AccessTokenManagerServiceTest, ClawPermissionServiceTest005, TestSize.Level1)
{
    AccessTokenID tokenId = INVALID_TOKENID;
    uint64_t fullTokenId = CreateClawServiceTestToken(
        "claw_permission_cli_challenge_test", true, BuildClawManagePermissionStates(), tokenId);
    ASSERT_NE(0, fullTokenId);
    SetSelfTokenID(fullTokenId);

    CliAuthInfoParcel invalidAuthInfoParcel;
    invalidAuthInfoParcel.info.cliInfo = BuildCliInfoParcels()[0].cliInfo;
    invalidAuthInfoParcel.info.permissionNames = {"ohos.permission.POWER_MANAGER"};
    ToolAuthResultParcel authResult;
    EXPECT_EQ(AccessTokenError::ERR_PARAM_INVALID,
        atManagerService_->GenerateCliAuthResult(tokenId, DEFAULT_AGENT_ID, {invalidAuthInfoParcel}, authResult));

    CliAuthInfoParcel authInfoParcel;
    authInfoParcel.info.cliInfo = BuildCliInfoParcels()[0].cliInfo;
    authInfoParcel.info.permissionNames = {"ohos.permission.POWER_MANAGER"};
    authInfoParcel.info.authorizationResults = {false};
    ASSERT_EQ(RET_SUCCESS,
        atManagerService_->GenerateCliAuthResult(tokenId, DEFAULT_AGENT_ID, {authInfoParcel}, authResult));
    ASSERT_EQ(1, static_cast<int32_t>(authResult.result.authResults.size()));
    EXPECT_FALSE(authResult.result.authResults[0].empty());

    CliAuthInfoParcel emptyAuthInfoParcel;
    emptyAuthInfoParcel.info.cliInfo = BuildEmptyPermissionCliInfoParcels()[0].cliInfo;
    ASSERT_EQ(RET_SUCCESS,
        atManagerService_->GenerateCliAuthResult(tokenId, DEFAULT_AGENT_ID, {emptyAuthInfoParcel}, authResult));
    ASSERT_EQ(1, static_cast<int32_t>(authResult.result.authResults.size()));
    EXPECT_FALSE(authResult.result.authResults[0].empty());

    SetSelfTokenID(g_selfShellTokenId);
    (void)AccessTokenInfoManager::GetInstance().RemoveHapTokenInfo(tokenId);
}

/**
 * @tc.name: ClawPermissionServiceTest006
 * @tc.desc: Test undeclared required CLI permission returns NO_DIALOG_NOT_DECLARED and no dialog.
 * @tc.require:
 * @tc.type: FUNC
 */
HWTEST_F(AccessTokenManagerServiceTest, ClawPermissionServiceTest006, TestSize.Level1)
{
    AccessTokenID tokenId = INVALID_TOKENID;
    uint64_t fullTokenId = CreateClawServiceTestToken(
        "claw_permission_cli_undeclared_test", true, BuildClawQueryAndManagePermissionStates(), tokenId);
    ASSERT_NE(0, fullTokenId);
    SetSelfTokenID(fullTokenId);

    PermissionDialogResultParcel dialogResult;
    ASSERT_EQ(RET_SUCCESS,
        atManagerService_->GetCliPermissionRequestInfo(DEFAULT_AGENT_ID, BuildCliInfoParcels(), dialogResult));
    ASSERT_EQ(1, static_cast<int32_t>(dialogResult.result.detailList.size()));
    EXPECT_FALSE(dialogResult.result.detailList[0].needPermissionDialog);
    ASSERT_EQ(1, static_cast<int32_t>(dialogResult.result.detailList[0].permissionNameList.size()));
    EXPECT_EQ("ohos.permission.POWER_MANAGER", dialogResult.result.detailList[0].permissionNameList[0]);
    ASSERT_EQ(1, static_cast<int32_t>(dialogResult.result.detailList[0].statusList.size()));
    EXPECT_EQ(PermissionDecisionStatus::NO_DIALOG_NOT_DECLARED,
        dialogResult.result.detailList[0].statusList[0]);
    EXPECT_TRUE(dialogResult.result.detailList[0].authResult.empty());

    CliPermissionsResultParcel cliPermissionsResult;
    ASSERT_EQ(RET_SUCCESS,
        atManagerService_->GetCliPermissions(
            tokenId, DEFAULT_AGENT_ID, BuildCliInfoParcels(), cliPermissionsResult));
    ASSERT_EQ(1, static_cast<int32_t>(cliPermissionsResult.result.permList.size()));
    const auto& detail = cliPermissionsResult.result.permList[0].requiredCliPermissions[0];
    EXPECT_EQ(PermissionDecisionStatus::NO_DIALOG_NOT_DECLARED, detail.cliPermissionStatus);
    EXPECT_TRUE(detail.usedPermissions.empty());

    SetSelfTokenID(g_selfShellTokenId);
    (void)AccessTokenInfoManager::GetInstance().RemoveHapTokenInfo(tokenId);
}

/**
 * @tc.name: ClawPermissionServiceTest007
 * @tc.desc: Test denied required CLI permission is returned as status instead of permission denied.
 * @tc.require:
 * @tc.type: FUNC
 */
HWTEST_F(AccessTokenManagerServiceTest, ClawPermissionServiceTest007, TestSize.Level1)
{
    PermissionStatus cliState = {
        .permissionName = "ohos.permission.POWER_MANAGER",
        .grantStatus = PermissionState::PERMISSION_DENIED,
        .grantFlag = PermissionFlag::PERMISSION_USER_FIXED
    };
    auto permStates = BuildClawQueryAndManagePermissionStates();
    permStates.emplace_back(cliState);
    AccessTokenID tokenId = INVALID_TOKENID;
    uint64_t fullTokenId = CreateClawServiceTestToken(
        "claw_permission_cli_denied_status_test", true, permStates, tokenId);
    ASSERT_NE(0, fullTokenId);
    SetSelfTokenID(fullTokenId);

    PermissionDialogResultParcel dialogResult;
    ASSERT_EQ(RET_SUCCESS,
        atManagerService_->GetCliPermissionRequestInfo(DEFAULT_AGENT_ID, BuildCliInfoParcels(), dialogResult));
    ASSERT_EQ(1, static_cast<int32_t>(dialogResult.result.detailList.size()));
    ASSERT_EQ(1, static_cast<int32_t>(dialogResult.result.detailList[0].statusList.size()));
    EXPECT_EQ(PermissionDecisionStatus::NO_DIALOG_DENIED, dialogResult.result.detailList[0].statusList[0]);

    CliPermissionsResultParcel cliPermissionsResult;
    ASSERT_EQ(RET_SUCCESS,
        atManagerService_->GetCliPermissions(
            tokenId, DEFAULT_AGENT_ID, BuildCliInfoParcels(), cliPermissionsResult));
    ASSERT_EQ(1, static_cast<int32_t>(cliPermissionsResult.result.permList.size()));
    const auto& detail = cliPermissionsResult.result.permList[0].requiredCliPermissions[0];
    EXPECT_EQ(PermissionDecisionStatus::NO_DIALOG_DENIED, detail.cliPermissionStatus);
    ASSERT_EQ(1, static_cast<int32_t>(detail.usedPermissions.size()));

    SetSelfTokenID(g_selfShellTokenId);
    (void)AccessTokenInfoManager::GetInstance().RemoveHapTokenInfo(tokenId);
}

/**
 * @tc.name: ClawPermissionServiceTest007_001
 * @tc.desc: Test CLI dialog challenge is generated only for details without permission dialog.
 * @tc.require:
 * @tc.type: FUNC
 */
HWTEST_F(AccessTokenManagerServiceTest, ClawPermissionServiceTest007_001, TestSize.Level1)
{
    PermissionStatus cliCameraState = {
        .permissionName = "ohos.permission.POWER_MANAGER",
        .grantStatus = PermissionState::PERMISSION_GRANTED,
        .grantFlag = PermissionFlag::PERMISSION_USER_SET
    };
    auto permStates = BuildClawQueryPermissionStates();
    permStates.emplace_back(cliCameraState);
    AccessTokenID tokenId = INVALID_TOKENID;
    uint64_t fullTokenId = CreateClawServiceTestToken(
        "claw_permission_cli_mixed_dialog_test", true, permStates, tokenId);
    ASSERT_NE(0, fullTokenId);
    SetSelfTokenID(fullTokenId);

    PermissionDialogResultParcel dialogResult;
    ASSERT_EQ(RET_SUCCESS,
        atManagerService_->GetCliPermissionRequestInfo(
            DEFAULT_AGENT_ID, BuildMixedDialogCliInfoParcels(), dialogResult));
    ASSERT_EQ(2, static_cast<int32_t>(dialogResult.result.detailList.size()));

    const auto& locationDetail = dialogResult.result.detailList[0];
    EXPECT_FALSE(locationDetail.needPermissionDialog);
    EXPECT_TRUE(locationDetail.authResult.empty());

    const auto& cameraDetail = dialogResult.result.detailList[1];
    EXPECT_FALSE(cameraDetail.needPermissionDialog);
    EXPECT_FALSE(cameraDetail.authResult.empty());

    SetSelfTokenID(g_selfShellTokenId);
    (void)AccessTokenInfoManager::GetInstance().RemoveHapTokenInfo(tokenId);
}

/**
 * @tc.name: ClawPermissionServiceTest007_002
 * @tc.desc: Test CLI dialog query returns ERR_PARAM_INVALID when metadata queryRet is not success.
 * @tc.require:
 * @tc.type: FUNC
 */
HWTEST_F(AccessTokenManagerServiceTest, ClawPermissionServiceTest007_002, TestSize.Level1)
{
    AccessTokenID tokenId = INVALID_TOKENID;
    uint64_t fullTokenId = CreateClawServiceTestToken(
        "claw_permission_cli_validate_error_test", true, BuildClawQueryAndManagePermissionStates(), tokenId);
    ASSERT_NE(0, fullTokenId);
    SetSelfTokenID(fullTokenId);

    PermissionDialogResultParcel dialogResult;
    ASSERT_EQ(AccessTokenError::ERR_PARAM_INVALID,
        atManagerService_->GetCliPermissionRequestInfo(
            DEFAULT_AGENT_ID, BuildUnknownCliInfoParcels(), dialogResult));

    CliPermissionsResultParcel cliPermissionsResult;
    ASSERT_EQ(AccessTokenError::ERR_PARAM_INVALID,
        atManagerService_->GetCliPermissions(
            tokenId, DEFAULT_AGENT_ID, BuildUnknownCliInfoParcels(), cliPermissionsResult));

    SetSelfTokenID(g_selfShellTokenId);
    (void)AccessTokenInfoManager::GetInstance().RemoveHapTokenInfo(tokenId);
}

/**
 * @tc.name: ClawPermissionServiceTest007_003
 * @tc.desc: Test CLI dialog query returns error when CLI permission has no mapping and no definition.
 * @tc.require:
 * @tc.type: FUNC
 */
HWTEST_F(AccessTokenManagerServiceTest, ClawPermissionServiceTest007_003, TestSize.Level1)
{
    AccessTokenID tokenId = INVALID_TOKENID;
    uint64_t fullTokenId = CreateClawServiceTestToken(
        "claw_permission_cli_build_error_test", true, BuildClawQueryPermissionStates(), tokenId);
    ASSERT_NE(0, fullTokenId);
    SetSelfTokenID(fullTokenId);

    PermissionDialogResultParcel dialogResult;
    ASSERT_EQ(AccessTokenError::ERR_PERMISSION_NOT_EXIST,
        atManagerService_->GetCliPermissionRequestInfo(
            DEFAULT_AGENT_ID, BuildMissingMappingCliInfoParcels(), dialogResult));

    SetSelfTokenID(g_selfShellTokenId);
    (void)AccessTokenInfoManager::GetInstance().RemoveHapTokenInfo(tokenId);
}

/**
 * @tc.name: ClawPermissionServiceTest007_004
 * @tc.desc: Test CLI without required permissions does not require dialog or permission mapping.
 * @tc.require:
 * @tc.type: FUNC
 */
HWTEST_F(AccessTokenManagerServiceTest, ClawPermissionServiceTest007_004, TestSize.Level1)
{
    AccessTokenID tokenId = INVALID_TOKENID;
    uint64_t fullTokenId = CreateClawServiceTestToken(
        "claw_permission_cli_empty_permission_test", true, BuildClawQueryAndManagePermissionStates(), tokenId);
    ASSERT_NE(0, fullTokenId);
    SetSelfTokenID(fullTokenId);

    PermissionDialogResultParcel dialogResult;
    ASSERT_EQ(RET_SUCCESS,
        atManagerService_->GetCliPermissionRequestInfo(
            DEFAULT_AGENT_ID, BuildEmptyPermissionCliInfoParcels(), dialogResult));
    ASSERT_EQ(1, static_cast<int32_t>(dialogResult.result.detailList.size()));
    EXPECT_FALSE(dialogResult.result.detailList[0].needPermissionDialog);
    EXPECT_TRUE(dialogResult.result.detailList[0].permissionNameList.empty());
    EXPECT_TRUE(dialogResult.result.detailList[0].statusList.empty());
    EXPECT_FALSE(dialogResult.result.detailList[0].authResult.empty());

    CliPermissionsResultParcel cliPermissionsResult;
    ASSERT_EQ(RET_SUCCESS,
        atManagerService_->GetCliPermissions(
            tokenId, DEFAULT_AGENT_ID, BuildEmptyPermissionCliInfoParcels(), cliPermissionsResult));
    ASSERT_EQ(1, static_cast<int32_t>(cliPermissionsResult.result.permList.size()));
    EXPECT_TRUE(cliPermissionsResult.result.permList[0].requiredCliPermissions.empty());

    SetSelfTokenID(g_selfShellTokenId);
    (void)AccessTokenInfoManager::GetInstance().RemoveHapTokenInfo(tokenId);
}

/**
 * @tc.name: ClawPermissionServiceTest008
 * @tc.desc: Test skill token challenge still generates challenge when skill metadata query returns empty.
 * @tc.require:
 * @tc.type: FUNC
 */
HWTEST_F(AccessTokenManagerServiceTest, ClawPermissionServiceTest008, TestSize.Level1)
{
    PermissionStatus cameraState = {
        .permissionName = "ohos.permission.CAMERA",
        .grantStatus = PermissionState::PERMISSION_DENIED,
        .grantFlag = PermissionFlag::PERMISSION_DEFAULT_FLAG
    };
    auto permStates = BuildClawManagePermissionStates();
    permStates.emplace_back(cameraState);
    AccessTokenID tokenId = INVALID_TOKENID;
    uint64_t fullTokenId = CreateClawServiceTestToken(
        "claw_permission_skill_no_grant_test", true, permStates, tokenId);
    ASSERT_NE(0, fullTokenId);
    SetSelfTokenID(fullTokenId);

    SkillAuthInfoParcel authInfoParcel;
    authInfoParcel.info.skillInfo = BuildSkillInfoParcels()[0].skillInfo;
    authInfoParcel.info.permissionNames = {"ohos.permission.CAMERA"};
    authInfoParcel.info.authorizationResults = {true};
    ToolAuthResultParcel authResult;
    ASSERT_EQ(RET_SUCCESS,
        atManagerService_->GenerateSkillAuthResult(tokenId, DEFAULT_AGENT_ID, {authInfoParcel}, authResult));
    ASSERT_EQ(1, static_cast<int32_t>(authResult.result.authResults.size()));
    EXPECT_FALSE(authResult.result.authResults[0].empty());

    SkillPermissionsResultParcel skillPermissionsResult;
    ASSERT_EQ(RET_SUCCESS,
        atManagerService_->GetSkillPermissions(
            tokenId, DEFAULT_AGENT_ID, BuildSkillInfoParcels(), skillPermissionsResult));
    ASSERT_EQ(1, static_cast<int32_t>(skillPermissionsResult.result.permList.size()));
    EXPECT_TRUE(skillPermissionsResult.result.permList[0].usedPermissions.empty());
    EXPECT_TRUE(skillPermissionsResult.result.permList[0].statusList.empty());

    SetSelfTokenID(g_selfShellTokenId);
    (void)AccessTokenInfoManager::GetInstance().RemoveHapTokenInfo(tokenId);
}

/**
 * @tc.name: ClawPermissionServiceTest008_001
 * @tc.desc: Test skill dialog query falls back to no-dialog result when skill metadata query is empty.
 * @tc.require:
 * @tc.type: FUNC
 */
HWTEST_F(AccessTokenManagerServiceTest, ClawPermissionServiceTest008_001, TestSize.Level1)
{
    PermissionStatus cameraState = {
        .permissionName = "ohos.permission.CAMERA",
        .grantStatus = PermissionState::PERMISSION_DENIED,
        .grantFlag = PermissionFlag::PERMISSION_DEFAULT_FLAG
    };
    auto permStates = BuildClawQueryPermissionStates();
    permStates.emplace_back(cameraState);
    AccessTokenID tokenId = INVALID_TOKENID;
    uint64_t fullTokenId = CreateClawServiceTestToken(
        "claw_permission_skill_all_dialog_test", true, permStates, tokenId);
    ASSERT_NE(0, fullTokenId);
    SetSelfTokenID(fullTokenId);

    PermissionDialogResultParcel dialogResult;
    ASSERT_EQ(RET_SUCCESS,
        atManagerService_->GetSkillPermissionRequestInfo(DEFAULT_AGENT_ID, BuildSkillInfoParcels(), dialogResult));
    ASSERT_EQ(1, static_cast<int32_t>(dialogResult.result.detailList.size()));
    EXPECT_FALSE(dialogResult.result.detailList[0].needPermissionDialog);
    EXPECT_FALSE(dialogResult.result.detailList[0].authResult.empty());

    SetSelfTokenID(g_selfShellTokenId);
    (void)AccessTokenInfoManager::GetInstance().RemoveHapTokenInfo(tokenId);
}

/**
 * @tc.name: ClawPermissionServiceTest008_002
 * @tc.desc: Test mixed skill dialog query now generates challenge for every detail when metadata is empty.
 * @tc.require:
 * @tc.type: FUNC
 */
HWTEST_F(AccessTokenManagerServiceTest, ClawPermissionServiceTest008_002, TestSize.Level1)
{
    PermissionStatus cameraState = {
        .permissionName = "ohos.permission.CAMERA",
        .grantStatus = PermissionState::PERMISSION_DENIED,
        .grantFlag = PermissionFlag::PERMISSION_DEFAULT_FLAG
    };
    auto permStates = BuildClawQueryPermissionStates();
    permStates.emplace_back(cameraState);
    AccessTokenID tokenId = INVALID_TOKENID;
    uint64_t fullTokenId = CreateClawServiceTestToken(
        "claw_permission_skill_mixed_dialog_test", true, permStates, tokenId);
    ASSERT_NE(0, fullTokenId);
    SetSelfTokenID(fullTokenId);

    PermissionDialogResultParcel dialogResult;
    ASSERT_EQ(RET_SUCCESS,
        atManagerService_->GetSkillPermissionRequestInfo(
            DEFAULT_AGENT_ID, BuildMixedDialogSkillInfoParcels(), dialogResult));
    ASSERT_EQ(2, static_cast<int32_t>(dialogResult.result.detailList.size()));

    const auto& cameraDetail = dialogResult.result.detailList[0];
    EXPECT_FALSE(cameraDetail.needPermissionDialog);
    EXPECT_FALSE(cameraDetail.authResult.empty());

    const auto& locationDetail = dialogResult.result.detailList[1];
    EXPECT_FALSE(locationDetail.needPermissionDialog);
    EXPECT_FALSE(locationDetail.authResult.empty());
    EXPECT_NE(cameraDetail.authResult, locationDetail.authResult);

    SetSelfTokenID(g_selfShellTokenId);
    (void)AccessTokenInfoManager::GetInstance().RemoveHapTokenInfo(tokenId);
}

/**
 * @tc.name: ClawPermissionServiceTest009
 * @tc.desc: Test token challenge generates challenge even if authorized permission does not exist.
 * @tc.require:
 * @tc.type: FUNC
 */
HWTEST_F(AccessTokenManagerServiceTest, ClawPermissionServiceTest009, TestSize.Level1)
{
    AccessTokenID tokenId = INVALID_TOKENID;
    uint64_t fullTokenId = CreateClawServiceTestToken(
        "claw_permission_cli_no_grant_test", true, BuildClawManagePermissionStates(), tokenId);
    ASSERT_NE(0, fullTokenId);
    SetSelfTokenID(fullTokenId);

    CliAuthInfoParcel authInfoParcel;
    authInfoParcel.info.cliInfo = BuildCliInfoParcels()[0].cliInfo;
    authInfoParcel.info.permissionNames = {"ohos.permission.POWER_MANAGER"};
    authInfoParcel.info.authorizationResults = {true};
    ToolAuthResultParcel authResult;
    ASSERT_EQ(RET_SUCCESS,
        atManagerService_->GenerateCliAuthResult(tokenId, DEFAULT_AGENT_ID, {authInfoParcel}, authResult));
    ASSERT_EQ(1, static_cast<int32_t>(authResult.result.authResults.size()));
    EXPECT_FALSE(authResult.result.authResults[0].empty());

    SetSelfTokenID(g_selfShellTokenId);
    (void)AccessTokenInfoManager::GetInstance().RemoveHapTokenInfo(tokenId);
}

/**
 * @tc.name: ClawPermissionServiceTest010
 * @tc.desc: Test multiple CLI auth info generates auth results in auth info order.
 * @tc.require:
 * @tc.type: FUNC
 */
HWTEST_F(AccessTokenManagerServiceTest, ClawPermissionServiceTest010, TestSize.Level1)
{
    AccessTokenID tokenId = INVALID_TOKENID;
    uint64_t fullTokenId = CreateClawServiceTestToken(
        "claw_permission_cli_challenge_order_test", true, BuildClawManagePermissionStates(), tokenId);
    ASSERT_NE(0, fullTokenId);
    SetSelfTokenID(fullTokenId);

    CliAuthInfoParcel cameraAuthInfoParcel;
    cameraAuthInfoParcel.info.cliInfo = BuildCliInfoParcels()[0].cliInfo;
    cameraAuthInfoParcel.info.permissionNames = {"ohos.permission.POWER_MANAGER"};
    cameraAuthInfoParcel.info.authorizationResults = {false};

    CliAuthInfoParcel locationAuthInfoParcel;
    locationAuthInfoParcel.info.cliInfo = {
        .cliName = "location",
        .subCliName = "query"
    };
    locationAuthInfoParcel.info.permissionNames = {"ohos.permission.APPROXIMATELY_LOCATION"};
    locationAuthInfoParcel.info.authorizationResults = {false};

    ToolAuthResultParcel authResult;
    ASSERT_EQ(RET_SUCCESS, atManagerService_->GenerateCliAuthResult(
        tokenId, DEFAULT_AGENT_ID, {cameraAuthInfoParcel, locationAuthInfoParcel}, authResult));
    ASSERT_EQ(2, static_cast<int32_t>(authResult.result.authResults.size()));
    EXPECT_FALSE(authResult.result.authResults[0].empty());
    EXPECT_FALSE(authResult.result.authResults[1].empty());
    EXPECT_NE(authResult.result.authResults[0], authResult.result.authResults[1]);

    SetSelfTokenID(g_selfShellTokenId);
    (void)AccessTokenInfoManager::GetInstance().RemoveHapTokenInfo(tokenId);
}

/**
 * @tc.name: ClawPermissionServiceTest011
 * @tc.desc: Test CLI auth result expands CLI permission to mapped system permissions before ticket generation.
 * @tc.require:
 * @tc.type: FUNC
 */
HWTEST_F(AccessTokenManagerServiceTest, ClawPermissionServiceTest011, TestSize.Level1)
{
    AccessTokenID tokenId = INVALID_TOKENID;
    uint64_t fullTokenId = CreateClawServiceTestToken(
        "claw_permission_cli_expand_used_permissions_test", true, BuildClawManagePermissionStates(), tokenId);
    ASSERT_NE(0, fullTokenId);
    SetSelfTokenID(fullTokenId);

    CliAuthInfoParcel authInfoParcel;
    authInfoParcel.info.cliInfo = {
        .cliName = "location",
        .subCliName = "query"
    };
    authInfoParcel.info.permissionNames = {"ohos.permission.APPROXIMATELY_LOCATION"};
    authInfoParcel.info.authorizationResults = {true};
    ToolAuthResultParcel authResult;
    ASSERT_EQ(RET_SUCCESS,
        atManagerService_->GenerateCliAuthResult(tokenId, DEFAULT_AGENT_ID, {authInfoParcel}, authResult));
    ASSERT_EQ(1, static_cast<int32_t>(authResult.result.authResults.size()));
    EXPECT_FALSE(authResult.result.authResults[0].empty());

    std::vector<PermissionStatus> permList;
    ASSERT_EQ(RET_SUCCESS, ClawTicketManager::GetInstance().VerifyCliClawTicket(
        tokenId, authResult.result.authResults[0], authInfoParcel.info.cliInfo, permList));
    ASSERT_EQ(2, static_cast<int32_t>(permList.size()));
    EXPECT_EQ("ohos.permission.LOCATION", permList[0].permissionName);
    EXPECT_EQ(PERMISSION_GRANTED, permList[0].grantStatus);
    EXPECT_EQ("ohos.permission.APPROXIMATELY_LOCATION", permList[1].permissionName);
    EXPECT_EQ(PERMISSION_GRANTED, permList[1].grantStatus);

    SetSelfTokenID(g_selfShellTokenId);
    (void)AccessTokenInfoManager::GetInstance().RemoveHapTokenInfo(tokenId);
}

/**
 * @tc.name: ClawPermissionServiceTest012
 * @tc.desc: Test host granted system permission is not downgraded by CLI authorization result.
 * @tc.require:
 * @tc.type: FUNC
 */
HWTEST_F(AccessTokenManagerServiceTest, ClawPermissionServiceTest012, TestSize.Level1)
{
    PermissionStatus cliState = {
        .permissionName = "ohos.permission.POWER_MANAGER",
        .grantStatus = PermissionState::PERMISSION_GRANTED,
        .grantFlag = PermissionFlag::PERMISSION_USER_SET
    };
    auto permStates = BuildClawManagePermissionStates();
    permStates.emplace_back(cliState);
    AccessTokenID tokenId = INVALID_TOKENID;
    uint64_t fullTokenId = CreateClawServiceTestToken(
        "claw_permission_cli_keep_granted_system_permission_test", true, permStates, tokenId);
    ASSERT_NE(0, fullTokenId);
    SetSelfTokenID(fullTokenId);

    CliAuthInfoParcel authInfoParcel;
    authInfoParcel.info.cliInfo = BuildCliInfoParcels()[0].cliInfo;
    authInfoParcel.info.permissionNames = {"ohos.permission.POWER_MANAGER"};
    authInfoParcel.info.authorizationResults = {false};
    ToolAuthResultParcel authResult;
    ASSERT_EQ(RET_SUCCESS,
        atManagerService_->GenerateCliAuthResult(tokenId, DEFAULT_AGENT_ID, {authInfoParcel}, authResult));
    ASSERT_EQ(1, static_cast<int32_t>(authResult.result.authResults.size()));
    EXPECT_FALSE(authResult.result.authResults[0].empty());

    std::vector<PermissionStatus> permList;
    ASSERT_EQ(RET_SUCCESS, ClawTicketManager::GetInstance().VerifyCliClawTicket(
        tokenId, authResult.result.authResults[0], authInfoParcel.info.cliInfo, permList));
    ASSERT_EQ(1, static_cast<int32_t>(permList.size()));
    EXPECT_EQ("ohos.permission.POWER_MANAGER", permList[0].permissionName);
    EXPECT_EQ(PERMISSION_GRANTED, permList[0].grantStatus);

    SetSelfTokenID(g_selfShellTokenId);
    (void)AccessTokenInfoManager::GetInstance().RemoveHapTokenInfo(tokenId);
}

#ifdef SUPPORT_MANAGE_USER_POLICY
/**
 * @tc.name: PolicyWhiteListServiceTest001
 * @tc.desc: Test UpdatePolicyWhiteList service param validation.
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(AccessTokenManagerServiceTest, PolicyWhiteListServiceTest001, TestSize.Level1)
{
    HapInfoParcel infoParcel;
    infoParcel.hapInfoParameter = g_info;
    HapPolicyParcel policyParcel;
    policyParcel.hapPolicy.apl = APL_SYSTEM_BASIC;
    policyParcel.hapPolicy.domain = "test.domain";
    PermissionStatus internetState = {
        .permissionName = "ohos.permission.INTERNET",
        .grantStatus = static_cast<int32_t>(PermissionState::PERMISSION_GRANTED),
        .grantFlag = static_cast<uint32_t>(PermissionFlag::PERMISSION_DEFAULT_FLAG)
    };
    policyParcel.hapPolicy.permStateList = {internetState};

    AccessTokenID tokenId;
    std::map<int32_t, TokenIdInfo> tokenIdAplMap;
    CreateHapToken(infoParcel, policyParcel, tokenId, tokenIdAplMap);

    uint32_t permCode = 0;
    ASSERT_TRUE(TransferPermissionToOpcode("ohos.permission.INTERNET", permCode));

    EXPECT_EQ(ERR_PARAM_INVALID,
        atManagerService_->UpdatePolicyWhiteList(INVALID_TOKENID, permCode, static_cast<int32_t>(ADD)));
    EXPECT_EQ(ERR_PARAM_INVALID,
        atManagerService_->UpdatePolicyWhiteList(tokenId, permCode, 2)); // 2: invalid enum value
    EXPECT_EQ(ERR_PARAM_INVALID,
        atManagerService_->UpdatePolicyWhiteList(tokenId, UINT32_MAX, static_cast<int32_t>(ADD)));

    AccessTokenID nativeTokenId = AccessTokenKit::GetNativeTokenId("foundation");
    EXPECT_EQ(ERR_PARAM_INVALID,
        atManagerService_->UpdatePolicyWhiteList(nativeTokenId, permCode, static_cast<int32_t>(ADD)));

    DelTestDataAndRestoreOri(tokenId, {});
}

/**
 * @tc.name: PolicyWhiteListServiceTest002
 * @tc.desc: Test GetPolicyWhiteList service param validation.
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(AccessTokenManagerServiceTest, PolicyWhiteListServiceTest002, TestSize.Level1)
{
    std::vector<AccessTokenID> tokenIdList = {RANDOM_TOKENID};
    EXPECT_EQ(ERR_PARAM_INVALID, atManagerService_->GetPolicyWhiteList(UINT32_MAX, tokenIdList));
}
#endif

/**
 * @tc.name: IsSupportPermissionService001
 * @tc.desc: Test IsSupportPermission service with abnormal string permissionName.
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(AccessTokenManagerServiceTest, IsSupportPermissionService001, TestSize.Level0)
{
    bool isSupported = false;
    // Test with empty string
    int32_t ret = atManagerService_->IsSupportPermission(" ", isSupported);
    EXPECT_EQ(RET_SUCCESS, ret);
    EXPECT_FALSE(isSupported);
 
    // Test with invalid string name.
    ret = atManagerService_->IsSupportPermission("invalid.name", isSupported);
    EXPECT_EQ(RET_SUCCESS, ret);
    EXPECT_FALSE(isSupported);
}

/**
 * @tc.name: IsSupportPermissionService002
 * @tc.desc: Test IsSupportPermission service with valid and invalid permissions.
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(AccessTokenManagerServiceTest, IsSupportPermissionService002, TestSize.Level0)
{
    bool isSupported = false;
    
    // Test with valid permission
    int32_t ret = atManagerService_->IsSupportPermission("ohos.permission.CAMERA", isSupported);
    EXPECT_EQ(RET_SUCCESS, ret);
    EXPECT_TRUE(isSupported);
    
    // Test with invalid permission
    ret = atManagerService_->IsSupportPermission("ohos.permission.INVALID_PERM", isSupported);
    EXPECT_EQ(RET_SUCCESS, ret);
    EXPECT_FALSE(isSupported);
    
    // Test with disabled permission
    constexpr const char* permissionName = "ohos.permission.MICROPHONE";
    ASSERT_TRUE(SetPermissionBriefEnabled(permissionName, false));
    ret = atManagerService_->IsSupportPermission(permissionName, isSupported);
    EXPECT_EQ(RET_SUCCESS, ret);
    EXPECT_FALSE(isSupported);
    ASSERT_TRUE(SetPermissionBriefEnabled(permissionName, true));
}

/**
 * @tc.name: GetPermissionCodeService001
 * @tc.desc: Test GetPermissionCode service with valid and disabled permissions.
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(AccessTokenManagerServiceTest, GetPermissionCodeService001, TestSize.Level0)
{
    uint32_t opCode = 0;
    
    // Test with valid permission
    int32_t ret = atManagerService_->GetPermissionCode("ohos.permission.CAMERA", opCode);
    EXPECT_EQ(RET_SUCCESS, ret);
    EXPECT_NE(0, opCode);
    
    // Test with disabled permission
    constexpr const char* permissionName = "ohos.permission.MICROPHONE";
    ASSERT_TRUE(SetPermissionBriefEnabled(permissionName, false));
    ret = atManagerService_->GetPermissionCode(permissionName, opCode);
    EXPECT_EQ(ERR_PERMISSION_NOT_EXIST, ret);
    ASSERT_TRUE(SetPermissionBriefEnabled(permissionName, true));
    
    // Test with invalid permission
    ret = atManagerService_->GetPermissionCode("ohos.permission.INVALID_PERM", opCode);
    EXPECT_EQ(ERR_PERMISSION_NOT_EXIST, ret);
}
} // namespace AccessToken
} // namespace Security
} // namespace OHOS
