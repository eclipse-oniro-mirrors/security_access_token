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
#include <cstring>

#define private public
#include "accesstoken_callbacks.h"
#include "accesstoken_info_manager.h"
#include "accesstoken_kit.h"
#include "access_token_db_operator.h"
#include "access_token_db.h"
#include "access_token_error.h"
#include "accesstoken_id_manager.h"
#include "accesstoken_info_utils.h"
#include "atm_tools_param_info_parcel.h"
#include "claw_ticket_manager.h"
#include "hap_info_parcel.h"
#include "hap_policy_parcel.h"
#include "mock_permission.h"
#include "parameters.h"
#include "os_account_manager_lite.h"
#include "permission_feature_manager.h"
#include "permission_map.h"
#include "permission_manager.h"
#include "permission_request_toggle_manager.h"
#include "perm_state_change_callback_customize.h"
#ifdef SECURITY_COMPONENT_ENHANCE_ENABLE
#include "sec_comp_enhance_agent.h"
#endif
#include "securec.h"
#include "test_common.h"
#include "token_field_const.h"
#include "tokenid_attributes.h"
#include "token_setproc.h"
#include "user_policy_manager.h"
#undef private

const char* DEVELOPER_MODE_STATE = "const.security.developermode.state";


using namespace testing::ext;
using namespace testing::mt;
using namespace OHOS;

namespace OHOS {
namespace Security {
namespace AccessToken {
namespace {
struct UidGuard {
    explicit UidGuard(uid_t newUid) : origUid(getuid())
    {
        (void)setuid(newUid);
    }

    ~UidGuard()
    {
        (void)setuid(origUid);
    }

    UidGuard(const UidGuard&) = delete;
    UidGuard& operator=(const UidGuard&) = delete;

    uid_t origUid;
};

static constexpr int32_t USER_ID = 100;
static constexpr int32_t LEGACY_SUBPROFILE_ID = -1;
static constexpr int32_t INST_INDEX = 0;
static constexpr int32_t INDEX_ONE = 1;
static constexpr int32_t INDEX_TWO = 2;
static constexpr int32_t INDEX_THREE = 3;
static constexpr int32_t MAX_PERMISSION_SIZE = 1024;
static constexpr int32_t API_VERSION_9 = 9;
static constexpr int32_t RANDOM_TOKENID = 123;
static constexpr uid_t NON_ROOT_UID = 2000;
static const std::string DEFAULT_AGENT_ID = "1001";
static const std::string MANAGE_USER_POLICY = "ohos.permission.MANAGE_USER_POLICY";
static const std::string MANAGE_EDM_POLICY = "ohos.permission.MANAGE_EDM_POLICY";
static const std::string GRANT_SENSITIVE_PERMISSIONS = "ohos.permission.GRANT_SENSITIVE_PERMISSIONS";
static const std::string REVOKE_SENSITIVE_PERMISSIONS = "ohos.permission.REVOKE_SENSITIVE_PERMISSIONS";
static const std::string GET_SENSITIVE_PERMISSIONS = "ohos.permission.GET_SENSITIVE_PERMISSIONS";
static const std::string DISABLE_PERMISSION_DIALOG = "ohos.permission.DISABLE_PERMISSION_DIALOG";
static const unsigned int DEBUG_APP_FLAG = 0x0008;
static uint64_t g_selfShellTokenId = 0;

class OsAccountMockGuard final {
public:
    ~OsAccountMockGuard()
    {
        ResetMockOsAccountManagerLite();
    }
};

class PermissionRequestToggleStatusGuard final {
public:
    PermissionRequestToggleStatusGuard(int32_t userId, const std::string& permissionName)
        : userId_(userId), permissionName_(permissionName)
    {
        (void)PermissionRequestToggleManager::GetInstance().FindPermRequestToggleStatusRecordsFromDb(
            userId_, permissionName_, LEGACY_SUBPROFILE_ID, originalRecords_);
        DeleteRecords({});
    }

    ~PermissionRequestToggleStatusGuard()
    {
        DeleteRecords(originalRecords_);
    }

private:
    void DeleteRecords(const std::vector<GenericValues>& records)
    {
        GenericValues condition;
        condition.Put(TokenFiledConst::FIELD_USER_ID, userId_);
        condition.Put(TokenFiledConst::FIELD_PERMISSION_NAME, permissionName_);

        std::vector<DelInfo> delInfoVec;
        AccessTokenInfoUtils::GenerateDelInfoToVec(
            AtmDataType::ACCESSTOKEN_PERMISSION_REQUEST_TOGGLE_STATUS, condition, delInfoVec);
        std::vector<AddInfo> addInfoVec;
        AccessTokenInfoUtils::GenerateAddInfoToVec(
            AtmDataType::ACCESSTOKEN_PERMISSION_REQUEST_TOGGLE_STATUS, records, addInfoVec);
        (void)AccessTokenDbOperator::DeleteAndInsertValues(delInfoVec, addInfoVec);
    }

    int32_t userId_;
    std::string permissionName_;
    std::vector<GenericValues> originalRecords_;
};

#ifdef SECURITY_COMPONENT_ENHANCE_ENABLE
void ResetSecCompEnhanceKey()
{
    auto& agent = SecCompEnhanceAgent::GetInstance();
    std::lock_guard<std::mutex> lock(agent.secCompEnhanceKeyMutex_);
    (void)memset_s(agent.secCompEnhanceKey_.key.data, MAX_HMAC_SIZE, 0, MAX_HMAC_SIZE);
    agent.secCompEnhanceKey_.key.size = 0;
    agent.secCompEnhanceKey_.epoch = 0;
    agent.hasSecCompEnhanceKey_ = false;
}

SecCompEnhanceKeyIdl BuildSecCompEnhanceKeyIdl(uint64_t epoch, uint8_t value)
{
    SecCompEnhanceKeyIdl enhanceKey;
    enhanceKey.epoch = epoch;
    enhanceKey.key.assign(MAX_HMAC_SIZE, value);
    return enhanceKey;
}
#endif

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

uint64_t CreateServiceTestHapToken(
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

std::vector<CliInfoIdl> BuildCliInfoIdls()
{
    return {{ .cliName = "camera", .subCliName = "capture" }};
}

std::vector<CliInfoIdl> BuildMixedDialogCliInfoIdls()
{
    return {
        { .cliName = "location", .subCliName = "query" },
        { .cliName = "camera", .subCliName = "capture" },
    };
}

std::vector<CliInfoIdl> BuildUnknownCliInfoIdls()
{
    return {{ .cliName = "unknown", .subCliName = "cmd" }};
}

std::vector<CliInfoIdl> BuildMissingMappingCliInfoIdls()
{
    return {{ .cliName = "missingmap", .subCliName = "run" }};
}

std::vector<CliInfoIdl> BuildEmptyPermissionCliInfoIdls()
{
    return {{ .cliName = "empty", .subCliName = "run" }};
}

PermissionStatus BuildBundleClearPermStatus(const std::string& permissionName)
{
    return {
        .permissionName = permissionName,
        .grantStatus = PermissionState::PERMISSION_DENIED,
        .grantFlag = PermissionFlag::PERMISSION_DEFAULT_FLAG
    };
}

AccessTokenIDEx CreateBundleClearHapToken(
    const std::string& bundleName, int32_t instIndex, const std::string& provisionType)
{
    HapInfoParams hapInfo = {
        .userID = USER_ID,
        .bundleName = bundleName,
        .instIndex = instIndex,
        .dlpType = static_cast<int>(HapDlpType::DLP_COMMON),
        .apiVersion = API_VERSION_9,
        .isSystemApp = false,
        .appIDDesc = bundleName,
        .appProvisionType = provisionType
    };
    HapPolicy hapPolicy = {
        .apl = APL_NORMAL,
        .domain = "test.domain",
        .permStateList = {
            BuildBundleClearPermStatus("ohos.permission.CAMERA"),
            BuildBundleClearPermStatus("ohos.permission.MICROPHONE")
        }
    };

    AccessTokenIDEx tokenIdEx = {0};
    std::vector<GenericValues> undefValues;
    EXPECT_EQ(RET_SUCCESS, AccessTokenInfoManager::GetInstance().CreateHapTokenInfo(
        hapInfo, hapPolicy, tokenIdEx, undefValues));
    EXPECT_NE(INVALID_TOKENID, tokenIdEx.tokenIdExStruct.tokenID);
    return tokenIdEx;
}

void SetCameraMicrophoneUserFixedStateByService(AccessTokenID tokenID)
{
    ASSERT_EQ(RET_SUCCESS, PermissionManager::GetInstance().GrantPermission(
        tokenID, "ohos.permission.CAMERA", PERMISSION_USER_FIXED));
    ASSERT_EQ(RET_SUCCESS, PermissionManager::GetInstance().RevokePermission(
        tokenID, "ohos.permission.MICROPHONE", PERMISSION_USER_FIXED));
    ASSERT_EQ(RET_SUCCESS, AccessTokenInfoManager::GetInstance().SetPermDialogCap(tokenID, true));
    ASSERT_TRUE(AccessTokenInfoManager::GetInstance().GetPermDialogCap(tokenID));
}

void AssertCameraMicrophoneCanShowDialog(
    const std::shared_ptr<AccessTokenManagerService>& service, AccessTokenIDEx tokenIdEx)
{
    PermissionListStateParcel cameraState;
    cameraState.permsState.permissionName = "ohos.permission.CAMERA";
    PermissionListStateParcel microphoneState;
    microphoneState.permsState.permissionName = "ohos.permission.MICROPHONE";
    std::vector<PermissionListStateParcel> reqPermList = {cameraState, microphoneState};
    PermissionGrantInfoParcel infoParcel;
    int32_t permOper = INVALID_OPER;

    uint64_t selfTokenId = GetSelfTokenID();
    int32_t setRet = SetSelfTokenID(tokenIdEx.tokenIDEx);
    int32_t ret = service->GetSelfPermissionsState(reqPermList, infoParcel, permOper);
    int32_t restoreRet = SetSelfTokenID(selfTokenId);

    ASSERT_EQ(RET_SUCCESS, setRet);
    ASSERT_EQ(RET_SUCCESS, restoreRet);
    ASSERT_EQ(RET_SUCCESS, ret);
    ASSERT_EQ(DYNAMIC_OPER, permOper);
    ASSERT_EQ(DYNAMIC_OPER, reqPermList[0].permsState.state);
    ASSERT_EQ(DYNAMIC_OPER, reqPermList[1].permsState.state);
}

uint64_t SetShellCallerByTest()
{
    uint64_t selfTokenId = GetSelfTokenID();
    EXPECT_NE(INVALID_TOKENID, g_selfShellTokenId);
    EXPECT_EQ(RET_SUCCESS, SetSelfTokenID(g_selfShellTokenId));
    return selfTokenId;
}

void RestoreCallerByTest(uint64_t selfTokenId)
{
    EXPECT_EQ(RET_SUCCESS, SetSelfTokenID(selfTokenId));
}

void DeleteBundleClearToken(AccessTokenID tokenID)
{
    if (tokenID != INVALID_TOKENID) {
        (void)AccessTokenInfoManager::GetInstance().RemoveHapTokenInfo(tokenID);
    }
}
}

void AccessTokenManagerServiceTest::SetUpTestCase()
{
    g_selfShellTokenId = GetSelfTokenID();
    TestCommon::SetTestEvironment(g_selfShellTokenId);
}

void AccessTokenManagerServiceTest::TearDownTestCase()
{
    TestCommon::ResetTestEvironment();
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
    uint64_t selfTokenId = GetSelfTokenID();
    AccessTokenID shellTokenId = AccessTokenIDManager::GetInstance().CreateAndRegisterTokenId(TOKEN_SHELL, 0, 0, 0);
    ASSERT_NE(INVALID_TOKENID, shellTokenId);
    ASSERT_EQ(TOKEN_SHELL, AccessTokenIDManager::GetInstance().GetTokenIdType(shellTokenId));
    SetSelfTokenID(shellTokenId);

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
    SetSelfTokenID(selfTokenId);
    AccessTokenIDManager::GetInstance().ReleaseTokenId(shellTokenId);
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

class RecordingCbCustomizeTest : public PermStateChangeCallbackCustomize {
public:
    explicit RecordingCbCustomizeTest(const PermStateChangeScope& scopeInfo)
        : PermStateChangeCallbackCustomize(scopeInfo)
    {}

    ~RecordingCbCustomizeTest() override = default;

    void PermStateChangeCallback(PermStateChangeInfo& result) override
    {
        ready_ = true;
        lastInfo_ = result;
    }

    bool ready_ = false;
    PermStateChangeInfo lastInfo_ = {};
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
 * @tc.name: GetPermissionStatusDetailsServiceTest001
 * @tc.desc: Test GetPermissionStatusDetails returns param invalid for invalid tokenId and oversize list.
 * @tc.require:
 * @tc.type: FUNC
 */
HWTEST_F(AccessTokenManagerServiceTest, GetPermissionStatusDetailsServiceTest001, TestSize.Level1)
{
    std::vector<PermissionStatusDetailIdl> resultList;
    EXPECT_EQ(ERR_PARAM_INVALID,
        atManagerService_->GetPermissionStatusDetails(INVALID_TOKENID, {"ohos.permission.LOCATION"}, resultList));
    EXPECT_TRUE(resultList.empty());

    std::vector<std::string> permissionList(MAX_PERMISSION_SIZE + 1, "ohos.permission.LOCATION");
    EXPECT_EQ(ERR_PARAM_INVALID,
        atManagerService_->GetPermissionStatusDetails(RANDOM_TOKENID, permissionList, resultList));
    EXPECT_TRUE(resultList.empty());
}

/**
 * @tc.name: GetPermissionStatusDetailsServiceTest002
 * @tc.desc: Test GetPermissionStatusDetails checks invalid param before caller permission.
 * @tc.require:
 * @tc.type: FUNC
 */
HWTEST_F(AccessTokenManagerServiceTest, GetPermissionStatusDetailsServiceTest002, TestSize.Level1)
{
    AccessTokenID tokenId = INVALID_TOKENID;
    uint64_t fullTokenId = CreateServiceTestHapToken("permission_detail_non_system_test", false, {}, tokenId);
    ASSERT_NE(0, fullTokenId);
    SetSelfTokenID(fullTokenId);

    std::vector<PermissionStatusDetailIdl> resultList;
    EXPECT_EQ(ERR_PARAM_INVALID, atManagerService_->GetPermissionStatusDetails(tokenId, {}, resultList));
    EXPECT_TRUE(resultList.empty());

    SetSelfTokenID(g_selfShellTokenId);
    (void)AccessTokenInfoManager::GetInstance().RemoveHapTokenInfo(tokenId);
}

/**
 * @tc.name: GetPermissionStatusDetailsServiceTest003
 * @tc.desc: Test GetPermissionStatusDetails returns token not exist for render token.
 * @tc.require:
 * @tc.type: FUNC
 */
HWTEST_F(AccessTokenManagerServiceTest, GetPermissionStatusDetailsServiceTest003, TestSize.Level1)
{
    MockNativeToken mock("foundation");
    AccessTokenID tokenId = INVALID_TOKENID;
    uint64_t fullTokenId = CreateServiceTestHapToken("permission_detail_render_token_test", true, {}, tokenId);
    ASSERT_NE(0, fullTokenId);
    AccessTokenID renderTokenId = static_cast<AccessTokenID>(AccessTokenKit::GetRenderTokenID(tokenId));
    ASSERT_NE(INVALID_TOKENID, renderTokenId);

    std::vector<PermissionStatusDetailIdl> resultList;
    EXPECT_EQ(ERR_TOKENID_NOT_EXIST,
        atManagerService_->GetPermissionStatusDetails(renderTokenId, {"ohos.permission.LOCATION"}, resultList));
    EXPECT_TRUE(resultList.empty());

    (void)AccessTokenInfoManager::GetInstance().RemoveHapTokenInfo(tokenId);
}

/**
 * @tc.name: GetPermissionStatusDetailsServiceTest004
 * @tc.desc: Test GetPermissionStatusDetails returns ERR_SERVICE_ABNORMAL when requested permission cache is missing.
 * @tc.require:
 * @tc.type: FUNC
 */
HWTEST_F(AccessTokenManagerServiceTest, GetPermissionStatusDetailsServiceTest004, TestSize.Level1)
{
    MockNativeToken mock("foundation");
    AccessTokenID tokenId = INVALID_TOKENID;
    uint64_t fullTokenId = CreateServiceTestHapToken("permission_detail_missing_brief_test", true,
        {BuildGrantedPermissionStatus("ohos.permission.LOCATION")}, tokenId);
    ASSERT_NE(0, fullTokenId);

    ASSERT_EQ(RET_SUCCESS, PermissionDataBrief::GetInstance().DeleteBriefPermDataByTokenId(tokenId));

    std::vector<PermissionStatusDetailIdl> resultList;
    int32_t ret = atManagerService_->GetPermissionStatusDetails(tokenId, {"ohos.permission.LOCATION"}, resultList);
    EXPECT_EQ(ERR_SERVICE_ABNORMAL, ret);
    EXPECT_TRUE(resultList.empty());

    (void)AccessTokenInfoManager::GetInstance().RemoveHapTokenInfo(tokenId);
}

/**
 * @tc.name: ClawPermissionServiceTest001
 * @tc.desc: Test CLAW permission service APIs with empty list params.
 * @tc.require:
 * @tc.type: FUNC
 */
HWTEST_F(AccessTokenManagerServiceTest, ClawPermissionServiceTest001, TestSize.Level1)
{
    PermissionDialogResultIdl dialogResult;
    EXPECT_EQ(AccessTokenError::ERR_PARAM_INVALID,
        atManagerService_->GetCliPermissionRequestInfo(
            DEFAULT_AGENT_ID, std::vector<CliInfoIdl> {}, dialogResult));

    CliPermissionsResultIdl cliPermissionsResult;
    EXPECT_EQ(AccessTokenError::ERR_PARAM_INVALID,
        atManagerService_->GetCliPermissions(
            INVALID_TOKENID, DEFAULT_AGENT_ID, BuildCliInfoIdls(), cliPermissionsResult));
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
    uint64_t fullTokenId = CreateServiceTestHapToken("claw_permission_non_system_test", false, {}, tokenId);
    ASSERT_NE(0, fullTokenId);
    SetSelfTokenID(fullTokenId);

    PermissionDialogResultIdl dialogResult;
    EXPECT_EQ(AccessTokenError::ERR_NOT_SYSTEM_APP,
        atManagerService_->GetCliPermissionRequestInfo(DEFAULT_AGENT_ID, BuildCliInfoIdls(), dialogResult));

    CliPermissionsResultIdl cliPermissionsResult;
    EXPECT_EQ(AccessTokenError::ERR_NOT_SYSTEM_APP,
        atManagerService_->GetCliPermissions(
            tokenId, DEFAULT_AGENT_ID, BuildCliInfoIdls(), cliPermissionsResult));

    SetSelfTokenID(g_selfShellTokenId);
    (void)AccessTokenInfoManager::GetInstance().RemoveHapTokenInfo(tokenId);
}

/**
 * @tc.name: ClawPermissionServiceTest004
 * @tc.desc: Test CLAW permission service APIs reject system callers without required interface permission.
 * @tc.require:
 * @tc.type: FUNC
 */
HWTEST_F(AccessTokenManagerServiceTest, ClawPermissionServiceTest004, TestSize.Level1)
{
    AccessTokenID tokenId = INVALID_TOKENID;
    uint64_t fullTokenId = CreateServiceTestHapToken("claw_permission_no_api_permission_test", true, {}, tokenId);
    ASSERT_NE(0, fullTokenId);
    SetSelfTokenID(fullTokenId);

    PermissionDialogResultIdl dialogResult;
    EXPECT_EQ(AccessTokenError::ERR_PERMISSION_DENIED,
        atManagerService_->GetCliPermissionRequestInfo(DEFAULT_AGENT_ID, BuildCliInfoIdls(), dialogResult));

    CliPermissionsResultIdl cliPermissionsResult;
    EXPECT_EQ(AccessTokenError::ERR_PERMISSION_DENIED,
        atManagerService_->GetCliPermissions(
            tokenId, DEFAULT_AGENT_ID, BuildCliInfoIdls(), cliPermissionsResult));

    CliAuthInfoIdl cliAuthInfoIdl;
    cliAuthInfoIdl.cliInfo = BuildCliInfoIdls()[0];
    cliAuthInfoIdl.permissionNames = {"ohos.permission.POWER_MANAGER"};
    cliAuthInfoIdl.authorizationResults = {false};
    ToolAuthResultIdl authResult;
    EXPECT_EQ(AccessTokenError::ERR_PERMISSION_DENIED,
        atManagerService_->GenerateCliAuthResult(tokenId, DEFAULT_AGENT_ID, {cliAuthInfoIdl}, authResult));

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
    uint64_t fullTokenId = CreateServiceTestHapToken(
        "claw_permission_system_service_test", true, permStates, tokenId);
    ASSERT_NE(0, fullTokenId);
    SetSelfTokenID(fullTokenId);

    PermissionDialogResultIdl dialogResult;
    ASSERT_EQ(RET_SUCCESS,
        atManagerService_->GetCliPermissionRequestInfo(DEFAULT_AGENT_ID, BuildCliInfoIdls(), dialogResult));
    ASSERT_EQ(1, static_cast<int32_t>(dialogResult.detailList.size()));
    EXPECT_FALSE(dialogResult.detailList[0].needPermissionDialog);
    EXPECT_FALSE(dialogResult.detailList[0].authResult.empty());

    CliPermissionsResultIdl cliPermissionsResult;
    ASSERT_EQ(RET_SUCCESS,
        atManagerService_->GetCliPermissions(
            tokenId, DEFAULT_AGENT_ID, BuildCliInfoIdls(), cliPermissionsResult));
    ASSERT_EQ(1, static_cast<int32_t>(cliPermissionsResult.permList.size()));

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
    uint64_t fullTokenId = CreateServiceTestHapToken(
        "claw_permission_cli_challenge_test", true, BuildClawManagePermissionStates(), tokenId);
    ASSERT_NE(0, fullTokenId);
    SetSelfTokenID(fullTokenId);

    CliAuthInfoIdl invalidAuthInfoIdl;
    invalidAuthInfoIdl.cliInfo = BuildCliInfoIdls()[0];
    invalidAuthInfoIdl.permissionNames = {"ohos.permission.POWER_MANAGER"};
    ToolAuthResultIdl authResult;
    EXPECT_EQ(AccessTokenError::ERR_PARAM_INVALID,
        atManagerService_->GenerateCliAuthResult(tokenId, DEFAULT_AGENT_ID, {invalidAuthInfoIdl}, authResult));

    CliAuthInfoIdl authInfoIdl;
    authInfoIdl.cliInfo = BuildCliInfoIdls()[0];
    authInfoIdl.permissionNames = {"ohos.permission.POWER_MANAGER"};
    authInfoIdl.authorizationResults = {false};
    ASSERT_EQ(RET_SUCCESS,
        atManagerService_->GenerateCliAuthResult(tokenId, DEFAULT_AGENT_ID, {authInfoIdl}, authResult));
    ASSERT_EQ(1, static_cast<int32_t>(authResult.authResults.size()));
    EXPECT_FALSE(authResult.authResults[0].empty());

    CliAuthInfoIdl emptyAuthInfoIdl;
    emptyAuthInfoIdl.cliInfo = BuildEmptyPermissionCliInfoIdls()[0];
    ASSERT_EQ(RET_SUCCESS,
        atManagerService_->GenerateCliAuthResult(tokenId, DEFAULT_AGENT_ID, {emptyAuthInfoIdl}, authResult));
    ASSERT_EQ(1, static_cast<int32_t>(authResult.authResults.size()));
    EXPECT_FALSE(authResult.authResults[0].empty());

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
    uint64_t fullTokenId = CreateServiceTestHapToken(
        "claw_permission_cli_undeclared_test", true, BuildClawQueryAndManagePermissionStates(), tokenId);
    ASSERT_NE(0, fullTokenId);
    SetSelfTokenID(fullTokenId);

    PermissionDialogResultIdl dialogResult;
    ASSERT_EQ(RET_SUCCESS,
        atManagerService_->GetCliPermissionRequestInfo(DEFAULT_AGENT_ID, BuildCliInfoIdls(), dialogResult));
    ASSERT_EQ(1, static_cast<int32_t>(dialogResult.detailList.size()));
    EXPECT_FALSE(dialogResult.detailList[0].needPermissionDialog);
    ASSERT_EQ(1, static_cast<int32_t>(dialogResult.detailList[0].permissionNameList.size()));
    EXPECT_EQ("ohos.permission.POWER_MANAGER", dialogResult.detailList[0].permissionNameList[0]);
    ASSERT_EQ(1, static_cast<int32_t>(dialogResult.detailList[0].statusList.size()));
    EXPECT_EQ(PermissionDecisionStatusIdl::NO_DIALOG_NOT_DECLARED,
        dialogResult.detailList[0].statusList[0]);
    EXPECT_TRUE(dialogResult.detailList[0].authResult.empty());

    CliPermissionsResultIdl cliPermissionsResult;
    ASSERT_EQ(RET_SUCCESS,
        atManagerService_->GetCliPermissions(
            tokenId, DEFAULT_AGENT_ID, BuildCliInfoIdls(), cliPermissionsResult));
    ASSERT_EQ(1, static_cast<int32_t>(cliPermissionsResult.permList.size()));
    const auto& detail = cliPermissionsResult.permList[0].requiredCliPermissions[0];
    EXPECT_EQ(PermissionDecisionStatusIdl::NO_DIALOG_NOT_DECLARED, detail.cliPermissionStatus);
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
    uint64_t fullTokenId = CreateServiceTestHapToken(
        "claw_permission_cli_denied_status_test", true, permStates, tokenId);
    ASSERT_NE(0, fullTokenId);
    SetSelfTokenID(fullTokenId);

    PermissionDialogResultIdl dialogResult;
    ASSERT_EQ(RET_SUCCESS,
        atManagerService_->GetCliPermissionRequestInfo(DEFAULT_AGENT_ID, BuildCliInfoIdls(), dialogResult));
    ASSERT_EQ(1, static_cast<int32_t>(dialogResult.detailList.size()));
    ASSERT_EQ(1, static_cast<int32_t>(dialogResult.detailList[0].statusList.size()));
    EXPECT_EQ(PermissionDecisionStatusIdl::NO_DIALOG_DENIED, dialogResult.detailList[0].statusList[0]);

    CliPermissionsResultIdl cliPermissionsResult;
    ASSERT_EQ(RET_SUCCESS,
        atManagerService_->GetCliPermissions(
            tokenId, DEFAULT_AGENT_ID, BuildCliInfoIdls(), cliPermissionsResult));
    ASSERT_EQ(1, static_cast<int32_t>(cliPermissionsResult.permList.size()));
    const auto& detail = cliPermissionsResult.permList[0].requiredCliPermissions[0];
    EXPECT_EQ(PermissionDecisionStatusIdl::NO_DIALOG_DENIED, detail.cliPermissionStatus);
    ASSERT_EQ(1, static_cast<int32_t>(detail.usedPermissions.size()));

    SetSelfTokenID(g_selfShellTokenId);
    (void)AccessTokenInfoManager::GetInstance().RemoveHapTokenInfo(tokenId);
}

/**
 * @tc.name: ClawPermissionServiceTest008
 * @tc.desc: Test CLI dialog challenge is generated only for details without permission dialog.
 * @tc.require:
 * @tc.type: FUNC
 */
HWTEST_F(AccessTokenManagerServiceTest, ClawPermissionServiceTest008, TestSize.Level1)
{
    PermissionStatus cliCameraState = {
        .permissionName = "ohos.permission.POWER_MANAGER",
        .grantStatus = PermissionState::PERMISSION_GRANTED,
        .grantFlag = PermissionFlag::PERMISSION_USER_SET
    };
    auto permStates = BuildClawQueryPermissionStates();
    permStates.emplace_back(cliCameraState);
    AccessTokenID tokenId = INVALID_TOKENID;
    uint64_t fullTokenId = CreateServiceTestHapToken(
        "claw_permission_cli_mixed_dialog_test", true, permStates, tokenId);
    ASSERT_NE(0, fullTokenId);
    SetSelfTokenID(fullTokenId);

    PermissionDialogResultIdl dialogResult;
    ASSERT_EQ(RET_SUCCESS,
        atManagerService_->GetCliPermissionRequestInfo(
            DEFAULT_AGENT_ID, BuildMixedDialogCliInfoIdls(), dialogResult));
    ASSERT_EQ(2, static_cast<int32_t>(dialogResult.detailList.size()));

    const auto& locationDetail = dialogResult.detailList[0];
    EXPECT_FALSE(locationDetail.needPermissionDialog);
    EXPECT_TRUE(locationDetail.authResult.empty());

    const auto& cameraDetail = dialogResult.detailList[1];
    EXPECT_FALSE(cameraDetail.needPermissionDialog);
    EXPECT_FALSE(cameraDetail.authResult.empty());

    SetSelfTokenID(g_selfShellTokenId);
    (void)AccessTokenInfoManager::GetInstance().RemoveHapTokenInfo(tokenId);
}

/**
 * @tc.name: ClawPermissionServiceTest009
 * @tc.desc: Test CLI dialog query returns ERR_QUERY_PERMISSION_FAILED when metadata queryRet is not success.
 * @tc.require:
 * @tc.type: FUNC
 */
HWTEST_F(AccessTokenManagerServiceTest, ClawPermissionServiceTest009, TestSize.Level1)
{
    AccessTokenID tokenId = INVALID_TOKENID;
    uint64_t fullTokenId = CreateServiceTestHapToken(
        "claw_permission_cli_validate_error_test", true, BuildClawQueryAndManagePermissionStates(), tokenId);
    ASSERT_NE(0, fullTokenId);
    SetSelfTokenID(fullTokenId);

    PermissionDialogResultIdl dialogResult;
    ASSERT_EQ(AccessTokenError::ERR_QUERY_PERMISSION_FAILED,
        atManagerService_->GetCliPermissionRequestInfo(
            DEFAULT_AGENT_ID, BuildUnknownCliInfoIdls(), dialogResult));

    CliPermissionsResultIdl cliPermissionsResult;
    ASSERT_EQ(AccessTokenError::ERR_QUERY_PERMISSION_FAILED,
        atManagerService_->GetCliPermissions(
            tokenId, DEFAULT_AGENT_ID, BuildUnknownCliInfoIdls(), cliPermissionsResult));

    SetSelfTokenID(g_selfShellTokenId);
    (void)AccessTokenInfoManager::GetInstance().RemoveHapTokenInfo(tokenId);
}

/**
 * @tc.name: ClawPermissionServiceTest010
 * @tc.desc: Test CLI dialog query returns error when CLI permission has no mapping and no definition.
 * @tc.require:
 * @tc.type: FUNC
 */
HWTEST_F(AccessTokenManagerServiceTest, ClawPermissionServiceTest010, TestSize.Level1)
{
    AccessTokenID tokenId = INVALID_TOKENID;
    uint64_t fullTokenId = CreateServiceTestHapToken(
        "claw_permission_cli_build_error_test", true, BuildClawQueryPermissionStates(), tokenId);
    ASSERT_NE(0, fullTokenId);
    SetSelfTokenID(fullTokenId);

    PermissionDialogResultIdl dialogResult;
    ASSERT_EQ(AccessTokenError::ERR_PERMISSION_NOT_EXIST,
        atManagerService_->GetCliPermissionRequestInfo(
            DEFAULT_AGENT_ID, BuildMissingMappingCliInfoIdls(), dialogResult));

    SetSelfTokenID(g_selfShellTokenId);
    (void)AccessTokenInfoManager::GetInstance().RemoveHapTokenInfo(tokenId);
}

/**
 * @tc.name: ClawPermissionServiceTest011
 * @tc.desc: Test CLI without required permissions does not require dialog or permission mapping.
 * @tc.require:
 * @tc.type: FUNC
 */
HWTEST_F(AccessTokenManagerServiceTest, ClawPermissionServiceTest011, TestSize.Level1)
{
    AccessTokenID tokenId = INVALID_TOKENID;
    uint64_t fullTokenId = CreateServiceTestHapToken(
        "claw_permission_cli_empty_permission_test", true, BuildClawQueryAndManagePermissionStates(), tokenId);
    ASSERT_NE(0, fullTokenId);
    SetSelfTokenID(fullTokenId);

    PermissionDialogResultIdl dialogResult;
    ASSERT_EQ(RET_SUCCESS,
        atManagerService_->GetCliPermissionRequestInfo(
            DEFAULT_AGENT_ID, BuildEmptyPermissionCliInfoIdls(), dialogResult));
    ASSERT_EQ(1, static_cast<int32_t>(dialogResult.detailList.size()));
    EXPECT_FALSE(dialogResult.detailList[0].needPermissionDialog);
    EXPECT_TRUE(dialogResult.detailList[0].permissionNameList.empty());
    EXPECT_TRUE(dialogResult.detailList[0].statusList.empty());
    EXPECT_FALSE(dialogResult.detailList[0].authResult.empty());

    CliPermissionsResultIdl cliPermissionsResult;
    ASSERT_EQ(RET_SUCCESS,
        atManagerService_->GetCliPermissions(
            tokenId, DEFAULT_AGENT_ID, BuildEmptyPermissionCliInfoIdls(), cliPermissionsResult));
    ASSERT_EQ(1, static_cast<int32_t>(cliPermissionsResult.permList.size()));
    EXPECT_TRUE(cliPermissionsResult.permList[0].requiredCliPermissions.empty());

    SetSelfTokenID(g_selfShellTokenId);
    (void)AccessTokenInfoManager::GetInstance().RemoveHapTokenInfo(tokenId);
}

/**
 * @tc.name: ClawPermissionServiceTest012
 * @tc.desc: Test token challenge generates challenge even if authorized permission does not exist.
 * @tc.require:
 * @tc.type: FUNC
 */
HWTEST_F(AccessTokenManagerServiceTest, ClawPermissionServiceTest012, TestSize.Level1)
{
    AccessTokenID tokenId = INVALID_TOKENID;
    uint64_t fullTokenId = CreateServiceTestHapToken(
        "claw_permission_cli_no_grant_test", true, BuildClawManagePermissionStates(), tokenId);
    ASSERT_NE(0, fullTokenId);
    SetSelfTokenID(fullTokenId);

    CliAuthInfoIdl authInfoIdl;
    authInfoIdl.cliInfo = BuildCliInfoIdls()[0];
    authInfoIdl.permissionNames = {"ohos.permission.POWER_MANAGER"};
    authInfoIdl.authorizationResults = {true};
    ToolAuthResultIdl authResult;
    ASSERT_EQ(RET_SUCCESS,
        atManagerService_->GenerateCliAuthResult(tokenId, DEFAULT_AGENT_ID, {authInfoIdl}, authResult));
    ASSERT_EQ(1, static_cast<int32_t>(authResult.authResults.size()));
    EXPECT_FALSE(authResult.authResults[0].empty());

    SetSelfTokenID(g_selfShellTokenId);
    (void)AccessTokenInfoManager::GetInstance().RemoveHapTokenInfo(tokenId);
}

/**
 * @tc.name: ClawPermissionServiceTest013
 * @tc.desc: Test multiple CLI auth info generates auth results in auth info order.
 * @tc.require:
 * @tc.type: FUNC
 */
HWTEST_F(AccessTokenManagerServiceTest, ClawPermissionServiceTest013, TestSize.Level1)
{
    AccessTokenID tokenId = INVALID_TOKENID;
    uint64_t fullTokenId = CreateServiceTestHapToken(
        "claw_permission_cli_challenge_order_test", true, BuildClawManagePermissionStates(), tokenId);
    ASSERT_NE(0, fullTokenId);
    SetSelfTokenID(fullTokenId);

    CliAuthInfoIdl cameraAuthInfoIdl;
    cameraAuthInfoIdl.cliInfo = BuildCliInfoIdls()[0];
    cameraAuthInfoIdl.permissionNames = {"ohos.permission.POWER_MANAGER"};
    cameraAuthInfoIdl.authorizationResults = {false};

    CliAuthInfoIdl locationAuthInfoIdl;
    locationAuthInfoIdl.cliInfo = {
        .cliName = "location",
        .subCliName = "query"
    };
    locationAuthInfoIdl.permissionNames = {"ohos.permission.APPROXIMATELY_LOCATION"};
    locationAuthInfoIdl.authorizationResults = {false};

    ToolAuthResultIdl authResult;
    ASSERT_EQ(RET_SUCCESS, atManagerService_->GenerateCliAuthResult(
        tokenId, DEFAULT_AGENT_ID, {cameraAuthInfoIdl, locationAuthInfoIdl}, authResult));
    ASSERT_EQ(2, static_cast<int32_t>(authResult.authResults.size()));
    EXPECT_FALSE(authResult.authResults[0].empty());
    EXPECT_FALSE(authResult.authResults[1].empty());
    EXPECT_NE(authResult.authResults[0], authResult.authResults[1]);

    SetSelfTokenID(g_selfShellTokenId);
    (void)AccessTokenInfoManager::GetInstance().RemoveHapTokenInfo(tokenId);
}

/**
 * @tc.name: ClawPermissionServiceTest014
 * @tc.desc: Test CLI auth result expands CLI permission to mapped system permissions before ticket generation.
 * @tc.require:
 * @tc.type: FUNC
 */
HWTEST_F(AccessTokenManagerServiceTest, ClawPermissionServiceTest014, TestSize.Level1)
{
    AccessTokenID tokenId = INVALID_TOKENID;
    uint64_t fullTokenId = CreateServiceTestHapToken(
        "claw_permission_cli_expand_used_permissions_test", true, BuildClawManagePermissionStates(), tokenId);
    ASSERT_NE(0, fullTokenId);
    SetSelfTokenID(fullTokenId);

    CliAuthInfoIdl authInfoIdl;
    authInfoIdl.cliInfo = {
        .cliName = "location",
        .subCliName = "query"
    };
    authInfoIdl.permissionNames = {"ohos.permission.APPROXIMATELY_LOCATION"};
    authInfoIdl.authorizationResults = {true};
    ToolAuthResultIdl authResult;
    ASSERT_EQ(RET_SUCCESS,
        atManagerService_->GenerateCliAuthResult(tokenId, DEFAULT_AGENT_ID, {authInfoIdl}, authResult));
    ASSERT_EQ(1, static_cast<int32_t>(authResult.authResults.size()));
    EXPECT_FALSE(authResult.authResults[0].empty());

    std::vector<PermissionStatus> permList;
    ASSERT_EQ(RET_SUCCESS, ClawTicketManager::GetInstance().VerifyCliClawTicket(
        tokenId, authResult.authResults[0],
        { .cliName = authInfoIdl.cliInfo.cliName, .subCliName = authInfoIdl.cliInfo.subCliName }, permList));
    ASSERT_EQ(2, static_cast<int32_t>(permList.size()));
    EXPECT_EQ("ohos.permission.LOCATION", permList[0].permissionName);
    EXPECT_EQ(PERMISSION_GRANTED, permList[0].grantStatus);
    EXPECT_EQ("ohos.permission.APPROXIMATELY_LOCATION", permList[1].permissionName);
    EXPECT_EQ(PERMISSION_GRANTED, permList[1].grantStatus);

    SetSelfTokenID(g_selfShellTokenId);
    (void)AccessTokenInfoManager::GetInstance().RemoveHapTokenInfo(tokenId);
}

/**
 * @tc.name: ClawPermissionServiceTest015
 * @tc.desc: Test host granted system permission is not downgraded by CLI authorization result.
 * @tc.require:
 * @tc.type: FUNC
 */
HWTEST_F(AccessTokenManagerServiceTest, ClawPermissionServiceTest015, TestSize.Level1)
{
    PermissionStatus cliState = {
        .permissionName = "ohos.permission.POWER_MANAGER",
        .grantStatus = PermissionState::PERMISSION_GRANTED,
        .grantFlag = PermissionFlag::PERMISSION_USER_SET
    };
    auto permStates = BuildClawManagePermissionStates();
    permStates.emplace_back(cliState);
    AccessTokenID tokenId = INVALID_TOKENID;
    uint64_t fullTokenId = CreateServiceTestHapToken(
        "claw_permission_cli_keep_granted_system_permission_test", true, permStates, tokenId);
    ASSERT_NE(0, fullTokenId);
    SetSelfTokenID(fullTokenId);

    CliAuthInfoIdl authInfoIdl;
    authInfoIdl.cliInfo = BuildCliInfoIdls()[0];
    authInfoIdl.permissionNames = {"ohos.permission.POWER_MANAGER"};
    authInfoIdl.authorizationResults = {false};
    ToolAuthResultIdl authResult;
    ASSERT_EQ(RET_SUCCESS,
        atManagerService_->GenerateCliAuthResult(tokenId, DEFAULT_AGENT_ID, {authInfoIdl}, authResult));
    ASSERT_EQ(1, static_cast<int32_t>(authResult.authResults.size()));
    EXPECT_FALSE(authResult.authResults[0].empty());

    std::vector<PermissionStatus> permList;
    ASSERT_EQ(RET_SUCCESS, ClawTicketManager::GetInstance().VerifyCliClawTicket(
        tokenId, authResult.authResults[0],
        { .cliName = authInfoIdl.cliInfo.cliName, .subCliName = authInfoIdl.cliInfo.subCliName }, permList));
    ASSERT_EQ(1, static_cast<int32_t>(permList.size()));
    EXPECT_EQ("ohos.permission.POWER_MANAGER", permList[0].permissionName);
    EXPECT_EQ(PERMISSION_GRANTED, permList[0].grantStatus);

    SetSelfTokenID(g_selfShellTokenId);
    (void)AccessTokenInfoManager::GetInstance().RemoveHapTokenInfo(tokenId);
}

#ifdef SUPPORT_MANAGE_USER_POLICY
/**
 * @tc.name: UserPolicyServiceTest001
 * @tc.desc: Test SetUserPolicy service list size validation.
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(AccessTokenManagerServiceTest, UserPolicyServiceTest001, TestSize.Level1)
{
    EXPECT_EQ(ERR_PARAM_INVALID, atManagerService_->SetUserPolicy({}));
    constexpr int32_t MAX_SET_USER_POLICY_SIZE = 200;

    std::vector<UserPermissionPolicyIdl> userPermissionList(MAX_SET_USER_POLICY_SIZE + 1);
    EXPECT_EQ(ERR_PARAM_INVALID, atManagerService_->SetUserPolicy(userPermissionList));
}

/**
 * @tc.name: UserPolicyServiceTest002
 * @tc.desc: Test ClearUserPolicy service list size validation.
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(AccessTokenManagerServiceTest, UserPolicyServiceTest002, TestSize.Level1)
{
    EXPECT_EQ(ERR_PARAM_INVALID, atManagerService_->ClearUserPolicy({}));

    std::vector<std::string> permissionList(MAX_PERMISSION_SIZE + 1, "ohos.permission.INTERNET");
    EXPECT_EQ(ERR_OVERSIZE, atManagerService_->ClearUserPolicy(permissionList));
}

/**
 * @tc.name: UserPolicyServiceTest003
 * @tc.desc: Test SetUserPolicy and ClearUserPolicy service permission validation.
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(AccessTokenManagerServiceTest, UserPolicyServiceTest003, TestSize.Level1)
{
    AccessTokenID tokenId = INVALID_TOKENID;
    uint64_t fullTokenId = CreateServiceTestHapToken("user_policy_service_no_permission_test", true, {}, tokenId);
    ASSERT_NE(0, fullTokenId);
    SetSelfTokenID(fullTokenId);

    UserPermissionPolicyIdl userPolicyIdl;
    userPolicyIdl.permissionName = "ohos.permission.INTERNET";
    userPolicyIdl.userPolicyList = {{ .userId = USER_ID, .isRestricted = true }};
    std::vector<UserPermissionPolicyIdl> userPermissionList = { userPolicyIdl };
    EXPECT_EQ(ERR_PERMISSION_DENIED, atManagerService_->SetUserPolicy(userPermissionList));

    EXPECT_EQ(ERR_PERMISSION_DENIED, atManagerService_->ClearUserPolicy({ "ohos.permission.INTERNET" }));

    SetSelfTokenID(g_selfShellTokenId);
    (void)AccessTokenInfoManager::GetInstance().RemoveHapTokenInfo(tokenId);
}

/**
 * @tc.name: UserPolicyServiceTest004
 * @tc.desc: Test SetUserPolicy service idl conversion and permission state refresh.
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(AccessTokenManagerServiceTest, UserPolicyServiceTest004, TestSize.Level1)
{
    MockToken mock(g_selfShellTokenId, "accesstoken_service", false);
    mock.Grant(MANAGE_USER_POLICY);
    AccessTokenID tokenId = INVALID_TOKENID;
    uint64_t fullTokenId = CreateServiceTestHapToken("user_policy_service_convert_test", true,
        {
            BuildGrantedPermissionStatus("ohos.permission.INTERNET"),
            BuildGrantedPermissionStatus("ohos.permission.GET_NETWORK_STATS")
        }, tokenId);
    ASSERT_NE(0, fullTokenId);

    UserPermissionPolicyIdl userPolicyIdl;
    userPolicyIdl.permissionName = "ohos.permission.INTERNET";
    userPolicyIdl.isPersist = true;
    userPolicyIdl.userPolicyList = {{ .userId = USER_ID, .isRestricted = true }};
    UserPermissionPolicyIdl userPolicyIdl2 = userPolicyIdl;
    userPolicyIdl2.permissionName = "ohos.permission.GET_NETWORK_STATS";
    userPolicyIdl2.isPersist = false;
    userPolicyIdl2.userPolicyList = {{ .userId = USER_ID, .isRestricted = false }};

    EXPECT_EQ(RET_SUCCESS, atManagerService_->SetUserPolicy({ userPolicyIdl, userPolicyIdl2 }));
    EXPECT_EQ(PERMISSION_DENIED,
        AccessTokenInfoManager::GetInstance().VerifyAccessToken(tokenId, "ohos.permission.INTERNET"));
    EXPECT_EQ(PERMISSION_GRANTED,
        AccessTokenInfoManager::GetInstance().VerifyAccessToken(tokenId, "ohos.permission.GET_NETWORK_STATS"));

    EXPECT_EQ(RET_SUCCESS, atManagerService_->ClearUserPolicy({ "ohos.permission.INTERNET" }));
    EXPECT_EQ(PERMISSION_GRANTED,
        AccessTokenInfoManager::GetInstance().VerifyAccessToken(tokenId, "ohos.permission.INTERNET"));
    EXPECT_EQ(PERMISSION_GRANTED,
        AccessTokenInfoManager::GetInstance().VerifyAccessToken(tokenId, "ohos.permission.GET_NETWORK_STATS"));

    (void)AccessTokenInfoManager::GetInstance().RemoveHapTokenInfo(tokenId);
}

/**
 * @tc.name: UserPolicyServiceTest005
 * @tc.desc: Test SetPermissionStatusWithPolicy grant does not override active user policy restriction.
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(AccessTokenManagerServiceTest, UserPolicyServiceTest005, TestSize.Level1)
{
    MockToken mock(g_selfShellTokenId, "accesstoken_service", false);
    mock.Grant(MANAGE_USER_POLICY);
    mock.Grant(MANAGE_EDM_POLICY);
    AccessTokenID tokenId = INVALID_TOKENID;
    uint64_t fullTokenId = CreateServiceTestHapToken("user_policy_service_independent_test", true,
        {
            {
                .permissionName = "ohos.permission.MICROPHONE",
                .grantStatus = PermissionState::PERMISSION_GRANTED,
                .grantFlag = PermissionFlag::PERMISSION_USER_FIXED
            }
        }, tokenId);
    ASSERT_NE(0, fullTokenId);
    EXPECT_EQ(PERMISSION_GRANTED,
        AccessTokenInfoManager::GetInstance().VerifyAccessToken(tokenId, "ohos.permission.MICROPHONE"));

    UserPermissionPolicyIdl userPolicyIdl;
    userPolicyIdl.permissionName = "ohos.permission.MICROPHONE";
    userPolicyIdl.isPersist = false;
    userPolicyIdl.userPolicyList = {{ .userId = USER_ID, .isRestricted = true }};
    EXPECT_EQ(RET_SUCCESS, atManagerService_->SetUserPolicy({ userPolicyIdl }));
    EXPECT_EQ(PERMISSION_DENIED,
        AccessTokenInfoManager::GetInstance().VerifyAccessToken(tokenId, "ohos.permission.MICROPHONE"));

    EXPECT_EQ(RET_SUCCESS, atManagerService_->SetPermissionStatusWithPolicy(tokenId,
        { "ohos.permission.MICROPHONE" }, PERMISSION_GRANTED, PERMISSION_FIXED_BY_ADMIN_POLICY));
    EXPECT_EQ(PERMISSION_DENIED,
        AccessTokenInfoManager::GetInstance().VerifyAccessToken(tokenId, "ohos.permission.MICROPHONE"));

    EXPECT_EQ(RET_SUCCESS, atManagerService_->ClearUserPolicy({ "ohos.permission.MICROPHONE" }));
    EXPECT_EQ(PERMISSION_GRANTED,
        AccessTokenInfoManager::GetInstance().VerifyAccessToken(tokenId, "ohos.permission.MICROPHONE"));

    (void)AccessTokenInfoManager::GetInstance().RemoveHapTokenInfo(tokenId);
}

/**
 * @tc.name: UserPolicyServiceTest006
 * @tc.desc: Test active user policy restriction suppresses permission granted by SetPermissionStatusWithPolicy.
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(AccessTokenManagerServiceTest, UserPolicyServiceTest006, TestSize.Level1)
{
    MockToken mock(g_selfShellTokenId, "accesstoken_service", false);
    mock.Grant(MANAGE_USER_POLICY);
    mock.Grant(MANAGE_EDM_POLICY);
    AccessTokenID tokenId = INVALID_TOKENID;
    uint64_t fullTokenId = CreateServiceTestHapToken("user_policy_service_grant_then_restrict_test", true,
        {
            {
                .permissionName = "ohos.permission.MICROPHONE",
                .grantStatus = PermissionState::PERMISSION_DENIED,
                .grantFlag = PermissionFlag::PERMISSION_DEFAULT_FLAG
            }
        }, tokenId);
    ASSERT_NE(0, fullTokenId);
    EXPECT_EQ(PERMISSION_DENIED,
        AccessTokenInfoManager::GetInstance().VerifyAccessToken(tokenId, "ohos.permission.MICROPHONE"));

    EXPECT_EQ(RET_SUCCESS, atManagerService_->SetPermissionStatusWithPolicy(tokenId,
        { "ohos.permission.MICROPHONE" }, PERMISSION_GRANTED, PERMISSION_FIXED_BY_ADMIN_POLICY));
    EXPECT_EQ(PERMISSION_GRANTED,
        AccessTokenInfoManager::GetInstance().VerifyAccessToken(tokenId, "ohos.permission.MICROPHONE"));

    UserPermissionPolicyIdl userPolicyIdl;
    userPolicyIdl.permissionName = "ohos.permission.MICROPHONE";
    userPolicyIdl.isPersist = false;
    userPolicyIdl.userPolicyList = {{ .userId = USER_ID, .isRestricted = true }};
    EXPECT_EQ(RET_SUCCESS, atManagerService_->SetUserPolicy({ userPolicyIdl }));
    EXPECT_EQ(PERMISSION_DENIED,
        AccessTokenInfoManager::GetInstance().VerifyAccessToken(tokenId, "ohos.permission.MICROPHONE"));

    EXPECT_EQ(RET_SUCCESS, atManagerService_->ClearUserPolicy({ "ohos.permission.MICROPHONE" }));
    EXPECT_EQ(PERMISSION_GRANTED,
        AccessTokenInfoManager::GetInstance().VerifyAccessToken(tokenId, "ohos.permission.MICROPHONE"));

    (void)AccessTokenInfoManager::GetInstance().RemoveHapTokenInfo(tokenId);
}

/**
 * @tc.name: UserPolicyServiceTest007
 * @tc.desc: Test GrantPermission takes effect after active user policy restriction is cleared.
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(AccessTokenManagerServiceTest, UserPolicyServiceTest007, TestSize.Level1)
{
    MockToken mock(g_selfShellTokenId, "accesstoken_service", false);
    mock.Grant(MANAGE_USER_POLICY);
    mock.Grant(GRANT_SENSITIVE_PERMISSIONS);
    mock.Grant("ohos.permission.GET_SENSITIVE_PERMISSIONS");
    AccessTokenID tokenId = INVALID_TOKENID;
    uint64_t fullTokenId = CreateServiceTestHapToken("user_policy_service_grant_under_restrict_test", true,
        {
            {
                .permissionName = "ohos.permission.MICROPHONE",
                .grantStatus = PermissionState::PERMISSION_DENIED,
                .grantFlag = PermissionFlag::PERMISSION_DEFAULT_FLAG
            }
        }, tokenId);
    ASSERT_NE(0, fullTokenId);

    UserPermissionPolicyIdl userPolicyIdl;
    userPolicyIdl.permissionName = "ohos.permission.MICROPHONE";
    userPolicyIdl.isPersist = false;
    userPolicyIdl.userPolicyList = {{ .userId = USER_ID, .isRestricted = true }};
    EXPECT_EQ(RET_SUCCESS, atManagerService_->SetUserPolicy({ userPolicyIdl }));
    EXPECT_EQ(PERMISSION_DENIED,
        AccessTokenInfoManager::GetInstance().VerifyAccessToken(tokenId, "ohos.permission.MICROPHONE"));

    EXPECT_EQ(RET_SUCCESS, atManagerService_->GrantPermission(
        tokenId, "ohos.permission.MICROPHONE", PERMISSION_USER_FIXED, USER_GRANTED_PERM));
    EXPECT_EQ(PERMISSION_DENIED,
        AccessTokenInfoManager::GetInstance().VerifyAccessToken(tokenId, "ohos.permission.MICROPHONE"));

    EXPECT_EQ(RET_SUCCESS, atManagerService_->ClearUserPolicy({ "ohos.permission.MICROPHONE" }));
    EXPECT_EQ(PERMISSION_GRANTED,
        AccessTokenInfoManager::GetInstance().VerifyAccessToken(tokenId, "ohos.permission.MICROPHONE"));

    (void)AccessTokenInfoManager::GetInstance().RemoveHapTokenInfo(tokenId);
}

/**
 * @tc.name: UserPolicyServiceTest008
 * @tc.desc: Test RevokePermission takes effect after active user policy restriction is cleared.
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(AccessTokenManagerServiceTest, UserPolicyServiceTest008, TestSize.Level1)
{
    MockToken mock(g_selfShellTokenId, "accesstoken_service", false);
    mock.Grant(MANAGE_USER_POLICY);
    mock.Grant(REVOKE_SENSITIVE_PERMISSIONS);
    AccessTokenID tokenId = INVALID_TOKENID;
    uint64_t fullTokenId = CreateServiceTestHapToken("user_policy_service_revoke_under_restrict_test", true,
        {
            {
                .permissionName = "ohos.permission.MICROPHONE",
                .grantStatus = PermissionState::PERMISSION_GRANTED,
                .grantFlag = PermissionFlag::PERMISSION_USER_FIXED
            }
        }, tokenId);
    ASSERT_NE(0, fullTokenId);
    EXPECT_EQ(PERMISSION_GRANTED,
        AccessTokenInfoManager::GetInstance().VerifyAccessToken(tokenId, "ohos.permission.MICROPHONE"));

    UserPermissionPolicyIdl userPolicyIdl;
    userPolicyIdl.permissionName = "ohos.permission.MICROPHONE";
    userPolicyIdl.isPersist = false;
    userPolicyIdl.userPolicyList = {{ .userId = USER_ID, .isRestricted = true }};
    EXPECT_EQ(RET_SUCCESS, atManagerService_->SetUserPolicy({ userPolicyIdl }));
    EXPECT_EQ(PERMISSION_DENIED,
        AccessTokenInfoManager::GetInstance().VerifyAccessToken(tokenId, "ohos.permission.MICROPHONE"));

    EXPECT_EQ(RET_SUCCESS, atManagerService_->RevokePermission(
        tokenId, "ohos.permission.MICROPHONE", PERMISSION_USER_FIXED, USER_GRANTED_PERM));
    EXPECT_EQ(PERMISSION_DENIED,
        AccessTokenInfoManager::GetInstance().VerifyAccessToken(tokenId, "ohos.permission.MICROPHONE"));

    EXPECT_EQ(RET_SUCCESS, atManagerService_->ClearUserPolicy({ "ohos.permission.MICROPHONE" }));
    EXPECT_EQ(PERMISSION_DENIED,
        AccessTokenInfoManager::GetInstance().VerifyAccessToken(tokenId, "ohos.permission.MICROPHONE"));

    (void)AccessTokenInfoManager::GetInstance().RemoveHapTokenInfo(tokenId);
}

/**
 * @tc.name: UserPolicyServiceTest009
 * @tc.desc: Test ClearUserGrantedPermissionState keeps active user policy restriction.
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(AccessTokenManagerServiceTest, UserPolicyServiceTest009, TestSize.Level1)
{
    MockToken mock(g_selfShellTokenId, "accesstoken_service", false);
    mock.Grant(MANAGE_USER_POLICY);
    mock.Grant(REVOKE_SENSITIVE_PERMISSIONS);
    AccessTokenID tokenId = INVALID_TOKENID;
    uint64_t fullTokenId = CreateServiceTestHapToken("user_policy_service_clear_user_grant_test", true,
        {
            {
                .permissionName = "ohos.permission.MICROPHONE",
                .grantStatus = PermissionState::PERMISSION_GRANTED,
                .grantFlag = PermissionFlag::PERMISSION_USER_FIXED
            }
        }, tokenId);
    ASSERT_NE(0, fullTokenId);
    EXPECT_EQ(PERMISSION_GRANTED,
        AccessTokenInfoManager::GetInstance().VerifyAccessToken(tokenId, "ohos.permission.MICROPHONE"));

    UserPermissionPolicyIdl userPolicyIdl;
    userPolicyIdl.permissionName = "ohos.permission.MICROPHONE";
    userPolicyIdl.isPersist = false;
    userPolicyIdl.userPolicyList = {{ .userId = USER_ID, .isRestricted = true }};
    EXPECT_EQ(RET_SUCCESS, atManagerService_->SetUserPolicy({ userPolicyIdl }));
    EXPECT_EQ(PERMISSION_DENIED,
        AccessTokenInfoManager::GetInstance().VerifyAccessToken(tokenId, "ohos.permission.MICROPHONE"));

    uint32_t flag = 0;
    EXPECT_EQ(RET_SUCCESS, atManagerService_->GetPermissionFlag(tokenId, "ohos.permission.MICROPHONE", flag));
    EXPECT_NE(0U, flag & PERMISSION_RESTRICTED_BY_ADMIN);

    EXPECT_EQ(RET_SUCCESS, atManagerService_->ClearUserGrantedPermissionState(tokenId));
    EXPECT_EQ(RET_SUCCESS, atManagerService_->GetPermissionFlag(tokenId, "ohos.permission.MICROPHONE", flag));
    EXPECT_NE(0U, flag & PERMISSION_RESTRICTED_BY_ADMIN);
    EXPECT_EQ(PERMISSION_DENIED,
        AccessTokenInfoManager::GetInstance().VerifyAccessToken(tokenId, "ohos.permission.MICROPHONE"));

    EXPECT_EQ(RET_SUCCESS, atManagerService_->ClearUserPolicy({ "ohos.permission.MICROPHONE" }));
    (void)AccessTokenInfoManager::GetInstance().RemoveHapTokenInfo(tokenId);
}

/**
 * @tc.name: UserPolicyServiceTest010
 * @tc.desc: Test SetUserPolicy and ClearUserPolicy service parameter validation branches.
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(AccessTokenManagerServiceTest, UserPolicyServiceTest010, TestSize.Level1)
{
    MockToken mock(g_selfShellTokenId, "accesstoken_service", false);
    mock.Grant(MANAGE_USER_POLICY);

    UserPermissionPolicyIdl emptyUserListPolicy;
    emptyUserListPolicy.permissionName = "ohos.permission.INTERNET";
    emptyUserListPolicy.isPersist = false;
    EXPECT_EQ(ERR_PARAM_INVALID, atManagerService_->SetUserPolicy({ emptyUserListPolicy }));

    UserPermissionPolicyIdl userPolicyIdl;
    userPolicyIdl.permissionName = "ohos.permission.INTERNET";
    userPolicyIdl.isPersist = false;
    userPolicyIdl.userPolicyList = {{ .userId = USER_ID, .isRestricted = true }};
    UserPermissionPolicyIdl duplicatePolicyIdl = userPolicyIdl;
    EXPECT_EQ(ERR_PARAM_INVALID, atManagerService_->SetUserPolicy({ userPolicyIdl, duplicatePolicyIdl }));

    duplicatePolicyIdl.isPersist = true;
    EXPECT_EQ(ERR_PERM_POLICY_PERSISTENCE_FLAG_NOT_MATCH,
        atManagerService_->SetUserPolicy({ userPolicyIdl, duplicatePolicyIdl }));

    EXPECT_EQ(ERR_PARAM_INVALID, atManagerService_->ClearUserPolicy({ "ohos.permission.INVALID" }));
    EXPECT_EQ(ERR_PERM_POLICY_NOT_SET, atManagerService_->ClearUserPolicy({ "ohos.permission.INTERNET" }));
}

/**
 * @tc.name: UserPolicyServiceTest011
 * @tc.desc: Test permission state callback is skipped while grant stays restricted by user policy.
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(AccessTokenManagerServiceTest, UserPolicyServiceTest011, TestSize.Level1)
{
    MockToken mock(g_selfShellTokenId, "accesstoken_service", false);
    mock.Grant(MANAGE_USER_POLICY);
    mock.Grant(GRANT_SENSITIVE_PERMISSIONS);
    mock.Grant("ohos.permission.GET_SENSITIVE_PERMISSIONS");

    AccessTokenID tokenId = INVALID_TOKENID;
    uint64_t fullTokenId = CreateServiceTestHapToken("user_policy_service_callback_effective_state_test", true,
        {
            {
                .permissionName = "ohos.permission.MICROPHONE",
                .grantStatus = PermissionState::PERMISSION_DENIED,
                .grantFlag = PermissionFlag::PERMISSION_DEFAULT_FLAG
            }
        }, tokenId);
    ASSERT_NE(0, fullTokenId);

    UserPermissionPolicyIdl userPolicyIdl;
    userPolicyIdl.permissionName = "ohos.permission.MICROPHONE";
    userPolicyIdl.isPersist = false;
    userPolicyIdl.userPolicyList = {{ .userId = USER_ID, .isRestricted = true }};
    ASSERT_EQ(RET_SUCCESS, atManagerService_->SetUserPolicy({ userPolicyIdl }));

    PermStateChangeScope scopeInfo;
    scopeInfo.tokenIDs = {tokenId};
    scopeInfo.permList = {"ohos.permission.MICROPHONE"};
    auto callbackPtr = std::make_shared<RecordingCbCustomizeTest>(scopeInfo);
    auto callback = new (std::nothrow) PermissionStateChangeCallback(callbackPtr);
    ASSERT_NE(nullptr, callback);
    PermStateChangeScopeParcel scopeParcel;
    scopeParcel.scope = scopeInfo;
    ASSERT_EQ(RET_SUCCESS, atManagerService_->RegisterPermStateChangeCallback(
        scopeParcel, callback->AsObject()));

    ASSERT_EQ(RET_SUCCESS, atManagerService_->GrantPermission(
        tokenId, "ohos.permission.MICROPHONE", PERMISSION_USER_FIXED, USER_GRANTED_PERM));
    usleep(500000); // 500000us = 0.5s

    EXPECT_FALSE(callbackPtr->ready_);
    EXPECT_EQ(PERMISSION_DENIED,
        AccessTokenInfoManager::GetInstance().VerifyAccessToken(tokenId, "ohos.permission.MICROPHONE"));

    EXPECT_EQ(RET_SUCCESS, atManagerService_->UnRegisterPermStateChangeCallback(callback->AsObject()));
    EXPECT_EQ(RET_SUCCESS, atManagerService_->ClearUserPolicy({ "ohos.permission.MICROPHONE" }));
    (void)AccessTokenInfoManager::GetInstance().RemoveHapTokenInfo(tokenId);
}

/**
 * @tc.name: UserPolicyServiceTest012
 * @tc.desc: Test SetUserPolicy rolls back refreshed hap permission state when a later hap refresh fails.
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(AccessTokenManagerServiceTest, UserPolicyServiceTest012, TestSize.Level1)
{
    MockToken mock(g_selfShellTokenId, "accesstoken_service", false);
    mock.Grant(MANAGE_USER_POLICY);

    AccessTokenID tokenId = INVALID_TOKENID;
    uint64_t fullTokenId = CreateServiceTestHapToken("user_policy_service_refresh_rollback_test", true,
        { BuildGrantedPermissionStatus("ohos.permission.INTERNET") }, tokenId);
    ASSERT_NE(0, fullTokenId);
    ASSERT_NE(INVALID_TOKENID, tokenId);
    uint32_t flag = 0;
    ASSERT_EQ(RET_SUCCESS, atManagerService_->GetPermissionFlag(tokenId, "ohos.permission.INTERNET", flag));
    ASSERT_EQ(PERMISSION_SYSTEM_FIXED, flag);
    int32_t statusBefore = AccessTokenInfoManager::GetInstance().VerifyAccessToken(tokenId, "ohos.permission.INTERNET");

    AccessTokenID invalidSameUserTokenId =
        AccessTokenIDManager::GetInstance().CreateAndRegisterTokenId(TOKEN_HAP, 0, 0, 0);
    ASSERT_NE(INVALID_TOKENID, invalidSameUserTokenId);
    auto invalidInfo = std::make_shared<HapTokenInfoInner>();
    invalidInfo->tokenInfoBasic_.tokenID = invalidSameUserTokenId;
    invalidInfo->tokenInfoBasic_.userID = USER_ID;
    invalidInfo->tokenInfoBasic_.bundleName = "invalid_refresh_rollback";
    invalidInfo->tokenInfoBasic_.instIndex = 0;
    invalidInfo->tokenInfoBasic_.apiVersion = API_VERSION_9;
    AccessTokenInfoManager::GetInstance().hapTokenInfoMap_[invalidSameUserTokenId] = invalidInfo;

    UserPermissionPolicyIdl userPolicyIdl;
    userPolicyIdl.permissionName = "ohos.permission.INTERNET";
    userPolicyIdl.isPersist = false;
    userPolicyIdl.userPolicyList = {{ .userId = USER_ID, .isRestricted = true }};

    EXPECT_NE(RET_SUCCESS, atManagerService_->SetUserPolicy({ userPolicyIdl }));
    EXPECT_EQ(statusBefore,
        AccessTokenInfoManager::GetInstance().VerifyAccessToken(tokenId, "ohos.permission.INTERNET"));

    AccessTokenInfoManager::GetInstance().hapTokenInfoMap_.erase(invalidSameUserTokenId);
    AccessTokenIDManager::GetInstance().ReleaseTokenId(invalidSameUserTokenId);
    EXPECT_EQ(RET_SUCCESS, atManagerService_->ClearUserPolicy({ "ohos.permission.INTERNET" }));
    (void)AccessTokenInfoManager::GetInstance().RemoveHapTokenInfo(tokenId);
}

/**
 * @tc.name: UserPolicyServiceTest013
 * @tc.desc: Test RefreshUserPolicyPermState handles empty input.
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(AccessTokenManagerServiceTest, UserPolicyServiceTest013, TestSize.Level1)
{
    EXPECT_EQ(RET_SUCCESS, atManagerService_->RefreshUserPolicyPermState({}));
}

/**
 * @tc.name: UserPolicyServiceTest014
 * @tc.desc: Test hap rollback continues when one snapshot restore fails.
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(AccessTokenManagerServiceTest, UserPolicyServiceTest014, TestSize.Level1)
{
    AccessTokenID tokenId = INVALID_TOKENID;
    uint64_t fullTokenId = CreateServiceTestHapToken("user_policy_service_hap_rollback_continue_test", true,
        { BuildGrantedPermissionStatus("ohos.permission.INTERNET") }, tokenId);
    ASSERT_NE(0, fullTokenId);
    ASSERT_NE(INVALID_TOKENID, tokenId);

    uint32_t permCode = 0;
    ASSERT_TRUE(TransferPermissionToOpcode("ohos.permission.INTERNET", permCode));
    ASSERT_EQ(PERMISSION_GRANTED,
        AccessTokenInfoManager::GetInstance().VerifyAccessToken(tokenId, "ohos.permission.INTERNET"));
    ASSERT_EQ(RET_SUCCESS, AccessTokenInfoManager::GetInstance().UpdateRestrictedFlagAndRefreshKernel(
        tokenId, permCode, true, false, "test"));
    ASSERT_EQ(PERMISSION_DENIED,
        AccessTokenInfoManager::GetInstance().VerifyAccessToken(tokenId, "ohos.permission.INTERNET"));

    std::vector<UserPolicyRefreshSnapshot> snapshots = {
        {
            .target = UserPolicyRefreshTarget::HAP,
            .tokenId = tokenId,
            .permCode = permCode,
            .originalStatus = PERMISSION_GRANTED,
            .originalFlag = PERMISSION_SYSTEM_FIXED,
        },
        {
            .target = UserPolicyRefreshTarget::HAP,
            .tokenId = INVALID_TOKENID,
            .permCode = permCode,
            .originalStatus = PERMISSION_GRANTED,
            .originalFlag = PERMISSION_SYSTEM_FIXED,
        }
    };

    AccessTokenInfoManager::GetInstance().RollbackUserPolicyFlag(snapshots);
    EXPECT_EQ(PERMISSION_GRANTED,
        AccessTokenInfoManager::GetInstance().VerifyAccessToken(tokenId, "ohos.permission.INTERNET"));

    (void)AccessTokenInfoManager::GetInstance().RemoveHapTokenInfo(tokenId);
}

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

    AccessTokenID nativeTokenId = AccessTokenInfoManager::GetInstance().GetNativeTokenId("foundation");
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
    EXPECT_TRUE(tokenIdList.empty());
}

/**
 * @tc.name: PolicyWhiteListServiceTest003
 * @tc.desc: Test UpdatePolicyWhiteList returns invalid when HAP user id cannot be queried.
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(AccessTokenManagerServiceTest, PolicyWhiteListServiceTest003, TestSize.Level1)
{
    MockToken mock(g_selfShellTokenId, "accesstoken_service", false);
    mock.Grant(MANAGE_USER_POLICY);
    uint32_t permCode = 0;
    ASSERT_TRUE(TransferPermissionToOpcode("ohos.permission.INTERNET", permCode));

    AccessTokenID tokenId = AccessTokenIDManager::GetInstance().CreateAndRegisterTokenId(TOKEN_HAP, 0, 0, 0);
    ASSERT_EQ(TOKEN_HAP, AccessTokenIDManager::GetInstance().GetTokenIdType(tokenId));
    EXPECT_EQ(ERR_PARAM_INVALID,
        atManagerService_->UpdatePolicyWhiteList(tokenId, permCode, static_cast<int32_t>(ADD)));
    AccessTokenIDManager::GetInstance().ReleaseTokenId(tokenId);
}

/**
 * @tc.name: PolicyWhiteListServiceTest004
 * @tc.desc: Test UpdatePolicyWhiteList service updates whitelist and restricted flag.
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(AccessTokenManagerServiceTest, PolicyWhiteListServiceTest004, TestSize.Level1)
{
    MockToken mock(g_selfShellTokenId, "accesstoken_service", false);
    mock.Grant(MANAGE_USER_POLICY);
    AccessTokenID tokenId = INVALID_TOKENID;
    uint64_t fullTokenId = CreateServiceTestHapToken("policy_whitelist_service_success", true,
        { BuildGrantedPermissionStatus("ohos.permission.CAMERA") }, tokenId);
    ASSERT_NE(0, fullTokenId);

    UserPermissionPolicyIdl userPolicyIdl;
    userPolicyIdl.permissionName = "ohos.permission.CAMERA";
    userPolicyIdl.isPersist = true;
    userPolicyIdl.userPolicyList = {{ .userId = USER_ID, .isRestricted = true }};
    ASSERT_EQ(RET_SUCCESS, atManagerService_->SetUserPolicy({ userPolicyIdl }));
    EXPECT_EQ(PERMISSION_DENIED,
        AccessTokenInfoManager::GetInstance().VerifyAccessToken(tokenId, "ohos.permission.CAMERA"));

    uint32_t permCode = 0;
    ASSERT_TRUE(TransferPermissionToOpcode("ohos.permission.CAMERA", permCode));
    EXPECT_EQ(RET_SUCCESS, atManagerService_->UpdatePolicyWhiteList(tokenId, permCode, static_cast<int32_t>(ADD)));
    EXPECT_EQ(PERMISSION_GRANTED,
        AccessTokenInfoManager::GetInstance().VerifyAccessToken(tokenId, "ohos.permission.CAMERA"));
    std::vector<AccessTokenID> tokenIdList;
    EXPECT_EQ(RET_SUCCESS, atManagerService_->GetPolicyWhiteList(permCode, tokenIdList));
    ASSERT_EQ(1u, tokenIdList.size());
    EXPECT_EQ(tokenId, tokenIdList[0]);

    EXPECT_EQ(RET_SUCCESS, atManagerService_->UpdatePolicyWhiteList(tokenId, permCode, static_cast<int32_t>(DELETE)));
    EXPECT_EQ(PERMISSION_DENIED,
        AccessTokenInfoManager::GetInstance().VerifyAccessToken(tokenId, "ohos.permission.CAMERA"));
    tokenIdList = { tokenId };
    EXPECT_EQ(RET_SUCCESS, atManagerService_->GetPolicyWhiteList(permCode, tokenIdList));
    EXPECT_TRUE(tokenIdList.empty());

    EXPECT_EQ(RET_SUCCESS, atManagerService_->ClearUserPolicy({ "ohos.permission.CAMERA" }));
    (void)AccessTokenInfoManager::GetInstance().RemoveHapTokenInfo(tokenId);
}

/**
 * @tc.name: PolicyWhiteListServiceTest005
 * @tc.desc: Test UpdatePolicyWhiteList rolls back whitelist when restricted flag update fails.
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(AccessTokenManagerServiceTest, PolicyWhiteListServiceTest005, TestSize.Level1)
{
    MockToken mock(g_selfShellTokenId, "accesstoken_service", false);
    mock.Grant(MANAGE_USER_POLICY);
    AccessTokenID tokenId = INVALID_TOKENID;
    uint64_t fullTokenId = CreateServiceTestHapToken("policy_whitelist_service_rollback", true,
        { BuildGrantedPermissionStatus("ohos.permission.GET_NETWORK_STATS") }, tokenId);
    ASSERT_NE(0, fullTokenId);

    uint32_t permCode = 0;
    ASSERT_TRUE(TransferPermissionToOpcode("ohos.permission.INTERNET", permCode));
    UserPermissionPolicy policy {
        .permissionName = "ohos.permission.INTERNET",
        .userPolicyList = {{ .userId = USER_ID, .isRestricted = true }},
        .isPersist = true
    };
    std::vector<UserPolicyChange> userPolicyList;
    ASSERT_EQ(RET_SUCCESS, UserPolicyManager::GetInstance().SetUserPolicy({ policy }, GetSelfTokenID(),
        userPolicyList));

    EXPECT_EQ(ERR_PERMISSION_NOT_EXIST,
        atManagerService_->UpdatePolicyWhiteList(tokenId, permCode, static_cast<int32_t>(ADD)));

    std::vector<AccessTokenID> tokenIdList = { tokenId };
    EXPECT_EQ(RET_SUCCESS, atManagerService_->GetPolicyWhiteList(permCode, tokenIdList));
    EXPECT_TRUE(tokenIdList.empty());

    EXPECT_EQ(RET_SUCCESS,
        UserPolicyManager::GetInstance().ClearUserPolicy({ "ohos.permission.INTERNET" }, GetSelfTokenID(),
            userPolicyList));
    (void)AccessTokenInfoManager::GetInstance().RemoveHapTokenInfo(tokenId);
}

/**
 * @tc.name: PolicyWhiteListServiceTest006
 * @tc.desc: Test UpdatePolicyWhiteList validation branches for policy state.
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(AccessTokenManagerServiceTest, PolicyWhiteListServiceTest006, TestSize.Level1)
{
    MockToken mock(g_selfShellTokenId, "accesstoken_service", false);
    mock.Grant(MANAGE_USER_POLICY);
    AccessTokenID tokenId = INVALID_TOKENID;
    uint64_t fullTokenId = CreateServiceTestHapToken("policy_whitelist_service_branch_test", true,
        { BuildGrantedPermissionStatus("ohos.permission.CAMERA") }, tokenId);
    ASSERT_NE(0, fullTokenId);

    uint32_t cameraCode = 0;
    ASSERT_TRUE(TransferPermissionToOpcode("ohos.permission.CAMERA", cameraCode));
    EXPECT_EQ(ERR_PERM_POLICY_NOT_SET,
        atManagerService_->UpdatePolicyWhiteList(tokenId, cameraCode, static_cast<int32_t>(ADD)));

    UserPermissionPolicyIdl userPolicyIdl;
    userPolicyIdl.permissionName = "ohos.permission.CAMERA";
    userPolicyIdl.isPersist = false;
    userPolicyIdl.userPolicyList = {{ .userId = USER_ID + 1, .isRestricted = true }};
    ASSERT_EQ(RET_SUCCESS, atManagerService_->SetUserPolicy({ userPolicyIdl }));
    EXPECT_EQ(ERR_TOKENID_NOT_IN_POLICY_USERLIST,
        atManagerService_->UpdatePolicyWhiteList(tokenId, cameraCode, static_cast<int32_t>(ADD)));
    EXPECT_EQ(RET_SUCCESS, atManagerService_->ClearUserPolicy({ "ohos.permission.CAMERA" }));

    userPolicyIdl.userPolicyList = {{ .userId = USER_ID, .isRestricted = true }};
    ASSERT_EQ(RET_SUCCESS, atManagerService_->SetUserPolicy({ userPolicyIdl }));
    EXPECT_EQ(ERR_TOKENID_NOT_IN_POLICY_WHITELIST,
        atManagerService_->UpdatePolicyWhiteList(tokenId, cameraCode, static_cast<int32_t>(DELETE)));
    EXPECT_EQ(RET_SUCCESS, atManagerService_->UpdatePolicyWhiteList(tokenId, cameraCode, static_cast<int32_t>(ADD)));
    EXPECT_EQ(ERR_TOKENID_ALREADY_IN_POLICY_WHITELIST,
        atManagerService_->UpdatePolicyWhiteList(tokenId, cameraCode, static_cast<int32_t>(ADD)));

    EXPECT_EQ(RET_SUCCESS, atManagerService_->ClearUserPolicy({ "ohos.permission.CAMERA" }));
    (void)AccessTokenInfoManager::GetInstance().RemoveHapTokenInfo(tokenId);
}

/**
 * @tc.name: PolicyWhiteListServicePermissionTest001
 * @tc.desc: Test UpdatePolicyWhiteList returns permission denied before manager whitelist update.
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(AccessTokenManagerServiceTest, PolicyWhiteListServicePermissionTest001, TestSize.Level1)
{
    AccessTokenID callerTokenId = INVALID_TOKENID;
    uint64_t callerFullTokenId = CreateServiceTestHapToken(
        "user_policy_service_permission_test_update", true, {}, callerTokenId);
    ASSERT_NE(0, callerFullTokenId);

    AccessTokenID targetTokenId = INVALID_TOKENID;
    uint64_t targetFullTokenId = CreateServiceTestHapToken(
        "user_policy_service_permission_target_update", true, {}, targetTokenId);
    ASSERT_NE(0, targetFullTokenId);

    uint32_t permCode = 0;
    ASSERT_TRUE(TransferPermissionToOpcode("ohos.permission.INTERNET", permCode));
    SetSelfTokenID(callerFullTokenId);

    EXPECT_EQ(ERR_PERMISSION_DENIED,
        atManagerService_->UpdatePolicyWhiteList(targetTokenId, permCode, static_cast<int32_t>(ADD)));

    SetSelfTokenID(g_selfShellTokenId);
    (void)AccessTokenInfoManager::GetInstance().RemoveHapTokenInfo(callerTokenId);
    (void)AccessTokenInfoManager::GetInstance().RemoveHapTokenInfo(targetTokenId);
}

/**
 * @tc.name: PolicyWhiteListServicePermissionTest002
 * @tc.desc: Test GetPolicyWhiteList returns permission denied and clears output list.
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(AccessTokenManagerServiceTest, PolicyWhiteListServicePermissionTest002, TestSize.Level1)
{
    AccessTokenID callerTokenId = INVALID_TOKENID;
    uint64_t callerFullTokenId = CreateServiceTestHapToken(
        "user_policy_service_permission_test_get", true, {}, callerTokenId);
    ASSERT_NE(0, callerFullTokenId);

    uint32_t permCode = 0;
    ASSERT_TRUE(TransferPermissionToOpcode("ohos.permission.INTERNET", permCode));
    SetSelfTokenID(callerFullTokenId);

    std::vector<AccessTokenID> tokenIdList = {RANDOM_TOKENID};
    EXPECT_EQ(ERR_PERMISSION_DENIED, atManagerService_->GetPolicyWhiteList(permCode, tokenIdList));
    EXPECT_TRUE(tokenIdList.empty());

    SetSelfTokenID(g_selfShellTokenId);
    (void)AccessTokenInfoManager::GetInstance().RemoveHapTokenInfo(callerTokenId);
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

/**
 * @tc.name: ClearUserGrantedPermStateByBundleFuncTest001
 * @tc.desc: Clear user granted permission state by bundle for debug hap.
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(AccessTokenManagerServiceTest, ClearUserGrantedPermStateByBundleFuncTest001, TestSize.Level0)
{
    atManagerService_->Initialize();
    const std::string bundleName = "ClearUserGrantedPermStateByBundleService";
    AccessTokenIDEx tokenIdEx = CreateBundleClearHapToken(bundleName, 0, "debug");
    AccessTokenID tokenID = tokenIdEx.tokenIdExStruct.tokenID;
    SetCameraMicrophoneUserFixedStateByService(tokenID);
    uint64_t selfTokenId = SetShellCallerByTest();
    int32_t ret = atManagerService_->ClearUserGrantedPermStateByBundle(bundleName);
    RestoreCallerByTest(selfTokenId);
    ASSERT_EQ(RET_SUCCESS, ret);

    ASSERT_FALSE(AccessTokenInfoManager::GetInstance().GetPermDialogCap(tokenID));
    AssertCameraMicrophoneCanShowDialog(atManagerService_, tokenIdEx);
    DeleteBundleClearToken(tokenID);
}

/**
 * @tc.name: ClearUserGrantedPermStateByBundleFuncTest002
 * @tc.desc: Clear user granted permission state by bundle for multiple debug hap tokens.
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(AccessTokenManagerServiceTest, ClearUserGrantedPermStateByBundleFuncTest002, TestSize.Level0)
{
    atManagerService_->Initialize();
    const std::string bundleName = "ClearUserGrantedPermStateByBundleMultiDebugService";
    AccessTokenIDEx tokenIdEx1 = CreateBundleClearHapToken(bundleName, 0, "debug");
    AccessTokenIDEx tokenIdEx2 = CreateBundleClearHapToken(bundleName, 1, "debug");
    AccessTokenID tokenID1 = tokenIdEx1.tokenIdExStruct.tokenID;
    AccessTokenID tokenID2 = tokenIdEx2.tokenIdExStruct.tokenID;
    SetCameraMicrophoneUserFixedStateByService(tokenID1);
    SetCameraMicrophoneUserFixedStateByService(tokenID2);

    uint64_t selfTokenId = SetShellCallerByTest();
    int32_t ret = atManagerService_->ClearUserGrantedPermStateByBundle(bundleName);
    RestoreCallerByTest(selfTokenId);

    ASSERT_EQ(RET_SUCCESS, ret);

    ASSERT_FALSE(AccessTokenInfoManager::GetInstance().GetPermDialogCap(tokenID1));
    ASSERT_FALSE(AccessTokenInfoManager::GetInstance().GetPermDialogCap(tokenID2));
    AssertCameraMicrophoneCanShowDialog(atManagerService_, tokenIdEx1);
    AssertCameraMicrophoneCanShowDialog(atManagerService_, tokenIdEx2);
    DeleteBundleClearToken(tokenID1);
    DeleteBundleClearToken(tokenID2);
}

/**
 * @tc.name: ClearUserGrantedPermStateByBundleFuncTest003
 * @tc.desc: Clear only debug hap token state when debug and release hap tokens share one bundle name.
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(AccessTokenManagerServiceTest, ClearUserGrantedPermStateByBundleFuncTest003, TestSize.Level0)
{
    atManagerService_->Initialize();
    const std::string bundleName = "ClearUserGrantedPermStateByBundleMixedService";
    AccessTokenIDEx debugTokenIdEx = CreateBundleClearHapToken(bundleName, 0, "debug");
    AccessTokenIDEx releaseTokenIdEx = CreateBundleClearHapToken(bundleName, 1, "release");
    AccessTokenID debugTokenID = debugTokenIdEx.tokenIdExStruct.tokenID;
    AccessTokenID releaseTokenID = releaseTokenIdEx.tokenIdExStruct.tokenID;
    SetCameraMicrophoneUserFixedStateByService(debugTokenID);
    SetCameraMicrophoneUserFixedStateByService(releaseTokenID);

    uint64_t selfTokenId = SetShellCallerByTest();
    int32_t ret = atManagerService_->ClearUserGrantedPermStateByBundle(bundleName);
    RestoreCallerByTest(selfTokenId);
    ASSERT_EQ(RET_SUCCESS, ret);

    ASSERT_FALSE(AccessTokenInfoManager::GetInstance().GetPermDialogCap(debugTokenID));
    AssertCameraMicrophoneCanShowDialog(atManagerService_, debugTokenIdEx);
#ifdef ATM_BUILD_VARIANT_USER_ENABLE
    ASSERT_TRUE(AccessTokenInfoManager::GetInstance().GetPermDialogCap(releaseTokenID));
#else
    ASSERT_FALSE(AccessTokenInfoManager::GetInstance().GetPermDialogCap(releaseTokenID));
    AssertCameraMicrophoneCanShowDialog(atManagerService_, releaseTokenIdEx);
#endif
    DeleteBundleClearToken(debugTokenID);
    DeleteBundleClearToken(releaseTokenID);
}

/**
 * @tc.name: ClearUserGrantedPermStateByBundleAbnormalTest001
 * @tc.desc: Clear user granted permission state by bundle for release-only hap tokens.
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(AccessTokenManagerServiceTest, ClearUserGrantedPermStateByBundleAbnormalTest001, TestSize.Level0)
{
    atManagerService_->Initialize();
    const std::string bundleName = "ClearUserGrantedPermStateByBundleReleaseOnlyService";
    AccessTokenID tokenID = CreateBundleClearHapToken(bundleName, 0, "release").tokenIdExStruct.tokenID;
    SetCameraMicrophoneUserFixedStateByService(tokenID);

    uint64_t selfTokenId = SetShellCallerByTest();
    int32_t ret = atManagerService_->ClearUserGrantedPermStateByBundle(bundleName);
    RestoreCallerByTest(selfTokenId);
#ifdef ATM_BUILD_VARIANT_USER_ENABLE
    ASSERT_EQ(AccessTokenError::ERR_PERMISSION_DENIED, ret);
    ASSERT_TRUE(AccessTokenInfoManager::GetInstance().GetPermDialogCap(tokenID));
#else
    ASSERT_EQ(RET_SUCCESS, ret);
    ASSERT_FALSE(AccessTokenInfoManager::GetInstance().GetPermDialogCap(tokenID));
#endif
    DeleteBundleClearToken(tokenID);
}

/**
 * @tc.name: ClearUserGrantedPermStateByBundleAbnormalTest002
 * @tc.desc: Clear user granted permission state by bundle rejects nonexistent bundle name.
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(AccessTokenManagerServiceTest, ClearUserGrantedPermStateByBundleAbnormalTest002, TestSize.Level0)
{
    atManagerService_->Initialize();
    uint64_t selfTokenId = SetShellCallerByTest();
    int32_t ret = atManagerService_->ClearUserGrantedPermStateByBundle(
        "ClearUserGrantedPermStateByBundleNotExistService");
    RestoreCallerByTest(selfTokenId);
    ASSERT_EQ(AccessTokenError::ERR_BUNDLE_NOT_EXIST, ret);
}

/**
 * @tc.name: ClearUserGrantedPermStateByBundleAbnormalTest003
 * @tc.desc: Clear user granted permission state by bundle rejects invalid bundle name.
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(AccessTokenManagerServiceTest, ClearUserGrantedPermStateByBundleAbnormalTest003, TestSize.Level0)
{
    atManagerService_->Initialize();
    uint64_t selfTokenId = SetShellCallerByTest();
    int32_t emptyRet = atManagerService_->ClearUserGrantedPermStateByBundle("");
    RestoreCallerByTest(selfTokenId);
    ASSERT_EQ(AccessTokenError::ERR_PARAM_INVALID, emptyRet);
}

/**
 * @tc.name: ClearUserGrantedPermStateByBundleFuncTest004
 * @tc.desc: Clear user granted permission state by bundle without user setting.
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(AccessTokenManagerServiceTest, ClearUserGrantedPermStateByBundleFuncTest004, TestSize.Level0)
{
    atManagerService_->Initialize();
    const std::string bundleName = "ClearUserGrantedPermStateByBundleNoSettingService";
    AccessTokenIDEx tokenIdEx = CreateBundleClearHapToken(bundleName, 0, "debug");
    AccessTokenID tokenID = tokenIdEx.tokenIdExStruct.tokenID;
    ASSERT_FALSE(AccessTokenInfoManager::GetInstance().GetPermDialogCap(tokenID));

    uint64_t selfTokenId = SetShellCallerByTest();
    int32_t ret = atManagerService_->ClearUserGrantedPermStateByBundle(bundleName);
    RestoreCallerByTest(selfTokenId);
    ASSERT_EQ(RET_SUCCESS, ret);

    ASSERT_FALSE(AccessTokenInfoManager::GetInstance().GetPermDialogCap(tokenID));
    AssertCameraMicrophoneCanShowDialog(atManagerService_, tokenIdEx);
    DeleteBundleClearToken(tokenID);
}

#ifdef SECURITY_COMPONENT_ENHANCE_ENABLE
/**
 * @tc.name: SecCompEnhanceKeyService001
 * @tc.desc: Reject Store and Get from a caller other than security_component_service
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(AccessTokenManagerServiceTest, SecCompEnhanceKeyService001, TestSize.Level1)
{
    ResetSecCompEnhanceKey();
    MockNativeToken mock("foundation");
    SecCompEnhanceKeyIdl input = BuildSecCompEnhanceKeyIdl(1, 0x11);
    SecCompEnhanceKeyIdl output;
    EXPECT_EQ(AccessTokenError::ERR_PERMISSION_DENIED, atManagerService_->StoreSecCompEnhanceKey(input));
    EXPECT_EQ(AccessTokenError::ERR_PERMISSION_DENIED, atManagerService_->GetSecCompEnhanceKey(output));
}

/**
 * @tc.name: SecCompEnhanceKeyService002
 * @tc.desc: Allow security_component_service to Store and Get an enhance key
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(AccessTokenManagerServiceTest, SecCompEnhanceKeyService002, TestSize.Level1)
{
    ResetSecCompEnhanceKey();
    MockNativeToken mock("security_component_service");
    SecCompEnhanceKeyIdl input = BuildSecCompEnhanceKeyIdl(1, 0x22);
    SecCompEnhanceKeyIdl output;
    EXPECT_EQ(RET_SUCCESS, atManagerService_->StoreSecCompEnhanceKey(input));
    EXPECT_EQ(RET_SUCCESS, atManagerService_->GetSecCompEnhanceKey(output));
    EXPECT_EQ(input.epoch, output.epoch);
    EXPECT_EQ(input.key, output.key);
    ResetSecCompEnhanceKey();
}
#endif

/**
 * @tc.name: ToggleRequestService001
 * @tc.desc: Verify request toggle succeeds with the specified user ID for root caller.
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(AccessTokenManagerServiceTest, ToggleRequestService001, TestSize.Level0)
{
    PermissionRequestToggleStatusGuard toggleGuard(USER_ID, "ohos.permission.CAMERA");
    OsAccountMockGuard mockGuard;
    SetMockOsAccountLocalIdForSubProfile(USER_ID, ERR_OK);
    MockToken mock(g_selfShellTokenId, "accesstoken_service", false);
    mock.Grant(DISABLE_PERMISSION_DIALOG);
    mock.Grant(GET_SENSITIVE_PERMISSIONS);
    uint32_t status = PermissionRequestToggleStatus::OPEN;
    ASSERT_EQ(RET_SUCCESS, atManagerService_->SetPermissionRequestToggleStatus(
        "ohos.permission.CAMERA", status, USER_ID, 0));
    status = PermissionRequestToggleStatus::CLOSED;
    ASSERT_EQ(RET_SUCCESS, atManagerService_->GetPermissionRequestToggleStatus(
        "ohos.permission.CAMERA", status, USER_ID, 0));
    EXPECT_EQ(PermissionRequestToggleStatus::OPEN, status);
}

/**
 * @tc.name: ToggleRequestService002
 * @tc.desc: Verify request toggle succeeds with the caller user ID for non-root caller.
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(AccessTokenManagerServiceTest, ToggleRequestService002, TestSize.Level0)
{
    PermissionRequestToggleStatusGuard toggleGuard(0, "ohos.permission.CAMERA");
    OsAccountMockGuard mockGuard;
    SetMockOsAccountLocalIdForSubProfile(0, ERR_OK);
    MockToken mock(g_selfShellTokenId, "accesstoken_service", false);
    mock.Grant(DISABLE_PERMISSION_DIALOG);
    mock.Grant(GET_SENSITIVE_PERMISSIONS);
    UidGuard uidGuard(NON_ROOT_UID);
    uint32_t status = PermissionRequestToggleStatus::OPEN;
    ASSERT_EQ(RET_SUCCESS, atManagerService_->SetPermissionRequestToggleStatus(
        "ohos.permission.CAMERA", status, 0, 0));
    status = PermissionRequestToggleStatus::CLOSED;
    ASSERT_EQ(RET_SUCCESS, atManagerService_->GetPermissionRequestToggleStatus(
        "ohos.permission.CAMERA", status, 0, 0));
    EXPECT_EQ(PermissionRequestToggleStatus::OPEN, status);
}
} // namespace AccessToken
} // namespace Security
} // namespace OHOS
