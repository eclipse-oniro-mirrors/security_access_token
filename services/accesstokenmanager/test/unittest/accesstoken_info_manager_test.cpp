/*
 * Copyright (c) 2021-2022 Huawei Device Co., Ltd.
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

#include "accesstoken_info_manager_test.h"

#include <fcntl.h>
#include <gmock/gmock.h>

#include "accesstoken_id_manager.h"
#include "access_token_error.h"
#define private public
#include "accesstoken_callback_stubs.h"
#include "accesstoken_info_manager.h"
#include "accesstoken_remote_token_manager.h"
#include "libraryloader.h"
#include "token_field_const.h"
#ifdef TOKEN_SYNC_ENABLE
#include "token_sync_kit_loader.h"
#endif
#include "permission_manager.h"
#include "token_modify_notifier.h"
#undef private
#include "permission_validator.h"
#include "string_ex.h"
#include "token_setproc.h"
#include "system_ability_definition.h"

using namespace testing::ext;
using namespace OHOS;

namespace OHOS {
namespace Security {
namespace AccessToken {
namespace {
static constexpr int32_t DEFAULT_API_VERSION = 8;
static constexpr int USER_ID = 100;
static constexpr int INST_INDEX = 0;
static constexpr int32_t MAX_EXTENDED_MAP_SIZE = 512;
static constexpr int32_t MAX_VALUE_LENGTH = 1024;
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

static PermissionStatus g_permState = {
    .permissionName = "ohos.permission.CAMERA",
    .grantStatus = PermissionState::PERMISSION_DENIED,
    .grantFlag = PermissionFlag::PERMISSION_DEFAULT_FLAG
};

#ifdef TOKEN_SYNC_ENABLE
static uint32_t tokenSyncId_ = 0;
static const int32_t FAKE_SYNC_RET = 0xabcdef;
class TokenSyncCallbackMock : public TokenSyncCallbackStub {
public:
    TokenSyncCallbackMock() = default;
    virtual ~TokenSyncCallbackMock() = default;

    MOCK_METHOD(int32_t, GetRemoteHapTokenInfo, (const std::string&, AccessTokenID), (override));
    MOCK_METHOD(int32_t, DeleteRemoteHapTokenInfo, (AccessTokenID), (override));
    MOCK_METHOD(int32_t, UpdateRemoteHapTokenInfo, (const HapTokenInfoForSync&), (override));
};
#endif
}

void AccessTokenInfoManagerTest::SetUpTestCase()
{
    g_selfTokenId = GetSelfTokenID();
    uint32_t hapSize = 0;
    uint32_t nativeSize = 0;
    uint32_t pefDefSize = 0;
    uint32_t dlpSize = 0;
    std::map<int32_t, int32_t> tokenIdAplMap;
    AccessTokenInfoManager::GetInstance().Init(hapSize, nativeSize, pefDefSize, dlpSize, tokenIdAplMap);
}

void AccessTokenInfoManagerTest::TearDownTestCase()
{
    sleep(3); // delay 3 minutes
    SetSelfTokenID(g_selfTokenId);
}

void AccessTokenInfoManagerTest::SetUp()
{
    atManagerService_ = DelayedSingleton<AccessTokenManagerService>::GetInstance();
    EXPECT_NE(nullptr, atManagerService_);
}

void AccessTokenInfoManagerTest::TearDown()
{
    atManagerService_ = nullptr;
}

/**
 * @tc.name: HapTokenInfoInner001
 * @tc.desc: HapTokenInfoInner::HapTokenInfoInner.
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(AccessTokenInfoManagerTest, HapTokenInfoInner001, TestSize.Level0)
{
    AccessTokenID id = 0x20240112;
    HapTokenInfo info = {
        .ver = 1,
        .userID = 1,
        .bundleName = "com.ohos.access_token",
        .instIndex = 1,
        .tokenID = id,
        .tokenAttr = 0
    };
    std::vector<PermissionStatus> permStateList;
    std::shared_ptr<HapTokenInfoInner> hap = std::make_shared<HapTokenInfoInner>(id, info, permStateList);
    ASSERT_EQ(hap->IsRemote(), false);
    hap->SetRemote(true);
    std::vector<GenericValues> valueList;
    hap->StoreHapInfo(valueList, "test", APL_NORMAL);

    hap->StorePermissionPolicy(valueList);
    ASSERT_EQ(hap->IsRemote(), true);
    hap->SetRemote(false);
    int32_t version = hap->GetApiVersion(5608);
    ASSERT_EQ(static_cast<int32_t>(608), version);
}

/**
 * @tc.name: CreateHapTokenInfo001
 * @tc.desc: Verify the CreateHapTokenInfo add one hap token function.
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(AccessTokenInfoManagerTest, CreateHapTokenInfo001, TestSize.Level0)
{
    AccessTokenIDEx tokenIdEx = {0};
    std::vector<GenericValues> undefValues;
    int ret = AccessTokenInfoManager::GetInstance().CreateHapTokenInfo(g_infoManagerTestInfoParms,
        g_infoManagerTestPolicyPrams1, tokenIdEx, undefValues);
    ASSERT_EQ(RET_SUCCESS, ret);
    GTEST_LOG_(INFO) << "add a hap token";

    std::shared_ptr<HapTokenInfoInner> tokenInfo;
    tokenInfo = AccessTokenInfoManager::GetInstance().GetHapTokenInfoInner(tokenIdEx.tokenIdExStruct.tokenID);
    ASSERT_NE(nullptr, tokenInfo);
    std::string infoDes;
    tokenInfo->ToString(infoDes);
    GTEST_LOG_(INFO) << "get hap token info:" << infoDes.c_str();

    ret = AccessTokenInfoManager::GetInstance().RemoveHapTokenInfo(tokenIdEx.tokenIdExStruct.tokenID);
    ASSERT_EQ(RET_SUCCESS, ret);
    GTEST_LOG_(INFO) << "remove the token info";

    tokenInfo = AccessTokenInfoManager::GetInstance().GetHapTokenInfoInner(tokenIdEx.tokenIdExStruct.tokenID);
    ASSERT_EQ(nullptr, tokenInfo);
}

/**
 * @tc.name: CreateHapTokenInfo002
 * @tc.desc: Verify the CreateHapTokenInfo add one hap token twice function.
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(AccessTokenInfoManagerTest, CreateHapTokenInfo002, TestSize.Level0)
{
    AccessTokenIDEx tokenIdEx = {0};
    std::vector<GenericValues> undefValues;
    int ret = AccessTokenInfoManager::GetInstance().CreateHapTokenInfo(g_infoManagerTestInfoParms,
        g_infoManagerTestPolicyPrams1, tokenIdEx, undefValues);
    ASSERT_EQ(RET_SUCCESS, ret);
    GTEST_LOG_(INFO) << "add a hap token";

    AccessTokenIDEx tokenIdEx1 = {0};
    ret = AccessTokenInfoManager::GetInstance().CreateHapTokenInfo(g_infoManagerTestInfoParms,
        g_infoManagerTestPolicyPrams1, tokenIdEx1, undefValues);
    ASSERT_EQ(RET_SUCCESS, ret);
    ASSERT_NE(tokenIdEx.tokenIdExStruct.tokenID, tokenIdEx1.tokenIdExStruct.tokenID);
    GTEST_LOG_(INFO) << "add same hap token";

    std::shared_ptr<HapTokenInfoInner> tokenInfo;
    tokenInfo = AccessTokenInfoManager::GetInstance().GetHapTokenInfoInner(tokenIdEx1.tokenIdExStruct.tokenID);
    ASSERT_NE(nullptr, tokenInfo);

    std::string infoDes;
    tokenInfo->ToString(infoDes);
    GTEST_LOG_(INFO) << "get hap token info:" << infoDes.c_str();

    ret = AccessTokenInfoManager::GetInstance().RemoveHapTokenInfo(tokenIdEx1.tokenIdExStruct.tokenID);
    ASSERT_EQ(RET_SUCCESS, ret);
    GTEST_LOG_(INFO) << "remove the token info";
}

/**
 * @tc.name: CreateHapTokenInfo003
 * @tc.desc: AccessTokenInfoManager::CreateHapTokenInfo function test userID invalid
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(AccessTokenInfoManagerTest, CreateHapTokenInfo003, TestSize.Level0)
{
    HapInfoParams info = {
        .userID = -1
    };
    HapPolicy policy;
    AccessTokenIDEx tokenIdEx;
    std::vector<GenericValues> undefValues;

    ASSERT_NE(RET_SUCCESS, AccessTokenInfoManager::GetInstance().CreateHapTokenInfo(info, policy, tokenIdEx,
        undefValues));
}

/**
 * @tc.name: CreateHapTokenInfo004
 * @tc.desc: AccessTokenInfoManager::CreateHapTokenInfo function test bundleName invalid
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(AccessTokenInfoManagerTest, CreateHapTokenInfo004, TestSize.Level0)
{
    HapInfoParams info = {
        .userID = USER_ID,
        .bundleName = ""
    };
    HapPolicy policy;
    AccessTokenIDEx tokenIdEx;
    std::vector<GenericValues> undefValues;

    ASSERT_NE(RET_SUCCESS, AccessTokenInfoManager::GetInstance().CreateHapTokenInfo(info, policy, tokenIdEx,
        undefValues));
}

/**
 * @tc.name: CreateHapTokenInfo005
 * @tc.desc: AccessTokenInfoManager::CreateHapTokenInfo function test appIDDesc invalid
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(AccessTokenInfoManagerTest, CreateHapTokenInfo005, TestSize.Level0)
{
    HapInfoParams info = {
        .userID = USER_ID,
        .bundleName = "ohos.com.testtesttest",
        .appIDDesc = ""
    };
    HapPolicy policy;
    AccessTokenIDEx tokenIdEx;
    std::vector<GenericValues> undefValues;

    ASSERT_NE(RET_SUCCESS, AccessTokenInfoManager::GetInstance().CreateHapTokenInfo(info, policy, tokenIdEx,
        undefValues));
}

/**
 * @tc.name: CreateHapTokenInfo006
 * @tc.desc: AccessTokenInfoManager::CreateHapTokenInfo function test domain invalid
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(AccessTokenInfoManagerTest, CreateHapTokenInfo006, TestSize.Level0)
{
    HapInfoParams info = {
        .userID = USER_ID,
        .bundleName = "ohos.com.testtesttest",
        .appIDDesc = "who cares"
    };
    HapPolicy policy = {
        .domain = ""
    };
    AccessTokenIDEx tokenIdEx;
    std::vector<GenericValues> undefValues;

    ASSERT_NE(RET_SUCCESS, AccessTokenInfoManager::GetInstance().CreateHapTokenInfo(info, policy, tokenIdEx,
        undefValues));
}

/**
 * @tc.name: CreateHapTokenInfo007
 * @tc.desc: AccessTokenInfoManager::CreateHapTokenInfo function test dlpType invalid
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(AccessTokenInfoManagerTest, CreateHapTokenInfo007, TestSize.Level0)
{
    HapInfoParams info = {
        .userID = USER_ID,
        .bundleName = "ohos.com.testtesttest",
        .dlpType = -1,
        .appIDDesc = "who cares"
    };
    HapPolicy policy = {
        .domain = "who cares"
    };
    AccessTokenIDEx tokenIdEx;
    std::vector<GenericValues> undefValues;

    ASSERT_NE(RET_SUCCESS, AccessTokenInfoManager::GetInstance().CreateHapTokenInfo(info, policy, tokenIdEx,
        undefValues));
}

/**
 * @tc.name: CreateHapTokenInfo008
 * @tc.desc: AccessTokenInfoManager::CreateHapTokenInfo function test grant mode invalid
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(AccessTokenInfoManagerTest, CreateHapTokenInfo008, TestSize.Level0)
{
    static PermissionDef permDef = {
        .permissionName = "ohos.permission.test",
        .bundleName = "accesstoken_test",
        .grantMode = -1,    // -1:invalid grant mode
        .availableLevel = APL_NORMAL,
        .provisionEnable = false,
        .distributedSceneEnable = false,
        .label = "label",
        .labelId = 1,
        .description = "open the door",
        .descriptionId = 1
    };
    HapInfoParams info = {
        .userID = USER_ID,
        .bundleName = "ohos.com.testtesttest",
        .appIDDesc = ""
    };
    HapPolicy policy = {
        .apl = APL_NORMAL,
        .domain = "test.domain",
        .permList = {permDef}
    };
    AccessTokenIDEx tokenIdEx;
    std::vector<GenericValues> undefValues;
    ASSERT_NE(RET_SUCCESS, AccessTokenInfoManager::GetInstance().CreateHapTokenInfo(info, policy, tokenIdEx,
        undefValues));
}

/**
 * @tc.name: InitHapToken001
 * @tc.desc: InitHapToken function test with invalid userID
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(AccessTokenInfoManagerTest, InitHapToken001, TestSize.Level0)
{
    HapInfoParcel hapinfoParcel;
    hapinfoParcel.hapInfoParameter = {
        .userID = -1,
        .bundleName = "accesstoken_test",
        .instIndex = 0,
        .dlpType = DLP_COMMON,
        .appIDDesc = "testtesttesttest",
        .apiVersion = DEFAULT_API_VERSION,
        .isSystemApp = false,
    };
    HapPolicyParcel hapPolicyParcel;
    hapPolicyParcel.hapPolicy.apl = ATokenAplEnum::APL_NORMAL;
    hapPolicyParcel.hapPolicy.domain = "test.domain";
    uint64_t fullTokenId;
    HapInfoCheckResultIdl result;
    ASSERT_EQ(ERR_PARAM_INVALID,
        atManagerService_->InitHapToken(hapinfoParcel, hapPolicyParcel, fullTokenId, result));
}

/**
 * @tc.name: InitHapToken002
 * @tc.desc: InitHapToken function test with invalid userID
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(AccessTokenInfoManagerTest, InitHapToken002, TestSize.Level0)
{
    HapInfoParcel hapinfoParcel;
    hapinfoParcel.hapInfoParameter = {
        .userID = -1,
        .bundleName = "accesstoken_test",
        .instIndex = 0,
        .dlpType = DLP_READ,
        .appIDDesc = "testtesttesttest",
        .apiVersion = DEFAULT_API_VERSION,
        .isSystemApp = false,
    };
    HapPolicyParcel hapPolicyParcel;
    hapPolicyParcel.hapPolicy.apl = ATokenAplEnum::APL_NORMAL;
    hapPolicyParcel.hapPolicy.domain = "test.domain";
    uint64_t fullTokenId;
    HapInfoCheckResultIdl result;
    ASSERT_EQ(ERR_PERM_REQUEST_CFG_FAILED,
        atManagerService_->InitHapToken(hapinfoParcel, hapPolicyParcel, fullTokenId, result));
}

/**
 * @tc.name: InitHapToken003
 * @tc.desc: InitHapToken function test with invalid apl permission
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(AccessTokenInfoManagerTest, InitHapToken003, TestSize.Level0)
{
    HapInfoParcel info;
    info.hapInfoParameter = {
        .userID = 0,
        .bundleName = "accesstoken_test",
        .instIndex = 0,
        .dlpType = DLP_COMMON,
        .appIDDesc = "testtesttesttest",
        .apiVersion = DEFAULT_API_VERSION,
        .isSystemApp = false,
    };
    HapPolicyParcel policy;
    PermissionStatus permissionStateA = {
        .permissionName = "ohos.permission.GET_ALL_APP_ACCOUNTS",
        .grantStatus = 1,
        .grantFlag = 1
    };
    PermissionStatus permissionStateB = {
        .permissionName = "ohos.permission.test",
        .grantStatus = 1,
        .grantFlag = 1
    };
    policy.hapPolicy = {
        .apl = APL_NORMAL,
        .domain = "test",
        .permList = {},
        .permStateList = { permissionStateA, permissionStateB }
    };
    uint64_t fullTokenId;;
    HapInfoCheckResultIdl resultInfoIdl;
    HapInfoCheckResult result;

    ASSERT_EQ(0,
        atManagerService_->InitHapToken(info, policy, fullTokenId, resultInfoIdl));

    PermissionInfoCheckResult permCheckResult;
    permCheckResult.permissionName = resultInfoIdl.permissionName;
    int32_t rule = static_cast<int32_t>(resultInfoIdl.rule);
    permCheckResult.rule = PermissionRulesEnum(rule);
    result.permCheckResult = permCheckResult;
    ASSERT_EQ(result.permCheckResult.permissionName, "ohos.permission.GET_ALL_APP_ACCOUNTS");
    ASSERT_EQ(result.permCheckResult.rule, PERMISSION_ACL_RULE);
    permissionStateA.permissionName = "ohos.permission.ENTERPRISE_MANAGE_SETTINGS";
    policy.hapPolicy.aclRequestedList = { "ohos.permission.ENTERPRISE_MANAGE_SETTINGS" };
    policy.hapPolicy.permStateList = { permissionStateA, permissionStateB };
    ASSERT_EQ(0,
        atManagerService_->InitHapToken(info, policy, fullTokenId, resultInfoIdl));

    ASSERT_EQ(resultInfoIdl.permissionName, "ohos.permission.ENTERPRISE_MANAGE_SETTINGS");
    rule = static_cast<int32_t>(resultInfoIdl.rule);
    ASSERT_EQ(PermissionRulesEnum(rule), PERMISSION_EDM_RULE);
}

static void GetHapParams(HapInfoParams& infoParams, HapPolicy& policyParams)
{
    infoParams.userID = 0;
    infoParams.bundleName = "com.ohos.AccessTokenTestBundle";
    infoParams.instIndex = 0;
    infoParams.appIDDesc = "AccessTokenTestAppID";
    infoParams.apiVersion = DEFAULT_API_VERSION;
    infoParams.isSystemApp = true;
    infoParams.appDistributionType = "";

    policyParams.apl = APL_SYSTEM_CORE;
    policyParams.domain = "accesstoken_test_domain";
}

void TestPrepareKernelPermissionStatus(HapPolicy& policyParams)
{
    PermissionStatus permissionStatusBasic = {
        .permissionName = "ohos.permission.test_basic",
        .grantStatus = PERMISSION_GRANTED,
        .grantFlag = PERMISSION_SYSTEM_FIXED,
    };

    PermissionStatus PermissionStatus001 = permissionStatusBasic;
    PermissionStatus001.permissionName = "ohos.permission.KERNEL_ATM_SELF_USE";
    PermissionStatus PermissionStatus002 = permissionStatusBasic;
    PermissionStatus002.permissionName = "ohos.permission.MICROPHONE";
    PermissionStatus PermissionStatus003 = permissionStatusBasic;
    PermissionStatus003.permissionName = "ohos.permission.CAMERA";
    policyParams.permStateList = {PermissionStatus001, PermissionStatus002, PermissionStatus003};
    policyParams.aclExtendedMap["ohos.permission.KERNEL_ATM_SELF_USE"] = "123";
    policyParams.aclExtendedMap["ohos.permission.MICROPHONE"] = "456"; // filtered
    policyParams.aclExtendedMap["ohos.permission.CAMERA"] = "789"; // filtered
}

/**
 * @tc.name: InitHapToken004
 * @tc.desc: aclExtendedMap size test
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(AccessTokenInfoManagerTest, InitHapToken004, TestSize.Level0)
{
    HapInfoParcel info;
    HapPolicyParcel policy;
    GetHapParams(info.hapInfoParameter, policy.hapPolicy);

    uint64_t fullTokenId;;
    HapInfoCheckResultIdl result;
    int32_t ret = atManagerService_->InitHapToken(info, policy, fullTokenId, result);
    ASSERT_EQ(RET_SUCCESS, ret);

    for (size_t i = 0; i < MAX_EXTENDED_MAP_SIZE - 1; i++) {
        policy.hapPolicy.aclExtendedMap[std::to_string(i)] = std::to_string(i);
    }
    ret = atManagerService_->InitHapToken(info, policy, fullTokenId, result);
    ASSERT_EQ(RET_SUCCESS, ret);

    policy.hapPolicy.aclExtendedMap[std::to_string(MAX_EXTENDED_MAP_SIZE - 1)] =
        std::to_string(MAX_EXTENDED_MAP_SIZE - 1);
    ret = atManagerService_->InitHapToken(info, policy, fullTokenId, result);
    ASSERT_EQ(RET_SUCCESS, ret);
    AccessTokenIDEx tokenIDEx = {fullTokenId};
    AccessTokenID tokenID = tokenIDEx.tokenIdExStruct.tokenID;

    policy.hapPolicy.aclExtendedMap[std::to_string(MAX_EXTENDED_MAP_SIZE)] =
        std::to_string(MAX_EXTENDED_MAP_SIZE);
    ret = atManagerService_->InitHapToken(info, policy, fullTokenId, result);
    ASSERT_EQ(AccessTokenError::ERR_PARAM_INVALID, ret);

    ret = atManagerService_->DeleteToken(tokenID);
    EXPECT_EQ(RET_SUCCESS, ret);
}

/**
 * @tc.name: InitHapToken005
 * @tc.desc: aclExtendedMap size test
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(AccessTokenInfoManagerTest, InitHapToken005, TestSize.Level0)
{
    HapInfoParcel info;
    HapPolicyParcel policy;
    GetHapParams(info.hapInfoParameter, policy.hapPolicy);

    uint64_t fullTokenId;
    HapInfoCheckResultIdl result;
    policy.hapPolicy.aclExtendedMap["ohos.permission.ACCESS_CERT_MANAGER"] = "";
    int32_t ret = atManagerService_->InitHapToken(info, policy, fullTokenId, result);
    ASSERT_EQ(AccessTokenError::ERR_PARAM_INVALID, ret);

    std::string testValue(MAX_VALUE_LENGTH - 1, '1');
    policy.hapPolicy.aclExtendedMap["ohos.permission.ACCESS_CERT_MANAGER"] = testValue;
    ret = atManagerService_->InitHapToken(info, policy, fullTokenId, result);
    ASSERT_EQ(RET_SUCCESS, ret);

    testValue.push_back('1');
    policy.hapPolicy.aclExtendedMap["ohos.permission.ACCESS_CERT_MANAGER"] = testValue;
    ret = atManagerService_->InitHapToken(info, policy, fullTokenId, result);
    ASSERT_EQ(RET_SUCCESS, ret);
    AccessTokenIDEx tokenIDEx = {fullTokenId};
    AccessTokenID tokenID = tokenIDEx.tokenIdExStruct.tokenID;

    testValue.push_back('1');
    policy.hapPolicy.aclExtendedMap["ohos.permission.ACCESS_CERT_MANAGER"] = testValue;
    ret = atManagerService_->InitHapToken(info, policy, fullTokenId, result);
    ASSERT_EQ(AccessTokenError::ERR_PARAM_INVALID, ret);

    ret = atManagerService_->DeleteToken(tokenID);
    EXPECT_EQ(RET_SUCCESS, ret);
}

/**
 * @tc.name: InitHapToken006
 * @tc.desc: InitHapToken permission with value
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(AccessTokenInfoManagerTest, InitHapToken006, TestSize.Level0)
{
    HapInfoParcel info;
    HapPolicyParcel policy;
    GetHapParams(info.hapInfoParameter, policy.hapPolicy);
    uint64_t fullTokenId;
    HapInfoCheckResultIdl result;

    TestPrepareKernelPermissionStatus(policy.hapPolicy);
    ASSERT_EQ(RET_SUCCESS, atManagerService_->InitHapToken(info, policy, fullTokenId, result));
    AccessTokenID tokenID = static_cast<AccessTokenID>(fullTokenId);

    std::vector<PermissionWithValueIdl> kernelPermList;
    EXPECT_EQ(RET_SUCCESS, atManagerService_->GetKernelPermissions(tokenID, kernelPermList));
    EXPECT_EQ(1, kernelPermList.size());

    std::string value;
    EXPECT_EQ(RET_SUCCESS, atManagerService_->GetReqPermissionByName(
        tokenID, "ohos.permission.KERNEL_ATM_SELF_USE", value));
    EXPECT_EQ("123", value);

    EXPECT_EQ(AccessTokenError::ERR_PERMISSION_WITHOUT_VALUE, atManagerService_->GetReqPermissionByName(
        tokenID, "ohos.permission.MICROPHONE", value));
    EXPECT_EQ(AccessTokenError::ERR_PERMISSION_WITHOUT_VALUE, atManagerService_->GetReqPermissionByName(
        tokenID, "ohos.permission.CAMERA", value));

    ASSERT_EQ(RET_SUCCESS, atManagerService_->DeleteToken(tokenID));
}


/**
 * @tc.name: InitHapToken007
 * @tc.desc: InitHapToken app.apl > policy.apl, extended permission not in aclExtendedMap
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(AccessTokenInfoManagerTest, InitHapToken007, TestSize.Level0)
{
    HapInfoParcel info;
    HapPolicyParcel policy;
    GetHapParams(info.hapInfoParameter, policy.hapPolicy);
    uint64_t fullTokenId;
    HapInfoCheckResultIdl result;

    TestPrepareKernelPermissionStatus(policy.hapPolicy);
    policy.hapPolicy.aclExtendedMap.erase("ohos.permission.KERNEL_ATM_SELF_USE");
    ASSERT_EQ(RET_SUCCESS, atManagerService_->InitHapToken(info, policy, fullTokenId, result));
    AccessTokenID tokenID = static_cast<AccessTokenID>(fullTokenId);

    std::vector<PermissionWithValueIdl> kernelPermList;
    EXPECT_EQ(RET_SUCCESS, atManagerService_->GetKernelPermissions(tokenID, kernelPermList));
    EXPECT_EQ(1, kernelPermList.size());

    std::string value;
    EXPECT_EQ(RET_SUCCESS, atManagerService_->GetReqPermissionByName(
        tokenID, "ohos.permission.KERNEL_ATM_SELF_USE", value));
    EXPECT_EQ("", value);

    ASSERT_EQ(RET_SUCCESS, atManagerService_->DeleteToken(tokenID));
}

/**
 * @tc.name: IsTokenIdExist001
 * @tc.desc: Verify the IsTokenIdExist exist accesstokenid.
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(AccessTokenInfoManagerTest, IsTokenIdExist001, TestSize.Level0)
{
    AccessTokenID testId = 1;
    ASSERT_EQ(AccessTokenInfoManager::GetInstance().IsTokenIdExist(testId), false);
}

/**
 * @tc.name: GetHapTokenInfo001
 * @tc.desc: Verify the GetHapTokenInfo abnormal and normal branch.
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(AccessTokenInfoManagerTest, GetHapTokenInfo001, TestSize.Level0)
{
    AccessTokenIDEx tokenIdEx = {0};
    int result;
    HapTokenInfo hapInfo;
    result = AccessTokenInfoManager::GetInstance().GetHapTokenInfo(tokenIdEx.tokenIdExStruct.tokenID, hapInfo);
    ASSERT_EQ(result, ERR_TOKENID_NOT_EXIST);

    std::vector<GenericValues> undefValues;
    result = AccessTokenInfoManager::GetInstance().CreateHapTokenInfo(
        g_infoManagerTestInfoParms, g_infoManagerTestPolicyPrams1, tokenIdEx, undefValues);
    ASSERT_EQ(RET_SUCCESS, result);
    GTEST_LOG_(INFO) << "add a hap token";
    result = AccessTokenInfoManager::GetInstance().GetHapTokenInfo(tokenIdEx.tokenIdExStruct.tokenID, hapInfo);
    ASSERT_EQ(result, RET_SUCCESS);
    result = AccessTokenInfoManager::GetInstance().RemoveHapTokenInfo(tokenIdEx.tokenIdExStruct.tokenID);
    ASSERT_EQ(RET_SUCCESS, result);
    GTEST_LOG_(INFO) << "remove the token info";
}

/**
 * @tc.name: RemoveHapTokenInfo001
 * @tc.desc: Verify the RemoveHapTokenInfo abnormal branch tokenID type is not true.
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(AccessTokenInfoManagerTest, RemoveHapTokenInfo001, TestSize.Level0)
{
    AccessTokenIDEx tokenIdEx = {0};
    // type != TOKEN_HAP
    ASSERT_EQ(
        ERR_PARAM_INVALID, AccessTokenInfoManager::GetInstance().RemoveHapTokenInfo(tokenIdEx.tokenIdExStruct.tokenID));

    AccessTokenID tokenId = 537919487; // 537919487 is max hap tokenId: 001 00 0 000000 11111111111111111111
    ASSERT_EQ(RET_SUCCESS, AccessTokenIDManager::GetInstance().RegisterTokenId(tokenId, TOKEN_HAP));
    // hapTokenInfoMap_.count(id) == 0
    ASSERT_EQ(ERR_TOKENID_NOT_EXIST, AccessTokenInfoManager::GetInstance().RemoveHapTokenInfo(tokenId));

    ASSERT_EQ(RET_SUCCESS, AccessTokenIDManager::GetInstance().RegisterTokenId(tokenId, TOKEN_HAP));
    AccessTokenInfoManager::GetInstance().hapTokenInfoMap_[tokenId] = nullptr;
    ASSERT_EQ(ERR_TOKEN_INVALID, AccessTokenInfoManager::GetInstance().RemoveHapTokenInfo(tokenId)); // info == nullptr
    AccessTokenInfoManager::GetInstance().hapTokenInfoMap_.erase(tokenId);

    std::shared_ptr<HapTokenInfoInner> info = std::make_shared<HapTokenInfoInner>();
    info->tokenInfoBasic_.userID = USER_ID;
    info->tokenInfoBasic_.bundleName = "com.ohos.TEST";
    info->tokenInfoBasic_.instIndex = INST_INDEX;
    AccessTokenInfoManager::GetInstance().hapTokenInfoMap_[tokenId] = info;
    ASSERT_EQ(RET_SUCCESS, AccessTokenIDManager::GetInstance().RegisterTokenId(tokenId, TOKEN_HAP));
    // count(HapUniqueKey) == 0
    ASSERT_EQ(RET_SUCCESS, AccessTokenInfoManager::GetInstance().RemoveHapTokenInfo(tokenId));

    ASSERT_EQ(RET_SUCCESS, AccessTokenIDManager::GetInstance().RegisterTokenId(tokenId, TOKEN_HAP)); // removed above
    AccessTokenID tokenId2 = 537919486; // 537919486: 001 00 0 000000 11111111111111111110
    AccessTokenInfoManager::GetInstance().hapTokenInfoMap_[tokenId] = info;
    std::string hapUniqueKey = "com.ohos.TEST&" + std::to_string(USER_ID) + "&" + std::to_string(INST_INDEX);
    AccessTokenInfoManager::GetInstance().hapTokenIdMap_[hapUniqueKey] = tokenId2;
    // hapTokenIdMap_[HapUniqueKey] != id
    ASSERT_EQ(RET_SUCCESS, AccessTokenInfoManager::GetInstance().RemoveHapTokenInfo(tokenId));
    AccessTokenInfoManager::GetInstance().hapTokenIdMap_.erase(hapUniqueKey);
}

/**
 * @tc.name: GetHapTokenID001
 * @tc.desc: Verify the GetHapTokenID by userID/bundleName/instIndex, function.
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(AccessTokenInfoManagerTest, GetHapTokenID001, TestSize.Level0)
{
    AccessTokenIDEx tokenIdEx = {0};
    std::vector<GenericValues> undefValues;
    int ret = AccessTokenInfoManager::GetInstance().CreateHapTokenInfo(g_infoManagerTestInfoParms,
        g_infoManagerTestPolicyPrams1, tokenIdEx, undefValues);
    ASSERT_EQ(RET_SUCCESS, ret);
    GTEST_LOG_(INFO) << "add a hap token";

    tokenIdEx = AccessTokenInfoManager::GetInstance().GetHapTokenID(g_infoManagerTestInfoParms.userID,
        g_infoManagerTestInfoParms.bundleName, g_infoManagerTestInfoParms.instIndex);
    ASSERT_NE(INVALID_TOKENID, tokenIdEx.tokenIdExStruct.tokenID);
    GTEST_LOG_(INFO) << "find hap info";

    std::shared_ptr<HapTokenInfoInner> tokenInfo;
    tokenInfo = AccessTokenInfoManager::GetInstance().GetHapTokenInfoInner(tokenIdEx.tokenIdExStruct.tokenID);
    ASSERT_NE(nullptr, tokenInfo);
    GTEST_LOG_(INFO) << "remove the token info";

    ret = AccessTokenInfoManager::GetInstance().RemoveHapTokenInfo(tokenIdEx.tokenIdExStruct.tokenID);
    ASSERT_EQ(RET_SUCCESS, ret);
    GTEST_LOG_(INFO) << "remove the token info";
}

/**
 * @tc.name: UpdateHapToken001
 * @tc.desc: Verify the UpdateHapToken token function.
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(AccessTokenInfoManagerTest, UpdateHapToken001, TestSize.Level0)
{
    AccessTokenIDEx tokenIdEx = {0};
    std::vector<GenericValues> undefValues;
    int ret = AccessTokenInfoManager::GetInstance().CreateHapTokenInfo(g_infoManagerTestInfoParms,
        g_infoManagerTestPolicyPrams1, tokenIdEx, undefValues);
    ASSERT_EQ(RET_SUCCESS, ret);
    GTEST_LOG_(INFO) << "add a hap token";

    HapPolicy policy = g_infoManagerTestPolicyPrams1;
    policy.apl = APL_SYSTEM_BASIC;
    UpdateHapInfoParams info;
    info.appIDDesc = std::string("updateAppId");
    info.apiVersion = DEFAULT_API_VERSION;
    info.isSystemApp = false;
    ret = AccessTokenInfoManager::GetInstance().UpdateHapToken(
        tokenIdEx, info, policy.permStateList, policy, undefValues);
    ASSERT_EQ(RET_SUCCESS, ret);
    GTEST_LOG_(INFO) << "update the hap token";

    std::shared_ptr<HapTokenInfoInner> tokenInfo;
    tokenInfo = AccessTokenInfoManager::GetInstance().GetHapTokenInfoInner(tokenIdEx.tokenIdExStruct.tokenID);
    ASSERT_NE(nullptr, tokenInfo);
    std::string infoDes;
    tokenInfo->ToString(infoDes);
    GTEST_LOG_(INFO) << "get hap token info:" << infoDes.c_str();

    ret = AccessTokenInfoManager::GetInstance().RemoveHapTokenInfo(tokenIdEx.tokenIdExStruct.tokenID);
    ASSERT_EQ(RET_SUCCESS, ret);
    GTEST_LOG_(INFO) << "remove the token info";
}

/**
 * @tc.name: UpdateHapToken002
 * @tc.desc: Verify the UpdateHapToken token function abnormal branch.
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(AccessTokenInfoManagerTest, UpdateHapToken002, TestSize.Level0)
{
    AccessTokenIDEx tokenIdEx = {0};
    HapPolicy policy = g_infoManagerTestPolicyPrams1;
    policy.apl = APL_SYSTEM_BASIC;
    UpdateHapInfoParams info;
    info.appIDDesc = std::string("");
    info.apiVersion = DEFAULT_API_VERSION;
    info.isSystemApp = false;
    std::vector<GenericValues> undefValues;
    int ret = AccessTokenInfoManager::GetInstance().UpdateHapToken(
        tokenIdEx, info, policy.permStateList, policy, undefValues);
    ASSERT_EQ(ERR_PARAM_INVALID, ret);

    info.appIDDesc = std::string("updateAppId");
    ret = AccessTokenInfoManager::GetInstance().UpdateHapToken(
        tokenIdEx, info, policy.permStateList, policy, undefValues);
    ASSERT_EQ(ERR_TOKENID_NOT_EXIST, ret);
}

/**
 * @tc.name: UpdateHapToken003
 * @tc.desc: AccessTokenInfoManager::UpdateHapToken function test IsRemote_ true
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(AccessTokenInfoManagerTest, UpdateHapToken003, TestSize.Level0)
{
    AccessTokenID tokenId = 537919487; // 537919487 is max hap tokenId: 001 00 0 000000 11111111111111111111
    AccessTokenIDEx tokenIdEx = {0};
    tokenIdEx.tokenIdExStruct.tokenID = tokenId;
    std::shared_ptr<HapTokenInfoInner> info = std::make_shared<HapTokenInfoInner>();
    info->isRemote_ = true;
    AccessTokenInfoManager::GetInstance().hapTokenInfoMap_[tokenId] = info;
    HapPolicy policy;
    UpdateHapInfoParams hapInfoParams;
    hapInfoParams.appIDDesc = "who cares";
    hapInfoParams.apiVersion = DEFAULT_API_VERSION;
    hapInfoParams.isSystemApp = false;
    std::vector<GenericValues> undefValues;
    ASSERT_EQ(ERR_IDENTITY_CHECK_FAILED, AccessTokenInfoManager::GetInstance().UpdateHapToken(
        tokenIdEx, hapInfoParams, policy.permStateList, policy, undefValues));
    AccessTokenInfoManager::GetInstance().hapTokenInfoMap_.erase(tokenId);
}

/**
 * @tc.name: UpdateHapToken004
 * @tc.desc: UpdateHapToken permission with value
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(AccessTokenInfoManagerTest, UpdateHapToken004, TestSize.Level0)
{
    HapInfoParcel info;
    HapPolicyParcel policy;
    GetHapParams(info.hapInfoParameter, policy.hapPolicy);
    uint64_t fullTokenId;
    HapInfoCheckResultIdl result;

    TestPrepareKernelPermissionStatus(policy.hapPolicy);
    ASSERT_EQ(RET_SUCCESS, atManagerService_->InitHapToken(info, policy, fullTokenId, result));
    AccessTokenID tokenID = static_cast<AccessTokenID>(fullTokenId);

    policy.hapPolicy.aclExtendedMap["ohos.permission.KERNEL_ATM_SELF_USE"] = "1"; // modified value
    UpdateHapInfoParamsIdl updateInfoParams = {
        .appIDDesc = "AccessTokenTestAppID",
        .apiVersion = DEFAULT_API_VERSION,
        .isSystemApp = true,
        .appDistributionType = "",
    };
    EXPECT_EQ(RET_SUCCESS, atManagerService_->UpdateHapToken(fullTokenId, updateInfoParams, policy, result));

    std::vector<PermissionWithValueIdl> kernelPermList;
    EXPECT_EQ(RET_SUCCESS, atManagerService_->GetKernelPermissions(tokenID, kernelPermList));
    EXPECT_EQ(1, kernelPermList.size());

    std::string value;
    EXPECT_EQ(RET_SUCCESS, atManagerService_->GetReqPermissionByName(
        tokenID, "ohos.permission.KERNEL_ATM_SELF_USE", value));
    EXPECT_EQ("1", value);

    EXPECT_EQ(AccessTokenError::ERR_PERMISSION_WITHOUT_VALUE, atManagerService_->GetReqPermissionByName(
        tokenID, "ohos.permission.MICROPHONE", value));
    EXPECT_EQ(AccessTokenError::ERR_PERMISSION_WITHOUT_VALUE, atManagerService_->GetReqPermissionByName(
        tokenID, "ohos.permission.CAMERA", value));

    ASSERT_EQ(RET_SUCCESS, atManagerService_->DeleteToken(tokenID));
}


#ifdef TOKEN_SYNC_ENABLE
/**
 * @tc.name: GetHapTokenSync001
 * @tc.desc: Verify the GetHapTokenSync token function and abnormal branch.
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(AccessTokenInfoManagerTest, GetHapTokenSync001, TestSize.Level0)
{
    AccessTokenIDEx tokenIdEx = {0};
    int result;
    std::vector<GenericValues> undefValues;
    result = AccessTokenInfoManager::GetInstance().CreateHapTokenInfo(
        g_infoManagerTestInfoParms, g_infoManagerTestPolicyPrams1, tokenIdEx, undefValues);
    ASSERT_EQ(RET_SUCCESS, result);
    GTEST_LOG_(INFO) << "add a hap token";

    HapTokenInfoForSync hapSync;
    result = AccessTokenInfoManager::GetInstance().GetHapTokenSync(tokenIdEx.tokenIdExStruct.tokenID, hapSync);
    ASSERT_EQ(result, RET_SUCCESS);

    result = AccessTokenInfoManager::GetInstance().RemoveHapTokenInfo(tokenIdEx.tokenIdExStruct.tokenID);
    ASSERT_EQ(RET_SUCCESS, result);
    GTEST_LOG_(INFO) << "remove the token info";

    result = AccessTokenInfoManager::GetInstance().GetHapTokenSync(tokenIdEx.tokenIdExStruct.tokenID, hapSync);
    ASSERT_NE(result, RET_SUCCESS);
}

/**
 * @tc.name: GetHapTokenSync002
 * @tc.desc: AccessTokenInfoManager::GetHapTokenSync function test permSetPtr is null
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(AccessTokenInfoManagerTest, GetHapTokenSync002, TestSize.Level0)
{
    AccessTokenID tokenId = 537919487; // 537919487 is max hap tokenId: 001 00 0 000000 11111111111111111111
    std::shared_ptr<HapTokenInfoInner> info = std::make_shared<HapTokenInfoInner>();
    AccessTokenInfoManager::GetInstance().hapTokenInfoMap_[tokenId] = info;
    HapTokenInfoForSync hapSync;
    ASSERT_NE(0, AccessTokenInfoManager::GetInstance().GetHapTokenSync(tokenId, hapSync));
    AccessTokenInfoManager::GetInstance().hapTokenInfoMap_.erase(tokenId);
}

/**
 * @tc.name: GetHapTokenInfoFromRemote001
 * @tc.desc: Verify the GetHapTokenInfoFromRemote token function .
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(AccessTokenInfoManagerTest, GetHapTokenInfoFromRemote001, TestSize.Level0)
{
    AccessTokenIDEx tokenIdEx = {0};
    std::vector<GenericValues> undefValues;
    int ret = AccessTokenInfoManager::GetInstance().CreateHapTokenInfo(
        g_infoManagerTestInfoParms, g_infoManagerTestPolicyPrams1, tokenIdEx, undefValues);
    ASSERT_EQ(RET_SUCCESS, ret);
    GTEST_LOG_(INFO) << "add a hap token";

    HapTokenInfoForSync hapSync;
    ret = AccessTokenInfoManager::GetInstance().GetHapTokenInfoFromRemote(tokenIdEx.tokenIdExStruct.tokenID, hapSync);
    ASSERT_EQ(ret, RET_SUCCESS);

    ret = AccessTokenInfoManager::GetInstance().RemoveHapTokenInfo(tokenIdEx.tokenIdExStruct.tokenID);
    ASSERT_EQ(RET_SUCCESS, ret);
    GTEST_LOG_(INFO) << "remove the token info";
}

/**
 * @tc.name: RemoteHapTest001001
 * @tc.desc: Verify the RemoteHap token function .
 * @tc.type: FUNC
 * @tc.require: issueI5RJBB
 */
HWTEST_F(AccessTokenInfoManagerTest, RemoteHapTest001, TestSize.Level0)
{
    AccessTokenIDEx tokenIdEx = {0};
    std::vector<GenericValues> undefValues;
    int32_t ret = AccessTokenInfoManager::GetInstance().CreateHapTokenInfo(
        g_infoManagerTestInfoParms, g_infoManagerTestPolicyPrams1, tokenIdEx, undefValues);
    ASSERT_EQ(RET_SUCCESS, ret);
    GTEST_LOG_(INFO) << "add a hap token";

    std::string deviceId = "device_1";
    std::string deviceId2 = "device_2";
    AccessTokenID mapID =
        AccessTokenInfoManager::GetInstance().AllocLocalTokenID(deviceId, tokenIdEx.tokenIdExStruct.tokenID);
    ASSERT_EQ(mapID, 0);
    HapTokenInfoForSync hapSync;
    ret = AccessTokenInfoManager::GetInstance().GetHapTokenInfoFromRemote(tokenIdEx.tokenIdExStruct.tokenID, hapSync);
    ASSERT_EQ(RET_SUCCESS, ret);
    ret = AccessTokenInfoManager::GetInstance().SetRemoteHapTokenInfo(deviceId, hapSync);
    ASSERT_EQ(RET_SUCCESS, ret);
    ret = AccessTokenInfoManager::GetInstance().DeleteRemoteDeviceTokens(deviceId);
    ASSERT_EQ(RET_SUCCESS, ret);
    ret = AccessTokenInfoManager::GetInstance().DeleteRemoteDeviceTokens(deviceId2);
    ASSERT_EQ(ERR_DEVICE_NOT_EXIST, ret);

    ret = AccessTokenInfoManager::GetInstance().RemoveHapTokenInfo(tokenIdEx.tokenIdExStruct.tokenID);
    ASSERT_EQ(RET_SUCCESS, ret);
    GTEST_LOG_(INFO) << "remove the token info";
}

/**
 * @tc.name: DeleteRemoteToken001
 * @tc.desc: Verify the DeleteRemoteToken normal and abnormal branch.
 * @tc.type: FUNC
 * @tc.require: issueI5RJBB
 */
HWTEST_F(AccessTokenInfoManagerTest, DeleteRemoteToken001, TestSize.Level0)
{
    AccessTokenIDEx tokenIdEx = {0};
    std::vector<GenericValues> undefValues;
    int32_t ret = AccessTokenInfoManager::GetInstance().CreateHapTokenInfo(
        g_infoManagerTestInfoParms, g_infoManagerTestPolicyPrams1, tokenIdEx, undefValues);
    ASSERT_EQ(RET_SUCCESS, ret);
    GTEST_LOG_(INFO) << "add a hap token";

    std::string deviceId = "device_1";
    std::string deviceId2 = "device_2";
    AccessTokenID mapId =
        AccessTokenInfoManager::GetInstance().AllocLocalTokenID(deviceId, tokenIdEx.tokenIdExStruct.tokenID);
    ASSERT_EQ(mapId == 0, true);
    HapTokenInfoForSync hapSync;
    ret = AccessTokenInfoManager::GetInstance().GetHapTokenInfoFromRemote(tokenIdEx.tokenIdExStruct.tokenID, hapSync);
    ASSERT_EQ(RET_SUCCESS, ret);
    ret = AccessTokenInfoManager::GetInstance().SetRemoteHapTokenInfo(deviceId, hapSync);
    ASSERT_EQ(RET_SUCCESS, ret);
    ret = AccessTokenInfoManager::GetInstance().DeleteRemoteToken(deviceId, tokenIdEx.tokenIdExStruct.tokenID);
    ASSERT_EQ(RET_SUCCESS, ret);
    ret = AccessTokenInfoManager::GetInstance().DeleteRemoteToken(deviceId2, tokenIdEx.tokenIdExStruct.tokenID);
    ASSERT_NE(RET_SUCCESS, ret);

    ret = AccessTokenInfoManager::GetInstance().RemoveHapTokenInfo(tokenIdEx.tokenIdExStruct.tokenID);
    ASSERT_EQ(RET_SUCCESS, ret);
    GTEST_LOG_(INFO) << "remove the token info";
}

static bool SetRemoteHapTokenInfoTest(const std::string& deviceID, const HapTokenInfo& baseInfo)
{
    std::vector<PermissionStatus> permStateList;
    permStateList.emplace_back(g_infoManagerTestState1);
    HapTokenInfoForSync remoteTokenInfo = {
        .baseInfo = baseInfo,
        .permStateList = permStateList
    };

    return RET_SUCCESS == AccessTokenInfoManager::GetInstance().SetRemoteHapTokenInfo(deviceID, remoteTokenInfo);
}

/**
 * @tc.name: SetRemoteHapTokenInfo001
 * @tc.desc: set remote hap token info, token info is wrong
 * @tc.type: FUNC
 * @tc.require: issue5RJBB
 */
HWTEST_F(AccessTokenInfoManagerTest, SetRemoteHapTokenInfo001, TestSize.Level0)
{
    std::string deviceID = "deviceId";
    HapTokenInfo rightBaseInfo = {
        .ver = 1,
        .userID = 1,
        .bundleName = "com.ohos.access_token",
        .instIndex = 1,
        .tokenID = 0x20100000,
        .tokenAttr = 0
    };
    HapTokenInfo wrongBaseInfo = rightBaseInfo;
    std::string wrongStr(10241, 'x');

    EXPECT_EQ(false, SetRemoteHapTokenInfoTest("", wrongBaseInfo));

    wrongBaseInfo = rightBaseInfo;
    wrongBaseInfo.userID = -1; // wrong userID
    EXPECT_EQ(false, SetRemoteHapTokenInfoTest(deviceID, wrongBaseInfo));

    wrongBaseInfo = rightBaseInfo;
    wrongBaseInfo.bundleName = wrongStr; // wrong bundleName
    EXPECT_EQ(false, SetRemoteHapTokenInfoTest(deviceID, wrongBaseInfo));

    wrongBaseInfo = rightBaseInfo;
    wrongBaseInfo.tokenID = 0; // wrong tokenID
    EXPECT_EQ(false, SetRemoteHapTokenInfoTest(deviceID, wrongBaseInfo));

    wrongBaseInfo = rightBaseInfo;
    wrongBaseInfo.dlpType = (HapDlpType)11; // wrong dlpType
    EXPECT_EQ(false, SetRemoteHapTokenInfoTest(deviceID, wrongBaseInfo));

    wrongBaseInfo = rightBaseInfo;
    wrongBaseInfo.ver = 2; // 2: wrong version
    EXPECT_EQ(false, SetRemoteHapTokenInfoTest(deviceID, wrongBaseInfo));

    wrongBaseInfo = rightBaseInfo;
    wrongBaseInfo.tokenID = AccessTokenInfoManager::GetInstance().GetNativeTokenId("hdcd");
    EXPECT_EQ(false, SetRemoteHapTokenInfoTest(deviceID, wrongBaseInfo));
}

/**
 * @tc.name: ClearUserGrantedPermissionState001
 * @tc.desc: AccessTokenInfoManagerTest::ClearUserGrantedPermissionState function test
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(AccessTokenInfoManagerTest, ClearUserGrantedPermissionState001, TestSize.Level0)
{
    AccessTokenID tokenId = 123; // 123 is random input

    std::shared_ptr<HapTokenInfoInner> hap = std::make_shared<HapTokenInfoInner>();
    ASSERT_NE(nullptr, hap);
    AccessTokenInfoManager::GetInstance().hapTokenInfoMap_[tokenId] = hap;

    AccessTokenInfoManager::GetInstance().ClearUserGrantedPermissionState(tokenId); // permPolicySet is null

    AccessTokenInfoManager::GetInstance().hapTokenInfoMap_.erase(tokenId);
}

/**
 * @tc.name: NotifyTokenSyncTask001
 * @tc.desc: TokenModifyNotifier::NotifyTokenSyncTask function test
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(AccessTokenInfoManagerTest, NotifyTokenSyncTask001, TestSize.Level0)
{
    std::vector<AccessTokenID> modifiedTokenList = TokenModifyNotifier::GetInstance().modifiedTokenList_; // backup
    TokenModifyNotifier::GetInstance().modifiedTokenList_.clear();

    AccessTokenID tokenId = 123; // 123 is random input

    TokenModifyNotifier::GetInstance().modifiedTokenList_.emplace_back(tokenId);
    ASSERT_EQ(true, TokenModifyNotifier::GetInstance().modifiedTokenList_.size() > 0);
    TokenModifyNotifier::GetInstance().NotifyTokenSyncTask();

    TokenModifyNotifier::GetInstance().modifiedTokenList_ = modifiedTokenList; // recovery
}

void setPermission()
{
    setuid(0);
    if (tokenSyncId_ == 0) {
        tokenSyncId_ = AccessTokenInfoManager::GetInstance().GetNativeTokenId("token_sync_service");
    }
    SetSelfTokenID(tokenSyncId_);
}

/**
 * @tc.name: RegisterTokenSyncCallback001
 * @tc.desc: TokenModifyNotifier::RegisterTokenSyncCallback function test
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(AccessTokenInfoManagerTest, RegisterTokenSyncCallback001, TestSize.Level0)
{
    setPermission();
    sptr<TokenSyncCallbackMock> callback = new (std::nothrow) TokenSyncCallbackMock();
    ASSERT_NE(nullptr, callback);
    EXPECT_EQ(RET_SUCCESS,
        atManagerService_->RegisterTokenSyncCallback(callback->AsObject()));
    EXPECT_NE(nullptr, TokenModifyNotifier::GetInstance().tokenSyncCallbackObject_);
    EXPECT_NE(nullptr, TokenModifyNotifier::GetInstance().tokenSyncCallbackDeathRecipient_);
    
    setuid(3020);
    EXPECT_CALL(*callback, GetRemoteHapTokenInfo(testing::_, testing::_)).WillOnce(testing::Return(FAKE_SYNC_RET));
    EXPECT_EQ(FAKE_SYNC_RET, TokenModifyNotifier::GetInstance().tokenSyncCallbackObject_->GetRemoteHapTokenInfo("", 0));
    
    EXPECT_CALL(*callback, DeleteRemoteHapTokenInfo(testing::_)).WillOnce(testing::Return(FAKE_SYNC_RET));
    EXPECT_EQ(FAKE_SYNC_RET, TokenModifyNotifier::GetInstance().tokenSyncCallbackObject_->DeleteRemoteHapTokenInfo(0));
    
    HapTokenInfoForSync tokenInfo;
    EXPECT_CALL(*callback, UpdateRemoteHapTokenInfo(testing::_)).WillOnce(testing::Return(FAKE_SYNC_RET));
    EXPECT_EQ(FAKE_SYNC_RET,
        TokenModifyNotifier::GetInstance().tokenSyncCallbackObject_->UpdateRemoteHapTokenInfo(tokenInfo));
    setPermission();
    EXPECT_EQ(RET_SUCCESS,
        atManagerService_->UnRegisterTokenSyncCallback());
    EXPECT_EQ(nullptr, TokenModifyNotifier::GetInstance().tokenSyncCallbackObject_);
    EXPECT_EQ(nullptr, TokenModifyNotifier::GetInstance().tokenSyncCallbackDeathRecipient_);
    setuid(0);
}

/**
 * @tc.name: RegisterTokenSyncCallback002
 * @tc.desc: TokenModifyNotifier::RegisterTokenSyncCallback function test
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(AccessTokenInfoManagerTest, RegisterTokenSyncCallback002, TestSize.Level0)
{
    setPermission();
    sptr<TokenSyncCallbackMock> callback = new (std::nothrow) TokenSyncCallbackMock();
    ASSERT_NE(nullptr, callback);
    EXPECT_EQ(RET_SUCCESS,
        atManagerService_->RegisterTokenSyncCallback(callback->AsObject()));
    EXPECT_NE(nullptr, TokenModifyNotifier::GetInstance().tokenSyncCallbackObject_);
    setuid(3020);
    EXPECT_CALL(*callback, GetRemoteHapTokenInfo(testing::_, testing::_))
        .WillOnce(testing::Return(FAKE_SYNC_RET));
    EXPECT_EQ(FAKE_SYNC_RET, TokenModifyNotifier::GetInstance().GetRemoteHapTokenInfo("", 0));

    std::vector<AccessTokenID> modifiedTokenList =
        TokenModifyNotifier::GetInstance().modifiedTokenList_; // backup
    std::vector<AccessTokenID> deleteTokenList = TokenModifyNotifier::GetInstance().deleteTokenList_;
    TokenModifyNotifier::GetInstance().modifiedTokenList_.clear();
    TokenModifyNotifier::GetInstance().deleteTokenList_.clear();

    // add a hap token
    AccessTokenIDEx tokenIdEx = {123};
    std::vector<GenericValues> undefValues;
    int32_t result = AccessTokenInfoManager::GetInstance().CreateHapTokenInfo(
        g_infoManagerTestInfoParms, g_infoManagerTestPolicyPrams1, tokenIdEx, undefValues);
    EXPECT_EQ(RET_SUCCESS, result);

    HapTokenInfoForSync hapSync;
    result = AccessTokenInfoManager::GetInstance().GetHapTokenSync(tokenIdEx.tokenIdExStruct.tokenID, hapSync);
    ASSERT_EQ(result, RET_SUCCESS);
    TokenModifyNotifier::GetInstance().modifiedTokenList_.emplace_back(tokenIdEx.tokenIdExStruct.tokenID);
    ASSERT_EQ(true, TokenModifyNotifier::GetInstance().modifiedTokenList_.size() > 0);
    TokenModifyNotifier::GetInstance().deleteTokenList_.clear();

    EXPECT_CALL(*callback, UpdateRemoteHapTokenInfo(testing::_)) // 0 is a test ret
        .WillOnce(testing::Return(0));
    TokenModifyNotifier::GetInstance().NotifyTokenSyncTask();

    TokenModifyNotifier::GetInstance().deleteTokenList_.emplace_back(tokenIdEx.tokenIdExStruct.tokenID);
    ASSERT_EQ(true, TokenModifyNotifier::GetInstance().deleteTokenList_.size() > 0);
    EXPECT_CALL(*callback, DeleteRemoteHapTokenInfo(testing::_)) // 0 is a test ret
        .WillOnce(testing::Return(0));
    TokenModifyNotifier::GetInstance().NotifyTokenSyncTask();

    TokenModifyNotifier::GetInstance().modifiedTokenList_ = modifiedTokenList; // recovery
    TokenModifyNotifier::GetInstance().deleteTokenList_ = deleteTokenList;
    setPermission();
    EXPECT_EQ(RET_SUCCESS,
        atManagerService_->UnRegisterTokenSyncCallback());
    setuid(0);
}

/**
 * @tc.name: GetRemoteHapTokenInfo001
 * @tc.desc: TokenModifyNotifier::GetRemoteHapTokenInfo function test
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(AccessTokenInfoManagerTest, GetRemoteHapTokenInfo001, TestSize.Level0)
{
    setPermission();
    sptr<TokenSyncCallbackMock> callback = new (std::nothrow) TokenSyncCallbackMock();
    ASSERT_NE(nullptr, callback);
    EXPECT_EQ(RET_SUCCESS, atManagerService_->RegisterTokenSyncCallback(callback->AsObject()));
    setuid(3020);
    EXPECT_CALL(*callback, GetRemoteHapTokenInfo(testing::_, testing::_))
        .WillOnce(testing::Return(FAKE_SYNC_RET));
    EXPECT_EQ(FAKE_SYNC_RET, TokenModifyNotifier::GetInstance()
        .GetRemoteHapTokenInfo("invalid_id", 0)); // this is a test input
    
    EXPECT_CALL(*callback, GetRemoteHapTokenInfo(testing::_, testing::_))
        .WillOnce(testing::Return(TOKEN_SYNC_OPENSOURCE_DEVICE));
    EXPECT_EQ(TOKEN_SYNC_IPC_ERROR, TokenModifyNotifier::GetInstance()
        .GetRemoteHapTokenInfo("invalid_id", 0)); // this is a test input
    setPermission();
    EXPECT_EQ(RET_SUCCESS,
        atManagerService_->UnRegisterTokenSyncCallback());
    setuid(0);
}

/**
 * @tc.name: UpdateRemoteHapTokenInfo001
 * @tc.desc: AccessTokenInfoManager::UpdateRemoteHapTokenInfo function test
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(AccessTokenInfoManagerTest, UpdateRemoteHapTokenInfo001, TestSize.Level0)
{
    AccessTokenID mapID = 0;
    HapTokenInfoForSync hapSync;

    // infoPtr is null
    ASSERT_NE(RET_SUCCESS, AccessTokenInfoManager::GetInstance().UpdateRemoteHapTokenInfo(mapID, hapSync));

    mapID = 123; // 123 is random input
    std::shared_ptr<HapTokenInfoInner> info = std::make_shared<HapTokenInfoInner>();
    info->SetRemote(true);
    AccessTokenInfoManager::GetInstance().hapTokenInfoMap_[mapID] = info;

    // remote is true
    ASSERT_EQ(RET_SUCCESS, AccessTokenInfoManager::GetInstance().UpdateRemoteHapTokenInfo(mapID, hapSync));

    AccessTokenInfoManager::GetInstance().hapTokenInfoMap_.erase(mapID);
}

/**
 * @tc.name: CreateRemoteHapTokenInfo001
 * @tc.desc: AccessTokenInfoManager::CreateRemoteHapTokenInfo function test
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(AccessTokenInfoManagerTest, CreateRemoteHapTokenInfo001, TestSize.Level0)
{
    AccessTokenID mapID = 123; // 123 is random input
    HapTokenInfoForSync hapSync;

    hapSync.baseInfo.tokenID = 123; // 123 is random input
    std::shared_ptr<HapTokenInfoInner> info = std::make_shared<HapTokenInfoInner>();
    AccessTokenInfoManager::GetInstance().hapTokenInfoMap_[123] = info;

    // count(id) exsit
    ASSERT_NE(RET_SUCCESS, AccessTokenInfoManager::GetInstance().CreateRemoteHapTokenInfo(mapID, hapSync));

    AccessTokenInfoManager::GetInstance().hapTokenInfoMap_.erase(123);
}

/**
 * @tc.name: DeleteRemoteToken002
 * @tc.desc: AccessTokenInfoManager::DeleteRemoteToken function test
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(AccessTokenInfoManagerTest, DeleteRemoteToken002, TestSize.Level0)
{
    std::string deviceID = "dev-001";
    AccessTokenID tokenID = 123; // 123 is random input

    ASSERT_EQ(AccessTokenError::ERR_PARAM_INVALID,
        AccessTokenInfoManager::GetInstance().DeleteRemoteToken("", tokenID));

    AccessTokenRemoteDevice device;
    device.deviceID_ = deviceID;
    // 537919487 is max hap tokenId: 001 00 0 000000 11111111111111111111
    device.MappingTokenIDPairMap_.insert(std::pair<AccessTokenID, AccessTokenID>(tokenID, 537919487));
    AccessTokenRemoteTokenManager::GetInstance().remoteDeviceMap_[deviceID] = device;

    ASSERT_EQ(RET_SUCCESS, AccessTokenIDManager::GetInstance().RegisterTokenId(537919487, TOKEN_HAP));
    // hap mapID 537919487 is not exist
    ASSERT_NE(RET_SUCCESS, AccessTokenInfoManager::GetInstance().DeleteRemoteToken(deviceID, tokenID));
    AccessTokenRemoteTokenManager::GetInstance().remoteDeviceMap_.erase(deviceID);
    AccessTokenIDManager::GetInstance().ReleaseTokenId(537919487);

    // 672137215 is max native tokenId: 001 01 0 000000 11111111111111111111
    device.MappingTokenIDPairMap_[tokenID] = 672137215;
    AccessTokenRemoteTokenManager::GetInstance().remoteDeviceMap_[deviceID] = device;

    ASSERT_EQ(RET_SUCCESS, AccessTokenIDManager::GetInstance().RegisterTokenId(672137215, TOKEN_NATIVE));
    // native mapID 672137215 is not exist
    ASSERT_NE(RET_SUCCESS, AccessTokenInfoManager::GetInstance().DeleteRemoteToken(deviceID, tokenID));
    AccessTokenRemoteTokenManager::GetInstance().remoteDeviceMap_.erase(deviceID);
    AccessTokenIDManager::GetInstance().ReleaseTokenId(672137215);
}

/**
 * @tc.name: AllocLocalTokenID001
 * @tc.desc: AccessTokenInfoManager::AllocLocalTokenID function test
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(AccessTokenInfoManagerTest, AllocLocalTokenID001, TestSize.Level0)
{
    std::string remoteDeviceID;
    AccessTokenID remoteTokenID = 0;

    ASSERT_EQ(static_cast<AccessTokenID>(0), AccessTokenInfoManager::GetInstance().AllocLocalTokenID(remoteDeviceID,
        remoteTokenID)); // remoteDeviceID invalid

    // deviceID invalid + tokenID == 0
    ASSERT_EQ(static_cast<AccessTokenID>(0),
        AccessTokenInfoManager::GetInstance().GetRemoteNativeTokenID(remoteDeviceID, remoteTokenID));

    // deviceID invalid
    ASSERT_EQ(ERR_PARAM_INVALID, AccessTokenInfoManager::GetInstance().DeleteRemoteDeviceTokens(remoteDeviceID));

    remoteDeviceID = "dev-001";
    ASSERT_EQ(static_cast<AccessTokenID>(0), AccessTokenInfoManager::GetInstance().AllocLocalTokenID(remoteDeviceID,
        remoteTokenID)); // remoteTokenID invalid

    // deviceID valid + tokenID == 0
    ASSERT_EQ(static_cast<AccessTokenID>(0),
        AccessTokenInfoManager::GetInstance().GetRemoteNativeTokenID(remoteDeviceID, remoteTokenID));

    remoteTokenID = 537919487; // 537919487 is max hap tokenId: 001 00 0 000000 11111111111111111111
    // deviceID valid + tokenID != 0 + type != native + type != shell
    ASSERT_EQ(static_cast<AccessTokenID>(0),
        AccessTokenInfoManager::GetInstance().GetRemoteNativeTokenID(remoteDeviceID, remoteTokenID));
}
#endif

/**
 * @tc.name: Dump001
 * @tc.desc: Dump tokeninfo.
 * @tc.type: FUNC
 * @tc.require: issueI4V02P
 */
HWTEST_F(AccessTokenInfoManagerTest, Dump001, TestSize.Level0)
{
    int fd = -1;
    std::vector<std::u16string> args;

    // fd is 0
    ASSERT_NE(RET_SUCCESS, atManagerService_->Dump(fd, args));

    fd = open("/dev/null", O_WRONLY);

    // hidumper
    ASSERT_EQ(RET_SUCCESS, atManagerService_->Dump(fd, args));

    // hidumper -h
    args.emplace_back(Str8ToStr16("-h"));
    ASSERT_EQ(RET_SUCCESS, atManagerService_->Dump(fd, args));

    args.clear();
    // hidumper -a
    args.emplace_back(Str8ToStr16("-a"));
    ASSERT_EQ(RET_SUCCESS, atManagerService_->Dump(fd, args));

    args.clear();
    // hidumper -t
    args.emplace_back(Str8ToStr16("-t"));
    ASSERT_NE(RET_SUCCESS, atManagerService_->Dump(fd, args));

    args.clear();
    // hidumper -t
    args.emplace_back(Str8ToStr16("-t"));
    args.emplace_back(Str8ToStr16("-1")); // illegal tokenId
    ASSERT_NE(RET_SUCCESS, atManagerService_->Dump(fd, args));

    args.clear();
    // hidumper -t
    args.emplace_back(Str8ToStr16("-t"));
    args.emplace_back(Str8ToStr16("123")); // invalid tokenId
    ASSERT_EQ(RET_SUCCESS, atManagerService_->Dump(fd, args));
}

/**
 * @tc.name: DumpTokenInfo001
 * @tc.desc: Test DumpTokenInfo with invalid tokenId.
 * @tc.type: FUNC
 * @tc.require: issueI4V02P
 */
HWTEST_F(AccessTokenInfoManagerTest, DumpTokenInfo001, TestSize.Level0)
{
    std::string dumpInfo;
    AtmToolsParamInfo info;
    info.tokenId = static_cast<AccessTokenID>(0);
    AccessTokenInfoManager::GetInstance().DumpTokenInfo(info, dumpInfo);
    EXPECT_EQ(false, dumpInfo.empty());

    dumpInfo.clear();
    info.tokenId = static_cast<AccessTokenID>(123);
    AccessTokenInfoManager::GetInstance().DumpTokenInfo(info, dumpInfo);
    EXPECT_EQ("invalid tokenId", dumpInfo);
}

/**
 * @tc.name: DumpTokenInfo002
 * @tc.desc: Test DumpTokenInfo with hap tokenId.
 * @tc.type: FUNC
 * @tc.require: issueI4V02P
 */
HWTEST_F(AccessTokenInfoManagerTest, DumpTokenInfo002, TestSize.Level0)
{
    AccessTokenIDEx tokenIdEx = {0};
    std::vector<GenericValues> undefValues;
    AccessTokenInfoManager::GetInstance().CreateHapTokenInfo(g_infoManagerTestInfoParms,
        g_infoManagerTestPolicyPrams1, tokenIdEx, undefValues);

    tokenIdEx = AccessTokenInfoManager::GetInstance().GetHapTokenID(g_infoManagerTestInfoParms.userID,
        g_infoManagerTestInfoParms.bundleName, g_infoManagerTestInfoParms.instIndex);
    AccessTokenID tokenId = tokenIdEx.tokenIdExStruct.tokenID;
    EXPECT_NE(0, static_cast<int>(tokenId));
    std::string dumpInfo;
    AtmToolsParamInfo info;
    info.tokenId = tokenId;
    AccessTokenInfoManager::GetInstance().DumpTokenInfo(info, dumpInfo);
    EXPECT_EQ(false, dumpInfo.empty());

    int32_t ret = AccessTokenInfoManager::GetInstance().RemoveHapTokenInfo(
        tokenIdEx.tokenIdExStruct.tokenID);
    ASSERT_EQ(RET_SUCCESS, ret);
    GTEST_LOG_(INFO) << "remove the token info";
}

/**
 * @tc.name: DumpTokenInfo003
 * @tc.desc: Test DumpTokenInfo with native tokenId.
 * @tc.type: FUNC
 * @tc.require: issueI4V02P
 */
HWTEST_F(AccessTokenInfoManagerTest, DumpTokenInfo003, TestSize.Level0)
{
    std::string dumpInfo;
    AtmToolsParamInfo info;
    info.tokenId = AccessTokenInfoManager::GetInstance().GetNativeTokenId("accesstoken_service");
    AccessTokenInfoManager::GetInstance().DumpTokenInfo(info, dumpInfo);
    EXPECT_EQ(false, dumpInfo.empty());
}

/**
 * @tc.name: DumpTokenInfo004
 * @tc.desc: Test DumpTokenInfo with shell tokenId.
 * @tc.type: FUNC
 * @tc.require: issueI4V02P
 */
HWTEST_F(AccessTokenInfoManagerTest, DumpTokenInfo004, TestSize.Level0)
{
    std::string dumpInfo;
    AtmToolsParamInfo info;
    info.tokenId = AccessTokenInfoManager::GetInstance().GetNativeTokenId("hdcd");
    AccessTokenInfoManager::GetInstance().DumpTokenInfo(info, dumpInfo);
    EXPECT_EQ(false, dumpInfo.empty());
}

/**
 * @tc.name: DumpTokenInfo005
 * @tc.desc: Test DumpTokenInfo with native processName.
 * @tc.type: FUNC
 * @tc.require: issueI4V02P
 */
HWTEST_F(AccessTokenInfoManagerTest, DumpTokenInfo005, TestSize.Level0)
{
    std::string dumpInfo;
    AtmToolsParamInfo info;
    info.processName = "hdcd";
    AccessTokenInfoManager::GetInstance().DumpTokenInfo(info, dumpInfo);
    EXPECT_EQ(false, dumpInfo.empty());
}

/**
 * @tc.name: DumpTokenInfo006
 * @tc.desc: Test DumpTokenInfo with hap bundleName.
 * @tc.type: FUNC
 * @tc.require: issueI4V02P
 */
HWTEST_F(AccessTokenInfoManagerTest, DumpTokenInfo006, TestSize.Level0)
{
    AccessTokenIDEx tokenIdEx = {0};
    std::vector<GenericValues> undefValues;
    AccessTokenInfoManager::GetInstance().CreateHapTokenInfo(g_infoManagerTestInfoParms,
        g_infoManagerTestPolicyPrams1, tokenIdEx, undefValues);

    tokenIdEx = AccessTokenInfoManager::GetInstance().GetHapTokenID(g_infoManagerTestInfoParms.userID,
        g_infoManagerTestInfoParms.bundleName, g_infoManagerTestInfoParms.instIndex);
    AccessTokenID tokenId = tokenIdEx.tokenIdExStruct.tokenID;
    EXPECT_NE(0, static_cast<int>(tokenId));
    
    std::string dumpInfo;
    AtmToolsParamInfo info;
    info.bundleName = g_infoManagerTestInfoParms.bundleName;
    AccessTokenInfoManager::GetInstance().DumpTokenInfo(info, dumpInfo);
    EXPECT_EQ(false, dumpInfo.empty());

    int32_t ret = AccessTokenInfoManager::GetInstance().RemoveHapTokenInfo(
        tokenIdEx.tokenIdExStruct.tokenID);
    ASSERT_EQ(RET_SUCCESS, ret);
}

/**
 * @tc.name: AccessTokenInfoManager001
 * @tc.desc: AccessTokenInfoManager::~AccessTokenInfoManager+Init function test hasInited_ is false
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(AccessTokenInfoManagerTest, AccessTokenInfoManager001, TestSize.Level0)
{
    AccessTokenInfoManager::GetInstance().hasInited_ = true;
    uint32_t hapSize = 0;
    uint32_t nativeSize = 0;
    uint32_t pefDefSize = 0;
    uint32_t dlpSize = 0;
    std::map<int32_t, int32_t> tokenIdAplMap;
    AccessTokenInfoManager::GetInstance().Init(hapSize, nativeSize, pefDefSize, dlpSize, tokenIdAplMap);
    AccessTokenInfoManager::GetInstance().hasInited_ = false;
    ASSERT_EQ(false, AccessTokenInfoManager::GetInstance().hasInited_);
}

/**
 * @tc.name: GetHapUniqueStr001
 * @tc.desc: AccessTokenInfoManager::GetHapUniqueStr function test info is null
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(AccessTokenInfoManagerTest, GetHapUniqueStr001, TestSize.Level0)
{
    std::shared_ptr<HapTokenInfoInner> info = nullptr;
    ASSERT_EQ("", AccessTokenInfoManager::GetInstance().GetHapUniqueStr(info));
}

/**
 * @tc.name: AddHapTokenInfo001
 * @tc.desc: AccessTokenInfoManager::AddHapTokenInfo function test info is null
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(AccessTokenInfoManagerTest, AddHapTokenInfo001, TestSize.Level0)
{
    std::shared_ptr<HapTokenInfoInner> info = nullptr;
    AccessTokenID oriTokenId = 0;
    ASSERT_NE(0, AccessTokenInfoManager::GetInstance().AddHapTokenInfo(info, oriTokenId));
}

/**
 * @tc.name: AddHapTokenInfo002
 * @tc.desc: AccessTokenInfoManager::AddHapTokenInfo function test count(id) > 0
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(AccessTokenInfoManagerTest, AddHapTokenInfo002, TestSize.Level0)
{
    HapInfoParams info = {
        .userID = USER_ID,
        .bundleName = "accesstoken_info_manager_test",
        .instIndex = INST_INDEX,
        .appIDDesc = "accesstoken_info_manager_test"
    };
    HapPolicy policy = {
        .apl = APL_NORMAL,
        .domain = "domain"
    };
    AccessTokenIDEx tokenIdEx = {0};
    std::vector<GenericValues> undefValues;
    ASSERT_EQ(RET_SUCCESS, AccessTokenInfoManager::GetInstance().CreateHapTokenInfo(info, policy, tokenIdEx,
        undefValues));
    AccessTokenID tokenId = tokenIdEx.tokenIdExStruct.tokenID;
    ASSERT_NE(static_cast<AccessTokenID>(0), tokenId);

    std::shared_ptr<HapTokenInfoInner> infoPtr = AccessTokenInfoManager::GetInstance().GetHapTokenInfoInner(tokenId);
    AccessTokenID oriTokenId = 0;
    ASSERT_NE(0, AccessTokenInfoManager::GetInstance().AddHapTokenInfo(infoPtr, oriTokenId));

    ASSERT_EQ(RET_SUCCESS, AccessTokenInfoManager::GetInstance().RemoveHapTokenInfo(tokenId));
}

/**
 * @tc.name: GetHapTokenID002
 * @tc.desc: test GetHapTokenID function abnomal branch
 * @tc.type: FUNC
 * @tc.require: issueI60F1M
 */
HWTEST_F(AccessTokenInfoManagerTest, GetHapTokenID002, TestSize.Level0)
{
    AccessTokenIDEx tokenIdEx = AccessTokenInfoManager::GetInstance().GetHapTokenID(
        USER_ID, "com.ohos.test", INST_INDEX);
    ASSERT_EQ(static_cast<AccessTokenID>(0), tokenIdEx.tokenIDEx);
}

/**
 * @tc.name: IsPermissionDefValid001
 * @tc.desc: PermissionValidator::IsPermissionDefValid function test
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(AccessTokenInfoManagerTest, IsPermissionDefValid001, TestSize.Level0)
{
    PermissionDef permDef = {
        .permissionName = "ohos.permission.TEST",
        .bundleName = "com.ohos.test",
        .grantMode = static_cast<GrantMode>(2),
        .availableLevel = ATokenAplEnum::APL_NORMAL,
        .provisionEnable = false,
        .distributedSceneEnable = false,
        .label = "buzhidao",
        .labelId = 100, // 100 is random input
        .description = "buzhidao",
        .descriptionId = 100 // 100 is random input
    };

    // ret not RET_SUCCESS
    ASSERT_EQ(false, PermissionValidator::IsPermissionDefValid(permDef)); // grant mode invalid

    permDef.grantMode = GrantMode::USER_GRANT;
    permDef.availableType = ATokenAvailableTypeEnum::INVALID;
    ASSERT_EQ(false, PermissionValidator::IsPermissionDefValid(permDef)); // availableType invalid
}

/**
 * @tc.name: IsPermissionStateValid001
 * @tc.desc: PermissionValidator::IsPermissionStateValid function test
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(AccessTokenInfoManagerTest, IsPermissionStateValid001, TestSize.Level0)
{
    std::string permissionName;
    std::string deviceID = "dev-001";
    int grantState = PermissionState::PERMISSION_DENIED;
    uint32_t grantFlag = PermissionFlag::PERMISSION_DEFAULT_FLAG;
    PermissionStatus permState = {
        .permissionName = permissionName,
        .grantStatus = grantState,
        .grantFlag = grantFlag
    };

    ASSERT_EQ(false, PermissionValidator::IsPermissionStateValid(permState)); // permissionName empty

    permState.permissionName = "com.ohos.TEST";
    permState.grantStatus = 1; // 1: invalid status
    ASSERT_EQ(false, PermissionValidator::IsPermissionStateValid(permState));

    permState.grantStatus = grantState;
    permState.grantFlag = -1; // -1: invalid flag
    ASSERT_EQ(false, PermissionValidator::IsPermissionStateValid(permState));

    permState.grantFlag = grantFlag;
    ASSERT_EQ(true, PermissionValidator::IsPermissionStateValid(permState));
}

/**
 * @tc.name: FilterInvalidPermissionDef001
 * @tc.desc: PermissionValidator::FilterInvalidPermissionDef function test
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(AccessTokenInfoManagerTest, FilterInvalidPermissionDef001, TestSize.Level0)
{
    PermissionDef permDef = {
        .permissionName = "ohos.permission.TEST",
        .bundleName = "com.ohos.test",
        .grantMode = GrantMode::SYSTEM_GRANT,
        .availableLevel = ATokenAplEnum::APL_NORMAL,
        .provisionEnable = false,
        .distributedSceneEnable = false,
        .label = "buzhidao",
        .labelId = 100, // 100 is random input
        .description = "buzhidao",
        .descriptionId = 100 // 100 is random input
    };

    std::vector<PermissionDef> permList;
    permList.emplace_back(permDef);
    permList.emplace_back(permDef);

    ASSERT_EQ(static_cast<uint32_t>(2), permList.size());

    std::vector<PermissionDef> result;
    PermissionValidator::FilterInvalidPermissionDef(permList, result); // permDefSet.count != 0
    ASSERT_EQ(static_cast<uint32_t>(1), result.size());
}

/**
 * @tc.name: QueryPermissionFlag001
 * @tc.desc: PermissionPolicySet::QueryPermissionFlag function test
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(AccessTokenInfoManagerTest, QueryPermissionFlag001, TestSize.Level0)
{
    PermissionStatus perm = {
        .permissionName = "ohos.permission.TEST",
        .grantStatus = PermissionState::PERMISSION_DENIED,
        .grantFlag = PermissionFlag::PERMISSION_DEFAULT_FLAG
    };

    AccessTokenID tokenId = 0x280bc140; // 0x280bc140 is random native
    std::vector<PermissionStatus> permStateList;
    permStateList.emplace_back(perm);

    PermissionDataBrief::GetInstance().AddPermToBriefPermission(tokenId, permStateList, true);

    // perm.permissionName != permissionName
    uint32_t flag = 0;
    ASSERT_EQ(ERR_PERMISSION_NOT_EXIST,
        PermissionDataBrief::GetInstance().QueryPermissionFlag(tokenId, "ohos.permission.TEST1", flag));
}

/**
 * @tc.name: UpdatePermissionStatus001
 * @tc.desc: PermissionPolicySet::UpdatePermissionStatus function test
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(AccessTokenInfoManagerTest, UpdatePermissionStatus001, TestSize.Level0)
{
    PermissionStatus perm = {
        .permissionName = "ohos.permission.CAMERA",
        .grantStatus = PermissionState::PERMISSION_DENIED,
        .grantFlag = PermissionFlag::PERMISSION_DEFAULT_FLAG
    };

    AccessTokenID tokenId = 789; // 789 is random input
    std::vector<PermissionStatus> permStateList;
    permStateList.emplace_back(perm);

    PermissionDataBrief::GetInstance().AddPermToBriefPermission(tokenId, permStateList, true);

    // iter reach the end
    bool isGranted = false;
    uint32_t flag = PermissionFlag::PERMISSION_DEFAULT_FLAG;
    bool changed = false;

    // permission is invalid
    ASSERT_EQ(ERR_PARAM_INVALID, PermissionDataBrief::GetInstance().UpdatePermissionStatus(tokenId,
        "ohos.permission.TEST1", isGranted, flag, changed));
    // flag != PERMISSION_COMPONENT_SET
    flag = PermissionFlag::PERMISSION_DEFAULT_FLAG;
    ASSERT_EQ(RET_SUCCESS, PermissionDataBrief::GetInstance().UpdatePermissionStatus(tokenId,
        "ohos.permission.CAMERA", isGranted, flag, changed));
    
    // flag == PERMISSION_COMPONENT_SET
    flag = PermissionFlag::PERMISSION_COMPONENT_SET;
    ASSERT_EQ(RET_SUCCESS, PermissionDataBrief::GetInstance().UpdatePermissionStatus(tokenId,
        "ohos.permission.CAMERA", isGranted, flag, changed));


    // flag == PERMISSION_SYSTEM_FIXED
    flag = PermissionFlag::PERMISSION_SYSTEM_FIXED;
    ASSERT_EQ(RET_SUCCESS, PermissionDataBrief::GetInstance().UpdatePermissionStatus(tokenId,
        "ohos.permission.CAMERA", isGranted, flag, changed));

    // Permission fixed by system
    flag = PermissionFlag::PERMISSION_DEFAULT_FLAG;
    ASSERT_EQ(ERR_PARAM_INVALID, PermissionDataBrief::GetInstance().UpdatePermissionStatus(tokenId,
        "ohos.permission.CAMERA", isGranted, flag, changed));
}

#ifdef TOKEN_SYNC_ENABLE
/**
 * @tc.name: MapRemoteDeviceTokenToLocal001
 * @tc.desc: AccessTokenRemoteTokenManager::MapRemoteDeviceTokenToLocal function test
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(AccessTokenInfoManagerTest, MapRemoteDeviceTokenToLocal001, TestSize.Level0)
{
    std::map<std::string, AccessTokenRemoteDevice> remoteDeviceMap;
    remoteDeviceMap = AccessTokenRemoteTokenManager::GetInstance().remoteDeviceMap_; // backup
    AccessTokenRemoteTokenManager::GetInstance().remoteDeviceMap_.clear();

    std::string deviceID;
    AccessTokenID remoteID = 0;

    // input invalid
    ASSERT_EQ(static_cast<AccessTokenID>(0),
        AccessTokenRemoteTokenManager::GetInstance().MapRemoteDeviceTokenToLocal(deviceID, remoteID));

    remoteID = 940572671; // 940572671 is max butt tokenId: 001 11 0 000000 11111111111111111111
    deviceID = "dev-001";

    // tokeType invalid
    ASSERT_EQ(static_cast<AccessTokenID>(0),
        AccessTokenRemoteTokenManager::GetInstance().MapRemoteDeviceTokenToLocal(deviceID, remoteID));

    remoteID = 537919487; // 537919487 is max hap tokenId: 001 00 0 000000 11111111111111111111, no need to register
    std::map<AccessTokenID, AccessTokenID> MappingTokenIDPairMap;
    MappingTokenIDPairMap[537919487] = 456; // 456 is random input
    AccessTokenRemoteDevice device = {
        .deviceID_ = "dev-001",
        .MappingTokenIDPairMap_ = MappingTokenIDPairMap
    };
    AccessTokenRemoteTokenManager::GetInstance().remoteDeviceMap_["dev-001"] = device;

    // count(remoteID) > 0
    ASSERT_EQ(static_cast<AccessTokenID>(456),
        AccessTokenRemoteTokenManager::GetInstance().MapRemoteDeviceTokenToLocal(deviceID, remoteID));

    AccessTokenRemoteTokenManager::GetInstance().remoteDeviceMap_ = remoteDeviceMap; // recovery
}

/**
 * @tc.name: GetDeviceAllRemoteTokenID001
 * @tc.desc: AccessTokenRemoteTokenManager::GetDeviceAllRemoteTokenID function test
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(AccessTokenInfoManagerTest, GetDeviceAllRemoteTokenID001, TestSize.Level0)
{
    std::string deviceID;
    std::vector<AccessTokenID> remoteIDs;

    // deviceID invalid
    ASSERT_EQ(ERR_PARAM_INVALID,
        AccessTokenRemoteTokenManager::GetInstance().GetDeviceAllRemoteTokenID(deviceID, remoteIDs));
}

/**
 * @tc.name: RemoveDeviceMappingTokenID001
 * @tc.desc: AccessTokenRemoteTokenManager::RemoveDeviceMappingTokenID function test
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(AccessTokenInfoManagerTest, RemoveDeviceMappingTokenID001, TestSize.Level0)
{
    std::map<std::string, AccessTokenRemoteDevice> remoteDeviceMap;
    remoteDeviceMap = AccessTokenRemoteTokenManager::GetInstance().remoteDeviceMap_; // backup
    AccessTokenRemoteTokenManager::GetInstance().remoteDeviceMap_.clear();

    std::string deviceID;
    AccessTokenID remoteID = 0;

    // input invalid
    ASSERT_NE(RET_SUCCESS,
        AccessTokenRemoteTokenManager::GetInstance().RemoveDeviceMappingTokenID(deviceID, remoteID));

    deviceID = "dev-001";
    remoteID = 123; // 123 is random input

    // count < 1
    ASSERT_NE(RET_SUCCESS,
        AccessTokenRemoteTokenManager::GetInstance().RemoveDeviceMappingTokenID(deviceID, remoteID));

    AccessTokenRemoteTokenManager::GetInstance().remoteDeviceMap_ = remoteDeviceMap; // recovery
}

/**
 * @tc.name: AddHapTokenObservation001
 * @tc.desc: TokenModifyNotifier::AddHapTokenObservation function test
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(AccessTokenInfoManagerTest, AddHapTokenObservation001, TestSize.Level0)
{
    std::set<AccessTokenID> observationSet = TokenModifyNotifier::GetInstance().observationSet_; // backup
    TokenModifyNotifier::GetInstance().observationSet_.clear();

    AccessTokenID tokenId = 123; // 123 is random input

    TokenModifyNotifier::GetInstance().observationSet_.insert(tokenId);
    ASSERT_EQ(true, TokenModifyNotifier::GetInstance().observationSet_.count(tokenId) > 0);

    // count > 0
    TokenModifyNotifier::GetInstance().AddHapTokenObservation(tokenId);
    TokenModifyNotifier::GetInstance().NotifyTokenModify(tokenId);

    TokenModifyNotifier::GetInstance().observationSet_ = observationSet; // recovery
}
#endif

/**
 * @tc.name: RestoreHapTokenInfo001
 * @tc.desc: HapTokenInfoInner::RestoreHapTokenInfo function test
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(AccessTokenInfoManagerTest, RestoreHapTokenInfo001, TestSize.Level0)
{
    std::shared_ptr<HapTokenInfoInner> hap = std::make_shared<HapTokenInfoInner>();
    ASSERT_NE(nullptr, hap);

    AccessTokenID tokenId = 0;
    GenericValues tokenValue;
    std::vector<GenericValues> permStateRes;
    std::vector<GenericValues> extendedPermRes;
    std::string bundleName;
    std::string appIDDesc;
    std::string deviceID;
    int version = 10; // 10 is random input which only need not equal 1
    HapPolicy policy;
    UpdateHapInfoParams hapInfo;
    hapInfo.apiVersion = DEFAULT_API_VERSION;
    hapInfo.isSystemApp = false;
    hap->Update(hapInfo, policy.permStateList, policy); // permPolicySet_ is null

    std::string info;
    hap->ToString(info); // permPolicySet_ is null

    std::vector<GenericValues> hapInfoValues;
    std::vector<GenericValues> permStateValues;
    hap->StoreHapInfo(hapInfoValues, "test", APL_NORMAL);
    hap->StorePermissionPolicy(permStateValues); // permPolicySet_ is null


    tokenValue.Put(TokenFiledConst::FIELD_BUNDLE_NAME, bundleName);
    // bundleName invalid
    ASSERT_EQ(ERR_PARAM_INVALID, hap->RestoreHapTokenInfo(tokenId, tokenValue, permStateRes, extendedPermRes));
    tokenValue.Remove(TokenFiledConst::FIELD_BUNDLE_NAME);

    bundleName = "com.ohos.permissionmanger";
    tokenValue.Put(TokenFiledConst::FIELD_BUNDLE_NAME, bundleName);
    tokenValue.Put(TokenFiledConst::FIELD_TOKEN_VERSION, version);
    // version invalid
    ASSERT_EQ(ERR_PARAM_INVALID, hap->RestoreHapTokenInfo(tokenId, tokenValue, permStateRes, extendedPermRes));
}

/**
 * @tc.name: RegisterTokenId001
 * @tc.desc: AccessTokenIDManager::RegisterTokenId function test
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(AccessTokenInfoManagerTest, RegisterTokenId001, TestSize.Level0)
{
    // 1477443583 is max abnormal butt tokenId which version is 2: 010 11 0 000000 11111111111111111111
    AccessTokenID tokenId = 1477443583;
    ATokenTypeEnum type = ATokenTypeEnum::TOKEN_HAP;

    // version != 1 + type dismatch
    ASSERT_NE(RET_SUCCESS, AccessTokenIDManager::GetInstance().RegisterTokenId(tokenId, type));

    AccessTokenIDEx tokenIdEx = {0};
    std::vector<GenericValues> undefValues;
    ASSERT_EQ(RET_SUCCESS, AccessTokenInfoManager::GetInstance().CreateHapTokenInfo(g_infoManagerTestInfoParms,
        g_infoManagerTestPolicyPrams1, tokenIdEx, undefValues));

    // register repeat
    ASSERT_NE(RET_SUCCESS, AccessTokenIDManager::GetInstance().RegisterTokenId(
        tokenIdEx.tokenIdExStruct.tokenID, type));
    ASSERT_EQ(RET_SUCCESS, AccessTokenInfoManager::GetInstance().RemoveHapTokenInfo(tokenIdEx.tokenIdExStruct.tokenID));
}

/**
 * @tc.name: ClearAllSecCompGrantedPerm001
 * @tc.desc: ClearAllSecCompGrantedPerm function test
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(AccessTokenInfoManagerTest, ClearAllSecCompGrantedPerm001, TestSize.Level0)
{
    AccessTokenIDEx tokenIdEx = {0};
    std::vector<GenericValues> undefValues;
    int32_t ret = AccessTokenInfoManager::GetInstance().CreateHapTokenInfo(
        g_infoManagerTestInfoParms, g_infoManagerTestPolicyPrams1, tokenIdEx, undefValues);
    ASSERT_EQ(RET_SUCCESS, ret);
    AccessTokenID tokenId = tokenIdEx.tokenIdExStruct.tokenID;

    ASSERT_EQ(PERMISSION_DENIED,
        AccessTokenInfoManager::GetInstance().VerifyAccessToken(tokenId, "ohos.permission.LOCATION"));
    PermissionManager::GetInstance().GrantPermission(tokenId, "ohos.permission.LOCATION", PERMISSION_COMPONENT_SET);
    ASSERT_EQ(PERMISSION_GRANTED,
        AccessTokenInfoManager::GetInstance().VerifyAccessToken(tokenId, "ohos.permission.LOCATION"));

    std::string deviceId;
    atManagerService_->OnRemoveSystemAbility(SECURITY_COMPONENT_SERVICE_ID, deviceId);
    ASSERT_EQ(PERMISSION_DENIED,
        AccessTokenInfoManager::GetInstance().VerifyAccessToken(tokenId, "ohos.permission.LOCATION"));

    // delete test token
    ASSERT_EQ(RET_SUCCESS, AccessTokenInfoManager::GetInstance().RemoveHapTokenInfo(tokenId));
}

/**
 * @tc.name: SetPermDialogCap001
 * @tc.desc: SetPermDialogCap with HapUniqueKey not exist
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(AccessTokenInfoManagerTest, SetPermDialogCap001, TestSize.Level0)
{
    AccessTokenID tokenId = 123; // 123: invalid tokenid
    ASSERT_EQ(ERR_TOKENID_NOT_EXIST, AccessTokenInfoManager::GetInstance().SetPermDialogCap(tokenId, true));
}

/**
 * @tc.name: SetPermDialogCap002
 * @tc.desc: SetPermDialogCap with abnormal branch
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(AccessTokenInfoManagerTest, SetPermDialogCap002, TestSize.Level0)
{
    AccessTokenIDEx tokenIdEx = {0};
    std::vector<GenericValues> undefValues;
    int32_t ret = AccessTokenInfoManager::GetInstance().CreateHapTokenInfo(
        g_infoManagerTestInfoParms, g_infoManagerTestPolicyPrams1, tokenIdEx, undefValues);
    ASSERT_EQ(RET_SUCCESS, ret);
    AccessTokenID tokenId = tokenIdEx.tokenIdExStruct.tokenID;

    // SetPermDialogCap successfull
    ASSERT_EQ(RET_SUCCESS, AccessTokenInfoManager::GetInstance().SetPermDialogCap(tokenId, true));
    ASSERT_EQ(true, AccessTokenInfoManager::GetInstance().GetPermDialogCap(tokenId));
    ASSERT_EQ(RET_SUCCESS, AccessTokenInfoManager::GetInstance().SetPermDialogCap(tokenId, false));
    ASSERT_EQ(false, AccessTokenInfoManager::GetInstance().GetPermDialogCap(tokenId));

    std::shared_ptr<HapTokenInfoInner> back = AccessTokenInfoManager::GetInstance().hapTokenInfoMap_[tokenId];

    // tokeninfo of hapTokenInfoMap_ is nullptr, return true(forbid)
    AccessTokenInfoManager::GetInstance().hapTokenInfoMap_[tokenId] = nullptr;
    ASSERT_EQ(ERR_TOKENID_NOT_EXIST,
        AccessTokenInfoManager::GetInstance().SetPermDialogCap(tokenId, true)); // info is null
    ASSERT_EQ(true, AccessTokenInfoManager::GetInstance().GetPermDialogCap(tokenId));

    // token is not found in hapTokenInfoMap_, return true(forbid)
    AccessTokenInfoManager::GetInstance().hapTokenInfoMap_.erase(tokenId);
    ASSERT_EQ(ERR_TOKENID_NOT_EXIST,
        AccessTokenInfoManager::GetInstance().SetPermDialogCap(tokenId, true)); // info is null
    ASSERT_EQ(true, AccessTokenInfoManager::GetInstance().GetPermDialogCap(tokenId));
    AccessTokenInfoManager::GetInstance().hapTokenInfoMap_[tokenId] = back;
    
    ASSERT_EQ(RET_SUCCESS, AccessTokenInfoManager::GetInstance().RemoveHapTokenInfo(tokenId));
}

/**
 * @tc.name: GetPermDialogCap001
 * @tc.desc: GetPermDialogCap with abnormal branch
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(AccessTokenInfoManagerTest, GetPermDialogCap001, TestSize.Level0)
{
    // invalid token
    ASSERT_EQ(true, AccessTokenInfoManager::GetInstance().GetPermDialogCap(INVALID_TOKENID));

    // nonexist token
    ASSERT_EQ(true, AccessTokenInfoManager::GetInstance().GetPermDialogCap(123)); // 123: tokenid

    // tokeninfo is nullptr
    HapBaseInfo baseInfo = {
        .userID = g_infoManagerTestInfoParms.userID,
        .bundleName = g_infoManagerTestInfoParms.bundleName,
        .instIndex = g_infoManagerTestInfoParms.instIndex,
    };
    AccessTokenIDEx tokenIdEx = {0};
    std::vector<GenericValues> undefValues;
    int32_t ret = AccessTokenInfoManager::GetInstance().CreateHapTokenInfo(
        g_infoManagerTestInfoParms, g_infoManagerTestPolicyPrams1, tokenIdEx, undefValues);
    ASSERT_EQ(RET_SUCCESS, ret);
    AccessTokenID tokenId = tokenIdEx.tokenIdExStruct.tokenID;
    std::shared_ptr<HapTokenInfoInner> back = AccessTokenInfoManager::GetInstance().hapTokenInfoMap_[tokenId];
    AccessTokenInfoManager::GetInstance().hapTokenInfoMap_[tokenId] = nullptr;
    ASSERT_EQ(true, AccessTokenInfoManager::GetInstance().GetPermDialogCap(123)); // 123: tokenid

    AccessTokenInfoManager::GetInstance().hapTokenInfoMap_[tokenId] = back;
    ASSERT_EQ(RET_SUCCESS, AccessTokenInfoManager::GetInstance().RemoveHapTokenInfo(tokenId));
}

/**
 * @tc.name: AllocHapToken001
 * @tc.desc: alloc hap create haptokeninfo failed.
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(AccessTokenInfoManagerTest, AllocHapToken001, TestSize.Level0)
{
    HapInfoParcel hapinfoParcel;
    hapinfoParcel.hapInfoParameter = {
        .userID = -1,
        .bundleName = "accesstoken_test",
        .instIndex = 0,
        .appIDDesc = "testtesttesttest",
        .apiVersion = DEFAULT_API_VERSION,
        .isSystemApp = false,
    };
    HapPolicyParcel hapPolicyParcel;
    hapPolicyParcel.hapPolicy.apl = ATokenAplEnum::APL_NORMAL;
    hapPolicyParcel.hapPolicy.domain = "test.domain";

    uint64_t tokenIDEx;
    atManagerService_->AllocHapToken(hapinfoParcel, hapPolicyParcel, tokenIDEx);
    ASSERT_EQ(INVALID_TOKENID, tokenIDEx);
}

/**
 * @tc.name: OnStart001
 * @tc.desc: service is running.
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(AccessTokenInfoManagerTest, OnStart001, TestSize.Level0)
{
    ServiceRunningState state = atManagerService_->state_;
    atManagerService_->state_ = ServiceRunningState::STATE_RUNNING;
    atManagerService_->OnStart();
    ASSERT_EQ(ServiceRunningState::STATE_RUNNING, atManagerService_->state_);
    atManagerService_->state_ = state;
}

/**
 * @tc.name: Dlopen001
 * @tc.desc: Open a not exist lib & not exist func
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(AccessTokenInfoManagerTest, Dlopen001, TestSize.Level0)
{
    LibraryLoader loader1("libnotexist.z.so"); // is a not exist path
    EXPECT_EQ(nullptr, loader1.handle_);

    LibraryLoader loader2("libaccesstoken_manager_service.z.so"); // is a exist lib without create func
    EXPECT_EQ(nullptr, loader2.instance_);
    EXPECT_NE(nullptr, loader2.handle_);
}

#ifdef TOKEN_SYNC_ENABLE
/**
 * @tc.name: Dlopen002
 * @tc.desc: Open a exist lib & exist func
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(AccessTokenInfoManagerTest, Dlopen002, TestSize.Level0)
{
    LibraryLoader loader(TOKEN_SYNC_LIBPATH);
    TokenSyncKitInterface* tokenSyncKit = loader.GetObject<TokenSyncKitInterface>();
    EXPECT_NE(nullptr, loader.handle_);
    EXPECT_NE(nullptr, tokenSyncKit);
}
#endif

/**
 * @tc.name: VerifyNativeAccessToken001
 * @tc.desc: AccessTokenInfoManagerTest::VerifyNativeAccessToken function test
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(AccessTokenInfoManagerTest, VerifyNativeAccessToken001, TestSize.Level0)
{
    AccessTokenID tokenId = 0x280bc142; // 0x280bc142 is random input
    std::string permissionName = "ohos.permission.INVALID_AA";
    AccessTokenID tokenId1 = AccessTokenInfoManager::GetInstance().GetNativeTokenId("accesstoken_service");
    // tokenId is not exist
    ASSERT_EQ(PermissionState::PERMISSION_DENIED,
        AccessTokenInfoManager::GetInstance().VerifyNativeAccessToken(tokenId, permissionName));

    permissionName = "ohos.permission.CAMERA";
    // permission is not request
    ASSERT_EQ(PermissionState::PERMISSION_DENIED,
        AccessTokenInfoManager::GetInstance().VerifyNativeAccessToken(tokenId1, permissionName));

    // tokenId is native token, and permission is defined
    ASSERT_EQ(PermissionState::PERMISSION_DENIED,
        AccessTokenInfoManager::GetInstance().VerifyNativeAccessToken(tokenId1, permissionName));

    permissionName = "ohos.permission.KILL_APP_PROCESSES";
    ASSERT_EQ(PermissionState::PERMISSION_GRANTED,
        AccessTokenInfoManager::GetInstance().VerifyNativeAccessToken(tokenId1, permissionName));
}

/**
 * @tc.name: VerifyAccessToken001
 * @tc.desc: AccessTokenInfoManagerTest::VerifyAccessToken function test
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(AccessTokenInfoManagerTest, VerifyAccessToken001, TestSize.Level0)
{
    AccessTokenID tokenId = 0;
    std::string permissionName;
    // tokenID invalid
    ASSERT_EQ(PERMISSION_DENIED, AccessTokenInfoManager::GetInstance().VerifyAccessToken(tokenId, permissionName));

    tokenId = 940572671; // 940572671 is max butt tokenId: 001 11 0 000000 11111111111111111111
    // permissionName invalid
    ASSERT_EQ(PERMISSION_DENIED, AccessTokenInfoManager::GetInstance().VerifyAccessToken(tokenId, permissionName));

    // tokenID invalid
    permissionName = "ohos.permission.CAMERA";
    ASSERT_EQ(PERMISSION_DENIED, AccessTokenInfoManager::GetInstance().VerifyAccessToken(tokenId, permissionName));
}

/**
 * @tc.name: GetAppId001
 * @tc.desc: AccessTokenInfoManagerTest::VerifyAccessToken function test
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(AccessTokenInfoManagerTest, GetAppId001, TestSize.Level0)
{
    HapInfoParams info = {
        .userID = USER_ID,
        .bundleName = "accesstoken_info_manager_test",
        .instIndex = INST_INDEX,
        .appIDDesc = "accesstoken_info_manager_test"
    };
    HapPolicy policy = {
        .apl = APL_NORMAL,
        .domain = "domain"
    };
    AccessTokenIDEx tokenIdEx = {0};
    std::vector<GenericValues> undefValues;
    ASSERT_EQ(RET_SUCCESS, AccessTokenInfoManager::GetInstance().CreateHapTokenInfo(info, policy, tokenIdEx,
        undefValues));
    std::string appId;
    int ret = AccessTokenInfoManager::GetInstance().GetHapAppIdByTokenId(tokenIdEx.tokenIdExStruct.tokenID, appId);
    ASSERT_EQ(ret, RET_SUCCESS);
    ASSERT_EQ(appId, "accesstoken_info_manager_test");
    ASSERT_EQ(RET_SUCCESS, AccessTokenInfoManager::GetInstance().RemoveHapTokenInfo(tokenIdEx.tokenIdExStruct.tokenID));
}


/**
 * @tc.name: SetPermissionRequestToggleStatus001
 * @tc.desc: PermissionManager::SetPermissionRequestToggleStatus function test with invalid permissionName, invalid
 * status and invalid userID.
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(AccessTokenInfoManagerTest, SetPermissionRequestToggleStatus001, TestSize.Level0)
{
    int32_t userID = -1;
    uint32_t status = PermissionRequestToggleStatus::CLOSED;
    std::string permissionName = "ohos.permission.CAMERA";

    // UserId is invalid.
    ASSERT_EQ(ERR_PARAM_INVALID, AccessTokenInfoManager::GetInstance().SetPermissionRequestToggleStatus(
        permissionName, status, userID));

    // Permission name is invalid.
    userID = 123;
    ASSERT_EQ(ERR_PARAM_INVALID, AccessTokenInfoManager::GetInstance().SetPermissionRequestToggleStatus(
        "", status, userID));

    // PermissionName is not defined.
    permissionName = "ohos.permission.invalid";
    ASSERT_EQ(ERR_PERMISSION_NOT_EXIST, AccessTokenInfoManager::GetInstance().SetPermissionRequestToggleStatus(
        permissionName, status, userID));

    // Permission is system_grant.
    permissionName = "ohos.permission.USE_BLUETOOTH";
    ASSERT_EQ(ERR_PARAM_INVALID, AccessTokenInfoManager::GetInstance().SetPermissionRequestToggleStatus(
        permissionName, status, userID));

    // Status is invalid.
    status = -1;
    permissionName = "ohos.permission.CAMERA";
    ASSERT_EQ(ERR_PARAM_INVALID, AccessTokenInfoManager::GetInstance().SetPermissionRequestToggleStatus(
        permissionName, status, userID));
}

/**
 * @tc.name: SetPermissionRequestToggleStatus002
 * @tc.desc: PermissionManager::SetPermissionRequestToggleStatus function test with normal process.
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(AccessTokenInfoManagerTest, SetPermissionRequestToggleStatus002, TestSize.Level0)
{
    int32_t userID = 123;
    uint32_t status = PermissionRequestToggleStatus::CLOSED;
    std::string permissionName = "ohos.permission.CAMERA";

    ASSERT_EQ(RET_SUCCESS, AccessTokenInfoManager::GetInstance().SetPermissionRequestToggleStatus(
        permissionName, status, userID));

    status = PermissionRequestToggleStatus::OPEN;
    ASSERT_EQ(RET_SUCCESS, AccessTokenInfoManager::GetInstance().SetPermissionRequestToggleStatus(
        permissionName, status, userID));
}

/**
 * @tc.name: GetPermissionRequestToggleStatus001
 * @tc.desc: PermissionManager::GetPermissionRequestToggleStatus function test with invalid userID, invalid permission
 * name.
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(AccessTokenInfoManagerTest, GetPermissionRequestToggleStatus001, TestSize.Level0)
{
    int32_t userID = -1;
    uint32_t status;
    std::string permissionName = "ohos.permission.CAMERA";

    // UserId is invalid.
    ASSERT_EQ(ERR_PARAM_INVALID, AccessTokenInfoManager::GetInstance().GetPermissionRequestToggleStatus(
        permissionName, status, userID));

    // PermissionName is invalid.
    userID = 123;
    ASSERT_EQ(ERR_PARAM_INVALID, AccessTokenInfoManager::GetInstance().GetPermissionRequestToggleStatus(
        "", status, userID));

    // PermissionName is not defined.
    permissionName = "ohos.permission.invalid";
    ASSERT_EQ(ERR_PERMISSION_NOT_EXIST, AccessTokenInfoManager::GetInstance().GetPermissionRequestToggleStatus(
        permissionName, status, userID));

    // Permission is system_grant.
    permissionName = "ohos.permission.USE_BLUETOOTH";
    ASSERT_EQ(ERR_PARAM_INVALID, AccessTokenInfoManager::GetInstance().GetPermissionRequestToggleStatus(
        permissionName, status, userID));
}

/**
 * @tc.name: GetPermissionRequestToggleStatus002
 * @tc.desc: PermissionManager::GetPermissionRequestToggleStatus function test with normal process.
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(AccessTokenInfoManagerTest, GetPermissionRequestToggleStatus002, TestSize.Level0)
{
    int32_t userID = 123;
    uint32_t setStatusClose = PermissionRequestToggleStatus::CLOSED;
    uint32_t setStatusOpen = PermissionRequestToggleStatus::OPEN;
    uint32_t getStatus;

    ASSERT_EQ(RET_SUCCESS, AccessTokenInfoManager::GetInstance().GetPermissionRequestToggleStatus(
        "ohos.permission.CAMERA", getStatus, userID));

    ASSERT_EQ(setStatusOpen, getStatus);

    ASSERT_EQ(RET_SUCCESS, AccessTokenInfoManager::GetInstance().SetPermissionRequestToggleStatus(
        "ohos.permission.CAMERA", setStatusClose, userID));

    ASSERT_EQ(RET_SUCCESS, AccessTokenInfoManager::GetInstance().GetPermissionRequestToggleStatus(
        "ohos.permission.CAMERA", getStatus, userID));

    ASSERT_EQ(setStatusClose, getStatus);

    ASSERT_EQ(RET_SUCCESS, AccessTokenInfoManager::GetInstance().SetPermissionRequestToggleStatus(
        "ohos.permission.CAMERA", setStatusOpen, userID));

    ASSERT_EQ(RET_SUCCESS, AccessTokenInfoManager::GetInstance().GetPermissionRequestToggleStatus(
        "ohos.permission.CAMERA", getStatus, userID));

    ASSERT_EQ(setStatusOpen, getStatus);
}

/**
 * @tc.name: IsPermissionRestrictedByUserPolicy001
 * @tc.desc: IsPermissionRestrictedByUserPolicy function test with invalid tokenid.
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(AccessTokenInfoManagerTest, IsPermissionRestrictedByUserPolicy001, TestSize.Level0)
{
    AccessTokenID tokenID = 123; // invalid tokenid
    EXPECT_TRUE(AccessTokenInfoManager::GetInstance().IsPermissionRestrictedByUserPolicy(tokenID,
        "ohos.permission.CAMERA"));
}
} // namespace AccessToken
} // namespace Security
} // namespace OHOS