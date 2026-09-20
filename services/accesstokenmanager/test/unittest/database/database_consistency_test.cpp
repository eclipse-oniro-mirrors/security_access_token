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

#include "database_consistency_test.h"
#include "gtest/gtest.h"

#include "access_token_db.h"
#include "access_token_error.h"
#include "accesstoken_info_manager.h"
#include "atm_tools_param_info_parcel.h"
#include "hap_token_info_inner.h"
#include "parameters.h"
#include "permission_manager.h"
#include "permission_map.h"
#include "table_item.h"
#include "token_field_const.h"

using namespace testing::ext;
using namespace OHOS;

namespace OHOS {
namespace Security {
namespace AccessToken {
namespace {
static constexpr int32_t USER_ID = 100;
static constexpr int32_t INST_INDEX = 0;
static constexpr int32_t API_VERSION_9 = 9;

static PermissionStatus g_state1 = { // user grant permission
    .permissionName = "ohos.permission.WRITE_CALENDAR",
    .grantStatus = static_cast<int32_t>(PermissionState::PERMISSION_DENIED),
    .grantFlag = static_cast<uint32_t>(PermissionFlag::PERMISSION_DEFAULT_FLAG)
};

static PermissionStatus g_state2 = { // system core and granted
    .permissionName = "ohos.permission.POWER_MANAGER",
    .grantStatus = static_cast<int32_t>(PermissionState::PERMISSION_GRANTED),
    .grantFlag = static_cast<uint32_t>(PermissionFlag::PERMISSION_SYSTEM_FIXED)
};

static PermissionStatus g_state3 = { // system grant permission
    .permissionName = "ohos.permission.REFRESH_USER_ACTION",
    .grantStatus = static_cast<int32_t>(PermissionState::PERMISSION_DENIED),
    .grantFlag = static_cast<uint32_t>(PermissionFlag::PERMISSION_DEFAULT_FLAG)
};

static PermissionStatus g_state4 = { // system grant permission
    .permissionName = "ohos.permission.REFRESH_USER_ACTION",
    .grantStatus = static_cast<int32_t>(PermissionState::PERMISSION_GRANTED),
    .grantFlag = static_cast<uint32_t>(PermissionFlag::PERMISSION_SYSTEM_FIXED)
};

static PermissionStatus g_state5 = { // system grant permission
    .permissionName = "ohos.permission.READ_SCREEN_SAVER",
    .grantStatus = static_cast<int32_t>(PermissionState::PERMISSION_GRANTED),
    .grantFlag = static_cast<uint32_t>(PermissionFlag::PERMISSION_SYSTEM_FIXED)
};

static PermissionStatus g_state6 = { // system grant permission
    .permissionName = "ohos.permission.MANAGE_LOCAL_ACCOUNTS",
    .grantStatus = static_cast<int32_t>(PermissionState::PERMISSION_DENIED),
    .grantFlag = static_cast<uint32_t>(PermissionFlag::PERMISSION_DEFAULT_FLAG)
};

static HapInfoParams g_info = { // system app
    .userID = USER_ID,
    .bundleName = "AccessTokenDbConsistencyTest",
    .instIndex = INST_INDEX,
    .dlpType = static_cast<int>(HapDlpType::DLP_COMMON),
    .apiVersion = API_VERSION_9,
    .isSystemApp = true,
    .appIDDesc = "AccessTokenDbConsistencyTestDesc",
};

static HapPolicy g_policy = {
    .apl = ATokenAplEnum::APL_SYSTEM_CORE,
    .domain = "test.domain",
    .permStateList = {g_state1, g_state2, g_state3},
};
}

void AccessTokenDbConsistencyTest::SetUpTestCase()
{
}

void AccessTokenDbConsistencyTest::TearDownTestCase()
{
}

void AccessTokenDbConsistencyTest::SetUp()
{
    atManagerService_ = DelayedSingleton<AccessTokenManagerService>::GetInstance();
    EXPECT_NE(nullptr, atManagerService_);
}

void AccessTokenDbConsistencyTest::TearDown()
{
    DelayedSingleton<AccessTokenManagerService>::DestroyInstance();
    atManagerService_ = nullptr;
}

void AccessTokenDbConsistencyTest::CreateHapToken(const HapInfoParcel& infoParCel, const HapPolicyParcel& policyParcel,
    AccessTokenID& tokenId, std::map<int32_t, int32_t>& tokenIdAplMap, bool hasInit)
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
    tokenIdAplMap[static_cast<int32_t>(tokenId)] = g_policy.apl;
}

/**
 * @tc.name: CreateHapTokenCompareTest001
 * @tc.desc: test consistency between cache & DB after add hap
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(AccessTokenDbConsistencyTest, CreateHapTokenCompareTest001, TestSize.Level0)
{
    HapInfoParcel infoParCel;
    infoParCel.hapInfoParameter = g_info;
    HapPolicyParcel policyParcel;
    policyParcel.hapPolicy = g_policy;
    AccessTokenID tokenId;
    std::map<int32_t, int32_t> tokenIdAplMap;
    CreateHapToken(infoParCel, policyParcel, tokenId, tokenIdAplMap);

    // compare after add
    GenericValues conditionValue;
    conditionValue.Put(TokenFiledConst::FIELD_TOKEN_ID, static_cast<int32_t>(tokenId));
    std::vector<GenericValues> results;
    EXPECT_EQ(RET_SUCCESS, AccessTokenDb::GetInstance()->Find(
        AtmDataType::ACCESSTOKEN_PERMISSION_STATE, conditionValue, results));
    EXPECT_EQ(policyParcel.hapPolicy.permStateList.size(), results.size()); // size is 3
    for (auto const &val : results) {
        std::string perm = val.GetString(TokenFiledConst::FIELD_PERMISSION_NAME);
        auto it = std::find_if(policyParcel.hapPolicy.permStateList.begin(), policyParcel.hapPolicy.permStateList.end(),
            [&perm](const PermissionStatus &status) { return status.permissionName == perm; });
        EXPECT_TRUE(it != policyParcel.hapPolicy.permStateList.end());
        EXPECT_EQ(atManagerService_->VerifyAccessToken(tokenId, perm), val.GetInt(TokenFiledConst::FIELD_GRANT_STATE));
    }

    std::vector<GenericValues> results2;
    EXPECT_EQ(RET_SUCCESS, AccessTokenDb::GetInstance()->Find(
        AtmDataType::ACCESSTOKEN_HAP_TOKEN_INFO, conditionValue, results2));
    EXPECT_EQ(1, results2.size());

    EXPECT_EQ(RET_SUCCESS, atManagerService_->DeleteToken(tokenId, false));
}

/**
 * @tc.name: UpdateHapTokenCompareTest001
 * @tc.desc: test consistency between cache & DB after update hap
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(AccessTokenDbConsistencyTest, UpdateHapTokenCompareTest001, TestSize.Level0)
{
    HapInfoParcel infoParCel;
    infoParCel.hapInfoParameter = g_info;
    HapPolicyParcel policyParcel;
    policyParcel.hapPolicy = g_policy;
    AccessTokenID tokenId;
    std::map<int32_t, int32_t> tokenIdAplMap;
    CreateHapToken(infoParCel, policyParcel, tokenId, tokenIdAplMap);

    // update hap
    uint64_t fullTokenId;
    AccessTokenIDEx tokenIDEx;
    tokenIDEx.tokenIdExStruct.tokenID = tokenId;
    fullTokenId = tokenIDEx.tokenIDEx;
    policyParcel.hapPolicy.permStateList = {g_state2, g_state4, g_state5, g_state6};
    UpdateHapInfoParamsIdl infoIdl;
    infoIdl.appIDDesc = g_info.appIDDesc;
    infoIdl.apiVersion = g_info.apiVersion;
    infoIdl.isSystemApp = g_info.isSystemApp;
    infoIdl.appDistributionType = g_info.appDistributionType;
    infoIdl.isAtomicService = g_info.isAtomicService;
    infoIdl.dataRefresh = true;
    HapInfoCheckResultIdl resultInfoIdl;
    EXPECT_EQ(RET_SUCCESS, atManagerService_->UpdateHapToken(fullTokenId, infoIdl, policyParcel, resultInfoIdl));

    // compare after update
    GenericValues conditionValue;
    conditionValue.Put(TokenFiledConst::FIELD_TOKEN_ID, static_cast<int32_t>(tokenId));
    std::vector<GenericValues> results;
    EXPECT_EQ(RET_SUCCESS, AccessTokenDb::GetInstance()->Find(
        AtmDataType::ACCESSTOKEN_PERMISSION_STATE, conditionValue, results));
    EXPECT_EQ(policyParcel.hapPolicy.permStateList.size(), results.size()); // size is 4
    for (auto const &val : results) {
        std::string perm = val.GetString(TokenFiledConst::FIELD_PERMISSION_NAME);
        auto it = std::find_if(policyParcel.hapPolicy.permStateList.begin(), policyParcel.hapPolicy.permStateList.end(),
            [&perm](const PermissionStatus &status) { return status.permissionName == perm; });
        EXPECT_TRUE(it != policyParcel.hapPolicy.permStateList.end());
        EXPECT_EQ(atManagerService_->VerifyAccessToken(tokenId, perm), val.GetInt(TokenFiledConst::FIELD_GRANT_STATE));
    }

    std::vector<GenericValues> results2;
    EXPECT_EQ(RET_SUCCESS, AccessTokenDb::GetInstance()->Find(
        AtmDataType::ACCESSTOKEN_HAP_TOKEN_INFO, conditionValue, results2));
    EXPECT_EQ(1, results2.size());

    EXPECT_EQ(RET_SUCCESS, atManagerService_->DeleteToken(tokenId, false));
}

/**
 * @tc.name: HapTokenSideloadPersistTest001
 * @tc.desc: test sideload flag persistence: db roundtrip, restore path and default 0 for legacy rows
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(AccessTokenDbConsistencyTest, HapTokenSideloadPersistTest001, TestSize.Level0)
{
    HapInfoParcel infoParCel;
    infoParCel.hapInfoParameter = g_info;
    infoParCel.hapInfoParameter.appDistributionType = "developer_id";
    infoParCel.hapInfoParameter.isSideloadApp = true;
    HapPolicyParcel policyParcel;
    policyParcel.hapPolicy = g_policy;
    AccessTokenID tokenId;
    std::map<int32_t, int32_t> tokenIdAplMap;
    CreateHapToken(infoParCel, policyParcel, tokenId, tokenIdAplMap);

    // db row keeps is_sideload = 1 after install
    GenericValues conditionValue;
    conditionValue.Put(TokenFiledConst::FIELD_TOKEN_ID, static_cast<int32_t>(tokenId));
    std::vector<GenericValues> results;
    EXPECT_EQ(RET_SUCCESS, AccessTokenDb::GetInstance()->Find(
        AtmDataType::ACCESSTOKEN_HAP_TOKEN_INFO, conditionValue, results));
    ASSERT_EQ(1, results.size());
    EXPECT_EQ(1, results[0].GetInt(TokenFiledConst::FIELD_IS_SIDELOAD));

    // cache flag is consistent with db
    auto inner = AccessTokenInfoManager::GetInstance().GetHapTokenInfoInner(tokenId);
    ASSERT_NE(nullptr, inner);
    EXPECT_TRUE(inner->IsSideloadApp());

    // restore path: db rows -> HapTokenInfoItem -> HapTokenInfoInner
    std::vector<HapTokenInfoItem> items;
    HapTokenInfoItem::LoadFromDB(results, items);
    ASSERT_EQ(1, items.size());
    EXPECT_TRUE(items[0].isSideload);
    HapTokenInfoInner restored(items[0]);
    EXPECT_TRUE(restored.IsSideloadApp());

    // non-sideload token keeps default 0 in db
    HapInfoParcel infoParCel2;
    infoParCel2.hapInfoParameter = g_info;
    infoParCel2.hapInfoParameter.bundleName = g_info.bundleName + "2";
    AccessTokenID tokenId2;
    CreateHapToken(infoParCel2, policyParcel, tokenId2, tokenIdAplMap, true);
    GenericValues conditionValue2;
    conditionValue2.Put(TokenFiledConst::FIELD_TOKEN_ID, static_cast<int32_t>(tokenId2));
    std::vector<GenericValues> results2;
    EXPECT_EQ(RET_SUCCESS, AccessTokenDb::GetInstance()->Find(
        AtmDataType::ACCESSTOKEN_HAP_TOKEN_INFO, conditionValue2, results2));
    ASSERT_EQ(1, results2.size());
    EXPECT_EQ(0, results2[0].GetInt(TokenFiledConst::FIELD_IS_SIDELOAD));

    EXPECT_EQ(RET_SUCCESS, atManagerService_->DeleteToken(tokenId, false));
    EXPECT_EQ(RET_SUCCESS, atManagerService_->DeleteToken(tokenId2, false));
}

/**
 * @tc.name: UpdateHapTokenSideloadConsistencyTest001
 * @tc.desc: test cache & db consistency after dataRefresh update with sideload flag
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(AccessTokenDbConsistencyTest, UpdateHapTokenSideloadConsistencyTest001, TestSize.Level0)
{
    HapInfoParcel infoParCel;
    infoParCel.hapInfoParameter = g_info;
    infoParCel.hapInfoParameter.appDistributionType = "developer_id";
    infoParCel.hapInfoParameter.isSideloadApp = true;
    HapPolicyParcel policyParcel;
    policyParcel.hapPolicy = g_policy;
    AccessTokenID tokenId;
    std::map<int32_t, int32_t> tokenIdAplMap;
    CreateHapToken(infoParCel, policyParcel, tokenId, tokenIdAplMap);

    // dataRefresh update with consistent sideload flag success
    uint64_t fullTokenId;
    AccessTokenIDEx tokenIDEx;
    tokenIDEx.tokenIdExStruct.tokenID = tokenId;
    fullTokenId = tokenIDEx.tokenIDEx;
    UpdateHapInfoParamsIdl infoIdl;
    infoIdl.appIDDesc = g_info.appIDDesc;
    infoIdl.apiVersion = g_info.apiVersion;
    infoIdl.isSystemApp = g_info.isSystemApp;
    infoIdl.appDistributionType = "developer_id";
    infoIdl.isAtomicService = g_info.isAtomicService;
    infoIdl.dataRefresh = true;
    infoIdl.isSideloadApp = true;
    HapInfoCheckResultIdl resultInfoIdl;
    EXPECT_EQ(RET_SUCCESS, atManagerService_->UpdateHapToken(fullTokenId, infoIdl, policyParcel, resultInfoIdl));

    // db row keeps is_sideload = 1 after dataRefresh update
    GenericValues conditionValue;
    conditionValue.Put(TokenFiledConst::FIELD_TOKEN_ID, static_cast<int32_t>(tokenId));
    std::vector<GenericValues> results;
    EXPECT_EQ(RET_SUCCESS, AccessTokenDb::GetInstance()->Find(
        AtmDataType::ACCESSTOKEN_HAP_TOKEN_INFO, conditionValue, results));
    ASSERT_EQ(1, results.size());
    EXPECT_EQ(1, results[0].GetInt(TokenFiledConst::FIELD_IS_SIDELOAD));

    // cache flag keeps true after dataRefresh update
    auto inner = AccessTokenInfoManager::GetInstance().GetHapTokenInfoInner(tokenId);
    ASSERT_NE(nullptr, inner);
    EXPECT_TRUE(inner->IsSideloadApp());

    // update to non-sideload succeeds and flag flipped
    infoIdl.isSideloadApp = false;
    EXPECT_EQ(RET_SUCCESS, atManagerService_->UpdateHapToken(fullTokenId, infoIdl, policyParcel, resultInfoIdl));
    std::vector<GenericValues> results3;
    EXPECT_EQ(RET_SUCCESS, AccessTokenDb::GetInstance()->Find(
        AtmDataType::ACCESSTOKEN_HAP_TOKEN_INFO, conditionValue, results3));
    ASSERT_EQ(1, results3.size());
    EXPECT_EQ(0, results3[0].GetInt(TokenFiledConst::FIELD_IS_SIDELOAD));
    auto innerAfterRevoke = AccessTokenInfoManager::GetInstance().GetHapTokenInfoInner(tokenId);
    ASSERT_NE(nullptr, innerAfterRevoke);
    EXPECT_FALSE(innerAfterRevoke->IsSideloadApp());

    EXPECT_EQ(RET_SUCCESS, atManagerService_->DeleteToken(tokenId, false));
}

/**
 * @tc.name: SideloadParamNormalizeTest001
 * @tc.desc: inconsistent sideload params on create/update are normalized to non-sideload,
 *           update allows sideload <-> non-sideload transition, exemption follows updated state
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(AccessTokenDbConsistencyTest, SideloadParamNormalizeTest001, TestSize.Level0)
{
    // create with inconsistent sideload params succeeds and is normalized to non-sideload
    HapInfoParcel infoParCel;
    infoParCel.hapInfoParameter = g_info;
    infoParCel.hapInfoParameter.appDistributionType = "appgallery";
    infoParCel.hapInfoParameter.isSideloadApp = true;
    HapPolicyParcel policyParcel;
    policyParcel.hapPolicy = g_policy;
    AccessTokenID tokenId;
    std::map<int32_t, int32_t> tokenIdAplMap;
    CreateHapToken(infoParCel, policyParcel, tokenId, tokenIdAplMap);

    GenericValues conditionValue;
    conditionValue.Put(TokenFiledConst::FIELD_TOKEN_ID, static_cast<int32_t>(tokenId));
    std::vector<GenericValues> results;
    EXPECT_EQ(RET_SUCCESS, AccessTokenDb::GetInstance()->Find(
        AtmDataType::ACCESSTOKEN_HAP_TOKEN_INFO, conditionValue, results));
    ASSERT_EQ(1, results.size());
    EXPECT_EQ(0, results[0].GetInt(TokenFiledConst::FIELD_IS_SIDELOAD));
    auto inner = AccessTokenInfoManager::GetInstance().GetHapTokenInfoInner(tokenId);
    ASSERT_NE(nullptr, inner);
    EXPECT_FALSE(inner->IsSideloadApp());

    // update to sideload with consistent params succeeds and flag is persisted
    uint64_t fullTokenId;
    AccessTokenIDEx tokenIDEx;
    tokenIDEx.tokenIdExStruct.tokenID = tokenId;
    fullTokenId = tokenIDEx.tokenIDEx;
    UpdateHapInfoParamsIdl infoIdl;
    infoIdl.appIDDesc = g_info.appIDDesc;
    infoIdl.apiVersion = g_info.apiVersion;
    infoIdl.isSystemApp = g_info.isSystemApp;
    infoIdl.appDistributionType = "developer_id";
    infoIdl.isAtomicService = g_info.isAtomicService;
    infoIdl.dataRefresh = true;
    infoIdl.isSideloadApp = true;
    HapInfoCheckResultIdl resultInfoIdl;
    EXPECT_EQ(RET_SUCCESS, atManagerService_->UpdateHapToken(fullTokenId, infoIdl, policyParcel, resultInfoIdl));
    std::vector<GenericValues> results2;
    EXPECT_EQ(RET_SUCCESS, AccessTokenDb::GetInstance()->Find(
        AtmDataType::ACCESSTOKEN_HAP_TOKEN_INFO, conditionValue, results2));
    ASSERT_EQ(1, results2.size());
    EXPECT_EQ(1, results2[0].GetInt(TokenFiledConst::FIELD_IS_SIDELOAD));

    // update back to non-sideload succeeds and flag flipped
    infoIdl.isSideloadApp = false;
    EXPECT_EQ(RET_SUCCESS, atManagerService_->UpdateHapToken(fullTokenId, infoIdl, policyParcel, resultInfoIdl));
    std::vector<GenericValues> results3;
    EXPECT_EQ(RET_SUCCESS, AccessTokenDb::GetInstance()->Find(
        AtmDataType::ACCESSTOKEN_HAP_TOKEN_INFO, conditionValue, results3));
    ASSERT_EQ(1, results3.size());
    EXPECT_EQ(0, results3[0].GetInt(TokenFiledConst::FIELD_IS_SIDELOAD));

    EXPECT_EQ(RET_SUCCESS, atManagerService_->DeleteToken(tokenId, false));
}

/**
 * @tc.name: UpdateNonSideloadAclFailTest001
 * @tc.desc: with test perms: KERNEL_ATM_SELF_USE (sideload-available) is exempted on sideload create,
 *           update to non-sideload requesting it without acl is rejected and state unchanged
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(AccessTokenDbConsistencyTest, UpdateNonSideloadAclFailTest001, TestSize.Level0)
{
    // test perm definitions: KERNEL_ATM_SELF_USE supports sideload, MANUAL_ATM_SELF_USE does not
    PermissionBriefDef kernelDef;
    ASSERT_TRUE(GetPermissionBriefDef("ohos.permission.KERNEL_ATM_SELF_USE", kernelDef));
    EXPECT_TRUE(kernelDef.provisionBypassForSideload);
    PermissionBriefDef manualDef;
    ASSERT_TRUE(GetPermissionBriefDef("ohos.permission.MANUAL_ATM_SELF_USE", manualDef));
    EXPECT_FALSE(manualDef.provisionBypassForSideload);

    // create sideload token with normal apl requesting KERNEL_ATM_SELF_USE without acl: exempted
    HapInfoParcel infoParCel;
    infoParCel.hapInfoParameter = g_info;
    infoParCel.hapInfoParameter.appDistributionType = "developer_id";
    infoParCel.hapInfoParameter.isSideloadApp = true;
    HapPolicyParcel policyParcel;
    policyParcel.hapPolicy.apl = APL_NORMAL;
    policyParcel.hapPolicy.domain = "test.domain";
    PermissionStatus kernelState;
    kernelState.permissionName = "ohos.permission.KERNEL_ATM_SELF_USE";
    kernelState.grantStatus = static_cast<int32_t>(PermissionState::PERMISSION_GRANTED);
    kernelState.grantFlag = static_cast<uint32_t>(PermissionFlag::PERMISSION_SYSTEM_FIXED);
    policyParcel.hapPolicy.permStateList = {kernelState};
    AccessTokenID tokenId;
    std::map<int32_t, int32_t> tokenIdAplMap;
    CreateHapToken(infoParCel, policyParcel, tokenId, tokenIdAplMap);

    // update to non-sideload requesting the same perm without acl is rejected (fail-closed)
    uint64_t fullTokenId;
    AccessTokenIDEx tokenIDEx;
    tokenIDEx.tokenIdExStruct.tokenID = tokenId;
    fullTokenId = tokenIDEx.tokenIDEx;
    UpdateHapInfoParamsIdl infoIdl;
    infoIdl.appIDDesc = g_info.appIDDesc;
    infoIdl.apiVersion = g_info.apiVersion;
    infoIdl.isSystemApp = g_info.isSystemApp;
    infoIdl.appDistributionType = "appgallery";
    infoIdl.isAtomicService = g_info.isAtomicService;
    infoIdl.isSideloadApp = false;
    HapInfoCheckResultIdl resultInfoIdl;
    EXPECT_EQ(RET_SUCCESS,
        atManagerService_->UpdateHapToken(fullTokenId, infoIdl, policyParcel, resultInfoIdl));
    EXPECT_EQ(PERMISSION_ACL_RULE, static_cast<PermissionRulesEnum>(resultInfoIdl.rule));
    EXPECT_EQ(kernelState.permissionName, resultInfoIdl.permissionName);

    // rejected update keeps stored state unchanged
    GenericValues conditionValue;
    conditionValue.Put(TokenFiledConst::FIELD_TOKEN_ID, static_cast<int32_t>(tokenId));
    std::vector<GenericValues> results;
    EXPECT_EQ(RET_SUCCESS, AccessTokenDb::GetInstance()->Find(
        AtmDataType::ACCESSTOKEN_HAP_TOKEN_INFO, conditionValue, results));
    ASSERT_EQ(1, results.size());
    EXPECT_EQ(1, results[0].GetInt(TokenFiledConst::FIELD_IS_SIDELOAD));

    // phase 2: declare acl for the perm in the update policy (hasValue perm -> aclExtendedMap),
    // the same non-sideload update succeeds
    policyParcel.hapPolicy.aclExtendedMap = {{kernelState.permissionName, "1"}};
    EXPECT_EQ(RET_SUCCESS,
        atManagerService_->UpdateHapToken(fullTokenId, infoIdl, policyParcel, resultInfoIdl));

    // sideload flag flips to 0, the perm is kept via the acl path
    std::vector<GenericValues> results2;
    EXPECT_EQ(RET_SUCCESS, AccessTokenDb::GetInstance()->Find(
        AtmDataType::ACCESSTOKEN_HAP_TOKEN_INFO, conditionValue, results2));
    ASSERT_EQ(1, results2.size());
    EXPECT_EQ(0, results2[0].GetInt(TokenFiledConst::FIELD_IS_SIDELOAD));
    GenericValues permCondition;
    permCondition.Put(TokenFiledConst::FIELD_TOKEN_ID, static_cast<int32_t>(tokenId));
    permCondition.Put(TokenFiledConst::FIELD_PERMISSION_NAME, kernelState.permissionName);
    std::vector<GenericValues> permResults;
    EXPECT_EQ(RET_SUCCESS, AccessTokenDb::GetInstance()->Find(
        AtmDataType::ACCESSTOKEN_PERMISSION_STATE, permCondition, permResults));
    EXPECT_EQ(1, permResults.size());

    EXPECT_EQ(RET_SUCCESS, atManagerService_->DeleteToken(tokenId, false));
}

/**
 * @tc.name: SideloadDefaultInstallFailTest001
 * @tc.desc: default (non-sideload) app requesting a sideload-available acl perm without acl
 *           declaration fails to install (fail-closed), no token created
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(AccessTokenDbConsistencyTest, SideloadDefaultInstallFailTest001, TestSize.Level0)
{
    // isSideloadApp 缺省（false）+ developer_id 分发 → 非侧载（PC 插件同场景）
    HapInfoParcel infoParCel;
    infoParCel.hapInfoParameter = g_info;
    infoParCel.hapInfoParameter.appDistributionType = "developer_id";
    HapPolicyParcel policyParcel;
    policyParcel.hapPolicy.apl = APL_NORMAL;
    policyParcel.hapPolicy.domain = "test.domain";
    PermissionStatus kernelState;
    kernelState.permissionName = "ohos.permission.KERNEL_ATM_SELF_USE";
    kernelState.grantStatus = static_cast<int32_t>(PermissionState::PERMISSION_GRANTED);
    kernelState.grantFlag = static_cast<uint32_t>(PermissionFlag::PERMISSION_SYSTEM_FIXED);
    policyParcel.hapPolicy.permStateList = {kernelState};

    uint64_t fullTokenId = 0;
    HapInfoCheckResultIdl resultInfoIdl;
    EXPECT_EQ(RET_SUCCESS,
        atManagerService_->InitHapToken(infoParCel, policyParcel, fullTokenId, resultInfoIdl));
    EXPECT_EQ(PERMISSION_ACL_RULE, static_cast<PermissionRulesEnum>(resultInfoIdl.rule));
    EXPECT_EQ(kernelState.permissionName, resultInfoIdl.permissionName);
    EXPECT_EQ(0u, fullTokenId);
}

/**
 * @tc.name: UpdatePermStatusCompareTest001
 * @tc.desc: test consistency between cache & DB after grant & revoke
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(AccessTokenDbConsistencyTest, UpdatePermStatusCompareTest001, TestSize.Level0)
{
    HapInfoParcel infoParCel;
    infoParCel.hapInfoParameter = g_info;
    HapPolicyParcel policyParcel;
    policyParcel.hapPolicy = g_policy;
    AccessTokenID tokenId;
    std::map<int32_t, int32_t> tokenIdAplMap;
    CreateHapToken(infoParCel, policyParcel, tokenId, tokenIdAplMap);

    // grant
    PermissionManager::GetInstance().GrantPermission(
        tokenId, g_state1.permissionName, PermissionFlag::PERMISSION_USER_FIXED);
    PermissionManager::GetInstance().GrantPermission(
        tokenId, g_state3.permissionName, PermissionFlag::PERMISSION_SYSTEM_FIXED);

    // compare after grant
    GenericValues conditionValue;
    conditionValue.Put(TokenFiledConst::FIELD_TOKEN_ID, static_cast<int32_t>(tokenId));
    std::vector<GenericValues> results;
    EXPECT_EQ(RET_SUCCESS, AccessTokenDb::GetInstance()->Find(
        AtmDataType::ACCESSTOKEN_PERMISSION_STATE, conditionValue, results));
    EXPECT_EQ(policyParcel.hapPolicy.permStateList.size(), results.size()); // size is 3
    for (auto const &val : results) {
        std::string perm = val.GetString(TokenFiledConst::FIELD_PERMISSION_NAME);
        auto it = std::find_if(policyParcel.hapPolicy.permStateList.begin(), policyParcel.hapPolicy.permStateList.end(),
            [&perm](const PermissionStatus &status) { return status.permissionName == perm; });
        EXPECT_TRUE(it != policyParcel.hapPolicy.permStateList.end());
        EXPECT_EQ(atManagerService_->VerifyAccessToken(tokenId, perm), val.GetInt(TokenFiledConst::FIELD_GRANT_STATE));
    }

    // revoke
    PermissionManager::GetInstance().RevokePermission(
        tokenId, g_state1.permissionName, PermissionFlag::PERMISSION_USER_FIXED);
    PermissionManager::GetInstance().RevokePermission(
        tokenId, g_state2.permissionName, PermissionFlag::PERMISSION_SYSTEM_FIXED);

    // compare after revoke
    std::vector<GenericValues> results2;
    EXPECT_EQ(RET_SUCCESS, AccessTokenDb::GetInstance()->Find(
        AtmDataType::ACCESSTOKEN_PERMISSION_STATE, conditionValue, results2));
    EXPECT_EQ(policyParcel.hapPolicy.permStateList.size(), results2.size()); // size is 3
    for (auto const &val : results2) {
        std::string perm = val.GetString(TokenFiledConst::FIELD_PERMISSION_NAME);
        auto it = std::find_if(policyParcel.hapPolicy.permStateList.begin(), policyParcel.hapPolicy.permStateList.end(),
            [&perm](const PermissionStatus &status) { return status.permissionName == perm; });
        EXPECT_TRUE(it != policyParcel.hapPolicy.permStateList.end());
        EXPECT_EQ(atManagerService_->VerifyAccessToken(tokenId, perm), val.GetInt(TokenFiledConst::FIELD_GRANT_STATE));
    }

    std::vector<GenericValues> results3;
    EXPECT_EQ(RET_SUCCESS, AccessTokenDb::GetInstance()->Find(
        AtmDataType::ACCESSTOKEN_HAP_TOKEN_INFO, conditionValue, results3));
    EXPECT_EQ(1, results3.size());

    EXPECT_EQ(RET_SUCCESS, atManagerService_->DeleteToken(tokenId, false));
}

/**
 * @tc.name: DeleteHapTokenCompareTest001
 * @tc.desc: test consistency between cache & DB after delete hap
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(AccessTokenDbConsistencyTest, DeleteHapTokenCompareTest001, TestSize.Level0)
{
    HapInfoParcel infoParCel;
    infoParCel.hapInfoParameter = g_info;
    HapPolicyParcel policyParcel;
    policyParcel.hapPolicy = g_policy;
    AccessTokenID tokenId;
    std::map<int32_t, int32_t> tokenIdAplMap;
    CreateHapToken(infoParCel, policyParcel, tokenId, tokenIdAplMap);

    // delete
    EXPECT_EQ(RET_SUCCESS, atManagerService_->DeleteToken(tokenId, false));

    // get hap token info empty
    HapTokenInfo hapInfo;
    int32_t ret = AccessTokenInfoManager::GetInstance().GetHapTokenInfo(tokenId, hapInfo);
    EXPECT_EQ(ret, ERR_TOKENID_NOT_EXIST);

    GenericValues conditionValue;
    conditionValue.Put(TokenFiledConst::FIELD_TOKEN_ID, static_cast<int32_t>(tokenId));
    std::vector<GenericValues> results;
    EXPECT_EQ(RET_SUCCESS, AccessTokenDb::GetInstance()->Find(
        AtmDataType::ACCESSTOKEN_PERMISSION_STATE, conditionValue, results));
    EXPECT_EQ(0, results.size()); // size is 0

    std::vector<GenericValues> results2;
    EXPECT_EQ(RET_SUCCESS, AccessTokenDb::GetInstance()->Find(
        AtmDataType::ACCESSTOKEN_HAP_TOKEN_INFO, conditionValue, results2));
    EXPECT_EQ(0, results2.size()); // size is 0
}
} // namespace AccessToken
} // namespace Security
} // namespace OHOS
