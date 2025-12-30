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

#include "accesstoken_db_consistency_test.h"
#include "gtest/gtest.h"

#include "access_token_db.h"
#include "access_token_error.h"
#include "accesstoken_info_manager.h"
#include "atm_tools_param_info_parcel.h"
#include "parameters.h"
#include "permission_manager.h"
#include "permission_map.h"
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
        AtmDataType::ACCESSTOKEN_HAP_INFO, conditionValue, results2));
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
        AtmDataType::ACCESSTOKEN_HAP_INFO, conditionValue, results2));
    EXPECT_EQ(1, results2.size());

    EXPECT_EQ(RET_SUCCESS, atManagerService_->DeleteToken(tokenId, false));
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
        AtmDataType::ACCESSTOKEN_HAP_INFO, conditionValue, results3));
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
        AtmDataType::ACCESSTOKEN_HAP_INFO, conditionValue, results2));
    EXPECT_EQ(0, results2.size()); // size is 0
}
} // namespace AccessToken
} // namespace Security
} // namespace OHOS
