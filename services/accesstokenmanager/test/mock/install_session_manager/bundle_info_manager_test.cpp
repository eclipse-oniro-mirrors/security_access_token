/*
 * Copyright (c) 2026 Huawei Device Co., Ltd.
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

#include "bundle_info_manager_test.h"

#include <map>
#include <string>
#include <vector>

#include "accesstoken_dfx_define.h"
#include "accesstoken_id_manager.h"
#include "accesstoken_info_manager.h"
#include "accesstoken_info_utils.h"
#include "accesstoken_manager_service.h"
#include "atm_data_type.h"
#include "bundle_info_manager.h"
#include "delete_bundle_manager.h"
#include "install_session_manager.h"
#include "access_token.h"
#include "access_token_db_operator.h"
#include "access_token_error.h"
#include "generic_values.h"
#include "hap_token_info.h"
#include "token_field_const.h"

#ifdef SPM_DATA_ENABLE
using namespace testing::ext;
namespace OHOS {
namespace Security {
namespace AccessToken {
namespace {
// local aggregate of SignInfoQueryFlag: query every section in one call
constexpr uint32_t QUERY_ALL_SIGN_INFO = QUERY_PROFILE | QUERY_MODULE_INFO | QUERY_SHARED_FILES;
static constexpr int USER_ID = 100;
static constexpr int INST_INDEX = 0;
static std::shared_ptr<AccessTokenManagerService> atManagerService_;
static InstallSessionManager* g_installSessionManager = nullptr;

// This branch folds the DeleteIdentity chain into DeleteBundleManager, so the
// former DeleteIdentityCore entry maps onto DeleteIdentityWithDfx.
int32_t DeleteIdentityCore(AccessTokenID tokenID, const std::string& bundleName,
    ReservedType reservedType, int32_t& sceneCode)
{
    DeleteDfxInfo deleteDfx = {};
    int32_t ret = DeleteBundleManager::GetInstance().DeleteIdentityWithDfx(
        tokenID, bundleName, reservedType, deleteDfx);
    sceneCode = deleteDfx.sceneCode;
    return ret;
}
}

void BundleInfoManagerTest::SetUpTestCase()
{
    atManagerService_ = DelayedSingleton<AccessTokenManagerService>::GetInstance();
    g_installSessionManager = &InstallSessionManager::GetInstance();

    uint32_t nativeSize = 0;
    uint32_t pefDefSize = 0;
    uint32_t dlpSize = 0;
    AccessTokenInfoManager::GetInstance().Init(nativeSize, pefDefSize, dlpSize);
    g_installSessionManager->SetMigrationDone();
    AccessTokenIDManager::GetInstance().SetMigrationDone();
}

void BundleInfoManagerTest::TearDownTestCase()
{
    g_installSessionManager = nullptr;
    DelayedSingleton<AccessTokenManagerService>::DestroyInstance();
    atManagerService_ = nullptr;
}

void BundleInfoManagerTest::SetUp()
{}

void BundleInfoManagerTest::TearDown()
{}

/**
 * @tc.name: GetInfoByBundleNameTest001
 * @tc.desc: Test GetHapSignInfo.
 * @tc.type: FUNC
 * @tc.require: Issue
 */
HWTEST_F(BundleInfoManagerTest, GetInfoByBundleNameTest001, TestSize.Level0)
{
    std::string path =
        "/SYSTEM/system_basic/state:[mic,syswin,getwifi]/acl:[getwifi]/Module001/GetInfoByBundleNameTest001";
    std::string path2 =
        "/SYSTEM/system_basic/state:[cam,syswin]/Module002/GetInfoByBundleNameTest001";

    BundleHapList hapList;
    hapList.hapPaths.emplace_back(path);
    hapList.hapPaths.emplace_back(path2);
    hapList.isPreInstalled = false;
    hapList.userId = 100;

    int32_t sessionId = 0;
    std::vector<TrustedBundleInfo> bundleInfo;
    HapVerifyResultInfo resultInfo;
    EXPECT_EQ(ERR_OK, g_installSessionManager->CheckHapSignInfo(hapList, nullptr, sessionId, bundleInfo, resultInfo, QUERY_ALL_SIGN_INFO));

    HapInfoCheckResult result;
    EXPECT_EQ(ERR_OK, g_installSessionManager->CheckHapPermissionInfo(sessionId, TYPE_INSTALL, result));

    HapBaseInfo baseInfo;
    baseInfo.userID = 100;
    baseInfo.bundleName = "GetInfoByBundleNameTest001";
    baseInfo.instIndex = 0;

    BundlePolicy bundlePolicy;
    bundlePolicy.dlpType = DLP_COMMON;
    bundlePolicy.isDebugGrant = false;

    Identity identity = {0, -1};
    int32_t ret = g_installSessionManager->PrepareHapIdentity(sessionId, baseInfo, bundlePolicy, nullptr, identity);
    EXPECT_EQ(ERR_OK, ret);
    EXPECT_NE(0, identity.uid);
    EXPECT_NE(0, identity.tokenId);
    AccessTokenID tokenId = static_cast<AccessTokenID>(identity.tokenId);

    std::map<std::string, std::string> modulePathMap;
    modulePathMap[path] = path;
    modulePathMap[path2] = path2;
    EXPECT_EQ(ERR_OK, g_installSessionManager->FinishInstall(sessionId, true, modulePathMap));

    std::vector<TrustedBundleInfo> bundleInfo2;
    EXPECT_EQ(ERR_OK, BundleInfoManager::GetInstance().GetHapSignInfo(
        "GetInfoByBundleNameTest001", bundleInfo2, QUERY_ALL_SIGN_INFO));

    EXPECT_EQ(bundleInfo.size(), hapList.hapPaths.size());
    EXPECT_EQ(bundleInfo.size(), bundleInfo2.size());

    int32_t sceneCode = 0;
    EXPECT_EQ(ERR_OK,
        DeleteIdentityCore(tokenId, "GetInfoByBundleNameTest001", ReservedType::NONE, sceneCode));
}

/**
 * @tc.name: GetInfoByBundleNameTest002
 * @tc.desc: Test GetHapSignInfo, with an explicit main mode query.
 * @tc.type: FUNC
 * @tc.require: Issue
 */
HWTEST_F(BundleInfoManagerTest, GetInfoByBundleNameTest002, TestSize.Level0)
{
    std::string path =
        "/SYSTEM/system_basic/state:[mic,syswin,getwifi]/acl:[getwifi]/Module001/GetInfoByBundleNameTest002";
    std::string path2 =
        "/SYSTEM/system_basic/state:[cam,syswin]/Module002/GetInfoByBundleNameTest002";

    BundleHapList hapList;
    hapList.hapPaths.emplace_back(path);
    hapList.hapPaths.emplace_back(path2);
    hapList.isPreInstalled = false;
    hapList.userId = 100;

    int32_t sessionId = 0;
    std::vector<TrustedBundleInfo> bundleInfo;
    HapVerifyResultInfo resultInfo;
    EXPECT_EQ(ERR_OK, g_installSessionManager->CheckHapSignInfo(
        hapList, nullptr, sessionId, bundleInfo, resultInfo, QUERY_ALL_SIGN_INFO));

    HapInfoCheckResult result;
    EXPECT_EQ(ERR_OK, g_installSessionManager->CheckHapPermissionInfo(sessionId, TYPE_INSTALL, result));

    HapBaseInfo baseInfo;
    baseInfo.userID = 100;
    baseInfo.bundleName = "GetInfoByBundleNameTest002";
    baseInfo.instIndex = 0;

    BundlePolicy bundlePolicy;
    bundlePolicy.dlpType = DLP_COMMON;
    bundlePolicy.isDebugGrant = false;

    Identity identity = {0, -1};
    int32_t ret = g_installSessionManager->PrepareHapIdentity(sessionId, baseInfo, bundlePolicy, nullptr, identity);
    EXPECT_EQ(ERR_OK, ret);
    AccessTokenID tokenId = static_cast<AccessTokenID>(identity.tokenId);

    std::map<std::string, std::string> modulePathMap;
    modulePathMap[path] = path;
    modulePathMap[path2] = path2;
    EXPECT_EQ(ERR_OK, g_installSessionManager->FinishInstall(sessionId, true, modulePathMap));

    // explicit main mode: the strict query returns the installed modules
    std::vector<TrustedBundleInfo> bundleInfo2;
    EXPECT_EQ(ERR_OK, BundleInfoManager::GetInstance().GetHapSignInfo(
        "GetInfoByBundleNameTest002", bundleInfo2, QUERY_ALL_SIGN_INFO,
        MultipleMode::DEFAULT_OR_MAIN_MODE));
    EXPECT_EQ(hapList.hapPaths.size(), bundleInfo2.size());

    int32_t sceneCode = 0;
    EXPECT_EQ(ERR_OK,
        DeleteIdentityCore(tokenId, "GetInfoByBundleNameTest002", ReservedType::NONE, sceneCode));
}

/**
 * @tc.name: GetInfoByBundleNameFailTest001
 * @tc.desc: Test GetHapSignInfo, with not exist bundle, with check failed.
 * @tc.type: FUNC
 * @tc.require: Issue
 */
HWTEST_F(BundleInfoManagerTest, GetInfoByBundleNameFailTest001, TestSize.Level0)
{
    std::vector<TrustedBundleInfo> bundleInfo;
    EXPECT_NE(ERR_OK, BundleInfoManager::GetInstance().GetHapSignInfo(
        "", bundleInfo, QUERY_ALL_SIGN_INFO));
    EXPECT_NE(ERR_OK, BundleInfoManager::GetInstance().GetHapSignInfo(
        "GetInfoByBundleNameFailTest001", bundleInfo, QUERY_ALL_SIGN_INFO));
    EXPECT_TRUE(bundleInfo.empty());

    GenericValues addValue;
    addValue.Put(TokenFiledConst::FIELD_BUNDLE_NAME, "GetInfoByBundleNameFailTest001");
    addValue.Put(TokenFiledConst::FIELD_MODULE_NAME, "CheckFailedModule");
    addValue.Put(TokenFiledConst::FIELD_PATH,
        "/SYSTEM/system_basic/state:[cam,mic,syswin,getwifi]/acl:[getwifi]/"
        "CheckFailedModule/GetInfoByBundleNameFailTest001");
    addValue.Put(TokenFiledConst::FIELD_BUNDLE_TYPE, static_cast<int32_t>(AppExecFwk::Spm::BundleType::APP));
    addValue.Put(TokenFiledConst::FIELD_IS_PREINSTALLED, 0);
    std::vector<uint8_t> blobData = {0x01, 0x02, 0x03};
    addValue.PutBlob(TokenFiledConst::FIELD_PERSIST_DATA, blobData);

    std::vector<GenericValues> signValues{addValue};
    GenericValues delCondition;
    std::vector<AddInfo> addInfoVec;
    std::vector<DelInfo> delInfoVec;
    AccessTokenInfoUtils::GenerateAddInfoToVec(AtmDataType::ACCESSTOKEN_HAP_PACKAGE_INFO, signValues, addInfoVec);
    int32_t ret = AccessTokenDbOperator::DeleteAndInsertValues(delInfoVec, addInfoVec);
    EXPECT_EQ(ERR_OK, ret);

    std::vector<TrustedBundleInfo> bundleInfo2;
    EXPECT_NE(ERR_OK, BundleInfoManager::GetInstance().GetHapSignInfo(
        "GetInfoByBundleNameFailTest001", bundleInfo2, QUERY_ALL_SIGN_INFO));
    EXPECT_TRUE(bundleInfo2.empty());

    GenericValues delCondition2;
    delCondition2.Put(TokenFiledConst::FIELD_BUNDLE_NAME, "GetInfoByBundleNameFailTest001");
    std::vector<AddInfo> addInfoVec2;
    std::vector<DelInfo> delInfoVec2;
    AccessTokenInfoUtils::GenerateDelInfoToVec(AtmDataType::ACCESSTOKEN_HAP_PACKAGE_INFO, delCondition2, delInfoVec2);
    ret = AccessTokenDbOperator::DeleteAndInsertValues(delInfoVec2, addInfoVec2);
    EXPECT_EQ(ERR_OK, ret);
}

/**
 * @tc.name: GetInfoByBundleNameFailTest002
 * @tc.desc: Test GetHapSignInfo, with invalid flag, with check failed.
 * @tc.type: FUNC
 * @tc.require: Issue
 */
HWTEST_F(BundleInfoManagerTest, GetInfoByBundleNameFailTest002, TestSize.Level0)
{
    std::vector<TrustedBundleInfo> bundleInfo;
    // flag 0 is rejected
    EXPECT_EQ(AccessTokenError::ERR_PARAM_INVALID,
        BundleInfoManager::GetInstance().GetHapSignInfo(
            "GetInfoByBundleNameFailTest002", bundleInfo, 0));
    // flag bits outside the valid mask are rejected
    EXPECT_EQ(AccessTokenError::ERR_PARAM_INVALID,
        BundleInfoManager::GetInstance().GetHapSignInfo(
            "GetInfoByBundleNameFailTest002", bundleInfo, QUERY_ALL_SIGN_INFO | (1 << 3)));
    EXPECT_TRUE(bundleInfo.empty());
}

/**
 * @tc.name: GetHapAppIdByTokenIdTest001
 * @tc.desc: Test GetHapAppIdByTokenId, with not exist token.
 * @tc.type: FUNC
 * @tc.require: Issue
 */
HWTEST_F(BundleInfoManagerTest, GetHapAppIdByTokenIdTest001, TestSize.Level0)
{
    std::string appId;
    EXPECT_EQ(AccessTokenError::ERR_TOKENID_NOT_EXIST,
        BundleInfoManager::GetInstance().GetHapAppIdByTokenId(0, appId));
    EXPECT_EQ(AccessTokenError::ERR_TOKENID_NOT_EXIST,
        BundleInfoManager::GetInstance().GetHapAppIdByTokenId(0xFFFFFFFF, appId));
    EXPECT_TRUE(appId.empty());
}

/**
 * @tc.name: GetHapAppIdByTokenIdTest002
 * @tc.desc: Test GetHapAppIdByTokenId, with an installed token, via the sign-info channel.
 * @tc.type: FUNC
 * @tc.require: Issue
 */
HWTEST_F(BundleInfoManagerTest, GetHapAppIdByTokenIdTest002, TestSize.Level0)
{
    std::string bundleName = "GetHapAppIdByTokenIdTest002";
    std::string path =
        "/SYSTEM/system_basic/state:[mic,syswin,getwifi]/acl:[getwifi]/Module001/GetHapAppIdByTokenIdTest002";

    BundleHapList hapList;
    hapList.hapPaths.emplace_back(path);
    hapList.isPreInstalled = false;
    hapList.userId = 100;

    int32_t sessionId = 0;
    std::vector<TrustedBundleInfo> bundleInfo;
    HapVerifyResultInfo resultInfo;
    EXPECT_EQ(ERR_OK, g_installSessionManager->CheckHapSignInfo(
        hapList, nullptr, sessionId, bundleInfo, resultInfo, QUERY_ALL_SIGN_INFO));

    HapInfoCheckResult result;
    EXPECT_EQ(ERR_OK, g_installSessionManager->CheckHapPermissionInfo(sessionId, TYPE_INSTALL, result));

    HapBaseInfo baseInfo;
    baseInfo.userID = 100;
    baseInfo.bundleName = bundleName;
    baseInfo.instIndex = 0;

    BundlePolicy bundlePolicy;
    bundlePolicy.dlpType = DLP_COMMON;
    bundlePolicy.isDebugGrant = false;

    Identity identity = {0, -1};
    EXPECT_EQ(ERR_OK,
        g_installSessionManager->PrepareHapIdentity(sessionId, baseInfo, bundlePolicy, nullptr, identity));
    AccessTokenID tokenId = static_cast<AccessTokenID>(identity.tokenId);

    std::map<std::string, std::string> modulePathMap;
    modulePathMap[path] = path;
    EXPECT_EQ(ERR_OK, g_installSessionManager->FinishInstall(sessionId, true, modulePathMap));

    // sign-info channel: the verifier reports the bundle name as the profile appId
    std::string appId;
    EXPECT_EQ(ERR_OK, BundleInfoManager::GetInstance().GetHapAppIdByTokenId(tokenId, appId));
    EXPECT_EQ(bundleName, appId);

    int32_t sceneCode = 0;
    EXPECT_EQ(ERR_OK, DeleteIdentityCore(tokenId, bundleName, ReservedType::NONE, sceneCode));
}

/**
 * @tc.name: GetHapAppIdByTokenIdTest003
 * @tc.desc: Test GetHapAppIdByTokenId falls back to the hap_token_info table row
 *           for a token without package-info rows (spm not enforcing, the
 *           enforcing param comes from the in-process test mock).
 * @tc.type: FUNC
 * @tc.require: Issue
 */
HWTEST_F(BundleInfoManagerTest, GetHapAppIdByTokenIdTest003, TestSize.Level0)
{
    // CreateHapTokenInfo only writes the hap_token_info row: the sign-info
    // channel finds no package-info row and the query falls back to the table
    HapInfoParams info = {
        .userID = USER_ID,
        .bundleName = "get_appid_fallback_test",
        .instIndex = INST_INDEX,
        .appIDDesc = "get_appid_fallback_appid"
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
    ASSERT_EQ(RET_SUCCESS, BundleInfoManager::GetInstance().GetHapAppIdByTokenId(
        tokenIdEx.tokenIdExStruct.tokenID, appId));
    ASSERT_EQ(appId, "get_appid_fallback_appid");
    ASSERT_EQ(RET_SUCCESS, AccessTokenInfoManager::GetInstance().RemoveHapTokenInfo(
        tokenIdEx.tokenIdExStruct.tokenID));
}
} // namespace AccessToken
} // namespace Security
} // namespace OHOS
#endif // SPM_DATA_ENABLE
