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

#include <cerrno>
#include <gtest/gtest.h>

#define private public
#include "accesstoken_id_manager.h"
#include "accesstoken_info_manager.h"
#include "accesstoken_info_utils.h"
#include "accesstoken_manager_service.h"
#include "install_db_repository.h"
#include "install_identity_manager.h"
#include "install_session_manager.h"
#undef private
#include "access_token.h"
#include "access_token_error.h"
#include "fake_token_setproc.h"
#include "generic_values.h"
#include "hap_data_structure.h"
#include "hap_token_info.h"
#include "permission_kernel_utils.h"
#include "token_field_const.h"

using namespace testing::ext;

namespace OHOS {
namespace Security {
namespace AccessToken {
namespace {
constexpr uint32_t MAX_UID_RANGE = 200000;
constexpr int32_t TEST_APP_UID_BASE = 20100000;
static InstallSessionManager* g_installSessionManager = nullptr;
static std::map<std::string, std::string> g_modulePathMap;

HapTokenInfo BuildHapInfo(AccessTokenID tokenId, const std::string& bundleName)
{
    HapTokenInfo hapInfo = {};
    hapInfo.ver = 1;
    hapInfo.userID = 100;
    hapInfo.bundleName = bundleName;
    hapInfo.apiVersion = 12;
    hapInfo.instIndex = 0;
    hapInfo.dlpType = DLP_COMMON;
    hapInfo.tokenID = tokenId;
    hapInfo.tokenAttr = 0;
    hapInfo.uid = TEST_APP_UID_BASE + (tokenId % MAX_UID_RANGE);
    return hapInfo;
}

InstallHapInfo BuildInstallHapInfo(AccessTokenID tokenId, const std::string& bundleName)
{
    InstallHapInfo installInfo;
    installInfo.baseInfo = BuildHapInfo(tokenId, bundleName);
    return installInfo;
}

BundleNoCachedInfo BuildNoCached()
{
    BundleNoCachedInfo info;
    info.apl = APL_NORMAL;
    info.distributionType = static_cast<int32_t>(Security::Verify::AppDistType::NONE_TYPE);
    info.idType = 2;
    info.ownerid = 1;
    return info;
}

std::vector<BriefPermData> BuildBriefList(uint16_t permCode)
{
    BriefPermData data = {0};
    data.permCode = permCode;
    data.status = PERMISSION_GRANTED;
    data.flag = PERMISSION_SYSTEM_FIXED;
    return {data};
}

InstallCache BuildTestCache(AccessTokenID newTokenId = 0)
{
    InstallCache cache;
    cache.baseInfo.userID = 100;
    cache.baseInfo.bundleName = "test.bundle";
    cache.baseInfo.instIndex = 0;
    cache.bundleParam.bundleName = "test.bundle";
    cache.bundleParam.appId = "test.bundle@123";
    cache.bundleParam.isSystem = false;
    cache.bundleParam.isAtomicService = false;
    cache.bundleParam.isDebug = false;
    cache.policy.apl = APL_NORMAL;

    if (newTokenId != 0) {
        cache.identity.tokenId = newTokenId;
        cache.identity.appUid = TEST_APP_UID_BASE + (newTokenId % MAX_UID_RANGE);
    }

    return cache;
}

FinishContext BuildFinishContext()
{
    FinishContext context;
    context.noCachedInfo = BuildNoCached();
    return context;
}
} // namespace

class InstallSessionSpmTaskTest : public testing::Test {
public:
    void SetUp() override
    {
        ResetFakeSpmKernelState();
        g_installSessionManager = &InstallSessionManager::GetInstance();

        uint32_t nativeSize = 0;
        uint32_t pefDefSize = 0;
        uint32_t dlpSize = 0;
        AccessTokenInfoManager::GetInstance().Init(nativeSize, pefDefSize, dlpSize);

        g_installSessionManager->SetMigrationDone();
        AccessTokenIDManager::GetInstance().SetMigrationDone();
    }

    void TearDown() override
    {
        ResetFakeSpmKernelState();

        std::vector<int32_t> sessionList;
        for (auto it : g_installSessionManager->sessionToInstallCache) {
            sessionList.emplace_back(it.first);
        }
        for (auto session : sessionList) {
            g_installSessionManager->FinishInstall(session, false, g_modulePathMap);
        }
    }
};

/**
 * @tc.name: BuildSpmKernelParams001
 * @tc.desc: Test BuildSpmKernelParams with ACTIVE tokenID, should add to updateParams
 * @tc.type: FUNC
 * @tc.require: Issue
 */
HWTEST_F(InstallSessionSpmTaskTest, BuildSpmKernelParams001, TestSize.Level0)
{
    // Create a tokenID and set it to ACTIVE status
    // TokenID format: version=1 (bits 29-31), type=0 (bits 27-28), type_ext=0 (bit 23)
    AccessTokenID tokenId1 = 0x20000001;
    int32_t ret = AccessTokenIDManager::GetInstance().RegisterTokenId(tokenId1, TOKEN_HAP);
    ASSERT_EQ(ERR_OK, ret);

    // Build test data
    InstallCache cache = BuildTestCache();
    FinishContext context = BuildFinishContext();

    context.hapInfos.emplace_back(BuildInstallHapInfo(tokenId1, "test.bundle"));
    context.permBriefDataLists.emplace_back(BuildBriefList(1));
    context.extendPermLists.emplace_back();
    context.oldPermList.emplace_back(std::make_shared<std::vector<BriefPermData>>());

    std::vector<SpmDataParam> addParams;
    std::vector<SpmDataParam> updateParams;
    g_installSessionManager->BuildSpmKernelParams(cache, context, addParams, updateParams);

    // Verify: ACTIVE tokenID should be added to updateParams, not addParams
    EXPECT_EQ(0, addParams.size());
    EXPECT_EQ(1, updateParams.size());

    AccessTokenIDManager::GetInstance().ReleaseTokenId(tokenId1);
}

/**
 * @tc.name: BuildSpmKernelParams002
 * @tc.desc: Test BuildSpmKernelParams with new installation (cache.identity.tokenId != 0)
 * @tc.type: FUNC
 * @tc.require: Issue
 */
HWTEST_F(InstallSessionSpmTaskTest, BuildSpmKernelParams002, TestSize.Level0)
{
    // Simulate new installation with a new tokenID
    AccessTokenID newTokenId = 0x20000007;
    int32_t ret = AccessTokenIDManager::GetInstance().RegisterTokenId(newTokenId, TOKEN_HAP);
    ASSERT_EQ(ERR_OK, ret);

    // Build test data for new installation
    InstallCache cache = BuildTestCache(newTokenId);
    FinishContext context = BuildFinishContext();

    // Add new tokenID to context (simulating new installation)
    context.hapInfos.emplace_back(BuildInstallHapInfo(newTokenId, "test.bundle"));
    context.permBriefDataLists.emplace_back(BuildBriefList(7));
    context.extendPermLists.emplace_back();
    context.oldPermList.emplace_back(std::make_shared<std::vector<BriefPermData>>());

    // Add an existing ACTIVE tokenID for update
    AccessTokenID existingTokenId = 0x20000008;
    ret = AccessTokenIDManager::GetInstance().RegisterTokenId(existingTokenId, TOKEN_HAP);
    ASSERT_EQ(ERR_OK, ret);

    context.hapInfos.emplace_back(BuildInstallHapInfo(existingTokenId, "test.bundle"));
    context.permBriefDataLists.emplace_back(BuildBriefList(8));
    context.extendPermLists.emplace_back();
    context.oldPermList.emplace_back(std::make_shared<std::vector<BriefPermData>>());

    std::vector<SpmDataParam> addParams;
    std::vector<SpmDataParam> updateParams;
    g_installSessionManager->BuildSpmKernelParams(cache, context, addParams, updateParams);

    // Verify: newTokenId goes to addParams (first element)
    //         existingTokenId goes to updateParams (ACTIVE)
    EXPECT_EQ(1, addParams.size());
    EXPECT_EQ(1, updateParams.size());
    EXPECT_EQ(newTokenId, addParams[0].hapInfo.get().tokenID);
    EXPECT_EQ(existingTokenId, updateParams[0].hapInfo.get().tokenID);

    AccessTokenIDManager::GetInstance().ReleaseTokenId(newTokenId);
    AccessTokenIDManager::GetInstance().ReleaseTokenId(existingTokenId);
}

/**
 * @tc.name: BuildSpmKernelParams003
 * @tc.desc: Test BuildSpmKernelParams with oldPermList boundary condition
 * @tc.type: FUNC
 * @tc.require: Issue
 */
HWTEST_F(InstallSessionSpmTaskTest, BuildSpmKernelParams003, TestSize.Level0)
{
    // Explicitly reset fake kernel state to ensure clean state
    ResetFakeSpmKernelState();

    // Create ACTIVE tokenID
    AccessTokenID tokenId1 = 0x2000000C;
    int32_t ret = AccessTokenIDManager::GetInstance().RegisterTokenId(tokenId1, TOKEN_HAP);
    ASSERT_EQ(ERR_OK, ret);

    // Build test data with oldPermList containing valid data
    InstallCache cache = BuildTestCache();
    FinishContext context = BuildFinishContext();

    context.hapInfos.emplace_back(BuildInstallHapInfo(tokenId1, "test.bundle"));
    context.permBriefDataLists.emplace_back(BuildBriefList(12));
    context.extendPermLists.emplace_back();
    // Use valid oldPermData instead of nullptr
    std::vector<BriefPermData> oldPermData = BuildBriefList(12);
    context.oldPermList.emplace_back(std::make_shared<std::vector<BriefPermData>>(oldPermData));

    std::vector<SpmDataParam> addParams;
    std::vector<SpmDataParam> updateParams;
    g_installSessionManager->BuildSpmKernelParams(cache, context, addParams, updateParams);

    // Verify: Should handle boundary condition gracefully
    EXPECT_EQ(0, addParams.size());
    EXPECT_EQ(1, updateParams.size());
    EXPECT_NE(nullptr, updateParams[0].oldPermBriefDataList);

    AccessTokenIDManager::GetInstance().ReleaseTokenId(tokenId1);
}
/**
 * @tc.name: StageSpmKernelTasks_Fail001
 * @tc.desc: Kernel add failure fails the staging (task self-rolled-back); after the
 *           fault is cleared the same context succeeds again (reinstall-recovery semantics).
 * @tc.type: FUNC
 * @tc.require: Issue
 */
HWTEST_F(InstallSessionSpmTaskTest, StageSpmKernelTasks_Fail001, TestSize.Level0)
{
    AccessTokenID newTokenId = 0x2000000D;
    int32_t ret = AccessTokenIDManager::GetInstance().RegisterTokenId(newTokenId, TOKEN_HAP);
    ASSERT_EQ(ERR_OK, ret);

    InstallCache cache = BuildTestCache(newTokenId);
    FinishContext context = BuildFinishContext();
    context.hapInfos.emplace_back(BuildInstallHapInfo(newTokenId, "test.bundle"));
    context.permBriefDataLists.emplace_back(BuildBriefList(13));
    context.extendPermLists.emplace_back();
    context.oldPermList.emplace_back(std::make_shared<std::vector<BriefPermData>>());

    GetFakeSpmKernelState().addRet = -1; // kernel add fails
    {
        KernelAndDBWriteTransaction txn;
        ret = g_installSessionManager->StageSpmKernelTasks(cache, context, txn);
        EXPECT_EQ(ERR_KERNEL_OPERATION_FAILED, ret);
    }

    // retry after the fault is cleared: same context succeeds (reinstall recovery)
    ResetFakeSpmKernelState();
    {
        KernelAndDBWriteTransaction txn;
        ret = g_installSessionManager->StageSpmKernelTasks(cache, context, txn);
        EXPECT_EQ(RET_SUCCESS, ret);
        txn.Commit();
    }
    std::vector<SpmDataParam> addParams;
    std::vector<SpmDataParam> updateParams;
    g_installSessionManager->BuildSpmKernelParams(cache, context, addParams, updateParams);
    EXPECT_EQ(1, addParams.size());

    AccessTokenIDManager::GetInstance().ReleaseTokenId(newTokenId);
}

/**
 * @tc.name: StageSpmKernelTasks_Fail002
 * @tc.desc: Kernel update failure leaves the executed add compensated by the
 *           transaction destructor (no partial state left); retry after reset succeeds.
 * @tc.type: FUNC
 * @tc.require: Issue
 */
HWTEST_F(InstallSessionSpmTaskTest, StageSpmKernelTasks_Fail002, TestSize.Level0)
{
    AccessTokenID newTokenId = 0x2000000E;
    int32_t ret = AccessTokenIDManager::GetInstance().RegisterTokenId(newTokenId, TOKEN_HAP);
    ASSERT_EQ(ERR_OK, ret);
    AccessTokenID existingTokenId = 0x2000000F;
    ret = AccessTokenIDManager::GetInstance().RegisterTokenId(existingTokenId, TOKEN_HAP);
    ASSERT_EQ(ERR_OK, ret);

    InstallCache cache = BuildTestCache(newTokenId);
    FinishContext context = BuildFinishContext();
    context.hapInfos.emplace_back(BuildInstallHapInfo(newTokenId, "test.bundle"));
    context.permBriefDataLists.emplace_back(BuildBriefList(14));
    context.extendPermLists.emplace_back();
    context.oldPermList.emplace_back(std::make_shared<std::vector<BriefPermData>>());
    context.hapInfos.emplace_back(BuildInstallHapInfo(existingTokenId, "test.bundle"));
    context.permBriefDataLists.emplace_back(BuildBriefList(15));
    context.extendPermLists.emplace_back();
    context.oldPermList.emplace_back(std::make_shared<std::vector<BriefPermData>>());

    GetFakeSpmKernelState().setRet = -1; // kernel update fails, add already executed
    {
        KernelAndDBWriteTransaction txn;
        ret = g_installSessionManager->StageSpmKernelTasks(cache, context, txn);
        EXPECT_EQ(ERR_KERNEL_OPERATION_FAILED, ret);
        // while the transaction is alive the executed add is not yet compensated
        EXPECT_TRUE(GetFakeSpmKernelState().removedTokenIds.empty());
    }
    // scope exit: the transaction destructor compensates the executed add
    EXPECT_FALSE(GetFakeSpmKernelState().removedTokenIds.empty());

    ResetFakeSpmKernelState();
    {
        KernelAndDBWriteTransaction txn;
        ret = g_installSessionManager->StageSpmKernelTasks(cache, context, txn);
        EXPECT_EQ(RET_SUCCESS, ret);
        txn.Commit();
    }

    AccessTokenIDManager::GetInstance().ReleaseTokenId(newTokenId);
    AccessTokenIDManager::GetInstance().ReleaseTokenId(existingTokenId);
}

/**
 * @tc.name: GetTokenIdAndUidFromCallerTest001
 * @tc.desc: GetTokenIdAndUid adopts the caller input uid (fake kernel refcnt free)
 *           and marks isAppUidFromCaller; no desired uid keeps isAppUidFromCaller false.
 * @tc.type: FUNC
 * @tc.require: Issue
 */
HWTEST_F(InstallSessionSpmTaskTest, GetTokenIdAndUidFromCallerTest001, TestSize.Level0)
{
    constexpr int32_t CALLER_UID = 20033333; // userId 100, bundleId 33333 (free in fake kernel)
    BundlePolicy bundlePolicy{std::vector<PreAuthorizationInfo>(), DLP_COMMON, false};

    // caller designates the appUid via PrepareHapIdentity identity input
    InstallCache cache;
    cache.baseInfo = HapBaseInfo{100, "FromCallerUidTest001", 0};
    cache.repairedIdentity.appUid = CALLER_UID;
    int32_t ret = InstallIdentityManager::GetTokenIdAndUid(cache, bundlePolicy);
    EXPECT_EQ(RET_SUCCESS, ret);
    EXPECT_EQ(CALLER_UID, cache.identity.uid);
    EXPECT_TRUE(cache.isAppUidFromCaller);
    AccessTokenIDManager::GetInstance().ReleaseTokenId(static_cast<AccessTokenID>(cache.identity.tokenId));
    AccessTokenIDManager::GetInstance().RemoveBundleId(CALLER_UID);

    // no desired uid: fresh allocation via fake kernel, isAppUidFromCaller stays false
    InstallCache cache2;
    cache2.baseInfo = HapBaseInfo{100, "FromCallerUidTest001", 0};
    cache2.repairedIdentity.uid = -1;
    cache2.repairedIdentity.appUid = -1;
    ret = InstallIdentityManager::GetTokenIdAndUid(cache2, bundlePolicy);
    EXPECT_EQ(RET_SUCCESS, ret);
    EXPECT_NE(-1, cache2.identity.uid);
    EXPECT_FALSE(cache2.isAppUidFromCaller);
    AccessTokenIDManager::GetInstance().ReleaseTokenId(static_cast<AccessTokenID>(cache2.identity.tokenId));
    AccessTokenIDManager::GetInstance().RemoveBundleId(cache2.identity.uid);
}

/**
 * @tc.name: GetTokenIdAndUidFlagMismatchTest001
 * @tc.desc: A desired token id with mismatched dlp/clone flag must be rejected
 *           before registration (no tokenIdSet_ leak); a flag-matching id is adopted.
 * @tc.type: FUNC
 * @tc.require: Issue
 */
HWTEST_F(InstallSessionSpmTaskTest, GetTokenIdAndUidFlagMismatchTest001, TestSize.Level0)
{
    BundlePolicy bundlePolicy{std::vector<PreAuthorizationInfo>(), DLP_COMMON, false}; // plain hap install

    // desired carries the dlp flag while the session is not a dlp app:
    // adoption must be rejected before RegisterTokenId, otherwise the
    // registered-then-rejected id leaks in tokenIdSet_ with no release path
    AccessTokenID desiredDlp = AccessTokenIDManager::GetInstance().CreateAndRegisterTokenId(
        TOKEN_HAP, 1, 0, 0);
    ASSERT_NE(static_cast<AccessTokenID>(0), desiredDlp);
    AccessTokenIDManager::GetInstance().ReleaseTokenId(desiredDlp); // unregistered, flag-carrying

    InstallCache cache;
    cache.baseInfo = HapBaseInfo{100, "FlagMismatchTest001", 0};
    cache.repairedIdentity.tokenId = desiredDlp;
    int32_t ret = InstallIdentityManager::GetTokenIdAndUid(cache, bundlePolicy);
    EXPECT_EQ(RET_SUCCESS, ret);
    // fresh allocation instead of the mismatched desired id
    EXPECT_NE(desiredDlp, AccessTokenIDManager::ExtractTokenIdFromFull(cache.identity.tokenId));
    // the rejected desired id must not linger in any id set
    TokenIdStatus status;
    EXPECT_NE(RET_SUCCESS, AccessTokenIDManager::GetInstance().GetTokenIdStatus(desiredDlp, status));
    AccessTokenIDManager::GetInstance().ReleaseTokenId(static_cast<AccessTokenID>(cache.identity.tokenId));
    AccessTokenIDManager::GetInstance().RemoveBundleId(cache.identity.uid);

    // positive control: flags match, the desired id is adopted
    AccessTokenID desiredPlain = AccessTokenIDManager::GetInstance().CreateAndRegisterTokenId(
        TOKEN_HAP, 0, 0, 0);
    ASSERT_NE(static_cast<AccessTokenID>(0), desiredPlain);
    AccessTokenIDManager::GetInstance().ReleaseTokenId(desiredPlain);

    InstallCache cache2;
    cache2.baseInfo = HapBaseInfo{100, "FlagMismatchTest001", 0};
    cache2.repairedIdentity.tokenId = desiredPlain;
    ret = InstallIdentityManager::GetTokenIdAndUid(cache2, bundlePolicy);
    EXPECT_EQ(RET_SUCCESS, ret);
    EXPECT_EQ(desiredPlain, AccessTokenIDManager::ExtractTokenIdFromFull(cache2.identity.tokenId));
    AccessTokenIDManager::GetInstance().ReleaseTokenId(desiredPlain);
    AccessTokenIDManager::GetInstance().RemoveBundleId(cache2.identity.uid);
}

/**
 * @tc.name: GenerateTokenDbOpsVec001
 * @tc.desc: Verify GenerateTokenDbOpsVec writes ACCESSTOKEN_PERMISSION_EXTEND_VALUE and
 *           ACCESSTOKEN_HAP_UNDEFINE_INFO add/del entries (same tables as master).
 * @tc.type: FUNC
 * @tc.require: Issue
 */
HWTEST_F(InstallSessionSpmTaskTest, GenerateTokenDbOpsVec001, TestSize.Level0)
{
    constexpr AccessTokenID DBOPS_TOKEN_ID = 0x20260501;
    InstallCache cache = BuildTestCache(DBOPS_TOKEN_ID);
    cache.bundleParam.bundleName = "com.example.dbops";

    FinishContext context = BuildFinishContext();
    context.hapInfos.emplace_back(BuildInstallHapInfo(DBOPS_TOKEN_ID, "com.example.dbops"));
    context.permBriefDataLists.emplace_back(BuildBriefList(1));
    context.extendPermLists.emplace_back();
    context.oldPermList.emplace_back(std::make_shared<std::vector<BriefPermData>>());

    // Add an extended permission (ACL value) and an undefined permission
    PermissionWithValue extPerm;
    extPerm.permissionName = "ohos.permission.kernel.SUPPORT_PLUGIN";
    extPerm.value = "allowed";
    context.extendPermLists[0].emplace_back(extPerm);

    GenericValues undefValue;
    undefValue.Put(TokenFiledConst::FIELD_PERMISSION_NAME, "ohos.permission.test.UNDEFINED");
    undefValue.Put(TokenFiledConst::FIELD_AVAILABLE_TYPE, 0);
    context.undefValues.emplace_back(undefValue);

    std::vector<AddInfo> addInfoVec;
    std::vector<DelInfo> delInfoVec;
    InstallDbRepository::GenerateTokenDbOpsVec(cache, context, 0, addInfoVec, delInfoVec);

    // Verify add entries cover all 5 tables (token_info, perm_state, extend_value, undefine_info)
    bool hasTokenInfo = false;
    bool hasPermState = false;
    bool hasExtendValue = false;
    bool hasUndefineInfo = false;
    for (const auto& addInfo : addInfoVec) {
        switch (addInfo.addType) {
            case AtmDataType::ACCESSTOKEN_HAP_TOKEN_INFO:
                hasTokenInfo = true;
                break;
            case AtmDataType::ACCESSTOKEN_PERMISSION_STATE:
                hasPermState = true;
                break;
            case AtmDataType::ACCESSTOKEN_PERMISSION_EXTEND_VALUE:
                hasExtendValue = true;
                break;
            case AtmDataType::ACCESSTOKEN_HAP_UNDEFINE_INFO:
                hasUndefineInfo = true;
                break;
            default:
                break;
        }
    }
    EXPECT_TRUE(hasTokenInfo);
    EXPECT_TRUE(hasPermState);
    EXPECT_TRUE(hasExtendValue);
    EXPECT_TRUE(hasUndefineInfo);

    // Verify del entries cover the new tables (extend_value + undefine_info)
    bool hasExtendDel = false;
    bool hasUndefineDel = false;
    for (const auto& delInfo : delInfoVec) {
        if (delInfo.delType == AtmDataType::ACCESSTOKEN_PERMISSION_EXTEND_VALUE) {
            hasExtendDel = true;
        }
        if (delInfo.delType == AtmDataType::ACCESSTOKEN_HAP_UNDEFINE_INFO) {
            hasUndefineDel = true;
        }
    }
    EXPECT_TRUE(hasExtendDel);
    EXPECT_TRUE(hasUndefineDel);

    // Verify the extend value entry contains the correct permission name and value
    for (const auto& addInfo : addInfoVec) {
        if (addInfo.addType != AtmDataType::ACCESSTOKEN_PERMISSION_EXTEND_VALUE) {
            continue;
        }
        ASSERT_EQ(1u, addInfo.addValues.size());
        EXPECT_EQ("ohos.permission.kernel.SUPPORT_PLUGIN",
            addInfo.addValues[0].GetString(TokenFiledConst::FIELD_PERMISSION_NAME));
        EXPECT_EQ("allowed", addInfo.addValues[0].GetString(TokenFiledConst::FIELD_VALUE));
        EXPECT_EQ(DBOPS_TOKEN_ID,
            static_cast<AccessTokenID>(addInfo.addValues[0].GetInt(TokenFiledConst::FIELD_TOKEN_ID)));
    }

    // Verify the undefine info entry contains the correct permission name and token ID
    for (const auto& addInfo : addInfoVec) {
        if (addInfo.addType != AtmDataType::ACCESSTOKEN_HAP_UNDEFINE_INFO) {
            continue;
        }
        ASSERT_EQ(1u, addInfo.addValues.size());
        EXPECT_EQ("ohos.permission.test.UNDEFINED",
            addInfo.addValues[0].GetString(TokenFiledConst::FIELD_PERMISSION_NAME));
        EXPECT_EQ(DBOPS_TOKEN_ID,
            static_cast<AccessTokenID>(addInfo.addValues[0].GetInt(TokenFiledConst::FIELD_TOKEN_ID)));
    }
}

/**
 * @tc.name: GenerateTokenDbOpsVec002
 * @tc.desc: Verify GenerateTokenDbOpsVec with empty extendPermList and undefValues produces
 *           no add entries for those tables but still has the del entries.
 * @tc.type: FUNC
 * @tc.require: Issue
 */
HWTEST_F(InstallSessionSpmTaskTest, GenerateTokenDbOpsVec002, TestSize.Level0)
{
    constexpr AccessTokenID DBOPS_EMPTY_TOKEN_ID = 0x20260502;
    InstallCache cache = BuildTestCache(DBOPS_EMPTY_TOKEN_ID);
    cache.bundleParam.bundleName = "com.example.dbops.empty";

    FinishContext context = BuildFinishContext();
    context.hapInfos.emplace_back(BuildInstallHapInfo(DBOPS_EMPTY_TOKEN_ID, "com.example.dbops.empty"));
    context.permBriefDataLists.emplace_back(BuildBriefList(1));
    context.extendPermLists.emplace_back();
    context.oldPermList.emplace_back(std::make_shared<std::vector<BriefPermData>>());
    // undefValues is empty

    std::vector<AddInfo> addInfoVec;
    std::vector<DelInfo> delInfoVec;
    InstallDbRepository::GenerateTokenDbOpsVec(cache, context, 0, addInfoVec, delInfoVec);

    // No add entries for the optional tables when lists are empty
    for (const auto& addInfo : addInfoVec) {
        EXPECT_NE(AtmDataType::ACCESSTOKEN_PERMISSION_EXTEND_VALUE, addInfo.addType);
        EXPECT_NE(AtmDataType::ACCESSTOKEN_HAP_UNDEFINE_INFO, addInfo.addType);
    }

    // But del entries still exist (clean up any residual rows)
    bool hasExtendDel = false;
    bool hasUndefineDel = false;
    for (const auto& delInfo : delInfoVec) {
        if (delInfo.delType == AtmDataType::ACCESSTOKEN_PERMISSION_EXTEND_VALUE) {
            hasExtendDel = true;
        }
        if (delInfo.delType == AtmDataType::ACCESSTOKEN_HAP_UNDEFINE_INFO) {
            hasUndefineDel = true;
        }
    }
    EXPECT_TRUE(hasExtendDel);
    EXPECT_TRUE(hasUndefineDel);
}

/**
 * @tc.name: CreateInstallSessionDesiredUidValidation001
 * @tc.desc: A repair identity whose uid mismatches or whose appUid belongs to another user is
 *           downgraded instead of rejected: session creation proceeds and the mismatched appUid
 *           is skipped by adoption, falling back to the standard resolution chain.
 * @tc.type: FUNC
 * @tc.require: Issue
 */
HWTEST_F(InstallSessionSpmTaskTest, CreateInstallSessionDesiredUidValidation001, TestSize.Level0)
{
    BundlePolicy bundlePolicy{std::vector<PreAuthorizationInfo>(), DLP_COMMON, false};
    HapBaseInfo info{100, "DesiredUidValidation001", 0};
    int32_t sessionId = 0;
    // Let the flow end in the installed-bundle query (the bundle has no rows), as in the
    // sibling adoption test, so no session side effect survives either call.
    GetFakeSpmKernelState().getVersionRet = ENOTSUP;

    Identity badUid;
    badUid.tokenId = 0x20000101;
    badUid.uid = 777;
    badUid.appUid = 20010001;
    EXPECT_NE(ERR_PARAM_INVALID,
        g_installSessionManager->CreateInstallSession(info, bundlePolicy, nullptr, sessionId, badUid));

    Identity badAppUid;
    badAppUid.tokenId = 0x20000102;
    badAppUid.uid = 20210001;
    badAppUid.appUid = 20210001;
    EXPECT_NE(ERR_PARAM_INVALID,
        g_installSessionManager->CreateInstallSession(info, bundlePolicy, nullptr, sessionId, badAppUid));
    ResetFakeSpmKernelState();
}

/**
 * @tc.name: CreateInstallSessionDesiredUidAdoption001
 * @tc.desc: Repair identity whose uid equals appUid passes the CreateInstallSession
 *           desired-identity validation and is adopted by PrepareSessionIdentity: the caller
 *           tokenId and appUid are taken over and isAppUidFromCaller is set.
 * @tc.type: FUNC
 * @tc.require: Issue
 */
HWTEST_F(InstallSessionSpmTaskTest, CreateInstallSessionDesiredUidAdoption001, TestSize.Level0)
{
    constexpr AccessTokenID SAME_AS_APPUID_TOKEN = 0x20000103;
    constexpr int32_t REPAIR_APP_UID = 20010001; // userId 100, bundleId 10001 (free in fake kernel)
    constexpr int32_t REPAIR_SESSION_ID = 990001;
    BundlePolicy bundlePolicy{std::vector<PreAuthorizationInfo>(), DLP_COMMON, false};
    HapBaseInfo info{100, "DesiredUidValidation001", 0};
    int32_t sessionId = 0;

    // A positive CreateInstallSession continues into FillInstallPolicy; report the kernel as
    // unsupported so the flow ends in the installed-bundle query (the bundle has no rows).
    GetFakeSpmKernelState().getVersionRet = ENOTSUP;

    Identity sameAsAppUid;
    sameAsAppUid.tokenId = SAME_AS_APPUID_TOKEN;
    sameAsAppUid.uid = REPAIR_APP_UID;
    sameAsAppUid.appUid = REPAIR_APP_UID;
    EXPECT_NE(ERR_PARAM_INVALID,
        g_installSessionManager->CreateInstallSession(info, bundlePolicy, nullptr, sessionId, sameAsAppUid));

    // No session survives CreateInstallSession (no installed rows), so the adoption is asserted
    // through PrepareSessionIdentity on a seeded session carrying the accepted repair identity.
    ResetFakeSpmKernelState();
    auto& sessionCache = g_installSessionManager->sessionToInstallCache;
    InstallCache appUidCache;
    appUidCache.baseInfo = info;
    appUidCache.hasPermChecked = true;
    appUidCache.repairedIdentity = sameAsAppUid;
    sessionCache[REPAIR_SESSION_ID] = appUidCache;
    Identity prepared;
    int32_t ret = g_installSessionManager->PrepareSessionIdentity(
        REPAIR_SESSION_ID, info, bundlePolicy, prepared, false);
    EXPECT_EQ(RET_SUCCESS, ret);
    EXPECT_EQ(REPAIR_APP_UID, prepared.appUid);
    EXPECT_EQ(REPAIR_APP_UID, prepared.uid); // SPM v1 kernel: the runtime uid stays the appUid
    EXPECT_EQ(SAME_AS_APPUID_TOKEN, AccessTokenIDManager::ExtractTokenIdFromFull(prepared.tokenId));
    auto appUidIt = sessionCache.find(REPAIR_SESSION_ID);
    ASSERT_NE(sessionCache.end(), appUidIt);
    EXPECT_TRUE(appUidIt->second.isAppUidFromCaller);
    // erase the seeded session so TearDown does not run FinishInstall on it
    sessionCache.erase(appUidIt);
    AccessTokenIDManager::GetInstance().ReleaseTokenId(static_cast<AccessTokenID>(prepared.tokenId));
    AccessTokenIDManager::GetInstance().RemoveBundleId(REPAIR_APP_UID);
}

/**
 * @tc.name: CreateInstallSessionDesiredUidAdoption002
 * @tc.desc: Repair identity whose uid equals userID passes the CreateInstallSession
 *           desired-identity validation and is adopted by PrepareSessionIdentity together
 *           with the caller tokenId and appUid.
 * @tc.type: FUNC
 * @tc.require: Issue
 */
HWTEST_F(InstallSessionSpmTaskTest, CreateInstallSessionDesiredUidAdoption002, TestSize.Level0)
{
    constexpr AccessTokenID SAME_AS_USER_TOKEN = 0x20000104;
    constexpr int32_t REPAIR_APP_UID = 20010001; // userId 100, bundleId 10001 (free in fake kernel)
    constexpr int32_t REPAIR_SESSION_ID = 990001;
    BundlePolicy bundlePolicy{std::vector<PreAuthorizationInfo>(), DLP_COMMON, false};
    HapBaseInfo info{100, "DesiredUidValidation001", 0};
    int32_t sessionId = 0;

    GetFakeSpmKernelState().getVersionRet = ENOTSUP;
    Identity sameAsUser;
    sameAsUser.tokenId = SAME_AS_USER_TOKEN;
    sameAsUser.uid = info.userID;
    sameAsUser.appUid = REPAIR_APP_UID;
    EXPECT_NE(ERR_PARAM_INVALID,
        g_installSessionManager->CreateInstallSession(info, bundlePolicy, nullptr, sessionId, sameAsUser));

    ResetFakeSpmKernelState();
    auto& sessionCache = g_installSessionManager->sessionToInstallCache;
    InstallCache userCache;
    userCache.baseInfo = info;
    userCache.hasPermChecked = true;
    userCache.repairedIdentity = sameAsUser;
    sessionCache[REPAIR_SESSION_ID] = userCache;
    Identity preparedUser;
    int32_t ret = g_installSessionManager->PrepareSessionIdentity(
        REPAIR_SESSION_ID, info, bundlePolicy, preparedUser, false);
    EXPECT_EQ(RET_SUCCESS, ret);
    EXPECT_EQ(REPAIR_APP_UID, preparedUser.appUid);
    EXPECT_EQ(REPAIR_APP_UID, preparedUser.uid); // SPM v1 kernel: the runtime uid stays the appUid
    EXPECT_EQ(SAME_AS_USER_TOKEN, AccessTokenIDManager::ExtractTokenIdFromFull(preparedUser.tokenId));
    auto userIt = sessionCache.find(REPAIR_SESSION_ID);
    ASSERT_NE(sessionCache.end(), userIt);
    EXPECT_TRUE(userIt->second.isAppUidFromCaller);
    // erase the seeded session so TearDown does not run FinishInstall on it
    sessionCache.erase(userIt);
    AccessTokenIDManager::GetInstance().ReleaseTokenId(static_cast<AccessTokenID>(preparedUser.tokenId));
    AccessTokenIDManager::GetInstance().RemoveBundleId(REPAIR_APP_UID);
}

/**
 * @tc.name: CreateInstallSessionDesiredUidOccupied001
 * @tc.desc: A repair identity whose desired appUid is already occupied passes the
 *           CreateInstallSession validation but is rejected at adoption time: the occupied
 *           bundleId makes IsAppUidReusable report non-reusable, so the conflicting appUid is
 *           never adopted and the session identity falls back to a fresh allocation.
 * @tc.type: FUNC
 * @tc.require: Issue
 */
HWTEST_F(InstallSessionSpmTaskTest, CreateInstallSessionDesiredUidOccupied001, TestSize.Level0)
{
    constexpr AccessTokenID OCCUPIED_DESIRED_TOKEN = 0x20000106;
    constexpr int32_t OCCUPIED_APP_UID = 20010005; // userId 100, bundleId 10005 (unused elsewhere)
    constexpr int32_t OCCUPIED_SESSION_ID = 990003;
    BundlePolicy bundlePolicy{std::vector<PreAuthorizationInfo>(), DLP_COMMON, false};
    HapBaseInfo info{100, "DesiredUidOccupied001", 0};
    int32_t sessionId = 0;

    // A positive CreateInstallSession continues into FillInstallPolicy; report the kernel as
    // unsupported so the flow ends in the installed-bundle query (the bundle has no rows).
    GetFakeSpmKernelState().getVersionRet = ENOTSUP;

    // The desired appUid belongs to user 100 and uid == appUid: the desired-identity validation
    // passes even though the appUid is occupied (occupancy is only checked at adoption time).
    Identity occupiedUid;
    occupiedUid.tokenId = OCCUPIED_DESIRED_TOKEN;
    occupiedUid.uid = OCCUPIED_APP_UID;
    occupiedUid.appUid = OCCUPIED_APP_UID;
    EXPECT_NE(ERR_PARAM_INVALID,
        g_installSessionManager->CreateInstallSession(info, bundlePolicy, nullptr, sessionId, occupiedUid));

    // Occupy the desired appUid's bundleId so IsAppUidReusable reports non-reusable
    ResetFakeSpmKernelState();
    ASSERT_EQ(RET_SUCCESS, AccessTokenIDManager::GetInstance().InitSingleBundleIdCache(OCCUPIED_APP_UID));

    // No session survives CreateInstallSession (no installed rows), so the adoption rejection is
    // asserted through PrepareSessionIdentity on a seeded session carrying the repair identity.
    auto& sessionCache = g_installSessionManager->sessionToInstallCache;
    InstallCache occupiedCache;
    occupiedCache.baseInfo = info;
    occupiedCache.hasPermChecked = true;
    occupiedCache.repairedIdentity = occupiedUid;
    sessionCache[OCCUPIED_SESSION_ID] = occupiedCache;
    Identity prepared;
    int32_t ret = g_installSessionManager->PrepareSessionIdentity(
        OCCUPIED_SESSION_ID, info, bundlePolicy, prepared, false);
    EXPECT_EQ(RET_SUCCESS, ret);
    // The conflicting desired appUid is rejected: a fresh conflict-free appUid is allocated
    EXPECT_NE(OCCUPIED_APP_UID, prepared.appUid);
    EXPECT_NE(-1, prepared.appUid);
    EXPECT_EQ(prepared.appUid, prepared.uid); // no uid switch: the runtime uid stays the appUid
    // The desired tokenId carries no conflict and is still adopted (only the appUid is rejected)
    EXPECT_EQ(OCCUPIED_DESIRED_TOKEN, AccessTokenIDManager::ExtractTokenIdFromFull(prepared.tokenId));
    auto occupiedIt = sessionCache.find(OCCUPIED_SESSION_ID);
    bool sessionFound = (occupiedIt != sessionCache.end());
    EXPECT_TRUE(sessionFound);
    if (sessionFound) {
        EXPECT_FALSE(occupiedIt->second.isAppUidFromCaller);
        // erase the seeded session so TearDown does not run FinishInstall on it
        sessionCache.erase(occupiedIt);
    }
    AccessTokenIDManager::GetInstance().ReleaseTokenId(static_cast<AccessTokenID>(prepared.tokenId));
    AccessTokenIDManager::GetInstance().RemoveBundleId(prepared.appUid);
    // Remove the occupancy seed so later tests see bundleId 10005 as free again
    AccessTokenIDManager::GetInstance().RemoveBundleId(OCCUPIED_APP_UID);
}

/**
 * @tc.name: CreateInstallSessionIncompleteRepairExpectation001
 * @tc.desc: A repair identity carrying a tokenId but invalid appUid/uid is an incomplete
 *           expectation: it is neither rejected nor adopted, the desired tokenId stays
 *           unregistered and the session identity is freshly allocated instead.
 * @tc.type: FUNC
 * @tc.require: Issue
 */
HWTEST_F(InstallSessionSpmTaskTest, CreateInstallSessionIncompleteRepairExpectation001, TestSize.Level0)
{
    constexpr AccessTokenID INCOMPLETE_DESIRED_TOKEN = 0x20000105;
    constexpr int32_t INCOMPLETE_SESSION_ID = 990002;
    BundlePolicy bundlePolicy{std::vector<PreAuthorizationInfo>(), DLP_COMMON, false};
    HapBaseInfo info{100, "IncompleteRepair001", 0};
    int32_t sessionId = 0;

    // report the kernel as unsupported so the flow ends in the installed-bundle query
    GetFakeSpmKernelState().getVersionRet = ENOTSUP;

    // tokenId set but appUid/uid invalid: an incomplete repair expectation
    Identity incomplete;
    incomplete.tokenId = INCOMPLETE_DESIRED_TOKEN;
    incomplete.uid = -1;
    incomplete.appUid = -1;
    EXPECT_NE(ERR_PARAM_INVALID,
        g_installSessionManager->CreateInstallSession(info, bundlePolicy, nullptr, sessionId, incomplete));

    // the fallback branch must not adopt (register) the desired tokenId
    TokenIdStatus status;
    EXPECT_NE(RET_SUCCESS,
        AccessTokenIDManager::GetInstance().GetTokenIdStatus(INCOMPLETE_DESIRED_TOKEN, status));

    // no session survives CreateInstallSession (no installed rows), so assert the fallback
    // consequence on a session seeded the way production leaves it: repairedIdentity stays
    // at its default {0, -1, -1} (the incomplete desired is NOT copied in)
    ResetFakeSpmKernelState();
    auto& sessionCache = g_installSessionManager->sessionToInstallCache;
    InstallCache freshCache;
    freshCache.baseInfo = info;
    freshCache.hasPermChecked = true;
    sessionCache[INCOMPLETE_SESSION_ID] = freshCache;
    Identity prepared;
    int32_t ret = g_installSessionManager->PrepareSessionIdentity(
        INCOMPLETE_SESSION_ID, info, bundlePolicy, prepared, false);
    EXPECT_EQ(RET_SUCCESS, ret);
    // fresh allocation: the desired tokenId was not adopted, appUid/uid are valid new values
    EXPECT_NE(INCOMPLETE_DESIRED_TOKEN, AccessTokenIDManager::ExtractTokenIdFromFull(prepared.tokenId));
    EXPECT_NE(-1, prepared.appUid);
    EXPECT_NE(-1, prepared.uid);
    auto freshIt = sessionCache.find(INCOMPLETE_SESSION_ID);
    bool sessionFound = (freshIt != sessionCache.end());
    EXPECT_TRUE(sessionFound);
    if (sessionFound) {
        EXPECT_FALSE(freshIt->second.isAppUidFromCaller);
        // erase the seeded session so TearDown does not run FinishInstall on it
        sessionCache.erase(freshIt);
    }
    AccessTokenIDManager::GetInstance().ReleaseTokenId(static_cast<AccessTokenID>(prepared.tokenId));
    AccessTokenIDManager::GetInstance().RemoveBundleId(prepared.appUid);
}

/**
 * @tc.name: CreateInstallSessionLegacyUidOnlyRepair001
 * @tc.desc: A legacy uid-only repair expectation (appUid left at the kit default 0) is
 *           the client's compatibility concern: the service takes the identity as-is,
 *           so the unset appUid is an incomplete expectation and the session identity
 *           is freshly allocated instead of adopting the caller's uid.
 * @tc.type: FUNC
 * @tc.require: Issue
 */
HWTEST_F(InstallSessionSpmTaskTest, CreateInstallSessionLegacyUidOnlyRepair001, TestSize.Level0)
{
    constexpr AccessTokenID LEGACY_DESIRED_TOKEN = 0x20000109;
    constexpr int32_t LEGACY_UID = 20010009; // userId 100, bundleId 10009
    constexpr int32_t LEGACY_SESSION_ID = 990003;

    // legacy input: tokenId + uid only, appUid stays the kit default 0; the client
    // folds uid onto appUid, the service contract below sees the folded form.
    Identity legacy;
    legacy.tokenId = LEGACY_DESIRED_TOKEN;
    legacy.uid = LEGACY_UID;
    legacy.appUid = 0;

    GetFakeSpmKernelState().getVersionRet = ENOTSUP;
    BundlePolicy bundlePolicy{std::vector<PreAuthorizationInfo>(), DLP_COMMON, false};
    HapBaseInfo info{100, "LegacyUidOnly001", 0};
    int32_t sessionId = 0;
    EXPECT_NE(ERR_PARAM_INVALID,
        g_installSessionManager->CreateInstallSession(info, bundlePolicy, nullptr, sessionId, legacy));

    // the unfolded input must not adopt (register) the desired tokenId
    TokenIdStatus status;
    EXPECT_NE(RET_SUCCESS,
        AccessTokenIDManager::GetInstance().GetTokenIdStatus(LEGACY_DESIRED_TOKEN, status));

    // no session survives CreateInstallSession (no installed rows), so assert the
    // fallback consequence on a session seeded the way production leaves it: with the
    // unfolded input the repairedIdentity stays at its default {0, -1, -1}
    ResetFakeSpmKernelState();
    auto& sessionCache = g_installSessionManager->sessionToInstallCache;
    InstallCache legacyCache;
    legacyCache.baseInfo = info;
    legacyCache.hasPermChecked = true;
    sessionCache[LEGACY_SESSION_ID] = legacyCache;
    Identity prepared;
    int32_t ret = g_installSessionManager->PrepareSessionIdentity(
        LEGACY_SESSION_ID, info, bundlePolicy, prepared, false);
    EXPECT_EQ(RET_SUCCESS, ret);
    // fresh allocation: the legacy uid is not adopted by the service itself
    EXPECT_NE(LEGACY_UID, prepared.appUid);
    EXPECT_NE(-1, prepared.appUid);
    EXPECT_NE(-1, prepared.uid);
    auto legacyIt = sessionCache.find(LEGACY_SESSION_ID);
    bool sessionFound = (legacyIt != sessionCache.end());
    EXPECT_TRUE(sessionFound);
    if (sessionFound) {
        EXPECT_FALSE(legacyIt->second.isAppUidFromCaller);
        // erase the seeded session so TearDown does not run FinishInstall on it
        sessionCache.erase(legacyIt);
    }
    AccessTokenIDManager::GetInstance().ReleaseTokenId(static_cast<AccessTokenID>(prepared.tokenId));
    AccessTokenIDManager::GetInstance().RemoveBundleId(prepared.appUid);
}

/**
 * @tc.name: SupplementUpdateInfoUidResolve001
 * @tc.desc: SupplementUpdateInfo records appUid allocation state only and never derives the
 *           runtime uid, even when isSharedUid is true on a v2 kernel. The supplemented
 *           entry carries the cached appUid, policy registration and dlpType carry-over
 *           survive, and the in-memory cached uid stays untouched because uid resolution is
 *           centralized at CreateUpdateHapInfo.
 * @tc.type: FUNC
 * @tc.require: Issue
 */
HWTEST_F(InstallSessionSpmTaskTest, SupplementUpdateInfoUidResolve001, TestSize.Level0)
{
    constexpr AccessTokenID SUPPLEMENT_TOKEN_ID = 0x20000021;
    constexpr int32_t SUPPLEMENT_APP_UID = 20010001; // userId 100, bundleId 10001

    // v2 kernel with the switch decision on: SupplementUpdateInfo still must not derive uid.
    GetFakeSpmKernelState().versionValue = 2;

    // Seed an ACTIVE in-memory token whose cached uid is the conservative appUid value.
    HapTokenInfo hapInfo = BuildHapInfo(SUPPLEMENT_TOKEN_ID, "test.bundle");
    auto inner = std::make_shared<HapTokenInfoInner>(
        SUPPLEMENT_TOKEN_ID, hapInfo, std::vector<PermissionStatus>());
    inner->SetAppUid(SUPPLEMENT_APP_UID);
    auto& tokenCache = AccessTokenInfoManager::GetInstance().hapTokenInfoMap_;
    tokenCache[SUPPLEMENT_TOKEN_ID] = inner;
    ASSERT_EQ(ERR_OK, AccessTokenIDManager::GetInstance().RegisterTokenId(SUPPLEMENT_TOKEN_ID, TOKEN_HAP));

    // Bundle whose profile flips the switch decision on; token list already loaded and no
    // explicit BMS policy, so the supplement fallback branch runs.
    InstallCache cache = BuildTestCache();
    cache.bundleParam.isSharedUid = true;
    cache.bundleTokenIdsLoaded = true;
    cache.bundleTokenIdList = {SUPPLEMENT_TOKEN_ID};

    g_installSessionManager->SupplementUpdateInfo(cache);

    // Surviving responsibilities: policy registration plus dlpType carry-over from the token.
    EXPECT_EQ(1u, cache.updatedBundlePolicyMap.count(SUPPLEMENT_TOKEN_ID));
    EXPECT_EQ(DLP_COMMON, cache.updatedBundlePolicyMap[SUPPLEMENT_TOKEN_ID].dlpType);
    // appUid allocation state only: the cached appUid, never a derived uid.
    auto it = cache.updatedUidStateMap.find(SUPPLEMENT_TOKEN_ID);
    bool found = (it != cache.updatedUidStateMap.end());
    EXPECT_TRUE(found);
    if (found) {
        EXPECT_EQ(SUPPLEMENT_APP_UID, it->second.appUid);
        EXPECT_FALSE(it->second.isNewBundleId);
        EXPECT_FALSE(it->second.fromCaller);
    }
    // No uid re-resolution here: the cached uid stays the seeded value even though
    // isSharedUid is true on a v2 kernel.
    EXPECT_EQ(SUPPLEMENT_APP_UID, inner->GetAppUid());

    tokenCache.erase(SUPPLEMENT_TOKEN_ID);
    AccessTokenIDManager::GetInstance().ReleaseTokenId(SUPPLEMENT_TOKEN_ID);
    AccessTokenIDManager::GetInstance().RemoveBundleId(SUPPLEMENT_APP_UID);
}

/**
 * @tc.name: SupplementUpdateInfoUidResolve003
 * @tc.desc: Corrupted row with appUid zero: SupplementUpdateInfo records the appUid state as-is
 *           (the appUid guard now lives in the migration and boot refresh paths, not here) and
 *           still never derives or writes the identity, so the corrupted appUid survives verbatim.
 * @tc.type: FUNC
 * @tc.require: Issue
 */
HWTEST_F(InstallSessionSpmTaskTest, SupplementUpdateInfoUidResolve003, TestSize.Level0)
{
    constexpr AccessTokenID SUPPLEMENT_TOKEN_ID = 0x20000023;
    constexpr int32_t SUPPLEMENT_VALID_UID = 20010001; // userId 100, bundleId 10001
    constexpr int32_t CORRUPTED_APP_UID = 0; // half-valid row: appUid corrupted to zero

    // v2 kernel with the switch decision on: the guard that used to skip re-resolution is gone.
    GetFakeSpmKernelState().versionValue = 2;

    // Seed an ACTIVE token whose appUid is corrupted to zero while the uid stays valid.
    HapTokenInfo hapInfo = BuildHapInfo(SUPPLEMENT_TOKEN_ID, "test.bundle");
    auto inner = std::make_shared<HapTokenInfoInner>(
        SUPPLEMENT_TOKEN_ID, hapInfo, std::vector<PermissionStatus>());
    inner->SetAppUid(CORRUPTED_APP_UID);
    auto& tokenCache = AccessTokenInfoManager::GetInstance().hapTokenInfoMap_;
    tokenCache[SUPPLEMENT_TOKEN_ID] = inner;
    ASSERT_EQ(ERR_OK, AccessTokenIDManager::GetInstance().RegisterTokenId(SUPPLEMENT_TOKEN_ID, TOKEN_HAP));

    InstallCache cache = BuildTestCache();
    cache.bundleParam.isSharedUid = true;
    cache.bundleTokenIdsLoaded = true;
    cache.bundleTokenIdList = {SUPPLEMENT_TOKEN_ID};

    g_installSessionManager->SupplementUpdateInfo(cache);

    EXPECT_EQ(1u, cache.updatedBundlePolicyMap.count(SUPPLEMENT_TOKEN_ID));
    auto it = cache.updatedUidStateMap.find(SUPPLEMENT_TOKEN_ID);
    bool found = (it != cache.updatedUidStateMap.end());
    EXPECT_TRUE(found);
    if (found) {
        // The corrupted appUid is recorded verbatim; no uid is derived from it here.
        EXPECT_EQ(CORRUPTED_APP_UID, it->second.appUid);
        EXPECT_FALSE(it->second.isNewBundleId);
        EXPECT_FALSE(it->second.fromCaller);
    }
    // The corrupted appUid is recorded verbatim because SupplementUpdateInfo never writes appUid.
    EXPECT_EQ(CORRUPTED_APP_UID, inner->GetAppUid());

    tokenCache.erase(SUPPLEMENT_TOKEN_ID);
    AccessTokenIDManager::GetInstance().ReleaseTokenId(SUPPLEMENT_TOKEN_ID);
    AccessTokenIDManager::GetInstance().RemoveBundleId(SUPPLEMENT_VALID_UID);
}

/**
 * @tc.name: SupplementUpdateInfoUidResolve004
 * @tc.desc: Invalid-token skip: a bundle token id with no in-memory info is skipped by
 *           SupplementUpdateInfo (no policy entry, no appUid state), while a valid sibling
 *           token is still supplemented. The former device-type no-switch scenario now lives
 *           in ResolveHapUidSwitchSemantics001 because uid derivation is centralized.
 * @tc.type: FUNC
 * @tc.require: Issue
 */
HWTEST_F(InstallSessionSpmTaskTest, SupplementUpdateInfoUidResolve004, TestSize.Level0)
{
    constexpr AccessTokenID VALID_TOKEN_ID = 0x20000024;
    constexpr AccessTokenID MISSING_TOKEN_ID = 0x20000025; // no in-memory info seeded
    constexpr int32_t VALID_APP_UID = 20010001; // userId 100, bundleId 10001

    GetFakeSpmKernelState().versionValue = 2;

    // Seed only the valid token; MISSING_TOKEN_ID has no in-memory info so it is skipped.
    HapTokenInfo hapInfo = BuildHapInfo(VALID_TOKEN_ID, "test.bundle");
    auto inner = std::make_shared<HapTokenInfoInner>(
        VALID_TOKEN_ID, hapInfo, std::vector<PermissionStatus>());
    inner->SetAppUid(VALID_APP_UID);
    auto& tokenCache = AccessTokenInfoManager::GetInstance().hapTokenInfoMap_;
    tokenCache[VALID_TOKEN_ID] = inner;
    ASSERT_EQ(ERR_OK, AccessTokenIDManager::GetInstance().RegisterTokenId(VALID_TOKEN_ID, TOKEN_HAP));

    InstallCache cache = BuildTestCache();
    cache.bundleParam.isSharedUid = true;
    cache.bundleTokenIdsLoaded = true;
    cache.bundleTokenIdList = {VALID_TOKEN_ID, MISSING_TOKEN_ID};

    g_installSessionManager->SupplementUpdateInfo(cache);

    // The valid token is supplemented; the missing token is skipped on both maps.
    EXPECT_EQ(1u, cache.updatedBundlePolicyMap.count(VALID_TOKEN_ID));
    EXPECT_EQ(0u, cache.updatedBundlePolicyMap.count(MISSING_TOKEN_ID));
    EXPECT_EQ(1u, cache.updatedUidStateMap.count(VALID_TOKEN_ID));
    EXPECT_EQ(0u, cache.updatedUidStateMap.count(MISSING_TOKEN_ID));

    tokenCache.erase(VALID_TOKEN_ID);
    AccessTokenIDManager::GetInstance().ReleaseTokenId(VALID_TOKEN_ID);
    AccessTokenIDManager::GetInstance().RemoveBundleId(VALID_APP_UID);
}

/**
 * @tc.name: ResolveHapUidSwitchSemantics001
 * @tc.desc: Centralized uid derivation locked at the single decision point that both
 *           CreateUpdateHapInfo and UpdateHapPolicy call. ResolveHapUid returns the userId
 *           form only when isSharedUid is true on a v2 kernel; it stays appUid when the
 *           switch decision is false, when the kernel version is below the switch version,
 *           or when the version query fails; an invalid uid short-circuits.
 * @tc.type: FUNC
 * @tc.require: Issue
 */
HWTEST_F(InstallSessionSpmTaskTest, ResolveHapUidSwitchSemantics001, TestSize.Level0)
{
    constexpr int32_t APP_UID = 20010001; // userId 100, bundleId 10001
    constexpr int32_t USER_ID_FORM = 100; // ExtractUserId of APP_UID
    constexpr int32_t INVALID_HAP_UID = -1;

    // v2 kernel: the switch decision selects between the userId form and appUid.
    GetFakeSpmKernelState().versionValue = 2;
    EXPECT_EQ(USER_ID_FORM, AccessTokenInfoUtils::ResolveHapUid(APP_UID, true));
    EXPECT_EQ(APP_UID, AccessTokenInfoUtils::ResolveHapUid(APP_UID, false));

    // Below the switch version: uid stays appUid even when the switch decision is true.
    GetFakeSpmKernelState().versionValue = 1;
    EXPECT_EQ(APP_UID, AccessTokenInfoUtils::ResolveHapUid(APP_UID, true));

    // Version query failure: falls back to appUid regardless of the switch decision.
    ResetFakeSpmKernelState();
    GetFakeSpmKernelState().getVersionRet = ENOTSUP;
    EXPECT_EQ(APP_UID, AccessTokenInfoUtils::ResolveHapUid(APP_UID, true));

    // Invalid uid short-circuits before any kernel query.
    ResetFakeSpmKernelState();
    GetFakeSpmKernelState().versionValue = 2;
    EXPECT_EQ(INVALID_HAP_UID, AccessTokenInfoUtils::ResolveHapUid(INVALID_HAP_UID, true));
}
} // namespace AccessToken
} // namespace Security
} // namespace OHOS
