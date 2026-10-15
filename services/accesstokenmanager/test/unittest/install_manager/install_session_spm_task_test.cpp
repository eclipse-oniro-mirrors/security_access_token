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

#include <gtest/gtest.h>

#define private public
#include "accesstoken_id_manager.h"
#include "accesstoken_info_manager.h"
#include "accesstoken_info_utils.h"
#include "accesstoken_manager_service.h"
#include "install_identity_manager.h"
#include "install_session_manager.h"
#undef private
#include "access_token.h"
#include "access_token_error.h"
#include "fake_token_setproc.h"
#include "hap_data_structure.h"
#include "hap_token_info.h"
#include "permission_kernel_utils.h"

using namespace testing::ext;

namespace OHOS {
namespace Security {
namespace AccessToken {
namespace {
constexpr uint32_t MAX_UID_RANGE = 200000;
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
    hapInfo.uid = 20100000 + (tokenId % MAX_UID_RANGE);
    return hapInfo;
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
        cache.identity.uid = 20100000 + (newTokenId % MAX_UID_RANGE);
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

        uint32_t hapSize = 0;
        uint32_t nativeSize = 0;
        uint32_t pefDefSize = 0;
        uint32_t dlpSize = 0;
        std::map<int32_t, TokenIdInfo> tokenIdAplMap;
        AccessTokenInfoManager::GetInstance().Init(hapSize, nativeSize, pefDefSize, dlpSize, tokenIdAplMap);

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

    HapTokenInfo hapInfo1 = BuildHapInfo(tokenId1, "test.bundle");
    context.hapInfos.emplace_back(hapInfo1);
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
    context.hapInfos.emplace_back(BuildHapInfo(newTokenId, "test.bundle"));
    context.permBriefDataLists.emplace_back(BuildBriefList(7));
    context.extendPermLists.emplace_back();
    context.oldPermList.emplace_back(std::make_shared<std::vector<BriefPermData>>());

    // Add an existing ACTIVE tokenID for update
    AccessTokenID existingTokenId = 0x20000008;
    ret = AccessTokenIDManager::GetInstance().RegisterTokenId(existingTokenId, TOKEN_HAP);
    ASSERT_EQ(ERR_OK, ret);

    context.hapInfos.emplace_back(BuildHapInfo(existingTokenId, "test.bundle"));
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

    context.hapInfos.emplace_back(BuildHapInfo(tokenId1, "test.bundle"));
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
    context.hapInfos.emplace_back(BuildHapInfo(newTokenId, "test.bundle"));
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
    context.hapInfos.emplace_back(BuildHapInfo(newTokenId, "test.bundle"));
    context.permBriefDataLists.emplace_back(BuildBriefList(14));
    context.extendPermLists.emplace_back();
    context.oldPermList.emplace_back(std::make_shared<std::vector<BriefPermData>>());
    context.hapInfos.emplace_back(BuildHapInfo(existingTokenId, "test.bundle"));
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
 *           and marks uidFromCaller; no desired uid keeps uidFromCaller false.
 * @tc.type: FUNC
 * @tc.require: Issue
 */
HWTEST_F(InstallSessionSpmTaskTest, GetTokenIdAndUidFromCallerTest001, TestSize.Level0)
{
    constexpr int32_t CALLER_UID = 20033333; // userId 100, bundleId 33333 (free in fake kernel)
    BundlePolicy bundlePolicy{std::vector<PreAuthorizationInfo>(), DLP_COMMON, false};

    // caller designates the uid via PrepareHapIdentity identity input
    InstallCache cache;
    cache.baseInfo = HapBaseInfo{100, "FromCallerUidTest001", 0};
    cache.repairedIdentity.uid = CALLER_UID;
    int32_t ret = InstallIdentityManager::GetTokenIdAndUid(cache, bundlePolicy);
    EXPECT_EQ(RET_SUCCESS, ret);
    EXPECT_EQ(CALLER_UID, cache.identity.uid);
    EXPECT_TRUE(cache.uidFromCaller);
    AccessTokenIDManager::GetInstance().ReleaseTokenId(static_cast<AccessTokenID>(cache.identity.tokenId));
    AccessTokenIDManager::GetInstance().RemoveBundleId(CALLER_UID);

    // no desired uid: fresh allocation via fake kernel, uidFromCaller stays false
    InstallCache cache2;
    cache2.baseInfo = HapBaseInfo{100, "FromCallerUidTest001", 0};
    cache2.repairedIdentity.uid = -1;
    ret = InstallIdentityManager::GetTokenIdAndUid(cache2, bundlePolicy);
    EXPECT_EQ(RET_SUCCESS, ret);
    EXPECT_NE(-1, cache2.identity.uid);
    EXPECT_FALSE(cache2.uidFromCaller);
    AccessTokenIDManager::GetInstance().ReleaseTokenId(static_cast<AccessTokenID>(cache2.identity.tokenId));
    AccessTokenIDManager::GetInstance().RemoveBundleId(cache2.identity.uid);
}
} // namespace AccessToken
} // namespace Security
} // namespace OHOS
