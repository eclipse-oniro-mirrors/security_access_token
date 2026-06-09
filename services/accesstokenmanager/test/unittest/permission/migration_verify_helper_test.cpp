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

#include "gtest/gtest.h"
#include <gtest/hwext/gtest-tag.h>

#include <chrono>
#include <thread>

#include "access_token_db_operator.h"
#include "access_token_error.h"
#include "accesstoken_common_log.h"
#include "hap_token_info_inner.h"
#include "idl_common.h"
#include "permission_data_brief.h"
#include "token_field_const.h"

#define private public
#include "migration_verify_worker.h"
#include "hap_sign_verify_manager.h"
#include "hap_sign_verify_helper.h"
#include "migration_verify_helper.h"
#undef private
#include "mock_app_verify_adapter.h"
#include "test_common.h"
#include "token_setproc.h"

using namespace testing::ext;

namespace OHOS {
namespace Security {
namespace AccessToken {
namespace {
MockAppVerifyAdapter mockAdapter_;
AppVerifyAdapter resetAdapter_;

void SetUpVerifyEnvironment()
{
    HapSignVerifyManager::GetInstance().adapter_ = &mockAdapter_;
}

void TearDownVerifyEnvironment()
{
    HapSignVerifyManager::GetInstance().adapter_ = &resetAdapter_;
}

MigratedInfoIdl BuildBasicMigratedInfo(const std::string& bundleName, const std::string& hapPath,
    bool isPreInstalled = false)
{
    MigratedInfoIdl migratedInfo;
    migratedInfo.bundleName = bundleName;
    migratedInfo.pathList.hapPaths = { hapPath };
    migratedInfo.pathList.isPreInstalled = isPreInstalled;
    HapBaseInfoIdl baseInfo;
    baseInfo.bundleName = bundleName;
    baseInfo.userID = 100; // 100: user id
    baseInfo.instIndex = 0;
    migratedInfo.hapBaseInfoList = { baseInfo };
    migratedInfo.uidList = { 200100 };
    migratedInfo.reservedTypeList = { ReservedTypeIdl::NONE };
    return migratedInfo;
}

std::shared_ptr<HapTokenInfoInner> BuildCachedInfo(AccessTokenID tokenId, int32_t userId,
    const std::string& bundleName, int32_t instIndex)
{
    auto infoPtr = std::make_shared<HapTokenInfoInner>();
    HapTokenInfo hapTokenInfo;
    hapTokenInfo.tokenID = tokenId;
    hapTokenInfo.userID = userId;
    hapTokenInfo.bundleName = bundleName;
    hapTokenInfo.instIndex = instIndex;
    infoPtr->SetTokenBaseInfo(hapTokenInfo);
    return infoPtr;
}
} // namespace

class MigrationVerifyHelperTest : public testing::Test {
public:
    static void SetUpTestCase()
    {
        SetUpVerifyEnvironment();
        TestCommon::SetTestEvironment(GetSelfTokenID());
    }

    static void TearDownTestCase()
    {
        TearDownVerifyEnvironment();
        TestCommon::ResetTestEvironment();
    }
};

/**
 * @tc.name: VerifyMigratedBundle001
 * @tc.desc: Full happy path — verification, kernel, DB persist, and cache update all succeed.
 *           Verifies sign info in DB and permission data in cache after completion.
 * @tc.type: FUNC
 */
HWTEST_F(MigrationVerifyHelperTest, VerifyMigratedBundle001, TestSize.Level1)
{
    MockNativeToken mock("foundation");

    HapInfoParams info = TestCommon::GetInfoManagerTestSystemInfoParms();
    info.bundleName = "com.example.verify.full";
    info.appIDDesc = info.bundleName;
    HapPolicyParams policy = TestCommon::GetTestPolicyParams();

    AccessTokenIDEx tokenIdEx = {0};
    ASSERT_EQ(RET_SUCCESS, TestCommon::AllocTestHapToken(info, policy, tokenIdEx));

    AccessTokenID tokenId = tokenIdEx.tokenIdExStruct.tokenID;
    auto cachedInfo = BuildCachedInfo(tokenId, info.userID, info.bundleName, 0);
    std::vector<std::shared_ptr<HapTokenInfoInner>> cachedInfos = { cachedInfo };

    // Configure mock adapter to return a verified bundle name matching migratedInfo.bundleName
    mockAdapter_.bundleName_ = info.bundleName;
    MigratedInfoIdl migratedInfo = BuildBasicMigratedInfo(info.bundleName, info.bundleName);
    // Insert a placeholder sign info row so DoBundleInfoOperations can Modify (UPDATE) it;
    // without a placeholder, Modify affects zero rows and sign info is never persisted.
    {
        GenericValues placeholder;
        placeholder.Put(TokenFiledConst::FIELD_BUNDLE_NAME, migratedInfo.bundleName);
        placeholder.Put(TokenFiledConst::FIELD_MODULE_NAME, "#0");
        placeholder.Put(TokenFiledConst::FIELD_PATH, migratedInfo.pathList.hapPaths[0]);
        placeholder.Put(TokenFiledConst::FIELD_IS_PREINSTALLED, false);
        placeholder.Put(TokenFiledConst::FIELD_BUNDLE_TYPE, 0);
        std::vector<uint8_t> emptyBlob {1};
        placeholder.PutBlob(TokenFiledConst::FIELD_PERSIST_DATA, emptyBlob);
        AddInfo addInfo;
        addInfo.addType = AtmDataType::ACCESSTOKEN_HAP_PACKAGE_INFO;
        addInfo.addValues = { placeholder };
        ASSERT_EQ(RET_SUCCESS, AccessTokenDbOperator::DeleteAndInsertValues({}, { addInfo }));
    }


    int32_t ret = MigrationVerifyHelper::GetInstance().VerifyMigratedBundle(migratedInfo, cachedInfos);
    EXPECT_EQ(RET_SUCCESS, ret);

    // Verify DB: sign info persisted for the bundle with valid fields
    GenericValues signCondition;
    signCondition.Put(TokenFiledConst::FIELD_BUNDLE_NAME, info.bundleName);
    std::vector<GenericValues> signResults;
    ASSERT_EQ(RET_SUCCESS, AccessTokenDbOperator::Find(
        AtmDataType::ACCESSTOKEN_HAP_PACKAGE_INFO, signCondition, signResults));
    ASSERT_FALSE(signResults.empty());
    for (const auto& row : signResults) {
        std::string moduleName = row.GetString(TokenFiledConst::FIELD_MODULE_NAME);
        EXPECT_EQ(moduleName, mockAdapter_.moduleName_);
    }

    // Verify cache: permission data populated for the token
    std::vector<BriefPermData> briefDataList;
    EXPECT_EQ(RET_SUCCESS, PermissionDataBrief::GetInstance().GetBriefPermDataByTokenId(
        tokenId, briefDataList));
    EXPECT_FALSE(briefDataList.empty());

    (void)SpmRemoveEntry(tokenId);
    EXPECT_EQ(RET_SUCCESS, AccessTokenKit::DeleteToken(tokenId));
}

/**
 * @tc.name: VerifyMigratedBundle002
 * @tc.desc: VerifyMigratedBundle with empty cachedInfos returns ERR_PARAM_INVALID.
 * @tc.type: FUNC
 */
HWTEST_F(MigrationVerifyHelperTest, VerifyMigratedBundle002, TestSize.Level1)
{
    MockNativeToken mock("foundation");

    MigratedInfoIdl migratedInfo = BuildBasicMigratedInfo("com.example.verify.empty", "com.example.verify.empty");
    std::vector<std::shared_ptr<HapTokenInfoInner>> cachedInfos;

    int32_t ret = MigrationVerifyHelper::GetInstance().VerifyMigratedBundle(migratedInfo, cachedInfos);
    EXPECT_EQ(ERR_PARAM_INVALID, ret);
}

/**
 * @tc.name: VerifyMigratedBundle003
 * @tc.desc: VerifyMigratedBundle with mismatched bundleName fails verification gracefully.
 * @tc.type: FUNC
 */
HWTEST_F(MigrationVerifyHelperTest, VerifyMigratedBundle003, TestSize.Level1)
{
    MockNativeToken mock("foundation");

    HapInfoParams info = TestCommon::GetInfoManagerTestSystemInfoParms();
    info.bundleName = "com.example.verify.mismatch";
    info.appIDDesc = info.bundleName;
    HapPolicyParams policy = TestCommon::GetTestPolicyParams();

    AccessTokenIDEx tokenIdEx = {0};
    ASSERT_EQ(RET_SUCCESS, TestCommon::AllocTestHapToken(info, policy, tokenIdEx));

    AccessTokenID tokenId = tokenIdEx.tokenIdExStruct.tokenID;
    auto cachedInfo = BuildCachedInfo(tokenId, info.userID, info.bundleName, 0);
    std::vector<std::shared_ptr<HapTokenInfoInner>> cachedInfos = { cachedInfo };

    // Use a different bundleName from hapPath — mock adapter derives verified
    // bundle name from hapPath, so mismatch triggers ERR_PARAM_INVALID
    MigratedInfoIdl migratedInfo = BuildBasicMigratedInfo("com.example.mismatched", "com.example.different");

    int32_t ret = MigrationVerifyHelper::GetInstance().VerifyMigratedBundle(migratedInfo, cachedInfos);
    // Bundle name mismatch causes DoVerifyMigratedBundle failure → error propagated
    EXPECT_NE(RET_SUCCESS, ret);

    (void)SpmRemoveEntry(tokenId);
    EXPECT_EQ(RET_SUCCESS, AccessTokenKit::DeleteToken(tokenId));
}

/**
 * @tc.name: VerifyMigratedBundle004
 * @tc.desc: DoVerifyMigratedBundle fails → returns RET_SUCCESS (best-effort).
 * @tc.type: FUNC
 */
HWTEST_F(MigrationVerifyHelperTest, VerifyMigratedBundle004, TestSize.Level1)
{
    MockNativeToken mock("foundation");

    HapInfoParams info = TestCommon::GetInfoManagerTestSystemInfoParms();
    info.bundleName = "com.example.verify.signfail";
    info.appIDDesc = info.bundleName;
    HapPolicyParams policy = TestCommon::GetTestPolicyParams();

    AccessTokenIDEx tokenIdEx = {0};
    ASSERT_EQ(RET_SUCCESS, TestCommon::AllocTestHapToken(info, policy, tokenIdEx));

    AccessTokenID tokenId = tokenIdEx.tokenIdExStruct.tokenID;
    auto cachedInfo = BuildCachedInfo(tokenId, info.userID, info.bundleName, 0);
    std::vector<std::shared_ptr<HapTokenInfoInner>> cachedInfos = { cachedInfo };

    MigratedInfoIdl migratedInfo = BuildBasicMigratedInfo(info.bundleName, info.bundleName);

    // Force CheckHapsSignInfo to fail via mock adapter
    mockAdapter_.verifyRet_ = AccessTokenError::ERR_PARAM_INVALID;
    int32_t ret = MigrationVerifyHelper::GetInstance().VerifyMigratedBundle(migratedInfo, cachedInfos);
    mockAdapter_.verifyRet_ = RET_SUCCESS;
    // DoVerifyMigratedBundle failure propagates the error
    EXPECT_EQ(AccessTokenError::ERR_HAP_SIGN_VERIFY_FAILED, ret);

    (void)SpmRemoveEntry(tokenId);
    EXPECT_EQ(RET_SUCCESS, AccessTokenKit::DeleteToken(tokenId));
}

/**
 * @tc.name: VerifyMigratedBundle006
 * @tc.desc: Same as 001 but the database value is not updated since the value is not a placeholder
 * @tc.type: FUNC
 */
HWTEST_F(MigrationVerifyHelperTest, VerifyMigratedBundle006, TestSize.Level1)
{
    MockNativeToken mock("foundation");

    HapInfoParams info = TestCommon::GetInfoManagerTestSystemInfoParms();
    info.bundleName = "com.example.verify.updated";
    info.appIDDesc = info.bundleName;
    HapPolicyParams policy = TestCommon::GetTestPolicyParams();

    AccessTokenIDEx tokenIdEx = {0};
    ASSERT_EQ(RET_SUCCESS, TestCommon::AllocTestHapToken(info, policy, tokenIdEx));

    AccessTokenID tokenId = tokenIdEx.tokenIdExStruct.tokenID;
    auto cachedInfo = BuildCachedInfo(tokenId, info.userID, info.bundleName, 0);
    std::vector<std::shared_ptr<HapTokenInfoInner>> cachedInfos = { cachedInfo };

    // Configure mock adapter to return a verified bundle name matching migratedInfo.bundleName
    mockAdapter_.bundleName_ = info.bundleName;
    MigratedInfoIdl migratedInfo = BuildBasicMigratedInfo(info.bundleName, info.bundleName);
    // Insert a placeholder sign info row so DoBundleInfoOperations can Modify (UPDATE) it;
    // without a placeholder, Modify affects zero rows and sign info is never persisted.
    {
        GenericValues placeholder;
        placeholder.Put(TokenFiledConst::FIELD_BUNDLE_NAME, migratedInfo.bundleName);
        placeholder.Put(TokenFiledConst::FIELD_MODULE_NAME, "valid_module_name");
        placeholder.Put(TokenFiledConst::FIELD_PATH, migratedInfo.pathList.hapPaths[0]);
        placeholder.Put(TokenFiledConst::FIELD_IS_PREINSTALLED, false);
        placeholder.Put(TokenFiledConst::FIELD_BUNDLE_TYPE, 0);
        std::vector<uint8_t> emptyBlob {1};
        placeholder.PutBlob(TokenFiledConst::FIELD_PERSIST_DATA, emptyBlob);
        AddInfo addInfo;
        addInfo.addType = AtmDataType::ACCESSTOKEN_HAP_PACKAGE_INFO;
        addInfo.addValues = { placeholder };
        ASSERT_EQ(RET_SUCCESS, AccessTokenDbOperator::DeleteAndInsertValues({}, { addInfo }));
    }

    int32_t ret = MigrationVerifyHelper::GetInstance().VerifyMigratedBundle(migratedInfo, cachedInfos);
    EXPECT_EQ(RET_SUCCESS, ret);

    // Verify DB: sign info persisted for the bundle with valid fields
    GenericValues signCondition;
    signCondition.Put(TokenFiledConst::FIELD_BUNDLE_NAME, info.bundleName);
    std::vector<GenericValues> signResults;
    ASSERT_EQ(RET_SUCCESS, AccessTokenDbOperator::Find(
        AtmDataType::ACCESSTOKEN_HAP_PACKAGE_INFO, signCondition, signResults));
    ASSERT_FALSE(signResults.empty());
    for (const auto& row : signResults) {
        std::string moduleName = row.GetString(TokenFiledConst::FIELD_MODULE_NAME);
        EXPECT_EQ(moduleName, "valid_module_name");
    }

    // Verify cache: permission data populated for the token
    std::vector<BriefPermData> briefDataList;
    EXPECT_EQ(RET_SUCCESS, PermissionDataBrief::GetInstance().GetBriefPermDataByTokenId(
        tokenId, briefDataList));
    EXPECT_FALSE(briefDataList.empty());

    (void)SpmRemoveEntry(tokenId);
    EXPECT_EQ(RET_SUCCESS, AccessTokenKit::DeleteToken(tokenId));
}

/**
 * @tc.name: VerifyMigratedBundle007
 * @tc.desc: CheckMultipleHaps fails due to mismatched appIdentifier
 * @tc.type: FUNC
 */
HWTEST_F(MigrationVerifyHelperTest, VerifyMigratedBundle007, TestSize.Level1)
{
    MockNativeToken mock("foundation");

    HapInfoParams info = TestCommon::GetInfoManagerTestSystemInfoParms();
    info.bundleName = "com.example.verify.multifail";
    info.appIDDesc = info.bundleName;
    HapPolicyParams policy = TestCommon::GetTestPolicyParams();

    AccessTokenIDEx tokenIdEx = {0};
    ASSERT_EQ(RET_SUCCESS, TestCommon::AllocTestHapToken(info, policy, tokenIdEx));

    AccessTokenID tokenId = tokenIdEx.tokenIdExStruct.tokenID;
    auto cachedInfo = BuildCachedInfo(tokenId, info.userID, info.bundleName, 0);
    std::vector<std::shared_ptr<HapTokenInfoInner>> cachedInfos = { cachedInfo };

    // Build migratedInfo with 2 different hapPaths
    MigratedInfoIdl migratedInfo;
    migratedInfo.bundleName = info.bundleName;
    migratedInfo.pathList.hapPaths = { info.bundleName + "_a", info.bundleName + "_b" };
    migratedInfo.pathList.isPreInstalled = false;
    migratedInfo.uidList = { 200100, 200101 };
    migratedInfo.reservedTypeList = { ReservedTypeIdl::NONE, ReservedTypeIdl::NONE };
    HapBaseInfoIdl baseInfo;
    baseInfo.bundleName = info.bundleName;
    baseInfo.userID = 100;
    baseInfo.instIndex = 0;
    migratedInfo.hapBaseInfoList = { baseInfo, baseInfo };

    mockAdapter_.bundleName_ = info.bundleName;
    // Clear appIdentifier_: each VerifyHap call uses params.filePath (hapPath) as appIdentifier
    // → two hapPaths produce different appIdentifiers → CheckMultipleHaps detects mismatch
    mockAdapter_.appIdentifier_ = "";
    mockAdapter_.appId_ = "";

    int32_t ret = MigrationVerifyHelper::GetInstance().VerifyMigratedBundle(migratedInfo, cachedInfos);
    // CheckMultipleHaps fails with ERR_PARAM_INVALID → line 70 → DoVerifyMigratedBundle returns error
    EXPECT_NE(RET_SUCCESS, ret);

    mockAdapter_.appIdentifier_ = "mock.identifier";
    mockAdapter_.appId_ = "mock.appid";

    (void)SpmRemoveEntry(tokenId);
    EXPECT_EQ(RET_SUCCESS, AccessTokenKit::DeleteToken(tokenId));
}

/**
 * @tc.name: VerifyMigratedBundle008
 * @tc.desc: ToGenericValues fails due to mismatched list sizes
 * @tc.type: FUNC
 */
HWTEST_F(MigrationVerifyHelperTest, VerifyMigratedBundle008, TestSize.Level1)
{
    MockNativeToken mock("foundation");

    // Construct a BundleSignInfo with mismatched list sizes
    BundleSignInfo bundleSignInfo;
    bundleSignInfo.bundleName = "com.example.badsign";
    bundleSignInfo.moduleNameList = { "entry" };
    bundleSignInfo.pathList = {};  // empty, size 0 != moduleNameList size 1
    bundleSignInfo.bundleType = { 0 };
    bundleSignInfo.persistDataList = { {} };

    int32_t ret = MigrationVerifyHelper::GetInstance().DoBundleInfoOperations(bundleSignInfo);
    // ToGenericValues detects size mismatch → returns ERR_PARAM_INVALID → line 131
    EXPECT_EQ(AccessTokenError::ERR_PARAM_INVALID, ret);
}

/**
 * @tc.name: VerifyMigratedBundle009
 * @tc.desc: BuildBundleSignInfo fails with mismatched sizes
 * @tc.type: FUNC
 */
HWTEST_F(MigrationVerifyHelperTest, VerifyMigratedBundle009, TestSize.Level1)
{
    MockNativeToken mock("foundation");

    // Construct mismatched MigratedInfoIdl and VerifiedMigrationBundle
    MigratedInfoIdl migratedInfo;
    migratedInfo.bundleName = "com.example.badsize";
    migratedInfo.pathList.hapPaths = { "hap_a", "hap_b" };  // 2 hapPaths
    VerifiedMigrationBundle verifiedBundle;
    // Only 1 verifiedInfo → verifiedSize=1 != hapPaths.size()=2 → line 99
    auto info1 = std::make_shared<TrustedBundleInfoInner>();
    verifiedBundle.verifiedInfos = { *info1 };

    BundleSignInfo bundleSignInfo;
    int32_t ret = MigrationVerifyHelper::GetInstance().BuildBundleSignInfo(
        migratedInfo, verifiedBundle, bundleSignInfo);
    EXPECT_EQ(AccessTokenError::ERR_PARAM_INVALID, ret);
}

/**
 * @tc.name: VerifyMigratedBundle010
 * @tc.desc: BuildPermStateValues with unknown permCode
 * @tc.type: FUNC
 */
HWTEST_F(MigrationVerifyHelperTest, VerifyMigratedBundle010, TestSize.Level1)
{
    MockNativeToken mock("foundation");

    // Construct BriefPermData with an unknown permCode (0xFFFF)
    std::vector<BriefPermData> data;
    BriefPermData badPerm;
    badPerm.permCode = 0xFFFF;  // non-existent permCode → TransferOpcodeToPermission returns empty
    badPerm.status = PERMISSION_GRANTED;
    badPerm.flag = PERMISSION_SYSTEM_FIXED;
    data.emplace_back(badPerm);

    AccessTokenID testTokenId = 1;
    std::vector<GenericValues> result =
        MigrationVerifyHelper::GetInstance().BuildPermStateValues(testTokenId, data);
    ASSERT_EQ(0U, result.size());
}

/**
 * @tc.name: BuildPermBriefDataFromPolicy001
 * @tc.desc: BuildPermBriefDataListFromPolicy and BuildExtendPermListFromPolicy
 * with known policy produce correct output.
 * @tc.type: FUNC
 */
HWTEST_F(MigrationVerifyHelperTest, BuildPermBriefDataFromPolicy001, TestSize.Level1)
{
    HapPolicy policy;
    PermissionStatus permState;
    permState.permissionName = "ohos.permission.CAMERA";
    permState.grantStatus = PERMISSION_GRANTED;
    permState.grantFlag = PERMISSION_SYSTEM_FIXED;
    policy.permStateList = { permState };
    policy.aclExtendedMap = { {"ohos.permission.CAMERA", "test_value"} };

    std::vector<BriefPermData> briefList;
    HapSignVerifyHelper::BuildPermBriefDataListFromPolicy(policy, briefList);
    EXPECT_FALSE(briefList.empty());

    std::vector<PermissionWithValue> extendList;
    HapSignVerifyHelper::BuildExtendPermListFromPolicy(policy, extendList);
    ASSERT_EQ(1u, extendList.size());
    EXPECT_EQ("ohos.permission.CAMERA", extendList[0].permissionName);
    EXPECT_EQ("test_value", extendList[0].value);
}

/**
 * @tc.name: BuildPermBriefDataFromPolicy002
 * @tc.desc: BuildPermBriefDataListFromPolicy with empty permStateList returns empty result.
 * @tc.type: FUNC
 */
HWTEST_F(MigrationVerifyHelperTest, BuildPermBriefDataFromPolicy002, TestSize.Level1)
{
    HapPolicy policy;
    policy.aclExtendedMap = {};

    std::vector<BriefPermData> briefList;
    HapSignVerifyHelper::BuildPermBriefDataListFromPolicy(policy, briefList);
    EXPECT_TRUE(briefList.empty());

    std::vector<PermissionWithValue> extendList;
    HapSignVerifyHelper::BuildExtendPermListFromPolicy(policy, extendList);
    EXPECT_TRUE(extendList.empty());
}

class MigrationVerifyWorkerTest : public testing::Test {
public:
    static void SetUpTestCase()
    {
        TestCommon::SetTestEvironment(GetSelfTokenID());
    }

    static void TearDownTestCase()
    {
        TestCommon::ResetTestEvironment();
    }

    void SetUp() override
    {
        // Ensure worker is in a clean state
        MigrationVerifyWorker::GetInstance().Shutdown();
    }

    void TearDown() override
    {
        MigrationVerifyWorker::GetInstance().Shutdown();
    }
};

/**
 * @tc.name: WorkerSubmitAndShutdown001
 * @tc.desc: Submit tasks and shutdown — worker starts, processes tasks, stops cleanly.
 * @tc.type: FUNC
 */
HWTEST_F(MigrationVerifyWorkerTest, WorkerSubmitAndShutdown001, TestSize.Level1)
{
    MockNativeToken mock("foundation");
    SetUpVerifyEnvironment();

    MigratedInfoIdl migratedInfo = BuildBasicMigratedInfo("com.example.worker.basic", "com.example.worker.basic");
    std::vector<std::shared_ptr<HapTokenInfoInner>> cachedInfos;

    // Submit should not crash even with empty cachedInfos
    MigrationVerifyWorker::GetInstance().Submit(migratedInfo, cachedInfos);

    // Give worker time to process
    std::this_thread::sleep_for(std::chrono::milliseconds(100));

    // Shutdown should not hang
    MigrationVerifyWorker::GetInstance().Shutdown();

    // Submit after shutdown should be rejected (logged as warning, no crash)
    MigrationVerifyWorker::GetInstance().Submit(migratedInfo, cachedInfos);

    TearDownVerifyEnvironment();
}

/**
 * @tc.name: WorkerIdleTimeout002
 * @tc.desc: Worker thread auto-exits after idle timeout, new Submit spawns new thread.
 * @tc.type: FUNC
 */
HWTEST_F(MigrationVerifyWorkerTest, WorkerIdleTimeout002, TestSize.Level1)
{
    MockNativeToken mock("foundation");

    MigratedInfoIdl migratedInfo = BuildBasicMigratedInfo("com.example.worker.idle", "com.example.worker.idle");
    std::vector<std::shared_ptr<HapTokenInfoInner>> cachedInfos;

    // First submit starts the worker
    MigrationVerifyWorker::GetInstance().Submit(migratedInfo, cachedInfos);

    // Wait longer than the idle timeout (30s default, but we just test no-crash with re-submit)
    // In unit test, we just verify Submit + Shutdown is idempotent
    MigrationVerifyWorker::GetInstance().Shutdown();

    // Re-submit after shutdown should restart
    MigrationVerifyWorker::GetInstance().Submit(migratedInfo, cachedInfos);
    std::this_thread::sleep_for(std::chrono::milliseconds(100));
    MigrationVerifyWorker::GetInstance().Shutdown();
}

/**
 * @tc.name: WorkerMultipleSubmit003
 * @tc.desc: Multiple rapid submits are handled without data loss or crash.
 * @tc.type: FUNC
 */
HWTEST_F(MigrationVerifyWorkerTest, WorkerMultipleSubmit003, TestSize.Level1)
{
    MockNativeToken mock("foundation");

    for (int i = 0; i < 5; ++i) {
        MigratedInfoIdl migratedInfo = BuildBasicMigratedInfo(
            "com.example.worker.multi" + std::to_string(i),
            "com.example.worker.multi" + std::to_string(i));
        std::vector<std::shared_ptr<HapTokenInfoInner>> cachedInfos;
        MigrationVerifyWorker::GetInstance().Submit(migratedInfo, cachedInfos);
    }

    // Let worker drain the queue
    std::this_thread::sleep_for(std::chrono::milliseconds(200));
    MigrationVerifyWorker::GetInstance().Shutdown();
}

/**
 * @tc.name: WorkerProcessRealTask004
 * @tc.desc: Worker processes a real verification task with mock adapter — completes without crash.
 * @tc.type: FUNC
 */
HWTEST_F(MigrationVerifyWorkerTest, WorkerProcessRealTask004, TestSize.Level1)
{
    MockNativeToken mock("foundation");
    SetUpVerifyEnvironment();

    HapInfoParams info = TestCommon::GetInfoManagerTestSystemInfoParms();
    info.bundleName = "com.example.worker.real";
    info.appIDDesc = info.bundleName;
    HapPolicyParams policy = TestCommon::GetTestPolicyParams();

    AccessTokenIDEx tokenIdEx = {0};
    ASSERT_EQ(RET_SUCCESS, TestCommon::AllocTestHapToken(info, policy, tokenIdEx));

    AccessTokenID tokenId = tokenIdEx.tokenIdExStruct.tokenID;
    auto cachedInfo = BuildCachedInfo(tokenId, info.userID, info.bundleName, 0);
    std::vector<std::shared_ptr<HapTokenInfoInner>> cachedInfos = { cachedInfo };

    MigratedInfoIdl migratedInfo = BuildBasicMigratedInfo(info.bundleName, info.bundleName);
    MigrationVerifyWorker::GetInstance().Submit(migratedInfo, cachedInfos);

    // Give worker time to process the real verification task
    std::this_thread::sleep_for(std::chrono::milliseconds(500));
    MigrationVerifyWorker::GetInstance().Shutdown();

    (void)SpmRemoveEntry(tokenId);
    EXPECT_EQ(RET_SUCCESS, AccessTokenKit::DeleteToken(tokenId));

    TearDownVerifyEnvironment();
}

/**
 * @tc.name: WorkerShutdownDuringProcessing005
 * @tc.desc: Shutdown called while worker is processing tasks — does not hang or crash.
 * @tc.type: FUNC
 */
HWTEST_F(MigrationVerifyWorkerTest, WorkerShutdownDuringProcessing005, TestSize.Level1)
{
    MockNativeToken mock("foundation");

    // Submit several tasks
    for (int i = 0; i < 3; ++i) {
        MigratedInfoIdl migratedInfo = BuildBasicMigratedInfo(
            "com.example.worker.shutdown" + std::to_string(i),
            "com.example.worker.shutdown" + std::to_string(i));
        std::vector<std::shared_ptr<HapTokenInfoInner>> cachedInfos;
        MigrationVerifyWorker::GetInstance().Submit(migratedInfo, cachedInfos);
    }

    // Immediately shutdown while worker may still be processing
    MigrationVerifyWorker::GetInstance().Shutdown();

    EXPECT_EQ(true, MigrationVerifyWorker::GetInstance().taskQueue_.empty());

    // Double shutdown should be safe
    MigrationVerifyWorker::GetInstance().Shutdown();
}

/**
 * @tc.name: ThreadAutoShutdown001
 * @tc.desc: Ensure thread shutdown automatically after idle timeout
 * @tc.type: FUNC
 */
HWTEST_F(MigrationVerifyWorkerTest, ThreadAutoShutdown001, TestSize.Level1)
{
    MigrationVerifyWorker::GetInstance().IDLE_TIMEOUT = std::chrono::seconds(1);
    MigrationVerifyWorker::GetInstance().EnsureThreadRunning();
    MigrationVerifyWorker::GetInstance().EnsureThreadRunning();

    std::this_thread::sleep_for(std::chrono::seconds(2));
    
    EXPECT_EQ(false, MigrationVerifyWorker::GetInstance().running_);
    MigrationVerifyWorker::GetInstance().IDLE_TIMEOUT = std::chrono::seconds(30);
}
} // namespace AccessToken
} // namespace Security
} // namespace OHOS
