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

#include "access_token_db.h"
#include "access_token_db_operator.h"
#include "access_token_error.h"
#include "accesstoken_kit.h"
#include "accesstoken_info_manager.h"

#define private public
#ifdef IS_SUPPORT_HAP_RUNNING
#include "migration_verify_worker.h"
#include "hap_sign_verify_manager.h"
#endif
#include "accesstoken_id_manager.h"
#include "accesstoken_migration_manager.h"
#undef private

#include "accesstoken_manager_service.h"
#ifdef IS_SUPPORT_HAP_RUNNING
#include "migration_verify_helper.h"
#include "mock_app_verify_adapter.h"
#endif
#include "data_validator.h"
#include "spm_setproc.h"
#include "table_item.h"
#include "test_common.h"
#include "token_setproc.h"
#include "token_field_const.h"
#include <unistd.h>

using namespace testing::ext;

namespace OHOS {
namespace Security {
namespace AccessToken {
namespace {

// RAII guard that temporarily switches to a non-root UID so that
// IsPrivilegedCalling() returns false and permission checks are enforced.
struct UidGuard {
    uid_t origUid;
    explicit UidGuard(uid_t newUid)
    {
        setuid(newUid);
    }
    ~UidGuard()
    {
        setuid(0);
    }
    UidGuard(const UidGuard&) = delete;
    UidGuard& operator=(const UidGuard&) = delete;
};

constexpr const char* BMS_MIGRATE_COMPLETED = "bms_migrate_completed";
#ifdef IS_SUPPORT_HAP_RUNNING
MockAppVerifyAdapter mockAdapter_;
AppVerifyAdapter resetAdapter_;
#endif

void ClearMigrationCompletedRecord()
{
    GenericValues delValue;
    delValue.Put(TokenFiledConst::FIELD_NAME, BMS_MIGRATE_COMPLETED);
    DelInfo delInfo;
    delInfo.delType = AtmDataType::ACCESSTOKEN_SYSTEM_CONFIG;
    delInfo.delValue = delValue;
    std::vector<DelInfo> delInfoVec = { delInfo };
    std::vector<AddInfo> addInfoVec;
    ASSERT_EQ(RET_SUCCESS, AccessTokenDb::GetInstance()->DeleteAndInsertValues(delInfoVec, addInfoVec));
    
    // Also reset the migration done flag in ID manager for test isolation
    {
        std::unique_lock<std::mutex> lock(AccessTokenIDManager::GetInstance().migrationLock_);
        AccessTokenIDManager::GetInstance().migrationDone_ = false;
    }
}

void CleanupTestDbArtifacts()
{
    // Find all hap info rows — empty condition returns all rows from the table
    GenericValues emptyCondition;
    std::vector<GenericValues> hapResults;
    int32_t ret = AccessTokenDbOperator::Find(AtmDataType::ACCESSTOKEN_HAP_INFO, emptyCondition, hapResults);
    if (ret != RET_SUCCESS) {
        return;
    }

    std::vector<DelInfo> delInfoVec;
    for (const auto& row : hapResults) {
        std::string bundleName = row.GetString(TokenFiledConst::FIELD_BUNDLE_NAME);
        if (bundleName.find("com.example.") == 0) {
            GenericValues delValue;
            delValue.Put(TokenFiledConst::FIELD_TOKEN_ID, row.GetInt(TokenFiledConst::FIELD_TOKEN_ID));
            DelInfo delInfo;
            delInfo.delType = AtmDataType::ACCESSTOKEN_HAP_INFO;
            delInfo.delValue = delValue;
            delInfoVec.emplace_back(delInfo);

            // Also clean up sign info for this bundle
            GenericValues signDelValue;
            signDelValue.Put(TokenFiledConst::FIELD_BUNDLE_NAME, bundleName);
            DelInfo signDelInfo;
            signDelInfo.delType = AtmDataType::ACCESSTOKEN_HAP_PACKAGE_INFO;
            signDelInfo.delValue = signDelValue;
            delInfoVec.emplace_back(signDelInfo);

            // Clean up kernel and cache for stale tokens
            AccessTokenID tokenId = static_cast<AccessTokenID>(row.GetInt(TokenFiledConst::FIELD_TOKEN_ID));
            (void)SpmRemoveEntry(tokenId);
            (void)AccessTokenInfoManager::GetInstance().RemoveHapTokenInfo(tokenId);
        }
    }

    // Also scan HAP_PACKAGE_INFO directly for orphaned sign info rows
    // (e.g. placeholder rows written by PersistMigratedBundles for new tokens).
    std::vector<GenericValues> signResults;
    ret = AccessTokenDbOperator::Find(AtmDataType::ACCESSTOKEN_HAP_PACKAGE_INFO, emptyCondition, signResults);
    if (ret == RET_SUCCESS) {
        for (const auto& row : signResults) {
            std::string bundleName = row.GetString(TokenFiledConst::FIELD_BUNDLE_NAME);
            if (bundleName.find("com.example.") == 0) {
                GenericValues signDelValue;
                signDelValue.Put(TokenFiledConst::FIELD_BUNDLE_NAME, bundleName);
                DelInfo signDelInfo;
                signDelInfo.delType = AtmDataType::ACCESSTOKEN_HAP_PACKAGE_INFO;
                signDelInfo.delValue = signDelValue;
                delInfoVec.emplace_back(signDelInfo);
            }
        }
        std::vector<AddInfo> emptyAdd;
        (void)AccessTokenDbOperator::DeleteAndInsertValues(delInfoVec, emptyAdd);
    }
}

int32_t AllocHapTokenLocally(const HapInfoParams& info, HapPolicyParams& policyParams, AccessTokenIDEx& tokenIdEx)
{
    HapPolicy policy;
    policy.apl = policyParams.apl;
    policy.domain = policyParams.domain;
    policy.permList.assign(policyParams.permList.begin(), policyParams.permList.end());
    policy.aclRequestedList.assign(policyParams.aclRequestedList.begin(), policyParams.aclRequestedList.end());
    for (const auto& perm : policyParams.permStateList) {
        PermissionStatus tmp;
        tmp.permissionName = perm.permissionName;
        tmp.grantStatus = perm.grantStatus.empty() ? PERMISSION_DENIED : perm.grantStatus[0];
        tmp.grantFlag = perm.grantFlags.empty() ? PERMISSION_DEFAULT_FLAG : perm.grantFlags[0];
        tmp.feature = perm.feature;
        policy.permStateList.emplace_back(tmp);
    }
    policy.aclExtendedMap = policyParams.aclExtendedMap;
    std::vector<GenericValues> undefValues;
    return AccessTokenInfoManager::GetInstance().CreateHapTokenInfo(info, policy, tokenIdEx, undefValues);
}

void BuildMigratedInfo(const HapInfoParams& info, uint64_t tokenIdEx, int32_t uid, MigratedInfoIdl& migratedInfo)
{
    migratedInfo.bundleName = info.bundleName;
    migratedInfo.pathList.hapPaths = { info.bundleName };
    migratedInfo.pathList.isPreInstalled = false;
    HapBaseInfoIdl baseInfo;
    baseInfo.bundleName = info.bundleName;
    baseInfo.userID = info.userID;
    baseInfo.instIndex = 0;
    migratedInfo.hapBaseInfoList = { baseInfo };
    migratedInfo.uidList = { uid };
    migratedInfo.reservedTypeList = { ReservedTypeIdl::NONE };
}

void ExpectMigratedDbState(AccessTokenID tokenId, const std::string& bundleName, int32_t uid,
    ReservedType reserved = ReservedType::NONE, bool checkSignInfo = false)
{
    // Ensure all pending verify tasks are completed before checking DB
#ifdef IS_SUPPORT_HAP_RUNNING
    MigrationVerifyWorker::GetInstance().Shutdown();
#endif
    GenericValues hapCondition;
    hapCondition.Put(TokenFiledConst::FIELD_TOKEN_ID, static_cast<int32_t>(tokenId));
    std::vector<GenericValues> hapResults;
    ASSERT_EQ(RET_SUCCESS, AccessTokenDbOperator::Find(
        AtmDataType::ACCESSTOKEN_HAP_INFO, hapCondition, hapResults));
    ASSERT_EQ(1u, hapResults.size());
    EXPECT_EQ(uid, hapResults[0].GetInt(TokenFiledConst::FIELD_UID));
    EXPECT_EQ(static_cast<int32_t>(reserved), hapResults[0].GetInt(TokenFiledConst::FIELD_RESERVED));

#ifdef IS_SUPPORT_HAP_RUNNING
    if (checkSignInfo) {
        GenericValues signCondition;
        signCondition.Put(TokenFiledConst::FIELD_BUNDLE_NAME, bundleName);
        std::vector<GenericValues> signResults;
        ASSERT_EQ(RET_SUCCESS, AccessTokenDbOperator::Find(
            AtmDataType::ACCESSTOKEN_HAP_PACKAGE_INFO, signCondition, signResults));
        ASSERT_FALSE(signResults.empty());
        for (const auto& row : signResults) {
            std::string moduleName = row.GetString(TokenFiledConst::FIELD_MODULE_NAME);
            EXPECT_EQ(moduleName, mockAdapter_.moduleName_);
        }
    }
#endif
}
} // namespace

class MigrateInstalledBundlesServiceTest : public testing::Test {
public:
    static void SetUpTestCase()
    {
        TestCommon::SetTestEvironment(GetSelfTokenID());
        CleanupTestDbArtifacts();
        ClearMigrationCompletedRecord();
#ifdef IS_SUPPORT_HAP_RUNNING
        MigrationVerifyWorker::GetInstance().Shutdown();
        HapSignVerifyManager::GetInstance().adapter_ = &mockAdapter_;
#endif
    }

    static void TearDownTestCase()
    {
#ifdef IS_SUPPORT_HAP_RUNNING
        HapSignVerifyManager::GetInstance().adapter_ = &resetAdapter_;
#endif
        CleanupTestDbArtifacts();
        ClearMigrationCompletedRecord();
    }

    void SetUp() override
    {
        CleanupTestDbArtifacts();
        ClearMigrationCompletedRecord();
#ifdef IS_SUPPORT_HAP_RUNNING
        MigrationVerifyWorker::GetInstance().Shutdown();
#endif
    }

    void TearDown() override
    {
        ClearMigrationCompletedRecord();
    }
};

// =============================================================================
// PreMigrateUIDList — one spec per test
// =============================================================================

/**
 * @tc.name: PreMigrateUIDList_EmptyList
 * @tc.desc: Empty uidList returns ERR_PARAM_INVALID.
 * @tc.type: FUNC
 */
HWTEST_F(MigrateInstalledBundlesServiceTest, PreMigrateUIDList_EmptyList, TestSize.Level1)
{
    MockNativeToken mock("foundation");
    auto service = DelayedSingleton<AccessTokenManagerService>::GetInstance();
    ASSERT_NE(nullptr, service);
    EXPECT_EQ(AccessTokenError::ERR_PARAM_INVALID, service->PreMigrateUIDList({}));
}

/**
 * @tc.name: PreMigrateUIDList_DuplicateUids
 * @tc.desc: Duplicate UIDs in a single PreMigrateUIDList call return ERR_MIGRATION_UID_DUPLICATED.
 * @tc.type: FUNC
 */
HWTEST_F(MigrateInstalledBundlesServiceTest, PreMigrateUIDList_DuplicateUids, TestSize.Level1)
{
    MockNativeToken mock("foundation");
    auto service = DelayedSingleton<AccessTokenManagerService>::GetInstance();
    ASSERT_NE(nullptr, service);
    EXPECT_EQ(AccessTokenError::ERR_MIGRATION_UID_DUPLICATED, service->PreMigrateUIDList({ 200100, 200100 }));
}

/**
 * @tc.name: PreMigrateUIDList_DbUidConflict
 * @tc.desc: PreMigrateUIDList returns ERR_MIGRATION_UID_DUPLICATED when a UID already exists in the DB.
 * @tc.type: FUNC
 */
HWTEST_F(MigrateInstalledBundlesServiceTest, PreMigrateUIDList_DbUidConflict, TestSize.Level1)
{
    MockNativeToken mock("foundation");

    // Insert a row with UID 0 into ACCESSTOKEN_HAP_INFO to trigger DB conflict
    HapTokenInfoItem item;
    item.tokenId = 99999;
    item.bundleName = "com.example.uidconflict";
    item.uid = 0;
    std::vector<GenericValues> hapValues;
    item.BuildAddValue(hapValues);
    AddInfo addInfo;
    addInfo.addType = AtmDataType::ACCESSTOKEN_HAP_INFO;
    addInfo.addValues = hapValues;
    ASSERT_EQ(RET_SUCCESS, AccessTokenDbOperator::DeleteAndInsertValues({}, { addInfo }));

    auto service = DelayedSingleton<AccessTokenManagerService>::GetInstance();
    ASSERT_NE(nullptr, service);
    EXPECT_EQ(AccessTokenError::ERR_MIGRATION_UID_DUPLICATED,
        service->PreMigrateUIDList({ 0 }));
}

/**
 * @tc.name: PreMigrateUIDList_AfterFinishMigration
 * @tc.desc: PreMigrateUIDList returns ERR_MIGRATION_COMPLETED after FinishMigration.
 * @tc.type: FUNC
 */
HWTEST_F(MigrateInstalledBundlesServiceTest, PreMigrateUIDList_AfterFinishMigration, TestSize.Level1)
{
    MockNativeToken mock("foundation");
    auto service = DelayedSingleton<AccessTokenManagerService>::GetInstance();
    ASSERT_NE(nullptr, service);
    ASSERT_EQ(RET_SUCCESS, service->FinishMigration());
    EXPECT_EQ(AccessTokenError::ERR_MIGRATION_COMPLETED, service->PreMigrateUIDList({ 200101 }));
}

// =============================================================================
// MigrateInstalledBundles — top-level checks (return value)
// =============================================================================

/**
 * @tc.name: MigrateInstalledBundles_ExceedsMaxSize
 * @tc.desc: List exceeding MAX_MIGRATED_INFO_SIZE (50) returns ERR_PARAM_INVALID from MigrateInstalledBundles.
 * @tc.type: FUNC
 */
HWTEST_F(MigrateInstalledBundlesServiceTest, MigrateInstalledBundles_ExceedsMaxSize, TestSize.Level1)
{
    MockNativeToken mock("foundation");
    auto service = DelayedSingleton<AccessTokenManagerService>::GetInstance();
    ASSERT_NE(nullptr, service);

    MigratedInfoIdl item;
    item.bundleName = "com.example.test";
    std::vector<MigratedInfoIdl> largeList(51, item);
    std::vector<BundleMigrateResultIdl> results;
    EXPECT_EQ(AccessTokenError::ERR_PARAM_INVALID,
        service->MigrateInstalledBundles(largeList, results));
    EXPECT_TRUE(results.empty());
}

/**
 * @tc.name: MigrateInstalledBundles_AfterFinishMigration
 * @tc.desc: MigrateInstalledBundles returns ERR_MIGRATION_COMPLETED after FinishMigration.
 * @tc.type: FUNC
 */
HWTEST_F(MigrateInstalledBundlesServiceTest, MigrateInstalledBundles_AfterFinishMigration, TestSize.Level1)
{
    MockNativeToken mock("foundation");
    auto service = DelayedSingleton<AccessTokenManagerService>::GetInstance();
    ASSERT_NE(nullptr, service);
    ASSERT_EQ(RET_SUCCESS, service->FinishMigration());

    MigratedInfoIdl migratedInfo;
    migratedInfo.bundleName = "com.example.test";
    std::vector<BundleMigrateResultIdl> results;
    EXPECT_EQ(AccessTokenError::ERR_MIGRATION_COMPLETED,
        service->MigrateInstalledBundles({ migratedInfo }, results));
    EXPECT_TRUE(results.empty());
}

/**
 * @tc.name: MigrateInstalledBundles_UidNotPreRegistered
 * @tc.desc: MigrateInstalledBundles returns ERR_PARAM_INVALID per-item when UID was not registered
 *           via PreMigrateUIDList.
 * @tc.type: FUNC
 */
HWTEST_F(MigrateInstalledBundlesServiceTest, MigrateInstalledBundles_UidNotPreRegistered, TestSize.Level1)
{
    MockNativeToken mock("foundation");

    HapInfoParams info = TestCommon::GetInfoManagerTestSystemInfoParms();
    info.bundleName = "com.example.noreg";
    info.appIDDesc = info.bundleName;

    HapBaseInfoIdl baseInfo;
    baseInfo.bundleName = info.bundleName;
    baseInfo.userID = info.userID;
    baseInfo.instIndex = 0;

    MigratedInfoIdl migratedInfo;
    migratedInfo.bundleName = info.bundleName;
    migratedInfo.pathList.hapPaths = { info.bundleName };
    migratedInfo.hapBaseInfoList = { baseInfo };
    migratedInfo.uidList = { 203001 };
    migratedInfo.reservedTypeList = { ReservedTypeIdl::NONE };

    auto service = DelayedSingleton<AccessTokenManagerService>::GetInstance();
    ASSERT_NE(nullptr, service);
    // NOTE: PreMigrateUIDList is NOT called — UID 203001 is not in the cached set.
    std::vector<BundleMigrateResultIdl> results;
    EXPECT_EQ(RET_SUCCESS, service->MigrateInstalledBundles({ migratedInfo }, results));
    ASSERT_EQ(1u, results.size());
    EXPECT_EQ(AccessTokenError::ERR_PARAM_INVALID, results[0].errcode);
}

// =============================================================================
// MigrateInstalledBundles — per-item validation: invalid shape (errParamInvalid)
// =============================================================================

/**
 * @tc.name: MigrateInstalledBundles_InvalidBundleName
 * @tc.desc: Bundle name too long fails IsBundleNameValid, per-item ERR_PARAM_INVALID.
 * @tc.type: FUNC
 */
HWTEST_F(MigrateInstalledBundlesServiceTest, MigrateInstalledBundles_InvalidBundleName, TestSize.Level1)
{
    MockNativeToken mock("foundation");
    auto service = DelayedSingleton<AccessTokenManagerService>::GetInstance();
    ASSERT_NE(nullptr, service);
    std::string nameTooLong(300, 'x');
    MigratedInfoIdl migratedInfo;
    migratedInfo.bundleName = nameTooLong;
    std::vector<BundleMigrateResultIdl> results;
    EXPECT_EQ(RET_SUCCESS, service->MigrateInstalledBundles({ migratedInfo }, results));
    ASSERT_EQ(1u, results.size());
    EXPECT_EQ(AccessTokenError::ERR_PARAM_INVALID, results[0].errcode);
}

/**
 * @tc.name: MigrateInstalledBundles_UidListSizeMismatch
 * @tc.desc: uidList.size() != hapBaseInfoList.size() fails IsMigratedInfoShapeValid.
 * @tc.type: FUNC
 */
HWTEST_F(MigrateInstalledBundlesServiceTest, MigrateInstalledBundles_UidListSizeMismatch, TestSize.Level1)
{
    MockNativeToken mock("foundation");

    HapInfoParams info = TestCommon::GetInfoManagerTestSystemInfoParms();
    info.bundleName = "com.example.uidmismatch";
    info.appIDDesc = info.bundleName;

    HapBaseInfoIdl baseInfo;
    baseInfo.bundleName = info.bundleName;
    baseInfo.userID = info.userID;
    baseInfo.instIndex = 0;

    MigratedInfoIdl migratedInfo;
    migratedInfo.bundleName = info.bundleName;
    migratedInfo.pathList.hapPaths = { info.bundleName };
    migratedInfo.hapBaseInfoList = { baseInfo, baseInfo }; // size 2
    migratedInfo.uidList = { 200201 };                     // size 1 — mismatch
    migratedInfo.reservedTypeList = { ReservedTypeIdl::NONE, ReservedTypeIdl::NONE };

    auto service = DelayedSingleton<AccessTokenManagerService>::GetInstance();
    ASSERT_NE(nullptr, service);
    std::vector<BundleMigrateResultIdl> results;
    EXPECT_EQ(RET_SUCCESS, service->MigrateInstalledBundles({ migratedInfo }, results));
    ASSERT_EQ(1u, results.size());
    EXPECT_EQ(AccessTokenError::ERR_PARAM_INVALID, results[0].errcode);
}

/**
 * @tc.name: MigrateInstalledBundles_ReservedTypeListSizeMismatch
 * @tc.desc: reservedTypeList.size() != hapBaseInfoList.size() fails IsMigratedInfoShapeValid.
 * @tc.type: FUNC
 */
HWTEST_F(MigrateInstalledBundlesServiceTest, MigrateInstalledBundles_ReservedTypeListSizeMismatch, TestSize.Level1)
{
    MockNativeToken mock("foundation");

    HapInfoParams info = TestCommon::GetInfoManagerTestSystemInfoParms();
    info.bundleName = "com.example.rsvmismatch";
    info.appIDDesc = info.bundleName;

    HapBaseInfoIdl baseInfo;
    baseInfo.bundleName = info.bundleName;
    baseInfo.userID = info.userID;
    baseInfo.instIndex = 0;

    MigratedInfoIdl migratedInfo;
    migratedInfo.bundleName = info.bundleName;
    migratedInfo.pathList.hapPaths = { info.bundleName };
    migratedInfo.hapBaseInfoList = { baseInfo, baseInfo }; // size 2
    migratedInfo.uidList = { 200301, 200302 };             // size 2
    migratedInfo.reservedTypeList = { ReservedTypeIdl::NONE }; // size 1 — mismatch

    auto service = DelayedSingleton<AccessTokenManagerService>::GetInstance();
    ASSERT_NE(nullptr, service);
    std::vector<BundleMigrateResultIdl> results;
    EXPECT_EQ(RET_SUCCESS, service->MigrateInstalledBundles({ migratedInfo }, results));
    ASSERT_EQ(1u, results.size());
    EXPECT_EQ(AccessTokenError::ERR_PARAM_INVALID, results[0].errcode);
}

/**
 * @tc.name: MigrateInstalledBundles_InvalidReservedType
 * @tc.desc: A reserved type value not in {NONE, RESERVED_IDENTITY, RESERVED_DATA} fails validation.
 * @tc.type: FUNC
 */
HWTEST_F(MigrateInstalledBundlesServiceTest, MigrateInstalledBundles_InvalidReservedType, TestSize.Level1)
{
    MockNativeToken mock("foundation");

    HapInfoParams info = TestCommon::GetInfoManagerTestSystemInfoParms();
    info.bundleName = "com.example.badreserved";
    info.appIDDesc = info.bundleName;

    HapBaseInfoIdl baseInfo;
    baseInfo.bundleName = info.bundleName;
    baseInfo.userID = info.userID;
    baseInfo.instIndex = 0;

    MigratedInfoIdl migratedInfo;
    migratedInfo.bundleName = info.bundleName;
    migratedInfo.pathList.hapPaths = { info.bundleName };
    migratedInfo.hapBaseInfoList = { baseInfo };
    migratedInfo.uidList = { 200401 };
    migratedInfo.reservedTypeList = { static_cast<ReservedTypeIdl>(999) };

    auto service = DelayedSingleton<AccessTokenManagerService>::GetInstance();
    ASSERT_NE(nullptr, service);
    std::vector<BundleMigrateResultIdl> results;
    EXPECT_EQ(RET_SUCCESS, service->MigrateInstalledBundles({ migratedInfo }, results));
    ASSERT_EQ(1u, results.size());
    EXPECT_EQ(AccessTokenError::ERR_PARAM_INVALID, results[0].errcode);
}

// =============================================================================
// MigrateInstalledBundles — per-item validation: HapBaseInfo basic fields
// =============================================================================

/**
 * @tc.name: MigrateInstalledBundles_NegativeUserID
 * @tc.desc: hapBaseInfo.userID < 0 fails CheckHapBaseInfoBasic.
 * @tc.type: FUNC
 */
HWTEST_F(MigrateInstalledBundlesServiceTest, MigrateInstalledBundles_NegativeUserID, TestSize.Level1)
{
    MockNativeToken mock("foundation");

    HapInfoParams info = TestCommon::GetInfoManagerTestSystemInfoParms();
    info.bundleName = "com.example.neguser";
    info.appIDDesc = info.bundleName;

    HapBaseInfoIdl baseInfo;
    baseInfo.bundleName = info.bundleName;
    baseInfo.userID = -1;
    baseInfo.instIndex = 0;

    MigratedInfoIdl migratedInfo;
    migratedInfo.bundleName = info.bundleName;
    migratedInfo.pathList.hapPaths = { info.bundleName };
    migratedInfo.hapBaseInfoList = { baseInfo };
    migratedInfo.uidList = { 200501 };
    migratedInfo.reservedTypeList = { ReservedTypeIdl::NONE };

    auto service = DelayedSingleton<AccessTokenManagerService>::GetInstance();
    ASSERT_NE(nullptr, service);
    std::vector<BundleMigrateResultIdl> results;
    EXPECT_EQ(RET_SUCCESS, service->MigrateInstalledBundles({ migratedInfo }, results));
    ASSERT_EQ(1u, results.size());
    EXPECT_EQ(AccessTokenError::ERR_PARAM_INVALID, results[0].errcode);
}

/**
 * @tc.name: MigrateInstalledBundles_InvalidHapBundleName
 * @tc.desc: hapBaseInfo.bundleName too long fails CheckHapBaseInfoBasic.
 * @tc.type: FUNC
 */
HWTEST_F(MigrateInstalledBundlesServiceTest, MigrateInstalledBundles_InvalidHapBundleName, TestSize.Level1)
{
    MockNativeToken mock("foundation");

    HapInfoParams info = TestCommon::GetInfoManagerTestSystemInfoParms();
    info.bundleName = "com.example.parent";
    info.appIDDesc = info.bundleName;

    std::string nameTooLong(300, 'x');
    HapBaseInfoIdl baseInfo;
    baseInfo.bundleName = nameTooLong;
    baseInfo.userID = info.userID;
    baseInfo.instIndex = 0;

    MigratedInfoIdl migratedInfo;
    migratedInfo.bundleName = info.bundleName;
    migratedInfo.pathList.hapPaths = { info.bundleName };
    migratedInfo.hapBaseInfoList = { baseInfo };
    migratedInfo.uidList = { 200601 };
    migratedInfo.reservedTypeList = { ReservedTypeIdl::NONE };

    auto service = DelayedSingleton<AccessTokenManagerService>::GetInstance();
    ASSERT_NE(nullptr, service);
    std::vector<BundleMigrateResultIdl> results;
    EXPECT_EQ(RET_SUCCESS, service->MigrateInstalledBundles({ migratedInfo }, results));
    ASSERT_EQ(1u, results.size());
    EXPECT_EQ(AccessTokenError::ERR_PARAM_INVALID, results[0].errcode);
}

/**
 * @tc.name: MigrateInstalledBundles_NegativeInstIndex
 * @tc.desc: hapBaseInfo.instIndex < 0 fails CheckHapBaseInfoBasic.
 * @tc.type: FUNC
 */
HWTEST_F(MigrateInstalledBundlesServiceTest, MigrateInstalledBundles_NegativeInstIndex, TestSize.Level1)
{
    MockNativeToken mock("foundation");

    HapInfoParams info = TestCommon::GetInfoManagerTestSystemInfoParms();
    info.bundleName = "com.example.negindex";
    info.appIDDesc = info.bundleName;

    HapBaseInfoIdl baseInfo;
    baseInfo.bundleName = info.bundleName;
    baseInfo.userID = info.userID;
    baseInfo.instIndex = -1;

    MigratedInfoIdl migratedInfo;
    migratedInfo.bundleName = info.bundleName;
    migratedInfo.pathList.hapPaths = { info.bundleName };
    migratedInfo.hapBaseInfoList = { baseInfo };
    migratedInfo.uidList = { 200701 };
    migratedInfo.reservedTypeList = { ReservedTypeIdl::NONE };

    auto service = DelayedSingleton<AccessTokenManagerService>::GetInstance();
    ASSERT_NE(nullptr, service);
    std::vector<BundleMigrateResultIdl> results;
    EXPECT_EQ(RET_SUCCESS, service->MigrateInstalledBundles({ migratedInfo }, results));
    ASSERT_EQ(1u, results.size());
    EXPECT_EQ(AccessTokenError::ERR_PARAM_INVALID, results[0].errcode);
}

// =============================================================================
// MigrateInstalledBundles — per-item validation: identity collection
// =============================================================================

/**
 * @tc.name: MigrateInstalledBundles_HapBundleNameMismatch
 * @tc.desc: hapBaseInfo.bundleName != migratedInfo.bundleName fails ValidateAndCollectIdentityInfos.
 * @tc.type: FUNC
 */
HWTEST_F(MigrateInstalledBundlesServiceTest, MigrateInstalledBundles_HapBundleNameMismatch, TestSize.Level1)
{
    MockNativeToken mock("foundation");

    HapInfoParams info = TestCommon::GetInfoManagerTestSystemInfoParms();
    info.bundleName = "com.example.parentbundle";
    info.appIDDesc = info.bundleName;

    HapBaseInfoIdl baseInfo;
    baseInfo.bundleName = "com.example.different";
    baseInfo.userID = info.userID;
    baseInfo.instIndex = 0;

    MigratedInfoIdl migratedInfo;
    migratedInfo.bundleName = info.bundleName;
    migratedInfo.pathList.hapPaths = { info.bundleName };
    migratedInfo.hapBaseInfoList = { baseInfo };
    migratedInfo.uidList = { 200801 };
    migratedInfo.reservedTypeList = { ReservedTypeIdl::NONE };

    auto service = DelayedSingleton<AccessTokenManagerService>::GetInstance();
    ASSERT_NE(nullptr, service);
    std::vector<BundleMigrateResultIdl> results;
    EXPECT_EQ(RET_SUCCESS, service->MigrateInstalledBundles({ migratedInfo }, results));
    ASSERT_EQ(1u, results.size());
    EXPECT_EQ(AccessTokenError::ERR_PARAM_INVALID, results[0].errcode);
}

/**
 * @tc.name: MigrateInstalledBundles_DuplicateUidInBundle
 * @tc.desc: Duplicate UID within a single bundle request returns ERR_MIGRATION_UID_DUPLICATED per-item.
 * @tc.type: FUNC
 */
HWTEST_F(MigrateInstalledBundlesServiceTest, MigrateInstalledBundles_DuplicateUidInBundle, TestSize.Level1)
{
    MockNativeToken mock("foundation");

    HapInfoParams info = TestCommon::GetInfoManagerTestSystemInfoParms();
    info.bundleName = "com.example.dupuid";
    info.appIDDesc = info.bundleName;

    HapBaseInfoIdl baseInfo0;
    baseInfo0.bundleName = info.bundleName;
    baseInfo0.userID = info.userID;
    baseInfo0.instIndex = 0;

    HapBaseInfoIdl baseInfo1;
    baseInfo1.bundleName = info.bundleName;
    baseInfo1.userID = info.userID;
    baseInfo1.instIndex = 1;

    MigratedInfoIdl migratedInfo;
    migratedInfo.bundleName = info.bundleName;
    migratedInfo.pathList.hapPaths = { info.bundleName };
    migratedInfo.hapBaseInfoList = { baseInfo0, baseInfo1 };
    migratedInfo.uidList = { 200901, 200901 }; // duplicate
    migratedInfo.reservedTypeList = { ReservedTypeIdl::NONE, ReservedTypeIdl::NONE };

    auto service = DelayedSingleton<AccessTokenManagerService>::GetInstance();
    ASSERT_NE(nullptr, service);
    ASSERT_EQ(RET_SUCCESS, service->PreMigrateUIDList({ 200901 }));
    std::vector<BundleMigrateResultIdl> results;
    EXPECT_EQ(RET_SUCCESS, service->MigrateInstalledBundles({ migratedInfo }, results));
    ASSERT_EQ(1u, results.size());
    EXPECT_EQ(AccessTokenError::ERR_MIGRATION_UID_DUPLICATED, results[0].errcode);
}

/**
 * @tc.name: MigrateInstalledBundles_CachedUidDiffers
 * @tc.desc: Existing token with cached UID different from migration UID fails per-item.
 * @tc.type: FUNC
 */
HWTEST_F(MigrateInstalledBundlesServiceTest, MigrateInstalledBundles_CachedUidDiffers, TestSize.Level1)
{
    MockNativeToken mock("foundation");

    HapInfoParams info = TestCommon::GetInfoManagerTestSystemInfoParms();
    info.bundleName = "com.example.cacheduid";
    info.appIDDesc = info.bundleName;
    HapPolicyParams policy = TestCommon::GetTestPolicyParams();

    AccessTokenIDEx tokenIdEx = {0};
    ASSERT_EQ(RET_SUCCESS, AllocHapTokenLocally(info, policy, tokenIdEx));

    auto infoPtr = AccessTokenInfoManager::GetInstance().GetHapTokenInfoInner(tokenIdEx.tokenIdExStruct.tokenID);
    ASSERT_NE(nullptr, infoPtr);
    infoPtr->SetUid(201001); // set a valid UID different from migration UID

    MigratedInfoIdl migratedInfo;
    BuildMigratedInfo(info, tokenIdEx.tokenIDEx, 201002, migratedInfo);

    auto service = DelayedSingleton<AccessTokenManagerService>::GetInstance();
    ASSERT_NE(nullptr, service);
    EXPECT_EQ(RET_SUCCESS, service->PreMigrateUIDList({ migratedInfo.uidList[0] }));
    std::vector<BundleMigrateResultIdl> results;
    EXPECT_EQ(RET_SUCCESS, service->MigrateInstalledBundles({ migratedInfo }, results));
    ASSERT_EQ(1u, results.size());
    EXPECT_EQ(AccessTokenError::ERR_MIGRATION_UID_EXISTED, results[0].errcode);
    // Original UID must be preserved on failure
    EXPECT_EQ(201001u, infoPtr->GetUid());

    EXPECT_EQ(RET_SUCCESS, AccessTokenInfoManager::GetInstance().RemoveHapTokenInfo(tokenIdEx.tokenIdExStruct.tokenID));
}

// =============================================================================
// MigrateInstalledBundles — successful migration paths
// =============================================================================

/**
 * @tc.name: MigrateInstalledBundles_BasicSuccess
 * @tc.desc: Basic migration succeeds: UID updated in cache, DB reflects migrated uid and ReservedType::NONE.
 * @tc.type: FUNC
 */
HWTEST_F(MigrateInstalledBundlesServiceTest, MigrateInstalledBundles_BasicSuccess, TestSize.Level1)
{
    MockNativeToken mock("foundation");

    HapInfoParams info = TestCommon::GetInfoManagerTestSystemInfoParms();
    info.bundleName = "com.example.basic";
    info.appIDDesc = info.bundleName;
    HapPolicyParams policy = TestCommon::GetTestPolicyParams();

    AccessTokenIDEx tokenIdEx = {0};
    ASSERT_EQ(RET_SUCCESS, AllocHapTokenLocally(info, policy, tokenIdEx));

    MigratedInfoIdl migratedInfo;
    BuildMigratedInfo(info, tokenIdEx.tokenIDEx, 201101, migratedInfo);

    auto service = DelayedSingleton<AccessTokenManagerService>::GetInstance();
    ASSERT_NE(nullptr, service);
    EXPECT_EQ(RET_SUCCESS, service->PreMigrateUIDList({ migratedInfo.uidList[0] }));
    std::vector<BundleMigrateResultIdl> results;
    EXPECT_EQ(RET_SUCCESS, service->MigrateInstalledBundles({ migratedInfo }, results));
    ASSERT_EQ(1u, results.size());
    EXPECT_EQ(RET_SUCCESS, results[0].errcode);
    ASSERT_EQ(1u, results[0].tokenIdList.size());
    EXPECT_EQ(tokenIdEx.tokenIDEx, results[0].tokenIdList[0]);
    ASSERT_EQ(1u, results[0].reservedTypeList.size());
    EXPECT_EQ(ReservedTypeIdl::NONE, results[0].reservedTypeList[0]);

    // Verify cache reflects migrated UID
    auto infoPtr = AccessTokenInfoManager::GetInstance().GetHapTokenInfoInner(tokenIdEx.tokenIdExStruct.tokenID);
    ASSERT_NE(nullptr, infoPtr);
    EXPECT_EQ(static_cast<uint32_t>(migratedInfo.uidList[0]), infoPtr->GetUid());
    // Verify DB state
    ExpectMigratedDbState(tokenIdEx.tokenIdExStruct.tokenID, info.bundleName, migratedInfo.uidList[0]);

    (void)SpmRemoveEntry(tokenIdEx.tokenIdExStruct.tokenID);
    EXPECT_EQ(RET_SUCCESS, AccessTokenInfoManager::GetInstance().RemoveHapTokenInfo(tokenIdEx.tokenIdExStruct.tokenID));
}

/**
 * @tc.name: MigrateInstalledBundles_PreInstalledReservedIdentity
 * @tc.desc: Pre-installed app with RESERVED_IDENTITY: DB shows reserved=RESERVED_IDENTITY.
 * @tc.type: FUNC
 */
HWTEST_F(MigrateInstalledBundlesServiceTest, MigrateInstalledBundles_PreInstalledReservedIdentity, TestSize.Level1)
{
    MockNativeToken mock("foundation");

    HapInfoParams info = TestCommon::GetInfoManagerTestSystemInfoParms();
    info.bundleName = "com.example.preinstall";
    info.appIDDesc = info.bundleName;
    HapPolicyParams policy = TestCommon::GetTestPolicyParams();

    AccessTokenIDEx tokenIdEx = {0};
    ASSERT_EQ(RET_SUCCESS, AllocHapTokenLocally(info, policy, tokenIdEx));

    MigratedInfoIdl migratedInfo;
    BuildMigratedInfo(info, tokenIdEx.tokenIDEx, 201201, migratedInfo);
    migratedInfo.pathList.isPreInstalled = true;
    migratedInfo.reservedTypeList = { ReservedTypeIdl::RESERVED_IDENTITY };

    auto service = DelayedSingleton<AccessTokenManagerService>::GetInstance();
    ASSERT_NE(nullptr, service);
    EXPECT_EQ(RET_SUCCESS, service->PreMigrateUIDList({ migratedInfo.uidList[0] }));
    std::vector<BundleMigrateResultIdl> results;
    EXPECT_EQ(RET_SUCCESS, service->MigrateInstalledBundles({ migratedInfo }, results));
    ASSERT_EQ(1u, results.size());
    EXPECT_EQ(RET_SUCCESS, results[0].errcode);
    ASSERT_EQ(1u, results[0].reservedTypeList.size());
    EXPECT_EQ(ReservedTypeIdl::RESERVED_IDENTITY, results[0].reservedTypeList[0]);
    ExpectMigratedDbState(tokenIdEx.tokenIdExStruct.tokenID, info.bundleName, migratedInfo.uidList[0],
        ReservedType::RESERVED_IDENTITY);

    (void)SpmRemoveEntry(tokenIdEx.tokenIdExStruct.tokenID);
    EXPECT_EQ(RET_SUCCESS, AccessTokenInfoManager::GetInstance().RemoveHapTokenInfo(tokenIdEx.tokenIdExStruct.tokenID));
}

/**
 * @tc.name: MigrateInstalledBundles_NewToken
 * @tc.desc: Token does not exist in DB → creates new token with RESERVED_DATA, placeholder DB row with correct UID.
 * @tc.type: FUNC
 */
HWTEST_F(MigrateInstalledBundlesServiceTest, MigrateInstalledBundles_NewToken, TestSize.Level1)
{
    MockNativeToken mock("foundation");

    HapInfoParams info = TestCommon::GetInfoManagerTestSystemInfoParms();
    info.bundleName = "com.example.newtoken2";
    info.appIDDesc = info.bundleName;

    HapBaseInfoIdl baseInfo;
    baseInfo.bundleName = info.bundleName;
    baseInfo.userID = info.userID;
    baseInfo.instIndex = 0;

    MigratedInfoIdl migratedInfo;
    migratedInfo.bundleName = info.bundleName;
    migratedInfo.pathList.hapPaths = { info.bundleName };
    migratedInfo.pathList.isPreInstalled = false;
    migratedInfo.hapBaseInfoList = { baseInfo };
    migratedInfo.uidList = { 201301 };
    migratedInfo.reservedTypeList = { ReservedTypeIdl::NONE };

    auto service = DelayedSingleton<AccessTokenManagerService>::GetInstance();
    ASSERT_NE(nullptr, service);
    EXPECT_EQ(RET_SUCCESS, service->PreMigrateUIDList({ migratedInfo.uidList[0] }));
    std::vector<BundleMigrateResultIdl> results;
    EXPECT_EQ(RET_SUCCESS, service->MigrateInstalledBundles({ migratedInfo }, results));
    ASSERT_EQ(1u, results.size());
    EXPECT_EQ(RET_SUCCESS, results[0].errcode);
    ASSERT_EQ(1u, results[0].tokenIdList.size());
    EXPECT_NE(0u, results[0].tokenIdList[0]);
    ASSERT_EQ(1u, results[0].reservedTypeList.size());
    EXPECT_EQ(ReservedTypeIdl::RESERVED_DATA, results[0].reservedTypeList[0]);

    // Verify placeholder DB row exists with correct UID
    GenericValues hapCondition;
    hapCondition.Put(TokenFiledConst::FIELD_TOKEN_ID,
        static_cast<int32_t>(results[0].tokenIdList[0]));
    std::vector<GenericValues> hapResults;
    ASSERT_EQ(RET_SUCCESS, AccessTokenDbOperator::Find(
        AtmDataType::ACCESSTOKEN_HAP_INFO, hapCondition, hapResults));
    ASSERT_EQ(1u, hapResults.size());
    EXPECT_EQ(migratedInfo.uidList[0], hapResults[0].GetInt(TokenFiledConst::FIELD_UID));

    (void)SpmRemoveEntry(results[0].tokenIdList[0]);

    // Remove placeholder DB row — RemoveHapTokenInfo alone may not clean migration-created tokens
    GenericValues delValue;
    delValue.Put(TokenFiledConst::FIELD_TOKEN_ID,
        static_cast<int32_t>(results[0].tokenIdList[0]));
    DelInfo delInfo;
    delInfo.delType = AtmDataType::ACCESSTOKEN_HAP_INFO;
    delInfo.delValue = delValue;
    (void)AccessTokenDbOperator::DeleteAndInsertValues({delInfo}, {});
    (void)AccessTokenInfoManager::GetInstance().RemoveHapTokenInfo(results[0].tokenIdList[0]);
}

/**
 * @tc.name: MigrateInstalledBundles_BatchMixedValidity
 * @tc.desc: Batch migration — bad bundle fails per-item, valid bundle succeeds independently.
 * @tc.type: FUNC
 */
HWTEST_F(MigrateInstalledBundlesServiceTest, MigrateInstalledBundles_BatchMixedValidity, TestSize.Level1)
{
    MockNativeToken mock("foundation");

    HapInfoParams info = TestCommon::GetInfoManagerTestSystemInfoParms();
    info.bundleName = "com.example.batch";
    info.appIDDesc = info.bundleName;
    HapPolicyParams policy = TestCommon::GetTestPolicyParams();

    AccessTokenIDEx tokenIdEx = {0};
    ASSERT_EQ(RET_SUCCESS, AllocHapTokenLocally(info, policy, tokenIdEx));

    MigratedInfoIdl invalidInfo;
    invalidInfo.bundleName = "bad bundle name";

    MigratedInfoIdl validInfo;
    BuildMigratedInfo(info, tokenIdEx.tokenIDEx, 201401, validInfo);

    auto service = DelayedSingleton<AccessTokenManagerService>::GetInstance();
    ASSERT_NE(nullptr, service);
    EXPECT_EQ(RET_SUCCESS, service->PreMigrateUIDList({ validInfo.uidList[0] }));

    std::vector<BundleMigrateResultIdl> results;
    EXPECT_EQ(RET_SUCCESS, service->MigrateInstalledBundles({ invalidInfo, validInfo }, results));
    ASSERT_EQ(2u, results.size());
    EXPECT_EQ(AccessTokenError::ERR_PARAM_INVALID, results[0].errcode);
    EXPECT_EQ(RET_SUCCESS, results[1].errcode);
    ASSERT_EQ(1u, results[1].tokenIdList.size());
    EXPECT_EQ(tokenIdEx.tokenIDEx, results[1].tokenIdList[0]);

    // Valid bundle should have its UID and DB updated
    auto infoPtr = AccessTokenInfoManager::GetInstance().GetHapTokenInfoInner(tokenIdEx.tokenIdExStruct.tokenID);
    ASSERT_NE(nullptr, infoPtr);
    EXPECT_EQ(static_cast<uint32_t>(validInfo.uidList[0]), infoPtr->GetUid());
    ExpectMigratedDbState(tokenIdEx.tokenIdExStruct.tokenID, info.bundleName, validInfo.uidList[0]);

    (void)SpmRemoveEntry(tokenIdEx.tokenIdExStruct.tokenID);
    EXPECT_EQ(RET_SUCCESS, AccessTokenInfoManager::GetInstance().RemoveHapTokenInfo(tokenIdEx.tokenIdExStruct.tokenID));
}

// =============================================================================
// MigrateInstalledBundles — UID cache lifecycle (PreMigrateUIDList ↔ MigrateInstalledBundles)
// =============================================================================

/**
 * @tc.name: MigrateInstalledBundles_UidConsumedAfterSuccess
 * @tc.desc: After a successful migration, the UID is removed from the PreMigrateUIDList cache.
 *          A second migration attempt with the same UID without re-registration fails.
 * @tc.type: FUNC
 */
HWTEST_F(MigrateInstalledBundlesServiceTest, MigrateInstalledBundles_UidConsumedAfterSuccess, TestSize.Level1)
{
    MockNativeToken mock("foundation");

    HapInfoParams info = TestCommon::GetInfoManagerTestSystemInfoParms();
    info.bundleName = "com.example.consumed";
    info.appIDDesc = info.bundleName;
    HapPolicyParams policy = TestCommon::GetTestPolicyParams();

    AccessTokenIDEx tokenIdEx = {0};
    ASSERT_EQ(RET_SUCCESS, AllocHapTokenLocally(info, policy, tokenIdEx));

    MigratedInfoIdl migratedInfo;
    BuildMigratedInfo(info, tokenIdEx.tokenIDEx, 203101, migratedInfo);

    auto service = DelayedSingleton<AccessTokenManagerService>::GetInstance();
    ASSERT_NE(nullptr, service);
    EXPECT_EQ(RET_SUCCESS, service->PreMigrateUIDList({ migratedInfo.uidList[0] }));

    // First migration succeeds — UID is consumed
    std::vector<BundleMigrateResultIdl> results;
    EXPECT_EQ(RET_SUCCESS, service->MigrateInstalledBundles({ migratedInfo }, results));
    ASSERT_EQ(1u, results.size());
    EXPECT_EQ(RET_SUCCESS, results[0].errcode);

    // Second migration with same UID must fail — UID no longer in cache
    std::vector<BundleMigrateResultIdl> results2;
    EXPECT_EQ(RET_SUCCESS, service->MigrateInstalledBundles({ migratedInfo }, results2));
    ASSERT_EQ(1u, results2.size());
    EXPECT_EQ(AccessTokenError::ERR_PARAM_INVALID, results2[0].errcode);

    (void)SpmRemoveEntry(tokenIdEx.tokenIdExStruct.tokenID);
    EXPECT_EQ(RET_SUCCESS, AccessTokenInfoManager::GetInstance().RemoveHapTokenInfo(tokenIdEx.tokenIdExStruct.tokenID));
}

/**
 * @tc.name: MigrateInstalledBundles_UidRetainedAfterFailure
 * @tc.desc: After a failed migration, the UID remains in the PreMigrateUIDList cache.
 *          A retry without re-registration succeeds.
 * @tc.type: FUNC
 */
HWTEST_F(MigrateInstalledBundlesServiceTest, MigrateInstalledBundles_UidRetainedAfterFailure, TestSize.Level1)
{
    MockNativeToken mock("foundation");

    HapInfoParams info = TestCommon::GetInfoManagerTestSystemInfoParms();
    info.bundleName = "com.example.retained";
    info.appIDDesc = info.bundleName;
    HapPolicyParams policy = TestCommon::GetTestPolicyParams();

    AccessTokenIDEx tokenIdEx = {0};
    ASSERT_EQ(RET_SUCCESS, AllocHapTokenLocally(info, policy, tokenIdEx));

    // Set a conflicting cached UID so the first migration fails
    auto infoPtr = AccessTokenInfoManager::GetInstance().GetHapTokenInfoInner(tokenIdEx.tokenIdExStruct.tokenID);
    ASSERT_NE(nullptr, infoPtr);
    infoPtr->SetUid(203201);

    MigratedInfoIdl migratedInfo;
    BuildMigratedInfo(info, tokenIdEx.tokenIDEx, 203202, migratedInfo);

    auto service = DelayedSingleton<AccessTokenManagerService>::GetInstance();
    ASSERT_NE(nullptr, service);
    EXPECT_EQ(RET_SUCCESS, service->PreMigrateUIDList({ migratedInfo.uidList[0] }));

    // First migration fails due to cached UID conflict
    std::vector<BundleMigrateResultIdl> results;
    EXPECT_EQ(RET_SUCCESS, service->MigrateInstalledBundles({ migratedInfo }, results));
    ASSERT_EQ(1u, results.size());
    EXPECT_EQ(AccessTokenError::ERR_MIGRATION_UID_EXISTED, results[0].errcode);

    // UID must still be in cache — retry without re-registration should succeed after fixing the conflict
    infoPtr->SetUid(static_cast<uint32_t>(-1)); // INVALID_HAP_UID
    std::vector<BundleMigrateResultIdl> results2;
    EXPECT_EQ(RET_SUCCESS, service->MigrateInstalledBundles({ migratedInfo }, results2));
    ASSERT_EQ(1u, results2.size());
    EXPECT_EQ(RET_SUCCESS, results2[0].errcode);

    (void)SpmRemoveEntry(tokenIdEx.tokenIdExStruct.tokenID);
    EXPECT_EQ(RET_SUCCESS, AccessTokenInfoManager::GetInstance().RemoveHapTokenInfo(tokenIdEx.tokenIdExStruct.tokenID));
}

// =============================================================================
// FinishMigration — one spec per test
// =============================================================================

/**
 * @tc.name: FinishMigration_FirstCall
 * @tc.desc: First FinishMigration call returns RET_SUCCESS and sets migrationDone_ flag.
 * @tc.type: FUNC
 */
HWTEST_F(MigrateInstalledBundlesServiceTest, FinishMigration_FirstCall, TestSize.Level1)
{
    MockNativeToken mock("foundation");

    {
        std::unique_lock<std::mutex> lock(AccessTokenIDManager::GetInstance().migrationLock_);
        ASSERT_FALSE(AccessTokenIDManager::GetInstance().migrationDone_);
    }

    auto service = DelayedSingleton<AccessTokenManagerService>::GetInstance();
    ASSERT_NE(nullptr, service);
    EXPECT_EQ(RET_SUCCESS, service->FinishMigration());

    {
        std::unique_lock<std::mutex> lock(AccessTokenIDManager::GetInstance().migrationLock_);
        EXPECT_TRUE(AccessTokenIDManager::GetInstance().migrationDone_);
    }
}

/**
 * @tc.name: FinishMigration_SecondCall
 * @tc.desc: Second FinishMigration call returns ERR_MIGRATION_COMPLETED.
 * @tc.type: FUNC
 */
HWTEST_F(MigrateInstalledBundlesServiceTest, FinishMigration_SecondCall, TestSize.Level1)
{
    MockNativeToken mock("foundation");
    auto service = DelayedSingleton<AccessTokenManagerService>::GetInstance();
    ASSERT_NE(nullptr, service);
    ASSERT_EQ(RET_SUCCESS, service->FinishMigration());
    EXPECT_EQ(AccessTokenError::ERR_MIGRATION_COMPLETED, service->FinishMigration());
}

#ifdef IS_SUPPORT_HAP_RUNNING
// =============================================================================
// MigrationVerifyHelper::VerifyMigratedBundle — triggered via worker after MigrateInstalledBundles
// Each test calls Shutdown() after migration to wait for the worker to finish
// verification synchronously, then checks DB state.
// =============================================================================

/**
 * @tc.name: VerifyMigratedBundle_WorkerHapSignVerifyFailure
 * @tc.desc: Worker calls VerifyMigratedBundle with failing mock verifyRet_;
 *          migration DB state remains unchanged after verification failure.
 * @tc.type: FUNC
 */
HWTEST_F(MigrateInstalledBundlesServiceTest, VerifyMigratedBundle_WorkerHapSignVerifyFailure, TestSize.Level1)
{
    MockNativeToken mock("foundation");

    HapInfoParams info = TestCommon::GetInfoManagerTestSystemInfoParms();
    info.bundleName = "com.example.verify.fail";
    info.appIDDesc = info.bundleName;
    HapPolicyParams policy = TestCommon::GetTestPolicyParams();

    AccessTokenIDEx tokenIdEx = {0};
    ASSERT_EQ(RET_SUCCESS, AllocHapTokenLocally(info, policy, tokenIdEx));

    MigratedInfoIdl migratedInfo;
    BuildMigratedInfo(info, tokenIdEx.tokenIDEx, 202001, migratedInfo);

    // Inject verification failure before migration — worker will see this
    mockAdapter_.verifyRet_ = AccessTokenError::ERR_PARAM_INVALID;

    auto service = DelayedSingleton<AccessTokenManagerService>::GetInstance();
    ASSERT_NE(nullptr, service);
    EXPECT_EQ(RET_SUCCESS, service->PreMigrateUIDList({ migratedInfo.uidList[0] }));
    std::vector<BundleMigrateResultIdl> results;
    EXPECT_EQ(RET_SUCCESS, service->MigrateInstalledBundles({ migratedInfo }, results));
    ASSERT_EQ(1u, results.size());
    EXPECT_EQ(RET_SUCCESS, results[0].errcode);

    // Migration DB state must still be intact — verification failed, no changes committed
    ExpectMigratedDbState(tokenIdEx.tokenIdExStruct.tokenID, info.bundleName, migratedInfo.uidList[0]);

    mockAdapter_.verifyRet_ = RET_SUCCESS;

    (void)SpmRemoveEntry(tokenIdEx.tokenIdExStruct.tokenID);
    EXPECT_EQ(RET_SUCCESS, AccessTokenInfoManager::GetInstance().RemoveHapTokenInfo(tokenIdEx.tokenIdExStruct.tokenID));
}

/**
 * @tc.name: VerifyMigratedBundle_WorkerBundleNameMismatch
 * @tc.desc: Worker sees verified bundleName != migratedInfo.bundleName;
 *          migration DB state remains unchanged.
 * @tc.type: FUNC
 */
HWTEST_F(MigrateInstalledBundlesServiceTest, VerifyMigratedBundle_WorkerBundleNameMismatch, TestSize.Level1)
{
    MockNativeToken mock("foundation");

    HapInfoParams info = TestCommon::GetInfoManagerTestSystemInfoParms();
    info.bundleName = "com.example.match";
    info.appIDDesc = info.bundleName;
    HapPolicyParams policy = TestCommon::GetTestPolicyParams();

    AccessTokenIDEx tokenIdEx = {0};
    ASSERT_EQ(RET_SUCCESS, AllocHapTokenLocally(info, policy, tokenIdEx));

    MigratedInfoIdl migratedInfo;
    BuildMigratedInfo(info, tokenIdEx.tokenIDEx, 202101, migratedInfo);
    // Override hapPaths to a different name — mock sets verified bundleName to this value
    migratedInfo.pathList.hapPaths = { "com.example.mismatch" };

    auto service = DelayedSingleton<AccessTokenManagerService>::GetInstance();
    ASSERT_NE(nullptr, service);
    EXPECT_EQ(RET_SUCCESS, service->PreMigrateUIDList({ migratedInfo.uidList[0] }));
    std::vector<BundleMigrateResultIdl> results;
    EXPECT_EQ(RET_SUCCESS, service->MigrateInstalledBundles({ migratedInfo }, results));
    ASSERT_EQ(1u, results.size());
    EXPECT_EQ(RET_SUCCESS, results[0].errcode);

    // Migration DB state must still be intact
    ExpectMigratedDbState(tokenIdEx.tokenIdExStruct.tokenID, info.bundleName, migratedInfo.uidList[0]);

    (void)SpmRemoveEntry(tokenIdEx.tokenIdExStruct.tokenID);
    EXPECT_EQ(RET_SUCCESS, AccessTokenInfoManager::GetInstance().RemoveHapTokenInfo(tokenIdEx.tokenIdExStruct.tokenID));
}

/**
 * @tc.name: VerifyMigratedBundle_WorkerSuccess
 * @tc.desc: Worker completes VerifyMigratedBundle successfully;
 *          DB reflects both migrated UID and verified sign info.
 * @tc.type: FUNC
 */
HWTEST_F(MigrateInstalledBundlesServiceTest, VerifyMigratedBundle_WorkerSuccess, TestSize.Level1)
{
    MockNativeToken mock("foundation");

    HapInfoParams info = TestCommon::GetInfoManagerTestSystemInfoParms();
    info.bundleName = "com.example.verify.ok";
    info.appIDDesc = info.bundleName;
    HapPolicyParams policy = TestCommon::GetTestPolicyParams();

    AccessTokenIDEx tokenIdEx = {0};
    ASSERT_EQ(RET_SUCCESS, AllocHapTokenLocally(info, policy, tokenIdEx));

    MigratedInfoIdl migratedInfo;
    BuildMigratedInfo(info, tokenIdEx.tokenIDEx, 202201, migratedInfo);

    // Configure mock adapter to return a verified bundle name matching migratedInfo.bundleName
    mockAdapter_.bundleName_ = info.bundleName;

    auto service = DelayedSingleton<AccessTokenManagerService>::GetInstance();
    ASSERT_NE(nullptr, service);
    EXPECT_EQ(RET_SUCCESS, service->PreMigrateUIDList({ migratedInfo.uidList[0] }));
    std::vector<BundleMigrateResultIdl> results;
    EXPECT_EQ(RET_SUCCESS, service->MigrateInstalledBundles({ migratedInfo }, results));
    ASSERT_EQ(1u, results.size());
    EXPECT_EQ(RET_SUCCESS, results[0].errcode);

    // DB should have both migrated state and verified sign info
    ExpectMigratedDbState(tokenIdEx.tokenIdExStruct.tokenID, info.bundleName, migratedInfo.uidList[0],
        ReservedType::NONE, true);

    (void)SpmRemoveEntry(tokenIdEx.tokenIdExStruct.tokenID);
    EXPECT_EQ(RET_SUCCESS, AccessTokenInfoManager::GetInstance().RemoveHapTokenInfo(tokenIdEx.tokenIdExStruct.tokenID));
}
#endif

// =============================================================================
// misc — supplementary coverage (IsTokenIdValid, IsStringListValid, Kit APIs,
//        permission-denial branches)
// =============================================================================

/**
 * @tc.name: IsStringListValid_ExceedsMaxLength
 * @tc.desc: A string in the list exceeding MAX_LENGTH (256) returns false.
 * @tc.type: FUNC
 */
HWTEST_F(MigrateInstalledBundlesServiceTest, IsStringListValid_ExceedsMaxLength, TestSize.Level1)
{
    // Valid list as baseline
    EXPECT_TRUE(DataValidator::IsStringListValid({"valid"}));
    // Exceeds MAX_LENGTH (256)
    std::string tooLong(257, 'x');
    EXPECT_FALSE(DataValidator::IsStringListValid({tooLong}));
    // Mixed: first valid, second too long
    EXPECT_FALSE(DataValidator::IsStringListValid({"valid", tooLong}));
}

/**
 * @tc.name: PreMigrateUIDList_KitNormal
 * @tc.desc: PreMigrateUIDList through AccessTokenKit with valid UIDs returns RET_SUCCESS.
 * @tc.type: FUNC
 */
HWTEST_F(MigrateInstalledBundlesServiceTest, PreMigrateUIDList_KitNormal, TestSize.Level1)
{
    MockNativeToken mock("foundation");
    EXPECT_EQ(RET_SUCCESS, AccessTokenKit::PreMigrateUIDList({ 202501, 202502 }));
}

/**
 * @tc.name: MigrateInstalledBundles_KitHapBaseInfoNotEmpty
 * @tc.desc: MigrateInstalledBundles through AccessTokenKit with non-empty hapBaseInfoList migrates successfully.
 * @tc.type: FUNC
 */
HWTEST_F(MigrateInstalledBundlesServiceTest, MigrateInstalledBundles_KitHapBaseInfoNotEmpty, TestSize.Level1)
{
    MockNativeToken mock("foundation");

    HapInfoParams info = TestCommon::GetInfoManagerTestSystemInfoParms();
    info.bundleName = "com.example.kitmigrate";
    info.appIDDesc = info.bundleName;
    HapPolicyParams policy = TestCommon::GetTestPolicyParams();

    MigratedInfo migratedInfo;
    migratedInfo.bundleName = info.bundleName;
    migratedInfo.pathList.hapPaths = { info.bundleName };
    migratedInfo.pathList.isPreInstalled = false;
    HapBaseInfo baseInfo;
    baseInfo.userID = info.userID;
    baseInfo.bundleName = info.bundleName;
    baseInfo.instIndex = 0;
    migratedInfo.hapBaseInfoList = { baseInfo };
    migratedInfo.uidList = { 202602 };
    migratedInfo.reservedTypeList = { ReservedType::NONE };

    auto service = DelayedSingleton<AccessTokenManagerService>::GetInstance();
    ASSERT_NE(nullptr, service);
    EXPECT_EQ(RET_SUCCESS, AccessTokenKit::PreMigrateUIDList({ migratedInfo.uidList[0] }));
    std::vector<BundleMigrateResult> results;
    EXPECT_EQ(RET_SUCCESS, AccessTokenKit::MigrateInstalledBundles({ migratedInfo }, results));
    ASSERT_EQ(1u, results.size());
    EXPECT_EQ(RET_SUCCESS, results[0].errcode);
    ASSERT_EQ(1u, results[0].tokenIdList.size());

    ExpectMigratedDbState(results[0].tokenIdList[0].tokenIDEx, info.bundleName,
        migratedInfo.uidList[0], ReservedType::RESERVED_DATA);

    (void)SpmRemoveEntry(results[0].tokenIdList[0].tokenIDEx);
    (void)AccessTokenKit::DeleteToken(results[0].tokenIdList[0].tokenIDEx);
}

/**
 * @tc.name: PreMigrateUIDList_NoPermission
 * @tc.desc: PreMigrateUIDList returns ERR_PERMISSION_DENIED when caller lacks MANAGE_HAP_TOKENID_PERMISSION.
 * @tc.type: FUNC
 */
HWTEST_F(MigrateInstalledBundlesServiceTest, PreMigrateUIDList_NoPermission, TestSize.Level1)
{
    MockHapToken mock("com.example.noperm", {}, false);
    UidGuard guard(2000);
    auto service = DelayedSingleton<AccessTokenManagerService>::GetInstance();
    ASSERT_NE(nullptr, service);
    EXPECT_EQ(AccessTokenError::ERR_PERMISSION_DENIED, service->PreMigrateUIDList({ 202701 }));
}

/**
 * @tc.name: MigrateInstalledBundles_NoPermission
 * @tc.desc: MigrateInstalledBundles returns ERR_PERMISSION_DENIED when caller lacks MANAGE_HAP_TOKENID_PERMISSION.
 * @tc.type: FUNC
 */
HWTEST_F(MigrateInstalledBundlesServiceTest, MigrateInstalledBundles_NoPermission, TestSize.Level1)
{
    MockHapToken mock("com.example.noperm", {}, false);
    UidGuard guard(2000);
    auto service = DelayedSingleton<AccessTokenManagerService>::GetInstance();
    ASSERT_NE(nullptr, service);
    MigratedInfoIdl migratedInfo;
    migratedInfo.bundleName = "com.example.test";
    std::vector<BundleMigrateResultIdl> results;
    EXPECT_EQ(AccessTokenError::ERR_PERMISSION_DENIED,
        service->MigrateInstalledBundles({ migratedInfo }, results));
}

/**
 * @tc.name: FinishMigration_NoPermission
 * @tc.desc: FinishMigration returns ERR_PERMISSION_DENIED when caller lacks MANAGE_HAP_TOKENID_PERMISSION.
 * @tc.type: FUNC
 */
HWTEST_F(MigrateInstalledBundlesServiceTest, FinishMigration_NoPermission, TestSize.Level1)
{
    MockHapToken mock("com.example.noperm", {}, false);
    UidGuard guard(2000);
    auto service = DelayedSingleton<AccessTokenManagerService>::GetInstance();
    ASSERT_NE(nullptr, service);
    EXPECT_EQ(AccessTokenError::ERR_PERMISSION_DENIED, service->FinishMigration());
}

/**
 * @tc.name: MigrateInstalledBundles_InvalidHapPaths
 * @tc.desc: hapPaths with a string exceeding max length triggers IsStringListValid failure
 * @tc.type: FUNC
 */
HWTEST_F(MigrateInstalledBundlesServiceTest, MigrateInstalledBundles_InvalidHapPaths, TestSize.Level1)
{
    MockNativeToken mock("foundation");

    HapInfoParams info = TestCommon::GetInfoManagerTestSystemInfoParms();
    info.bundleName = "com.example.happathfail";

    HapBaseInfoIdl baseInfo;
    baseInfo.bundleName = info.bundleName;
    baseInfo.userID = info.userID;
    baseInfo.instIndex = 0;

    std::string tooLong(300, 'x');
    MigratedInfoIdl migratedInfo;
    migratedInfo.bundleName = info.bundleName;
    migratedInfo.pathList.hapPaths = { tooLong };
    migratedInfo.hapBaseInfoList = { baseInfo };
    migratedInfo.uidList = { 200801 };
    migratedInfo.reservedTypeList = { ReservedTypeIdl::NONE };

    auto service = DelayedSingleton<AccessTokenManagerService>::GetInstance();
    ASSERT_NE(nullptr, service);
    ASSERT_EQ(RET_SUCCESS, service->PreMigrateUIDList({ 200801 }));
    std::vector<BundleMigrateResultIdl> results;
    EXPECT_EQ(RET_SUCCESS, service->MigrateInstalledBundles({ migratedInfo }, results));
    ASSERT_EQ(1u, results.size());
    EXPECT_EQ(AccessTokenError::ERR_PARAM_INVALID, results[0].errcode);
}

/**
 * @tc.name: MigrateInstalledBundles_BothListSizeMismatch
 * @tc.desc: uidList and reservedTypeList both mismatch hapBaseInfoList size
 * @tc.type: FUNC
 */
HWTEST_F(MigrateInstalledBundlesServiceTest, MigrateInstalledBundles_BothListSizeMismatch, TestSize.Level1)
{
    MockNativeToken mock("foundation");

    HapInfoParams info = TestCommon::GetInfoManagerTestSystemInfoParms();
    info.bundleName = "com.example.bothmismatch";

    HapBaseInfoIdl baseInfo;
    baseInfo.bundleName = info.bundleName;
    baseInfo.userID = info.userID;
    baseInfo.instIndex = 0;

    MigratedInfoIdl migratedInfo;
    migratedInfo.bundleName = info.bundleName;
    migratedInfo.pathList.hapPaths = { info.bundleName };
    migratedInfo.hapBaseInfoList = { baseInfo, baseInfo }; // size 2
    migratedInfo.uidList = { 200901 };                     // size 1
    migratedInfo.reservedTypeList = {};                     // size 0

    auto service = DelayedSingleton<AccessTokenManagerService>::GetInstance();
    ASSERT_NE(nullptr, service);
    ASSERT_EQ(RET_SUCCESS, service->PreMigrateUIDList({ 200901 }));
    std::vector<BundleMigrateResultIdl> results;
    EXPECT_EQ(RET_SUCCESS, service->MigrateInstalledBundles({ migratedInfo }, results));
    ASSERT_EQ(1u, results.size());
    EXPECT_EQ(AccessTokenError::ERR_PARAM_INVALID, results[0].errcode);
}

/**
 * @tc.name: MigrateInstalledBundles_DuplicateUidSeparateTokens
 * @tc.desc: Two haps with same userID/instIndex but different hapBaseInfo entries;
 *           still covers the validation loop for hapBaseInfo (line 99).
 * @tc.type: FUNC
 */
HWTEST_F(MigrateInstalledBundlesServiceTest, MigrateInstalledBundles_DuplicateUidSeparateTokens, TestSize.Level1)
{
    MockNativeToken mock("foundation");

    HapInfoParams info = TestCommon::GetInfoManagerTestSystemInfoParms();
    info.bundleName = "com.example.dupuidsep";

    HapBaseInfoIdl baseInfo;
    baseInfo.bundleName = info.bundleName;
    baseInfo.userID = info.userID;
    baseInfo.instIndex = 0;

    MigratedInfoIdl migratedInfo;
    migratedInfo.bundleName = info.bundleName;
    migratedInfo.pathList.hapPaths = { info.bundleName };
    migratedInfo.hapBaseInfoList = { baseInfo, baseInfo };
    migratedInfo.uidList = { 201001, 201001 }; // same UID
    migratedInfo.reservedTypeList = { ReservedTypeIdl::NONE, ReservedTypeIdl::NONE };

    auto service = DelayedSingleton<AccessTokenManagerService>::GetInstance();
    ASSERT_NE(nullptr, service);
    ASSERT_EQ(RET_SUCCESS, service->PreMigrateUIDList({ 201001 }));
    std::vector<BundleMigrateResultIdl> results;
    EXPECT_EQ(RET_SUCCESS, service->MigrateInstalledBundles({ migratedInfo }, results));
    ASSERT_EQ(1u, results.size());
    EXPECT_EQ(AccessTokenError::ERR_MIGRATION_UID_DUPLICATED, results[0].errcode);
}

/**
 * @tc.name: MigrateInstalledBundles_SecondHapBundleNameMismatch
 * @tc.desc: First hap validates ok, second hap has mismatched bundleName (line 103).
 * @tc.type: FUNC
 */
HWTEST_F(MigrateInstalledBundlesServiceTest, MigrateInstalledBundles_SecondHapBundleNameMismatch, TestSize.Level1)
{
    MockNativeToken mock("foundation");

    HapInfoParams info = TestCommon::GetInfoManagerTestSystemInfoParms();
    info.bundleName = "com.example.sechmm";

    HapBaseInfoIdl baseInfoOk;
    baseInfoOk.bundleName = info.bundleName;
    baseInfoOk.userID = info.userID;
    baseInfoOk.instIndex = 0;

    HapBaseInfoIdl baseInfoBad;
    baseInfoBad.bundleName = "com.example.different";
    baseInfoBad.userID = info.userID;
    baseInfoBad.instIndex = 1;

    MigratedInfoIdl migratedInfo;
    migratedInfo.bundleName = info.bundleName;
    migratedInfo.pathList.hapPaths = { info.bundleName };
    migratedInfo.hapBaseInfoList = { baseInfoOk, baseInfoBad };
    migratedInfo.uidList = { 201101, 201102 };
    migratedInfo.reservedTypeList = { ReservedTypeIdl::NONE, ReservedTypeIdl::NONE };

    auto service = DelayedSingleton<AccessTokenManagerService>::GetInstance();
    ASSERT_NE(nullptr, service);
    ASSERT_EQ(RET_SUCCESS, service->PreMigrateUIDList({ 201101, 201102 }));
    std::vector<BundleMigrateResultIdl> results;
    EXPECT_EQ(RET_SUCCESS, service->MigrateInstalledBundles({ migratedInfo }, results));
    ASSERT_EQ(1u, results.size());
    EXPECT_EQ(AccessTokenError::ERR_PARAM_INVALID, results[0].errcode);
}

/**
 * @tc.name: GetCachedTokenInfo_TokenNotInCache
 * @tc.desc: GetCachedTokenInfo returns ERR_PARAM_INVALID when infoPtr is nullptr (line 125).
 * @tc.type: FUNC
 */
HWTEST_F(MigrateInstalledBundlesServiceTest, GetCachedTokenInfo_TokenNotInCache, TestSize.Level1)
{
    MockNativeToken mock("foundation");

    std::shared_ptr<HapTokenInfoInner> infoPtr;
    int32_t ret = AccessTokenMigrationManager::GetInstance().GetCachedTokenInfo(
        999999, "com.example.nonexist", infoPtr);
    EXPECT_EQ(AccessTokenError::ERR_PARAM_INVALID, ret);
}

/**
 * @tc.name: GetCachedTokenInfo_BundleNameMismatch
 * @tc.desc: GetCachedTokenInfo returns ERR_PARAM_INVALID when bundleName doesn't match (line 130).
 * @tc.type: FUNC
 */
HWTEST_F(MigrateInstalledBundlesServiceTest, GetCachedTokenInfo_BundleNameMismatch, TestSize.Level1)
{
    MockNativeToken mock("foundation");

    HapInfoParams info = TestCommon::GetInfoManagerTestSystemInfoParms();
    info.bundleName = "com.example.gtcachebmm";
    info.appIDDesc = info.bundleName;
    HapPolicyParams policy = TestCommon::GetTestPolicyParams();

    AccessTokenIDEx tokenIdEx = {0};
    ASSERT_EQ(RET_SUCCESS, AllocHapTokenLocally(info, policy, tokenIdEx));
    AccessTokenID tokenId = tokenIdEx.tokenIdExStruct.tokenID;

    std::shared_ptr<HapTokenInfoInner> infoPtr;
    int32_t ret = AccessTokenMigrationManager::GetInstance().GetCachedTokenInfo(
        tokenId, "com.example.wrongname", infoPtr);
    EXPECT_EQ(AccessTokenError::ERR_PARAM_INVALID, ret);

    EXPECT_EQ(RET_SUCCESS, AccessTokenInfoManager::GetInstance().RemoveHapTokenInfo(tokenId));
}

/**
 * @tc.name: AppendHapTokenDbInfo_TokenNotInDbCache
 * @tc.desc: When dbRowCache_ doesn't contain the token, AppendHapTokenDbInfo
 *           returns ERR_DATABASE_OPERATE_FAILED (line 367).
 *           This triggers PersistMigratedBundles failure at line 241.
 * @tc.type: FUNC
 */
HWTEST_F(MigrateInstalledBundlesServiceTest, AppendHapTokenDbInfo_TokenNotInDbCache, TestSize.Level1)
{
    MockNativeToken mock("foundation");

    HapInfoParams info = TestCommon::GetInfoManagerTestSystemInfoParms();
    info.bundleName = "com.example.nodbcache";
    info.appIDDesc = info.bundleName;
    HapPolicyParams policy = TestCommon::GetTestPolicyParams();

    AccessTokenIDEx tokenIdEx = {0};
    ASSERT_EQ(RET_SUCCESS, AllocHapTokenLocally(info, policy, tokenIdEx));

    MigratedInfoIdl migratedInfo;
    BuildMigratedInfo(info, tokenIdEx.tokenIDEx, 201201, migratedInfo);

    auto& manager = AccessTokenMigrationManager::GetInstance();
    // PreMigrateUIDList with a different UID populates dbRowCache_ but NOT for our token
    auto service = DelayedSingleton<AccessTokenManagerService>::GetInstance();
    ASSERT_NE(nullptr, service);
    ASSERT_EQ(RET_SUCCESS, service->PreMigrateUIDList({ 209999 }));
    // Now clear dbRowCache_ to simulate the cache not having our token
    manager.dbRowCache_.clear();

    // MigrateInstalledBundles will fail because UID not in preMigratedUidSet_
    // But we want to test the internal path, so call MigrateSingleBundle directly
    MigratedInfoIdl migratedInfoCopy = migratedInfo;
    BundleMigrateResultIdl result;
    int32_t ret = manager.MigrateSingleBundle(migratedInfoCopy, result);
    // An existing token (not new) requires dbRowCache_ lookup which will fail
    EXPECT_NE(RET_SUCCESS, ret);

    EXPECT_EQ(RET_SUCCESS, AccessTokenInfoManager::GetInstance().RemoveHapTokenInfo(
        tokenIdEx.tokenIdExStruct.tokenID));
}

/**
 * @tc.name: Initialize_AfterMigrationCompleted
 * @tc.desc: Initialize() detects migration is completed and sets migrationDone_ flag (line 397).
 * @tc.type: FUNC
 */
HWTEST_F(MigrateInstalledBundlesServiceTest, Initialize_AfterMigrationCompleted, TestSize.Level1)
{
    MockNativeToken mock("foundation");

    // Complete migration first
    auto service = DelayedSingleton<AccessTokenManagerService>::GetInstance();
    ASSERT_NE(nullptr, service);
    ASSERT_EQ(RET_SUCCESS, service->FinishMigration());

    // Initialize should detect migration completed and set the flag (line 397)
    AccessTokenMigrationManager::GetInstance().Initialize();

    {
        std::unique_lock<std::mutex> lock(AccessTokenIDManager::GetInstance().migrationLock_);
        EXPECT_TRUE(AccessTokenIDManager::GetInstance().migrationDone_);
    }
}
} // namespace AccessToken
} // namespace Security
} // namespace OHOS
