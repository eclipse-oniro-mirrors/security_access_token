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

#include "spm_kit_test.h"

#include <map>
#include <set>
#include <string>
#include <vector>

#include "access_token.h"
#include "access_token_error.h"
#include "hap_token_info.h"

using namespace testing::ext;

namespace OHOS {
namespace Security {
namespace AccessToken {
namespace {
static const std::string TEST_BUNDLE_NAME = "com.example.spmtest";
static const std::string TEST_HAP_PATH = "/system/app/com.example.spmtest/entry.hap";
static constexpr int32_t TEST_USER_ID = 100;
static constexpr int32_t TEST_UID = 9900;
static constexpr int32_t TEST_SESSION_ID = 1;
static constexpr AccessTokenID TEST_TOKEN_ID = 12345;
} // namespace

void SpmKitTest::SetUpTestCase() {}

void SpmKitTest::TearDownTestCase() {}

void SpmKitTest::SetUp() {}

void SpmKitTest::TearDown() {}

static HapBaseInfo BuildHapBaseInfo()
{
    HapBaseInfo info;
    info.userID = TEST_USER_ID;
    info.bundleName = TEST_BUNDLE_NAME;
    info.instIndex = 0;
    return info;
}

static BundlePolicy BuildBundlePolicy()
{
    BundlePolicy policy = {};
    policy.dlpType = DLP_COMMON;
    policy.isDebugGrant = false;
    return policy;
}

static BundleHapList BuildBundleHapList()
{
    BundleHapList list;
    list.hapPaths = {TEST_HAP_PATH};
    list.isPreInstalled = false;
    list.userId = TEST_USER_ID;
    list.mode = 0;
    return list;
}

/**
 * @tc.name: DeleteIdentity001
 * @tc.desc: AccessTokenKit::DeleteIdentity function test
 * @tc.type: FUNC
 * @tc.require: Issue Number
 */
HWTEST_F(SpmKitTest, DeleteIdentity001, TestSize.Level1)
{
    AccessTokenID tokenID = TEST_TOKEN_ID;
    EXPECT_EQ(0, AccessTokenKit::DeleteIdentity(tokenID, TEST_BUNDLE_NAME, ReservedType::RESERVED_IDENTITY));
}

/**
 * @tc.name: MigrateInstalledBundles001
 * @tc.desc: AccessTokenKit::MigrateInstalledBundles function test
 * @tc.type: FUNC
 * @tc.require: Issue Number
 */
HWTEST_F(SpmKitTest, MigrateInstalledBundles001, TestSize.Level1)
{
    MigratedInfo migratedInfo;
    migratedInfo.bundleName = TEST_BUNDLE_NAME;
    migratedInfo.pathList = BuildBundleHapList();
    migratedInfo.hapBaseInfoList = {BuildHapBaseInfo()};
    migratedInfo.uidList = {TEST_UID};
    migratedInfo.reservedTypeList = {ReservedType::RESERVED_IDENTITY};
    std::vector<MigratedInfo> migratedInfoList = {migratedInfo};
    std::vector<BundleMigrateResult> results;
    EXPECT_EQ(0, AccessTokenKit::MigrateInstalledBundles(migratedInfoList, results));
}

/**
 * @tc.name: FinishMigration001
 * @tc.desc: AccessTokenKit::FinishMigration function test
 * @tc.type: FUNC
 * @tc.require: Issue Number
 */
HWTEST_F(SpmKitTest, FinishMigration001, TestSize.Level1)
{
    EXPECT_EQ(0, AccessTokenKit::FinishMigration());
}

/**
 * @tc.name: CheckMigratedUidSet001
 * @tc.desc: AccessTokenKit::CheckMigratedUidSet function test
 * @tc.type: FUNC
 * @tc.require: Issue Number
 */
HWTEST_F(SpmKitTest, CheckMigratedUidSet001, TestSize.Level1)
{
    std::set<int32_t> totalUids = {TEST_UID, TEST_UID + 1};
    std::set<int32_t> unreceivedUids;
    EXPECT_EQ(0, AccessTokenKit::CheckMigratedUidSet(totalUids, unreceivedUids));
}

/**
 * @tc.name: GetHapIdentity001
 * @tc.desc: AccessTokenKit::GetHapIdentity function test
 * @tc.type: FUNC
 * @tc.require: Issue Number
 */
HWTEST_F(SpmKitTest, GetHapIdentity001, TestSize.Level1)
{
    Identity identity;
    EXPECT_EQ(0, AccessTokenKit::GetHapIdentity(BuildHapBaseInfo(), identity));
}

/**
 * @tc.name: GetHapBaseInfoByUid001
 * @tc.desc: AccessTokenKit::GetHapBaseInfoByUid function test
 * @tc.type: FUNC
 * @tc.require: Issue Number
 */
HWTEST_F(SpmKitTest, GetHapBaseInfoByUid001, TestSize.Level1)
{
    HapBaseInfo info;
    EXPECT_EQ(0, AccessTokenKit::GetHapBaseInfoByUid(TEST_UID, info));
}

/**
 * @tc.name: CheckHapSignInfo001
 * @tc.desc: AccessTokenKit::CheckHapSignInfo function test
 * @tc.type: FUNC
 * @tc.require: Issue Number
 */
HWTEST_F(SpmKitTest, CheckHapSignInfo001, TestSize.Level1)
{
    int32_t sessionId = TEST_SESSION_ID;
    std::vector<TrustedBundleInfo> bundleInfo;
    HapVerifyResultInfo resultInfo;
    EXPECT_EQ(0, AccessTokenKit::CheckHapSignInfo(BuildBundleHapList(), SignInfoQueryFlag::QUERY_PROFILE,
        sessionId, bundleInfo, resultInfo));
}

/**
 * @tc.name: CheckHapPermissionInfo001
 * @tc.desc: AccessTokenKit::CheckHapPermissionInfo function test
 * @tc.type: FUNC
 * @tc.require: Issue Number
 */
HWTEST_F(SpmKitTest, CheckHapPermissionInfo001, TestSize.Level1)
{
    HapInfoCheckResult result;
    EXPECT_EQ(0, AccessTokenKit::CheckHapPermissionInfo(TEST_SESSION_ID, InstallTypeEnum::TYPE_INSTALL, result));
}

/**
 * @tc.name: PrepareHapIdentity001
 * @tc.desc: AccessTokenKit::PrepareHapIdentity function test
 * @tc.type: FUNC
 * @tc.require: Issue Number
 */
HWTEST_F(SpmKitTest, PrepareHapIdentity001, TestSize.Level1)
{
    int32_t sessionId = TEST_SESSION_ID;
    Identity identity;
    EXPECT_EQ(0, AccessTokenKit::PrepareHapIdentity(sessionId, BuildHapBaseInfo(), BuildBundlePolicy(), identity));
}

/**
 * @tc.name: UpdateHapPolicy001
 * @tc.desc: AccessTokenKit::UpdateHapPolicy function test
 * @tc.type: FUNC
 * @tc.require: Issue Number
 */
HWTEST_F(SpmKitTest, UpdateHapPolicy001, TestSize.Level1)
{
    int32_t uid = TEST_UID;
    EXPECT_EQ(0, AccessTokenKit::UpdateHapPolicy(TEST_SESSION_ID, TEST_TOKEN_ID, BuildBundlePolicy(), uid));
}

/**
 * @tc.name: FinishInstall001
 * @tc.desc: AccessTokenKit::FinishInstall function test
 * @tc.type: FUNC
 * @tc.require: Issue Number
 */
HWTEST_F(SpmKitTest, FinishInstall001, TestSize.Level1)
{
    std::map<std::string, std::string> modulePathMap = {{"entry", "/system/app/com.example.spmtest"}};
    EXPECT_EQ(0, AccessTokenKit::FinishInstall(TEST_SESSION_ID, true, modulePathMap));
}

/**
 * @tc.name: GetHapSignInfo001
 * @tc.desc: AccessTokenKit::GetHapSignInfo function test
 * @tc.type: FUNC
 * @tc.require: Issue Number
 */
HWTEST_F(SpmKitTest, GetHapSignInfo001, TestSize.Level1)
{
    std::vector<TrustedBundleInfo> bundleInfo;
    EXPECT_EQ(0, AccessTokenKit::GetHapSignInfo(TEST_BUNDLE_NAME, SignInfoQueryFlag::QUERY_PROFILE, bundleInfo));
}

/**
 * @tc.name: GetCacheSignInfoBySessionId001
 * @tc.desc: AccessTokenKit::GetCacheSignInfoBySessionId function test
 * @tc.type: FUNC
 * @tc.require: Issue Number
 */
HWTEST_F(SpmKitTest, GetCacheSignInfoBySessionId001, TestSize.Level1)
{
    std::vector<TrustedBundleInfo> bundleInfo;
    EXPECT_EQ(0, AccessTokenKit::GetCacheSignInfoBySessionId(TEST_SESSION_ID,
        SignInfoQueryFlag::QUERY_PROFILE, bundleInfo));
}

/**
 * @tc.name: GetCachePolicyBySessionId001
 * @tc.desc: AccessTokenKit::GetCachePolicyBySessionId function test
 * @tc.type: FUNC
 * @tc.require: Issue Number
 */
HWTEST_F(SpmKitTest, GetCachePolicyBySessionId001, TestSize.Level1)
{
    BundlePolicyInfo bundlePolicyInfo;
    EXPECT_EQ(0, AccessTokenKit::GetCachePolicyBySessionId(TEST_SESSION_ID, TEST_BUNDLE_NAME, bundlePolicyInfo));
}
} // namespace AccessToken
} // namespace Security
} // namespace OHOS
