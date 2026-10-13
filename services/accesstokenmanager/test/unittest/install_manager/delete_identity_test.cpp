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

// UT design principle: every case drives the chain through a pre-dispatch
// entry (the service entry AccessTokenManagerService::DeleteIdentity for the
// permission check, DeleteIdentityWithDfx for everything else), so the
// validation order, the dispatch routing and the DFX scene codes are covered
// on the real path. Entry-observable scenarios keep no direct-call
// counterparts (redundant). Direct calls to post-dispatch internals are only
// kept where no entry can ever reach them:
//   - BuildTokenRemoveDbOps006: the remote-token defensive tail (the entry
//     rejects remote tokens in DeleteActiveToken before any op is built);
//   - NotifyBundleTokensDeletedSizeMismatch001: the size-mismatch defense of
//     the batch notifier (entries always build matched sizes).

#include <gtest/gtest.h>
#include <memory>
#include <vector>

#include "access_token.h"
#include "access_token_error.h"
#include "accesstoken_dfx_define.h"
#include "fake_token_setproc.h"
#include "generic_values.h"
#include "hap_token_info.h"
#include "mock_access_token_db_operator.h"
#include "permission_data_brief.h"
#include "permission_map.h"
#include "permission_status.h"
#include "token_field_const.h"
#define private public
#include "accesstoken_id_manager.h"
#include "accesstoken_info_manager.h"
// The service header transitively includes the managers above; it must stay
// inside the private-public block or its include guards would shield them.
#include "accesstoken_manager_service.h"
#include "delete_bundle_manager.h"
#include "permission_change_notifier.h"
#include "token_modify_notifier.h"
#include "user_policy_manager.h"
#undef private

using namespace testing::ext;

namespace OHOS {
namespace Security {
namespace AccessToken {
namespace {
constexpr AccessTokenID TEST_TOKEN_ID = 0x20100001;    // type bits 27-28 = 0 (TOKEN_HAP), version 1
constexpr AccessTokenID TEST_RESERVED_ID = 0x20100002; // type bits 27-28 = 0 (TOKEN_HAP), version 1
constexpr AccessTokenID TEST_OTHER_ID = 0x20100003;    // type bits 27-28 = 0 (TOKEN_HAP), version 1
constexpr AccessTokenID TEST_RESERVED_DATA_ID = 0x20100004; // type bits 27-28 = 0 (TOKEN_HAP), version 1
constexpr AccessTokenID TEST_UNTRUSTED_NONE_ID = 0x20100221;     // untrusted complete delete
constexpr AccessTokenID TEST_UNTRUSTED_IDENTITY_ID = 0x20100222; // untrusted keep-identity
constexpr AccessTokenID TEST_UNTRUSTED_DATA_ID = 0x20100223;     // untrusted keep-data
constexpr AccessTokenID TEST_UNTRUSTED_WHOLE_ID = 0x20100224;    // untrusted inside a whole-bundle delete
constexpr uint32_t TOKEN_RESERVED_FLAG = 0x0004;
const std::string TEST_BUNDLE = "com.example.deleteidentity.test";

HapTokenInfo BuildHapInfo(AccessTokenID tokenId, const std::string& bundleName)
{
    HapTokenInfo hapInfo = {};
    hapInfo.ver = 1;
    hapInfo.userID = 100; // 100: userId
    hapInfo.bundleName = bundleName;
    hapInfo.apiVersion = 12; // 12: api version
    hapInfo.instIndex = 0;
    hapInfo.dlpType = DLP_COMMON;
    hapInfo.tokenID = tokenId;
    hapInfo.tokenAttr = 0;
    hapInfo.uid = 20020000 + (tokenId % 45536); // 20020000: user base, 45536: bundleId range
    return hapInfo;
}

std::shared_ptr<HapTokenInfoInner> BuildInfoInner(AccessTokenID tokenId, const std::string& bundleName)
{
    HapTokenInfo hapInfo = BuildHapInfo(tokenId, bundleName);
    return std::make_shared<HapTokenInfoInner>(tokenId, hapInfo, std::vector<PermissionStatus>());
}

GenericValues BuildTokenRow(AccessTokenID tokenId, const std::string& bundleName, int32_t reserved)
{
    GenericValues row;
    row.Put(TokenFiledConst::FIELD_TOKEN_ID, static_cast<int32_t>(tokenId));
    row.Put(TokenFiledConst::FIELD_BUNDLE_NAME, bundleName);
    // 20020000: user base, 45536: bundleId range
    row.Put(TokenFiledConst::FIELD_UID, static_cast<int32_t>(20020000 + (tokenId % 45536)));
    row.Put(TokenFiledConst::FIELD_RESERVED, reserved);
    return row;
}

// A row restorable by LoadHapTokenInfoFromDbAndNoCache: untrusted tokens live
// in the db only (no active cache entry), so the pure snapshot must succeed.
GenericValues BuildRestorableTokenRow(AccessTokenID tokenId, const std::string& bundleName)
{
    GenericValues row = BuildTokenRow(tokenId, bundleName, 0);
    row.Put(TokenFiledConst::FIELD_USER_ID, 100);      // 100: userId
    row.Put(TokenFiledConst::FIELD_INST_INDEX, 0);
    row.Put(TokenFiledConst::FIELD_API_VERSION, 12);   // 12: api version
    row.Put(TokenFiledConst::FIELD_DLP_TYPE, 0);       // 0: DLP_COMMON
    row.Put(TokenFiledConst::FIELD_TOKEN_VERSION, 1);  // 1: DEFAULT_TOKEN_VERSION
    row.Put(TokenFiledConst::FIELD_TOKEN_ATTR, 0);
    row.Put(TokenFiledConst::FIELD_FORBID_PERM_DIALOG, 0);
    row.Put(TokenFiledConst::FIELD_IS_SIDELOAD, 0);
    row.Put(TokenFiledConst::FIELD_MIGRATED, 0);
    return row;
}

size_t CountDelInfo(const std::vector<DelInfo>& delInfoVec, AtmDataType type)
{
    size_t count = 0;
    for (const auto& delInfo : delInfoVec) {
        if (delInfo.delType == type) {
            count++;
        }
    }
    return count;
}

std::vector<BriefPermData> BuildGrantedBrief(uint16_t permCode)
{
    BriefPermData data = {0};
    data.permCode = permCode;
    data.status = PERMISSION_GRANTED;
    data.flag = PERMISSION_SYSTEM_FIXED;
    return { data };
}

AccessTokenID BuildNonHapTokenId()
{
    AccessTokenID id = TEST_TOKEN_ID;
    AccessTokenIDInner* idInner = reinterpret_cast<AccessTokenIDInner*>(&id);
    idInner->type = TOKEN_NATIVE;
    return id;
}

// Matrix row: the per-table delete-op counts expected from one deletion
// scenario (token info / permission state / extend value / undefine info /
// permission def / package info).
void ExpectDelOpRow(size_t tokenInfo, size_t permState, size_t extendValue, size_t undefineInfo,
    size_t permDef, size_t packageInfo)
{
    const auto& dels = GetMockDbState().lastDeleteInfos;
    EXPECT_EQ(tokenInfo, CountDelInfo(dels, AtmDataType::ACCESSTOKEN_HAP_TOKEN_INFO));
    EXPECT_EQ(permState, CountDelInfo(dels, AtmDataType::ACCESSTOKEN_PERMISSION_STATE));
    EXPECT_EQ(extendValue, CountDelInfo(dels, AtmDataType::ACCESSTOKEN_PERMISSION_EXTEND_VALUE));
    EXPECT_EQ(undefineInfo, CountDelInfo(dels, AtmDataType::ACCESSTOKEN_HAP_UNDEFINE_INFO));
    EXPECT_EQ(permDef, CountDelInfo(dels, AtmDataType::ACCESSTOKEN_PERMISSION_DEF));
    EXPECT_EQ(packageInfo, CountDelInfo(dels, AtmDataType::ACCESSTOKEN_HAP_PACKAGE_INFO));
}
} // namespace

class DeleteIdentityTest : public testing::Test {
public:
    void SetUp() override
    {
        ResetFakeSpmKernelState();
        ResetMockDbState();
    }

    void TearDown() override
    {
        ResetFakeSpmKernelState();
        ResetMockDbState();
        AccessTokenIDManager::GetInstance().ReleaseTokenId(TEST_TOKEN_ID);
        AccessTokenIDManager::GetInstance().ReleaseTokenId(TEST_OTHER_ID);
        AccessTokenIDManager::GetInstance().RemoveReservedTokenId(TEST_TOKEN_ID);
        AccessTokenIDManager::GetInstance().RemoveReservedTokenId(TEST_RESERVED_ID);
        AccessTokenIDManager::GetInstance().RemoveReservedTokenId(TEST_RESERVED_DATA_ID);
        AccessTokenIDManager::GetInstance().ReleaseTokenIdForce(TEST_UNTRUSTED_NONE_ID);
        AccessTokenIDManager::GetInstance().ReleaseTokenIdForce(TEST_UNTRUSTED_IDENTITY_ID);
        AccessTokenIDManager::GetInstance().ReleaseTokenIdForce(TEST_UNTRUSTED_DATA_ID);
        AccessTokenIDManager::GetInstance().ReleaseTokenIdForce(TEST_UNTRUSTED_WHOLE_ID);
    }
};

/**
 * @tc.name: BuildTokenRemoveDbOps001
 * @tc.desc: NONE deletes the token row and permission state, re-inserts nothing.
 * @tc.type: FUNC
 */
HWTEST_F(DeleteIdentityTest, BuildTokenRemoveDbOps001, TestSize.Level0)
{
    auto info = BuildInfoInner(TEST_TOKEN_ID, TEST_BUNDLE);
    auto& tokenCache = AccessTokenInfoManager::GetInstance().hapTokenInfoMap_;
    tokenCache[TEST_TOKEN_ID] = info;
    AccessTokenIDManager::GetInstance().RegisterTokenId(TEST_TOKEN_ID, TOKEN_HAP);
    DeleteDfxInfo dfx = {};
    uint64_t paramBefore = PermissionChangeNotifier::GetInstance().paramValue_;

    EXPECT_EQ(RET_SUCCESS, DeleteBundleManager::GetInstance().DeleteIdentityWithDfx(
        TEST_TOKEN_ID, TEST_BUNDLE, ReservedType::NONE, dfx));

    EXPECT_EQ(static_cast<int32_t>(AT_DELETE_NORMAL), dfx.sceneCode);
    EXPECT_EQ(1u, CountDelInfo(GetMockDbState().lastDeleteInfos, AtmDataType::ACCESSTOKEN_HAP_TOKEN_INFO));
    EXPECT_EQ(1u, CountDelInfo(GetMockDbState().lastDeleteInfos, AtmDataType::ACCESSTOKEN_PERMISSION_STATE));
    EXPECT_EQ(1u, CountDelInfo(GetMockDbState().lastDeleteInfos, AtmDataType::ACCESSTOKEN_PERMISSION_EXTEND_VALUE));
    EXPECT_EQ(1u, CountDelInfo(GetMockDbState().lastDeleteInfos, AtmDataType::ACCESSTOKEN_HAP_UNDEFINE_INFO));
    EXPECT_TRUE(GetMockDbState().lastAddInfos.empty());
    // No granted permission: no ParamUpdate fires.
    EXPECT_EQ(paramBefore, PermissionChangeNotifier::GetInstance().paramValue_);
}

/**
 * @tc.name: BuildTokenRemoveDbOps002
 * @tc.desc: RESERVED_IDENTITY re-inserts the row with reserved flags and unavailable uid.
 * @tc.type: FUNC
 */
HWTEST_F(DeleteIdentityTest, BuildTokenRemoveDbOps002, TestSize.Level0)
{
    auto info = BuildInfoInner(TEST_TOKEN_ID, TEST_BUNDLE);
    auto& tokenCache = AccessTokenInfoManager::GetInstance().hapTokenInfoMap_;
    tokenCache[TEST_TOKEN_ID] = info;
    AccessTokenIDManager::GetInstance().RegisterTokenId(TEST_TOKEN_ID, TOKEN_HAP);
    DeleteDfxInfo dfx = {};

    EXPECT_EQ(RET_SUCCESS, DeleteBundleManager::GetInstance().DeleteIdentityWithDfx(
        TEST_TOKEN_ID, TEST_BUNDLE, ReservedType::RESERVED_IDENTITY, dfx));

    EXPECT_EQ(static_cast<int32_t>(AT_DELETE_KEEP_TOKEN_FINISH), dfx.sceneCode);
    // The reserved id is registered (the db row carries the state).
    EXPECT_TRUE(AccessTokenIDManager::GetInstance().IsReservedTokenId(TEST_TOKEN_ID));

    bool hasHapReinsert = false;
    for (const auto& addInfo : GetMockDbState().lastAddInfos) {
        if (addInfo.addType == AtmDataType::ACCESSTOKEN_HAP_TOKEN_INFO) {
            hasHapReinsert = true;
            ASSERT_EQ(1u, addInfo.addValues.size());
            EXPECT_NE(0, addInfo.addValues[0].GetInt(TokenFiledConst::FIELD_TOKEN_ATTR) & TOKEN_RESERVED_FLAG);
            EXPECT_EQ(static_cast<int32_t>(ReservedType::RESERVED_IDENTITY),
                addInfo.addValues[0].GetInt(TokenFiledConst::FIELD_RESERVED));
            EXPECT_EQ(-1, addInfo.addValues[0].GetInt(TokenFiledConst::FIELD_UID));
        }
    }
    EXPECT_TRUE(hasHapReinsert);
    EXPECT_EQ(1u, CountDelInfo(GetMockDbState().lastDeleteInfos, AtmDataType::ACCESSTOKEN_PERMISSION_STATE));
}

/**
 * @tc.name: BuildTokenRemoveDbOps003
 * @tc.desc: RESERVED_DATA keeps the permission state table and the uid.
 * @tc.type: FUNC
 */
HWTEST_F(DeleteIdentityTest, BuildTokenRemoveDbOps003, TestSize.Level0)
{
    auto info = BuildInfoInner(TEST_TOKEN_ID, TEST_BUNDLE);
    auto& tokenCache = AccessTokenInfoManager::GetInstance().hapTokenInfoMap_;
    tokenCache[TEST_TOKEN_ID] = info;
    AccessTokenIDManager::GetInstance().RegisterTokenId(TEST_TOKEN_ID, TOKEN_HAP);
    DeleteDfxInfo dfx = {};

    EXPECT_EQ(RET_SUCCESS, DeleteBundleManager::GetInstance().DeleteIdentityWithDfx(
        TEST_TOKEN_ID, TEST_BUNDLE, ReservedType::RESERVED_DATA, dfx));

    EXPECT_EQ(static_cast<int32_t>(AT_DELETE_KEEP_DATA), dfx.sceneCode);
    // The coordinates are filled before the mode dispatch, RESERVED_DATA included.
    EXPECT_EQ(BuildHapInfo(TEST_TOKEN_ID, TEST_BUNDLE).userID, dfx.userId);
    EXPECT_EQ(BuildHapInfo(TEST_TOKEN_ID, TEST_BUNDLE).instIndex, dfx.instIndex);
    EXPECT_EQ(0u, CountDelInfo(GetMockDbState().lastDeleteInfos, AtmDataType::ACCESSTOKEN_PERMISSION_STATE));

    bool hasHapReinsert = false;
    for (const auto& addInfo : GetMockDbState().lastAddInfos) {
        if (addInfo.addType == AtmDataType::ACCESSTOKEN_HAP_TOKEN_INFO) {
            hasHapReinsert = true;
            ASSERT_EQ(1u, addInfo.addValues.size());
            EXPECT_EQ(static_cast<int32_t>(ReservedType::RESERVED_DATA),
                addInfo.addValues[0].GetInt(TokenFiledConst::FIELD_RESERVED));
            EXPECT_EQ(static_cast<int32_t>(BuildHapInfo(TEST_TOKEN_ID, TEST_BUNDLE).uid),
                addInfo.addValues[0].GetInt(TokenFiledConst::FIELD_UID));
        }
    }
    EXPECT_TRUE(hasHapReinsert);
}

/**
 * @tc.name: BuildTokenRemoveDbOps005
 * @tc.desc: A system-resource bundle also deletes its permission definitions.
 * @tc.type: FUNC
 */
HWTEST_F(DeleteIdentityTest, BuildTokenRemoveDbOps005, TestSize.Level0)
{
    auto info = BuildInfoInner(TEST_TOKEN_ID, "ohos.global.systemres");
    auto& tokenCache = AccessTokenInfoManager::GetInstance().hapTokenInfoMap_;
    tokenCache[TEST_TOKEN_ID] = info;
    AccessTokenIDManager::GetInstance().RegisterTokenId(TEST_TOKEN_ID, TOKEN_HAP);
    DeleteDfxInfo dfx = {};

    EXPECT_EQ(RET_SUCCESS, DeleteBundleManager::GetInstance().DeleteIdentityWithDfx(
        TEST_TOKEN_ID, "ohos.global.systemres", ReservedType::NONE, dfx));

    EXPECT_EQ(1u, CountDelInfo(GetMockDbState().lastDeleteInfos, AtmDataType::ACCESSTOKEN_HAP_TOKEN_INFO));
    EXPECT_EQ(1u, CountDelInfo(GetMockDbState().lastDeleteInfos, AtmDataType::ACCESSTOKEN_PERMISSION_STATE));
    EXPECT_EQ(1u, CountDelInfo(GetMockDbState().lastDeleteInfos, AtmDataType::ACCESSTOKEN_PERMISSION_DEF));
}

/**
 * @tc.name: BuildTokenRemoveDbOps006
 * @tc.desc: A remote token generates no re-insert values, so no add ops are built.
 *           Direct call: the dispatch entry rejects remote tokens earlier, so
 *           this defensive tail is unreachable through DeleteIdentityWithDfx.
 * @tc.type: FUNC
 */
HWTEST_F(DeleteIdentityTest, BuildTokenRemoveDbOps006, TestSize.Level0)
{
    auto info = BuildInfoInner(TEST_TOKEN_ID, TEST_BUNDLE);
    info->SetRemote(true);
    std::vector<DelInfo> delInfoVec;
    std::vector<AddInfo> addInfoVec;
    DeleteBundleManager::BuildTokenRemoveDbOps(
        info, ReservedType::RESERVED_IDENTITY, delInfoVec, addInfoVec);

    EXPECT_TRUE(addInfoVec.empty());
    EXPECT_EQ(1u, CountDelInfo(delInfoVec, AtmDataType::ACCESSTOKEN_HAP_TOKEN_INFO));
}

/**
 * @tc.name: BuildBundleCleanDbOps001
 * @tc.desc: Another active token of the bundle keeps the package info row.
 * @tc.type: FUNC
 */
HWTEST_F(DeleteIdentityTest, BuildBundleCleanDbOps001, TestSize.Level0)
{
    auto info = BuildInfoInner(TEST_TOKEN_ID, TEST_BUNDLE);
    auto& tokenCache = AccessTokenInfoManager::GetInstance().hapTokenInfoMap_;
    tokenCache[TEST_TOKEN_ID] = info;
    AccessTokenIDManager::GetInstance().RegisterTokenId(TEST_TOKEN_ID, TOKEN_HAP);
    SetMockDbFindResult(AtmDataType::ACCESSTOKEN_HAP_TOKEN_INFO, RET_SUCCESS,
        { BuildTokenRow(TEST_OTHER_ID, TEST_BUNDLE, 0) });
    DeleteDfxInfo dfx = {};

    EXPECT_EQ(RET_SUCCESS, DeleteBundleManager::GetInstance().DeleteIdentityWithDfx(
        TEST_TOKEN_ID, TEST_BUNDLE, ReservedType::NONE, dfx));

    // The other active row keeps the package info: no package-info delete op.
    EXPECT_EQ(0u, CountDelInfo(GetMockDbState().lastDeleteInfos, AtmDataType::ACCESSTOKEN_HAP_PACKAGE_INFO));
    EXPECT_EQ(1u, CountDelInfo(GetMockDbState().lastDeleteInfos, AtmDataType::ACCESSTOKEN_HAP_TOKEN_INFO));
}

/**
 * @tc.name: BuildBundleCleanDbOps002
 * @tc.desc: No other active token appends the package info deletion and releases the bundleId.
 * @tc.type: FUNC
 */
HWTEST_F(DeleteIdentityTest, BuildBundleCleanDbOps002, TestSize.Level0)
{
    int32_t testUid = 20020000 + static_cast<int32_t>(TEST_TOKEN_ID % 45536); // same as BuildHapInfo
    int32_t bundleId = -1;
    ASSERT_TRUE(AccessTokenIDManager::GetInstance().ExtractBundleId(testUid, bundleId));
    auto& bundleIdSet = AccessTokenIDManager::GetInstance().bundleIdSet_;
    bundleIdSet.insert(bundleId); // simulate a registered bundle identity

    auto info = BuildInfoInner(TEST_TOKEN_ID, TEST_BUNDLE);
    auto& tokenCache = AccessTokenInfoManager::GetInstance().hapTokenInfoMap_;
    tokenCache[TEST_TOKEN_ID] = info;
    AccessTokenIDManager::GetInstance().RegisterTokenId(TEST_TOKEN_ID, TOKEN_HAP);
    DeleteDfxInfo dfx = {};

    EXPECT_EQ(RET_SUCCESS, DeleteBundleManager::GetInstance().DeleteIdentityWithDfx(
        TEST_TOKEN_ID, TEST_BUNDLE, ReservedType::RESERVED_IDENTITY, dfx));

    // The last trace is gone: the package info row is deleted in the same commit.
    EXPECT_EQ(1u, CountDelInfo(GetMockDbState().lastDeleteInfos, AtmDataType::ACCESSTOKEN_HAP_PACKAGE_INFO));
    // The judgment runs with the original (still valid) uid: the bundleId returns to the pool.
    EXPECT_EQ(0u, bundleIdSet.count(bundleId));
}

/**
 * @tc.name: BuildBundleCleanDbOps003
 * @tc.desc: RESERVED_DATA retains the uid, so the bundleId must not be released.
 * @tc.type: FUNC
 */
HWTEST_F(DeleteIdentityTest, BuildBundleCleanDbOps003, TestSize.Level0)
{
    int32_t testUid = 20020000 + static_cast<int32_t>(TEST_TOKEN_ID % 45536); // same as BuildHapInfo
    int32_t bundleId = -1;
    ASSERT_TRUE(AccessTokenIDManager::GetInstance().ExtractBundleId(testUid, bundleId));
    auto& bundleIdSet = AccessTokenIDManager::GetInstance().bundleIdSet_;
    bundleIdSet.insert(bundleId); // simulate a registered bundle identity

    auto info = BuildInfoInner(TEST_TOKEN_ID, TEST_BUNDLE);
    auto& tokenCache = AccessTokenInfoManager::GetInstance().hapTokenInfoMap_;
    tokenCache[TEST_TOKEN_ID] = info;
    AccessTokenIDManager::GetInstance().RegisterTokenId(TEST_TOKEN_ID, TOKEN_HAP);
    DeleteDfxInfo dfx = {};

    EXPECT_EQ(RET_SUCCESS, DeleteBundleManager::GetInstance().DeleteIdentityWithDfx(
        TEST_TOKEN_ID, TEST_BUNDLE, ReservedType::RESERVED_DATA, dfx));

    // The package info row is still ownerless and deleted ...
    EXPECT_EQ(1u, CountDelInfo(GetMockDbState().lastDeleteInfos, AtmDataType::ACCESSTOKEN_HAP_PACKAGE_INFO));
    // ... but the uid is retained with the data, so the bundleId stays in the pool.
    EXPECT_EQ(1u, bundleIdSet.count(bundleId));
}

/**
 * @tc.name: BuildBundleCleanDbOps004
 * @tc.desc: A failed token query propagates before any clean op is built.
 * @tc.type: FUNC
 */
HWTEST_F(DeleteIdentityTest, BuildBundleCleanDbOps004, TestSize.Level0)
{
    auto info = BuildInfoInner(TEST_TOKEN_ID, TEST_BUNDLE);
    auto& tokenCache = AccessTokenInfoManager::GetInstance().hapTokenInfoMap_;
    tokenCache[TEST_TOKEN_ID] = info;
    AccessTokenIDManager::GetInstance().RegisterTokenId(TEST_TOKEN_ID, TOKEN_HAP);
    SetMockDbFindResult(AtmDataType::ACCESSTOKEN_HAP_TOKEN_INFO, ERR_DATABASE_OPERATE_FAILED, {});
    DeleteDfxInfo dfx = {};

    EXPECT_EQ(ERR_DATABASE_OPERATE_FAILED, DeleteBundleManager::GetInstance().DeleteIdentityWithDfx(
        TEST_TOKEN_ID, TEST_BUNDLE, ReservedType::NONE, dfx));

    // Nothing is committed and the staged kernel removal is compensated.
    EXPECT_EQ(0u, GetMockDbState().deleteAndInsertCallCount);
    EXPECT_EQ(0u, CountDelInfo(GetMockDbState().lastDeleteInfos, AtmDataType::ACCESSTOKEN_HAP_PACKAGE_INFO));
    EXPECT_EQ(1, GetFakeSpmKernelState().removeCallCount);
    EXPECT_EQ(1, GetFakeSpmKernelState().addCallCount);
    tokenCache.erase(TEST_TOKEN_ID);
}

/**
 * @tc.name: BuildBundleDelDbOps001
 * @tc.desc: Whole-bundle deletion partitions active and reserved tokens and deletes the package info.
 * @tc.type: FUNC
 */
HWTEST_F(DeleteIdentityTest, BuildBundleDelDbOps001, TestSize.Level0)
{
    SetMockDbFindResult(AtmDataType::ACCESSTOKEN_HAP_TOKEN_INFO, RET_SUCCESS,
        { BuildTokenRow(TEST_TOKEN_ID, TEST_BUNDLE, 0), BuildTokenRow(TEST_OTHER_ID, TEST_BUNDLE, 0),
          BuildTokenRow(TEST_RESERVED_ID, TEST_BUNDLE, 1), BuildTokenRow(TEST_RESERVED_DATA_ID, TEST_BUNDLE, 2) });
    PermissionDataBrief::GetInstance().ReplaceBriefPermDataByTokenId(TEST_TOKEN_ID, BuildGrantedBrief(1), {});
    PermissionDataBrief::GetInstance().ReplaceBriefPermDataByTokenId(TEST_OTHER_ID, BuildGrantedBrief(1), {});
    AccessTokenIDManager::GetInstance().AddReservedTokenId(TEST_RESERVED_ID);
    AccessTokenIDManager::GetInstance().AddReservedTokenId(TEST_RESERVED_DATA_ID);
    DeleteDfxInfo dfx = {};

    EXPECT_EQ(RET_SUCCESS, DeleteBundleManager::GetInstance().DeleteIdentityWithDfx(
        INVALID_TOKENID, TEST_BUNDLE, ReservedType::NONE, dfx));

    EXPECT_EQ(static_cast<int32_t>(AT_DELETE_ALL_BUNDLE), dfx.sceneCode);
    // Only the two active tokens own kernel objects and stage a removal.
    EXPECT_EQ(2, GetFakeSpmKernelState().removeCallCount);
    EXPECT_EQ(4u, CountDelInfo(GetMockDbState().lastDeleteInfos, AtmDataType::ACCESSTOKEN_HAP_TOKEN_INFO));
    // The whole-bundle delete is a complete deletion for every token, so the
    // permission state goes for all of them regardless of the stored type.
    EXPECT_EQ(4u, CountDelInfo(GetMockDbState().lastDeleteInfos, AtmDataType::ACCESSTOKEN_PERMISSION_STATE));
    EXPECT_EQ(1u, CountDelInfo(GetMockDbState().lastDeleteInfos, AtmDataType::ACCESSTOKEN_HAP_PACKAGE_INFO));
    EXPECT_FALSE(AccessTokenIDManager::GetInstance().IsReservedTokenId(TEST_RESERVED_ID));
    EXPECT_FALSE(AccessTokenIDManager::GetInstance().IsReservedTokenId(TEST_RESERVED_DATA_ID));
}

/**
 * @tc.name: DeleteReservedToken002
 * @tc.desc: Case 2.1 rejects a bundleName that does not match the stored row.
 * @tc.type: FUNC
 */
HWTEST_F(DeleteIdentityTest, DeleteReservedToken002, TestSize.Level0)
{
    AccessTokenIDManager::GetInstance().AddReservedTokenId(TEST_RESERVED_ID);
    SetMockDbFindResult(AtmDataType::ACCESSTOKEN_HAP_TOKEN_INFO, RET_SUCCESS,
        { BuildTokenRow(TEST_RESERVED_ID, TEST_BUNDLE, 1) });
    DeleteDfxInfo dfx = {};

    EXPECT_EQ(AccessTokenError::ERR_PARAM_INVALID, DeleteBundleManager::GetInstance().DeleteIdentityWithDfx(
        TEST_RESERVED_ID, "com.example.other", ReservedType::NONE, dfx));

    EXPECT_EQ(static_cast<int32_t>(AT_DELETE_RESERVED_TOKEN), dfx.sceneCode);
    EXPECT_EQ(0u, GetMockDbState().deleteAndInsertCallCount);
    EXPECT_TRUE(AccessTokenIDManager::GetInstance().IsReservedTokenId(TEST_RESERVED_ID));
}

/**
 * @tc.name: DeleteReservedToken004
 * @tc.desc: A complete reserved-token delete removes the permission state even for a
 *           RESERVED_DATA-stored token: includePermissionState follows the deletion
 *           mode, not the token's stored type.
 * @tc.type: FUNC
 */
HWTEST_F(DeleteIdentityTest, DeleteReservedToken004, TestSize.Level0)
{
    AccessTokenIDManager::GetInstance().AddReservedTokenId(TEST_RESERVED_DATA_ID);
    SetMockDbFindResult(AtmDataType::ACCESSTOKEN_HAP_TOKEN_INFO, RET_SUCCESS,
        { BuildTokenRow(TEST_RESERVED_DATA_ID, TEST_BUNDLE, 2) });
    DeleteDfxInfo dfx = {};

    EXPECT_EQ(RET_SUCCESS, DeleteBundleManager::GetInstance().DeleteIdentityWithDfx(
        TEST_RESERVED_DATA_ID, TEST_BUNDLE, ReservedType::NONE, dfx));

    EXPECT_EQ(1u, CountDelInfo(GetMockDbState().lastDeleteInfos, AtmDataType::ACCESSTOKEN_PERMISSION_STATE));
    EXPECT_EQ(1u, CountDelInfo(GetMockDbState().lastDeleteInfos, AtmDataType::ACCESSTOKEN_HAP_TOKEN_INFO));
    EXPECT_FALSE(AccessTokenIDManager::GetInstance().IsReservedTokenId(TEST_RESERVED_DATA_ID));
}

/**
 * @tc.name: DeleteReservedToken003
 * @tc.desc: Case 2.1 surfaces a db failure and keeps the reserved id (F5.4).
 * @tc.type: FUNC
 */
HWTEST_F(DeleteIdentityTest, DeleteReservedToken003, TestSize.Level0)
{
    AccessTokenIDManager::GetInstance().AddReservedTokenId(TEST_RESERVED_ID);
    SetMockDbFindResult(AtmDataType::ACCESSTOKEN_HAP_TOKEN_INFO, RET_SUCCESS,
        { BuildTokenRow(TEST_RESERVED_ID, TEST_BUNDLE, 1) });
    GetMockDbState().deleteAndInsertRet = ERR_DATABASE_OPERATE_FAILED;
    DeleteDfxInfo dfx = {};

    EXPECT_NE(RET_SUCCESS, DeleteBundleManager::GetInstance().DeleteIdentityWithDfx(
        TEST_RESERVED_ID, TEST_BUNDLE, ReservedType::NONE, dfx));

    EXPECT_TRUE(AccessTokenIDManager::GetInstance().IsReservedTokenId(TEST_RESERVED_ID));
}

/**
 * @tc.name: DeleteActiveTokenInner001
 * @tc.desc: Case 2.2 success stages the kernel removal and commits the db ops once.
 * @tc.type: FUNC
 */
HWTEST_F(DeleteIdentityTest, DeleteActiveTokenInner001, TestSize.Level0)
{
    auto info = BuildInfoInner(TEST_TOKEN_ID, TEST_BUNDLE);
    auto& tokenCache = AccessTokenInfoManager::GetInstance().hapTokenInfoMap_;
    tokenCache[TEST_TOKEN_ID] = info;
    AccessTokenIDManager::GetInstance().RegisterTokenId(TEST_TOKEN_ID, TOKEN_HAP);
    // Two granted perms: the notification tail iterates exactly this list.
    uint32_t camCode = 0;
    uint32_t manageCode = 0;
    ASSERT_TRUE(TransferPermissionToOpcode("ohos.permission.CAMERA", camCode));
    ASSERT_TRUE(TransferPermissionToOpcode("ohos.permission.MANAGE_HAP_TOKENID", manageCode));
    std::vector<BriefPermData> briefs = BuildGrantedBrief(camCode);
    std::vector<BriefPermData> manageBriefs = BuildGrantedBrief(manageCode);
    briefs.insert(briefs.end(), manageBriefs.begin(), manageBriefs.end());
    PermissionDataBrief::GetInstance().ReplaceBriefPermDataByTokenId(TEST_TOKEN_ID, briefs, {});
    // The token is observed for the distributed delete sync.
    TokenModifyNotifier::GetInstance().observationSet_.insert(TEST_TOKEN_ID);
    DeleteDfxInfo dfx = {};

    // The revoke loop input carries exactly the two granted permissions.
    std::vector<std::string> grantedBefore;
    HapTokenInfoInner::GetGrantedPermList(TEST_TOKEN_ID, grantedBefore);
    ASSERT_EQ(2u, grantedBefore.size());
    uint64_t paramBefore = PermissionChangeNotifier::GetInstance().paramValue_;

    EXPECT_EQ(RET_SUCCESS, DeleteBundleManager::GetInstance().DeleteIdentityWithDfx(
        TEST_TOKEN_ID, TEST_BUNDLE, ReservedType::NONE, dfx));

    EXPECT_EQ(1, GetFakeSpmKernelState().removeCallCount);
    EXPECT_EQ(1, GetFakeSpmKernelState().removePermCallCount);
    EXPECT_EQ(1u, GetMockDbState().deleteAndInsertCallCount);
    EXPECT_EQ(0, GetFakeSpmKernelState().addCallCount); // no rollback on success
    EXPECT_EQ(0, GetFakeSpmKernelState().addPermCallCount);
    std::vector<BriefPermData> briefAfter;
    EXPECT_NE(RET_SUCCESS,
        PermissionDataBrief::GetInstance().GetBriefPermDataByTokenId(TEST_TOKEN_ID, briefAfter));
    // ParamUpdate carries the first granted permission only (legacy parity).
    EXPECT_EQ(paramBefore + 1, PermissionChangeNotifier::GetInstance().paramValue_);
    // The sync-notify path consumed the observation entry.
    EXPECT_EQ(0u, TokenModifyNotifier::GetInstance().observationSet_.count(TEST_TOKEN_ID));
}

/**
 * @tc.name: DeleteActiveTokenInner002
 * @tc.desc: Case 2.2 db failure returns an error and the destructor restores the kernel (F5.4).
 * @tc.type: FUNC
 */
HWTEST_F(DeleteIdentityTest, DeleteActiveTokenInner002, TestSize.Level0)
{
    auto info = BuildInfoInner(TEST_TOKEN_ID, TEST_BUNDLE);
    auto& tokenCache = AccessTokenInfoManager::GetInstance().hapTokenInfoMap_;
    tokenCache[TEST_TOKEN_ID] = info;
    AccessTokenIDManager::GetInstance().RegisterTokenId(TEST_TOKEN_ID, TOKEN_HAP);
    PermissionDataBrief::GetInstance().ReplaceBriefPermDataByTokenId(TEST_TOKEN_ID, BuildGrantedBrief(1), {});
    GetMockDbState().deleteAndInsertRet = ERR_DATABASE_OPERATE_FAILED;
    DeleteDfxInfo dfx = {};

    EXPECT_NE(RET_SUCCESS, DeleteBundleManager::GetInstance().DeleteIdentityWithDfx(
        TEST_TOKEN_ID, TEST_BUNDLE, ReservedType::NONE, dfx));

    // The removal was staged and the rollback restored both kernel objects.
    EXPECT_EQ(1, GetFakeSpmKernelState().removeCallCount);
    EXPECT_EQ(1, GetFakeSpmKernelState().removePermCallCount);
    EXPECT_EQ(1, GetFakeSpmKernelState().addCallCount);
    EXPECT_EQ(1, GetFakeSpmKernelState().addPermCallCount);
    EXPECT_EQ(1u, GetMockDbState().deleteAndInsertCallCount);
    // The brief survives: the cache is only committed after a successful CommitDb.
    std::vector<BriefPermData> briefAfter;
    EXPECT_EQ(RET_SUCCESS,
        PermissionDataBrief::GetInstance().GetBriefPermDataByTokenId(TEST_TOKEN_ID, briefAfter));
    EXPECT_EQ(1u, briefAfter.size());
}

/**
 * @tc.name: DeleteActiveTokenInner003
 * @tc.desc: A NONE delete drops the policy whitelist entry inside the same transaction.
 * @tc.type: FUNC
 */
HWTEST_F(DeleteIdentityTest, DeleteActiveTokenInner003, TestSize.Level0)
{
    uint32_t permCode = 0;
    ASSERT_TRUE(TransferPermissionToOpcode("ohos.permission.MANAGE_HAP_TOKENID", permCode));
    UserPolicyRecord record;
    record.isPersist = true;
    record.controllerToken = TEST_TOKEN_ID;
    record.whiteList = { TEST_TOKEN_ID, TEST_OTHER_ID };
    std::map<uint32_t, UserPolicyRecord> policyRecords;
    policyRecords[permCode] = record;
    UserPolicyManager::GetInstance().userPolicyRecords_ = policyRecords;

    auto info = BuildInfoInner(TEST_TOKEN_ID, TEST_BUNDLE);
    auto& tokenCache = AccessTokenInfoManager::GetInstance().hapTokenInfoMap_;
    tokenCache[TEST_TOKEN_ID] = info;
    AccessTokenIDManager::GetInstance().RegisterTokenId(TEST_TOKEN_ID, TOKEN_HAP);
    PermissionDataBrief::GetInstance().ReplaceBriefPermDataByTokenId(TEST_TOKEN_ID, BuildGrantedBrief(1), {});
    DeleteDfxInfo dfx = {};

    EXPECT_EQ(RET_SUCCESS, DeleteBundleManager::GetInstance().DeleteIdentityWithDfx(
        TEST_TOKEN_ID, TEST_BUNDLE, ReservedType::NONE, dfx));

    // The whitelist row re-insert joined the same CommitDb as the token delete.
    bool hasPolicyReinsert = false;
    for (const auto& addInfo : GetMockDbState().lastAddInfos) {
        if (addInfo.addType == AtmDataType::ACCESSTOKEN_USER_POLICY) {
            hasPolicyReinsert = true;
            EXPECT_EQ(1u, addInfo.addValues.size());
        }
    }
    EXPECT_TRUE(hasPolicyReinsert);
    // The in-memory half is published: the deleted id is gone, the peer survives.
    std::vector<AccessTokenID> whiteList;
    EXPECT_EQ(RET_SUCCESS, UserPolicyManager::GetInstance().GetPolicyWhiteList(permCode, whiteList));
    EXPECT_EQ(1u, whiteList.size());
    EXPECT_EQ(TEST_OTHER_ID, whiteList[0]);
    UserPolicyManager::GetInstance().userPolicyRecords_.clear();
}

/**
 * @tc.name: DeleteActiveToken002
 * @tc.desc: An unknown token id is reported as not existing.
 * @tc.type: FUNC
 */
HWTEST_F(DeleteIdentityTest, DeleteActiveToken002, TestSize.Level0)
{
    // Isolate from any earlier case that injected a cache entry for this id.
    AccessTokenInfoManager::GetInstance().hapTokenInfoMap_.erase(TEST_TOKEN_ID);
    DeleteDfxInfo dfx = {};

    EXPECT_EQ(AccessTokenError::ERR_TOKENID_NOT_EXIST, DeleteBundleManager::GetInstance().DeleteIdentityWithDfx(
        TEST_TOKEN_ID, TEST_BUNDLE, ReservedType::NONE, dfx));

    EXPECT_EQ(static_cast<int32_t>(AT_DELETE_NORMAL), dfx.sceneCode);
    // Not-found keeps the default coordinates ("found means filled").
    EXPECT_EQ(0, dfx.userId);
    EXPECT_EQ(0, dfx.instIndex);
    EXPECT_EQ(0u, GetMockDbState().deleteAndInsertCallCount);
}

/**
 * @tc.name: DeleteActiveToken003
 * @tc.desc: A bundleName that does not own the token is rejected.
 * @tc.type: FUNC
 */
HWTEST_F(DeleteIdentityTest, DeleteActiveToken003, TestSize.Level0)
{
    HapTokenInfo hapInfo = BuildHapInfo(TEST_TOKEN_ID, TEST_BUNDLE);
    hapInfo.instIndex = 1; // distinguishable from the default coordinate
    auto info = std::make_shared<HapTokenInfoInner>(TEST_TOKEN_ID, hapInfo, std::vector<PermissionStatus>());
    auto& tokenCache = AccessTokenInfoManager::GetInstance().hapTokenInfoMap_;
    tokenCache[TEST_TOKEN_ID] = info;
    AccessTokenIDManager::GetInstance().RegisterTokenId(TEST_TOKEN_ID, TOKEN_HAP);
    DeleteDfxInfo dfx = {};

    EXPECT_EQ(AccessTokenError::ERR_PARAM_INVALID, DeleteBundleManager::GetInstance().DeleteIdentityWithDfx(
        TEST_TOKEN_ID, "com.example.other", ReservedType::NONE, dfx));

    EXPECT_EQ(static_cast<int32_t>(AT_DELETE_NORMAL), dfx.sceneCode);
    // The coordinates were filled before the rejection ("found means filled").
    EXPECT_EQ(hapInfo.userID, dfx.userId);
    EXPECT_EQ(hapInfo.instIndex, dfx.instIndex);
    tokenCache.erase(TEST_TOKEN_ID);
    EXPECT_EQ(0u, GetMockDbState().deleteAndInsertCallCount);
}

/**
 * @tc.name: DeleteActiveToken004
 * @tc.desc: A remote hap token identity is rejected with ERR_PARAM_INVALID.
 * @tc.type: FUNC
 */
HWTEST_F(DeleteIdentityTest, DeleteActiveToken004, TestSize.Level0)
{
    HapTokenInfo hapInfo = BuildHapInfo(TEST_TOKEN_ID, TEST_BUNDLE);
    hapInfo.instIndex = 1; // distinguishable from the default coordinate
    auto info = std::make_shared<HapTokenInfoInner>(TEST_TOKEN_ID, hapInfo, std::vector<PermissionStatus>());
    info->SetRemote(true);
    auto& tokenCache = AccessTokenInfoManager::GetInstance().hapTokenInfoMap_;
    tokenCache[TEST_TOKEN_ID] = info;
    AccessTokenIDManager::GetInstance().RegisterTokenId(TEST_TOKEN_ID, TOKEN_HAP);
    DeleteDfxInfo dfx = {};

    EXPECT_EQ(ERR_PARAM_INVALID, DeleteBundleManager::GetInstance().DeleteIdentityWithDfx(
        TEST_TOKEN_ID, TEST_BUNDLE, ReservedType::NONE, dfx));

    EXPECT_EQ(static_cast<int32_t>(AT_DELETE_NORMAL), dfx.sceneCode);
    // The coordinates were filled before the rejection ("found means filled").
    EXPECT_EQ(hapInfo.userID, dfx.userId);
    EXPECT_EQ(hapInfo.instIndex, dfx.instIndex);
    tokenCache.erase(TEST_TOKEN_ID);
    EXPECT_EQ(0u, GetMockDbState().deleteAndInsertCallCount);
}

/**
 * @tc.name: ServiceDeleteIdentityPermDenied001
 * @tc.desc: The service entry rejects a caller without MANAGE_HAP_TOKENID_PERMISSION.
 * @tc.type: FUNC
 */
HWTEST_F(DeleteIdentityTest, ServiceDeleteIdentityPermDenied001, TestSize.Level0)
{
    // The in-process caller holds no MANAGE_HAP_TOKENID_PERMISSION, so the
    // service-layer check rejects before any dispatch.
    EXPECT_EQ(AccessTokenError::ERR_PERMISSION_DENIED,
        DelayedSingleton<AccessTokenManagerService>::GetInstance()->DeleteIdentity(
            TEST_TOKEN_ID, TEST_BUNDLE, ReservedTypeIdl::NONE));
    EXPECT_EQ(0u, GetMockDbState().deleteAndInsertCallCount);
}

/**
 * @tc.name: DeleteIdentityWithDfx004
 * @tc.desc: Case 2.2 RESERVED_IDENTITY dispatch sets the scene and reserves the row;
 *           non-persist whitelist records are cleaned in memory without db ops and
 *           unresolvable perm codes are skipped defensively.
 * @tc.type: FUNC
 */
HWTEST_F(DeleteIdentityTest, DeleteIdentityWithDfx004, TestSize.Level0)
{
    uint32_t permCode = 0;
    ASSERT_TRUE(TransferPermissionToOpcode("ohos.permission.MANAGE_HAP_TOKENID", permCode));
    UserPolicyRecord memRecord;
    memRecord.isPersist = false;
    memRecord.whiteList = { TEST_TOKEN_ID };
    UserPolicyRecord bogusRecord;
    bogusRecord.isPersist = true;
    bogusRecord.whiteList = { TEST_TOKEN_ID };
    std::map<uint32_t, UserPolicyRecord> policyRecords;
    policyRecords[permCode] = memRecord;
    policyRecords[999999] = bogusRecord; // unresolvable code: ops must be skipped
    UserPolicyManager::GetInstance().userPolicyRecords_ = policyRecords;

    auto info = BuildInfoInner(TEST_TOKEN_ID, TEST_BUNDLE);
    auto& tokenCache = AccessTokenInfoManager::GetInstance().hapTokenInfoMap_;
    tokenCache[TEST_TOKEN_ID] = info;
    AccessTokenIDManager::GetInstance().RegisterTokenId(TEST_TOKEN_ID, TOKEN_HAP);
    DeleteDfxInfo dfx = {};
    EXPECT_EQ(RET_SUCCESS, DeleteBundleManager::GetInstance().DeleteIdentityWithDfx(
        TEST_TOKEN_ID, TEST_BUNDLE, ReservedType::RESERVED_IDENTITY, dfx));
    EXPECT_EQ(static_cast<int32_t>(AT_DELETE_KEEP_TOKEN_FINISH), dfx.sceneCode);
    EXPECT_EQ(BuildHapInfo(TEST_TOKEN_ID, TEST_BUNDLE).userID, dfx.userId);
    EXPECT_EQ(BuildHapInfo(TEST_TOKEN_ID, TEST_BUNDLE).instIndex, dfx.instIndex);
    tokenCache.erase(TEST_TOKEN_ID);
    // The reserved id is registered (see the spec: reinstall
    // allocates a fresh id). SPM keeps no in-memory index: the db row carries
    // the reserved state, so assert the id-set registration instead.
    EXPECT_TRUE(AccessTokenIDManager::GetInstance().IsReservedTokenId(TEST_TOKEN_ID));

    // The token row is re-inserted with the reserved flag; perm state deleted.
    bool hasHapReinsert = false;
    for (const auto& addInfo : GetMockDbState().lastAddInfos) {
        if (addInfo.addType == AtmDataType::ACCESSTOKEN_HAP_TOKEN_INFO) {
            hasHapReinsert = true;
            ASSERT_EQ(1u, addInfo.addValues.size());
            EXPECT_EQ(static_cast<int32_t>(ReservedType::RESERVED_IDENTITY),
                addInfo.addValues[0].GetInt(TokenFiledConst::FIELD_RESERVED));
        }
        EXPECT_NE(AtmDataType::ACCESSTOKEN_USER_POLICY, addInfo.addType);
    }
    EXPECT_TRUE(hasHapReinsert);
    EXPECT_EQ(1u, CountDelInfo(GetMockDbState().lastDeleteInfos, AtmDataType::ACCESSTOKEN_PERMISSION_STATE));
    // Memory half is published: the resolvable record's whitelist is empty now.
    std::vector<AccessTokenID> whiteList;
    EXPECT_EQ(RET_SUCCESS, UserPolicyManager::GetInstance().GetPolicyWhiteList(permCode, whiteList));
    EXPECT_TRUE(whiteList.empty());
    UserPolicyManager::GetInstance().userPolicyRecords_.clear();
}

/**
 * @tc.name: DeleteIdentityWithDfx005
 * @tc.desc: Case 2.1 dispatch succeeds for a reserved token and reports the scene.
 * @tc.type: FUNC
 */
HWTEST_F(DeleteIdentityTest, DeleteIdentityWithDfx005, TestSize.Level0)
{
    // RESERVED_IDENTITY-stored rows keep uid=-1: the re-insert writes the
    // unavailable uid and the bundleId went back to the pool at reserve time.
    GenericValues row = BuildTokenRow(TEST_RESERVED_ID, TEST_BUNDLE, 1);
    row.Remove(TokenFiledConst::FIELD_UID);
    row.Put(TokenFiledConst::FIELD_UID, -1);
    SetMockDbFindResult(AtmDataType::ACCESSTOKEN_HAP_TOKEN_INFO, RET_SUCCESS, { row });
    // Sentinel: rule B2 must keep the unavailable uid out of the pool release.
    auto& bundleIdSet = AccessTokenIDManager::GetInstance().bundleIdSet_;
    bundleIdSet.insert(-1);
    AccessTokenIDManager::GetInstance().AddReservedTokenId(TEST_RESERVED_ID);
    DeleteDfxInfo dfx = {};
    EXPECT_EQ(RET_SUCCESS, DeleteBundleManager::GetInstance().DeleteIdentityWithDfx(
        TEST_RESERVED_ID, TEST_BUNDLE, ReservedType::NONE, dfx));
    EXPECT_EQ(static_cast<int32_t>(AT_DELETE_RESERVED_TOKEN), dfx.sceneCode);
    EXPECT_EQ(1u, GetMockDbState().deleteAndInsertCallCount);
    EXPECT_FALSE(AccessTokenIDManager::GetInstance().IsReservedTokenId(TEST_RESERVED_ID));
    // The last trace is gone: the package info row is deleted (rule A2) ...
    EXPECT_EQ(1u, CountDelInfo(GetMockDbState().lastDeleteInfos, AtmDataType::ACCESSTOKEN_HAP_PACKAGE_INFO));
    // ... but the unavailable uid never reaches the pool release (rule B2).
    EXPECT_EQ(1u, bundleIdSet.count(-1));
}

/**
 * @tc.name: DeleteActiveTokenInner004
 * @tc.desc: RESERVED_DATA keeps the policy whitelist entirely: no ops, memory untouched.
 * @tc.type: FUNC
 */
HWTEST_F(DeleteIdentityTest, DeleteActiveTokenInner004, TestSize.Level0)
{
    uint32_t permCode = 0;
    ASSERT_TRUE(TransferPermissionToOpcode("ohos.permission.MANAGE_HAP_TOKENID", permCode));
    UserPolicyRecord persistRecord;
    persistRecord.isPersist = true;
    persistRecord.whiteList = { TEST_TOKEN_ID, TEST_OTHER_ID };
    std::map<uint32_t, UserPolicyRecord> policyRecords;
    policyRecords[permCode] = persistRecord;
    UserPolicyManager::GetInstance().userPolicyRecords_ = policyRecords;

    auto info = BuildInfoInner(TEST_TOKEN_ID, TEST_BUNDLE);
    auto& tokenCache = AccessTokenInfoManager::GetInstance().hapTokenInfoMap_;
    tokenCache[TEST_TOKEN_ID] = info;
    AccessTokenIDManager::GetInstance().RegisterTokenId(TEST_TOKEN_ID, TOKEN_HAP);
    PermissionDataBrief::GetInstance().ReplaceBriefPermDataByTokenId(TEST_TOKEN_ID, BuildGrantedBrief(1), {});
    DeleteDfxInfo dfx = {};

    EXPECT_EQ(RET_SUCCESS, DeleteBundleManager::GetInstance().DeleteIdentityWithDfx(
        TEST_TOKEN_ID, TEST_BUNDLE, ReservedType::RESERVED_DATA, dfx));

    // No whitelist ops at all and no permission-state deletion (RESERVED_DATA).
    for (const auto& addInfo : GetMockDbState().lastAddInfos) {
        EXPECT_NE(AtmDataType::ACCESSTOKEN_USER_POLICY, addInfo.addType);
    }
    EXPECT_EQ(0u, CountDelInfo(GetMockDbState().lastDeleteInfos, AtmDataType::ACCESSTOKEN_PERMISSION_STATE));
    // The whitelist survives with both ids.
    std::vector<AccessTokenID> whiteList;
    EXPECT_EQ(RET_SUCCESS, UserPolicyManager::GetInstance().GetPolicyWhiteList(permCode, whiteList));
    EXPECT_EQ(2u, whiteList.size());
    UserPolicyManager::GetInstance().userPolicyRecords_.clear();
}

/**
 * @tc.name: DeleteWholeBundle006
 * @tc.desc: A whole-bundle delete returns the bundleId it occupied to the pool.
 * @tc.type: FUNC
 */
HWTEST_F(DeleteIdentityTest, DeleteWholeBundle006, TestSize.Level0)
{
    int32_t testUid = 20020000 + static_cast<int32_t>(TEST_TOKEN_ID % 45536); // same as BuildTokenRow
    int32_t bundleId = -1;
    ASSERT_TRUE(AccessTokenIDManager::GetInstance().ExtractBundleId(testUid, bundleId));
    auto& bundleIdSet = AccessTokenIDManager::GetInstance().bundleIdSet_;
    bundleIdSet.insert(bundleId); // simulate a registered bundle identity

    SetMockDbFindResult(AtmDataType::ACCESSTOKEN_HAP_TOKEN_INFO, RET_SUCCESS,
        { BuildTokenRow(TEST_TOKEN_ID, TEST_BUNDLE, 0) });
    DeleteDfxInfo dfx = {};
    EXPECT_EQ(RET_SUCCESS, DeleteBundleManager::GetInstance().DeleteIdentityWithDfx(
        INVALID_TOKENID, TEST_BUNDLE, ReservedType::NONE, dfx));

    // The bundle is gone, so its bundleId must not linger in the pool.
    EXPECT_EQ(0u, bundleIdSet.count(bundleId));
}

/**
 * @tc.name: DeleteWholeBundle007
 * @tc.desc: A whole-bundle delete with granted permissions runs the full
 *           notification tail (param update, per-permission callbacks, sync).
 * @tc.type: FUNC
 */
HWTEST_F(DeleteIdentityTest, DeleteWholeBundle007, TestSize.Level0)
{
    SetMockDbFindResult(AtmDataType::ACCESSTOKEN_HAP_TOKEN_INFO, RET_SUCCESS,
        { BuildTokenRow(TEST_TOKEN_ID, TEST_BUNDLE, 0) });
    PermissionDataBrief::GetInstance().ReplaceBriefPermDataByTokenId(TEST_TOKEN_ID, BuildGrantedBrief(1), {});
    DeleteDfxInfo dfx = {};

    EXPECT_EQ(RET_SUCCESS, DeleteBundleManager::GetInstance().DeleteIdentityWithDfx(
        INVALID_TOKENID, TEST_BUNDLE, ReservedType::NONE, dfx));

    // Deep callback assertions need a mock CallbackManager; the granted-list
    // capture path and the notification tail executing without a crash are
    // verified here (the brief existed, so the tail ran the non-empty path).
    EXPECT_EQ(1, GetFakeSpmKernelState().removeCallCount);
    EXPECT_EQ(1u, GetMockDbState().deleteAndInsertCallCount);
}

/**
 * @tc.name: DeleteReservedToken008
 * @tc.desc: Case 2.1 clears the reserved-id index and returns the bundleId to
 *           the pool when the token was the bundle's last trace.
 * @tc.type: FUNC
 */
HWTEST_F(DeleteIdentityTest, DeleteReservedToken008, TestSize.Level0)
{
    int32_t testUid = 20020000 + static_cast<int32_t>(TEST_RESERVED_DATA_ID % 45536); // same as BuildTokenRow
    int32_t bundleId = -1;
    ASSERT_TRUE(AccessTokenIDManager::GetInstance().ExtractBundleId(testUid, bundleId));
    auto& bundleIdSet = AccessTokenIDManager::GetInstance().bundleIdSet_;
    bundleIdSet.insert(bundleId); // simulate a registered bundle identity

    GenericValues row = BuildTokenRow(TEST_RESERVED_DATA_ID, TEST_BUNDLE, 2); // RESERVED_DATA keeps uid
    SetMockDbFindResult(AtmDataType::ACCESSTOKEN_HAP_TOKEN_INFO, RET_SUCCESS, { row });
    // Register the reserved identity (SPM: id-set only; the db row carries
    // the identity triple for the reinstall lookup).
    AccessTokenIDManager::GetInstance().AddReservedTokenId(TEST_RESERVED_DATA_ID);

    DeleteDfxInfo dfx = {};
    EXPECT_EQ(RET_SUCCESS, DeleteBundleManager::GetInstance().DeleteIdentityWithDfx(
        TEST_RESERVED_DATA_ID, TEST_BUNDLE, ReservedType::NONE, dfx));

    // The reserved id-set entry is gone (the db row was deleted with it).
    EXPECT_FALSE(AccessTokenIDManager::GetInstance().IsReservedTokenId(TEST_RESERVED_DATA_ID));
    // The bundleId went back to the pool.
    EXPECT_EQ(0u, bundleIdSet.count(bundleId));
    // DFX coordinates were carried out from the db row.
    EXPECT_EQ(row.GetInt(TokenFiledConst::FIELD_USER_ID), dfx.userId);
    EXPECT_EQ(row.GetInt(TokenFiledConst::FIELD_INST_INDEX), dfx.instIndex);
}

/**
 * @tc.name: DeleteWholeBundle004
 * @tc.desc: An empty bundle still commits the package-info delete without kernel staging.
 * @tc.type: FUNC
 */
HWTEST_F(DeleteIdentityTest, DeleteWholeBundle004, TestSize.Level0)
{
    SetMockDbFindResult(AtmDataType::ACCESSTOKEN_HAP_TOKEN_INFO, RET_SUCCESS, {});
    DeleteDfxInfo dfx = {};
    EXPECT_EQ(RET_SUCCESS, DeleteBundleManager::GetInstance().DeleteIdentityWithDfx(
        INVALID_TOKENID, TEST_BUNDLE, ReservedType::NONE, dfx));

    EXPECT_EQ(0, GetFakeSpmKernelState().removeCallCount);
    EXPECT_EQ(1u, GetMockDbState().deleteAndInsertCallCount);
    EXPECT_EQ(1u, CountDelInfo(GetMockDbState().lastDeleteInfos, AtmDataType::ACCESSTOKEN_HAP_PACKAGE_INFO));
}

/**
 * @tc.name: DeleteWholeBundle005
 * @tc.desc: A failed token query aborts the whole-bundle delete before staging.
 * @tc.type: FUNC
 */
HWTEST_F(DeleteIdentityTest, DeleteWholeBundle005, TestSize.Level0)
{
    SetMockDbFindResult(AtmDataType::ACCESSTOKEN_HAP_TOKEN_INFO, ERR_DATABASE_OPERATE_FAILED, {});
    DeleteDfxInfo dfx = {};
    EXPECT_EQ(ERR_DATABASE_OPERATE_FAILED, DeleteBundleManager::GetInstance().DeleteIdentityWithDfx(
        INVALID_TOKENID, TEST_BUNDLE, ReservedType::NONE, dfx));

    EXPECT_EQ(0, GetFakeSpmKernelState().removeCallCount);
    EXPECT_EQ(0u, GetMockDbState().deleteAndInsertCallCount);
}

/**
 * @tc.name: DeleteReservedToken006
 * @tc.desc: A failed token query keeps the reserved id and surfaces the error.
 * @tc.type: FUNC
 */
HWTEST_F(DeleteIdentityTest, DeleteReservedToken006, TestSize.Level0)
{
    AccessTokenIDManager::GetInstance().AddReservedTokenId(TEST_RESERVED_ID);
    SetMockDbFindResult(AtmDataType::ACCESSTOKEN_HAP_TOKEN_INFO, ERR_DATABASE_OPERATE_FAILED, {});
    DeleteDfxInfo dfx = {};

    EXPECT_EQ(ERR_DATABASE_OPERATE_FAILED, DeleteBundleManager::GetInstance().DeleteIdentityWithDfx(
        TEST_RESERVED_ID, TEST_BUNDLE, ReservedType::NONE, dfx));

    EXPECT_TRUE(AccessTokenIDManager::GetInstance().IsReservedTokenId(TEST_RESERVED_ID));
    EXPECT_EQ(0u, GetMockDbState().deleteAndInsertCallCount);
}

/**
 * @tc.name: DeleteReservedToken007
 * @tc.desc: A missing db row is idempotent: the reserved id is still released.
 * @tc.type: FUNC
 */
HWTEST_F(DeleteIdentityTest, DeleteReservedToken007, TestSize.Level0)
{
    AccessTokenIDManager::GetInstance().AddReservedTokenId(TEST_RESERVED_ID);
    SetMockDbFindResult(AtmDataType::ACCESSTOKEN_HAP_TOKEN_INFO, RET_SUCCESS, {});
    DeleteDfxInfo dfx = {};

    EXPECT_EQ(RET_SUCCESS, DeleteBundleManager::GetInstance().DeleteIdentityWithDfx(
        TEST_RESERVED_ID, TEST_BUNDLE, ReservedType::NONE, dfx));

    EXPECT_FALSE(AccessTokenIDManager::GetInstance().IsReservedTokenId(TEST_RESERVED_ID));
    EXPECT_EQ(1u, GetMockDbState().deleteAndInsertCallCount);
}

/**
 * @tc.name: DeleteWholeBundle001
 * @tc.desc: Whole-bundle deletion stages kernel removal only for active tokens (F6.6).
 * @tc.type: FUNC
 */
HWTEST_F(DeleteIdentityTest, DeleteWholeBundle001, TestSize.Level0)
{
    uint32_t permCode = 0;
    ASSERT_TRUE(TransferPermissionToOpcode("ohos.permission.MANAGE_HAP_TOKENID", permCode));
    // The policy whitelist carries ACTIVE tokens only: reserved tokens lost
    // their entries at reserve time (Case 2.2 drops them for non-RESERVED_DATA).
    UserPolicyRecord record;
    record.isPersist = true;
    record.whiteList = { TEST_TOKEN_ID };
    std::map<uint32_t, UserPolicyRecord> policyRecords;
    policyRecords[permCode] = record;
    UserPolicyManager::GetInstance().userPolicyRecords_ = policyRecords;

    SetMockDbFindResult(AtmDataType::ACCESSTOKEN_HAP_TOKEN_INFO, RET_SUCCESS,
        { BuildTokenRow(TEST_TOKEN_ID, TEST_BUNDLE, 0), BuildTokenRow(TEST_RESERVED_ID, TEST_BUNDLE, 1) });
    PermissionDataBrief::GetInstance().ReplaceBriefPermDataByTokenId(TEST_TOKEN_ID, BuildGrantedBrief(1), {});
    AccessTokenIDManager::GetInstance().AddReservedTokenId(TEST_RESERVED_ID);
    DeleteDfxInfo dfx = {};

    EXPECT_EQ(RET_SUCCESS, DeleteBundleManager::GetInstance().DeleteIdentityWithDfx(
        INVALID_TOKENID, TEST_BUNDLE, ReservedType::NONE, dfx));

    // Only the active token owns kernel objects; the reserved one stages nothing.
    EXPECT_EQ(1, GetFakeSpmKernelState().removeCallCount);
    EXPECT_EQ(1, GetFakeSpmKernelState().removePermCallCount);
    EXPECT_EQ(0, GetFakeSpmKernelState().addCallCount); // success: no rollback happens
    EXPECT_EQ(1u, GetMockDbState().deleteAndInsertCallCount);
    EXPECT_FALSE(AccessTokenIDManager::GetInstance().IsReservedTokenId(TEST_RESERVED_ID));
    std::vector<BriefPermData> briefAfter;
    EXPECT_NE(RET_SUCCESS,
        PermissionDataBrief::GetInstance().GetBriefPermDataByTokenId(TEST_TOKEN_ID, briefAfter));
    // The active token's whitelist entry is dropped in the same commit; the
    // reserved token never carried one.
    std::vector<AccessTokenID> whiteList;
    EXPECT_EQ(RET_SUCCESS, UserPolicyManager::GetInstance().GetPolicyWhiteList(permCode, whiteList));
    EXPECT_TRUE(whiteList.empty());
    UserPolicyManager::GetInstance().userPolicyRecords_.clear();
}

/**
 * @tc.name: DeleteWholeBundle002
 * @tc.desc: Whole-bundle db failure restores every staged kernel object (F6.6 rollback).
 * @tc.type: FUNC
 */
HWTEST_F(DeleteIdentityTest, DeleteWholeBundle002, TestSize.Level0)
{
    SetMockDbFindResult(AtmDataType::ACCESSTOKEN_HAP_TOKEN_INFO, RET_SUCCESS,
        { BuildTokenRow(TEST_TOKEN_ID, TEST_BUNDLE, 0), BuildTokenRow(TEST_RESERVED_ID, TEST_BUNDLE, 1) });
    PermissionDataBrief::GetInstance().ReplaceBriefPermDataByTokenId(TEST_TOKEN_ID, BuildGrantedBrief(1), {});
    AccessTokenIDManager::GetInstance().AddReservedTokenId(TEST_RESERVED_ID);
    GetMockDbState().deleteAndInsertRet = ERR_DATABASE_OPERATE_FAILED;
    DeleteDfxInfo dfx = {};

    EXPECT_NE(RET_SUCCESS, DeleteBundleManager::GetInstance().DeleteIdentityWithDfx(
        INVALID_TOKENID, TEST_BUNDLE, ReservedType::NONE, dfx));

    // The staged removal is compensated: both kernel objects come back.
    EXPECT_EQ(1, GetFakeSpmKernelState().removeCallCount);
    EXPECT_EQ(1, GetFakeSpmKernelState().addCallCount);     // spm entry restored
    EXPECT_EQ(1, GetFakeSpmKernelState().addPermCallCount); // bitmap restored from captured brief
    // The restored bitmap carries the seeded permission code, not just any call.
    ASSERT_EQ(1u, GetFakeSpmKernelState().addPermOpCodeBatches.size());
    ASSERT_EQ(1u, GetFakeSpmKernelState().addPermOpCodeBatches[0].size());
    EXPECT_EQ(1u, GetFakeSpmKernelState().addPermOpCodeBatches[0][0]);
    EXPECT_EQ(1u, GetMockDbState().deleteAndInsertCallCount);
    // Memory state stays untouched: the reserved id is still reserved, the brief survives.
    EXPECT_TRUE(AccessTokenIDManager::GetInstance().IsReservedTokenId(TEST_RESERVED_ID));
    std::vector<BriefPermData> briefAfter;
    EXPECT_EQ(RET_SUCCESS,
        PermissionDataBrief::GetInstance().GetBriefPermDataByTokenId(TEST_TOKEN_ID, briefAfter));
    EXPECT_EQ(1u, briefAfter.size());
}

/**
 * @tc.name: DeleteWholeBundle003
 * @tc.desc: A reserved-only bundle stages no kernel removal at all.
 * @tc.type: FUNC
 */
HWTEST_F(DeleteIdentityTest, DeleteWholeBundle003, TestSize.Level0)
{
    SetMockDbFindResult(AtmDataType::ACCESSTOKEN_HAP_TOKEN_INFO, RET_SUCCESS,
        { BuildTokenRow(TEST_RESERVED_ID, TEST_BUNDLE, 1) });
    AccessTokenIDManager::GetInstance().AddReservedTokenId(TEST_RESERVED_ID);
    DeleteDfxInfo dfx = {};

    EXPECT_EQ(RET_SUCCESS, DeleteBundleManager::GetInstance().DeleteIdentityWithDfx(
        INVALID_TOKENID, TEST_BUNDLE, ReservedType::NONE, dfx));

    EXPECT_EQ(0, GetFakeSpmKernelState().removeCallCount);
    EXPECT_EQ(0, GetFakeSpmKernelState().removePermCallCount);
    EXPECT_EQ(1u, GetMockDbState().deleteAndInsertCallCount);
    EXPECT_FALSE(AccessTokenIDManager::GetInstance().IsReservedTokenId(TEST_RESERVED_ID));
}

/**
 * @tc.name: DeleteIdentityWithDfx001
 * @tc.desc: Case 1 rejects a non-NONE reserved type and sets the ALL_BUNDLE scene.
 * @tc.type: FUNC
 */
HWTEST_F(DeleteIdentityTest, DeleteIdentityWithDfx001, TestSize.Level0)
{
    DeleteDfxInfo dfx = {};
    EXPECT_EQ(AccessTokenError::ERR_PARAM_INVALID,
        DeleteBundleManager::GetInstance().DeleteIdentityWithDfx(
            INVALID_TOKENID, TEST_BUNDLE, ReservedType::RESERVED_IDENTITY, dfx));
    EXPECT_EQ(static_cast<int32_t>(AT_DELETE_ALL_BUNDLE), dfx.sceneCode);
    EXPECT_EQ(0u, GetMockDbState().deleteAndInsertCallCount);
}

/**
 * @tc.name: DeleteIdentityWithDfx002
 * @tc.desc: A non-hap token id is rejected by the dispatcher.
 * @tc.type: FUNC
 */
HWTEST_F(DeleteIdentityTest, DeleteIdentityWithDfx002, TestSize.Level0)
{
    DeleteDfxInfo dfx = {};
    EXPECT_EQ(AccessTokenError::ERR_PARAM_INVALID,
        DeleteBundleManager::GetInstance().DeleteIdentityWithDfx(
            BuildNonHapTokenId(), TEST_BUNDLE, ReservedType::NONE, dfx));
    EXPECT_EQ(static_cast<int32_t>(AT_DELETE_COMMON_FINISH), dfx.sceneCode);
    EXPECT_EQ(0u, GetMockDbState().deleteAndInsertCallCount);
}

/**
 * @tc.name: DeleteIdentityWithDfx003
 * @tc.desc: Case 2.1 rejects a non-NONE reserved type for a reserved token.
 * @tc.type: FUNC
 */
HWTEST_F(DeleteIdentityTest, DeleteIdentityWithDfx003, TestSize.Level0)
{
    AccessTokenIDManager::GetInstance().AddReservedTokenId(TEST_RESERVED_ID);
    DeleteDfxInfo dfx = {};
    EXPECT_EQ(AccessTokenError::ERR_PARAM_INVALID,
        DeleteBundleManager::GetInstance().DeleteIdentityWithDfx(
            TEST_RESERVED_ID, TEST_BUNDLE, ReservedType::RESERVED_DATA, dfx));
    EXPECT_EQ(static_cast<int32_t>(AT_DELETE_RESERVED_TOKEN), dfx.sceneCode);
    EXPECT_EQ(0u, GetMockDbState().deleteAndInsertCallCount);
}

/**
 * @tc.name: NotifyBundleTokensDeletedSizeMismatch001
 * @tc.desc: A grantedPermLists/activeTokens size mismatch aborts the whole
 *           notification batch without crashing.
 *           Direct call: defense branch unreachable through any entry (the
 *           entries always build matched sizes).
 * @tc.type: FUNC
 */
HWTEST_F(DeleteIdentityTest, NotifyBundleTokensDeletedSizeMismatch001, TestSize.Level0)
{
    std::vector<AccessTokenID> activeTokens = { TEST_TOKEN_ID };
    std::vector<std::vector<std::string>> grantedPermLists; // size mismatch
    DeleteBundleManager::GetInstance().NotifyBundleTokensDeleted(activeTokens, grantedPermLists);
    // Contract: the batch is abandoned; nothing observable changes.
    EXPECT_EQ(0u, GetMockDbState().deleteAndInsertCallCount);
}

/**
 * @tc.name: DataCleanupMatrix001
 * @tc.desc: Case 2.2 data-cleanup matrix: NONE/RESERVED_IDENTITY drop the
 *           permission state, RESERVED_DATA keeps it; a normal bundle never
 *           touches the permission definitions; only the reserved modes
 *           re-insert the token row.
 * @tc.type: FUNC
 */
HWTEST_F(DeleteIdentityTest, DataCleanupMatrix001, TestSize.Level0)
{
    constexpr AccessTokenID MATRIX_NONE_ID = 0x20100011;
    constexpr AccessTokenID MATRIX_IDENTITY_ID = 0x20100012;
    constexpr AccessTokenID MATRIX_DATA_ID = 0x20100013;
    auto& tokenCache = AccessTokenInfoManager::GetInstance().hapTokenInfoMap_;

    // NONE: every per-token table goes, nothing is re-inserted.
    tokenCache[MATRIX_NONE_ID] = BuildInfoInner(MATRIX_NONE_ID, TEST_BUNDLE);
    AccessTokenIDManager::GetInstance().RegisterTokenId(MATRIX_NONE_ID, TOKEN_HAP);
    PermissionDataBrief::GetInstance().ReplaceBriefPermDataByTokenId(MATRIX_NONE_ID, BuildGrantedBrief(1), {});
    SetMockDbFindResult(AtmDataType::ACCESSTOKEN_HAP_TOKEN_INFO, RET_SUCCESS,
        { BuildTokenRow(MATRIX_NONE_ID, TEST_BUNDLE, 0) });
    DeleteDfxInfo dfx = {};
    EXPECT_EQ(RET_SUCCESS, DeleteBundleManager::GetInstance().DeleteIdentityWithDfx(
        MATRIX_NONE_ID, TEST_BUNDLE, ReservedType::NONE, dfx));
    ExpectDelOpRow(1, 1, 1, 1, 0, 1);
    EXPECT_TRUE(GetMockDbState().lastAddInfos.empty());
    ResetMockDbState();

    // RESERVED_IDENTITY: the same delete set (the permission state still goes)
    // plus the reserved re-insert.
    tokenCache[MATRIX_IDENTITY_ID] = BuildInfoInner(MATRIX_IDENTITY_ID, TEST_BUNDLE);
    AccessTokenIDManager::GetInstance().RegisterTokenId(MATRIX_IDENTITY_ID, TOKEN_HAP);
    PermissionDataBrief::GetInstance().ReplaceBriefPermDataByTokenId(
        MATRIX_IDENTITY_ID, BuildGrantedBrief(1), {});
    SetMockDbFindResult(AtmDataType::ACCESSTOKEN_HAP_TOKEN_INFO, RET_SUCCESS,
        { BuildTokenRow(MATRIX_IDENTITY_ID, TEST_BUNDLE, 0) });
    EXPECT_EQ(RET_SUCCESS, DeleteBundleManager::GetInstance().DeleteIdentityWithDfx(
        MATRIX_IDENTITY_ID, TEST_BUNDLE, ReservedType::RESERVED_IDENTITY, dfx));
    ExpectDelOpRow(1, 1, 1, 1, 0, 1);
    ASSERT_EQ(1u, GetMockDbState().lastAddInfos.size());
    EXPECT_EQ(AtmDataType::ACCESSTOKEN_HAP_TOKEN_INFO, GetMockDbState().lastAddInfos[0].addType);
    ResetMockDbState();

    // RESERVED_DATA: only the permission state is kept; the row is re-inserted.
    tokenCache[MATRIX_DATA_ID] = BuildInfoInner(MATRIX_DATA_ID, TEST_BUNDLE);
    AccessTokenIDManager::GetInstance().RegisterTokenId(MATRIX_DATA_ID, TOKEN_HAP);
    PermissionDataBrief::GetInstance().ReplaceBriefPermDataByTokenId(MATRIX_DATA_ID, BuildGrantedBrief(1), {});
    SetMockDbFindResult(AtmDataType::ACCESSTOKEN_HAP_TOKEN_INFO, RET_SUCCESS,
        { BuildTokenRow(MATRIX_DATA_ID, TEST_BUNDLE, 0) });
    EXPECT_EQ(RET_SUCCESS, DeleteBundleManager::GetInstance().DeleteIdentityWithDfx(
        MATRIX_DATA_ID, TEST_BUNDLE, ReservedType::RESERVED_DATA, dfx));
    ExpectDelOpRow(1, 0, 1, 1, 0, 1);
    ASSERT_EQ(1u, GetMockDbState().lastAddInfos.size());
    EXPECT_EQ(AtmDataType::ACCESSTOKEN_HAP_TOKEN_INFO, GetMockDbState().lastAddInfos[0].addType);
}

/**
 * @tc.name: DataCleanupMatrix002
 * @tc.desc: includePermissionState follows the deletion mode, never the stored
 *           type: Case 2.1 and Case 1 still drop the permission state of
 *           stored-RESERVED_DATA rows; Case 1 keeps the default dfx coordinates.
 * @tc.type: FUNC
 */
HWTEST_F(DeleteIdentityTest, DataCleanupMatrix002, TestSize.Level0)
{
    // Case 2.1: the reserved row stores RESERVED_DATA, but the complete delete
    // still removes its permission state; the row is the bundle's last trace,
    // so rule A2 drops the package info in the same transaction.
    AccessTokenIDManager::GetInstance().AddReservedTokenId(TEST_RESERVED_DATA_ID);
    SetMockDbFindResult(AtmDataType::ACCESSTOKEN_HAP_TOKEN_INFO, RET_SUCCESS,
        { BuildTokenRow(TEST_RESERVED_DATA_ID, TEST_BUNDLE, 2) });
    DeleteDfxInfo dfx = {};
    EXPECT_EQ(RET_SUCCESS, DeleteBundleManager::GetInstance().DeleteIdentityWithDfx(
        TEST_RESERVED_DATA_ID, TEST_BUNDLE, ReservedType::NONE, dfx));
    ExpectDelOpRow(1, 1, 1, 1, 0, 1);
    EXPECT_TRUE(GetMockDbState().lastAddInfos.empty());
    ResetMockDbState();

    // Case 1: the stored-RESERVED_DATA row loses its permission state too.
    // Fresh dfx: Case 2.1 filled its coordinates from the db row, Case 1 must
    // keep the defaults.
    constexpr AccessTokenID MATRIX_C1_ACTIVE_ID = 0x20100014;
    constexpr AccessTokenID MATRIX_C1_RESERVED_ID = 0x20100015;
    SetMockDbFindResult(AtmDataType::ACCESSTOKEN_HAP_TOKEN_INFO, RET_SUCCESS,
        { BuildTokenRow(MATRIX_C1_ACTIVE_ID, TEST_BUNDLE, 0),
          BuildTokenRow(MATRIX_C1_RESERVED_ID, TEST_BUNDLE, 2) });
    PermissionDataBrief::GetInstance().ReplaceBriefPermDataByTokenId(
        MATRIX_C1_ACTIVE_ID, BuildGrantedBrief(1), {});
    DeleteDfxInfo c1Dfx = {};
    EXPECT_EQ(RET_SUCCESS, DeleteBundleManager::GetInstance().DeleteIdentityWithDfx(
        INVALID_TOKENID, TEST_BUNDLE, ReservedType::NONE, c1Dfx));
    ExpectDelOpRow(2, 2, 2, 2, 0, 1);
    // Case 1 performs no per-token lookup: the coordinates keep their defaults.
    EXPECT_EQ(0, c1Dfx.userId);
    EXPECT_EQ(0, c1Dfx.instIndex);
}

/**
 * @tc.name: DeleteWholeBundleActiveOverLimit001
 * @tc.desc: More than 255 (MAX_ENTRY_NUM) active tokens fail the staging build,
 *           so the whole delete aborts before any kernel mutation or db commit.
 * @tc.type: FUNC
 */
HWTEST_F(DeleteIdentityTest, DeleteWholeBundleActiveOverLimit001, TestSize.Level0)
{
    constexpr uint32_t OVER_LIMIT = 256; // MAX_ENTRY_NUM + 1
    constexpr AccessTokenID FIRST_ID = 0x20100021;
    std::vector<GenericValues> rows;
    for (uint32_t i = 0; i < OVER_LIMIT; ++i) {
        AccessTokenID id = FIRST_ID + i;
        rows.emplace_back(BuildTokenRow(id, TEST_BUNDLE, 0));
        PermissionDataBrief::GetInstance().ReplaceBriefPermDataByTokenId(id, BuildGrantedBrief(1), {});
    }
    SetMockDbFindResult(AtmDataType::ACCESSTOKEN_HAP_TOKEN_INFO, RET_SUCCESS, rows);
    DeleteDfxInfo dfx = {};

    EXPECT_EQ(AccessTokenError::ERR_PARAM_INVALID, DeleteBundleManager::GetInstance().DeleteIdentityWithDfx(
        INVALID_TOKENID, TEST_BUNDLE, ReservedType::NONE, dfx));

    EXPECT_EQ(static_cast<int32_t>(AT_DELETE_ALL_BUNDLE), dfx.sceneCode);
    EXPECT_EQ(0u, GetMockDbState().deleteAndInsertCallCount); // no partial commit
    EXPECT_EQ(0, GetFakeSpmKernelState().removeCallCount);    // nothing staged
    EXPECT_EQ(0, GetFakeSpmKernelState().removePermCallCount);
}

/**
 * @tc.name: DeleteWholeBundleActiveAtLimit001
 * @tc.desc: Exactly 255 (MAX_ENTRY_NUM) active tokens stay within the staging
 *           cap: the whole bundle deletes in a single commit.
 * @tc.type: FUNC
 */
HWTEST_F(DeleteIdentityTest, DeleteWholeBundleActiveAtLimit001, TestSize.Level0)
{
    constexpr uint32_t AT_LIMIT = 255; // MAX_ENTRY_NUM
    constexpr AccessTokenID FIRST_ID = 0x20100121;
    std::vector<GenericValues> rows;
    for (uint32_t i = 0; i < AT_LIMIT; ++i) {
        AccessTokenID id = FIRST_ID + i;
        rows.emplace_back(BuildTokenRow(id, TEST_BUNDLE, 0));
        PermissionDataBrief::GetInstance().ReplaceBriefPermDataByTokenId(id, BuildGrantedBrief(1), {});
    }
    SetMockDbFindResult(AtmDataType::ACCESSTOKEN_HAP_TOKEN_INFO, RET_SUCCESS, rows);
    DeleteDfxInfo dfx = {};

    EXPECT_EQ(RET_SUCCESS, DeleteBundleManager::GetInstance().DeleteIdentityWithDfx(
        INVALID_TOKENID, TEST_BUNDLE, ReservedType::NONE, dfx));

    EXPECT_EQ(1u, GetMockDbState().deleteAndInsertCallCount); // one atomic commit
    EXPECT_EQ(255, GetFakeSpmKernelState().removeCallCount);  // the cap is inclusive
    // Case 1 keeps the default coordinates (no per-token lookup on this path).
    EXPECT_EQ(static_cast<int32_t>(AT_DELETE_ALL_BUNDLE), dfx.sceneCode);
    EXPECT_EQ(0, dfx.userId);
    EXPECT_EQ(0, dfx.instIndex);
}

/**
 * @tc.name: DeleteActiveTokenNoBrief001
 * @tc.desc: A token without a registered brief is not compensable: the delete
 *           degrades (rollback limited to the spm entry) but still succeeds.
 * @tc.type: FUNC
 */
HWTEST_F(DeleteIdentityTest, DeleteActiveTokenNoBrief001, TestSize.Level0)
{
    constexpr AccessTokenID NO_BRIEF_ID = 0x20100005;
    AccessTokenInfoManager::GetInstance().hapTokenInfoMap_[NO_BRIEF_ID] =
        BuildInfoInner(NO_BRIEF_ID, TEST_BUNDLE);
    AccessTokenIDManager::GetInstance().RegisterTokenId(NO_BRIEF_ID, TOKEN_HAP);
    SetMockDbFindResult(AtmDataType::ACCESSTOKEN_HAP_TOKEN_INFO, RET_SUCCESS,
        { BuildTokenRow(NO_BRIEF_ID, TEST_BUNDLE, 0) });
    DeleteDfxInfo dfx = {};

    EXPECT_EQ(RET_SUCCESS, DeleteBundleManager::GetInstance().DeleteIdentityWithDfx(
        NO_BRIEF_ID, TEST_BUNDLE, ReservedType::NONE, dfx));

    EXPECT_EQ(1, GetFakeSpmKernelState().removeCallCount);
    EXPECT_EQ(1u, GetMockDbState().deleteAndInsertCallCount);
}

/**
 * @tc.name: DeleteActiveTokenNoBriefDbFail001
 * @tc.desc: Brief missing plus a db failure: the degraded rollback restores the
 *           spm entry only - the permission bitmap cannot come back.
 * @tc.type: FUNC
 */
HWTEST_F(DeleteIdentityTest, DeleteActiveTokenNoBriefDbFail001, TestSize.Level0)
{
    constexpr AccessTokenID NO_BRIEF_ID = 0x20100006;
    AccessTokenInfoManager::GetInstance().hapTokenInfoMap_[NO_BRIEF_ID] =
        BuildInfoInner(NO_BRIEF_ID, TEST_BUNDLE);
    AccessTokenIDManager::GetInstance().RegisterTokenId(NO_BRIEF_ID, TOKEN_HAP);
    SetMockDbFindResult(AtmDataType::ACCESSTOKEN_HAP_TOKEN_INFO, RET_SUCCESS,
        { BuildTokenRow(NO_BRIEF_ID, TEST_BUNDLE, 0) });
    GetMockDbState().deleteAndInsertRet = ERR_DATABASE_OPERATE_FAILED;
    DeleteDfxInfo dfx = {};

    EXPECT_NE(RET_SUCCESS, DeleteBundleManager::GetInstance().DeleteIdentityWithDfx(
        NO_BRIEF_ID, TEST_BUNDLE, ReservedType::NONE, dfx));

    EXPECT_EQ(1, GetFakeSpmKernelState().removeCallCount);
    EXPECT_EQ(1, GetFakeSpmKernelState().removePermCallCount);
    EXPECT_EQ(1, GetFakeSpmKernelState().addCallCount);     // spm entry restored
    EXPECT_EQ(0, GetFakeSpmKernelState().addPermCallCount); // bitmap not restorable
}

/**
 * @tc.name: BundleIdHeldByOtherUserRow001
 * @tc.desc: Rule B3: another user's row of the bundle derives the same
 *           bundleId, so the last trace of the deleted uid does not return the
 *           shared id to the pool.
 * @tc.type: FUNC
 */
HWTEST_F(DeleteIdentityTest, BundleIdHeldByOtherUserRow001, TestSize.Level0)
{
    int32_t currentUid = 20020000 + static_cast<int32_t>(TEST_TOKEN_ID % 45536); // same as BuildHapInfo
    int32_t bundleId = -1;
    ASSERT_TRUE(AccessTokenIDManager::GetInstance().ExtractBundleId(currentUid, bundleId));
    auto& bundleIdSet = AccessTokenIDManager::GetInstance().bundleIdSet_;
    bundleIdSet.insert(bundleId);

    AccessTokenInfoManager::GetInstance().hapTokenInfoMap_[TEST_TOKEN_ID] =
        BuildInfoInner(TEST_TOKEN_ID, TEST_BUNDLE);
    AccessTokenIDManager::GetInstance().RegisterTokenId(TEST_TOKEN_ID, TOKEN_HAP);
    PermissionDataBrief::GetInstance().ReplaceBriefPermDataByTokenId(TEST_TOKEN_ID, BuildGrantedBrief(1), {});
    // Another user's RESERVED_DATA row: a valid uid deriving the same bundleId.
    GenericValues otherRow = BuildTokenRow(TEST_RESERVED_DATA_ID, TEST_BUNDLE, 2);
    otherRow.Remove(TokenFiledConst::FIELD_UID);
    otherRow.Put(TokenFiledConst::FIELD_UID, currentUid + 200000); // 200000: uid divisor
    SetMockDbFindResult(AtmDataType::ACCESSTOKEN_HAP_TOKEN_INFO, RET_SUCCESS,
        { BuildTokenRow(TEST_TOKEN_ID, TEST_BUNDLE, 0), otherRow });
    DeleteDfxInfo dfx = {};

    EXPECT_EQ(RET_SUCCESS, DeleteBundleManager::GetInstance().DeleteIdentityWithDfx(
        TEST_TOKEN_ID, TEST_BUNDLE, ReservedType::NONE, dfx));

    // A2: the deleted uid was the last active trace, so the package info goes...
    EXPECT_EQ(1u, CountDelInfo(GetMockDbState().lastDeleteInfos, AtmDataType::ACCESSTOKEN_HAP_PACKAGE_INFO));
    // ...B3: but the shared bundleId stays occupied by the other user's row.
    EXPECT_EQ(1u, bundleIdSet.count(bundleId));
}

/**
 * @tc.name: DeleteReservedTokenKeepPackageWhenActiveRemains001
 * @tc.desc: Case 2.1 rule A1: another active row of the bundle keeps the
 *           package info row out of the complete delete.
 * @tc.type: FUNC
 */
HWTEST_F(DeleteIdentityTest, DeleteReservedTokenKeepPackageWhenActiveRemains001, TestSize.Level0)
{
    AccessTokenIDManager::GetInstance().AddReservedTokenId(TEST_RESERVED_ID);
    // The bundle still has an active row besides the reserved one being deleted.
    SetMockDbFindResult(AtmDataType::ACCESSTOKEN_HAP_TOKEN_INFO, RET_SUCCESS,
        { BuildTokenRow(TEST_OTHER_ID, TEST_BUNDLE, 0),
          BuildTokenRow(TEST_RESERVED_ID, TEST_BUNDLE, 1) });
    DeleteDfxInfo dfx = {};

    EXPECT_EQ(RET_SUCCESS, DeleteBundleManager::GetInstance().DeleteIdentityWithDfx(
        TEST_RESERVED_ID, TEST_BUNDLE, ReservedType::NONE, dfx));

    EXPECT_EQ(static_cast<int32_t>(AT_DELETE_RESERVED_TOKEN), dfx.sceneCode);
    // Only the reserved token's own rows go; the package info stays (A1).
    ExpectDelOpRow(1, 1, 1, 1, 0, 0);
    EXPECT_FALSE(AccessTokenIDManager::GetInstance().IsReservedTokenId(TEST_RESERVED_ID));
}

/**
 * @tc.name: DeleteUntrustedToken001
 * @tc.desc: Case 2.2 NONE on an untrusted token: the db-snapshot info drives
 *           the complete delete and the force release empties the untrusted
 *           set entry.
 * @tc.type: FUNC
 */
HWTEST_F(DeleteIdentityTest, DeleteUntrustedToken001, TestSize.Level0)
{
    auto& untrustedSet = AccessTokenIDManager::GetInstance().untrustedTokenIdSet_;
    untrustedSet.insert(TEST_UNTRUSTED_NONE_ID);
    SetMockDbFindResult(AtmDataType::ACCESSTOKEN_HAP_TOKEN_INFO, RET_SUCCESS,
        { BuildRestorableTokenRow(TEST_UNTRUSTED_NONE_ID, TEST_BUNDLE) });
    DeleteDfxInfo dfx = {};

    EXPECT_EQ(RET_SUCCESS, DeleteBundleManager::GetInstance().DeleteIdentityWithDfx(
        TEST_UNTRUSTED_NONE_ID, TEST_BUNDLE, ReservedType::NONE, dfx));

    EXPECT_EQ(static_cast<int32_t>(AT_DELETE_NORMAL), dfx.sceneCode);
    // Coordinates carried out from the db-restored token info.
    EXPECT_EQ(100, dfx.userId); // 100: userId of the restorable row
    EXPECT_EQ(0, dfx.instIndex);
    ExpectDelOpRow(1, 1, 1, 1, 0, 1);
    EXPECT_TRUE(GetMockDbState().lastAddInfos.empty());
    EXPECT_EQ(0u, untrustedSet.count(TEST_UNTRUSTED_NONE_ID));
    EXPECT_FALSE(AccessTokenIDManager::GetInstance().IsReservedTokenId(TEST_UNTRUSTED_NONE_ID));
}

/**
 * @tc.name: DeleteUntrustedToken002
 * @tc.desc: Case 2.2 RESERVED_IDENTITY on an untrusted token: the id moves
 *           into the reserved set and the row is re-inserted reserved=1.
 * @tc.type: FUNC
 */
HWTEST_F(DeleteIdentityTest, DeleteUntrustedToken002, TestSize.Level0)
{
    auto& untrustedSet = AccessTokenIDManager::GetInstance().untrustedTokenIdSet_;
    untrustedSet.insert(TEST_UNTRUSTED_IDENTITY_ID);
    SetMockDbFindResult(AtmDataType::ACCESSTOKEN_HAP_TOKEN_INFO, RET_SUCCESS,
        { BuildRestorableTokenRow(TEST_UNTRUSTED_IDENTITY_ID, TEST_BUNDLE) });
    DeleteDfxInfo dfx = {};

    EXPECT_EQ(RET_SUCCESS, DeleteBundleManager::GetInstance().DeleteIdentityWithDfx(
        TEST_UNTRUSTED_IDENTITY_ID, TEST_BUNDLE, ReservedType::RESERVED_IDENTITY, dfx));

    EXPECT_EQ(static_cast<int32_t>(AT_DELETE_KEEP_TOKEN_FINISH), dfx.sceneCode);
    EXPECT_EQ(0u, untrustedSet.count(TEST_UNTRUSTED_IDENTITY_ID));
    EXPECT_TRUE(AccessTokenIDManager::GetInstance().IsReservedTokenId(TEST_UNTRUSTED_IDENTITY_ID));
    ASSERT_EQ(1u, GetMockDbState().lastAddInfos.size());
    ASSERT_EQ(1u, GetMockDbState().lastAddInfos[0].addValues.size());
    EXPECT_EQ(static_cast<int32_t>(ReservedType::RESERVED_IDENTITY),
        GetMockDbState().lastAddInfos[0].addValues[0].GetInt(TokenFiledConst::FIELD_RESERVED));
    EXPECT_EQ(-1, GetMockDbState().lastAddInfos[0].addValues[0].GetInt(TokenFiledConst::FIELD_UID));
}

/**
 * @tc.name: DeleteUntrustedToken003
 * @tc.desc: Case 2.2 RESERVED_DATA on an untrusted token: the permission
 *           state is kept and the id moves into the reserved set.
 * @tc.type: FUNC
 */
HWTEST_F(DeleteIdentityTest, DeleteUntrustedToken003, TestSize.Level0)
{
    auto& untrustedSet = AccessTokenIDManager::GetInstance().untrustedTokenIdSet_;
    untrustedSet.insert(TEST_UNTRUSTED_DATA_ID);
    SetMockDbFindResult(AtmDataType::ACCESSTOKEN_HAP_TOKEN_INFO, RET_SUCCESS,
        { BuildRestorableTokenRow(TEST_UNTRUSTED_DATA_ID, TEST_BUNDLE) });
    DeleteDfxInfo dfx = {};

    EXPECT_EQ(RET_SUCCESS, DeleteBundleManager::GetInstance().DeleteIdentityWithDfx(
        TEST_UNTRUSTED_DATA_ID, TEST_BUNDLE, ReservedType::RESERVED_DATA, dfx));

    EXPECT_EQ(static_cast<int32_t>(AT_DELETE_KEEP_DATA), dfx.sceneCode);
    EXPECT_EQ(0u, CountDelInfo(GetMockDbState().lastDeleteInfos, AtmDataType::ACCESSTOKEN_PERMISSION_STATE));
    EXPECT_EQ(0u, untrustedSet.count(TEST_UNTRUSTED_DATA_ID));
    EXPECT_TRUE(AccessTokenIDManager::GetInstance().IsReservedTokenId(TEST_UNTRUSTED_DATA_ID));
    // The re-insert keeps the uid for the reinstall reuse.
    ASSERT_EQ(1u, GetMockDbState().lastAddInfos.size());
    ASSERT_EQ(1u, GetMockDbState().lastAddInfos[0].addValues.size());
    EXPECT_EQ(static_cast<int32_t>(ReservedType::RESERVED_DATA),
        GetMockDbState().lastAddInfos[0].addValues[0].GetInt(TokenFiledConst::FIELD_RESERVED));
}

/**
 * @tc.name: DeleteWholeBundleUntrusted001
 * @tc.desc: Case 1 with an untrusted row: the reserved-field partition
 *           classifies it active, and the force release empties the
 *           untrusted-set entry with the whole-bundle wipe.
 * @tc.type: FUNC
 */
HWTEST_F(DeleteIdentityTest, DeleteWholeBundleUntrusted001, TestSize.Level0)
{
    auto& untrustedSet = AccessTokenIDManager::GetInstance().untrustedTokenIdSet_;
    untrustedSet.insert(TEST_UNTRUSTED_WHOLE_ID);
    SetMockDbFindResult(AtmDataType::ACCESSTOKEN_HAP_TOKEN_INFO, RET_SUCCESS,
        { BuildTokenRow(TEST_UNTRUSTED_WHOLE_ID, TEST_BUNDLE, 0),
          BuildTokenRow(TEST_OTHER_ID, TEST_BUNDLE, 0) });
    PermissionDataBrief::GetInstance().ReplaceBriefPermDataByTokenId(
        TEST_UNTRUSTED_WHOLE_ID, BuildGrantedBrief(1), {});
    PermissionDataBrief::GetInstance().ReplaceBriefPermDataByTokenId(TEST_OTHER_ID, BuildGrantedBrief(1), {});
    DeleteDfxInfo dfx = {};

    EXPECT_EQ(RET_SUCCESS, DeleteBundleManager::GetInstance().DeleteIdentityWithDfx(
        INVALID_TOKENID, TEST_BUNDLE, ReservedType::NONE, dfx));

    EXPECT_EQ(static_cast<int32_t>(AT_DELETE_ALL_BUNDLE), dfx.sceneCode);
    // Both reserved=NONE rows classify active: both stage the kernel removal.
    EXPECT_EQ(2, GetFakeSpmKernelState().removeCallCount);
    EXPECT_EQ(1u, GetMockDbState().deleteAndInsertCallCount); // one atomic commit
    EXPECT_EQ(2u, CountDelInfo(GetMockDbState().lastDeleteInfos, AtmDataType::ACCESSTOKEN_HAP_TOKEN_INFO));
    EXPECT_EQ(1u, CountDelInfo(GetMockDbState().lastDeleteInfos, AtmDataType::ACCESSTOKEN_HAP_PACKAGE_INFO));
    // The force release empties the untrusted-set entry (the db partition
    // cannot distinguish active from untrusted).
    EXPECT_EQ(0u, untrustedSet.count(TEST_UNTRUSTED_WHOLE_ID));
}
} // namespace AccessToken
} // namespace Security
} // namespace OHOS
