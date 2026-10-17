/*
 * Copyright (c) 2026 Huawei Device Co., Ltd.
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 *
 * http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 */

#include <gtest/gtest.h>
#include <algorithm>

#define private public
#include "accesstoken_info_manager.h"
#undef private

#include "access_token_error.h"

using namespace testing::ext;

namespace OHOS {
namespace Security {
namespace AccessToken {
namespace {
constexpr AccessTokenID TEST_TOKEN_ID = 0x20260428;
constexpr AccessTokenID TEST_TOKEN_ID_2 =  0x20260429;
constexpr int32_t TEST_USER_ID = 100;
constexpr int32_t TEST_INST_INDEX = 0;

HapTokenInfoItem BuildTestHapInfoItem(AccessTokenID tokenId, const std::string& bundleName, int32_t apiVersion)
{
    HapTokenInfoItem item;
    item.tokenId = tokenId;
    item.userId = static_cast<uint32_t>(TEST_USER_ID);
    item.bundleName = bundleName;
    item.apiVersion = apiVersion;
    item.instIndex = static_cast<uint32_t>(TEST_INST_INDEX);
    item.dlpType = DLP_COMMON;
    item.uid = 20100000; //20100000: test uid
    return item;
}

std::vector<BriefPermData> BuildBriefData(uint16_t permCode, int8_t status, uint32_t flag)
{
    BriefPermData data = {0};
    data.permCode = permCode;
    data.status = status;
    data.flag = flag;
    return { data };
}

AccessTokenInfoManager::HapTokenRestoreData BuildRestoreData(AccessTokenID tokenId, const std::string& bundleName)
{
    AccessTokenInfoManager::HapTokenRestoreData restoreData;
    BriefPermData permData1 = {0};
    permData1.permCode = 1; // 1: test perm code
    permData1.status = PERMISSION_GRANTED;
    permData1.flag = PERMISSION_SYSTEM_FIXED;
    BriefPermData permData2 = {0};
    permData2.permCode = 2; // 2: test perm code
    permData2.status = PERMISSION_DENIED;
    permData2.flag = PERMISSION_DEFAULT_FLAG;
    PermissionWithValue extendedPerm;
    extendedPerm.permissionName = "ohos.permission.kernel.SUPPORT_PLUGIN";
    extendedPerm.value = "allowed";
    restoreData.hapTokenInfoItem.tokenId = tokenId;
    restoreData.hapTokenInfoItem.bundleName = bundleName;
    restoreData.hapTokenInfoItem.userId = TEST_USER_ID;
    restoreData.hapTokenInfoItem.apiVersion = 12; // 12: test api version
    restoreData.hapTokenInfoItem.instIndex = TEST_INST_INDEX;
    restoreData.hapTokenInfoItem.dlpType = DLP_COMMON;
    restoreData.hapTokenInfoItem.tokenAttr = 0;
    restoreData.hapTokenInfoItem.uid = 20100000; //20100000: test uid
    restoreData.hapTokenInfoItem.apl = APL_NORMAL;
    restoreData.requestedPermData = { permData1, permData2 };
    restoreData.extendedPermList = { extendedPerm };
    return restoreData;
}
}

class HapCacheCommitTest : public testing::Test {
public:
    void TearDown() override
    {
        auto& manager = AccessTokenInfoManager::GetInstance();
        std::unique_lock<std::shared_mutex> lock(manager.hapTokenInfoLock_);
        manager.hapTokenInfoMap_.erase(TEST_TOKEN_ID);
        manager.hapTokenInfoMap_.erase(TEST_TOKEN_ID_2);
        manager.hapTokenIdMap_.erase("com.example.cache&100&0");
        manager.hapTokenIdMap_.erase("com.example.cache.updated&100&1");
        manager.hapTokenIdMap_.erase("com.example.cache.multi&100&0");
        manager.hapTokenIdMap_.erase("com.example.cache.multi&100&1");
        (void)PermissionDataBrief::GetInstance().DeleteBriefPermDataByTokenId(TEST_TOKEN_ID);
        (void)PermissionDataBrief::GetInstance().DeleteBriefPermDataByTokenId(TEST_TOKEN_ID_2);
    }
};

/**
 * @tc.name: CommitCreateHapCache001
 * @tc.desc: Verify create cache writes hap and brief caches.
 * @tc.type: FUNC
 */
HWTEST_F(HapCacheCommitTest, CommitCreateHapCache001, TestSize.Level0)
{
    auto& manager = AccessTokenInfoManager::GetInstance();
    auto hapInfoItem = BuildTestHapInfoItem(TEST_TOKEN_ID, "com.example.cache", 12);
    hapInfoItem.isSideload = true;
    hapInfoItem.migrated = true;
    auto briefData = BuildBriefData(1, PERMISSION_GRANTED, PERMISSION_SYSTEM_FIXED);

    manager.CommitCreateHapCache(hapInfoItem, briefData, {});

    ASSERT_NE(manager.hapTokenInfoMap_.find(TEST_TOKEN_ID), manager.hapTokenInfoMap_.end());
    ASSERT_NE(nullptr, manager.hapTokenInfoMap_[TEST_TOKEN_ID]);
    HapTokenInfo cachedInfo = manager.hapTokenInfoMap_[TEST_TOKEN_ID]->GetHapInfoBasic();
    EXPECT_EQ(hapInfoItem.tokenId, cachedInfo.tokenID);
    EXPECT_EQ(hapInfoItem.bundleName, cachedInfo.bundleName);
    EXPECT_EQ(hapInfoItem.apiVersion, cachedInfo.apiVersion);
    // sideload/migrated ride on the item (uidFromCaller corresponds to migrated)
    EXPECT_TRUE(manager.hapTokenInfoMap_[TEST_TOKEN_ID]->IsSideloadApp());
    EXPECT_TRUE(manager.hapTokenInfoMap_[TEST_TOKEN_ID]->IsMigrated());
    ASSERT_NE(manager.hapTokenIdMap_.find("com.example.cache&100&0"), manager.hapTokenIdMap_.end());
    EXPECT_EQ(TEST_TOKEN_ID, manager.hapTokenIdMap_["com.example.cache&100&0"]);
    // the userId cache is populated on create
    EXPECT_EQ(1u, manager.userIdSet_.count(TEST_USER_ID));

    std::vector<BriefPermData> queriedData;
    ASSERT_EQ(RET_SUCCESS, PermissionDataBrief::GetInstance().GetBriefPermDataByTokenId(TEST_TOKEN_ID, queriedData));
    ASSERT_EQ(1u, queriedData.size());
    EXPECT_EQ(1, queriedData[0].permCode);
}

/**
 * @tc.name: CommitUpdateHapCache001
 * @tc.desc: Verify update cache keeps original HapTokenInfoInner instance and only updates token base info.
 * @tc.type: FUNC
 */
HWTEST_F(HapCacheCommitTest, CommitUpdateHapCache001, TestSize.Level0)
{
    auto& manager = AccessTokenInfoManager::GetInstance();
    auto hapInfoItem = BuildTestHapInfoItem(TEST_TOKEN_ID, "com.example.cache", 12);
    manager.CommitCreateHapCache(hapInfoItem, BuildBriefData(1, PERMISSION_GRANTED, 0), {});

    auto oldPtr = manager.hapTokenInfoMap_[TEST_TOKEN_ID];
    HapTokenInfoItem updatedInfo = hapInfoItem;
    updatedInfo.apiVersion = 15;
    updatedInfo.tokenAttr = 0x8;

    manager.CommitUpdateHapCache(updatedInfo,
        BuildBriefData(2, PERMISSION_DENIED, PERMISSION_DEFAULT_FLAG), {});

    ASSERT_NE(manager.hapTokenInfoMap_.find(TEST_TOKEN_ID), manager.hapTokenInfoMap_.end());
    EXPECT_EQ(oldPtr, manager.hapTokenInfoMap_[TEST_TOKEN_ID]);
    HapTokenInfo cachedInfo = manager.hapTokenInfoMap_[TEST_TOKEN_ID]->GetHapInfoBasic();
    EXPECT_EQ(15, cachedInfo.apiVersion);
    EXPECT_EQ(static_cast<uint32_t>(0x8), cachedInfo.tokenAttr);
    // the identity-triple <-> tokenID mapping is untouched by the update
    ASSERT_NE(manager.hapTokenIdMap_.find("com.example.cache&100&0"), manager.hapTokenIdMap_.end());
    EXPECT_EQ(TEST_TOKEN_ID, manager.hapTokenIdMap_["com.example.cache&100&0"]);

    std::vector<BriefPermData> queriedData;
    ASSERT_EQ(RET_SUCCESS, PermissionDataBrief::GetInstance().GetBriefPermDataByTokenId(TEST_TOKEN_ID, queriedData));
    ASSERT_EQ(1u, queriedData.size());
    EXPECT_EQ(2, queriedData[0].permCode);
}

/**
 * @tc.name: CommitDeleteHapCache001
 * @tc.desc: Verify delete cache removes hap and brief caches.
 * @tc.type: FUNC
 */
HWTEST_F(HapCacheCommitTest, CommitDeleteHapCache001, TestSize.Level0)
{
    auto& manager = AccessTokenInfoManager::GetInstance();
    auto hapInfoItem = BuildTestHapInfoItem(TEST_TOKEN_ID, "com.example.cache", 12);
    manager.CommitCreateHapCache(hapInfoItem, BuildBriefData(1, PERMISSION_GRANTED, 0), {});

    manager.CommitDeleteHapCache(TEST_TOKEN_ID);

    EXPECT_EQ(manager.hapTokenInfoMap_.end(), manager.hapTokenInfoMap_.find(TEST_TOKEN_ID));
    EXPECT_EQ(manager.hapTokenIdMap_.end(), manager.hapTokenIdMap_.find("com.example.cache&100&0"));

    std::vector<BriefPermData> queriedData;
    EXPECT_NE(RET_SUCCESS, PermissionDataBrief::GetInstance().GetBriefPermDataByTokenId(TEST_TOKEN_ID, queriedData));
}

/**
 * @tc.name: CommitUpdateHapCache003
 * @tc.desc: Verify update cache rebuilds the live cache entry for a token collected by the update session.
 * @tc.type: FUNC
 */
HWTEST_F(HapCacheCommitTest, CommitUpdateHapCache003, TestSize.Level0)
{
    auto& manager = AccessTokenInfoManager::GetInstance();
    HapTokenInfoItem updatedInfo = BuildTestHapInfoItem(TEST_TOKEN_ID, "com.example.cache.updated", 15);

    manager.CommitUpdateHapCache(updatedInfo,
        BuildBriefData(2, PERMISSION_DENIED, PERMISSION_DEFAULT_FLAG), {});

    ASSERT_NE(manager.hapTokenInfoMap_.end(), manager.hapTokenInfoMap_.find(TEST_TOKEN_ID));
    HapTokenInfo cachedInfo = manager.hapTokenInfoMap_[TEST_TOKEN_ID]->GetHapInfoBasic();
    EXPECT_EQ(15, cachedInfo.apiVersion);
}

/**
 * @tc.name: CommitDeleteHapCache002
 * @tc.desc: Verify delete cache of one token keeps the other tokens.
 * @tc.type: FUNC
 */
HWTEST_F(HapCacheCommitTest, CommitDeleteHapCache002, TestSize.Level0)
{
    auto& manager = AccessTokenInfoManager::GetInstance();
    manager.CommitCreateHapCache(BuildTestHapInfoItem(TEST_TOKEN_ID, "com.example.cache.multi", 12),
        BuildBriefData(1, PERMISSION_GRANTED, 0), {});
    manager.CommitCreateHapCache(BuildTestHapInfoItem(TEST_TOKEN_ID_2, "com.example.cache.multi", 12),
        BuildBriefData(2, PERMISSION_GRANTED, 0), {});

    manager.CommitDeleteHapCache(TEST_TOKEN_ID);

    EXPECT_EQ(manager.hapTokenInfoMap_.end(), manager.hapTokenInfoMap_.find(TEST_TOKEN_ID));
    ASSERT_NE(manager.hapTokenInfoMap_.end(), manager.hapTokenInfoMap_.find(TEST_TOKEN_ID_2));
}

/**
 * @tc.name: CommitCreateHapCacheWithExtendedPerm001
 * @tc.desc: Verify create cache with extended permission list sets extendedValue_ correctly.
 * @tc.type: FUNC
 */
HWTEST_F(HapCacheCommitTest, CommitCreateHapCacheWithExtendedPerm001, TestSize.Level0)
{
    auto& manager = AccessTokenInfoManager::GetInstance();
    auto hapInfoItem = BuildTestHapInfoItem(TEST_TOKEN_ID, "com.example.cache", 12);
    auto briefData = BuildBriefData(1, PERMISSION_GRANTED, PERMISSION_SYSTEM_FIXED);

    // Build extended permission list
    std::vector<PermissionWithValue> extendedPermList;
    PermissionWithValue perm1;
    perm1.permissionName = "ohos.permission.ACCESS_DDK_DRIVERS";
    perm1.value = "allowed";
    extendedPermList.push_back(perm1);

    PermissionWithValue perm2;
    perm2.permissionName = "ohos.permission.kernel.SUPPORT_PLUGIN";
    perm2.value = "denied";
    extendedPermList.push_back(perm2);

    manager.CommitCreateHapCache(hapInfoItem, briefData, extendedPermList);

    ASSERT_NE(manager.hapTokenInfoMap_.find(TEST_TOKEN_ID), manager.hapTokenInfoMap_.end());
    std::vector<BriefPermData> queriedData;
    ASSERT_EQ(RET_SUCCESS, PermissionDataBrief::GetInstance().GetBriefPermDataByTokenId(TEST_TOKEN_ID, queriedData));
    ASSERT_EQ(1u, queriedData.size());
    EXPECT_EQ(1, queriedData[0].permCode);

    // Verify extended permissions are set
    std::vector<PermissionWithValue> queriedExtendedPerms;
    PermissionDataBrief::GetInstance().GetExtendedValueList(TEST_TOKEN_ID, queriedExtendedPerms);
    ASSERT_EQ(2u, queriedExtendedPerms.size());
    bool flag1 = false;
    bool flag2 = false;
    for (const auto& perm : queriedExtendedPerms) {
        if (perm.permissionName == "ohos.permission.ACCESS_DDK_DRIVERS") {
            flag1 = true;
            EXPECT_EQ("allowed", perm.value);
        } else if (perm.permissionName == "ohos.permission.kernel.SUPPORT_PLUGIN") {
            flag2 = true;
            EXPECT_EQ("denied", perm.value);
        }
    }
    EXPECT_TRUE(flag1);
    EXPECT_TRUE(flag2);
}

/**
 * @tc.name: CommitCreateHapCacheWithExtendedPerm002
 * @tc.desc: Verify create cache with empty extended permission list clears existing extendedValue_.
 * @tc.type: FUNC
 */
HWTEST_F(HapCacheCommitTest, CommitCreateHapCacheWithExtendedPerm002, TestSize.Level0)
{
    auto& manager = AccessTokenInfoManager::GetInstance();
    auto hapInfoItem = BuildTestHapInfoItem(TEST_TOKEN_ID, "com.example.cache", 12);
    auto briefData = BuildBriefData(1, PERMISSION_GRANTED, PERMISSION_SYSTEM_FIXED);

    // First create with extended permissions
    std::vector<PermissionWithValue> extendedPermList;
    PermissionWithValue perm1;
    perm1.permissionName = "ohos.permission.ACCESS_DDK_DRIVERS";
    perm1.value = "allowed";
    extendedPermList.push_back(perm1);
    manager.CommitCreateHapCache(hapInfoItem, briefData, extendedPermList);

    // Verify extended permissions are set
    std::vector<PermissionWithValue> queriedExtendedPerms;
    PermissionDataBrief::GetInstance().GetExtendedValueList(TEST_TOKEN_ID, queriedExtendedPerms);
    ASSERT_EQ(1u, queriedExtendedPerms.size());

    // Update with empty extended permission list
    manager.CommitCreateHapCache(hapInfoItem, briefData, {});

    // Verify extended permissions are cleared
    queriedExtendedPerms.clear();
    PermissionDataBrief::GetInstance().GetExtendedValueList(TEST_TOKEN_ID, queriedExtendedPerms);
    EXPECT_EQ(0u, queriedExtendedPerms.size());
}

/**
 * @tc.name: CommitUpdateHapCacheWithExtendedPerm001
 * @tc.desc: Verify update cache with extended permission list updates extendedValue_ correctly.
 * @tc.type: FUNC
 */
HWTEST_F(HapCacheCommitTest, CommitUpdateHapCacheWithExtendedPerm001, TestSize.Level0)
{
    auto& manager = AccessTokenInfoManager::GetInstance();
    auto hapInfoItem = BuildTestHapInfoItem(TEST_TOKEN_ID, "com.example.cache", 12);
    manager.CommitCreateHapCache(hapInfoItem, BuildBriefData(1, PERMISSION_GRANTED, 0), {});

    // Build updated extended permission list
    std::vector<PermissionWithValue> extendedPermList;
    PermissionWithValue perm1;
    perm1.permissionName = "ohos.permission.ACCESS_DDK_DRIVERS";
    perm1.value = "in_use";
    extendedPermList.push_back(perm1);

    HapTokenInfoItem updatedInfo = hapInfoItem;
    updatedInfo.apiVersion = 15;

    manager.CommitUpdateHapCache(updatedInfo,
        BuildBriefData(1, PERMISSION_GRANTED, PERMISSION_DEFAULT_FLAG), extendedPermList);

    // Verify extended permissions are updated
    std::vector<PermissionWithValue> queriedExtendedPerms;
    PermissionDataBrief::GetInstance().GetExtendedValueList(TEST_TOKEN_ID, queriedExtendedPerms);
    ASSERT_EQ(1u, queriedExtendedPerms.size());
    EXPECT_EQ("ohos.permission.ACCESS_DDK_DRIVERS", queriedExtendedPerms[0].permissionName);
    EXPECT_EQ("in_use", queriedExtendedPerms[0].value);
}

/**
 * @tc.name: CommitUpdateHapCacheWithExtendedPerm002
 * @tc.desc: Verify update cache replaces existing extended permissions with new ones.
 * @tc.type: FUNC
 */
HWTEST_F(HapCacheCommitTest, CommitUpdateHapCacheWithExtendedPerm002, TestSize.Level0)
{
    auto& manager = AccessTokenInfoManager::GetInstance();
    auto hapInfoItem = BuildTestHapInfoItem(TEST_TOKEN_ID, "com.example.cache", 12);

    // Create with initial extended permissions
    std::vector<PermissionWithValue> initialExtendedList;
    PermissionWithValue perm1;
    perm1.permissionName = "ohos.permission.ACCESS_DDK_DRIVERS";
    perm1.value = "allowed";
    initialExtendedList.push_back(perm1);
    manager.CommitCreateHapCache(hapInfoItem, BuildBriefData(1, PERMISSION_GRANTED, 0), initialExtendedList);

    // Verify initial extended permissions
    std::vector<PermissionWithValue> queriedExtendedPerms;
    PermissionDataBrief::GetInstance().GetExtendedValueList(TEST_TOKEN_ID, queriedExtendedPerms);
    ASSERT_EQ(1u, queriedExtendedPerms.size());

    // Update with different extended permissions
    std::vector<PermissionWithValue> updatedExtendedList;
    PermissionWithValue perm2;
    perm2.permissionName = "ohos.permission.kernel.SUPPORT_PLUGIN";
    perm2.value = "denied";
    updatedExtendedList.push_back(perm2);

    manager.CommitUpdateHapCache(hapInfoItem,
        BuildBriefData(1, PERMISSION_GRANTED, PERMISSION_DEFAULT_FLAG), updatedExtendedList);

    // Verify extended permissions are replaced
    queriedExtendedPerms.clear();
    PermissionDataBrief::GetInstance().GetExtendedValueList(TEST_TOKEN_ID, queriedExtendedPerms);
    ASSERT_EQ(1u, queriedExtendedPerms.size());
    EXPECT_EQ("ohos.permission.kernel.SUPPORT_PLUGIN", queriedExtendedPerms[0].permissionName);
    EXPECT_EQ("denied", queriedExtendedPerms[0].value);
}

/**
 * @tc.name: RestoreHapCache001
 * @tc.desc: Verify RestoreHapCache correctly restores HAP token info with extended permissions.
 * @tc.type: FUNC
 */
HWTEST_F(HapCacheCommitTest, RestoreHapCache001, TestSize.Level0)
{
    auto& manager = AccessTokenInfoManager::GetInstance();
    std::vector<AccessTokenInfoManager::HapTokenRestoreData> tokenRestoreDataList = {
        BuildRestoreData(TEST_TOKEN_ID, "com.example.cache")
    };

    manager.RestoreHapCache(tokenRestoreDataList);

    // Verify HAP token info is restored
    ASSERT_NE(manager.hapTokenInfoMap_.find(TEST_TOKEN_ID), manager.hapTokenInfoMap_.end());
    ASSERT_NE(nullptr, manager.hapTokenInfoMap_[TEST_TOKEN_ID]);
    HapTokenInfo cachedInfo = manager.hapTokenInfoMap_[TEST_TOKEN_ID]->GetHapInfoBasic();
    EXPECT_EQ(TEST_TOKEN_ID, cachedInfo.tokenID);
    EXPECT_EQ("com.example.cache", cachedInfo.bundleName);
    EXPECT_EQ(12, cachedInfo.apiVersion);

    // Verify brief permissions are restored
    std::vector<BriefPermData> queriedData;
    ASSERT_EQ(RET_SUCCESS, PermissionDataBrief::GetInstance().GetBriefPermDataByTokenId(TEST_TOKEN_ID, queriedData));
    ASSERT_EQ(2u, queriedData.size());
    EXPECT_EQ(1, queriedData[0].permCode);
    EXPECT_EQ(2, queriedData[1].permCode);

    // Verify extended permissions are restored
    std::vector<PermissionWithValue> queriedExtendedPerms;
    PermissionDataBrief::GetInstance().GetExtendedValueList(TEST_TOKEN_ID, queriedExtendedPerms);
    ASSERT_EQ(1u, queriedExtendedPerms.size());
    EXPECT_EQ("ohos.permission.kernel.SUPPORT_PLUGIN", queriedExtendedPerms[0].permissionName);
    EXPECT_EQ("allowed", queriedExtendedPerms[0].value);
}

/**
 * @tc.name: RestoreHapCache002
 * @tc.desc: Verify RestoreHapCache with multiple tokens correctly restores all data.
 * @tc.type: FUNC
 */
HWTEST_F(HapCacheCommitTest, RestoreHapCache002, TestSize.Level0)
{
    auto& manager = AccessTokenInfoManager::GetInstance();

    // Build restore data for first token
    AccessTokenInfoManager::HapTokenRestoreData restoreData1;
    restoreData1.hapTokenInfoItem.tokenId = TEST_TOKEN_ID;
    restoreData1.hapTokenInfoItem.bundleName = "com.example.cache.multi";
    restoreData1.hapTokenInfoItem.userId = TEST_USER_ID;
    restoreData1.hapTokenInfoItem.apiVersion = 12;
    restoreData1.hapTokenInfoItem.instIndex = 0;
    restoreData1.hapTokenInfoItem.dlpType = DLP_COMMON;
    restoreData1.hapTokenInfoItem.tokenAttr = 0;
    restoreData1.hapTokenInfoItem.uid = 20100000;
    restoreData1.hapTokenInfoItem.apl = APL_NORMAL;
    restoreData1.requestedPermData = BuildBriefData(1, PERMISSION_GRANTED, 0);

    // Build restore data for second token
    AccessTokenInfoManager::HapTokenRestoreData restoreData2;
    restoreData2.hapTokenInfoItem.tokenId = TEST_TOKEN_ID_2;
    restoreData2.hapTokenInfoItem.bundleName = "com.example.cache.multi";
    restoreData2.hapTokenInfoItem.userId = TEST_USER_ID;
    restoreData2.hapTokenInfoItem.apiVersion = 12;
    restoreData2.hapTokenInfoItem.instIndex = 1;
    restoreData2.hapTokenInfoItem.dlpType = DLP_COMMON;
    restoreData2.hapTokenInfoItem.tokenAttr = 0;
    restoreData2.hapTokenInfoItem.uid = 20100001;
    restoreData2.hapTokenInfoItem.apl = APL_NORMAL;
    restoreData2.requestedPermData = BuildBriefData(2, PERMISSION_DENIED, 0);

    std::vector<AccessTokenInfoManager::HapTokenRestoreData> tokenRestoreDataList;
    tokenRestoreDataList.push_back(restoreData1);
    tokenRestoreDataList.push_back(restoreData2);

    manager.RestoreHapCache(tokenRestoreDataList);

    // Verify both tokens are restored
    ASSERT_NE(manager.hapTokenInfoMap_.find(TEST_TOKEN_ID), manager.hapTokenInfoMap_.end());
    ASSERT_NE(manager.hapTokenInfoMap_.find(TEST_TOKEN_ID_2), manager.hapTokenInfoMap_.end());
}

/**
 * @tc.name: RestoreHapCache003
 * @tc.desc: Verify RestoreHapCache restores hap cache from the restore data list only.
 * @tc.type: FUNC
 */
HWTEST_F(HapCacheCommitTest, RestoreHapCache003, TestSize.Level0)
{
    auto& manager = AccessTokenInfoManager::GetInstance();
    std::vector<AccessTokenInfoManager::HapTokenRestoreData> tokenRestoreDataList = {
        BuildRestoreData(TEST_TOKEN_ID, "com.example.cache")
    };
    // a userId no other case touches: proves the restore path feeds the cache
    constexpr int32_t restoreTestUserId = 101; // 101: restore-only test user
    tokenRestoreDataList[0].hapTokenInfoItem.userId = restoreTestUserId;

    manager.RestoreHapCache(tokenRestoreDataList);

    ASSERT_NE(manager.hapTokenInfoMap_.find(TEST_TOKEN_ID), manager.hapTokenInfoMap_.end());
    ASSERT_NE(nullptr, manager.hapTokenInfoMap_[TEST_TOKEN_ID]);
    HapTokenInfo cachedInfo = manager.hapTokenInfoMap_[TEST_TOKEN_ID]->GetHapInfoBasic();
    EXPECT_EQ(TEST_TOKEN_ID, cachedInfo.tokenID);
    EXPECT_EQ("com.example.cache", cachedInfo.bundleName);
    // the restore path also populates the userId cache
    EXPECT_EQ(1u, manager.userIdSet_.count(restoreTestUserId));

    std::vector<BriefPermData> queriedData;
    ASSERT_EQ(RET_SUCCESS, PermissionDataBrief::GetInstance().GetBriefPermDataByTokenId(TEST_TOKEN_ID, queriedData));
    ASSERT_EQ(2u, queriedData.size());

    std::vector<PermissionWithValue> queriedExtendedPerms;
    PermissionDataBrief::GetInstance().GetExtendedValueList(TEST_TOKEN_ID, queriedExtendedPerms);
    ASSERT_EQ(1u, queriedExtendedPerms.size());
    EXPECT_EQ("allowed", queriedExtendedPerms[0].value);
}
} // namespace AccessToken
} // namespace Security
} // namespace OHOS
