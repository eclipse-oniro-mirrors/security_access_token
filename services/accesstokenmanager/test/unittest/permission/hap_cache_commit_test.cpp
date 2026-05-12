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
constexpr AccessTokenID TEST_TOKEN_ID_2 = 0x20260429;
constexpr int32_t TEST_USER_ID = 100;
constexpr int32_t TEST_INST_INDEX = 0;

HapTokenInfo BuildTestHapInfo(AccessTokenID tokenId, const std::string& bundleName, int32_t apiVersion)
{
    HapTokenInfo info = {};
    info.ver = 1;
    info.userID = TEST_USER_ID;
    info.bundleName = bundleName;
    info.apiVersion = apiVersion;
    info.instIndex = TEST_INST_INDEX;
    info.dlpType = DLP_COMMON;
    info.tokenID = tokenId;
    info.tokenAttr = 0;
    info.uid = 20100000; //20100000: test uid
    return info;
}

std::vector<BriefPermData> BuildBriefData(uint16_t permCode, int8_t status, uint32_t flag)
{
    BriefPermData data = {0};
    data.permCode = permCode;
    data.status = status;
    data.flag = flag;
    return { data };
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
        manager.bundleInfoMap_.erase("com.example.cache");
        manager.bundleInfoMap_.erase("com.example.cache.updated");
        manager.bundleInfoMap_.erase("com.example.cache.multi");
        (void)PermissionDataBrief::GetInstance().DeleteBriefPermDataByTokenId(TEST_TOKEN_ID);
        (void)PermissionDataBrief::GetInstance().DeleteBriefPermDataByTokenId(TEST_TOKEN_ID_2);
    }
};

/**
 * @tc.name: CommitCreateHapCache001
 * @tc.desc: Verify create cache writes hap, bundle and brief caches.
 * @tc.type: FUNC
 */
HWTEST_F(HapCacheCommitTest, CommitCreateHapCache001, TestSize.Level0)
{
    auto& manager = AccessTokenInfoManager::GetInstance();
    auto hapInfo = BuildTestHapInfo(TEST_TOKEN_ID, "com.example.cache", 12);
    auto bundleInfo = std::make_shared<BundleInfoInner>();
    bundleInfo->tokenIds = { TEST_TOKEN_ID };
    bundleInfo->permCodeList = { 1 };
    auto briefData = BuildBriefData(1, PERMISSION_GRANTED, PERMISSION_SYSTEM_FIXED);

    manager.CommitCreateHapCache(hapInfo, briefData, bundleInfo);

    ASSERT_NE(manager.hapTokenInfoMap_.find(TEST_TOKEN_ID), manager.hapTokenInfoMap_.end());
    ASSERT_NE(nullptr, manager.hapTokenInfoMap_[TEST_TOKEN_ID]);
    HapTokenInfo cachedInfo = manager.hapTokenInfoMap_[TEST_TOKEN_ID]->GetHapInfoBasic();
    EXPECT_EQ(hapInfo.tokenID, cachedInfo.tokenID);
    EXPECT_EQ(hapInfo.bundleName, cachedInfo.bundleName);
    EXPECT_EQ(hapInfo.apiVersion, cachedInfo.apiVersion);
    ASSERT_NE(manager.hapTokenIdMap_.find("com.example.cache&100&0"), manager.hapTokenIdMap_.end());
    EXPECT_EQ(TEST_TOKEN_ID, manager.hapTokenIdMap_["com.example.cache&100&0"]);
    ASSERT_NE(manager.bundleInfoMap_.find("com.example.cache"), manager.bundleInfoMap_.end());
    EXPECT_EQ(bundleInfo, manager.bundleInfoMap_["com.example.cache"]);
    ASSERT_EQ(1u, manager.bundleInfoMap_["com.example.cache"]->tokenIds.size());
    EXPECT_EQ(TEST_TOKEN_ID, manager.bundleInfoMap_["com.example.cache"]->tokenIds[0]);

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
    auto hapInfo = BuildTestHapInfo(TEST_TOKEN_ID, "com.example.cache", 12);
    auto bundleInfo = std::make_shared<BundleInfoInner>();
    bundleInfo->tokenIds = { TEST_TOKEN_ID };
    bundleInfo->permCodeList = { 1 };
    manager.CommitCreateHapCache(hapInfo, BuildBriefData(1, PERMISSION_GRANTED, 0), bundleInfo);

    auto oldPtr = manager.hapTokenInfoMap_[TEST_TOKEN_ID];
    HapTokenInfo updatedInfo = hapInfo;
    updatedInfo.apiVersion = 15;
    updatedInfo.tokenAttr = 0x8;
    auto updatedBundleInfo = std::make_shared<BundleInfoInner>();
    updatedBundleInfo->tokenIds = { TEST_TOKEN_ID };
    updatedBundleInfo->permCodeList = { 2 };

    manager.CommitUpdateHapCache(updatedInfo,
        BuildBriefData(2, PERMISSION_DENIED, PERMISSION_DEFAULT_FLAG), updatedBundleInfo);

    ASSERT_NE(manager.hapTokenInfoMap_.find(TEST_TOKEN_ID), manager.hapTokenInfoMap_.end());
    EXPECT_EQ(oldPtr, manager.hapTokenInfoMap_[TEST_TOKEN_ID]);
    HapTokenInfo cachedInfo = manager.hapTokenInfoMap_[TEST_TOKEN_ID]->GetHapInfoBasic();
    EXPECT_EQ(15, cachedInfo.apiVersion);
    EXPECT_EQ(static_cast<uint32_t>(0x8), cachedInfo.tokenAttr);
    ASSERT_NE(manager.bundleInfoMap_.find("com.example.cache"), manager.bundleInfoMap_.end());
    EXPECT_EQ(updatedBundleInfo, manager.bundleInfoMap_["com.example.cache"]);
    ASSERT_EQ(1u, manager.bundleInfoMap_["com.example.cache"]->tokenIds.size());
    EXPECT_EQ(TEST_TOKEN_ID, manager.bundleInfoMap_["com.example.cache"]->tokenIds[0]);

    std::vector<BriefPermData> queriedData;
    ASSERT_EQ(RET_SUCCESS, PermissionDataBrief::GetInstance().GetBriefPermDataByTokenId(TEST_TOKEN_ID, queriedData));
    ASSERT_EQ(1u, queriedData.size());
    EXPECT_EQ(2, queriedData[0].permCode);
}

/**
 * @tc.name: CommitDeleteHapCache001
 * @tc.desc: Verify delete cache removes hap, bundle and brief caches.
 * @tc.type: FUNC
 */
HWTEST_F(HapCacheCommitTest, CommitDeleteHapCache001, TestSize.Level0)
{
    auto& manager = AccessTokenInfoManager::GetInstance();
    auto hapInfo = BuildTestHapInfo(TEST_TOKEN_ID, "com.example.cache", 12);
    auto bundleInfo = std::make_shared<BundleInfoInner>();
    bundleInfo->tokenIds = { TEST_TOKEN_ID };
    bundleInfo->permCodeList = { 1 };
    manager.CommitCreateHapCache(hapInfo, BuildBriefData(1, PERMISSION_GRANTED, 0), bundleInfo);

    manager.CommitDeleteHapCache(TEST_TOKEN_ID, "com.example.cache");

    EXPECT_EQ(manager.hapTokenInfoMap_.end(), manager.hapTokenInfoMap_.find(TEST_TOKEN_ID));
    EXPECT_EQ(manager.hapTokenIdMap_.end(), manager.hapTokenIdMap_.find("com.example.cache&100&0"));
    EXPECT_EQ(manager.bundleInfoMap_.end(), manager.bundleInfoMap_.find("com.example.cache"));

    std::vector<BriefPermData> queriedData;
    EXPECT_NE(RET_SUCCESS, PermissionDataBrief::GetInstance().GetBriefPermDataByTokenId(TEST_TOKEN_ID, queriedData));
}

/**
 * @tc.name: CommitUpdateHapCache002
 * @tc.desc: Verify update cache inherits original tokenIds when bundle info pointer changes.
 * @tc.type: FUNC
 */
HWTEST_F(HapCacheCommitTest, CommitUpdateHapCache002, TestSize.Level0)
{
    auto& manager = AccessTokenInfoManager::GetInstance();
    auto hapInfo = BuildTestHapInfo(TEST_TOKEN_ID, "com.example.cache", 12);
    auto bundleInfo = std::make_shared<BundleInfoInner>();
    bundleInfo->tokenIds = { TEST_TOKEN_ID };
    bundleInfo->permCodeList = { 1 };
    manager.CommitCreateHapCache(hapInfo, BuildBriefData(1, PERMISSION_GRANTED, 0), bundleInfo);

    auto updatedBundleInfo = std::make_shared<BundleInfoInner>();
    updatedBundleInfo->tokenIds = { TEST_TOKEN_ID_2 };
    updatedBundleInfo->permCodeList = { 2 };

    manager.CommitUpdateHapCache(hapInfo,
        BuildBriefData(2, PERMISSION_DENIED, PERMISSION_DEFAULT_FLAG), updatedBundleInfo);

    ASSERT_NE(manager.bundleInfoMap_.end(), manager.bundleInfoMap_.find("com.example.cache"));
    EXPECT_EQ(updatedBundleInfo, manager.bundleInfoMap_["com.example.cache"]);
    ASSERT_EQ(1u, manager.bundleInfoMap_["com.example.cache"]->tokenIds.size());
    EXPECT_EQ(TEST_TOKEN_ID, manager.bundleInfoMap_["com.example.cache"]->tokenIds[0]);
}

/**
 * @tc.name: CommitCreateHapCache002
 * @tc.desc: Verify create cache keeps existing tokenIds in the passed bundle info and appends current tokenId.
 * @tc.type: FUNC
 */
HWTEST_F(HapCacheCommitTest, CommitCreateHapCache002, TestSize.Level0)
{
    auto& manager = AccessTokenInfoManager::GetInstance();
    auto hapInfo = BuildTestHapInfo(TEST_TOKEN_ID, "com.example.cache", 12);
    auto bundleInfo = std::make_shared<BundleInfoInner>();
    bundleInfo->tokenIds = { TEST_TOKEN_ID_2 };
    bundleInfo->permCodeList = { 1 };

    manager.CommitCreateHapCache(hapInfo, BuildBriefData(1, PERMISSION_GRANTED, 0), bundleInfo);

    ASSERT_NE(manager.bundleInfoMap_.end(), manager.bundleInfoMap_.find("com.example.cache"));
    ASSERT_EQ(2u, manager.bundleInfoMap_["com.example.cache"]->tokenIds.size());
    EXPECT_NE(std::find(manager.bundleInfoMap_["com.example.cache"]->tokenIds.begin(),
        manager.bundleInfoMap_["com.example.cache"]->tokenIds.end(), TEST_TOKEN_ID),
        manager.bundleInfoMap_["com.example.cache"]->tokenIds.end());
    EXPECT_NE(std::find(manager.bundleInfoMap_["com.example.cache"]->tokenIds.begin(),
        manager.bundleInfoMap_["com.example.cache"]->tokenIds.end(), TEST_TOKEN_ID_2),
        manager.bundleInfoMap_["com.example.cache"]->tokenIds.end());
}

/**
 * @tc.name: CommitCreateHapCache003
 * @tc.desc: Verify create cache replaces different bundle info pointer and preserves old tokenIds.
 * @tc.type: FUNC
 */
HWTEST_F(HapCacheCommitTest, CommitCreateHapCache003, TestSize.Level0)
{
    auto& manager = AccessTokenInfoManager::GetInstance();
    auto oldBundleInfo = std::make_shared<BundleInfoInner>();
    oldBundleInfo->tokenIds = { TEST_TOKEN_ID_2 };
    oldBundleInfo->permCodeList = { 9 };
    manager.bundleInfoMap_["com.example.cache"] = oldBundleInfo;

    auto newBundleInfo = std::make_shared<BundleInfoInner>();
    newBundleInfo->tokenIds = {};
    newBundleInfo->permCodeList = { 1 };

    manager.CommitCreateHapCache(BuildTestHapInfo(TEST_TOKEN_ID, "com.example.cache", 12),
        BuildBriefData(1, PERMISSION_GRANTED, 0), newBundleInfo);

    ASSERT_NE(manager.bundleInfoMap_.end(), manager.bundleInfoMap_.find("com.example.cache"));
    EXPECT_EQ(newBundleInfo, manager.bundleInfoMap_["com.example.cache"]);
    ASSERT_EQ(2u, manager.bundleInfoMap_["com.example.cache"]->tokenIds.size());
    EXPECT_NE(std::find(manager.bundleInfoMap_["com.example.cache"]->tokenIds.begin(),
        manager.bundleInfoMap_["com.example.cache"]->tokenIds.end(), TEST_TOKEN_ID),
        manager.bundleInfoMap_["com.example.cache"]->tokenIds.end());
    EXPECT_NE(std::find(manager.bundleInfoMap_["com.example.cache"]->tokenIds.begin(),
        manager.bundleInfoMap_["com.example.cache"]->tokenIds.end(), TEST_TOKEN_ID_2),
        manager.bundleInfoMap_["com.example.cache"]->tokenIds.end());
}

/**
 * @tc.name: CommitCreateHapCache004
 * @tc.desc: Verify create cache does not append duplicate tokenIds into bundle info.
 * @tc.type: FUNC
 */
HWTEST_F(HapCacheCommitTest, CommitCreateHapCache004, TestSize.Level0)
{
    auto& manager = AccessTokenInfoManager::GetInstance();
    auto oldBundleInfo = std::make_shared<BundleInfoInner>();
    oldBundleInfo->tokenIds = { TEST_TOKEN_ID };
    oldBundleInfo->permCodeList = { 9 };
    manager.bundleInfoMap_["com.example.cache"] = oldBundleInfo;

    auto newBundleInfo = std::make_shared<BundleInfoInner>();
    newBundleInfo->tokenIds = { TEST_TOKEN_ID };
    newBundleInfo->permCodeList = { 1 };

    manager.CommitCreateHapCache(BuildTestHapInfo(TEST_TOKEN_ID, "com.example.cache", 12),
        BuildBriefData(1, PERMISSION_GRANTED, 0), newBundleInfo);

    ASSERT_NE(manager.bundleInfoMap_.end(), manager.bundleInfoMap_.find("com.example.cache"));
    EXPECT_EQ(newBundleInfo, manager.bundleInfoMap_["com.example.cache"]);
    ASSERT_EQ(1u, manager.bundleInfoMap_["com.example.cache"]->tokenIds.size());
    EXPECT_EQ(TEST_TOKEN_ID, manager.bundleInfoMap_["com.example.cache"]->tokenIds[0]);
}

/**
 * @tc.name: CommitUpdateHapCache004
 * @tc.desc: Verify update cache preserves original tokenIds when replacing bundle info content.
 * @tc.type: FUNC
 */
HWTEST_F(HapCacheCommitTest, CommitUpdateHapCache004, TestSize.Level0)
{
    auto& manager = AccessTokenInfoManager::GetInstance();
    auto hapInfo = BuildTestHapInfo(TEST_TOKEN_ID, "com.example.cache", 12);
    auto bundleInfo = std::make_shared<BundleInfoInner>();
    bundleInfo->tokenIds = { TEST_TOKEN_ID };
    bundleInfo->permCodeList = { 1 };
    manager.CommitCreateHapCache(hapInfo, BuildBriefData(1, PERMISSION_GRANTED, 0), bundleInfo);

    manager.bundleInfoMap_["com.example.cache"]->tokenIds = { TEST_TOKEN_ID, TEST_TOKEN_ID_2 };
    auto updatedBundleInfo = std::make_shared<BundleInfoInner>();
    updatedBundleInfo->tokenIds = {};
    updatedBundleInfo->permCodeList = { 2 };

    manager.CommitUpdateHapCache(hapInfo,
        BuildBriefData(2, PERMISSION_DENIED, PERMISSION_DEFAULT_FLAG), updatedBundleInfo);

    ASSERT_NE(manager.bundleInfoMap_.end(), manager.bundleInfoMap_.find("com.example.cache"));
    EXPECT_EQ(updatedBundleInfo, manager.bundleInfoMap_["com.example.cache"]);
    ASSERT_EQ(2u, manager.bundleInfoMap_["com.example.cache"]->tokenIds.size());
    EXPECT_NE(std::find(manager.bundleInfoMap_["com.example.cache"]->tokenIds.begin(),
        manager.bundleInfoMap_["com.example.cache"]->tokenIds.end(), TEST_TOKEN_ID),
        manager.bundleInfoMap_["com.example.cache"]->tokenIds.end());
    EXPECT_NE(std::find(manager.bundleInfoMap_["com.example.cache"]->tokenIds.begin(),
        manager.bundleInfoMap_["com.example.cache"]->tokenIds.end(), TEST_TOKEN_ID_2),
        manager.bundleInfoMap_["com.example.cache"]->tokenIds.end());
}

/**
 * @tc.name: CommitUpdateHapCache003
 * @tc.desc: Verify update cache is a no-op when token does not exist in cache.
 * @tc.type: FUNC
 */
HWTEST_F(HapCacheCommitTest, CommitUpdateHapCache003, TestSize.Level0)
{
    auto& manager = AccessTokenInfoManager::GetInstance();
    HapTokenInfo updatedInfo = BuildTestHapInfo(TEST_TOKEN_ID, "com.example.cache.updated", 15);
    auto updatedBundleInfo = std::make_shared<BundleInfoInner>();
    updatedBundleInfo->tokenIds = { TEST_TOKEN_ID };
    updatedBundleInfo->permCodeList = { 2 };

    manager.CommitUpdateHapCache(updatedInfo,
        BuildBriefData(2, PERMISSION_DENIED, PERMISSION_DEFAULT_FLAG), updatedBundleInfo);

    EXPECT_EQ(manager.hapTokenInfoMap_.end(), manager.hapTokenInfoMap_.find(TEST_TOKEN_ID));
    EXPECT_EQ(manager.hapTokenIdMap_.end(), manager.hapTokenIdMap_.find("com.example.cache.updated&100&0"));
    EXPECT_EQ(manager.bundleInfoMap_.end(), manager.bundleInfoMap_.find("com.example.cache.updated"));
}

/**
 * @tc.name: CommitDeleteHapCache002
 * @tc.desc: Verify delete cache keeps bundle cache when other tokenIds still belong to the same bundle.
 * @tc.type: FUNC
 */
HWTEST_F(HapCacheCommitTest, CommitDeleteHapCache002, TestSize.Level0)
{
    auto& manager = AccessTokenInfoManager::GetInstance();
    auto bundleInfo = std::make_shared<BundleInfoInner>();
    bundleInfo->tokenIds = { TEST_TOKEN_ID, TEST_TOKEN_ID_2 };
    bundleInfo->permCodeList = { 1, 2 };
    manager.CommitCreateHapCache(BuildTestHapInfo(TEST_TOKEN_ID, "com.example.cache.multi", 12),
        BuildBriefData(1, PERMISSION_GRANTED, 0), bundleInfo);
    manager.CommitCreateHapCache(BuildTestHapInfo(TEST_TOKEN_ID_2, "com.example.cache.multi", 12),
        BuildBriefData(2, PERMISSION_GRANTED, 0), bundleInfo);

    manager.CommitDeleteHapCache(TEST_TOKEN_ID, "com.example.cache.multi");

    EXPECT_EQ(manager.hapTokenInfoMap_.end(), manager.hapTokenInfoMap_.find(TEST_TOKEN_ID));
    ASSERT_NE(manager.hapTokenInfoMap_.end(), manager.hapTokenInfoMap_.find(TEST_TOKEN_ID_2));
    ASSERT_NE(manager.bundleInfoMap_.end(), manager.bundleInfoMap_.find("com.example.cache.multi"));
    ASSERT_NE(nullptr, manager.bundleInfoMap_["com.example.cache.multi"]);
    ASSERT_EQ(1u, manager.bundleInfoMap_["com.example.cache.multi"]->tokenIds.size());
    EXPECT_EQ(TEST_TOKEN_ID_2, manager.bundleInfoMap_["com.example.cache.multi"]->tokenIds[0]);
}
} // namespace AccessToken
} // namespace Security
} // namespace OHOS
