/*
 * Copyright (c) 2021-2026 Huawei Device Co., Ltd.
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

#include "token_info_manager_test.h"

#include <algorithm>
#include <atomic>
#include <fcntl.h>
#include <gmock/gmock.h>
#include <limits>
#include <thread>
#include <unordered_set>
#include <vector>

#include "accesstoken_id_manager.h"
#include "access_token_error.h"
#include "access_token_db.h"
#define private public
#include "accesstoken_callback_stubs.h"
#include "access_token_db_operator.h"
#include "accesstoken_info_utils.h"
#include "accesstoken_info_manager.h"
#include "accesstoken_remote_token_manager.h"
#ifdef SUPPORT_SANDBOX_APP
#include "dlp_permission_set_manager.h"
#endif
#include "libraryloader.h"
#include "token_field_const.h"
#include "user_policy_manager.h"
#ifdef TOKEN_SYNC_ENABLE
#include "token_sync_kit_loader.h"
#endif
#include "permission_manager.h"
#include "permission_constraint_check.h"
#include "token_modify_notifier.h"
#undef private
#ifdef ACCESS_TOKEN_SUPPORT_SUBPROFILE
#include "os_account_manager_lite.h"
#endif
#include "permission_kernel_utils.h"
#include "permission_map.h"
#include "permission_validator.h"
#include "string_ex.h"
#include "token_setproc.h"
#include "system_ability_definition.h"

using namespace testing::ext;
using namespace OHOS;

namespace OHOS {
namespace Security {
namespace AccessToken {
namespace {
static constexpr int32_t RANDOM_TOKENID = 123;
static constexpr int32_t DEFAULT_API_VERSION = 8;
static constexpr int USER_ID = 100;
static constexpr int INST_INDEX = 0;
static constexpr int32_t MAX_EXTENDED_MAP_SIZE = 512;
static constexpr int32_t MAX_VALUE_LENGTH = 1024;
#ifdef SUPPORT_MANAGE_USER_POLICY
static constexpr uint32_t USER_POLICY_MAX_LIST_SIZE = 1024;
#endif
#ifdef ACCESS_TOKEN_SUPPORT_SUBPROFILE
static constexpr int32_t SUBPROFILE_TEST_ID = 10;
static constexpr int32_t SUBPROFILE_TEST_INDEX = 1;

class SubProfileTestStateGuard {
public:
    ~SubProfileTestStateGuard()
    {
        ResetMockOsAccountManagerLite();
        for (const auto tokenId : tokenIdList_) {
            (void)AccessTokenInfoManager::GetInstance().RemoveHapTokenInfo(tokenId);
        }
    }

    void AddTokenId(AccessTokenID tokenId)
    {
        if (tokenId != INVALID_TOKENID) {
            tokenIdList_.emplace_back(tokenId);
        }
    }

private:
    std::vector<AccessTokenID> tokenIdList_;
};
#endif
static constexpr int32_t INVALID_GRANT_MODE = 1000;
static const int32_t TOKEN_ATTR_RESERVED = 0x4;
static AccessTokenID g_selfTokenId = 0;
static PermissionDef g_infoManagerTestPermDef1 = {
    .permissionName = "open the door",
    .bundleName = "accesstoken_test",
    .grantMode = 1,
    .availableLevel = APL_NORMAL,
    .provisionEnable = false,
    .distributedSceneEnable = false,
    .label = "label",
    .labelId = 1,
    .description = "open the door",
    .descriptionId = 1
};

static PermissionDef g_infoManagerTestPermDef2 = {
    .permissionName = "break the door",
    .bundleName = "accesstoken_test",
    .grantMode = 1,
    .availableLevel = APL_NORMAL,
    .provisionEnable = false,
    .distributedSceneEnable = false,
    .label = "label",
    .labelId = 1,
    .description = "break the door",
    .descriptionId = 1
};

static PermissionStatus g_infoManagerTestState1 = {
    .permissionName = "open the door",
    .grantStatus = 1,
    .grantFlag = 1
};

static PermissionStatus g_infoManagerTestState2 = {
    .permissionName = "break the door",
    .grantStatus = 1,
    .grantFlag = 1
};

static HapInfoParams g_infoManagerTestInfoParms = {
    .userID = 1,
    .bundleName = "accesstoken_test",
    .instIndex = 0,
    .appIDDesc = "testtesttesttest",
    .isSystemApp = false
};

static HapInfoParams g_infoManagerTestInfoParms2 = {
    .userID = 1,
    .bundleName = "token_info_manager_test2",
    .instIndex = 0,
    .appIDDesc = "testtesttesttest",
    .isSystemApp = true
};

static HapPolicy g_infoManagerTestPolicyPrams1 = {
    .apl = APL_NORMAL,
    .domain = "test.domain",
    .permList = {g_infoManagerTestPermDef1, g_infoManagerTestPermDef2},
    .permStateList = {g_infoManagerTestState1, g_infoManagerTestState2}
};

static PermissionStatus g_permState = {
    .permissionName = "ohos.permission.CAMERA",
    .grantStatus = PermissionState::PERMISSION_DENIED,
    .grantFlag = PermissionFlag::PERMISSION_DEFAULT_FLAG
};

#ifdef SUPPORT_MANAGE_USER_POLICY
class PolicyWhiteListStateGuard {
public:
    PolicyWhiteListStateGuard(UserPolicyManager& manager, uint32_t permCode)
        : manager_(manager), permCode_(permCode)
    {
        std::unique_lock<std::shared_mutex> lock(manager_.userPolicyLock_);
        auto recordIter = manager_.userPolicyRecords_.find(permCode_);
        if (recordIter != manager_.userPolicyRecords_.end()) {
            hasRecord_ = true;
            oldRecord_ = recordIter->second;
        }
    }

    ~PolicyWhiteListStateGuard()
    {
        std::unique_lock<std::shared_mutex> lock(manager_.userPolicyLock_);
        if (hasRecord_) {
            manager_.userPolicyRecords_[permCode_] = oldRecord_;
        } else {
            manager_.userPolicyRecords_.erase(permCode_);
        }
    }

    void SetControlledUser(int32_t userId, AccessTokenID controller)
    {
        std::unique_lock<std::shared_mutex> lock(manager_.userPolicyLock_);
        auto& record = manager_.userPolicyRecords_[permCode_];
        record.userList = { userId };
        record.controllerToken = controller;
        record.whiteList.clear();
    }

    void SetWhiteList(int32_t userId, AccessTokenID controller, const std::unordered_set<AccessTokenID>& whiteList,
        bool isPersist = false)
    {
        std::unique_lock<std::shared_mutex> lock(manager_.userPolicyLock_);
        auto& record = manager_.userPolicyRecords_[permCode_];
        record.userList = { userId };
        record.controllerToken = controller;
        record.whiteList = whiteList;
        record.isPersist = isPersist;
    }

    void EraseRecord()
    {
        std::unique_lock<std::shared_mutex> lock(manager_.userPolicyLock_);
        manager_.userPolicyRecords_.erase(permCode_);
    }

private:
    UserPolicyManager& manager_;
    uint32_t permCode_;
    UserPolicyRecord oldRecord_;
    bool hasRecord_ = false;
};

class UserPolicyRecordsGuard {
public:
    explicit UserPolicyRecordsGuard(UserPolicyManager& manager) : manager_(manager)
    {
        std::unique_lock<std::shared_mutex> lock(manager_.userPolicyLock_);
        oldRecords_ = manager_.userPolicyRecords_;
    }

    ~UserPolicyRecordsGuard()
    {
        std::unique_lock<std::shared_mutex> lock(manager_.userPolicyLock_);
        manager_.userPolicyRecords_ = oldRecords_;
    }

private:
    UserPolicyManager& manager_;
    std::map<uint32_t, UserPolicyRecord> oldRecords_;
};

static GenericValues BuildUserPolicyDbCondition(const std::string& permissionName)
{
    GenericValues condition;
    condition.Put(TokenFiledConst::FIELD_PERMISSION_NAME, permissionName);
    return condition;
}

static GenericValues BuildPermissionStateDbCondition(AccessTokenID tokenId, const std::string& permissionName)
{
    GenericValues condition;
    condition.Put(TokenFiledConst::FIELD_TOKEN_ID, static_cast<int32_t>(tokenId));
    condition.Put(TokenFiledConst::FIELD_PERMISSION_NAME, permissionName);
    return condition;
}

static int32_t DeleteUserPolicyDbRecord(const std::string& permissionName)
{
    DelInfo delInfo;
    delInfo.delType = AtmDataType::ACCESSTOKEN_USER_POLICY;
    delInfo.delValue = BuildUserPolicyDbCondition(permissionName);
    return AccessTokenDb::GetInstance()->DeleteAndInsertValues({ delInfo }, {});
}

static void ExpectBriefPermissionState(AccessTokenID tokenId, uint32_t permCode, int32_t status, uint32_t flag)
{
    int32_t cacheStatus = PermissionState::PERMISSION_DENIED;
    uint32_t cacheFlag = PermissionFlag::PERMISSION_DEFAULT_FLAG;
    EXPECT_EQ(RET_SUCCESS,
        PermissionDataBrief::GetInstance().QueryEffectivePermissionStatusAndFlag(
            tokenId, permCode, cacheStatus, cacheFlag));
    EXPECT_EQ(status, cacheStatus);
    EXPECT_EQ(flag, cacheFlag);
}

static void ExpectDbPermissionState(AccessTokenID tokenId, const std::string& permissionName,
    int32_t status, uint32_t flag)
{
    std::vector<GenericValues> results;
    EXPECT_EQ(RET_SUCCESS,
        AccessTokenDb::GetInstance()->Find(AtmDataType::ACCESSTOKEN_PERMISSION_STATE,
            BuildPermissionStateDbCondition(tokenId, permissionName), results));
    ASSERT_EQ(1u, results.size());
    EXPECT_EQ(status, results[0].GetInt(TokenFiledConst::FIELD_GRANT_STATE));
    EXPECT_EQ(static_cast<int32_t>(flag), results[0].GetInt(TokenFiledConst::FIELD_GRANT_FLAG));
}

static void ExpectCacheAndDbPermissionState(AccessTokenID tokenId, uint32_t permCode,
    const std::string& permissionName, int32_t status, uint32_t cacheFlag, uint32_t dbFlag)
{
    ExpectBriefPermissionState(tokenId, permCode, status, cacheFlag);
    ExpectDbPermissionState(tokenId, permissionName, status, dbFlag);
}

static void ExpectUserPolicyDbRecord(const std::string& permissionName, AccessTokenID controllerToken,
    const std::string& restrictedUser)
{
    std::vector<GenericValues> results;
    EXPECT_EQ(RET_SUCCESS,
        AccessTokenDb::GetInstance()->Find(AtmDataType::ACCESSTOKEN_USER_POLICY,
            BuildUserPolicyDbCondition(permissionName), results));
    ASSERT_EQ(1u, results.size());
    EXPECT_EQ(permissionName, results[0].GetString(TokenFiledConst::FIELD_PERMISSION_NAME));
    EXPECT_EQ(static_cast<int32_t>(controllerToken), results[0].GetInt(TokenFiledConst::FIELD_CONTROLLER_TOKENID));
    EXPECT_EQ(restrictedUser, results[0].GetString(TokenFiledConst::FIELD_RESTRICTED_USER));
}

static void ExpectNoUserPolicyDbRecord(const std::string& permissionName)
{
    std::vector<GenericValues> results;
    EXPECT_EQ(RET_SUCCESS,
        AccessTokenDb::GetInstance()->Find(AtmDataType::ACCESSTOKEN_USER_POLICY,
            BuildUserPolicyDbCondition(permissionName), results));
    EXPECT_TRUE(results.empty());
}

static void ExpectUserPolicyDbWhiteList(const std::string& permissionName, const std::string& whiteList)
{
    std::vector<GenericValues> results;
    EXPECT_EQ(RET_SUCCESS,
        AccessTokenDb::GetInstance()->Find(AtmDataType::ACCESSTOKEN_USER_POLICY,
            BuildUserPolicyDbCondition(permissionName), results));
    ASSERT_EQ(1u, results.size());
    EXPECT_EQ(whiteList, results[0].GetString(TokenFiledConst::FIELD_WHITELIST));
}

static int32_t UpsertUserPolicyDbRecord(
    const std::string& permissionName, AccessTokenID controllerToken, const std::string& userList,
    const std::string& whiteList)
{
    DelInfo delInfo;
    delInfo.delType = AtmDataType::ACCESSTOKEN_USER_POLICY;
    delInfo.delValue = BuildUserPolicyDbCondition(permissionName);

    GenericValues addValue;
    addValue.Put(TokenFiledConst::FIELD_PERMISSION_NAME, permissionName);
    addValue.Put(TokenFiledConst::FIELD_CONTROLLER_TOKENID, static_cast<int32_t>(controllerToken));
    addValue.Put(TokenFiledConst::FIELD_RESTRICTED_USER, userList);
    addValue.Put(TokenFiledConst::FIELD_WHITELIST, whiteList);

    AddInfo addInfo;
    addInfo.addType = AtmDataType::ACCESSTOKEN_USER_POLICY;
    addInfo.addValues = { addValue };
    return AccessTokenDb::GetInstance()->DeleteAndInsertValues({ delInfo }, { addInfo });
}
#endif

#ifdef TOKEN_SYNC_ENABLE
static uint32_t tokenSyncId_ = 0;
static const int32_t FAKE_SYNC_RET = 0xabcdef;
class TokenSyncCallbackMock : public TokenSyncCallbackStub {
public:
    TokenSyncCallbackMock() = default;
    virtual ~TokenSyncCallbackMock() = default;

    MOCK_METHOD(int32_t, GetRemoteHapTokenInfo, (const std::string&, AccessTokenID), (override));
    MOCK_METHOD(int32_t, DeleteRemoteHapTokenInfo, (AccessTokenID), (override));
    MOCK_METHOD(int32_t, UpdateRemoteHapTokenInfo, (const HapTokenInfoForSync&), (override));
};
#endif
}

void TokenInfoManagerTest::SetUpTestCase()
{
    g_selfTokenId = GetSelfTokenID();
    uint32_t hapSize = 0;
    uint32_t nativeSize = 0;
    uint32_t pefDefSize = 0;
    uint32_t dlpSize = 0;
    std::map<int32_t, TokenIdInfo> tokenIdAplMap;
    AccessTokenInfoManager::GetInstance().Init(hapSize, nativeSize, pefDefSize, dlpSize, tokenIdAplMap);
}

void TokenInfoManagerTest::TearDownTestCase()
{
    sleep(3); // delay 3 minutes
    SetSelfTokenID(g_selfTokenId);
}

void TokenInfoManagerTest::SetUp()
{
    atManagerService_ = DelayedSingleton<AccessTokenManagerService>::GetInstance();
    EXPECT_NE(nullptr, atManagerService_);
}

void TokenInfoManagerTest::TearDown()
{
    atManagerService_ = nullptr;
    setuid(0);
}

/**
 * @tc.name: HapTokenInfoInner001
 * @tc.desc: HapTokenInfoInner::HapTokenInfoInner.
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(TokenInfoManagerTest, HapTokenInfoInner001, TestSize.Level0)
{
    AccessTokenID id = 0x20240112;
    HapTokenInfo info = {
        .ver = 1,
        .userID = 1,
        .bundleName = "com.ohos.access_token",
        .instIndex = 1,
        .tokenID = id,
        .tokenAttr = 0
    };
    std::vector<PermissionStatus> permStateList;
    std::shared_ptr<HapTokenInfoInner> hap = std::make_shared<HapTokenInfoInner>(id, info, permStateList);
    ASSERT_EQ(hap->IsRemote(), false);
    hap->SetRemote(true);
    std::vector<GenericValues> valueList;
    hap->GenerateHapInfoValues("test", APL_NORMAL, valueList);

    hap->GeneratePermStateValues({}, valueList);
    ASSERT_EQ(hap->IsRemote(), true);
    hap->SetRemote(false);
    int32_t version = hap->GetApiVersion(5608);
    ASSERT_EQ(static_cast<int32_t>(608), version);
}

#ifdef SUPPORT_SANDBOX_APP
/**
 * @tc.name: IsPermissionAvailableToDlpHap001
 * @tc.desc: DlpPermissionSetManager::IsPermissionAvailableToDlpHap supports permCode input
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(TokenInfoManagerTest, IsPermissionAvailableToDlpHap001, TestSize.Level0)
{
    uint32_t cameraCode = 0;
    ASSERT_TRUE(TransferPermissionToOpcode("ohos.permission.CAMERA", cameraCode));

    auto& manager = DlpPermissionSetManager::GetInstance();
    EXPECT_EQ(manager.IsPermissionAvailableToDlpHap(DLP_READ, "ohos.permission.CAMERA"),
        manager.IsPermissionAvailableToDlpHap(DLP_READ, cameraCode));
    EXPECT_FALSE(manager.IsPermissionAvailableToDlpHap(DLP_READ, std::numeric_limits<uint32_t>::max()));
}
#endif

/**
 * @tc.name: GetBundleInfoInner001
 * @tc.desc: AccessTokenInfoManager::GetBundleInfoInner returns existing bundle cache and does not create one.
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(TokenInfoManagerTest, GetBundleInfoInner001, TestSize.Level0)
{
    auto& manager = AccessTokenInfoManager::GetInstance();
    const std::string bundleName = "com.ohos.bundle.info.inner";
    manager.bundleInfoMap_.erase(bundleName);

    auto queried = manager.GetBundleInfoInner(bundleName);
    EXPECT_EQ(nullptr, queried);
    EXPECT_EQ(manager.bundleInfoMap_.end(), manager.bundleInfoMap_.find(bundleName));

    auto cached = std::make_shared<BundleInfoInner>();
    cached->permCodeList = { 1, 2 };
    manager.bundleInfoMap_[bundleName] = cached;
    queried = manager.GetBundleInfoInner(bundleName);
    EXPECT_EQ(cached, queried);
    ASSERT_NE(nullptr, queried);
    ASSERT_EQ(2u, queried->permCodeList.size());

    manager.bundleInfoMap_.erase(bundleName);
}

/**
 * @tc.name: UpsertBundleInfoInnerCache001
 * @tc.desc: AccessTokenInfoManager::UpsertBundleInfoInnerCache inserts and updates bundle cache.
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(TokenInfoManagerTest, UpsertBundleInfoInnerCache001, TestSize.Level0)
{
    auto& manager = AccessTokenInfoManager::GetInstance();
    const std::string bundleName = "com.ohos.bundle.info.upsert";
    manager.bundleInfoMap_.erase(bundleName);

    auto first = std::make_shared<BundleInfoInner>();
    first->tokenIds = { 1 };
    manager.UpsertBundleInfoInnerCache(bundleName, first);
    ASSERT_NE(manager.bundleInfoMap_.end(), manager.bundleInfoMap_.find(bundleName));
    EXPECT_EQ(first, manager.bundleInfoMap_[bundleName]);

    auto second = std::make_shared<BundleInfoInner>();
    second->tokenIds = { 2, 3 };
    manager.UpsertBundleInfoInnerCache(bundleName, second);
    EXPECT_EQ(second, manager.bundleInfoMap_[bundleName]);
    ASSERT_EQ(2u, manager.bundleInfoMap_[bundleName]->tokenIds.size());

    manager.bundleInfoMap_.erase(bundleName);
}

/**
 * @tc.name: GetHapTokenIdListByBundleName001
 * @tc.desc: AccessTokenInfoManager::GetHapTokenIdListByBundleName gets token IDs from hap token info cache.
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(TokenInfoManagerTest, GetHapTokenIdListByBundleName001, TestSize.Level0)
{
    auto& manager = AccessTokenInfoManager::GetInstance();
    HapInfoParams info = g_infoManagerTestInfoParms;
    info.bundleName = "com.ohos.bundle.token.id.list";
    info.appIDDesc = info.bundleName;

    AccessTokenIDEx tokenIdEx = {0};
    std::vector<GenericValues> undefValues;
    ASSERT_EQ(RET_SUCCESS, manager.CreateHapTokenInfo(info, g_infoManagerTestPolicyPrams1, tokenIdEx, undefValues));
    AccessTokenID tokenId = tokenIdEx.tokenIdExStruct.tokenID;
    ASSERT_NE(INVALID_TOKENID, tokenId);

    manager.bundleInfoMap_.erase(info.bundleName);
    std::vector<AccessTokenID> tokenIdList;
    ASSERT_EQ(RET_SUCCESS, manager.GetHapTokenIdListByBundleName(info.bundleName, tokenIdList));
    ASSERT_EQ(1u, tokenIdList.size());
    EXPECT_EQ(tokenId, tokenIdList[0]);

    AccessTokenID remoteTokenId = 0x20240615;
    HapTokenInfo remoteInfo = {
        .ver = DEFAULT_TOKEN_VERSION,
        .userID = info.userID,
        .bundleName = info.bundleName,
        .instIndex = 1,
        .tokenID = remoteTokenId
    };
    auto remoteHap = std::make_shared<HapTokenInfoInner>(remoteTokenId, remoteInfo, std::vector<PermissionStatus>());
    remoteHap->SetRemote(true);
    manager.hapTokenInfoMap_[remoteTokenId] = remoteHap;

    tokenIdList.clear();
    ASSERT_EQ(RET_SUCCESS, manager.GetHapTokenIdListByBundleName(info.bundleName, tokenIdList));
    ASSERT_EQ(1u, tokenIdList.size());
    EXPECT_EQ(tokenId, tokenIdList[0]);

    manager.hapTokenInfoMap_.erase(remoteTokenId);
    (void)manager.RemoveHapTokenInfo(tokenId);
}

/**
 * @tc.name: CreateHapTokenInfo001
 * @tc.desc: Verify the CreateHapTokenInfo add one hap token function.
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(TokenInfoManagerTest, CreateHapTokenInfo001, TestSize.Level0)
{
    AccessTokenIDEx tokenIdEx = {0};
    std::vector<GenericValues> undefValues;
    int ret = AccessTokenInfoManager::GetInstance().CreateHapTokenInfo(g_infoManagerTestInfoParms,
        g_infoManagerTestPolicyPrams1, tokenIdEx, undefValues);
    ASSERT_EQ(RET_SUCCESS, ret);
    AccessTokenID tokenId = tokenIdEx.tokenIdExStruct.tokenID;
    GTEST_LOG_(INFO) << "add a hap token " << tokenId;

    std::shared_ptr<HapTokenInfoInner> tokenInfo;
    tokenInfo = AccessTokenInfoManager::GetInstance().GetHapTokenInfoInner(tokenId);
    ASSERT_NE(nullptr, tokenInfo);

    ret = AccessTokenInfoManager::GetInstance().RemoveHapTokenInfo(tokenId);
    ASSERT_EQ(RET_SUCCESS, ret);
    GTEST_LOG_(INFO) << "remove the token info";

    tokenInfo = AccessTokenInfoManager::GetInstance().GetHapTokenInfoInner(tokenId);
    ASSERT_EQ(nullptr, tokenInfo);
}

/**
 * @tc.name: CreateHapTokenInfo002
 * @tc.desc: Verify the CreateHapTokenInfo add one hap token twice function.
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(TokenInfoManagerTest, CreateHapTokenInfo002, TestSize.Level0)
{
    AccessTokenIDEx tokenIdEx = {0};
    std::vector<GenericValues> undefValues;
    int ret = AccessTokenInfoManager::GetInstance().CreateHapTokenInfo(g_infoManagerTestInfoParms,
        g_infoManagerTestPolicyPrams1, tokenIdEx, undefValues);
    ASSERT_EQ(RET_SUCCESS, ret);
    GTEST_LOG_(INFO) << "add a hap token " << tokenIdEx.tokenIdExStruct.tokenID;

    AccessTokenIDEx tokenIdEx1 = {0};
    ret = AccessTokenInfoManager::GetInstance().CreateHapTokenInfo(g_infoManagerTestInfoParms,
        g_infoManagerTestPolicyPrams1, tokenIdEx1, undefValues);
    ASSERT_EQ(RET_SUCCESS, ret);
    ASSERT_NE(tokenIdEx.tokenIdExStruct.tokenID, tokenIdEx1.tokenIdExStruct.tokenID);
    GTEST_LOG_(INFO) << "add same hap token";

    std::shared_ptr<HapTokenInfoInner> tokenInfo;
    tokenInfo = AccessTokenInfoManager::GetInstance().GetHapTokenInfoInner(tokenIdEx1.tokenIdExStruct.tokenID);
    ASSERT_NE(nullptr, tokenInfo);

    ret = AccessTokenInfoManager::GetInstance().RemoveHapTokenInfo(tokenIdEx1.tokenIdExStruct.tokenID);
    ASSERT_EQ(RET_SUCCESS, ret);
    GTEST_LOG_(INFO) << "remove the token info";
}

/**
 * @tc.name: CreateHapTokenInfo003
 * @tc.desc: AccessTokenInfoManager::CreateHapTokenInfo function test userID invalid
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(TokenInfoManagerTest, CreateHapTokenInfo003, TestSize.Level0)
{
    HapInfoParams info = {
        .userID = -1
    };
    HapPolicy policy;
    AccessTokenIDEx tokenIdEx;
    std::vector<GenericValues> undefValues;

    ASSERT_NE(RET_SUCCESS, AccessTokenInfoManager::GetInstance().CreateHapTokenInfo(info, policy, tokenIdEx,
        undefValues));
}

/**
 * @tc.name: CreateHapTokenInfo004
 * @tc.desc: AccessTokenInfoManager::CreateHapTokenInfo function test bundleName invalid
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(TokenInfoManagerTest, CreateHapTokenInfo004, TestSize.Level0)
{
    HapInfoParams info = {
        .userID = USER_ID,
        .bundleName = ""
    };
    HapPolicy policy;
    AccessTokenIDEx tokenIdEx;
    std::vector<GenericValues> undefValues;

    ASSERT_NE(RET_SUCCESS, AccessTokenInfoManager::GetInstance().CreateHapTokenInfo(info, policy, tokenIdEx,
        undefValues));
}

/**
 * @tc.name: CreateHapTokenInfo005
 * @tc.desc: AccessTokenInfoManager::CreateHapTokenInfo function test appIDDesc invalid
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(TokenInfoManagerTest, CreateHapTokenInfo005, TestSize.Level0)
{
    HapInfoParams info = {
        .userID = USER_ID,
        .bundleName = "ohos.com.testtesttest",
        .appIDDesc = ""
    };
    HapPolicy policy;
    AccessTokenIDEx tokenIdEx;
    std::vector<GenericValues> undefValues;

    ASSERT_NE(RET_SUCCESS, AccessTokenInfoManager::GetInstance().CreateHapTokenInfo(info, policy, tokenIdEx,
        undefValues));
}

/**
 * @tc.name: CreateHapTokenInfo006
 * @tc.desc: AccessTokenInfoManager::CreateHapTokenInfo function test domain invalid
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(TokenInfoManagerTest, CreateHapTokenInfo006, TestSize.Level0)
{
    HapInfoParams info = {
        .userID = USER_ID,
        .bundleName = "ohos.com.testtesttest",
        .appIDDesc = "who cares"
    };
    HapPolicy policy = {
        .domain = ""
    };
    AccessTokenIDEx tokenIdEx;
    std::vector<GenericValues> undefValues;

    ASSERT_NE(RET_SUCCESS, AccessTokenInfoManager::GetInstance().CreateHapTokenInfo(info, policy, tokenIdEx,
        undefValues));
}

/**
 * @tc.name: CreateHapTokenInfo007
 * @tc.desc: AccessTokenInfoManager::CreateHapTokenInfo function test dlpType invalid
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(TokenInfoManagerTest, CreateHapTokenInfo007, TestSize.Level0)
{
    HapInfoParams info = {
        .userID = USER_ID,
        .bundleName = "ohos.com.testtesttest",
        .dlpType = -1,
        .appIDDesc = "who cares"
    };
    HapPolicy policy = {
        .domain = "who cares"
    };
    AccessTokenIDEx tokenIdEx;
    std::vector<GenericValues> undefValues;

    ASSERT_NE(RET_SUCCESS, AccessTokenInfoManager::GetInstance().CreateHapTokenInfo(info, policy, tokenIdEx,
        undefValues));
}

/**
 * @tc.name: CreateHapTokenInfo008
 * @tc.desc: AccessTokenInfoManager::CreateHapTokenInfo function test grant mode invalid
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(TokenInfoManagerTest, CreateHapTokenInfo008, TestSize.Level0)
{
    static PermissionDef permDef = {
        .permissionName = "ohos.permission.test",
        .bundleName = "accesstoken_test",
        .grantMode = -1,    // -1:invalid grant mode
        .availableLevel = APL_NORMAL,
        .provisionEnable = false,
        .distributedSceneEnable = false,
        .label = "label",
        .labelId = 1,
        .description = "open the door",
        .descriptionId = 1
    };
    HapInfoParams info = {
        .userID = USER_ID,
        .bundleName = "ohos.com.testtesttest",
        .appIDDesc = ""
    };
    HapPolicy policy = {
        .apl = APL_NORMAL,
        .domain = "test.domain",
        .permList = {permDef}
    };
    AccessTokenIDEx tokenIdEx;
    std::vector<GenericValues> undefValues;
    ASSERT_NE(RET_SUCCESS, AccessTokenInfoManager::GetInstance().CreateHapTokenInfo(info, policy, tokenIdEx,
        undefValues));
}

/**
 * @tc.name: InitHapToken001
 * @tc.desc: InitHapToken function test with invalid userID
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(TokenInfoManagerTest, InitHapToken001, TestSize.Level0)
{
    HapInfoParcel hapinfoParcel;
    hapinfoParcel.hapInfoParameter = {
        .userID = -1,
        .bundleName = "accesstoken_test",
        .instIndex = 0,
        .dlpType = DLP_COMMON,
        .appIDDesc = "testtesttesttest",
        .apiVersion = DEFAULT_API_VERSION,
        .isSystemApp = false,
    };
    HapPolicyParcel hapPolicyParcel;
    hapPolicyParcel.hapPolicy.apl = ATokenAplEnum::APL_NORMAL;
    hapPolicyParcel.hapPolicy.domain = "test.domain";
    uint64_t fullTokenId;
    HapInfoCheckResultIdl result;
    ASSERT_EQ(ERR_PARAM_INVALID,
        atManagerService_->InitHapToken(hapinfoParcel, hapPolicyParcel, fullTokenId, result));
}

/**
 * @tc.name: InitHapToken002
 * @tc.desc: InitHapToken function test with invalid userID
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(TokenInfoManagerTest, InitHapToken002, TestSize.Level0)
{
    HapInfoParcel hapinfoParcel;
    hapinfoParcel.hapInfoParameter = {
        .userID = -1,
        .bundleName = "accesstoken_test",
        .instIndex = 0,
        .dlpType = DLP_READ,
        .appIDDesc = "testtesttesttest",
        .apiVersion = DEFAULT_API_VERSION,
        .isSystemApp = false,
    };
    HapPolicyParcel hapPolicyParcel;
    hapPolicyParcel.hapPolicy.apl = ATokenAplEnum::APL_NORMAL;
    hapPolicyParcel.hapPolicy.domain = "test.domain";
    uint64_t fullTokenId;
    HapInfoCheckResultIdl result;
    ASSERT_EQ(ERR_PERM_REQUEST_CFG_FAILED,
        atManagerService_->InitHapToken(hapinfoParcel, hapPolicyParcel, fullTokenId, result));
}

/**
 * @tc.name: InitHapToken003
 * @tc.desc: InitHapToken function test with invalid apl permission
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(TokenInfoManagerTest, InitHapToken003, TestSize.Level0)
{
    HapInfoParcel info;
    info.hapInfoParameter = {
        .userID = 0,
        .bundleName = "accesstoken_test",
        .instIndex = 0,
        .dlpType = DLP_COMMON,
        .appIDDesc = "testtesttesttest",
        .apiVersion = DEFAULT_API_VERSION,
        .isSystemApp = false,
        .appDistributionType = "app_gallery",
    };
    HapPolicyParcel policy;
    PermissionStatus permissionStateA = {
        .permissionName = "ohos.permission.GET_ALL_APP_ACCOUNTS",
        .grantStatus = 1,
        .grantFlag = 1
    };
    PermissionStatus permissionStateB = {
        .permissionName = "ohos.permission.test",
        .grantStatus = 1,
        .grantFlag = 1
    };
    policy.hapPolicy = {
        .apl = APL_NORMAL,
        .domain = "test",
        .permList = {},
        .permStateList = { permissionStateA, permissionStateB }
    };
    uint64_t fullTokenId;
    HapInfoCheckResultIdl resultInfoIdl;
    HapInfoCheckResult result;

    ASSERT_EQ(0, atManagerService_->InitHapToken(info, policy, fullTokenId, resultInfoIdl));

    PermissionInfoCheckResult permCheckResult;
    permCheckResult.permissionName = resultInfoIdl.permissionName;
    int32_t rule = static_cast<int32_t>(resultInfoIdl.rule);
    permCheckResult.rule = PermissionRulesEnum(rule);
    result.permCheckResult = permCheckResult;
    ASSERT_EQ(result.permCheckResult.permissionName, "ohos.permission.GET_ALL_APP_ACCOUNTS");
    ASSERT_EQ(result.permCheckResult.rule, PERMISSION_ACL_RULE);
    permissionStateA.permissionName = "ohos.permission.ENTERPRISE_MANAGE_SETTINGS";
    policy.hapPolicy.aclRequestedList = { "ohos.permission.ENTERPRISE_MANAGE_SETTINGS" };
    policy.hapPolicy.permStateList = { permissionStateA, permissionStateB };
    resultInfoIdl = {};
    ASSERT_EQ(0, atManagerService_->InitHapToken(info, policy, fullTokenId, resultInfoIdl));

    ASSERT_EQ(resultInfoIdl.permissionName, "ohos.permission.ENTERPRISE_MANAGE_SETTINGS");
    rule = static_cast<int32_t>(resultInfoIdl.rule);
    ASSERT_EQ(PermissionRulesEnum(rule), PERMISSION_EDM_RULE);
}

static void GetHapParams(HapInfoParams& infoParams, HapPolicy& policyParams)
{
    infoParams.userID = 0;
    infoParams.bundleName = "com.ohos.AccessTokenTestBundle";
    infoParams.instIndex = 0;
    infoParams.appIDDesc = "AccessTokenTestAppID";
    infoParams.apiVersion = DEFAULT_API_VERSION;
    infoParams.isSystemApp = true;
    infoParams.appDistributionType = "";

    policyParams.apl = APL_SYSTEM_CORE;
    policyParams.domain = "accesstoken_test_domain";
}

void TestPrepareKernelPermissionStatus(HapPolicy& policyParams)
{
    PermissionStatus permissionStatusBasic = {
        .permissionName = "ohos.permission.test_basic",
        .grantStatus = PERMISSION_GRANTED,
        .grantFlag = PERMISSION_SYSTEM_FIXED,
    };

    PermissionStatus PermissionStatus001 = permissionStatusBasic;
    PermissionStatus001.permissionName = "ohos.permission.KERNEL_ATM_SELF_USE";
    PermissionStatus PermissionStatus002 = permissionStatusBasic;
    PermissionStatus002.permissionName = "ohos.permission.MICROPHONE";
    PermissionStatus PermissionStatus003 = permissionStatusBasic;
    PermissionStatus003.permissionName = "ohos.permission.CAMERA";
    policyParams.permStateList = {PermissionStatus001, PermissionStatus002, PermissionStatus003};
    policyParams.aclExtendedMap["ohos.permission.KERNEL_ATM_SELF_USE"] = "123";
    policyParams.aclExtendedMap["ohos.permission.MICROPHONE"] = "456"; // filtered
    policyParams.aclExtendedMap["ohos.permission.CAMERA"] = "789"; // filtered
}

/**
 * @tc.name: InitHapToken004
 * @tc.desc: aclExtendedMap size test
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(TokenInfoManagerTest, InitHapToken004, TestSize.Level0)
{
    HapInfoParcel info;
    HapPolicyParcel policy;
    GetHapParams(info.hapInfoParameter, policy.hapPolicy);

    uint64_t fullTokenId;
    HapInfoCheckResultIdl result;
    int32_t ret = atManagerService_->InitHapToken(info, policy, fullTokenId, result);
    ASSERT_EQ(RET_SUCCESS, ret);

    for (size_t i = 0; i < MAX_EXTENDED_MAP_SIZE - 1; i++) {
        policy.hapPolicy.aclExtendedMap[std::to_string(i)] = std::to_string(i);
    }
    ret = atManagerService_->InitHapToken(info, policy, fullTokenId, result);
    ASSERT_EQ(RET_SUCCESS, ret);

    policy.hapPolicy.aclExtendedMap[std::to_string(MAX_EXTENDED_MAP_SIZE - 1)] =
        std::to_string(MAX_EXTENDED_MAP_SIZE - 1);
    ret = atManagerService_->InitHapToken(info, policy, fullTokenId, result);
    ASSERT_EQ(RET_SUCCESS, ret);
    AccessTokenIDEx tokenIDEx = {fullTokenId};
    AccessTokenID tokenID = tokenIDEx.tokenIdExStruct.tokenID;

    policy.hapPolicy.aclExtendedMap[std::to_string(MAX_EXTENDED_MAP_SIZE)] =
        std::to_string(MAX_EXTENDED_MAP_SIZE);
    ret = atManagerService_->InitHapToken(info, policy, fullTokenId, result);
    ASSERT_EQ(AccessTokenError::ERR_PARAM_INVALID, ret);

    ret = atManagerService_->DeleteToken(tokenID, false);
    EXPECT_EQ(RET_SUCCESS, ret);
}

/**
 * @tc.name: InitHapToken005
 * @tc.desc: aclExtendedMap size test
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(TokenInfoManagerTest, InitHapToken005, TestSize.Level0)
{
    HapInfoParcel info;
    HapPolicyParcel policy;
    GetHapParams(info.hapInfoParameter, policy.hapPolicy);

    uint64_t fullTokenId;
    HapInfoCheckResultIdl result;
    policy.hapPolicy.aclExtendedMap["ohos.permission.ACCESS_CERT_MANAGER"] = "";
    int32_t ret = atManagerService_->InitHapToken(info, policy, fullTokenId, result);
    ASSERT_EQ(AccessTokenError::ERR_PARAM_INVALID, ret);

    std::string testValue(MAX_VALUE_LENGTH - 1, '1');
    policy.hapPolicy.aclExtendedMap["ohos.permission.ACCESS_CERT_MANAGER"] = testValue;
    ret = atManagerService_->InitHapToken(info, policy, fullTokenId, result);
    ASSERT_EQ(RET_SUCCESS, ret);

    testValue.push_back('1');
    policy.hapPolicy.aclExtendedMap["ohos.permission.ACCESS_CERT_MANAGER"] = testValue;
    ret = atManagerService_->InitHapToken(info, policy, fullTokenId, result);
    ASSERT_EQ(RET_SUCCESS, ret);
    AccessTokenIDEx tokenIDEx = {fullTokenId};
    AccessTokenID tokenID = tokenIDEx.tokenIdExStruct.tokenID;

    testValue.push_back('1');
    policy.hapPolicy.aclExtendedMap["ohos.permission.ACCESS_CERT_MANAGER"] = testValue;
    ret = atManagerService_->InitHapToken(info, policy, fullTokenId, result);
    ASSERT_EQ(AccessTokenError::ERR_PARAM_INVALID, ret);

    ret = atManagerService_->DeleteToken(tokenID, false);
    EXPECT_EQ(RET_SUCCESS, ret);
}

/**
 * @tc.name: InitHapToken006
 * @tc.desc: InitHapToken permission with value
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(TokenInfoManagerTest, InitHapToken006, TestSize.Level0)
{
    HapInfoParcel info;
    HapPolicyParcel policy;
    GetHapParams(info.hapInfoParameter, policy.hapPolicy);
    uint64_t fullTokenId;
    HapInfoCheckResultIdl result;

    TestPrepareKernelPermissionStatus(policy.hapPolicy);
    ASSERT_EQ(RET_SUCCESS, atManagerService_->InitHapToken(info, policy, fullTokenId, result));
    AccessTokenID tokenID = static_cast<AccessTokenID>(fullTokenId);

    std::vector<PermissionWithValueIdl> kernelPermList;
    EXPECT_EQ(RET_SUCCESS, atManagerService_->GetKernelPermissions(tokenID, kernelPermList));
    EXPECT_EQ(1, kernelPermList.size());

    std::string value;
    EXPECT_EQ(RET_SUCCESS, atManagerService_->GetReqPermissionByName(
        tokenID, "ohos.permission.KERNEL_ATM_SELF_USE", value));
    EXPECT_EQ("123", value);

    EXPECT_EQ(AccessTokenError::ERR_PERMISSION_WITHOUT_VALUE, atManagerService_->GetReqPermissionByName(
        tokenID, "ohos.permission.MICROPHONE", value));
    EXPECT_EQ(AccessTokenError::ERR_PERMISSION_WITHOUT_VALUE, atManagerService_->GetReqPermissionByName(
        tokenID, "ohos.permission.CAMERA", value));

    ASSERT_EQ(RET_SUCCESS, atManagerService_->DeleteToken(tokenID, false));
}


/**
 * @tc.name: InitHapToken007
 * @tc.desc: InitHapToken app.apl > policy.apl, extended permission not in aclExtendedMap
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(TokenInfoManagerTest, InitHapToken007, TestSize.Level0)
{
    HapInfoParcel info;
    HapPolicyParcel policy;
    GetHapParams(info.hapInfoParameter, policy.hapPolicy);
    uint64_t fullTokenId;
    HapInfoCheckResultIdl result;

    TestPrepareKernelPermissionStatus(policy.hapPolicy);
    policy.hapPolicy.aclExtendedMap.erase("ohos.permission.KERNEL_ATM_SELF_USE");
    ASSERT_EQ(RET_SUCCESS, atManagerService_->InitHapToken(info, policy, fullTokenId, result));
    AccessTokenID tokenID = static_cast<AccessTokenID>(fullTokenId);

    std::vector<PermissionWithValueIdl> kernelPermList;
    EXPECT_EQ(RET_SUCCESS, atManagerService_->GetKernelPermissions(tokenID, kernelPermList));
    EXPECT_EQ(1, kernelPermList.size());

    std::string value;
    EXPECT_EQ(RET_SUCCESS, atManagerService_->GetReqPermissionByName(
        tokenID, "ohos.permission.KERNEL_ATM_SELF_USE", value));
    EXPECT_EQ("", value);

    ASSERT_EQ(RET_SUCCESS, atManagerService_->DeleteToken(tokenID, false));
}

/**
 * @tc.name: InitHapToken008
 * @tc.desc: InitHapToken function test with invalid apl permission
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(TokenInfoManagerTest, InitHapToken008, TestSize.Level0)
{
    HapInfoParcel info;
    info.hapInfoParameter = {
        .userID = 0,
        .bundleName = "accesstoken_test",
        .instIndex = 0,
        .dlpType = DLP_COMMON,
        .appIDDesc = "testtesttesttest",
        .apiVersion = DEFAULT_API_VERSION,
        .isSystemApp = false,
    };
    HapPolicyParcel policy;
    PermissionStatus permissionStateA = {
        .permissionName = "ohos.permission.GET_ALL_APP_ACCOUNTS",
        .grantStatus = 1,
        .grantFlag = 1
    };
    PermissionStatus permissionStateB = {
        .permissionName = "ohos.permission.test",
        .grantStatus = 1,
        .grantFlag = 1
    };
    policy.hapPolicy = {
        .apl = APL_NORMAL,
        .domain = "test",
        .permList = {},
        .permStateList = { permissionStateA, permissionStateB }
    };
    uint64_t fullTokenId;
    HapInfoCheckResultIdl resultInfoIdl;
    HapInfoCheckResult result;

    ASSERT_EQ(0,
        atManagerService_->InitHapToken(info, policy, fullTokenId, resultInfoIdl));

    PermissionInfoCheckResult permCheckResult;
    permCheckResult.permissionName = resultInfoIdl.permissionName;
    int32_t rule = static_cast<int32_t>(resultInfoIdl.rule);
    permCheckResult.rule = PermissionRulesEnum(rule);
    result.permCheckResult = permCheckResult;
    ASSERT_EQ(result.permCheckResult.permissionName, "ohos.permission.GET_ALL_APP_ACCOUNTS");
    ASSERT_EQ(result.permCheckResult.rule, PERMISSION_ACL_RULE);
    permissionStateA.permissionName = "ohos.permission.GET_DOMAIN_ACCOUNTS";
    policy.hapPolicy.aclRequestedList = { "ohos.permission.GET_DOMAIN_ACCOUNTS" };
    policy.hapPolicy.permStateList = { permissionStateA, permissionStateB };
    ASSERT_EQ(0, atManagerService_->InitHapToken(info, policy, fullTokenId, resultInfoIdl));
}

/**
 * @tc.name: IsTokenIdExist001
 * @tc.desc: Verify the IsTokenIdExist exist accesstokenid.
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(TokenInfoManagerTest, IsTokenIdExist001, TestSize.Level0)
{
    AccessTokenID testId = 1;
    ASSERT_EQ(AccessTokenInfoManager::GetInstance().IsTokenIdExist(testId), false);
}

/**
 * @tc.name: GetHapTokenInfo001
 * @tc.desc: Verify the GetHapTokenInfo abnormal and normal branch.
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(TokenInfoManagerTest, GetHapTokenInfo001, TestSize.Level0)
{
    AccessTokenIDEx tokenIdEx = {0};
    int result;
    HapTokenInfo hapInfo;
    result = AccessTokenInfoManager::GetInstance().GetHapTokenInfo(tokenIdEx.tokenIdExStruct.tokenID, hapInfo);
    ASSERT_EQ(result, ERR_TOKENID_NOT_EXIST);

    std::vector<GenericValues> undefValues;
    result = AccessTokenInfoManager::GetInstance().CreateHapTokenInfo(
        g_infoManagerTestInfoParms, g_infoManagerTestPolicyPrams1, tokenIdEx, undefValues);
    ASSERT_EQ(RET_SUCCESS, result);
    GTEST_LOG_(INFO) << "add a hap token " << tokenIdEx.tokenIdExStruct.tokenID;
    result = AccessTokenInfoManager::GetInstance().GetHapTokenInfo(tokenIdEx.tokenIdExStruct.tokenID, hapInfo);
    ASSERT_EQ(result, RET_SUCCESS);
    result = AccessTokenInfoManager::GetInstance().RemoveHapTokenInfo(tokenIdEx.tokenIdExStruct.tokenID);
    ASSERT_EQ(RET_SUCCESS, result);
    GTEST_LOG_(INFO) << "remove the token info";
}

/**
 * @tc.name: RemoveHapTokenInfo001
 * @tc.desc: Verify the RemoveHapTokenInfo abnormal branch tokenID type is not true.
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(TokenInfoManagerTest, RemoveHapTokenInfo001, TestSize.Level0)
{
    AccessTokenIDEx tokenIdEx = {0};
    // type != TOKEN_HAP
    ASSERT_EQ(
        ERR_PARAM_INVALID, AccessTokenInfoManager::GetInstance().RemoveHapTokenInfo(tokenIdEx.tokenIdExStruct.tokenID));

    AccessTokenID tokenId = 537919487; // 537919487 is max hap tokenId: 001 00 0 000000 11111111111111111111
    ASSERT_EQ(RET_SUCCESS, AccessTokenIDManager::GetInstance().RegisterTokenId(tokenId, TOKEN_HAP));
    // hapTokenInfoMap_.count(id) == 0
    ASSERT_EQ(ERR_TOKENID_NOT_EXIST, AccessTokenInfoManager::GetInstance().RemoveHapTokenInfo(tokenId));

    ASSERT_EQ(RET_SUCCESS, AccessTokenIDManager::GetInstance().RegisterTokenId(tokenId, TOKEN_HAP));
    AccessTokenInfoManager::GetInstance().hapTokenInfoMap_[tokenId] = nullptr;
    ASSERT_EQ(ERR_TOKEN_INVALID, AccessTokenInfoManager::GetInstance().RemoveHapTokenInfo(tokenId)); // info == nullptr
    AccessTokenInfoManager::GetInstance().hapTokenInfoMap_.erase(tokenId);

    std::shared_ptr<HapTokenInfoInner> info = std::make_shared<HapTokenInfoInner>();
    info->tokenInfoBasic_.userID = USER_ID;
    info->tokenInfoBasic_.bundleName = "com.ohos.TEST";
    info->tokenInfoBasic_.instIndex = INST_INDEX;
    AccessTokenInfoManager::GetInstance().hapTokenInfoMap_[tokenId] = info;
    ASSERT_EQ(RET_SUCCESS, AccessTokenIDManager::GetInstance().RegisterTokenId(tokenId, TOKEN_HAP));
    // count(HapUniqueKey) == 0
    ASSERT_EQ(RET_SUCCESS, AccessTokenInfoManager::GetInstance().RemoveHapTokenInfo(tokenId));

    ASSERT_EQ(RET_SUCCESS, AccessTokenIDManager::GetInstance().RegisterTokenId(tokenId, TOKEN_HAP)); // removed above
    AccessTokenID tokenId2 = 537919486; // 537919486: 001 00 0 000000 11111111111111111110
    AccessTokenInfoManager::GetInstance().hapTokenInfoMap_[tokenId] = info;
    std::string hapUniqueKey = "com.ohos.TEST&" + std::to_string(USER_ID) + "&" + std::to_string(INST_INDEX);
    AccessTokenInfoManager::GetInstance().hapTokenIdMap_[hapUniqueKey] = tokenId2;
    // hapTokenIdMap_[HapUniqueKey] != id
    ASSERT_EQ(RET_SUCCESS, AccessTokenInfoManager::GetInstance().RemoveHapTokenInfo(tokenId));
    AccessTokenInfoManager::GetInstance().hapTokenIdMap_.erase(hapUniqueKey);
}

/**
 * @tc.name: GetHapTokenID001
 * @tc.desc: Verify the GetHapTokenID by userID/bundleName/instIndex, function.
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(TokenInfoManagerTest, GetHapTokenID001, TestSize.Level0)
{
    AccessTokenIDEx tokenIdEx = {0};
    std::vector<GenericValues> undefValues;
    int ret = AccessTokenInfoManager::GetInstance().CreateHapTokenInfo(g_infoManagerTestInfoParms,
        g_infoManagerTestPolicyPrams1, tokenIdEx, undefValues);
    ASSERT_EQ(RET_SUCCESS, ret);
    GTEST_LOG_(INFO) << "add a hap token" << tokenIdEx.tokenIdExStruct.tokenID;

    tokenIdEx = AccessTokenInfoManager::GetInstance().GetHapTokenID(g_infoManagerTestInfoParms.userID,
        g_infoManagerTestInfoParms.bundleName, g_infoManagerTestInfoParms.instIndex);
    ASSERT_NE(INVALID_TOKENID, tokenIdEx.tokenIdExStruct.tokenID);
    GTEST_LOG_(INFO) << "find hap info";

    std::shared_ptr<HapTokenInfoInner> tokenInfo;
    tokenInfo = AccessTokenInfoManager::GetInstance().GetHapTokenInfoInner(tokenIdEx.tokenIdExStruct.tokenID);
    ASSERT_NE(nullptr, tokenInfo);
    GTEST_LOG_(INFO) << "remove the token info";

    ret = AccessTokenInfoManager::GetInstance().RemoveHapTokenInfo(tokenIdEx.tokenIdExStruct.tokenID);
    ASSERT_EQ(RET_SUCCESS, ret);
    GTEST_LOG_(INFO) << "remove the token info";
}

#ifdef ACCESS_TOKEN_SUPPORT_SUBPROFILE
/**
 * @tc.name: GetTokenIDByUserIDWithSubProfile001
 * @tc.desc: GetTokenIDByUserID filters token by index resolved from userId and subProfileId.
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(TokenInfoManagerTest, GetTokenIDByUserIDWithSubProfile001, TestSize.Level0)
{
    SubProfileTestStateGuard guard;
    std::vector<GenericValues> undefValues;
    HapInfoParams info1 = g_infoManagerTestInfoParms;
    HapInfoParams info2 = g_infoManagerTestInfoParms;
    info1.bundleName = "token_info_subprofile_test1";
    info2.bundleName = "token_info_subprofile_test2";
    info1.instIndex = INST_INDEX;
    info2.instIndex = SUBPROFILE_TEST_INDEX;

    AccessTokenIDEx tokenIdEx1 = {0};
    AccessTokenIDEx tokenIdEx2 = {0};
    ASSERT_EQ(RET_SUCCESS, AccessTokenInfoManager::GetInstance().CreateHapTokenInfo(
        info1, g_infoManagerTestPolicyPrams1, tokenIdEx1, undefValues));
    guard.AddTokenId(tokenIdEx1.tokenIdExStruct.tokenID);
    ASSERT_EQ(RET_SUCCESS, AccessTokenInfoManager::GetInstance().CreateHapTokenInfo(
        info2, g_infoManagerTestPolicyPrams1, tokenIdEx2, undefValues));
    guard.AddTokenId(tokenIdEx2.tokenIdExStruct.tokenID);

    SetMockOsAccountSubProfileIndex(SUBPROFILE_TEST_INDEX, ERR_OK);
    std::unordered_set<AccessTokenID> tokenIdList;
    AccessTokenInfoManager::GetInstance().GetTokenIDByUserID(info1.userID, SUBPROFILE_TEST_ID, tokenIdList);
    EXPECT_EQ(tokenIdList.end(), tokenIdList.find(tokenIdEx1.tokenIdExStruct.tokenID));
    EXPECT_NE(tokenIdList.end(), tokenIdList.find(tokenIdEx2.tokenIdExStruct.tokenID));
}

/**
 * @tc.name: GetTokenIDByUserIDWithSubProfile002
 * @tc.desc: GetTokenIDByUserID returns empty list when account fails to resolve subProfile index.
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(TokenInfoManagerTest, GetTokenIDByUserIDWithSubProfile002, TestSize.Level0)
{
    SubProfileTestStateGuard guard;
    std::vector<GenericValues> undefValues;
    AccessTokenIDEx tokenIdEx = {0};
    ASSERT_EQ(RET_SUCCESS, AccessTokenInfoManager::GetInstance().CreateHapTokenInfo(
        g_infoManagerTestInfoParms, g_infoManagerTestPolicyPrams1, tokenIdEx, undefValues));
    guard.AddTokenId(tokenIdEx.tokenIdExStruct.tokenID);

    SetMockOsAccountSubProfileIndex(SUBPROFILE_TEST_INDEX, ERR_INVALID_VALUE);
    std::unordered_set<AccessTokenID> tokenIdList;
    AccessTokenInfoManager::GetInstance().GetTokenIDByUserID(
        g_infoManagerTestInfoParms.userID, SUBPROFILE_TEST_ID, tokenIdList);
    EXPECT_TRUE(tokenIdList.empty());
}
#endif

/**
 * @tc.name: UpdateHapToken001
 * @tc.desc: Verify the UpdateHapToken token function.
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(TokenInfoManagerTest, UpdateHapToken001, TestSize.Level0)
{
    AccessTokenIDEx tokenIdEx = {0};
    std::vector<GenericValues> undefValues;
    int ret = AccessTokenInfoManager::GetInstance().CreateHapTokenInfo(g_infoManagerTestInfoParms,
        g_infoManagerTestPolicyPrams1, tokenIdEx, undefValues);
    ASSERT_EQ(RET_SUCCESS, ret);
    GTEST_LOG_(INFO) << "add a hap token " << tokenIdEx.tokenIdExStruct.tokenID;

    HapPolicy policy = g_infoManagerTestPolicyPrams1;
    policy.apl = APL_SYSTEM_BASIC;
    UpdateHapInfoParams info;
    info.appIDDesc = std::string("updateAppId");
    info.apiVersion = DEFAULT_API_VERSION;
    info.isSystemApp = false;
    ret = AccessTokenInfoManager::GetInstance().UpdateHapToken(
        tokenIdEx, info, policy.permStateList, policy, undefValues);
    ASSERT_EQ(RET_SUCCESS, ret);
    GTEST_LOG_(INFO) << "update the hap token";

    std::shared_ptr<HapTokenInfoInner> tokenInfo;
    tokenInfo = AccessTokenInfoManager::GetInstance().GetHapTokenInfoInner(tokenIdEx.tokenIdExStruct.tokenID);
    ASSERT_NE(nullptr, tokenInfo);

    ret = AccessTokenInfoManager::GetInstance().RemoveHapTokenInfo(tokenIdEx.tokenIdExStruct.tokenID);
    ASSERT_EQ(RET_SUCCESS, ret);
    GTEST_LOG_(INFO) << "remove the token info";
}

/**
 * @tc.name: UpdateHapToken002
 * @tc.desc: Verify the UpdateHapToken token function abnormal branch.
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(TokenInfoManagerTest, UpdateHapToken002, TestSize.Level0)
{
    AccessTokenIDEx tokenIdEx = {0};
    HapPolicy policy = g_infoManagerTestPolicyPrams1;
    policy.apl = APL_SYSTEM_BASIC;
    UpdateHapInfoParams info;
    info.appIDDesc = std::string("");
    info.apiVersion = DEFAULT_API_VERSION;
    info.isSystemApp = false;
    std::vector<GenericValues> undefValues;
    int ret = AccessTokenInfoManager::GetInstance().UpdateHapToken(
        tokenIdEx, info, policy.permStateList, policy, undefValues);
    ASSERT_EQ(ERR_PARAM_INVALID, ret);

    info.appIDDesc = std::string("updateAppId");
    ret = AccessTokenInfoManager::GetInstance().UpdateHapToken(
        tokenIdEx, info, policy.permStateList, policy, undefValues);
    ASSERT_EQ(ERR_TOKENID_NOT_EXIST, ret);
}

/**
 * @tc.name: UpdateHapToken003
 * @tc.desc: AccessTokenInfoManager::UpdateHapToken function test IsRemote_ true
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(TokenInfoManagerTest, UpdateHapToken003, TestSize.Level0)
{
    AccessTokenID tokenId = 537919487; // 537919487 is max hap tokenId: 001 00 0 000000 11111111111111111111
    AccessTokenIDEx tokenIdEx = {0};
    tokenIdEx.tokenIdExStruct.tokenID = tokenId;
    std::shared_ptr<HapTokenInfoInner> info = std::make_shared<HapTokenInfoInner>();
    info->isRemote_ = true;
    AccessTokenInfoManager::GetInstance().hapTokenInfoMap_[tokenId] = info;
    HapPolicy policy;
    UpdateHapInfoParams hapInfoParams;
    hapInfoParams.appIDDesc = "who cares";
    hapInfoParams.apiVersion = DEFAULT_API_VERSION;
    hapInfoParams.isSystemApp = false;
    std::vector<GenericValues> undefValues;
    ASSERT_EQ(ERR_IDENTITY_CHECK_FAILED, AccessTokenInfoManager::GetInstance().UpdateHapToken(
        tokenIdEx, hapInfoParams, policy.permStateList, policy, undefValues));
    AccessTokenInfoManager::GetInstance().hapTokenInfoMap_.erase(tokenId);
}

/**
 * @tc.name: UpdateHapToken004
 * @tc.desc: UpdateHapToken permission with value
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(TokenInfoManagerTest, UpdateHapToken004, TestSize.Level0)
{
    HapInfoParcel info;
    HapPolicyParcel policy;
    GetHapParams(info.hapInfoParameter, policy.hapPolicy);
    uint64_t fullTokenId;
    HapInfoCheckResultIdl result;

    TestPrepareKernelPermissionStatus(policy.hapPolicy);
    ASSERT_EQ(RET_SUCCESS, atManagerService_->InitHapToken(info, policy, fullTokenId, result));
    AccessTokenID tokenID = static_cast<AccessTokenID>(fullTokenId);

    policy.hapPolicy.aclExtendedMap["ohos.permission.KERNEL_ATM_SELF_USE"] = "1"; // modified value
    UpdateHapInfoParamsIdl updateInfoParams = {
        .appIDDesc = "AccessTokenTestAppID",
        .apiVersion = DEFAULT_API_VERSION,
        .isSystemApp = true,
        .appDistributionType = "",
    };
    EXPECT_EQ(RET_SUCCESS, atManagerService_->UpdateHapToken(fullTokenId, updateInfoParams, policy, result));

    std::vector<PermissionWithValueIdl> kernelPermList;
    EXPECT_EQ(RET_SUCCESS, atManagerService_->GetKernelPermissions(tokenID, kernelPermList));
    EXPECT_EQ(1, kernelPermList.size());

    std::string value;
    EXPECT_EQ(RET_SUCCESS, atManagerService_->GetReqPermissionByName(
        tokenID, "ohos.permission.KERNEL_ATM_SELF_USE", value));
    EXPECT_EQ("1", value);

    EXPECT_EQ(AccessTokenError::ERR_PERMISSION_WITHOUT_VALUE, atManagerService_->GetReqPermissionByName(
        tokenID, "ohos.permission.MICROPHONE", value));
    EXPECT_EQ(AccessTokenError::ERR_PERMISSION_WITHOUT_VALUE, atManagerService_->GetReqPermissionByName(
        tokenID, "ohos.permission.CAMERA", value));

    ASSERT_EQ(RET_SUCCESS, atManagerService_->DeleteToken(tokenID, false));
}


#ifdef TOKEN_SYNC_ENABLE
/**
 * @tc.name: GetHapTokenSync001
 * @tc.desc: Verify the GetHapTokenSync token function and abnormal branch.
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(TokenInfoManagerTest, GetHapTokenSync001, TestSize.Level0)
{
    AccessTokenIDEx tokenIdEx = {0};
    int result;
    std::vector<GenericValues> undefValues;
    result = AccessTokenInfoManager::GetInstance().CreateHapTokenInfo(
        g_infoManagerTestInfoParms, g_infoManagerTestPolicyPrams1, tokenIdEx, undefValues);
    ASSERT_EQ(RET_SUCCESS, result);
    GTEST_LOG_(INFO) << "add a hap token " << tokenIdEx.tokenIdExStruct.tokenID;

    HapTokenInfoForSync hapSync;
    result = AccessTokenInfoManager::GetInstance().GetHapTokenSync(tokenIdEx.tokenIdExStruct.tokenID, hapSync);
    ASSERT_EQ(result, RET_SUCCESS);

    result = AccessTokenInfoManager::GetInstance().RemoveHapTokenInfo(tokenIdEx.tokenIdExStruct.tokenID);
    ASSERT_EQ(RET_SUCCESS, result);
    GTEST_LOG_(INFO) << "remove the token info";

    result = AccessTokenInfoManager::GetInstance().GetHapTokenSync(tokenIdEx.tokenIdExStruct.tokenID, hapSync);
    ASSERT_NE(result, RET_SUCCESS);
}

/**
 * @tc.name: GetHapTokenSync002
 * @tc.desc: AccessTokenInfoManager::GetHapTokenSync function test permSetPtr is null
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(TokenInfoManagerTest, GetHapTokenSync002, TestSize.Level0)
{
    AccessTokenID tokenId = 537919487; // 537919487 is max hap tokenId: 001 00 0 000000 11111111111111111111
    std::shared_ptr<HapTokenInfoInner> info = std::make_shared<HapTokenInfoInner>();
    AccessTokenInfoManager::GetInstance().hapTokenInfoMap_[tokenId] = info;
    HapTokenInfoForSync hapSync;
    ASSERT_NE(0, AccessTokenInfoManager::GetInstance().GetHapTokenSync(tokenId, hapSync));
    AccessTokenInfoManager::GetInstance().hapTokenInfoMap_.erase(tokenId);
}

/**
 * @tc.name: GetHapTokenInfoFromRemote001
 * @tc.desc: Verify the GetHapTokenInfoFromRemote token function .
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(TokenInfoManagerTest, GetHapTokenInfoFromRemote001, TestSize.Level0)
{
    AccessTokenIDEx tokenIdEx = {0};
    std::vector<GenericValues> undefValues;
    int ret = AccessTokenInfoManager::GetInstance().CreateHapTokenInfo(
        g_infoManagerTestInfoParms, g_infoManagerTestPolicyPrams1, tokenIdEx, undefValues);
    ASSERT_EQ(RET_SUCCESS, ret);
    GTEST_LOG_(INFO) << "add a hap token " << tokenIdEx.tokenIdExStruct.tokenID;

    HapTokenInfoForSync hapSync;
    ret = AccessTokenInfoManager::GetInstance().GetHapTokenInfoFromRemote(tokenIdEx.tokenIdExStruct.tokenID, hapSync);
    ASSERT_EQ(ret, RET_SUCCESS);

    ret = AccessTokenInfoManager::GetInstance().RemoveHapTokenInfo(tokenIdEx.tokenIdExStruct.tokenID);
    ASSERT_EQ(RET_SUCCESS, ret);
    GTEST_LOG_(INFO) << "remove the token info";
}

/**
 * @tc.name: RemoteHapTest001001
 * @tc.desc: Verify the RemoteHap token function .
 * @tc.type: FUNC
 * @tc.require: issueI5RJBB
 */
HWTEST_F(TokenInfoManagerTest, RemoteHapTest001, TestSize.Level0)
{
    AccessTokenIDEx tokenIdEx = {0};
    std::vector<GenericValues> undefValues;
    int32_t ret = AccessTokenInfoManager::GetInstance().CreateHapTokenInfo(
        g_infoManagerTestInfoParms, g_infoManagerTestPolicyPrams1, tokenIdEx, undefValues);
    ASSERT_EQ(RET_SUCCESS, ret);
    GTEST_LOG_(INFO) << "add a hap token " << tokenIdEx.tokenIdExStruct.tokenID;

    std::string deviceId = "device_1";
    std::string deviceId2 = "device_2";
    AccessTokenIDEx idEx = {0};
    idEx.tokenIDEx =
        AccessTokenInfoManager::GetInstance().AllocLocalTokenID(deviceId, tokenIdEx.tokenIdExStruct.tokenID);
    AccessTokenID mapID = idEx.tokenIdExStruct.tokenID;
    ASSERT_EQ(mapID, 0);
    HapTokenInfoForSync hapSync;
    ret = AccessTokenInfoManager::GetInstance().GetHapTokenInfoFromRemote(tokenIdEx.tokenIdExStruct.tokenID, hapSync);
    ASSERT_EQ(RET_SUCCESS, ret);
    ret = AccessTokenInfoManager::GetInstance().SetRemoteHapTokenInfo(deviceId, hapSync);
    ASSERT_EQ(RET_SUCCESS, ret);
    ret = AccessTokenInfoManager::GetInstance().DeleteRemoteDeviceTokens(deviceId);
    ASSERT_EQ(RET_SUCCESS, ret);
    ret = AccessTokenInfoManager::GetInstance().DeleteRemoteDeviceTokens(deviceId2);
    ASSERT_EQ(ERR_DEVICE_NOT_EXIST, ret);

    ret = AccessTokenInfoManager::GetInstance().RemoveHapTokenInfo(tokenIdEx.tokenIdExStruct.tokenID);
    ASSERT_EQ(RET_SUCCESS, ret);
    GTEST_LOG_(INFO) << "remove the token info";
}

/**
 * @tc.name: DeleteRemoteToken001
 * @tc.desc: Verify the DeleteRemoteToken normal and abnormal branch.
 * @tc.type: FUNC
 * @tc.require: issueI5RJBB
 */
HWTEST_F(TokenInfoManagerTest, DeleteRemoteToken001, TestSize.Level0)
{
    AccessTokenIDEx tokenIdEx = {0};
    std::vector<GenericValues> undefValues;
    int32_t ret = AccessTokenInfoManager::GetInstance().CreateHapTokenInfo(
        g_infoManagerTestInfoParms, g_infoManagerTestPolicyPrams1, tokenIdEx, undefValues);
    ASSERT_EQ(RET_SUCCESS, ret);
    GTEST_LOG_(INFO) << "add a hap token " << tokenIdEx.tokenIdExStruct.tokenID;

    std::string deviceId = "device_1";
    std::string deviceId2 = "device_2";
    AccessTokenIDEx idEx = {0};
    idEx.tokenIDEx =
        AccessTokenInfoManager::GetInstance().AllocLocalTokenID(deviceId, tokenIdEx.tokenIdExStruct.tokenID);
    AccessTokenID mapId = idEx.tokenIdExStruct.tokenID;
    ASSERT_EQ(mapId == 0, true);
    HapTokenInfoForSync hapSync;
    ret = AccessTokenInfoManager::GetInstance().GetHapTokenInfoFromRemote(tokenIdEx.tokenIdExStruct.tokenID, hapSync);
    ASSERT_EQ(RET_SUCCESS, ret);
    ret = AccessTokenInfoManager::GetInstance().SetRemoteHapTokenInfo(deviceId, hapSync);
    ASSERT_EQ(RET_SUCCESS, ret);
    ret = AccessTokenInfoManager::GetInstance().DeleteRemoteToken(deviceId, tokenIdEx.tokenIdExStruct.tokenID);
    ASSERT_EQ(RET_SUCCESS, ret);
    ret = AccessTokenInfoManager::GetInstance().DeleteRemoteToken(deviceId2, tokenIdEx.tokenIdExStruct.tokenID);
    ASSERT_NE(RET_SUCCESS, ret);

    ret = AccessTokenInfoManager::GetInstance().RemoveHapTokenInfo(tokenIdEx.tokenIdExStruct.tokenID);
    ASSERT_EQ(RET_SUCCESS, ret);
    GTEST_LOG_(INFO) << "remove the token info";
}

static bool SetRemoteHapTokenInfoTest(const std::string& deviceID, const HapTokenInfo& baseInfo)
{
    std::vector<PermissionStatus> permStateList;
    permStateList.emplace_back(g_infoManagerTestState1);
    HapTokenInfoForSync remoteTokenInfo = {
        .baseInfo = baseInfo,
        .permStateList = permStateList
    };

    return RET_SUCCESS == AccessTokenInfoManager::GetInstance().SetRemoteHapTokenInfo(deviceID, remoteTokenInfo);
}

/**
 * @tc.name: SetRemoteHapTokenInfo001
 * @tc.desc: set remote hap token info, token info is wrong
 * @tc.type: FUNC
 * @tc.require: issue5RJBB
 */
HWTEST_F(TokenInfoManagerTest, SetRemoteHapTokenInfo001, TestSize.Level0)
{
    std::string deviceID = "deviceId";
    HapTokenInfo rightBaseInfo = {
        .ver = 1,
        .userID = 1,
        .bundleName = "com.ohos.access_token",
        .instIndex = 1,
        .tokenID = 0x20100000,
        .tokenAttr = 0
    };
    HapTokenInfo wrongBaseInfo = rightBaseInfo;
    std::string wrongStr(10241, 'x');

    EXPECT_EQ(false, SetRemoteHapTokenInfoTest("", wrongBaseInfo));

    wrongBaseInfo = rightBaseInfo;
    wrongBaseInfo.userID = -1; // wrong userID
    EXPECT_EQ(false, SetRemoteHapTokenInfoTest(deviceID, wrongBaseInfo));

    wrongBaseInfo = rightBaseInfo;
    wrongBaseInfo.bundleName = wrongStr; // wrong bundleName
    EXPECT_EQ(false, SetRemoteHapTokenInfoTest(deviceID, wrongBaseInfo));

    wrongBaseInfo = rightBaseInfo;
    wrongBaseInfo.tokenID = 0; // wrong tokenID
    EXPECT_EQ(false, SetRemoteHapTokenInfoTest(deviceID, wrongBaseInfo));

    wrongBaseInfo = rightBaseInfo;
    wrongBaseInfo.dlpType = (HapDlpType)11; // wrong dlpType
    EXPECT_EQ(false, SetRemoteHapTokenInfoTest(deviceID, wrongBaseInfo));

    wrongBaseInfo = rightBaseInfo;
    wrongBaseInfo.ver = 2; // 2: wrong version
    EXPECT_EQ(false, SetRemoteHapTokenInfoTest(deviceID, wrongBaseInfo));

    wrongBaseInfo = rightBaseInfo;
    wrongBaseInfo.tokenID = AccessTokenInfoManager::GetInstance().GetNativeTokenId("hdcd");
    EXPECT_EQ(false, SetRemoteHapTokenInfoTest(deviceID, wrongBaseInfo));
}

/**
 * @tc.name: ClearUserGrantedPermissionState001
 * @tc.desc: TokenInfoManagerTest::ClearUserGrantedPermissionState function test
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(TokenInfoManagerTest, ClearUserGrantedPermissionState001, TestSize.Level0)
{
    AccessTokenID tokenId = RANDOM_TOKENID;

    std::shared_ptr<HapTokenInfoInner> hap = std::make_shared<HapTokenInfoInner>();
    ASSERT_NE(nullptr, hap);
    AccessTokenInfoManager::GetInstance().hapTokenInfoMap_[tokenId] = hap;

    AccessTokenInfoManager::GetInstance().ClearUserGrantedPermissionState(tokenId); // permPolicySet is null

    AccessTokenInfoManager::GetInstance().hapTokenInfoMap_.erase(tokenId);
}

/**
 * @tc.name: NotifyTokenSyncTask001
 * @tc.desc: TokenModifyNotifier::NotifyTokenSyncTask function test
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(TokenInfoManagerTest, NotifyTokenSyncTask001, TestSize.Level0)
{
    std::vector<AccessTokenID> modifiedTokenList = TokenModifyNotifier::GetInstance().modifiedTokenList_; // backup
    TokenModifyNotifier::GetInstance().modifiedTokenList_.clear();

    AccessTokenID tokenId = RANDOM_TOKENID;

    TokenModifyNotifier::GetInstance().modifiedTokenList_.emplace_back(tokenId);
    ASSERT_EQ(true, TokenModifyNotifier::GetInstance().modifiedTokenList_.size() > 0);
    TokenModifyNotifier::GetInstance().NotifyTokenSyncTask();

    TokenModifyNotifier::GetInstance().modifiedTokenList_ = modifiedTokenList; // recovery
}

void setPermission()
{
    setuid(0);
    if (tokenSyncId_ == 0) {
        tokenSyncId_ = AccessTokenInfoManager::GetInstance().GetNativeTokenId("token_sync_service");
    }
    SetSelfTokenID(tokenSyncId_);
}

/**
 * @tc.name: RegisterTokenSyncCallback001
 * @tc.desc: TokenModifyNotifier::RegisterTokenSyncCallback function test
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(TokenInfoManagerTest, RegisterTokenSyncCallback001, TestSize.Level0)
{
    setPermission();
    sptr<TokenSyncCallbackMock> callback = new (std::nothrow) TokenSyncCallbackMock();
    ASSERT_NE(nullptr, callback);
    EXPECT_EQ(RET_SUCCESS,
        atManagerService_->RegisterTokenSyncCallback(callback->AsObject()));
    EXPECT_NE(nullptr, TokenModifyNotifier::GetInstance().tokenSyncCallbackObject_);
    EXPECT_NE(nullptr, TokenModifyNotifier::GetInstance().tokenSyncCallbackDeathRecipient_);
    
    setuid(3020);
    EXPECT_CALL(*callback, GetRemoteHapTokenInfo(testing::_, testing::_)).WillOnce(testing::Return(FAKE_SYNC_RET));
    EXPECT_EQ(FAKE_SYNC_RET, TokenModifyNotifier::GetInstance().tokenSyncCallbackObject_->GetRemoteHapTokenInfo("", 0));
    
    EXPECT_CALL(*callback, DeleteRemoteHapTokenInfo(testing::_)).WillOnce(testing::Return(FAKE_SYNC_RET));
    EXPECT_EQ(FAKE_SYNC_RET, TokenModifyNotifier::GetInstance().tokenSyncCallbackObject_->DeleteRemoteHapTokenInfo(0));
    
    HapTokenInfoForSync tokenInfo;
    EXPECT_CALL(*callback, UpdateRemoteHapTokenInfo(testing::_)).WillOnce(testing::Return(FAKE_SYNC_RET));
    EXPECT_EQ(FAKE_SYNC_RET,
        TokenModifyNotifier::GetInstance().tokenSyncCallbackObject_->UpdateRemoteHapTokenInfo(tokenInfo));
    setPermission();
    EXPECT_EQ(RET_SUCCESS,
        atManagerService_->UnRegisterTokenSyncCallback());
    EXPECT_EQ(nullptr, TokenModifyNotifier::GetInstance().tokenSyncCallbackObject_);
    EXPECT_EQ(nullptr, TokenModifyNotifier::GetInstance().tokenSyncCallbackDeathRecipient_);
    setuid(0);
}

/**
 * @tc.name: RegisterTokenSyncCallback002
 * @tc.desc: TokenModifyNotifier::RegisterTokenSyncCallback function test
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(TokenInfoManagerTest, RegisterTokenSyncCallback002, TestSize.Level0)
{
    setPermission();
    sptr<TokenSyncCallbackMock> callback = new (std::nothrow) TokenSyncCallbackMock();
    ASSERT_NE(nullptr, callback);
    EXPECT_EQ(RET_SUCCESS,
        atManagerService_->RegisterTokenSyncCallback(callback->AsObject()));
    EXPECT_NE(nullptr, TokenModifyNotifier::GetInstance().tokenSyncCallbackObject_);
    setuid(3020);
    EXPECT_CALL(*callback, GetRemoteHapTokenInfo(testing::_, testing::_))
        .WillOnce(testing::Return(FAKE_SYNC_RET));
    EXPECT_EQ(FAKE_SYNC_RET, TokenModifyNotifier::GetInstance().GetRemoteHapTokenInfo("", 0));

    std::vector<AccessTokenID> modifiedTokenList =
        TokenModifyNotifier::GetInstance().modifiedTokenList_; // backup
    std::vector<AccessTokenID> deleteTokenList = TokenModifyNotifier::GetInstance().deleteTokenList_;
    TokenModifyNotifier::GetInstance().modifiedTokenList_.clear();
    TokenModifyNotifier::GetInstance().deleteTokenList_.clear();

    // add a hap token
    AccessTokenIDEx tokenIdEx = { RANDOM_TOKENID };
    std::vector<GenericValues> undefValues;
    int32_t result = AccessTokenInfoManager::GetInstance().CreateHapTokenInfo(
        g_infoManagerTestInfoParms, g_infoManagerTestPolicyPrams1, tokenIdEx, undefValues);
    EXPECT_EQ(RET_SUCCESS, result);

    HapTokenInfoForSync hapSync;
    result = AccessTokenInfoManager::GetInstance().GetHapTokenSync(tokenIdEx.tokenIdExStruct.tokenID, hapSync);
    ASSERT_EQ(result, RET_SUCCESS);
    TokenModifyNotifier::GetInstance().modifiedTokenList_.emplace_back(tokenIdEx.tokenIdExStruct.tokenID);
    ASSERT_EQ(true, TokenModifyNotifier::GetInstance().modifiedTokenList_.size() > 0);
    TokenModifyNotifier::GetInstance().deleteTokenList_.clear();

    EXPECT_CALL(*callback, UpdateRemoteHapTokenInfo(testing::_)) // 0 is a test ret
        .WillOnce(testing::Return(0));
    TokenModifyNotifier::GetInstance().NotifyTokenSyncTask();

    TokenModifyNotifier::GetInstance().deleteTokenList_.emplace_back(tokenIdEx.tokenIdExStruct.tokenID);
    ASSERT_EQ(true, TokenModifyNotifier::GetInstance().deleteTokenList_.size() > 0);
    EXPECT_CALL(*callback, DeleteRemoteHapTokenInfo(testing::_)) // 0 is a test ret
        .WillOnce(testing::Return(0));
    TokenModifyNotifier::GetInstance().NotifyTokenSyncTask();

    TokenModifyNotifier::GetInstance().modifiedTokenList_ = modifiedTokenList; // recovery
    TokenModifyNotifier::GetInstance().deleteTokenList_ = deleteTokenList;
    ASSERT_EQ(RET_SUCCESS, AccessTokenInfoManager::GetInstance().RemoveHapTokenInfo(tokenIdEx.tokenIdExStruct.tokenID));
    setPermission();
    EXPECT_EQ(RET_SUCCESS,
        atManagerService_->UnRegisterTokenSyncCallback());
    setuid(0);
}

/**
 * @tc.name: GetRemoteHapTokenInfo001
 * @tc.desc: TokenModifyNotifier::GetRemoteHapTokenInfo function test
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(TokenInfoManagerTest, GetRemoteHapTokenInfo001, TestSize.Level0)
{
    setPermission();
    sptr<TokenSyncCallbackMock> callback = new (std::nothrow) TokenSyncCallbackMock();
    ASSERT_NE(nullptr, callback);
    EXPECT_EQ(RET_SUCCESS, atManagerService_->RegisterTokenSyncCallback(callback->AsObject()));
    setuid(3020);
    EXPECT_CALL(*callback, GetRemoteHapTokenInfo(testing::_, testing::_))
        .WillOnce(testing::Return(FAKE_SYNC_RET));
    EXPECT_EQ(FAKE_SYNC_RET, TokenModifyNotifier::GetInstance()
        .GetRemoteHapTokenInfo("invalid_id", 0)); // this is a test input
    
    EXPECT_CALL(*callback, GetRemoteHapTokenInfo(testing::_, testing::_))
        .WillOnce(testing::Return(TOKEN_SYNC_OPENSOURCE_DEVICE));
    EXPECT_EQ(TOKEN_SYNC_IPC_ERROR, TokenModifyNotifier::GetInstance()
        .GetRemoteHapTokenInfo("invalid_id", 0)); // this is a test input
    setPermission();
    EXPECT_EQ(RET_SUCCESS,
        atManagerService_->UnRegisterTokenSyncCallback());
    setuid(0);
}

/**
 * @tc.name: UpdateRemoteHapTokenInfo001
 * @tc.desc: AccessTokenInfoManager::UpdateRemoteHapTokenInfo function test
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(TokenInfoManagerTest, UpdateRemoteHapTokenInfo001, TestSize.Level0)
{
    AccessTokenID mapID = 0;
    HapTokenInfoForSync hapSync;

    // infoPtr is null
    ASSERT_NE(RET_SUCCESS, AccessTokenInfoManager::GetInstance().UpdateRemoteHapTokenInfo(mapID, hapSync));

    mapID = RANDOM_TOKENID;
    std::shared_ptr<HapTokenInfoInner> info = std::make_shared<HapTokenInfoInner>();
    info->SetRemote(true);
    AccessTokenInfoManager::GetInstance().hapTokenInfoMap_[mapID] = info;

    // remote is true
    ASSERT_EQ(RET_SUCCESS, AccessTokenInfoManager::GetInstance().UpdateRemoteHapTokenInfo(mapID, hapSync));

    AccessTokenInfoManager::GetInstance().hapTokenInfoMap_.erase(mapID);
}

/**
 * @tc.name: CreateRemoteHapTokenInfo001
 * @tc.desc: AccessTokenInfoManager::CreateRemoteHapTokenInfo function test
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(TokenInfoManagerTest, CreateRemoteHapTokenInfo001, TestSize.Level0)
{
    AccessTokenID mapID = RANDOM_TOKENID;
    HapTokenInfoForSync hapSync;

    hapSync.baseInfo.tokenID = RANDOM_TOKENID;
    std::shared_ptr<HapTokenInfoInner> info = std::make_shared<HapTokenInfoInner>();
    AccessTokenInfoManager::GetInstance().hapTokenInfoMap_[RANDOM_TOKENID] = info;

    // count(id) exsit
    ASSERT_NE(RET_SUCCESS, AccessTokenInfoManager::GetInstance().CreateRemoteHapTokenInfo(mapID, hapSync));

    AccessTokenInfoManager::GetInstance().hapTokenInfoMap_.erase(RANDOM_TOKENID);
}

/**
 * @tc.name: DeleteRemoteToken002
 * @tc.desc: AccessTokenInfoManager::DeleteRemoteToken function test
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(TokenInfoManagerTest, DeleteRemoteToken002, TestSize.Level0)
{
    std::string deviceID = "dev-001";
    AccessTokenID tokenID = RANDOM_TOKENID;

    ASSERT_EQ(AccessTokenError::ERR_PARAM_INVALID,
        AccessTokenInfoManager::GetInstance().DeleteRemoteToken("", tokenID));

    AccessTokenRemoteDevice device;
    device.deviceID_ = deviceID;
    // 537919487 is max hap tokenId: 001 00 0 000000 11111111111111111111
    device.MappingTokenIDPairMap_.insert(std::pair<AccessTokenID, AccessTokenID>(tokenID, 537919487));
    AccessTokenRemoteTokenManager::GetInstance().remoteDeviceMap_[deviceID] = device;

    ASSERT_EQ(RET_SUCCESS, AccessTokenIDManager::GetInstance().RegisterTokenId(537919487, TOKEN_HAP));
    // hap mapID 537919487 is not exist
    ASSERT_NE(RET_SUCCESS, AccessTokenInfoManager::GetInstance().DeleteRemoteToken(deviceID, tokenID));
    AccessTokenRemoteTokenManager::GetInstance().remoteDeviceMap_.erase(deviceID);
    AccessTokenIDManager::GetInstance().ReleaseTokenId(537919487);

    // 672137215 is max native tokenId: 001 01 0 000000 11111111111111111111
    device.MappingTokenIDPairMap_[tokenID] = 672137215;
    AccessTokenRemoteTokenManager::GetInstance().remoteDeviceMap_[deviceID] = device;

    ASSERT_EQ(RET_SUCCESS, AccessTokenIDManager::GetInstance().RegisterTokenId(672137215, TOKEN_NATIVE));
    // native mapID 672137215 is not exist
    ASSERT_NE(RET_SUCCESS, AccessTokenInfoManager::GetInstance().DeleteRemoteToken(deviceID, tokenID));
    AccessTokenRemoteTokenManager::GetInstance().remoteDeviceMap_.erase(deviceID);
    AccessTokenIDManager::GetInstance().ReleaseTokenId(672137215);
}

/**
 * @tc.name: AllocLocalTokenID001
 * @tc.desc: AccessTokenInfoManager::AllocLocalTokenID function test
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(TokenInfoManagerTest, AllocLocalTokenID001, TestSize.Level0)
{
    std::string remoteDeviceID;
    AccessTokenID remoteTokenID = 0;

    ASSERT_EQ(static_cast<uint64_t>(0), AccessTokenInfoManager::GetInstance().AllocLocalTokenID(remoteDeviceID,
        remoteTokenID)); // remoteDeviceID invalid

    // deviceID invalid + tokenID == 0
    ASSERT_EQ(static_cast<AccessTokenID>(0),
        AccessTokenInfoManager::GetInstance().GetRemoteNativeTokenID(remoteDeviceID, remoteTokenID));

    // deviceID invalid
    ASSERT_EQ(ERR_PARAM_INVALID, AccessTokenInfoManager::GetInstance().DeleteRemoteDeviceTokens(remoteDeviceID));

    remoteDeviceID = "dev-001";
    ASSERT_EQ(static_cast<uint64_t>(0), AccessTokenInfoManager::GetInstance().AllocLocalTokenID(remoteDeviceID,
        remoteTokenID)); // remoteTokenID invalid

    // deviceID valid + tokenID == 0
    ASSERT_EQ(static_cast<AccessTokenID>(0),
        AccessTokenInfoManager::GetInstance().GetRemoteNativeTokenID(remoteDeviceID, remoteTokenID));

    remoteTokenID = 537919487; // 537919487 is max hap tokenId: 001 00 0 000000 11111111111111111111
    // deviceID valid + tokenID != 0 + type != native + type != shell
    ASSERT_EQ(static_cast<AccessTokenID>(0),
        AccessTokenInfoManager::GetInstance().GetRemoteNativeTokenID(remoteDeviceID, remoteTokenID));
}
#endif

/**
 * @tc.name: AccessTokenInfoManager001
 * @tc.desc: AccessTokenInfoManager::~AccessTokenInfoManager+Init function test hasInited_ is false
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(TokenInfoManagerTest, AccessTokenInfoManager001, TestSize.Level0)
{
    AccessTokenInfoManager::GetInstance().hasInited_ = true;
    uint32_t hapSize = 0;
    uint32_t nativeSize = 0;
    uint32_t pefDefSize = 0;
    uint32_t dlpSize = 0;
    std::map<int32_t, TokenIdInfo> tokenIdAplMap;
    AccessTokenInfoManager::GetInstance().Init(hapSize, nativeSize, pefDefSize, dlpSize, tokenIdAplMap);
    AccessTokenInfoManager::GetInstance().hasInited_ = false;
    ASSERT_EQ(false, AccessTokenInfoManager::GetInstance().hasInited_);
}

/**
 * @tc.name: GetHapUniqueStr001
 * @tc.desc: AccessTokenInfoManager::GetHapUniqueStr function test info is null
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(TokenInfoManagerTest, GetHapUniqueStr001, TestSize.Level0)
{
    std::shared_ptr<HapTokenInfoInner> info = nullptr;
    ASSERT_EQ("", AccessTokenInfoUtils::GetHapUniqueStr(info));
}

/**
 * @tc.name: AddHapTokenInfo001
 * @tc.desc: AccessTokenInfoManager::AddHapTokenInfo function test info is null
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(TokenInfoManagerTest, AddHapTokenInfo001, TestSize.Level0)
{
    std::shared_ptr<HapTokenInfoInner> info = nullptr;
    AccessTokenID oriTokenId = 0;
    ASSERT_NE(0, AccessTokenInfoManager::GetInstance().AddHapTokenInfo(info, oriTokenId));
}

/**
 * @tc.name: AddHapTokenInfo002
 * @tc.desc: AccessTokenInfoManager::AddHapTokenInfo function test count(id) > 0
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(TokenInfoManagerTest, AddHapTokenInfo002, TestSize.Level0)
{
    HapInfoParams info = {
        .userID = USER_ID,
        .bundleName = "token_info_manager_test",
        .instIndex = INST_INDEX,
        .appIDDesc = "token_info_manager_test"
    };
    HapPolicy policy = {
        .apl = APL_NORMAL,
        .domain = "domain"
    };
    AccessTokenIDEx tokenIdEx = {0};
    std::vector<GenericValues> undefValues;
    ASSERT_EQ(RET_SUCCESS, AccessTokenInfoManager::GetInstance().CreateHapTokenInfo(info, policy, tokenIdEx,
        undefValues));
    AccessTokenID tokenId = tokenIdEx.tokenIdExStruct.tokenID;
    ASSERT_NE(static_cast<AccessTokenID>(0), tokenId);

    std::shared_ptr<HapTokenInfoInner> infoPtr = AccessTokenInfoManager::GetInstance().GetHapTokenInfoInner(tokenId);
    AccessTokenID oriTokenId = 0;
    ASSERT_NE(0, AccessTokenInfoManager::GetInstance().AddHapTokenInfo(infoPtr, oriTokenId));

    ASSERT_EQ(RET_SUCCESS, AccessTokenInfoManager::GetInstance().RemoveHapTokenInfo(tokenId));
}

/**
 * @tc.name: GetHapTokenID002
 * @tc.desc: test GetHapTokenID function abnomal branch
 * @tc.type: FUNC
 * @tc.require: issueI60F1M
 */
HWTEST_F(TokenInfoManagerTest, GetHapTokenID002, TestSize.Level0)
{
    AccessTokenIDEx tokenIdEx = AccessTokenInfoManager::GetInstance().GetHapTokenID(
        USER_ID, "com.ohos.test", INST_INDEX);
    ASSERT_EQ(static_cast<AccessTokenID>(0), tokenIdEx.tokenIDEx);
}

/**
 * @tc.name: IsPermissionDefValid001
 * @tc.desc: PermissionValidator::IsPermissionDefValid function test
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(TokenInfoManagerTest, IsPermissionDefValid001, TestSize.Level0)
{
    PermissionDef permDef = {
        .permissionName = "ohos.permission.TEST",
        .bundleName = "com.ohos.test",
        .grantMode = static_cast<GrantMode>(INVALID_GRANT_MODE),
        .availableLevel = ATokenAplEnum::APL_NORMAL,
        .provisionEnable = false,
        .distributedSceneEnable = false,
        .label = "buzhidao",
        .labelId = 100, // 100 is random input
        .description = "buzhidao",
        .descriptionId = 100 // 100 is random input
    };

    // ret not RET_SUCCESS
    ASSERT_EQ(false, PermissionValidator::IsPermissionDefValid(permDef)); // grant mode invalid

    permDef.grantMode = GrantMode::USER_GRANT;
    permDef.availableType = ATokenAvailableTypeEnum::INVALID;
    ASSERT_EQ(false, PermissionValidator::IsPermissionDefValid(permDef)); // availableType invalid
}

/**
 * @tc.name: IsPermissionStateValid001
 * @tc.desc: PermissionValidator::IsPermissionStateValid function test
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(TokenInfoManagerTest, IsPermissionStateValid001, TestSize.Level0)
{
    std::string permissionName;
    std::string deviceID = "dev-001";
    int grantState = PermissionState::PERMISSION_DENIED;
    uint32_t grantFlag = PermissionFlag::PERMISSION_DEFAULT_FLAG;
    PermissionStatus permState = {
        .permissionName = permissionName,
        .grantStatus = grantState,
        .grantFlag = grantFlag
    };

    ASSERT_EQ(false, PermissionValidator::IsPermissionStateValid(permState)); // permissionName empty

    permState.permissionName = "com.ohos.TEST";
    permState.grantStatus = 1; // 1: invalid status
    ASSERT_EQ(false, PermissionValidator::IsPermissionStateValid(permState));

    permState.grantStatus = grantState;
    permState.grantFlag = -1; // -1: invalid flag
    ASSERT_EQ(false, PermissionValidator::IsPermissionStateValid(permState));

    permState.grantFlag = grantFlag;
    ASSERT_EQ(true, PermissionValidator::IsPermissionStateValid(permState));
}

/**
 * @tc.name: FilterInvalidPermissionDef001
 * @tc.desc: PermissionValidator::FilterInvalidPermissionDef function test
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(TokenInfoManagerTest, FilterInvalidPermissionDef001, TestSize.Level0)
{
    PermissionDef permDef = {
        .permissionName = "ohos.permission.TEST",
        .bundleName = "com.ohos.test",
        .grantMode = GrantMode::SYSTEM_GRANT,
        .availableLevel = ATokenAplEnum::APL_NORMAL,
        .provisionEnable = false,
        .distributedSceneEnable = false,
        .label = "buzhidao",
        .labelId = 100, // 100 is random input
        .description = "buzhidao",
        .descriptionId = 100 // 100 is random input
    };

    std::vector<PermissionDef> permList;
    permList.emplace_back(permDef);
    permList.emplace_back(permDef);

    ASSERT_EQ(static_cast<uint32_t>(2), permList.size());

    std::vector<PermissionDef> result;
    PermissionValidator::FilterInvalidPermissionDef(permList, result); // permDefSet.count != 0
    ASSERT_EQ(static_cast<uint32_t>(1), result.size());
}

/**
 * @tc.name: UpdatePermissionStatus001
 * @tc.desc: PermissionPolicySet::UpdatePermissionStatus function test
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(TokenInfoManagerTest, UpdatePermissionStatus001, TestSize.Level0)
{
    PermissionStatus perm = {
        .permissionName = "ohos.permission.CAMERA",
        .grantStatus = PermissionState::PERMISSION_DENIED,
        .grantFlag = PermissionFlag::PERMISSION_DEFAULT_FLAG
    };

    AccessTokenID tokenId = 789; // 789 is random input
    std::vector<PermissionStatus> permStateList;
    permStateList.emplace_back(perm);

    PermissionDataBrief::GetInstance().AddPermToBriefPermission(tokenId, permStateList, true);

    // iter reach the end
    bool isGranted = false;
    uint32_t flag = PermissionFlag::PERMISSION_DEFAULT_FLAG;
    PermissionDataBrief::PermissionStatusChangeType changed =
        PermissionDataBrief::PermissionStatusChangeType::NO_CHANGE;

    // permission is invalid
    ASSERT_EQ(ERR_PARAM_INVALID, PermissionDataBrief::GetInstance().UpdatePermissionStatus(tokenId,
        "ohos.permission.TEST1", isGranted, flag, changed));
    // flag != PERMISSION_COMPONENT_SET
    flag = PermissionFlag::PERMISSION_DEFAULT_FLAG;
    ASSERT_EQ(RET_SUCCESS, PermissionDataBrief::GetInstance().UpdatePermissionStatus(tokenId,
        "ohos.permission.CAMERA", isGranted, flag, changed));

    flag = PermissionFlag::PERMISSION_ADMIN_POLICIES_CANCEL;
    ASSERT_EQ(ERR_PARAM_INVALID, PermissionDataBrief::GetInstance().UpdatePermissionStatus(tokenId,
        "ohos.permission.CAMERA", isGranted, flag, changed));
    flag = PermissionFlag::PERMISSION_FIXED_BY_ADMIN_POLICY;
    ASSERT_EQ(RET_SUCCESS, PermissionDataBrief::GetInstance().UpdatePermissionStatus(tokenId,
        "ohos.permission.CAMERA", isGranted, flag, changed));
    flag = PermissionFlag::PERMISSION_FIXED_FOR_SECURITY_POLICY;
    ASSERT_EQ(ERR_PERMISSION_RESTRICTED, PermissionDataBrief::GetInstance().UpdatePermissionStatus(tokenId,
        "ohos.permission.CAMERA", isGranted, flag, changed));
    flag = PermissionFlag::PERMISSION_ADMIN_POLICIES_CANCEL;
    ASSERT_EQ(RET_SUCCESS, PermissionDataBrief::GetInstance().UpdatePermissionStatus(tokenId,
        "ohos.permission.CAMERA", isGranted, flag, changed));

    // flag == PERMISSION_COMPONENT_SET
    flag = PermissionFlag::PERMISSION_COMPONENT_SET;
    ASSERT_EQ(RET_SUCCESS, PermissionDataBrief::GetInstance().UpdatePermissionStatus(tokenId,
        "ohos.permission.CAMERA", isGranted, flag, changed));


    // flag == PERMISSION_SYSTEM_FIXED
    flag = PermissionFlag::PERMISSION_SYSTEM_FIXED;
    ASSERT_EQ(RET_SUCCESS, PermissionDataBrief::GetInstance().UpdatePermissionStatus(tokenId,
        "ohos.permission.CAMERA", isGranted, flag, changed));

    // Permission fixed by system
    flag = PermissionFlag::PERMISSION_DEFAULT_FLAG;
    ASSERT_EQ(ERR_PARAM_INVALID, PermissionDataBrief::GetInstance().UpdatePermissionStatus(tokenId,
        "ohos.permission.CAMERA", isGranted, flag, changed));
}

/**
 * @tc.name: UpdatePermStatus001
 * @tc.desc: PermissionDataBrief::UpdatePermStatus function test
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(TokenInfoManagerTest, UpdatePermStatus001, TestSize.Level0)
{
    BriefPermData permOld;
    BriefPermData permNew;

    permOld.flag = PermissionFlag::PERMISSION_FIXED_BY_ADMIN_POLICY;
    permOld.status = PERMISSION_DENIED;

    permNew.flag = PermissionFlag::PERMISSION_SYSTEM_FIXED;
    permNew.status = PERMISSION_GRANTED;
    PermissionDataBrief::GetInstance().UpdatePermStatus(permOld, permNew);
    ASSERT_NE(permOld.status, permNew.status);

    permOld.flag = PermissionFlag::PERMISSION_ADMIN_POLICIES_CANCEL;
    PermissionDataBrief::GetInstance().UpdatePermStatus(permOld, permNew);
    ASSERT_NE(permOld.status, permNew.status);

    permOld.flag = PermissionFlag::PERMISSION_ADMIN_POLICIES_CANCEL;
    permNew.flag = PermissionFlag::PERMISSION_PRE_AUTHORIZED_CANCELABLE;
    PermissionDataBrief::GetInstance().UpdatePermStatus(permOld, permNew);
    ASSERT_NE(permOld.status, permNew.status);

    permOld.flag = PermissionFlag::PERMISSION_SYSTEM_FIXED;
    PermissionDataBrief::GetInstance().UpdatePermStatus(permOld, permNew);
    ASSERT_NE(permOld.status, permNew.status);

    permOld.flag = PermissionFlag::PERMISSION_PRE_AUTHORIZED_CANCELABLE;
    PermissionDataBrief::GetInstance().UpdatePermStatus(permOld, permNew);
    ASSERT_NE(permOld.status, permNew.status);
}

#ifdef TOKEN_SYNC_ENABLE
/**
 * @tc.name: MapRemoteDeviceTokenToLocal001
 * @tc.desc: AccessTokenRemoteTokenManager::MapRemoteDeviceTokenToLocal function test
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(TokenInfoManagerTest, MapRemoteDeviceTokenToLocal001, TestSize.Level0)
{
    std::map<std::string, AccessTokenRemoteDevice> remoteDeviceMap;
    remoteDeviceMap = AccessTokenRemoteTokenManager::GetInstance().remoteDeviceMap_; // backup
    AccessTokenRemoteTokenManager::GetInstance().remoteDeviceMap_.clear();

    std::string deviceID;
    AccessTokenID remoteID = 0;

    // input invalid
    ASSERT_EQ(static_cast<AccessTokenID>(0),
        AccessTokenRemoteTokenManager::GetInstance().MapRemoteDeviceTokenToLocal(deviceID, remoteID));

    remoteID = 940572671; // 940572671 is max butt tokenId: 001 11 0 000000 11111111111111111111
    deviceID = "dev-001";

    // tokeType invalid
    ASSERT_EQ(static_cast<AccessTokenID>(0),
        AccessTokenRemoteTokenManager::GetInstance().MapRemoteDeviceTokenToLocal(deviceID, remoteID));

    remoteID = 537919487; // 537919487 is max hap tokenId: 001 00 0 000000 11111111111111111111, no need to register
    std::map<AccessTokenID, AccessTokenID> MappingTokenIDPairMap;
    MappingTokenIDPairMap[537919487] = 456; // 456 is random input
    AccessTokenRemoteDevice device = {
        .deviceID_ = "dev-001",
        .MappingTokenIDPairMap_ = MappingTokenIDPairMap
    };
    AccessTokenRemoteTokenManager::GetInstance().remoteDeviceMap_["dev-001"] = device;

    // count(remoteID) > 0
    ASSERT_EQ(static_cast<AccessTokenID>(456),
        AccessTokenRemoteTokenManager::GetInstance().MapRemoteDeviceTokenToLocal(deviceID, remoteID));

    AccessTokenRemoteTokenManager::GetInstance().remoteDeviceMap_ = remoteDeviceMap; // recovery
}

/**
 * @tc.name: GetDeviceAllRemoteTokenID001
 * @tc.desc: AccessTokenRemoteTokenManager::GetDeviceAllRemoteTokenID function test
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(TokenInfoManagerTest, GetDeviceAllRemoteTokenID001, TestSize.Level0)
{
    std::string deviceID;
    std::vector<AccessTokenID> remoteIDs;

    // deviceID invalid
    ASSERT_EQ(ERR_PARAM_INVALID,
        AccessTokenRemoteTokenManager::GetInstance().GetDeviceAllRemoteTokenID(deviceID, remoteIDs));
}

/**
 * @tc.name: RemoveDeviceMappingTokenID001
 * @tc.desc: AccessTokenRemoteTokenManager::RemoveDeviceMappingTokenID function test
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(TokenInfoManagerTest, RemoveDeviceMappingTokenID001, TestSize.Level0)
{
    std::map<std::string, AccessTokenRemoteDevice> remoteDeviceMap;
    remoteDeviceMap = AccessTokenRemoteTokenManager::GetInstance().remoteDeviceMap_; // backup
    AccessTokenRemoteTokenManager::GetInstance().remoteDeviceMap_.clear();

    std::string deviceID;
    AccessTokenID remoteID = 0;

    // input invalid
    ASSERT_NE(RET_SUCCESS,
        AccessTokenRemoteTokenManager::GetInstance().RemoveDeviceMappingTokenID(deviceID, remoteID));

    deviceID = "dev-001";
    remoteID = RANDOM_TOKENID;

    // count < 1
    ASSERT_NE(RET_SUCCESS,
        AccessTokenRemoteTokenManager::GetInstance().RemoveDeviceMappingTokenID(deviceID, remoteID));

    AccessTokenRemoteTokenManager::GetInstance().remoteDeviceMap_ = remoteDeviceMap; // recovery
}

/**
 * @tc.name: AddHapTokenObservation001
 * @tc.desc: TokenModifyNotifier::AddHapTokenObservation function test
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(TokenInfoManagerTest, AddHapTokenObservation001, TestSize.Level0)
{
    std::set<AccessTokenID> observationSet = TokenModifyNotifier::GetInstance().observationSet_; // backup
    TokenModifyNotifier::GetInstance().observationSet_.clear();

    AccessTokenID tokenId = RANDOM_TOKENID;

    TokenModifyNotifier::GetInstance().observationSet_.insert(tokenId);
    ASSERT_EQ(true, TokenModifyNotifier::GetInstance().observationSet_.count(tokenId) > 0);

    // count > 0
    TokenModifyNotifier::GetInstance().AddHapTokenObservation(tokenId);
    TokenModifyNotifier::GetInstance().NotifyTokenModify(tokenId);

    TokenModifyNotifier::GetInstance().observationSet_ = observationSet; // recovery
}
#endif

/**
 * @tc.name: RestoreHapTokenInfo001
 * @tc.desc: HapTokenInfoInner::RestoreHapTokenInfo function test
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(TokenInfoManagerTest, RestoreHapTokenInfo001, TestSize.Level0)
{
    std::shared_ptr<HapTokenInfoInner> hap = std::make_shared<HapTokenInfoInner>();
    ASSERT_NE(nullptr, hap);

    AccessTokenID tokenId = 0;
    GenericValues tokenValue;
    std::vector<GenericValues> permStateRes;
    std::vector<GenericValues> extendedPermRes;
    std::string bundleName;
    std::string appIDDesc;
    std::string deviceID;
    int version = 10; // 10 is random input which only need not equal 1
    HapPolicy policy;
    UpdateHapInfoParams hapInfo;
    hapInfo.apiVersion = DEFAULT_API_VERSION;
    hapInfo.isSystemApp = false;
    hap->Update(hapInfo, policy.permStateList, policy); // permPolicySet_ is null

    std::vector<GenericValues> hapInfoValues;
    std::vector<GenericValues> permStateValues;
    hap->GenerateHapInfoValues("test", APL_NORMAL, hapInfoValues);
    hap->GeneratePermStateValues({}, permStateValues); // permPolicySet_ is null


    tokenValue.Put(TokenFiledConst::FIELD_BUNDLE_NAME, bundleName);
    // bundleName invalid
    ASSERT_EQ(ERR_PARAM_INVALID, hap->RestoreHapTokenInfo(tokenId, tokenValue, permStateRes, extendedPermRes));
    tokenValue.Remove(TokenFiledConst::FIELD_BUNDLE_NAME);

    bundleName = "com.ohos.permissionmanger";
    tokenValue.Put(TokenFiledConst::FIELD_BUNDLE_NAME, bundleName);
    tokenValue.Put(TokenFiledConst::FIELD_TOKEN_VERSION, version);
    // version invalid
    ASSERT_EQ(ERR_PARAM_INVALID, hap->RestoreHapTokenInfo(tokenId, tokenValue, permStateRes, extendedPermRes));
}

/**
 * @tc.name: RegisterTokenId001
 * @tc.desc: AccessTokenIDManager::RegisterTokenId function test
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(TokenInfoManagerTest, RegisterTokenId001, TestSize.Level0)
{
    // 1477443583 is max abnormal butt tokenId which version is 2: 010 11 0 000000 11111111111111111111
    AccessTokenID tokenId = 1477443583;
    ATokenTypeEnum type = ATokenTypeEnum::TOKEN_HAP;

    // version != 1 + type dismatch
    ASSERT_NE(RET_SUCCESS, AccessTokenIDManager::GetInstance().RegisterTokenId(tokenId, type));

    AccessTokenIDEx tokenIdEx = {0};
    std::vector<GenericValues> undefValues;
    ASSERT_EQ(RET_SUCCESS, AccessTokenInfoManager::GetInstance().CreateHapTokenInfo(g_infoManagerTestInfoParms,
        g_infoManagerTestPolicyPrams1, tokenIdEx, undefValues));

    // register repeat
    ASSERT_NE(RET_SUCCESS, AccessTokenIDManager::GetInstance().RegisterTokenId(
        tokenIdEx.tokenIdExStruct.tokenID, type));
    ASSERT_EQ(RET_SUCCESS, AccessTokenInfoManager::GetInstance().RemoveHapTokenInfo(tokenIdEx.tokenIdExStruct.tokenID));
}

/**
 * @tc.name: ClearAllSecCompGrantedPerm001
 * @tc.desc: ClearAllSecCompGrantedPerm function test
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(TokenInfoManagerTest, ClearAllSecCompGrantedPerm001, TestSize.Level0)
{
    AccessTokenIDEx tokenIdEx = {0};
    std::vector<GenericValues> undefValues;
    int32_t ret = AccessTokenInfoManager::GetInstance().CreateHapTokenInfo(
        g_infoManagerTestInfoParms, g_infoManagerTestPolicyPrams1, tokenIdEx, undefValues);
    ASSERT_EQ(RET_SUCCESS, ret);
    AccessTokenID tokenId = tokenIdEx.tokenIdExStruct.tokenID;

    ASSERT_EQ(PERMISSION_DENIED,
        AccessTokenInfoManager::GetInstance().VerifyAccessToken(tokenId, "ohos.permission.LOCATION"));
    ASSERT_EQ(RET_SUCCESS, PermissionManager::GetInstance().GrantPermission(
        tokenId, "ohos.permission.LOCATION", PERMISSION_COMPONENT_SET));
    ASSERT_EQ(PERMISSION_GRANTED,
        AccessTokenInfoManager::GetInstance().VerifyAccessToken(tokenId, "ohos.permission.LOCATION"));

    std::string deviceId;
    atManagerService_->OnRemoveSystemAbility(SECURITY_COMPONENT_SERVICE_ID, deviceId);
    ASSERT_EQ(PERMISSION_DENIED,
        AccessTokenInfoManager::GetInstance().VerifyAccessToken(tokenId, "ohos.permission.LOCATION"));

    // delete test token
    ASSERT_EQ(RET_SUCCESS, AccessTokenInfoManager::GetInstance().RemoveHapTokenInfo(tokenId));
}

/**
 * @tc.name: ClearUserGrantedPermissionStateAdminFlag001
 * @tc.desc: ResetUserGrantPermissionStatus should keep admin restricted flag.
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(TokenInfoManagerTest, ClearUserGrantedPermissionStateAdminFlag001, TestSize.Level0)
{
    AccessTokenID tokenId = RANDOM_TOKENID;
    uint32_t permCode = 0;
    ASSERT_TRUE(TransferPermissionToOpcode("ohos.permission.CAMERA", permCode));

    std::vector<PermissionStatus> permStateList = {{
        .permissionName = "ohos.permission.CAMERA",
        .grantStatus = PERMISSION_GRANTED,
        .grantFlag = PERMISSION_RESTRICTED_BY_ADMIN
    }, {
        .permissionName = "ohos.permission.LOCATION",
        .grantStatus = PERMISSION_GRANTED,
        .grantFlag = PERMISSION_ADMIN_POLICIES_CANCEL
    }};
    PermissionDataBrief::GetInstance().AddPermToBriefPermission(tokenId, permStateList, true);

    ASSERT_EQ(RET_SUCCESS, PermissionDataBrief::GetInstance().ResetUserGrantPermissionStatus(tokenId));

    std::vector<BriefPermData> permDataList;
    ASSERT_EQ(RET_SUCCESS, PermissionDataBrief::GetInstance().GetBriefPermDataByTokenId(tokenId, permDataList));
    auto permData = std::find_if(permDataList.begin(), permDataList.end(), [permCode](const BriefPermData& data) {
        return data.permCode == permCode;
    });
    ASSERT_NE(permDataList.end(), permData);
    EXPECT_EQ(PERMISSION_GRANTED, permData->status);
    EXPECT_NE(0u, permData->flag & PERMISSION_RESTRICTED_BY_ADMIN);
    EXPECT_EQ(0u, permData->flag & PERMISSION_USER_SET);

    ASSERT_TRUE(TransferPermissionToOpcode("ohos.permission.LOCATION", permCode));
    permData = std::find_if(permDataList.begin(), permDataList.end(), [permCode](const BriefPermData& data) {
        return data.permCode == permCode;
    });
    ASSERT_NE(permDataList.end(), permData);
    EXPECT_EQ(PERMISSION_DENIED, permData->status);
    EXPECT_EQ(PERMISSION_DEFAULT_FLAG, permData->flag);
    EXPECT_EQ(0u, permData->flag & PERMISSION_USER_SET);

    ASSERT_EQ(RET_SUCCESS, PermissionDataBrief::GetInstance().DeleteBriefPermDataByTokenId(tokenId));
}

/**
 * @tc.name: SetPermDialogCap001
 * @tc.desc: SetPermDialogCap with HapUniqueKey not exist
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(TokenInfoManagerTest, SetPermDialogCap001, TestSize.Level0)
{
    AccessTokenID tokenId = RANDOM_TOKENID;
    ASSERT_EQ(ERR_TOKENID_NOT_EXIST, AccessTokenInfoManager::GetInstance().SetPermDialogCap(tokenId, true));
}

/**
 * @tc.name: SetPermDialogCap002
 * @tc.desc: SetPermDialogCap with abnormal branch
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(TokenInfoManagerTest, SetPermDialogCap002, TestSize.Level0)
{
    AccessTokenIDEx tokenIdEx = {0};
    std::vector<GenericValues> undefValues;
    int32_t ret = AccessTokenInfoManager::GetInstance().CreateHapTokenInfo(
        g_infoManagerTestInfoParms, g_infoManagerTestPolicyPrams1, tokenIdEx, undefValues);
    ASSERT_EQ(RET_SUCCESS, ret);
    AccessTokenID tokenId = tokenIdEx.tokenIdExStruct.tokenID;

    // SetPermDialogCap successfull
    ASSERT_EQ(RET_SUCCESS, AccessTokenInfoManager::GetInstance().SetPermDialogCap(tokenId, true));
    ASSERT_EQ(true, AccessTokenInfoManager::GetInstance().GetPermDialogCap(tokenId));
    ASSERT_EQ(RET_SUCCESS, AccessTokenInfoManager::GetInstance().SetPermDialogCap(tokenId, false));
    ASSERT_EQ(false, AccessTokenInfoManager::GetInstance().GetPermDialogCap(tokenId));

    std::shared_ptr<HapTokenInfoInner> back = AccessTokenInfoManager::GetInstance().hapTokenInfoMap_[tokenId];

    // tokeninfo of hapTokenInfoMap_ is nullptr, return true(forbid)
    AccessTokenInfoManager::GetInstance().hapTokenInfoMap_[tokenId] = nullptr;
    ASSERT_EQ(ERR_TOKENID_NOT_EXIST,
        AccessTokenInfoManager::GetInstance().SetPermDialogCap(tokenId, true)); // info is null
    ASSERT_EQ(true, AccessTokenInfoManager::GetInstance().GetPermDialogCap(tokenId));

    // token is not found in hapTokenInfoMap_, return true(forbid)
    AccessTokenInfoManager::GetInstance().hapTokenInfoMap_.erase(tokenId);
    ASSERT_EQ(ERR_TOKENID_NOT_EXIST,
        AccessTokenInfoManager::GetInstance().SetPermDialogCap(tokenId, true)); // info is null
    ASSERT_EQ(true, AccessTokenInfoManager::GetInstance().GetPermDialogCap(tokenId));
    AccessTokenInfoManager::GetInstance().hapTokenInfoMap_[tokenId] = back;
    
    ASSERT_EQ(RET_SUCCESS, AccessTokenInfoManager::GetInstance().RemoveHapTokenInfo(tokenId));
}

/**
 * @tc.name: GetPermDialogCap001
 * @tc.desc: GetPermDialogCap with abnormal branch
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(TokenInfoManagerTest, GetPermDialogCap001, TestSize.Level0)
{
    // invalid token
    ASSERT_EQ(true, AccessTokenInfoManager::GetInstance().GetPermDialogCap(INVALID_TOKENID));

    // nonexist token
    ASSERT_EQ(true, AccessTokenInfoManager::GetInstance().GetPermDialogCap(RANDOM_TOKENID));

    // tokeninfo is nullptr
    HapBaseInfo baseInfo = {
        .userID = g_infoManagerTestInfoParms.userID,
        .bundleName = g_infoManagerTestInfoParms.bundleName,
        .instIndex = g_infoManagerTestInfoParms.instIndex,
    };
    AccessTokenIDEx tokenIdEx = {0};
    std::vector<GenericValues> undefValues;
    int32_t ret = AccessTokenInfoManager::GetInstance().CreateHapTokenInfo(
        g_infoManagerTestInfoParms, g_infoManagerTestPolicyPrams1, tokenIdEx, undefValues);
    ASSERT_EQ(RET_SUCCESS, ret);
    AccessTokenID tokenId = tokenIdEx.tokenIdExStruct.tokenID;
    std::shared_ptr<HapTokenInfoInner> back = AccessTokenInfoManager::GetInstance().hapTokenInfoMap_[tokenId];
    AccessTokenInfoManager::GetInstance().hapTokenInfoMap_[tokenId] = nullptr;
    ASSERT_EQ(true, AccessTokenInfoManager::GetInstance().GetPermDialogCap(RANDOM_TOKENID));

    AccessTokenInfoManager::GetInstance().hapTokenInfoMap_[tokenId] = back;
    ASSERT_EQ(RET_SUCCESS, AccessTokenInfoManager::GetInstance().RemoveHapTokenInfo(tokenId));
}

/**
 * @tc.name: AllocHapToken001
 * @tc.desc: alloc hap create haptokeninfo failed.
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(TokenInfoManagerTest, AllocHapToken001, TestSize.Level0)
{
    HapInfoParcel hapinfoParcel;
    hapinfoParcel.hapInfoParameter = {
        .userID = -1,
        .bundleName = "accesstoken_test",
        .instIndex = 0,
        .appIDDesc = "testtesttesttest",
        .apiVersion = DEFAULT_API_VERSION,
        .isSystemApp = false,
    };
    HapPolicyParcel hapPolicyParcel;
    hapPolicyParcel.hapPolicy.apl = ATokenAplEnum::APL_NORMAL;
    hapPolicyParcel.hapPolicy.domain = "test.domain";

    uint64_t tokenIDEx;
    atManagerService_->AllocHapToken(hapinfoParcel, hapPolicyParcel, tokenIDEx);
    ASSERT_EQ(INVALID_TOKENID, tokenIDEx);
}

/**
 * @tc.name: OnStart001
 * @tc.desc: service is running.
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(TokenInfoManagerTest, OnStart001, TestSize.Level0)
{
    ServiceRunningState state = atManagerService_->state_;
    atManagerService_->state_ = ServiceRunningState::STATE_RUNNING;
    atManagerService_->OnStart();
    ASSERT_EQ(ServiceRunningState::STATE_RUNNING, atManagerService_->state_);
    atManagerService_->state_ = state;
}

/**
 * @tc.name: Dlopen001
 * @tc.desc: Open a not exist lib & not exist func
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(TokenInfoManagerTest, Dlopen001, TestSize.Level0)
{
    LibraryLoader loader1("libnotexist.z.so"); // is a not exist path
    EXPECT_EQ(nullptr, loader1.handle_);

    LibraryLoader loader2("libaccesstoken_sdk.z.so"); // is a exist lib without create func
    EXPECT_EQ(nullptr, loader2.instance_);
    EXPECT_NE(nullptr, loader2.handle_);
}

#ifdef TOKEN_SYNC_ENABLE
/**
 * @tc.name: Dlopen002
 * @tc.desc: Open a exist lib & exist func
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(TokenInfoManagerTest, Dlopen002, TestSize.Level0)
{
    LibraryLoader loader(TOKEN_SYNC_LIBPATH);
    TokenSyncKitInterface* tokenSyncKit = loader.GetObject<TokenSyncKitInterface>();
    EXPECT_NE(nullptr, loader.handle_);
    EXPECT_NE(nullptr, tokenSyncKit);
}
#endif

/**
 * @tc.name: VerifyNativeAccessToken001
 * @tc.desc: TokenInfoManagerTest::VerifyNativeAccessToken function test
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(TokenInfoManagerTest, VerifyNativeAccessToken001, TestSize.Level0)
{
    AccessTokenID tokenId = 0x280bc142; // 0x280bc142 is random input
    std::string permissionName = "ohos.permission.INVALID_AA";
    AccessTokenID tokenId1 = AccessTokenInfoManager::GetInstance().GetNativeTokenId("accesstoken_service");
    uint32_t permCode = 0;
    ASSERT_TRUE(TransferPermissionToOpcode("ohos.permission.KILL_APP_PROCESSES", permCode));
    AccessTokenInfoManager::GetInstance().nativeTokenInfoMap_[tokenId1].opCodeList.emplace_back(permCode);
    // tokenId is not exist
    ASSERT_EQ(PermissionState::PERMISSION_DENIED,
        AccessTokenInfoManager::GetInstance().VerifyNativeAccessToken(tokenId, permissionName));

    permissionName = "ohos.permission.CAMERA";
    // permission is not request
    ASSERT_EQ(PermissionState::PERMISSION_DENIED,
        AccessTokenInfoManager::GetInstance().VerifyNativeAccessToken(tokenId1, permissionName));

    // tokenId is native token, and permission is defined
    if (!PermissionKernelUtils::IsKernelSupportSpm()) {
        permissionName = "ohos.permission.KILL_APP_PROCESSES";
        ASSERT_EQ(PermissionState::PERMISSION_GRANTED,
        AccessTokenInfoManager::GetInstance().VerifyNativeAccessToken(tokenId1, permissionName));
    }
}

/**
 * @tc.name: VerifyAccessToken001
 * @tc.desc: TokenInfoManagerTest::VerifyAccessToken function test
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(TokenInfoManagerTest, VerifyAccessToken001, TestSize.Level0)
{
    AccessTokenID tokenId = 0;
    std::string permissionName;
    // tokenID invalid
    ASSERT_EQ(PERMISSION_DENIED, AccessTokenInfoManager::GetInstance().VerifyAccessToken(tokenId, permissionName));

    tokenId = 940572671; // 940572671 is max butt tokenId: 001 11 0 000000 11111111111111111111
    // permissionName invalid
    ASSERT_EQ(PERMISSION_DENIED, AccessTokenInfoManager::GetInstance().VerifyAccessToken(tokenId, permissionName));

    // tokenID invalid
    permissionName = "ohos.permission.CAMERA";
    ASSERT_EQ(PERMISSION_DENIED, AccessTokenInfoManager::GetInstance().VerifyAccessToken(tokenId, permissionName));
}

/**
 * @tc.name: VerifyAccessToken002
 * @tc.desc: TokenInfoManagerTest::VerifyAccessToken falls back to manager cache when kernel query fails.
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(TokenInfoManagerTest, VerifyAccessToken002, TestSize.Level0)
{
    HapInfoParams info = g_infoManagerTestInfoParms;
    info.bundleName = "verify_access_token_manager_fallback";
    info.appProvisionType = "debug";
    PermissionStatus permState = g_permState;
    permState.grantStatus = PERMISSION_GRANTED;
    HapPolicy policy = {
        .apl = APL_SYSTEM_BASIC,
        .domain = "verify.access.token.manager",
        .permStateList = {permState},
        .isDebugGrant = true
    };

    AccessTokenIDEx tokenIdEx = {0};
    std::vector<GenericValues> undefValues;
    ASSERT_EQ(RET_SUCCESS, AccessTokenInfoManager::GetInstance().CreateHapTokenInfo(
        info, policy, tokenIdEx, undefValues));
    AccessTokenID tokenId = tokenIdEx.tokenIdExStruct.tokenID;
    ASSERT_NE(INVALID_TOKENID, tokenId);

    ASSERT_EQ(PERMISSION_GRANTED,
        AccessTokenInfoManager::GetInstance().VerifyAccessToken(tokenId, "ohos.permission.CAMERA"));

    ASSERT_EQ(RET_SUCCESS, AccessTokenInfoManager::GetInstance().RemoveHapTokenInfo(tokenId));
}

/**
 * @tc.name: GetAppId001
 * @tc.desc: TokenInfoManagerTest::VerifyAccessToken function test
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(TokenInfoManagerTest, GetAppId001, TestSize.Level0)
{
    HapInfoParams info = {
        .userID = USER_ID,
        .bundleName = "token_info_manager_test",
        .instIndex = INST_INDEX,
        .appIDDesc = "token_info_manager_test"
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
    int ret = AccessTokenInfoManager::GetInstance().GetHapAppIdByTokenId(tokenIdEx.tokenIdExStruct.tokenID, appId);
    ASSERT_EQ(ret, RET_SUCCESS);
    ASSERT_EQ(appId, "token_info_manager_test");
    ASSERT_EQ(RET_SUCCESS, AccessTokenInfoManager::GetInstance().RemoveHapTokenInfo(tokenIdEx.tokenIdExStruct.tokenID));
}

/**
 * @tc.name: GetApiVersionByTokenId002
 * @tc.desc: AccessTokenInfoManager::GetApiVersionByTokenId function test with hap token.
 * @tc.type: FUNC
 */
HWTEST_F(TokenInfoManagerTest, GetApiVersionByTokenId002, TestSize.Level0)
{
    HapInfoParams info = g_infoManagerTestInfoParms;
    info.apiVersion = 1205;
    AccessTokenIDEx tokenIdEx = {0};
    std::vector<GenericValues> undefValues;
    ASSERT_EQ(RET_SUCCESS, AccessTokenInfoManager::GetInstance().CreateHapTokenInfo(
        info, g_infoManagerTestPolicyPrams1, tokenIdEx, undefValues));
    AccessTokenID tokenId = tokenIdEx.tokenIdExStruct.tokenID;
    ASSERT_NE(INVALID_TOKENID, tokenId);

    int32_t apiVersion = 0;
    ASSERT_TRUE(AccessTokenInfoManager::GetInstance().GetApiVersionByTokenId(tokenId, apiVersion));
    ASSERT_EQ(205, apiVersion);
    ASSERT_EQ(RET_SUCCESS, AccessTokenInfoManager::GetInstance().RemoveHapTokenInfo(tokenId));
}


/**
 * @tc.name: UserPolicyManagerIsPermissionRestricted001
 * @tc.desc: UserPolicyManager::IsPermissionRestricted function test with invalid tokenid.
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(TokenInfoManagerTest, UserPolicyManagerIsPermissionRestricted001, TestSize.Level0)
{
    AccessTokenID tokenID = 123; // invalid tokenid
    uint32_t permCode;
    ASSERT_TRUE(TransferPermissionToOpcode("ohos.permission.CAMERA", permCode));
#ifdef SUPPORT_MANAGE_USER_POLICY
    auto& manager = UserPolicyManager::GetInstance();
    PolicyWhiteListStateGuard stateGuard(manager, permCode);
    stateGuard.SetControlledUser(USER_ID, GetSelfTokenID());
    EXPECT_TRUE(manager.IsPermissionRestricted(tokenID, USER_ID, permCode));
#else
    EXPECT_TRUE(tokenID != INVALID_TOKENID);
#endif
}

#ifdef SUPPORT_MANAGE_USER_POLICY
/**
 * @tc.name: UpdatePolicyWhiteList001
 * @tc.desc: UpdatePolicyWhiteList returns error when token user is outside controlled user list.
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(TokenInfoManagerTest, UpdatePolicyWhiteList001, TestSize.Level0)
{
    AccessTokenIDEx tokenIdEx = {0};
    std::vector<GenericValues> undefValues;
    ASSERT_EQ(RET_SUCCESS, AccessTokenInfoManager::GetInstance().CreateHapTokenInfo(
        g_infoManagerTestInfoParms, g_infoManagerTestPolicyPrams1, tokenIdEx, undefValues));
    AccessTokenID tokenId = tokenIdEx.tokenIdExStruct.tokenID;

    uint32_t permCode;
    ASSERT_TRUE(TransferPermissionToOpcode("ohos.permission.CAMERA", permCode));

    auto& manager = UserPolicyManager::GetInstance();
    PolicyWhiteListStateGuard stateGuard(manager, permCode);
    stateGuard.SetControlledUser(USER_ID, GetSelfTokenID());
    PolicyWhiteListUpdateInfo addContext {
        .tokenId = tokenId,
        .userId = g_infoManagerTestInfoParms.userID,
        .permCode = permCode,
        .type = UpdateWhiteListType::ADD,
        .callerToken = GetSelfTokenID()
    };
    PolicyWhiteListUpdateInfo deleteContext = addContext;
    deleteContext.type = UpdateWhiteListType::DELETE;

    EXPECT_EQ(ERR_TOKENID_NOT_IN_POLICY_USERLIST, manager.UpdatePolicyWhiteList(addContext));
    EXPECT_EQ(ERR_TOKENID_NOT_IN_POLICY_USERLIST,
        manager.UpdatePolicyWhiteList(deleteContext));

    std::vector<AccessTokenID> tokenIdList;
    EXPECT_EQ(RET_SUCCESS, manager.GetPolicyWhiteList(permCode, tokenIdList));
    EXPECT_TRUE(tokenIdList.empty());

    EXPECT_EQ(RET_SUCCESS, AccessTokenInfoManager::GetInstance().RemoveHapTokenInfo(tokenId));
}

/**
 * @tc.name: UpdatePolicyWhiteList002
 * @tc.desc: UpdatePolicyWhiteList returns error when permission policy is not set.
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(TokenInfoManagerTest, UpdatePolicyWhiteList002, TestSize.Level0)
{
    uint32_t permCode;
    ASSERT_TRUE(TransferPermissionToOpcode("ohos.permission.CAMERA", permCode));

    auto& manager = UserPolicyManager::GetInstance();
    PolicyWhiteListUpdateInfo context {
        .tokenId = INVALID_TOKENID,
        .userId = USER_ID,
        .permCode = permCode,
        .type = UpdateWhiteListType::ADD,
        .callerToken = GetSelfTokenID()
    };
    EXPECT_EQ(ERR_PERM_POLICY_NOT_SET,
        manager.UpdatePolicyWhiteList(context));
}

/**
 * @tc.name: UpdatePolicyWhiteList003
 * @tc.desc: UpdatePolicyWhiteList returns error when caller is not the policy controller.
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(TokenInfoManagerTest, UpdatePolicyWhiteList003, TestSize.Level0)
{
    uint32_t permCode;
    ASSERT_TRUE(TransferPermissionToOpcode("ohos.permission.CAMERA", permCode));

    auto& manager = UserPolicyManager::GetInstance();
    PolicyWhiteListStateGuard stateGuard(manager, permCode);
    AccessTokenID controllerToken = GetSelfTokenID();
    stateGuard.SetControlledUser(USER_ID, controllerToken);

    PolicyWhiteListUpdateInfo context {
        .tokenId = RANDOM_TOKENID,
        .userId = USER_ID,
        .permCode = permCode,
        .type = UpdateWhiteListType::ADD,
        .callerToken = controllerToken + 1
    };
    EXPECT_EQ(ERR_PERM_POLICY_ALREADY_SET_BY_OTHER, manager.UpdatePolicyWhiteList(context));

    std::vector<AccessTokenID> tokenIdList = {RANDOM_TOKENID};
    EXPECT_EQ(RET_SUCCESS, manager.GetPolicyWhiteList(permCode, tokenIdList));
    EXPECT_TRUE(tokenIdList.empty());
}

/**
 * @tc.name: GetPolicyWhiteList001
 * @tc.desc: GetPolicyWhiteList clears output list and returns error for invalid permCode.
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(TokenInfoManagerTest, GetPolicyWhiteList001, TestSize.Level0)
{
    auto& manager = UserPolicyManager::GetInstance();
    std::vector<AccessTokenID> tokenIdList = {RANDOM_TOKENID};

    EXPECT_EQ(ERR_PARAM_INVALID, manager.GetPolicyWhiteList(UINT32_MAX, tokenIdList));
    EXPECT_TRUE(tokenIdList.empty());
}

/**
 * @tc.name: GetPolicyWhiteList002
 * @tc.desc: GetPolicyWhiteList clears output list and returns empty list when policy is not set.
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(TokenInfoManagerTest, GetPolicyWhiteList002, TestSize.Level0)
{
    uint32_t permCode;
    ASSERT_TRUE(TransferPermissionToOpcode("ohos.permission.CAMERA", permCode));

    auto& manager = UserPolicyManager::GetInstance();
    PolicyWhiteListStateGuard stateGuard(manager, permCode);
    stateGuard.EraseRecord();
    std::vector<AccessTokenID> tokenIdList = {RANDOM_TOKENID};

    EXPECT_EQ(RET_SUCCESS, manager.GetPolicyWhiteList(permCode, tokenIdList));
    EXPECT_TRUE(tokenIdList.empty());
}

/**
 * @tc.name: GetPolicyWhiteList003
 * @tc.desc: GetPolicyWhiteList clears output list and returns empty list when policy exists without whitelist.
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(TokenInfoManagerTest, GetPolicyWhiteList003, TestSize.Level0)
{
    uint32_t permCode;
    ASSERT_TRUE(TransferPermissionToOpcode("ohos.permission.CAMERA", permCode));

    auto& manager = UserPolicyManager::GetInstance();
    PolicyWhiteListStateGuard stateGuard(manager, permCode);
    stateGuard.SetControlledUser(USER_ID, GetSelfTokenID());
    std::vector<AccessTokenID> tokenIdList = {RANDOM_TOKENID};

    EXPECT_EQ(RET_SUCCESS, manager.GetPolicyWhiteList(permCode, tokenIdList));
    EXPECT_TRUE(tokenIdList.empty());
}

/**
 * @tc.name: GetPolicyWhiteList004
 * @tc.desc: GetPolicyWhiteList returns current whitelist tokens without order dependency.
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(TokenInfoManagerTest, GetPolicyWhiteList004, TestSize.Level0)
{
    uint32_t permCode;
    ASSERT_TRUE(TransferPermissionToOpcode("ohos.permission.CAMERA", permCode));

    AccessTokenID tokenId1 = RANDOM_TOKENID;
    AccessTokenID tokenId2 = RANDOM_TOKENID + 1;
    auto& manager = UserPolicyManager::GetInstance();
    PolicyWhiteListStateGuard stateGuard(manager, permCode);
    stateGuard.SetWhiteList(USER_ID, GetSelfTokenID(), { tokenId1, tokenId2 });
    std::vector<AccessTokenID> tokenIdList;

    EXPECT_EQ(RET_SUCCESS, manager.GetPolicyWhiteList(permCode, tokenIdList));
    EXPECT_EQ(2u, tokenIdList.size());
    EXPECT_NE(tokenIdList.end(), std::find(tokenIdList.begin(), tokenIdList.end(), tokenId1));
    EXPECT_NE(tokenIdList.end(), std::find(tokenIdList.begin(), tokenIdList.end(), tokenId2));
}

/**
 * @tc.name: UpdateWhiteListRollback001
 * @tc.desc: UpdatePolicyWhiteList returns error when white list token is duplicated and state stays unchanged.
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(TokenInfoManagerTest, UpdateWhiteListRollback001, TestSize.Level0)
{
    uint32_t permCode;
    ASSERT_TRUE(TransferPermissionToOpcode("ohos.permission.CAMERA", permCode));

    auto& manager = UserPolicyManager::GetInstance();
    PolicyWhiteListStateGuard stateGuard(manager, permCode);
    AccessTokenID tokenId = RANDOM_TOKENID;
    stateGuard.SetWhiteList(USER_ID, GetSelfTokenID(), { tokenId });

    PolicyWhiteListUpdateInfo addContext {
        .tokenId = tokenId,
        .userId = USER_ID,
        .permCode = permCode,
        .type = UpdateWhiteListType::ADD,
        .callerToken = GetSelfTokenID()
    };
    PolicyWhiteListUpdateInfo deleteContext = addContext;
    deleteContext.tokenId = tokenId + 1;
    deleteContext.type = UpdateWhiteListType::DELETE;

    EXPECT_EQ(ERR_TOKENID_ALREADY_IN_POLICY_WHITELIST, manager.UpdatePolicyWhiteList(addContext));
    EXPECT_EQ(ERR_TOKENID_NOT_IN_POLICY_WHITELIST, manager.UpdatePolicyWhiteList(deleteContext));

    std::vector<AccessTokenID> tokenIdList;
    EXPECT_EQ(RET_SUCCESS, manager.GetPolicyWhiteList(permCode, tokenIdList));
    ASSERT_EQ(1u, tokenIdList.size());
    EXPECT_EQ(tokenId, tokenIdList[0]);
}

/**
 * @tc.name: UpdateWhiteListDbRollback001
 * @tc.desc: UpdatePolicyWhiteList keeps state unchanged when input is rejected.
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(TokenInfoManagerTest, UpdateWhiteListDbRollback001, TestSize.Level0)
{
    uint32_t permCode;
    ASSERT_TRUE(TransferPermissionToOpcode("ohos.permission.CAMERA", permCode));

    auto& manager = UserPolicyManager::GetInstance();
    PolicyWhiteListStateGuard stateGuard(manager, permCode);
    AccessTokenID tokenId = RANDOM_TOKENID;
    stateGuard.SetWhiteList(USER_ID, GetSelfTokenID(), { tokenId });

    PolicyWhiteListUpdateInfo addContext {
        .tokenId = tokenId,
        .userId = USER_ID,
        .permCode = permCode,
        .type = UpdateWhiteListType::ADD,
        .callerToken = GetSelfTokenID()
    };
    PolicyWhiteListUpdateInfo deleteContext = addContext;
    deleteContext.tokenId = tokenId + 1;
    deleteContext.type = UpdateWhiteListType::DELETE;

    EXPECT_EQ(ERR_TOKENID_ALREADY_IN_POLICY_WHITELIST, manager.UpdatePolicyWhiteList(addContext));
    EXPECT_EQ(ERR_TOKENID_NOT_IN_POLICY_WHITELIST, manager.UpdatePolicyWhiteList(deleteContext));

    std::vector<AccessTokenID> tokenIdList;
    EXPECT_EQ(RET_SUCCESS, manager.GetPolicyWhiteList(permCode, tokenIdList));
    ASSERT_EQ(1u, tokenIdList.size());
    EXPECT_EQ(tokenId, tokenIdList[0]);
}

/**
 * @tc.name: UpdateWhiteListMaxLimit001
 * @tc.desc: UpdatePolicyWhiteList rejects adding token when whitelist reaches max size.
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(TokenInfoManagerTest, UpdateWhiteListMaxLimit001, TestSize.Level0)
{
    uint32_t permCode;
    ASSERT_TRUE(TransferPermissionToOpcode("ohos.permission.CAMERA", permCode));

    auto& manager = UserPolicyManager::GetInstance();
    PolicyWhiteListStateGuard stateGuard(manager, permCode);
    std::unordered_set<AccessTokenID> whiteList;
    for (uint32_t index = 0; index < USER_POLICY_MAX_LIST_SIZE; ++index) {
        whiteList.insert(static_cast<AccessTokenID>(RANDOM_TOKENID + index));
    }
    AccessTokenID newTokenId = static_cast<AccessTokenID>(RANDOM_TOKENID + USER_POLICY_MAX_LIST_SIZE + 1);
    stateGuard.SetWhiteList(USER_ID, GetSelfTokenID(), whiteList);

    PolicyWhiteListUpdateInfo addContext {
        .tokenId = newTokenId,
        .userId = USER_ID,
        .permCode = permCode,
        .type = UpdateWhiteListType::ADD,
        .callerToken = GetSelfTokenID()
    };
    EXPECT_EQ(ERR_OVERSIZE, manager.UpdatePolicyWhiteList(addContext));

    std::vector<AccessTokenID> tokenIdList;
    EXPECT_EQ(RET_SUCCESS, manager.GetPolicyWhiteList(permCode, tokenIdList));
    EXPECT_EQ(USER_POLICY_MAX_LIST_SIZE, tokenIdList.size());
    EXPECT_EQ(tokenIdList.end(), std::find(tokenIdList.begin(), tokenIdList.end(), newTokenId));
}

/**
 * @tc.name: GetRestrictedPermListByUserId001
 * @tc.desc: GetRestrictedPermListByUserId returns permissions controlled for the specified user.
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(TokenInfoManagerTest, GetRestrictedPermListByUserId001, TestSize.Level0)
{
    uint32_t permCode;
    ASSERT_TRUE(TransferPermissionToOpcode("ohos.permission.CAMERA", permCode));

    auto& manager = UserPolicyManager::GetInstance();
    PolicyWhiteListStateGuard stateGuard(manager, permCode);
    stateGuard.SetControlledUser(USER_ID, GetSelfTokenID());

    std::vector<uint32_t> permCodeList = manager.GetRestrictedPermListByUserId(USER_ID);
    EXPECT_NE(std::find(permCodeList.begin(), permCodeList.end(), permCode), permCodeList.end());
    std::vector<uint32_t> otherUserPermCodeList = manager.GetRestrictedPermListByUserId(USER_ID + 1);
    EXPECT_EQ(std::find(otherUserPermCodeList.begin(), otherUserPermCodeList.end(), permCode),
        otherUserPermCodeList.end());
}

/**
 * @tc.name: UpdatePermissionStatusListForUserPolicy001
 * @tc.desc: UpdatePermissionStatusListForUserPolicy adds and removes restricted flag by user policy.
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(TokenInfoManagerTest, UpdatePermissionStatusListForUserPolicy001, TestSize.Level0)
{
    uint32_t permCode;
    ASSERT_TRUE(TransferPermissionToOpcode("ohos.permission.CAMERA", permCode));

    auto& manager = UserPolicyManager::GetInstance();
    PolicyWhiteListStateGuard stateGuard(manager, permCode);
    stateGuard.SetControlledUser(USER_ID, GetSelfTokenID());

    std::vector<PermissionStatus> permStateList = { g_permState };
    manager.UpdatePermissionStatusListForUserPolicy(RANDOM_TOKENID, USER_ID, permStateList);
    ASSERT_EQ(1u, permStateList.size());
    EXPECT_NE(0u, permStateList[0].grantFlag & PERMISSION_RESTRICTED_BY_ADMIN);

    manager.UpdatePermissionStatusListForUserPolicy(RANDOM_TOKENID, USER_ID + 1, permStateList);
    EXPECT_EQ(0u, permStateList[0].grantFlag & PERMISSION_RESTRICTED_BY_ADMIN);
}

/**
 * @tc.name: UpdatePermissionStatusListForUserPolicy002
 * @tc.desc: UpdatePermissionStatusListForUserPolicy skips invalid permission names and keeps whitelist tokens clear.
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(TokenInfoManagerTest, UpdatePermissionStatusListForUserPolicy002, TestSize.Level0)
{
    uint32_t permCode;
    ASSERT_TRUE(TransferPermissionToOpcode("ohos.permission.CAMERA", permCode));

    auto& manager = UserPolicyManager::GetInstance();
    PolicyWhiteListStateGuard stateGuard(manager, permCode);
    stateGuard.SetWhiteList(USER_ID, GetSelfTokenID(), { RANDOM_TOKENID });

    std::vector<PermissionStatus> permStateList = {
        {
            .permissionName = "invalid_permission_name",
            .grantStatus = PermissionState::PERMISSION_DENIED,
            .grantFlag = PERMISSION_RESTRICTED_BY_ADMIN
        },
        g_permState
    };
    manager.UpdatePermissionStatusListForUserPolicy(RANDOM_TOKENID, USER_ID, permStateList);
    ASSERT_EQ(2u, permStateList.size());
    EXPECT_NE(0u, permStateList[0].grantFlag & PERMISSION_RESTRICTED_BY_ADMIN);
    EXPECT_EQ(0u, permStateList[1].grantFlag & PERMISSION_RESTRICTED_BY_ADMIN);
    EXPECT_FALSE(manager.IsPermissionRestricted(RANDOM_TOKENID, USER_ID, permCode));
}

/**
 * @tc.name: SetUserPolicyPersistDb001
 * @tc.desc: SetUserPolicy with isPersist=true writes policy to user_policy_table.
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(TokenInfoManagerTest, SetUserPolicyPersistDb001, TestSize.Level0)
{
    const std::string permissionName = "ohos.permission.CAMERA";
    uint32_t permCode;
    ASSERT_TRUE(TransferPermissionToOpcode(permissionName, permCode));
    auto& manager = UserPolicyManager::GetInstance();
    PolicyWhiteListStateGuard stateGuard(manager, permCode);
    stateGuard.EraseRecord();
    EXPECT_EQ(RET_SUCCESS, DeleteUserPolicyDbRecord(permissionName));

    HapInfoParams info = {
        .userID = USER_ID,
        .bundleName = "set_user_policy_persist_db_001",
        .instIndex = INST_INDEX,
        .appIDDesc = "set_user_policy_persist_db_001"
    };
    HapPolicy hapPolicy = {
        .apl = APL_NORMAL,
        .domain = "domain",
        .permStateList = { g_permState }
    };
    AccessTokenIDEx tokenIdEx = {0};
    std::vector<GenericValues> undefValues;
    ASSERT_EQ(RET_SUCCESS,
        AccessTokenInfoManager::GetInstance().CreateHapTokenInfo(info, hapPolicy, tokenIdEx, undefValues));
    AccessTokenID tokenId = tokenIdEx.tokenIdExStruct.tokenID;
    const uint32_t initFlag = PermissionFlag::PERMISSION_DEFAULT_FLAG;
    const uint32_t restrictedFlag = initFlag | PERMISSION_RESTRICTED_BY_ADMIN;
    ExpectCacheAndDbPermissionState(tokenId, permCode, permissionName, PermissionState::PERMISSION_DENIED,
        initFlag, initFlag);

    UserPermissionPolicy policy = {
        .permissionName = permissionName,
        .userPolicyList = {{ .userId = USER_ID, .isRestricted = true }},
        .isPersist = true
    };
    std::vector<UserPolicyChange> userPolicyList;
    EXPECT_EQ(RET_SUCCESS, manager.SetUserPolicy({ policy }, GetSelfTokenID(), userPolicyList));
    EXPECT_TRUE(manager.IsPolicyPersisted(permCode));

    ExpectUserPolicyDbRecord(permissionName, GetSelfTokenID(), std::to_string(USER_ID));

    bool hasFlagChanged = false;
    EXPECT_EQ(RET_SUCCESS,
        AccessTokenInfoManager::GetInstance().UpdateRestrictedFlag(tokenId, permCode, true, policy.isPersist,
            hasFlagChanged));
    EXPECT_TRUE(hasFlagChanged);
    ExpectCacheAndDbPermissionState(tokenId, permCode, permissionName, PermissionState::PERMISSION_DENIED,
        restrictedFlag, restrictedFlag);

    EXPECT_EQ(RET_SUCCESS,
        AccessTokenInfoManager::GetInstance().UpdateRestrictedFlag(tokenId, permCode, false, policy.isPersist,
            hasFlagChanged));
    EXPECT_EQ(RET_SUCCESS, manager.ClearUserPolicy({ permissionName }, GetSelfTokenID(), userPolicyList));
    EXPECT_EQ(RET_SUCCESS, AccessTokenInfoManager::GetInstance().RemoveHapTokenInfo(tokenId));
}

/**
 * @tc.name: SetUserPolicyPersistDb002
 * @tc.desc: SetUserPolicy with isPersist=false updates cache only and does not write user_policy_table.
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(TokenInfoManagerTest, SetUserPolicyPersistDb002, TestSize.Level0)
{
    const std::string permissionName = "ohos.permission.CAMERA";
    uint32_t permCode;
    ASSERT_TRUE(TransferPermissionToOpcode(permissionName, permCode));
    auto& manager = UserPolicyManager::GetInstance();
    PolicyWhiteListStateGuard stateGuard(manager, permCode);
    stateGuard.EraseRecord();
    EXPECT_EQ(RET_SUCCESS, DeleteUserPolicyDbRecord(permissionName));

    HapInfoParams info = {
        .userID = USER_ID,
        .bundleName = "set_user_policy_persist_db_002",
        .instIndex = INST_INDEX,
        .appIDDesc = "set_user_policy_persist_db_002"
    };
    HapPolicy hapPolicy = {
        .apl = APL_NORMAL,
        .domain = "domain",
        .permStateList = { g_permState }
    };
    AccessTokenIDEx tokenIdEx = {0};
    std::vector<GenericValues> undefValues;
    ASSERT_EQ(RET_SUCCESS,
        AccessTokenInfoManager::GetInstance().CreateHapTokenInfo(info, hapPolicy, tokenIdEx, undefValues));
    AccessTokenID tokenId = tokenIdEx.tokenIdExStruct.tokenID;
    const uint32_t initFlag = PermissionFlag::PERMISSION_DEFAULT_FLAG;
    const uint32_t restrictedFlag = initFlag | PERMISSION_RESTRICTED_BY_ADMIN;
    ExpectCacheAndDbPermissionState(tokenId, permCode, permissionName, PermissionState::PERMISSION_DENIED,
        initFlag, initFlag);

    UserPermissionPolicy policy = {
        .permissionName = permissionName,
        .userPolicyList = {{ .userId = USER_ID, .isRestricted = true }},
        .isPersist = false
    };
    std::vector<UserPolicyChange> userPolicyList;
    EXPECT_EQ(RET_SUCCESS, manager.SetUserPolicy({ policy }, GetSelfTokenID(), userPolicyList));
    EXPECT_FALSE(manager.IsPolicyPersisted(permCode));

    ExpectNoUserPolicyDbRecord(permissionName);
    EXPECT_TRUE(manager.IsPermissionRestricted(RANDOM_TOKENID, USER_ID, permCode));

    bool hasFlagChanged = false;
    EXPECT_EQ(RET_SUCCESS,
        AccessTokenInfoManager::GetInstance().UpdateRestrictedFlag(tokenId, permCode, true, policy.isPersist,
            hasFlagChanged));
    EXPECT_TRUE(hasFlagChanged);
    ExpectCacheAndDbPermissionState(tokenId, permCode, permissionName, PermissionState::PERMISSION_DENIED,
        restrictedFlag, initFlag);

    EXPECT_EQ(RET_SUCCESS,
        AccessTokenInfoManager::GetInstance().UpdateRestrictedFlag(tokenId, permCode, false, policy.isPersist,
            hasFlagChanged));
    EXPECT_EQ(RET_SUCCESS, manager.ClearUserPolicy({ permissionName }, GetSelfTokenID(), userPolicyList));
    EXPECT_EQ(RET_SUCCESS, AccessTokenInfoManager::GetInstance().RemoveHapTokenInfo(tokenId));
}

#ifdef SUPPORT_MANAGE_USER_POLICY
/**
 * @tc.name: SetUserPolicyPersistDbUpdate001
 * @tc.desc: SetUserPolicy with isPersist=true rewrites user_policy_table with the next user list.
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(TokenInfoManagerTest, SetUserPolicyPersistDbUpdate001, TestSize.Level0)
{
    const std::string permissionName = "ohos.permission.CAMERA";
    const int32_t otherUserId = USER_ID + 1;
    uint32_t permCode;
    ASSERT_TRUE(TransferPermissionToOpcode(permissionName, permCode));
    auto& manager = UserPolicyManager::GetInstance();
    PolicyWhiteListStateGuard stateGuard(manager, permCode);
    stateGuard.EraseRecord();
    EXPECT_EQ(RET_SUCCESS, DeleteUserPolicyDbRecord(permissionName));

    UserPermissionPolicy policy = {
        .permissionName = permissionName,
        .userPolicyList = {{ .userId = USER_ID, .isRestricted = true }},
        .isPersist = true
    };
    std::vector<UserPolicyChange> userPolicyList;
    EXPECT_EQ(RET_SUCCESS, manager.SetUserPolicy({ policy }, GetSelfTokenID(), userPolicyList));
    ExpectUserPolicyDbRecord(permissionName, GetSelfTokenID(), std::to_string(USER_ID));

    policy.userPolicyList = {{ .userId = otherUserId, .isRestricted = true }};
    EXPECT_EQ(RET_SUCCESS, manager.SetUserPolicy({ policy }, GetSelfTokenID(), userPolicyList));
    ExpectUserPolicyDbRecord(permissionName, GetSelfTokenID(),
        std::to_string(USER_ID) + "," + std::to_string(otherUserId));

    policy.userPolicyList = {{ .userId = USER_ID, .isRestricted = false }};
    EXPECT_EQ(RET_SUCCESS, manager.SetUserPolicy({ policy }, GetSelfTokenID(), userPolicyList));
    ExpectUserPolicyDbRecord(permissionName, GetSelfTokenID(), std::to_string(otherUserId));

    EXPECT_EQ(RET_SUCCESS, manager.ClearUserPolicy({ permissionName }, GetSelfTokenID(), userPolicyList));
}

/**
 * @tc.name: SetUserPolicyPersistDbRemove001
 * @tc.desc: SetUserPolicy deletes user_policy_table row when the next user list is empty.
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(TokenInfoManagerTest, SetUserPolicyPersistDbRemove001, TestSize.Level0)
{
    const std::string permissionName = "ohos.permission.CAMERA";
    uint32_t permCode;
    ASSERT_TRUE(TransferPermissionToOpcode(permissionName, permCode));
    auto& manager = UserPolicyManager::GetInstance();
    PolicyWhiteListStateGuard stateGuard(manager, permCode);
    stateGuard.EraseRecord();
    EXPECT_EQ(RET_SUCCESS, DeleteUserPolicyDbRecord(permissionName));

    UserPermissionPolicy policy = {
        .permissionName = permissionName,
        .userPolicyList = {{ .userId = USER_ID, .isRestricted = true }},
        .isPersist = true
    };
    std::vector<UserPolicyChange> userPolicyList;
    EXPECT_EQ(RET_SUCCESS, manager.SetUserPolicy({ policy }, GetSelfTokenID(), userPolicyList));
    ExpectUserPolicyDbRecord(permissionName, GetSelfTokenID(), std::to_string(USER_ID));

    policy.userPolicyList = {{ .userId = USER_ID, .isRestricted = false }};
    EXPECT_EQ(RET_SUCCESS, manager.SetUserPolicy({ policy }, GetSelfTokenID(), userPolicyList));
    ExpectNoUserPolicyDbRecord(permissionName);
    EXPECT_EQ(ERR_PERM_POLICY_NOT_SET, manager.ClearUserPolicy({ permissionName }, GetSelfTokenID(), userPolicyList));
}
#endif

/**
 * @tc.name: UpdateWhiteListPersistDb001
 * @tc.desc: UpdatePolicyWhiteList under persisted policy updates whitelist cache and DB.
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(TokenInfoManagerTest, UpdateWhiteListPersistDb001, TestSize.Level0)
{
    const std::string permissionName = "ohos.permission.CAMERA";
    uint32_t permCode;
    ASSERT_TRUE(TransferPermissionToOpcode(permissionName, permCode));
    auto& manager = UserPolicyManager::GetInstance();
    PolicyWhiteListStateGuard stateGuard(manager, permCode);
    stateGuard.EraseRecord();
    EXPECT_EQ(RET_SUCCESS, DeleteUserPolicyDbRecord(permissionName));

    HapInfoParams info = {
        .userID = USER_ID,
        .bundleName = "update_white_list_persist_db_001",
        .instIndex = INST_INDEX,
        .appIDDesc = "update_white_list_persist_db_001"
    };
    HapPolicy hapPolicy = {
        .apl = APL_NORMAL,
        .domain = "domain",
        .permStateList = { g_permState }
    };
    AccessTokenIDEx tokenIdEx = {0};
    std::vector<GenericValues> undefValues;
    ASSERT_EQ(RET_SUCCESS,
        AccessTokenInfoManager::GetInstance().CreateHapTokenInfo(info, hapPolicy, tokenIdEx, undefValues));
    AccessTokenID tokenId = tokenIdEx.tokenIdExStruct.tokenID;
    const uint32_t initFlag = PermissionFlag::PERMISSION_DEFAULT_FLAG;
    const uint32_t restrictedFlag = initFlag | PERMISSION_RESTRICTED_BY_ADMIN;

    UserPermissionPolicy policy = {
        .permissionName = permissionName,
        .userPolicyList = {{ .userId = USER_ID, .isRestricted = true }},
        .isPersist = true
    };
    std::vector<UserPolicyChange> userPolicyList;
    EXPECT_EQ(RET_SUCCESS, manager.SetUserPolicy({ policy }, GetSelfTokenID(), userPolicyList));
    ExpectUserPolicyDbRecord(permissionName, GetSelfTokenID(), std::to_string(USER_ID));
    ExpectUserPolicyDbWhiteList(permissionName, "");

    bool hasFlagChanged = false;
    EXPECT_EQ(RET_SUCCESS,
        AccessTokenInfoManager::GetInstance().UpdateRestrictedFlag(tokenId, permCode, true, policy.isPersist,
            hasFlagChanged));
    ExpectCacheAndDbPermissionState(tokenId, permCode, permissionName, PermissionState::PERMISSION_DENIED,
        restrictedFlag, restrictedFlag);

    PolicyWhiteListUpdateInfo addContext {
        .tokenId = tokenId,
        .userId = USER_ID,
        .permCode = permCode,
        .type = UpdateWhiteListType::ADD,
        .callerToken = GetSelfTokenID()
    };
    EXPECT_EQ(RET_SUCCESS, manager.UpdatePolicyWhiteList(addContext));
    EXPECT_EQ(RET_SUCCESS,
        AccessTokenInfoManager::GetInstance().UpdateRestrictedFlag(tokenId, permCode, false, policy.isPersist,
            hasFlagChanged));
    std::vector<AccessTokenID> tokenIdList;
    EXPECT_EQ(RET_SUCCESS, manager.GetPolicyWhiteList(permCode, tokenIdList));
    ASSERT_EQ(1u, tokenIdList.size());
    EXPECT_EQ(tokenId, tokenIdList[0]);
    ExpectUserPolicyDbWhiteList(permissionName, std::to_string(tokenId));
    ExpectCacheAndDbPermissionState(tokenId, permCode, permissionName, PermissionState::PERMISSION_DENIED,
        initFlag, initFlag);

    PolicyWhiteListUpdateInfo deleteContext = addContext;
    deleteContext.type = UpdateWhiteListType::DELETE;
    EXPECT_EQ(RET_SUCCESS, manager.UpdatePolicyWhiteList(deleteContext));
    EXPECT_EQ(RET_SUCCESS,
        AccessTokenInfoManager::GetInstance().UpdateRestrictedFlag(tokenId, permCode, true, policy.isPersist,
            hasFlagChanged));
    tokenIdList = { tokenId };
    EXPECT_EQ(RET_SUCCESS, manager.GetPolicyWhiteList(permCode, tokenIdList));
    EXPECT_TRUE(tokenIdList.empty());
    ExpectUserPolicyDbWhiteList(permissionName, "");
    ExpectCacheAndDbPermissionState(tokenId, permCode, permissionName, PermissionState::PERMISSION_DENIED,
        restrictedFlag, restrictedFlag);

    EXPECT_EQ(RET_SUCCESS,
        AccessTokenInfoManager::GetInstance().UpdateRestrictedFlag(tokenId, permCode, false, policy.isPersist,
            hasFlagChanged));
    EXPECT_EQ(RET_SUCCESS, manager.ClearUserPolicy({ permissionName }, GetSelfTokenID(), userPolicyList));
    EXPECT_EQ(RET_SUCCESS, AccessTokenInfoManager::GetInstance().RemoveHapTokenInfo(tokenId));
}

/**
 * @tc.name: UpdateWhiteListNonPersistDb001
 * @tc.desc: UpdatePolicyWhiteList under non-persisted policy updates cache only and does not write DB.
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(TokenInfoManagerTest, UpdateWhiteListNonPersistDb001, TestSize.Level0)
{
    const std::string permissionName = "ohos.permission.CAMERA";
    uint32_t permCode;
    ASSERT_TRUE(TransferPermissionToOpcode(permissionName, permCode));
    auto& manager = UserPolicyManager::GetInstance();
    PolicyWhiteListStateGuard stateGuard(manager, permCode);
    stateGuard.EraseRecord();
    EXPECT_EQ(RET_SUCCESS, DeleteUserPolicyDbRecord(permissionName));

    HapInfoParams info = {
        .userID = USER_ID,
        .bundleName = "update_white_list_non_persist_db_001",
        .instIndex = INST_INDEX,
        .appIDDesc = "update_white_list_non_persist_db_001"
    };
    HapPolicy hapPolicy = {
        .apl = APL_NORMAL,
        .domain = "domain",
        .permStateList = { g_permState }
    };
    AccessTokenIDEx tokenIdEx = {0};
    std::vector<GenericValues> undefValues;
    ASSERT_EQ(RET_SUCCESS,
        AccessTokenInfoManager::GetInstance().CreateHapTokenInfo(info, hapPolicy, tokenIdEx, undefValues));
    AccessTokenID tokenId = tokenIdEx.tokenIdExStruct.tokenID;
    const uint32_t initFlag = PermissionFlag::PERMISSION_DEFAULT_FLAG;
    const uint32_t restrictedFlag = initFlag | PERMISSION_RESTRICTED_BY_ADMIN;

    UserPermissionPolicy policy = {
        .permissionName = permissionName,
        .userPolicyList = {{ .userId = USER_ID, .isRestricted = true }},
        .isPersist = false
    };
    std::vector<UserPolicyChange> userPolicyList;
    EXPECT_EQ(RET_SUCCESS, manager.SetUserPolicy({ policy }, GetSelfTokenID(), userPolicyList));
    EXPECT_FALSE(manager.IsPolicyPersisted(permCode));
    ExpectNoUserPolicyDbRecord(permissionName);

    bool hasFlagChanged = false;
    EXPECT_EQ(RET_SUCCESS,
        AccessTokenInfoManager::GetInstance().UpdateRestrictedFlag(tokenId, permCode, true, policy.isPersist,
            hasFlagChanged));
    ExpectCacheAndDbPermissionState(tokenId, permCode, permissionName, PermissionState::PERMISSION_DENIED,
        restrictedFlag, initFlag);

    PolicyWhiteListUpdateInfo addContext {
        .tokenId = tokenId,
        .userId = USER_ID,
        .permCode = permCode,
        .type = UpdateWhiteListType::ADD,
        .callerToken = GetSelfTokenID()
    };
    EXPECT_EQ(RET_SUCCESS, manager.UpdatePolicyWhiteList(addContext));
    EXPECT_EQ(RET_SUCCESS,
        AccessTokenInfoManager::GetInstance().UpdateRestrictedFlag(tokenId, permCode, false, policy.isPersist,
            hasFlagChanged));
    std::vector<AccessTokenID> tokenIdList;
    EXPECT_EQ(RET_SUCCESS, manager.GetPolicyWhiteList(permCode, tokenIdList));
    ASSERT_EQ(1u, tokenIdList.size());
    EXPECT_EQ(tokenId, tokenIdList[0]);
    ExpectNoUserPolicyDbRecord(permissionName);
    ExpectCacheAndDbPermissionState(tokenId, permCode, permissionName, PermissionState::PERMISSION_DENIED,
        initFlag, initFlag);

    PolicyWhiteListUpdateInfo deleteContext = addContext;
    deleteContext.type = UpdateWhiteListType::DELETE;
    EXPECT_EQ(RET_SUCCESS, manager.UpdatePolicyWhiteList(deleteContext));
    EXPECT_EQ(RET_SUCCESS,
        AccessTokenInfoManager::GetInstance().UpdateRestrictedFlag(tokenId, permCode, true, policy.isPersist,
            hasFlagChanged));
    tokenIdList = { tokenId };
    EXPECT_EQ(RET_SUCCESS, manager.GetPolicyWhiteList(permCode, tokenIdList));
    EXPECT_TRUE(tokenIdList.empty());
    ExpectNoUserPolicyDbRecord(permissionName);
    ExpectCacheAndDbPermissionState(tokenId, permCode, permissionName, PermissionState::PERMISSION_DENIED,
        restrictedFlag, initFlag);

    EXPECT_EQ(RET_SUCCESS,
        AccessTokenInfoManager::GetInstance().UpdateRestrictedFlag(tokenId, permCode, false, policy.isPersist,
            hasFlagChanged));
    EXPECT_EQ(RET_SUCCESS, manager.ClearUserPolicy({ permissionName }, GetSelfTokenID(), userPolicyList));
    EXPECT_EQ(RET_SUCCESS, AccessTokenInfoManager::GetInstance().RemoveHapTokenInfo(tokenId));
}

/**
 * @tc.name: RemoveTokenFromPolicyWhiteList001
 * @tc.desc: RemoveTokenFromPolicyWhiteList keeps whitelist cache and persisted DB without invalid token.
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(TokenInfoManagerTest, RemoveTokenFromPolicyWhiteList001, TestSize.Level0)
{
    const std::string permissionName = "ohos.permission.CAMERA";
    uint32_t permCode;
    ASSERT_TRUE(TransferPermissionToOpcode(permissionName, permCode));
    auto& manager = UserPolicyManager::GetInstance();
    PolicyWhiteListStateGuard stateGuard(manager, permCode);
    stateGuard.EraseRecord();
    EXPECT_EQ(RET_SUCCESS, DeleteUserPolicyDbRecord(permissionName));

    AccessTokenID removedToken = RANDOM_TOKENID;
    AccessTokenID keptToken = RANDOM_TOKENID + 1;
    UserPolicyRecord persistedRecord;
    persistedRecord.userList = { USER_ID };
    persistedRecord.controllerToken = GetSelfTokenID();
    persistedRecord.whiteList = { removedToken, keptToken };
    persistedRecord.isPersist = true;

    AddInfo addInfo;
    addInfo.addType = AtmDataType::ACCESSTOKEN_USER_POLICY;
    GenericValues addValue;
    addValue.Put(TokenFiledConst::FIELD_PERMISSION_NAME, permissionName);
    addValue.Put(TokenFiledConst::FIELD_CONTROLLER_TOKENID, static_cast<int32_t>(persistedRecord.controllerToken));
    addValue.Put(TokenFiledConst::FIELD_RESTRICTED_USER, std::to_string(USER_ID));
    addValue.Put(TokenFiledConst::FIELD_WHITELIST, std::to_string(keptToken) + "," + std::to_string(removedToken));
    addInfo.addValues.emplace_back(addValue);
    EXPECT_EQ(RET_SUCCESS, AccessTokenDb::GetInstance()->DeleteAndInsertValues({}, { addInfo }));
    stateGuard.SetWhiteList(USER_ID, GetSelfTokenID(), persistedRecord.whiteList, true);

    EXPECT_EQ(RET_SUCCESS, manager.RemoveTokenFromPolicyWhiteList(removedToken));

    std::vector<AccessTokenID> tokenIdList;
    EXPECT_EQ(RET_SUCCESS, manager.GetPolicyWhiteList(permCode, tokenIdList));
    ASSERT_EQ(1u, tokenIdList.size());
    EXPECT_EQ(keptToken, tokenIdList[0]);
    ExpectUserPolicyDbWhiteList(permissionName, std::to_string(keptToken));

    EXPECT_EQ(RET_SUCCESS, manager.RemoveTokenFromPolicyWhiteList(removedToken));
    tokenIdList.clear();
    EXPECT_EQ(RET_SUCCESS, manager.GetPolicyWhiteList(permCode, tokenIdList));
    ASSERT_EQ(1u, tokenIdList.size());
    EXPECT_EQ(keptToken, tokenIdList[0]);
    ExpectUserPolicyDbWhiteList(permissionName, std::to_string(keptToken));

    EXPECT_EQ(RET_SUCCESS, DeleteUserPolicyDbRecord(permissionName));
}

/**
 * @tc.name: RemoveTokenFromPolicyWhiteList002
 * @tc.desc: RemoveTokenFromPolicyWhiteList updates non-persisted cache only.
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(TokenInfoManagerTest, RemoveTokenFromPolicyWhiteList002, TestSize.Level0)
{
    const std::string permissionName = "ohos.permission.CAMERA";
    uint32_t permCode;
    ASSERT_TRUE(TransferPermissionToOpcode(permissionName, permCode));
    auto& manager = UserPolicyManager::GetInstance();
    PolicyWhiteListStateGuard stateGuard(manager, permCode);
    EXPECT_EQ(RET_SUCCESS, DeleteUserPolicyDbRecord(permissionName));

    AccessTokenID removedToken = RANDOM_TOKENID;
    AccessTokenID keptToken = RANDOM_TOKENID + 1;
    stateGuard.SetWhiteList(USER_ID, GetSelfTokenID(), { removedToken, keptToken }, false);

    EXPECT_EQ(RET_SUCCESS, manager.RemoveTokenFromPolicyWhiteList(removedToken));

    std::vector<AccessTokenID> tokenIdList;
    EXPECT_EQ(RET_SUCCESS, manager.GetPolicyWhiteList(permCode, tokenIdList));
    ASSERT_EQ(1u, tokenIdList.size());
    EXPECT_EQ(keptToken, tokenIdList[0]);
    ExpectNoUserPolicyDbRecord(permissionName);
}

#ifdef SUPPORT_MANAGE_USER_POLICY
/**
 * @tc.name: SetUserPolicyDbRollback001
 * @tc.desc: SetUserPolicy keeps state unchanged when a batch item is invalid.
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(TokenInfoManagerTest, SetUserPolicyDbRollback001, TestSize.Level0)
{
    uint32_t permCode;
    ASSERT_TRUE(TransferPermissionToOpcode("ohos.permission.CAMERA", permCode));
    auto& manager = UserPolicyManager::GetInstance();
    PolicyWhiteListStateGuard stateGuard(manager, permCode);
    stateGuard.EraseRecord();

    UserPermissionPolicy validPolicy = {
        .permissionName = "ohos.permission.CAMERA",
        .userPolicyList = {{ .userId = USER_ID, .isRestricted = true }},
        .isPersist = true
    };
    UserPermissionPolicy invalidPolicy = {
        .permissionName = "ohos.permission.CAMERA",
        .userPolicyList = {{ .userId = -1, .isRestricted = true }},
        .isPersist = true
    };
    std::vector<UserPolicyChange> userPolicyList;
    EXPECT_EQ(RET_SUCCESS, manager.SetUserPolicy({ validPolicy }, GetSelfTokenID(), userPolicyList));
    EXPECT_EQ(ERR_PARAM_INVALID, manager.SetUserPolicy({ invalidPolicy }, GetSelfTokenID(), userPolicyList));
    std::vector<AccessTokenID> tokenIdList;
    EXPECT_EQ(RET_SUCCESS, manager.GetPolicyWhiteList(permCode, tokenIdList));
    EXPECT_TRUE(tokenIdList.empty());
    EXPECT_EQ(RET_SUCCESS, manager.ClearUserPolicy({ "ohos.permission.CAMERA" }, GetSelfTokenID(), userPolicyList));
}

/**
 * @tc.name: SetUserPolicyInvalidPermission001
 * @tc.desc: SetUserPolicy rejects unknown permission and unsupported APL permission.
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(TokenInfoManagerTest, SetUserPolicyInvalidPermission001, TestSize.Level0)
{
    auto& manager = UserPolicyManager::GetInstance();
    std::vector<UserPolicyChange> userPolicyList = {{ .permCode = 1 }};
    UserPermissionPolicy unknownPermissionPolicy = {
        .permissionName = "ohos.permission.TEST_INVALID_USER_POLICY",
        .userPolicyList = {{ .userId = USER_ID, .isRestricted = true }},
        .isPersist = false
    };
    EXPECT_EQ(ERR_PARAM_INVALID,
        manager.SetUserPolicy({ unknownPermissionPolicy }, GetSelfTokenID(), userPolicyList));
    EXPECT_TRUE(userPolicyList.empty());

    UserPermissionPolicy corePermissionPolicy = {
        .permissionName = "ohos.permission.CONNECT_CRYPTO_EXTENSION",
        .userPolicyList = {{ .userId = USER_ID, .isRestricted = true }},
        .isPersist = false
    };
    EXPECT_EQ(ERR_PARAM_INVALID,
        manager.SetUserPolicy({ corePermissionPolicy }, GetSelfTokenID(), userPolicyList));
    EXPECT_TRUE(userPolicyList.empty());
}

/**
 * @tc.name: SetUserPolicyEmptyUserList001
 * @tc.desc: SetUserPolicy rejects policy with empty userPolicyList.
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(TokenInfoManagerTest, SetUserPolicyEmptyUserList001, TestSize.Level0)
{
    auto& manager = UserPolicyManager::GetInstance();
    std::vector<UserPolicyChange> userPolicyList = {{ .permCode = 1 }};
    UserPermissionPolicy policy = {
        .permissionName = "ohos.permission.CAMERA",
        .userPolicyList = {},
        .isPersist = false
    };
    EXPECT_EQ(ERR_PARAM_INVALID, manager.SetUserPolicy({ policy }, GetSelfTokenID(), userPolicyList));
    EXPECT_TRUE(userPolicyList.empty());
}

/**
 * @tc.name: SetUserPolicyNoChange001
 * @tc.desc: SetUserPolicy succeeds without cache or changed-list updates when requested state is unchanged.
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(TokenInfoManagerTest, SetUserPolicyNoChange001, TestSize.Level0)
{
    uint32_t permCode;
    ASSERT_TRUE(TransferPermissionToOpcode("ohos.permission.CAMERA", permCode));
    auto& manager = UserPolicyManager::GetInstance();
    PolicyWhiteListStateGuard stateGuard(manager, permCode);
    stateGuard.SetControlledUser(USER_ID, GetSelfTokenID());

    UserPermissionPolicy policy = {
        .permissionName = "ohos.permission.CAMERA",
        .userPolicyList = {{ .userId = USER_ID, .isRestricted = true }},
        .isPersist = false
    };
    std::vector<UserPolicyChange> userPolicyList = {{ .permCode = permCode }};
    EXPECT_EQ(RET_SUCCESS, manager.SetUserPolicy({ policy }, GetSelfTokenID(), userPolicyList));
    EXPECT_TRUE(userPolicyList.empty());
    EXPECT_TRUE(manager.IsPermissionRestricted(RANDOM_TOKENID, USER_ID, permCode));
}

/**
 * @tc.name: SetUserPolicyDuplicatePermission001
 * @tc.desc: SetUserPolicy rejects duplicate permissions in one batch.
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(TokenInfoManagerTest, SetUserPolicyDuplicatePermission001, TestSize.Level0)
{
    constexpr int32_t otherUserId = USER_ID + 1;
    uint32_t permCode;
    ASSERT_TRUE(TransferPermissionToOpcode("ohos.permission.CAMERA", permCode));
    auto& manager = UserPolicyManager::GetInstance();
    PolicyWhiteListStateGuard stateGuard(manager, permCode);
    stateGuard.EraseRecord();

    UserPermissionPolicy policy = {
        .permissionName = "ohos.permission.CAMERA",
        .userPolicyList = {{ .userId = USER_ID, .isRestricted = true }},
        .isPersist = true
    };
    UserPermissionPolicy duplicatedPolicy = {
        .permissionName = "ohos.permission.CAMERA",
        .userPolicyList = {{ .userId = otherUserId, .isRestricted = true }},
        .isPersist = true
    };
    std::vector<UserPolicyChange> userPolicyList;
    EXPECT_EQ(ERR_PARAM_INVALID, manager.SetUserPolicy({ policy, duplicatedPolicy }, GetSelfTokenID(),
        userPolicyList));
    EXPECT_FALSE(manager.IsPermissionRestricted(RANDOM_TOKENID, USER_ID, permCode));
    EXPECT_FALSE(manager.IsPermissionRestricted(RANDOM_TOKENID, otherUserId, permCode));
}

/**
 * @tc.name: SetUserPolicyCacheMaxLimit001
 * @tc.desc: SetUserPolicy rejects adding a new policy when policy cache reaches max size.
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(TokenInfoManagerTest, SetUserPolicyCacheMaxLimit001, TestSize.Level0)
{
    uint32_t permCode;
    ASSERT_TRUE(TransferPermissionToOpcode("ohos.permission.CAMERA", permCode));
    auto& manager = UserPolicyManager::GetInstance();
    UserPolicyRecordsGuard recordsGuard(manager);
    {
        std::unique_lock<std::shared_mutex> lock(manager.userPolicyLock_);
        manager.userPolicyRecords_.clear();
        for (uint32_t fakePermCode = 1; manager.userPolicyRecords_.size() < USER_POLICY_MAX_LIST_SIZE;
            ++fakePermCode) {
            if (fakePermCode == permCode) {
                continue;
            }
            UserPolicyRecord record;
            record.userList = { USER_ID };
            record.controllerToken = GetSelfTokenID();
            record.isPersist = false;
            manager.userPolicyRecords_[fakePermCode] = record;
        }
    }

    UserPermissionPolicy policy = {
        .permissionName = "ohos.permission.CAMERA",
        .userPolicyList = {{ .userId = USER_ID, .isRestricted = true }},
        .isPersist = false
    };
    std::vector<UserPolicyChange> userPolicyList;
    EXPECT_EQ(ERR_OVERSIZE, manager.SetUserPolicy({ policy }, GetSelfTokenID(), userPolicyList));
    EXPECT_TRUE(userPolicyList.empty());
    std::shared_lock<std::shared_mutex> lock(manager.userPolicyLock_);
    EXPECT_EQ(manager.userPolicyRecords_.end(), manager.userPolicyRecords_.find(permCode));
}

/**
 * @tc.name: SetUserPolicyUserListMaxLimit001
 * @tc.desc: SetUserPolicy rejects adding user when one policy user list reaches max size.
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(TokenInfoManagerTest, SetUserPolicyUserListMaxLimit001, TestSize.Level0)
{
    uint32_t permCode;
    ASSERT_TRUE(TransferPermissionToOpcode("ohos.permission.CAMERA", permCode));
    auto& manager = UserPolicyManager::GetInstance();
    PolicyWhiteListStateGuard stateGuard(manager, permCode);
    {
        std::unique_lock<std::shared_mutex> lock(manager.userPolicyLock_);
        auto& record = manager.userPolicyRecords_[permCode];
        record.userList.clear();
        for (uint32_t index = 0; index < USER_POLICY_MAX_LIST_SIZE; ++index) {
            record.userList.emplace_back(static_cast<int32_t>(index));
        }
        record.controllerToken = GetSelfTokenID();
        record.isPersist = false;
        record.whiteList.clear();
    }

    UserPermissionPolicy policy = {
        .permissionName = "ohos.permission.CAMERA",
        .userPolicyList = {{ .userId = static_cast<int32_t>(USER_POLICY_MAX_LIST_SIZE), .isRestricted = true }},
        .isPersist = false
    };
    std::vector<UserPolicyChange> userPolicyList;
    EXPECT_EQ(ERR_OVERSIZE, manager.SetUserPolicy({ policy }, GetSelfTokenID(), userPolicyList));
    EXPECT_TRUE(userPolicyList.empty());

    std::shared_lock<std::shared_mutex> lock(manager.userPolicyLock_);
    auto recordIter = manager.userPolicyRecords_.find(permCode);
    ASSERT_NE(manager.userPolicyRecords_.end(), recordIter);
    EXPECT_EQ(USER_POLICY_MAX_LIST_SIZE, recordIter->second.userList.size());
    EXPECT_EQ(recordIter->second.userList.end(),
        std::find(recordIter->second.userList.begin(), recordIter->second.userList.end(),
            USER_POLICY_MAX_LIST_SIZE));
}

/**
 * @tc.name: SetUserPolicyWhiteListMaxLimit001
 * @tc.desc: SetUserPolicy rejects update when merged policy cache contains oversized whitelist.
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(TokenInfoManagerTest, SetUserPolicyWhiteListMaxLimit001, TestSize.Level0)
{
    uint32_t permCode;
    ASSERT_TRUE(TransferPermissionToOpcode("ohos.permission.CAMERA", permCode));
    auto& manager = UserPolicyManager::GetInstance();
    PolicyWhiteListStateGuard stateGuard(manager, permCode);
    std::unordered_set<AccessTokenID> whiteList;
    for (uint32_t index = 0; index <= USER_POLICY_MAX_LIST_SIZE; ++index) {
        whiteList.insert(static_cast<AccessTokenID>(RANDOM_TOKENID + index));
    }
    stateGuard.SetWhiteList(USER_ID, GetSelfTokenID(), whiteList);

    UserPermissionPolicy policy = {
        .permissionName = "ohos.permission.CAMERA",
        .userPolicyList = {{ .userId = USER_ID, .isRestricted = true }},
        .isPersist = false
    };
    std::vector<UserPolicyChange> userPolicyList;
    EXPECT_EQ(ERR_OVERSIZE, manager.SetUserPolicy({ policy }, GetSelfTokenID(), userPolicyList));
    EXPECT_TRUE(userPolicyList.empty());

    std::shared_lock<std::shared_mutex> lock(manager.userPolicyLock_);
    auto recordIter = manager.userPolicyRecords_.find(permCode);
    ASSERT_NE(manager.userPolicyRecords_.end(), recordIter);
    EXPECT_EQ(USER_POLICY_MAX_LIST_SIZE + 1, recordIter->second.whiteList.size());
}
#endif

/**
 * @tc.name: ClearUserPolicyDbRollback001
 * @tc.desc: ClearUserPolicy keeps state unchanged when a batch item is invalid.
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(TokenInfoManagerTest, ClearUserPolicyDbRollback001, TestSize.Level0)
{
    uint32_t permCode;
    ASSERT_TRUE(TransferPermissionToOpcode("ohos.permission.CAMERA", permCode));
    auto& manager = UserPolicyManager::GetInstance();
    PolicyWhiteListStateGuard stateGuard(manager, permCode);
    stateGuard.SetControlledUser(USER_ID, GetSelfTokenID());

    std::vector<UserPolicyChange> userPolicyList;
    std::vector<std::string> permissionList = { "ohos.permission.CAMERA", "test" };
    EXPECT_EQ(ERR_PARAM_INVALID, manager.ClearUserPolicy(permissionList, GetSelfTokenID(), userPolicyList));

    std::vector<AccessTokenID> tokenIdList;
    EXPECT_EQ(RET_SUCCESS, manager.GetPolicyWhiteList(permCode, tokenIdList));
    EXPECT_TRUE(tokenIdList.empty());
}

/**
 * @tc.name: UserPolicyDbCreateUpgrade001
 * @tc.desc: Persisted user policy rows can be queried after creation.
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(TokenInfoManagerTest, UserPolicyDbCreateUpgrade001, TestSize.Level0)
{
    std::vector<GenericValues> results;
    EXPECT_EQ(RET_SUCCESS,
        AccessTokenDb::GetInstance()->Find(AtmDataType::ACCESSTOKEN_USER_POLICY,
            BuildUserPolicyDbCondition("ohos.permission.CAMERA"), results));
    EXPECT_TRUE(results.empty());
}

/**
 * @tc.name: UserPolicyDbRecoverDirtyData001
 * @tc.desc: LoadPersistedPolicies ignores dirty user policy rows.
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(TokenInfoManagerTest, UserPolicyDbRecoverDirtyData001, TestSize.Level0)
{
    uint32_t permCode;
    ASSERT_TRUE(TransferPermissionToOpcode("ohos.permission.CAMERA", permCode));
    auto& manager = UserPolicyManager::GetInstance();
    PolicyWhiteListStateGuard stateGuard(manager, permCode);

    GenericValues addValue;
    addValue.Put(TokenFiledConst::FIELD_PERMISSION_NAME, std::string("ohos.permission.CAMERA"));
    addValue.Put(TokenFiledConst::FIELD_CONTROLLER_TOKENID, static_cast<int32_t>(GetSelfTokenID()));
    addValue.Put(TokenFiledConst::FIELD_RESTRICTED_USER, std::string("abc"));
    addValue.Put(TokenFiledConst::FIELD_WHITELIST, std::string("1"));

    AddInfo addInfo;
    addInfo.addType = AtmDataType::ACCESSTOKEN_USER_POLICY;
    addInfo.addValues = { addValue };
    DelInfo delInfo;
    delInfo.delType = AtmDataType::ACCESSTOKEN_USER_POLICY;
    delInfo.delValue.Put(TokenFiledConst::FIELD_PERMISSION_NAME, std::string("ohos.permission.CAMERA"));
    EXPECT_EQ(RET_SUCCESS, AccessTokenDb::GetInstance()->DeleteAndInsertValues({ delInfo }, { addInfo }));
    EXPECT_EQ(RET_SUCCESS, manager.LoadPersistedPolicies());
    EXPECT_FALSE(manager.IsPolicyPersisted(permCode));

    EXPECT_EQ(RET_SUCCESS, AccessTokenDb::GetInstance()->DeleteAndInsertValues({ delInfo }, {}));
}

/**
 * @tc.name: LoadPersistedPolicies001
 * @tc.desc: LoadPersistedPolicies loads valid rows and ignores dirty persisted rows.
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(TokenInfoManagerTest, LoadPersistedPolicies001, TestSize.Level0)
{
    const std::string permissionName = "ohos.permission.CAMERA";
    const std::string invalidPermissionName = "ohos.permission.TEST_INVALID_USER_POLICY";
    const std::string invalidUserListPermission = "ohos.permission.INTERNET";
    const std::string invalidWhiteListPermission = "ohos.permission.GET_NETWORK_STATS";
    const std::string emptyUserListPermission = "ohos.permission.LOCATION";
    uint32_t permCode;
    uint32_t invalidUserListPermCode;
    uint32_t invalidWhiteListPermCode;
    uint32_t emptyUserListPermCode;
    ASSERT_TRUE(TransferPermissionToOpcode(permissionName, permCode));
    ASSERT_TRUE(TransferPermissionToOpcode(invalidUserListPermission, invalidUserListPermCode));
    ASSERT_TRUE(TransferPermissionToOpcode(invalidWhiteListPermission, invalidWhiteListPermCode));
    ASSERT_TRUE(TransferPermissionToOpcode(emptyUserListPermission, emptyUserListPermCode));
    auto& manager = UserPolicyManager::GetInstance();
    UserPolicyRecordsGuard recordsGuard(manager);
    EXPECT_EQ(RET_SUCCESS, UpsertUserPolicyDbRecord(permissionName, GetSelfTokenID(),
        std::to_string(USER_ID), std::to_string(RANDOM_TOKENID)));
    EXPECT_EQ(RET_SUCCESS, UpsertUserPolicyDbRecord(invalidPermissionName, GetSelfTokenID(),
        std::to_string(USER_ID + 1), ""));
    EXPECT_EQ(RET_SUCCESS, UpsertUserPolicyDbRecord(invalidUserListPermission, GetSelfTokenID(),
        "abc", ""));
    EXPECT_EQ(RET_SUCCESS, UpsertUserPolicyDbRecord(invalidWhiteListPermission, GetSelfTokenID(),
        std::to_string(USER_ID + 2), "abc"));
    EXPECT_EQ(RET_SUCCESS, UpsertUserPolicyDbRecord(emptyUserListPermission, GetSelfTokenID(), "", ""));

    EXPECT_EQ(RET_SUCCESS, manager.LoadPersistedPolicies());

    EXPECT_TRUE(manager.IsPolicyPersisted(permCode));
    EXPECT_FALSE(manager.IsPolicyPersisted(invalidUserListPermCode));
    EXPECT_FALSE(manager.IsPolicyPersisted(invalidWhiteListPermCode));
    EXPECT_FALSE(manager.IsPolicyPersisted(emptyUserListPermCode));
    EXPECT_TRUE(manager.IsPermissionRestricted(RANDOM_TOKENID + 1, USER_ID, permCode));
    EXPECT_FALSE(manager.IsPermissionRestricted(RANDOM_TOKENID, USER_ID, permCode));
    std::vector<AccessTokenID> tokenIdList;
    EXPECT_EQ(RET_SUCCESS, manager.GetPolicyWhiteList(permCode, tokenIdList));
    ASSERT_EQ(1u, tokenIdList.size());
    EXPECT_EQ(RANDOM_TOKENID, tokenIdList[0]);

    EXPECT_EQ(RET_SUCCESS, DeleteUserPolicyDbRecord(permissionName));
    EXPECT_EQ(RET_SUCCESS, DeleteUserPolicyDbRecord(invalidPermissionName));
    EXPECT_EQ(RET_SUCCESS, DeleteUserPolicyDbRecord(invalidUserListPermission));
    EXPECT_EQ(RET_SUCCESS, DeleteUserPolicyDbRecord(invalidWhiteListPermission));
    EXPECT_EQ(RET_SUCCESS, DeleteUserPolicyDbRecord(emptyUserListPermission));
}

/**
 * @tc.name: UserPolicyConcurrency001
 * @tc.desc: UserPolicyManager handles concurrent whitelist updates.
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(TokenInfoManagerTest, UserPolicyConcurrency001, TestSize.Level0)
{
    uint32_t permCode;
    ASSERT_TRUE(TransferPermissionToOpcode("ohos.permission.CAMERA", permCode));
    auto& manager = UserPolicyManager::GetInstance();
    PolicyWhiteListStateGuard stateGuard(manager, permCode);
    stateGuard.SetControlledUser(USER_ID, GetSelfTokenID());

    std::atomic<bool> ok { true };
    auto worker = [&manager, permCode, &ok](AccessTokenID tokenId) {
        for (int i = 0; i < 8; ++i) {
            PolicyWhiteListUpdateInfo addContext {
                .tokenId = tokenId,
                .userId = USER_ID,
                .permCode = permCode,
                .type = UpdateWhiteListType::ADD,
                .callerToken = GetSelfTokenID()
            };
            PolicyWhiteListUpdateInfo deleteContext = addContext;
            deleteContext.type = UpdateWhiteListType::DELETE;
            if (manager.UpdatePolicyWhiteList(addContext) != RET_SUCCESS) {
                ok = false;
            }
            if (manager.UpdatePolicyWhiteList(deleteContext) != RET_SUCCESS) {
                ok = false;
            }
        }
    };

    std::thread t1(worker, RANDOM_TOKENID);
    std::thread t2(worker, RANDOM_TOKENID + 1);
    t1.join();
    t2.join();

    EXPECT_TRUE(ok);
    std::vector<AccessTokenID> tokenIdList;
    EXPECT_EQ(RET_SUCCESS, manager.GetPolicyWhiteList(permCode, tokenIdList));
    EXPECT_TRUE(tokenIdList.empty());
}
#endif

/**
 * @tc.name: ReservedHapInfo001
 * @tc.desc: RemoveReservedHapInfo
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(TokenInfoManagerTest, ReservedHapInfo001, TestSize.Level0)
{
    AccessTokenIDEx tokenIdEx = {0};
    std::vector<GenericValues> undefValues;
    int32_t ret = AccessTokenInfoManager::GetInstance().CreateHapTokenInfo(g_infoManagerTestInfoParms,
        g_infoManagerTestPolicyPrams1, tokenIdEx, undefValues);
    ASSERT_EQ(RET_SUCCESS, ret);
    GTEST_LOG_(INFO) << "add a normal hap token";

    AccessTokenID tokenID = tokenIdEx.tokenIdExStruct.tokenID;
    ret = AccessTokenInfoManager::GetInstance().RemoveHapTokenInfo(tokenID, true);
    // check whether reserved successfully
    ASSERT_EQ(RET_SUCCESS, ret);
    std::string HapUniqueKey = AccessTokenInfoUtils::GetHapUniqueStr(g_infoManagerTestInfoParms.userID,
        g_infoManagerTestInfoParms.bundleName, g_infoManagerTestInfoParms.instIndex);
    auto it = AccessTokenInfoManager::GetInstance().reservedHapTokenIdMap_.find(HapUniqueKey);
    ASSERT_NE(it, AccessTokenInfoManager::GetInstance().reservedHapTokenIdMap_.end());
    GenericValues conditionValue;
    conditionValue.Put(TokenFiledConst::FIELD_TOKEN_ID, static_cast<int32_t>(tokenID));
    std::vector<GenericValues> hapTokenResults;
    ret = AccessTokenDbOperator::Find(AtmDataType::ACCESSTOKEN_HAP_TOKEN_INFO, conditionValue, hapTokenResults);
    ASSERT_EQ(RET_SUCCESS, ret);
    ASSERT_EQ(false, hapTokenResults.empty());
    ASSERT_NE(0, hapTokenResults[0].GetInt(TokenFiledConst::FIELD_TOKEN_ATTR) & TOKEN_ATTR_RESERVED);

    // check whether can get hap info
    HapTokenInfo info;
    ASSERT_EQ(AccessTokenError::ERR_TOKENID_NOT_EXIST,
        AccessTokenInfoManager::GetInstance().GetHapTokenInfo(tokenID, info));
    ASSERT_EQ(AccessTokenError::ERR_PARAM_INVALID,
        AccessTokenInfoManager::GetInstance().RemoveHapTokenInfo(tokenID, true));

    // create hap again, will remove reserved info
    AccessTokenIDEx tokenIdEx1 = {0};
    ret = AccessTokenInfoManager::GetInstance().CreateHapTokenInfo(g_infoManagerTestInfoParms,
        g_infoManagerTestPolicyPrams1, tokenIdEx1, undefValues);
    ASSERT_EQ(RET_SUCCESS, ret);
    AccessTokenID tokenID1 = tokenIdEx1.tokenIdExStruct.tokenID;
    ASSERT_NE(tokenID, tokenID1);
    it = AccessTokenInfoManager::GetInstance().reservedHapTokenIdMap_.find(HapUniqueKey);
    ASSERT_EQ(it, AccessTokenInfoManager::GetInstance().reservedHapTokenIdMap_.end());
    hapTokenResults.clear();
    ret = AccessTokenDbOperator::Find(AtmDataType::ACCESSTOKEN_HAP_TOKEN_INFO, conditionValue, hapTokenResults);
    ASSERT_EQ(RET_SUCCESS, ret);
    ASSERT_EQ(true, hapTokenResults.empty());
    ASSERT_EQ(RET_SUCCESS, AccessTokenInfoManager::GetInstance().RemoveHapTokenInfo(tokenID1));
}

/**
 * @tc.name: ReservedHapInfo002
 * @tc.desc: Inithaptokeninfos with invalid token info in db
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(TokenInfoManagerTest, ReservedHapInfo002, TestSize.Level0)
{
    GenericValues genericValues;
    genericValues.Put(TokenFiledConst::FIELD_TOKEN_ID, 123);
    genericValues.Put(TokenFiledConst::FIELD_USER_ID, 100);
    genericValues.Put(TokenFiledConst::FIELD_BUNDLE_NAME, "test_bundle_name");
    genericValues.Put(TokenFiledConst::FIELD_API_VERSION, 9);
    genericValues.Put(TokenFiledConst::FIELD_INST_INDEX, 0);
    genericValues.Put(TokenFiledConst::FIELD_DLP_TYPE, 0);
    genericValues.Put(TokenFiledConst::FIELD_APP_ID, "test_app_id");
    genericValues.Put(TokenFiledConst::FIELD_DEVICE_ID, "test_device_id");
    genericValues.Put(TokenFiledConst::FIELD_APL, ATokenAplEnum::APL_NORMAL);
    genericValues.Put(TokenFiledConst::FIELD_TOKEN_VERSION, 0);
    genericValues.Put(TokenFiledConst::FIELD_TOKEN_ATTR, TOKEN_ATTR_RESERVED);
    genericValues.Put(TokenFiledConst::FIELD_FORBID_PERM_DIALOG, "test_perm_dialog_cap_state");
    AddInfo addInfo;
    addInfo.addType = AtmDataType::ACCESSTOKEN_HAP_TOKEN_INFO;
    addInfo.addValues.emplace_back(genericValues);

    std::vector<DelInfo> delInfoVec;
    std::vector<AddInfo> addInfoVec;
    addInfoVec.emplace_back(addInfo);
    EXPECT_EQ(RET_SUCCESS, AccessTokenDb::GetInstance()->DeleteAndInsertValues(delInfoVec, addInfoVec));
    AccessTokenInfoManager::GetInstance().hasInited_ = false;
    uint32_t hapSize = 0;
    uint32_t nativeSize = 0;
    uint32_t pefDefSize = 0;
    uint32_t dlpSize = 0;
    std::map<int32_t, TokenIdInfo> tokenIdAplMap;
    AccessTokenInfoManager::GetInstance().Init(hapSize, nativeSize, pefDefSize, dlpSize, tokenIdAplMap);
    std::string HapUniqueKey = AccessTokenInfoUtils::GetHapUniqueStr(100, "test_bundle_name", 0);
    auto it = AccessTokenInfoManager::GetInstance().reservedHapTokenIdMap_.find(HapUniqueKey);
    EXPECT_NE(it, AccessTokenInfoManager::GetInstance().reservedHapTokenIdMap_.end());

    AccessTokenInfoManager::GetInstance().reservedHapTokenIdMap_.erase(HapUniqueKey);
    addInfoVec.clear();
    DelInfo delInfo;
    delInfo.delType = AtmDataType::ACCESSTOKEN_HAP_TOKEN_INFO;
    delInfo.delValue.Put(TokenFiledConst::FIELD_TOKEN_ID, 123);
    delInfoVec.emplace_back(delInfo);
    EXPECT_EQ(RET_SUCCESS, AccessTokenDb::GetInstance()->DeleteAndInsertValues(delInfoVec, addInfoVec));
}

/**
 * @tc.name: ReservedHapInfo003
 * @tc.desc: RegisterTokenId with reserved hap tokenid
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(TokenInfoManagerTest, ReservedHapInfo003, TestSize.Level0)
{
    AccessTokenIDInner idInner = {
        .cloneFlag = 0,
        .renderFlag = 0,
        .dlpFlag = 0,
        .version = DEFAULT_TOKEN_VERSION, // invalid version
        .type = ATokenTypeEnum::TOKEN_HAP,
        .tokenUniqueID = 123,
    };
    AccessTokenID tokenId = static_cast<AccessTokenID>(*(reinterpret_cast<uint32_t*>(&idInner)));
    AccessTokenInfoManager::GetInstance().AddReservedHapTokenId(100, "test_bundle_name", 0, tokenId);
    AccessTokenInfoManager::GetInstance().AddReservedHapTokenId(100, "test_bundle_name", 0, tokenId); // repeat add
    std::string HapUniqueKey = AccessTokenInfoUtils::GetHapUniqueStr(100, "test_bundle_name", 0);
    EXPECT_EQ(AccessTokenInfoManager::GetInstance().reservedHapTokenIdMap_.count(HapUniqueKey), 1);

    EXPECT_EQ(ERR_TOKENID_HAS_EXISTED,
        AccessTokenIDManager::GetInstance().RegisterTokenId(tokenId, ATokenTypeEnum::TOKEN_HAP));
    AccessTokenInfoManager::GetInstance().RemoveReservedHapTokenId(100, "test_bundle_name", 0);
}

/**
 * @tc.name: ReservedHapInfo004
 * @tc.desc: if reservedHapTokenIdMap_ not find tokenid, get from db
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(TokenInfoManagerTest, ReservedHapInfo004, TestSize.Level0)
{
    AccessTokenIDEx tokenIdEx = {0};
    std::vector<GenericValues> undefValues;
    int32_t ret = AccessTokenInfoManager::GetInstance().CreateHapTokenInfo(g_infoManagerTestInfoParms,
        g_infoManagerTestPolicyPrams1, tokenIdEx, undefValues);
    ASSERT_EQ(RET_SUCCESS, ret);
    GTEST_LOG_(INFO) << "add a normal hap token";

    AccessTokenID tokenID = tokenIdEx.tokenIdExStruct.tokenID;
    ret = AccessTokenInfoManager::GetInstance().RemoveHapTokenInfo(tokenID, true);
    // check whether reserved successfully
    ASSERT_EQ(RET_SUCCESS, ret);
    std::string HapUniqueKey = AccessTokenInfoUtils::GetHapUniqueStr(g_infoManagerTestInfoParms.userID,
        g_infoManagerTestInfoParms.bundleName, g_infoManagerTestInfoParms.instIndex);
    auto it = AccessTokenInfoManager::GetInstance().reservedHapTokenIdMap_.find(HapUniqueKey);
    ASSERT_NE(it, AccessTokenInfoManager::GetInstance().reservedHapTokenIdMap_.end());
    AccessTokenInfoManager::GetInstance().reservedHapTokenIdMap_.erase(HapUniqueKey);
    // check whether can get hap info
    HapTokenInfo info;
    ASSERT_EQ(AccessTokenError::ERR_TOKENID_NOT_EXIST,
        AccessTokenInfoManager::GetInstance().GetHapTokenInfo(tokenID, info));
    it = AccessTokenInfoManager::GetInstance().reservedHapTokenIdMap_.find(HapUniqueKey);
    ASSERT_EQ(it, AccessTokenInfoManager::GetInstance().reservedHapTokenIdMap_.end());

    AccessTokenIDEx tokenIdEx1 = {0};
    ret = AccessTokenInfoManager::GetInstance().CreateHapTokenInfo(g_infoManagerTestInfoParms,
        g_infoManagerTestPolicyPrams1, tokenIdEx1, undefValues);
    ASSERT_EQ(RET_SUCCESS, ret);
    AccessTokenID tokenID1 = tokenIdEx1.tokenIdExStruct.tokenID;
    ASSERT_EQ(RET_SUCCESS, AccessTokenInfoManager::GetInstance().RemoveHapTokenInfo(tokenID1));
}

/**
 * @tc.name: ReservedHapInfo005
 * @tc.desc: coverage test
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(TokenInfoManagerTest, ReservedHapInfo005, TestSize.Level0)
{
    AccessTokenIDEx tokenIdEx = {0};
    std::vector<GenericValues> undefValues;
    int32_t ret = AccessTokenInfoManager::GetInstance().CreateHapTokenInfo(g_infoManagerTestInfoParms,
        g_infoManagerTestPolicyPrams1, tokenIdEx, undefValues);
    ASSERT_EQ(RET_SUCCESS, ret);
    GTEST_LOG_(INFO) << "add a normal hap token";

    AccessTokenID tokenID = tokenIdEx.tokenIdExStruct.tokenID;
    AccessTokenInfoManager::GetInstance().hapTokenInfoMap_.erase(tokenID);
    HapTokenInfo info;
    EXPECT_EQ(RET_SUCCESS, AccessTokenInfoManager::GetInstance().GetHapTokenInfo(tokenID, info));

    ASSERT_EQ(RET_SUCCESS, AccessTokenInfoManager::GetInstance().RemoveHapTokenInfo(tokenID));
}

#ifdef TOKEN_SYNC_ENABLE
/**
 * @tc.name: GetFullRemoteTokenId001
 * @tc.desc: GetFullRemoteTokenId with invalid tokenid.
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(TokenInfoManagerTest, GetFullRemoteTokenId001, TestSize.Level0)
{
    AccessTokenIDEx idEx = {0};
    idEx.tokenIdExStruct.tokenID = 123; // invalid tokenid

    AccessTokenIDEx idEx2 = {0};
    idEx2.tokenIDEx = AccessTokenInfoManager::GetInstance().GetFullRemoteTokenId(idEx.tokenIdExStruct.tokenID);
    EXPECT_EQ(idEx.tokenIDEx, idEx2.tokenIDEx);
}

/**
 * @tc.name: GetFullRemoteTokenId002
 * @tc.desc: GetFullRemoteTokenId with normal app tokenid.
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(TokenInfoManagerTest, GetFullRemoteTokenId002, TestSize.Level0)
{
    AccessTokenIDEx tokenIdEx = {0};
    std::vector<GenericValues> undefValues;
    int32_t ret = AccessTokenInfoManager::GetInstance().CreateHapTokenInfo(g_infoManagerTestInfoParms,
        g_infoManagerTestPolicyPrams1, tokenIdEx, undefValues);
    ASSERT_EQ(RET_SUCCESS, ret);
    GTEST_LOG_(INFO) << "add a normal hap token " << tokenIdEx.tokenIdExStruct.tokenID;

    AccessTokenID tokenID = tokenIdEx.tokenIdExStruct.tokenID;
    std::shared_ptr<HapTokenInfoInner> tokenInfo;
    tokenInfo = AccessTokenInfoManager::GetInstance().GetHapTokenInfoInner(tokenID);
    EXPECT_NE(nullptr, tokenInfo);

    EXPECT_EQ(tokenIdEx.tokenIDEx, AccessTokenInfoManager::GetInstance().GetFullRemoteTokenId(tokenID));

    ret = AccessTokenInfoManager::GetInstance().RemoveHapTokenInfo(tokenID);
    ASSERT_EQ(RET_SUCCESS, ret);
    GTEST_LOG_(INFO) << "remove the normal hap token info";
}

/**
 * @tc.name: GetFullRemoteTokenId003
 * @tc.desc: GetFullRemoteTokenId with system app tokenid.
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(TokenInfoManagerTest, GetFullRemoteTokenId003, TestSize.Level0)
{
    AccessTokenIDEx tokenIdEx = {0};
    std::vector<GenericValues> undefValues;
    int32_t ret = AccessTokenInfoManager::GetInstance().CreateHapTokenInfo(g_infoManagerTestInfoParms2,
        g_infoManagerTestPolicyPrams1, tokenIdEx, undefValues);
    ASSERT_EQ(RET_SUCCESS, ret);
    GTEST_LOG_(INFO) << "add a system hap token " << tokenIdEx.tokenIdExStruct.tokenID;

    AccessTokenID tokenID = tokenIdEx.tokenIdExStruct.tokenID;
    std::shared_ptr<HapTokenInfoInner> tokenInfo;
    tokenInfo = AccessTokenInfoManager::GetInstance().GetHapTokenInfoInner(tokenID);
    EXPECT_NE(nullptr, tokenInfo);

    EXPECT_NE(tokenID, AccessTokenInfoManager::GetInstance().GetFullRemoteTokenId(tokenID));
    EXPECT_EQ(tokenIdEx.tokenIDEx, AccessTokenInfoManager::GetInstance().GetFullRemoteTokenId(tokenID));

    ret = AccessTokenInfoManager::GetInstance().RemoveHapTokenInfo(tokenID);
    ASSERT_EQ(RET_SUCCESS, ret);
    GTEST_LOG_(INFO) << "remove the system hap token info";
}
#endif

/**
 * @tc.name: GetReqPermissionByName001
 * @tc.desc: GetReqPermissionByName test function for disable permissionName.
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(TokenInfoManagerTest, GetReqPermissionByName001, TestSize.Level0)
{
    AccessTokenID tokenId = 123;
    std::string permissionName = "invalid.permission";
    std::string value;
    bool tokenIdCheck = false;

    int32_t ret = PermissionDataBrief::GetInstance().GetReqPermissionByName(
        tokenId, permissionName, value, tokenIdCheck);
 
    EXPECT_EQ(ERR_PERMISSION_NOT_EXIST, ret);
}

/**
 * @tc.name: RegisterTokenId002
 * @tc.desc: Invalid type_ext
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(TokenInfoManagerTest, RegisterTokenId002, TestSize.Level0)
{
    AccessTokenIDInner innerId = {0};
    innerId.version = DEFAULT_TOKEN_VERSION;
    innerId.type = TOKEN_HAP;
    innerId.toolFlag = 1;
    innerId.tokenUniqueID = 1;
    innerId.type_ext = 1;
    AccessTokenID tokenId1 = *reinterpret_cast<AccessTokenID*>(&innerId);
    ASSERT_EQ(ERR_PARAM_INVALID, AccessTokenIDManager::GetInstance().RegisterTokenId(tokenId1, TOKEN_HAP));
}

/**
 * @tc.name: RegisterTokenId003
 * @tc.desc: Invalid type
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(TokenInfoManagerTest, RegisterTokenId003, TestSize.Level0)
{
    AccessTokenIDInner innerId = {0};
    innerId.version = DEFAULT_TOKEN_VERSION;
    innerId.type = TOKEN_SHELL;
    innerId.toolFlag = 1;
    innerId.tokenUniqueID = 1;
    innerId.type_ext = 0;
    AccessTokenID tokenId1 = *reinterpret_cast<AccessTokenID*>(&innerId);
    ASSERT_EQ(ERR_PARAM_INVALID, AccessTokenIDManager::GetInstance().RegisterTokenId(tokenId1, TOKEN_HAP));
}
} // namespace AccessToken
} // namespace Security
} // namespace OHOS
