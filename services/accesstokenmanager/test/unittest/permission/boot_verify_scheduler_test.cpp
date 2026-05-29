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
#include <gtest/hwext/gtest-tag.h>

#include <algorithm>
#include <memory>
#include <vector>

#include "access_token_error.h"
#include "generic_values.h"
#include "interfaces/hap_verify.h"
#include "mock_access_token_db_operator.h"
#include "mock_app_verify_adapter.h"
#define private public
#include "boot_verify_scheduler.h"
#include "hap_sign_verify_manager.h"
#undef private
#include "permission_data_brief.h"
#include "permission_map.h"
#include "token_field_const.h"

using namespace testing::ext;

namespace OHOS {
namespace Security {
namespace AccessToken {
namespace {
constexpr AccessTokenID TEST_TOKEN_ID = 123456;
constexpr AccessTokenID TEST_TOKEN_ID_2 = 123457;
constexpr AccessTokenID TEST_TOKEN_ID_3 = 123458;
constexpr uint32_t TEST_UID = 20010001;
#ifdef SPM_DATA_ENABLE
constexpr int32_t INVALID_UID = -1;
#endif
constexpr char DEFAULT_TOKEN_VERSION_VALUE = 1;
const std::string TEST_BUNDLE_NAME = "com.example.camera";
const std::string TEST_BUNDLE_NAME_2 = "com.example.music";
const std::string TEST_BUNDLE_NAME_3 = "com.example.notes";
const std::string TEST_PATH = "/data/test/camera.hap";
}

class BootVerifySchedulerTest : public testing::Test {
public:
    static void SetUpTestCase() {}
    static void TearDownTestCase() {}

    void SetUp() override
    {
        ResetMockDbState();
        PermissionDataBrief::GetInstance().DeleteBriefPermDataByTokenId(TEST_TOKEN_ID);
        PermissionDataBrief::GetInstance().DeleteBriefPermDataByTokenId(TEST_TOKEN_ID_2);
        auto& scheduler = BootVerifyScheduler::GetInstance();
        scheduler.ClearBundleVerifyContext();
        scheduler.bundleSignInfoMap_.clear();
        scheduler.isAllHapBundlesVerified_.store(false);
        scheduler.uidSet_.clear();
        originAdapter_ = HapSignVerifyManager::GetInstance().adapter_;
        adapter_ = std::make_unique<MockAppVerifyAdapter>();
        adapter_->bundleName_ = TEST_BUNDLE_NAME;
        adapter_->appIdentifier_ = "mock.identifier";
        adapter_->appId_ = "mock.appid";
        adapter_->moduleName_ = "entry";
        adapter_->moduleRaw_ = TEST_BUNDLE_NAME;
        adapter_->profileJsonRaw_ = TEST_BUNDLE_NAME;
        HapSignVerifyManager::GetInstance().adapter_ = adapter_.get();
    }

    void TearDown() override
    {
        HapSignVerifyManager::GetInstance().adapter_ = originAdapter_;
        auto& scheduler = BootVerifyScheduler::GetInstance();
        scheduler.ClearBundleVerifyContext();
        scheduler.bundleSignInfoMap_.clear();
        scheduler.uidSet_.clear();
        PermissionDataBrief::GetInstance().DeleteBriefPermDataByTokenId(TEST_TOKEN_ID);
        PermissionDataBrief::GetInstance().DeleteBriefPermDataByTokenId(TEST_TOKEN_ID_2);
        ResetMockDbState();
    }

protected:
    GenericValues BuildHapInfoValue(AccessTokenID tokenId, const std::string& bundleName, uint32_t uid,
        int32_t apl = APL_NORMAL, uint32_t tokenAttr = 0, bool migrated = true) const
    {
        GenericValues value;
        value.Put(TokenFiledConst::FIELD_TOKEN_ID, static_cast<int32_t>(tokenId));
        value.Put(TokenFiledConst::FIELD_USER_ID, 100);
        value.Put(TokenFiledConst::FIELD_BUNDLE_NAME, bundleName);
        value.Put(TokenFiledConst::FIELD_API_VERSION, 12);
        value.Put(TokenFiledConst::FIELD_INST_INDEX, 0);
        value.Put(TokenFiledConst::FIELD_DLP_TYPE, 0);
        value.Put(TokenFiledConst::FIELD_UID, static_cast<int32_t>(uid));
        value.Put(TokenFiledConst::FIELD_TOKEN_VERSION, static_cast<int32_t>(DEFAULT_TOKEN_VERSION_VALUE));
        value.Put(TokenFiledConst::FIELD_TOKEN_ATTR, static_cast<int32_t>(tokenAttr));
        value.Put(TokenFiledConst::FIELD_APL, apl);
        value.Put(TokenFiledConst::FIELD_MIGRATED, migrated ? 1 : 0);
        return value;
    }

    GenericValues BuildPermStateValue(AccessTokenID tokenId, const std::string& permissionName,
        PermissionState grantState = PermissionState::PERMISSION_DENIED,
        PermissionFlag grantFlag = PermissionFlag::PERMISSION_DEFAULT_FLAG) const
    {
        GenericValues value;
        value.Put(TokenFiledConst::FIELD_TOKEN_ID, static_cast<int32_t>(tokenId));
        value.Put(TokenFiledConst::FIELD_PERMISSION_NAME, permissionName);
        value.Put(TokenFiledConst::FIELD_DEVICE_ID, "");
        value.Put(TokenFiledConst::FIELD_GRANT_IS_GENERAL, 1);
        value.Put(TokenFiledConst::FIELD_GRANT_STATE, static_cast<int32_t>(grantState));
        value.Put(TokenFiledConst::FIELD_GRANT_FLAG, static_cast<int32_t>(grantFlag));
        return value;
    }

    GenericValues BuildExtendedValue(AccessTokenID tokenId, const std::string& permissionName,
        const std::string& valueStr) const
    {
        GenericValues value;
        value.Put(TokenFiledConst::FIELD_TOKEN_ID, static_cast<int32_t>(tokenId));
        value.Put(TokenFiledConst::FIELD_PERMISSION_NAME, permissionName);
        value.Put(TokenFiledConst::FIELD_VALUE, valueStr);
        return value;
    }

    uint16_t GetPermCode(const std::string& permissionName) const
    {
        uint32_t permCode = 0;
        EXPECT_TRUE(TransferPermissionToOpcode(permissionName, permCode));
        return static_cast<uint16_t>(permCode);
    }

    GenericValues BuildBundleSignValue(const std::string& bundleName, const std::string& moduleName,
        const std::string& path, bool isPreInstalled, int32_t bundleType,
        const std::vector<uint8_t>& persistData) const
    {
        GenericValues value;
        value.Put(TokenFiledConst::FIELD_BUNDLE_NAME, bundleName);
        value.Put(TokenFiledConst::FIELD_MODULE_NAME, moduleName);
        value.Put(TokenFiledConst::FIELD_PATH, path);
        value.Put(TokenFiledConst::FIELD_IS_PREINSTALLED, isPreInstalled ? 1 : 0);
        value.Put(TokenFiledConst::FIELD_BUNDLE_TYPE, bundleType);
        value.PutBlob(TokenFiledConst::FIELD_PERSIST_DATA, persistData);
        return value;
    }

    std::vector<uint8_t> BuildPersistData(const std::string& moduleRaw, const std::string& profileRaw) const
    {
        Verify::BootstrapInfo bootstrapInfo;
        bootstrapInfo.version = 1;
        bootstrapInfo.moduleRaw = moduleRaw;
        bootstrapInfo.profileJsonRaw = profileRaw;
        std::unique_ptr<uint8_t[]> dump(bootstrapInfo.Dump());
        uint64_t size = bootstrapInfo.GetSize();
        return std::vector<uint8_t>(dump.get(), dump.get() + size);
    }

    void PrepareVerifyDb(bool preInstalled = true, uint32_t uid = TEST_UID, bool migrated = true,
        uint32_t tokenAttr = 0)
    {
        SetMockDbFindResult(AtmDataType::ACCESSTOKEN_HAP_INFO, RET_SUCCESS,
            {BuildHapInfoValue(TEST_TOKEN_ID, TEST_BUNDLE_NAME, uid, APL_NORMAL, tokenAttr, migrated)});
        SetMockDbFindResult(AtmDataType::ACCESSTOKEN_PERMISSION_STATE, RET_SUCCESS,
            {BuildPermStateValue(TEST_TOKEN_ID, "ohos.permission.CAMERA")});
        SetMockDbFindResult(AtmDataType::ACCESSTOKEN_PERMISSION_EXTEND_VALUE, RET_SUCCESS, {});
        SetMockDbFindResult(AtmDataType::ACCESSTOKEN_HAP_PACKAGE_INFO, RET_SUCCESS,
            {BuildBundleSignValue(TEST_BUNDLE_NAME, "entry", TEST_PATH, preInstalled,
                static_cast<int32_t>(AppExecFwk::Spm::BundleType::APP),
                BuildPersistData(TEST_BUNDLE_NAME, TEST_BUNDLE_NAME))});
        SetMockDbFindResult(AtmDataType::ACCESSTOKEN_SYSTEM_CONFIG, RET_SUCCESS, {});
        SetMockDbFindResult(AtmDataType::ACCESSTOKEN_HAP_UNDEFINE_INFO, RET_SUCCESS, {});
    }

    BundleSignInfo BuildSignInfo(const std::string& bundleName = TEST_BUNDLE_NAME) const
    {
        BundleSignInfo signInfo;
        signInfo.bundleName = bundleName;
        signInfo.isPreInstalled = true;
        signInfo.moduleNameList = { "entry" };
        signInfo.pathList = { TEST_PATH };
        signInfo.bundleType = { static_cast<uint32_t>(AppExecFwk::Spm::BundleType::APP) };
        signInfo.persistDataList = { BuildPersistData(TEST_BUNDLE_NAME, TEST_BUNDLE_NAME) };
        return signInfo;
    }

    std::shared_ptr<BundleInfoInner> BuildBundleInfo(const std::vector<AccessTokenID>& tokenIds) const
    {
        auto bundleInfo = std::make_shared<BundleInfoInner>();
        bundleInfo->tokenIds = tokenIds;
        return bundleInfo;
    }

    HapTokenInfoItem BuildHapTokenInfoItem(AccessTokenID tokenId, const std::string& bundleName = TEST_BUNDLE_NAME,
        uint32_t uid = TEST_UID, bool migrated = true) const
    {
        HapTokenInfoItem item;
        item.tokenId = tokenId;
        item.userId = 100;
        item.bundleName = bundleName;
        item.instIndex = 0;
        item.dlpType = DLP_COMMON;
        item.version = DEFAULT_TOKEN_VERSION_VALUE;
        item.apiVersion = 12;
        item.tokenAttr = 0;
        item.uid = uid;
        item.migrated = migrated;
        item.apl = APL_NORMAL;
        item.appId = "mock.appid";
        return item;
    }

    std::unique_ptr<MockAppVerifyAdapter> adapter_;
    const IAppVerifyAdapter* originAdapter_ = nullptr;
};

HWTEST_F(BootVerifySchedulerTest, VerifyBundleSignInfoWhenStart001, TestSize.Level1)
{
    SetMockDbFindResult(AtmDataType::ACCESSTOKEN_HAP_INFO, ERR_PARAM_INVALID, {});
    EXPECT_EQ(ERR_PARAM_INVALID, BootVerifyScheduler::GetInstance().VerifyBundleSignInfoWhenStart());
}

HWTEST_F(BootVerifySchedulerTest, VerifyBundleSignInfoWhenStart002, TestSize.Level1)
{
    SetMockDbFindResult(AtmDataType::ACCESSTOKEN_HAP_INFO, RET_SUCCESS,
        {BuildHapInfoValue(TEST_TOKEN_ID, TEST_BUNDLE_NAME, TEST_UID)});
    SetMockDbFindResult(AtmDataType::ACCESSTOKEN_PERMISSION_STATE, ERR_PARAM_INVALID, {});
    EXPECT_EQ(ERR_PARAM_INVALID, BootVerifyScheduler::GetInstance().VerifyBundleSignInfoWhenStart());
}
#ifdef SPM_DATA_ENABLE

HWTEST_F(BootVerifySchedulerTest, VerifyBundleSignInfoWhenStart003, TestSize.Level1)
{
    PrepareVerifyDb(true);
    EXPECT_EQ(RET_SUCCESS, BootVerifyScheduler::GetInstance().VerifyBundleSignInfoWhenStart());
    EXPECT_TRUE(BootVerifyScheduler::GetInstance().highPrivilegeBundleList_.size() == 1);
    EXPECT_TRUE(BootVerifyScheduler::GetInstance().normalBundleList_.empty());
    EXPECT_EQ(1U, GetMockDbState().deleteAndInsertCallCount);
}

HWTEST_F(BootVerifySchedulerTest, VerifyBundleSignInfoWhenStart004, TestSize.Level1)
{
    PrepareVerifyDb(true);
    adapter_->verifyRet_ = ERR_PARAM_INVALID;
    EXPECT_EQ(ERR_HAP_VERIFY_FAILED, BootVerifyScheduler::GetInstance().VerifyBundleSignInfoWhenStart());
}

HWTEST_F(BootVerifySchedulerTest, VerifyBundleSignInfoWhenStart005, TestSize.Level1)
{
    PrepareVerifyDb(false);
    EXPECT_EQ(RET_SUCCESS, BootVerifyScheduler::GetInstance().VerifyBundleSignInfoWhenStart());
    EXPECT_TRUE(BootVerifyScheduler::GetInstance().highPrivilegeBundleList_.empty());
    EXPECT_TRUE(BootVerifyScheduler::GetInstance().normalBundleList_.size() == 1);
}

HWTEST_F(BootVerifySchedulerTest, VerifyBundleSignInfoWhenStart006, TestSize.Level1)
{
    PrepareVerifyDb(true, static_cast<uint32_t>(INVALID_UID), false);
    EXPECT_EQ(RET_SUCCESS, BootVerifyScheduler::GetInstance().VerifyBundleSignInfoWhenStart());
    // ski
    EXPECT_EQ(0U, GetMockDbState().deleteAndInsertCallCount);
    EXPECT_TRUE(BootVerifyScheduler::GetInstance().isVerifiedMap_[TEST_BUNDLE_NAME]);
}

HWTEST_F(BootVerifySchedulerTest, VerifyBundleSignInfoWhenStart007, TestSize.Level1)
{
    PrepareVerifyDb(true);
    adapter_->verifyIsChanged_ = true;
    adapter_->moduleName_ = "entry_changed";
    EXPECT_EQ(RET_SUCCESS, BootVerifyScheduler::GetInstance().VerifyBundleSignInfoWhenStart());
    ASSERT_FALSE(GetMockDbState().lastAddInfos.empty());
    bool hasPackageInfo = false;
    for (const auto& addInfo : GetMockDbState().lastAddInfos) {
        if (addInfo.addType == AtmDataType::ACCESSTOKEN_HAP_PACKAGE_INFO) {
            hasPackageInfo = true;
        }
    }
    EXPECT_TRUE(hasPackageInfo);
}

HWTEST_F(BootVerifySchedulerTest, VerifyBundleSignInfoWhenStart008, TestSize.Level1)
{
    PrepareVerifyDb(false);
    auto& scheduler = BootVerifyScheduler::GetInstance();
    EXPECT_EQ(RET_SUCCESS, scheduler.VerifyBundleSignInfoWhenStart());
    EXPECT_TRUE(scheduler.isVerifiedMap_[TEST_BUNDLE_NAME]);
    EXPECT_FALSE(scheduler.isVerifyingMap_[TEST_BUNDLE_NAME]);
    EXPECT_TRUE(scheduler.bundleInfoMap_.find(TEST_BUNDLE_NAME) != scheduler.bundleInfoMap_.end());
    EXPECT_TRUE(scheduler.bundleNoCachedInfoMap_.find(TEST_BUNDLE_NAME) != scheduler.bundleNoCachedInfoMap_.end());
}
#endif // SPM_DATA_ENABLE

HWTEST_F(BootVerifySchedulerTest, BuildPriorityBundleList001, TestSize.Level1)
{
    auto& scheduler = BootVerifyScheduler::GetInstance();
    scheduler.bundleSignInfoMap_[TEST_BUNDLE_NAME] = BuildSignInfo(TEST_BUNDLE_NAME);
    scheduler.bundleSignInfoMap_[TEST_BUNDLE_NAME_2] = BuildSignInfo(TEST_BUNDLE_NAME_2);
    scheduler.bundleSignInfoMap_[TEST_BUNDLE_NAME_2].isPreInstalled = false;
    scheduler.hapTokenInfoMap_[TEST_TOKEN_ID] = BuildHapTokenInfoItem(TEST_TOKEN_ID, TEST_BUNDLE_NAME);
    scheduler.hapTokenInfoMap_[TEST_TOKEN_ID_2] = BuildHapTokenInfoItem(TEST_TOKEN_ID_2, TEST_BUNDLE_NAME_2);
    scheduler.hapTokenInfoMap_[TEST_TOKEN_ID_3] = BuildHapTokenInfoItem(TEST_TOKEN_ID_3, TEST_BUNDLE_NAME_3);

    scheduler.BuildPriorityBundleList();

    EXPECT_EQ(2U, scheduler.highPrivilegeBundleList_.size());
    EXPECT_EQ(1U, scheduler.normalBundleList_.size());
    EXPECT_TRUE(std::find(scheduler.highPrivilegeBundleList_.begin(),
        scheduler.highPrivilegeBundleList_.end(), TEST_BUNDLE_NAME) != scheduler.highPrivilegeBundleList_.end());
    EXPECT_TRUE(std::find(scheduler.highPrivilegeBundleList_.begin(),
        scheduler.highPrivilegeBundleList_.end(), TEST_BUNDLE_NAME_3) != scheduler.highPrivilegeBundleList_.end());
    EXPECT_TRUE(std::find(scheduler.normalBundleList_.begin(),
        scheduler.normalBundleList_.end(), TEST_BUNDLE_NAME_2) != scheduler.normalBundleList_.end());
}

HWTEST_F(BootVerifySchedulerTest, PreVerifyBundle001, TestSize.Level1)
{
    PrepareVerifyDb(false);
    ASSERT_EQ(RET_SUCCESS, BootVerifyScheduler::GetInstance().VerifyBundleSignInfoWhenStart());
    EXPECT_EQ(RET_SUCCESS, BootVerifyScheduler::GetInstance().PreVerifyBundle(TEST_BUNDLE_NAME));
}

HWTEST_F(BootVerifySchedulerTest, PreVerifyBundle002, TestSize.Level1)
{
    PrepareVerifyDb(false);
    ASSERT_EQ(RET_SUCCESS, BootVerifyScheduler::GetInstance().VerifyBundleSignInfoWhenStart());
    EXPECT_EQ(RET_SUCCESS, BootVerifyScheduler::GetInstance().PreVerifyBundle(TEST_TOKEN_ID));
}

HWTEST_F(BootVerifySchedulerTest, PreVerifyBundle003, TestSize.Level1)
{
    EXPECT_EQ(RET_SUCCESS, BootVerifyScheduler::GetInstance().PreVerifyBundle(TEST_TOKEN_ID));
}

HWTEST_F(BootVerifySchedulerTest, PreVerifyBundle004, TestSize.Level1)
{
    auto& scheduler = BootVerifyScheduler::GetInstance();
    scheduler.bundleInfoMap_[TEST_BUNDLE_NAME] = BuildBundleInfo({});
    scheduler.bundleSignInfoMap_[TEST_BUNDLE_NAME] = BuildSignInfo();
    scheduler.hapTokenInfoMap_[TEST_TOKEN_ID] = BuildHapTokenInfoItem(TEST_TOKEN_ID);
    scheduler.isVerifiedMap_[TEST_BUNDLE_NAME] = false;
    scheduler.isVerifyingMap_[TEST_BUNDLE_NAME] = false;

    EXPECT_EQ(RET_SUCCESS, scheduler.PreVerifyBundle(TEST_TOKEN_ID));
    EXPECT_TRUE(scheduler.isVerifiedMap_[TEST_BUNDLE_NAME]);
    EXPECT_FALSE(scheduler.isVerifyingMap_[TEST_BUNDLE_NAME]);
}

HWTEST_F(BootVerifySchedulerTest, LoadVerifyDataFromDb001, TestSize.Level1)
{
    PrepareVerifyDb(true);
    SetMockDbFindResult(AtmDataType::ACCESSTOKEN_PERMISSION_EXTEND_VALUE, ERR_PARAM_INVALID, {});
    EXPECT_EQ(RET_SUCCESS, BootVerifyScheduler::GetInstance().LoadVerifyDataFromDb());
}

HWTEST_F(BootVerifySchedulerTest, RefreshBundleSignInfoMap001, TestSize.Level1)
{
    PrepareVerifyDb(true);
    GenericValues invalidBundleType = BuildBundleSignValue(TEST_BUNDLE_NAME, "entry", TEST_PATH, true, 999,
        BuildPersistData(TEST_BUNDLE_NAME, TEST_BUNDLE_NAME));
    SetMockDbFindResult(AtmDataType::ACCESSTOKEN_HAP_PACKAGE_INFO, RET_SUCCESS, {invalidBundleType});
    EXPECT_EQ(RET_SUCCESS, BootVerifyScheduler::GetInstance().RefreshBundleSignInfoMap());
    EXPECT_TRUE(BootVerifyScheduler::GetInstance().bundleSignInfoMap_[TEST_BUNDLE_NAME].bundleType.empty());
}

HWTEST_F(BootVerifySchedulerTest, BuildSpmParams001, TestSize.Level1)
{
    auto& scheduler = BootVerifyScheduler::GetInstance();
    scheduler.bundleInfoMap_[TEST_BUNDLE_NAME] = std::make_shared<BundleInfoInner>();
    scheduler.bundleInfoMap_[TEST_BUNDLE_NAME]->tokenIds = {TEST_TOKEN_ID};
    scheduler.bundleNoCachedInfoMap_[TEST_BUNDLE_NAME] = BundleNoCachedInfo {};
    HapTokenInfoItem item;
    item.tokenId = TEST_TOKEN_ID;
    item.userId = 100;
    item.bundleName = TEST_BUNDLE_NAME;
    item.instIndex = 0;
    item.dlpType = DLP_COMMON;
    item.version = DEFAULT_TOKEN_VERSION_VALUE;
    item.apiVersion = 12;
    item.tokenAttr = 0;
    item.uid = TEST_UID;
    item.migrated = true;
    scheduler.hapTokenInfoMap_[TEST_TOKEN_ID] = item;
    scheduler.requestedPermData_[TEST_TOKEN_ID] = {};
    scheduler.extendedPermMap_[TEST_TOKEN_ID] = {};
    BundleNoCachedInfo noCachedInfo;
    std::vector<HapTokenInfo> hapInfoCache;
    std::vector<std::vector<BriefPermData>> permBriefDataListCache;
    std::vector<std::vector<PermissionWithValue>> extendPermListCache;
    std::vector<SpmDataParam> params;
    EXPECT_EQ(RET_SUCCESS, scheduler.BuildSpmParams(TEST_BUNDLE_NAME, noCachedInfo, hapInfoCache,
        permBriefDataListCache, extendPermListCache, params));
    EXPECT_EQ(1U, params.size());
}

HWTEST_F(BootVerifySchedulerTest, BuildSpmParams002, TestSize.Level1)
{
    BundleNoCachedInfo noCachedInfo;
    std::vector<HapTokenInfo> hapInfoCache;
    std::vector<std::vector<BriefPermData>> permBriefDataListCache;
    std::vector<std::vector<PermissionWithValue>> extendPermListCache;
    std::vector<SpmDataParam> params;
    EXPECT_EQ(ERR_BUNDLE_NOT_EXIST, BootVerifyScheduler::GetInstance().BuildSpmParams(TEST_BUNDLE_NAME,
        noCachedInfo, hapInfoCache, permBriefDataListCache, extendPermListCache, params));
}

HWTEST_F(BootVerifySchedulerTest, AddSpmDataAndCommitCache001, TestSize.Level1)
{
    auto& scheduler = BootVerifyScheduler::GetInstance();
    scheduler.bundleInfoMap_[TEST_BUNDLE_NAME] = std::make_shared<BundleInfoInner>();
    scheduler.bundleInfoMap_[TEST_BUNDLE_NAME]->tokenIds.clear();
    scheduler.bundleNoCachedInfoMap_[TEST_BUNDLE_NAME] = BundleNoCachedInfo {};
    scheduler.isVerifiedMap_[TEST_BUNDLE_NAME] = false;
    scheduler.isVerifyingMap_[TEST_BUNDLE_NAME] = true;
    EXPECT_EQ(RET_SUCCESS, scheduler.AddSpmDataAndCommitCache(TEST_BUNDLE_NAME, {}));
    EXPECT_TRUE(scheduler.isVerifiedMap_[TEST_BUNDLE_NAME]);
}

HWTEST_F(BootVerifySchedulerTest, SplitBundleList001, TestSize.Level1)
{
    auto splitList = BootVerifyScheduler::SplitBundleList({ "a", "b", "c" }, 0);
    EXPECT_TRUE(splitList.empty());
}

HWTEST_F(BootVerifySchedulerTest, GetVerifyTaskResult001, TestSize.Level1)
{
    EXPECT_EQ(ERR_PARAM_INVALID, BootVerifyScheduler::GetVerifyTaskResult({ RET_SUCCESS, ERR_PARAM_INVALID }));
}

HWTEST_F(BootVerifySchedulerTest, VerifySingleBundle001, TestSize.Level1)
{
    auto& scheduler = BootVerifyScheduler::GetInstance();
    scheduler.bundleInfoMap_[TEST_BUNDLE_NAME] = BuildBundleInfo({ TEST_TOKEN_ID });
    scheduler.hapTokenInfoMap_[TEST_TOKEN_ID] = BuildHapTokenInfoItem(TEST_TOKEN_ID);
    scheduler.requestedPermData_[TEST_TOKEN_ID] = {};
    scheduler.extendedPermMap_[TEST_TOKEN_ID] = {};

    BundleSignInfo updatedInfo = BuildSignInfo();
    VerifiedBundleState state;
    EXPECT_EQ(RET_SUCCESS, scheduler.VerifySingleBundle(TEST_BUNDLE_NAME, updatedInfo, state));
    EXPECT_EQ(TEST_BUNDLE_NAME, state.bundleName);
    EXPECT_TRUE(scheduler.bundleNoCachedInfoMap_.find(TEST_BUNDLE_NAME) != scheduler.bundleNoCachedInfoMap_.end());
}

HWTEST_F(BootVerifySchedulerTest, ReconcileVerifiedBundleCache001, TestSize.Level1)
{
    auto& scheduler = BootVerifyScheduler::GetInstance();
    scheduler.bundleInfoMap_[TEST_BUNDLE_NAME] = BuildBundleInfo({ TEST_TOKEN_ID });
    scheduler.hapTokenInfoMap_[TEST_TOKEN_ID] = BuildHapTokenInfoItem(TEST_TOKEN_ID);
    scheduler.requestedPermData_[TEST_TOKEN_ID] = {};
    scheduler.extendedPermMap_[TEST_TOKEN_ID] = {};

    BundleSignInfo updatedInfo = BuildSignInfo();
    VerifiedBundleState verifyState;
    ASSERT_EQ(RET_SUCCESS, scheduler.VerifySingleBundle(TEST_BUNDLE_NAME, updatedInfo, verifyState));
    auto oldNoCachedInfo = scheduler.bundleNoCachedInfoMap_[TEST_BUNDLE_NAME];

    HapPolicy policy;
    BundleParam param;
    TrustedBundleInfoInner trustedInfo;
    bool isChanged = false;
    trustedInfo.bootstrapInfo = std::make_shared<Security::Verify::BootstrapInfo>();
    trustedInfo.bootstrapInfo->Load(updatedInfo.persistDataList[0].data(), updatedInfo.persistDataList[0].size());
    ASSERT_EQ(RET_SUCCESS, HapSignVerifyManager::GetInstance().CheckHapsSignInfo(
        updatedInfo.pathList[0], Verify::VerifyType::Fast, -1, trustedInfo, isChanged));
    ASSERT_EQ(RET_SUCCESS, HapSignVerifyManager::GetInstance().BuildHapPolicy({ trustedInfo }, policy, param));

    VerifiedBundleState state;
    EXPECT_EQ(RET_SUCCESS, scheduler.ReconcileVerifiedBundleCache(TEST_BUNDLE_NAME, policy, param, state));
    EXPECT_TRUE(scheduler.bundleNoCachedInfoMap_.find(TEST_BUNDLE_NAME) != scheduler.bundleNoCachedInfoMap_.end());
    EXPECT_TRUE(scheduler.bundleInfoMap_[TEST_BUNDLE_NAME] != nullptr);
    EXPECT_EQ(oldNoCachedInfo.ownerid, scheduler.bundleNoCachedInfoMap_[TEST_BUNDLE_NAME].ownerid);
}

HWTEST_F(BootVerifySchedulerTest, VerifyBundleWithState001, TestSize.Level1)
{
    auto& scheduler = BootVerifyScheduler::GetInstance();
    scheduler.bundleInfoMap_[TEST_BUNDLE_NAME] = BuildBundleInfo({});
    scheduler.bundleSignInfoMap_[TEST_BUNDLE_NAME] = BuildSignInfo();
    scheduler.isVerifiedMap_[TEST_BUNDLE_NAME] = false;
    scheduler.isVerifyingMap_[TEST_BUNDLE_NAME] = false;

    EXPECT_EQ(RET_SUCCESS, scheduler.VerifyBundleWithState(TEST_BUNDLE_NAME));
    EXPECT_TRUE(scheduler.isVerifiedMap_[TEST_BUNDLE_NAME]);
    EXPECT_FALSE(scheduler.isVerifyingMap_[TEST_BUNDLE_NAME]);
}

HWTEST_F(BootVerifySchedulerTest, VerifyBundleWithState002, TestSize.Level1)
{
    auto& scheduler = BootVerifyScheduler::GetInstance();
    scheduler.bundleInfoMap_[TEST_BUNDLE_NAME] = BuildBundleInfo({ TEST_TOKEN_ID });
    scheduler.bundleSignInfoMap_[TEST_BUNDLE_NAME] = BuildSignInfo();
    scheduler.hapTokenInfoMap_[TEST_TOKEN_ID] = BuildHapTokenInfoItem(TEST_TOKEN_ID);
    scheduler.requestedPermData_[TEST_TOKEN_ID] = { BriefPermData {
        .permCode = GetPermCode("ohos.permission.CAMERA"),
        .status = PERMISSION_DENIED,
        .flag = PERMISSION_DEFAULT_FLAG,
        .type = 0 } };
    scheduler.extendedPermMap_[TEST_TOKEN_ID] = {};
    scheduler.isVerifiedMap_[TEST_BUNDLE_NAME] = false;
    scheduler.isVerifyingMap_[TEST_BUNDLE_NAME] = false;

    EXPECT_EQ(RET_SUCCESS, scheduler.VerifyBundleWithState(TEST_BUNDLE_NAME));
    EXPECT_EQ(0U, GetMockDbState().deleteAndInsertCallCount);
    EXPECT_TRUE(scheduler.isVerifiedMap_[TEST_BUNDLE_NAME]);
    EXPECT_FALSE(scheduler.isVerifyingMap_[TEST_BUNDLE_NAME]);
}

HWTEST_F(BootVerifySchedulerTest, VerifyBundleWithState003, TestSize.Level1)
{
    auto& scheduler = BootVerifyScheduler::GetInstance();
    scheduler.bundleInfoMap_[TEST_BUNDLE_NAME] = BuildBundleInfo({ TEST_TOKEN_ID });
    auto hapInfo = BuildHapTokenInfoItem(TEST_TOKEN_ID);
    hapInfo.apl = APL_SYSTEM_CORE;
    scheduler.bundleSignInfoMap_[TEST_BUNDLE_NAME] = BuildSignInfo();
    scheduler.hapTokenInfoMap_[TEST_TOKEN_ID] = hapInfo;
    scheduler.requestedPermData_[TEST_TOKEN_ID] = { BriefPermData {
        .permCode = GetPermCode("ohos.permission.MICROPHONE"),
        .status = PERMISSION_DENIED,
        .flag = PERMISSION_DEFAULT_FLAG,
        .type = 0 } };
    scheduler.extendedPermMap_[TEST_TOKEN_ID] = {};
    scheduler.isVerifiedMap_[TEST_BUNDLE_NAME] = false;
    scheduler.isVerifyingMap_[TEST_BUNDLE_NAME] = false;

    EXPECT_EQ(RET_SUCCESS, scheduler.VerifyBundleWithState(TEST_BUNDLE_NAME));
    EXPECT_EQ(1U, GetMockDbState().deleteAndInsertCallCount);
    ASSERT_FALSE(GetMockDbState().lastDeleteInfos.empty());
    ASSERT_FALSE(GetMockDbState().lastAddInfos.empty());

    bool hasHapInfoUpdate = false;
    bool hasPermStateUpdate = false;
    for (const auto& addInfo : GetMockDbState().lastAddInfos) {
        if (addInfo.addType == AtmDataType::ACCESSTOKEN_HAP_INFO) {
            hasHapInfoUpdate = true;
        }
        if (addInfo.addType == AtmDataType::ACCESSTOKEN_PERMISSION_STATE) {
            hasPermStateUpdate = true;
        }
    }
    EXPECT_TRUE(hasHapInfoUpdate);
    EXPECT_TRUE(hasPermStateUpdate);
    EXPECT_TRUE(scheduler.isVerifiedMap_[TEST_BUNDLE_NAME]);
    EXPECT_FALSE(scheduler.isVerifyingMap_[TEST_BUNDLE_NAME]);
}

HWTEST_F(BootVerifySchedulerTest, VerifyBundleList001, TestSize.Level1)
{
    auto& scheduler = BootVerifyScheduler::GetInstance();
    scheduler.bundleInfoMap_[TEST_BUNDLE_NAME] = BuildBundleInfo({});
    scheduler.bundleSignInfoMap_[TEST_BUNDLE_NAME] = BuildSignInfo();
    scheduler.isVerifiedMap_[TEST_BUNDLE_NAME] = false;
    scheduler.isVerifyingMap_[TEST_BUNDLE_NAME] = false;

    std::vector<VerifiedBundleState> stateList;
    EXPECT_EQ(RET_SUCCESS, scheduler.VerifyBundleList({ TEST_BUNDLE_NAME }, stateList));
    ASSERT_EQ(1U, stateList.size());
    EXPECT_EQ(TEST_BUNDLE_NAME, stateList[0].bundleName);
}

} // namespace AccessToken
} // namespace Security
} // namespace OHOS
