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
#include "parameter.h"
#define private public
#include "accesstoken_id_manager.h"
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
constexpr AccessTokenID TEST_TOKEN_ID = 0x20000001;
constexpr AccessTokenID TEST_TOKEN_ID_2 = 0x20000002;
constexpr AccessTokenID TEST_TOKEN_ID_3 = 0x20000003;
constexpr const char* APP_VERIFY_PARAM = "accesstoken.permission.appverify";
constexpr uint32_t PARAM_VALUE_MAX_LEN = 32;
constexpr uint32_t TEST_UID = 20010001;
#ifdef SPM_DATA_ENABLE
constexpr int32_t INVALID_UID = -1;
#endif
constexpr char DEFAULT_TOKEN_VERSION_VALUE = 1;
const std::string TEST_BUNDLE_NAME = "com.example.camera";
const std::string TEST_BUNDLE_NAME_2 = "com.example.music";
const std::string TEST_BUNDLE_NAME_3 = "com.example.notes";
const std::string TEST_PATH = "/data/test/camera.hap";
std::string g_appVerifyParamBackup;
}

class BootVerifySchedulerTest : public testing::Test {
public:
    static void SetUpTestCase()
    {
        char value[PARAM_VALUE_MAX_LEN] = {0};
        if (GetParameter(APP_VERIFY_PARAM, "", value, PARAM_VALUE_MAX_LEN - 1) >= 0) {
            g_appVerifyParamBackup = value;
        } else {
            g_appVerifyParamBackup.clear();
        }
    }

    static void TearDownTestCase()
    {
        if (g_appVerifyParamBackup.empty()) {
            SetParameter(APP_VERIFY_PARAM, "");
            return;
        }
        SetParameter(APP_VERIFY_PARAM, g_appVerifyParamBackup.c_str());
    }

    void SetUp() override
    {
        ResetMockDbState();
        SetParameter(APP_VERIFY_PARAM, "0");
        AccessTokenIDManager::GetInstance().ReleaseTokenId(TEST_TOKEN_ID);
        AccessTokenIDManager::GetInstance().ReleaseTokenId(TEST_TOKEN_ID_2);
        AccessTokenIDManager::GetInstance().ReleaseTokenId(TEST_TOKEN_ID_3);
        AccessTokenIDManager::GetInstance().RemoveReservedTokenId(TEST_TOKEN_ID);
        AccessTokenIDManager::GetInstance().RemoveReservedTokenId(TEST_TOKEN_ID_2);
        AccessTokenIDManager::GetInstance().RemoveReservedTokenId(TEST_TOKEN_ID_3);
        PermissionDataBrief::GetInstance().DeleteBriefPermDataByTokenId(TEST_TOKEN_ID);
        PermissionDataBrief::GetInstance().DeleteBriefPermDataByTokenId(TEST_TOKEN_ID_2);
        PermissionDataBrief::GetInstance().DeleteBriefPermDataByTokenId(TEST_TOKEN_ID_3);
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
        adapter_->verifyIsChanged_ = false;
    }

    void TearDown() override
    {
        HapSignVerifyManager::GetInstance().adapter_ = originAdapter_;
        SetParameter(APP_VERIFY_PARAM, "0");
        AccessTokenIDManager::GetInstance().ReleaseTokenId(TEST_TOKEN_ID);
        AccessTokenIDManager::GetInstance().ReleaseTokenId(TEST_TOKEN_ID_2);
        AccessTokenIDManager::GetInstance().ReleaseTokenId(TEST_TOKEN_ID_3);
        AccessTokenIDManager::GetInstance().RemoveReservedTokenId(TEST_TOKEN_ID);
        AccessTokenIDManager::GetInstance().RemoveReservedTokenId(TEST_TOKEN_ID_2);
        AccessTokenIDManager::GetInstance().RemoveReservedTokenId(TEST_TOKEN_ID_3);
        auto& scheduler = BootVerifyScheduler::GetInstance();
        scheduler.ClearBundleVerifyContext();
        scheduler.bundleSignInfoMap_.clear();
        scheduler.uidSet_.clear();
        PermissionDataBrief::GetInstance().DeleteBriefPermDataByTokenId(TEST_TOKEN_ID);
        PermissionDataBrief::GetInstance().DeleteBriefPermDataByTokenId(TEST_TOKEN_ID_2);
        PermissionDataBrief::GetInstance().DeleteBriefPermDataByTokenId(TEST_TOKEN_ID_3);
        ResetMockDbState();
    }

protected:
    GenericValues BuildHapInfoValue(AccessTokenID tokenId, const std::string& bundleName, uint32_t uid,
        int32_t apl = APL_NORMAL, uint32_t tokenAttr = 0, bool migrated = true,
        ReservedType reserved = ReservedType::NONE) const
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
        value.Put(TokenFiledConst::FIELD_RESERVED, static_cast<int32_t>(reserved));
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

/**
 * @tc.name: VerifyBundleSignInfoWhenStart001
 * @tc.desc: Verify startup verification returns DB find error when hap info loading fails.
 * @tc.type: FUNC
 */
HWTEST_F(BootVerifySchedulerTest, VerifyBundleSignInfoWhenStart001, TestSize.Level1)
{
    SetMockDbFindResult(AtmDataType::ACCESSTOKEN_HAP_INFO, ERR_PARAM_INVALID, {});
    EXPECT_EQ(ERR_PARAM_INVALID, BootVerifyScheduler::GetInstance().VerifyBundleSignInfoWhenStart());
}

/**
 * @tc.name: VerifyBundleSignInfoWhenStart002
 * @tc.desc: Verify startup verification returns permission state loading error after hap info loads.
 * @tc.type: FUNC
 */
HWTEST_F(BootVerifySchedulerTest, VerifyBundleSignInfoWhenStart002, TestSize.Level1)
{
    SetMockDbFindResult(AtmDataType::ACCESSTOKEN_HAP_INFO, RET_SUCCESS,
        {BuildHapInfoValue(TEST_TOKEN_ID, TEST_BUNDLE_NAME, TEST_UID)});
    SetMockDbFindResult(AtmDataType::ACCESSTOKEN_PERMISSION_STATE, ERR_PARAM_INVALID, {});
    EXPECT_EQ(ERR_PARAM_INVALID, BootVerifyScheduler::GetInstance().VerifyBundleSignInfoWhenStart());
}
#ifdef SPM_DATA_ENABLE

/**
 * @tc.name: VerifyBundleSignInfoWhenStart003
 * @tc.desc: Verify startup verification classifies a preinstalled bundle as high privilege
 *           and persists fixed hap info when the verified APL differs from cached hap info.
 * @tc.type: FUNC
 */
HWTEST_F(BootVerifySchedulerTest, VerifyBundleSignInfoWhenStart003, TestSize.Level1)
{
    // PrepareVerifyDb seeds cached hap info from mock DB with default APL_NORMAL.
    PrepareVerifyDb(true);
    // Mock verify result upgrades the verified APL to system_core, forcing hap info persistence.
    adapter_->apl_ = "system_core";
    EXPECT_EQ(RET_SUCCESS, BootVerifyScheduler::GetInstance().VerifyBundleSignInfoWhenStart());
    EXPECT_TRUE(BootVerifyScheduler::GetInstance().highPrivilegeBundleList_.size() == 1);
    EXPECT_TRUE(BootVerifyScheduler::GetInstance().normalBundleList_.empty());
    EXPECT_EQ(1U, GetMockDbState().deleteAndInsertCallCount);
}

/**
 * @tc.name: VerifyBundleSignInfoWhenStart004
 * @tc.desc: Verify one preinstalled bundle verify failure does not block later preinstalled bundle verification,
 *           and a later successful bundle can still finish hap info persistence.
 * @tc.type: FUNC
 */
HWTEST_F(BootVerifySchedulerTest, VerifyBundleSignInfoWhenStart004, TestSize.Level1)
{
    const std::string secondPath = "/data/test/music.hap";
    // Prepare two preinstalled high-privilege bundles in mock DB so startup verification handles them in sequence.
    SetMockDbFindResult(AtmDataType::ACCESSTOKEN_HAP_INFO, RET_SUCCESS, {
        BuildHapInfoValue(TEST_TOKEN_ID, TEST_BUNDLE_NAME, TEST_UID),
        BuildHapInfoValue(TEST_TOKEN_ID_2, TEST_BUNDLE_NAME_2, TEST_UID + 1),
    });
    SetMockDbFindResult(AtmDataType::ACCESSTOKEN_PERMISSION_STATE, RET_SUCCESS, {
        BuildPermStateValue(TEST_TOKEN_ID, "ohos.permission.CAMERA"),
        BuildPermStateValue(TEST_TOKEN_ID_2, "ohos.permission.CAMERA"),
    });
    SetMockDbFindResult(AtmDataType::ACCESSTOKEN_PERMISSION_EXTEND_VALUE, RET_SUCCESS, {});
    SetMockDbFindResult(AtmDataType::ACCESSTOKEN_HAP_PACKAGE_INFO, RET_SUCCESS, {
        BuildBundleSignValue(TEST_BUNDLE_NAME, "entry", TEST_PATH, true,
            static_cast<int32_t>(AppExecFwk::Spm::BundleType::APP),
            BuildPersistData(TEST_BUNDLE_NAME, TEST_BUNDLE_NAME)),
        BuildBundleSignValue(TEST_BUNDLE_NAME_2, "entry", secondPath, true,
            static_cast<int32_t>(AppExecFwk::Spm::BundleType::APP),
            BuildPersistData(TEST_BUNDLE_NAME_2, TEST_BUNDLE_NAME_2)),
    });
    SetMockDbFindResult(AtmDataType::ACCESSTOKEN_SYSTEM_CONFIG, RET_SUCCESS, {});
    SetMockDbFindResult(AtmDataType::ACCESSTOKEN_HAP_UNDEFINE_INFO, RET_SUCCESS, {});

    // Step 1: Fail the first bundle only during verify.
    adapter_->verifyFailPath_ = TEST_PATH;
    adapter_->verifyFailRet_ = ERR_PARAM_INVALID;
    // Step 2: Make the second bundle produce a verified APL mismatch so successful verification triggers persistence.
    adapter_->apl_ = "system_core";
    // Step 3: Verify startup flow still completes and persists the later successful bundle.
    EXPECT_EQ(RET_SUCCESS, BootVerifyScheduler::GetInstance().VerifyBundleSignInfoWhenStart());
    EXPECT_EQ(2U, BootVerifyScheduler::GetInstance().highPrivilegeBundleList_.size());
    EXPECT_EQ(1U, GetMockDbState().deleteAndInsertCallCount);
}

/**
 * @tc.name: VerifyBundleSignInfoWhenStart005
 * @tc.desc: Verify non-preinstalled bundle is classified into normal bundle list at startup.
 * @tc.type: FUNC
 */
HWTEST_F(BootVerifySchedulerTest, VerifyBundleSignInfoWhenStart005, TestSize.Level1)
{
    PrepareVerifyDb(false);
    EXPECT_EQ(RET_SUCCESS, BootVerifyScheduler::GetInstance().VerifyBundleSignInfoWhenStart());
    EXPECT_TRUE(BootVerifyScheduler::GetInstance().highPrivilegeBundleList_.empty());
    EXPECT_TRUE(BootVerifyScheduler::GetInstance().normalBundleList_.size() == 1);
}

/**
 * @tc.name: VerifyBundleSignInfoWhenStart006
 * @tc.desc: Verify startup verification skips SPM persistence for invalid uid and unmigrated bundle.
 * @tc.type: FUNC
 */
HWTEST_F(BootVerifySchedulerTest, VerifyBundleSignInfoWhenStart006, TestSize.Level1)
{
    PrepareVerifyDb(true, static_cast<uint32_t>(INVALID_UID), false);
    EXPECT_EQ(RET_SUCCESS, BootVerifyScheduler::GetInstance().VerifyBundleSignInfoWhenStart());
    // ski
    EXPECT_EQ(0U, GetMockDbState().deleteAndInsertCallCount);
    EXPECT_TRUE(BootVerifyScheduler::GetInstance().isVerifiedMap_[TEST_BUNDLE_NAME]);
}

/**
 * @tc.name: VerifyBundleSignInfoWhenStart007
 * @tc.desc: Verify startup verification persists bundle package info when verified sign data changes.
 * @tc.type: FUNC
 */
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
    adapter_->verifyIsChanged_ = false;
}

/**
 * @tc.name: VerifyBundleSignInfoWhenStart008
 * @tc.desc: Verify startup verification keeps a non-preinstalled bundle in normal bundle flow
 *           without marking it verified during the high-privilege stage.
 * @tc.type: FUNC
 */
HWTEST_F(BootVerifySchedulerTest, VerifyBundleSignInfoWhenStart008, TestSize.Level1)
{
    PrepareVerifyDb(false);
    auto& scheduler = BootVerifyScheduler::GetInstance();
    EXPECT_EQ(RET_SUCCESS, scheduler.VerifyBundleSignInfoWhenStart());
    EXPECT_TRUE(scheduler.highPrivilegeBundleList_.empty());
    EXPECT_EQ(1U, scheduler.normalBundleList_.size());
    EXPECT_EQ(TEST_BUNDLE_NAME, scheduler.normalBundleList_[0]);
    EXPECT_FALSE(scheduler.isVerifiedMap_[TEST_BUNDLE_NAME]);
    EXPECT_FALSE(scheduler.isVerifyingMap_[TEST_BUNDLE_NAME]);
    EXPECT_TRUE(scheduler.bundleInfoMap_.find(TEST_BUNDLE_NAME) != scheduler.bundleInfoMap_.end());
    EXPECT_TRUE(scheduler.bundleNoCachedInfoMap_.find(TEST_BUNDLE_NAME) != scheduler.bundleNoCachedInfoMap_.end());
}
#endif // SPM_DATA_ENABLE

/**
 * @tc.name: BuildPriorityBundleList001
 * @tc.desc: Verify priority list builder classifies preinstalled or signless bundles as high privilege
 *           and non-preinstalled signed bundles as normal.
 * @tc.type: FUNC
 */
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

/**
 * @tc.name: PreVerifyBundle001
 * @tc.desc: Verify PreVerifyBundle by bundle name succeeds after startup preparation for normal bundle.
 * @tc.type: FUNC
 */
HWTEST_F(BootVerifySchedulerTest, PreVerifyBundle001, TestSize.Level1)
{
    PrepareVerifyDb(false);
    ASSERT_EQ(RET_SUCCESS, BootVerifyScheduler::GetInstance().VerifyBundleSignInfoWhenStart());
    EXPECT_EQ(RET_SUCCESS, BootVerifyScheduler::GetInstance().PreVerifyBundle(TEST_BUNDLE_NAME));
}

/**
 * @tc.name: PreVerifyBundle002
 * @tc.desc: Verify PreVerifyBundle by token id succeeds after startup preparation for normal bundle.
 * @tc.type: FUNC
 */
HWTEST_F(BootVerifySchedulerTest, PreVerifyBundle002, TestSize.Level1)
{
    PrepareVerifyDb(false);
    ASSERT_EQ(RET_SUCCESS, BootVerifyScheduler::GetInstance().VerifyBundleSignInfoWhenStart());
    EXPECT_EQ(RET_SUCCESS, BootVerifyScheduler::GetInstance().PreVerifyBundle(TEST_TOKEN_ID));
}

/**
 * @tc.name: PreVerifyBundle003
 * @tc.desc: Verify PreVerifyBundle by token id returns success when no verification context exists.
 * @tc.type: FUNC
 */
HWTEST_F(BootVerifySchedulerTest, PreVerifyBundle003, TestSize.Level1)
{
    EXPECT_EQ(RET_SUCCESS, BootVerifyScheduler::GetInstance().PreVerifyBundle(TEST_TOKEN_ID));
}

/**
 * @tc.name: PreVerifyBundle004
 * @tc.desc: Verify PreVerifyBundle completes verification state update for cached bundle context.
 * @tc.type: FUNC
 */
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

/**
 * @tc.name: LoadVerifyDataFromDb001
 * @tc.desc: Verify LoadVerifyDataFromDb tolerates extended permission query failure.
 * @tc.type: FUNC
 */
HWTEST_F(BootVerifySchedulerTest, LoadVerifyDataFromDb001, TestSize.Level1)
{
    PrepareVerifyDb(true);
    SetMockDbFindResult(AtmDataType::ACCESSTOKEN_PERMISSION_EXTEND_VALUE, ERR_PARAM_INVALID, {});
    EXPECT_EQ(RET_SUCCESS, BootVerifyScheduler::GetInstance().LoadVerifyDataFromDb());
}

#ifdef SPM_DATA_ENABLE
HWTEST_F(BootVerifySchedulerTest, LoadVerifyDataFromDb002, TestSize.Level1)
{
    SetMockDbFindResult(AtmDataType::ACCESSTOKEN_HAP_INFO, RET_SUCCESS,
        {
            BuildHapInfoValue(TEST_TOKEN_ID, TEST_BUNDLE_NAME, TEST_UID, APL_NORMAL, 0, true,
                ReservedType::RESERVED_DATA),
            BuildHapInfoValue(TEST_TOKEN_ID_2, TEST_BUNDLE_NAME_2, static_cast<uint32_t>(INVALID_UID), APL_NORMAL, 0,
                true, ReservedType::RESERVED_IDENTITY),
        });
    SetMockDbFindResult(AtmDataType::ACCESSTOKEN_PERMISSION_STATE, RET_SUCCESS, {});
    SetMockDbFindResult(AtmDataType::ACCESSTOKEN_PERMISSION_EXTEND_VALUE, RET_SUCCESS, {});
    SetMockDbFindResult(AtmDataType::ACCESSTOKEN_HAP_PACKAGE_INFO, RET_SUCCESS, {});
    auto& scheduler = BootVerifyScheduler::GetInstance();

    EXPECT_EQ(RET_SUCCESS, scheduler.LoadVerifyDataFromDb());
    EXPECT_TRUE(scheduler.uidSet_.count(static_cast<int32_t>(TEST_UID)) > 0);
    EXPECT_TRUE(scheduler.uidSet_.count(INVALID_UID) == 0);
    EXPECT_TRUE(AccessTokenIDManager::GetInstance().IsReservedTokenId(TEST_TOKEN_ID));
    EXPECT_TRUE(AccessTokenIDManager::GetInstance().IsReservedTokenId(TEST_TOKEN_ID_2));
}
#endif

/**
 * @tc.name: RefreshBundleSignInfoMap001
 * @tc.desc: Verify RefreshBundleSignInfoMap skips invalid bundle type entries.
 * @tc.type: FUNC
 */
HWTEST_F(BootVerifySchedulerTest, RefreshBundleSignInfoMap001, TestSize.Level1)
{
    PrepareVerifyDb(true);
    GenericValues invalidBundleType = BuildBundleSignValue(TEST_BUNDLE_NAME, "entry", TEST_PATH, true, 999,
        BuildPersistData(TEST_BUNDLE_NAME, TEST_BUNDLE_NAME));
    SetMockDbFindResult(AtmDataType::ACCESSTOKEN_HAP_PACKAGE_INFO, RET_SUCCESS, {invalidBundleType});
    EXPECT_EQ(RET_SUCCESS, BootVerifyScheduler::GetInstance().RefreshBundleSignInfoMap());
    EXPECT_TRUE(BootVerifyScheduler::GetInstance().bundleSignInfoMap_[TEST_BUNDLE_NAME].bundleType.empty());
}

#ifdef SPM_DATA_ENABLE
/**
 * @tc.name: RefreshBundleSignInfoMap002
 * @tc.desc: Verify RefreshBundleSignInfoMap correctly loads valid bundle type entries.
 * @tc.type: FUNC
 */
HWTEST_F(BootVerifySchedulerTest, RefreshBundleSignInfoMap002, TestSize.Level1)
{
    PrepareVerifyDb(true);
    GenericValues atomicServiceValue = BuildBundleSignValue(TEST_BUNDLE_NAME, "entry", TEST_PATH, true,
        static_cast<int32_t>(AppExecFwk::Spm::BundleType::ATOMIC_SERVICE),
        BuildPersistData(TEST_BUNDLE_NAME, TEST_BUNDLE_NAME));
    SetMockDbFindResult(AtmDataType::ACCESSTOKEN_HAP_PACKAGE_INFO, RET_SUCCESS, {atomicServiceValue});
    auto& scheduler = BootVerifyScheduler::GetInstance();
    EXPECT_EQ(RET_SUCCESS, scheduler.RefreshBundleSignInfoMap());
    ASSERT_TRUE(scheduler.bundleSignInfoMap_.find(TEST_BUNDLE_NAME) != scheduler.bundleSignInfoMap_.end());
    ASSERT_EQ(1U, scheduler.bundleSignInfoMap_[TEST_BUNDLE_NAME].bundleType.size());
    EXPECT_EQ(static_cast<uint32_t>(AppExecFwk::Spm::BundleType::ATOMIC_SERVICE),
        scheduler.bundleSignInfoMap_[TEST_BUNDLE_NAME].bundleType[0]);
}

/**
 * @tc.name: RefreshBundleSignInfoMap003
 * @tc.desc: Verify RefreshBundleSignInfoMap correctly loads valid bundle type entries.
 * @tc.type: FUNC
 */
HWTEST_F(BootVerifySchedulerTest, RefreshBundleSignInfoMap003, TestSize.Level1)
{
    PrepareVerifyDb(true);
    GenericValues appServiceFwkValue = BuildBundleSignValue(TEST_BUNDLE_NAME, "entry", TEST_PATH, true,
        static_cast<int32_t>(AppExecFwk::Spm::BundleType::APP_SERVICE_FWK),
        BuildPersistData(TEST_BUNDLE_NAME, TEST_BUNDLE_NAME));
    SetMockDbFindResult(AtmDataType::ACCESSTOKEN_HAP_PACKAGE_INFO, RET_SUCCESS, {appServiceFwkValue});
    auto& scheduler = BootVerifyScheduler::GetInstance();
    EXPECT_EQ(RET_SUCCESS, scheduler.RefreshBundleSignInfoMap());
    ASSERT_TRUE(scheduler.bundleSignInfoMap_.find(TEST_BUNDLE_NAME) != scheduler.bundleSignInfoMap_.end());
    ASSERT_EQ(1U, scheduler.bundleSignInfoMap_[TEST_BUNDLE_NAME].bundleType.size());
    EXPECT_EQ(static_cast<uint32_t>(AppExecFwk::Spm::BundleType::APP_SERVICE_FWK),
        scheduler.bundleSignInfoMap_[TEST_BUNDLE_NAME].bundleType[0]);
}
#endif

/**
 * @tc.name: BuildSpmParams001
 * @tc.desc: Verify BuildSpmParams builds one SPM parameter set for a valid cached bundle context.
 * @tc.type: FUNC
 */
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

/**
 * @tc.name: BuildSpmParams002
 * @tc.desc: Verify BuildSpmParams returns ERR_BUNDLE_NOT_EXIST for missing bundle cache.
 * @tc.type: FUNC
 */
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

/**
 * @tc.name: AddSpmDataAndCommitCache001
 * @tc.desc: Verify AddSpmDataAndCommitCache marks a bundle verified after minimal single-bundle
 *           cache, permission, and verified-state inputs are prepared.
 * @tc.type: FUNC
 */
HWTEST_F(BootVerifySchedulerTest, AddSpmDataAndCommitCache001, TestSize.Level1)
{
    auto& scheduler = BootVerifyScheduler::GetInstance();
    // Step 1: Prepare the minimal cached bundle/token context required by BuildSpmParams.
    scheduler.bundleInfoMap_[TEST_BUNDLE_NAME] = std::make_shared<BundleInfoInner>();
    scheduler.bundleInfoMap_[TEST_BUNDLE_NAME]->tokenIds = { TEST_TOKEN_ID };
    scheduler.bundleNoCachedInfoMap_[TEST_BUNDLE_NAME] = BundleNoCachedInfo {};
    scheduler.hapTokenInfoMap_[TEST_TOKEN_ID] = BuildHapTokenInfoItem(TEST_TOKEN_ID);
    scheduler.requestedPermData_[TEST_TOKEN_ID] = {};
    scheduler.extendedPermMap_[TEST_TOKEN_ID] = {};
    scheduler.isVerifiedMap_[TEST_BUNDLE_NAME] = false;
    scheduler.isVerifyingMap_[TEST_BUNDLE_NAME] = true;
    // Step 2: Execute single-bundle SPM add and cache commit with the verified result of this bundle.
    VerifiedBundleState state;
    state.bundleName = TEST_BUNDLE_NAME;
    EXPECT_EQ(RET_SUCCESS, scheduler.AddSpmDataAndCommitCache(TEST_BUNDLE_NAME, state));
    // Step 3: Verify the bundle is marked verified after commit.
    EXPECT_TRUE(scheduler.isVerifiedMap_[TEST_BUNDLE_NAME]);
}

/**
 * @tc.name: SplitBundleList001
 * @tc.desc: Verify SplitBundleList returns empty groups when split size is zero.
 * @tc.type: FUNC
 */
HWTEST_F(BootVerifySchedulerTest, SplitBundleList001, TestSize.Level1)
{
    auto splitList = BootVerifyScheduler::SplitBundleList({ "a", "b", "c" }, 0);
    EXPECT_TRUE(splitList.empty());
}

/**
 * @tc.name: GetVerifyTaskResult001
 * @tc.desc: Verify GetVerifyTaskResult returns the first non-success task result.
 * @tc.type: FUNC
 */
HWTEST_F(BootVerifySchedulerTest, GetVerifyTaskResult001, TestSize.Level1)
{
    EXPECT_EQ(ERR_PARAM_INVALID, BootVerifyScheduler::GetVerifyTaskResult({ RET_SUCCESS, ERR_PARAM_INVALID }));
}

/**
 * @tc.name: VerifySingleBundle001
 * @tc.desc: Verify VerifySingleBundle builds verified state and refreshes bundle cache.
 * @tc.type: FUNC
 */
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

/**
 * @tc.name: ReconcileVerifiedBundleCache001
 * @tc.desc: Verify ReconcileVerifiedBundleCache updates bundle cache while preserving unchanged no-cache fields.
 * @tc.type: FUNC
 */
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

/**
 * @tc.name: VerifyBundleWithState001
 * @tc.desc: Verify VerifyBundleWithState completes cached bundle verification and updates state flags.
 * @tc.type: FUNC
 */
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

/**
 * @tc.name: VerifyBundleWithState002
 * @tc.desc: Verify VerifyBundleWithState handles cached permission data for the bundle verification path.
 * @tc.type: FUNC
 */
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

/**
 * @tc.name: VerifyBundleWithState003
 * @tc.desc: Verify VerifyBundleWithState persists hap info and permission state when verified
 *           bundle data differs from cached bundle data.
 * @tc.type: FUNC
 */
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

/**
 * @tc.name: VerifyBundleList001
 * @tc.desc: Verify VerifyBundleList records successful verification results into the per-bundle state map.
 * @tc.type: FUNC
 */
HWTEST_F(BootVerifySchedulerTest, VerifyBundleList001, TestSize.Level1)
{
    auto& scheduler = BootVerifyScheduler::GetInstance();
    scheduler.bundleInfoMap_[TEST_BUNDLE_NAME] = BuildBundleInfo({ TEST_TOKEN_ID });
    scheduler.bundleSignInfoMap_[TEST_BUNDLE_NAME] = BuildSignInfo();
    scheduler.hapTokenInfoMap_[TEST_TOKEN_ID] = BuildHapTokenInfoItem(TEST_TOKEN_ID);
    scheduler.requestedPermData_[TEST_TOKEN_ID] = {};
    scheduler.extendedPermMap_[TEST_TOKEN_ID] = {};
    scheduler.isVerifiedMap_[TEST_BUNDLE_NAME] = false;
    scheduler.isVerifyingMap_[TEST_BUNDLE_NAME] = false;

    std::map<std::string, VerifiedBundleState> stateMap;
    EXPECT_EQ(RET_SUCCESS, scheduler.VerifyBundleList({ TEST_BUNDLE_NAME }, stateMap));
    ASSERT_EQ(1U, stateMap.size());
    EXPECT_TRUE(stateMap.find(TEST_BUNDLE_NAME) != stateMap.end());
}

} // namespace AccessToken
} // namespace Security
} // namespace OHOS
