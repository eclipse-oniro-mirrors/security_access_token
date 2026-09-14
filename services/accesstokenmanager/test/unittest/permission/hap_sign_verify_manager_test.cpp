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

#include <algorithm>
#include <fstream>
#include <filesystem>

#include "access_token_error.h"
#include "app_verify_adapter.h"
#define private public
#include "hap_sign_verify_manager.h"
#undef private
#include "hap_sign_verify_helper.h"
#include "mock_app_verify_adapter.h"
#include "permission_data_brief.h"
#include "permission_map.h"
#include "provision/provision_info.h"
#include "provision/provision_verify.h"
#include "spm_module_parser.h"

using namespace testing::ext;

namespace OHOS {
namespace Security {
namespace AccessToken {
namespace {
const std::string TEST_DIR = "/data/app/el1/bundle/public/access_token_test";
const std::string TEST_PATH = "/data/app/el1/bundle/public/access_token_test/camera.hap";
}
class HapSignVerifyManagerTest : public testing::Test {
public:
    void SetUp() override {}
    void TearDown() override {}
    static void SetUpTestCase()
    {
        std::filesystem::create_directory(TEST_DIR);
        std::ofstream file(TEST_PATH);
        file << "This is test data.";
        file.close();
    }
    static void TearDownTestCase()
    {
        std::filesystem::remove_all(TEST_DIR);
    }
};

// Builds a minimal TrustedBundleInfoInner with consistent bundleName across provision/module.
// Used by CheckMultipleHaps and BuildHapPolicy002 tests as a baseline.
TrustedBundleInfoInner BuildTrustedBundleInfo(const std::string& bundleName)
{
    TrustedBundleInfoInner info;
    info.moduleData.bundleName = bundleName;
    info.moduleData.moduleName = bundleName;
    info.provisionInfo.bundleInfo.bundleName = bundleName;
    info.provisionInfo.bundleInfo.appIdentifier = "12345";
    info.provisionInfo.bundleInfo.apl = "normal";
    info.provisionInfo.distributionType = Security::Verify::NONE_TYPE;
    info.provisionInfo.type = Security::Verify::RELEASE;
    return info;
}

/**
 * @tc.name: CheckHapsSignInfo001
 * @tc.desc: Null bootstrapInfo is auto-created, provisionInfo and module fields are populated.
 * @tc.type: FUNC
 */
HWTEST_F(HapSignVerifyManagerTest, CheckHapsSignInfo001, TestSize.Level1)
{
    MockAppVerifyAdapter adapter;
    HapSignVerifyManager manager(adapter);
    TrustedBundleInfoInner info;
    bool isChanged = true;

    EXPECT_EQ(RET_SUCCESS, manager.CheckHapsSignInfo(
        HapSignVerifyManager::MakeVerifyParams(TEST_PATH, Security::Verify::VerifyType::Fast, -1),
        false, info, isChanged));
    ASSERT_NE(nullptr, info.bootstrapInfo);
    EXPECT_EQ("com.example.bundle", info.provisionInfo.bundleInfo.bundleName);
    EXPECT_EQ("mock.identifier", info.provisionInfo.bundleInfo.appIdentifier);
}

/**
 * @tc.name: CheckHapsSignInfo002
 * @tc.desc: Pre-existing bootstrapInfo pointer is reused (not replaced), provisionInfo still populated.
 * @tc.type: FUNC
 */
HWTEST_F(HapSignVerifyManagerTest, CheckHapsSignInfo002, TestSize.Level1)
{
    MockAppVerifyAdapter adapter;
    HapSignVerifyManager manager(adapter);
    TrustedBundleInfoInner info;
    info.bootstrapInfo = std::make_shared<Security::Verify::BootstrapInfo>();
    std::shared_ptr<Security::Verify::BootstrapInfo> bootstrapInfo = info.bootstrapInfo;
    bool isChanged = false;

    EXPECT_EQ(RET_SUCCESS, manager.CheckHapsSignInfo(
        HapSignVerifyManager::MakeVerifyParams(TEST_PATH, Security::Verify::VerifyType::Fast, -1),
        false, info, isChanged));
    EXPECT_EQ(bootstrapInfo, info.bootstrapInfo);
    EXPECT_EQ("com.example.bundle", info.provisionInfo.bundleInfo.bundleName);
}

/**
 * @tc.name: CheckHapsSignInfo003
 * @tc.desc: ParseHapModuleInfo is called internally; userId=-1 produces empty certPath.
 * @tc.type: FUNC
 */
HWTEST_F(HapSignVerifyManagerTest, CheckHapsSignInfo003, TestSize.Level1)
{
    MockAppVerifyAdapter adapter;
    HapSignVerifyManager manager(adapter);
    TrustedBundleInfoInner info;
    bool isChanged = false;

    EXPECT_EQ(RET_SUCCESS, manager.CheckHapsSignInfo(
        HapSignVerifyManager::MakeVerifyParams(TEST_PATH, Security::Verify::VerifyType::Fast, -1),
        false, info, isChanged));
    EXPECT_TRUE(adapter.isParseCalled_);
    EXPECT_EQ("", adapter.lastCertPath_);
    EXPECT_EQ("entry", info.moduleData.moduleName);
}

/**
 * @tc.name: CheckHapsSignInfo004
 * @tc.desc: VerifyHap failure is propagated and ParseHapModuleInfo is never called.
 * @tc.type: FUNC
 */
HWTEST_F(HapSignVerifyManagerTest, CheckHapsSignInfo004, TestSize.Level1)
{
    MockAppVerifyAdapter adapter;
    adapter.verifyRet_ = AccessTokenError::ERR_PARAM_INVALID;
    HapSignVerifyManager manager(adapter);
    TrustedBundleInfoInner info;
    bool isChanged = false;

    EXPECT_NE(RET_SUCCESS,
        manager.CheckHapsSignInfo(
            HapSignVerifyManager::MakeVerifyParams(TEST_PATH, Security::Verify::VerifyType::Fast, -1),
            false, info, isChanged));
    EXPECT_FALSE(adapter.isParseCalled_);
}

/**
 * @tc.name: CheckHapsSignInfo005
 * @tc.desc: ParseHapModuleInfo failure is propagated after successful verify.
 * @tc.type: FUNC
 */
HWTEST_F(HapSignVerifyManagerTest, CheckHapsSignInfo005, TestSize.Level1)
{
    MockAppVerifyAdapter adapter;
    adapter.parseRet_ = AccessTokenError::ERR_PARAM_INVALID;
    HapSignVerifyManager manager(adapter);
    TrustedBundleInfoInner info;
    bool isChanged = true;

    EXPECT_NE(RET_SUCCESS,
        manager.CheckHapsSignInfo(
            HapSignVerifyManager::MakeVerifyParams(TEST_PATH, Security::Verify::VerifyType::Fast, -1),
            false, info, isChanged));
    EXPECT_TRUE(adapter.isParseCalled_);
}


/**
 * @tc.name: CheckHapsSignInfo006
 * @tc.desc: Hap path not allowed.
 * @tc.type: FUNC
 */
HWTEST_F(HapSignVerifyManagerTest, CheckHapsSignInfo006, TestSize.Level1)
{
    MockAppVerifyAdapter adapter;
    HapSignVerifyManager manager(adapter);
    TrustedBundleInfoInner info;
    bool isChanged = true;
    
    // The check is bypassed in UT, so here is a success
    EXPECT_EQ(ERR_VERIFY_FILE_NOT_EXIST,
        manager.CheckHapsSignInfo(
            HapSignVerifyManager::MakeVerifyParams("bad_path.hap", Security::Verify::VerifyType::Fast, -1),
            false, info, isChanged));
}

/**
 * @tc.name: CheckMultipleHaps001
 * @tc.desc: Mismatched appIdentifier across haps returns ERR_PARAM_INVALID.
 * @tc.type: FUNC
 */
HWTEST_F(HapSignVerifyManagerTest, CheckMultipleHaps001, TestSize.Level1)
{
    HapSignVerifyManager& manager = HapSignVerifyManager::GetInstance();
    TrustedBundleInfoInner info1 = BuildTrustedBundleInfo("bundle");

    TrustedBundleInfoInner info2 = info1;
    info2.provisionInfo.bundleInfo.appIdentifier = "identifier2";
    info2.provisionInfo.appId = "app-id-desc2";
    std::vector<TrustedBundleInfoInner> infos_mismatch = {info1, info2};
    EXPECT_EQ(AccessTokenError::ERR_PARAM_INVALID, manager.CheckMultipleHaps(infos_mismatch));
}

/**
 * @tc.name: CheckMultipleHaps002
 * @tc.desc: Empty infos returns ERR_PARAM_INVALID; identical infos returns RET_SUCCESS.
 * @tc.type: FUNC
 */
HWTEST_F(HapSignVerifyManagerTest, CheckMultipleHaps002, TestSize.Level1)
{
    HapSignVerifyManager& manager = HapSignVerifyManager::GetInstance();
    TrustedBundleInfoInner info = BuildTrustedBundleInfo("bundle");

    std::vector<TrustedBundleInfoInner> emptyInfos;
    EXPECT_EQ(AccessTokenError::ERR_PARAM_INVALID, manager.CheckMultipleHaps(emptyInfos));
    std::vector<TrustedBundleInfoInner> infos = {info, info};
    EXPECT_EQ(RET_SUCCESS, manager.CheckMultipleHaps(infos));
}

/**
 * @tc.name: CheckMultipleHaps003
 * @tc.desc: Mismatched bundleName, apl, appFeature, distributionType class, or provision type
 *           returns ERR_PARAM_INVALID.
 * @tc.type: FUNC
 */
HWTEST_F(HapSignVerifyManagerTest, CheckMultipleHaps003, TestSize.Level1)
{
    HapSignVerifyManager& manager = HapSignVerifyManager::GetInstance();
    TrustedBundleInfoInner info1 = BuildTrustedBundleInfo("bundle");
    TrustedBundleInfoInner info2 = info1;
    info2.provisionInfo.bundleInfo.bundleName = "other.bundle";
    std::vector<TrustedBundleInfoInner> infos = {info1, info2};
    EXPECT_EQ(AccessTokenError::ERR_PARAM_INVALID, manager.CheckMultipleHaps(infos));

    info2 = info1;
    info2.provisionInfo.bundleInfo.apl = "system_basic";
    infos = {info1, info2};
    EXPECT_EQ(AccessTokenError::ERR_PARAM_INVALID, manager.CheckMultipleHaps(infos));

    info2 = info1;
    info2.provisionInfo.bundleInfo.appFeature = "hos_system_app";
    infos = {info1, info2};
    EXPECT_EQ(AccessTokenError::ERR_PARAM_INVALID, manager.CheckMultipleHaps(infos));

    info2 = info1;
    info2.provisionInfo.distributionType = Security::Verify::ENTERPRISE;
    infos = {info1, info2};
    EXPECT_EQ(AccessTokenError::ERR_PARAM_INVALID, manager.CheckMultipleHaps(infos));

    info2 = info1;
    info2.provisionInfo.type = Security::Verify::DEBUG;
    infos = {info1, info2};
    EXPECT_EQ(AccessTokenError::ERR_PARAM_INVALID, manager.CheckMultipleHaps(infos));
}

/**
 * @tc.name: CheckMultipleHaps004
 * @tc.desc: Different distributionType values within the same class (enterprise or non-enterprise)
 *           are allowed and return RET_SUCCESS.
 * @tc.type: FUNC
 */
HWTEST_F(HapSignVerifyManagerTest, CheckMultipleHaps004, TestSize.Level1)
{
    HapSignVerifyManager& manager = HapSignVerifyManager::GetInstance();
    TrustedBundleInfoInner info1 = BuildTrustedBundleInfo("bundle");
    TrustedBundleInfoInner info2 = info1;
    info2.provisionInfo.distributionType = Security::Verify::APP_GALLERY;
    std::vector<TrustedBundleInfoInner> infos = {info1, info2};
    EXPECT_EQ(RET_SUCCESS, manager.CheckMultipleHaps(infos));

    info1.provisionInfo.distributionType = Security::Verify::ENTERPRISE;
    info2 = info1;
    info2.provisionInfo.distributionType = Security::Verify::ENTERPRISE_NORMAL;
    infos = {info1, info2};
    EXPECT_EQ(RET_SUCCESS, manager.CheckMultipleHaps(infos));

    info2.provisionInfo.distributionType = Security::Verify::ENTERPRISE_MDM;
    infos = {info1, info2};
    EXPECT_EQ(RET_SUCCESS, manager.CheckMultipleHaps(infos));
}

/**
 * @tc.name: CheckMultipleHaps005
 * @tc.desc: appIdentifier differs but appId is identical across haps returns RET_SUCCESS.
 * @tc.type: FUNC
 */
HWTEST_F(HapSignVerifyManagerTest, CheckMultipleHaps005, TestSize.Level1)
{
    HapSignVerifyManager& manager = HapSignVerifyManager::GetInstance();
    TrustedBundleInfoInner info1 = BuildTrustedBundleInfo("bundle");
    info1.provisionInfo.appId = "app-id-desc";
    TrustedBundleInfoInner info2 = info1;
    info2.provisionInfo.bundleInfo.appIdentifier = "identifier2";
    std::vector<TrustedBundleInfoInner> infos = {info1, info2};
    EXPECT_EQ(RET_SUCCESS, manager.CheckMultipleHaps(infos));
}

constexpr int32_t TEST_API_VERSION = 12;

static std::pair<TrustedBundleInfoInner, TrustedBundleInfoInner> BuildCameraBundleInfos()
{
    TrustedBundleInfoInner info1;
    info1.moduleData.bundleName = "com.example.camera";
    info1.moduleData.moduleName = "entry";
    info1.moduleData.apiTargetVersion = TEST_API_VERSION;
    info1.moduleData.bundleType = AppExecFwk::Spm::BundleType::ATOMIC_SERVICE;
    info1.moduleData.definePermission = {
        AppExecFwk::Spm::DefinePermission {
            .name = "ohos.permission.CAMERA", .grantMode = "user_grant", .availableLevel = "normal",
        },
        AppExecFwk::Spm::DefinePermission {
            .name = "ohos.permission.BAD", .grantMode = "user_grant", .availableLevel = "normal",
        }
    };
    info1.moduleData.requestPermission = {
        AppExecFwk::Spm::RequestPermission { .name = "ohos.permission.CAMERA", .requiredFeature = "", },
        AppExecFwk::Spm::RequestPermission { .name = "ohos.permission.BAD", .requiredFeature = "", }
    };
    info1.provisionInfo.bundleInfo.bundleName = "com.example.camera";
    info1.provisionInfo.bundleInfo.appIdentifier = "12345";
    info1.provisionInfo.bundleInfo.apl = "system_basic";
    info1.provisionInfo.bundleInfo.appFeature = "hos_system_app";
    info1.provisionInfo.acls.allowedAcls = { "ohos.permission.CAMERA" };
    info1.provisionInfo.appServiceCapabilities = "{\"ohos.permission.ACCESS_CERT_MANAGER\":\"cert\"}";
    info1.provisionInfo.appId = "app-id-desc";
    info1.provisionInfo.distributionType = Security::Verify::APP_GALLERY;
    info1.provisionInfo.type = Security::Verify::DEBUG;

    TrustedBundleInfoInner info2 = info1;
    info2.moduleData.moduleName = "feature";
    info2.moduleData.definePermission = {
        AppExecFwk::Spm::DefinePermission {
            .name = "ohos.permission.CAMERA", .grantMode = "user_grant", .availableLevel = "normal",
        },
        AppExecFwk::Spm::DefinePermission {
            .name = "ohos.permission.MICROPHONE", .grantMode = "system_grant", .availableLevel = "system_basic",
        }
    };
    info2.moduleData.requestPermission = {
        AppExecFwk::Spm::RequestPermission { .name = "ohos.permission.CAMERA", .requiredFeature = "", },
        AppExecFwk::Spm::RequestPermission { .name = "ohos.permission.MICROPHONE", .requiredFeature = "mic", }
    };
    info2.provisionInfo.acls.allowedAcls = { "ohos.permission.MICROPHONE", "ohos.permission.CAMERA" };
    info2.provisionInfo.appServiceCapabilities =
        "{\"ohos.permission.ACCESS_CERT_MANAGER\":\"shadow\","
        "\"ohos.permission.ACCESS_STORAGE\":\"storage\"}";
    return {info1, info2};
}

/**
 * @tc.name: BuildHapPolicy001
 * @tc.desc: Full hap path with 2 modules exercising dedup, ACLs, extended ACLs,
 *           system app, atomic service, and debug.
 * @tc.type: FUNC
 */
HWTEST_F(HapSignVerifyManagerTest, BuildHapPolicy001, TestSize.Level1)
{
    auto [info1, info2] = BuildCameraBundleInfos();
    HapSignVerifyManager& manager = HapSignVerifyManager::GetInstance();
    HapPolicy policy;
    BundleParam param;
    EXPECT_EQ(RET_SUCCESS, manager.BuildHapPolicy({info1, info2}, policy, param));
    EXPECT_EQ(APL_SYSTEM_BASIC, policy.apl);
    EXPECT_EQ(3u, policy.permList.size());
    EXPECT_EQ(3u, policy.permStateList.size());
    ASSERT_EQ(2u, policy.aclRequestedList.size());
    ASSERT_EQ(1u, policy.aclExtendedMap.size());
    EXPECT_TRUE(policy.preAuthorizationInfo.empty());
    EXPECT_FALSE(policy.isDebugGrant);
    EXPECT_EQ(TEST_API_VERSION, param.apiVersion);
    EXPECT_TRUE(param.isSystem);
    EXPECT_TRUE(param.isAtomicService);
    EXPECT_EQ("com.example.camera_app-id-desc", param.appId);
    EXPECT_EQ(Security::Verify::AppDistType::APP_GALLERY, param.distributionType);
    EXPECT_TRUE(param.isDebug);
    EXPECT_EQ(12345u, param.appIdentifier);
}

/**
 * @tc.name: BuildHapPolicy002
 * @tc.desc: Edge cases including empty infos, fallback bundleName,
 *           system_core APL, manual_settings, MDM, and malformed JSON.
 * @tc.type: FUNC
 */
HWTEST_F(HapSignVerifyManagerTest, BuildHapPolicy002, TestSize.Level1)
{
    HapSignVerifyManager& manager = HapSignVerifyManager::GetInstance();
    HapPolicy policy;
    BundleParam param;

    EXPECT_EQ(AccessTokenError::ERR_PARAM_INVALID, manager.BuildHapPolicy({}, policy, param));

    TrustedBundleInfoInner info = BuildTrustedBundleInfo("com.example.policy");
    info.provisionInfo.bundleInfo.bundleName.clear();
    info.moduleData.bundleName.clear();
    info.moduleData.moduleName = "fallback.module";
    info.provisionInfo.bundleInfo.appIdentifier = "invalid-owner";
    info.provisionInfo.bundleInfo.apl = "system_core";
    info.provisionInfo.bundleInfo.appFeature.clear();
    info.provisionInfo.appServiceCapabilities = "{invalid json";
    info.moduleData.bundleType = AppExecFwk::Spm::BundleType::APP;
    info.moduleData.definePermission = {
        AppExecFwk::Spm::DefinePermission {
            .name = "ohos.permission.TEST_MANUAL",
            .grantMode = "manual_settings",
            .availableLevel = "system_core",
            .availableType = "mdm",
        }
    };

    ASSERT_EQ(RET_SUCCESS, manager.BuildHapPolicy({info}, policy, param));
    ASSERT_EQ(1u, policy.permList.size());
    EXPECT_EQ(APL_SYSTEM_CORE, policy.apl);
    EXPECT_EQ(GrantMode::MANUAL_SETTINGS, policy.permList[0].grantMode);
    EXPECT_EQ(ATokenAvailableTypeEnum::MDM, policy.permList[0].availableType);
    EXPECT_TRUE(policy.aclExtendedMap.empty());
    EXPECT_EQ("fallback.module", param.bundleName);
    EXPECT_FALSE(param.isSystem);
    EXPECT_FALSE(param.isAtomicService);
    EXPECT_FALSE(param.isDebug);
    EXPECT_EQ(0u, param.appIdentifier);
}

/**
 * @tc.name: BuildHapPolicy003
 * @tc.desc: CheckMultipleHaps sorts: puts entry first, then remaining modules alphabetically.
 *           Input: feature, entry, alpha → after sort: entry, alpha, feature.
 * @tc.type: FUNC
 */
HWTEST_F(HapSignVerifyManagerTest, BuildHapPolicy003, TestSize.Level1)
{
    HapSignVerifyManager& manager = HapSignVerifyManager::GetInstance();

    auto makeInfo = [](const std::string& bundleName, const std::string& moduleName,
        const std::string& permName) {
        TrustedBundleInfoInner info;
        info.moduleData.bundleName = bundleName;
        info.moduleData.moduleName = moduleName;
        info.moduleData.definePermission = {
            AppExecFwk::Spm::DefinePermission {
                .name = permName,
                .grantMode = "system_grant",
                .availableLevel = "normal",
            }
        };
        info.moduleData.requestPermission = {
            AppExecFwk::Spm::RequestPermission {
                .name = permName,
            }
        };
        info.provisionInfo.bundleInfo.bundleName = bundleName;
        info.provisionInfo.bundleInfo.appIdentifier = "12345";
        info.provisionInfo.bundleInfo.apl = "normal";
        info.provisionInfo.type = Security::Verify::RELEASE;
        info.provisionInfo.distributionType = Security::Verify::NONE_TYPE;
        return info;
    };

    TrustedBundleInfoInner infoFeature = makeInfo("com.example", "feature", "ohos.permission.CAMERA");
    TrustedBundleInfoInner infoEntry = makeInfo("com.example", "entry", "ohos.permission.MICROPHONE");
    TrustedBundleInfoInner infoAlpha = makeInfo("com.example", "alpha", "ohos.permission.LOCATION");

    std::vector<TrustedBundleInfoInner> infos = {infoFeature, infoEntry, infoAlpha};
    ASSERT_EQ(RET_SUCCESS, manager.CheckMultipleHaps(infos));

    HapPolicy policy;
    BundleParam param;
    ASSERT_EQ(RET_SUCCESS, manager.BuildHapPolicy(infos, policy, param));

    ASSERT_EQ(3u, policy.permList.size());
    EXPECT_EQ("ohos.permission.MICROPHONE", policy.permList[0].permissionName);
    EXPECT_EQ("ohos.permission.LOCATION", policy.permList[1].permissionName);
    EXPECT_EQ("ohos.permission.CAMERA", policy.permList[2].permissionName);

    ASSERT_EQ(3u, policy.permStateList.size());
    EXPECT_EQ("ohos.permission.MICROPHONE", policy.permStateList[0].permissionName);
    EXPECT_EQ("ohos.permission.LOCATION", policy.permStateList[1].permissionName);
    EXPECT_EQ("ohos.permission.CAMERA", policy.permStateList[2].permissionName);
}

/**
 * @tc.name: BuildHapPolicy004
 * @tc.desc: CheckMultipleHaps without "entry" sorts purely alphabetically.
 *           Input: bravo, alpha → after sort: alpha, bravo.
 * @tc.type: FUNC
 */
HWTEST_F(HapSignVerifyManagerTest, BuildHapPolicy004, TestSize.Level1)
{
    HapSignVerifyManager& manager = HapSignVerifyManager::GetInstance();

    auto makeInfo = [](const std::string& bundleName, const std::string& moduleName,
        const std::string& permName) {
        TrustedBundleInfoInner info;
        info.moduleData.bundleName = bundleName;
        info.moduleData.moduleName = moduleName;
        info.moduleData.definePermission = {
            AppExecFwk::Spm::DefinePermission {
                .name = permName,
                .grantMode = "system_grant",
                .availableLevel = "normal",
            }
        };
        info.moduleData.requestPermission = {
            AppExecFwk::Spm::RequestPermission {
                .name = permName,
            }
        };
        info.provisionInfo.bundleInfo.bundleName = bundleName;
        info.provisionInfo.bundleInfo.appIdentifier = "12345";
        info.provisionInfo.bundleInfo.apl = "normal";
        info.provisionInfo.type = Security::Verify::RELEASE;
        info.provisionInfo.distributionType = Security::Verify::NONE_TYPE;
        return info;
    };

    TrustedBundleInfoInner infoBravo = makeInfo("com.example", "bravo", "ohos.permission.MICROPHONE");
    TrustedBundleInfoInner infoAlpha = makeInfo("com.example", "alpha", "ohos.permission.CAMERA");

    std::vector<TrustedBundleInfoInner> infos = {infoBravo, infoAlpha};
    ASSERT_EQ(RET_SUCCESS, manager.CheckMultipleHaps(infos));

    HapPolicy policy;
    BundleParam param;
    ASSERT_EQ(RET_SUCCESS, manager.BuildHapPolicy(infos, policy, param));

    ASSERT_EQ(2u, policy.permList.size());
    EXPECT_EQ("ohos.permission.CAMERA", policy.permList[0].permissionName);
    EXPECT_EQ("ohos.permission.MICROPHONE", policy.permList[1].permissionName);

    ASSERT_EQ(2u, policy.permStateList.size());
    EXPECT_EQ("ohos.permission.CAMERA", policy.permStateList[0].permissionName);
    EXPECT_EQ("ohos.permission.MICROPHONE", policy.permStateList[1].permissionName);
}

/**
 * @tc.name: BuildHapPolicy005
 * @tc.desc: CheckMultipleHaps sorts + dedup: when "entry" and "feature" both define CAMERA,
 *           the entry's definition wins because entry sorts first,
 *           and the duplicate from feature is skipped.
 *           grantMode is preserved from the winning entry.
 * @tc.type: FUNC
 */
HWTEST_F(HapSignVerifyManagerTest, BuildHapPolicy005, TestSize.Level1)
{
    auto makeInfo = [](const std::string& moduleName) {
        TrustedBundleInfoInner info;
        info.moduleData.bundleName = "com.example";
        info.moduleData.moduleName = moduleName;
        info.provisionInfo.bundleInfo.bundleName = "com.example";
        info.provisionInfo.bundleInfo.appIdentifier = "12345";
        info.provisionInfo.bundleInfo.apl = "normal";
        info.provisionInfo.type = Security::Verify::RELEASE;
        info.provisionInfo.distributionType = Security::Verify::NONE_TYPE;
        return info;
    };
    TrustedBundleInfoInner infoEntry = makeInfo("entry");
    infoEntry.moduleData.definePermission = {
        AppExecFwk::Spm::DefinePermission {
            .name = "ohos.permission.CAMERA", .grantMode = "system_grant", .availableLevel = "normal",
        }
    };
    infoEntry.moduleData.requestPermission = {
        AppExecFwk::Spm::RequestPermission { .name = "ohos.permission.CAMERA", }
    };

    TrustedBundleInfoInner infoFeature = makeInfo("feature");
    infoFeature.moduleData.definePermission = {
        AppExecFwk::Spm::DefinePermission {
            .name = "ohos.permission.CAMERA", .grantMode = "system_grant", .availableLevel = "normal",
        },
        AppExecFwk::Spm::DefinePermission {
            .name = "ohos.permission.MICROPHONE", .grantMode = "user_grant", .availableLevel = "system_basic",
        }
    };
    infoFeature.moduleData.requestPermission = {
        AppExecFwk::Spm::RequestPermission { .name = "ohos.permission.CAMERA", },
        AppExecFwk::Spm::RequestPermission { .name = "ohos.permission.MICROPHONE", }
    };

    std::vector<TrustedBundleInfoInner> infos = {infoFeature, infoEntry};
    HapSignVerifyManager& manager = HapSignVerifyManager::GetInstance();
    ASSERT_EQ(RET_SUCCESS, manager.CheckMultipleHaps(infos));

    HapPolicy policy;
    BundleParam param;
    ASSERT_EQ(RET_SUCCESS, manager.BuildHapPolicy(infos, policy, param));
    ASSERT_EQ(2u, policy.permList.size());
    EXPECT_EQ("ohos.permission.CAMERA", policy.permList[0].permissionName);
    EXPECT_EQ("ohos.permission.MICROPHONE", policy.permList[1].permissionName);
    EXPECT_EQ(GrantMode::SYSTEM_GRANT, policy.permList[0].grantMode);
    ASSERT_EQ(2u, policy.permStateList.size());
    EXPECT_EQ("ohos.permission.CAMERA", policy.permStateList[0].permissionName);
    EXPECT_EQ("ohos.permission.MICROPHONE", policy.permStateList[1].permissionName);
}

/**
 * @tc.name: CheckPermissionRequestValid001
 * @tc.desc: Single module with one request permission, normal apl, release type passes validation.
 * @tc.type: FUNC
 */
HWTEST_F(HapSignVerifyManagerTest, CheckPermissionRequestValid001, TestSize.Level1)
{
    HapSignVerifyManager& manager = HapSignVerifyManager::GetInstance();
    TrustedBundleInfoInner info;
    info.moduleData.requestPermission = {
        AppExecFwk::Spm::RequestPermission {
            .name = "ohos.permission.CAMERA",
            .requiredFeature = "",
        }
    };
    info.provisionInfo.bundleInfo.bundleName = "com.example.camera";
    info.provisionInfo.bundleInfo.apl = "normal";
    info.provisionInfo.distributionType = Security::Verify::NONE_TYPE;
    info.provisionInfo.type = Security::Verify::RELEASE;

    HapPolicy policy;
    BundleParam param;
    ASSERT_EQ(RET_SUCCESS, manager.BuildHapPolicy({info}, policy, param));
    HapInfoCheckResult result;
    EXPECT_EQ(RET_SUCCESS, manager.CheckPermissionRequestValid(info, policy, result));
}

/**
 * @tc.name: GetBundleName004
 * @tc.desc: GetBundleName falls back to moduleData.moduleName when both bundleNames are empty.
 * @tc.type: FUNC
 */
HWTEST_F(HapSignVerifyManagerTest, GetBundleName004, TestSize.Level1)
{
    TrustedBundleInfoInner info;
    info.provisionInfo.bundleInfo.bundleName.clear();
    info.moduleData.bundleName.clear();
    info.moduleData.moduleName = "only.module";
    EXPECT_EQ("only.module", info.GetBundleName());
}

/**
 * @tc.name: GetBundleType001
 * @tc.desc: GetBundleType returns the int32_t cast of moduleData.bundleType.
 * @tc.type: FUNC
 */
HWTEST_F(HapSignVerifyManagerTest, GetBundleType001, TestSize.Level1)
{
    TrustedBundleInfoInner info;
    info.moduleData.bundleType = AppExecFwk::Spm::BundleType::ATOMIC_SERVICE;
    EXPECT_EQ(static_cast<int32_t>(AppExecFwk::Spm::BundleType::ATOMIC_SERVICE), info.GetBundleType());

    info.moduleData.bundleType = AppExecFwk::Spm::BundleType::APP;
    EXPECT_EQ(static_cast<int32_t>(AppExecFwk::Spm::BundleType::APP), info.GetBundleType());
}

/**
 * @tc.name: GetApiTargetVersion001
 * @tc.desc: GetApiTargetVersion returns moduleData.apiTargetVersion.
 * @tc.type: FUNC
 */
HWTEST_F(HapSignVerifyManagerTest, GetApiTargetVersion001, TestSize.Level1)
{
    TrustedBundleInfoInner info;
    info.moduleData.apiTargetVersion = 12;
    EXPECT_EQ(12, info.GetApiTargetVersion());

    info.moduleData.apiTargetVersion = 0;
    EXPECT_EQ(0, info.GetApiTargetVersion());
}

/**
 * @tc.name: BuildOwnerId001
 * @tc.desc: BuildOwnerId returns 0 when appIdentifier is empty.
 * @tc.type: FUNC
 */
HWTEST_F(HapSignVerifyManagerTest, BuildOwnerId001, TestSize.Level1)
{
    EXPECT_EQ(0u, HapSignVerifyHelper::BuildOwnerId(""));
}

/**
 * @tc.name: ParseAclExtendedMap001
 * @tc.desc: ParseAclExtendedMap returns empty map when appServiceCapabilities is empty.
 * @tc.type: FUNC
 */
HWTEST_F(HapSignVerifyManagerTest, ParseAclExtendedMap001, TestSize.Level1)
{
    auto result = HapSignVerifyHelper::ParseAclExtendedMap("");
    EXPECT_TRUE(result.empty());
}

/**
 * @tc.name: ParseAclExtendedMap002
 * @tc.desc: ParseAclExtendedMap parses valid JSON with string-value permissions.
 * @tc.type: FUNC
 */
HWTEST_F(HapSignVerifyManagerTest, ParseAclExtendedMap002, TestSize.Level1)
{
    auto result = HapSignVerifyHelper::ParseAclExtendedMap(
        "{\"ohos.permission.ACCESS_CERT_MANAGER\":\"cert\"}");
    ASSERT_EQ(1u, result.size());
    EXPECT_EQ("cert", result["ohos.permission.ACCESS_CERT_MANAGER"]);
}

/**
 * @tc.name: ParseAclExtendedMap003
 * @tc.desc: ParseAclExtendedMap returns empty map for malformed JSON.
 * @tc.type: FUNC
 */
HWTEST_F(HapSignVerifyManagerTest, ParseAclExtendedMap003, TestSize.Level1)
{
    auto result = HapSignVerifyHelper::ParseAclExtendedMap("{invalid");
    EXPECT_TRUE(result.empty());
}

/**
 * @tc.name: ParseAclExtendedMap004
 * @tc.desc: ParseAclExtendedMap returns empty map when JSON root is not an object (array).
 * @tc.type: FUNC
 */
HWTEST_F(HapSignVerifyManagerTest, ParseAclExtendedMap004, TestSize.Level1)
{
    auto result = HapSignVerifyHelper::ParseAclExtendedMap("[\"value\"]");
    EXPECT_TRUE(result.empty());
}

/**
 * @tc.name: ParseAclExtendedMap005
 * @tc.desc: ParseAclExtendedMap skips disabled or unknown permission names,
 *           only keeping valid enabled permissions.
 * @tc.type: FUNC
 */
HWTEST_F(HapSignVerifyManagerTest, ParseAclExtendedMap005, TestSize.Level1)
{
    auto result = HapSignVerifyHelper::ParseAclExtendedMap(
        "{\"ohos.permission.INVALID_FAKE\":\"bad\","
        "\"ohos.permission.ACCESS_CERT_MANAGER\":\"cert\"}");
    ASSERT_EQ(1u, result.size());
    EXPECT_EQ("cert", result["ohos.permission.ACCESS_CERT_MANAGER"]);
    EXPECT_EQ(result.end(), result.find("ohos.permission.INVALID_FAKE"));
}

/**
 * @tc.name: ParseAclExtendedMap006
 * @tc.desc: ParseAclExtendedMap handles non-string values: number, array, boolean, null.
 *           All go through cJSON_PrintUnformatted serialization.
 * @tc.type: FUNC
 */
HWTEST_F(HapSignVerifyManagerTest, ParseAclExtendedMap006, TestSize.Level1)
{
    auto result = HapSignVerifyHelper::ParseAclExtendedMap(
        "{\"ohos.permission.ACCESS_CERT_MANAGER\":42}");
    ASSERT_EQ(1u, result.size());
    EXPECT_EQ("42", result["ohos.permission.ACCESS_CERT_MANAGER"]);
}

/**
 * @tc.name: ParseAclExtendedMap007
 * @tc.desc: ParseAclExtendedMap handles boolean and null values via serialization.
 * @tc.type: FUNC
 */
HWTEST_F(HapSignVerifyManagerTest, ParseAclExtendedMap007, TestSize.Level1)
{
    auto result = HapSignVerifyHelper::ParseAclExtendedMap(
        "{\"ohos.permission.ACCESS_CERT_MANAGER\":true}");
    ASSERT_EQ(1u, result.size());
    EXPECT_EQ("true", result["ohos.permission.ACCESS_CERT_MANAGER"]);
}

/**
 * @tc.name: BuildTrustedBundleInfo001
 * @tc.desc: BuildTrustedBundleInfo returns ERR_PARAM_INVALID when bootstrapInfo is null.
 * @tc.type: FUNC
 */
HWTEST_F(HapSignVerifyManagerTest, BuildTrustedBundleInfo001, TestSize.Level1)
{
    MockAppVerifyAdapter adapter;
    HapSignVerifyManager manager(adapter);
    Security::Verify::ProvisionInfo provisionInfo;
    TrustedBundleInfoInner info;
    EXPECT_EQ(AccessTokenError::ERR_PARAM_INVALID,
        manager.BuildTrustedBundleInfo(nullptr, provisionInfo, info));
}

/**
 * @tc.name: GetTokenId001
 * @tc.desc: GetTokenId masks to lower 32 bits of tokenIdEx.
 * @tc.type: FUNC
 */
HWTEST_F(HapSignVerifyManagerTest, GetTokenId001, TestSize.Level1)
{
    EXPECT_EQ(0xABCDu, HapSignVerifyHelper::GetTokenId(0x123456780000ABCDull));
}

/**
 * @tc.name: CheckDeviceMode001
 * @tc.desc: CheckDeviceMode returns true when cmdline contains oemmode=rd without oemmode=user.
 * @tc.type: FUNC
 */
HWTEST_F(HapSignVerifyManagerTest, CheckDeviceMode001, TestSize.Level1)
{
    char buf[] = "init=/init oemmode=rd console=tty0";
    EXPECT_TRUE(RdDeviceChecker::CheckDeviceMode(buf, sizeof(buf) - 1));
}

/**
 * @tc.name: CheckDeviceMode002
 * @tc.desc: CheckDeviceMode returns false when cmdline contains oemmode=user.
 * @tc.type: FUNC
 */
HWTEST_F(HapSignVerifyManagerTest, CheckDeviceMode002, TestSize.Level1)
{
    char buf[] = "init=/init oemmode=user console=tty0";
    EXPECT_FALSE(RdDeviceChecker::CheckDeviceMode(buf, sizeof(buf) - 1));
}

/**
 * @tc.name: CheckDeviceMode003
 * @tc.desc: CheckDeviceMode returns false when cmdline has no oemmode= entry.
 * @tc.type: FUNC
 */
HWTEST_F(HapSignVerifyManagerTest, CheckDeviceMode003, TestSize.Level1)
{
    char buf[] = "init=/init console=tty0";
    EXPECT_FALSE(RdDeviceChecker::CheckDeviceMode(buf, sizeof(buf) - 1));
}

/**
 * @tc.name: CheckDeviceMode004
 * @tc.desc: CheckDeviceMode returns false under attacked cmdline (oemmode=user before oemmode=).
 * @tc.type: FUNC
 */
HWTEST_F(HapSignVerifyManagerTest, CheckDeviceMode004, TestSize.Level1)
{
    char buf[] = "oemmode=user oemmode=rd extra";
    EXPECT_FALSE(RdDeviceChecker::CheckDeviceMode(buf, sizeof(buf) - 1));
}

/**
 * @tc.name: CheckEfuseStatus001
 * @tc.desc: CheckEfuseStatus returns true when efuse_status=1 and no efuse_status=0.
 * @tc.type: FUNC
 */
HWTEST_F(HapSignVerifyManagerTest, CheckEfuseStatus001, TestSize.Level1)
{
    char buf[] = "init=/init efuse_status=1 console=tty0";
    EXPECT_TRUE(RdDeviceChecker::CheckEfuseStatus(buf, sizeof(buf) - 1));
}

/**
 * @tc.name: CheckEfuseStatus002
 * @tc.desc: CheckEfuseStatus returns false when efuse_status=0 is present.
 * @tc.type: FUNC
 */
HWTEST_F(HapSignVerifyManagerTest, CheckEfuseStatus002, TestSize.Level1)
{
    char buf[] = "init=/init efuse_status=0 console=tty0";
    EXPECT_FALSE(RdDeviceChecker::CheckEfuseStatus(buf, sizeof(buf) - 1));
}

/**
 * @tc.name: CheckEfuseStatus003
 * @tc.desc: CheckEfuseStatus returns false when no efuse_status= entry.
 * @tc.type: FUNC
 */
HWTEST_F(HapSignVerifyManagerTest, CheckEfuseStatus003, TestSize.Level1)
{
    char buf[] = "init=/init console=tty0";
    EXPECT_FALSE(RdDeviceChecker::CheckEfuseStatus(buf, sizeof(buf) - 1));
}

/**
 * @tc.name: CheckEfuseStatus004
 * @tc.desc: CheckEfuseStatus returns false under attacked cmdline (efuse_status=0 before efuse_status=).
 * @tc.type: FUNC
 */
HWTEST_F(HapSignVerifyManagerTest, CheckEfuseStatus004, TestSize.Level1)
{
    char buf[] = "efuse_status=0 efuse_status=1 extra";
    EXPECT_FALSE(RdDeviceChecker::CheckEfuseStatus(buf, sizeof(buf) - 1));
}

/**
 * @tc.name: BuildPermBriefDataList001
 * @tc.desc: BuildPermBriefDataListFromPolicy sets IS_KERNEL_EFFECT type when
 *           permission has isKernelEffect flag (e.g. ohos.permission.kernel.ALLOW_WRITABLE_CODE_MEMORY).
 * @tc.type: FUNC
 */
HWTEST_F(HapSignVerifyManagerTest, BuildPermBriefDataList001, TestSize.Level1)
{
    HapPolicy policy;
    PermissionStatus permState;
    permState.permissionName = "ohos.permission.kernel.ALLOW_WRITABLE_CODE_MEMORY";
    permState.grantStatus = PERMISSION_DENIED;
    permState.grantFlag = PERMISSION_DEFAULT_FLAG;
    policy.permStateList.push_back(permState);

    std::vector<BriefPermData> permBriefDataList;
    HapSignVerifyHelper::BuildPermBriefDataListFromPolicy(policy, permBriefDataList);
    ASSERT_EQ(1u, permBriefDataList.size());
    EXPECT_NE(0u, permBriefDataList[0].type & 1u);  // IS_KERNEL_EFFECT
    EXPECT_EQ(0u, permBriefDataList[0].type & 2u);  // no HAS_VALUE
}

/**
 * @tc.name: BuildPermBriefDataList002
 * @tc.desc: BuildPermBriefDataListFromPolicy sets both IS_KERNEL_EFFECT and HAS_VALUE
 *           when permission has both flags (e.g. ohos.permission.kernel.SUPPORT_PLUGIN).
 * @tc.type: FUNC
 */
HWTEST_F(HapSignVerifyManagerTest, BuildPermBriefDataList002, TestSize.Level1)
{
    HapPolicy policy;
    PermissionStatus permState;
    permState.permissionName = "ohos.permission.kernel.SUPPORT_PLUGIN";
    permState.grantStatus = PERMISSION_DENIED;
    permState.grantFlag = PERMISSION_DEFAULT_FLAG;
    policy.permStateList.push_back(permState);

    std::vector<BriefPermData> permBriefDataList;
    HapSignVerifyHelper::BuildPermBriefDataListFromPolicy(policy, permBriefDataList);
    ASSERT_EQ(1u, permBriefDataList.size());
    EXPECT_NE(0u, permBriefDataList[0].type & 1u);  // IS_KERNEL_EFFECT
    EXPECT_NE(0u, permBriefDataList[0].type & 2u);  // HAS_VALUE
}

/**
 * @tc.name: BuildExtendPermList001
 * @tc.desc: BuildExtendPermListFromPolicy converts aclExtendedMap entries to PermissionWithValue vector.
 * @tc.type: FUNC
 */
HWTEST_F(HapSignVerifyManagerTest, BuildExtendPermList001, TestSize.Level1)
{
    HapPolicy policy;
    policy.aclExtendedMap["ohos.permission.CAMERA"] = "cert";
    policy.aclExtendedMap["ohos.permission.MICROPHONE"] = "shadow";

    std::vector<PermissionWithValue> extendPermList;
    HapSignVerifyHelper::BuildExtendPermListFromPolicy(policy, extendPermList);
    ASSERT_EQ(2u, extendPermList.size());
    EXPECT_EQ("ohos.permission.CAMERA", extendPermList[0].permissionName);
    EXPECT_EQ("cert", extendPermList[0].value);
    EXPECT_EQ("ohos.permission.MICROPHONE", extendPermList[1].permissionName);
    EXPECT_EQ("shadow", extendPermList[1].value);
}

/**
 * @tc.name: BuildExtendPermList002
 * @tc.desc: BuildExtendPermListFromPolicy returns empty vector when aclExtendedMap is empty.
 * @tc.type: FUNC
 */
HWTEST_F(HapSignVerifyManagerTest, BuildExtendPermList002, TestSize.Level1)
{
    HapPolicy policy;

    std::vector<PermissionWithValue> extendPermList;
    HapSignVerifyHelper::BuildExtendPermListFromPolicy(policy, extendPermList);
    EXPECT_TRUE(extendPermList.empty());
}

constexpr uint32_t PROCESS_OWNERID_APP = 2;
constexpr uint32_t PROCESS_OWNERID_DEBUG = 3;
constexpr uint32_t PROCESS_OWNERID_COMPAT = 5;
constexpr uint32_t PROCESS_OWNERID_APP_TEMP_ALLOW = 10;

/**
 * @tc.name: BuildIdType001
 * @tc.desc: HapSignVerifyHelper::BuildIdType returns correct idType for debug, compat, temp_jit, and normal app.
 * @tc.type: FUNC
 */
HWTEST_F(HapSignVerifyManagerTest, BuildIdType001, TestSize.Level1)
{
    // Case 1: Debug → PROCESS_OWNERID_DEBUG
    EXPECT_EQ(PROCESS_OWNERID_DEBUG,
        HapSignVerifyHelper::BuildIdType(true, "12345", {}));

    // Case 2: Empty appIdentifier → PROCESS_OWNERID_COMPAT
    EXPECT_EQ(PROCESS_OWNERID_COMPAT,
        HapSignVerifyHelper::BuildIdType(false, "", {}));

    // Case 3: Has TEMP_JIT_ALLOW → PROCESS_OWNERID_APP_TEMP_ALLOW
    PermissionStatus tempJitAllow;
    tempJitAllow.permissionName = "TEMPJITALLOW";
    EXPECT_EQ(PROCESS_OWNERID_APP_TEMP_ALLOW,
        HapSignVerifyHelper::BuildIdType(false, "12345", {tempJitAllow}));

    // Case 4: Normal app → PROCESS_OWNERID_APP
    EXPECT_EQ(PROCESS_OWNERID_APP,
        HapSignVerifyHelper::BuildIdType(false, "12345", {}));
}

/**
 * @tc.name: CheckAppIdentifier001
 * @tc.desc: CheckAppIdentifier covers all branches:
 *           (1) same non-empty appIdentifier → true
 *           (2) different appIdentifier, same appId → true
 *           (3) different appIdentifier, different appId → false
 *           (4) old appIdentifier empty, same appId → true
 *           (5) old appIdentifier empty, different appId → false
 *           (6) new appIdentifier empty, same appId → true
 *           (7) both appIdentifier empty, same appId → true
 *           (8) both appIdentifier empty, different appId → false
 * @tc.type: FUNC
 */
HWTEST_F(HapSignVerifyManagerTest, CheckAppIdentifier001, TestSize.Level1)
{
    HapSignVerifyManager& manager = HapSignVerifyManager::GetInstance();

    TrustedBundleInfoInner oldInfo;
    TrustedBundleInfoInner newInfo;

    // (1) Both appIdentifiers non-empty and equal → true (versionCode update path)
    oldInfo.provisionInfo.bundleInfo.appIdentifier = "12345";
    newInfo.provisionInfo.bundleInfo.appIdentifier = "12345";
    oldInfo.provisionInfo.appId = "old-app-id";
    newInfo.provisionInfo.appId = "new-app-id";
    EXPECT_TRUE(manager.CheckAppIdentifier(oldInfo, newInfo));

    // (2) Different appIdentifier, same appId → true (appId fallback path)
    oldInfo.provisionInfo.bundleInfo.appIdentifier = "11111";
    newInfo.provisionInfo.bundleInfo.appIdentifier = "22222";
    oldInfo.provisionInfo.appId = "same-app-id";
    newInfo.provisionInfo.appId = "same-app-id";
    EXPECT_TRUE(manager.CheckAppIdentifier(oldInfo, newInfo));

    // (3) Different appIdentifier, different appId → false
    oldInfo.provisionInfo.bundleInfo.appIdentifier = "11111";
    newInfo.provisionInfo.bundleInfo.appIdentifier = "22222";
    oldInfo.provisionInfo.appId = "old-app-id";
    newInfo.provisionInfo.appId = "new-app-id";
    EXPECT_FALSE(manager.CheckAppIdentifier(oldInfo, newInfo));

    // (4) Old appIdentifier empty, same appId → true
    oldInfo.provisionInfo.bundleInfo.appIdentifier = "";
    newInfo.provisionInfo.bundleInfo.appIdentifier = "22222";
    oldInfo.provisionInfo.appId = "same-app-id";
    newInfo.provisionInfo.appId = "same-app-id";
    EXPECT_TRUE(manager.CheckAppIdentifier(oldInfo, newInfo));

    // (5) Old appIdentifier empty, different appId → false
    oldInfo.provisionInfo.bundleInfo.appIdentifier = "";
    newInfo.provisionInfo.bundleInfo.appIdentifier = "22222";
    oldInfo.provisionInfo.appId = "old-app-id";
    newInfo.provisionInfo.appId = "new-app-id";
    EXPECT_FALSE(manager.CheckAppIdentifier(oldInfo, newInfo));

    // (6) New appIdentifier empty, same appId → true
    oldInfo.provisionInfo.bundleInfo.appIdentifier = "11111";
    newInfo.provisionInfo.bundleInfo.appIdentifier = "";
    oldInfo.provisionInfo.appId = "same-app-id";
    newInfo.provisionInfo.appId = "same-app-id";
    EXPECT_TRUE(manager.CheckAppIdentifier(oldInfo, newInfo));

    // (7) Both appIdentifiers empty, same appId → true
    oldInfo.provisionInfo.bundleInfo.appIdentifier = "";
    newInfo.provisionInfo.bundleInfo.appIdentifier = "";
    oldInfo.provisionInfo.appId = "same-app-id";
    newInfo.provisionInfo.appId = "same-app-id";
    EXPECT_TRUE(manager.CheckAppIdentifier(oldInfo, newInfo));

    // (8) Both appIdentifiers empty, different appId → false
    oldInfo.provisionInfo.bundleInfo.appIdentifier = "";
    newInfo.provisionInfo.bundleInfo.appIdentifier = "";
    oldInfo.provisionInfo.appId = "old-app-id";
    newInfo.provisionInfo.appId = "new-app-id";
    EXPECT_FALSE(manager.CheckAppIdentifier(oldInfo, newInfo));
}

/**
 * @tc.name: AppVerifyAdapter001
 * @tc.desc: AppVerifyAdapter::ParseHapModuleInfo parses a valid module json and rejects invalid json.
 * @tc.type: FUNC
 */
HWTEST_F(HapSignVerifyManagerTest, AppVerifyAdapter001, TestSize.Level1)
{
    AppVerifyAdapter adapter;
    AppExecFwk::Spm::InnerModuleInfoForSpm moduleInfo;
    const std::string validModuleJson =
        "{\"app\":{\"bundleName\":\"com.example.test\",\"bundleType\":\"app\"},"
        "\"module\":{\"name\":\"entry\",\"targetAPIVersion\":12,"
        "\"definePermissions\":[],\"requestPermissions\":[]}}";
    EXPECT_EQ(RET_SUCCESS, adapter.ParseHapModuleInfo(validModuleJson, moduleInfo));
    EXPECT_EQ("com.example.test", moduleInfo.bundleName);
    EXPECT_EQ("entry", moduleInfo.moduleName);

    EXPECT_EQ(AccessTokenError::ERR_PARAM_INVALID, adapter.ParseHapModuleInfo("{invalid", moduleInfo));
    EXPECT_EQ(AccessTokenError::ERR_PARAM_INVALID, adapter.ParseHapModuleInfo("", moduleInfo));
    EXPECT_EQ(AccessTokenError::ERR_PARAM_INVALID,
        adapter.ParseHapModuleInfo("{\"app\":{\"bundleName\":\"com.example.test\"}}", moduleInfo));
}

/**
 * @tc.name: AppVerifyAdapter002
 * @tc.desc: AppVerifyAdapter::ParseProvision and ParseProfile exercise both result branches.
 * @tc.type: FUNC
 */
HWTEST_F(HapSignVerifyManagerTest, AppVerifyAdapter002, TestSize.Level1)
{
    AppVerifyAdapter adapter;
    Security::Verify::ProvisionInfo info;
    EXPECT_NE(RET_SUCCESS, adapter.ParseProvision("", info));
    EXPECT_NE(RET_SUCCESS, adapter.ParseProvision("{invalid", info));
    EXPECT_EQ(RET_SUCCESS, adapter.ParseProfile("", info));
}

/**
 * @tc.name: CheckHapsSignInfo011
 * @tc.desc: A path sharing a prefix string but not a directory boundary (public_evil) is only
 *           warned, verification still proceeds and returns RET_SUCCESS.
 * @tc.type: FUNC
 */
HWTEST_F(HapSignVerifyManagerTest, CheckHapsSignInfo011, TestSize.Level1)
{
    const std::string boundaryDir = "/data/app/el1/bundle/public_evil";
    std::filesystem::create_directory(boundaryDir);
    const std::string boundaryPath = boundaryDir + "/evil.hap";
    std::ofstream file(boundaryPath);
    file << "evil";
    file.close();

    MockAppVerifyAdapter adapter;
    HapSignVerifyManager manager(adapter);
    TrustedBundleInfoInner info;
    bool isChanged = true;
    EXPECT_EQ(RET_SUCCESS, manager.CheckHapsSignInfo(
        HapSignVerifyManager::MakeVerifyParams(boundaryPath, Security::Verify::VerifyType::Fast, -1),
        false, info, isChanged));

    std::filesystem::remove_all(boundaryDir);
}

/**
 * @tc.name: CheckPermissionRequestValid002
 * @tc.desc: A high-APL system_grant permission with no provisionEnable fails InitPermissionList,
 *           returning ERR_PERM_REQUEST_CFG_FAILED.
 * @tc.type: FUNC
 */
HWTEST_F(HapSignVerifyManagerTest, CheckPermissionRequestValid002, TestSize.Level1)
{
    HapSignVerifyManager& manager = HapSignVerifyManager::GetInstance();
    TrustedBundleInfoInner info;
    info.provisionInfo.bundleInfo.bundleName = "com.example.test";
    info.provisionInfo.bundleInfo.apl = "normal";
    info.provisionInfo.distributionType = Security::Verify::NONE_TYPE;
    info.provisionInfo.type = Security::Verify::RELEASE;

    HapPolicy policy;
    policy.apl = APL_NORMAL;
    PermissionStatus state;
    state.permissionName = "ohos.permission.kernel.ALLOW_WRITABLE_CODE_MEMORY";
    state.grantStatus = PERMISSION_DENIED;
    state.grantFlag = PERMISSION_DEFAULT_FLAG;
    policy.permStateList.push_back(state);

    HapInfoCheckResult result;
    EXPECT_EQ(AccessTokenError::ERR_PERM_REQUEST_CFG_FAILED,
        manager.CheckPermissionRequestValid(info, policy, result));
}

/**
 * @tc.name: ConvertTrustedBundleInfo001
 * @tc.desc: ConvertTrustedBundleInfo converts inner infos to TrustedBundleInfo and skips null bootstrapInfo.
 * @tc.type: FUNC
 */
HWTEST_F(HapSignVerifyManagerTest, ConvertTrustedBundleInfo001, TestSize.Level1)
{
    HapSignVerifyManager& manager = HapSignVerifyManager::GetInstance();

    TrustedBundleInfoInner inner;
    inner.bootstrapInfo = std::make_shared<Security::Verify::BootstrapInfo>();
    inner.bootstrapInfo->moduleRaw = "module-raw";
    inner.bootstrapInfo->shareFilesRaw = "share-files";
    inner.bootstrapInfo->profileJsonRaw = "profile-json";
    inner.provisionInfo.profileBlockLength = 3;
    inner.provisionInfo.profileBlock = std::make_unique<unsigned char[]>(3);
    inner.provisionInfo.profileBlock[0] = 'a';
    inner.provisionInfo.profileBlock[1] = 'b';
    inner.provisionInfo.profileBlock[2] = 'c';
    inner.provisionInfo.appId = "app-id";
    inner.provisionInfo.fingerprint = "fingerprint";
    inner.provisionInfo.organization = "org";
    inner.provisionInfo.isOpenHarmony = true;
    inner.provisionInfo.isEnterpriseResigned = true;

    std::vector<TrustedBundleInfo> infos;
    manager.ConvertTrustedBundleInfo({inner}, infos);
    ASSERT_EQ(1u, infos.size());
    EXPECT_EQ("module-raw", infos[0].moduleInfo);
    EXPECT_EQ("share-files", infos[0].sharedFiles);
    EXPECT_EQ("profile-json", infos[0].profileData.provisionRaw);
    EXPECT_EQ(3, infos[0].profileData.profileBlockLength);
    ASSERT_EQ(3u, infos[0].profileData.profileBlock.size());
    EXPECT_EQ('a', infos[0].profileData.profileBlock[0]);
    EXPECT_EQ('b', infos[0].profileData.profileBlock[1]);
    EXPECT_EQ('c', infos[0].profileData.profileBlock[2]);
    EXPECT_EQ("app-id", infos[0].profileData.appId);
    EXPECT_EQ("fingerprint", infos[0].profileData.fingerprint);
    EXPECT_EQ("org", infos[0].profileData.organization);
    EXPECT_TRUE(infos[0].profileData.isOpenHarmony);
    EXPECT_TRUE(infos[0].profileData.isEnterpriseResigned);

    TrustedBundleInfoInner emptyInner;
    std::vector<TrustedBundleInfo> emptyInfos;
    manager.ConvertTrustedBundleInfo({emptyInner}, emptyInfos);
    EXPECT_TRUE(emptyInfos.empty());

    TrustedBundleInfoInner nullBlock;
    nullBlock.bootstrapInfo = std::make_shared<Security::Verify::BootstrapInfo>();
    nullBlock.provisionInfo.profileBlockLength = 5;
    std::vector<TrustedBundleInfo> nullBlockInfos;
    manager.ConvertTrustedBundleInfo({nullBlock}, nullBlockInfos);
    ASSERT_EQ(1u, nullBlockInfos.size());
    EXPECT_EQ(5, nullBlockInfos[0].profileData.profileBlockLength);
    EXPECT_TRUE(nullBlockInfos[0].profileData.profileBlock.empty());
}

/**
 * @tc.name: GetAppDistributionType001
 * @tc.desc: GetAppDistributionType returns the string form of distributionType.
 * @tc.type: FUNC
 */
HWTEST_F(HapSignVerifyManagerTest, GetAppDistributionType001, TestSize.Level1)
{
    TrustedBundleInfoInner info;
    info.provisionInfo.distributionType = Security::Verify::APP_GALLERY;
    EXPECT_EQ("app_gallery", info.GetAppDistributionType());
    info.provisionInfo.distributionType = Security::Verify::ENTERPRISE_MDM;
    EXPECT_EQ("enterprise_mdm", info.GetAppDistributionType());
}

/**
 * @tc.name: MakeVerifyParams001
 * @tc.desc: MakeVerifyParams sets certPath from userId when userId != -1, empty otherwise.
 * @tc.type: FUNC
 */
HWTEST_F(HapSignVerifyManagerTest, MakeVerifyParams001, TestSize.Level1)
{
    auto params = HapSignVerifyManager::MakeVerifyParams(
        "/path/hap.hap", Security::Verify::VerifyType::Fast, 100);
    EXPECT_EQ("/path/hap.hap", params.filePath);
    EXPECT_EQ("/data/service/el1/public/bms/bundle_manager_service/certificates/enterprise/100", params.certPath);
    EXPECT_EQ(Security::Verify::VerifyType::Fast, params.type);

    auto paramsNoUser = HapSignVerifyManager::MakeVerifyParams(
        "/path/hap.hap", Security::Verify::VerifyType::Fast, -1);
    EXPECT_EQ("", paramsNoUser.certPath);
}

/**
 * @tc.name: FillPermissionDefList001
 * @tc.desc: FillPermissionDefList with empty sortedInfos returns without populating permList.
 * @tc.type: FUNC
 */
HWTEST_F(HapSignVerifyManagerTest, FillPermissionDefList001, TestSize.Level1)
{
    std::vector<PermissionDef> permList;
    HapSignVerifyHelper::FillPermissionDefList({}, permList);
    EXPECT_TRUE(permList.empty());
}

/**
 * @tc.name: FillAclExtendedMap001
 * @tc.desc: FillAclExtendedMap with empty sortedInfos clears the map.
 * @tc.type: FUNC
 */
HWTEST_F(HapSignVerifyManagerTest, FillAclExtendedMap001, TestSize.Level1)
{
    std::map<std::string, std::string> aclExtendedMap;
    aclExtendedMap["x"] = "y";
    HapSignVerifyHelper::FillAclExtendedMap({}, aclExtendedMap);
    EXPECT_TRUE(aclExtendedMap.empty());
}

/**
 * @tc.name: BuildPermBriefDataList003
 * @tc.desc: BuildPermBriefDataListFromPolicy skips undefined permission names.
 * @tc.type: FUNC
 */
HWTEST_F(HapSignVerifyManagerTest, BuildPermBriefDataList003, TestSize.Level1)
{
    HapPolicy policy;
    PermissionStatus permState;
    permState.permissionName = "ohos.permission.INVALID_FAKE";
    policy.permStateList.push_back(permState);

    std::vector<BriefPermData> permBriefDataList;
    HapSignVerifyHelper::BuildPermBriefDataListFromPolicy(policy, permBriefDataList);
    EXPECT_TRUE(permBriefDataList.empty());
}

/**
 * @tc.name: BuildPermBriefDataList004
 * @tc.desc: BuildPermBriefDataListFromPolicy skips disabled permissions.
 * @tc.type: FUNC
 */
HWTEST_F(HapSignVerifyManagerTest, BuildPermBriefDataList004, TestSize.Level1)
{
    EXPECT_TRUE(SetPermissionBriefEnabled("ohos.permission.CAMERA", false));

    HapPolicy policy;
    PermissionStatus permState;
    permState.permissionName = "ohos.permission.CAMERA";
    policy.permStateList.push_back(permState);

    std::vector<BriefPermData> permBriefDataList;
    HapSignVerifyHelper::BuildPermBriefDataListFromPolicy(policy, permBriefDataList);
    EXPECT_TRUE(permBriefDataList.empty());

    EXPECT_TRUE(SetPermissionBriefEnabled("ohos.permission.CAMERA", true));
}

/**
 * @tc.name: ParseAclExtendedMap008
 * @tc.desc: ParseAclExtendedMap skips disabled permissions.
 * @tc.type: FUNC
 */
HWTEST_F(HapSignVerifyManagerTest, ParseAclExtendedMap008, TestSize.Level1)
{
    EXPECT_TRUE(SetPermissionBriefEnabled("ohos.permission.CAMERA", false));

    auto result = HapSignVerifyHelper::ParseAclExtendedMap(
        "{\"ohos.permission.CAMERA\":\"cert\"}");
    EXPECT_TRUE(result.empty());

    EXPECT_TRUE(SetPermissionBriefEnabled("ohos.permission.CAMERA", true));
}

/**
 * @tc.name: CheckHapsSignInfo007
 * @tc.desc: isChanged=false and booting=true takes the ParseProfile path.
 * @tc.type: FUNC
 */
HWTEST_F(HapSignVerifyManagerTest, CheckHapsSignInfo007, TestSize.Level1)
{
    MockAppVerifyAdapter adapter;
    adapter.verifyIsChanged_ = false;
    HapSignVerifyManager manager(adapter);
    TrustedBundleInfoInner info;
    bool isChanged = true;

    EXPECT_EQ(RET_SUCCESS, manager.CheckHapsSignInfo(
        HapSignVerifyManager::MakeVerifyParams(TEST_PATH, Security::Verify::VerifyType::Fast, -1),
        true, info, isChanged));
    EXPECT_EQ(1u, adapter.parseProfileCallCount_);
    EXPECT_EQ(0u, adapter.parseProvisionCallCount_);
}

/**
 * @tc.name: CheckHapsSignInfo008
 * @tc.desc: isChanged=false and booting=false takes the ParseProvision path,
 *           and a parse failure returns ERR_HAP_PROVISION_INVALID.
 * @tc.type: FUNC
 */
HWTEST_F(HapSignVerifyManagerTest, CheckHapsSignInfo008, TestSize.Level1)
{
    MockAppVerifyAdapter adapter;
    adapter.verifyIsChanged_ = false;
    HapSignVerifyManager manager(adapter);
    TrustedBundleInfoInner info;
    bool isChanged = true;

    EXPECT_EQ(RET_SUCCESS, manager.CheckHapsSignInfo(
        HapSignVerifyManager::MakeVerifyParams(TEST_PATH, Security::Verify::VerifyType::Fast, -1),
        false, info, isChanged));
    EXPECT_EQ(0u, adapter.parseProfileCallCount_);
    EXPECT_EQ(1u, adapter.parseProvisionCallCount_);

    MockAppVerifyAdapter failAdapter;
    failAdapter.verifyIsChanged_ = false;
    failAdapter.parseProvisionRet_ = AccessTokenError::ERR_PARAM_INVALID;
    HapSignVerifyManager failManager(failAdapter);
    TrustedBundleInfoInner failInfo;
    bool failChanged = true;
    EXPECT_EQ(ERR_HAP_PROVISION_INVALID, failManager.CheckHapsSignInfo(
        HapSignVerifyManager::MakeVerifyParams(TEST_PATH, Security::Verify::VerifyType::Fast, -1),
        false, failInfo, failChanged));
}

/**
 * @tc.name: CheckHapsSignInfo009
 * @tc.desc: Existing hap path outside allowed directories is only warned, verification still
 *           proceeds and returns RET_SUCCESS.
 * @tc.type: FUNC
 */
HWTEST_F(HapSignVerifyManagerTest, CheckHapsSignInfo009, TestSize.Level1)
{
    const std::string evilDir = "/data/local/tmp/hapverify_evil";
    std::filesystem::create_directory(evilDir);
    const std::string evilPath = evilDir + "/evil.hap";
    std::ofstream file(evilPath);
    file << "evil";
    file.close();

    MockAppVerifyAdapter adapter;
    HapSignVerifyManager manager(adapter);
    TrustedBundleInfoInner info;
    bool isChanged = true;
    EXPECT_EQ(RET_SUCCESS, manager.CheckHapsSignInfo(
        HapSignVerifyManager::MakeVerifyParams(evilPath, Security::Verify::VerifyType::Fast, -1),
        false, info, isChanged));

    std::filesystem::remove_all(evilDir);
}

/**
 * @tc.name: CheckHapsSignInfo010
 * @tc.desc: realpath failure with errno != ENOENT returns ERR_VERIFY_CANT_OPEN.
 * @tc.type: FUNC
 */
HWTEST_F(HapSignVerifyManagerTest, CheckHapsSignInfo010, TestSize.Level1)
{
    const std::string notADir = TEST_DIR + "/not_a_dir";
    std::ofstream file(notADir);
    file << "regular file";
    file.close();

    MockAppVerifyAdapter adapter;
    HapSignVerifyManager manager(adapter);
    TrustedBundleInfoInner info;
    bool isChanged = true;
    EXPECT_EQ(ERR_VERIFY_CANT_OPEN, manager.CheckHapsSignInfo(
        HapSignVerifyManager::MakeVerifyParams(notADir + "/camera.hap", Security::Verify::VerifyType::Fast, -1),
        false, info, isChanged));

    std::filesystem::remove(notADir);
}

/**
 * @tc.name: AppVerifyAdapter003
 * @tc.desc: AppVerifyAdapter::ParseProfile accepts a well-formed provision profile json,
 *           covering the PROVISION_OK branch.
 * @tc.type: FUNC
 */
HWTEST_F(HapSignVerifyManagerTest, AppVerifyAdapter003, TestSize.Level1)
{
    AppVerifyAdapter adapter;
    Security::Verify::ProvisionInfo info;
    const std::string validProvision = R"({
    "version-name": "1.0.0",
    "version-code": 1,
    "uuid": "fe686e1b-3770-4824-a938-961b140a7c98",
    "validity": {"not-before": 1610519532, "not-after": 1705127532},
    "type": "debug",
    "bundle-info": {
        "developer-id": "OpenHarmony",
        "bundle-name": "com.example.test",
        "apl": "normal",
        "app-feature": "hos_normal_app"
    },
    "acls": {"allowed-acls": []},
    "permissions": {"restricted-permissions": []},
    "debug-info": {"device-ids": ["69C7505BE341BDA5948C3C0CB44ABCD530296054159EFE0BD16A16CD0129CC42"],
        "device-id-type": "udid"},
    "issuer": "pki_internal"
    })";
    EXPECT_EQ(Security::Verify::PROVISION_OK, Security::Verify::ParseProfile(validProvision, info));
    EXPECT_EQ(RET_SUCCESS, adapter.ParseProfile(validProvision, info));
}
} // namespace AccessToken
} // namespace Security
} // namespace OHOS
