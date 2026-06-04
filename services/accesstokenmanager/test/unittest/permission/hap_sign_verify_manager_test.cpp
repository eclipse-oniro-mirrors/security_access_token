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

#include "access_token_error.h"
#include "app_verify_adapter.h"
#define private public
#include "hap_sign_verify_manager.h"
#undef private
#include "hap_sign_verify_helper.h"
#include "mock_app_verify_adapter.h"
#include "permission_data_brief.h"
#include "provision/provision_info.h"
#include "provision/provision_verify.h"
#include "spm_module_parser.h"

using namespace testing::ext;

namespace OHOS {
namespace Security {
namespace AccessToken {
class HapSignVerifyManagerTest : public testing::Test {
public:
    void SetUp() override {}
    void TearDown() override {}
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

    EXPECT_EQ(RET_SUCCESS, manager.CheckHapsSignInfo("/data/camera.hap",
        Security::Verify::VerifyType::Fast, -1, info, isChanged));
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
    bool isChanged;

    EXPECT_EQ(RET_SUCCESS, manager.CheckHapsSignInfo("/data/camera.hap",
        Security::Verify::VerifyType::Fast, -1, info, isChanged));
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
    bool isChanged;

    EXPECT_EQ(RET_SUCCESS, manager.CheckHapsSignInfo("/data/camera.hap",
        Security::Verify::VerifyType::Fast, -1, info, isChanged));
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
    bool isChanged;

    EXPECT_EQ(AccessTokenError::ERR_HAP_VERIFY_FAILED,
        manager.CheckHapsSignInfo("/data/camera.hap", Security::Verify::VerifyType::Fast, -1, info, isChanged));
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

    EXPECT_EQ(AccessTokenError::ERR_HAP_MODULE_INVALID,
        manager.CheckHapsSignInfo("/data/camera.hap", Security::Verify::VerifyType::Fast, -1, info, isChanged));
    EXPECT_TRUE(adapter.isParseCalled_);
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
 * @tc.desc: Mismatched bundleName, apl, distributionType, or provision type returns ERR_PARAM_INVALID.
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
    info2.provisionInfo.distributionType = Security::Verify::APP_GALLERY;
    infos = {info1, info2};
    EXPECT_EQ(AccessTokenError::ERR_PARAM_INVALID, manager.CheckMultipleHaps(infos));

    info2 = info1;
    info2.provisionInfo.type = Security::Verify::DEBUG;
    infos = {info1, info2};
    EXPECT_EQ(AccessTokenError::ERR_PARAM_INVALID, manager.CheckMultipleHaps(infos));
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

#define PROCESS_OWNERID_APP 2
#define PROCESS_OWNERID_DEBUG 3
#define PROCESS_OWNERID_COMPAT 5
#define PROCESS_OWNERID_APP_TEMP_ALLOW 10

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
} // namespace AccessToken
} // namespace Security
} // namespace OHOS
