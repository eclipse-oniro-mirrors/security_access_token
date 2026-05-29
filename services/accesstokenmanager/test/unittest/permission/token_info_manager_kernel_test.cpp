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

#include "access_token_error.h"
#include "accesstoken_kit.h"
#include "fake_token_setproc.h"
#include "hap_data_structure.h"
#include "hap_token_info.h"
#include "hap_token_info_inner.h"
#ifdef SUPPORT_SANDBOX_APP
#include "dlp_permission_set_manager.h"
#endif
#define private public
#include "accesstoken_info_manager.h"
#include "boot_verify_scheduler.h"
#undef private

#include "permission_map.h"

using namespace testing::ext;
using namespace OHOS;
using namespace OHOS::Security::AccessToken;

namespace {
constexpr int32_t USER_ID = 100;
constexpr int32_t SLEEP_TIME_SECONDS = 3;
}

class TokenInfoManagerKernelTest : public testing::Test {
public:
    void SetUp() override
    {
        // 在需要重置内核状态的测试用例中调用
    }

    void TearDown() override
    {
        uint32_t hapSize = 0;
        uint32_t nativeSize = 0;
        uint32_t pefDefSize = 0;
        uint32_t dlpSize = 0;
        AccessTokenInfoManager::GetInstance().Init(hapSize, nativeSize, pefDefSize, dlpSize);
        (void)BootVerifyScheduler::GetInstance().VerifyBundleSignInfoWhenStart();
        BootVerifyScheduler::GetInstance().StartVerifyNormalBundleListAsync();
        sleep(SLEEP_TIME_SECONDS);
    }
};

/**
 * @tc.name: FillInstallPolicyWithoutHaps001
 * @tc.desc: AccessTokenInfoManager::FillInstallPolicyWithoutHaps checks bundle cache existence.
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(TokenInfoManagerKernelTest, FillInstallPolicyWithoutHaps001, TestSize.Level0)
{
    BundleParam param;
    HapPolicy policy;
    BundlePolicy bundlePolicy;

    // Empty bundleName or non-existent bundle will return ERR_BUNDLE_NOT_EXIST
    ASSERT_EQ(ERR_BUNDLE_NOT_EXIST,
        AccessTokenInfoManager::GetInstance().FillInstallPolicyWithoutHaps("", bundlePolicy, param, policy));
    ASSERT_EQ(ERR_BUNDLE_NOT_EXIST,
        AccessTokenInfoManager::GetInstance().FillInstallPolicyWithoutHaps(
            "com.ohos.not.exist", bundlePolicy, param, policy));
}

/**
 * @tc.name: FillInstallPolicyWithoutHaps002
 * @tc.desc: AccessTokenInfoManager::FillInstallPolicyWithoutHaps skips non-zero instIndex haps.
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(TokenInfoManagerKernelTest, FillInstallPolicyWithoutHaps002, TestSize.Level0)
{
    auto& manager = AccessTokenInfoManager::GetInstance();
    const std::string bundleName = "com.ohos.fill.install.policy.test";
    const AccessTokenID sandboxTokenId = 0x12001;

    uint32_t cameraCode = 0;
    uint32_t bluetoothCode = 0;
    ASSERT_TRUE(TransferPermissionToOpcode("ohos.permission.CAMERA", cameraCode));
    ASSERT_TRUE(TransferPermissionToOpcode("ohos.permission.USE_BLUETOOTH", bluetoothCode));

    auto bundleInfo = std::make_shared<BundleInfoInner>();
    bundleInfo->permCodeList = { static_cast<uint16_t>(cameraCode), static_cast<uint16_t>(bluetoothCode) };
    bundleInfo->tokenIds = { sandboxTokenId };

    HapTokenInfo sandboxInfo = {};
    sandboxInfo.ver = DEFAULT_TOKEN_VERSION;
    sandboxInfo.tokenID = sandboxTokenId;
    sandboxInfo.userID = USER_ID;
    sandboxInfo.bundleName = bundleName;
    sandboxInfo.apiVersion = 10;
    sandboxInfo.instIndex = 1;
    sandboxInfo.dlpType = DLP_COMMON;
    sandboxInfo.tokenAttr = 0;
    sandboxInfo.uid = USER_ID * 200000 + 1;

    auto sandboxHapInfo = std::make_shared<HapTokenInfoInner>(
        sandboxTokenId, sandboxInfo, std::vector<PermissionStatus>{});
    manager.bundleInfoMap_[bundleName] = bundleInfo;
    manager.hapTokenInfoMap_[sandboxTokenId] = sandboxHapInfo;

    BundlePolicy bundlePolicy;
    bundlePolicy.dlpType = DLP_COMMON;

    BundleParam param;
    HapPolicy policy;
    int32_t ret = manager.FillInstallPolicyWithoutHaps(bundleName, bundlePolicy, param, policy);

    manager.hapTokenInfoMap_.erase(sandboxTokenId);
    manager.bundleInfoMap_.erase(bundleName);

    ASSERT_EQ(ERR_TOKENID_NOT_EXIST, ret);
}

/**
 * @tc.name: FillInstallPolicyWithoutHaps003
 * @tc.desc: AccessTokenInfoManager::FillInstallPolicyWithoutHaps rebuilds policy from base hap cache and kernel info.
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(TokenInfoManagerKernelTest, FillInstallPolicyWithoutHaps003, TestSize.Level0)
{
    ResetFakeSpmKernelState();
    auto& manager = AccessTokenInfoManager::GetInstance();
    const std::string bundleName = "com.ohos.fill.install.policy.success";
    const AccessTokenID baseTokenId = 0x12002;

    uint32_t cameraCode = 0;
    uint32_t bluetoothCode = 0;
    ASSERT_TRUE(TransferPermissionToOpcode("ohos.permission.CAMERA", cameraCode));
    ASSERT_TRUE(TransferPermissionToOpcode("ohos.permission.USE_BLUETOOTH", bluetoothCode));

    auto bundleInfo = std::make_shared<BundleInfoInner>();
    bundleInfo->permCodeList = { static_cast<uint16_t>(cameraCode), static_cast<uint16_t>(bluetoothCode) };
    bundleInfo->tokenIds = { baseTokenId };

    HapTokenInfo baseInfo = {};
    baseInfo.ver = DEFAULT_TOKEN_VERSION;
    baseInfo.tokenID = baseTokenId;
    baseInfo.userID = USER_ID;
    baseInfo.bundleName = bundleName;
    baseInfo.apiVersion = 10;
    baseInfo.instIndex = 0;
    baseInfo.dlpType = DLP_COMMON;
    baseInfo.tokenAttr = 0;
    baseInfo.uid = USER_ID * 200000;

    auto baseHapInfo = std::make_shared<HapTokenInfoInner>(baseTokenId, baseInfo, std::vector<PermissionStatus>{});
    manager.bundleInfoMap_[bundleName] = bundleInfo;
    manager.hapTokenInfoMap_[baseTokenId] = baseHapInfo;

    BundlePolicy bundlePolicy;
    bundlePolicy.dlpType = DLP_COMMON;

    BundleParam param;
    HapPolicy policy;
    int32_t ret = manager.FillInstallPolicyWithoutHaps(bundleName, bundlePolicy, param, policy);

    manager.hapTokenInfoMap_.erase(baseTokenId);
    manager.bundleInfoMap_.erase(bundleName);

    ASSERT_EQ(RET_SUCCESS, ret);
    EXPECT_EQ(bundleName, param.bundleName);
    EXPECT_EQ(1u, param.appIdentifier);
    EXPECT_EQ(10, param.apiVersion);
    EXPECT_EQ(OHOS::Security::Verify::AppDistType::NONE_TYPE, static_cast<int32_t>(param.distributionType));
    EXPECT_EQ(2u, policy.permStateList.size());
    EXPECT_TRUE(policy.aclExtendedMap.empty());
}

#ifdef SUPPORT_SANDBOX_APP
/**
 * @tc.name: FillInstallPolicyWithoutHaps004
 * @tc.desc: AccessTokenInfoManager::FillInstallPolicyWithoutHaps applies DLP filtering when rebuilding policy.
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(TokenInfoManagerKernelTest, FillInstallPolicyWithoutHaps004, TestSize.Level0)
{
    ResetFakeSpmKernelState();
    auto& manager = AccessTokenInfoManager::GetInstance();
    const std::string bundleName = "com.ohos.fill.install.policy.dlp";
    const AccessTokenID baseTokenId = 0x12003;

    uint32_t cameraCode = 0;
    uint32_t bluetoothCode = 0;
    ASSERT_TRUE(TransferPermissionToOpcode("ohos.permission.CAMERA", cameraCode));
    ASSERT_TRUE(TransferPermissionToOpcode("ohos.permission.USE_BLUETOOTH", bluetoothCode));


    PermissionDlpMode bluetoothDlpMode;
    bluetoothDlpMode.permissionName = "ohos.permission.USE_BLUETOOTH";
    bluetoothDlpMode.dlpMode = DLP_PERM_FULL_CONTROL;
    DlpPermissionSetManager::GetInstance().ProcessDlpPermInfos({ bluetoothDlpMode });

    auto bundleInfo = std::make_shared<BundleInfoInner>();
    bundleInfo->permCodeList = { static_cast<uint16_t>(cameraCode), static_cast<uint16_t>(bluetoothCode) };
    bundleInfo->tokenIds = { baseTokenId };

    HapTokenInfo baseInfo = {};
    baseInfo.ver = DEFAULT_TOKEN_VERSION;
    baseInfo.tokenID = baseTokenId;
    baseInfo.userID = USER_ID;
    baseInfo.bundleName = bundleName;
    baseInfo.apiVersion = 10;
    baseInfo.instIndex = 0;
    baseInfo.dlpType = DLP_READ;
    baseInfo.tokenAttr = 0;
    baseInfo.uid = USER_ID * 200000;

    auto baseHapInfo = std::make_shared<HapTokenInfoInner>(baseTokenId, baseInfo, std::vector<PermissionStatus>{});
    manager.bundleInfoMap_[bundleName] = bundleInfo;
    manager.hapTokenInfoMap_[baseTokenId] = baseHapInfo;

    BundlePolicy bundlePolicy;
    bundlePolicy.dlpType = DLP_READ;

    BundleParam param;
    HapPolicy policy;
    int32_t ret = manager.FillInstallPolicyWithoutHaps(bundleName, bundlePolicy, param, policy);

    manager.hapTokenInfoMap_.erase(baseTokenId);
    manager.bundleInfoMap_.erase(bundleName);

    ASSERT_EQ(RET_SUCCESS, ret);
    ASSERT_EQ(1u, policy.permStateList.size());
    EXPECT_EQ("ohos.permission.CAMERA", policy.permStateList[0].permissionName);
}
#endif
