/*
 * Copyright (c) 2024 Huawei Device Co., Ltd.
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

#include "register_token_sync_callback_test.h"
#include <thread>

#include "accesstoken_kit.h"
#include "accesstoken_common_log.h"
#include "access_token_error.h"
#include "nativetoken_kit.h"
#include "test_common.h"
#include "token_setproc.h"

using namespace testing::ext;
using namespace OHOS::Security::AccessToken;

namespace {
static const std::string TEST_BUNDLE_NAME = "ohos";
static const std::string TEST_PKG_NAME = "com.softbus.test";
static uint64_t g_selfTokenId = 0;
static AccessTokenID g_testTokenId = 0x20100000;

HapTokenInfo g_baseInfo = {
    .ver = 1,
    .userID = 1,
    .bundleName = "com.ohos.access_token",
    .instIndex = 1,
    .tokenID = g_testTokenId,
    .tokenAttr = 0
};

#ifdef TOKEN_SYNC_ENABLE
static const int32_t FAKE_SYNC_RET = 0xabcdef;
class TokenSyncCallbackImpl : public TokenSyncKitInterface {
public:
    ~TokenSyncCallbackImpl()
    {}

    int32_t GetRemoteHapTokenInfo(const std::string& deviceID, AccessTokenID tokenID) const override
    {
        LOGI(ATM_DOMAIN, ATM_TAG, "GetRemoteHapTokenInfo called.");
        return FAKE_SYNC_RET;
    };

    int32_t DeleteRemoteHapTokenInfo(AccessTokenID tokenID) const override
    {
        LOGI(ATM_DOMAIN, ATM_TAG, "DeleteRemoteHapTokenInfo called.");
        return FAKE_SYNC_RET;
    };

    int32_t UpdateRemoteHapTokenInfo(const HapTokenInfoForSync& tokenInfo) const override
    {
        LOGI(ATM_DOMAIN, ATM_TAG, "UpdateRemoteHapTokenInfo called.");
        return FAKE_SYNC_RET;
    };
};
#endif
}

void RegisterTokenSyncCallbackTest::SetUpTestCase()
{
    g_selfTokenId = GetSelfTokenID();
    TestCommon::SetTestEvironment(g_selfTokenId);

#ifdef TOKEN_SYNC_ENABLE
    {
        MockNativeToken mock("foundation");
        std::shared_ptr<TestDmInitCallback> ptrDmInitCallback = std::make_shared<TestDmInitCallback>();
        int32_t res =
            DistributedHardware::DeviceManager::GetInstance().InitDeviceManager(TEST_PKG_NAME, ptrDmInitCallback);
        ASSERT_EQ(res, RET_SUCCESS);
    }
#endif
}

void RegisterTokenSyncCallbackTest::TearDownTestCase()
{
#ifdef TOKEN_SYNC_ENABLE
    {
        MockNativeToken mock("foundation");
        int32_t res = DistributedHardware::DeviceManager::GetInstance().UnInitDeviceManager(TEST_PKG_NAME);
        ASSERT_EQ(res, RET_SUCCESS);
    }
#endif
    EXPECT_EQ(0, SetSelfTokenID(g_selfTokenId));
    TestCommon::ResetTestEvironment();
}

void RegisterTokenSyncCallbackTest::SetUp()
{
#ifdef TOKEN_SYNC_ENABLE
    MockNativeToken mock("foundation");
    DistributedHardware::DmDeviceInfo deviceInfo;
    int32_t res = DistributedHardware::DeviceManager::GetInstance().GetLocalDeviceInfo(TEST_PKG_NAME, deviceInfo);
    ASSERT_EQ(res, RET_SUCCESS);

    networkId_ = std::string(deviceInfo.networkId);
    ASSERT_NE(networkId_, "");

    res = DistributedHardware::DeviceManager::GetInstance().GetUdidByNetworkId(TEST_PKG_NAME, networkId_, udid_);
    ASSERT_EQ(res, RET_SUCCESS);
    ASSERT_NE(udid_, "");
#endif

    LOGI(ATM_DOMAIN, ATM_TAG, "SetUp ok.");
}

void RegisterTokenSyncCallbackTest::TearDown()
{
    EXPECT_EQ(0, SetSelfTokenID(g_selfTokenId));
    udid_.clear();
    networkId_.clear();
}

#ifdef TOKEN_SYNC_ENABLE
/**
 * @tc.name: RegisterTokenSyncCallbackAbnormalTest001
 * @tc.desc: set token sync callback with invalid pointer
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(RegisterTokenSyncCallbackTest, RegisterTokenSyncCallbackAbnormalTest001, TestSize.Level1)
{
    LOGI(ATM_DOMAIN, ATM_TAG, "RegisterTokenSyncCallbackAbnormalTest001 start.");
    int32_t ret = AccessTokenKit::RegisterTokenSyncCallback(nullptr);
    EXPECT_EQ(ERR_PARAM_INVALID, ret);
}

/**
 * @tc.name: RegisterTokenSyncCallbackAbnormalTest002
 * @tc.desc: RegisterTokenSyncCallback with no permission
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(RegisterTokenSyncCallbackTest, RegisterTokenSyncCallbackAbnormalTest002, TestSize.Level1)
{
    LOGI(ATM_DOMAIN, ATM_TAG, "RegisterTokenSyncCallbackAbnormalTest002 start.");
    std::shared_ptr<TokenSyncKitInterface> callback = std::make_shared<TokenSyncCallbackImpl>();
    EXPECT_EQ(AccessTokenError::ERR_PERMISSION_DENIED, AccessTokenKit::RegisterTokenSyncCallback(callback));
    EXPECT_EQ(AccessTokenError::ERR_PERMISSION_DENIED, AccessTokenKit::UnRegisterTokenSyncCallback());
}

/**
 * @tc.name: RegisterTokenSyncCallbackFuncTest001
 * @tc.desc: set token sync callback with right pointer
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(RegisterTokenSyncCallbackTest, RegisterTokenSyncCallbackFuncTest001, TestSize.Level1)
{
    MockNativeToken mock("token_sync_service");
    LOGI(ATM_DOMAIN, ATM_TAG, "RegisterTokenSyncCallbackFuncTest001 start.");
    std::shared_ptr<TokenSyncKitInterface> callback = std::make_shared<TokenSyncCallbackImpl>();
    EXPECT_EQ(RET_SUCCESS, AccessTokenKit::RegisterTokenSyncCallback(callback));
    EXPECT_EQ(RET_SUCCESS, AccessTokenKit::AllocLocalTokenID(networkId_, 0)); // invalid input, would ret 0
    EXPECT_EQ(RET_SUCCESS, AccessTokenKit::UnRegisterTokenSyncCallback());
}
#endif