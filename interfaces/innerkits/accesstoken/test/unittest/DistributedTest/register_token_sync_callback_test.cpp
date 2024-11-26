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
#include "accesstoken_log.h"
#include "access_token_error.h"
#include "nativetoken_kit.h"
#include "token_setproc.h"
#include "test_common.h"

using namespace testing::ext;
using namespace OHOS::Security::AccessToken;

namespace {
static constexpr OHOS::HiviewDFX::HiLogLabel LABEL = {
    LOG_CORE, SECURITY_DOMAIN_ACCESSTOKEN, "RegisterTokenSyncCallbackTest"};
static const std::string TEST_BUNDLE_NAME = "ohos";
static const std::string TEST_PKG_NAME = "com.softbus.test";
static AccessTokenID g_selfTokenId = 0;

HapTokenInfo g_baseInfo = {
    .ver = 1,
    .userID = 1,
    .bundleName = "com.ohos.access_token",
    .instIndex = 1,
    .tokenID = 0x20100000,
    .tokenAttr = 0
};

void NativeTokenGet()
{
    uint32_t tokenId = AccessTokenKit::GetNativeTokenId("token_sync_service");
    ASSERT_NE(tokenId, INVALID_TOKENID);
    EXPECT_EQ(0, SetSelfTokenID(tokenId));
}

#ifdef TOKEN_SYNC_ENABLE
static const int32_t FAKE_SYNC_RET = 0xabcdef;
class TokenSyncCallbackImpl : public TokenSyncKitInterface {
public:
    ~TokenSyncCallbackImpl()
    {}

    int32_t GetRemoteHapTokenInfo(const std::string& deviceID, AccessTokenID tokenID) const override
    {
        ACCESSTOKEN_LOG_INFO(LABEL, "GetRemoteHapTokenInfo called.");
        return FAKE_SYNC_RET;
    };

    int32_t DeleteRemoteHapTokenInfo(AccessTokenID tokenID) const override
    {
        ACCESSTOKEN_LOG_INFO(LABEL, "DeleteRemoteHapTokenInfo called.");
        return FAKE_SYNC_RET;
    };

    int32_t UpdateRemoteHapTokenInfo(const HapTokenInfoForSync& tokenInfo) const override
    {
        ACCESSTOKEN_LOG_INFO(LABEL, "UpdateRemoteHapTokenInfo called.");
        return FAKE_SYNC_RET;
    };
};
#endif
}

void RegisterTokenSyncCallbackTest::SetUpTestCase()
{
    g_selfTokenId = GetSelfTokenID();

    NativeTokenGet();

#ifdef TOKEN_SYNC_ENABLE
    std::shared_ptr<TestDmInitCallback> ptrDmInitCallback = std::make_shared<TestDmInitCallback>();
    int32_t res = DistributedHardware::DeviceManager::GetInstance().InitDeviceManager(TEST_PKG_NAME, ptrDmInitCallback);
    ASSERT_EQ(res, RET_SUCCESS);
#endif
}

void RegisterTokenSyncCallbackTest::TearDownTestCase()
{
    SetSelfTokenID(g_selfTokenId);
#ifdef TOKEN_SYNC_ENABLE
    int32_t res = DistributedHardware::DeviceManager::GetInstance().UnInitDeviceManager(TEST_PKG_NAME);
    ASSERT_EQ(res, RET_SUCCESS);
#endif
}

void RegisterTokenSyncCallbackTest::SetUp()
{
    selfTokenId_ = GetSelfTokenID();

#ifdef TOKEN_SYNC_ENABLE
    DistributedHardware::DmDeviceInfo deviceInfo;
    int32_t res = DistributedHardware::DeviceManager::GetInstance().GetLocalDeviceInfo(TEST_PKG_NAME, deviceInfo);
    ASSERT_EQ(res, RET_SUCCESS);

    networkId_ = std::string(deviceInfo.networkId);
    ASSERT_NE(networkId_, "");

    res = DistributedHardware::DeviceManager::GetInstance().GetUdidByNetworkId(TEST_PKG_NAME, networkId_, udid_);
    ASSERT_EQ(res, RET_SUCCESS);
    ASSERT_NE(udid_, "");
#endif

    ACCESSTOKEN_LOG_INFO(LABEL, "SetUp ok.");
    setuid(0);
}

void RegisterTokenSyncCallbackTest::TearDown()
{
    EXPECT_EQ(0, SetSelfTokenID(selfTokenId_));
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
    ACCESSTOKEN_LOG_INFO(LABEL, "RegisterTokenSyncCallbackAbnormalTest001 start.");
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
    ACCESSTOKEN_LOG_INFO(LABEL, "RegisterTokenSyncCallbackAbnormalTest002 start.");
    EXPECT_EQ(0, SetSelfTokenID(g_selfTokenId));
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
    ACCESSTOKEN_LOG_INFO(LABEL, "RegisterTokenSyncCallbackFuncTest001 start.");
    std::shared_ptr<TokenSyncKitInterface> callback = std::make_shared<TokenSyncCallbackImpl>();
    EXPECT_EQ(RET_SUCCESS, AccessTokenKit::RegisterTokenSyncCallback(callback));
    EXPECT_EQ(RET_SUCCESS, AccessTokenKit::AllocLocalTokenID(networkId_, 0)); // invalid input, would ret 0
    EXPECT_EQ(RET_SUCCESS, AccessTokenKit::UnRegisterTokenSyncCallback());
}
#endif