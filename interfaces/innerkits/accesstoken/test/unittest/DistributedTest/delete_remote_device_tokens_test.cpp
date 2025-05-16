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

#include "delete_remote_device_tokens_test.h"
#include <thread>

#include "accesstoken_kit.h"
#include "accesstoken_common_log.h"
#include "access_token_error.h"
#include "nativetoken_kit.h"
#include "test_common.h"
#include "token_setproc.h"
#include "test_common.h"

using namespace testing::ext;
using namespace OHOS::Security::AccessToken;

namespace {
static const std::string TEST_BUNDLE_NAME = "ohos";
static const std::string TEST_PKG_NAME = "com.softbus.test";
static uint64_t g_selfTokenId = 0;
static AccessTokenID g_testTokenId1 = 0x20100000;
static AccessTokenID g_testTokenId2 = 0x20100001;

HapTokenInfo g_baseInfo = {
    .ver = 1,
    .userID = 1,
    .bundleName = "com.ohos.access_token",
    .instIndex = 1,
    .tokenID = g_testTokenId1,
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

void DeleteRemoteDeviceTokensTest::SetUpTestCase()
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

void DeleteRemoteDeviceTokensTest::TearDownTestCase()
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

void DeleteRemoteDeviceTokensTest::SetUp()
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

void DeleteRemoteDeviceTokensTest::TearDown()
{
    udid_.clear();
    networkId_.clear();
}

#ifdef TOKEN_SYNC_ENABLE
/**
 * @tc.name: DeleteRemoteDeviceTokensFuncTest001
 * @tc.desc: delete all mapping tokens of exist device
 * @tc.type: FUNC
 * @tc.require:issue I5R4UF
 */
HWTEST_F(DeleteRemoteDeviceTokensTest, DeleteRemoteDeviceTokensFuncTest001, TestSize.Level0)
{
    MockNativeToken mock("token_sync_service");
    LOGI(ATM_DOMAIN, ATM_TAG, "DeleteRemoteDeviceTokensFuncTest001 start.");
    std::string deviceID1 = udid_;
    AccessTokenKit::DeleteRemoteToken(deviceID1, g_testTokenId1);
    AccessTokenKit::DeleteRemoteToken(deviceID1, g_testTokenId2);
    PermissionStatus infoManagerTestState4 = {
        .permissionName = "ohos.permission.test1",
        .grantStatus = PermissionState::PERMISSION_GRANTED,
        .grantFlag = PermissionFlag::PERMISSION_USER_SET};
    std::vector<PermissionStatus> permStateList1;
    permStateList1.emplace_back(infoManagerTestState4);

    HapTokenInfoForSync remoteTokenInfo1 = {
        .baseInfo = g_baseInfo,
        .permStateList = permStateList1
    };

    int ret = AccessTokenKit::SetRemoteHapTokenInfo(deviceID1, remoteTokenInfo1);
    ASSERT_EQ(ret, RET_SUCCESS);

    HapTokenInfoForSync remoteTokenInfo2 = remoteTokenInfo1;
    remoteTokenInfo2.baseInfo.tokenID = g_testTokenId2;
    remoteTokenInfo2.baseInfo.bundleName = "com.ohos.access_token1";
    ret = AccessTokenKit::SetRemoteHapTokenInfo(deviceID1, remoteTokenInfo2);
    ASSERT_EQ(ret, RET_SUCCESS);

    AccessTokenID mapID = AccessTokenKit::AllocLocalTokenID(networkId_, g_testTokenId1);
    ASSERT_NE(mapID, 0);
    AccessTokenID mapID1 = AccessTokenKit::AllocLocalTokenID(networkId_, g_testTokenId2);
    ASSERT_NE(mapID1, 0);

    ret = AccessTokenKit::DeleteRemoteDeviceTokens(deviceID1);
    ASSERT_EQ(ret, RET_SUCCESS);

    HapTokenInfo info;
    ret = AccessTokenKit::GetHapTokenInfo(mapID, info);
    ASSERT_NE(ret, RET_SUCCESS);
    ret = AccessTokenKit::GetHapTokenInfo(mapID1, info);
    ASSERT_NE(ret, RET_SUCCESS);
}

/**
 * @tc.name: DeleteRemoteDeviceTokensFuncTest002
 * @tc.desc: delete all mapping tokens of NOT exist device
 * @tc.type: FUNC
 * @tc.require:issue I5R4UF
 */
HWTEST_F(DeleteRemoteDeviceTokensTest, DeleteRemoteDeviceTokensFuncTest002, TestSize.Level0)
{
    MockNativeToken mock("token_sync_service");
    LOGI(ATM_DOMAIN, ATM_TAG, "DeleteRemoteDeviceTokensFuncTest002 start.");
    std::string deviceID2 = udid_;
    AccessTokenKit::DeleteRemoteToken(deviceID2, g_testTokenId1);
    AccessTokenKit::DeleteRemoteToken(deviceID2, g_testTokenId2);
    PermissionStatus infoManagerTestState2 = {
        .permissionName = "ohos.permission.test1",
        .grantStatus = PermissionState::PERMISSION_GRANTED,
        .grantFlag = PermissionFlag::PERMISSION_USER_SET};
    std::vector<PermissionStatus> permStateList2;
    permStateList2.emplace_back(infoManagerTestState2);

    HapTokenInfoForSync remoteTokenInfo2 = {
        .baseInfo = g_baseInfo,
        .permStateList = permStateList2
    };

    int ret = AccessTokenKit::SetRemoteHapTokenInfo(deviceID2, remoteTokenInfo2);
    ASSERT_EQ(ret, RET_SUCCESS);

    HapTokenInfoForSync remoteTokenInfo1 = remoteTokenInfo2;
    remoteTokenInfo1.baseInfo.tokenID = g_testTokenId2;
    remoteTokenInfo1.baseInfo.bundleName = "com.ohos.access_token1";
    ret = AccessTokenKit::SetRemoteHapTokenInfo(deviceID2, remoteTokenInfo1);
    ASSERT_EQ(ret, RET_SUCCESS);

    AccessTokenID mapID = AccessTokenKit::AllocLocalTokenID(networkId_, g_testTokenId1);
    ASSERT_NE(mapID, 0);
    AccessTokenID mapID1 = AccessTokenKit::AllocLocalTokenID(networkId_, g_testTokenId2);
    ASSERT_NE(mapID1, 0);

    ret = AccessTokenKit::DeleteRemoteDeviceTokens("1111111");
    ASSERT_NE(ret, RET_SUCCESS);

    AccessTokenKit::DeleteRemoteToken(deviceID2, g_testTokenId1);
    AccessTokenKit::DeleteRemoteToken(deviceID2, g_testTokenId2);
}

/**
 * @tc.name: DeleteRemoteDeviceTokensAbnormalTest001
 * @tc.desc: call DeleteRemoteDeviceTokens with other native process(not accesstoken uid, permission denied)
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(DeleteRemoteDeviceTokensTest, DeleteRemoteDeviceTokensAbnormalTest001, TestSize.Level0)
{
    LOGI(ATM_DOMAIN, ATM_TAG, "DeleteRemoteDeviceTokensAbnormalTest001 start.");
    SetSelfTokenID(g_selfTokenId);
    std::string device = "device";
    ASSERT_EQ(AccessTokenError::ERR_PERMISSION_DENIED, AccessTokenKit::DeleteRemoteDeviceTokens(device));
}
#endif