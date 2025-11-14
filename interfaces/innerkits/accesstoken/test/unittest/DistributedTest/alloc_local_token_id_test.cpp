/*
 * Copyright (c) 2024-2025 Huawei Device Co., Ltd.
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

#include "alloc_local_token_id_test.h"
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
static AccessTokenID g_testTokenIdNormal = 0x20100001;
static AccessTokenID g_testTokenIdSystem = 0x20100002;

HapTokenInfo g_baseInfo = {
    .ver = 1,
    .userID = 1,
    .bundleName = "com.ohos.access_token",
    .instIndex = 1,
    .tokenID = g_testTokenId,
    .tokenAttr = 0
};

HapTokenInfo g_baseInfoNormal = {
    .ver = 1,
    .userID = 1,
    .bundleName = "com.ohos.access_token_normal",
    .instIndex = 1,
    .tokenID = g_testTokenIdNormal,
    .tokenAttr = 0
};

HapTokenInfo g_baseInfoSystem = {
    .ver = 1,
    .userID = 1,
    .bundleName = "com.ohos.access_token_system",
    .instIndex = 1,
    .tokenID = g_testTokenIdSystem,
    .tokenAttr = 1 // system hap
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

void AllocLocalTokenIDTest::SetUpTestCase()
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

void AllocLocalTokenIDTest::TearDownTestCase()
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

void AllocLocalTokenIDTest::SetUp()
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

void AllocLocalTokenIDTest::TearDown()
{
    EXPECT_EQ(0, SetSelfTokenID(g_selfTokenId));
    udid_.clear();
    networkId_.clear();
}

#ifdef TOKEN_SYNC_ENABLE
/**
 * @tc.name: AllocLocalTokenIDFuncTest001
 * @tc.desc: test call AllocLocalTokenID by hap token(permission denied)
 * @tc.type: FUNC
 * @tc.require:issue I5R4UF
 */
HWTEST_F(AllocLocalTokenIDTest, AllocLocalTokenIDFuncTest001, TestSize.Level0)
{
    LOGI(ATM_DOMAIN, ATM_TAG, "AllocLocalTokenIDFuncTest001 start.");
    HapInfoParams infoParms = {
        .userID = 1,
        .bundleName = "GetHapTokenInfoFromRemoteTest",
        .instIndex = 0,
        .appIDDesc = "test.bundle",
        .apiVersion = 8,
        .appDistributionType = "enterprise_mdm"
    };

    HapPolicyParams policyPrams = {
        .apl = APL_NORMAL,
        .domain = "test.domain",
    };
    AccessTokenIDEx tokenIdEx = {0};
    ASSERT_EQ(RET_SUCCESS, TestCommon::AllocTestHapToken(infoParms, policyPrams, tokenIdEx));
    AccessTokenID tokenId = tokenIdEx.tokenIdExStruct.tokenID;
    ASSERT_NE(tokenId, INVALID_TOKENID);
    EXPECT_EQ(0, SetSelfTokenID(tokenIdEx.tokenIDEx));  // set self hap token

    AccessTokenIDEx idEx = {0};
    idEx.tokenIDEx = AccessTokenKit::AllocLocalTokenID(networkId_, g_testTokenId);
    AccessTokenID mapID = idEx.tokenIdExStruct.tokenID;
    EXPECT_EQ(mapID, 0);

    EXPECT_EQ(RET_SUCCESS, TestCommon::DeleteTestHapToken(tokenId));
}

/**
 * @tc.name: AllocLocalTokenIDFuncTest002
 * @tc.desc: get already mapping tokenInfo, makesure ipc right, by native token(permission pass)
 * @tc.type: FUNC
 * @tc.require:issue I5R4UF
 */
HWTEST_F(AllocLocalTokenIDTest, AllocLocalTokenIDFuncTest002, TestSize.Level0)
{
    LOGI(ATM_DOMAIN, ATM_TAG, "AllocLocalTokenIDFuncTest002 start.");
    MockNativeToken mock("token_sync_service");
    std::string deviceID1 = udid_;
    AccessTokenKit::DeleteRemoteToken(deviceID1, g_testTokenId);
    PermissionStatus infoManagerTestState_1 = {
        .permissionName = "ohos.permission.test1",
        .grantStatus = PermissionState::PERMISSION_GRANTED,
        .grantFlag = PermissionFlag::PERMISSION_USER_SET};
    std::vector<PermissionStatus> permStateList1;
    permStateList1.emplace_back(infoManagerTestState_1);

    HapTokenInfoForSync remoteTokenInfo1 = {
        .baseInfo = g_baseInfo,
        .permStateList = permStateList1
    };

    int ret = AccessTokenKit::SetRemoteHapTokenInfo(deviceID1, remoteTokenInfo1);
    ASSERT_EQ(ret, RET_SUCCESS);

    AccessTokenIDEx idEx = {0};
    idEx.tokenIDEx = AccessTokenKit::AllocLocalTokenID(networkId_, g_testTokenId);
    AccessTokenID mapID = idEx.tokenIdExStruct.tokenID;
    ASSERT_NE(mapID, 0);
}

/**
 * @tc.name: AllocLocalTokenIDFuncTest003
 * @tc.desc: get already mapping tokenInfo with normal app
 * @tc.type: FUNC
 * @tc.require:issue
 */
HWTEST_F(AllocLocalTokenIDTest, AllocLocalTokenIDFuncTest003, TestSize.Level0)
{
    LOGI(ATM_DOMAIN, ATM_TAG, "AllocLocalTokenIDFuncTest003 start.");
    MockNativeToken mock("token_sync_service");
    std::string deviceID1 = udid_;
    AccessTokenKit::DeleteRemoteToken(deviceID1, g_testTokenIdNormal);
    PermissionStatus infoManagerTestState_3 = {
        .permissionName = "ohos.permission.test1",
        .grantStatus = PermissionState::PERMISSION_GRANTED,
        .grantFlag = PermissionFlag::PERMISSION_USER_SET};
    std::vector<PermissionStatus> permStateList3;
    permStateList3.emplace_back(infoManagerTestState_3);

    HapTokenInfoForSync remoteTokenInfo3 = {
        .baseInfo = g_baseInfoNormal,
        .permStateList = permStateList3
    };

    int32_t ret = AccessTokenKit::SetRemoteHapTokenInfo(deviceID1, remoteTokenInfo3);
    ASSERT_EQ(ret, RET_SUCCESS);

    uint64_t mapID = AccessTokenKit::AllocLocalTokenID(networkId_, g_testTokenIdNormal);
    EXPECT_NE(mapID, 0);
    EXPECT_FALSE(AccessTokenKit::IsSystemAppByFullTokenID(mapID));
    AccessTokenKit::DeleteRemoteToken(deviceID1, g_testTokenIdNormal);
}

/**
 * @tc.name: AllocLocalTokenIDFuncTest004
 * @tc.desc: get already mapping tokenInfo with system app
 * @tc.type: FUNC
 * @tc.require:issue
 */
HWTEST_F(AllocLocalTokenIDTest, AllocLocalTokenIDFuncTest004, TestSize.Level0)
{
    LOGI(ATM_DOMAIN, ATM_TAG, "AllocLocalTokenIDFuncTest004 start.");
    MockNativeToken mock("token_sync_service");
    std::string deviceID1 = udid_;
    AccessTokenKit::DeleteRemoteToken(deviceID1, g_testTokenIdSystem);
    PermissionStatus infoManagerTestState_4 = {
        .permissionName = "ohos.permission.test1",
        .grantStatus = PermissionState::PERMISSION_GRANTED,
        .grantFlag = PermissionFlag::PERMISSION_USER_SET};
    std::vector<PermissionStatus> permStateList4;
    permStateList4.emplace_back(infoManagerTestState_4);

    HapTokenInfoForSync remoteTokenInfo4 = {
        .baseInfo = g_baseInfoSystem,
        .permStateList = permStateList4
    };

    int32_t ret = AccessTokenKit::SetRemoteHapTokenInfo(deviceID1, remoteTokenInfo4);
    ASSERT_EQ(ret, RET_SUCCESS);

    uint64_t mapID = AccessTokenKit::AllocLocalTokenID(networkId_, g_testTokenIdSystem);
    EXPECT_NE(mapID, 0);
    EXPECT_TRUE(AccessTokenKit::IsSystemAppByFullTokenID(mapID));
    AccessTokenKit::DeleteRemoteToken(deviceID1, g_testTokenIdSystem);
}
#endif