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

#include "get_hap_token_info_from_remote_test.h"
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

HapInfoParams g_infoManagerTestInfoParms = TestCommon::GetInfoManagerTestInfoParms();
HapPolicyParams g_infoManagerTestPolicyPrams = TestCommon::GetInfoManagerTestPolicyPrams();

HapTokenInfo g_baseInfo = {
    .ver = 1,
    .userID = 1,
    .bundleName = "com.ohos.access_token",
    .instIndex = 1,
    .tokenID = 0x20100000,
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

void GetHapTokenInfoFromRemoteTest::SetUpTestCase()
{
    g_selfTokenId = GetSelfTokenID();
    TestCommon::SetTestEvironment(g_selfTokenId);

    // make test case clean
    AccessTokenIDEx tokenIdEx = TestCommon::GetHapTokenIdFromBundle(g_infoManagerTestInfoParms.userID,
        g_infoManagerTestInfoParms.bundleName, g_infoManagerTestInfoParms.instIndex);
    TestCommon::DeleteTestHapToken(tokenIdEx.tokenIdExStruct.tokenID);

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

void GetHapTokenInfoFromRemoteTest::TearDownTestCase()
{
    AccessTokenIDEx tokenIdEx = TestCommon::GetHapTokenIdFromBundle(g_infoManagerTestInfoParms.userID,
        g_infoManagerTestInfoParms.bundleName, g_infoManagerTestInfoParms.instIndex);
    TestCommon::DeleteTestHapToken(tokenIdEx.tokenIdExStruct.tokenID);

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

void GetHapTokenInfoFromRemoteTest::SetUp()
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

void GetHapTokenInfoFromRemoteTest::TearDown()
{
    EXPECT_EQ(0, SetSelfTokenID(g_selfTokenId));
    udid_.clear();
    networkId_.clear();
}

#ifdef TOKEN_SYNC_ENABLE
/**
 * @tc.name: GetHapTokenInfoFromRemoteFuncTest001
 * @tc.desc: get normal local tokenInfo
 * @tc.type: FUNC
 * @tc.require:issue I5R4UF
 */
HWTEST_F(GetHapTokenInfoFromRemoteTest, GetHapTokenInfoFromRemoteFuncTest001, TestSize.Level0)
{
    LOGI(ATM_DOMAIN, ATM_TAG, "GetHapTokenInfoFromRemoteFuncTest001 start.");

    AccessTokenIDEx tokenIdEx = {0};
    ASSERT_EQ(RET_SUCCESS, TestCommon::AllocTestHapToken(
        g_infoManagerTestInfoParms, g_infoManagerTestPolicyPrams, tokenIdEx));
    AccessTokenID localTokenID = tokenIdEx.tokenIdExStruct.tokenID;

    MockNativeToken mock("token_sync_service");

    HapTokenInfoForSync infoSync;
    int ret = AccessTokenKit::GetHapTokenInfoFromRemote(localTokenID, infoSync);
    EXPECT_EQ(ret, RET_SUCCESS);
    EXPECT_EQ(infoSync.permStateList.size(), static_cast<uint32_t>(2));

    EXPECT_EQ(infoSync.permStateList[0].permissionName, g_infoManagerTestPolicyPrams.permStateList[0].permissionName);

    EXPECT_EQ(infoSync.permStateList[1].permissionName, g_infoManagerTestPolicyPrams.permStateList[1].permissionName);

    EXPECT_EQ(infoSync.baseInfo.bundleName, g_infoManagerTestInfoParms.bundleName);
    EXPECT_EQ(infoSync.baseInfo.userID, g_infoManagerTestInfoParms.userID);
    EXPECT_EQ(infoSync.baseInfo.instIndex, g_infoManagerTestInfoParms.instIndex);
    EXPECT_EQ(infoSync.baseInfo.ver, 1);
    EXPECT_EQ(infoSync.baseInfo.tokenID, localTokenID);
    EXPECT_EQ(infoSync.baseInfo.tokenAttr, 0);

    EXPECT_EQ(RET_SUCCESS, TestCommon::DeleteTestHapToken(localTokenID));
}

/**
 * @tc.name: GetHapTokenInfoFromRemoteFuncTest002
 * @tc.desc: get remote mapping tokenInfo
 * @tc.type: FUNC
 * @tc.require:issue I5R4UF
 */
HWTEST_F(GetHapTokenInfoFromRemoteTest, GetHapTokenInfoFromRemoteFuncTest002, TestSize.Level0)
{
    MockNativeToken mock("token_sync_service");
    LOGI(ATM_DOMAIN, ATM_TAG, "GetHapTokenInfoFromRemoteFuncTest002 start.");
    std::string deviceID2 = udid_;
    AccessTokenKit::DeleteRemoteToken(deviceID2, 0x20100000);
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

    AccessTokenID mapID = AccessTokenKit::AllocLocalTokenID(networkId_, 0x20100000);
    ASSERT_NE(mapID, 0);

    HapTokenInfoForSync infoSync;
    ret = AccessTokenKit::GetHapTokenInfoFromRemote(mapID, infoSync);
    ASSERT_NE(ret, RET_SUCCESS);

    AccessTokenKit::DeleteRemoteToken(deviceID2, 0x20100000);
}

/**
 * @tc.name: GetHapTokenInfoFromRemoteAbnormalTest001
 * @tc.desc: get wrong tokenInfo
 * @tc.type: FUNC
 * @tc.require:issue I5R4UF
 */
HWTEST_F(GetHapTokenInfoFromRemoteTest, GetHapTokenInfoFromRemoteAbnormalTest001, TestSize.Level0)
{
    LOGI(ATM_DOMAIN, ATM_TAG, "GetHapTokenInfoFromRemoteAbnormalTest001 start.");
    HapTokenInfoForSync infoSync;
    int ret = AccessTokenKit::GetHapTokenInfoFromRemote(0, infoSync);
    ASSERT_NE(ret, RET_SUCCESS);
}

/**
 * @tc.name: GetHapTokenInfoFromRemoteAbnormalTest002
 * @tc.desc: GetHapTokenInfoFromRemote with no permission
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(GetHapTokenInfoFromRemoteTest, GetHapTokenInfoFromRemoteAbnormalTest002, TestSize.Level0)
{
    LOGI(ATM_DOMAIN, ATM_TAG, "GetHapTokenInfoFromRemoteAbnormalTest002 start.");
    EXPECT_EQ(0, SetSelfTokenID(g_selfTokenId));
    AccessTokenID tokenId = 123;
    HapTokenInfoForSync hapSync;
    ASSERT_EQ(AccessTokenError::ERR_PERMISSION_DENIED, AccessTokenKit::GetHapTokenInfoFromRemote(tokenId, hapSync));
}
#endif