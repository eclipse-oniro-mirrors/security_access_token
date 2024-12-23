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
#include "accesstoken_log.h"
#include "access_token_error.h"
#include "nativetoken_kit.h"
#include "token_setproc.h"
#include "test_common.h"

using namespace testing::ext;
using namespace OHOS::Security::AccessToken;

namespace {
static constexpr OHOS::HiviewDFX::HiLogLabel LABEL = {
    LOG_CORE, SECURITY_DOMAIN_ACCESSTOKEN, "GetHapTokenInfoFromRemoteTest"};
static const std::string TEST_BUNDLE_NAME = "ohos";
static const std::string TEST_PKG_NAME = "com.softbus.test";
static AccessTokenID g_selfTokenId = 0;

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

void GetHapTokenInfoFromRemoteTest::SetUpTestCase()
{
    g_selfTokenId = GetSelfTokenID();

    // make test case clean
    AccessTokenID tokenID = AccessTokenKit::GetHapTokenID(g_infoManagerTestInfoParms.userID,
                                                          g_infoManagerTestInfoParms.bundleName,
                                                          g_infoManagerTestInfoParms.instIndex);
    AccessTokenKit::DeleteToken(tokenID);

    NativeTokenGet();

#ifdef TOKEN_SYNC_ENABLE
    std::shared_ptr<TestDmInitCallback> ptrDmInitCallback = std::make_shared<TestDmInitCallback>();
    int32_t res = DistributedHardware::DeviceManager::GetInstance().InitDeviceManager(TEST_PKG_NAME, ptrDmInitCallback);
    ASSERT_EQ(res, RET_SUCCESS);
#endif
}

void GetHapTokenInfoFromRemoteTest::TearDownTestCase()
{
    AccessTokenID tokenID = AccessTokenKit::GetHapTokenID(g_infoManagerTestInfoParms.userID,
                                                          g_infoManagerTestInfoParms.bundleName,
                                                          g_infoManagerTestInfoParms.instIndex);
    AccessTokenKit::DeleteToken(tokenID);

    SetSelfTokenID(g_selfTokenId);
#ifdef TOKEN_SYNC_ENABLE
    int32_t res = DistributedHardware::DeviceManager::GetInstance().UnInitDeviceManager(TEST_PKG_NAME);
    ASSERT_EQ(res, RET_SUCCESS);
#endif
}

void GetHapTokenInfoFromRemoteTest::SetUp()
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

void GetHapTokenInfoFromRemoteTest::TearDown()
{
    EXPECT_EQ(0, SetSelfTokenID(selfTokenId_));
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
HWTEST_F(GetHapTokenInfoFromRemoteTest, GetHapTokenInfoFromRemoteFuncTest001, TestSize.Level1)
{
    ACCESSTOKEN_LOG_INFO(LABEL, "GetHapTokenInfoFromRemoteFuncTest001 start.");
    AccessTokenIDEx tokenIdEx = {0};
    tokenIdEx = AccessTokenKit::AllocHapToken(g_infoManagerTestInfoParms, g_infoManagerTestPolicyPrams);
    AccessTokenID localTokenID = tokenIdEx.tokenIdExStruct.tokenID;

    HapTokenInfoForSync infoSync;
    int ret = AccessTokenKit::GetHapTokenInfoFromRemote(localTokenID, infoSync);
    ASSERT_EQ(ret, RET_SUCCESS);
    ASSERT_EQ(infoSync.permStateList.size(), static_cast<uint32_t>(2));

    ASSERT_EQ(infoSync.permStateList[0].permissionName, g_infoManagerTestPolicyPrams.permStateList[0].permissionName);
    ASSERT_EQ(infoSync.permStateList[0].grantFlag, g_infoManagerTestPolicyPrams.permStateList[0].grantFlags[0]);
    ASSERT_EQ(infoSync.permStateList[0].grantStatus, g_infoManagerTestPolicyPrams.permStateList[0].grantStatus[0]);

    ASSERT_EQ(infoSync.permStateList[1].permissionName, g_infoManagerTestPolicyPrams.permStateList[1].permissionName);
    ASSERT_EQ(infoSync.permStateList[1].grantFlag, g_infoManagerTestPolicyPrams.permStateList[1].grantFlags[0]);
    ASSERT_EQ(infoSync.permStateList[1].grantStatus, g_infoManagerTestPolicyPrams.permStateList[1].grantStatus[0]);

    ASSERT_EQ(infoSync.baseInfo.bundleName, g_infoManagerTestInfoParms.bundleName);
    ASSERT_EQ(infoSync.baseInfo.userID, g_infoManagerTestInfoParms.userID);
    ASSERT_EQ(infoSync.baseInfo.instIndex, g_infoManagerTestInfoParms.instIndex);
    ASSERT_EQ(infoSync.baseInfo.ver, 1);
    ASSERT_EQ(infoSync.baseInfo.tokenID, localTokenID);
    ASSERT_EQ(infoSync.baseInfo.tokenAttr, 0);

    AccessTokenKit::DeleteToken(localTokenID);
}

/**
 * @tc.name: GetHapTokenInfoFromRemoteFuncTest002
 * @tc.desc: get remote mapping tokenInfo
 * @tc.type: FUNC
 * @tc.require:issue I5R4UF
 */
HWTEST_F(GetHapTokenInfoFromRemoteTest, GetHapTokenInfoFromRemoteFuncTest002, TestSize.Level1)
{
    ACCESSTOKEN_LOG_INFO(LABEL, "GetHapTokenInfoFromRemoteFuncTest002 start.");
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
HWTEST_F(GetHapTokenInfoFromRemoteTest, GetHapTokenInfoFromRemoteAbnormalTest001, TestSize.Level1)
{
    ACCESSTOKEN_LOG_INFO(LABEL, "GetHapTokenInfoFromRemoteAbnormalTest001 start.");
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
HWTEST_F(GetHapTokenInfoFromRemoteTest, GetHapTokenInfoFromRemoteAbnormalTest002, TestSize.Level1)
{
    ACCESSTOKEN_LOG_INFO(LABEL, "GetHapTokenInfoFromRemoteAbnormalTest002 start.");
    EXPECT_EQ(0, SetSelfTokenID(g_selfTokenId));
    AccessTokenID tokenId = 123;
    HapTokenInfoForSync hapSync;
    ASSERT_EQ(AccessTokenError::ERR_PERMISSION_DENIED, AccessTokenKit::GetHapTokenInfoFromRemote(tokenId, hapSync));
}
#endif