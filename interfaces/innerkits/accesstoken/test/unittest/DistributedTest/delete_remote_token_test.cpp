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

#include "delete_remote_token_test.h"
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
static constexpr OHOS::HiviewDFX::HiLogLabel LABEL = {LOG_CORE, SECURITY_DOMAIN_ACCESSTOKEN, "DeleteRemoteTokenTest"};
static const std::string TEST_BUNDLE_NAME = "ohos";
static const std::string TEST_PKG_NAME = "com.softbus.test";
static AccessTokenID g_selfTokenId = 0;

HapInfoParams g_infoManagerTestInfoParms = TestCommon::GetInfoManagerTestInfoParms();

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

void DeleteRemoteTokenTest::SetUpTestCase()
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

void DeleteRemoteTokenTest::TearDownTestCase()
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

void DeleteRemoteTokenTest::SetUp()
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

void DeleteRemoteTokenTest::TearDown()
{
    EXPECT_EQ(0, SetSelfTokenID(selfTokenId_));
    udid_.clear();
    networkId_.clear();
}

#ifdef TOKEN_SYNC_ENABLE
/**
 * @tc.name: DeleteRemoteTokenAbnormalTest001
 * @tc.desc: DeleteRemoteToken with invalid parameters.
 * @tc.type: FUNC
 * @tc.require:Issue Number
 */
HWTEST_F(DeleteRemoteTokenTest, DeleteRemoteTokenAbnormalTest001, TestSize.Level1)
{
    ACCESSTOKEN_LOG_INFO(LABEL, "DeleteRemoteTokenAbnormalTest001 start.");

    std::string deviceId = "device";
    AccessTokenID tokenID = AccessTokenKit::GetHapTokenID(g_infoManagerTestInfoParms.userID,
                                                          g_infoManagerTestInfoParms.bundleName,
                                                          g_infoManagerTestInfoParms.instIndex);
    int res = AccessTokenKit::DeleteRemoteToken("", tokenID);
    ASSERT_EQ(AccessTokenError::ERR_PARAM_INVALID, res);

    res = AccessTokenKit::DeleteRemoteToken(deviceId, tokenID);
    ASSERT_NE(RET_SUCCESS, res);
}

/**
 * @tc.name: DeleteRemoteTokenAbnormalTest002
 * @tc.desc: DeleteRemoteToken with no permission
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(DeleteRemoteTokenTest, DeleteRemoteTokenAbnormalTest002, TestSize.Level1)
{
    ACCESSTOKEN_LOG_INFO(LABEL, "DeleteRemoteTokenAbnormalTest002 start.");
    EXPECT_EQ(0, SetSelfTokenID(g_selfTokenId));
    std::string device = "device";
    AccessTokenID tokenId = 123;
    ASSERT_EQ(AccessTokenError::ERR_PERMISSION_DENIED, AccessTokenKit::DeleteRemoteToken(device, tokenId));
}

/**
 * @tc.name: DeleteRemoteTokenFuncTest001
 * @tc.desc: delete exist device mapping tokenId
 * @tc.type: FUNC
 * @tc.require:issue I5R4UF
 */
HWTEST_F(DeleteRemoteTokenTest, DeleteRemoteTokenFuncTest001, TestSize.Level1)
{
    ACCESSTOKEN_LOG_INFO(LABEL, "DeleteRemoteTokenFuncTest001 start.");
    std::string deviceID1 = udid_;
    AccessTokenKit::DeleteRemoteToken(deviceID1, 0x20100000);
    PermissionStatus infoManagerTestState_3 = {
        .permissionName = "ohos.permission.test1",
        .grantStatus = PermissionState::PERMISSION_GRANTED,
        .grantFlag = PermissionFlag::PERMISSION_USER_SET};
    std::vector<PermissionStatus> permStateList1;
    permStateList1.emplace_back(infoManagerTestState_3);

    HapTokenInfoForSync remoteTokenInfo11 = {
        .baseInfo = g_baseInfo,
        .permStateList = permStateList1
    };

    int ret = AccessTokenKit::SetRemoteHapTokenInfo(deviceID1, remoteTokenInfo11);
    ASSERT_EQ(ret, RET_SUCCESS);

    AccessTokenID mapID = AccessTokenKit::AllocLocalTokenID(networkId_, 0x20100000);
    ASSERT_NE(mapID, 0);

    HapTokenInfo info;
    ret = AccessTokenKit::GetHapTokenInfo(mapID, info);
    ASSERT_EQ(ret, RET_SUCCESS);

    ret = AccessTokenKit::DeleteRemoteToken(deviceID1, 0x20100000);
    ASSERT_EQ(ret, RET_SUCCESS);

    ret = AccessTokenKit::GetHapTokenInfo(mapID, info);
    ASSERT_NE(ret, RET_SUCCESS);
}

/**
 * @tc.name: DeleteRemoteTokenFuncTest002
 * @tc.desc: delete exist device mapping tokenId
 * @tc.type: FUNC
 * @tc.require:issue I5R4UF
 */
HWTEST_F(DeleteRemoteTokenTest, DeleteRemoteTokenFuncTest002, TestSize.Level1)
{
    ACCESSTOKEN_LOG_INFO(LABEL, "DeleteRemoteTokenFuncTest002 start.");
    std::string deviceID2 = udid_;
    AccessTokenKit::DeleteRemoteToken(deviceID2, 0x20100000);
    PermissionStatus infoManagerTestState_2 = {
        .permissionName = "ohos.permission.test1",
        .grantStatus = PermissionState::PERMISSION_GRANTED,
        .grantFlag = PermissionFlag::PERMISSION_USER_SET};
    std::vector<PermissionStatus> permStateList2;
    permStateList2.emplace_back(infoManagerTestState_2);

    HapTokenInfoForSync remoteTokenInfo2 = {
        .baseInfo = g_baseInfo,
        .permStateList = permStateList2
    };

    int ret = AccessTokenKit::SetRemoteHapTokenInfo(deviceID2, remoteTokenInfo2);
    ASSERT_EQ(ret, RET_SUCCESS);

    AccessTokenID mapID = AccessTokenKit::AllocLocalTokenID(networkId_, 0x20100000);
    ASSERT_NE(mapID, 0);

    HapTokenInfo info;
    ret = AccessTokenKit::GetHapTokenInfo(mapID, info);
    ASSERT_EQ(ret, RET_SUCCESS);

    ret = AccessTokenKit::DeleteRemoteToken(deviceID2, 0);
    ASSERT_NE(ret, RET_SUCCESS);

    // deviceID is wrong
    std::string wrongStr(10241, 'x');
    deviceID2 = wrongStr;
    ret = AccessTokenKit::DeleteRemoteToken(deviceID2, 0x20100000);
    ASSERT_NE(ret, RET_SUCCESS);
}

/**
 * @tc.name: DeleteRemoteTokenFuncTest003
 * @tc.desc: delete exist device mapping tokenId
 * @tc.type: FUNC
 * @tc.require:issue I5R4UF
 */
HWTEST_F(DeleteRemoteTokenTest, DeleteRemoteTokenFuncTest003, TestSize.Level1)
{
    ACCESSTOKEN_LOG_INFO(LABEL, "DeleteRemoteTokenFuncTest003 start.");
    std::string deviceID3 = udid_;
    AccessTokenKit::DeleteRemoteToken(deviceID3, 0x20100000);

    int ret = AccessTokenKit::DeleteRemoteToken(deviceID3, 0x20100000);
    ASSERT_NE(ret, RET_SUCCESS);
}
#endif