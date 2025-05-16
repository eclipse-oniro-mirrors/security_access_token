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

#include "set_remote_hap_token_info_test.h"
#include <thread>

#include "access_token.h"
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

void SetRemoteHapTokenInfoTest::SetUpTestCase()
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

void SetRemoteHapTokenInfoTest::TearDownTestCase()
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

void SetRemoteHapTokenInfoTest::SetUp()
{
#ifdef TOKEN_SYNC_ENABLE
    MockNativeToken mock("foundation"); // distribute permission
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

void SetRemoteHapTokenInfoTest::TearDown()
{
    EXPECT_EQ(0, SetSelfTokenID(g_selfTokenId));
    udid_.clear();
    networkId_.clear();
}

#ifdef TOKEN_SYNC_ENABLE
/**
 * @tc.name: SetRemoteHapTokenInfoFuncTest001
 * @tc.desc: set remote hap token info success
 * @tc.type: FUNC
 * @tc.require:issue I5R4UF
 */
HWTEST_F(SetRemoteHapTokenInfoTest, SetRemoteHapTokenInfoFuncTest001, TestSize.Level0)
{
    MockNativeToken mock("token_sync_service");
    LOGI(ATM_DOMAIN, ATM_TAG, "SetRemoteHapTokenInfoFuncTest001 start.");
    std::string deviceID1 = udid_;
    AccessTokenKit::DeleteRemoteToken(deviceID1, g_testTokenId);
    PermissionStatus infoManagerTestState2 = {
        .permissionName = "ohos.permission.CAMERA",
        .grantStatus = PermissionState::PERMISSION_GRANTED,
        .grantFlag = PermissionFlag::PERMISSION_SYSTEM_FIXED};
    std::vector<PermissionStatus> permStateList1;
    permStateList1.emplace_back(infoManagerTestState2);

    HapTokenInfoForSync remoteTokenInfo1 = {
        .baseInfo = g_baseInfo,
        .permStateList = permStateList1
    };

    int ret = AccessTokenKit::SetRemoteHapTokenInfo(deviceID1, remoteTokenInfo1);
    ASSERT_EQ(ret, RET_SUCCESS);

    // Get local map token ID
    AccessTokenID mapID = AccessTokenKit::AllocLocalTokenID(networkId_, g_testTokenId);
    ASSERT_NE(mapID, 0);

    // check local map token
    HapTokenInfo resultInfo;
    ret = AccessTokenKit::GetHapTokenInfo(mapID, resultInfo);
    ASSERT_EQ(ret, RET_SUCCESS);
    ASSERT_EQ(resultInfo.ver, remoteTokenInfo1.baseInfo.ver);
    ASSERT_EQ(resultInfo.userID, remoteTokenInfo1.baseInfo.userID);
    ASSERT_EQ(resultInfo.bundleName, remoteTokenInfo1.baseInfo.bundleName);
    ASSERT_EQ(resultInfo.instIndex, remoteTokenInfo1.baseInfo.instIndex);
    ASSERT_NE(resultInfo.tokenID, remoteTokenInfo1.baseInfo.tokenID); // tokenID already is map tokenID
    ASSERT_EQ(resultInfo.tokenAttr, remoteTokenInfo1.baseInfo.tokenAttr);

    ret = AccessTokenKit::VerifyAccessToken(mapID, "ohos.permission.CAMERA", false);
    ASSERT_EQ(ret, PermissionState::PERMISSION_GRANTED);

    ret = AccessTokenKit::DeleteRemoteToken(deviceID1, g_testTokenId);
    ASSERT_EQ(ret, RET_SUCCESS);
}

void SetRemoteHapTokenInfoWithWrongInfo1(HapTokenInfo &wrongBaseInfo, const HapTokenInfo &rightBaseInfo,
    HapTokenInfoForSync &remoteTokenInfo, const std::string &deviceID)
{
    std::string wrongStr(10241, 'x'); // 10241 means the invalid string length

    wrongBaseInfo = rightBaseInfo;
    wrongBaseInfo.bundleName = wrongStr; // wrong bundleName
    remoteTokenInfo.baseInfo = wrongBaseInfo;
    int32_t ret = AccessTokenKit::SetRemoteHapTokenInfo(deviceID, remoteTokenInfo);
    EXPECT_NE(ret, RET_SUCCESS);

    wrongBaseInfo = rightBaseInfo;
    wrongBaseInfo.tokenID = 0; // wrong tokenID
    remoteTokenInfo.baseInfo = wrongBaseInfo;
    ret = AccessTokenKit::SetRemoteHapTokenInfo(deviceID, remoteTokenInfo);
    EXPECT_NE(ret, RET_SUCCESS);
}

/**
 * @tc.name: SetRemoteHapTokenInfoFuncTest002
 * @tc.desc: set remote hap token info, token info is wrong
 * @tc.type: FUNC
 * @tc.require:issue I5R4UF
 */
HWTEST_F(SetRemoteHapTokenInfoTest, SetRemoteHapTokenInfoFuncTest002, TestSize.Level0)
{
    MockNativeToken mock("token_sync_service");
    LOGI(ATM_DOMAIN, ATM_TAG, "SetRemoteHapTokenInfoFuncTest002 start.");
    std::string deviceID2 = udid_;
    AccessTokenKit::DeleteRemoteToken(deviceID2, g_testTokenId);
    HapTokenInfo rightBaseInfo = {
        .ver = 1,
        .userID = 1,
        .bundleName = "com.ohos.access_token",
        .instIndex = 1,
        .tokenID = g_testTokenId,
        .tokenAttr = 0
    };

    HapTokenInfo wrongBaseInfo = rightBaseInfo;
    wrongBaseInfo.userID = -11; // wrong userid

    PermissionStatus infoManagerTestState_2 = {
        .permissionName = "ohos.permission.test1",
        .grantStatus = PermissionState::PERMISSION_GRANTED,
        .grantFlag = PermissionFlag::PERMISSION_SYSTEM_FIXED};
    std::vector<PermissionStatus> permStateList2;
    permStateList2.emplace_back(infoManagerTestState_2);

    HapTokenInfoForSync remoteTokenInfo2 = {
        .baseInfo = wrongBaseInfo,
        .permStateList = permStateList2
    };

    int ret = AccessTokenKit::SetRemoteHapTokenInfo(deviceID2, remoteTokenInfo2);
    ASSERT_NE(ret, RET_SUCCESS);

    SetRemoteHapTokenInfoWithWrongInfo1(wrongBaseInfo, rightBaseInfo, remoteTokenInfo2, deviceID2);
}

/**
 * @tc.name: SetRemoteHapTokenInfoFuncTest003
 * @tc.desc: set remote hap token wrong permission grant
 * @tc.type: FUNC
 * @tc.require:issue I5R4UF
 */
HWTEST_F(SetRemoteHapTokenInfoTest, SetRemoteHapTokenInfoFuncTest003, TestSize.Level0)
{
    MockNativeToken mock("token_sync_service");
    LOGI(ATM_DOMAIN, ATM_TAG, "SetRemoteHapTokenInfoFuncTest003 start.");
    std::string deviceID3 = udid_;
    AccessTokenKit::DeleteRemoteToken(deviceID3, g_testTokenId);

    PermissionStatus infoManagerTestState_3 = {
        .permissionName = "ohos.permission.test1",
        .grantStatus = PermissionState::PERMISSION_GRANTED,
        .grantFlag = 11, // wrong flags
    };
    std::vector<PermissionStatus> permStateList3;
    permStateList3.emplace_back(infoManagerTestState_3);

    HapTokenInfoForSync remoteTokenInfo3 = {
        .baseInfo = g_baseInfo,
        .permStateList = permStateList3
    };

    int ret = AccessTokenKit::SetRemoteHapTokenInfo(deviceID3, remoteTokenInfo3);
    ASSERT_EQ(ret, RET_SUCCESS);

    // Get local map token ID
    AccessTokenID mapID = AccessTokenKit::AllocLocalTokenID(networkId_, g_testTokenId);
    ASSERT_NE(mapID, 0);

    ret = AccessTokenKit::VerifyAccessToken(mapID, "ohos.permission.test1", false);
    ASSERT_EQ(ret, PermissionState::PERMISSION_DENIED);

    ret = AccessTokenKit::DeleteRemoteToken(deviceID3, g_testTokenId);
    ASSERT_EQ(ret, RET_SUCCESS);
}

/**
 * @tc.name: SetRemoteHapTokenInfoFuncTest004
 * @tc.desc: update remote hap token when remote exist
 * @tc.type: FUNC
 * @tc.require:issue I5R4UF
 */
HWTEST_F(SetRemoteHapTokenInfoTest, SetRemoteHapTokenInfoFuncTest004, TestSize.Level0)
{
    MockNativeToken mock("token_sync_service");
    LOGI(ATM_DOMAIN, ATM_TAG, "SetRemoteHapTokenInfoFuncTest004 start.");
    std::string deviceID4 = udid_;
    AccessTokenKit::DeleteRemoteToken(deviceID4, g_testTokenId);
    PermissionStatus infoManagerTestState_4 = {
        .permissionName = "ohos.permission.CAMERA",
        .grantStatus = PermissionState::PERMISSION_DENIED, // first denied
        .grantFlag = PermissionFlag::PERMISSION_SYSTEM_FIXED};
    std::vector<PermissionStatus> permStateList4;
    permStateList4.emplace_back(infoManagerTestState_4);

    HapTokenInfoForSync remoteTokenInfo4 = {
        .baseInfo = g_baseInfo,
        .permStateList = permStateList4
    };

    int ret = AccessTokenKit::SetRemoteHapTokenInfo(deviceID4, remoteTokenInfo4);
    ASSERT_EQ(ret, RET_SUCCESS);

    // Get local map token ID
    AccessTokenID mapID = AccessTokenKit::AllocLocalTokenID(networkId_, g_testTokenId);
    ASSERT_NE(mapID, 0);

    ret = AccessTokenKit::VerifyAccessToken(mapID, "ohos.permission.CAMERA", false);
    ASSERT_EQ(ret, PermissionState::PERMISSION_DENIED);

    remoteTokenInfo4.permStateList[0].grantStatus = PermissionState::PERMISSION_GRANTED; // second granted
    ret = AccessTokenKit::SetRemoteHapTokenInfo(deviceID4, remoteTokenInfo4);
    ASSERT_EQ(ret, RET_SUCCESS);

    ret = AccessTokenKit::VerifyAccessToken(mapID, "ohos.permission.CAMERA", false);
    ASSERT_EQ(ret, PermissionState::PERMISSION_GRANTED);

    ret = AccessTokenKit::DeleteRemoteToken(deviceID4, g_testTokenId);
    ASSERT_EQ(ret, RET_SUCCESS);
}

/**
 * @tc.name: SetRemoteHapTokenInfoSpecTest001
 * @tc.desc: add remote hap token, it can not grant by GrantPermission
 * @tc.type: FUNC
 * @tc.require:issue I5R4UF
 */
HWTEST_F(SetRemoteHapTokenInfoTest, SetRemoteHapTokenInfoSpecTest001, TestSize.Level0)
{
    MockNativeToken mock("token_sync_service");
    LOGI(ATM_DOMAIN, ATM_TAG, "SetRemoteHapTokenInfoSpecTest001 start.");
    std::string deviceID5 = udid_;
    AccessTokenKit::DeleteRemoteToken(deviceID5, g_testTokenId);
    PermissionStatus infoManagerTestState5 = {
        .permissionName = "ohos.permission.test1",
        .grantStatus = PermissionState::PERMISSION_DENIED, // first denied
        .grantFlag = PermissionFlag::PERMISSION_SYSTEM_FIXED};
    std::vector<PermissionStatus> permStateList5;
    permStateList5.emplace_back(infoManagerTestState5);

    HapTokenInfoForSync remoteTokenInfo5 = {
        .baseInfo = g_baseInfo,
        .permStateList = permStateList5
    };

    int ret = AccessTokenKit::SetRemoteHapTokenInfo(deviceID5, remoteTokenInfo5);
    ASSERT_EQ(ret, RET_SUCCESS);

    // Get local map token ID
    AccessTokenID mapID = AccessTokenKit::AllocLocalTokenID(networkId_, g_testTokenId);
    ASSERT_NE(mapID, 0);

    ret = AccessTokenKit::VerifyAccessToken(mapID, "ohos.permission.test1", false);
    ASSERT_EQ(ret, PermissionState::PERMISSION_DENIED);

    {
        std::vector<std::string> reqPerm;
        reqPerm.emplace_back("ohos.permission.GRANT_SENSITIVE_PERMISSIONS");
        MockHapToken mock("SetRemoteHapTokenInfoSpecTest001", reqPerm);
        ret = AccessTokenKit::GrantPermission(mapID, "ohos.permission.test1", PermissionFlag::PERMISSION_SYSTEM_FIXED);
        ASSERT_EQ(ret, ERR_PERMISSION_NOT_EXIST);
    }

    ret = AccessTokenKit::VerifyAccessToken(mapID, "ohos.permission.test1", false);
    ASSERT_EQ(ret, PermissionState::PERMISSION_DENIED);

    ret = AccessTokenKit::DeleteRemoteToken(deviceID5, g_testTokenId);
    ASSERT_EQ(ret, RET_SUCCESS);
}

/**
 * @tc.name: SetRemoteHapTokenInfoSpecTest002
 * @tc.desc: add remote hap token, it can not revoke by RevokePermission
 * @tc.type: FUNC
 * @tc.require:issue I5R4UF
 */
HWTEST_F(SetRemoteHapTokenInfoTest, SetRemoteHapTokenInfoSpecTest002, TestSize.Level0)
{
    MockNativeToken mock("token_sync_service");
    LOGI(ATM_DOMAIN, ATM_TAG, "SetRemoteHapTokenInfoSpecTest002 start.");
    std::string deviceID6 = udid_;
    AccessTokenKit::DeleteRemoteToken(deviceID6, g_testTokenId);
    PermissionStatus infoManagerTestState6 = {
        .permissionName = "ohos.permission.READ_AUDIO",
        .grantStatus = PermissionState::PERMISSION_GRANTED, // first grant
        .grantFlag = PermissionFlag::PERMISSION_SYSTEM_FIXED};
    PermissionStatus infoManagerTestState7 = {
        .permissionName = "ohos.permission.test1",
        .grantStatus = PermissionState::PERMISSION_GRANTED, // first grant
        .grantFlag = PermissionFlag::PERMISSION_SYSTEM_FIXED};
    std::vector<PermissionStatus> permStateList6;
    permStateList6.emplace_back(infoManagerTestState6);
    permStateList6.emplace_back(infoManagerTestState7);

    HapTokenInfoForSync remoteTokenInfo6 = {
        .baseInfo = g_baseInfo,
        .permStateList = permStateList6
    };

    int ret = AccessTokenKit::SetRemoteHapTokenInfo(deviceID6, remoteTokenInfo6);
    ASSERT_EQ(ret, RET_SUCCESS);

    // Get local map token ID
    AccessTokenID mapID = AccessTokenKit::AllocLocalTokenID(networkId_, g_testTokenId);
    ASSERT_NE(mapID, 0);

    ret = AccessTokenKit::VerifyAccessToken(mapID, "ohos.permission.READ_AUDIO", false);
    EXPECT_EQ(ret, PermissionState::PERMISSION_GRANTED);

    {
        std::vector<std::string> reqPerm;
        reqPerm.emplace_back("ohos.permission.REVOKE_SENSITIVE_PERMISSIONS");
        MockHapToken mock("SetRemoteHapTokenInfoSpecTest002", reqPerm);
        ret = AccessTokenKit::RevokePermission(mapID, "ohos.permission.test1", PermissionFlag::PERMISSION_SYSTEM_FIXED);
        ASSERT_EQ(ret, ERR_PERMISSION_NOT_EXIST);
    }

    ret = AccessTokenKit::VerifyAccessToken(mapID, "ohos.permission.READ_AUDIO", false);
    EXPECT_EQ(ret, PermissionState::PERMISSION_GRANTED);

    ret = AccessTokenKit::DeleteRemoteToken(deviceID6, g_testTokenId);
    EXPECT_EQ(ret, RET_SUCCESS);
}

/**
 * @tc.name: SetRemoteHapTokenInfoSpecTest003
 * @tc.desc: add remote hap token, it can not delete by DeleteToken
 * @tc.type: FUNC
 * @tc.require:issue I5R4UF
 */
HWTEST_F(SetRemoteHapTokenInfoTest, SetRemoteHapTokenInfoSpecTest003, TestSize.Level0)
{
    MockNativeToken mock("token_sync_service");
    LOGI(ATM_DOMAIN, ATM_TAG, "SetRemoteHapTokenInfoSpecTest003 start.");
    std::string deviceID7 = udid_;
    AccessTokenKit::DeleteRemoteToken(deviceID7, g_testTokenId);
    PermissionStatus infoManagerTestState7 = {
        .permissionName = "ohos.permission.READ_AUDIO",
        .grantStatus = PermissionState::PERMISSION_DENIED, // first denied
        .grantFlag = PermissionFlag::PERMISSION_SYSTEM_FIXED};
    std::vector<PermissionStatus> permStateList7;
    permStateList7.emplace_back(infoManagerTestState7);

    HapTokenInfoForSync remoteTokenInfo7 = {
        .baseInfo = g_baseInfo,
        .permStateList = permStateList7
    };

    int ret = AccessTokenKit::SetRemoteHapTokenInfo(deviceID7, remoteTokenInfo7);
    ASSERT_EQ(ret, RET_SUCCESS);

    // Get local map token ID
    AccessTokenID mapID = AccessTokenKit::AllocLocalTokenID(networkId_, g_testTokenId);
    ASSERT_NE(mapID, 0);

    ret = AccessTokenKit::DeleteToken(mapID);
    ASSERT_NE(ret, RET_SUCCESS);

    ret = AccessTokenKit::DeleteRemoteToken(deviceID7, g_testTokenId);
    ASSERT_EQ(ret, RET_SUCCESS);
}

/**
 * @tc.name: SetRemoteHapTokenInfoSpecTest004
 * @tc.desc: add remote hap token, it can not update by UpdateHapToken
 * @tc.type: FUNC
 * @tc.require:issue I5R4UF
 */
HWTEST_F(SetRemoteHapTokenInfoTest, SetRemoteHapTokenInfoSpecTest004, TestSize.Level0)
{
    MockNativeToken mock("token_sync_service");
    LOGI(ATM_DOMAIN, ATM_TAG, "SetRemoteHapTokenInfoSpecTest004 start.");
    std::string deviceID8 = udid_;
    AccessTokenKit::DeleteRemoteToken(deviceID8, g_testTokenId);
    int32_t DEFAULT_API_VERSION = 8;
    PermissionStatus infoManagerTestState8 = {
        .permissionName = "ohos.permission.test1",
        .grantStatus = PermissionState::PERMISSION_DENIED, // first denied
        .grantFlag = PermissionFlag::PERMISSION_SYSTEM_FIXED};
    std::vector<PermissionStatus> permStateList8;
    permStateList8.emplace_back(infoManagerTestState8);

    HapTokenInfoForSync remoteTokenInfo8 = {
        .baseInfo = g_baseInfo,
        .permStateList = permStateList8
    };

    int ret = AccessTokenKit::SetRemoteHapTokenInfo(deviceID8, remoteTokenInfo8);
    ASSERT_EQ(ret, RET_SUCCESS);

    // Get local map token ID
    AccessTokenID mapID = AccessTokenKit::AllocLocalTokenID(networkId_, g_testTokenId);
    ASSERT_NE(mapID, 0);
    AccessTokenIDEx tokenIdEx {
        .tokenIdExStruct.tokenID = mapID,
        .tokenIdExStruct.tokenAttr = 0,
    };
    HapPolicyParams policy;
    UpdateHapInfoParams info;
    info.appIDDesc = std::string("updateFailed");
    info.apiVersion = DEFAULT_API_VERSION;
    info.isSystemApp = false;
    ret = AccessTokenKit::UpdateHapToken(tokenIdEx, info, policy);
    ASSERT_EQ(ret, AccessTokenError::ERR_PARAM_INVALID);

    ret = AccessTokenKit::DeleteRemoteToken(deviceID8, g_testTokenId);
    ASSERT_EQ(ret, RET_SUCCESS);
}

/**
 * @tc.name: SetRemoteHapTokenInfoSpecTest005
 * @tc.desc: add remote hap token, it can not clear by ClearUserGrantedPermissionState
 * @tc.type: FUNC
 * @tc.require:issue I5R4UF
 */
HWTEST_F(SetRemoteHapTokenInfoTest, SetRemoteHapTokenInfoSpecTest005, TestSize.Level0)
{
    MockNativeToken mock("token_sync_service");
    LOGI(ATM_DOMAIN, ATM_TAG, "SetRemoteHapTokenInfoSpecTest005 start.");
    std::string deviceID9 = udid_;
    AccessTokenKit::DeleteRemoteToken(deviceID9, g_testTokenId);
    PermissionStatus infoManagerTestState9 = {
        .permissionName = "ohos.permission.CAMERA",
        .grantStatus = PermissionState::PERMISSION_GRANTED,
        .grantFlag = PermissionFlag::PERMISSION_USER_SET};
    std::vector<PermissionStatus> permStateList9;
    permStateList9.emplace_back(infoManagerTestState9);

    HapTokenInfoForSync remoteTokenInfo9 = {
        .baseInfo = g_baseInfo,
        .permStateList = permStateList9
    };

    int ret = AccessTokenKit::SetRemoteHapTokenInfo(deviceID9, remoteTokenInfo9);
    ASSERT_EQ(ret, RET_SUCCESS);

    // Get local map token ID
    AccessTokenID mapID = AccessTokenKit::AllocLocalTokenID(networkId_, g_testTokenId);
    ASSERT_NE(mapID, 0);

    ret = AccessTokenKit::VerifyAccessToken(mapID, "ohos.permission.CAMERA", false);
    ASSERT_EQ(ret, PermissionState::PERMISSION_GRANTED);

    {
        MockNativeToken mock("foundation");
        ASSERT_EQ(RET_SUCCESS, AccessTokenKit::ClearUserGrantedPermissionState(mapID));
    }

    ret = AccessTokenKit::VerifyAccessToken(mapID, "ohos.permission.CAMERA", false);
    ASSERT_EQ(ret, PermissionState::PERMISSION_GRANTED);

    ret = AccessTokenKit::DeleteRemoteToken(deviceID9, g_testTokenId);
    ASSERT_EQ(ret, RET_SUCCESS);
}

/**
 * @tc.name: SetRemoteHapTokenInfoSpecTest006
 * @tc.desc: tokenID is not hap token
 * @tc.type: FUNC
 * @tc.require:issue I5R4UF
 */
HWTEST_F(SetRemoteHapTokenInfoTest, SetRemoteHapTokenInfoSpecTest006, TestSize.Level0)
{
    MockNativeToken mock("token_sync_service");
    LOGI(ATM_DOMAIN, ATM_TAG, "SetRemoteHapTokenInfoSpecTest006 start.");
    std::string deviceID = udid_;
    HapTokenInfo baseInfo = {
        .ver = 1,
        .userID = 1,
        .bundleName = "com.ohos.access_token",
        .instIndex = 1,
        .tokenID = 0x28100000,
        .tokenAttr = 0
    };

    PermissionStatus infoManagerTestState = {
        .permissionName = "ohos.permission.test1",
        .grantStatus = PermissionState::PERMISSION_GRANTED,
        .grantFlag = PermissionFlag::PERMISSION_USER_SET};
    std::vector<PermissionStatus> permStateList;
    permStateList.emplace_back(infoManagerTestState);

    HapTokenInfoForSync remoteTokenInfo = {
        .baseInfo = baseInfo,
        .permStateList = permStateList
    };

    int ret = AccessTokenKit::SetRemoteHapTokenInfo(deviceID, remoteTokenInfo);
    ASSERT_NE(ret, RET_SUCCESS);
}

/**
 * @tc.name: SetRemoteHapTokenInfoAbnormalTest001
 * @tc.desc: SetRemoteHapTokenInfo with no permission
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(SetRemoteHapTokenInfoTest, SetRemoteHapTokenInfoAbnormalTest001, TestSize.Level0)
{
    LOGI(ATM_DOMAIN, ATM_TAG, "SetRemoteHapTokenInfoAbnormalTest001 start.");
    std::string device = "device";
    HapTokenInfoForSync hapSync;
    ASSERT_EQ(AccessTokenError::ERR_PERMISSION_DENIED, AccessTokenKit::SetRemoteHapTokenInfo(device, hapSync));
}
#endif