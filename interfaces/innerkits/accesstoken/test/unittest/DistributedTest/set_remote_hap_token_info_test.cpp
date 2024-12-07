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
#include "accesstoken_log.h"
#include "access_token_error.h"
#include "nativetoken_kit.h"
#include "token_setproc.h"
#include "test_common.h"

using namespace testing::ext;
using namespace OHOS::Security::AccessToken;

namespace {
static constexpr OHOS::HiviewDFX::HiLogLabel LABEL = {
    LOG_CORE, SECURITY_DOMAIN_ACCESSTOKEN, "SetRemoteHapTokenInfoTest"};

static const std::string TEST_BUNDLE_NAME = "ohos";
static const std::string TEST_PKG_NAME = "com.softbus.test";
static AccessTokenID g_selfTokenId = 0;

HapTokenInfo g_baseInfo = {
    .apl = APL_NORMAL,
    .ver = 1,
    .userID = 1,
    .bundleName = "com.ohos.access_token",
    .instIndex = 1,
    .appID = "test4",
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

void SetRemoteHapTokenInfoTest::SetUpTestCase()
{
    g_selfTokenId = GetSelfTokenID();

    NativeTokenGet();

#ifdef TOKEN_SYNC_ENABLE
    std::shared_ptr<TestDmInitCallback> ptrDmInitCallback = std::make_shared<TestDmInitCallback>();
    int32_t res = DistributedHardware::DeviceManager::GetInstance().InitDeviceManager(TEST_PKG_NAME, ptrDmInitCallback);
    ASSERT_EQ(res, RET_SUCCESS);
#endif
}

void SetRemoteHapTokenInfoTest::TearDownTestCase()
{
    SetSelfTokenID(g_selfTokenId);
#ifdef TOKEN_SYNC_ENABLE
    int32_t res = DistributedHardware::DeviceManager::GetInstance().UnInitDeviceManager(TEST_PKG_NAME);
    ASSERT_EQ(res, RET_SUCCESS);
#endif
}

void SetRemoteHapTokenInfoTest::SetUp()
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

void SetRemoteHapTokenInfoTest::TearDown()
{
    EXPECT_EQ(0, SetSelfTokenID(selfTokenId_));
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
HWTEST_F(SetRemoteHapTokenInfoTest, SetRemoteHapTokenInfoFuncTest001, TestSize.Level1)
{
    ACCESSTOKEN_LOG_INFO(LABEL, "SetRemoteHapTokenInfoFuncTest001 start.");
    std::string deviceID1 = udid_;
    AccessTokenKit::DeleteRemoteToken(deviceID1, 0x20100000);
    PermissionStateFull infoManagerTestState2 = {
        .permissionName = "ohos.permission.CAMERA",
         .isGeneral = true,
        .resDeviceID = {"local4"},
        .grantStatus = {PermissionState::PERMISSION_GRANTED},
        .grantFlags = {PermissionFlag::PERMISSION_SYSTEM_FIXED}};
    std::vector<PermissionStateFull> permStateList1;
    permStateList1.emplace_back(infoManagerTestState2);

    g_baseInfo.deviceID = deviceID1;
    HapTokenInfoForSync remoteTokenInfo1 = {
        .baseInfo = g_baseInfo,
        .permStateList = permStateList1
    };

    int ret = AccessTokenKit::SetRemoteHapTokenInfo(deviceID1, remoteTokenInfo1);
    ASSERT_EQ(ret, RET_SUCCESS);

    // Get local map token ID
    AccessTokenID mapID = AccessTokenKit::AllocLocalTokenID(networkId_, 0x20100000);
    ASSERT_NE(mapID, 0);

    // check local map token
    HapTokenInfo resultInfo;
    ret = AccessTokenKit::GetHapTokenInfo(mapID, resultInfo);
    ASSERT_EQ(ret, RET_SUCCESS);
    ASSERT_EQ(resultInfo.apl, remoteTokenInfo1.baseInfo.apl);
    ASSERT_EQ(resultInfo.ver, remoteTokenInfo1.baseInfo.ver);
    ASSERT_EQ(resultInfo.userID, remoteTokenInfo1.baseInfo.userID);
    ASSERT_EQ(resultInfo.bundleName, remoteTokenInfo1.baseInfo.bundleName);
    ASSERT_EQ(resultInfo.instIndex, remoteTokenInfo1.baseInfo.instIndex);
    ASSERT_EQ(resultInfo.appID, remoteTokenInfo1.baseInfo.appID);
    ASSERT_EQ(resultInfo.deviceID, remoteTokenInfo1.baseInfo.deviceID);
    ASSERT_NE(resultInfo.tokenID, remoteTokenInfo1.baseInfo.tokenID); // tokenID already is map tokenID
    ASSERT_EQ(resultInfo.tokenAttr, remoteTokenInfo1.baseInfo.tokenAttr);

    ret = AccessTokenKit::VerifyAccessToken(mapID, "ohos.permission.CAMERA", false);
    ASSERT_EQ(ret, PermissionState::PERMISSION_GRANTED);

    ret = AccessTokenKit::DeleteRemoteToken(deviceID1, 0x20100000);
    ASSERT_EQ(ret, RET_SUCCESS);
}

void SetRemoteHapTokenInfoWithWrongInfo1(HapTokenInfo &wrongBaseInfo, const HapTokenInfo &rightBaseInfo,
    HapTokenInfoForSync &remoteTokenInfo, const std::string &deviceID)
{
    std::string wrongStr(10241, 'x'); // 10241 means the invalid string length

    wrongBaseInfo = rightBaseInfo;
    wrongBaseInfo.appID = wrongStr; // wrong appID
    remoteTokenInfo.baseInfo = wrongBaseInfo;
    int32_t ret = AccessTokenKit::SetRemoteHapTokenInfo(deviceID, remoteTokenInfo);
    EXPECT_NE(ret, RET_SUCCESS);

    wrongBaseInfo = rightBaseInfo;
    wrongBaseInfo.bundleName = wrongStr; // wrong bundleName
    remoteTokenInfo.baseInfo = wrongBaseInfo;
    ret = AccessTokenKit::SetRemoteHapTokenInfo(deviceID, remoteTokenInfo);
    EXPECT_NE(ret, RET_SUCCESS);

    wrongBaseInfo = rightBaseInfo;
    wrongBaseInfo.deviceID = wrongStr; // wrong deviceID
    remoteTokenInfo.baseInfo = wrongBaseInfo;
    ret = AccessTokenKit::SetRemoteHapTokenInfo(deviceID, remoteTokenInfo);
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
HWTEST_F(SetRemoteHapTokenInfoTest, SetRemoteHapTokenInfoFuncTest002, TestSize.Level1)
{
    ACCESSTOKEN_LOG_INFO(LABEL, "SetRemoteHapTokenInfoFuncTest002 start.");
    std::string deviceID2 = udid_;
    AccessTokenKit::DeleteRemoteToken(deviceID2, 0x20100000);
    HapTokenInfo rightBaseInfo = {
        .apl = APL_NORMAL,
        .ver = 1,
        .userID = 1,
        .bundleName = "com.ohos.access_token",
        .instIndex = 1,
        .appID = "test4",
        .deviceID = udid_,
        .tokenID = 0x20100000,
        .tokenAttr = 0
    };

    HapTokenInfo wrongBaseInfo = rightBaseInfo;
    wrongBaseInfo.apl = (ATokenAplEnum)11; // wrong apl

    PermissionStateFull infoManagerTestState_2 = {
        .permissionName = "ohos.permission.test1",
        .isGeneral = true,
        .resDeviceID = {"local"},
        .grantStatus = {PermissionState::PERMISSION_GRANTED},
        .grantFlags = {PermissionFlag::PERMISSION_SYSTEM_FIXED}};
    std::vector<PermissionStateFull> permStateList2;
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
HWTEST_F(SetRemoteHapTokenInfoTest, SetRemoteHapTokenInfoFuncTest003, TestSize.Level1)
{
    ACCESSTOKEN_LOG_INFO(LABEL, "SetRemoteHapTokenInfoFuncTest003 start.");
    std::string deviceID3 = udid_;
    AccessTokenKit::DeleteRemoteToken(deviceID3, 0x20100000);

    PermissionStateFull infoManagerTestState_3 = {
        .permissionName = "ohos.permission.test1",
        .isGeneral = true,
        .resDeviceID = {"local"},
        .grantStatus = {PermissionState::PERMISSION_GRANTED},
        .grantFlags = {11}, // wrong flags
        };
    std::vector<PermissionStateFull> permStateList3;
    permStateList3.emplace_back(infoManagerTestState_3);

    g_baseInfo.deviceID = deviceID3;
    HapTokenInfoForSync remoteTokenInfo3 = {
        .baseInfo = g_baseInfo,
        .permStateList = permStateList3
    };

    int ret = AccessTokenKit::SetRemoteHapTokenInfo(deviceID3, remoteTokenInfo3);
    ASSERT_EQ(ret, RET_SUCCESS);

    // Get local map token ID
    AccessTokenID mapID = AccessTokenKit::AllocLocalTokenID(networkId_, 0x20100000);
    ASSERT_NE(mapID, 0);

    ret = AccessTokenKit::VerifyAccessToken(mapID, "ohos.permission.test1", false);
    ASSERT_EQ(ret, PermissionState::PERMISSION_DENIED);

    ret = AccessTokenKit::DeleteRemoteToken(deviceID3, 0x20100000);
    ASSERT_EQ(ret, RET_SUCCESS);
}

/**
 * @tc.name: SetRemoteHapTokenInfoFuncTest004
 * @tc.desc: update remote hap token when remote exist
 * @tc.type: FUNC
 * @tc.require:issue I5R4UF
 */
HWTEST_F(SetRemoteHapTokenInfoTest, SetRemoteHapTokenInfoFuncTest004, TestSize.Level1)
{
    ACCESSTOKEN_LOG_INFO(LABEL, "SetRemoteHapTokenInfoFuncTest004 start.");
    std::string deviceID4 = udid_;
    AccessTokenKit::DeleteRemoteToken(deviceID4, 0x20100000);
    PermissionStateFull infoManagerTestState_4 = {
        .permissionName = "ohos.permission.CAMERA",
        .isGeneral = true,
        .resDeviceID = {"local"},
        .grantStatus = {PermissionState::PERMISSION_DENIED}, // first denied
        .grantFlags = {PermissionFlag::PERMISSION_SYSTEM_FIXED}};
    std::vector<PermissionStateFull> permStateList4;
    permStateList4.emplace_back(infoManagerTestState_4);

    g_baseInfo.deviceID = deviceID4;
    HapTokenInfoForSync remoteTokenInfo4 = {
        .baseInfo = g_baseInfo,
        .permStateList = permStateList4
    };

    int ret = AccessTokenKit::SetRemoteHapTokenInfo(deviceID4, remoteTokenInfo4);
    ASSERT_EQ(ret, RET_SUCCESS);

    // Get local map token ID
    AccessTokenID mapID = AccessTokenKit::AllocLocalTokenID(networkId_, 0x20100000);
    ASSERT_NE(mapID, 0);

    ret = AccessTokenKit::VerifyAccessToken(mapID, "ohos.permission.CAMERA", false);
    ASSERT_EQ(ret, PermissionState::PERMISSION_DENIED);

    remoteTokenInfo4.permStateList[0].grantStatus[0] = PermissionState::PERMISSION_GRANTED; // second granted
    ret = AccessTokenKit::SetRemoteHapTokenInfo(deviceID4, remoteTokenInfo4);
    ASSERT_EQ(ret, RET_SUCCESS);

    ret = AccessTokenKit::VerifyAccessToken(mapID, "ohos.permission.CAMERA", false);
    ASSERT_EQ(ret, PermissionState::PERMISSION_GRANTED);

    ret = AccessTokenKit::DeleteRemoteToken(deviceID4, 0x20100000);
    ASSERT_EQ(ret, RET_SUCCESS);
}

/**
 * @tc.name: SetRemoteHapTokenInfoSpecTest001
 * @tc.desc: add remote hap token, it can not grant by GrantPermission
 * @tc.type: FUNC
 * @tc.require:issue I5R4UF
 */
HWTEST_F(SetRemoteHapTokenInfoTest, SetRemoteHapTokenInfoSpecTest001, TestSize.Level1)
{
    ACCESSTOKEN_LOG_INFO(LABEL, "SetRemoteHapTokenInfoSpecTest001 start.");
    std::string deviceID5 = udid_;
    AccessTokenKit::DeleteRemoteToken(deviceID5, 0x20100000);
    PermissionStateFull infoManagerTestState5 = {
        .permissionName = "ohos.permission.test1",
        .isGeneral = true,
        .resDeviceID = {"local"},
        .grantStatus = {PermissionState::PERMISSION_DENIED}, // first denied
        .grantFlags = {PermissionFlag::PERMISSION_SYSTEM_FIXED}};
    std::vector<PermissionStateFull> permStateList5;
    permStateList5.emplace_back(infoManagerTestState5);

    g_baseInfo.deviceID = deviceID5;
    HapTokenInfoForSync remoteTokenInfo5 = {
        .baseInfo = g_baseInfo,
        .permStateList = permStateList5
    };

    int ret = AccessTokenKit::SetRemoteHapTokenInfo(deviceID5, remoteTokenInfo5);
    ASSERT_EQ(ret, RET_SUCCESS);

    // Get local map token ID
    AccessTokenID mapID = AccessTokenKit::AllocLocalTokenID(networkId_, 0x20100000);
    ASSERT_NE(mapID, 0);

    ret = AccessTokenKit::VerifyAccessToken(mapID, "ohos.permission.test1", false);
    ASSERT_EQ(ret, PermissionState::PERMISSION_DENIED);

    ret = AccessTokenKit::GrantPermission(mapID, "ohos.permission.test1", PermissionFlag::PERMISSION_SYSTEM_FIXED);
    ASSERT_EQ(ret, ERR_PERMISSION_NOT_EXIST);

    ret = AccessTokenKit::VerifyAccessToken(mapID, "ohos.permission.test1", false);
    ASSERT_EQ(ret, PermissionState::PERMISSION_DENIED);

    ret = AccessTokenKit::DeleteRemoteToken(deviceID5, 0x20100000);
    ASSERT_EQ(ret, RET_SUCCESS);
}

/**
 * @tc.name: SetRemoteHapTokenInfoSpecTest002
 * @tc.desc: add remote hap token, it can not revoke by RevokePermission
 * @tc.type: FUNC
 * @tc.require:issue I5R4UF
 */
HWTEST_F(SetRemoteHapTokenInfoTest, SetRemoteHapTokenInfoSpecTest002, TestSize.Level1)
{
    ACCESSTOKEN_LOG_INFO(LABEL, "SetRemoteHapTokenInfoSpecTest002 start.");
    std::string deviceID6 = udid_;
    AccessTokenKit::DeleteRemoteToken(deviceID6, 0x20100000);
    PermissionStateFull infoManagerTestState6 = {
        .permissionName = "ohos.permission.READ_AUDIO",
        .isGeneral = true,
        .resDeviceID = {"local4"},
        .grantStatus = {PermissionState::PERMISSION_GRANTED}, // first grant
        .grantFlags = {PermissionFlag::PERMISSION_SYSTEM_FIXED}};
    PermissionStateFull infoManagerTestState7 = {
        .permissionName = "ohos.permission.test1",
        .isGeneral = true,
        .resDeviceID = {"local4"},
        .grantStatus = {PermissionState::PERMISSION_GRANTED}, // first grant
        .grantFlags = {PermissionFlag::PERMISSION_SYSTEM_FIXED}};
    std::vector<PermissionStateFull> permStateList6;
    permStateList6.emplace_back(infoManagerTestState6);
    permStateList6.emplace_back(infoManagerTestState7);

    g_baseInfo.deviceID = deviceID6;
    HapTokenInfoForSync remoteTokenInfo6 = {
        .baseInfo = g_baseInfo,
        .permStateList = permStateList6
    };

    int ret = AccessTokenKit::SetRemoteHapTokenInfo(deviceID6, remoteTokenInfo6);
    ASSERT_EQ(ret, RET_SUCCESS);

    // Get local map token ID
    AccessTokenID mapID = AccessTokenKit::AllocLocalTokenID(networkId_, 0x20100000);
    ASSERT_NE(mapID, 0);

    ret = AccessTokenKit::VerifyAccessToken(mapID, "ohos.permission.READ_AUDIO", false);
    EXPECT_EQ(ret, PermissionState::PERMISSION_GRANTED);

    ret = AccessTokenKit::RevokePermission(
        mapID, "ohos.permission.test1", PermissionFlag::PERMISSION_SYSTEM_FIXED);
    EXPECT_EQ(ret, ERR_PERMISSION_NOT_EXIST);

    ret = AccessTokenKit::VerifyAccessToken(mapID, "ohos.permission.READ_AUDIO", false);
    EXPECT_EQ(ret, PermissionState::PERMISSION_GRANTED);

    ret = AccessTokenKit::DeleteRemoteToken(deviceID6, 0x20100000);
    EXPECT_EQ(ret, RET_SUCCESS);
}

/**
 * @tc.name: SetRemoteHapTokenInfoSpecTest003
 * @tc.desc: add remote hap token, it can not delete by DeleteToken
 * @tc.type: FUNC
 * @tc.require:issue I5R4UF
 */
HWTEST_F(SetRemoteHapTokenInfoTest, SetRemoteHapTokenInfoSpecTest003, TestSize.Level1)
{
    ACCESSTOKEN_LOG_INFO(LABEL, "SetRemoteHapTokenInfoSpecTest003 start.");
    std::string deviceID7 = udid_;
    AccessTokenKit::DeleteRemoteToken(deviceID7, 0x20100000);
    PermissionStateFull infoManagerTestState7 = {
        .permissionName = "ohos.permission.READ_AUDIO",
        .isGeneral = true,
        .resDeviceID = {"local"},
        .grantStatus = {PermissionState::PERMISSION_DENIED}, // first denied
        .grantFlags = {PermissionFlag::PERMISSION_SYSTEM_FIXED}};
    std::vector<PermissionStateFull> permStateList7;
    permStateList7.emplace_back(infoManagerTestState7);

    g_baseInfo.deviceID = deviceID7;
    HapTokenInfoForSync remoteTokenInfo7 = {
        .baseInfo = g_baseInfo,
        .permStateList = permStateList7
    };

    int ret = AccessTokenKit::SetRemoteHapTokenInfo(deviceID7, remoteTokenInfo7);
    ASSERT_EQ(ret, RET_SUCCESS);

    // Get local map token ID
    AccessTokenID mapID = AccessTokenKit::AllocLocalTokenID(networkId_, 0x20100000);
    ASSERT_NE(mapID, 0);

    ret = AccessTokenKit::DeleteToken(mapID);
    ASSERT_NE(ret, RET_SUCCESS);

    ret = AccessTokenKit::DeleteRemoteToken(deviceID7, 0x20100000);
    ASSERT_EQ(ret, RET_SUCCESS);
}

/**
 * @tc.name: SetRemoteHapTokenInfoSpecTest004
 * @tc.desc: add remote hap token, it can not update by UpdateHapToken
 * @tc.type: FUNC
 * @tc.require:issue I5R4UF
 */
HWTEST_F(SetRemoteHapTokenInfoTest, SetRemoteHapTokenInfoSpecTest004, TestSize.Level1)
{
    ACCESSTOKEN_LOG_INFO(LABEL, "SetRemoteHapTokenInfoSpecTest004 start.");
    std::string deviceID8 = udid_;
    AccessTokenKit::DeleteRemoteToken(deviceID8, 0x20100000);
    int32_t DEFAULT_API_VERSION = 8;
    PermissionStateFull infoManagerTestState8 = {
        .permissionName = "ohos.permission.test1",
        .isGeneral = true,
        .resDeviceID = {"local"},
        .grantStatus = {PermissionState::PERMISSION_DENIED}, // first denied
        .grantFlags = {PermissionFlag::PERMISSION_SYSTEM_FIXED}};
    std::vector<PermissionStateFull> permStateList8;
    permStateList8.emplace_back(infoManagerTestState8);

    g_baseInfo.deviceID = deviceID8;
    HapTokenInfoForSync remoteTokenInfo8 = {
        .baseInfo = g_baseInfo,
        .permStateList = permStateList8
    };

    int ret = AccessTokenKit::SetRemoteHapTokenInfo(deviceID8, remoteTokenInfo8);
    ASSERT_EQ(ret, RET_SUCCESS);

    // Get local map token ID
    AccessTokenID mapID = AccessTokenKit::AllocLocalTokenID(networkId_, 0x20100000);
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

    ret = AccessTokenKit::DeleteRemoteToken(deviceID8, 0x20100000);
    ASSERT_EQ(ret, RET_SUCCESS);
}

/**
 * @tc.name: SetRemoteHapTokenInfoSpecTest005
 * @tc.desc: add remote hap token, it can not clear by ClearUserGrantedPermissionState
 * @tc.type: FUNC
 * @tc.require:issue I5R4UF
 */
HWTEST_F(SetRemoteHapTokenInfoTest, SetRemoteHapTokenInfoSpecTest005, TestSize.Level1)
{
    ACCESSTOKEN_LOG_INFO(LABEL, "SetRemoteHapTokenInfoSpecTest005 start.");
    std::string deviceID9 = udid_;
    AccessTokenKit::DeleteRemoteToken(deviceID9, 0x20100000);
    PermissionStateFull infoManagerTestState9 = {
        .permissionName = "ohos.permission.CAMERA",
        .isGeneral = true,
        .resDeviceID = {"local4"},
        .grantStatus = {PermissionState::PERMISSION_GRANTED},
        .grantFlags = {PermissionFlag::PERMISSION_USER_SET}};
    std::vector<PermissionStateFull> permStateList9;
    permStateList9.emplace_back(infoManagerTestState9);

    g_baseInfo.deviceID = deviceID9;
    HapTokenInfoForSync remoteTokenInfo9 = {
        .baseInfo = g_baseInfo,
        .permStateList = permStateList9
    };

    int ret = AccessTokenKit::SetRemoteHapTokenInfo(deviceID9, remoteTokenInfo9);
    ASSERT_EQ(ret, RET_SUCCESS);

    // Get local map token ID
    AccessTokenID mapID = AccessTokenKit::AllocLocalTokenID(networkId_, 0x20100000);
    ASSERT_NE(mapID, 0);

    ret = AccessTokenKit::VerifyAccessToken(mapID, "ohos.permission.CAMERA", false);
    ASSERT_EQ(ret, PermissionState::PERMISSION_GRANTED);

    ret = AccessTokenKit::ClearUserGrantedPermissionState(mapID);
    ASSERT_EQ(ret, RET_SUCCESS);

    ret = AccessTokenKit::VerifyAccessToken(mapID, "ohos.permission.CAMERA", false);
    ASSERT_EQ(ret, PermissionState::PERMISSION_GRANTED);

    ret = AccessTokenKit::DeleteRemoteToken(deviceID9, 0x20100000);
    ASSERT_EQ(ret, RET_SUCCESS);
}

/**
 * @tc.name: SetRemoteHapTokenInfoSpecTest006
 * @tc.desc: tokenID is not hap token
 * @tc.type: FUNC
 * @tc.require:issue I5R4UF
 */
HWTEST_F(SetRemoteHapTokenInfoTest, SetRemoteHapTokenInfoSpecTest006, TestSize.Level1)
{
    ACCESSTOKEN_LOG_INFO(LABEL, "SetRemoteHapTokenInfoSpecTest006 start.");
    std::string deviceID = udid_;
    HapTokenInfo baseInfo = {
        .apl = APL_NORMAL,
        .ver = 1,
        .userID = 1,
        .bundleName = "com.ohos.access_token",
        .instIndex = 1,
        .appID = "testtesttesttest",
        .deviceID = udid_,
        .tokenID = 0x28100000,
        .tokenAttr = 0
    };

    PermissionStateFull infoManagerTestState = {
        .permissionName = "ohos.permission.test1",
        .isGeneral = true,
        .resDeviceID = {"local"},
        .grantStatus = {PermissionState::PERMISSION_GRANTED},
        .grantFlags = {PermissionFlag::PERMISSION_USER_SET}};
    std::vector<PermissionStateFull> permStateList;
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
HWTEST_F(SetRemoteHapTokenInfoTest, SetRemoteHapTokenInfoAbnormalTest001, TestSize.Level1)
{
    ACCESSTOKEN_LOG_INFO(LABEL, "SetRemoteHapTokenInfoAbnormalTest001 start.");
    EXPECT_EQ(0, SetSelfTokenID(g_selfTokenId));
    std::string device = "device";
    HapTokenInfoForSync hapSync;
    ASSERT_EQ(AccessTokenError::ERR_PERMISSION_DENIED, AccessTokenKit::SetRemoteHapTokenInfo(device, hapSync));
}
#endif