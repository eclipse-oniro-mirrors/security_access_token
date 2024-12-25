/*
 * Copyright (c) 2022-2024 Huawei Device Co., Ltd.
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

#include "remote_token_kit_test.h"
#include <thread>

#include "accesstoken_kit.h"
#include "accesstoken_log.h"
#include "access_token_error.h"
#include "nativetoken_kit.h"
#include "token_setproc.h"

using namespace testing::ext;
using namespace OHOS::Security::AccessToken;

namespace {
static constexpr OHOS::HiviewDFX::HiLogLabel LABEL = {LOG_CORE, SECURITY_DOMAIN_ACCESSTOKEN, "RemoteTokenKitTest"};

static const std::string TEST_BUNDLE_NAME = "ohos";
static const std::string TEST_PKG_NAME = "com.softbus.test";
static const int TEST_USER_ID = 0;

PermissionDef g_infoManagerTestPermDef1 = {
    .permissionName = "ohos.permission.test1",
    .bundleName = "accesstoken_test",
    .grantMode = 1,
    .availableLevel = APL_NORMAL,
    .label = "label4",
    .labelId = 1,
    .description = "open the door",
    .descriptionId = 1,
};

PermissionDef g_infoManagerTestPermDef2 = {
    .permissionName = "ohos.permission.test2",
    .bundleName = "accesstoken_test",
    .grantMode = 1,
    .availableLevel = APL_NORMAL,
    .label = "label4",
    .labelId = 1,
    .description = "break the door",
    .descriptionId = 1,
};

PermissionStateFull g_infoManagerTestState1 = {
    .permissionName = "ohos.permission.test1",
    .isGeneral = true,
    .resDeviceID = {"local4"},
    .grantStatus = {PermissionState::PERMISSION_GRANTED},
    .grantFlags = {1},
};

PermissionStateFull g_infoManagerTestState2 = {
    .permissionName = "ohos.permission.test2",
    .isGeneral = false,
    .resDeviceID = {"device 1", "device 2"},
    .grantStatus = {PermissionState::PERMISSION_GRANTED, PermissionState::PERMISSION_GRANTED},
    .grantFlags = {1, 2},
};

HapInfoParams g_infoManagerTestInfoParms = {
    .userID = 1,
    .bundleName = "accesstoken_test",
    .instIndex = 0,
    .appIDDesc = "test4"
};

HapPolicyParams g_infoManagerTestPolicyPrams = {
    .apl = APL_NORMAL,
    .domain = "test.domain4",
    .permList = {g_infoManagerTestPermDef1, g_infoManagerTestPermDef2},
    .permStateList = {g_infoManagerTestState1, g_infoManagerTestState2}
};

HapInfoParams g_infoManagerTestInfoParmsBak = {
    .userID = 1,
    .bundleName = "accesstoken_test",
    .instIndex = 0,
    .appIDDesc = "test4"
};

HapPolicyParams g_infoManagerTestPolicyPramsBak = {
    .apl = APL_NORMAL,
    .domain = "test.domain4",
    .permList = {g_infoManagerTestPermDef1, g_infoManagerTestPermDef2},
    .permStateList = {g_infoManagerTestState1, g_infoManagerTestState2}
};

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

void RemoteTokenKitTest::SetUpTestCase()
{
    // make test case clean
    AccessTokenID tokenID = AccessTokenKit::GetHapTokenID(g_infoManagerTestInfoParms.userID,
                                                          g_infoManagerTestInfoParms.bundleName,
                                                          g_infoManagerTestInfoParms.instIndex);
    AccessTokenKit::DeleteToken(tokenID);

    tokenID = AccessTokenKit::GetHapTokenID(TEST_USER_ID, TEST_BUNDLE_NAME, 0);
    AccessTokenKit::DeleteToken(tokenID);

    NativeTokenGet();

#ifdef TOKEN_SYNC_ENABLE
    std::shared_ptr<TestDmInitCallback> ptrDmInitCallback = std::make_shared<TestDmInitCallback>();
    int32_t res = DistributedHardware::DeviceManager::GetInstance().InitDeviceManager(TEST_PKG_NAME, ptrDmInitCallback);
    ASSERT_EQ(res, RET_SUCCESS);
#endif
}

void RemoteTokenKitTest::TearDownTestCase()
{
#ifdef TOKEN_SYNC_ENABLE
    int32_t res = DistributedHardware::DeviceManager::GetInstance().UnInitDeviceManager(TEST_PKG_NAME);
    ASSERT_EQ(res, RET_SUCCESS);
#endif
}

void RemoteTokenKitTest::SetUp()
{
    selfTokenId_ = GetSelfTokenID();
    g_infoManagerTestInfoParms = g_infoManagerTestInfoParmsBak;
    g_infoManagerTestPolicyPrams = g_infoManagerTestPolicyPramsBak;
    AccessTokenID tokenID = AccessTokenKit::GetHapTokenID(g_infoManagerTestInfoParms.userID,
                                                          g_infoManagerTestInfoParms.bundleName,
                                                          g_infoManagerTestInfoParms.instIndex);
    AccessTokenKit::DeleteToken(tokenID);

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
}

void RemoteTokenKitTest::TearDown()
{
    AccessTokenID tokenID = GetAccessTokenID(TEST_USER_ID, TEST_BUNDLE_NAME, 0);
    AccessTokenKit::DeleteToken(tokenID);
    EXPECT_EQ(0, SetSelfTokenID(selfTokenId_));
    udid_.clear();
    networkId_.clear();
}

unsigned int RemoteTokenKitTest::GetAccessTokenID(int userID, std::string bundleName, int instIndex)
{
    return AccessTokenKit::GetHapTokenID(userID, bundleName, instIndex);
}

void RemoteTokenKitTest::DeleteTestToken() const
{
    AccessTokenID tokenID = AccessTokenKit::GetHapTokenID(g_infoManagerTestInfoParms.userID,
                                                          g_infoManagerTestInfoParms.bundleName,
                                                          g_infoManagerTestInfoParms.instIndex);
    int ret = AccessTokenKit::DeleteToken(tokenID);
    if (tokenID != 0) {
        ASSERT_EQ(RET_SUCCESS, ret);
    }
}

void RemoteTokenKitTest::AllocTestToken() const
{
    AccessTokenIDEx tokenIdEx = {0};
    tokenIdEx = AccessTokenKit::AllocHapToken(g_infoManagerTestInfoParms, g_infoManagerTestPolicyPrams);
    ASSERT_NE(INVALID_TOKENID, tokenIdEx.tokenIdExStruct.tokenID);
}

#ifdef TOKEN_SYNC_ENABLE
/**
 * @tc.name: SetRemoteHapTokenInfo001
 * @tc.desc: set remote hap token info success
 * @tc.type: FUNC
 * @tc.require:issue I5R4UF
 */
HWTEST_F(RemoteTokenKitTest, SetRemoteHapTokenInfo001, TestSize.Level1)
{
    ACCESSTOKEN_LOG_INFO(LABEL, "SetRemoteHapTokenInfo001 start.");
    std::string deviceID1 = udid_;
    AccessTokenKit::DeleteRemoteToken(deviceID1, 0x20100000);
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
    AccessTokenID mapID = AccessTokenKit::AllocLocalTokenID(networkId_, 0x20100000);
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

    ret = AccessTokenKit::DeleteRemoteToken(deviceID1, 0x20100000);
    ASSERT_EQ(ret, RET_SUCCESS);
}

void SetRemoteHapTokenInfoWithWrongInfo(HapTokenInfo &wrongBaseInfo, const HapTokenInfo &rightBaseInfo,
    HapTokenInfoForSync &remoteTokenInfo, const std::string &deviceID)
{
    std::string wrongStr(10241, 'x'); // 10241 means the invalid string length

    wrongBaseInfo = rightBaseInfo;
    wrongBaseInfo.bundleName = wrongStr; // wrong bundleName
    remoteTokenInfo.baseInfo = wrongBaseInfo;
    int ret = AccessTokenKit::SetRemoteHapTokenInfo(deviceID, remoteTokenInfo);
    EXPECT_NE(ret, RET_SUCCESS);

    wrongBaseInfo = rightBaseInfo;
    wrongBaseInfo.tokenID = 0; // wrong tokenID
    remoteTokenInfo.baseInfo = wrongBaseInfo;
    ret = AccessTokenKit::SetRemoteHapTokenInfo(deviceID, remoteTokenInfo);
    EXPECT_NE(ret, RET_SUCCESS);
}

/**
 * @tc.name: SetRemoteHapTokenInfo002
 * @tc.desc: set remote hap token info, token info is wrong
 * @tc.type: FUNC
 * @tc.require:issue I5R4UF
 */
HWTEST_F(RemoteTokenKitTest, SetRemoteHapTokenInfo002, TestSize.Level1)
{
    ACCESSTOKEN_LOG_INFO(LABEL, "SetRemoteHapTokenInfo002 start.");
    std::string deviceID2 = udid_;
    AccessTokenKit::DeleteRemoteToken(deviceID2, 0x20100000);
    HapTokenInfo rightBaseInfo = {
        .ver = 1,
        .userID = 1,
        .bundleName = "com.ohos.access_token",
        .instIndex = 1,
        .tokenID = 0x20100000,
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

    SetRemoteHapTokenInfoWithWrongInfo(wrongBaseInfo, rightBaseInfo, remoteTokenInfo2, deviceID2);
}

/**
 * @tc.name: SetRemoteHapTokenInfo003
 * @tc.desc: set remote hap token wrong permission grant
 * @tc.type: FUNC
 * @tc.require:issue I5R4UF
 */
HWTEST_F(RemoteTokenKitTest, SetRemoteHapTokenInfo003, TestSize.Level1)
{
    ACCESSTOKEN_LOG_INFO(LABEL, "SetRemoteHapTokenInfo003 start.");
    std::string deviceID3 = udid_;
    AccessTokenKit::DeleteRemoteToken(deviceID3, 0x20100000);

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
    AccessTokenID mapID = AccessTokenKit::AllocLocalTokenID(networkId_, 0x20100000);
    ASSERT_NE(mapID, 0);

    ret = AccessTokenKit::VerifyAccessToken(mapID, "ohos.permission.test1", false);
    ASSERT_EQ(ret, PermissionState::PERMISSION_DENIED);

    ret = AccessTokenKit::DeleteRemoteToken(deviceID3, 0x20100000);
    ASSERT_EQ(ret, RET_SUCCESS);
}

/**
 * @tc.name: SetRemoteHapTokenInfo004
 * @tc.desc: update remote hap token when remote exist
 * @tc.type: FUNC
 * @tc.require:issue I5R4UF
 */
HWTEST_F(RemoteTokenKitTest, SetRemoteHapTokenInfo004, TestSize.Level1)
{
    ACCESSTOKEN_LOG_INFO(LABEL, "SetRemoteHapTokenInfo004 start.");
    std::string deviceID4 = udid_;
    AccessTokenKit::DeleteRemoteToken(deviceID4, 0x20100000);
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
    AccessTokenID mapID = AccessTokenKit::AllocLocalTokenID(networkId_, 0x20100000);
    ASSERT_NE(mapID, 0);

    ret = AccessTokenKit::VerifyAccessToken(mapID, "ohos.permission.CAMERA", false);
    ASSERT_EQ(ret, PermissionState::PERMISSION_DENIED);

    remoteTokenInfo4.permStateList[0].grantStatus = PermissionState::PERMISSION_GRANTED; // second granted
    ret = AccessTokenKit::SetRemoteHapTokenInfo(deviceID4, remoteTokenInfo4);
    ASSERT_EQ(ret, RET_SUCCESS);

    ret = AccessTokenKit::VerifyAccessToken(mapID, "ohos.permission.CAMERA", false);
    ASSERT_EQ(ret, PermissionState::PERMISSION_GRANTED);

    ret = AccessTokenKit::DeleteRemoteToken(deviceID4, 0x20100000);
    ASSERT_EQ(ret, RET_SUCCESS);
}

/**
 * @tc.name: SetRemoteHapTokenInfo005
 * @tc.desc: add remote hap token, it can not grant by GrantPermission
 * @tc.type: FUNC
 * @tc.require:issue I5R4UF
 */
HWTEST_F(RemoteTokenKitTest, SetRemoteHapTokenInfo005, TestSize.Level1)
{
    ACCESSTOKEN_LOG_INFO(LABEL, "SetRemoteHapTokenInfo005 start.");
    std::string deviceID5 = udid_;
    AccessTokenKit::DeleteRemoteToken(deviceID5, 0x20100000);
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
 * @tc.name: SetRemoteHapTokenInfo006
 * @tc.desc: add remote hap token, it can not revoke by RevokePermission
 * @tc.type: FUNC
 * @tc.require:issue I5R4UF
 */
HWTEST_F(RemoteTokenKitTest, SetRemoteHapTokenInfo006, TestSize.Level1)
{
    ACCESSTOKEN_LOG_INFO(LABEL, "SetRemoteHapTokenInfo006 start.");
    std::string deviceID6 = udid_;
    AccessTokenKit::DeleteRemoteToken(deviceID6, 0x20100000);
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
 * @tc.name: SetRemoteHapTokenInfo007
 * @tc.desc: add remote hap token, it can not delete by DeleteToken
 * @tc.type: FUNC
 * @tc.require:issue I5R4UF
 */
HWTEST_F(RemoteTokenKitTest, SetRemoteHapTokenInfo007, TestSize.Level1)
{
    ACCESSTOKEN_LOG_INFO(LABEL, "SetRemoteHapTokenInfo007 start.");
    std::string deviceID7 = udid_;
    AccessTokenKit::DeleteRemoteToken(deviceID7, 0x20100000);
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
    AccessTokenID mapID = AccessTokenKit::AllocLocalTokenID(networkId_, 0x20100000);
    ASSERT_NE(mapID, 0);

    ret = AccessTokenKit::DeleteToken(mapID);
    ASSERT_NE(ret, RET_SUCCESS);

    ret = AccessTokenKit::DeleteRemoteToken(deviceID7, 0x20100000);
    ASSERT_EQ(ret, RET_SUCCESS);
}

/**
 * @tc.name: SetRemoteHapTokenInfo008
 * @tc.desc: add remote hap token, it can not update by UpdateHapToken
 * @tc.type: FUNC
 * @tc.require:issue I5R4UF
 */
HWTEST_F(RemoteTokenKitTest, SetRemoteHapTokenInfo008, TestSize.Level1)
{
    ACCESSTOKEN_LOG_INFO(LABEL, "SetRemoteHapTokenInfo008 start.");
    std::string deviceID8 = udid_;
    AccessTokenKit::DeleteRemoteToken(deviceID8, 0x20100000);
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
 * @tc.name: SetRemoteHapTokenInfo009
 * @tc.desc: add remote hap token, it can not clear by ClearUserGrantedPermissionState
 * @tc.type: FUNC
 * @tc.require:issue I5R4UF
 */
HWTEST_F(RemoteTokenKitTest, SetRemoteHapTokenInfo009, TestSize.Level1)
{
    ACCESSTOKEN_LOG_INFO(LABEL, "SetRemoteHapTokenInfo009 start.");
    std::string deviceID9 = udid_;
    AccessTokenKit::DeleteRemoteToken(deviceID9, 0x20100000);
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
 * @tc.name: SetRemoteHapTokenInfo010
 * @tc.desc: tokenID is not hap token
 * @tc.type: FUNC
 * @tc.require:issue I5R4UF
 */
HWTEST_F(RemoteTokenKitTest, SetRemoteHapTokenInfo010, TestSize.Level1)
{
    ACCESSTOKEN_LOG_INFO(LABEL, "SetRemoteHapTokenInfo009 start.");
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
 * @tc.name: DeleteRemoteDeviceToken001
 * @tc.desc: delete exist device mapping tokenId
 * @tc.type: FUNC
 * @tc.require:issue I5R4UF
 */
HWTEST_F(RemoteTokenKitTest, DeleteRemoteDeviceToken001, TestSize.Level1)
{
    ACCESSTOKEN_LOG_INFO(LABEL, "DeleteRemoteDeviceTokens001 start.");
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
 * @tc.name: DeleteRemoteDeviceToken002
 * @tc.desc: delete exist device mapping tokenId
 * @tc.type: FUNC
 * @tc.require:issue I5R4UF
 */
HWTEST_F(RemoteTokenKitTest, DeleteRemoteDeviceToken002, TestSize.Level1)
{
    ACCESSTOKEN_LOG_INFO(LABEL, "DeleteRemoteDeviceTokens001 start.");
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
 * @tc.name: DeleteRemoteDeviceToken003
 * @tc.desc: delete exist device mapping tokenId
 * @tc.type: FUNC
 * @tc.require:issue I5R4UF
 */
HWTEST_F(RemoteTokenKitTest, DeleteRemoteDeviceToken003, TestSize.Level1)
{
    ACCESSTOKEN_LOG_INFO(LABEL, "DeleteRemoteDeviceToken003 start.");
    std::string deviceID3 = udid_;
    AccessTokenKit::DeleteRemoteToken(deviceID3, 0x20100000);

    int ret = AccessTokenKit::DeleteRemoteToken(deviceID3, 0x20100000);
    ASSERT_NE(ret, RET_SUCCESS);
}

/**
 * @tc.name: DeleteRemoteDeviceTokens001
 * @tc.desc: delete all mapping tokens of exist device
 * @tc.type: FUNC
 * @tc.require:issue I5R4UF
 */
HWTEST_F(RemoteTokenKitTest, DeleteRemoteDeviceTokens001, TestSize.Level1)
{
    ACCESSTOKEN_LOG_INFO(LABEL, "DeleteRemoteDeviceTokens001 start.");
    std::string deviceID1 = udid_;
    AccessTokenKit::DeleteRemoteToken(deviceID1, 0x20100000);
    AccessTokenKit::DeleteRemoteToken(deviceID1, 0x20100001);
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
    remoteTokenInfo2.baseInfo.tokenID = 0x20100001;
    remoteTokenInfo2.baseInfo.bundleName = "com.ohos.access_token1";
    ret = AccessTokenKit::SetRemoteHapTokenInfo(deviceID1, remoteTokenInfo2);
    ASSERT_EQ(ret, RET_SUCCESS);

    AccessTokenID mapID = AccessTokenKit::AllocLocalTokenID(networkId_, 0x20100000);
    ASSERT_NE(mapID, 0);
    AccessTokenID mapID1 = AccessTokenKit::AllocLocalTokenID(networkId_, 0x20100001);
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
 * @tc.name: DeleteRemoteDeviceTokens002
 * @tc.desc: delete all mapping tokens of NOT exist device
 * @tc.type: FUNC
 * @tc.require:issue I5R4UF
 */
HWTEST_F(RemoteTokenKitTest, DeleteRemoteDeviceTokens002, TestSize.Level1)
{
    ACCESSTOKEN_LOG_INFO(LABEL, "DeleteRemoteDeviceTokens002 start.");
    std::string deviceID2 = udid_;
    AccessTokenKit::DeleteRemoteToken(deviceID2, 0x20100000);
    AccessTokenKit::DeleteRemoteToken(deviceID2, 0x20100001);
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
    remoteTokenInfo1.baseInfo.tokenID = 0x20100001;
    remoteTokenInfo1.baseInfo.bundleName = "com.ohos.access_token1";
    ret = AccessTokenKit::SetRemoteHapTokenInfo(deviceID2, remoteTokenInfo1);
    ASSERT_EQ(ret, RET_SUCCESS);

    AccessTokenID mapID = AccessTokenKit::AllocLocalTokenID(networkId_, 0x20100000);
    ASSERT_NE(mapID, 0);
    AccessTokenID mapID1 = AccessTokenKit::AllocLocalTokenID(networkId_, 0x20100001);
    ASSERT_NE(mapID1, 0);

    ret = AccessTokenKit::DeleteRemoteDeviceTokens("1111111");
    ASSERT_NE(ret, RET_SUCCESS);

    AccessTokenKit::DeleteRemoteToken(deviceID2, 0x20100000);
    AccessTokenKit::DeleteRemoteToken(deviceID2, 0x20100001);
}

/**
 * @tc.name: GetHapTokenInfoFromRemote001
 * @tc.desc: get normal local tokenInfo
 * @tc.type: FUNC
 * @tc.require:issue I5R4UF
 */
HWTEST_F(RemoteTokenKitTest, GetHapTokenInfoFromRemote001, TestSize.Level1)
{
    ACCESSTOKEN_LOG_INFO(LABEL, "GetHapTokenInfoFromRemote001 start.");
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
 * @tc.name: GetHapTokenInfoFromRemote002
 * @tc.desc: get remote mapping tokenInfo
 * @tc.type: FUNC
 * @tc.require:issue I5R4UF
 */
HWTEST_F(RemoteTokenKitTest, GetHapTokenInfoFromRemote002, TestSize.Level1)
{
    ACCESSTOKEN_LOG_INFO(LABEL, "GetHapTokenInfoFromRemote002 start.");
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
 * @tc.name: GetHapTokenInfoFromRemote003
 * @tc.desc: get wrong tokenInfo
 * @tc.type: FUNC
 * @tc.require:issue I5R4UF
 */
HWTEST_F(RemoteTokenKitTest, GetHapTokenInfoFromRemote003, TestSize.Level1)
{
    ACCESSTOKEN_LOG_INFO(LABEL, "GetHapTokenInfoFromRemote003 start.");
    HapTokenInfoForSync infoSync;
    int ret = AccessTokenKit::GetHapTokenInfoFromRemote(0, infoSync);
    ASSERT_NE(ret, RET_SUCCESS);
}

/**
 * @tc.name: AllocLocalTokenID001
 * @tc.desc: get already mapping tokenInfo, makesure ipc right
 * @tc.type: FUNC
 * @tc.require:issue I5R4UF
 */
HWTEST_F(RemoteTokenKitTest, AllocLocalTokenID001, TestSize.Level1)
{
    ACCESSTOKEN_LOG_INFO(LABEL, "AllocLocalTokenID001 start.");
    std::string deviceID1 = udid_;
    AccessTokenKit::DeleteRemoteToken(deviceID1, 0x20100000);
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

    AccessTokenID mapID = AccessTokenKit::AllocLocalTokenID(networkId_, 0x20100000);
    ASSERT_NE(mapID, 0);
}

/**
 * @tc.name: DeleteRemoteToken001
 * @tc.desc: DeleteRemoteToken with invalid parameters.
 * @tc.type: FUNC
 * @tc.require:Issue Number
 */
HWTEST_F(RemoteTokenKitTest, DeleteRemoteToken001, TestSize.Level1)
{
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
 * @tc.name: RegisterTokenSyncCallback001
 * @tc.desc: set token sync callback with invalid pointer
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(RemoteTokenKitTest, RegisterTokenSyncCallback001, TestSize.Level1)
{
    int32_t ret = AccessTokenKit::RegisterTokenSyncCallback(nullptr);
    EXPECT_EQ(ERR_PARAM_INVALID, ret);
}

/**
 * @tc.name: RegisterTokenSyncCallback002
 * @tc.desc: set token sync callback with right pointer
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(RemoteTokenKitTest, RegisterTokenSyncCallback002, TestSize.Level1)
{
    std::shared_ptr<TokenSyncKitInterface> callback = std::make_shared<TokenSyncCallbackImpl>();
    EXPECT_EQ(RET_SUCCESS, AccessTokenKit::RegisterTokenSyncCallback(callback));
    EXPECT_EQ(RET_SUCCESS, AccessTokenKit::AllocLocalTokenID(networkId_, 0)); // invalid input, would ret 0
    EXPECT_EQ(RET_SUCCESS, AccessTokenKit::UnRegisterTokenSyncCallback());
}
#endif
