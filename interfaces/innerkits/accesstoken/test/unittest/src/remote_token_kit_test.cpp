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
#include "softbus_bus_center.h"
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
}

void RemoteTokenKitTest::TearDownTestCase()
{
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

    NodeBasicInfo deviceInfo;
    int32_t res = ::GetLocalNodeDeviceInfo(TEST_PKG_NAME.c_str(), &deviceInfo);
    ASSERT_EQ(res, RET_SUCCESS);
    char udid[128] = {0}; // 128 is udid length
    ::GetNodeKeyInfo(TEST_PKG_NAME.c_str(), deviceInfo.networkId,
        NodeDeviceInfoKey::NODE_KEY_UDID, reinterpret_cast<uint8_t *>(udid), 128); // 128 is udid length

    udid_.append(udid);
    networkId_.append(deviceInfo.networkId);

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

void SetRemoteHapTokenInfoWithWrongInfo(HapTokenInfo &wrongBaseInfo, const HapTokenInfo &rightBaseInfo,
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
    PermissionStateFull infoManagerTestState6 = {
        .permissionName = "ohos.permission.test1",
        .isGeneral = true,
        .resDeviceID = {"local4"},
        .grantStatus = {PermissionState::PERMISSION_GRANTED}, // first grant
        .grantFlags = {PermissionFlag::PERMISSION_SYSTEM_FIXED}};
    std::vector<PermissionStateFull> permStateList6;
    permStateList6.emplace_back(infoManagerTestState6);

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

    ret = AccessTokenKit::VerifyAccessToken(mapID, "ohos.permission.test1", false);
    EXPECT_EQ(ret, PermissionState::PERMISSION_GRANTED);

    ret = AccessTokenKit::RevokePermission(mapID, "ohos.permission.test1", PermissionFlag::PERMISSION_SYSTEM_FIXED);
    EXPECT_EQ(ret, ERR_PERMISSION_NOT_EXIST);

    ret = AccessTokenKit::VerifyAccessToken(mapID, "ohos.permission.test1", false);
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
    PermissionStateFull infoManagerTestState7 = {
        .permissionName = "ohos.permission.test1",
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
    PermissionStateFull infoManagerTestState_3 = {
        .permissionName = "ohos.permission.test1",
        .isGeneral = true,
        .resDeviceID = {"local4"},
        .grantStatus = {PermissionState::PERMISSION_GRANTED},
        .grantFlags = {PermissionFlag::PERMISSION_USER_SET}};
    std::vector<PermissionStateFull> permStateList1;
    permStateList1.emplace_back(infoManagerTestState_3);

    g_baseInfo.deviceID = deviceID1;
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
    PermissionStateFull infoManagerTestState_2 = {
        .permissionName = "ohos.permission.test1",
        .isGeneral = true,
        .resDeviceID = {"local4"},
        .grantStatus = {PermissionState::PERMISSION_GRANTED},
        .grantFlags = {PermissionFlag::PERMISSION_USER_SET}};
    std::vector<PermissionStateFull> permStateList2;
    permStateList2.emplace_back(infoManagerTestState_2);

    g_baseInfo.deviceID = deviceID2;
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
    PermissionStateFull infoManagerTestState4 = {
        .permissionName = "ohos.permission.test1",
        .isGeneral = true,
        .resDeviceID = {"local4"},
        .grantStatus = {PermissionState::PERMISSION_GRANTED},
        .grantFlags = {PermissionFlag::PERMISSION_USER_SET}};
    std::vector<PermissionStateFull> permStateList1;
    permStateList1.emplace_back(infoManagerTestState4);

    g_baseInfo.deviceID = deviceID1;
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
    PermissionStateFull infoManagerTestState2 = {
        .permissionName = "ohos.permission.test1",
        .isGeneral = true,
        .resDeviceID = {"local"},
        .grantStatus = {PermissionState::PERMISSION_GRANTED},
        .grantFlags = {PermissionFlag::PERMISSION_USER_SET}};
    std::vector<PermissionStateFull> permStateList2;
    permStateList2.emplace_back(infoManagerTestState2);

    g_baseInfo.deviceID = deviceID2;
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
    ASSERT_EQ(infoSync.baseInfo.apl, g_infoManagerTestPolicyPrams.apl);
    ASSERT_EQ(infoSync.permStateList.size(), static_cast<uint32_t>(2));
    ASSERT_EQ(infoSync.permStateList[1].grantFlags.size(), static_cast<uint32_t>(2));

    ASSERT_EQ(infoSync.permStateList[0].permissionName, g_infoManagerTestPolicyPrams.permStateList[0].permissionName);
    ASSERT_EQ(infoSync.permStateList[0].grantFlags[0], g_infoManagerTestPolicyPrams.permStateList[0].grantFlags[0]);
    ASSERT_EQ(infoSync.permStateList[0].grantStatus[0], g_infoManagerTestPolicyPrams.permStateList[0].grantStatus[0]);
    ASSERT_EQ(infoSync.permStateList[0].resDeviceID[0], g_infoManagerTestPolicyPrams.permStateList[0].resDeviceID[0]);
    ASSERT_EQ(infoSync.permStateList[0].isGeneral, g_infoManagerTestPolicyPrams.permStateList[0].isGeneral);

    ASSERT_EQ(infoSync.permStateList[1].permissionName, g_infoManagerTestPolicyPrams.permStateList[1].permissionName);
    ASSERT_EQ(infoSync.permStateList[1].grantFlags[0], g_infoManagerTestPolicyPrams.permStateList[1].grantFlags[0]);
    ASSERT_EQ(infoSync.permStateList[1].grantStatus[0], g_infoManagerTestPolicyPrams.permStateList[1].grantStatus[0]);
    ASSERT_EQ(infoSync.permStateList[1].resDeviceID[0], g_infoManagerTestPolicyPrams.permStateList[1].resDeviceID[0]);
    ASSERT_EQ(infoSync.permStateList[1].isGeneral, g_infoManagerTestPolicyPrams.permStateList[1].isGeneral);

    ASSERT_EQ(infoSync.permStateList[1].grantFlags[1], g_infoManagerTestPolicyPrams.permStateList[1].grantFlags[1]);
    ASSERT_EQ(infoSync.permStateList[1].grantStatus[1], g_infoManagerTestPolicyPrams.permStateList[1].grantStatus[1]);
    ASSERT_EQ(infoSync.permStateList[1].resDeviceID[1], g_infoManagerTestPolicyPrams.permStateList[1].resDeviceID[1]);

    ASSERT_EQ(infoSync.baseInfo.bundleName, g_infoManagerTestInfoParms.bundleName);
    ASSERT_EQ(infoSync.baseInfo.userID, g_infoManagerTestInfoParms.userID);
    ASSERT_EQ(infoSync.baseInfo.instIndex, g_infoManagerTestInfoParms.instIndex);
    ASSERT_EQ(infoSync.baseInfo.appID, g_infoManagerTestInfoParms.appIDDesc);
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
    PermissionStateFull infoManagerTestState2 = {
        .permissionName = "ohos.permission.test1",
        .isGeneral = true,
        .resDeviceID = {"local"},
        .grantStatus = {PermissionState::PERMISSION_GRANTED},
        .grantFlags = {PermissionFlag::PERMISSION_USER_SET}};
    std::vector<PermissionStateFull> permStateList2;
    permStateList2.emplace_back(infoManagerTestState2);

    g_baseInfo.deviceID = deviceID2;
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
    PermissionStateFull infoManagerTestState_1 = {
        .permissionName = "ohos.permission.test1",
        .isGeneral = true,
        .resDeviceID = {"local4"},
        .grantStatus = {PermissionState::PERMISSION_GRANTED},
        .grantFlags = {PermissionFlag::PERMISSION_USER_SET}};
    std::vector<PermissionStateFull> permStateList1;
    permStateList1.emplace_back(infoManagerTestState_1);

    g_baseInfo.deviceID = deviceID1;
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
 * @tc.name: GetAllNativeTokenInfo001
 * @tc.desc: get all native token with dcaps
 * @tc.type: FUNC
 * @tc.require:issue I5R4UF
 */
HWTEST_F(RemoteTokenKitTest, GetAllNativeTokenInfo001, TestSize.Level1)
{
    ACCESSTOKEN_LOG_INFO(LABEL, "GetAllNativeTokenInfo001 start.");

    std::vector<NativeTokenInfoForSync> nativeTokenInfosRes;
    int ret = AccessTokenKit::GetAllNativeTokenInfo(nativeTokenInfosRes);
    ASSERT_EQ(ret, RET_SUCCESS);
}

/**
 * @tc.name: GetAllNativeTokenInfo002
 * @tc.desc: GetAllNativeTokenInfo function test.
 * @tc.type: FUNC
 * @tc.require: issueI61NS6
 */
HWTEST_F(RemoteTokenKitTest, GetAllNativeTokenInfo002, TestSize.Level1)
{
    AccessTokenID tokenId = AccessTokenKit::GetNativeTokenId("token_sync_service");
    EXPECT_EQ(0, SetSelfTokenID(tokenId));
    std::vector<NativeTokenInfoForSync> nativeTokenInfoRes;
    int res = AccessTokenKit::GetAllNativeTokenInfo(nativeTokenInfoRes);
    ASSERT_EQ(0, res);
}

/**
 * @tc.name: SetRemoteNativeTokenInfo001
 * @tc.desc: set already mapping tokenInfo
 * @tc.type: FUNC
 * @tc.require:issue I5R4UF
 */
HWTEST_F(RemoteTokenKitTest, SetRemoteNativeTokenInfo001, TestSize.Level1)
{
    ACCESSTOKEN_LOG_INFO(LABEL, "SetRemoteNativeTokenInfo001 start.");
    std::string deviceID = udid_;

    NativeTokenInfoForSync native1 = {
        .baseInfo.apl = APL_NORMAL,
        .baseInfo.ver = 1,
        .baseInfo.processName = "native_test1",
        .baseInfo.dcap = {"SYSDCAP", "DMSDCAP"},
        .baseInfo.tokenID = 0x28000000,
        .baseInfo.tokenAttr = 0,
        .baseInfo.nativeAcls = {"ohos.permission.DISTRIBUTED_DATASYNC"},
    };

    std::vector<NativeTokenInfoForSync> nativeTokenInfoList;
    nativeTokenInfoList.emplace_back(native1);

    int ret = AccessTokenKit::SetRemoteNativeTokenInfo(deviceID, nativeTokenInfoList);
    ASSERT_EQ(ret, RET_SUCCESS);

    AccessTokenID mapID = AccessTokenKit::GetRemoteNativeTokenID(deviceID, 0x28000000);
    ASSERT_NE(mapID, 0);

    NativeTokenInfo resultInfo;
    ret = AccessTokenKit::GetNativeTokenInfo(mapID, resultInfo);
    ASSERT_EQ(ret, RET_SUCCESS);

    ASSERT_EQ(resultInfo.apl, native1.baseInfo.apl);
    ASSERT_EQ(resultInfo.ver, native1.baseInfo.ver);
    ASSERT_EQ(resultInfo.processName, native1.baseInfo.processName);
    ASSERT_EQ(resultInfo.dcap.size(), 2);
    ASSERT_EQ(resultInfo.dcap[0], "SYSDCAP");
    ASSERT_EQ(resultInfo.dcap[1], "DMSDCAP");
    ASSERT_EQ(resultInfo.nativeAcls.size(), 1);
    ASSERT_EQ(resultInfo.nativeAcls[0], "ohos.permission.DISTRIBUTED_DATASYNC");
    ASSERT_EQ(resultInfo.tokenID, mapID);
    ASSERT_EQ(resultInfo.tokenAttr, native1.baseInfo.tokenAttr);
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
