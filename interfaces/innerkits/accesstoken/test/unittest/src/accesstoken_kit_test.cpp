/*
 * Copyright (c) 2021-2022 Huawei Device Co., Ltd.
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

#include "accesstoken_kit_test.h"
#include <thread>

#include "accesstoken_kit.h"
#include "nativetoken_kit.h"
#include "accesstoken_log.h"
#include "token_setproc.h"
#include "softbus_bus_center.h"

using namespace testing::ext;
using namespace OHOS::Security::AccessToken;

namespace {
static constexpr OHOS::HiviewDFX::HiLogLabel LABEL = {LOG_CORE, SECURITY_DOMAIN_ACCESSTOKEN, "AccessTokenKitTest"};

PermissionStateFull g_grantPermissionReq = {
    .permissionName = "ohos.permission.GRANT_SENSITIVE_PERMISSIONS",
    .isGeneral = true,
    .resDeviceID = {"device"},
    .grantStatus = {PermissionState::PERMISSION_GRANTED},
    .grantFlags = {PermissionFlag::PERMISSION_SYSTEM_FIXED}
};
PermissionStateFull g_revokePermissionReq = {
    .permissionName = "ohos.permission.REVOKE_SENSITIVE_PERMISSIONS",
    .isGeneral = true,
    .resDeviceID = {"device"},
    .grantStatus = {PermissionState::PERMISSION_GRANTED},
    .grantFlags = {PermissionFlag::PERMISSION_SYSTEM_FIXED}
};

PermissionDef g_infoManagerTestPermDef1 = {
    .permissionName = "ohos.permission.test1",
    .bundleName = "accesstoken_test",
    .grantMode = 1,
    .label = "label",
    .labelId = 1,
    .description = "open the door",
    .descriptionId = 1,
    .availableLevel = APL_NORMAL
};

PermissionDef g_infoManagerTestPermDef2 = {
    .permissionName = "ohos.permission.test2",
    .bundleName = "accesstoken_test",
    .grantMode = 1,
    .label = "label",
    .labelId = 1,
    .description = "break the door",
    .descriptionId = 1,
    .availableLevel = APL_NORMAL
};

PermissionStateFull g_infoManagerTestState1 = {
    .grantFlags = {1},
    .grantStatus = {PermissionState::PERMISSION_GRANTED},
    .isGeneral = true,
    .permissionName = "ohos.permission.test1",
    .resDeviceID = {"local"}
};

PermissionStateFull g_infoManagerTestState2 = {
    .permissionName = "ohos.permission.test2",
    .isGeneral = false,
    .grantFlags = {1, 2},
    .grantStatus = {PermissionState::PERMISSION_GRANTED, PermissionState::PERMISSION_GRANTED},
    .resDeviceID = {"device 1", "device 2"}
};

HapInfoParams g_infoManagerTestInfoParms = {
    .bundleName = "accesstoken_test",
    .userID = 1,
    .instIndex = 0,
    .appIDDesc = "testtesttesttest"
};

HapPolicyParams g_infoManagerTestPolicyPrams = {
    .apl = APL_NORMAL,
    .domain = "test.domain",
    .permList = {g_infoManagerTestPermDef1, g_infoManagerTestPermDef2},
    .permStateList = {g_infoManagerTestState1, g_infoManagerTestState2}
};

HapInfoParams g_infoManagerTestInfoParmsBak = {
    .bundleName = "accesstoken_test",
    .userID = 1,
    .instIndex = 0,
    .appIDDesc = "testtesttesttest"
};

HapPolicyParams g_infoManagerTestPolicyPramsBak = {
    .apl = APL_NORMAL,
    .domain = "test.domain",
    .permList = {g_infoManagerTestPermDef1, g_infoManagerTestPermDef2},
    .permStateList = {g_infoManagerTestState1, g_infoManagerTestState2}
};
}

void AccessTokenKitTest::SetUpTestCase()
{
    // make test case clean
    AccessTokenID tokenID = AccessTokenKit::GetHapTokenID(g_infoManagerTestInfoParms.userID,
                                                          g_infoManagerTestInfoParms.bundleName,
                                                          g_infoManagerTestInfoParms.instIndex);
    AccessTokenKit::DeleteToken(tokenID);

    tokenID = AccessTokenKit::GetHapTokenID(TEST_USER_ID, TEST_BUNDLE_NAME, 0);
    AccessTokenKit::DeleteToken(tokenID);
}

void AccessTokenKitTest::TearDownTestCase()
{
}

void AccessTokenKitTest::SetUp()
{
    selfTokenId_ = GetSelfTokenID();
    g_infoManagerTestInfoParms = g_infoManagerTestInfoParmsBak;
    g_infoManagerTestPolicyPrams = g_infoManagerTestPolicyPramsBak;
    HapInfoParams info = {
        .userID = TEST_USER_ID,
        .bundleName = TEST_BUNDLE_NAME,
        .instIndex = 0,
        .appIDDesc = "appIDDesc",
    };

    HapPolicyParams policy = {
        .apl = APL_NORMAL,
        .domain = "domain"
    };

    PermissionDef permissionDefAlpha = {
        .permissionName = TEST_PERMISSION_NAME_ALPHA,
        .bundleName = TEST_BUNDLE_NAME,
        .grantMode = GrantMode::USER_GRANT,
        .availableLevel = APL_NORMAL,
        .provisionEnable = false,
        .distributedSceneEnable = false
    };

    PermissionDef permissionDefBeta = {
        .permissionName = TEST_PERMISSION_NAME_BETA,
        .bundleName = TEST_BUNDLE_NAME,
        .grantMode = GrantMode::SYSTEM_GRANT,
        .availableLevel = APL_NORMAL,
        .provisionEnable = false,
        .distributedSceneEnable = false
    };
    PermissionDef testPermDef1 = {
        .permissionName = "ohos.permission.testPermDef1",
        .bundleName = TEST_BUNDLE_NAME,
        .grantMode = GrantMode::USER_GRANT,
        .availableLevel = APL_NORMAL,
        .provisionEnable = false,
        .distributedSceneEnable = false
    };

    PermissionDef testPermDef2 = {
        .permissionName = "ohos.permission.testPermDef2",
        .bundleName = TEST_BUNDLE_NAME,
        .grantMode = GrantMode::USER_GRANT,
        .availableLevel = APL_NORMAL,
        .provisionEnable = false,
        .distributedSceneEnable = false
    };

    PermissionDef testPermDef3 = {
        .permissionName = "ohos.permission.testPermDef3",
        .bundleName = TEST_BUNDLE_NAME,
        .grantMode = GrantMode::USER_GRANT,
        .availableLevel = APL_NORMAL,
        .provisionEnable = false,
        .distributedSceneEnable = false
    };
    PermissionDef testPermDef4 = {
        .permissionName = "ohos.permission.testPermDef4",
        .bundleName = TEST_BUNDLE_NAME,
        .grantMode = GrantMode::USER_GRANT,
        .availableLevel = APL_NORMAL,
        .provisionEnable = false,
        .distributedSceneEnable = false
    };
    policy.permList.emplace_back(permissionDefAlpha);
    policy.permList.emplace_back(permissionDefBeta);
    policy.permList.emplace_back(testPermDef1);
    policy.permList.emplace_back(testPermDef2);
    policy.permList.emplace_back(testPermDef3);
    policy.permList.emplace_back(testPermDef4);

    PermissionStateFull permStatAlpha = {
        .permissionName = TEST_PERMISSION_NAME_ALPHA,
        .isGeneral = true,
        .resDeviceID = {"device"},
        .grantStatus = {PermissionState::PERMISSION_DENIED},
        .grantFlags = {PermissionFlag::PERMISSION_USER_SET}
    };
    PermissionStateFull permStatBeta = {
        .permissionName = TEST_PERMISSION_NAME_BETA,
        .isGeneral = true,
        .resDeviceID = {"device"},
        .grantStatus = {PermissionState::PERMISSION_GRANTED},
        .grantFlags = {PermissionFlag::PERMISSION_SYSTEM_FIXED}
    };
    PermissionStateFull permTestState1 = {
        .grantFlags = {0},
        .grantStatus = {PermissionState::PERMISSION_DENIED},
        .isGeneral = true,
        .permissionName = "ohos.permission.testPermDef1",
        .resDeviceID = {"local"}
    };

    PermissionStateFull permTestState2 = {
        .grantFlags = {1},
        .grantStatus = {PermissionState::PERMISSION_DENIED},
        .isGeneral = true,
        .permissionName = "ohos.permission.testPermDef2",
        .resDeviceID = {"local"}
    };

    PermissionStateFull permTestState3 = {
        .grantFlags = {2},
        .grantStatus = {PermissionState::PERMISSION_DENIED},
        .isGeneral = true,
        .permissionName = "ohos.permission.testPermDef3",
        .resDeviceID = {"local"}
    };

    PermissionStateFull permTestState4 = {
        .grantFlags = {1},
        .grantStatus = {PermissionState::PERMISSION_GRANTED},
        .isGeneral = true,
        .permissionName = "ohos.permission.testPermDef4",
        .resDeviceID = {"local"}
    };

    policy.permStateList.emplace_back(permStatAlpha);
    policy.permStateList.emplace_back(permStatBeta);
    policy.permStateList.emplace_back(g_grantPermissionReq);
    policy.permStateList.emplace_back(g_revokePermissionReq);
    policy.permStateList.emplace_back(permTestState1);
    policy.permStateList.emplace_back(permTestState1);
    policy.permStateList.emplace_back(permTestState2);
    policy.permStateList.emplace_back(permTestState3);
    policy.permStateList.emplace_back(permTestState4);
    AccessTokenKit::AllocHapToken(info, policy);
    AccessTokenID tokenID = AccessTokenKit::GetHapTokenID(g_infoManagerTestInfoParms.userID,
                                                          g_infoManagerTestInfoParms.bundleName,
                                                          g_infoManagerTestInfoParms.instIndex);
    AccessTokenKit::DeleteToken(tokenID);
    (void)remove("/data/token.json");

    NodeBasicInfo deviceInfo;
    int32_t res = ::GetLocalNodeDeviceInfo(TEST_PKG_NAME.c_str(), &deviceInfo);
    ASSERT_EQ(res, RET_SUCCESS);
    char udid[128] = {0}; // 128 is udid length
    ::GetNodeKeyInfo(TEST_PKG_NAME.c_str(), deviceInfo.networkId,
        NodeDeviceInfoKey::NODE_KEY_UDID, (uint8_t *)udid, 128); // 128 is udid length

    udid_.append(udid);
    networkId_.append(deviceInfo.networkId);

    ACCESSTOKEN_LOG_INFO(LABEL, "SetUp ok.");
}

void AccessTokenKitTest::TearDown()
{
    AccessTokenID tokenID = GetAccessTokenID(TEST_USER_ID, TEST_BUNDLE_NAME, 0);
    AccessTokenKit::DeleteToken(tokenID);
    SetSelfTokenID(selfTokenId_);
    udid_.clear();
    networkId_.clear();
}

unsigned int AccessTokenKitTest::GetAccessTokenID(int userID, std::string bundleName, int instIndex)
{
    return AccessTokenKit::GetHapTokenID(userID, bundleName, instIndex);
}

void AccessTokenKitTest::DeleteTestToken() const
{
    AccessTokenID tokenID = AccessTokenKit::GetHapTokenID(g_infoManagerTestInfoParms.userID,
                                                          g_infoManagerTestInfoParms.bundleName,
                                                          g_infoManagerTestInfoParms.instIndex);
    int ret = AccessTokenKit::DeleteToken(tokenID);
    if (tokenID != 0) {
        ASSERT_EQ(RET_SUCCESS, ret);
    }
}

void AccessTokenKitTest::AllocTestToken() const
{
    AccessTokenIDEx tokenIdEx = {0};
    tokenIdEx = AccessTokenKit::AllocHapToken(g_infoManagerTestInfoParms, g_infoManagerTestPolicyPrams);
    ASSERT_NE(0, tokenIdEx.tokenIdExStruct.tokenID);
}

/**
 * @tc.name: GetDefPermission001
 * @tc.desc: Get permission definition info after AllocHapToken function has been invoked.
 * @tc.type: FUNC
 * @tc.require:AR000GM5FC AR000GK6TG
 */
HWTEST_F(AccessTokenKitTest, GetDefPermission001, TestSize.Level1)
{
    PermissionDef permDefResultAlpha;
    int ret = AccessTokenKit::GetDefPermission(TEST_PERMISSION_NAME_ALPHA, permDefResultAlpha);
    ASSERT_EQ(RET_SUCCESS, ret);
    ASSERT_EQ(TEST_PERMISSION_NAME_ALPHA, permDefResultAlpha.permissionName);

    PermissionDef permDefResultBeta;
    ret = AccessTokenKit::GetDefPermission(TEST_PERMISSION_NAME_BETA, permDefResultBeta);
    ASSERT_EQ(RET_SUCCESS, ret);
    ASSERT_EQ(TEST_PERMISSION_NAME_BETA, permDefResultBeta.permissionName);
}

/**
 * @tc.name: GetDefPermission002
 * @tc.desc: Get permission definition info that permission is invalid.
 * @tc.type: FUNC
 * @tc.require:AR000GM5FC
 */
HWTEST_F(AccessTokenKitTest, GetDefPermission002, TestSize.Level1)
{
    PermissionDef permDefResult;
    int ret = AccessTokenKit::GetDefPermission(TEST_PERMISSION_NAME_GAMMA, permDefResult);
    ASSERT_EQ(RET_FAILED, ret);

    ret = AccessTokenKit::GetDefPermission("", permDefResult);
    ASSERT_EQ(RET_FAILED, ret);

    std::string invalidPerm(INVALID_PERMNAME_LEN, 'a');
    ret = AccessTokenKit::GetDefPermission(invalidPerm, permDefResult);
    ASSERT_EQ(RET_FAILED, ret);
}

/**
 * @tc.name: GetDefPermission003
 * @tc.desc: GetDefPermission is invoked multiple times.
 * @tc.type: FUNC
 * @tc.require:AR000GM5FC
 */
HWTEST_F(AccessTokenKitTest, GetDefPermission003, TestSize.Level0)
{
    int ret = RET_FAILED;
    for (int i = 0; i < CYCLE_TIMES; i++) {
        PermissionDef permDefResultAlpha;
        ret = AccessTokenKit::GetDefPermission(TEST_PERMISSION_NAME_ALPHA, permDefResultAlpha);
        ASSERT_EQ(RET_SUCCESS, ret);
        ASSERT_EQ(TEST_PERMISSION_NAME_ALPHA, permDefResultAlpha.permissionName);
    }
}

/**
 * @tc.name: GetDefPermissions001
 * @tc.desc: Get permission definition info list after AllocHapToken function has been invoked.
 * @tc.type: FUNC
 * @tc.require:AR000GM5FC AR000GK6TG
 */
HWTEST_F(AccessTokenKitTest, GetDefPermissions001, TestSize.Level1)
{
    AccessTokenID tokenID = GetAccessTokenID(TEST_USER_ID, TEST_BUNDLE_NAME, 0);
    ASSERT_NE(0, tokenID);
    std::vector<PermissionDef> permDefList;
    int ret = AccessTokenKit::GetDefPermissions(tokenID, permDefList);
    ASSERT_EQ(RET_SUCCESS, ret);
    ASSERT_EQ(6, permDefList.size());
}

/**
 * @tc.name: GetDefPermissions002
 * @tc.desc: Get permission definition info list after clear permission definition list
 * @tc.type: FUNC
 * @tc.require:AR000GM5FC
 */
HWTEST_F(AccessTokenKitTest, GetDefPermissions002, TestSize.Level1)
{
    HapPolicyParams testPolicyPrams = g_infoManagerTestPolicyPrams;
    testPolicyPrams.permList.clear();
    AccessTokenKit::AllocHapToken(g_infoManagerTestInfoParms, testPolicyPrams);

    AccessTokenID tokenID = GetAccessTokenID(g_infoManagerTestInfoParms.userID,
                               g_infoManagerTestInfoParms.bundleName,
                               g_infoManagerTestInfoParms.instIndex);
    ASSERT_NE(0, tokenID);

    std::vector<PermissionDef> permDefList;
    int ret = AccessTokenKit::GetDefPermissions(tokenID, permDefList);
    ASSERT_EQ(RET_SUCCESS, ret);
    ASSERT_EQ(0, permDefList.size());

    AccessTokenKit::DeleteToken(tokenID);
}

/**
 * @tc.name: GetDefPermissions003
 * @tc.desc: Get permission definition info list that tokenID is invalid.
 * @tc.type: FUNC
 * @tc.require:AR000GM5FC
 */
HWTEST_F(AccessTokenKitTest, GetDefPermissions003, TestSize.Level1)
{
    AccessTokenID tokenID = GetAccessTokenID(TEST_USER_ID, TEST_BUNDLE_NAME, 0);
    ASSERT_NE(0, tokenID);
    AccessTokenKit::DeleteToken(tokenID);

    std::vector<PermissionDef> permDefList;
    int ret = AccessTokenKit::GetDefPermissions(TEST_TOKENID_INVALID, permDefList);
    ASSERT_EQ(RET_FAILED, ret);

    std::vector<PermissionDef> permDefListRes;
    ret = AccessTokenKit::GetDefPermissions(tokenID, permDefListRes);
    ASSERT_EQ(RET_FAILED, ret);
    ASSERT_EQ(0, permDefListRes.size());
}

/**
 * @tc.name: GetDefPermissions004
 * @tc.desc: GetDefPermissions is invoked multiple times.
 * @tc.type: FUNC
 * @tc.require:AR000GM5FC
 */
HWTEST_F(AccessTokenKitTest, GetDefPermissions004, TestSize.Level0)
{
    AccessTokenID tokenID = GetAccessTokenID(TEST_USER_ID, TEST_BUNDLE_NAME, 0);
    ASSERT_NE(0, tokenID);
    int ret = RET_FAILED;
    for (int i = 0; i < CYCLE_TIMES; i++) {
        std::vector<PermissionDef> permDefList;
        ret = AccessTokenKit::GetDefPermissions(tokenID, permDefList);
        ASSERT_EQ(RET_SUCCESS, ret);
        ASSERT_EQ(6, permDefList.size());
    }
}

/**
 * @tc.name: GetReqPermissions001
 * @tc.desc: Get user granted permission state info.
 * @tc.type: FUNC
 * @tc.require:AR000GM5FC AR000GK6TG
 */
HWTEST_F(AccessTokenKitTest, GetReqPermissions001, TestSize.Level1)
{
    AccessTokenID tokenID = GetAccessTokenID(TEST_USER_ID, TEST_BUNDLE_NAME, 0);
    ASSERT_NE(0, tokenID);
    std::vector<PermissionStateFull> permStatList;
    int ret = AccessTokenKit::GetReqPermissions(tokenID, permStatList, false);
    ASSERT_EQ(RET_SUCCESS, ret);
    ASSERT_EQ(5, permStatList.size());
    ASSERT_EQ(TEST_PERMISSION_NAME_ALPHA, permStatList[0].permissionName);

    ret = AccessTokenKit::VerifyAccessToken(tokenID, TEST_PERMISSION_NAME_ALPHA);
    ASSERT_EQ(ret, permStatList[0].grantStatus[0]);
}

/**
 * @tc.name: GetReqPermissions002
 * @tc.desc: Get system granted permission state info.
 * @tc.type: FUNC
 * @tc.require:AR000GM5FC
 */
HWTEST_F(AccessTokenKitTest, GetReqPermissions002, TestSize.Level1)
{
    AccessTokenID tokenID = GetAccessTokenID(TEST_USER_ID, TEST_BUNDLE_NAME, 0);
    ASSERT_NE(0, tokenID);
    std::vector<PermissionStateFull> permStatList;
    int ret = AccessTokenKit::GetReqPermissions(tokenID, permStatList, true);
    ASSERT_EQ(RET_SUCCESS, ret);
    ASSERT_EQ(3, permStatList.size());
    ASSERT_EQ(TEST_PERMISSION_NAME_BETA, permStatList[0].permissionName);

    ret = AccessTokenKit::VerifyAccessToken(tokenID, TEST_PERMISSION_NAME_BETA);
    ASSERT_EQ(ret, permStatList[0].grantStatus[0]);
}

/**
 * @tc.name: GetReqPermissions003
 * @tc.desc: Get user granted permission state info after clear request permission list.
 * @tc.type: FUNC
 * @tc.require:AR000GM5FC
 */
HWTEST_F(AccessTokenKitTest, GetReqPermissions003, TestSize.Level1)
{
    AccessTokenID tokenID = GetAccessTokenID(TEST_USER_ID, TEST_BUNDLE_NAME, 0);
    ASSERT_NE(0, tokenID);

    HapTokenInfo hapInfo;
    int ret = AccessTokenKit::GetHapTokenInfo(tokenID, hapInfo);
    ASSERT_EQ(RET_SUCCESS, ret);

    HapPolicyParams policy = {
        .apl = hapInfo.apl,
        .domain = "domain"
    };
    policy.permStateList.clear();

    ret = AccessTokenKit::UpdateHapToken(tokenID, hapInfo.appID, policy);
    ASSERT_EQ(RET_SUCCESS, ret);

    std::vector<PermissionStateFull> permStatUserList;
    ret = AccessTokenKit::GetReqPermissions(tokenID, permStatUserList, false);
    ASSERT_EQ(RET_SUCCESS, ret);
    ASSERT_EQ(0, permStatUserList.size());

    std::vector<PermissionStateFull> permStatSystemList;
    ret = AccessTokenKit::GetReqPermissions(tokenID, permStatSystemList, true);
    ASSERT_EQ(RET_SUCCESS, ret);
    ASSERT_EQ(0, permStatSystemList.size());
}

/**
 * @tc.name: GetReqPermissions004
 * @tc.desc: Get permission state info list that tokenID is invalid.
 * @tc.type: FUNC
 * @tc.require:AR000GM5FC
 */
HWTEST_F(AccessTokenKitTest, GetReqPermissions004, TestSize.Level1)
{
    AccessTokenID tokenID = GetAccessTokenID(TEST_USER_ID, TEST_BUNDLE_NAME, 0);
    ASSERT_NE(0, tokenID);

    std::vector<PermissionStateFull> permStatList;
    int ret = AccessTokenKit::GetReqPermissions(TEST_TOKENID_INVALID, permStatList, false);
    ASSERT_EQ(RET_FAILED, ret);

    AccessTokenKit::DeleteToken(tokenID);

    ret = AccessTokenKit::GetReqPermissions(tokenID, permStatList, false);
    ASSERT_EQ(RET_FAILED, ret);
    ASSERT_EQ(0, permStatList.size());
}

/**
 * @tc.name: GetReqPermissions005
 * @tc.desc: GetReqPermissions is invoked multiple times.
 * @tc.type: FUNC
 * @tc.require:AR000GM5FC
 */
HWTEST_F(AccessTokenKitTest, GetReqPermissions005, TestSize.Level0)
{
    AccessTokenID tokenID = GetAccessTokenID(TEST_USER_ID, TEST_BUNDLE_NAME, 0);
    ASSERT_NE(0, tokenID);
    int ret = RET_FAILED;
    for (int i = 0; i < CYCLE_TIMES; i++) {
        std::vector<PermissionStateFull> permStatList;
        ret = AccessTokenKit::GetReqPermissions(tokenID, permStatList, false);
        ASSERT_EQ(RET_SUCCESS, ret);
        ASSERT_EQ(5, permStatList.size());
        ASSERT_EQ(TEST_PERMISSION_NAME_ALPHA, permStatList[0].permissionName);
    }
}

/**
 * @tc.name: GetPermissionFlag001
 * @tc.desc: Get permission flag after grant permission.
 * @tc.type: FUNC
 * @tc.require:AR000GM5FC AR000GK6TG
 */
HWTEST_F(AccessTokenKitTest, GetPermissionFlag001, TestSize.Level1)
{
    AccessTokenID tokenID = GetAccessTokenID(TEST_USER_ID, TEST_BUNDLE_NAME, 0);
    ASSERT_NE(0, tokenID);
    int ret = AccessTokenKit::GrantPermission(tokenID, TEST_PERMISSION_NAME_ALPHA, PERMISSION_USER_FIXED);
    ASSERT_EQ(RET_SUCCESS, ret);

    ret = AccessTokenKit::GetPermissionFlag(tokenID, TEST_PERMISSION_NAME_ALPHA);
    ASSERT_EQ(PERMISSION_USER_FIXED, ret);
}

/**
 * @tc.name: GetPermissionFlag002
 * @tc.desc: Get permission flag that tokenID or permission is invalid.
 * @tc.type: FUNC
 * @tc.require:AR000GM5FC
 */
HWTEST_F(AccessTokenKitTest, GetPermissionFlag002, TestSize.Level1)
{
    AccessTokenID tokenID = GetAccessTokenID(TEST_USER_ID, TEST_BUNDLE_NAME, 0);
    ASSERT_NE(0, tokenID);

    int ret = AccessTokenKit::GetPermissionFlag(tokenID, TEST_PERMISSION_NAME_GAMMA);
    ASSERT_EQ(PERMISSION_DEFAULT_FLAG, ret);

    ret = AccessTokenKit::GetPermissionFlag(tokenID, "");
    ASSERT_EQ(PERMISSION_DEFAULT_FLAG, ret);

    std::string invalidPerm(INVALID_PERMNAME_LEN, 'a');
    ret = AccessTokenKit::GetPermissionFlag(tokenID, invalidPerm);
    ASSERT_EQ(PERMISSION_DEFAULT_FLAG, ret);

    ret = AccessTokenKit::GetPermissionFlag(TEST_TOKENID_INVALID, TEST_PERMISSION_NAME_ALPHA);
    ASSERT_EQ(PERMISSION_DEFAULT_FLAG, ret);

    AccessTokenKit::DeleteToken(tokenID);

    ret = AccessTokenKit::GetPermissionFlag(tokenID, TEST_PERMISSION_NAME_ALPHA);
    ASSERT_EQ(PERMISSION_DEFAULT_FLAG, ret);
}

/**
 * @tc.name: GetPermissionFlag003
 * @tc.desc: GetPermissionFlag is invoked multiple times.
 * @tc.type: FUNC
 * @tc.require:AR000GM5FC
 */
HWTEST_F(AccessTokenKitTest, GetPermissionFlag003, TestSize.Level0)
{
    AccessTokenID tokenID = GetAccessTokenID(TEST_USER_ID, TEST_BUNDLE_NAME, 0);
    ASSERT_NE(0, tokenID);
    int ret = RET_FAILED;
    for (int i = 0; i < CYCLE_TIMES; i++) {
        ret = AccessTokenKit::GrantPermission(tokenID, TEST_PERMISSION_NAME_ALPHA, PERMISSION_USER_FIXED);
        ASSERT_EQ(RET_SUCCESS, ret);

        ret = AccessTokenKit::GetPermissionFlag(tokenID, TEST_PERMISSION_NAME_ALPHA);
        ASSERT_EQ(PERMISSION_USER_FIXED, ret);
    }
}

/**
 * @tc.name: VerifyAccessToken001
 * @tc.desc: Verify user granted permission.
 * @tc.type: FUNC
 * @tc.require:AR000GK6T8 AR000GK6TG
 */
HWTEST_F(AccessTokenKitTest, VerifyAccessToken001, TestSize.Level0)
{
    AccessTokenID tokenID = GetAccessTokenID(TEST_USER_ID, TEST_BUNDLE_NAME, 0);
    ASSERT_NE(0, tokenID);
    int ret = AccessTokenKit::GrantPermission(tokenID, TEST_PERMISSION_NAME_ALPHA, PERMISSION_USER_FIXED);
    ASSERT_EQ(RET_SUCCESS, ret);

    ret = AccessTokenKit::VerifyAccessToken(tokenID, TEST_PERMISSION_NAME_ALPHA);
    ASSERT_EQ(PERMISSION_GRANTED, ret);

    ret = AccessTokenKit::RevokePermission(tokenID, TEST_PERMISSION_NAME_ALPHA, PERMISSION_USER_FIXED);
    ASSERT_EQ(RET_SUCCESS, ret);

    ret = AccessTokenKit::VerifyAccessToken(tokenID, TEST_PERMISSION_NAME_ALPHA);
    ASSERT_EQ(PERMISSION_DENIED, ret);
}

/**
 * @tc.name: VerifyAccessToken002
 * @tc.desc: Verify system granted permission.
 * @tc.type: FUNC
 * @tc.require:AR000GK6T8
 */
HWTEST_F(AccessTokenKitTest, VerifyAccessToken002, TestSize.Level0)
{
    AccessTokenID tokenID = GetAccessTokenID(TEST_USER_ID, TEST_BUNDLE_NAME, 0);
    ASSERT_NE(0, tokenID);
    int ret = AccessTokenKit::GrantPermission(tokenID, TEST_PERMISSION_NAME_BETA, PERMISSION_USER_FIXED);
    ASSERT_EQ(RET_SUCCESS, ret);

    ret = AccessTokenKit::VerifyAccessToken(tokenID, TEST_PERMISSION_NAME_BETA);
    ASSERT_EQ(PERMISSION_GRANTED, ret);

    ret = AccessTokenKit::RevokePermission(tokenID, TEST_PERMISSION_NAME_BETA, PERMISSION_USER_FIXED);
    ASSERT_EQ(RET_SUCCESS, ret);

    ret = AccessTokenKit::VerifyAccessToken(tokenID, TEST_PERMISSION_NAME_BETA);
    ASSERT_EQ(PERMISSION_DENIED, ret);
}

/**
 * @tc.name: VerifyAccessToken003
 * @tc.desc: Verify permission that tokenID or permission is invalid.
 * @tc.type: FUNC
 * @tc.require:AR000GK6T8
 */
HWTEST_F(AccessTokenKitTest, VerifyAccessToken003, TestSize.Level0)
{
    AccessTokenID tokenID = GetAccessTokenID(TEST_USER_ID, TEST_BUNDLE_NAME, 0);
    ASSERT_NE(0, tokenID);
    int ret = AccessTokenKit::VerifyAccessToken(tokenID, TEST_PERMISSION_NAME_GAMMA);
    ASSERT_EQ(PERMISSION_DENIED, ret);

    ret = AccessTokenKit::VerifyAccessToken(tokenID, "");
    ASSERT_EQ(PERMISSION_DENIED, ret);

    std::string invalidPerm(INVALID_PERMNAME_LEN, 'a');
    ret = AccessTokenKit::VerifyAccessToken(tokenID, invalidPerm);
    ASSERT_EQ(PERMISSION_DENIED, ret);

    AccessTokenKit::VerifyAccessToken(TEST_TOKENID_INVALID, TEST_PERMISSION_NAME_BETA);
    ASSERT_EQ(PERMISSION_DENIED, ret);

    AccessTokenKit::DeleteToken(tokenID);

    AccessTokenKit::VerifyAccessToken(tokenID, TEST_PERMISSION_NAME_BETA);
    ASSERT_EQ(PERMISSION_DENIED, ret);
}

/**
 * @tc.name: VerifyAccessToken004
 * @tc.desc: Verify permission after update.
 * @tc.type: FUNC
 * @tc.require:AR000GK6T8
 */
HWTEST_F(AccessTokenKitTest, VerifyAccessToken004, TestSize.Level0)
{
    AccessTokenID tokenID = GetAccessTokenID(TEST_USER_ID, TEST_BUNDLE_NAME, 0);
    ASSERT_NE(0, tokenID);

    int ret = AccessTokenKit::GrantPermission(tokenID, TEST_PERMISSION_NAME_ALPHA, PERMISSION_USER_FIXED);
    ASSERT_EQ(RET_SUCCESS, ret);

    HapTokenInfo hapInfo;
    ret = AccessTokenKit::GetHapTokenInfo(tokenID, hapInfo);
    ASSERT_EQ(RET_SUCCESS, ret);

    std::vector<PermissionDef>  permDefList;
    ret = AccessTokenKit::GetDefPermissions(tokenID, permDefList);
    ASSERT_EQ(RET_SUCCESS, ret);

    std::vector<PermissionStateFull> permStatList;
    ret = AccessTokenKit::GetReqPermissions(tokenID, permStatList, false);
    ASSERT_EQ(RET_SUCCESS, ret);

    HapPolicyParams policy = {
        .apl = hapInfo.apl,
        .domain = "domain",
        .permList = permDefList,
        .permStateList = permStatList
    };

    ret = AccessTokenKit::UpdateHapToken(tokenID, hapInfo.appID, policy);
    ASSERT_EQ(RET_SUCCESS, ret);

    ret = AccessTokenKit::VerifyAccessToken(tokenID, TEST_PERMISSION_NAME_ALPHA);
    ASSERT_EQ(PERMISSION_GRANTED, ret);
}

/**
 * @tc.name: GrantPermission001
 * @tc.desc: Grant permission that has ohos.permission.GRANT_SENSITIVE_PERMISSIONS
 * @tc.type: FUNC
 * @tc.require:AR000GK6TF AR000GK6TG
 */
HWTEST_F(AccessTokenKitTest, GrantPermission001, TestSize.Level0)
{
    AccessTokenID tokenID = GetAccessTokenID(TEST_USER_ID, TEST_BUNDLE_NAME, 0);
    ASSERT_NE(0, tokenID);
    int ret = AccessTokenKit::GrantPermission(tokenID, TEST_PERMISSION_NAME_ALPHA, PERMISSION_USER_FIXED);
    ASSERT_EQ(RET_SUCCESS, ret);

    ret = AccessTokenKit::VerifyAccessToken(tokenID, TEST_PERMISSION_NAME_ALPHA);
    ASSERT_EQ(PERMISSION_GRANTED, ret);

    ret = AccessTokenKit::GrantPermission(tokenID, TEST_PERMISSION_NAME_BETA, PERMISSION_USER_FIXED);
    ASSERT_EQ(RET_SUCCESS, ret);

    ret = AccessTokenKit::VerifyAccessToken(tokenID, TEST_PERMISSION_NAME_ALPHA);
    ASSERT_EQ(PERMISSION_GRANTED, ret);
}

/**
 * @tc.name: GrantPermission002
 * @tc.desc: Grant permission that tokenID or permission is invalid.
 * @tc.type: FUNC
 * @tc.require:AR000GK6TF
 */
HWTEST_F(AccessTokenKitTest, GrantPermission002, TestSize.Level0)
{
    AccessTokenID tokenID = GetAccessTokenID(TEST_USER_ID, TEST_BUNDLE_NAME, 0);
    ASSERT_NE(0, tokenID);

    int ret = AccessTokenKit::GrantPermission(tokenID, TEST_PERMISSION_NAME_GAMMA, PERMISSION_USER_FIXED);
    ASSERT_EQ(RET_SUCCESS, ret);

    ret = AccessTokenKit::GrantPermission(tokenID, "", PERMISSION_USER_FIXED);
    ASSERT_EQ(RET_FAILED, ret);

    std::string invalidPerm(INVALID_PERMNAME_LEN, 'a');
    ret = AccessTokenKit::GrantPermission(tokenID, invalidPerm, PERMISSION_USER_FIXED);
    ASSERT_EQ(RET_FAILED, ret);

    ret = AccessTokenKit::GrantPermission(TEST_TOKENID_INVALID, TEST_PERMISSION_NAME_BETA, PERMISSION_USER_FIXED);
    ASSERT_EQ(RET_FAILED, ret);

    AccessTokenKit::DeleteToken(tokenID);

    ret = AccessTokenKit::GrantPermission(tokenID, TEST_PERMISSION_NAME_BETA, PERMISSION_USER_FIXED);
    ASSERT_EQ(RET_SUCCESS, ret);
}

/**
 * @tc.name: GrantPermission003
 * @tc.desc: GrantPermission is invoked multiple times.
 * @tc.type: FUNC
 * @tc.require:AR000GK6TF
 */
HWTEST_F(AccessTokenKitTest, GrantPermission003, TestSize.Level0)
{
    AccessTokenID tokenID = GetAccessTokenID(TEST_USER_ID, TEST_BUNDLE_NAME, 0);
    ASSERT_NE(0, tokenID);
    int ret = RET_FAILED;
    for (int i = 0; i < CYCLE_TIMES; i++) {
        ret = AccessTokenKit::GrantPermission(tokenID, TEST_PERMISSION_NAME_ALPHA, PERMISSION_USER_FIXED);
        ASSERT_EQ(RET_SUCCESS, ret);

        ret = AccessTokenKit::VerifyAccessToken(tokenID, TEST_PERMISSION_NAME_ALPHA);
        ASSERT_EQ(PERMISSION_GRANTED, ret);

        ret = AccessTokenKit::GetPermissionFlag(tokenID, TEST_PERMISSION_NAME_ALPHA);
        ASSERT_EQ(PERMISSION_USER_FIXED, ret);
    }
}

/**
 * @tc.name: RevokePermission001
 * @tc.desc: Revoke permission that has ohos.permission.GRANT_SENSITIVE_PERMISSIONS
 * @tc.type: FUNC
 * @tc.require:AR000GK6TF AR000GK6TG
 */
HWTEST_F(AccessTokenKitTest, RevokePermission001, TestSize.Level0)
{
    AccessTokenID tokenID = GetAccessTokenID(TEST_USER_ID, TEST_BUNDLE_NAME, 0);
    ASSERT_NE(0, tokenID);
    int ret = AccessTokenKit::RevokePermission(tokenID, TEST_PERMISSION_NAME_ALPHA, PERMISSION_USER_FIXED);
    ASSERT_EQ(RET_SUCCESS, ret);

    ret = AccessTokenKit::VerifyAccessToken(tokenID, TEST_PERMISSION_NAME_ALPHA);
    ASSERT_EQ(PERMISSION_DENIED, ret);

    ret = AccessTokenKit::RevokePermission(tokenID, TEST_PERMISSION_NAME_BETA, PERMISSION_USER_FIXED);
    ASSERT_EQ(RET_SUCCESS, ret);

    ret = AccessTokenKit::VerifyAccessToken(tokenID, TEST_PERMISSION_NAME_ALPHA);
    ASSERT_EQ(PERMISSION_DENIED, ret);
}

/**
 * @tc.name: RevokePermission002
 * @tc.desc: Revoke permission that tokenID or permission is invalid.
 * @tc.type: FUNC
 * @tc.require:AR000GK6TF
 */
HWTEST_F(AccessTokenKitTest, RevokePermission002, TestSize.Level0)
{
    AccessTokenID tokenID = GetAccessTokenID(TEST_USER_ID, TEST_BUNDLE_NAME, 0);
    ASSERT_NE(0, tokenID);

    int ret = AccessTokenKit::RevokePermission(tokenID, TEST_PERMISSION_NAME_GAMMA, PERMISSION_USER_FIXED);
    ASSERT_EQ(RET_SUCCESS, ret);

    ret = AccessTokenKit::RevokePermission(tokenID, "", PERMISSION_USER_FIXED);
    ASSERT_EQ(RET_FAILED, ret);

    std::string invalidPerm(INVALID_PERMNAME_LEN, 'a');
    ret = AccessTokenKit::RevokePermission(tokenID, invalidPerm, PERMISSION_USER_FIXED);
    ASSERT_EQ(RET_FAILED, ret);

    ret = AccessTokenKit::RevokePermission(TEST_TOKENID_INVALID, TEST_PERMISSION_NAME_BETA, PERMISSION_USER_FIXED);
    ASSERT_EQ(RET_FAILED, ret);

    AccessTokenKit::DeleteToken(tokenID);

    ret = AccessTokenKit::RevokePermission(tokenID, TEST_PERMISSION_NAME_BETA, PERMISSION_USER_FIXED);
    ASSERT_EQ(RET_SUCCESS, ret);
}

/**
 * @tc.name: RevokePermission003
 * @tc.desc: RevokePermission is invoked multiple times.
 * @tc.type: FUNC
 * @tc.require:AR000GK6TF
 */
HWTEST_F(AccessTokenKitTest, RevokePermission003, TestSize.Level0)
{
    AccessTokenID tokenID = GetAccessTokenID(TEST_USER_ID, TEST_BUNDLE_NAME, 0);
    ASSERT_NE(0, tokenID);
    int ret = RET_FAILED;
    for (int i = 0; i < CYCLE_TIMES; i++) {
        ret = AccessTokenKit::RevokePermission(tokenID, TEST_PERMISSION_NAME_ALPHA, PERMISSION_USER_FIXED);
        ASSERT_EQ(RET_SUCCESS, ret);

        ret = AccessTokenKit::VerifyAccessToken(tokenID, TEST_PERMISSION_NAME_ALPHA);
        ASSERT_EQ(PERMISSION_DENIED, ret);

        ret = AccessTokenKit::GetPermissionFlag(tokenID, TEST_PERMISSION_NAME_ALPHA);
        ASSERT_EQ(PERMISSION_USER_FIXED, ret);
    }
}

/**
 * @tc.name: ClearUserGrantedPermissionState001
 * @tc.desc: Clear user/system granted permission after ClearUserGrantedPermissionState has been invoked.
 * @tc.type: FUNC
 * @tc.require:AR000GK6TF AR000GK6TG
 */
HWTEST_F(AccessTokenKitTest, ClearUserGrantedPermissionState001, TestSize.Level0)
{
    AccessTokenID tokenID = GetAccessTokenID(TEST_USER_ID, TEST_BUNDLE_NAME, 0);
    ASSERT_NE(0, tokenID);
    int ret = AccessTokenKit::ClearUserGrantedPermissionState(tokenID);
    ASSERT_EQ(RET_SUCCESS, ret);

    ret = AccessTokenKit::VerifyAccessToken(tokenID, TEST_PERMISSION_NAME_ALPHA);
    ASSERT_EQ(PERMISSION_DENIED, ret);

    ret = AccessTokenKit::VerifyAccessToken(tokenID, TEST_PERMISSION_NAME_BETA);
    ASSERT_EQ(PERMISSION_GRANTED, ret);
}

/**
 * @tc.name: ClearUserGrantedPermissionState002
 * @tc.desc: Clear user/system granted permission that tokenID or permission is invalid.
 * @tc.type: FUNC
 * @tc.require:AR000GK6TF
 */
HWTEST_F(AccessTokenKitTest, ClearUserGrantedPermissionState002, TestSize.Level0)
{
    AccessTokenID tokenID = GetAccessTokenID(TEST_USER_ID, TEST_BUNDLE_NAME, 0);
    ASSERT_NE(0, tokenID);

    int ret = AccessTokenKit::ClearUserGrantedPermissionState(TEST_TOKENID_INVALID);
    ASSERT_EQ(RET_FAILED, ret);

    AccessTokenKit::DeleteToken(tokenID);

    ret = AccessTokenKit::ClearUserGrantedPermissionState(tokenID);
    ASSERT_EQ(RET_SUCCESS, ret);
}

/**
 * @tc.name: ClearUserGrantedPermissionState003
 * @tc.desc: ClearUserGrantedPermissionState is invoked multiple times.
 * @tc.type: FUNC
 * @tc.require:AR000GK6TF
 */
HWTEST_F(AccessTokenKitTest, ClearUserGrantedPermissionState003, TestSize.Level0)
{
    AccessTokenID tokenID = GetAccessTokenID(TEST_USER_ID, TEST_BUNDLE_NAME, 0);
    ASSERT_NE(0, tokenID);
    int ret = RET_FAILED;
    for (int i = 0; i < CYCLE_TIMES; i++) {
        ret = AccessTokenKit::ClearUserGrantedPermissionState(tokenID);
        ASSERT_EQ(RET_SUCCESS, ret);

        ret = AccessTokenKit::VerifyAccessToken(tokenID, TEST_PERMISSION_NAME_ALPHA);
        ASSERT_EQ(PERMISSION_DENIED, ret);
    }
}

/**
 * @tc.name: ClearUserGrantedPermissionState004
 * @tc.desc: Clear user/system granted permission after ClearUserGrantedPermissionState has been invoked.
 * @tc.type: FUNC
 * @tc.require:AR000GK6TF AR000GK6TG
 */
HWTEST_F(AccessTokenKitTest, ClearUserGrantedPermissionState004, TestSize.Level0)
{
    AccessTokenIDEx tokenIdEx = {0};
    OHOS::Security::AccessToken::PermissionStateFull infoManagerTestState1 = {
        .permissionName = "ohos.permission.CAMERA",
        .isGeneral = true,
        .resDeviceID = {"local"},
        .grantStatus = {OHOS::Security::AccessToken::PermissionState::PERMISSION_GRANTED},
        .grantFlags = {PERMISSION_GRANTED_BY_POLICY | PERMISSION_DEFAULT_FLAG}
    };
    OHOS::Security::AccessToken::PermissionStateFull infoManagerTestState2 = {
        .permissionName = "ohos.permission.SEND_MESSAGES",
        .isGeneral = true,
        .resDeviceID = {"local"},
        .grantStatus = {OHOS::Security::AccessToken::PermissionState::PERMISSION_DENIED},
        .grantFlags = {PERMISSION_GRANTED_BY_POLICY | PERMISSION_USER_FIXED}
    };
    OHOS::Security::AccessToken::PermissionStateFull infoManagerTestState3 = {
        .permissionName = "ohos.permission.RECEIVE_SMS",
        .isGeneral = true,
        .resDeviceID = {"local"},
        .grantStatus = {OHOS::Security::AccessToken::PermissionState::PERMISSION_GRANTED},
        .grantFlags = {PERMISSION_USER_FIXED}
    };
    OHOS::Security::AccessToken::HapPolicyParams infoManagerTestPolicyPrams = {
        .apl = OHOS::Security::AccessToken::ATokenAplEnum::APL_NORMAL,
        .domain = "test.domain",
        .permList = {g_infoManagerTestPermDef1},
        .permStateList = {infoManagerTestState1, infoManagerTestState2, infoManagerTestState3}
    };
    tokenIdEx = AccessTokenKit::AllocHapToken(g_infoManagerTestInfoParms, infoManagerTestPolicyPrams);
    AccessTokenID tokenID = tokenIdEx.tokenIdExStruct.tokenID;
    ASSERT_NE(0, tokenID);
    int ret = AccessTokenKit::ClearUserGrantedPermissionState(tokenID);
    ASSERT_EQ(RET_SUCCESS, ret);

    ret = AccessTokenKit::VerifyAccessToken(tokenID, "ohos.permission.CAMERA");
    ASSERT_EQ(PERMISSION_GRANTED, ret);

    ret = AccessTokenKit::VerifyAccessToken(tokenID, "ohos.permission.SEND_MESSAGES");
    ASSERT_EQ(PERMISSION_GRANTED, ret);

    ret = AccessTokenKit::VerifyAccessToken(tokenID, "ohos.permission.RECEIVE_SMS");
    ASSERT_EQ(PERMISSION_DENIED, ret);

    ret = AccessTokenKit::DeleteToken(tokenID);
    ASSERT_EQ(RET_SUCCESS, ret);
}

/**
 * @tc.name: GetTokenType001
 * @tc.desc: get the token type.
 * @tc.type: FUNC
 * @tc.require:AR000GK6TH
 */
HWTEST_F(AccessTokenKitTest, GetTokenType001, TestSize.Level0)
{
    AllocTestToken();
    AccessTokenID tokenID = GetAccessTokenID(g_infoManagerTestInfoParms.userID,
                                             g_infoManagerTestInfoParms.bundleName,
                                             g_infoManagerTestInfoParms.instIndex);
    int ret = AccessTokenKit::GetTokenType(tokenID);
    ASSERT_EQ(TOKEN_HAP, ret);
    DeleteTestToken();
}

/**
 * @tc.name: GetHapTokenInfo001
 * @tc.desc: get the token info and verify.
 * @tc.type: FUNC
 * @tc.require:AR000GK6TH
 */
HWTEST_F(AccessTokenKitTest, GetHapTokenInfo001, TestSize.Level0)
{
    HapTokenInfo hapTokenInfoRes;
    AccessTokenID tokenID = GetAccessTokenID(TEST_USER_ID, TEST_BUNDLE_NAME, 0);
    int ret = AccessTokenKit::GetHapTokenInfo(tokenID, hapTokenInfoRes);
    ASSERT_EQ(RET_SUCCESS, ret);

    ASSERT_EQ(hapTokenInfoRes.apl, APL_NORMAL);
    ASSERT_EQ(hapTokenInfoRes.userID, TEST_USER_ID);
    ASSERT_EQ(hapTokenInfoRes.tokenID, tokenID);
    ASSERT_EQ(hapTokenInfoRes.tokenAttr, 0);
    ASSERT_EQ(hapTokenInfoRes.instIndex, 0);

    ASSERT_EQ(hapTokenInfoRes.appID, "appIDDesc");

    ASSERT_EQ(hapTokenInfoRes.bundleName, TEST_BUNDLE_NAME);
}

/**
 * @tc.name: GetHapTokenInfo002
 * @tc.desc: try to get the token info with invalid tokenId.
 * @tc.type: FUNC
 * @tc.require:AR000GK6TH
 */
HWTEST_F(AccessTokenKitTest, GetHapTokenInfo002, TestSize.Level0)
{
    HapTokenInfo hapTokenInfoRes;
    int ret = AccessTokenKit::GetHapTokenInfo(TEST_TOKENID_INVALID, hapTokenInfoRes);
    ASSERT_EQ(RET_FAILED, ret);
}

/**
 * @tc.name: DeleteToken001
 * @tc.desc: Cannot get permission definition info after DeleteToken function has been invoked.
 * @tc.type: FUNC
 * @tc.require:AR000GK6TI
 */
HWTEST_F(AccessTokenKitTest, DeleteToken001, TestSize.Level1)
{
    AccessTokenID tokenID = GetAccessTokenID(TEST_USER_ID, TEST_BUNDLE_NAME, 0);
    PermissionDef permDefResultAlpha;
    int ret = AccessTokenKit::GetDefPermission(TEST_PERMISSION_NAME_ALPHA, permDefResultAlpha);
    ASSERT_EQ(TEST_PERMISSION_NAME_ALPHA, permDefResultAlpha.permissionName);
    ASSERT_EQ(RET_SUCCESS, ret);

    ret = AccessTokenKit::DeleteToken(tokenID);
    ASSERT_EQ(RET_SUCCESS, ret);

    PermissionDef defResult;
    ret = AccessTokenKit::GetDefPermission(TEST_PERMISSION_NAME_ALPHA, defResult);
    ASSERT_EQ(RET_FAILED, ret);
}

/**
 * @tc.name: DeleteToken002
 * @tc.desc: Delete invalid tokenID.
 * @tc.type: FUNC
 * @tc.require:AR000GK6TI
 */
HWTEST_F(AccessTokenKitTest, DeleteToken002, TestSize.Level1)
{
    int ret = AccessTokenKit::DeleteToken(TEST_USER_ID_INVALID);
    ASSERT_EQ(RET_FAILED, ret);
}

/**
 * @tc.name: DeleteToken002
 * @tc.desc: Delete invalid tokenID.
 * @tc.type: FUNC
 * @tc.require:AR000GK6TI
 */
HWTEST_F(AccessTokenKitTest, DeleteToken003, TestSize.Level1)
{
    HapTokenInfo hapTokenInfoRes;
    AccessTokenID tokenID = GetAccessTokenID(TEST_USER_ID, TEST_BUNDLE_NAME, 0);

    int ret = AccessTokenKit::GetHapTokenInfo(tokenID, hapTokenInfoRes);
    ASSERT_EQ(RET_SUCCESS, ret);

    ret = AccessTokenKit::DeleteToken(tokenID);
    ASSERT_EQ(RET_SUCCESS, ret);

    ret = AccessTokenKit::GetHapTokenInfo(tokenID, hapTokenInfoRes);
    ASSERT_EQ(RET_FAILED, ret);
}

/**
 * @tc.name: DeleteToken004
 * @tc.desc: alloc a tokenId successfully, delete it successfully the first time and fail to delte it again.
 * @tc.type: FUNC
 * @tc.require:AR000GK6TI
 */
HWTEST_F(AccessTokenKitTest, DeleteToken004, TestSize.Level1)
{
    AccessTokenIDEx tokenIdEx = {0};
    tokenIdEx = AccessTokenKit::AllocHapToken(g_infoManagerTestInfoParms, g_infoManagerTestPolicyPrams);
    GTEST_LOG_(INFO) << "tokenIdEx.tokenIdExStruct.tokenID :" << tokenIdEx.tokenIdExStruct.tokenID;
    AccessTokenID tokenID = GetAccessTokenID(g_infoManagerTestInfoParms.userID,
                                             g_infoManagerTestInfoParms.bundleName,
                                             g_infoManagerTestInfoParms.instIndex);

    int ret = AccessTokenKit::DeleteToken(tokenID);
    GTEST_LOG_(INFO) << "g_infoManagerTestInfoParms.userID :" << g_infoManagerTestInfoParms.userID;
    GTEST_LOG_(INFO) << "g_infoManagerTestInfoParms.bundleName :" << g_infoManagerTestInfoParms.bundleName.c_str();
    GTEST_LOG_(INFO) << "g_infoManagerTestInfoParms.instIndex :" << g_infoManagerTestInfoParms.instIndex;
    GTEST_LOG_(INFO) << "tokenID :" << tokenID;
    ASSERT_EQ(RET_SUCCESS, ret);
    ret = AccessTokenKit::DeleteToken(tokenID);
    ASSERT_EQ(RET_FAILED, ret);
}

/**
 * @tc.name: GetHapTokenID001
 * @tc.desc: get hap tokenid.
 * @tc.type: FUNC
 * @tc.require:AR000GK6TH
 */
HWTEST_F(AccessTokenKitTest, GetHapTokenID001, TestSize.Level1)
{
    HapTokenInfo hapTokenInfoRes;
    AccessTokenID tokenID;
    tokenID = AccessTokenKit::GetHapTokenID(TEST_USER_ID, TEST_BUNDLE_NAME, 0);

    int ret = AccessTokenKit::GetHapTokenInfo(tokenID, hapTokenInfoRes);
    ASSERT_EQ(RET_SUCCESS, ret);
    ASSERT_EQ(hapTokenInfoRes.bundleName, TEST_BUNDLE_NAME);
}

/**
 * @tc.name: GetHapTokenID002
 * @tc.desc: cannot get hap tokenid with invalid userId.
 * @tc.type: FUNC
 * @tc.require:AR000GK6TH
 */
HWTEST_F(AccessTokenKitTest, GetHapTokenID002, TestSize.Level1)
{
    AccessTokenID tokenID;
    tokenID = AccessTokenKit::GetHapTokenID(TEST_USER_ID_INVALID, TEST_BUNDLE_NAME, 0);
    ASSERT_EQ(0, tokenID);
}

/**
 * @tc.name: GetHapTokenID003
 * @tc.desc: cannot get hap tokenid with invalid bundlename.
 * @tc.type: FUNC
 * @tc.require:AR000GK6TH
 */
HWTEST_F(AccessTokenKitTest, GetHapTokenID003, TestSize.Level1)
{
    AccessTokenID tokenID;
    tokenID = AccessTokenKit::GetHapTokenID(TEST_USER_ID, "invalid bundlename", 0);
    ASSERT_EQ(0, tokenID);
}

/**
 * @tc.name: GetHapTokenID003
 * @tc.desc: cannot get hap tokenid with invalid bundlename.
 * @tc.type: FUNC
 * @tc.require:AR000GK6TH
 */
HWTEST_F(AccessTokenKitTest, GetHapTokenID004, TestSize.Level1)
{
    AccessTokenID tokenID;
    tokenID = AccessTokenKit::GetHapTokenID(TEST_USER_ID, TEST_BUNDLE_NAME, 0xffff);
    ASSERT_EQ(0, tokenID);
}

/**
 * @tc.name: AllocHapToken001
 * @tc.desc: alloc a tokenId successfully, delete it successfully the first time and fail to delte it again.
 * @tc.type: FUNC
 * @tc.require:AR000GK6TJ
 */
HWTEST_F(AccessTokenKitTest, AllocHapToken001, TestSize.Level1)
{
    AccessTokenIDEx tokenIdEx = {0};
    tokenIdEx = AccessTokenKit::AllocHapToken(g_infoManagerTestInfoParms, g_infoManagerTestPolicyPrams);
    GTEST_LOG_(INFO) << "tokenIdEx.tokenIdExStruct.tokenID :" << tokenIdEx.tokenIdExStruct.tokenID;
    AccessTokenID tokenID = GetAccessTokenID(g_infoManagerTestInfoParms.userID,
                                             g_infoManagerTestInfoParms.bundleName,
                                             g_infoManagerTestInfoParms.instIndex);
    GTEST_LOG_(INFO) << "tokenID :" << tokenID;
    int ret = AccessTokenKit::DeleteToken(tokenID);
    ASSERT_EQ(RET_SUCCESS, ret);
    ret = AccessTokenKit::DeleteToken(tokenID);
    ASSERT_EQ(RET_FAILED, ret);
}

/**
 * @tc.name: AllocHapToken002
 * @tc.desc: alloc a tokenId successfully,
 *           and fail to alloc it with the same info and policy again.
 * @tc.type: FUNC
 * @tc.require:AR000GK6TJ
 */
HWTEST_F(AccessTokenKitTest, AllocHapToken002, TestSize.Level1)
{
    AccessTokenIDEx tokenIdEx = {0};
    AccessTokenID tokenID;
    int ret;

    tokenID = GetAccessTokenID(g_infoManagerTestInfoParms.userID,
                               g_infoManagerTestInfoParms.bundleName,
                               g_infoManagerTestInfoParms.instIndex);

    ret = AccessTokenKit::DeleteToken(tokenID);
    GTEST_LOG_(INFO) << "DeleteToken ret:" << ret;
    GTEST_LOG_(INFO) << "tokenID :" << tokenID;

    tokenIdEx = AccessTokenKit::AllocHapToken(g_infoManagerTestInfoParms, g_infoManagerTestPolicyPrams);
    GTEST_LOG_(INFO) << "tokenIdEx.tokenIdExStruct.tokenID :" << tokenIdEx.tokenIdExStruct.tokenID;

    tokenID = GetAccessTokenID(g_infoManagerTestInfoParms.userID,
                               g_infoManagerTestInfoParms.bundleName,
                               g_infoManagerTestInfoParms.instIndex);
    GTEST_LOG_(INFO) << "tokenID :" << tokenID;
    ASSERT_NE(0, tokenID);

    tokenIdEx = AccessTokenKit::AllocHapToken(g_infoManagerTestInfoParms, g_infoManagerTestPolicyPrams);
    ASSERT_EQ(0, tokenIdEx.tokenIdExStruct.tokenID);

    ret = AccessTokenKit::DeleteToken(tokenID);
    ASSERT_EQ(RET_SUCCESS, ret);
}

/**
 * @tc.name: AllocHapToken003
 * @tc.desc: cannot alloc a tokenId with invalid bundlename.
 * @tc.type: FUNC
 * @tc.require:AR000GK6TJ
 */
HWTEST_F(AccessTokenKitTest, AllocHapToken003, TestSize.Level1)
{
    std::string invalidBundleName (INVALID_BUNDLENAME_LEN, 'x');
    AccessTokenIDEx tokenIdEx = {0};
    int ret;
    AccessTokenID tokenID;

    DeleteTestToken();
    GTEST_LOG_(INFO) << "get hap token info:" << invalidBundleName.length();
    g_infoManagerTestInfoParms.bundleName = invalidBundleName;
    tokenIdEx = AccessTokenKit::AllocHapToken(g_infoManagerTestInfoParms, g_infoManagerTestPolicyPrams);

    ASSERT_EQ(0, tokenIdEx.tokenIdExStruct.tokenID);

    tokenID = GetAccessTokenID(g_infoManagerTestInfoParms.userID,
                               g_infoManagerTestInfoParms.bundleName,
                               g_infoManagerTestInfoParms.instIndex);
    ASSERT_EQ(0, tokenID);
    ret = AccessTokenKit::DeleteToken(tokenID);
    ASSERT_EQ(RET_FAILED, ret);

    g_infoManagerTestInfoParms.bundleName = "accesstoken_test";
}

/**
 * @tc.name: AllocHapToken004
 * @tc.desc: cannot alloc a tokenId with invalid apl.
 * @tc.type: FUNC
 * @tc.require:AR000GK6TJ
 */
HWTEST_F(AccessTokenKitTest, AllocHapToken004, TestSize.Level1)
{
    AccessTokenIDEx tokenIdEx = {0};
    AccessTokenID tokenID;
    ATokenAplEnum typeBackUp = g_infoManagerTestPolicyPrams.apl;
    DeleteTestToken();

    g_infoManagerTestPolicyPrams.apl = (ATokenAplEnum)5;
    tokenIdEx = AccessTokenKit::AllocHapToken(g_infoManagerTestInfoParms, g_infoManagerTestPolicyPrams);

    ASSERT_EQ(0, tokenIdEx.tokenIdExStruct.tokenID);

    tokenID = GetAccessTokenID(g_infoManagerTestInfoParms.userID,
                               g_infoManagerTestInfoParms.bundleName,
                               g_infoManagerTestInfoParms.instIndex);
    ASSERT_EQ(0, tokenID);
    int ret = AccessTokenKit::DeleteToken(tokenID);
    ASSERT_EQ(RET_FAILED, ret);
    g_infoManagerTestPolicyPrams.apl = typeBackUp;
}

/**
 * @tc.name: AllocHapToken005
 * @tc.desc: can alloc a tokenId when bundlename in permdef is different with bundlename in info.
 * @tc.type: FUNC
 * @tc.require:AR000GK6TJ
 */
HWTEST_F(AccessTokenKitTest, AllocHapToken005, TestSize.Level1)
{
    AccessTokenIDEx tokenIdEx = {0};
    std::string backUp;
    std::string backUpPermission;
    std::string bundleNameBackUp = g_infoManagerTestPermDef1.bundleName;
    DeleteTestToken();

    backUp = g_infoManagerTestPolicyPrams.permList[0].bundleName;
    backUpPermission = g_infoManagerTestPolicyPrams.permList[0].permissionName;

    g_infoManagerTestPolicyPrams.permList[0].bundleName = "invalid_bundleName";
    g_infoManagerTestPolicyPrams.permList[0].permissionName = "ohos.permission.testtmp01";
    tokenIdEx = AccessTokenKit::AllocHapToken(g_infoManagerTestInfoParms, g_infoManagerTestPolicyPrams);
    ASSERT_NE(0, tokenIdEx.tokenIdExStruct.tokenID);

    PermissionDef permDefResultBeta;
    int ret = AccessTokenKit::GetDefPermission(
        g_infoManagerTestPolicyPrams.permList[0].permissionName, permDefResultBeta);
    ASSERT_EQ(RET_SUCCESS, ret);
    ret = AccessTokenKit::GetDefPermission(g_infoManagerTestPolicyPrams.permList[1].permissionName, permDefResultBeta);
    ASSERT_EQ(RET_SUCCESS, ret);
    g_infoManagerTestPolicyPrams.permList[0].bundleName  = backUp;
    g_infoManagerTestPolicyPrams.permList[0].permissionName = backUpPermission;
}

/**
 * @tc.name: AllocHapToken006
 * @tc.desc: can alloc a tokenId with a invalid permList permissionName.
 * @tc.type: FUNC
 * @tc.require:AR000GK6TJ
 */
HWTEST_F(AccessTokenKitTest, AllocHapToken006, TestSize.Level1)
{
    AccessTokenIDEx tokenIdEx = {0};
    std::string backUp;
    DeleteTestToken();

    const std::string invalidPermissionName (INVALID_PERMNAME_LEN, 'x');
    backUp = g_infoManagerTestPolicyPrams.permList[0].permissionName;
    g_infoManagerTestPolicyPrams.permList[0].permissionName = invalidPermissionName;
    tokenIdEx = AccessTokenKit::AllocHapToken(g_infoManagerTestInfoParms, g_infoManagerTestPolicyPrams);
    ASSERT_NE(0, tokenIdEx.tokenIdExStruct.tokenID);

    PermissionDef permDefResultBeta;
    int ret = AccessTokenKit::GetDefPermission(invalidPermissionName, permDefResultBeta);
    ASSERT_EQ(RET_FAILED, ret);
    ret = AccessTokenKit::GetDefPermission(g_infoManagerTestPolicyPrams.permList[1].permissionName, permDefResultBeta);
    ASSERT_EQ(RET_SUCCESS, ret);
    g_infoManagerTestPolicyPrams.permList[0].permissionName  = backUp;
}

/**
 * @tc.name: AllocHapToken007
 * @tc.desc: can alloc a tokenId with invalid permdef.
 * @tc.type: FUNC
 * @tc.require:AR000GK6TJ
 */
HWTEST_F(AccessTokenKitTest, AllocHapToken007, TestSize.Level1)
{
    AccessTokenIDEx tokenIdEx = {0};
    std::string backUp;
    std::string backUpPermission;
    DeleteTestToken();

    const std::string invalidBundleName (INVALID_BUNDLENAME_LEN, 'x');
    backUp = g_infoManagerTestPolicyPrams.permList[0].bundleName;
    backUpPermission = g_infoManagerTestPolicyPrams.permList[0].permissionName;

    g_infoManagerTestPolicyPrams.permList[0].permissionName = "ohos.permission.testtmp02";
    g_infoManagerTestPolicyPrams.permList[0].bundleName = invalidBundleName;
    tokenIdEx = AccessTokenKit::AllocHapToken(g_infoManagerTestInfoParms, g_infoManagerTestPolicyPrams);
    ASSERT_NE(0, tokenIdEx.tokenIdExStruct.tokenID);

    PermissionDef permDefResultBeta;
    int ret = AccessTokenKit::GetDefPermission(
        g_infoManagerTestPolicyPrams.permList[0].permissionName, permDefResultBeta);
    ASSERT_EQ(RET_FAILED, ret);
    ret = AccessTokenKit::GetDefPermission(g_infoManagerTestPolicyPrams.permList[1].permissionName, permDefResultBeta);
    ASSERT_EQ(RET_SUCCESS, ret);
    g_infoManagerTestPolicyPrams.permList[0].bundleName  = backUp;
    g_infoManagerTestPolicyPrams.permList[0].permissionName = backUpPermission;
}

/**
 * @tc.name: AllocHapToken008
 * @tc.desc: can alloc a tokenId with invalid permdef.
 * @tc.type: FUNC
 * @tc.require:AR000GK6TJ
 */
HWTEST_F(AccessTokenKitTest, AllocHapToken008, TestSize.Level1)
{
    AccessTokenIDEx tokenIdEx = {0};
    std::string backUp;
    std::string backUpPermission;
    DeleteTestToken();

    const std::string invalidLabel (INVALID_LABEL_LEN, 'x');
    backUp = g_infoManagerTestPolicyPrams.permList[0].label;
    backUpPermission = g_infoManagerTestPolicyPrams.permList[0].permissionName;
    g_infoManagerTestPolicyPrams.permList[0].permissionName = "ohos.permission.testtmp03";
    g_infoManagerTestPolicyPrams.permList[0].label = invalidLabel;
    tokenIdEx = AccessTokenKit::AllocHapToken(g_infoManagerTestInfoParms, g_infoManagerTestPolicyPrams);
    ASSERT_NE(0, tokenIdEx.tokenIdExStruct.tokenID);

    PermissionDef permDefResultBeta;
    int ret = AccessTokenKit::GetDefPermission(
        g_infoManagerTestPolicyPrams.permList[0].permissionName, permDefResultBeta);
    ASSERT_EQ(RET_FAILED, ret);
    ret = AccessTokenKit::GetDefPermission(g_infoManagerTestPolicyPrams.permList[1].permissionName, permDefResultBeta);
    ASSERT_EQ(RET_SUCCESS, ret);
    g_infoManagerTestPolicyPrams.permList[0].label  = backUp;
    g_infoManagerTestPolicyPrams.permList[0].permissionName = backUpPermission;
}

/**
 * @tc.name: AllocHapToken009
 * @tc.desc: can alloc a tokenId with invalid permdef.
 * @tc.type: FUNC
 * @tc.require:AR000GK6TJ
 */
HWTEST_F(AccessTokenKitTest, AllocHapToken009, TestSize.Level1)
{
    AccessTokenIDEx tokenIdEx = {0};
    std::string backUp;
    std::string backUpPermission;
    DeleteTestToken();

    const std::string invalidDescription (INVALID_DESCRIPTION_LEN, 'x');
    backUp = g_infoManagerTestPolicyPrams.permList[0].description;
    backUpPermission = g_infoManagerTestPolicyPrams.permList[0].permissionName;

    g_infoManagerTestPolicyPrams.permList[0].permissionName = "ohos.permission.testtmp04";
    g_infoManagerTestPolicyPrams.permList[0].description = invalidDescription;
    tokenIdEx = AccessTokenKit::AllocHapToken(g_infoManagerTestInfoParms, g_infoManagerTestPolicyPrams);
    ASSERT_NE(0, tokenIdEx.tokenIdExStruct.tokenID);

    PermissionDef permDefResultBeta;
    int ret = AccessTokenKit::GetDefPermission(
        g_infoManagerTestPolicyPrams.permList[0].permissionName, permDefResultBeta);
    ASSERT_EQ(RET_FAILED, ret);
    ret = AccessTokenKit::GetDefPermission(
        g_infoManagerTestPolicyPrams.permList[1].permissionName, permDefResultBeta);
    ASSERT_EQ(RET_SUCCESS, ret);

    g_infoManagerTestPolicyPrams.permList[0].description  = backUp;
    g_infoManagerTestPolicyPrams.permList[0].permissionName = backUpPermission;
}

static bool ExistInVector(vector<unsigned int> array, unsigned int value)
{
    vector<unsigned int>::iterator it;
    it = find(array.begin(), array.end(), value);
    if (it != array.end()) {
        return true;
    } else {
        return false;
    }
}

/**
 * @tc.name: AllocHapToken010
 * @tc.desc: alloc and delete in a loop.
 * @tc.type: FUNC
 * @tc.require:AR000GK6TJ
 */
HWTEST_F(AccessTokenKitTest, AllocHapToken010, TestSize.Level1)
{
    AccessTokenIDEx tokenIdEx = {0};
    AccessTokenID tokenID;
    int ret;
    bool exist = false;
    int allocFlag = 0;
    int deleteFlag = 0;

    DeleteTestToken();
    vector<unsigned int> obj;
    for (int i = 0; i < CYCLE_TIMES; i++) {
        tokenIdEx = AccessTokenKit::AllocHapToken(g_infoManagerTestInfoParms, g_infoManagerTestPolicyPrams);
        tokenID = GetAccessTokenID(g_infoManagerTestInfoParms.userID,
                                   g_infoManagerTestInfoParms.bundleName,
                                   g_infoManagerTestInfoParms.instIndex);

        exist = ExistInVector(obj, tokenID);
        if (exist) {
            allocFlag = 1;
        }
        obj.push_back(tokenID);

        ret = AccessTokenKit::DeleteToken(tokenID);
        if (RET_SUCCESS != ret) {
            deleteFlag = 1;
        }
    }
    ASSERT_EQ(allocFlag, 0);
    ASSERT_EQ(deleteFlag, 0);
}

/**
 * @tc.name: AllocHapToken011
 * @tc.desc: cannot alloc a tokenId with invalid appIDDesc.
 * @tc.type: FUNC
 * @tc.require:AR000GK6TJ
 */
HWTEST_F(AccessTokenKitTest, AllocHapToken011, TestSize.Level1)
{
    std::string invalidAppIDDesc (INVALID_APPIDDESC_LEN, 'x');
    std::string backup;
    AccessTokenIDEx tokenIdEx = {0};

    DeleteTestToken();
    backup = g_infoManagerTestInfoParms.appIDDesc;
    g_infoManagerTestInfoParms.appIDDesc = invalidAppIDDesc;
    tokenIdEx = AccessTokenKit::AllocHapToken(g_infoManagerTestInfoParms, g_infoManagerTestPolicyPrams);
    ASSERT_EQ(0, tokenIdEx.tokenIdExStruct.tokenID);
    g_infoManagerTestInfoParms.appIDDesc = backup;
}

/**
 * @tc.name: AllocHapToken012
 * @tc.desc: cannot alloc a tokenId with invalid bundleName.
 * @tc.type: FUNC
 * @tc.require:AR000GK6TJ
 */
HWTEST_F(AccessTokenKitTest, AllocHapToken012, TestSize.Level1)
{
    std::string backup;
    AccessTokenIDEx tokenIdEx = {0};

    backup = g_infoManagerTestInfoParms.bundleName;
    g_infoManagerTestInfoParms.bundleName = "";
    tokenIdEx = AccessTokenKit::AllocHapToken(g_infoManagerTestInfoParms, g_infoManagerTestPolicyPrams);
    ASSERT_EQ(0, tokenIdEx.tokenIdExStruct.tokenID);
    g_infoManagerTestInfoParms.bundleName = backup;
}

/**
 * @tc.name: AllocHapToken013
 * @tc.desc: cannot alloc a tokenId with invalid appIDDesc.
 * @tc.type: FUNC
 * @tc.require:AR000GK6TJ
 */
HWTEST_F(AccessTokenKitTest, AllocHapToken013, TestSize.Level1)
{
    std::string backup;
    AccessTokenIDEx tokenIdEx = {0};

    backup = g_infoManagerTestInfoParms.appIDDesc;
    g_infoManagerTestInfoParms.appIDDesc = "";
    tokenIdEx = AccessTokenKit::AllocHapToken(g_infoManagerTestInfoParms, g_infoManagerTestPolicyPrams);
    ASSERT_EQ(0, tokenIdEx.tokenIdExStruct.tokenID);
    g_infoManagerTestInfoParms.appIDDesc = backup;
}

/**
 * @tc.name: AllocHapToken014
 * @tc.desc: can alloc a tokenId with permList permissionName as "".
 * @tc.type: FUNC
 * @tc.require:AR000GK6TJ
 */
HWTEST_F(AccessTokenKitTest, AllocHapToken014, TestSize.Level1)
{
    std::string backup;
    AccessTokenIDEx tokenIdEx = {0};

    backup = g_infoManagerTestPolicyPrams.permList[0].permissionName;
    g_infoManagerTestPolicyPrams.permList[0].permissionName = "";
    tokenIdEx = AccessTokenKit::AllocHapToken(g_infoManagerTestInfoParms, g_infoManagerTestPolicyPrams);
    PermissionDef permDefResultBeta;
    int ret = AccessTokenKit::GetDefPermission("", permDefResultBeta);
    ASSERT_EQ(RET_FAILED, ret);
    g_infoManagerTestPolicyPrams.permList[0].permissionName = backup;
}

/**
 * @tc.name: AllocHapToken015
 * @tc.desc: can alloc a tokenId with permList bundleName as "".
 * @tc.type: FUNC
 * @tc.require:AR000GK6TJ
 */
HWTEST_F(AccessTokenKitTest, AllocHapToken015, TestSize.Level1)
{
    std::string backup;
    std::string backUpPermission;
    AccessTokenIDEx tokenIdEx = {0};

    backup = g_infoManagerTestPolicyPrams.permList[0].bundleName;
    backUpPermission = g_infoManagerTestPolicyPrams.permList[0].permissionName;
    g_infoManagerTestPolicyPrams.permList[0].bundleName = "";
    g_infoManagerTestPolicyPrams.permList[0].permissionName = "ohos.permission.testtmp05";
    tokenIdEx = AccessTokenKit::AllocHapToken(g_infoManagerTestInfoParms, g_infoManagerTestPolicyPrams);

    PermissionDef permDefResultBeta;
    int ret = AccessTokenKit::GetDefPermission(
        g_infoManagerTestPolicyPrams.permList[0].permissionName, permDefResultBeta);
    ASSERT_EQ(RET_FAILED, ret);
    ret = AccessTokenKit::GetDefPermission(g_infoManagerTestPolicyPrams.permList[1].permissionName, permDefResultBeta);
    ASSERT_EQ(RET_SUCCESS, ret);
    g_infoManagerTestPolicyPrams.permList[0].bundleName = backup;
    g_infoManagerTestPolicyPrams.permList[0].permissionName = backUpPermission;
}

/**
 * @tc.name: AllocHapToken016
 * @tc.desc: can alloc a tokenId with label as "".
 * @tc.type: FUNC
 * @tc.require:AR000GK6TJ
 */
HWTEST_F(AccessTokenKitTest, AllocHapToken016, TestSize.Level1)
{
    std::string backup;
    std::string backUpPermission;
    AccessTokenIDEx tokenIdEx = {0};

    backup = g_infoManagerTestPolicyPrams.permList[0].label;
    g_infoManagerTestPolicyPrams.permList[0].label = "";
    backUpPermission = g_infoManagerTestPolicyPrams.permList[0].permissionName;
    g_infoManagerTestPolicyPrams.permList[0].permissionName = "ohos.permission.testtmp06";
    tokenIdEx = AccessTokenKit::AllocHapToken(g_infoManagerTestInfoParms, g_infoManagerTestPolicyPrams);

    PermissionDef permDefResult;
    int ret = AccessTokenKit::GetDefPermission(g_infoManagerTestPolicyPrams.permList[0].permissionName, permDefResult);
    ASSERT_EQ(ret, RET_SUCCESS);
    g_infoManagerTestPolicyPrams.permList[0].label = backup;
    g_infoManagerTestPolicyPrams.permList[0].permissionName = backUpPermission;
}

/**
 * @tc.name: AllocHapToken017
 * @tc.desc: cannot alloc a tokenId with invalid permdef.
 * @tc.type: FUNC
 * @tc.require:AR000GK6TJ
 */
HWTEST_F(AccessTokenKitTest, AllocHapToken017, TestSize.Level1)
{
    std::string backUpPermission;
    std::string backup;
    AccessTokenIDEx tokenIdEx = {0};

    backup = g_infoManagerTestPolicyPrams.permList[0].description;
    g_infoManagerTestPolicyPrams.permList[0].description = "";
    backUpPermission = g_infoManagerTestPolicyPrams.permList[0].permissionName;
    g_infoManagerTestPolicyPrams.permList[0].permissionName = "ohos.permission.testtmp07";
    tokenIdEx = AccessTokenKit::AllocHapToken(g_infoManagerTestInfoParms, g_infoManagerTestPolicyPrams);

    PermissionDef permDefResult;
    int ret = AccessTokenKit::GetDefPermission(g_infoManagerTestPolicyPrams.permList[0].permissionName, permDefResult);
    ASSERT_EQ(ret, RET_SUCCESS);
    g_infoManagerTestPolicyPrams.permList[0].description = backup;
    g_infoManagerTestPolicyPrams.permList[0].permissionName = backUpPermission;
}

/**
 * @tc.name: AllocHapToken018
 * @tc.desc: alloc a tokenId with vaild dlptype.
 * @tc.type: FUNC
 * @tc.require:AR000H4SAB
 */
HWTEST_F(AccessTokenKitTest, AllocHapToken018, TestSize.Level1)
{
    AccessTokenIDEx tokenIdEx = {0};
    HapPolicyParams infoManagerTestPolicyPrams = {
        .apl = APL_NORMAL,
        .domain = "test.domain",
        .permList = {},
        .permStateList = {}
    };
    HapInfoParams infoManagerTestInfoParms1 = {
        .bundleName = "dlp_test1",
        .userID = 1,
        .instIndex = 0,
        .dlpType = DLP_COMMON,
        .appIDDesc = "testtesttesttest"
    };
    HapInfoParams infoManagerTestInfoParms2 = {
        .bundleName = "dlp_test2",
        .userID = 1,
        .instIndex = 1,
        .dlpType = DLP_READ,
        .appIDDesc = "testtesttesttest"
    };
    HapInfoParams infoManagerTestInfoParms3 = {
        .bundleName = "dlp_test3",
        .userID = 1,
        .instIndex = 2,
        .dlpType = DLP_FULL_CONTROL,
        .appIDDesc = "testtesttesttest"
    };
    HapTokenInfo hapTokenInfoRes;

    tokenIdEx= AccessTokenKit::AllocHapToken(infoManagerTestInfoParms1, infoManagerTestPolicyPrams);
    ASSERT_NE(0, tokenIdEx.tokenIdExStruct.tokenID);
    int ret = AccessTokenKit::GetHapTokenInfo(tokenIdEx.tokenIdExStruct.tokenID, hapTokenInfoRes);
    ASSERT_EQ(ret, RET_SUCCESS);
    ASSERT_EQ(hapTokenInfoRes.dlpType, DLP_COMMON);
    ret = AccessTokenKit::DeleteToken(tokenIdEx.tokenIdExStruct.tokenID);
    ASSERT_EQ(RET_SUCCESS, ret);
    ret = AccessTokenKit::GetHapTokenInfo(tokenIdEx.tokenIdExStruct.tokenID, hapTokenInfoRes);
    ASSERT_EQ(ret, RET_FAILED);

    tokenIdEx = AccessTokenKit::AllocHapToken(infoManagerTestInfoParms2, infoManagerTestPolicyPrams);
    ASSERT_NE(0, tokenIdEx.tokenIdExStruct.tokenID);
    ret = AccessTokenKit::GetHapTokenInfo(tokenIdEx.tokenIdExStruct.tokenID, hapTokenInfoRes);
    ASSERT_EQ(ret, RET_SUCCESS);
    ASSERT_EQ(hapTokenInfoRes.dlpType, DLP_READ);
    ret = AccessTokenKit::DeleteToken(tokenIdEx.tokenIdExStruct.tokenID);
    ASSERT_EQ(RET_SUCCESS, ret);
    ret = AccessTokenKit::GetHapTokenInfo(tokenIdEx.tokenIdExStruct.tokenID, hapTokenInfoRes);
    ASSERT_EQ(ret, RET_FAILED);

    tokenIdEx = AccessTokenKit::AllocHapToken(infoManagerTestInfoParms3, infoManagerTestPolicyPrams);
    ASSERT_NE(0, tokenIdEx.tokenIdExStruct.tokenID);
    ret = AccessTokenKit::GetHapTokenInfo(tokenIdEx.tokenIdExStruct.tokenID, hapTokenInfoRes);
    ASSERT_EQ(ret, RET_SUCCESS);
    ASSERT_EQ(hapTokenInfoRes.dlpType, DLP_FULL_CONTROL);
    ret = AccessTokenKit::DeleteToken(tokenIdEx.tokenIdExStruct.tokenID);
    ASSERT_EQ(RET_SUCCESS, ret);
    ret = AccessTokenKit::GetHapTokenInfo(tokenIdEx.tokenIdExStruct.tokenID, hapTokenInfoRes);
    ASSERT_EQ(ret, RET_FAILED);
}

/**
 * @tc.name: AllocHapToken019
 * @tc.desc: cannot alloc a tokenId with invaild dlptype.
 * @tc.type: FUNC
 * @tc.require:AR000H4SAB
 */
HWTEST_F(AccessTokenKitTest, AllocHapToken019, TestSize.Level1)
{
    AccessTokenIDEx tokenIdEx = {0};
    HapPolicyParams infoManagerTestPolicyPrams = {
        .apl = APL_NORMAL,
        .domain = "test.domain",
        .permList = {},
        .permStateList = {}
    };
    HapInfoParams infoManagerTestInfoParms1 = {
        .bundleName = "accesstoken_test",
        .userID = 1,
        .instIndex = 4,
        .dlpType = INVALID_DLP_TYPE,
        .appIDDesc = "testtesttesttest"
    };

    tokenIdEx = AccessTokenKit::AllocHapToken(infoManagerTestInfoParms1, infoManagerTestPolicyPrams);
    ASSERT_EQ(0, tokenIdEx.tokenIdExStruct.tokenID);
}

/**
 * @tc.name: UpdateHapToken001
 * @tc.desc: alloc a tokenId successfully, update it successfully and verify it.
 * @tc.type: FUNC
 * @tc.require:AR000GK6TJ
 */
HWTEST_F(AccessTokenKitTest, UpdateHapToken001, TestSize.Level1)
{
    int userID = g_infoManagerTestInfoParms.userID;
    const std::string bundleName = g_infoManagerTestInfoParms.bundleName;
    int instIndex = g_infoManagerTestInfoParms.instIndex;

    const std::string appIDDesc = "housework app";

    DeleteTestToken();
    AccessTokenIDEx tokenIdEx = {0};
    tokenIdEx = AccessTokenKit::AllocHapToken(g_infoManagerTestInfoParms, g_infoManagerTestPolicyPrams);
    GTEST_LOG_(INFO) << "tokenID :" << tokenIdEx.tokenIdExStruct.tokenID;
    AccessTokenID tokenID = AccessTokenKit::GetHapTokenID(userID, bundleName, instIndex);
    GTEST_LOG_(INFO) << "tokenID :" << tokenID;
    g_infoManagerTestPolicyPrams.apl = APL_SYSTEM_BASIC;

    int ret = AccessTokenKit::UpdateHapToken(tokenID, appIDDesc, g_infoManagerTestPolicyPrams);
    ASSERT_EQ(0, ret);

    HapTokenInfo hapTokenInfoRes;
    ret = AccessTokenKit::GetHapTokenInfo(tokenID, hapTokenInfoRes);
    ASSERT_EQ(RET_SUCCESS, ret);

    ASSERT_EQ(hapTokenInfoRes.appID, "housework app");
    ASSERT_EQ(hapTokenInfoRes.apl, APL_SYSTEM_BASIC);

    ret = AccessTokenKit::DeleteToken(tokenID);
    ASSERT_EQ(RET_SUCCESS, ret);
}

/**
 * @tc.name: UpdateHapToken002
 * @tc.desc: cannot update hap token info with invalid userId.
 * @tc.type: FUNC
 * @tc.require:AR000GK6TJ
 */
HWTEST_F(AccessTokenKitTest, UpdateHapToken002, TestSize.Level1)
{
    int ret = AccessTokenKit::UpdateHapToken(TEST_USER_ID_INVALID, "appIDDesc", g_infoManagerTestPolicyPrams);
    ASSERT_EQ(RET_FAILED, ret);
}

/**
 * @tc.name: UpdateHapToken003
 * @tc.desc: cannot update hap token info with invalid appIDDesc.
 * @tc.type: FUNC
 * @tc.require:AR000GK6TJ
 */
HWTEST_F(AccessTokenKitTest, UpdateHapToken003, TestSize.Level1)
{
    int userID = g_infoManagerTestInfoParms.userID;
    const std::string bundleName = g_infoManagerTestInfoParms.bundleName;
    int instIndex = g_infoManagerTestInfoParms.instIndex;

    const std::string appIDDesc (INVALID_APPIDDESC_LEN, 'x');

    AccessTokenIDEx tokenIdEx = {0};
    tokenIdEx = AccessTokenKit::AllocHapToken(g_infoManagerTestInfoParms, g_infoManagerTestPolicyPrams);

    AccessTokenID tokenID = AccessTokenKit::GetHapTokenID(userID, bundleName, instIndex);

    int ret = AccessTokenKit::UpdateHapToken(tokenID, appIDDesc, g_infoManagerTestPolicyPrams);
    ASSERT_EQ(RET_FAILED, ret);

    HapTokenInfo hapTokenInfoRes;
    ret = AccessTokenKit::GetHapTokenInfo(tokenID, hapTokenInfoRes);
    ASSERT_EQ(RET_SUCCESS, ret);

    ASSERT_EQ(hapTokenInfoRes.appID, "testtesttesttest");

    ret = AccessTokenKit::DeleteToken(tokenID);
    ASSERT_EQ(RET_SUCCESS, ret);
}

/**
 * @tc.name: UpdateHapToken004
 * @tc.desc: cannot update a tokenId with invalid apl.
 * @tc.type: FUNC
 * @tc.require:AR000GK6TJ
 */
HWTEST_F(AccessTokenKitTest, UpdateHapToken004, TestSize.Level1)
{
    int userID = g_infoManagerTestInfoParms.userID;
    const std::string bundleName = g_infoManagerTestInfoParms.bundleName;
    int instIndex = g_infoManagerTestInfoParms.instIndex;

    const std::string appIDDesc = "housework app";

    AccessTokenIDEx tokenIdEx = {0};
    tokenIdEx = AccessTokenKit::AllocHapToken(g_infoManagerTestInfoParms, g_infoManagerTestPolicyPrams);

    AccessTokenID tokenID = AccessTokenKit::GetHapTokenID(userID, bundleName, instIndex);

    g_infoManagerTestPolicyPrams.apl = (ATokenAplEnum)5;

    int ret = AccessTokenKit::UpdateHapToken(tokenID, appIDDesc, g_infoManagerTestPolicyPrams);
    ASSERT_EQ(RET_FAILED, ret);

    HapTokenInfo hapTokenInfoRes;
    ret = AccessTokenKit::GetHapTokenInfo(tokenID, hapTokenInfoRes);
    ASSERT_EQ(RET_SUCCESS, ret);

    ASSERT_EQ(hapTokenInfoRes.apl, APL_NORMAL);

    ret = AccessTokenKit::DeleteToken(tokenID);
    ASSERT_EQ(RET_SUCCESS, ret);
}

/**
 * @tc.name: UpdateHapToken005
 * @tc.desc: cannot update a tokenId with invalid string value.
 * @tc.type: FUNC
 * @tc.require:AR000GK6TJ
 */
HWTEST_F(AccessTokenKitTest, UpdateHapToken005, TestSize.Level1)
{
    std::string backUpPermission;
    const std::string appIDDesc = g_infoManagerTestInfoParms.appIDDesc;
    PermissionDef permDefResult;

    DeleteTestToken();
    AccessTokenIDEx tokenIdEx = AccessTokenKit::AllocHapToken(g_infoManagerTestInfoParms, g_infoManagerTestPolicyPrams);
    AccessTokenID tokenID = tokenIdEx.tokenIdExStruct.tokenID;
    ASSERT_NE(0, tokenID);

    std::string backup = g_infoManagerTestPolicyPrams.permList[0].permissionName;
    g_infoManagerTestPolicyPrams.permList[0].permissionName = "";
    int ret = AccessTokenKit::UpdateHapToken(tokenID, appIDDesc, g_infoManagerTestPolicyPrams);
    ret = AccessTokenKit::GetDefPermission(g_infoManagerTestPolicyPrams.permList[0].permissionName, permDefResult);
    ASSERT_EQ(RET_FAILED, ret);
    g_infoManagerTestPolicyPrams.permList[0].permissionName = backup;

    backUpPermission = g_infoManagerTestPolicyPrams.permList[0].permissionName;
    g_infoManagerTestPolicyPrams.permList[0].permissionName = "ohos.permission.testtmp11";
    backup = g_infoManagerTestPolicyPrams.permList[0].bundleName;
    g_infoManagerTestPolicyPrams.permList[0].bundleName = "";
    ret = AccessTokenKit::UpdateHapToken(tokenID, appIDDesc, g_infoManagerTestPolicyPrams);
    ret = AccessTokenKit::GetDefPermission(g_infoManagerTestPolicyPrams.permList[0].permissionName, permDefResult);
    ASSERT_EQ(RET_FAILED, ret);
    g_infoManagerTestPolicyPrams.permList[0].bundleName = backup;
    g_infoManagerTestPolicyPrams.permList[0].permissionName = backUpPermission;

    backUpPermission = g_infoManagerTestPolicyPrams.permList[0].permissionName;
    g_infoManagerTestPolicyPrams.permList[0].permissionName = "ohos.permission.testtmp12";
    backup = g_infoManagerTestPolicyPrams.permList[0].label;
    g_infoManagerTestPolicyPrams.permList[0].label = "";
    ret = AccessTokenKit::UpdateHapToken(tokenID, appIDDesc, g_infoManagerTestPolicyPrams);
    ASSERT_EQ(RET_SUCCESS, ret);
    ret = AccessTokenKit::GetDefPermission(g_infoManagerTestPolicyPrams.permList[0].permissionName, permDefResult);
    ASSERT_EQ(RET_SUCCESS, ret);
    g_infoManagerTestPolicyPrams.permList[0].label = backup;
    g_infoManagerTestPolicyPrams.permList[0].permissionName = backUpPermission;

    backUpPermission = g_infoManagerTestPolicyPrams.permList[0].permissionName;
    g_infoManagerTestPolicyPrams.permList[0].permissionName = "ohos.permission.testtmp13";
    backup = g_infoManagerTestPolicyPrams.permList[0].description;
    g_infoManagerTestPolicyPrams.permList[0].description = "";
    ret = AccessTokenKit::UpdateHapToken(tokenID, appIDDesc, g_infoManagerTestPolicyPrams);
    ASSERT_EQ(RET_SUCCESS, ret);
    ret = AccessTokenKit::GetDefPermission(g_infoManagerTestPolicyPrams.permList[0].permissionName, permDefResult);
    ASSERT_EQ(RET_SUCCESS, ret);
    g_infoManagerTestPolicyPrams.permList[0].description = backup;
    g_infoManagerTestPolicyPrams.permList[0].permissionName = backUpPermission;

    ret = AccessTokenKit::DeleteToken(tokenID);
    ASSERT_EQ(RET_SUCCESS, ret);
}

/**
 * @tc.name: UpdateHapToken006
 * @tc.desc: update a batch of tokenId.
 * @tc.type: FUNC
 * @tc.require:AR000GK6TJ
 */
HWTEST_F(AccessTokenKitTest, UpdateHapToken006, TestSize.Level1)
{
    int allocFlag = 0;
    int updateFlag = 0;
    int deleteFlag = 0;
    AccessTokenIDEx tokenIdEx = {0};
    AccessTokenID tokenID;
    int ret;
    vector<AccessTokenID> obj;
    bool exist;
    const std::string appIDDesc = g_infoManagerTestInfoParms.appIDDesc;
    HapInfoParams infoManagerTestInfo = g_infoManagerTestInfoParms;
    DeleteTestToken();

    for (int i = 0; i < CYCLE_TIMES; i++) {
        tokenIdEx = AccessTokenKit::AllocHapToken(infoManagerTestInfo, g_infoManagerTestPolicyPrams);
        tokenID = GetAccessTokenID(infoManagerTestInfo.userID,
                                   infoManagerTestInfo.bundleName,
                                   infoManagerTestInfo.instIndex);

        exist = ExistInVector(obj, tokenID);
        if (exist) {
            allocFlag = 1;
            break;
        }
        obj.push_back(tokenID);
        infoManagerTestInfo.userID++;
    }

    infoManagerTestInfo.instIndex = 1;
    g_infoManagerTestPolicyPrams.apl = APL_SYSTEM_BASIC;
    for (int i = 0; i < obj.size(); i++) {
        ret = AccessTokenKit::UpdateHapToken(obj[i], appIDDesc, g_infoManagerTestPolicyPrams);
        if (RET_SUCCESS != ret) {
            updateFlag = 1;
            break;
        }
    }
    g_infoManagerTestPolicyPrams.apl = APL_NORMAL;

    for (int i = 0; i < obj.size(); i++) {
        ret = AccessTokenKit::DeleteToken(obj[i]);
        if (RET_SUCCESS != ret) {
            deleteFlag = 1;
        }
    }
    ASSERT_EQ(allocFlag, 0);
    ASSERT_EQ(updateFlag, 0);
    ASSERT_EQ(deleteFlag, 0);
}

/**
 * @tc.name: UpdateHapToken007
 * @tc.desc: add new permissdef.
 * @tc.type: FUNC
 * @tc.require:AR000GK6TJ
 */
HWTEST_F(AccessTokenKitTest, UpdateHapToken007, TestSize.Level1)
{
    int ret;
    std::string backup;
    const std::string appIDDesc = g_infoManagerTestInfoParms.appIDDesc;
    DeleteTestToken();

    AccessTokenIDEx tokenIdEx = {0};
    tokenIdEx = AccessTokenKit::AllocHapToken(g_infoManagerTestInfoParms, g_infoManagerTestPolicyPrams);
    AccessTokenID tokenID = tokenIdEx.tokenIdExStruct.tokenID;
    GTEST_LOG_(INFO) << "tokenID :" << tokenID;

    PermissionDef permDefResult;
    /* check permission define before update */
    ret = AccessTokenKit::GetDefPermission("ohos.permission.test3", permDefResult);
    ASSERT_EQ(RET_FAILED, ret);

    backup = g_infoManagerTestPolicyPrams.permList[0].permissionName;
    g_infoManagerTestPolicyPrams.permList[0].permissionName = "ohos.permission.test3";
    ret = AccessTokenKit::UpdateHapToken(tokenID, appIDDesc, g_infoManagerTestPolicyPrams);
    ASSERT_EQ(RET_SUCCESS, ret);
    g_infoManagerTestPolicyPrams.permList[0].permissionName = backup;

    GTEST_LOG_(INFO) << "permissionName :" << g_infoManagerTestPolicyPrams.permList[0].permissionName;

    ret = AccessTokenKit::GetDefPermission("ohos.permission.test3", permDefResult);
    if (ret != RET_SUCCESS) {
        ret = AccessTokenKit::DeleteToken(tokenID);
        ASSERT_EQ(RET_SUCCESS, ret);
    }
    ASSERT_EQ(RET_SUCCESS, ret);
    ASSERT_EQ("ohos.permission.test3", permDefResult.permissionName);

    ret = AccessTokenKit::DeleteToken(tokenID);
    ASSERT_EQ(RET_SUCCESS, ret);
}
/**
 * @tc.name: UpdateHapToken008
 * @tc.desc: modify permissdef's grantMode.
 * @tc.type: FUNC
 * @tc.require:AR000GK6TJ
 */
HWTEST_F(AccessTokenKitTest, UpdateHapToken008, TestSize.Level1)
{
    int ret;
    std::string backup;
    const std::string appIDDesc = g_infoManagerTestInfoParms.appIDDesc;
    DeleteTestToken();

    AccessTokenIDEx tokenIdEx = {0};
    tokenIdEx = AccessTokenKit::AllocHapToken(g_infoManagerTestInfoParms, g_infoManagerTestPolicyPrams);
    AccessTokenID tokenID = tokenIdEx.tokenIdExStruct.tokenID;
    GTEST_LOG_(INFO) << "tokenID :" << tokenID;

    PermissionDef permDefResult;
    /* check permission define before update */
    ret = AccessTokenKit::GetDefPermission(g_infoManagerTestPolicyPrams.permList[0].permissionName, permDefResult);
    ASSERT_EQ(g_infoManagerTestPolicyPrams.permList[0].permissionName, permDefResult.permissionName);
    ASSERT_EQ("label", permDefResult.label);
    ASSERT_EQ(1, permDefResult.grantMode);
    ASSERT_EQ(RET_SUCCESS, ret);

    backup = g_infoManagerTestPolicyPrams.permList[0].label;
    g_infoManagerTestPolicyPrams.permList[0].grantMode = 0;
    g_infoManagerTestPolicyPrams.permList[0].label = "updated label";
    ret = AccessTokenKit::UpdateHapToken(tokenID, appIDDesc, g_infoManagerTestPolicyPrams);
    ASSERT_EQ(RET_SUCCESS, ret);
    g_infoManagerTestPolicyPrams.permList[0].label = backup;
    g_infoManagerTestPolicyPrams.permList[0].grantMode = 1;

    /* check permission define after update */
    ret = AccessTokenKit::GetDefPermission(g_infoManagerTestPolicyPrams.permList[0].permissionName, permDefResult);
    ASSERT_EQ(g_infoManagerTestPolicyPrams.permList[0].permissionName, permDefResult.permissionName);
    ASSERT_EQ("updated label", permDefResult.label);
    ASSERT_EQ(0, permDefResult.grantMode);
    ASSERT_EQ(RET_SUCCESS, ret);

    ret = AccessTokenKit::DeleteToken(tokenID);
    ASSERT_EQ(RET_SUCCESS, ret);
}

/**
 * @tc.name: UpdateHapToken009
 * @tc.desc: old permission define will not update its grantStatus.
 * @tc.type: FUNC
 * @tc.require:AR000GK6TJ
 */
HWTEST_F(AccessTokenKitTest, UpdateHapToken009, TestSize.Level1)
{
    int ret;
    std::vector<PermissionDef> permDefList;
    const std::string appIDDesc = g_infoManagerTestInfoParms.appIDDesc;
    PermissionDef infoManagerTestPermDef = g_infoManagerTestPermDef1;
    PermissionStateFull infoManagerTestState = {
        .grantFlags = {PermissionState::PERMISSION_DENIED},
        .grantStatus = {3},
        .isGeneral = true,
        .permissionName = "ohos.permission.test1",
        .resDeviceID = {"local"}};

    HapPolicyParams infoManagerTestPolicyPrams = {
        .apl = APL_NORMAL,
        .domain = "test.domain",
        .permList = {infoManagerTestPermDef},
        .permStateList = {infoManagerTestState}};

    DeleteTestToken();
    AccessTokenIDEx tokenIdEx = {0};
    tokenIdEx = AccessTokenKit::AllocHapToken(g_infoManagerTestInfoParms, g_infoManagerTestPolicyPrams);
    AccessTokenID tokenID = tokenIdEx.tokenIdExStruct.tokenID;
    GTEST_LOG_(INFO) << "tokenID :" << tokenID;

    ret = AccessTokenKit::VerifyAccessToken(tokenID, "ohos.permission.test1");
    ASSERT_EQ(ret, g_infoManagerTestState1.grantStatus[0]);

    ret = AccessTokenKit::UpdateHapToken(tokenID, appIDDesc, infoManagerTestPolicyPrams);

    ret = AccessTokenKit::VerifyAccessToken(tokenID, "ohos.permission.test1");
    ASSERT_EQ(ret, PermissionState::PERMISSION_DENIED);

    ret = AccessTokenKit::DeleteToken(tokenID);
    ASSERT_EQ(RET_SUCCESS, ret);
}

static void *ThreadTestFunc01(void *args)
{
    ATokenTypeEnum type;
    AccessTokenID tokenID;

    for (int i = 0; i < CYCLE_TIMES; i++) {
        tokenID = AccessTokenKit::GetHapTokenID(g_infoManagerTestInfoParms.userID,
                                                g_infoManagerTestInfoParms.bundleName,
                                                g_infoManagerTestInfoParms.instIndex);
        type = AccessTokenKit::GetTokenType(tokenID);
        if (type != TOKEN_HAP) {
            GTEST_LOG_(INFO) << "ThreadTestFunc01 failed" << tokenID;
        }
    }
    return NULL;
}

static void *ThreadTestFunc02(void *args)
{
    int ret;
    AccessTokenID tokenID;
    HapTokenInfo hapTokenInfoRes;

    for (int i = 0; i < CYCLE_TIMES; i++) {
        tokenID = AccessTokenKit::GetHapTokenID(g_infoManagerTestInfoParms.userID,
                                                g_infoManagerTestInfoParms.bundleName,
                                                g_infoManagerTestInfoParms.instIndex);
        ret = AccessTokenKit::GetHapTokenInfo(tokenID, hapTokenInfoRes);
        if (ret != RET_SUCCESS) {
            GTEST_LOG_(INFO) << "ThreadTestFunc02 failed" << tokenID;
        }
    }
    return NULL;
}

/**
 * @tc.name: AllocHapToken011
 * @tc.desc: Mulitpulthread test.
 * @tc.type: FUNC
 * @tc.require:AR000GK6TJ
 */
HWTEST_F(AccessTokenKitTest, Mulitpulthread001, TestSize.Level1)
{
    int ret;
    AccessTokenIDEx tokenIdEx = {0};
    tokenIdEx = AccessTokenKit::AllocHapToken(g_infoManagerTestInfoParms, g_infoManagerTestPolicyPrams);
    ASSERT_NE(0, tokenIdEx.tokenIdExStruct.tokenID);
    pthread_t tid[2];
    (void)pthread_create(&tid[0], 0, &ThreadTestFunc01, NULL);
    (void)pthread_create(&tid[1], 0, &ThreadTestFunc01, NULL);
    pthread_join(tid[0], NULL);
    pthread_join(tid[1], NULL);

    (void)pthread_create(&tid[0], 0, &ThreadTestFunc02, NULL);
    (void)pthread_create(&tid[1], 0, &ThreadTestFunc02, NULL);
    pthread_join(tid[0], NULL);
    pthread_join(tid[1], NULL);

    ret = AccessTokenKit::DeleteToken(tokenIdEx.tokenIdExStruct.tokenID);
    ASSERT_EQ(RET_SUCCESS, ret);
}

void ConcurrencyTask(unsigned int tokenID)
{
    for (int i = 0; i < CYCLE_TIMES; i++) {
        AccessTokenKit::GrantPermission(tokenID, TEST_PERMISSION_NAME_ALPHA, PERMISSION_USER_FIXED);
        AccessTokenKit::GetPermissionFlag(tokenID, TEST_PERMISSION_NAME_ALPHA);
        AccessTokenKit::VerifyAccessToken(tokenID, TEST_PERMISSION_NAME_ALPHA);

        AccessTokenKit::RevokePermission(tokenID, TEST_PERMISSION_NAME_ALPHA, PERMISSION_USER_SET);
        AccessTokenKit::GetPermissionFlag(tokenID, TEST_PERMISSION_NAME_ALPHA);
        AccessTokenKit::VerifyAccessToken(tokenID, TEST_PERMISSION_NAME_ALPHA);
    }
}

/**
 * @tc.name: ConcurrencyTest001
 * @tc.desc: Concurrency testing
 * @tc.type: FUNC
 * @tc.require:AR000GM5FC AR000GK6T8 AR000GK6TF
 */
HWTEST_F(AccessTokenKitTest, ConcurrencyTest001, TestSize.Level1)
{
    AccessTokenID tokenID = GetAccessTokenID(TEST_USER_ID, TEST_BUNDLE_NAME, 0);
    ASSERT_NE(0, tokenID);
    std::vector<std::thread> threadVec;
    for (int i = 0; i < THREAD_NUM; i++) {
        threadVec.emplace_back(std::thread(ConcurrencyTask, tokenID));
    }
    for (auto it = threadVec.begin(); it != threadVec.end(); it++) {
        it->join();
    }
}

/**
 * @tc.name: CheckNativeDCap001
 * @tc.desc: cannot Check native dcap with invalid tokenID.
 * @tc.type: FUNC
 * @tc.require:AR000GK6TD
 */
HWTEST_F(AccessTokenKitTest, CheckNativeDCap001, TestSize.Level1)
{
    AccessTokenID tokenID = 0;
    const std::string dcap = "AT_CAP";
    int ret = AccessTokenKit::CheckNativeDCap(tokenID, dcap);
    ASSERT_EQ(RET_FAILED, ret);

    tokenID = 1;
    ret = AccessTokenKit::CheckNativeDCap(tokenID, dcap);
    ASSERT_EQ(RET_FAILED, ret);
}

/**
 * @tc.name: CheckNativeDCap002
 * @tc.desc: cannot Check native dcap with invalid dcap.
 * @tc.type: FUNC
 * @tc.require:AR000GK6TD
 */
HWTEST_F(AccessTokenKitTest, CheckNativeDCap002, TestSize.Level1)
{
    AccessTokenID tokenID = 0Xff;
    const std::string invalidDcap (INVALID_DCAP_LEN, 'x');
    int ret = AccessTokenKit::CheckNativeDCap(tokenID, invalidDcap);
    ASSERT_EQ(RET_FAILED, ret);
}

/**
 * @tc.name: GetNativeTokenInfo001
 * @tc.desc: cannot get native token with invalid tokenID.
 * @tc.type: FUNC
 * @tc.require:AR000GK6TD
 */
HWTEST_F(AccessTokenKitTest, GetNativeTokenInfo001, TestSize.Level1)
{
    AccessTokenID tokenID = 0;
    NativeTokenInfo findInfo;
    int ret = AccessTokenKit::GetNativeTokenInfo(tokenID, findInfo);
    ASSERT_EQ(ret, RET_FAILED);

    tokenID = 0xff;
    ret = AccessTokenKit::GetNativeTokenInfo(tokenID, findInfo);
    ASSERT_EQ(ret, RET_FAILED);
}

/**
 * @tc.name: GetTokenTypeFlag001
 * @tc.desc: cannot get token type with tokenID.
 * @tc.type: FUNC
 * @tc.require:AR000GK6TD
 */
HWTEST_F(AccessTokenKitTest, GetTokenTypeFlag001, TestSize.Level1)
{
    AccessTokenID tokenID = 0;
    ATokenTypeEnum ret = AccessTokenKit::GetTokenTypeFlag(tokenID);
    ASSERT_EQ(ret, TOKEN_INVALID);
}

/**
 * @tc.name: GetTokenTypeFlag002
 * @tc.desc: Get token type with native tokenID.
 * @tc.type: FUNC
 * @tc.require:AR000GK6TD
 */
HWTEST_F(AccessTokenKitTest, GetTokenTypeFlag002, TestSize.Level1)
{
    NativeTokenInfoParams infoInstance = {
        .dcapsNum = 0,
        .permsNum = 0,
        .aclsNum = 0,
        .dcaps = nullptr,
        .perms = nullptr,
        .acls = nullptr,
        .processName = "GetTokenTypeFlag002",
        .aplStr = "system_core",
    };
    uint64_t tokenId01 = GetAccessTokenId(&infoInstance);

    AccessTokenID tokenID = tokenId01 & 0xffffffff;
    ATokenTypeEnum ret = AccessTokenKit::GetTokenTypeFlag(tokenID);
    ASSERT_EQ(ret, TOKEN_NATIVE);
}

/**
 * @tc.name: GetSelfPermissionsState001
 * @tc.desc: get permission list state
 * @tc.type: FUNC
 * @tc.require:AR000GK6T6
 */
HWTEST_F(AccessTokenKitTest, GetSelfPermissionsState001, TestSize.Level1)
{
    AccessTokenID tokenID = GetAccessTokenID(TEST_USER_ID, TEST_BUNDLE_NAME, 0);
    ASSERT_NE(0, tokenID);
    ASSERT_EQ(0, SetSelfTokenID(tokenID));

    PermissionListState perm1 = {
        .permissionName = "ohos.permission.testPermDef1",
        .state = -1,
    };
    PermissionListState perm2 = {
        .permissionName = "ohos.permission.testPermDef2",
        .state = -1,
    };
    PermissionListState perm3 = {
        .permissionName = "ohos.permission.testPermDef3",
        .state = -1,
    };
    PermissionListState perm4 = {
        .permissionName = "ohos.permission.testPermDef4",
        .state = -1,
    };

    std::vector<PermissionListState> permsList1;
    permsList1.emplace_back(perm1);
    permsList1.emplace_back(perm2);
    permsList1.emplace_back(perm3);
    permsList1.emplace_back(perm4);

    PermissionOper ret = AccessTokenKit::GetSelfPermissionsState(permsList1);
    ASSERT_EQ(DYNAMIC_OPER, ret);
    ASSERT_EQ(4, permsList1.size());
    ASSERT_EQ(DYNAMIC_OPER, permsList1[0].state);
    ASSERT_EQ(DYNAMIC_OPER, permsList1[1].state);
    ASSERT_EQ(SETTING_OPER, permsList1[2].state);
    ASSERT_EQ(PASS_OPER, permsList1[3].state);
    ASSERT_EQ("ohos.permission.testPermDef1", permsList1[0].permissionName);
    ASSERT_EQ("ohos.permission.testPermDef2", permsList1[1].permissionName);
    ASSERT_EQ("ohos.permission.testPermDef3", permsList1[2].permissionName);
    ASSERT_EQ("ohos.permission.testPermDef4", permsList1[3].permissionName);

    PermissionListState perm5 = {
        .permissionName = "ohos.permission.testPermDef5",
        .state = -1,
    };
    permsList1.emplace_back(perm5);
    ret = AccessTokenKit::GetSelfPermissionsState(permsList1);
    ASSERT_EQ(INVALID_OPER, permsList1[4].state);
    ASSERT_EQ(DYNAMIC_OPER, ret);

    std::vector<PermissionListState> permsList2;
    permsList2.emplace_back(perm3);
    permsList2.emplace_back(perm4);
    ret = AccessTokenKit::GetSelfPermissionsState(permsList2);
    ASSERT_EQ(SETTING_OPER, permsList2[0].state);
    ASSERT_EQ(PASS_OPER, permsList2[1].state);
    ASSERT_EQ(PASS_OPER, ret);

    permsList2.emplace_back(perm5);
    ret = AccessTokenKit::GetSelfPermissionsState(permsList2);
    ASSERT_EQ(SETTING_OPER, permsList2[0].state);
    ASSERT_EQ(PASS_OPER, permsList2[1].state);
    ASSERT_EQ(INVALID_OPER, permsList2[2].state);
    ASSERT_EQ(PASS_OPER, ret);

    std::vector<PermissionListState> permsList3;
    permsList3.emplace_back(perm5);
    ret = AccessTokenKit::GetSelfPermissionsState(permsList3);
    ASSERT_EQ(INVALID_OPER, permsList3[0].state);
    ASSERT_EQ(PASS_OPER, ret);
}

/**
 * @tc.name: GetTokenTypeFlag003
 * @tc.desc: Get token type with hap tokenID.
 * @tc.type: FUNC
 * @tc.require:AR000GK6TD
 */
HWTEST_F(AccessTokenKitTest, GetTokenTypeFlag003, TestSize.Level1)
{
    AccessTokenIDEx tokenIdEx = {0};
    tokenIdEx = AccessTokenKit::AllocHapToken(g_infoManagerTestInfoParms, g_infoManagerTestPolicyPrams);
    ASSERT_NE(0, tokenIdEx.tokenIdExStruct.tokenID);

    ATokenTypeEnum ret = AccessTokenKit::GetTokenTypeFlag(tokenIdEx.tokenIdExStruct.tokenID);
    ASSERT_EQ(ret, TOKEN_HAP);

    int res = AccessTokenKit::DeleteToken(tokenIdEx.tokenIdExStruct.tokenID);
    ASSERT_EQ(RET_SUCCESS, res);
}

class CbCustomizeTest : public PermStateChangeCbCustomize {
public:
    explicit CbCustomizeTest(const PermStateChangeScope &scopeInfo)
        : PermStateChangeCbCustomize(scopeInfo)
    {
        GTEST_LOG_(INFO) << "CbCustomizeTest create";
    }

    ~CbCustomizeTest()
    {}

    virtual void PermStateChangeCallback(PermStateChangeInfo& result)
    {
        ready_ = true;
        GTEST_LOG_(INFO) << "CbCustomizeTest PermStateChangeCallback";
        GTEST_LOG_(INFO) << "tokenid" << result.tokenID;
        GTEST_LOG_(INFO) << "permissionName" << result.permissionName;
    }

    bool ready_;
};

/**
 * @tc.name: RegisterPermStateChangeCallback001
 * @tc.desc: RegisterPermStateChangeCallback permList
 * @tc.type: FUNC
 * @tc.require:AR000GK6TD
 */
HWTEST_F(AccessTokenKitTest, RegisterPermStateChangeCallback001, TestSize.Level1)
{
    PermStateChangeScope scopeInfo;
    scopeInfo.permList = {"ohos.permission.CAMERA"};
    scopeInfo.tokenIDs = {};
    auto callbackPtr = std::make_shared<CbCustomizeTest>(scopeInfo);
    callbackPtr->ready_ = false;

    int32_t res = AccessTokenKit::RegisterPermStateChangeCallback(callbackPtr);

    static PermissionStateFull infoManagerTestStateA = {
        .permissionName = "ohos.permission.CAMERA",
        .grantFlags = {1},
        .grantStatus = {PERMISSION_DENIED},
        .isGeneral = true,
        .resDeviceID = {"local"}
    };
    static HapPolicyParams infoManagerTestPolicyPrams = {
        .apl = APL_NORMAL,
        .domain = "test.domain",
        .permList = {},
        .permStateList = {infoManagerTestStateA}
    };

    AccessTokenIDEx tokenIdEx = {0};
    AccessTokenID tokenID;
    tokenIdEx = AccessTokenKit::AllocHapToken(g_infoManagerTestInfoParms, infoManagerTestPolicyPrams);

    tokenID = tokenIdEx.tokenIdExStruct.tokenID;
    ASSERT_NE(0, tokenID);

    ATokenTypeEnum ret = AccessTokenKit::GetTokenTypeFlag(tokenID);
    ASSERT_EQ(ret, TOKEN_HAP);

    res = AccessTokenKit::VerifyAccessToken(tokenID, "ohos.permission.CAMERA");
    ASSERT_EQ(PERMISSION_DENIED, res);

    res = AccessTokenKit::GrantPermission(tokenID, "ohos.permission.CAMERA", 2);
    ASSERT_EQ(RET_SUCCESS, res);

    res = AccessTokenKit::VerifyAccessToken(tokenID, "ohos.permission.CAMERA");
    ASSERT_EQ(PERMISSION_GRANTED, res);

    ASSERT_EQ(true, callbackPtr->ready_);

    callbackPtr->ready_ = false;

    res = AccessTokenKit::RevokePermission(tokenID, "ohos.permission.CAMERA", 2);
    ASSERT_EQ(RET_SUCCESS, res);

    ASSERT_EQ(true, callbackPtr->ready_);

    res = AccessTokenKit::UnRegisterPermStateChangeCallback(callbackPtr);
    ASSERT_EQ(RET_SUCCESS, res);

    callbackPtr->ready_ = false;

    res = AccessTokenKit::GrantPermission(tokenID, "ohos.permission.CAMERA", 2);
    ASSERT_EQ(RET_SUCCESS, res);

    ASSERT_EQ(false, callbackPtr->ready_);

    callbackPtr->ready_ = false;

    res = AccessTokenKit::RevokePermission(tokenID, "ohos.permission.CAMERA", 2);
    ASSERT_EQ(RET_SUCCESS, res);

    ASSERT_EQ(false, callbackPtr->ready_);

    res = AccessTokenKit::DeleteToken(tokenID);
    ASSERT_EQ(RET_SUCCESS, res);
}

/**
 * @tc.name: RegisterPermStateChangeCallback002
 * @tc.desc: RegisterPermStateChangeCallback permList
 * @tc.type: FUNC
 * @tc.require:AR000GK6TD
 */
HWTEST_F(AccessTokenKitTest, RegisterPermStateChangeCallback002, TestSize.Level1)
{
    PermStateChangeScope scopeInfo;
    scopeInfo.permList = {"ohos.permission.GET_BUNDLE_INFO"};
    scopeInfo.tokenIDs = {};
    auto callbackPtr = std::make_shared<CbCustomizeTest>(scopeInfo);
    callbackPtr->ready_ = false;

    int32_t res = AccessTokenKit::RegisterPermStateChangeCallback(callbackPtr);

    static PermissionStateFull infoManagerTestStateA = {
        .permissionName = "ohos.permission.GET_BUNDLE_INFO",
        .grantFlags = {1},
        .grantStatus = {PERMISSION_GRANTED},
        .isGeneral = true,
        .resDeviceID = {"local"}
    };
    static PermissionStateFull infoManagerTestStateB = {
        .permissionName = "ohos.permission.CAMERA",
        .grantFlags = {1},
        .grantStatus = {PERMISSION_GRANTED},
        .isGeneral = true,
        .resDeviceID = {"local"}
    };
    static HapPolicyParams infoManagerTestPolicyPrams = {
        .apl = APL_SYSTEM_BASIC,
        .domain = "test.domain",
        .permList = {},
        .permStateList = {infoManagerTestStateA, infoManagerTestStateB}
    };

    AccessTokenIDEx tokenIdEx = {0};
    tokenIdEx = AccessTokenKit::AllocHapToken(g_infoManagerTestInfoParms, infoManagerTestPolicyPrams);

    AccessTokenID tokenID = tokenIdEx.tokenIdExStruct.tokenID;

    res = AccessTokenKit::VerifyAccessToken(tokenID, "ohos.permission.CAMERA");
    ASSERT_EQ(PERMISSION_GRANTED, res);

    res = AccessTokenKit::GrantPermission(tokenID, "ohos.permission.CAMERA", 2);
    ASSERT_EQ(RET_SUCCESS, res);

    ASSERT_EQ(false, callbackPtr->ready_);

    res = AccessTokenKit::DeleteToken(tokenID);
    ASSERT_EQ(RET_SUCCESS, res);

    res = AccessTokenKit::UnRegisterPermStateChangeCallback(callbackPtr);
    ASSERT_EQ(RET_SUCCESS, res);
}

/**
 * @tc.name: RegisterPermStateChangeCallback003
 * @tc.desc: RegisterPermStateChangeCallback permList
 * @tc.type: FUNC
 * @tc.require:AR000GK6TD
 */
HWTEST_F(AccessTokenKitTest, RegisterPermStateChangeCallback003, TestSize.Level1)
{
    PermStateChangeScope scopeInfo;
    scopeInfo.permList = {};
    scopeInfo.tokenIDs = {};
    auto callbackPtr = std::make_shared<CbCustomizeTest>(scopeInfo);
    callbackPtr->ready_ = false;

    int32_t res = AccessTokenKit::RegisterPermStateChangeCallback(callbackPtr);

    static PermissionStateFull infoManagerTestStateA = {
        .permissionName = "ohos.permission.GET_BUNDLE_INFO",
        .grantFlags = {1},
        .grantStatus = {PERMISSION_DENIED},
        .isGeneral = true,
        .resDeviceID = {"local"}
    };
    static PermissionStateFull infoManagerTestStateB = {
        .permissionName = "ohos.permission.CAMERA",
        .grantFlags = {1},
        .grantStatus = {PERMISSION_DENIED},
        .isGeneral = true,
        .resDeviceID = {"local"}
    };
    static HapPolicyParams infoManagerTestPolicyPrams = {
        .apl = APL_SYSTEM_CORE,
        .domain = "test.domain",
        .permList = {},
        .permStateList = {infoManagerTestStateA, infoManagerTestStateB}
    };

    AccessTokenIDEx tokenIdEx = {0};
    tokenIdEx = AccessTokenKit::AllocHapToken(g_infoManagerTestInfoParms, infoManagerTestPolicyPrams);

    AccessTokenID tokenID = tokenIdEx.tokenIdExStruct.tokenID;

    callbackPtr->ready_ = false;
    res = AccessTokenKit::VerifyAccessToken(tokenID, "ohos.permission.CAMERA");
    ASSERT_EQ(PERMISSION_DENIED, res);
    res = AccessTokenKit::GrantPermission(tokenID, "ohos.permission.CAMERA", 2);
    ASSERT_EQ(RET_SUCCESS, res);
    res = AccessTokenKit::VerifyAccessToken(tokenID, "ohos.permission.CAMERA");
    ASSERT_EQ(PERMISSION_GRANTED, res);
    ASSERT_EQ(true, callbackPtr->ready_);

    callbackPtr->ready_ = false;
    res = AccessTokenKit::VerifyAccessToken(tokenID, "ohos.permission.GET_BUNDLE_INFO");
    ASSERT_EQ(PERMISSION_DENIED, res);
    res = AccessTokenKit::GrantPermission(tokenID, "ohos.permission.GET_BUNDLE_INFO", 2);
    ASSERT_EQ(RET_SUCCESS, res);

    ASSERT_EQ(true, callbackPtr->ready_);

    res = AccessTokenKit::DeleteToken(tokenID);
    ASSERT_EQ(RET_SUCCESS, res);

    res = AccessTokenKit::UnRegisterPermStateChangeCallback(callbackPtr);
    ASSERT_EQ(RET_SUCCESS, res);
}

/**
 * @tc.name: RegisterPermStateChangeCallback004
 * @tc.desc: RegisterPermStateChangeCallback permList
 * @tc.type: FUNC
 * @tc.require:AR000GK6TD
 */
HWTEST_F(AccessTokenKitTest, RegisterPermStateChangeCallback004, TestSize.Level1)
{
    PermStateChangeScope scopeInfo;
    scopeInfo.permList = {"ohos.permission.GET_BUNDLE_INFO", "ohos.permission.CAMERA"};
    scopeInfo.tokenIDs = {555555}; // 555555为模拟的tokenid
    auto callbackPtr = std::make_shared<CbCustomizeTest>(scopeInfo);
    callbackPtr->ready_ = false;

    int32_t res = AccessTokenKit::RegisterPermStateChangeCallback(callbackPtr);

    static PermissionStateFull infoManagerTestStateA = {
        .permissionName = "ohos.permission.GET_BUNDLE_INFO",
        .grantFlags = {1},
        .grantStatus = {PERMISSION_GRANTED},
        .isGeneral = true,
        .resDeviceID = {"local"}
    };
    static PermissionStateFull infoManagerTestStateB = {
        .permissionName = "ohos.permission.CAMERA",
        .grantFlags = {1},
        .grantStatus = {PERMISSION_GRANTED},
        .isGeneral = true,
        .resDeviceID = {"local"}
    };
    static HapPolicyParams infoManagerTestPolicyPrams = {
        .apl = APL_NORMAL,
        .domain = "test.domain",
        .permList = {},
        .permStateList = {infoManagerTestStateA, infoManagerTestStateB}
    };

    AccessTokenIDEx tokenIdEx = {0};
    tokenIdEx = AccessTokenKit::AllocHapToken(g_infoManagerTestInfoParms, infoManagerTestPolicyPrams);

    AccessTokenID tokenID = tokenIdEx.tokenIdExStruct.tokenID;

    callbackPtr->ready_ = false;
    res = AccessTokenKit::VerifyAccessToken(tokenID, "ohos.permission.CAMERA");
    ASSERT_EQ(PERMISSION_GRANTED, res);
    res = AccessTokenKit::RevokePermission(tokenID, "ohos.permission.CAMERA", 2);
    ASSERT_EQ(RET_SUCCESS, res);
    res = AccessTokenKit::VerifyAccessToken(tokenID, "ohos.permission.CAMERA");
    ASSERT_EQ(PERMISSION_DENIED, res);
    ASSERT_EQ(false, callbackPtr->ready_);

    callbackPtr->ready_ = false;
    res = AccessTokenKit::VerifyAccessToken(tokenID, "ohos.permission.GET_BUNDLE_INFO");
    ASSERT_EQ(PERMISSION_GRANTED, res);
    res = AccessTokenKit::RevokePermission(tokenID, "ohos.permission.GET_BUNDLE_INFO", 2);
    ASSERT_EQ(RET_SUCCESS, res);

    ASSERT_EQ(false, callbackPtr->ready_);

    res = AccessTokenKit::DeleteToken(tokenID);
    ASSERT_EQ(RET_SUCCESS, res);

    res = AccessTokenKit::UnRegisterPermStateChangeCallback(callbackPtr);
    ASSERT_EQ(RET_SUCCESS, res);
}

/**
 * @tc.name: RegisterPermStateChangeCallback005
 * @tc.desc: RegisterPermStateChangeCallback permList
 * @tc.type: FUNC
 * @tc.require:AR000GK6TD
 */
HWTEST_F(AccessTokenKitTest, RegisterPermStateChangeCallback005, TestSize.Level1)
{
    static PermissionStateFull infoManagerTestStateA = {
        .permissionName = "ohos.permission.CAMERA",
        .grantFlags = {1},
        .grantStatus = {PERMISSION_DENIED},
        .isGeneral = true,
        .resDeviceID = {"local"}
    };
    static PermissionStateFull infoManagerTestStateB = {
        .permissionName = "ohos.permission.GET_BUNDLE_INFO",
        .grantFlags = {1},
        .grantStatus = {PERMISSION_GRANTED},
        .isGeneral = true,
        .resDeviceID = {"local"}
    };
    static HapPolicyParams infoManagerTestPolicyPrams = {
        .apl = APL_NORMAL,
        .domain = "test.domain",
        .permList = {},
        .permStateList = {infoManagerTestStateA, infoManagerTestStateB}
    };

    AccessTokenIDEx tokenIdEx = {0};
    tokenIdEx = AccessTokenKit::AllocHapToken(g_infoManagerTestInfoParms, infoManagerTestPolicyPrams);

    AccessTokenID tokenID = tokenIdEx.tokenIdExStruct.tokenID;

    PermStateChangeScope scopeInfo;
    scopeInfo.permList = {"ohos.permission.GET_BUNDLE_INFO", "ohos.permission.CAMERA"};
    scopeInfo.tokenIDs = {tokenID, 0};
    auto callbackPtr = std::make_shared<CbCustomizeTest>(scopeInfo);
    callbackPtr->ready_ = false;

    int32_t res = AccessTokenKit::RegisterPermStateChangeCallback(callbackPtr);

    callbackPtr->ready_ = false;
    res = AccessTokenKit::VerifyAccessToken(tokenID, "ohos.permission.CAMERA");
    ASSERT_EQ(PERMISSION_DENIED, res);
    res = AccessTokenKit::GrantPermission(tokenID, "ohos.permission.CAMERA", 2);
    ASSERT_EQ(RET_SUCCESS, res);
    ASSERT_EQ(true, callbackPtr->ready_);

    callbackPtr->ready_ = false;
    res = AccessTokenKit::VerifyAccessToken(tokenID, "ohos.permission.GET_BUNDLE_INFO");
    ASSERT_EQ(PERMISSION_GRANTED, res);
    res = AccessTokenKit::GrantPermission(tokenID, "ohos.permission.GET_BUNDLE_INFO", 2);
    ASSERT_EQ(RET_SUCCESS, res);

    ASSERT_EQ(false, callbackPtr->ready_);

    res = AccessTokenKit::DeleteToken(tokenID);
    ASSERT_EQ(RET_SUCCESS, res);

    res = AccessTokenKit::UnRegisterPermStateChangeCallback(callbackPtr);
    ASSERT_EQ(RET_SUCCESS, res);
}

#ifdef TOKEN_SYNC_ENABLE
/**
 * @tc.name: SetRemoteHapTokenInfo001
 * @tc.desc: set remote hap token info success
 * @tc.type: FUNC
 * @tc.require:AR000GK6T5
 */
HWTEST_F(AccessTokenKitTest, SetRemoteHapTokenInfo001, TestSize.Level1)
{
    ACCESSTOKEN_LOG_INFO(LABEL, "SetRemoteHapTokenInfo001 start.");
    std::string deviceID = udid_;
    AccessTokenKit::DeleteRemoteToken(deviceID, 0x20100000);
    HapTokenInfo baseInfo = {
        .apl = APL_NORMAL,
        .ver = 1,
        .userID = 1,
        .bundleName = "com.ohos.access_token",
        .instIndex = 1,
        .appID = "testtesttesttest",
        .deviceID = deviceID,
        .tokenID = 0x20100000,
        .tokenAttr = 0
    };

    PermissionStateFull infoManagerTestState = {
        .grantFlags = {PermissionFlag::PERMISSION_SYSTEM_FIXED},
        .grantStatus = {PermissionState::PERMISSION_GRANTED},
        .isGeneral = true,
        .permissionName = "ohos.permission.test1",
        .resDeviceID = {"local"}};
    std::vector<PermissionStateFull> permStateList;
    permStateList.emplace_back(infoManagerTestState);

    HapTokenInfoForSync remoteTokenInfo = {
        .baseInfo = baseInfo,
        .permStateList = permStateList
    };

    int ret = AccessTokenKit::SetRemoteHapTokenInfo(deviceID, remoteTokenInfo);
    ASSERT_EQ(ret, RET_SUCCESS);

    // Get local map token ID
    AccessTokenID mapID = AccessTokenKit::AllocLocalTokenID(networkId_, 0x20100000);
    ASSERT_NE(mapID, 0);

    // check local map token
    HapTokenInfo resultInfo;
    ret = AccessTokenKit::GetHapTokenInfo(mapID, resultInfo);
    ASSERT_EQ(ret, RET_SUCCESS);
    ASSERT_EQ(resultInfo.apl, remoteTokenInfo.baseInfo.apl);
    ASSERT_EQ(resultInfo.ver, remoteTokenInfo.baseInfo.ver);
    ASSERT_EQ(resultInfo.userID, remoteTokenInfo.baseInfo.userID);
    ASSERT_EQ(resultInfo.bundleName, remoteTokenInfo.baseInfo.bundleName);
    ASSERT_EQ(resultInfo.instIndex, remoteTokenInfo.baseInfo.instIndex);
    ASSERT_EQ(resultInfo.appID, remoteTokenInfo.baseInfo.appID);
    ASSERT_EQ(resultInfo.deviceID, remoteTokenInfo.baseInfo.deviceID);
    ASSERT_NE(resultInfo.tokenID, remoteTokenInfo.baseInfo.tokenID); // tokenID already is map tokenID
    ASSERT_EQ(resultInfo.tokenAttr, remoteTokenInfo.baseInfo.tokenAttr);

    ret = AccessTokenKit::VerifyAccessToken(mapID, "ohos.permission.test1");
    ASSERT_EQ(ret, PermissionState::PERMISSION_GRANTED);

    ret = AccessTokenKit::DeleteRemoteToken(deviceID, 0x20100000);
    ASSERT_EQ(ret, RET_SUCCESS);
}

/**
 * @tc.name: SetRemoteHapTokenInfo002
 * @tc.desc: set remote hap token info, token info is wrong
 * @tc.type: FUNC
 * @tc.require:AR000GK6T5
 */
HWTEST_F(AccessTokenKitTest, SetRemoteHapTokenInfo002, TestSize.Level1)
{
    ACCESSTOKEN_LOG_INFO(LABEL, "SetRemoteHapTokenInfo002 start.");
    std::string deviceID = udid_;
    AccessTokenKit::DeleteRemoteToken(deviceID, 0x20100000);
    HapTokenInfo rightBaseInfo = {
        .apl = APL_NORMAL,
        .ver = 1,
        .userID = 1,
        .bundleName = "com.ohos.access_token",
        .instIndex = 1,
        .appID = "testtesttesttest",
        .deviceID = udid_,
        .tokenID = 0x20100000,
        .tokenAttr = 0
    };

    HapTokenInfo wrongBaseInfo = rightBaseInfo;
    wrongBaseInfo.apl = (ATokenAplEnum)11; // wrong apl

    PermissionStateFull infoManagerTestState = {
        .grantFlags = {PermissionFlag::PERMISSION_SYSTEM_FIXED},
        .grantStatus = {PermissionState::PERMISSION_GRANTED},
        .isGeneral = true,
        .permissionName = "ohos.permission.test1",
        .resDeviceID = {"local"}};
    std::vector<PermissionStateFull> permStateList;
    permStateList.emplace_back(infoManagerTestState);

    HapTokenInfoForSync remoteTokenInfo = {
        .baseInfo = wrongBaseInfo,
        .permStateList = permStateList
    };

    int ret = AccessTokenKit::SetRemoteHapTokenInfo(deviceID, remoteTokenInfo);
    ASSERT_NE(ret, RET_SUCCESS);

    std::string wrongStr(10241, 'x');

    wrongBaseInfo = rightBaseInfo;
    wrongBaseInfo.appID = wrongStr; // wrong appID
    remoteTokenInfo.baseInfo = wrongBaseInfo;
    ret = AccessTokenKit::SetRemoteHapTokenInfo(deviceID, remoteTokenInfo);
    ASSERT_NE(ret, RET_SUCCESS);

    wrongBaseInfo = rightBaseInfo;
    wrongBaseInfo.bundleName = wrongStr; // wrong bundleName
    remoteTokenInfo.baseInfo = wrongBaseInfo;
    ret = AccessTokenKit::SetRemoteHapTokenInfo(deviceID, remoteTokenInfo);
    ASSERT_NE(ret, RET_SUCCESS);

    wrongBaseInfo = rightBaseInfo;
    wrongBaseInfo.deviceID = wrongStr; // wrong deviceID
    remoteTokenInfo.baseInfo = wrongBaseInfo;
    ret = AccessTokenKit::SetRemoteHapTokenInfo(deviceID, remoteTokenInfo);
    ASSERT_NE(ret, RET_SUCCESS);

    wrongBaseInfo = rightBaseInfo;
    wrongBaseInfo.tokenID = 0; // wrong tokenID
    remoteTokenInfo.baseInfo = wrongBaseInfo;
    ret = AccessTokenKit::SetRemoteHapTokenInfo(deviceID, remoteTokenInfo);
    ASSERT_NE(ret, RET_SUCCESS);
}

/**
 * @tc.name: SetRemoteHapTokenInfo003
 * @tc.desc: set remote hap token wrong permission grant
 * @tc.type: FUNC
 * @tc.require:AR000GK6T5
 */
HWTEST_F(AccessTokenKitTest, SetRemoteHapTokenInfo003, TestSize.Level1)
{
    ACCESSTOKEN_LOG_INFO(LABEL, "SetRemoteHapTokenInfo003 start.");
    std::string deviceID = udid_;
    AccessTokenKit::DeleteRemoteToken(deviceID, 0x20100000);
    HapTokenInfo baseInfo = {
        .apl = APL_NORMAL,
        .ver = 1,
        .userID = 1,
        .bundleName = "com.ohos.access_token",
        .instIndex = 1,
        .appID = "testtesttesttest",
        .deviceID = udid_,
        .tokenID = 0x20100000,
        .tokenAttr = 0
    };

    PermissionStateFull infoManagerTestState = {
        .grantFlags = {11}, // wrong flags
        .grantStatus = {PermissionState::PERMISSION_GRANTED},
        .isGeneral = true,
        .permissionName = "ohos.permission.test1",
        .resDeviceID = {"local"}};
    std::vector<PermissionStateFull> permStateList;
    permStateList.emplace_back(infoManagerTestState);

    HapTokenInfoForSync remoteTokenInfo = {
        .baseInfo = baseInfo,
        .permStateList = permStateList
    };

    int ret = AccessTokenKit::SetRemoteHapTokenInfo(deviceID, remoteTokenInfo);
    ASSERT_EQ(ret, RET_SUCCESS);

    // Get local map token ID
    AccessTokenID mapID = AccessTokenKit::AllocLocalTokenID(networkId_, 0x20100000);
    ASSERT_NE(mapID, 0);

    ret = AccessTokenKit::VerifyAccessToken(mapID, "ohos.permission.test1");
    ASSERT_EQ(ret, PermissionState::PERMISSION_DENIED);

    ret = AccessTokenKit::DeleteRemoteToken(deviceID, 0x20100000);
    ASSERT_EQ(ret, RET_SUCCESS);
}

/**
 * @tc.name: SetRemoteHapTokenInfo004
 * @tc.desc: update remote hap token when remote exist
 * @tc.type: FUNC
 * @tc.require:AR000GK6T5
 */
HWTEST_F(AccessTokenKitTest, SetRemoteHapTokenInfo004, TestSize.Level1)
{
    ACCESSTOKEN_LOG_INFO(LABEL, "SetRemoteHapTokenInfo004 start.");
    std::string deviceID = udid_;
    AccessTokenKit::DeleteRemoteToken(deviceID, 0x20100000);
    HapTokenInfo baseInfo = {
        .apl = APL_NORMAL,
        .ver = 1,
        .userID = 1,
        .bundleName = "com.ohos.access_token",
        .instIndex = 1,
        .appID = "testtesttesttest",
        .deviceID = udid_,
        .tokenID = 0x20100000,
        .tokenAttr = 0
    };

    PermissionStateFull infoManagerTestState = {
        .grantFlags = {PermissionFlag::PERMISSION_SYSTEM_FIXED},
        .grantStatus = {PermissionState::PERMISSION_DENIED}, // first denied
        .isGeneral = true,
        .permissionName = "ohos.permission.test1",
        .resDeviceID = {"local"}};
    std::vector<PermissionStateFull> permStateList;
    permStateList.emplace_back(infoManagerTestState);

    HapTokenInfoForSync remoteTokenInfo = {
        .baseInfo = baseInfo,
        .permStateList = permStateList
    };

    int ret = AccessTokenKit::SetRemoteHapTokenInfo(deviceID, remoteTokenInfo);
    ASSERT_EQ(ret, RET_SUCCESS);

    // Get local map token ID
    AccessTokenID mapID = AccessTokenKit::AllocLocalTokenID(networkId_, 0x20100000);
    ASSERT_NE(mapID, 0);

    ret = AccessTokenKit::VerifyAccessToken(mapID, "ohos.permission.test1");
    ASSERT_EQ(ret, PermissionState::PERMISSION_DENIED);

    remoteTokenInfo.permStateList[0].grantStatus[0] = PermissionState::PERMISSION_GRANTED; // second granted
    ret = AccessTokenKit::SetRemoteHapTokenInfo(deviceID, remoteTokenInfo);
    ASSERT_EQ(ret, RET_SUCCESS);

    ret = AccessTokenKit::VerifyAccessToken(mapID, "ohos.permission.test1");
    ASSERT_EQ(ret, PermissionState::PERMISSION_GRANTED);

    ret = AccessTokenKit::DeleteRemoteToken(deviceID, 0x20100000);
    ASSERT_EQ(ret, RET_SUCCESS);
}

/**
 * @tc.name: SetRemoteHapTokenInfo005
 * @tc.desc: add remote hap token, it can not grant by GrantPermission
 * @tc.type: FUNC
 * @tc.require:AR000GK6T5
 */
HWTEST_F(AccessTokenKitTest, SetRemoteHapTokenInfo005, TestSize.Level1)
{
    ACCESSTOKEN_LOG_INFO(LABEL, "SetRemoteHapTokenInfo005 start.");
    std::string deviceID = udid_;
    AccessTokenKit::DeleteRemoteToken(deviceID, 0x20100000);
    HapTokenInfo baseInfo = {
        .apl = APL_NORMAL,
        .ver = 1,
        .userID = 1,
        .bundleName = "com.ohos.access_token",
        .instIndex = 1,
        .appID = "testtesttesttest",
        .deviceID = udid_,
        .tokenID = 0x20100000,
        .tokenAttr = 0
    };

    PermissionStateFull infoManagerTestState = {
        .grantFlags = {PermissionFlag::PERMISSION_SYSTEM_FIXED},
        .grantStatus = {PermissionState::PERMISSION_DENIED}, // first denied
        .isGeneral = true,
        .permissionName = "ohos.permission.test1",
        .resDeviceID = {"local"}};
    std::vector<PermissionStateFull> permStateList;
    permStateList.emplace_back(infoManagerTestState);

    HapTokenInfoForSync remoteTokenInfo = {
        .baseInfo = baseInfo,
        .permStateList = permStateList
    };

    int ret = AccessTokenKit::SetRemoteHapTokenInfo(deviceID, remoteTokenInfo);
    ASSERT_EQ(ret, RET_SUCCESS);

    // Get local map token ID
    AccessTokenID mapID = AccessTokenKit::AllocLocalTokenID(networkId_, 0x20100000);
    ASSERT_NE(mapID, 0);

    ret = AccessTokenKit::VerifyAccessToken(mapID, "ohos.permission.test1");
    ASSERT_EQ(ret, PermissionState::PERMISSION_DENIED);

    ret = AccessTokenKit::GrantPermission(mapID, "ohos.permission.test1", PermissionFlag::PERMISSION_SYSTEM_FIXED);
    ASSERT_EQ(ret, RET_SUCCESS);

    ret = AccessTokenKit::VerifyAccessToken(mapID, "ohos.permission.test1");
    ASSERT_EQ(ret, PermissionState::PERMISSION_DENIED);

    ret = AccessTokenKit::DeleteRemoteToken(deviceID, 0x20100000);
    ASSERT_EQ(ret, RET_SUCCESS);
}

/**
 * @tc.name: SetRemoteHapTokenInfo006
 * @tc.desc: add remote hap token, it can not revoke by RevokePermission
 * @tc.type: FUNC
 * @tc.require:AR000GK6T5
 */
HWTEST_F(AccessTokenKitTest, SetRemoteHapTokenInfo006, TestSize.Level1)
{
    ACCESSTOKEN_LOG_INFO(LABEL, "SetRemoteHapTokenInfo006 start.");
    std::string deviceID = udid_;
    AccessTokenKit::DeleteRemoteToken(deviceID, 0x20100000);
    HapTokenInfo baseInfo = {
        .apl = APL_NORMAL,
        .ver = 1,
        .userID = 1,
        .bundleName = "com.ohos.access_token",
        .instIndex = 1,
        .appID = "testtesttesttest",
        .deviceID = udid_,
        .tokenID = 0x20100000,
        .tokenAttr = 0
    };

    PermissionStateFull infoManagerTestState = {
        .grantFlags = {PermissionFlag::PERMISSION_SYSTEM_FIXED},
        .grantStatus = {PermissionState::PERMISSION_GRANTED}, // first grant
        .isGeneral = true,
        .permissionName = "ohos.permission.test1",
        .resDeviceID = {"local"}};
    std::vector<PermissionStateFull> permStateList;
    permStateList.emplace_back(infoManagerTestState);

    HapTokenInfoForSync remoteTokenInfo = {
        .baseInfo = baseInfo,
        .permStateList = permStateList
    };

    int ret = AccessTokenKit::SetRemoteHapTokenInfo(deviceID, remoteTokenInfo);
    ASSERT_EQ(ret, RET_SUCCESS);

    // Get local map token ID
    AccessTokenID mapID = AccessTokenKit::AllocLocalTokenID(networkId_, 0x20100000);
    ASSERT_NE(mapID, 0);

    ret = AccessTokenKit::VerifyAccessToken(mapID, "ohos.permission.test1");
    ASSERT_EQ(ret, PermissionState::PERMISSION_GRANTED);

    ret = AccessTokenKit::RevokePermission(mapID, "ohos.permission.test1", PermissionFlag::PERMISSION_SYSTEM_FIXED);
    ASSERT_EQ(ret, RET_SUCCESS);

    ret = AccessTokenKit::VerifyAccessToken(mapID, "ohos.permission.test1");
    ASSERT_EQ(ret, PermissionState::PERMISSION_GRANTED);

    ret = AccessTokenKit::DeleteRemoteToken(deviceID, 0x20100000);
    ASSERT_EQ(ret, RET_SUCCESS);
}

/**
 * @tc.name: SetRemoteHapTokenInfo007
 * @tc.desc: add remote hap token, it can not delete by DeleteToken
 * @tc.type: FUNC
 * @tc.require:AR000GK6T5
 */
HWTEST_F(AccessTokenKitTest, SetRemoteHapTokenInfo007, TestSize.Level1)
{
    ACCESSTOKEN_LOG_INFO(LABEL, "SetRemoteHapTokenInfo007 start.");
    std::string deviceID = udid_;
    AccessTokenKit::DeleteRemoteToken(deviceID, 0x20100000);
    HapTokenInfo baseInfo = {
        .apl = APL_NORMAL,
        .ver = 1,
        .userID = 1,
        .bundleName = "com.ohos.access_token",
        .instIndex = 1,
        .appID = "testtesttesttest",
        .deviceID = udid_,
        .tokenID = 0x20100000,
        .tokenAttr = 0
    };

    PermissionStateFull infoManagerTestState = {
        .grantFlags = {PermissionFlag::PERMISSION_SYSTEM_FIXED},
        .grantStatus = {PermissionState::PERMISSION_DENIED}, // first denied
        .isGeneral = true,
        .permissionName = "ohos.permission.test1",
        .resDeviceID = {"local"}};
    std::vector<PermissionStateFull> permStateList;
    permStateList.emplace_back(infoManagerTestState);

    HapTokenInfoForSync remoteTokenInfo = {
        .baseInfo = baseInfo,
        .permStateList = permStateList
    };

    int ret = AccessTokenKit::SetRemoteHapTokenInfo(deviceID, remoteTokenInfo);
    ASSERT_EQ(ret, RET_SUCCESS);

    // Get local map token ID
    AccessTokenID mapID = AccessTokenKit::AllocLocalTokenID(networkId_, 0x20100000);
    ASSERT_NE(mapID, 0);

    ret = AccessTokenKit::DeleteToken(mapID);
    ASSERT_EQ(ret, RET_FAILED);

    ret = AccessTokenKit::DeleteRemoteToken(deviceID, 0x20100000);
    ASSERT_EQ(ret, RET_SUCCESS);
}

/**
 * @tc.name: SetRemoteHapTokenInfo008
 * @tc.desc: add remote hap token, it can not update by UpdateHapToken
 * @tc.type: FUNC
 * @tc.require:AR000GK6T5
 */
HWTEST_F(AccessTokenKitTest, SetRemoteHapTokenInfo008, TestSize.Level1)
{
    ACCESSTOKEN_LOG_INFO(LABEL, "SetRemoteHapTokenInfo008 start.");
    std::string deviceID = udid_;
    AccessTokenKit::DeleteRemoteToken(deviceID, 0x20100000);
    HapTokenInfo baseInfo = {
        .apl = APL_NORMAL,
        .ver = 1,
        .userID = 1,
        .bundleName = "com.ohos.access_token",
        .instIndex = 1,
        .appID = "testtesttesttest",
        .deviceID = udid_,
        .tokenID = 0x20100000,
        .tokenAttr = 0
    };

    PermissionStateFull infoManagerTestState = {
        .grantFlags = {PermissionFlag::PERMISSION_SYSTEM_FIXED},
        .grantStatus = {PermissionState::PERMISSION_DENIED}, // first denied
        .isGeneral = true,
        .permissionName = "ohos.permission.test1",
        .resDeviceID = {"local"}};
    std::vector<PermissionStateFull> permStateList;
    permStateList.emplace_back(infoManagerTestState);

    HapTokenInfoForSync remoteTokenInfo = {
        .baseInfo = baseInfo,
        .permStateList = permStateList
    };

    int ret = AccessTokenKit::SetRemoteHapTokenInfo(deviceID, remoteTokenInfo);
    ASSERT_EQ(ret, RET_SUCCESS);

    // Get local map token ID
    AccessTokenID mapID = AccessTokenKit::AllocLocalTokenID(networkId_, 0x20100000);
    ASSERT_NE(mapID, 0);

    HapPolicyParams policy;

    ret = AccessTokenKit::UpdateHapToken(mapID, "updateFailed", policy);
    ASSERT_EQ(ret, RET_FAILED);

    ret = AccessTokenKit::DeleteRemoteToken(deviceID, 0x20100000);
    ASSERT_EQ(ret, RET_SUCCESS);
}

/**
 * @tc.name: SetRemoteHapTokenInfo009
 * @tc.desc: add remote hap token, it can not clear by ClearUserGrantedPermissionState
 * @tc.type: FUNC
 * @tc.require:AR000GK6T5
 */
HWTEST_F(AccessTokenKitTest, SetRemoteHapTokenInfo009, TestSize.Level1)
{
    ACCESSTOKEN_LOG_INFO(LABEL, "SetRemoteHapTokenInfo009 start.");
    std::string deviceID = udid_;
    AccessTokenKit::DeleteRemoteToken(deviceID, 0x20100000);
    HapTokenInfo baseInfo = {
        .apl = APL_NORMAL,
        .ver = 1,
        .userID = 1,
        .bundleName = "com.ohos.access_token",
        .instIndex = 1,
        .appID = "testtesttesttest",
        .deviceID = udid_,
        .tokenID = 0x20100000,
        .tokenAttr = 0
    };

    PermissionStateFull infoManagerTestState = {
        .grantFlags = {PermissionFlag::PERMISSION_USER_SET},
        .grantStatus = {PermissionState::PERMISSION_GRANTED},
        .isGeneral = true,
        .permissionName = "ohos.permission.test1",
        .resDeviceID = {"local"}};
    std::vector<PermissionStateFull> permStateList;
    permStateList.emplace_back(infoManagerTestState);

    HapTokenInfoForSync remoteTokenInfo = {
        .baseInfo = baseInfo,
        .permStateList = permStateList
    };

    int ret = AccessTokenKit::SetRemoteHapTokenInfo(deviceID, remoteTokenInfo);
    ASSERT_EQ(ret, RET_SUCCESS);

    // Get local map token ID
    AccessTokenID mapID = AccessTokenKit::AllocLocalTokenID(networkId_, 0x20100000);
    ASSERT_NE(mapID, 0);

    ret = AccessTokenKit::VerifyAccessToken(mapID, "ohos.permission.test1");
    ASSERT_EQ(ret, PermissionState::PERMISSION_GRANTED);

    ret = AccessTokenKit::ClearUserGrantedPermissionState(mapID);
    ASSERT_EQ(ret, RET_SUCCESS);

    ret = AccessTokenKit::VerifyAccessToken(mapID, "ohos.permission.test1");
    ASSERT_EQ(ret, PermissionState::PERMISSION_GRANTED);

    ret = AccessTokenKit::DeleteRemoteToken(deviceID, 0x20100000);
    ASSERT_EQ(ret, RET_SUCCESS);
}

/**
 * @tc.name: SetRemoteHapTokenInfo010
 * @tc.desc: tokenID is not hap token
 * @tc.type: FUNC
 * @tc.require:AR000GK6T5
 */
HWTEST_F(AccessTokenKitTest, SetRemoteHapTokenInfo010, TestSize.Level1)
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
        .grantFlags = {PermissionFlag::PERMISSION_USER_SET},
        .grantStatus = {PermissionState::PERMISSION_GRANTED},
        .isGeneral = true,
        .permissionName = "ohos.permission.test1",
        .resDeviceID = {"local"}};
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
 * @tc.require:AR000GK6TA
 */
HWTEST_F(AccessTokenKitTest, DeleteRemoteDeviceToken001, TestSize.Level1)
{
    ACCESSTOKEN_LOG_INFO(LABEL, "DeleteRemoteDeviceTokens001 start.");
    std::string deviceID = udid_;
    AccessTokenKit::DeleteRemoteToken(deviceID, 0x20100000);
    HapTokenInfo baseInfo = {
        .apl = APL_NORMAL,
        .ver = 1,
        .userID = 1,
        .bundleName = "com.ohos.access_token",
        .instIndex = 1,
        .appID = "testtesttesttest",
        .deviceID = deviceID,
        .tokenID = 0x20100000,
        .tokenAttr = 0
    };

    PermissionStateFull infoManagerTestState = {
        .grantFlags = {PermissionFlag::PERMISSION_USER_SET},
        .grantStatus = {PermissionState::PERMISSION_GRANTED},
        .isGeneral = true,
        .permissionName = "ohos.permission.test1",
        .resDeviceID = {"local"}};
    std::vector<PermissionStateFull> permStateList;
    permStateList.emplace_back(infoManagerTestState);

    HapTokenInfoForSync remoteTokenInfo = {
        .baseInfo = baseInfo,
        .permStateList = permStateList
    };

    int ret = AccessTokenKit::SetRemoteHapTokenInfo(deviceID, remoteTokenInfo);
    ASSERT_EQ(ret, RET_SUCCESS);

    AccessTokenID mapID = AccessTokenKit::AllocLocalTokenID(networkId_, 0x20100000);
    ASSERT_NE(mapID, 0);

    HapTokenInfo info;
    ret = AccessTokenKit::GetHapTokenInfo(mapID, info);
    ASSERT_EQ(ret, RET_SUCCESS);

    ret = AccessTokenKit::DeleteRemoteToken(deviceID, 0x20100000);
    ASSERT_EQ(ret, RET_SUCCESS);

    ret = AccessTokenKit::GetHapTokenInfo(mapID, info);
    ASSERT_NE(ret, RET_SUCCESS);
}

/**
 * @tc.name: DeleteRemoteDeviceToken002
 * @tc.desc: delete exist device mapping tokenId
 * @tc.type: FUNC
 * @tc.require:AR000GK6TA
 */
HWTEST_F(AccessTokenKitTest, DeleteRemoteDeviceToken002, TestSize.Level1)
{
    ACCESSTOKEN_LOG_INFO(LABEL, "DeleteRemoteDeviceTokens001 start.");
    std::string deviceID = udid_;
    AccessTokenKit::DeleteRemoteToken(deviceID, 0x20100000);
    HapTokenInfo baseInfo = {
        .apl = APL_NORMAL,
        .ver = 1,
        .userID = 1,
        .bundleName = "com.ohos.access_token",
        .instIndex = 1,
        .appID = "testtesttesttest",
        .deviceID = deviceID,
        .tokenID = 0x20100000,
        .tokenAttr = 0
    };

    PermissionStateFull infoManagerTestState = {
        .grantFlags = {PermissionFlag::PERMISSION_USER_SET},
        .grantStatus = {PermissionState::PERMISSION_GRANTED},
        .isGeneral = true,
        .permissionName = "ohos.permission.test1",
        .resDeviceID = {"local"}};
    std::vector<PermissionStateFull> permStateList;
    permStateList.emplace_back(infoManagerTestState);

    HapTokenInfoForSync remoteTokenInfo = {
        .baseInfo = baseInfo,
        .permStateList = permStateList
    };

    int ret = AccessTokenKit::SetRemoteHapTokenInfo(deviceID, remoteTokenInfo);
    ASSERT_EQ(ret, RET_SUCCESS);

    AccessTokenID mapID = AccessTokenKit::AllocLocalTokenID(networkId_, 0x20100000);
    ASSERT_NE(mapID, 0);

    HapTokenInfo info;
    ret = AccessTokenKit::GetHapTokenInfo(mapID, info);
    ASSERT_EQ(ret, RET_SUCCESS);

    ret = AccessTokenKit::DeleteRemoteToken(deviceID, 0);
    ASSERT_NE(ret, RET_SUCCESS);

    // deviceID is wrong
    std::string wrongStr(10241, 'x');
    deviceID = wrongStr;
    ret = AccessTokenKit::DeleteRemoteToken(deviceID, 0x20100000);
    ASSERT_NE(ret, RET_SUCCESS);
}

/**
 * @tc.name: DeleteRemoteDeviceToken003
 * @tc.desc: delete exist device mapping tokenId
 * @tc.type: FUNC
 * @tc.require:AR000GK6TA
 */
HWTEST_F(AccessTokenKitTest, DeleteRemoteDeviceToken003, TestSize.Level1)
{
    ACCESSTOKEN_LOG_INFO(LABEL, "DeleteRemoteDeviceToken003 start.");
    std::string deviceID = udid_;
    AccessTokenKit::DeleteRemoteToken(deviceID, 0x20100000);

    int ret = AccessTokenKit::DeleteRemoteToken(deviceID, 0x20100000);
    ASSERT_NE(ret, RET_SUCCESS);
}

/**
 * @tc.name: DeleteRemoteDeviceTokens001
 * @tc.desc: delete all mapping tokens of exist device
 * @tc.type: FUNC
 * @tc.require:AR000GK6TA
 */
HWTEST_F(AccessTokenKitTest, DeleteRemoteDeviceTokens001, TestSize.Level1)
{
    ACCESSTOKEN_LOG_INFO(LABEL, "DeleteRemoteDeviceTokens001 start.");
    std::string deviceID = udid_;
    AccessTokenKit::DeleteRemoteToken(deviceID, 0x20100000);
    AccessTokenKit::DeleteRemoteToken(deviceID, 0x20100001);
    HapTokenInfo baseInfo = {
        .apl = APL_NORMAL,
        .ver = 1,
        .userID = 1,
        .bundleName = "com.ohos.access_token",
        .instIndex = 1,
        .appID = "testtesttesttest",
        .deviceID = udid_,
        .tokenID = 0x20100000,
        .tokenAttr = 0
    };

    PermissionStateFull infoManagerTestState = {
        .grantFlags = {PermissionFlag::PERMISSION_USER_SET},
        .grantStatus = {PermissionState::PERMISSION_GRANTED},
        .isGeneral = true,
        .permissionName = "ohos.permission.test1",
        .resDeviceID = {"local"}};
    std::vector<PermissionStateFull> permStateList;
    permStateList.emplace_back(infoManagerTestState);

    HapTokenInfoForSync remoteTokenInfo = {
        .baseInfo = baseInfo,
        .permStateList = permStateList
    };

    int ret = AccessTokenKit::SetRemoteHapTokenInfo(deviceID, remoteTokenInfo);
    ASSERT_EQ(ret, RET_SUCCESS);

    HapTokenInfoForSync remoteTokenInfo1 = remoteTokenInfo;
    remoteTokenInfo1.baseInfo.tokenID = 0x20100001;
    remoteTokenInfo1.baseInfo.bundleName = "com.ohos.access_token1";
    ret = AccessTokenKit::SetRemoteHapTokenInfo(deviceID, remoteTokenInfo1);
    ASSERT_EQ(ret, RET_SUCCESS);

    AccessTokenID mapID = AccessTokenKit::AllocLocalTokenID(networkId_, 0x20100000);
    ASSERT_NE(mapID, 0);
    AccessTokenID mapID1 = AccessTokenKit::AllocLocalTokenID(networkId_, 0x20100001);
    ASSERT_NE(mapID1, 0);

    ret = AccessTokenKit::DeleteRemoteDeviceTokens(deviceID);
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
 * @tc.require:AR000GK6TA
 */
HWTEST_F(AccessTokenKitTest, DeleteRemoteDeviceTokens002, TestSize.Level1)
{
    ACCESSTOKEN_LOG_INFO(LABEL, "DeleteRemoteDeviceTokens002 start.");
    std::string deviceID = udid_;
    AccessTokenKit::DeleteRemoteToken(deviceID, 0x20100000);
    AccessTokenKit::DeleteRemoteToken(deviceID, 0x20100001);
    HapTokenInfo baseInfo = {
        .apl = APL_NORMAL,
        .ver = 1,
        .userID = 1,
        .bundleName = "com.ohos.access_token",
        .instIndex = 1,
        .appID = "testtesttesttest",
        .deviceID = udid_,
        .tokenID = 0x20100000,
        .tokenAttr = 0
    };

    PermissionStateFull infoManagerTestState = {
        .grantFlags = {PermissionFlag::PERMISSION_USER_SET},
        .grantStatus = {PermissionState::PERMISSION_GRANTED},
        .isGeneral = true,
        .permissionName = "ohos.permission.test1",
        .resDeviceID = {"local"}};
    std::vector<PermissionStateFull> permStateList;
    permStateList.emplace_back(infoManagerTestState);

    HapTokenInfoForSync remoteTokenInfo = {
        .baseInfo = baseInfo,
        .permStateList = permStateList
    };

    int ret = AccessTokenKit::SetRemoteHapTokenInfo(deviceID, remoteTokenInfo);
    ASSERT_EQ(ret, RET_SUCCESS);

    HapTokenInfoForSync remoteTokenInfo1 = remoteTokenInfo;
    remoteTokenInfo1.baseInfo.tokenID = 0x20100001;
    remoteTokenInfo1.baseInfo.bundleName = "com.ohos.access_token1";
    ret = AccessTokenKit::SetRemoteHapTokenInfo(deviceID, remoteTokenInfo1);
    ASSERT_EQ(ret, RET_SUCCESS);

    AccessTokenID mapID = AccessTokenKit::AllocLocalTokenID(networkId_, 0x20100000);
    ASSERT_NE(mapID, 0);
    AccessTokenID mapID1 = AccessTokenKit::AllocLocalTokenID(networkId_, 0x20100001);
    ASSERT_NE(mapID1, 0);

    ret = AccessTokenKit::DeleteRemoteDeviceTokens("1111111");
    ASSERT_NE(ret, RET_SUCCESS);

    AccessTokenKit::DeleteRemoteToken(deviceID, 0x20100000);
    AccessTokenKit::DeleteRemoteToken(deviceID, 0x20100001);
}

/**
 * @tc.name: GetHapTokenInfoFromRemote001
 * @tc.desc: get normal local tokenInfo
 * @tc.type: FUNC
 * @tc.require:AR000GK6TA
 */
HWTEST_F(AccessTokenKitTest, GetHapTokenInfoFromRemote001, TestSize.Level1)
{
    ACCESSTOKEN_LOG_INFO(LABEL, "GetHapTokenInfoFromRemote001 start.");
    AccessTokenIDEx tokenIdEx = {0};
    tokenIdEx = AccessTokenKit::AllocHapToken(g_infoManagerTestInfoParms, g_infoManagerTestPolicyPrams);
    AccessTokenID localTokenID = tokenIdEx.tokenIdExStruct.tokenID;

    HapTokenInfoForSync infoSync;
    int ret = AccessTokenKit::GetHapTokenInfoFromRemote(localTokenID, infoSync);
    ASSERT_EQ(ret, RET_SUCCESS);
    ASSERT_EQ(infoSync.baseInfo.apl, g_infoManagerTestPolicyPrams.apl);
    ASSERT_EQ(infoSync.permStateList.size(), 2);
    ASSERT_EQ(infoSync.permStateList[1].grantFlags.size(), 2);

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
 * @tc.require:AR000GK6TA
 */
HWTEST_F(AccessTokenKitTest, GetHapTokenInfoFromRemote002, TestSize.Level1)
{
    ACCESSTOKEN_LOG_INFO(LABEL, "GetHapTokenInfoFromRemote002 start.");
    std::string deviceID = udid_;
    AccessTokenKit::DeleteRemoteToken(deviceID, 0x20100000);
    HapTokenInfo baseInfo = {
        .apl = APL_NORMAL,
        .ver = 1,
        .userID = 1,
        .bundleName = "com.ohos.access_token",
        .instIndex = 1,
        .appID = "testtesttesttest",
        .deviceID = udid_,
        .tokenID = 0x20100000,
        .tokenAttr = 0
    };

    PermissionStateFull infoManagerTestState = {
        .grantFlags = {PermissionFlag::PERMISSION_USER_SET},
        .grantStatus = {PermissionState::PERMISSION_GRANTED},
        .isGeneral = true,
        .permissionName = "ohos.permission.test1",
        .resDeviceID = {"local"}};
    std::vector<PermissionStateFull> permStateList;
    permStateList.emplace_back(infoManagerTestState);

    HapTokenInfoForSync remoteTokenInfo = {
        .baseInfo = baseInfo,
        .permStateList = permStateList
    };

    int ret = AccessTokenKit::SetRemoteHapTokenInfo(deviceID, remoteTokenInfo);
    ASSERT_EQ(ret, RET_SUCCESS);

    AccessTokenID mapID = AccessTokenKit::AllocLocalTokenID(networkId_, 0x20100000);
    ASSERT_NE(mapID, 0);

    HapTokenInfoForSync infoSync;
    ret = AccessTokenKit::GetHapTokenInfoFromRemote(mapID, infoSync);
    ASSERT_NE(ret, RET_SUCCESS);

    AccessTokenKit::DeleteRemoteToken(deviceID, 0x20100000);
}

/**
 * @tc.name: GetHapTokenInfoFromRemote003
 * @tc.desc: get wrong tokenInfo
 * @tc.type: FUNC
 * @tc.require:AR000GK6TA
 */
HWTEST_F(AccessTokenKitTest, GetHapTokenInfoFromRemote003, TestSize.Level1)
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
 * @tc.require:AR000GK6T5
 */
HWTEST_F(AccessTokenKitTest, AllocLocalTokenID001, TestSize.Level1)
{
    ACCESSTOKEN_LOG_INFO(LABEL, "AllocLocalTokenID001 start.");
    std::string deviceID = udid_;
    AccessTokenKit::DeleteRemoteToken(deviceID, 0x20100000);
    HapTokenInfo baseInfo = {
        .apl = APL_NORMAL,
        .ver = 1,
        .userID = 1,
        .bundleName = "com.ohos.access_token",
        .instIndex = 1,
        .appID = "testtesttesttest",
        .deviceID = udid_,
        .tokenID = 0x20100000,
        .tokenAttr = 0
    };

    PermissionStateFull infoManagerTestState = {
        .grantFlags = {PermissionFlag::PERMISSION_USER_SET},
        .grantStatus = {PermissionState::PERMISSION_GRANTED},
        .isGeneral = true,
        .permissionName = "ohos.permission.test1",
        .resDeviceID = {"local"}};
    std::vector<PermissionStateFull> permStateList;
    permStateList.emplace_back(infoManagerTestState);

    HapTokenInfoForSync remoteTokenInfo = {
        .baseInfo = baseInfo,
        .permStateList = permStateList
    };

    int ret = AccessTokenKit::SetRemoteHapTokenInfo(deviceID, remoteTokenInfo);
    ASSERT_EQ(ret, RET_SUCCESS);

    AccessTokenID mapID = AccessTokenKit::AllocLocalTokenID(networkId_, 0x20100000);
    ASSERT_NE(mapID, 0);
}

/**
 * @tc.name: GetAllNativeTokenInfo001
 * @tc.desc: get all native token with dcaps
 * @tc.type: FUNC
 * @tc.require:AR000GK6T6
 */
HWTEST_F(AccessTokenKitTest, GetAllNativeTokenInfo001, TestSize.Level1)
{
    ACCESSTOKEN_LOG_INFO(LABEL, "GetAllNativeTokenInfo001 start.");

    std::vector<NativeTokenInfoForSync> nativeTokenInfosRes;
    int ret = AccessTokenKit::GetAllNativeTokenInfo(nativeTokenInfosRes);
    ASSERT_EQ(ret, RET_SUCCESS);
}

/**
 * @tc.name: SetRemoteNativeTokenInfo001
 * @tc.desc: set already mapping tokenInfo
 * @tc.type: FUNC
 * @tc.require:AR000GK6T6
 */
HWTEST_F(AccessTokenKitTest, SetRemoteNativeTokenInfo001, TestSize.Level1)
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
#endif
