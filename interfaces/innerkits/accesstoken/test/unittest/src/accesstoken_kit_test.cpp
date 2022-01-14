/*
 * Copyright (c) 2021 Huawei Device Co., Ltd.
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

using namespace testing::ext;
using namespace OHOS::Security::AccessToken;

namespace {
static PermissionStateFull g_grantPermissionReq = {
    .permissionName = "ohos.permission.GRANT_SENSITIVE_PERMISSIONS",
    .isGeneral = true,
    .resDeviceID = {"device"},
    .grantStatus = {PermissionState::PERMISSION_GRANTED},
    .grantFlags = {PermissionFlag::PERMISSION_SYSTEM_FIXED}
};
static PermissionStateFull g_revokePermissionReq = {
    .permissionName = "ohos.permission.REVOKE_SENSITIVE_PERMISSIONS",
    .isGeneral = true,
    .resDeviceID = {"device"},
    .grantStatus = {PermissionState::PERMISSION_GRANTED},
    .grantFlags = {PermissionFlag::PERMISSION_SYSTEM_FIXED}
};

static PermissionDef g_infoManagerTestPermDef1 = {
    .permissionName = "ohos.permission.test1",
    .bundleName = "accesstoken_test",
    .grantMode = 1,
    .label = "label",
    .labelId = 1,
    .description = "open the door",
    .descriptionId = 1,
    .availableLevel = APL_NORMAL
};

static PermissionDef g_infoManagerTestPermDef2 = {
    .permissionName = "ohos.permission.test2",
    .bundleName = "accesstoken_test",
    .grantMode = 1,
    .label = "label",
    .labelId = 1,
    .description = "break the door",
    .descriptionId = 1,
    .availableLevel = APL_NORMAL
};

static PermissionStateFull g_infoManagerTestState1 = {
    .grantFlags = {1},
    .grantStatus = {PermissionState::PERMISSION_GRANTED},
    .isGeneral = true,
    .permissionName = "ohos.permission.test1",
    .resDeviceID = {"local"}
};

static PermissionStateFull g_infoManagerTestState2 = {
    .permissionName = "ohos.permission.test2",
    .isGeneral = false,
    .grantFlags = {1, 2},
    .grantStatus = {PermissionState::PERMISSION_GRANTED, PermissionState::PERMISSION_GRANTED},
    .resDeviceID = {"device 1", "device 2"}
};

static HapInfoParams g_infoManagerTestInfoParms = {
    .bundleName = "accesstoken_test",
    .userID = 1,
    .instIndex = 0,
    .appIDDesc = "testtesttesttest"
};

static HapPolicyParams g_infoManagerTestPolicyPrams = {
    .apl = APL_NORMAL,
    .domain = "test.domain",
    .permList = {g_infoManagerTestPermDef1, g_infoManagerTestPermDef2},
    .permStateList = {g_infoManagerTestState1, g_infoManagerTestState2}
};

static HapInfoParams g_infoManagerTestInfoParms_bak = {
    .bundleName = "accesstoken_test",
    .userID = 1,
    .instIndex = 0,
    .appIDDesc = "testtesttesttest"
};

static HapPolicyParams g_infoManagerTestPolicyPrams_bak = {
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
    g_infoManagerTestInfoParms = g_infoManagerTestInfoParms_bak;
    g_infoManagerTestPolicyPrams = g_infoManagerTestPolicyPrams_bak;
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
    policy.permList.emplace_back(permissionDefAlpha);
    policy.permList.emplace_back(permissionDefBeta);

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
        .grantFlags = {PermissionFlag::PERMISSION_USER_SET}
    };
    policy.permStateList.emplace_back(permStatAlpha);
    policy.permStateList.emplace_back(permStatBeta);
    policy.permStateList.emplace_back(g_grantPermissionReq);
    policy.permStateList.emplace_back(g_revokePermissionReq);

    AccessTokenKit::AllocHapToken(info, policy);
    AccessTokenID tokenID = AccessTokenKit::GetHapTokenID(g_infoManagerTestInfoParms.userID,
                                                          g_infoManagerTestInfoParms.bundleName,
                                                          g_infoManagerTestInfoParms.instIndex);
    AccessTokenKit::DeleteToken(tokenID);
}

void AccessTokenKitTest::TearDown()
{
    AccessTokenID tokenID = GetAccessTokenID(TEST_USER_ID, TEST_BUNDLE_NAME, 0);
    AccessTokenKit::DeleteToken(tokenID);
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
    ASSERT_EQ(2, permDefList.size());
}

/**
 * @tc.name: GetDefPermissions002
 * @tc.desc: Get permission definition info list after clear permission definition list
 * @tc.type: FUNC
 * @tc.require:AR000GM5FC
 */
HWTEST_F(AccessTokenKitTest, GetDefPermissions002, TestSize.Level1)
{
    HapPolicyParams TestPolicyPrams = g_infoManagerTestPolicyPrams;
    TestPolicyPrams.permList.clear();
    AccessTokenKit::AllocHapToken(g_infoManagerTestInfoParms, TestPolicyPrams);

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
        ret = ret = AccessTokenKit::GetDefPermissions(tokenID, permDefList);
        ASSERT_EQ(RET_SUCCESS, ret);
        ASSERT_EQ(2, permDefList.size());
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
    ASSERT_EQ(1, permStatList.size());
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
        ret = ret = AccessTokenKit::GetReqPermissions(tokenID, permStatList, false);
        ASSERT_EQ(RET_SUCCESS, ret);
        ASSERT_EQ(1, permStatList.size());
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
    ASSERT_EQ(DEFAULT_PERMISSION_FLAGS, ret);

    ret = AccessTokenKit::GetPermissionFlag(tokenID, "");
    ASSERT_EQ(DEFAULT_PERMISSION_FLAGS, ret);

    std::string invalidPerm(INVALID_PERMNAME_LEN, 'a');
    ret = AccessTokenKit::GetPermissionFlag(tokenID, invalidPerm);
    ASSERT_EQ(DEFAULT_PERMISSION_FLAGS, ret);

    ret = AccessTokenKit::GetPermissionFlag(TEST_TOKENID_INVALID, TEST_PERMISSION_NAME_ALPHA);
    ASSERT_EQ(DEFAULT_PERMISSION_FLAGS, ret);

    AccessTokenKit::DeleteToken(tokenID);

    ret = AccessTokenKit::GetPermissionFlag(tokenID, TEST_PERMISSION_NAME_ALPHA);
    ASSERT_EQ(DEFAULT_PERMISSION_FLAGS, ret);
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

        ret = ret = AccessTokenKit::GetPermissionFlag(tokenID, TEST_PERMISSION_NAME_ALPHA);
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

    DeleteTestToken();
    vector<unsigned int> obj;
    for (int i = 0; i < CYCLE_TIMES; i++) {
        tokenIdEx = AccessTokenKit::AllocHapToken(g_infoManagerTestInfoParms, g_infoManagerTestPolicyPrams);
        tokenID = GetAccessTokenID(g_infoManagerTestInfoParms.userID,
                                   g_infoManagerTestInfoParms.bundleName,
                                   g_infoManagerTestInfoParms.instIndex);

        exist = ExistInVector(obj, tokenID);
        ASSERT_EQ(false, exist);
        obj.push_back(tokenID);

        ret = AccessTokenKit::DeleteToken(tokenID);
        ASSERT_EQ(RET_SUCCESS, ret);
    }
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
    g_infoManagerTestInfoParms.bundleName = "test_UpdateHapToken005";
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
        ASSERT_EQ(false, exist);
        obj.push_back(tokenID);
        infoManagerTestInfo.userID++;
    }

    infoManagerTestInfo.instIndex = 1;
    g_infoManagerTestPolicyPrams.apl = APL_SYSTEM_BASIC;
    for (int i = 0; i < obj.size(); i++) {
        ret = AccessTokenKit::UpdateHapToken(obj[i], appIDDesc, g_infoManagerTestPolicyPrams);
        ASSERT_EQ(RET_SUCCESS, ret);
    }
    g_infoManagerTestPolicyPrams.apl = APL_NORMAL;

    for (int i = 0; i < obj.size(); i++) {
        ret = AccessTokenKit::DeleteToken(obj[i]);
        ASSERT_EQ(RET_SUCCESS, ret);
    }
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
    /* check permission define befor update */
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
    /* check permission define befor update */
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
