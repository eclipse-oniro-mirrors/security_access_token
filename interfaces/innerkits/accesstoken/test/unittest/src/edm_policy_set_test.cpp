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

#include "edm_policy_set_test.h"
#include <thread>

#include "accesstoken_kit.h"
#include "accesstoken_log.h"
#include "access_token_error.h"
#include "permission_map.h"
#include "perm_setproc.h"
#include "token_setproc.h"
#include "tokenid_kit.h"

using namespace testing::ext;
using namespace OHOS::Security::AccessToken;

namespace {
static const uint32_t DEFAULT_ACCOUNT_ID = 100;
static const uint32_t MOCK_USER_ID_10001 = 10001;
static const uint32_t MOCK_USER_ID_10002 = 10002;
static const uint32_t MOCK_USER_ID_10003 = 10003;
const std::string MANAGE_HAP_TOKEN_ID_PERMISSION = "ohos.permission.MANAGE_HAP_TOKENID";
const std::string INTERNET = "ohos.permission.INTERNET";
static const std::string GET_NETWORK_STATS = "ohos.permission.GET_NETWORK_STATS";
static const std::string LOCATION = "ohos.permission.LOCATION";
static const std::string GET_SENSITIVE_PERMISSIONS = "ohos.permission.GET_SENSITIVE_PERMISSIONS";
static const std::string REVOKE_SENSITIVE_PERMISSIONS = "ohos.permission.REVOKE_SENSITIVE_PERMISSIONS";

PermissionStateFull g_infoManagerInternetState = {
    .permissionName = INTERNET,
    .isGeneral = true,
    .resDeviceID = {"local2"},
    .grantStatus = {PermissionState::PERMISSION_GRANTED},
    .grantFlags = {0}
};

PermissionStateFull g_infoManagerNetWorkState = {
    .permissionName = GET_NETWORK_STATS,
    .isGeneral = true,
    .resDeviceID = {"local2"},
    .grantStatus = {PermissionState::PERMISSION_GRANTED},
    .grantFlags = {0}
};

PermissionStateFull g_infoManagerManageNetState = {
    .permissionName = LOCATION,
    .isGeneral = true,
    .resDeviceID = {"local2"},
    .grantStatus = {PermissionState::PERMISSION_DENIED},
    .grantFlags = {0}
};

// Permission set
HapInfoParams g_testHapInfoParams = {
    .userID = 0,
    .bundleName = "testName",
    .instIndex = 0,
    .appIDDesc = "test2",
    .apiVersion = 11 // api version is 11
};

HapPolicyParams g_testPolicyParams = {
    .apl = APL_SYSTEM_CORE,
    .domain = "test.domain2",
    .permStateList = {
        g_infoManagerInternetState,
        g_infoManagerNetWorkState,
        g_infoManagerManageNetState,
    }
};

uint64_t g_selfShellTokenId;

PermissionStateFull g_tddPermReq = {
    .permissionName = MANAGE_HAP_TOKEN_ID_PERMISSION,
    .isGeneral = true,
    .resDeviceID = {"device3"},
    .grantStatus = {PermissionState::PERMISSION_GRANTED},
    .grantFlags = {PermissionFlag::PERMISSION_SYSTEM_FIXED}
};

PermissionStateFull g_tddPermGet = {
    .permissionName = "ohos.permission.GET_SENSITIVE_PERMISSIONS",
    .isGeneral = true,
    .resDeviceID = {"device3"},
    .grantStatus = {PermissionState::PERMISSION_GRANTED},
    .grantFlags = {PermissionFlag::PERMISSION_SYSTEM_FIXED}
};

PermissionStateFull g_tddPermRevoke = {
    .permissionName = "ohos.permission.REVOKE_SENSITIVE_PERMISSIONS",
    .isGeneral = true,
    .resDeviceID = {"device3"},
    .grantStatus = {PermissionState::PERMISSION_GRANTED},
    .grantFlags = {PermissionFlag::PERMISSION_SYSTEM_FIXED}
};

HapInfoParams g_tddHapInfoParams = {
    .userID = 1,
    .bundleName = "EdmPolicySetTest",
    .instIndex = 0,
    .appIDDesc = "test2",
    .apiVersion = 11, // api version is 11
    .isSystemApp = true
};

HapPolicyParams g_tddPolicyParams = {
    .apl = APL_SYSTEM_CORE,
    .domain = "test.domain2",
    .permStateList = {g_tddPermReq, g_tddPermGet, g_tddPermRevoke}
};

static constexpr OHOS::HiviewDFX::HiLogLabel LABEL = {LOG_CORE, SECURITY_DOMAIN_ACCESSTOKEN, "EdmPolicySetTest"};
}

void EdmPolicySetTest::TearDownTestCase()
{
    AccessTokenID tokenId = AccessTokenKit::GetHapTokenID(g_tddHapInfoParams.userID,
        g_tddHapInfoParams.bundleName,
        g_tddHapInfoParams.instIndex);
    AccessTokenKit::DeleteToken(tokenId);
}

void EdmPolicySetTest::SetUp()
{
    ACCESSTOKEN_LOG_INFO(LABEL, "SetUp ok.");
}

void EdmPolicySetTest::TearDown()
{
}

void EdmPolicySetTest::SetUpTestCase()
{
    g_selfShellTokenId = GetSelfTokenID();
    AccessTokenIDEx tokenIdEx = AccessTokenKit::AllocHapToken(g_tddHapInfoParams, g_tddPolicyParams);
    SetSelfTokenID(tokenIdEx.tokenIDEx);
    ACCESSTOKEN_LOG_INFO(LABEL, "SetUpTestCase ok.");
}

/**
 * @tc.name: InitUserPolicy002
 * @tc.desc: InitUserPolicy failed invalid userList size.
 * @tc.type: FUNC
 * @tc.require:Issue Number
 */
HWTEST_F(EdmPolicySetTest, InitUserPolicy002, TestSize.Level1)
{
    const int32_t invalidSize = 1025; // 1025 is invalid size.
    std::vector<UserState> userList(invalidSize);
    std::vector<std::string> permList = { "ohos.permission.INTERNET" };
    int32_t ret = AccessTokenKit::InitUserPolicy(userList, permList);
    EXPECT_EQ(ret, AccessTokenError::ERR_PARAM_INVALID);
}

/**
 * @tc.name: InitUserPolicy003
 * @tc.desc: InitUserPolicy failed empty userList.
 * @tc.type: FUNC
 * @tc.require:Issue Number
 */
HWTEST_F(EdmPolicySetTest, InitUserPolicy003, TestSize.Level1)
{
    std::vector<UserState> userListEmtpy;
    std::vector<std::string> permList = { "ohos.permission.INTERNET" };
    int32_t ret = AccessTokenKit::InitUserPolicy(userListEmtpy, permList);
    EXPECT_EQ(ret, AccessTokenError::ERR_PARAM_INVALID);
}

/**
 * @tc.name: InitUserPolicy004
 * @tc.desc: InitUserPolicy failed empty userList.
 * @tc.type: FUNC
 * @tc.require:Issue Number
 */
HWTEST_F(EdmPolicySetTest, InitUserPolicy004, TestSize.Level1)
{
    UserState user = {.userId = DEFAULT_ACCOUNT_ID, .isActive = true};
    const int32_t invalidSize = 1025; // 1025 is invalid size.
    std::vector<UserState> userList = { user };
    std::vector<std::string> permList(invalidSize, "abc");
    int32_t ret = AccessTokenKit::InitUserPolicy(userList, permList);
    EXPECT_EQ(ret, AccessTokenError::ERR_PARAM_INVALID);
}

/**
 * @tc.name: InitUserPolicy005
 * @tc.desc: InitUserPolicy failed empty permList.
 * @tc.type: FUNC
 * @tc.require:Issue Number
 */
HWTEST_F(EdmPolicySetTest, InitUserPolicy005, TestSize.Level1)
{
    UserState user = {.userId = DEFAULT_ACCOUNT_ID, .isActive = true};
    std::vector<UserState> userList = { user };
    std::vector<std::string> permListEmpty;
    int32_t ret = AccessTokenKit::InitUserPolicy(userList, permListEmpty);
    EXPECT_EQ(ret, AccessTokenError::ERR_PARAM_INVALID);
}

/**
 * @tc.name: UpdateUserPolicy001
 * @tc.desc: UpdateUserPolicy failed with
 * policy uninitialized and ClearUserPolicy successfully with policy uninitialized.
 * @tc.type: FUNC
 * @tc.require:Issue Number
 */
HWTEST_F(EdmPolicySetTest, UpdateUserPolicy001, TestSize.Level1)
{
    uint32_t tokenId = AccessTokenKit::GetNativeTokenId("foundation");
    EXPECT_EQ(0, SetSelfTokenID(tokenId));
    GTEST_LOG_(INFO) << "permissionSet OK ";

    UserState user = {.userId = DEFAULT_ACCOUNT_ID, .isActive = true};
    const std::vector<UserState> userList = { user };
    int32_t res = AccessTokenKit::UpdateUserPolicy(userList);
    EXPECT_EQ(res, AccessTokenError::ERR_USER_POLICY_NOT_INITIALIZED);

    res = AccessTokenKit::ClearUserPolicy();
    EXPECT_EQ(res, RET_SUCCESS);
}

/**
 * @tc.name: InitUserPolicy008
 * @tc.desc: Check permission status in the heap.
 * @tc.type: FUNC
 * @tc.require:Issue Number
 */
HWTEST_F(EdmPolicySetTest, InitUserPolicy008, TestSize.Level1)
{
    uint32_t tokenId = AccessTokenKit::GetNativeTokenId("foundation");
    EXPECT_EQ(0, SetSelfTokenID(tokenId));
    GTEST_LOG_(INFO) << "permissionSet OK ";

    g_testHapInfoParams.userID = MOCK_USER_ID_10001;
    AccessTokenIDEx fullIdUser1;
    EXPECT_EQ(RET_SUCCESS, AccessTokenKit::InitHapToken(g_testHapInfoParams, g_testPolicyParams, fullIdUser1));
    g_testHapInfoParams.userID = MOCK_USER_ID_10002;
    AccessTokenIDEx fullIdUser2;
    EXPECT_EQ(RET_SUCCESS, AccessTokenKit::InitHapToken(g_testHapInfoParams, g_testPolicyParams, fullIdUser2));

    UserState user0 = {.userId = -1, .isActive = true};
    UserState user1 = {.userId = MOCK_USER_ID_10001, .isActive = true};
    UserState user2 = {.userId = MOCK_USER_ID_10002, .isActive = false};

    std::vector<UserState> userList = { user0, user1, user2};
    std::vector<std::string> permList = { INTERNET, GET_NETWORK_STATS, LOCATION };
    int32_t res = AccessTokenKit::InitUserPolicy(userList, permList);
    EXPECT_EQ(res, 0);

    EXPECT_EQ(AccessTokenKit::VerifyAccessToken(fullIdUser1.tokenIdExStruct.tokenID, INTERNET), PERMISSION_GRANTED);
    EXPECT_EQ(AccessTokenKit::VerifyAccessToken(fullIdUser2.tokenIdExStruct.tokenID, INTERNET), PERMISSION_DENIED);

    std::vector<PermissionStateFull> permStatList;
    res = AccessTokenKit::GetReqPermissions(fullIdUser2.tokenIdExStruct.tokenID, permStatList, true);
    EXPECT_EQ(RET_SUCCESS, res);
    EXPECT_EQ(static_cast<uint32_t>(2), permStatList.size());
    EXPECT_EQ(INTERNET, permStatList[0].permissionName);
    EXPECT_EQ(PERMISSION_GRANTED, permStatList[0].grantStatus[0]);

    EXPECT_EQ(RET_SUCCESS, AccessTokenKit::DeleteToken(fullIdUser1.tokenIdExStruct.tokenID));
    EXPECT_EQ(RET_SUCCESS, AccessTokenKit::DeleteToken(fullIdUser2.tokenIdExStruct.tokenID));

    res = AccessTokenKit::ClearUserPolicy();
    EXPECT_EQ(res, 0);
}

/**
 * @tc.name: InitUserPolicy007
 * @tc.desc: InitUserPolicy and the stock permission status is refreshed according to the policy.
 * @tc.type: FUNC
 * @tc.require:Issue Number
 */
HWTEST_F(EdmPolicySetTest, InitUserPolicy007, TestSize.Level1)
{
    uint32_t tokenId = AccessTokenKit::GetNativeTokenId("foundation");
    EXPECT_EQ(0, SetSelfTokenID(tokenId));
    GTEST_LOG_(INFO) << "permissionSet OK ";

    g_testHapInfoParams.userID = MOCK_USER_ID_10001;
    AccessTokenIDEx fullIdUser1;
    EXPECT_EQ(RET_SUCCESS, AccessTokenKit::InitHapToken(g_testHapInfoParams, g_testPolicyParams, fullIdUser1));
    g_testHapInfoParams.userID = MOCK_USER_ID_10002;
    AccessTokenIDEx fullIdUser2;
    EXPECT_EQ(RET_SUCCESS, AccessTokenKit::InitHapToken(g_testHapInfoParams, g_testPolicyParams, fullIdUser2));
    g_testHapInfoParams.userID = MOCK_USER_ID_10003;
    AccessTokenIDEx fullIdUser3;
    EXPECT_EQ(RET_SUCCESS, AccessTokenKit::InitHapToken(g_testHapInfoParams, g_testPolicyParams, fullIdUser3));

    EXPECT_EQ(AccessTokenKit::VerifyAccessToken(fullIdUser1.tokenIdExStruct.tokenID, LOCATION),
        PERMISSION_DENIED);

    UserState user0 = {.userId = -1, .isActive = true};
    UserState user1 = {.userId = MOCK_USER_ID_10001, .isActive = true};
    UserState user2 = {.userId = MOCK_USER_ID_10002, .isActive = false};
    UserState user3 = {.userId = MOCK_USER_ID_10003, .isActive = false};

    std::vector<UserState> userList = { user0, user1, user2, user3 };
    std::vector<std::string> permList = { INTERNET, GET_NETWORK_STATS, LOCATION };
    int32_t ret = AccessTokenKit::InitUserPolicy(userList, permList);
    EXPECT_EQ(ret, 0);

    EXPECT_EQ(AccessTokenKit::VerifyAccessToken(fullIdUser1.tokenIdExStruct.tokenID, INTERNET), PERMISSION_GRANTED);
    EXPECT_EQ(AccessTokenKit::VerifyAccessToken(fullIdUser2.tokenIdExStruct.tokenID, INTERNET), PERMISSION_DENIED);
    EXPECT_EQ(AccessTokenKit::VerifyAccessToken(fullIdUser3.tokenIdExStruct.tokenID, INTERNET), PERMISSION_DENIED);
    EXPECT_EQ(AccessTokenKit::VerifyAccessToken(fullIdUser1.tokenIdExStruct.tokenID, LOCATION),
        PERMISSION_DENIED);
    EXPECT_EQ(AccessTokenKit::VerifyAccessToken(fullIdUser2.tokenIdExStruct.tokenID, LOCATION),
        PERMISSION_DENIED);
    EXPECT_EQ(AccessTokenKit::VerifyAccessToken(fullIdUser3.tokenIdExStruct.tokenID, LOCATION),
        PERMISSION_DENIED);

    EXPECT_EQ(RET_SUCCESS, AccessTokenKit::DeleteToken(fullIdUser1.tokenIdExStruct.tokenID));
    EXPECT_EQ(RET_SUCCESS, AccessTokenKit::DeleteToken(fullIdUser2.tokenIdExStruct.tokenID));
    EXPECT_EQ(RET_SUCCESS, AccessTokenKit::DeleteToken(fullIdUser3.tokenIdExStruct.tokenID));

    int32_t res = AccessTokenKit::ClearUserPolicy();
    EXPECT_EQ(res, 0);
}

/**
 * @tc.name: UpdateUserPolicy003
 * @tc.desc: UpdateUserPolicy with invalid userList.
 * @tc.type: FUNC
 * @tc.require:Issue Number
 */
HWTEST_F(EdmPolicySetTest, UpdateUserPolicy003, TestSize.Level1)
{
    const int32_t invalidSize = 1025; // 1025 is invalid size.
    std::vector<UserState> userList(invalidSize);
    int32_t ret = AccessTokenKit::UpdateUserPolicy(userList);
    EXPECT_EQ(ret, AccessTokenError::ERR_PARAM_INVALID);

    std::vector<UserState> userListEmpty;
    ret = AccessTokenKit::UpdateUserPolicy(userListEmpty);
    EXPECT_EQ(ret, AccessTokenError::ERR_PARAM_INVALID);
}

/**
 * @tc.name: UpdateUserPolicy004
 * @tc.desc: UpdateUserPolicy and the stock permission status is refreshed according to the policy.
 * @tc.type: FUNC
 * @tc.require:Issue Number
 */
HWTEST_F(EdmPolicySetTest, UpdateUserPolicy004, TestSize.Level1)
{
    g_testHapInfoParams.userID = MOCK_USER_ID_10001;
    AccessTokenIDEx fullIdUser1;
    EXPECT_EQ(RET_SUCCESS, AccessTokenKit::InitHapToken(g_testHapInfoParams, g_testPolicyParams, fullIdUser1));
    g_testHapInfoParams.userID = MOCK_USER_ID_10002;
    AccessTokenIDEx fullIdUser2;
    EXPECT_EQ(RET_SUCCESS, AccessTokenKit::InitHapToken(g_testHapInfoParams, g_testPolicyParams, fullIdUser2));

    UserState user1 = {.userId = MOCK_USER_ID_10001, .isActive = false};
    UserState user2 = {.userId = MOCK_USER_ID_10002, .isActive = true};
    std::vector<UserState> userListBefore = { user1, user2 };
    std::vector<std::string> permList = { INTERNET, LOCATION };
    int32_t ret = AccessTokenKit::InitUserPolicy(userListBefore, permList);
    EXPECT_EQ(ret, 0);
    EXPECT_EQ(AccessTokenKit::VerifyAccessToken(fullIdUser1.tokenIdExStruct.tokenID, INTERNET), PERMISSION_DENIED);
    EXPECT_EQ(AccessTokenKit::VerifyAccessToken(fullIdUser2.tokenIdExStruct.tokenID, INTERNET), PERMISSION_GRANTED);
    EXPECT_EQ(AccessTokenKit::VerifyAccessToken(fullIdUser1.tokenIdExStruct.tokenID, LOCATION),
        PERMISSION_DENIED);
    EXPECT_EQ(AccessTokenKit::VerifyAccessToken(fullIdUser2.tokenIdExStruct.tokenID, LOCATION),
        PERMISSION_DENIED);

    // update the policy
    user1.isActive = true;
    user2.isActive = false;
    std::vector<UserState> userListAfter = { user1, user2 };
    ret = AccessTokenKit::UpdateUserPolicy(userListAfter);
    EXPECT_EQ(ret, 0);
    EXPECT_EQ(AccessTokenKit::VerifyAccessToken(fullIdUser1.tokenIdExStruct.tokenID, INTERNET), PERMISSION_GRANTED);
    EXPECT_EQ(AccessTokenKit::VerifyAccessToken(fullIdUser2.tokenIdExStruct.tokenID, INTERNET), PERMISSION_DENIED);
    EXPECT_EQ(AccessTokenKit::VerifyAccessToken(fullIdUser1.tokenIdExStruct.tokenID, LOCATION),
        PERMISSION_DENIED);
    EXPECT_EQ(AccessTokenKit::VerifyAccessToken(fullIdUser2.tokenIdExStruct.tokenID, LOCATION),
        PERMISSION_DENIED);

    EXPECT_EQ(RET_SUCCESS, AccessTokenKit::DeleteToken(fullIdUser1.tokenIdExStruct.tokenID));
    EXPECT_EQ(RET_SUCCESS, AccessTokenKit::DeleteToken(fullIdUser2.tokenIdExStruct.tokenID));

    int32_t res = AccessTokenKit::ClearUserPolicy();
    EXPECT_EQ(res, 0);
}


/**
 * @tc.name: UserPolicyTestForNewHap
 * @tc.desc: Set the authorization status based on the user policy during new hap installation
 * @tc.type: FUNC
 * @tc.require:Issue Number
 */
HWTEST_F(EdmPolicySetTest, UserPolicyTestForNewHap, TestSize.Level1)
{
    UserState user1 = {.userId = MOCK_USER_ID_10001, .isActive = true};
    UserState user2 = {.userId = MOCK_USER_ID_10002, .isActive = true};
    std::vector<UserState> userListBefore = { user1, user2 };
    std::vector<std::string> permList = { INTERNET, LOCATION };
    EXPECT_EQ(AccessTokenKit::InitUserPolicy(userListBefore, permList), 0);

    g_testHapInfoParams.userID = MOCK_USER_ID_10001;
    AccessTokenIDEx fullIdUser1;
    EXPECT_EQ(RET_SUCCESS, AccessTokenKit::InitHapToken(g_testHapInfoParams, g_testPolicyParams, fullIdUser1));
    g_testHapInfoParams.userID = MOCK_USER_ID_10002;
    AccessTokenIDEx fullIdUser2;
    EXPECT_EQ(RET_SUCCESS, AccessTokenKit::InitHapToken(g_testHapInfoParams, g_testPolicyParams, fullIdUser2));

    EXPECT_EQ(AccessTokenKit::VerifyAccessToken(fullIdUser1.tokenIdExStruct.tokenID, INTERNET), PERMISSION_GRANTED);
    EXPECT_EQ(AccessTokenKit::VerifyAccessToken(fullIdUser2.tokenIdExStruct.tokenID, INTERNET), PERMISSION_GRANTED);
    EXPECT_EQ(AccessTokenKit::VerifyAccessToken(fullIdUser1.tokenIdExStruct.tokenID, LOCATION),
        PERMISSION_DENIED);
    EXPECT_EQ(AccessTokenKit::VerifyAccessToken(fullIdUser2.tokenIdExStruct.tokenID, LOCATION),
        PERMISSION_DENIED);
    EXPECT_EQ(RET_SUCCESS, AccessTokenKit::DeleteToken(fullIdUser1.tokenIdExStruct.tokenID));
    EXPECT_EQ(RET_SUCCESS, AccessTokenKit::DeleteToken(fullIdUser2.tokenIdExStruct.tokenID));

    // update the policy
    user1.isActive = false;
    user2.isActive = false;
    std::vector<UserState> userListAfter = { user1, user2 };
    int32_t ret = AccessTokenKit::UpdateUserPolicy(userListAfter);
    EXPECT_EQ(ret, 0);
    g_testHapInfoParams.userID = MOCK_USER_ID_10001;
    EXPECT_EQ(RET_SUCCESS, AccessTokenKit::InitHapToken(g_testHapInfoParams, g_testPolicyParams, fullIdUser1));
    g_testHapInfoParams.userID = MOCK_USER_ID_10002;
    EXPECT_EQ(RET_SUCCESS, AccessTokenKit::InitHapToken(g_testHapInfoParams, g_testPolicyParams, fullIdUser2));
    EXPECT_EQ(AccessTokenKit::VerifyAccessToken(fullIdUser1.tokenIdExStruct.tokenID, INTERNET), PERMISSION_DENIED);
    EXPECT_EQ(AccessTokenKit::VerifyAccessToken(fullIdUser2.tokenIdExStruct.tokenID, INTERNET), PERMISSION_DENIED);
    EXPECT_EQ(AccessTokenKit::VerifyAccessToken(fullIdUser1.tokenIdExStruct.tokenID, LOCATION),
        PERMISSION_DENIED);
    EXPECT_EQ(AccessTokenKit::VerifyAccessToken(fullIdUser2.tokenIdExStruct.tokenID, LOCATION),
        PERMISSION_DENIED);
    EXPECT_EQ(RET_SUCCESS, AccessTokenKit::DeleteToken(fullIdUser1.tokenIdExStruct.tokenID));
    EXPECT_EQ(RET_SUCCESS, AccessTokenKit::DeleteToken(fullIdUser2.tokenIdExStruct.tokenID));
    EXPECT_EQ(AccessTokenKit::ClearUserPolicy(), 0);
}

/**
 * @tc.name: UserPolicyTestForNewHap
 * @tc.desc: Set the authorization status based on the user policy during new hap installation
 * @tc.type: FUNC
 * @tc.require:Issue Number
 */
HWTEST_F(EdmPolicySetTest, UserPolicyTestForClearUserGranted, TestSize.Level1)
{
    UserState user1 = {.userId = MOCK_USER_ID_10001, .isActive = true};
    UserState user2 = {.userId = MOCK_USER_ID_10002, .isActive = false};
    std::vector<UserState> userListBefore = { user1, user2 };
    std::vector<std::string> permList = { INTERNET, LOCATION };
    int32_t ret = AccessTokenKit::InitUserPolicy(userListBefore, permList);
    EXPECT_EQ(ret, 0);

    g_testHapInfoParams.userID = MOCK_USER_ID_10001;
    AccessTokenIDEx fullIdUser1;
    EXPECT_EQ(RET_SUCCESS, AccessTokenKit::InitHapToken(g_testHapInfoParams, g_testPolicyParams, fullIdUser1));
    g_testHapInfoParams.userID = MOCK_USER_ID_10002;
    AccessTokenIDEx fullIdUser2;
    EXPECT_EQ(RET_SUCCESS, AccessTokenKit::InitHapToken(g_testHapInfoParams, g_testPolicyParams, fullIdUser2));

    EXPECT_EQ(AccessTokenKit::VerifyAccessToken(fullIdUser1.tokenIdExStruct.tokenID, INTERNET), PERMISSION_GRANTED);
    EXPECT_EQ(AccessTokenKit::VerifyAccessToken(fullIdUser2.tokenIdExStruct.tokenID, INTERNET), PERMISSION_DENIED);

    ret = AccessTokenKit::ClearUserGrantedPermissionState(fullIdUser1.tokenIdExStruct.tokenID);
    EXPECT_EQ(RET_SUCCESS, ret);
    ret = AccessTokenKit::ClearUserGrantedPermissionState(fullIdUser2.tokenIdExStruct.tokenID);
    EXPECT_EQ(RET_SUCCESS, ret);
    EXPECT_EQ(AccessTokenKit::VerifyAccessToken(fullIdUser1.tokenIdExStruct.tokenID, INTERNET), PERMISSION_GRANTED);
    EXPECT_EQ(AccessTokenKit::VerifyAccessToken(fullIdUser2.tokenIdExStruct.tokenID, INTERNET), PERMISSION_DENIED);

    // update the policy
    user1.isActive = false;
    user2.isActive = true;
    std::vector<UserState> userListAfter = { user1, user2 };
    ret = AccessTokenKit::UpdateUserPolicy(userListAfter);

    EXPECT_EQ(AccessTokenKit::VerifyAccessToken(fullIdUser1.tokenIdExStruct.tokenID, INTERNET), PERMISSION_DENIED);
    EXPECT_EQ(AccessTokenKit::VerifyAccessToken(fullIdUser2.tokenIdExStruct.tokenID, INTERNET), PERMISSION_GRANTED);

    ret = AccessTokenKit::ClearUserGrantedPermissionState(fullIdUser1.tokenIdExStruct.tokenID);
    ret = AccessTokenKit::ClearUserGrantedPermissionState(fullIdUser2.tokenIdExStruct.tokenID);
    EXPECT_EQ(AccessTokenKit::VerifyAccessToken(fullIdUser1.tokenIdExStruct.tokenID, INTERNET), PERMISSION_DENIED);
    EXPECT_EQ(AccessTokenKit::VerifyAccessToken(fullIdUser2.tokenIdExStruct.tokenID, INTERNET), PERMISSION_GRANTED);

    EXPECT_EQ(RET_SUCCESS, AccessTokenKit::DeleteToken(fullIdUser1.tokenIdExStruct.tokenID));
    EXPECT_EQ(RET_SUCCESS, AccessTokenKit::DeleteToken(fullIdUser2.tokenIdExStruct.tokenID));

    int32_t res = AccessTokenKit::ClearUserPolicy();
    EXPECT_EQ(res, 0);
}

/**
 * @tc.name: ClearUserPolicy001
 * @tc.desc: Check permission status after clear user policy.
 * @tc.type: FUNC
 * @tc.require:Issue Number
 */
HWTEST_F(EdmPolicySetTest, ClearUserPolicy001, TestSize.Level1)
{
    g_testHapInfoParams.userID = MOCK_USER_ID_10002;
    AccessTokenIDEx fullIdUser2;
    EXPECT_EQ(RET_SUCCESS, AccessTokenKit::InitHapToken(g_testHapInfoParams, g_testPolicyParams, fullIdUser2));
    g_testHapInfoParams.userID = MOCK_USER_ID_10001;
    AccessTokenIDEx fullIdUser1;
    EXPECT_EQ(RET_SUCCESS, AccessTokenKit::InitHapToken(g_testHapInfoParams, g_testPolicyParams, fullIdUser1));

    UserState user1 = {.userId = MOCK_USER_ID_10001, .isActive = false};
    UserState user2 = {.userId = MOCK_USER_ID_10002, .isActive = false};
    std::vector<UserState> userList = { user1, user2};
    std::vector<std::string> permList = { INTERNET };
    EXPECT_EQ(0, AccessTokenKit::InitUserPolicy(userList, permList));
    EXPECT_EQ(AccessTokenKit::VerifyAccessToken(fullIdUser1.tokenIdExStruct.tokenID, INTERNET), PERMISSION_DENIED);
    EXPECT_EQ(AccessTokenKit::VerifyAccessToken(fullIdUser2.tokenIdExStruct.tokenID, INTERNET), PERMISSION_DENIED);
    EXPECT_EQ(AccessTokenKit::VerifyAccessToken(fullIdUser2.tokenIdExStruct.tokenID, INTERNET, true),
        PERMISSION_DENIED);
    EXPECT_EQ(AccessTokenKit::VerifyAccessToken(fullIdUser1.tokenIdExStruct.tokenID, INTERNET, true),
        PERMISSION_DENIED);

    int32_t res = AccessTokenKit::ClearUserPolicy();
    EXPECT_EQ(res, 0);

    EXPECT_EQ(AccessTokenKit::VerifyAccessToken(fullIdUser1.tokenIdExStruct.tokenID, INTERNET), PERMISSION_GRANTED);
    EXPECT_EQ(AccessTokenKit::VerifyAccessToken(fullIdUser2.tokenIdExStruct.tokenID, INTERNET), PERMISSION_GRANTED);

    EXPECT_EQ(RET_SUCCESS, AccessTokenKit::DeleteToken(fullIdUser1.tokenIdExStruct.tokenID));
    EXPECT_EQ(RET_SUCCESS, AccessTokenKit::DeleteToken(fullIdUser2.tokenIdExStruct.tokenID));
}


/**
 * @tc.name: UserPolicyForUpdateHapTokenTest
 * @tc.desc: UpdateHapToken and check permission status with user policy After .
 * @tc.type: FUNC
 * @tc.require:Issue Number
 */
HWTEST_F(EdmPolicySetTest, UserPolicyForUpdateHapTokenTest, TestSize.Level1)
{
    HapPolicyParams testPolicyParams1 = {
        .apl = APL_SYSTEM_CORE,
        .domain = "test.domain2",
        .permStateList = {
            g_infoManagerNetWorkState,
        }
    };
    g_testHapInfoParams.userID = MOCK_USER_ID_10001;
    AccessTokenIDEx fullIdUser1;
    EXPECT_EQ(RET_SUCCESS, AccessTokenKit::InitHapToken(g_testHapInfoParams, testPolicyParams1, fullIdUser1));

    UserState user1 = {.userId = MOCK_USER_ID_10001, .isActive = false};
    std::vector<UserState> userList = { user1};
    std::vector<std::string> permList = { INTERNET };
    EXPECT_EQ(0, AccessTokenKit::InitUserPolicy(userList, permList));
    HapPolicyParams testPolicyParams2 = {
        .apl = APL_SYSTEM_CORE,
        .domain = "test.domain2",
        .permStateList = {
            g_infoManagerInternetState,
            g_infoManagerNetWorkState,
        }
    };
    UpdateHapInfoParams info;
    info.appIDDesc = "TEST";
    info.apiVersion = 12;
    info.isSystemApp = false;
    int32_t res = AccessTokenKit::UpdateHapToken(fullIdUser1, info, testPolicyParams2);
    EXPECT_EQ(res, 0);
    EXPECT_EQ(AccessTokenKit::VerifyAccessToken(fullIdUser1.tokenIdExStruct.tokenID, INTERNET), PERMISSION_DENIED);

    res = AccessTokenKit::ClearUserPolicy();
    EXPECT_EQ(res, 0);
    EXPECT_EQ(AccessTokenKit::VerifyAccessToken(fullIdUser1.tokenIdExStruct.tokenID, INTERNET), PERMISSION_GRANTED);

    EXPECT_EQ(RET_SUCCESS, AccessTokenKit::DeleteToken(fullIdUser1.tokenIdExStruct.tokenID));
}