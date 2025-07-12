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
#include "accesstoken_common_log.h"
#include "access_token_error.h"
#include "permission_map.h"
#include "perm_setproc.h"
#include "test_common.h"
#include "token_setproc.h"
#include "tokenid_kit.h"

using namespace testing::ext;
using namespace OHOS::Security::AccessToken;

namespace {
static const uint32_t DEFAULT_ACCOUNT_ID = 100;
static const uint32_t MOCK_USER_ID_10001 = 10001;
static const uint32_t MOCK_USER_ID_10002 = 10002;
static const uint32_t MOCK_USER_ID_10003 = 10003;
static const int32_t MAX_PERMISSION_LIST_SIZE = 1024;
static const int32_t MAX_LENGTH = 256;
const std::string MANAGE_HAP_TOKEN_ID_PERMISSION = "ohos.permission.MANAGE_HAP_TOKENID";
const std::string INTERNET = "ohos.permission.INTERNET";
static const std::string GET_NETWORK_STATS = "ohos.permission.GET_NETWORK_STATS";
static const std::string LOCATION = "ohos.permission.LOCATION";
static const std::string GET_SENSITIVE_PERMISSIONS = "ohos.permission.GET_SENSITIVE_PERMISSIONS";
static const std::string REVOKE_SENSITIVE_PERMISSIONS = "ohos.permission.REVOKE_SENSITIVE_PERMISSIONS"; // system_grant
static const std::string MICROPHONE = "ohos.permission.MICROPHONE"; // user_grant
static const std::string CAMERA = "ohos.permission.CAMERA"; // user_grant
static const std::string CUSTOM_SCREEN_CAPTURE = "ohos.permission.CUSTOM_SCREEN_CAPTURE"; // user_grant
static const std::string READ_HEALTH_DATA = "ohos.permission.READ_HEALTH_DATA";
static const std::string MANAGE_EDM_POLICY = "ohos.permission.MANAGE_EDM_POLICY"; // system_grant
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

PermissionStateFull g_infoManagerMicrophoneState = {
    .permissionName = MICROPHONE,
    .isGeneral = true,
    .resDeviceID = {"local2"},
    .grantStatus = {PermissionState::PERMISSION_DENIED},
    .grantFlags = {0}
};

PermissionStateFull g_infoManagerCameraState = {
    .permissionName = CAMERA,
    .isGeneral = true,
    .resDeviceID = {"local2"},
    .grantStatus = {PermissionState::PERMISSION_GRANTED},
    .grantFlags = {PermissionFlag::PERMISSION_SYSTEM_FIXED}
};

PermissionStateFull g_infoManagerCustomScreenCaptureState = {
    .permissionName = CUSTOM_SCREEN_CAPTURE,
    .isGeneral = true,
    .resDeviceID = {"local2"},
    .grantStatus = {PermissionState::PERMISSION_GRANTED},
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
        g_infoManagerMicrophoneState,
        g_infoManagerCameraState,
        g_infoManagerCustomScreenCaptureState,
    }
};

PermissionStateFull g_infoManagerCustomScreenCaptureState02 = {
    .permissionName = CUSTOM_SCREEN_CAPTURE,
    .isGeneral = true,
    .resDeviceID = {"local2"},
    .grantStatus = {PermissionState::PERMISSION_GRANTED},
    .grantFlags = {0}
};

HapPolicyParams g_testPolicyParams02 = {
    .apl = APL_SYSTEM_CORE,
    .domain = "test.domain2",
    .preAuthorizationInfo = {
        {
            .permissionName = CUSTOM_SCREEN_CAPTURE,
            .userCancelable = true,
        },
    },
    .permStateList = {
        g_infoManagerCustomScreenCaptureState02
    }
};

HapPolicyParams g_testPolicyParams03 = {
    .apl = APL_SYSTEM_CORE,
    .domain = "test.domain2",
    .preAuthorizationInfo = {
        {
            .permissionName = CUSTOM_SCREEN_CAPTURE,
            .userCancelable = false,
        },
    },
    .permStateList = {
        g_infoManagerCustomScreenCaptureState02
    }
};

uint64_t g_selfShellTokenId;
static MockHapToken* g_mock = nullptr;
}

void EdmPolicySetTest::TearDownTestCase()
{
    AccessTokenIDEx tokenIdEx = TestCommon::GetHapTokenIdFromBundle(
        g_testHapInfoParams.userID, g_testHapInfoParams.bundleName, g_testHapInfoParams.instIndex);
    TestCommon::DeleteTestHapToken(tokenIdEx.tokenIdExStruct.tokenID);
    if (g_mock != nullptr) {
        delete g_mock;
        g_mock = nullptr;
    }
    EXPECT_EQ(0, SetSelfTokenID(g_selfShellTokenId));
    TestCommon::ResetTestEvironment();
}

void EdmPolicySetTest::SetUp()
{
    LOGI(ATM_DOMAIN, ATM_TAG, "SetUp ok.");
}

void EdmPolicySetTest::TearDown()
{
}

void EdmPolicySetTest::SetUpTestCase()
{
    g_selfShellTokenId = GetSelfTokenID();
    TestCommon::SetTestEvironment(g_selfShellTokenId);

    std::vector<std::string> reqPerm;
    reqPerm.emplace_back(MANAGE_HAP_TOKEN_ID_PERMISSION);
    reqPerm.emplace_back(GET_SENSITIVE_PERMISSIONS);
    reqPerm.emplace_back(REVOKE_SENSITIVE_PERMISSIONS);
    g_mock = new (std::nothrow) MockHapToken("EdmPolicySetTest", reqPerm);
    LOGI(ATM_DOMAIN, ATM_TAG, "SetUpTestCase ok.");
}

/**
 * @tc.name: InitUserPolicy001
 * @tc.desc: InitUserPolicy failed invalid userList size.
 * @tc.type: FUNC
 * @tc.require:Issue Number
 */
HWTEST_F(EdmPolicySetTest, InitUserPolicy001, TestSize.Level0)
{
    const int32_t invalidSize = 1025; // 1025 is invalid size.
    std::vector<UserState> userList(invalidSize);
    std::vector<std::string> permList = { "ohos.permission.INTERNET" };
    int32_t ret = AccessTokenKit::InitUserPolicy(userList, permList);
    EXPECT_EQ(ret, AccessTokenError::ERR_PARAM_INVALID);
}

/**
 * @tc.name: InitUserPolicy002
 * @tc.desc: InitUserPolicy failed empty userList.
 * @tc.type: FUNC
 * @tc.require:Issue Number
 */
HWTEST_F(EdmPolicySetTest, InitUserPolicy002, TestSize.Level0)
{
    std::vector<UserState> userListEmtpy;
    std::vector<std::string> permList = { "ohos.permission.INTERNET" };
    int32_t ret = AccessTokenKit::InitUserPolicy(userListEmtpy, permList);
    EXPECT_EQ(ret, AccessTokenError::ERR_PARAM_INVALID);
}

/**
 * @tc.name: InitUserPolicy003
 * @tc.desc: InitUserPolicy failed empty userList.
 * @tc.type: FUNC
 * @tc.require:Issue Number
 */
HWTEST_F(EdmPolicySetTest, InitUserPolicy003, TestSize.Level0)
{
    UserState user = {.userId = DEFAULT_ACCOUNT_ID, .isActive = true};
    const int32_t invalidSize = 1025; // 1025 is invalid size.
    std::vector<UserState> userList = { user };
    std::vector<std::string> permList(invalidSize, "abc");
    int32_t ret = AccessTokenKit::InitUserPolicy(userList, permList);
    EXPECT_EQ(ret, AccessTokenError::ERR_PARAM_INVALID);
}

/**
 * @tc.name: InitUserPolicy004
 * @tc.desc: InitUserPolicy failed empty permList.
 * @tc.type: FUNC
 * @tc.require:Issue Number
 */
HWTEST_F(EdmPolicySetTest, InitUserPolicy004, TestSize.Level0)
{
    UserState user = {.userId = DEFAULT_ACCOUNT_ID, .isActive = true};
    std::vector<UserState> userList = { user };
    std::vector<std::string> permListEmpty;
    int32_t ret = AccessTokenKit::InitUserPolicy(userList, permListEmpty);
    EXPECT_EQ(ret, AccessTokenError::ERR_PARAM_INVALID);
}


/**
 * @tc.name: InitUserPolicy005
 * @tc.desc: InitUserPolicy and the stock permission status is refreshed according to the policy.
 * @tc.type: FUNC
 * @tc.require:Issue Number
 */
HWTEST_F(EdmPolicySetTest, InitUserPolicy005, TestSize.Level0)
{
    GTEST_LOG_(INFO) << "permissionSet OK ";
    MockNativeToken mock("foundation");

    g_testHapInfoParams.userID = MOCK_USER_ID_10001;
    AccessTokenIDEx fullIdUser1;
    EXPECT_EQ(RET_SUCCESS,
        TestCommon::AllocTestHapToken(g_testHapInfoParams, g_testPolicyParams, fullIdUser1));
    g_testHapInfoParams.userID = MOCK_USER_ID_10002;
    AccessTokenIDEx fullIdUser2;
    EXPECT_EQ(RET_SUCCESS,
        TestCommon::AllocTestHapToken(g_testHapInfoParams, g_testPolicyParams, fullIdUser2));
    g_testHapInfoParams.userID = MOCK_USER_ID_10003;
    AccessTokenIDEx fullIdUser3;
    EXPECT_EQ(RET_SUCCESS,
        TestCommon::AllocTestHapToken(g_testHapInfoParams, g_testPolicyParams, fullIdUser3));

    EXPECT_EQ(AccessTokenKit::VerifyAccessToken(fullIdUser1.tokenIdExStruct.tokenID, LOCATION),
        PERMISSION_DENIED);

    UserState user0 = {.userId = -1, .isActive = true};
    UserState user1 = {.userId = MOCK_USER_ID_10001, .isActive = true};
    UserState user2 = {.userId = MOCK_USER_ID_10002, .isActive = false};
    UserState user3 = {.userId = MOCK_USER_ID_10003, .isActive = false};

    std::vector<UserState> userList = { user0, user1, user2, user3 };
    std::vector<std::string> permList = { INTERNET, GET_NETWORK_STATS, LOCATION };
    EXPECT_EQ(RET_SUCCESS,  AccessTokenKit::InitUserPolicy(userList, permList));

    EXPECT_EQ(AccessTokenKit::VerifyAccessToken(fullIdUser1.tokenIdExStruct.tokenID, INTERNET), PERMISSION_GRANTED);
    EXPECT_EQ(AccessTokenKit::VerifyAccessToken(fullIdUser2.tokenIdExStruct.tokenID, INTERNET), PERMISSION_DENIED);
    EXPECT_EQ(AccessTokenKit::VerifyAccessToken(fullIdUser3.tokenIdExStruct.tokenID, INTERNET), PERMISSION_DENIED);
    EXPECT_EQ(AccessTokenKit::VerifyAccessToken(fullIdUser1.tokenIdExStruct.tokenID, LOCATION),
        PERMISSION_DENIED);
    EXPECT_EQ(AccessTokenKit::VerifyAccessToken(fullIdUser2.tokenIdExStruct.tokenID, LOCATION),
        PERMISSION_DENIED);
    EXPECT_EQ(AccessTokenKit::VerifyAccessToken(fullIdUser3.tokenIdExStruct.tokenID, LOCATION),
        PERMISSION_DENIED);

    EXPECT_EQ(RET_SUCCESS, TestCommon::DeleteTestHapToken(fullIdUser1.tokenIdExStruct.tokenID));
    EXPECT_EQ(RET_SUCCESS, TestCommon::DeleteTestHapToken(fullIdUser2.tokenIdExStruct.tokenID));
    EXPECT_EQ(RET_SUCCESS, TestCommon::DeleteTestHapToken(fullIdUser3.tokenIdExStruct.tokenID));

    EXPECT_EQ(RET_SUCCESS, AccessTokenKit::ClearUserPolicy());
}

/**
 * @tc.name: InitUserPolicy006
 * @tc.desc: Check permission status in the heap.
 * @tc.type: FUNC
 * @tc.require:Issue Number
 */
HWTEST_F(EdmPolicySetTest, InitUserPolicy006, TestSize.Level0)
{
    GTEST_LOG_(INFO) << "permissionSet OK ";
    MockNativeToken mock("foundation");

    g_testHapInfoParams.userID = MOCK_USER_ID_10001;
    AccessTokenIDEx fullIdUser1;
    EXPECT_EQ(RET_SUCCESS,
        TestCommon::AllocTestHapToken(g_testHapInfoParams, g_testPolicyParams, fullIdUser1));
    g_testHapInfoParams.userID = MOCK_USER_ID_10002;
    AccessTokenIDEx fullIdUser2;
    EXPECT_EQ(RET_SUCCESS,
        TestCommon::AllocTestHapToken(g_testHapInfoParams, g_testPolicyParams, fullIdUser2));

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
    EXPECT_EQ(RET_SUCCESS, AccessTokenKit::GetReqPermissions(fullIdUser2.tokenIdExStruct.tokenID, permStatList, true));
    EXPECT_EQ(static_cast<uint32_t>(2), permStatList.size());
    EXPECT_EQ(INTERNET, permStatList[0].permissionName);
    EXPECT_EQ(PERMISSION_GRANTED, permStatList[0].grantStatus[0]);

    EXPECT_EQ(RET_SUCCESS, TestCommon::DeleteTestHapToken(fullIdUser1.tokenIdExStruct.tokenID));
    EXPECT_EQ(RET_SUCCESS, TestCommon::DeleteTestHapToken(fullIdUser2.tokenIdExStruct.tokenID));

    res = AccessTokenKit::ClearUserPolicy();
    EXPECT_EQ(res, 0);
}

/**
 * @tc.name: UpdateUserPolicy001
 * @tc.desc: UpdateUserPolicy failed with
 * policy uninitialized and ClearUserPolicy successfully with policy uninitialized.
 * @tc.type: FUNC
 * @tc.require:Issue Number
 */
HWTEST_F(EdmPolicySetTest, UpdateUserPolicy001, TestSize.Level0)
{
    GTEST_LOG_(INFO) << "permissionSet OK ";
    MockNativeToken mock("foundation");

    UserState user = {.userId = DEFAULT_ACCOUNT_ID, .isActive = true};
    const std::vector<UserState> userList = { user };
    int32_t res = AccessTokenKit::UpdateUserPolicy(userList);
    EXPECT_EQ(res, AccessTokenError::ERR_USER_POLICY_NOT_INITIALIZED);

    res = AccessTokenKit::ClearUserPolicy();
    EXPECT_EQ(res, RET_SUCCESS);
}

/**
 * @tc.name: UpdateUserPolicy003
 * @tc.desc: UpdateUserPolicy with invalid userList.
 * @tc.type: FUNC
 * @tc.require:Issue Number
 */
HWTEST_F(EdmPolicySetTest, UpdateUserPolicy003, TestSize.Level0)
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
HWTEST_F(EdmPolicySetTest, UpdateUserPolicy004, TestSize.Level0)
{
    g_testHapInfoParams.userID = MOCK_USER_ID_10001;
    AccessTokenIDEx fullIdUser1;
    EXPECT_EQ(RET_SUCCESS,
        TestCommon::AllocTestHapToken(g_testHapInfoParams, g_testPolicyParams, fullIdUser1));
    g_testHapInfoParams.userID = MOCK_USER_ID_10002;
    AccessTokenIDEx fullIdUser2;
    EXPECT_EQ(RET_SUCCESS,
        TestCommon::AllocTestHapToken(g_testHapInfoParams, g_testPolicyParams, fullIdUser2));

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

    EXPECT_EQ(RET_SUCCESS, TestCommon::DeleteTestHapToken(fullIdUser1.tokenIdExStruct.tokenID));
    EXPECT_EQ(RET_SUCCESS, TestCommon::DeleteTestHapToken(fullIdUser2.tokenIdExStruct.tokenID));

    int32_t res = AccessTokenKit::ClearUserPolicy();
    EXPECT_EQ(res, 0);
}


/**
 * @tc.name: UserPolicyTestForNewHap
 * @tc.desc: Set the authorization status based on the user policy during new hap installation
 * @tc.type: FUNC
 * @tc.require:Issue Number
 */
HWTEST_F(EdmPolicySetTest, UserPolicyTestForNewHap, TestSize.Level0)
{
    UserState user1 = {.userId = MOCK_USER_ID_10001, .isActive = true};
    UserState user2 = {.userId = MOCK_USER_ID_10002, .isActive = true};
    std::vector<UserState> userListBefore = { user1, user2 };
    std::vector<std::string> permList = { INTERNET, LOCATION };
    EXPECT_EQ(AccessTokenKit::InitUserPolicy(userListBefore, permList), 0);

    g_testHapInfoParams.userID = MOCK_USER_ID_10001;
    AccessTokenIDEx fullIdUser1;
    EXPECT_EQ(RET_SUCCESS,
        TestCommon::AllocTestHapToken(g_testHapInfoParams, g_testPolicyParams, fullIdUser1));
    g_testHapInfoParams.userID = MOCK_USER_ID_10002;
    AccessTokenIDEx fullIdUser2;
    EXPECT_EQ(RET_SUCCESS,
        TestCommon::AllocTestHapToken(g_testHapInfoParams, g_testPolicyParams, fullIdUser2));

    EXPECT_EQ(AccessTokenKit::VerifyAccessToken(fullIdUser1.tokenIdExStruct.tokenID, INTERNET), PERMISSION_GRANTED);
    EXPECT_EQ(AccessTokenKit::VerifyAccessToken(fullIdUser2.tokenIdExStruct.tokenID, INTERNET), PERMISSION_GRANTED);
    EXPECT_EQ(AccessTokenKit::VerifyAccessToken(fullIdUser1.tokenIdExStruct.tokenID, LOCATION),
        PERMISSION_DENIED);
    EXPECT_EQ(AccessTokenKit::VerifyAccessToken(fullIdUser2.tokenIdExStruct.tokenID, LOCATION),
        PERMISSION_DENIED);
    EXPECT_EQ(RET_SUCCESS, TestCommon::DeleteTestHapToken(fullIdUser1.tokenIdExStruct.tokenID));
    EXPECT_EQ(RET_SUCCESS, TestCommon::DeleteTestHapToken(fullIdUser2.tokenIdExStruct.tokenID));

    // update the policy
    user1.isActive = false;
    user2.isActive = false;
    std::vector<UserState> userListAfter = { user1, user2 };
    int32_t ret = AccessTokenKit::UpdateUserPolicy(userListAfter);
    EXPECT_EQ(ret, 0);
    g_testHapInfoParams.userID = MOCK_USER_ID_10001;
    EXPECT_EQ(RET_SUCCESS,
        TestCommon::AllocTestHapToken(g_testHapInfoParams, g_testPolicyParams, fullIdUser1));
    g_testHapInfoParams.userID = MOCK_USER_ID_10002;
    EXPECT_EQ(RET_SUCCESS,
        TestCommon::AllocTestHapToken(g_testHapInfoParams, g_testPolicyParams, fullIdUser2));
    EXPECT_EQ(AccessTokenKit::VerifyAccessToken(fullIdUser1.tokenIdExStruct.tokenID, INTERNET), PERMISSION_DENIED);
    EXPECT_EQ(AccessTokenKit::VerifyAccessToken(fullIdUser2.tokenIdExStruct.tokenID, INTERNET), PERMISSION_DENIED);
    EXPECT_EQ(AccessTokenKit::VerifyAccessToken(fullIdUser1.tokenIdExStruct.tokenID, LOCATION),
        PERMISSION_DENIED);
    EXPECT_EQ(AccessTokenKit::VerifyAccessToken(fullIdUser2.tokenIdExStruct.tokenID, LOCATION),
        PERMISSION_DENIED);
    EXPECT_EQ(RET_SUCCESS, TestCommon::DeleteTestHapToken(fullIdUser1.tokenIdExStruct.tokenID));
    EXPECT_EQ(RET_SUCCESS, TestCommon::DeleteTestHapToken(fullIdUser2.tokenIdExStruct.tokenID));
    EXPECT_EQ(AccessTokenKit::ClearUserPolicy(), 0);
}

/**
 * @tc.name: UserPolicyTestForNewHap
 * @tc.desc: Set the authorization status based on the user policy during new hap installation
 * @tc.type: FUNC
 * @tc.require:Issue Number
 */
HWTEST_F(EdmPolicySetTest, UserPolicyTestForClearUserGranted, TestSize.Level0)
{
    UserState user1 = {.userId = MOCK_USER_ID_10001, .isActive = true};
    UserState user2 = {.userId = MOCK_USER_ID_10002, .isActive = false};
    std::vector<UserState> userListBefore = { user1, user2 };
    std::vector<std::string> permList = { INTERNET, LOCATION };
    int32_t ret = AccessTokenKit::InitUserPolicy(userListBefore, permList);
    EXPECT_EQ(ret, 0);

    g_testHapInfoParams.userID = MOCK_USER_ID_10001;
    AccessTokenIDEx fullIdUser1;
    EXPECT_EQ(RET_SUCCESS,
        TestCommon::AllocTestHapToken(g_testHapInfoParams, g_testPolicyParams, fullIdUser1));
    g_testHapInfoParams.userID = MOCK_USER_ID_10002;
    AccessTokenIDEx fullIdUser2;
    EXPECT_EQ(RET_SUCCESS,
        TestCommon::AllocTestHapToken(g_testHapInfoParams, g_testPolicyParams, fullIdUser2));

    EXPECT_EQ(AccessTokenKit::VerifyAccessToken(fullIdUser1.tokenIdExStruct.tokenID, INTERNET), PERMISSION_GRANTED);
    EXPECT_EQ(AccessTokenKit::VerifyAccessToken(fullIdUser2.tokenIdExStruct.tokenID, INTERNET), PERMISSION_DENIED);

    ret = TestCommon::ClearUserGrantedPermissionStateByTest(fullIdUser1.tokenIdExStruct.tokenID);
    EXPECT_EQ(RET_SUCCESS, ret);
    ret = TestCommon::ClearUserGrantedPermissionStateByTest(fullIdUser2.tokenIdExStruct.tokenID);
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

    ret = TestCommon::ClearUserGrantedPermissionStateByTest(fullIdUser1.tokenIdExStruct.tokenID);
    ret = TestCommon::ClearUserGrantedPermissionStateByTest(fullIdUser2.tokenIdExStruct.tokenID);
    EXPECT_EQ(AccessTokenKit::VerifyAccessToken(fullIdUser1.tokenIdExStruct.tokenID, INTERNET), PERMISSION_DENIED);
    EXPECT_EQ(AccessTokenKit::VerifyAccessToken(fullIdUser2.tokenIdExStruct.tokenID, INTERNET), PERMISSION_GRANTED);

    EXPECT_EQ(RET_SUCCESS, TestCommon::DeleteTestHapToken(fullIdUser1.tokenIdExStruct.tokenID));
    EXPECT_EQ(RET_SUCCESS, TestCommon::DeleteTestHapToken(fullIdUser2.tokenIdExStruct.tokenID));

    int32_t res = AccessTokenKit::ClearUserPolicy();
    EXPECT_EQ(res, 0);
}

/**
 * @tc.name: ClearUserPolicy001
 * @tc.desc: Check permission status after clear user policy.
 * @tc.type: FUNC
 * @tc.require:Issue Number
 */
HWTEST_F(EdmPolicySetTest, ClearUserPolicy001, TestSize.Level0)
{
    g_testHapInfoParams.userID = MOCK_USER_ID_10002;
    AccessTokenIDEx fullIdUser2;
    EXPECT_EQ(RET_SUCCESS,
        TestCommon::AllocTestHapToken(g_testHapInfoParams, g_testPolicyParams, fullIdUser2));
    g_testHapInfoParams.userID = MOCK_USER_ID_10001;
    AccessTokenIDEx fullIdUser1;
    EXPECT_EQ(RET_SUCCESS,
        TestCommon::AllocTestHapToken(g_testHapInfoParams, g_testPolicyParams, fullIdUser1));

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

    EXPECT_EQ(RET_SUCCESS, TestCommon::DeleteTestHapToken(fullIdUser1.tokenIdExStruct.tokenID));
    EXPECT_EQ(RET_SUCCESS, TestCommon::DeleteTestHapToken(fullIdUser2.tokenIdExStruct.tokenID));
}


/**
 * @tc.name: UserPolicyForUpdateHapTokenTest
 * @tc.desc: UpdateHapToken and check permission status with user policy After .
 * @tc.type: FUNC
 * @tc.require:Issue Number
 */
HWTEST_F(EdmPolicySetTest, UserPolicyForUpdateHapTokenTest, TestSize.Level0)
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
    EXPECT_EQ(RET_SUCCESS,
        TestCommon::AllocTestHapToken(g_testHapInfoParams, testPolicyParams1, fullIdUser1));

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
    {
        MockNativeToken mock("foundation");
        EXPECT_EQ(RET_SUCCESS, AccessTokenKit::UpdateHapToken(fullIdUser1, info, testPolicyParams2));
    }
    EXPECT_EQ(AccessTokenKit::VerifyAccessToken(fullIdUser1.tokenIdExStruct.tokenID, INTERNET), PERMISSION_DENIED);

    EXPECT_EQ(RET_SUCCESS, AccessTokenKit::ClearUserPolicy());
    EXPECT_EQ(AccessTokenKit::VerifyAccessToken(fullIdUser1.tokenIdExStruct.tokenID, INTERNET), PERMISSION_GRANTED);

    EXPECT_EQ(RET_SUCCESS, TestCommon::DeleteTestHapToken(fullIdUser1.tokenIdExStruct.tokenID));
}

/**
 * @tc.name: SetPermissionStatusWithPolicy001
 * @tc.desc: Normal parameter testing.
 * @tc.type: FUNC
 * @tc.require:Issue Number
 */
HWTEST_F(EdmPolicySetTest, SetPermissionStatusWithPolicy001, TestSize.Level0)
{
    LOGI(ATM_DOMAIN, ATM_TAG, "SetPermissionStatusWithPolicy001");

    g_testHapInfoParams.userID = MOCK_USER_ID_10001;
    AccessTokenIDEx tokenIdEx = TestCommon::AllocAndGrantHapTokenByTest(g_testHapInfoParams, g_testPolicyParams);
    AccessTokenID tokenID = tokenIdEx.tokenIdExStruct.tokenID;
    ASSERT_NE(INVALID_TOKENID, tokenID);

    MockNativeToken mock("edm");
    uint64_t selfTokenId = GetSelfTokenID();
    ASSERT_EQ(PERMISSION_GRANTED, AccessTokenKit::VerifyAccessToken(selfTokenId, MANAGE_EDM_POLICY, false));

    uint32_t flag = 0;
    std::vector<std::string> permList = {MICROPHONE, CUSTOM_SCREEN_CAPTURE};
    std::vector<PermissionState> stateList = {PERMISSION_GRANTED, PERMISSION_DENIED};
    for (auto status : stateList) {
        GTEST_LOG_(INFO) << "SetPermissionStatusWithPolicy001 status: " << status;
        EXPECT_EQ(RET_SUCCESS,
        AccessTokenKit::SetPermissionStatusWithPolicy(tokenID, permList, status, PERMISSION_FIXED_BY_ADMIN_POLICY));
        std::vector<PermissionListState> permsList;
        for (auto perm : permList) {
            GTEST_LOG_(INFO) << "SetPermissionStatusWithPolicy001 check perm: " << perm;
            EXPECT_EQ(status, AccessTokenKit::VerifyAccessToken(tokenID, perm, false));
            EXPECT_EQ(RET_SUCCESS, AccessTokenKit::GetPermissionFlag(tokenID, perm, flag));
            EXPECT_EQ(PERMISSION_FIXED_BY_ADMIN_POLICY, flag);
        }
    }

    EXPECT_EQ(RET_SUCCESS, TestCommon::DeleteTestHapToken(tokenID));
}

/**
 * @tc.name: SetPermissionStatusWithPolicy002
 * @tc.desc: tokenID exception test.
 * @tc.type: FUNC
 * @tc.require:Issue Number
 */
HWTEST_F(EdmPolicySetTest, SetPermissionStatusWithPolicy002, TestSize.Level0)
{
    LOGI(ATM_DOMAIN, ATM_TAG, "SetPermissionStatusWithPolicy002");

    g_testHapInfoParams.userID = MOCK_USER_ID_10001;
    AccessTokenIDEx tokenIdEx = TestCommon::AllocAndGrantHapTokenByTest(g_testHapInfoParams, g_testPolicyParams);
    AccessTokenID tokenID = tokenIdEx.tokenIdExStruct.tokenID;
    ASSERT_NE(INVALID_TOKENID, tokenID);

    MockNativeToken mock("edm");
    uint64_t selfTokenId = GetSelfTokenID();
    ASSERT_EQ(PERMISSION_GRANTED, AccessTokenKit::VerifyAccessToken(selfTokenId, MANAGE_EDM_POLICY, false));

    std::vector<std::string> permList = {MICROPHONE, CUSTOM_SCREEN_CAPTURE};
    uint32_t ret = RET_SUCCESS;
    ret = AccessTokenKit::SetPermissionStatusWithPolicy(
        INVALID_TOKENID, permList, PERMISSION_GRANTED, PERMISSION_FIXED_BY_ADMIN_POLICY);
    EXPECT_EQ(ERR_PARAM_INVALID, ret);

    EXPECT_EQ(RET_SUCCESS, TestCommon::DeleteTestHapToken(tokenID));
}

/**
 * @tc.name: SetPermissionStatusWithPolicy003
 * @tc.desc: PermissionList exception test.
 * @tc.type: FUNC
 * @tc.require:Issue Number
 */
HWTEST_F(EdmPolicySetTest, SetPermissionStatusWithPolicy003, TestSize.Level0)
{
    LOGI(ATM_DOMAIN, ATM_TAG, "SetPermissionStatusWithPolicy003");

    g_testHapInfoParams.userID = MOCK_USER_ID_10001;
    AccessTokenIDEx tokenIdEx = TestCommon::AllocAndGrantHapTokenByTest(g_testHapInfoParams, g_testPolicyParams);
    AccessTokenID tokenID = tokenIdEx.tokenIdExStruct.tokenID;
    ASSERT_NE(INVALID_TOKENID, tokenID);

    MockNativeToken mock("edm");
    uint64_t selfTokenId = GetSelfTokenID();
    ASSERT_EQ(PERMISSION_GRANTED, AccessTokenKit::VerifyAccessToken(selfTokenId, MANAGE_EDM_POLICY, false));

    uint32_t ret = RET_SUCCESS;

    ret = AccessTokenKit::SetPermissionStatusWithPolicy(
        tokenID, {""}, PERMISSION_GRANTED, PERMISSION_FIXED_BY_ADMIN_POLICY);
    EXPECT_EQ(ERR_PARAM_INVALID, ret);

    std::string permName(MAX_LENGTH + 1, 'A');
    ret = AccessTokenKit::SetPermissionStatusWithPolicy(
        tokenID, {""}, PERMISSION_GRANTED, PERMISSION_FIXED_BY_ADMIN_POLICY);
    EXPECT_EQ(ERR_PARAM_INVALID, ret);

    std::vector<std::string> permList = {};
    ret = RET_SUCCESS;
    ret = AccessTokenKit::SetPermissionStatusWithPolicy(
        tokenID, permList, PERMISSION_GRANTED, PERMISSION_FIXED_BY_ADMIN_POLICY);
    EXPECT_EQ(ERR_PARAM_INVALID, ret);

    permList.resize(MAX_PERMISSION_LIST_SIZE + 1, MICROPHONE);
    ret = AccessTokenKit::SetPermissionStatusWithPolicy(
        tokenID, permList, PERMISSION_GRANTED, PERMISSION_FIXED_BY_ADMIN_POLICY);
    EXPECT_EQ(ERR_PARAM_INVALID, ret);

    permList.clear();
    permList.push_back("ohos.permission.TEST_123");
    ret = AccessTokenKit::SetPermissionStatusWithPolicy(
        tokenID, permList, PERMISSION_GRANTED, PERMISSION_FIXED_BY_ADMIN_POLICY);
    EXPECT_EQ(ERR_PERMISSION_NOT_EXIST, ret);

    EXPECT_EQ(RET_SUCCESS, TestCommon::DeleteTestHapToken(tokenID));
}

/**
 * @tc.name: SetPermissionStatusWithPolicy004
 * @tc.desc: status exception test.
 * @tc.type: FUNC
 * @tc.require:Issue Number
 */
HWTEST_F(EdmPolicySetTest, SetPermissionStatusWithPolicy004, TestSize.Level0)
{
    LOGI(ATM_DOMAIN, ATM_TAG, "SetPermissionStatusWithPolicy004");

    g_testHapInfoParams.userID = MOCK_USER_ID_10001;
    AccessTokenIDEx tokenIdEx = TestCommon::AllocAndGrantHapTokenByTest(g_testHapInfoParams, g_testPolicyParams);
    AccessTokenID tokenID = tokenIdEx.tokenIdExStruct.tokenID;
    ASSERT_NE(INVALID_TOKENID, tokenID);

    MockNativeToken mock("edm");
    uint64_t selfTokenId = GetSelfTokenID();
    ASSERT_EQ(PERMISSION_GRANTED, AccessTokenKit::VerifyAccessToken(selfTokenId, MANAGE_EDM_POLICY, false));

    std::vector<std::string> permList = {MICROPHONE, CUSTOM_SCREEN_CAPTURE};
    uint32_t ret = RET_SUCCESS;
    ret = AccessTokenKit::SetPermissionStatusWithPolicy(
        tokenID, permList, 1, PERMISSION_FIXED_BY_ADMIN_POLICY);
    EXPECT_EQ(ERR_PARAM_INVALID, ret);

    EXPECT_EQ(RET_SUCCESS, TestCommon::DeleteTestHapToken(tokenID));
}

/**
 * @tc.name: SetPermissionStatusWithPolicy005
 * @tc.desc: flag exception test.
 * @tc.type: FUNC
 * @tc.require:Issue Number
 */
HWTEST_F(EdmPolicySetTest, SetPermissionStatusWithPolicy005, TestSize.Level0)
{
    LOGI(ATM_DOMAIN, ATM_TAG, "SetPermissionStatusWithPolicy005");

    g_testHapInfoParams.userID = MOCK_USER_ID_10001;
    AccessTokenIDEx tokenIdEx = TestCommon::AllocAndGrantHapTokenByTest(g_testHapInfoParams, g_testPolicyParams);
    AccessTokenID tokenID = tokenIdEx.tokenIdExStruct.tokenID;
    ASSERT_NE(INVALID_TOKENID, tokenID);

    MockNativeToken mock("edm");
    uint64_t selfTokenId = GetSelfTokenID();
    ASSERT_EQ(PERMISSION_GRANTED, AccessTokenKit::VerifyAccessToken(selfTokenId, MANAGE_EDM_POLICY, false));

    std::vector<std::string> permList = {MICROPHONE, CUSTOM_SCREEN_CAPTURE};

    EXPECT_EQ(ERR_PARAM_INVALID, AccessTokenKit::SetPermissionStatusWithPolicy(tokenID, permList, PERMISSION_DENIED,
        1<<9));
    EXPECT_EQ(ERR_PARAM_INVALID, AccessTokenKit::SetPermissionStatusWithPolicy(tokenID, permList, PERMISSION_GRANTED,
        1<<6));

    EXPECT_EQ(RET_SUCCESS, TestCommon::DeleteTestHapToken(tokenID));
}

/**
 * @tc.name: SetPermissionStatusWithPolicy006
 * @tc.desc: hap unauthorized testing.
 * @tc.type: FUNC
 * @tc.require:Issue Number
 */
HWTEST_F(EdmPolicySetTest, SetPermissionStatusWithPolicy006, TestSize.Level0)
{
    LOGI(ATM_DOMAIN, ATM_TAG, "SetPermissionStatusWithPolicy006");

    g_testHapInfoParams.userID = MOCK_USER_ID_10001;
    AccessTokenIDEx tokenIdEx = TestCommon::AllocAndGrantHapTokenByTest(g_testHapInfoParams, g_testPolicyParams);
    AccessTokenID tokenID = tokenIdEx.tokenIdExStruct.tokenID;
    ASSERT_NE(INVALID_TOKENID, tokenID);

    MockNativeToken mock("edm");
    uint64_t selfTokenId = GetSelfTokenID();
    ASSERT_EQ(PERMISSION_GRANTED, AccessTokenKit::VerifyAccessToken(selfTokenId, MANAGE_EDM_POLICY, false));

    std::vector<std::string> permList = {CAMERA};
    uint32_t ret = RET_SUCCESS;
    ret = AccessTokenKit::SetPermissionStatusWithPolicy(
        tokenID, permList, PERMISSION_GRANTED, PERMISSION_FIXED_BY_ADMIN_POLICY);
    EXPECT_EQ(ERR_PARAM_INVALID, ret);

    EXPECT_EQ(RET_SUCCESS, TestCommon::DeleteTestHapToken(tokenID));
}

/**
 * @tc.name: SetPermissionStatusWithPolicy007
 * @tc.desc: The caller has no permission to test.
 * @tc.type: FUNC
 * @tc.require:Issue Number
 */
HWTEST_F(EdmPolicySetTest, SetPermissionStatusWithPolicy007, TestSize.Level0)
{
    LOGI(ATM_DOMAIN, ATM_TAG, "SetPermissionStatusWithPolicy007");

    g_testHapInfoParams.userID = MOCK_USER_ID_10001;
    AccessTokenIDEx tokenIdEx = TestCommon::AllocAndGrantHapTokenByTest(g_testHapInfoParams, g_testPolicyParams);
    AccessTokenID tokenID = tokenIdEx.tokenIdExStruct.tokenID;
    ASSERT_NE(INVALID_TOKENID, tokenID);

    MockNativeToken mock("foundation");

    std::vector<std::string> permList = {MICROPHONE, CUSTOM_SCREEN_CAPTURE};
    uint32_t ret = RET_SUCCESS;
    int32_t selfUid = getuid();
    setuid(10001);
    ret = AccessTokenKit::SetPermissionStatusWithPolicy(
        tokenID, permList, PERMISSION_GRANTED, PERMISSION_FIXED_BY_ADMIN_POLICY);
    EXPECT_EQ(ERR_PERMISSION_DENIED, ret);
    setuid(selfUid);
    EXPECT_EQ(RET_SUCCESS, TestCommon::DeleteTestHapToken(tokenID));
}

/**
 * @tc.name: SetPermissionStatusWithPolicy008
 * @tc.desc: Permission priority test.
 * @tc.type: FUNC
 * @tc.require:Issue Number
 */
HWTEST_F(EdmPolicySetTest, SetPermissionStatusWithPolicy008, TestSize.Level0)
{
    LOGI(ATM_DOMAIN, ATM_TAG, "SetPermissionStatusWithPolicy008");

    g_testHapInfoParams.userID = MOCK_USER_ID_10001;
    AccessTokenIDEx tokenIdEx = TestCommon::AllocAndGrantHapTokenByTest(g_testHapInfoParams, g_testPolicyParams);
    AccessTokenID tokenID = tokenIdEx.tokenIdExStruct.tokenID;
    ASSERT_NE(INVALID_TOKENID, tokenID);
    MockNativeToken mock("edm");

    uint32_t flag = 0;
    uint32_t ret = RET_SUCCESS;

    std::vector<std::string> permList = {CUSTOM_SCREEN_CAPTURE};
    ret = AccessTokenKit::SetPermissionStatusWithPolicy(
        tokenID, permList, PERMISSION_GRANTED, PERMISSION_ADMIN_POLICIES_CANCEL);
    EXPECT_EQ(ERR_PARAM_INVALID, ret);
    EXPECT_EQ(RET_SUCCESS, AccessTokenKit::GetPermissionFlag(tokenID, CUSTOM_SCREEN_CAPTURE, flag));
    EXPECT_EQ(PERMISSION_DEFAULT_FLAG, flag);

    // 1. set flag is PERMISSION_USER_FIXED.
    EXPECT_EQ(RET_SUCCESS, TestCommon::GrantPermissionByTest(tokenID, CUSTOM_SCREEN_CAPTURE, PERMISSION_USER_FIXED));
    EXPECT_EQ(RET_SUCCESS, AccessTokenKit::GetPermissionFlag(tokenID, CUSTOM_SCREEN_CAPTURE, flag));
    EXPECT_EQ(PERMISSION_USER_FIXED, flag);

    // 2. set flag is PERMISSION_FIXED_BY_ADMIN_POLICY.
    ret = AccessTokenKit::SetPermissionStatusWithPolicy(
        tokenID, permList, PERMISSION_GRANTED, PERMISSION_FIXED_BY_ADMIN_POLICY);
    EXPECT_EQ(RET_SUCCESS, ret);
    EXPECT_EQ(RET_SUCCESS, AccessTokenKit::GetPermissionFlag(tokenID, CUSTOM_SCREEN_CAPTURE, flag));
    EXPECT_EQ(PERMISSION_FIXED_BY_ADMIN_POLICY, flag);

    // 3. can't clear PERMISSION_FIXED_BY_ADMIN_POLICY.
    EXPECT_EQ(RET_SUCCESS, TestCommon::ClearUserGrantedPermissionStateByTest(tokenID));
    EXPECT_EQ(RET_SUCCESS, AccessTokenKit::GetPermissionFlag(tokenID, CUSTOM_SCREEN_CAPTURE, flag));
    EXPECT_EQ(PERMISSION_FIXED_BY_ADMIN_POLICY, flag);
    EXPECT_EQ(PERMISSION_GRANTED, AccessTokenKit::VerifyAccessToken(tokenID, CUSTOM_SCREEN_CAPTURE, false));

    // 4. can't set flag is PERMISSION_USER_FIXED.
    EXPECT_EQ(ERR_PERMISSION_RESTRICTED,
        TestCommon::GrantPermissionByTest(tokenID, CUSTOM_SCREEN_CAPTURE, PERMISSION_USER_FIXED));
    EXPECT_EQ(RET_SUCCESS, AccessTokenKit::GetPermissionFlag(tokenID, CUSTOM_SCREEN_CAPTURE, flag));
    EXPECT_EQ(PERMISSION_FIXED_BY_ADMIN_POLICY, flag);

    // 5. can set flag is PERMISSION_SYSTEM_FIXED.
    EXPECT_EQ(RET_SUCCESS, TestCommon::GrantPermissionByTest(tokenID, CUSTOM_SCREEN_CAPTURE, PERMISSION_SYSTEM_FIXED));
    EXPECT_EQ(RET_SUCCESS, AccessTokenKit::GetPermissionFlag(tokenID, CUSTOM_SCREEN_CAPTURE, flag));
    EXPECT_EQ(PERMISSION_SYSTEM_FIXED, flag);

    // 6. can not set flag is PERMISSION_FIXED_BY_ADMIN_POLICY
    ret = AccessTokenKit::SetPermissionStatusWithPolicy(
        tokenID, permList, PERMISSION_GRANTED, PERMISSION_FIXED_BY_ADMIN_POLICY);
    EXPECT_EQ(ERR_PARAM_INVALID, ret);
    EXPECT_EQ(RET_SUCCESS, AccessTokenKit::GetPermissionFlag(tokenID, CUSTOM_SCREEN_CAPTURE, flag));
    EXPECT_EQ(PERMISSION_SYSTEM_FIXED, flag);

    EXPECT_EQ(RET_SUCCESS, TestCommon::DeleteTestHapToken(tokenID));
}

/**
 * @tc.name: EdmTestGrantPermission001
 * @tc.desc: Grant permission priority test.
 * @tc.type: FUNC
 * @tc.require:Issue Number
 */
HWTEST_F(EdmPolicySetTest, EdmTestGrantPermission001, TestSize.Level0)
{
    LOGI(ATM_DOMAIN, ATM_TAG, "EdmTestGrantPermission001");

    g_testHapInfoParams.userID = MOCK_USER_ID_10001;
    AccessTokenIDEx tokenIdEx = TestCommon::AllocAndGrantHapTokenByTest(g_testHapInfoParams, g_testPolicyParams);
    AccessTokenID tokenID = tokenIdEx.tokenIdExStruct.tokenID;
    ASSERT_NE(INVALID_TOKENID, tokenID);

    MockNativeToken mock("edm");
    uint32_t flag = 0;

    // 1. set flag is PERMISSION_FIXED_BY_ADMIN_POLICY.
    std::vector<std::string> permList = {CUSTOM_SCREEN_CAPTURE};
    uint32_t ret = RET_SUCCESS;
    ret = AccessTokenKit::SetPermissionStatusWithPolicy(
        tokenID, permList, PERMISSION_GRANTED, PERMISSION_FIXED_BY_ADMIN_POLICY);
    EXPECT_EQ(RET_SUCCESS, ret);
    EXPECT_EQ(RET_SUCCESS, AccessTokenKit::GetPermissionFlag(tokenID, CUSTOM_SCREEN_CAPTURE, flag));
    EXPECT_EQ(PERMISSION_FIXED_BY_ADMIN_POLICY, flag);
    EXPECT_EQ(PERMISSION_GRANTED, AccessTokenKit::VerifyAccessToken(tokenID, CUSTOM_SCREEN_CAPTURE, false));

    // 2. can't grant flag is PERMISSION_USER_FIXED
    ret = TestCommon::GrantPermissionByTest(tokenID, CUSTOM_SCREEN_CAPTURE, PERMISSION_USER_FIXED);
    EXPECT_EQ(ERR_PERMISSION_RESTRICTED, ret);
    EXPECT_EQ(RET_SUCCESS, AccessTokenKit::GetPermissionFlag(tokenID, CUSTOM_SCREEN_CAPTURE, flag));
    EXPECT_EQ(PERMISSION_FIXED_BY_ADMIN_POLICY, flag);
    EXPECT_EQ(PERMISSION_GRANTED, AccessTokenKit::VerifyAccessToken(tokenID, CUSTOM_SCREEN_CAPTURE, false));

    // 3. set flag is PERMISSION_ADMIN_POLICIES_CANCEL.
    ret = AccessTokenKit::SetPermissionStatusWithPolicy(
        tokenID, permList, PERMISSION_GRANTED, PERMISSION_ADMIN_POLICIES_CANCEL);
    EXPECT_EQ(RET_SUCCESS, ret);
    EXPECT_EQ(RET_SUCCESS, AccessTokenKit::GetPermissionFlag(tokenID, CUSTOM_SCREEN_CAPTURE, flag));
    EXPECT_EQ(PERMISSION_ADMIN_POLICIES_CANCEL, flag);
    EXPECT_EQ(PERMISSION_GRANTED, AccessTokenKit::VerifyAccessToken(tokenID, CUSTOM_SCREEN_CAPTURE, false));

    // 4. can grant flag is PERMISSION_USER_FIXED
    ret = TestCommon::GrantPermissionByTest(tokenID, CUSTOM_SCREEN_CAPTURE, PERMISSION_USER_FIXED);
    EXPECT_EQ(RET_SUCCESS, ret);
    EXPECT_EQ(RET_SUCCESS, AccessTokenKit::GetPermissionFlag(tokenID, CUSTOM_SCREEN_CAPTURE, flag));
    EXPECT_EQ(PERMISSION_USER_FIXED, flag);
    EXPECT_EQ(PERMISSION_GRANTED, AccessTokenKit::VerifyAccessToken(tokenID, CUSTOM_SCREEN_CAPTURE, false));

    EXPECT_EQ(RET_SUCCESS, TestCommon::DeleteTestHapToken(tokenID));
}

/**
 * @tc.name: EdmTestRevokePermission001
 * @tc.desc: Revoke permission priority test.
 * @tc.type: FUNC
 * @tc.require:Issue Number
 */
HWTEST_F(EdmPolicySetTest, EdmTestRevokePermission001, TestSize.Level0)
{
    LOGI(ATM_DOMAIN, ATM_TAG, "EdmTestRevokePermission001");

    g_testHapInfoParams.userID = MOCK_USER_ID_10001;
    AccessTokenIDEx tokenIdEx = TestCommon::AllocAndGrantHapTokenByTest(g_testHapInfoParams, g_testPolicyParams);
    AccessTokenID tokenID = tokenIdEx.tokenIdExStruct.tokenID;
    ASSERT_NE(INVALID_TOKENID, tokenID);

    MockNativeToken mock("edm");
    uint32_t flag = 0;

    // 1. set flag is PERMISSION_FIXED_BY_ADMIN_POLICY.
    std::vector<std::string> permList = {CUSTOM_SCREEN_CAPTURE};
    uint32_t ret = RET_SUCCESS;
    ret = AccessTokenKit::SetPermissionStatusWithPolicy(
        tokenID, permList, PERMISSION_GRANTED, PERMISSION_FIXED_BY_ADMIN_POLICY);
    EXPECT_EQ(RET_SUCCESS, ret);
    EXPECT_EQ(RET_SUCCESS, AccessTokenKit::GetPermissionFlag(tokenID, CUSTOM_SCREEN_CAPTURE, flag));
    EXPECT_EQ(PERMISSION_FIXED_BY_ADMIN_POLICY, flag);
    EXPECT_EQ(PERMISSION_GRANTED, AccessTokenKit::VerifyAccessToken(tokenID, CUSTOM_SCREEN_CAPTURE, false));

    // 2. can't revoke flag is PERMISSION_USER_FIXED
    ret = TestCommon::RevokePermissionByTest(tokenID, CUSTOM_SCREEN_CAPTURE, PERMISSION_USER_FIXED);
    EXPECT_EQ(ERR_PERMISSION_RESTRICTED, ret);
    EXPECT_EQ(RET_SUCCESS, AccessTokenKit::GetPermissionFlag(tokenID, CUSTOM_SCREEN_CAPTURE, flag));
    EXPECT_EQ(PERMISSION_FIXED_BY_ADMIN_POLICY, flag);
    EXPECT_EQ(PERMISSION_GRANTED, AccessTokenKit::VerifyAccessToken(tokenID, CUSTOM_SCREEN_CAPTURE, false));

    // 3. set flag is PERMISSION_ADMIN_POLICIES_CANCEL.
    ret = AccessTokenKit::SetPermissionStatusWithPolicy(
        tokenID, permList, PERMISSION_GRANTED, PERMISSION_ADMIN_POLICIES_CANCEL);
    EXPECT_EQ(RET_SUCCESS, ret);
    EXPECT_EQ(RET_SUCCESS, AccessTokenKit::GetPermissionFlag(tokenID, CUSTOM_SCREEN_CAPTURE, flag));
    EXPECT_EQ(PERMISSION_ADMIN_POLICIES_CANCEL, flag);
    EXPECT_EQ(PERMISSION_GRANTED, AccessTokenKit::VerifyAccessToken(tokenID, CUSTOM_SCREEN_CAPTURE, false));

    // 4. can revoke flag is PERMISSION_USER_FIXED
    ret = TestCommon::RevokePermissionByTest(tokenID, CUSTOM_SCREEN_CAPTURE, PERMISSION_USER_FIXED);
    EXPECT_EQ(RET_SUCCESS, ret);
    EXPECT_EQ(RET_SUCCESS, AccessTokenKit::GetPermissionFlag(tokenID, CUSTOM_SCREEN_CAPTURE, flag));
    EXPECT_EQ(PERMISSION_USER_FIXED, flag);
    EXPECT_EQ(PERMISSION_DENIED, AccessTokenKit::VerifyAccessToken(tokenID, CUSTOM_SCREEN_CAPTURE, false));

    EXPECT_EQ(RET_SUCCESS, TestCommon::DeleteTestHapToken(tokenID));
}

/**
 * @tc.name: EdmTestClearUserGrantedPermissionState001
 * @tc.desc: Clear user granted permission state test.
 * @tc.type: FUNC
 * @tc.require:Issue Number
 */
HWTEST_F(EdmPolicySetTest, EdmTestClearUserGrantedPermissionState001, TestSize.Level0)
{
    LOGI(ATM_DOMAIN, ATM_TAG, "EdmTestClearUserGrantedPermissionState001");

    g_testHapInfoParams.userID = MOCK_USER_ID_10001;
    AccessTokenIDEx tokenIdEx = TestCommon::AllocAndGrantHapTokenByTest(g_testHapInfoParams, g_testPolicyParams);
    AccessTokenID tokenID = tokenIdEx.tokenIdExStruct.tokenID;
    ASSERT_NE(INVALID_TOKENID, tokenID);

    MockNativeToken mock("edm");
    uint32_t flag = 0;

    // 1. set flag is PERMISSION_FIXED_BY_ADMIN_POLICY.
    std::vector<std::string> permList = {CUSTOM_SCREEN_CAPTURE};
    uint32_t ret = RET_SUCCESS;
    ret = AccessTokenKit::SetPermissionStatusWithPolicy(
        tokenID, permList, PERMISSION_GRANTED, PERMISSION_FIXED_BY_ADMIN_POLICY);
    EXPECT_EQ(RET_SUCCESS, ret);
    EXPECT_EQ(RET_SUCCESS, AccessTokenKit::GetPermissionFlag(tokenID, CUSTOM_SCREEN_CAPTURE, flag));
    EXPECT_EQ(PERMISSION_FIXED_BY_ADMIN_POLICY, flag);
    EXPECT_EQ(PERMISSION_GRANTED, AccessTokenKit::VerifyAccessToken(tokenID, CUSTOM_SCREEN_CAPTURE, false));

    // 2. can't clear flag is PERMISSION_FIXED_BY_ADMIN_POLICY
    ret = TestCommon::ClearUserGrantedPermissionStateByTest(tokenID);
    EXPECT_EQ(RET_SUCCESS, ret);
    EXPECT_EQ(RET_SUCCESS, AccessTokenKit::GetPermissionFlag(tokenID, CUSTOM_SCREEN_CAPTURE, flag));
    EXPECT_EQ(PERMISSION_FIXED_BY_ADMIN_POLICY, flag);
    EXPECT_EQ(PERMISSION_GRANTED, AccessTokenKit::VerifyAccessToken(tokenID, CUSTOM_SCREEN_CAPTURE, false));

    // 3. set flag is PERMISSION_ADMIN_POLICIES_CANCEL.
    ret = AccessTokenKit::SetPermissionStatusWithPolicy(
        tokenID, permList, PERMISSION_GRANTED, PERMISSION_ADMIN_POLICIES_CANCEL);
    EXPECT_EQ(RET_SUCCESS, ret);
    EXPECT_EQ(RET_SUCCESS, AccessTokenKit::GetPermissionFlag(tokenID, CUSTOM_SCREEN_CAPTURE, flag));
    EXPECT_EQ(PERMISSION_ADMIN_POLICIES_CANCEL, flag);
    EXPECT_EQ(PERMISSION_GRANTED, AccessTokenKit::VerifyAccessToken(tokenID, CUSTOM_SCREEN_CAPTURE, false));

    // 4. can clear flag is PERMISSION_ADMIN_POLICIES_CANCEL
    ret = TestCommon::ClearUserGrantedPermissionStateByTest(tokenID);
    EXPECT_EQ(RET_SUCCESS, ret);
    EXPECT_EQ(RET_SUCCESS, AccessTokenKit::GetPermissionFlag(tokenID, CUSTOM_SCREEN_CAPTURE, flag));
    EXPECT_EQ(PERMISSION_DEFAULT_FLAG, flag);
    EXPECT_EQ(PERMISSION_DENIED, AccessTokenKit::VerifyAccessToken(tokenID, CUSTOM_SCREEN_CAPTURE, false));

    EXPECT_EQ(RET_SUCCESS, TestCommon::DeleteTestHapToken(tokenID));
}

/**
 * @tc.name: EdmTestGetSelfPermissionsState001
 * @tc.desc: GetSelfPermissionsState test.
 * @tc.type: FUNC
 * @tc.require:Issue Number
 */
HWTEST_F(EdmPolicySetTest, EdmTestGetSelfPermissionsState001, TestSize.Level0)
{
    LOGI(ATM_DOMAIN, ATM_TAG, "EdmTestGetSelfPermissionsState001");

    g_testHapInfoParams.userID = MOCK_USER_ID_10001;
    AccessTokenIDEx tokenIdEx = TestCommon::AllocAndGrantHapTokenByTest(g_testHapInfoParams, g_testPolicyParams);
    AccessTokenID tokenID = tokenIdEx.tokenIdExStruct.tokenID;
    ASSERT_NE(INVALID_TOKENID, tokenID);

    MockNativeToken mock("edm");
    uint64_t selfTokenId = GetSelfTokenID();
    uint32_t flag = 0;

    // 1. set flag is PERMISSION_FIXED_BY_ADMIN_POLICY.
    std::vector<std::string> permList = {CUSTOM_SCREEN_CAPTURE};
    uint32_t ret = RET_SUCCESS;
    ret = AccessTokenKit::SetPermissionStatusWithPolicy(
        tokenID, permList, PERMISSION_DENIED, PERMISSION_FIXED_BY_ADMIN_POLICY);
    EXPECT_EQ(RET_SUCCESS, ret);
    EXPECT_EQ(RET_SUCCESS, AccessTokenKit::GetPermissionFlag(tokenID, CUSTOM_SCREEN_CAPTURE, flag));
    EXPECT_EQ(PERMISSION_FIXED_BY_ADMIN_POLICY, flag);
    EXPECT_EQ(PERMISSION_DENIED, AccessTokenKit::VerifyAccessToken(tokenID, CUSTOM_SCREEN_CAPTURE, false));

    // 2. get permission state is FORBIDDEN_OPER.
    std::vector<PermissionListState> permsList = {{CUSTOM_SCREEN_CAPTURE}};
    PermissionGrantInfo info;
    SetSelfTokenID(tokenID);
    EXPECT_EQ(FORBIDDEN_OPER, AccessTokenKit::GetSelfPermissionsState(permsList, info));
    EXPECT_EQ(FORBIDDEN_OPER, permsList[0].state);
    SetSelfTokenID(selfTokenId);

    // 3. set flag is PERMISSION_ADMIN_POLICIES_CANCEL.
    ret = AccessTokenKit::SetPermissionStatusWithPolicy(
        tokenID, permList, PERMISSION_DENIED, PERMISSION_ADMIN_POLICIES_CANCEL);
    EXPECT_EQ(RET_SUCCESS, ret);
    EXPECT_EQ(RET_SUCCESS, AccessTokenKit::GetPermissionFlag(tokenID, CUSTOM_SCREEN_CAPTURE, flag));
    EXPECT_EQ(PERMISSION_ADMIN_POLICIES_CANCEL, flag);
    EXPECT_EQ(PERMISSION_DENIED, AccessTokenKit::VerifyAccessToken(tokenID, CUSTOM_SCREEN_CAPTURE, false));

    // 4. get permission state is SETTING_OPER.
    SetSelfTokenID(tokenID);
    EXPECT_EQ(PASS_OPER, AccessTokenKit::GetSelfPermissionsState(permsList, info));
    EXPECT_EQ(SETTING_OPER, permsList[0].state);
    SetSelfTokenID(selfTokenId);

    EXPECT_EQ(RET_SUCCESS, TestCommon::DeleteTestHapToken(tokenID));
}


/**
 * @tc.name: EdmTestUpdateHapToken001
 * @tc.desc: GetSelfPermissionsState test with admin fixed status.
 * @tc.type: FUNC
 * @tc.require:Issue Number
 */
HWTEST_F(EdmPolicySetTest, EdmTestUpdateHapToken001, TestSize.Level0)
{
    LOGI(ATM_DOMAIN, ATM_TAG, "EdmTestUpdateHapToken001");

    g_testHapInfoParams.userID = MOCK_USER_ID_10001;
    AccessTokenIDEx tokenIdEx = TestCommon::AllocAndGrantHapTokenByTest(g_testHapInfoParams, g_testPolicyParams);
    AccessTokenID tokenID = tokenIdEx.tokenIdExStruct.tokenID;
    ASSERT_NE(INVALID_TOKENID, tokenID);

    MockNativeToken mock("edm");
    uint32_t flag = 0;

    // 1. set flag is PERMISSION_FIXED_BY_ADMIN_POLICY.
    std::vector<std::string> permList = {CUSTOM_SCREEN_CAPTURE};
    uint32_t ret = RET_SUCCESS;
    ret = AccessTokenKit::SetPermissionStatusWithPolicy(
        tokenID, permList, PERMISSION_GRANTED, PERMISSION_FIXED_BY_ADMIN_POLICY);
    EXPECT_EQ(RET_SUCCESS, ret);
    EXPECT_EQ(RET_SUCCESS, AccessTokenKit::GetPermissionFlag(tokenID, CUSTOM_SCREEN_CAPTURE, flag));
    EXPECT_EQ(PERMISSION_FIXED_BY_ADMIN_POLICY, flag);
    EXPECT_EQ(PERMISSION_GRANTED, AccessTokenKit::VerifyAccessToken(tokenID, CUSTOM_SCREEN_CAPTURE, false));

    // 2. can't UpdateHapToken flag is PERMISSION_PRE_AUTHORIZED_CANCELABLE.
    UpdateHapInfoParams info;
    info.appIDDesc = "TEST";
    info.apiVersion = 12;
    info.isSystemApp = false;
    {
        MockNativeToken mock("foundation");
        ret = AccessTokenKit::UpdateHapToken(tokenIdEx, info, g_testPolicyParams02);
    }
    EXPECT_EQ(RET_SUCCESS, ret);
    EXPECT_EQ(RET_SUCCESS, AccessTokenKit::GetPermissionFlag(tokenID, CUSTOM_SCREEN_CAPTURE, flag));
    EXPECT_EQ(PERMISSION_FIXED_BY_ADMIN_POLICY, flag);
    EXPECT_EQ(PERMISSION_GRANTED, AccessTokenKit::VerifyAccessToken(tokenID, CUSTOM_SCREEN_CAPTURE, false));

    // 3. can UpdateHapToken flag is PERMISSION_SYSTEM_FIXED.
    {
        MockNativeToken mock("foundation");
        ret = AccessTokenKit::UpdateHapToken(tokenIdEx, info, g_testPolicyParams03);
    }
    EXPECT_EQ(RET_SUCCESS, ret);
    EXPECT_EQ(RET_SUCCESS, AccessTokenKit::GetPermissionFlag(tokenID, CUSTOM_SCREEN_CAPTURE, flag));
    EXPECT_EQ(PERMISSION_SYSTEM_FIXED, flag);
    EXPECT_EQ(PERMISSION_GRANTED, AccessTokenKit::VerifyAccessToken(tokenID, CUSTOM_SCREEN_CAPTURE, false));
}


/**
 * @tc.name: EdmTestUpdateHapToken002
 * @tc.desc: UpdateHapToken test with admin cancel status.
 * @tc.type: FUNC
 * @tc.require:Issue Number
 */
HWTEST_F(EdmPolicySetTest, EdmTestUpdateHapToken002, TestSize.Level0)
{
    LOGI(ATM_DOMAIN, ATM_TAG, "EdmTestUpdateHapToken002");

    g_testHapInfoParams.userID = MOCK_USER_ID_10001;
    AccessTokenIDEx tokenIdEx = TestCommon::AllocAndGrantHapTokenByTest(g_testHapInfoParams, g_testPolicyParams);
    AccessTokenID tokenID = tokenIdEx.tokenIdExStruct.tokenID;
    ASSERT_NE(INVALID_TOKENID, tokenID);

    MockNativeToken mock("edm");
    uint32_t flag = 0;

    // 1. set flag is PERMISSION_FIXED_BY_ADMIN_POLICY.
    std::vector<std::string> permList = {CUSTOM_SCREEN_CAPTURE};
    uint32_t ret = RET_SUCCESS;
    ret = AccessTokenKit::SetPermissionStatusWithPolicy(
        tokenID, permList, PERMISSION_GRANTED, PERMISSION_FIXED_BY_ADMIN_POLICY);
    EXPECT_EQ(RET_SUCCESS, ret);
    EXPECT_EQ(RET_SUCCESS, AccessTokenKit::GetPermissionFlag(tokenID, CUSTOM_SCREEN_CAPTURE, flag));
    EXPECT_EQ(PERMISSION_FIXED_BY_ADMIN_POLICY, flag);
    EXPECT_EQ(PERMISSION_GRANTED, AccessTokenKit::VerifyAccessToken(tokenID, CUSTOM_SCREEN_CAPTURE, false));

    // 2. set flag is PERMISSION_ADMIN_POLICIES_CANCEL.
    ret = AccessTokenKit::SetPermissionStatusWithPolicy(
        tokenID, permList, PERMISSION_GRANTED, PERMISSION_ADMIN_POLICIES_CANCEL);
    EXPECT_EQ(RET_SUCCESS, ret);
    EXPECT_EQ(RET_SUCCESS, AccessTokenKit::GetPermissionFlag(tokenID, CUSTOM_SCREEN_CAPTURE, flag));
    EXPECT_EQ(PERMISSION_ADMIN_POLICIES_CANCEL, flag);
    EXPECT_EQ(PERMISSION_GRANTED, AccessTokenKit::VerifyAccessToken(tokenID, CUSTOM_SCREEN_CAPTURE, false));

    // 3. can UpdateHapToken flag is PERMISSION_PRE_AUTHORIZED_CANCELABLE.
    UpdateHapInfoParams info;
    info.appIDDesc = "TEST";
    info.apiVersion = 12;
    info.isSystemApp = false;
    {
        MockNativeToken mock("foundation");
        ret = AccessTokenKit::UpdateHapToken(tokenIdEx, info, g_testPolicyParams02);
    }
    EXPECT_EQ(RET_SUCCESS, ret);
    EXPECT_EQ(RET_SUCCESS, AccessTokenKit::GetPermissionFlag(tokenID, CUSTOM_SCREEN_CAPTURE, flag));
    EXPECT_EQ(PERMISSION_DEFAULT_FLAG, flag); // PERMISSION_PRE_AUTHORIZED_CANCELABLE not return
    EXPECT_EQ(PERMISSION_GRANTED, AccessTokenKit::VerifyAccessToken(tokenID, CUSTOM_SCREEN_CAPTURE, false));

    EXPECT_EQ(RET_SUCCESS, TestCommon::DeleteTestHapToken(tokenID));
}

/**
 * @tc.name: EdmTestUpdateHapToken003
 * @tc.desc: UpdateHapToken test with system fixed status.
 * @tc.type: FUNC
 * @tc.require:Issue Number
 */
HWTEST_F(EdmPolicySetTest, EdmTestUpdateHapToken003, TestSize.Level0)
{
    LOGI(ATM_DOMAIN, ATM_TAG, "EdmTestUpdateHapToken003");

    g_testHapInfoParams.userID = MOCK_USER_ID_10001;
    AccessTokenIDEx tokenIdEx = TestCommon::AllocAndGrantHapTokenByTest(g_testHapInfoParams, g_testPolicyParams);
    AccessTokenID tokenID = tokenIdEx.tokenIdExStruct.tokenID;
    ASSERT_NE(INVALID_TOKENID, tokenID);

    MockNativeToken mock("edm");
    uint32_t flag = 0;

    // 1. set flag is PERMISSION_FIXED_BY_ADMIN_POLICY.
    std::vector<std::string> permList = {CUSTOM_SCREEN_CAPTURE};
    uint32_t ret = RET_SUCCESS;
    ret = AccessTokenKit::SetPermissionStatusWithPolicy(
        tokenID, permList, PERMISSION_GRANTED, PERMISSION_FIXED_BY_ADMIN_POLICY);
    EXPECT_EQ(RET_SUCCESS, ret);
    EXPECT_EQ(RET_SUCCESS, AccessTokenKit::GetPermissionFlag(tokenID, CUSTOM_SCREEN_CAPTURE, flag));
    EXPECT_EQ(PERMISSION_FIXED_BY_ADMIN_POLICY, flag);
    EXPECT_EQ(PERMISSION_GRANTED, AccessTokenKit::VerifyAccessToken(tokenID, CUSTOM_SCREEN_CAPTURE, false));

    // 2. set flag is PERMISSION_ADMIN_POLICIES_CANCEL.
    ret = AccessTokenKit::SetPermissionStatusWithPolicy(
        tokenID, permList, PERMISSION_GRANTED, PERMISSION_ADMIN_POLICIES_CANCEL);
    EXPECT_EQ(RET_SUCCESS, ret);
    EXPECT_EQ(RET_SUCCESS, AccessTokenKit::GetPermissionFlag(tokenID, CUSTOM_SCREEN_CAPTURE, flag));
    EXPECT_EQ(PERMISSION_ADMIN_POLICIES_CANCEL, flag);
    EXPECT_EQ(PERMISSION_GRANTED, AccessTokenKit::VerifyAccessToken(tokenID, CUSTOM_SCREEN_CAPTURE, false));

    // 3. can UpdateHapToken flag is PERMISSION_SYSTEM_FIXED.
    UpdateHapInfoParams info;
    info.appIDDesc = "TEST";
    info.apiVersion = 12;
    info.isSystemApp = false;
    {
        MockNativeToken mock("foundation");
        ret = AccessTokenKit::UpdateHapToken(tokenIdEx, info, g_testPolicyParams03);
    }
    EXPECT_EQ(RET_SUCCESS, ret);
    EXPECT_EQ(RET_SUCCESS, AccessTokenKit::GetPermissionFlag(tokenID, CUSTOM_SCREEN_CAPTURE, flag));
    EXPECT_EQ(PERMISSION_SYSTEM_FIXED, flag);
    EXPECT_EQ(PERMISSION_GRANTED, AccessTokenKit::VerifyAccessToken(tokenID, CUSTOM_SCREEN_CAPTURE, false));

    EXPECT_EQ(RET_SUCCESS, TestCommon::DeleteTestHapToken(tokenID));
}
