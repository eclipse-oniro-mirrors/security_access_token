/*
 * Copyright (c) 2024-2026 Huawei Device Co., Ltd.
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
namespace OHOS {
namespace Security {
namespace AccessToken {
namespace {
static const uint32_t MOCK_USER_ID_10001 = 10001;
static const uint32_t MOCK_USER_ID_10002 = 10002;
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
    .bundleName = "EdmPolicySetTest",
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

PermissionStateFull g_infoManagerCustomScreenCaptureState03 = {
    .permissionName = CUSTOM_SCREEN_CAPTURE,
    .isGeneral = true,
    .resDeviceID = {"local2"},
    .grantStatus = {PermissionState::PERMISSION_GRANTED},
    .grantFlags = {PERMISSION_FIXED_BY_ADMIN_POLICY}
};

PermissionStateFull g_infoManagerCustomScreenCaptureState04 = {
    .permissionName = CUSTOM_SCREEN_CAPTURE,
    .isGeneral = true,
    .resDeviceID = {"local2"},
    .grantStatus = {PermissionState::PERMISSION_GRANTED},
    .grantFlags = {PERMISSION_ADMIN_POLICIES_CANCEL}
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

HapPolicyParams g_testPolicyParams04 = {
    .apl = APL_SYSTEM_CORE,
    .domain = "test.domain2",
    .preAuthorizationInfo = {
        {
            .permissionName = CUSTOM_SCREEN_CAPTURE,
            .userCancelable = false,
        },
    },
    .permStateList = {
        g_infoManagerCustomScreenCaptureState03
    }
};

HapPolicyParams g_testPolicyParams05 = {
    .apl = APL_SYSTEM_CORE,
    .domain = "test.domain2",
    .preAuthorizationInfo = {
        {
            .permissionName = CUSTOM_SCREEN_CAPTURE,
            .userCancelable = false,
        },
    },
    .permStateList = {
        g_infoManagerCustomScreenCaptureState04
    }
};

std::vector<uint32_t> g_permFlagList = {
    PERMISSION_DEFAULT_FLAG,
    PERMISSION_COMPONENT_SET,
    PERMISSION_USER_SET,
    PERMISSION_USER_FIXED,
    PERMISSION_PRE_AUTHORIZED_CANCELABLE,
    PERMISSION_FIXED_FOR_SECURITY_POLICY,
    // PERMISSION_ALLOW_THIS_TIME
};

UpdateHapInfoParams g_updateHapInfo = {
    .appIDDesc = "TEST",
    .apiVersion = 12,
    .isSystemApp = false
};

uint64_t g_selfShellTokenId;
static MockHapToken* g_mock = nullptr;
}

void EdmPolicySetTest::TearDownTestCase()
{
    AccessTokenIDEx tokenIdEx = TestCommon::GetHapTokenIdFromBundle(
        g_testHapInfoParams.userID, g_testHapInfoParams.bundleName, g_testHapInfoParams.instIndex);
    TestCommon::DeleteTestHapToken(tokenIdEx.tokenIdExStruct.tokenID);

    g_testHapInfoParams.userID = MOCK_USER_ID_10001;
    tokenIdEx = TestCommon::GetHapTokenIdFromBundle(
        g_testHapInfoParams.userID, g_testHapInfoParams.bundleName, g_testHapInfoParams.instIndex);
    TestCommon::DeleteTestHapToken(tokenIdEx.tokenIdExStruct.tokenID);

    g_testHapInfoParams.userID = MOCK_USER_ID_10002;
    tokenIdEx = TestCommon::GetHapTokenIdFromBundle(
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
    reqPerm.emplace_back(REVOKE_SENSITIVE_PERMISSIONS);
    g_mock = new (std::nothrow) MockHapToken("EdmPolicySetMockTest", reqPerm);
    LOGI(ATM_DOMAIN, ATM_TAG, "SetUpTestCase ok.");
}

#ifdef SUPPORT_MANAGE_USER_POLICY
static uint32_t g_mockUserPolicy1 = 0;
static uint32_t g_mockUserPolicy2 = 0;
static const int32_t TIME_500_MS = 1000 * 500; // 500ms
static const int32_t TIME_3000_MS = 1000 * 3000; // 3s
uint32_t MocNativeTokenID(const char *processName)
{
    const char **dcapArray = new (std::nothrow) const char *[2];
    if (dcapArray == nullptr) {
        return 0;
    }
    dcapArray[0] = "AT_CAP";
    dcapArray[1] = "ST_CAP";
    uint64_t tokenId;
    const char **permArray = new (std::nothrow) const char *[2];
    if (permArray == nullptr) {
        return 0;
    }
    permArray[0] = "ohos.permission.GET_SENSITIVE_PERMISSIONS";
    permArray[1] = "ohos.permission.MANAGE_USER_POLICY";
    const char **acls = new (std::nothrow) const char *[1];
    if (acls == nullptr) {
        return 0;
    }
    acls[0] = "ohos.permission.test1";
    NativeTokenInfoParams infoInstance = {
        .dcapsNum = 2,
        .permsNum = 2,
        .aclsNum = 1,
        .dcaps = dcapArray,
        .perms = permArray,
        .acls = acls,
        .processName = processName,
        .aplStr = "system_core",
    };
    tokenId = GetAccessTokenId(&infoInstance);
    delete[] dcapArray;
    delete[] permArray;
    delete[] acls;
    return tokenId;
}

static void InitUserPolicyTestEnviroment()
{
    MockNativeToken mock("accesstoken_service");
    g_mockUserPolicy1 = AccessTokenKit::GetNativeTokenId("MockUserPolicy1");
    g_mockUserPolicy2 = AccessTokenKit::GetNativeTokenId("MockUserPolicy2");
    if ((g_mockUserPolicy1 != 0) && (g_mockUserPolicy2 != 0)) {
        return;
    }
    g_mockUserPolicy1 = MocNativeTokenID("MockUserPolicy1");
    g_mockUserPolicy2 = MocNativeTokenID("MockUserPolicy2");

    std::system("service_control stop accesstoken_service");
    usleep(TIME_500_MS);
    GTEST_LOG_(INFO) << "stop service, pidof accesstoken_service:";
    std::system("pidof accesstoken_service");

    std::system("service_control start accesstoken_service");
    usleep(TIME_3000_MS);
    GTEST_LOG_(INFO) << "restart service, pidof accesstoken_service:";
    std::system("pidof accesstoken_service");
}

static int32_t GetPermissionStatusFromCache(AccessTokenID tokenId, const std::string& permission)
{
    std::vector<PermissionStateFull> permStatList;
    EXPECT_EQ(RET_SUCCESS, AccessTokenKit::GetReqPermissions(tokenId, permStatList, true));
    for (const auto& permState : permStatList) {
        if (permState.permissionName == permission) {
            return permState.grantStatus[0];
        }
    }
    return PERMISSION_DENIED;
}

/**
 * @tc.name: SetUserPolicy001
 * @tc.desc: SetUserPolicy failed with invalid userPermissionPolicyList.
 * @tc.type: FUNC
 * @tc.require:Issue Number
 */
HWTEST_F(EdmPolicySetTest, SetUserPolicy001, TestSize.Level1)
{
    InitUserPolicyTestEnviroment(); // called by first testcase
    MockNativeToken userPolicyMock("MockUserPolicy1");
    std::vector<UserPermissionPolicy> permPolicyListEmpty;
    // empty
    EXPECT_EQ(AccessTokenError::ERR_PARAM_INVALID, AccessTokenKit::SetUserPolicy(permPolicyListEmpty));

    // oversize
    const int32_t invalidSize = 1025; // 1025 is invalid size.
    std::vector<UserPermissionPolicy> permPolicyListOverSize(invalidSize);
    EXPECT_EQ(AccessTokenError::ERR_PARAM_INVALID, AccessTokenKit::SetUserPolicy(permPolicyListOverSize));
}

/**
 * @tc.name: SetUserPolicy002
 * @tc.desc: SetUserPolicy failed with invalid userPolicyList.
 * @tc.type: FUNC
 * @tc.require:Issue Number
 */
HWTEST_F(EdmPolicySetTest, SetUserPolicy002, TestSize.Level1)
{
    MockNativeToken userPolicyMock("MockUserPolicy1");
    UserPermissionPolicy policy;
    policy.permissionName = "ohos.permission.INTERNET";
    std::vector<UserPermissionPolicy> permPolicyList;

    // empty userPolicyList
    EXPECT_EQ(AccessTokenError::ERR_PARAM_INVALID, AccessTokenKit::SetUserPolicy({ policy }));

    // oversize userPolicyList
    UserPolicy userPolicy;
    const int32_t invalidSize = 1025; // 1025 is invalid size.
    policy.userPolicyList.resize(invalidSize, userPolicy);
    EXPECT_EQ(AccessTokenError::ERR_PARAM_INVALID, AccessTokenKit::SetUserPolicy({ policy }));
}

/**
 * @tc.name: SetUserPolicy003
 * @tc.desc: SetUserPolicy failed: 1. invalid userId of userList; 2. invalid permission.
 * @tc.type: FUNC
 * @tc.require:Issue Number
 */
HWTEST_F(EdmPolicySetTest, SetUserPolicy003, TestSize.Level1)
{
    MockNativeToken userPolicyMock("MockUserPolicy1");
    UserPermissionPolicy policy = {
        .permissionName = INTERNET,
        .userPolicyList = {{ .userId = MOCK_USER_ID_10002, .isRestricted = true }}
    };

    // empty permission
    policy.permissionName = "";
    EXPECT_EQ(AccessTokenError::ERR_PARAM_INVALID, AccessTokenKit::SetUserPolicy({ policy }));

    // permission is oversize
    std::string permName(MAX_LENGTH + 1, 'A');
    policy.permissionName = permName;
    EXPECT_EQ(AccessTokenError::ERR_PARAM_INVALID, AccessTokenKit::SetUserPolicy({ policy }));

    // permission is noexist
    policy.permissionName = "test";
    EXPECT_EQ(AccessTokenError::ERR_PARAM_INVALID, AccessTokenKit::SetUserPolicy({ policy }));

    // permission is user_grant
    policy.permissionName = "ohos.permission.CAMERA";
    EXPECT_EQ(AccessTokenError::ERR_PARAM_INVALID, AccessTokenKit::SetUserPolicy({ policy }));

    // invalid userId
    policy.permissionName = "ohos.permission.INTERNET";
    policy.userPolicyList[0].userId = -1; // -1: invalid userId
    EXPECT_EQ(AccessTokenError::ERR_PARAM_INVALID, AccessTokenKit::SetUserPolicy({ policy }));
}

/**
 * @tc.name: SetUserPolicy004
 * @tc.desc: 1. SetUserPolicy; 2. Install hap, permission is restricted.
 * @tc.type: FUNC
 * @tc.require:Issue Number
 */
HWTEST_F(EdmPolicySetTest, SetUserPolicy004, TestSize.Level1)
{
    MockNativeToken userPolicyMock("MockUserPolicy1");
    UserPermissionPolicy policy = {
        .permissionName = INTERNET,
        .userPolicyList = {{ .userId = MOCK_USER_ID_10001, .isRestricted = true }}
    };
    EXPECT_EQ(RET_SUCCESS, AccessTokenKit::SetUserPolicy({ policy }));

    HapInfoParams testHapInfo = g_testHapInfoParams;
    testHapInfo.userID = MOCK_USER_ID_10001;
    AccessTokenIDEx fullIdUser1;
    EXPECT_EQ(RET_SUCCESS, TestCommon::AllocTestHapToken(testHapInfo, g_testPolicyParams, fullIdUser1));
    AccessTokenID tokenId = fullIdUser1.tokenIdExStruct.tokenID;

    // system_grant: Denied by VerifyAccessToken(restricted by policy)
    EXPECT_EQ(PERMISSION_DENIED, AccessTokenKit::VerifyAccessToken(tokenId, INTERNET));
    EXPECT_EQ(PERMISSION_GRANTED, GetPermissionStatusFromCache(tokenId, INTERNET));

    // clear policy, permission is restored
    EXPECT_EQ(RET_SUCCESS, AccessTokenKit::ClearUserPolicy({ INTERNET }));
    EXPECT_EQ(PERMISSION_GRANTED, AccessTokenKit::VerifyAccessToken(tokenId, INTERNET));
    EXPECT_EQ(PERMISSION_GRANTED, GetPermissionStatusFromCache(tokenId, INTERNET));

    EXPECT_EQ(RET_SUCCESS, TestCommon::DeleteTestHapToken(tokenId));
}

/**
 * @tc.name: SetUserPolicy005
 * @tc.desc: 1. Install hap, permission is restricted; 2. SetUserPolicy.
 * @tc.type: FUNC
 * @tc.require:Issue Number
 */
HWTEST_F(EdmPolicySetTest, SetUserPolicy005, TestSize.Level1)
{
    MockNativeToken userPolicyMock("MockUserPolicy1");
    HapInfoParams testHapInfo = g_testHapInfoParams;
    testHapInfo.userID = MOCK_USER_ID_10001;
    AccessTokenIDEx fullIdUser1;
    EXPECT_EQ(RET_SUCCESS, TestCommon::AllocTestHapToken(testHapInfo, g_testPolicyParams, fullIdUser1));
    AccessTokenID tokenId = fullIdUser1.tokenIdExStruct.tokenID;

    // system_grant: granted defaultly
    EXPECT_EQ(PERMISSION_GRANTED, AccessTokenKit::VerifyAccessToken(tokenId, INTERNET));
    EXPECT_EQ(PERMISSION_GRANTED, GetPermissionStatusFromCache(tokenId, INTERNET));

    UserPermissionPolicy policy = {
        .permissionName = INTERNET,
        .userPolicyList = {{ .userId = MOCK_USER_ID_10001, .isRestricted = true }}
    };
    EXPECT_EQ(RET_SUCCESS, AccessTokenKit::SetUserPolicy({ policy }));

    // system_grant: Denied by VerifyAccessToken(restricted by policy)
    EXPECT_EQ(PERMISSION_DENIED, AccessTokenKit::VerifyAccessToken(tokenId, INTERNET));
    EXPECT_EQ(PERMISSION_GRANTED, GetPermissionStatusFromCache(tokenId, INTERNET));

    // clear policy, permission is restored
    EXPECT_EQ(RET_SUCCESS, AccessTokenKit::ClearUserPolicy({ INTERNET }));
    EXPECT_EQ(PERMISSION_GRANTED, AccessTokenKit::VerifyAccessToken(tokenId, INTERNET));
    EXPECT_EQ(PERMISSION_GRANTED, GetPermissionStatusFromCache(tokenId, INTERNET));

    EXPECT_EQ(RET_SUCCESS, TestCommon::DeleteTestHapToken(tokenId));
}

/**
 * @tc.name: SetUserPolicy006
 * @tc.desc: SetUserPolicy twice with different permission.
 * @tc.type: FUNC
 * @tc.require:Issue Number
 */
HWTEST_F(EdmPolicySetTest, SetUserPolicy006, TestSize.Level1)
{
    MockNativeToken userPolicyMock("MockUserPolicy1");
    HapInfoParams testHapInfo = g_testHapInfoParams;
    testHapInfo.userID = MOCK_USER_ID_10001;
    AccessTokenIDEx fullIdUser1;
    EXPECT_EQ(RET_SUCCESS, TestCommon::AllocTestHapToken(testHapInfo, g_testPolicyParams, fullIdUser1));
    AccessTokenID tokenId = fullIdUser1.tokenIdExStruct.tokenID;
    EXPECT_EQ(PERMISSION_GRANTED, AccessTokenKit::VerifyAccessToken(tokenId, INTERNET));
    EXPECT_EQ(PERMISSION_GRANTED, AccessTokenKit::VerifyAccessToken(tokenId, GET_NETWORK_STATS));

    UserPermissionPolicy policy1 = {
        .permissionName = INTERNET,
        .userPolicyList = {{ .userId = MOCK_USER_ID_10001, .isRestricted = true }}
    };
    EXPECT_EQ(RET_SUCCESS, AccessTokenKit::SetUserPolicy({ policy1 }));

    EXPECT_EQ(PERMISSION_DENIED, AccessTokenKit::VerifyAccessToken(tokenId, INTERNET));
    EXPECT_EQ(PERMISSION_GRANTED, GetPermissionStatusFromCache(tokenId, INTERNET));

    UserPermissionPolicy policy2 = {
        .permissionName = GET_NETWORK_STATS,
        .userPolicyList = {{ .userId = MOCK_USER_ID_10001, .isRestricted = true }}
    };
    policy1.userPolicyList[0].isRestricted = false;
    EXPECT_EQ(RET_SUCCESS, AccessTokenKit::SetUserPolicy({ policy1, policy2 }));

    EXPECT_EQ(PERMISSION_GRANTED, AccessTokenKit::VerifyAccessToken(tokenId, INTERNET));
    EXPECT_EQ(PERMISSION_GRANTED, GetPermissionStatusFromCache(tokenId, INTERNET));
    EXPECT_EQ(PERMISSION_DENIED, AccessTokenKit::VerifyAccessToken(tokenId, GET_NETWORK_STATS));
    EXPECT_EQ(PERMISSION_GRANTED, GetPermissionStatusFromCache(tokenId, GET_NETWORK_STATS));

    // clear policy of INTERNET and GET_NETWORK_STATS, permission is restored
    EXPECT_EQ(RET_SUCCESS, AccessTokenKit::ClearUserPolicy({ INTERNET, GET_NETWORK_STATS }));
    EXPECT_EQ(PERMISSION_GRANTED, AccessTokenKit::VerifyAccessToken(tokenId, INTERNET));
    EXPECT_EQ(PERMISSION_GRANTED, AccessTokenKit::VerifyAccessToken(tokenId, GET_NETWORK_STATS));

    EXPECT_EQ(RET_SUCCESS, TestCommon::DeleteTestHapToken(tokenId));
}

/**
 * @tc.name: SetUserPolicy007
 * @tc.desc: SetUserPolicy tiwce with different user for same permission.
 * @tc.type: FUNC
 * @tc.require:Issue Number
 */
HWTEST_F(EdmPolicySetTest, SetUserPolicy007, TestSize.Level1)
{
    MockNativeToken userPolicyMock("MockUserPolicy1");
    HapInfoParams testHapInfo = g_testHapInfoParams;
    testHapInfo.userID = MOCK_USER_ID_10001;
    AccessTokenIDEx fullIdUser1;
    EXPECT_EQ(RET_SUCCESS, TestCommon::AllocTestHapToken(testHapInfo, g_testPolicyParams, fullIdUser1));
    AccessTokenID tokenId1 = fullIdUser1.tokenIdExStruct.tokenID;

    testHapInfo.userID = MOCK_USER_ID_10002;
    AccessTokenIDEx fullIdUser2;
    EXPECT_EQ(RET_SUCCESS, TestCommon::AllocTestHapToken(testHapInfo, g_testPolicyParams, fullIdUser2));
    AccessTokenID tokenId2 = fullIdUser2.tokenIdExStruct.tokenID;

    EXPECT_EQ(PERMISSION_GRANTED, AccessTokenKit::VerifyAccessToken(tokenId1, INTERNET));
    EXPECT_EQ(PERMISSION_GRANTED, AccessTokenKit::VerifyAccessToken(tokenId2, INTERNET));

    UserPermissionPolicy policy = {
        .permissionName = INTERNET,
        .userPolicyList = {
            { .userId = MOCK_USER_ID_10001, .isRestricted = true},
            { .userId = MOCK_USER_ID_10002, .isRestricted = true},
        }
    };
    // first set policy
    EXPECT_EQ(RET_SUCCESS, AccessTokenKit::SetUserPolicy({ policy }));
    EXPECT_EQ(PERMISSION_DENIED, AccessTokenKit::VerifyAccessToken(tokenId1, INTERNET));
    EXPECT_EQ(PERMISSION_DENIED, AccessTokenKit::VerifyAccessToken(tokenId2, INTERNET));
    EXPECT_EQ(PERMISSION_GRANTED, GetPermissionStatusFromCache(tokenId1, INTERNET));
    EXPECT_EQ(PERMISSION_GRANTED, GetPermissionStatusFromCache(tokenId2, INTERNET));

    // second set policy
    policy.userPolicyList[0].isRestricted = false;
    EXPECT_EQ(RET_SUCCESS, AccessTokenKit::SetUserPolicy({ policy }));
    EXPECT_EQ(PERMISSION_GRANTED, AccessTokenKit::VerifyAccessToken(tokenId1, INTERNET));
    EXPECT_EQ(PERMISSION_DENIED, AccessTokenKit::VerifyAccessToken(tokenId2, INTERNET));
    EXPECT_EQ(PERMISSION_GRANTED, GetPermissionStatusFromCache(tokenId1, INTERNET));
    EXPECT_EQ(PERMISSION_GRANTED, GetPermissionStatusFromCache(tokenId2, INTERNET));

    EXPECT_EQ(RET_SUCCESS, AccessTokenKit::ClearUserPolicy({ INTERNET }));
    EXPECT_EQ(PERMISSION_GRANTED, AccessTokenKit::VerifyAccessToken(tokenId1, INTERNET));
    EXPECT_EQ(PERMISSION_GRANTED, AccessTokenKit::VerifyAccessToken(tokenId2, INTERNET));

    EXPECT_EQ(RET_SUCCESS, TestCommon::DeleteTestHapToken(tokenId1));
    EXPECT_EQ(RET_SUCCESS, TestCommon::DeleteTestHapToken(tokenId2));
}

/**
 * @tc.name: SetUserPolicy008
 * @tc.desc: SetUserPolicy tiwce with different user for different permission.
 * @tc.type: FUNC
 * @tc.require:Issue Number
 */
HWTEST_F(EdmPolicySetTest, SetUserPolicy008, TestSize.Level1)
{
    MockNativeToken userPolicyMock("MockUserPolicy1");
    HapInfoParams testHapInfo = g_testHapInfoParams;
    testHapInfo.userID = MOCK_USER_ID_10001;
    AccessTokenIDEx fullIdUser1;
    EXPECT_EQ(RET_SUCCESS, TestCommon::AllocTestHapToken(testHapInfo, g_testPolicyParams, fullIdUser1));
    AccessTokenID tokenId1 = fullIdUser1.tokenIdExStruct.tokenID;
    EXPECT_EQ(PERMISSION_GRANTED, AccessTokenKit::VerifyAccessToken(tokenId1, INTERNET));
    EXPECT_EQ(PERMISSION_GRANTED, AccessTokenKit::VerifyAccessToken(tokenId1, GET_NETWORK_STATS));

    testHapInfo.userID = MOCK_USER_ID_10002;
    AccessTokenIDEx fullIdUser2;
    EXPECT_EQ(RET_SUCCESS, TestCommon::AllocTestHapToken(testHapInfo, g_testPolicyParams, fullIdUser2));
    AccessTokenID tokenId2 = fullIdUser2.tokenIdExStruct.tokenID;
    EXPECT_EQ(PERMISSION_GRANTED, AccessTokenKit::VerifyAccessToken(tokenId2, INTERNET));
    EXPECT_EQ(PERMISSION_GRANTED, AccessTokenKit::VerifyAccessToken(tokenId2, GET_NETWORK_STATS));

    UserPermissionPolicy policy1 = {
        .permissionName = INTERNET,
        .userPolicyList = {{ .userId = MOCK_USER_ID_10001, .isRestricted = true }}
    };
    UserPermissionPolicy policy2 = {
        .permissionName = GET_NETWORK_STATS,
        .userPolicyList = {{ .userId = MOCK_USER_ID_10002, .isRestricted = true }}
    };
    EXPECT_EQ(RET_SUCCESS, AccessTokenKit::SetUserPolicy({ policy1, policy2 }));
    EXPECT_EQ(PERMISSION_DENIED, AccessTokenKit::VerifyAccessToken(tokenId1, INTERNET));
    EXPECT_EQ(PERMISSION_GRANTED, AccessTokenKit::VerifyAccessToken(tokenId1, GET_NETWORK_STATS));
    EXPECT_EQ(PERMISSION_GRANTED, GetPermissionStatusFromCache(tokenId1, INTERNET));
    EXPECT_EQ(PERMISSION_GRANTED, AccessTokenKit::VerifyAccessToken(tokenId2, INTERNET));
    EXPECT_EQ(PERMISSION_DENIED, AccessTokenKit::VerifyAccessToken(tokenId2, GET_NETWORK_STATS));
    EXPECT_EQ(PERMISSION_GRANTED, GetPermissionStatusFromCache(tokenId2, GET_NETWORK_STATS));

    policy1.userPolicyList[0].isRestricted = false;
    EXPECT_EQ(RET_SUCCESS, AccessTokenKit::SetUserPolicy({ policy1 }));
    EXPECT_EQ(PERMISSION_GRANTED, AccessTokenKit::VerifyAccessToken(tokenId1, INTERNET));

    EXPECT_EQ(RET_SUCCESS, AccessTokenKit::ClearUserPolicy({ INTERNET, GET_NETWORK_STATS }));
    EXPECT_EQ(PERMISSION_GRANTED, AccessTokenKit::VerifyAccessToken(tokenId1, INTERNET));
    EXPECT_EQ(PERMISSION_GRANTED, AccessTokenKit::VerifyAccessToken(tokenId2, GET_NETWORK_STATS));
    EXPECT_EQ(RET_SUCCESS, TestCommon::DeleteTestHapToken(tokenId1));
    EXPECT_EQ(RET_SUCCESS, TestCommon::DeleteTestHapToken(tokenId2));
}

/**
 * @tc.name: SetUserPolicy009
 * @tc.desc: The same caller is allowed to call SetUserPolicy multiple times to set the same policy.
 * @tc.type: FUNC
 * @tc.require:Issue Number
 */
HWTEST_F(EdmPolicySetTest, SetUserPolicy009, TestSize.Level1)
{
    MockNativeToken userPolicyMock("MockUserPolicy1");
    HapInfoParams testHapInfo = g_testHapInfoParams;
    AccessTokenIDEx fullIdUser1;
    EXPECT_EQ(RET_SUCCESS, TestCommon::AllocTestHapToken(testHapInfo, g_testPolicyParams, fullIdUser1));
    AccessTokenID tokenId = fullIdUser1.tokenIdExStruct.tokenID;

    UserPermissionPolicy policy = {
        .permissionName = INTERNET,
        .userPolicyList = {{ .userId = testHapInfo.userID, .isRestricted = true }}
    };
    EXPECT_EQ(RET_SUCCESS, AccessTokenKit::SetUserPolicy({ policy }));

    EXPECT_EQ(PERMISSION_DENIED, AccessTokenKit::VerifyAccessToken(tokenId, INTERNET));
    EXPECT_EQ(PERMISSION_GRANTED, GetPermissionStatusFromCache(tokenId, INTERNET));

    EXPECT_EQ(RET_SUCCESS, AccessTokenKit::ClearUserPolicy({ INTERNET }));
    EXPECT_EQ(PERMISSION_GRANTED, AccessTokenKit::VerifyAccessToken(tokenId, INTERNET));
    EXPECT_EQ(RET_SUCCESS, TestCommon::DeleteTestHapToken(tokenId));
}

/**
 * @tc.name: SetUserPolicy010
 * @tc.desc: Multiple calls to SetUserPolicy by the same caller (tokenid) to set the same policy are not allowed,
 * and an error code will be returned (failure will be returned as long as
 * it includes permissions that have already been set).
 * @tc.type: FUNC
 * @tc.require:Issue Number
 */
HWTEST_F(EdmPolicySetTest, SetUserPolicy010, TestSize.Level1)
{
    MockNativeToken userPolicyMock("MockUserPolicy1");
    HapInfoParams testHapInfo = g_testHapInfoParams;
    AccessTokenIDEx fullIdUser1;
    EXPECT_EQ(RET_SUCCESS, TestCommon::AllocTestHapToken(testHapInfo, g_testPolicyParams, fullIdUser1));
    AccessTokenID tokenId = fullIdUser1.tokenIdExStruct.tokenID;

    UserPermissionPolicy policy = {
        .permissionName = INTERNET,
        .userPolicyList = {{ .userId = testHapInfo.userID, .isRestricted = true }}
    };
    EXPECT_EQ(RET_SUCCESS, AccessTokenKit::SetUserPolicy({ policy }));
    EXPECT_EQ(PERMISSION_DENIED, AccessTokenKit::VerifyAccessToken(tokenId, INTERNET));
    EXPECT_EQ(PERMISSION_GRANTED, GetPermissionStatusFromCache(tokenId, INTERNET));

    // permisison is set by other process
    {
        MockNativeToken mock("MockUserPolicy2");
        EXPECT_EQ(ERR_PERM_POLICY_ALREADY_SET_BY_OTHER, AccessTokenKit::SetUserPolicy({ policy })); // same permission
        EXPECT_EQ(PERMISSION_DENIED, AccessTokenKit::VerifyAccessToken(tokenId, INTERNET));
        EXPECT_EQ(PERMISSION_GRANTED, GetPermissionStatusFromCache(tokenId, INTERNET));

        policy.permissionName = GET_NETWORK_STATS;
        EXPECT_EQ(RET_SUCCESS, AccessTokenKit::SetUserPolicy({ policy })); // same permission
        EXPECT_EQ(PERMISSION_DENIED, AccessTokenKit::VerifyAccessToken(tokenId, GET_NETWORK_STATS));
        EXPECT_EQ(PERMISSION_GRANTED, GetPermissionStatusFromCache(tokenId, GET_NETWORK_STATS));

        EXPECT_EQ(RET_SUCCESS, AccessTokenKit::ClearUserPolicy({ GET_NETWORK_STATS }));
        EXPECT_EQ(PERMISSION_GRANTED, AccessTokenKit::VerifyAccessToken(tokenId, GET_NETWORK_STATS));
        policy.permissionName = INTERNET;
    }

    EXPECT_EQ(RET_SUCCESS, AccessTokenKit::ClearUserPolicy({ INTERNET }));
    EXPECT_EQ(PERMISSION_GRANTED, AccessTokenKit::VerifyAccessToken(tokenId, INTERNET));

    // After clear, permission is set success
    {
        MockNativeToken mock("MockUserPolicy2");
        EXPECT_EQ(RET_SUCCESS, AccessTokenKit::SetUserPolicy({ policy })); // same permission
        EXPECT_EQ(PERMISSION_DENIED, AccessTokenKit::VerifyAccessToken(tokenId, INTERNET));
        EXPECT_EQ(PERMISSION_GRANTED, GetPermissionStatusFromCache(tokenId, INTERNET));

        EXPECT_EQ(RET_SUCCESS, AccessTokenKit::ClearUserPolicy({ INTERNET }));
        EXPECT_EQ(PERMISSION_GRANTED, AccessTokenKit::VerifyAccessToken(tokenId, INTERNET));
    }

    EXPECT_EQ(RET_SUCCESS, TestCommon::DeleteTestHapToken(tokenId));
}

/**
 * @tc.name: SetUserPolicy011
 * @tc.desc: Different callers (tokenid) call SetUserPolicy multiple times to set the same policy:
 * cancel the policy through SetUsePolicy, but do not call ClearUserPolicy, and secondary calls are not allowed.
 * @tc.type: FUNC
 * @tc.require:Issue Number
 */
HWTEST_F(EdmPolicySetTest, SetUserPolicy011, TestSize.Level1)
{
    MockNativeToken userPolicyMock("MockUserPolicy1");
    HapInfoParams testHapInfo = g_testHapInfoParams;
    AccessTokenIDEx fullIdUser1;
    EXPECT_EQ(RET_SUCCESS, TestCommon::AllocTestHapToken(testHapInfo, g_testPolicyParams, fullIdUser1));
    AccessTokenID tokenId = fullIdUser1.tokenIdExStruct.tokenID;

    UserPermissionPolicy policy = {
        .permissionName = INTERNET,
        .userPolicyList = {{ .userId = testHapInfo.userID, .isRestricted = true }}
    };
    EXPECT_EQ(RET_SUCCESS, AccessTokenKit::SetUserPolicy({ policy }));
    EXPECT_EQ(PERMISSION_DENIED, AccessTokenKit::VerifyAccessToken(tokenId, INTERNET));
    EXPECT_EQ(PERMISSION_GRANTED, GetPermissionStatusFromCache(tokenId, INTERNET));

    // cancel policy of INTERNET
    policy.userPolicyList[0].isRestricted = false;
    EXPECT_EQ(RET_SUCCESS, AccessTokenKit::SetUserPolicy({ policy }));
    EXPECT_EQ(PERMISSION_GRANTED, AccessTokenKit::VerifyAccessToken(tokenId, INTERNET));
    EXPECT_EQ(PERMISSION_GRANTED, GetPermissionStatusFromCache(tokenId, INTERNET));
    {
        MockNativeToken mock("MockUserPolicy2");
        EXPECT_EQ(ERR_PERM_POLICY_ALREADY_SET_BY_OTHER, AccessTokenKit::SetUserPolicy({ policy })); // same permission
    }

    // clear policy of INTERNET
    EXPECT_EQ(RET_SUCCESS, AccessTokenKit::ClearUserPolicy({ INTERNET }));
    EXPECT_EQ(PERMISSION_GRANTED, AccessTokenKit::VerifyAccessToken(tokenId, INTERNET));
    {
        MockNativeToken mock("MockUserPolicy2");
        policy.userPolicyList[0].isRestricted = true;
        EXPECT_EQ(RET_SUCCESS, AccessTokenKit::SetUserPolicy({ policy })); // same permission
        EXPECT_EQ(PERMISSION_DENIED, AccessTokenKit::VerifyAccessToken(tokenId, INTERNET));
        EXPECT_EQ(PERMISSION_GRANTED, GetPermissionStatusFromCache(tokenId, INTERNET));

        EXPECT_EQ(RET_SUCCESS, AccessTokenKit::ClearUserPolicy({ INTERNET }));
        EXPECT_EQ(PERMISSION_GRANTED, AccessTokenKit::VerifyAccessToken(tokenId, INTERNET));
    }
    EXPECT_EQ(RET_SUCCESS, TestCommon::DeleteTestHapToken(tokenId));
}

/**
 * @tc.name: SetUserPolicy012
 * @tc.desc: When setting the policy for the first time, set isRestricted to false,
 * and other processes are still not allowed to set it.
 * @tc.type: FUNC
 * @tc.require:Issue Number
 */
HWTEST_F(EdmPolicySetTest, SetUserPolicy012, TestSize.Level1)
{
    MockNativeToken userPolicyMock("MockUserPolicy1");
    HapInfoParams testHapInfo = g_testHapInfoParams;
    AccessTokenIDEx fullIdUser1;
    EXPECT_EQ(RET_SUCCESS, TestCommon::AllocTestHapToken(testHapInfo, g_testPolicyParams, fullIdUser1));
    AccessTokenID tokenId = fullIdUser1.tokenIdExStruct.tokenID;

    UserPermissionPolicy policy = {
        .permissionName = INTERNET,
        .userPolicyList = {{ .userId = testHapInfo.userID, .isRestricted = false }}
    };
    EXPECT_EQ(RET_SUCCESS, AccessTokenKit::SetUserPolicy({ policy }));
    EXPECT_EQ(PERMISSION_GRANTED, AccessTokenKit::VerifyAccessToken(tokenId, INTERNET));
    EXPECT_EQ(PERMISSION_GRANTED, GetPermissionStatusFromCache(tokenId, INTERNET));

    {
        MockNativeToken mock("MockUserPolicy2");
        EXPECT_EQ(ERR_PERM_POLICY_ALREADY_SET_BY_OTHER, AccessTokenKit::SetUserPolicy({ policy })); // same permission
    }

    // clear policy of INTERNET
    EXPECT_EQ(RET_SUCCESS, AccessTokenKit::ClearUserPolicy({ INTERNET }));
    EXPECT_EQ(PERMISSION_GRANTED, AccessTokenKit::VerifyAccessToken(tokenId, INTERNET));
    {
        MockNativeToken mock("MockUserPolicy2");
        policy.userPolicyList[0].isRestricted = true;
        EXPECT_EQ(RET_SUCCESS, AccessTokenKit::SetUserPolicy({ policy })); // same permission
        EXPECT_EQ(PERMISSION_DENIED, AccessTokenKit::VerifyAccessToken(tokenId, INTERNET));
        EXPECT_EQ(PERMISSION_GRANTED, GetPermissionStatusFromCache(tokenId, INTERNET));

        EXPECT_EQ(RET_SUCCESS, AccessTokenKit::ClearUserPolicy({ INTERNET }));
        EXPECT_EQ(PERMISSION_GRANTED, AccessTokenKit::VerifyAccessToken(tokenId, INTERNET));
    }
    EXPECT_EQ(RET_SUCCESS, TestCommon::DeleteTestHapToken(tokenId));
}

/**
 * @tc.name: SetUserPolicy013
 * @tc.desc: If there are multiple permission policies and one of them corresponds to a userId of -1,
 * ERR_PARAM_INVALID will be returned, and the already set permission policy will not take effect.
 * @tc.type: FUNC
 * @tc.require:Issue Number
 */
HWTEST_F(EdmPolicySetTest, SetUserPolicy013, TestSize.Level1)
{
    MockNativeToken userPolicyMock("MockUserPolicy1");
    HapInfoParams testHapInfo = g_testHapInfoParams;
    AccessTokenIDEx fullIdUser1;
    EXPECT_EQ(RET_SUCCESS, TestCommon::AllocTestHapToken(testHapInfo, g_testPolicyParams, fullIdUser1));
    AccessTokenID tokenId = fullIdUser1.tokenIdExStruct.tokenID;

    UserPermissionPolicy policy1 = {
        .permissionName = INTERNET,
        .userPolicyList = {{ .userId = testHapInfo.userID, .isRestricted = true }}
    };
    UserPermissionPolicy policy2 = {
        .permissionName = GET_NETWORK_STATS,
        .userPolicyList = {{ .userId = -1, .isRestricted = true }}
    };
    EXPECT_EQ(AccessTokenError::ERR_PARAM_INVALID, AccessTokenKit::SetUserPolicy({ policy1, policy2 }));

    {
        MockNativeToken mock("MockUserPolicy2");
        EXPECT_EQ(RET_SUCCESS, AccessTokenKit::SetUserPolicy({ policy1 }));
        EXPECT_EQ(PERMISSION_DENIED, AccessTokenKit::VerifyAccessToken(tokenId, INTERNET));
        EXPECT_EQ(PERMISSION_GRANTED, GetPermissionStatusFromCache(tokenId, INTERNET));

        EXPECT_EQ(RET_SUCCESS, AccessTokenKit::ClearUserPolicy({ INTERNET }));
        EXPECT_EQ(PERMISSION_GRANTED, AccessTokenKit::VerifyAccessToken(tokenId, INTERNET));
    }

    EXPECT_EQ(RET_SUCCESS, TestCommon::DeleteTestHapToken(tokenId));
}

/**
 * @tc.name: SetUserPolicy014
 * @tc.desc: SetUserPolicy to restrict permission, QueryStatusByPermission/QueryStatusByTokenID return PERMISSION_DENIED
 * @tc.type: FUNC
 * @tc.require:Issue Number
 */
HWTEST_F(EdmPolicySetTest, SetUserPolicy014, TestSize.Level1)
{
    MockNativeToken userPolicyMock("MockUserPolicy1");
    HapInfoParams testHapInfo = g_testHapInfoParams;
    AccessTokenIDEx fullIdUser1;
    EXPECT_EQ(RET_SUCCESS, TestCommon::AllocTestHapToken(testHapInfo, g_testPolicyParams, fullIdUser1));
    AccessTokenID tokenID = fullIdUser1.tokenIdExStruct.tokenID;
    UserPermissionPolicy policy = {
        .permissionName = INTERNET,
        .userPolicyList = {{ .userId = testHapInfo.userID, .isRestricted = true }}
    };
    EXPECT_EQ(RET_SUCCESS, AccessTokenKit::SetUserPolicy({ policy }));

    {
        MockNativeToken mockNative("privacy_service");
        std::vector<PermissionStatus> permissionInfoList1;
        EXPECT_EQ(RET_SUCCESS, AccessTokenKit::QueryStatusByPermission({INTERNET}, permissionInfoList1));
        EXPECT_FALSE(permissionInfoList1.empty());
        for (const auto& info : permissionInfoList1) {
            if (info.tokenID == tokenID) {
                EXPECT_EQ(PERMISSION_DENIED, info.grantStatus);
            }
        }

        std::vector<PermissionStatus> permissionInfoList2;
        EXPECT_EQ(RET_SUCCESS, AccessTokenKit::QueryStatusByTokenID({tokenID}, permissionInfoList2));
        EXPECT_FALSE(permissionInfoList2.empty());
        for (const auto& info : permissionInfoList2) {
            if (info.permissionName == "ohos.permission.INTERNET") {
                EXPECT_EQ(PERMISSION_DENIED, info.grantStatus);
            }
        }
    }
    EXPECT_EQ(RET_SUCCESS, AccessTokenKit::ClearUserPolicy({ INTERNET }));
    EXPECT_EQ(RET_SUCCESS, TestCommon::DeleteTestHapToken(tokenID));
}

/**
 * @tc.name: ClearUserPolicy001
 * @tc.desc: ClearUserPolicy failed: 1. invalid permissionList; 2. invalid permission of permissionList.
 * @tc.type: FUNC
 * @tc.require:Issue Number
 */
HWTEST_F(EdmPolicySetTest, ClearUserPolicy001, TestSize.Level1)
{
    MockNativeToken userPolicyMock("MockUserPolicy1");
    std::vector<std::string> permListEmpty;
    // empty
    EXPECT_EQ(AccessTokenError::ERR_PARAM_INVALID, AccessTokenKit::ClearUserPolicy(permListEmpty));

    // oversize
    const int32_t invalidSize = 1025; // 1025 is invalid size.
    std::vector<std::string> permPListOverSize(invalidSize);
    EXPECT_EQ(AccessTokenError::ERR_PARAM_INVALID, AccessTokenKit::ClearUserPolicy(permPListOverSize));

    // empty permission
    std::string permissionName = "";
    EXPECT_EQ(AccessTokenError::ERR_PARAM_INVALID, AccessTokenKit::ClearUserPolicy({ permissionName }));

    // permission is oversize
    permissionName.resize(MAX_LENGTH + 1, 'A');
    EXPECT_EQ(AccessTokenError::ERR_PARAM_INVALID, AccessTokenKit::ClearUserPolicy({ permissionName }));

    // permission is noexist
    permissionName = "test";
    EXPECT_EQ(AccessTokenError::ERR_PARAM_INVALID, AccessTokenKit::ClearUserPolicy({ permissionName }));

    // permission is user_grant
    permissionName = "ohos.permission.CAMERA";
    EXPECT_EQ(AccessTokenError::ERR_PERM_POLICY_NOT_SET, AccessTokenKit::ClearUserPolicy({ permissionName }));

    // permission is system_grant, but not set policy
    permissionName = "ohos.permission.INTERNET";
    EXPECT_EQ(AccessTokenError::ERR_PERM_POLICY_NOT_SET, AccessTokenKit::ClearUserPolicy({ permissionName }));
}

/**
 * @tc.name: ClearUserPolicy002
 * @tc.desc: The policy for permission A is set by process A.
 * When B calls clear, it returns ERR_PERM_POLICY_ALREADY_SET_BY_OTHER.
 * @tc.type: FUNC
 * @tc.require:Issue Number
 */
HWTEST_F(EdmPolicySetTest, ClearUserPolicy002, TestSize.Level1)
{
    MockNativeToken userPolicyMock("MockUserPolicy1");
    HapInfoParams testHapInfo = g_testHapInfoParams;
    AccessTokenIDEx fullIdUser1;
    EXPECT_EQ(RET_SUCCESS, TestCommon::AllocTestHapToken(testHapInfo, g_testPolicyParams, fullIdUser1));
    AccessTokenID tokenId = fullIdUser1.tokenIdExStruct.tokenID;

    UserPermissionPolicy policy1 = {
        .permissionName = INTERNET,
        .userPolicyList = {{ .userId = testHapInfo.userID, .isRestricted = true }}
    };
    EXPECT_EQ(RET_SUCCESS, AccessTokenKit::SetUserPolicy({ policy1 }));
    EXPECT_EQ(PERMISSION_DENIED, AccessTokenKit::VerifyAccessToken(tokenId, INTERNET));
    EXPECT_EQ(PERMISSION_GRANTED, GetPermissionStatusFromCache(tokenId, INTERNET));

    {
        MockNativeToken mock("MockUserPolicy2");
        EXPECT_EQ(ERR_PERM_POLICY_ALREADY_SET_BY_OTHER, AccessTokenKit::ClearUserPolicy({ INTERNET }));
    }

    EXPECT_EQ(RET_SUCCESS, AccessTokenKit::ClearUserPolicy({ INTERNET }));
    EXPECT_EQ(PERMISSION_GRANTED, AccessTokenKit::VerifyAccessToken(tokenId, INTERNET));

    EXPECT_EQ(RET_SUCCESS, TestCommon::DeleteTestHapToken(tokenId));
}

/**
 * @tc.name: ClearUserPolicy003
 * @tc.desc: ClearUserPolicy failed with invalid permission of permissionList.
 * @tc.type: FUNC
 * @tc.require:Issue Number
 */
HWTEST_F(EdmPolicySetTest, ClearUserPolicy003, TestSize.Level1)
{
    MockNativeToken userPolicyMock("MockUserPolicy1");
    HapInfoParams testHapInfo = g_testHapInfoParams;
    AccessTokenIDEx fullIdUser1;
    EXPECT_EQ(RET_SUCCESS, TestCommon::AllocTestHapToken(testHapInfo, g_testPolicyParams, fullIdUser1));
    AccessTokenID tokenId = fullIdUser1.tokenIdExStruct.tokenID;

    UserPermissionPolicy policy = {
        .permissionName = INTERNET,
        .userPolicyList = {{ .userId = testHapInfo.userID, .isRestricted = true }}
    };
    EXPECT_EQ(RET_SUCCESS, AccessTokenKit::SetUserPolicy({ policy }));
    EXPECT_EQ(PERMISSION_DENIED, AccessTokenKit::VerifyAccessToken(tokenId, INTERNET));
    EXPECT_EQ(PERMISSION_GRANTED, GetPermissionStatusFromCache(tokenId, INTERNET));

    EXPECT_EQ(RET_SUCCESS, AccessTokenKit::ClearUserPolicy({ INTERNET }));
    EXPECT_EQ(PERMISSION_GRANTED, AccessTokenKit::VerifyAccessToken(tokenId, INTERNET));

    EXPECT_EQ(AccessTokenError::ERR_PERM_POLICY_NOT_SET, AccessTokenKit::ClearUserPolicy({ INTERNET }));

    EXPECT_EQ(RET_SUCCESS, TestCommon::DeleteTestHapToken(tokenId));
}

/**
 * @tc.name: ClearUserPolicy004
 * @tc.desc: When a permission policy fails to be cleared from the permission list,
 * other policies also fail to be cleared during the same interface call.
 * @tc.type: FUNC
 * @tc.require:Issue Number
 */
HWTEST_F(EdmPolicySetTest, ClearUserPolicy004, TestSize.Level1)
{
    MockNativeToken userPolicyMock("MockUserPolicy1");
    HapInfoParams testHapInfo = g_testHapInfoParams;
    UserPermissionPolicy policy = {
        .permissionName = INTERNET,
        .userPolicyList = {{ .userId = testHapInfo.userID, .isRestricted = true }}
    };
    EXPECT_EQ(RET_SUCCESS, AccessTokenKit::SetUserPolicy({ policy }));

    AccessTokenIDEx fullIdUser1;
    EXPECT_EQ(RET_SUCCESS, TestCommon::AllocTestHapToken(testHapInfo, g_testPolicyParams, fullIdUser1));
    AccessTokenID tokenId = fullIdUser1.tokenIdExStruct.tokenID;
    EXPECT_EQ(PERMISSION_DENIED, AccessTokenKit::VerifyAccessToken(tokenId, INTERNET));
    EXPECT_EQ(PERMISSION_GRANTED, GetPermissionStatusFromCache(tokenId, INTERNET));

    EXPECT_EQ(AccessTokenError::ERR_PARAM_INVALID, AccessTokenKit::ClearUserPolicy({ INTERNET, "test" }));
    EXPECT_EQ(PERMISSION_DENIED, AccessTokenKit::VerifyAccessToken(tokenId, INTERNET));
    EXPECT_EQ(PERMISSION_GRANTED, GetPermissionStatusFromCache(tokenId, INTERNET));

    {
        MockNativeToken mock("MockUserPolicy2");
        EXPECT_EQ(ERR_PERM_POLICY_ALREADY_SET_BY_OTHER, AccessTokenKit::ClearUserPolicy({ INTERNET }));
    }

    EXPECT_EQ(RET_SUCCESS, AccessTokenKit::ClearUserPolicy({ INTERNET }));
    EXPECT_EQ(PERMISSION_GRANTED, AccessTokenKit::VerifyAccessToken(tokenId, INTERNET));
    EXPECT_EQ(PERMISSION_GRANTED, GetPermissionStatusFromCache(tokenId, INTERNET));

    EXPECT_EQ(RET_SUCCESS, TestCommon::DeleteTestHapToken(tokenId));
}

/**
 * @tc.name: UserPolicyTestForInitHap
 * @tc.desc: Set the authorization status based on the user policy during new hap installation
 * @tc.type: FUNC
 * @tc.require:Issue Number
 */
HWTEST_F(EdmPolicySetTest, UserPolicyTestForInitHap, TestSize.Level1)
{
    MockNativeToken userPolicyMock("MockUserPolicy1");
    UserPermissionPolicy policy1 = {
        .permissionName = INTERNET,
        .userPolicyList = {{ .userId = MOCK_USER_ID_10001, .isRestricted = true }}
    };
    UserPermissionPolicy policy2 = {
        .permissionName = GET_NETWORK_STATS,
        .userPolicyList = {{ .userId = MOCK_USER_ID_10002, .isRestricted = true }}
    };
    std::vector<UserPermissionPolicy> policyListBefore = { policy1, policy2 };
    EXPECT_EQ(RET_SUCCESS, AccessTokenKit::SetUserPolicy(policyListBefore));

    HapInfoParams testHapInfo = g_testHapInfoParams;
    testHapInfo.userID = MOCK_USER_ID_10001;
    AccessTokenIDEx fullIdUser1;
    EXPECT_EQ(RET_SUCCESS, TestCommon::AllocTestHapToken(testHapInfo, g_testPolicyParams, fullIdUser1));
    AccessTokenID tokenId1 = fullIdUser1.tokenIdExStruct.tokenID;

    testHapInfo.userID = MOCK_USER_ID_10002;
    AccessTokenIDEx fullIdUser2;
    EXPECT_EQ(RET_SUCCESS, TestCommon::AllocTestHapToken(testHapInfo, g_testPolicyParams, fullIdUser2));
    AccessTokenID tokenId2 = fullIdUser2.tokenIdExStruct.tokenID;

    EXPECT_EQ(PERMISSION_DENIED, AccessTokenKit::VerifyAccessToken(tokenId1, INTERNET));
    EXPECT_EQ(PERMISSION_GRANTED, GetPermissionStatusFromCache(tokenId1, INTERNET));
    EXPECT_EQ(PERMISSION_GRANTED, AccessTokenKit::VerifyAccessToken(tokenId1, GET_NETWORK_STATS));
    EXPECT_EQ(PERMISSION_GRANTED, AccessTokenKit::VerifyAccessToken(tokenId2, INTERNET));
    EXPECT_EQ(PERMISSION_DENIED, AccessTokenKit::VerifyAccessToken(tokenId2, GET_NETWORK_STATS));
    EXPECT_EQ(PERMISSION_GRANTED, GetPermissionStatusFromCache(tokenId2, GET_NETWORK_STATS));

    EXPECT_EQ(RET_SUCCESS, AccessTokenKit::ClearUserPolicy({ INTERNET, GET_NETWORK_STATS }));
    EXPECT_EQ(RET_SUCCESS, TestCommon::DeleteTestHapToken(tokenId1));
    EXPECT_EQ(RET_SUCCESS, TestCommon::DeleteTestHapToken(tokenId2));
}

/**
 * @tc.name: UserPolicyTestForUpdateHap
 * @tc.desc: UpdateHapToken and check permission status with user policy.
 * @tc.type: FUNC
 * @tc.require:Issue Number
 */
HWTEST_F(EdmPolicySetTest, UserPolicyTestForUpdateHap, TestSize.Level1)
{
    MockNativeToken userPolicyMock("MockUserPolicy1");
    HapPolicyParams testPolicyParams1 = {
        .apl = APL_SYSTEM_CORE,
        .domain = "test.domain2",
        .permStateList = { g_infoManagerInternetState }
    };
    HapInfoParams testHapInfo = g_testHapInfoParams;
    testHapInfo.userID = MOCK_USER_ID_10001;
    AccessTokenIDEx fullIdUser1;
    EXPECT_EQ(RET_SUCCESS, TestCommon::AllocTestHapToken(testHapInfo, testPolicyParams1, fullIdUser1));
    AccessTokenID tokenId = fullIdUser1.tokenIdExStruct.tokenID;
    EXPECT_EQ(PERMISSION_GRANTED, AccessTokenKit::VerifyAccessToken(tokenId, INTERNET));

    // set policy
    UserPermissionPolicy policy = {
        .permissionName = INTERNET,
        .userPolicyList = {{ .userId = MOCK_USER_ID_10001, .isRestricted = true }}
    };
    EXPECT_EQ(RET_SUCCESS, AccessTokenKit::SetUserPolicy({ policy }));
    EXPECT_EQ(PERMISSION_DENIED, AccessTokenKit::VerifyAccessToken(tokenId, INTERNET));
    EXPECT_EQ(PERMISSION_GRANTED, GetPermissionStatusFromCache(tokenId, INTERNET));

    HapPolicyParams testPolicyParams2 = {
        .apl = APL_SYSTEM_CORE,
        .domain = "test.domain2",
        .permStateList = { g_infoManagerInternetState, g_infoManagerNetWorkState }
    };
    UpdateHapInfoParams info;
    info.appIDDesc = "TEST";
    info.apiVersion = 12;
    info.isSystemApp = false;
    {
        MockNativeToken mock("foundation");
        EXPECT_EQ(RET_SUCCESS, AccessTokenKit::UpdateHapToken(fullIdUser1, info, testPolicyParams2));
    }
    EXPECT_EQ(PERMISSION_DENIED, AccessTokenKit::VerifyAccessToken(tokenId, INTERNET));
    EXPECT_EQ(PERMISSION_GRANTED, GetPermissionStatusFromCache(tokenId, INTERNET));
    EXPECT_EQ(PERMISSION_GRANTED, AccessTokenKit::VerifyAccessToken(tokenId, GET_NETWORK_STATS));
    EXPECT_EQ(PERMISSION_GRANTED, GetPermissionStatusFromCache(tokenId, GET_NETWORK_STATS));

    EXPECT_EQ(RET_SUCCESS, AccessTokenKit::ClearUserPolicy({ INTERNET }));
    EXPECT_EQ(PERMISSION_GRANTED, AccessTokenKit::VerifyAccessToken(tokenId, INTERNET));
    EXPECT_EQ(PERMISSION_GRANTED, AccessTokenKit::VerifyAccessToken(tokenId, GET_NETWORK_STATS));

    EXPECT_EQ(RET_SUCCESS, TestCommon::DeleteTestHapToken(tokenId));
}

class CbCustomizeTestForEdm : public PermStateChangeCallbackCustomize {
public:
    explicit CbCustomizeTestForEdm(const PermStateChangeScope &scopeInfo)
        : PermStateChangeCallbackCustomize(scopeInfo)
    {
    }

    ~CbCustomizeTestForEdm()
    {}

    virtual void PermStateChangeCallback(PermStateChangeInfo& result)
    {
        GTEST_LOG_(INFO) << "PermStateChangeCallback permissionName: " << result.permissionName;
        GTEST_LOG_(INFO) << "PermStateChangeCallback permStateChangeType: " << result.permStateChangeType;
        ready_ = true;
        changeCnt_++;
    }

    bool ready_ = false;
    uint32_t changeCnt_ = 0;
};

/**
 * @tc.name: UserPolicyTestForRemove
 * @tc.desc: UpdateHapToken and check permission status with user policy.
 * @tc.type: FUNC
 * @tc.require:Issue Number
 */
HWTEST_F(EdmPolicySetTest, UserPolicyTestForRemove, TestSize.Level1)
{
    MockNativeToken userPolicyMock("MockUserPolicy1");
    // set policy
    UserPermissionPolicy policy = {
        .permissionName = INTERNET,
        .userPolicyList = {{ .userId = MOCK_USER_ID_10001, .isRestricted = true }}
    };
    EXPECT_EQ(RET_SUCCESS, AccessTokenKit::SetUserPolicy({ policy }));

    HapPolicyParams testPolicyParams1 = {
        .apl = APL_SYSTEM_CORE,
        .domain = "test.domain2",
        .permStateList = { g_infoManagerInternetState, g_infoManagerNetWorkState }
    };
    HapInfoParams testHapInfo = g_testHapInfoParams;
    testHapInfo.userID = MOCK_USER_ID_10001;
    AccessTokenIDEx fullIdUser1;
    EXPECT_EQ(RET_SUCCESS, TestCommon::AllocTestHapToken(testHapInfo, testPolicyParams1, fullIdUser1));
    AccessTokenID tokenId = fullIdUser1.tokenIdExStruct.tokenID;
    EXPECT_EQ(PERMISSION_DENIED, AccessTokenKit::VerifyAccessToken(tokenId, INTERNET));
    EXPECT_EQ(PERMISSION_GRANTED, AccessTokenKit::VerifyAccessToken(tokenId, GET_NETWORK_STATS));

    PermStateChangeScope scopeInfo;
    scopeInfo.permList = { INTERNET, GET_NETWORK_STATS };
    scopeInfo.tokenIDs = { tokenId };
    auto callbackPtr = std::make_shared<CbCustomizeTestForEdm>(scopeInfo);
    callbackPtr->ready_ = false;
    ASSERT_EQ(RET_SUCCESS, AccessTokenKit::RegisterPermStateChangeCallback(callbackPtr));

    EXPECT_EQ(PERMISSION_DENIED, AccessTokenKit::VerifyAccessToken(tokenId, INTERNET));
    EXPECT_EQ(PERMISSION_GRANTED, GetPermissionStatusFromCache(tokenId, INTERNET));
    EXPECT_EQ(PERMISSION_GRANTED, AccessTokenKit::VerifyAccessToken(tokenId, GET_NETWORK_STATS));
    EXPECT_EQ(PERMISSION_GRANTED, GetPermissionStatusFromCache(tokenId, GET_NETWORK_STATS));

    EXPECT_EQ(RET_SUCCESS, TestCommon::DeleteTestHapToken(tokenId));

    usleep(500000); // 500000us = 0.5s
    EXPECT_EQ(true, callbackPtr->ready_);
    EXPECT_EQ(1, callbackPtr->changeCnt_); // 1：1次回调

    EXPECT_EQ(RET_SUCCESS, AccessTokenKit::ClearUserPolicy({ INTERNET }));
    ASSERT_EQ(RET_SUCCESS, AccessTokenKit::UnRegisterPermStateChangeCallback(callbackPtr));
}

/**
 * @tc.name: UserPolicyTestForClearUserGranted
 * @tc.desc: Set the authorization status based on the user policy during clearing hap.
 * @tc.type: FUNC
 * @tc.require:Issue Number
 */
HWTEST_F(EdmPolicySetTest, UserPolicyTestForClearUserGranted, TestSize.Level1)
{
    MockNativeToken userPolicyMock("MockUserPolicy1");
    UserPermissionPolicy policy = {
        .permissionName = INTERNET,
        .userPolicyList = {
            { .userId = MOCK_USER_ID_10001, .isRestricted = true},
            { .userId = MOCK_USER_ID_10002, .isRestricted = true},
        }
    };
    EXPECT_EQ(RET_SUCCESS, AccessTokenKit::SetUserPolicy({ policy }));

    HapInfoParams testHapInfo = g_testHapInfoParams;
    testHapInfo.userID = MOCK_USER_ID_10001;
    AccessTokenIDEx fullIdUser1;
    EXPECT_EQ(RET_SUCCESS, TestCommon::AllocTestHapToken(testHapInfo, g_testPolicyParams, fullIdUser1));
    AccessTokenID tokenId1 = fullIdUser1.tokenIdExStruct.tokenID;

    testHapInfo.userID = MOCK_USER_ID_10002;
    AccessTokenIDEx fullIdUser2;
    EXPECT_EQ(RET_SUCCESS, TestCommon::AllocTestHapToken(testHapInfo, g_testPolicyParams, fullIdUser2));
    AccessTokenID tokenId2 = fullIdUser2.tokenIdExStruct.tokenID;

    EXPECT_EQ(PERMISSION_DENIED, AccessTokenKit::VerifyAccessToken(tokenId1, INTERNET));
    EXPECT_EQ(PERMISSION_DENIED, AccessTokenKit::VerifyAccessToken(tokenId2, INTERNET));

    EXPECT_EQ(RET_SUCCESS, TestCommon::ClearUserGrantedPermissionStateByTest(tokenId1));
    EXPECT_EQ(RET_SUCCESS, TestCommon::ClearUserGrantedPermissionStateByTest(tokenId2));

    EXPECT_EQ(PERMISSION_DENIED, AccessTokenKit::VerifyAccessToken(tokenId1, INTERNET));
    EXPECT_EQ(PERMISSION_DENIED, AccessTokenKit::VerifyAccessToken(tokenId2, INTERNET));

    EXPECT_EQ(RET_SUCCESS, AccessTokenKit::ClearUserPolicy({ INTERNET }));
    EXPECT_EQ(PERMISSION_GRANTED, AccessTokenKit::VerifyAccessToken(tokenId1, INTERNET));
    EXPECT_EQ(PERMISSION_GRANTED, AccessTokenKit::VerifyAccessToken(tokenId2, INTERNET));

    EXPECT_EQ(RET_SUCCESS, TestCommon::DeleteTestHapToken(tokenId1));
    EXPECT_EQ(RET_SUCCESS, TestCommon::DeleteTestHapToken(tokenId2));
}
#else
/**
 * @tc.name: SetUserPolicy001
 * @tc.desc: Not support to SetUserPolicy.
 * @tc.type: FUNC
 * @tc.require:Issue Number
 */
HWTEST_F(EdmPolicySetTest, SetUserPolicy001, TestSize.Level0)
{
    std::vector<UserPermissionPolicy> permPolicyListEmpty;
    EXPECT_EQ(AccessTokenError::ERR_CAPABILITY_NOT_SUPPORT, AccessTokenKit::SetUserPolicy(permPolicyListEmpty));
    EXPECT_EQ(AccessTokenError::ERR_CAPABILITY_NOT_SUPPORT, AccessTokenKit::ClearUserPolicy({ INTERNET }));
}
#endif

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
    int32_t ret = RET_SUCCESS;
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

    int32_t ret = RET_SUCCESS;

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
    int32_t ret = RET_SUCCESS;
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
    int32_t ret = RET_SUCCESS;
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
    int32_t ret = RET_SUCCESS;
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
    int32_t ret = RET_SUCCESS;

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
 * @tc.name: SetPermissionStatusWithPolicy009
 * @tc.desc: Permission priority test.
 * @tc.type: FUNC
 * @tc.require:Issue Number
 */
HWTEST_F(EdmPolicySetTest, SetPermissionStatusWithPolicy009, TestSize.Level0)
{
    LOGI(ATM_DOMAIN, ATM_TAG, "SetPermissionStatusWithPolicy009");

    g_testHapInfoParams.userID = MOCK_USER_ID_10001;
    AccessTokenIDEx tokenIdEx = TestCommon::AllocAndGrantHapTokenByTest(g_testHapInfoParams, g_testPolicyParams);
    AccessTokenID tokenID = tokenIdEx.tokenIdExStruct.tokenID;
    ASSERT_NE(INVALID_TOKENID, tokenID);
    MockNativeToken mock("edm");

    uint32_t flag = 0;
    int32_t ret = RET_SUCCESS;
    std::vector<std::string> permList = {CUSTOM_SCREEN_CAPTURE};

    // set flag is PERMISSION_FIXED_BY_ADMIN_POLICY, status is PERMISSION_GRANTED.
    ret = AccessTokenKit::SetPermissionStatusWithPolicy(
        tokenID, permList, PERMISSION_GRANTED, PERMISSION_FIXED_BY_ADMIN_POLICY);
    EXPECT_EQ(RET_SUCCESS, ret);
    EXPECT_EQ(RET_SUCCESS, AccessTokenKit::GetPermissionFlag(tokenID, CUSTOM_SCREEN_CAPTURE, flag));
    EXPECT_EQ(PERMISSION_FIXED_BY_ADMIN_POLICY, flag);
    EXPECT_EQ(PERMISSION_GRANTED, AccessTokenKit::VerifyAccessToken(tokenID, CUSTOM_SCREEN_CAPTURE, false));

    // set flag is PERMISSION_ADMIN_POLICIES_CANCEL, status is PERMISSION_DENIED.
    ret = AccessTokenKit::SetPermissionStatusWithPolicy(
        tokenID, permList, PERMISSION_DENIED, PERMISSION_ADMIN_POLICIES_CANCEL);
    EXPECT_EQ(RET_SUCCESS, ret);
    EXPECT_EQ(RET_SUCCESS, AccessTokenKit::GetPermissionFlag(tokenID, CUSTOM_SCREEN_CAPTURE, flag));
    // flag is change.
    EXPECT_EQ(PERMISSION_ADMIN_POLICIES_CANCEL, flag);
    // status is not change.
    EXPECT_EQ(PERMISSION_GRANTED, AccessTokenKit::VerifyAccessToken(tokenID, CUSTOM_SCREEN_CAPTURE, false));

    EXPECT_EQ(RET_SUCCESS, TestCommon::DeleteTestHapToken(tokenID));
}

/**
 * @tc.name: SetPermissionStatusWithPolicy010
 * @tc.desc: Permission priority test.
 * @tc.type: FUNC
 * @tc.require:Issue Number
 */
HWTEST_F(EdmPolicySetTest, SetPermissionStatusWithPolicy010, TestSize.Level0)
{
    LOGI(ATM_DOMAIN, ATM_TAG, "SetPermissionStatusWithPolicy010");

    g_testHapInfoParams.userID = MOCK_USER_ID_10001;
    AccessTokenIDEx tokenIdEx = TestCommon::AllocAndGrantHapTokenByTest(g_testHapInfoParams, g_testPolicyParams);
    AccessTokenID tokenID = tokenIdEx.tokenIdExStruct.tokenID;
    ASSERT_NE(INVALID_TOKENID, tokenID);
    MockNativeToken mock("edm");

    uint32_t flag = 0;
    int32_t ret = RET_SUCCESS;
    std::vector<std::string> permList = {CUSTOM_SCREEN_CAPTURE};

    // set flag is PERMISSION_ADMIN_POLICIES_CANCEL, status is PERMISSION_GRANTED.
    ret = AccessTokenKit::SetPermissionStatusWithPolicy(
        tokenID, permList, PERMISSION_DENIED, PERMISSION_FIXED_BY_ADMIN_POLICY);
    EXPECT_EQ(RET_SUCCESS, ret);
    EXPECT_EQ(RET_SUCCESS, AccessTokenKit::GetPermissionFlag(tokenID, CUSTOM_SCREEN_CAPTURE, flag));
    EXPECT_EQ(PERMISSION_FIXED_BY_ADMIN_POLICY, flag);
    EXPECT_EQ(PERMISSION_DENIED, AccessTokenKit::VerifyAccessToken(tokenID, CUSTOM_SCREEN_CAPTURE, false));
    ret = AccessTokenKit::SetPermissionStatusWithPolicy(
        tokenID, permList, PERMISSION_DENIED, PERMISSION_ADMIN_POLICIES_CANCEL);
    EXPECT_EQ(RET_SUCCESS, ret);
    EXPECT_EQ(RET_SUCCESS, AccessTokenKit::GetPermissionFlag(tokenID, CUSTOM_SCREEN_CAPTURE, flag));
    // flag is change.
    EXPECT_EQ(PERMISSION_ADMIN_POLICIES_CANCEL, flag);
    // status is not change.
    EXPECT_EQ(PERMISSION_DENIED, AccessTokenKit::VerifyAccessToken(tokenID, CUSTOM_SCREEN_CAPTURE, false));

    // can GrantPermission the flag is PERMISSION_USER_FIXED.
    ret = TestCommon::GrantPermissionByTest(tokenID, CUSTOM_SCREEN_CAPTURE, PERMISSION_USER_FIXED);
    EXPECT_EQ(RET_SUCCESS, ret);
    EXPECT_EQ(RET_SUCCESS, AccessTokenKit::GetPermissionFlag(tokenID, CUSTOM_SCREEN_CAPTURE, flag));
    EXPECT_EQ(PERMISSION_USER_FIXED, flag);
    EXPECT_EQ(PERMISSION_GRANTED, AccessTokenKit::VerifyAccessToken(tokenID, CUSTOM_SCREEN_CAPTURE, false));

    // set flag is PERMISSION_ADMIN_POLICIES_CANCEL, status is PERMISSION_GRANTED.
    ret = AccessTokenKit::SetPermissionStatusWithPolicy(
        tokenID, permList, PERMISSION_DENIED, PERMISSION_FIXED_BY_ADMIN_POLICY);
    EXPECT_EQ(RET_SUCCESS, ret);
    EXPECT_EQ(RET_SUCCESS, AccessTokenKit::GetPermissionFlag(tokenID, CUSTOM_SCREEN_CAPTURE, flag));
    EXPECT_EQ(PERMISSION_FIXED_BY_ADMIN_POLICY, flag);
    EXPECT_EQ(PERMISSION_DENIED, AccessTokenKit::VerifyAccessToken(tokenID, CUSTOM_SCREEN_CAPTURE, false));
    ret = AccessTokenKit::SetPermissionStatusWithPolicy(
        tokenID, permList, PERMISSION_DENIED, PERMISSION_ADMIN_POLICIES_CANCEL);
    EXPECT_EQ(RET_SUCCESS, ret);
    EXPECT_EQ(RET_SUCCESS, AccessTokenKit::GetPermissionFlag(tokenID, CUSTOM_SCREEN_CAPTURE, flag));
    // flag is change.
    EXPECT_EQ(PERMISSION_ADMIN_POLICIES_CANCEL, flag);
    // status is not change.
    EXPECT_EQ(PERMISSION_DENIED, AccessTokenKit::VerifyAccessToken(tokenID, CUSTOM_SCREEN_CAPTURE, false));

    // can set the flag is PERMISSION_FIXED_BY_ADMIN_POLICY
    ret = AccessTokenKit::SetPermissionStatusWithPolicy(
    tokenID, permList, PERMISSION_DENIED, PERMISSION_FIXED_BY_ADMIN_POLICY);
    EXPECT_EQ(RET_SUCCESS, ret);
    EXPECT_EQ(RET_SUCCESS, AccessTokenKit::GetPermissionFlag(tokenID, CUSTOM_SCREEN_CAPTURE, flag));
    EXPECT_EQ(PERMISSION_FIXED_BY_ADMIN_POLICY, flag);
    EXPECT_EQ(PERMISSION_DENIED, AccessTokenKit::VerifyAccessToken(tokenID, CUSTOM_SCREEN_CAPTURE, false));

    EXPECT_EQ(RET_SUCCESS, TestCommon::DeleteTestHapToken(tokenID));
}

/**
 * @tc.name: SetPermissionStatusWithPolicy011
 * @tc.desc: Permission priority test.
 * @tc.type: FUNC
 * @tc.require:Issue Number
 */
HWTEST_F(EdmPolicySetTest, SetPermissionStatusWithPolicy011, TestSize.Level0)
{
    LOGI(ATM_DOMAIN, ATM_TAG, "SetPermissionStatusWithPolicy011");

    g_testHapInfoParams.userID = MOCK_USER_ID_10001;
    AccessTokenIDEx tokenIdEx = TestCommon::AllocAndGrantHapTokenByTest(g_testHapInfoParams, g_testPolicyParams);
    AccessTokenID tokenID = tokenIdEx.tokenIdExStruct.tokenID;
    ASSERT_NE(INVALID_TOKENID, tokenID);
    MockNativeToken mock("edm");

    uint32_t flag = 0;
    int32_t ret = RET_SUCCESS;
    std::vector<std::string> permList = {CUSTOM_SCREEN_CAPTURE};

    for (const uint32_t &permFlag : g_permFlagList) {
        GTEST_LOG_(INFO) << "permFlag: " << permFlag;
        LOGI(ATM_DOMAIN, ATM_TAG, "permFlag: %{public}u", permFlag);
        // GrantPermission the flag is permFlag.
        ret = TestCommon::GrantPermissionByTest(tokenID, CUSTOM_SCREEN_CAPTURE, permFlag);
        EXPECT_EQ(RET_SUCCESS, ret);
        EXPECT_EQ(RET_SUCCESS, AccessTokenKit::GetPermissionFlag(tokenID, CUSTOM_SCREEN_CAPTURE, flag));
        if (permFlag == PERMISSION_PRE_AUTHORIZED_CANCELABLE) {
            // GetPermissionFlag will filt the PERMISSION_PRE_AUTHORIZED_CANCELABLE
            EXPECT_EQ(0, flag);
        } else if (permFlag == PERMISSION_COMPONENT_SET) {
            EXPECT_EQ(PERMISSION_COMPONENT_SET | PERMISSION_ADMIN_POLICIES_CANCEL, flag);
        } else {
            EXPECT_EQ(permFlag, flag);
        }
        EXPECT_EQ(PERMISSION_GRANTED, AccessTokenKit::VerifyAccessToken(tokenID, CUSTOM_SCREEN_CAPTURE, false));

        ret = AccessTokenKit::SetPermissionStatusWithPolicy(
            tokenID, permList, PERMISSION_DENIED, PERMISSION_FIXED_BY_ADMIN_POLICY);
        EXPECT_EQ(RET_SUCCESS, ret);
        EXPECT_EQ(RET_SUCCESS, AccessTokenKit::GetPermissionFlag(tokenID, CUSTOM_SCREEN_CAPTURE, flag));
        EXPECT_EQ(PERMISSION_FIXED_BY_ADMIN_POLICY, flag);

        ret = AccessTokenKit::SetPermissionStatusWithPolicy(
            tokenID, permList, PERMISSION_DENIED, PERMISSION_ADMIN_POLICIES_CANCEL);
        EXPECT_EQ(RET_SUCCESS, ret);
        EXPECT_EQ(RET_SUCCESS, AccessTokenKit::GetPermissionFlag(tokenID, CUSTOM_SCREEN_CAPTURE, flag));
        EXPECT_EQ(PERMISSION_ADMIN_POLICIES_CANCEL, flag);
    }

    // GrantPermission the flag is PERMISSION_SYSTEM_FIXED.
    ret = TestCommon::GrantPermissionByTest(tokenID, CUSTOM_SCREEN_CAPTURE, PERMISSION_SYSTEM_FIXED);
    EXPECT_EQ(RET_SUCCESS, ret);
    EXPECT_EQ(RET_SUCCESS, AccessTokenKit::GetPermissionFlag(tokenID, CUSTOM_SCREEN_CAPTURE, flag));
    EXPECT_EQ(PERMISSION_SYSTEM_FIXED, flag);
    EXPECT_EQ(PERMISSION_GRANTED, AccessTokenKit::VerifyAccessToken(tokenID, CUSTOM_SCREEN_CAPTURE, false));

    // can't set flag is PERMISSION_FIXED_BY_ADMIN_POLICY.
    ret = AccessTokenKit::SetPermissionStatusWithPolicy(
        tokenID, permList, PERMISSION_DENIED, PERMISSION_FIXED_BY_ADMIN_POLICY);
    EXPECT_EQ(ERR_PARAM_INVALID, ret);
    EXPECT_EQ(RET_SUCCESS, AccessTokenKit::GetPermissionFlag(tokenID, CUSTOM_SCREEN_CAPTURE, flag));
    EXPECT_EQ(PERMISSION_GRANTED, AccessTokenKit::VerifyAccessToken(tokenID, CUSTOM_SCREEN_CAPTURE, false));
    EXPECT_EQ(PERMISSION_SYSTEM_FIXED, flag);

    EXPECT_EQ(RET_SUCCESS, TestCommon::DeleteTestHapToken(tokenID));
}

/**
 * @tc.name: SetPermissionStatusWithPolicy012
 * @tc.desc: Permission priority test.
 * @tc.type: FUNC
 * @tc.require:Issue Number
 */
HWTEST_F(EdmPolicySetTest, SetPermissionStatusWithPolicy012, TestSize.Level0)
{
    LOGI(ATM_DOMAIN, ATM_TAG, "SetPermissionStatusWithPolicy012");

    g_testHapInfoParams.userID = MOCK_USER_ID_10001;
    AccessTokenIDEx tokenIdEx = TestCommon::AllocAndGrantHapTokenByTest(g_testHapInfoParams, g_testPolicyParams);
    AccessTokenID tokenID = tokenIdEx.tokenIdExStruct.tokenID;
    ASSERT_NE(INVALID_TOKENID, tokenID);
    MockNativeToken mock("edm");

    uint32_t flag = 0;
    int32_t ret = RET_SUCCESS;
    std::vector<std::string> permList = {CUSTOM_SCREEN_CAPTURE};

    std::vector<uint32_t> permFlagList = {
        PERMISSION_DEFAULT_FLAG,
        PERMISSION_USER_SET,
        PERMISSION_USER_FIXED,
        PERMISSION_PRE_AUTHORIZED_CANCELABLE,
        PERMISSION_COMPONENT_SET,
        PERMISSION_FIXED_FOR_SECURITY_POLICY,
        // PERMISSION_ALLOW_THIS_TIME
    };

    // set flag is PERMISSION_FIXED_BY_ADMIN_POLICY.
    ret = AccessTokenKit::SetPermissionStatusWithPolicy(
        tokenID, permList, PERMISSION_DENIED, PERMISSION_FIXED_BY_ADMIN_POLICY);
    EXPECT_EQ(RET_SUCCESS, ret);
    EXPECT_EQ(RET_SUCCESS, AccessTokenKit::GetPermissionFlag(tokenID, CUSTOM_SCREEN_CAPTURE, flag));
    EXPECT_EQ(PERMISSION_DENIED, AccessTokenKit::VerifyAccessToken(tokenID, CUSTOM_SCREEN_CAPTURE, false));
    EXPECT_EQ(PERMISSION_FIXED_BY_ADMIN_POLICY, flag);

    for (const uint32_t &permFlag : permFlagList) {
        GTEST_LOG_(INFO) << "permFlag: " << permFlag;
        LOGI(ATM_DOMAIN, ATM_TAG, "permFlag: %{public}u", permFlag);
        // can't GrantPermission the flag is permFlag.
        ret = TestCommon::GrantPermissionByTest(tokenID, CUSTOM_SCREEN_CAPTURE, permFlag);
        EXPECT_EQ(ERR_PERMISSION_RESTRICTED, ret);
        EXPECT_EQ(RET_SUCCESS, AccessTokenKit::GetPermissionFlag(tokenID, CUSTOM_SCREEN_CAPTURE, flag));
        EXPECT_EQ(PERMISSION_FIXED_BY_ADMIN_POLICY, flag);
        EXPECT_EQ(PERMISSION_DENIED, AccessTokenKit::VerifyAccessToken(tokenID, CUSTOM_SCREEN_CAPTURE, false));
    }

    // can GrantPermission the flag is PERMISSION_SYSTEM_FIXED.
    ret = TestCommon::GrantPermissionByTest(tokenID, CUSTOM_SCREEN_CAPTURE, PERMISSION_SYSTEM_FIXED);
    EXPECT_EQ(RET_SUCCESS, ret);
    EXPECT_EQ(RET_SUCCESS, AccessTokenKit::GetPermissionFlag(tokenID, CUSTOM_SCREEN_CAPTURE, flag));
    EXPECT_EQ(PERMISSION_SYSTEM_FIXED, flag);
    EXPECT_EQ(PERMISSION_GRANTED, AccessTokenKit::VerifyAccessToken(tokenID, CUSTOM_SCREEN_CAPTURE, false));

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

    // GrantPermission can't set PERMISSION_FIXED_BY_ADMIN_POLICY or PERMISSION_ADMIN_POLICIES_CANCEL
    EXPECT_EQ(ERR_PARAM_INVALID,
        TestCommon::GrantPermissionByTest(tokenID, CUSTOM_SCREEN_CAPTURE, PERMISSION_FIXED_BY_ADMIN_POLICY));
    EXPECT_EQ(ERR_PARAM_INVALID,
        TestCommon::GrantPermissionByTest(tokenID, CUSTOM_SCREEN_CAPTURE, PERMISSION_ADMIN_POLICIES_CANCEL));

    // 1. set flag is PERMISSION_FIXED_BY_ADMIN_POLICY.
    std::vector<std::string> permList = {CUSTOM_SCREEN_CAPTURE};
    int32_t ret = RET_SUCCESS;
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
    
    // RevokePermission can't set PERMISSION_FIXED_BY_ADMIN_POLICY or PERMISSION_ADMIN_POLICIES_CANCEL
    EXPECT_EQ(ERR_PARAM_INVALID,
        TestCommon::RevokePermissionByTest(tokenID, CUSTOM_SCREEN_CAPTURE, PERMISSION_FIXED_BY_ADMIN_POLICY));
    EXPECT_EQ(ERR_PARAM_INVALID,
        TestCommon::RevokePermissionByTest(tokenID, CUSTOM_SCREEN_CAPTURE, PERMISSION_ADMIN_POLICIES_CANCEL));

    // 1. set flag is PERMISSION_FIXED_BY_ADMIN_POLICY.
    std::vector<std::string> permList = {CUSTOM_SCREEN_CAPTURE};
    int32_t ret = RET_SUCCESS;
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
    int32_t ret = RET_SUCCESS;
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

    // 5. set flag is PERMISSION_USER_FIXED
    ret = TestCommon::GrantPermissionByTest(tokenID, CUSTOM_SCREEN_CAPTURE, PERMISSION_USER_FIXED);
    EXPECT_EQ(RET_SUCCESS, ret);
    EXPECT_EQ(RET_SUCCESS, AccessTokenKit::GetPermissionFlag(tokenID, CUSTOM_SCREEN_CAPTURE, flag));
    EXPECT_EQ(PERMISSION_USER_FIXED, flag);

    // 6. can clear flag is PERMISSION_USER_FIXED
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
    int32_t ret = RET_SUCCESS;
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
    int32_t ret = RET_SUCCESS;

    // can't UpdateHapToken flag is PERMISSION_FIXED_BY_ADMIN_POLICY.
    {
        MockNativeToken mock("foundation");
        ret = AccessTokenKit::UpdateHapToken(tokenIdEx, g_updateHapInfo, g_testPolicyParams04);
    }
    EXPECT_EQ(RET_SUCCESS, ret);
    EXPECT_EQ(RET_SUCCESS, AccessTokenKit::GetPermissionFlag(tokenID, CUSTOM_SCREEN_CAPTURE, flag));
    EXPECT_EQ(PERMISSION_DEFAULT_FLAG, flag);
    EXPECT_EQ(PERMISSION_GRANTED, AccessTokenKit::VerifyAccessToken(tokenID, CUSTOM_SCREEN_CAPTURE, false));

    // can't UpdateHapToken flag is PERMISSION_ADMIN_POLICIES_CANCEL.
    {
        MockNativeToken mock("foundation");
        ret = AccessTokenKit::UpdateHapToken(tokenIdEx, g_updateHapInfo, g_testPolicyParams05);
    }
    EXPECT_EQ(RET_SUCCESS, ret);
    EXPECT_EQ(RET_SUCCESS, AccessTokenKit::GetPermissionFlag(tokenID, CUSTOM_SCREEN_CAPTURE, flag));
    EXPECT_EQ(PERMISSION_DEFAULT_FLAG, flag); // PERMISSION_ADMIN_POLICIES_CANCEL not return
    EXPECT_EQ(PERMISSION_GRANTED, AccessTokenKit::VerifyAccessToken(tokenID, CUSTOM_SCREEN_CAPTURE, false));

    // 1. set flag is PERMISSION_FIXED_BY_ADMIN_POLICY.
    std::vector<std::string> permList = {CUSTOM_SCREEN_CAPTURE};
    ret = AccessTokenKit::SetPermissionStatusWithPolicy(
        tokenID, permList, PERMISSION_GRANTED, PERMISSION_FIXED_BY_ADMIN_POLICY);
    EXPECT_EQ(RET_SUCCESS, ret);
    EXPECT_EQ(RET_SUCCESS, AccessTokenKit::GetPermissionFlag(tokenID, CUSTOM_SCREEN_CAPTURE, flag));
    EXPECT_EQ(PERMISSION_FIXED_BY_ADMIN_POLICY, flag);
    EXPECT_EQ(PERMISSION_GRANTED, AccessTokenKit::VerifyAccessToken(tokenID, CUSTOM_SCREEN_CAPTURE, false));

    // 2. can't UpdateHapToken flag is PERMISSION_PRE_AUTHORIZED_CANCELABLE.
    {
        MockNativeToken mock("foundation");
        ret = AccessTokenKit::UpdateHapToken(tokenIdEx, g_updateHapInfo, g_testPolicyParams02);
    }
    EXPECT_EQ(RET_SUCCESS, ret);
    EXPECT_EQ(RET_SUCCESS, AccessTokenKit::GetPermissionFlag(tokenID, CUSTOM_SCREEN_CAPTURE, flag));
    EXPECT_EQ(PERMISSION_FIXED_BY_ADMIN_POLICY, flag);
    EXPECT_EQ(PERMISSION_GRANTED, AccessTokenKit::VerifyAccessToken(tokenID, CUSTOM_SCREEN_CAPTURE, false));

    // 3. can UpdateHapToken flag is PERMISSION_SYSTEM_FIXED.
    {
        MockNativeToken mock("foundation");
        ret = AccessTokenKit::UpdateHapToken(tokenIdEx, g_updateHapInfo, g_testPolicyParams03);
    }
    EXPECT_EQ(RET_SUCCESS, ret);
    EXPECT_EQ(RET_SUCCESS, AccessTokenKit::GetPermissionFlag(tokenID, CUSTOM_SCREEN_CAPTURE, flag));
    EXPECT_EQ(PERMISSION_SYSTEM_FIXED, flag);
    EXPECT_EQ(PERMISSION_GRANTED, AccessTokenKit::VerifyAccessToken(tokenID, CUSTOM_SCREEN_CAPTURE, false));

    EXPECT_EQ(RET_SUCCESS, TestCommon::DeleteTestHapToken(tokenID));
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
    int32_t ret = RET_SUCCESS;
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
    int32_t ret = RET_SUCCESS;
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
}
}
}