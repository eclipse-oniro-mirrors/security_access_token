/*
 * Copyright (c) 2026 Huawei Device Co., Ltd.
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

#include "user_policy_test.h"

#include <algorithm>
#include <atomic>
#include <thread>

#include "accesstoken_kit.h"
#include "accesstoken_common_log.h"
#include "access_token_error.h"
#include "mock_permission.h"
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
const std::string INTERNET = "ohos.permission.INTERNET";
static const std::string GET_NETWORK_STATS = "ohos.permission.GET_NETWORK_STATS";
static const std::string LOCATION = "ohos.permission.LOCATION";
static const std::string REVOKE_SENSITIVE_PERMISSIONS = "ohos.permission.REVOKE_SENSITIVE_PERMISSIONS"; // system_grant
static const std::string MICROPHONE = "ohos.permission.MICROPHONE"; // user_grant
static const std::string CAMERA = "ohos.permission.CAMERA"; // user_grant
static const std::string CUSTOM_SCREEN_CAPTURE = "ohos.permission.CUSTOM_SCREEN_CAPTURE"; // user_grant
static const std::string MANAGE_EDM_POLICY = "ohos.permission.MANAGE_EDM_POLICY"; // system_grant
static const std::string MANAGE_USER_POLICY = "ohos.permission.MANAGE_USER_POLICY"; // system_grant
static const std::string GET_SENSITIVE_PERMISSIONS = "ohos.permission.GET_SENSITIVE_PERMISSIONS"; // system_grant

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

HapInfoParams g_testHapInfoParams = {
    .userID = 0,
    .bundleName = "UserPolicyTest",
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

UpdateHapInfoParams g_updateHapInfo = {
    .appIDDesc = "TEST",
    .apiVersion = 12,
    .isSystemApp = false
};

uint64_t g_selfShellTokenId;
static MockToken* g_mock = nullptr;
} // namespace

void UserPolicyTest::SetUpTestCase()
{
    g_selfShellTokenId = GetSelfTokenID();
    TestCommon::SetTestEvironment(g_selfShellTokenId);

    g_mock = new (std::nothrow) MockToken(g_selfShellTokenId, "privacy_service", false);
    ASSERT_NE(nullptr, g_mock);
    GTEST_LOG_(INFO) << g_mock->GetMockErrorMsg();
    GTEST_LOG_(INFO) << g_mock->GetTokenId();
    g_mock->Grant(MANAGE_USER_POLICY);
    GTEST_LOG_(INFO) << g_mock->GetMockErrorMsg();

    LOGI(ATM_DOMAIN, ATM_TAG, "SetUpTestCase ok.");
}

void UserPolicyTest::TearDownTestCase()
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

void UserPolicyTest::SetUp()
{
    LOGI(ATM_DOMAIN, ATM_TAG, "SetUp ok.");
}

void UserPolicyTest::TearDown()
{
}

#ifdef SUPPORT_MANAGE_USER_POLICY
static const AccessTokenID MOCK_HAP_TOKEN_ID = 0x20000001; // version=1, type=TOKEN_HAP, uniqueId=1
static const int32_t MAX_LENGTH = 256;
static void ExpectPermissionStatusInCache(AccessTokenID tokenId, const std::string& permission,
    int32_t expectedStatus)
{
    std::vector<PermissionStateFull> permStatList;
    EXPECT_EQ(RET_SUCCESS, AccessTokenKit::GetReqPermissions(tokenId, permStatList, true));
    for (const auto& permState : permStatList) {
        if (permState.permissionName == permission) {
            EXPECT_EQ(expectedStatus, permState.grantStatus[0]);
            return;
        }
    }
    EXPECT_TRUE(false) << "permission not found in cache";
}

static bool FindPermissionStatus(const std::vector<PermissionStatus>& permissionInfoList, AccessTokenID tokenId,
    const std::string& permissionName, PermissionStatus& permissionStatus)
{
    auto iter = std::find_if(permissionInfoList.begin(), permissionInfoList.end(),
        [tokenId, &permissionName](const PermissionStatus& status) {
            return status.tokenID == tokenId && status.permissionName == permissionName;
        });
    if (iter == permissionInfoList.end()) {
        return false;
    }
    permissionStatus = *iter;
    return true;
}

static void ExpectPermissionStatusInList(const std::vector<PermissionStatus>& permissionInfoList,
    AccessTokenID tokenId, const std::string& permissionName, int32_t expectedStatus, uint32_t expectedFlag)
{
    PermissionStatus permissionStatus;
    bool found = FindPermissionStatus(permissionInfoList, tokenId, permissionName, permissionStatus);
    EXPECT_TRUE(found);
    if (!found) {
        return;
    }
    EXPECT_EQ(expectedStatus, permissionStatus.grantStatus);
    EXPECT_EQ(expectedFlag, permissionStatus.grantFlag & PERMISSION_RESTRICTED_BY_ADMIN);
}

static void ExpectPermissionQueryState(AccessTokenID tokenId, const std::string& permissionName,
    int32_t expectedVerifyStatus, int32_t expectedQueryStatus, uint32_t expectedFlag,
    int32_t expectedCacheStatus = PERMISSION_GRANTED)
{
    MockToken mock(g_selfShellTokenId, "com.ohos.permissionmanager", true);
    mock.Grant(GET_SENSITIVE_PERMISSIONS);
    // step1: check flag state.
    uint32_t flag = 0;
    EXPECT_EQ(RET_SUCCESS, AccessTokenKit::GetPermissionFlag(tokenId, permissionName, flag));
    EXPECT_EQ(expectedFlag, flag & PERMISSION_RESTRICTED_BY_ADMIN);
    // step2: check cache state.
    ExpectPermissionStatusInCache(tokenId, permissionName, expectedCacheStatus);
    // step3: check VerifyAccessToken and query results.
    EXPECT_EQ(expectedVerifyStatus, AccessTokenKit::VerifyAccessToken(tokenId, permissionName));

    std::vector<PermissionStatus> byPermissionList;
    EXPECT_EQ(RET_SUCCESS, AccessTokenKit::QueryStatusByPermission({ permissionName }, byPermissionList));
    ExpectPermissionStatusInList(byPermissionList, tokenId, permissionName, expectedQueryStatus, expectedFlag);

    std::vector<PermissionStatus> byTokenList;
    EXPECT_EQ(RET_SUCCESS, AccessTokenKit::QueryStatusByTokenID({ tokenId }, byTokenList));
    ExpectPermissionStatusInList(byTokenList, tokenId, permissionName, expectedQueryStatus, expectedFlag);
}

/**
 * @tc.name: SetUserPolicy001
 * @tc.desc: SetUserPolicy failed with invalid parameters.
 * @tc.type: FUNC
 * @tc.require:Issue Number
 */
HWTEST_F(UserPolicyTest, SetUserPolicy001, TestSize.Level1)
{
    std::vector<UserPermissionPolicy> permPolicyListEmpty;
    // empty
    EXPECT_EQ(AccessTokenError::ERR_PARAM_INVALID, AccessTokenKit::SetUserPolicy(permPolicyListEmpty));

    // over single request limit
    const int32_t invalidPolicySize = 201; // 201 is invalid policy size.
    std::vector<UserPermissionPolicy> permPolicyListOverSize(invalidPolicySize);
    EXPECT_EQ(AccessTokenError::ERR_PARAM_INVALID, AccessTokenKit::SetUserPolicy(permPolicyListOverSize));

    UserPermissionPolicy policy;
    policy.permissionName = INTERNET;

    // empty userPolicyList
    EXPECT_EQ(AccessTokenError::ERR_PARAM_INVALID, AccessTokenKit::SetUserPolicy({ policy }));

    policy.userPolicyList = {{ .userId = MOCK_USER_ID_10002, .isRestricted = true }};

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

    // invalid userId
    policy.permissionName = INTERNET;
    policy.userPolicyList[0].userId = -1; // -1: invalid userId
    EXPECT_EQ(AccessTokenError::ERR_PARAM_INVALID, AccessTokenKit::SetUserPolicy({ policy }));
}

/**
 * @tc.name: SetUserPolicy002
 * @tc.desc: SetUserPolicy boundary validation for supported and unsupported policy apl.
 * @tc.type: FUNC
 * @tc.require:Issue Number
 */
HWTEST_F(UserPolicyTest, SetUserPolicy002, TestSize.Level1)
{
    UserPermissionPolicy supportedPolicy = {
        .permissionName = INTERNET,
        .userPolicyList = {{ .userId = MOCK_USER_ID_10001, .isRestricted = true }}
    };
    EXPECT_EQ(RET_SUCCESS, AccessTokenKit::SetUserPolicy({ supportedPolicy }));
    EXPECT_EQ(RET_SUCCESS, AccessTokenKit::ClearUserPolicy({ INTERNET }));

    UserPermissionPolicy unsupportedPolicy = {
        .permissionName = "ohos.permission.POWER_MANAGER",
        .userPolicyList = {{ .userId = MOCK_USER_ID_10001, .isRestricted = true }}
    };
    EXPECT_EQ(AccessTokenError::ERR_PARAM_INVALID, AccessTokenKit::SetUserPolicy({ unsupportedPolicy }));
}

/**
 * @tc.name: SetUserPolicy003
 * @tc.desc: Other caller cannot maintain an existing policy, but can set it after userList becomes empty.
 * @tc.type: FUNC
 * @tc.require:Issue Number
 */
HWTEST_F(UserPolicyTest, SetUserPolicy003, TestSize.Level1)
{
    HapInfoParams testHapInfo = g_testHapInfoParams;
    AccessTokenIDEx fullIdUser1;
    EXPECT_EQ(RET_SUCCESS, TestCommon::AllocTestHapToken(testHapInfo, g_testPolicyParams, fullIdUser1));
    AccessTokenID tokenId = fullIdUser1.tokenIdExStruct.tokenID;

    UserPermissionPolicy policy = {
        .permissionName = INTERNET,
        .userPolicyList = {{ .userId = testHapInfo.userID, .isRestricted = true }}
    };
    EXPECT_EQ(RET_SUCCESS, AccessTokenKit::SetUserPolicy({ policy }));
    ExpectPermissionQueryState(tokenId, INTERNET, PERMISSION_DENIED, PERMISSION_DENIED,
        PERMISSION_RESTRICTED_BY_ADMIN);

    // permisison is set by other process
    {
        MockToken mock(g_selfShellTokenId, "accesstoken_service", false);
        mock.Grant(MANAGE_USER_POLICY);
        EXPECT_EQ(ERR_PERM_POLICY_ALREADY_SET_BY_OTHER, AccessTokenKit::SetUserPolicy({ policy })); // same permission
        ExpectPermissionQueryState(tokenId, INTERNET, PERMISSION_DENIED, PERMISSION_DENIED,
            PERMISSION_RESTRICTED_BY_ADMIN);

        policy.permissionName = GET_NETWORK_STATS;
        EXPECT_EQ(RET_SUCCESS, AccessTokenKit::SetUserPolicy({ policy })); // same permission
        ExpectPermissionQueryState(tokenId, GET_NETWORK_STATS, PERMISSION_DENIED, PERMISSION_DENIED,
            PERMISSION_RESTRICTED_BY_ADMIN);

        EXPECT_EQ(RET_SUCCESS, AccessTokenKit::ClearUserPolicy({ GET_NETWORK_STATS }));
        ExpectPermissionQueryState(tokenId, GET_NETWORK_STATS, PERMISSION_GRANTED, PERMISSION_GRANTED, 0u);
        policy.permissionName = INTERNET;
    }

    policy.userPolicyList[0].isRestricted = false;
    EXPECT_EQ(RET_SUCCESS, AccessTokenKit::SetUserPolicy({ policy }));
    ExpectPermissionQueryState(tokenId, INTERNET, PERMISSION_GRANTED, PERMISSION_GRANTED, 0u);

    // The only controlled user has been removed, so the policy record is deleted and another caller can set it.
    {
        MockToken mock(g_selfShellTokenId, "accesstoken_service", false);
        mock.Grant(MANAGE_USER_POLICY);
        policy.userPolicyList[0].isRestricted = true;
        EXPECT_EQ(RET_SUCCESS, AccessTokenKit::SetUserPolicy({ policy }));
        ExpectPermissionQueryState(tokenId, INTERNET, PERMISSION_DENIED, PERMISSION_DENIED,
            PERMISSION_RESTRICTED_BY_ADMIN);
        EXPECT_EQ(RET_SUCCESS, AccessTokenKit::ClearUserPolicy({ INTERNET }));
        ExpectPermissionQueryState(tokenId, INTERNET, PERMISSION_GRANTED, PERMISSION_GRANTED, 0u);
    }

    EXPECT_EQ(RET_SUCCESS, TestCommon::DeleteTestHapToken(tokenId));
}

/**
 * @tc.name: SetUserPolicy004
 * @tc.desc: SetUserPolicy returns ERR_PERM_POLICY_PERSISTENCE_FLAG_NOT_MATCH when isPersist is inconsistent.
 * @tc.type: FUNC
 * @tc.require:Issue Number
 */
HWTEST_F(UserPolicyTest, SetUserPolicy004, TestSize.Level1)
{
    HapInfoParams testHapInfo = g_testHapInfoParams;
    AccessTokenIDEx fullIdUser1;
    EXPECT_EQ(RET_SUCCESS, TestCommon::AllocTestHapToken(testHapInfo, g_testPolicyParams, fullIdUser1));
    AccessTokenID tokenId = fullIdUser1.tokenIdExStruct.tokenID;

    UserPermissionPolicy policy = {
        .permissionName = INTERNET,
        .userPolicyList = {{ .userId = testHapInfo.userID, .isRestricted = true }},
        .isPersist = true
    };
    EXPECT_EQ(RET_SUCCESS, AccessTokenKit::SetUserPolicy({ policy }));
    ExpectPermissionQueryState(tokenId, INTERNET, PERMISSION_DENIED, PERMISSION_DENIED,
        PERMISSION_RESTRICTED_BY_ADMIN);

    policy.isPersist = false;
    EXPECT_EQ(ERR_PERM_POLICY_PERSISTENCE_FLAG_NOT_MATCH, AccessTokenKit::SetUserPolicy({ policy }));
    ExpectPermissionQueryState(tokenId, INTERNET, PERMISSION_DENIED, PERMISSION_DENIED,
        PERMISSION_RESTRICTED_BY_ADMIN);
    ExpectPermissionQueryState(tokenId, INTERNET, PERMISSION_DENIED, PERMISSION_DENIED,
        PERMISSION_RESTRICTED_BY_ADMIN);

    EXPECT_EQ(RET_SUCCESS, AccessTokenKit::ClearUserPolicy({ INTERNET }));
    ExpectPermissionQueryState(tokenId, INTERNET, PERMISSION_GRANTED, PERMISSION_GRANTED, 0u);

    policy.isPersist = false;
    EXPECT_EQ(RET_SUCCESS, AccessTokenKit::SetUserPolicy({ policy }));
    ExpectPermissionQueryState(tokenId, INTERNET, PERMISSION_DENIED, PERMISSION_DENIED,
        PERMISSION_RESTRICTED_BY_ADMIN);

    policy.isPersist = true;
    EXPECT_EQ(ERR_PERM_POLICY_PERSISTENCE_FLAG_NOT_MATCH, AccessTokenKit::SetUserPolicy({ policy }));
    ExpectPermissionQueryState(tokenId, INTERNET, PERMISSION_DENIED, PERMISSION_DENIED,
        PERMISSION_RESTRICTED_BY_ADMIN);

    UserPermissionPolicy policyMismatch = {
        .permissionName = GET_NETWORK_STATS,
        .userPolicyList = {{ .userId = testHapInfo.userID, .isRestricted = true }},
        .isPersist = false
    };
    UserPermissionPolicy policyMismatch2 = policyMismatch;
    policyMismatch2.isPersist = true;
    EXPECT_EQ(ERR_PERM_POLICY_PERSISTENCE_FLAG_NOT_MATCH,
        AccessTokenKit::SetUserPolicy({ policyMismatch, policyMismatch2 }));
    ExpectPermissionQueryState(tokenId, GET_NETWORK_STATS, PERMISSION_GRANTED, PERMISSION_GRANTED, 0u);

    EXPECT_EQ(RET_SUCCESS, AccessTokenKit::ClearUserPolicy({ INTERNET }));
    ExpectPermissionQueryState(tokenId, INTERNET, PERMISSION_GRANTED, PERMISSION_GRANTED, 0u);
    EXPECT_EQ(RET_SUCCESS, TestCommon::DeleteTestHapToken(tokenId));
}

/**
 * @tc.name: SetUserPolicy005
 * @tc.desc: SetUserPolicy batch is atomic when one policy fails validation.
 * @tc.type: FUNC
 * @tc.require:Issue Number
 */
HWTEST_F(UserPolicyTest, SetUserPolicy005, TestSize.Level1)
{
    HapInfoParams testHapInfo = g_testHapInfoParams;
    testHapInfo.userID = MOCK_USER_ID_10001;
    AccessTokenIDEx fullIdUser1;
    EXPECT_EQ(RET_SUCCESS, TestCommon::AllocTestHapToken(testHapInfo, g_testPolicyParams, fullIdUser1));
    AccessTokenID tokenId = fullIdUser1.tokenIdExStruct.tokenID;

    UserPermissionPolicy policy1 = {
        .permissionName = INTERNET,
        .userPolicyList = {{ .userId = MOCK_USER_ID_10001, .isRestricted = true }}
    };
    UserPermissionPolicy policy2 = {
        .permissionName = GET_NETWORK_STATS,
        .userPolicyList = {{ .userId = -1, .isRestricted = true }}
    };
    EXPECT_EQ(AccessTokenError::ERR_PARAM_INVALID, AccessTokenKit::SetUserPolicy({ policy1, policy2 }));
    ExpectPermissionQueryState(tokenId, INTERNET, PERMISSION_GRANTED, PERMISSION_GRANTED, 0u);
    ExpectPermissionQueryState(tokenId, GET_NETWORK_STATS, PERMISSION_GRANTED, PERMISSION_GRANTED, 0u);

    EXPECT_EQ(RET_SUCCESS, AccessTokenKit::SetUserPolicy({ policy1 }));
    ExpectPermissionQueryState(tokenId, INTERNET, PERMISSION_DENIED, PERMISSION_DENIED,
        PERMISSION_RESTRICTED_BY_ADMIN);

    EXPECT_EQ(AccessTokenError::ERR_PARAM_INVALID, AccessTokenKit::SetUserPolicy({ policy2, policy1 }));
    ExpectPermissionQueryState(tokenId, INTERNET, PERMISSION_DENIED, PERMISSION_DENIED,
        PERMISSION_RESTRICTED_BY_ADMIN);
    ExpectPermissionQueryState(tokenId, GET_NETWORK_STATS, PERMISSION_GRANTED, PERMISSION_GRANTED, 0u);

    EXPECT_EQ(RET_SUCCESS, AccessTokenKit::ClearUserPolicy({ INTERNET }));
    EXPECT_EQ(RET_SUCCESS, TestCommon::DeleteTestHapToken(tokenId));
}

/**
 * @tc.name: SetUserPolicy006
 * @tc.desc: Initial false policy does not create a policy record; empty userList removes the record.
 * @tc.type: FUNC
 * @tc.require:Issue Number
 */
HWTEST_F(UserPolicyTest, SetUserPolicy006, TestSize.Level1)
{
    HapInfoParams testHapInfo = g_testHapInfoParams;
    AccessTokenIDEx fullIdUser1;
    EXPECT_EQ(RET_SUCCESS, TestCommon::AllocTestHapToken(testHapInfo, g_testPolicyParams, fullIdUser1));
    AccessTokenID tokenId = fullIdUser1.tokenIdExStruct.tokenID;

    UserPermissionPolicy policy = {
        .permissionName = INTERNET,
        .userPolicyList = {{ .userId = testHapInfo.userID, .isRestricted = false }}
    };
    // A sets isRestricted=false first. No effective policy record should be created.
    EXPECT_EQ(RET_SUCCESS, AccessTokenKit::SetUserPolicy({ policy }));
    ExpectPermissionQueryState(tokenId, INTERNET, PERMISSION_GRANTED, PERMISSION_GRANTED, 0u);
    EXPECT_EQ(AccessTokenError::ERR_PERM_POLICY_NOT_SET, AccessTokenKit::ClearUserPolicy({ INTERNET }));

    {
        MockToken mock(g_selfShellTokenId, "accesstoken_service", false);
        mock.Grant(MANAGE_USER_POLICY);
        policy.userPolicyList[0].isRestricted = true;
        // Because A did not create a policy record, B can set the same permission directly.
        EXPECT_EQ(RET_SUCCESS, AccessTokenKit::SetUserPolicy({ policy }));
        ExpectPermissionQueryState(tokenId, INTERNET, PERMISSION_DENIED, PERMISSION_DENIED,
            PERMISSION_RESTRICTED_BY_ADMIN);

        EXPECT_EQ(RET_SUCCESS, AccessTokenKit::ClearUserPolicy({ INTERNET }));
        ExpectPermissionQueryState(tokenId, INTERNET, PERMISSION_GRANTED, PERMISSION_GRANTED, 0u);
    }

    policy.userPolicyList[0].isRestricted = true;
    EXPECT_EQ(RET_SUCCESS, AccessTokenKit::SetUserPolicy({ policy }));
    ExpectPermissionQueryState(tokenId, INTERNET, PERMISSION_DENIED, PERMISSION_DENIED,
        PERMISSION_RESTRICTED_BY_ADMIN);

    policy.userPolicyList[0].isRestricted = false;
    EXPECT_EQ(RET_SUCCESS, AccessTokenKit::SetUserPolicy({ policy }));
    ExpectPermissionQueryState(tokenId, INTERNET, PERMISSION_GRANTED, PERMISSION_GRANTED, 0u);

    {
        MockToken mock(g_selfShellTokenId, "accesstoken_service", false);
        mock.Grant(MANAGE_USER_POLICY);
        policy.userPolicyList[0].isRestricted = true;
        EXPECT_EQ(RET_SUCCESS, AccessTokenKit::SetUserPolicy({ policy }));
        ExpectPermissionQueryState(tokenId, INTERNET, PERMISSION_DENIED, PERMISSION_DENIED,
            PERMISSION_RESTRICTED_BY_ADMIN);
        EXPECT_EQ(RET_SUCCESS, AccessTokenKit::ClearUserPolicy({ INTERNET }));
    }
    EXPECT_EQ(RET_SUCCESS, TestCommon::DeleteTestHapToken(tokenId));
}

/**
 * @tc.name: SetUserPolicy007
 * @tc.desc: User policy keeps real grant status and exposes effective denied status with restricted flag.
 * @tc.type: FUNC
 * @tc.require:Issue Number
 */
HWTEST_F(UserPolicyTest, SetUserPolicy007, TestSize.Level1)
{
    HapInfoParams testHapInfo = g_testHapInfoParams;
    AccessTokenIDEx fullId;
    ASSERT_EQ(RET_SUCCESS, TestCommon::AllocTestHapToken(testHapInfo, g_testPolicyParams, fullId));
    AccessTokenID tokenId = fullId.tokenIdExStruct.tokenID;

    ExpectPermissionQueryState(tokenId, INTERNET, PERMISSION_GRANTED, PERMISSION_GRANTED, 0u);

    UserPermissionPolicy policy = {
        .permissionName = INTERNET,
        .userPolicyList = {{ .userId = testHapInfo.userID, .isRestricted = true }}
    };
    EXPECT_EQ(RET_SUCCESS, AccessTokenKit::SetUserPolicy({ policy }));
    ExpectPermissionQueryState(tokenId, INTERNET, PERMISSION_DENIED, PERMISSION_DENIED,
        PERMISSION_RESTRICTED_BY_ADMIN);

    EXPECT_EQ(RET_SUCCESS, AccessTokenKit::ClearUserPolicy({ INTERNET }));
    ExpectPermissionQueryState(tokenId, INTERNET, PERMISSION_GRANTED, PERMISSION_GRANTED, 0u);
    EXPECT_EQ(RET_SUCCESS, TestCommon::DeleteTestHapToken(tokenId));
}

/**
 * @tc.name: SetUserPolicy008
 * @tc.desc: SetUserPolicy adds controlled users incrementally and keeps different permissions independent.
 * @tc.type: FUNC
 * @tc.require:Issue Number
 */
HWTEST_F(UserPolicyTest, SetUserPolicy008, TestSize.Level1)
{
    HapInfoParams testHapInfo = g_testHapInfoParams;
    testHapInfo.userID = MOCK_USER_ID_10001;
    AccessTokenIDEx fullIdUser1;
    EXPECT_EQ(RET_SUCCESS, TestCommon::AllocTestHapToken(testHapInfo, g_testPolicyParams, fullIdUser1));
    AccessTokenID tokenId1 = fullIdUser1.tokenIdExStruct.tokenID;
    ExpectPermissionQueryState(tokenId1, INTERNET, PERMISSION_GRANTED, PERMISSION_GRANTED, 0u);
    ExpectPermissionQueryState(tokenId1, GET_NETWORK_STATS, PERMISSION_GRANTED, PERMISSION_GRANTED, 0u);

    testHapInfo.userID = MOCK_USER_ID_10002;
    AccessTokenIDEx fullIdUser2;
    EXPECT_EQ(RET_SUCCESS, TestCommon::AllocTestHapToken(testHapInfo, g_testPolicyParams, fullIdUser2));
    AccessTokenID tokenId2 = fullIdUser2.tokenIdExStruct.tokenID;
    ExpectPermissionQueryState(tokenId2, INTERNET, PERMISSION_GRANTED, PERMISSION_GRANTED, 0u);
    ExpectPermissionQueryState(tokenId2, GET_NETWORK_STATS, PERMISSION_GRANTED, PERMISSION_GRANTED, 0u);

    UserPermissionPolicy policy1 = {
        .permissionName = INTERNET,
        .userPolicyList = {{ .userId = MOCK_USER_ID_10001, .isRestricted = true }}
    };
    EXPECT_EQ(RET_SUCCESS, AccessTokenKit::SetUserPolicy({ policy1 }));
    ExpectPermissionQueryState(tokenId1, INTERNET, PERMISSION_DENIED, PERMISSION_DENIED,
        PERMISSION_RESTRICTED_BY_ADMIN);
    ExpectPermissionQueryState(tokenId2, INTERNET, PERMISSION_GRANTED, PERMISSION_GRANTED, 0u);

    UserPermissionPolicy policyAddUser = {
        .permissionName = INTERNET,
        .userPolicyList = {{ .userId = MOCK_USER_ID_10002, .isRestricted = true }}
    };
    UserPermissionPolicy policyNewPermission = {
        .permissionName = GET_NETWORK_STATS,
        .userPolicyList = {{ .userId = MOCK_USER_ID_10002, .isRestricted = true }}
    };
    EXPECT_EQ(RET_SUCCESS, AccessTokenKit::SetUserPolicy({ policyAddUser, policyNewPermission }));

    ExpectPermissionQueryState(tokenId1, INTERNET, PERMISSION_DENIED, PERMISSION_DENIED,
        PERMISSION_RESTRICTED_BY_ADMIN);
    ExpectPermissionQueryState(tokenId1, GET_NETWORK_STATS, PERMISSION_GRANTED, PERMISSION_GRANTED, 0u);
    ExpectPermissionQueryState(tokenId2, INTERNET, PERMISSION_DENIED, PERMISSION_DENIED,
        PERMISSION_RESTRICTED_BY_ADMIN);
    ExpectPermissionQueryState(tokenId2, GET_NETWORK_STATS, PERMISSION_DENIED, PERMISSION_DENIED,
        PERMISSION_RESTRICTED_BY_ADMIN);

    EXPECT_EQ(RET_SUCCESS, AccessTokenKit::ClearUserPolicy({ INTERNET, GET_NETWORK_STATS }));
    ExpectPermissionQueryState(tokenId1, INTERNET, PERMISSION_GRANTED, PERMISSION_GRANTED, 0u);
    ExpectPermissionQueryState(tokenId1, GET_NETWORK_STATS, PERMISSION_GRANTED, PERMISSION_GRANTED, 0u);
    ExpectPermissionQueryState(tokenId2, INTERNET, PERMISSION_GRANTED, PERMISSION_GRANTED, 0u);
    ExpectPermissionQueryState(tokenId2, GET_NETWORK_STATS, PERMISSION_GRANTED, PERMISSION_GRANTED, 0u);
    EXPECT_EQ(RET_SUCCESS, TestCommon::DeleteTestHapToken(tokenId1));
    EXPECT_EQ(RET_SUCCESS, TestCommon::DeleteTestHapToken(tokenId2));
}

/**
 * @tc.name: SetUserPolicy009
 * @tc.desc: SetUserPolicy removes part of controlled users for the same permission.
 * @tc.type: FUNC
 * @tc.require:Issue Number
 */
HWTEST_F(UserPolicyTest, SetUserPolicy009, TestSize.Level1)
{
    HapInfoParams testHapInfo = g_testHapInfoParams;
    testHapInfo.userID = MOCK_USER_ID_10001;
    AccessTokenIDEx fullIdUser1;
    EXPECT_EQ(RET_SUCCESS, TestCommon::AllocTestHapToken(testHapInfo, g_testPolicyParams, fullIdUser1));
    AccessTokenID tokenId1 = fullIdUser1.tokenIdExStruct.tokenID;

    testHapInfo.userID = MOCK_USER_ID_10002;
    AccessTokenIDEx fullIdUser2;
    EXPECT_EQ(RET_SUCCESS, TestCommon::AllocTestHapToken(testHapInfo, g_testPolicyParams, fullIdUser2));
    AccessTokenID tokenId2 = fullIdUser2.tokenIdExStruct.tokenID;

    ExpectPermissionQueryState(tokenId1, INTERNET, PERMISSION_GRANTED, PERMISSION_GRANTED, 0u);
    ExpectPermissionQueryState(tokenId2, INTERNET, PERMISSION_GRANTED, PERMISSION_GRANTED, 0u);

    UserPermissionPolicy policy = {
        .permissionName = INTERNET,
        .userPolicyList = {
            { .userId = MOCK_USER_ID_10001, .isRestricted = true},
            { .userId = MOCK_USER_ID_10002, .isRestricted = true},
        }
    };
    // first set policy
    EXPECT_EQ(RET_SUCCESS, AccessTokenKit::SetUserPolicy({ policy }));
    ExpectPermissionQueryState(tokenId1, INTERNET, PERMISSION_DENIED, PERMISSION_DENIED,
        PERMISSION_RESTRICTED_BY_ADMIN);
    ExpectPermissionQueryState(tokenId2, INTERNET, PERMISSION_DENIED, PERMISSION_DENIED,
        PERMISSION_RESTRICTED_BY_ADMIN);

    // second set policy
    policy.userPolicyList[0].isRestricted = false;
    EXPECT_EQ(RET_SUCCESS, AccessTokenKit::SetUserPolicy({ policy }));
    ExpectPermissionQueryState(tokenId1, INTERNET, PERMISSION_GRANTED, PERMISSION_GRANTED, 0u);
    ExpectPermissionQueryState(tokenId2, INTERNET, PERMISSION_DENIED, PERMISSION_DENIED,
        PERMISSION_RESTRICTED_BY_ADMIN);

    EXPECT_EQ(RET_SUCCESS, AccessTokenKit::ClearUserPolicy({ INTERNET }));
    ExpectPermissionQueryState(tokenId1, INTERNET, PERMISSION_GRANTED, PERMISSION_GRANTED, 0u);
    ExpectPermissionQueryState(tokenId2, INTERNET, PERMISSION_GRANTED, PERMISSION_GRANTED, 0u);

    EXPECT_EQ(RET_SUCCESS, TestCommon::DeleteTestHapToken(tokenId1));
    EXPECT_EQ(RET_SUCCESS, TestCommon::DeleteTestHapToken(tokenId2));
}

/**
 * @tc.name: SetUserPolicy010
 * @tc.desc: The same caller is allowed to call SetUserPolicy multiple times to set the same policy.
 * @tc.type: FUNC
 * @tc.require:Issue Number
 */
HWTEST_F(UserPolicyTest, SetUserPolicy010, TestSize.Level1)
{
    HapInfoParams testHapInfo = g_testHapInfoParams;
    AccessTokenIDEx fullIdUser1;
    EXPECT_EQ(RET_SUCCESS, TestCommon::AllocTestHapToken(testHapInfo, g_testPolicyParams, fullIdUser1));
    AccessTokenID tokenId = fullIdUser1.tokenIdExStruct.tokenID;

    UserPermissionPolicy policy = {
        .permissionName = INTERNET,
        .userPolicyList = {{ .userId = testHapInfo.userID, .isRestricted = true }}
    };
    EXPECT_EQ(RET_SUCCESS, AccessTokenKit::SetUserPolicy({ policy }));

    ExpectPermissionQueryState(tokenId, INTERNET, PERMISSION_DENIED, PERMISSION_DENIED,
        PERMISSION_RESTRICTED_BY_ADMIN);

    EXPECT_EQ(RET_SUCCESS, AccessTokenKit::ClearUserPolicy({ INTERNET }));
    ExpectPermissionQueryState(tokenId, INTERNET, PERMISSION_GRANTED, PERMISSION_GRANTED, 0u);
    EXPECT_EQ(RET_SUCCESS, TestCommon::DeleteTestHapToken(tokenId));
}

/**
 * @tc.name: SetUserPolicy011
 * @tc.desc: 1. SetUserPolicy; 2. Install hap, permission is restricted.
 * @tc.type: FUNC
 * @tc.require:Issue Number
 */
HWTEST_F(UserPolicyTest, SetUserPolicy011, TestSize.Level1)
{
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
    ExpectPermissionQueryState(tokenId, INTERNET, PERMISSION_DENIED, PERMISSION_DENIED,
        PERMISSION_RESTRICTED_BY_ADMIN);

    // clear policy, permission is restored
    EXPECT_EQ(RET_SUCCESS, AccessTokenKit::ClearUserPolicy({ INTERNET }));
    ExpectPermissionQueryState(tokenId, INTERNET, PERMISSION_GRANTED, PERMISSION_GRANTED, 0u);

    EXPECT_EQ(RET_SUCCESS, TestCommon::DeleteTestHapToken(tokenId));
}

/**
 * @tc.name: SetUserPolicy012
 * @tc.desc: 1. Install hap, permission is restricted; 2. SetUserPolicy.
 * @tc.type: FUNC
 * @tc.require:Issue Number
 */
HWTEST_F(UserPolicyTest, SetUserPolicy012, TestSize.Level1)
{
    HapInfoParams testHapInfo = g_testHapInfoParams;
    testHapInfo.userID = MOCK_USER_ID_10001;
    AccessTokenIDEx fullIdUser1;
    EXPECT_EQ(RET_SUCCESS, TestCommon::AllocTestHapToken(testHapInfo, g_testPolicyParams, fullIdUser1));
    AccessTokenID tokenId = fullIdUser1.tokenIdExStruct.tokenID;

    // system_grant: granted defaultly
    ExpectPermissionQueryState(tokenId, INTERNET, PERMISSION_GRANTED, PERMISSION_GRANTED, 0u);

    UserPermissionPolicy policy = {
        .permissionName = INTERNET,
        .userPolicyList = {{ .userId = MOCK_USER_ID_10001, .isRestricted = true }}
    };
    EXPECT_EQ(RET_SUCCESS, AccessTokenKit::SetUserPolicy({ policy }));

    // system_grant: Denied by VerifyAccessToken(restricted by policy)
    ExpectPermissionQueryState(tokenId, INTERNET, PERMISSION_DENIED, PERMISSION_DENIED,
        PERMISSION_RESTRICTED_BY_ADMIN);

    // clear policy, permission is restored
    EXPECT_EQ(RET_SUCCESS, AccessTokenKit::ClearUserPolicy({ INTERNET }));
    ExpectPermissionQueryState(tokenId, INTERNET, PERMISSION_GRANTED, PERMISSION_GRANTED, 0u);

    EXPECT_EQ(RET_SUCCESS, TestCommon::DeleteTestHapToken(tokenId));
}

/**
 * @tc.name: SetUserPolicy013
 * @tc.desc: SetUserPolicy refreshes effective grant state and restricted flag.
 * @tc.type: FUNC
 * @tc.require:Issue Number
 */
HWTEST_F(UserPolicyTest, SetUserPolicy013, TestSize.Level1)
{
    HapInfoParams testHapInfo = g_testHapInfoParams;
    testHapInfo.userID = MOCK_USER_ID_10001;
    AccessTokenIDEx fullId;
    EXPECT_EQ(RET_SUCCESS, TestCommon::AllocTestHapToken(testHapInfo, g_testPolicyParams, fullId));
    AccessTokenID tokenId = fullId.tokenIdExStruct.tokenID;

    ExpectPermissionQueryState(tokenId, INTERNET, PERMISSION_GRANTED, PERMISSION_GRANTED, 0u);

    UserPermissionPolicy policy = {
        .permissionName = INTERNET,
        .userPolicyList = {{ .userId = MOCK_USER_ID_10001, .isRestricted = true }}
    };
    EXPECT_EQ(RET_SUCCESS, AccessTokenKit::SetUserPolicy({ policy }));
    ExpectPermissionQueryState(tokenId, INTERNET, PERMISSION_DENIED, PERMISSION_DENIED,
        PERMISSION_RESTRICTED_BY_ADMIN);

    EXPECT_EQ(RET_SUCCESS, AccessTokenKit::ClearUserPolicy({ INTERNET }));
    ExpectPermissionQueryState(tokenId, INTERNET, PERMISSION_GRANTED, PERMISSION_GRANTED, 0u);
    EXPECT_EQ(RET_SUCCESS, TestCommon::DeleteTestHapToken(tokenId));
}

/**
 * @tc.name: ClearUserPolicy001
 * @tc.desc: ClearUserPolicy failed: 1. invalid permissionList; 2. invalid permission of permissionList.
 * @tc.type: FUNC
 * @tc.require:Issue Number
 */
HWTEST_F(UserPolicyTest, ClearUserPolicy001, TestSize.Level1)
{
    std::vector<std::string> permListEmpty;
    // empty
    EXPECT_EQ(AccessTokenError::ERR_PARAM_INVALID, AccessTokenKit::ClearUserPolicy(permListEmpty));

    // oversize
    const int32_t invalidSize = 201; // 201 is invalid size.
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

    HapInfoParams testHapInfo = g_testHapInfoParams;
    AccessTokenIDEx fullIdUser1;
    EXPECT_EQ(RET_SUCCESS, TestCommon::AllocTestHapToken(testHapInfo, g_testPolicyParams, fullIdUser1));
    AccessTokenID tokenId = fullIdUser1.tokenIdExStruct.tokenID;

    UserPermissionPolicy policy = {
        .permissionName = INTERNET,
        .userPolicyList = {{ .userId = testHapInfo.userID, .isRestricted = true }}
    };
    EXPECT_EQ(RET_SUCCESS, AccessTokenKit::SetUserPolicy({ policy }));
    ExpectPermissionQueryState(tokenId, INTERNET, PERMISSION_DENIED, PERMISSION_DENIED,
        PERMISSION_RESTRICTED_BY_ADMIN);

    EXPECT_EQ(RET_SUCCESS, AccessTokenKit::ClearUserPolicy({ INTERNET }));
    ExpectPermissionQueryState(tokenId, INTERNET, PERMISSION_GRANTED, PERMISSION_GRANTED, 0u);
    EXPECT_EQ(AccessTokenError::ERR_PERM_POLICY_NOT_SET, AccessTokenKit::ClearUserPolicy({ INTERNET }));

    EXPECT_EQ(RET_SUCCESS, TestCommon::DeleteTestHapToken(tokenId));
}

/**
 * @tc.name: ClearUserPolicy002
 * @tc.desc: ClearUserPolicy only clears policy set by the same caller.
 * Another caller returns ERR_PERM_POLICY_ALREADY_SET_BY_OTHER.
 * @tc.type: FUNC
 * @tc.require:Issue Number
 */
HWTEST_F(UserPolicyTest, ClearUserPolicy002, TestSize.Level1)
{
    HapInfoParams testHapInfo = g_testHapInfoParams;
    AccessTokenIDEx fullIdUser1;
    EXPECT_EQ(RET_SUCCESS, TestCommon::AllocTestHapToken(testHapInfo, g_testPolicyParams, fullIdUser1));
    AccessTokenID tokenId = fullIdUser1.tokenIdExStruct.tokenID;

    UserPermissionPolicy policy1 = {
        .permissionName = INTERNET,
        .userPolicyList = {{ .userId = testHapInfo.userID, .isRestricted = true }}
    };
    EXPECT_EQ(RET_SUCCESS, AccessTokenKit::SetUserPolicy({ policy1 }));
    ExpectPermissionQueryState(tokenId, INTERNET, PERMISSION_DENIED, PERMISSION_DENIED,
        PERMISSION_RESTRICTED_BY_ADMIN);

    {
        MockToken mock(g_selfShellTokenId, "accesstoken_service", false);
        mock.Grant(MANAGE_USER_POLICY);
        EXPECT_EQ(ERR_PERM_POLICY_ALREADY_SET_BY_OTHER, AccessTokenKit::ClearUserPolicy({ INTERNET }));
    }

    EXPECT_EQ(RET_SUCCESS, AccessTokenKit::ClearUserPolicy({ INTERNET }));
    ExpectPermissionQueryState(tokenId, INTERNET, PERMISSION_GRANTED, PERMISSION_GRANTED, 0u);

    EXPECT_EQ(RET_SUCCESS, TestCommon::DeleteTestHapToken(tokenId));
}

/**
 * @tc.name: ClearUserPolicy003
 * @tc.desc: When a permission policy fails to be cleared from the permission list,
 * other policies also fail to be cleared during the same interface call.
 * @tc.type: FUNC
 * @tc.require:Issue Number
 */
HWTEST_F(UserPolicyTest, ClearUserPolicy003, TestSize.Level1)
{
    HapInfoParams testHapInfo = g_testHapInfoParams;
    UserPermissionPolicy policy = {
        .permissionName = INTERNET,
        .userPolicyList = {{ .userId = testHapInfo.userID, .isRestricted = true }}
    };
    EXPECT_EQ(RET_SUCCESS, AccessTokenKit::SetUserPolicy({ policy }));

    AccessTokenIDEx fullIdUser1;
    EXPECT_EQ(RET_SUCCESS, TestCommon::AllocTestHapToken(testHapInfo, g_testPolicyParams, fullIdUser1));
    AccessTokenID tokenId = fullIdUser1.tokenIdExStruct.tokenID;
    ExpectPermissionQueryState(tokenId, INTERNET, PERMISSION_DENIED, PERMISSION_DENIED,
        PERMISSION_RESTRICTED_BY_ADMIN);

    EXPECT_EQ(AccessTokenError::ERR_PARAM_INVALID, AccessTokenKit::ClearUserPolicy({ INTERNET, "test" }));
    ExpectPermissionQueryState(tokenId, INTERNET, PERMISSION_DENIED, PERMISSION_DENIED,
        PERMISSION_RESTRICTED_BY_ADMIN);

    {
        MockToken mock(g_selfShellTokenId, "accesstoken_service", false);
        mock.Grant(MANAGE_USER_POLICY);
        EXPECT_EQ(ERR_PERM_POLICY_ALREADY_SET_BY_OTHER, AccessTokenKit::ClearUserPolicy({ INTERNET }));
    }

    EXPECT_EQ(RET_SUCCESS, AccessTokenKit::ClearUserPolicy({ INTERNET }));
    ExpectPermissionQueryState(tokenId, INTERNET, PERMISSION_GRANTED, PERMISSION_GRANTED, 0u);

    EXPECT_EQ(RET_SUCCESS, TestCommon::DeleteTestHapToken(tokenId));
}

/**
 * @tc.name: PolicyWhiteListTest001
 * @tc.desc: UpdatePolicyWhiteList/GetPolicyWhiteList basic function and invalid parameter test.
 * @tc.type: FUNC
 * @tc.require:Issue Number
 */
HWTEST_F(UserPolicyTest, PolicyWhiteListTest001, TestSize.Level1)
{
    EXPECT_EQ(ERR_PARAM_INVALID, AccessTokenKit::UpdatePolicyWhiteList(INVALID_TOKENID, INTERNET, ADD));
    EXPECT_EQ(ERR_PARAM_INVALID, AccessTokenKit::UpdatePolicyWhiteList(MOCK_HAP_TOKEN_ID, "", ADD));

    std::string invalidPermName(MAX_LENGTH + 1, 'A');
    EXPECT_EQ(ERR_PARAM_INVALID, AccessTokenKit::UpdatePolicyWhiteList(MOCK_HAP_TOKEN_ID, invalidPermName, ADD));
    EXPECT_EQ(ERR_PARAM_INVALID,
        AccessTokenKit::UpdatePolicyWhiteList(MOCK_HAP_TOKEN_ID, INTERNET, static_cast<UpdateWhiteListType>(2)));

    std::vector<AccessTokenID> tokenIdList = {MOCK_HAP_TOKEN_ID};
    EXPECT_EQ(ERR_PARAM_INVALID, AccessTokenKit::GetPolicyWhiteList("", tokenIdList));
    EXPECT_EQ(ERR_PARAM_INVALID, AccessTokenKit::GetPolicyWhiteList(invalidPermName, tokenIdList));

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

    ExpectPermissionQueryState(tokenId, INTERNET, PERMISSION_DENIED, PERMISSION_DENIED,
        PERMISSION_RESTRICTED_BY_ADMIN);

    tokenIdList.clear();
    EXPECT_EQ(RET_SUCCESS, AccessTokenKit::GetPolicyWhiteList(INTERNET, tokenIdList));
    EXPECT_TRUE(tokenIdList.empty());

    EXPECT_EQ(RET_SUCCESS, AccessTokenKit::UpdatePolicyWhiteList(tokenId, INTERNET, ADD));
    ExpectPermissionQueryState(tokenId, INTERNET, PERMISSION_GRANTED, PERMISSION_GRANTED, 0u);

    tokenIdList.clear();
    EXPECT_EQ(RET_SUCCESS, AccessTokenKit::GetPolicyWhiteList(INTERNET, tokenIdList));
    ASSERT_EQ(1u, tokenIdList.size());
    EXPECT_EQ(tokenId, tokenIdList[0]);

    EXPECT_EQ(RET_SUCCESS, AccessTokenKit::UpdatePolicyWhiteList(tokenId, INTERNET, DELETE));
    ExpectPermissionQueryState(tokenId, INTERNET, PERMISSION_DENIED, PERMISSION_DENIED,
        PERMISSION_RESTRICTED_BY_ADMIN);

    EXPECT_EQ(RET_SUCCESS, AccessTokenKit::ClearUserPolicy({ INTERNET }));
    EXPECT_EQ(RET_SUCCESS, TestCommon::DeleteTestHapToken(tokenId));
}

/**
 * @tc.name: PolicyWhiteListTest002
 * @tc.desc: Whitelist can only be updated when policy exists and caller is the controller.
 * @tc.type: FUNC
 * @tc.require:Issue Number
 */
HWTEST_F(UserPolicyTest, PolicyWhiteListTest002, TestSize.Level1)
{
    HapInfoParams testHapInfo = g_testHapInfoParams;
    testHapInfo.userID = MOCK_USER_ID_10001;
    AccessTokenIDEx fullIdUser1;
    EXPECT_EQ(RET_SUCCESS, TestCommon::AllocTestHapToken(testHapInfo, g_testPolicyParams, fullIdUser1));
    AccessTokenID tokenId = fullIdUser1.tokenIdExStruct.tokenID;

    EXPECT_EQ(ERR_PERM_POLICY_NOT_SET, AccessTokenKit::UpdatePolicyWhiteList(tokenId, INTERNET, ADD));

    UserPermissionPolicy policy = {
        .permissionName = INTERNET,
        .userPolicyList = {{ .userId = MOCK_USER_ID_10001, .isRestricted = true }}
    };
    EXPECT_EQ(RET_SUCCESS, AccessTokenKit::SetUserPolicy({ policy }));

    {
        MockToken mock(g_selfShellTokenId, "accesstoken_service", false);
        mock.Grant(MANAGE_USER_POLICY);
        EXPECT_EQ(ERR_PERM_POLICY_ALREADY_SET_BY_OTHER,
            AccessTokenKit::UpdatePolicyWhiteList(tokenId, INTERNET, ADD));
    }
    std::vector<AccessTokenID> tokenIdList;
    EXPECT_EQ(RET_SUCCESS, AccessTokenKit::GetPolicyWhiteList(INTERNET, tokenIdList));
    EXPECT_TRUE(tokenIdList.empty());

    EXPECT_EQ(RET_SUCCESS, AccessTokenKit::UpdatePolicyWhiteList(tokenId, INTERNET, ADD));
    tokenIdList.clear();
    EXPECT_EQ(RET_SUCCESS, AccessTokenKit::GetPolicyWhiteList(INTERNET, tokenIdList));
    ASSERT_EQ(1u, tokenIdList.size());
    EXPECT_EQ(tokenId, tokenIdList[0]);

    EXPECT_EQ(RET_SUCCESS, AccessTokenKit::ClearUserPolicy({ INTERNET }));
    EXPECT_EQ(RET_SUCCESS, TestCommon::DeleteTestHapToken(tokenId));
}

/**
 * @tc.name: PolicyWhiteListTest003
 * @tc.desc: UpdatePolicyWhiteList returns error when adding duplicated token or deleting absent token.
 * @tc.type: FUNC
 * @tc.require:Issue Number
 */
HWTEST_F(UserPolicyTest, PolicyWhiteListTest003, TestSize.Level1)
{
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

    EXPECT_EQ(RET_SUCCESS, AccessTokenKit::UpdatePolicyWhiteList(tokenId, INTERNET, ADD));
    EXPECT_EQ(ERR_TOKENID_ALREADY_IN_POLICY_WHITELIST,
        AccessTokenKit::UpdatePolicyWhiteList(tokenId, INTERNET, ADD));

    EXPECT_EQ(RET_SUCCESS, AccessTokenKit::UpdatePolicyWhiteList(tokenId, INTERNET, DELETE));
    EXPECT_EQ(ERR_TOKENID_NOT_IN_POLICY_WHITELIST,
        AccessTokenKit::UpdatePolicyWhiteList(tokenId, INTERNET, DELETE));

    EXPECT_EQ(RET_SUCCESS, AccessTokenKit::ClearUserPolicy({ INTERNET }));
    EXPECT_EQ(RET_SUCCESS, TestCommon::DeleteTestHapToken(tokenId));
}

/**
 * @tc.name: PolicyWhiteListTest004
 * @tc.desc: UpdatePolicyWhiteList/GetPolicyWhiteList with multiple tokens.
 * @tc.type: FUNC
 * @tc.require:Issue Number
 */
HWTEST_F(UserPolicyTest, PolicyWhiteListTest004, TestSize.Level1)
{
    UserPermissionPolicy policy = {
        .permissionName = INTERNET,
        .userPolicyList = {{ .userId = MOCK_USER_ID_10001, .isRestricted = true }}
    };
    EXPECT_EQ(RET_SUCCESS, AccessTokenKit::SetUserPolicy({ policy }));

    HapInfoParams testHapInfo = g_testHapInfoParams;
    testHapInfo.userID = MOCK_USER_ID_10001;
    AccessTokenIDEx fullIdUser1;
    AccessTokenIDEx fullIdUser2;
    EXPECT_EQ(RET_SUCCESS, TestCommon::AllocTestHapToken(testHapInfo, g_testPolicyParams, fullIdUser1));
    testHapInfo.instIndex = 1;
    EXPECT_EQ(RET_SUCCESS, TestCommon::AllocTestHapToken(testHapInfo, g_testPolicyParams, fullIdUser2));
    AccessTokenID tokenId1 = fullIdUser1.tokenIdExStruct.tokenID;
    AccessTokenID tokenId2 = fullIdUser2.tokenIdExStruct.tokenID;

    EXPECT_EQ(RET_SUCCESS, AccessTokenKit::UpdatePolicyWhiteList(tokenId1, INTERNET, ADD));
    EXPECT_EQ(RET_SUCCESS, AccessTokenKit::UpdatePolicyWhiteList(tokenId2, INTERNET, ADD));

    std::vector<AccessTokenID> tokenIdList;
    EXPECT_EQ(RET_SUCCESS, AccessTokenKit::GetPolicyWhiteList(INTERNET, tokenIdList));
    EXPECT_EQ(2u, tokenIdList.size());
    EXPECT_NE(tokenIdList.end(), std::find(tokenIdList.begin(), tokenIdList.end(), tokenId1));
    EXPECT_NE(tokenIdList.end(), std::find(tokenIdList.begin(), tokenIdList.end(), tokenId2));

    EXPECT_EQ(RET_SUCCESS, AccessTokenKit::UpdatePolicyWhiteList(tokenId1, INTERNET, DELETE));
    EXPECT_EQ(RET_SUCCESS, AccessTokenKit::GetPolicyWhiteList(INTERNET, tokenIdList));
    ASSERT_EQ(1u, tokenIdList.size());
    EXPECT_EQ(tokenId2, tokenIdList[0]);

    EXPECT_EQ(RET_SUCCESS, AccessTokenKit::ClearUserPolicy({ INTERNET }));
    testHapInfo.instIndex = 0;
    EXPECT_EQ(RET_SUCCESS, TestCommon::DeleteTestHapToken(tokenId1));
    testHapInfo.instIndex = 1;
    EXPECT_EQ(RET_SUCCESS, TestCommon::DeleteTestHapToken(tokenId2));
}

/**
 * @tc.name: PolicyWhiteListTest005
 * @tc.desc: White list only works for target token and is cleared with user policy.
 * @tc.type: FUNC
 * @tc.require:Issue Number
 */
HWTEST_F(UserPolicyTest, PolicyWhiteListTest005, TestSize.Level1)
{
    UserPermissionPolicy policy = {
        .permissionName = INTERNET,
        .userPolicyList = {{ .userId = MOCK_USER_ID_10001, .isRestricted = true }}
    };
    EXPECT_EQ(RET_SUCCESS, AccessTokenKit::SetUserPolicy({ policy }));

    HapInfoParams testHapInfo = g_testHapInfoParams;
    testHapInfo.userID = MOCK_USER_ID_10001;
    AccessTokenIDEx fullIdUser1;
    AccessTokenIDEx fullIdUser2;
    EXPECT_EQ(RET_SUCCESS, TestCommon::AllocTestHapToken(testHapInfo, g_testPolicyParams, fullIdUser1));
    testHapInfo.instIndex = 1;
    EXPECT_EQ(RET_SUCCESS, TestCommon::AllocTestHapToken(testHapInfo, g_testPolicyParams, fullIdUser2));
    AccessTokenID tokenId1 = fullIdUser1.tokenIdExStruct.tokenID;
    AccessTokenID tokenId2 = fullIdUser2.tokenIdExStruct.tokenID;

    ExpectPermissionQueryState(tokenId1, INTERNET, PERMISSION_DENIED, PERMISSION_DENIED,
        PERMISSION_RESTRICTED_BY_ADMIN);
    ExpectPermissionQueryState(tokenId2, INTERNET, PERMISSION_DENIED, PERMISSION_DENIED,
        PERMISSION_RESTRICTED_BY_ADMIN);

    EXPECT_EQ(RET_SUCCESS, AccessTokenKit::UpdatePolicyWhiteList(tokenId1, INTERNET, ADD));
    ExpectPermissionQueryState(tokenId1, INTERNET, PERMISSION_GRANTED, PERMISSION_GRANTED, 0u);
    ExpectPermissionQueryState(tokenId2, INTERNET, PERMISSION_DENIED, PERMISSION_DENIED,
        PERMISSION_RESTRICTED_BY_ADMIN);

    EXPECT_EQ(RET_SUCCESS, AccessTokenKit::ClearUserPolicy({ INTERNET }));

    std::vector<AccessTokenID> tokenIdList = {tokenId1, tokenId2};
    EXPECT_EQ(RET_SUCCESS, AccessTokenKit::GetPolicyWhiteList(INTERNET, tokenIdList));
    EXPECT_TRUE(tokenIdList.empty());
    ExpectPermissionQueryState(tokenId1, INTERNET, PERMISSION_GRANTED, PERMISSION_GRANTED, 0u);
    ExpectPermissionQueryState(tokenId2, INTERNET, PERMISSION_GRANTED, PERMISSION_GRANTED, 0u);

    testHapInfo.instIndex = 0;
    EXPECT_EQ(RET_SUCCESS, TestCommon::DeleteTestHapToken(tokenId1));
    testHapInfo.instIndex = 1;
    EXPECT_EQ(RET_SUCCESS, TestCommon::DeleteTestHapToken(tokenId2));
}

/**
 * @tc.name: PolicyWhiteListTest006
 * @tc.desc: UpdatePolicyWhiteList returns error when token user is outside controlled userIds.
 * @tc.type: FUNC
 * @tc.require:Issue Number
 */
HWTEST_F(UserPolicyTest, PolicyWhiteListTest006, TestSize.Level1)
{
    UserPermissionPolicy policy = {
        .permissionName = INTERNET,
        .userPolicyList = {{ .userId = MOCK_USER_ID_10001, .isRestricted = true }}
    };
    EXPECT_EQ(RET_SUCCESS, AccessTokenKit::SetUserPolicy({ policy }));

    HapInfoParams testHapInfo = g_testHapInfoParams;
    testHapInfo.userID = MOCK_USER_ID_10002;
    AccessTokenIDEx fullIdUser2;
    EXPECT_EQ(RET_SUCCESS, TestCommon::AllocTestHapToken(testHapInfo, g_testPolicyParams, fullIdUser2));
    AccessTokenID tokenId = fullIdUser2.tokenIdExStruct.tokenID;

    EXPECT_EQ(ERR_TOKENID_NOT_IN_POLICY_USERLIST, AccessTokenKit::UpdatePolicyWhiteList(tokenId, INTERNET, ADD));
    EXPECT_EQ(ERR_TOKENID_NOT_IN_POLICY_USERLIST, AccessTokenKit::UpdatePolicyWhiteList(tokenId, INTERNET, DELETE));

    std::vector<AccessTokenID> tokenIdList;
    EXPECT_EQ(RET_SUCCESS, AccessTokenKit::GetPolicyWhiteList(INTERNET, tokenIdList));
    EXPECT_TRUE(tokenIdList.empty());

    EXPECT_EQ(RET_SUCCESS, AccessTokenKit::ClearUserPolicy({ INTERNET }));
    EXPECT_EQ(RET_SUCCESS, TestCommon::DeleteTestHapToken(tokenId));
}

/**
 * @tc.name: PolicyWhiteListTest007
 * @tc.desc: GetPolicyWhiteList clears output list when parameter is invalid.
 * @tc.type: FUNC
 * @tc.require:Issue Number
 */
HWTEST_F(UserPolicyTest, PolicyWhiteListTest007, TestSize.Level1)
{
    std::vector<AccessTokenID> tokenIdList = {INVALID_TOKENID};

    EXPECT_EQ(ERR_PARAM_INVALID, AccessTokenKit::GetPolicyWhiteList("", tokenIdList));
    EXPECT_TRUE(tokenIdList.empty());

    tokenIdList = {INVALID_TOKENID};
    std::string invalidPermName(MAX_LENGTH + 1, 'A');
    EXPECT_EQ(ERR_PARAM_INVALID, AccessTokenKit::GetPolicyWhiteList(invalidPermName, tokenIdList));
    EXPECT_TRUE(tokenIdList.empty());
}

/**
 * @tc.name: PolicyWhiteListTest008
 * @tc.desc: GetPolicyWhiteList returns empty list when whitelist does not exist.
 * @tc.type: FUNC
 * @tc.require:Issue Number
 */
HWTEST_F(UserPolicyTest, PolicyWhiteListTest008, TestSize.Level1)
{
    std::vector<AccessTokenID> tokenIdList;

    EXPECT_EQ(RET_SUCCESS, AccessTokenKit::GetPolicyWhiteList(INTERNET, tokenIdList));
    EXPECT_TRUE(tokenIdList.empty());
}

/**
 * @tc.name: PolicyWhiteListTest009
 * @tc.desc: UpdatePolicyWhiteList returns error when tokenId is not hap.
 * @tc.type: FUNC
 * @tc.require:Issue Number
 */
HWTEST_F(UserPolicyTest, PolicyWhiteListTest009, TestSize.Level1)
{
    AccessTokenID nativeTokenId = AccessTokenKit::GetNativeTokenId("foundation");
    EXPECT_EQ(ERR_PARAM_INVALID, AccessTokenKit::UpdatePolicyWhiteList(nativeTokenId, INTERNET, ADD));
}

/**
 * @tc.name: PolicyWhiteListTest010
 * @tc.desc: GetPolicyWhiteList clears prefilled output list before valid query.
 * @tc.type: FUNC
 * @tc.require:Issue Number
 */
HWTEST_F(UserPolicyTest, PolicyWhiteListTest010, TestSize.Level1)
{
    std::vector<AccessTokenID> tokenIdList = {INVALID_TOKENID};

    EXPECT_EQ(RET_SUCCESS, AccessTokenKit::GetPolicyWhiteList(INTERNET, tokenIdList));
    EXPECT_TRUE(tokenIdList.empty());
}

/**
 * @tc.name: PolicyWhiteListTest011
 * @tc.desc: UpdatePolicyWhiteList returns invalid when permission does not exist.
 * @tc.type: FUNC
 * @tc.require:Issue Number
 */
HWTEST_F(UserPolicyTest, PolicyWhiteListTest011, TestSize.Level1)
{
    HapInfoParams testHapInfo = g_testHapInfoParams;
    testHapInfo.userID = MOCK_USER_ID_10001;
    AccessTokenIDEx fullIdUser1;
    EXPECT_EQ(RET_SUCCESS, TestCommon::AllocTestHapToken(testHapInfo, g_testPolicyParams, fullIdUser1));
    AccessTokenID tokenId = fullIdUser1.tokenIdExStruct.tokenID;

    EXPECT_EQ(ERR_PARAM_INVALID,
        AccessTokenKit::UpdatePolicyWhiteList(tokenId, "ohos.permission.TEST_123", ADD));

    EXPECT_EQ(RET_SUCCESS, TestCommon::DeleteTestHapToken(tokenId));
}

/**
 * @tc.name: PolicyWhiteListTest012
 * @tc.desc: QueryStatusByPermission and QueryStatusByTokenID reflect whitelist final state.
 * @tc.type: FUNC
 * @tc.require:Issue Number
 */
HWTEST_F(UserPolicyTest, PolicyWhiteListTest012, TestSize.Level1)
{
    UserPermissionPolicy policy = {
        .permissionName = INTERNET, .userPolicyList = {{ .userId = MOCK_USER_ID_10001, .isRestricted = true }}
    };
    EXPECT_EQ(RET_SUCCESS, AccessTokenKit::SetUserPolicy({ policy }));

    HapInfoParams testHapInfo = g_testHapInfoParams;
    testHapInfo.userID = MOCK_USER_ID_10001;
    AccessTokenIDEx fullIdUser1;
    EXPECT_EQ(RET_SUCCESS, TestCommon::AllocTestHapToken(testHapInfo, g_testPolicyParams, fullIdUser1));
    AccessTokenID tokenId = fullIdUser1.tokenIdExStruct.tokenID;

    EXPECT_EQ(RET_SUCCESS, AccessTokenKit::UpdatePolicyWhiteList(tokenId, INTERNET, ADD));
    {
        MockToken mock(g_selfShellTokenId, "com.ohos.permissionmanager", true);
        mock.Grant(GET_SENSITIVE_PERMISSIONS);
        std::vector<PermissionStatus> permissionInfoList1;
        EXPECT_EQ(RET_SUCCESS, AccessTokenKit::QueryStatusByPermission({INTERNET}, permissionInfoList1));
        for (const auto& info : permissionInfoList1) {
            if (info.tokenID == tokenId) {
                EXPECT_EQ(PERMISSION_GRANTED, info.grantStatus);
            }
        }

        std::vector<PermissionStatus> permissionInfoList2;
        EXPECT_EQ(RET_SUCCESS, AccessTokenKit::QueryStatusByTokenID({tokenId}, permissionInfoList2));
        for (const auto& info : permissionInfoList2) {
            if (info.permissionName == INTERNET) {
                EXPECT_EQ(PERMISSION_GRANTED, info.grantStatus);
            }
        }
    }

    EXPECT_EQ(RET_SUCCESS, AccessTokenKit::UpdatePolicyWhiteList(tokenId, INTERNET, DELETE));
    {
        MockToken mock(g_selfShellTokenId, "com.ohos.permissionmanager", true);
        mock.Grant(GET_SENSITIVE_PERMISSIONS);
        std::vector<PermissionStatus> permissionInfoList1;
        EXPECT_EQ(RET_SUCCESS, AccessTokenKit::QueryStatusByPermission({INTERNET}, permissionInfoList1));
        for (const auto& info : permissionInfoList1) {
            if (info.tokenID == tokenId) {
                EXPECT_EQ(PERMISSION_DENIED, info.grantStatus);
            }
        }

        std::vector<PermissionStatus> permissionInfoList2;
        EXPECT_EQ(RET_SUCCESS, AccessTokenKit::QueryStatusByTokenID({tokenId}, permissionInfoList2));
        for (const auto& info : permissionInfoList2) {
            if (info.permissionName == INTERNET) {
                EXPECT_EQ(PERMISSION_DENIED, info.grantStatus);
            }
        }
    }

    EXPECT_EQ(RET_SUCCESS, AccessTokenKit::ClearUserPolicy({ INTERNET }));
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
 * @tc.name: PolicyWhiteListTest013
 * @tc.desc: UpdatePolicyWhiteList triggers permission state change callback on add and delete.
 * @tc.type: FUNC
 * @tc.require:Issue Number
 */
HWTEST_F(UserPolicyTest, PolicyWhiteListTest013, TestSize.Level1)
{
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
    ExpectPermissionQueryState(tokenId, INTERNET, PERMISSION_DENIED, PERMISSION_DENIED,
        PERMISSION_RESTRICTED_BY_ADMIN);

    PermStateChangeScope scopeInfo;
    scopeInfo.permList = { INTERNET };
    scopeInfo.tokenIDs = { tokenId };
    auto callbackPtr = std::make_shared<CbCustomizeTestForEdm>(scopeInfo);
    ASSERT_EQ(RET_SUCCESS, AccessTokenKit::RegisterPermStateChangeCallback(callbackPtr));

    EXPECT_EQ(RET_SUCCESS, AccessTokenKit::UpdatePolicyWhiteList(tokenId, INTERNET, ADD));
    usleep(500000); // 500000us = 0.5s
    EXPECT_TRUE(callbackPtr->ready_);
    EXPECT_EQ(1u, callbackPtr->changeCnt_);

    callbackPtr->ready_ = false;
    EXPECT_EQ(RET_SUCCESS, AccessTokenKit::UpdatePolicyWhiteList(tokenId, INTERNET, DELETE));
    usleep(500000); // 500000us = 0.5s
    EXPECT_TRUE(callbackPtr->ready_);
    EXPECT_EQ(2u, callbackPtr->changeCnt_);

    EXPECT_EQ(RET_SUCCESS, AccessTokenKit::UnRegisterPermStateChangeCallback(callbackPtr));
    EXPECT_EQ(RET_SUCCESS, AccessTokenKit::ClearUserPolicy({ INTERNET }));
    EXPECT_EQ(RET_SUCCESS, TestCommon::DeleteTestHapToken(tokenId));
}

/**
 * @tc.name: UserPolicyTestForInitHap
 * @tc.desc: Set the authorization status based on the user policy during new hap installation
 * @tc.type: FUNC
 * @tc.require:Issue Number
 */
HWTEST_F(UserPolicyTest, UserPolicyTestForInitHap, TestSize.Level1)
{
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

    ExpectPermissionQueryState(tokenId1, INTERNET, PERMISSION_DENIED, PERMISSION_DENIED,
        PERMISSION_RESTRICTED_BY_ADMIN);
    ExpectPermissionQueryState(tokenId1, GET_NETWORK_STATS, PERMISSION_GRANTED, PERMISSION_GRANTED, 0u);
    ExpectPermissionQueryState(tokenId2, INTERNET, PERMISSION_GRANTED, PERMISSION_GRANTED, 0u);
    ExpectPermissionQueryState(tokenId2, GET_NETWORK_STATS, PERMISSION_DENIED, PERMISSION_DENIED,
        PERMISSION_RESTRICTED_BY_ADMIN);

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
HWTEST_F(UserPolicyTest, UserPolicyTestForUpdateHap, TestSize.Level1)
{
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
    ExpectPermissionQueryState(tokenId, INTERNET, PERMISSION_GRANTED, PERMISSION_GRANTED, 0u);

    // set policy
    UserPermissionPolicy policy = {
        .permissionName = INTERNET,
        .userPolicyList = {{ .userId = MOCK_USER_ID_10001, .isRestricted = true }}
    };
    EXPECT_EQ(RET_SUCCESS, AccessTokenKit::SetUserPolicy({ policy }));
    ExpectPermissionQueryState(tokenId, INTERNET, PERMISSION_DENIED, PERMISSION_DENIED,
        PERMISSION_RESTRICTED_BY_ADMIN);

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
        MockToken mock(g_selfShellTokenId, "accesstoken_service", false);
        mock.Grant("ohos.permission.MANAGE_HAP_TOKENID");
        EXPECT_EQ(RET_SUCCESS, AccessTokenKit::UpdateHapToken(fullIdUser1, info, testPolicyParams2));
    }
    ExpectPermissionQueryState(tokenId, INTERNET, PERMISSION_DENIED, PERMISSION_DENIED,
        PERMISSION_RESTRICTED_BY_ADMIN);
    ExpectPermissionQueryState(tokenId, GET_NETWORK_STATS, PERMISSION_GRANTED, PERMISSION_GRANTED, 0u);

    EXPECT_EQ(RET_SUCCESS, AccessTokenKit::ClearUserPolicy({ INTERNET }));
    ExpectPermissionQueryState(tokenId, INTERNET, PERMISSION_GRANTED, PERMISSION_GRANTED, 0u);
    ExpectPermissionQueryState(tokenId, GET_NETWORK_STATS, PERMISSION_GRANTED, PERMISSION_GRANTED, 0u);

    EXPECT_EQ(RET_SUCCESS, TestCommon::DeleteTestHapToken(tokenId));
}

/**
 * @tc.name: UserPolicyTestForRemove
 * @tc.desc: UpdateHapToken and check permission status with user policy.
 * @tc.type: FUNC
 * @tc.require:Issue Number
 */
HWTEST_F(UserPolicyTest, UserPolicyTestForRemove, TestSize.Level1)
{
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
    ExpectPermissionQueryState(tokenId, INTERNET, PERMISSION_DENIED, PERMISSION_DENIED,
        PERMISSION_RESTRICTED_BY_ADMIN);
    ExpectPermissionQueryState(tokenId, GET_NETWORK_STATS, PERMISSION_GRANTED, PERMISSION_GRANTED, 0u);

    PermStateChangeScope scopeInfo;
    scopeInfo.permList = { INTERNET, GET_NETWORK_STATS };
    scopeInfo.tokenIDs = { tokenId };
    auto callbackPtr = std::make_shared<CbCustomizeTestForEdm>(scopeInfo);
    callbackPtr->ready_ = false;
    ASSERT_EQ(RET_SUCCESS, AccessTokenKit::RegisterPermStateChangeCallback(callbackPtr));

    ExpectPermissionQueryState(tokenId, INTERNET, PERMISSION_DENIED, PERMISSION_DENIED,
        PERMISSION_RESTRICTED_BY_ADMIN);
    ExpectPermissionQueryState(tokenId, GET_NETWORK_STATS, PERMISSION_GRANTED, PERMISSION_GRANTED, 0u);

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
HWTEST_F(UserPolicyTest, UserPolicyTestForClearUserGranted, TestSize.Level1)
{
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

    ExpectPermissionQueryState(tokenId1, INTERNET, PERMISSION_DENIED, PERMISSION_DENIED,
        PERMISSION_RESTRICTED_BY_ADMIN);
    ExpectPermissionQueryState(tokenId2, INTERNET, PERMISSION_DENIED, PERMISSION_DENIED,
        PERMISSION_RESTRICTED_BY_ADMIN);

    EXPECT_EQ(RET_SUCCESS, TestCommon::ClearUserGrantedPermissionStateByTest(tokenId1));
    EXPECT_EQ(RET_SUCCESS, TestCommon::ClearUserGrantedPermissionStateByTest(tokenId2));

    ExpectPermissionQueryState(tokenId1, INTERNET, PERMISSION_DENIED, PERMISSION_DENIED,
        PERMISSION_RESTRICTED_BY_ADMIN);
    ExpectPermissionQueryState(tokenId2, INTERNET, PERMISSION_DENIED, PERMISSION_DENIED,
        PERMISSION_RESTRICTED_BY_ADMIN);

    EXPECT_EQ(RET_SUCCESS, AccessTokenKit::ClearUserPolicy({ INTERNET }));
    ExpectPermissionQueryState(tokenId1, INTERNET, PERMISSION_GRANTED, PERMISSION_GRANTED, 0u);
    ExpectPermissionQueryState(tokenId2, INTERNET, PERMISSION_GRANTED, PERMISSION_GRANTED, 0u);

    EXPECT_EQ(RET_SUCCESS, TestCommon::DeleteTestHapToken(tokenId1));
    EXPECT_EQ(RET_SUCCESS, TestCommon::DeleteTestHapToken(tokenId2));
}

/**
 * @tc.name: PolicyWhiteListRestrictedFlag001
 * @tc.desc: Policy whitelist add/delete clears and restores the restricted flag for the target HAP token.
 * @tc.type: FUNC
 * @tc.require:Issue Number
 */
HWTEST_F(UserPolicyTest, PolicyWhiteListRestrictedFlag001, TestSize.Level1)
{
    HapInfoParams testHapInfo = g_testHapInfoParams;
    AccessTokenIDEx fullId;
    ASSERT_EQ(RET_SUCCESS, TestCommon::AllocTestHapToken(testHapInfo, g_testPolicyParams, fullId));
    AccessTokenID tokenId = fullId.tokenIdExStruct.tokenID;

    UserPermissionPolicy policy = {
        .permissionName = INTERNET,
        .userPolicyList = {{ .userId = testHapInfo.userID, .isRestricted = true }}
    };
    EXPECT_EQ(RET_SUCCESS, AccessTokenKit::SetUserPolicy({ policy }));

    ExpectPermissionQueryState(tokenId, INTERNET, PERMISSION_DENIED, PERMISSION_DENIED, PERMISSION_RESTRICTED_BY_ADMIN);

    EXPECT_EQ(RET_SUCCESS, AccessTokenKit::UpdatePolicyWhiteList(tokenId, INTERNET, ADD));
    ExpectPermissionQueryState(tokenId, INTERNET, PERMISSION_GRANTED, PERMISSION_GRANTED, 0u);
    {
        MockToken mock(g_selfShellTokenId, "com.ohos.permissionmanager", true);
        mock.Grant(GET_SENSITIVE_PERMISSIONS);
        std::vector<PermissionStatus> permissionInfoList;
        EXPECT_EQ(RET_SUCCESS, AccessTokenKit::QueryStatusByTokenID({ tokenId }, permissionInfoList));
        PermissionStatus permissionStatus;
        bool found = FindPermissionStatus(permissionInfoList, tokenId, INTERNET, permissionStatus);
        EXPECT_TRUE(found);
        if (found) {
            EXPECT_EQ(PERMISSION_GRANTED, permissionStatus.grantStatus);
            EXPECT_EQ(0u, permissionStatus.grantFlag & PERMISSION_RESTRICTED_BY_ADMIN);
        }
    }

    EXPECT_EQ(RET_SUCCESS, AccessTokenKit::UpdatePolicyWhiteList(tokenId, INTERNET, DELETE));
    ExpectPermissionQueryState(tokenId, INTERNET, PERMISSION_DENIED, PERMISSION_DENIED,
        PERMISSION_RESTRICTED_BY_ADMIN);

    EXPECT_EQ(RET_SUCCESS, AccessTokenKit::ClearUserPolicy({ INTERNET }));
    EXPECT_EQ(RET_SUCCESS, TestCommon::DeleteTestHapToken(tokenId));
}

/**
 * @tc.name: UserPolicyScope001
 * @tc.desc: User policy only affects tokens in the controlled user scope.
 * @tc.type: FUNC
 * @tc.require:Issue Number
 */
HWTEST_F(UserPolicyTest, UserPolicyScope001, TestSize.Level1)
{
    HapInfoParams testHapInfo = g_testHapInfoParams;
    testHapInfo.userID = MOCK_USER_ID_10001;
    AccessTokenIDEx fullId1;
    EXPECT_EQ(RET_SUCCESS, TestCommon::AllocTestHapToken(testHapInfo, g_testPolicyParams, fullId1));
    AccessTokenID tokenId1 = fullId1.tokenIdExStruct.tokenID;

    testHapInfo.userID = MOCK_USER_ID_10002;
    AccessTokenIDEx fullId2;
    EXPECT_EQ(RET_SUCCESS, TestCommon::AllocTestHapToken(testHapInfo, g_testPolicyParams, fullId2));
    AccessTokenID tokenId2 = fullId2.tokenIdExStruct.tokenID;

    UserPermissionPolicy policy = {
        .permissionName = INTERNET,
        .userPolicyList = {{ .userId = MOCK_USER_ID_10001, .isRestricted = true }}
    };
    EXPECT_EQ(RET_SUCCESS, AccessTokenKit::SetUserPolicy({ policy }));
    ExpectPermissionQueryState(tokenId1, INTERNET, PERMISSION_DENIED, PERMISSION_DENIED,
        PERMISSION_RESTRICTED_BY_ADMIN);
    ExpectPermissionQueryState(tokenId2, INTERNET, PERMISSION_GRANTED, PERMISSION_GRANTED, 0u);

    EXPECT_EQ(RET_SUCCESS, AccessTokenKit::ClearUserPolicy({ INTERNET }));
    EXPECT_EQ(RET_SUCCESS, TestCommon::DeleteTestHapToken(tokenId1));
    EXPECT_EQ(RET_SUCCESS, TestCommon::DeleteTestHapToken(tokenId2));
}

/**
 * @tc.name: ClearUserPolicyRefreshState001
 * @tc.desc: ClearUserPolicy refreshes effective grant state and restricted flag.
 * @tc.type: FUNC
 * @tc.require:Issue Number
 */
HWTEST_F(UserPolicyTest, ClearUserPolicyRefreshState001, TestSize.Level1)
{
    HapInfoParams testHapInfo = g_testHapInfoParams;
    testHapInfo.userID = MOCK_USER_ID_10001;
    AccessTokenIDEx fullId;
    EXPECT_EQ(RET_SUCCESS, TestCommon::AllocTestHapToken(testHapInfo, g_testPolicyParams, fullId));
    AccessTokenID tokenId = fullId.tokenIdExStruct.tokenID;

    UserPermissionPolicy policy = {
        .permissionName = INTERNET,
        .userPolicyList = {{ .userId = MOCK_USER_ID_10001, .isRestricted = true }}
    };
    EXPECT_EQ(RET_SUCCESS, AccessTokenKit::SetUserPolicy({ policy }));
    ExpectPermissionQueryState(tokenId, INTERNET, PERMISSION_DENIED, PERMISSION_DENIED,
        PERMISSION_RESTRICTED_BY_ADMIN);
    EXPECT_EQ(RET_SUCCESS, AccessTokenKit::ClearUserPolicy({ INTERNET }));
    ExpectPermissionQueryState(tokenId, INTERNET, PERMISSION_GRANTED, PERMISSION_GRANTED, 0u);

    EXPECT_EQ(RET_SUCCESS, TestCommon::DeleteTestHapToken(tokenId));
}

/**
 * @tc.name: UpdateWhiteListParamFlag001
 * @tc.desc: UpdatePolicyWhiteList refreshes effective permission flag for add and delete.
 * @tc.type: FUNC
 * @tc.require:Issue Number
 */
HWTEST_F(UserPolicyTest, UpdateWhiteListParamFlag001, TestSize.Level1)
{
    HapInfoParams testHapInfo = g_testHapInfoParams;
    testHapInfo.userID = MOCK_USER_ID_10001;
    AccessTokenIDEx fullId;
    EXPECT_EQ(RET_SUCCESS, TestCommon::AllocTestHapToken(testHapInfo, g_testPolicyParams, fullId));
    AccessTokenID tokenId = fullId.tokenIdExStruct.tokenID;

    UserPermissionPolicy policy = {
        .permissionName = INTERNET,
        .userPolicyList = {{ .userId = MOCK_USER_ID_10001, .isRestricted = true }}
    };
    EXPECT_EQ(RET_SUCCESS, AccessTokenKit::SetUserPolicy({ policy }));
    ExpectPermissionQueryState(tokenId, INTERNET, PERMISSION_DENIED, PERMISSION_DENIED,
        PERMISSION_RESTRICTED_BY_ADMIN);

    EXPECT_EQ(RET_SUCCESS, AccessTokenKit::UpdatePolicyWhiteList(tokenId, INTERNET, ADD));
    ExpectPermissionQueryState(tokenId, INTERNET, PERMISSION_GRANTED, PERMISSION_GRANTED, 0u);

    EXPECT_EQ(RET_SUCCESS, AccessTokenKit::UpdatePolicyWhiteList(tokenId, INTERNET, DELETE));
    ExpectPermissionQueryState(tokenId, INTERNET, PERMISSION_DENIED, PERMISSION_DENIED,
        PERMISSION_RESTRICTED_BY_ADMIN);

    EXPECT_EQ(RET_SUCCESS, AccessTokenKit::ClearUserPolicy({ INTERNET }));
    EXPECT_EQ(RET_SUCCESS, TestCommon::DeleteTestHapToken(tokenId));
}

/**
 * @tc.name: UpdateWhiteListAddFlagRollback001
 * @tc.desc: Failed duplicate ADD keeps whitelist and restricted flag unchanged.
 * @tc.type: FUNC
 * @tc.require:Issue Number
 */
HWTEST_F(UserPolicyTest, UpdateWhiteListAddFlagRollback001, TestSize.Level1)
{
    HapInfoParams testHapInfo = g_testHapInfoParams;
    testHapInfo.userID = MOCK_USER_ID_10001;
    AccessTokenIDEx fullId;
    EXPECT_EQ(RET_SUCCESS, TestCommon::AllocTestHapToken(testHapInfo, g_testPolicyParams, fullId));
    AccessTokenID tokenId = fullId.tokenIdExStruct.tokenID;

    UserPermissionPolicy policy = {
        .permissionName = INTERNET,
        .userPolicyList = {{ .userId = MOCK_USER_ID_10001, .isRestricted = true }}
    };
    EXPECT_EQ(RET_SUCCESS, AccessTokenKit::SetUserPolicy({ policy }));
    EXPECT_EQ(RET_SUCCESS, AccessTokenKit::UpdatePolicyWhiteList(tokenId, INTERNET, ADD));
    EXPECT_EQ(ERR_TOKENID_ALREADY_IN_POLICY_WHITELIST,
        AccessTokenKit::UpdatePolicyWhiteList(tokenId, INTERNET, ADD));

    ExpectPermissionQueryState(tokenId, INTERNET, PERMISSION_GRANTED, PERMISSION_GRANTED, 0u);
    std::vector<AccessTokenID> tokenIdList;
    EXPECT_EQ(RET_SUCCESS, AccessTokenKit::GetPolicyWhiteList(INTERNET, tokenIdList));
    ASSERT_EQ(1u, tokenIdList.size());
    EXPECT_EQ(tokenId, tokenIdList[0]);

    EXPECT_EQ(RET_SUCCESS, AccessTokenKit::ClearUserPolicy({ INTERNET }));
    EXPECT_EQ(RET_SUCCESS, TestCommon::DeleteTestHapToken(tokenId));
}

/**
 * @tc.name: UpdateWhiteListDeleteFlagRollback001
 * @tc.desc: Failed duplicate DELETE keeps whitelist and restricted flag unchanged.
 * @tc.type: FUNC
 * @tc.require:Issue Number
 */
HWTEST_F(UserPolicyTest, UpdateWhiteListDeleteFlagRollback001, TestSize.Level1)
{
    HapInfoParams testHapInfo = g_testHapInfoParams;
    testHapInfo.userID = MOCK_USER_ID_10001;
    AccessTokenIDEx fullId;
    EXPECT_EQ(RET_SUCCESS, TestCommon::AllocTestHapToken(testHapInfo, g_testPolicyParams, fullId));
    AccessTokenID tokenId = fullId.tokenIdExStruct.tokenID;

    UserPermissionPolicy policy = {
        .permissionName = INTERNET,
        .userPolicyList = {{ .userId = MOCK_USER_ID_10001, .isRestricted = true }}
    };
    EXPECT_EQ(RET_SUCCESS, AccessTokenKit::SetUserPolicy({ policy }));
    EXPECT_EQ(RET_SUCCESS, AccessTokenKit::UpdatePolicyWhiteList(tokenId, INTERNET, ADD));
    EXPECT_EQ(RET_SUCCESS, AccessTokenKit::UpdatePolicyWhiteList(tokenId, INTERNET, DELETE));
    EXPECT_EQ(ERR_TOKENID_NOT_IN_POLICY_WHITELIST,
        AccessTokenKit::UpdatePolicyWhiteList(tokenId, INTERNET, DELETE));

    ExpectPermissionQueryState(tokenId, INTERNET, PERMISSION_DENIED, PERMISSION_DENIED,
        PERMISSION_RESTRICTED_BY_ADMIN);
    std::vector<AccessTokenID> tokenIdList = {tokenId};
    EXPECT_EQ(RET_SUCCESS, AccessTokenKit::GetPolicyWhiteList(INTERNET, tokenIdList));
    EXPECT_TRUE(tokenIdList.empty());

    EXPECT_EQ(RET_SUCCESS, AccessTokenKit::ClearUserPolicy({ INTERNET }));
    EXPECT_EQ(RET_SUCCESS, TestCommon::DeleteTestHapToken(tokenId));
}

/**
 * @tc.name: WhiteListHostToolIsolation001
 * @tc.desc: White list update only affects the target token and does not leak to other tokens.
 * @tc.type: FUNC
 * @tc.require:Issue Number
 */
HWTEST_F(UserPolicyTest, WhiteListHostToolIsolation001, TestSize.Level1)
{
    HapInfoParams testHapInfo = g_testHapInfoParams;
    testHapInfo.userID = MOCK_USER_ID_10001;
    AccessTokenIDEx fullId1;
    EXPECT_EQ(RET_SUCCESS, TestCommon::AllocTestHapToken(testHapInfo, g_testPolicyParams, fullId1));
    AccessTokenID tokenId1 = fullId1.tokenIdExStruct.tokenID;

    testHapInfo.userID = MOCK_USER_ID_10002;
    AccessTokenIDEx fullId2;
    EXPECT_EQ(RET_SUCCESS, TestCommon::AllocTestHapToken(testHapInfo, g_testPolicyParams, fullId2));
    AccessTokenID tokenId2 = fullId2.tokenIdExStruct.tokenID;

    UserPermissionPolicy policy = {
        .permissionName = INTERNET,
        .userPolicyList = {
            { .userId = MOCK_USER_ID_10001, .isRestricted = true },
            { .userId = MOCK_USER_ID_10002, .isRestricted = true },
        }
    };
    EXPECT_EQ(RET_SUCCESS, AccessTokenKit::SetUserPolicy({ policy }));
    EXPECT_EQ(RET_SUCCESS, AccessTokenKit::UpdatePolicyWhiteList(tokenId1, INTERNET, ADD));
    ExpectPermissionQueryState(tokenId1, INTERNET, PERMISSION_GRANTED, PERMISSION_GRANTED, 0u);
    ExpectPermissionQueryState(tokenId2, INTERNET, PERMISSION_DENIED, PERMISSION_DENIED,
        PERMISSION_RESTRICTED_BY_ADMIN);

    EXPECT_EQ(RET_SUCCESS, AccessTokenKit::ClearUserPolicy({ INTERNET }));
    EXPECT_EQ(RET_SUCCESS, TestCommon::DeleteTestHapToken(tokenId1));
    EXPECT_EQ(RET_SUCCESS, TestCommon::DeleteTestHapToken(tokenId2));
}

/**
 * @tc.name: UserPolicyConcurrency001
 * @tc.desc: User policy can tolerate concurrent whitelist updates.
 * @tc.type: FUNC
 * @tc.require:Issue Number
 */
HWTEST_F(UserPolicyTest, UserPolicyConcurrency001, TestSize.Level1)
{
    HapInfoParams testHapInfo = g_testHapInfoParams;
    testHapInfo.userID = MOCK_USER_ID_10001;
    AccessTokenIDEx fullId;
    EXPECT_EQ(RET_SUCCESS, TestCommon::AllocTestHapToken(testHapInfo, g_testPolicyParams, fullId));
    AccessTokenID tokenId = fullId.tokenIdExStruct.tokenID;
    testHapInfo.instIndex = 1;
    AccessTokenIDEx fullId2;
    EXPECT_EQ(RET_SUCCESS, TestCommon::AllocTestHapToken(testHapInfo, g_testPolicyParams, fullId2));
    AccessTokenID tokenId2 = fullId2.tokenIdExStruct.tokenID;

    UserPermissionPolicy policy = {
        .permissionName = INTERNET,
        .userPolicyList = {{ .userId = MOCK_USER_ID_10001, .isRestricted = true }}
    };
    EXPECT_EQ(RET_SUCCESS, AccessTokenKit::SetUserPolicy({ policy }));

    std::atomic<bool> ok { true };
    auto worker = [&ok](AccessTokenID targetToken) {
        for (int i = 0; i < 8; ++i) {
            if (AccessTokenKit::UpdatePolicyWhiteList(targetToken, INTERNET, ADD) != RET_SUCCESS) {
                ok = false;
            }
            if (AccessTokenKit::UpdatePolicyWhiteList(targetToken, INTERNET, DELETE) != RET_SUCCESS) {
                ok = false;
            }
        }
    };

    std::thread t1(worker, tokenId);
    std::thread t2(worker, tokenId2);
    t1.join();
    t2.join();

    EXPECT_TRUE(ok);
    std::vector<AccessTokenID> tokenIdList;
    EXPECT_EQ(RET_SUCCESS, AccessTokenKit::GetPolicyWhiteList(INTERNET, tokenIdList));
    EXPECT_TRUE(tokenIdList.empty());

    EXPECT_EQ(RET_SUCCESS, AccessTokenKit::ClearUserPolicy({ INTERNET }));
    EXPECT_EQ(RET_SUCCESS, TestCommon::DeleteTestHapToken(tokenId));
    EXPECT_EQ(RET_SUCCESS, TestCommon::DeleteTestHapToken(tokenId2));
}
/**
 * @tc.name: UserPolicyPersistE2E001
 * @tc.desc: Persisted user policy end-to-end flow covers SetUserPolicy, GetPolicyWhiteList, VerifyAccessToken and
 * ClearUserPolicy.
 * @tc.type: FUNC
 * @tc.require:Issue Number
 */
HWTEST_F(UserPolicyTest, UserPolicyPersistE2E001, TestSize.Level1)
{
    HapInfoParams testHapInfo = g_testHapInfoParams;
    testHapInfo.userID = MOCK_USER_ID_10001;
    AccessTokenIDEx fullId;
    EXPECT_EQ(RET_SUCCESS, TestCommon::AllocTestHapToken(testHapInfo, g_testPolicyParams, fullId));
    AccessTokenID tokenId = fullId.tokenIdExStruct.tokenID;

    UserPermissionPolicy policy = {
        .permissionName = INTERNET,
        .userPolicyList = {{ .userId = MOCK_USER_ID_10001, .isRestricted = true }},
        .isPersist = true
    };
    EXPECT_EQ(RET_SUCCESS, AccessTokenKit::SetUserPolicy({ policy }));
    ExpectPermissionQueryState(tokenId, INTERNET, PERMISSION_DENIED, PERMISSION_DENIED,
        PERMISSION_RESTRICTED_BY_ADMIN);
    std::vector<AccessTokenID> tokenIdList;
    EXPECT_EQ(RET_SUCCESS, AccessTokenKit::GetPolicyWhiteList(INTERNET, tokenIdList));
    EXPECT_TRUE(tokenIdList.empty());
    ExpectPermissionQueryState(tokenId, INTERNET, PERMISSION_DENIED, PERMISSION_DENIED,
        PERMISSION_RESTRICTED_BY_ADMIN);

    EXPECT_EQ(RET_SUCCESS, AccessTokenKit::ClearUserPolicy({ INTERNET }));
    EXPECT_EQ(RET_SUCCESS, TestCommon::DeleteTestHapToken(tokenId));
}

/**
 * @tc.name: UserPolicyPersistE2E002
 * @tc.desc: Non-persisted user policy end-to-end flow covers SetUserPolicy, GetPolicyWhiteList, VerifyAccessToken and ClearUserPolicy.
 * @tc.type: FUNC
 * @tc.require:Issue Number
 */
HWTEST_F(UserPolicyTest, UserPolicyPersistE2E002, TestSize.Level1)
{
    HapInfoParams testHapInfo = g_testHapInfoParams;
    testHapInfo.userID = MOCK_USER_ID_10001;
    AccessTokenIDEx fullId;
    EXPECT_EQ(RET_SUCCESS, TestCommon::AllocTestHapToken(testHapInfo, g_testPolicyParams, fullId));
    AccessTokenID tokenId = fullId.tokenIdExStruct.tokenID;

    UserPermissionPolicy policy = {
        .permissionName = INTERNET,
        .userPolicyList = {{ .userId = MOCK_USER_ID_10001, .isRestricted = true }},
        .isPersist = false
    };
    EXPECT_EQ(RET_SUCCESS, AccessTokenKit::SetUserPolicy({ policy }));
    ExpectPermissionQueryState(tokenId, INTERNET, PERMISSION_DENIED, PERMISSION_DENIED,
        PERMISSION_RESTRICTED_BY_ADMIN);
    std::vector<AccessTokenID> tokenIdList;
    EXPECT_EQ(RET_SUCCESS, AccessTokenKit::GetPolicyWhiteList(INTERNET, tokenIdList));
    EXPECT_TRUE(tokenIdList.empty());
    ExpectPermissionQueryState(tokenId, INTERNET, PERMISSION_DENIED, PERMISSION_DENIED,
        PERMISSION_RESTRICTED_BY_ADMIN);

    EXPECT_EQ(RET_SUCCESS, AccessTokenKit::ClearUserPolicy({ INTERNET }));
    EXPECT_EQ(RET_SUCCESS, TestCommon::DeleteTestHapToken(tokenId));
}

/**
 * @tc.name: UserPolicyPersistE2E003
 * @tc.desc: Persisted user policy clear end-to-end flow covers SetUserPolicy, VerifyAccessToken and ClearUserPolicy.
 * @tc.type: FUNC
 * @tc.require:Issue Number
 */
HWTEST_F(UserPolicyTest, UserPolicyPersistE2E003, TestSize.Level1)
{
    HapInfoParams testHapInfo = g_testHapInfoParams;
    testHapInfo.userID = MOCK_USER_ID_10001;
    AccessTokenIDEx fullId;
    EXPECT_EQ(RET_SUCCESS, TestCommon::AllocTestHapToken(testHapInfo, g_testPolicyParams, fullId));
    AccessTokenID tokenId = fullId.tokenIdExStruct.tokenID;

    UserPermissionPolicy policy = {
        .permissionName = INTERNET,
        .userPolicyList = {{ .userId = MOCK_USER_ID_10001, .isRestricted = true }},
        .isPersist = true
    };
    EXPECT_EQ(RET_SUCCESS, AccessTokenKit::SetUserPolicy({ policy }));
    ExpectPermissionQueryState(tokenId, INTERNET, PERMISSION_DENIED, PERMISSION_DENIED,
        PERMISSION_RESTRICTED_BY_ADMIN);

    EXPECT_EQ(RET_SUCCESS, AccessTokenKit::ClearUserPolicy({ INTERNET }));
    ExpectPermissionQueryState(tokenId, INTERNET, PERMISSION_GRANTED, PERMISSION_GRANTED, 0u);

    EXPECT_EQ(RET_SUCCESS, TestCommon::DeleteTestHapToken(tokenId));
}

#else
/**
 * @tc.name: SetUserPolicyNotSupport001
 * @tc.desc: Not support to SetUserPolicy.
 * @tc.type: FUNC
 * @tc.require:Issue Number
 */
HWTEST_F(UserPolicyTest, SetUserPolicyNotSupport001, TestSize.Level0)
{
    std::vector<UserPermissionPolicy> permPolicyListEmpty;
    EXPECT_EQ(AccessTokenError::ERR_CAPABILITY_NOT_SUPPORT, AccessTokenKit::SetUserPolicy(permPolicyListEmpty));
    EXPECT_EQ(AccessTokenError::ERR_CAPABILITY_NOT_SUPPORT, AccessTokenKit::ClearUserPolicy({ INTERNET }));
}

/**
 * @tc.name: PolicyWhiteListNotSupport001
 * @tc.desc: Not support to UpdatePolicyWhiteList/GetPolicyWhiteList.
 * @tc.type: FUNC
 * @tc.require:Issue Number
 */
HWTEST_F(UserPolicyTest, PolicyWhiteListNotSupport001, TestSize.Level0)
{
    std::vector<AccessTokenID> tokenIdList;
    EXPECT_EQ(AccessTokenError::ERR_CAPABILITY_NOT_SUPPORT,
        AccessTokenKit::UpdatePolicyWhiteList(INVALID_TOKENID, INTERNET, ADD));
    EXPECT_EQ(AccessTokenError::ERR_CAPABILITY_NOT_SUPPORT,
        AccessTokenKit::GetPolicyWhiteList(INTERNET, tokenIdList));
}
#endif
} // namespace AccessToken
} // namespace Security
} // namespace OHOS
