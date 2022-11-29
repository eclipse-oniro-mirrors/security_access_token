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
#include "accesstoken_log.h"
#include "access_token_error.h"
#include "i_accesstoken_manager.h"
#include "native_token_info_for_sync_parcel.h"
#include "nativetoken_kit.h"
#include "permission_state_change_info_parcel.h"
#include "softbus_bus_center.h"
#include "string_ex.h"
#include "token_setproc.h"
#define private public
#include "accesstoken_manager_client.h"
#undef private

using namespace testing::ext;

namespace OHOS {
namespace Security {
namespace AccessToken {
namespace {
static const int MAX_PERMISSION_SIZE = 1000;
static const int INVALID_DLP_TOKEN_FLAG = -1;
static constexpr int32_t DEFAULT_API_VERSION = 8;
static constexpr int32_t VAGUE_LOCATION_API_VERSION = 9;
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
    .availableLevel = APL_NORMAL,
    .label = "label",
    .labelId = 1,
    .description = "open the door",
    .descriptionId = 1
};

PermissionDef g_infoManagerTestPermDef2 = {
    .permissionName = "ohos.permission.test2",
    .bundleName = "accesstoken_test",
    .grantMode = 1,
    .availableLevel = APL_NORMAL,
    .label = "label",
    .labelId = 1,
    .description = "break the door",
    .descriptionId = 1
};

PermissionStateFull g_infoManagerTestState1 = {
    .permissionName = "ohos.permission.test1",
    .isGeneral = true,
    .resDeviceID = {"local"},
    .grantStatus = {PermissionState::PERMISSION_GRANTED},
    .grantFlags = {1}
};

PermissionStateFull g_infoManagerTestState2 = {
    .permissionName = "ohos.permission.test2",
    .isGeneral = false,
    .resDeviceID = {"device 1", "device 2"},
    .grantStatus = {PermissionState::PERMISSION_GRANTED, PermissionState::PERMISSION_GRANTED},
    .grantFlags = {1, 2}
};

HapInfoParams g_infoManagerTestInfoParms = {
    .userID = 1,
    .bundleName = "accesstoken_test",
    .instIndex = 0,
    .appIDDesc = "testtesttesttest",
    .apiVersion = DEFAULT_API_VERSION
};

HapPolicyParams g_infoManagerTestPolicyPrams = {
    .apl = APL_NORMAL,
    .domain = "test.domain",
    .permList = {g_infoManagerTestPermDef1, g_infoManagerTestPermDef2},
    .permStateList = {g_infoManagerTestState1, g_infoManagerTestState2}
};

HapInfoParams g_infoManagerTestInfoParmsBak = {
    .userID = 1,
    .bundleName = "accesstoken_test",
    .instIndex = 0,
    .appIDDesc = "testtesttesttest",
    .apiVersion = DEFAULT_API_VERSION
};

HapPolicyParams g_infoManagerTestPolicyPramsBak = {
    .apl = APL_NORMAL,
    .domain = "test.domain",
    .permList = {g_infoManagerTestPermDef1, g_infoManagerTestPermDef2},
    .permStateList = {g_infoManagerTestState1, g_infoManagerTestState2}
};

HapInfoParams g_locationTestInfo = {
    .userID = TEST_USER_ID,
    .bundleName = "accesstoken_location_test",
    .instIndex = 0,
    .appIDDesc = "testtesttesttest"
};

PermissionDef g_locationTestDefVague = {
    .permissionName = "ohos.permission.APPROXIMATELY_LOCATION",
    .bundleName = "accesstoken_location_test",
    .grantMode = GrantMode::USER_GRANT,
    .availableLevel = APL_NORMAL,
    .provisionEnable = false,
    .distributedSceneEnable = true
};

PermissionDef g_locationTestDefAccurate = {
    .permissionName = "ohos.permission.LOCATION",
    .bundleName = "accesstoken_location_test",
    .grantMode = GrantMode::USER_GRANT,
    .availableLevel = APL_NORMAL,
    .provisionEnable = true,
    .distributedSceneEnable = true
};

PermissionDef g_locationTestDefSystemGrant = {
    .permissionName = "ohos.permission.locationtest1",
    .bundleName = "accesstoken_location_test",
    .grantMode = GrantMode::SYSTEM_GRANT,
    .availableLevel = APL_NORMAL,
    .provisionEnable = false,
    .distributedSceneEnable = false
};

PermissionDef g_locationTestDefUserGrant = {
    .permissionName = "ohos.permission.locationtest2",
    .bundleName = "accesstoken_location_test",
    .grantMode = GrantMode::USER_GRANT,
    .availableLevel = APL_NORMAL,
    .provisionEnable = false,
    .distributedSceneEnable = false
};

PermissionStateFull g_locationTestStateSystemGrant = {
    .permissionName = "ohos.permission.locationtest1",
    .isGeneral = true,
    .resDeviceID = {"device"},
    .grantStatus = {PermissionState::PERMISSION_GRANTED},
    .grantFlags = {PermissionFlag::PERMISSION_SYSTEM_FIXED}
};

PermissionStateFull g_locationTestStateUserGrant = {
    .permissionName = "ohos.permission.locationtest2",
    .isGeneral = true,
    .resDeviceID = {"device"},
    .grantStatus = {PermissionState::PERMISSION_DENIED},
    .grantFlags = {PermissionFlag::PERMISSION_DEFAULT_FLAG}
};

PermissionStateFull g_locationTestStateVague02 = {
    .permissionName = "ohos.permission.APPROXIMATELY_LOCATION",
    .isGeneral = true,
    .resDeviceID = {"device"},
    .grantStatus = {PermissionState::PERMISSION_GRANTED},
    .grantFlags = {PermissionFlag::PERMISSION_USER_FIXED}
};

PermissionStateFull g_locationTestStateVague10 = {
    .permissionName = "ohos.permission.APPROXIMATELY_LOCATION",
    .isGeneral = true,
    .resDeviceID = {"device"},
    .grantStatus = {PermissionState::PERMISSION_DENIED},
    .grantFlags = {PermissionFlag::PERMISSION_DEFAULT_FLAG}
};

PermissionStateFull g_locationTestStateVague12 = {
    .permissionName = "ohos.permission.APPROXIMATELY_LOCATION",
    .isGeneral = true,
    .resDeviceID = {"device"},
    .grantStatus = {PermissionState::PERMISSION_DENIED},
    .grantFlags = {PermissionFlag::PERMISSION_USER_FIXED}
};

PermissionStateFull g_locationTestStateAccurate02 = {
    .permissionName = "ohos.permission.LOCATION",
    .isGeneral = true,
    .resDeviceID = {"device"},
    .grantStatus = {PermissionState::PERMISSION_GRANTED},
    .grantFlags = {PermissionFlag::PERMISSION_USER_FIXED}
};

PermissionStateFull g_locationTestStateAccurate10 = {
    .permissionName = "ohos.permission.LOCATION",
    .isGeneral = true,
    .resDeviceID = {"device"},
    .grantStatus = {PermissionState::PERMISSION_DENIED},
    .grantFlags = {PermissionFlag::PERMISSION_DEFAULT_FLAG}
};

PermissionStateFull g_locationTestStateAccurate12 = {
    .permissionName = "ohos.permission.LOCATION",
    .isGeneral = true,
    .resDeviceID = {"device"},
    .grantStatus = {PermissionState::PERMISSION_DENIED},
    .grantFlags = {PermissionFlag::PERMISSION_USER_FIXED}
};
}

void NativeTokenGet()
{
    uint64_t tokenId;
    const char **perms = new const char *[4];
    perms[0] = "ohos.permission.DISTRIBUTED_DATASYNC";
    perms[1] = "ohos.permission.GRANT_SENSITIVE_PERMISSIONS";
    perms[2] = "ohos.permission.REVOKE_SENSITIVE_PERMISSIONS";
    perms[3] = "ohos.permission.GET_SENSITIVE_PERMISSIONS";

    NativeTokenInfoParams infoInstance = {
        .dcapsNum = 0,
        .permsNum = 4,
        .aclsNum = 0,
        .dcaps = nullptr,
        .perms = perms,
        .acls = nullptr,
        .aplStr = "system_core",
    };

    infoInstance.processName = "TestCase";
    tokenId = GetAccessTokenId(&infoInstance);
    SetSelfTokenID(tokenId);
    AccessTokenKit::ReloadNativeTokenInfo();
    delete[] perms;
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

    NativeTokenGet();
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
        .apiVersion = DEFAULT_API_VERSION
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
        .permissionName = "ohos.permission.testPermDef1",
        .isGeneral = true,
        .resDeviceID = {"local"},
        .grantStatus = {PermissionState::PERMISSION_DENIED},
        .grantFlags = {0},
    };

    PermissionStateFull permTestState2 = {
        .permissionName = "ohos.permission.testPermDef2",
        .isGeneral = true,
        .resDeviceID = {"local"},
        .grantStatus = {PermissionState::PERMISSION_DENIED},
        .grantFlags = {1}
    };

    PermissionStateFull permTestState3 = {
        .permissionName = "ohos.permission.testPermDef3",
        .isGeneral = true,
        .resDeviceID = {"local"},
        .grantStatus = {PermissionState::PERMISSION_DENIED},
        .grantFlags = {2}
    };

    PermissionStateFull permTestState4 = {
        .permissionName = "ohos.permission.testPermDef4",
        .isGeneral = true,
        .resDeviceID = {"local"},
        .grantStatus = {PermissionState::PERMISSION_GRANTED},
        .grantFlags = {1}
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

    ACCESSTOKEN_LOG_INFO(LABEL, "SetUp ok.");
}

void AccessTokenKitTest::TearDown()
{
    AccessTokenID tokenID = GetAccessTokenID(TEST_USER_ID, TEST_BUNDLE_NAME, 0);
    AccessTokenKit::DeleteToken(tokenID);
    SetSelfTokenID(selfTokenId_);
}

void AccessTokenKitTest::AllocHapToken(std::vector<PermissionDef>& permmissionDefs,
    std::vector<PermissionStateFull>& permissionStateFulls, int32_t apiVersion)
{
    AccessTokenID tokenID = AccessTokenKit::GetHapTokenID(TEST_USER_ID, "accesstoken_location_test", 0);
    AccessTokenKit::DeleteToken(tokenID);

    HapInfoParams info = g_locationTestInfo;
    info.apiVersion = apiVersion;

    HapPolicyParams policy = {
        .apl = APL_NORMAL,
        .domain = "domain"
    };

    for (auto& permmissionDef:permmissionDefs) {
        policy.permList.emplace_back(permmissionDef);
    }

    for (auto& permissionStateFull:permissionStateFulls) {
        policy.permStateList.emplace_back(permissionStateFull);
    }

    AccessTokenKit::AllocHapToken(info, policy);
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
    ASSERT_NE(INVALID_TOKENID, tokenIdEx.tokenIdExStruct.tokenID);
}

/**
 * @tc.name: GetDefPermission001
 * @tc.desc: Get permission definition info after AllocHapToken function has been invoked.
 * @tc.type: FUNC
 * @tc.require: Issue Number
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
 * @tc.require: Issue Number
 */
HWTEST_F(AccessTokenKitTest, GetDefPermission002, TestSize.Level1)
{
    PermissionDef permDefResult;
    int ret = AccessTokenKit::GetDefPermission(TEST_PERMISSION_NAME_GAMMA, permDefResult);
    ASSERT_EQ(AccessTokenError::ERR_PERMISSION_NOT_EXIT, ret);

    ret = AccessTokenKit::GetDefPermission("", permDefResult);
    ASSERT_EQ(AccessTokenError::ERR_PARAM_INVALID, ret);

    std::string invalidPerm(INVALID_PERMNAME_LEN, 'a');
    ret = AccessTokenKit::GetDefPermission(invalidPerm, permDefResult);
    ASSERT_EQ(AccessTokenError::ERR_PARAM_INVALID, ret);
}

/**
 * @tc.name: GetDefPermission003
 * @tc.desc: GetDefPermission is invoked multiple times.
 * @tc.type: FUNC
 * @tc.require: Issue Number
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
 * @tc.require: Issue Number
 */
HWTEST_F(AccessTokenKitTest, GetDefPermissions001, TestSize.Level1)
{
    AccessTokenID tokenID = GetAccessTokenID(TEST_USER_ID, TEST_BUNDLE_NAME, 0);
    ASSERT_NE(INVALID_TOKENID, tokenID);
    std::vector<PermissionDef> permDefList;
    int ret = AccessTokenKit::GetDefPermissions(tokenID, permDefList);
    ASSERT_EQ(RET_SUCCESS, ret);
    ASSERT_EQ(static_cast<uint32_t>(6), permDefList.size());
}

/**
 * @tc.name: GetDefPermissions002
 * @tc.desc: Get permission definition info list after clear permission definition list
 * @tc.type: FUNC
 * @tc.require: Issue Number
 */
HWTEST_F(AccessTokenKitTest, GetDefPermissions002, TestSize.Level1)
{
    HapPolicyParams testPolicyPrams = g_infoManagerTestPolicyPrams;
    testPolicyPrams.permList.clear();
    AccessTokenKit::AllocHapToken(g_infoManagerTestInfoParms, testPolicyPrams);

    AccessTokenID tokenID = GetAccessTokenID(g_infoManagerTestInfoParms.userID,
                               g_infoManagerTestInfoParms.bundleName,
                               g_infoManagerTestInfoParms.instIndex);
    ASSERT_NE(INVALID_TOKENID, tokenID);

    std::vector<PermissionDef> permDefList;
    int ret = AccessTokenKit::GetDefPermissions(tokenID, permDefList);
    ASSERT_EQ(RET_SUCCESS, ret);
    ASSERT_EQ(static_cast<uint32_t>(0), permDefList.size());

    AccessTokenKit::DeleteToken(tokenID);
}

/**
 * @tc.name: GetDefPermissions003
 * @tc.desc: Get permission definition info list that tokenID is invalid.
 * @tc.type: FUNC
 * @tc.require: Issue Number
 */
HWTEST_F(AccessTokenKitTest, GetDefPermissions003, TestSize.Level1)
{
    AccessTokenID tokenID = GetAccessTokenID(TEST_USER_ID, TEST_BUNDLE_NAME, 0);
    ASSERT_NE(INVALID_TOKENID, tokenID);
    AccessTokenKit::DeleteToken(tokenID);

    std::vector<PermissionDef> permDefList;
    int ret = AccessTokenKit::GetDefPermissions(TEST_TOKENID_INVALID, permDefList);
    ASSERT_EQ(RET_FAILED, ret);

    std::vector<PermissionDef> permDefListRes;
    ret = AccessTokenKit::GetDefPermissions(tokenID, permDefListRes);
    ASSERT_EQ(RET_FAILED, ret);
    ASSERT_EQ(static_cast<uint32_t>(0), permDefListRes.size());
}

/**
 * @tc.name: GetDefPermissions004
 * @tc.desc: GetDefPermissions is invoked multiple times.
 * @tc.type: FUNC
 * @tc.require: Issue Number
 */
HWTEST_F(AccessTokenKitTest, GetDefPermissions004, TestSize.Level0)
{
    AccessTokenID tokenID = GetAccessTokenID(TEST_USER_ID, TEST_BUNDLE_NAME, 0);
    ASSERT_NE(INVALID_TOKENID, tokenID);
    int ret = RET_FAILED;
    for (int i = 0; i < CYCLE_TIMES; i++) {
        std::vector<PermissionDef> permDefList;
        ret = AccessTokenKit::GetDefPermissions(tokenID, permDefList);
        ASSERT_EQ(RET_SUCCESS, ret);
        ASSERT_EQ(static_cast<uint32_t>(6), permDefList.size());
    }
}

/**
 * @tc.name: GetReqPermissions001
 * @tc.desc: Get user granted permission state info.
 * @tc.type: FUNC
 * @tc.require: Issue Number
 */
HWTEST_F(AccessTokenKitTest, GetReqPermissions001, TestSize.Level1)
{
    AccessTokenID tokenID = GetAccessTokenID(TEST_USER_ID, TEST_BUNDLE_NAME, 0);
    ASSERT_NE(INVALID_TOKENID, tokenID);
    std::vector<PermissionStateFull> permStatList;
    int ret = AccessTokenKit::GetReqPermissions(tokenID, permStatList, false);
    ASSERT_EQ(RET_SUCCESS, ret);
    ASSERT_EQ(static_cast<uint32_t>(5), permStatList.size());
    ASSERT_EQ(TEST_PERMISSION_NAME_ALPHA, permStatList[0].permissionName);

    ret = AccessTokenKit::VerifyAccessToken(tokenID, TEST_PERMISSION_NAME_ALPHA);
    ASSERT_EQ(ret, permStatList[0].grantStatus[0]);
}

/**
 * @tc.name: GetReqPermissions002
 * @tc.desc: Get system granted permission state info.
 * @tc.type: FUNC
 * @tc.require: Issue Number
 */
HWTEST_F(AccessTokenKitTest, GetReqPermissions002, TestSize.Level1)
{
    AccessTokenID tokenID = GetAccessTokenID(TEST_USER_ID, TEST_BUNDLE_NAME, 0);
    ASSERT_NE(INVALID_TOKENID, tokenID);
    std::vector<PermissionStateFull> permStatList;
    int ret = AccessTokenKit::GetReqPermissions(tokenID, permStatList, true);
    ASSERT_EQ(RET_SUCCESS, ret);
    ASSERT_EQ(static_cast<uint32_t>(3), permStatList.size());
    ASSERT_EQ(TEST_PERMISSION_NAME_BETA, permStatList[0].permissionName);

    ret = AccessTokenKit::VerifyAccessToken(tokenID, TEST_PERMISSION_NAME_BETA);
    ASSERT_EQ(ret, permStatList[0].grantStatus[0]);
}

/**
 * @tc.name: GetReqPermissions003
 * @tc.desc: Get user granted permission state info after clear request permission list.
 * @tc.type: FUNC
 * @tc.require: Issue Number
 */
HWTEST_F(AccessTokenKitTest, GetReqPermissions003, TestSize.Level1)
{
    AccessTokenID tokenID = GetAccessTokenID(TEST_USER_ID, TEST_BUNDLE_NAME, 0);
    ASSERT_NE(INVALID_TOKENID, tokenID);

    HapTokenInfo hapInfo;
    int ret = AccessTokenKit::GetHapTokenInfo(tokenID, hapInfo);
    ASSERT_EQ(RET_SUCCESS, ret);

    HapPolicyParams policy = {
        .apl = hapInfo.apl,
        .domain = "domain"
    };
    policy.permStateList.clear();

    ret = AccessTokenKit::UpdateHapToken(tokenID, hapInfo.appID, DEFAULT_API_VERSION, policy);
    ASSERT_EQ(RET_SUCCESS, ret);

    std::vector<PermissionStateFull> permStatUserList;
    ret = AccessTokenKit::GetReqPermissions(tokenID, permStatUserList, false);
    ASSERT_EQ(RET_SUCCESS, ret);
    ASSERT_EQ(static_cast<uint32_t>(0), permStatUserList.size());

    std::vector<PermissionStateFull> permStatSystemList;
    ret = AccessTokenKit::GetReqPermissions(tokenID, permStatSystemList, true);
    ASSERT_EQ(RET_SUCCESS, ret);
    ASSERT_EQ(static_cast<uint32_t>(0), permStatSystemList.size());
}

/**
 * @tc.name: GetReqPermissions004
 * @tc.desc: Get permission state info list that tokenID is invalid.
 * @tc.type: FUNC
 * @tc.require: Issue Number
 */
HWTEST_F(AccessTokenKitTest, GetReqPermissions004, TestSize.Level1)
{
    AccessTokenID tokenID = GetAccessTokenID(TEST_USER_ID, TEST_BUNDLE_NAME, 0);
    ASSERT_NE(INVALID_TOKENID, tokenID);

    std::vector<PermissionStateFull> permStatList;
    int ret = AccessTokenKit::GetReqPermissions(TEST_TOKENID_INVALID, permStatList, false);
    ASSERT_EQ(RET_FAILED, ret);

    AccessTokenKit::DeleteToken(tokenID);

    ret = AccessTokenKit::GetReqPermissions(tokenID, permStatList, false);
    ASSERT_EQ(RET_FAILED, ret);
    ASSERT_EQ(static_cast<uint32_t>(0), permStatList.size());
}

/**
 * @tc.name: GetReqPermissions005
 * @tc.desc: GetReqPermissions is invoked multiple times.
 * @tc.type: FUNC
 * @tc.require: Issue Number
 */
HWTEST_F(AccessTokenKitTest, GetReqPermissions005, TestSize.Level0)
{
    AccessTokenID tokenID = GetAccessTokenID(TEST_USER_ID, TEST_BUNDLE_NAME, 0);
    ASSERT_NE(INVALID_TOKENID, tokenID);
    int ret = RET_FAILED;
    for (int i = 0; i < CYCLE_TIMES; i++) {
        std::vector<PermissionStateFull> permStatList;
        ret = AccessTokenKit::GetReqPermissions(tokenID, permStatList, false);
        ASSERT_EQ(RET_SUCCESS, ret);
        ASSERT_EQ(static_cast<uint32_t>(5), permStatList.size());
        ASSERT_EQ(TEST_PERMISSION_NAME_ALPHA, permStatList[0].permissionName);
    }
}

/**
 * @tc.name: GetPermissionFlag001
 * @tc.desc: Get permission flag after grant permission.
 * @tc.type: FUNC
 * @tc.require: Issue Number
 */
HWTEST_F(AccessTokenKitTest, GetPermissionFlag001, TestSize.Level1)
{
    AccessTokenID tokenID = GetAccessTokenID(TEST_USER_ID, TEST_BUNDLE_NAME, 0);
    ASSERT_NE(INVALID_TOKENID, tokenID);
    int ret = AccessTokenKit::GrantPermission(tokenID, TEST_PERMISSION_NAME_ALPHA, PERMISSION_USER_FIXED);
    ASSERT_EQ(RET_SUCCESS, ret);

    int32_t flag;
    ret = AccessTokenKit::GetPermissionFlag(tokenID, TEST_PERMISSION_NAME_ALPHA, flag);
    ASSERT_EQ(PERMISSION_USER_FIXED, flag);
    ASSERT_EQ(RET_SUCCESS, ret);
}

/**
 * @tc.name: GetPermissionFlag002
 * @tc.desc: Get permission flag that tokenID or permission is invalid.
 * @tc.type: FUNC
 * @tc.require: Issue Number
 */
HWTEST_F(AccessTokenKitTest, GetPermissionFlag002, TestSize.Level1)
{
    AccessTokenID tokenID = GetAccessTokenID(TEST_USER_ID, TEST_BUNDLE_NAME, 0);
    ASSERT_NE(INVALID_TOKENID, tokenID);

    int32_t flag;
    int ret = AccessTokenKit::GetPermissionFlag(tokenID, TEST_PERMISSION_NAME_GAMMA, flag);
    ASSERT_EQ(AccessTokenError::ERR_PERMISSION_NOT_EXIT, ret);

    ret = AccessTokenKit::GetPermissionFlag(tokenID, "", flag);
    ASSERT_EQ(AccessTokenError::ERR_PARAM_INVALID, ret);

    std::string invalidPerm(INVALID_PERMNAME_LEN, 'a');
    ret = AccessTokenKit::GetPermissionFlag(tokenID, invalidPerm, flag);
    ASSERT_EQ(AccessTokenError::ERR_PARAM_INVALID, ret);

    ret = AccessTokenKit::GetPermissionFlag(TEST_TOKENID_INVALID, TEST_PERMISSION_NAME_ALPHA, flag);
    ASSERT_EQ(AccessTokenError::ERR_PARAM_INVALID, ret);

    AccessTokenKit::DeleteToken(tokenID);

    ret = AccessTokenKit::GetPermissionFlag(tokenID, TEST_PERMISSION_NAME_ALPHA, flag);
    ASSERT_EQ(AccessTokenError::ERR_PERMISSION_NOT_EXIT, ret);
}

/**
 * @tc.name: GetPermissionFlag003
 * @tc.desc: GetPermissionFlag is invoked multiple times.
 * @tc.type: FUNC
 * @tc.require: Issue Number
 */
HWTEST_F(AccessTokenKitTest, GetPermissionFlag003, TestSize.Level0)
{
    AccessTokenID tokenID = GetAccessTokenID(TEST_USER_ID, TEST_BUNDLE_NAME, 0);
    ASSERT_NE(INVALID_TOKENID, tokenID);
    int ret = RET_FAILED;
    int32_t flag;
    for (int i = 0; i < CYCLE_TIMES; i++) {
        ret = AccessTokenKit::GrantPermission(tokenID, TEST_PERMISSION_NAME_ALPHA, PERMISSION_USER_FIXED);
        ASSERT_EQ(RET_SUCCESS, ret);

        ret = AccessTokenKit::GetPermissionFlag(tokenID, TEST_PERMISSION_NAME_ALPHA, flag);
        ASSERT_EQ(RET_SUCCESS, ret);
        ASSERT_EQ(PERMISSION_USER_FIXED, flag);
    }
}

/**
 * @tc.name: VerifyAccessToken001
 * @tc.desc: Verify user granted permission.
 * @tc.type: FUNC
 * @tc.require: Issue Number
 */
HWTEST_F(AccessTokenKitTest, VerifyAccessToken001, TestSize.Level0)
{
    AccessTokenID tokenID = GetAccessTokenID(TEST_USER_ID, TEST_BUNDLE_NAME, 0);
    ASSERT_NE(INVALID_TOKENID, tokenID);
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
 * @tc.require: Issue Number
 */
HWTEST_F(AccessTokenKitTest, VerifyAccessToken002, TestSize.Level0)
{
    AccessTokenID tokenID = GetAccessTokenID(TEST_USER_ID, TEST_BUNDLE_NAME, 0);
    ASSERT_NE(INVALID_TOKENID, tokenID);
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
 * @tc.require: Issue Number
 */
HWTEST_F(AccessTokenKitTest, VerifyAccessToken003, TestSize.Level0)
{
    AccessTokenID tokenID = GetAccessTokenID(TEST_USER_ID, TEST_BUNDLE_NAME, 0);
    ASSERT_NE(INVALID_TOKENID, tokenID);
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
 * @tc.require: Issue Number
 */
HWTEST_F(AccessTokenKitTest, VerifyAccessToken004, TestSize.Level0)
{
    AccessTokenID tokenID = GetAccessTokenID(TEST_USER_ID, TEST_BUNDLE_NAME, 0);
    ASSERT_NE(INVALID_TOKENID, tokenID);

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

    ret = AccessTokenKit::UpdateHapToken(tokenID, hapInfo.appID, DEFAULT_API_VERSION, policy);
    ASSERT_EQ(RET_SUCCESS, ret);

    ret = AccessTokenKit::VerifyAccessToken(tokenID, TEST_PERMISSION_NAME_ALPHA);
    ASSERT_EQ(PERMISSION_GRANTED, ret);
}

/**
 * @tc.name: GrantPermission001
 * @tc.desc: Grant permission that has ohos.permission.GRANT_SENSITIVE_PERMISSIONS
 * @tc.type: FUNC
 * @tc.require: Issue Number
 */
HWTEST_F(AccessTokenKitTest, GrantPermission001, TestSize.Level0)
{
    AccessTokenID tokenID = GetAccessTokenID(TEST_USER_ID, TEST_BUNDLE_NAME, 0);
    ASSERT_NE(INVALID_TOKENID, tokenID);
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
 * @tc.require: Issue Number
 */
HWTEST_F(AccessTokenKitTest, GrantPermission002, TestSize.Level0)
{
    AccessTokenID tokenID = GetAccessTokenID(TEST_USER_ID, TEST_BUNDLE_NAME, 0);
    ASSERT_NE(INVALID_TOKENID, tokenID);

    int ret = AccessTokenKit::GrantPermission(tokenID, TEST_PERMISSION_NAME_GAMMA, PERMISSION_USER_FIXED);
    ASSERT_EQ(RET_SUCCESS, ret);

    ret = AccessTokenKit::GrantPermission(tokenID, "", PERMISSION_USER_FIXED);
    ASSERT_EQ(AccessTokenError::ERR_PARAM_INVALID, ret);

    std::string invalidPerm(INVALID_PERMNAME_LEN, 'a');
    ret = AccessTokenKit::GrantPermission(tokenID, invalidPerm, PERMISSION_USER_FIXED);
    ASSERT_EQ(AccessTokenError::ERR_PARAM_INVALID, ret);

    ret = AccessTokenKit::GrantPermission(TEST_TOKENID_INVALID, TEST_PERMISSION_NAME_BETA, PERMISSION_USER_FIXED);
    ASSERT_EQ(AccessTokenError::ERR_PARAM_INVALID, ret);

    AccessTokenKit::DeleteToken(tokenID);

    ret = AccessTokenKit::GrantPermission(tokenID, TEST_PERMISSION_NAME_BETA, PERMISSION_USER_FIXED);
    ASSERT_EQ(RET_SUCCESS, ret);
}

/**
 * @tc.name: GrantPermission003
 * @tc.desc: GrantPermission is invoked multiple times.
 * @tc.type: FUNC
 * @tc.require: Issue Number
 */
HWTEST_F(AccessTokenKitTest, GrantPermission003, TestSize.Level0)
{
    AccessTokenID tokenID = GetAccessTokenID(TEST_USER_ID, TEST_BUNDLE_NAME, 0);
    ASSERT_NE(INVALID_TOKENID, tokenID);
    int ret = RET_FAILED;
    int32_t flag;
    for (int i = 0; i < CYCLE_TIMES; i++) {
        ret = AccessTokenKit::GrantPermission(tokenID, TEST_PERMISSION_NAME_ALPHA, PERMISSION_USER_FIXED);
        ASSERT_EQ(RET_SUCCESS, ret);

        ret = AccessTokenKit::VerifyAccessToken(tokenID, TEST_PERMISSION_NAME_ALPHA);
        ASSERT_EQ(PERMISSION_GRANTED, ret);

        ret = AccessTokenKit::GetPermissionFlag(tokenID, TEST_PERMISSION_NAME_ALPHA, flag);
        ASSERT_EQ(PERMISSION_USER_FIXED, flag);
        ASSERT_EQ(RET_SUCCESS, ret);
    }
}

/**
 * @tc.name: GrantPermission004
 * @tc.desc: GrantPermission function abnormal branch
 * @tc.type: FUNC
 * @tc.require:Issue I5RJBB
 */
HWTEST_F(AccessTokenKitTest, GrantPermission004, TestSize.Level0)
{
    AccessTokenID tokenID = GetAccessTokenID(TEST_USER_ID, TEST_BUNDLE_NAME, 0);
    ASSERT_NE(INVALID_TOKENID, tokenID);
    int32_t invalidFlag = -1;
    int32_t ret = AccessTokenKit::GrantPermission(tokenID, TEST_PERMISSION_NAME_ALPHA, invalidFlag);
    ASSERT_EQ(AccessTokenError::ERR_PARAM_INVALID, ret);
}

/**
 * @tc.name: RevokePermission001
 * @tc.desc: Revoke permission that has ohos.permission.GRANT_SENSITIVE_PERMISSIONS
 * @tc.type: FUNC
 * @tc.require: Issue Number
 */
HWTEST_F(AccessTokenKitTest, RevokePermission001, TestSize.Level0)
{
    AccessTokenID tokenID = GetAccessTokenID(TEST_USER_ID, TEST_BUNDLE_NAME, 0);
    ASSERT_NE(INVALID_TOKENID, tokenID);
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
 * @tc.require: Issue Number
 */
HWTEST_F(AccessTokenKitTest, RevokePermission002, TestSize.Level0)
{
    AccessTokenID tokenID = GetAccessTokenID(TEST_USER_ID, TEST_BUNDLE_NAME, 0);
    ASSERT_NE(INVALID_TOKENID, tokenID);

    int ret = AccessTokenKit::RevokePermission(tokenID, TEST_PERMISSION_NAME_GAMMA, PERMISSION_USER_FIXED);
    ASSERT_EQ(RET_SUCCESS, ret);

    ret = AccessTokenKit::RevokePermission(tokenID, "", PERMISSION_USER_FIXED);
    ASSERT_EQ(AccessTokenError::ERR_PARAM_INVALID, ret);

    std::string invalidPerm(INVALID_PERMNAME_LEN, 'a');
    ret = AccessTokenKit::RevokePermission(tokenID, invalidPerm, PERMISSION_USER_FIXED);
    ASSERT_EQ(AccessTokenError::ERR_PARAM_INVALID, ret);

    ret = AccessTokenKit::RevokePermission(TEST_TOKENID_INVALID, TEST_PERMISSION_NAME_BETA, PERMISSION_USER_FIXED);
    ASSERT_EQ(AccessTokenError::ERR_PARAM_INVALID, ret);

    AccessTokenKit::DeleteToken(tokenID);

    ret = AccessTokenKit::RevokePermission(tokenID, TEST_PERMISSION_NAME_BETA, PERMISSION_USER_FIXED);
    ASSERT_EQ(RET_SUCCESS, ret);
}

/**
 * @tc.name: RevokePermission003
 * @tc.desc: RevokePermission is invoked multiple times.
 * @tc.type: FUNC
 * @tc.require: Issue Number
 */
HWTEST_F(AccessTokenKitTest, RevokePermission003, TestSize.Level0)
{
    AccessTokenID tokenID = GetAccessTokenID(TEST_USER_ID, TEST_BUNDLE_NAME, 0);
    ASSERT_NE(INVALID_TOKENID, tokenID);
    int ret = RET_FAILED;
    int32_t flag;
    for (int i = 0; i < CYCLE_TIMES; i++) {
        ret = AccessTokenKit::RevokePermission(tokenID, TEST_PERMISSION_NAME_ALPHA, PERMISSION_USER_FIXED);
        ASSERT_EQ(RET_SUCCESS, ret);

        ret = AccessTokenKit::VerifyAccessToken(tokenID, TEST_PERMISSION_NAME_ALPHA);
        ASSERT_EQ(PERMISSION_DENIED, ret);

        ret = AccessTokenKit::GetPermissionFlag(tokenID, TEST_PERMISSION_NAME_ALPHA, flag);
        ASSERT_EQ(PERMISSION_USER_FIXED, flag);
        ASSERT_EQ(RET_SUCCESS, ret);
    }
}

/**
 * @tc.name: RevokePermission004
 * @tc.desc: Revoke permission abnormal branch.
 * @tc.type: FUNC
 * @tc.require:Issue I5RJBB
 */
HWTEST_F(AccessTokenKitTest, RevokePermission004, TestSize.Level0)
{
    AccessTokenID tokenID = GetAccessTokenID(TEST_USER_ID, TEST_BUNDLE_NAME, 0);
    ASSERT_NE(INVALID_TOKENID, tokenID);
    int invalidFlag = -1;
    int32_t ret = AccessTokenKit::RevokePermission(tokenID, TEST_PERMISSION_NAME_ALPHA, invalidFlag);
    ASSERT_EQ(AccessTokenError::ERR_PARAM_INVALID, ret);
}

/**
 * @tc.name: ClearUserGrantedPermissionState001
 * @tc.desc: Clear user/system granted permission after ClearUserGrantedPermissionState has been invoked.
 * @tc.type: FUNC
 * @tc.require: Issue Number
 */
HWTEST_F(AccessTokenKitTest, ClearUserGrantedPermissionState001, TestSize.Level0)
{
    AccessTokenID tokenID = GetAccessTokenID(TEST_USER_ID, TEST_BUNDLE_NAME, 0);
    ASSERT_NE(INVALID_TOKENID, tokenID);
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
 * @tc.require: Issue Number
 */
HWTEST_F(AccessTokenKitTest, ClearUserGrantedPermissionState002, TestSize.Level0)
{
    AccessTokenID tokenID = GetAccessTokenID(TEST_USER_ID, TEST_BUNDLE_NAME, 0);
    ASSERT_NE(INVALID_TOKENID, tokenID);

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
 * @tc.require: Issue Number
 */
HWTEST_F(AccessTokenKitTest, ClearUserGrantedPermissionState003, TestSize.Level0)
{
    AccessTokenID tokenID = GetAccessTokenID(TEST_USER_ID, TEST_BUNDLE_NAME, 0);
    ASSERT_NE(INVALID_TOKENID, tokenID);
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
 * @tc.require: Issue Number
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
    ASSERT_NE(INVALID_TOKENID, tokenID);
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
 * @tc.require: Issue Number
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
 * @tc.name: GetTokenType002
 * @tc.desc: get the token type abnormal branch.
 * @tc.type: FUNC
 * @tc.require Issue I5RJBB
 */
HWTEST_F(AccessTokenKitTest, GetTokenType002, TestSize.Level0)
{
    AccessTokenID tokenID = 0;
    int32_t ret = AccessTokenKit::GetTokenType(tokenID);
    ASSERT_EQ(TOKEN_INVALID, ret);
}

/**
 * @tc.name: GetHapDlpFlag001
 * @tc.desc: GetHapDlpFlag function abnormal branch.
 * @tc.type: FUNC
 * @tc.require Issue Number:I5RJBB
 */
HWTEST_F(AccessTokenKitTest, GetHapDlpFlag001, TestSize.Level0)
{
    AccessTokenID tokenID = 0;
    int32_t ret = AccessTokenKit::GetHapDlpFlag(tokenID);
    ASSERT_EQ(INVALID_DLP_TOKEN_FLAG, ret);
}

/**
 * @tc.name: GetHapTokenInfo001
 * @tc.desc: get the token info and verify.
 * @tc.type: FUNC
 * @tc.require: Issue Number
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
    ASSERT_EQ(hapTokenInfoRes.tokenAttr, static_cast<AccessTokenAttr>(0));
    ASSERT_EQ(hapTokenInfoRes.instIndex, 0);

    ASSERT_EQ(hapTokenInfoRes.appID, "appIDDesc");

    ASSERT_EQ(hapTokenInfoRes.bundleName, TEST_BUNDLE_NAME);
}

/**
 * @tc.name: GetHapTokenInfo002
 * @tc.desc: try to get the token info with invalid tokenId.
 * @tc.type: FUNC
 * @tc.require: Issue Number
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
 * @tc.require: Issue Number
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
    ASSERT_EQ(AccessTokenError::ERR_PERMISSION_NOT_EXIT, ret);
}

/**
 * @tc.name: DeleteToken002
 * @tc.desc: Delete invalid tokenID.
 * @tc.type: FUNC
 * @tc.require: Issue Number
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
 * @tc.require: Issue Number
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
 * @tc.require: Issue Number
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
 * @tc.require: Issue Number
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
 * @tc.require: Issue Number
 */
HWTEST_F(AccessTokenKitTest, GetHapTokenID002, TestSize.Level1)
{
    AccessTokenID tokenID;
    tokenID = AccessTokenKit::GetHapTokenID(TEST_USER_ID_INVALID, TEST_BUNDLE_NAME, 0);
    ASSERT_EQ(INVALID_TOKENID, tokenID);
}

/**
 * @tc.name: GetHapTokenID003
 * @tc.desc: cannot get hap tokenid with invalid bundlename.
 * @tc.type: FUNC
 * @tc.require: Issue Number
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
 * @tc.require: Issue Number
 */
HWTEST_F(AccessTokenKitTest, GetHapTokenID004, TestSize.Level1)
{
    AccessTokenID tokenID;
    tokenID = AccessTokenKit::GetHapTokenID(TEST_USER_ID, TEST_BUNDLE_NAME, 0xffff);
    ASSERT_EQ(0, tokenID);
}

/**
 * @tc.name: ReloadNativeTokenInfo001
 * @tc.desc: cannot get hap tokenid with invalid bundlename.
 * @tc.type: FUNC
 * @tc.require: Issue Number
 */
HWTEST_F(AccessTokenKitTest, ReloadNativeTokenInfo001, TestSize.Level1)
{
    int32_t ret = AccessTokenKit::ReloadNativeTokenInfo();
    ASSERT_EQ(RET_SUCCESS, ret);
}

/**
 * @tc.name: GetNativeTokenId001
 * @tc.desc: cannot get native tokenid with invalid processName.
 * @tc.type: FUNC
 * @tc.require: Issue Number
 */
HWTEST_F(AccessTokenKitTest, GetNativeTokenId001, TestSize.Level1)
{
    std::string processName = "";
    ASSERT_EQ(0, AccessTokenKit::GetNativeTokenId(processName));

    processName = "invalid processName";
    ASSERT_EQ(0, AccessTokenKit::GetNativeTokenId(processName));
}

/**
 * @tc.name: GetNativeTokenId002
 * @tc.desc: get native tokenid with processName.
 * @tc.type: FUNC
 * @tc.require: Issue Number
 */
HWTEST_F(AccessTokenKitTest, GetNativeTokenId002, TestSize.Level1)
{
    std::string processName = "hdcd";
    AccessTokenID tokenID = AccessTokenKit::GetNativeTokenId(processName);
    ASSERT_NE(INVALID_TOKENID, tokenID);

    NativeTokenInfo tokenInfo;
    ASSERT_EQ(RET_SUCCESS, AccessTokenKit::GetNativeTokenInfo(tokenID, tokenInfo));
    ASSERT_EQ(true, tokenInfo.processName == processName);
}

/**
 * @tc.name: GetNativeTokenId003
 * @tc.desc: get native tokenid with hap.
 * @tc.type: FUNC
 * @tc.require: Issue Number
 */
HWTEST_F(AccessTokenKitTest, GetNativeTokenId003, TestSize.Level1)
{
    std::string processName = "hdcd";
    AccessTokenID tokenID = GetAccessTokenID(TEST_USER_ID, TEST_BUNDLE_NAME, 0);
    ASSERT_NE(INVALID_TOKENID, tokenID);
    ASSERT_EQ(0, SetSelfTokenID(tokenID));
    ASSERT_EQ(RET_SUCCESS, AccessTokenKit::ReloadNativeTokenInfo());

    tokenID = AccessTokenKit::GetNativeTokenId(processName);
    ASSERT_NE(INVALID_TOKENID, tokenID);

    NativeTokenInfo tokenInfo;
    ASSERT_EQ(RET_SUCCESS, AccessTokenKit::GetNativeTokenInfo(tokenID, tokenInfo));
    ASSERT_EQ(true, tokenInfo.processName == processName);

    ASSERT_EQ(0, SetSelfTokenID(selfTokenId_));
}

/**
 * @tc.name: GetNativeTokenId004
 * @tc.desc: get native tokenid with hap.
 * @tc.type: FUNC
 * @tc.require: Issue Number
 */
HWTEST_F(AccessTokenKitTest, GetNativeTokenId004, TestSize.Level1)
{
    std::string processName = "hdcd";
    AccessTokenID tokenID = GetAccessTokenID(TEST_USER_ID, TEST_BUNDLE_NAME, 0);
    ASSERT_NE(INVALID_TOKENID, tokenID);
    ASSERT_EQ(RET_SUCCESS, SetSelfTokenID(tokenID));
    ASSERT_EQ(RET_SUCCESS, AccessTokenKit::ReloadNativeTokenInfo());

    int32_t selfUid = getuid();
    setuid(10001); // 10001： UID

    ASSERT_EQ(0, AccessTokenKit::GetNativeTokenId(processName));

    // restore environment
    setuid(selfUid);
    ASSERT_EQ(RET_SUCCESS, SetSelfTokenID(selfTokenId_));
}

/**
 * @tc.name: AllocHapToken001
 * @tc.desc: alloc a tokenId successfully, delete it successfully the first time and fail to delete it again.
 * @tc.type: FUNC
 * @tc.require: Issue Number
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
 * @tc.require: Issue Number
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
    ASSERT_NE(INVALID_TOKENID, tokenID);

    tokenIdEx = AccessTokenKit::AllocHapToken(g_infoManagerTestInfoParms, g_infoManagerTestPolicyPrams);
    ASSERT_NE(0, tokenIdEx.tokenIdExStruct.tokenID);
    ASSERT_NE(tokenID, tokenIdEx.tokenIdExStruct.tokenID);
    ASSERT_EQ(RET_FAILED, AccessTokenKit::DeleteToken(tokenID));
    ASSERT_EQ(RET_SUCCESS, AccessTokenKit::DeleteToken(tokenIdEx.tokenIdExStruct.tokenID));
}

/**
 * @tc.name: AllocHapToken003
 * @tc.desc: cannot alloc a tokenId with invalid bundlename.
 * @tc.type: FUNC
 * @tc.require: Issue Number
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
 * @tc.require: Issue Number
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
 * @tc.require: Issue Number
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
 * @tc.require: Issue Number
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
    ASSERT_EQ(AccessTokenError::ERR_PARAM_INVALID, ret);
    ret = AccessTokenKit::GetDefPermission(g_infoManagerTestPolicyPrams.permList[1].permissionName, permDefResultBeta);
    ASSERT_EQ(RET_SUCCESS, ret);
    g_infoManagerTestPolicyPrams.permList[0].permissionName  = backUp;
}

/**
 * @tc.name: AllocHapToken007
 * @tc.desc: can alloc a tokenId with invalid permdef.
 * @tc.type: FUNC
 * @tc.require: Issue Number
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
    ASSERT_EQ(AccessTokenError::ERR_PERMISSION_NOT_EXIT, ret);
    ret = AccessTokenKit::GetDefPermission(g_infoManagerTestPolicyPrams.permList[1].permissionName, permDefResultBeta);
    ASSERT_EQ(RET_SUCCESS, ret);
    g_infoManagerTestPolicyPrams.permList[0].bundleName  = backUp;
    g_infoManagerTestPolicyPrams.permList[0].permissionName = backUpPermission;
}

/**
 * @tc.name: AllocHapToken008
 * @tc.desc: can alloc a tokenId with invalid permdef.
 * @tc.type: FUNC
 * @tc.require: Issue Number
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
    ASSERT_EQ(AccessTokenError::ERR_PERMISSION_NOT_EXIT, ret);
    ret = AccessTokenKit::GetDefPermission(g_infoManagerTestPolicyPrams.permList[1].permissionName, permDefResultBeta);
    ASSERT_EQ(RET_SUCCESS, ret);
    g_infoManagerTestPolicyPrams.permList[0].label  = backUp;
    g_infoManagerTestPolicyPrams.permList[0].permissionName = backUpPermission;
}

/**
 * @tc.name: AllocHapToken009
 * @tc.desc: can alloc a tokenId with invalid permdef.
 * @tc.type: FUNC
 * @tc.require: Issue Number
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
    ASSERT_EQ(AccessTokenError::ERR_PERMISSION_NOT_EXIT, ret);
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
 * @tc.require: Issue Number
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
 * @tc.require: Issue Number
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
 * @tc.require: Issue Number
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
 * @tc.require: Issue Number
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
 * @tc.require: Issue Number
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
    ASSERT_EQ(AccessTokenError::ERR_PARAM_INVALID, ret);
    g_infoManagerTestPolicyPrams.permList[0].permissionName = backup;
}

/**
 * @tc.name: AllocHapToken015
 * @tc.desc: can alloc a tokenId with permList bundleName as "".
 * @tc.type: FUNC
 * @tc.require: Issue Number
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
    ASSERT_EQ(AccessTokenError::ERR_PERMISSION_NOT_EXIT, ret);
    ret = AccessTokenKit::GetDefPermission(g_infoManagerTestPolicyPrams.permList[1].permissionName, permDefResultBeta);
    ASSERT_EQ(RET_SUCCESS, ret);
    g_infoManagerTestPolicyPrams.permList[0].bundleName = backup;
    g_infoManagerTestPolicyPrams.permList[0].permissionName = backUpPermission;
}

/**
 * @tc.name: AllocHapToken016
 * @tc.desc: can alloc a tokenId with label as "".
 * @tc.type: FUNC
 * @tc.require: Issue Number
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
 * @tc.require: Issue Number
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
 * @tc.require: Issue Number
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
        .userID = 1,
        .bundleName = "dlp_test1",
        .instIndex = 0,
        .dlpType = DLP_COMMON,
        .appIDDesc = "testtesttesttest",
        .apiVersion = DEFAULT_API_VERSION
    };
    HapInfoParams infoManagerTestInfoParms2 = {
        .userID = 1,
        .bundleName = "dlp_test2",
        .instIndex = 1,
        .dlpType = DLP_READ,
        .appIDDesc = "testtesttesttest",
        .apiVersion = DEFAULT_API_VERSION
    };
    HapInfoParams infoManagerTestInfoParms3 = {
        .userID = 1,
        .bundleName = "dlp_test3",
        .instIndex = 2,
        .dlpType = DLP_FULL_CONTROL,
        .appIDDesc = "testtesttesttest",
        .apiVersion = DEFAULT_API_VERSION
    };
    HapTokenInfo hapTokenInfoRes;
    AccessTokenID tokenID;
    int32_t ret;

    tokenID = GetAccessTokenID(infoManagerTestInfoParms1.userID, infoManagerTestInfoParms1.bundleName, 0);
    if (tokenID != 0) {
        ret = AccessTokenKit::DeleteToken(tokenID);
    }
    tokenIdEx= AccessTokenKit::AllocHapToken(infoManagerTestInfoParms1, infoManagerTestPolicyPrams);
    ASSERT_NE(0, tokenIdEx.tokenIdExStruct.tokenID);
    ret = AccessTokenKit::GetHapTokenInfo(tokenIdEx.tokenIdExStruct.tokenID, hapTokenInfoRes);
    ASSERT_EQ(ret, RET_SUCCESS);
    ASSERT_EQ(AccessTokenKit::GetHapDlpFlag(tokenIdEx.tokenIdExStruct.tokenID), 0);
    ASSERT_EQ(hapTokenInfoRes.dlpType, DLP_COMMON);
    ret = AccessTokenKit::DeleteToken(tokenIdEx.tokenIdExStruct.tokenID);
    ASSERT_EQ(RET_SUCCESS, ret);
    ret = AccessTokenKit::GetHapTokenInfo(tokenIdEx.tokenIdExStruct.tokenID, hapTokenInfoRes);
    ASSERT_EQ(ret, RET_FAILED);

    tokenID = GetAccessTokenID(infoManagerTestInfoParms2.userID, infoManagerTestInfoParms2.bundleName, 1);
    if (tokenID != 0) {
        ret = AccessTokenKit::DeleteToken(tokenID);
    }
    tokenIdEx = AccessTokenKit::AllocHapToken(infoManagerTestInfoParms2, infoManagerTestPolicyPrams);
    ASSERT_NE(0, tokenIdEx.tokenIdExStruct.tokenID);
    ret = AccessTokenKit::GetHapTokenInfo(tokenIdEx.tokenIdExStruct.tokenID, hapTokenInfoRes);
    ASSERT_EQ(ret, RET_SUCCESS);
    ASSERT_EQ(hapTokenInfoRes.dlpType, DLP_READ);
    ASSERT_EQ(AccessTokenKit::GetHapDlpFlag(tokenIdEx.tokenIdExStruct.tokenID), 1);
    ret = AccessTokenKit::DeleteToken(tokenIdEx.tokenIdExStruct.tokenID);
    ASSERT_EQ(RET_SUCCESS, ret);
    ret = AccessTokenKit::GetHapTokenInfo(tokenIdEx.tokenIdExStruct.tokenID, hapTokenInfoRes);
    ASSERT_EQ(ret, RET_FAILED);

    tokenID = GetAccessTokenID(infoManagerTestInfoParms3.userID, infoManagerTestInfoParms3.bundleName, 2);
    if (tokenID != 0) {
        ret = AccessTokenKit::DeleteToken(tokenID);
    }
    tokenIdEx = AccessTokenKit::AllocHapToken(infoManagerTestInfoParms3, infoManagerTestPolicyPrams);
    ASSERT_NE(0, tokenIdEx.tokenIdExStruct.tokenID);
    ret = AccessTokenKit::GetHapTokenInfo(tokenIdEx.tokenIdExStruct.tokenID, hapTokenInfoRes);
    ASSERT_EQ(ret, RET_SUCCESS);
    ASSERT_EQ(hapTokenInfoRes.dlpType, DLP_FULL_CONTROL);
    ASSERT_EQ(AccessTokenKit::GetHapDlpFlag(tokenIdEx.tokenIdExStruct.tokenID), 1);
    ret = AccessTokenKit::DeleteToken(tokenIdEx.tokenIdExStruct.tokenID);
    ASSERT_EQ(RET_SUCCESS, ret);
    ret = AccessTokenKit::GetHapTokenInfo(tokenIdEx.tokenIdExStruct.tokenID, hapTokenInfoRes);
    ASSERT_EQ(ret, RET_FAILED);
}

/**
 * @tc.name: AllocHapToken019
 * @tc.desc: cannot alloc a tokenId with invaild dlptype.
 * @tc.type: FUNC
 * @tc.require: Issue Number
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
        .userID = 1,
        .bundleName = "accesstoken_test",
        .instIndex = 4,
        .dlpType = INVALID_DLP_TYPE,
        .appIDDesc = "testtesttesttest",
        .apiVersion = DEFAULT_API_VERSION
    };

    tokenIdEx = AccessTokenKit::AllocHapToken(infoManagerTestInfoParms1, infoManagerTestPolicyPrams);
    ASSERT_EQ(0, tokenIdEx.tokenIdExStruct.tokenID);
}

/**
 * @tc.name: UpdateHapToken001
 * @tc.desc: alloc a tokenId successfully, update it successfully and verify it.
 * @tc.type: FUNC
 * @tc.require: Issue Number
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

    int ret = AccessTokenKit::UpdateHapToken(tokenID, appIDDesc, DEFAULT_API_VERSION, g_infoManagerTestPolicyPrams);
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
 * @tc.require: Issue Number
 */
HWTEST_F(AccessTokenKitTest, UpdateHapToken002, TestSize.Level1)
{
    int ret = AccessTokenKit::UpdateHapToken(
        TEST_USER_ID_INVALID, "appIDDesc", DEFAULT_API_VERSION, g_infoManagerTestPolicyPrams);
    ASSERT_EQ(RET_FAILED, ret);
}

/**
 * @tc.name: UpdateHapToken003
 * @tc.desc: cannot update hap token info with invalid appIDDesc.
 * @tc.type: FUNC
 * @tc.require: Issue Number
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

    int ret = AccessTokenKit::UpdateHapToken(tokenID, appIDDesc, DEFAULT_API_VERSION, g_infoManagerTestPolicyPrams);
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
 * @tc.require: Issue Number
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

    int ret = AccessTokenKit::UpdateHapToken(tokenID, appIDDesc, DEFAULT_API_VERSION, g_infoManagerTestPolicyPrams);
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
 * @tc.require: Issue Number
 */
HWTEST_F(AccessTokenKitTest, UpdateHapToken005, TestSize.Level1)
{
    std::string backUpPermission;
    const std::string appIDDesc = g_infoManagerTestInfoParms.appIDDesc;
    PermissionDef permDefResult;

    DeleteTestToken();
    AccessTokenIDEx tokenIdEx = AccessTokenKit::AllocHapToken(g_infoManagerTestInfoParms, g_infoManagerTestPolicyPrams);
    AccessTokenID tokenID = tokenIdEx.tokenIdExStruct.tokenID;
    ASSERT_NE(INVALID_TOKENID, tokenID);

    std::string backup = g_infoManagerTestPolicyPrams.permList[0].permissionName;
    g_infoManagerTestPolicyPrams.permList[0].permissionName = "";
    int ret = AccessTokenKit::UpdateHapToken(tokenID, appIDDesc, DEFAULT_API_VERSION, g_infoManagerTestPolicyPrams);
    ret = AccessTokenKit::GetDefPermission(g_infoManagerTestPolicyPrams.permList[0].permissionName, permDefResult);
    ASSERT_EQ(AccessTokenError::ERR_PARAM_INVALID, ret);
    g_infoManagerTestPolicyPrams.permList[0].permissionName = backup;

    backUpPermission = g_infoManagerTestPolicyPrams.permList[0].permissionName;
    g_infoManagerTestPolicyPrams.permList[0].permissionName = "ohos.permission.testtmp11";
    backup = g_infoManagerTestPolicyPrams.permList[0].bundleName;
    g_infoManagerTestPolicyPrams.permList[0].bundleName = "";
    ret = AccessTokenKit::UpdateHapToken(tokenID, appIDDesc, DEFAULT_API_VERSION, g_infoManagerTestPolicyPrams);
    ret = AccessTokenKit::GetDefPermission(g_infoManagerTestPolicyPrams.permList[0].permissionName, permDefResult);
    ASSERT_EQ(AccessTokenError::ERR_PERMISSION_NOT_EXIT, ret);
    g_infoManagerTestPolicyPrams.permList[0].bundleName = backup;
    g_infoManagerTestPolicyPrams.permList[0].permissionName = backUpPermission;

    backUpPermission = g_infoManagerTestPolicyPrams.permList[0].permissionName;
    g_infoManagerTestPolicyPrams.permList[0].permissionName = "ohos.permission.testtmp12";
    backup = g_infoManagerTestPolicyPrams.permList[0].label;
    g_infoManagerTestPolicyPrams.permList[0].label = "";
    ret = AccessTokenKit::UpdateHapToken(tokenID, appIDDesc, DEFAULT_API_VERSION, g_infoManagerTestPolicyPrams);
    ASSERT_EQ(RET_SUCCESS, ret);
    ret = AccessTokenKit::GetDefPermission(g_infoManagerTestPolicyPrams.permList[0].permissionName, permDefResult);
    ASSERT_EQ(RET_SUCCESS, ret);
    g_infoManagerTestPolicyPrams.permList[0].label = backup;
    g_infoManagerTestPolicyPrams.permList[0].permissionName = backUpPermission;

    backUpPermission = g_infoManagerTestPolicyPrams.permList[0].permissionName;
    g_infoManagerTestPolicyPrams.permList[0].permissionName = "ohos.permission.testtmp13";
    backup = g_infoManagerTestPolicyPrams.permList[0].description;
    g_infoManagerTestPolicyPrams.permList[0].description = "";
    ret = AccessTokenKit::UpdateHapToken(tokenID, appIDDesc, DEFAULT_API_VERSION, g_infoManagerTestPolicyPrams);
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
 * @tc.require: Issue Number
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
    for (size_t i = 0; i < obj.size(); i++) {
        ret = AccessTokenKit::UpdateHapToken(obj[i], appIDDesc, DEFAULT_API_VERSION, g_infoManagerTestPolicyPrams);
        if (RET_SUCCESS != ret) {
            updateFlag = 1;
            break;
        }
    }
    g_infoManagerTestPolicyPrams.apl = APL_NORMAL;

    for (size_t i = 0; i < obj.size(); i++) {
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
 * @tc.require: Issue Number
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
    ASSERT_EQ(AccessTokenError::ERR_PERMISSION_NOT_EXIT, ret);

    backup = g_infoManagerTestPolicyPrams.permList[0].permissionName;
    g_infoManagerTestPolicyPrams.permList[0].permissionName = "ohos.permission.test3";
    ret = AccessTokenKit::UpdateHapToken(tokenID, appIDDesc, DEFAULT_API_VERSION, g_infoManagerTestPolicyPrams);
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
 * @tc.require: Issue Number
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
    ret = AccessTokenKit::UpdateHapToken(tokenID, appIDDesc, DEFAULT_API_VERSION, g_infoManagerTestPolicyPrams);
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
 * @tc.require: Issue Number
 */
HWTEST_F(AccessTokenKitTest, UpdateHapToken009, TestSize.Level1)
{
    int ret;
    std::vector<PermissionDef> permDefList;
    const std::string appIDDesc = g_infoManagerTestInfoParms.appIDDesc;
    PermissionDef infoManagerTestPermDef = g_infoManagerTestPermDef1;
    PermissionStateFull infoManagerTestState = {
        .permissionName = "ohos.permission.test1",
        .isGeneral = true,
        .resDeviceID = {"local"},
        .grantStatus = {3},
        .grantFlags = {PermissionState::PERMISSION_DENIED}
    };

    HapPolicyParams infoManagerTestPolicyPrams = {
        .apl = APL_NORMAL,
        .domain = "test.domain",
        .permList = {infoManagerTestPermDef},
        .permStateList = {infoManagerTestState}
    };

    DeleteTestToken();
    AccessTokenIDEx tokenIdEx = {0};
    tokenIdEx = AccessTokenKit::AllocHapToken(g_infoManagerTestInfoParms, g_infoManagerTestPolicyPrams);
    AccessTokenID tokenID = tokenIdEx.tokenIdExStruct.tokenID;
    GTEST_LOG_(INFO) << "tokenID :" << tokenID;

    ret = AccessTokenKit::VerifyAccessToken(tokenID, "ohos.permission.test1");
    ASSERT_EQ(ret, g_infoManagerTestState1.grantStatus[0]);

    ret = AccessTokenKit::UpdateHapToken(tokenID, appIDDesc, DEFAULT_API_VERSION, infoManagerTestPolicyPrams);

    ret = AccessTokenKit::VerifyAccessToken(tokenID, "ohos.permission.test1");
    ASSERT_EQ(ret, PermissionState::PERMISSION_DENIED);

    ret = AccessTokenKit::DeleteToken(tokenID);
    ASSERT_EQ(RET_SUCCESS, ret);
}

/**
 * @tc.name: UpdateHapToken010
 * @tc.desc: update api version.
 * @tc.type: FUNC
 * @tc.require:Issue Number
 */
HWTEST_F(AccessTokenKitTest, UpdateHapToken010, TestSize.Level1)
{
    AccessTokenIDEx tokenIdEx = {0};
    const std::string appIDDesc = g_infoManagerTestInfoParms.appIDDesc;
    tokenIdEx = AccessTokenKit::AllocHapToken(g_infoManagerTestInfoParms, g_infoManagerTestPolicyPrams);
    AccessTokenID tokenID = tokenIdEx.tokenIdExStruct.tokenID;
    GTEST_LOG_(INFO) << "tokenID :" << tokenID;

    int32_t apiVersion = DEFAULT_API_VERSION - 1;
    int ret = AccessTokenKit::UpdateHapToken(tokenID, appIDDesc, apiVersion, g_infoManagerTestPolicyPrams);

    HapTokenInfo hapTokenInfoRes;
    ret = AccessTokenKit::GetHapTokenInfo(tokenID, hapTokenInfoRes);
    ASSERT_EQ(apiVersion, hapTokenInfoRes.apiVersion);

    apiVersion = DEFAULT_API_VERSION + 1;
    ret = AccessTokenKit::UpdateHapToken(tokenID, appIDDesc, apiVersion, g_infoManagerTestPolicyPrams);

    ret = AccessTokenKit::GetHapTokenInfo(tokenID, hapTokenInfoRes);
    ASSERT_EQ(apiVersion, hapTokenInfoRes.apiVersion);
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
    return nullptr;
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
    return nullptr;
}

/**
 * @tc.name: AllocHapToken011
 * @tc.desc: Mulitpulthread test.
 * @tc.type: FUNC
 * @tc.require: Issue Number
 */
HWTEST_F(AccessTokenKitTest, Mulitpulthread001, TestSize.Level1)
{
    int ret;
    AccessTokenIDEx tokenIdEx = {0};
    tokenIdEx = AccessTokenKit::AllocHapToken(g_infoManagerTestInfoParms, g_infoManagerTestPolicyPrams);
    ASSERT_NE(0, tokenIdEx.tokenIdExStruct.tokenID);
    pthread_t tid[2];
    (void)pthread_create(&tid[0], 0, &ThreadTestFunc01, nullptr);
    (void)pthread_create(&tid[1], 0, &ThreadTestFunc01, nullptr);
    (void)pthread_join(tid[0], nullptr);
    (void)pthread_join(tid[1], nullptr);

    (void)pthread_create(&tid[0], 0, &ThreadTestFunc02, nullptr);
    (void)pthread_create(&tid[1], 0, &ThreadTestFunc02, nullptr);
    (void)pthread_join(tid[0], nullptr);
    (void)pthread_join(tid[1], nullptr);

    ret = AccessTokenKit::DeleteToken(tokenIdEx.tokenIdExStruct.tokenID);
    ASSERT_EQ(RET_SUCCESS, ret);
}

void ConcurrencyTask(unsigned int tokenID)
{
    int32_t flag;
    for (int i = 0; i < CYCLE_TIMES; i++) {
        AccessTokenKit::GrantPermission(tokenID, TEST_PERMISSION_NAME_ALPHA, PERMISSION_USER_FIXED);
        AccessTokenKit::GetPermissionFlag(tokenID, TEST_PERMISSION_NAME_ALPHA, flag);
        AccessTokenKit::VerifyAccessToken(tokenID, TEST_PERMISSION_NAME_ALPHA);

        AccessTokenKit::RevokePermission(tokenID, TEST_PERMISSION_NAME_ALPHA, PERMISSION_USER_SET);
        AccessTokenKit::GetPermissionFlag(tokenID, TEST_PERMISSION_NAME_ALPHA, flag);
        AccessTokenKit::VerifyAccessToken(tokenID, TEST_PERMISSION_NAME_ALPHA);
    }
}

/**
 * @tc.name: ConcurrencyTest001
 * @tc.desc: Concurrency testing
 * @tc.type: FUNC
 * @tc.require: Issue Number
 */
HWTEST_F(AccessTokenKitTest, ConcurrencyTest001, TestSize.Level1)
{
    AccessTokenID tokenID = GetAccessTokenID(TEST_USER_ID, TEST_BUNDLE_NAME, 0);
    ASSERT_NE(INVALID_TOKENID, tokenID);
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
 * @tc.require: Issue Number
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
 * @tc.require: Issue Number
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
 * @tc.require: Issue Number
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
 * @tc.require: Issue Number
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
 * @tc.require: Issue Number
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
 * @tc.require: Issue Number
 */
HWTEST_F(AccessTokenKitTest, GetSelfPermissionsState001, TestSize.Level1)
{
    AccessTokenID tokenID = GetAccessTokenID(TEST_USER_ID, TEST_BUNDLE_NAME, 0);
    ASSERT_NE(INVALID_TOKENID, tokenID);
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
    ASSERT_EQ(static_cast<uint32_t>(4), permsList1.size());
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
 * @tc.name: GetSelfPermissionsState002
 * @tc.desc: only vague location permission
 * @tc.type: FUNC
 * @tc.require: issueI5NOQI
 */
HWTEST_F(AccessTokenKitTest, GetSelfPermissionsState002, TestSize.Level1)
{
    std::vector<PermissionDef> permmissionDefs;
    permmissionDefs.emplace_back(g_locationTestDefVague);

    std::vector<PermissionStateFull> permissionStateFulls;
    permissionStateFulls.emplace_back(g_locationTestStateVague10); // {-1,0}

    AllocHapToken(permmissionDefs, permissionStateFulls, VAGUE_LOCATION_API_VERSION);

    AccessTokenID tokenID = GetAccessTokenID(TEST_USER_ID, "accesstoken_location_test", 0);
    ASSERT_NE(INVALID_TOKENID, tokenID);
    ASSERT_EQ(0, SetSelfTokenID(tokenID));

    PermissionListState permVague = {
        .permissionName = "ohos.permission.APPROXIMATELY_LOCATION",
        .state = -1,
    };

    std::vector<PermissionListState> permsList;
    permsList.emplace_back(permVague);

    PermissionOper ret = AccessTokenKit::GetSelfPermissionsState(permsList);
    ASSERT_EQ(DYNAMIC_OPER, ret);
    ASSERT_EQ(static_cast<uint32_t>(1), permsList.size());
    ASSERT_EQ(DYNAMIC_OPER, permsList[0].state);

    AccessTokenKit::DeleteToken(tokenID);
    SetSelfTokenID(selfTokenId_);
}

/**
 * @tc.name: GetSelfPermissionsState003
 * @tc.desc: only vague location permission after refuse
 * @tc.type: FUNC
 * @tc.require: issueI5NOQI
 */
HWTEST_F(AccessTokenKitTest, GetSelfPermissionsState003, TestSize.Level1)
{
    std::vector<PermissionDef> permmissionDefs;
    permmissionDefs.emplace_back(g_locationTestDefVague);

    std::vector<PermissionStateFull> permissionStateFulls;
    permissionStateFulls.emplace_back(g_locationTestStateVague12); // {-1,2}

    AllocHapToken(permmissionDefs, permissionStateFulls, VAGUE_LOCATION_API_VERSION);

    AccessTokenID tokenID = GetAccessTokenID(TEST_USER_ID, "accesstoken_location_test", 0);
    ASSERT_NE(INVALID_TOKENID, tokenID);
    ASSERT_EQ(0, SetSelfTokenID(tokenID));

    PermissionListState permVague = {
        .permissionName = "ohos.permission.APPROXIMATELY_LOCATION",
        .state = -1,
    };

    std::vector<PermissionListState> permsList;
    permsList.emplace_back(permVague);

    PermissionOper ret = AccessTokenKit::GetSelfPermissionsState(permsList);
    ASSERT_EQ(PASS_OPER, ret);
    ASSERT_EQ(static_cast<uint32_t>(1), permsList.size());
    ASSERT_EQ(SETTING_OPER, permsList[0].state);

    AccessTokenKit::DeleteToken(tokenID);
    SetSelfTokenID(selfTokenId_);
}

/**
 * @tc.name: GetSelfPermissionsState004
 * @tc.desc: only vague location permission after accept
 * @tc.type: FUNC
 * @tc.require: issueI5NOQI
 */
HWTEST_F(AccessTokenKitTest, GetSelfPermissionsState004, TestSize.Level1)
{
    std::vector<PermissionDef> permmissionDefs;
    permmissionDefs.emplace_back(g_locationTestDefVague);

    std::vector<PermissionStateFull> permissionStateFulls;
    permissionStateFulls.emplace_back(g_locationTestStateVague02); // {0,2}

    AllocHapToken(permmissionDefs, permissionStateFulls, VAGUE_LOCATION_API_VERSION);

    AccessTokenID tokenID = GetAccessTokenID(TEST_USER_ID, "accesstoken_location_test", 0);
    ASSERT_NE(INVALID_TOKENID, tokenID);
    ASSERT_EQ(0, SetSelfTokenID(tokenID));

    PermissionListState permVague = {
        .permissionName = "ohos.permission.APPROXIMATELY_LOCATION",
        .state = -1,
    };

    std::vector<PermissionListState> permsList;
    permsList.emplace_back(permVague);

    PermissionOper ret = AccessTokenKit::GetSelfPermissionsState(permsList);
    ASSERT_EQ(PASS_OPER, ret);
    ASSERT_EQ(static_cast<uint32_t>(1), permsList.size());
    ASSERT_EQ(PASS_OPER, permsList[0].state);

    AccessTokenKit::DeleteToken(tokenID);
    SetSelfTokenID(selfTokenId_);
}

/**
 * @tc.name: GetSelfPermissionsState005
 * @tc.desc: only accurate location permission
 * @tc.type: FUNC
 * @tc.require: issueI5NOQI
 */
HWTEST_F(AccessTokenKitTest, GetSelfPermissionsState005, TestSize.Level1)
{
    std::vector<PermissionDef> permmissionDefs;
    permmissionDefs.emplace_back(g_locationTestDefAccurate);

    std::vector<PermissionStateFull> permissionStateFulls;
    permissionStateFulls.emplace_back(g_locationTestStateAccurate10); // {-1,0}

    AllocHapToken(permmissionDefs, permissionStateFulls, VAGUE_LOCATION_API_VERSION);

    AccessTokenID tokenID = GetAccessTokenID(TEST_USER_ID, "accesstoken_location_test", 0);
    ASSERT_NE(INVALID_TOKENID, tokenID);
    ASSERT_EQ(0, SetSelfTokenID(tokenID));

    PermissionListState permAccurate = {
        .permissionName = "ohos.permission.LOCATION",
        .state = -1,
    };

    std::vector<PermissionListState> permsList;
    permsList.emplace_back(permAccurate);

    PermissionOper ret = AccessTokenKit::GetSelfPermissionsState(permsList);
    ASSERT_EQ(INVALID_OPER, ret);
    ASSERT_EQ(static_cast<uint32_t>(1), permsList.size());
    ASSERT_EQ(INVALID_OPER, permsList[0].state);

    AccessTokenKit::DeleteToken(tokenID);
    SetSelfTokenID(selfTokenId_);
}

/**
 * @tc.name: GetSelfPermissionsState006
 * @tc.desc: all location permissions
 * @tc.type: FUNC
 * @tc.require: issueI5NOQI
 */
HWTEST_F(AccessTokenKitTest, GetSelfPermissionsState006, TestSize.Level1)
{
    std::vector<PermissionDef> permmissionDefs;
    permmissionDefs.emplace_back(g_locationTestDefVague);
    permmissionDefs.emplace_back(g_locationTestDefAccurate);

    std::vector<PermissionStateFull> permissionStateFulls;
    permissionStateFulls.emplace_back(g_locationTestStateVague10); // {-1,0}
    permissionStateFulls.emplace_back(g_locationTestStateAccurate10); // {-1,0}

    AllocHapToken(permmissionDefs, permissionStateFulls, VAGUE_LOCATION_API_VERSION);

    AccessTokenID tokenID = GetAccessTokenID(TEST_USER_ID, "accesstoken_location_test", 0);
    ASSERT_NE(INVALID_TOKENID, tokenID);
    ASSERT_EQ(0, SetSelfTokenID(tokenID));

    PermissionListState permVague = {
        .permissionName = "ohos.permission.APPROXIMATELY_LOCATION",
        .state = -1,
    };
    PermissionListState permAccurate = {
        .permissionName = "ohos.permission.LOCATION",
        .state = -1,
    };

    std::vector<PermissionListState> permsList;
    permsList.emplace_back(permVague);
    permsList.emplace_back(permAccurate);

    PermissionOper ret = AccessTokenKit::GetSelfPermissionsState(permsList);
    ASSERT_EQ(DYNAMIC_OPER, ret);
    ASSERT_EQ(static_cast<uint32_t>(2), permsList.size());
    ASSERT_EQ(DYNAMIC_OPER, permsList[0].state);
    ASSERT_EQ(DYNAMIC_OPER, permsList[1].state);

    AccessTokenKit::DeleteToken(tokenID);
    SetSelfTokenID(selfTokenId_);
}

/**
 * @tc.name: GetSelfPermissionsState007
 * @tc.desc: all location permissions after accept vague location permission
 * @tc.type: FUNC
 * @tc.require: issueI5NOQI
 */
HWTEST_F(AccessTokenKitTest, GetSelfPermissionsState007, TestSize.Level1)
{
    std::vector<PermissionDef> permmissionDefs;
    permmissionDefs.emplace_back(g_locationTestDefVague);
    permmissionDefs.emplace_back(g_locationTestDefAccurate);

    std::vector<PermissionStateFull> permissionStateFulls;
    permissionStateFulls.emplace_back(g_locationTestStateVague02); // {0,2}
    permissionStateFulls.emplace_back(g_locationTestStateAccurate10); // {-1,0}

    AllocHapToken(permmissionDefs, permissionStateFulls, VAGUE_LOCATION_API_VERSION);

    AccessTokenID tokenID = GetAccessTokenID(TEST_USER_ID, "accesstoken_location_test", 0);
    ASSERT_NE(INVALID_TOKENID, tokenID);
    ASSERT_EQ(0, SetSelfTokenID(tokenID));

    PermissionListState permVague = {
        .permissionName = "ohos.permission.APPROXIMATELY_LOCATION",
        .state = -1,
    };
    PermissionListState permAccurate = {
        .permissionName = "ohos.permission.LOCATION",
        .state = -1,
    };

    std::vector<PermissionListState> permsList;
    permsList.emplace_back(permVague);
    permsList.emplace_back(permAccurate);

    PermissionOper ret = AccessTokenKit::GetSelfPermissionsState(permsList);
    ASSERT_EQ(DYNAMIC_OPER, ret);
    ASSERT_EQ(static_cast<uint32_t>(2), permsList.size());
    ASSERT_EQ(PASS_OPER, permsList[0].state);
    ASSERT_EQ(DYNAMIC_OPER, permsList[1].state);

    AccessTokenKit::DeleteToken(tokenID);
    SetSelfTokenID(selfTokenId_);
}

/**
 * @tc.name: GetSelfPermissionsState008
 * @tc.desc: all location permissions after refuse vague location permission
 * @tc.type: FUNC
 * @tc.require: issueI5NOQI
 */
HWTEST_F(AccessTokenKitTest, GetSelfPermissionsState008, TestSize.Level1)
{
    std::vector<PermissionDef> permmissionDefs;
    permmissionDefs.emplace_back(g_locationTestDefVague);
    permmissionDefs.emplace_back(g_locationTestDefAccurate);

    std::vector<PermissionStateFull> permissionStateFulls;
    permissionStateFulls.emplace_back(g_locationTestStateVague12); // {-1,2}
    permissionStateFulls.emplace_back(g_locationTestStateAccurate10); // {-1,0}

    AllocHapToken(permmissionDefs, permissionStateFulls, VAGUE_LOCATION_API_VERSION);

    AccessTokenID tokenID = GetAccessTokenID(TEST_USER_ID, "accesstoken_location_test", 0);
    ASSERT_NE(INVALID_TOKENID, tokenID);
    ASSERT_EQ(0, SetSelfTokenID(tokenID));

    PermissionListState permVague = {
        .permissionName = "ohos.permission.APPROXIMATELY_LOCATION",
        .state = -1,
    };
    PermissionListState permAccurate = {
        .permissionName = "ohos.permission.LOCATION",
        .state = -1,
    };

    std::vector<PermissionListState> permsList;
    permsList.emplace_back(permVague);
    permsList.emplace_back(permAccurate);

    PermissionOper ret = AccessTokenKit::GetSelfPermissionsState(permsList);
    ASSERT_EQ(PASS_OPER, ret);
    ASSERT_EQ(static_cast<uint32_t>(2), permsList.size());
    ASSERT_EQ(SETTING_OPER, permsList[0].state);
    ASSERT_EQ(SETTING_OPER, permsList[1].state);

    AccessTokenKit::DeleteToken(tokenID);
    SetSelfTokenID(selfTokenId_);
}

/**
 * @tc.name: GetSelfPermissionsState009
 * @tc.desc: all location permissions after accept all location permissions
 * @tc.type: FUNC
 * @tc.require: issueI5NOQI
 */
HWTEST_F(AccessTokenKitTest, GetSelfPermissionsState009, TestSize.Level1)
{
    std::vector<PermissionDef> permmissionDefs;
    permmissionDefs.emplace_back(g_locationTestDefVague);
    permmissionDefs.emplace_back(g_locationTestDefAccurate);

    std::vector<PermissionStateFull> permissionStateFulls;
    permissionStateFulls.emplace_back(g_locationTestStateVague02); // {0,2}
    permissionStateFulls.emplace_back(g_locationTestStateAccurate02); // {0,2}

    AllocHapToken(permmissionDefs, permissionStateFulls, VAGUE_LOCATION_API_VERSION);

    AccessTokenID tokenID = GetAccessTokenID(TEST_USER_ID, "accesstoken_location_test", 0);
    ASSERT_NE(INVALID_TOKENID, tokenID);
    ASSERT_EQ(0, SetSelfTokenID(tokenID));

    PermissionListState permVague = {
        .permissionName = "ohos.permission.APPROXIMATELY_LOCATION",
        .state = -1,
    };
    PermissionListState permAccurate = {
        .permissionName = "ohos.permission.LOCATION",
        .state = -1,
    };

    std::vector<PermissionListState> permsList;
    permsList.emplace_back(permVague);
    permsList.emplace_back(permAccurate);

    PermissionOper ret = AccessTokenKit::GetSelfPermissionsState(permsList);
    ASSERT_EQ(PASS_OPER, ret);
    ASSERT_EQ(static_cast<uint32_t>(2), permsList.size());
    ASSERT_EQ(PASS_OPER, permsList[0].state);
    ASSERT_EQ(PASS_OPER, permsList[1].state);

    AccessTokenKit::DeleteToken(tokenID);
    SetSelfTokenID(selfTokenId_);
}

/**
 * @tc.name: GetSelfPermissionsState010
 * @tc.desc: all location permissions whith other permissions
 * @tc.type: FUNC
 * @tc.require: issueI5NOQI
 */
HWTEST_F(AccessTokenKitTest, GetSelfPermissionsState010, TestSize.Level1)
{
    std::vector<PermissionDef> permmissionDefs;
    permmissionDefs.emplace_back(g_locationTestDefVague);
    permmissionDefs.emplace_back(g_locationTestDefAccurate);
    permmissionDefs.emplace_back(g_locationTestDefSystemGrant);
    permmissionDefs.emplace_back(g_locationTestDefUserGrant);

    std::vector<PermissionStateFull> permissionStateFulls;
    permissionStateFulls.emplace_back(g_locationTestStateVague10); // {-1,0}
    permissionStateFulls.emplace_back(g_locationTestStateAccurate10); // {-1,0}
    permissionStateFulls.emplace_back(g_locationTestStateSystemGrant); // {0,4}
    permissionStateFulls.emplace_back(g_locationTestStateUserGrant); // {-1,0}

    AllocHapToken(permmissionDefs, permissionStateFulls, VAGUE_LOCATION_API_VERSION);

    AccessTokenID tokenID = GetAccessTokenID(TEST_USER_ID, "accesstoken_location_test", 0);
    ASSERT_NE(INVALID_TOKENID, tokenID);
    ASSERT_EQ(0, SetSelfTokenID(tokenID));

    PermissionListState permVague = {
        .permissionName = "ohos.permission.APPROXIMATELY_LOCATION",
        .state = -1,
    };
    PermissionListState permAccurate = {
        .permissionName = "ohos.permission.LOCATION",
        .state = -1,
    };
    PermissionListState permSystem = {
        .permissionName = "ohos.permission.locationtest1",
        .state = -1,
    };
    PermissionListState permUser = {
        .permissionName = "ohos.permission.locationtest2",
        .state = -1,
    };

    std::vector<PermissionListState> permsList;
    permsList.emplace_back(permVague);
    permsList.emplace_back(permAccurate);
    permsList.emplace_back(permSystem);
    permsList.emplace_back(permUser);

    PermissionOper ret = AccessTokenKit::GetSelfPermissionsState(permsList);
    ASSERT_EQ(DYNAMIC_OPER, ret);
    ASSERT_EQ(static_cast<uint32_t>(4), permsList.size());
    ASSERT_EQ(DYNAMIC_OPER, permsList[0].state);
    ASSERT_EQ(DYNAMIC_OPER, permsList[1].state);
    ASSERT_EQ(PASS_OPER, permsList[2].state);
    ASSERT_EQ(DYNAMIC_OPER, permsList[3].state);

    AccessTokenKit::DeleteToken(tokenID);
    SetSelfTokenID(selfTokenId_);
}

/**
 * @tc.name: GetSelfPermissionsState011
 * @tc.desc: only accurate location permission whith api8
 * @tc.type: FUNC
 * @tc.require: issueI5NOQI
 */
HWTEST_F(AccessTokenKitTest, GetSelfPermissionsState011, TestSize.Level1)
{
    std::vector<PermissionDef> permmissionDefs;
    permmissionDefs.emplace_back(g_locationTestDefAccurate);

    std::vector<PermissionStateFull> permissionStateFulls;
    permissionStateFulls.emplace_back(g_locationTestStateAccurate10); // {-1,0}

    AllocHapToken(permmissionDefs, permissionStateFulls, DEFAULT_API_VERSION);

    AccessTokenID tokenID = GetAccessTokenID(TEST_USER_ID, "accesstoken_location_test", 0);
    ASSERT_NE(INVALID_TOKENID, tokenID);
    ASSERT_EQ(0, SetSelfTokenID(tokenID));

    PermissionListState permAccurate = {
        .permissionName = "ohos.permission.LOCATION",
        .state = -1,
    };

    std::vector<PermissionListState> permsList;
    permsList.emplace_back(permAccurate);

    PermissionOper ret = AccessTokenKit::GetSelfPermissionsState(permsList);
    ASSERT_EQ(DYNAMIC_OPER, ret);
    ASSERT_EQ(static_cast<uint32_t>(1), permsList.size());
    ASSERT_EQ(DYNAMIC_OPER, permsList[0].state);

    AccessTokenKit::DeleteToken(tokenID);
    SetSelfTokenID(selfTokenId_);
}

/**
 * @tc.name: GetSelfPermissionsState012
 * @tc.desc: all location permissions with api8
 * @tc.type: FUNC
 * @tc.require: issueI5NOQI
 */
HWTEST_F(AccessTokenKitTest, GetSelfPermissionsState012, TestSize.Level1)
{
    std::vector<PermissionDef> permmissionDefs;
    permmissionDefs.emplace_back(g_locationTestDefVague);
    permmissionDefs.emplace_back(g_locationTestDefAccurate);

    std::vector<PermissionStateFull> permissionStateFulls;
    permissionStateFulls.emplace_back(g_locationTestStateVague10); // {-1,0}
    permissionStateFulls.emplace_back(g_locationTestStateAccurate10); // {-1,0}

    AllocHapToken(permmissionDefs, permissionStateFulls, DEFAULT_API_VERSION);

    AccessTokenID tokenID = GetAccessTokenID(TEST_USER_ID, "accesstoken_location_test", 0);
    ASSERT_NE(INVALID_TOKENID, tokenID);
    ASSERT_EQ(0, SetSelfTokenID(tokenID));

    PermissionListState permVague = {
        .permissionName = "ohos.permission.APPROXIMATELY_LOCATION",
        .state = -1,
    };
    PermissionListState permAccurate = {
        .permissionName = "ohos.permission.LOCATION",
        .state = -1,
    };

    std::vector<PermissionListState> permsList;
    permsList.emplace_back(permVague);
    permsList.emplace_back(permAccurate);

    PermissionOper ret = AccessTokenKit::GetSelfPermissionsState(permsList);
    ASSERT_EQ(DYNAMIC_OPER, ret);
    ASSERT_EQ(static_cast<uint32_t>(2), permsList.size());
    ASSERT_EQ(INVALID_OPER, permsList[0].state);
    ASSERT_EQ(DYNAMIC_OPER, permsList[1].state);

    AccessTokenKit::DeleteToken(tokenID);
    SetSelfTokenID(selfTokenId_);
}

/**
 * @tc.name: GetSelfPermissionsState013
 * @tc.desc: permission list is empty or oversize
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(AccessTokenKitTest, GetSelfPermissionsState013, TestSize.Level1)
{
    std::vector<PermissionListState> permsList;
    ASSERT_EQ(PASS_OPER, AccessTokenKit::GetSelfPermissionsState(permsList));

    for (uint32_t i = 0; i < MAX_PERMISSION_SIZE + 1; i++) {
        PermissionListState tmp = {
            .permissionName = "ohos.permission.CAMERA",
            .state = 0
        };
        permsList.emplace_back(tmp);
    }
    ASSERT_EQ(INVALID_OPER, AccessTokenKit::GetSelfPermissionsState(permsList));
}

/**
 * @tc.name: GetSelfPermissionsState014
 * @tc.desc: test token id is native
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(AccessTokenKitTest, GetSelfPermissionsState014, TestSize.Level1)
{
    AccessTokenID tokenId = AccessTokenKit::GetNativeTokenId("hdcd");
    SetSelfTokenID(tokenId);
    std::vector<PermissionListState> permsList;
    PermissionListState tmp = {
        .permissionName = "ohos.permission.CAMERA",
        .state = 0
    };
    permsList.emplace_back(tmp);
    ASSERT_EQ(INVALID_OPER, AccessTokenKit::GetSelfPermissionsState(permsList));
}

/**
 * @tc.name: GetSelfPermissionsState015
 * @tc.desc: test noexist token id
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(AccessTokenKitTest, GetSelfPermissionsState015, TestSize.Level1)
{
    AccessTokenID tokenId = AccessTokenKit::GetHapTokenID(TEST_USER_ID, TEST_BUNDLE_NAME, 0);
    SetSelfTokenID(tokenId);
    ASSERT_EQ(RET_SUCCESS, AccessTokenKit::DeleteToken(tokenId));
    std::vector<PermissionListState> permsList;
    PermissionListState tmp = {
        .permissionName = "ohos.permission.CAMERA",
        .state = 0
    };
    permsList.emplace_back(tmp);
    ASSERT_EQ(INVALID_OPER, AccessTokenKit::GetSelfPermissionsState(permsList));
}

/**
 * @tc.name: GetTokenTypeFlag003
 * @tc.desc: Get token type with hap tokenID.
 * @tc.type: FUNC
 * @tc.require: Issue Number
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

/**
 * @tc.name: DumpTokenInfo001
 * @tc.desc: Get dump token information with invalid tokenID
 * @tc.type: FUNC
 * @tc.require:Issue Number
 */
HWTEST_F(AccessTokenKitTest, DumpTokenInfo001, TestSize.Level1)
{
    std::string info;
    AccessTokenKit::DumpTokenInfo(123, info);
    ASSERT_EQ("invalid tokenId", info);
}

class CbCustomizeTest : public PermStateChangeCallbackCustomize {
public:
    explicit CbCustomizeTest(const PermStateChangeScope &scopeInfo)
        : PermStateChangeCallbackCustomize(scopeInfo)
    {
    }

    ~CbCustomizeTest()
    {}

    virtual void PermStateChangeCallback(PermStateChangeInfo& result)
    {
        ready_ = true;
    }

    bool ready_;
};

/**
 * @tc.name: RegisterPermStateChangeCallback001
 * @tc.desc: RegisterPermStateChangeCallback permList
 * @tc.type: FUNC
 * @tc.require: issueI5NT1X
 */
HWTEST_F(AccessTokenKitTest, RegisterPermStateChangeCallback001, TestSize.Level1)
{
    PermStateChangeScope scopeInfo;
    scopeInfo.permList = {"ohos.permission.CAMERA"};
    scopeInfo.tokenIDs = {};
    auto callbackPtr = std::make_shared<CbCustomizeTest>(scopeInfo);
    callbackPtr->ready_ = false;

    int32_t res = AccessTokenKit::RegisterPermStateChangeCallback(callbackPtr);
    ASSERT_EQ(RET_SUCCESS, res);

    static PermissionStateFull infoManagerTestStateA = {
        .permissionName = "ohos.permission.CAMERA",
        .isGeneral = true,
        .resDeviceID = {"local"},
        .grantStatus = {PERMISSION_DENIED},
        .grantFlags = {1}
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
    ASSERT_NE(INVALID_TOKENID, tokenID);

    ATokenTypeEnum ret = AccessTokenKit::GetTokenTypeFlag(tokenID);
    ASSERT_EQ(ret, TOKEN_HAP);

    res = AccessTokenKit::VerifyAccessToken(tokenID, "ohos.permission.CAMERA");
    ASSERT_EQ(PERMISSION_DENIED, res);

    res = AccessTokenKit::GrantPermission(tokenID, "ohos.permission.CAMERA", 2);
    ASSERT_EQ(RET_SUCCESS, res);

    res = AccessTokenKit::VerifyAccessToken(tokenID, "ohos.permission.CAMERA");
    ASSERT_EQ(PERMISSION_GRANTED, res);

    EXPECT_EQ(true, callbackPtr->ready_);

    callbackPtr->ready_ = false;

    res = AccessTokenKit::RevokePermission(tokenID, "ohos.permission.CAMERA", 2);
    ASSERT_EQ(RET_SUCCESS, res);

    EXPECT_EQ(true, callbackPtr->ready_);

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
 * @tc.require: issueI5NT1X
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
        .isGeneral = true,
        .resDeviceID = {"local"},
        .grantStatus = {PERMISSION_GRANTED},
        .grantFlags = {1}
    };
    static PermissionStateFull infoManagerTestStateB = {
        .permissionName = "ohos.permission.CAMERA",
        .isGeneral = true,
        .resDeviceID = {"local"},
        .grantStatus = {PERMISSION_GRANTED},
        .grantFlags = {1}
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

    EXPECT_EQ(false, callbackPtr->ready_);

    res = AccessTokenKit::DeleteToken(tokenID);
    ASSERT_EQ(RET_SUCCESS, res);

    res = AccessTokenKit::UnRegisterPermStateChangeCallback(callbackPtr);
    ASSERT_EQ(RET_SUCCESS, res);
}

/**
 * @tc.name: RegisterPermStateChangeCallback003
 * @tc.desc: RegisterPermStateChangeCallback permList
 * @tc.type: FUNC
 * @tc.require: issueI5NT1X
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
        .isGeneral = true,
        .resDeviceID = {"local"},
        .grantStatus = {PERMISSION_DENIED},
        .grantFlags = {1}
    };
    static PermissionStateFull infoManagerTestStateB = {
        .permissionName = "ohos.permission.CAMERA",
        .isGeneral = true,
        .resDeviceID = {"local"},
        .grantStatus = {PERMISSION_DENIED},
        .grantFlags = {1}
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
    EXPECT_EQ(true, callbackPtr->ready_);

    callbackPtr->ready_ = false;
    res = AccessTokenKit::VerifyAccessToken(tokenID, "ohos.permission.GET_BUNDLE_INFO");
    ASSERT_EQ(PERMISSION_DENIED, res);
    res = AccessTokenKit::GrantPermission(tokenID, "ohos.permission.GET_BUNDLE_INFO", 2);
    ASSERT_EQ(RET_SUCCESS, res);

    EXPECT_EQ(true, callbackPtr->ready_);

    res = AccessTokenKit::DeleteToken(tokenID);
    ASSERT_EQ(RET_SUCCESS, res);

    res = AccessTokenKit::UnRegisterPermStateChangeCallback(callbackPtr);
    ASSERT_EQ(RET_SUCCESS, res);
}

/**
 * @tc.name: RegisterPermStateChangeCallback004
 * @tc.desc: RegisterPermStateChangeCallback with invalid tokenId
 * @tc.type: FUNC
 * @tc.require: issueI5NT1X
 */
HWTEST_F(AccessTokenKitTest, RegisterPermStateChangeCallback004, TestSize.Level1)
{
    PermStateChangeScope scopeInfo;
    scopeInfo.permList = {"ohos.permission.GET_BUNDLE_INFO", "ohos.permission.CAMERA"};
    scopeInfo.tokenIDs = {555555}; // 555555为模拟的tokenid
    auto callbackPtr = std::make_shared<CbCustomizeTest>(scopeInfo);
    callbackPtr->ready_ = false;

    int32_t res = AccessTokenKit::RegisterPermStateChangeCallback(callbackPtr);
    ASSERT_EQ(AccessTokenError::ERR_PARAM_INVALID, res);

    static PermissionStateFull infoManagerTestStateA = {
        .permissionName = "ohos.permission.GET_BUNDLE_INFO",
        .isGeneral = true,
        .resDeviceID = {"local"},
        .grantStatus = {PERMISSION_GRANTED},
        .grantFlags = {1},
    };
    static PermissionStateFull infoManagerTestStateB = {
        .permissionName = "ohos.permission.CAMERA",
        .isGeneral = true,
        .resDeviceID = {"local"},
        .grantStatus = {PERMISSION_GRANTED},
        .grantFlags = {1}
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
    EXPECT_EQ(false, callbackPtr->ready_);

    callbackPtr->ready_ = false;
    res = AccessTokenKit::VerifyAccessToken(tokenID, "ohos.permission.GET_BUNDLE_INFO");
    ASSERT_EQ(PERMISSION_GRANTED, res);
    res = AccessTokenKit::RevokePermission(tokenID, "ohos.permission.GET_BUNDLE_INFO", 2);
    ASSERT_EQ(RET_SUCCESS, res);

    EXPECT_EQ(false, callbackPtr->ready_);

    res = AccessTokenKit::DeleteToken(tokenID);
    ASSERT_EQ(RET_SUCCESS, res);
}

/**
 * @tc.name: RegisterPermStateChangeCallback005
 * @tc.desc: RegisterPermStateChangeCallback permList
 * @tc.type: FUNC
 * @tc.require: issueI5NT1X
 */
HWTEST_F(AccessTokenKitTest, RegisterPermStateChangeCallback005, TestSize.Level1)
{
    static PermissionStateFull infoManagerTestStateA = {
        .permissionName = "ohos.permission.CAMERA",
        .isGeneral = true,
        .resDeviceID = {"local"},
        .grantStatus = {PERMISSION_DENIED},
        .grantFlags = {1}
    };
    static PermissionStateFull infoManagerTestStateB = {
        .permissionName = "ohos.permission.GET_BUNDLE_INFO",
        .isGeneral = true,
        .resDeviceID = {"local"},
        .grantStatus = {PERMISSION_GRANTED},
        .grantFlags = {1}
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
    EXPECT_EQ(true, callbackPtr->ready_);

    callbackPtr->ready_ = false;
    res = AccessTokenKit::VerifyAccessToken(tokenID, "ohos.permission.GET_BUNDLE_INFO");
    ASSERT_EQ(PERMISSION_GRANTED, res);
    res = AccessTokenKit::GrantPermission(tokenID, "ohos.permission.GET_BUNDLE_INFO", 2);
    ASSERT_EQ(RET_SUCCESS, res);

    EXPECT_EQ(false, callbackPtr->ready_);

    res = AccessTokenKit::DeleteToken(tokenID);
    ASSERT_EQ(RET_SUCCESS, res);

    res = AccessTokenKit::UnRegisterPermStateChangeCallback(callbackPtr);
    ASSERT_EQ(RET_SUCCESS, res);
}

/**
 * @tc.name: RegisterPermStateChangeCallback006
 * @tc.desc: RegisterPermStateChangeCallback with invaild permission
 * @tc.type: FUNC
 * @tc.require: issueI5NT1X
 */
HWTEST_F(AccessTokenKitTest, RegisterPermStateChangeCallback006, TestSize.Level1)
{
    PermStateChangeScope scopeInfo;
    scopeInfo.permList = {"ohos.permission.INVALID"};
    scopeInfo.tokenIDs = {};
    auto callbackPtr1 = std::make_shared<CbCustomizeTest>(scopeInfo);
    int32_t res = AccessTokenKit::RegisterPermStateChangeCallback(callbackPtr1);
    ASSERT_EQ(AccessTokenError::ERR_PARAM_INVALID, res);

    static PermissionStateFull infoManagerTestStateA = {
        .permissionName = "ohos.permission.CAMERA",
        .isGeneral = true,
        .resDeviceID = {"local"},
        .grantStatus = {PERMISSION_DENIED},
        .grantFlags = {1}
    };
    static HapPolicyParams infoManagerTestPolicyPrams = {
        .apl = APL_SYSTEM_BASIC,
        .domain = "test.domain",
        .permList = {},
        .permStateList = {infoManagerTestStateA}
    };

    AccessTokenIDEx tokenIdEx = {0};
    tokenIdEx = AccessTokenKit::AllocHapToken(g_infoManagerTestInfoParms, infoManagerTestPolicyPrams);

    scopeInfo.tokenIDs = {tokenIdEx.tokenIdExStruct.tokenID};
    scopeInfo.permList = {"ohos.permission.INVALID", "ohos.permission.CAMERA"};
    auto callbackPtr = std::make_shared<CbCustomizeTest>(scopeInfo);
    res = AccessTokenKit::RegisterPermStateChangeCallback(callbackPtr);
    ASSERT_EQ(RET_SUCCESS, res);

    res = AccessTokenKit::GrantPermission(tokenIdEx.tokenIdExStruct.tokenID, "ohos.permission.CAMERA", 2);
    ASSERT_EQ(RET_SUCCESS, res);
    EXPECT_EQ(true, callbackPtr->ready_);

    res = AccessTokenKit::DeleteToken(tokenIdEx.tokenIdExStruct.tokenID);
    ASSERT_EQ(RET_SUCCESS, res);

    res = AccessTokenKit::UnRegisterPermStateChangeCallback(callbackPtr);
    ASSERT_EQ(RET_SUCCESS, res);
}

/**
 * @tc.name: RegisterPermStateChangeCallback007
 * @tc.desc: RegisterPermStateChangeCallback with permList, whose size is 1024/1025
 * @tc.type: FUNC
 * @tc.require: issueI5NT1X
 */
HWTEST_F(AccessTokenKitTest, RegisterPermStateChangeCallback007, TestSize.Level1)
{
    PermStateChangeScope scopeInfo;
    scopeInfo.permList = {};
    scopeInfo.tokenIDs = {};
    for (int32_t i = 1; i <= 1025; i++) { // 1025 is a invalid size
        scopeInfo.permList.emplace_back("ohos.permission.GET_BUNDLE_INFO");
        if (i == 1025) { // 1025 is a invalid size
            auto callbackPtr = std::make_shared<CbCustomizeTest>(scopeInfo);
            int32_t res = AccessTokenKit::RegisterPermStateChangeCallback(callbackPtr);
            ASSERT_EQ(AccessTokenError::ERR_PARAM_INVALID, res);
            break;
        }
        auto callbackPtr = std::make_shared<CbCustomizeTest>(scopeInfo);
        int32_t res = AccessTokenKit::RegisterPermStateChangeCallback(callbackPtr);
        ASSERT_EQ(RET_SUCCESS, res);
        res = AccessTokenKit::UnRegisterPermStateChangeCallback(callbackPtr);
        ASSERT_EQ(RET_SUCCESS, res);
    }
}

/**
 * @tc.name: RegisterPermStateChangeCallback008
 * @tc.desc: RegisterPermStateChangeCallback with tokenList, whose size is 1024/1025
 * @tc.type: FUNC
 * @tc.require: issueI5NT1X
 */
HWTEST_F(AccessTokenKitTest, RegisterPermStateChangeCallback008, TestSize.Level1)
{
    PermStateChangeScope scopeInfo;
    scopeInfo.permList = {};
    scopeInfo.tokenIDs = {};
    auto callbackPtr = std::make_shared<CbCustomizeTest>(scopeInfo);
    callbackPtr->ready_ = false;

    static HapPolicyParams infoManagerTestPolicyPrams = {
        .apl = APL_NORMAL,
        .domain = "test.domain",
        .permList = {},
        .permStateList = {}
    };

    AccessTokenIDEx tokenIdEx = {0};
    tokenIdEx = AccessTokenKit::AllocHapToken(g_infoManagerTestInfoParms, infoManagerTestPolicyPrams);

    for (int32_t i = 1; i <= 1025; i++) { // 1025 is a invalid size
        scopeInfo.tokenIDs.emplace_back(tokenIdEx.tokenIdExStruct.tokenID);
        if (i == 1025) { // 1025 is a invalid size
            auto callbackPtr = std::make_shared<CbCustomizeTest>(scopeInfo);
            int32_t res = AccessTokenKit::RegisterPermStateChangeCallback(callbackPtr);
            ASSERT_EQ(AccessTokenError::ERR_PARAM_INVALID, res);
            break;
        }
        auto callbackPtr = std::make_shared<CbCustomizeTest>(scopeInfo);
        int32_t res = AccessTokenKit::RegisterPermStateChangeCallback(callbackPtr);
        ASSERT_EQ(RET_SUCCESS, res);
        res = AccessTokenKit::UnRegisterPermStateChangeCallback(callbackPtr);
        ASSERT_EQ(RET_SUCCESS, res);
    }

    int32_t res = AccessTokenKit::DeleteToken(tokenIdEx.tokenIdExStruct.tokenID);
    ASSERT_EQ(RET_SUCCESS, res);
}

/**
 * @tc.name: RegisterPermStateChangeCallback009
 * @tc.desc: RegisterPermStateChangeCallback
 * @tc.type: FUNC
 * @tc.require: issueI5NT1X
 */
HWTEST_F(AccessTokenKitTest, RegisterPermStateChangeCallback009, TestSize.Level1)
{
    PermStateChangeScope scopeInfo;
    scopeInfo.permList = {};
    scopeInfo.tokenIDs = {};
    std::vector<std::shared_ptr<CbCustomizeTest>> callbackList;

    for (int32_t i = 0; i < 200; i++) { // 200 is the max size
        if (i == 200) { // 200 is the max size
            auto callbackPtr = std::make_shared<CbCustomizeTest>(scopeInfo);
            int32_t res = AccessTokenKit::RegisterPermStateChangeCallback(callbackPtr);
            ASSERT_EQ(AccessTokenError::ERR_EXCEEDED_MAXNUM_REGISTRATION_LIMIT, res);
            break;
        }
        auto callbackPtr = std::make_shared<CbCustomizeTest>(scopeInfo);
        int32_t res = AccessTokenKit::RegisterPermStateChangeCallback(callbackPtr);
        ASSERT_EQ(RET_SUCCESS, res);
        callbackList.emplace_back(callbackPtr);
    }
    for (int32_t i = 0; i < 200; i++) { // release 200 callback
        auto callbackPtr = callbackList[i];
        int32_t res = AccessTokenKit::UnRegisterPermStateChangeCallback(callbackPtr);
        ASSERT_EQ(RET_SUCCESS, res);
    }
    callbackList.clear();
}

/**
 * @tc.name: RegisterPermStateChangeCallback010
 * @tc.desc: RegisterPermStateChangeCallback with nullptr
 * @tc.type: FUNC
 * @tc.require: issueI5NT1X
 */
HWTEST_F(AccessTokenKitTest, RegisterPermStateChangeCallback010, TestSize.Level1)
{
    int32_t res = AccessTokenKit::RegisterPermStateChangeCallback(nullptr);
    ASSERT_EQ(AccessTokenError::ERR_PARAM_INVALID, res);
}

/**
 * @tc.name: UnRegisterPermStateChangeCallback001
 * @tc.desc: UnRegisterPermStateChangeCallback with invalid input.
 * @tc.type: FUNC
 * @tc.require: issueI5NT1X
 */
HWTEST_F(AccessTokenKitTest, UnRegisterPermStateChangeCallback001, TestSize.Level1)
{
    PermStateChangeScope scopeInfo;
    scopeInfo.permList = {};
    scopeInfo.tokenIDs = {};
    auto callbackPtr = std::make_shared<CbCustomizeTest>(scopeInfo);
    callbackPtr->ready_ = false;

    int32_t res = AccessTokenKit::UnRegisterPermStateChangeCallback(callbackPtr);
    ASSERT_EQ(AccessTokenError::ERR_INTERFACE_NOT_USED_TOGETHER, res);
}

/**
 * @tc.name: UnRegisterPermStateChangeCallback002
 * @tc.desc: UnRegisterPermStateChangeCallback repeatedly.
 * @tc.type: FUNC
 * @tc.require: issueI5NT1X
 */
HWTEST_F(AccessTokenKitTest, UnRegisterPermStateChangeCallback002, TestSize.Level1)
{
    PermStateChangeScope scopeInfo;
    scopeInfo.permList = {};
    scopeInfo.tokenIDs = {};
    auto callbackPtr = std::make_shared<CbCustomizeTest>(scopeInfo);
    callbackPtr->ready_ = false;

    int32_t res = AccessTokenKit::RegisterPermStateChangeCallback(callbackPtr);
    ASSERT_EQ(RET_SUCCESS, res);
    res = AccessTokenKit::RegisterPermStateChangeCallback(callbackPtr);
    ASSERT_EQ(AccessTokenError::ERR_PARAM_INVALID, res);
    res = AccessTokenKit::UnRegisterPermStateChangeCallback(callbackPtr);
    ASSERT_EQ(RET_SUCCESS, res);
    res = AccessTokenKit::UnRegisterPermStateChangeCallback(callbackPtr);
    ASSERT_EQ(AccessTokenError::ERR_INTERFACE_NOT_USED_TOGETHER, res);
}

/**
 * @tc.name: GetVersion001
 * @tc.desc: GetVersion001 test.
 * @tc.type: FUNC
 * @tc.require: issueI5NT1X
 */
HWTEST_F(AccessTokenKitTest, GetVersion001, TestSize.Level1)
{
    int32_t res = AccessTokenKit::GetVersion();
    ASSERT_EQ(DEFAULT_TOKEN_VERSION, res);
}

/**
 * @tc.name: PermStateChangeCallback001
 * @tc.desc: PermissionStateChangeCallback::PermStateChangeCallback function test.
 * @tc.type: FUNC
 * @tc.require: issueI61NS6
 */
HWTEST_F(AccessTokenKitTest, PermStateChangeCallback001, TestSize.Level1)
{
    PermStateChangeInfo result = {
        .PermStateChangeType = 0,
        .tokenID = 123,
        .permissionName = "ohos.permission.CAMERA"
    };

    std::shared_ptr<CbCustomizeTest> callbackPtr = nullptr;
    std::shared_ptr<PermissionStateChangeCallback> callback = std::make_shared<PermissionStateChangeCallback>(
        callbackPtr);
    callback->PermStateChangeCallback(result);
}

class TestCallBack : public PermissionStateChangeCallbackStub {
public:
    TestCallBack() = default;
    virtual ~TestCallBack() = default;

    void PermStateChangeCallback(PermStateChangeInfo& result)
    {
        GTEST_LOG_(INFO) << "PermStateChangeCallback,  tokenID is " << result.tokenID;
    }
};

/**
 * @tc.name: OnRemoteRequest001
 * @tc.desc: StateChangeCallbackStub::OnRemoteRequest function test
 * @tc.type: FUNC
 * @tc.require: issueI61A6M
 */
HWTEST_F(AccessTokenKitTest, OnRemoteRequest001, TestSize.Level1)
{
    PermStateChangeInfo info = {
        .PermStateChangeType = 0,
        .tokenID = 123,
        .permissionName = "ohos.permission.CAMERA"
    };

    TestCallBack callback;
    PermissionStateChangeInfoParcel infoParcel;
    infoParcel.changeInfo = info;

    OHOS::MessageParcel data;
    std::string descriptor = "I don't know";
    data.WriteInterfaceToken(OHOS::Str8ToStr16(descriptor));
    ASSERT_EQ(true, data.WriteParcelable(&infoParcel));

    OHOS::MessageParcel reply;
    OHOS::MessageOption option(OHOS::MessageOption::TF_SYNC);
    ASSERT_NE(0, callback.OnRemoteRequest(static_cast<uint32_t>(IPermissionStateCallback::PERMISSION_STATE_CHANGE),
        data, reply, option)); // descriptor false

    ASSERT_EQ(true, data.WriteInterfaceToken(IPermissionStateCallback::GetDescriptor()));
    ASSERT_EQ(true, data.WriteParcelable(&infoParcel));
    uint32_t code = 10;
    ASSERT_NE(0, callback.OnRemoteRequest(code, data, reply, option)); // descriptor true + msgCode false
}

/**
 * @tc.name: CreatePermStateChangeCallback001
 * @tc.desc: AccessTokenManagerClient::CreatePermStateChangeCallback function test
 * @tc.type: FUNC
 * @tc.require: issueI61A6M
 */
HWTEST_F(AccessTokenKitTest, CreatePermStateChangeCallback001, TestSize.Level1)
{
    std::vector<std::shared_ptr<CbCustomizeTest>> callbackList;

    uint32_t times = 201;
    for (uint32_t i = 0; i < times; i++) {
        PermStateChangeScope scopeInfo;
        scopeInfo.permList = {};
        scopeInfo.tokenIDs = {};
        auto callbackPtr = std::make_shared<CbCustomizeTest>(scopeInfo);
        callbackList.emplace_back(callbackPtr);
        int32_t res = AccessTokenKit::RegisterPermStateChangeCallback(callbackPtr);

        if (i == 200) {
            EXPECT_EQ(AccessTokenError::ERR_EXCEEDED_MAXNUM_REGISTRATION_LIMIT, res);
            break;
        }
    }

    for (uint32_t i = 0; i < 200; i++) {
        ASSERT_EQ(0, AccessTokenKit::UnRegisterPermStateChangeCallback(callbackList[i]));
    }

    std::shared_ptr<PermStateChangeCallbackCustomize> customizedCb = nullptr;
    AccessTokenKit::RegisterPermStateChangeCallback(customizedCb); // customizedCb is null
}

/**
 * @tc.name: InitProxy001
 * @tc.desc: AccessTokenManagerClient::InitProxy function test
 * @tc.type: FUNC
 * @tc.require: issueI61A6M
 */
HWTEST_F(AccessTokenKitTest, InitProxy001, TestSize.Level1)
{
    ASSERT_NE(nullptr, AccessTokenManagerClient::GetInstance().proxy_);
    OHOS::sptr<IAccessTokenManager> proxy = AccessTokenManagerClient::GetInstance().proxy_; // backup
    AccessTokenManagerClient::GetInstance().proxy_ = nullptr;
    ASSERT_EQ(nullptr, AccessTokenManagerClient::GetInstance().proxy_);
    AccessTokenManagerClient::GetInstance().InitProxy(); // proxy_ is null
    AccessTokenManagerClient::GetInstance().proxy_ = proxy; // recovery
}

/**
 * @tc.name: AllocHapToken020
 * @tc.desc: AccessTokenKit::AllocHapToken function test
 * @tc.type: FUNC
 * @tc.require: issueI61A6M
 */
HWTEST_F(AccessTokenKitTest, AllocHapToken020, TestSize.Level1)
{
    HapInfoParams info;
    HapPolicyParams policy;
    info.userID = -1;
    AccessTokenKit::AllocHapToken(info, policy);
    ASSERT_EQ(-1, info.userID);
}

/**
 * @tc.name: UpdateHapToken011
 * @tc.desc: AccessTokenKit::UpdateHapToken function test
 * @tc.type: FUNC
 * @tc.require: issueI61A6M
 */
HWTEST_F(AccessTokenKitTest, UpdateHapToken011, TestSize.Level1)
{
    AccessTokenID tokenID = 0;
    std::string appIDDesc;
    int32_t apiVersion = 0;
    HapPolicyParams policy;
    ASSERT_EQ(RET_FAILED, AccessTokenKit::UpdateHapToken(tokenID, appIDDesc, apiVersion, policy));
}

/**
 * @tc.name: VerifyAccessToken005
 * @tc.desc: AccessTokenKit::VerifyAccessToken function test
 * @tc.type: FUNC
 * @tc.require: issueI61A6M
 */
HWTEST_F(AccessTokenKitTest, VerifyAccessToken005, TestSize.Level1)
{
    AccessTokenID callerTokenID = AccessTokenKit::GetHapTokenID(100, "com.ohos.photos", 0); // tokenId for photo app
    ASSERT_NE(INVALID_TOKENID, callerTokenID);
    AccessTokenID firstTokenID;
    std::string permissionName;

    // ret = PERMISSION_GRANTED + firstTokenID = 0
    permissionName = "ohos.permission.READ_MEDIA";
    firstTokenID = 0;
    ASSERT_EQ(PermissionState::PERMISSION_GRANTED, AccessTokenKit::VerifyAccessToken(
        callerTokenID, firstTokenID, permissionName));

    firstTokenID = 1;
    // ret = PERMISSION_GRANTED + firstTokenID != 0
    ASSERT_EQ(PermissionState::PERMISSION_DENIED, AccessTokenKit::VerifyAccessToken(
        callerTokenID, firstTokenID, permissionName));

    callerTokenID = 0;
    // ret = PERMISSION_GRANTED
    ASSERT_EQ(PermissionState::PERMISSION_DENIED, AccessTokenKit::VerifyAccessToken(
        callerTokenID, firstTokenID, permissionName));
}
} // namespace AccessToken
} // namespace Security
} // namespace OHOS
