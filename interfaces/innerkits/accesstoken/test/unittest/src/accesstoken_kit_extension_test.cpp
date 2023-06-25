/*
 * Copyright (c) 2023 Huawei Device Co., Ltd.
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

#include "accesstoken_kit_extension_test.h"
#include <thread>

#include "access_token_error.h"
#include "accesstoken_log.h"
#include "accesstoken_service_ipc_interface_code.h"
#include "native_token_info_for_sync_parcel.h"
#include "nativetoken_kit.h"
#include "permission_state_change_info_parcel.h"
#include "softbus_bus_center.h"
#include "string_ex.h"
#include "tokenid_kit.h"
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
static constexpr int32_t DEFAULT_API_VERSION = 8;
static constexpr int32_t VAGUE_LOCATION_API_VERSION = 9;
static const std::string TEST_BUNDLE_NAME = "ohos";
static const std::string TEST_PERMISSION_NAME_ALPHA = "ohos.permission.ALPHA";
static const std::string TEST_PERMISSION_NAME_BETA = "ohos.permission.BETA";
static const int TEST_USER_ID = 0;
static constexpr OHOS::HiviewDFX::HiLogLabel LABEL = {LOG_CORE,
    SECURITY_DOMAIN_ACCESSTOKEN, "AccessTokenKitExtensionTest"};

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

PermissionStateFull g_getPermissionReq = {
    .permissionName = "ohos.permission.GET_SENSITIVE_PERMISSIONS",
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

HapInfoParams g_infoManagerTestNormalInfoParms = {
    .userID = 1,
    .bundleName = "accesstoken_test",
    .instIndex = 0,
    .appIDDesc = "testtesttesttest",
    .apiVersion = DEFAULT_API_VERSION,
    .isSystemApp = false
};

HapInfoParams g_infoManagerTestSystemInfoParms = {
    .userID = 1,
    .bundleName = "accesstoken_test",
    .instIndex = 0,
    .appIDDesc = "testtesttesttest",
    .apiVersion = DEFAULT_API_VERSION,
    .isSystemApp = true
};
}

void GetNativeToken()
{
    uint64_t tokenId;
    const char **perms = new const char *[4];
    perms[0] = "ohos.permission.DISTRIBUTED_DATASYNC";
    perms[1] = "ohos.permission.GRANT_SENSITIVE_PERMISSIONS";
    perms[2] = "ohos.permission.REVOKE_SENSITIVE_PERMISSIONS"; // 2 means the second permission
    perms[3] = "ohos.permission.GET_SENSITIVE_PERMISSIONS"; // 3 means the third permission

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
    EXPECT_EQ(0, SetSelfTokenID(tokenId));
    AccessTokenKit::ReloadNativeTokenInfo();
    delete[] perms;
}

void AccessTokenKitExtensionTest::SetUpTestCase()
{
    // make test case clean
    AccessTokenID tokenID = AccessTokenKit::GetHapTokenID(g_infoManagerTestInfoParms.userID,
        g_infoManagerTestInfoParms.bundleName,
        g_infoManagerTestInfoParms.instIndex);
    AccessTokenKit::DeleteToken(tokenID);

    tokenID = AccessTokenKit::GetHapTokenID(g_infoManagerTestNormalInfoParms.userID,
        g_infoManagerTestNormalInfoParms.bundleName,
        g_infoManagerTestNormalInfoParms.instIndex);
    AccessTokenKit::DeleteToken(tokenID);

    tokenID = AccessTokenKit::GetHapTokenID(g_infoManagerTestSystemInfoParms.userID,
        g_infoManagerTestSystemInfoParms.bundleName,
        g_infoManagerTestSystemInfoParms.instIndex);
    AccessTokenKit::DeleteToken(tokenID);

    tokenID = AccessTokenKit::GetHapTokenID(TEST_USER_ID, TEST_BUNDLE_NAME, 0);
    AccessTokenKit::DeleteToken(tokenID);

    GetNativeToken();
}

void AccessTokenKitExtensionTest::TearDownTestCase()
{
}

void PreparePermStateList(HapPolicyParams &policy)
{
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
    policy.permStateList.emplace_back(permTestState1);
    policy.permStateList.emplace_back(permTestState2);
    policy.permStateList.emplace_back(permTestState3);
    policy.permStateList.emplace_back(permTestState4);
}

void PreparePermDefList(HapPolicyParams &policy)
{
    PermissionDef permissionDefAlpha;
    permissionDefAlpha.permissionName = TEST_PERMISSION_NAME_ALPHA;
    permissionDefAlpha.bundleName = TEST_BUNDLE_NAME;
    permissionDefAlpha.grantMode = GrantMode::USER_GRANT;
    permissionDefAlpha.availableLevel = APL_NORMAL;
    permissionDefAlpha.provisionEnable = false;
    permissionDefAlpha.distributedSceneEnable = false;

    PermissionDef permissionDefBeta;
    permissionDefBeta.permissionName = TEST_PERMISSION_NAME_BETA;
    permissionDefBeta.bundleName = TEST_BUNDLE_NAME;
    permissionDefBeta.grantMode = GrantMode::SYSTEM_GRANT;
    permissionDefBeta.availableLevel = APL_NORMAL;
    permissionDefBeta.provisionEnable = false;
    permissionDefBeta.distributedSceneEnable = false;

    PermissionDef testPermDef1;
    testPermDef1.permissionName = "ohos.permission.testPermDef1";
    testPermDef1.bundleName = TEST_BUNDLE_NAME;
    testPermDef1.grantMode = GrantMode::USER_GRANT;
    testPermDef1.availableLevel = APL_NORMAL;
    testPermDef1.provisionEnable = false;
    testPermDef1.distributedSceneEnable = false;

    PermissionDef testPermDef2;
    testPermDef2.permissionName = "ohos.permission.testPermDef2";
    testPermDef2.bundleName = TEST_BUNDLE_NAME;
    testPermDef2.grantMode = GrantMode::USER_GRANT;
    testPermDef2.availableLevel = APL_NORMAL;
    testPermDef2.provisionEnable = false;
    testPermDef2.distributedSceneEnable = false;

    PermissionDef testPermDef3;
    testPermDef3.permissionName = "ohos.permission.testPermDef3";
    testPermDef3.bundleName = TEST_BUNDLE_NAME;
    testPermDef3.grantMode = GrantMode::USER_GRANT;
    testPermDef3.availableLevel = APL_NORMAL;
    testPermDef3.provisionEnable = false;
    testPermDef3.distributedSceneEnable = false;

    PermissionDef testPermDef4;
    testPermDef4.permissionName = "ohos.permission.testPermDef4";
    testPermDef4.bundleName = TEST_BUNDLE_NAME;
    testPermDef4.grantMode = GrantMode::USER_GRANT;
    testPermDef4.availableLevel = APL_NORMAL;
    testPermDef4.provisionEnable = false;
    testPermDef4.distributedSceneEnable = false;

    policy.permList.emplace_back(permissionDefAlpha);
    policy.permList.emplace_back(permissionDefBeta);
    policy.permList.emplace_back(testPermDef1);
    policy.permList.emplace_back(testPermDef2);
    policy.permList.emplace_back(testPermDef3);
    policy.permList.emplace_back(testPermDef4);
}

void AccessTokenKitExtensionTest::SetUp()
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
    PreparePermDefList(policy);
    PreparePermStateList(policy);
    policy.permStateList.emplace_back(g_grantPermissionReq);
    policy.permStateList.emplace_back(g_revokePermissionReq);
    AccessTokenKit::AllocHapToken(info, policy);
    AccessTokenID tokenID = AccessTokenKit::GetHapTokenID(g_infoManagerTestInfoParms.userID,
                                                          g_infoManagerTestInfoParms.bundleName,
                                                          g_infoManagerTestInfoParms.instIndex);
    AccessTokenKit::DeleteToken(tokenID);
    ACCESSTOKEN_LOG_INFO(LABEL, "SetUp ok.");
}

void AccessTokenKitExtensionTest::TearDown()
{
    AccessTokenID tokenID = GetAccessTokenID(TEST_USER_ID, TEST_BUNDLE_NAME, 0);
    AccessTokenKit::DeleteToken(tokenID);
    tokenID = AccessTokenKit::GetHapTokenID(g_infoManagerTestNormalInfoParms.userID,
                                            g_infoManagerTestNormalInfoParms.bundleName,
                                            g_infoManagerTestNormalInfoParms.instIndex);
    AccessTokenKit::DeleteToken(tokenID);

    tokenID = AccessTokenKit::GetHapTokenID(g_infoManagerTestSystemInfoParms.userID,
                                            g_infoManagerTestSystemInfoParms.bundleName,
                                            g_infoManagerTestSystemInfoParms.instIndex);
    AccessTokenKit::DeleteToken(tokenID);
    EXPECT_EQ(0, SetSelfTokenID(selfTokenId_));
}

void AccessTokenKitExtensionTest::AllocHapToken(std::vector<PermissionDef>& permissionDefs,
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

    for (auto& permissionDef:permissionDefs) {
        policy.permList.emplace_back(permissionDef);
    }

    for (auto& permissionStateFull:permissionStateFulls) {
        policy.permStateList.emplace_back(permissionStateFull);
    }

    AccessTokenKit::AllocHapToken(info, policy);
}

unsigned int AccessTokenKitExtensionTest::GetAccessTokenID(int userID, std::string bundleName, int instIndex)
{
    return AccessTokenKit::GetHapTokenID(userID, bundleName, instIndex);
}

void GetPermsList1(std::vector<PermissionListState> &permsList1)
{
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
    permsList1.emplace_back(perm1);
    permsList1.emplace_back(perm2);
    permsList1.emplace_back(perm3);
    permsList1.emplace_back(perm4);
}

void GetPermsList2(std::vector<PermissionListState> &permsList2)
{
    PermissionListState perm3 = {
        .permissionName = "ohos.permission.testPermDef3",
        .state = -1,
    };
    PermissionListState perm4 = {
        .permissionName = "ohos.permission.testPermDef4",
        .state = -1,
    };
    permsList2.emplace_back(perm3);
    permsList2.emplace_back(perm4);
}
/**
 * @tc.name: GetSelfPermissionsState001
 * @tc.desc: get permission list state
 * @tc.type: FUNC
 * @tc.require: Issue Number
 */
HWTEST_F(AccessTokenKitExtensionTest, GetSelfPermissionsState001, TestSize.Level1)
{
    AccessTokenID tokenID = GetAccessTokenID(TEST_USER_ID, TEST_BUNDLE_NAME, 0);
    ASSERT_NE(INVALID_TOKENID, tokenID);
    ASSERT_EQ(0, SetSelfTokenID(tokenID));

    std::vector<PermissionListState> permsList1;
    GetPermsList1(permsList1);
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
    GetPermsList2(permsList2);
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
HWTEST_F(AccessTokenKitExtensionTest, GetSelfPermissionsState002, TestSize.Level1)
{
    std::vector<PermissionDef> permissionDefs;
    permissionDefs.emplace_back(g_locationTestDefVague);

    std::vector<PermissionStateFull> permissionStateFulls;
    permissionStateFulls.emplace_back(g_locationTestStateVague10); // {-1,0}

    AllocHapToken(permissionDefs, permissionStateFulls, VAGUE_LOCATION_API_VERSION);

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
    EXPECT_EQ(0, SetSelfTokenID(selfTokenId_));
}

/**
 * @tc.name: GetSelfPermissionsState003
 * @tc.desc: only vague location permission after refuse
 * @tc.type: FUNC
 * @tc.require: issueI5NOQI
 */
HWTEST_F(AccessTokenKitExtensionTest, GetSelfPermissionsState003, TestSize.Level1)
{
    std::vector<PermissionDef> permissionDefs;
    permissionDefs.emplace_back(g_locationTestDefVague);

    std::vector<PermissionStateFull> permissionStateFulls;
    permissionStateFulls.emplace_back(g_locationTestStateVague12); // {-1,2}

    AllocHapToken(permissionDefs, permissionStateFulls, VAGUE_LOCATION_API_VERSION);

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
    EXPECT_EQ(0, SetSelfTokenID(selfTokenId_));
}

/**
 * @tc.name: GetSelfPermissionsState004
 * @tc.desc: only vague location permission after accept
 * @tc.type: FUNC
 * @tc.require: issueI5NOQI
 */
HWTEST_F(AccessTokenKitExtensionTest, GetSelfPermissionsState004, TestSize.Level1)
{
    std::vector<PermissionDef> permissionDefs;
    permissionDefs.emplace_back(g_locationTestDefVague);

    std::vector<PermissionStateFull> permissionStateFulls;
    permissionStateFulls.emplace_back(g_locationTestStateVague02); // {0,2}

    AllocHapToken(permissionDefs, permissionStateFulls, VAGUE_LOCATION_API_VERSION);

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
    EXPECT_EQ(0, SetSelfTokenID(selfTokenId_));
}

/**
 * @tc.name: GetSelfPermissionsState005
 * @tc.desc: only accurate location permission
 * @tc.type: FUNC
 * @tc.require: issueI5NOQI
 */
HWTEST_F(AccessTokenKitExtensionTest, GetSelfPermissionsState005, TestSize.Level1)
{
    std::vector<PermissionDef> permissionDefs;
    permissionDefs.emplace_back(g_locationTestDefAccurate);

    std::vector<PermissionStateFull> permissionStateFulls;
    permissionStateFulls.emplace_back(g_locationTestStateAccurate10); // {-1,0}

    AllocHapToken(permissionDefs, permissionStateFulls, VAGUE_LOCATION_API_VERSION);

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
    EXPECT_EQ(0, SetSelfTokenID(selfTokenId_));
}

/**
 * @tc.name: GetSelfPermissionsState006
 * @tc.desc: all location permissions
 * @tc.type: FUNC
 * @tc.require: issueI5NOQI
 */
HWTEST_F(AccessTokenKitExtensionTest, GetSelfPermissionsState006, TestSize.Level1)
{
    std::vector<PermissionDef> permissionDefs;
    permissionDefs.emplace_back(g_locationTestDefVague);
    permissionDefs.emplace_back(g_locationTestDefAccurate);

    std::vector<PermissionStateFull> permissionStateFulls;
    permissionStateFulls.emplace_back(g_locationTestStateVague10); // {-1,0}
    permissionStateFulls.emplace_back(g_locationTestStateAccurate10); // {-1,0}

    AllocHapToken(permissionDefs, permissionStateFulls, VAGUE_LOCATION_API_VERSION);

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
    EXPECT_EQ(0, SetSelfTokenID(selfTokenId_));
}

/**
 * @tc.name: GetSelfPermissionsState007
 * @tc.desc: all location permissions after accept vague location permission
 * @tc.type: FUNC
 * @tc.require: issueI5NOQI
 */
HWTEST_F(AccessTokenKitExtensionTest, GetSelfPermissionsState007, TestSize.Level1)
{
    std::vector<PermissionDef> permissionDefs;
    permissionDefs.emplace_back(g_locationTestDefVague);
    permissionDefs.emplace_back(g_locationTestDefAccurate);

    std::vector<PermissionStateFull> permissionStateFulls;
    permissionStateFulls.emplace_back(g_locationTestStateVague02); // {0,2}
    permissionStateFulls.emplace_back(g_locationTestStateAccurate10); // {-1,0}

    AllocHapToken(permissionDefs, permissionStateFulls, VAGUE_LOCATION_API_VERSION);

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
    EXPECT_EQ(0, SetSelfTokenID(selfTokenId_));
}

/**
 * @tc.name: GetSelfPermissionsState008
 * @tc.desc: all location permissions after refuse vague location permission
 * @tc.type: FUNC
 * @tc.require: issueI5NOQI
 */
HWTEST_F(AccessTokenKitExtensionTest, GetSelfPermissionsState008, TestSize.Level1)
{
    std::vector<PermissionDef> permissionDefs;
    permissionDefs.emplace_back(g_locationTestDefVague);
    permissionDefs.emplace_back(g_locationTestDefAccurate);

    std::vector<PermissionStateFull> permissionStateFulls;
    permissionStateFulls.emplace_back(g_locationTestStateVague12); // {-1,2}
    permissionStateFulls.emplace_back(g_locationTestStateAccurate10); // {-1,0}

    AllocHapToken(permissionDefs, permissionStateFulls, VAGUE_LOCATION_API_VERSION);

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
    EXPECT_EQ(0, SetSelfTokenID(selfTokenId_));
}

/**
 * @tc.name: GetSelfPermissionsState009
 * @tc.desc: all location permissions after accept all location permissions
 * @tc.type: FUNC
 * @tc.require: issueI5NOQI
 */
HWTEST_F(AccessTokenKitExtensionTest, GetSelfPermissionsState009, TestSize.Level1)
{
    std::vector<PermissionDef> permissionDefs;
    permissionDefs.emplace_back(g_locationTestDefVague);
    permissionDefs.emplace_back(g_locationTestDefAccurate);

    std::vector<PermissionStateFull> permissionStateFulls;
    permissionStateFulls.emplace_back(g_locationTestStateVague02); // {0,2}
    permissionStateFulls.emplace_back(g_locationTestStateAccurate02); // {0,2}

    AllocHapToken(permissionDefs, permissionStateFulls, VAGUE_LOCATION_API_VERSION);

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
    EXPECT_EQ(0, SetSelfTokenID(selfTokenId_));
}

/**
 * @tc.name: GetSelfPermissionsState010
 * @tc.desc: all location permissions whith other permissions
 * @tc.type: FUNC
 * @tc.require: issueI5NOQI
 */
HWTEST_F(AccessTokenKitExtensionTest, GetSelfPermissionsState010, TestSize.Level1)
{
    std::vector<PermissionDef> permissionDefs;
    permissionDefs.emplace_back(g_locationTestDefVague);
    permissionDefs.emplace_back(g_locationTestDefAccurate);
    permissionDefs.emplace_back(g_locationTestDefSystemGrant);
    permissionDefs.emplace_back(g_locationTestDefUserGrant);

    std::vector<PermissionStateFull> permissionStateFulls;
    permissionStateFulls.emplace_back(g_locationTestStateVague10); // {-1,0}
    permissionStateFulls.emplace_back(g_locationTestStateAccurate10); // {-1,0}
    permissionStateFulls.emplace_back(g_locationTestStateSystemGrant); // {0,4}
    permissionStateFulls.emplace_back(g_locationTestStateUserGrant); // {-1,0}

    AllocHapToken(permissionDefs, permissionStateFulls, VAGUE_LOCATION_API_VERSION);

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
    EXPECT_EQ(0, SetSelfTokenID(selfTokenId_));
}

/**
 * @tc.name: GetSelfPermissionsState011
 * @tc.desc: only accurate location permission whith api8
 * @tc.type: FUNC
 * @tc.require: issueI5NOQI
 */
HWTEST_F(AccessTokenKitExtensionTest, GetSelfPermissionsState011, TestSize.Level1)
{
    std::vector<PermissionDef> permissionDefs;
    permissionDefs.emplace_back(g_locationTestDefAccurate);

    std::vector<PermissionStateFull> permissionStateFulls;
    permissionStateFulls.emplace_back(g_locationTestStateAccurate10); // {-1,0}

    AllocHapToken(permissionDefs, permissionStateFulls, DEFAULT_API_VERSION);

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
    EXPECT_EQ(0, SetSelfTokenID(selfTokenId_));
}

/**
 * @tc.name: GetSelfPermissionsState012
 * @tc.desc: all location permissions with api8
 * @tc.type: FUNC
 * @tc.require: issueI5NOQI
 */
HWTEST_F(AccessTokenKitExtensionTest, GetSelfPermissionsState012, TestSize.Level1)
{
    std::vector<PermissionDef> permissionDefs;
    permissionDefs.emplace_back(g_locationTestDefVague);
    permissionDefs.emplace_back(g_locationTestDefAccurate);

    std::vector<PermissionStateFull> permissionStateFulls;
    permissionStateFulls.emplace_back(g_locationTestStateVague10); // {-1,0}
    permissionStateFulls.emplace_back(g_locationTestStateAccurate10); // {-1,0}

    AllocHapToken(permissionDefs, permissionStateFulls, DEFAULT_API_VERSION);

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
    EXPECT_EQ(0, SetSelfTokenID(selfTokenId_));
}

/**
 * @tc.name: GetSelfPermissionsState013
 * @tc.desc: permission list is empty or oversize
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(AccessTokenKitExtensionTest, GetSelfPermissionsState013, TestSize.Level1)
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
HWTEST_F(AccessTokenKitExtensionTest, GetSelfPermissionsState014, TestSize.Level1)
{
    AccessTokenID tokenId = AccessTokenKit::GetNativeTokenId("hdcd");
    EXPECT_EQ(0, SetSelfTokenID(tokenId));
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
HWTEST_F(AccessTokenKitExtensionTest, GetSelfPermissionsState015, TestSize.Level1)
{
    AccessTokenID tokenId = AccessTokenKit::GetHapTokenID(TEST_USER_ID, TEST_BUNDLE_NAME, 0);
    EXPECT_EQ(0, SetSelfTokenID(tokenId));
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
HWTEST_F(AccessTokenKitExtensionTest, GetTokenTypeFlag003, TestSize.Level1)
{
    AccessTokenIDEx tokenIdEx = {0};
    tokenIdEx = AccessTokenKit::AllocHapToken(g_infoManagerTestInfoParms, g_infoManagerTestPolicyPrams);
    ASSERT_NE(INVALID_TOKENID, tokenIdEx.tokenIdExStruct.tokenID);

    ATokenTypeEnum ret = AccessTokenKit::GetTokenTypeFlag(tokenIdEx.tokenIdExStruct.tokenID);
    ASSERT_EQ(ret, TOKEN_HAP);

    int res = AccessTokenKit::DeleteToken(tokenIdEx.tokenIdExStruct.tokenID);
    ASSERT_EQ(RET_SUCCESS, res);
}

/**
 * @tc.name: GetPermissionFlag006
 * @tc.desc: Get permission flag after grant permission.
 * @tc.type: FUNC
 * @tc.require: Issue Number
 */
HWTEST_F(AccessTokenKitExtensionTest, GetPermissionFlag006, TestSize.Level1)
{
    AccessTokenID tokenID = GetAccessTokenID(TEST_USER_ID, TEST_BUNDLE_NAME, 0);
    ASSERT_NE(INVALID_TOKENID, tokenID);
    int ret = AccessTokenKit::RevokePermission(tokenID, TEST_PERMISSION_NAME_ALPHA, PERMISSION_POLICY_FIXED);
    ASSERT_EQ(RET_SUCCESS, ret);

    int32_t flag;
    ret = AccessTokenKit::GetPermissionFlag(tokenID, TEST_PERMISSION_NAME_ALPHA, flag);
    ASSERT_EQ(PERMISSION_POLICY_FIXED, flag);
    ASSERT_EQ(RET_SUCCESS, ret);
}

/**
 * @tc.name: DumpTokenInfo001
 * @tc.desc: Get dump token information with invalid tokenID
 * @tc.type: FUNC
 * @tc.require:Issue Number
 */
HWTEST_F(AccessTokenKitExtensionTest, DumpTokenInfo001, TestSize.Level1)
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
HWTEST_F(AccessTokenKitExtensionTest, RegisterPermStateChangeCallback001, TestSize.Level1)
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

    AccessTokenIDEx tokenIdEx = AccessTokenKit::AllocHapToken(g_infoManagerTestInfoParms, infoManagerTestPolicyPrams);
    AccessTokenID tokenID = tokenIdEx.tokenIdExStruct.tokenID;
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
HWTEST_F(AccessTokenKitExtensionTest, RegisterPermStateChangeCallback002, TestSize.Level1)
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
HWTEST_F(AccessTokenKitExtensionTest, RegisterPermStateChangeCallback003, TestSize.Level1)
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
HWTEST_F(AccessTokenKitExtensionTest, RegisterPermStateChangeCallback004, TestSize.Level1)
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
HWTEST_F(AccessTokenKitExtensionTest, RegisterPermStateChangeCallback005, TestSize.Level1)
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
HWTEST_F(AccessTokenKitExtensionTest, RegisterPermStateChangeCallback006, TestSize.Level1)
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
HWTEST_F(AccessTokenKitExtensionTest, RegisterPermStateChangeCallback007, TestSize.Level1)
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
HWTEST_F(AccessTokenKitExtensionTest, RegisterPermStateChangeCallback008, TestSize.Level1)
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
HWTEST_F(AccessTokenKitExtensionTest, RegisterPermStateChangeCallback009, TestSize.Level1)
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
HWTEST_F(AccessTokenKitExtensionTest, RegisterPermStateChangeCallback010, TestSize.Level1)
{
    int32_t res = AccessTokenKit::RegisterPermStateChangeCallback(nullptr);
    ASSERT_EQ(AccessTokenError::ERR_PARAM_INVALID, res);
}

/**
 * @tc.name: RegisterPermStateChangeCallback011
 * @tc.desc: RegisterPermStateChangeCallback caller is normal app.
 * @tc.type: FUNC
 * @tc.require: issueI66BH3
 */
HWTEST_F(AccessTokenKitExtensionTest, RegisterPermStateChangeCallback011, TestSize.Level0)
{
    AccessTokenIDEx tokenIdEx = {0};
    tokenIdEx = AccessTokenKit::AllocHapToken(g_infoManagerTestNormalInfoParms, g_infoManagerTestPolicyPrams);
    ASSERT_NE(INVALID_TOKENID, tokenIdEx.tokenIDEx);
    EXPECT_EQ(0, SetSelfTokenID(tokenIdEx.tokenIDEx));

    PermStateChangeScope scopeInfo;
    scopeInfo.permList = {"ohos.permission.CAMERA"};
    scopeInfo.tokenIDs = {};
    auto callbackPtr = std::make_shared<CbCustomizeTest>(scopeInfo);
    callbackPtr->ready_ = false;

    int32_t res = AccessTokenKit::RegisterPermStateChangeCallback(callbackPtr);
    ASSERT_EQ(ERR_NOT_SYSTEM_APP, res);
}

/**
 * @tc.name: RegisterPermStateChangeCallback012
 * @tc.desc: RegisterPermStateChangeCallback caller is system app.
 * @tc.type: FUNC
 * @tc.require: issueI66BH3
 */
HWTEST_F(AccessTokenKitExtensionTest, RegisterPermStateChangeCallback012, TestSize.Level0)
{
    static HapPolicyParams policyPrams = {
        .apl = APL_SYSTEM_CORE,
        .domain = "test.domain",
    };
    policyPrams.permStateList.emplace_back(g_getPermissionReq);
    AccessTokenIDEx tokenIdEx = {0};
    tokenIdEx = AccessTokenKit::AllocHapToken(g_infoManagerTestSystemInfoParms, policyPrams);
    ASSERT_NE(INVALID_TOKENID, tokenIdEx.tokenIDEx);
    EXPECT_EQ(0, SetSelfTokenID(tokenIdEx.tokenIDEx));

    PermStateChangeScope scopeInfo;
    scopeInfo.permList = {"ohos.permission.CAMERA"};
    scopeInfo.tokenIDs = {};
    auto callbackPtr = std::make_shared<CbCustomizeTest>(scopeInfo);
    callbackPtr->ready_ = false;

    int32_t res = AccessTokenKit::RegisterPermStateChangeCallback(callbackPtr);
    ASSERT_EQ(RET_SUCCESS, res);
    res = AccessTokenKit::UnRegisterPermStateChangeCallback(callbackPtr);
    ASSERT_EQ(RET_SUCCESS, res);
}

/**
 * @tc.name: RegisterPermStateChangeCallback013
 * @tc.desc: ClearUserGrantedPermissionState notify.
 * @tc.type: FUNC
 * @tc.require: issueI5NT1X
 */
HWTEST_F(AccessTokenKitExtensionTest, RegisterPermStateChangeCallback013, TestSize.Level1)
{
    PermStateChangeScope scopeInfo;
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
    scopeInfo.permList = {"ohos.permission.CAMERA"};
    auto callbackPtr = std::make_shared<CbCustomizeTest>(scopeInfo);
    int32_t res = AccessTokenKit::RegisterPermStateChangeCallback(callbackPtr);
    ASSERT_EQ(RET_SUCCESS, res);

    res = AccessTokenKit::GrantPermission(tokenIdEx.tokenIdExStruct.tokenID, "ohos.permission.CAMERA", 2);
    EXPECT_EQ(RET_SUCCESS, res);
    EXPECT_EQ(true, callbackPtr->ready_);

    callbackPtr->ready_ = false;
    res = AccessTokenKit::ClearUserGrantedPermissionState(tokenIdEx.tokenIdExStruct.tokenID);
    EXPECT_EQ(RET_SUCCESS, res);
    EXPECT_EQ(true, callbackPtr->ready_);

    callbackPtr->ready_ = false;
    res = AccessTokenKit::GrantPermission(tokenIdEx.tokenIdExStruct.tokenID, "ohos.permission.CAMERA", 2);
    EXPECT_EQ(RET_SUCCESS, res);
    EXPECT_EQ(true, callbackPtr->ready_);

    callbackPtr->ready_ = false;
    res = AccessTokenKit::DeleteToken(tokenIdEx.tokenIdExStruct.tokenID);
    EXPECT_EQ(RET_SUCCESS, res);
    EXPECT_EQ(true, callbackPtr->ready_);

    res = AccessTokenKit::UnRegisterPermStateChangeCallback(callbackPtr);
    ASSERT_EQ(RET_SUCCESS, res);
}

/**
 * @tc.name: RegisterPermStateChangeCallback014
 * @tc.desc: ClearUserGrantedPermissionState notify.
 * @tc.type: FUNC
 * @tc.require: issueI5NT1X
 */
HWTEST_F(AccessTokenKitExtensionTest, RegisterPermStateChangeCallback014, TestSize.Level1)
{
    PermStateChangeScope scopeInfo;
    static PermissionStateFull infoManagerTestStateA = {
        .permissionName = "ohos.permission.READ_MEDIA",
        .isGeneral = true,
        .resDeviceID = {"local"},
        .grantStatus = {PERMISSION_DENIED},
        .grantFlags = {1}
    };
    static HapPolicyParams infoManagerTestPolicyPrams = {
        .apl = APL_SYSTEM_BASIC,
        .domain = "testA.domain",
        .permList = {},
        .permStateList = {infoManagerTestStateA}
    };

    AccessTokenIDEx tokenIdEx = {0};
    tokenIdEx = AccessTokenKit::AllocHapToken(g_infoManagerTestInfoParms, infoManagerTestPolicyPrams);

    scopeInfo.tokenIDs = {tokenIdEx.tokenIdExStruct.tokenID};
    scopeInfo.permList = {"ohos.permission.READ_MEDIA"};
    auto callbackPtr = std::make_shared<CbCustomizeTest>(scopeInfo);
    int32_t res = AccessTokenKit::RegisterPermStateChangeCallback(callbackPtr);
    ASSERT_EQ(RET_SUCCESS, res);

    res = AccessTokenKit::GrantPermission(tokenIdEx.tokenIdExStruct.tokenID,
        "ohos.permission.READ_MEDIA", PERMISSION_SYSTEM_FIXED);
    EXPECT_EQ(RET_SUCCESS, res);
    EXPECT_EQ(true, callbackPtr->ready_);

    callbackPtr->ready_ = false;
    res = AccessTokenKit::ClearUserGrantedPermissionState(tokenIdEx.tokenIdExStruct.tokenID);
    EXPECT_EQ(RET_SUCCESS, res);
    EXPECT_EQ(false, callbackPtr->ready_);

    callbackPtr->ready_ = false;
    res = AccessTokenKit::RevokePermission(tokenIdEx.tokenIdExStruct.tokenID,
        "ohos.permission.READ_MEDIA", PERMISSION_GRANTED_BY_POLICY);
    EXPECT_EQ(RET_SUCCESS, res);
    EXPECT_EQ(true, callbackPtr->ready_);

    callbackPtr->ready_ = false;
    res = AccessTokenKit::ClearUserGrantedPermissionState(tokenIdEx.tokenIdExStruct.tokenID);
    EXPECT_EQ(RET_SUCCESS, res);
    EXPECT_EQ(true, callbackPtr->ready_);

    callbackPtr->ready_ = false;
    res = AccessTokenKit::DeleteToken(tokenIdEx.tokenIdExStruct.tokenID);
    EXPECT_EQ(RET_SUCCESS, res);
    EXPECT_EQ(true, callbackPtr->ready_);

    res = AccessTokenKit::UnRegisterPermStateChangeCallback(callbackPtr);
    ASSERT_EQ(RET_SUCCESS, res);
}

/**
 * @tc.name: UnRegisterPermStateChangeCallback001
 * @tc.desc: UnRegisterPermStateChangeCallback with invalid input.
 * @tc.type: FUNC
 * @tc.require: issueI5NT1X
 */
HWTEST_F(AccessTokenKitExtensionTest, UnRegisterPermStateChangeCallback001, TestSize.Level1)
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
HWTEST_F(AccessTokenKitExtensionTest, UnRegisterPermStateChangeCallback002, TestSize.Level1)
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
 * @tc.name: UnRegisterPermStateChangeCallback003
 * @tc.desc: UnRegisterPermStateChangeCallback caller is normal app.
 * @tc.type: FUNC
 * @tc.require: issueI66BH3
 */
HWTEST_F(AccessTokenKitExtensionTest, UnRegisterPermStateChangeCallback003, TestSize.Level0)
{
    PermStateChangeScope scopeInfo;
    scopeInfo.permList = {};
    scopeInfo.tokenIDs = {};
    auto callbackPtr = std::make_shared<CbCustomizeTest>(scopeInfo);
    callbackPtr->ready_ = false;

    int32_t res = AccessTokenKit::RegisterPermStateChangeCallback(callbackPtr);
    ASSERT_EQ(RET_SUCCESS, res);

    AccessTokenIDEx tokenIdEx = {0};
    tokenIdEx = AccessTokenKit::AllocHapToken(g_infoManagerTestNormalInfoParms, g_infoManagerTestPolicyPrams);
    ASSERT_NE(INVALID_TOKENID, tokenIdEx.tokenIDEx);
    EXPECT_EQ(0, SetSelfTokenID(tokenIdEx.tokenIDEx));

    res = AccessTokenKit::UnRegisterPermStateChangeCallback(callbackPtr);
    ASSERT_EQ(ERR_NOT_SYSTEM_APP, res);

    EXPECT_EQ(0, SetSelfTokenID(selfTokenId_));
    res = AccessTokenKit::UnRegisterPermStateChangeCallback(callbackPtr);
    ASSERT_EQ(RET_SUCCESS, res);
}

/**
 * @tc.name: GetVersion001
 * @tc.desc: GetVersion001 test.
 * @tc.type: FUNC
 * @tc.require: issueI5NT1X
 */
HWTEST_F(AccessTokenKitExtensionTest, GetVersion001, TestSize.Level1)
{
    int32_t res = AccessTokenKit::GetVersion();
    ASSERT_EQ(DEFAULT_TOKEN_VERSION, res);
}

/**
 * @tc.name: GetVersion002
 * @tc.desc: GetVersion caller is normal app.
 * @tc.type: FUNC
 * @tc.require: issueI5NT1X
 */
HWTEST_F(AccessTokenKitExtensionTest, GetVersion002, TestSize.Level1)
{
    AccessTokenIDEx tokenIdEx = {0};
    tokenIdEx = AccessTokenKit::AllocHapToken(g_infoManagerTestNormalInfoParms, g_infoManagerTestPolicyPrams);
    ASSERT_NE(INVALID_TOKENID, tokenIdEx.tokenIDEx);
    EXPECT_EQ(0, SetSelfTokenID(tokenIdEx.tokenIDEx));

    int32_t res = AccessTokenKit::GetVersion();
    ASSERT_EQ(ERR_NOT_SYSTEM_APP, res);
}

/**
 * @tc.name: GetVersion003
 * @tc.desc: GetVersion caller is system app.
 * @tc.type: FUNC
 * @tc.require: issueI5NT1X
 */
HWTEST_F(AccessTokenKitExtensionTest, GetVersion003, TestSize.Level1)
{
    AccessTokenIDEx tokenIdEx = {0};
    tokenIdEx = AccessTokenKit::AllocHapToken(g_infoManagerTestSystemInfoParms, g_infoManagerTestPolicyPrams);
    ASSERT_NE(INVALID_TOKENID, tokenIdEx.tokenIDEx);
    EXPECT_EQ(0, SetSelfTokenID(tokenIdEx.tokenIDEx));

    int32_t res = AccessTokenKit::GetVersion();
    ASSERT_EQ(DEFAULT_TOKEN_VERSION, res);
}

/**
 * @tc.name: PermStateChangeCallback001
 * @tc.desc: PermissionStateChangeCallback::PermStateChangeCallback function test.
 * @tc.type: FUNC
 * @tc.require: issueI61NS6
 */
HWTEST_F(AccessTokenKitExtensionTest, PermStateChangeCallback001, TestSize.Level1)
{
    PermStateChangeInfo result = {
        .permStateChangeType = 0,
        .tokenID = 123,
        .permissionName = "ohos.permission.CAMERA"
    };

    std::shared_ptr<CbCustomizeTest> callbackPtr = nullptr;
    std::shared_ptr<PermissionStateChangeCallback> callback = std::make_shared<PermissionStateChangeCallback>(
        callbackPtr);
    ASSERT_NE(callback, nullptr);

    callback->PermStateChangeCallback(result);
    ASSERT_EQ(callback->customizedCallback_, nullptr);
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
HWTEST_F(AccessTokenKitExtensionTest, OnRemoteRequest001, TestSize.Level1)
{
    PermStateChangeInfo info = {
        .permStateChangeType = 0,
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
HWTEST_F(AccessTokenKitExtensionTest, CreatePermStateChangeCallback001, TestSize.Level1)
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
HWTEST_F(AccessTokenKitExtensionTest, InitProxy001, TestSize.Level1)
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
HWTEST_F(AccessTokenKitExtensionTest, AllocHapToken020, TestSize.Level1)
{
    HapInfoParams info;
    HapPolicyParams policy;
    info.userID = -1;
    AccessTokenKit::AllocHapToken(info, policy);
    ASSERT_EQ(-1, info.userID);
}

/**
 * @tc.name: VerifyAccessToken005
 * @tc.desc: AccessTokenKit::VerifyAccessToken function test
 * @tc.type: FUNC
 * @tc.require: issueI61A6M
 */
HWTEST_F(AccessTokenKitExtensionTest, VerifyAccessToken005, TestSize.Level1)
{
    std::string bundleName = "com.ohos.medialibrary.medialibrarydata";
    AccessTokenID callerTokenID = AccessTokenKit::GetHapTokenID(100, bundleName, 0); // tokenId for photo app
    ASSERT_NE(INVALID_TOKENID, callerTokenID);
    AccessTokenID firstTokenID;
    std::string permissionName;

    // ret = PERMISSION_GRANTED + firstTokenID = 0
    permissionName = "ohos.permission.READ_MEDIA";
    firstTokenID = 0;
    ASSERT_EQ(PermissionState::PERMISSION_DENIED, AccessTokenKit::VerifyAccessToken(
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

/**
 * @tc.name: IsSystemAppByFullTokenIDTest001
 * @tc.desc: check systemapp level by TokenIDEx after AllocHapToken function set isSystemApp true.
 * @tc.type: FUNC
 * @tc.require: issueI60F1M
 */
HWTEST_F(AccessTokenKitExtensionTest, IsSystemAppByFullTokenIDTest001, TestSize.Level1)
{
    AccessTokenIDEx tokenIdEx = {0};
    tokenIdEx = AccessTokenKit::AllocHapToken(g_infoManagerTestSystemInfoParms, g_infoManagerTestPolicyPrams);
    AccessTokenIDEx tokenIdEx1 = AccessTokenKit::GetHapTokenIDEx(1, "accesstoken_test", 0);
    ASSERT_EQ(tokenIdEx.tokenIDEx, tokenIdEx1.tokenIDEx);
    bool res = TokenIdKit::IsSystemAppByFullTokenID(tokenIdEx.tokenIDEx);
    ASSERT_EQ(true, res);
    ASSERT_EQ(RET_SUCCESS, AccessTokenKit::UpdateHapToken(tokenIdEx, false, g_infoManagerTestSystemInfoParms.appIDDesc,
        g_infoManagerTestSystemInfoParms.apiVersion, g_infoManagerTestPolicyPrams));
    tokenIdEx1 = AccessTokenKit::GetHapTokenIDEx(1, "accesstoken_test", 0);
    ASSERT_EQ(tokenIdEx.tokenIDEx, tokenIdEx1.tokenIDEx);
    res = TokenIdKit::IsSystemAppByFullTokenID(tokenIdEx.tokenIDEx);
    ASSERT_EQ(false, res);
}

/**
 * @tc.name: IsSystemAppByFullTokenIDTest002
 * @tc.desc: check systemapp level by TokenIDEx after AllocHapToken function set isSystemApp false.
 * @tc.type: FUNC
 * @tc.require: issueI60F1M
 */
HWTEST_F(AccessTokenKitExtensionTest, IsSystemAppByFullTokenIDTest002, TestSize.Level1)
{
    AccessTokenIDEx tokenIdEx = {0};
    tokenIdEx = AccessTokenKit::AllocHapToken(g_infoManagerTestNormalInfoParms, g_infoManagerTestPolicyPrams);
    bool res = TokenIdKit::IsSystemAppByFullTokenID(tokenIdEx.tokenIDEx);
    AccessTokenIDEx tokenIdEx1 = AccessTokenKit::GetHapTokenIDEx(1, "accesstoken_test", 0);
    ASSERT_EQ(tokenIdEx.tokenIDEx, tokenIdEx1.tokenIDEx);
    ASSERT_EQ(false, res);
    ASSERT_EQ(RET_SUCCESS, AccessTokenKit::UpdateHapToken(tokenIdEx, true, g_infoManagerTestNormalInfoParms.appIDDesc,
        g_infoManagerTestNormalInfoParms.apiVersion, g_infoManagerTestPolicyPrams));
    tokenIdEx1 = AccessTokenKit::GetHapTokenIDEx(1, "accesstoken_test", 0);
    ASSERT_EQ(tokenIdEx.tokenIDEx, tokenIdEx1.tokenIDEx);
    res = TokenIdKit::IsSystemAppByFullTokenID(tokenIdEx.tokenIDEx);
    ASSERT_EQ(true, res);
}
} // namespace AccessToken
} // namespace Security
} // namespace OHOS
