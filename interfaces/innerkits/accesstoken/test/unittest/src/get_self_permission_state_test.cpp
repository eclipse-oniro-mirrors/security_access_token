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
#include "get_self_permission_state_test.h"
#include "nativetoken_kit.h"
#include "token_setproc.h"

namespace OHOS {
namespace Security {
namespace AccessToken {
using namespace testing::ext;
namespace {
static const int MAX_PERMISSION_SIZE = 1000;
static const std::string TEST_BUNDLE_NAME = "ohos";
static const int TEST_USER_ID = 0;
static const std::string TEST_PERMISSION_NAME_A_MICRO = "ohos.permission.MICROPHONE";
static const std::string TEST_PERMISSION_NAME_A_CAMERA = "ohos.permission.SET_WIFI_INFO";
PermissionDef g_permDef1 = {
    .permissionName = "ohos.permission.test1",
    .bundleName = "accesstoken_test",
    .grantMode = 1,
    .availableLevel = APL_NORMAL,
    .label = "label2",
    .labelId = 1,
    .description = "open the door",
    .descriptionId = 1
};

PermissionDef g_permDef2 = {
    .permissionName = "ohos.permission.test2",
    .bundleName = "accesstoken_test",
    .grantMode = 1,
    .availableLevel = APL_NORMAL,
    .label = "label2",
    .labelId = 1,
    .description = "break the door",
    .descriptionId = 1
};

HapInfoParams g_infoManager = {
    .userID = 1,
    .bundleName = "accesstoken_test",
    .instIndex = 0,
    .appIDDesc = "test2",
    .apiVersion = 8  // 8: api version
};

PermissionStateFull g_permState1 = {
    .permissionName = "ohos.permission.test1",
    .isGeneral = true,
    .resDeviceID = {"local2"},
    .grantStatus = {PermissionState::PERMISSION_GRANTED},
    .grantFlags = {1}
};

PermissionStateFull g_permState2 = {
    .permissionName = "ohos.permission.test2",
    .isGeneral = false,
    .resDeviceID = {"device 1", "device 2"},
    .grantStatus = {PermissionState::PERMISSION_GRANTED, PermissionState::PERMISSION_GRANTED},
    .grantFlags = {1, 2}
};

HapPolicyParams g_infoManagerTestPolicyPrams = {
    .apl = APL_NORMAL,
    .domain = "test.domain2",
    .permList = {g_permDef1, g_permDef2},
    .permStateList = {g_permState1, g_permState2}
};
}

void GetSelfPermissionStateTest::SetUpTestCase()
{
    setuid(0);
    const char **perms = new const char *[1]; // 1: array size
    perms[0] = "ohos.permission.DISABLE_PERMISSION_DIALOG";

    NativeTokenInfoParams infoInstance = {
        .dcapsNum = 0,
        .permsNum = 1, // 1: array size
        .aclsNum = 0,
        .dcaps = nullptr,
        .perms = perms,
        .acls = nullptr,
        .aplStr = "system_core",
        .processName = "TestCase",
    };

    uint64_t tokenId = GetAccessTokenId(&infoInstance);
    AccessTokenKit::ReloadNativeTokenInfo();
    
    EXPECT_EQ(0, SetSelfTokenID(tokenId));
    delete[] perms;
}

void GetSelfPermissionStateTest::TearDownTestCase()
{
}

void InitPermStateList(HapPolicyParams &policy)
{
    PermissionStateFull permTestState1 = {
        .permissionName = "ohos.permission.LOCATION",
        .isGeneral = true,
        .resDeviceID = {"local"},
        .grantStatus = {PermissionState::PERMISSION_DENIED},
        .grantFlags = {PermissionFlag::PERMISSION_DEFAULT_FLAG},
    };

    PermissionStateFull permTestState2 = {
        .permissionName = "ohos.permission.MICROPHONE",
        .isGeneral = true,
        .resDeviceID = {"local"},
        .grantStatus = {PermissionState::PERMISSION_DENIED},
        .grantFlags = {PermissionFlag::PERMISSION_USER_SET}
    };

    PermissionStateFull permTestState3 = {
        .permissionName = "ohos.permission.WRITE_CALENDAR",
        .isGeneral = true,
        .resDeviceID = {"local"},
        .grantStatus = {PermissionState::PERMISSION_DENIED},
        .grantFlags = {PermissionFlag::PERMISSION_USER_FIXED}
    };

    PermissionStateFull permTestState4 = {
        .permissionName = "ohos.permission.READ_IMAGEVIDEO",
        .isGeneral = true,
        .resDeviceID = {"local"},
        .grantStatus = {PermissionState::PERMISSION_GRANTED},
        .grantFlags = {PermissionFlag::PERMISSION_USER_SET}
    };
    policy.permStateList.emplace_back(permTestState1);
    policy.permStateList.emplace_back(permTestState2);
    policy.permStateList.emplace_back(permTestState3);
    policy.permStateList.emplace_back(permTestState4);
}

void InitPermDefList(HapPolicyParams &policy)
{
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

    policy.permList.emplace_back(testPermDef1);
    policy.permList.emplace_back(testPermDef2);
    policy.permList.emplace_back(testPermDef3);
    policy.permList.emplace_back(testPermDef4);
}

void GetSelfPermissionStateTest::SetUp()
{
    selfTokenId_ = GetSelfTokenID();
    HapInfoParams info = {
        .userID = TEST_USER_ID,
        .bundleName = TEST_BUNDLE_NAME,
        .instIndex = 0,
        .appIDDesc = "appIDDesc",
        .apiVersion = 8 // 8: api version
    };

    HapPolicyParams policy = {
        .apl = APL_NORMAL,
        .domain = "domain",
    };
    InitPermStateList(policy);
    InitPermDefList(policy);
    AccessTokenKit::AllocHapToken(info, policy);
}

void GetSelfPermissionStateTest::TearDown()
{
    SetSelfTokenID(selfTokenId_);
    AccessTokenID tokenID = AccessTokenKit::GetHapTokenID(TEST_USER_ID, TEST_BUNDLE_NAME, 0);
    AccessTokenKit::DeleteToken(tokenID);
    DeleteTestToken();
}

unsigned int GetSelfPermissionStateTest::GetAccessTokenID(int userID, std::string bundleName, int instIndex)
{
    return AccessTokenKit::GetHapTokenID(userID, bundleName, instIndex);
}

AccessTokenID GetSelfPermissionStateTest::AllocTestToken(
    const HapInfoParams& hapInfo, const HapPolicyParams& hapPolicy) const
{
    AccessTokenIDEx tokenIdEx = {0};
    tokenIdEx = AccessTokenKit::AllocHapToken(hapInfo, hapPolicy);
    return tokenIdEx.tokenIdExStruct.tokenID;
}

void GetSelfPermissionStateTest::DeleteTestToken() const
{
    AccessTokenID tokenID = AccessTokenKit::GetHapTokenID(g_infoManager.userID,
                                                          g_infoManager.bundleName,
                                                          g_infoManager.instIndex);
    int ret = AccessTokenKit::DeleteToken(tokenID);
    if (tokenID != 0) {
        ASSERT_EQ(RET_SUCCESS, ret);
    }
}

void GetPermsList1(std::vector<PermissionListState> &permsList1)
{
    PermissionListState perm1 = {
        .permissionName = "ohos.permission.LOCATION",
        .state = SETTING_OPER,
    };
    PermissionListState perm2 = {
        .permissionName = "ohos.permission.MICROPHONE",
        .state = SETTING_OPER,
    };
    PermissionListState perm3 = {
        .permissionName = "ohos.permission.WRITE_CALENDAR",
        .state = SETTING_OPER,
    };
    PermissionListState perm4 = {
        .permissionName = "ohos.permission.READ_IMAGEVIDEO",
        .state = SETTING_OPER,
    };
    permsList1.emplace_back(perm1);
    permsList1.emplace_back(perm2);
    permsList1.emplace_back(perm3);
    permsList1.emplace_back(perm4);
}

void GetPermsList2(std::vector<PermissionListState> &permsList2)
{
    PermissionListState perm3 = {
        .permissionName = "ohos.permission.WRITE_CALENDAR",
        .state = SETTING_OPER,
    };
    PermissionListState perm4 = {
        .permissionName = "ohos.permission.READ_IMAGEVIDEO",
        .state = SETTING_OPER,
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
HWTEST_F(GetSelfPermissionStateTest, GetSelfPermissionsState001, TestSize.Level1)
{
    AccessTokenID tokenID = GetAccessTokenID(TEST_USER_ID, TEST_BUNDLE_NAME, 0);
    ASSERT_NE(INVALID_TOKENID, tokenID);
    ASSERT_EQ(0, SetSelfTokenID(tokenID));

    std::vector<PermissionListState> permsList1;
    GetPermsList1(permsList1);
    PermissionGrantInfo info;
    PermissionOper ret = AccessTokenKit::GetSelfPermissionsState(permsList1, info);
    ASSERT_EQ(DYNAMIC_OPER, ret);
    ASSERT_EQ(static_cast<uint32_t>(4), permsList1.size());
    ASSERT_EQ(DYNAMIC_OPER, permsList1[0].state);
    ASSERT_EQ(DYNAMIC_OPER, permsList1[1].state);
    ASSERT_EQ(SETTING_OPER, permsList1[2].state);
    ASSERT_EQ(PASS_OPER, permsList1[3].state);
    ASSERT_EQ("ohos.permission.LOCATION", permsList1[0].permissionName);
    ASSERT_EQ("ohos.permission.MICROPHONE", permsList1[1].permissionName);
    ASSERT_EQ("ohos.permission.WRITE_CALENDAR", permsList1[2].permissionName);
    ASSERT_EQ("ohos.permission.READ_IMAGEVIDEO", permsList1[3].permissionName);

    PermissionListState perm5 = {
        .permissionName = "ohos.permission.testPermDef5",
        .state = SETTING_OPER,
    };
    permsList1.emplace_back(perm5);
    ret = AccessTokenKit::GetSelfPermissionsState(permsList1, info);
    ASSERT_EQ(INVALID_OPER, permsList1[4].state);
    ASSERT_EQ(DYNAMIC_OPER, ret);

    std::vector<PermissionListState> permsList2;
    GetPermsList2(permsList2);
    ret = AccessTokenKit::GetSelfPermissionsState(permsList2, info);
    ASSERT_EQ(SETTING_OPER, permsList2[0].state);
    ASSERT_EQ(PASS_OPER, permsList2[1].state);
    ASSERT_EQ(PASS_OPER, ret);

    permsList2.emplace_back(perm5);
    ret = AccessTokenKit::GetSelfPermissionsState(permsList2, info);
    ASSERT_EQ(SETTING_OPER, permsList2[0].state);
    ASSERT_EQ(PASS_OPER, permsList2[1].state);
    ASSERT_EQ(INVALID_OPER, permsList2[2].state);
    ASSERT_EQ(PASS_OPER, ret);

    std::vector<PermissionListState> permsList3;
    permsList3.emplace_back(perm5);
    ret = AccessTokenKit::GetSelfPermissionsState(permsList3, info);
    ASSERT_EQ(INVALID_OPER, permsList3[0].state);
    ASSERT_EQ(PASS_OPER, ret);
}

/**
 * @tc.name: GetSelfPermissionsState002
 * @tc.desc: permission list is empty or oversize
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(GetSelfPermissionStateTest, GetSelfPermissionsState002, TestSize.Level1)
{
    std::vector<PermissionListState> permsList;
    PermissionGrantInfo info;
    ASSERT_EQ(PASS_OPER, AccessTokenKit::GetSelfPermissionsState(permsList, info));

    for (uint32_t i = 0; i < MAX_PERMISSION_SIZE + 1; i++) {
        PermissionListState tmp = {
            .permissionName = "ohos.permission.CAMERA",
            .state = PASS_OPER
        };
        permsList.emplace_back(tmp);
    }
    ASSERT_EQ(INVALID_OPER, AccessTokenKit::GetSelfPermissionsState(permsList, info));
}

/**
 * @tc.name: GetSelfPermissionsState003
 * @tc.desc: test token id is native
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(GetSelfPermissionStateTest, GetSelfPermissionsState003, TestSize.Level1)
{
    AccessTokenID tokenId = AccessTokenKit::GetNativeTokenId("hdcd");
    EXPECT_EQ(0, SetSelfTokenID(tokenId));
    std::vector<PermissionListState> permsList3;
    PermissionListState tmp = {
        .permissionName = "ohos.permission.CAMERA",
        .state = PASS_OPER
    };
    permsList3.emplace_back(tmp);
    PermissionGrantInfo info;
    ASSERT_EQ(INVALID_OPER, AccessTokenKit::GetSelfPermissionsState(permsList3, info));
}

/**
 * @tc.name: GetSelfPermissionsState004
 * @tc.desc: test noexist token id
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(GetSelfPermissionStateTest, GetSelfPermissionsState004, TestSize.Level1)
{
    AccessTokenID tokenId = AccessTokenKit::GetHapTokenID(TEST_USER_ID, TEST_BUNDLE_NAME, 0);
    EXPECT_EQ(0, SetSelfTokenID(tokenId));
    ASSERT_EQ(RET_SUCCESS, AccessTokenKit::DeleteToken(tokenId));
    std::vector<PermissionListState> permsList4;
    PermissionListState tmp = {
        .permissionName = "ohos.permission.CAMERA",
        .state = PASS_OPER
    };
    permsList4.emplace_back(tmp);
    PermissionGrantInfo info;
    ASSERT_EQ(INVALID_OPER, AccessTokenKit::GetSelfPermissionsState(permsList4, info));
}

/**
 * @tc.name: GetSelfPermissionsState005
 * @tc.desc: test noexist token id
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(GetSelfPermissionStateTest, GetSelfPermissionsState005, TestSize.Level1)
{
    AccessTokenID tokenId = AccessTokenKit::GetHapTokenID(TEST_USER_ID, TEST_BUNDLE_NAME, 0);
    EXPECT_EQ(0, SetSelfTokenID(tokenId));
    std::vector<PermissionListState> permsList4;
    PermissionListState tmp = {
        .permissionName = "ohos.permission.SHORT_TERM_WRITE_IMAGEVIDEO",
        .state = PASS_OPER
    };
    permsList4.emplace_back(tmp);
    PermissionGrantInfo info;
    ASSERT_EQ(PASS_OPER, AccessTokenKit::GetSelfPermissionsState(permsList4, info));
    ASSERT_EQ(RET_SUCCESS, AccessTokenKit::DeleteToken(tokenId));
}


/**
 * @tc.name: GetSelfPermissionsState006
 * @tc.desc: get self permissions state with wrong token type.
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(GetSelfPermissionStateTest, GetSelfPermissionsState006, TestSize.Level1)
{
    AccessTokenID tokenID = AllocTestToken(g_infoManager, g_infoManagerTestPolicyPrams);
    HapBaseInfo hapBaseInfo = {
        .userID = g_infoManager.userID,
        .bundleName = g_infoManager.bundleName,
        .instIndex = g_infoManager.instIndex,
    };

    std::vector<PermissionListState> permsList;
    PermissionListState tmp = {
        .permissionName = g_infoManagerTestPolicyPrams.permStateList[0].permissionName,
        .state = BUTT_OPER
    };
    permsList.emplace_back(tmp);

    // test dialog isn't forbiddedn
    ASSERT_EQ(0, AccessTokenKit::SetPermDialogCap(hapBaseInfo, false));
    SetSelfTokenID(tokenID);
    PermissionGrantInfo info;
    ASSERT_EQ(INVALID_OPER, AccessTokenKit::GetSelfPermissionsState(permsList, info));
}

HapPolicyParams GetPolicyParam()
{
    //test REQ_SUCCESS
    PermissionStateFull permState1 = {
        .permissionName = "ohos.permission.READ_HEALTH_DATA",
        .isGeneral = true,
        .resDeviceID = {"local3"},
        .grantStatus = {PermissionState::PERMISSION_GRANTED},
        .grantFlags = {PermissionFlag::PERMISSION_SYSTEM_FIXED}
    };
    PermissionStateFull permState2 = {
        .permissionName = "ohos.permission.DISTRIBUTED_DATASYNC",
        .isGeneral = true,
        .resDeviceID = {"local3"},
        .grantStatus = {PermissionState::PERMISSION_DENIED},
        .grantFlags = {PermissionFlag::PERMISSION_USER_SET}
    };
    //test UNABLE_POP_UP
    PermissionStateFull permState3 = {
        .permissionName = "ohos.permission.READ_MESSAGES",
        .isGeneral = true,
        .resDeviceID = {"local3"},
        .grantStatus = {PermissionState::PERMISSION_DENIED},
        .grantFlags = {PermissionFlag::PERMISSION_DEFAULT_FLAG}
    };
    //test CONDITIONS_NOT_MET
    PermissionStateFull permState4 = {
        .permissionName = "ohos.permission.APPROXIMATELY_LOCATION",
        .isGeneral = true,
        .resDeviceID = {"local3"},
        .grantStatus = {PermissionState::PERMISSION_DENIED},
        .grantFlags = {PermissionFlag::PERMISSION_DEFAULT_FLAG}
    };
    //test REQ_SUCCESS
    PermissionStateFull permState5 = {
        .permissionName = "ohos.permission.WRITE_MEDIA",
        .isGeneral = true,
        .resDeviceID = {"local3"},
        .grantStatus = {PermissionState::PERMISSION_DENIED},
        .grantFlags = {PermissionFlag::PERMISSION_DEFAULT_FLAG}
    };

    HapPolicyParams policyParam = {
        .apl = APL_NORMAL,
        .domain = "test.domain3",
        .permStateList = {permState1, permState2, permState3, permState4, permState5}
    };
    return policyParam;
}

/**
 * @tc.name: GetSelfPermissionsState007
 * @tc.desc: The test function GetSelfPermissionsState returns the object property field errorReason.
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(GetSelfPermissionStateTest, GetSelfPermissionsState007, TestSize.Level1)
{
    HapPolicyParams policyParam = GetPolicyParam();
    AccessTokenID tokenID = AllocTestToken(g_infoManager, policyParam);
    
    PermissionListState permInvalid = {
        .permissionName = "ohos.permission.WU_ERROR_REASON",
        .state = FORBIDDEN_OPER
    };
    PermissionListState permNotConfig = {
        .permissionName = "ohos.permission.READ_MEDIA",
        .state = FORBIDDEN_OPER
    };
    std::vector<PermissionListState> permsList;
    permsList.emplace_back(permInvalid);
    permsList.emplace_back(permNotConfig);
    for (auto& perm : policyParam.permStateList) {
        PermissionListState tmp = {
            .permissionName = perm.permissionName,
            .state = FORBIDDEN_OPER
        };
        permsList.emplace_back(tmp);
    }
    SetSelfTokenID(tokenID);
    PermissionGrantInfo info;
    ASSERT_EQ(DYNAMIC_OPER, AccessTokenKit::GetSelfPermissionsState(permsList, info));
    EXPECT_EQ(permsList[0].errorReason, PERM_INVALID);
    EXPECT_EQ(permsList[1].errorReason, PERM_NOT_DECLEARED);
    EXPECT_EQ(permsList[2].errorReason, REQ_SUCCESS);
    EXPECT_EQ(permsList[3].errorReason, REQ_SUCCESS);
    EXPECT_EQ(permsList[4].errorReason, UNABLE_POP_UP);
    EXPECT_EQ(permsList[5].errorReason, CONDITIONS_NOT_MET);
    EXPECT_EQ(permsList[6].errorReason, REQ_SUCCESS);
    ASSERT_EQ(RET_SUCCESS, AccessTokenKit::DeleteToken(tokenID));
}

/**
 * @tc.name: GetSelfPermissionsState008
 * @tc.desc: If the user does not agree to the privacy statement, the test function GetSelfPermissionsState returns
 *  the object attribute field errorReason.
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(GetSelfPermissionStateTest, GetSelfPermissionsState008, TestSize.Level1)
{
    HapPolicyParams policyParam = GetPolicyParam();
    AccessTokenID tokenID = AllocTestToken(g_infoManager, policyParam);
    HapBaseInfo hapBaseInfo = {
        .userID = g_infoManager.userID,
        .bundleName = g_infoManager.bundleName,
        .instIndex = g_infoManager.instIndex,
    };
    std::vector<PermissionListState> permsList;
    for (auto& perm : policyParam.permStateList) {
        PermissionListState tmp = {
            .permissionName = perm.permissionName,
            .state = FORBIDDEN_OPER
        };
        permsList.emplace_back(tmp);
    }
    ASSERT_EQ(0, AccessTokenKit::SetPermDialogCap(hapBaseInfo, true));
    SetSelfTokenID(tokenID);
    PermissionGrantInfo info;
    ASSERT_EQ(FORBIDDEN_OPER, AccessTokenKit::GetSelfPermissionsState(permsList, info));
    EXPECT_EQ(permsList[0].errorReason, PRIVACY_STATEMENT_NOT_AGREED);
    EXPECT_EQ(permsList[1].errorReason, PRIVACY_STATEMENT_NOT_AGREED);
    EXPECT_EQ(permsList[2].errorReason, UNABLE_POP_UP);
    EXPECT_EQ(permsList[3].errorReason, CONDITIONS_NOT_MET);
    EXPECT_EQ(permsList[4].errorReason, PRIVACY_STATEMENT_NOT_AGREED);
    ASSERT_EQ(RET_SUCCESS, AccessTokenKit::DeleteToken(tokenID));
}

HapPolicyParams getHapPolicyLocationParams(const std::vector<std::string>& permissions)
{
    HapPolicyParams policyParam = {
        .apl = APL_NORMAL,
        .domain = "test.domain3",
        .permStateList = {}
    };
    for (auto& perm : permissions) {
        PermissionStateFull location = {
            .permissionName = perm,
            .isGeneral = true,
            .resDeviceID = {"local3"},
            .grantStatus = {PermissionState::PERMISSION_DENIED},
            .grantFlags = {PermissionFlag::PERMISSION_DEFAULT_FLAG}
        };
        policyParam.permStateList.emplace_back(location);
    }
    return policyParam;
}

/**
 * @tc.name: GetSelfPermissionsState009
 * @tc.desc: The test position-related permission function GetSelfPermissionsState returns the object property
 *  field errorReason.
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(GetSelfPermissionStateTest, GetSelfPermissionsState009, TestSize.Level1)
{
    std::string location = "ohos.permission.LOCATION";
    std::string vague = "ohos.permission.APPROXIMATELY_LOCATION";
    std::string background = "ohos.permission.LOCATION_IN_BACKGROUND";
    std::vector<std::string> permissions = {location, vague};
    HapPolicyParams policyParam = getHapPolicyLocationParams(permissions);
    HapInfoParams hapInfo = g_infoManager;
    hapInfo.apiVersion = 14;
    AccessTokenID tokenID = AllocTestToken(hapInfo, policyParam);
    std::vector<PermissionListState> permsList;
    PermissionListState locationState = {
        .permissionName = vague,
        .state = FORBIDDEN_OPER
    };
    permsList.emplace_back(locationState);
    SetSelfTokenID(tokenID);
    PermissionGrantInfo info;

    ASSERT_EQ(DYNAMIC_OPER, AccessTokenKit::GetSelfPermissionsState(permsList, info));
    EXPECT_EQ(permsList[0].errorReason, REQ_SUCCESS);

    locationState.permissionName = location;
    permsList.emplace_back(locationState);
    ASSERT_EQ(DYNAMIC_OPER, AccessTokenKit::GetSelfPermissionsState(permsList, info));
    EXPECT_EQ(permsList[0].errorReason, REQ_SUCCESS);
    EXPECT_EQ(permsList[1].errorReason, REQ_SUCCESS);

    permsList[1].permissionName = background;
    ASSERT_EQ(PASS_OPER, AccessTokenKit::GetSelfPermissionsState(permsList, info));
    EXPECT_EQ(permsList[0].errorReason, CONDITIONS_NOT_MET);
    EXPECT_EQ(permsList[1].errorReason, CONDITIONS_NOT_MET);

    std::vector<PermissionListState> locationPermsList = {locationState};
    ASSERT_EQ(PASS_OPER, AccessTokenKit::GetSelfPermissionsState(locationPermsList, info));
    EXPECT_EQ(locationPermsList[0].errorReason, CONDITIONS_NOT_MET);

    SetSelfTokenID(selfTokenId_);
    ASSERT_EQ(RET_SUCCESS, AccessTokenKit::GrantPermission(tokenID, vague, PERMISSION_USER_FIXED));
    SetSelfTokenID(tokenID);
    ASSERT_EQ(DYNAMIC_OPER, AccessTokenKit::GetSelfPermissionsState(locationPermsList, info));
    EXPECT_EQ(locationPermsList[0].errorReason, REQ_SUCCESS);

    locationState.permissionName = background;
    std::vector<PermissionListState> backgroundPermsList = {locationState};
    ASSERT_EQ(PASS_OPER, AccessTokenKit::GetSelfPermissionsState(backgroundPermsList, info));
    EXPECT_EQ(backgroundPermsList[0].errorReason, CONDITIONS_NOT_MET);

    ASSERT_EQ(RET_SUCCESS, AccessTokenKit::DeleteToken(tokenID));

    std::vector<std::string> vaguePermissions = {vague};
    policyParam = getHapPolicyLocationParams(vaguePermissions);
    tokenID = AllocTestToken(hapInfo, policyParam);
    SetSelfTokenID(tokenID);

    ASSERT_EQ(PASS_OPER, AccessTokenKit::GetSelfPermissionsState(locationPermsList, info));
    EXPECT_EQ(locationPermsList[0].errorReason, PERM_NOT_DECLEARED);

    ASSERT_EQ(RET_SUCCESS, AccessTokenKit::DeleteToken(tokenID));
}
} // namespace AccessToken
} // namespace Security
} // namespace OHOS