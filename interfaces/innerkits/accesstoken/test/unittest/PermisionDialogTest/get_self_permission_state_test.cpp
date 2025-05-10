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
#include "test_common.h"
#include "token_setproc.h"

namespace OHOS {
namespace Security {
namespace AccessToken {
using namespace testing::ext;
namespace {
static const int MAX_PERMISSION_SIZE = 1024;
static const std::string TEST_BUNDLE_NAME = "ohos";
static const int TEST_USER_ID = 0;
static const std::string LOCATION_PERMISSION = "ohos.permission.LOCATION";
static const std::string APPROXIMATELY_LOCATION_PERMISSION = "ohos.permission.APPROXIMATELY_LOCATION";
static const std::string LOCATION_IN_BACKGROUND_PERMISSION = "ohos.permission.LOCATION_IN_BACKGROUND";
PermissionStateFull g_permTestState1 = {
    .permissionName = LOCATION_PERMISSION,
    .isGeneral = true,
    .resDeviceID = {"local"},
    .grantStatus = {PermissionState::PERMISSION_DENIED},
    .grantFlags = {PermissionFlag::PERMISSION_DEFAULT_FLAG},
};

PermissionStateFull g_permTestState2 = {
    .permissionName = "ohos.permission.MICROPHONE",
    .isGeneral = true,
    .resDeviceID = {"local"},
    .grantStatus = {PermissionState::PERMISSION_DENIED},
    .grantFlags = {PermissionFlag::PERMISSION_USER_SET}
};

PermissionStateFull g_permTestState3 = {
    .permissionName = "ohos.permission.WRITE_CALENDAR",
    .isGeneral = true,
    .resDeviceID = {"local"},
    .grantStatus = {PermissionState::PERMISSION_DENIED},
    .grantFlags = {PermissionFlag::PERMISSION_USER_FIXED}
};

PermissionStateFull g_permTestState4 = {
    .permissionName = "ohos.permission.READ_IMAGEVIDEO",
    .isGeneral = true,
    .resDeviceID = {"local"},
    .grantStatus = {PermissionState::PERMISSION_GRANTED},
    .grantFlags = {PermissionFlag::PERMISSION_USER_SET}
};

HapInfoParams g_infoManager = {
    .userID = 1,
    .bundleName = "accesstoken_test",
    .instIndex = 0,
    .appIDDesc = "test2",
    .apiVersion = 8  // 8: api version
};

HapPolicyParams g_policy = {
    .apl = APL_NORMAL,
    .domain = "domain",
    .permStateList = {g_permTestState1, g_permTestState2, g_permTestState3, g_permTestState4}
};

static uint64_t g_selfTokenId = 0;
}

void GetSelfPermissionStateTest::SetUpTestCase()
{
    g_selfTokenId = GetSelfTokenID();
    TestCommon::SetTestEvironment(g_selfTokenId);
}

void GetSelfPermissionStateTest::TearDownTestCase()
{
    ASSERT_EQ(RET_SUCCESS, SetSelfTokenID(g_selfTokenId));
    TestCommon::ResetTestEvironment();
}

void GetSelfPermissionStateTest::SetUp()
{
    HapInfoParams info = {
        .userID = TEST_USER_ID,
        .bundleName = TEST_BUNDLE_NAME,
        .instIndex = 0,
        .appIDDesc = "appIDDesc",
        .apiVersion = 8 // 8: api version
    };

    AccessTokenIDEx tokenIdEx = TestCommon::AllocAndGrantHapTokenByTest(info, g_policy);
    AccessTokenID tokenId = tokenIdEx.tokenIdExStruct.tokenID;
    ASSERT_NE(tokenId, INVALID_TOKENID);
    ASSERT_EQ(RET_SUCCESS, SetSelfTokenID(tokenIdEx.tokenIDEx));
}

void GetSelfPermissionStateTest::TearDown()
{
    AccessTokenIDEx tokenIdEx = TestCommon::GetHapTokenIdFromBundle(TEST_USER_ID, TEST_BUNDLE_NAME, 0);
    AccessTokenID tokenId = tokenIdEx.tokenIdExStruct.tokenID;
    if (tokenId != INVALID_TOKENID) {
        EXPECT_EQ(RET_SUCCESS, TestCommon::DeleteTestHapToken(tokenId));
    }
}

void GetPermsList1(std::vector<PermissionListState> &permsList1)
{
    PermissionListState perm1 = {
        .permissionName = LOCATION_PERMISSION,
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
    AccessTokenIDEx tokenIdEx = TestCommon::GetHapTokenIdFromBundle(TEST_USER_ID, TEST_BUNDLE_NAME, 0);
    AccessTokenID tokenID = tokenIdEx.tokenIdExStruct.tokenID;
    ASSERT_NE(INVALID_TOKENID, tokenID);

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
    ASSERT_EQ(LOCATION_PERMISSION, permsList1[0].permissionName);
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
    MockNativeToken mock("hdcd");
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
    AccessTokenIDEx tokenIdEx = TestCommon::GetHapTokenIdFromBundle(TEST_USER_ID, TEST_BUNDLE_NAME, 0);
    AccessTokenID tokenId = tokenIdEx.tokenIdExStruct.tokenID;
    ASSERT_EQ(RET_SUCCESS, TestCommon::DeleteTestHapToken(tokenId));
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
 * @tc.desc: test noexist permission
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(GetSelfPermissionStateTest, GetSelfPermissionsState005, TestSize.Level1)
{
    std::vector<PermissionListState> permsList4;
    PermissionListState tmp = {
        .permissionName = "ohos.permission.SHORT_TERM_WRITE_IMAGEVIDEO",
        .state = PASS_OPER
    };
    permsList4.emplace_back(tmp);
    PermissionGrantInfo info;
    ASSERT_EQ(PASS_OPER, AccessTokenKit::GetSelfPermissionsState(permsList4, info));
}

/**
 * @tc.name: GetSelfPermissionsState006
 * @tc.desc: get self permissions state with wrong token type.
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(GetSelfPermissionStateTest, GetSelfPermissionsState006, TestSize.Level1)
{
    std::vector<PermissionListState> permsList;
    PermissionListState tmp = {
        .permissionName = g_policy.permStateList[0].permissionName,
        .state = BUTT_OPER
    };
    permsList.emplace_back(tmp);

    {
        std::vector<std::string> reqPerm;
        reqPerm.emplace_back("ohos.permission.DISABLE_PERMISSION_DIALOG");
        MockHapToken mock("GetSelfPermissionsState006", reqPerm, true);

        HapBaseInfo hapBaseInfo = {
            .userID = TEST_USER_ID,
            .bundleName = TEST_BUNDLE_NAME,
            .instIndex = 0,
        };

        // test dialog isn't forbiddedn
        ASSERT_EQ(0, AccessTokenKit::SetPermDialogCap(hapBaseInfo, false));
    }
    
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
        .permissionName = APPROXIMATELY_LOCATION_PERMISSION,
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
    AccessTokenIDEx tokenIdEx = TestCommon::AllocAndGrantHapTokenByTest(g_infoManager, policyParam);
    AccessTokenID tokenID = tokenIdEx.tokenIdExStruct.tokenID;
    ASSERT_NE(tokenID, INVALID_TOKENID);
    EXPECT_EQ(0, SetSelfTokenID(tokenIdEx.tokenIDEx));  // set self hap token

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
    PermissionGrantInfo info;
    ASSERT_EQ(DYNAMIC_OPER, AccessTokenKit::GetSelfPermissionsState(permsList, info));
    EXPECT_EQ(permsList[0].errorReason, PERM_INVALID);
    EXPECT_EQ(permsList[1].errorReason, PERM_NOT_DECLEARED);
    EXPECT_EQ(permsList[2].errorReason, REQ_SUCCESS);
    EXPECT_EQ(permsList[3].errorReason, REQ_SUCCESS);
    EXPECT_EQ(permsList[4].errorReason, UNABLE_POP_UP);
    EXPECT_EQ(permsList[5].errorReason, CONDITIONS_NOT_MET);
    EXPECT_EQ(permsList[6].errorReason, REQ_SUCCESS);
    ASSERT_EQ(RET_SUCCESS, TestCommon::DeleteTestHapToken(tokenID));
    ASSERT_EQ(RET_SUCCESS, SetSelfTokenID(g_selfTokenId));
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
    AccessTokenIDEx tokenIdEx = TestCommon::AllocAndGrantHapTokenByTest(g_infoManager, policyParam);
    AccessTokenID tokenID = tokenIdEx.tokenIdExStruct.tokenID;
    ASSERT_NE(tokenID, INVALID_TOKENID);
    EXPECT_EQ(0, SetSelfTokenID(tokenIdEx.tokenIDEx));  // set self hap token

    std::vector<PermissionListState> permsList;
    for (auto& perm : policyParam.permStateList) {
        PermissionListState tmp = {
            .permissionName = perm.permissionName,
            .state = FORBIDDEN_OPER
        };
        permsList.emplace_back(tmp);
    }
    {
        std::vector<std::string> reqPerm;
        reqPerm.emplace_back("ohos.permission.DISABLE_PERMISSION_DIALOG");
        MockHapToken mock("GetSelfPermissionsState008", reqPerm, true);

        HapBaseInfo hapBaseInfo = {
            .userID = g_infoManager.userID,
            .bundleName = g_infoManager.bundleName,
            .instIndex = g_infoManager.instIndex,
        };

        // test dialog isn't forbiddedn
        ASSERT_EQ(0, AccessTokenKit::SetPermDialogCap(hapBaseInfo, true));
    }

    PermissionGrantInfo info;
    ASSERT_EQ(FORBIDDEN_OPER, AccessTokenKit::GetSelfPermissionsState(permsList, info));
    EXPECT_EQ(permsList[0].errorReason, PRIVACY_STATEMENT_NOT_AGREED);
    EXPECT_EQ(permsList[1].errorReason, PRIVACY_STATEMENT_NOT_AGREED);
    EXPECT_EQ(permsList[2].errorReason, UNABLE_POP_UP);
    EXPECT_EQ(permsList[3].errorReason, CONDITIONS_NOT_MET);
    EXPECT_EQ(permsList[4].errorReason, PRIVACY_STATEMENT_NOT_AGREED);
    ASSERT_EQ(RET_SUCCESS, TestCommon::DeleteTestHapToken(tokenID));
    ASSERT_EQ(RET_SUCCESS, SetSelfTokenID(g_selfTokenId));
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
    std::vector<std::string> permissions = {LOCATION_PERMISSION, APPROXIMATELY_LOCATION_PERMISSION};
    HapPolicyParams policyParam = getHapPolicyLocationParams(permissions);
    HapInfoParams hapInfo = g_infoManager;
    hapInfo.apiVersion = 14;

    AccessTokenIDEx tokenIdEx = TestCommon::AllocAndGrantHapTokenByTest(hapInfo, policyParam);
    ASSERT_NE(tokenIdEx.tokenIdExStruct.tokenID, INVALID_TOKENID);
    EXPECT_EQ(0, SetSelfTokenID(tokenIdEx.tokenIDEx));  // set self hap token

    std::vector<PermissionListState> permsList;
    PermissionListState locationState = {
        .permissionName = APPROXIMATELY_LOCATION_PERMISSION,
        .state = FORBIDDEN_OPER
    };
    permsList.emplace_back(locationState);
    PermissionGrantInfo info;
    ASSERT_EQ(DYNAMIC_OPER, AccessTokenKit::GetSelfPermissionsState(permsList, info));
    EXPECT_EQ(permsList[0].errorReason, REQ_SUCCESS);

    locationState.permissionName = LOCATION_PERMISSION;
    permsList.emplace_back(locationState);
    ASSERT_EQ(DYNAMIC_OPER, AccessTokenKit::GetSelfPermissionsState(permsList, info));
    EXPECT_EQ(permsList[0].errorReason, REQ_SUCCESS);
    EXPECT_EQ(permsList[1].errorReason, REQ_SUCCESS);

    permsList[1].permissionName = LOCATION_IN_BACKGROUND_PERMISSION;
    ASSERT_EQ(PASS_OPER, AccessTokenKit::GetSelfPermissionsState(permsList, info));
    EXPECT_EQ(permsList[0].errorReason, CONDITIONS_NOT_MET);
    EXPECT_EQ(permsList[1].errorReason, CONDITIONS_NOT_MET);

    std::vector<PermissionListState> locationPermsList = {locationState};
    ASSERT_EQ(PASS_OPER, AccessTokenKit::GetSelfPermissionsState(locationPermsList, info));
    EXPECT_EQ(locationPermsList[0].errorReason, CONDITIONS_NOT_MET);

    ASSERT_EQ(RET_SUCCESS, TestCommon::GrantPermissionByTest(
        tokenIdEx.tokenIdExStruct.tokenID, APPROXIMATELY_LOCATION_PERMISSION, PERMISSION_USER_FIXED));
    ASSERT_EQ(DYNAMIC_OPER, AccessTokenKit::GetSelfPermissionsState(locationPermsList, info));
    EXPECT_EQ(locationPermsList[0].errorReason, REQ_SUCCESS);

    locationState.permissionName = LOCATION_IN_BACKGROUND_PERMISSION;
    std::vector<PermissionListState> backgroundPermsList = {locationState};
    ASSERT_EQ(PASS_OPER, AccessTokenKit::GetSelfPermissionsState(backgroundPermsList, info));
    EXPECT_EQ(backgroundPermsList[0].errorReason, CONDITIONS_NOT_MET);

    ASSERT_EQ(RET_SUCCESS, TestCommon::DeleteTestHapToken(tokenIdEx.tokenIdExStruct.tokenID));
    std::vector<std::string> vaguePermissions = {APPROXIMATELY_LOCATION_PERMISSION};
    policyParam = getHapPolicyLocationParams(vaguePermissions);

    tokenIdEx = TestCommon::AllocAndGrantHapTokenByTest(hapInfo, policyParam);
    ASSERT_NE(tokenIdEx.tokenIdExStruct.tokenID, INVALID_TOKENID);
    EXPECT_EQ(0, SetSelfTokenID(tokenIdEx.tokenIDEx));  // set self hap token

    ASSERT_EQ(PASS_OPER, AccessTokenKit::GetSelfPermissionsState(locationPermsList, info));
    EXPECT_EQ(locationPermsList[0].errorReason, PERM_NOT_DECLEARED);
    ASSERT_EQ(RET_SUCCESS, TestCommon::DeleteTestHapToken(tokenIdEx.tokenIdExStruct.tokenID));
    EXPECT_EQ(0, SetSelfTokenID(g_selfTokenId));  // set self hap token
}
} // namespace AccessToken
} // namespace Security
} // namespace OHOS