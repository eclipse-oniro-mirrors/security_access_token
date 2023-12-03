/*
 * Copyright (c) 1922 Huawei Device Co., Ltd.
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

#include "accesstoken_location_request_test.h"

#include "access_token.h"
#include "accesstoken_kit.h"
#include "hap_token_info.h"
#include "permission_def.h"
#include "permission_grant_info.h"
#include "permission_list_state.h"
#include "permission_state_full.h"
#include "token_setproc.h"

using namespace testing::ext;

namespace OHOS {
namespace Security {
namespace AccessToken {
namespace {
static constexpr int32_t TEST_USER_ID = 100;
static std::string TEST_BUNDLE_NAME = "accesstoken_location_request_test";
static constexpr int32_t TEST_INST_INDEX = 0;
static constexpr int32_t DEFAULT_API_VERSION = 8;
static constexpr int32_t VAGUE_LOCATION_API_VERSION = 9;
static constexpr int32_t BACKGROUND_LOCATION_API_VERSION = 11;

PermissionStateFull g_locationTestStateSystemGrant = {
    .permissionName = "ohos.permission.UPDATE_SYSTEM",
    .isGeneral = true,
    .resDeviceID = {"device"},
    .grantStatus = {PermissionState::PERMISSION_GRANTED},
    .grantFlags = {PermissionFlag::PERMISSION_SYSTEM_FIXED}
};
PermissionStateFull g_locationTestStateUserGrant = {
    .permissionName = "ohos.permission.CAMERA",
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

PermissionStateFull g_locationTestStateBack02 = {
    .permissionName = "ohos.permission.LOCATION_IN_BACKGROUND",
    .isGeneral = true,
    .resDeviceID = {"device"},
    .grantStatus = {PermissionState::PERMISSION_GRANTED},
    .grantFlags = {PermissionFlag::PERMISSION_USER_FIXED}
};
PermissionStateFull g_locationTestStateBack10 = {
    .permissionName = "ohos.permission.LOCATION_IN_BACKGROUND",
    .isGeneral = true,
    .resDeviceID = {"device"},
    .grantStatus = {PermissionState::PERMISSION_DENIED},
    .grantFlags = {PermissionFlag::PERMISSION_DEFAULT_FLAG}
};
PermissionStateFull g_locationTestStateBack12 = {
    .permissionName = "ohos.permission.LOCATION_IN_BACKGROUND",
    .isGeneral = true,
    .resDeviceID = {"device"},
    .grantStatus = {PermissionState::PERMISSION_DENIED},
    .grantFlags = {PermissionFlag::PERMISSION_USER_FIXED}
};
}

void AccessTokenLocationRequestTest::SetUpTestCase()
{
    AccessTokenID tokenId = AccessTokenKit::GetHapTokenID(TEST_USER_ID, TEST_BUNDLE_NAME, TEST_INST_INDEX);
    AccessTokenKit::DeleteToken(tokenId);
}

void AccessTokenLocationRequestTest::TearDownTestCase()
{
}

void AccessTokenLocationRequestTest::SetUp()
{
    selfTokenId_ = GetSelfTokenID();
}

void AccessTokenLocationRequestTest::TearDown()
{
    AccessTokenID tokenId = AccessTokenKit::GetHapTokenID(TEST_USER_ID, TEST_BUNDLE_NAME, TEST_INST_INDEX);
    AccessTokenKit::DeleteToken(tokenId);
    SetSelfTokenID(selfTokenId_);
}

AccessTokenIDEx AllocHapToken(std::vector<PermissionStateFull>& permissionStateFulls, int32_t apiVersion)
{
    HapInfoParams info = {
        .userID = TEST_USER_ID,
        .bundleName = TEST_BUNDLE_NAME,
        .instIndex = TEST_INST_INDEX,
        .appIDDesc = "location_test",
        .apiVersion = apiVersion,
        .isSystemApp = true,
    };

    HapPolicyParams policy = {
        .apl = APL_NORMAL,
        .domain = "domain"
    };

    for (auto& permissionStateFull:permissionStateFulls) {
        policy.permStateList.emplace_back(permissionStateFull);
    }

    return AccessTokenKit::AllocHapToken(info, policy);
}

/**
 * @tc.name: GetSelfPermissionsState001
 * @tc.desc: only vague location permission, ret: DYNAMIC_OPER, state: DYNAMIC_OPER
 * @tc.type: FUNC
 * @tc.require: issueI5NOQI
 */
HWTEST_F(AccessTokenLocationRequestTest, GetSelfPermissionsState001, TestSize.Level1)
{
    std::vector<PermissionStateFull> permissionStateFulls;
    permissionStateFulls.emplace_back(g_locationTestStateVague10); // {-1,0} {grantStatus, grantFlags}

    AccessTokenIDEx tokenIdEx = AllocHapToken(permissionStateFulls, BACKGROUND_LOCATION_API_VERSION);
    AccessTokenID tokenID = tokenIdEx.tokenIdExStruct.tokenID;
    ASSERT_NE(INVALID_TOKENID, tokenID);
    ASSERT_EQ(0, SetSelfTokenID(tokenIdEx.tokenIDEx));

    PermissionListState permVague1 = {
        .permissionName = "ohos.permission.APPROXIMATELY_LOCATION",
        .state = SETTING_OPER,
    };

    std::vector<PermissionListState> permsList1;
    permsList1.emplace_back(permVague1);

    PermissionGrantInfo info;
    PermissionOper ret = AccessTokenKit::GetSelfPermissionsState(permsList1, info);
    ASSERT_EQ(DYNAMIC_OPER, ret);
    ASSERT_EQ(static_cast<uint32_t>(1), permsList1.size());
    ASSERT_EQ(DYNAMIC_OPER, permsList1[0].state);
}

/**
 * @tc.name: GetSelfPermissionsState002
 * @tc.desc: only vague location permission after refuse, ret: PASS_OPER, state: SETTING_OPER
 * @tc.type: FUNC
 * @tc.require: issueI5NOQI
 */
HWTEST_F(AccessTokenLocationRequestTest, GetSelfPermissionsState002, TestSize.Level1)
{
    std::vector<PermissionStateFull> permissionStateFulls;
    permissionStateFulls.emplace_back(g_locationTestStateVague12); // {-1,2}

    AccessTokenIDEx tokenIdEx = AllocHapToken(permissionStateFulls, BACKGROUND_LOCATION_API_VERSION);
    AccessTokenID tokenID = tokenIdEx.tokenIdExStruct.tokenID;
    ASSERT_NE(INVALID_TOKENID, tokenID);
    ASSERT_EQ(0, SetSelfTokenID(tokenIdEx.tokenIDEx));

    PermissionListState permVague2 = {
        .permissionName = "ohos.permission.APPROXIMATELY_LOCATION",
        .state = SETTING_OPER,
    };

    std::vector<PermissionListState> permsList2;
    permsList2.emplace_back(permVague2);

    PermissionGrantInfo info;
    PermissionOper ret = AccessTokenKit::GetSelfPermissionsState(permsList2, info);
    ASSERT_EQ(PASS_OPER, ret);
    ASSERT_EQ(static_cast<uint32_t>(1), permsList2.size());
    ASSERT_EQ(SETTING_OPER, permsList2[0].state);
}

/**
 * @tc.name: GetSelfPermissionsState003
 * @tc.desc: only vague location permission after accept, ret: PASS_OPER, state: PASS_OPER
 * @tc.type: FUNC
 * @tc.require: issueI5NOQI
 */
HWTEST_F(AccessTokenLocationRequestTest, GetSelfPermissionsState003, TestSize.Level1)
{
    std::vector<PermissionStateFull> permissionStateFulls;
    permissionStateFulls.emplace_back(g_locationTestStateVague02); // {0,2}

    AccessTokenIDEx tokenIdEx = AllocHapToken(permissionStateFulls, BACKGROUND_LOCATION_API_VERSION);
    AccessTokenID tokenID = tokenIdEx.tokenIdExStruct.tokenID;
    ASSERT_NE(INVALID_TOKENID, tokenID);
    ASSERT_EQ(0, SetSelfTokenID(tokenIdEx.tokenIDEx));

    PermissionListState permVague3 = {
        .permissionName = "ohos.permission.APPROXIMATELY_LOCATION",
        .state = SETTING_OPER,
    };

    std::vector<PermissionListState> permsList3;
    permsList3.emplace_back(permVague3);

    PermissionGrantInfo info;
    PermissionOper ret = AccessTokenKit::GetSelfPermissionsState(permsList3, info);
    ASSERT_EQ(PASS_OPER, ret);
    ASSERT_EQ(static_cast<uint32_t>(1), permsList3.size());
    ASSERT_EQ(PASS_OPER, permsList3[0].state);
}

/**
 * @tc.name: GetSelfPermissionsState004
 * @tc.desc: only accurate location permission, ret: PASS_OPER, state: INVALID_OPER
 * @tc.type: FUNC
 * @tc.require: issueI5NOQI
 */
HWTEST_F(AccessTokenLocationRequestTest, GetSelfPermissionsState004, TestSize.Level1)
{
    std::vector<PermissionStateFull> permissionStateFulls;
    permissionStateFulls.emplace_back(g_locationTestStateAccurate10); // {-1,0}

    AccessTokenIDEx tokenIdEx = AllocHapToken(permissionStateFulls, BACKGROUND_LOCATION_API_VERSION);
    AccessTokenID tokenID = tokenIdEx.tokenIdExStruct.tokenID;
    ASSERT_NE(INVALID_TOKENID, tokenID);
    ASSERT_EQ(0, SetSelfTokenID(tokenIdEx.tokenIDEx));

    std::vector<PermissionListState> permsList4;
    PermissionListState permAccurate4 = {
        .permissionName = "ohos.permission.LOCATION",
        .state = SETTING_OPER,
    };

    permsList4.emplace_back(permAccurate4);

    PermissionGrantInfo info;
    PermissionOper ret = AccessTokenKit::GetSelfPermissionsState(permsList4, info);
    ASSERT_EQ(PASS_OPER, ret);
    ASSERT_EQ(static_cast<uint32_t>(1), permsList4.size());
    ASSERT_EQ(INVALID_OPER, permsList4[0].state);
}

/**
 * @tc.name: GetSelfPermissionsState005
 * @tc.desc: only accurate location permission with granted vague location, ret: PASS_OPER, state: INVALID_OPER
 * @tc.type: FUNC
 * @tc.require: issueI5NOQI
 */
HWTEST_F(AccessTokenLocationRequestTest, GetSelfPermissionsState005, TestSize.Level1)
{
    std::vector<PermissionStateFull> permissionStateFulls;
    permissionStateFulls.emplace_back(g_locationTestStateAccurate10); // {-1,0}
    permissionStateFulls.emplace_back(g_locationTestStateVague02); // {0,2}

    AccessTokenIDEx tokenIdEx = AllocHapToken(permissionStateFulls, BACKGROUND_LOCATION_API_VERSION);
    AccessTokenID tokenID = tokenIdEx.tokenIdExStruct.tokenID;
    ASSERT_NE(INVALID_TOKENID, tokenID);
    ASSERT_EQ(0, SetSelfTokenID(tokenIdEx.tokenIDEx));

    std::vector<PermissionListState> permsList5;
    PermissionListState permAccurate5 = {
        .permissionName = "ohos.permission.LOCATION",
        .state = SETTING_OPER,
    };

    permsList5.emplace_back(permAccurate5);

    PermissionGrantInfo info;
    PermissionOper ret = AccessTokenKit::GetSelfPermissionsState(permsList5, info);
    ASSERT_EQ(PASS_OPER, ret);
    ASSERT_EQ(static_cast<uint32_t>(1), permsList5.size());
    ASSERT_EQ(INVALID_OPER, permsList5[0].state);
}

/**
 * @tc.name: GetSelfPermissionsState006
 * @tc.desc: only background location permission, ret: PASS_OPER, state: INVALID_OPER
 * @tc.type: FUNC
 * @tc.require: issueI5NOQI
 */
HWTEST_F(AccessTokenLocationRequestTest, GetSelfPermissionsState006, TestSize.Level1)
{
    std::vector<PermissionStateFull> permissionStateFulls;
    permissionStateFulls.emplace_back(g_locationTestStateBack10); // {-1,0}

    AccessTokenIDEx tokenIdEx = AllocHapToken(permissionStateFulls, BACKGROUND_LOCATION_API_VERSION);
    AccessTokenID tokenID = tokenIdEx.tokenIdExStruct.tokenID;
    ASSERT_NE(INVALID_TOKENID, tokenID);
    ASSERT_EQ(0, SetSelfTokenID(tokenIdEx.tokenIDEx));

    std::vector<PermissionListState> permsList6;
    PermissionListState permBack6 = {
        .permissionName = "ohos.permission.LOCATION_IN_BACKGROUND",
        .state = SETTING_OPER,
    };

    permsList6.emplace_back(permBack6);

    PermissionGrantInfo info;
    PermissionOper ret = AccessTokenKit::GetSelfPermissionsState(permsList6, info);
    ASSERT_EQ(PASS_OPER, ret);
    ASSERT_EQ(static_cast<uint32_t>(1), permsList6.size());
    ASSERT_EQ(INVALID_OPER, permsList6[0].state);
}

/**
 * @tc.name: GetSelfPermissionsState007
 * @tc.desc: only background location permission with granted vague location, ret: PASS_OPER, state: INVALID_OPER
 * @tc.type: FUNC
 * @tc.require: issueI5NOQI
 */
HWTEST_F(AccessTokenLocationRequestTest, GetSelfPermissionsState007, TestSize.Level1)
{
    std::vector<PermissionStateFull> permissionStateFulls;
    permissionStateFulls.emplace_back(g_locationTestStateBack10); // {-1,0}
    permissionStateFulls.emplace_back(g_locationTestStateVague02); // {0,2}

    AccessTokenIDEx tokenIdEx = AllocHapToken(permissionStateFulls, BACKGROUND_LOCATION_API_VERSION);
    AccessTokenID tokenID = tokenIdEx.tokenIdExStruct.tokenID;
    ASSERT_NE(INVALID_TOKENID, tokenID);
    ASSERT_EQ(0, SetSelfTokenID(tokenIdEx.tokenIDEx));

    std::vector<PermissionListState> permsList7;
    PermissionListState permBack7 = {
        .permissionName = "ohos.permission.LOCATION_IN_BACKGROUND",
        .state = SETTING_OPER,
    };

    permsList7.emplace_back(permBack7);

    PermissionGrantInfo info;
    PermissionOper ret = AccessTokenKit::GetSelfPermissionsState(permsList7, info);
    ASSERT_EQ(PASS_OPER, ret);
    ASSERT_EQ(static_cast<uint32_t>(1), permsList7.size());
    ASSERT_EQ(INVALID_OPER, permsList7[0].state);
}

/**
 * @tc.name: GetSelfPermissionsState008
 * @tc.desc: vague + accurate location permissions, ret: DYNAMIC_OPER, state: DYNAMIC_OPER
 * @tc.type: FUNC
 * @tc.require: issueI5NOQI
 */
HWTEST_F(AccessTokenLocationRequestTest, GetSelfPermissionsState008, TestSize.Level1)
{
    std::vector<PermissionStateFull> permissionStateFulls;
    permissionStateFulls.emplace_back(g_locationTestStateVague10); // {-1,0}
    permissionStateFulls.emplace_back(g_locationTestStateAccurate10); // {-1,0}

    AccessTokenIDEx tokenIdEx = AllocHapToken(permissionStateFulls, BACKGROUND_LOCATION_API_VERSION);
    AccessTokenID tokenID = tokenIdEx.tokenIdExStruct.tokenID;
    ASSERT_NE(INVALID_TOKENID, tokenID);
    ASSERT_EQ(0, SetSelfTokenID(tokenIdEx.tokenIDEx));

    PermissionListState permVague8 = {
        .permissionName = "ohos.permission.APPROXIMATELY_LOCATION",
        .state = SETTING_OPER,
    };
    PermissionListState permAccurate8 = {
        .permissionName = "ohos.permission.LOCATION",
        .state = SETTING_OPER,
    };

    std::vector<PermissionListState> permsList8;
    permsList8.emplace_back(permVague8);
    permsList8.emplace_back(permAccurate8);

    PermissionGrantInfo info;
    PermissionOper ret = AccessTokenKit::GetSelfPermissionsState(permsList8, info);
    ASSERT_EQ(DYNAMIC_OPER, ret);
    ASSERT_EQ(static_cast<uint32_t>(2), permsList8.size());
    ASSERT_EQ(DYNAMIC_OPER, permsList8[0].state);
    ASSERT_EQ(DYNAMIC_OPER, permsList8[1].state);
}

/**
 * @tc.name: GetSelfPermissionsState009
 * @tc.desc: vague + accurate after accept vague location permission, ret: DYNAMIC_OPER, state: PASS_OPER + DYNAMIC_OPER
 * @tc.type: FUNC
 * @tc.require: issueI5NOQI
 */
HWTEST_F(AccessTokenLocationRequestTest, GetSelfPermissionsState009, TestSize.Level1)
{
    std::vector<PermissionStateFull> permissionStateFulls;
    permissionStateFulls.emplace_back(g_locationTestStateVague02); // {0,2}
    permissionStateFulls.emplace_back(g_locationTestStateAccurate10); // {-1,0}

    AccessTokenIDEx tokenIdEx = AllocHapToken(permissionStateFulls, BACKGROUND_LOCATION_API_VERSION);
    AccessTokenID tokenID = tokenIdEx.tokenIdExStruct.tokenID;
    ASSERT_NE(INVALID_TOKENID, tokenID);
    ASSERT_EQ(0, SetSelfTokenID(tokenIdEx.tokenIDEx));

    PermissionListState permVague9 = {
        .permissionName = "ohos.permission.APPROXIMATELY_LOCATION",
        .state = SETTING_OPER,
    };
    PermissionListState permAccurate9 = {
        .permissionName = "ohos.permission.LOCATION",
        .state = SETTING_OPER,
    };

    std::vector<PermissionListState> permsList9;
    permsList9.emplace_back(permVague9);
    permsList9.emplace_back(permAccurate9);

    PermissionGrantInfo info;
    PermissionOper ret = AccessTokenKit::GetSelfPermissionsState(permsList9, info);
    ASSERT_EQ(DYNAMIC_OPER, ret);
    ASSERT_EQ(static_cast<uint32_t>(2), permsList9.size());
    ASSERT_EQ(PASS_OPER, permsList9[0].state);
    ASSERT_EQ(DYNAMIC_OPER, permsList9[1].state);
}

/**
 * @tc.name: GetSelfPermissionsState010
 * @tc.desc: vague + accurate after refuse vague location permission, ret: PASS_OPER, state: SETTING_OPER + INVALID_OPER
 * @tc.type: FUNC
 * @tc.require: issueI5NOQI
 */
HWTEST_F(AccessTokenLocationRequestTest, GetSelfPermissionsState010, TestSize.Level1)
{
    std::vector<PermissionStateFull> permissionStateFulls;
    permissionStateFulls.emplace_back(g_locationTestStateVague12); // {-1,2}
    permissionStateFulls.emplace_back(g_locationTestStateAccurate10); // {-1,0}

    AccessTokenIDEx tokenIdEx = AllocHapToken(permissionStateFulls, BACKGROUND_LOCATION_API_VERSION);
    AccessTokenID tokenID = tokenIdEx.tokenIdExStruct.tokenID;
    ASSERT_NE(INVALID_TOKENID, tokenID);
    ASSERT_EQ(0, SetSelfTokenID(tokenIdEx.tokenIDEx));

    PermissionListState permVague10 = {
        .permissionName = "ohos.permission.APPROXIMATELY_LOCATION",
        .state = SETTING_OPER,
    };
    PermissionListState permAccurate10 = {
        .permissionName = "ohos.permission.LOCATION",
        .state = SETTING_OPER,
    };

    std::vector<PermissionListState> permsList10;
    permsList10.emplace_back(permVague10);
    permsList10.emplace_back(permAccurate10);

    PermissionGrantInfo info;
    PermissionOper ret = AccessTokenKit::GetSelfPermissionsState(permsList10, info);
    ASSERT_EQ(PASS_OPER, ret);
    ASSERT_EQ(static_cast<uint32_t>(2), permsList10.size());
    ASSERT_EQ(SETTING_OPER, permsList10[0].state);
    ASSERT_EQ(INVALID_OPER, permsList10[1].state);
}

/**
 * @tc.name: GetSelfPermissionsState011
 * @tc.desc: vague + accurate after accept all location permissions, ret: PASS_OPER, state: PASS_OPER + PASS_OPER
 * @tc.type: FUNC
 * @tc.require: issueI5NOQI
 */
HWTEST_F(AccessTokenLocationRequestTest, GetSelfPermissionsState011, TestSize.Level1)
{
    std::vector<PermissionStateFull> permissionStateFulls;
    permissionStateFulls.emplace_back(g_locationTestStateVague02); // {0,2}
    permissionStateFulls.emplace_back(g_locationTestStateAccurate02); // {0,2}

    AccessTokenIDEx tokenIdEx = AllocHapToken(permissionStateFulls, BACKGROUND_LOCATION_API_VERSION);
    AccessTokenID tokenID = tokenIdEx.tokenIdExStruct.tokenID;
    ASSERT_NE(INVALID_TOKENID, tokenID);
    ASSERT_EQ(0, SetSelfTokenID(tokenIdEx.tokenIDEx));

    PermissionListState permVague11 = {
        .permissionName = "ohos.permission.APPROXIMATELY_LOCATION",
        .state = SETTING_OPER,
    };
    PermissionListState permAccurate11 = {
        .permissionName = "ohos.permission.LOCATION",
        .state = SETTING_OPER,
    };

    std::vector<PermissionListState> permsList11;
    permsList11.emplace_back(permVague11);
    permsList11.emplace_back(permAccurate11);

    PermissionGrantInfo info;
    PermissionOper ret = AccessTokenKit::GetSelfPermissionsState(permsList11, info);
    ASSERT_EQ(PASS_OPER, ret);
    ASSERT_EQ(static_cast<uint32_t>(2), permsList11.size());
    ASSERT_EQ(PASS_OPER, permsList11[0].state);
    ASSERT_EQ(PASS_OPER, permsList11[1].state);
}

/**
 * @tc.name: GetSelfPermissionsState012
 * @tc.desc: vague + background location permissions, ret: PASS_OPER, state: INVALID_OPER + INVALID_OPER
 * @tc.type: FUNC
 * @tc.require: issueI5NOQI
 */
HWTEST_F(AccessTokenLocationRequestTest, GetSelfPermissionsState012, TestSize.Level1)
{
    std::vector<PermissionStateFull> permissionStateFulls;
    permissionStateFulls.emplace_back(g_locationTestStateVague10); // {-1,0}
    permissionStateFulls.emplace_back(g_locationTestStateBack10); // {-1,0}

    AccessTokenIDEx tokenIdEx = AllocHapToken(permissionStateFulls, BACKGROUND_LOCATION_API_VERSION);
    AccessTokenID tokenID = tokenIdEx.tokenIdExStruct.tokenID;
    ASSERT_NE(INVALID_TOKENID, tokenID);
    ASSERT_EQ(0, SetSelfTokenID(tokenIdEx.tokenIDEx));

    PermissionListState permVague12 = {
        .permissionName = "ohos.permission.APPROXIMATELY_LOCATION",
        .state = SETTING_OPER,
    };
    PermissionListState permBack12 = {
        .permissionName = "ohos.permission.LOCATION_IN_BACKGROUND",
        .state = SETTING_OPER,
    };

    std::vector<PermissionListState> permsList12;
    permsList12.emplace_back(permVague12);
    permsList12.emplace_back(permBack12);

    PermissionGrantInfo info;
    PermissionOper ret = AccessTokenKit::GetSelfPermissionsState(permsList12, info);
    ASSERT_EQ(PASS_OPER, ret);
    ASSERT_EQ(static_cast<uint32_t>(2), permsList12.size());
    ASSERT_EQ(INVALID_OPER, permsList12[0].state);
    ASSERT_EQ(INVALID_OPER, permsList12[1].state);

    // grant back permission, get vague again, ret: DYNAMIC_OPER, state: DYNAMIC_OPER
    ASSERT_EQ(RET_SUCCESS, AccessTokenKit::GrantPermission(
        tokenID, "ohos.permission.LOCATION_IN_BACKGROUND", PermissionFlag::PERMISSION_USER_FIXED));
    std::vector<PermissionListState> permsList121;
    permsList121.emplace_back(permVague12);
    ret = AccessTokenKit::GetSelfPermissionsState(permsList121, info);
    ASSERT_EQ(DYNAMIC_OPER, ret);
    ASSERT_EQ(static_cast<uint32_t>(1), permsList121.size());
    ASSERT_EQ(DYNAMIC_OPER, permsList121[0].state);
}

/**
 * @tc.name: GetSelfPermissionsState013
 * @tc.desc: vague + background after accept vague location permission, ret: PASS_OPER, state: INVALID_OPER
 * @tc.type: FUNC
 * @tc.require: issueI5NOQI
 */
HWTEST_F(AccessTokenLocationRequestTest, GetSelfPermissionsState013, TestSize.Level1)
{
    std::vector<PermissionStateFull> permissionStateFulls;
    permissionStateFulls.emplace_back(g_locationTestStateVague02); // {0,2}
    permissionStateFulls.emplace_back(g_locationTestStateBack10); // {-1,0}

    AccessTokenIDEx tokenIdEx = AllocHapToken(permissionStateFulls, BACKGROUND_LOCATION_API_VERSION);
    AccessTokenID tokenID = tokenIdEx.tokenIdExStruct.tokenID;
    ASSERT_NE(INVALID_TOKENID, tokenID);
    ASSERT_EQ(0, SetSelfTokenID(tokenIdEx.tokenIDEx));

    PermissionListState permVague13 = {
        .permissionName = "ohos.permission.APPROXIMATELY_LOCATION",
        .state = SETTING_OPER,
    };
    PermissionListState permBack13 = {
        .permissionName = "ohos.permission.LOCATION_IN_BACKGROUND",
        .state = SETTING_OPER,
    };

    std::vector<PermissionListState> permsList13;
    permsList13.emplace_back(permVague13);
    permsList13.emplace_back(permBack13);

    PermissionGrantInfo info;
    PermissionOper ret = AccessTokenKit::GetSelfPermissionsState(permsList13, info);
    ASSERT_EQ(PASS_OPER, ret);
    ASSERT_EQ(static_cast<uint32_t>(2), permsList13.size());
    ASSERT_EQ(INVALID_OPER, permsList13[0].state);
    ASSERT_EQ(INVALID_OPER, permsList13[1].state);
    // grant back permission, get vague again, ret: PASS_OPER, state: PASS_OPER
    ASSERT_EQ(RET_SUCCESS, AccessTokenKit::GrantPermission(
        tokenID, "ohos.permission.LOCATION_IN_BACKGROUND", PermissionFlag::PERMISSION_USER_FIXED));
    std::vector<PermissionListState> permsList131;
    permsList131.emplace_back(permVague13);
    ret = AccessTokenKit::GetSelfPermissionsState(permsList131, info);
    ASSERT_EQ(PASS_OPER, ret);
    ASSERT_EQ(static_cast<uint32_t>(1), permsList131.size());
    ASSERT_EQ(PASS_OPER, permsList131[0].state);
}

/**
 * @tc.name: GetSelfPermissionsState014
 * @tc.desc: vague + background after refuse vague location permission, ret: PASS_OPER, state: INVALID_OPER
 * @tc.type: FUNC
 * @tc.require: issueI5NOQI
 */
HWTEST_F(AccessTokenLocationRequestTest, GetSelfPermissionsState014, TestSize.Level1)
{
    std::vector<PermissionStateFull> permissionStateFulls;
    permissionStateFulls.emplace_back(g_locationTestStateVague12); // {-1,2}
    permissionStateFulls.emplace_back(g_locationTestStateBack10); // {-1,0}

    AccessTokenIDEx tokenIdEx = AllocHapToken(permissionStateFulls, BACKGROUND_LOCATION_API_VERSION);
    AccessTokenID tokenID = tokenIdEx.tokenIdExStruct.tokenID;
    ASSERT_NE(INVALID_TOKENID, tokenID);
    ASSERT_EQ(0, SetSelfTokenID(tokenIdEx.tokenIDEx));

    PermissionListState permVague14 = {
        .permissionName = "ohos.permission.APPROXIMATELY_LOCATION",
        .state = SETTING_OPER,
    };
    PermissionListState permBack14 = {
        .permissionName = "ohos.permission.LOCATION_IN_BACKGROUND",
        .state = SETTING_OPER,
    };

    std::vector<PermissionListState> permsList14;
    permsList14.emplace_back(permVague14);
    permsList14.emplace_back(permBack14);

    PermissionGrantInfo info;
    PermissionOper ret = AccessTokenKit::GetSelfPermissionsState(permsList14, info);
    ASSERT_EQ(PASS_OPER, ret);
    ASSERT_EQ(static_cast<uint32_t>(2), permsList14.size());
    ASSERT_EQ(INVALID_OPER, permsList14[0].state);
    ASSERT_EQ(INVALID_OPER, permsList14[1].state);
    // grant back permission, get vague again, ret: PASS_OPER, state: SETTING_OPER
    ASSERT_EQ(RET_SUCCESS, AccessTokenKit::GrantPermission(
        tokenID, "ohos.permission.LOCATION_IN_BACKGROUND", PermissionFlag::PERMISSION_USER_FIXED));
    std::vector<PermissionListState> permsList141;
    permsList141.emplace_back(permVague14);
    ret = AccessTokenKit::GetSelfPermissionsState(permsList141, info);
    ASSERT_EQ(PASS_OPER, ret);
    ASSERT_EQ(static_cast<uint32_t>(1), permsList141.size());
    ASSERT_EQ(SETTING_OPER, permsList141[0].state);
}

/**
 * @tc.name: GetSelfPermissionsState015
 * @tc.desc: vague + background after accept all location permissions, ret: PASS_OPER, state: INVALID_OPER
 * @tc.type: FUNC
 * @tc.require: issueI5NOQI
 */
HWTEST_F(AccessTokenLocationRequestTest, GetSelfPermissionsState015, TestSize.Level1)
{
    std::vector<PermissionStateFull> permissionStateFulls;
    permissionStateFulls.emplace_back(g_locationTestStateVague02); // {0,2}
    permissionStateFulls.emplace_back(g_locationTestStateBack02); // {0,2}

    AccessTokenIDEx tokenIdEx = AllocHapToken(permissionStateFulls, BACKGROUND_LOCATION_API_VERSION);
    AccessTokenID tokenID = tokenIdEx.tokenIdExStruct.tokenID;
    ASSERT_NE(INVALID_TOKENID, tokenID);
    ASSERT_EQ(0, SetSelfTokenID(tokenIdEx.tokenIDEx));

    PermissionListState permVague15 = {
        .permissionName = "ohos.permission.APPROXIMATELY_LOCATION",
        .state = SETTING_OPER,
    };
    PermissionListState permBack15 = {
        .permissionName = "ohos.permission.LOCATION_IN_BACKGROUND",
        .state = SETTING_OPER,
    };

    std::vector<PermissionListState> permsList15;
    permsList15.emplace_back(permVague15);
    permsList15.emplace_back(permBack15);

    PermissionGrantInfo info;
    PermissionOper ret = AccessTokenKit::GetSelfPermissionsState(permsList15, info);
    ASSERT_EQ(PASS_OPER, ret);
    ASSERT_EQ(static_cast<uint32_t>(2), permsList15.size());
    ASSERT_EQ(INVALID_OPER, permsList15[0].state);
    ASSERT_EQ(INVALID_OPER, permsList15[1].state);
    // grant back permission, get vague again, ret: PASS_OPER, state: PASS_OPER
    ASSERT_EQ(RET_SUCCESS, AccessTokenKit::GrantPermission(
        tokenID, "ohos.permission.LOCATION_IN_BACKGROUND", PermissionFlag::PERMISSION_USER_FIXED));
    std::vector<PermissionListState> permsList151;
    permsList151.emplace_back(permVague15);
    ret = AccessTokenKit::GetSelfPermissionsState(permsList151, info);
    ASSERT_EQ(PASS_OPER, ret);
    ASSERT_EQ(static_cast<uint32_t>(1), permsList151.size());
    ASSERT_EQ(PASS_OPER, permsList151[0].state);
}

/**
 * @tc.name: GetSelfPermissionsState016
 * @tc.desc: accurate + background, ret: PASS_OPER, state: INVALID_OPER
 * @tc.type: FUNC
 * @tc.require: issueI5NOQI
 */
HWTEST_F(AccessTokenLocationRequestTest, GetSelfPermissionsState016, TestSize.Level1)
{
    std::vector<PermissionStateFull> permissionStateFulls;
    permissionStateFulls.emplace_back(g_locationTestStateAccurate10); // {-1,0}
    permissionStateFulls.emplace_back(g_locationTestStateBack10); // {-1,0}

    AccessTokenIDEx tokenIdEx = AllocHapToken(permissionStateFulls, BACKGROUND_LOCATION_API_VERSION);
    AccessTokenID tokenID = tokenIdEx.tokenIdExStruct.tokenID;
    ASSERT_NE(INVALID_TOKENID, tokenID);
    ASSERT_EQ(0, SetSelfTokenID(tokenIdEx.tokenIDEx));

    PermissionListState permAccurate16 = {
        .permissionName = "ohos.permission.LOCATION",
        .state = SETTING_OPER,
    };
    PermissionListState permBack16 = {
        .permissionName = "ohos.permission.LOCATION_IN_BACKGROUND",
        .state = SETTING_OPER,
    };

    std::vector<PermissionListState> permsList16;
    permsList16.emplace_back(permAccurate16);
    permsList16.emplace_back(permBack16);

    PermissionGrantInfo info;
    PermissionOper ret = AccessTokenKit::GetSelfPermissionsState(permsList16, info);
    ASSERT_EQ(PASS_OPER, ret);
    ASSERT_EQ(static_cast<uint32_t>(2), permsList16.size());
    ASSERT_EQ(INVALID_OPER, permsList16[0].state);
    ASSERT_EQ(INVALID_OPER, permsList16[1].state);

    // grant back permission, get accerate again, ret: PASS_OPER, state: INVALID_OPER
    ASSERT_EQ(RET_SUCCESS, AccessTokenKit::GrantPermission(
        tokenID, "ohos.permission.LOCATION_IN_BACKGROUND", PermissionFlag::PERMISSION_USER_FIXED));
    std::vector<PermissionListState> permsList161;
    permsList161.emplace_back(permAccurate16);
    ret = AccessTokenKit::GetSelfPermissionsState(permsList161, info);
    ASSERT_EQ(PASS_OPER, ret);
    ASSERT_EQ(static_cast<uint32_t>(1), permsList161.size());
    ASSERT_EQ(INVALID_OPER, permsList161[0].state);
}

/**
 * @tc.name: GetSelfPermissionsState017
 * @tc.desc: accurate + background with granted vague location, ret: PASS_OPER, state: INVALID_OPER
 * @tc.type: FUNC
 * @tc.require: issueI5NOQI
 */
HWTEST_F(AccessTokenLocationRequestTest, GetSelfPermissionsState017, TestSize.Level1)
{
    std::vector<PermissionStateFull> permissionStateFulls;
    permissionStateFulls.emplace_back(g_locationTestStateVague02); // {0,2}
    permissionStateFulls.emplace_back(g_locationTestStateAccurate10); // {-1,0}
    permissionStateFulls.emplace_back(g_locationTestStateBack10); // {-1,0}

    AccessTokenIDEx tokenIdEx = AllocHapToken(permissionStateFulls, BACKGROUND_LOCATION_API_VERSION);
    AccessTokenID tokenID = tokenIdEx.tokenIdExStruct.tokenID;
    ASSERT_NE(INVALID_TOKENID, tokenID);
    ASSERT_EQ(0, SetSelfTokenID(tokenIdEx.tokenIDEx));

    PermissionListState permAccurate17 = {
        .permissionName = "ohos.permission.LOCATION",
        .state = SETTING_OPER,
    };
    PermissionListState permBack17 = {
        .permissionName = "ohos.permission.LOCATION_IN_BACKGROUND",
        .state = SETTING_OPER,
    };

    std::vector<PermissionListState> permsList17;
    permsList17.emplace_back(permAccurate17);
    permsList17.emplace_back(permBack17);

    PermissionGrantInfo info;
    PermissionOper ret = AccessTokenKit::GetSelfPermissionsState(permsList17, info);
    ASSERT_EQ(PASS_OPER, ret);
    ASSERT_EQ(static_cast<uint32_t>(2), permsList17.size());
    ASSERT_EQ(INVALID_OPER, permsList17[0].state);
    ASSERT_EQ(INVALID_OPER, permsList17[1].state);

    // grant back permission, get accerate again, ret: PASS_OPER, state: INVALID_OPER
    ASSERT_EQ(RET_SUCCESS, AccessTokenKit::GrantPermission(
        tokenID, "ohos.permission.LOCATION_IN_BACKGROUND", PermissionFlag::PERMISSION_USER_FIXED));
    std::vector<PermissionListState> permsList171;
    permsList171.emplace_back(permAccurate17);
    ret = AccessTokenKit::GetSelfPermissionsState(permsList171, info);
    ASSERT_EQ(PASS_OPER, ret);
    ASSERT_EQ(static_cast<uint32_t>(1), permsList171.size());
    ASSERT_EQ(INVALID_OPER, permsList171[0].state);
}

/**
 * @tc.name: GetSelfPermissionsState018
 * @tc.desc: vague + accurate + background, ret: PASS_OPER, state: INVALID_OPER
 * @tc.type: FUNC
 * @tc.require: issueI5NOQI
 */
HWTEST_F(AccessTokenLocationRequestTest, GetSelfPermissionsState018, TestSize.Level1)
{
    std::vector<PermissionStateFull> permissionStateFulls;
    permissionStateFulls.emplace_back(g_locationTestStateVague10); // {-1,0}
    permissionStateFulls.emplace_back(g_locationTestStateAccurate10); // {-1,0}
    permissionStateFulls.emplace_back(g_locationTestStateBack10); // {-1,0}

    AccessTokenIDEx tokenIdEx = AllocHapToken(permissionStateFulls, BACKGROUND_LOCATION_API_VERSION);
    AccessTokenID tokenID = tokenIdEx.tokenIdExStruct.tokenID;
    ASSERT_NE(INVALID_TOKENID, tokenID);
    ASSERT_EQ(0, SetSelfTokenID(tokenIdEx.tokenIDEx));

    PermissionListState permVague18 = {
        .permissionName = "ohos.permission.APPROXIMATELY_LOCATION",
        .state = SETTING_OPER,
    };
    PermissionListState permAccurate18 = {
        .permissionName = "ohos.permission.LOCATION",
        .state = SETTING_OPER,
    };
    PermissionListState permBack18 = {
        .permissionName = "ohos.permission.LOCATION_IN_BACKGROUND",
        .state = SETTING_OPER,
    };

    std::vector<PermissionListState> permsList18;
    permsList18.emplace_back(permVague18);
    permsList18.emplace_back(permAccurate18);
    permsList18.emplace_back(permBack18);

    PermissionGrantInfo info;
    PermissionOper ret = AccessTokenKit::GetSelfPermissionsState(permsList18, info);
    ASSERT_EQ(PASS_OPER, ret);
    ASSERT_EQ(static_cast<uint32_t>(3), permsList18.size());
    ASSERT_EQ(INVALID_OPER, permsList18[0].state);
    ASSERT_EQ(INVALID_OPER, permsList18[1].state);
    ASSERT_EQ(INVALID_OPER, permsList18[2].state);

    // grant back permission, get accerate&vague again, ret: DYNAMIC_OPER, state: DYNAMIC_OPER
    ASSERT_EQ(RET_SUCCESS, AccessTokenKit::GrantPermission(
        tokenID, "ohos.permission.LOCATION_IN_BACKGROUND", PermissionFlag::PERMISSION_USER_FIXED));
    std::vector<PermissionListState> permsList181;
    permsList181.emplace_back(permVague18);
    permsList181.emplace_back(permAccurate18);
    ret = AccessTokenKit::GetSelfPermissionsState(permsList181, info);
    ASSERT_EQ(DYNAMIC_OPER, ret);
    ASSERT_EQ(static_cast<uint32_t>(2), permsList181.size());
    ASSERT_EQ(DYNAMIC_OPER, permsList181[0].state);
    ASSERT_EQ(DYNAMIC_OPER, permsList181[1].state);
}

/**
 * @tc.name: GetSelfPermissionsState019
 * @tc.desc: vague + accurate + background after accept vague location permission, ret: PASS_OPER, state: INVALID_OPER
 * @tc.type: FUNC
 * @tc.require: issueI5NOQI
 */
HWTEST_F(AccessTokenLocationRequestTest, GetSelfPermissionsState019, TestSize.Level1)
{
    std::vector<PermissionStateFull> permissionStateFulls;
    permissionStateFulls.emplace_back(g_locationTestStateVague02); // {0,2}
    permissionStateFulls.emplace_back(g_locationTestStateAccurate10); // {-1,0}
    permissionStateFulls.emplace_back(g_locationTestStateBack10); // {-1,0}

    AccessTokenIDEx tokenIdEx = AllocHapToken(permissionStateFulls, BACKGROUND_LOCATION_API_VERSION);
    AccessTokenID tokenID = tokenIdEx.tokenIdExStruct.tokenID;
    ASSERT_NE(INVALID_TOKENID, tokenID);
    ASSERT_EQ(0, SetSelfTokenID(tokenIdEx.tokenIDEx));

    PermissionListState permVague19 = {
        .permissionName = "ohos.permission.APPROXIMATELY_LOCATION",
        .state = SETTING_OPER,
    };
    PermissionListState permAccurate19 = {
        .permissionName = "ohos.permission.LOCATION",
        .state = SETTING_OPER,
    };
    PermissionListState permBack19 = {
        .permissionName = "ohos.permission.LOCATION_IN_BACKGROUND",
        .state = SETTING_OPER,
    };

    std::vector<PermissionListState> permsList19;
    permsList19.emplace_back(permVague19);
    permsList19.emplace_back(permAccurate19);
    permsList19.emplace_back(permBack19);

    PermissionGrantInfo info;
    PermissionOper ret = AccessTokenKit::GetSelfPermissionsState(permsList19, info);
    ASSERT_EQ(PASS_OPER, ret);
    ASSERT_EQ(static_cast<uint32_t>(3), permsList19.size());
    ASSERT_EQ(INVALID_OPER, permsList19[0].state);
    ASSERT_EQ(INVALID_OPER, permsList19[1].state);
    ASSERT_EQ(INVALID_OPER, permsList19[2].state);

    // grant back permission, get accerate&vague again, ret: DYNAMIC_OPER, state: PASS_OPER + DYNAMIC_OPER
    ASSERT_EQ(RET_SUCCESS, AccessTokenKit::GrantPermission(
        tokenID, "ohos.permission.LOCATION_IN_BACKGROUND", PermissionFlag::PERMISSION_USER_FIXED));
    std::vector<PermissionListState> permsList191;
    permsList191.emplace_back(permVague19);
    permsList191.emplace_back(permAccurate19);
    ret = AccessTokenKit::GetSelfPermissionsState(permsList191, info);
    ASSERT_EQ(DYNAMIC_OPER, ret);
    ASSERT_EQ(static_cast<uint32_t>(2), permsList191.size());
    ASSERT_EQ(PASS_OPER, permsList191[0].state);
    ASSERT_EQ(DYNAMIC_OPER, permsList191[1].state);
}

/**
 * @tc.name: GetSelfPermissionsState020
 * @tc.desc: vague + accurate + background after accept vague + accurate, ret: PASS_OPER, state: INVALID_OPER
 * @tc.type: FUNC
 * @tc.require: issueI5NOQI
 */
HWTEST_F(AccessTokenLocationRequestTest, GetSelfPermissionsState020, TestSize.Level1)
{
    std::vector<PermissionStateFull> permissionStateFulls;
    permissionStateFulls.emplace_back(g_locationTestStateVague02); // {0,2}
    permissionStateFulls.emplace_back(g_locationTestStateAccurate02); // {0,2}
    permissionStateFulls.emplace_back(g_locationTestStateBack10); // {-1,0}

    AccessTokenIDEx tokenIdEx = AllocHapToken(permissionStateFulls, BACKGROUND_LOCATION_API_VERSION);
    AccessTokenID tokenID = tokenIdEx.tokenIdExStruct.tokenID;
    ASSERT_NE(INVALID_TOKENID, tokenID);
    ASSERT_EQ(0, SetSelfTokenID(tokenIdEx.tokenIDEx));

    PermissionListState permVague20 = {
        .permissionName = "ohos.permission.APPROXIMATELY_LOCATION",
        .state = SETTING_OPER,
    };
    PermissionListState permAccurate20 = {
        .permissionName = "ohos.permission.LOCATION",
        .state = SETTING_OPER,
    };
    PermissionListState permBack20 = {
        .permissionName = "ohos.permission.LOCATION_IN_BACKGROUND",
        .state = SETTING_OPER,
    };

    std::vector<PermissionListState> permsList20;
    permsList20.emplace_back(permVague20);
    permsList20.emplace_back(permAccurate20);
    permsList20.emplace_back(permBack20);

    PermissionGrantInfo info;
    PermissionOper ret = AccessTokenKit::GetSelfPermissionsState(permsList20, info);
    ASSERT_EQ(PASS_OPER, ret);
    ASSERT_EQ(static_cast<uint32_t>(3), permsList20.size());
    ASSERT_EQ(INVALID_OPER, permsList20[0].state);
    ASSERT_EQ(INVALID_OPER, permsList20[1].state);
    ASSERT_EQ(INVALID_OPER, permsList20[2].state);

    // grant back permission, get accerate&vague again, ret: PASS_OPER, state: PASS_OPER + PASS_OPER
    ASSERT_EQ(RET_SUCCESS, AccessTokenKit::GrantPermission(
        tokenID, "ohos.permission.LOCATION_IN_BACKGROUND", PermissionFlag::PERMISSION_USER_FIXED));
    std::vector<PermissionListState> permsList201;
    permsList201.emplace_back(permVague20);
    permsList201.emplace_back(permAccurate20);
    ret = AccessTokenKit::GetSelfPermissionsState(permsList201, info);
    ASSERT_EQ(PASS_OPER, ret);
    ASSERT_EQ(static_cast<uint32_t>(2), permsList201.size());
    ASSERT_EQ(PASS_OPER, permsList201[0].state);
    ASSERT_EQ(PASS_OPER, permsList201[1].state);
}

/**
 * @tc.name: GetSelfPermissionsState021
 * @tc.desc: vague + accurate + background after accept vague + back, ret: PASS_OPER, state: INVALID_OPER
 * @tc.type: FUNC
 * @tc.require: issueI5NOQI
 */
HWTEST_F(AccessTokenLocationRequestTest, GetSelfPermissionsState021, TestSize.Level1)
{
    std::vector<PermissionStateFull> permissionStateFulls;
    permissionStateFulls.emplace_back(g_locationTestStateVague02); // {0,2}
    permissionStateFulls.emplace_back(g_locationTestStateAccurate10); // {-1,0}
    permissionStateFulls.emplace_back(g_locationTestStateBack02); // {0,2}

    AccessTokenIDEx tokenIdEx = AllocHapToken(permissionStateFulls, BACKGROUND_LOCATION_API_VERSION);
    AccessTokenID tokenID = tokenIdEx.tokenIdExStruct.tokenID;
    ASSERT_NE(INVALID_TOKENID, tokenID);
    ASSERT_EQ(0, SetSelfTokenID(tokenIdEx.tokenIDEx));

    PermissionListState permVague21 = {
        .permissionName = "ohos.permission.APPROXIMATELY_LOCATION",
        .state = SETTING_OPER,
    };
    PermissionListState permAccurate21 = {
        .permissionName = "ohos.permission.LOCATION",
        .state = SETTING_OPER,
    };
    PermissionListState permBack21 = {
        .permissionName = "ohos.permission.LOCATION_IN_BACKGROUND",
        .state = SETTING_OPER,
    };

    std::vector<PermissionListState> permsList21;
    permsList21.emplace_back(permVague21);
    permsList21.emplace_back(permAccurate21);
    permsList21.emplace_back(permBack21);

    PermissionGrantInfo info;
    PermissionOper ret = AccessTokenKit::GetSelfPermissionsState(permsList21, info);
    ASSERT_EQ(PASS_OPER, ret);
    ASSERT_EQ(static_cast<uint32_t>(3), permsList21.size());
    ASSERT_EQ(INVALID_OPER, permsList21[0].state);
    ASSERT_EQ(INVALID_OPER, permsList21[1].state);
    ASSERT_EQ(INVALID_OPER, permsList21[2].state);

    // get accerate&vague again, ret: DYNAMIC_OPER, state: PASS_OPER + DYNAMIC_OPER
    std::vector<PermissionListState> permsList211;
    permsList211.emplace_back(permVague21);
    permsList211.emplace_back(permAccurate21);
    ret = AccessTokenKit::GetSelfPermissionsState(permsList211, info);
    ASSERT_EQ(DYNAMIC_OPER, ret);
    ASSERT_EQ(static_cast<uint32_t>(2), permsList211.size());
    ASSERT_EQ(PASS_OPER, permsList211[0].state);
    ASSERT_EQ(DYNAMIC_OPER, permsList211[1].state);
}

/**
 * @tc.name: GetSelfPermissionsState022
 * @tc.desc: vague + accurate + background after accept all, ret: PASS_OPER, state: INVALID_OPER
 * @tc.type: FUNC
 * @tc.require: issueI5NOQI
 */
HWTEST_F(AccessTokenLocationRequestTest, GetSelfPermissionsState022, TestSize.Level1)
{
    std::vector<PermissionStateFull> permissionStateFulls;
    permissionStateFulls.emplace_back(g_locationTestStateVague02); // {0,2}
    permissionStateFulls.emplace_back(g_locationTestStateAccurate02); // {0,2}
    permissionStateFulls.emplace_back(g_locationTestStateBack02); // {0,2}

    AccessTokenIDEx tokenIdEx = AllocHapToken(permissionStateFulls, BACKGROUND_LOCATION_API_VERSION);
    AccessTokenID tokenID = tokenIdEx.tokenIdExStruct.tokenID;
    ASSERT_NE(INVALID_TOKENID, tokenID);
    ASSERT_EQ(0, SetSelfTokenID(tokenIdEx.tokenIDEx));

    PermissionListState permVague22 = {
        .permissionName = "ohos.permission.APPROXIMATELY_LOCATION",
        .state = SETTING_OPER,
    };
    PermissionListState permAccurate22 = {
        .permissionName = "ohos.permission.LOCATION",
        .state = SETTING_OPER,
    };
    PermissionListState permBack22 = {
        .permissionName = "ohos.permission.LOCATION_IN_BACKGROUND",
        .state = SETTING_OPER,
    };

    std::vector<PermissionListState> permsList22;
    permsList22.emplace_back(permVague22);
    permsList22.emplace_back(permAccurate22);
    permsList22.emplace_back(permBack22);

    PermissionGrantInfo info;
    PermissionOper ret = AccessTokenKit::GetSelfPermissionsState(permsList22, info);
    ASSERT_EQ(PASS_OPER, ret);
    ASSERT_EQ(static_cast<uint32_t>(3), permsList22.size());
    ASSERT_EQ(INVALID_OPER, permsList22[0].state);
    ASSERT_EQ(INVALID_OPER, permsList22[1].state);
    ASSERT_EQ(INVALID_OPER, permsList22[2].state);

    // get accerate&vague again, ret: PASS_OPER, state: PASS_OPER + PASS_OPER
    std::vector<PermissionListState> permsList221;
    permsList221.emplace_back(permVague22);
    permsList221.emplace_back(permAccurate22);
    ret = AccessTokenKit::GetSelfPermissionsState(permsList221, info);
    ASSERT_EQ(PASS_OPER, ret);
    ASSERT_EQ(static_cast<uint32_t>(2), permsList221.size());
    ASSERT_EQ(PASS_OPER, permsList221[0].state);
    ASSERT_EQ(PASS_OPER, permsList221[1].state);
}

/**
 * @tc.name: GetSelfPermissionsState023
 * @tc.desc: vague + accurate + background after refuse vague location permission, ret: PASS_OPER, state: INVALID_OPER
 * @tc.type: FUNC
 * @tc.require: issueI5NOQI
 */
HWTEST_F(AccessTokenLocationRequestTest, GetSelfPermissionsState023, TestSize.Level1)
{
    std::vector<PermissionStateFull> permissionStateFulls;
    permissionStateFulls.emplace_back(g_locationTestStateVague12); // {-1,2}
    permissionStateFulls.emplace_back(g_locationTestStateAccurate10); // {-1,0}
    permissionStateFulls.emplace_back(g_locationTestStateBack10); // {-1,0}

    AccessTokenIDEx tokenIdEx = AllocHapToken(permissionStateFulls, BACKGROUND_LOCATION_API_VERSION);
    AccessTokenID tokenID = tokenIdEx.tokenIdExStruct.tokenID;
    ASSERT_NE(INVALID_TOKENID, tokenID);
    ASSERT_EQ(0, SetSelfTokenID(tokenIdEx.tokenIDEx));

    PermissionListState permVague23 = {
        .permissionName = "ohos.permission.APPROXIMATELY_LOCATION",
        .state = SETTING_OPER,
    };
    PermissionListState permAccurate23 = {
        .permissionName = "ohos.permission.LOCATION",
        .state = SETTING_OPER,
    };
    PermissionListState permBack23 = {
        .permissionName = "ohos.permission.LOCATION_IN_BACKGROUND",
        .state = SETTING_OPER,
    };

    std::vector<PermissionListState> permsList23;
    permsList23.emplace_back(permVague23);
    permsList23.emplace_back(permAccurate23);
    permsList23.emplace_back(permBack23);

    PermissionGrantInfo info;
    PermissionOper ret = AccessTokenKit::GetSelfPermissionsState(permsList23, info);
    ASSERT_EQ(PASS_OPER, ret);
    ASSERT_EQ(static_cast<uint32_t>(3), permsList23.size());
    ASSERT_EQ(INVALID_OPER, permsList23[0].state);
    ASSERT_EQ(INVALID_OPER, permsList23[1].state);
    ASSERT_EQ(INVALID_OPER, permsList23[2].state);
    // grant back permission, get accerate&vague again, ret: PASS_OPER, state: SETTING_OPER + INVALID_OPER
    ASSERT_EQ(RET_SUCCESS, AccessTokenKit::GrantPermission(
        tokenID, "ohos.permission.LOCATION_IN_BACKGROUND", PermissionFlag::PERMISSION_USER_FIXED));
    std::vector<PermissionListState> permsList231;
    permsList231.emplace_back(permVague23);
    permsList231.emplace_back(permAccurate23);
    ret = AccessTokenKit::GetSelfPermissionsState(permsList231, info);
    ASSERT_EQ(PASS_OPER, ret);
    ASSERT_EQ(static_cast<uint32_t>(2), permsList231.size());
    ASSERT_EQ(SETTING_OPER, permsList231[0].state);
    ASSERT_EQ(INVALID_OPER, permsList231[1].state);
}

/**
 * @tc.name: GetSelfPermissionsState024
 * @tc.desc: vague + accurate + background after refuse vague + accurate, ret: PASS_OPER, state: INVALID_OPER
 * @tc.type: FUNC
 * @tc.require: issueI5NOQI
 */
HWTEST_F(AccessTokenLocationRequestTest, GetSelfPermissionsState024, TestSize.Level1)
{
    std::vector<PermissionStateFull> permissionStateFulls;
    permissionStateFulls.emplace_back(g_locationTestStateVague12); // {-1,2}
    permissionStateFulls.emplace_back(g_locationTestStateAccurate12); // {-1,2}
    permissionStateFulls.emplace_back(g_locationTestStateBack10); // {-1,0}

    AccessTokenIDEx tokenIdEx = AllocHapToken(permissionStateFulls, BACKGROUND_LOCATION_API_VERSION);
    AccessTokenID tokenID = tokenIdEx.tokenIdExStruct.tokenID;
    ASSERT_NE(INVALID_TOKENID, tokenID);
    ASSERT_EQ(0, SetSelfTokenID(tokenIdEx.tokenIDEx));

    PermissionListState permVague24 = {
        .permissionName = "ohos.permission.APPROXIMATELY_LOCATION",
        .state = SETTING_OPER,
    };
    PermissionListState permAccurate24 = {
        .permissionName = "ohos.permission.LOCATION",
        .state = SETTING_OPER,
    };
    PermissionListState permBack24 = {
        .permissionName = "ohos.permission.LOCATION_IN_BACKGROUND",
        .state = SETTING_OPER,
    };

    std::vector<PermissionListState> permsList24;
    permsList24.emplace_back(permVague24);
    permsList24.emplace_back(permAccurate24);
    permsList24.emplace_back(permBack24);

    PermissionGrantInfo info;
    PermissionOper ret = AccessTokenKit::GetSelfPermissionsState(permsList24, info);
    ASSERT_EQ(PASS_OPER, ret);
    ASSERT_EQ(static_cast<uint32_t>(3), permsList24.size());
    ASSERT_EQ(INVALID_OPER, permsList24[0].state);
    ASSERT_EQ(INVALID_OPER, permsList24[1].state);
    ASSERT_EQ(INVALID_OPER, permsList24[2].state);

    // grant back permission, get accerate&vague again, ret: PASS_OPER, state: SETTING_OPER + SETTING_OPER
    ASSERT_EQ(RET_SUCCESS, AccessTokenKit::GrantPermission(
        tokenID, "ohos.permission.LOCATION_IN_BACKGROUND", PermissionFlag::PERMISSION_USER_FIXED));
    std::vector<PermissionListState> permsList241;
    permsList241.emplace_back(permVague24);
    permsList241.emplace_back(permAccurate24);
    ret = AccessTokenKit::GetSelfPermissionsState(permsList241, info);
    ASSERT_EQ(PASS_OPER, ret);
    ASSERT_EQ(static_cast<uint32_t>(2), permsList241.size());
    ASSERT_EQ(SETTING_OPER, permsList241[0].state);
    ASSERT_EQ(SETTING_OPER, permsList241[1].state);

    // grant vague permission, get accerate&vague again, ret: PASS_OPER, state: PASS_OPER + SETTING_OPER
    ASSERT_EQ(RET_SUCCESS, AccessTokenKit::GrantPermission(
        tokenID, "ohos.permission.APPROXIMATELY_LOCATION", PermissionFlag::PERMISSION_USER_FIXED));
    ret = AccessTokenKit::GetSelfPermissionsState(permsList241, info);
    ASSERT_EQ(PASS_OPER, ret);
    ASSERT_EQ(static_cast<uint32_t>(2), permsList241.size());
    ASSERT_EQ(PASS_OPER, permsList241[0].state);
    ASSERT_EQ(SETTING_OPER, permsList241[1].state);
}

/**
 * @tc.name: GetSelfPermissionsState025
 * @tc.desc: vague + accurate + background after refuse vague + back, ret: PASS_OPER, state: INVALID_OPER
 * @tc.type: FUNC
 * @tc.require: issueI5NOQI
 */
HWTEST_F(AccessTokenLocationRequestTest, GetSelfPermissionsState025, TestSize.Level1)
{
    std::vector<PermissionStateFull> permissionStateFulls;
    permissionStateFulls.emplace_back(g_locationTestStateVague12); // {-1,2}
    permissionStateFulls.emplace_back(g_locationTestStateAccurate10); // {-1,0}
    permissionStateFulls.emplace_back(g_locationTestStateBack12); // {-1,2}

    AccessTokenIDEx tokenIdEx = AllocHapToken(permissionStateFulls, BACKGROUND_LOCATION_API_VERSION);
    AccessTokenID tokenID = tokenIdEx.tokenIdExStruct.tokenID;
    ASSERT_NE(INVALID_TOKENID, tokenID);
    ASSERT_EQ(0, SetSelfTokenID(tokenIdEx.tokenIDEx));

    PermissionListState permVague25 = {
        .permissionName = "ohos.permission.APPROXIMATELY_LOCATION",
        .state = SETTING_OPER,
    };
    PermissionListState permAccurate25 = {
        .permissionName = "ohos.permission.LOCATION",
        .state = SETTING_OPER,
    };
    PermissionListState permBack25 = {
        .permissionName = "ohos.permission.LOCATION_IN_BACKGROUND",
        .state = SETTING_OPER,
    };

    std::vector<PermissionListState> permsList25;
    permsList25.emplace_back(permVague25);
    permsList25.emplace_back(permAccurate25);
    permsList25.emplace_back(permBack25);

    PermissionGrantInfo info;
    PermissionOper ret = AccessTokenKit::GetSelfPermissionsState(permsList25, info);
    ASSERT_EQ(PASS_OPER, ret);
    ASSERT_EQ(static_cast<uint32_t>(3), permsList25.size());
    ASSERT_EQ(INVALID_OPER, permsList25[0].state);
    ASSERT_EQ(INVALID_OPER, permsList25[1].state);
    ASSERT_EQ(INVALID_OPER, permsList25[2].state);

    // grant back permission, get accerate&vague again, ret: PASS_OPER, state: SETTING_OPER + INVALID_OPER
    ASSERT_EQ(RET_SUCCESS, AccessTokenKit::GrantPermission(
        tokenID, "ohos.permission.LOCATION_IN_BACKGROUND", PermissionFlag::PERMISSION_USER_FIXED));
    std::vector<PermissionListState> permsList251;
    permsList251.emplace_back(permVague25);
    permsList251.emplace_back(permAccurate25);
    ret = AccessTokenKit::GetSelfPermissionsState(permsList251, info);
    ASSERT_EQ(PASS_OPER, ret);
    ASSERT_EQ(static_cast<uint32_t>(2), permsList251.size());
    ASSERT_EQ(SETTING_OPER, permsList251[0].state);
    ASSERT_EQ(INVALID_OPER, permsList251[1].state);

    // grant vague permission, get accerate&vague again, ret: DYNAMIC_OPER, state: PASS_OPER + DYNAMIC_OPER
    ASSERT_EQ(RET_SUCCESS, AccessTokenKit::GrantPermission(
        tokenID, "ohos.permission.APPROXIMATELY_LOCATION", PermissionFlag::PERMISSION_USER_FIXED));
    ret = AccessTokenKit::GetSelfPermissionsState(permsList251, info);
    ASSERT_EQ(DYNAMIC_OPER, ret);
    ASSERT_EQ(static_cast<uint32_t>(2), permsList251.size());
    ASSERT_EQ(PASS_OPER, permsList251[0].state);
    ASSERT_EQ(DYNAMIC_OPER, permsList251[1].state);
}

/**
 * @tc.name: GetSelfPermissionsState026
 * @tc.desc: vague + accurate + background after refuse all, ret: PASS_OPER, state: INVALID_OPER
 * @tc.type: FUNC
 * @tc.require: issueI5NOQI
 */
HWTEST_F(AccessTokenLocationRequestTest, GetSelfPermissionsState026, TestSize.Level1)
{
    std::vector<PermissionStateFull> permissionStateFulls;
    permissionStateFulls.emplace_back(g_locationTestStateVague12); // {-1,2}
    permissionStateFulls.emplace_back(g_locationTestStateAccurate12); // {-1,2}
    permissionStateFulls.emplace_back(g_locationTestStateBack12); // {-1,2}

    AccessTokenIDEx tokenIdEx = AllocHapToken(permissionStateFulls, BACKGROUND_LOCATION_API_VERSION);
    AccessTokenID tokenID = tokenIdEx.tokenIdExStruct.tokenID;
    ASSERT_NE(INVALID_TOKENID, tokenID);
    ASSERT_EQ(0, SetSelfTokenID(tokenIdEx.tokenIDEx));

    PermissionListState permVague26 = {
        .permissionName = "ohos.permission.APPROXIMATELY_LOCATION",
        .state = SETTING_OPER,
    };
    PermissionListState permAccurate26 = {
        .permissionName = "ohos.permission.LOCATION",
        .state = SETTING_OPER,
    };
    PermissionListState permBack26 = {
        .permissionName = "ohos.permission.LOCATION_IN_BACKGROUND",
        .state = SETTING_OPER,
    };

    std::vector<PermissionListState> permsList26;
    permsList26.emplace_back(permVague26);
    permsList26.emplace_back(permAccurate26);
    permsList26.emplace_back(permBack26);

    PermissionGrantInfo info;
    PermissionOper ret = AccessTokenKit::GetSelfPermissionsState(permsList26, info);
    ASSERT_EQ(PASS_OPER, ret);
    ASSERT_EQ(static_cast<uint32_t>(3), permsList26.size());
    ASSERT_EQ(INVALID_OPER, permsList26[0].state);
    ASSERT_EQ(INVALID_OPER, permsList26[1].state);
    ASSERT_EQ(INVALID_OPER, permsList26[2].state);

    // grant back permission, get accerate&vague again, ret: PASS_OPER, state: SETTING_OPER + SETTING_OPER
    ASSERT_EQ(RET_SUCCESS, AccessTokenKit::GrantPermission(
        tokenID, "ohos.permission.LOCATION_IN_BACKGROUND", PermissionFlag::PERMISSION_USER_FIXED));
    std::vector<PermissionListState> permsList261;
    permsList261.emplace_back(permVague26);
    permsList261.emplace_back(permAccurate26);
    ret = AccessTokenKit::GetSelfPermissionsState(permsList261, info);
    ASSERT_EQ(PASS_OPER, ret);
    ASSERT_EQ(static_cast<uint32_t>(2), permsList261.size());
    ASSERT_EQ(SETTING_OPER, permsList261[0].state);
    ASSERT_EQ(SETTING_OPER, permsList261[1].state);

    // grant vague permission, get accerate&vague again, ret: PASS_OPER, state: PASS_OPER + SETTING_OPER
    ASSERT_EQ(RET_SUCCESS, AccessTokenKit::GrantPermission(
        tokenID, "ohos.permission.APPROXIMATELY_LOCATION", PermissionFlag::PERMISSION_USER_FIXED));
    ret = AccessTokenKit::GetSelfPermissionsState(permsList261, info);
    ASSERT_EQ(PASS_OPER, ret);
    ASSERT_EQ(static_cast<uint32_t>(2), permsList261.size());
    ASSERT_EQ(PASS_OPER, permsList261[0].state);
    ASSERT_EQ(SETTING_OPER, permsList261[1].state);
}

/**
 * @tc.name: GetSelfPermissionsState027
 * @tc.desc: vague + accurate + back + other, ret: DYNAMIC_OPER, state: INVALID_OPER + PASS_OPER/DYNAMIC_OPER
 * @tc.type: FUNC
 * @tc.require: issueI5NOQI
 */
HWTEST_F(AccessTokenLocationRequestTest, GetSelfPermissionsState027, TestSize.Level1)
{
    std::vector<PermissionStateFull> permissionStateFulls;
    permissionStateFulls.emplace_back(g_locationTestStateVague10); // {-1,0}
    permissionStateFulls.emplace_back(g_locationTestStateAccurate10); // {-1,0}
    permissionStateFulls.emplace_back(g_locationTestStateBack10); // {-1,0}
    permissionStateFulls.emplace_back(g_locationTestStateSystemGrant); // {0,4}
    permissionStateFulls.emplace_back(g_locationTestStateUserGrant); // {-1,0}

    AccessTokenIDEx tokenIdEx = AllocHapToken(permissionStateFulls, BACKGROUND_LOCATION_API_VERSION);
    AccessTokenID tokenID = tokenIdEx.tokenIdExStruct.tokenID;
    ASSERT_NE(INVALID_TOKENID, tokenID);
    ASSERT_EQ(0, SetSelfTokenID(tokenIdEx.tokenIDEx));

    PermissionListState permVague27 = {
        .permissionName = "ohos.permission.APPROXIMATELY_LOCATION",
        .state = SETTING_OPER,
    };
    PermissionListState permAccurate27 = {
        .permissionName = "ohos.permission.LOCATION",
        .state = SETTING_OPER,
    };
    PermissionListState permBack27 = {
        .permissionName = "ohos.permission.LOCATION_IN_BACKGROUND",
        .state = SETTING_OPER,
    };
    PermissionListState permSystem27 = {
        .permissionName = "ohos.permission.UPDATE_SYSTEM",
        .state = SETTING_OPER,
    };
    PermissionListState permUser27 = {
        .permissionName = "ohos.permission.CAMERA",
        .state = SETTING_OPER,
    };

    std::vector<PermissionListState> permsList27;
    permsList27.emplace_back(permVague27);
    permsList27.emplace_back(permAccurate27);
    permsList27.emplace_back(permBack27);
    permsList27.emplace_back(permSystem27);
    permsList27.emplace_back(permUser27);

    PermissionGrantInfo info;
    PermissionOper ret = AccessTokenKit::GetSelfPermissionsState(permsList27, info);
    ASSERT_EQ(DYNAMIC_OPER, ret);
    ASSERT_EQ(static_cast<uint32_t>(5), permsList27.size());
    ASSERT_EQ(INVALID_OPER, permsList27[0].state);
    ASSERT_EQ(INVALID_OPER, permsList27[1].state);
    ASSERT_EQ(INVALID_OPER, permsList27[2].state);
    ASSERT_EQ(PASS_OPER, permsList27[3].state);
    ASSERT_EQ(DYNAMIC_OPER, permsList27[4].state);
}

/**
 * @tc.name: GetSelfPermissionsState028
 * @tc.desc: vague + api8
 * @tc.type: FUNC
 * @tc.require: issueI5NOQI
 */
HWTEST_F(AccessTokenLocationRequestTest, GetSelfPermissionsState028, TestSize.Level1)
{
    std::vector<PermissionStateFull> permissionStateFulls;
    permissionStateFulls.emplace_back(g_locationTestStateVague10); // {-1,0}

    AccessTokenIDEx tokenIdEx = AllocHapToken(permissionStateFulls, DEFAULT_API_VERSION);
    AccessTokenID tokenID = tokenIdEx.tokenIdExStruct.tokenID;
    ASSERT_NE(INVALID_TOKENID, tokenID);
    ASSERT_EQ(0, SetSelfTokenID(tokenIdEx.tokenIDEx));

    PermissionListState permVague28 = {
        .permissionName = "ohos.permission.APPROXIMATELY_LOCATION",
        .state = SETTING_OPER,
    };

    std::vector<PermissionListState> permsList28;
    permsList28.emplace_back(permVague28);

    PermissionGrantInfo info;
    PermissionOper ret = AccessTokenKit::GetSelfPermissionsState(permsList28, info);
    ASSERT_EQ(PASS_OPER, ret);
    ASSERT_EQ(static_cast<uint32_t>(1), permsList28.size());
    ASSERT_EQ(INVALID_OPER, permsList28[0].state);
}

/**
 * @tc.name: GetSelfPermissionsState029
 * @tc.desc: accurate + api8
 * @tc.type: FUNC
 * @tc.require: issueI5NOQI
 */
HWTEST_F(AccessTokenLocationRequestTest, GetSelfPermissionsState029, TestSize.Level1)
{
    std::vector<PermissionStateFull> permissionStateFulls;
    permissionStateFulls.emplace_back(g_locationTestStateAccurate10); // {-1,0}

    AccessTokenIDEx tokenIdEx = AllocHapToken(permissionStateFulls, DEFAULT_API_VERSION);
    AccessTokenID tokenID = tokenIdEx.tokenIdExStruct.tokenID;
    ASSERT_NE(INVALID_TOKENID, tokenID);
    ASSERT_EQ(0, SetSelfTokenID(tokenIdEx.tokenIDEx));

    PermissionListState permAccurate29 = {
        .permissionName = "ohos.permission.LOCATION",
        .state = SETTING_OPER,
    };

    std::vector<PermissionListState> permsList29;
    permsList29.emplace_back(permAccurate29);

    PermissionGrantInfo info;
    PermissionOper ret = AccessTokenKit::GetSelfPermissionsState(permsList29, info);
    ASSERT_EQ(DYNAMIC_OPER, ret);
    ASSERT_EQ(static_cast<uint32_t>(1), permsList29.size());
    ASSERT_EQ(DYNAMIC_OPER, permsList29[0].state);
}

/**
 * @tc.name: GetSelfPermissionsState030
 * @tc.desc: back + api8
 * @tc.type: FUNC
 * @tc.require: issueI5NOQI
 */
HWTEST_F(AccessTokenLocationRequestTest, GetSelfPermissionsState030, TestSize.Level1)
{
    std::vector<PermissionStateFull> permissionStateFulls;
    permissionStateFulls.emplace_back(g_locationTestStateBack10); // {-1,0}

    AccessTokenIDEx tokenIdEx = AllocHapToken(permissionStateFulls, DEFAULT_API_VERSION);
    AccessTokenID tokenID = tokenIdEx.tokenIdExStruct.tokenID;
    ASSERT_NE(INVALID_TOKENID, tokenID);
    ASSERT_EQ(0, SetSelfTokenID(tokenIdEx.tokenIDEx));

    PermissionListState permBack30 = {
        .permissionName = "ohos.permission.LOCATION_IN_BACKGROUND",
        .state = SETTING_OPER,
    };

    std::vector<PermissionListState> permsList30;
    permsList30.emplace_back(permBack30);

    PermissionGrantInfo info;
    PermissionOper ret = AccessTokenKit::GetSelfPermissionsState(permsList30, info);
    ASSERT_EQ(DYNAMIC_OPER, ret);
    ASSERT_EQ(static_cast<uint32_t>(1), permsList30.size());
    ASSERT_EQ(DYNAMIC_OPER, permsList30[0].state);
}

/**
 * @tc.name: GetSelfPermissionsState031
 * @tc.desc: vague + accurate + api8
 * @tc.type: FUNC
 * @tc.require: issueI5NOQI
 */
HWTEST_F(AccessTokenLocationRequestTest, GetSelfPermissionsState031, TestSize.Level1)
{
    std::vector<PermissionStateFull> permissionStateFulls;
    permissionStateFulls.emplace_back(g_locationTestStateVague10); // {-1,0}
    permissionStateFulls.emplace_back(g_locationTestStateAccurate10); // {-1,0}

    AccessTokenIDEx tokenIdEx = AllocHapToken(permissionStateFulls, DEFAULT_API_VERSION);
    AccessTokenID tokenID = tokenIdEx.tokenIdExStruct.tokenID;
    ASSERT_NE(INVALID_TOKENID, tokenID);
    ASSERT_EQ(0, SetSelfTokenID(tokenIdEx.tokenIDEx));

    PermissionListState permVague31 = {
        .permissionName = "ohos.permission.APPROXIMATELY_LOCATION",
        .state = SETTING_OPER,
    };
    PermissionListState permAccurate31 = {
        .permissionName = "ohos.permission.LOCATION",
        .state = SETTING_OPER,
    };

    std::vector<PermissionListState> permsList31;
    permsList31.emplace_back(permVague31);
    permsList31.emplace_back(permAccurate31);

    PermissionGrantInfo info;
    PermissionOper ret = AccessTokenKit::GetSelfPermissionsState(permsList31, info);
    ASSERT_EQ(DYNAMIC_OPER, ret);
    ASSERT_EQ(static_cast<uint32_t>(2), permsList31.size());
    ASSERT_EQ(INVALID_OPER, permsList31[0].state);
    ASSERT_EQ(DYNAMIC_OPER, permsList31[1].state);
}

/**
 * @tc.name: GetSelfPermissionsState032
 * @tc.desc: vague + back + api8
 * @tc.type: FUNC
 * @tc.require: issueI5NOQI
 */
HWTEST_F(AccessTokenLocationRequestTest, GetSelfPermissionsState032, TestSize.Level1)
{
    std::vector<PermissionStateFull> permissionStateFulls;
    permissionStateFulls.emplace_back(g_locationTestStateVague10); // {-1,0}
    permissionStateFulls.emplace_back(g_locationTestStateBack10); // {-1,0}

    AccessTokenIDEx tokenIdEx = AllocHapToken(permissionStateFulls, DEFAULT_API_VERSION);
    AccessTokenID tokenID = tokenIdEx.tokenIdExStruct.tokenID;
    ASSERT_NE(INVALID_TOKENID, tokenID);
    ASSERT_EQ(0, SetSelfTokenID(tokenIdEx.tokenIDEx));

    PermissionListState permVague32 = {
        .permissionName = "ohos.permission.APPROXIMATELY_LOCATION",
        .state = SETTING_OPER,
    };
    PermissionListState permBack32 = {
        .permissionName = "ohos.permission.LOCATION_IN_BACKGROUND",
        .state = SETTING_OPER,
    };

    std::vector<PermissionListState> permsList32;
    permsList32.emplace_back(permVague32);
    permsList32.emplace_back(permBack32);

    PermissionGrantInfo info;
    PermissionOper ret = AccessTokenKit::GetSelfPermissionsState(permsList32, info);
    ASSERT_EQ(DYNAMIC_OPER, ret);
    ASSERT_EQ(static_cast<uint32_t>(2), permsList32.size());
    ASSERT_EQ(INVALID_OPER, permsList32[0].state);
    ASSERT_EQ(DYNAMIC_OPER, permsList32[1].state);
}

/**
 * @tc.name: GetSelfPermissionsState033
 * @tc.desc: accurate + back + api8
 * @tc.type: FUNC
 * @tc.require: issueI5NOQI
 */
HWTEST_F(AccessTokenLocationRequestTest, GetSelfPermissionsState033, TestSize.Level1)
{
    std::vector<PermissionStateFull> permissionStateFulls;
    permissionStateFulls.emplace_back(g_locationTestStateAccurate10); // {-1,0}
    permissionStateFulls.emplace_back(g_locationTestStateBack10); // {-1,0}

    AccessTokenIDEx tokenIdEx = AllocHapToken(permissionStateFulls, DEFAULT_API_VERSION);
    AccessTokenID tokenID = tokenIdEx.tokenIdExStruct.tokenID;
    ASSERT_NE(INVALID_TOKENID, tokenID);
    ASSERT_EQ(0, SetSelfTokenID(tokenIdEx.tokenIDEx));

    PermissionListState permAccurate33 = {
        .permissionName = "ohos.permission.LOCATION",
        .state = SETTING_OPER,
    };
    PermissionListState permBack33 = {
        .permissionName = "ohos.permission.LOCATION_IN_BACKGROUND",
        .state = SETTING_OPER,
    };

    std::vector<PermissionListState> permsList33;
    permsList33.emplace_back(permAccurate33);
    permsList33.emplace_back(permBack33);

    PermissionGrantInfo info;
    PermissionOper ret = AccessTokenKit::GetSelfPermissionsState(permsList33, info);
    ASSERT_EQ(DYNAMIC_OPER, ret);
    ASSERT_EQ(static_cast<uint32_t>(2), permsList33.size());
    ASSERT_EQ(DYNAMIC_OPER, permsList33[0].state);
    ASSERT_EQ(DYNAMIC_OPER, permsList33[0].state);
}

/**
 * @tc.name: GetSelfPermissionsState034
 * @tc.desc: vague + accurate + back + api8
 * @tc.type: FUNC
 * @tc.require: issueI5NOQI
 */
HWTEST_F(AccessTokenLocationRequestTest, GetSelfPermissionsState034, TestSize.Level1)
{
    std::vector<PermissionStateFull> permissionStateFulls;
    permissionStateFulls.emplace_back(g_locationTestStateVague10); // {-1,0}
    permissionStateFulls.emplace_back(g_locationTestStateAccurate10); // {-1,0}
    permissionStateFulls.emplace_back(g_locationTestStateBack10); // {-1,0}

    AccessTokenIDEx tokenIdEx = AllocHapToken(permissionStateFulls, DEFAULT_API_VERSION);
    AccessTokenID tokenID = tokenIdEx.tokenIdExStruct.tokenID;
    ASSERT_NE(INVALID_TOKENID, tokenID);
    ASSERT_EQ(0, SetSelfTokenID(tokenIdEx.tokenIDEx));

    PermissionListState permVague34 = {
        .permissionName = "ohos.permission.APPROXIMATELY_LOCATION",
        .state = SETTING_OPER,
    };
    PermissionListState permAccurate34 = {
        .permissionName = "ohos.permission.LOCATION",
        .state = SETTING_OPER,
    };
    PermissionListState permBack34 = {
        .permissionName = "ohos.permission.LOCATION_IN_BACKGROUND",
        .state = SETTING_OPER,
    };

    std::vector<PermissionListState> permsList34;
    permsList34.emplace_back(permVague34);
    permsList34.emplace_back(permAccurate34);
    permsList34.emplace_back(permBack34);

    PermissionGrantInfo info;
    PermissionOper ret = AccessTokenKit::GetSelfPermissionsState(permsList34, info);
    ASSERT_EQ(DYNAMIC_OPER, ret);
    ASSERT_EQ(static_cast<uint32_t>(3), permsList34.size());
    ASSERT_EQ(INVALID_OPER, permsList34[0].state);
    ASSERT_EQ(DYNAMIC_OPER, permsList34[1].state);
    ASSERT_EQ(DYNAMIC_OPER, permsList34[2].state);
}

/**
 * @tc.name: GetSelfPermissionsState035
 * @tc.desc: vague + background location permissions api9, ret: DYNAMIC_OPER, state: DYNAMIC_OPER + SETTING_OPER
 * @tc.type: FUNC
 * @tc.require: issueI5NOQI
 */
HWTEST_F(AccessTokenLocationRequestTest, GetSelfPermissionsState035, TestSize.Level1)
{
    std::vector<PermissionStateFull> permissionStateFulls;
    permissionStateFulls.emplace_back(g_locationTestStateVague10); // {-1,0}
    permissionStateFulls.emplace_back(g_locationTestStateBack10); // {-1,0}

    AccessTokenIDEx tokenIdEx = AllocHapToken(permissionStateFulls, VAGUE_LOCATION_API_VERSION);
    AccessTokenID tokenID = tokenIdEx.tokenIdExStruct.tokenID;
    ASSERT_NE(INVALID_TOKENID, tokenID);
    ASSERT_EQ(0, SetSelfTokenID(tokenIdEx.tokenIDEx));

    PermissionListState permVague35 = {
        .permissionName = "ohos.permission.APPROXIMATELY_LOCATION",
        .state = SETTING_OPER,
    };
    PermissionListState permBack35 = {
        .permissionName = "ohos.permission.LOCATION_IN_BACKGROUND",
        .state = SETTING_OPER,
    };

    std::vector<PermissionListState> permsList35;
    permsList35.emplace_back(permVague35);
    permsList35.emplace_back(permBack35);

    PermissionGrantInfo info;
    PermissionOper ret = AccessTokenKit::GetSelfPermissionsState(permsList35, info);
    ASSERT_EQ(DYNAMIC_OPER, ret);
    ASSERT_EQ(static_cast<uint32_t>(2), permsList35.size());
    ASSERT_EQ(DYNAMIC_OPER, permsList35[0].state);
    ASSERT_EQ(SETTING_OPER, permsList35[1].state);

    // grant back permission, get vague again, ret: DYNAMIC_OPER, state: DYNAMIC_OPER
    ASSERT_EQ(RET_SUCCESS, AccessTokenKit::GrantPermission(
        tokenID, "ohos.permission.LOCATION_IN_BACKGROUND", PermissionFlag::PERMISSION_USER_FIXED));
    std::vector<PermissionListState> permsList351;
    permsList351.emplace_back(permVague35);
    ret = AccessTokenKit::GetSelfPermissionsState(permsList351, info);
    ASSERT_EQ(DYNAMIC_OPER, ret);
    ASSERT_EQ(static_cast<uint32_t>(1), permsList351.size());
    ASSERT_EQ(DYNAMIC_OPER, permsList351[0].state);
}

/**
 * @tc.name: GetSelfPermissionsState036
 * @tc.desc: vague + background after accept vague location permission api9
 * @tc.type: FUNC
 * @tc.require: issueI5NOQI
 */
HWTEST_F(AccessTokenLocationRequestTest, GetSelfPermissionsState036, TestSize.Level1)
{
    std::vector<PermissionStateFull> permissionStateFulls;
    permissionStateFulls.emplace_back(g_locationTestStateVague02); // {0,2}
    permissionStateFulls.emplace_back(g_locationTestStateBack10); // {-1,0}

    AccessTokenIDEx tokenIdEx = AllocHapToken(permissionStateFulls, VAGUE_LOCATION_API_VERSION);
    AccessTokenID tokenID = tokenIdEx.tokenIdExStruct.tokenID;
    ASSERT_NE(INVALID_TOKENID, tokenID);
    ASSERT_EQ(0, SetSelfTokenID(tokenIdEx.tokenIDEx));

    PermissionListState permVague36 = {
        .permissionName = "ohos.permission.APPROXIMATELY_LOCATION",
        .state = SETTING_OPER,
    };
    PermissionListState permBack36 = {
        .permissionName = "ohos.permission.LOCATION_IN_BACKGROUND",
        .state = SETTING_OPER,
    };

    std::vector<PermissionListState> permsList36;
    permsList36.emplace_back(permVague36);
    permsList36.emplace_back(permBack36);

    PermissionGrantInfo info;
    PermissionOper ret = AccessTokenKit::GetSelfPermissionsState(permsList36, info);
    ASSERT_EQ(PASS_OPER, ret);
    ASSERT_EQ(static_cast<uint32_t>(2), permsList36.size());
    ASSERT_EQ(PASS_OPER, permsList36[0].state);
    ASSERT_EQ(INVALID_OPER, permsList36[1].state);
}

/**
 * @tc.name: GetSelfPermissionsState037
 * @tc.desc: vague + background after refuse vague location permission api9
 * @tc.type: FUNC
 * @tc.require: issueI5NOQI
 */
HWTEST_F(AccessTokenLocationRequestTest, GetSelfPermissionsState037, TestSize.Level1)
{
    std::vector<PermissionStateFull> permissionStateFulls;
    permissionStateFulls.emplace_back(g_locationTestStateVague12); // {-1,2}
    permissionStateFulls.emplace_back(g_locationTestStateBack10); // {-1,0}

    AccessTokenIDEx tokenIdEx = AllocHapToken(permissionStateFulls, VAGUE_LOCATION_API_VERSION);
    AccessTokenID tokenID = tokenIdEx.tokenIdExStruct.tokenID;
    ASSERT_NE(INVALID_TOKENID, tokenID);
    ASSERT_EQ(0, SetSelfTokenID(tokenIdEx.tokenIDEx));

    PermissionListState permVague37 = {
        .permissionName = "ohos.permission.APPROXIMATELY_LOCATION",
        .state = SETTING_OPER,
    };
    PermissionListState permBack37 = {
        .permissionName = "ohos.permission.LOCATION_IN_BACKGROUND",
        .state = SETTING_OPER,
    };

    std::vector<PermissionListState> permsList37;
    permsList37.emplace_back(permVague37);
    permsList37.emplace_back(permBack37);

    PermissionGrantInfo info;
    PermissionOper ret = AccessTokenKit::GetSelfPermissionsState(permsList37, info);
    ASSERT_EQ(PASS_OPER, ret);
    ASSERT_EQ(static_cast<uint32_t>(2), permsList37.size());
    ASSERT_EQ(SETTING_OPER, permsList37[0].state);
    ASSERT_EQ(INVALID_OPER, permsList37[1].state);
}

/**
 * @tc.name: GetSelfPermissionsState038
 * @tc.desc: vague + background after accept all location permissions api9
 * @tc.type: FUNC
 * @tc.require: issueI5NOQI
 */
HWTEST_F(AccessTokenLocationRequestTest, GetSelfPermissionsState038, TestSize.Level1)
{
    std::vector<PermissionStateFull> permissionStateFulls;
    permissionStateFulls.emplace_back(g_locationTestStateVague02); // {0,2}
    permissionStateFulls.emplace_back(g_locationTestStateBack02); // {0,2}

    AccessTokenIDEx tokenIdEx = AllocHapToken(permissionStateFulls, VAGUE_LOCATION_API_VERSION);
    AccessTokenID tokenID = tokenIdEx.tokenIdExStruct.tokenID;
    ASSERT_NE(INVALID_TOKENID, tokenID);
    ASSERT_EQ(0, SetSelfTokenID(tokenIdEx.tokenIDEx));

    PermissionListState permVague38 = {
        .permissionName = "ohos.permission.APPROXIMATELY_LOCATION",
        .state = SETTING_OPER,
    };
    PermissionListState permBack38 = {
        .permissionName = "ohos.permission.LOCATION_IN_BACKGROUND",
        .state = SETTING_OPER,
    };

    std::vector<PermissionListState> permsList38;
    permsList38.emplace_back(permVague38);
    permsList38.emplace_back(permBack38);

    PermissionGrantInfo info;
    PermissionOper ret = AccessTokenKit::GetSelfPermissionsState(permsList38, info);
    ASSERT_EQ(PASS_OPER, ret);
    ASSERT_EQ(static_cast<uint32_t>(2), permsList38.size());
    ASSERT_EQ(PASS_OPER, permsList38[0].state);
    ASSERT_EQ(PASS_OPER, permsList38[1].state);
}

/**
 * @tc.name: GetSelfPermissionsState039
 * @tc.desc: accurate + background api9, ret: PASS_OPER, state: INVALID_OPER
 * @tc.type: FUNC
 * @tc.require: issueI5NOQI
 */
HWTEST_F(AccessTokenLocationRequestTest, GetSelfPermissionsState039, TestSize.Level1)
{
    std::vector<PermissionStateFull> permissionStateFulls;
    permissionStateFulls.emplace_back(g_locationTestStateAccurate10); // {-1,0}
    permissionStateFulls.emplace_back(g_locationTestStateBack10); // {-1,0}

    AccessTokenIDEx tokenIdEx = AllocHapToken(permissionStateFulls, VAGUE_LOCATION_API_VERSION);
    AccessTokenID tokenID = tokenIdEx.tokenIdExStruct.tokenID;
    ASSERT_NE(INVALID_TOKENID, tokenID);
    ASSERT_EQ(0, SetSelfTokenID(tokenIdEx.tokenIDEx));

    PermissionListState permAccurate39 = {
        .permissionName = "ohos.permission.LOCATION",
        .state = SETTING_OPER,
    };
    PermissionListState permBack39 = {
        .permissionName = "ohos.permission.LOCATION_IN_BACKGROUND",
        .state = SETTING_OPER,
    };

    std::vector<PermissionListState> permsList39;
    permsList39.emplace_back(permAccurate39);
    permsList39.emplace_back(permBack39);

    PermissionGrantInfo info;
    PermissionOper ret = AccessTokenKit::GetSelfPermissionsState(permsList39, info);
    ASSERT_EQ(PASS_OPER, ret);
    ASSERT_EQ(static_cast<uint32_t>(2), permsList39.size());
    ASSERT_EQ(INVALID_OPER, permsList39[0].state);
    ASSERT_EQ(INVALID_OPER, permsList39[1].state);
}

/**
 * @tc.name: GetSelfPermissionsState040
 * @tc.desc: accurate + background with granted vague location api9, ret: PASS_OPER, state: INVALID_OPER + INVALID_OPER
 * @tc.type: FUNC
 * @tc.require: issueI5NOQI
 */
HWTEST_F(AccessTokenLocationRequestTest, GetSelfPermissionsState040, TestSize.Level1)
{
    std::vector<PermissionStateFull> permissionStateFulls;
    permissionStateFulls.emplace_back(g_locationTestStateVague02); // {0,2}
    permissionStateFulls.emplace_back(g_locationTestStateAccurate10); // {-1,0}
    permissionStateFulls.emplace_back(g_locationTestStateBack10); // {-1,0}

    AccessTokenIDEx tokenIdEx = AllocHapToken(permissionStateFulls, VAGUE_LOCATION_API_VERSION);
    AccessTokenID tokenID = tokenIdEx.tokenIdExStruct.tokenID;
    ASSERT_NE(INVALID_TOKENID, tokenID);
    ASSERT_EQ(0, SetSelfTokenID(tokenIdEx.tokenIDEx));

    PermissionListState permAccurate40 = {
        .permissionName = "ohos.permission.LOCATION",
        .state = SETTING_OPER,
    };
    PermissionListState permBack40 = {
        .permissionName = "ohos.permission.LOCATION_IN_BACKGROUND",
        .state = SETTING_OPER,
    };

    std::vector<PermissionListState> permsList40;
    permsList40.emplace_back(permAccurate40);
    permsList40.emplace_back(permBack40);

    PermissionGrantInfo info;
    PermissionOper ret = AccessTokenKit::GetSelfPermissionsState(permsList40, info);
    ASSERT_EQ(PASS_OPER, ret);
    ASSERT_EQ(static_cast<uint32_t>(2), permsList40.size());
    ASSERT_EQ(INVALID_OPER, permsList40[0].state);
    ASSERT_EQ(INVALID_OPER, permsList40[1].state);
}

/**
 * @tc.name: GetSelfPermissionsState041
 * @tc.desc: vague + accurate + background api9, ret: DYNAMIC_OPER, state: DYNAMIC_OPER + DYNAMIC_OPER + SETTING_OPER
 * @tc.type: FUNC
 * @tc.require: issueI5NOQI
 */
HWTEST_F(AccessTokenLocationRequestTest, GetSelfPermissionsState041, TestSize.Level1)
{
    std::vector<PermissionStateFull> permissionStateFulls;
    permissionStateFulls.emplace_back(g_locationTestStateVague10); // {-1,0}
    permissionStateFulls.emplace_back(g_locationTestStateAccurate10); // {-1,0}
    permissionStateFulls.emplace_back(g_locationTestStateBack10); // {-1,0}

    AccessTokenIDEx tokenIdEx = AllocHapToken(permissionStateFulls, VAGUE_LOCATION_API_VERSION);
    AccessTokenID tokenID = tokenIdEx.tokenIdExStruct.tokenID;
    ASSERT_NE(INVALID_TOKENID, tokenID);
    ASSERT_EQ(0, SetSelfTokenID(tokenIdEx.tokenIDEx));

    PermissionListState permVague41 = {
        .permissionName = "ohos.permission.APPROXIMATELY_LOCATION",
        .state = SETTING_OPER,
    };
    PermissionListState permAccurate41 = {
        .permissionName = "ohos.permission.LOCATION",
        .state = SETTING_OPER,
    };
    PermissionListState permBack41 = {
        .permissionName = "ohos.permission.LOCATION_IN_BACKGROUND",
        .state = SETTING_OPER,
    };

    std::vector<PermissionListState> permsList41;
    permsList41.emplace_back(permVague41);
    permsList41.emplace_back(permAccurate41);
    permsList41.emplace_back(permBack41);

    PermissionGrantInfo info;
    PermissionOper ret = AccessTokenKit::GetSelfPermissionsState(permsList41, info);
    ASSERT_EQ(DYNAMIC_OPER, ret);
    ASSERT_EQ(static_cast<uint32_t>(3), permsList41.size());
    ASSERT_EQ(DYNAMIC_OPER, permsList41[0].state);
    ASSERT_EQ(DYNAMIC_OPER, permsList41[1].state);
    ASSERT_EQ(SETTING_OPER, permsList41[2].state);
}

/**
 * @tc.name: GetSelfPermissionsState042
 * @tc.desc: vague + accurate + background after accept vague location permission api9
 * @tc.type: FUNC
 * @tc.require: issueI5NOQI
 */
HWTEST_F(AccessTokenLocationRequestTest, GetSelfPermissionsState042, TestSize.Level1)
{
    std::vector<PermissionStateFull> permissionStateFulls;
    permissionStateFulls.emplace_back(g_locationTestStateVague02); // {0,2}
    permissionStateFulls.emplace_back(g_locationTestStateAccurate10); // {-1,0}
    permissionStateFulls.emplace_back(g_locationTestStateBack10); // {-1,0}

    AccessTokenIDEx tokenIdEx = AllocHapToken(permissionStateFulls, VAGUE_LOCATION_API_VERSION);
    AccessTokenID tokenID = tokenIdEx.tokenIdExStruct.tokenID;
    ASSERT_NE(INVALID_TOKENID, tokenID);
    ASSERT_EQ(0, SetSelfTokenID(tokenIdEx.tokenIDEx));

    PermissionListState permVague42 = {
        .permissionName = "ohos.permission.APPROXIMATELY_LOCATION",
        .state = SETTING_OPER,
    };
    PermissionListState permAccurate42 = {
        .permissionName = "ohos.permission.LOCATION",
        .state = SETTING_OPER,
    };
    PermissionListState permBack42 = {
        .permissionName = "ohos.permission.LOCATION_IN_BACKGROUND",
        .state = SETTING_OPER,
    };

    std::vector<PermissionListState> permsList42;
    permsList42.emplace_back(permVague42);
    permsList42.emplace_back(permAccurate42);
    permsList42.emplace_back(permBack42);

    PermissionGrantInfo info;
    PermissionOper ret = AccessTokenKit::GetSelfPermissionsState(permsList42, info);
    ASSERT_EQ(DYNAMIC_OPER, ret);
    ASSERT_EQ(static_cast<uint32_t>(3), permsList42.size());
    ASSERT_EQ(PASS_OPER, permsList42[0].state);
    ASSERT_EQ(DYNAMIC_OPER, permsList42[1].state);
    ASSERT_EQ(SETTING_OPER, permsList42[2].state);
}

/**
 * @tc.name: GetSelfPermissionsState043
 * @tc.desc: vague + accurate + background after accept vague + accurate, api9
 * @tc.type: FUNC
 * @tc.require: issueI5NOQI
 */
HWTEST_F(AccessTokenLocationRequestTest, GetSelfPermissionsState043, TestSize.Level1)
{
    std::vector<PermissionStateFull> permissionStateFulls;
    permissionStateFulls.emplace_back(g_locationTestStateVague02); // {0,2}
    permissionStateFulls.emplace_back(g_locationTestStateAccurate02); // {0,2}
    permissionStateFulls.emplace_back(g_locationTestStateBack10); // {-1,0}

    AccessTokenIDEx tokenIdEx = AllocHapToken(permissionStateFulls, VAGUE_LOCATION_API_VERSION);
    AccessTokenID tokenID = tokenIdEx.tokenIdExStruct.tokenID;
    ASSERT_NE(INVALID_TOKENID, tokenID);
    ASSERT_EQ(0, SetSelfTokenID(tokenIdEx.tokenIDEx));

    PermissionListState permVague20 = {
        .permissionName = "ohos.permission.APPROXIMATELY_LOCATION",
        .state = SETTING_OPER,
    };
    PermissionListState permAccurate20 = {
        .permissionName = "ohos.permission.LOCATION",
        .state = SETTING_OPER,
    };
    PermissionListState permBack20 = {
        .permissionName = "ohos.permission.LOCATION_IN_BACKGROUND",
        .state = SETTING_OPER,
    };

    std::vector<PermissionListState> permsList43;
    permsList43.emplace_back(permVague20);
    permsList43.emplace_back(permAccurate20);
    permsList43.emplace_back(permBack20);

    PermissionGrantInfo info;
    PermissionOper ret = AccessTokenKit::GetSelfPermissionsState(permsList43, info);
    ASSERT_EQ(PASS_OPER, ret);
    ASSERT_EQ(static_cast<uint32_t>(3), permsList43.size());
    ASSERT_EQ(PASS_OPER, permsList43[0].state);
    ASSERT_EQ(PASS_OPER, permsList43[1].state);
    ASSERT_EQ(INVALID_OPER, permsList43[2].state);
}

/**
 * @tc.name: GetSelfPermissionsState044
 * @tc.desc: vague + accurate + background after accept vague + back, api9
 * @tc.type: FUNC
 * @tc.require: issueI5NOQI
 */
HWTEST_F(AccessTokenLocationRequestTest, GetSelfPermissionsState044, TestSize.Level1)
{
    std::vector<PermissionStateFull> permissionStateFulls;
    permissionStateFulls.emplace_back(g_locationTestStateVague02); // {0,2}
    permissionStateFulls.emplace_back(g_locationTestStateAccurate10); // {-1,0}
    permissionStateFulls.emplace_back(g_locationTestStateBack02); // {0,2}

    AccessTokenIDEx tokenIdEx = AllocHapToken(permissionStateFulls, VAGUE_LOCATION_API_VERSION);
    AccessTokenID tokenID = tokenIdEx.tokenIdExStruct.tokenID;
    ASSERT_NE(INVALID_TOKENID, tokenID);
    ASSERT_EQ(0, SetSelfTokenID(tokenIdEx.tokenIDEx));

    PermissionListState permVague44 = {
        .permissionName = "ohos.permission.APPROXIMATELY_LOCATION",
        .state = SETTING_OPER,
    };
    PermissionListState permAccurate44 = {
        .permissionName = "ohos.permission.LOCATION",
        .state = SETTING_OPER,
    };
    PermissionListState permBack44 = {
        .permissionName = "ohos.permission.LOCATION_IN_BACKGROUND",
        .state = SETTING_OPER,
    };

    std::vector<PermissionListState> permsList44;
    permsList44.emplace_back(permVague44);
    permsList44.emplace_back(permAccurate44);
    permsList44.emplace_back(permBack44);

    PermissionGrantInfo info;
    PermissionOper ret = AccessTokenKit::GetSelfPermissionsState(permsList44, info);
    ASSERT_EQ(DYNAMIC_OPER, ret);
    ASSERT_EQ(static_cast<uint32_t>(3), permsList44.size());
    ASSERT_EQ(PASS_OPER, permsList44[0].state);
    ASSERT_EQ(DYNAMIC_OPER, permsList44[1].state);
    ASSERT_EQ(PASS_OPER, permsList44[2].state);
}

/**
 * @tc.name: GetSelfPermissionsState045
 * @tc.desc: vague + accurate + background after accept all, api9
 * @tc.type: FUNC
 * @tc.require: issueI5NOQI
 */
HWTEST_F(AccessTokenLocationRequestTest, GetSelfPermissionsState045, TestSize.Level1)
{
    std::vector<PermissionStateFull> permissionStateFulls;
    permissionStateFulls.emplace_back(g_locationTestStateVague02); // {0,2}
    permissionStateFulls.emplace_back(g_locationTestStateAccurate02); // {0,2}
    permissionStateFulls.emplace_back(g_locationTestStateBack02); // {0,2}

    AccessTokenIDEx tokenIdEx = AllocHapToken(permissionStateFulls, VAGUE_LOCATION_API_VERSION);
    AccessTokenID tokenID = tokenIdEx.tokenIdExStruct.tokenID;
    ASSERT_NE(INVALID_TOKENID, tokenID);
    ASSERT_EQ(0, SetSelfTokenID(tokenIdEx.tokenIDEx));

    PermissionListState permVague45 = {
        .permissionName = "ohos.permission.APPROXIMATELY_LOCATION",
        .state = SETTING_OPER,
    };
    PermissionListState permAccurate45 = {
        .permissionName = "ohos.permission.LOCATION",
        .state = SETTING_OPER,
    };
    PermissionListState permBack45 = {
        .permissionName = "ohos.permission.LOCATION_IN_BACKGROUND",
        .state = SETTING_OPER,
    };

    std::vector<PermissionListState> permsList45;
    permsList45.emplace_back(permVague45);
    permsList45.emplace_back(permAccurate45);
    permsList45.emplace_back(permBack45);

    PermissionGrantInfo info;
    PermissionOper ret = AccessTokenKit::GetSelfPermissionsState(permsList45, info);
    ASSERT_EQ(PASS_OPER, ret);
    ASSERT_EQ(static_cast<uint32_t>(3), permsList45.size());
    ASSERT_EQ(PASS_OPER, permsList45[0].state);
    ASSERT_EQ(PASS_OPER, permsList45[1].state);
    ASSERT_EQ(PASS_OPER, permsList45[2].state);
}

/**
 * @tc.name: GetSelfPermissionsState046
 * @tc.desc: vague + accurate + background after refuse vague location permission, api9
 * @tc.type: FUNC
 * @tc.require: issueI5NOQI
 */
HWTEST_F(AccessTokenLocationRequestTest, GetSelfPermissionsState046, TestSize.Level1)
{
    std::vector<PermissionStateFull> permissionStateFulls;
    permissionStateFulls.emplace_back(g_locationTestStateVague12); // {-1,2}
    permissionStateFulls.emplace_back(g_locationTestStateAccurate10); // {-1,0}
    permissionStateFulls.emplace_back(g_locationTestStateBack10); // {-1,0}

    AccessTokenIDEx tokenIdEx = AllocHapToken(permissionStateFulls, VAGUE_LOCATION_API_VERSION);
    AccessTokenID tokenID = tokenIdEx.tokenIdExStruct.tokenID;
    ASSERT_NE(INVALID_TOKENID, tokenID);
    ASSERT_EQ(0, SetSelfTokenID(tokenIdEx.tokenIDEx));

    PermissionListState permVague46 = {
        .permissionName = "ohos.permission.APPROXIMATELY_LOCATION",
        .state = SETTING_OPER,
    };
    PermissionListState permAccurate46 = {
        .permissionName = "ohos.permission.LOCATION",
        .state = SETTING_OPER,
    };
    PermissionListState permBack46 = {
        .permissionName = "ohos.permission.LOCATION_IN_BACKGROUND",
        .state = SETTING_OPER,
    };

    std::vector<PermissionListState> permsList46;
    permsList46.emplace_back(permVague46);
    permsList46.emplace_back(permAccurate46);
    permsList46.emplace_back(permBack46);

    PermissionGrantInfo info;
    PermissionOper ret = AccessTokenKit::GetSelfPermissionsState(permsList46, info);
    ASSERT_EQ(PASS_OPER, ret);
    ASSERT_EQ(static_cast<uint32_t>(3), permsList46.size());
    ASSERT_EQ(SETTING_OPER, permsList46[0].state);
    ASSERT_EQ(INVALID_OPER, permsList46[1].state);
    ASSERT_EQ(INVALID_OPER, permsList46[2].state);
}

/**
 * @tc.name: GetSelfPermissionsState047
 * @tc.desc: vague + accurate + background after refuse vague + accurate, api9
 * @tc.type: FUNC
 * @tc.require: issueI5NOQI
 */
HWTEST_F(AccessTokenLocationRequestTest, GetSelfPermissionsState047, TestSize.Level1)
{
    std::vector<PermissionStateFull> permissionStateFulls;
    permissionStateFulls.emplace_back(g_locationTestStateVague12); // {-1,2}
    permissionStateFulls.emplace_back(g_locationTestStateAccurate12); // {-1,2}
    permissionStateFulls.emplace_back(g_locationTestStateBack10); // {-1,0}

    AccessTokenIDEx tokenIdEx = AllocHapToken(permissionStateFulls, VAGUE_LOCATION_API_VERSION);
    AccessTokenID tokenID = tokenIdEx.tokenIdExStruct.tokenID;
    ASSERT_NE(INVALID_TOKENID, tokenID);
    ASSERT_EQ(0, SetSelfTokenID(tokenIdEx.tokenIDEx));

    PermissionListState permVague47 = {
        .permissionName = "ohos.permission.APPROXIMATELY_LOCATION",
        .state = SETTING_OPER,
    };
    PermissionListState permAccurate47 = {
        .permissionName = "ohos.permission.LOCATION",
        .state = SETTING_OPER,
    };
    PermissionListState permBack47 = {
        .permissionName = "ohos.permission.LOCATION_IN_BACKGROUND",
        .state = SETTING_OPER,
    };

    std::vector<PermissionListState> permsList47;
    permsList47.emplace_back(permVague47);
    permsList47.emplace_back(permAccurate47);
    permsList47.emplace_back(permBack47);

    PermissionGrantInfo info;
    PermissionOper ret = AccessTokenKit::GetSelfPermissionsState(permsList47, info);
    ASSERT_EQ(PASS_OPER, ret);
    ASSERT_EQ(static_cast<uint32_t>(3), permsList47.size());
    ASSERT_EQ(SETTING_OPER, permsList47[0].state);
    ASSERT_EQ(SETTING_OPER, permsList47[1].state);
    ASSERT_EQ(INVALID_OPER, permsList47[2].state);
}

/**
 * @tc.name: GetSelfPermissionsState048
 * @tc.desc: vague + accurate + background after refuse vague + back, api9
 * @tc.type: FUNC
 * @tc.require: issueI5NOQI
 */
HWTEST_F(AccessTokenLocationRequestTest, GetSelfPermissionsState048, TestSize.Level1)
{
    std::vector<PermissionStateFull> permissionStateFulls;
    permissionStateFulls.emplace_back(g_locationTestStateVague12); // {-1,2}
    permissionStateFulls.emplace_back(g_locationTestStateAccurate10); // {-1,0}
    permissionStateFulls.emplace_back(g_locationTestStateBack12); // {-1,2}

    AccessTokenIDEx tokenIdEx = AllocHapToken(permissionStateFulls, VAGUE_LOCATION_API_VERSION);
    AccessTokenID tokenID = tokenIdEx.tokenIdExStruct.tokenID;
    ASSERT_NE(INVALID_TOKENID, tokenID);
    ASSERT_EQ(0, SetSelfTokenID(tokenIdEx.tokenIDEx));

    PermissionListState permVague48 = {
        .permissionName = "ohos.permission.APPROXIMATELY_LOCATION",
        .state = SETTING_OPER,
    };
    PermissionListState permAccurate48 = {
        .permissionName = "ohos.permission.LOCATION",
        .state = SETTING_OPER,
    };
    PermissionListState permBack48 = {
        .permissionName = "ohos.permission.LOCATION_IN_BACKGROUND",
        .state = SETTING_OPER,
    };

    std::vector<PermissionListState> permsList48;
    permsList48.emplace_back(permVague48);
    permsList48.emplace_back(permAccurate48);
    permsList48.emplace_back(permBack48);

    PermissionGrantInfo info;
    PermissionOper ret = AccessTokenKit::GetSelfPermissionsState(permsList48, info);
    ASSERT_EQ(PASS_OPER, ret);
    ASSERT_EQ(static_cast<uint32_t>(3), permsList48.size());
    ASSERT_EQ(SETTING_OPER, permsList48[0].state);
    ASSERT_EQ(INVALID_OPER, permsList48[1].state);
    ASSERT_EQ(SETTING_OPER, permsList48[2].state);
}

/**
 * @tc.name: GetSelfPermissionsState049
 * @tc.desc: vague + accurate + background after refuse all, api9
 * @tc.type: FUNC
 * @tc.require: issueI5NOQI
 */
HWTEST_F(AccessTokenLocationRequestTest, GetSelfPermissionsState049, TestSize.Level1)
{
    std::vector<PermissionStateFull> permissionStateFulls;
    permissionStateFulls.emplace_back(g_locationTestStateVague12); // {-1,2}
    permissionStateFulls.emplace_back(g_locationTestStateAccurate12); // {-1,2}
    permissionStateFulls.emplace_back(g_locationTestStateBack12); // {-1,2}

    AccessTokenIDEx tokenIdEx = AllocHapToken(permissionStateFulls, VAGUE_LOCATION_API_VERSION);
    AccessTokenID tokenID = tokenIdEx.tokenIdExStruct.tokenID;
    ASSERT_NE(INVALID_TOKENID, tokenID);
    ASSERT_EQ(0, SetSelfTokenID(tokenIdEx.tokenIDEx));

    PermissionListState permVague49 = {
        .permissionName = "ohos.permission.APPROXIMATELY_LOCATION",
        .state = SETTING_OPER,
    };
    PermissionListState permAccurate49 = {
        .permissionName = "ohos.permission.LOCATION",
        .state = SETTING_OPER,
    };
    PermissionListState permBack49 = {
        .permissionName = "ohos.permission.LOCATION_IN_BACKGROUND",
        .state = SETTING_OPER,
    };

    std::vector<PermissionListState> permsList49;
    permsList49.emplace_back(permVague49);
    permsList49.emplace_back(permAccurate49);
    permsList49.emplace_back(permBack49);

    PermissionGrantInfo info;
    PermissionOper ret = AccessTokenKit::GetSelfPermissionsState(permsList49, info);
    ASSERT_EQ(PASS_OPER, ret);
    ASSERT_EQ(static_cast<uint32_t>(3), permsList49.size());
    ASSERT_EQ(SETTING_OPER, permsList49[0].state);
    ASSERT_EQ(SETTING_OPER, permsList49[1].state);
    ASSERT_EQ(SETTING_OPER, permsList49[2].state);
}

/**
 * @tc.name: GetSelfPermissionsState050
 * @tc.desc: vague + accurate + back + other, api9
 * @tc.type: FUNC
 * @tc.require: issueI5NOQI
 */
HWTEST_F(AccessTokenLocationRequestTest, GetSelfPermissionsState050, TestSize.Level1)
{
    std::vector<PermissionStateFull> permissionStateFulls;
    permissionStateFulls.emplace_back(g_locationTestStateVague10); // {-1,0}
    permissionStateFulls.emplace_back(g_locationTestStateAccurate10); // {-1,0}
    permissionStateFulls.emplace_back(g_locationTestStateBack10); // {-1,0}
    permissionStateFulls.emplace_back(g_locationTestStateSystemGrant); // {0,4}
    permissionStateFulls.emplace_back(g_locationTestStateUserGrant); // {-1,0}

    AccessTokenIDEx tokenIdEx = AllocHapToken(permissionStateFulls, VAGUE_LOCATION_API_VERSION);
    AccessTokenID tokenID = tokenIdEx.tokenIdExStruct.tokenID;
    ASSERT_NE(INVALID_TOKENID, tokenID);
    ASSERT_EQ(0, SetSelfTokenID(tokenIdEx.tokenIDEx));

    PermissionListState permVague50 = {
        .permissionName = "ohos.permission.APPROXIMATELY_LOCATION",
        .state = SETTING_OPER,
    };
    PermissionListState permAccurate50 = {
        .permissionName = "ohos.permission.LOCATION",
        .state = SETTING_OPER,
    };
    PermissionListState permBack50 = {
        .permissionName = "ohos.permission.LOCATION_IN_BACKGROUND",
        .state = SETTING_OPER,
    };
    PermissionListState permSystem50 = {
        .permissionName = "ohos.permission.UPDATE_SYSTEM",
        .state = SETTING_OPER,
    };
    PermissionListState permUser50 = {
        .permissionName = "ohos.permission.CAMERA",
        .state = SETTING_OPER,
    };

    std::vector<PermissionListState> permsList50;
    permsList50.emplace_back(permVague50);
    permsList50.emplace_back(permAccurate50);
    permsList50.emplace_back(permBack50);
    permsList50.emplace_back(permSystem50);
    permsList50.emplace_back(permUser50);

    PermissionGrantInfo info;
    PermissionOper ret = AccessTokenKit::GetSelfPermissionsState(permsList50, info);
    ASSERT_EQ(DYNAMIC_OPER, ret);
    ASSERT_EQ(static_cast<uint32_t>(5), permsList50.size());
    ASSERT_EQ(DYNAMIC_OPER, permsList50[0].state);
    ASSERT_EQ(DYNAMIC_OPER, permsList50[1].state);
    ASSERT_EQ(SETTING_OPER, permsList50[2].state);
    ASSERT_EQ(PASS_OPER, permsList50[3].state);
    ASSERT_EQ(DYNAMIC_OPER, permsList50[4].state);
}
} // namespace AccessToken
} // namespace Security
} // namespace OHOS
