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

#include "accesstoken_kit.h"
#include "hap_token_info.h"
#include "permission_def.h"
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

void AllocHapToken(std::vector<PermissionStateFull>& permissionStateFulls, int32_t apiVersion)
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

    AccessTokenIDEx tokenIdEx = AccessTokenKit::AllocHapToken(info, policy);
    ASSERT_NE(INVALID_TOKENID, tokenIdEx.tokenIDEx);
    ASSERT_EQ(0, SetSelfTokenID(tokenIdEx.tokenIDEx));
}

// GetSelfPermissionsState001:vague + api9
// GetSelfPermissionsState002:vague after refuse + api9
// GetSelfPermissionsState003:vague after accept + api9
// GetSelfPermissionsState004:accurate + api9
// GetSelfPermissionsState005:accurate + granted vague + api9
// GetSelfPermissionsState006:back + api9
// GetSelfPermissionsState007:back + granted vague + api9
// GetSelfPermissionsState008:vague + accurate + api9
// GetSelfPermissionsState009:vague + accurate after accept vague location permission + api9
// GetSelfPermissionsState010:vague + accurate after refuse vague location permission + api9
// GetSelfPermissionsState011:vague + accurate after accept all + api9
// GetSelfPermissionsState012:vague + back + api9
// GetSelfPermissionsState013:vague + back after accept vague location permission + api9
// GetSelfPermissionsState014:vague + back after refuse vague location permission + api9
// GetSelfPermissionsState015:vague + back after accept all + api9
// GetSelfPermissionsState016:accurate + back + api9
// GetSelfPermissionsState017:accurate + back + granted vague + api9
// GetSelfPermissionsState018:vague + accurate + back + api9
// GetSelfPermissionsState019:vague + accurate + back after accept vague location permission + api9
// GetSelfPermissionsState020:vague + accurate + back after accept vague + accurate + api9
// GetSelfPermissionsState021:vague + accurate + back after accept vague + back + api9
// GetSelfPermissionsState022:vague + accurate + back after accept all + api9
// GetSelfPermissionsState023:vague + accurate + back after refuse vague location permission + api9
// GetSelfPermissionsState024:vague + accurate + back after refuse vague + accurate + api9
// GetSelfPermissionsState025:vague + accurate + back after refuse vague + back + api9
// GetSelfPermissionsState026:vague + accurate + back after refuse all + api9
// GetSelfPermissionsState027:vague + accurate + back + other permissions + api9
// GetSelfPermissionsState028:vague + api8
// GetSelfPermissionsState029:accurate + api8
// GetSelfPermissionsState030:back + api8
// GetSelfPermissionsState031:vague + accurate + api8
// GetSelfPermissionsState032:vague + back + api8
// GetSelfPermissionsState033:accurate + back + api8
// GetSelfPermissionsState034:vague + accurate + back + api8

/**
 * @tc.name: GetSelfPermissionsState001
 * @tc.desc: only vague location permission
 * @tc.type: FUNC
 * @tc.require: issueI5NOQI
 */
HWTEST_F(AccessTokenLocationRequestTest, GetSelfPermissionsState001, TestSize.Level1)
{
    std::vector<PermissionStateFull> permissionStateFulls;
    permissionStateFulls.emplace_back(g_locationTestStateVague10); // {-1,0}

    AllocHapToken(permissionStateFulls, VAGUE_LOCATION_API_VERSION);

    PermissionListState permVague1 = {
        .permissionName = "ohos.permission.APPROXIMATELY_LOCATION",
        .state = -1,
    };

    std::vector<PermissionListState> permsList1;
    permsList1.emplace_back(permVague1);

    PermissionOper ret = AccessTokenKit::GetSelfPermissionsState(permsList1);
    ASSERT_EQ(DYNAMIC_OPER, ret);
    ASSERT_EQ(static_cast<uint32_t>(1), permsList1.size());
    ASSERT_EQ(DYNAMIC_OPER, permsList1[0].state);
}

/**
 * @tc.name: GetSelfPermissionsState002
 * @tc.desc: only vague location permission after refuse
 * @tc.type: FUNC
 * @tc.require: issueI5NOQI
 */
HWTEST_F(AccessTokenLocationRequestTest, GetSelfPermissionsState002, TestSize.Level1)
{
    std::vector<PermissionStateFull> permissionStateFulls;
    permissionStateFulls.emplace_back(g_locationTestStateVague12); // {-1,2}

    AllocHapToken(permissionStateFulls, VAGUE_LOCATION_API_VERSION);

    PermissionListState permVague2 = {
        .permissionName = "ohos.permission.APPROXIMATELY_LOCATION",
        .state = -1,
    };

    std::vector<PermissionListState> permsList2;
    permsList2.emplace_back(permVague2);

    PermissionOper ret = AccessTokenKit::GetSelfPermissionsState(permsList2);
    ASSERT_EQ(PASS_OPER, ret);
    ASSERT_EQ(static_cast<uint32_t>(1), permsList2.size());
    ASSERT_EQ(SETTING_OPER, permsList2[0].state);
}

/**
 * @tc.name: GetSelfPermissionsState003
 * @tc.desc: only vague location permission after accept
 * @tc.type: FUNC
 * @tc.require: issueI5NOQI
 */
HWTEST_F(AccessTokenLocationRequestTest, GetSelfPermissionsState003, TestSize.Level1)
{
    std::vector<PermissionStateFull> permissionStateFulls;
    permissionStateFulls.emplace_back(g_locationTestStateVague02); // {0,2}

    AllocHapToken(permissionStateFulls, VAGUE_LOCATION_API_VERSION);

    PermissionListState permVague3 = {
        .permissionName = "ohos.permission.APPROXIMATELY_LOCATION",
        .state = -1,
    };

    std::vector<PermissionListState> permsList3;
    permsList3.emplace_back(permVague3);

    PermissionOper ret = AccessTokenKit::GetSelfPermissionsState(permsList3);
    ASSERT_EQ(PASS_OPER, ret);
    ASSERT_EQ(static_cast<uint32_t>(1), permsList3.size());
    ASSERT_EQ(PASS_OPER, permsList3[0].state);
}

/**
 * @tc.name: GetSelfPermissionsState004
 * @tc.desc: only accurate location permission
 * @tc.type: FUNC
 * @tc.require: issueI5NOQI
 */
HWTEST_F(AccessTokenLocationRequestTest, GetSelfPermissionsState004, TestSize.Level1)
{
    std::vector<PermissionStateFull> permissionStateFulls;
    permissionStateFulls.emplace_back(g_locationTestStateAccurate10); // {-1,0}

    AllocHapToken(permissionStateFulls, VAGUE_LOCATION_API_VERSION);

    std::vector<PermissionListState> permsList4;
    PermissionListState permAccurate4 = {
        .permissionName = "ohos.permission.LOCATION",
        .state = -1,
    };

    permsList4.emplace_back(permAccurate4);

    PermissionOper ret = AccessTokenKit::GetSelfPermissionsState(permsList4);
    ASSERT_EQ(PASS_OPER, ret);
    ASSERT_EQ(static_cast<uint32_t>(1), permsList4.size());
    ASSERT_EQ(INVALID_OPER, permsList4[0].state);
}

/**
 * @tc.name: GetSelfPermissionsState005
 * @tc.desc: only accurate location permission with granted vague location
 * @tc.type: FUNC
 * @tc.require: issueI5NOQI
 */
HWTEST_F(AccessTokenLocationRequestTest, GetSelfPermissionsState005, TestSize.Level1)
{
    std::vector<PermissionStateFull> permissionStateFulls;
    permissionStateFulls.emplace_back(g_locationTestStateAccurate10); // {-1,0}
    permissionStateFulls.emplace_back(g_locationTestStateVague02); // {0,2}

    AllocHapToken(permissionStateFulls, VAGUE_LOCATION_API_VERSION);

    std::vector<PermissionListState> permsList5;
    PermissionListState permAccurate5 = {
        .permissionName = "ohos.permission.LOCATION",
        .state = -1,
    };

    permsList5.emplace_back(permAccurate5);

    PermissionOper ret = AccessTokenKit::GetSelfPermissionsState(permsList5);
    ASSERT_EQ(DYNAMIC_OPER, ret);
    ASSERT_EQ(static_cast<uint32_t>(1), permsList5.size());
    ASSERT_EQ(DYNAMIC_OPER, permsList5[0].state);
}

/**
 * @tc.name: GetSelfPermissionsState006
 * @tc.desc: only background location permission
 * @tc.type: FUNC
 * @tc.require: issueI5NOQI
 */
HWTEST_F(AccessTokenLocationRequestTest, GetSelfPermissionsState006, TestSize.Level1)
{
    std::vector<PermissionStateFull> permissionStateFulls;
    permissionStateFulls.emplace_back(g_locationTestStateBack10); // {-1,0}

    AllocHapToken(permissionStateFulls, VAGUE_LOCATION_API_VERSION);

    std::vector<PermissionListState> permsList6;
    PermissionListState permBack6 = {
        .permissionName = "ohos.permission.LOCATION_IN_BACKGROUND",
        .state = -1,
    };

    permsList6.emplace_back(permBack6);

    PermissionOper ret = AccessTokenKit::GetSelfPermissionsState(permsList6);
    ASSERT_EQ(PASS_OPER, ret);
    ASSERT_EQ(static_cast<uint32_t>(1), permsList6.size());
    ASSERT_EQ(INVALID_OPER, permsList6[0].state);
}

/**
 * @tc.name: GetSelfPermissionsState007
 * @tc.desc: only background location permission with granted vague location
 * @tc.type: FUNC
 * @tc.require: issueI5NOQI
 */
HWTEST_F(AccessTokenLocationRequestTest, GetSelfPermissionsState007, TestSize.Level1)
{
    std::vector<PermissionStateFull> permissionStateFulls;
    permissionStateFulls.emplace_back(g_locationTestStateBack10); // {-1,0}
    permissionStateFulls.emplace_back(g_locationTestStateVague02); // {0,2}

    AllocHapToken(permissionStateFulls, VAGUE_LOCATION_API_VERSION);

    std::vector<PermissionListState> permsList7;
    PermissionListState permBack7 = {
        .permissionName = "ohos.permission.LOCATION_IN_BACKGROUND",
        .state = -1,
    };

    permsList7.emplace_back(permBack7);

    PermissionOper ret = AccessTokenKit::GetSelfPermissionsState(permsList7);
    ASSERT_EQ(DYNAMIC_OPER, ret);
    ASSERT_EQ(static_cast<uint32_t>(1), permsList7.size());
    ASSERT_EQ(DYNAMIC_OPER, permsList7[0].state);
}

/**
 * @tc.name: GetSelfPermissionsState008
 * @tc.desc: vague + accurate location permissions
 * @tc.type: FUNC
 * @tc.require: issueI5NOQI
 */
HWTEST_F(AccessTokenLocationRequestTest, GetSelfPermissionsState008, TestSize.Level1)
{
    std::vector<PermissionStateFull> permissionStateFulls;
    permissionStateFulls.emplace_back(g_locationTestStateVague10); // {-1,0}
    permissionStateFulls.emplace_back(g_locationTestStateAccurate10); // {-1,0}

    AllocHapToken(permissionStateFulls, VAGUE_LOCATION_API_VERSION);

    PermissionListState permVague8 = {
        .permissionName = "ohos.permission.APPROXIMATELY_LOCATION",
        .state = -1,
    };
    PermissionListState permAccurate8 = {
        .permissionName = "ohos.permission.LOCATION",
        .state = -1,
    };
    
    std::vector<PermissionListState> permsList8;
    permsList8.emplace_back(permVague8);
    permsList8.emplace_back(permAccurate8);

    PermissionOper ret = AccessTokenKit::GetSelfPermissionsState(permsList8);
    ASSERT_EQ(DYNAMIC_OPER, ret);
    ASSERT_EQ(static_cast<uint32_t>(2), permsList8.size());
    ASSERT_EQ(DYNAMIC_OPER, permsList8[0].state);
    ASSERT_EQ(DYNAMIC_OPER, permsList8[1].state);
}

/**
 * @tc.name: GetSelfPermissionsState009
 * @tc.desc: vague + accurate after accept vague location permission
 * @tc.type: FUNC
 * @tc.require: issueI5NOQI
 */
HWTEST_F(AccessTokenLocationRequestTest, GetSelfPermissionsState009, TestSize.Level1)
{
    std::vector<PermissionStateFull> permissionStateFulls;
    permissionStateFulls.emplace_back(g_locationTestStateVague02); // {0,2}
    permissionStateFulls.emplace_back(g_locationTestStateAccurate10); // {-1,0}

    AllocHapToken(permissionStateFulls, VAGUE_LOCATION_API_VERSION);

    PermissionListState permVague9 = {
        .permissionName = "ohos.permission.APPROXIMATELY_LOCATION",
        .state = -1,
    };
    PermissionListState permAccurate9 = {
        .permissionName = "ohos.permission.LOCATION",
        .state = -1,
    };

    std::vector<PermissionListState> permsList9;
    permsList9.emplace_back(permVague9);
    permsList9.emplace_back(permAccurate9);

    PermissionOper ret = AccessTokenKit::GetSelfPermissionsState(permsList9);
    ASSERT_EQ(DYNAMIC_OPER, ret);
    ASSERT_EQ(static_cast<uint32_t>(2), permsList9.size());
    ASSERT_EQ(PASS_OPER, permsList9[0].state);
    ASSERT_EQ(DYNAMIC_OPER, permsList9[1].state);
}

/**
 * @tc.name: GetSelfPermissionsState010
 * @tc.desc: vague + accurate after refuse vague location permission
 * @tc.type: FUNC
 * @tc.require: issueI5NOQI
 */
HWTEST_F(AccessTokenLocationRequestTest, GetSelfPermissionsState010, TestSize.Level1)
{
    std::vector<PermissionStateFull> permissionStateFulls;
    permissionStateFulls.emplace_back(g_locationTestStateVague12); // {-1,2}
    permissionStateFulls.emplace_back(g_locationTestStateAccurate10); // {-1,0}

    AllocHapToken(permissionStateFulls, VAGUE_LOCATION_API_VERSION);

    PermissionListState permVague10 = {
        .permissionName = "ohos.permission.APPROXIMATELY_LOCATION",
        .state = -1,
    };
    PermissionListState permAccurate10 = {
        .permissionName = "ohos.permission.LOCATION",
        .state = -1,
    };

    std::vector<PermissionListState> permsList10;
    permsList10.emplace_back(permVague10);
    permsList10.emplace_back(permAccurate10);

    PermissionOper ret = AccessTokenKit::GetSelfPermissionsState(permsList10);
    ASSERT_EQ(PASS_OPER, ret);
    ASSERT_EQ(static_cast<uint32_t>(2), permsList10.size());
    ASSERT_EQ(SETTING_OPER, permsList10[0].state);
    ASSERT_EQ(SETTING_OPER, permsList10[1].state);
}

/**
 * @tc.name: GetSelfPermissionsState011
 * @tc.desc: vague + accurate after accept all location permissions
 * @tc.type: FUNC
 * @tc.require: issueI5NOQI
 */
HWTEST_F(AccessTokenLocationRequestTest, GetSelfPermissionsState011, TestSize.Level1)
{
    std::vector<PermissionStateFull> permissionStateFulls;
    permissionStateFulls.emplace_back(g_locationTestStateVague02); // {0,2}
    permissionStateFulls.emplace_back(g_locationTestStateAccurate02); // {0,2}

    AllocHapToken(permissionStateFulls, VAGUE_LOCATION_API_VERSION);

    PermissionListState permVague11 = {
        .permissionName = "ohos.permission.APPROXIMATELY_LOCATION",
        .state = -1,
    };
    PermissionListState permAccurate11 = {
        .permissionName = "ohos.permission.LOCATION",
        .state = -1,
    };

    std::vector<PermissionListState> permsList11;
    permsList11.emplace_back(permVague11);
    permsList11.emplace_back(permAccurate11);

    PermissionOper ret = AccessTokenKit::GetSelfPermissionsState(permsList11);
    ASSERT_EQ(PASS_OPER, ret);
    ASSERT_EQ(static_cast<uint32_t>(2), permsList11.size());
    ASSERT_EQ(PASS_OPER, permsList11[0].state);
    ASSERT_EQ(PASS_OPER, permsList11[1].state);
}

/**
 * @tc.name: GetSelfPermissionsState012
 * @tc.desc: vague + background location permissions
 * @tc.type: FUNC
 * @tc.require: issueI5NOQI
 */
HWTEST_F(AccessTokenLocationRequestTest, GetSelfPermissionsState012, TestSize.Level1)
{
    std::vector<PermissionStateFull> permissionStateFulls;
    permissionStateFulls.emplace_back(g_locationTestStateVague10); // {-1,0}
    permissionStateFulls.emplace_back(g_locationTestStateBack10); // {-1,0}

    AllocHapToken(permissionStateFulls, VAGUE_LOCATION_API_VERSION);

    PermissionListState permVague12 = {
        .permissionName = "ohos.permission.APPROXIMATELY_LOCATION",
        .state = -1,
    };
    PermissionListState permBack12 = {
        .permissionName = "ohos.permission.LOCATION_IN_BACKGROUND",
        .state = -1,
    };
    
    std::vector<PermissionListState> permsList12;
    permsList12.emplace_back(permVague12);
    permsList12.emplace_back(permBack12);

    PermissionOper ret = AccessTokenKit::GetSelfPermissionsState(permsList12);
    ASSERT_EQ(DYNAMIC_OPER, ret);
    ASSERT_EQ(static_cast<uint32_t>(2), permsList12.size());
    ASSERT_EQ(DYNAMIC_OPER, permsList12[0].state);
    ASSERT_EQ(DYNAMIC_OPER, permsList12[1].state);
}

/**
 * @tc.name: GetSelfPermissionsState013
 * @tc.desc: vague + background after accept vague location permission
 * @tc.type: FUNC
 * @tc.require: issueI5NOQI
 */
HWTEST_F(AccessTokenLocationRequestTest, GetSelfPermissionsState013, TestSize.Level1)
{
    std::vector<PermissionStateFull> permissionStateFulls;
    permissionStateFulls.emplace_back(g_locationTestStateVague02); // {0,2}
    permissionStateFulls.emplace_back(g_locationTestStateBack10); // {-1,0}

    AllocHapToken(permissionStateFulls, VAGUE_LOCATION_API_VERSION);

    PermissionListState permVague13 = {
        .permissionName = "ohos.permission.APPROXIMATELY_LOCATION",
        .state = -1,
    };
    PermissionListState permBack13 = {
        .permissionName = "ohos.permission.LOCATION_IN_BACKGROUND",
        .state = -1,
    };

    std::vector<PermissionListState> permsList13;
    permsList13.emplace_back(permVague13);
    permsList13.emplace_back(permBack13);

    PermissionOper ret = AccessTokenKit::GetSelfPermissionsState(permsList13);
    ASSERT_EQ(DYNAMIC_OPER, ret);
    ASSERT_EQ(static_cast<uint32_t>(2), permsList13.size());
    ASSERT_EQ(PASS_OPER, permsList13[0].state);
    ASSERT_EQ(DYNAMIC_OPER, permsList13[1].state);
}

/**
 * @tc.name: GetSelfPermissionsState014
 * @tc.desc: vague + background after refuse vague location permission
 * @tc.type: FUNC
 * @tc.require: issueI5NOQI
 */
HWTEST_F(AccessTokenLocationRequestTest, GetSelfPermissionsState014, TestSize.Level1)
{
    std::vector<PermissionStateFull> permissionStateFulls;
    permissionStateFulls.emplace_back(g_locationTestStateVague12); // {-1,2}
    permissionStateFulls.emplace_back(g_locationTestStateBack10); // {-1,0}

    AllocHapToken(permissionStateFulls, VAGUE_LOCATION_API_VERSION);

    PermissionListState permVague14 = {
        .permissionName = "ohos.permission.APPROXIMATELY_LOCATION",
        .state = -1,
    };
    PermissionListState permBack14 = {
        .permissionName = "ohos.permission.LOCATION_IN_BACKGROUND",
        .state = -1,
    };

    std::vector<PermissionListState> permsList14;
    permsList14.emplace_back(permVague14);
    permsList14.emplace_back(permBack14);

    PermissionOper ret = AccessTokenKit::GetSelfPermissionsState(permsList14);
    ASSERT_EQ(PASS_OPER, ret);
    ASSERT_EQ(static_cast<uint32_t>(2), permsList14.size());
    ASSERT_EQ(SETTING_OPER, permsList14[0].state);
    ASSERT_EQ(SETTING_OPER, permsList14[1].state);
}

/**
 * @tc.name: GetSelfPermissionsState015
 * @tc.desc: vague + background after accept all location permissions
 * @tc.type: FUNC
 * @tc.require: issueI5NOQI
 */
HWTEST_F(AccessTokenLocationRequestTest, GetSelfPermissionsState015, TestSize.Level1)
{
    std::vector<PermissionStateFull> permissionStateFulls;
    permissionStateFulls.emplace_back(g_locationTestStateVague02); // {0,2}
    permissionStateFulls.emplace_back(g_locationTestStateBack02); // {0,2}

    AllocHapToken(permissionStateFulls, VAGUE_LOCATION_API_VERSION);

    PermissionListState permVague15 = {
        .permissionName = "ohos.permission.APPROXIMATELY_LOCATION",
        .state = -1,
    };
    PermissionListState permBack15 = {
        .permissionName = "ohos.permission.LOCATION_IN_BACKGROUND",
        .state = -1,
    };

    std::vector<PermissionListState> permsList15;
    permsList15.emplace_back(permVague15);
    permsList15.emplace_back(permBack15);

    PermissionOper ret = AccessTokenKit::GetSelfPermissionsState(permsList15);
    ASSERT_EQ(PASS_OPER, ret);
    ASSERT_EQ(static_cast<uint32_t>(2), permsList15.size());
    ASSERT_EQ(PASS_OPER, permsList15[0].state);
    ASSERT_EQ(PASS_OPER, permsList15[1].state);
}

/**
 * @tc.name: GetSelfPermissionsState016
 * @tc.desc: accurate + background
 * @tc.type: FUNC
 * @tc.require: issueI5NOQI
 */
HWTEST_F(AccessTokenLocationRequestTest, GetSelfPermissionsState016, TestSize.Level1)
{
    std::vector<PermissionStateFull> permissionStateFulls;
    permissionStateFulls.emplace_back(g_locationTestStateAccurate10); // {-1,0}
    permissionStateFulls.emplace_back(g_locationTestStateBack10); // {-1,0}

    AllocHapToken(permissionStateFulls, VAGUE_LOCATION_API_VERSION);

    PermissionListState permAccurate16 = {
        .permissionName = "ohos.permission.LOCATION",
        .state = -1,
    };
    PermissionListState permBack16 = {
        .permissionName = "ohos.permission.LOCATION_IN_BACKGROUND",
        .state = -1,
    };

    std::vector<PermissionListState> permsList16;
    permsList16.emplace_back(permAccurate16);
    permsList16.emplace_back(permBack16);

    PermissionOper ret = AccessTokenKit::GetSelfPermissionsState(permsList16);
    ASSERT_EQ(PASS_OPER, ret);
    ASSERT_EQ(static_cast<uint32_t>(2), permsList16.size());
    ASSERT_EQ(INVALID_OPER, permsList16[0].state);
    ASSERT_EQ(INVALID_OPER, permsList16[1].state);
}

/**
 * @tc.name: GetSelfPermissionsState017
 * @tc.desc: vague + background with granted vague location
 * @tc.type: FUNC
 * @tc.require: issueI5NOQI
 */
HWTEST_F(AccessTokenLocationRequestTest, GetSelfPermissionsState017, TestSize.Level1)
{
    std::vector<PermissionStateFull> permissionStateFulls;
    permissionStateFulls.emplace_back(g_locationTestStateVague02); // {0,2}
    permissionStateFulls.emplace_back(g_locationTestStateAccurate10); // {-1,0}
    permissionStateFulls.emplace_back(g_locationTestStateBack10); // {-1,0}

    AllocHapToken(permissionStateFulls, VAGUE_LOCATION_API_VERSION);

    PermissionListState permAccurate17 = {
        .permissionName = "ohos.permission.LOCATION",
        .state = -1,
    };
    PermissionListState permBack17 = {
        .permissionName = "ohos.permission.LOCATION_IN_BACKGROUND",
        .state = -1,
    };

    std::vector<PermissionListState> permsList17;
    permsList17.emplace_back(permAccurate17);
    permsList17.emplace_back(permBack17);

    PermissionOper ret = AccessTokenKit::GetSelfPermissionsState(permsList17);
    ASSERT_EQ(DYNAMIC_OPER, ret);
    ASSERT_EQ(static_cast<uint32_t>(2), permsList17.size());
    ASSERT_EQ(DYNAMIC_OPER, permsList17[0].state);
    ASSERT_EQ(DYNAMIC_OPER, permsList17[1].state);
}

/**
 * @tc.name: GetSelfPermissionsState018
 * @tc.desc: vague + accurate + background
 * @tc.type: FUNC
 * @tc.require: issueI5NOQI
 */
HWTEST_F(AccessTokenLocationRequestTest, GetSelfPermissionsState018, TestSize.Level1)
{
    std::vector<PermissionStateFull> permissionStateFulls;
    permissionStateFulls.emplace_back(g_locationTestStateVague10); // {-1,0}
    permissionStateFulls.emplace_back(g_locationTestStateAccurate10); // {-1,0}
    permissionStateFulls.emplace_back(g_locationTestStateBack10); // {-1,0}

    AllocHapToken(permissionStateFulls, VAGUE_LOCATION_API_VERSION);

    PermissionListState permVague18 = {
        .permissionName = "ohos.permission.APPROXIMATELY_LOCATION",
        .state = -1,
    };
    PermissionListState permAccurate18 = {
        .permissionName = "ohos.permission.LOCATION",
        .state = -1,
    };
    PermissionListState permBack18 = {
        .permissionName = "ohos.permission.LOCATION_IN_BACKGROUND",
        .state = -1,
    };

    std::vector<PermissionListState> permsList18;
    permsList18.emplace_back(permVague18);
    permsList18.emplace_back(permAccurate18);
    permsList18.emplace_back(permBack18);

    PermissionOper ret = AccessTokenKit::GetSelfPermissionsState(permsList18);
    ASSERT_EQ(DYNAMIC_OPER, ret);
    ASSERT_EQ(static_cast<uint32_t>(3), permsList18.size());
    ASSERT_EQ(DYNAMIC_OPER, permsList18[0].state);
    ASSERT_EQ(DYNAMIC_OPER, permsList18[1].state);
    ASSERT_EQ(DYNAMIC_OPER, permsList18[2].state);
}

/**
 * @tc.name: GetSelfPermissionsState019
 * @tc.desc: vague + accurate + background after accept vague location permission
 * @tc.type: FUNC
 * @tc.require: issueI5NOQI
 */
HWTEST_F(AccessTokenLocationRequestTest, GetSelfPermissionsState019, TestSize.Level1)
{
    std::vector<PermissionStateFull> permissionStateFulls;
    permissionStateFulls.emplace_back(g_locationTestStateVague02); // {0,2}
    permissionStateFulls.emplace_back(g_locationTestStateAccurate10); // {-1,0}
    permissionStateFulls.emplace_back(g_locationTestStateBack10); // {-1,0}

    AllocHapToken(permissionStateFulls, VAGUE_LOCATION_API_VERSION);

    PermissionListState permVague19 = {
        .permissionName = "ohos.permission.APPROXIMATELY_LOCATION",
        .state = -1,
    };
    PermissionListState permAccurate19 = {
        .permissionName = "ohos.permission.LOCATION",
        .state = -1,
    };
    PermissionListState permBack19 = {
        .permissionName = "ohos.permission.LOCATION_IN_BACKGROUND",
        .state = -1,
    };

    std::vector<PermissionListState> permsList19;
    permsList19.emplace_back(permVague19);
    permsList19.emplace_back(permAccurate19);
    permsList19.emplace_back(permBack19);

    PermissionOper ret = AccessTokenKit::GetSelfPermissionsState(permsList19);
    ASSERT_EQ(DYNAMIC_OPER, ret);
    ASSERT_EQ(static_cast<uint32_t>(3), permsList19.size());
    ASSERT_EQ(PASS_OPER, permsList19[0].state);
    ASSERT_EQ(DYNAMIC_OPER, permsList19[1].state);
    ASSERT_EQ(DYNAMIC_OPER, permsList19[2].state);
}

/**
 * @tc.name: GetSelfPermissionsState020
 * @tc.desc: vague + accurate + background after accept vague + accurate
 * @tc.type: FUNC
 * @tc.require: issueI5NOQI
 */
HWTEST_F(AccessTokenLocationRequestTest, GetSelfPermissionsState020, TestSize.Level1)
{
    std::vector<PermissionStateFull> permissionStateFulls;
    permissionStateFulls.emplace_back(g_locationTestStateVague02); // {0,2}
    permissionStateFulls.emplace_back(g_locationTestStateAccurate02); // {0,2}
    permissionStateFulls.emplace_back(g_locationTestStateBack10); // {-1,0}

    AllocHapToken(permissionStateFulls, VAGUE_LOCATION_API_VERSION);

    PermissionListState permVague20 = {
        .permissionName = "ohos.permission.APPROXIMATELY_LOCATION",
        .state = -1,
    };
    PermissionListState permAccurate20 = {
        .permissionName = "ohos.permission.LOCATION",
        .state = -1,
    };
    PermissionListState permBack20 = {
        .permissionName = "ohos.permission.LOCATION_IN_BACKGROUND",
        .state = -1,
    };

    std::vector<PermissionListState> permsList20;
    permsList20.emplace_back(permVague20);
    permsList20.emplace_back(permAccurate20);
    permsList20.emplace_back(permBack20);

    PermissionOper ret = AccessTokenKit::GetSelfPermissionsState(permsList20);
    ASSERT_EQ(DYNAMIC_OPER, ret);
    ASSERT_EQ(static_cast<uint32_t>(3), permsList20.size());
    ASSERT_EQ(PASS_OPER, permsList20[0].state);
    ASSERT_EQ(PASS_OPER, permsList20[1].state);
    ASSERT_EQ(DYNAMIC_OPER, permsList20[2].state);
}

/**
 * @tc.name: GetSelfPermissionsState021
 * @tc.desc: vague + accurate + background after accept vague + back
 * @tc.type: FUNC
 * @tc.require: issueI5NOQI
 */
HWTEST_F(AccessTokenLocationRequestTest, GetSelfPermissionsState021, TestSize.Level1)
{
    std::vector<PermissionStateFull> permissionStateFulls;
    permissionStateFulls.emplace_back(g_locationTestStateVague02); // {0,2}
    permissionStateFulls.emplace_back(g_locationTestStateAccurate10); // {-1,0}
    permissionStateFulls.emplace_back(g_locationTestStateBack02); // {0,2}

    AllocHapToken(permissionStateFulls, VAGUE_LOCATION_API_VERSION);

    PermissionListState permVague21 = {
        .permissionName = "ohos.permission.APPROXIMATELY_LOCATION",
        .state = -1,
    };
    PermissionListState permAccurate21 = {
        .permissionName = "ohos.permission.LOCATION",
        .state = -1,
    };
    PermissionListState permBack21 = {
        .permissionName = "ohos.permission.LOCATION_IN_BACKGROUND",
        .state = -1,
    };

    std::vector<PermissionListState> permsList21;
    permsList21.emplace_back(permVague21);
    permsList21.emplace_back(permAccurate21);
    permsList21.emplace_back(permBack21);

    PermissionOper ret = AccessTokenKit::GetSelfPermissionsState(permsList21);
    ASSERT_EQ(DYNAMIC_OPER, ret);
    ASSERT_EQ(static_cast<uint32_t>(3), permsList21.size());
    ASSERT_EQ(PASS_OPER, permsList21[0].state);
    ASSERT_EQ(DYNAMIC_OPER, permsList21[1].state);
    ASSERT_EQ(PASS_OPER, permsList21[2].state);
}

/**
 * @tc.name: GetSelfPermissionsState022
 * @tc.desc: vague + accurate + background after accept all
 * @tc.type: FUNC
 * @tc.require: issueI5NOQI
 */
HWTEST_F(AccessTokenLocationRequestTest, GetSelfPermissionsState022, TestSize.Level1)
{
    std::vector<PermissionStateFull> permissionStateFulls;
    permissionStateFulls.emplace_back(g_locationTestStateVague02); // {0,2}
    permissionStateFulls.emplace_back(g_locationTestStateAccurate02); // {0,2}
    permissionStateFulls.emplace_back(g_locationTestStateBack02); // {0,2}

    AllocHapToken(permissionStateFulls, VAGUE_LOCATION_API_VERSION);

    PermissionListState permVague22 = {
        .permissionName = "ohos.permission.APPROXIMATELY_LOCATION",
        .state = -1,
    };
    PermissionListState permAccurate22 = {
        .permissionName = "ohos.permission.LOCATION",
        .state = -1,
    };
    PermissionListState permBack22 = {
        .permissionName = "ohos.permission.LOCATION_IN_BACKGROUND",
        .state = -1,
    };

    std::vector<PermissionListState> permsList22;
    permsList22.emplace_back(permVague22);
    permsList22.emplace_back(permAccurate22);
    permsList22.emplace_back(permBack22);

    PermissionOper ret = AccessTokenKit::GetSelfPermissionsState(permsList22);
    ASSERT_EQ(PASS_OPER, ret);
    ASSERT_EQ(static_cast<uint32_t>(3), permsList22.size());
    ASSERT_EQ(PASS_OPER, permsList22[0].state);
    ASSERT_EQ(PASS_OPER, permsList22[1].state);
    ASSERT_EQ(PASS_OPER, permsList22[2].state);
}

/**
 * @tc.name: GetSelfPermissionsState023
 * @tc.desc: vague + accurate + background after refuse vague location permission
 * @tc.type: FUNC
 * @tc.require: issueI5NOQI
 */
HWTEST_F(AccessTokenLocationRequestTest, GetSelfPermissionsState023, TestSize.Level1)
{
    std::vector<PermissionStateFull> permissionStateFulls;
    permissionStateFulls.emplace_back(g_locationTestStateVague12); // {-1,2}
    permissionStateFulls.emplace_back(g_locationTestStateAccurate02); // {-1,0}
    permissionStateFulls.emplace_back(g_locationTestStateBack10); // {-1,0}

    AllocHapToken(permissionStateFulls, VAGUE_LOCATION_API_VERSION);

    PermissionListState permVague23 = {
        .permissionName = "ohos.permission.APPROXIMATELY_LOCATION",
        .state = -1,
    };
    PermissionListState permAccurate23 = {
        .permissionName = "ohos.permission.LOCATION",
        .state = -1,
    };
    PermissionListState permBack23 = {
        .permissionName = "ohos.permission.LOCATION_IN_BACKGROUND",
        .state = -1,
    };

    std::vector<PermissionListState> permsList23;
    permsList23.emplace_back(permVague23);
    permsList23.emplace_back(permAccurate23);
    permsList23.emplace_back(permBack23);

    PermissionOper ret = AccessTokenKit::GetSelfPermissionsState(permsList23);
    ASSERT_EQ(PASS_OPER, ret);
    ASSERT_EQ(static_cast<uint32_t>(3), permsList23.size());
    ASSERT_EQ(SETTING_OPER, permsList23[0].state);
    ASSERT_EQ(SETTING_OPER, permsList23[1].state);
    ASSERT_EQ(SETTING_OPER, permsList23[2].state);
}

/**
 * @tc.name: GetSelfPermissionsState024
 * @tc.desc: vague + accurate + background after refuse vague + accurate
 * @tc.type: FUNC
 * @tc.require: issueI5NOQI
 */
HWTEST_F(AccessTokenLocationRequestTest, GetSelfPermissionsState024, TestSize.Level1)
{
    std::vector<PermissionStateFull> permissionStateFulls;
    permissionStateFulls.emplace_back(g_locationTestStateVague12); // {-1,2}
    permissionStateFulls.emplace_back(g_locationTestStateAccurate12); // {-1,2}
    permissionStateFulls.emplace_back(g_locationTestStateBack10); // {-1,0}

    AllocHapToken(permissionStateFulls, VAGUE_LOCATION_API_VERSION);

    PermissionListState permVague24 = {
        .permissionName = "ohos.permission.APPROXIMATELY_LOCATION",
        .state = -1,
    };
    PermissionListState permAccurate24 = {
        .permissionName = "ohos.permission.LOCATION",
        .state = -1,
    };
    PermissionListState permBack24 = {
        .permissionName = "ohos.permission.LOCATION_IN_BACKGROUND",
        .state = -1,
    };

    std::vector<PermissionListState> permsList24;
    permsList24.emplace_back(permVague24);
    permsList24.emplace_back(permAccurate24);
    permsList24.emplace_back(permBack24);

    PermissionOper ret = AccessTokenKit::GetSelfPermissionsState(permsList24);
    ASSERT_EQ(PASS_OPER, ret);
    ASSERT_EQ(static_cast<uint32_t>(3), permsList24.size());
    ASSERT_EQ(SETTING_OPER, permsList24[0].state);
    ASSERT_EQ(SETTING_OPER, permsList24[1].state);
    ASSERT_EQ(SETTING_OPER, permsList24[2].state);
}

/**
 * @tc.name: GetSelfPermissionsState025
 * @tc.desc: vague + accurate + background after refuse vague + back
 * @tc.type: FUNC
 * @tc.require: issueI5NOQI
 */
HWTEST_F(AccessTokenLocationRequestTest, GetSelfPermissionsState025, TestSize.Level1)
{
    std::vector<PermissionStateFull> permissionStateFulls;
    permissionStateFulls.emplace_back(g_locationTestStateVague12); // {-1,2}
    permissionStateFulls.emplace_back(g_locationTestStateAccurate10); // {-1,0}
    permissionStateFulls.emplace_back(g_locationTestStateBack12); // {-1,2}

    AllocHapToken(permissionStateFulls, VAGUE_LOCATION_API_VERSION);

    PermissionListState permVague25 = {
        .permissionName = "ohos.permission.APPROXIMATELY_LOCATION",
        .state = -1,
    };
    PermissionListState permAccurate25 = {
        .permissionName = "ohos.permission.LOCATION",
        .state = -1,
    };
    PermissionListState permBack25 = {
        .permissionName = "ohos.permission.LOCATION_IN_BACKGROUND",
        .state = -1,
    };

    std::vector<PermissionListState> permsList25;
    permsList25.emplace_back(permVague25);
    permsList25.emplace_back(permAccurate25);
    permsList25.emplace_back(permBack25);

    PermissionOper ret = AccessTokenKit::GetSelfPermissionsState(permsList25);
    ASSERT_EQ(PASS_OPER, ret);
    ASSERT_EQ(static_cast<uint32_t>(3), permsList25.size());
    ASSERT_EQ(SETTING_OPER, permsList25[0].state);
    ASSERT_EQ(SETTING_OPER, permsList25[1].state);
    ASSERT_EQ(SETTING_OPER, permsList25[2].state);
}

/**
 * @tc.name: GetSelfPermissionsState026
 * @tc.desc: vague + accurate + background after refuse all
 * @tc.type: FUNC
 * @tc.require: issueI5NOQI
 */
HWTEST_F(AccessTokenLocationRequestTest, GetSelfPermissionsState026, TestSize.Level1)
{
    std::vector<PermissionStateFull> permissionStateFulls;
    permissionStateFulls.emplace_back(g_locationTestStateVague12); // {-1,2}
    permissionStateFulls.emplace_back(g_locationTestStateAccurate12); // {-1,2}
    permissionStateFulls.emplace_back(g_locationTestStateBack12); // {-1,2}

    AllocHapToken(permissionStateFulls, VAGUE_LOCATION_API_VERSION);

    PermissionListState permVague26 = {
        .permissionName = "ohos.permission.APPROXIMATELY_LOCATION",
        .state = -1,
    };
    PermissionListState permAccurate26 = {
        .permissionName = "ohos.permission.LOCATION",
        .state = -1,
    };
    PermissionListState permBack26 = {
        .permissionName = "ohos.permission.LOCATION_IN_BACKGROUND",
        .state = -1,
    };

    std::vector<PermissionListState> permsList26;
    permsList26.emplace_back(permVague26);
    permsList26.emplace_back(permAccurate26);
    permsList26.emplace_back(permBack26);

    PermissionOper ret = AccessTokenKit::GetSelfPermissionsState(permsList26);
    ASSERT_EQ(PASS_OPER, ret);
    ASSERT_EQ(static_cast<uint32_t>(3), permsList26.size());
    ASSERT_EQ(SETTING_OPER, permsList26[0].state);
    ASSERT_EQ(SETTING_OPER, permsList26[1].state);
    ASSERT_EQ(SETTING_OPER, permsList26[2].state);
}

/**
 * @tc.name: GetSelfPermissionsState027
 * @tc.desc: vague + accurate + back + other permissions
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

    AllocHapToken(permissionStateFulls, VAGUE_LOCATION_API_VERSION);

    PermissionListState permVague27 = {
        .permissionName = "ohos.permission.APPROXIMATELY_LOCATION",
        .state = -1,
    };
    PermissionListState permAccurate27 = {
        .permissionName = "ohos.permission.LOCATION",
        .state = -1,
    };
    PermissionListState permBack27 = {
        .permissionName = "ohos.permission.LOCATION_IN_BACKGROUND",
        .state = -1,
    };
    PermissionListState permSystem27 = {
        .permissionName = "ohos.permission.UPDATE_SYSTEM",
        .state = -1,
    };
    PermissionListState permUser27 = {
        .permissionName = "ohos.permission.CAMERA",
        .state = -1,
    };

    std::vector<PermissionListState> permsList27;
    permsList27.emplace_back(permVague27);
    permsList27.emplace_back(permAccurate27);
    permsList27.emplace_back(permBack27);
    permsList27.emplace_back(permSystem27);
    permsList27.emplace_back(permUser27);

    PermissionOper ret = AccessTokenKit::GetSelfPermissionsState(permsList27);
    ASSERT_EQ(DYNAMIC_OPER, ret);
    ASSERT_EQ(static_cast<uint32_t>(5), permsList27.size());
    ASSERT_EQ(DYNAMIC_OPER, permsList27[0].state);
    ASSERT_EQ(DYNAMIC_OPER, permsList27[1].state);
    ASSERT_EQ(DYNAMIC_OPER, permsList27[2].state);
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

    AllocHapToken(permissionStateFulls, DEFAULT_API_VERSION);

    PermissionListState permVague28 = {
        .permissionName = "ohos.permission.APPROXIMATELY_LOCATION",
        .state = -1,
    };

    std::vector<PermissionListState> permsList28;
    permsList28.emplace_back(permVague28);

    PermissionOper ret = AccessTokenKit::GetSelfPermissionsState(permsList28);
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

    AllocHapToken(permissionStateFulls, DEFAULT_API_VERSION);

    PermissionListState permAccurate29 = {
        .permissionName = "ohos.permission.LOCATION",
        .state = -1,
    };

    std::vector<PermissionListState> permsList29;
    permsList29.emplace_back(permAccurate29);

    PermissionOper ret = AccessTokenKit::GetSelfPermissionsState(permsList29);
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

    AllocHapToken(permissionStateFulls, DEFAULT_API_VERSION);

    PermissionListState permBack30 = {
        .permissionName = "ohos.permission.LOCATION_IN_BACKGROUND",
        .state = -1,
    };

    std::vector<PermissionListState> permsList30;
    permsList30.emplace_back(permBack30);

    PermissionOper ret = AccessTokenKit::GetSelfPermissionsState(permsList30);
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

    AllocHapToken(permissionStateFulls, DEFAULT_API_VERSION);

    PermissionListState permVague31 = {
        .permissionName = "ohos.permission.APPROXIMATELY_LOCATION",
        .state = -1,
    };
    PermissionListState permAccurate31 = {
        .permissionName = "ohos.permission.LOCATION",
        .state = -1,
    };

    std::vector<PermissionListState> permsList31;
    permsList31.emplace_back(permVague31);
    permsList31.emplace_back(permAccurate31);

    PermissionOper ret = AccessTokenKit::GetSelfPermissionsState(permsList31);
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

    AllocHapToken(permissionStateFulls, DEFAULT_API_VERSION);

    PermissionListState permVague32 = {
        .permissionName = "ohos.permission.APPROXIMATELY_LOCATION",
        .state = -1,
    };
    PermissionListState permBack32 = {
        .permissionName = "ohos.permission.LOCATION_IN_BACKGROUND",
        .state = -1,
    };

    std::vector<PermissionListState> permsList32;
    permsList32.emplace_back(permVague32);
    permsList32.emplace_back(permBack32);

    PermissionOper ret = AccessTokenKit::GetSelfPermissionsState(permsList32);
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

    AllocHapToken(permissionStateFulls, DEFAULT_API_VERSION);

    PermissionListState permAccurate33 = {
        .permissionName = "ohos.permission.LOCATION",
        .state = -1,
    };
    PermissionListState permBack33 = {
        .permissionName = "ohos.permission.LOCATION_IN_BACKGROUND",
        .state = -1,
    };

    std::vector<PermissionListState> permsList33;
    permsList33.emplace_back(permAccurate33);
    permsList33.emplace_back(permBack33);

    PermissionOper ret = AccessTokenKit::GetSelfPermissionsState(permsList33);
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

    AllocHapToken(permissionStateFulls, DEFAULT_API_VERSION);

    PermissionListState permVague34 = {
        .permissionName = "ohos.permission.APPROXIMATELY_LOCATION",
        .state = -1,
    };
    PermissionListState permAccurate34 = {
        .permissionName = "ohos.permission.LOCATION",
        .state = -1,
    };
    PermissionListState permBack34 = {
        .permissionName = "ohos.permission.LOCATION_IN_BACKGROUND",
        .state = -1,
    };

    std::vector<PermissionListState> permsList34;
    permsList34.emplace_back(permVague34);
    permsList34.emplace_back(permAccurate34);
    permsList34.emplace_back(permBack34);

    PermissionOper ret = AccessTokenKit::GetSelfPermissionsState(permsList34);
    ASSERT_EQ(DYNAMIC_OPER, ret);
    ASSERT_EQ(static_cast<uint32_t>(3), permsList34.size());
    ASSERT_EQ(INVALID_OPER, permsList34[0].state);
    ASSERT_EQ(DYNAMIC_OPER, permsList34[1].state);
    ASSERT_EQ(DYNAMIC_OPER, permsList34[2].state);
}
} // namespace AccessToken
} // namespace Security
} // namespace OHOS
