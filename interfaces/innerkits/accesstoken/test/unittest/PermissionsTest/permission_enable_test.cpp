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

#include "gtest/gtest.h"
#include "accesstoken_kit.h"
#include "access_token_error.h"
#include "permission_map.h"
#include "permission_enable_test.h"
#include "permission_list_state.h"
#include "test_common.h"
#include "tokenid_kit.h"


using namespace testing::ext;
namespace OHOS {
namespace Security {
namespace AccessToken {
namespace {
static constexpr int32_t TEST_USER_ID = 0;
static const std::string TEST_BUNDLE_NAME = "permission_enable_test";
static constexpr int32_t DEFAULT_API_VERSION = 8;
}

void PermissionEnableTest::SetUpTestCase() {}

void PermissionEnableTest::TearDownTestCase() {}

void PermissionEnableTest::SetUp()
{
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
    TestCommon::TestPreparePermStateList(policy);
    AccessTokenIDEx tokenIdEx = {0};
    ASSERT_EQ(RET_SUCCESS, TestCommon::AllocTestHapToken(info, policy, tokenIdEx));
    ASSERT_NE(INVALID_TOKENID, tokenIdEx.tokenIdExStruct.tokenID);
}

void PermissionEnableTest::TearDown()
{
    AccessTokenID tokenID = AccessTokenKit::GetHapTokenID(TEST_USER_ID, TEST_BUNDLE_NAME, 0);
    AccessTokenKit::DeleteToken(tokenID);
}

/*
 * @tc.name: GetDefPermission001
 * @tc.desc: GetDefPermission should return error for disabled permission
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(PermissionEnableTest, GetDefPermission001, TestSize.Level0)
{
    std::string permissionName = "ohos.permission.CAMERA";
    PermissionDef permissionDef;
    
    ASSERT_TRUE(SetPermissionBriefEnabled(permissionName, false));
    EXPECT_EQ(AccessTokenError::ERR_PERMISSION_NOT_EXIST,
              AccessTokenKit::GetDefPermission(permissionName, permissionDef));
    ASSERT_TRUE(SetPermissionBriefEnabled(permissionName, true));
}

/*
 * @tc.name: GetPermissionFlag001
 * @tc.desc: GetPermissionFlag should return error for disabled permission
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(PermissionEnableTest, GetPermissionFlag001, TestSize.Level0)
{
    AccessTokenID tokenID = AccessTokenKit::GetHapTokenID(TEST_USER_ID, TEST_BUNDLE_NAME, 0);
    ASSERT_NE(INVALID_TOKENID, tokenID);
    
    std::string permissionName = "ohos.permission.CAMERA";
    uint32_t flag;
    
    ASSERT_TRUE(SetPermissionBriefEnabled(permissionName, false));
    EXPECT_EQ(AccessTokenError::ERR_PERMISSION_NOT_EXIST,
              AccessTokenKit::GetPermissionFlag(tokenID, permissionName, flag));
    ASSERT_TRUE(SetPermissionBriefEnabled(permissionName, true));
}

/*
 * @tc.name: QueryStatusByPermission001
 * @tc.desc: QueryStatusByPermission should filter disabled permissions
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(PermissionEnableTest, QueryStatusByPermission001, TestSize.Level0)
{
    std::string permissionName = "ohos.permission.CAMERA";
    std::vector<std::string> permissionList = {permissionName};
    std::vector<PermissionStatus> permissionInfoList;
    
    ASSERT_TRUE(SetPermissionBriefEnabled(permissionName, false));
    EXPECT_EQ(AccessTokenError::ERR_PERMISSION_NOT_EXIST,
              AccessTokenKit::QueryStatusByPermission(permissionList, permissionInfoList));
    ASSERT_TRUE(SetPermissionBriefEnabled(permissionName, true));
}

/*
 * @tc.name: QueryStatusByTokenID001
 * @tc.desc: QueryStatusByTokenID should filter disabled permissions
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(PermissionEnableTest, QueryStatusByTokenID001, TestSize.Level0)
{
    AccessTokenID tokenID = AccessTokenKit::GetHapTokenID(TEST_USER_ID, TEST_BUNDLE_NAME, 0);
    ASSERT_NE(INVALID_TOKENID, tokenID);
    
    std::string permissionName = "ohos.permission.CAMERA";
    std::vector<AccessTokenID> tokenIDList = {tokenID};
    std::vector<PermissionStatus> permissionInfoList;
    
    ASSERT_TRUE(SetPermissionBriefEnabled(permissionName, false));
    EXPECT_EQ(AccessTokenError::ERR_PERMISSION_NOT_EXIST,
              AccessTokenKit::QueryStatusByTokenID(tokenIDList, permissionInfoList));
    ASSERT_TRUE(SetPermissionBriefEnabled(permissionName, true));
}

/*
 * @tc.name: GetPermissionsStatus001
 * @tc.desc: GetPermissionsStatus should filter disabled permissions
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(PermissionEnableTest, GetPermissionsStatus001, TestSize.Level0)
{
    AccessTokenID tokenID = AccessTokenKit::GetHapTokenID(TEST_USER_ID, TEST_BUNDLE_NAME, 0);
    ASSERT_NE(INVALID_TOKENID, tokenID);

    std::string permissionName = "ohos.permission.CAMERA";
    std::vector<PermissionListState> permList;

    ASSERT_TRUE(SetPermissionBriefEnabled(permissionName, false));
    int32_t ret = AccessTokenKit::GetPermissionsStatus(tokenID, permList);
    EXPECT_EQ(RET_SUCCESS, ret);
    for (const auto& perm : permList) {
        EXPECT_NE(permissionName, perm.permissionName);
    }
    ASSERT_TRUE(SetPermissionBriefEnabled(permissionName, true));
}

/*
 * @tc.name: VerifyAccessToken001
 * @tc.desc: VerifyAccessToken should return denied for disabled permission
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(PermissionEnableTest, VerifyAccessToken001, TestSize.Level0)
{
    AccessTokenID tokenID = AccessTokenKit::GetHapTokenID(TEST_USER_ID, TEST_BUNDLE_NAME, 0);
    ASSERT_NE(INVALID_TOKENID, tokenID);
    
    std::string permissionName = "ohos.permission.CAMERA";
    
    ASSERT_TRUE(SetPermissionBriefEnabled(permissionName, false));
    EXPECT_EQ(PERMISSION_DENIED, AccessTokenKit::VerifyAccessToken(tokenID, permissionName, false));
    ASSERT_TRUE(SetPermissionBriefEnabled(permissionName, true));
}

} // namespace AccessToken
} // namespace Security
} // namespace OHOS