/*
 * Copyright (c) 2021 Huawei Device Co., Ltd.
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

#include "accesstoken_kit.h"

using namespace testing::ext;
using namespace OHOS::Security::AccessToken;

void AccessTokenKitTest::SetUpTestCase()
{}

void AccessTokenKitTest::TearDownTestCase()
{
}

void AccessTokenKitTest::SetUp()
{
    HapInfoParams info = {
        .userID = TEST_USER_ID,
        .bundleName = TEST_BUNDLE_NAME,
        .instIndex = 0,
        .appIDDesc = "appIDDesc",
    };
    HapPolicyParams policy = {
        .apl = APL_NORMAL,
        .domain = "domain"
    };

    PermissionDef permissionDefAlpha = {
        .permissionName = TEST_PERMISSION_NAME_ALPHA,
        .bundleName = TEST_BUNDLE_NAME,
        .grantMode = GrantMode::USER_GRANT,
        .availableScope = AVAILABLE_SCOPE_ALL,
    };

    PermissionDef permissionDefBeta = {
        .permissionName = TEST_PERMISSION_NAME_BETA,
        .bundleName = TEST_BUNDLE_NAME,
        .grantMode = GrantMode::SYSTEM_GRANT,
        .availableScope = AVAILABLE_SCOPE_ALL,
    };
    policy.permList.emplace_back(permissionDefAlpha);
    policy.permList.emplace_back(permissionDefBeta);

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
        .grantFlags = {PermissionFlag::PERMISSION_USER_SET}
    };
    policy.permStateList.emplace_back(permStatAlpha);
    policy.permStateList.emplace_back(permStatBeta);

    AccessTokenKit::AllocHapToken(info, policy);
}

void AccessTokenKitTest::TearDown()
{
    AccessTokenID tokenID = GetAccessTokenID(TEST_USER_ID, TEST_BUNDLE_NAME, 0);
    AccessTokenKit::DeleteToken(tokenID);
}

unsigned int AccessTokenKitTest::GetAccessTokenID(int userID, std::string bundleName, int instIndex)
{
    return AccessTokenKit::GetHapTokenID(userID, bundleName, instIndex);
}
/**
 * @tc.name: AllocHapToken001
 * @tc.desc: Get permission definition info after AllocHapToken function has been invoked.
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(AccessTokenKitTest, AllocHapToken001, TestSize.Level1)
{
    PermissionDef permDefResultAlpha;
    int ret = AccessTokenKit::GetDefPermission(TEST_PERMISSION_NAME_ALPHA, permDefResultAlpha);
    ASSERT_EQ(TEST_PERMISSION_NAME_ALPHA, permDefResultAlpha.permissionName);
    ASSERT_EQ(RET_SUCCESS, ret);

    PermissionDef permDefResultBeta;
    ret = AccessTokenKit::GetDefPermission(TEST_PERMISSION_NAME_BETA, permDefResultBeta);
    ASSERT_EQ(TEST_PERMISSION_NAME_BETA, permDefResultBeta.permissionName);
    ASSERT_EQ(RET_SUCCESS, ret);
}

/**
 * @tc.name: AllocHapToken002
 * @tc.desc: Get permission definition info that permission is not exist.
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(AccessTokenKitTest, AllocHapToken002, TestSize.Level1)
{
    PermissionDef permDefResult;
    int ret = AccessTokenKit::GetDefPermission(TEST_PERMISSION_NAME_GAMMA, permDefResult);
    ASSERT_EQ(RET_FAILED, ret);
}

/**
 * @tc.name: AllocHapToken003
 * @tc.desc: Get permission definition info list after AllocHapToken function has been invoked.
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(AccessTokenKitTest, AllocHapToken003, TestSize.Level1)
{
    AccessTokenID tokenID = GetAccessTokenID(TEST_USER_ID, TEST_BUNDLE_NAME, 0);
    std::vector<PermissionDef> permDefList;
    int ret = AccessTokenKit::GetDefPermissions(tokenID, permDefList);
    ASSERT_EQ(RET_SUCCESS, ret);
    ASSERT_EQ(2, permDefList.size());
}

/**
 * @tc.name: AllocHapToken004
 * @tc.desc: Get permission definition info list that tokenID is invalid.
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(AccessTokenKitTest, AllocHapToken004, TestSize.Level1)
{
    std::vector<PermissionDef> permDefList;
    int ret = AccessTokenKit::GetDefPermissions(TEST_TOKENID_INVALID, permDefList);
    ASSERT_EQ(RET_FAILED, ret);
}

/**
 * @tc.name: GetReqPermissions001
 * @tc.desc: Get user granted permission state info.
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(AccessTokenKitTest, GetReqPermissions001, TestSize.Level1)
{
    AccessTokenID tokenID = GetAccessTokenID(TEST_USER_ID, TEST_BUNDLE_NAME, 0);
    std::vector<PermissionStateFull> permStatList;
    int ret = AccessTokenKit::GetReqPermissions(tokenID, permStatList, false);
    ASSERT_EQ(RET_SUCCESS, ret);
    ASSERT_EQ(1, permStatList.size());
    ASSERT_EQ(TEST_PERMISSION_NAME_ALPHA, permStatList[0].permissionName);

    ret = AccessTokenKit::VerifyAccessToken(tokenID, TEST_PERMISSION_NAME_ALPHA);
    ASSERT_EQ(ret, permStatList[0].grantStatus[0]);
}

/**
 * @tc.name: GetReqPermissions002
 * @tc.desc: Get system granted permission state info.
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(AccessTokenKitTest, GetReqPermissions002, TestSize.Level1)
{
    AccessTokenID tokenID = GetAccessTokenID(TEST_USER_ID, TEST_BUNDLE_NAME, 0);
    std::vector<PermissionStateFull> permStatList;
    int ret = AccessTokenKit::GetReqPermissions(tokenID, permStatList, true);
    ASSERT_EQ(RET_SUCCESS, ret);
    ASSERT_EQ(1, permStatList.size());
    ASSERT_EQ(TEST_PERMISSION_NAME_BETA, permStatList[0].permissionName);

    ret = AccessTokenKit::VerifyAccessToken(tokenID, TEST_PERMISSION_NAME_BETA);
    ASSERT_EQ(ret, permStatList[0].grantStatus[0]);
}

/**
 * @tc.name: GetPermissionFlag001
 * @tc.desc: Get permission flag after grant permission.
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(AccessTokenKitTest, GetPermissionFlag001, TestSize.Level1)
{
    AccessTokenID tokenID = GetAccessTokenID(TEST_USER_ID, TEST_BUNDLE_NAME, 0);
    int ret = AccessTokenKit::GrantPermission(tokenID, TEST_PERMISSION_NAME_ALPHA, PERMISSION_USER_FIXED);
    ASSERT_EQ(RET_SUCCESS, ret);

    ret = AccessTokenKit::GetPermissionFlag(tokenID, TEST_PERMISSION_NAME_ALPHA);
    ASSERT_EQ(PERMISSION_USER_FIXED, ret);
}

/**
 * @tc.name: VerifyAccessToken001
 * @tc.desc: Verify user granted permission.
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(AccessTokenKitTest, VerifyAccessToken001, TestSize.Level0)
{
    AccessTokenID tokenID = GetAccessTokenID(TEST_USER_ID, TEST_BUNDLE_NAME, 0);
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
 * @tc.require:
 */
HWTEST_F(AccessTokenKitTest, VerifyAccessToken002, TestSize.Level0)
{
    AccessTokenID tokenID = GetAccessTokenID(TEST_USER_ID, TEST_BUNDLE_NAME, 0);
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
 * @tc.desc: Verify permission that has not been defined.
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(AccessTokenKitTest, VerifyAccessToken003, TestSize.Level0)
{
    AccessTokenID tokenID = GetAccessTokenID(TEST_USER_ID, TEST_BUNDLE_NAME, 0);
    int ret = AccessTokenKit::VerifyAccessToken(tokenID, TEST_PERMISSION_NAME_GAMMA);
    ASSERT_EQ(PERMISSION_DENIED, ret);
}

/**
 * @tc.name: ClearUserGrantedPermissionState001
 * @tc.desc: Clear user granted permission fater ClearUserGrantedPermissionState has been invoked.
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(AccessTokenKitTest, ClearUserGrantedPermissionState001, TestSize.Level0)
{
    AccessTokenID tokenID = GetAccessTokenID(TEST_USER_ID, TEST_BUNDLE_NAME, 0);
    int ret = AccessTokenKit::ClearUserGrantedPermissionState(tokenID);
    ASSERT_EQ(RET_SUCCESS, ret);

    ret = AccessTokenKit::VerifyAccessToken(tokenID, TEST_PERMISSION_NAME_ALPHA);
    ASSERT_EQ(PERMISSION_DENIED, ret);
}

/**
 * @tc.name: DeleteToken001
 * @tc.desc: Cannot get permission definition info after DeleteToken function has been invoked.
 * @tc.type: FUNC
 * @tc.require:
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
    ASSERT_EQ(RET_FAILED, ret);
}

/**
 * @tc.name: DeleteToken002
 * @tc.desc: Delete invalid tokenID.
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(AccessTokenKitTest, DeleteToken002, TestSize.Level1)
{
    int ret = AccessTokenKit::DeleteToken(TEST_USER_ID_INVALID);
    ASSERT_EQ(RET_FAILED, ret);
}
