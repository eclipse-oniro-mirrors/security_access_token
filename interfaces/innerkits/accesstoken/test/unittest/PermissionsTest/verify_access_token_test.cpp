/*
 * Copyright (c) 2024 Huawei Device Co., Ltd.
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

#include "verify_access_token_test.h"
#include "gtest/gtest.h"
#include <thread>

#include "access_token.h"
#include "access_token_error.h"
#include "accesstoken_common_log.h"
#include "iaccess_token_manager.h"
#include "permission_grant_info.h"
#include "permission_state_change_info_parcel.h"
#include "string_ex.h"
#include "test_common.h"
#include "tokenid_kit.h"
#include "token_setproc.h"

using namespace testing::ext;
namespace OHOS {
namespace Security {
namespace AccessToken {
namespace {
static uint64_t g_selfTokenId = 0;
static const std::string TEST_BUNDLE_NAME = "ohos";
static const int INVALID_PERMNAME_LEN = 260;
static const unsigned int TEST_TOKENID_INVALID = 0;
static const int TEST_USER_ID = 0;
static constexpr int32_t DEFAULT_API_VERSION = 8;
};

void VerifyAccessTokenTest::SetUpTestCase()
{
    g_selfTokenId = GetSelfTokenID();
    TestCommon::SetTestEvironment(g_selfTokenId);

    // clean up test cases
    AccessTokenIDEx tokenIdEx = TestCommon::GetHapTokenIdFromBundle(TEST_USER_ID, TEST_BUNDLE_NAME, 0);
    AccessTokenID tokenID = tokenIdEx.tokenIdExStruct.tokenID;
    TestCommon::DeleteTestHapToken(tokenID);
}

void VerifyAccessTokenTest::TearDownTestCase()
{
    AccessTokenIDEx tokenIdEx = TestCommon::GetHapTokenIdFromBundle(TEST_USER_ID, TEST_BUNDLE_NAME, 0);
    AccessTokenID tokenID = tokenIdEx.tokenIdExStruct.tokenID;
    TestCommon::DeleteTestHapToken(tokenID);

    SetSelfTokenID(g_selfTokenId);
    TestCommon::ResetTestEvironment();
}

void VerifyAccessTokenTest::SetUp()
{
    LOGI(ATM_DOMAIN, ATM_TAG, "SetUp ok.");

    setuid(0);
    HapInfoParams info = {
        .userID = TEST_USER_ID,
        .bundleName = TEST_BUNDLE_NAME,
        .instIndex = 0,
        .appIDDesc = "VerifyAccessTokenTest",
        .apiVersion = DEFAULT_API_VERSION
    };

    PermissionStateFull permStatMicro = {
        .permissionName = "ohos.permission.MICROPHONE",
        .isGeneral = true,
        .resDeviceID = {"device3"},
        .grantStatus = {PermissionState::PERMISSION_DENIED},
        .grantFlags = {PermissionFlag::PERMISSION_USER_SET}
    };
    PermissionStateFull permStatLocation = {
        .permissionName = "ohos.permission.APPROXIMATELY_LOCATION",
        .isGeneral = true,
        .resDeviceID = {"device3"},
        .grantStatus = {PermissionState::PERMISSION_DENIED},
        .grantFlags = {PermissionFlag::PERMISSION_USER_FIXED}
    };

    HapPolicyParams policy = {
        .apl = APL_NORMAL,
        .domain = "VerifyAccessTokenTest",
        .permStateList = { permStatMicro, permStatLocation },
    };

    AccessTokenIDEx tokenIdEx = {0};
    ASSERT_EQ(RET_SUCCESS, TestCommon::AllocTestHapToken(info, policy, tokenIdEx));
    ASSERT_NE(tokenIdEx.tokenIdExStruct.tokenID, INVALID_TOKENID);
}

void VerifyAccessTokenTest::TearDown()
{
    AccessTokenIDEx tokenIdEx = TestCommon::GetHapTokenIdFromBundle(TEST_USER_ID, TEST_BUNDLE_NAME, 0);
    TestCommon::DeleteTestHapToken(tokenIdEx.tokenIdExStruct.tokenID);
}

/**
 * @tc.name: VerifyAccessTokenFuncTest001
 * @tc.desc: Verify user granted permission.
 * @tc.type: FUNC
 * @tc.require: Issue Number
 */
HWTEST_F(VerifyAccessTokenTest, VerifyAccessTokenFuncTest001, TestSize.Level0)
{
    LOGI(ATM_DOMAIN, ATM_TAG, "VerifyAccessTokenFuncTest001");
    AccessTokenIDEx tokenIdEx = TestCommon::GetHapTokenIdFromBundle(TEST_USER_ID, TEST_BUNDLE_NAME, 0);
    AccessTokenID tokenID = tokenIdEx.tokenIdExStruct.tokenID;
    int ret = TestCommon::GrantPermissionByTest(tokenID, "ohos.permission.MICROPHONE", PERMISSION_USER_FIXED);
    ASSERT_EQ(RET_SUCCESS, ret);

    ret = AccessTokenKit::VerifyAccessToken(tokenID, "ohos.permission.MICROPHONE");
    ASSERT_EQ(PERMISSION_GRANTED, ret);
    ret = AccessTokenKit::VerifyAccessToken(tokenID, "ohos.permission.MICROPHONE", false);
    ASSERT_EQ(PERMISSION_GRANTED, ret);

    ret = TestCommon::RevokePermissionByTest(tokenID, "ohos.permission.MICROPHONE", PERMISSION_USER_FIXED);
    ASSERT_EQ(RET_SUCCESS, ret);

    ret = AccessTokenKit::VerifyAccessToken(tokenID, "ohos.permission.MICROPHONE");
    ASSERT_EQ(PERMISSION_DENIED, ret);
    ret = AccessTokenKit::VerifyAccessToken(tokenID, "ohos.permission.MICROPHONE", false);
    ASSERT_EQ(PERMISSION_DENIED, ret);
}

/**
 * @tc.name: VerifyAccessTokenFuncTest002
 * @tc.desc: Verify system granted permission.
 * @tc.type: FUNC
 * @tc.require: Issue Number
 */
HWTEST_F(VerifyAccessTokenTest, VerifyAccessTokenFuncTest002, TestSize.Level0)
{
    LOGI(ATM_DOMAIN, ATM_TAG, "VerifyAccessTokenFuncTest002");
    AccessTokenIDEx tokenIdEx = TestCommon::GetHapTokenIdFromBundle(TEST_USER_ID, TEST_BUNDLE_NAME, 0);
    AccessTokenID tokenID = tokenIdEx.tokenIdExStruct.tokenID;
    int ret =
        TestCommon::GrantPermissionByTest(tokenID, "ohos.permission.APPROXIMATELY_LOCATION", PERMISSION_USER_FIXED);
    ASSERT_EQ(RET_SUCCESS, ret);

    ret = AccessTokenKit::VerifyAccessToken(tokenID, "ohos.permission.APPROXIMATELY_LOCATION");
    ASSERT_EQ(PERMISSION_GRANTED, ret);
    ret = AccessTokenKit::VerifyAccessToken(tokenID, "ohos.permission.APPROXIMATELY_LOCATION", false);
    ASSERT_EQ(PERMISSION_GRANTED, ret);

    ret = TestCommon::RevokePermissionByTest(tokenID, "ohos.permission.APPROXIMATELY_LOCATION", PERMISSION_USER_FIXED);
    ASSERT_EQ(RET_SUCCESS, ret);

    ret = AccessTokenKit::VerifyAccessToken(tokenID, "ohos.permission.APPROXIMATELY_LOCATION");
    ASSERT_EQ(PERMISSION_DENIED, ret);
    ret = AccessTokenKit::VerifyAccessToken(tokenID, "ohos.permission.APPROXIMATELY_LOCATION", false);
    ASSERT_EQ(PERMISSION_DENIED, ret);
}

/**
 * @tc.name: VerifyAccessTokenAbnormalTest001
 * @tc.desc: Verify permission that tokenID or permission is invalid.
 * @tc.type: FUNC
 * @tc.require: Issue Number
 */
HWTEST_F(VerifyAccessTokenTest, VerifyAccessTokenAbnormalTest001, TestSize.Level0)
{
    LOGI(ATM_DOMAIN, ATM_TAG, "VerifyAccessTokenAbnormalTest001");
    AccessTokenIDEx tokenIdEx = TestCommon::GetHapTokenIdFromBundle(TEST_USER_ID, TEST_BUNDLE_NAME, 0);
    AccessTokenID tokenID = tokenIdEx.tokenIdExStruct.tokenID;
    int ret = AccessTokenKit::VerifyAccessToken(tokenID, "ohos.permission.GAMMA", false);
    ASSERT_EQ(PERMISSION_DENIED, ret);

    ret = AccessTokenKit::VerifyAccessToken(tokenID, "");
    ASSERT_EQ(PERMISSION_DENIED, ret);
    ret = AccessTokenKit::VerifyAccessToken(tokenID, "", false);
    ASSERT_EQ(PERMISSION_DENIED, ret);

    std::string invalidPerm(INVALID_PERMNAME_LEN, 'a');
    ret = AccessTokenKit::VerifyAccessToken(tokenID, invalidPerm, false);
    ASSERT_EQ(PERMISSION_DENIED, ret);

    AccessTokenKit::VerifyAccessToken(TEST_TOKENID_INVALID, "ohos.permission.APPROXIMATELY_LOCATION");
    ASSERT_EQ(PERMISSION_DENIED, ret);
    AccessTokenKit::VerifyAccessToken(TEST_TOKENID_INVALID, "ohos.permission.APPROXIMATELY_LOCATION", false);
    ASSERT_EQ(PERMISSION_DENIED, ret);

    AccessTokenKit::DeleteToken(tokenID);

    AccessTokenKit::VerifyAccessToken(tokenID, "ohos.permission.APPROXIMATELY_LOCATION");
    ASSERT_EQ(PERMISSION_DENIED, ret);
    AccessTokenKit::VerifyAccessToken(tokenID, "ohos.permission.APPROXIMATELY_LOCATION", false);
    ASSERT_EQ(PERMISSION_DENIED, ret);
}

/**
 * @tc.name: VerifyAccessTokenWithListFuncTest001
 * @tc.desc: Verify permission with list.
 * @tc.type: FUNC
 * @tc.require: Issue Number
 */
HWTEST_F(VerifyAccessTokenTest, VerifyAccessTokenWithListFuncTest001, TestSize.Level0)
{
    LOGI(ATM_DOMAIN, ATM_TAG, "VerifyAccessTokenWithListFuncTest001");
    AccessTokenIDEx tokenIdEx = TestCommon::GetHapTokenIdFromBundle(TEST_USER_ID, TEST_BUNDLE_NAME, 0);
    AccessTokenID tokenID = tokenIdEx.tokenIdExStruct.tokenID;
    int ret = TestCommon::GrantPermissionByTest(tokenID, "ohos.permission.MICROPHONE", PERMISSION_USER_FIXED);
    ASSERT_EQ(RET_SUCCESS, ret);
    ret = TestCommon::GrantPermissionByTest(tokenID, "ohos.permission.APPROXIMATELY_LOCATION", PERMISSION_USER_FIXED);
    ASSERT_EQ(RET_SUCCESS, ret);

    std::vector<std::string> permissionList;
    permissionList.emplace_back("ohos.permission.MICROPHONE");
    permissionList.emplace_back("ohos.permission.APPROXIMATELY_LOCATION");

    std::vector<int32_t> permStateList;
    ret = AccessTokenKit::VerifyAccessToken(tokenID, permissionList, permStateList);
    for (int i = 0; i < permissionList.size(); i++) {
        ASSERT_EQ(PERMISSION_GRANTED, permStateList[i]);
    }

    permStateList.clear();
    ret = AccessTokenKit::VerifyAccessToken(tokenID, permissionList, permStateList, true);
    for (int i = 0; i < permissionList.size(); i++) {
        ASSERT_EQ(PERMISSION_GRANTED, permStateList[i]);
    }

    ret = TestCommon::RevokePermissionByTest(tokenID, "ohos.permission.MICROPHONE", PERMISSION_USER_FIXED);
    ASSERT_EQ(RET_SUCCESS, ret);
    ret = TestCommon::RevokePermissionByTest(tokenID, "ohos.permission.APPROXIMATELY_LOCATION", PERMISSION_USER_FIXED);
    ASSERT_EQ(RET_SUCCESS, ret);

    permStateList.clear();
    ret = AccessTokenKit::VerifyAccessToken(tokenID, permissionList, permStateList);
    for (int i = 0; i < permissionList.size(); i++) {
        ASSERT_EQ(PERMISSION_DENIED, permStateList[i]);
    }

    permStateList.clear();
    ret = AccessTokenKit::VerifyAccessToken(tokenID, permissionList, permStateList, true);
    for (int i = 0; i < permissionList.size(); i++) {
        ASSERT_EQ(PERMISSION_DENIED, permStateList[i]);
    }
}

/**
 * @tc.name: VerifyAccessTokenWithListAbnormalTest001
 * @tc.desc: Verify permission that tokenID or permission is invalid.
 * @tc.type: FUNC
 * @tc.require: Issue Number
 */
HWTEST_F(VerifyAccessTokenTest, VerifyAccessTokenWithListAbnormalTest001, TestSize.Level0)
{
    LOGI(ATM_DOMAIN, ATM_TAG, "VerifyAccessTokenWithListAbnormalTest001");
    AccessTokenIDEx tokenIdEx = TestCommon::GetHapTokenIdFromBundle(TEST_USER_ID, TEST_BUNDLE_NAME, 0);
    AccessTokenID tokenID = tokenIdEx.tokenIdExStruct.tokenID;

    std::vector<std::string> permissionList;
    permissionList.emplace_back("ohos.permission.GAMMA");
    std::vector<int32_t> permStateList;
    int ret = AccessTokenKit::VerifyAccessToken(tokenID, permissionList, permStateList, false);
    ASSERT_EQ(RET_SUCCESS, ret);
    ASSERT_EQ(PERMISSION_DENIED, permStateList[0]);

    permissionList.clear();
    permissionList.emplace_back("");
    permStateList.clear();
    ret = AccessTokenKit::VerifyAccessToken(tokenID, permissionList, permStateList);
    ASSERT_EQ(RET_SUCCESS, ret);
    ASSERT_EQ(PERMISSION_DENIED, permStateList[0]);

    std::string invalidPerm(INVALID_PERMNAME_LEN, 'a');
    permissionList.clear();
    permissionList.emplace_back(invalidPerm);
    permStateList.clear();
    ret = AccessTokenKit::VerifyAccessToken(tokenID, permissionList, permStateList);
    ASSERT_EQ(RET_SUCCESS, ret);
    ASSERT_EQ(PERMISSION_DENIED, permStateList[0]);

    permissionList.clear();
    permissionList.emplace_back("ohos.permission.MICROPHONE");
    permissionList.emplace_back("ohos.permission.APPROXIMATELY_LOCATION");
    permissionList.emplace_back(invalidPerm);
    permStateList.clear();
    ret = AccessTokenKit::VerifyAccessToken(TEST_TOKENID_INVALID, permissionList, permStateList);
    ASSERT_EQ(RET_SUCCESS, ret);
    ASSERT_EQ(PERMISSION_DENIED, permStateList[0]);
    ASSERT_EQ(PERMISSION_DENIED, permStateList[1]);
    ASSERT_EQ(PERMISSION_DENIED, permStateList[2]);
}
} // namespace AccessToken
} // namespace Security
} // namespace OHOS