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
#include "accesstoken_log.h"
#include "accesstoken_service_ipc_interface_code.h"
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
static constexpr OHOS::HiviewDFX::HiLogLabel LABEL = {LOG_CORE,
    SECURITY_DOMAIN_ACCESSTOKEN, "VerifyAccessTokenTest"};
static AccessTokenID g_selfTokenId = 0;
static const std::string TEST_BUNDLE_NAME = "ohos";
static const int INVALID_PERMNAME_LEN = 260;
static const unsigned int TEST_TOKENID_INVALID = 0;
static const int TEST_USER_ID = 0;
static constexpr int32_t DEFAULT_API_VERSION = 8;
HapInfoParams g_infoManagerTestSystemInfoParms = TestCommon::GetInfoManagerTestSystemInfoParms();
HapInfoParams g_infoManagerTestNormalInfoParms = TestCommon::GetInfoManagerTestNormalInfoParms();
};

void VerifyAccessTokenTest::SetUpTestCase()
{
    g_selfTokenId = GetSelfTokenID();

    // clean up test cases
    AccessTokenID tokenID = AccessTokenKit::GetHapTokenID(TEST_USER_ID, TEST_BUNDLE_NAME, 0);
    AccessTokenKit::DeleteToken(tokenID);

    tokenID = AccessTokenKit::GetHapTokenID(g_infoManagerTestNormalInfoParms.userID,
                                            g_infoManagerTestNormalInfoParms.bundleName,
                                            g_infoManagerTestNormalInfoParms.instIndex);
    AccessTokenKit::DeleteToken(tokenID);

    tokenID = AccessTokenKit::GetHapTokenID(g_infoManagerTestSystemInfoParms.userID,
                                            g_infoManagerTestSystemInfoParms.bundleName,
                                            g_infoManagerTestSystemInfoParms.instIndex);
    AccessTokenKit::DeleteToken(tokenID);

    AccessTokenIDEx tokenIdEx = AccessTokenKit::AllocHapToken(g_infoManagerTestSystemInfoParms,
                                                              TestCommon::GetTestPolicyParams());
    SetSelfTokenID(tokenIdEx.tokenIDEx);
}

void VerifyAccessTokenTest::TearDownTestCase()
{
    AccessTokenID tokenID = AccessTokenKit::GetHapTokenID(TEST_USER_ID, TEST_BUNDLE_NAME, 0);
    AccessTokenKit::DeleteToken(tokenID);

    tokenID = AccessTokenKit::GetHapTokenID(g_infoManagerTestNormalInfoParms.userID,
                                            g_infoManagerTestNormalInfoParms.bundleName,
                                            g_infoManagerTestNormalInfoParms.instIndex);
    AccessTokenKit::DeleteToken(tokenID);

    tokenID = AccessTokenKit::GetHapTokenID(g_infoManagerTestSystemInfoParms.userID,
                                            g_infoManagerTestSystemInfoParms.bundleName,
                                            g_infoManagerTestSystemInfoParms.instIndex);
    AccessTokenKit::DeleteToken(tokenID);

    SetSelfTokenID(g_selfTokenId);
}

void VerifyAccessTokenTest::SetUp()
{
    ACCESSTOKEN_LOG_INFO(LABEL, "SetUp ok.");

    setuid(0);
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
    TestCommon::TestPreparePermDefList(policy);
    TestCommon::TestPreparePermStateList(policy);

    AccessTokenKit::AllocHapToken(info, policy);
}

void VerifyAccessTokenTest::TearDown()
{
}

/**
 * @tc.name: VerifyAccessTokenFuncTest001
 * @tc.desc: Verify user granted permission.
 * @tc.type: FUNC
 * @tc.require: Issue Number
 */
HWTEST_F(VerifyAccessTokenTest, VerifyAccessTokenFuncTest001, TestSize.Level0)
{
    ACCESSTOKEN_LOG_INFO(LABEL, "VerifyAccessTokenFuncTest001");
    AccessTokenID tokenID = AccessTokenKit::GetHapTokenID(TEST_USER_ID, TEST_BUNDLE_NAME, 0);
    ASSERT_NE(INVALID_TOKENID, tokenID);
    int ret = AccessTokenKit::GrantPermission(tokenID, "ohos.permission.MICROPHONE", PERMISSION_USER_FIXED);
    ASSERT_EQ(RET_SUCCESS, ret);

    ret = AccessTokenKit::VerifyAccessToken(tokenID, "ohos.permission.MICROPHONE");
    ASSERT_EQ(PERMISSION_GRANTED, ret);
    ret = AccessTokenKit::VerifyAccessToken(tokenID, "ohos.permission.MICROPHONE", false);
    ASSERT_EQ(PERMISSION_GRANTED, ret);

    ret = AccessTokenKit::RevokePermission(tokenID, "ohos.permission.MICROPHONE", PERMISSION_USER_FIXED);
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
    ACCESSTOKEN_LOG_INFO(LABEL, "VerifyAccessTokenFuncTest002");
    AccessTokenID tokenID = AccessTokenKit::GetHapTokenID(TEST_USER_ID, TEST_BUNDLE_NAME, 0);
    ASSERT_NE(INVALID_TOKENID, tokenID);
    int ret = AccessTokenKit::GrantPermission(tokenID, "ohos.permission.SET_WIFI_INFO", PERMISSION_USER_FIXED);
    ASSERT_EQ(RET_SUCCESS, ret);

    ret = AccessTokenKit::VerifyAccessToken(tokenID, "ohos.permission.SET_WIFI_INFO");
    ASSERT_EQ(PERMISSION_GRANTED, ret);
    ret = AccessTokenKit::VerifyAccessToken(tokenID, "ohos.permission.SET_WIFI_INFO", false);
    ASSERT_EQ(PERMISSION_GRANTED, ret);

    ret = AccessTokenKit::RevokePermission(tokenID, "ohos.permission.SET_WIFI_INFO", PERMISSION_USER_FIXED);
    ASSERT_EQ(RET_SUCCESS, ret);

    ret = AccessTokenKit::VerifyAccessToken(tokenID, "ohos.permission.SET_WIFI_INFO");
    ASSERT_EQ(PERMISSION_DENIED, ret);
    ret = AccessTokenKit::VerifyAccessToken(tokenID, "ohos.permission.SET_WIFI_INFO", false);
    ASSERT_EQ(PERMISSION_DENIED, ret);
}

/**
 * @tc.name: VerifyAccessTokenFuncTest003
 * @tc.desc: Verify permission after update.
 * @tc.type: FUNC
 * @tc.require: Issue Number
 */
HWTEST_F(VerifyAccessTokenTest, VerifyAccessTokenFuncTest003, TestSize.Level0)
{
    ACCESSTOKEN_LOG_INFO(LABEL, "VerifyAccessTokenFuncTest003");
    AccessTokenIDEx tokenIdEx = AccessTokenKit::GetHapTokenIDEx(TEST_USER_ID, TEST_BUNDLE_NAME, 0);
    AccessTokenID tokenID = tokenIdEx.tokenIdExStruct.tokenID;
    ASSERT_NE(INVALID_TOKENID, tokenID);

    int ret = AccessTokenKit::GrantPermission(tokenID, "ohos.permission.MICROPHONE", PERMISSION_USER_FIXED);
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
        .apl = APL_NORMAL,
        .domain = "domain",
        .permList = permDefList,
        .permStateList = permStatList
    };
    UpdateHapInfoParams info;
    info.appIDDesc = "appIDDesc";
    info.apiVersion = DEFAULT_API_VERSION;
    info.isSystemApp = false;
    ret = AccessTokenKit::UpdateHapToken(tokenIdEx, info, policy);
    ASSERT_EQ(RET_SUCCESS, ret);

    ret = AccessTokenKit::VerifyAccessToken(tokenID, "ohos.permission.MICROPHONE", false);
    ASSERT_EQ(PERMISSION_GRANTED, ret);
}

/**
 * @tc.name: VerifyAccessTokenAbnormalTest001
 * @tc.desc: Verify permission that tokenID or permission is invalid.
 * @tc.type: FUNC
 * @tc.require: Issue Number
 */
HWTEST_F(VerifyAccessTokenTest, VerifyAccessTokenAbnormalTest001, TestSize.Level0)
{
    ACCESSTOKEN_LOG_INFO(LABEL, "VerifyAccessTokenAbnormalTest001");
    AccessTokenID tokenID = AccessTokenKit::GetHapTokenID(TEST_USER_ID, TEST_BUNDLE_NAME, 0);
    ASSERT_NE(INVALID_TOKENID, tokenID);
    int ret = AccessTokenKit::VerifyAccessToken(tokenID, "ohos.permission.GAMMA", false);
    ASSERT_EQ(PERMISSION_DENIED, ret);

    ret = AccessTokenKit::VerifyAccessToken(tokenID, "");
    ASSERT_EQ(PERMISSION_DENIED, ret);
    ret = AccessTokenKit::VerifyAccessToken(tokenID, "", false);
    ASSERT_EQ(PERMISSION_DENIED, ret);

    std::string invalidPerm(INVALID_PERMNAME_LEN, 'a');
    ret = AccessTokenKit::VerifyAccessToken(tokenID, invalidPerm, false);
    ASSERT_EQ(PERMISSION_DENIED, ret);

    AccessTokenKit::VerifyAccessToken(TEST_TOKENID_INVALID, "ohos.permission.SET_WIFI_INFO");
    ASSERT_EQ(PERMISSION_DENIED, ret);
    AccessTokenKit::VerifyAccessToken(TEST_TOKENID_INVALID, "ohos.permission.SET_WIFI_INFO", false);
    ASSERT_EQ(PERMISSION_DENIED, ret);

    AccessTokenKit::DeleteToken(tokenID);

    AccessTokenKit::VerifyAccessToken(tokenID, "ohos.permission.SET_WIFI_INFO");
    ASSERT_EQ(PERMISSION_DENIED, ret);
    AccessTokenKit::VerifyAccessToken(tokenID, "ohos.permission.SET_WIFI_INFO", false);
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
    ACCESSTOKEN_LOG_INFO(LABEL, "VerifyAccessTokenWithListFuncTest001");
    AccessTokenID tokenID = AccessTokenKit::GetHapTokenID(TEST_USER_ID, TEST_BUNDLE_NAME, 0);
    ASSERT_NE(INVALID_TOKENID, tokenID);
    int ret = AccessTokenKit::GrantPermission(tokenID, "ohos.permission.MICROPHONE", PERMISSION_USER_FIXED);
    ASSERT_EQ(RET_SUCCESS, ret);
    ret = AccessTokenKit::GrantPermission(tokenID, "ohos.permission.SET_WIFI_INFO", PERMISSION_USER_FIXED);
    ASSERT_EQ(RET_SUCCESS, ret);

    std::vector<std::string> permissionList;
    permissionList.emplace_back("ohos.permission.MICROPHONE");
    permissionList.emplace_back("ohos.permission.SET_WIFI_INFO");

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

    ret = AccessTokenKit::RevokePermission(tokenID, "ohos.permission.MICROPHONE", PERMISSION_USER_FIXED);
    ASSERT_EQ(RET_SUCCESS, ret);
    ret = AccessTokenKit::RevokePermission(tokenID, "ohos.permission.SET_WIFI_INFO", PERMISSION_USER_FIXED);
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
    ACCESSTOKEN_LOG_INFO(LABEL, "VerifyAccessTokenWithListAbnormalTest001");
    AccessTokenID tokenID = AccessTokenKit::GetHapTokenID(TEST_USER_ID, TEST_BUNDLE_NAME, 0);
    ASSERT_NE(INVALID_TOKENID, tokenID);

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
    permissionList.emplace_back("ohos.permission.SET_WIFI_INFO");
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