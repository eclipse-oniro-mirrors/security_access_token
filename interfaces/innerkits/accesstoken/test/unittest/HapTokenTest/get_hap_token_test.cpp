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

#include "get_hap_token_test.h"
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
static const unsigned int TEST_TOKENID_INVALID = 0;
static const int TEST_USER_ID = 0;
static constexpr int32_t DEFAULT_API_VERSION = 8;
static const int TEST_USER_ID_INVALID = -1;
static MockNativeToken* g_mock;
HapInfoParams g_testSystemInfoParms = TestCommon::GetInfoManagerTestSystemInfoParms();
HapInfoParams g_testNormalInfoParms = TestCommon::GetInfoManagerTestNormalInfoParms();
HapPolicyParams g_testPolicyPrams = TestCommon::GetInfoManagerTestPolicyPrams();
}

void GetHapTokenTest::SetUpTestCase()
{
    g_selfTokenId = GetSelfTokenID();
    TestCommon::SetTestEvironment(g_selfTokenId);
    g_mock = new (std::nothrow) MockNativeToken("foundation");

    // clean up test cases
    AccessTokenID tokenID = AccessTokenKit::GetHapTokenID(TEST_USER_ID, TEST_BUNDLE_NAME, 0);
    TestCommon::DeleteTestHapToken(tokenID);
}

void GetHapTokenTest::TearDownTestCase()
{
    AccessTokenID tokenID = AccessTokenKit::GetHapTokenID(TEST_USER_ID, TEST_BUNDLE_NAME, 0);
    TestCommon::DeleteTestHapToken(tokenID);

    if (g_mock != nullptr) {
        delete g_mock;
        g_mock = nullptr;
    }
    SetSelfTokenID(g_selfTokenId);
    TestCommon::ResetTestEvironment();
}

void GetHapTokenTest::SetUp()
{
    LOGI(ATM_DOMAIN, ATM_TAG, "SetUp ok.");

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
    ASSERT_EQ(RET_SUCCESS, AccessTokenKit::InitHapToken(info, policy, tokenIdEx));
    EXPECT_NE(INVALID_TOKENID, tokenIdEx.tokenIdExStruct.tokenID);
}

void GetHapTokenTest::TearDown()
{
    AccessTokenID tokenID = AccessTokenKit::GetHapTokenID(TEST_USER_ID, TEST_BUNDLE_NAME, 0);
    TestCommon::DeleteTestHapToken(tokenID);
}

/**
 * @tc.name: GetHapTokenIDFuncTest001
 * @tc.desc: get hap tokenid.
 * @tc.type: FUNC
 * @tc.require: Issue Number
 */
HWTEST_F(GetHapTokenTest, GetHapTokenIDFuncTest001, TestSize.Level0)
{
    LOGI(ATM_DOMAIN, ATM_TAG, "GetHapTokenIDFuncTest001");

    HapTokenInfo hapTokenInfoRes;
    AccessTokenID tokenID = AccessTokenKit::GetHapTokenID(TEST_USER_ID, TEST_BUNDLE_NAME, 0);
    ASSERT_NE(INVALID_TOKENID, tokenID);

    int ret = AccessTokenKit::GetHapTokenInfo(tokenID, hapTokenInfoRes);
    ASSERT_EQ(RET_SUCCESS, ret);
    EXPECT_EQ(hapTokenInfoRes.bundleName, TEST_BUNDLE_NAME);

    ret = TestCommon::DeleteTestHapToken(tokenID);
    ASSERT_EQ(RET_SUCCESS, ret);
}

/**
 * @tc.name: GetHapTokenIDAbnormalTest001
 * @tc.desc: cannot get hap tokenid with invalid userId.
 * @tc.type: FUNC
 * @tc.require: Issue Number
 */
HWTEST_F(GetHapTokenTest, GetHapTokenIDAbnormalTest001, TestSize.Level0)
{
    LOGI(ATM_DOMAIN, ATM_TAG, "GetHapTokenIDAbnormalTest001");

    AccessTokenID tokenID = AccessTokenKit::GetHapTokenID(TEST_USER_ID_INVALID, TEST_BUNDLE_NAME, 0);
    EXPECT_EQ(INVALID_TOKENID, tokenID);
}

/**
 * @tc.name: GetHapTokenIDAbnormalTest002
 * @tc.desc: cannot get hap tokenid with invalid bundlename.
 * @tc.type: FUNC
 * @tc.require: Issue Number
 */
HWTEST_F(GetHapTokenTest, GetHapTokenIDAbnormalTest002, TestSize.Level0)
{
    LOGI(ATM_DOMAIN, ATM_TAG, "GetHapTokenIDAbnormalTest002");

    AccessTokenID tokenID = AccessTokenKit::GetHapTokenID(TEST_USER_ID, "", 0);
    EXPECT_EQ(INVALID_TOKENID, tokenID);

    tokenID = AccessTokenKit::GetHapTokenID(TEST_USER_ID, "invalid bundlename", 0);
    EXPECT_EQ(INVALID_TOKENID, tokenID);
}

/**
 * @tc.name: GetHapTokenIDAbnormalTest003
 * @tc.desc: cannot get hap tokenid with invalid instIndex.
 * @tc.type: FUNC
 * @tc.require: Issue Number
 */
HWTEST_F(GetHapTokenTest, GetHapTokenIDAbnormalTest003, TestSize.Level0)
{
    LOGI(ATM_DOMAIN, ATM_TAG, "GetHapTokenIDAbnormalTest003");

    AccessTokenID tokenID = AccessTokenKit::GetHapTokenID(TEST_USER_ID, TEST_BUNDLE_NAME, 0xffff);
    EXPECT_EQ(INVALID_TOKENID, tokenID);
}

/**
 * @tc.name: GetHapTokenIDExFuncTest001
 * @tc.desc: get hap tokenid.
 * @tc.type: FUNC
 * @tc.require: issueI60F1M
 */
HWTEST_F(GetHapTokenTest, GetHapTokenIDExFuncTest001, TestSize.Level0)
{
    LOGI(ATM_DOMAIN, ATM_TAG, "GetHapTokenIDExFuncTest001");

    AccessTokenIDEx tokenIdEx;
    TestCommon::AllocTestHapToken(g_testSystemInfoParms, g_testPolicyPrams, tokenIdEx);
    AccessTokenIDEx tokenIdEx1 = TestCommon::GetHapTokenIdFromBundle(g_testSystemInfoParms.userID,
        g_testSystemInfoParms.bundleName, g_testSystemInfoParms.instIndex);

    EXPECT_EQ(tokenIdEx.tokenIDEx, tokenIdEx1.tokenIDEx);
    HapTokenInfo hapTokenInfoRes;
    AccessTokenID tokenID = tokenIdEx.tokenIdExStruct.tokenID;
    EXPECT_EQ(RET_SUCCESS, AccessTokenKit::GetHapTokenInfo(tokenID, hapTokenInfoRes));
    EXPECT_EQ(hapTokenInfoRes.bundleName, g_testSystemInfoParms.bundleName);
    EXPECT_EQ(RET_SUCCESS, TestCommon::DeleteTestHapToken(tokenID));
}

/**
 * @tc.name: GetHapTokenIDExAbnormalTest001
 * @tc.desc: cannot get hap tokenid with invalid userId.
 * @tc.type: FUNC
 * @tc.require: issueI60F1M
 */
HWTEST_F(GetHapTokenTest, GetHapTokenIDExAbnormalTest001, TestSize.Level0)
{
    LOGI(ATM_DOMAIN, ATM_TAG, "GetHapTokenIDExAbnormalTest001");

    AccessTokenIDEx tokenIdEx = AccessTokenKit::GetHapTokenIDEx(TEST_USER_ID_INVALID, TEST_BUNDLE_NAME, 0);
    EXPECT_EQ(INVALID_TOKENID, tokenIdEx.tokenIDEx);
}

/**
 * @tc.name: GetHapTokenIDExAbnormalTest002
 * @tc.desc: cannot get hap tokenid with invalid bundlename.
 * @tc.type: FUNC
 * @tc.require: issueI60F1M
 */
HWTEST_F(GetHapTokenTest, GetHapTokenIDExAbnormalTest002, TestSize.Level0)
{
    LOGI(ATM_DOMAIN, ATM_TAG, "GetHapTokenIDExAbnormalTest002");

    AccessTokenIDEx tokenIdEx = AccessTokenKit::GetHapTokenIDEx(TEST_USER_ID, "invalid bundlename", 0);
    EXPECT_EQ(INVALID_TOKENID, tokenIdEx.tokenIDEx);
}

/**
 * @tc.name: GetHapTokenIDExAbnormalTest003
 * @tc.desc: cannot get hap tokenid with invalid instIndex.
 * @tc.type: FUNC
 * @tc.require: issueI60F1M
 */
HWTEST_F(GetHapTokenTest, GetHapTokenIDExAbnormalTest003, TestSize.Level0)
{
    LOGI(ATM_DOMAIN, ATM_TAG, "GetHapTokenIDExAbnormalTest003");

    AccessTokenIDEx tokenIdEx = AccessTokenKit::GetHapTokenIDEx(TEST_USER_ID, "", 0);
    EXPECT_EQ(INVALID_TOKENID, tokenIdEx.tokenIDEx);

    tokenIdEx = AccessTokenKit::GetHapTokenIDEx(TEST_USER_ID, TEST_BUNDLE_NAME, 0xffff);
    EXPECT_EQ(INVALID_TOKENID, tokenIdEx.tokenIDEx);
}

/**
 * @tc.name: GetHapTokenInfoFuncTest001
 * @tc.desc: get the token info and verify.
 * @tc.type: FUNC
 * @tc.require: Issue Number
 */
HWTEST_F(GetHapTokenTest, GetHapTokenInfoFuncTest001, TestSize.Level0)
{
    LOGI(ATM_DOMAIN, ATM_TAG, "GetHapTokenInfoFuncTest001");

    HapTokenInfo hapTokenInfoRes;
    AccessTokenID tokenID = AccessTokenKit::GetHapTokenID(TEST_USER_ID, TEST_BUNDLE_NAME, 0);
    ASSERT_NE(INVALID_TOKENID, tokenID);

    int ret = AccessTokenKit::GetHapTokenInfo(tokenID, hapTokenInfoRes);
    ASSERT_EQ(RET_SUCCESS, ret);
    EXPECT_EQ(hapTokenInfoRes.userID, TEST_USER_ID);
    EXPECT_EQ(hapTokenInfoRes.tokenID, tokenID);
    EXPECT_EQ(hapTokenInfoRes.tokenAttr, static_cast<AccessTokenAttr>(0));
    EXPECT_EQ(hapTokenInfoRes.instIndex, 0);
    EXPECT_EQ(hapTokenInfoRes.bundleName, TEST_BUNDLE_NAME);
    EXPECT_EQ(RET_SUCCESS, TestCommon::DeleteTestHapToken(tokenID));
}

/**
 * @tc.name: GetHapTokenInfoAbnormalTest001
 * @tc.desc: try to get the token info with invalid tokenId.
 * @tc.type: FUNC
 * @tc.require: Issue Number
 */
HWTEST_F(GetHapTokenTest, GetHapTokenInfoAbnormalTest001, TestSize.Level0)
{
    LOGI(ATM_DOMAIN, ATM_TAG, "GetHapTokenInfoAbnormalTest001");

    HapTokenInfo hapTokenInfoRes;
    int ret = AccessTokenKit::GetHapTokenInfo(TEST_TOKENID_INVALID, hapTokenInfoRes);
    EXPECT_EQ(AccessTokenError::ERR_PARAM_INVALID, ret);
}

/**
 * @tc.name: GetHapTokenInfoExtensionFuncTest001
 * @tc.desc: GetHapTokenInfoExt001.
 * @tc.type: FUNC
 * @tc.require: IAZTZD
 */
HWTEST_F(GetHapTokenTest, GetHapTokenInfoExtensionFuncTest001, TestSize.Level0)
{
    LOGI(ATM_DOMAIN, ATM_TAG, "GetHapTokenInfoExtensionFuncTest001");
    setuid(0);
    AccessTokenID tokenID = AccessTokenKit::GetHapTokenID(TEST_USER_ID, TEST_BUNDLE_NAME, 0);
    ASSERT_NE(INVALID_TOKENID, tokenID);
    HapTokenInfoExt hapTokenInfoExt;
    int ret = AccessTokenKit::GetHapTokenInfoExtension(tokenID, hapTokenInfoExt);
    ASSERT_EQ(ret, 0);
    EXPECT_EQ(TEST_BUNDLE_NAME, hapTokenInfoExt.baseInfo.bundleName);
    EXPECT_EQ("appIDDesc", hapTokenInfoExt.appID);

    ret = AccessTokenKit::GetHapTokenInfoExtension(INVALID_TOKENID, hapTokenInfoExt);
    EXPECT_EQ(ret, AccessTokenError::ERR_PARAM_INVALID);
}

/**
 * @tc.name: IsSystemAppByFullTokenIDTest001
 * @tc.desc: check systemapp level by TokenIDEx after AllocHapToken function set isSystemApp true.
 * @tc.type: FUNC
 * @tc.require: issueI60F1M
 */
HWTEST_F(GetHapTokenTest, IsSystemAppByFullTokenIDTest001, TestSize.Level0)
{
    std::vector<std::string> reqPerm;
    AccessTokenIDEx tokenIdEx = {0};
    TestCommon::AllocTestHapToken(g_testSystemInfoParms, g_testPolicyPrams, tokenIdEx);
    ASSERT_EQ(true, TokenIdKit::IsSystemAppByFullTokenID(tokenIdEx.tokenIDEx));

    AccessTokenIDEx tokenIdEx1 = TestCommon::GetHapTokenIdFromBundle(g_testSystemInfoParms.userID,
        g_testSystemInfoParms.bundleName, g_testSystemInfoParms.instIndex);

    EXPECT_EQ(tokenIdEx.tokenIDEx, tokenIdEx1.tokenIDEx);

    UpdateHapInfoParams info;
    info.appIDDesc = g_testSystemInfoParms.appIDDesc;
    info.apiVersion = g_testSystemInfoParms.apiVersion;
    info.isSystemApp = false;
    EXPECT_EQ(RET_SUCCESS, AccessTokenKit::UpdateHapToken(tokenIdEx, info, g_testPolicyPrams));
    tokenIdEx1 = TestCommon::GetHapTokenIdFromBundle(g_testSystemInfoParms.userID,
        g_testSystemInfoParms.bundleName, g_testSystemInfoParms.instIndex);
    EXPECT_EQ(tokenIdEx.tokenIDEx, tokenIdEx1.tokenIDEx);

    EXPECT_EQ(false, TokenIdKit::IsSystemAppByFullTokenID(tokenIdEx.tokenIDEx));
    EXPECT_EQ(RET_SUCCESS, TestCommon::DeleteTestHapToken(tokenIdEx.tokenIdExStruct.tokenID));
}

/**
 * @tc.name: IsSystemAppByFullTokenIDTest002
 * @tc.desc: check systemapp level by TokenIDEx after AllocHapToken function set isSystemApp false.
 * @tc.type: FUNC
 * @tc.require: issueI60F1M
 */
HWTEST_F(GetHapTokenTest, IsSystemAppByFullTokenIDTest002, TestSize.Level0)
{
    AccessTokenIDEx tokenIdEx = {0};
    TestCommon::AllocTestHapToken(g_testSystemInfoParms, g_testPolicyPrams, tokenIdEx);
    EXPECT_TRUE(TokenIdKit::IsSystemAppByFullTokenID(tokenIdEx.tokenIDEx));

    AccessTokenIDEx tokenIdEx1 = TestCommon::GetHapTokenIdFromBundle(g_testSystemInfoParms.userID,
        g_testSystemInfoParms.bundleName, g_testSystemInfoParms.instIndex);
    EXPECT_EQ(tokenIdEx.tokenIDEx, tokenIdEx1.tokenIDEx);
    UpdateHapInfoParams info;
    info.appIDDesc = g_testNormalInfoParms.appIDDesc;
    info.apiVersion = g_testNormalInfoParms.apiVersion;
    info.isSystemApp = true;
    EXPECT_EQ(RET_SUCCESS, AccessTokenKit::UpdateHapToken(tokenIdEx, info, g_testPolicyPrams));
    tokenIdEx1 = TestCommon::GetHapTokenIdFromBundle(g_testSystemInfoParms.userID,
        g_testSystemInfoParms.bundleName, g_testSystemInfoParms.instIndex);
    EXPECT_EQ(tokenIdEx.tokenIDEx, tokenIdEx1.tokenIDEx);

    EXPECT_EQ(true,  TokenIdKit::IsSystemAppByFullTokenID(tokenIdEx.tokenIDEx));
    EXPECT_EQ(RET_SUCCESS, TestCommon::DeleteTestHapToken(tokenIdEx.tokenIdExStruct.tokenID));
}

/**
 * @tc.name: IsSystemAppByFullTokenIDTest003
 * @tc.desc: check systemapp level by TokenIDEx after AllocHapToken function set isSystemApp false.
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(GetHapTokenTest, IsSystemAppByFullTokenIDTest003, TestSize.Level0)
{
    AccessTokenIDEx tokenIdEx = {0};
    TestCommon::AllocTestHapToken(g_testSystemInfoParms, g_testPolicyPrams, tokenIdEx);
    AccessTokenIDEx tokenIdEx1 = TestCommon::GetHapTokenIdFromBundle(g_testSystemInfoParms.userID,
        g_testSystemInfoParms.bundleName, g_testSystemInfoParms.instIndex);
    ASSERT_EQ(tokenIdEx.tokenIDEx, tokenIdEx1.tokenIDEx);
    bool res = AccessTokenKit::IsSystemAppByFullTokenID(tokenIdEx.tokenIDEx);
    ASSERT_TRUE(res);
    EXPECT_EQ(RET_SUCCESS, TestCommon::DeleteTestHapToken(tokenIdEx.tokenIdExStruct.tokenID));
}

/**
 * @tc.name: GetHapTokenInfoWithRenderTest001
 * @tc.desc: GetHapTokenInfo with render tokenID
 * @tc.type: FUNC
 * @tc.require: issue
 */
HWTEST_F(GetHapTokenTest, GetHapTokenInfoWithRenderTest001, TestSize.Level0)
{
    AccessTokenID tokenID = AccessTokenKit::GetHapTokenID(TEST_USER_ID, TEST_BUNDLE_NAME, 0);
    ASSERT_NE(INVALID_TOKENID, tokenID);
    
    // get render token
    uint64_t renderToken = AccessTokenKit::GetRenderTokenID(tokenID);
    ASSERT_NE(renderToken, INVALID_TOKENID);
    ASSERT_NE(renderToken, tokenID);

    HapTokenInfo hapTokenInfoRes;
    int ret = AccessTokenKit::GetHapTokenInfo(renderToken, hapTokenInfoRes);
    EXPECT_EQ(AccessTokenError::ERR_TOKENID_NOT_EXIST, ret);

    HapTokenInfoExt hapTokenInfoExt;
    ret = AccessTokenKit::GetHapTokenInfoExtension(renderToken, hapTokenInfoExt);
    EXPECT_EQ(AccessTokenError::ERR_TOKENID_NOT_EXIST, ret);
}
} // namespace AccessToken
} // namespace Security
} // namespace OHOS