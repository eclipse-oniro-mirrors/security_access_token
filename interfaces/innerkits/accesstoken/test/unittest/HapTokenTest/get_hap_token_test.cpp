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
    SECURITY_DOMAIN_ACCESSTOKEN, "GetHapTokenTest"};
static AccessTokenID g_selfTokenId = 0;
static const std::string TEST_BUNDLE_NAME = "ohos";
static const unsigned int TEST_TOKENID_INVALID = 0;
static const int TEST_USER_ID = 0;
static constexpr int32_t DEFAULT_API_VERSION = 8;
static const int TEST_USER_ID_INVALID = -1;
HapInfoParams g_infoManagerTestSystemInfoParms = TestCommon::GetInfoManagerTestSystemInfoParms();
HapPolicyParams g_infoManagerTestPolicyPrams = TestCommon::GetInfoManagerTestPolicyPrams();
}

void GetHapTokenTest::SetUpTestCase()
{
    g_selfTokenId = GetSelfTokenID();

    // clean up test cases
    AccessTokenID tokenID = AccessTokenKit::GetHapTokenID(TEST_USER_ID, TEST_BUNDLE_NAME, 0);
    AccessTokenKit::DeleteToken(tokenID);

    tokenID = AccessTokenKit::GetHapTokenID(g_infoManagerTestSystemInfoParms.userID,
                                            g_infoManagerTestSystemInfoParms.bundleName,
                                            g_infoManagerTestSystemInfoParms.instIndex);
    AccessTokenKit::DeleteToken(tokenID);

    AccessTokenIDEx tokenIdEx = AccessTokenKit::AllocHapToken(g_infoManagerTestSystemInfoParms,
                                                              TestCommon::GetTestPolicyParams());
    SetSelfTokenID(tokenIdEx.tokenIDEx);
}

void GetHapTokenTest::TearDownTestCase()
{
    AccessTokenID tokenID = AccessTokenKit::GetHapTokenID(TEST_USER_ID, TEST_BUNDLE_NAME, 0);
    AccessTokenKit::DeleteToken(tokenID);

    tokenID = AccessTokenKit::GetHapTokenID(g_infoManagerTestSystemInfoParms.userID,
                                            g_infoManagerTestSystemInfoParms.bundleName,
                                            g_infoManagerTestSystemInfoParms.instIndex);
    AccessTokenKit::DeleteToken(tokenID);

    SetSelfTokenID(g_selfTokenId);
}

void GetHapTokenTest::SetUp()
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

void GetHapTokenTest::TearDown()
{
}

/**
 * @tc.name: GetHapTokenIDFuncTest001
 * @tc.desc: get hap tokenid.
 * @tc.type: FUNC
 * @tc.require: Issue Number
 */
HWTEST_F(GetHapTokenTest, GetHapTokenIDFuncTest001, TestSize.Level1)
{
    ACCESSTOKEN_LOG_INFO(LABEL, "GetHapTokenIDFuncTest001");

    HapTokenInfo hapTokenInfoRes;
    AccessTokenID tokenID = AccessTokenKit::GetHapTokenID(TEST_USER_ID, TEST_BUNDLE_NAME, 0);
    ASSERT_NE(INVALID_TOKENID, tokenID);

    int ret = AccessTokenKit::GetHapTokenInfo(tokenID, hapTokenInfoRes);
    ASSERT_EQ(RET_SUCCESS, ret);
    ASSERT_EQ(hapTokenInfoRes.bundleName, TEST_BUNDLE_NAME);

    ret = AccessTokenKit::DeleteToken(tokenID);
    ASSERT_EQ(RET_SUCCESS, ret);
}

/**
 * @tc.name: GetHapTokenIDAbnormalTest001
 * @tc.desc: cannot get hap tokenid with invalid userId.
 * @tc.type: FUNC
 * @tc.require: Issue Number
 */
HWTEST_F(GetHapTokenTest, GetHapTokenIDAbnormalTest001, TestSize.Level1)
{
    ACCESSTOKEN_LOG_INFO(LABEL, "GetHapTokenIDAbnormalTest001");

    AccessTokenID tokenID = AccessTokenKit::GetHapTokenID(TEST_USER_ID_INVALID, TEST_BUNDLE_NAME, 0);
    ASSERT_EQ(INVALID_TOKENID, tokenID);
}

/**
 * @tc.name: GetHapTokenIDAbnormalTest002
 * @tc.desc: cannot get hap tokenid with invalid bundlename.
 * @tc.type: FUNC
 * @tc.require: Issue Number
 */
HWTEST_F(GetHapTokenTest, GetHapTokenIDAbnormalTest002, TestSize.Level1)
{
    ACCESSTOKEN_LOG_INFO(LABEL, "GetHapTokenIDAbnormalTest002");

    AccessTokenID tokenID = AccessTokenKit::GetHapTokenID(TEST_USER_ID, "invalid bundlename", 0);
    ASSERT_EQ(INVALID_TOKENID, tokenID);
}

/**
 * @tc.name: GetHapTokenIDAbnormalTest003
 * @tc.desc: cannot get hap tokenid with invalid bundlename.
 * @tc.type: FUNC
 * @tc.require: Issue Number
 */
HWTEST_F(GetHapTokenTest, GetHapTokenIDAbnormalTest003, TestSize.Level1)
{
    ACCESSTOKEN_LOG_INFO(LABEL, "GetHapTokenIDAbnormalTest003");

    AccessTokenID tokenID = AccessTokenKit::GetHapTokenID(TEST_USER_ID, TEST_BUNDLE_NAME, 0xffff);
    ASSERT_EQ(INVALID_TOKENID, tokenID);
}

/**
 * @tc.name: GetHapTokenIDExFuncTest001
 * @tc.desc: get hap tokenid.
 * @tc.type: FUNC
 * @tc.require: issueI60F1M
 */
HWTEST_F(GetHapTokenTest, GetHapTokenIDExFuncTest001, TestSize.Level1)
{
    ACCESSTOKEN_LOG_INFO(LABEL, "GetHapTokenIDExFuncTest001");

    AccessTokenIDEx tokenIdEx = AccessTokenKit::AllocHapToken(g_infoManagerTestSystemInfoParms,
                                                              g_infoManagerTestPolicyPrams);

    AccessTokenIDEx tokenIdEx1 = AccessTokenKit::GetHapTokenIDEx(g_infoManagerTestSystemInfoParms.userID,
                                                                 g_infoManagerTestSystemInfoParms.bundleName,
                                                                 g_infoManagerTestSystemInfoParms.instIndex);

    ASSERT_EQ(tokenIdEx.tokenIDEx, tokenIdEx1.tokenIDEx);
    HapTokenInfo hapTokenInfoRes;
    AccessTokenID tokenID = tokenIdEx.tokenIdExStruct.tokenID;
    int ret = AccessTokenKit::GetHapTokenInfo(tokenID, hapTokenInfoRes);
    ASSERT_EQ(RET_SUCCESS, ret);
    ASSERT_EQ(hapTokenInfoRes.bundleName, g_infoManagerTestSystemInfoParms.bundleName);
    ASSERT_EQ(RET_SUCCESS, AccessTokenKit::DeleteToken(tokenID));
}

/**
 * @tc.name: GetHapTokenIDExAbnormalTest001
 * @tc.desc: cannot get hap tokenid with invalid userId.
 * @tc.type: FUNC
 * @tc.require: issueI60F1M
 */
HWTEST_F(GetHapTokenTest, GetHapTokenIDExAbnormalTest001, TestSize.Level1)
{
    ACCESSTOKEN_LOG_INFO(LABEL, "GetHapTokenIDExAbnormalTest001");

    AccessTokenIDEx tokenIdEx = AccessTokenKit::GetHapTokenIDEx(TEST_USER_ID_INVALID, TEST_BUNDLE_NAME, 0);
    ASSERT_EQ(INVALID_TOKENID, tokenIdEx.tokenIDEx);
}

/**
 * @tc.name: GetHapTokenIDExAbnormalTest002
 * @tc.desc: cannot get hap tokenid with invalid bundlename.
 * @tc.type: FUNC
 * @tc.require: issueI60F1M
 */
HWTEST_F(GetHapTokenTest, GetHapTokenIDExAbnormalTest002, TestSize.Level1)
{
    ACCESSTOKEN_LOG_INFO(LABEL, "GetHapTokenIDExAbnormalTest002");

    AccessTokenIDEx tokenIdEx = AccessTokenKit::GetHapTokenIDEx(TEST_USER_ID, "invalid bundlename", 0);
    ASSERT_EQ(INVALID_TOKENID, tokenIdEx.tokenIDEx);
}

/**
 * @tc.name: GetHapTokenIDExAbnormalTest003
 * @tc.desc: cannot get hap tokenid with invalid instIndex.
 * @tc.type: FUNC
 * @tc.require: issueI60F1M
 */
HWTEST_F(GetHapTokenTest, GetHapTokenIDExAbnormalTest003, TestSize.Level1)
{
    ACCESSTOKEN_LOG_INFO(LABEL, "GetHapTokenIDExAbnormalTest003");

    AccessTokenIDEx tokenIdEx = AccessTokenKit::GetHapTokenIDEx(TEST_USER_ID, TEST_BUNDLE_NAME, 0xffff);
    ASSERT_EQ(INVALID_TOKENID, tokenIdEx.tokenIDEx);
}

/**
 * @tc.name: GetHapTokenInfoFuncTest001
 * @tc.desc: get the token info and verify.
 * @tc.type: FUNC
 * @tc.require: Issue Number
 */
HWTEST_F(GetHapTokenTest, GetHapTokenInfoFuncTest001, TestSize.Level0)
{
    ACCESSTOKEN_LOG_INFO(LABEL, "GetHapTokenInfoFuncTest001");

    HapTokenInfo hapTokenInfoRes;
    AccessTokenID tokenID = AccessTokenKit::GetHapTokenID(TEST_USER_ID, TEST_BUNDLE_NAME, 0);
    ASSERT_NE(INVALID_TOKENID, tokenID);

    int ret = AccessTokenKit::GetHapTokenInfo(tokenID, hapTokenInfoRes);
    ASSERT_EQ(RET_SUCCESS, ret);

    ASSERT_EQ(hapTokenInfoRes.apl, APL_NORMAL);
    ASSERT_EQ(hapTokenInfoRes.userID, TEST_USER_ID);
    ASSERT_EQ(hapTokenInfoRes.tokenID, tokenID);
    ASSERT_EQ(hapTokenInfoRes.tokenAttr, static_cast<AccessTokenAttr>(0));
    ASSERT_EQ(hapTokenInfoRes.instIndex, 0);

    ASSERT_EQ(hapTokenInfoRes.appID, "appIDDesc");

    ASSERT_EQ(hapTokenInfoRes.bundleName, TEST_BUNDLE_NAME);
    ASSERT_EQ(RET_SUCCESS, AccessTokenKit::DeleteToken(tokenID));
}

/**
 * @tc.name: GetHapTokenInfoAbnormalTest001
 * @tc.desc: try to get the token info with invalid tokenId.
 * @tc.type: FUNC
 * @tc.require: Issue Number
 */
HWTEST_F(GetHapTokenTest, GetHapTokenInfoAbnormalTest001, TestSize.Level0)
{
    ACCESSTOKEN_LOG_INFO(LABEL, "GetHapTokenInfoAbnormalTest001");

    HapTokenInfo hapTokenInfoRes;
    int ret = AccessTokenKit::GetHapTokenInfo(TEST_TOKENID_INVALID, hapTokenInfoRes);
    ASSERT_EQ(AccessTokenError::ERR_PARAM_INVALID, ret);
}
} // namespace AccessToken
} // namespace Security
} // namespace OHOS