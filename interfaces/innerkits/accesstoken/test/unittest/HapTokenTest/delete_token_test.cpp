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

#include "delete_token_test.h"
#include "gtest/gtest.h"
#include <thread>
#include <unistd.h>

#include "access_token.h"
#include "access_token_error.h"
#include "accesstoken_common_log.h"
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
static AccessTokenID g_selfTokenId = 0;
static const std::string TEST_BUNDLE_NAME = "ohos";
static const unsigned int TEST_TOKENID_INVALID = 0;
static const int TEST_USER_ID = 0;
static constexpr int32_t DEFAULT_API_VERSION = 8;
HapInfoParams g_infoManagerTestInfoParms = TestCommon::GetInfoManagerTestInfoParms();
HapPolicyParams g_infoManagerTestPolicyPrams = TestCommon::GetInfoManagerTestPolicyPrams();
};

void DeleteTokenTest::SetUpTestCase()
{
    g_selfTokenId = GetSelfTokenID();

    // clean up test cases
    AccessTokenID tokenID = AccessTokenKit::GetHapTokenID(TEST_USER_ID, TEST_BUNDLE_NAME, 0);
    AccessTokenKit::DeleteToken(tokenID);

    tokenID = AccessTokenKit::GetHapTokenID(g_infoManagerTestInfoParms.userID,
                                            g_infoManagerTestInfoParms.bundleName,
                                            g_infoManagerTestInfoParms.instIndex);
    AccessTokenKit::DeleteToken(tokenID);

    AccessTokenIDEx tokenIdEx = AccessTokenKit::AllocHapToken(g_infoManagerTestInfoParms,
                                                              TestCommon::GetTestPolicyParams());
    SetSelfTokenID(tokenIdEx.tokenIDEx);
}

void DeleteTokenTest::TearDownTestCase()
{
    AccessTokenID tokenID = AccessTokenKit::GetHapTokenID(TEST_USER_ID, TEST_BUNDLE_NAME, 0);
    AccessTokenKit::DeleteToken(tokenID);

    tokenID = AccessTokenKit::GetHapTokenID(g_infoManagerTestInfoParms.userID,
                                            g_infoManagerTestInfoParms.bundleName,
                                            g_infoManagerTestInfoParms.instIndex);
    AccessTokenKit::DeleteToken(tokenID);

    SetSelfTokenID(g_selfTokenId);
}

void DeleteTokenTest::SetUp()
{
    LOGI(ATM_DOMAIN, ATM_TAG, "SetUp ok.");

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

void DeleteTokenTest::TearDown()
{
}

/**
 * @tc.name: DeleteTokenFuncTest001
 * @tc.desc: Cannot get permission definition info after DeleteToken function has been invoked.
 * @tc.type: FUNC
 * @tc.require: Issue Number
 */
HWTEST_F(DeleteTokenTest, DeleteTokenFuncTest001, TestSize.Level1)
{
    LOGI(ATM_DOMAIN, ATM_TAG, "DeleteTokenFuncTest001");

    AccessTokenID tokenID = AccessTokenKit::GetHapTokenID(TEST_USER_ID, TEST_BUNDLE_NAME, 0);
    ASSERT_NE(INVALID_TOKENID, tokenID);

    PermissionDef permDefResultAlpha;
    int ret = AccessTokenKit::GetDefPermission("ohos.permission.ALPHA", permDefResultAlpha);
    ASSERT_EQ("ohos.permission.ALPHA", permDefResultAlpha.permissionName);
    ASSERT_EQ(RET_SUCCESS, ret);

    ret = AccessTokenKit::DeleteToken(tokenID);
    ASSERT_EQ(RET_SUCCESS, ret);

    PermissionDef defResult;
    ret = AccessTokenKit::GetDefPermission("ohos.permission.ALPHA", defResult);
    ASSERT_EQ(AccessTokenError::ERR_PERMISSION_NOT_EXIST, ret);
}

/**
 * @tc.name: DeleteTokenFuncTest002
 * @tc.desc: Cannot get haptoken info after DeleteToken function has been invoked.
 * @tc.type: FUNC
 * @tc.require: Issue Number
 */
HWTEST_F(DeleteTokenTest, DeleteTokenFuncTest002, TestSize.Level1)
{
    LOGI(ATM_DOMAIN, ATM_TAG, "DeleteTokenFuncTest002");

    HapTokenInfo hapTokenInfoRes;
    AccessTokenID tokenID = AccessTokenKit::GetHapTokenID(TEST_USER_ID, TEST_BUNDLE_NAME, 0);
    ASSERT_NE(INVALID_TOKENID, tokenID);

    int ret = AccessTokenKit::GetHapTokenInfo(tokenID, hapTokenInfoRes);
    ASSERT_EQ(RET_SUCCESS, ret);

    ret = AccessTokenKit::DeleteToken(tokenID);
    ASSERT_EQ(RET_SUCCESS, ret);

    ret = AccessTokenKit::GetHapTokenInfo(tokenID, hapTokenInfoRes);
    ASSERT_EQ(AccessTokenError::ERR_TOKENID_NOT_EXIST, ret);
}

/**
 * @tc.name: DeleteTokenAbnormalTest001
 * @tc.desc: Delete invalid tokenID.
 * @tc.type: FUNC
 * @tc.require: Issue Number
 */
HWTEST_F(DeleteTokenTest, DeleteTokenAbnormalTest001, TestSize.Level1)
{
    LOGI(ATM_DOMAIN, ATM_TAG, "DeleteTokenAbnormalTest001");

    int ret = AccessTokenKit::DeleteToken(TEST_TOKENID_INVALID);
    ASSERT_EQ(AccessTokenError::ERR_PARAM_INVALID, ret);
}

/**
 * @tc.name: DeleteTokenAbnormalTest002
 * @tc.desc: Delete invalid tokenID, tokenID != TOKEN_HAP
 * @tc.type: FUNC
 * @tc.require: Issue Number
 */
HWTEST_F(DeleteTokenTest, DeleteTokenAbnormalTest002, TestSize.Level1)
{
    LOGI(ATM_DOMAIN, ATM_TAG, "DeleteTokenAbnormalTest002");

    // tokenID != TOKEN_HAP
    AccessTokenID tokenID = AccessTokenKit::GetNativeTokenId("hdcd");
    ASSERT_EQ(TOKEN_SHELL, AccessTokenKit::GetTokenType(tokenID));
    int ret = AccessTokenKit::DeleteToken(tokenID);
    ASSERT_EQ(ERR_PARAM_INVALID, ret);
}

/**
 * @tc.name: DeleteTokenSpecTest001
 * @tc.desc: alloc a tokenId successfully, delete it successfully the first time and fail to delete it again.
 * @tc.type: FUNC
 * @tc.require: Issue Number
 */
HWTEST_F(DeleteTokenTest, DeleteTokenSpecTest001, TestSize.Level1)
{
    LOGI(ATM_DOMAIN, ATM_TAG, "DeleteTokenSpecTest001");

    AccessTokenID tokenID = TestCommon::AllocTestToken(g_infoManagerTestInfoParms, g_infoManagerTestPolicyPrams);
    ASSERT_NE(INVALID_TOKENID, tokenID);

    ASSERT_EQ(RET_SUCCESS, AccessTokenKit::DeleteToken(tokenID));
    ASSERT_NE(RET_SUCCESS, AccessTokenKit::DeleteToken(tokenID));
}
} // namespace AccessToken
} // namespace Security
} // namespace OHOS