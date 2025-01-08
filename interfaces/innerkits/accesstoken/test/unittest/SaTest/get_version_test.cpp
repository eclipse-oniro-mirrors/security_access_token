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

#include "get_version_test.h"
#include <thread>

#include "access_token.h"
#include "access_token_error.h"
#include "accesstoken_common_log.h"
#include "accesstoken_service_ipc_interface_code.h"
#include "hap_token_info.h"
#include "nativetoken_kit.h"
#include "permission_grant_info.h"
#include "permission_state_change_info_parcel.h"
#include "string_ex.h"
#include "tokenid_kit.h"
#include "token_setproc.h"
#include "accesstoken_manager_client.h"
#include "test_common.h"

using namespace testing::ext;

namespace OHOS {
namespace Security {
namespace AccessToken {
namespace {
static const std::string TEST_BUNDLE_NAME = "ohos";
static const int TEST_USER_ID = 0;

HapInfoParams g_locationTestInfo = {
    .userID = TEST_USER_ID,
    .bundleName = "accesstoken_location_test",
    .instIndex = 0,
    .appIDDesc = "test2"
};

HapInfoParams g_infoManagerTestNormalInfoParms = TestCommon::GetInfoManagerTestNormalInfoParms();
HapInfoParams g_infoManagerTestSystemInfoParms = TestCommon::GetInfoManagerTestSystemInfoParms();
HapPolicyParams g_infoManagerTestPolicyPrams = TestCommon::GetInfoManagerTestPolicyPrams();
HapPolicyParams g_infoManagerTestPolicyPramsBak = g_infoManagerTestPolicyPrams;

uint64_t g_selfShellTokenId;
}

void GetNativeTokenTest()
{
    uint64_t tokenId;
    const char **perms = new const char *[4];
    perms[0] = "ohos.permission.DISTRIBUTED_DATASYNC";
    perms[1] = "ohos.permission.GRANT_SENSITIVE_PERMISSIONS";
    perms[2] = "ohos.permission.REVOKE_SENSITIVE_PERMISSIONS"; // 2 means the second permission
    perms[3] = "ohos.permission.GET_SENSITIVE_PERMISSIONS"; // 3 means the third permission

    NativeTokenInfoParams infoInstance = {
        .dcapsNum = 0,
        .permsNum = 4,
        .aclsNum = 0,
        .dcaps = nullptr,
        .perms = perms,
        .acls = nullptr,
        .aplStr = "system_core",
    };

    infoInstance.processName = "TestCase";
    tokenId = GetAccessTokenId(&infoInstance);
    EXPECT_EQ(0, SetSelfTokenID(tokenId));
    AccessTokenKit::ReloadNativeTokenInfo();
    delete[] perms;
}

void GetVersionTest::SetUpTestCase()
{
    g_selfShellTokenId = GetSelfTokenID();
    // clean up test cases
    AccessTokenID tokenId = AccessTokenKit::GetHapTokenID(g_infoManagerTestNormalInfoParms.userID,
                                                          g_infoManagerTestNormalInfoParms.bundleName,
                                                          g_infoManagerTestNormalInfoParms.instIndex);
    AccessTokenKit::DeleteToken(tokenId);

    tokenId = AccessTokenKit::GetHapTokenID(g_infoManagerTestSystemInfoParms.userID,
                                            g_infoManagerTestSystemInfoParms.bundleName,
                                            g_infoManagerTestSystemInfoParms.instIndex);
    AccessTokenKit::DeleteToken(tokenId);

    tokenId = AccessTokenKit::GetHapTokenID(TEST_USER_ID, TEST_BUNDLE_NAME, 0);
    AccessTokenKit::DeleteToken(tokenId);

    GetNativeTokenTest();
}

void GetVersionTest::TearDownTestCase()
{
    SetSelfTokenID(g_selfShellTokenId);
}

void GetVersionTest::SetUp()
{
    setuid(0);
    selfTokenId_ = GetSelfTokenID();
    g_infoManagerTestPolicyPrams = g_infoManagerTestPolicyPramsBak;
    HapInfoParams info = {
        .userID = TEST_USER_ID,
        .bundleName = TEST_BUNDLE_NAME,
        .instIndex = 0,
        .appIDDesc = "appIDDesc",
        .apiVersion = 8,
        .isSystemApp = true
    };

    HapPolicyParams policy = {
        .apl = APL_NORMAL,
        .domain = "domain"
    };
    AccessTokenKit::AllocHapToken(info, policy);
    LOGI(ATM_DOMAIN, ATM_TAG, "SetUp ok.");
}

void GetVersionTest::TearDown()
{
    AccessTokenID tokenId = AccessTokenKit::GetHapTokenID(TEST_USER_ID, TEST_BUNDLE_NAME, 0);
    AccessTokenKit::DeleteToken(tokenId);
    tokenId = AccessTokenKit::GetHapTokenID(g_infoManagerTestNormalInfoParms.userID,
                                            g_infoManagerTestNormalInfoParms.bundleName,
                                            g_infoManagerTestNormalInfoParms.instIndex);
    AccessTokenKit::DeleteToken(tokenId);

    tokenId = AccessTokenKit::GetHapTokenID(g_infoManagerTestSystemInfoParms.userID,
                                            g_infoManagerTestSystemInfoParms.bundleName,
                                            g_infoManagerTestSystemInfoParms.instIndex);
    AccessTokenKit::DeleteToken(tokenId);
    EXPECT_EQ(0, SetSelfTokenID(selfTokenId_));
}

void GetVersionTest::AllocHapToken(std::vector<PermissionDef>& permissionDefs,
    std::vector<PermissionStateFull>& permissionStateFulls, int32_t apiVersion)
{
    AccessTokenID tokenID = AccessTokenKit::GetHapTokenID(TEST_USER_ID, "accesstoken_location_test", 0);
    AccessTokenKit::DeleteToken(tokenID);

    HapInfoParams info = g_locationTestInfo;
    info.apiVersion = apiVersion;

    HapPolicyParams policy = {
        .apl = APL_NORMAL,
        .domain = "domain"
    };

    for (auto& permissionDef:permissionDefs) {
        policy.permList.emplace_back(permissionDef);
    }

    for (auto& permissionStateFull:permissionStateFulls) {
        policy.permStateList.emplace_back(permissionStateFull);
    }

    AccessTokenKit::AllocHapToken(info, policy);
}

/**
 * @tc.name: GetVersionFuncTest001
 * @tc.desc: GetVersion caller is normal app.
 * @tc.type: FUNC
 * @tc.require: issueI5NT1X
 */
HWTEST_F(GetVersionTest, GetVersionFuncTest001, TestSize.Level1)
{
    LOGI(ATM_DOMAIN, ATM_TAG, "GetVersionFuncTest001");
    AccessTokenIDEx tokenIdEx = {0};
    tokenIdEx = AccessTokenKit::AllocHapToken(g_infoManagerTestNormalInfoParms, g_infoManagerTestPolicyPrams);
    ASSERT_NE(INVALID_TOKENID, tokenIdEx.tokenIDEx);
    EXPECT_EQ(0, SetSelfTokenID(tokenIdEx.tokenIDEx));

    uint32_t version;
    int32_t res = AccessTokenKit::GetVersion(version);
    ASSERT_EQ(ERR_NOT_SYSTEM_APP, res);
}

/**
 * @tc.name: GetVersionFuncTest002
 * @tc.desc: GetVersion caller is system app.
 * @tc.type: FUNC
 * @tc.require: issueI5NT1X
 */
HWTEST_F(GetVersionTest, GetVersionFuncTest002, TestSize.Level1)
{
    LOGI(ATM_DOMAIN, ATM_TAG, "GetVersionFuncTest002");
    AccessTokenIDEx tokenIdEx = {0};
    tokenIdEx = AccessTokenKit::AllocHapToken(g_infoManagerTestSystemInfoParms, g_infoManagerTestPolicyPrams);
    ASSERT_NE(INVALID_TOKENID, tokenIdEx.tokenIDEx);
    EXPECT_EQ(0, SetSelfTokenID(tokenIdEx.tokenIDEx));

    uint32_t version;
    int32_t res = AccessTokenKit::GetVersion(version);
    ASSERT_EQ(RET_SUCCESS, res);
    ASSERT_EQ(DEFAULT_TOKEN_VERSION, version);
}
} // namespace AccessToken
} // namespace Security
} // namespace OHOS