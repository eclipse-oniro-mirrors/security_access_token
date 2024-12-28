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

#include "set_perm_dialog_cap_test.h"
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
static const std::string TEST_PERMISSION_NAME_ALPHA = "ohos.permission.ALPHA";
static const std::string TEST_PERMISSION_NAME_BETA = "ohos.permission.BETA";
static const std::string TEST_PKG_NAME = "com.softbus.test";
static const int TEST_USER_ID = 0;
static constexpr int32_t DEFAULT_API_VERSION = 8;
static const std::string TEST_PERMISSION_NAME_A_MICRO = "ohos.permission.MICROPHONE";
static const std::string TEST_PERMISSION_NAME_A_CAMERA = "ohos.permission.SET_WIFI_INFO";
static const int32_t INDEX_ZERO = 0;
static const int32_t INDEX_ONE = 1;
static const int32_t INDEX_TWO = 2;
static const int32_t INDEX_THREE = 3;
static const int32_t INDEX_FOUR = 4;

HapInfoParams g_infoManagerTestInfoParms = TestCommon::GetInfoManagerTestInfoParms();
HapPolicyParams g_infoManagerTestPolicyPrams = TestCommon::GetInfoManagerTestPolicyPrams();

HapInfoParams g_infoManagerTestInfoParmsBak = g_infoManagerTestInfoParms;
HapPolicyParams g_infoManagerTestPolicyPramsBak = g_infoManagerTestPolicyPrams;
}
uint64_t GetNativeToken(const char *processName, const char **perms, int32_t permNum)
{
    uint64_t tokenId;
    NativeTokenInfoParams infoInstance = {
        .dcapsNum = 0,
        .permsNum = permNum,
        .aclsNum = 0,
        .dcaps = nullptr,
        .perms = perms,
        .acls = nullptr,
        .aplStr = "system_core",
        .processName = processName,
    };

    tokenId = GetAccessTokenId(&infoInstance);
    AccessTokenKit::ReloadNativeTokenInfo();
    return tokenId;
}

void NativeTokenGet1()
{
    uint64_t tokenID;
    const char **perms = new const char *[5]; // 5: array size
    perms[INDEX_ZERO] = "ohos.permission.DISTRIBUTED_DATASYNC";
    perms[INDEX_ONE] = "ohos.permission.GRANT_SENSITIVE_PERMISSIONS";
    perms[INDEX_TWO] = "ohos.permission.REVOKE_SENSITIVE_PERMISSIONS";
    perms[INDEX_THREE] = "ohos.permission.GET_SENSITIVE_PERMISSIONS";
    perms[INDEX_FOUR] = "ohos.permission.DISABLE_PERMISSION_DIALOG";

    tokenID = GetNativeToken("TestCase", perms, 5); // 5: array size
    EXPECT_EQ(0, SetSelfTokenID(tokenID));
    delete[] perms;
}

void SetPermDialogCapTest::SetUpTestCase()
{
    g_selfTokenId = GetSelfTokenID();
    setuid(0);
    // make test case clean
    AccessTokenID tokenID = AccessTokenKit::GetHapTokenID(g_infoManagerTestInfoParms.userID,
                                                          g_infoManagerTestInfoParms.bundleName,
                                                          g_infoManagerTestInfoParms.instIndex);
    AccessTokenKit::DeleteToken(tokenID);

    tokenID = AccessTokenKit::GetHapTokenID(TEST_USER_ID, TEST_BUNDLE_NAME, 0);
    AccessTokenKit::DeleteToken(tokenID);

    NativeTokenGet1();
}

void SetPermDialogCapTest::TearDownTestCase()
{
    SetSelfTokenID(g_selfTokenId);
}

void SetPermDialogCapTest::SetUp()
{
    selfTokenId_ = GetSelfTokenID();
    g_infoManagerTestPolicyPrams = g_infoManagerTestPolicyPramsBak;
    g_infoManagerTestInfoParms = g_infoManagerTestInfoParmsBak;
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
    AccessTokenID tokenID = AccessTokenKit::GetHapTokenID(g_infoManagerTestInfoParms.userID,
                                                          g_infoManagerTestInfoParms.bundleName,
                                                          g_infoManagerTestInfoParms.instIndex);
    AccessTokenKit::DeleteToken(tokenID);
}

void SetPermDialogCapTest::TearDown()
{
    AccessTokenID tokenID = AccessTokenKit::GetHapTokenID(TEST_USER_ID, TEST_BUNDLE_NAME, 0);
    AccessTokenKit::DeleteToken(tokenID);

    tokenID = AccessTokenKit::GetHapTokenID(g_infoManagerTestInfoParms.userID,
                                            g_infoManagerTestInfoParms.bundleName,
                                            g_infoManagerTestInfoParms.instIndex);
    AccessTokenKit::DeleteToken(tokenID);

    EXPECT_EQ(0, SetSelfTokenID(selfTokenId_));
}

/**
 * @tc.name: SetPermDialogCapAbnormalTest001
 * @tc.desc: Set permission dialog capability with noexist app.
 * @tc.type: FUNC
 * @tc.require: Issue Number
 */
HWTEST_F(SetPermDialogCapTest, SetPermDialogCapAbnormalTest001, TestSize.Level1)
{
    LOGI(ATM_DOMAIN, ATM_TAG, "SetPermDialogCapAbnormalTest001");
    HapBaseInfo hapBaseInfo = {
        .userID = 111, // 111: user id
        .bundleName = "noexist bundle",
        .instIndex = 0,
    };

    HapTokenInfo hapInfo;
    ASSERT_EQ(ERR_TOKENID_NOT_EXIST, AccessTokenKit::SetPermDialogCap(hapBaseInfo, true));
}

/**
 * @tc.name: SetPermDialogCapFuncTest001
 * @tc.desc: Set permission dialog capability, and get set permissionState.
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(SetPermDialogCapTest, SetPermDialogCapFuncTest001, TestSize.Level1)
{
    LOGI(ATM_DOMAIN, ATM_TAG, "SetPermDialogCapFuncTest001");
    AccessTokenID tokenID = TestCommon::AllocTestToken(g_infoManagerTestInfoParms, g_infoManagerTestPolicyPrams);
    HapBaseInfo hapBaseInfo = {
        .userID = g_infoManagerTestInfoParms.userID,
        .bundleName = g_infoManagerTestInfoParms.bundleName,
        .instIndex = g_infoManagerTestInfoParms.instIndex,
    };

    std::vector<PermissionListState> permsList;
    PermissionListState tmp = {
        .permissionName = g_infoManagerTestPolicyPrams.permStateList[0].permissionName,
        .state = PASS_OPER
    };
    permsList.emplace_back(tmp);

    // test dialog is forbiddedn
    ASSERT_EQ(0, AccessTokenKit::SetPermDialogCap(hapBaseInfo, true));
    SetSelfTokenID(tokenID);
    PermissionGrantInfo info;
    ASSERT_EQ(FORBIDDEN_OPER, AccessTokenKit::GetSelfPermissionsState(permsList, info));
    SetSelfTokenID(selfTokenId_);

    // test dialog is not forbiddedn
    ASSERT_EQ(0, AccessTokenKit::SetPermDialogCap(hapBaseInfo, false));
    SetSelfTokenID(tokenID);
    ASSERT_NE(FORBIDDEN_OPER, AccessTokenKit::GetSelfPermissionsState(permsList, info));
    SetSelfTokenID(selfTokenId_);

    ASSERT_EQ(RET_SUCCESS, AccessTokenKit::DeleteToken(tokenID));
}
} // namespace AccessToken
} // namespace Security
} // namespace OHOS