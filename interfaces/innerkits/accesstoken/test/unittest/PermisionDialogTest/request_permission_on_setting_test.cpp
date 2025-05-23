/*
 * Copyright (c) 2025 Huawei Device Co., Ltd.
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

#include "request_permission_on_setting_test.h"

#include "access_token.h"
#include "access_token_error.h"
#include "accesstoken_kit.h"
#include "test_common.h"
#include "token_setproc.h"

using namespace testing::ext;

namespace OHOS {
namespace Security {
namespace AccessToken {
namespace {
static uint64_t g_selfTokenId = 0;
}
void RequestPermissionOnSettingTest::SetUpTestCase()
{
    g_selfTokenId = GetSelfTokenID();
    TestCommon::SetTestEvironment(g_selfTokenId);
}

void RequestPermissionOnSettingTest::TearDownTestCase()
{
    TestCommon::ResetTestEvironment();
}

void RequestPermissionOnSettingTest::SetUp()
{
}

void RequestPermissionOnSettingTest::TearDown()
{
}

/**
 * @tc.name: RequestAppPermOnSettingTest001
 * @tc.desc: RequestAppPermOnSetting invalid token.
 * @tc.type: FUNC
 * @tc.require: Issue
 */
HWTEST_F(RequestPermissionOnSettingTest, RequestAppPermOnSettingTest001, TestSize.Level1)
{
    std::vector<std::string> reqPerm;
    MockHapToken mock("RequestAppPermOnSettingTest001", reqPerm, true);

    // invalid tokenID in client
    uint64_t tokenID = 0;
    ASSERT_EQ(AccessTokenError::ERR_PARAM_INVALID, AccessTokenKit::RequestAppPermOnSetting(tokenID));

    tokenID = 123; // 123: invalid token
    ASSERT_EQ(AccessTokenError::ERR_TOKENID_NOT_EXIST, AccessTokenKit::RequestAppPermOnSetting(tokenID));
}

/**
 * @tc.name: RequestAppPermOnSettingTest002
 * @tc.desc: RequestAppPermOnSetting not system app.
 * @tc.type: FUNC
 * @tc.require: Issue Number
 */
HWTEST_F(RequestPermissionOnSettingTest, RequestAppPermOnSettingTest002, TestSize.Level0)
{
    std::vector<std::string> reqPerm;
    MockHapToken mock("RequestAppPermOnSettingTest002", reqPerm, false);

    AccessTokenID tokenID = 123;
    ASSERT_EQ(ERR_NOT_SYSTEM_APP, AccessTokenKit::RequestAppPermOnSetting(tokenID));
}

/**
 * @tc.name: RequestAppPermOnSettingTest003
 * @tc.desc: RequestAppPermOnSetting add hap and call function.
 * @tc.type: FUNC
 * @tc.require: Issue Number
 */
HWTEST_F(RequestPermissionOnSettingTest, RequestAppPermOnSettingTest003, TestSize.Level0)
{
    std::vector<std::string> reqPerm;
    MockHapToken mock("RequestAppPermOnSettingTest003", reqPerm, true);

    HapInfoParams infoManager = {
        .userID = 1,
        .bundleName = "accesstoken_test",
        .instIndex = 0,
        .appIDDesc = "test2",
        .apiVersion = 8  // 8: api version
    };

    PermissionStateFull permState = {
        .permissionName = "ohos.permission.CAMERA",
        .isGeneral = true,
        .resDeviceID = {"local2"},
        .grantStatus = {PermissionState::PERMISSION_GRANTED},
        .grantFlags = {1}
    };

    HapPolicyParams policyPrams = {
        .apl = APL_NORMAL,
        .domain = "test.domain2",
        .permStateList = {permState}
    };
    AccessTokenIDEx tokenIdEx = {0};
    ASSERT_EQ(RET_SUCCESS, TestCommon::AllocTestHapToken(infoManager, policyPrams, tokenIdEx));
    AccessTokenID tokenID = tokenIdEx.tokenIdExStruct.tokenID;
    ASSERT_NE(INVALID_TOKENID, tokenID);
    AccessTokenKit::RequestAppPermOnSetting(tokenID);

    EXPECT_EQ(RET_SUCCESS, TestCommon::DeleteTestHapToken(tokenID));
}
} // namespace AccessToken
} // namespace Security
} // namespace OHOS
