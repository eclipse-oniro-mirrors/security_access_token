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

#include "dump_token_info_test.h"
#include "gtest/gtest.h"
#include <thread>
#include <unistd.h>

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
static int32_t g_selfUid;

static HapPolicyParams g_PolicyPrams = {
    .apl = APL_NORMAL,
    .domain = "test.domain",
};

static HapInfoParams g_InfoParms = {
    .userID = 1,
    .bundleName = "ohos.test.bundle",
    .instIndex = 0,
    .appIDDesc = "test.bundle",
    .isSystemApp = true
};
};

void DumpTokenInfoTest::SetUpTestCase()
{
    g_selfTokenId = GetSelfTokenID();
    g_selfUid = getuid();
    TestCommon::SetTestEvironment(g_selfTokenId);
}

void DumpTokenInfoTest::TearDownTestCase()
{
    setuid(g_selfUid);
    SetSelfTokenID(g_selfTokenId);
    TestCommon::ResetTestEvironment();
}

void DumpTokenInfoTest::SetUp()
{
    LOGI(ATM_DOMAIN, ATM_TAG, "SetUp ok.");

    setuid(0);
}

void DumpTokenInfoTest::TearDown()
{
}

/**
 * @tc.name: DumpTokenInfoAbnormalTest001
 * @tc.desc: Verify the DumpTokenInfo abnormal branch return nullptr proxy.
 * @tc.type: FUNC
 * @tc.require:Issue Number
 */
HWTEST_F(DumpTokenInfoTest, DumpTokenInfoAbnormalTest001, TestSize.Level1)
{
    LOGI(ATM_DOMAIN, ATM_TAG, "DumpTokenInfoAbnormalTest001");
    AccessTokenIDEx tokenIdEx = {0};
    ASSERT_EQ(RET_SUCCESS, TestCommon::AllocTestHapToken(g_InfoParms, g_PolicyPrams, tokenIdEx));
    ASSERT_NE(INVALID_TOKENID, tokenIdEx.tokenIdExStruct.tokenID);

    setuid(g_selfUid);
    EXPECT_EQ(0, SetSelfTokenID(tokenIdEx.tokenIDEx));
    setuid(1234); // 1234: UID

    std::string dumpInfo;
    AtmToolsParamInfo info;
    info.tokenId = 123;
    AccessTokenKit::DumpTokenInfo(info, dumpInfo);
    EXPECT_EQ("", dumpInfo);

    setuid(g_selfUid);
    EXPECT_EQ(0, SetSelfTokenID(g_selfTokenId));
    setuid(g_selfUid);

    ASSERT_EQ(RET_SUCCESS, TestCommon::DeleteTestHapToken(tokenIdEx.tokenIdExStruct.tokenID));
}

/**
 * @tc.name: DumpTokenInfoAbnormalTest002
 * @tc.desc: Get dump token information with invalid tokenID
 * @tc.type: FUNC
 * @tc.require:Issue Number
 */
HWTEST_F(DumpTokenInfoTest, DumpTokenInfoAbnormalTest002, TestSize.Level1)
{
    LOGI(ATM_DOMAIN, ATM_TAG, "DumpTokenInfoAbnormalTest002");
    SetSelfTokenID(g_selfTokenId);
    std::string dumpInfo;
    AtmToolsParamInfo info;
    info.tokenId = 123;
    AccessTokenKit::DumpTokenInfo(info, dumpInfo);
    ASSERT_EQ("invalid tokenId", dumpInfo);
}

/**
 * @tc.name: DumpTokenInfoAbnormalTest003
 * @tc.desc: Get dump information with invalid param
 * @tc.type: FUNC
 * @tc.require:Issue Number
 */
HWTEST_F(DumpTokenInfoTest, DumpTokenInfoAbnormalTest003, TestSize.Level1)
{
    LOGI(ATM_DOMAIN, ATM_TAG, "DumpTokenInfoAbnormalTest003");
    SetSelfTokenID(g_selfTokenId);
    std::string dumpInfo = "param invalid";
    AtmToolsParamInfo info;
    std::string invalidstr(257, 's');
    info.permissionName = invalidstr;
    AccessTokenKit::DumpTokenInfo(info, dumpInfo);
    ASSERT_EQ("param invalid", dumpInfo);
    info.permissionName = "";
    info.bundleName = invalidstr;
    AccessTokenKit::DumpTokenInfo(info, dumpInfo);
    ASSERT_EQ("param invalid", dumpInfo);
    info.bundleName = "";
    info.processName = invalidstr;
    AccessTokenKit::DumpTokenInfo(info, dumpInfo);
    ASSERT_EQ("param invalid", dumpInfo);
}

/**
 * @tc.name: DumpTokenInfoFuncTest001
 * @tc.desc: Get dump token information with valid tokenID
 * @tc.type: FUNC
 * @tc.require:Issue Number
 */
HWTEST_F(DumpTokenInfoTest, DumpTokenInfoFuncTest001, TestSize.Level1)
{
    LOGI(ATM_DOMAIN, ATM_TAG, "DumpTokenInfoFuncTest001");
    AccessTokenIDEx tokenIdEx = {0};
    ASSERT_EQ(RET_SUCCESS, TestCommon::AllocTestHapToken(g_InfoParms, g_PolicyPrams, tokenIdEx));
    ASSERT_NE(INVALID_TOKENID, tokenIdEx.tokenIdExStruct.tokenID);

    std::string dumpInfo;
    AtmToolsParamInfo info1;
    info1.tokenId = tokenIdEx.tokenIdExStruct.tokenID;
    AccessTokenKit::DumpTokenInfo(info1, dumpInfo);
    EXPECT_NE("", dumpInfo);

    AtmToolsParamInfo info2;
    info2.processName = "hdcd";
    AccessTokenKit::DumpTokenInfo(info2, dumpInfo);
    EXPECT_NE("", dumpInfo);

    ASSERT_EQ(RET_SUCCESS, TestCommon::DeleteTestHapToken(tokenIdEx.tokenIdExStruct.tokenID));
}
} // namespace AccessToken
} // namespace Security
} // namespace OHOS