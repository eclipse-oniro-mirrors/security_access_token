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
    SECURITY_DOMAIN_ACCESSTOKEN, "DumpTokenInfoTest"};
static AccessTokenID g_selfTokenId = 0;
static const std::string TEST_BUNDLE_NAME = "ohos";
static AccessTokenIDEx g_testTokenIDEx = {0};
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
}

void DumpTokenInfoTest::TearDownTestCase()
{
    setuid(g_selfUid);
    SetSelfTokenID(g_selfTokenId);
}

void DumpTokenInfoTest::SetUp()
{
    ACCESSTOKEN_LOG_INFO(LABEL, "SetUp ok.");

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
    ACCESSTOKEN_LOG_INFO(LABEL, "DumpTokenInfoAbnormalTest001");
    AccessTokenKit::AllocHapToken(g_InfoParms, g_PolicyPrams);

    g_testTokenIDEx = AccessTokenKit::GetHapTokenIDEx(g_InfoParms.userID,
                                                      g_InfoParms.bundleName,
                                                      g_InfoParms.instIndex);
    ASSERT_NE(INVALID_TOKENID, g_testTokenIDEx.tokenIDEx);
    setuid(g_selfUid);
    EXPECT_EQ(0, SetSelfTokenID(g_testTokenIDEx.tokenIDEx));
    setuid(1234); // 1234: UID


    std::string dumpInfo;
    AtmToolsParamInfo info;
    info.tokenId = 123;
    AccessTokenKit::DumpTokenInfo(info, dumpInfo);
    ASSERT_EQ("", dumpInfo);

    setuid(g_selfUid);
    EXPECT_EQ(0, SetSelfTokenID(g_selfTokenId));
    setuid(g_selfUid);
}

/**
 * @tc.name: DumpTokenInfoAbnormalTest002
 * @tc.desc: Get dump token information with invalid tokenID
 * @tc.type: FUNC
 * @tc.require:Issue Number
 */
HWTEST_F(DumpTokenInfoTest, DumpTokenInfoAbnormalTest002, TestSize.Level1)
{
    ACCESSTOKEN_LOG_INFO(LABEL, "DumpTokenInfoAbnormalTest002");
    SetSelfTokenID(g_selfTokenId);
    std::string dumpInfo;
    AtmToolsParamInfo info;
    info.tokenId = 123;
    AccessTokenKit::DumpTokenInfo(info, dumpInfo);
    ASSERT_EQ("invalid tokenId", dumpInfo);
}
} // namespace AccessToken
} // namespace Security
} // namespace OHOS