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
#include "iaccess_token_manager.h"
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
uint64_t g_selfShellTokenId;
}

void GetVersionTest::SetUpTestCase()
{
    g_selfShellTokenId = GetSelfTokenID();
    TestCommon::SetTestEvironment(g_selfShellTokenId);
}

void GetVersionTest::TearDownTestCase()
{
    SetSelfTokenID(g_selfShellTokenId);
    TestCommon::ResetTestEvironment();
}

void GetVersionTest::SetUp()
{
    LOGI(ATM_DOMAIN, ATM_TAG, "SetUp ok.");
}

void GetVersionTest::TearDown()
{
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
    std::vector<std::string> reqPerm;
    MockHapToken mock("GetVersionFuncTest001", reqPerm, false);

    uint32_t version;
    ASSERT_EQ(ERR_NOT_SYSTEM_APP, AccessTokenKit::GetVersion(version));
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
    std::vector<std::string> reqPerm;
    MockHapToken mock("GetVersionFuncTest002", reqPerm, true);

    uint32_t version;
    int32_t res = AccessTokenKit::GetVersion(version);
    ASSERT_EQ(RET_SUCCESS, res);
    ASSERT_EQ(DEFAULT_TOKEN_VERSION, version);
}
} // namespace AccessToken
} // namespace Security
} // namespace OHOS