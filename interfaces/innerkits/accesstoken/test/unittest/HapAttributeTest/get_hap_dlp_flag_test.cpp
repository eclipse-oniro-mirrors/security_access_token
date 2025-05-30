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

#include "get_hap_dlp_flag_test.h"
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
static const int INVALID_DLP_TOKEN_FLAG = -1;

void GetHapDlpFlagTest::SetUpTestCase()
{
}

void GetHapDlpFlagTest::TearDownTestCase()
{
}

void GetHapDlpFlagTest::SetUp()
{
    LOGI(ATM_DOMAIN, ATM_TAG, "SetUp ok.");
}

void GetHapDlpFlagTest::TearDown()
{
}

/**
 * @tc.name: GetHapDlpFlagFuncTest001
 * @tc.desc: GetHapDlpFlag function abnormal branch.
 * @tc.type: FUNC
 * @tc.require Issue Number:I5RJBB
 */
HWTEST_F(GetHapDlpFlagTest, GetHapDlpFlagFuncTest001, TestSize.Level0)
{
    LOGI(ATM_DOMAIN, ATM_TAG, "GetHapDlpFlagFuncTest001");

    AccessTokenID tokenID = 0;
    int32_t ret = AccessTokenKit::GetHapDlpFlag(tokenID);
    EXPECT_EQ(INVALID_DLP_TOKEN_FLAG, ret);
}
} // namespace AccessToken
} // namespace Security
} // namespace OHOS