/*
 * Copyright (c) 2024-2026 Huawei Device Co., Ltd.
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

#include "multi_thread_test.h"

#include "access_token.h"
#include "access_token_error.h"
#include "accesstoken_common_log.h"
#define private public
#include "accesstoken_id_manager.h"
#undef private
#include "permission_validator.h"
#include "string_ex.h"
#include "token_setproc.h"


using namespace testing::ext;
using namespace testing::mt;
namespace OHOS {
namespace Security {
namespace AccessToken {
namespace {
bool g_register = false;
static std::set<AccessTokenID> g_tokenIdSet;
static constexpr int32_t TEST_TOKEN_ID_1 = 537800000;
static constexpr int32_t TEST_TOKEN_ID_2 = 537900000;
static constexpr int32_t MULTI_CYCLE_TIMES = 1000;
}

void AccessTokenMultiThreadTest::SetUpTestCase()
{
}

void AccessTokenMultiThreadTest::TearDownTestCase()
{
}

void AccessTokenMultiThreadTest::SetUp()
{
    LOGI(ATM_DOMAIN, ATM_TAG, "SetUp ok.");
    g_tokenIdSet = AccessTokenIDManager::GetInstance().tokenIdSet_;
    AccessTokenIDManager::GetInstance().tokenIdSet_.clear();
}

void AccessTokenMultiThreadTest::TearDown()
{
    AccessTokenIDManager::GetInstance().tokenIdSet_ = g_tokenIdSet; // recovery
}

void TestRegisterTokenId()
{
    AccessTokenID tokenId = TEST_TOKEN_ID_2;
    int32_t i = MULTI_CYCLE_TIMES + 1;
    while (i--) {
        tokenId += i;
        AccessTokenIDManager::GetInstance().RegisterTokenId(tokenId, TOKEN_HAP);
    }
}

void TestReleaseTokenId()
{
    AccessTokenID releaseId = TEST_TOKEN_ID_2;
    AccessTokenID tokenId = TEST_TOKEN_ID_1;
    g_register = !g_register;
    int32_t i = MULTI_CYCLE_TIMES + 1;
    if (!g_register) {
        while (i--) {
            releaseId += i;
            AccessTokenIDManager::GetInstance().ReleaseTokenId(releaseId);
        }
    } else {
        while (i--) {
            tokenId += i;
            AccessTokenIDManager::GetInstance().RegisterTokenId(tokenId, TOKEN_HAP);
        }
    }
}
} // namespace AccessToken
} // namespace Security
} // namespace OHOS
