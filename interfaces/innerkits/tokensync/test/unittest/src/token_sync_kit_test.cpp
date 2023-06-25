/*
 * Copyright (c) 2022 Huawei Device Co., Ltd.
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

#include "token_sync_kit_test.h"

#include "i_token_sync_manager.h"
#include "token_sync_manager_client.h"

using namespace testing::ext;

namespace OHOS {
namespace Security {
namespace AccessToken {
void TokenSyncKitTest::SetUpTestCase()
{}

void TokenSyncKitTest::TearDownTestCase()
{
}

void TokenSyncKitTest::SetUp()
{
}

void TokenSyncKitTest::TearDown()
{}

/**
 * @tc.name: UpdateRemoteHapTokenInfo001
 * @tc.desc: TokenSyncManagerProxy::UpdateRemoteHapTokenInfo function test
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(TokenSyncKitTest, UpdateRemoteHapTokenInfo001, TestSize.Level1)
{
    HapTokenInfoForSync tokenInfo;

    ASSERT_EQ(TokenSyncError::TOKEN_SYNC_IPC_ERROR,
        TokenSyncManagerClient::GetInstance().UpdateRemoteHapTokenInfo(tokenInfo));
}
} // namespace AccessToken
} // namespace Security
} // namespace OHOS
