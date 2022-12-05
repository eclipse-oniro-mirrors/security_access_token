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
#define private public
#include "token_sync_load_callback.h"
#undef private

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
 * @tc.name: OnLoadSystemAbilitySuccess001
 * @tc.desc: TokenSyncLoadCallback::OnLoadSystemAbilitySuccess function test
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(TokenSyncKitTest, OnLoadSystemAbilitySuccess001, TestSize.Level1)
{
    int32_t systemAbilityId = 0;

    bool ready = TokenSyncManagerClient::GetInstance().ready_; // backup
    TokenSyncManagerClient::GetInstance().ready_ = true;

    sptr<TokenSyncLoadCallback> callback = new (std::nothrow) TokenSyncLoadCallback();
    ASSERT_NE(nullptr, callback);

    callback->OnLoadSystemAbilitySuccess(systemAbilityId, nullptr); // start aystemabilityId is not TokenSync
    ASSERT_EQ(true, TokenSyncManagerClient::GetInstance().ready_);

    TokenSyncManagerClient::GetInstance().ready_ = false;
    callback->OnLoadSystemAbilityFail(0); // start aystemabilityId is not TokenSync
    ASSERT_EQ(false, TokenSyncManagerClient::GetInstance().ready_);

    systemAbilityId = ITokenSyncManager::SA_ID_TOKENSYNC_MANAGER_SERVICE;
    TokenSyncManagerClient::GetInstance().ready_ = true;
    callback->OnLoadSystemAbilitySuccess(systemAbilityId, nullptr); // remoteObject is null
    ASSERT_EQ(true, TokenSyncManagerClient::GetInstance().ready_);

    TokenSyncManagerClient::GetInstance().ready_ = false;
    callback->OnLoadSystemAbilityFail(systemAbilityId); // systemAbilityId = 3504
    ASSERT_EQ(true, TokenSyncManagerClient::GetInstance().ready_);

    TokenSyncManagerClient::GetInstance().ready_ = ready; // recovery
}

/**
 * @tc.name: UpdateRemoteHapTokenInfo001
 * @tc.desc: TokenSyncManagerProxy::UpdateRemoteHapTokenInfo function test
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(TokenSyncKitTest, UpdateRemoteHapTokenInfo001, TestSize.Level1)
{
    HapTokenInfoForSync tokenInfo;

    ASSERT_EQ(0, TokenSyncManagerClient::GetInstance().UpdateRemoteHapTokenInfo(tokenInfo));
}
} // namespace AccessToken
} // namespace Security
} // namespace OHOS
