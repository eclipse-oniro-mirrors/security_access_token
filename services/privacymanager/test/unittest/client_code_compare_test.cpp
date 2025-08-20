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

#include <gtest/gtest.h>

#include "ability_manager_adapter.h"
#include "ability_manager_ipc_interface_code.h"
#include "app_manager_access_client.h"
#include "app_mgr_ipc_interface_code.h"

using namespace testing::ext;

namespace OHOS {
namespace Security {
namespace AccessToken {
class ClientCodeCompareTest : public testing::Test {
public:
    static void SetUpTestCase();
    static void TearDownTestCase();
    void SetUp();
    void TearDown();
};

void ClientCodeCompareTest::SetUpTestCase() {}
void ClientCodeCompareTest::TearDownTestCase() {}
void ClientCodeCompareTest::SetUp() {}
void ClientCodeCompareTest::TearDown() {}

/*
 * @tc.name: AmsCodeTest001
 * @tc.desc: test ability manager service interface code consistency.
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(ClientCodeCompareTest, AmsCodeTest001, TestSize.Level1)
{
    // ability manager interface code
    EXPECT_EQ(static_cast<uint32_t>(AbilityManagerAdapter::Message::START_ABILITY),
        static_cast<uint32_t>(AAFwk::AbilityManagerInterfaceCode::START_ABILITY));
    EXPECT_EQ(static_cast<uint32_t>(AbilityManagerAdapter::Message::KILL_PROCESS_FOR_PERMISSION_UPDATE),
        static_cast<uint32_t>(AAFwk::AbilityManagerInterfaceCode::KILL_PROCESS_FOR_PERMISSION_UPDATE));

    // app manager interface code
    EXPECT_EQ(static_cast<uint32_t>(AppManagerAccessClient::Message::REGISTER_APPLICATION_STATE_OBSERVER),
        static_cast<uint32_t>(AppExecFwk::AppMgrInterfaceCode::REGISTER_APPLICATION_STATE_OBSERVER));
    EXPECT_EQ(static_cast<uint32_t>(AppManagerAccessClient::Message::UNREGISTER_APPLICATION_STATE_OBSERVER),
        static_cast<uint32_t>(AppExecFwk::AppMgrInterfaceCode::UNREGISTER_APPLICATION_STATE_OBSERVER));
    EXPECT_EQ(static_cast<uint32_t>(AppManagerAccessClient::Message::GET_FOREGROUND_APPLICATIONS),
        static_cast<uint32_t>(AppExecFwk::AppMgrInterfaceCode::GET_FOREGROUND_APPLICATIONS));
}
} // namespace AccessToken
} // namespace Security
} // namespace OHOS
