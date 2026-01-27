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

#include "permission_manager_mock_test.h"

#include "access_token.h"
#include "access_token_error.h"

using namespace testing::ext;
using namespace OHOS;

namespace OHOS {
namespace Security {
namespace AccessToken {

void PermissionManagerMockTest::SetUpTestCase()
{}

void PermissionManagerMockTest::TearDownTestCase()
{}

void PermissionManagerMockTest::SetUp()
{}

void PermissionManagerMockTest::TearDown()
{}

/**
 * @tc.name: RequestAppPermOnSettingTest001
 * @tc.desc: Test RequestAppPermOnSetting.
 * @tc.type: FUNC
 * @tc.require: Issue
 */
HWTEST_F(PermissionManagerMockTest, RequestAppPermOnSettingTest001, TestSize.Level4)
{
    HapTokenInfo hapInfo;
    hapInfo.bundleName = "aaa";
    hapInfo.instIndex = 0;
    hapInfo.tokenID = 123;
    hapInfo.userID = 100;
    std::string bundleName = "bundleName";
    std::string abilityName = "abilityName";

    EXPECT_EQ(ERR_SERVICE_ABNORMAL,
        PermissionManager::GetInstance().RequestAppPermOnSetting(hapInfo, bundleName, abilityName));

    hapInfo.instIndex = 1;
    EXPECT_EQ(ERR_OK,
        PermissionManager::GetInstance().RequestAppPermOnSetting(hapInfo, bundleName, abilityName));
}
} // namespace AccessToken
} // namespace Security
} // namespace OHOS
