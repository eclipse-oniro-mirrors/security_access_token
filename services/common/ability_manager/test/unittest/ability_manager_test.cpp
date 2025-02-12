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

#include <gtest/gtest.h>
#include <string>
#include "access_token.h"
#include "ability_manager_access_loader.h"

using namespace testing::ext;

namespace OHOS {
namespace Security {
namespace AccessToken {
class AbilityManagerTest : public testing::Test {
public:
    static void SetUpTestCase(void);
    static void TearDownTestCase(void);
    void SetUp();
    void TearDown();
};

void AbilityManagerTest::SetUpTestCase() {}
void AbilityManagerTest::TearDownTestCase() {}
void AbilityManagerTest::SetUp() {}
void AbilityManagerTest::TearDown() {}

/**
 * @tc.name: AbilityManagerTest001
 * @tc.desc: Test StartAbility with invalid bundle name.
 * @tc.type: FUNC
 * @tc.require: Issue Number
 */
HWTEST_F(AbilityManagerTest, AbilityManagerTest001, TestSize.Level1)
{
    AbilityManagerAccessLoaderInterface* loader = static_cast<AbilityManagerAccessLoaderInterface*>(Create());
    InnerWant innerWant = {
        .bundleName = "InvalidBundleName001",
        .abilityName = "InvalidAbilityName001"
    };

    EXPECT_NE(ERR_OK, loader->StartAbility(innerWant, nullptr));
    Destroy(loader);
}
} // namespace AccessToken
} // namespace Security
} // namespace OHOS
