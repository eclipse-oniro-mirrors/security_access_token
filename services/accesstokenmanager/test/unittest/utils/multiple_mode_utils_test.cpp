/*
 * Copyright (c) 2026 Huawei Device Co., Ltd.
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 *
 * http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 */

#include <gtest/gtest.h>

#include "multiple_mode_utils.h"

using namespace testing::ext;
using namespace OHOS::Security::AccessToken;

namespace {
static constexpr int32_t MAIN_CLONE_INDEX_BASE = 10000;

class ModeUtilTest : public testing::Test {};

HWTEST(ModeUtilTest, GetTokenMode001, TestSize.Level1)
{
    EXPECT_EQ(MultipleMode::DEFAULT_OR_MAIN_MODE, MultipleModeUtils::GetTokenMode(0));
    EXPECT_EQ(MultipleMode::DEFAULT_OR_MAIN_MODE, MultipleModeUtils::GetTokenMode(9999));
    EXPECT_EQ(MultipleMode::SUB_MODE, MultipleModeUtils::GetTokenMode(10000));
    EXPECT_EQ(MultipleMode::SUB_MODE, MultipleModeUtils::GetTokenMode(19999));
}

HWTEST(ModeUtilTest, IsMainAppIndex001, TestSize.Level1)
{
    EXPECT_TRUE(MultipleModeUtils::IsMainAppIndex(0));
    EXPECT_TRUE(MultipleModeUtils::IsMainAppIndex(MAIN_CLONE_INDEX_BASE));
    EXPECT_FALSE(MultipleModeUtils::IsMainAppIndex(1));
    EXPECT_FALSE(MultipleModeUtils::IsMainAppIndex(9999));
    EXPECT_FALSE(MultipleModeUtils::IsMainAppIndex(10001));
    EXPECT_FALSE(MultipleModeUtils::IsMainAppIndex(19999));
}

HWTEST(ModeUtilTest, GetCurrentMode001, TestSize.Level1)
{
    EXPECT_EQ(MultipleMode::DEFAULT_OR_MAIN_MODE, MultipleModeUtils::GetCurrentMode());
}

HWTEST(ModeUtilTest, GetBundleModeKey001, TestSize.Level1)
{
    EXPECT_EQ("bundle0", MultipleModeUtils::GetBundleModeKey("bundle", 0));
    EXPECT_EQ("bundle11", MultipleModeUtils::GetBundleModeKey("bundle1", 1));
    EXPECT_EQ("bundle100000", MultipleModeUtils::GetBundleModeKey("bundle10000", 0));
}
}
