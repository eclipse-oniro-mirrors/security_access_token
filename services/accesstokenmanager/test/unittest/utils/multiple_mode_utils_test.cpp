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

#include <climits>

#include "multiple_mode_utils.h"
#include "parameters.h"

using namespace testing::ext;
using namespace OHOS::Security::AccessToken;

namespace {
static constexpr int32_t MAIN_CLONE_INDEX_BASE = 10000;
// keep in sync with the private constants in multiple_mode_utils.cpp
static constexpr const char* IS_PC_MODE_PARAM = "persist.sceneboard.ispcmode";
static constexpr const char* MAIN_MODE_PARAM = "persist.sceneboard.mainmode";

class ModeUtilTest : public testing::Test {};

HWTEST(ModeUtilTest, GetTokenMode001, TestSize.Level1)
{
    EXPECT_EQ(MultipleMode::DEFAULT_OR_MAIN_MODE, MultipleModeUtils::GetTokenMode(0));
    EXPECT_EQ(MultipleMode::DEFAULT_OR_MAIN_MODE, MultipleModeUtils::GetTokenMode(9999));
    EXPECT_EQ(MultipleMode::SUB_MODE, MultipleModeUtils::GetTokenMode(10000));
    EXPECT_EQ(MultipleMode::SUB_MODE, MultipleModeUtils::GetTokenMode(19999));
}

HWTEST(ModeUtilTest, GetTokenMode002, TestSize.Level1)
{
    // negative indexes are clamped to the main mode, never a query-only value
    EXPECT_EQ(MultipleMode::DEFAULT_OR_MAIN_MODE, MultipleModeUtils::GetTokenMode(-1));
    EXPECT_EQ(MultipleMode::DEFAULT_OR_MAIN_MODE, MultipleModeUtils::GetTokenMode(-9999));
    EXPECT_EQ(MultipleMode::DEFAULT_OR_MAIN_MODE, MultipleModeUtils::GetTokenMode(-10000));
    EXPECT_EQ(MultipleMode::DEFAULT_OR_MAIN_MODE, MultipleModeUtils::GetTokenMode(-2 * MAIN_CLONE_INDEX_BASE));
    EXPECT_EQ(MultipleMode::SUB_MODE, MultipleModeUtils::GetTokenMode(10000));
    EXPECT_EQ(MultipleMode::SUB_MODE, MultipleModeUtils::GetTokenMode(10001));
    // beyond MAX_MODE the division result is passed through as-is
    EXPECT_EQ(2, static_cast<int32_t>(MultipleModeUtils::GetTokenMode(2 * MAIN_CLONE_INDEX_BASE)));
    EXPECT_EQ(INT_MAX / MAIN_CLONE_INDEX_BASE,
        static_cast<int32_t>(MultipleModeUtils::GetTokenMode(INT_MAX)));
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

HWTEST(ModeUtilTest, IsMainAppIndex002, TestSize.Level1)
{
    // every multiple of the base is a main-app index, negative ones included
    EXPECT_TRUE(MultipleModeUtils::IsMainAppIndex(2 * MAIN_CLONE_INDEX_BASE));
    EXPECT_TRUE(MultipleModeUtils::IsMainAppIndex(-MAIN_CLONE_INDEX_BASE));
    EXPECT_TRUE(MultipleModeUtils::IsMainAppIndex(-2 * MAIN_CLONE_INDEX_BASE));
    // any non-zero remainder is not
    EXPECT_FALSE(MultipleModeUtils::IsMainAppIndex(-1));
    EXPECT_FALSE(MultipleModeUtils::IsMainAppIndex(20001));
    EXPECT_FALSE(MultipleModeUtils::IsMainAppIndex(INT_MAX));
}

HWTEST(ModeUtilTest, GetCurrentMode001, TestSize.Level1)
{
    EXPECT_EQ(MultipleMode::DEFAULT_OR_MAIN_MODE, MultipleModeUtils::GetCurrentMode());
}

HWTEST(ModeUtilTest, GetCurrentMode002, TestSize.Level1)
{
    // ispcmode differs from mainmode: resolved as the sub mode
    OHOS::system::SetIntParameter(IS_PC_MODE_PARAM, 1);
    OHOS::system::SetIntParameter(MAIN_MODE_PARAM, 0);
    EXPECT_EQ(MultipleMode::SUB_MODE, MultipleModeUtils::GetCurrentMode());
    // mainmode above the sub mode value: still a mismatch
    OHOS::system::SetIntParameter(MAIN_MODE_PARAM, 2);
    EXPECT_EQ(MultipleMode::SUB_MODE, MultipleModeUtils::GetCurrentMode());
    OHOS::system::ClearIntParameter(IS_PC_MODE_PARAM);
    OHOS::system::ClearIntParameter(MAIN_MODE_PARAM);
}

HWTEST(ModeUtilTest, GetCurrentMode003, TestSize.Level1)
{
    // equal values resolve to the main mode, non-zero ones included
    OHOS::system::SetIntParameter(IS_PC_MODE_PARAM, 1);
    OHOS::system::SetIntParameter(MAIN_MODE_PARAM, 1);
    EXPECT_EQ(MultipleMode::DEFAULT_OR_MAIN_MODE, MultipleModeUtils::GetCurrentMode());
    OHOS::system::SetIntParameter(IS_PC_MODE_PARAM, 0);
    OHOS::system::SetIntParameter(MAIN_MODE_PARAM, 0);
    EXPECT_EQ(MultipleMode::DEFAULT_OR_MAIN_MODE, MultipleModeUtils::GetCurrentMode());
    OHOS::system::ClearIntParameter(IS_PC_MODE_PARAM);
    OHOS::system::ClearIntParameter(MAIN_MODE_PARAM);
}

HWTEST(ModeUtilTest, GetBundleModeKey001, TestSize.Level1)
{
    EXPECT_EQ("bundle0", MultipleModeUtils::GetBundleModeKey("bundle", 0));
    EXPECT_EQ("bundle11", MultipleModeUtils::GetBundleModeKey("bundle1", 1));
    EXPECT_EQ("bundle100000", MultipleModeUtils::GetBundleModeKey("bundle10000", 0));
}
}
