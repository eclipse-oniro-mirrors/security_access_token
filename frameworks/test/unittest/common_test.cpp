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

#include <gtest/gtest.h>
#include <memory>
#include <string>

#include "constant_common.h"

using namespace testing::ext;

namespace OHOS {
namespace Security {
namespace AccessToken {
class CommonTest : public testing::Test  {
public:
    static void SetUpTestCase();
    static void TearDownTestCase();

    void SetUp();
    void TearDown();
};

void CommonTest::SetUpTestCase() {}
void CommonTest::TearDownTestCase() {}
void CommonTest::SetUp() {}
void CommonTest::TearDown() {}

/**
 * @tc.name: EncryptDevId001
 * @tc.desc: Test EncryptDevId001 function.
 * @tc.type: FUNC
 * @tc.require: issueI5RUCC
 */
HWTEST_F(CommonTest, EncryptDevId001, TestSize.Level1)
{
    std::string res;
    res = ConstantCommon::EncryptDevId("");
    EXPECT_EQ(res, "");

    res = ConstantCommon::EncryptDevId("12345");
    EXPECT_EQ(res, "1*******");

    res = ConstantCommon::EncryptDevId("123454321");
    EXPECT_EQ(res, "1234****4321");
}
} // namespace AccessToken
} // namespace Security
} // namespace OHOS
