/*
 * Copyright (c) 2022-2024 Huawei Device Co., Ltd.
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
#include <fcntl.h>

#include "access_token_error.h"
#include "constant_common.h"
#define private public
#include "permission_map.h"
#undef private

using namespace testing::ext;

namespace OHOS {
namespace Security {
namespace AccessToken {
namespace {
const static uint32_t MAX_PERM_SIZE = 2048;
}
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

/*
 * @tc.name: TransferOpcodeToPermission001
 * @tc.desc: TransferOpcodeToPermission function test
 * @tc.type: FUNC
 * @tc.require: issueI6024A
 */
HWTEST_F(CommonTest, TransferOpcodeToPermission001, TestSize.Level1)
{
    std::string permissionName;
    uint32_t opCode;
    EXPECT_TRUE(TransferPermissionToOpcode("ohos.permission.ANSWER_CALL", opCode));
    EXPECT_TRUE(TransferOpcodeToPermission(opCode, permissionName));
    EXPECT_EQ(permissionName, "ohos.permission.ANSWER_CALL");
}

/*
 * @tc.name: TransferOpcodeToPermission002
 * @tc.desc: TransferOpcodeToPermission code oversize
 * @tc.type: FUNC
 * @tc.require: issueI6024A
 */
HWTEST_F(CommonTest, TransferOpcodeToPermission002, TestSize.Level1)
{
    std::string permissionName;
    EXPECT_FALSE(TransferOpcodeToPermission(MAX_PERM_SIZE, permissionName));
    EXPECT_FALSE(TransferOpcodeToPermission(MAX_PERM_SIZE - 1, permissionName));
}

/*
 * @tc.name: PermissionDefineMapTest
 * @tc.desc: Test find permission difinition
 * @tc.type: FUNC
 * @tc.require:IBRDIV
 */
HWTEST_F(CommonTest, PermissionDefineMapTest, TestSize.Level1)
{
    EXPECT_TRUE(IsDefinedPermission("ohos.permission.ANSWER_CALL"));
    PermissionBriefDef permDef;
    EXPECT_TRUE(GetPermissionBriefDef("ohos.permission.ANSWER_CALL", permDef));
    EXPECT_TRUE(strcmp("ohos.permission.ANSWER_CALL", permDef.permissionName) == 0);
}
} // namespace AccessToken
} // namespace Security
} // namespace OHOS
