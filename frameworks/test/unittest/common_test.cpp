/*
 * Copyright (c) 2022-2025 Huawei Device Co., Ltd.
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
#include "data_validator.h"
#define private public
#include "permission_map.h"
#undef private
#include "permission_validator.h"
#include "privacy_param.h"

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
    std::string res = ConstantCommon::EncryptDevId("");
    EXPECT_EQ(res, "");

    res = ConstantCommon::EncryptDevId("12345");
    EXPECT_EQ(res, "1*******");

    res = ConstantCommon::EncryptDevId("123454321");
    EXPECT_EQ(res, "1234****4321");
}

/*
 * @tc.name: IsDefinedPermissionTest001
 * @tc.desc: IsDefinedPermission function test
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(CommonTest, IsDefinedPermissionTest001, TestSize.Level1)
{
    bool res = IsDefinedPermission("ohos.permission.ANSWER_CALL");
    EXPECT_EQ(res, true);
    res = IsDefinedPermission("ohos.permission.TTTTT");
    EXPECT_EQ(res, false);
}

/*
 * @tc.name: IsUserGrantPermissionTest001
 * @tc.desc: IsUserGrantPermission function test
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(CommonTest, IsUserGrantPermissionTest001, TestSize.Level1)
{
    bool res = IsUserGrantPermission("ohos.permission.CAMERA");
    EXPECT_EQ(res, true);
    res = IsUserGrantPermission("ohos.permission.TTTTT");
    EXPECT_EQ(res, false);
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

/*
 * @tc.name: DataValidatorTest001
 * @tc.desc: Test IsLabelValid
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(CommonTest, DataValidatorTest001, TestSize.Level1)
{
    std::string label(MAX_PERM_SIZE, 'a');
    // invalid label, size > 256
    EXPECT_FALSE(DataValidator::IsLabelValid(label));
}

/*
 * @tc.name: DataValidatorTest002
 * @tc.desc: Test IsDescValid
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(CommonTest, DataValidatorTest002, TestSize.Level1)
{
    std::string desc(MAX_PERM_SIZE, 'a');
    // invalid desc, size > 256
    EXPECT_FALSE(DataValidator::IsDescValid(desc));
}

/*
 * @tc.name: DataValidatorTest003
 * @tc.desc: Test IsAclExtendedMapContentValid
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(CommonTest, DataValidatorTest003, TestSize.Level1)
{
    std::string permissionName;
    std::string value;
    // permissionName is empty
    EXPECT_FALSE(DataValidator::IsAclExtendedMapContentValid(permissionName, value));
}

/*
 * @tc.name: DataValidatorTest004
 * @tc.desc: Test IsPolicyTypeValid
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(CommonTest, DataValidatorTest004, TestSize.Level1)
{
    EXPECT_TRUE(DataValidator::IsPolicyTypeValid(static_cast<uint32_t>(EDM)));
    EXPECT_TRUE(DataValidator::IsPolicyTypeValid(static_cast<uint32_t>(PRIVACY)));
    EXPECT_TRUE(DataValidator::IsPolicyTypeValid(static_cast<uint32_t>(TEMPORARY)));
    EXPECT_FALSE(DataValidator::IsPolicyTypeValid(static_cast<uint32_t>(MIXED)));
}

/*
 * @tc.name: PermissionValidatorTest001
 * @tc.desc: Test IsPermissionDefValid
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(CommonTest, PermissionValidatorTest001, TestSize.Level1)
{
    std::string invalid(MAX_PERM_SIZE, 'a');
    PermissionDef def;
    def.label = invalid;
    EXPECT_FALSE(PermissionValidator::IsPermissionDefValid(def));
    def.label = "";

    def.description = invalid;
    EXPECT_FALSE(PermissionValidator::IsPermissionDefValid(def));
    def.description = "";

    def.bundleName = "";
    EXPECT_FALSE(PermissionValidator::IsPermissionDefValid(def));
    def.bundleName = "123";

    def.permissionName = "";
    EXPECT_FALSE(PermissionValidator::IsPermissionDefValid(def));
    def.permissionName = "ohos.permission.CAMERA";

    def.grantMode = MAX_PERM_SIZE;
    EXPECT_FALSE(PermissionValidator::IsPermissionDefValid(def));
    def.grantMode = GrantMode::USER_GRANT;

    def.availableLevel = APL_INVALID;
    EXPECT_FALSE(PermissionValidator::IsPermissionDefValid(def));
    def.availableLevel = APL_NORMAL;

    EXPECT_TRUE(PermissionValidator::IsPermissionDefValid(def));
}

/*
 * @tc.name: PermissionValidatorTest002
 * @tc.desc: Test FilterInvalidPermissionDef
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(CommonTest, PermissionValidatorTest002, TestSize.Level1)
{
    std::vector<PermissionDef> permList;
    std::vector<PermissionDef> result;

    PermissionDef def;
    def.label = "";
    def.description = "";
    def.bundleName = "123";
    def.permissionName = "ohos.permission.CAMERA";
    def.grantMode = GrantMode::USER_GRANT;
    def.availableLevel = APL_NORMAL;
    permList.push_back(def);
    // repetitive
    permList.push_back(def);

    def.permissionName = "";
    // invalid
    permList.push_back(def);

    PermissionValidator::FilterInvalidPermissionDef(permList, result);
    EXPECT_EQ(1, result.size());
}

/*
 * @tc.name: PermissionValidatorTest003
 * @tc.desc: Test FilterInvalidPermissionState
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(CommonTest, PermissionValidatorTest003, TestSize.Level1)
{
    std::vector<PermissionStatus> permList;
    std::vector<PermissionStatus> result;

    PermissionStatus status;
    status.permissionName = "ohos.permission.CAMERA";
    status.grantStatus = 0;
    status.grantFlag = 1;
    permList.push_back(status);
    // repetitive
    permList.push_back(status);

    PermissionValidator::FilterInvalidPermissionState(TOKEN_HAP, false, permList, result);
    EXPECT_EQ(1, result.size());
}
} // namespace AccessToken
} // namespace Security
} // namespace OHOS
