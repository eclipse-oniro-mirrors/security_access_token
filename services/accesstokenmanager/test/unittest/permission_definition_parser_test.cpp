/*
 * Copyright (c) 2021-2022 Huawei Device Co., Ltd.
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

#include "permission_definition_parser_test.h"

#include "gtest/gtest.h"
#include <fcntl.h>
#include <memory>
#include <string>
#include <sys/socket.h>
#include <sys/stat.h>
#include <sys/un.h>
#include <thread>
#include <unistd.h>
#include <vector>

#include "access_token.h"
#include "accesstoken_info_manager.h"
#include "accesstoken_kit.h"
#include "access_token_error.h"
#include "permission_manager.h"
#include "permission_state_full.h"
#define private public
#include "json_parser.h"
#include "permission_definition_cache.h"
#include "permission_definition_parser.h"
#undef private
#include "securec.h"
#include "access_token_db.h"
#include "token_field_const.h"

using namespace testing::ext;
using namespace OHOS::Security::AccessToken;

namespace {
static bool g_hasHapPermissionDefinition;
static std::map<std::string, PermissionDefData> g_permissionDefinitionMap;
static const int32_t EXTENSION_PERMISSION_ID = 0;
static constexpr OHOS::HiviewDFX::HiLogLabel LABEL = {LOG_CORE,
    SECURITY_DOMAIN_ACCESSTOKEN, "PermissionDefinitionParserTest"};
static const std::string SYSTEM_PERMISSION_A = "ohos.permission.PermDefParserTestA";
static const std::string USER_PERMISSION_B = "ohos.permission.PermDefParserTestB";
}

void PermissionDefinitionParserTest::SetUpTestCase()
{
}

void PermissionDefinitionParserTest::TearDownTestCase()
{
}

void PermissionDefinitionParserTest::SetUp()
{
    g_permissionDefinitionMap = PermissionDefinitionCache::GetInstance().permissionDefinitionMap_;
    PermissionDefinitionCache::GetInstance().permissionDefinitionMap_.clear();
    g_hasHapPermissionDefinition = PermissionDefinitionCache::GetInstance().hasHapPermissionDefinition_;
    PermissionDefinitionCache::GetInstance().hasHapPermissionDefinition_ = false;
}

void PermissionDefinitionParserTest::TearDown()
{
    PermissionDefinitionCache::GetInstance().permissionDefinitionMap_ = g_permissionDefinitionMap; // recovery
    PermissionDefinitionCache::GetInstance().hasHapPermissionDefinition_ = g_hasHapPermissionDefinition;
    ACCESSTOKEN_LOG_INFO(LABEL, "test down!");
}

/**
 * @tc.name: ParserPermsRawDataTest001
 * @tc.desc: Parse permission definition information.
 * @tc.type: FUNC
 * @tc.require: Issue Number
 */
HWTEST_F(PermissionDefinitionParserTest, ParserPermsRawDataTest001, TestSize.Level1)
{
    EXPECT_FALSE(PermissionDefinitionCache::GetInstance().HasDefinition(SYSTEM_PERMISSION_A));
    EXPECT_FALSE(PermissionDefinitionCache::GetInstance().HasDefinition(USER_PERMISSION_B));
    PermissionDefinitionParser& parser = PermissionDefinitionParser::GetInstance();
    std::string permsRawData = R"({"systemGrantPermissions":[)"\
        R"({"name":"ohos.permission.PermDefParserTestA","grantMode":"system_grant","availableLevel":"system_basic",)"\
        R"("availableType":"SERVICE","provisionEnable":true,"distributedSceneEnable":false}],)"\
        R"("userGrantPermissions":[)"\
        R"({"name":"ohos.permission.PermDefParserTestB","grantMode":"user_grant","availableLevel":"system_basic",)"\
        R"("availableType":"SERVICE","provisionEnable":true,"distributedSceneEnable":false,)"\
        R"("label":"$string:test_label_B","description":"$string:test_description_B"}]})";
    std::vector<PermissionDef> permDefList;
    int32_t ret = parser.ParserPermsRawData(permsRawData, permDefList);
    ASSERT_EQ(ret, RET_SUCCESS);
    EXPECT_EQ(2, permDefList.size());

    for (const auto& perm : permDefList) {
        GTEST_LOG_(INFO) << perm.permissionName.c_str();
        PermissionDefinitionCache::GetInstance().Insert(perm, EXTENSION_PERMISSION_ID);
    }

    EXPECT_TRUE(PermissionDefinitionCache::GetInstance().HasDefinition(SYSTEM_PERMISSION_A));
    EXPECT_TRUE(PermissionDefinitionCache::GetInstance().HasDefinition(USER_PERMISSION_B));
    PermissionDef permissionDefResult;
    PermissionManager::GetInstance().GetDefPermission(SYSTEM_PERMISSION_A, permissionDefResult);
    EXPECT_EQ(SYSTEM_GRANT, permissionDefResult.grantMode);
    EXPECT_EQ(APL_SYSTEM_BASIC, permissionDefResult.availableLevel);
    EXPECT_EQ(SERVICE, permissionDefResult.availableType);
    EXPECT_EQ(true, permissionDefResult.provisionEnable);
    EXPECT_EQ(false, permissionDefResult.distributedSceneEnable);
    EXPECT_EQ("", permissionDefResult.label);
    EXPECT_EQ("", permissionDefResult.description);

    PermissionManager::GetInstance().GetDefPermission(USER_PERMISSION_B, permissionDefResult);
    EXPECT_EQ(USER_GRANT, permissionDefResult.grantMode);
    EXPECT_EQ(APL_SYSTEM_BASIC, permissionDefResult.availableLevel);
    EXPECT_EQ(SERVICE, permissionDefResult.availableType);
    EXPECT_EQ(true, permissionDefResult.provisionEnable);
    EXPECT_EQ(false, permissionDefResult.distributedSceneEnable);
    EXPECT_EQ("$string:test_label_B", permissionDefResult.label);
    EXPECT_EQ("$string:test_description_B", permissionDefResult.description);
}

/**
 * @tc.name: ParserPermsRawDataTest002
 * @tc.desc: Invalid file.
 * @tc.type: FUNC
 * @tc.require: Issue Number
 */
HWTEST_F(PermissionDefinitionParserTest, ParserPermsRawDataTest002, TestSize.Level1)
{
    PermissionDefinitionParser& parser = PermissionDefinitionParser::GetInstance();
    std::string permsRawData = R"({"systemGrantPermissions":[)"\
        R"({"name":"ohos.permission.xxxxxxxxxxxxxxxxxxxxxxxxxx",)"\
        R"("xxxxxxxxxxxxxxxxxxxxxxxxxx":"$string:test_description_B"}]})";
    std::vector<PermissionDef> permDefList;
    int32_t ret = parser.ParserPermsRawData(permsRawData, permDefList);
    ASSERT_EQ(ret, ERR_PERM_REQUEST_CFG_FAILED);
}

/**
 * @tc.name: ParserPermsRawDataTest003
 * @tc.desc: Permission definition file missing.
 * @tc.type: FUNC
 * @tc.require: Issue Number
 */
HWTEST_F(PermissionDefinitionParserTest, ParserPermsRawDataTest003, TestSize.Level1)
{
    EXPECT_FALSE(PermissionDefinitionCache::GetInstance().HasDefinition(SYSTEM_PERMISSION_A));
    EXPECT_FALSE(PermissionDefinitionCache::GetInstance().HasDefinition(USER_PERMISSION_B));
    PermissionDefinitionParser& parser = PermissionDefinitionParser::GetInstance();
    std::string permsRawData = R"({"systemGrantPermissions":[)"\
        R"({"name":"ohos.permission.PermDefParserTestA","grantMode":"system_grant","availableLevel":"system_basic",)"\
        R"("availableType":"SERVICE","provisionEnable":true,"distributedSceneEnable":false}]})";
    std::vector<PermissionDef> permDefList;
    int32_t ret = parser.ParserPermsRawData(permsRawData, permDefList);
    ASSERT_EQ(ret, ERR_PARAM_INVALID);

    permsRawData = R"({"userGrantPermissions":[)"\
        R"({"name":"ohos.permission.PermDefParserTestB","grantMode":"user_grant","availableLevel":"system_basic",)"\
        R"("availableType":"SERVICE","provisionEnable":true,"distributedSceneEnable":false,)"\
        R"("label":"$string:test_label_B","description":"$string:test_description_B"}]})";
    ret = parser.ParserPermsRawData(permsRawData, permDefList);
    ASSERT_EQ(ret, ERR_PARAM_INVALID);
}

/**
 * @tc.name: FromJson001
 * @tc.desc: Test property value is missing
 * @tc.type: FUNC
 * @tc.require: Issue Number
 */
HWTEST_F(PermissionDefinitionParserTest, FromJson001, TestSize.Level1)
{
    PermissionDefinitionParser& instance = PermissionDefinitionParser::GetInstance();
    std::string permsRawData = R"({"systemGrantPermissions":[)"\
        R"({"grantMode":"system_grant","availableLevel":"system_basic",)"\
        R"("availableType":"SERVICE","provisionEnable":true,"distributedSceneEnable":false}],)"\
        R"("userGrantPermissions":[]})";
    std::vector<PermissionDef> permDefList;
    instance.ParserPermsRawData(permsRawData, permDefList);
    EXPECT_EQ(0, permDefList.size());
    EXPECT_EQ(false, PermissionDefinitionCache::GetInstance().HasDefinition(SYSTEM_PERMISSION_A));

    permsRawData = R"({"systemGrantPermissions":[)"\
        R"({"name":"ohos.permission.PermDefParserTestA","availableLevel":"system_basic",)"\
        R"("availableType":"SERVICE","provisionEnable":true,"distributedSceneEnable":false}],)"\
        R"("userGrantPermissions":[]})";
    instance.ParserPermsRawData(permsRawData, permDefList);
    EXPECT_EQ(0, permDefList.size());
    EXPECT_EQ(false, PermissionDefinitionCache::GetInstance().HasDefinition(SYSTEM_PERMISSION_A));

    permsRawData = R"({"systemGrantPermissions":[)"\
        R"({"name":"ohos.permission.PermDefParserTestA","grantMode":"system_grant",)"\
        R"("availableType":"SERVICE","provisionEnable":true,"distributedSceneEnable":false}],)"\
        R"("userGrantPermissions":[]})";
    instance.ParserPermsRawData(permsRawData, permDefList);
    EXPECT_EQ(0, permDefList.size());
    EXPECT_EQ(false, PermissionDefinitionCache::GetInstance().HasDefinition(SYSTEM_PERMISSION_A));

    permsRawData = R"({"systemGrantPermissions":[)"\
        R"({"name":"ohos.permission.PermDefParserTestA","grantMode":"system_grant","availableLevel":"system_basic",)"\
        R"("provisionEnable":true,"distributedSceneEnable":false}],)"\
        R"("userGrantPermissions":[]})";
    instance.ParserPermsRawData(permsRawData, permDefList);
    EXPECT_EQ(0, permDefList.size());
    EXPECT_EQ(false, PermissionDefinitionCache::GetInstance().HasDefinition(SYSTEM_PERMISSION_A));
}

/**
 * @tc.name: FromJson002
 * @tc.desc: Test property value is missing
 * @tc.type: FUNC
 * @tc.require: Issue Number
 */
HWTEST_F(PermissionDefinitionParserTest, FromJson002, TestSize.Level1)
{
    PermissionDefinitionParser& instance = PermissionDefinitionParser::GetInstance();
    std::string permsRawData = R"({"systemGrantPermissions":[)"\
        R"({"name":"ohos.permission.PermDefParserTestA","grantMode":"system_grant","availableLevel":"system_basic",)"\
        R"("availableType":"SERVICE","distributedSceneEnable":false}],)"\
        R"("userGrantPermissions":[]})";
    std::vector<PermissionDef> permDefList;
    instance.ParserPermsRawData(permsRawData, permDefList);
    EXPECT_EQ(0, permDefList.size());
    EXPECT_EQ(false, PermissionDefinitionCache::GetInstance().HasDefinition(SYSTEM_PERMISSION_A));

    permsRawData = R"({"systemGrantPermissions":[],)"\
        R"("userGrantPermissions":[)"\
        R"({"name":"ohos.permission.PermDefParserTestB","grantMode":"user_grant","availableLevel":"system_basic",)"\
        R"("availableType":"SERVICE","provisionEnable":true,"distributedSceneEnable":false,)"\
        R"("description":"$string:test_description_B"}]})";
    instance.ParserPermsRawData(permsRawData, permDefList);
    EXPECT_EQ(0, permDefList.size());
    EXPECT_EQ(false, PermissionDefinitionCache::GetInstance().HasDefinition(USER_PERMISSION_B));

    permsRawData = R"({"systemGrantPermissions":[],)"\
        R"("userGrantPermissions":[)"\
        R"({"name":"ohos.permission.PermDefParserTestB","grantMode":"user_grant","availableLevel":"system_basic",)"\
        R"("availableType":"SERVICE","provisionEnable":true,"distributedSceneEnable":false,})"\
        R"("label":"$string:test_label_B"]})";
    instance.ParserPermsRawData(permsRawData, permDefList);
    EXPECT_EQ(0, permDefList.size());
    EXPECT_EQ(false, PermissionDefinitionCache::GetInstance().HasDefinition(USER_PERMISSION_B));
}

/**
 * @tc.name: FromJson003
 * @tc.desc: Invalid param
 * @tc.type: FUNC
 * @tc.require: Issue Number
 */
HWTEST_F(PermissionDefinitionParserTest, FromJson003, TestSize.Level1)
{
    PermissionDefinitionParser& instance = PermissionDefinitionParser::GetInstance();
    std::string permsRawData = R"({"systemGrantPermissions":[)"\
        R"({"name":123,"grantMode":"system_grant","availableLevel":"system_basic",)"\
        R"("availableType":"SERVICE","provisionEnable":true,"distributedSceneEnable":false}],)"\
        R"("userGrantPermissions":[]})";
    std::vector<PermissionDef> permDefList;
    instance.ParserPermsRawData(permsRawData, permDefList);
    EXPECT_EQ(0, permDefList.size());
    EXPECT_EQ(false, PermissionDefinitionCache::GetInstance().HasDefinition(SYSTEM_PERMISSION_A));

    permsRawData = R"({"systemGrantPermissions":[)"\
        R"({"name":"ohos.permission.PermDefParserTestA","grantMode":123,"availableLevel":"system_basic",)"\
        R"("availableType":"SERVICE","provisionEnable":true,"distributedSceneEnable":false}],)"\
        R"("userGrantPermissions":[]})";
    instance.ParserPermsRawData(permsRawData, permDefList);
    EXPECT_EQ(0, permDefList.size());
    EXPECT_EQ(false, PermissionDefinitionCache::GetInstance().HasDefinition(SYSTEM_PERMISSION_A));

    permsRawData = R"({"systemGrantPermissions":[)"\
        R"({"name":"ohos.permission.PermDefParserTestA","grantMode":"system_grant","availableLevel":123,)"\
        R"("availableType":"SERVICE","provisionEnable":true,"distributedSceneEnable":false}],)"\
        R"("userGrantPermissions":[]})";
    instance.ParserPermsRawData(permsRawData, permDefList);
    EXPECT_EQ(0, permDefList.size());
    EXPECT_EQ(false, PermissionDefinitionCache::GetInstance().HasDefinition(SYSTEM_PERMISSION_A));

    permsRawData = R"({"systemGrantPermissions":[)"\
        R"({"name":"ohos.permission.PermDefParserTestA","grantMode":"system_grant","availableLevel":"system_basic",)"\
        R"("availableType":SERVICE,"provisionEnable":true,"distributedSceneEnable":false}],)"\
        R"("userGrantPermissions":[]})";
    instance.ParserPermsRawData(permsRawData, permDefList);
    EXPECT_EQ(0, permDefList.size());
    EXPECT_EQ(false, PermissionDefinitionCache::GetInstance().HasDefinition(SYSTEM_PERMISSION_A));
}

/**
 * @tc.name: FromJson004
 * @tc.desc: Invalid param
 * @tc.type: FUNC
 * @tc.require: Issue Number
 */
HWTEST_F(PermissionDefinitionParserTest, FromJson004, TestSize.Level1)
{
    PermissionDefinitionParser& instance = PermissionDefinitionParser::GetInstance();
    std::string permsRawData = R"({"systemGrantPermissions":[)"\
        R"({"name":"ohos.permission.PermDefParserTestA","grantMode":"system_grant","availableLevel":"system_basic",)"\
        R"("availableType":"SERVICE","provisionEnable":"true","distributedSceneEnable":false}],)"\
        R"("userGrantPermissions":[]})";
    std::vector<PermissionDef> permDefList;
    instance.ParserPermsRawData(permsRawData, permDefList);
    EXPECT_EQ(0, permDefList.size());
    EXPECT_EQ(false, PermissionDefinitionCache::GetInstance().HasDefinition(SYSTEM_PERMISSION_A));

    permsRawData = R"({"systemGrantPermissions":[)"\
        R"({"name":"ohos.permission.PermDefParserTestA","grantMode":"system_grant","availableLevel":"system_basic",)"\
        R"("availableType":"SERVICE","provisionEnable":true,"distributedSceneEnable":"false"}],)"\
        R"("userGrantPermissions":[]})";
    instance.ParserPermsRawData(permsRawData, permDefList);
    EXPECT_EQ(0, permDefList.size());
    EXPECT_EQ(false, PermissionDefinitionCache::GetInstance().HasDefinition(SYSTEM_PERMISSION_A));

    permsRawData = R"({"systemGrantPermissions":[],)"\
        R"("userGrantPermissions":[)"\
        R"({"name":"ohos.permission.PermDefParserTestB","grantMode":"user_grant","availableLevel":"system_basic",)"\
        R"("availableType":"SERVICE","provisionEnable":true,"distributedSceneEnable":false,"label":123,)"\
        R"("description":"$string:test_description_B"}]})";
    instance.ParserPermsRawData(permsRawData, permDefList);
    EXPECT_EQ(0, permDefList.size());
    EXPECT_EQ(false, PermissionDefinitionCache::GetInstance().HasDefinition(USER_PERMISSION_B));

    permsRawData = R"({"systemGrantPermissions":[],)"\
        R"("userGrantPermissions":[)"\
        R"({"name":"ohos.permission.PermDefParserTestB","grantMode":"user_grant","availableLevel":"system_basic",)"\
        R"("availableType":"SERVICE","provisionEnable":true,"distributedSceneEnable":false,)"\
        R"("label":"$string:test_label_B","description":123}]})";
    instance.ParserPermsRawData(permsRawData, permDefList);
    EXPECT_EQ(0, permDefList.size());
    EXPECT_EQ(false, PermissionDefinitionCache::GetInstance().HasDefinition(USER_PERMISSION_B));
}

/**
 * @tc.name: FromJson005
 * @tc.desc: Invalid param
 * @tc.type: FUNC
 * @tc.require: Issue Number
 */
HWTEST_F(PermissionDefinitionParserTest, FromJson005, TestSize.Level1)
{
    PermissionDefinitionParser& instance = PermissionDefinitionParser::GetInstance();
    std::string permsRawData = R"({"systemGrantPermissions":[)"\
        R"({"name":"","grantMode":"system_grant","availableLevel":"system_basic",)"\
        R"("availableType":"SERVICE","provisionEnable":true,"distributedSceneEnable":false}],)"\
        R"("userGrantPermissions":[]})";
    std::vector<PermissionDef> permDefList;
    instance.ParserPermsRawData(permsRawData, permDefList);
    EXPECT_EQ(0, permDefList.size());

    permsRawData = R"({"systemGrantPermissions":[)"\
        R"({"name":"ohos.permission.PermDefParserTestA","grantMode":"system_grant","availableLevel":"test",)"\
        R"("availableType":TEST,"provisionEnable":true,"distributedSceneEnable":"false"}],)"\
        R"("userGrantPermissions":[]})";
    instance.ParserPermsRawData(permsRawData, permDefList);
    EXPECT_EQ(0, permDefList.size());
}

/**
 * @tc.name: IsSystemGrantedPermission001
 * @tc.desc: Invalid param
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(PermissionDefinitionParserTest, IsSystemGrantedPermission001, TestSize.Level1)
{
    EXPECT_FALSE(
        PermissionDefinitionCache::GetInstance().IsSystemGrantedPermission("ohos.permission.SYSTEM_GRANT_FASLE"));
}
