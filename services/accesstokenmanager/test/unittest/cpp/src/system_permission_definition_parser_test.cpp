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

#include "system_permission_definition_parser_test.h"

#include <fcntl.h>
#include <memory>
#include <string>
#include <sys/socket.h>
#include <sys/stat.h>
#include <sys/un.h>
#include <thread>
#include <unistd.h>
#include <vector>

#include "accesstoken_info_manager.h"
#include "accesstoken_kit.h"
#include "access_token_error.h"
#include "permission_manager.h"
#include "data_storage.h"
#include "token_field_const.h"
#include "permission_state_full.h"
#define private public
#include "json_parser.h"
#include "permission_definition_cache.h"
#include "system_permission_definition_parser.h"
#undef private
#include "securec.h"

using namespace testing::ext;
using namespace OHOS::Security::AccessToken;

namespace {
static bool g_hasHapPermissionDefinition;
static std::map<std::string, PermissionDefData> g_permissionDefinitionMap;
static const int32_t EXTENSION_PERMISSION_ID = 0;
static constexpr OHOS::HiviewDFX::HiLogLabel LABEL = {LOG_CORE,
    SECURITY_DOMAIN_ACCESSTOKEN, "SystemPermissionDefinitionParserTest"};
static const std::string VALID_HAP_PERMISSION = "ohos.permission.VALID";
static const std::string SYSTEM_PERMISSION_NICER = "ohos.permission.NICER";
static PermissionDef g_hapDef = {
    .permissionName = VALID_HAP_PERMISSION,
    .bundleName = "SystemPermissionDefinitionParserTest",
    .grantMode = 1,
    .availableLevel = APL_NORMAL,
    .provisionEnable = false,
    .distributedSceneEnable = false,
    .label = "label",
    .labelId = 1,
    .description = "description",
    .descriptionId = 1
};
static PermissionStateFull g_stateNicer = {
    .permissionName = SYSTEM_PERMISSION_NICER,
    .isGeneral = true,
    .resDeviceID = {"local"},
    .grantStatus = {0},
    .grantFlags = {1}
};
static PermissionStateFull g_stateHapValid = {
    .permissionName = VALID_HAP_PERMISSION,
    .isGeneral = true,
    .resDeviceID = {"local"},
    .grantStatus = {0},
    .grantFlags = {1}
};
static HapPolicyParams g_policy = {
    .apl = APL_NORMAL,
    .domain = "test.domain",
    .permStateList = {g_stateNicer, g_stateHapValid}
};
}

void SystemPermissionDefinitionParserTest::SetUpTestCase()
{
}

void SystemPermissionDefinitionParserTest::TearDownTestCase()
{
}

void SystemPermissionDefinitionParserTest::SetUp()
{
    g_permissionDefinitionMap = PermissionDefinitionCache::GetInstance().permissionDefinitionMap_;
    PermissionDefinitionCache::GetInstance().permissionDefinitionMap_.clear();
    g_hasHapPermissionDefinition = PermissionDefinitionCache::GetInstance().hasHapPermissionDefinition_;
    PermissionDefinitionCache::GetInstance().hasHapPermissionDefinition_ = false;
}

void SystemPermissionDefinitionParserTest::TearDown()
{
    PermissionDefinitionCache::GetInstance().permissionDefinitionMap_ = g_permissionDefinitionMap; // recovery
    PermissionDefinitionCache::GetInstance().hasHapPermissionDefinition_ = g_hasHapPermissionDefinition;
    ACCESSTOKEN_LOG_INFO(LABEL, "test down!");
}

/**
 * @tc.name: ParserNativeRawData001
 * @tc.desc: Verify processing right native token json.
 * @tc.type: FUNC
 * @tc.require: Issue Number
 */
HWTEST_F(SystemPermissionDefinitionParserTest, ParserRawData001, TestSize.Level1)
{
    ACCESSTOKEN_LOG_INFO(LABEL, "test ParserRawData001!");

    SystemPermissionDefinitionParser& parser = SystemPermissionDefinitionParser::GetInstance();
    std::string permsRawData;
    int32_t ret = JsonParser::ReadCfgFile("/data/service/el0/access_token/permission_define.json", permsRawData);
    ASSERT_EQ(ret, 0);
    std::vector<PermissionDef> permDefList;
    ret = parser.ParserPermsRawData(permsRawData, permDefList);
    ASSERT_EQ(ret, 0);

    EXPECT_EQ(2, permDefList.size());
}

/**
 * @tc.name: ParserNativeRawData002
 * @tc.desc:
 * @tc.type: FUNC
 * @tc.require: Issue Number
 */
HWTEST_F(SystemPermissionDefinitionParserTest, ParserRawData002, TestSize.Level1)
{
    ACCESSTOKEN_LOG_INFO(LABEL, "test ParserRawData003!");
    EXPECT_EQ(false, PermissionDefinitionCache::GetInstance().HasDefinition("ohos.permission.NICER"));
    EXPECT_EQ(false, PermissionDefinitionCache::GetInstance().HasDefinition("ohos.permission.NICE"));
    SystemPermissionDefinitionParser& parser = SystemPermissionDefinitionParser::GetInstance();
    std::string permsRawData = R"({"definePermissions":[)"\
        R"({"name":"ohos.permission.NICE","grantMode":"system_grant", "availableLevel":"system_basic",)"\
        R"("provisionEnable":true, "distributedSceneEnable": false},)"\
        R"({"name":"ohos.permission.NICER","grantMode":"system_grant", "availableLevel":"system_basic",)"\
        R"("provisionEnable":true, "distributedSceneEnable": false}]})";
    std::vector<PermissionDef> permDefList;
    int32_t ret = parser.ParserPermsRawData(permsRawData, permDefList);
    ASSERT_EQ(ret, 0);

    EXPECT_EQ(2, permDefList.size());
    EXPECT_EQ(false, PermissionDefinitionCache::GetInstance().hasHapPermissionDefinition_);
    for (const auto& perm : permDefList) {
        GTEST_LOG_(INFO) << perm.permissionName.c_str();
        PermissionDefinitionCache::GetInstance().Insert(perm, EXTENSION_PERMISSION_ID);
    }
    EXPECT_EQ(true, PermissionDefinitionCache::GetInstance().HasDefinition("ohos.permission.NICE"));
    EXPECT_EQ(true, PermissionDefinitionCache::GetInstance().HasDefinition("ohos.permission.NICER"));
    PermissionDef permissionDefResult;
    PermissionManager::GetInstance().GetDefPermission("ohos.permission.NICE", permissionDefResult);
    EXPECT_EQ(APL_SYSTEM_BASIC, permissionDefResult.availableLevel);
    EXPECT_EQ(1, permissionDefResult.grantMode);
    EXPECT_EQ("system_ability", permissionDefResult.bundleName);
    EXPECT_EQ("", permissionDefResult.description);
    EXPECT_EQ("", permissionDefResult.label);
    EXPECT_EQ(true, permissionDefResult.provisionEnable);
    EXPECT_EQ(false, permissionDefResult.distributedSceneEnable);
}

/**
 * @tc.name: ParserRawData003
 * @tc.desc:
 * @tc.type: FUNC
 * @tc.require: Issue Number
 */
HWTEST_F(SystemPermissionDefinitionParserTest, ParserRawData003, TestSize.Level1)
{
    ACCESSTOKEN_LOG_INFO(LABEL, "test ParserRawData003!");
    SystemPermissionDefinitionParser& parser = SystemPermissionDefinitionParser::GetInstance();
    std::string permsRawData = R"({"definePermissions":[)"\
        R"({"name":"ohos.permission.NICE","grantMode":"system_grant", "availableLevel":"system_basic",)"\
        R"("provisionEnable":true, "distributedSceneEnable": false},)"\
        R"({"name":"ohos.permission.NICER","grantMode":"user_grant", "availableLevel":"system_basic",)"\
        R"("provisionEnable":true, "distributedSceneEnable": false}]})";
    EXPECT_EQ(false, PermissionDefinitionCache::GetInstance().HasDefinition("ohos.permission.NICER"));
    EXPECT_EQ(false, PermissionDefinitionCache::GetInstance().HasDefinition("ohos.permission.NICE"));
    std::vector<PermissionDef> permDefList;
    int32_t ret = parser.ParserPermsRawData(permsRawData, permDefList);
    ASSERT_EQ(ret, 0);

    EXPECT_EQ(1, permDefList.size());
    for (const auto& perm : permDefList) {
        GTEST_LOG_(INFO) << perm.permissionName.c_str();
        PermissionDefinitionCache::GetInstance().Insert(perm, EXTENSION_PERMISSION_ID);
    }
    EXPECT_EQ(true, PermissionDefinitionCache::GetInstance().HasDefinition("ohos.permission.NICE"));
    EXPECT_EQ(false, PermissionDefinitionCache::GetInstance().HasDefinition("ohos.permission.NICER"));
}

/**
 * @tc.name: ParserRawData004
 * @tc.desc: invalid grantMode
 * @tc.type: FUNC
 * @tc.require: Issue Number
 */
HWTEST_F(SystemPermissionDefinitionParserTest, ParserRawData004, TestSize.Level1)
{
    SystemPermissionDefinitionParser& instance = SystemPermissionDefinitionParser::GetInstance();
    std::string data = R"({"definePermissions":[)"\
        R"({"name":"ohos.permission.NICE","grantMode":"system_grant", "availableLevel":"system_xx",)"\
        R"("provisionEnable":true, "distributedSceneEnable": false},)"\
        R"({"name":"ohos.permission.NICER","grantMode":"system_grant", "availableLevel":"",)"\
        R"("provisionEnable":true, "distributedSceneEnable": false}]})";
    std::vector<PermissionDef> permDefList;
    int32_t ret = instance.ParserPermsRawData(data, permDefList);
    EXPECT_EQ(ret, 0);

    EXPECT_EQ(0, permDefList.size());
    for (const auto& permDef : permDefList) {
        PermissionDefinitionCache::GetInstance().Insert(permDef, EXTENSION_PERMISSION_ID);
    }
    EXPECT_EQ(false, PermissionDefinitionCache::GetInstance().HasDefinition("ohos.permission.NICE"));
    EXPECT_EQ(false, PermissionDefinitionCache::GetInstance().HasDefinition("ohos.permission.NICER"));
}

/**
 * @tc.name: ParserRawData005
 * @tc.desc: invalid name.
 * @tc.type: FUNC
 * @tc.require: Issue Number
 */
HWTEST_F(SystemPermissionDefinitionParserTest, ParserRawData005, TestSize.Level1)
{
    SystemPermissionDefinitionParser& parser = SystemPermissionDefinitionParser::GetInstance();
    std::string rawData = R"({"definePermissions":[)"\
        R"({"name":"","grantMode":"system_grant", "availableLevel":"system_basic",)"\
        R"("provisionEnable":true, "distributedSceneEnable": false},)"\
        R"({"name":"ohos.permission.NICERxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxx)"\
        R"(xxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxx)"\
        R"(xxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxx)"\
        R"(xxxxx","grantMode":"system_grant", "availableLevel":"system_basic",)"\
        R"("provisionEnable":true, "distributedSceneEnable": false},)"\
        R"({"name":"","grantMode":"system_grant", "availableLevel":"system_basic",)"\
        R"("provisionEnable":true, "distributedSceneEnable": false}]})";
    EXPECT_EQ(false, PermissionDefinitionCache::GetInstance().HasDefinition("ohos.permission.NICER"));
    EXPECT_EQ(false, PermissionDefinitionCache::GetInstance().HasDefinition("ohos.permission.NICE"));
    std::vector<PermissionDef> permDefList;
    int32_t ret = parser.ParserPermsRawData(rawData, permDefList);
    ASSERT_EQ(ret, 0);

    EXPECT_EQ(0, permDefList.size());
    for (const auto& perm : permDefList) {
        GTEST_LOG_(INFO) << perm.permissionName.c_str();
        PermissionDefinitionCache::GetInstance().Insert(perm, EXTENSION_PERMISSION_ID);
    }
    EXPECT_EQ(false, PermissionDefinitionCache::GetInstance().HasDefinition("ohos.permission.NICE"));
    EXPECT_EQ(false, PermissionDefinitionCache::GetInstance().HasDefinition("ohos.permission.NICER"));
}

/**
 * @tc.name: ParserRawData006
 * @tc.desc: invalid provisionEnable
 * @tc.type: FUNC
 * @tc.require: Issue Number
 */
HWTEST_F(SystemPermissionDefinitionParserTest, ParserRawData006, TestSize.Level1)
{
    SystemPermissionDefinitionParser& instance = SystemPermissionDefinitionParser::GetInstance();
    std::string data = R"({"definePermissions":[)"\
        R"({"name":"ohos.permission.NICE","grantMode":"system_grant", "availableLevel":"system_core",)"\
        R"("provisionEnable":true, "distributedSceneEnable": false},)"\
        R"({"name":"ohos.permission.NICER","grantMode":"user_grant", "availableLevel":"system_core",)"\
        R"("provisionEnable":"true", "distributedSceneEnable": false}]})";
    EXPECT_EQ(false, PermissionDefinitionCache::GetInstance().HasDefinition("ohos.permission.NICER"));
    EXPECT_EQ(false, PermissionDefinitionCache::GetInstance().HasDefinition("ohos.permission.NICE"));
    std::vector<PermissionDef> permDefList;
    (void)instance.ParserPermsRawData(data, permDefList);

    EXPECT_EQ(1, permDefList.size());
    for (const auto& p : permDefList) {
        PermissionDefinitionCache::GetInstance().Insert(p, EXTENSION_PERMISSION_ID);
    }
    EXPECT_EQ(true, PermissionDefinitionCache::GetInstance().HasDefinition("ohos.permission.NICE"));
    EXPECT_EQ(false, PermissionDefinitionCache::GetInstance().HasDefinition("ohos.permission.NICER"));
}

/**
 * @tc.name: ParserRawData007
 * @tc.desc: invalid distributedSceneEnable
 * @tc.type: FUNC
 * @tc.require: Issue Number
 */
HWTEST_F(SystemPermissionDefinitionParserTest, ParserRawData007, TestSize.Level1)
{
    SystemPermissionDefinitionParser& instance = SystemPermissionDefinitionParser::GetInstance();
    std::string data = R"({"definePermissions":[)"\
        R"({"name":"ohos.permission.NICE","grantMode":"system_grant", "availableLevel":"system_core",)"\
        R"("provisionEnable":true, "distributedSceneEnable": "xx"},)"\
        R"({"name":"ohos.permission.NICER","grantMode":"system_grant", "availableLevel":"system_core",)"\
        R"("provisionEnable":false, "distributedSceneEnable": false}]})";
    EXPECT_EQ(false, PermissionDefinitionCache::GetInstance().HasDefinition("ohos.permission.NICER"));
    EXPECT_EQ(false, PermissionDefinitionCache::GetInstance().HasDefinition("ohos.permission.NICE"));
    std::vector<PermissionDef> permDefList;
    (void)instance.ParserPermsRawData(data, permDefList);

    EXPECT_EQ(1, permDefList.size());
    for (const auto& p : permDefList) {
        PermissionDefinitionCache::GetInstance().Insert(p, EXTENSION_PERMISSION_ID);
    }
    EXPECT_EQ(false, PermissionDefinitionCache::GetInstance().HasDefinition("ohos.permission.NICE"));
    EXPECT_EQ(true, PermissionDefinitionCache::GetInstance().HasDefinition("ohos.permission.NICER"));
}

/**
 * @tc.name: ParserRawData008
 * @tc.desc:
 * @tc.type: FUNC
 * @tc.require: Issue Number
 */
HWTEST_F(SystemPermissionDefinitionParserTest, ParserRawData008, TestSize.Level1)
{
    SystemPermissionDefinitionParser& instance = SystemPermissionDefinitionParser::GetInstance();
    std::string data = R"({"definePermissions":[)"\
        R"({"name":"ohos.permission.NICER","grantMode":"system_grant", "availableLevel":"system_core",)"\
        R"("provisionEnable":false, "distributedSceneEnable": false}]})";
    std::vector<PermissionDef> list;
    (void)instance.ParserPermsRawData(data, list);
    EXPECT_EQ(1, list.size());
    for (const auto& perm : list) {
        PermissionDefinitionCache::GetInstance().Insert(perm, EXTENSION_PERMISSION_ID);
    }
    EXPECT_EQ(true, PermissionDefinitionCache::GetInstance().HasDefinition("ohos.permission.NICER"));
    PermissionDefinitionCache::GetInstance().Insert(g_hapDef, 1); // insert valid hap permission
    EXPECT_EQ(true, PermissionDefinitionCache::GetInstance().HasDefinition(VALID_HAP_PERMISSION));
    AccessTokenIDEx tokenIdEx = {0};
    HapInfoParams info = {
        .userID = 1,
        .bundleName = "ParserRawData008",
        .instIndex = 0,
        .appIDDesc = "ParserRawData008Test"
    };
    (void)AccessTokenInfoManager::GetInstance().CreateHapTokenInfo(info, g_policy, tokenIdEx);
    EXPECT_NE(0, tokenIdEx.tokenIdExStruct.tokenID);
    uint32_t tokenId = tokenIdEx.tokenIdExStruct.tokenID;
    std::vector<PermissionStateFull> permListHap;
    int32_t res = PermissionManager::GetInstance().GetReqPermissions(tokenId, permListHap, 1);
    EXPECT_EQ(0, res);
    EXPECT_EQ(1, permListHap.size());
    EXPECT_EQ(0, PermissionManager::GetInstance().VerifyAccessToken(tokenId, VALID_HAP_PERMISSION));
    EXPECT_EQ(-1, PermissionManager::GetInstance().VerifyAccessToken(tokenId, "ohos.permission.NICER"));
    (void)AccessTokenInfoManager::GetInstance().RemoveHapTokenInfo(tokenIdEx.tokenIdExStruct.tokenID);

    std::vector<std::shared_ptr<NativeTokenInfoInner>> tokenInfos;
    uint32_t nativeTokenId = 0x280bc141; // 0x280bc141
    NativeTokenInfo nativeInfo = {
        .apl = APL_NORMAL,
        .ver = 1,
        .processName = "ParserRawData008W",
        .dcap =  {"AT_CAP", "ST_CAP"},
        .tokenID = nativeTokenId,
        .tokenAttr = 0
    };

    std::vector<PermissionStateFull> permStateList = {g_stateNicer, g_stateHapValid};
    std::shared_ptr<NativeTokenInfoInner> nativeToken =
        std::make_shared<NativeTokenInfoInner>(nativeInfo, permStateList);
    tokenInfos.emplace_back(nativeToken);
    AccessTokenInfoManager::GetInstance().ProcessNativeTokenInfos(tokenInfos);
    EXPECT_EQ(0, PermissionManager::GetInstance().VerifyAccessToken(nativeTokenId, VALID_HAP_PERMISSION));
    EXPECT_EQ(0, PermissionManager::GetInstance().VerifyAccessToken(nativeTokenId, "ohos.permission.NICER"));
}