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
#include <fcntl.h>
#include <memory>
#include <string>

#define private public
#include "json_parse_loader.h"
#undef private

using namespace testing::ext;

namespace OHOS {
namespace Security {
namespace AccessToken {
namespace {
constexpr const char* TEST_FILE_PATH = "/data/test/abcdefg.txt";
}

class JsonParseLoaderTest : public testing::Test  {
public:
    static void SetUpTestCase();
    static void TearDownTestCase();

    void SetUp();
    void TearDown();
};

void JsonParseLoaderTest::SetUpTestCase() {}
void JsonParseLoaderTest::TearDownTestCase() {}
void JsonParseLoaderTest::SetUp() {}
void JsonParseLoaderTest::TearDown() {}

/*
 * @tc.name: IsDirExsit
 * @tc.desc: IsDirExsit
 * @tc.type: FUNC
 * @tc.require: TDD coverage
 */
HWTEST_F(JsonParseLoaderTest, IsDirExsitTest001, TestSize.Level4)
{
    ConfigPolicLoader loader;
    EXPECT_FALSE(loader.IsDirExsit(""));
    int32_t fd = open(TEST_FILE_PATH, O_RDWR | O_CREAT);
    EXPECT_NE(-1, fd);

    EXPECT_FALSE(loader.IsDirExsit(TEST_FILE_PATH));
}

#ifdef CUSTOMIZATION_CONFIG_POLICY_ENABLE
/*
 * @tc.name: GetConfigValueFromFile
 * @tc.desc: GetConfigValueFromFile
 * @tc.type: FUNC
 * @tc.require: TDD coverage
 */
HWTEST_F(JsonParseLoaderTest, GetConfigValueFromFileTest001, TestSize.Level4)
{
    ConfigPolicLoader loader;
    AccessTokenConfigValue config;
    EXPECT_FALSE(loader.GetConfigValueFromFile(ServiceType::ACCESSTOKEN_SERVICE, "", config));
}

/*
 * @tc.name: GetAtCfgFromJson
 * @tc.desc: GetAtCfgFromJson without permission_manager_bundle_name
 * @tc.type: FUNC
 * @tc.require: TDD coverage
 */
HWTEST_F(JsonParseLoaderTest, GetAtCfgFromJsonTest001, TestSize.Level4)
{
    ConfigPolicLoader loader;
    AccessTokenConfigValue config;
    std::string testJson = "{\"privacy\":{\"permission_used_record_size_maximum\":10,"
        "\"permission_used_record_aging_time\":1,\"global_dialog_bundle_name\":\"test_bundle_name\","
        "\"global_dialog_ability_name\":\"test_ability_name\"},\"accesstoken\":{"
        "\"grant_ability_name\":\"test_ability_name\",\"grant_service_ability_name\":"
        "\"test_ability_name\",\"permission_state_sheet_ability_name\":\"test_ability_name\","
        "\"global_switch_sheet_ability_name\":\"test_ability_name\",\"temp_perm_cencle_time\":12345,"
        "\"application_setting_ability_name\":\"test_ability_name\",\"open_setting_ability_name\":"
        "\"test_ability_name\"},\"tokensync\":{\"send_request_repeat_times\":1}}";
    EXPECT_FALSE(loader.GetConfigValueFromFile(ServiceType::ACCESSTOKEN_SERVICE, testJson, config));
}

/*
 * @tc.name: GetAtCfgFromJson
 * @tc.desc: GetAtCfgFromJson without grant_ability_name
 * @tc.type: FUNC
 * @tc.require: TDD coverage
 */
HWTEST_F(JsonParseLoaderTest, GetAtCfgFromJsonTest002, TestSize.Level4)
{
    ConfigPolicLoader loader;
    AccessTokenConfigValue config;
    std::string testJson = "{\"privacy\":{\"permission_used_record_size_maximum\":10,"
        "\"permission_used_record_aging_time\":1,\"global_dialog_bundle_name\":\"test_bundle_name\","
        "\"global_dialog_ability_name\":\"test_ability_name\"},\"accesstoken\":{\"permission_manager_bundle_name\":"
        "\"test_bundle_name\",\"grant_service_ability_name\":"
        "\"test_ability_name\",\"permission_state_sheet_ability_name\":\"test_ability_name\","
        "\"global_switch_sheet_ability_name\":\"test_ability_name\",\"temp_perm_cencle_time\":12345,"
        "\"application_setting_ability_name\":\"test_ability_name\",\"open_setting_ability_name\":"
        "\"test_ability_name\"},\"tokensync\":{\"send_request_repeat_times\":1}}";
    EXPECT_FALSE(loader.GetConfigValueFromFile(ServiceType::ACCESSTOKEN_SERVICE, testJson, config));
}

/*
 * @tc.name: GetAtCfgFromJson
 * @tc.desc: GetAtCfgFromJson without grant_service_ability_name
 * @tc.type: FUNC
 * @tc.require: TDD coverage
 */
HWTEST_F(JsonParseLoaderTest, GetAtCfgFromJsonTest003, TestSize.Level4)
{
    ConfigPolicLoader loader;
    AccessTokenConfigValue config;
    std::string testJson = "{\"privacy\":{\"permission_used_record_size_maximum\":10,"
        "\"permission_used_record_aging_time\":1,\"global_dialog_bundle_name\":\"test_bundle_name\","
        "\"global_dialog_ability_name\":\"test_ability_name\"},\"accesstoken\":{\"permission_manager_bundle_name\":"
        "\"test_bundle_name\",\"grant_ability_name\":\"test_ability_name\","
        "\"permission_state_sheet_ability_name\":\"test_ability_name\","
        "\"global_switch_sheet_ability_name\":\"test_ability_name\",\"temp_perm_cencle_time\":12345,"
        "\"application_setting_ability_name\":\"test_ability_name\",\"open_setting_ability_name\":"
        "\"test_ability_name\"},\"tokensync\":{\"send_request_repeat_times\":1}}";
    EXPECT_FALSE(loader.GetConfigValueFromFile(ServiceType::ACCESSTOKEN_SERVICE, testJson, config));
}

/*
 * @tc.name: GetAtCfgFromJson
 * @tc.desc: GetAtCfgFromJson without permission_state_sheet_ability_name
 * @tc.type: FUNC
 * @tc.require: TDD coverage
 */
HWTEST_F(JsonParseLoaderTest, GetAtCfgFromJsonTest004, TestSize.Level4)
{
    ConfigPolicLoader loader;
    AccessTokenConfigValue config;
    std::string testJson = "{\"privacy\":{\"permission_used_record_size_maximum\":10,"
        "\"permission_used_record_aging_time\":1,\"global_dialog_bundle_name\":\"test_bundle_name\","
        "\"global_dialog_ability_name\":\"test_ability_name\"},\"accesstoken\":{\"permission_manager_bundle_name\":"
        "\"test_bundle_name\",\"grant_ability_name\":\"test_ability_name\",\"grant_service_ability_name\":"
        "\"test_ability_name\","
        "\"global_switch_sheet_ability_name\":\"test_ability_name\",\"temp_perm_cencle_time\":12345,"
        "\"application_setting_ability_name\":\"test_ability_name\",\"open_setting_ability_name\":"
        "\"test_ability_name\"},\"tokensync\":{\"send_request_repeat_times\":1}}";
    EXPECT_FALSE(loader.GetConfigValueFromFile(ServiceType::ACCESSTOKEN_SERVICE, testJson, config));
}

/*
 * @tc.name: GetAtCfgFromJson
 * @tc.desc: GetAtCfgFromJson without global_switch_sheet_ability_name
 * @tc.type: FUNC
 * @tc.require: TDD coverage
 */
HWTEST_F(JsonParseLoaderTest, GetAtCfgFromJsonTest005, TestSize.Level4)
{
    ConfigPolicLoader loader;
    AccessTokenConfigValue config;
    std::string testJson = "{\"privacy\":{\"permission_used_record_size_maximum\":10,"
        "\"permission_used_record_aging_time\":1,\"global_dialog_bundle_name\":\"test_bundle_name\","
        "\"global_dialog_ability_name\":\"test_ability_name\"},\"accesstoken\":{\"permission_manager_bundle_name\":"
        "\"test_bundle_name\",\"grant_ability_name\":\"test_ability_name\",\"grant_service_ability_name\":"
        "\"test_ability_name\",\"permission_state_sheet_ability_name\":\"test_ability_name\","
        "\"temp_perm_cencle_time\":12345,"
        "\"application_setting_ability_name\":\"test_ability_name\",\"open_setting_ability_name\":"
        "\"test_ability_name\"},\"tokensync\":{\"send_request_repeat_times\":1}}";
    EXPECT_FALSE(loader.GetConfigValueFromFile(ServiceType::ACCESSTOKEN_SERVICE, testJson, config));
}

/*
 * @tc.name: GetAtCfgFromJson
 * @tc.desc: GetAtCfgFromJson without temp_perm_cencle_time
 * @tc.type: FUNC
 * @tc.require: TDD coverage
 */
HWTEST_F(JsonParseLoaderTest, GetAtCfgFromJsonTest006, TestSize.Level4)
{
    ConfigPolicLoader loader;
    AccessTokenConfigValue config;
    std::string testJson = "{\"privacy\":{\"permission_used_record_size_maximum\":10,"
        "\"permission_used_record_aging_time\":1,\"global_dialog_bundle_name\":\"test_bundle_name\","
        "\"global_dialog_ability_name\":\"test_ability_name\"},\"accesstoken\":{\"permission_manager_bundle_name\":"
        "\"test_bundle_name\",\"grant_ability_name\":\"test_ability_name\",\"grant_service_ability_name\":"
        "\"test_ability_name\",\"permission_state_sheet_ability_name\":\"test_ability_name\","
        "\"global_switch_sheet_ability_name\":\"test_ability_name\","
        "\"application_setting_ability_name\":\"test_ability_name\",\"open_setting_ability_name\":"
        "\"test_ability_name\"},\"tokensync\":{\"send_request_repeat_times\":1}}";
    EXPECT_FALSE(loader.GetConfigValueFromFile(ServiceType::ACCESSTOKEN_SERVICE, testJson, config));
}

/*
 * @tc.name: GetPrivacyCfgFromJson
 * @tc.desc: GetPrivacyCfgFromJson without permission_used_record_size_maximum
 * @tc.type: FUNC
 * @tc.require: TDD coverage
 */
HWTEST_F(JsonParseLoaderTest, GetPrivacyCfgFromJsonTest001, TestSize.Level4)
{
    ConfigPolicLoader loader;
    AccessTokenConfigValue config;
    std::string testJson = "{\"privacy\":{"
        "\"permission_used_record_aging_time\":1,\"global_dialog_bundle_name\":\"test_bundle_name\","
        "\"global_dialog_ability_name\":\"test_ability_name\"},\"accesstoken\":{\"permission_manager_bundle_name\":"
        "\"test_bundle_name\",\"grant_ability_name\":\"test_ability_name\",\"grant_service_ability_name\":"
        "\"test_ability_name\",\"permission_state_sheet_ability_name\":\"test_ability_name\","
        "\"global_switch_sheet_ability_name\":\"test_ability_name\",\"temp_perm_cencle_time\":12345,"
        "\"application_setting_ability_name\":\"test_ability_name\",\"open_setting_ability_name\":"
        "\"test_ability_name\"},\"tokensync\":{\"send_request_repeat_times\":1}}";
    EXPECT_FALSE(loader.GetConfigValueFromFile(ServiceType::PRIVACY_SERVICE, testJson, config));
}

/*
 * @tc.name: GetPrivacyCfgFromJson
 * @tc.desc: GetPrivacyCfgFromJson without permission_used_record_aging_time
 * @tc.type: FUNC
 * @tc.require: TDD coverage
 */
HWTEST_F(JsonParseLoaderTest, GetPrivacyCfgFromJsonTest002, TestSize.Level4)
{
    ConfigPolicLoader loader;
    AccessTokenConfigValue config;
    std::string testJson = "{\"privacy\":{\"permission_used_record_size_maximum\":10,"
        "\"global_dialog_bundle_name\":\"test_bundle_name\","
        "\"global_dialog_ability_name\":\"test_ability_name\"},\"accesstoken\":{\"permission_manager_bundle_name\":"
        "\"test_bundle_name\",\"grant_ability_name\":\"test_ability_name\",\"grant_service_ability_name\":"
        "\"test_ability_name\",\"permission_state_sheet_ability_name\":\"test_ability_name\","
        "\"global_switch_sheet_ability_name\":\"test_ability_name\",\"temp_perm_cencle_time\":12345,"
        "\"application_setting_ability_name\":\"test_ability_name\",\"open_setting_ability_name\":"
        "\"test_ability_name\"},\"tokensync\":{\"send_request_repeat_times\":1}}";
    EXPECT_FALSE(loader.GetConfigValueFromFile(ServiceType::PRIVACY_SERVICE, testJson, config));
}

/*
 * @tc.name: GetPrivacyCfgFromJson
 * @tc.desc: GetPrivacyCfgFromJson without global_dialog_bundle_name
 * @tc.type: FUNC
 * @tc.require: TDD coverage
 */
HWTEST_F(JsonParseLoaderTest, GetPrivacyCfgFromJsonTest003, TestSize.Level4)
{
    ConfigPolicLoader loader;
    AccessTokenConfigValue config;
    std::string testJson = "{\"privacy\":{\"permission_used_record_size_maximum\":10,"
        "\"permission_used_record_aging_time\":1,"
        "\"global_dialog_ability_name\":\"test_ability_name\"},\"accesstoken\":{\"permission_manager_bundle_name\":"
        "\"test_bundle_name\",\"grant_ability_name\":\"test_ability_name\",\"grant_service_ability_name\":"
        "\"test_ability_name\",\"permission_state_sheet_ability_name\":\"test_ability_name\","
        "\"global_switch_sheet_ability_name\":\"test_ability_name\",\"temp_perm_cencle_time\":12345,"
        "\"application_setting_ability_name\":\"test_ability_name\",\"open_setting_ability_name\":"
        "\"test_ability_name\"},\"tokensync\":{\"send_request_repeat_times\":1}}";
    EXPECT_FALSE(loader.GetConfigValueFromFile(ServiceType::PRIVACY_SERVICE, testJson, config));
}

/*
 * @tc.name: GetPrivacyCfgFromJson
 * @tc.desc: GetPrivacyCfgFromJson without global_dialog_ability_name
 * @tc.type: FUNC
 * @tc.require: TDD coverage
 */
HWTEST_F(JsonParseLoaderTest, GetPrivacyCfgFromJsonTest004, TestSize.Level4)
{
    ConfigPolicLoader loader;
    AccessTokenConfigValue config;
    std::string testJson = "{\"privacy\":{\"permission_used_record_size_maximum\":10,"
        "\"permission_used_record_aging_time\":1,\"global_dialog_bundle_name\":\"test_bundle_name\""
        "},\"accesstoken\":{\"permission_manager_bundle_name\":"
        "\"test_bundle_name\",\"grant_ability_name\":\"test_ability_name\",\"grant_service_ability_name\":"
        "\"test_ability_name\",\"permission_state_sheet_ability_name\":\"test_ability_name\","
        "\"global_switch_sheet_ability_name\":\"test_ability_name\",\"temp_perm_cencle_time\":12345,"
        "\"application_setting_ability_name\":\"test_ability_name\",\"open_setting_ability_name\":"
        "\"test_ability_name\"},\"tokensync\":{\"send_request_repeat_times\":1}}";
    EXPECT_FALSE(loader.GetConfigValueFromFile(ServiceType::PRIVACY_SERVICE, testJson, config));
}

/*
 * @tc.name: GetTokenSyncCfgFromJson
 * @tc.desc: GetTokenSyncCfgFromJson without send_request_repeat_times
 * @tc.type: FUNC
 * @tc.require: TDD coverage
 */
HWTEST_F(JsonParseLoaderTest, GetTokenSyncCfgFromJsonTest001, TestSize.Level4)
{
    ConfigPolicLoader loader;
    AccessTokenConfigValue config;
        std::string testJson = "{\"privacy\":{\"permission_used_record_size_maximum\":10,"
        "\"permission_used_record_aging_time\":1,\"global_dialog_bundle_name\":\"test_bundle_name\","
        "\"global_dialog_ability_name\":\"test_ability_name\"},\"accesstoken\":{\"permission_manager_bundle_name\":"
        "\"test_bundle_name\",\"grant_ability_name\":\"test_ability_name\",\"grant_service_ability_name\":"
        "\"test_ability_name\",\"permission_state_sheet_ability_name\":\"test_ability_name\","
        "\"global_switch_sheet_ability_name\":\"test_ability_name\",\"temp_perm_cencle_time\":12345,"
        "\"application_setting_ability_name\":\"test_ability_name\",\"open_setting_ability_name\":"
        "\"test_ability_name\"},\"tokensync\":{}}";
    EXPECT_FALSE(loader.GetConfigValueFromFile(ServiceType::TOKENSYNC_SERVICE, testJson, config));
}
#endif // CUSTOMIZATION_CONFIG_POLICY_ENABLE
/*
 * @tc.name: ParserDlpPermsRawData
 * @tc.desc: ParserDlpPermsRawData
 * @tc.type: FUNC
 * @tc.require: TDD coverage
 */
HWTEST_F(JsonParseLoaderTest, ParserDlpPermsRawDataTest001, TestSize.Level4)
{
    ConfigPolicLoader loader;
    std::vector<PermissionDlpMode> dlpPerms;
    EXPECT_FALSE(loader.ParserDlpPermsRawData("", dlpPerms));
}

/*
 * @tc.name: ParserDlpPermsRawData
 * @tc.desc: ParserDlpPermsRawData without dlpPermissions
 * @tc.type: FUNC
 * @tc.require: TDD coverage
 */
HWTEST_F(JsonParseLoaderTest, ParserDlpPermsRawDataTest002, TestSize.Level4)
{
    ConfigPolicLoader loader;
    std::vector<PermissionDlpMode> dlpPerms;
    std::string testJson = "{\"invalid\":[{\"name\":\"123\",\"dlpGrantRange\":\"all\"}]}";
    EXPECT_TRUE(loader.ParserDlpPermsRawData(testJson, dlpPerms));
}

/*
 * @tc.name: ParserDlpPermsRawData
 * @tc.desc: ParserDlpPermsRawData without name
 * @tc.type: FUNC
 * @tc.require: TDD coverage
 */
HWTEST_F(JsonParseLoaderTest, ParserDlpPermsRawDataTest003, TestSize.Level4)
{
    ConfigPolicLoader loader;
    std::vector<PermissionDlpMode> dlpPerms;
    std::string testJson = "{\"dlpPermissions\":[{\"invalid\":\"123\",\"dlpGrantRange\":\"all\"}]}";
    EXPECT_TRUE(loader.ParserDlpPermsRawData(testJson, dlpPerms));
}

/*
 * @tc.name: ParserDlpPermsRawData
 * @tc.desc: ParserDlpPermsRawData with invalid name
 * @tc.type: FUNC
 * @tc.require: TDD coverage
 */
HWTEST_F(JsonParseLoaderTest, ParserDlpPermsRawDataTest004, TestSize.Level4)
{
    ConfigPolicLoader loader;
    std::vector<PermissionDlpMode> dlpPerms;
    std::string testJson = "{\"dlpPermissions\":[{\"name\":\"\",\"dlpGrantRange\":\"all\"}]}";
    EXPECT_TRUE(loader.ParserDlpPermsRawData(testJson, dlpPerms));
}

/*
 * @tc.name: ParserDlpPermsRawData
 * @tc.desc: ParserDlpPermsRawData without dlpGrantRange
 * @tc.type: FUNC
 * @tc.require: TDD coverage
 */
HWTEST_F(JsonParseLoaderTest, ParserDlpPermsRawDataTest005, TestSize.Level4)
{
    ConfigPolicLoader loader;
    std::vector<PermissionDlpMode> dlpPerms;
    std::string testJson = "{\"dlpPermissions\":[{\"name\":\"123\",\"invalid\":\"all\"}]}";
    EXPECT_TRUE(loader.ParserDlpPermsRawData(testJson, dlpPerms));
}

/*
 * @tc.name: ParserDlpPermsRawData
 * @tc.desc: ParserDlpPermsRawData with dlpGrantRange all
 * @tc.type: FUNC
 * @tc.require: TDD coverage
 */
HWTEST_F(JsonParseLoaderTest, ParserDlpPermsRawDataTest006, TestSize.Level4)
{
    ConfigPolicLoader loader;
    std::vector<PermissionDlpMode> dlpPerms;
    std::string testJson = "{\"dlpPermissions\":[{\"name\":\"123\",\"dlpGrantRange\":\"all\"}]}";
    EXPECT_TRUE(loader.ParserDlpPermsRawData(testJson, dlpPerms));
}

/*
 * @tc.name: ParserDlpPermsRawData
 * @tc.desc: ParserDlpPermsRawData with dlpGrantRange full_control
 * @tc.type: FUNC
 * @tc.require: TDD coverage
 */
HWTEST_F(JsonParseLoaderTest, ParserDlpPermsRawDataTest007, TestSize.Level4)
{
    ConfigPolicLoader loader;
    std::vector<PermissionDlpMode> dlpPerms;
    std::string testJson = "{\"dlpPermissions\":[{\"name\":\"123\",\"dlpGrantRange\":\"full_control\"}]}";
    EXPECT_TRUE(loader.ParserDlpPermsRawData(testJson, dlpPerms));
}

/*
 * @tc.name: ParserNativeRawData
 * @tc.desc: ParserNativeRawData
 * @tc.type: FUNC
 * @tc.require: TDD coverage
 */
HWTEST_F(JsonParseLoaderTest, ParserNativeRawDataTest001, TestSize.Level4)
{
    ConfigPolicLoader loader;
    std::vector<NativeTokenInfoBase> tokenInfos;
    EXPECT_FALSE(loader.ParserNativeRawData("", tokenInfos));
}

/*
 * @tc.name: ParserNativeRawData
 * @tc.desc: ParserNativeRawData without apl
 * @tc.type: FUNC
 * @tc.require: TDD coverage
 */
HWTEST_F(JsonParseLoaderTest, ParserNativeRawDataTest002, TestSize.Level4)
{
    ConfigPolicLoader loader;
    std::vector<NativeTokenInfoBase> tokenInfos;
    std::string testJson = "[{\"processName\":\"abc\",\"version\":1,\"tokenId\":672000000,\"tokenAttr\":0,"
        "\"dcaps\":[\"abc\"],\"nativeAcls\":[\"abc\"],\"permissions\":[\"perm1\",\"perm2\"]}]";
    EXPECT_TRUE(loader.ParserNativeRawData(testJson, tokenInfos));
}

/*
 * @tc.name: ParserNativeRawData
 * @tc.desc: ParserNativeRawData with invalid apl
 * @tc.type: FUNC
 * @tc.require: TDD coverage
 */
HWTEST_F(JsonParseLoaderTest, ParserNativeRawDataTest003, TestSize.Level4)
{
    ConfigPolicLoader loader;
    std::vector<NativeTokenInfoBase> tokenInfos;
    std::string testJson = "[{\"processName\":\"abc\",\"APL\":0,\"version\":1,\"tokenId\":672000000,\"tokenAttr\":0,"
        "\"dcaps\":[\"abc\"],\"nativeAcls\":[\"abc\"],\"permissions\":[\"perm1\",\"perm2\"]}]";
    EXPECT_TRUE(loader.ParserNativeRawData(testJson, tokenInfos));
}

/*
 * @tc.name: ParserNativeRawData
 * @tc.desc: ParserNativeRawData with hap token
 * @tc.type: FUNC
 * @tc.require: TDD coverage
 */
HWTEST_F(JsonParseLoaderTest, ParserNativeRawDataTest004, TestSize.Level4)
{
    ConfigPolicLoader loader;
    std::vector<NativeTokenInfoBase> tokenInfos;
    std::string testJson = "[{\"processName\":\"abc\",\"APL\":3,\"version\":1,\"tokenId\":537000000,\"tokenAttr\":0,"
        "\"dcaps\":[\"abc\"],\"nativeAcls\":[\"abc\"],\"permissions\":[\"perm1\",\"perm2\"]}]";
    EXPECT_TRUE(loader.ParserNativeRawData(testJson, tokenInfos));
}

/*
 * @tc.name: ParserNativeRawData
 * @tc.desc: ParserNativeRawData with hap token
 * @tc.type: FUNC
 * @tc.require: TDD coverage
 */
HWTEST_F(JsonParseLoaderTest, ParserNativeRawDataTest005, TestSize.Level4)
{
    ConfigPolicLoader loader;
    std::vector<NativeTokenInfoBase> tokenInfos;
    std::string testJson = "[{\"processName\":\"abc\",\"APL\":3,\"version\":1,\"tokenId\":537000000,\"tokenAttr\":0,"
        "\"dcaps\":[\"abc\"],\"nativeAcls\":[\"abc\"],\"permissions\":[\"perm1\",\"perm2\"]}]";
    EXPECT_TRUE(loader.ParserNativeRawData(testJson, tokenInfos));
}

/*
 * @tc.name: ParserNativeRawData
 * @tc.desc: ParserNativeRawData without attr
 * @tc.type: FUNC
 * @tc.require: TDD coverage
 */
HWTEST_F(JsonParseLoaderTest, ParserNativeRawDataTest006, TestSize.Level4)
{
    ConfigPolicLoader loader;
    std::vector<NativeTokenInfoBase> tokenInfos;
    std::string testJson = "[{\"processName\":\"abc\",\"APL\":3,\"version\":1,\"tokenId\":672000000,"
        "\"dcaps\":[\"abc\"],\"nativeAcls\":[\"abc\"],\"permissions\":[\"perm1\",\"perm2\"]}]";
    EXPECT_TRUE(loader.ParserNativeRawData(testJson, tokenInfos));
}

/*
 * @tc.name: ParserNativeRawData
 * @tc.desc: ParserNativeRawData without perm
 * @tc.type: FUNC
 * @tc.require: TDD coverage
 */
HWTEST_F(JsonParseLoaderTest, ParserNativeRawDataTest007, TestSize.Level4)
{
    ConfigPolicLoader loader;
    std::vector<NativeTokenInfoBase> tokenInfos;
    std::string testJson = "[{\"processName\":\"abc\",\"APL\":3,\"version\":1,\"tokenId\":672000000,\"tokenAttr\":0,"
        "\"dcaps\":[\"abc\"],\"nativeAcls\":[\"abc\"]}]";
    EXPECT_TRUE(loader.ParserNativeRawData(testJson, tokenInfos));
}

/*
 * @tc.name: ParserNativeRawData
 * @tc.desc: ParserNativeRawData without name
 * @tc.type: FUNC
 * @tc.require: TDD coverage
 */
HWTEST_F(JsonParseLoaderTest, ParserNativeRawDataTest008, TestSize.Level4)
{
    ConfigPolicLoader loader;
    std::vector<NativeTokenInfoBase> tokenInfos;
    std::string testJson = "[{\"APL\":3,\"version\":1,\"tokenId\":672000000,\"tokenAttr\":0,"
        "\"dcaps\":[\"abc\"],\"nativeAcls\":[\"abc\"],\"permissions\":[\"perm1\",\"perm2\"]}]";
    EXPECT_TRUE(loader.ParserNativeRawData(testJson, tokenInfos));
}

/*
 * @tc.name: ParserNativeRawData
 * @tc.desc: ParserNativeRawData with invalid name
 * @tc.type: FUNC
 * @tc.require: TDD coverage
 */
HWTEST_F(JsonParseLoaderTest, ParserNativeRawDataTest009, TestSize.Level4)
{
    ConfigPolicLoader loader;
    std::vector<NativeTokenInfoBase> tokenInfos;
    std::string testJson = "[{\"processName\":\"\",\"APL\":3,\"version\":1,\"tokenId\":672000000,\"tokenAttr\":0,"
        "\"dcaps\":[\"abc\"],\"nativeAcls\":[\"abc\"],\"permissions\":[\"perm1\",\"perm2\"]}]";
    EXPECT_TRUE(loader.ParserNativeRawData(testJson, tokenInfos));
}
} // namespace AccessToken
} // namespace Security
} // namespace OHOS
