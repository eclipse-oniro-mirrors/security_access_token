/*
 * Copyright (c) 2026 Huawei Device Co., Ltd.
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
#include <gtest/hwext/gtest-tag.h>

#include <filesystem>
#include <fstream>
#include <string>

#define private public
#include "pre_authorization_parser.h"
#undef private

using namespace testing::ext;

namespace OHOS {
namespace Security {
namespace AccessToken {
namespace {
constexpr const char* TEST_JSON_PATH = "/data/test_temp/install_list_permissions_test.json";
constexpr const char* TEST_BUNDLE_NAME = "com.example.camera";
constexpr const char* TEST_PERMISSION_NAME = "ohos.permission.CAMERA";
}

class PreAuthorizationParserTest : public testing::Test {
public:
    static void SetUpTestCase()
    {
        std::filesystem::create_directories("/data/test_temp");
    }

    void SetUp() override
    {
        PreAuthorizationParser::GetInstance().preAuthMap_.clear();
    }

    void TearDown() override
    {
        PreAuthorizationParser::GetInstance().preAuthMap_.clear();
        std::remove(TEST_JSON_PATH);
    }
};

/**
 * @tc.name: GetPreAuthPermissions001
 * @tc.desc: Verify GetPreAuthPermissions returns empty when bundle has no pre-auth record.
 * @tc.type: FUNC
 */
HWTEST_F(PreAuthorizationParserTest, GetPreAuthPermissions001, TestSize.Level1)
{
    auto& parser = PreAuthorizationParser::GetInstance();
    EXPECT_TRUE(parser.GetPreAuthPermissions(TEST_BUNDLE_NAME).empty());
}

/**
 * @tc.name: GetPreAuthPermissions002
 * @tc.desc: Verify GetPreAuthPermissions returns pre-auth list when bundle record exists.
 * @tc.type: FUNC
 */
HWTEST_F(PreAuthorizationParserTest, GetPreAuthPermissions002, TestSize.Level1)
{
    auto& parser = PreAuthorizationParser::GetInstance();
    parser.preAuthMap_[TEST_BUNDLE_NAME].permissions[TEST_PERMISSION_NAME] = true;

    auto perms = parser.GetPreAuthPermissions(TEST_BUNDLE_NAME);
    ASSERT_EQ(1U, perms.size());
    auto iter = perms.find(TEST_PERMISSION_NAME);
    ASSERT_NE(perms.end(), iter);
    EXPECT_TRUE(iter->second);
}

/**
 * @tc.name: ParseOneFile001
 * @tc.desc: Verify ParseOneFile is a no-op when the config file does not exist.
 * @tc.type: FUNC
 */
HWTEST_F(PreAuthorizationParserTest, ParseOneFile001, TestSize.Level1)
{
    auto& parser = PreAuthorizationParser::GetInstance();
    parser.ParseOneFile("/data/test_temp/not_exist_install_list_permissions.json");
    EXPECT_TRUE(parser.preAuthMap_.empty());
}

/**
 * @tc.name: ParseOneFile002
 * @tc.desc: Verify ParseOneFile is a no-op when the config file is not valid json.
 * @tc.type: FUNC
 */
HWTEST_F(PreAuthorizationParserTest, ParseOneFile002, TestSize.Level1)
{
    std::ofstream file(TEST_JSON_PATH);
    file << "not a json";
    file.close();

    auto& parser = PreAuthorizationParser::GetInstance();
    parser.ParseOneFile(TEST_JSON_PATH);
    EXPECT_TRUE(parser.preAuthMap_.empty());
}

/**
 * @tc.name: ParseOneFile003
 * @tc.desc: Verify ParseOneFile loads valid bundle pre-auth records.
 * @tc.type: FUNC
 */
HWTEST_F(PreAuthorizationParserTest, ParseOneFile003, TestSize.Level1)
{
    std::ofstream file(TEST_JSON_PATH);
    file << "[{\"bundleName\":\"" << TEST_BUNDLE_NAME <<
        "\",\"permissions\":[{\"name\":\"" << TEST_PERMISSION_NAME << "\",\"userCancellable\":true}]}]";
    file.close();

    auto& parser = PreAuthorizationParser::GetInstance();
    parser.ParseOneFile(TEST_JSON_PATH);

    auto perms = parser.GetPreAuthPermissions(TEST_BUNDLE_NAME);
    ASSERT_EQ(1U, perms.size());
    auto iter = perms.find(TEST_PERMISSION_NAME);
    ASSERT_NE(perms.end(), iter);
    EXPECT_TRUE(iter->second);
}

/**
 * @tc.name: ParseOneFile004
 * @tc.desc: Verify ParseOneFile skips entries without bundle name, and stores an empty
 *           permission list for a bundle whose permissions all lack names.
 * @tc.type: FUNC
 */
HWTEST_F(PreAuthorizationParserTest, ParseOneFile004, TestSize.Level1)
{
    std::ofstream file(TEST_JSON_PATH);
    file << "[{\"permissions\":[{\"name\":\"ohos.permission.A\"}]}," <<
        "{\"bundleName\":\"" << TEST_BUNDLE_NAME << "\",\"permissions\":[{\"userCancellable\":true}]}]";
    file.close();

    auto& parser = PreAuthorizationParser::GetInstance();
    parser.ParseOneFile(TEST_JSON_PATH);
    ASSERT_EQ(1U, parser.preAuthMap_.size());
    EXPECT_TRUE(parser.GetPreAuthPermissions(TEST_BUNDLE_NAME).empty());
}

/**
 * @tc.name: ParseOneFile005
 * @tc.desc: Verify ParseOneFile stores an empty permission list for a bundle entry that has no permissions array.
 * @tc.type: FUNC
 */
HWTEST_F(PreAuthorizationParserTest, ParseOneFile005, TestSize.Level1)
{
    std::ofstream file(TEST_JSON_PATH);
    file << "[{\"bundleName\":\"" << TEST_BUNDLE_NAME << "\"}]";
    file.close();

    auto& parser = PreAuthorizationParser::GetInstance();
    parser.ParseOneFile(TEST_JSON_PATH);
    ASSERT_EQ(1U, parser.preAuthMap_.size());
    EXPECT_TRUE(parser.GetPreAuthPermissions(TEST_BUNDLE_NAME).empty());
}

/**
 * @tc.name: ParseOneFile006
 * @tc.desc: Verify ParseOneFile loads multiple bundles.
 * @tc.type: FUNC
 */
HWTEST_F(PreAuthorizationParserTest, ParseOneFile006, TestSize.Level1)
{
    std::ofstream file(TEST_JSON_PATH);
    file << "[{\"bundleName\":\"com.example.a\",\"permissions\":[{\"name\":\"ohos.permission.A\"}]}," <<
        "{\"bundleName\":\"com.example.b\",\"permissions\":[{\"name\":\"ohos.permission.B\"}]}]";
    file.close();

    auto& parser = PreAuthorizationParser::GetInstance();
    parser.ParseOneFile(TEST_JSON_PATH);
    ASSERT_EQ(2U, parser.preAuthMap_.size());
    auto permsA = parser.GetPreAuthPermissions("com.example.a");
    ASSERT_EQ(1U, permsA.size());
    EXPECT_NE(permsA.end(), permsA.find("ohos.permission.A"));
    auto permsB = parser.GetPreAuthPermissions("com.example.b");
    ASSERT_EQ(1U, permsB.size());
    EXPECT_NE(permsB.end(), permsB.find("ohos.permission.B"));
}

/**
 * @tc.name: ParseOneFile007
 * @tc.desc: Verify ParseOneFile defaults userCancellable to false when the field is absent.
 * @tc.type: FUNC
 */
HWTEST_F(PreAuthorizationParserTest, ParseOneFile007, TestSize.Level1)
{
    std::ofstream file(TEST_JSON_PATH);
    file << "[{\"bundleName\":\"" << TEST_BUNDLE_NAME <<
        "\",\"permissions\":[{\"name\":\"" << TEST_PERMISSION_NAME << "\"}]}]";
    file.close();

    auto& parser = PreAuthorizationParser::GetInstance();
    parser.ParseOneFile(TEST_JSON_PATH);
    auto perms = parser.GetPreAuthPermissions(TEST_BUNDLE_NAME);
    ASSERT_EQ(1U, perms.size());
    auto iter = perms.find(TEST_PERMISSION_NAME);
    ASSERT_NE(perms.end(), iter);
    EXPECT_FALSE(iter->second);
}

/**
 * @tc.name: CollectFilePaths001
 * @tc.desc: Verify CollectFilePaths always includes the default /system install_list_permissions path.
 * @tc.type: FUNC
 */
HWTEST_F(PreAuthorizationParserTest, CollectFilePaths001, TestSize.Level1)
{
    auto& parser = PreAuthorizationParser::GetInstance();
    std::vector<std::string> filePaths;
    parser.CollectFilePaths(filePaths);

    bool foundDefault = false;
    for (const auto& path : filePaths) {
        if (path == "/system/etc/app/install_list_permissions.json") {
            foundDefault = true;
            break;
        }
    }
    EXPECT_TRUE(foundDefault);
}

/**
 * @tc.name: ParseOneFile008
 * @tc.desc: Verify ParseOneFile parses app_signature and permissions via the json_parse loader.
 * @tc.type: FUNC
 */
HWTEST_F(PreAuthorizationParserTest, ParseOneFile008, TestSize.Level1)
{
    std::ofstream file(TEST_JSON_PATH);
    file << "[{\"bundleName\":\"" << TEST_BUNDLE_NAME <<
        "\",\"app_signature\":[\"com.example.camera_abcd1234\"],"
        "\"permissions\":[{\"name\":\"" << TEST_PERMISSION_NAME << "\",\"userCancellable\":true}]}]";
    file.close();

    auto& parser = PreAuthorizationParser::GetInstance();
    parser.ParseOneFile(TEST_JSON_PATH);
    const PreAuthBundleInfo* info = parser.GetPreAuthBundleInfo(TEST_BUNDLE_NAME);
    ASSERT_NE(nullptr, info);
    ASSERT_EQ(1U, info->appSignature.size());
    EXPECT_EQ("com.example.camera_abcd1234", info->appSignature[0]);
    ASSERT_EQ(1U, info->permissions.size());
    EXPECT_NE(info->permissions.end(), info->permissions.find(TEST_PERMISSION_NAME));
}
} // namespace AccessToken
} // namespace Security
} // namespace OHOS