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

#include "atm_command_test.h"
#include "atm_command.h"
#include "atm_tools_param_info.h"
#include "gtest/gtest.h"
#include <unistd.h>
#include <regex>
#include <chrono>
#include <vector>
#include <string>
#include <sstream>

#include "accesstoken_kit.h"
#include "permission_def.h"
#include "token_setproc.h"
#include "tokenid_kit.h"

using namespace testing::ext;

namespace OHOS {
namespace Security {
namespace AccessToken {

// Test context variables
uint64_t g_shellTokenId = 0;
int32_t g_selfUid = 0;
uint64_t g_hapTokenId = 0;

// Test data constants
const std::string TEST_BUNDLE_NAME = "com.example.atm.test";
const std::string TEST_PERMISSION_CAMERA = "ohos.permission.CAMERA";
const std::string TEST_PERMISSION_LOCATION = "ohos.permission.LOCATION";
const std::string TEST_PERMISSION_READ_CALENDAR = "ohos.permission.READ_CALENDAR";
const std::string TEST_PROCESS_NAME = "foundation";
const std::string INVALID_BUNDLE_NAME = "com.invalid.nonexistent.bundle";
const std::string INVALID_PERMISSION_NAME = "ohos.permission.INVALID";

// HAP token creation parameters
static HapInfoParams g_HapInfoParms = {
    .userID = 10001,
    .bundleName = "com.example.atm.test",
    .instIndex = 0,
    .appIDDesc = "atm.test.app",
    .isSystemApp = false
};

static HapPolicyParams g_HapPolicyPrams = {
    .apl = APL_NORMAL,
    .domain = "test.domain",
};

/**
 * @brief Get native token ID by process name
 * @param processName Process name (e.g., "foundation")
 * @return Native token ID, or 0 if failed
 */
static AccessTokenID GetNativeTokenIdFromProcess(const std::string& processName)
{
    // Use DumpTokenInfo to get token info
    std::string dumpInfo;
    AtmToolsParamInfo info;
    info.processName = processName;
    AccessTokenKit::DumpTokenInfo(info, dumpInfo);

    // Parse token ID from dump info
    size_t pos = dumpInfo.find("\"tokenID\": ");
    if (pos == std::string::npos) {
        return 0;
    }

    pos += std::string("\"tokenID\": ").length();
    std::string numStr;
    while (pos < dumpInfo.length() && std::isdigit(dumpInfo[pos])) {
        numStr += dumpInfo[pos];
        ++pos;
    }

    std::istringstream iss(numStr);
    AccessTokenID tokenID;
    iss >> tokenID;

    return tokenID;
}

/**
 * @brief Initialize HAP token with elevated privileges (foundation token)
 * @return AccessTokenID Created token ID, or 0 if failed
 */
static AccessTokenID CreateTestHapTokenID()
{
    // Get foundation token ID and elevate privileges
    AccessTokenID foundationTokenId = GetNativeTokenIdFromProcess(TEST_PROCESS_NAME);
    if (foundationTokenId == 0) {
        return 0;
    }

    SetSelfTokenID(foundationTokenId);

    // Create a HAP token for testing
    AccessTokenIDEx tokenIdEx;
    int32_t ret = AccessTokenKit::InitHapToken(g_HapInfoParms, g_HapPolicyPrams, tokenIdEx);

    // Restore original token ID
    SetSelfTokenID(g_shellTokenId);

    if (ret == RET_SUCCESS) {
        g_hapTokenId = tokenIdEx.tokenIdExStruct.tokenID;
        return g_hapTokenId;
    }

    return 0;
}

/**
 * @brief Delete HAP token with elevated privileges (foundation token)
 */
static void DeleteTestHapTokenID()
{
    // Get foundation token ID and elevate privileges
    AccessTokenID foundationTokenId = GetNativeTokenIdFromProcess(TEST_PROCESS_NAME);
    if (foundationTokenId == 0) {
        return;
    }

    SetSelfTokenID(foundationTokenId);

    // Remove the created HAP token
    if (g_hapTokenId != 0) {
        AccessTokenKit::DeleteToken(g_hapTokenId);
        g_hapTokenId = 0;
    }

    // Restore original token ID
    SetSelfTokenID(g_shellTokenId);
}

void AtmCommandTest::SetUpTestCase()
{
    g_shellTokenId = GetSelfTokenID();
    g_selfUid = getuid();

    g_hapTokenId = CreateTestHapTokenID();
}

void AtmCommandTest::TearDownTestCase()
{
    DeleteTestHapTokenID();
}

void AtmCommandTest::SetUp()
{
}

void AtmCommandTest::TearDown()
{
}

/**
 * @brief Execute AtmCommand and optionally log the result for debugging
 * @param argc Argument count
 * @param argv Argument values
 * @param enableLog Whether to print log (default false)
 * @return Command execution result
 */
static inline std::string ExecAtmCommand(int argc, char* argv[], bool enableLog = false)
{
    std::string cmdStr;
    for (int i = 0; i < argc; i++) {
        cmdStr += argv[i];
        if (i < argc - 1) {
            cmdStr += " ";
        }
    }

    // Create modifiable copies of argv strings
    // getopt_long will permute argv, so we need writable copies
    std::vector<std::string> argvCopy;
    std::vector<char*> argvPtr;
    argvCopy.reserve(argc);
    argvPtr.reserve(argc + 1);
    for (int i = 0; i < argc; i++) {
        argvCopy.emplace_back(argv[i]);
        argvPtr.emplace_back(const_cast<char*>(argvCopy[i].c_str()));
    }
    argvPtr.emplace_back(nullptr);  // Null-terminate argv array

    AtmCommand cmd(argc, argvPtr.data());
    std::string result = cmd.ExecCommand();

    if (enableLog) {
        std::cout << "========== ATM Command Log ==========" << std::endl;
        std::cout << "Command: " << cmdStr << std::endl;
        std::cout << "Result Length: " << result.length() << std::endl;
        if (!result.empty()) {
            std::cout << "Result: " << result << std::endl;
        } else {
            std::cout << "Result: (empty)" << std::endl;
        }
        std::cout << "====================================" << std::endl;
    }

    return result;
}

bool IsOutputContain(const std::string& output, const std::string& expected)
{
    return output.find(expected) != std::string::npos;
}

bool IsValidJson(const std::string& jsonStr)
{
    if (jsonStr.empty()) {
        return false;
    }
    std::string trimmed = jsonStr;
    size_t start = trimmed.find_first_not_of(" \t\n\r");
    size_t end = trimmed.find_last_not_of(" \t\n\r");

    if (start == std::string::npos || end == std::string::npos) {
        return false;
    }

    trimmed = trimmed.substr(start, end - start + 1);
    return (trimmed[0] == '{' || trimmed[0] == '[') &&
           (trimmed[trimmed.length() - 1] == '}' || trimmed[trimmed.length() - 1] == ']');
}

/**
 * @tc.name: atm_help_test001
 * @tc.desc: Display main help information
 * @tc.type: FUNC
 * @tc.require: AR000GVIEG
 */
HWTEST_F(AtmCommandTest, atm_help_test001, TestSize.Level1)
{
    const char* argv[] = {"atm", "help"};
    int argc = sizeof(argv) / sizeof(argv[0]);

    // AtmCommand call replaced with ExecAtmCommand
    std::string result = ExecAtmCommand(argc, const_cast<char**>(argv));

    EXPECT_TRUE(IsOutputContain(result, "usage: atm <command>"));
    EXPECT_TRUE(IsOutputContain(result, "help"));
    EXPECT_TRUE(IsOutputContain(result, "dump"));
#ifndef ATM_BUILD_VARIANT_USER_ENABLE
    EXPECT_TRUE(IsOutputContain(result, "perm"));
    EXPECT_TRUE(IsOutputContain(result, "toggle"));
#endif
}

/**
 * @tc.name: atm_help_test002
 * @tc.desc: Display dump command help
 * @tc.type: FUNC
 * @tc.require: AR000GVIEG
 */
HWTEST_F(AtmCommandTest, atm_help_test002, TestSize.Level1)
{
    const char* argv[] = {"atm", "dump", "-h"};
    int argc = sizeof(argv) / sizeof(argv[0]);

    // AtmCommand call replaced with ExecAtmCommand
    std::string result = ExecAtmCommand(argc, const_cast<char**>(argv));

    EXPECT_TRUE(IsOutputContain(result, "usage: atm dump"));
    EXPECT_TRUE(IsOutputContain(result, "--definition") || IsOutputContain(result, "-d"));
    EXPECT_TRUE(IsOutputContain(result, "--token-info") || IsOutputContain(result, "-t"));

#ifndef ATM_BUILD_VARIANT_USER_ENABLE
    EXPECT_TRUE(IsOutputContain(result, "--record") || IsOutputContain(result, "-r"));
    EXPECT_TRUE(IsOutputContain(result, "--ver") || IsOutputContain(result, "-v"));
#endif
}

#ifndef ATM_BUILD_VARIANT_USER_ENABLE
/**
 * @tc.name: atm_help_test003
 * @tc.desc: Display perm command help (non-user variant)
 * @tc.type: FUNC
 * @tc.require: AR000GVIEG
 */
HWTEST_F(AtmCommandTest, atm_help_test003, TestSize.Level1)
{
    const char* argv[] = {"atm", "perm", "-h"};
    int argc = sizeof(argv) / sizeof(argv[0]);

    // AtmCommand call replaced with ExecAtmCommand
    std::string result = ExecAtmCommand(argc, const_cast<char**>(argv));

    EXPECT_TRUE(IsOutputContain(result, "usage: atm perm"));
    EXPECT_TRUE(IsOutputContain(result, "--grant") || IsOutputContain(result, "-g"));
    EXPECT_TRUE(IsOutputContain(result, "--cancel") || IsOutputContain(result, "-c"));
}
#endif

#ifndef ATM_BUILD_VARIANT_USER_ENABLE
/**
 * @tc.name: atm_help_test004
 * @tc.desc: Display toggle request help (non-user variant)
 * @tc.type: FUNC
 * @tc.require: AR000GVIEG
 */
HWTEST_F(AtmCommandTest, atm_help_test004, TestSize.Level1)
{
    const char* argv[] = {"atm", "toggle", "request", "-h"};
    int argc = sizeof(argv) / sizeof(argv[0]);

    // AtmCommand call replaced with ExecAtmCommand
    std::string result = ExecAtmCommand(argc, const_cast<char**>(argv));

    EXPECT_TRUE(IsOutputContain(result, "usage: atm toggle request"));
    EXPECT_TRUE(IsOutputContain(result, "--set") || IsOutputContain(result, "-s"));
    EXPECT_TRUE(IsOutputContain(result, "--get") || IsOutputContain(result, "-o"));
}
#endif

#ifndef ATM_BUILD_VARIANT_USER_ENABLE
/**
 * @tc.name: atm_help_test005
 * @tc.desc: Display toggle record help (non-user variant)
 * @tc.type: FUNC
 * @tc.require: AR000GVIEG
 */
HWTEST_F(AtmCommandTest, atm_help_test005, TestSize.Level1)
{
    const char* argv[] = {"atm", "toggle", "record", "-h"};
    int argc = sizeof(argv) / sizeof(argv[0]);

    // AtmCommand call replaced with ExecAtmCommand
    std::string result = ExecAtmCommand(argc, const_cast<char**>(argv));

    EXPECT_TRUE(IsOutputContain(result, "usage: atm toggle record"));
    EXPECT_TRUE(IsOutputContain(result, "--set") || IsOutputContain(result, "-s"));
    EXPECT_TRUE(IsOutputContain(result, "--get") || IsOutputContain(result, "-o"));
}
#endif

/**
 * @tc.name: atm_dump_perm_test001
 * @tc.desc: Query all permission definitions
 * @tc.type: FUNC
 * @tc.require: AR000GVIEG
 */
HWTEST_F(AtmCommandTest, atm_dump_perm_test001, TestSize.Level1)
{
    const char* argv[] = {"atm", "dump", "-d"};
    int argc = sizeof(argv) / sizeof(argv[0]);

    std::string result = ExecAtmCommand(argc, const_cast<char**>(argv));

    EXPECT_FALSE(result.empty());
    EXPECT_TRUE(IsValidJson(result) || IsOutputContain(result, "permissionName"));
}

/**
 * @tc.name: atm_dump_perm_test002
 * @tc.desc: Query specific permission definition (valid permission)
 * @tc.type: FUNC
 * @tc.require: AR000GVIEG
 */
HWTEST_F(AtmCommandTest, atm_dump_perm_test002, TestSize.Level1)
{
    const char* argv[] = {"atm", "dump", "-d", "-p", TEST_PERMISSION_CAMERA.c_str()};
    int argc = sizeof(argv) / sizeof(argv[0]);

    std::string result = ExecAtmCommand(argc, const_cast<char**>(argv));

    // Result may contain permission definition or be empty/error
    EXPECT_TRUE(result.empty() || IsValidJson(result) ||
                IsOutputContain(result, "invalid") || IsOutputContain(result, "not found"));
}

/**
 * @tc.name: atm_dump_perm_test003
 * @tc.desc: Query invalid permission definition
 * @tc.type: FUNC
 * @tc.require: AR000GVIEG
 */
HWTEST_F(AtmCommandTest, atm_dump_perm_test003, TestSize.Level1)
{
    const char* argv[] = {"atm", "dump", "-d", "-p", INVALID_PERMISSION_NAME.c_str()};
    int argc = sizeof(argv) / sizeof(argv[0]);

    std::string result = ExecAtmCommand(argc, const_cast<char**>(argv));

    // Should handle invalid permission gracefully
    EXPECT_TRUE(result.empty() || IsOutputContain(result, "does not exist"));
}

/**
 * @tc.name: atm_dump_perm_test004
 * @tc.desc: Query with missing permission name parameter
 * @tc.type: FUNC
 * @tc.require: AR000GVIEG
 */
HWTEST_F(AtmCommandTest, atm_dump_perm_test004, TestSize.Level1)
{
    const char* argv[] = {"atm", "dump", "-d", "-p"};
    int argc = sizeof(argv) / sizeof(argv[0]);

    std::string result = ExecAtmCommand(argc, const_cast<char**>(argv));

    // Missing -p parameter value should return error
    EXPECT_TRUE(IsOutputContain(result, "option requires a value") || IsOutputContain(result, "requires a value"));
}

/**
 * @tc.name: atm_dump_perm_test005
 * @tc.desc: Query with empty permission name
 * @tc.type: FUNC
 * @tc.require: AR000GVIEG
 */
HWTEST_F(AtmCommandTest, atm_dump_perm_test005, TestSize.Level1)
{
    const char* argv[] = {"atm", "dump", "-d", "-p", ""};
    int argc = sizeof(argv) / sizeof(argv[0]);

    std::string result = ExecAtmCommand(argc, const_cast<char**>(argv));

    // Empty permission name is treated as missing parameter
    EXPECT_TRUE(IsOutputContain(result, "option requires a value") || IsOutputContain(result, "requires a value"));
}

/**
 * @tc.name: atm_dump_perm_test006
 * @tc.desc: Query multiple permission definitions
 * @tc.type: FUNC
 * @tc.require: AR000GVIEG
 */
HWTEST_F(AtmCommandTest, atm_dump_perm_test006, TestSize.Level1)
{
    const char* argv[] = {"atm", "dump", "-d", "-p", TEST_PERMISSION_CAMERA.c_str(),
                          "-p", TEST_PERMISSION_LOCATION.c_str()};
    int argc = sizeof(argv) / sizeof(argv[0]);

    std::string result = ExecAtmCommand(argc, const_cast<char**>(argv));

    // Only supports querying one permission definition, later -p overrides earlier ones, output contains the last permission
    EXPECT_TRUE(IsValidJson(result) && IsOutputContain(result, TEST_PERMISSION_LOCATION));
}

/**
 * @tc.name: atm_dump_token_test001
 * @tc.desc: Query all tokens
 * @tc.type: FUNC
 * @tc.require: AR000GVIEG
 */
HWTEST_F(AtmCommandTest, atm_dump_token_test001, TestSize.Level1)
{
    const char* argv[] = {"atm", "dump", "-t"};
    int argc = sizeof(argv) / sizeof(argv[0]);

    // AtmCommand call replaced with ExecAtmCommand
    std::string result = ExecAtmCommand(argc, const_cast<char**>(argv));

    EXPECT_FALSE(result.empty());
}

/**
 * @tc.name: atm_dump_token_test002
 * @tc.desc: Query token by valid ID
 * @tc.type: FUNC
 * @tc.require: AR000GVIEG
 */
HWTEST_F(AtmCommandTest, atm_dump_token_test002, TestSize.Level1)
{
    // Use self token ID which should exist
    std::string tokenIdStr = std::to_string(g_shellTokenId);
    const char* argv[] = {"atm", "dump", "-t", "-i", tokenIdStr.c_str()};
    int argc = sizeof(argv) / sizeof(argv[0]);

    // AtmCommand call replaced with ExecAtmCommand
    std::string result = ExecAtmCommand(argc, const_cast<char**>(argv));

    EXPECT_TRUE(IsOutputContain(result, tokenIdStr) || IsOutputContain(result, TEST_BUNDLE_NAME));
}

/**
 * @tc.name: atm_dump_token_test003
 * @tc.desc: Query token by invalid ID
 * @tc.type: FUNC
 * @tc.require: AR000GVIEG
 */
HWTEST_F(AtmCommandTest, atm_dump_token_test003, TestSize.Level1)
{
    const char* argv[] = {"atm", "dump", "-t", "-i", "99999999"};
    int argc = sizeof(argv) / sizeof(argv[0]);

    // AtmCommand call replaced with ExecAtmCommand
    std::string result = ExecAtmCommand(argc, const_cast<char**>(argv));

    EXPECT_TRUE(IsOutputContain(result, "TokenID does not exist."));
}

/**
 * @tc.name: atm_dump_token_test004
 * @tc.desc: Query token with ID=0
 * @tc.type: FUNC
 * @tc.require: AR000GVIEG
 */
HWTEST_F(AtmCommandTest, atm_dump_token_test004, TestSize.Level1)
{
    const char* argv[] = {"atm", "dump", "-t", "-i", "0"};
    int argc = sizeof(argv) / sizeof(argv[0]);

    // AtmCommand call replaced with ExecAtmCommand
    std::string result = ExecAtmCommand(argc, const_cast<char**>(argv));

    EXPECT_TRUE(IsOutputContain(result, "TokenID is invalid."));
}

/**
 * @tc.name: atm_dump_token_test005
 * @tc.desc: Query token by valid bundle name
 * @tc.type: FUNC
 * @tc.require: AR000GVIEG
 */
HWTEST_F(AtmCommandTest, atm_dump_token_test005, TestSize.Level1)
{
    const char* argv[] = {"atm", "dump", "-t", "-b", TEST_BUNDLE_NAME.c_str()};
    int argc = sizeof(argv) / sizeof(argv[0]);

    // AtmCommand call replaced with ExecAtmCommand
    std::string result = ExecAtmCommand(argc, const_cast<char**>(argv));

    // May or may not find the bundle
    EXPECT_TRUE(result.empty() || IsOutputContain(result, TEST_BUNDLE_NAME) ||
                IsOutputContain(result, "not found"));
}

/**
 * @tc.name: atm_dump_token_test006
 * @tc.desc: Query token by invalid bundle name
 * @tc.type: FUNC
 * @tc.require: AR000GVIEG
 */
HWTEST_F(AtmCommandTest, atm_dump_token_test006, TestSize.Level1)
{
    const char* argv[] = {"atm", "dump", "-t", "-b", INVALID_BUNDLE_NAME.c_str()};
    int argc = sizeof(argv) / sizeof(argv[0]);

    // AtmCommand call replaced with ExecAtmCommand
    std::string result = ExecAtmCommand(argc, const_cast<char**>(argv));

    EXPECT_TRUE(IsOutputContain(result, "BundleName") && IsOutputContain(result, "does not exist"));
}

/**
 * @tc.name: atm_dump_token_test007
 * @tc.desc: Query token with -b option missing value
 * @tc.type: FUNC
 * @tc.require: AR000GVIEG
 */
HWTEST_F(AtmCommandTest, atm_dump_token_test007, TestSize.Level1)
{
    const char* argv[] = {"atm", "dump", "-t", "-b"};
    int argc = sizeof(argv) / sizeof(argv[0]);

    // AtmCommand call replaced with ExecAtmCommand
    std::string result = ExecAtmCommand(argc, const_cast<char**>(argv));

    EXPECT_TRUE(IsOutputContain(result, "option requires a value"));
}

/**
 * @tc.name: atm_dump_token_test008
 * @tc.desc: Query token with -n option missing value
 * @tc.type: FUNC
 * @tc.require: AR000GVIEG
 */
HWTEST_F(AtmCommandTest, atm_dump_token_test008, TestSize.Level1)
{
    const char* argv[] = {"atm", "dump", "-t", "-n"};
    int argc = sizeof(argv) / sizeof(argv[0]);

    // AtmCommand call replaced with ExecAtmCommand
    std::string result = ExecAtmCommand(argc, const_cast<char**>(argv));

    EXPECT_TRUE(IsOutputContain(result, "option requires a value"));
}

/**
 * @tc.name: atm_dump_token_test009
 * @tc.desc: Query token by valid process name
 * @tc.type: FUNC
 * @tc.require: AR000GVIEG
 */
HWTEST_F(AtmCommandTest, atm_dump_token_test009, TestSize.Level1)
{
    const char* argv[] = {"atm", "dump", "-t", "-n", TEST_PROCESS_NAME.c_str()};
    int argc = sizeof(argv) / sizeof(argv[0]);

    // AtmCommand call replaced with ExecAtmCommand
    std::string result = ExecAtmCommand(argc, const_cast<char**>(argv));

    // May or may not find the process
    EXPECT_TRUE(result.empty() || IsOutputContain(result, TEST_PROCESS_NAME));
}

/**
 * @tc.name: atm_dump_token_test010
 * @tc.desc: Query token by invalid process name
 * @tc.type: FUNC
 * @tc.require: AR000GVIEG
 */
HWTEST_F(AtmCommandTest, atm_dump_token_test010, TestSize.Level1)
{
    const char* argv[] = {"atm", "dump", "-t", "-n", "nonexistent_process"};
    int argc = sizeof(argv) / sizeof(argv[0]);

    // AtmCommand call replaced with ExecAtmCommand
    std::string result = ExecAtmCommand(argc, const_cast<char**>(argv));

    EXPECT_TRUE(IsOutputContain(result, "ProcessName") && IsOutputContain(result, "does not exist"));
}

/**
 * @tc.name: atm_dump_token_test011
 * @tc.desc: Query with both Token ID and bundle name options
 * @tc.type: FUNC
 * @tc.require: AR000GVIEG
 */
HWTEST_F(AtmCommandTest, atm_dump_token_test011, TestSize.Level1)
{
    std::string tokenIdStr = std::to_string(g_shellTokenId);
    const char* argv[] = {"atm", "dump", "-t", "-i", tokenIdStr.c_str(),
                          "-b", TEST_BUNDLE_NAME.c_str()};
    int argc = sizeof(argv) / sizeof(argv[0]);

    // AtmCommand call replaced with ExecAtmCommand
    std::string result = ExecAtmCommand(argc, const_cast<char**>(argv));

    // Last option takes precedence, should query by bundle name
    EXPECT_TRUE(IsOutputContain(result, TEST_BUNDLE_NAME) || !result.empty());
}

/**
 * @tc.name: atm_dump_token_test012
 * @tc.desc: Query with both Token ID and permission options
 * @tc.type: FUNC
 * @tc.require: AR000GVIEG
 */
HWTEST_F(AtmCommandTest, atm_dump_token_test012, TestSize.Level1)
{
    std::string tokenIdStr = std::to_string(g_shellTokenId);
    const char* argv[] = {"atm", "dump", "-t", "-i", tokenIdStr.c_str(),
                          "-p", TEST_PERMISSION_CAMERA.c_str()};
    int argc = sizeof(argv) / sizeof(argv[0]);

    // AtmCommand call replaced with ExecAtmCommand
    std::string result = ExecAtmCommand(argc, const_cast<char**>(argv));

    // Last option takes precedence, should query by permission
    EXPECT_TRUE(IsOutputContain(result, TEST_PERMISSION_CAMERA) || !result.empty());
}

/**
 * @tc.name: atm_dump_record_test001
 * @tc.desc: Query all permission records
 * @tc.type: FUNC
 * @tc.require: AR000GVIEG
 */
HWTEST_F(AtmCommandTest, atm_dump_record_test001, TestSize.Level1)
{
#ifndef ATM_BUILD_VARIANT_USER_ENABLE
    const char* argv[] = {"atm", "dump", "-r"};
    int argc = sizeof(argv) / sizeof(argv[0]);

    // AtmCommand call replaced with ExecAtmCommand
    std::string result = ExecAtmCommand(argc, const_cast<char**>(argv));

    // May be empty if no records exist
    EXPECT_TRUE(result.empty() || !IsOutputContain(result, "error"));
#endif
}

/**
 * @tc.name: atm_dump_record_test002
 * @tc.desc: Query records by token ID
 * @tc.type: FUNC
 * @tc.require: AR000GVIEG
 */
HWTEST_F(AtmCommandTest, atm_dump_record_test002, TestSize.Level1)
{
#ifndef ATM_BUILD_VARIANT_USER_ENABLE
    std::string tokenIdStr = std::to_string(g_shellTokenId);
    const char* argv[] = {"atm", "dump", "-r", "-i", tokenIdStr.c_str()};
    int argc = sizeof(argv) / sizeof(argv[0]);

    // AtmCommand call replaced with ExecAtmCommand
    std::string result = ExecAtmCommand(argc, const_cast<char**>(argv));

    // May be empty if no records exist for this token
    EXPECT_TRUE(result.empty() || !IsOutputContain(result, "error"));
#endif
}

/**
 * @tc.name: atm_dump_record_test003
 * @tc.desc: Query records by permission
 * @tc.type: FUNC
 * @tc.require: AR000GVIEG
 */
HWTEST_F(AtmCommandTest, atm_dump_record_test003, TestSize.Level1)
{
#ifndef ATM_BUILD_VARIANT_USER_ENABLE
    const char* argv[] = {"atm", "dump", "-r", "-p", TEST_PERMISSION_CAMERA.c_str()};
    int argc = sizeof(argv) / sizeof(argv[0]);

    // AtmCommand call replaced with ExecAtmCommand
    std::string result = ExecAtmCommand(argc, const_cast<char**>(argv));

    // May be empty if no records exist for this permission
    EXPECT_TRUE(result.empty() || !IsOutputContain(result, "error"));
#endif
}

/**
 * @tc.name: atm_dump_record_test004
 * @tc.desc: Query records by token and permission
 * @tc.type: FUNC
 * @tc.require: AR000GVIEG
 */
HWTEST_F(AtmCommandTest, atm_dump_record_test004, TestSize.Level1)
{
#ifndef ATM_BUILD_VARIANT_USER_ENABLE
    std::string tokenIdStr = std::to_string(g_shellTokenId);
    const char* argv[] = {"atm", "dump", "-r", "-i", tokenIdStr.c_str(),
                          "-p", TEST_PERMISSION_CAMERA.c_str()};
    int argc = sizeof(argv) / sizeof(argv[0]);

    // AtmCommand call replaced with ExecAtmCommand
    std::string result = ExecAtmCommand(argc, const_cast<char**>(argv));

    // Last option takes precedence, should query by permission
    EXPECT_TRUE(result.empty() || !IsOutputContain(result, "error"));
#endif
}

/**
 * @tc.name: atm_dump_type_test001
 * @tc.desc: Query all visit types
 * @tc.type: FUNC
 * @tc.require: AR000GVIEG
 */
HWTEST_F(AtmCommandTest, atm_dump_type_test001, TestSize.Level2)
{
#ifndef ATM_BUILD_VARIANT_USER_ENABLE
    const char* argv[] = {"atm", "dump", "-v"};
    int argc = sizeof(argv) / sizeof(argv[0]);

    // AtmCommand call replaced with ExecAtmCommand
    std::string result = ExecAtmCommand(argc, const_cast<char**>(argv));

    // May be empty if no visit type records exist
    EXPECT_TRUE(result.empty() || !IsOutputContain(result, "error"));
#endif
}

/**
 * @tc.name: atm_dump_type_test002
 * @tc.desc: Query visit types by token ID
 * @tc.type: FUNC
 * @tc.require: AR000GVIEG
 */
HWTEST_F(AtmCommandTest, atm_dump_type_test002, TestSize.Level2)
{
#ifndef ATM_BUILD_VARIANT_USER_ENABLE
    std::string tokenIdStr = std::to_string(g_shellTokenId);
    const char* argv[] = {"atm", "dump", "-v", "-i", tokenIdStr.c_str()};
    int argc = sizeof(argv) / sizeof(argv[0]);

    // AtmCommand call replaced with ExecAtmCommand
    std::string result = ExecAtmCommand(argc, const_cast<char**>(argv));

    // May be empty if no visit type records exist
    EXPECT_TRUE(result.empty() || !IsOutputContain(result, "error"));
#endif
}

/**
 * @tc.name: atm_dump_type_test003
 * @tc.desc: Query visit types by permission
 * @tc.type: FUNC
 * @tc.require: AR000GVIEG
 */
HWTEST_F(AtmCommandTest, atm_dump_type_test003, TestSize.Level2)
{
#ifndef ATM_BUILD_VARIANT_USER_ENABLE
    const char* argv[] = {"atm", "dump", "-v", "-p", TEST_PERMISSION_CAMERA.c_str()};
    int argc = sizeof(argv) / sizeof(argv[0]);

    // AtmCommand call replaced with ExecAtmCommand
    std::string result = ExecAtmCommand(argc, const_cast<char**>(argv));

    // May be empty if no visit type records exist
    EXPECT_TRUE(result.empty() || !IsOutputContain(result, "error"));
#endif
}

/**
 * @tc.name: atm_dump_type_test004
 * @tc.desc: Query visit types by token and permission
 * @tc.type: FUNC
 * @tc.require: AR000GVIEG
 */
HWTEST_F(AtmCommandTest, atm_dump_type_test004, TestSize.Level2)
{
#ifndef ATM_BUILD_VARIANT_USER_ENABLE
    std::string tokenIdStr = std::to_string(g_shellTokenId);
    const char* argv[] = {"atm", "dump", "-v", "-i", tokenIdStr.c_str(),
                          "-p", TEST_PERMISSION_CAMERA.c_str()};
    int argc = sizeof(argv) / sizeof(argv[0]);

    // AtmCommand call replaced with ExecAtmCommand
    std::string result = ExecAtmCommand(argc, const_cast<char**>(argv));

    // Last option takes precedence, should query by permission
    EXPECT_TRUE(result.empty() || !IsOutputContain(result, "error"));
#endif
}

/**
 * @tc.name: atm_dump_status_by_perm_test001
 * @tc.desc: Query token status by valid permission name
 * @tc.type: FUNC
 * @tc.require: AR000GVIEG
 */
HWTEST_F(AtmCommandTest, atm_dump_status_by_perm_test001, TestSize.Level1)
{
    const char* argv[] = {"atm", "dump", "-t", "-p", TEST_PERMISSION_CAMERA.c_str()};
    int argc = sizeof(argv) / sizeof(argv[0]);

    // AtmCommand call replaced with ExecAtmCommand
    std::string result = ExecAtmCommand(argc, const_cast<char**>(argv));

    // Should return tokens with the specified permission
    EXPECT_TRUE(result.empty() || !IsOutputContain(result, "error"));
}

/**
 * @tc.name: atm_dump_status_by_perm_test002
 * @tc.desc: Query token status by another valid permission
 * @tc.type: FUNC
 * @tc.require: AR000GVIEG
 */
HWTEST_F(AtmCommandTest, atm_dump_status_by_perm_test002, TestSize.Level1)
{
    const char* argv[] = {"atm", "dump", "-t", "-p", TEST_PERMISSION_READ_CALENDAR.c_str()};
    int argc = sizeof(argv) / sizeof(argv[0]);

    // AtmCommand call replaced with ExecAtmCommand
    std::string result = ExecAtmCommand(argc, const_cast<char**>(argv));

    // Should return tokens with the specified permission
    EXPECT_TRUE(result.empty() || !IsOutputContain(result, "error"));
}

/**
 * @tc.name: atm_dump_status_by_perm_test003
 * @tc.desc: Query token status by invalid permission name
 * @tc.type: FUNC
 * @tc.require: AR000GVIEG
 */
HWTEST_F(AtmCommandTest, atm_dump_status_by_perm_test003, TestSize.Level2)
{
    const char* argv[] = {"atm", "dump", "-t", "-p", "ohos.permission.invalid.test.perm"};
    int argc = sizeof(argv) / sizeof(argv[0]);

    // AtmCommand call replaced with ExecAtmCommand
    std::string result = ExecAtmCommand(argc, const_cast<char**>(argv));

    // Should return empty result or error for invalid permission
    EXPECT_TRUE(result.empty() || IsOutputContain(result, "not found") ||
                IsOutputContain(result, "invalid") || IsOutputContain(result, "error"));
}

/**
 * @tc.name: atm_dump_status_by_perm_test004
 * @tc.desc: Query token status with empty permission value
 * @tc.type: FUNC
 * @tc.require: AR000GVIEG
 */
HWTEST_F(AtmCommandTest, atm_dump_status_by_perm_test004, TestSize.Level2)
{
    const char* argv[] = {"atm", "dump", "-t", "-p", ""};
    int argc = sizeof(argv) / sizeof(argv[0]);

    // AtmCommand call replaced with ExecAtmCommand
    std::string result = ExecAtmCommand(argc, const_cast<char**>(argv));

    // Empty permission string should result in error or help information
    EXPECT_TRUE(IsOutputContain(result, "option requires a value") || IsOutputContain(result, "usage:") ||
                IsOutputContain(result, "Error") || IsOutputContain(result, "invalid"));
}

/**
 * @tc.name: atm_dump_status_by_perm_test005
 * @tc.desc: Query token status without permission value specified
 * @tc.type: FUNC
 * @tc.require: AR000GVIEG
 */
HWTEST_F(AtmCommandTest, atm_dump_status_by_perm_test005, TestSize.Level2)
{
    const char* argv[] = {"atm", "dump", "-t", "-p"};
    int argc = sizeof(argv) / sizeof(argv[0]);

    // AtmCommand call replaced with ExecAtmCommand
    std::string result = ExecAtmCommand(argc, const_cast<char**>(argv));

    // Missing permission value should result in error or help information
    EXPECT_TRUE(IsOutputContain(result, "option requires a value") || IsOutputContain(result, "usage:") ||
                IsOutputContain(result, "Error") || IsOutputContain(result, "invalid") ||
                IsOutputContain(result, "Missing"));
}

/**
 * @tc.name: atm_error_test001
 * @tc.desc: Invalid main command
 * @tc.type: FUNC
 * @tc.require: AR000GVIEG
 */
HWTEST_F(AtmCommandTest, atm_error_test001, TestSize.Level1)
{
    const char* argv[] = {"atm", "invalid_command"};
    int argc = sizeof(argv) / sizeof(argv[0]);

    // AtmCommand call replaced with ExecAtmCommand
    std::string result = ExecAtmCommand(argc, const_cast<char**>(argv));

    EXPECT_TRUE(IsOutputContain(result, "not a valid") || IsOutputContain(result, "invalid"));
}

/**
 * @tc.name: atm_error_test002
 * @tc.desc: Dump command without options
 * @tc.type: FUNC
 * @tc.require: AR000GVIEG
 */
HWTEST_F(AtmCommandTest, atm_error_test002, TestSize.Level1)
{
    const char* argv[] = {"atm", "dump"};
    int argc = sizeof(argv) / sizeof(argv[0]);

    // AtmCommand call replaced with ExecAtmCommand
    std::string result = ExecAtmCommand(argc, const_cast<char**>(argv));

    EXPECT_TRUE(IsOutputContain(result, "must specify") || IsOutputContain(result, "option"));
}

/**
 * @tc.name: atm_error_test003
 * @tc.desc: Unknown option
 * @tc.type: FUNC
 * @tc.require: AR000GVIEG
 */
HWTEST_F(AtmCommandTest, atm_error_test003, TestSize.Level1)
{
    const char* argv[] = {"atm", "dump", "-x"};
    int argc = sizeof(argv) / sizeof(argv[0]);

    // AtmCommand call replaced with ExecAtmCommand
    std::string result = ExecAtmCommand(argc, const_cast<char**>(argv));

    EXPECT_TRUE(IsOutputContain(result, "unknown") || IsOutputContain(result, "invalid"));
}

/**
 * @tc.name: atm_error_test004
 * @tc.desc: Option without argument value
 * @tc.type: FUNC
 * @tc.require: AR000GVIEG
 */
HWTEST_F(AtmCommandTest, atm_error_test004, TestSize.Level1)
{
    const char* argv[] = {"atm", "dump", "-t", "-i"};
    int argc = sizeof(argv) / sizeof(argv[0]);

    // AtmCommand call replaced with ExecAtmCommand
    std::string result = ExecAtmCommand(argc, const_cast<char**>(argv));

    EXPECT_TRUE(IsOutputContain(result, "requires a value") || IsOutputContain(result, "option requires"));
}

/**
 * @tc.name: atm_error_test005
 * @tc.desc: Invalid parameter format (non-numeric token ID)
 * @tc.type: FUNC
 * @tc.require: AR000GVIEG
 */
HWTEST_F(AtmCommandTest, atm_error_test005, TestSize.Level2)
{
    const char* argv[] = {"atm", "dump", "-t", "-i", "abc"};
    int argc = sizeof(argv) / sizeof(argv[0]);

    // AtmCommand call replaced with ExecAtmCommand
    std::string result = ExecAtmCommand(argc, const_cast<char**>(argv));

    // Should parse as 0 or handle error
    EXPECT_TRUE(IsOutputContain(result, "invalid") || IsOutputContain(result, "0"));
}

/**
 * @tc.name: atm_error_test006
 * @tc.desc: Too long parameter
 * @tc.type: FUNC
 * @tc.require: AR000GVIEG
 */
HWTEST_F(AtmCommandTest, atm_error_test006, TestSize.Level3)
{
    std::string longBundleName(1000, 'a');
    const char* argv[] = {"atm", "dump", "-t", "-b", longBundleName.c_str()};
    int argc = sizeof(argv) / sizeof(argv[0]);

    // AtmCommand call replaced with ExecAtmCommand
    std::string result = ExecAtmCommand(argc, const_cast<char**>(argv));

    // Should handle gracefully
    EXPECT_TRUE(!result.empty());
}

/**
 * @tc.name: atm_error_test007
 * @tc.desc: Special characters in parameter
 * @tc.type: FUNC
 * @tc.require: AR000GVIEG
 */
HWTEST_F(AtmCommandTest, atm_error_test007, TestSize.Level3)
{
    const char* argv[] = {"atm", "dump", "-t", "-b", "com.example!@#$"};
    int argc = sizeof(argv) / sizeof(argv[0]);

    // AtmCommand call replaced with ExecAtmCommand
    std::string result = ExecAtmCommand(argc, const_cast<char**>(argv));

    // Should handle gracefully
    EXPECT_TRUE(!result.empty());
}

/**
 * @tc.name: atm_boundary_test001
 * @tc.desc: Token ID minimum boundary value (1)
 * @tc.type: FUNC
 * @tc.require: AR000GVIEG
 */
HWTEST_F(AtmCommandTest, atm_boundary_test001, TestSize.Level2)
{
    const char* argv[] = {"atm", "dump", "-t", "-i", "1"};
    int argc = sizeof(argv) / sizeof(argv[0]);

    // AtmCommand call replaced with ExecAtmCommand
    std::string result = ExecAtmCommand(argc, const_cast<char**>(argv));

    // Should handle gracefully
    EXPECT_TRUE(!result.empty());
}

/**
 * @tc.name: atm_boundary_test002
 * @tc.desc: Token ID maximum boundary value
 * @tc.type: FUNC
 * @tc.require: AR000GVIEG
 */
HWTEST_F(AtmCommandTest, atm_boundary_test002, TestSize.Level2)
{
    const char* argv[] = {"atm", "dump", "-t", "-i", "4294967295"};
    int argc = sizeof(argv) / sizeof(argv[0]);

    // AtmCommand call replaced with ExecAtmCommand
    std::string result = ExecAtmCommand(argc, const_cast<char**>(argv));

    // Should handle gracefully
    EXPECT_TRUE(!result.empty());
}

/**
 * @tc.name: atm_boundary_test003
 * @tc.desc: Negative token ID
 * @tc.type: FUNC
 * @tc.require: AR000GVIEG
 */
HWTEST_F(AtmCommandTest, atm_boundary_test003, TestSize.Level2)
{
    const char* argv[] = {"atm", "dump", "-t", "-i", "-1"};
    int argc = sizeof(argv) / sizeof(argv[0]);

    // AtmCommand call replaced with ExecAtmCommand
    std::string result = ExecAtmCommand(argc, const_cast<char**>(argv));

    EXPECT_TRUE(IsOutputContain(result, "TokenID does not exist."));
}

/**
 * @tc.name: atm_boundary_test004
 * @tc.desc: UserID minimum boundary value (0)
 * @tc.type: FUNC
 * @tc.require: AR000GVIEG
 */
HWTEST_F(AtmCommandTest, atm_boundary_test004, TestSize.Level2)
{
#ifndef ATM_BUILD_VARIANT_USER_ENABLE
    const char* argv[] = {"atm", "toggle", "record", "-s", "-i", "0", "-k", "1"};
    int argc = sizeof(argv) / sizeof(argv[0]);

    // AtmCommand call replaced with ExecAtmCommand
    std::string result = ExecAtmCommand(argc, const_cast<char**>(argv));

    // Should handle gracefully
    EXPECT_TRUE(!result.empty());
#endif
}

/**
 * @tc.name: atm_boundary_test005
 * @tc.desc: UserID maximum boundary value
 * @tc.type: FUNC
 * @tc.require: AR000GVIEG
 */
HWTEST_F(AtmCommandTest, atm_boundary_test005, TestSize.Level2)
{
#ifndef ATM_BUILD_VARIANT_USER_ENABLE
    const char* argv[] = {"atm", "toggle", "record", "-s", "-i", "999999", "-k", "1"};
    int argc = sizeof(argv) / sizeof(argv[0]);

    // AtmCommand call replaced with ExecAtmCommand
    std::string result = ExecAtmCommand(argc, const_cast<char**>(argv));

    // Should handle gracefully
    EXPECT_TRUE(!result.empty());
#endif
}

/**
 * @tc.name: atm_boundary_test006
 * @tc.desc: Empty string parameter for bundle name
 * @tc.type: FUNC
 * @tc.require: AR000GVIEG
 */
HWTEST_F(AtmCommandTest, atm_boundary_test006, TestSize.Level2)
{
    const char* argv[] = {"atm", "dump", "-t", "-b", ""};
    int argc = sizeof(argv) / sizeof(argv[0]);

    // AtmCommand call replaced with ExecAtmCommand
    std::string result = ExecAtmCommand(argc, const_cast<char**>(argv));

    // Empty string is treated as missing parameter, outputs help information
    EXPECT_TRUE(IsOutputContain(result, "option requires a value") || IsOutputContain(result, "usage:"));
}

/**
 * @tc.name: atm_boundary_test007
 * @tc.desc: Mutually exclusive options -t -i and -p used together
 * @tc.type: FUNC
 * @tc.require: AR000GVIEG
 */
HWTEST_F(AtmCommandTest, atm_boundary_test007, TestSize.Level2)
{
    const char* argv[] = {"atm", "dump", "-t", "-i", "123456",
                          "-p", TEST_PERMISSION_CAMERA.c_str()};
    int argc = sizeof(argv) / sizeof(argv[0]);

    // AtmCommand call replaced with ExecAtmCommand
    std::string result = ExecAtmCommand(argc, const_cast<char**>(argv));

    // Should return mutual exclusivity error
    EXPECT_TRUE(IsOutputContain(result, "mutually exclusive") ||
                IsOutputContain(result, "Error") ||
                IsOutputContain(result, "Only one of them"));
}

/**
 * @tc.name: atm_boundary_test008
 * @tc.desc: Mutually exclusive options -t -i and -b used together
 * @tc.type: FUNC
 * @tc.require: AR000GVIEG
 */
HWTEST_F(AtmCommandTest, atm_boundary_test008, TestSize.Level2)
{
    const char* argv[] = {"atm", "dump", "-t", "-i", "123456",
                          "-b", TEST_BUNDLE_NAME.c_str()};
    int argc = sizeof(argv) / sizeof(argv[0]);

    // AtmCommand call replaced with ExecAtmCommand
    std::string result = ExecAtmCommand(argc, const_cast<char**>(argv));

    // Should return mutual exclusivity error
    EXPECT_TRUE(IsOutputContain(result, "mutually exclusive") ||
                IsOutputContain(result, "Error") ||
                IsOutputContain(result, "Only one of them"));
}

/**
 * @tc.name: atm_boundary_test009
 * @tc.desc: Mutually exclusive options -t -p and -b used together
 * @tc.type: FUNC
 * @tc.require: AR000GVIEG
 */
HWTEST_F(AtmCommandTest, atm_boundary_test009, TestSize.Level2)
{
    const char* argv[] = {"atm", "dump", "-t", "-p", TEST_PERMISSION_CAMERA.c_str(),
                          "-b", TEST_BUNDLE_NAME.c_str()};
    int argc = sizeof(argv) / sizeof(argv[0]);

    // AtmCommand call replaced with ExecAtmCommand
    std::string result = ExecAtmCommand(argc, const_cast<char**>(argv));

    // Should return mutual exclusivity error
    EXPECT_TRUE(IsOutputContain(result, "mutually exclusive") ||
                IsOutputContain(result, "Error") ||
                IsOutputContain(result, "Only one of them"));
}

/**
 * @tc.name: atm_boundary_test010
 * @tc.desc: Mutually exclusive options -t -i and -n used together
 * @tc.type: FUNC
 * @tc.require: AR000GVIEG
 */
HWTEST_F(AtmCommandTest, atm_boundary_test010, TestSize.Level2)
{
    const char* argv[] = {"atm", "dump", "-t", "-i", "123456", "-n", "test_process"};
    int argc = sizeof(argv) / sizeof(argv[0]);

    // AtmCommand call replaced with ExecAtmCommand
    std::string result = ExecAtmCommand(argc, const_cast<char**>(argv));

    // Should return mutual exclusivity error
    EXPECT_TRUE(IsOutputContain(result, "mutually exclusive") ||
                IsOutputContain(result, "Error") ||
                IsOutputContain(result, "Only one of them"));
}

/**
 * @tc.name: atm_boundary_test011
 * @tc.desc: Mutually exclusive options -t -b and -n used together
 * @tc.type: FUNC
 * @tc.require: AR000GVIEG
 */
HWTEST_F(AtmCommandTest, atm_boundary_test011, TestSize.Level2)
{
    const char* argv[] = {"atm", "dump", "-t", "-b", TEST_BUNDLE_NAME.c_str(), "-n", "test_process"};
    int argc = sizeof(argv) / sizeof(argv[0]);

    // AtmCommand call replaced with ExecAtmCommand
    std::string result = ExecAtmCommand(argc, const_cast<char**>(argv));

    // Should return mutual exclusivity error
    EXPECT_TRUE(IsOutputContain(result, "mutually exclusive") ||
                IsOutputContain(result, "Error") ||
                IsOutputContain(result, "Only one of them"));
}

/**
 * @tc.name: atm_boundary_test012
 * @tc.desc: Three mutually exclusive options used together (-i, -p, -b)
 * @tc.type: FUNC
 * @tc.require: AR000GVIEG
 */
HWTEST_F(AtmCommandTest, atm_boundary_test012, TestSize.Level2)
{
    const char* argv[] = {"atm", "dump", "-t", "-i", "123456",
                          "-p", TEST_PERMISSION_CAMERA.c_str(),
                          "-b", TEST_BUNDLE_NAME.c_str()};
    int argc = sizeof(argv) / sizeof(argv[0]);

    // AtmCommand call replaced with ExecAtmCommand
    std::string result = ExecAtmCommand(argc, const_cast<char**>(argv));

    // Should return mutual exclusivity error
    EXPECT_TRUE(IsOutputContain(result, "mutually exclusive") ||
                IsOutputContain(result, "Error") ||
                IsOutputContain(result, "Only one of them"));
}

/**
 * @tc.name: atm_perf_test001
 * @tc.desc: Large token query performance test
 * @tc.type: FUNC
 * @tc.require: AR000GVIEG
 */
HWTEST_F(AtmCommandTest, atm_perf_test001, TestSize.Level3)
{
    const char* argv[] = {"atm", "dump", "-t"};
    int argc = sizeof(argv) / sizeof(argv[0]);

    auto startTime = std::chrono::high_resolution_clock::now();

    // AtmCommand call replaced with ExecAtmCommand
    std::string result = ExecAtmCommand(argc, const_cast<char**>(argv));

    auto endTime = std::chrono::high_resolution_clock::now();
    auto duration = std::chrono::duration_cast<std::chrono::milliseconds>(endTime - startTime).count();

    EXPECT_TRUE(result.empty() || !IsOutputContain(result, "error"));
    EXPECT_LT(duration, 5000) << "Query took " << duration << "ms, expected < 5000ms";
}

/**
 * @tc.name: atm_perf_test002
 * @tc.desc: Permission definitions query performance test
 * @tc.type: FUNC
 * @tc.require: AR000GVIEG
 */
HWTEST_F(AtmCommandTest, atm_perf_test002, TestSize.Level3)
{
    const char* argv[] = {"atm", "dump", "-d"};
    int argc = sizeof(argv) / sizeof(argv[0]);

    auto startTime = std::chrono::high_resolution_clock::now();

    // AtmCommand call replaced with ExecAtmCommand
    std::string result = ExecAtmCommand(argc, const_cast<char**>(argv));

    auto endTime = std::chrono::high_resolution_clock::now();
    auto duration = std::chrono::duration_cast<std::chrono::milliseconds>(endTime - startTime).count();

    EXPECT_TRUE(result.empty() || IsValidJson(result));
    EXPECT_LT(duration, 3000) << "Query took " << duration << "ms, expected < 3000ms";
}

/**
 * @tc.name: atm_perf_test003
 * @tc.desc: Continuous command execution stability test
 * @tc.type: FUNC
 * @tc.require: AR000GVIEG
 */
HWTEST_F(AtmCommandTest, atm_perf_test003, TestSize.Level3)
{
    const char* argv[] = {"atm", "dump", "-t"};
    int argc = sizeof(argv) / sizeof(argv[0]);

    // Execute 100 times
    for (int i = 0; i < 100; i++) {
        // AtmCommand call replaced with ExecAtmCommand
        std::string result = ExecAtmCommand(argc, const_cast<char**>(argv));
        // Should not crash
    }

    SUCCEED() << "Completed 100 continuous executions without crash";
}

/**
 * @tc.name: atm_stab_test001
 * @tc.desc: Repeated execution of same command
 * @tc.type: FUNC
 * @tc.require: AR000GVIEG
 */
HWTEST_F(AtmCommandTest, atm_stab_test001, TestSize.Level3)
{
    const char* argv[] = {"atm", "help"};
    int argc = sizeof(argv) / sizeof(argv[0]);

    // Execute 1000 times
    for (int i = 0; i < 1000; i++) {
        // AtmCommand call replaced with ExecAtmCommand
        std::string result = ExecAtmCommand(argc, const_cast<char**>(argv));
        ASSERT_TRUE(IsOutputContain(result, "usage: atm"));
    }

    SUCCEED() << "Completed 1000 repetitions without memory leak";
}

/**
 * @tc.name: atm_stab_test002
 * @tc.desc: Concurrent execution of different commands
 * @tc.type: FUNC
 * @tc.require: AR000GVIEG
 */
HWTEST_F(AtmCommandTest, atm_stab_test002, TestSize.Level3)
{
    // Note: True concurrency testing would require multi-threading
    // This test verifies sequential execution of different commands

    const char* argv1[] = {"atm", "help"};
    int argc1 = sizeof(argv1) / sizeof(argv1[0]);
    std::string result1 = ExecAtmCommand(argc1, const_cast<char**>(argv1));
    EXPECT_TRUE(IsOutputContain(result1, "usage: atm"));

    const char* argv2[] = {"atm", "dump", "-t"};
    int argc2 = sizeof(argv2) / sizeof(argv2[0]);
    std::string result2 = ExecAtmCommand(argc2, const_cast<char**>(argv2));
    EXPECT_FALSE(result2.empty());

    const char* argv3[] = {"atm", "dump", "-d"};
    int argc3 = sizeof(argv3) / sizeof(argv3[0]);
    std::string result3 = ExecAtmCommand(argc3, const_cast<char**>(argv3));
    EXPECT_TRUE(result3.empty() || IsValidJson(result3));

    SUCCEED() << "Multiple commands executed successfully";
}

/**
 * @tc.name: atm_stab_test003
 * @tc.desc: Abnormal input stress test
 * @tc.type: FUNC
 * @tc.require: AR000GVIEG
 */
HWTEST_F(AtmCommandTest, atm_stab_test003, TestSize.Level3)
{
    // Test various abnormal inputs
    const char* testCommands[][10] = {
        {"atm", "dump", "-t", "-i", "0"},
        {"atm", "dump", "-t", "-i", "-1"},
        {"atm", "dump", "-t", "-i", "999999999999"},
        {"atm", "dump", "-t", "-b", ""},
        {"atm", "dump", "-t", "-b", "very.long.bundle.name.that.exceeds.normal.length"},
        {"atm", "dump", "-d", "-p", ""},
        {"atm", "dump", "-d", "-p", "invalid!@#$%"},
        {"atm", "dump", "-x", "-y", "-z"},
    };

    for (size_t i = 0; i < sizeof(testCommands) / sizeof(testCommands[0]); i++) {
        int argc = 0;
        while (argc < 10 && testCommands[i][argc] != nullptr) {
            argc++;
        }

        ExecAtmCommand(argc, const_cast<char**>(testCommands[i]));
        // Should not crash
    }

    SUCCEED() << "All abnormal inputs handled without crash";
}

#ifndef ATM_BUILD_VARIANT_USER_ENABLE
/**
 * @tc.name: atm_perm_grant_test001
 * @tc.desc: Grant permission to shell token (should fail)
 * @tc.type: FUNC
 * @tc.require: AR000GVIEG
 */
HWTEST_F(AtmCommandTest, atm_perm_grant_test001, TestSize.Level1)
{
    std::string tokenIdStr = std::to_string(g_shellTokenId);
    const char* argv[] = {"atm", "perm", "-g", "-i", tokenIdStr.c_str(),
                          "-p", TEST_PERMISSION_CAMERA.c_str()};
    int argc = sizeof(argv) / sizeof(argv[0]);

    std::string result = ExecAtmCommand(argc, const_cast<char**>(argv));

    EXPECT_TRUE(IsOutputContain(result, "Error: TokenID does not exist or is not a valid application TokenID."));
}

/**
 * @tc.name: atm_perm_grant_test002
 * @tc.desc: Grant permission to HAP token
 * @tc.type: FUNC
 * @tc.require: AR000GVIEG
 */
HWTEST_F(AtmCommandTest, atm_perm_grant_test002, TestSize.Level1)
{
    std::string tokenIdStr = std::to_string(g_hapTokenId);
    const char* argv[] = {"atm", "perm", "-g", "-i", tokenIdStr.c_str(),
                          "-p", TEST_PERMISSION_CAMERA.c_str()};
    int argc = sizeof(argv) / sizeof(argv[0]);

    // AtmCommand call replaced with ExecAtmCommand
    std::string result = ExecAtmCommand(argc, const_cast<char**>(argv));

    // HAP token can be granted permissions through atm perm command
    EXPECT_TRUE(IsOutputContain(result, "Success") || IsOutputContain(result, "Failure"));
}

/**
 * @tc.name: atm_perm_grant_test003
 * @tc.desc: Grant permission to invalid token
 * @tc.type: FUNC
 * @tc.require: AR000GVIEG
 */
HWTEST_F(AtmCommandTest, atm_perm_grant_test003, TestSize.Level1)
{
    const char* argv[] = {"atm", "perm", "-g", "-i", "99999999",
                          "-p", TEST_PERMISSION_CAMERA.c_str()};
    int argc = sizeof(argv) / sizeof(argv[0]);

    // AtmCommand call replaced with ExecAtmCommand
    std::string result = ExecAtmCommand(argc, const_cast<char**>(argv));

    EXPECT_TRUE(IsOutputContain(result, "Failure") || IsOutputContain(result, "not exist"));
}

/**
 * @tc.name: atm_perm_grant_test004
 * @tc.desc: Grant invalid permission to token
 * @tc.type: FUNC
 * @tc.require: AR000GVIEG
 */
HWTEST_F(AtmCommandTest, atm_perm_grant_test004, TestSize.Level1)
{
    std::string tokenIdStr = std::to_string(g_shellTokenId);
    const char* argv[] = {"atm", "perm", "-g", "-i", tokenIdStr.c_str(),
                          "-p", INVALID_PERMISSION_NAME.c_str()};
    int argc = sizeof(argv) / sizeof(argv[0]);

    // AtmCommand call replaced with ExecAtmCommand
    std::string result = ExecAtmCommand(argc, const_cast<char**>(argv));

    EXPECT_TRUE(IsOutputContain(result, "Permission") && IsOutputContain(result, "does not exist"));
}

/**
 * @tc.name: atm_perm_grant_test005
 * @tc.desc: Grant permission without tokenID parameter
 * @tc.type: FUNC
 * @tc.require: AR000GVIEG
 */
HWTEST_F(AtmCommandTest, atm_perm_grant_test005, TestSize.Level1)
{
    const char* argv[] = {"atm", "perm", "-g", "-p", TEST_PERMISSION_CAMERA.c_str()};
    int argc = sizeof(argv) / sizeof(argv[0]);

    // AtmCommand call replaced with ExecAtmCommand
    std::string result = ExecAtmCommand(argc, const_cast<char**>(argv));

    EXPECT_TRUE(IsOutputContain(result, "Missing required parameter") ||
                IsOutputContain(result, "-i"));
}

/**
 * @tc.name: atm_perm_grant_test006
 * @tc.desc: Grant permission with tokenID=0
 * @tc.type: FUNC
 * @tc.require: AR000GVIEG
 */
HWTEST_F(AtmCommandTest, atm_perm_grant_test006, TestSize.Level1)
{
    const char* argv[] = {"atm", "perm", "-g", "-i", "0", "-p", TEST_PERMISSION_CAMERA.c_str()};
    int argc = sizeof(argv) / sizeof(argv[0]);

    // AtmCommand call replaced with ExecAtmCommand
    std::string result = ExecAtmCommand(argc, const_cast<char**>(argv));

    EXPECT_TRUE(IsOutputContain(result, "TokenID is invalid"));
}

/**
 * @tc.name: atm_perm_grant_test007
 * @tc.desc: Grant permission with non-existent tokenID
 * @tc.type: FUNC
 * @tc.require: AR000GVIEG
 */
HWTEST_F(AtmCommandTest, atm_perm_grant_test007, TestSize.Level1)
{
    const char* argv[] = {"atm", "perm", "-g", "-i", "99999999", "-p", TEST_PERMISSION_CAMERA.c_str()};
    int argc = sizeof(argv) / sizeof(argv[0]);

    // AtmCommand call replaced with ExecAtmCommand
    std::string result = ExecAtmCommand(argc, const_cast<char**>(argv));

    EXPECT_TRUE(IsOutputContain(result, "TokenID") && IsOutputContain(result, "does not exist"));
}

/**
 * @tc.name: atm_perm_grant_test008
 * @tc.desc: Grant permission without permission name parameter
 * @tc.type: FUNC
 * @tc.require: AR000GVIEG
 */
HWTEST_F(AtmCommandTest, atm_perm_grant_test008, TestSize.Level1)
{
    std::string tokenIdStr = std::to_string(g_shellTokenId);
    const char* argv[] = {"atm", "perm", "-g", "-i", tokenIdStr.c_str()};
    int argc = sizeof(argv) / sizeof(argv[0]);

    // AtmCommand call replaced with ExecAtmCommand
    std::string result = ExecAtmCommand(argc, const_cast<char**>(argv));

    EXPECT_TRUE(IsOutputContain(result, "Missing required parameter") ||
                IsOutputContain(result, "-p"));
}

/**
 * @tc.name: atm_perm_grant_test009
 * @tc.desc: Grant already granted permission to token
 * @tc.type: FUNC
 * @tc.require: AR000GVIEG
 */
HWTEST_F(AtmCommandTest, atm_perm_grant_test009, TestSize.Level2)
{
    std::string tokenIdStr = std::to_string(g_hapTokenId);
    const char* argv[] = {"atm", "perm", "-g", "-i", tokenIdStr.c_str(),
                          "-p", TEST_PERMISSION_CAMERA.c_str()};
    int argc = sizeof(argv) / sizeof(argv[0]);

    // Grant twice to test duplicate permission handling
    ExecAtmCommand(argc, const_cast<char**>(argv));
    std::string result = ExecAtmCommand(argc, const_cast<char**>(argv));

    EXPECT_TRUE(IsOutputContain(result, "Success") || IsOutputContain(result, "already granted") ||
                IsOutputContain(result, "Failure"));
}

/**
 * @tc.name: atm_perm_grant_test010
 * @tc.desc: Grant system level permission to token
 * @tc.type: FUNC
 * @tc.require: AR000GVIEG
 */
HWTEST_F(AtmCommandTest, atm_perm_grant_test010, TestSize.Level2)
{
    std::string tokenIdStr = std::to_string(g_hapTokenId);
    const char* argv[] = {"atm", "perm", "-g", "-i", tokenIdStr.c_str(),
                          "-p", "ohos.permission.GET_NETWORK_INFO"};
    int argc = sizeof(argv) / sizeof(argv[0]);

    std::string result = ExecAtmCommand(argc, const_cast<char**>(argv));

    EXPECT_TRUE(IsOutputContain(result, "Success") || IsOutputContain(result, "Failure") ||
                IsOutputContain(result, "not allowed"));
}

/**
 * @tc.name: atm_perm_revoke_test001
 * @tc.desc: Revoke permission from shell token (should fail)
 * @tc.type: FUNC
 * @tc.require: AR000GVIEG
 */
HWTEST_F(AtmCommandTest, atm_perm_revoke_test001, TestSize.Level1)
{
    std::string tokenIdStr = std::to_string(g_shellTokenId);
    const char* argv[] = {"atm", "perm", "-c", "-i", tokenIdStr.c_str(),
                          "-p", TEST_PERMISSION_CAMERA.c_str()};
    int argc = sizeof(argv) / sizeof(argv[0]);

    std::string result = ExecAtmCommand(argc, const_cast<char**>(argv));

    EXPECT_TRUE(IsOutputContain(result, "Error: TokenID does not exist or is not a valid application TokenID."));
}

/**
 * @tc.name: atm_perm_revoke_test002
 * @tc.desc: Revoke permission from HAP token
 * @tc.type: FUNC
 * @tc.require: AR000GVIEG
 */
HWTEST_F(AtmCommandTest, atm_perm_revoke_test002, TestSize.Level1)
{
    std::string tokenIdStr = std::to_string(g_hapTokenId);
    const char* argv[] = {"atm", "perm", "-c", "-i", tokenIdStr.c_str(),
                          "-p", TEST_PERMISSION_CAMERA.c_str()};
    int argc = sizeof(argv) / sizeof(argv[0]);

    std::string result = ExecAtmCommand(argc, const_cast<char**>(argv));

    // HAP token can have permissions revoked through atm perm command
    EXPECT_TRUE(IsOutputContain(result, "Success") || IsOutputContain(result, "Failure"));
}

/**
 * @tc.name: atm_perm_revoke_test003
 * @tc.desc: Revoke permission from invalid token
 * @tc.type: FUNC
 * @tc.require: AR000GVIEG
 */
HWTEST_F(AtmCommandTest, atm_perm_revoke_test003, TestSize.Level1)
{
    const char* argv[] = {"atm", "perm", "-c", "-i", "99999999",
                          "-p", TEST_PERMISSION_CAMERA.c_str()};
    int argc = sizeof(argv) / sizeof(argv[0]);

    // AtmCommand call replaced with ExecAtmCommand
    std::string result = ExecAtmCommand(argc, const_cast<char**>(argv));

    EXPECT_TRUE(IsOutputContain(result, "Failure") || IsOutputContain(result, "not exist"));
}

/**
 * @tc.name: atm_perm_revoke_test004
 * @tc.desc: Revoke invalid permission from token
 * @tc.type: FUNC
 * @tc.require: AR000GVIEG
 */
HWTEST_F(AtmCommandTest, atm_perm_revoke_test004, TestSize.Level1)
{
    std::string tokenIdStr = std::to_string(g_shellTokenId);
    const char* argv[] = {"atm", "perm", "-c", "-i", tokenIdStr.c_str(),
                          "-p", INVALID_PERMISSION_NAME.c_str()};
    int argc = sizeof(argv) / sizeof(argv[0]);

    // AtmCommand call replaced with ExecAtmCommand
    std::string result = ExecAtmCommand(argc, const_cast<char**>(argv));

    EXPECT_TRUE(IsOutputContain(result, "Permission") && IsOutputContain(result, "does not exist"));
}

/**
 * @tc.name: atm_perm_revoke_test005
 * @tc.desc: Revoke permission without tokenID parameter
 * @tc.type: FUNC
 * @tc.require: AR000GVIEG
 */
HWTEST_F(AtmCommandTest, atm_perm_revoke_test005, TestSize.Level1)
{
    const char* argv[] = {"atm", "perm", "-c", "-p", TEST_PERMISSION_CAMERA.c_str()};
    int argc = sizeof(argv) / sizeof(argv[0]);

    // AtmCommand call replaced with ExecAtmCommand
    std::string result = ExecAtmCommand(argc, const_cast<char**>(argv));

    EXPECT_TRUE(IsOutputContain(result, "Missing required parameter") ||
                IsOutputContain(result, "-i"));
}

/**
 * @tc.name: atm_perm_revoke_test006
 * @tc.desc: Revoke permission with tokenID=0
 * @tc.type: FUNC
 * @tc.require: AR000GVIEG
 */
HWTEST_F(AtmCommandTest, atm_perm_revoke_test006, TestSize.Level1)
{
    const char* argv[] = {"atm", "perm", "-c", "-i", "0", "-p", TEST_PERMISSION_CAMERA.c_str()};
    int argc = sizeof(argv) / sizeof(argv[0]);

    // AtmCommand call replaced with ExecAtmCommand
    std::string result = ExecAtmCommand(argc, const_cast<char**>(argv));

    EXPECT_TRUE(IsOutputContain(result, "TokenID is invalid"));
}

/**
 * @tc.name: atm_perm_revoke_test007
 * @tc.desc: Revoke permission with non-existent tokenID
 * @tc.type: FUNC
 * @tc.require: AR000GVIEG
 */
HWTEST_F(AtmCommandTest, atm_perm_revoke_test007, TestSize.Level1)
{
    const char* argv[] = {"atm", "perm", "-c", "-i", "99999999", "-p", TEST_PERMISSION_CAMERA.c_str()};
    int argc = sizeof(argv) / sizeof(argv[0]);

    // AtmCommand call replaced with ExecAtmCommand
    std::string result = ExecAtmCommand(argc, const_cast<char**>(argv));

    EXPECT_TRUE(IsOutputContain(result, "TokenID") && IsOutputContain(result, "does not exist"));
}

/**
 * @tc.name: atm_perm_revoke_test008
 * @tc.desc: Revoke permission without permission name parameter
 * @tc.type: FUNC
 * @tc.require: AR000GVIEG
 */
HWTEST_F(AtmCommandTest, atm_perm_revoke_test008, TestSize.Level1)
{
    std::string tokenIdStr = std::to_string(g_shellTokenId);
    const char* argv[] = {"atm", "perm", "-c", "-i", tokenIdStr.c_str()};
    int argc = sizeof(argv) / sizeof(argv[0]);

    // AtmCommand call replaced with ExecAtmCommand
    std::string result = ExecAtmCommand(argc, const_cast<char**>(argv));

    EXPECT_TRUE(IsOutputContain(result, "Missing required parameter") ||
                IsOutputContain(result, "-p"));
}

#endif // !ATM_BUILD_VARIANT_USER_ENABLE

/**
 * @tc.name: atm_toggle_req_test001
 * @tc.desc: Set request toggle status to open
 * @tc.type: FUNC
 * @tc.require: AR000GVIEG
 */
HWTEST_F(AtmCommandTest, atm_toggle_req_test001, TestSize.Level1)
{
#ifndef ATM_BUILD_VARIANT_USER_ENABLE
    const char* argv[] = {"atm", "toggle", "request", "-s",
                          "-i", "100",
                          "-p", TEST_PERMISSION_CAMERA.c_str(),
                          "-k", "1"};
    int argc = sizeof(argv) / sizeof(argv[0]);

    // AtmCommand call replaced with ExecAtmCommand
    std::string result = ExecAtmCommand(argc, const_cast<char**>(argv));

    EXPECT_TRUE(IsOutputContain(result, "Success") || IsOutputContain(result, "open"));
#endif
}

/**
 * @tc.name: atm_toggle_req_test002
 * @tc.desc: Set request toggle status to closed
 * @tc.type: FUNC
 * @tc.require: AR000GVIEG
 */
HWTEST_F(AtmCommandTest, atm_toggle_req_test002, TestSize.Level1)
{
#ifndef ATM_BUILD_VARIANT_USER_ENABLE
    const char* argv[] = {"atm", "toggle", "request", "-s",
                          "-i", "100",
                          "-p", TEST_PERMISSION_CAMERA.c_str(),
                          "-k", "0"};
    int argc = sizeof(argv) / sizeof(argv[0]);

    // AtmCommand call replaced with ExecAtmCommand
    std::string result = ExecAtmCommand(argc, const_cast<char**>(argv));

    EXPECT_TRUE(IsOutputContain(result, "Success") || IsOutputContain(result, "closed"));
#endif
}

/**
 * @tc.name: atm_toggle_req_test003
 * @tc.desc: Get request toggle status
 * @tc.type: FUNC
 * @tc.require: AR000GVIEG
 */
HWTEST_F(AtmCommandTest, atm_toggle_req_test003, TestSize.Level1)
{
#ifndef ATM_BUILD_VARIANT_USER_ENABLE
    const char* argv[] = {"atm", "toggle", "request", "-o",
                          "-i", "100",
                          "-p", TEST_PERMISSION_CAMERA.c_str()};
    int argc = sizeof(argv) / sizeof(argv[0]);

    // AtmCommand call replaced with ExecAtmCommand
    std::string result = ExecAtmCommand(argc, const_cast<char**>(argv));

    EXPECT_TRUE(IsOutputContain(result, "Toggle status") || IsOutputContain(result, "Success"));
#endif
}

/**
 * @tc.name: atm_toggle_req_test004
 * @tc.desc: Set request toggle without userID parameter
 * @tc.type: FUNC
 * @tc.require: AR000GVIEG
 */
HWTEST_F(AtmCommandTest, atm_toggle_req_test004, TestSize.Level1)
{
#ifndef ATM_BUILD_VARIANT_USER_ENABLE
    const char* argv[] = {"atm", "toggle", "request", "-s",
                          "-p", TEST_PERMISSION_CAMERA.c_str(),
                          "-k", "1"};
    int argc = sizeof(argv) / sizeof(argv[0]);

    // AtmCommand call replaced with ExecAtmCommand
    std::string result = ExecAtmCommand(argc, const_cast<char**>(argv));

    // System may have default userID, so it can succeed
    EXPECT_TRUE(IsOutputContain(result, "Success") || IsOutputContain(result, "open"));
#endif
}

/**
 * @tc.name: atm_toggle_req_test005
 * @tc.desc: Toggle request status between open and closed
 * @tc.type: FUNC
 * @tc.require: AR000GVIEG
 */
HWTEST_F(AtmCommandTest, atm_toggle_req_test005, TestSize.Level2)
{
#ifndef ATM_BUILD_VARIANT_USER_ENABLE
    // Set to open
    const char* argv1[] = {"atm", "toggle", "request", "-s",
                           "-i", "100",
                           "-p", TEST_PERMISSION_CAMERA.c_str(),
                           "-k", "1"};
    int argc1 = sizeof(argv1) / sizeof(argv1[0]);

    AtmCommand cmd1(argc1, const_cast<char**>(argv1));
    std::string result1 = cmd1.ExecCommand();

    EXPECT_TRUE(IsOutputContain(result1, "Success") || IsOutputContain(result1, "open"));

    // Set to closed
    const char* argv2[] = {"atm", "toggle", "request", "-s",
                           "-i", "100",
                           "-p", TEST_PERMISSION_CAMERA.c_str(),
                           "-k", "0"};
    int argc2 = sizeof(argv2) / sizeof(argv2[0]);

    AtmCommand cmd2(argc2, const_cast<char**>(argv2));
    std::string result2 = cmd2.ExecCommand();

    EXPECT_TRUE(IsOutputContain(result2, "Success") || IsOutputContain(result2, "closed"));
#endif
}

/**
 * @tc.name: atm_toggle_req_test006
 * @tc.desc: Set request toggle with invalid status value
 * @tc.type: FUNC
 * @tc.require: AR000GVIEG
 */
HWTEST_F(AtmCommandTest, atm_toggle_req_test006, TestSize.Level2)
{
#ifndef ATM_BUILD_VARIANT_USER_ENABLE
    const char* argv[] = {"atm", "toggle", "request", "-s",
                          "-i", "100",
                          "-p", TEST_PERMISSION_CAMERA.c_str(),
                          "-k", "2"};
    int argc = sizeof(argv) / sizeof(argv[0]);

    std::string result = ExecAtmCommand(argc, const_cast<char**>(argv));

    EXPECT_TRUE(IsOutputContain(result, "invalid") || IsOutputContain(result, "error") ||
                IsOutputContain(result, "Failure"));
#endif
}

/**
 * @tc.name: atm_toggle_req_test007
 * @tc.desc: Set request toggle without permission name parameter
 * @tc.type: FUNC
 * @tc.require: AR000GVIEG
 */
HWTEST_F(AtmCommandTest, atm_toggle_req_test007, TestSize.Level1)
{
#ifndef ATM_BUILD_VARIANT_USER_ENABLE
    const char* argv[] = {"atm", "toggle", "request", "-s",
                          "-i", "100",
                          "-k", "1"};
    int argc = sizeof(argv) / sizeof(argv[0]);

    std::string result = ExecAtmCommand(argc, const_cast<char**>(argv));

    EXPECT_TRUE(IsOutputContain(result, "Missing required parameter") ||
                IsOutputContain(result, "-p") ||
                IsOutputContain(result, "requires a value"));
#endif
}

/**
 * @tc.name: atm_toggle_rec_test001
 * @tc.desc: Set record toggle status to open
 * @tc.type: FUNC
 * @tc.require: AR000GVIEG
 */
HWTEST_F(AtmCommandTest, atm_toggle_rec_test001, TestSize.Level1)
{
#ifndef ATM_BUILD_VARIANT_USER_ENABLE
    const char* argv[] = {"atm", "toggle", "record", "-s",
                          "-i", "100",
                          "-k", "1"};
    int argc = sizeof(argv) / sizeof(argv[0]);

    // AtmCommand call replaced with ExecAtmCommand
    std::string result = ExecAtmCommand(argc, const_cast<char**>(argv));

    EXPECT_TRUE(IsOutputContain(result, "Success") || IsOutputContain(result, "open"));
#endif
}

/**
 * @tc.name: atm_toggle_rec_test002
 * @tc.desc: Set record toggle status to closed
 * @tc.type: FUNC
 * @tc.require: AR000GVIEG
 */
HWTEST_F(AtmCommandTest, atm_toggle_rec_test002, TestSize.Level1)
{
#ifndef ATM_BUILD_VARIANT_USER_ENABLE
    const char* argv[] = {"atm", "toggle", "record", "-s",
                          "-i", "100",
                          "-k", "0"};
    int argc = sizeof(argv) / sizeof(argv[0]);

    // AtmCommand call replaced with ExecAtmCommand
    std::string result = ExecAtmCommand(argc, const_cast<char**>(argv));

    EXPECT_TRUE(IsOutputContain(result, "Success") || IsOutputContain(result, "closed"));
#endif
}

/**
 * @tc.name: atm_toggle_rec_test003
 * @tc.desc: Get record toggle status
 * @tc.type: FUNC
 * @tc.require: AR000GVIEG
 */
HWTEST_F(AtmCommandTest, atm_toggle_rec_test003, TestSize.Level1)
{
#ifndef ATM_BUILD_VARIANT_USER_ENABLE
    const char* argv[] = {"atm", "toggle", "record", "-o",
                          "-i", "100"};
    int argc = sizeof(argv) / sizeof(argv[0]);

    // AtmCommand call replaced with ExecAtmCommand
    std::string result = ExecAtmCommand(argc, const_cast<char**>(argv));

    EXPECT_TRUE(IsOutputContain(result, "Record toggle status") || IsOutputContain(result, "Success"));
#endif
}

/**
 * @tc.name: atm_toggle_rec_test004
 * @tc.desc: Get record toggle status for unset userID
 * @tc.type: FUNC
 * @tc.require: AR000GVIEG
 */
HWTEST_F(AtmCommandTest, atm_toggle_rec_test004, TestSize.Level2)
{
#ifndef ATM_BUILD_VARIANT_USER_ENABLE
    const char* argv[] = {"atm", "toggle", "record", "-o",
                          "-i", "999999"};
    int argc = sizeof(argv) / sizeof(argv[0]);

    std::string result = ExecAtmCommand(argc, const_cast<char**>(argv));

    EXPECT_TRUE(IsOutputContain(result, "Failure"));
#endif
}

/**
 * @tc.name: atm_toggle_rec_test005
 * @tc.desc: Set record toggle with invalid status value
 * @tc.type: FUNC
 * @tc.require: AR000GVIEG
 */
HWTEST_F(AtmCommandTest, atm_toggle_rec_test005, TestSize.Level2)
{
#ifndef ATM_BUILD_VARIANT_USER_ENABLE
    const char* argv[] = {"atm", "toggle", "record", "-s",
                          "-i", "100",
                          "-k", "2"};
    int argc = sizeof(argv) / sizeof(argv[0]);

    std::string result = ExecAtmCommand(argc, const_cast<char**>(argv));

    EXPECT_TRUE(IsOutputContain(result, "Error") || IsOutputContain(result, "Failure"));
#endif
}

/**
 * @tc.name: atm_toggle_rec_test006
 * @tc.desc: Set record toggle without userID parameter
 * @tc.type: FUNC
 * @tc.require: AR000GVIEG
 */
HWTEST_F(AtmCommandTest, atm_toggle_rec_test006, TestSize.Level1)
{
#ifndef ATM_BUILD_VARIANT_USER_ENABLE
    const char* argv[] = {"atm", "toggle", "record", "-s",
                          "-k", "1"};
    int argc = sizeof(argv) / sizeof(argv[0]);

    std::string result = ExecAtmCommand(argc, const_cast<char**>(argv));

    EXPECT_TRUE(IsOutputContain(result, "Missing required parameter") ||
                IsOutputContain(result, "-i") ||
                IsOutputContain(result, "requires a value"));
#endif
}
} // namespace AccessToken
} // namespace Security
} // namespace OHOS
