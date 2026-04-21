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

#include "claw_ticket_manager_test.h"

#include <thread>
#include <chrono>

#include "access_token_error.h"
#include "accesstoken_common_log.h"
#include "access_token_error.h"
#include "accesstoken_info_manager.h"
#include "hap_token_info.h"
#include "permission_manager.h"
#include "token_setproc.h"

namespace OHOS {
namespace Security {
namespace AccessToken {

using namespace testing::ext;

namespace {

static constexpr int32_t TEST_USER_ID = 100;
static constexpr int32_t TEST_INST_INDEX = 0;
static constexpr size_t LONG_STRING_SIZE = 4096;

CliAuthInfo CreateTestCliAuth(const std::string& cliName,
    const std::vector<std::string>& perms, const std::vector<bool>& states)
{
    CliAuthInfo auth;
    auth.cliInfo.cliName = cliName;
    auth.cliInfo.subCliName = "test_sub";
    auth.permissionNames = perms;
    auth.authorizationResults = states;
    return auth;
}

SkillAuthInfo CreateTestSkillAuth(const std::string& bundleName,
    const std::vector<std::string>& perms, const std::vector<bool>& states)
{
    SkillAuthInfo auth;
    auth.skillInfo.bundleName = bundleName;
    auth.skillInfo.moduleName = "test_module";
    auth.skillInfo.skillName = "test_skill";
    auth.permissionNames = perms;
    auth.authorizationResults = states;
    return auth;
}

std::string GenerateLongString(size_t len)
{
    return std::string(len, 'a');
}

std::string GenerateSpecialString()
{
    return "test\"with\\special\nchars\t中文!@#$%^&*()";
}

AccessTokenID CreateTestHapTokenHelper()
{
    HapInfoParams infoParms = {
        .userID = TEST_USER_ID,
        .bundleName = "claw_ticket_test",
        .instIndex = TEST_INST_INDEX,
        .appIDDesc = "test"
    };
    HapPolicy policyPrams = {
        .apl = APL_NORMAL,
        .domain = "test.domain"
    };
    AccessTokenIDEx tokenIdEx = {0};
    std::vector<GenericValues> undefValues;
    int32_t ret = AccessTokenInfoManager::GetInstance().CreateHapTokenInfo(
        infoParms, policyPrams, tokenIdEx, undefValues);
    if (ret != RET_SUCCESS) {
        return INVALID_TOKENID;
    }
    return tokenIdEx.tokenIdExStruct.tokenID;
}

using BatchGenerateTicketFunc = int32_t (*)(uint32_t, AccessTokenID,
    const std::vector<std::string>&, std::vector<VerifyTicketInfo>&);
using BatchVerifyTicketFunc = int32_t (*)(uint32_t, AccessTokenID,
    const std::vector<VerifyTicketInfo>&, std::vector<int32_t>&);

static BatchGenerateTicketFunc g_batchGenerateTicketFunc = nullptr;
static BatchVerifyTicketFunc g_batchVerifyTicketFunc = nullptr;

static int32_t MockBatchGenerateTicketFailed(uint32_t osAccountId, AccessTokenID callerId,
    const std::vector<std::string>& messages, std::vector<VerifyTicketInfo>& tickets)
{
    tickets.clear();
    return RET_FAILED;
}

static int32_t MockBatchVerifyTicketAllGranted(uint32_t osAccountId, AccessTokenID callerId,
    const std::vector<VerifyTicketInfo>& verifyInfos, std::vector<int32_t>& verifyRes)
{
    verifyRes.assign(verifyInfos.size(), PERMISSION_GRANTED);
    return RET_SUCCESS;
}

static int32_t MockBatchVerifyTicketAllDenied(uint32_t osAccountId, AccessTokenID callerId,
    const std::vector<VerifyTicketInfo>& verifyInfos, std::vector<int32_t>& verifyRes)
{
    verifyRes.assign(verifyInfos.size(), PERMISSION_DENIED);
    return RET_SUCCESS;
}

static int32_t MockBatchVerifyTicketMixed(uint32_t osAccountId, AccessTokenID callerId,
    const std::vector<VerifyTicketInfo>& verifyInfos, std::vector<int32_t>& verifyRes)
{
    verifyRes = {PERMISSION_GRANTED, PERMISSION_DENIED, PERMISSION_GRANTED};
    return RET_SUCCESS;
}

static int32_t MockBatchVerifyTicketFailed(uint32_t osAccountId, AccessTokenID callerId,
    const std::vector<VerifyTicketInfo>& verifyInfos, std::vector<int32_t>& verifyRes)
{
    verifyRes.clear();
    return RET_FAILED;
}

__attribute__((unused)) int32_t BatchGenerateTicket(uint32_t osAccountId, AccessTokenID callerId,
    const std::vector<std::string>& messages, std::vector<VerifyTicketInfo>& tickets)
{
    if (g_batchGenerateTicketFunc != nullptr) {
        return g_batchGenerateTicketFunc(osAccountId, callerId, messages, tickets);
    }
    return RET_SUCCESS;
}

__attribute__((unused)) int32_t BatchVerifyTicket(uint32_t osAccountId, AccessTokenID callerId,
    const std::vector<VerifyTicketInfo>& verifyInfos, std::vector<int32_t>& verifyRes)
{
    if (g_batchVerifyTicketFunc != nullptr) {
        return g_batchVerifyTicketFunc(osAccountId, callerId, verifyInfos, verifyRes);
    }
    return RET_SUCCESS;
}

inline void SetBatchGenerateTicketMock(BatchGenerateTicketFunc func)
{
    g_batchGenerateTicketFunc = func;
}

inline void SetBatchVerifyTicketMock(BatchVerifyTicketFunc func)
{
    g_batchVerifyTicketFunc = func;
}

inline void ClearBatchMocks()
{
    g_batchGenerateTicketFunc = nullptr;
    g_batchVerifyTicketFunc = nullptr;
}

} // anonymous namespace

void ClawTicketManagerTest::SetUpTestCase() {}

void ClawTicketManagerTest::TearDownTestCase() {}

void ClawTicketManagerTest::SetUp()
{
    auto atManagerService = DelayedSingleton<AccessTokenManagerService>::GetInstance();
    ASSERT_NE(nullptr, atManagerService);
    atManagerService->Initialize();
    testTokenId_ = CreateTestHapToken();
}

void ClawTicketManagerTest::TearDown()
{
    for (const auto& challenge : testChallenges_) {
        ClawTicketManager::GetInstance().DeleteClawTicket(challenge);
    }
    testChallenges_.clear();

    if (testTokenId_ != INVALID_TOKENID) {
        AccessTokenInfoManager::GetInstance().RemoveHapTokenInfo(testTokenId_);
        testTokenId_ = INVALID_TOKENID;
    }

    DelayedSingleton<AccessTokenManagerService>::DestroyInstance();
}

AccessTokenID ClawTicketManagerTest::CreateTestHapToken()
{
    return CreateTestHapTokenHelper();
}

void ClawTicketManagerTest::DeleteTestHapToken(AccessTokenID tokenId)
{
    if (tokenId != INVALID_TOKENID) {
        AccessTokenInfoManager::GetInstance().RemoveHapTokenInfo(tokenId);
    }
}

std::string ClawTicketManagerTest::GenerateTestCliTicket(AccessTokenID tokenId)
{
    std::vector<CliAuthInfo> cliAuthInfos;
    cliAuthInfos.push_back(CreateTestCliAuth("test_cli",
        {"ohos.permission.CAMERA", "ohos.permission.MICROPHONE"},
        {true, false}));

    std::vector<std::string> challenges;
    int32_t ret = ClawTicketManager::GetInstance().GenerateCliTicket(tokenId, cliAuthInfos, challenges);
    if (ret != RET_SUCCESS || challenges.empty()) {
        return "";
    }
    testChallenges_.push_back(challenges[0]);
    return challenges[0];
}

std::string ClawTicketManagerTest::GenerateTestSkillTicket(AccessTokenID tokenId)
{
    std::vector<SkillAuthInfo> skillAuthInfos;
    skillAuthInfos.push_back(CreateTestSkillAuth("com.test.bundle",
        {"ohos.permission.CAMERA", "ohos.permission.MICROPHONE"},
        {true, false}));

    std::vector<std::string> challenges;
    int32_t ret = ClawTicketManager::GetInstance().GenerateSkillTicket(tokenId, skillAuthInfos, challenges);
    if (ret != RET_SUCCESS || challenges.empty()) {
        return "";
    }
    testChallenges_.push_back(challenges[0]);
    return challenges[0];
}

// ==================== GenerateCliTicket Test Cases ====================

/**
 * @tc.name: GenerateCliTicketTest001
 * @tc.desc: Test GenerateCliTicket with valid input
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(ClawTicketManagerTest, GenerateCliTicketTest001, TestSize.Level0)
{
    AccessTokenID tokenId = CreateTestHapToken();
    ASSERT_NE(INVALID_TOKENID, tokenId);

    std::vector<CliAuthInfo> cliAuthInfos;
    cliAuthInfos.push_back(CreateTestCliAuth("test_cli",
        {"ohos.permission.CAMERA", "ohos.permission.MICROPHONE"},
        {true, false}));

    std::vector<std::string> challenges;
    int32_t ret = ClawTicketManager::GetInstance().GenerateCliTicket(tokenId, cliAuthInfos, challenges);

    EXPECT_EQ(RET_SUCCESS, ret);
    EXPECT_EQ(1, challenges.size());
    EXPECT_FALSE(challenges[0].empty());
    testChallenges_.push_back(challenges[0]);

    DeleteTestHapToken(tokenId);
}

/**
 * @tc.name: GenerateCliTicketTest002
 * @tc.desc: Test GenerateCliTicket with multiple CliAuthInfo
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(ClawTicketManagerTest, GenerateCliTicketTest002, TestSize.Level0)
{
    AccessTokenID tokenId = CreateTestHapToken();
    ASSERT_NE(INVALID_TOKENID, tokenId);

    std::vector<CliAuthInfo> cliAuthInfos;
    cliAuthInfos.push_back(CreateTestCliAuth("test_cli1",
        {"ohos.permission.CAMERA"}, {true}));
    cliAuthInfos.push_back(CreateTestCliAuth("test_cli2",
        {"ohos.permission.MICROPHONE"}, {false}));
    cliAuthInfos.push_back(CreateTestCliAuth("test_cli3",
        {"ohos.permission.READ_CONTACTS"}, {true}));

    std::vector<std::string> challenges;
    int32_t ret = ClawTicketManager::GetInstance().GenerateCliTicket(tokenId, cliAuthInfos, challenges);

    EXPECT_EQ(RET_SUCCESS, ret);
    EXPECT_EQ(3, challenges.size());
    for (const auto& challenge : challenges) {
        EXPECT_FALSE(challenge.empty());
        testChallenges_.push_back(challenge);
    }

    DeleteTestHapToken(tokenId);
}

/**
 * @tc.name: GenerateCliTicketTest003
 * @tc.desc: Test GenerateCliTicket with invalid tokenId
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(ClawTicketManagerTest, GenerateCliTicketTest003, TestSize.Level0)
{
    std::vector<CliAuthInfo> cliAuthInfos;
    cliAuthInfos.push_back(CreateTestCliAuth("test_cli",
        {"ohos.permission.CAMERA"}, {true}));

    std::vector<std::string> challenges;
    int32_t ret = ClawTicketManager::GetInstance().GenerateCliTicket(INVALID_TOKENID, cliAuthInfos, challenges);

    EXPECT_EQ(AccessTokenError::ERR_TOKENID_NOT_EXIST, ret);
    EXPECT_TRUE(challenges.empty());
}

/**
 * @tc.name: GenerateCliTicketTest004
 * @tc.desc: Test GenerateCliTicket when BatchGenerateTicket returns failure
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(ClawTicketManagerTest, GenerateCliTicketTest004, TestSize.Level0)
{
    AccessTokenID tokenId = CreateTestHapToken();
    ASSERT_NE(INVALID_TOKENID, tokenId);

    SetBatchGenerateTicketMock(MockBatchGenerateTicketFailed);

    std::vector<CliAuthInfo> cliAuthInfos;
    cliAuthInfos.push_back(CreateTestCliAuth("test_cli",
        {"ohos.permission.CAMERA"}, {true}));

    std::vector<std::string> challenges;
    int32_t ret = ClawTicketManager::GetInstance().GenerateCliTicket(tokenId, cliAuthInfos, challenges);

    EXPECT_EQ(RET_FAILED, ret);
    EXPECT_TRUE(challenges.empty());

    ClearBatchMocks();
    DeleteTestHapToken(tokenId);
}

/**
 * @tc.name: GenerateCliTicketTest005
 * @tc.desc: Test GenerateCliTicket with oversized strings
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(ClawTicketManagerTest, GenerateCliTicketTest005, TestSize.Level0)
{
    AccessTokenID tokenId = CreateTestHapToken();
    ASSERT_NE(INVALID_TOKENID, tokenId);

    std::string longCliName = GenerateLongString(LONG_STRING_SIZE);
    std::vector<CliAuthInfo> cliAuthInfos;
    cliAuthInfos.push_back(CreateTestCliAuth(longCliName,
        {"ohos.permission.CAMERA"}, {true}));

    std::vector<std::string> challenges;
    int32_t ret = ClawTicketManager::GetInstance().GenerateCliTicket(tokenId, cliAuthInfos, challenges);

    EXPECT_EQ(RET_SUCCESS, ret);
    if (ret == RET_SUCCESS) {
        EXPECT_EQ(1, challenges.size());
        testChallenges_.push_back(challenges[0]);
    }

    DeleteTestHapToken(tokenId);
}

/**
 * @tc.name: GenerateCliTicketTest006
 * @tc.desc: Test GenerateCliTicket with special characters
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(ClawTicketManagerTest, GenerateCliTicketTest006, TestSize.Level0)
{
    AccessTokenID tokenId = CreateTestHapToken();
    ASSERT_NE(INVALID_TOKENID, tokenId);

    std::string specialCliName = GenerateSpecialString();
    std::vector<CliAuthInfo> cliAuthInfos;
    cliAuthInfos.push_back(CreateTestCliAuth(specialCliName,
        {"ohos.permission.CAMERA", "ohos.permission.MICROPHONE"},
        {true, false}));

    std::vector<std::string> challenges;
    int32_t ret = ClawTicketManager::GetInstance().GenerateCliTicket(tokenId, cliAuthInfos, challenges);

    EXPECT_EQ(RET_SUCCESS, ret);
    EXPECT_EQ(1, challenges.size());
    EXPECT_FALSE(challenges[0].empty());
    testChallenges_.push_back(challenges[0]);

    DeleteTestHapToken(tokenId);
}

/**
 * @tc.name: GenerateCliTicketTest007
 * @tc.desc: Test GenerateCliTicket with empty permissionNames
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(ClawTicketManagerTest, GenerateCliTicketTest007, TestSize.Level0)
{
    AccessTokenID tokenId = CreateTestHapToken();
    ASSERT_NE(INVALID_TOKENID, tokenId);

    std::vector<CliAuthInfo> cliAuthInfos;
    cliAuthInfos.push_back(CreateTestCliAuth("test_cli", {}, {}));

    std::vector<std::string> challenges;
    int32_t ret = ClawTicketManager::GetInstance().GenerateCliTicket(tokenId, cliAuthInfos, challenges);

    EXPECT_EQ(RET_SUCCESS, ret);
    EXPECT_EQ(1, challenges.size());
    testChallenges_.push_back(challenges[0]);

    DeleteTestHapToken(tokenId);
}

/**
 * @tc.name: GenerateCliTicketTest008
 * @tc.desc: Test GenerateCliTicket with empty permissionStatus
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(ClawTicketManagerTest, GenerateCliTicketTest008, TestSize.Level0)
{
    AccessTokenID tokenId = CreateTestHapToken();
    ASSERT_NE(INVALID_TOKENID, tokenId);

    std::vector<CliAuthInfo> cliAuthInfos;
    cliAuthInfos.push_back(CreateTestCliAuth("test_cli",
        {"ohos.permission.CAMERA", "ohos.permission.MICROPHONE"}, {}));

    std::vector<std::string> challenges;
    int32_t ret = ClawTicketManager::GetInstance().GenerateCliTicket(tokenId, cliAuthInfos, challenges);

    EXPECT_EQ(RET_SUCCESS, ret);
    EXPECT_EQ(1, challenges.size());
    testChallenges_.push_back(challenges[0]);

    DeleteTestHapToken(tokenId);
}

/**
 * @tc.name: GenerateCliTicketTest009
 * @tc.desc: Test GenerateCliTicket concurrent safety
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(ClawTicketManagerTest, GenerateCliTicketTest009, TestSize.Level0)
{
    AccessTokenID tokenId = CreateTestHapToken();
    ASSERT_NE(INVALID_TOKENID, tokenId);

    std::vector<CliAuthInfo> cliAuthInfos;
    cliAuthInfos.push_back(CreateTestCliAuth("test_cli",
        {"ohos.permission.CAMERA"}, {true}));

    constexpr int32_t threadCount = 10;
    std::vector<std::thread> threads;
    std::vector<int32_t> results(threadCount, -1);
    std::vector<std::vector<std::string>> allChallenges(threadCount);

    for (int32_t i = 0; i < threadCount; ++i) {
        threads.emplace_back([tokenId, &cliAuthInfos, &results, &allChallenges, i]() {
            results[i] = ClawTicketManager::GetInstance().GenerateCliTicket(
                tokenId, cliAuthInfos, allChallenges[i]);
        });
    }

    for (auto& thread : threads) {
        thread.join();
    }

    for (int32_t i = 0; i < threadCount; ++i) {
        EXPECT_EQ(RET_SUCCESS, results[i]);
        EXPECT_EQ(1, allChallenges[i].size());
        EXPECT_FALSE(allChallenges[i][0].empty());
        testChallenges_.push_back(allChallenges[i][0]);
    }

    DeleteTestHapToken(tokenId);
}

// ==================== GenerateSkillTicket Test Cases ====================

/**
 * @tc.name: GenerateSkillTicketTest001
 * @tc.desc: Test GenerateSkillTicket with valid input
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(ClawTicketManagerTest, GenerateSkillTicketTest001, TestSize.Level0)
{
    AccessTokenID tokenId = CreateTestHapToken();
    ASSERT_NE(INVALID_TOKENID, tokenId);

    std::vector<SkillAuthInfo> skillAuthInfos;
    skillAuthInfos.push_back(CreateTestSkillAuth("com.test.bundle",
        {"ohos.permission.CAMERA", "ohos.permission.MICROPHONE"},
        {true, false}));

    std::vector<std::string> challenges;
    int32_t ret = ClawTicketManager::GetInstance().GenerateSkillTicket(tokenId, skillAuthInfos, challenges);

    EXPECT_EQ(RET_SUCCESS, ret);
    EXPECT_EQ(1, challenges.size());
    EXPECT_FALSE(challenges[0].empty());
    testChallenges_.push_back(challenges[0]);

    DeleteTestHapToken(tokenId);
}

/**
 * @tc.name: GenerateSkillTicketTest002
 * @tc.desc: Test GenerateSkillTicket with multiple SkillAuthInfo
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(ClawTicketManagerTest, GenerateSkillTicketTest002, TestSize.Level0)
{
    AccessTokenID tokenId = CreateTestHapToken();
    ASSERT_NE(INVALID_TOKENID, tokenId);

    std::vector<SkillAuthInfo> skillAuthInfos;
    skillAuthInfos.push_back(CreateTestSkillAuth("com.test.bundle1",
        {"ohos.permission.CAMERA"}, {true}));
    skillAuthInfos.push_back(CreateTestSkillAuth("com.test.bundle2",
        {"ohos.permission.MICROPHONE"}, {false}));
    skillAuthInfos.push_back(CreateTestSkillAuth("com.test.bundle3",
        {"ohos.permission.READ_CONTACTS"}, {true}));

    std::vector<std::string> challenges;
    int32_t ret = ClawTicketManager::GetInstance().GenerateSkillTicket(tokenId, skillAuthInfos, challenges);

    EXPECT_EQ(RET_SUCCESS, ret);
    EXPECT_EQ(3, challenges.size());
    for (const auto& challenge : challenges) {
        EXPECT_FALSE(challenge.empty());
        testChallenges_.push_back(challenge);
    }

    DeleteTestHapToken(tokenId);
}

/**
 * @tc.name: GenerateSkillTicketTest003
 * @tc.desc: Test GenerateSkillTicket with invalid tokenId
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(ClawTicketManagerTest, GenerateSkillTicketTest003, TestSize.Level0)
{
    std::vector<SkillAuthInfo> skillAuthInfos;
    skillAuthInfos.push_back(CreateTestSkillAuth("com.test.bundle",
        {"ohos.permission.CAMERA"}, {true}));

    std::vector<std::string> challenges;
    int32_t ret = ClawTicketManager::GetInstance().GenerateSkillTicket(INVALID_TOKENID, skillAuthInfos, challenges);

    EXPECT_EQ(AccessTokenError::ERR_TOKENID_NOT_EXIST, ret);
    EXPECT_TRUE(challenges.empty());
}

/**
 * @tc.name: GenerateSkillTicketTest004
 * @tc.desc: Test GenerateSkillTicket when BatchGenerateTicket returns failure
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(ClawTicketManagerTest, GenerateSkillTicketTest004, TestSize.Level0)
{
    AccessTokenID tokenId = CreateTestHapToken();
    ASSERT_NE(INVALID_TOKENID, tokenId);

    SetBatchGenerateTicketMock(MockBatchGenerateTicketFailed);

    std::vector<SkillAuthInfo> skillAuthInfos;
    skillAuthInfos.push_back(CreateTestSkillAuth("com.test.bundle",
        {"ohos.permission.CAMERA"}, {true}));

    std::vector<std::string> challenges;
    int32_t ret = ClawTicketManager::GetInstance().GenerateSkillTicket(tokenId, skillAuthInfos, challenges);

    EXPECT_EQ(RET_FAILED, ret);
    EXPECT_TRUE(challenges.empty());

    ClearBatchMocks();
    DeleteTestHapToken(tokenId);
}

/**
 * @tc.name: GenerateSkillTicketTest005
 * @tc.desc: Test GenerateSkillTicket with oversized strings
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(ClawTicketManagerTest, GenerateSkillTicketTest005, TestSize.Level0)
{
    AccessTokenID tokenId = CreateTestHapToken();
    ASSERT_NE(INVALID_TOKENID, tokenId);

    std::string longBundleName = GenerateLongString(LONG_STRING_SIZE);
    std::vector<SkillAuthInfo> skillAuthInfos;
    skillAuthInfos.push_back(CreateTestSkillAuth(longBundleName,
        {"ohos.permission.CAMERA"}, {true}));

    std::vector<std::string> challenges;
    int32_t ret = ClawTicketManager::GetInstance().GenerateSkillTicket(tokenId, skillAuthInfos, challenges);

    EXPECT_EQ(RET_SUCCESS, ret);
    if (ret == RET_SUCCESS) {
        EXPECT_EQ(1, challenges.size());
        testChallenges_.push_back(challenges[0]);
    }

    DeleteTestHapToken(tokenId);
}

/**
 * @tc.name: GenerateSkillTicketTest006
 * @tc.desc: Test GenerateSkillTicket with special characters
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(ClawTicketManagerTest, GenerateSkillTicketTest006, TestSize.Level0)
{
    AccessTokenID tokenId = CreateTestHapToken();
    ASSERT_NE(INVALID_TOKENID, tokenId);

    std::string specialBundleName = GenerateSpecialString();
    std::vector<SkillAuthInfo> skillAuthInfos;
    skillAuthInfos.push_back(CreateTestSkillAuth(specialBundleName,
        {"ohos.permission.CAMERA", "ohos.permission.MICROPHONE"},
        {true, false}));

    std::vector<std::string> challenges;
    int32_t ret = ClawTicketManager::GetInstance().GenerateSkillTicket(tokenId, skillAuthInfos, challenges);

    EXPECT_EQ(RET_SUCCESS, ret);
    EXPECT_EQ(1, challenges.size());
    EXPECT_FALSE(challenges[0].empty());
    testChallenges_.push_back(challenges[0]);

    DeleteTestHapToken(tokenId);
}

/**
 * @tc.name: GenerateSkillTicketTest007
 * @tc.desc: Test GenerateSkillTicket with empty permissionNames
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(ClawTicketManagerTest, GenerateSkillTicketTest007, TestSize.Level0)
{
    AccessTokenID tokenId = CreateTestHapToken();
    ASSERT_NE(INVALID_TOKENID, tokenId);

    std::vector<SkillAuthInfo> skillAuthInfos;
    skillAuthInfos.push_back(CreateTestSkillAuth("com.test.bundle", {}, {}));

    std::vector<std::string> challenges;
    int32_t ret = ClawTicketManager::GetInstance().GenerateSkillTicket(tokenId, skillAuthInfos, challenges);

    EXPECT_EQ(RET_SUCCESS, ret);
    EXPECT_EQ(1, challenges.size());
    testChallenges_.push_back(challenges[0]);

    DeleteTestHapToken(tokenId);
}

/**
 * @tc.name: GenerateSkillTicketTest008
 * @tc.desc: Test GenerateSkillTicket with empty permissionStatus
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(ClawTicketManagerTest, GenerateSkillTicketTest008, TestSize.Level0)
{
    AccessTokenID tokenId = CreateTestHapToken();
    ASSERT_NE(INVALID_TOKENID, tokenId);

    std::vector<SkillAuthInfo> skillAuthInfos;
    skillAuthInfos.push_back(CreateTestSkillAuth("com.test.bundle",
        {"ohos.permission.CAMERA", "ohos.permission.MICROPHONE"}, {}));

    std::vector<std::string> challenges;
    int32_t ret = ClawTicketManager::GetInstance().GenerateSkillTicket(tokenId, skillAuthInfos, challenges);

    EXPECT_EQ(RET_SUCCESS, ret);
    EXPECT_EQ(1, challenges.size());
    testChallenges_.push_back(challenges[0]);

    DeleteTestHapToken(tokenId);
}

// ==================== VerifyCliClawTicket Test Cases ====================

/**
 * @tc.name: VerifyCliClawTicketTest001
 * @tc.desc: Test VerifyCliClawTicket with valid challenge
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(ClawTicketManagerTest, VerifyCliClawTicketTest001, TestSize.Level0)
{
    AccessTokenID tokenId = CreateTestHapToken();
    ASSERT_NE(INVALID_TOKENID, tokenId);

    std::string challenge = GenerateTestCliTicket(tokenId);
    ASSERT_FALSE(challenge.empty());

    CliInfo cliInfo = {{"test_cli", "test_sub"}};
    std::vector<PermissionStatus> permList;
    int32_t ret = ClawTicketManager::GetInstance().VerifyCliClawTicket(tokenId, challenge, cliInfo, permList);

    EXPECT_EQ(RET_SUCCESS, ret);
    EXPECT_FALSE(permList.empty());

    DeleteTestHapToken(tokenId);
}

/**
 * @tc.name: VerifyCliClawTicketTest002
 * @tc.desc: Test VerifyCliClawTicket with non-existent challenge
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(ClawTicketManagerTest, VerifyCliClawTicketTest002, TestSize.Level0)
{
    AccessTokenID tokenId = CreateTestHapToken();
    ASSERT_NE(INVALID_TOKENID, tokenId);

    std::string challenge = "non_existent_challenge";
    CliInfo cliInfo = {{"test_cli", "test_sub"}};
    std::vector<PermissionStatus> permList;
    int32_t ret = ClawTicketManager::GetInstance().VerifyCliClawTicket(tokenId, challenge, cliInfo, permList);

    EXPECT_EQ(AccessTokenError::ERR_PARAM_INVALID, ret);
    EXPECT_TRUE(permList.empty());

    DeleteTestHapToken(tokenId);
}

/**
 * @tc.name: VerifyCliClawTicketTest003
 * @tc.desc: Test VerifyCliClawTicket when GetHapTokenInfoInner returns nullptr
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(ClawTicketManagerTest, VerifyCliClawTicketTest003, TestSize.Level0)
{
    AccessTokenID tokenId = CreateTestHapToken();
    ASSERT_NE(INVALID_TOKENID, tokenId);

    std::string challenge = GenerateTestCliTicket(tokenId);
    ASSERT_FALSE(challenge.empty());

    AccessTokenInfoManager::GetInstance().hapTokenInfoMap_.erase(tokenId);

    CliInfo cliInfo = {{"test_cli", "test_sub"}};
    std::vector<PermissionStatus> permList;
    int32_t ret = ClawTicketManager::GetInstance().VerifyCliClawTicket(tokenId, challenge, cliInfo, permList);

    EXPECT_EQ(AccessTokenError::ERR_TOKENID_NOT_EXIST, ret);
    EXPECT_TRUE(permList.empty());

    DeleteTestHapToken(tokenId);
}

/**
 * @tc.name: VerifyCliClawTicketTest004
 * @tc.desc: Test VerifyCliClawTicket when BatchVerifyTicket returns failure
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(ClawTicketManagerTest, VerifyCliClawTicketTest004, TestSize.Level0)
{
    AccessTokenID tokenId = CreateTestHapToken();
    ASSERT_NE(INVALID_TOKENID, tokenId);

    std::string challenge = GenerateTestCliTicket(tokenId);
    ASSERT_FALSE(challenge.empty());

    SetBatchVerifyTicketMock(MockBatchVerifyTicketFailed);

    CliInfo cliInfo = {{"test_cli", "test_sub"}};
    std::vector<PermissionStatus> permList;
    int32_t ret = ClawTicketManager::GetInstance().VerifyCliClawTicket(tokenId, challenge, cliInfo, permList);

    EXPECT_EQ(RET_FAILED, ret);

    ClearBatchMocks();
    DeleteTestHapToken(tokenId);
}

/**
 * @tc.name: VerifyCliClawTicketTest005
 * @tc.desc: Test VerifyCliClawTicket with all permissions granted
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(ClawTicketManagerTest, VerifyCliClawTicketTest005, TestSize.Level0)
{
    AccessTokenID tokenId = CreateTestHapToken();
    ASSERT_NE(INVALID_TOKENID, tokenId);

    std::string challenge = GenerateTestCliTicket(tokenId);
    ASSERT_FALSE(challenge.empty());

    SetBatchVerifyTicketMock(MockBatchVerifyTicketAllGranted);

    CliInfo cliInfo = {{"test_cli", "test_sub"}};
    std::vector<PermissionStatus> permList;
    int32_t ret = ClawTicketManager::GetInstance().VerifyCliClawTicket(tokenId, challenge, cliInfo, permList);

    EXPECT_EQ(RET_SUCCESS, ret);
    EXPECT_EQ(2, permList.size());
    EXPECT_EQ(PERMISSION_GRANTED, permList[0].grantStatus);
    EXPECT_EQ(PERMISSION_DENIED, permList[1].grantStatus);

    ClearBatchMocks();
    DeleteTestHapToken(tokenId);
}

/**
 * @tc.name: VerifyCliClawTicketTest006
 * @tc.desc: Test VerifyCliClawTicket with all permissions denied
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(ClawTicketManagerTest, VerifyCliClawTicketTest006, TestSize.Level0)
{
    AccessTokenID tokenId = CreateTestHapToken();
    ASSERT_NE(INVALID_TOKENID, tokenId);

    std::string challenge = GenerateTestCliTicket(tokenId);
    ASSERT_FALSE(challenge.empty());

    SetBatchVerifyTicketMock(MockBatchVerifyTicketAllDenied);

    CliInfo cliInfo = {{"test_cli", "test_sub"}};
    std::vector<PermissionStatus> permList;
    int32_t ret = ClawTicketManager::GetInstance().VerifyCliClawTicket(tokenId, challenge, cliInfo, permList);

    EXPECT_EQ(RET_SUCCESS, ret);
    EXPECT_EQ(2, permList.size());
    EXPECT_EQ(PERMISSION_DENIED, permList[0].grantStatus);
    EXPECT_EQ(PERMISSION_DENIED, permList[1].grantStatus);

    ClearBatchMocks();
    DeleteTestHapToken(tokenId);
}

/**
 * @tc.name: VerifyCliClawTicketTest007
 * @tc.desc: Test VerifyCliClawTicket with mixed permission states
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(ClawTicketManagerTest, VerifyCliClawTicketTest007, TestSize.Level0)
{
    AccessTokenID tokenId = CreateTestHapToken();
    ASSERT_NE(INVALID_TOKENID, tokenId);

    std::string challenge = GenerateTestCliTicket(tokenId);
    ASSERT_FALSE(challenge.empty());

    SetBatchVerifyTicketMock(MockBatchVerifyTicketMixed);

    CliInfo cliInfo = {{"test_cli", "test_sub"}};
    std::vector<PermissionStatus> permList;
    int32_t ret = ClawTicketManager::GetInstance().VerifyCliClawTicket(tokenId, challenge, cliInfo, permList);

    EXPECT_EQ(RET_SUCCESS, ret);
    EXPECT_EQ(3, permList.size());
    EXPECT_EQ(PERMISSION_GRANTED, permList[0].grantStatus);
    EXPECT_EQ(PERMISSION_DENIED, permList[1].grantStatus);
    EXPECT_EQ(PERMISSION_GRANTED, permList[2].grantStatus);

    ClearBatchMocks();
    DeleteTestHapToken(tokenId);
}

/**
 * @tc.name: VerifyCliClawTicketTest008
 * @tc.desc: Test VerifyCliClawTicket with empty challenge
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(ClawTicketManagerTest, VerifyCliClawTicketTest008, TestSize.Level0)
{
    AccessTokenID tokenId = CreateTestHapToken();
    ASSERT_NE(INVALID_TOKENID, tokenId);

    std::string challenge = "";
    CliInfo cliInfo = {{"test_cli", "test_sub"}};
    std::vector<PermissionStatus> permList;
    int32_t ret = ClawTicketManager::GetInstance().VerifyCliClawTicket(tokenId, challenge, cliInfo, permList);

    EXPECT_EQ(AccessTokenError::ERR_PARAM_INVALID, ret);
    EXPECT_TRUE(permList.empty());

    DeleteTestHapToken(tokenId);
}

/**
 * @tc.name: VerifyCliClawTicketTest009
 * @tc.desc: Test VerifyCliClawTicket with normal JSON deserialization
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(ClawTicketManagerTest, VerifyCliClawTicketTest009, TestSize.Level0)
{
    AccessTokenID tokenId = CreateTestHapToken();
    ASSERT_NE(INVALID_TOKENID, tokenId);

    std::string challenge = GenerateTestCliTicket(tokenId);
    ASSERT_FALSE(challenge.empty());

    CliInfo cliInfo = {{"test_cli", "test_sub"}};
    std::vector<PermissionStatus> permList;
    int32_t ret = ClawTicketManager::GetInstance().VerifyCliClawTicket(tokenId, challenge, cliInfo, permList);

    EXPECT_EQ(RET_SUCCESS, ret);
    EXPECT_FALSE(permList.empty());
    EXPECT_EQ("ohos.permission.CAMERA", permList[0].permissionName);
    EXPECT_EQ("ohos.permission.MICROPHONE", permList[1].permissionName);

    DeleteTestHapToken(tokenId);
}

/**
 * @tc.name: VerifyCliClawTicketTest010
 * @tc.desc: Test VerifyCliClawTicket with oversized JSON
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(ClawTicketManagerTest, VerifyCliClawTicketTest010, TestSize.Level0)
{
    AccessTokenID tokenId = CreateTestHapToken();
    ASSERT_NE(INVALID_TOKENID, tokenId);

    std::string longCliName = GenerateLongString(LONG_STRING_SIZE);
    std::vector<CliAuthInfo> cliAuthInfos;
    cliAuthInfos.push_back(CreateTestCliAuth(longCliName,
        {"ohos.permission.CAMERA"}, {true}));

    std::vector<std::string> challenges;
    int32_t genRet = ClawTicketManager::GetInstance().GenerateCliTicket(tokenId, cliAuthInfos, challenges);

    if (genRet == RET_SUCCESS && !challenges.empty()) {
        testChallenges_.push_back(challenges[0]);

        CliInfo cliInfo = {{"test_cli", "test_sub"}};
        std::vector<PermissionStatus> permList;
        int32_t ret = ClawTicketManager::GetInstance().VerifyCliClawTicket(tokenId, challenges[0], cliInfo, permList);

        EXPECT_EQ(RET_SUCCESS, ret);
    }

    DeleteTestHapToken(tokenId);
}

/**
 * @tc.name: VerifyCliClawTicketTest011
 * @tc.desc: Test VerifyCliClawTicket with special characters in JSON
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(ClawTicketManagerTest, VerifyCliClawTicketTest011, TestSize.Level0)
{
    AccessTokenID tokenId = CreateTestHapToken();
    ASSERT_NE(INVALID_TOKENID, tokenId);

    std::string specialCliName = GenerateSpecialString();
    std::vector<CliAuthInfo> cliAuthInfos;
    cliAuthInfos.push_back(CreateTestCliAuth(specialCliName,
        {"ohos.permission.CAMERA", "ohos.permission.MICROPHONE"},
        {true, false}));

    std::vector<std::string> challenges;
    ASSERT_EQ(RET_SUCCESS, ClawTicketManager::GetInstance().GenerateCliTicket(tokenId, cliAuthInfos, challenges));
    ASSERT_EQ(1, challenges.size());
    testChallenges_.push_back(challenges[0]);

    CliInfo cliInfo = {specialCliName, "test_sub"};
    std::vector<PermissionStatus> permList;
    int32_t ret = ClawTicketManager::GetInstance().VerifyCliClawTicket(tokenId, challenges[0], cliInfo, permList);

    EXPECT_EQ(RET_SUCCESS, ret);
    EXPECT_EQ(2, permList.size());

    DeleteTestHapToken(tokenId);
}

// ==================== VerifySkillClawTicket Test Cases ====================

/**
 * @tc.name: VerifySkillClawTicketTest001
 * @tc.desc: Test VerifySkillClawTicket with valid challenge
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(ClawTicketManagerTest, VerifySkillClawTicketTest001, TestSize.Level0)
{
    AccessTokenID tokenId = CreateTestHapToken();
    ASSERT_NE(INVALID_TOKENID, tokenId);

    std::string challenge = GenerateTestSkillTicket(tokenId);
    ASSERT_FALSE(challenge.empty());

    SkillInfo skillInfo = {"com.test.bundle", "test_module", "test_skill"};
    std::vector<PermissionStatus> permList;
    int32_t ret = ClawTicketManager::GetInstance().VerifySkillClawTicket(tokenId, challenge, skillInfo, permList);

    EXPECT_EQ(RET_SUCCESS, ret);
    EXPECT_FALSE(permList.empty());

    DeleteTestHapToken(tokenId);
}

/**
 * @tc.name: VerifySkillClawTicketTest002
 * @tc.desc: Test VerifySkillClawTicket with non-existent challenge
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(ClawTicketManagerTest, VerifySkillClawTicketTest002, TestSize.Level0)
{
    AccessTokenID tokenId = CreateTestHapToken();
    ASSERT_NE(INVALID_TOKENID, tokenId);

    std::string challenge = "non_existent_challenge";
    SkillInfo skillInfo = {"com.test.bundle", "test_module", "test_skill"};
    std::vector<PermissionStatus> permList;
    int32_t ret = ClawTicketManager::GetInstance().VerifySkillClawTicket(tokenId, challenge, skillInfo, permList);

    EXPECT_EQ(AccessTokenError::ERR_PARAM_INVALID, ret);
    EXPECT_TRUE(permList.empty());

    DeleteTestHapToken(tokenId);
}

/**
 * @tc.name: VerifySkillClawTicketTest003
 * @tc.desc: Test VerifySkillClawTicket when GetHapTokenInfoInner returns nullptr
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(ClawTicketManagerTest, VerifySkillClawTicketTest003, TestSize.Level0)
{
    AccessTokenID tokenId = CreateTestHapToken();
    ASSERT_NE(INVALID_TOKENID, tokenId);

    std::string challenge = GenerateTestSkillTicket(tokenId);
    ASSERT_FALSE(challenge.empty());

    AccessTokenInfoManager::GetInstance().hapTokenInfoMap_.erase(tokenId);

    SkillInfo skillInfo = {"com.test.bundle", "test_module", "test_skill"};
    std::vector<PermissionStatus> permList;
    int32_t ret = ClawTicketManager::GetInstance().VerifySkillClawTicket(tokenId, challenge, skillInfo, permList);

    EXPECT_EQ(AccessTokenError::ERR_TOKENID_NOT_EXIST, ret);
    EXPECT_TRUE(permList.empty());

    DeleteTestHapToken(tokenId);
}

/**
 * @tc.name: VerifySkillClawTicketTest004
 * @tc.desc: Test VerifySkillClawTicket when BatchVerifyTicket returns failure
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(ClawTicketManagerTest, VerifySkillClawTicketTest004, TestSize.Level0)
{
    AccessTokenID tokenId = CreateTestHapToken();
    ASSERT_NE(INVALID_TOKENID, tokenId);

    std::string challenge = GenerateTestSkillTicket(tokenId);
    ASSERT_FALSE(challenge.empty());

    SetBatchVerifyTicketMock(MockBatchVerifyTicketFailed);

    SkillInfo skillInfo = {"com.test.bundle", "test_module", "test_skill"};
    std::vector<PermissionStatus> permList;
    int32_t ret = ClawTicketManager::GetInstance().VerifySkillClawTicket(tokenId, challenge, skillInfo, permList);

    EXPECT_EQ(RET_FAILED, ret);

    ClearBatchMocks();
    DeleteTestHapToken(tokenId);
}

/**
 * @tc.name: VerifySkillClawTicketTest005
 * @tc.desc: Test VerifySkillClawTicket with mixed permission states
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(ClawTicketManagerTest, VerifySkillClawTicketTest005, TestSize.Level0)
{
    AccessTokenID tokenId = CreateTestHapToken();
    ASSERT_NE(INVALID_TOKENID, tokenId);

    std::string challenge = GenerateTestSkillTicket(tokenId);
    ASSERT_FALSE(challenge.empty());

    SetBatchVerifyTicketMock(MockBatchVerifyTicketMixed);

    SkillInfo skillInfo = {"com.test.bundle", "test_module", "test_skill"};
    std::vector<PermissionStatus> permList;
    int32_t ret = ClawTicketManager::GetInstance().VerifySkillClawTicket(tokenId, challenge, skillInfo, permList);

    EXPECT_EQ(RET_SUCCESS, ret);
    EXPECT_EQ(3, permList.size());
    EXPECT_EQ(PERMISSION_GRANTED, permList[0].grantStatus);
    EXPECT_EQ(PERMISSION_DENIED, permList[1].grantStatus);
    EXPECT_EQ(PERMISSION_GRANTED, permList[2].grantStatus);

    ClearBatchMocks();
    DeleteTestHapToken(tokenId);
}

/**
 * @tc.name: VerifySkillClawTicketTest006
 * @tc.desc: Test VerifySkillClawTicket with empty challenge
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(ClawTicketManagerTest, VerifySkillClawTicketTest006, TestSize.Level0)
{
    AccessTokenID tokenId = CreateTestHapToken();
    ASSERT_NE(INVALID_TOKENID, tokenId);

    std::string challenge = "";
    SkillInfo skillInfo = {"com.test.bundle", "test_module", "test_skill"};
    std::vector<PermissionStatus> permList;
    int32_t ret = ClawTicketManager::GetInstance().VerifySkillClawTicket(tokenId, challenge, skillInfo, permList);

    EXPECT_EQ(AccessTokenError::ERR_PARAM_INVALID, ret);
    EXPECT_TRUE(permList.empty());

    DeleteTestHapToken(tokenId);
}

/**
 * @tc.name: VerifySkillClawTicketTest007
 * @tc.desc: Test VerifySkillClawTicket with normal JSON deserialization
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(ClawTicketManagerTest, VerifySkillClawTicketTest007, TestSize.Level0)
{
    AccessTokenID tokenId = CreateTestHapToken();
    ASSERT_NE(INVALID_TOKENID, tokenId);

    std::string challenge = GenerateTestSkillTicket(tokenId);
    ASSERT_FALSE(challenge.empty());

    SkillInfo skillInfo = {"com.test.bundle", "test_module", "test_skill"};
    std::vector<PermissionStatus> permList;
    int32_t ret = ClawTicketManager::GetInstance().VerifySkillClawTicket(tokenId, challenge, skillInfo, permList);

    EXPECT_EQ(RET_SUCCESS, ret);
    EXPECT_FALSE(permList.empty());
    EXPECT_EQ("ohos.permission.CAMERA", permList[0].permissionName);
    EXPECT_EQ("ohos.permission.MICROPHONE", permList[1].permissionName);

    DeleteTestHapToken(tokenId);
}

/**
 * @tc.name: VerifySkillClawTicketTest008
 * @tc.desc: Test VerifySkillClawTicket with oversized JSON
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(ClawTicketManagerTest, VerifySkillClawTicketTest008, TestSize.Level0)
{
    AccessTokenID tokenId = CreateTestHapToken();
    ASSERT_NE(INVALID_TOKENID, tokenId);

    std::string longBundleName = GenerateLongString(LONG_STRING_SIZE);
    std::vector<SkillAuthInfo> skillAuthInfos;
    skillAuthInfos.push_back(CreateTestSkillAuth(longBundleName,
        {"ohos.permission.CAMERA"}, {true}));

    std::vector<std::string> challenges;
    int32_t genRet = ClawTicketManager::GetInstance().GenerateSkillTicket(tokenId, skillAuthInfos, challenges);

    if (genRet == RET_SUCCESS && !challenges.empty()) {
        testChallenges_.push_back(challenges[0]);

        SkillInfo skillInfo = {longBundleName, "test_module", "test_skill"};
        std::vector<PermissionStatus> permList;
        int32_t ret = ClawTicketManager::GetInstance().VerifySkillClawTicket(tokenId, challenges[0], skillInfo,
            permList);

        EXPECT_EQ(RET_SUCCESS, ret);
    }

    DeleteTestHapToken(tokenId);
}

// ==================== DeleteClawTicket Test Cases ====================

/**
 * @tc.name: DeleteClawTicketTest001
 * @tc.desc: Test DeleteClawTicket with valid challenge
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(ClawTicketManagerTest, DeleteClawTicketTest001, TestSize.Level0)
{
    AccessTokenID tokenId = CreateTestHapToken();
    ASSERT_NE(INVALID_TOKENID, tokenId);

    std::string challenge = GenerateTestCliTicket(tokenId);
    ASSERT_FALSE(challenge.empty());

    int32_t ret = ClawTicketManager::GetInstance().DeleteClawTicket(challenge);
    EXPECT_EQ(RET_SUCCESS, ret);

    std::vector<PermissionStatus> permList;
    CliInfo cliInfo = {{"test_cli", "test_sub"}};
    ret = ClawTicketManager::GetInstance().VerifyCliClawTicket(tokenId, challenge, cliInfo, permList);
    EXPECT_EQ(AccessTokenError::ERR_PARAM_INVALID, ret);

    testChallenges_.clear();
    DeleteTestHapToken(tokenId);
}

/**
 * @tc.name: DeleteClawTicketTest002
 * @tc.desc: Test DeleteClawTicket with non-existent challenge
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(ClawTicketManagerTest, DeleteClawTicketTest002, TestSize.Level0)
{
    AccessTokenID tokenId = CreateTestHapToken();
    ASSERT_NE(INVALID_TOKENID, tokenId);

    int32_t ret = ClawTicketManager::GetInstance().DeleteClawTicket("non_existent_challenge");
    EXPECT_EQ(AccessTokenError::ERR_PARAM_INVALID, ret);

    DeleteTestHapToken(tokenId);
}

/**
 * @tc.name: DeleteClawTicketTest003
 * @tc.desc: Test DeleteClawTicket with empty challenge
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(ClawTicketManagerTest, DeleteClawTicketTest003, TestSize.Level0)
{
    AccessTokenID tokenId = CreateTestHapToken();
    ASSERT_NE(INVALID_TOKENID, tokenId);

    int32_t ret = ClawTicketManager::GetInstance().DeleteClawTicket("");
    EXPECT_EQ(AccessTokenError::ERR_PARAM_INVALID, ret);

    DeleteTestHapToken(tokenId);
}

// ==================== DeleteClawTicketByCallerTokenId Test Cases ====================

/**
 * @tc.name: DeleteClawTicketByTokenIdTest001
 * @tc.desc: Test DeleteClawTicketByCallerTokenId with multiple tickets
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(ClawTicketManagerTest, DeleteClawTicketByTokenIdTest001, TestSize.Level0)
{
    AccessTokenID tokenId = CreateTestHapToken();
    ASSERT_NE(INVALID_TOKENID, tokenId);

    std::vector<std::string> challenges;
    for (int32_t i = 0; i < 3; ++i) {
        std::vector<CliAuthInfo> cliAuthInfos;
        cliAuthInfos.push_back(CreateTestCliAuth("test_cli" + std::to_string(i),
            {"ohos.permission.CAMERA"}, {true}));
        std::vector<std::string> tmpChallenges;
        ASSERT_EQ(RET_SUCCESS, ClawTicketManager::GetInstance().GenerateCliTicket(
            tokenId, cliAuthInfos, tmpChallenges));
        challenges.push_back(tmpChallenges[0]);
        testChallenges_.push_back(tmpChallenges[0]);
    }

    ClawTicketManager::GetInstance().DeleteClawTicketByCallerTokenId(tokenId);
    testChallenges_.clear();

    for (const auto& challenge : challenges) {
        std::vector<PermissionStatus> permList;
        CliInfo cliInfo = {{"test_cli", "test_sub"}};
        int32_t ret = ClawTicketManager::GetInstance().VerifyCliClawTicket(tokenId, challenge, cliInfo, permList);
        EXPECT_EQ(RET_FAILED, ret);
    }

    DeleteTestHapToken(tokenId);
}

/**
 * @tc.name: DeleteClawTicketByTokenIdTest002
 * @tc.desc: Test DeleteClawTicketByCallerTokenId when token has no tickets
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(ClawTicketManagerTest, DeleteClawTicketByTokenIdTest002, TestSize.Level0)
{
    AccessTokenID tokenId = CreateTestHapToken();
    ASSERT_NE(INVALID_TOKENID, tokenId);

    ClawTicketManager::GetInstance().DeleteClawTicketByCallerTokenId(tokenId);

    DeleteTestHapToken(tokenId);
}

/**
 * @tc.name: DeleteClawTicketByTokenIdTest003
 * @tc.desc: Test DeleteClawTicketByCallerTokenId with delete and verify
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(ClawTicketManagerTest, DeleteClawTicketByTokenIdTest003, TestSize.Level0)
{
    AccessTokenID tokenId = CreateTestHapToken();
    ASSERT_NE(INVALID_TOKENID, tokenId);

    std::string challenge = GenerateTestCliTicket(tokenId);
    ASSERT_FALSE(challenge.empty());

    ClawTicketManager::GetInstance().DeleteClawTicketByCallerTokenId(tokenId);
    testChallenges_.clear();

    std::vector<PermissionStatus> permList;
    CliInfo cliInfo = {{"test_cli", "test_sub"}};
    int32_t ret = ClawTicketManager::GetInstance().VerifyCliClawTicket(tokenId, challenge, cliInfo, permList);
    EXPECT_EQ(RET_FAILED, ret);

    DeleteTestHapToken(tokenId);
}

// ==================== OnAppStopped Callback Test Cases ====================

/**
 * @tc.name: OnAppStoppedTest001
 * @tc.desc: Test OnAppStopped cleans up tickets when app terminates
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(ClawTicketManagerTest, OnAppStoppedTest001, TestSize.Level0)
{
    AccessTokenID tokenId = CreateTestHapToken();
    ASSERT_NE(INVALID_TOKENID, tokenId);

    std::string challenge = GenerateTestCliTicket(tokenId);
    ASSERT_FALSE(challenge.empty());

    AppStateData appStateData;
    appStateData.accessTokenId = tokenId;
    appStateData.state = static_cast<int32_t>(ApplicationState::APP_STATE_TERMINATED);

    ClawTicketAppStateObserver observer;
    observer.OnAppStopped(appStateData);

    std::vector<PermissionStatus> permList;
    CliInfo cliInfo = {{"test_cli", "test_sub"}};
    int32_t ret = ClawTicketManager::GetInstance().VerifyCliClawTicket(tokenId, challenge, cliInfo, permList);
    EXPECT_EQ(RET_FAILED, ret);

    testChallenges_.clear();
    DeleteTestHapToken(tokenId);
}

/**
 * @tc.name: OnAppStoppedTest002
 * @tc.desc: Test OnAppStopped does not affect other apps' tickets
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(ClawTicketManagerTest, OnAppStoppedTest002, TestSize.Level0)
{
    AccessTokenID tokenId1 = CreateTestHapToken();
    AccessTokenID tokenId2 = CreateTestHapToken();
    ASSERT_NE(INVALID_TOKENID, tokenId1);
    ASSERT_NE(INVALID_TOKENID, tokenId2);

    std::string challenge1 = GenerateTestCliTicket(tokenId1);
    std::string challenge2 = GenerateTestCliTicket(tokenId2);
    ASSERT_FALSE(challenge1.empty());
    ASSERT_FALSE(challenge2.empty());

    AppStateData appStateData;
    appStateData.accessTokenId = tokenId1;
    appStateData.state = static_cast<int32_t>(ApplicationState::APP_STATE_TERMINATED);

    ClawTicketAppStateObserver observer;
    observer.OnAppStopped(appStateData);

    std::vector<PermissionStatus> permList;
    CliInfo cliInfo = {{"test_cli", "test_sub"}};
    int32_t ret = ClawTicketManager::GetInstance().VerifyCliClawTicket(tokenId1, challenge1, cliInfo, permList);
    EXPECT_EQ(RET_FAILED, ret);

    ret = ClawTicketManager::GetInstance().VerifyCliClawTicket(tokenId2, challenge2, cliInfo, permList);
    EXPECT_EQ(RET_SUCCESS, ret);

    testChallenges_.clear();
    DeleteTestHapToken(tokenId1);
    DeleteTestHapToken(tokenId2);
}

/**
 * @tc.name: OnAppStoppedTest003
 * @tc.desc: Test OnAppStopped does not clean up tickets for non-terminated state
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(ClawTicketManagerTest, OnAppStoppedTest003, TestSize.Level0)
{
    AccessTokenID tokenId = CreateTestHapToken();
    ASSERT_NE(INVALID_TOKENID, tokenId);

    std::string challenge = GenerateTestCliTicket(tokenId);
    ASSERT_FALSE(challenge.empty());

    AppStateData appStateData;
    appStateData.accessTokenId = tokenId;
    appStateData.state = static_cast<int32_t>(ApplicationState::APP_STATE_BACKGROUND);

    ClawTicketAppStateObserver observer;
    observer.OnAppStopped(appStateData);

    std::vector<PermissionStatus> permList;
    CliInfo cliInfo = {{"test_cli", "test_sub"}};
    int32_t ret = ClawTicketManager::GetInstance().VerifyCliClawTicket(tokenId, challenge, cliInfo, permList);
    EXPECT_EQ(RET_SUCCESS, ret);

    testChallenges_.clear();
    DeleteTestHapToken(tokenId);
}

/**
 * @tc.name: OnAppStoppedTest004
 * @tc.desc: Test OnAppStopped with invalid AppStateData
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(ClawTicketManagerTest, OnAppStoppedTest004, TestSize.Level0)
{
    AccessTokenID tokenId = CreateTestHapToken();
    ASSERT_NE(INVALID_TOKENID, tokenId);

    std::string challenge = GenerateTestCliTicket(tokenId);
    ASSERT_FALSE(challenge.empty());

    AppStateData appStateData;
    appStateData.accessTokenId = INVALID_TOKENID;
    appStateData.state = static_cast<int32_t>(ApplicationState::APP_STATE_TERMINATED);

    ClawTicketAppStateObserver observer;
    observer.OnAppStopped(appStateData);

    std::vector<PermissionStatus> permList;
    CliInfo cliInfo = {{"test_cli", "test_sub"}};
    int32_t ret = ClawTicketManager::GetInstance().VerifyCliClawTicket(tokenId, challenge, cliInfo, permList);
    EXPECT_EQ(RET_SUCCESS, ret);

    testChallenges_.clear();
    DeleteTestHapToken(tokenId);
}
} // namespace AccessToken
} // namespace Security
} // namespace OHOS