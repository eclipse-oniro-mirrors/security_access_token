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
#include <string>

#include "access_token_error.h"
#include "accesstoken_common_log.h"
#include "accesstoken_info_manager.h"
#include "claw_permission_status_helper.h"
#include "cjson_utils.h"
#include "saf_agent_fence.h"
#ifdef SAF_AGENT_FENCE_ENABLE
#include "saf_result_code.h"
#endif

namespace OHOS {
namespace Security {
namespace AccessToken {

using namespace testing::ext;

namespace {
static constexpr int32_t TEST_USER_ID = 100;
static constexpr int32_t TEST_INST_INDEX = 0;
static constexpr size_t LONG_STRING_SIZE = 4096;

std::string GenerateLongString(size_t len)
{
    return std::string(len, 'a');
}

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

void InsertTestTicket(AccessTokenID callerTokenId, const std::string& challenge, const CliAuthInfo& cliAuth)
{
    CJsonUnique cliObj = CreateJson();
    if (cliObj == nullptr) {
        return;
    }
    CJsonUnique cliInfoObj = CreateJson();
    if (cliInfoObj == nullptr) {
        return;
    }
    (void)AddStringToJson(cliInfoObj, "cliName", cliAuth.cliInfo.cliName);
    (void)AddStringToJson(cliInfoObj, "subCliName", cliAuth.cliInfo.subCliName);
    (void)AddObjToJson(cliObj, "cliInfo", cliInfoObj);

    CJsonUnique permNamesArr = CreateJsonArray();
    if (permNamesArr != nullptr) {
        for (const auto& permName : cliAuth.permissionNames) {
            (void)AddStringToArray(permNamesArr, permName);
        }
        (void)AddObjToJson(cliObj, "permissionNames", permNamesArr);
    }

    CJsonUnique permStatusArr = CreateJsonArray();
    if (permStatusArr != nullptr) {
        for (bool status : cliAuth.authorizationResults) {
            (void)AddStringToArray(permStatusArr, status ? "true" : "false");
        }
        (void)AddObjToJson(cliObj, "authorizationResults", permStatusArr);
    }

    ClawTicket ticket;
    ticket.callerTokenId = callerTokenId;
    ticket.message = PackJsonToString(cliObj);
    ticket.ticket = "test_ticket";
    ClawTicketManager::GetInstance().ticketMap_[challenge] = ticket;
}

std::string ExtractChallenge(const std::string& authResult)
{
    CJsonUnique json = CreateJsonFromString(authResult);
    if (json == nullptr) {
        return authResult;
    }
    std::string challenge;
    GetStringFromJson(json.get(), "challenge", challenge);
    return challenge.empty() ? authResult : challenge;
}

PermissionStatus GetPermissionStatus(const std::vector<PermissionStatus>& permList, const std::string& permName)
{
    for (const auto& status : permList) {
        if (status.permissionName == permName) {
            return status;
        }
    }
    return {0, "", "", PERMISSION_DENIED, 0};
}
} // anonymous namespace

void ClawTicketManagerTest::SetUpTestCase() {}

void ClawTicketManagerTest::TearDownTestCase() {}

void ClawTicketManagerTest::SetUp()
{
    ResetMockCounter();
    auto atManagerService = DelayedSingleton<AccessTokenManagerService>::GetInstance();
    ASSERT_NE(nullptr, atManagerService);
    testTokenId_ = CreateTestHapToken();
}

void ClawTicketManagerTest::TearDown()
{
    for (const auto& challenge : testChallenges_) {
        ClawTicketManager::GetInstance().DeleteClawTicket(challenge);
    }
    testChallenges_.clear();
    {
        std::unique_lock<std::shared_mutex> lock(ClawTicketManager::GetInstance().multiLock_);
        ClawTicketManager::GetInstance().ticketMap_.clear();
    }

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

    std::vector<std::string> authResults;
    int32_t ret = ClawTicketManager::GetInstance().GenerateCliTicket(tokenId, cliAuthInfos, authResults);

    EXPECT_EQ(RET_SUCCESS, ret);
    EXPECT_EQ(1, authResults.size());
    EXPECT_EQ("mock_challenge_1", ExtractChallenge(authResults[0]));

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

    std::vector<std::string> authResults;
    int32_t ret = ClawTicketManager::GetInstance().GenerateCliTicket(tokenId, cliAuthInfos, authResults);

    EXPECT_EQ(RET_SUCCESS, ret);
    EXPECT_EQ(3, authResults.size());
    EXPECT_EQ("mock_challenge_1", ExtractChallenge(authResults[0]));
    EXPECT_EQ("mock_challenge_2", ExtractChallenge(authResults[1]));
    EXPECT_EQ("mock_challenge_3", ExtractChallenge(authResults[2]));

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

    std::vector<std::string> authResults;
    int32_t ret = ClawTicketManager::GetInstance().GenerateCliTicket(INVALID_TOKENID, cliAuthInfos, authResults);

    EXPECT_EQ(AccessTokenError::ERR_TOKEN_INVALID, ret);
    EXPECT_TRUE(authResults.empty());
}

/**
 * @tc.name: GenerateCliTicketTest004
 * @tc.desc: Test GenerateCliTicket with oversized strings
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(ClawTicketManagerTest, GenerateCliTicketTest004, TestSize.Level0)
{
    AccessTokenID tokenId = CreateTestHapToken();
    ASSERT_NE(INVALID_TOKENID, tokenId);

    std::string longCliName = GenerateLongString(LONG_STRING_SIZE);
    std::vector<CliAuthInfo> cliAuthInfos;
    cliAuthInfos.push_back(CreateTestCliAuth(longCliName,
        {"ohos.permission.CAMERA"}, {true}));

    std::vector<std::string> authResults;
    int32_t ret = ClawTicketManager::GetInstance().GenerateCliTicket(tokenId, cliAuthInfos, authResults);

    EXPECT_EQ(RET_SUCCESS, ret);
    EXPECT_EQ(1, authResults.size());
    EXPECT_EQ("mock_challenge_1", ExtractChallenge(authResults[0]));

    DeleteTestHapToken(tokenId);
}

/**
 * @tc.name: GenerateCliTicketTest005
 * @tc.desc: Test GenerateCliTicket with empty permissionNames
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(ClawTicketManagerTest, GenerateCliTicketTest005, TestSize.Level0)
{
    AccessTokenID tokenId = CreateTestHapToken();
    ASSERT_NE(INVALID_TOKENID, tokenId);

    std::vector<CliAuthInfo> cliAuthInfos;
    cliAuthInfos.push_back(CreateTestCliAuth("test_cli", {}, {}));

    std::vector<std::string> authResults;
    int32_t ret = ClawTicketManager::GetInstance().GenerateCliTicket(tokenId, cliAuthInfos, authResults);

    EXPECT_EQ(RET_SUCCESS, ret);
    EXPECT_FALSE(authResults.empty());

    DeleteTestHapToken(tokenId);
}

/**
 * @tc.name: GenerateCliTicketTest006
 * @tc.desc: Test GenerateCliTicket with empty permissionStatus
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(ClawTicketManagerTest, GenerateCliTicketTest006, TestSize.Level0)
{
    AccessTokenID tokenId = CreateTestHapToken();
    ASSERT_NE(INVALID_TOKENID, tokenId);

    std::vector<CliAuthInfo> cliAuthInfos;
    cliAuthInfos.push_back(CreateTestCliAuth("test_cli",
        {"ohos.permission.CAMERA", "ohos.permission.MICROPHONE"}, {}));

    std::vector<std::string> authResults;
    int32_t ret = ClawTicketManager::GetInstance().GenerateCliTicket(tokenId, cliAuthInfos, authResults);

    EXPECT_EQ(RET_SUCCESS, ret);
    EXPECT_FALSE(authResults.empty());

    DeleteTestHapToken(tokenId);
}

/**
 * @tc.name: GenerateCliTicketTest007
 * @tc.desc: Test GenerateCliTicket concurrent safety
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(ClawTicketManagerTest, GenerateCliTicketTest007, TestSize.Level0)
{
    AccessTokenID tokenId = CreateTestHapToken();
    ASSERT_NE(INVALID_TOKENID, tokenId);

    std::vector<CliAuthInfo> cliAuthInfos;
    cliAuthInfos.push_back(CreateTestCliAuth("test_cli",
        {"ohos.permission.CAMERA"}, {true}));

    constexpr int32_t threadCount = 10;
    std::vector<std::thread> threads;
    std::vector<int32_t> results(threadCount, -1);
    std::vector<std::vector<std::string>> allAuthResults(threadCount);

    for (int32_t i = 0; i < threadCount; ++i) {
        threads.emplace_back([tokenId, &cliAuthInfos, &results, &allAuthResults, i]() {
            results[i] = ClawTicketManager::GetInstance().GenerateCliTicket(tokenId, cliAuthInfos, allAuthResults[i]);
        });
    }

    for (auto& thread : threads) {
        thread.join();
    }

    for (int32_t i = 0; i < threadCount; ++i) {
        EXPECT_EQ(RET_SUCCESS, results[i]);
        EXPECT_EQ(1, allAuthResults[i].size());
    }

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

    std::string challenge = "test_challenge_001";
    InsertTestTicket(tokenId, challenge,
        CreateTestCliAuth("test_cli", {"ohos.permission.CAMERA", "ohos.permission.MICROPHONE"}, {true, false}));
    testChallenges_.push_back(challenge);

    CliInfo cliInfo = {"test_cli", "test_sub"};
    std::vector<PermissionStatus> permList;
    int32_t ret = ClawTicketManager::GetInstance().VerifyCliClawTicket(tokenId, challenge, cliInfo, permList);

    EXPECT_EQ(RET_SUCCESS, ret);

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
    CliInfo cliInfo = {"test_cli", "test_sub"};
    std::vector<PermissionStatus> permList;
    int32_t ret = ClawTicketManager::GetInstance().VerifyCliClawTicket(tokenId, challenge, cliInfo, permList);

    EXPECT_EQ(AccessTokenError::ERR_PARAM_INVALID, ret);

    DeleteTestHapToken(tokenId);
}

/**
 * @tc.name: VerifyCliClawTicketTest003
 * @tc.desc: Test VerifyCliClawTicket with all permissions granted
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(ClawTicketManagerTest, VerifyCliClawTicketTest003, TestSize.Level0)
{
    AccessTokenID tokenId = CreateTestHapToken();
    ASSERT_NE(INVALID_TOKENID, tokenId);

    std::string challenge = "test_challenge_005";
    InsertTestTicket(tokenId, challenge,
        CreateTestCliAuth("test_cli", {"ohos.permission.CAMERA", "ohos.permission.MICROPHONE"}, {true, true}));
    testChallenges_.push_back(challenge);

    CliInfo cliInfo = {"test_cli", "test_sub"};
    std::vector<PermissionStatus> permList;
    int32_t ret = ClawTicketManager::GetInstance().VerifyCliClawTicket(tokenId, challenge, cliInfo, permList);

    EXPECT_EQ(RET_SUCCESS, ret);
    EXPECT_EQ(2, permList.size());
    EXPECT_EQ(PERMISSION_GRANTED, GetPermissionStatus(permList, "ohos.permission.CAMERA").grantStatus);
    EXPECT_EQ(PERMISSION_GRANTED, GetPermissionStatus(permList, "ohos.permission.MICROPHONE").grantStatus);

    DeleteTestHapToken(tokenId);
}

/**
 * @tc.name: VerifyCliClawTicketTest004
 * @tc.desc: Test VerifyCliClawTicket with all permissions denied
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(ClawTicketManagerTest, VerifyCliClawTicketTest004, TestSize.Level0)
{
    AccessTokenID tokenId = CreateTestHapToken();
    ASSERT_NE(INVALID_TOKENID, tokenId);

    std::string challenge = "test_challenge_006";
    InsertTestTicket(tokenId, challenge,
        CreateTestCliAuth("test_cli", {"ohos.permission.CAMERA", "ohos.permission.MICROPHONE"}, {false, false}));
    testChallenges_.push_back(challenge);

    CliInfo cliInfo = {"test_cli", "test_sub"};
    std::vector<PermissionStatus> permList;
    int32_t ret = ClawTicketManager::GetInstance().VerifyCliClawTicket(tokenId, challenge, cliInfo, permList);

    EXPECT_EQ(RET_SUCCESS, ret);
    EXPECT_EQ(2, permList.size());
    EXPECT_EQ(PERMISSION_DENIED, GetPermissionStatus(permList, "ohos.permission.CAMERA").grantStatus);
    EXPECT_EQ(PERMISSION_DENIED, GetPermissionStatus(permList, "ohos.permission.MICROPHONE").grantStatus);

    DeleteTestHapToken(tokenId);
}

/**
 * @tc.name: VerifyCliClawTicketTest005
 * @tc.desc: Test VerifyCliClawTicket with mixed permission states
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(ClawTicketManagerTest, VerifyCliClawTicketTest005, TestSize.Level0)
{
    AccessTokenID tokenId = CreateTestHapToken();
    ASSERT_NE(INVALID_TOKENID, tokenId);

    std::string challenge = "test_challenge_007";
    InsertTestTicket(tokenId, challenge, CreateTestCliAuth("test_cli",
        {"ohos.permission.CAMERA", "ohos.permission.MICROPHONE", "ohos.permission.LOCATION"}, {true, false, true}));
    testChallenges_.push_back(challenge);

    CliInfo cliInfo = {"test_cli", "test_sub"};
    std::vector<PermissionStatus> permList;
    int32_t ret = ClawTicketManager::GetInstance().VerifyCliClawTicket(tokenId, challenge, cliInfo, permList);

    EXPECT_EQ(RET_SUCCESS, ret);
    EXPECT_EQ(3, permList.size());
    EXPECT_EQ(PERMISSION_GRANTED, GetPermissionStatus(permList, "ohos.permission.CAMERA").grantStatus);
    EXPECT_EQ(PERMISSION_DENIED, GetPermissionStatus(permList, "ohos.permission.MICROPHONE").grantStatus);
    EXPECT_EQ(PERMISSION_GRANTED, GetPermissionStatus(permList, "ohos.permission.LOCATION").grantStatus);

    DeleteTestHapToken(tokenId);
}

#ifdef ENHANCE_CAPABILITY
/**
 * @tc.name: VerifyCliClawTicketTest006
 * @tc.desc: Test VerifyCliClawTicket with empty challenge
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(ClawTicketManagerTest, VerifyCliClawTicketTest006, TestSize.Level0)
{
    AccessTokenID tokenId = CreateTestHapToken();
    ASSERT_NE(INVALID_TOKENID, tokenId);

    std::string challenge = "";
    CliInfo cliInfo = {"test_cli", "test_sub"};
    std::vector<PermissionStatus> permList;
    int32_t ret = ClawTicketManager::GetInstance().VerifyCliClawTicket(tokenId, challenge, cliInfo, permList);

    EXPECT_EQ(AccessTokenError::ERR_PARAM_INVALID, ret);

    DeleteTestHapToken(tokenId);
}
#endif

/**
 * @tc.name: VerifyCliClawTicketTest007
 * @tc.desc: Test VerifyCliClawTicket with normal JSON deserialization
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(ClawTicketManagerTest, VerifyCliClawTicketTest007, TestSize.Level0)
{
    AccessTokenID tokenId = CreateTestHapToken();
    ASSERT_NE(INVALID_TOKENID, tokenId);

    std::string challenge = "test_challenge_009";
    InsertTestTicket(tokenId, challenge,
        CreateTestCliAuth("test_cli", {"ohos.permission.CAMERA", "ohos.permission.MICROPHONE"}, {true, false}));
    testChallenges_.push_back(challenge);

    CliInfo cliInfo = {"test_cli", "test_sub"};
    std::vector<PermissionStatus> permList;
    int32_t ret = ClawTicketManager::GetInstance().VerifyCliClawTicket(tokenId, challenge, cliInfo, permList);

    EXPECT_EQ(RET_SUCCESS, ret);

    DeleteTestHapToken(tokenId);
}

/**
 * @tc.name: VerifyCliClawTicketTest008
 * @tc.desc: Test VerifyCliClawTicket when SAF returns ticket invalid
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(ClawTicketManagerTest, VerifyCliClawTicketTest008, TestSize.Level0)
{
    AccessTokenID tokenId = CreateTestHapToken();
    ASSERT_NE(INVALID_TOKENID, tokenId);

    std::string challenge = "test_challenge_008";
    InsertTestTicket(tokenId, challenge,
        CreateTestCliAuth("test_cli",
            {"ohos.permission.CAMERA", "ohos.permission.MICROPHONE"}, {true, true}));
    testChallenges_.push_back(challenge);

    SetMockVerifyTicketResult({1}, RET_SUCCESS);

    CliInfo cliInfo = {"test_cli", "test_sub"};
    std::vector<PermissionStatus> permList;
    int32_t ret = ClawTicketManager::GetInstance().VerifyCliClawTicket(tokenId, challenge, cliInfo, permList);

    EXPECT_EQ(RET_SUCCESS, ret);
    EXPECT_EQ(2, permList.size());
    EXPECT_EQ(PERMISSION_DENIED, GetPermissionStatus(permList, "ohos.permission.CAMERA").grantStatus);
    EXPECT_EQ(PERMISSION_DENIED, GetPermissionStatus(permList, "ohos.permission.MICROPHONE").grantStatus);

    DeleteTestHapToken(tokenId);
}

/**
 * @tc.name: VerifyCliClawTicketTest009
 * @tc.desc: Test VerifyCliClawTicket when BatchVerifyTicket returns error
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(ClawTicketManagerTest, VerifyCliClawTicketTest009, TestSize.Level0)
{
    AccessTokenID tokenId = CreateTestHapToken();
    ASSERT_NE(INVALID_TOKENID, tokenId);

    std::string challenge = "test_challenge_009_batch_fail";
    InsertTestTicket(tokenId, challenge,
        CreateTestCliAuth("test_cli",
            {"ohos.permission.CAMERA", "ohos.permission.MICROPHONE"}, {true, false}));
    testChallenges_.push_back(challenge);

    SetMockVerifyTicketResult({}, ERR_INVALID_OPERATION);

    CliInfo cliInfo = {"test_cli", "test_sub"};
    std::vector<PermissionStatus> permList;
    int32_t ret = ClawTicketManager::GetInstance().VerifyCliClawTicket(tokenId, challenge, cliInfo, permList);

    EXPECT_EQ(ERR_INVALID_OPERATION, ret);
    EXPECT_TRUE(permList.empty());

    DeleteTestHapToken(tokenId);
}

/**
 * @tc.name: VerifyCliClawTicketTest010
 * @tc.desc: Test VerifyCliClawTicket with mismatched cliName
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(ClawTicketManagerTest, VerifyCliClawTicketTest010, TestSize.Level0)
{
    AccessTokenID tokenId = CreateTestHapToken();
    ASSERT_NE(INVALID_TOKENID, tokenId);

    std::string challenge = "test_challenge_010";
    InsertTestTicket(tokenId, challenge,
        CreateTestCliAuth("test_cli", {"ohos.permission.CAMERA"}, {true}));

    CliInfo cliInfo = {"wrong_cli", "test_sub"};
    std::vector<PermissionStatus> permList;
    int32_t ret = ClawTicketManager::GetInstance().VerifyCliClawTicket(tokenId, challenge, cliInfo, permList);

    EXPECT_EQ(AccessTokenError::ERR_PARAM_INVALID, ret);

    DeleteTestHapToken(tokenId);
}

/**
 * @tc.name: VerifyCliClawTicketTest011
 * @tc.desc: Test VerifyCliClawTicket with mismatched subCliName
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(ClawTicketManagerTest, VerifyCliClawTicketTest011, TestSize.Level0)
{
    AccessTokenID tokenId = CreateTestHapToken();
    ASSERT_NE(INVALID_TOKENID, tokenId);

    std::string challenge = "test_challenge_011";
    InsertTestTicket(tokenId, challenge,
        CreateTestCliAuth("test_cli", {"ohos.permission.CAMERA"}, {true}));

    CliInfo cliInfo = {"test_cli", "wrong_sub"};
    std::vector<PermissionStatus> permList;
    int32_t ret = ClawTicketManager::GetInstance().VerifyCliClawTicket(tokenId, challenge, cliInfo, permList);

    EXPECT_EQ(AccessTokenError::ERR_PARAM_INVALID, ret);

    DeleteTestHapToken(tokenId);
}

/**
 * @tc.name: VerifyCliClawTicketTest012
 * @tc.desc: Test VerifyCliClawTicket with mismatched cliName and subCliName
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(ClawTicketManagerTest, VerifyCliClawTicketTest012, TestSize.Level0)
{
    AccessTokenID tokenId = CreateTestHapToken();
    ASSERT_NE(INVALID_TOKENID, tokenId);

    std::string challenge = "test_challenge_012";
    InsertTestTicket(tokenId, challenge,
        CreateTestCliAuth("test_cli", {"ohos.permission.CAMERA"}, {true}));

    CliInfo cliInfo = {"wrong_cli", "wrong_sub"};
    std::vector<PermissionStatus> permList;
    int32_t ret = ClawTicketManager::GetInstance().VerifyCliClawTicket(tokenId, challenge, cliInfo, permList);

    EXPECT_EQ(AccessTokenError::ERR_PARAM_INVALID, ret);

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

    std::string challenge = "test_challenge_delete_001";
    InsertTestTicket(tokenId, challenge,
        CreateTestCliAuth("test_cli", {"ohos.permission.CAMERA", "ohos.permission.MICROPHONE"}, {true, false}));

    auto itBefore = ClawTicketManager::GetInstance().ticketMap_.find(challenge);
    ASSERT_NE(ClawTicketManager::GetInstance().ticketMap_.end(), itBefore);

    int32_t ret = ClawTicketManager::GetInstance().DeleteClawTicket(challenge);
    EXPECT_EQ(RET_SUCCESS, ret);

    auto itAfter = ClawTicketManager::GetInstance().ticketMap_.find(challenge);
    EXPECT_EQ(ClawTicketManager::GetInstance().ticketMap_.end(), itAfter);

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
 * @tc.desc: Test DeleteClawTicketByCallerTokenId and verify ticket is deleted
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(ClawTicketManagerTest, DeleteClawTicketByTokenIdTest001, TestSize.Level1)
{
    AccessTokenID tokenId = CreateTestHapToken();
    ASSERT_NE(INVALID_TOKENID, tokenId);

    std::string challenge = "test_challenge_delete_by_tokenid_001";
    InsertTestTicket(tokenId, challenge,
        CreateTestCliAuth("test_cli", {"ohos.permission.CAMERA", "ohos.permission.MICROPHONE"}, {true, false}));

    auto itBefore = ClawTicketManager::GetInstance().ticketMap_.find(challenge);
    ASSERT_NE(ClawTicketManager::GetInstance().ticketMap_.end(), itBefore);

    ClawTicketManager::GetInstance().DeleteClawTicketByCallerTokenId(tokenId);

    auto itAfter = ClawTicketManager::GetInstance().ticketMap_.find(challenge);
    EXPECT_EQ(ClawTicketManager::GetInstance().ticketMap_.end(), itAfter);

    DeleteTestHapToken(tokenId);
}

/**
 * @tc.name: DeleteClawTicketByTokenIdTest002
 * @tc.desc: Test DeleteClawTicketByCallerTokenId with invalid tokenId
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(ClawTicketManagerTest, DeleteClawTicketByTokenIdTest002, TestSize.Level1)
{
    size_t sizeBefore = ClawTicketManager::GetInstance().ticketMap_.size();

    ClawTicketManager::GetInstance().DeleteClawTicketByCallerTokenId(INVALID_TOKENID);

    EXPECT_EQ(sizeBefore, ClawTicketManager::GetInstance().ticketMap_.size());
}

/**
 * @tc.name: DeleteClawTicketByTokenIdTest003
 * @tc.desc: Test DeleteClawTicketByCallerTokenId with tokenId that has no associated tickets
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(ClawTicketManagerTest, DeleteClawTicketByTokenIdTest003, TestSize.Level1)
{
    AccessTokenID tokenId = CreateTestHapToken();
    ASSERT_NE(INVALID_TOKENID, tokenId);

    size_t sizeBefore = ClawTicketManager::GetInstance().ticketMap_.size();

    ClawTicketManager::GetInstance().DeleteClawTicketByCallerTokenId(tokenId);

    EXPECT_EQ(sizeBefore, ClawTicketManager::GetInstance().ticketMap_.size());

    DeleteTestHapToken(tokenId);
}

// ==================== OnAppStopped Callback Test Cases ====================

/**
 * @tc.name: OnAppStoppedTest001
 * @tc.desc: Test OnAppStopped cleans up tickets when app terminates
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(ClawTicketManagerTest, OnAppStoppedTest001, TestSize.Level1)
{
    AccessTokenID tokenId = CreateTestHapToken();
    ASSERT_NE(INVALID_TOKENID, tokenId);

    std::string challenge = "test_challenge_onstop_001";
    InsertTestTicket(tokenId, challenge,
        CreateTestCliAuth("test_cli", {"ohos.permission.CAMERA", "ohos.permission.MICROPHONE"}, {true, false}));

    auto itBefore = ClawTicketManager::GetInstance().ticketMap_.find(challenge);
    ASSERT_NE(ClawTicketManager::GetInstance().ticketMap_.end(), itBefore);

    AppStateData appStateData;
    appStateData.accessTokenId = tokenId;
    appStateData.state = static_cast<int32_t>(ApplicationState::APP_STATE_TERMINATED);

    ClawTicketAppStateObserver observer;
    observer.OnAppStopped(appStateData);

    auto itAfter = ClawTicketManager::GetInstance().ticketMap_.find(challenge);
    EXPECT_EQ(ClawTicketManager::GetInstance().ticketMap_.end(), itAfter);

    DeleteTestHapToken(tokenId);
}

/**
 * @tc.name: OnAppStoppedTest002
 * @tc.desc: Test OnAppStopped does not affect other apps' tickets
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(ClawTicketManagerTest, OnAppStoppedTest002, TestSize.Level1)
{
    AccessTokenID tokenId1 = CreateTestHapToken();
    AccessTokenID tokenId2 = CreateTestHapToken();
    ASSERT_NE(INVALID_TOKENID, tokenId1);
    ASSERT_NE(INVALID_TOKENID, tokenId2);

    std::string challenge1 = "test_challenge_onstop_002_1";
    std::string challenge2 = "test_challenge_onstop_002_2";
    InsertTestTicket(tokenId1, challenge1, CreateTestCliAuth("test_cli", {"ohos.permission.CAMERA"}, {true}));
    InsertTestTicket(tokenId2, challenge2, CreateTestCliAuth("test_cli", {"ohos.permission.MICROPHONE"}, {true}));

    auto itBefore1 = ClawTicketManager::GetInstance().ticketMap_.find(challenge1);
    auto itBefore2 = ClawTicketManager::GetInstance().ticketMap_.find(challenge2);
    ASSERT_NE(ClawTicketManager::GetInstance().ticketMap_.end(), itBefore1);
    ASSERT_NE(ClawTicketManager::GetInstance().ticketMap_.end(), itBefore2);

    AppStateData appStateData;
    appStateData.accessTokenId = tokenId1;
    appStateData.state = static_cast<int32_t>(ApplicationState::APP_STATE_TERMINATED);

    ClawTicketAppStateObserver observer;
    observer.OnAppStopped(appStateData);

    auto itAfter1 = ClawTicketManager::GetInstance().ticketMap_.find(challenge1);
    auto itAfter2 = ClawTicketManager::GetInstance().ticketMap_.find(challenge2);
    EXPECT_EQ(ClawTicketManager::GetInstance().ticketMap_.end(), itAfter1);
    EXPECT_NE(ClawTicketManager::GetInstance().ticketMap_.end(), itAfter2);

    DeleteTestHapToken(tokenId1);
    DeleteTestHapToken(tokenId2);
}

/**
 * @tc.name: OnAppStoppedTest003
 * @tc.desc: Test OnAppStopped does not clean up tickets for non-terminated state
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(ClawTicketManagerTest, OnAppStoppedTest003, TestSize.Level1)
{
    AccessTokenID tokenId = CreateTestHapToken();
    ASSERT_NE(INVALID_TOKENID, tokenId);

    std::string challenge = "test_challenge_onstop_003";
    InsertTestTicket(tokenId, challenge,
        CreateTestCliAuth("test_cli", {"ohos.permission.CAMERA", "ohos.permission.MICROPHONE"}, {true, false}));

    AppStateData appStateData;
    appStateData.accessTokenId = tokenId;
    appStateData.state = static_cast<int32_t>(ApplicationState::APP_STATE_BACKGROUND);

    ClawTicketAppStateObserver observer;
    observer.OnAppStopped(appStateData);

    auto it = ClawTicketManager::GetInstance().ticketMap_.find(challenge);
    ASSERT_NE(ClawTicketManager::GetInstance().ticketMap_.end(), it);

    DeleteTestHapToken(tokenId);
}

/**
 * @tc.name: OnAppStoppedTest004
 * @tc.desc: Test OnAppStopped with invalid AppStateData
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(ClawTicketManagerTest, OnAppStoppedTest004, TestSize.Level1)
{
    AccessTokenID tokenId = CreateTestHapToken();
    ASSERT_NE(INVALID_TOKENID, tokenId);

    std::string challenge = "test_challenge_onstop_004";
    InsertTestTicket(tokenId, challenge,
        CreateTestCliAuth("test_cli", {"ohos.permission.CAMERA", "ohos.permission.MICROPHONE"}, {true, false}));

    AppStateData appStateData;
    appStateData.accessTokenId = INVALID_TOKENID;
    appStateData.state = static_cast<int32_t>(ApplicationState::APP_STATE_TERMINATED);

    ClawTicketAppStateObserver observer;
    observer.OnAppStopped(appStateData);

    auto it = ClawTicketManager::GetInstance().ticketMap_.find(challenge);
    ASSERT_NE(ClawTicketManager::GetInstance().ticketMap_.end(), it);

    DeleteTestHapToken(tokenId);
}

// ==================== TransferErrorCode Test Cases ====================

/**
 * @tc.name: TransferErrorCodeTest001
 * @tc.desc: Test TransferErrorCode with ERR_TICKET_NOT_LOGGED_IN
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(ClawTicketManagerTest, TransferErrorCodeTest001, TestSize.Level2)
{
    int32_t ret = TransferErrorCode(ERR_TICKET_NOT_LOGGED_IN);
    EXPECT_EQ(ERR_NOT_LOGGED_IN, ret);
}

/**
 * @tc.name: TransferErrorCodeTest002
 * @tc.desc: Test TransferErrorCode with ERR_TICKET_NETWORK_DISCONNECTED
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(ClawTicketManagerTest, TransferErrorCodeTest002, TestSize.Level2)
{
    int32_t ret = TransferErrorCode(ERR_TICKET_NETWORK_DISCONNECTED);
    EXPECT_EQ(ERR_NETWORK_DISCONNECTED, ret);
}

/**
 * @tc.name: TransferErrorCodeTest003
 * @tc.desc: Test TransferErrorCode with unknown error code returns unchanged
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(ClawTicketManagerTest, TransferErrorCodeTest003, TestSize.Level2)
{
    int32_t ret = TransferErrorCode(RET_SUCCESS);
    EXPECT_EQ(RET_SUCCESS, ret);

    ret = TransferErrorCode(ERR_PERMISSION_DENIED);
    EXPECT_EQ(ERR_PERMISSION_DENIED, ret);
}

#ifdef SAF_AGENT_FENCE_ENABLE
/**
 * @tc.name: TransferErrorCodeTest004
 * @tc.desc: Test TransferErrorCode with SAF_ERR_IPC_WRITE_DATA_FAIL
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(ClawTicketManagerTest, TransferErrorCodeTest004, TestSize.Level2)
{
    int32_t ret = TransferErrorCode(SAF_ERR_IPC_WRITE_DATA_FAIL);
    EXPECT_EQ(ERR_WRITE_PARCEL_FAILED, ret);
}

/**
 * @tc.name: TransferErrorCodeTest005
 * @tc.desc: Test TransferErrorCode with SAF_ERR_IPC_READ_DATA_FAIL
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(ClawTicketManagerTest, TransferErrorCodeTest005, TestSize.Level2)
{
    int32_t ret = TransferErrorCode(SAF_ERR_IPC_READ_DATA_FAIL);
    EXPECT_EQ(ERR_READ_PARCEL_FAILED, ret);
}

/**
 * @tc.name: TransferErrorCodeTest006
 * @tc.desc: Test TransferErrorCode with SAF_ERR_IPC_SEND_REQUEST_FAIL
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(ClawTicketManagerTest, TransferErrorCodeTest006, TestSize.Level2)
{
    int32_t ret = TransferErrorCode(SAF_ERR_IPC_SEND_REQUEST_FAIL);
    EXPECT_EQ(ERROR_IPC_REQUEST_FAIL, ret);
}

/**
 * @tc.name: TransferErrorCodeTest007
 * @tc.desc: Test TransferErrorCode with SAF_ERR_IPC_PROXY_FAIL
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(ClawTicketManagerTest, TransferErrorCodeTest007, TestSize.Level2)
{
    int32_t ret = TransferErrorCode(SAF_ERR_IPC_PROXY_FAIL);
    EXPECT_EQ(ERROR_IPC_REQUEST_FAIL, ret);
}

/**
 * @tc.name: TransferErrorCodeTest008
 * @tc.desc: Test TransferErrorCode with SAF_ERR_IPC_ERROR
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(ClawTicketManagerTest, TransferErrorCodeTest008, TestSize.Level2)
{
    int32_t ret = TransferErrorCode(SAF_ERR_IPC_ERROR);
    EXPECT_EQ(ERROR_IPC_REQUEST_FAIL, ret);
}

/**
 * @tc.name: TransferErrorCodeTest009
 * @tc.desc: Test TransferErrorCode with SAF_ERR_IPC_INVALID_IPC_CODE
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(ClawTicketManagerTest, TransferErrorCodeTest009, TestSize.Level2)
{
    int32_t ret = TransferErrorCode(SAF_ERR_IPC_INVALID_IPC_CODE);
    EXPECT_EQ(ERROR_IPC_REQUEST_FAIL, ret);
}

/**
 * @tc.name: TransferErrorCodeTest010
 * @tc.desc: Test TransferErrorCode with SAF_ERR_SERVICE_UNAVAILABLE
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(ClawTicketManagerTest, TransferErrorCodeTest010, TestSize.Level2)
{
    int32_t ret = TransferErrorCode(SAF_ERR_SERVICE_UNAVAILABLE);
    EXPECT_EQ(ERR_SERVICE_ABNORMAL, ret);
}

/**
 * @tc.name: TransferErrorCodeTest011
 * @tc.desc: Test TransferErrorCode with SAF_ERR_SERVICE_IS_STOPPING
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(ClawTicketManagerTest, TransferErrorCodeTest011, TestSize.Level2)
{
    int32_t ret = TransferErrorCode(SAF_ERR_SERVICE_IS_STOPPING);
    EXPECT_EQ(ERR_SERVICE_ABNORMAL, ret);
}

// ==================== QueryCommandPermissions Test Cases ====================

/**
 * @tc.name: QueryCommandPermissionsTest001
 * @tc.desc: Test QueryCommandPermissions with valid single-permission command
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(ClawTicketManagerTest, QueryCommandPermissionsTest001, TestSize.Level1)
{
    CliInfo cliInfo = {"location", "query"};
    std::vector<PermissionStatus> permList;
    int32_t ret = ClawTicketManager::GetInstance().QueryCommandPermissions(cliInfo, permList);

    EXPECT_EQ(RET_SUCCESS, ret);
    ASSERT_EQ(1, permList.size());
    EXPECT_EQ("ohos.permission.APPROXIMATELY_LOCATION", permList[0].permissionName);
    EXPECT_EQ(PERMISSION_GRANTED, permList[0].grantStatus);
}

/**
 * @tc.name: QueryCommandPermissionsTest002
 * @tc.desc: Test QueryCommandPermissions with multi-permission command
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(ClawTicketManagerTest, QueryCommandPermissionsTest002, TestSize.Level1)
{
    CliInfo cliInfo = {"mixed", "run"};
    std::vector<PermissionStatus> permList;
    int32_t ret = ClawTicketManager::GetInstance().QueryCommandPermissions(cliInfo, permList);

    EXPECT_EQ(RET_SUCCESS, ret);
    ASSERT_EQ(2, permList.size());
    EXPECT_EQ("ohos.permission.APPROXIMATELY_LOCATION", permList[0].permissionName);
    EXPECT_EQ("ohos.permission.CAMERA", permList[1].permissionName);
    EXPECT_EQ(PERMISSION_GRANTED, permList[0].grantStatus);
    EXPECT_EQ(PERMISSION_GRANTED, permList[1].grantStatus);
}

/**
 * @tc.name: QueryCommandPermissionsTest003
 * @tc.desc: Test QueryCommandPermissions with command having empty permission list
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(ClawTicketManagerTest, QueryCommandPermissionsTest003, TestSize.Level1)
{
    CliInfo cliInfo = {"empty", "run"};
    std::vector<PermissionStatus> permList;
    int32_t ret = ClawTicketManager::GetInstance().QueryCommandPermissions(cliInfo, permList);

    EXPECT_EQ(RET_SUCCESS, ret);
    EXPECT_TRUE(permList.empty());
}

/**
 * @tc.name: QueryCommandPermissionsTest004
 * @tc.desc: Test QueryCommandPermissions with unmapped command
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(ClawTicketManagerTest, QueryCommandPermissionsTest004, TestSize.Level1)
{
    CliInfo cliInfo = {"unknown", "cmd"};
    std::vector<PermissionStatus> permList;
    int32_t ret = ClawTicketManager::GetInstance().QueryCommandPermissions(cliInfo, permList);

    EXPECT_EQ(RET_SUCCESS, ret);
    EXPECT_TRUE(permList.empty());
}

/**
 * @tc.name: QueryCommandPermissionsTest005
 * @tc.desc: Test QueryCommandPermissions with empty cmdName
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(ClawTicketManagerTest, QueryCommandPermissionsTest005, TestSize.Level1)
{
    CliInfo cliInfo = {"", "run"};
    std::vector<PermissionStatus> permList;
    int32_t ret = ClawTicketManager::GetInstance().QueryCommandPermissions(cliInfo, permList);

    EXPECT_EQ(RET_SUCCESS, ret);
    EXPECT_TRUE(permList.empty());
}

/**
 * @tc.name: QueryCommandPermissionsTest006
 * @tc.desc: Test QueryCommandPermissions with abnormal queryRet command
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(ClawTicketManagerTest, QueryCommandPermissionsTest006, TestSize.Level1)
{
    CliInfo cliInfo = {"abnormal", "run"};
    std::vector<PermissionStatus> permList;
    int32_t ret = ClawTicketManager::GetInstance().QueryCommandPermissions(cliInfo, permList);

    EXPECT_EQ(RET_SUCCESS, ret);
    EXPECT_TRUE(permList.empty());
}

/**
 * @tc.name: QueryCommandPermissionsTest007
 * @tc.desc: Test QueryCommandPermissions with multi-permission command (multi:run)
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(ClawTicketManagerTest, QueryCommandPermissionsTest007, TestSize.Level1)
{
    CliInfo cliInfo = {"multi", "run"};
    std::vector<PermissionStatus> permList;
    int32_t ret = ClawTicketManager::GetInstance().QueryCommandPermissions(cliInfo, permList);

    EXPECT_EQ(RET_SUCCESS, ret);
    ASSERT_EQ(2, permList.size());
    EXPECT_EQ("ohos.permission.APPROXIMATELY_LOCATION", permList[0].permissionName);
    EXPECT_EQ("ohos.permission.POWER_MANAGER", permList[1].permissionName);
    EXPECT_EQ(PERMISSION_GRANTED, permList[0].grantStatus);
    EXPECT_EQ(PERMISSION_GRANTED, permList[1].grantStatus);
}

/**
 * @tc.name: QueryCommandPermissionsTest008
 * @tc.desc: Test QueryCommandPermissions with different permission mapping (camera:capture)
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(ClawTicketManagerTest, QueryCommandPermissionsTest008, TestSize.Level1)
{
    CliInfo cliInfo = {"camera", "capture"};
    std::vector<PermissionStatus> permList;
    int32_t ret = ClawTicketManager::GetInstance().QueryCommandPermissions(cliInfo, permList);

    EXPECT_EQ(RET_SUCCESS, ret);
    ASSERT_EQ(1, permList.size());
    EXPECT_EQ("ohos.permission.POWER_MANAGER", permList[0].permissionName);
    EXPECT_EQ(PERMISSION_GRANTED, permList[0].grantStatus);
}
#endif
} // namespace AccessToken
} // namespace Security
} // namespace OHOS
