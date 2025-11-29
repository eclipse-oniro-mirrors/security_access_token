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

#include <algorithm>
#include <fstream>
#include <functional>
#include <iostream>
#include <map>
#include <memory>
#include <thread>
#include "gtest/gtest.h"

#define private public
#include "base_remote_command.h"
#include "delete_remote_token_command.h"
#include "remote_command_executor.h"
#include "sync_remote_hap_token_command.h"
#include "update_remote_hap_token_command.h"
#undef private

#include "accesstoken_kit.h"
#include "accesstoken_common_log.h"
#include "access_token_error.h"
#include "constant.h"
#include "constant_common.h"
#include "device_info_manager.h"
#include "device_info.h"
#include "dm_device_info.h"
#include "remote_command_manager.h"
#include "socket.h"
#include "test_common.h"
#include "token_setproc.h"

using namespace std;
using namespace testing::ext;

namespace OHOS {
namespace Security {
namespace AccessToken {
namespace {
AccessTokenID g_testTokenId = 12345678;
std::string g_validDeviceId = "valid_deviceId1";
std::string g_invalidDeviceId = "invalid_deviceId1";
uint64_t g_selfShellTokenId;
}

class TokenSyncCommandCoverageTest : public testing::Test {
public:
    TokenSyncCommandCoverageTest();
    ~TokenSyncCommandCoverageTest();
    static void SetUpTestCase();
    static void TearDownTestCase();
    void SetUp();
    void TearDown();
};

TokenSyncCommandCoverageTest::TokenSyncCommandCoverageTest()
{
}

TokenSyncCommandCoverageTest::~TokenSyncCommandCoverageTest()
{
}

void TokenSyncCommandCoverageTest::SetUpTestCase()
{
    g_selfShellTokenId = GetSelfTokenID();
    TestCommon::SetTestEvironment(g_selfShellTokenId);
}

void TokenSyncCommandCoverageTest::TearDownTestCase()
{
    TestCommon::ResetTestEvironment();
}

void TokenSyncCommandCoverageTest::SetUp()
{
    TestCommon::SetTestEvironment(g_selfShellTokenId);
}

void TokenSyncCommandCoverageTest::TearDown()
{
    TestCommon::ResetTestEvironment();
}

/**
 * @tc.name: FromPermStateJsonTest001
 * @tc.desc: test json
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(TokenSyncCommandCoverageTest, FromPermStateJsonTest001, TestSize.Level4)
{
    DeleteRemoteTokenCommand deleteCommand("invalidDevice1", "invalidDevice2", 321); // invalid tokenid

    // no permissionName
    CJsonUnique jsonPtr = CreateJsonFromString("{\"bundleName\":\"test.bundle1\"}");
    PermissionStatus status;
    EXPECT_FALSE(deleteCommand.FromPermStateJson(jsonPtr.get(), status));

    // no inner grantStatus
    jsonPtr = CreateJsonFromString("{\"permissionName\":\"test.permission1\", \"grantStatus\":{\"grantFlag\":\"1\"}}");
    EXPECT_FALSE(deleteCommand.FromPermStateJson(jsonPtr.get(), status));

    // grantConfig size is 0
    jsonPtr = CreateJsonFromString("{\"bundleName\":\"test.bundle1\","
        "\"instIndex\":0,\"permState\":[{\"permissionName\":\"TEST\", "
        "\"grantStatus\":0, \"grantFlag\":0,\"isGeneral\":true,\"grantConfig\":"
        "[]}],\"tokenAttr\":0,\"tokenID\":111,\"userID\":0,\"version\":1}");
    EXPECT_FALSE(deleteCommand.FromPermStateJson(jsonPtr.get(), status));

    jsonPtr = CreateJsonFromString("{\"permissionName\":\"test.permission2\", \"grantConfig\":[]}");
    EXPECT_FALSE(deleteCommand.FromPermStateJson(jsonPtr.get(), status));
}

/**
 * @tc.name: FromHapTokenInfoJsonTest001
 * @tc.desc: test json
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(TokenSyncCommandCoverageTest, FromHapTokenInfoJsonTest001, TestSize.Level4)
{
    DeleteRemoteTokenCommand deleteCommand("invalidDevice1", "invalidDevice2", 321);

    // json not hap info
    CJsonUnique jsonPtr = CreateJsonFromString("{\"tokenID\":123}");
    HapTokenInfoForSync hapInfoSync;
    hapInfoSync.baseInfo.tokenID = 0;
    deleteCommand.FromHapTokenInfoJson(jsonPtr.get(), hapInfoSync);
    EXPECT_EQ(123, hapInfoSync.baseInfo.tokenID); // parse from json
}

/**
 * @tc.name: DeleteRemoteTokenCommandTest001
 * @tc.desc: test json
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(TokenSyncCommandCoverageTest, DeleteRemoteTokenCommandTest001, TestSize.Level4)
{
    DeleteRemoteTokenCommand deleteCommand1("abcdefg");
    EXPECT_EQ(0, deleteCommand1.deleteTokenId_);

    DeleteRemoteTokenCommand deleteCommand2("{\"tokenId\":123}");
    EXPECT_EQ(123, deleteCommand2.deleteTokenId_); // parse from json

    std::string result = deleteCommand2.ToJsonPayload();
    EXPECT_NE(std::string::npos, result.find("123"));

    DeleteRemoteTokenCommand deleteCommand3("{\"flag\":1}");
    EXPECT_EQ(0, deleteCommand3.deleteTokenId_);
}

/**
 * @tc.name: DeleteCommandMockExecuteTest001
 * @tc.desc: mock test
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(TokenSyncCommandCoverageTest, DeleteCommandMockExecuteTest001, TestSize.Level4)
{
    DeleteRemoteTokenCommand deleteCommand1(g_invalidDeviceId, g_invalidDeviceId, 123); // invalid tokenid
    deleteCommand1.Execute();
    EXPECT_EQ(deleteCommand1.remoteProtocol_.statusCode, Constant::FAILURE_BUT_CAN_RETRY);
    EXPECT_EQ(deleteCommand1.remoteProtocol_.message, Constant::COMMAND_RESULT_FAILED);
}

/**
 * @tc.name: DeleteCommandMockExecuteTest002
 * @tc.desc: mock test
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(TokenSyncCommandCoverageTest, DeleteCommandMockExecuteTest002, TestSize.Level4)
{
    MockNativeToken mock("token_sync_service");

    HapTokenInfo baseInfo = {
        .ver = 1,
        .userID = 1,
        .bundleName = "com.ohos.access_token",
        .instIndex = 1,
        .tokenID = g_testTokenId,
        .tokenAttr = 0
    };

    PermissionStatus infoManagerTestState = {
        .permissionName = "ohos.permission.CAMERA",
        .grantStatus = PermissionState::PERMISSION_GRANTED,
        .grantFlag = PermissionFlag::PERMISSION_SYSTEM_FIXED};
    std::vector<PermissionStatus> permStateList;
    permStateList.emplace_back(infoManagerTestState);

    HapTokenInfoForSync remoteTokenInfo = {
        .baseInfo = baseInfo,
        .permStateList = permStateList
    };

    int32_t ret = AccessTokenKit::SetRemoteHapTokenInfo(g_validDeviceId, remoteTokenInfo);
    ASSERT_EQ(ret, RET_SUCCESS);

    DeleteRemoteTokenCommand deleteCommand1(g_validDeviceId, g_validDeviceId, g_testTokenId);
    deleteCommand1.Execute();
    EXPECT_EQ(deleteCommand1.remoteProtocol_.statusCode, Constant::SUCCESS);
    EXPECT_EQ(deleteCommand1.remoteProtocol_.message, Constant::COMMAND_RESULT_SUCCESS);
}

/**
 * @tc.name: UpdateRemoteHapTokenCommandTest001
 * @tc.desc: test json
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(TokenSyncCommandCoverageTest, UpdateRemoteHapTokenCommandTest001, TestSize.Level4)
{
    UpdateRemoteHapTokenCommand updateCommand1("abcdefg");
    EXPECT_EQ(0, updateCommand1.updateTokenInfo_.permStateList.size());

    UpdateRemoteHapTokenCommand updateCommand2("{\"tokenId\":123}");
    EXPECT_EQ(0, updateCommand2.updateTokenInfo_.permStateList.size());

    UpdateRemoteHapTokenCommand updateCommand3("{\"HapTokenInfos\":{\"tokenID\":123}}");
    EXPECT_EQ(123, updateCommand3.updateTokenInfo_.baseInfo.tokenID); // parse from json

    std::string result = updateCommand3.ToJsonPayload();
    EXPECT_NE(std::string::npos, result.find("123"));
}

/**
 * @tc.name: UpdateCommandMockExecuteTest001
 * @tc.desc: mock test
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(TokenSyncCommandCoverageTest, UpdateCommandMockExecuteTest001, TestSize.Level4)
{
    HapTokenInfoForSync infoSync;
    infoSync.baseInfo.ver = 1;
    infoSync.baseInfo.userID = 1;
    infoSync.baseInfo.bundleName = "test_bundle";
    infoSync.baseInfo.apiVersion = 12; // 12 is default version
    infoSync.baseInfo.instIndex = 0;
    infoSync.baseInfo.dlpType = 0;
    infoSync.baseInfo.tokenID = g_testTokenId;
    infoSync.baseInfo.tokenAttr = 0;

    UpdateRemoteHapTokenCommand updateCommand1(g_invalidDeviceId, g_invalidDeviceId, infoSync);
    updateCommand1.Execute();
    EXPECT_EQ(updateCommand1.remoteProtocol_.statusCode, Constant::FAILURE_BUT_CAN_RETRY);
    EXPECT_EQ(updateCommand1.remoteProtocol_.message, Constant::COMMAND_RESULT_FAILED);
}

/**
 * @tc.name: UpdateCommandMockExecuteTest002
 * @tc.desc: mock test
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(TokenSyncCommandCoverageTest, UpdateCommandMockExecuteTest002, TestSize.Level4)
{
    MockNativeToken mock("token_sync_service");

    HapTokenInfo baseInfo = {
        .ver = 1,
        .userID = 1,
        .bundleName = "com.ohos.access_token",
        .instIndex = 1,
        .tokenID = g_testTokenId,
        .tokenAttr = 0
    };

    PermissionStatus infoManagerTestState = {
        .permissionName = "ohos.permission.CAMERA",
        .grantStatus = PermissionState::PERMISSION_GRANTED,
        .grantFlag = PermissionFlag::PERMISSION_SYSTEM_FIXED
    };
    std::vector<PermissionStatus> permStateList;
    permStateList.emplace_back(infoManagerTestState);

    HapTokenInfoForSync remoteTokenInfo = {
        .baseInfo = baseInfo,
        .permStateList = permStateList
    };

    int32_t ret = AccessTokenKit::SetRemoteHapTokenInfo(g_validDeviceId, remoteTokenInfo);
    ASSERT_EQ(ret, RET_SUCCESS);

    PermissionStatus infoManagerTestState2 = {
        .permissionName = "ohos.permission.MICROPHONE",
        .grantStatus = PermissionState::PERMISSION_GRANTED,
        .grantFlag = PermissionFlag::PERMISSION_USER_FIXED
    };
    remoteTokenInfo.permStateList.emplace_back(infoManagerTestState2);

    UpdateRemoteHapTokenCommand updateCommand1(g_validDeviceId, g_validDeviceId, remoteTokenInfo);
    updateCommand1.Execute();
    EXPECT_EQ(updateCommand1.remoteProtocol_.statusCode, Constant::SUCCESS);
    EXPECT_EQ(updateCommand1.remoteProtocol_.message, Constant::COMMAND_RESULT_SUCCESS);

    DeleteRemoteTokenCommand deleteCommand1(g_validDeviceId, g_validDeviceId, g_testTokenId);
    deleteCommand1.Execute();
}

/**
 * @tc.name: SyncRemoteHapTokenCommandTest001
 * @tc.desc: test json
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(TokenSyncCommandCoverageTest, SyncRemoteHapTokenCommandTest001, TestSize.Level4)
{
    SyncRemoteHapTokenCommand syncCommand1("abcdefg");
    EXPECT_EQ(0, syncCommand1.requestTokenId_);

    SyncRemoteHapTokenCommand syncCommand2("{\"requestTokenId\":123}");
    EXPECT_EQ(123, syncCommand2.requestTokenId_); // parse from json

    SyncRemoteHapTokenCommand syncCommand3("{\"requestTokenId\":123,\"HapTokenInfo\":{\"tokenID\":123}}");
    EXPECT_EQ(123, syncCommand3.requestTokenId_); // parse from json

    syncCommand3.remoteProtocol_.statusCode = Constant::FAILURE_BUT_CAN_RETRY;
    syncCommand3.Finish();
    syncCommand3.remoteProtocol_.statusCode = Constant::SUCCESS;
    syncCommand3.Finish();

    std::string result = syncCommand3.ToJsonPayload();
    EXPECT_NE(std::string::npos, result.find("123"));
}

/**
 * @tc.name: SyncCommandMockExecuteTest001
 * @tc.desc: mock test
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(TokenSyncCommandCoverageTest, SyncCommandMockExecuteTest001, TestSize.Level4)
{
    AccessTokenIDEx tokenIdEx = {0};
    {
        MockNativeToken mock("foundation");
        HapInfoParams infoParams = {
            .userID = 1,
            .bundleName = "token_sync_command_test_bundle",
            .instIndex = 0,
            .appIDDesc = "AccessTokenTestAppID",
            .apiVersion = 12, // 12 is default version
            .isSystemApp = false,
            .appDistributionType = "",
        };
        HapPolicyParams policyParams = {
            .apl = APL_NORMAL,
            .domain = "accesstoken_test_domain",
        };

        int32_t ret = AccessTokenKit::InitHapToken(infoParams, policyParams, tokenIdEx);
        ASSERT_EQ(RET_SUCCESS, ret);
    }

    {
        MockNativeToken mock("token_sync_service");
        SyncRemoteHapTokenCommand syncCommand1(g_validDeviceId, g_validDeviceId, tokenIdEx.tokenIdExStruct.tokenID);
        syncCommand1.Execute();
        EXPECT_EQ(syncCommand1.remoteProtocol_.statusCode, Constant::SUCCESS);
        EXPECT_EQ(syncCommand1.remoteProtocol_.message, Constant::COMMAND_RESULT_SUCCESS);
    }

    {
        MockNativeToken mock("foundation");
        AccessTokenKit::DeleteToken(tokenIdEx.tokenIdExStruct.tokenID);
    }
}
}  // namespace AccessToken
}  // namespace Security
}  // namespace OHOS
