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

#include "token_sync_kit_test.h"

#include "access_token.h"
#include "access_token_error.h"
#include "accesstoken_kit.h"
#include "i_token_sync_manager.h"
#include "nativetoken_kit.h"
#include "token_setproc.h"
#include "token_sync_manager_client.h"

using namespace testing::ext;

namespace OHOS {
namespace Security {
namespace AccessToken {
namespace {
static const int32_t TIME_2000_MS = 1000 * 2000; // 2 second
}
static void SetNativeTokenId(const std::string &process)
{
    std::string dumpInfo;
    AtmToolsParamInfo info;
    info.processName = process;
    AccessTokenKit::DumpTokenInfo(info, dumpInfo);
    size_t pos = dumpInfo.find("\"tokenID\": ");
    if (pos == std::string::npos) {
        return;
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

    SetSelfTokenID(tokenID);
}

static void StartOrStopTokenSyncService(bool start)
{
    pid_t pid = fork();
    int ret = 0;
    if (pid == 0) {
        if (start) {
            ret = execlp("service_control", "service_control", "start", "token_sync_service", nullptr);
        } else {
            ret = execlp("service_control", "service_control", "stop", "token_sync_service", nullptr);
        }
        if (ret == -1) {
            std::cout << "execlp failed" << std::endl;
        }
        exit(0);
    }
    usleep(TIME_2000_MS);
}

void TokenSyncKitTest::SetUpTestCase()
{}

void TokenSyncKitTest::TearDownTestCase()
{}

void TokenSyncKitTest::SetUp()
{
    StartOrStopTokenSyncService(false);
}

void TokenSyncKitTest::TearDown()
{}

/**
 * @tc.name: UpdateRemoteHapTokenInfo001
 * @tc.desc: TokenSyncManagerProxy::UpdateRemoteHapTokenInfo function test
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(TokenSyncKitTest, UpdateRemoteHapTokenInfo001, TestSize.Level1)
{
    HapTokenInfoForSync tokenInfo;
    uint64_t selfTokenId = GetSelfTokenID();

    // proxy is nullptr
    EXPECT_EQ(TokenSyncError::TOKEN_SYNC_IPC_ERROR,
        TokenSyncManagerClient::GetInstance().UpdateRemoteHapTokenInfo(tokenInfo));

    StartOrStopTokenSyncService(true);

    // service is starting, but no permission(shell process)
    SetNativeTokenId("hdcd");
    int32_t selfUid = getuid();
    setuid(10001); // 10001： UID
    EXPECT_EQ(ERR_IDENTITY_CHECK_FAILED, TokenSyncManagerClient::GetInstance().UpdateRemoteHapTokenInfo(tokenInfo));
    setuid(selfUid);

    // service is starting, and has permission(native process)
    SetNativeTokenId("accesstoken_service");
    EXPECT_EQ(0, TokenSyncManagerClient::GetInstance().UpdateRemoteHapTokenInfo(tokenInfo));

    StartOrStopTokenSyncService(false);
    SetSelfTokenID(selfTokenId);
}

/**
 * @tc.name: GetRemoteHapTokenInfo001
 * @tc.desc: TokenSyncManagerProxy::GetRemoteHapTokenInfo function test
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(TokenSyncKitTest, GetRemoteHapTokenInfo001, TestSize.Level1)
{
    uint64_t selfTokenId = GetSelfTokenID();

    // proxy is nullptr
    EXPECT_EQ(TokenSyncError::TOKEN_SYNC_IPC_ERROR,
        TokenSyncManagerClient::GetInstance().GetRemoteHapTokenInfo("", 0));

    StartOrStopTokenSyncService(true);

    // service is starting, but no permission(shell process)
    SetNativeTokenId("hdcd");
    int32_t selfUid = getuid();
    setuid(10001); // 10001： UID
    EXPECT_EQ(ERR_IDENTITY_CHECK_FAILED, TokenSyncManagerClient::GetInstance().GetRemoteHapTokenInfo("", 0));
    setuid(selfUid);

    // service is starting, and has permission(native process)
    SetNativeTokenId("accesstoken_service");
    EXPECT_EQ(TokenSyncError::TOKEN_SYNC_PARAMS_INVALID,
        TokenSyncManagerClient::GetInstance().GetRemoteHapTokenInfo("", 0));

    StartOrStopTokenSyncService(false);
    SetSelfTokenID(selfTokenId);
}

/**
 * @tc.name: DeleteRemoteHapTokenInfo001
 * @tc.desc: TokenSyncManagerProxy::DeleteRemoteHapTokenInfo function test
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(TokenSyncKitTest, DeleteRemoteHapTokenInfo001, TestSize.Level1)
{
    uint64_t selfTokenId = GetSelfTokenID();

    // proxy is nullptr
    EXPECT_EQ(TokenSyncError::TOKEN_SYNC_IPC_ERROR,
        TokenSyncManagerClient::GetInstance().DeleteRemoteHapTokenInfo(0));

    StartOrStopTokenSyncService(true);

    // service is starting, but no permission(shell process)
    SetNativeTokenId("hdcd");
    int32_t selfUid = getuid();
    setuid(10001); // 10001： UID
    EXPECT_EQ(ERR_IDENTITY_CHECK_FAILED, TokenSyncManagerClient::GetInstance().DeleteRemoteHapTokenInfo(0));
    setuid(selfUid);

    // service is starting, and has permission(native process)
    SetNativeTokenId("accesstoken_service");
    EXPECT_EQ(TokenSyncError::TOKEN_SYNC_PARAMS_INVALID,
        TokenSyncManagerClient::GetInstance().DeleteRemoteHapTokenInfo(0));

    StartOrStopTokenSyncService(false);
    SetSelfTokenID(selfTokenId);
}
} // namespace AccessToken
} // namespace Security
} // namespace OHOS
