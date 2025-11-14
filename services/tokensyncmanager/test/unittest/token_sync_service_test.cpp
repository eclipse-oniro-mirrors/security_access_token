/*
 * Copyright (c) 2021-2025 Huawei Device Co., Ltd.
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

#define private public
#include "remote_command_executor.h"
#include "token_sync_manager_service.h"
#undef private

#include "gtest/gtest.h"
#include "accesstoken_kit.h"
#include "accesstoken_common_log.h"
#include "access_token_error.h"
#include "base_remote_command.h"
#include "constant_common.h"
#include "delete_remote_token_command.h"
#include "device_info_manager.h"
#include "device_info_repository.h"
#include "device_info.h"
#include "device_manager.h"
#include "device_manager_callback.h"
#include "dm_device_info.h"
#include "i_token_sync_manager.h"
#define private public
#include "remote_command_manager.h"
#undef private
#include "socket.h"
#include "soft_bus_device_connection_listener.h"
#include "soft_bus_manager.h"
#include "soft_bus_socket_listener.h"
#include "test_common.h"
#include "token_setproc.h"
#include "token_sync_manager_stub.h"

using namespace std;
using namespace testing::ext;

namespace OHOS {
namespace Security {
namespace AccessToken {
static std::vector<std::thread> threads_;
static std::shared_ptr<SoftBusDeviceConnectionListener> g_ptrDeviceStateCallback =
    std::make_shared<SoftBusDeviceConnectionListener>();
static std::string g_udid = "deviceid-1:udid-001";
static int32_t g_selfUid;
static AccessTokenID g_selfTokenId = 0;
static const int32_t OUT_OF_MAP_SOCKET = 2;
static const std::string TOKEN_SYNC_PACKAGE_NAME = "ohos.security.distributed_access_token";
static const std::string TOKEN_SYNC_SOCKET_NAME = "ohos.security.atm_channel.";
static const uint32_t SOCKET_NAME_MAX_LEN = 256;
static const std::string JSON_APPID = "appID";
static const std::string JSON_DEVICEID = "deviceID";
static const std::string JSON_APL = "apl";
static const std::string DEFAULT_VALUE = "0";

class TokenSyncServiceTest : public testing::Test {
public:
    TokenSyncServiceTest();
    ~TokenSyncServiceTest();
    static void SetUpTestCase();
    static void TearDownTestCase();
    void OnDeviceOffline(const DistributedHardware::DmDeviceInfo &info);
    void SetUp();
    void TearDown();
    std::shared_ptr<TokenSyncManagerService> tokenSyncManagerService_;
};

static DistributedHardware::DmDeviceInfo g_devInfo = {
    // udid = deviceid-1:udid-001  uuid = deviceid-1:uuid-001
    .deviceId = "deviceid-1",
    .deviceName = "remote_mock",
    .deviceTypeId = 1,
    .networkId = "deviceid-1"
};

namespace {
static constexpr int MAX_RETRY_TIMES = 10;
static constexpr int32_t DEVICEID_MAX_LEN = 256;
}

TokenSyncServiceTest::TokenSyncServiceTest()
{
    DelayedSingleton<TokenSyncManagerService>::GetInstance()->Initialize();
}
TokenSyncServiceTest::~TokenSyncServiceTest()
{}

void NativeTokenGet()
{
    uint64_t tokenId = 0;
    tokenId = TestCommon::GetNativeTokenIdFromProcess("token_sync_service");
    ASSERT_NE(tokenId, static_cast<AccessTokenID>(0));
    EXPECT_EQ(0, SetSelfTokenID(tokenId));
}

void TokenSyncServiceTest::SetUpTestCase()
{
    g_selfUid = getuid();
    g_selfTokenId = GetSelfTokenID();
    TestCommon::SetTestEvironment(g_selfTokenId);

    NativeTokenGet();
}
void TokenSyncServiceTest::TearDownTestCase()
{
    SetSelfTokenID(g_selfTokenId);
    TestCommon::ResetTestEvironment();
}
void TokenSyncServiceTest::SetUp()
{
    tokenSyncManagerService_ = DelayedSingleton<TokenSyncManagerService>::GetInstance();
    EXPECT_NE(nullptr, tokenSyncManagerService_);
}
void TokenSyncServiceTest::TearDown()
{
    LOGI(ATM_DOMAIN, ATM_TAG, "TearDown start.");
    tokenSyncManagerService_ = nullptr;
    for (auto it = threads_.begin(); it != threads_.end(); it++) {
        it->join();
    }
    threads_.clear();

    if (g_ptrDeviceStateCallback != nullptr) {
        OnDeviceOffline(g_devInfo);
        sleep(1);
    }
}

void TokenSyncServiceTest::OnDeviceOffline(const DistributedHardware::DmDeviceInfo &info)
{
    std::string networkId = info.networkId;
    std::string uuid = SoftBusManager::GetInstance().ConvertToUniversallyUniqueIdOrFetch(networkId);
    std::string udid = SoftBusManager::GetInstance().ConvertToUniqueDeviceIdOrFetch(networkId);

    LOGI(ATM_DOMAIN, ATM_TAG,
        "networkId: %{public}s,  uuid: %{public}s, udid: %{public}s",
        networkId.c_str(),
        uuid.c_str(),
        ConstantCommon::EncryptDevId(udid).c_str());

    if (uuid != "" && udid != "") {
        RemoteCommandManager::GetInstance().NotifyDeviceOffline(uuid);
        RemoteCommandManager::GetInstance().NotifyDeviceOffline(udid);
        DeviceInfoManager::GetInstance().RemoveRemoteDeviceInfo(networkId, DeviceIdType::NETWORK_ID);
    } else {
        LOGE(ATM_DOMAIN, ATM_TAG, "uuid or udid is empty, offline failed.");
    }
}

namespace {
    std::string g_jsonBefore;
    std::string g_jsonAfter;
}

void SendTaskThread()
{
    int count = 0;
    while (!GetSendMessFlagMock() && count < MAX_RETRY_TIMES) {
        sleep(1);
        count++;
    }

    ResetSendMessFlagMock();

    std::string uuidMessage = GetUuidMock();
    std::string sendJson = g_jsonBefore + uuidMessage + g_jsonAfter;

    unsigned char *sendBuffer = (unsigned char *)malloc(0x1000);
    if (sendBuffer == nullptr) {
        return;
    }
    int sendLen = 0x1000;
    CompressMock(sendJson, sendBuffer, sendLen);

    SoftBusSocketListener::OnClientBytes(1, sendBuffer, sendLen);
    free(sendBuffer);
}

static PermissionDef g_infoManagerTestPermDef1 = {
    .permissionName = "ohos.permission.test1",
    .bundleName = "accesstoken_test",
    .grantMode = 1,
    .availableLevel = APL_NORMAL,
    .label = "label",
    .labelId = 1,
    .description = "open the door",
    .descriptionId = 1
};

static PermissionDef g_infoManagerTestPermDef2 = {
    .permissionName = "ohos.permission.test2",
    .bundleName = "accesstoken_test",
    .grantMode = 1,
    .availableLevel = APL_NORMAL,
    .label = "label",
    .labelId = 1,
    .description = "break the door",
    .descriptionId = 1
};

static PermissionStateFull g_infoManagerTestState1 = {
    .permissionName = "ohos.permission.test1",
    .isGeneral = true,
    .resDeviceID = {"local"},
    .grantStatus = {PermissionState::PERMISSION_GRANTED},
    .grantFlags = {1}
};

static PermissionStateFull g_infoManagerTestState2 = {
    .permissionName = "ohos.permission.test2",
    .isGeneral = false,
    .resDeviceID = {"device 1", "device 2"},
    .grantStatus = {PermissionState::PERMISSION_GRANTED, PermissionState::PERMISSION_GRANTED},
    .grantFlags = {1, 2}
};

static HapInfoParams g_infoManagerTestInfoParms = {
    .userID = 1,
    .bundleName = "accesstoken_test",
    .instIndex = 0,
    .appIDDesc = "testtesttesttest"
};

static HapPolicyParams g_infoManagerTestPolicyPrams = {
    .apl = APL_NORMAL,
    .domain = "test.domain",
    .permList = {g_infoManagerTestPermDef1, g_infoManagerTestPermDef2},
    .permStateList = {g_infoManagerTestState1, g_infoManagerTestState2}
};

class TestBaseRemoteCommand : public BaseRemoteCommand {
public:
    void Prepare() override {}

    void Execute() override {}

    void Finish() override {}

    std::string ToJsonPayload() override
    {
        return std::string();
    }

    TestBaseRemoteCommand() {}
    virtual ~TestBaseRemoteCommand() = default;
};

static void DeleteAndAllocToken(AccessTokenID& tokenId)
{
    // create local token
    AccessTokenIDEx tokenIdEx = TestCommon::GetHapTokenIdFromBundle(g_infoManagerTestInfoParms.userID,
        g_infoManagerTestInfoParms.bundleName, g_infoManagerTestInfoParms.instIndex);
    TestCommon::DeleteTestHapToken(tokenIdEx.tokenIdExStruct.tokenID);

    AccessTokenIDEx tokenIdEx1 = {0};
    TestCommon::AllocTestHapToken(g_infoManagerTestInfoParms, g_infoManagerTestPolicyPrams, tokenIdEx1);
    ASSERT_NE(static_cast<AccessTokenID>(0), tokenIdEx1.tokenIdExStruct.tokenID);
}

/**
 * @tc.name: ProcessOneCommand001
 * @tc.desc: RemoteCommandExecutor::ProcessOneCommand function test with nullptr
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(TokenSyncServiceTest, ProcessOneCommand001, TestSize.Level0)
{
    std::string nodeId = "test_nodeId";
    auto executor = std::make_shared<RemoteCommandExecutor>(nodeId);
    EXPECT_EQ(Constant::SUCCESS, executor->ProcessOneCommand(nullptr));
}

/**
 * @tc.name: ProcessOneCommand002
 * @tc.desc: RemoteCommandExecutor::ProcessOneCommand function test
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(TokenSyncServiceTest, ProcessOneCommand002, TestSize.Level0)
{
    std::string nodeId = "test_nodeId";
    auto executor = std::make_shared<RemoteCommandExecutor>(nodeId);
    auto cmd = std::make_shared<TestBaseRemoteCommand>();
    cmd->remoteProtocol_.statusCode = Constant::FAILURE;
    EXPECT_EQ(Constant::FAILURE, executor->ProcessOneCommand(cmd));
}

/**
 * @tc.name: ProcessOneCommand003
 * @tc.desc: RemoteCommandExecutor::ProcessOneCommand function test with status code 0
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(TokenSyncServiceTest, ProcessOneCommand003, TestSize.Level0)
{
    std::string nodeId = ConstantCommon::GetLocalDeviceId();
    auto executor = std::make_shared<RemoteCommandExecutor>(nodeId);
    auto cmd = std::make_shared<TestBaseRemoteCommand>();
    cmd->remoteProtocol_.statusCode = Constant::SUCCESS;
    EXPECT_EQ(Constant::FAILURE, executor->ProcessOneCommand(cmd));
}

/**
 * @tc.name: AddCommand001
 * @tc.desc: RemoteCommandExecutor::AddCommand function test with nullptr
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(TokenSyncServiceTest, AddCommand001, TestSize.Level0)
{
    std::string nodeId = "test_nodeId";
    auto executor = std::make_shared<RemoteCommandExecutor>(nodeId);
    EXPECT_EQ(Constant::INVALID_COMMAND, executor->AddCommand(nullptr));
}

/**
 * @tc.name: AddCommand002
 * @tc.desc: RemoteCommandExecutor::AddCommand function test
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(TokenSyncServiceTest, AddCommand002, TestSize.Level0)
{
    std::string nodeId = "test_nodeId";
    auto executor = std::make_shared<RemoteCommandExecutor>(nodeId);
    auto cmd = std::make_shared<TestBaseRemoteCommand>();
    EXPECT_EQ(Constant::SUCCESS, executor->AddCommand(cmd));
}

/**
 * @tc.name: ProcessBufferedCommands001
 * @tc.desc: RemoteCommandExecutor::ProcessBufferedCommands function test
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(TokenSyncServiceTest, ProcessBufferedCommands001, TestSize.Level0)
{
    std::string nodeId = "test_nodeId";
    auto executor = std::make_shared<RemoteCommandExecutor>(nodeId);
    executor->commands_.clear();
    EXPECT_EQ(Constant::SUCCESS, executor->ProcessBufferedCommands());
}

/**
 * @tc.name: ProcessBufferedCommands002
 * @tc.desc: RemoteCommandExecutor::ProcessBufferedCommands function test
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(TokenSyncServiceTest, ProcessBufferedCommands002, TestSize.Level0)
{
    std::string nodeId = "test_nodeId";
    auto executor = std::make_shared<RemoteCommandExecutor>(nodeId);
    auto cmd = std::make_shared<TestBaseRemoteCommand>();
    executor->commands_.emplace_back(cmd);
    EXPECT_EQ(Constant::SUCCESS, executor->ProcessBufferedCommands());
}

/**
 * @tc.name: ProcessBufferedCommands003
 * @tc.desc: RemoteCommandExecutor::ProcessBufferedCommands function test
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(TokenSyncServiceTest, ProcessBufferedCommands003, TestSize.Level0)
{
    std::string nodeId = "test_nodeId";
    auto executor = std::make_shared<RemoteCommandExecutor>(nodeId);
    auto cmd = std::make_shared<TestBaseRemoteCommand>();
    cmd->remoteProtocol_.statusCode = Constant::FAILURE_BUT_CAN_RETRY;
    executor->commands_.emplace_back(cmd);
    EXPECT_EQ(Constant::FAILURE, executor->ProcessBufferedCommands());
}

/**
 * @tc.name: ProcessBufferedCommands004
 * @tc.desc: RemoteCommandExecutor::ProcessBufferedCommands function test
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(TokenSyncServiceTest, ProcessBufferedCommands004, TestSize.Level0)
{
    std::string nodeId = "test_nodeId";
    auto executor = std::make_shared<RemoteCommandExecutor>(nodeId);
    auto cmd = std::make_shared<TestBaseRemoteCommand>();
    cmd->remoteProtocol_.statusCode = -3; // other error code
    executor->commands_.emplace_back(cmd);
    EXPECT_EQ(Constant::SUCCESS, executor->ProcessBufferedCommands());
}

/**
 * @tc.name: ClientProcessResult001
 * @tc.desc: RemoteCommandExecutor::ClientProcessResult function test
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(TokenSyncServiceTest, ClientProcessResult001, TestSize.Level0)
{
    std::string nodeId = "test_nodeId";
    auto executor = std::make_shared<RemoteCommandExecutor>(nodeId);
    auto cmd = std::make_shared<TestBaseRemoteCommand>();
    cmd->remoteProtocol_.statusCode = Constant::STATUS_CODE_BEFORE_RPC;
    EXPECT_EQ(Constant::FAILURE, executor->ClientProcessResult(cmd));
}

/**
 * @tc.name: ClientProcessResult002
 * @tc.desc: RemoteCommandExecutor::ClientProcessResult function test
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(TokenSyncServiceTest, ClientProcessResult002, TestSize.Level0)
{
    std::string nodeId = ConstantCommon::GetLocalDeviceId();
    auto executor = std::make_shared<RemoteCommandExecutor>(nodeId);
    auto cmd = std::make_shared<TestBaseRemoteCommand>();
    cmd->remoteProtocol_.statusCode = Constant::SUCCESS;
    EXPECT_EQ(Constant::SUCCESS, executor->ClientProcessResult(cmd));
    cmd->remoteProtocol_.statusCode = Constant::FAILURE;
    EXPECT_EQ(Constant::FAILURE, executor->ClientProcessResult(cmd));
}

/**
 * @tc.name: ToNativeTokenInfoJson001
 * @tc.desc: ToNativeTokenInfoJson function test
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(TokenSyncServiceTest, ToNativeTokenInfoJson001, TestSize.Level0)
{
    NativeTokenInfoBase native1 = {
        .ver = 1,
        .processName = "token_sync_test",
        .dcap = {"AT_CAP"},
        .tokenID = 1,
        .tokenAttr = 0,
        .nativeAcls = {},
    };
    auto cmd = std::make_shared<TestBaseRemoteCommand>();
    EXPECT_NE(nullptr, cmd->ToNativeTokenInfoJson(native1));
}

/**
 * @tc.name: FromPermStateListJson001
 * @tc.desc: FromPermStateListJson function test
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(TokenSyncServiceTest, FromPermStateListJson001, TestSize.Level0)
{
    HapTokenInfo baseInfo = {
        .ver = 1,
        .userID = 1,
        .bundleName = "com.ohos.access_token",
        .instIndex = 1,
        .tokenID = 0x20100000,
        .tokenAttr = 0
    };

    PermissionStatus infoManagerTestState = {
        .permissionName = "ohos.permission.test1",
        .grantStatus = PermissionState::PERMISSION_GRANTED,
        .grantFlag = PermissionFlag::PERMISSION_SYSTEM_FIXED};
    std::vector<PermissionStatus> permStateList;
    permStateList.emplace_back(infoManagerTestState);

    HapTokenInfoForSync remoteTokenInfo = {
        .baseInfo = baseInfo,
        .permStateList = permStateList
    };
    CJsonUnique hapTokenJson;
    auto cmd = std::make_shared<TestBaseRemoteCommand>();
    hapTokenJson = cmd->ToHapTokenInfosJson(remoteTokenInfo);

    HapTokenInfoForSync hap;
    cmd->FromHapTokenBasicInfoJson(hapTokenJson.get(), hap.baseInfo);
    cmd->FromPermStateListJson(hapTokenJson.get(), hap.permStateList);

    PermissionStatus state1 = {
        .permissionName = "ohos.permission.test1",
        .grantStatus = PermissionState::PERMISSION_GRANTED,
        .grantFlag = PermissionFlag::PERMISSION_SYSTEM_FIXED};
    CJsonUnique permStateJson = CreateJson();
    cmd->ToPermStateJson(permStateJson.get(), state1);

    PermissionStatus state2 = {
        .permissionName = "ohos.permission.test1",
        .grantStatus = PermissionState::PERMISSION_GRANTED,
        .grantFlag = PermissionFlag::PERMISSION_SYSTEM_FIXED};
    cmd->ToPermStateJson(permStateJson.get(), state2);

    EXPECT_EQ(hap.baseInfo.tokenID, remoteTokenInfo.baseInfo.tokenID);
}

/**
 * @tc.name: FromNativeTokenInfoJson001
 * @tc.desc: FromNativeTokenInfoJson function test
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(TokenSyncServiceTest, FromNativeTokenInfoJson001, TestSize.Level0)
{
    auto cmd = std::make_shared<TestBaseRemoteCommand>();

    CJsonUnique nativeTokenListJsonNull = CreateJson();
    NativeTokenInfoBase tokenNull;
    cmd->FromNativeTokenInfoJson(nativeTokenListJsonNull.get(), tokenNull);

    CJsonUnique hapTokenJsonNull = CreateJson();
    HapTokenInfo hapTokenBasicInfoNull;
    cmd->FromHapTokenBasicInfoJson(hapTokenJsonNull.get(), hapTokenBasicInfoNull);

    NativeTokenInfoBase native1 = {
        .apl = APL_NORMAL,
        .ver = 2,
        .processName = "token_sync_test",
        .dcap = {"AT_CAP"},
        .tokenID = 1,
        .tokenAttr = 0,
        .nativeAcls = {},
    };

    CJsonUnique nativeTokenListJson = cmd->ToNativeTokenInfoJson(native1);
    NativeTokenInfoBase token;
    cmd->FromNativeTokenInfoJson(nativeTokenListJson.get(), token);
    EXPECT_EQ(token.processName, "token_sync_test");
    EXPECT_EQ(token.apl, ATokenAplEnum::APL_NORMAL);
}

/**
 * @tc.name: FromPermStateListJson002
 * @tc.desc: FromPermStateListJson function test
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(TokenSyncServiceTest, FromPermStateListJson002, TestSize.Level0)
{
    auto cmd = std::make_shared<TestBaseRemoteCommand>();

    std::vector<PermissionStatus> permStateListNull;
    // lack grantStatus and grantFlag
    CJsonUnique hapTokenJsonNull = CreateJsonFromString("{\"bundleName\":\"\","
        "\"instIndex\":0,\"permState\":[{\"permissionName\":\"TEST\"}],"
        "\"tokenAttr\":0,\"tokenID\":111,\"userID\":0,\"version\":1}");
    cmd->FromPermStateListJson(hapTokenJsonNull.get(), permStateListNull);
    EXPECT_EQ(permStateListNull.size(), 0);

    permStateListNull.clear();
    // grantFlag
    hapTokenJsonNull = CreateJsonFromString("{\"bundleName\":\"\","
        "\"instIndex\":0,\"permState\":[{\"permissionName\":\"TEST\", \"grantStatus\":0}],"
        "\"tokenAttr\":0,\"tokenID\":111,\"userID\":0,\"version\":1}");
    cmd->FromPermStateListJson(hapTokenJsonNull.get(), permStateListNull);
    EXPECT_EQ(permStateListNull.size(), 0);


    permStateListNull.clear();
    // lack grantStatus and grantFlags in grantConfig
    hapTokenJsonNull = CreateJsonFromString("{\"bundleName\":\"test.bundle1\","
        "\"instIndex\":0,\"permState\":[{\"permissionName\":\"TEST\", "
        "\"isGeneral\":true,\"grantConfig\":[{\"resDeviceID\":\"0\"}]}],"
        "\"tokenAttr\":0,\"tokenID\":111,\"userID\":0,\"version\":1}");
    cmd->FromPermStateListJson(hapTokenJsonNull.get(), permStateListNull);
    EXPECT_EQ(permStateListNull.size(), 0);

    permStateListNull.clear();
    // lack grantFlags in grantConfig
    hapTokenJsonNull = CreateJsonFromString("{\"bundleName\":\"test.bundle1\","
        "\"instIndex\":0,\"permState\":[{\"permissionName\":\"TEST\", "
        "\"isGeneral\":true,\"grantConfig\":[{\"resDeviceID\":\"0\",\"grantStatus\":-1}]}],"
        "\"tokenAttr\":0,\"tokenID\":111,\"userID\":0,\"version\":1}");
    cmd->FromPermStateListJson(hapTokenJsonNull.get(), permStateListNull);
    EXPECT_EQ(permStateListNull.size(), 0);
}

/**
 * @tc.name: GetRemoteHapTokenInfo002
 * @tc.desc: test remote hap recv func
 * @tc.type: FUNC
 * @tc.require:AR000GK6T5 AR000GK6T9
 */
HWTEST_F(TokenSyncServiceTest, GetRemoteHapTokenInfo002, TestSize.Level0)
{
    LOGI(ATM_DOMAIN, ATM_TAG, "GetRemoteHapTokenInfo002 start.");

    ResetUuidMock();

    AccessTokenID tokenId = 0;
    DeleteAndAllocToken(tokenId);

    std::string jsonBefore =
        "{\"commandName\":\"SyncRemoteHapTokenCommand\",\"id\":\"0065e65f-\",\"jsonPayload\":"
        "\"{\\\"HapTokenInfo\\\":{\\\"bundleName\\\":\\\"\\\","
        "\\\"instIndex\\\":0,\\\"permState\\\":null,\\\"tokenAttr\\\":0,"
        "\\\"tokenID\\\":0,\\\"userID\\\":0,\\\"version\\\":1},\\\"commandName\\\":\\\"SyncRemoteHapTokenCommand\\\","
        "\\\"dstDeviceId\\\":\\\"local:udid-001\\\",\\\"dstDeviceLevel\\\":\\\"\\\",\\\"message\\\":\\\"success\\\","
        "\\\"requestTokenId\\\":";
    std::string jsonAfter = ",\\\"requestVersion\\\":2,\\\"responseDeviceId\\\":\\\"\\\",\\\"responseVersion\\\":2,"
        "\\\"srcDeviceId\\\":\\\"deviceid-1:udid-001\\\",\\\"srcDeviceLevel\\\":\\\"\\\",\\\"statusCode\\\":100001,"
        "\\\"uniqueId\\\":\\\"SyncRemoteHapTokenCommand\\\"}\",\"type\":\"request\"}";
    std::string recvJson = jsonBefore + std::to_string(tokenId) + jsonAfter;

    unsigned char *recvBuffer = (unsigned char *)malloc(0x1000);
    int recvLen = 0x1000;
    CompressMock(recvJson, recvBuffer, recvLen);

    ResetSendMessFlagMock();

    g_ptrDeviceStateCallback->OnDeviceOnline(g_devInfo); // create channel

    char networkId[DEVICEID_MAX_LEN + 1];
    char pkgName[SOCKET_NAME_MAX_LEN + 1];
    char peerName[SOCKET_NAME_MAX_LEN + 1];
    strcpy_s(networkId, DEVICEID_MAX_LEN, "deviceid-1:udid-001");
    strcpy_s(pkgName, SOCKET_NAME_MAX_LEN, TOKEN_SYNC_PACKAGE_NAME.c_str());
    strcpy_s(peerName, SOCKET_NAME_MAX_LEN, TOKEN_SYNC_SOCKET_NAME.c_str());
    PeerSocketInfo info = {
        .name = peerName,
        .networkId = networkId,
        .pkgName = pkgName
    };
    SoftBusSocketListener::OnBind(1, info);
    SoftBusSocketListener::OnClientBytes(1, recvBuffer, recvLen);
    int count = 0;
    while (!GetSendMessFlagMock() && count < MAX_RETRY_TIMES) {
        sleep(1);
        count++;
    }
    free(recvBuffer);

    ResetSendMessFlagMock();
    std::string uuidMessage = GetUuidMock();
    ASSERT_EQ(uuidMessage, "0065e65f-");
}

/**
 * @tc.name: GetRemoteHapTokenInfo003
 * @tc.desc: test remote hap send func, but get tokenInfo is wrong
 * @tc.type: FUNC
 * @tc.require:AR000GK6T5 AR000GK6T9
 */
HWTEST_F(TokenSyncServiceTest, GetRemoteHapTokenInfo003, TestSize.Level0)
{
    LOGI(ATM_DOMAIN, ATM_TAG, "GetRemoteHapTokenInfo003 start.");
    g_jsonBefore = "{\"commandName\":\"SyncRemoteHapTokenCommand\", \"id\":\"";
    // apl is error
    g_jsonAfter =
        "\",\"jsonPayload\":\"{\\\"HapTokenInfo\\\":{\\\"bundleName\\\":\\\"mock_token_sync\\\","
        "\\\"instIndex\\\":0,\\\"permState\\\":null,\\\"tokenAttr\\\":0,\\\"tokenID\\\":537919488,"
        "\\\"userID\\\":0,\\\"version\\\":1},\\\"commandName\\\":\\\"SyncRemoteHapTokenCommand\\\","
        "\\\"dstDeviceId\\\":\\\"deviceid-1:udid-001\\\","
        "\\\"dstDeviceLevel\\\":\\\"\\\",\\\"message\\\":\\\"success\\\","
        "\\\"requestTokenId\\\":537919488,\\\"requestVersion\\\":2,\\\"responseDeviceId\\\":\\\"deviceid-1:udid-001\\\""
        ",\\\"responseVersion\\\":2,\\\"srcDeviceId\\\":\\\"local:udid-001\\\",\\\"srcDeviceLevel\\\":\\\"\\\","
        "\\\"statusCode\\\":0,\\\"uniqueId\\\":\\\"SyncRemoteHapTokenCommand\\\"}\",\"type\":\"response\"}";

    g_ptrDeviceStateCallback->OnDeviceOnline(g_devInfo);
    sleep(3);
    threads_.emplace_back(std::thread(SendTaskThread));

    OHOS::DelayedSingleton<TokenSyncManagerService>::GetInstance()->GetRemoteHapTokenInfo(
        g_udid, 0x20100000);

    AccessTokenIDEx idEx = {0};
    idEx.tokenIDEx = AccessTokenKit::AllocLocalTokenID(g_udid, 0x20100000);
    AccessTokenID mapID = idEx.tokenIdExStruct.tokenID;
    ASSERT_EQ(mapID, static_cast<AccessTokenID>(0));
}

/**
 * @tc.name: GetRemoteHapTokenInfo004
 * @tc.desc: test remote hap send func, but json payload lost parameter
 * @tc.type: FUNC
 * @tc.require:AR000GK6T5 AR000GK6T9
 */
HWTEST_F(TokenSyncServiceTest, GetRemoteHapTokenInfo004, TestSize.Level0)
{
    LOGI(ATM_DOMAIN, ATM_TAG, "GetRemoteHapTokenInfo004 start.");
    g_jsonBefore = "{\"commandName\":\"SyncRemoteHapTokenCommand\", \"id\":\"";
    // lost tokenID
    g_jsonAfter =
        "\",\"jsonPayload\":\"{\\\"HapTokenInfo\\\":{\\\"bundleName\\\":\\\"mock_token_sync\\\","
        "\\\"permState\\\":null,\\\"tokenAttr\\\":0,"
        "\\\"userID\\\":0,\\\"version\\\":1},\\\"commandName\\\":\\\"SyncRemoteHapTokenCommand\\\","
        "\\\"dstDeviceId\\\":\\\"deviceid-1:udid-001\\\","
        "\\\"dstDeviceLevel\\\":\\\"\\\",\\\"message\\\":\\\"success\\\","
        "\\\"requestTokenId\\\":537919488,\\\"requestVersion\\\":2,\\\"responseDeviceId\\\":\\\"deviceid-1:udid-001\\\""
        ",\\\"responseVersion\\\":2,\\\"srcDeviceId\\\":\\\"local:udid-001\\\",\\\"srcDeviceLevel\\\":\\\"\\\","
        "\\\"statusCode\\\":0,\\\"uniqueId\\\":\\\"SyncRemoteHapTokenCommand\\\"}\",\"type\":\"response\"}";

    g_ptrDeviceStateCallback->OnDeviceOnline(g_devInfo);
    sleep(3);
    threads_.emplace_back(std::thread(SendTaskThread));

    OHOS::DelayedSingleton<TokenSyncManagerService>::GetInstance()->GetRemoteHapTokenInfo(
        g_udid, 0x20100000);

    AccessTokenIDEx idEx = {0};
    idEx.tokenIDEx = AccessTokenKit::AllocLocalTokenID(g_udid, 0x20100000);
    AccessTokenID mapID = idEx.tokenIdExStruct.tokenID;
    ASSERT_EQ(mapID, static_cast<AccessTokenID>(0));
}

/**
 * @tc.name: GetRemoteHapTokenInfo005
 * @tc.desc: test remote hap send func, but json payload parameter type is wrong
 * @tc.type: FUNC
 * @tc.require:AR000GK6T5 AR000GK6T9
 */
HWTEST_F(TokenSyncServiceTest, GetRemoteHapTokenInfo005, TestSize.Level0)
{
    LOGI(ATM_DOMAIN, ATM_TAG, "GetRemoteHapTokenInfo005 start.");
    g_jsonBefore = "{\"commandName\":\"SyncRemoteHapTokenCommand\", \"id\":\"";
    // instIndex is not number
    g_jsonAfter =
        "\",\"jsonPayload\":\"{\\\"HapTokenInfo\\\":{\\\"bundleName\\\":\\\"mock_token_sync\\\","
        "\\\"instIndex\\\":1,\\\"permState\\\":null,\\\"tokenAttr\\\":0,"
        "\\\"tokenID\\\":\\\"aaa\\\","
        "\\\"userID\\\":0,\\\"version\\\":1},\\\"commandName\\\":\\\"SyncRemoteHapTokenCommand\\\","
        "\\\"dstDeviceId\\\":\\\"deviceid-1:udid-001\\\","
        "\\\"dstDeviceLevel\\\":\\\"\\\",\\\"message\\\":\\\"success\\\","
        "\\\"requestTokenId\\\":537919488,\\\"requestVersion\\\":2,\\\"responseDeviceId\\\":\\\"deviceid-1:udid-001\\\""
        ",\\\"responseVersion\\\":2,\\\"srcDeviceId\\\":\\\"local:udid-001\\\",\\\"srcDeviceLevel\\\":\\\"\\\","
        "\\\"statusCode\\\":0,\\\"uniqueId\\\":\\\"SyncRemoteHapTokenCommand\\\"}\",\"type\":\"response\"}";

    g_ptrDeviceStateCallback->OnDeviceOnline(g_devInfo);
    sleep(3);

    threads_.emplace_back(std::thread(SendTaskThread));
    OHOS::DelayedSingleton<TokenSyncManagerService>::GetInstance()->GetRemoteHapTokenInfo(
        g_udid, 0x20100000);

    AccessTokenIDEx idEx = {0};
    idEx.tokenIDEx = AccessTokenKit::AllocLocalTokenID(g_udid, 0x20100000);
    AccessTokenID mapID = idEx.tokenIdExStruct.tokenID;
    ASSERT_EQ(mapID, static_cast<AccessTokenID>(0));
}

/**
 * @tc.name: GetRemoteHapTokenInfo006
 * @tc.desc: test remote hap send func, but json payload parameter format is wrong
 * @tc.type: FUNC
 * @tc.require:AR000GK6T5 AR000GK6T9
 */
HWTEST_F(TokenSyncServiceTest, GetRemoteHapTokenInfo006, TestSize.Level0)
{
    LOGI(ATM_DOMAIN, ATM_TAG, "GetRemoteHapTokenInfo006 start.");
    g_jsonBefore = "{\"commandName\":\"SyncRemoteHapTokenCommand\", \"id\":\"";
    // mock_token_sync lost \\\"
    g_jsonAfter =
        "\",\"jsonPayload\":\"{\\\"HapTokenInfo\\\":{\\\"bundleName\\\":\\\"mock_token_sync,"
        "\\\"111111\\\",\\\"instIndex\\\":1,\\\"permState\\\":null,\\\"tokenAttr\\\":0,"
        "\\\"tokenID\\\":537919488,"
        "\\\"userID\\\":0,\\\"version\\\":1},\\\"commandName\\\":\\\"SyncRemoteHapTokenCommand\\\","
        "\\\"dstDeviceId\\\":\\\"deviceid-1:udid-001\\\","
        "\\\"dstDeviceLevel\\\":\\\"\\\",\\\"message\\\":\\\"success\\\","
        "\\\"requestTokenId\\\":537919488,\\\"requestVersion\\\":2,\\\"responseDeviceId\\\":\\\"deviceid-1:udid-001\\\""
        ",\\\"responseVersion\\\":2,\\\"srcDeviceId\\\":\\\"local:udid-001\\\",\\\"srcDeviceLevel\\\":\\\"\\\","
        "\\\"statusCode\\\":0,\\\"uniqueId\\\":\\\"SyncRemoteHapTokenCommand\\\"}\",\"type\":\"response\"}";

    g_ptrDeviceStateCallback->OnDeviceOnline(g_devInfo);
    sleep(3);

    threads_.emplace_back(std::thread(SendTaskThread));

    OHOS::DelayedSingleton<TokenSyncManagerService>::GetInstance()->GetRemoteHapTokenInfo(
        g_udid, 0x20100000);

    AccessTokenIDEx idEx = {0};
    idEx.tokenIDEx = AccessTokenKit::AllocLocalTokenID(g_udid, 0x20100000);
    AccessTokenID mapID = idEx.tokenIdExStruct.tokenID;
    ASSERT_EQ(mapID, static_cast<AccessTokenID>(0));
}

/**
 * @tc.name: GetRemoteHapTokenInfo007
 * @tc.desc: test remote hap send func, statusCode is wrong
 * @tc.type: FUNC
 * @tc.require:AR000GK6T5 AR000GK6T9
 */
HWTEST_F(TokenSyncServiceTest, GetRemoteHapTokenInfo007, TestSize.Level0)
{
    LOGI(ATM_DOMAIN, ATM_TAG, "GetRemoteHapTokenInfo007 start.");
    g_jsonBefore = "{\"commandName\":\"SyncRemoteHapTokenCommand\", \"id\":\"";
    // statusCode error
    g_jsonAfter =
        "\",\"jsonPayload\":\"{\\\"HapTokenInfo\\\":{\\\"bundleName\\\":\\\"mock_token_sync\\\","
        "\\\"instIndex\\\":1,\\\"permState\\\":null,\\\"tokenAttr\\\":0,"
        "\\\"tokenID\\\":537919488,"
        "\\\"userID\\\":0,\\\"version\\\":1},\\\"commandName\\\":\\\"SyncRemoteHapTokenCommand\\\","
        "\\\"dstDeviceId\\\":\\\"deviceid-1\\\",\\\"dstDeviceLevel\\\":\\\"\\\",\\\"message\\\":\\\"success\\\","
        "\\\"requestTokenId\\\":537919488,\\\"requestVersion\\\":2,\\\"responseDeviceId\\\":\\\"deviceid-1:udid-001\\\""
        ",\\\"responseVersion\\\":2,\\\"srcDeviceId\\\":\\\"local:udid-001\\\",\\\"srcDeviceLevel\\\":\\\"\\\","
        "\\\"statusCode\\\":-2,\\\"uniqueId\\\":\\\"SyncRemoteHapTokenCommand\\\"}\","
        "\"type\":\"response\"}";

    g_ptrDeviceStateCallback->OnDeviceOnline(g_devInfo);
    sleep(3);
    threads_.emplace_back(std::thread(SendTaskThread));

    OHOS::DelayedSingleton<TokenSyncManagerService>::GetInstance()->GetRemoteHapTokenInfo(
        g_udid, 0x20100000);

    AccessTokenIDEx idEx = {0};
    idEx.tokenIDEx = AccessTokenKit::AllocLocalTokenID(g_udid, 0x20100000);
    AccessTokenID mapID = idEx.tokenIdExStruct.tokenID;
    ASSERT_EQ(mapID, static_cast<AccessTokenID>(0));
}

/**
 * @tc.name: GetRemoteHapTokenInfo008
 * @tc.desc: test remote hap recv func, tokenID is not exist
 * @tc.type: FUNC
 * @tc.require:AR000GK6T5 AR000GK6T9
 */
HWTEST_F(TokenSyncServiceTest, GetRemoteHapTokenInfo008, TestSize.Level0)
{
    LOGI(ATM_DOMAIN, ATM_TAG, "GetRemoteHapTokenInfo008 start.");
    // create local token
    AccessTokenIDEx tokenIdEx = TestCommon::GetHapTokenIdFromBundle(g_infoManagerTestInfoParms.userID,
        g_infoManagerTestInfoParms.bundleName, g_infoManagerTestInfoParms.instIndex);
    AccessTokenID tokenID = tokenIdEx.tokenIdExStruct.tokenID;
    TestCommon::DeleteTestHapToken(tokenID);

    // tokenID is not exist
    std::string jsonBefore =
        "{\"commandName\":\"SyncRemoteHapTokenCommand\",\"id\":\"0065e65f-\",\"jsonPayload\":"
        "\"{\\\"HapTokenInfo\\\":{\\\"bundleName\\\":\\\"\\\","
        "\\\"instIndex\\\":0,\\\"permState\\\":null,\\\"tokenAttr\\\":0,"
        "\\\"tokenID\\\":0,\\\"userID\\\":0,\\\"version\\\":1},\\\"commandName\\\":\\\"SyncRemoteHapTokenCommand\\\","
        "\\\"dstDeviceId\\\":\\\"local:udid-001\\\",\\\"dstDeviceLevel\\\":\\\"\\\",\\\"message\\\":\\\"success\\\","
        "\\\"requestTokenId\\\":";
    std::string tokenJsonStr = std::to_string(tokenID);
    std::string jsonAfter = ",\\\"requestVersion\\\":2,\\\"responseDeviceId\\\":\\\"\\\",\\\"responseVersion\\\":2,"
        "\\\"srcDeviceId\\\":\\\"deviceid-1:udid-001\\\",\\\"srcDeviceLevel\\\":\\\"\\\",\\\"statusCode\\\":100001,"
        "\\\"uniqueId\\\":\\\"SyncRemoteHapTokenCommand\\\"}\",\"type\":\"request\"}";

    // create recv message
    std::string recvJson = jsonBefore + tokenJsonStr + jsonAfter;
    unsigned char *recvBuffer = (unsigned char *)malloc(0x1000);
    int recvLen = 0x1000;
    CompressMock(recvJson, recvBuffer, recvLen);

    g_ptrDeviceStateCallback->OnDeviceOnline(g_devInfo);

    ResetSendMessFlagMock();
    SoftBusSocketListener::OnClientBytes(1, recvBuffer, recvLen);

    int count = 0;
    while (!GetSendMessFlagMock() && count < MAX_RETRY_TIMES) {
        sleep(1);
        count++;
    }
    free(recvBuffer);
    AccessTokenIDEx idEx = {0};
    idEx.tokenIDEx = AccessTokenKit::AllocLocalTokenID(g_udid, 0);
    AccessTokenID mapID = idEx.tokenIdExStruct.tokenID;
    ASSERT_EQ(mapID, static_cast<AccessTokenID>(0));
}

/**
 * @tc.name: DeleteRemoteTokenCommand001
 * @tc.desc: test delete remote token command
 * @tc.type: FUNC
 * @tc.require: Issue Number
 */
HWTEST_F(TokenSyncServiceTest, DeleteRemoteTokenCommand001, TestSize.Level0)
{
    std::string srcDeviceId = "001";
    std::string dstDeviceId = "002";
    AccessTokenID tokenID = 1;
    std::shared_ptr<DeleteRemoteTokenCommand> deleteRemoteTokenCommand =
        RemoteCommandFactory::GetInstance().NewDeleteRemoteTokenCommand(srcDeviceId, dstDeviceId, tokenID);
    ASSERT_EQ(deleteRemoteTokenCommand->remoteProtocol_.commandName, "DeleteRemoteTokenCommand");
    ASSERT_EQ(deleteRemoteTokenCommand->remoteProtocol_.uniqueId, "DeleteRemoteTokenCommand");
    ASSERT_EQ(deleteRemoteTokenCommand->remoteProtocol_.srcDeviceId, srcDeviceId);
    ASSERT_EQ(deleteRemoteTokenCommand->remoteProtocol_.dstDeviceId, dstDeviceId);
    ASSERT_EQ(
        // 2 is DISTRIBUTED_ACCESS_TOKEN_SERVICE_VERSION
        deleteRemoteTokenCommand->remoteProtocol_.responseVersion, 2);
    ASSERT_EQ(
        // 2 is DISTRIBUTED_ACCESS_TOKEN_SERVICE_VERSION
        deleteRemoteTokenCommand->remoteProtocol_.requestVersion, 2);

    deleteRemoteTokenCommand->Execute();
    deleteRemoteTokenCommand->Finish();
    ASSERT_EQ(deleteRemoteTokenCommand->remoteProtocol_.statusCode, Constant::SUCCESS);
}

/**
 * @tc.name: NewUpdateRemoteHapTokenCommand001
 * @tc.desc: test delete remote token command
 * @tc.type: FUNC
 * @tc.require: Issue Number
 */
HWTEST_F(TokenSyncServiceTest, NewUpdateRemoteHapTokenCommand001, TestSize.Level0)
{
    std::string srcDeviceId = "001";
    std::string dstDeviceId = "002";
    HapTokenInfoForSync tokenInfo;
    std::shared_ptr<UpdateRemoteHapTokenCommand> command =
        RemoteCommandFactory::GetInstance().NewUpdateRemoteHapTokenCommand(srcDeviceId, dstDeviceId, tokenInfo);
    ASSERT_EQ(command->remoteProtocol_.commandName, "UpdateRemoteHapTokenCommand");
    ASSERT_EQ(command->remoteProtocol_.uniqueId, "UpdateRemoteHapTokenCommand");
    command->Execute();
    command->Finish();
    ASSERT_EQ(command->remoteProtocol_.statusCode, Constant::SUCCESS);
}

/**
 * @tc.name: AddDeviceInfo001
 * @tc.desc: DeviceInfoManager::AddDeviceInfo function test
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(TokenSyncServiceTest, AddDeviceInfo001, TestSize.Level0)
{
    std::string networkId;
    std::string universallyUniqueId;
    std::string uniqueDeviceId;
    std::string deviceName;
    std::string deviceType;
    ASSERT_EQ("", networkId);
    ASSERT_EQ("", universallyUniqueId);
    ASSERT_EQ("", uniqueDeviceId);
    ASSERT_EQ("", deviceName);
    ASSERT_EQ("", deviceType);
    DeviceInfoManager::GetInstance().AddDeviceInfo(networkId, universallyUniqueId, uniqueDeviceId, deviceName,
        deviceType); // all empty

    networkId = "123";
    universallyUniqueId = "123";
    uniqueDeviceId = "123";
    deviceName = "123";
    deviceType = "123";
    ASSERT_NE("", networkId);
    ASSERT_NE("", universallyUniqueId);
    ASSERT_NE("", uniqueDeviceId);
    ASSERT_NE("", deviceName);
    ASSERT_NE("", deviceType);
    DeviceInfoManager::GetInstance().AddDeviceInfo(networkId, universallyUniqueId, uniqueDeviceId, deviceName,
        deviceType); // all valued

    std::string nodeId = uniqueDeviceId;
    DeviceIdType type = DeviceIdType::UNIQUE_DISABILITY_ID;
    DeviceInfoRepository::GetInstance().DeleteDeviceInfo(nodeId, type); // delete 123
}

/**
 * @tc.name: RemoveAllRemoteDeviceInfo001
 * @tc.desc: DeviceInfoManager::RemoveAllRemoteDeviceInfo function test
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(TokenSyncServiceTest, RemoveAllRemoteDeviceInfo001, TestSize.Level0)
{
    DeviceInfoManager::GetInstance().RemoveAllRemoteDeviceInfo(); // FindDeviceInfo false

    std::string networkId = "123";
    std::string universallyUniqueId = "123";
    std::string uniqueDeviceId;
    std::string deviceName = "123";
    std::string deviceType = "123";
    uniqueDeviceId = ConstantCommon::GetLocalDeviceId();
    ASSERT_EQ("local:udid-001", uniqueDeviceId);

    DeviceInfoManager::GetInstance().AddDeviceInfo(networkId, universallyUniqueId, uniqueDeviceId, deviceName,
        deviceType);
    DeviceInfoManager::GetInstance().RemoveAllRemoteDeviceInfo(); // FindDeviceInfo true

    std::string nodeId = uniqueDeviceId;
    DeviceIdType type = DeviceIdType::UNIQUE_DISABILITY_ID;
    DeviceInfoRepository::GetInstance().DeleteDeviceInfo(nodeId, type); // delete 123
}

/**
 * @tc.name: RemoveRemoteDeviceInfo001
 * @tc.desc: DeviceInfoManager::RemoveRemoteDeviceInfo function test
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(TokenSyncServiceTest, RemoveRemoteDeviceInfo001, TestSize.Level0)
{
    std::string nodeId;
    DeviceIdType deviceIdType = DeviceIdType::UNKNOWN;
    DeviceInfoManager::GetInstance().RemoveRemoteDeviceInfo(nodeId, deviceIdType); // nodeId invalid
    ASSERT_EQ("", nodeId);

    nodeId = "123";
    DeviceInfoManager::GetInstance().RemoveRemoteDeviceInfo(nodeId, deviceIdType); // FindDeviceInfo false

    std::string networkId = "123";
    std::string universallyUniqueId = "123";
    std::string uniqueDeviceId = "123";
    std::string deviceName = "123";
    std::string deviceType = "123";
    DeviceInfoManager::GetInstance().AddDeviceInfo(networkId, universallyUniqueId, uniqueDeviceId, deviceName,
        deviceType); // add 123 nodeid

    networkId = "456";
    universallyUniqueId = "456";
    uniqueDeviceId = ConstantCommon::GetLocalDeviceId();
    ASSERT_EQ("local:udid-001", uniqueDeviceId);
    deviceName = "456";
    deviceType = "456";
    DeviceInfoManager::GetInstance().AddDeviceInfo(networkId, universallyUniqueId, uniqueDeviceId, deviceName,
        deviceType); // add local unique deviceid

    nodeId = "123";
    deviceIdType = DeviceIdType::UNIQUE_DISABILITY_ID;
    // FindDeviceInfo true + uniqueDeviceId != localDevice true
    DeviceInfoManager::GetInstance().RemoveRemoteDeviceInfo(nodeId, deviceIdType); // delete 123

    nodeId = uniqueDeviceId;
    // FindDeviceInfo true + uniqueDeviceId != localDevice false
    DeviceInfoManager::GetInstance().RemoveRemoteDeviceInfo(nodeId, deviceIdType);

    nodeId = uniqueDeviceId;
    DeviceIdType type = DeviceIdType::UNIQUE_DISABILITY_ID;
    DeviceInfoRepository::GetInstance().DeleteDeviceInfo(nodeId, type); // delete local unique deviceid
}

/**
 * @tc.name: ConvertToUniversallyUniqueIdOrFetch001
 * @tc.desc: SoftBusManager::ConvertToUniversallyUniqueIdOrFetch function test
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(TokenSyncServiceTest, ConvertToUniversallyUniqueIdOrFetch001, TestSize.Level0)
{
    std::string nodeId;
    ASSERT_EQ("", DeviceInfoManager::GetInstance().ConvertToUniversallyUniqueId(nodeId));
    ASSERT_EQ("", SoftBusManager::GetInstance().ConvertToUniversallyUniqueIdOrFetch(nodeId)); // nodeId invalid

    nodeId = "123";
    // FindDeviceInfo false
    ASSERT_EQ("", DeviceInfoManager::GetInstance().ConvertToUniversallyUniqueId(nodeId));
    // GetUuidByNetworkId success
    ASSERT_EQ("123:uuid-001", SoftBusManager::GetInstance().ConvertToUniversallyUniqueIdOrFetch(nodeId));

    std::string networkId = "123";
    std::string universallyUniqueId = "123";
    std::string uniqueDeviceId = "123";
    std::string deviceName = "123";
    std::string deviceType = "123";
    DeviceInfoManager::GetInstance().AddDeviceInfo(networkId, universallyUniqueId, uniqueDeviceId, deviceName,
        deviceType); // add 123 nodeid

    nodeId = "123";
    // FindDeviceInfo true + universallyUniqueId is not empty
    SoftBusManager::GetInstance().ConvertToUniversallyUniqueIdOrFetch(nodeId);

    nodeId = uniqueDeviceId;
    // FindDeviceInfo true + uniqueDeviceId != localDevice false
    DeviceIdType deviceIdType = DeviceIdType::UNIQUE_DISABILITY_ID;
    DeviceInfoManager::GetInstance().RemoveRemoteDeviceInfo(nodeId, deviceIdType);

    nodeId = uniqueDeviceId;
    DeviceIdType type = DeviceIdType::UNIQUE_DISABILITY_ID;
    DeviceInfoRepository::GetInstance().DeleteDeviceInfo(nodeId, type); // delete 123
}

/**
 * @tc.name: ConvertToUniqueDeviceIdOrFetch001
 * @tc.desc: SoftBusManager::ConvertToUniqueDeviceIdOrFetch function test
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(TokenSyncServiceTest, ConvertToUniqueDeviceIdOrFetch001, TestSize.Level0)
{
    std::string nodeId;
    bool isFound;
    ASSERT_EQ("", DeviceInfoManager::GetInstance().ConvertToUniqueDeviceId(nodeId, isFound));
    ASSERT_EQ(false, isFound);
    ASSERT_EQ("", SoftBusManager::GetInstance().ConvertToUniqueDeviceIdOrFetch(nodeId)); // nodeId invalid

    nodeId = "123";
    // FindDeviceInfo false
    ASSERT_EQ("", DeviceInfoManager::GetInstance().ConvertToUniqueDeviceId(nodeId, isFound));
    ASSERT_EQ(false, isFound);
    ASSERT_EQ("", SoftBusManager::GetInstance().ConvertToUniqueDeviceIdOrFetch(nodeId));

    std::string networkId = "123";
    std::string universallyUniqueId = "123";
    std::string uniqueDeviceId = "123";
    std::string deviceName = "123";
    std::string deviceType = "123";
    DeviceInfoManager::GetInstance().AddDeviceInfo(networkId, universallyUniqueId, uniqueDeviceId, deviceName,
        deviceType); // add 123 nodeid

    nodeId = "123";
    // FindDeviceInfo true + universallyUniqueId is not empty
    DeviceInfoManager::GetInstance().ConvertToUniqueDeviceId(nodeId, isFound);
    ASSERT_EQ(true, isFound);
    SoftBusManager::GetInstance().ConvertToUniqueDeviceIdOrFetch(nodeId);

    nodeId = uniqueDeviceId;
    // FindDeviceInfo true + uniqueDeviceId != localDevice false
    DeviceIdType deviceIdType = DeviceIdType::UNIQUE_DISABILITY_ID;
    DeviceInfoManager::GetInstance().RemoveRemoteDeviceInfo(nodeId, deviceIdType);

    nodeId = uniqueDeviceId;
    DeviceIdType type = DeviceIdType::UNIQUE_DISABILITY_ID;
    DeviceInfoRepository::GetInstance().DeleteDeviceInfo(nodeId, type); // delete 123
}

/**
 * @tc.name: IsDeviceUniversallyUniqueId001
 * @tc.desc: DeviceInfoManager::IsDeviceUniversallyUniqueId function test
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(TokenSyncServiceTest, IsDeviceUniversallyUniqueId001, TestSize.Level0)
{
    std::string nodeId;
    ASSERT_EQ(false, DeviceInfoManager::GetInstance().IsDeviceUniversallyUniqueId(nodeId)); // nodeId invalid

    nodeId = "123";
    ASSERT_EQ(false, DeviceInfoManager::GetInstance().IsDeviceUniversallyUniqueId(nodeId)); // FindDeviceInfo false

    std::string networkId = "123";
    std::string universallyUniqueId = "123";
    std::string uniqueDeviceId = "123";
    std::string deviceName = "123";
    std::string deviceType = "123";
    DeviceInfoManager::GetInstance().AddDeviceInfo(networkId, universallyUniqueId, uniqueDeviceId, deviceName,
        deviceType); // add 123 nodeid

    ASSERT_EQ(true, DeviceInfoManager::GetInstance().IsDeviceUniversallyUniqueId(nodeId)); // FindDeviceInfo true

    nodeId = uniqueDeviceId;
    DeviceIdType type = DeviceIdType::UNIQUE_DISABILITY_ID;
    DeviceInfoRepository::GetInstance().DeleteDeviceInfo(nodeId, type); // delete 123
}

/**
 * @tc.name: FindDeviceInfo001
 * @tc.desc: DeviceInfoRepository::FindDeviceInfo function test
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(TokenSyncServiceTest, FindDeviceInfo001, TestSize.Level0)
{
    std::string networkId = "123";
    std::string universallyUniqueId = "123";
    std::string uniqueDeviceId = "123";
    std::string deviceName = "123";
    std::string deviceType = "123";

    DeviceId deviceId;
    deviceId.networkId = networkId;
    deviceId.universallyUniqueId = universallyUniqueId;
    deviceId.uniqueDeviceId = uniqueDeviceId;
    DeviceInfo deviceInfo;
    // count > 0 false
    DeviceIdType type = DeviceIdType::UNKNOWN;
    ASSERT_EQ(false, DeviceInfoRepository::GetInstance().FindDeviceInfo("456", type, deviceInfo));

    DeviceInfoRepository::GetInstance().SaveDeviceInfo(networkId, universallyUniqueId, uniqueDeviceId, deviceName,
        deviceType); // add 123 nodeid

    type = DeviceIdType::NETWORK_ID;
    // count > 0 true
    ASSERT_EQ(true, DeviceInfoRepository::GetInstance().FindDeviceInfo(networkId, type, deviceInfo));

    type = DeviceIdType::UNIVERSALLY_UNIQUE_ID;
    // count > 0 true
    ASSERT_EQ(true, DeviceInfoRepository::GetInstance().FindDeviceInfo(universallyUniqueId, type, deviceInfo));

    type = DeviceIdType::UNIQUE_DISABILITY_ID;
    // count > 0 true
    ASSERT_EQ(true, DeviceInfoRepository::GetInstance().FindDeviceInfo(uniqueDeviceId, type, deviceInfo));

    type = DeviceIdType::UNKNOWN;
    // count > 0 true
    ASSERT_EQ(true, DeviceInfoRepository::GetInstance().FindDeviceInfo(networkId, type, deviceInfo));

    std::string nodeId = uniqueDeviceId;
    type = DeviceIdType::UNIQUE_DISABILITY_ID;
    DeviceInfoRepository::GetInstance().DeleteDeviceInfo(nodeId, type); // delete 123
}

/**
 * @tc.name: GetRemoteHapTokenInfo001
 * @tc.desc: TokenSyncManagerService::GetRemoteHapTokenInfo function test
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(TokenSyncServiceTest, GetRemoteHapTokenInfo001, TestSize.Level0)
{
    std::string deviceID = "dev-001";
    AccessTokenID tokenID = 123; // 123 is random input

    // FindDeviceInfo failed
    ASSERT_EQ(TokenSyncError::TOKEN_SYNC_REMOTE_DEVICE_INVALID,
        tokenSyncManagerService_->GetRemoteHapTokenInfo(deviceID, tokenID));
}

/**
 * @tc.name: DeleteRemoteHapTokenInfo001
 * @tc.desc: TokenSyncManagerService::DeleteRemoteHapTokenInfo function test
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(TokenSyncServiceTest, DeleteRemoteHapTokenInfo001, TestSize.Level0)
{
    AccessTokenID tokenId;

    tokenId = 0;
    // Params is wrong, token id is invalid
    ASSERT_EQ(TokenSyncError::TOKEN_SYNC_PARAMS_INVALID,
        tokenSyncManagerService_->DeleteRemoteHapTokenInfo(tokenId));

    std::string networkId = "123";
    std::string universallyUniqueId = "123";
    std::string uniqueDeviceId = "123";
    std::string deviceName = "123";
    std::string deviceType = "123";
    DeviceInfoManager::GetInstance().AddDeviceInfo(networkId, universallyUniqueId, uniqueDeviceId, deviceName,
        deviceType); // add nodeId 123
    networkId = "456";
    universallyUniqueId = "456";
    std::string localUdid = ConstantCommon::GetLocalDeviceId();
    deviceName = "456";
    deviceType = "456";
    DeviceInfoManager::GetInstance().AddDeviceInfo(networkId, universallyUniqueId, localUdid, deviceName,
        deviceType); // add nodeId 456
    tokenId = 123; // 123 is random input
    // no need notify local device
    ASSERT_EQ(TokenSyncError::TOKEN_SYNC_SUCCESS, tokenSyncManagerService_->DeleteRemoteHapTokenInfo(tokenId));

    HapTokenInfoForSync tokenInfo;
    ASSERT_EQ(TokenSyncError::TOKEN_SYNC_SUCCESS, tokenSyncManagerService_->UpdateRemoteHapTokenInfo(tokenInfo));
}

/**
 * @tc.name: ExistDeviceInfo001
 * @tc.desc: TokenSyncManagerService::ExistDeviceInfo function test
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(TokenSyncServiceTest, ExistDeviceInfo001, TestSize.Level0)
{
    std::string nodeId = "111";
    DeviceIdType type = DeviceIdType::NETWORK_ID;
    EXPECT_FALSE(DeviceInfoManager::GetInstance().ExistDeviceInfo(nodeId, type));
}

class TestStub : public TokenSyncManagerStub {
public:
    TestStub() = default;
    virtual ~TestStub() = default;

    int GetRemoteHapTokenInfo(const std::string& deviceID, AccessTokenID tokenID)
    {
        return 0;
    }

    int DeleteRemoteHapTokenInfo(AccessTokenID tokenID)
    {
        return 0;
    }

    int UpdateRemoteHapTokenInfo(const HapTokenInfoForSync& tokenInfo)
    {
        return 0;
    }
};

/**
 * @tc.name: OnRemoteRequest001
 * @tc.desc: TokenSyncManagerStub::OnRemoteRequest function test
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(TokenSyncServiceTest, OnRemoteRequest001, TestSize.Level0)
{
    OHOS::MessageParcel data;
    OHOS::MessageParcel reply;
    OHOS::MessageOption option(OHOS::MessageOption::TF_SYNC);
    TestStub sub;

    ASSERT_EQ(true, data.WriteInterfaceToken(ITokenSyncManager::GetDescriptor()));
    uint32_t code = 10;
    ASSERT_NE(0, sub.OnRemoteRequest(code, data, reply, option)); // msgCode default

    ASSERT_EQ(true, data.WriteInterfaceToken(ITokenSyncManager::GetDescriptor()));
    // msgCode GET_REMOTE_HAP_TOKEN_INFO + type != TOKEN_NATIVE
    ASSERT_EQ(NO_ERROR, sub.OnRemoteRequest(static_cast<uint32_t>(
        TokenSyncInterfaceCode::GET_REMOTE_HAP_TOKEN_INFO), data, reply, option));

    ASSERT_EQ(true, data.WriteInterfaceToken(ITokenSyncManager::GetDescriptor()));
    // msgCode DELETE_REMOTE_HAP_TOKEN_INFO + type != TOKEN_NATIVE
    ASSERT_EQ(NO_ERROR, sub.OnRemoteRequest(static_cast<uint32_t>(
        TokenSyncInterfaceCode::DELETE_REMOTE_HAP_TOKEN_INFO), data, reply, option));

    ASSERT_EQ(true, data.WriteInterfaceToken(ITokenSyncManager::GetDescriptor()));
    // msgCode UPDATE_REMOTE_HAP_TOKEN_INFO + type != TOKEN_NATIVE
    ASSERT_EQ(NO_ERROR, sub.OnRemoteRequest(static_cast<uint32_t>(
        TokenSyncInterfaceCode::UPDATE_REMOTE_HAP_TOKEN_INFO), data, reply, option));
}

/**
 * @tc.name: OnRemoteRequest002
 * @tc.desc: TokenSyncManagerStub::OnRemoteRequest function test
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(TokenSyncServiceTest, OnRemoteRequest002, TestSize.Level0)
{
    OHOS::MessageParcel data;
    OHOS::MessageParcel reply;
    OHOS::MessageOption option(OHOS::MessageOption::TF_SYNC);
    TestStub sub;
    auto tokenId = GetSelfTokenID();
    EXPECT_EQ(0, SetSelfTokenID(g_selfTokenId));
    setuid(1234);
    ASSERT_EQ(true, data.WriteInterfaceToken(ITokenSyncManager::GetDescriptor()));
    
    ASSERT_EQ(NO_ERROR, sub.OnRemoteRequest(static_cast<uint32_t>(
        TokenSyncInterfaceCode::GET_REMOTE_HAP_TOKEN_INFO), data, reply, option));

    ASSERT_EQ(true, data.WriteInterfaceToken(ITokenSyncManager::GetDescriptor()));
    
    ASSERT_EQ(NO_ERROR, sub.OnRemoteRequest(static_cast<uint32_t>(
        TokenSyncInterfaceCode::DELETE_REMOTE_HAP_TOKEN_INFO), data, reply, option));

    ASSERT_EQ(true, data.WriteInterfaceToken(ITokenSyncManager::GetDescriptor()));

    ASSERT_EQ(NO_ERROR, sub.OnRemoteRequest(static_cast<uint32_t>(
        TokenSyncInterfaceCode::UPDATE_REMOTE_HAP_TOKEN_INFO), data, reply, option));
    
    ASSERT_EQ(ERR_IDENTITY_CHECK_FAILED, reply.ReadInt32());

    setuid(g_selfUid);
    EXPECT_EQ(0, SetSelfTokenID(tokenId));
}

/**
 * @tc.name: OnStart001
 * @tc.desc: TokenSyncManagerStub::OnStart function test
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(TokenSyncServiceTest, OnStart001, TestSize.Level0)
{
    tokenSyncManagerService_->OnStop();
    ASSERT_EQ(ServiceRunningState::STATE_NOT_START, tokenSyncManagerService_->state_);
    tokenSyncManagerService_->OnStart();
    ASSERT_EQ(ServiceRunningState::STATE_RUNNING, tokenSyncManagerService_->state_);
    tokenSyncManagerService_->OnStart();
}

/**
 * @tc.name: RemoteCommandManager001
 * @tc.desc: RemoteCommandManager001 function test
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(TokenSyncServiceTest, RemoteCommandManager001, TestSize.Level0)
{
    RemoteCommandManager::GetInstance().Init();
    std::string udid = "test_udId";
    auto cmd = std::make_shared<TestBaseRemoteCommand>();
    char networkId[DEVICEID_MAX_LEN + 1];
    char pkgName[SOCKET_NAME_MAX_LEN + 1];
    char peerName[SOCKET_NAME_MAX_LEN + 1];
    strcpy_s(networkId, DEVICEID_MAX_LEN, "deviceid-1:udid-001");
    strcpy_s(pkgName, SOCKET_NAME_MAX_LEN, TOKEN_SYNC_PACKAGE_NAME.c_str());
    strcpy_s(peerName, SOCKET_NAME_MAX_LEN, TOKEN_SYNC_SOCKET_NAME.c_str());
    PeerSocketInfo info = {
        .name = peerName,
        .networkId = networkId,
        .pkgName = pkgName
    };
    int recvLen = 0x1000;
    SoftBusSocketListener::OnBind(0, info);
    int32_t ret = RemoteCommandManager::GetInstance().AddCommand(udid, cmd);
    ASSERT_EQ(Constant::SUCCESS, ret);
    ret = RemoteCommandManager::GetInstance().AddCommand("", cmd);
    ASSERT_EQ(Constant::FAILURE, ret);
    SoftBusSocketListener::OnServiceBytes(0, nullptr, recvLen);
    ret = RemoteCommandManager::GetInstance().AddCommand(udid, nullptr);
    ASSERT_EQ(Constant::FAILURE, ret);
    SoftBusSocketListener::OnClientBytes(0, nullptr, recvLen);
    ret = RemoteCommandManager::GetInstance().AddCommand("", nullptr);
    ASSERT_EQ(Constant::FAILURE, ret);
    SoftBusSocketListener::OnShutdown(0, SHUTDOWN_REASON_UNKNOWN);
}

/**
 * @tc.name: RemoteCommandManager002
 * @tc.desc: RemoteCommandManager002 function test
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(TokenSyncServiceTest, RemoteCommandManager002, TestSize.Level0)
{
    RemoteCommandManager::GetInstance().Init();
    std::string udid = "test_udId_1";
    int32_t ret = RemoteCommandManager::GetInstance().ProcessDeviceCommandImmediately(udid);
    ASSERT_EQ(Constant::FAILURE, ret);
    ret = RemoteCommandManager::GetInstance().ProcessDeviceCommandImmediately("");
    ASSERT_EQ(Constant::FAILURE, ret);
    SoftBusSocketListener::OnShutdown(1, SHUTDOWN_REASON_UNKNOWN);
}

/**
 * @tc.name: RemoteCommandManager003
 * @tc.desc: RemoteCommandManager003 function test
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(TokenSyncServiceTest, RemoteCommandManager003, TestSize.Level0)
{
    RemoteCommandManager::GetInstance().Init();
    std::string nodeId = "test_udId";
    int32_t ret = RemoteCommandManager::GetInstance().NotifyDeviceOnline("");
    ASSERT_EQ(Constant::FAILURE, ret);
    ret = RemoteCommandManager::GetInstance().NotifyDeviceOnline(nodeId);
    ASSERT_EQ(Constant::SUCCESS, ret);
    SoftBusSocketListener::OnShutdown(OUT_OF_MAP_SOCKET, SHUTDOWN_REASON_UNKNOWN);
}

/**
 * @tc.name: RemoteCommandManager004
 * @tc.desc: RemoteCommandManager004 function test
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(TokenSyncServiceTest, RemoteCommandManager004, TestSize.Level0)
{
    RemoteCommandManager::GetInstance().Init();
    std::string udid = "test_udId";
    auto cmd = std::make_shared<TestBaseRemoteCommand>();
    char networkId[DEVICEID_MAX_LEN + 1];
    char pkgName[SOCKET_NAME_MAX_LEN + 1];
    char peerName[SOCKET_NAME_MAX_LEN + 1];
    strcpy_s(networkId, DEVICEID_MAX_LEN, "deviceid-1:udid-001");
    strcpy_s(pkgName, SOCKET_NAME_MAX_LEN, TOKEN_SYNC_PACKAGE_NAME.c_str());
    strcpy_s(peerName, SOCKET_NAME_MAX_LEN, "invalid");
    PeerSocketInfo info = {
        .name = peerName,
        .networkId = networkId,
        .pkgName = pkgName
    };
    SoftBusSocketListener::OnBind(1, info);
    int32_t ret = RemoteCommandManager::GetInstance().AddCommand(udid, cmd);
    ASSERT_EQ(Constant::SUCCESS, ret);
}

/**
 * @tc.name: RemoteCommandManager005
 * @tc.desc: RemoteCommandManager005 function test
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(TokenSyncServiceTest, RemoteCommandManager005, TestSize.Level0)
{
    RemoteCommandManager::GetInstance().Init();
    std::string udid = "test_udId";
    auto cmd = std::make_shared<TestBaseRemoteCommand>();
    char networkId[DEVICEID_MAX_LEN + 1];
    char pkgName[SOCKET_NAME_MAX_LEN + 1];
    char peerName[SOCKET_NAME_MAX_LEN + 1];
    strcpy_s(networkId, DEVICEID_MAX_LEN, "deviceid-1:udid-001");
    strcpy_s(pkgName, SOCKET_NAME_MAX_LEN, "invalid");
    strcpy_s(peerName, SOCKET_NAME_MAX_LEN, TOKEN_SYNC_SOCKET_NAME.c_str());
    PeerSocketInfo info = {
        .name = peerName,
        .networkId = networkId,
        .pkgName = pkgName
    };
    SoftBusSocketListener::OnBind(1, info);
    int32_t ret = RemoteCommandManager::GetInstance().AddCommand(udid, cmd);
    ASSERT_EQ(Constant::SUCCESS, ret);
}

/**
 * @tc.name: ProcessDeviceCommandImmediately001
 * @tc.desc: ProcessDeviceCommandImmediately function test
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(TokenSyncServiceTest, ProcessDeviceCommandImmediately001, TestSize.Level0)
{
    std::string udid = "test_udId_1";
    RemoteCommandManager::GetInstance().executors_[udid] = nullptr;
    int32_t ret = RemoteCommandManager::GetInstance().ProcessDeviceCommandImmediately(udid);
    ASSERT_EQ(Constant::FAILURE, ret);
    ASSERT_EQ(1, RemoteCommandManager::GetInstance().executors_.erase(udid));
}

/**
 * @tc.name: ProcessBufferedCommandsWithThread001
 * @tc.desc: RemoteCommandExecutor::ProcessBufferedCommandsWithThread function test
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(TokenSyncServiceTest, ProcessBufferedCommandsWithThread001, TestSize.Level0)
{
    std::string nodeId = "test_nodeId";
    auto executor = std::make_shared<RemoteCommandExecutor>(nodeId);
    executor->ProcessBufferedCommandsWithThread();
    EXPECT_FALSE(executor->running_);
    auto cmd = std::make_shared<TestBaseRemoteCommand>();
    cmd->remoteProtocol_.statusCode = Constant::FAILURE_BUT_CAN_RETRY;
    executor->commands_.emplace_back(cmd);
    executor->running_ = true;
    executor->ProcessBufferedCommandsWithThread();
    executor->running_ = false;
    executor->ProcessBufferedCommandsWithThread();
    EXPECT_TRUE(executor->running_);
}

namespace {
PermissionStatus g_infoManagerTestUpdateState1 = {
    .permissionName = "ohos.permission.CAMERA",
    .grantStatus = PermissionState::PERMISSION_DENIED,
    .grantFlag = 1
};

PermissionStatus g_infoManagerTestUpdateState2 = {
    .permissionName = "ohos.permission.ANSWER_CALL",
    .grantStatus = PermissionState::PERMISSION_DENIED,
    .grantFlag = 1
};

HapTokenInfo g_remoteHapInfoBasic = {
    .ver = 1,
    .userID = 1,
    .bundleName = "accesstoken_test",
    .instIndex = 1,
    .tokenID = 0x20000001,
    .tokenAttr = 0
};

HapTokenInfoForSync g_remoteHapInfo = {
    .baseInfo = g_remoteHapInfoBasic,
    .permStateList = {g_infoManagerTestUpdateState1, g_infoManagerTestUpdateState2}
};

/**
 * @tc.name: CompatibleOldVersionHapTokenInfo001
 * @tc.desc: test the info when filling the new hap token info
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(TokenSyncServiceTest, CompatibleOldVersionHapTokenInfo001, TestSize.Level0)
{
    HapTokenInfo baseInfo = {
        .ver = 1,
        .userID = 1,
        .bundleName = "com.ohos.access_token",
        .instIndex = 1,
        .tokenID = 0x20100000,
        .tokenAttr = 0
    };

    PermissionStatus infoManagerTestState = {
        .permissionName = "ohos.permission.test1",
        .grantStatus = PermissionState::PERMISSION_GRANTED,
        .grantFlag = PermissionFlag::PERMISSION_SYSTEM_FIXED};
    std::vector<PermissionStatus> permStateList;
    permStateList.emplace_back(infoManagerTestState);

    HapTokenInfoForSync remoteTokenInfo = {
        .baseInfo = baseInfo,
        .permStateList = permStateList
    };

    auto cmd = std::make_shared<TestBaseRemoteCommand>();
    CJsonUnique hapTokenJsonUnique = cmd->ToHapTokenInfosJson(remoteTokenInfo);
    // test appID, deviceID, apl equal defaut value
    EXPECT_NE(hapTokenJsonUnique, nullptr);
    CJson* hapTokenJson = hapTokenJsonUnique.get();
    std::string  appID = "";
    EXPECT_EQ(GetStringFromJson(hapTokenJson, JSON_APPID, appID), true);
    EXPECT_EQ(appID, DEFAULT_VALUE);
    std::string  deviceID = "";
    EXPECT_EQ(GetStringFromJson(hapTokenJson, JSON_DEVICEID, deviceID), true);
    EXPECT_EQ(deviceID, DEFAULT_VALUE);
    int32_t apl = 0;
    EXPECT_EQ(GetIntFromJson(hapTokenJson, JSON_APL, apl), true);
    EXPECT_EQ(apl, static_cast<int32_t>(APL_NORMAL));

    CJson* jsonObjTmp = GetArrayFromJson(hapTokenJson, "permState");
    ASSERT_NE(jsonObjTmp, nullptr);
    int32_t len = cJSON_GetArraySize(jsonObjTmp);
    ASSERT_EQ(len, 1);
    CJson* permissionJson = cJSON_GetArrayItem(jsonObjTmp, 0);
    bool isGeneral = false;
    EXPECT_EQ(GetBoolFromJson(permissionJson, "isGeneral", isGeneral), true);
    EXPECT_EQ(isGeneral, true);
    CJson* grantConfig = GetArrayFromJson(permissionJson, "grantConfig");
    ASSERT_NE(grantConfig, nullptr);
    int32_t configLen = cJSON_GetArraySize(grantConfig);
    ASSERT_EQ(configLen, 1);

    CJson* grantConfigItem = cJSON_GetArrayItem(grantConfig, 0);
    ASSERT_NE(grantConfigItem, nullptr);
    std::string resDeviceID = "";
    EXPECT_EQ(GetStringFromJson(grantConfigItem, "resDeviceID", resDeviceID), true);
    EXPECT_EQ(resDeviceID, DEFAULT_VALUE);
}

/**
 * @tc.name: CompatibleOldVersionHapTokenInfo002
 * @tc.desc: test the info when read old version hap token info
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(TokenSyncServiceTest, CompatibleOldVersionHapTokenInfo002, TestSize.Level0)
{
    // current version json string
    CJsonUnique hapTokenJson = CreateJsonFromString("{\"bundleName\":\"test.bundle1\","
        "\"instIndex\":0,\"permState\":[{\"permissionName\":\"TEST\", "
        "\"grantStatus\":0, \"grantFlag\":0,\"isGeneral\":true,\"grantConfig\":"
        "[{\"resDeviceID\":\"0\",\"grantStatus\":-1, \"grantFlags\":0}]}],\"tokenAttr\":0,"
        "\"tokenID\":111,\"userID\":0,\"version\":1}");
    auto cmd = std::make_shared<TestBaseRemoteCommand>();

    std::vector<PermissionStatus> permStateList;
    cmd->FromPermStateListJson(hapTokenJson.get(), permStateList);
    ASSERT_EQ(permStateList.size(), 1);
    EXPECT_EQ(permStateList[0].permissionName, "TEST");
    EXPECT_EQ(permStateList[0].grantStatus, static_cast<int32_t>(PermissionState::PERMISSION_GRANTED));
    EXPECT_EQ(permStateList[0].grantFlag, 0);
    permStateList.clear();

    // old version 1 json string
    hapTokenJson = CreateJsonFromString("{\"bundleName\":\"test.bundle1\","
        "\"instIndex\":0,\"permState\":[{\"permissionName\":\"TEST\", "
        "\"grantStatus\":0, \"grantFlag\":0}],\"tokenAttr\":0,"
        "\"tokenID\":111,\"userID\":0,\"version\":1}");
    cmd->FromPermStateListJson(hapTokenJson.get(), permStateList);
    ASSERT_EQ(permStateList.size(), 1);
    EXPECT_EQ(permStateList[0].permissionName, "TEST");
    EXPECT_EQ(permStateList[0].grantStatus, static_cast<int32_t>(PermissionState::PERMISSION_GRANTED));
    EXPECT_EQ(permStateList[0].grantFlag, 0);
    permStateList.clear();

    // old version 2 json string
    hapTokenJson = CreateJsonFromString("{\"bundleName\":\"test.bundle1\","
        "\"instIndex\":0,\"permState\":[{\"permissionName\":\"TEST\", "
        "\"isGeneral\":true,\"grantConfig\":[{\"resDeviceID\":\"0\",\"grantStatus\":-1,"
        "\"grantFlags\":0}]}],\"tokenAttr\":0,\"tokenID\":111,\"userID\":0,\"version\":1}");
    cmd->FromPermStateListJson(hapTokenJson.get(), permStateList);
    ASSERT_EQ(permStateList.size(), 1);
    EXPECT_EQ(permStateList[0].permissionName, "TEST");
    EXPECT_EQ(permStateList[0].grantStatus, static_cast<int32_t>(PermissionState::PERMISSION_DENIED));
    EXPECT_EQ(permStateList[0].grantFlag, 0);
    permStateList.clear();
}
}
}  // namespace AccessToken
}  // namespace Security
}  // namespace OHOS
