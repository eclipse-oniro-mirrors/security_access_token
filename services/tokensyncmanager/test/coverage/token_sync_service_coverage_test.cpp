/*
 * Copyright (c) 2024 Huawei Device Co., Ltd.
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
#include "soft_bus_manager.h"
#include "soft_bus_channel.h"
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
#include "device_manager_callback.h"
#include "dm_device_info.h"
#include "i_token_sync_manager.h"
#include "remote_command_manager.h"
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
namespace {
static DistributedHardware::DmDeviceInfo g_devInfo = {
    // udid = deviceid-1:udid-001  uuid = deviceid-1:uuid-001
    .deviceId = "deviceid-1",
    .deviceName = "remote_mock",
    .deviceTypeId = 1,
    .networkId = "deviceid-1"
};

static std::vector<std::thread> threads_;
static std::shared_ptr<SoftBusDeviceConnectionListener> g_ptrDeviceStateCallback =
    std::make_shared<SoftBusDeviceConnectionListener>();
static int32_t g_selfUid;
static AccessTokenID g_selfTokenId = 0;
static const int32_t OUT_OF_MAP_SOCKET = 2;
}

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
    ResetSoftBusSocketMock();
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

/**
 * @tc.name: HandleResponse001
 * @tc.desc: Handle response without holding the socket mutex while invoking the callback
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(TokenSyncServiceTest, HandleResponse001, TestSize.Level4)
{
    SoftBusChannel channel("test");
    std::string uuid("response-id");
    channel.InsertCallback(0, uuid);

    channel.HandleResponse(uuid, "response");

    ASSERT_TRUE(channel.callbacks_.empty());
    ASSERT_TRUE(channel.responseReceived_);
    ASSERT_EQ("response", channel.responseResult_);
}

/**
 * @tc.name: CheckAndCopyStr001
 * @tc.desc: destlen not equal to src
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(TokenSyncServiceTest, CheckAndCopyStr001, TestSize.Level4)
{
    std::string test_src = "testSrc";
    ASSERT_FALSE(SoftBusManager::GetInstance().CheckAndCopyStr(nullptr, test_src.length(), test_src));
}

/**
 * @tc.name: CloseSocket001
 * @tc.desc: invalid socketFd
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(TokenSyncServiceTest, CloseSocket001, TestSize.Level4)
{
    ASSERT_EQ(Constant::FAILURE, SoftBusManager::GetInstance().CloseSocket(-1));
    ASSERT_EQ(Constant::SUCCESS, SoftBusManager::GetInstance().CloseSocket(OUT_OF_MAP_SOCKET));
    std::string networkId;
    ASSERT_FALSE(SoftBusManager::GetInstance().GetNetworkIdBySocket(OUT_OF_MAP_SOCKET, networkId));
}

/**
 * @tc.name: GetUniversallyUniqueIdByNodeId001
 * @tc.desc: invalid nodeId
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(TokenSyncServiceTest, GetUniversallyUniqueIdByNodeId001, TestSize.Level4)
{
    SoftBusManager::GetInstance().Initialize();
    SoftBusManager::GetInstance().SetDefaultConfigValue();
    ASSERT_EQ("", SoftBusManager::GetInstance().GetUniversallyUniqueIdByNodeId(""));
    ASSERT_EQ("", SoftBusManager::GetInstance().GetUniqueDeviceIdByNodeId(""));
}

/**
 * @tc.name: ServiceSocketInit001
 * @tc.desc: listener is initialized and the socket is closed when Listen fails
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(TokenSyncServiceTest, ServiceSocketInit001, TestSize.Level4)
{
    constexpr int32_t socketFd = 20;
    SoftBusManager manager;
    SetSocketMockResult(socketFd);
    SetListenMockResult(Constant::FAILURE);

    EXPECT_NE(Constant::SUCCESS, manager.ServiceSocketInit());
    EXPECT_EQ(0, manager.socketFd_);
    EXPECT_EQ(1, GetShutdownMockCallCount());
    EXPECT_TRUE(WasLastListenListenerInitialized());
}

/**
 * @tc.name: ServiceSocketInit_002
 * @tc.desc: service socket initialization handles successful Listen and invalid socket results
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(TokenSyncServiceTest, ServiceSocketInit_002, TestSize.Level2)
{
    constexpr int32_t socketFd = 21;
    SoftBusManager manager;
    SetSocketMockResult(socketFd);
    SetListenMockResult(Constant::SUCCESS);

    EXPECT_EQ(Constant::SUCCESS, manager.ServiceSocketInit());
    EXPECT_EQ(socketFd, manager.socketFd_);
    EXPECT_EQ(0, GetShutdownMockCallCount());
    EXPECT_TRUE(WasLastListenListenerInitialized());

    ResetSoftBusSocketMock();
    SoftBusManager invalidManager;
    constexpr int32_t invalidSession = Constant::INVALID_SESSION;
    SetSocketMockResult(Constant::INVALID_SOCKET_FD);
    EXPECT_NE(Constant::SUCCESS, invalidManager.ServiceSocketInit());
    EXPECT_EQ(invalidSession, invalidManager.socketFd_);
    EXPECT_EQ(0, GetShutdownMockCallCount());
    EXPECT_FALSE(WasLastListenListenerInitialized());
}

/**
 * @tc.name: BindService001
 * @tc.desc: failed Bind attempts roll back the socket map and close the socket
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(TokenSyncServiceTest, BindService001, TestSize.Level4)
{
    constexpr int32_t socketFd = 30;
    constexpr int32_t maxBindRetryTimes = 10;
    const std::string networkId = "bind-network-id";
    const std::string uuid = "bind-uuid";
    const std::string udid = "bind-udid";
    DeviceInfoManager::GetInstance().AddDeviceInfo(networkId, uuid, udid, "device", "1");
    SoftBusManager manager;
    SetSocketMockResult(socketFd);
    SetBindMockResult(Constant::FAILURE);

    EXPECT_EQ(Constant::FAILURE, manager.BindService(udid));
    EXPECT_EQ(maxBindRetryTimes, GetBindMockCallCount());
    EXPECT_EQ(1, GetShutdownMockCallCount());
    EXPECT_TRUE(WasLastBindListenerInitialized());
    EXPECT_TRUE(manager.clientSocketMap_.empty());

    DeviceInfoManager::GetInstance().RemoveRemoteDeviceInfo(networkId, DeviceIdType::NETWORK_ID);
}

/**
 * @tc.name: BindService002
 * @tc.desc: duplicate socket mapping closes the new socket without attempting Bind
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(TokenSyncServiceTest, BindService002, TestSize.Level4)
{
    constexpr int32_t socketFd = 31;
    const std::string networkId = "duplicate-network-id";
    const std::string uuid = "duplicate-uuid";
    const std::string udid = "duplicate-udid";
    DeviceInfoManager::GetInstance().AddDeviceInfo(networkId, uuid, udid, "device", "1");
    SoftBusManager manager;
    manager.clientSocketMap_.emplace(socketFd, networkId);
    SetSocketMockResult(socketFd);

    EXPECT_LT(manager.BindService(udid), Constant::SUCCESS);
    EXPECT_EQ(0, GetBindMockCallCount());
    EXPECT_EQ(1, GetShutdownMockCallCount());
    EXPECT_EQ(1U, manager.clientSocketMap_.size());

    manager.clientSocketMap_.clear();
    DeviceInfoManager::GetInstance().RemoveRemoteDeviceInfo(networkId, DeviceIdType::NETWORK_ID);
}

/**
 * @tc.name: BindService_003
 * @tc.desc: client socket creation failure returns before map insertion and Bind
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(TokenSyncServiceTest, BindService_003, TestSize.Level2)
{
    const std::string networkId = "invalid-socket-network-id";
    const std::string uuid = "invalid-socket-uuid";
    const std::string udid = "invalid-socket-udid";
    DeviceInfoManager::GetInstance().AddDeviceInfo(networkId, uuid, udid, "device", "1");
    SoftBusManager manager;
    SetSocketMockResult(Constant::INVALID_SOCKET_FD);

    EXPECT_LT(manager.BindService(udid), Constant::SUCCESS);
    EXPECT_EQ(0, GetBindMockCallCount());
    EXPECT_EQ(0, GetShutdownMockCallCount());
    EXPECT_TRUE(manager.clientSocketMap_.empty());

    DeviceInfoManager::GetInstance().RemoveRemoteDeviceInfo(networkId, DeviceIdType::NETWORK_ID);
}

/**
 * @tc.name: InsertCallbackAndExcute001
 * @tc.desc: Ond
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(TokenSyncServiceTest, InsertCallbackAndExcute001, TestSize.Level4)
{
    SoftBusDeviceConnectionListener listener;
    listener.OnDeviceOffline(g_devInfo);
    DeviceInfoRepository::GetInstance().SaveDeviceInfo(g_devInfo.networkId, "123", g_devInfo.deviceId,
        g_devInfo.deviceName, std::to_string(g_devInfo.deviceTypeId));
    listener.OnDeviceOffline(g_devInfo);
    SoftBusChannel channel("test");
    std::string test("test");
    channel.InsertCallback(0, test);
    ASSERT_EQ(true, channel.isSocketUsing_);
    ASSERT_EQ("", channel.ExecuteCommand("test", "test"));
}

/**
 * @tc.name: Compress001
 * @tc.desc: compression rejects an undersized output buffer and preserves the terminating byte
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(TokenSyncServiceTest, Compress001, TestSize.Level4)
{
    SoftBusChannel channel("test");
    unsigned char compressedBytes[128] = { 0 };
    int compressedLength = static_cast<int>(sizeof(compressedBytes));
    EXPECT_EQ(Constant::FAILURE, channel.Compress("test", nullptr, compressedLength));

    compressedLength = 0;
    EXPECT_EQ(Constant::FAILURE, channel.Compress("test", compressedBytes, compressedLength));

    compressedLength = -1;
    EXPECT_EQ(Constant::FAILURE, channel.Compress("test", compressedBytes, compressedLength));

    compressedLength = 1;
    EXPECT_EQ(Constant::FAILURE, channel.Compress("test", compressedBytes, compressedLength));

    compressedLength = static_cast<int>(sizeof(compressedBytes));
    EXPECT_EQ(Constant::SUCCESS, channel.Compress("test", compressedBytes, compressedLength));
    EXPECT_EQ("test", channel.Decompress(compressedBytes, compressedLength));
}

/**
 * @tc.name: RandomUuid001
 * @tc.desc: UUID generation keeps the expected format
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(TokenSyncServiceTest, RandomUuid001, TestSize.Level4)
{
    constexpr size_t uuidBufferSize = 37;
    SoftBusChannel channel("test");
    char uuidBuffer[uuidBufferSize] = { 0 };
    channel.RandomUuid(uuidBuffer, sizeof(uuidBuffer));
    std::string uuid(uuidBuffer);
    EXPECT_EQ(uuidBufferSize - 1, uuid.length());
    EXPECT_EQ('-', uuid[8]);
    EXPECT_EQ('-', uuid[13]);
    EXPECT_EQ('4', uuid[14]);
    EXPECT_EQ('-', uuid[18]);
    EXPECT_NE(std::string::npos, std::string("89ab").find(uuid[19]));
    EXPECT_EQ('-', uuid[23]);
}

/**
 * @tc.name: SoftBusChannelCloseTaskName001
 * @tc.desc: each channel uses an independent delayed close task name
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(TokenSyncServiceTest, SoftBusChannelCloseTaskName001, TestSize.Level4)
{
    auto first = std::make_shared<SoftBusChannel>("device-a");
    auto second = std::make_shared<SoftBusChannel>("device-b");

    EXPECT_FALSE(first->closeTaskName_.empty());
    EXPECT_FALSE(second->closeTaskName_.empty());
    EXPECT_NE(first->closeTaskName_, second->closeTaskName_);
}

/**
 * @tc.name: CancelCloseConnectionIfNeeded_001
 * @tc.desc: delayed closing state is canceled under the socket mutex
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(TokenSyncServiceTest, CancelCloseConnectionIfNeeded_001, TestSize.Level4)
{
    auto channel = std::make_shared<SoftBusChannel>("device-a");
    channel->isDelayClosing_ = true;

    channel->CancelCloseConnectionIfNeeded();

    EXPECT_FALSE(channel->isDelayClosing_);
    std::unique_lock<std::mutex> lock(channel->socketMutex_, std::try_to_lock);
    EXPECT_TRUE(lock.owns_lock());
}

/**
 * @tc.name: BuildConnection_001
 * @tc.desc: negative SoftBus errors are not treated as valid socket descriptors
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(TokenSyncServiceTest, BuildConnection_001, TestSize.Level4)
{
    constexpr int32_t invalidSocketFd = Constant::INVALID_SOCKET_FD;
    auto channel = std::make_shared<SoftBusChannel>("device-without-info");

    EXPECT_EQ(Constant::FAILURE, channel->BuildConnection());
    EXPECT_EQ(invalidSocketFd, channel->socketFd_);

    channel->socketFd_ = Constant::FAILURE;
    EXPECT_FALSE(channel->IsSessionAvailable());
    channel->socketFd_ = Constant::INVALID_SOCKET_FD;
    EXPECT_FALSE(channel->IsSessionAvailable());
    channel->socketFd_ = 1;
    EXPECT_TRUE(channel->IsSessionAvailable());
}

/**
 * @tc.name: BuildConnection_002
 * @tc.desc: successful client Bind is reused without opening another socket
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(TokenSyncServiceTest, BuildConnection_002, TestSize.Level1)
{
    constexpr int32_t socketFd = 32;
    const std::string networkId = "build-network-id";
    const std::string uuid = "build-uuid";
    const std::string udid = "build-udid";
    DeviceInfoManager::GetInstance().AddDeviceInfo(networkId, uuid, udid, "device", "1");
    SetSocketMockResult(socketFd);
    SetBindMockResult(Constant::SUCCESS);
    auto channel = std::make_shared<SoftBusChannel>(udid);

    EXPECT_EQ(Constant::SUCCESS, channel->BuildConnection());
    EXPECT_EQ(socketFd, channel->socketFd_);
    EXPECT_EQ(1, GetBindMockCallCount());
    EXPECT_TRUE(WasLastBindListenerInitialized());

    EXPECT_EQ(Constant::SUCCESS, channel->BuildConnection());
    EXPECT_EQ(1, GetBindMockCallCount());

    EXPECT_EQ(Constant::SUCCESS, SoftBusManager::GetInstance().CloseSocket(socketFd));
    channel->socketFd_ = Constant::INVALID_SOCKET_FD;
    DeviceInfoManager::GetInstance().RemoveRemoteDeviceInfo(networkId, DeviceIdType::NETWORK_ID);
}
}  // namespace AccessToken
}  // namespace Security
}  // namespace OHOS
