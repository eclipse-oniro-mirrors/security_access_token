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
#include "token_sync_service_test.h"

#include <algorithm>
#include <fstream>
#include <functional>
#include <iostream>
#include <map>
#include <memory>
#include <thread>

#include "gtest/gtest.h"
#include "accesstoken_kit.h"
#include "accesstoken_log.h"
#include "base_remote_command.h"
#include "constant_common.h"
#include "session.h"
#include "delete_remote_token_command.h"
#include "device_info.h"
#include "soft_bus_device_connection_listener.h"
#include "soft_bus_session_listener.h"
#include "token_setproc.h"
#include "device_info_manager.h"

#define private public
#include "token_sync_manager_service.h"
#undef private

using namespace std;
using namespace testing::ext;

namespace OHOS {
namespace Security {
namespace AccessToken {
static std::vector<std::thread> threads_;
static std::shared_ptr<SoftBusDeviceConnectionListener> g_ptrDeviceStateCallback =
    std::make_shared<SoftBusDeviceConnectionListener>();
static std::string g_networkID = "deviceid-1";
static std::string g_udid = "deviceid-1:udid-001";
static DmDeviceInfo g_devInfo = {
    // udid = deviceid-1:udid-001  uuid = deviceid-1:uuid-001
    .deviceId = "deviceid-1",
    .deviceName = "remote_mock",
    .deviceTypeId = 1
};

namespace {
static constexpr OHOS::HiviewDFX::HiLogLabel LABEL = {LOG_CORE, SECURITY_DOMAIN_ACCESSTOKEN, "AccessTokenKitTest"};
}

TokenSyncServiceTest::TokenSyncServiceTest()
{
    DelayedSingleton<TokenSyncManagerService>::GetInstance()->Initialize();
}
TokenSyncServiceTest::~TokenSyncServiceTest()
{}

void NativeTokenGet()
{
    uint64_t tokenId;
    tokenId = AccessTokenKit::GetNativeTokenId("token_sync_service");
    ASSERT_NE(tokenId, 0);
    SetSelfTokenID(tokenId);
}

void TokenSyncServiceTest::SetUpTestCase()
{
    NativeTokenGet();
}
void TokenSyncServiceTest::TearDownTestCase()
{}
void TokenSyncServiceTest::SetUp()
{
}
void TokenSyncServiceTest::TearDown()
{
    ACCESSTOKEN_LOG_INFO(LABEL, "TearDown start.");
    for (auto it = threads_.begin(); it != threads_.end(); it++) {
        it->join();
    }
    threads_.clear();

    if (g_ptrDeviceStateCallback != nullptr) {
        OnDeviceOffline(g_devInfo);
        sleep(1);
    }
}

void TokenSyncServiceTest::OnDeviceOffline(const DmDeviceInfo &info)
{
    std::string networkId = info.deviceId;
    std::string uuid = DeviceInfoManager::GetInstance().ConvertToUniversallyUniqueIdOrFetch(networkId);
    std::string udid = DeviceInfoManager::GetInstance().ConvertToUniqueDeviceIdOrFetch(networkId);

    ACCESSTOKEN_LOG_INFO(LABEL,
        "networkId: %{public}s,  uuid: %{public}s, udid: %{public}s",
        networkId.c_str(),
        uuid.c_str(),
        ConstantCommon::EncryptDevId(udid).c_str());

    if (uuid != "" && udid != "") {
        RemoteCommandManager::GetInstance().NotifyDeviceOffline(uuid);
        RemoteCommandManager::GetInstance().NotifyDeviceOffline(udid);
        DeviceInfoManager::GetInstance().RemoveRemoteDeviceInfo(networkId, DeviceIdType::NETWORK_ID);
    } else {
        ACCESSTOKEN_LOG_ERROR(LABEL, "uuid or udid is empty, offline failed.");
    }
}

namespace {
    std::string g_jsonBefore;
    std::string g_jsonAfter;
}

void SendTaskThread()
{
    while (!GetSendMessFlagMock()) {
        sleep(1);
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

    SoftBusSessionListener::OnBytesReceived(1, sendBuffer, sendLen);
    free(sendBuffer);
}

static PermissionDef g_infoManagerTestPermDef1 = {
    .permissionName = "ohos.permission.test1",
    .bundleName = "accesstoken_test",
    .grantMode = 1,
    .label = "label",
    .labelId = 1,
    .description = "open the door",
    .descriptionId = 1,
    .availableLevel = APL_NORMAL
};

static PermissionDef g_infoManagerTestPermDef2 = {
    .permissionName = "ohos.permission.test2",
    .bundleName = "accesstoken_test",
    .grantMode = 1,
    .label = "label",
    .labelId = 1,
    .description = "break the door",
    .descriptionId = 1,
    .availableLevel = APL_NORMAL
};

static PermissionStateFull g_infoManagerTestState1 = {
    .grantFlags = {1},
    .grantStatus = {PermissionState::PERMISSION_GRANTED},
    .isGeneral = true,
    .permissionName = "ohos.permission.test1",
    .resDeviceID = {"local"}
};

static PermissionStateFull g_infoManagerTestState2 = {
    .permissionName = "ohos.permission.test2",
    .isGeneral = false,
    .grantFlags = {1, 2},
    .grantStatus = {PermissionState::PERMISSION_GRANTED, PermissionState::PERMISSION_GRANTED},
    .resDeviceID = {"device 1", "device 2"}
};

static HapInfoParams g_infoManagerTestInfoParms = {
    .bundleName = "accesstoken_test",
    .userID = 1,
    .instIndex = 0,
    .appIDDesc = "testtesttesttest"
};

static HapPolicyParams g_infoManagerTestPolicyPrams = {
    .apl = APL_NORMAL,
    .domain = "test.domain",
    .permList = {g_infoManagerTestPermDef1, g_infoManagerTestPermDef2},
    .permStateList = {g_infoManagerTestState1, g_infoManagerTestState2}
};

/**
 * @tc.name: GetRemoteHapTokenInfo002
 * @tc.desc: test remote hap recv func
 * @tc.type: FUNC
 * @tc.require:AR000GK6T5 AR000GK6T9
 */
HWTEST_F(TokenSyncServiceTest, GetRemoteHapTokenInfo002, TestSize.Level1)
{
    ACCESSTOKEN_LOG_INFO(LABEL, "GetRemoteHapTokenInfo002 start.");
    // create local token
    AccessTokenID tokenID = AccessTokenKit::GetHapTokenID(g_infoManagerTestInfoParms.userID,
                                                          g_infoManagerTestInfoParms.bundleName,
                                                          g_infoManagerTestInfoParms.instIndex);
    AccessTokenKit::DeleteToken(tokenID);

    AccessTokenIDEx tokenIdEx = {0};
    tokenIdEx = AccessTokenKit::AllocHapToken(g_infoManagerTestInfoParms, g_infoManagerTestPolicyPrams);
    ASSERT_NE(0, tokenIdEx.tokenIdExStruct.tokenID);

    std::string jsonBefore =
        "{\"commandName\":\"SyncRemoteHapTokenCommand\",\"id\":\"0065e65f-\",\"jsonPayload\":"
        "\"{\\\"HapTokenInfo\\\":{\\\"apl\\\":1,\\\"appID\\\":\\\"\\\",\\\"bundleName\\\":\\\"\\\","
        "\\\"deviceID\\\":\\\"\\\",\\\"instIndex\\\":0,\\\"permState\\\":null,\\\"tokenAttr\\\":0,"
        "\\\"tokenID\\\":0,\\\"userID\\\":0,\\\"version\\\":1},\\\"commandName\\\":\\\"SyncRemoteHapTokenCommand\\\","
        "\\\"dstDeviceId\\\":\\\"local:udid-001\\\",\\\"dstDeviceLevel\\\":\\\"\\\",\\\"message\\\":\\\"success\\\","
        "\\\"requestTokenId\\\":";
    std::string tokenJsonStr = std::to_string(tokenIdEx.tokenIdExStruct.tokenID);
    std::string jsonAfter = ",\\\"requestVersion\\\":2,\\\"responseDeviceId\\\":\\\"\\\",\\\"responseVersion\\\":2,"
        "\\\"srcDeviceId\\\":\\\"deviceid-1:udid-001\\\",\\\"srcDeviceLevel\\\":\\\"\\\",\\\"statusCode\\\":100001,"
        "\\\"uniqueId\\\":\\\"SyncRemoteHapTokenCommand\\\"}\",\"type\":\"request\"}";

    std::string recvJson = jsonBefore + tokenJsonStr + jsonAfter;

    unsigned char *recvBuffer = (unsigned char *)malloc(0x1000);
    int recvLen = 0x1000;
    CompressMock(recvJson, recvBuffer, recvLen);

    ResetSendMessFlagMock();
    g_ptrDeviceStateCallback->OnDeviceOnline(g_devInfo);
    int count = 0;
    while (!GetSendMessFlagMock() && count < 10) {
        sleep(1);
        count++;
    }

    ResetSendMessFlagMock();
    SoftBusSessionListener::OnBytesReceived(1, recvBuffer, recvLen);
    count = 0;
    while (!GetSendMessFlagMock() && count < 10) {
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
HWTEST_F(TokenSyncServiceTest, GetRemoteHapTokenInfo003, TestSize.Level1)
{
    ACCESSTOKEN_LOG_INFO(LABEL, "GetRemoteHapTokenInfo003 start.");
    g_jsonBefore = "{\"commandName\":\"SyncRemoteHapTokenCommand\", \"id\":\"";
    // apl is error
    g_jsonAfter =
        "\",\"jsonPayload\":\"{\\\"HapTokenInfo\\\":{\\\"apl\\\":11,\\\"appID\\\":"
        "\\\"test\\\",\\\"bundleName\\\":\\\"mock_token_sync\\\",\\\"deviceID\\\":"
        "\\\"111111\\\",\\\"instIndex\\\":0,\\\"permState\\\":null,\\\"tokenAttr\\\":0,\\\"tokenID\\\":537919488,"
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

    AccessTokenID mapID = AccessTokenKit::AllocLocalTokenID(g_udid, 0x20100000);
    ASSERT_EQ(mapID, (AccessTokenID)0);
}

/**
 * @tc.name: GetRemoteHapTokenInfo004
 * @tc.desc: test remote hap send func, but json payload lost parameter
 * @tc.type: FUNC
 * @tc.require:AR000GK6T5 AR000GK6T9
 */
HWTEST_F(TokenSyncServiceTest, GetRemoteHapTokenInfo004, TestSize.Level1)
{
    ACCESSTOKEN_LOG_INFO(LABEL, "GetRemoteHapTokenInfo004 start.");
    g_jsonBefore = "{\"commandName\":\"SyncRemoteHapTokenCommand\", \"id\":\"";
    // lost tokenID
    g_jsonAfter =
        "\",\"jsonPayload\":\"{\\\"HapTokenInfo\\\":{\\\"apl\\\":1,\\\"appID\\\":"
        "\\\"test\\\",\\\"bundleName\\\":\\\"mock_token_sync\\\",\\\"deviceID\\\":"
        "\\\"111111\\\",\\\"permState\\\":null,\\\"tokenAttr\\\":0,"
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

    AccessTokenID mapID = AccessTokenKit::AllocLocalTokenID(g_udid, 0x20100000);
    ASSERT_EQ(mapID, (AccessTokenID)0);
}

/**
 * @tc.name: GetRemoteHapTokenInfo005
 * @tc.desc: test remote hap send func, but json payload parameter type is wrong
 * @tc.type: FUNC
 * @tc.require:AR000GK6T5 AR000GK6T9
 */
HWTEST_F(TokenSyncServiceTest, GetRemoteHapTokenInfo005, TestSize.Level1)
{
    ACCESSTOKEN_LOG_INFO(LABEL, "GetRemoteHapTokenInfo005 start.");
    g_jsonBefore = "{\"commandName\":\"SyncRemoteHapTokenCommand\", \"id\":\"";
    // instIndex is not number
    g_jsonAfter =
        "\",\"jsonPayload\":\"{\\\"HapTokenInfo\\\":{\\\"apl\\\":1,\\\"appID\\\":"
        "\\\"test\\\",\\\"bundleName\\\":\\\"mock_token_sync\\\",\\\"deviceID\\\":"
        "\\\"111111\\\",\\\"instIndex\\\":1,\\\"permState\\\":null,\\\"tokenAttr\\\":0,"
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

    AccessTokenID mapID = AccessTokenKit::AllocLocalTokenID(g_udid, 0x20100000);
    ASSERT_EQ(mapID, (AccessTokenID)0);
}

/**
 * @tc.name: GetRemoteHapTokenInfo006
 * @tc.desc: test remote hap send func, but json payload parameter format is wrong
 * @tc.type: FUNC
 * @tc.require:AR000GK6T5 AR000GK6T9
 */
HWTEST_F(TokenSyncServiceTest, GetRemoteHapTokenInfo006, TestSize.Level1)
{
    ACCESSTOKEN_LOG_INFO(LABEL, "GetRemoteHapTokenInfo006 start.");
    g_jsonBefore = "{\"commandName\":\"SyncRemoteHapTokenCommand\", \"id\":\"";
    // mock_token_sync lost \\\"
    g_jsonAfter =
        "\",\"jsonPayload\":\"{\\\"HapTokenInfo\\\":{\\\"apl\\\":1,\\\"appID\\\":"
        "\\\"test\\\",\\\"bundleName\\\":\\\"mock_token_sync,\\\"deviceID\\\":"
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

    AccessTokenID mapID = AccessTokenKit::AllocLocalTokenID(g_udid, 0x20100000);
    ASSERT_EQ(mapID, (AccessTokenID)0);
}

/**
 * @tc.name: GetRemoteHapTokenInfo007
 * @tc.desc: test remote hap send func, statusCode is wrong
 * @tc.type: FUNC
 * @tc.require:AR000GK6T5 AR000GK6T9
 */
HWTEST_F(TokenSyncServiceTest, GetRemoteHapTokenInfo007, TestSize.Level1)
{
    ACCESSTOKEN_LOG_INFO(LABEL, "GetRemoteHapTokenInfo007 start.");
    g_jsonBefore = "{\"commandName\":\"SyncRemoteHapTokenCommand\", \"id\":\"";
    // statusCode error
    g_jsonAfter =
        "\",\"jsonPayload\":\"{\\\"HapTokenInfo\\\":{\\\"apl\\\":11,\\\"appID\\\":"
        "\\\"test\\\",\\\"bundleName\\\":\\\"mock_token_sync\\\",\\\"deviceID\\\":"
        "\\\"111111\\\",\\\"instIndex\\\":1,\\\"permState\\\":null,\\\"tokenAttr\\\":0,"
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

    AccessTokenID mapID = AccessTokenKit::AllocLocalTokenID(g_udid, 0x20100000);
    ASSERT_EQ(mapID, (AccessTokenID)0);
}

/**
 * @tc.name: GetRemoteHapTokenInfo008
 * @tc.desc: test remote hap recv func, tokenID is not exist
 * @tc.type: FUNC
 * @tc.require:AR000GK6T5 AR000GK6T9
 */
HWTEST_F(TokenSyncServiceTest, GetRemoteHapTokenInfo008, TestSize.Level1)
{
    ACCESSTOKEN_LOG_INFO(LABEL, "GetRemoteHapTokenInfo008 start.");
    // create local token
    AccessTokenID tokenID = AccessTokenKit::GetHapTokenID(g_infoManagerTestInfoParms.userID,
                                                          g_infoManagerTestInfoParms.bundleName,
                                                          g_infoManagerTestInfoParms.instIndex);
    AccessTokenKit::DeleteToken(tokenID);

    // tokenID is not exist
    std::string jsonBefore =
        "{\"commandName\":\"SyncRemoteHapTokenCommand\",\"id\":\"0065e65f-\",\"jsonPayload\":"
        "\"{\\\"HapTokenInfo\\\":{\\\"apl\\\":1,\\\"appID\\\":\\\"\\\",\\\"bundleName\\\":\\\"\\\","
        "\\\"deviceID\\\":\\\"\\\",\\\"instIndex\\\":0,\\\"permState\\\":null,\\\"tokenAttr\\\":0,"
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
    SoftBusSessionListener::OnBytesReceived(1, recvBuffer, recvLen);

    int count = 0;
    while (!GetSendMessFlagMock() && count < 10) {
        sleep(1);
        count++;
    }
    free(recvBuffer);
    AccessTokenID mapID = AccessTokenKit::AllocLocalTokenID(g_udid, 0);
    ASSERT_EQ(mapID, (AccessTokenID)0);
}

/**
 * @tc.name: SyncNativeTokens002
 * @tc.desc: when device is online, sync remote nativetoken which has no dcaps
 * @tc.type: FUNC
 * @tc.require:AR000GK6T6
 */
HWTEST_F(TokenSyncServiceTest, SyncNativeTokens002, TestSize.Level1)
{
    ACCESSTOKEN_LOG_INFO(LABEL, "SyncNativeTokens002 start.");
    g_jsonBefore = "{\"commandName\":\"SyncRemoteNativeTokenCommand\", \"id\":\"";
    // 0x28000001 token has no dcaps
    g_jsonAfter =
        "\",\"jsonPayload\":\"{\\\"NativeTokenInfos\\\":[{\\\"apl\\\":3,\\\"processName\\\":\\\"attest\\\","
        "\\\"tokenAttr\\\":0,\\\"tokenId\\\":671088640,\\\"version\\\":1,"
        "\\\"dcaps\\\":[\\\"SYSDCAP\\\",\\\"DMSDCAP\\\"]},"
        "{\\\"apl\\\":3,\\\"processName\\\":\\\"attest1\\\",\\\"tokenAttr\\\":0,\\\"tokenId\\\":671088641,"
        "\\\"version\\\":1,\\\"dcaps\\\":[]}],"
        "\\\"commandName\\\":\\\"SyncRemoteNativeTokenCommand\\\","
        "\\\"dstDeviceId\\\":\\\"deviceid-1\\\",\\\"dstDeviceLevel\\\":\\\"\\\",\\\"message\\\":\\\"success\\\","
        "\\\"requestVersion\\\":2,\\\"responseDeviceId\\\":\\\"deviceid-1:udid-001\\\","
        "\\\"responseVersion\\\":2,\\\"srcDeviceId\\\":\\\"local:udid-001\\\","
        "\\\"srcDeviceLevel\\\":\\\"\\\",\\\"statusCode\\\":0,\\\"uniqueId\\\":\\\"SyncRemoteNativeTokenCommand\\\"}\","
        "\"type\":\"response\"}";

    g_ptrDeviceStateCallback->OnDeviceOnline(g_devInfo);
    sleep(3);

    ResetSendMessFlagMock();
    threads_.emplace_back(std::thread(SendTaskThread));
    sleep(6);

    AccessTokenID mapID = AccessTokenKit::GetRemoteNativeTokenID(g_udid, 0x28000000);
    ASSERT_NE(mapID, (AccessTokenID)0);
    int ret = AccessTokenKit::CheckNativeDCap(mapID, "SYSDCAP");
    ASSERT_EQ(ret, RET_SUCCESS);
    ret = AccessTokenKit::CheckNativeDCap(mapID, "DMSDCAP");
    ASSERT_EQ(ret, RET_SUCCESS);

    mapID = AccessTokenKit::GetRemoteNativeTokenID(g_udid, 0x28000001);
    ASSERT_EQ(mapID, (AccessTokenID)0);
}

/**
 * @tc.name: SyncNativeTokens003
 * @tc.desc: when device is online, sync remote nativetokens status failed
 * @tc.type: FUNC
 * @tc.require:AR000GK6T6
 */
HWTEST_F(TokenSyncServiceTest, SyncNativeTokens003, TestSize.Level1)
{
    ACCESSTOKEN_LOG_INFO(LABEL, "SyncNativeTokens003 start.");
    g_jsonBefore = "{\"commandName\":\"SyncRemoteNativeTokenCommand\", \"id\":\"";
    g_jsonAfter =
        "\",\"jsonPayload\":\"{\\\"NativeTokenInfos\\\":[{\\\"apl\\\":3,\\\"processName\\\":\\\"attest\\\","
        "\\\"tokenAttr\\\":0,\\\"tokenId\\\":671088640,\\\"version\\\":1,"
        "\\\"dcaps\\\":[\\\"SYSDCAP\\\",\\\"DMSDCAP\\\"]},"
        "{\\\"apl\\\":3,\\\"processName\\\":\\\"attest1\\\",\\\"tokenAttr\\\":0,\\\"tokenId\\\":671088641,"
        "\\\"version\\\":1,\\\"dcaps\\\":[\\\"SYSDCAP\\\",\\\"DMSDCAP\\\"]}],"
        "\\\"commandName\\\":\\\"SyncRemoteNativeTokenCommand\\\","
        "\\\"dstDeviceId\\\":\\\"deviceid-1\\\",\\\"dstDeviceLevel\\\":\\\"\\\",\\\"message\\\":\\\"success\\\","
        "\\\"requestVersion\\\":2,\\\"responseDeviceId\\\":\\\"deviceid-1:udid-001\\\","
        "\\\"responseVersion\\\":2,\\\"srcDeviceId\\\":\\\"local:udid-001\\\","
        "\\\"srcDeviceLevel\\\":\\\"\\\",\\\"statusCode\\\":-2,"
        "\\\"uniqueId\\\":\\\"SyncRemoteNativeTokenCommand\\\"}\",\"type\":\"response\"}";


    threads_.emplace_back(std::thread(SendTaskThread));
    g_ptrDeviceStateCallback->OnDeviceOnline(g_devInfo);

    sleep(6);

    AccessTokenID mapID = AccessTokenKit::GetRemoteNativeTokenID(g_udid, 0x28000000);
    ASSERT_EQ(mapID, (AccessTokenID)0);

    mapID = AccessTokenKit::GetRemoteNativeTokenID(g_udid, 0x28000001);
    ASSERT_EQ(mapID, (AccessTokenID)0);
}

/**
 * @tc.name: SyncNativeTokens004
 * @tc.desc: when device is online, sync remote nativetokens which parameter is wrong
 * @tc.type: FUNC
 * @tc.require:AR000GK6T6
 */
HWTEST_F(TokenSyncServiceTest, SyncNativeTokens004, TestSize.Level1)
{
    ACCESSTOKEN_LOG_INFO(LABEL, "SyncNativeTokens004 start.");
    g_jsonBefore = "{\"commandName\":\"SyncRemoteNativeTokenCommand\", \"id\":\"";
    // apl is error
    g_jsonAfter =
        "\",\"jsonPayload\":\"{\\\"NativeTokenInfos\\\":[{\\\"apl\\\":11,\\\"processName\\\":\\\"attest\\\","
        "\\\"tokenAttr\\\":0,\\\"tokenId\\\":671088640,\\\"version\\\":1,"
        "\\\"dcaps\\\":[\\\"SYSDCAP\\\",\\\"DMSDCAP\\\"]},"
        "{\\\"apl\\\":11,\\\"processName\\\":\\\"attest1\\\",\\\"tokenAttr\\\":0,\\\"tokenId\\\":671088641,"
        "\\\"version\\\":1,\\\"dcaps\\\":[\\\"SYSDCAP\\\",\\\"DMSDCAP\\\"]}],"
        "\\\"commandName\\\":\\\"SyncRemoteNativeTokenCommand\\\","
        "\\\"dstDeviceId\\\":\\\"deviceid-1\\\",\\\"dstDeviceLevel\\\":\\\"\\\",\\\"message\\\":\\\"success\\\","
        "\\\"requestVersion\\\":2,\\\"responseDeviceId\\\":\\\"deviceid-1:udid-001\\\","
        "\\\"responseVersion\\\":2,\\\"srcDeviceId\\\":\\\"local:udid-001\\\","
        "\\\"srcDeviceLevel\\\":\\\"\\\",\\\"statusCode\\\":0,\\\"uniqueId\\\":\\\"SyncRemoteNativeTokenCommand\\\"}\","
        "\"type\":\"response\"}";

    threads_.emplace_back(std::thread(SendTaskThread));

    g_ptrDeviceStateCallback->OnDeviceOnline(g_devInfo);

    sleep(6);

    AccessTokenID mapID = AccessTokenKit::GetRemoteNativeTokenID(g_udid, 0x28000000);
    ASSERT_EQ(mapID, (AccessTokenID)0);

    mapID = AccessTokenKit::GetRemoteNativeTokenID(g_udid, 0x28000001);
    ASSERT_EQ(mapID, (AccessTokenID)0);
}

/**
 * @tc.name: SyncNativeTokens005
 * @tc.desc: test remote hap recv func
 * @tc.type: FUNC
 * @tc.require:AR000GK6T5
 */
HWTEST_F(TokenSyncServiceTest, SyncNativeTokens005, TestSize.Level1)
{
    ACCESSTOKEN_LOG_INFO(LABEL, "SyncNativeTokens005 start.");

    std::string recvJson =
        "{\"commandName\":\"SyncRemoteNativeTokenCommand\",\"id\":\"ec23cd2d-\",\"jsonPayload\":"
        "\"{\\\"NativeTokenInfos\\\":null,\\\"commandName\\\":\\\"SyncRemoteNativeTokenCommand\\\","
        "\\\"dstDeviceId\\\":\\\"local:udid-001\\\",\\\"dstDeviceLevel\\\":\\\"\\\",\\\"message\\\":\\\"success\\\","
        "\\\"requestTokenId\\\":,\\\"requestVersion\\\":2,\\\"responseDeviceId\\\":\\\"\\\",\\\"responseVersion\\\":2,"
        "\\\"srcDeviceId\\\":\\\"deviceid-1\\\",\\\"srcDeviceLevel\\\":\\\"\\\",\\\"statusCode\\\":100001,"
        "\\\"uniqueId\\\":\\\"SyncRemoteNativeTokenCommand\\\"}\",\"type\":\"request\"}";

    unsigned char *recvBuffer = (unsigned char *)malloc(0x1000);
    int recvLen = 0x1000;
    CompressMock(recvJson, recvBuffer, recvLen);

    ResetSendMessFlagMock();
    g_ptrDeviceStateCallback->OnDeviceOnline(g_devInfo);
    int count = 0;
    while (!GetSendMessFlagMock() && count < 10) {
        sleep(1);
        count++;
    }

    ResetSendMessFlagMock();
    SoftBusSessionListener::OnBytesReceived(1, recvBuffer, recvLen);
    count = 0;
    while (!GetSendMessFlagMock() && count < 10) {
        sleep(1);
        count++;
    }
    free(recvBuffer);

    std::string uuidMessage = GetUuidMock();
    ASSERT_EQ(uuidMessage, "ec23cd2d-");
}

/**
 * @tc.name: SyncNativeTokens005
 * @tc.desc: test delete remote token command
 * @tc.type: FUNC
 * @tc.require: Issue Number
 */
HWTEST_F(TokenSyncServiceTest, DeleteRemoteTokenCommand001, TestSize.Level1)
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
}

namespace {
PermissionStateFull g_infoManagerTestUpdateState1 = {
    .grantFlags = {1},
    .grantStatus = {PermissionState::PERMISSION_DENIED},
    .isGeneral = true,
    .permissionName = "ohos.permission.CAMERA",
    .resDeviceID = {"local"}
};

PermissionStateFull g_infoManagerTestUpdateState2 = {
    .permissionName = "ohos.permission.ANSWER_CALL",
    .isGeneral = false,
    .grantFlags = {1, 2},
    .grantStatus = {PermissionState::PERMISSION_DENIED, PermissionState::PERMISSION_DENIED},
    .resDeviceID = {"device 1", "device 2"}
};

HapTokenInfo g_remoteHapInfoBasic = {
    .apl = APL_NORMAL,
    .ver = 1,
    .userID = 1,
    .bundleName = "accesstoken_test",
    .instIndex = 1,
    .appID = "testtesttesttest",
    .deviceID = "0",
    .tokenID = 0x20000001,
    .tokenAttr = 0
};

HapTokenInfoForSync g_remoteHapInfo = {
    .baseInfo = g_remoteHapInfoBasic,
    .permStateList = {g_infoManagerTestUpdateState1, g_infoManagerTestUpdateState2}
};
}
}  // namespace AccessToken
}  // namespace Security
}  // namespace OHOS
