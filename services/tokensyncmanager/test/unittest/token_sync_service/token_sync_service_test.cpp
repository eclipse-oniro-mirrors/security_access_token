/*
 * Copyright (c) 2021 Huawei Device Co., Ltd.
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

#include "accesstoken_kit.h"
#include "accesstoken_log.h"
#include "base_remote_command.h"
#include "gtest/gtest.h"
#include "session.h"
#include "soft_bus_device_connection_listener.h"
#include "soft_bus_session_listener.h"

#define private public
#include "token_sync_manager_service.h"
#undef private

using namespace std;
using namespace OHOS::Security::AccessToken;
using namespace testing::ext;
static std::vector<std::thread> threads_;

namespace {
static constexpr OHOS::HiviewDFX::HiLogLabel LABEL = {LOG_CORE, SECURITY_DOMAIN_ACCESSTOKEN, "AccessTokenKitTest"};
}

TokenSyncServiceTest::TokenSyncServiceTest()
{
    DelayedSingleton<TokenSyncManagerService>::GetInstance()->Initialize();
}
TokenSyncServiceTest::~TokenSyncServiceTest()
{}
void TokenSyncServiceTest::SetUpTestCase()
{}
void TokenSyncServiceTest::TearDownTestCase()
{}
void TokenSyncServiceTest::SetUp()
{
}
void TokenSyncServiceTest::TearDown()
{
    for (auto it = threads_.begin(); it != threads_.end(); it++) {
        it->join();
    }
    threads_.clear();
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
}

/**
 * @tc.name: GetRemoteHapTokenInfo001
 * @tc.desc: test remote hap send func
 * @tc.type: FUNC
 * @tc.require:AR000GK6T5
 */
HWTEST_F(TokenSyncServiceTest, GetRemoteHapTokenInfo001, TestSize.Level1)
{
    ACCESSTOKEN_LOG_INFO(LABEL, "GetRemoteHapTokenInfo001 start.");
    g_jsonBefore = "{\"commandName\":\"SyncRemoteHapTokenCommand\", \"id\":\"";
    g_jsonAfter =
        "\",\"jsonPayload\":\"{\\\"HapTokenInfo\\\":{\\\"apl\\\":1,\\\"appID\\\":"
        "\\\"test\\\",\\\"bundleName\\\":\\\"mock_token_sync\\\",\\\"deviceID\\\":"
        "\\\"111111\\\",\\\"instIndex\\\":0,\\\"permState\\\":null,\\\"tokenAttr\\\":0,\\\"tokenID\\\":537919488,"
        "\\\"userID\\\":0,\\\"version\\\":1},\\\"commandName\\\":\\\"SyncRemoteHapTokenCommand\\\","
        "\\\"dstDeviceId\\\":\\\"deviceid-1\\\",\\\"dstDeviceLevel\\\":\\\"\\\",\\\"message\\\":\\\"success\\\","
        "\\\"requestTokenId\\\":537919488,\\\"requestVersion\\\":2,\\\"responseDeviceId\\\":\\\"deviceid-1:udid-001\\\""
        ",\\\"responseVersion\\\":2,\\\"srcDeviceId\\\":\\\"local:udid-001\\\",\\\"srcDeviceLevel\\\":\\\"\\\","
        "\\\"statusCode\\\":0,\\\"uniqueId\\\":\\\"SyncRemoteHapTokenCommand\\\"}\",\"type\":\"response\"}";

    threads_.emplace_back(std::thread(SendTaskThread));

    std::string networkID = "deviceid-1";
    std::string deviceName = "remote_mock";
    // udid = deviceid-1:udid-001    uuid = deviceid-1:uuid-001
    DmDeviceInfo devInfo;
    strcpy(devInfo.deviceId, networkID.c_str());
    strcpy(devInfo.deviceName, deviceName.c_str());
    devInfo.deviceTypeId = 1;

    std::shared_ptr<SoftBusDeviceConnectionListener> ptrDeviceStateCallback =
        std::make_shared<SoftBusDeviceConnectionListener>();

    ptrDeviceStateCallback->OnDeviceOnline(devInfo);

    int ret = OHOS::DelayedSingleton<TokenSyncManagerService>::GetInstance()->GetRemoteHapTokenInfo(
        networkID, 0x20100000);
    ASSERT_EQ(ret, RET_SUCCESS);

    AccessTokenID mapID = AccessTokenKit::AllocLocalTokenID(networkID, 0x20100000);
    ASSERT_NE(mapID, (AccessTokenID)0);

    HapTokenInfo tokeInfo;
    ret = AccessTokenKit::GetHapTokenInfo(mapID, tokeInfo);
    ASSERT_EQ(ret, RET_SUCCESS);

    ptrDeviceStateCallback->OnDeviceOffline(devInfo);
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
 * @tc.require:AR000GK6T5
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

    // create recv message
    std::string jsonBefore =
        "{\"commandName\":\"SyncRemoteHapTokenCommand\",\"id\":\"0065e65f-\",\"jsonPayload\":"
        "\"{\\\"HapTokenInfo\\\":{\\\"apl\\\":1,\\\"appID\\\":\\\"\\\",\\\"bundleName\\\":\\\"\\\","
        "\\\"deviceID\\\":\\\"\\\",\\\"instIndex\\\":0,\\\"permState\\\":null,\\\"tokenAttr\\\":0,"
        "\\\"tokenID\\\":0,\\\"userID\\\":0,\\\"version\\\":1},\\\"commandName\\\":\\\"SyncRemoteHapTokenCommand\\\","
        "\\\"dstDeviceId\\\":\\\"local:udid-001\\\",\\\"dstDeviceLevel\\\":\\\"\\\",\\\"message\\\":\\\"success\\\","
        "\\\"requestTokenId\\\":";
    std::string tokenJsonStr = std::to_string(tokenIdEx.tokenIdExStruct.tokenID);
    std::string jsonAfter = ",\\\"requestVersion\\\":2,\\\"responseDeviceId\\\":\\\"\\\",\\\"responseVersion\\\":2,"
        "\\\"srcDeviceId\\\":\\\"deviceid-1\\\",\\\"srcDeviceLevel\\\":\\\"\\\",\\\"statusCode\\\":100001,"
        "\\\"uniqueId\\\":\\\"SyncRemoteHapTokenCommand\\\"}\",\"type\":\"request\"}";

    std::string recvJson = jsonBefore + tokenJsonStr + jsonAfter;

    unsigned char *recvBuffer = (unsigned char *)malloc(0x1000);
    int recvLen = 0x1000;
    CompressMock(recvJson, recvBuffer, recvLen);

    // device online
    std::string networkID = "deviceid-1";
    std::string deviceName = "remote_mock";
    // udid = deviceid-1:udid-001   uuid = deviceid-1:uuid-001
    DmDeviceInfo devInfo;
    strcpy(devInfo.deviceId, networkID.c_str());
    strcpy(devInfo.deviceName, deviceName.c_str());
    devInfo.deviceTypeId = 1;

    std::shared_ptr<SoftBusDeviceConnectionListener> ptrDeviceStateCallback =
        std::make_shared<SoftBusDeviceConnectionListener>();
    ptrDeviceStateCallback->OnDeviceOnline(devInfo);

    SoftBusSessionListener::OnBytesReceived(1, recvBuffer, recvLen);

    int count = 0;
    while (!GetSendMessFlagMock() && count < 10) {
        sleep(1);
        count ++;
    }

    ResetSendMessFlagMock();
    std::string uuidMessage = GetUuidMock();
    ASSERT_EQ(uuidMessage, "0065e65f-");

    ptrDeviceStateCallback->OnDeviceOffline(devInfo);
}

/**
 * @tc.name: GetRemoteHapTokenInfo003
 * @tc.desc: test remote hap send func, but get tokenInfo is wrong
 * @tc.type: FUNC
 * @tc.require:AR000GK6T5
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
        "\\\"dstDeviceId\\\":\\\"deviceid-1\\\",\\\"dstDeviceLevel\\\":\\\"\\\",\\\"message\\\":\\\"success\\\","
        "\\\"requestTokenId\\\":537919488,\\\"requestVersion\\\":2,\\\"responseDeviceId\\\":\\\"deviceid-1:udid-001\\\""
        ",\\\"responseVersion\\\":2,\\\"srcDeviceId\\\":\\\"local:udid-001\\\",\\\"srcDeviceLevel\\\":\\\"\\\","
        "\\\"statusCode\\\":0,\\\"uniqueId\\\":\\\"SyncRemoteHapTokenCommand\\\"}\",\"type\":\"response\"}";

    threads_.emplace_back(std::thread(SendTaskThread));

    std::string networkID = "deviceid-1";
    std::string deviceName = "remote_mock";
    // udid = deviceid-1:udid-001    uuid = deviceid-1:uuid-001
    DmDeviceInfo devInfo;
    strcpy(devInfo.deviceId, networkID.c_str());
    strcpy(devInfo.deviceName, deviceName.c_str());
    devInfo.deviceTypeId = 1;

    std::shared_ptr<SoftBusDeviceConnectionListener> ptrDeviceStateCallback =
        std::make_shared<SoftBusDeviceConnectionListener>();

    ptrDeviceStateCallback->OnDeviceOnline(devInfo);

    OHOS::DelayedSingleton<TokenSyncManagerService>::GetInstance()->GetRemoteHapTokenInfo(
        networkID, 0x20100000);

    AccessTokenID mapID = AccessTokenKit::AllocLocalTokenID(networkID, 0x20100000);
    ASSERT_EQ(mapID, (AccessTokenID)0);

    ptrDeviceStateCallback->OnDeviceOffline(devInfo);
}

/**
 * @tc.name: GetRemoteHapTokenInfo004
 * @tc.desc: test remote hap send func, but json payload lost parameter
 * @tc.type: FUNC
 * @tc.require:AR000GK6T5
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
        "\\\"dstDeviceId\\\":\\\"deviceid-1\\\",\\\"dstDeviceLevel\\\":\\\"\\\",\\\"message\\\":\\\"success\\\","
        "\\\"requestTokenId\\\":537919488,\\\"requestVersion\\\":2,\\\"responseDeviceId\\\":\\\"deviceid-1:udid-001\\\""
        ",\\\"responseVersion\\\":2,\\\"srcDeviceId\\\":\\\"local:udid-001\\\",\\\"srcDeviceLevel\\\":\\\"\\\","
        "\\\"statusCode\\\":0,\\\"uniqueId\\\":\\\"SyncRemoteHapTokenCommand\\\"}\",\"type\":\"response\"}";

    threads_.emplace_back(std::thread(SendTaskThread));

    std::string networkID = "deviceid-1";
    std::string deviceName = "remote_mock";
    // udid = deviceid-1:udid-001    uuid = deviceid-1:uuid-001
    DmDeviceInfo devInfo;
    strcpy(devInfo.deviceId, networkID.c_str());
    strcpy(devInfo.deviceName, deviceName.c_str());
    devInfo.deviceTypeId = 1;

    std::shared_ptr<SoftBusDeviceConnectionListener> ptrDeviceStateCallback =
        std::make_shared<SoftBusDeviceConnectionListener>();

    ptrDeviceStateCallback->OnDeviceOnline(devInfo);

    OHOS::DelayedSingleton<TokenSyncManagerService>::GetInstance()->GetRemoteHapTokenInfo(
        networkID, 0x20100000);

    AccessTokenID mapID = AccessTokenKit::AllocLocalTokenID(networkID, 0x20100000);
    ASSERT_EQ(mapID, (AccessTokenID)0);

    ptrDeviceStateCallback->OnDeviceOffline(devInfo);
}

/**
 * @tc.name: GetRemoteHapTokenInfo005
 * @tc.desc: test remote hap send func, but json payload parameter type is wrong
 * @tc.type: FUNC
 * @tc.require:AR000GK6T5
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
        "\\\"dstDeviceId\\\":\\\"deviceid-1\\\",\\\"dstDeviceLevel\\\":\\\"\\\",\\\"message\\\":\\\"success\\\","
        "\\\"requestTokenId\\\":537919488,\\\"requestVersion\\\":2,\\\"responseDeviceId\\\":\\\"deviceid-1:udid-001\\\""
        ",\\\"responseVersion\\\":2,\\\"srcDeviceId\\\":\\\"local:udid-001\\\",\\\"srcDeviceLevel\\\":\\\"\\\","
        "\\\"statusCode\\\":0,\\\"uniqueId\\\":\\\"SyncRemoteHapTokenCommand\\\"}\",\"type\":\"response\"}";

    threads_.emplace_back(std::thread(SendTaskThread));

    std::string networkID = "deviceid-1";
    std::string deviceName = "remote_mock";
    // udid = deviceid-1:udid-001    uuid = deviceid-1:uuid-001
    DmDeviceInfo devInfo;
    strcpy(devInfo.deviceId, networkID.c_str());
    strcpy(devInfo.deviceName, deviceName.c_str());
    devInfo.deviceTypeId = 1;

    std::shared_ptr<SoftBusDeviceConnectionListener> ptrDeviceStateCallback =
        std::make_shared<SoftBusDeviceConnectionListener>();

    ptrDeviceStateCallback->OnDeviceOnline(devInfo);

    OHOS::DelayedSingleton<TokenSyncManagerService>::GetInstance()->GetRemoteHapTokenInfo(
        networkID, 0x20100000);

    AccessTokenID mapID = AccessTokenKit::AllocLocalTokenID(networkID, 0x20100000);
    ASSERT_EQ(mapID, (AccessTokenID)0);

    ptrDeviceStateCallback->OnDeviceOffline(devInfo);
}

/**
 * @tc.name: GetRemoteHapTokenInfo006
 * @tc.desc: test remote hap send func, but json payload parameter format is wrong
 * @tc.type: FUNC
 * @tc.require:AR000GK6T5
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
        "\\\"dstDeviceId\\\":\\\"deviceid-1\\\",\\\"dstDeviceLevel\\\":\\\"\\\",\\\"message\\\":\\\"success\\\","
        "\\\"requestTokenId\\\":537919488,\\\"requestVersion\\\":2,\\\"responseDeviceId\\\":\\\"deviceid-1:udid-001\\\""
        ",\\\"responseVersion\\\":2,\\\"srcDeviceId\\\":\\\"local:udid-001\\\",\\\"srcDeviceLevel\\\":\\\"\\\","
        "\\\"statusCode\\\":0,\\\"uniqueId\\\":\\\"SyncRemoteHapTokenCommand\\\"}\",\"type\":\"response\"}";

    threads_.emplace_back(std::thread(SendTaskThread));

    std::string networkID = "deviceid-1";
    std::string deviceName = "remote_mock";
    // udid = deviceid-1:udid-001    uuid = deviceid-1:uuid-001
    DmDeviceInfo devInfo;
    strcpy(devInfo.deviceId, networkID.c_str());
    strcpy(devInfo.deviceName, deviceName.c_str());
    devInfo.deviceTypeId = 1;

    std::shared_ptr<SoftBusDeviceConnectionListener> ptrDeviceStateCallback =
        std::make_shared<SoftBusDeviceConnectionListener>();

    ptrDeviceStateCallback->OnDeviceOnline(devInfo);

    OHOS::DelayedSingleton<TokenSyncManagerService>::GetInstance()->GetRemoteHapTokenInfo(
        networkID, 0x20100000);

    AccessTokenID mapID = AccessTokenKit::AllocLocalTokenID(networkID, 0x20100000);
    ASSERT_EQ(mapID, (AccessTokenID)0);

    ptrDeviceStateCallback->OnDeviceOffline(devInfo);
}

/**
 * @tc.name: GetRemoteHapTokenInfo007
 * @tc.desc: test remote hap send func, statusCode is wrong
 * @tc.type: FUNC
 * @tc.require:AR000GK6T5
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

    threads_.emplace_back(std::thread(SendTaskThread));

    std::string networkID = "deviceid-1";
    std::string deviceName = "remote_mock";
    // udid = deviceid-1:udid-001    uuid = deviceid-1:uuid-001
    DmDeviceInfo devInfo;
    strcpy(devInfo.deviceId, networkID.c_str());
    strcpy(devInfo.deviceName, deviceName.c_str());
    devInfo.deviceTypeId = 1;

    std::shared_ptr<SoftBusDeviceConnectionListener> ptrDeviceStateCallback =
        std::make_shared<SoftBusDeviceConnectionListener>();

    ptrDeviceStateCallback->OnDeviceOnline(devInfo);

    OHOS::DelayedSingleton<TokenSyncManagerService>::GetInstance()->GetRemoteHapTokenInfo(
        networkID, 0x20100000);

    AccessTokenID mapID = AccessTokenKit::AllocLocalTokenID(networkID, 0x20100000);
    ASSERT_EQ(mapID, (AccessTokenID)0);

    ptrDeviceStateCallback->OnDeviceOffline(devInfo);
}

/**
 * @tc.name: GetRemoteHapTokenInfo008
 * @tc.desc: test remote hap recv func, tokenID is not exist
 * @tc.type: FUNC
 * @tc.require:AR000GK6T5
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
        "\\\"srcDeviceId\\\":\\\"deviceid-1\\\",\\\"srcDeviceLevel\\\":\\\"\\\",\\\"statusCode\\\":100001,"
        "\\\"uniqueId\\\":\\\"SyncRemoteHapTokenCommand\\\"}\",\"type\":\"request\"}";

    // create recv message
    std::string recvJson = jsonBefore + tokenJsonStr + jsonAfter;
    unsigned char *recvBuffer = (unsigned char *)malloc(0x1000);
    int recvLen = 0x1000;
    CompressMock(recvJson, recvBuffer, recvLen);

    // device online
    std::string networkID = "deviceid-1";
    std::string deviceName = "remote_mock";
    // udid = deviceid-1:udid-001   uuid = deviceid-1:uuid-001
    DmDeviceInfo devInfo;
    strcpy(devInfo.deviceId, networkID.c_str());
    strcpy(devInfo.deviceName, deviceName.c_str());
    devInfo.deviceTypeId = 1;

    std::shared_ptr<SoftBusDeviceConnectionListener> ptrDeviceStateCallback =
        std::make_shared<SoftBusDeviceConnectionListener>();
    ptrDeviceStateCallback->OnDeviceOnline(devInfo);

    SoftBusSessionListener::OnBytesReceived(1, recvBuffer, recvLen);

    int count = 0;
    while (!GetSendMessFlagMock() && count < 10) {
        sleep(1);
        count ++;
    }

    ResetSendMessFlagMock();
    std::string uuidMessage = GetUuidMock();
    ASSERT_EQ(uuidMessage, "0065e65f-");

    ptrDeviceStateCallback->OnDeviceOffline(devInfo);
}

/**
 * @tc.name: SyncNativeTokens001
 * @tc.desc: when device is online, sync remote nativetokens which has dcap
 * @tc.type: FUNC
 * @tc.require:AR000GK6T6
 */
HWTEST_F(TokenSyncServiceTest, SyncNativeTokens001, TestSize.Level1)
{
    ACCESSTOKEN_LOG_INFO(LABEL, "SyncNativeTokens001 start.");
    g_jsonBefore = "{\"commandName\":\"SyncRemoteNativeTokenCommand\", \"id\":\"";
    g_jsonAfter =
        "\",\"jsonPayload\":\"{\\\"NativeTokenInfos\\\":[{\\\"apl\\\":3,\\\"processName\\\":\\\"attest\\\","
        "\\\"tokenAttr\\\":0,\\\"tokenId\\\":671836008,\\\"version\\\":1,"
        "\\\"dcaps\\\":[\\\"SYSDCAP\\\",\\\"DMSDCAP\\\"]},"
        "{\\\"APL\\\":3,\\\"processName\\\":\\\"attest1\\\",\\\"tokenAttr\\\":0,\\\"tokenId\\\":671836018,"
        "\\\"version\\\":1,\\\"dcaps\\\":[\\\"SYSDCAP\\\",\\\"DMSDCAP\\\"]}],"
        "\\\"commandName\\\":\\\"SyncRemoteNativeTokenCommand\\\","
        "\\\"dstDeviceId\\\":\\\"deviceid-1\\\",\\\"dstDeviceLevel\\\":\\\"\\\",\\\"message\\\":\\\"success\\\","
        "\\\"requestVersion\\\":2,\\\"responseDeviceId\\\":\\\"deviceid-1:udid-001\\\","
        "\\\"responseVersion\\\":2,\\\"srcDeviceId\\\":\\\"local:udid-001\\\","
        "\\\"srcDeviceLevel\\\":\\\"\\\",\\\"statusCode\\\":0,\\\"uniqueId\\\":\\\"SyncRemoteNativeTokenCommand\\\"}\","
        "\"type\":\"response\"}";

    threads_.emplace_back(std::thread(SendTaskThread));

    std::string networkID = "deviceid-1";
    std::string deviceName = "remote_mock";
    // udid = deviceid-1:udid-001    uuid = deviceid-1:uuid-001
    DmDeviceInfo devInfo;
    strcpy(devInfo.deviceId, networkID.c_str());
    strcpy(devInfo.deviceName, deviceName.c_str());
    devInfo.deviceTypeId = 1;

    std::shared_ptr<SoftBusDeviceConnectionListener> ptrDeviceStateCallback =
        std::make_shared<SoftBusDeviceConnectionListener>();

    ptrDeviceStateCallback->OnDeviceOnline(devInfo);

    sleep(6);

    AccessTokenID mapID = AccessTokenKit::GetRemoteNativeTokenID(networkID, 0x280b6768);
    ASSERT_NE(mapID, (AccessTokenID)0);
    int ret = AccessTokenKit::CheckNativeDCap(mapID, "SYSDCAP");
    ASSERT_EQ(ret, RET_SUCCESS);
    ret = AccessTokenKit::CheckNativeDCap(mapID, "DMSDCAP");
    ASSERT_EQ(ret, RET_SUCCESS);

    mapID = AccessTokenKit::GetRemoteNativeTokenID(networkID, 0x280b6772);
    ASSERT_NE(mapID, (AccessTokenID)0);
    ret = AccessTokenKit::CheckNativeDCap(mapID, "SYSDCAP");
    ASSERT_EQ(ret, RET_SUCCESS);
    ret = AccessTokenKit::CheckNativeDCap(mapID, "DMSDCAP");
    ASSERT_EQ(ret, RET_SUCCESS);

    ptrDeviceStateCallback->OnDeviceOffline(devInfo);
}
