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
static std::shared_ptr<SoftBusDeviceConnectionListener> g_ptrDeviceStateCallback =
    std::make_shared<SoftBusDeviceConnectionListener>();
static std::string g_networkID = "deviceid-1";
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
void TokenSyncServiceTest::SetUpTestCase()
{}
void TokenSyncServiceTest::TearDownTestCase()
{}
void TokenSyncServiceTest::SetUp()
{}
void TokenSyncServiceTest::TearDown()
{
    for (auto it = threads_.begin(); it != threads_.end(); it++) {
        it->join();
    }
    threads_.clear();

    if (g_ptrDeviceStateCallback != nullptr) {
        g_ptrDeviceStateCallback->OnDeviceOffline(g_devInfo);
        sleep(1);
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

/**
 * @tc.name: GetRemoteHapTokenInfo001
 * @tc.desc: test remote hap send func
 * @tc.type: FUNC
 * @tc.require:AR000GK6T5 AR000GK6T9
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

    g_ptrDeviceStateCallback->OnDeviceOnline(g_devInfo);

    int ret = OHOS::DelayedSingleton<TokenSyncManagerService>::GetInstance()->GetRemoteHapTokenInfo(
        g_networkID, 0x20100000);
    ASSERT_EQ(ret, RET_SUCCESS);

    AccessTokenID mapID = AccessTokenKit::AllocLocalTokenID(g_networkID, 0x20100000);
    ASSERT_NE(mapID, (AccessTokenID)0);

    HapTokenInfo tokeInfo;
    ret = AccessTokenKit::GetHapTokenInfo(mapID, tokeInfo);
    ASSERT_EQ(ret, RET_SUCCESS);
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
        "\\\"srcDeviceId\\\":\\\"deviceid-1\\\",\\\"srcDeviceLevel\\\":\\\"\\\",\\\"statusCode\\\":100001,"
        "\\\"uniqueId\\\":\\\"SyncRemoteHapTokenCommand\\\"}\",\"type\":\"request\"}";

    std::string recvJson = jsonBefore + tokenJsonStr + jsonAfter;

    unsigned char *recvBuffer = (unsigned char *)malloc(0x1000);
    int recvLen = 0x1000;
    CompressMock(recvJson, recvBuffer, recvLen);

    g_ptrDeviceStateCallback->OnDeviceOnline(g_devInfo);

    SoftBusSessionListener::OnBytesReceived(1, recvBuffer, recvLen);

    int count = 0;
    while (!GetSendMessFlagMock() && count < 10) {
        sleep(1);
        count ++;
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
        "\\\"dstDeviceId\\\":\\\"deviceid-1\\\",\\\"dstDeviceLevel\\\":\\\"\\\",\\\"message\\\":\\\"success\\\","
        "\\\"requestTokenId\\\":537919488,\\\"requestVersion\\\":2,\\\"responseDeviceId\\\":\\\"deviceid-1:udid-001\\\""
        ",\\\"responseVersion\\\":2,\\\"srcDeviceId\\\":\\\"local:udid-001\\\",\\\"srcDeviceLevel\\\":\\\"\\\","
        "\\\"statusCode\\\":0,\\\"uniqueId\\\":\\\"SyncRemoteHapTokenCommand\\\"}\",\"type\":\"response\"}";

    threads_.emplace_back(std::thread(SendTaskThread));

    g_ptrDeviceStateCallback->OnDeviceOnline(g_devInfo);

    OHOS::DelayedSingleton<TokenSyncManagerService>::GetInstance()->GetRemoteHapTokenInfo(
        g_networkID, 0x20100000);

    AccessTokenID mapID = AccessTokenKit::AllocLocalTokenID(g_networkID, 0x20100000);
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
        "\\\"dstDeviceId\\\":\\\"deviceid-1\\\",\\\"dstDeviceLevel\\\":\\\"\\\",\\\"message\\\":\\\"success\\\","
        "\\\"requestTokenId\\\":537919488,\\\"requestVersion\\\":2,\\\"responseDeviceId\\\":\\\"deviceid-1:udid-001\\\""
        ",\\\"responseVersion\\\":2,\\\"srcDeviceId\\\":\\\"local:udid-001\\\",\\\"srcDeviceLevel\\\":\\\"\\\","
        "\\\"statusCode\\\":0,\\\"uniqueId\\\":\\\"SyncRemoteHapTokenCommand\\\"}\",\"type\":\"response\"}";

    threads_.emplace_back(std::thread(SendTaskThread));

    g_ptrDeviceStateCallback->OnDeviceOnline(g_devInfo);

    OHOS::DelayedSingleton<TokenSyncManagerService>::GetInstance()->GetRemoteHapTokenInfo(
        g_networkID, 0x20100000);

    AccessTokenID mapID = AccessTokenKit::AllocLocalTokenID(g_networkID, 0x20100000);
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
        "\\\"dstDeviceId\\\":\\\"deviceid-1\\\",\\\"dstDeviceLevel\\\":\\\"\\\",\\\"message\\\":\\\"success\\\","
        "\\\"requestTokenId\\\":537919488,\\\"requestVersion\\\":2,\\\"responseDeviceId\\\":\\\"deviceid-1:udid-001\\\""
        ",\\\"responseVersion\\\":2,\\\"srcDeviceId\\\":\\\"local:udid-001\\\",\\\"srcDeviceLevel\\\":\\\"\\\","
        "\\\"statusCode\\\":0,\\\"uniqueId\\\":\\\"SyncRemoteHapTokenCommand\\\"}\",\"type\":\"response\"}";

    threads_.emplace_back(std::thread(SendTaskThread));

    g_ptrDeviceStateCallback->OnDeviceOnline(g_devInfo);

    OHOS::DelayedSingleton<TokenSyncManagerService>::GetInstance()->GetRemoteHapTokenInfo(
        g_networkID, 0x20100000);

    AccessTokenID mapID = AccessTokenKit::AllocLocalTokenID(g_networkID, 0x20100000);
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
        "\\\"dstDeviceId\\\":\\\"deviceid-1\\\",\\\"dstDeviceLevel\\\":\\\"\\\",\\\"message\\\":\\\"success\\\","
        "\\\"requestTokenId\\\":537919488,\\\"requestVersion\\\":2,\\\"responseDeviceId\\\":\\\"deviceid-1:udid-001\\\""
        ",\\\"responseVersion\\\":2,\\\"srcDeviceId\\\":\\\"local:udid-001\\\",\\\"srcDeviceLevel\\\":\\\"\\\","
        "\\\"statusCode\\\":0,\\\"uniqueId\\\":\\\"SyncRemoteHapTokenCommand\\\"}\",\"type\":\"response\"}";

    threads_.emplace_back(std::thread(SendTaskThread));

    g_ptrDeviceStateCallback->OnDeviceOnline(g_devInfo);

    OHOS::DelayedSingleton<TokenSyncManagerService>::GetInstance()->GetRemoteHapTokenInfo(
        g_networkID, 0x20100000);

    AccessTokenID mapID = AccessTokenKit::AllocLocalTokenID(g_networkID, 0x20100000);
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

    threads_.emplace_back(std::thread(SendTaskThread));


    g_ptrDeviceStateCallback->OnDeviceOnline(g_devInfo);

    OHOS::DelayedSingleton<TokenSyncManagerService>::GetInstance()->GetRemoteHapTokenInfo(
        g_networkID, 0x20100000);

    AccessTokenID mapID = AccessTokenKit::AllocLocalTokenID(g_networkID, 0x20100000);
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
        "\\\"srcDeviceId\\\":\\\"deviceid-1\\\",\\\"srcDeviceLevel\\\":\\\"\\\",\\\"statusCode\\\":100001,"
        "\\\"uniqueId\\\":\\\"SyncRemoteHapTokenCommand\\\"}\",\"type\":\"request\"}";

    // create recv message
    std::string recvJson = jsonBefore + tokenJsonStr + jsonAfter;
    unsigned char *recvBuffer = (unsigned char *)malloc(0x1000);
    int recvLen = 0x1000;
    CompressMock(recvJson, recvBuffer, recvLen);

    g_ptrDeviceStateCallback->OnDeviceOnline(g_devInfo);
    SoftBusSessionListener::OnBytesReceived(1, recvBuffer, recvLen);

    int count = 0;
    while (!GetSendMessFlagMock() && count < 10) {
        sleep(1);
        count ++;
    }
    free(recvBuffer);

    ResetSendMessFlagMock();
    std::string uuidMessage = GetUuidMock();
    ASSERT_EQ(uuidMessage, "0065e65f-");
}

/**
 * @tc.name: SyncNativeTokens001
 * @tc.desc: when device is online, sync remote nativetokens which have dcap
 * @tc.type: FUNC
 * @tc.require:AR000GK6T6
 */
HWTEST_F(TokenSyncServiceTest, SyncNativeTokens001, TestSize.Level1)
{
    ACCESSTOKEN_LOG_INFO(LABEL, "SyncNativeTokens001 start.");
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
        "\\\"srcDeviceLevel\\\":\\\"\\\",\\\"statusCode\\\":0,\\\"uniqueId\\\":\\\"SyncRemoteNativeTokenCommand\\\"}\","
        "\"type\":\"response\"}";

    threads_.emplace_back(std::thread(SendTaskThread));

    g_ptrDeviceStateCallback->OnDeviceOnline(g_devInfo);

    sleep(6);

    AccessTokenID mapID = AccessTokenKit::GetRemoteNativeTokenID(g_networkID, 0x28000000);
    ASSERT_NE(mapID, (AccessTokenID)0);
    int ret = AccessTokenKit::CheckNativeDCap(mapID, "SYSDCAP");
    ASSERT_EQ(ret, RET_SUCCESS);
    ret = AccessTokenKit::CheckNativeDCap(mapID, "DMSDCAP");
    ASSERT_EQ(ret, RET_SUCCESS);

    mapID = AccessTokenKit::GetRemoteNativeTokenID(g_networkID, 0x28000001);
    ASSERT_NE(mapID, (AccessTokenID)0);
    ret = AccessTokenKit::CheckNativeDCap(mapID, "SYSDCAP");
    ASSERT_EQ(ret, RET_SUCCESS);
    ret = AccessTokenKit::CheckNativeDCap(mapID, "DMSDCAP");
    ASSERT_EQ(ret, RET_SUCCESS);
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

    threads_.emplace_back(std::thread(SendTaskThread));
    g_ptrDeviceStateCallback->OnDeviceOnline(g_devInfo);

    sleep(6);

    AccessTokenID mapID = AccessTokenKit::GetRemoteNativeTokenID(g_networkID, 0x28000000);
    ASSERT_NE(mapID, (AccessTokenID)0);
    int ret = AccessTokenKit::CheckNativeDCap(mapID, "SYSDCAP");
    ASSERT_EQ(ret, RET_SUCCESS);
    ret = AccessTokenKit::CheckNativeDCap(mapID, "DMSDCAP");
    ASSERT_EQ(ret, RET_SUCCESS);

    mapID = AccessTokenKit::GetRemoteNativeTokenID(g_networkID, 0x28000001);
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

    AccessTokenID mapID = AccessTokenKit::GetRemoteNativeTokenID(g_networkID, 0x28000000);
    ASSERT_EQ(mapID, (AccessTokenID)0);

    mapID = AccessTokenKit::GetRemoteNativeTokenID(g_networkID, 0x28000001);
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

    AccessTokenID mapID = AccessTokenKit::GetRemoteNativeTokenID(g_networkID, 0x28000000);
    ASSERT_EQ(mapID, (AccessTokenID)0);

    mapID = AccessTokenKit::GetRemoteNativeTokenID(g_networkID, 0x28000001);
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

    g_ptrDeviceStateCallback->OnDeviceOnline(g_devInfo);
    SoftBusSessionListener::OnBytesReceived(1, recvBuffer, recvLen);

    int count = 0;
    while (!GetSendMessFlagMock() && count < 10) {
        sleep(1);
        count ++;
    }
    free(recvBuffer);

    ResetSendMessFlagMock();
    std::string uuidMessage = GetUuidMock();
    ASSERT_EQ(uuidMessage, "ec23cd2d-");
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

/**
 * @tc.name: UpdateRemoteHapTokenCommand001
 * @tc.desc: recv mapping hap token update message
 * @tc.type: FUNC
 * @tc.require:AR000GK6TB
 */
HWTEST_F(TokenSyncServiceTest, UpdateRemoteHapTokenCommand001, TestSize.Level1)
{
    ACCESSTOKEN_LOG_INFO(LABEL, "UpdateRemoteHapTokenCommand001 start.");
    sleep(1);
    g_ptrDeviceStateCallback->OnDeviceOnline(g_devInfo);
    sleep(6);

    int ret = AccessTokenKit::SetRemoteHapTokenInfo(g_networkID, g_remoteHapInfo);
    ASSERT_EQ(ret, RET_SUCCESS);
    AccessTokenID mapID = AccessTokenKit::AllocLocalTokenID(g_networkID, 0x20000001);
    ASSERT_NE(mapID, 0);

    HapTokenInfo mapInfo;
    ret = AccessTokenKit::GetHapTokenInfo(mapID, mapInfo);
    ASSERT_EQ(ret, RET_SUCCESS);

    ret = AccessTokenKit::VerifyAccessToken(mapID, "ohos.permission.CAMERA");
    ASSERT_EQ(ret, PERMISSION_DENIED);

    std::string recvJson =
        "{\"commandName\":\"UpdateRemoteHapTokenCommand\",\"id\":\"ec23cd2d-\",\"jsonPayload\":"
        "\"{\\\"HapTokenInfos\\\":{\\\"apl\\\":1,\\\"appID\\\":\\\"testtesttesttest\\\","
        "\\\"bundleName\\\":\\\"accesstoken_test\\\",\\\"deviceID\\\":\\\"0\\\",\\\"instIndex\\\":0,"
        "\\\"permState\\\":[{\\\"grantConfig\\\":[{\\\"grantFlags\\\":2,\\\"grantStatus\\\":0,"
        "\\\"resDeviceID\\\":\\\"local\\\"}],\\\"isGeneral\\\":true,"
        "\\\"permissionName\\\":\\\"ohos.permission.CAMERA\\\"},{\\\"grantConfig\\\":[{\\\"grantFlags\\\":1,"
        "\\\"grantStatus\\\":-1,\\\"resDeviceID\\\":\\\"device 1\\\"},{\\\"grantFlags\\\":2,\\\"grantStatus\\\":-1,"
        "\\\"resDeviceID\\\":\\\"device 2\\\"}],\\\"isGeneral\\\":false,"
        "\\\"permissionName\\\":\\\"ohos.permission.ANSWER_CALL\\\"}],\\\"tokenAttr\\\":0,\\\"tokenID\\\":536870913,"
        "\\\"userID\\\":1,\\\"version\\\":1},\\\"commandName\\\":\\\"UpdateRemoteHapTokenCommand\\\","
        "\\\"dstDeviceId\\\":\\\"local:udid-001\\\",\\\"dstDeviceLevel\\\":\\\"\\\",\\\"message\\\":\\\"success\\\","
        "\\\"requestTokenId\\\":536870913,\\\"requestVersion\\\":2,\\\"responseDeviceId\\\":\\\"\\\","
        "\\\"responseVersion\\\":2,"
        "\\\"srcDeviceId\\\":\\\"deviceid-1\\\",\\\"srcDeviceLevel\\\":\\\"\\\",\\\"statusCode\\\":100001,"
        "\\\"uniqueId\\\":\\\"UpdateRemoteHapTokenCommand\\\"}\",\"type\":\"request\"}";

    unsigned char *recvBuffer = (unsigned char *)malloc(0x1000);
    int recvLen = 0x1000;
    CompressMock(recvJson, recvBuffer, recvLen);
    SoftBusSessionListener::OnBytesReceived(1, recvBuffer, recvLen);
    sleep(2);

    free(recvBuffer);

    ret = AccessTokenKit::VerifyAccessToken(mapID, "ohos.permission.CAMERA");

    ASSERT_EQ(ret, PERMISSION_GRANTED);

    recvJson =
        "{\"commandName\":\"UpdateRemoteHapTokenCommand\",\"id\":\"ec23cd2d-\",\"jsonPayload\":"
        "\"{\\\"HapTokenInfos\\\":{\\\"apl\\\":2,\\\"appID\\\":\\\"testtesttesttest\\\","
        "\\\"bundleName\\\":\\\"accesstoken_test\\\",\\\"deviceID\\\":\\\"0\\\",\\\"instIndex\\\":0,"
        "\\\"permState\\\":[{\\\"grantConfig\\\":[{\\\"grantFlags\\\":2,\\\"grantStatus\\\":0,"
        "\\\"resDeviceID\\\":\\\"local\\\"}],\\\"isGeneral\\\":true,"
        "\\\"permissionName\\\":\\\"ohos.permission.CAMERA\\\"},{\\\"grantConfig\\\":[{\\\"grantFlags\\\":1,"
        "\\\"grantStatus\\\":-1,\\\"resDeviceID\\\":\\\"device 1\\\"},{\\\"grantFlags\\\":2,\\\"grantStatus\\\":-1,"
        "\\\"resDeviceID\\\":\\\"device 2\\\"}],\\\"isGeneral\\\":false,"
        "\\\"permissionName\\\":\\\"ohos.permission.ANSWER_CALL\\\"}],\\\"tokenAttr\\\":0,\\\"tokenID\\\":536870913,"
        "\\\"userID\\\":1,\\\"version\\\":1},\\\"commandName\\\":\\\"UpdateRemoteHapTokenCommand\\\","
        "\\\"dstDeviceId\\\":\\\"local:udid-001\\\",\\\"dstDeviceLevel\\\":\\\"\\\",\\\"message\\\":\\\"success\\\","
        "\\\"requestTokenId\\\":536870913,\\\"requestVersion\\\":2,\\\"responseDeviceId\\\":\\\"\\\","
        "\\\"responseVersion\\\":2,"
        "\\\"srcDeviceId\\\":\\\"deviceid-1\\\",\\\"srcDeviceLevel\\\":\\\"\\\",\\\"statusCode\\\":100001,"
        "\\\"uniqueId\\\":\\\"UpdateRemoteHapTokenCommand\\\"}\",\"type\":\"request\"}";

    recvBuffer = (unsigned char *)malloc(0x1000);
    recvLen = 0x1000;
    CompressMock(recvJson, recvBuffer, recvLen);
    SoftBusSessionListener::OnBytesReceived(1, recvBuffer, recvLen);
    sleep(2);
    free(recvBuffer);

    ret = AccessTokenKit::GetHapTokenInfo(mapID, mapInfo);
    ASSERT_EQ(ret, RET_SUCCESS);
    ASSERT_EQ(mapInfo.apl, 2);
}

/**
 * @tc.name: DeleteRemoteTokenCommand001
 * @tc.desc: recv delete mapping hap token update message
 * @tc.type: FUNC
 * @tc.require:AR000GK6TC
 */
HWTEST_F(TokenSyncServiceTest, DeleteRemoteTokenCommand001, TestSize.Level1)
{
    ACCESSTOKEN_LOG_INFO(LABEL, "DeleteRemoteTokenCommand001 start.");

    g_ptrDeviceStateCallback->OnDeviceOnline(g_devInfo);

    int ret = AccessTokenKit::SetRemoteHapTokenInfo(g_networkID, g_remoteHapInfo);
    ASSERT_EQ(ret, RET_SUCCESS);
    AccessTokenID mapID = AccessTokenKit::AllocLocalTokenID(g_networkID, 0x20000001);
    ASSERT_NE(mapID, 0);

    HapTokenInfo mapInfo;
    ret = AccessTokenKit::GetHapTokenInfo(mapID, mapInfo);
    ASSERT_EQ(ret, RET_SUCCESS);

    // create recv message
    std::string recvJson =
        "{\"commandName\":\"DeleteRemoteTokenCommand\",\"id\":\"9ff19cdf-\",\"jsonPayload\":"
        "\"{\\\"commandName\\\":\\\"DeleteRemoteTokenCommand\\\","
        "\\\"dstDeviceId\\\":\\\"local:udid-001\\\",\\\"dstDeviceLevel\\\":\\\"\\\",\\\"message\\\":\\\"success\\\","
        "\\\"requestTokenId\\\":536870913,\\\"requestVersion\\\":2,\\\"responseDeviceId\\\":\\\"\\\","
        "\\\"responseVersion\\\":2,"
        "\\\"srcDeviceId\\\":\\\"deviceid-1\\\",\\\"srcDeviceLevel\\\":\\\"\\\",\\\"statusCode\\\":100001,"
        "\\\"tokenId\\\":536870913,\\\"uniqueId\\\":\\\"DeleteRemoteTokenCommand\\\"}\",\"type\":\"request\"}";

    unsigned char *recvBuffer = (unsigned char *)malloc(0x1000);
    int recvLen = 0x1000;
    CompressMock(recvJson, recvBuffer, recvLen);
    SoftBusSessionListener::OnBytesReceived(1, recvBuffer, recvLen);
    sleep(2);
    free(recvBuffer);
    ret = AccessTokenKit::GetHapTokenInfo(mapID, mapInfo);
    ASSERT_EQ(ret, RET_FAILED);
}

/**
 * @tc.name: DeviceOffline001
 * @tc.desc: test device offline, will delete
 * @tc.type: FUNC
 * @tc.require:AR000GK6TB
 */
HWTEST_F(TokenSyncServiceTest, DeviceOffline001, TestSize.Level1)
{
    ACCESSTOKEN_LOG_INFO(LABEL, "DeviceOffline001 start.");

    // device online
    g_ptrDeviceStateCallback->OnDeviceOnline(g_devInfo);

    int ret = AccessTokenKit::SetRemoteHapTokenInfo(g_networkID, g_remoteHapInfo);
    ASSERT_EQ(ret, RET_SUCCESS);
    AccessTokenID mapID = AccessTokenKit::AllocLocalTokenID(g_networkID, 0x20000001);
    ASSERT_NE(mapID, 0);

    HapTokenInfo mapInfo;
    ret = AccessTokenKit::GetHapTokenInfo(mapID, mapInfo);
    ASSERT_EQ(ret, RET_SUCCESS);

    g_ptrDeviceStateCallback->OnDeviceOffline(g_devInfo);
    sleep(1);

    ret = AccessTokenKit::GetHapTokenInfo(mapID, mapInfo);
    ASSERT_EQ(ret, RET_FAILED);
}
