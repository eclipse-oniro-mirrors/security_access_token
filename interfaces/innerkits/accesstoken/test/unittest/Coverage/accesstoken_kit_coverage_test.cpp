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

#include "accesstoken_kit_coverage_test.h"
#include <thread>

#include "access_token.h"
#include "access_token_error.h"
#include "accesstoken_common_log.h"
#include "hap_token_info.h"
#include "nativetoken_kit.h"
#include "permission_grant_info.h"
#include "permission_state_change_info_parcel.h"
#include "string_ex.h"
#include "test_common.h"
#include "tokenid_kit.h"
#include "token_setproc.h"
#define private public
#include "accesstoken_manager_client.h"
#undef private

using namespace testing::ext;

namespace OHOS {
namespace Security {
namespace AccessToken {
namespace {
static constexpr int32_t DEFAULT_API_VERSION = 8;
static const std::string TEST_BUNDLE_NAME = "ohos";
static const std::string TEST_PERMISSION_NAME_ALPHA = "ohos.permission.ALPHA";
static const std::string TEST_PERMISSION_NAME_BETA = "ohos.permission.BETA";
static const int TEST_USER_ID = 0;
uint64_t g_selfShellTokenId;
}

void AccessTokenCoverageTest::SetUpTestCase()
{
    g_selfShellTokenId = GetSelfTokenID();
    TestCommon::SetTestEvironment(g_selfShellTokenId);
}

void AccessTokenCoverageTest::TearDownTestCase()
{
    SetSelfTokenID(g_selfShellTokenId);
    TestCommon::ResetTestEvironment();
}

void AccessTokenCoverageTest::SetUp()
{
    g_selfShellTokenId = GetSelfTokenID();
    LOGI(ATM_DOMAIN, ATM_TAG, "SetUp ok.");
}

void AccessTokenCoverageTest::TearDown()
{
    EXPECT_EQ(0, SetSelfTokenID(g_selfShellTokenId));
}

class CbCustomizeTest : public PermStateChangeCallbackCustomize {
public:
    explicit CbCustomizeTest(const PermStateChangeScope &scopeInfo)
        : PermStateChangeCallbackCustomize(scopeInfo)
    {
    }

    ~CbCustomizeTest()
    {}

    virtual void PermStateChangeCallback(PermStateChangeInfo& result)
    {
        ready_ = true;
        int32_t status = (result.permStateChangeType == 1) ? PERMISSION_GRANTED : PERMISSION_DENIED;
        ASSERT_EQ(status, AccessTokenKit::VerifyAccessToken(result.tokenID, result.permissionName));
    }

    bool ready_;
};

/**
 * @tc.name: PermStateChangeCallback001
 * @tc.desc: PermissionStateChangeCallback::PermStateChangeCallback function test.
 * @tc.type: FUNC
 * @tc.require: issueI61NS6
 */
HWTEST_F(AccessTokenCoverageTest, PermStateChangeCallback001, TestSize.Level1)
{
    PermStateChangeInfo result = {
        .permStateChangeType = 0,
        .tokenID = 123,
        .permissionName = "ohos.permission.CAMERA"
    };

    std::shared_ptr<CbCustomizeTest> callbackPtr = nullptr;
    std::shared_ptr<PermissionStateChangeCallback> callback = std::make_shared<PermissionStateChangeCallback>(
        callbackPtr);
    ASSERT_NE(callback, nullptr);

    callback->PermStateChangeCallback(result);
    ASSERT_EQ(callback->customizedCallback_, nullptr);
    callback->Stop();
}

class TestCallBack : public PermissionStateChangeCallbackStub {
public:
    TestCallBack() = default;
    virtual ~TestCallBack() = default;

    void PermStateChangeCallback(PermStateChangeInfo& result)
    {
        GTEST_LOG_(INFO) << "PermStateChangeCallback,  tokenID is " << result.tokenID;
    }
};

/**
 * @tc.name: OnRemoteRequest001
 * @tc.desc: StateChangeCallbackStub::OnRemoteRequest function test
 * @tc.type: FUNC
 * @tc.require: issueI61A6M
 */
HWTEST_F(AccessTokenCoverageTest, OnRemoteRequest001, TestSize.Level1)
{
    PermStateChangeInfo info = {
        .permStateChangeType = 0,
        .tokenID = 123,
        .permissionName = "ohos.permission.CAMERA"
    };

    TestCallBack callback;
    PermissionStateChangeInfoParcel infoParcel;
    infoParcel.changeInfo = info;

    OHOS::MessageParcel data;
    std::string descriptor = "I don't know";
    data.WriteInterfaceToken(OHOS::Str8ToStr16(descriptor));
    ASSERT_EQ(true, data.WriteParcelable(&infoParcel));

    OHOS::MessageParcel reply;
    OHOS::MessageOption option(OHOS::MessageOption::TF_SYNC);
    ASSERT_NE(0,
        callback.OnRemoteRequest(static_cast<uint32_t>(AccesstokenStateChangeInterfaceCode::PERMISSION_STATE_CHANGE),
        data, reply, option)); // descriptor false

    ASSERT_EQ(true, data.WriteInterfaceToken(IPermissionStateCallback::GetDescriptor()));
    ASSERT_EQ(true, data.WriteParcelable(&infoParcel));
    uint32_t code = 10;
    ASSERT_NE(0, callback.OnRemoteRequest(code, data, reply, option)); // descriptor true + msgCode false
}

/**
 * @tc.name: CreatePermStateChangeCallback001
 * @tc.desc: AccessTokenManagerClient::CreatePermStateChangeCallback function test
 * @tc.type: FUNC
 * @tc.require: issueI61A6M
 */
HWTEST_F(AccessTokenCoverageTest, CreatePermStateChangeCallback001, TestSize.Level1)
{
    std::vector<std::string> reqPerm;
    reqPerm.emplace_back("ohos.permission.GET_SENSITIVE_PERMISSIONS");
    MockHapToken mock("CreatePermStateChangeCallback001", reqPerm, true);

    std::vector<std::shared_ptr<CbCustomizeTest>> callbackList;

    uint32_t times = 201;
    for (uint32_t i = 0; i < times; i++) {
        PermStateChangeScope scopeInfo;
        scopeInfo.permList = {};
        scopeInfo.tokenIDs = {};
        auto callbackPtr = std::make_shared<CbCustomizeTest>(scopeInfo);
        callbackList.emplace_back(callbackPtr);
        int32_t res = AccessTokenKit::RegisterPermStateChangeCallback(callbackPtr);

        if (i == 200) {
            EXPECT_EQ(AccessTokenError::ERR_CALLBACKS_EXCEED_LIMITATION, res);
            break;
        }
    }

    for (uint32_t i = 0; i < 200; i++) {
        ASSERT_EQ(0, AccessTokenKit::UnRegisterPermStateChangeCallback(callbackList[i]));
    }

    std::shared_ptr<PermStateChangeCallbackCustomize> customizedCb = nullptr;
    AccessTokenKit::RegisterPermStateChangeCallback(customizedCb); // customizedCb is null
}

/**
 * @tc.name: InitProxy001
 * @tc.desc: AccessTokenManagerClient::InitProxy function test
 * @tc.type: FUNC
 * @tc.require: issueI61A6M
 */
HWTEST_F(AccessTokenCoverageTest, InitProxy001, TestSize.Level1)
{
    ASSERT_NE(nullptr, AccessTokenManagerClient::GetInstance().proxy_);
    OHOS::sptr<IAccessTokenManager> proxy = AccessTokenManagerClient::GetInstance().proxy_; // backup
    AccessTokenManagerClient::GetInstance().proxy_ = nullptr;
    ASSERT_EQ(nullptr, AccessTokenManagerClient::GetInstance().proxy_);
    AccessTokenManagerClient::GetInstance().InitProxy(); // proxy_ is null
    AccessTokenManagerClient::GetInstance().proxy_ = proxy; // recovery
}

/**
 * @tc.name: AllocHapToken001
 * @tc.desc: AccessTokenKit::AllocHapToken function test
 * @tc.type: FUNC
 * @tc.require: issueI61A6M
 */
HWTEST_F(AccessTokenCoverageTest, AllocHapToken001, TestSize.Level1)
{
    HapInfoParams info;
    HapPolicyParams policy;
    info.userID = -1;
    AccessTokenKit::AllocHapToken(info, policy);
    ASSERT_EQ(-1, info.userID);
}

/**
 * @tc.name: VerifyAccessToken005
 * @tc.desc: AccessTokenKit::VerifyAccessToken function test
 * @tc.type: FUNC
 * @tc.require: issueI61A6M
 */
HWTEST_F(AccessTokenCoverageTest, VerifyAccessToken005, TestSize.Level1)
{
    HapInfoParams info = {
        .userID = TEST_USER_ID,
        .bundleName = "accesstoken_test3",
        .instIndex = 0,
        .appIDDesc = "test3",
        .apiVersion = DEFAULT_API_VERSION
    };
    PermissionStateFull permState = {
        .permissionName = "ohos.permission.GET_BUNDLE_INFO",
        .isGeneral = true,
        .resDeviceID = {"local3"},
        .grantStatus = {PermissionState::PERMISSION_GRANTED},
        .grantFlags = {1}
    };

    HapPolicyParams policy = {
        .apl = APL_NORMAL,
        .domain = "test.domain3",
        .permStateList = {permState}
    };

    AccessTokenIDEx tokenIdEx = {0};
    ASSERT_EQ(RET_SUCCESS, TestCommon::AllocTestHapToken(info, policy, tokenIdEx));
    AccessTokenID callerTokenID = tokenIdEx.tokenIdExStruct.tokenID;
    ASSERT_NE(INVALID_TOKENID, callerTokenID);
    AccessTokenID firstTokenID;

    // ret = PERMISSION_GRANTED + firstTokenID = 0
    std::string permissionName = "ohos.permission.GET_BUNDLE_INFO";
    firstTokenID = 0;
    EXPECT_EQ(PermissionState::PERMISSION_GRANTED, AccessTokenKit::VerifyAccessToken(
        callerTokenID, firstTokenID, permissionName, false));

    firstTokenID = 1;
    // ret = PERMISSION_GRANTED + firstTokenID != 0
    EXPECT_EQ(PermissionState::PERMISSION_DENIED, AccessTokenKit::VerifyAccessToken(
        callerTokenID, firstTokenID, permissionName, false));
    ASSERT_EQ(RET_SUCCESS, TestCommon::DeleteTestHapToken(callerTokenID));

    callerTokenID = 0;
    // ret = PERMISSION_DENIED
    EXPECT_EQ(PermissionState::PERMISSION_DENIED, AccessTokenKit::VerifyAccessToken(
        callerTokenID, firstTokenID, permissionName, false));
}

/**
 * @tc.name: GetRenderTokenIDTest001
 * @tc.desc: TokenIdKit::GetRenderTokenID function test
 * @tc.type: FUNC
 * @tc.require: issueI7MOA1
 */
HWTEST_F(AccessTokenCoverageTest, GetRenderTokenIDTest001, TestSize.Level1)
{
    uint64_t validTokenID = GetSelfTokenID();
    uint64_t retTokenId = validTokenID;

    retTokenId = TokenIdKit::GetRenderTokenID(validTokenID);
    ASSERT_NE(retTokenId, validTokenID);
    ASSERT_NE(retTokenId, INVALID_TOKENID);
}

/**
 * @tc.name: GetRenderTokenIDTest002
 * @tc.desc: TokenIdKit::GetRenderTokenID function test
 * @tc.type: FUNC
 * @tc.require: issueI7MOA1
 */
HWTEST_F(AccessTokenCoverageTest, GetRenderTokenIDTest002, TestSize.Level1)
{
    uint64_t invalidTokenID = 0;
    uint64_t retTokenId = 1;    /* 1, for testing purposes */

    retTokenId = TokenIdKit::GetRenderTokenID(invalidTokenID);
    ASSERT_EQ(invalidTokenID, retTokenId);
}

/**
 * @tc.name: GetRenderTokenIDTest003
 * @tc.desc: AccessTokenKit::GetRenderTokenID function test
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(AccessTokenCoverageTest, GetRenderTokenIDTest003, TestSize.Level1)
{
    uint64_t invalidTokenID = 0;
    uint64_t retTokenId = 1;    /* 1, for testing purposes */

    retTokenId = AccessTokenKit::GetRenderTokenID(invalidTokenID);
    ASSERT_EQ(invalidTokenID, retTokenId);
}

#ifdef TOKEN_SYNC_ENABLE
namespace {
class TokenSyncCallbackStubTest : public TokenSyncCallbackStub {
public:
    TokenSyncCallbackStubTest() = default;
    virtual ~TokenSyncCallbackStubTest() = default;

    int32_t GetRemoteHapTokenInfo(const std::string& deviceID, AccessTokenID tokenID) override
    {
        return 0;
    };
    int32_t DeleteRemoteHapTokenInfo(AccessTokenID tokenID) override
    {
        return 0;
    };

    int32_t UpdateRemoteHapTokenInfo(const HapTokenInfoForSync& tokenInfo) override
    {
        return 0;
    };
};

static const int32_t FAKE_SYNC_RET = 0xabcdef;
class TokenSyncCallbackImpl : public TokenSyncKitInterface {
public:
    ~TokenSyncCallbackImpl()
    {}

    int32_t GetRemoteHapTokenInfo(const std::string& deviceID, AccessTokenID tokenID) const override
    {
        LOGI(ATM_DOMAIN, ATM_TAG, "GetRemoteHapTokenInfo called.");
        return FAKE_SYNC_RET;
    };

    int32_t DeleteRemoteHapTokenInfo(AccessTokenID tokenID) const override
    {
        LOGI(ATM_DOMAIN, ATM_TAG, "DeleteRemoteHapTokenInfo called.");
        return FAKE_SYNC_RET;
    };

    int32_t UpdateRemoteHapTokenInfo(const HapTokenInfoForSync& tokenInfo) const override
    {
        LOGI(ATM_DOMAIN, ATM_TAG, "UpdateRemoteHapTokenInfo called.");
        return FAKE_SYNC_RET;
    };
};
};

/**
 * @tc.name: TokenSyncCallbackStubTest001
 * @tc.desc: TokenSyncCallbackStub OnRemoteRequest deny test
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(AccessTokenCoverageTest, TokenSyncCallbackStubTest001, TestSize.Level1)
{
    TokenSyncCallbackStubTest callback;

    OHOS::MessageParcel data;
    std::string descriptor = "I don't know";
    data.WriteInterfaceToken(OHOS::Str8ToStr16(descriptor));

    OHOS::MessageParcel reply;
    OHOS::MessageOption option(OHOS::MessageOption::TF_SYNC);
    EXPECT_EQ(ERROR_IPC_REQUEST_FAIL,
        callback.OnRemoteRequest(static_cast<uint32_t>(TokenSyncCallbackInterfaceCode::GET_REMOTE_HAP_TOKEN_INFO),
        data, reply, option)); // descriptor false
}

/**
 * @tc.name: TokenSyncCallbackStubTest002
 * @tc.desc: TokenSyncCallbackStub OnRemoteRequest err code
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(AccessTokenCoverageTest, TokenSyncCallbackStubTest002, TestSize.Level1)
{
    TokenSyncCallbackStubTest callback;
    OHOS::MessageParcel data;
    data.WriteInterfaceToken(ITokenSyncCallback::GetDescriptor());

    OHOS::MessageParcel reply;
    OHOS::MessageOption option(OHOS::MessageOption::TF_SYNC);
    EXPECT_NE(0, callback.OnRemoteRequest(static_cast<uint32_t>(0xff), // code false
        data, reply, option));
}

/**
 * @tc.name: TokenSyncCallbackStubTest003
 * @tc.desc: TokenSyncCallbackStub OnRemoteRequest deny call
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(AccessTokenCoverageTest, TokenSyncCallbackStubTest003, TestSize.Level1)
{
    TokenSyncCallbackStubTest callback;
    OHOS::MessageParcel data;
    data.WriteInterfaceToken(ITokenSyncCallback::GetDescriptor());

    OHOS::MessageParcel reply;
    OHOS::MessageOption option(OHOS::MessageOption::TF_SYNC);
    EXPECT_EQ(0, callback.OnRemoteRequest(
        static_cast<uint32_t>(TokenSyncCallbackInterfaceCode::GET_REMOTE_HAP_TOKEN_INFO),
        data, reply, option));
    EXPECT_EQ(ERR_IDENTITY_CHECK_FAILED, reply.ReadInt32());

    data.WriteInterfaceToken(ITokenSyncCallback::GetDescriptor());
    EXPECT_EQ(0, callback.OnRemoteRequest(
        static_cast<uint32_t>(TokenSyncCallbackInterfaceCode::DELETE_REMOTE_HAP_TOKEN_INFO),
        data, reply, option));
    EXPECT_EQ(ERR_IDENTITY_CHECK_FAILED, reply.ReadInt32());

    data.WriteInterfaceToken(ITokenSyncCallback::GetDescriptor());
    EXPECT_EQ(0, callback.OnRemoteRequest(
        static_cast<uint32_t>(TokenSyncCallbackInterfaceCode::UPDATE_REMOTE_HAP_TOKEN_INFO),
        data, reply, option));
    EXPECT_EQ(ERR_IDENTITY_CHECK_FAILED, reply.ReadInt32());
}

/**
 * @tc.name: TokenSyncCallbackStubTest004
 * @tc.desc: TokenSyncCallbackStub OnRemoteRequest normal call
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(AccessTokenCoverageTest, TokenSyncCallbackStubTest004, TestSize.Level1)
{
    setuid(3020); // ACCESSTOKEN_UID

    TokenSyncCallbackStubTest callback;
    OHOS::MessageParcel data;
    OHOS::MessageParcel reply;
    OHOS::MessageOption option(OHOS::MessageOption::TF_SYNC);

    data.WriteInterfaceToken(ITokenSyncCallback::GetDescriptor());
    data.WriteString("test deviceID"); // test deviceID
    data.WriteUint32(0); // test tokenid
    EXPECT_EQ(0, callback.OnRemoteRequest(
        static_cast<uint32_t>(TokenSyncCallbackInterfaceCode::GET_REMOTE_HAP_TOKEN_INFO),
        data, reply, option));
    EXPECT_EQ(0, reply.ReadInt32());

    data.WriteInterfaceToken(ITokenSyncCallback::GetDescriptor());
    data.WriteUint32(0); // test tokenid
    EXPECT_EQ(0, callback.OnRemoteRequest(
        static_cast<uint32_t>(TokenSyncCallbackInterfaceCode::DELETE_REMOTE_HAP_TOKEN_INFO),
        data, reply, option));
    EXPECT_EQ(0, reply.ReadInt32());

    data.WriteInterfaceToken(ITokenSyncCallback::GetDescriptor());
    HapTokenInfoForSync info;
    HapTokenInfoForSyncParcel tokenInfoParcel;
    tokenInfoParcel.hapTokenInfoForSyncParams = info;
    data.WriteParcelable(&tokenInfoParcel);
    EXPECT_EQ(0, callback.OnRemoteRequest(
        static_cast<uint32_t>(TokenSyncCallbackInterfaceCode::UPDATE_REMOTE_HAP_TOKEN_INFO),
        data, reply, option));
    EXPECT_EQ(0, reply.ReadInt32());
    setuid(0); // root uid
}

/**
 * @tc.name: TokenSyncCallbackTest001
 * @tc.desc: TokenSyncCallback inner call
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(AccessTokenCoverageTest, TokenSyncCallbackTest001, TestSize.Level1)
{
    TokenSyncCallback callback(nullptr);
    EXPECT_EQ(nullptr, callback.tokenSyncCallback_); // test input

    std::shared_ptr<TokenSyncKitInterface> ptr = std::make_shared<TokenSyncCallbackImpl>();
    std::shared_ptr<TokenSyncCallback> callbackImpl = std::make_shared<TokenSyncCallback>(ptr);
    EXPECT_NE(nullptr, callbackImpl->tokenSyncCallback_);
    EXPECT_EQ(FAKE_SYNC_RET, callbackImpl->GetRemoteHapTokenInfo("test", 0)); // test input
    EXPECT_EQ(FAKE_SYNC_RET, callbackImpl->DeleteRemoteHapTokenInfo(0)); // test input
    HapTokenInfoForSync info;
    EXPECT_EQ(FAKE_SYNC_RET, callbackImpl->UpdateRemoteHapTokenInfo(info)); // test input
}
#endif // TOKEN_SYNC_ENABLE

/**
 * @tc.name: GetPermissionManagerInfo001
 * @tc.desc:
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(AccessTokenCoverageTest, GetPermissionManagerInfo001, TestSize.Level1)
{
    PermissionGrantInfo info;
    AccessTokenKit::GetPermissionManagerInfo(info);
    ASSERT_EQ(false, info.grantBundleName.empty());
}

} // namespace AccessToken
} // namespace Security
} // namespace OHOS
