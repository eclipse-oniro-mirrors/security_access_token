/*
 * Copyright (c) 2024-2025 Huawei Device Co., Ltd.
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

#include "el5_filekey_manager_service_mock_unittest.h"

#include "accesstoken_kit.h"
#include "el5_filekey_callback_interface_stub.h"
#include "el5_filekey_manager_error.h"
#include "el5_test_common.h"
#include "mock_ipc.h"
#include "token_setproc.h"

using namespace testing::ext;
using namespace OHOS::Security::AccessToken;
namespace {
constexpr uint32_t SCREEN_ON_DELAY_TIME = 30;
} // namespace

void El5FilekeyManagerServiceMockTest::SetUpTestCase()
{
}

void El5FilekeyManagerServiceMockTest::TearDownTestCase()
{
    sleep(SCREEN_ON_DELAY_TIME);
}

void El5FilekeyManagerServiceMockTest::SetUp()
{
    el5FilekeyManagerService_ = DelayedSingleton<El5FilekeyManagerService>::GetInstance();
    el5FilekeyManagerService_->Init();
    el5FilekeyManagerService_->service_ = nullptr;
}

void El5FilekeyManagerServiceMockTest::TearDown()
{
}

class TestEl5FilekeyCallback : public El5FilekeyCallbackInterfaceStub {
public:
    OHOS::ErrCode OnRegenerateAppKey(std::vector<AppKeyInfo> &infos)
    {
        GTEST_LOG_(INFO) << "OnRegenerateAppKey.";
        return OHOS::ERR_OK;
    }
};

class TestEl5FilekeyServiceExt : public El5FilekeyServiceExtInterface {
public:
    int32_t AcquireAccess(DataLockType type, bool isApp)
    {
        return EFM_SUCCESS;
    }

    int32_t ReleaseAccess(DataLockType type, bool isApp)
    {
        return EFM_SUCCESS;
    }

    int32_t GenerateAppKey(uint32_t uid, const std::string& bundleName, std::string& keyId)
    {
        return EFM_SUCCESS;
    }

    int32_t DeleteAppKey(const std::string& bundleName, int32_t userId)
    {
        return EFM_SUCCESS;
    }

    int32_t GetUserAppKey(int32_t userId, bool getAllFlag, std::vector<UserAppKeyInfo> &keyInfos)
    {
        int32_t key = 111;
        std::string info = "test";
        keyInfos.emplace_back(UserAppKeyInfo(key, info));
        return EFM_SUCCESS;
    }

    int32_t ChangeUserAppkeysLoadInfo(int32_t userId, const std::vector<AppKeyLoadInfo> &loadInfos)
    {
        return EFM_SUCCESS;
    }

    int32_t SetFilePathPolicy(int32_t userId)
    {
        return EFM_SUCCESS;
    }

    int32_t RegisterCallback(const OHOS::sptr<El5FilekeyCallbackInterface> &callback)
    {
        return EFM_SUCCESS;
    }

    int32_t GenerateGroupIDKey(uint32_t uid, const std::string &groupID, std::string &keyId)
    {
        return EFM_SUCCESS;
    }

    int32_t DeleteGroupIDKey(uint32_t uid, const std::string &groupID)
    {
        return EFM_SUCCESS;
    }

    int32_t QueryAppKeyState(DataLockType type, bool isApp)
    {
        return EFM_SUCCESS;
    }

    int32_t HandleUserCommonEvent(const std::string &eventName, int32_t userId)
    {
        return EFM_SUCCESS;
    }

    int32_t SetPolicyScreenLocked()
    {
        return EFM_SUCCESS;
    }

    int32_t DumpData(int fd, const std::vector<std::u16string>& args)
    {
        return EFM_SUCCESS;
    }

    void OnAddSystemAbility(int32_t systemAbilityId, const std::string& deviceId)
    {
        GTEST_LOG_(INFO) << "OnAddSystemAbility.";
    }

    void UnInit()
    {
        GTEST_LOG_(INFO) << "UnInit.";
    }
};

/**
 * @tc.name: AcquireAccess001
 * @tc.desc: Acquire default type data access.
 * @tc.type: FUNC
 * @tc.require: issueIAD2MD
 */
HWTEST_F(El5FilekeyManagerServiceMockTest, AcquireAccess001, TestSize.Level1)
{
    el5FilekeyManagerService_->service_ = nullptr;

    MockIpc::SetCallingUid(20020025);
    uint64_t tokenId = GetTokenIdFromBundleName("com.ohos.medialibrary.medialibrarydata");
    // if medialibrarydata not exist, try contactsdataability
    if (tokenId == INVALID_TOKENID) {
        tokenId = GetTokenIdFromBundleName("com.ohos.contactsdataability");
    }
    ASSERT_NE(tokenId, INVALID_TOKENID);
    MockIpc::SetCallingTokenID(static_cast<uint32_t>(tokenId));

    ASSERT_EQ(el5FilekeyManagerService_->AcquireAccess(DataLockType::DEFAULT_DATA), EFM_SUCCESS);
}

/**
 * @tc.name: AcquireAccess002
 * @tc.desc: Acquire default type data access.
 * @tc.type: FUNC
 * @tc.require: issueIAD2MD
 */
HWTEST_F(El5FilekeyManagerServiceMockTest, AcquireAccess002, TestSize.Level1)
{
    el5FilekeyManagerService_->service_ = new TestEl5FilekeyServiceExt();

    MockIpc::SetCallingUid(20020025);
    uint64_t tokenId = GetTokenIdFromBundleName("com.ohos.medialibrary.medialibrarydata");
    // if medialibrarydata not exist, try contactsdataability
    if (tokenId == INVALID_TOKENID) {
        tokenId = GetTokenIdFromBundleName("com.ohos.contactsdataability");
    }
    ASSERT_NE(tokenId, INVALID_TOKENID);
    MockIpc::SetCallingTokenID(static_cast<uint32_t>(tokenId));

    ASSERT_EQ(el5FilekeyManagerService_->AcquireAccess(DataLockType::DEFAULT_DATA), EFM_SUCCESS);
}

/**
 * @tc.name: ReleaseAccess001
 * @tc.desc: Release default type data access.
 * @tc.type: FUNC
 * @tc.require: issueIAD2MD
 */
HWTEST_F(El5FilekeyManagerServiceMockTest, ReleaseAccess001, TestSize.Level1)
{
    el5FilekeyManagerService_->service_ = nullptr;

    MockIpc::SetCallingUid(20020025);
    uint64_t tokenId = GetTokenIdFromBundleName("com.ohos.medialibrary.medialibrarydata");
    // if medialibrarydata not exist, try contactsdataability
    if (tokenId == INVALID_TOKENID) {
        tokenId = GetTokenIdFromBundleName("com.ohos.contactsdataability");
    }
    ASSERT_NE(tokenId, INVALID_TOKENID);
    MockIpc::SetCallingTokenID(static_cast<uint32_t>(tokenId));

    ASSERT_EQ(el5FilekeyManagerService_->ReleaseAccess(DataLockType::DEFAULT_DATA), EFM_SUCCESS);
}

/**
 * @tc.name: ReleaseAccess002
 * @tc.desc: Release default type data access.
 * @tc.type: FUNC
 * @tc.require: issueIAD2MD
 */
HWTEST_F(El5FilekeyManagerServiceMockTest, ReleaseAccess002, TestSize.Level1)
{
    el5FilekeyManagerService_->service_ = new TestEl5FilekeyServiceExt();

    MockIpc::SetCallingUid(20020025);
    uint64_t tokenId = GetTokenIdFromBundleName("com.ohos.medialibrary.medialibrarydata");
    // if medialibrarydata not exist, try contactsdataability
    if (tokenId == INVALID_TOKENID) {
        tokenId = GetTokenIdFromBundleName("com.ohos.contactsdataability");
    }
    ASSERT_NE(tokenId, INVALID_TOKENID);
    MockIpc::SetCallingTokenID(static_cast<uint32_t>(tokenId));

    ASSERT_EQ(el5FilekeyManagerService_->ReleaseAccess(DataLockType::DEFAULT_DATA), EFM_SUCCESS);
}

/**
 * @tc.name: GenerateAppKey001
 * @tc.desc: Generate app key by uid and bundle name.
 * @tc.type: FUNC
 * @tc.require: issueIAD2MD
 */
HWTEST_F(El5FilekeyManagerServiceMockTest, GenerateAppKey001, TestSize.Level1)
{
    el5FilekeyManagerService_->service_ = nullptr;

    int32_t uid = 12345;
    std::string bundleName = "com.ohos.el5_test";
    std::string keyId;

    MockIpc::SetCallingUid(3060);

    ASSERT_EQ(el5FilekeyManagerService_->GenerateAppKey(uid, bundleName, keyId), EFM_SUCCESS);
}

/**
 * @tc.name: GenerateAppKey002
 * @tc.desc: Generate app key by uid and bundle name.
 * @tc.type: FUNC
 * @tc.require: issueIAD2MD
 */
HWTEST_F(El5FilekeyManagerServiceMockTest, GenerateAppKey002, TestSize.Level1)
{
    el5FilekeyManagerService_->service_ = new TestEl5FilekeyServiceExt();

    int32_t uid = 12345;
    std::string bundleName = "com.ohos.el5_test";
    std::string keyId;

    MockIpc::SetCallingUid(3060);

    ASSERT_EQ(el5FilekeyManagerService_->GenerateAppKey(uid, bundleName, keyId), EFM_SUCCESS);
}

/**
 * @tc.name: DeleteAppKey001
 * @tc.desc: Delete app key by bundle name and user id.
 * @tc.type: FUNC
 * @tc.require: issueIAD2MD
 */
HWTEST_F(El5FilekeyManagerServiceMockTest, DeleteAppKey001, TestSize.Level1)
{
    el5FilekeyManagerService_->service_ = nullptr;

    std::string bundleName = "";
    int32_t userId = 100;

    MockIpc::SetCallingUid(3060);

    ASSERT_EQ(el5FilekeyManagerService_->DeleteAppKey(bundleName, userId), EFM_SUCCESS);
}

/**
 * @tc.name: DeleteAppKey002
 * @tc.desc: Delete app key by bundle name and user id.
 * @tc.type: FUNC
 * @tc.require: issueIAD2MD
 */
HWTEST_F(El5FilekeyManagerServiceMockTest, DeleteAppKey002, TestSize.Level1)
{
    el5FilekeyManagerService_->service_ = new TestEl5FilekeyServiceExt();

    std::string bundleName = "";
    int32_t userId = 100;

    MockIpc::SetCallingUid(3060);

    ASSERT_EQ(el5FilekeyManagerService_->DeleteAppKey(bundleName, userId), EFM_SUCCESS);
}

/**
 * @tc.name: GetUserAppKey001
 * @tc.desc: Find key infos of the specified user id.
 * @tc.type: FUNC
 * @tc.require: issueIAD2MD
 */
HWTEST_F(El5FilekeyManagerServiceMockTest, GetUserAppKey001, TestSize.Level1)
{
    el5FilekeyManagerService_->service_ = nullptr;

    int32_t userId = 100;
    std::vector<UserAppKeyInfo> keyInfos;

    AccessTokenID tokenId = AccessTokenKit::GetNativeTokenId("storage_daemon");
    MockIpc::SetCallingTokenID(static_cast<uint32_t>(tokenId));

    ASSERT_EQ(el5FilekeyManagerService_->GetUserAppKey(userId, false, keyInfos), EFM_SUCCESS);
}

/**
 * @tc.name: GetUserAppKey002
 * @tc.desc: Find key infos of the specified user id.
 * @tc.type: FUNC
 * @tc.require: issueIAD2MD
 */
HWTEST_F(El5FilekeyManagerServiceMockTest, GetUserAppKey002, TestSize.Level1)
{
    el5FilekeyManagerService_->service_ = new TestEl5FilekeyServiceExt();

    int32_t userId = 100;
    std::vector<UserAppKeyInfo> keyInfos;

    AccessTokenID tokenId = AccessTokenKit::GetNativeTokenId("storage_daemon");
    MockIpc::SetCallingTokenID(static_cast<uint32_t>(tokenId));

    ASSERT_EQ(el5FilekeyManagerService_->GetUserAppKey(userId, false, keyInfos), EFM_SUCCESS);
}

/**
 * @tc.name: GetUserAppKey003
 * @tc.desc: Find key infos of the specified user id.
 * @tc.type: FUNC
 * @tc.require: issueIAD2MD
 */
HWTEST_F(El5FilekeyManagerServiceMockTest, GetUserAppKey003, TestSize.Level1)
{
    OHOS::MessageParcel data;
    OHOS::MessageParcel reply;
    OHOS::MessageOption option(OHOS::MessageOption::TF_SYNC);

    ASSERT_EQ(true, data.WriteInterfaceToken(El5FilekeyManagerInterface::GetDescriptor()));

    data.WriteInt32(100);
    data.WriteBool(false);

    ASSERT_EQ(el5FilekeyManagerService_->OnRemoteRequest(
        static_cast<uint32_t>(El5FilekeyManagerInterfaceIpcCode::COMMAND_GET_USER_APP_KEY), data, reply, option),
        OHOS::NO_ERROR);
}

/**
 * @tc.name: ChangeUserAppkeysLoadInfo001
 * @tc.desc: Change key infos of the specified user id.
 * @tc.type: FUNC
 * @tc.require: issueIAD2MD
 */
HWTEST_F(El5FilekeyManagerServiceMockTest, ChangeUserAppkeysLoadInfo001, TestSize.Level1)
{
    el5FilekeyManagerService_->service_ = nullptr;

    int32_t userId = 100;
    std::vector<AppKeyLoadInfo> loadInfos;
    std::string emptyStr("");
    loadInfos.emplace_back(AppKeyLoadInfo(emptyStr, true));

    AccessTokenID tokenId = AccessTokenKit::GetNativeTokenId("storage_daemon");
    MockIpc::SetCallingTokenID(static_cast<uint32_t>(tokenId));

    ASSERT_EQ(el5FilekeyManagerService_->ChangeUserAppkeysLoadInfo(userId, loadInfos), EFM_SUCCESS);
}

/**
 * @tc.name: ChangeUserAppkeysLoadInfo002
 * @tc.desc: Change key infos of the specified user id.
 * @tc.type: FUNC
 * @tc.require: issueIAD2MD
 */
HWTEST_F(El5FilekeyManagerServiceMockTest, ChangeUserAppkeysLoadInfo002, TestSize.Level1)
{
    el5FilekeyManagerService_->service_ = new TestEl5FilekeyServiceExt();

    int32_t userId = 100;
    std::vector<AppKeyLoadInfo> loadInfos;
    std::string emptyStr("");
    loadInfos.emplace_back(AppKeyLoadInfo(emptyStr, true));

    AccessTokenID tokenId = AccessTokenKit::GetNativeTokenId("storage_daemon");
    MockIpc::SetCallingTokenID(static_cast<uint32_t>(tokenId));

    ASSERT_EQ(el5FilekeyManagerService_->ChangeUserAppkeysLoadInfo(userId, loadInfos), EFM_SUCCESS);
}

/**
 * @tc.name: SetFilePathPolicy001
 * @tc.desc: Set path policy.
 * @tc.type: FUNC
 * @tc.require: issueIAD2MD
 */
HWTEST_F(El5FilekeyManagerServiceMockTest, SetFilePathPolicy001, TestSize.Level1)
{
    el5FilekeyManagerService_->service_ = nullptr;

    MockIpc::SetCallingUid(20020025);
    AccessTokenID tokenId = AccessTokenKit::GetHapTokenID(100, "com.ohos.medialibrary.medialibrarydata", 0);
    MockIpc::SetCallingTokenID(static_cast<uint32_t>(tokenId));

    ASSERT_EQ(el5FilekeyManagerService_->SetFilePathPolicy(), EFM_SUCCESS);
}

/**
 * @tc.name: SetFilePathPolicy002
 * @tc.desc: Set path policy.
 * @tc.type: FUNC
 * @tc.require: issueIAD2MD
 */
HWTEST_F(El5FilekeyManagerServiceMockTest, SetFilePathPolicy002, TestSize.Level1)
{
    el5FilekeyManagerService_->service_ = new TestEl5FilekeyServiceExt();

    MockIpc::SetCallingUid(20020025);
    AccessTokenID tokenId = AccessTokenKit::GetHapTokenID(100, "com.ohos.medialibrary.medialibrarydata", 0);
    MockIpc::SetCallingTokenID(static_cast<uint32_t>(tokenId));

    ASSERT_EQ(el5FilekeyManagerService_->SetFilePathPolicy(), EFM_SUCCESS);
}

/**
 * @tc.name: RegisterCallback001
 * @tc.desc: Register app key generation callback.
 * @tc.type: FUNC
 * @tc.require: issueIAD2MD
 */
HWTEST_F(El5FilekeyManagerServiceMockTest, RegisterCallback001, TestSize.Level1)
{
    el5FilekeyManagerService_->service_ = nullptr;

    AccessTokenID tokenId = AccessTokenKit::GetNativeTokenId("foundation");
    MockIpc::SetCallingTokenID(static_cast<uint32_t>(tokenId));

    ASSERT_EQ(el5FilekeyManagerService_->RegisterCallback((new TestEl5FilekeyCallback())), EFM_SUCCESS);
}

/**
 * @tc.name: RegisterCallback002
 * @tc.desc: Register app key generation callback.
 * @tc.type: FUNC
 * @tc.require: issueIAD2MD
 */
HWTEST_F(El5FilekeyManagerServiceMockTest, RegisterCallback002, TestSize.Level1)
{
    el5FilekeyManagerService_->service_ = new TestEl5FilekeyServiceExt();

    AccessTokenID tokenId = AccessTokenKit::GetNativeTokenId("foundation");
    MockIpc::SetCallingTokenID(static_cast<uint32_t>(tokenId));

    ASSERT_EQ(el5FilekeyManagerService_->RegisterCallback((new TestEl5FilekeyCallback())), EFM_SUCCESS);
}

/**
 * @tc.name: GenerateGroupIDKey001
 * @tc.desc: Generate data group key by user id and group id.
 * @tc.type: FUNC
 * @tc.require: issueIAD2MD
 */
HWTEST_F(El5FilekeyManagerServiceMockTest, GenerateGroupIDKey001, TestSize.Level1)
{
    el5FilekeyManagerService_->service_ = nullptr;

    uint32_t uid = 100;
    std::string groupID = "abcdefghijklmn";
    std::string keyId;

    MockIpc::SetCallingUid(3060);

    ASSERT_EQ(el5FilekeyManagerService_->GenerateGroupIDKey(uid, groupID, keyId), EFM_SUCCESS);
}

/**
 * @tc.name: GenerateGroupIDKey002
 * @tc.desc: Generate data group key by user id and group id.
 * @tc.type: FUNC
 * @tc.require: issueIAD2MD
 */
HWTEST_F(El5FilekeyManagerServiceMockTest, GenerateGroupIDKey002, TestSize.Level1)
{
    el5FilekeyManagerService_->service_ = new TestEl5FilekeyServiceExt();

    uint32_t uid = 100;
    std::string groupID = "abcdefghijklmn";
    std::string keyId;

    MockIpc::SetCallingUid(3060);

    ASSERT_EQ(el5FilekeyManagerService_->GenerateGroupIDKey(uid, groupID, keyId), EFM_SUCCESS);
}

/**
 * @tc.name: DeleteGroupIDKey001
 * @tc.desc: Delete data group key by user id and group id.
 * @tc.type: FUNC
 * @tc.require: issueIAD2MD
 */
HWTEST_F(El5FilekeyManagerServiceMockTest, DeleteGroupIDKey001, TestSize.Level1)
{
    el5FilekeyManagerService_->service_ = nullptr;

    uint32_t uid = 100;
    std::string groupID = "";

    MockIpc::SetCallingUid(3060);

    ASSERT_EQ(el5FilekeyManagerService_->DeleteGroupIDKey(uid, groupID), EFM_SUCCESS);
}

/**
 * @tc.name: DeleteGroupIDKey002
 * @tc.desc: Delete data group key by user id and group id.
 * @tc.type: FUNC
 * @tc.require: issueIAD2MD
 */
HWTEST_F(El5FilekeyManagerServiceMockTest, DeleteGroupIDKey002, TestSize.Level1)
{
    el5FilekeyManagerService_->service_ = new TestEl5FilekeyServiceExt();

    uint32_t uid = 100;
    std::string groupID = "";

    MockIpc::SetCallingUid(3060);

    ASSERT_EQ(el5FilekeyManagerService_->DeleteGroupIDKey(uid, groupID), EFM_SUCCESS);
}

/**
 * @tc.name: QueryAppKeyState001
 * @tc.desc: Query default type app key.
 * @tc.type: FUNC
 * @tc.require: issueIAD2MD
 */
HWTEST_F(El5FilekeyManagerServiceMockTest, QueryAppKeyState001, TestSize.Level1)
{
    el5FilekeyManagerService_->service_ = nullptr;

    MockIpc::SetCallingUid(20020025);
    uint64_t tokenId = GetTokenIdFromBundleName("com.ohos.medialibrary.medialibrarydata");
    // if medialibrarydata not exist, try contactsdataability
    if (tokenId == INVALID_TOKENID) {
        tokenId = GetTokenIdFromBundleName("com.ohos.contactsdataability");
    }
    ASSERT_NE(tokenId, INVALID_TOKENID);
    MockIpc::SetCallingTokenID(static_cast<uint32_t>(tokenId));

    ASSERT_EQ(el5FilekeyManagerService_->QueryAppKeyState(DataLockType::DEFAULT_DATA), EFM_SUCCESS);
}

/**
 * @tc.name: QueryAppKeyState002
 * @tc.desc: Query default type app key.
 * @tc.type: FUNC
 * @tc.require: issueIAD2MD
 */
HWTEST_F(El5FilekeyManagerServiceMockTest, QueryAppKeyState002, TestSize.Level1)
{
    el5FilekeyManagerService_->service_ = new TestEl5FilekeyServiceExt();

    MockIpc::SetCallingUid(20020025);
    uint64_t tokenId = GetTokenIdFromBundleName("com.ohos.medialibrary.medialibrarydata");
    // if medialibrarydata not exist, try contactsdataability
    if (tokenId == INVALID_TOKENID) {
        tokenId = GetTokenIdFromBundleName("com.ohos.contactsdataability");
    }
    ASSERT_NE(tokenId, INVALID_TOKENID);
    MockIpc::SetCallingTokenID(static_cast<uint32_t>(tokenId));

    ASSERT_EQ(el5FilekeyManagerService_->QueryAppKeyState(DataLockType::DEFAULT_DATA), EFM_SUCCESS);
}

/**
 * @tc.name: SetPolicyScreenLocked001
 * @tc.desc: SetPolicyScreenLocked
 * @tc.type: FUNC
 * @tc.require: issueIAD2MD
 */
HWTEST_F(El5FilekeyManagerServiceMockTest, SetPolicyScreenLocked001, TestSize.Level1)
{
    el5FilekeyManagerService_->service_ = nullptr;

    ASSERT_EQ(el5FilekeyManagerService_->SetPolicyScreenLocked(), EFM_SUCCESS);
}

/**
 * @tc.name: SetPolicyScreenLocked002
 * @tc.desc: SetPolicyScreenLocked
 * @tc.type: FUNC
 * @tc.require: issueIAD2MD
 */
HWTEST_F(El5FilekeyManagerServiceMockTest, SetPolicyScreenLocked002, TestSize.Level1)
{
    el5FilekeyManagerService_->service_ = new TestEl5FilekeyServiceExt();

    ASSERT_EQ(el5FilekeyManagerService_->SetPolicyScreenLocked(), EFM_SUCCESS);
}

/**
 * @tc.name: Dump001
 * @tc.desc: Dump fd > 0
 * @tc.type: FUNC
 * @tc.require: issueIAD2MD
 */
HWTEST_F(El5FilekeyManagerServiceMockTest, Dump001, TestSize.Level1)
{
    el5FilekeyManagerService_->service_ = nullptr;

    int fd = 1;
    std::vector<std::u16string> args = {};
    ASSERT_EQ(el5FilekeyManagerService_->Dump(fd, args), EFM_SUCCESS);
}

/**
 * @tc.name: Dump002
 * @tc.desc: Dump fd > 0
 * @tc.type: FUNC
 * @tc.require: issueIAD2MD
 */
HWTEST_F(El5FilekeyManagerServiceMockTest, Dump002, TestSize.Level1)
{
    el5FilekeyManagerService_->service_ = new TestEl5FilekeyServiceExt();

    int fd = 1;
    std::vector<std::u16string> args = {};
    ASSERT_EQ(el5FilekeyManagerService_->Dump(fd, args), EFM_SUCCESS);
}

/**
 * @tc.name: HandleUserCommonEvent001
 * @tc.desc: HandleUserCommonEvent func test, service_ == null.
 * @tc.type: FUNC
 * @tc.require: issueIAD2MD
 */
HWTEST_F(El5FilekeyManagerServiceMockTest, HandleUserCommonEvent001, TestSize.Level1)
{
    el5FilekeyManagerService_->service_ = nullptr;
    std::string eventName = "abc";
    int userId = 1;
    ASSERT_EQ(el5FilekeyManagerService_->HandleUserCommonEvent(eventName, userId), EFM_SUCCESS);
}

/**
 * @tc.name: HandleUserCommonEvent002
 * @tc.desc: HandleUserCommonEvent func test, service_ != null.
 * @tc.type: FUNC
 * @tc.require: issueIAD2MD
 */
HWTEST_F(El5FilekeyManagerServiceMockTest, HandleUserCommonEvent002, TestSize.Level1)
{
    el5FilekeyManagerService_->service_ = new TestEl5FilekeyServiceExt();
    std::string eventName = "abc";
    int userId = 1;
    ASSERT_EQ(el5FilekeyManagerService_->HandleUserCommonEvent(eventName, userId), EFM_SUCCESS);
}

/**
 * @tc.name: OnRemoteRequest001
 * @tc.desc: El5FilekeyCallbackStub function test OnRemoteRequest001.
 * @tc.type: FUNC
 * @tc.require: Issue Number
 */
HWTEST_F(El5FilekeyManagerServiceMockTest, OnRemoteRequest001, TestSize.Level1)
{
    TestEl5FilekeyCallback testEl5FilekeyCallback;
    OHOS::MessageParcel data;
    OHOS::MessageParcel reply;
    OHOS::MessageOption option;
    uint32_t code = static_cast<uint32_t>(El5FilekeyCallbackInterfaceIpcCode::COMMAND_ON_REGENERATE_APP_KEY);

    ASSERT_EQ(data.WriteInterfaceToken(El5FilekeyCallbackInterface::GetDescriptor()), true);
    data.WriteUint32(1); // infosSize
    data.WriteInt32(1);  // AppKeyInfo size
    data.WriteUint32(static_cast<uint32_t>(AppKeyType::APP));
    data.WriteUint32(1000);
    std::string bundleName = "ohos.permission.test";
    data.WriteString(bundleName);
    data.WriteInt32(100);
    data.WriteString("testGroupId");
    ASSERT_EQ(testEl5FilekeyCallback.OnRemoteRequest(code, data, reply, option), OHOS::NO_ERROR);
}

/**
 * @tc.name: Marshalling001
 * @tc.desc: AppKeyInfo function test Marshalling.
 * @tc.type: FUNC
 * @tc.require: Issue Number
 */
HWTEST_F(El5FilekeyManagerServiceMockTest, Marshalling001, TestSize.Level1)
{
    AppKeyInfo appKeyInfo;
    appKeyInfo.uid = 1000;
    appKeyInfo.bundleName = "test";
    appKeyInfo.userId = 200;
    appKeyInfo.groupID = "testGroupId";
    OHOS::Parcel parcel;
    ASSERT_EQ(appKeyInfo.Marshalling(parcel), true);
}

/**
 * @tc.name: Unmarshalling001
 * @tc.desc: AppKeyInfo function test Marshalling.
 * @tc.type: FUNC
 * @tc.require: Issue Number
 */
HWTEST_F(El5FilekeyManagerServiceMockTest, Unmarshalling001, TestSize.Level1)
{
    AppKeyInfo appKeyInfo;
    OHOS::Parcel parcel;
    parcel.WriteUint32(static_cast<uint32_t>(AppKeyType::GROUPID));
    parcel.WriteUint32(1000);
    parcel.WriteString("ohos.permission.test");
    parcel.WriteInt32(100);
    parcel.WriteString("testGroupId");
    auto info = appKeyInfo.Unmarshalling(parcel);
    ASSERT_EQ(info != nullptr, true);
    ASSERT_EQ(info->bundleName, "ohos.permission.test");
}
