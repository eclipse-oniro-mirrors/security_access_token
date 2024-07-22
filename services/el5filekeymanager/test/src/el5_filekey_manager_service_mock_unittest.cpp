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

#include "el5_filekey_manager_service_mock_unittest.h"

#include "accesstoken_kit.h"
#include "el5_filekey_callback_stub.h"
#include "mock_ipc.h"
#include "token_setproc.h"

using namespace testing::ext;
using namespace OHOS::Security::AccessToken;

void El5FilekeyManagerServiceMockTest::SetUpTestCase()
{
}

void El5FilekeyManagerServiceMockTest::TearDownTestCase()
{
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

class TestEl5FilekeyCallback : public El5FilekeyCallbackStub {
public:
    void OnRegenerateAppKey(std::vector<AppKeyInfo> &infos)
    {
        GTEST_LOG_(INFO) << "OnRegenerateAppKey.";
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

    int32_t DeleteAppKey(const std::string& keyId)
    {
        return EFM_SUCCESS;
    }

    int32_t GetUserAppKey(int32_t userId, bool getAllFlag, std::vector<std::pair<int32_t, std::string>> &keyInfos)
    {
        int32_t key = 111;
        std::string info = "test";
        keyInfos.emplace_back(std::make_pair(key, info));
        return EFM_SUCCESS;
    }

    int32_t ChangeUserAppkeysLoadInfo(int32_t userId, std::vector<std::pair<std::string, bool>> &loadInfos)
    {
        return EFM_SUCCESS;
    }

    int32_t SetFilePathPolicy(int32_t userId)
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

    int32_t RegisterCallback(const OHOS::sptr<El5FilekeyCallbackInterface> &callback)
    {
        return EFM_SUCCESS;
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
    AccessTokenID tokenId = AccessTokenKit::GetHapTokenID(100, "com.ohos.medialibrary.medialibrarydata", 0);
    MockIpc::SetCallingTokenID(static_cast<uint32_t>(tokenId));

    ASSERT_EQ(el5FilekeyManagerService_->AcquireAccess(DEFAULT_DATA), EFM_SUCCESS);
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
    AccessTokenID tokenId = AccessTokenKit::GetHapTokenID(100, "com.ohos.medialibrary.medialibrarydata", 0);
    MockIpc::SetCallingTokenID(static_cast<uint32_t>(tokenId));

    ASSERT_EQ(el5FilekeyManagerService_->AcquireAccess(DEFAULT_DATA), EFM_SUCCESS);
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
    AccessTokenID tokenId = AccessTokenKit::GetHapTokenID(100, "com.ohos.medialibrary.medialibrarydata", 0);
    MockIpc::SetCallingTokenID(static_cast<uint32_t>(tokenId));

    ASSERT_EQ(el5FilekeyManagerService_->ReleaseAccess(DEFAULT_DATA), EFM_SUCCESS);
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
    AccessTokenID tokenId = AccessTokenKit::GetHapTokenID(100, "com.ohos.medialibrary.medialibrarydata", 0);
    MockIpc::SetCallingTokenID(static_cast<uint32_t>(tokenId));

    ASSERT_EQ(el5FilekeyManagerService_->ReleaseAccess(DEFAULT_DATA), EFM_SUCCESS);
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
 * @tc.desc: Delete app key by keyId.
 * @tc.type: FUNC
 * @tc.require: issueIAD2MD
 */
HWTEST_F(El5FilekeyManagerServiceMockTest, DeleteAppKey001, TestSize.Level1)
{
    el5FilekeyManagerService_->service_ = nullptr;

    std::string keyId = "";

    MockIpc::SetCallingUid(3060);

    ASSERT_EQ(el5FilekeyManagerService_->DeleteAppKey(keyId), EFM_SUCCESS);
}

/**
 * @tc.name: DeleteAppKey002
 * @tc.desc: Delete app key by keyId.
 * @tc.type: FUNC
 * @tc.require: issueIAD2MD
 */
HWTEST_F(El5FilekeyManagerServiceMockTest, DeleteAppKey002, TestSize.Level1)
{
    el5FilekeyManagerService_->service_ = new TestEl5FilekeyServiceExt();

    std::string keyId = "";

    MockIpc::SetCallingUid(3060);

    ASSERT_EQ(el5FilekeyManagerService_->DeleteAppKey(keyId), EFM_SUCCESS);
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
    std::vector<std::pair<int32_t, std::string>> keyInfos;

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
    std::vector<std::pair<int32_t, std::string>> keyInfos;

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
        static_cast<uint32_t>(EFMInterfaceCode::GET_USER_APP_KEY), data, reply, option), OHOS::NO_ERROR);
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
    std::vector<std::pair<std::string, bool>> loadInfos;
    loadInfos.emplace_back(std::make_pair("", true));

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
    std::vector<std::pair<std::string, bool>> loadInfos;
    loadInfos.emplace_back(std::make_pair("", true));

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
