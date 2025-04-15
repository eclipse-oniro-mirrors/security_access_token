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

#include "el5_filekey_manager_service_unittest.h"

#include "accesstoken_kit.h"
#include "el5_filekey_callback_interface_stub.h"
#include "el5_filekey_manager_error.h"
#include "token_setproc.h"

using namespace testing::ext;
using namespace OHOS::Security::AccessToken;
namespace {
constexpr uint32_t SCREEN_ON_DELAY_TIME = 30;
constexpr int32_t COMMON_EVENT_SERVICE_ID = 3299;
constexpr int32_t TIME_SERVICE_ID = 3702;
constexpr int32_t SCREENLOCK_SERVICE_ID = 3704;
} // namespace

void El5FilekeyManagerServiceTest::SetUpTestCase()
{
}

void El5FilekeyManagerServiceTest::TearDownTestCase()
{
    sleep(SCREEN_ON_DELAY_TIME);
}

void El5FilekeyManagerServiceTest::SetUp()
{
    el5FilekeyManagerService_ = DelayedSingleton<El5FilekeyManagerService>::GetInstance();
    el5FilekeyManagerService_->Init();
    el5FilekeyManagerService_->OnAddSystemAbility(COMMON_EVENT_SERVICE_ID, "");
    el5FilekeyManagerService_->OnAddSystemAbility(TIME_SERVICE_ID, "");
    el5FilekeyManagerService_->OnAddSystemAbility(SCREENLOCK_SERVICE_ID, "");
}

void El5FilekeyManagerServiceTest::TearDown()
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

/**
 * @tc.name: AcquireAccess001
 * @tc.desc: Acquire media type data access without permission.
 * @tc.type: FUNC
 * @tc.require: issueI9JGMV
 */
HWTEST_F(El5FilekeyManagerServiceTest, AcquireAccess001, TestSize.Level1)
{
    ASSERT_EQ(el5FilekeyManagerService_->AcquireAccess(DataLockType::MEDIA_DATA), EFM_ERR_NO_PERMISSION);
}

/**
 * @tc.name: AcquireAccess002
 * @tc.desc: Acquire all type data access without permission.
 * @tc.type: FUNC
 * @tc.require: issueI9JGMV
 */
HWTEST_F(El5FilekeyManagerServiceTest, AcquireAccess002, TestSize.Level1)
{
    ASSERT_EQ(el5FilekeyManagerService_->AcquireAccess(DataLockType::ALL_DATA), EFM_ERR_NO_PERMISSION);
}

/**
 * @tc.name: AcquireAccess003
 * @tc.desc: Acquire invalid type data access.
 * @tc.type: FUNC
 * @tc.require: issueIAD2MD
 */
HWTEST_F(El5FilekeyManagerServiceTest, AcquireAccess003, TestSize.Level1)
{
    uint32_t type = 3;
    ASSERT_EQ(el5FilekeyManagerService_->AcquireAccess(static_cast<DataLockType>(type)), EFM_ERR_NO_PERMISSION);
}

/**
 * @tc.name: ReleaseAccess001
 * @tc.desc: Release media type data access without permission.
 * @tc.type: FUNC
 * @tc.require: issueI9JGMV
 */
HWTEST_F(El5FilekeyManagerServiceTest, ReleaseAccess001, TestSize.Level1)
{
    ASSERT_EQ(el5FilekeyManagerService_->ReleaseAccess(DataLockType::MEDIA_DATA), EFM_ERR_NO_PERMISSION);
}

/**
 * @tc.name: ReleaseAccess002
 * @tc.desc: Release all type data access without permission.
 * @tc.type: FUNC
 * @tc.require: issueI9JGMV
 */
HWTEST_F(El5FilekeyManagerServiceTest, ReleaseAccess002, TestSize.Level1)
{
    ASSERT_EQ(el5FilekeyManagerService_->ReleaseAccess(DataLockType::ALL_DATA), EFM_ERR_NO_PERMISSION);
}

/**
 * @tc.name: GenerateAppKey001
 * @tc.desc: Generate app key by uid and bundle name without permission.
 * @tc.type: FUNC
 * @tc.require: issueI9JGMV
 */
HWTEST_F(El5FilekeyManagerServiceTest, GenerateAppKey001, TestSize.Level1)
{
    int32_t uid = 12345;
    std::string bundleName = "com.ohos.el5_test";
    std::string keyId;
    ASSERT_EQ(el5FilekeyManagerService_->GenerateAppKey(uid, bundleName, keyId), EFM_ERR_NO_PERMISSION);
}

/**
 * @tc.name: DeleteAppKey001
 * @tc.desc: Delete app key by bundle name and user id without permission.
 * @tc.type: FUNC
 * @tc.require: issueI9JGMV
 */
HWTEST_F(El5FilekeyManagerServiceTest, DeleteAppKey001, TestSize.Level1)
{
    std::string bundleName = "";
    int32_t userId = 100;
    ASSERT_EQ(el5FilekeyManagerService_->DeleteAppKey(bundleName, userId), EFM_ERR_NO_PERMISSION);
}

/**
 * @tc.name: GetUserAppKey001
 * @tc.desc: Find key infos of the specified user id without permission.
 * @tc.type: FUNC
 * @tc.require: issueI9JGMV
 */
HWTEST_F(El5FilekeyManagerServiceTest, GetUserAppKey001, TestSize.Level1)
{
    int32_t userId = 100;
    std::vector<UserAppKeyInfo> keyInfos;
    ASSERT_EQ(el5FilekeyManagerService_->GetUserAppKey(userId, false, keyInfos), EFM_ERR_NO_PERMISSION);
}

/**
 * @tc.name: GetUserAppKey002
 * @tc.desc: Find key infos of the specified user id without permission, userId < 0.
 * @tc.type: FUNC
 * @tc.require: issueI9JGMV
 */
HWTEST_F(El5FilekeyManagerServiceTest, GetUserAppKey002, TestSize.Level1)
{
    int32_t userId = -100;
    std::vector<UserAppKeyInfo> keyInfos;
    ASSERT_EQ(el5FilekeyManagerService_->GetUserAppKey(userId, false, keyInfos), EFM_ERR_INVALID_PARAMETER);
}

/**
 * @tc.name: ChangeUserAppkeysLoadInfo001
 * @tc.desc: Change key infos of the specified user id without permission.
 * @tc.type: FUNC
 * @tc.require: issueI9JGMV
 */
HWTEST_F(El5FilekeyManagerServiceTest, ChangeUserAppkeysLoadInfo001, TestSize.Level1)
{
    int32_t userId = 100;
    std::vector<AppKeyLoadInfo> loadInfos;
    std::string emptyStr("");
    loadInfos.emplace_back(AppKeyLoadInfo(emptyStr, true));
    ASSERT_EQ(el5FilekeyManagerService_->ChangeUserAppkeysLoadInfo(userId, loadInfos), EFM_ERR_NO_PERMISSION);
}

/**
 * @tc.name: ChangeUserAppkeysLoadInfo002
 * @tc.desc: Change key infos of the specified user id without permission, userId < 0.
 * @tc.type: FUNC
 * @tc.require: issueI9JGMV
 */
HWTEST_F(El5FilekeyManagerServiceTest, ChangeUserAppkeysLoadInfo002, TestSize.Level1)
{
    int32_t userId = -100;
    std::vector<AppKeyLoadInfo> loadInfos;
    std::string emptyStr("");
    loadInfos.emplace_back(AppKeyLoadInfo(emptyStr, true));
    ASSERT_EQ(el5FilekeyManagerService_->ChangeUserAppkeysLoadInfo(userId, loadInfos), EFM_ERR_INVALID_PARAMETER);
}

/**
 * @tc.name: SetFilePathPolicy001
 * @tc.desc: Set path policy without permission.
 * @tc.type: FUNC
 * @tc.require: issueI9Q6K2
 */
HWTEST_F(El5FilekeyManagerServiceTest, SetFilePathPolicy001, TestSize.Level1)
{
    ASSERT_EQ(el5FilekeyManagerService_->SetFilePathPolicy(), EFM_ERR_NO_PERMISSION);
}

/**
 * @tc.name: RegisterCallback001
 * @tc.desc: Register app key generation callback without permission.
 * @tc.type: FUNC
 * @tc.require: issueI9Q6K2
 */
HWTEST_F(El5FilekeyManagerServiceTest, RegisterCallback001, TestSize.Level1)
{
    ASSERT_EQ(el5FilekeyManagerService_->RegisterCallback((new TestEl5FilekeyCallback())), EFM_ERR_NO_PERMISSION);
}

/**
 * @tc.name: GenerateGroupIDKey001
 * @tc.desc: Generate data group key by userId and group id without permission.
 * @tc.type: FUNC
 * @tc.require: issueI9JGMV
 */
HWTEST_F(El5FilekeyManagerServiceTest, GenerateGroupIDKey001, TestSize.Level1)
{
    uint32_t uid = 100;
    std::string groupID = "abcdefghijklmn";
    std::string keyId;
    ASSERT_EQ(el5FilekeyManagerService_->GenerateGroupIDKey(uid, groupID, keyId), EFM_ERR_NO_PERMISSION);
}

/**
 * @tc.name: DeleteGroupIDKey001
 * @tc.desc: Delete data group key by user id and group id without permission.
 * @tc.type: FUNC
 * @tc.require: issueI9JGMV
 */
HWTEST_F(El5FilekeyManagerServiceTest, DeleteGroupIDKey001, TestSize.Level1)
{
    uint32_t uid = 100;
    std::string groupID = "";
    ASSERT_EQ(el5FilekeyManagerService_->DeleteGroupIDKey(uid, groupID), EFM_ERR_NO_PERMISSION);
}

/**
 * @tc.name: QueryAppKeyState001
 * @tc.desc: Query media type app key without permission.
 * @tc.type: FUNC
 * @tc.require: issueI9JGMV
 */
HWTEST_F(El5FilekeyManagerServiceTest, QueryAppKeyState001, TestSize.Level1)
{
    ASSERT_EQ(el5FilekeyManagerService_->QueryAppKeyState(DataLockType::MEDIA_DATA), EFM_ERR_NO_PERMISSION);
}

/**
 * @tc.name: QueryAppKeyState002
 * @tc.desc: Query all type app key without permission.
 * @tc.type: FUNC
 * @tc.require: issueI9JGMV
 */
HWTEST_F(El5FilekeyManagerServiceTest, QueryAppKeyState002, TestSize.Level1)
{
    ASSERT_EQ(el5FilekeyManagerService_->QueryAppKeyState(DataLockType::ALL_DATA), EFM_ERR_NO_PERMISSION);
}

/**
 * @tc.name: QueryAppKeyState003
 * @tc.desc: Query invalid type app key.
 * @tc.type: FUNC
 * @tc.require: issueIAD2MD
 */
HWTEST_F(El5FilekeyManagerServiceTest, QueryAppKeyState003, TestSize.Level1)
{
    uint32_t type = 3;
    ASSERT_EQ(el5FilekeyManagerService_->QueryAppKeyState(static_cast<DataLockType>(type)), EFM_ERR_NO_PERMISSION);
}

/**
 * @tc.name: SetPolicyScreenLocked001
 * @tc.desc: SetPolicyScreenLocked
 * @tc.type: FUNC
 * @tc.require: issueI9Q6K2
 */
HWTEST_F(El5FilekeyManagerServiceTest, SetPolicyScreenLocked001, TestSize.Level1)
{
    ASSERT_EQ(el5FilekeyManagerService_->SetPolicyScreenLocked(), EFM_SUCCESS);
}

/**
 * @tc.name: Dump001
 * @tc.desc: Dump fd > 0
 * @tc.type: FUNC
 * @tc.require: issueI9Q6K2
 */
HWTEST_F(El5FilekeyManagerServiceTest, Dump001, TestSize.Level1)
{
    int fd = 1;
    std::vector<std::u16string> args = {};
    ASSERT_EQ(el5FilekeyManagerService_->Dump(fd, args), EFM_SUCCESS);
}

/**
 * @tc.name: Dump002
 * @tc.desc: Dump fd < 0
 * @tc.type: FUNC
 * @tc.require: issueI9Q6K2
 */
HWTEST_F(El5FilekeyManagerServiceTest, Dump002, TestSize.Level1)
{
    int fd = -1;
    std::vector<std::u16string> args = {};
    ASSERT_EQ(el5FilekeyManagerService_->Dump(fd, args), EFM_ERR_INVALID_PARAMETER);
}

/**
 * @tc.name: Dump003
 * @tc.desc: Dump args != null
 * @tc.type: FUNC
 * @tc.require: issueI9Q6K2
 */
HWTEST_F(El5FilekeyManagerServiceTest, Dump003, TestSize.Level1)
{
    int fd = 1;
    std::vector<std::u16string> args = {u"-h"};
    ASSERT_EQ(el5FilekeyManagerService_->Dump(fd, args), EFM_SUCCESS);
}

/**
 * @tc.name: IsSystemApp001
 * @tc.desc: IsSystemApp fun test.
 * @tc.type: FUNC
 * @tc.require: issueI9Q6K2
 */
HWTEST_F(El5FilekeyManagerServiceTest, IsSystemApp001, TestSize.Level1)
{
    ASSERT_EQ(el5FilekeyManagerService_->IsSystemApp(), false);
}
