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

#include "el5_filekey_manager_kit_unittest.h"

#include "accesstoken_kit.h"
#include "el5_filekey_callback_interface_stub.h"
#include "el5_filekey_manager_error.h"
#include "el5_filekey_manager_kit.h"
#include "token_setproc.h"

using namespace testing::ext;
using namespace OHOS::Security::AccessToken;

void El5FilekeyManagerKitTest::SetUpTestCase()
{
}

void El5FilekeyManagerKitTest::TearDownTestCase()
{
}

void El5FilekeyManagerKitTest::SetUp()
{
}

void El5FilekeyManagerKitTest::TearDown()
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
HWTEST_F(El5FilekeyManagerKitTest, AcquireAccess001, TestSize.Level1)
{
    DataLockType type = DataLockType::MEDIA_DATA;
    ASSERT_EQ(El5FilekeyManagerKit::AcquireAccess(static_cast<DataLockType>(type)), EFM_ERR_NO_PERMISSION);
}

/**
 * @tc.name: AcquireAccess002
 * @tc.desc: Acquire all type data access without permission.
 * @tc.type: FUNC
 * @tc.require: issueI9JGMV
 */
HWTEST_F(El5FilekeyManagerKitTest, AcquireAccess002, TestSize.Level1)
{
    DataLockType type = DataLockType::ALL_DATA;
    ASSERT_EQ(El5FilekeyManagerKit::AcquireAccess(static_cast<DataLockType>(type)), EFM_ERR_NO_PERMISSION);
}

/**
 * @tc.name: ReleaseAccess001
 * @tc.desc: Release media type data access without permission.
 * @tc.type: FUNC
 * @tc.require: issueI9JGMV
 */
HWTEST_F(El5FilekeyManagerKitTest, ReleaseAccess001, TestSize.Level1)
{
    DataLockType type = DataLockType::MEDIA_DATA;
    ASSERT_EQ(El5FilekeyManagerKit::ReleaseAccess(static_cast<DataLockType>(type)), EFM_ERR_NO_PERMISSION);
}

/**
 * @tc.name: ReleaseAccess002
 * @tc.desc: Release all type data access without permission.
 * @tc.type: FUNC
 * @tc.require: issueI9JGMV
 */
HWTEST_F(El5FilekeyManagerKitTest, ReleaseAccess002, TestSize.Level1)
{
    DataLockType type = DataLockType::ALL_DATA;
    ASSERT_EQ(El5FilekeyManagerKit::ReleaseAccess(static_cast<DataLockType>(type)), EFM_ERR_NO_PERMISSION);
}

/**
 * @tc.name: GenerateAppKey001
 * @tc.desc: Generate app key by uid and bundle name without permission.
 * @tc.type: FUNC
 * @tc.require: issueI9JGMV
 */
HWTEST_F(El5FilekeyManagerKitTest, GenerateAppKey001, TestSize.Level1)
{
    int32_t uid = 10010;
    std::string bundleName = "com.ohos.systemui";
    std::string keyId;
    ASSERT_EQ(El5FilekeyManagerKit::GenerateAppKey(uid, bundleName, keyId), EFM_ERR_NO_PERMISSION);
}

/**
 * @tc.name: DeleteAppKey001
 * @tc.desc: Delete app key by bundle name and user id without permission.
 * @tc.type: FUNC
 * @tc.require: issueI9JGMV
 */
HWTEST_F(El5FilekeyManagerKitTest, DeleteAppKey001, TestSize.Level1)
{
    std::string bundleName = "";
    int32_t userId = 100;
    ASSERT_EQ(El5FilekeyManagerKit::DeleteAppKey(bundleName, userId), EFM_ERR_NO_PERMISSION);
}

/**
 * @tc.name: GetUserAppKey001
 * @tc.desc: Find key infos of the specified user id without permission.
 * @tc.type: FUNC
 * @tc.require: issueI9JGMV
 */
HWTEST_F(El5FilekeyManagerKitTest, GetUserAppKey001, TestSize.Level1)
{
    int32_t userId = 100;
    std::vector<std::pair<int32_t, std::string>> keyInfos;
    ASSERT_EQ(El5FilekeyManagerKit::GetUserAppKey(userId, keyInfos), EFM_ERR_NO_PERMISSION);
}

/**
 * @tc.name: ChangeUserAppkeysLoadInfo001
 * @tc.desc: Change key infos of the specified user id without permission.
 * @tc.type: FUNC
 * @tc.require: issueI9JGMV
 */
HWTEST_F(El5FilekeyManagerKitTest, ChangeUserAppkeysLoadInfo001, TestSize.Level1)
{
    int32_t userId = 100;
    std::vector<std::pair<std::string, bool>> loadInfos;
    loadInfos.emplace_back(std::make_pair("", true));
    ASSERT_EQ(El5FilekeyManagerKit::ChangeUserAppkeysLoadInfo(userId, loadInfos), EFM_ERR_NO_PERMISSION);
}

/**
 * @tc.name: SetFilePathPolicy001
 * @tc.desc: Set path policy without permission.
 * @tc.type: FUNC
 * @tc.require: issueI9Q6K2
 */
HWTEST_F(El5FilekeyManagerKitTest, SetFilePathPolicy001, TestSize.Level1)
{
    ASSERT_EQ(El5FilekeyManagerKit::SetFilePathPolicy(), EFM_ERR_NO_PERMISSION);
}

/**
 * @tc.name: RegisterCallback001
 * @tc.desc: Register app key generation callback without permission.
 * @tc.type: FUNC
 * @tc.require: issueI9Q6K2
 */
HWTEST_F(El5FilekeyManagerKitTest, RegisterCallback001, TestSize.Level1)
{
    ASSERT_NE(El5FilekeyManagerKit::RegisterCallback((new TestEl5FilekeyCallback())), EFM_SUCCESS);
}

/**
 * @tc.name: GetUserAllAppKey001
 * @tc.desc: GetUserAllAppKey function test without permission.
 * @tc.type: FUNC
 * @tc.require: issueI9Q6K2
 */
HWTEST_F(El5FilekeyManagerKitTest, GetUserAllAppKey001, TestSize.Level1)
{
    int32_t userId = 100;
    std::vector<std::pair<int32_t, std::string>> keyInfos;
    keyInfos.emplace_back(std::make_pair(100, ""));
    ASSERT_EQ(El5FilekeyManagerKit::GetUserAllAppKey(userId, keyInfos), EFM_ERR_NO_PERMISSION);
}

/**
 * @tc.name: GenerateGroupIDKey001
 * @tc.desc: Generate data group key by userId and group id without permission.
 * @tc.type: FUNC
 * @tc.require: issueI9JGMV
 */
HWTEST_F(El5FilekeyManagerKitTest, GenerateGroupIDKey001, TestSize.Level1)
{
    uint32_t uid = 100;
    std::string groupID = "abcdefghijklmn";
    std::string keyId;
    ASSERT_EQ(El5FilekeyManagerKit::GenerateGroupIDKey(uid, groupID, keyId), EFM_ERR_NO_PERMISSION);
}

/**
 * @tc.name: DeleteGroupIDKey001
 * @tc.desc: Delete data group key by user id and group id without permission.
 * @tc.type: FUNC
 * @tc.require: issueI9JGMV
 */
HWTEST_F(El5FilekeyManagerKitTest, DeleteGroupIDKey001, TestSize.Level1)
{
    uint32_t uid = 100;
    std::string groupID = "";
    ASSERT_EQ(El5FilekeyManagerKit::DeleteGroupIDKey(uid, groupID), EFM_ERR_NO_PERMISSION);
}

/**
 * @tc.name: QueryAppKeyState001
 * @tc.desc: Query media type app key without permission.
 * @tc.type: FUNC
 * @tc.require: issueI9JGMV
 */
HWTEST_F(El5FilekeyManagerKitTest, QueryAppKeyState001, TestSize.Level1)
{
    DataLockType type = DataLockType::MEDIA_DATA;
    ASSERT_EQ(El5FilekeyManagerKit::QueryAppKeyState(static_cast<DataLockType>(type)), EFM_ERR_NO_PERMISSION);
}

/**
 * @tc.name: QueryAppKeyState002
 * @tc.desc: Query all type app key without permission.
 * @tc.type: FUNC
 * @tc.require: issueI9JGMV
 */
HWTEST_F(El5FilekeyManagerKitTest, QueryAppKeyState002, TestSize.Level1)
{
    DataLockType type = DataLockType::ALL_DATA;
    ASSERT_EQ(El5FilekeyManagerKit::QueryAppKeyState(static_cast<DataLockType>(type)), EFM_ERR_NO_PERMISSION);
}
