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

#include "el5_filekey_manager_service_unittest.h"

#include "accesstoken_kit.h"
#include "token_setproc.h"

using namespace testing::ext;
using namespace OHOS::Security::AccessToken;

namespace {
static constexpr int32_t DEFAUTL_API_VERSION = 12;
static PermissionStateFull mediaGranted = {
    .permissionName = "ohos.permission.ACCESS_SCREEN_LOCK_MEDIA_DATA",
    .isGeneral = true,
    .resDeviceID = {"local"},
    .grantStatus = {PermissionState::PERMISSION_GRANTED},
    .grantFlags = {1}
};

static PermissionStateFull allGranted = {
    .permissionName = "ohos.permission.ACCESS_SCREEN_LOCK_ALL_DATA",
    .isGeneral = true,
    .resDeviceID = {"local"},
    .grantStatus = {PermissionState::PERMISSION_GRANTED},
    .grantFlags = {1}
};

static HapPolicyParams hapPolicyParamsMedia = {
    .apl = APL_SYSTEM_CORE,
    .domain = "test.domain.A",
    .permList = {},
    .permStateList = {mediaGranted}
};

static HapPolicyParams hapPolicyParamsAll = {
    .apl = APL_SYSTEM_CORE,
    .domain = "test.domain.B",
    .permList = {},
    .permStateList = {allGranted}
};

static HapPolicyParams hapPolicyParamsDefault = {
    .apl = APL_NORMAL,
    .domain = "test.domain.C",
    .permList = {},
    .permStateList = {}
};

static HapInfoParams info = {
    .userID = 100,
    .bundleName = "ohos.el5_filekey_test.app",
    .instIndex = 0,
    .apiVersion = DEFAUTL_API_VERSION,
    .appIDDesc = "el5_filekey_test.app",
    .isSystemApp = true
};

static AccessTokenIDEx g_tokenID = {0};
}

void El5FilekeyManagerServiceTest::SetUpTestCase()
{
}

void El5FilekeyManagerServiceTest::TearDownTestCase()
{
}

void El5FilekeyManagerServiceTest::SetUp()
{
    el5FilekeyManagerService_ = DelayedSingleton<El5FilekeyManagerService>::GetInstance();
    el5FilekeyManagerService_->Init();
    selfTokenId_ = GetSelfTokenID();
}

void El5FilekeyManagerServiceTest::TearDown()
{
}

/**
 * @tc.name: AcquireAccess001
 * @tc.desc: Acquire default type data access.
 * @tc.type: FUNC
 * @tc.require: issueI9JGMV
 */
HWTEST_F(El5FilekeyManagerServiceTest, AcquireAccess001, TestSize.Level1)
{
    g_tokenID = AccessTokenKit::AllocHapToken(info, hapPolicyParamsDefault);
    SetSelfTokenID(g_tokenID.tokenIDEx); // set self tokenID to normal app

    DataLockType type = DEFAULT_DATA;
    ASSERT_EQ(el5FilekeyManagerService_->AcquireAccess(static_cast<DataLockType>(type)), EFM_SUCCESS);

    SetSelfTokenID(selfTokenId_);
    AccessTokenID tokenId = AccessTokenKit::GetHapTokenID(info.userID, info.bundleName, info.instIndex);
    AccessTokenKit::DeleteToken(tokenId);
}

/**
 * @tc.name: AcquireAccess002
 * @tc.desc: Acquire media type data access without permission.
 * @tc.type: FUNC
 * @tc.require: issueI9JGMV
 */
HWTEST_F(El5FilekeyManagerServiceTest, AcquireAccess002, TestSize.Level1)
{
    DataLockType type = MEDIA_DATA;
    ASSERT_EQ(el5FilekeyManagerService_->AcquireAccess(static_cast<DataLockType>(type)), EFM_ERR_NO_PERMISSION);
}

/**
 * @tc.name: AcquireAccess003
 * @tc.desc: Acquire all type data access without permission.
 * @tc.type: FUNC
 * @tc.require: issueI9JGMV
 */
HWTEST_F(El5FilekeyManagerServiceTest, AcquireAccess003, TestSize.Level1)
{
    DataLockType type = ALL_DATA;
    ASSERT_EQ(el5FilekeyManagerService_->AcquireAccess(static_cast<DataLockType>(type)), EFM_ERR_NO_PERMISSION);
}

/**
 * @tc.name: ReleaseAccess001
 * @tc.desc: Release default type data access.
 * @tc.type: FUNC
 * @tc.require: issueI9JGMV
 */
HWTEST_F(El5FilekeyManagerServiceTest, ReleaseAccess001, TestSize.Level1)
{
    g_tokenID = AccessTokenKit::AllocHapToken(info, hapPolicyParamsDefault);
    SetSelfTokenID(g_tokenID.tokenIDEx); // set self tokenID to normal app

    DataLockType type = DEFAULT_DATA;
    ASSERT_EQ(el5FilekeyManagerService_->ReleaseAccess(static_cast<DataLockType>(type)), EFM_SUCCESS);

    SetSelfTokenID(selfTokenId_);
    AccessTokenID tokenId = AccessTokenKit::GetHapTokenID(info.userID, info.bundleName, info.instIndex);
    AccessTokenKit::DeleteToken(tokenId);
}

/**
 * @tc.name: ReleaseAccess002
 * @tc.desc: Release media type data access without permission.
 * @tc.type: FUNC
 * @tc.require: issueI9JGMV
 */
HWTEST_F(El5FilekeyManagerServiceTest, ReleaseAccess002, TestSize.Level1)
{
    DataLockType type = MEDIA_DATA;
    ASSERT_EQ(el5FilekeyManagerService_->ReleaseAccess(static_cast<DataLockType>(type)), EFM_ERR_NO_PERMISSION);
}

/**
 * @tc.name: ReleaseAccess003
 * @tc.desc: Release all type data access without permission.
 * @tc.type: FUNC
 * @tc.require: issueI9JGMV
 */
HWTEST_F(El5FilekeyManagerServiceTest, ReleaseAccess003, TestSize.Level1)
{
    DataLockType type = ALL_DATA;
    ASSERT_EQ(el5FilekeyManagerService_->ReleaseAccess(static_cast<DataLockType>(type)), EFM_ERR_NO_PERMISSION);
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
 * @tc.desc: Delete app key by keyId without permission.
 * @tc.type: FUNC
 * @tc.require: issueI9JGMV
 */
HWTEST_F(El5FilekeyManagerServiceTest, DeleteAppKey001, TestSize.Level1)
{
    std::string keyId = "";
    ASSERT_EQ(el5FilekeyManagerService_->DeleteAppKey(keyId), EFM_ERR_NO_PERMISSION);
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
    std::vector<std::pair<int32_t, std::string>> keyInfos;
    ASSERT_EQ(el5FilekeyManagerService_->GetUserAppKey(userId, keyInfos), EFM_ERR_NO_PERMISSION);
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
    std::vector<std::pair<std::string, bool>> loadInfos;
    loadInfos.emplace_back(std::make_pair("", true));
    ASSERT_EQ(el5FilekeyManagerService_->ChangeUserAppkeysLoadInfo(userId, loadInfos), EFM_ERR_NO_PERMISSION);
}
