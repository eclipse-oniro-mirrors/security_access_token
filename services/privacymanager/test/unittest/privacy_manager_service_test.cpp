/*
 * Copyright (c) 2022 Huawei Device Co., Ltd.
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

#include <gtest/gtest.h>

#include "accesstoken_kit.h"
#include "constant.h"
#include "privacy_field_const.h"
#define private public
#include "permission_record_manager.h"
#undef private
#include "perm_active_status_change_callback_stub.h"
#include "privacy_error.h"
#include "privacy_manager_service.h"
#include "string_ex.h"
#include "token_setproc.h"

using namespace testing::ext;

namespace OHOS {
namespace Security {
namespace AccessToken {
namespace {
static constexpr int32_t PERMISSION_USAGE_RECORDS_MAX_NUM = 10;
constexpr const char* CAMERA_PERMISSION_NAME = "ohos.permission.CAMERA";
constexpr const char* MICROPHONE_PERMISSION_NAME = "ohos.permission.MICROPHONE";
constexpr const char* LOCATION_PERMISSION_NAME = "ohos.permission.LOCATION";
static PermissionStateFull g_testState = {
    .permissionName = "ohos.permission.CAMERA",
    .isGeneral = true,
    .resDeviceID = {"local"},
    .grantStatus = {PermissionState::PERMISSION_GRANTED},
    .grantFlags = {1}
};

static HapPolicyParams g_PolicyPrams1 = {
    .apl = APL_NORMAL,
    .domain = "test.domain.A",
    .permList = {},
    .permStateList = {g_testState}
};

static HapInfoParams g_InfoParms1 = {
    .userID = 1,
    .bundleName = "ohos.privacy_test.bundleA",
    .instIndex = 0,
    .appIDDesc = "privacy_test.bundleA"
};

static HapPolicyParams g_PolicyPrams2 = {
    .apl = APL_NORMAL,
    .domain = "test.domain.B",
    .permList = {},
    .permStateList = {g_testState}
};

static HapInfoParams g_InfoParms2 = {
    .userID = 1,
    .bundleName = "ohos.privacy_test.bundleB",
    .instIndex = 0,
    .appIDDesc = "privacy_test.bundleB"
};
}

class PrivacyManagerServiceTest : public testing::Test {
public:
    static void SetUpTestCase();

    static void TearDownTestCase();

    void SetUp();

    void TearDown();
    std::shared_ptr<PrivacyManagerService> privacyManagerService_;
    uint64_t selfTokenId_;
};

void PrivacyManagerServiceTest::SetUpTestCase()
{
}

void PrivacyManagerServiceTest::TearDownTestCase()
{
}

void PrivacyManagerServiceTest::SetUp()
{
    privacyManagerService_ = DelayedSingleton<PrivacyManagerService>::GetInstance();
    PermissionRecordManager::GetInstance().Register();
    EXPECT_NE(nullptr, privacyManagerService_);
    AccessTokenKit::AllocHapToken(g_InfoParms1, g_PolicyPrams1);
    AccessTokenKit::AllocHapToken(g_InfoParms2, g_PolicyPrams2);
    selfTokenId_ = GetSelfTokenID();
}

void PrivacyManagerServiceTest::TearDown()
{
    privacyManagerService_ = nullptr;
    AccessTokenID tokenId = AccessTokenKit::GetHapTokenID(g_InfoParms1.userID, g_InfoParms1.bundleName,
        g_InfoParms1.instIndex);
    AccessTokenKit::DeleteToken(tokenId);
    tokenId = AccessTokenKit::GetHapTokenID(g_InfoParms2.userID, g_InfoParms2.bundleName,
        g_InfoParms2.instIndex);
    AccessTokenKit::DeleteToken(tokenId);
    SetSelfTokenID(selfTokenId_);
}

/**
 * @tc.name: Dump001
 * @tc.desc: Dump record info.
 * @tc.type: FUNC
 * @tc.require: issueI4V02P
 */
HWTEST_F(PrivacyManagerServiceTest, Dump001, TestSize.Level1)
{
    int32_t fd = -1;
    std::vector<std::u16string> args;

    // fd is 0
    ASSERT_NE(RET_SUCCESS, privacyManagerService_->Dump(fd, args));

    fd = 1; // 1: std output

    // hidumper
    ASSERT_EQ(RET_SUCCESS, privacyManagerService_->Dump(fd, args));

    // hidumper -h
    args.emplace_back(Str8ToStr16("-h"));
    ASSERT_EQ(RET_SUCCESS, privacyManagerService_->Dump(fd, args));

    args.clear();
    // hidumper -t
    args.emplace_back(Str8ToStr16("-t"));
    ASSERT_NE(RET_SUCCESS, privacyManagerService_->Dump(fd, args));

    args.clear();
    // hidumper -t
    args.emplace_back(Str8ToStr16("-t"));
    args.emplace_back(Str8ToStr16("-1")); // illegal tokenId
    ASSERT_NE(RET_SUCCESS, privacyManagerService_->Dump(fd, args));

    args.clear();
    // hidumper -t
    args.emplace_back(Str8ToStr16("-s"));
    ASSERT_NE(RET_SUCCESS, privacyManagerService_->Dump(fd, args));

    args.clear();
    // hidumper -t
    args.emplace_back(Str8ToStr16("-t"));
    args.emplace_back(Str8ToStr16("123")); // 123: invalid tokenId
    ASSERT_EQ(RET_SUCCESS, privacyManagerService_->Dump(fd, args));
}

/**
 * @tc.name: Dump002
 * @tc.desc: Dump record info.
 * @tc.type: FUNC
 * @tc.require: issueI4V02P
 */
HWTEST_F(PrivacyManagerServiceTest, Dump002, TestSize.Level1)
{
    int32_t fd = 123; // 123: invalid fd
    std::vector<std::u16string> args;
    AccessTokenID tokenId = AccessTokenKit::GetHapTokenID(g_InfoParms1.userID, g_InfoParms1.bundleName,
        g_InfoParms1.instIndex);
    args.emplace_back(Str8ToStr16("-t"));
    std::string tokenIdStr = std::to_string(tokenId);
    args.emplace_back(Str8ToStr16(tokenIdStr));

    ASSERT_EQ(RET_SUCCESS, privacyManagerService_->Dump(fd, args));

    std::string permission = "ohos.permission.CAMERA";
    for (int32_t i = 0; i < PERMISSION_USAGE_RECORDS_MAX_NUM; i++) {
        privacyManagerService_->AddPermissionUsedRecord(tokenId, permission, 1, 0);
    }

    ASSERT_EQ(RET_SUCCESS, privacyManagerService_->Dump(fd, args));

    privacyManagerService_->AddPermissionUsedRecord(tokenId, permission, 1, 0);
    ASSERT_EQ(RET_SUCCESS, privacyManagerService_->Dump(fd, args));
}

/*
 * @tc.name: IsAllowedUsingPermission001
 * @tc.desc: IsAllowedUsingPermission function test permissionName branch
 * @tc.type: FUNC
 * @tc.require: issueI5UPRK
 */
HWTEST_F(PrivacyManagerServiceTest, IsAllowedUsingPermission001, TestSize.Level1)
{
    AccessTokenID tokenId = AccessTokenKit::GetNativeTokenId("privacy_service");
    ASSERT_NE(INVALID_TOKENID, tokenId);
    SetSelfTokenID(tokenId);
    tokenId = AccessTokenKit::GetHapTokenID(g_InfoParms1.userID, g_InfoParms1.bundleName,
        g_InfoParms1.instIndex);
    ASSERT_NE(INVALID_TOKENID, tokenId);
    PermissionRecordManager::GetInstance().NotifyCameraFloatWindowChange(tokenId, false);
    ASSERT_EQ(false, privacyManagerService_->IsAllowedUsingPermission(tokenId, CAMERA_PERMISSION_NAME));
    PermissionRecordManager::GetInstance().NotifyCameraFloatWindowChange(tokenId, true);
    ASSERT_EQ(true, privacyManagerService_->IsAllowedUsingPermission(tokenId, CAMERA_PERMISSION_NAME));
    ASSERT_EQ(false, privacyManagerService_->IsAllowedUsingPermission(tokenId, MICROPHONE_PERMISSION_NAME));
    ASSERT_EQ(false, privacyManagerService_->IsAllowedUsingPermission(tokenId, LOCATION_PERMISSION_NAME));
}

/*
 * @tc.name: IsAllowedUsingPermission002
 * @tc.desc: IsAllowedUsingPermission function test invalid tokenId
 * @tc.type: FUNC
 * @tc.require: issueI5UPRK
 */
HWTEST_F(PrivacyManagerServiceTest, IsAllowedUsingPermission002, TestSize.Level1)
{
    ASSERT_EQ(false, privacyManagerService_->IsAllowedUsingPermission(0, CAMERA_PERMISSION_NAME));
    ASSERT_EQ(false, privacyManagerService_->IsAllowedUsingPermission(0, "test"));
}
} // namespace AccessToken
} // namespace Security
} // namespace OHOS
