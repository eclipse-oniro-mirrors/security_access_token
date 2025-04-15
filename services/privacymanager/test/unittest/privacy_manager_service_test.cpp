/*
 * Copyright (c) 2022-2025 Huawei Device Co., Ltd.
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
#include <memory>

#include "accesstoken_kit.h"
#include "constant.h"
#include "iprivacy_manager.h"
#include "on_permission_used_record_callback_stub.h"
#define private public
#include "permission_record_manager.h"
#include "privacy_manager_service.h"
#undef private
#include "perm_active_status_change_callback_stub.h"
#include "perm_active_status_change_callback.h"
#include "privacy_error.h"
#include "privacy_field_const.h"
#include "privacy_test_common.h"
#include "proxy_death_callback_stub.h"
#include "state_change_callback.h"
#include "string_ex.h"
#include "token_setproc.h"

using namespace testing::ext;

namespace OHOS {
namespace Security {
namespace AccessToken {
namespace {
static AccessTokenID g_selfTokenId = 0;
static constexpr int32_t PERMISSION_USAGE_RECORDS_MAX_NUM = 10;
constexpr const char* CAMERA_PERMISSION_NAME = "ohos.permission.CAMERA";
constexpr const char* MICROPHONE_PERMISSION_NAME = "ohos.permission.MICROPHONE";
constexpr const char* LOCATION_PERMISSION_NAME = "ohos.permission.LOCATION";
static const uint32_t PERM_LIST_SIZE_MAX = 1024;
static constexpr int32_t COMMON_EVENT_SERVICE_ID = 3299;
static constexpr int32_t SCREENLOCK_SERVICE_ID = 3704;
static constexpr int32_t INVALID_CODE = 999;
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
    .appIDDesc = "privacy_test.bundleA",
    .isSystemApp = true
};
}

class PrivacyManagerServiceTest : public testing::Test {
public:
    static void SetUpTestCase();

    static void TearDownTestCase();

    void SetUp();

    void TearDown();
    std::shared_ptr<PrivacyManagerService> privacyManagerService_;
};

void PrivacyManagerServiceTest::SetUpTestCase()
{
    g_selfTokenId = GetSelfTokenID();
    PrivacyTestCommon::SetTestEvironment(g_selfTokenId);
}

void PrivacyManagerServiceTest::TearDownTestCase()
{
    PrivacyTestCommon::ResetTestEvironment();
}

void PrivacyManagerServiceTest::SetUp()
{
    privacyManagerService_ = DelayedSingleton<PrivacyManagerService>::GetInstance();
    PermissionRecordManager::GetInstance().Register();
    EXPECT_NE(nullptr, privacyManagerService_);

    PrivacyTestCommon::AllocTestHapToken(g_InfoParms1, g_PolicyPrams1);
}

void PrivacyManagerServiceTest::TearDown()
{
    AccessTokenIDEx tokenIdEx = PrivacyTestCommon::GetHapTokenIdFromBundle(g_InfoParms1.userID, g_InfoParms1.bundleName,
        g_InfoParms1.instIndex);
    PrivacyTestCommon::DeleteTestHapToken(tokenIdEx.tokenIdExStruct.tokenID);
    privacyManagerService_->RemovePermissionUsedRecords(tokenIdEx.tokenIdExStruct.tokenID);

    privacyManagerService_ = nullptr;
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
    int32_t fd = 1; // 1: std output
    std::vector<std::u16string> args;
    AccessTokenIDEx tokenIdEx = PrivacyTestCommon::AllocTestHapToken(g_InfoParms1, g_PolicyPrams1);

    AccessTokenID tokenId = tokenIdEx.tokenIdExStruct.tokenID;
    args.emplace_back(Str8ToStr16("-t"));
    std::string tokenIdStr = std::to_string(tokenId);
    args.emplace_back(Str8ToStr16(tokenIdStr));

    ASSERT_EQ(RET_SUCCESS, privacyManagerService_->Dump(fd, args));

    AddPermParamInfoParcel infoParcel;
    infoParcel.info.tokenId = tokenId;
    infoParcel.info.permissionName = "ohos.permission.READ_CONTACTS";
    infoParcel.info.successCount = 1;
    infoParcel.info.failCount = 0;

    for (int32_t i = 0; i < PERMISSION_USAGE_RECORDS_MAX_NUM; i++) {
        privacyManagerService_->AddPermissionUsedRecord(infoParcel);
    }

    ASSERT_EQ(RET_SUCCESS, privacyManagerService_->Dump(fd, args));

    privacyManagerService_->AddPermissionUsedRecord(infoParcel);
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
    MockNativeToken mock("privacy_service");

    AccessTokenIDEx tokenIdEx = PrivacyTestCommon::GetHapTokenIdFromBundle(
        g_InfoParms1.userID, g_InfoParms1.bundleName, g_InfoParms1.instIndex);

    AccessTokenID tokenId = tokenIdEx.tokenIdExStruct.tokenID;
    ASSERT_NE(INVALID_TOKENID, tokenId);
    bool isAllowed = false;
    privacyManagerService_->IsAllowedUsingPermission(tokenId, MICROPHONE_PERMISSION_NAME, -1, isAllowed);
    ASSERT_EQ(false, isAllowed);
    privacyManagerService_->IsAllowedUsingPermission(tokenId, LOCATION_PERMISSION_NAME, -1, isAllowed);
    ASSERT_EQ(false, isAllowed);
    privacyManagerService_->IsAllowedUsingPermission(tokenId, CAMERA_PERMISSION_NAME, -1, isAllowed);
    ASSERT_EQ(false, isAllowed);
#ifdef CAMERA_FLOAT_WINDOW_ENABLE
    // not pip
    PermissionRecordManager::GetInstance().NotifyCameraWindowChange(false, tokenId, false);
    privacyManagerService_->IsAllowedUsingPermission(tokenId, CAMERA_PERMISSION_NAME, -1, isAllowed);
    ASSERT_EQ(false, isAllowed);

    PermissionRecordManager::GetInstance().NotifyCameraWindowChange(false, tokenId, false);
    // pip
    PermissionRecordManager::GetInstance().NotifyCameraWindowChange(true, tokenId, false);
    privacyManagerService_->IsAllowedUsingPermission(tokenId, CAMERA_PERMISSION_NAME, -1, isAllowed);
    ASSERT_EQ(false, isAllowed);
#endif
}

/*
 * @tc.name: IsAllowedUsingPermission002
 * @tc.desc: IsAllowedUsingPermission function test invalid tokenId and permission
 * @tc.type: FUNC
 * @tc.require: issueI5UPRK
 */
HWTEST_F(PrivacyManagerServiceTest, IsAllowedUsingPermission002, TestSize.Level1)
{
    AccessTokenID tokenId = PrivacyTestCommon::GetNativeTokenIdFromProcess("privacy_service");
    // invalid tokenId
    bool isAllowed = false;
    privacyManagerService_->IsAllowedUsingPermission(0, CAMERA_PERMISSION_NAME, -1, isAllowed);
    ASSERT_EQ(false, isAllowed);

    // native tokenId
    privacyManagerService_->IsAllowedUsingPermission(tokenId, CAMERA_PERMISSION_NAME, -1, isAllowed);
    ASSERT_EQ(false, isAllowed);

    // invalid permission
    AccessTokenIDEx tokenIdEx = PrivacyTestCommon::GetHapTokenIdFromBundle(
        g_InfoParms1.userID, g_InfoParms1.bundleName, g_InfoParms1.instIndex);
    tokenId = tokenIdEx.tokenIdExStruct.tokenID;
    ASSERT_NE(INVALID_TOKENID, tokenId);
    privacyManagerService_->IsAllowedUsingPermission(tokenId, "test", -1, isAllowed);
    ASSERT_EQ(false, isAllowed);
}

/*
 * @tc.name: IsAllowedUsingPermission003
 * @tc.desc: test camera with screen off
 * @tc.type: FUNC
 * @tc.require: issueI5UPRK
 */
HWTEST_F(PrivacyManagerServiceTest, IsAllowedUsingPermission003, TestSize.Level1)
{
    AccessTokenIDEx tokenIdEx = PrivacyTestCommon::GetHapTokenIdFromBundle(
        g_InfoParms1.userID, g_InfoParms1.bundleName, g_InfoParms1.instIndex);

    AccessTokenID tokenId = tokenIdEx.tokenIdExStruct.tokenID;
    ASSERT_NE(INVALID_TOKENID, tokenId);
    bool isAllowed = false;
    privacyManagerService_->IsAllowedUsingPermission(tokenId, CAMERA_PERMISSION_NAME, -1, isAllowed);
    ASSERT_EQ(false, isAllowed);
}

/**
 * @tc.name: AddPermissionUsedRecordInner001
 * @tc.desc: AddPermissionUsedRecordInner test.
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(PrivacyManagerServiceTest, AddPermissionUsedRecordInner001, TestSize.Level1)
{
    AccessTokenID tokenID = 123; // 123 is invalid tokenID
    std::string permissionName = "ohos.permission.test"; // is invalid permission
    int32_t successCount = 1; // number 1
    int32_t failCount = 1; // number 1

    AddPermParamInfoParcel infoParcel;
    infoParcel.info.tokenId = tokenID;
    infoParcel.info.permissionName = permissionName;
    infoParcel.info.successCount = successCount;
    infoParcel.info.failCount = failCount;

    // callingTokenID is native token hdcd with need permission, but input tokenID is not a real hap
    int32_t ret = privacyManagerService_->AddPermissionUsedRecord(infoParcel);

    EXPECT_NE(PrivacyError::ERR_NOT_SYSTEM_APP, ret);
    EXPECT_NE(PrivacyError::ERR_PERMISSION_DENIED, ret);
}

/**
 * @tc.name: AddPermissionUsedRecordInner002
 * @tc.desc: AddPermissionUsedRecordInner test.
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(PrivacyManagerServiceTest, AddPermissionUsedRecordInner002, TestSize.Level1)
{
    AccessTokenID tokenID = 123; // 123 is invalid tokenID
    std::string permissionName = "ohos.permission.test"; // is invalid permission
    int32_t successCount = 1; // number 1
    int32_t failCount = 1; // number 1

    std::vector<std::string> reqPerm;
    MockHapToken mock("AddPermissionUsedRecordInner002", reqPerm, false); // set self tokenID to normal app

    AddPermParamInfoParcel infoParcel;
    infoParcel.info.tokenId = tokenID;
    infoParcel.info.permissionName = permissionName;
    infoParcel.info.successCount = successCount;
    infoParcel.info.failCount = failCount;

    // callingTokenID is normal hap without need permission
    int32_t ret = privacyManagerService_->AddPermissionUsedRecord(infoParcel);
    
    ASSERT_EQ(PrivacyError::ERR_NOT_SYSTEM_APP, ret);
}

/**
 * @tc.name: AddPermissionUsedRecordInner003
 * @tc.desc: AddPermissionUsedRecordInner test.
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(PrivacyManagerServiceTest, AddPermissionUsedRecordInner003, TestSize.Level1)
{
    AccessTokenID tokenID = 123; // 123 is invalid tokenID
    std::string permissionName = "ohos.permission.test"; // is invalid permission
    int32_t successCount = 1; // number 1
    int32_t failCount = 1; // number 1

    std::vector<std::string> reqPerm;
    MockHapToken mock("AddPermissionUsedRecordInner003", reqPerm, true); // set self tokenID to system app

    AddPermParamInfoParcel infoParcel;
    infoParcel.info.tokenId = tokenID;
    infoParcel.info.permissionName = permissionName;
    infoParcel.info.successCount = successCount;
    infoParcel.info.failCount = failCount;

    // callingTokenID is normal hap without need permission
    int32_t ret = privacyManagerService_->AddPermissionUsedRecord(infoParcel);

    ASSERT_EQ(PrivacyError::ERR_PERMISSION_DENIED, ret);
}

/**
 * @tc.name: AddPermissionUsedRecordAsyncInner001
 * @tc.desc: AddPermissionUsedRecordAsyncInner test.
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(PrivacyManagerServiceTest, AddPermissionUsedRecordAsyncInner001, TestSize.Level1)
{
    AccessTokenID tokenID = 123; // 123 is invalid tokenID
    std::string permissionName = "ohos.permission.test"; // is invalid permission
    int32_t successCount = 1; // number 1
    int32_t failCount = 1; // number 1

    AddPermParamInfoParcel infoParcel;
    infoParcel.info.tokenId = tokenID;
    infoParcel.info.permissionName = permissionName;
    infoParcel.info.successCount = successCount;
    infoParcel.info.failCount = failCount;

    // callingTokenID is native token hdcd with need permission, but input tokenID is not a real hap
    int32_t ret = privacyManagerService_->AddPermissionUsedRecordAsync(infoParcel);

    EXPECT_NE(PrivacyError::ERR_NOT_SYSTEM_APP, ret);
    EXPECT_NE(PrivacyError::ERR_PERMISSION_DENIED, ret);
}

/**
 * @tc.name: AddPermissionUsedRecordAsyncInner002
 * @tc.desc: AddPermissionUsedRecordAsyncInner test.
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(PrivacyManagerServiceTest, AddPermissionUsedRecordAsyncInner002, TestSize.Level1)
{
    AccessTokenID tokenID = 123; // 123 is invalid tokenID
    std::string permissionName = "ohos.permission.test"; // is invalid permission
    int32_t successCount = 1; // number 1
    int32_t failCount = 1; // number 1

    std::vector<std::string> reqPerm;
    MockHapToken mock("AddPermissionUsedRecordAsyncInner002", reqPerm, false); // set self tokenID to normal app

    AddPermParamInfoParcel infoParcel;
    infoParcel.info.tokenId = tokenID;
    infoParcel.info.permissionName = permissionName;
    infoParcel.info.successCount = successCount;
    infoParcel.info.failCount = failCount;

    // callingTokenID is normal hap without need permission
    int32_t ret = privacyManagerService_->AddPermissionUsedRecordAsync(infoParcel);
    
    ASSERT_EQ(PrivacyError::ERR_NOT_SYSTEM_APP, ret);
}

/**
 * @tc.name: AddPermissionUsedRecordAsyncInner003
 * @tc.desc: AddPermissionUsedRecordAsyncInner test.
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(PrivacyManagerServiceTest, AddPermissionUsedRecordAsyncInner003, TestSize.Level1)
{
    AccessTokenID tokenID = 123; // 123 is invalid tokenID
    std::string permissionName = "ohos.permission.test"; // is invalid permission
    int32_t successCount = 1; // number 1
    int32_t failCount = 1; // number 1

    std::vector<std::string> reqPerm;
    MockHapToken mock("AddPermissionUsedRecordAsyncInner003", reqPerm, true); // set self tokenID to system app

    AddPermParamInfoParcel infoParcel;
    infoParcel.info.tokenId = tokenID;
    infoParcel.info.permissionName = permissionName;
    infoParcel.info.successCount = successCount;
    infoParcel.info.failCount = failCount;

    // callingTokenID is normal hap without need permission
    int32_t ret = privacyManagerService_->AddPermissionUsedRecordAsync(infoParcel);

    ASSERT_EQ(PrivacyError::ERR_PERMISSION_DENIED, ret);
}

/**
 * @tc.name: SetPermissionUsedRecordToggleStatusInner001
 * @tc.desc: SetPermissionUsedRecordToggleStatusInner test.
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(PrivacyManagerServiceTest, SetPermissionUsedRecordToggleStatusInner001, TestSize.Level1)
{
    int32_t userID = 1;
    bool status = true;

    int32_t ret = privacyManagerService_->SetPermissionUsedRecordToggleStatus(userID, status);
    ASSERT_EQ(RET_SUCCESS, ret);
}

/**
 * @tc.name: SetPermissionUsedRecordToggleStatusInner002
 * @tc.desc: SetPermissionUsedRecordToggleStatusInner test.
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(PrivacyManagerServiceTest, SetPermissionUsedRecordToggleStatusInner002, TestSize.Level1)
{
    int32_t userID = 1;
    bool status = true;

    std::vector<std::string> reqPerm;
    MockHapToken mock("SetPermissionUsedRecordToggleStatusInner002", reqPerm, false); // set self tokenID to normal app

    int32_t ret = privacyManagerService_->SetPermissionUsedRecordToggleStatus(userID, status);
    ASSERT_EQ(PrivacyError::ERR_NOT_SYSTEM_APP, ret);
}

/**
 * @tc.name: SetPermissionUsedRecordToggleStatusInner003
 * @tc.desc: SetPermissionUsedRecordToggleStatusInner test.
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(PrivacyManagerServiceTest, SetPermissionUsedRecordToggleStatusInner003, TestSize.Level1)
{
    int32_t userID = 1;
    bool status = true;

    std::vector<std::string> reqPerm;
    MockHapToken mock("SetPermissionUsedRecordToggleStatusInner003", reqPerm, true); // set self tokenID to system app

    int32_t ret = privacyManagerService_->SetPermissionUsedRecordToggleStatus(userID, status);
    ASSERT_EQ(RET_SUCCESS, ret);
}

/**
 * @tc.name: GetPermissionUsedRecordToggleStatusInner001
 * @tc.desc: GetPermissionUsedRecordToggleStatusInner test.
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(PrivacyManagerServiceTest, GetPermissionUsedRecordToggleStatusInner001, TestSize.Level1)
{
    int32_t userID = 1;
    bool status = true;

    int32_t ret = privacyManagerService_->GetPermissionUsedRecordToggleStatus(userID, status);
    ASSERT_EQ(RET_SUCCESS, ret);
}

/**
 * @tc.name: GetPermissionUsedRecordToggleStatusInner002
 * @tc.desc: GetPermissionUsedRecordToggleStatusInner test.
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(PrivacyManagerServiceTest, GetPermissionUsedRecordToggleStatusInner002, TestSize.Level1)
{
    int32_t userID = 1;
    bool status = true;

    std::vector<std::string> reqPerm;
    MockHapToken mock("GetPermissionUsedRecordToggleStatusInner002", reqPerm, false); // set self tokenID to normal app

    int32_t ret = privacyManagerService_->GetPermissionUsedRecordToggleStatus(userID, status);
    ASSERT_EQ(PrivacyError::ERR_NOT_SYSTEM_APP, ret);
}

/**
 * @tc.name: GetPermissionUsedRecordToggleStatusInner003
 * @tc.desc: GetPermissionUsedRecordToggleStatusInner test.
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(PrivacyManagerServiceTest, GetPermissionUsedRecordToggleStatusInner003, TestSize.Level1)
{
    int32_t userID = 1;
    bool status = true;

    std::vector<std::string> reqPerm;
    MockHapToken mock("GetPermissionUsedRecordToggleStatusInner003", reqPerm, true); // set self tokenID to system app

    int32_t ret = privacyManagerService_->GetPermissionUsedRecordToggleStatus(userID, status);
    ASSERT_EQ(RET_SUCCESS, ret);
}

/**
 * @tc.name: StartUsingPermissionInner001
 * @tc.desc: StartUsingPermissionInner test.
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(PrivacyManagerServiceTest, StartUsingPermissionInner001, TestSize.Level1)
{
    AccessTokenID tokenID = 123; // 123 is invalid tokenID
    std::string permissionName = "ohos.permission.test"; // is invalid permission
    int32_t pid = 456; // 456 is random input

    PermissionUsedTypeInfoParcel parcel;
    parcel.info.tokenId = tokenID;
    parcel.info.pid = pid;
    parcel.info.permissionName = permissionName;

    // callingTokenID is native token hdcd with need permission, but input tokenID & perm are invalid
    int32_t ret = privacyManagerService_->StartUsingPermission(parcel, nullptr);
    EXPECT_NE(PrivacyError::ERR_NOT_SYSTEM_APP, ret);
    EXPECT_NE(PrivacyError::ERR_PERMISSION_DENIED, ret);
}

/**
 * @tc.name: StartUsingPermissionInner002
 * @tc.desc: StartUsingPermissionInner test.
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(PrivacyManagerServiceTest, StartUsingPermissionInner002, TestSize.Level1)
{
    AccessTokenID tokenID = 123; // 123 is invalid tokenID
    std::string permissionName = "ohos.permission.test"; // is invalid permission

    std::vector<std::string> reqPerm;
    MockHapToken mock("StartUsingPermissionInner002", reqPerm, false); // set self tokenID to normal app

    PermissionUsedTypeInfoParcel parcel;
    parcel.info.tokenId = tokenID;
    parcel.info.pid = -1;
    parcel.info.permissionName = permissionName;
    // callingTokenID is normal hap without need permission
    ASSERT_EQ(PrivacyError::ERR_NOT_SYSTEM_APP, privacyManagerService_->StartUsingPermission(parcel, nullptr));
}

/**
 * @tc.name: StartUsingPermissionInner003
 * @tc.desc: StartUsingPermissionInner test.
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(PrivacyManagerServiceTest, StartUsingPermissionInner003, TestSize.Level1)
{
    AccessTokenID tokenID = 123; // 123 is invalid tokenID
    std::string permissionName = "ohos.permission.test"; // is invalid permission

    std::vector<std::string> reqPerm;
    MockHapToken mock("StartUsingPermissionInner003", reqPerm, true); // set self tokenID to system app

    PermissionUsedTypeInfoParcel parcel;
    parcel.info.tokenId = tokenID;
    parcel.info.pid = -1;
    parcel.info.permissionName = permissionName;
    // callingTokenID is system hap without need permission
    ASSERT_EQ(PrivacyError::ERR_PERMISSION_DENIED, privacyManagerService_->StartUsingPermission(parcel, nullptr));
}

/**
 * @tc.name: StartUsingPermissionCallbackInner001
 * @tc.desc: StartUsingPermissionCallbackInner test.
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(PrivacyManagerServiceTest, StartUsingPermissionCallbackInner001, TestSize.Level1)
{
    AccessTokenID tokenID = 123; // 123 is invalid tokenID
    std::string permissionName = "ohos.permission.test"; // is invalid permission
    int32_t pid = 111;

    std::vector<std::string> reqPerm;
    MockHapToken mock("StartUsingPermissionCallbackInner001", reqPerm, true); // set self tokenID to system app

    PermissionUsedTypeInfoParcel parcel;
    parcel.info.tokenId = tokenID;
    parcel.info.pid = pid;
    parcel.info.permissionName = permissionName;
    // callingTokenID has no request permission
    ASSERT_EQ(PrivacyError::ERR_PERMISSION_DENIED,
        privacyManagerService_->StartUsingPermissionCallback(parcel, nullptr, nullptr));
}

/**
 * @tc.name: StartUsingPermissionCallbackInner002
 * @tc.desc: StartUsingPermissionCallbackInner test.
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(PrivacyManagerServiceTest, StartUsingPermissionCallbackInner002, TestSize.Level1)
{
    AccessTokenID tokenID = 123; // 123 is invalid tokenID
    std::string permissionName = "ohos.permission.test"; // is invalid permission
    int32_t pid = 11;

    PermissionUsedTypeInfoParcel parcel;
    parcel.info.tokenId = tokenID;
    parcel.info.pid = pid;
    parcel.info.permissionName = permissionName;

    // callingTokenID is native token hdcd with request permission
    int32_t ret = privacyManagerService_->StartUsingPermissionCallback(parcel, nullptr, nullptr);
    EXPECT_NE(PrivacyError::ERR_NOT_SYSTEM_APP, ret);
    EXPECT_NE(PrivacyError::ERR_PERMISSION_DENIED, ret);
}

/**
 * @tc.name: StartUsingPermissionCallbackInner003
 * @tc.desc: StartUsingPermissionCallbackInner test.
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(PrivacyManagerServiceTest, StartUsingPermissionCallbackInner003, TestSize.Level1)
{
    AccessTokenID tokenID = 123; // 123 is invalid tokenID
    std::string permissionName = "ohos.permission.test"; // is invalid permission
    int32_t pid = 11;

    std::vector<std::string> reqPerm;
    MockHapToken mock("StartUsingPermissionCallbackInner003", reqPerm, false); // set self tokenID to normal app

    PermissionUsedTypeInfoParcel parcel;
    parcel.info.tokenId = tokenID;
    parcel.info.pid = pid;
    parcel.info.permissionName = permissionName;

    ASSERT_EQ(PrivacyError::ERR_NOT_SYSTEM_APP,
        privacyManagerService_->StartUsingPermissionCallback(parcel, nullptr, nullptr));
}

/**
 * @tc.name: StopUsingPermissionInner001
 * @tc.desc: StopUsingPermissionInner test.
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(PrivacyManagerServiceTest, StopUsingPermissionInner001, TestSize.Level1)
{
    AccessTokenID tokenID = 123; // 123 is invalid tokenID
    std::string permissionName = "ohos.permission.test"; // is invalid permission
    int32_t pid = 11;

    // callingTokenID is native token hdcd with need permission, but input tokenID is not a real hap
    int32_t ret = privacyManagerService_->StopUsingPermission(tokenID, pid, permissionName);
    EXPECT_NE(PrivacyError::ERR_NOT_SYSTEM_APP, ret);
    EXPECT_NE(PrivacyError::ERR_PERMISSION_DENIED, ret);
}

/**
 * @tc.name: StopUsingPermissionInner002
 * @tc.desc: StopUsingPermissionInner test.
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(PrivacyManagerServiceTest, StopUsingPermissionInner002, TestSize.Level1)
{
    AccessTokenID tokenID = 123; // 123 is invalid tokenID
    std::string permissionName = "ohos.permission.test"; // is invalid permission
    int32_t pid = 11;

    std::vector<std::string> reqPerm;
    MockHapToken mock("StopUsingPermissionInner002", reqPerm, false); // set self tokenID to normal app

    // callingTokenID is normal hap without need permission
    int32_t ret = privacyManagerService_->StopUsingPermission(tokenID, pid, permissionName);
    ASSERT_EQ(PrivacyError::ERR_NOT_SYSTEM_APP, ret);
}

/**
 * @tc.name: StopUsingPermissionInner003
 * @tc.desc: StopUsingPermissionInner test.
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(PrivacyManagerServiceTest, StopUsingPermissionInner003, TestSize.Level1)
{
    AccessTokenID tokenID = 123; // 123 is invalid tokenID
    std::string permissionName = "ohos.permission.test"; // is invalid permission
    int32_t pid = 11;

    std::vector<std::string> reqPerm;
    MockHapToken mock("StopUsingPermissionInner003", reqPerm, true); // set self tokenID to system app

    // callingTokenID is system hap without need permission
    int32_t ret = privacyManagerService_->StopUsingPermission(tokenID, pid, permissionName);
    ASSERT_EQ(PrivacyError::ERR_PERMISSION_DENIED, ret);
}

/**
 * @tc.name: RemovePermissionUsedRecordsInner001
 * @tc.desc: RemovePermissionUsedRecordsInner test.
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(PrivacyManagerServiceTest, RemovePermissionUsedRecordsInner001, TestSize.Level1)
{
    AccessTokenID tokenID = 123; // 123 is invalid tokenID

    // callingTokenID is native token hdcd with need permission, but input tokenID is not a real hap
    ASSERT_EQ(RET_SUCCESS, privacyManagerService_->RemovePermissionUsedRecords(tokenID));
}

/**
 * @tc.name: RemovePermissionUsedRecordsInner002
 * @tc.desc: RemovePermissionUsedRecordsInner test.
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(PrivacyManagerServiceTest, RemovePermissionUsedRecordsInner002, TestSize.Level1)
{
    AccessTokenID tokenID = 123; // 123 is invalid tokenID

    MockNativeToken mock("device_manager"); // set self tokenID to native device_manager
    AccessTokenID nativeTokenID = GetSelfTokenID();
    ASSERT_NE(nativeTokenID, static_cast<AccessTokenID>(0));

    // native token device_manager don't have request permission
    ASSERT_EQ(PrivacyError::ERR_PERMISSION_DENIED, privacyManagerService_->RemovePermissionUsedRecords(tokenID));
}

/**
 * @tc.name: RemovePermissionUsedRecordsInner003
 * @tc.desc: RemovePermissionUsedRecordsInner test.
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(PrivacyManagerServiceTest, RemovePermissionUsedRecordsInner003, TestSize.Level1)
{
    AccessTokenID tokenID = 123; // 123 is invalid tokenID

    std::vector<std::string> reqPerm;
    MockHapToken mock("RemovePermissionUsedRecordsInner003", reqPerm, false); // set self tokenID to normal app

    // native token device_manager don't have request permission
    ASSERT_EQ(PrivacyError::ERR_NOT_SYSTEM_APP, privacyManagerService_->RemovePermissionUsedRecords(tokenID));
}

/**
 * @tc.name: RemovePermissionUsedRecordsInner004
 * @tc.desc: RemovePermissionUsedRecordsInner test.
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(PrivacyManagerServiceTest, RemovePermissionUsedRecordsInner004, TestSize.Level1)
{
    AccessTokenID tokenID = 123; // 123 is invalid tokenID

    std::vector<std::string> reqPerm = {"ohos.permission.PERMISSION_USED_STATS"};
    MockHapToken mock("RemovePermissionUsedRecordsInner004", reqPerm, true); // set self tokenID to system app
    ASSERT_EQ(RET_SUCCESS, privacyManagerService_->RemovePermissionUsedRecords(tokenID));
}

/**
 * @tc.name: GetPermissionUsedRecordsInner001
 * @tc.desc: GetPermissionUsedRecordsInner test.
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(PrivacyManagerServiceTest, GetPermissionUsedRecordsInner001, TestSize.Level1)
{
    PermissionUsedRequestParcel request;
    request.request.isRemote = true;
    PermissionUsedResultParcel resultParcel;

    // callingTokenID is native token hdcd with need permission
    ASSERT_EQ(RET_SUCCESS, privacyManagerService_->GetPermissionUsedRecords(request, resultParcel));
}

/**
 * @tc.name: GetPermissionUsedRecordsInner002
 * @tc.desc: GetPermissionUsedRecordsInner test.
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(PrivacyManagerServiceTest, GetPermissionUsedRecordsInner002, TestSize.Level1)
{
    PermissionUsedRequestParcel request;
    request.request.isRemote = true;
    PermissionUsedResultParcel resultParcel;

    std::vector<std::string> reqPerm;
    MockHapToken mock("GetPermissionUsedRecordsInner002", reqPerm, false); // set self tokenID to normal app

    // callingTokenID is normal hap without need permission
    ASSERT_EQ(PrivacyError::ERR_NOT_SYSTEM_APP,
        privacyManagerService_->GetPermissionUsedRecords(request, resultParcel));
}

/**
 * @tc.name: GetPermissionUsedRecordsInner003
 * @tc.desc: GetPermissionUsedRecordsInner test.
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(PrivacyManagerServiceTest, GetPermissionUsedRecordsInner003, TestSize.Level1)
{
    PermissionUsedRequestParcel request;
    request.request.isRemote = true;
    PermissionUsedResultParcel resultParcel;

    std::vector<std::string> reqPerm;
    MockHapToken mock("GetPermissionUsedRecordsInner003", reqPerm, true); // set self tokenID to system app

    // callingTokenID is system hap without need permission
    ASSERT_EQ(PrivacyError::ERR_PERMISSION_DENIED,
        privacyManagerService_->GetPermissionUsedRecords(request, resultParcel));
}

/**
 * @tc.name: GetPermissionUsedRecordsAsyncInner001
 * @tc.desc: GetPermissionUsedRecordsAsyncInner test.
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(PrivacyManagerServiceTest, GetPermissionUsedRecordsAsyncInner001, TestSize.Level1)
{
    PermissionUsedRequestParcel request;
    request.request.isRemote = true;

    int32_t ret = privacyManagerService_->GetPermissionUsedRecordsAsync(request, nullptr);
    // callingTokenID is native token hdcd with need permission
    EXPECT_NE(PrivacyError::ERR_NOT_SYSTEM_APP, ret);
    EXPECT_NE(PrivacyError::ERR_PERMISSION_DENIED, ret);
}

/**
 * @tc.name: GetPermissionUsedRecordsAsyncInner002
 * @tc.desc: GetPermissionUsedRecordsAsyncInner test.
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(PrivacyManagerServiceTest, GetPermissionUsedRecordsAsyncInner002, TestSize.Level1)
{
    PermissionUsedRequestParcel request;
    request.request.isRemote = true;

    std::vector<std::string> reqPerm;
    MockHapToken mock("GetPermissionUsedRecordsAsyncInner002", reqPerm, false); // set self tokenID to normal app

    int32_t ret = privacyManagerService_->GetPermissionUsedRecordsAsync(request, nullptr);
    // callingTokenID is normal hap without need permission
    ASSERT_EQ(PrivacyError::ERR_NOT_SYSTEM_APP, ret);
}

/**
 * @tc.name: GetPermissionUsedRecordsAsyncInner003
 * @tc.desc: GetPermissionUsedRecordsAsyncInner test.
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(PrivacyManagerServiceTest, GetPermissionUsedRecordsAsyncInner003, TestSize.Level1)
{
    PermissionUsedRequestParcel request;
    request.request.isRemote = true;

    std::vector<std::string> reqPerm;
    MockHapToken mock("GetPermissionUsedRecordsAsyncInner003", reqPerm, true); // set self tokenID to system app

    int32_t ret = privacyManagerService_->GetPermissionUsedRecordsAsync(request, nullptr);
    // callingTokenID is system hap without need permission
    ASSERT_EQ(PrivacyError::ERR_PERMISSION_DENIED, ret);
}

/**
 * @tc.name: RegisterPermActiveStatusCallbackInner001
 * @tc.desc: RegisterPermActiveStatusCallbackInner test.
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(PrivacyManagerServiceTest, RegisterPermActiveStatusCallbackInner001, TestSize.Level1)
{
    std::vector<std::string> permList(PERM_LIST_SIZE_MAX + 1);

    // permList size oversize
    ASSERT_EQ(PrivacyError::ERR_OVERSIZE,
        privacyManagerService_->RegisterPermActiveStatusCallback(permList, nullptr));
}

/**
 * @tc.name: RegisterPermActiveStatusCallbackInner002
 * @tc.desc: RegisterPermActiveStatusCallbackInner test.
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(PrivacyManagerServiceTest, RegisterPermActiveStatusCallbackInner002, TestSize.Level1)
{
    std::vector<std::string> permList = {};

    std::vector<std::string> reqPerm;
    MockHapToken mock("RegisterPermActiveStatusCallbackInner002", reqPerm, false); // set self tokenID to normal app

    // callingTokenID is normal hap without need permission
    ASSERT_EQ(PrivacyError::ERR_NOT_SYSTEM_APP,
        privacyManagerService_->RegisterPermActiveStatusCallback(permList, nullptr));
}

/**
 * @tc.name: RegisterPermActiveStatusCallbackInner003
 * @tc.desc: RegisterPermActiveStatusCallbackInner test.
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(PrivacyManagerServiceTest, RegisterPermActiveStatusCallbackInner003, TestSize.Level1)
{
    std::vector<std::string> permList = {};

    std::vector<std::string> reqPerm;
    MockHapToken mock("RegisterPermActiveStatusCallbackInner003", reqPerm, true); // set self tokenID to system app

    // callingTokenID is system hap without need permission
    ASSERT_EQ(PrivacyError::ERR_PERMISSION_DENIED,
        privacyManagerService_->RegisterPermActiveStatusCallback(permList, nullptr));
}

/**
 * @tc.name: RegisterPermActiveStatusCallbackInner004
 * @tc.desc: RegisterPermActiveStatusCallbackInner test.
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(PrivacyManagerServiceTest, RegisterPermActiveStatusCallbackInner004, TestSize.Level1)
{
    std::vector<std::string> permList;

    // systemapp with need permission
    int32_t ret = privacyManagerService_->RegisterPermActiveStatusCallback(permList, nullptr);
    EXPECT_NE(PrivacyError::ERR_NOT_SYSTEM_APP, ret);
    EXPECT_NE(PrivacyError::ERR_PERMISSION_DENIED, ret);
}

/**
 * @tc.name: UnRegisterPermActiveStatusCallbackInner001
 * @tc.desc: UnRegisterPermActiveStatusCallbackInner test.
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(PrivacyManagerServiceTest, UnRegisterPermActiveStatusCallbackInner001, TestSize.Level1)
{
    // systemapp with need permission
    int32_t ret = privacyManagerService_->UnRegisterPermActiveStatusCallback(nullptr);
    EXPECT_NE(PrivacyError::ERR_NOT_SYSTEM_APP, ret);
    EXPECT_NE(PrivacyError::ERR_PERMISSION_DENIED, ret);
}

/**
 * @tc.name: UnRegisterPermActiveStatusCallbackInner002
 * @tc.desc: UnRegisterPermActiveStatusCallbackInner test.
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(PrivacyManagerServiceTest, UnRegisterPermActiveStatusCallbackInner002, TestSize.Level1)
{
    std::vector<std::string> reqPerm;
    MockHapToken mock("UnRegisterPermActiveStatusCallbackInner002", reqPerm, false); // set self tokenID to normal app

    // callingTokenID is normal hap without need permission
    ASSERT_EQ(PrivacyError::ERR_NOT_SYSTEM_APP,
        privacyManagerService_->UnRegisterPermActiveStatusCallback(nullptr));
}

/**
 * @tc.name: UnRegisterPermActiveStatusCallbackInner003
 * @tc.desc: UnRegisterPermActiveStatusCallbackInner test.
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(PrivacyManagerServiceTest, UnRegisterPermActiveStatusCallbackInner003, TestSize.Level1)
{
    std::vector<std::string> reqPerm;
    MockHapToken mock("UnRegisterPermActiveStatusCallbackInner003", reqPerm, true); // set self tokenID to system app

    // callingTokenID is system hap without need permission
    ASSERT_EQ(PrivacyError::ERR_PERMISSION_DENIED,
        privacyManagerService_->UnRegisterPermActiveStatusCallback(nullptr));
}

/**
 * @tc.name: IsAllowedUsingPermissionInner001
 * @tc.desc: IsAllowedUsingPermissionInner test.
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(PrivacyManagerServiceTest, IsAllowedUsingPermissionInner001, TestSize.Level1)
{
    AccessTokenID tokenID = 123; // 123 is invalid tokenID
    std::string permissionName = "ohos.permission.test"; // is invalid permission
    int32_t pid = 11;
    bool isAllowed = false;

    // callingTokenID is native token hdcd with need permission, but tokenID is invalid
    int32_t result = privacyManagerService_->IsAllowedUsingPermission(tokenID, permissionName, pid, isAllowed);
    ASSERT_EQ(result, RET_SUCCESS);
    ASSERT_EQ(false, isAllowed);
}

/**
 * @tc.name: IsAllowedUsingPermissionInner002
 * @tc.desc: IsAllowedUsingPermissionInner test.
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(PrivacyManagerServiceTest, IsAllowedUsingPermissionInner002, TestSize.Level1)
{
    AccessTokenID tokenID = 123; // 123 is invalid tokenID
    std::string permissionName = "ohos.permission.test"; // is invalid permission
    int32_t pid = 11;
    bool isAllowed = false;

    std::vector<std::string> reqPerm;
    MockHapToken mock("IsAllowedUsingPermissionInner002", reqPerm, false); // set self tokenID to normal app

    // callingTokenID is normal hap without need permission
    int32_t result = privacyManagerService_->IsAllowedUsingPermission(tokenID, permissionName, pid, isAllowed);
    ASSERT_EQ(result, PrivacyError::ERR_NOT_SYSTEM_APP);
}

/**
 * @tc.name: IsAllowedUsingPermissionInner003
 * @tc.desc: IsAllowedUsingPermissionInner test.
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(PrivacyManagerServiceTest, IsAllowedUsingPermissionInner003, TestSize.Level1)
{
    AccessTokenID tokenID = 123; // 123 is invalid tokenID
    std::string permissionName = "ohos.permission.test"; // is invalid permission
    int32_t pid = 11;
    bool isAllowed = false;

    std::vector<std::string> reqPerm;
    MockHapToken mock("IsAllowedUsingPermissionInner003", reqPerm, true); // set self tokenID to system app

    // callingTokenID is normal hap without need permission
    int32_t result = privacyManagerService_->IsAllowedUsingPermission(tokenID, permissionName, pid, isAllowed);
    ASSERT_EQ(result, PrivacyError::ERR_PERMISSION_DENIED);
}

/**
 * @tc.name: GetPermissionUsedTypeInfosInner001
 * @tc.desc: GetPermissionUsedTypeInfosInner test.
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(PrivacyManagerServiceTest, GetPermissionUsedTypeInfosInner001, TestSize.Level1)
{
    AccessTokenID tokenID = 123; // 123 is invalid tokenID
    std::string permissionName = "ohos.permission.test"; // is invalid permission
    std::vector<PermissionUsedTypeInfoParcel> resultsParcel;

    // systemapp with need permission
    int32_t ret = privacyManagerService_->GetPermissionUsedTypeInfos(tokenID, permissionName, resultsParcel);
    EXPECT_NE(PrivacyError::ERR_NOT_SYSTEM_APP, ret);
    EXPECT_NE(PrivacyError::ERR_PERMISSION_DENIED, ret);
}

/**
 * @tc.name: GetPermissionUsedTypeInfosInner002
 * @tc.desc: GetPermissionUsedTypeInfosInner test.
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(PrivacyManagerServiceTest, GetPermissionUsedTypeInfosInner002, TestSize.Level1)
{
    AccessTokenID tokenID = 123; // 123 is invalid tokenID
    std::string permissionName = "ohos.permission.test"; // is invalid permission
    std::vector<PermissionUsedTypeInfoParcel> resultsParcel;

    std::vector<std::string> reqPerm;
    MockHapToken mock("GetPermissionUsedTypeInfosInner002", reqPerm, false); // set self tokenID to normal app

    int32_t ret = privacyManagerService_->GetPermissionUsedTypeInfos(tokenID, permissionName, resultsParcel);
    EXPECT_EQ(PrivacyError::ERR_NOT_SYSTEM_APP, ret);
}

/**
 * @tc.name: GetPermissionUsedTypeInfosInner003
 * @tc.desc: GetPermissionUsedTypeInfosInner test.
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(PrivacyManagerServiceTest, GetPermissionUsedTypeInfosInner003, TestSize.Level1)
{
    AccessTokenID tokenID = 123; // 123 is invalid tokenID
    std::string permissionName = "ohos.permission.test"; // is invalid permission
    std::vector<PermissionUsedTypeInfoParcel> resultsParcel;

    std::vector<std::string> reqPerm;
    MockHapToken mock("GetPermissionUsedTypeInfosInner003", reqPerm, true); // set self tokenID to system app

    int32_t ret = privacyManagerService_->GetPermissionUsedTypeInfos(tokenID, permissionName, resultsParcel);
    EXPECT_EQ(PrivacyError::ERR_PERMISSION_DENIED, ret);
}

/**
 * @tc.name: SetMutePolicyInner001
 * @tc.desc: SetMutePolicyInner test.
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(PrivacyManagerServiceTest, SetMutePolicyInner001, TestSize.Level1)
{
    AccessTokenID tokenID = 123; // 123 is invalid tokenID
    uint32_t policyType = 0;
    uint32_t callerType = 0;
    bool isMute = false;

    std::vector<std::string> reqPerm;
    MockHapToken mock("SetMutePolicyInner001", reqPerm, true); // set self tokenID to system app

    int32_t ret = privacyManagerService_->SetMutePolicy(policyType, callerType, isMute, tokenID);
    EXPECT_EQ(PrivacyError::ERR_PERMISSION_DENIED, ret);
}

/**
 * @tc.name: SetMutePolicyInner002
 * @tc.desc: SetMutePolicyInner test.
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(PrivacyManagerServiceTest, SetMutePolicyInner002, TestSize.Level1)
{
    AccessTokenID tokenID = 123; // 123 is invalid tokenID
    uint32_t policyType = 0;
    uint32_t callerType = 0;
    bool isMute = false;

    MockNativeToken mock("camera_service");

    int32_t ret = privacyManagerService_->SetMutePolicy(policyType, callerType, isMute, tokenID);
    EXPECT_NE(PrivacyError::ERR_PERMISSION_DENIED, ret);
}

/**
 * @tc.name: SetHapWithFGReminderInner001
 * @tc.desc: SetHapWithFGReminderInner test.
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(PrivacyManagerServiceTest, SetHapWithFGReminderInner001, TestSize.Level1)
{
    AccessTokenID tokenID = 123; // 123 is invalid tokenID
    bool isAllowed = true;

    std::vector<std::string> reqPerm;
    MockHapToken mock("SetHapWithFGReminderInner001", reqPerm, true); // set self tokenID to system app

    // systemapp with need permission
    int32_t ret = privacyManagerService_->SetHapWithFGReminder(tokenID, isAllowed);
    EXPECT_EQ(PrivacyError::ERR_PERMISSION_DENIED, ret);
}

/**
 * @tc.name: GetProxyDeathHandle001
 * @tc.desc: GetProxyDeathHandle test.
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(PrivacyManagerServiceTest, GetProxyDeathHandle001, TestSize.Level1)
{
    auto handler1 = privacyManagerService_->GetProxyDeathHandler();
    ASSERT_NE(nullptr, handler1);
    auto handler2 = privacyManagerService_->GetProxyDeathHandler();
    ASSERT_NE(nullptr, handler2);

    privacyManagerService_->OnAddSystemAbility(COMMON_EVENT_SERVICE_ID, "123");
    privacyManagerService_->OnAddSystemAbility(SCREENLOCK_SERVICE_ID, "123");
    privacyManagerService_->OnAddSystemAbility(INVALID_CODE, "123");
}
} // namespace AccessToken
} // namespace Security
} // namespace OHOS
