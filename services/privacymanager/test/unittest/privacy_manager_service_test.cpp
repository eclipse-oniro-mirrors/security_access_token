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
#include "on_permission_used_record_callback_stub.h"
#define private public
#include "permission_record_manager.h"
#undef private
#include "perm_active_status_change_callback_stub.h"
#include "perm_active_status_change_callback.h"
#include "privacy_error.h"
#include "privacy_field_const.h"
#include "privacy_manager_service.h"
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
    ASSERT_EQ(false, privacyManagerService_->IsAllowedUsingPermission(tokenId, MICROPHONE_PERMISSION_NAME, -1));
    ASSERT_EQ(false, privacyManagerService_->IsAllowedUsingPermission(tokenId, LOCATION_PERMISSION_NAME, -1));
    ASSERT_EQ(false, privacyManagerService_->IsAllowedUsingPermission(tokenId, CAMERA_PERMISSION_NAME, -1));
#ifdef CAMERA_FLOAT_WINDOW_ENABLE
    // not pip
    PermissionRecordManager::GetInstance().NotifyCameraWindowChange(false, tokenId, false);
    ASSERT_EQ(false, privacyManagerService_->IsAllowedUsingPermission(tokenId, CAMERA_PERMISSION_NAME, -1));

    PermissionRecordManager::GetInstance().NotifyCameraWindowChange(false, tokenId, false);
    // pip
    PermissionRecordManager::GetInstance().NotifyCameraWindowChange(true, tokenId, false);
    ASSERT_EQ(false, privacyManagerService_->IsAllowedUsingPermission(tokenId, CAMERA_PERMISSION_NAME, -1));
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
    ASSERT_EQ(false, privacyManagerService_->IsAllowedUsingPermission(0, CAMERA_PERMISSION_NAME, -1));

    // native tokenId
    ASSERT_EQ(false, privacyManagerService_->IsAllowedUsingPermission(tokenId, CAMERA_PERMISSION_NAME, -1));

    // invalid permission
    AccessTokenIDEx tokenIdEx = PrivacyTestCommon::GetHapTokenIdFromBundle(
        g_InfoParms1.userID, g_InfoParms1.bundleName, g_InfoParms1.instIndex);
    tokenId = tokenIdEx.tokenIdExStruct.tokenID;
    ASSERT_NE(INVALID_TOKENID, tokenId);
    ASSERT_EQ(false, privacyManagerService_->IsAllowedUsingPermission(tokenId, "test", -1));
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
    ASSERT_EQ(false, privacyManagerService_->IsAllowedUsingPermission(tokenId, CAMERA_PERMISSION_NAME, -1));
}

class TestPrivacyManagerStub : public PrivacyManagerStub {
public:
    TestPrivacyManagerStub() = default;
    virtual ~TestPrivacyManagerStub() = default;

    int32_t AddPermissionUsedRecord(const AddPermParamInfoParcel& infoParcel, bool asyncMode = false)
    {
        return RET_SUCCESS;
    }
    int32_t SetPermissionUsedRecordToggleStatus(int32_t userID, bool status)
    {
        return RET_SUCCESS;
    }
    int32_t GetPermissionUsedRecordToggleStatus(int32_t userID, bool& status)
    {
        return RET_SUCCESS;
    }
    int32_t StartUsingPermission(const PermissionUsedTypeInfoParcel& info, const sptr<IRemoteObject>& anonyStub)
    {
        return RET_SUCCESS;
    }
    int32_t StartUsingPermission(const PermissionUsedTypeInfoParcel& info,
        const sptr<IRemoteObject>& callback, const sptr<IRemoteObject>& anonyStub)
    {
        return RET_SUCCESS;
    }
    int32_t StopUsingPermission(AccessTokenID tokenID, int32_t pid,  const std::string& permissionName)
    {
        return RET_SUCCESS;
    }
    int32_t RemovePermissionUsedRecords(AccessTokenID tokenID)
    {
        return RET_SUCCESS;
    }
    int32_t GetPermissionUsedRecords(
        const PermissionUsedRequestParcel& request, PermissionUsedResultParcel& result)
    {
        return RET_SUCCESS;
    }
    int32_t GetPermissionUsedRecords(
        const PermissionUsedRequestParcel& request, const sptr<OnPermissionUsedRecordCallback>& callback)
    {
        return RET_SUCCESS;
    }
    int32_t RegisterPermActiveStatusCallback(
        std::vector<std::string>& permList, const sptr<IRemoteObject>& callback)
    {
        return RET_SUCCESS;
    }
    int32_t UnRegisterPermActiveStatusCallback(const sptr<IRemoteObject>& callback)
    {
        return RET_SUCCESS;
    }
    bool IsAllowedUsingPermission(AccessTokenID tokenID, const std::string& permissionName, int32_t pid)
    {
        return true;
    }
    int32_t GetPermissionUsedTypeInfos(const AccessTokenID tokenId, const std::string& permissionName,
        std::vector<PermissionUsedTypeInfoParcel>& resultsParcel)
    {
        return RET_SUCCESS;
    }
    int32_t SetMutePolicy(uint32_t policyType, uint32_t callerType, bool isMute, uint32_t tokenID)
    {
        return RET_SUCCESS;
    }
    int32_t SetHapWithFGReminder(uint32_t tokenId, bool isAllowed)
    {
        return RET_SUCCESS;
    }
#ifdef SECURITY_COMPONENT_ENHANCE_ENABLE
    int32_t RegisterSecCompEnhance(const SecCompEnhanceDataParcel& enhanceParcel)
    {
        return RET_SUCCESS;
    }
    int32_t DepositSecCompEnhance(const std::vector<SecCompEnhanceDataParcel>& enhanceParcelList)
    {
        return RET_SUCCESS;
    }
    int32_t RecoverSecCompEnhance(std::vector<SecCompEnhanceDataParcel>& enhanceParcelList)
    {
        return RET_SUCCESS;
    }
#endif
};

/**
 * @tc.name: OnRemoteRequest001
 * @tc.desc: OnRemoteRequest test.
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(PrivacyManagerServiceTest, OnRemoteRequest001, TestSize.Level1)
{
    TestPrivacyManagerStub testSub;
    MessageParcel data;
    std::string descriptor = "I don't know";
    data.WriteInterfaceToken(OHOS::Str8ToStr16(descriptor));

    MessageParcel reply;
    MessageOption option(MessageOption::TF_SYNC);
    // descriptor error
    ASSERT_EQ(PrivacyError::ERROR_IPC_REQUEST_FAIL, testSub.OnRemoteRequest(
        static_cast<uint32_t>(PrivacyInterfaceCode::ADD_PERMISSION_USED_RECORD), data, reply, option));

    uint32_t code = 99999999; // code not exsit
    ASSERT_EQ(true, data.WriteInterfaceToken(IPrivacyManager::GetDescriptor()));
    ASSERT_NE(RET_SUCCESS, testSub.OnRemoteRequest(code, data, reply, option)); // descriptor true + error msgCode
}

/**
 * @tc.name: AddPermissionUsedRecordInner001
 * @tc.desc: AddPermissionUsedRecordInner test.
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(PrivacyManagerServiceTest, AddPermissionUsedRecordInner001, TestSize.Level1)
{
    AccessTokenID tokenID = 123; // 123 is random input
    std::string permissionName = "ohos.permission.test";
    int32_t successCount = 1; // number 1
    int32_t failCount = 1; // number 1

    TestPrivacyManagerStub testSub;
    MessageParcel data;
    MessageParcel reply;
    MessageOption option(MessageOption::TF_SYNC);

    ASSERT_EQ(true, data.WriteInterfaceToken(IPrivacyManager::GetDescriptor()));
    AddPermParamInfoParcel infoParcel;
    infoParcel.info.tokenId = tokenID;
    infoParcel.info.permissionName = permissionName;
    infoParcel.info.successCount = successCount;
    infoParcel.info.failCount = failCount;
    ASSERT_EQ(true, data.WriteParcelable(&infoParcel));
    ASSERT_EQ(RET_SUCCESS, testSub.OnRemoteRequest(
        static_cast<uint32_t>(PrivacyInterfaceCode::ADD_PERMISSION_USED_RECORD), data, reply, option));
    // callingTokenID is native token hdcd with need permission, but input tokenID is not a real hap
    ASSERT_EQ(RET_SUCCESS, reply.ReadInt32());
}

/**
 * @tc.name: AddPermissionUsedRecordInner002
 * @tc.desc: AddPermissionUsedRecordInner test.
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(PrivacyManagerServiceTest, AddPermissionUsedRecordInner002, TestSize.Level1)
{
    AccessTokenID tokenID = 123; // 123 is random input
    std::string permissionName = "ohos.permission.test";
    int32_t successCount = 1; // number 1
    int32_t failCount = 1; // number 1

    TestPrivacyManagerStub testSub;
    MessageParcel data;
    MessageParcel reply;
    MessageOption option(MessageOption::TF_SYNC);

    std::vector<std::string> reqPerm;
    MockHapToken mock("AddPermissionUsedRecordInner002", reqPerm, false); // set self tokenID to normal app

    ASSERT_EQ(true, data.WriteInterfaceToken(IPrivacyManager::GetDescriptor()));
    AddPermParamInfoParcel infoParcel;
    infoParcel.info.tokenId = tokenID;
    infoParcel.info.permissionName = permissionName;
    infoParcel.info.successCount = successCount;
    infoParcel.info.failCount = failCount;
    ASSERT_EQ(true, data.WriteParcelable(&infoParcel));
    ASSERT_EQ(RET_SUCCESS, testSub.OnRemoteRequest(
        static_cast<uint32_t>(PrivacyInterfaceCode::ADD_PERMISSION_USED_RECORD), data, reply, option));
    // callingTokenID is normal hap without need permission
    ASSERT_EQ(PrivacyError::ERR_NOT_SYSTEM_APP, reply.ReadInt32());
}

/**
 * @tc.name: AddPermissionUsedRecordInner003
 * @tc.desc: AddPermissionUsedRecordInner test.
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(PrivacyManagerServiceTest, AddPermissionUsedRecordInner003, TestSize.Level1)
{
    AccessTokenID tokenID = 123; // 123 is random input
    std::string permissionName = "ohos.permission.test";
    int32_t successCount = 1; // number 1
    int32_t failCount = 1; // number 1

    TestPrivacyManagerStub testSub;
    MessageParcel data;
    MessageParcel reply;
    MessageOption option(MessageOption::TF_SYNC);

    std::vector<std::string> reqPerm;
    MockHapToken mock("AddPermissionUsedRecordInner003", reqPerm, true); // set self tokenID to system app

    ASSERT_EQ(true, data.WriteInterfaceToken(IPrivacyManager::GetDescriptor()));
    AddPermParamInfoParcel infoParcel;
    infoParcel.info.tokenId = tokenID;
    infoParcel.info.permissionName = permissionName;
    infoParcel.info.successCount = successCount;
    infoParcel.info.failCount = failCount;
    ASSERT_EQ(true, data.WriteParcelable(&infoParcel));
    ASSERT_EQ(RET_SUCCESS, testSub.OnRemoteRequest(
        static_cast<uint32_t>(PrivacyInterfaceCode::ADD_PERMISSION_USED_RECORD), data, reply, option));
    // callingTokenID is system hap without need permission
    ASSERT_EQ(PrivacyError::ERR_PERMISSION_DENIED, reply.ReadInt32());
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

    TestPrivacyManagerStub testStub;
    MessageParcel data;
    MessageParcel reply;
    MessageOption option(MessageOption::TF_SYNC);

    ASSERT_EQ(true, data.WriteInterfaceToken(IPrivacyManager::GetDescriptor()));
    ASSERT_EQ(true, data.WriteInt32(userID));
    ASSERT_EQ(true, data.WriteBool(status));
    ASSERT_EQ(RET_SUCCESS, testStub.OnRemoteRequest(
        static_cast<uint32_t>(PrivacyInterfaceCode::SET_PERMISSION_USED_RECORD_TOGGLE_STATUS), data, reply, option));
    ASSERT_EQ(RET_SUCCESS, reply.ReadInt32());
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

    TestPrivacyManagerStub testStub;
    MessageParcel data;
    MessageParcel reply;
    MessageOption option(MessageOption::TF_SYNC);

    std::vector<std::string> reqPerm;
    MockHapToken mock("SetPermissionUsedRecordToggleStatusInner002", reqPerm, false); // set self tokenID to normal app

    ASSERT_EQ(true, data.WriteInterfaceToken(IPrivacyManager::GetDescriptor()));
    ASSERT_EQ(true, data.WriteInt32(userID));
    ASSERT_EQ(true, data.WriteBool(status));
    ASSERT_EQ(RET_SUCCESS, testStub.OnRemoteRequest(
        static_cast<uint32_t>(PrivacyInterfaceCode::SET_PERMISSION_USED_RECORD_TOGGLE_STATUS), data, reply, option));
    ASSERT_EQ(PrivacyError::ERR_NOT_SYSTEM_APP, reply.ReadInt32());
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

    TestPrivacyManagerStub testStub;
    MessageParcel data;
    MessageParcel reply;
    MessageOption option(MessageOption::TF_SYNC);

    ASSERT_EQ(true, data.WriteInterfaceToken(IPrivacyManager::GetDescriptor()));
    ASSERT_EQ(true, data.WriteInt32(userID));
    ASSERT_EQ(true, data.WriteBool(status));
    ASSERT_EQ(RET_SUCCESS, testStub.OnRemoteRequest(
        static_cast<uint32_t>(PrivacyInterfaceCode::GET_PERMISSION_USED_RECORD_TOGGLE_STATUS), data, reply, option));
    ASSERT_EQ(RET_SUCCESS, reply.ReadInt32());
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

    TestPrivacyManagerStub testStub;
    MessageParcel data;
    MessageParcel reply;
    MessageOption option(MessageOption::TF_SYNC);

    std::vector<std::string> reqPerm;
    MockHapToken mock("GetPermissionUsedRecordToggleStatusInner002", reqPerm, false); // set self tokenID to normal app

    ASSERT_EQ(true, data.WriteInterfaceToken(IPrivacyManager::GetDescriptor()));
    ASSERT_EQ(true, data.WriteInt32(userID));
    ASSERT_EQ(true, data.WriteBool(status));
    ASSERT_EQ(RET_SUCCESS, testStub.OnRemoteRequest(
        static_cast<uint32_t>(PrivacyInterfaceCode::GET_PERMISSION_USED_RECORD_TOGGLE_STATUS), data, reply, option));
    ASSERT_EQ(PrivacyError::ERR_NOT_SYSTEM_APP, reply.ReadInt32());
}

/**
 * @tc.name: StartUsingPermissionInner001
 * @tc.desc: StartUsingPermissionInner test.
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(PrivacyManagerServiceTest, StartUsingPermissionInner001, TestSize.Level1)
{
    AccessTokenID tokenID = 123; // 123 is random input
    std::string permissionName = "ohos.permission.test";
    int32_t pid = 456; // 456 is random input
    auto anonystub = new (std::nothrow) ProxyDeathCallBackStub();

    TestPrivacyManagerStub testSub;
    MessageParcel data;
    MessageParcel reply;
    MessageOption option(MessageOption::TF_SYNC);

    ASSERT_EQ(true, data.WriteInterfaceToken(IPrivacyManager::GetDescriptor()));
    PermissionUsedTypeInfoParcel parcel;
    parcel.info.tokenId = tokenID;
    parcel.info.pid = pid;
    parcel.info.permissionName = permissionName;
    ASSERT_EQ(true, data.WriteParcelable(&parcel));
    ASSERT_EQ(true, data.WriteRemoteObject(anonystub->AsObject()));
    ASSERT_EQ(RET_SUCCESS, testSub.OnRemoteRequest(
        static_cast<uint32_t>(PrivacyInterfaceCode::START_USING_PERMISSION), data, reply, option));
    // callingTokenID is native token hdcd with need permission, but input tokenID is not a real hap
    ASSERT_EQ(RET_SUCCESS, reply.ReadInt32());
}

/**
 * @tc.name: StartUsingPermissionInner002
 * @tc.desc: StartUsingPermissionInner test.
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(PrivacyManagerServiceTest, StartUsingPermissionInner002, TestSize.Level1)
{
    AccessTokenID tokenID = 123; // 123 is random input
    std::string permissionName = "ohos.permission.test";

    TestPrivacyManagerStub testSub;
    MessageParcel data;
    MessageParcel reply;
    MessageOption option(MessageOption::TF_SYNC);

    std::vector<std::string> reqPerm;
    MockHapToken mock("StartUsingPermissionInner002", reqPerm, false); // set self tokenID to normal app

    ASSERT_EQ(true, data.WriteInterfaceToken(IPrivacyManager::GetDescriptor()));
    PermissionUsedTypeInfoParcel parcel;
    parcel.info.tokenId = tokenID;
    parcel.info.pid = -1;
    parcel.info.permissionName = permissionName;
    ASSERT_EQ(true, data.WriteParcelable(&parcel));
    ASSERT_EQ(RET_SUCCESS, testSub.OnRemoteRequest(
        static_cast<uint32_t>(PrivacyInterfaceCode::START_USING_PERMISSION), data, reply, option));
    // callingTokenID is normal hap without need permission
    ASSERT_EQ(PrivacyError::ERR_NOT_SYSTEM_APP, reply.ReadInt32());
}

/**
 * @tc.name: StartUsingPermissionInner003
 * @tc.desc: StartUsingPermissionInner test.
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(PrivacyManagerServiceTest, StartUsingPermissionInner003, TestSize.Level1)
{
    AccessTokenID tokenID = 123; // 123 is random input
    std::string permissionName = "ohos.permission.test";

    TestPrivacyManagerStub testSub;
    MessageParcel data;
    MessageParcel reply;
    MessageOption option(MessageOption::TF_SYNC);

    std::vector<std::string> reqPerm;
    MockHapToken mock("StartUsingPermissionInner003", reqPerm, true); // set self tokenID to system app

    ASSERT_EQ(true, data.WriteInterfaceToken(IPrivacyManager::GetDescriptor()));
    PermissionUsedTypeInfoParcel parcel;
    parcel.info.tokenId = tokenID;
    parcel.info.pid = -1;
    parcel.info.permissionName = permissionName;
    ASSERT_EQ(true, data.WriteParcelable(&parcel));
    ASSERT_EQ(RET_SUCCESS, testSub.OnRemoteRequest(
        static_cast<uint32_t>(PrivacyInterfaceCode::START_USING_PERMISSION), data, reply, option));
    // callingTokenID is system hap without need permission
    ASSERT_EQ(PrivacyError::ERR_PERMISSION_DENIED, reply.ReadInt32());
}

class PrivacyManagerServiceTestCb1 : public StateCustomizedCbk {
public:
    PrivacyManagerServiceTestCb1()
    {}

    ~PrivacyManagerServiceTestCb1()
    {}

    virtual void StateChangeNotify(AccessTokenID tokenId, bool isShow)
    {}
};

/**
 * @tc.name: StartUsingPermissionCallbackInner001
 * @tc.desc: StartUsingPermissionCallbackInner test.
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(PrivacyManagerServiceTest, StartUsingPermissionCallbackInner001, TestSize.Level1)
{
    AccessTokenID tokenID = 123; // 123 is random input
    int32_t pid = 111;
    std::string permissionName = "ohos.permission.test";
    auto callbackPtr = std::make_shared<PrivacyManagerServiceTestCb1>();
    ASSERT_NE(nullptr, callbackPtr);
    auto callbackWrap = new (std::nothrow) StateChangeCallback(callbackPtr);
    ASSERT_NE(nullptr, callbackWrap);

    TestPrivacyManagerStub testSub;
    MessageParcel data;
    MessageParcel reply;
    MessageOption option(MessageOption::TF_SYNC);

    std::vector<std::string> reqPerm;
    MockHapToken mock("StartUsingPermissionCallbackInner001", reqPerm, true); // set self tokenID to system app

    ASSERT_EQ(true, data.WriteInterfaceToken(IPrivacyManager::GetDescriptor()));
    PermissionUsedTypeInfoParcel parcel;
    parcel.info.tokenId = tokenID;
    parcel.info.pid = pid;
    parcel.info.permissionName = permissionName;
    ASSERT_EQ(true, data.WriteParcelable(&parcel));
    ASSERT_EQ(true, data.WriteRemoteObject(callbackWrap->AsObject()));
    ASSERT_EQ(RET_SUCCESS, testSub.OnRemoteRequest(static_cast<uint32_t>(
        PrivacyInterfaceCode::START_USING_PERMISSION_CALLBACK), data, reply, option));
    // callingTokenID has no request permission
    ASSERT_EQ(PrivacyError::ERR_PERMISSION_DENIED, reply.ReadInt32());
}

/**
 * @tc.name: StartUsingPermissionCallbackInner002
 * @tc.desc: StartUsingPermissionCallbackInner test.
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(PrivacyManagerServiceTest, StartUsingPermissionCallbackInner002, TestSize.Level1)
{
    AccessTokenID tokenID = 123; // 123 is random input
    int32_t pid = 11;
    std::string permissionName = "ohos.permission.test";
    auto callbackPtr = std::make_shared<PrivacyManagerServiceTestCb1>();
    ASSERT_NE(nullptr, callbackPtr);
    auto callbackWrap = new (std::nothrow) StateChangeCallback(callbackPtr);
    ASSERT_NE(nullptr, callbackWrap);
    auto anonystub = new (std::nothrow) ProxyDeathCallBackStub();

    TestPrivacyManagerStub testSub;
    MessageParcel data;
    MessageParcel reply;
    MessageOption option(MessageOption::TF_SYNC);

    ASSERT_EQ(true, data.WriteInterfaceToken(IPrivacyManager::GetDescriptor()));
    PermissionUsedTypeInfoParcel parcel;
    parcel.info.tokenId = tokenID;
    parcel.info.pid = pid;
    parcel.info.permissionName = permissionName;
    ASSERT_EQ(true, data.WriteParcelable(&parcel));
    ASSERT_EQ(true, data.WriteRemoteObject(callbackWrap->AsObject()));
    ASSERT_EQ(true, data.WriteRemoteObject(anonystub->AsObject()));
    ASSERT_EQ(RET_SUCCESS, testSub.OnRemoteRequest(static_cast<uint32_t>(
        PrivacyInterfaceCode::START_USING_PERMISSION_CALLBACK), data, reply, option));
    // callingTokenID is native token hdcd with request permission
    ASSERT_EQ(RET_SUCCESS, reply.ReadInt32());
}

/**
 * @tc.name: StopUsingPermissionInner001
 * @tc.desc: StopUsingPermissionInner test.
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(PrivacyManagerServiceTest, StopUsingPermissionInner001, TestSize.Level1)
{
    AccessTokenID tokenID = 123; // 123 is random input
    int32_t pid = 11;
    std::string permissionName = "ohos.permission.test";

    TestPrivacyManagerStub testSub;
    MessageParcel data;
    MessageParcel reply;
    MessageOption option(MessageOption::TF_SYNC);

    ASSERT_EQ(true, data.WriteInterfaceToken(IPrivacyManager::GetDescriptor()));
    ASSERT_EQ(true, data.WriteUint32(tokenID));
    ASSERT_EQ(true, data.WriteInt32(pid));
    ASSERT_EQ(true, data.WriteString(permissionName));
    ASSERT_EQ(RET_SUCCESS, testSub.OnRemoteRequest(
        static_cast<uint32_t>(PrivacyInterfaceCode::STOP_USING_PERMISSION), data, reply, option));
    // callingTokenID is native token hdcd with need permission, but input tokenID is not a real hap
    ASSERT_EQ(RET_SUCCESS, reply.ReadInt32());
}

/**
 * @tc.name: StopUsingPermissionInner002
 * @tc.desc: StopUsingPermissionInner test.
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(PrivacyManagerServiceTest, StopUsingPermissionInner002, TestSize.Level1)
{
    AccessTokenID tokenID = 123; // 123 is random input
    std::string permissionName = "ohos.permission.test";

    TestPrivacyManagerStub testSub;
    MessageParcel data;
    MessageParcel reply;
    MessageOption option(MessageOption::TF_SYNC);

    std::vector<std::string> reqPerm;
    MockHapToken mock("StopUsingPermissionInner002", reqPerm, false); // set self tokenID to normal app

    ASSERT_EQ(true, data.WriteInterfaceToken(IPrivacyManager::GetDescriptor()));
    ASSERT_EQ(true, data.WriteUint32(tokenID));
    ASSERT_EQ(true, data.WriteString(permissionName));
    ASSERT_EQ(RET_SUCCESS, testSub.OnRemoteRequest(
        static_cast<uint32_t>(PrivacyInterfaceCode::STOP_USING_PERMISSION), data, reply, option));
    // callingTokenID is normal hap without need permission
    ASSERT_EQ(PrivacyError::ERR_NOT_SYSTEM_APP, reply.ReadInt32());
}

/**
 * @tc.name: StopUsingPermissionInner003
 * @tc.desc: StopUsingPermissionInner test.
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(PrivacyManagerServiceTest, StopUsingPermissionInner003, TestSize.Level1)
{
    AccessTokenID tokenID = 123; // 123 is random input
    std::string permissionName = "ohos.permission.test";

    TestPrivacyManagerStub testSub;
    MessageParcel data;
    MessageParcel reply;
    MessageOption option(MessageOption::TF_SYNC);

    std::vector<std::string> reqPerm;
    MockHapToken mock("StopUsingPermissionInner003", reqPerm, true); // set self tokenID to system app

    ASSERT_EQ(true, data.WriteInterfaceToken(IPrivacyManager::GetDescriptor()));
    ASSERT_EQ(true, data.WriteUint32(tokenID));
    ASSERT_EQ(true, data.WriteString(permissionName));
    ASSERT_EQ(RET_SUCCESS, testSub.OnRemoteRequest(
        static_cast<uint32_t>(PrivacyInterfaceCode::STOP_USING_PERMISSION), data, reply, option));
    // callingTokenID is system hap without need permission
    ASSERT_EQ(PrivacyError::ERR_PERMISSION_DENIED, reply.ReadInt32());
}

/**
 * @tc.name: RemovePermissionUsedRecordsInner001
 * @tc.desc: RemovePermissionUsedRecordsInner test.
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(PrivacyManagerServiceTest, RemovePermissionUsedRecordsInner001, TestSize.Level1)
{
    AccessTokenID tokenID = 123; // 123 is random input

    TestPrivacyManagerStub testSub;
    MessageParcel data;
    MessageParcel reply;
    MessageOption option(MessageOption::TF_SYNC);

    ASSERT_EQ(true, data.WriteInterfaceToken(IPrivacyManager::GetDescriptor()));
    ASSERT_EQ(true, data.WriteUint32(tokenID));
    ASSERT_EQ(RET_SUCCESS, testSub.OnRemoteRequest(static_cast<uint32_t>(
        PrivacyInterfaceCode::DELETE_PERMISSION_USED_RECORDS), data, reply, option));
    // callingTokenID is native token hdcd with need permission, but input tokenID is not a real hap
    ASSERT_EQ(RET_SUCCESS, reply.ReadInt32());
}

/**
 * @tc.name: RemovePermissionUsedRecordsInner002
 * @tc.desc: RemovePermissionUsedRecordsInner test.
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(PrivacyManagerServiceTest, RemovePermissionUsedRecordsInner002, TestSize.Level1)
{
    AccessTokenID tokenID = 123; // 123 is random input

    TestPrivacyManagerStub testSub;
    MessageParcel data;
    MessageParcel reply;
    MessageOption option(MessageOption::TF_SYNC);

    MockNativeToken mock("device_manager"); // set self tokenID to native device_manager
    AccessTokenID nativeTokenID = GetSelfTokenID();
    ASSERT_NE(nativeTokenID, static_cast<AccessTokenID>(0));

    ASSERT_EQ(true, data.WriteInterfaceToken(IPrivacyManager::GetDescriptor()));
    ASSERT_EQ(true, data.WriteUint32(tokenID));
    ASSERT_EQ(RET_SUCCESS, testSub.OnRemoteRequest(static_cast<uint32_t>(
        PrivacyInterfaceCode::DELETE_PERMISSION_USED_RECORDS), data, reply, option));
    // native token device_manager don't have request permission
    ASSERT_EQ(PrivacyError::ERR_PERMISSION_DENIED, reply.ReadInt32());
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

    TestPrivacyManagerStub testSub;
    MessageParcel data;
    MessageParcel reply;
    MessageOption option(MessageOption::TF_SYNC);

    ASSERT_EQ(true, data.WriteInterfaceToken(IPrivacyManager::GetDescriptor()));
    ASSERT_EQ(true, data.WriteParcelable(&request));
    ASSERT_EQ(RET_SUCCESS, testSub.OnRemoteRequest(static_cast<uint32_t>(
        PrivacyInterfaceCode::GET_PERMISSION_USED_RECORDS), data, reply, option));
    // callingTokenID is native token hdcd with need permission, remote is true return ERR_PARAM_INVALID
    ASSERT_EQ(RET_SUCCESS, reply.ReadInt32());
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

    TestPrivacyManagerStub testSub;
    MessageParcel data;
    MessageParcel reply;
    MessageOption option(MessageOption::TF_SYNC);

    std::vector<std::string> reqPerm;
    MockHapToken mock("GetPermissionUsedRecordsInner002", reqPerm, false); // set self tokenID to normal app

    ASSERT_EQ(true, data.WriteInterfaceToken(IPrivacyManager::GetDescriptor()));
    ASSERT_EQ(true, data.WriteParcelable(&request));
    ASSERT_EQ(RET_SUCCESS, testSub.OnRemoteRequest(static_cast<uint32_t>(
        PrivacyInterfaceCode::GET_PERMISSION_USED_RECORDS), data, reply, option));
    // callingTokenID is normal hap without need permission
    ASSERT_EQ(PrivacyError::ERR_NOT_SYSTEM_APP, reply.ReadInt32());
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

    TestPrivacyManagerStub testSub;
    MessageParcel data;
    MessageParcel reply;
    MessageOption option(MessageOption::TF_SYNC);

    std::vector<std::string> reqPerm;
    MockHapToken mock("GetPermissionUsedRecordsInner003", reqPerm, true); // set self tokenID to system app

    ASSERT_EQ(true, data.WriteInterfaceToken(IPrivacyManager::GetDescriptor()));
    ASSERT_EQ(true, data.WriteParcelable(&request));
    ASSERT_EQ(RET_SUCCESS, testSub.OnRemoteRequest(static_cast<uint32_t>(
        PrivacyInterfaceCode::GET_PERMISSION_USED_RECORDS), data, reply, option));
    // callingTokenID is system hap without need permission
    ASSERT_EQ(PrivacyError::ERR_PERMISSION_DENIED, reply.ReadInt32());
}

class TestCallBack : public OnPermissionUsedRecordCallbackStub {
public:
    TestCallBack() = default;
    virtual ~TestCallBack() = default;

    void OnQueried(ErrCode code, PermissionUsedResult& result)
    {
        GTEST_LOG_(INFO) << "TestCallBack, code :" << code << ", bundleSize :" << result.bundleRecords.size();
    }
};

/**
 * @tc.name: RegisterPermActiveStatusCallbackInner001
 * @tc.desc: RegisterPermActiveStatusCallbackInner test.
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(PrivacyManagerServiceTest, RegisterPermActiveStatusCallbackInner001, TestSize.Level1)
{
    std::vector<std::string> permList = {};

    TestPrivacyManagerStub testSub;
    MessageParcel data;
    MessageParcel reply;
    MessageOption option(MessageOption::TF_SYNC);

    ASSERT_EQ(true, data.WriteInterfaceToken(IPrivacyManager::GetDescriptor()));
    ASSERT_EQ(true, data.WriteUint32(permList.size()));
    ASSERT_EQ(RET_SUCCESS, testSub.OnRemoteRequest(static_cast<uint32_t>(
        PrivacyInterfaceCode::REGISTER_PERM_ACTIVE_STATUS_CHANGE_CALLBACK), data, reply, option));
    // callingTokenID is native token hdcd with need permission
    ASSERT_EQ(PrivacyError::ERR_READ_PARCEL_FAILED, reply.ReadInt32());
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
    TestPrivacyManagerStub testSub;
    MessageParcel data;
    MessageParcel reply;
    MessageOption option(MessageOption::TF_SYNC);

    std::vector<std::string> reqPerm;
    MockHapToken mock("RegisterPermActiveStatusCallbackInner002", reqPerm, false); // set self tokenID to normal app

    ASSERT_EQ(true, data.WriteInterfaceToken(IPrivacyManager::GetDescriptor()));
    ASSERT_EQ(true, data.WriteUint32(permList.size()));
    ASSERT_EQ(RET_SUCCESS, testSub.OnRemoteRequest(static_cast<uint32_t>(
        PrivacyInterfaceCode::REGISTER_PERM_ACTIVE_STATUS_CHANGE_CALLBACK), data, reply, option));
    // callingTokenID is normal hap without need permission
    ASSERT_EQ(PrivacyError::ERR_NOT_SYSTEM_APP, reply.ReadInt32());
}

/**
 * @tc.name: RegisterPermActiveStatusCallbackInner003
 * @tc.desc: RegisterPermActiveStatusCallbackInner test.
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(PrivacyManagerServiceTest, RegisterPermActiveStatusCallbackInner003, TestSize.Level1)
{
    TestPrivacyManagerStub testSub;
    MessageParcel data;
    MessageParcel reply;
    MessageOption option(MessageOption::TF_SYNC);

    std::vector<std::string> reqPerm;
    MockHapToken mock("RegisterPermActiveStatusCallbackInner003", reqPerm, true); // set self tokenID to system app

    ASSERT_EQ(true, data.WriteInterfaceToken(IPrivacyManager::GetDescriptor()));
    ASSERT_EQ(true, data.WriteUint32(0));
    ASSERT_EQ(RET_SUCCESS, testSub.OnRemoteRequest(static_cast<uint32_t>(
        PrivacyInterfaceCode::REGISTER_PERM_ACTIVE_STATUS_CHANGE_CALLBACK), data, reply, option));
    // callingTokenID is system hap without need permission
    ASSERT_EQ(PrivacyError::ERR_PERMISSION_DENIED, reply.ReadInt32());
}

/**
 * @tc.name: UnRegisterPermActiveStatusCallbackInner001
 * @tc.desc: UnRegisterPermActiveStatusCallbackInner test.
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(PrivacyManagerServiceTest, UnRegisterPermActiveStatusCallbackInner001, TestSize.Level1)
{
    TestPrivacyManagerStub testSub;
    MessageParcel data;
    MessageParcel reply;
    MessageOption option(MessageOption::TF_SYNC);
    ASSERT_EQ(true, data.WriteInterfaceToken(IPrivacyManager::GetDescriptor()));
    ASSERT_EQ(RET_SUCCESS, testSub.OnRemoteRequest(static_cast<uint32_t>(
        PrivacyInterfaceCode::UNREGISTER_PERM_ACTIVE_STATUS_CHANGE_CALLBACK), data, reply, option));
    // callingTokenID is native token hdcd with need permission
    ASSERT_EQ(PrivacyError::ERR_READ_PARCEL_FAILED, reply.ReadInt32());
}

/**
 * @tc.name: UnRegisterPermActiveStatusCallbackInner002
 * @tc.desc: UnRegisterPermActiveStatusCallbackInner test.
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(PrivacyManagerServiceTest, UnRegisterPermActiveStatusCallbackInner002, TestSize.Level1)
{
    TestPrivacyManagerStub testSub;
    MessageParcel data;
    MessageParcel reply;
    MessageOption option(MessageOption::TF_SYNC);

    std::vector<std::string> reqPerm;
    MockHapToken mock("UnRegisterPermActiveStatusCallbackInner002", reqPerm, false); // set self tokenID to normal app

    ASSERT_EQ(true, data.WriteInterfaceToken(IPrivacyManager::GetDescriptor()));
    ASSERT_EQ(RET_SUCCESS, testSub.OnRemoteRequest(static_cast<uint32_t>(
        PrivacyInterfaceCode::UNREGISTER_PERM_ACTIVE_STATUS_CHANGE_CALLBACK), data, reply, option));
    // callingTokenID is normal hap without need permission
    ASSERT_EQ(PrivacyError::ERR_NOT_SYSTEM_APP, reply.ReadInt32());
}

/**
 * @tc.name: UnRegisterPermActiveStatusCallbackInner003
 * @tc.desc: UnRegisterPermActiveStatusCallbackInner test.
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(PrivacyManagerServiceTest, UnRegisterPermActiveStatusCallbackInner003, TestSize.Level1)
{
    TestPrivacyManagerStub testSub;
    MessageParcel data;
    MessageParcel reply;
    MessageOption option(MessageOption::TF_SYNC);

    std::vector<std::string> reqPerm;
    MockHapToken mock("UnRegisterPermActiveStatusCallbackInner003", reqPerm, true); // set self tokenID to system app

    ASSERT_EQ(true, data.WriteInterfaceToken(IPrivacyManager::GetDescriptor()));
    ASSERT_EQ(RET_SUCCESS, testSub.OnRemoteRequest(static_cast<uint32_t>(
        PrivacyInterfaceCode::UNREGISTER_PERM_ACTIVE_STATUS_CHANGE_CALLBACK), data, reply, option));
    // callingTokenID is system hap without need permission
    ASSERT_EQ(PrivacyError::ERR_PERMISSION_DENIED, reply.ReadInt32());
}

/**
 * @tc.name: IsAllowedUsingPermissionInner001
 * @tc.desc: IsAllowedUsingPermissionInner test.
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(PrivacyManagerServiceTest, IsAllowedUsingPermissionInner001, TestSize.Level1)
{
    AccessTokenID tokenID = 123; // 123 is random input
    std::string permissionName = "ohos.permission.test";

    TestPrivacyManagerStub testSub;
    MessageParcel data;
    MessageParcel reply;
    MessageOption option(MessageOption::TF_SYNC);

    ASSERT_EQ(true, data.WriteInterfaceToken(IPrivacyManager::GetDescriptor()));
    ASSERT_EQ(true, data.WriteUint32(tokenID));
    ASSERT_EQ(true, data.WriteString(permissionName));
    ASSERT_EQ(RET_SUCCESS, testSub.OnRemoteRequest(static_cast<uint32_t>(
        PrivacyInterfaceCode::IS_ALLOWED_USING_PERMISSION), data, reply, option));
    // callingTokenID is native token hdcd with need permission, remote is true return ERR_PARAM_INVALID
    ASSERT_EQ(true, reply.ReadBool());
}

/**
 * @tc.name: IsAllowedUsingPermissionInner002
 * @tc.desc: IsAllowedUsingPermissionInner test.
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(PrivacyManagerServiceTest, IsAllowedUsingPermissionInner002, TestSize.Level1)
{
    AccessTokenID tokenID = 123; // 123 is random input
    std::string permissionName = "ohos.permission.test";

    TestPrivacyManagerStub testSub;
    MessageParcel data;
    MessageParcel reply;
    MessageOption option(MessageOption::TF_SYNC);

    std::vector<std::string> reqPerm;
    MockHapToken mock("IsAllowedUsingPermissionInner002", reqPerm, false); // set self tokenID to normal app

    ASSERT_EQ(true, data.WriteInterfaceToken(IPrivacyManager::GetDescriptor()));
    ASSERT_EQ(true, data.WriteUint32(tokenID));
    ASSERT_EQ(true, data.WriteString(permissionName));
    ASSERT_EQ(RET_SUCCESS, testSub.OnRemoteRequest(static_cast<uint32_t>(
        PrivacyInterfaceCode::IS_ALLOWED_USING_PERMISSION), data, reply, option));
    // callingTokenID is normal hap without need permission
    ASSERT_EQ(false, reply.ReadBool());
}
} // namespace AccessToken
} // namespace Security
} // namespace OHOS
