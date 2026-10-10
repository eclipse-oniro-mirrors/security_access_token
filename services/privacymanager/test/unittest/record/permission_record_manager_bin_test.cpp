/*
 * Copyright (c) 2026 Huawei Device Co., Ltd.
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

#include <cerrno>
#include <chrono>
#include <cstdint>
#include <mutex>
#include <thread>

#include <gtest/gtest.h>

#include "access_token.h"
#include "accesstoken_kit.h"
#include "active_change_response_info.h"
#include "constant.h"
#define private public
#include "active_status_callback_manager.h"
#include "permission_record_manager.h"
#include "permission_used_record_db.h"
#undef private
#include "permission_used_request.h"
#include "permission_used_result.h"
#include "perm_active_status_change_callback_stub.h"
#include "privacy_error.h"
#include "privacy_test_common.h"
#include "token_setproc.h"
#include "fake_parent_hap_tokenid.h"

using namespace testing;
using namespace testing::ext;
using namespace OHOS;

namespace OHOS {
namespace Security {
namespace AccessToken {
namespace {
static constexpr int32_t BIN_PID = 558;
static constexpr int32_t BIN_PID_A = 100;
static constexpr int32_t BIN_PID_B = 200;
static constexpr int32_t PARENT_HAP_PID = 999;
static constexpr int32_t INVALID_BIN_PID = -1;
static constexpr int32_t CALLER_PID = 11;
static constexpr int32_t SLEEP_TIME_MILLISECONDS = 200;
static constexpr int32_t EIO_ERR = EIO;
static constexpr uint64_t FULL_TOKEN_HIGH_BIT = (1ULL << 32);
static constexpr const char* CONTACTS_PERMISSION_NAME = "ohos.permission.READ_CONTACTS";

static HapInfoParams g_binInfoParms = {
    .userID = 1,
    .bundleName = "ohos.privacy_test.binbundle",
    .instIndex = 0,
    .appIDDesc = "privacy_test.binbundle"
};

static HapPolicyParams g_binPolicyPrams = {
    .apl = APL_NORMAL,
    .domain = "test.domain.bin",
    .permList = {},
    .permStateList = {}
};
}

class PermissionRecordManagerBinTest : public testing::Test {
public:
    static void SetUpTestCase()
    {
        PrivacyTestCommon::SetTestEvironment(GetSelfTokenID());
    }

    static void TearDownTestCase()
    {
        PrivacyTestCommon::ResetTestEvironment();
    }

    void SetUp();

    void TearDown();
};

void PermissionRecordManagerBinTest::SetUp()
{
    ResetFakeParentHapTokenIdState();
    PermissionRecordManager::GetInstance().Init();
    PermissionRecordManager::GetInstance().Register();
    AccessTokenIDEx tokenIdEx = PrivacyTestCommon::AllocTestHapToken(g_binInfoParms, g_binPolicyPrams);
    ASSERT_NE(tokenIdEx.tokenIdExStruct.tokenID, INVALID_TOKENID);
}

void PermissionRecordManagerBinTest::TearDown()
{
    AccessTokenIDEx tokenIdEx = PrivacyTestCommon::GetHapTokenIdFromBundle(
        g_binInfoParms.userID, g_binInfoParms.bundleName, g_binInfoParms.instIndex);
    PrivacyTestCommon::DeleteTestHapToken(tokenIdEx.tokenIdExStruct.tokenID);
    PermissionRecordManager::GetInstance().RemovePermissionUsedRecords(tokenIdEx.tokenIdExStruct.tokenID);
    ResetFakeParentHapTokenIdState();
}

namespace {
static AccessTokenID GetParentHapTokenId()
{
    return PrivacyTestCommon::GetHapTokenIdFromBundle(
        g_binInfoParms.userID, g_binInfoParms.bundleName, g_binInfoParms.instIndex).tokenIdExStruct.tokenID;
}

static AccessTokenID BuildBinTokenId(AccessTokenID hapTokenId)
{
    AccessTokenIDInner innerId = *reinterpret_cast<AccessTokenIDInner*>(&hapTokenId);
    innerId.type_ext = 1;
    return *reinterpret_cast<AccessTokenID*>(&innerId);
}

static AddPermParamInfo MakeBinAddInfo(AccessTokenID tokenId)
{
    AddPermParamInfo info = {
        .tokenId = tokenId,
        .permissionName = CONTACTS_PERMISSION_NAME,
        .successCount = 1
    };
    return info;
}

static PermissionUsedTypeInfo MakeBinStartInfo(AccessTokenID tokenId, int32_t pid,
    const std::string& permissionName = "ohos.permission.CAMERA")
{
    PermissionUsedTypeInfo info = {
        .tokenId = tokenId,
        .pid = pid,
        .permissionName = permissionName
    };
    return info;
}

static bool HasRecordInCache(AccessTokenID tokenId)
{
    auto& manager = PermissionRecordManager::GetInstance();
    std::lock_guard<std::mutex> lock(manager.permUsedRecMutex_);
    for (auto it = manager.permUsedRecList_.begin(); it != manager.permUsedRecList_.end(); ++it) {
        if (it->record.tokenId == tokenId) {
            return true;
        }
    }
    return false;
}

static bool HasRecordInStartList(AccessTokenID tokenId, int32_t pid)
{
    auto& manager = PermissionRecordManager::GetInstance();
    std::lock_guard<std::mutex> lock(manager.startRecordListMutex_);
    for (auto it = manager.startRecordList_.begin(); it != manager.startRecordList_.end(); ++it) {
        if ((it->tokenId == tokenId) && (it->pid == pid)) {
            return true;
        }
    }
    return false;
}

static int32_t GetRecordStatusInStartList(AccessTokenID tokenId, int32_t pid)
{
    auto& manager = PermissionRecordManager::GetInstance();
    std::lock_guard<std::mutex> lock(manager.startRecordListMutex_);
    for (auto it = manager.startRecordList_.begin(); it != manager.startRecordList_.end(); ++it) {
        if ((it->tokenId == tokenId) && (it->pid == pid)) {
            return it->status;
        }
    }
    return -1;
}
}

class BinPermActiveStatusChangeCallback : public PermActiveStatusChangeCallbackStub {
public:
    BinPermActiveStatusChangeCallback() = default;
    virtual ~BinPermActiveStatusChangeCallback() = default;

    bool AddDeathRecipient(const sptr<IRemoteObject::DeathRecipient>& deathRecipient) override
    {
        return true;
    }

    void ActiveStatusChangeCallback(ActiveChangeResponse& result) override
    {
        type_ = result.type;
        tokenId_ = result.tokenID;
        pid_ = result.pid;
    }

    ActiveChangeType type_ = PERM_INACTIVE;
    AccessTokenID tokenId_ = 0;
    int32_t pid_ = INVALID_BIN_PID;
};

static sptr<BinPermActiveStatusChangeCallback> RegisterBinActiveStatusCallback(
    const std::vector<std::string>& permList)
{
    sptr<BinPermActiveStatusChangeCallback> callback = new (std::nothrow) BinPermActiveStatusChangeCallback();
    EXPECT_NE(nullptr, callback);
    EXPECT_EQ(RET_SUCCESS, PermissionRecordManager::GetInstance().RegisterPermActiveStatusCallback(
        GetSelfTokenID(), permList, callback->AsObject(), static_cast<int32_t>(CallbackRegisterType::TOKEN_ONLY)));
    return callback;
}

static PermissionUsedResult QueryBinUsedRecords(AccessTokenID tokenId)
{
    PermissionUsedRequest request = {.tokenId = tokenId, .flag = FLAG_PERMISSION_USAGE_DETAIL};
    PermissionUsedResult result;
    EXPECT_EQ(RET_SUCCESS, PermissionRecordManager::GetInstance().GetPermissionUsedRecords(request, result));
    return result;
}

/**
 * @tc.name: BinAddRecordNormalized001
 * @tc.desc: BIN token add permission used record normalized to parent hap token.
 * @tc.type: FUNC
 * @tc.require: 20260805885509
 */
HWTEST_F(PermissionRecordManagerBinTest, BinAddRecordNormalized001, TestSize.Level0)
{
    MockNativeToken mock("audio_server");
    AccessTokenID parentTokenId = GetParentHapTokenId();
    ASSERT_NE(INVALID_TOKENID, parentTokenId);
    AccessTokenID binTokenId = BuildBinTokenId(parentTokenId);

    auto& state = GetFakeParentHapTokenIdState();
    state.ret = ACCESS_TOKEN_OK;
    state.parentHapTokenID = static_cast<uint64_t>(parentTokenId);

    ASSERT_EQ(RET_SUCCESS, PermissionRecordManager::GetInstance().AddPermissionUsedRecord(
        MakeBinAddInfo(binTokenId)));
    ASSERT_EQ(1, state.callCount);
    ASSERT_EQ(binTokenId, state.lastBinTokenID);
    ASSERT_TRUE(HasRecordInCache(parentTokenId));
    ASSERT_FALSE(HasRecordInCache(binTokenId));
}

/**
 * @tc.name: BinAddRecordBitTruncate001
 * @tc.desc: Parent full token with high bits is truncated to low 32 bits.
 * @tc.type: FUNC
 * @tc.require: 20260805885509
 */
HWTEST_F(PermissionRecordManagerBinTest, BinAddRecordBitTruncate001, TestSize.Level0)
{
    MockNativeToken mock("audio_server");
    AccessTokenID parentTokenId = GetParentHapTokenId();
    ASSERT_NE(INVALID_TOKENID, parentTokenId);
    AccessTokenID binTokenId = BuildBinTokenId(parentTokenId);

    auto& state = GetFakeParentHapTokenIdState();
    state.ret = ACCESS_TOKEN_OK;
    state.parentHapTokenID = static_cast<uint64_t>(parentTokenId) | FULL_TOKEN_HIGH_BIT;

    ASSERT_EQ(RET_SUCCESS, PermissionRecordManager::GetInstance().AddPermissionUsedRecord(
        MakeBinAddInfo(binTokenId)));
    ASSERT_TRUE(HasRecordInCache(parentTokenId));
}

/**
 * @tc.name: BinStartRecordPayload001
 * @tc.desc: BIN start using permission, callback payload carries parent token and bin pid.
 * @tc.type: FUNC
 * @tc.require: 20260805885509
 */
HWTEST_F(PermissionRecordManagerBinTest, BinStartRecordPayload001, TestSize.Level0)
{
    MockNativeToken mock("audio_server");
    AccessTokenID parentTokenId = GetParentHapTokenId();
    ASSERT_NE(INVALID_TOKENID, parentTokenId);
    AccessTokenID binTokenId = BuildBinTokenId(parentTokenId);

    auto& state = GetFakeParentHapTokenIdState();
    state.ret = ACCESS_TOKEN_OK;
    state.parentHapTokenID = static_cast<uint64_t>(parentTokenId);

    sptr<BinPermActiveStatusChangeCallback> callback = RegisterBinActiveStatusCallback({"ohos.permission.CAMERA"});
    ASSERT_NE(nullptr, callback);
    ASSERT_EQ(RET_SUCCESS, PermissionRecordManager::GetInstance().StartUsingPermission(
        MakeBinStartInfo(binTokenId, BIN_PID), CALLER_PID));
    std::this_thread::sleep_for(std::chrono::milliseconds(SLEEP_TIME_MILLISECONDS));
    EXPECT_EQ(parentTokenId, callback->tokenId_);
    EXPECT_EQ(BIN_PID, callback->pid_);

    ASSERT_EQ(RET_SUCCESS, PermissionRecordManager::GetInstance().StopUsingPermission(
        binTokenId, BIN_PID, "ohos.permission.CAMERA", CALLER_PID, ""));
}

/**
 * @tc.name: BinStartStatusBackground001
 * @tc.desc: BIN start using permission while parent hap not in foreground list, status is background.
 * @tc.type: FUNC
 * @tc.require: 20260805885509
 */
HWTEST_F(PermissionRecordManagerBinTest, BinStartStatusBackground001, TestSize.Level0)
{
    MockNativeToken mock("audio_server");
    AccessTokenID parentTokenId = GetParentHapTokenId();
    ASSERT_NE(INVALID_TOKENID, parentTokenId);
    AccessTokenID binTokenId = BuildBinTokenId(parentTokenId);

    auto& state = GetFakeParentHapTokenIdState();
    state.ret = ACCESS_TOKEN_OK;
    state.parentHapTokenID = static_cast<uint64_t>(parentTokenId);

    sptr<BinPermActiveStatusChangeCallback> callback = RegisterBinActiveStatusCallback({"ohos.permission.CAMERA"});
    ASSERT_NE(nullptr, callback);
    ASSERT_EQ(RET_SUCCESS, PermissionRecordManager::GetInstance().StartUsingPermission(
        MakeBinStartInfo(binTokenId, BIN_PID), CALLER_PID));
    std::this_thread::sleep_for(std::chrono::milliseconds(SLEEP_TIME_MILLISECONDS));
    EXPECT_EQ(PERM_ACTIVE_IN_BACKGROUND, callback->type_);

    ASSERT_EQ(RET_SUCCESS, PermissionRecordManager::GetInstance().StopUsingPermission(
        binTokenId, BIN_PID, "ohos.permission.CAMERA", CALLER_PID, ""));
}

/**
 * @tc.name: BinNormalizeFail001
 * @tc.desc: Kernel query failed or ioctl unsupported, add/start/stop fail without record.
 * @tc.type: FUNC
 * @tc.require: 20260805885509
 */
HWTEST_F(PermissionRecordManagerBinTest, BinNormalizeFail001, TestSize.Level0)
{
    MockNativeToken mock("audio_server");
    AccessTokenID parentTokenId = GetParentHapTokenId();
    AccessTokenID binTokenId = BuildBinTokenId(parentTokenId);

    auto& state = GetFakeParentHapTokenIdState();
    state.ret = EIO_ERR;

    ASSERT_EQ(PrivacyError::ERR_TOKENID_NOT_EXIST, PermissionRecordManager::GetInstance().AddPermissionUsedRecord(
        MakeBinAddInfo(binTokenId)));
    ASSERT_EQ(PrivacyError::ERR_TOKENID_NOT_EXIST, PermissionRecordManager::GetInstance().StartUsingPermission(
        MakeBinStartInfo(binTokenId, BIN_PID), CALLER_PID));
    ASSERT_EQ(PrivacyError::ERR_TOKENID_NOT_EXIST, PermissionRecordManager::GetInstance().StopUsingPermission(
        binTokenId, BIN_PID, "ohos.permission.CAMERA", CALLER_PID, ""));
    ASSERT_FALSE(HasRecordInCache(parentTokenId));
    ASSERT_FALSE(HasRecordInStartList(parentTokenId, BIN_PID));

    // kernel ioctl unsupported: same error code, ret logged for diagnosis
    ResetFakeParentHapTokenIdState();
    auto& unsupportedState = GetFakeParentHapTokenIdState();
    unsupportedState.ret = ENOTSUP;
    ASSERT_EQ(PrivacyError::ERR_TOKENID_NOT_EXIST,
        PermissionRecordManager::GetInstance().AddPermissionUsedRecord(MakeBinAddInfo(binTokenId)));
    ASSERT_EQ(PrivacyError::ERR_TOKENID_NOT_EXIST,
        PermissionRecordManager::GetInstance().StartUsingPermission(
            MakeBinStartInfo(binTokenId, BIN_PID), CALLER_PID));
    ASSERT_EQ(PrivacyError::ERR_TOKENID_NOT_EXIST,
        PermissionRecordManager::GetInstance().StopUsingPermission(
            binTokenId, BIN_PID, "ohos.permission.CAMERA", CALLER_PID, ""));
    ASSERT_FALSE(HasRecordInCache(parentTokenId));
    ASSERT_FALSE(HasRecordInStartList(parentTokenId, BIN_PID));
}

/**
 * @tc.name: BinNormalizeInvalidParent001
 * @tc.desc: Kernel returns ok but parent token invalid, return ERR_TOKENID_NOT_EXIST.
 * @tc.type: FUNC
 * @tc.require: 20260805885509
 */
HWTEST_F(PermissionRecordManagerBinTest, BinNormalizeInvalidParent001, TestSize.Level0)
{
    MockNativeToken mock("audio_server");
    AccessTokenID parentTokenId = GetParentHapTokenId();
    AccessTokenID binTokenId = BuildBinTokenId(parentTokenId);

    auto& state = GetFakeParentHapTokenIdState();
    state.ret = ACCESS_TOKEN_OK;
    state.parentHapTokenID = 0;

    ASSERT_EQ(PrivacyError::ERR_TOKENID_NOT_EXIST, PermissionRecordManager::GetInstance().AddPermissionUsedRecord(
        MakeBinAddInfo(binTokenId)));
    ASSERT_EQ(PrivacyError::ERR_TOKENID_NOT_EXIST, PermissionRecordManager::GetInstance().StartUsingPermission(
        MakeBinStartInfo(binTokenId, BIN_PID), CALLER_PID));
    ASSERT_FALSE(HasRecordInCache(parentTokenId));
}


/**
 * @tc.name: BinStopRecordNormalized001
 * @tc.desc: BIN start then stop by bin token, start list record removed; second stop returns not start using.
 * @tc.type: FUNC
 * @tc.require: 20260805885509
 */
HWTEST_F(PermissionRecordManagerBinTest, BinStopRecordNormalized001, TestSize.Level0)
{
    MockNativeToken mock("audio_server");
    AccessTokenID parentTokenId = GetParentHapTokenId();
    AccessTokenID binTokenId = BuildBinTokenId(parentTokenId);

    auto& state = GetFakeParentHapTokenIdState();
    state.ret = ACCESS_TOKEN_OK;
    state.parentHapTokenID = static_cast<uint64_t>(parentTokenId);

    ASSERT_EQ(RET_SUCCESS, PermissionRecordManager::GetInstance().StartUsingPermission(
        MakeBinStartInfo(binTokenId, BIN_PID), CALLER_PID));
    ASSERT_TRUE(HasRecordInStartList(parentTokenId, BIN_PID));

    ASSERT_EQ(RET_SUCCESS, PermissionRecordManager::GetInstance().StopUsingPermission(
        binTokenId, BIN_PID, "ohos.permission.CAMERA", CALLER_PID, ""));
    ASSERT_FALSE(HasRecordInStartList(parentTokenId, BIN_PID));

    ASSERT_EQ(PrivacyError::ERR_PERMISSION_NOT_START_USING, PermissionRecordManager::GetInstance().StopUsingPermission(
        binTokenId, BIN_PID, "ohos.permission.CAMERA", CALLER_PID, ""));
}

/**
 * @tc.name: BinMultiProcessIsolated001
 * @tc.desc: Two bin processes with different pids under same parent, start/stop do not interfere.
 * @tc.type: FUNC
 * @tc.require: 20260805885509
 */
HWTEST_F(PermissionRecordManagerBinTest, BinMultiProcessIsolated001, TestSize.Level0)
{
    MockNativeToken mock("audio_server");
    AccessTokenID parentTokenId = GetParentHapTokenId();
    ASSERT_NE(INVALID_TOKENID, parentTokenId);
    AccessTokenID binTokenId = BuildBinTokenId(parentTokenId);

    auto& state = GetFakeParentHapTokenIdState();
    state.ret = ACCESS_TOKEN_OK;
    state.parentHapTokenID = static_cast<uint64_t>(parentTokenId);

    ASSERT_EQ(RET_SUCCESS, PermissionRecordManager::GetInstance().StartUsingPermission(
        MakeBinStartInfo(binTokenId, BIN_PID_A), CALLER_PID));
    ASSERT_EQ(RET_SUCCESS, PermissionRecordManager::GetInstance().StartUsingPermission(
        MakeBinStartInfo(binTokenId, BIN_PID_B), CALLER_PID));
    ASSERT_TRUE(HasRecordInStartList(parentTokenId, BIN_PID_A));
    ASSERT_TRUE(HasRecordInStartList(parentTokenId, BIN_PID_B));

    ASSERT_EQ(RET_SUCCESS, PermissionRecordManager::GetInstance().StopUsingPermission(
        binTokenId, BIN_PID_A, "ohos.permission.CAMERA", CALLER_PID, ""));
    ASSERT_FALSE(HasRecordInStartList(parentTokenId, BIN_PID_A));
    ASSERT_TRUE(HasRecordInStartList(parentTokenId, BIN_PID_B));

    ASSERT_EQ(RET_SUCCESS, PermissionRecordManager::GetInstance().StopUsingPermission(
        binTokenId, BIN_PID_B, "ohos.permission.CAMERA", CALLER_PID, ""));
}

/**
 * @tc.name: BinDuplicateStartRejected001
 * @tc.desc: Same bin token and pid start twice, second returns already start using.
 * @tc.type: FUNC
 * @tc.require: 20260805885509
 */
HWTEST_F(PermissionRecordManagerBinTest, BinDuplicateStartRejected001, TestSize.Level0)
{
    MockNativeToken mock("audio_server");
    AccessTokenID parentTokenId = GetParentHapTokenId();
    AccessTokenID binTokenId = BuildBinTokenId(parentTokenId);

    auto& state = GetFakeParentHapTokenIdState();
    state.ret = ACCESS_TOKEN_OK;
    state.parentHapTokenID = static_cast<uint64_t>(parentTokenId);

    ASSERT_EQ(RET_SUCCESS, PermissionRecordManager::GetInstance().StartUsingPermission(
        MakeBinStartInfo(binTokenId, BIN_PID), CALLER_PID));
    ASSERT_EQ(PrivacyError::ERR_PERMISSION_ALREADY_START_USING,
        PermissionRecordManager::GetInstance().StartUsingPermission(
            MakeBinStartInfo(binTokenId, BIN_PID), CALLER_PID));

    ASSERT_EQ(RET_SUCCESS, PermissionRecordManager::GetInstance().StopUsingPermission(
        binTokenId, BIN_PID, "ohos.permission.CAMERA", CALLER_PID, ""));
}

/**
 * @tc.name: BinIsAllowedNormalized001
 * @tc.desc: Bin token is normalized to parent hap for IsAllowedUsingPermission; fail closed on normalize failure.
 * @tc.type: FUNC
 * @tc.require: 20260805885509
 */
HWTEST_F(PermissionRecordManagerBinTest, BinIsAllowedNormalized001, TestSize.Level0)
{
    MockNativeToken mock("audio_server");
    AccessTokenID parentTokenId = GetParentHapTokenId();
    AccessTokenID binTokenId = BuildBinTokenId(parentTokenId);

    // parent without camera background permission: normalized judgment denied, kernel query happened
    auto& state = GetFakeParentHapTokenIdState();
    state.ret = ACCESS_TOKEN_OK;
    state.parentHapTokenID = static_cast<uint64_t>(parentTokenId);
    ASSERT_FALSE(PermissionRecordManager::GetInstance().IsAllowedUsingPermission(
        binTokenId, "ohos.permission.CAMERA", BIN_PID));
    EXPECT_EQ(1, state.callCount);

    // normalize failed: fail closed without any judgment
    ResetFakeParentHapTokenIdState();
    auto& failState = GetFakeParentHapTokenIdState();
    failState.ret = EIO_ERR;
    ASSERT_FALSE(PermissionRecordManager::GetInstance().IsAllowedUsingPermission(
        binTokenId, "ohos.permission.CAMERA", BIN_PID));

    // parent granted camera background permission: normalized judgment allowed
    HapInfoParams grantedInfo = g_binInfoParms;
    grantedInfo.bundleName = "ohos.privacy_test.binbundle.granted";
    HapPolicyParams grantedPolicy = {
        .apl = APL_NORMAL,
        .domain = "test.domain.bin",
        .permList = {},
        .permStateList = {
            {
                .permissionName = "ohos.permission.CAMERA_BACKGROUND",
                .isGeneral = true,
                .resDeviceID = {"local"},
                .grantStatus = {PermissionState::PERMISSION_GRANTED},
                .grantFlags = {1}
            }
        }
    };
    AccessTokenIDEx grantedEx = PrivacyTestCommon::AllocTestHapToken(grantedInfo, grantedPolicy);
    ASSERT_NE(INVALID_TOKENID, grantedEx.tokenIdExStruct.tokenID);
    AccessTokenID grantedBinTokenId = BuildBinTokenId(grantedEx.tokenIdExStruct.tokenID);
    ResetFakeParentHapTokenIdState();
    auto& grantedState = GetFakeParentHapTokenIdState();
    grantedState.ret = ACCESS_TOKEN_OK;
    grantedState.parentHapTokenID = static_cast<uint64_t>(grantedEx.tokenIdExStruct.tokenID);
    ASSERT_TRUE(PermissionRecordManager::GetInstance().IsAllowedUsingPermission(
        grantedBinTokenId, "ohos.permission.CAMERA", BIN_PID));
    PrivacyTestCommon::DeleteTestHapToken(grantedEx.tokenIdExStruct.tokenID);

    // non bin token: no kernel query
    ResetFakeParentHapTokenIdState();
    ASSERT_FALSE(PermissionRecordManager::GetInstance().IsAllowedUsingPermission(
        parentTokenId, "ohos.permission.CAMERA", BIN_PID));
    EXPECT_EQ(0, GetFakeParentHapTokenIdState().callCount);
}

/**
 * @tc.name: BinRecordAggregated001
 * @tc.desc: Access counts of two bin processes in same minute and same status are aggregated to parent.
 * @tc.type: FUNC
 * @tc.require: 20260805885509
 */
HWTEST_F(PermissionRecordManagerBinTest, BinRecordAggregated001, TestSize.Level0)
{
    MockNativeToken mock("audio_server");
    AccessTokenID parentTokenId = GetParentHapTokenId();
    AccessTokenID binTokenId = BuildBinTokenId(parentTokenId);

    auto& state = GetFakeParentHapTokenIdState();
    state.ret = ACCESS_TOKEN_OK;
    state.parentHapTokenID = static_cast<uint64_t>(parentTokenId);

    AddPermParamInfo infoA = MakeBinAddInfo(binTokenId);
    infoA.successCount = 1;
    ASSERT_EQ(RET_SUCCESS, PermissionRecordManager::GetInstance().AddPermissionUsedRecord(infoA));
    AddPermParamInfo infoB = MakeBinAddInfo(binTokenId);
    infoB.successCount = 2;
    ASSERT_EQ(RET_SUCCESS, PermissionRecordManager::GetInstance().AddPermissionUsedRecord(infoB));

    PermissionUsedResult result = QueryBinUsedRecords(parentTokenId);
    bool found = false;
    for (const auto& bundleRecord : result.bundleRecords) {
        for (const auto& record : bundleRecord.permissionRecords) {
            if (record.permissionName == CONTACTS_PERMISSION_NAME) {
                found = true;
                EXPECT_EQ(3, record.accessCount);
            }
        }
    }
    EXPECT_TRUE(found);
}

/**
 * @tc.name: BinAppStateLinkedFg001
 * @tc.desc: Parent hap switches to foreground, bin persistent record status is linked to foreground.
 * @tc.type: FUNC
 * @tc.require: 20260805885509
 */
HWTEST_F(PermissionRecordManagerBinTest, BinAppStateLinkedFg001, TestSize.Level0)
{
    MockNativeToken mock("audio_server");
    AccessTokenID parentTokenId = GetParentHapTokenId();
    AccessTokenID binTokenId = BuildBinTokenId(parentTokenId);

    auto& state = GetFakeParentHapTokenIdState();
    state.ret = ACCESS_TOKEN_OK;
    state.parentHapTokenID = static_cast<uint64_t>(parentTokenId);

    sptr<BinPermActiveStatusChangeCallback> callback = RegisterBinActiveStatusCallback(
        {"ohos.permission.MICROPHONE"});
    ASSERT_NE(nullptr, callback);
    ASSERT_EQ(RET_SUCCESS, PermissionRecordManager::GetInstance().StartUsingPermission(
        MakeBinStartInfo(binTokenId, BIN_PID, "ohos.permission.MICROPHONE"), CALLER_PID));
    std::this_thread::sleep_for(std::chrono::milliseconds(SLEEP_TIME_MILLISECONDS));
    EXPECT_EQ(PERM_ACTIVE_IN_BACKGROUND, callback->type_);

    PermissionRecordManager::GetInstance().NotifyAppStateChange(parentTokenId, PARENT_HAP_PID,
        PERM_ACTIVE_IN_FOREGROUND);
    EXPECT_EQ(PERM_ACTIVE_IN_FOREGROUND, GetRecordStatusInStartList(parentTokenId, BIN_PID));
    EXPECT_NE(PERM_INACTIVE, callback->type_);

    ASSERT_EQ(RET_SUCCESS, PermissionRecordManager::GetInstance().StopUsingPermission(
        binTokenId, BIN_PID, "ohos.permission.MICROPHONE", CALLER_PID, ""));
}

/**
 * @tc.name: BinAppStateLinkedBg001
 * @tc.desc: Parent hap switches to background, bin persistent record status is linked to background.
 * @tc.type: FUNC
 * @tc.require: 20260805885509
 */
HWTEST_F(PermissionRecordManagerBinTest, BinAppStateLinkedBg001, TestSize.Level0)
{
    MockNativeToken mock("audio_server");
    AccessTokenID parentTokenId = GetParentHapTokenId();
    AccessTokenID binTokenId = BuildBinTokenId(parentTokenId);

    auto& state = GetFakeParentHapTokenIdState();
    state.ret = ACCESS_TOKEN_OK;
    state.parentHapTokenID = static_cast<uint64_t>(parentTokenId);

    sptr<BinPermActiveStatusChangeCallback> callback = RegisterBinActiveStatusCallback(
        {"ohos.permission.MICROPHONE"});
    ASSERT_NE(nullptr, callback);
    ASSERT_EQ(RET_SUCCESS, PermissionRecordManager::GetInstance().StartUsingPermission(
        MakeBinStartInfo(binTokenId, BIN_PID, "ohos.permission.MICROPHONE"), CALLER_PID));
    std::this_thread::sleep_for(std::chrono::milliseconds(SLEEP_TIME_MILLISECONDS));

    PermissionRecordManager::GetInstance().NotifyAppStateChange(parentTokenId, PARENT_HAP_PID,
        PERM_ACTIVE_IN_FOREGROUND);
    ASSERT_EQ(PERM_ACTIVE_IN_FOREGROUND, GetRecordStatusInStartList(parentTokenId, BIN_PID));

    PermissionRecordManager::GetInstance().NotifyAppStateChange(parentTokenId, PARENT_HAP_PID,
        PERM_ACTIVE_IN_BACKGROUND);
    EXPECT_EQ(PERM_ACTIVE_IN_BACKGROUND, GetRecordStatusInStartList(parentTokenId, BIN_PID));
    EXPECT_NE(PERM_INACTIVE, callback->type_);

    ASSERT_EQ(RET_SUCCESS, PermissionRecordManager::GetInstance().StopUsingPermission(
        binTokenId, BIN_PID, "ohos.permission.MICROPHONE", CALLER_PID, ""));
}

/**
 * @tc.name: BinExitResidue001
 * @tc.desc: Bin process dies without any notification, record remains and subscriber keeps receiving.
 * @tc.type: FUNC
 * @tc.require: 20260805885509
 */
HWTEST_F(PermissionRecordManagerBinTest, BinExitResidue001, TestSize.Level0)
{
    MockNativeToken mock("audio_server");
    AccessTokenID parentTokenId = GetParentHapTokenId();
    AccessTokenID binTokenId = BuildBinTokenId(parentTokenId);

    auto& state = GetFakeParentHapTokenIdState();
    state.ret = ACCESS_TOKEN_OK;
    state.parentHapTokenID = static_cast<uint64_t>(parentTokenId);

    sptr<BinPermActiveStatusChangeCallback> callback = RegisterBinActiveStatusCallback(
        {"ohos.permission.MICROPHONE"});
    ASSERT_NE(nullptr, callback);
    ASSERT_EQ(RET_SUCCESS, PermissionRecordManager::GetInstance().StartUsingPermission(
        MakeBinStartInfo(binTokenId, BIN_PID, "ohos.permission.MICROPHONE"), CALLER_PID));
    std::this_thread::sleep_for(std::chrono::milliseconds(SLEEP_TIME_MILLISECONDS));
    ASSERT_EQ(PERM_ACTIVE_IN_BACKGROUND, callback->type_);

    // bin process dies here: no death recipient and no appmgr notification is delivered by design,
    // so nothing is done to simulate it. The record must remain and keep notifying.
    ASSERT_TRUE(HasRecordInStartList(parentTokenId, BIN_PID));

    PermissionRecordManager::GetInstance().NotifyAppStateChange(parentTokenId, PARENT_HAP_PID,
        PERM_ACTIVE_IN_FOREGROUND);
    EXPECT_EQ(PERM_ACTIVE_IN_FOREGROUND, GetRecordStatusInStartList(parentTokenId, BIN_PID));
    EXPECT_NE(PERM_INACTIVE, callback->type_);

    ASSERT_EQ(RET_SUCCESS, PermissionRecordManager::GetInstance().StopUsingPermission(
        binTokenId, BIN_PID, "ohos.permission.MICROPHONE", CALLER_PID, ""));
}

/**
 * @tc.name: BinParentTerminatedCleanup001
 * @tc.desc: Parent hap terminated, all bin records cleaned with inactive callback; db records kept.
 * @tc.type: FUNC
 * @tc.require: 20260805885509
 */
HWTEST_F(PermissionRecordManagerBinTest, BinParentTerminatedCleanup001, TestSize.Level0)
{
    MockNativeToken mock("audio_server");
    AccessTokenID parentTokenId = GetParentHapTokenId();
    AccessTokenID binTokenId = BuildBinTokenId(parentTokenId);

    auto& state = GetFakeParentHapTokenIdState();
    state.ret = ACCESS_TOKEN_OK;
    state.parentHapTokenID = static_cast<uint64_t>(parentTokenId);

    sptr<BinPermActiveStatusChangeCallback> callback = RegisterBinActiveStatusCallback(
        {"ohos.permission.CAMERA"});
    ASSERT_NE(nullptr, callback);
    ASSERT_EQ(RET_SUCCESS, PermissionRecordManager::GetInstance().StartUsingPermission(
        MakeBinStartInfo(binTokenId, BIN_PID_A), CALLER_PID));
    ASSERT_EQ(RET_SUCCESS, PermissionRecordManager::GetInstance().StartUsingPermission(
        MakeBinStartInfo(binTokenId, BIN_PID_B), CALLER_PID));
    ASSERT_EQ(RET_SUCCESS, PermissionRecordManager::GetInstance().AddPermissionUsedRecord(
        MakeBinAddInfo(binTokenId)));

    PermissionRecordManager::GetInstance().RemoveRecordFromStartListByTokenAndIdentity(parentTokenId);
    std::this_thread::sleep_for(std::chrono::milliseconds(SLEEP_TIME_MILLISECONDS));
    EXPECT_FALSE(HasRecordInStartList(parentTokenId, BIN_PID_A));
    EXPECT_FALSE(HasRecordInStartList(parentTokenId, BIN_PID_B));
    EXPECT_EQ(PERM_INACTIVE, callback->type_);

    PermissionUsedResult result = QueryBinUsedRecords(parentTokenId);
    EXPECT_FALSE(result.bundleRecords.empty());
}

/**
 * @tc.name: NonBinNormalizeUnchanged001
 * @tc.desc: Non-bin hap token passes through NormalizeRecordTokenId unchanged, no kernel query.
 * @tc.type: FUNC
 * @tc.require: 20260805885509
 */
HWTEST_F(PermissionRecordManagerBinTest, NonBinNormalizeUnchanged001, TestSize.Level0)
{
    MockNativeToken mock("audio_server");
    AccessTokenID parentTokenId = GetParentHapTokenId();
    ASSERT_NE(INVALID_TOKENID, parentTokenId);

    AccessTokenID normalizedTokenId = INVALID_TOKENID;
    ASSERT_EQ(RET_SUCCESS, PermissionRecordManager::GetInstance().NormalizeRecordTokenId(
        parentTokenId, normalizedTokenId));
    EXPECT_EQ(parentTokenId, normalizedTokenId);
    EXPECT_EQ(0, GetFakeParentHapTokenIdState().callCount);

    ASSERT_EQ(RET_SUCCESS, PermissionRecordManager::GetInstance().AddPermissionUsedRecord(
        MakeBinAddInfo(parentTokenId)));
    EXPECT_EQ(0, GetFakeParentHapTokenIdState().callCount);
    ASSERT_TRUE(HasRecordInCache(parentTokenId));
}
} // namespace AccessToken
} // namespace Security
} // namespace OHOS
