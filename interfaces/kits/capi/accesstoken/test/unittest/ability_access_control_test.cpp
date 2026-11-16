/*
 * Copyright (c) 2026 Huawei Device Co., Ltd.
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 *
 * http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 */

#include <chrono>
#include <condition_variable>
#include <mutex>
#include <string>
#include <thread>
#include <utility>
#include <vector>

#include <gtest/gtest.h>

#include "ability_access_control.h"
#include "ability_access_control_mock.h"
#include "i_token_callback.h"

using namespace testing::ext;
using namespace OHOS;

namespace {

struct CallbackRecord {
    int32_t errorcode;
    std::vector<std::string> perms;
    std::vector<OH_AT_PermissionOperResult> opers;
    std::vector<bool> shown;
};

std::mutex g_recordMutex;
std::condition_variable g_recordCv;
std::vector<CallbackRecord> g_records;

void RecordCallback(const OH_AT_PermissionsRequestResult *result, void* userData)
{
    (void)userData;
    CallbackRecord record;
    record.errorcode = result->errorCode;
    for (int32_t i = 0; i < result->permCount; ++i) {
        record.perms.emplace_back(result->permissions[i]);
        record.opers.push_back(result->operResults[i]);
        record.shown.push_back(result->dialogShownResults[i]);
    }
    {
        std::lock_guard<std::mutex> lock(g_recordMutex);
        g_records.push_back(record);
    }
    g_recordCv.notify_one();
}

CallbackRecord WaitOneCallback()
{
    std::unique_lock<std::mutex> lock(g_recordMutex);
    g_recordCv.wait(lock, []() { return !g_records.empty(); });
    CallbackRecord record = g_records.front();
    g_records.erase(g_records.begin());
    return record;
}

void ClearRecords()
{
    std::lock_guard<std::mutex> lock(g_recordMutex);
    g_records.clear();
}

void TriggerReceiver(size_t index, const std::vector<std::string>&permissions, const std::vector<int32_t>&grantResults)
{
    ASSERT_LT(index, OHOS::Security::AccessToken::g_mockState.receivers.size());
    auto remote = OHOS::Security::AccessToken::g_mockState.receivers[index];
    ASSERT_NE(remote, nullptr);
    auto callback = iface_cast<OHOS::Security::AccessToken::ITokenCallback>(remote);
    ASSERT_NE(callback, nullptr);
    callback->GrantResultsCallback(permissions, grantResults);
}
} // namespace

namespace OHOS {
namespace Security {
namespace AccessToken {
class AbilityAccessControlTest : public testing::Test {
public:
    void SetUp() override
    {
        ResetMockState();
        ClearRecords();
    }
    void TearDown() override {}
};

/**
 * @tc.name: CheckSelfPermissionTest001
 * @tc.desc: Test OH_AT_CheckSelfPermission with granted, denied and null permission.
 * @tc.type: FUNC
 * @tc.require: Issue
 */
HWTEST_F(AbilityAccessControlTest, CheckSelfPermissionTest001, TestSize.Level1)
{
    g_mockState.verifyResult = static_cast<int>(PermissionState::PERMISSION_GRANTED);
    EXPECT_TRUE(OH_AT_CheckSelfPermission("ohos.permission.LOCATION"));
    g_mockState.verifyResult = static_cast<int>(PermissionState::PERMISSION_DENIED);
    EXPECT_FALSE(OH_AT_CheckSelfPermission("ohos.permission.LOCATION"));
    EXPECT_FALSE(OH_AT_CheckSelfPermission(nullptr));
}

/**
 * @tc.name: RequestInvalidParameterTest002
 * @tc.desc: Test OH_AT_RequestPermissionsFromUser with invalid request or permission item.
 * @tc.type: FUNC
 * @tc.require: Issue
 */
HWTEST_F(AbilityAccessControlTest, RequestInvalidParameterTest002, TestSize.Level1)
{
    const char* perms[] = { "ohos.permission.LOCATION" };
    EXPECT_EQ(OH_AT_ABILITY_ACCESS_CONTROL_INVALID_PARAMETER_ERROR,
        OH_AT_RequestPermissionsFromUser(nullptr, 1, RecordCallback, nullptr));
    EXPECT_EQ(OH_AT_ABILITY_ACCESS_CONTROL_INVALID_PARAMETER_ERROR,
        OH_AT_RequestPermissionsFromUser(perms, 1, nullptr, nullptr));
    EXPECT_EQ(OH_AT_ABILITY_ACCESS_CONTROL_INVALID_PARAMETER_ERROR,
        OH_AT_RequestPermissionsFromUser(perms, 0, RecordCallback, nullptr));
    std::vector<const char*> exceed(1025, "ohos.permission.LOCATION");
    EXPECT_EQ(OH_AT_ABILITY_ACCESS_CONTROL_INVALID_PARAMETER_ERROR,
        OH_AT_RequestPermissionsFromUser(exceed.data(), 1025, RecordCallback, nullptr));
    const char* emptyPerms[] = { "" };
    EXPECT_EQ(OH_AT_ABILITY_ACCESS_CONTROL_INVALID_PARAMETER_ERROR,
        OH_AT_RequestPermissionsFromUser(emptyPerms, 1, RecordCallback, nullptr));
    const char* nullPerms[] = { nullptr };
    EXPECT_EQ(OH_AT_ABILITY_ACCESS_CONTROL_INVALID_PARAMETER_ERROR,
        OH_AT_RequestPermissionsFromUser(nullPerms, 1, RecordCallback, nullptr));
}

/**
 * @tc.name: RequestCallerTokenNotPermittedTest003
 * @tc.desc: Test OH_AT_RequestPermissionsFromUser with a token of not permitted process type.
 * @tc.type: FUNC
 * @tc.require: Issue
 */
HWTEST_F(AbilityAccessControlTest, RequestCallerTokenNotPermittedTest003, TestSize.Level1)
{
    g_mockState.selfTokenId = 1;
    g_mockState.isBinToken = false;
    const char* perms[] = { "ohos.permission.LOCATION" };
    EXPECT_EQ(OH_AT_ABILITY_ACCESS_CONTROL_NOT_PERMITTED_PROCESS_TYPE_ERROR,
        OH_AT_RequestPermissionsFromUser(perms, 1, RecordCallback, nullptr));
}

/**
 * @tc.name: RequestServiceExceptionTest004
 * @tc.desc: Test OH_AT_RequestPermissionsFromUser when the access token service fails.
 * @tc.type: FUNC
 * @tc.require: Issue
 */
HWTEST_F(AbilityAccessControlTest, RequestServiceExceptionTest004, TestSize.Level1)
{
    g_mockState.selfTokenId = 1;
    g_mockState.grantInfoValid = false;
    const char* perms[] = { "ohos.permission.LOCATION" };
    EXPECT_EQ(OH_AT_ABILITY_ACCESS_CONTROL_SERVICE_EXCEPTION_ERROR,
        OH_AT_RequestPermissionsFromUser(perms, 1, RecordCallback, nullptr));
    g_mockState.grantInfoValid = true;
    g_mockState.oper = TypePermissionOper::INVALID_OPER;
    EXPECT_EQ(OH_AT_ABILITY_ACCESS_CONTROL_SERVICE_EXCEPTION_ERROR,
        OH_AT_RequestPermissionsFromUser(perms, 1, RecordCallback, nullptr));
}

/**
 * @tc.name: RequestStateDeliveredTest005
 * @tc.desc: Test the request is delivered directly when permissions are granted or require settings.
 * @tc.type: FUNC
 * @tc.require: Issue
 */
HWTEST_F(AbilityAccessControlTest, RequestStateDeliveredTest005, TestSize.Level1)
{
    g_mockState.selfTokenId = 1;
    g_mockState.oper = TypePermissionOper::PASS_OPER;
    g_mockState.permState = TypePermissionOper::PASS_OPER;
    const char* perms[] = { "ohos.permission.LOCATION", "ohos.permission.CAMERA" };
    EXPECT_EQ(OH_AT_ABILITY_ACCESS_CONTROL_SUCCESS,
        OH_AT_RequestPermissionsFromUser(perms, 2, RecordCallback, nullptr));
    auto granted = WaitOneCallback();
    EXPECT_EQ(OH_AT_ABILITY_ACCESS_CONTROL_SUCCESS, granted.errorcode);
    EXPECT_EQ("ohos.permission.LOCATION", granted.perms[0]);
    EXPECT_EQ("ohos.permission.CAMERA", granted.perms[1]);
    EXPECT_EQ(OH_AT_PERMISSION_OPER_GRANTED, granted.opers[0]);
    EXPECT_EQ(OH_AT_PERMISSION_OPER_GRANTED, granted.opers[1]);
    EXPECT_FALSE(granted.shown[0]);

    g_mockState.oper = TypePermissionOper::SETTING_OPER;
    g_mockState.permState = TypePermissionOper::SETTING_OPER;
    EXPECT_EQ(OH_AT_ABILITY_ACCESS_CONTROL_SUCCESS,
        OH_AT_RequestPermissionsFromUser(perms, 1, RecordCallback, nullptr));
    auto setting = WaitOneCallback();
    EXPECT_EQ(OH_AT_PERMISSION_OPER_SETTING, setting.opers[0]);
}

/**
 * @tc.name: RequestReasonMappedTest006
 * @tc.desc: Test the delivered result mapping for each permission error reason.
 * @tc.type: FUNC
 * @tc.require: Issue
 */
HWTEST_F(AbilityAccessControlTest, RequestReasonMappedTest006, TestSize.Level1)
{
    g_mockState.selfTokenId = 1;
    g_mockState.oper = TypePermissionOper::PASS_OPER;
    g_mockState.permState = TypePermissionOper::INVALID_OPER;
    const std::vector<std::pair<PermissionErrorReason, OH_AT_PermissionOperResult>> cases = {
        { PermissionErrorReason::PERM_NOT_DECLEARED, OH_AT_PERMISSION_OPER_NOT_DECLARED },
        { PermissionErrorReason::CONDITIONS_NOT_MET, OH_AT_PERMISSION_OPER_CONSTRAINTS_NOT_MET },
        { PermissionErrorReason::PERM_INVALID, OH_AT_PERMISSION_OPER_INVALID_NAME },
        { PermissionErrorReason::PRIVACY_STATEMENT_NOT_AGREED, OH_AT_PERMISSION_OPER_PRIVACY_STATEMENT_REQUIRED },
        { PermissionErrorReason::MANUAL_SETTING_PERM, OH_AT_PERMISSION_OPER_GRANT_MODE_MISMATCH },
        { PermissionErrorReason::UNABLE_POP_UP, OH_AT_PERMISSION_OPER_POP_UP_RESTRICTED },
        { static_cast<PermissionErrorReason>(99), OH_AT_PERMISSION_OPER_POP_UP_RESTRICTED },
    };
    const char* perms[] = { "ohos.permission.LOCATION" };
    for (const auto& item : cases) {
        g_mockState.reason = item.first;
        EXPECT_EQ(OH_AT_ABILITY_ACCESS_CONTROL_SUCCESS,
            OH_AT_RequestPermissionsFromUser(perms, 1, RecordCallback, nullptr));
        auto record = WaitOneCallback();
        EXPECT_EQ(item.second, record.opers[0]);
        EXPECT_FALSE(record.shown[0]);
    }
}

/**
 * @tc.name: RequestConcurrentIndependentTest007
 * @tc.desc: Test concurrent requests start dialogs independently and each receiver reports back.
 * @tc.type: FUNC
 * @tc.require: Issue
 */
HWTEST_F(AbilityAccessControlTest, RequestConcurrentIndependentTest007, TestSize.Level1)
{
    g_mockState.selfTokenId = 1;
    g_mockState.oper = TypePermissionOper::DYNAMIC_OPER;
    g_mockState.permState = TypePermissionOper::DYNAMIC_OPER;
    const char* perms[] = { "ohos.permission.LOCATION" };
    const char* secondPerms[] = { "ohos.permission.CAMERA" };
    EXPECT_EQ(OH_AT_ABILITY_ACCESS_CONTROL_SUCCESS,
        OH_AT_RequestPermissionsFromUser(perms, 1, RecordCallback, nullptr));
    EXPECT_EQ(OH_AT_ABILITY_ACCESS_CONTROL_SUCCESS,
        OH_AT_RequestPermissionsFromUser(secondPerms, 1, RecordCallback, nullptr));
    EXPECT_EQ(2, g_mockState.startAbilityCount);
    EXPECT_EQ(2U, g_mockState.receivers.size());
    TriggerReceiver(0, { "ohos.permission.LOCATION" }, { 0 });
    auto first = WaitOneCallback();
    EXPECT_EQ(OH_AT_ABILITY_ACCESS_CONTROL_SUCCESS, first.errorcode);
    EXPECT_EQ("ohos.permission.LOCATION", first.perms[0]);
    EXPECT_EQ(OH_AT_PERMISSION_OPER_GRANTED, first.opers[0]);
    EXPECT_TRUE(first.shown[0]);
    TriggerReceiver(1, { "ohos.permission.CAMERA" }, { -1 });
    auto second = WaitOneCallback();
    EXPECT_EQ(OH_AT_ABILITY_ACCESS_CONTROL_SUCCESS, second.errorcode);
    EXPECT_EQ("ohos.permission.CAMERA", second.perms[0]);
    EXPECT_EQ(OH_AT_PERMISSION_OPER_SETTING, second.opers[0]);
    EXPECT_TRUE(second.shown[0]);
}

/**
 * @tc.name: RequestStartAbilityFailTest008
 * @tc.desc: Test the request fails synchronously and the next request is accepted.
 * @tc.type: FUNC
 * @tc.require: Issue
 */
HWTEST_F(AbilityAccessControlTest, RequestStartAbilityFailTest008, TestSize.Level1)
{
    g_mockState.selfTokenId = 1;
    g_mockState.oper = TypePermissionOper::DYNAMIC_OPER;
    g_mockState.permState = TypePermissionOper::DYNAMIC_OPER;
    g_mockState.startAbilityErr = -1;
    const char* perms[] = { "ohos.permission.LOCATION" };
    EXPECT_EQ(OH_AT_ABILITY_ACCESS_CONTROL_COMMON_INNER_ERROR,
        OH_AT_RequestPermissionsFromUser(perms, 1, RecordCallback, nullptr));
    g_mockState.startAbilityErr = 0;
    g_mockState.oper = TypePermissionOper::PASS_OPER;
    g_mockState.permState = TypePermissionOper::PASS_OPER;
    EXPECT_EQ(OH_AT_ABILITY_ACCESS_CONTROL_SUCCESS,
        OH_AT_RequestPermissionsFromUser(perms, 1, RecordCallback, nullptr));
    auto record = WaitOneCallback();
    EXPECT_EQ(OH_AT_PERMISSION_OPER_GRANTED, record.opers[0]);
}

/**
 * @tc.name: RequestReceiverGrantResultTest009
 * @tc.desc: Test the dialog results are mapped to operation results.
 * @tc.type: FUNC
 * @tc.require: Issue
 */
HWTEST_F(AbilityAccessControlTest, RequestReceiverGrantResultTest009, TestSize.Level1)
{
    g_mockState.selfTokenId = 1;
    g_mockState.oper = TypePermissionOper::DYNAMIC_OPER;
    g_mockState.permState = TypePermissionOper::DYNAMIC_OPER;
    const char* perms[] = { "ohos.permission.LOCATION" };
    EXPECT_EQ(OH_AT_ABILITY_ACCESS_CONTROL_SUCCESS,
        OH_AT_RequestPermissionsFromUser(perms, 1, RecordCallback, nullptr));
    TriggerReceiver(0, { "ohos.permission.LOCATION" }, { 0 });
    auto granted = WaitOneCallback();
    EXPECT_EQ(OH_AT_PERMISSION_OPER_GRANTED, granted.opers[0]);

    EXPECT_EQ(OH_AT_ABILITY_ACCESS_CONTROL_SUCCESS,
        OH_AT_RequestPermissionsFromUser(perms, 1, RecordCallback, nullptr));
    TriggerReceiver(0, { "ohos.permission.LOCATION" }, { -1 });
    auto denied = WaitOneCallback();
    EXPECT_EQ(OH_AT_PERMISSION_OPER_SETTING, denied.opers[0]);

    EXPECT_EQ(OH_AT_ABILITY_ACCESS_CONTROL_SUCCESS,
        OH_AT_RequestPermissionsFromUser(perms, 1, RecordCallback, nullptr));
    TriggerReceiver(0, { "ohos.permission.LOCATION" }, { 2 });
    auto notSupported = WaitOneCallback();
    EXPECT_EQ(OH_AT_PERMISSION_OPER_POP_UP_RESTRICTED, notSupported.opers[0]);

    EXPECT_EQ(OH_AT_ABILITY_ACCESS_CONTROL_SUCCESS,
        OH_AT_RequestPermissionsFromUser(perms, 1, RecordCallback, nullptr));
    TriggerReceiver(0, { "ohos.permission.LOCATION" }, { 5 });
    auto notDeclared = WaitOneCallback();
    EXPECT_EQ(OH_AT_PERMISSION_OPER_NOT_DECLARED, notDeclared.opers[0]);

    EXPECT_EQ(OH_AT_ABILITY_ACCESS_CONTROL_SUCCESS,
        OH_AT_RequestPermissionsFromUser(perms, 1, RecordCallback, nullptr));
    TriggerReceiver(0, { "ohos.permission.LOCATION" }, { 9 });
    auto unknown = WaitOneCallback();
    EXPECT_EQ(OH_AT_PERMISSION_OPER_POP_UP_RESTRICTED, unknown.opers[0]);

    const char* mixedPerms[] = { "ohos.permission.LOCATION", "ohos.permission.CAMERA" };
    EXPECT_EQ(OH_AT_ABILITY_ACCESS_CONTROL_SUCCESS,
        OH_AT_RequestPermissionsFromUser(mixedPerms, 2, RecordCallback, nullptr));
    TriggerReceiver(5, { "ohos.permission.LOCATION", "ohos.permission.CAMERA" }, { 5, 0 });
    auto mixed = WaitOneCallback();
    EXPECT_EQ(OH_AT_PERMISSION_OPER_NOT_DECLARED, mixed.opers[0]);
    EXPECT_EQ(OH_AT_PERMISSION_OPER_GRANTED, mixed.opers[1]);
}

/**
 * @tc.name: RequestReceiverRequestLevelErrorTest010
 * @tc.desc: Test the delivered error code when the dialog reports request level errors.
 * @tc.type: FUNC
 * @tc.require: Issue
 */
HWTEST_F(AbilityAccessControlTest, RequestReceiverRequestLevelErrorTest010, TestSize.Level1)
{
    g_mockState.selfTokenId = 1;
    g_mockState.oper = TypePermissionOper::DYNAMIC_OPER;
    g_mockState.permState = TypePermissionOper::DYNAMIC_OPER;
    const char* perms[] = { "ohos.permission.LOCATION", "ohos.permission.CAMERA" };
    EXPECT_EQ(OH_AT_ABILITY_ACCESS_CONTROL_SUCCESS,
        OH_AT_RequestPermissionsFromUser(perms, 2, RecordCallback, nullptr));
    TriggerReceiver(0, { "ohos.permission.LOCATION", "ohos.permission.CAMERA" }, { 0, 3 });
    auto commonError = WaitOneCallback();
    EXPECT_EQ(OH_AT_ABILITY_ACCESS_CONTROL_COMMON_INNER_ERROR, commonError.errorcode);
    EXPECT_EQ(OH_AT_PERMISSION_OPER_POP_UP_RESTRICTED, commonError.opers[0]);
    EXPECT_EQ(OH_AT_PERMISSION_OPER_POP_UP_RESTRICTED, commonError.opers[1]);

    EXPECT_EQ(OH_AT_ABILITY_ACCESS_CONTROL_SUCCESS,
        OH_AT_RequestPermissionsFromUser(perms, 1, RecordCallback, nullptr));
    TriggerReceiver(0, { "ohos.permission.LOCATION" }, { 4 });
    auto legacyCommonError = WaitOneCallback();
    EXPECT_EQ(OH_AT_ABILITY_ACCESS_CONTROL_COMMON_INNER_ERROR, legacyCommonError.errorcode);
    EXPECT_EQ(OH_AT_PERMISSION_OPER_POP_UP_RESTRICTED, legacyCommonError.opers[0]);
}

/**
 * @tc.name: RequestReceiverMixedMergeTest011
 * @tc.desc: Test the pre-judged results are merged with the dialog results.
 * @tc.type: FUNC
 * @tc.require: Issue
 */
HWTEST_F(AbilityAccessControlTest, RequestReceiverMixedMergeTest011, TestSize.Level1)
{
    g_mockState.selfTokenId = 1;
    g_mockState.oper = TypePermissionOper::DYNAMIC_OPER;
    g_mockState.permState = TypePermissionOper::DYNAMIC_OPER;
    const char* perms[] = { "ohos.permission.LOCATION", "ohos.permission.CAMERA",
        "ohos.permission.MICROPHONE" };
    EXPECT_EQ(OH_AT_ABILITY_ACCESS_CONTROL_SUCCESS,
        OH_AT_RequestPermissionsFromUser(perms, 3, RecordCallback, nullptr));
    TriggerReceiver(0, { "ohos.permission.LOCATION" }, { 0 });
    auto record = WaitOneCallback();
    EXPECT_EQ(OH_AT_ABILITY_ACCESS_CONTROL_SUCCESS, record.errorcode);
    EXPECT_EQ(3, static_cast<int>(record.opers.size()));
    EXPECT_EQ(OH_AT_PERMISSION_OPER_GRANTED, record.opers[0]);
    EXPECT_EQ(OH_AT_PERMISSION_OPER_POP_UP_RESTRICTED, record.opers[1]);
    EXPECT_EQ(OH_AT_PERMISSION_OPER_POP_UP_RESTRICTED, record.opers[2]);
}

/**
 * @tc.name: RequestCapabilityDisabledTest012
 * @tc.desc: Test the request returns not supported when the kit capability is disabled.
 * @tc.type: FUNC
 * @tc.require: Issue
 */
HWTEST_F(AbilityAccessControlTest, RequestCapabilityDisabledTest012, TestSize.Level1)
{
    g_mockState.dialogEnabled = false;
    const char* perms[] = { "ohos.permission.LOCATION" };
    EXPECT_EQ(OH_AT_ABILITY_ACCESS_CONTROL_NOT_SUPPORTED_ERROR,
        OH_AT_RequestPermissionsFromUser(perms, 1, RecordCallback, nullptr));
    g_mockState.dialogEnabled = true;
    g_mockState.selfTokenId = 1;
    g_mockState.oper = TypePermissionOper::PASS_OPER;
    g_mockState.permState = TypePermissionOper::PASS_OPER;
    EXPECT_EQ(OH_AT_ABILITY_ACCESS_CONTROL_SUCCESS,
        OH_AT_RequestPermissionsFromUser(perms, 1, RecordCallback, nullptr));
    auto record = WaitOneCallback();
    EXPECT_EQ(OH_AT_PERMISSION_OPER_GRANTED, record.opers[0]);
}
} // namespace AccessToken
} // namespace Security
} // namespace OHOS
