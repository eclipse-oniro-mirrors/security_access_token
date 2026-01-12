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

#include "privacystub_fuzzer.h"

#include <string>
#include <thread>
#include <vector>

#include "accesstoken_fuzzdata.h"
#include "accesstoken_kit.h"
#include "fuzzer/FuzzedDataProvider.h"
#include "iprivacy_manager.h"
#include "nativetoken_kit.h"
#include "perm_active_status_change_callback.h"
#include "perm_active_status_customized_cbk.h"
#include "privacy_manager_service.h"
#include "token_setproc.h"

using namespace std;
using namespace OHOS::Security::AccessToken;
static AccessTokenID g_audioTokenID = 0;
const int CONSTANTS_NUMBER_TWO = 2;
static const int32_t ROOT_UID = 0;
static const uint32_t ACTIVE_CHANGE_CHANGE_TYPE_MAX = 4;
static const uint32_t CALLER_TYPE_MAX = 2;

class RegisterActiveFuzzTest : public PermActiveStatusCustomizedCbk {
public:
    explicit RegisterActiveFuzzTest(const std::vector<std::string> &permList)
        : PermActiveStatusCustomizedCbk(permList)
    {}

    ~RegisterActiveFuzzTest()
    {}

    virtual void ActiveStatusChangeCallback(ActiveChangeResponse& result)
    {
        type_ = result.type;
        return;
    }

    ActiveChangeType type_ = PERM_INACTIVE;
};

namespace OHOS {

void AddPermissionUsedRecordStubFuzzTest(FuzzedDataProvider &provider)
{
    MessageParcel datas;
    datas.WriteInterfaceToken(IPrivacyManager::GetDescriptor());

    AddPermParamInfoParcel infoParcel;
    infoParcel.info.tokenId = ConsumeTokenId(provider);
    infoParcel.info.permissionName = ConsumePermissionName(provider);
    infoParcel.info.successCount = provider.ConsumeIntegral<int32_t>();
    infoParcel.info.failCount = provider.ConsumeIntegral<int32_t>();
    infoParcel.info.type = static_cast<PermissionUsedType>(provider.ConsumeIntegralInRange<uint32_t>(
        0, static_cast<uint32_t>(PermissionUsedType::PERM_USED_TYPE_BUTT)));
    if (!datas.WriteParcelable(&infoParcel)) {
        return;
    }

    uint32_t code = static_cast<uint32_t>(IPrivacyManagerIpcCode::COMMAND_ADD_PERMISSION_USED_RECORD);

    MessageParcel reply;
    MessageOption option;
    (void)DelayedSingleton<PrivacyManagerService>::GetInstance()->OnRemoteRequest(code, datas, reply, option);
}

void GetPermissionUsedRecordsStubFuzzTest(FuzzedDataProvider &provider)
{
    PermissionUsedRequest request = {
        .tokenId = ConsumeTokenId(provider),
        .isRemote = provider.ConsumeBool(),
        .deviceId = provider.ConsumeRandomLengthString(),
        .bundleName = ConsumeProcessName(provider),
        .permissionList = {ConsumePermissionName(provider)},
        .beginTimeMillis = provider.ConsumeIntegral<int64_t>(),
        .endTimeMillis = provider.ConsumeIntegral<int64_t>(),
        .flag = static_cast<PermissionUsageFlag>(provider.ConsumeIntegralInRange<uint32_t>(
            0, static_cast<uint32_t>(PermissionUsageFlag::FLAG_PERMISSION_USAGE_SUMMARY_IN_APP_FOREGROUND))),
    };
    PermissionUsedRequestParcel requestParcel;
    requestParcel.request = request;

    MessageParcel datas;
    datas.WriteInterfaceToken(IPrivacyManager::GetDescriptor());
    if (!datas.WriteParcelable(&requestParcel)) {
        return;
    }

    uint32_t code = static_cast<uint32_t>(IPrivacyManagerIpcCode::COMMAND_GET_PERMISSION_USED_RECORDS);

    MessageParcel reply;
    MessageOption option;
    (void)DelayedSingleton<PrivacyManagerService>::GetInstance()->OnRemoteRequest(code, datas, reply, option);
}

void GetPermissionUsedRecordToggleStatusStubFuzzTest(FuzzedDataProvider &provider)
{
    MessageParcel datas;
    datas.WriteInterfaceToken(IPrivacyManager::GetDescriptor());

    int32_t userID = provider.ConsumeIntegral<int32_t>();
    if (!datas.WriteInt32(userID)) {
        return;
    }

    uint32_t code = static_cast<uint32_t>(IPrivacyManagerIpcCode::COMMAND_GET_PERMISSION_USED_RECORD_TOGGLE_STATUS);

    MessageParcel reply;
    MessageOption option;
    bool enable = ((provider.ConsumeIntegral<int32_t>() % CONSTANTS_NUMBER_TWO) == 0);
    if (enable) {
        setuid(CONSTANTS_NUMBER_TWO);
    }
    (void)DelayedSingleton<PrivacyManagerService>::GetInstance()->OnRemoteRequest(code, datas, reply, option);
    setuid(ROOT_UID);
}

void GetPermissionUsedTypeInfosStubFuzzTest(FuzzedDataProvider &provider)
{
    AccessTokenID tokenId = ConsumeTokenId(provider);
    std::string permissionName = ConsumePermissionName(provider);
    MessageParcel datas;
    datas.WriteInterfaceToken(IPrivacyManager::GetDescriptor());

    if (!datas.WriteUint32(tokenId)) {
        return;
    }
    if (!datas.WriteString(permissionName)) {
        return;
    }

    uint32_t code = static_cast<uint32_t>(IPrivacyManagerIpcCode::COMMAND_GET_PERMISSION_USED_TYPE_INFOS);

    MessageParcel reply;
    MessageOption option;
    (void)DelayedSingleton<PrivacyManagerService>::GetInstance()->OnRemoteRequest(code, datas, reply, option);
}

void IsAllowedUsingPermissionStubFuzzTest(FuzzedDataProvider &provider)
{
    AccessTokenID tokenId = ConsumeTokenId(provider);
    std::string permissionName = ConsumePermissionName(provider);

    MessageParcel datas;
    datas.WriteInterfaceToken(IPrivacyManager::GetDescriptor());
    if (!datas.WriteUint32(tokenId)) {
        return;
    }
    if (!datas.WriteString(permissionName)) {
        return;
    }
    if (!datas.WriteInt32(provider.ConsumeIntegral<int32_t>())) {
        return;
    }

    uint32_t code = static_cast<uint32_t>(
        IPrivacyManagerIpcCode::COMMAND_IS_ALLOWED_USING_PERMISSION);

    MessageParcel reply;
    MessageOption option;
    (void)DelayedSingleton<PrivacyManagerService>::GetInstance()->OnRemoteRequest(code, datas, reply, option);
}

void RegisterPermActiveStatusCallbackStubFuzzTest(FuzzedDataProvider &provider)
{
    std::vector<std::string> permList = {ConsumePermissionName(provider)};
    auto callback = std::make_shared<RegisterActiveFuzzTest>(permList);
    callback->type_ = PERM_INACTIVE;
    sptr<PermActiveStatusChangeCallback> callbackWrap = nullptr;
    callbackWrap = new (std::nothrow) PermActiveStatusChangeCallback(callback);

    MessageParcel datas;
    datas.WriteInterfaceToken(IPrivacyManager::GetDescriptor());
    if (!datas.WriteInt32(permList.size())) {
        return;
    }
    if (!datas.WriteString(permList[0])) {
        return;
    }
    if (!datas.WriteRemoteObject(callbackWrap->AsObject())) {
        return;
    }

    uint32_t code = static_cast<uint32_t>(IPrivacyManagerIpcCode::COMMAND_REGISTER_PERM_ACTIVE_STATUS_CALLBACK);

    MessageParcel reply;
    MessageOption option;
    (void)DelayedSingleton<PrivacyManagerService>::GetInstance()->OnRemoteRequest(code, datas, reply, option);
}

void RemovePermissionUsedRecordsStubFuzzTest(FuzzedDataProvider &provider)
{
    AccessTokenID tokenId = ConsumeTokenId(provider);
    std::string permissionName = ConsumePermissionName(provider);

    MessageParcel datas;
    datas.WriteInterfaceToken(IPrivacyManager::GetDescriptor());
    if (!datas.WriteUint32(tokenId)) {
        return;
    }
    if (!datas.WriteString(permissionName)) {
        return;
    }

    uint32_t code = static_cast<uint32_t>(
        IPrivacyManagerIpcCode::COMMAND_REMOVE_PERMISSION_USED_RECORDS);

    MessageParcel reply;
    MessageOption option;
    (void)DelayedSingleton<PrivacyManagerService>::GetInstance()->OnRemoteRequest(code, datas, reply, option);
}

void SetHapWithFGReminderStubFuzzTest(FuzzedDataProvider &provider)
{
    (void)SetSelfTokenID(g_audioTokenID);

    AccessTokenID tokenId = ConsumeTokenId(provider);
    bool isAllowed = provider.ConsumeBool();

    MessageParcel datas;
    datas.WriteInterfaceToken(IPrivacyManager::GetDescriptor());
    if (!datas.WriteUint32(tokenId)) {
        return;
    }
    if (!datas.WriteInt32(isAllowed ? 1 : 0)) {
        return;
    }

    uint32_t code = static_cast<uint32_t>(
        IPrivacyManagerIpcCode::COMMAND_SET_HAP_WITH_F_G_REMINDER);

    MessageParcel reply;
    MessageOption option;
    bool enable = ((provider.ConsumeIntegral<int32_t>() % CONSTANTS_NUMBER_TWO) == 0);
    if (enable) {
        setuid(CONSTANTS_NUMBER_TWO);
    }
    (void)DelayedSingleton<PrivacyManagerService>::GetInstance()->OnRemoteRequest(code, datas, reply, option);
    setuid(ROOT_UID);
}

void SetMutePolicyStubFuzzTest(FuzzedDataProvider &provider)
{
    (void)SetSelfTokenID(g_audioTokenID);

    uint32_t policyType = provider.ConsumeIntegralInRange<uint32_t>(0, ACTIVE_CHANGE_CHANGE_TYPE_MAX);
    uint32_t callerType = provider.ConsumeIntegralInRange<uint32_t>(0, CALLER_TYPE_MAX);
    bool isMute = provider.ConsumeBool();
    uint32_t tokenID = provider.ConsumeIntegral<uint32_t>();

    MessageParcel datas;
    datas.WriteInterfaceToken(IPrivacyManager::GetDescriptor());
    if (!datas.WriteUint32(policyType)) {
        return;
    }
    if (!datas.WriteUint32(callerType)) {
        return;
    }
    if (!datas.WriteInt32(isMute ? 1 : 0)) {
        return;
    }
    if (!datas.WriteUint32(tokenID)) {
        return;
    }

    uint32_t code = static_cast<uint32_t>(
        IPrivacyManagerIpcCode::COMMAND_SET_MUTE_POLICY);

    MessageParcel reply;
    MessageOption option;
    bool enable = ((provider.ConsumeIntegral<int32_t>() % CONSTANTS_NUMBER_TWO) == 0);
    if (enable) {
        setuid(CONSTANTS_NUMBER_TWO);
    }
    (void)DelayedSingleton<PrivacyManagerService>::GetInstance()->OnRemoteRequest(code, datas, reply, option);
    setuid(ROOT_UID);
}

void SetPermissionUsedRecordToggleStatusStubFuzzTest(FuzzedDataProvider &provider)
{
    MessageParcel datas;
    datas.WriteInterfaceToken(IPrivacyManager::GetDescriptor());

    int32_t userID = provider.ConsumeIntegral<int32_t>();
    bool status = provider.ConsumeBool();
    if (!datas.WriteInt32(userID) || !datas.WriteInt32(status ? 1 : 0)) {
        return;
    }

    uint32_t code = static_cast<uint32_t>(IPrivacyManagerIpcCode::COMMAND_SET_PERMISSION_USED_RECORD_TOGGLE_STATUS);

    MessageParcel reply;
    MessageOption option;
    bool enable = ((provider.ConsumeIntegral<int32_t>() % CONSTANTS_NUMBER_TWO) == 0);
    if (enable) {
        setuid(CONSTANTS_NUMBER_TWO);
    }
    (void)DelayedSingleton<PrivacyManagerService>::GetInstance()->OnRemoteRequest(code, datas, reply, option);
    setuid(ROOT_UID);
}

void StopUsingPermissionStubFuzzTest(FuzzedDataProvider &provider)
{
    MessageParcel datas;
    AccessTokenID tokenID = ConsumeTokenId(provider);
    std::string permissionName = ConsumePermissionName(provider);
    datas.WriteInterfaceToken(IPrivacyManager::GetDescriptor());
    if (!datas.WriteUint32(tokenID)) {
        return;
    }
    if (!datas.WriteString(permissionName)) {
        return;
    }
    if (!datas.WriteInt32(provider.ConsumeIntegral<int32_t>())) {
        return;
    }

    uint32_t code = static_cast<uint32_t>(IPrivacyManagerIpcCode::COMMAND_STOP_USING_PERMISSION);

    MessageParcel reply;
    MessageOption option;
    (void)DelayedSingleton<PrivacyManagerService>::GetInstance()->OnRemoteRequest(code, datas, reply, option);
}

bool PrivacyStubFuzzTest(FuzzedDataProvider &provider)
{
    AddPermissionUsedRecordStubFuzzTest(provider);
    GetPermissionUsedRecordsStubFuzzTest(provider);
    GetPermissionUsedRecordToggleStatusStubFuzzTest(provider);
    GetPermissionUsedTypeInfosStubFuzzTest(provider);
    IsAllowedUsingPermissionStubFuzzTest(provider);
    RegisterPermActiveStatusCallbackStubFuzzTest(provider);
    RemovePermissionUsedRecordsStubFuzzTest(provider);
    SetHapWithFGReminderStubFuzzTest(provider);
    SetMutePolicyStubFuzzTest(provider);
    SetPermissionUsedRecordToggleStatusStubFuzzTest(provider);
    StopUsingPermissionStubFuzzTest(provider);
    return true;
}

void Initialize()
{
    g_audioTokenID = AccessTokenKit::GetNativeTokenId("audio_server");
}
} // namespace OHOS

extern "C" int LLVMFuzzerInitialize(int *argc, char ***argv)
{
    OHOS::Initialize();
    return 0;
}

/* Fuzzer entry point */
extern "C" int LLVMFuzzerTestOneInput(const uint8_t* data, size_t size)
{
    /* Run your code on data */
    if ((data == nullptr) || (size == 0)) {
        return 0;
    }

    FuzzedDataProvider provider(data, size);
    OHOS::PrivacyStubFuzzTest(provider);
    return 0;
}
