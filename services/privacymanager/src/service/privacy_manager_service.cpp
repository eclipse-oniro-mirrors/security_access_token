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

#include "privacy_manager_service.h"

#include <cinttypes>
#include <cstring>

#include "access_token.h"
#include "accesstoken_kit.h"
#include "accesstoken_common_log.h"
#include "active_status_callback_manager.h"
#include "ipc_skeleton.h"
#ifdef COMMON_EVENT_SERVICE_ENABLE
#include "privacy_common_event_subscriber.h"
#endif //COMMON_EVENT_SERVICE_ENABLE
#include "constant_common.h"
#include "constant.h"
#include "data_usage_dfx.h"
#include "ipc_skeleton.h"
#include "permission_record_manager.h"
#include "privacy_error.h"
#include "privacy_manager_proxy_death_param.h"
#include "system_ability_definition.h"
#include "string_ex.h"
#include "tokenid_kit.h"

#ifdef HITRACE_NATIVE_ENABLE
#include "hitrace_meter.h"
#define PRIVACY_SYNC_TRACE HITRACE_METER_NAME(HITRACE_TAG_ACCESS_CONTROL, __PRETTY_FUNCTION__)
#endif

namespace OHOS {
namespace Security {
namespace AccessToken {
namespace {
constexpr const char* PERMISSION_USED_STATS = "ohos.permission.PERMISSION_USED_STATS";
constexpr const char* PERMISSION_RECORD_TOGGLE = "ohos.permission.PERMISSION_RECORD_TOGGLE";
constexpr const char* SET_FOREGROUND_HAP_REMINDER = "ohos.permission.SET_FOREGROUND_HAP_REMINDER";
constexpr const char* SET_MUTE_POLICY = "ohos.permission.SET_MUTE_POLICY";
static const int32_t SA_ID_PRIVACY_MANAGER_SERVICE = 3505;
static const uint32_t PERM_LIST_SIZE_MAX = 1024;
}

const bool REGISTER_RESULT =
    SystemAbility::MakeAndRegisterAbility(DelayedSingleton<PrivacyManagerService>::GetInstance().get());

PrivacyManagerService::PrivacyManagerService()
    : SystemAbility(SA_ID_PRIVACY_MANAGER_SERVICE, true), state_(ServiceRunningState::STATE_NOT_START)
{
    LOGI(PRI_DOMAIN, PRI_TAG, "PrivacyManagerService()");
}

PrivacyManagerService::~PrivacyManagerService()
{
    LOGI(PRI_DOMAIN, PRI_TAG, "~PrivacyManagerService()");
#ifdef COMMON_EVENT_SERVICE_ENABLE
    PrivacyCommonEventSubscriber::UnRegisterEvent();
#endif //COMMON_EVENT_SERVICE_ENABLE
}

void PrivacyManagerService::OnStart()
{
    if (state_ == ServiceRunningState::STATE_RUNNING) {
        LOGI(PRI_DOMAIN, PRI_TAG, "PrivacyManagerService has already started!");
        return;
    }
    LOGI(PRI_DOMAIN, PRI_TAG, "PrivacyManagerService is starting");
    if (!Initialize()) {
        LOGE(PRI_DOMAIN, PRI_TAG, "Failed to initialize");
        return;
    }
    AddSystemAbilityListener(ACCESS_TOKEN_MANAGER_SERVICE_ID);
    AddSystemAbilityListener(COMMON_EVENT_SERVICE_ID);
    AddSystemAbilityListener(SCREENLOCK_SERVICE_ID);
}

void PrivacyManagerService::OnStop()
{
    LOGI(PRI_DOMAIN, PRI_TAG, "Stop service");
    state_ = ServiceRunningState::STATE_NOT_START;
}

int32_t PrivacyManagerService::AddPermissionUsedRecord(const AddPermParamInfoParcel& infoParcel)
{
#ifdef HITRACE_NATIVE_ENABLE
    PRIVACY_SYNC_TRACE;
#endif
    LOGI(PRI_DOMAIN, PRI_TAG, "Entry!");

    uint32_t callingTokenID = IPCSkeleton::GetCallingTokenID();
    if ((AccessTokenKit::GetTokenTypeFlag(callingTokenID) == TOKEN_HAP) && (!IsSystemAppCalling())) {
        return PrivacyError::ERR_NOT_SYSTEM_APP;
    }
    if (!VerifyPermission(PERMISSION_USED_STATS)) {
        return PrivacyError::ERR_PERMISSION_DENIED;
    }

    AddPermParamInfo info = infoParcel.info;
    int32_t res = PermissionRecordManager::GetInstance().AddPermissionUsedRecord(info);
    LOGI(PRI_DOMAIN, PRI_TAG, "Exit!");
    return res;
}

int32_t PrivacyManagerService::AddPermissionUsedRecordAsync(const AddPermParamInfoParcel& infoParcel)
{
    return AddPermissionUsedRecord(infoParcel);
}

int32_t PrivacyManagerService::SetPermissionUsedRecordToggleStatus(int32_t userID, bool status)
{
    uint32_t callingTokenID = IPCSkeleton::GetCallingTokenID();
    if ((AccessTokenKit::GetTokenTypeFlag(callingTokenID) == TOKEN_HAP) && (!IsSystemAppCalling())) {
        return PrivacyError::ERR_NOT_SYSTEM_APP;
    }
    if (!IsPrivilegedCalling() && !VerifyPermission(PERMISSION_RECORD_TOGGLE)) {
        return PrivacyError::ERR_PERMISSION_DENIED;
    }

    LOGI(PRI_DOMAIN, PRI_TAG, "userID: %{public}d, status: %{public}d", userID, status ? 1 : 0);
    return PermissionRecordManager::GetInstance().SetPermissionUsedRecordToggleStatus(userID, status);
}

int32_t PrivacyManagerService::GetPermissionUsedRecordToggleStatus(int32_t userID, bool& status)
{
    uint32_t callingTokenID = IPCSkeleton::GetCallingTokenID();
    if ((AccessTokenKit::GetTokenTypeFlag(callingTokenID) == TOKEN_HAP) && (!IsSystemAppCalling())) {
        return PrivacyError::ERR_NOT_SYSTEM_APP;
    }
    if (!IsPrivilegedCalling() && !VerifyPermission(PERMISSION_USED_STATS)) {
        return PrivacyError::ERR_PERMISSION_DENIED;
    }

    LOGD(PRI_DOMAIN, PRI_TAG, "userID: %{public}d, status: %{public}d", userID, status ? 1 : 0);
    return PermissionRecordManager::GetInstance().GetPermissionUsedRecordToggleStatus(userID, status);
}

std::shared_ptr<ProxyDeathHandler> PrivacyManagerService::GetProxyDeathHandler()
{
    std::lock_guard<std::mutex> lock(deathHandlerMutex_);
    if (proxyDeathHandler_ == nullptr) {
        proxyDeathHandler_ = std::make_shared<ProxyDeathHandler>();
    }
    return proxyDeathHandler_;
}

void PrivacyManagerService::ProcessProxyDeathStub(const sptr<IRemoteObject>& anonyStub, int32_t callerPid)
{
    if (anonyStub == nullptr) {
        LOGE(PRI_DOMAIN, PRI_TAG, "anonyStub is nullptr.");
        return;
    }
    std::shared_ptr<ProxyDeathParam> param = std::make_shared<PrivacyManagerProxyDeathParam>(callerPid);
    if (param == nullptr) {
        LOGE(PRI_DOMAIN, PRI_TAG, "Create param failed.");
        return;
    }
    auto handler = GetProxyDeathHandler();
    if (handler == nullptr) {
        LOGE(PRI_DOMAIN, PRI_TAG, "Handler is nullptr.");
        return;
    }
    handler->AddProxyStub(anonyStub, param);
}

void PrivacyManagerService::ReleaseDeathStub(int32_t callerPid)
{
    std::shared_ptr<ProxyDeathParam> param = std::make_shared<PrivacyManagerProxyDeathParam>(callerPid);
    if (param == nullptr) {
        LOGE(PRI_DOMAIN, PRI_TAG, "Create param failed.");
        return;
    }
    auto handler = GetProxyDeathHandler();
    if (handler == nullptr) {
        LOGE(PRI_DOMAIN, PRI_TAG, "Handler is nullptr.");
        return;
    }
    handler->ReleaseProxyByParam(param);
}

int32_t PrivacyManagerService::StartUsingPermission(
    const PermissionUsedTypeInfoParcel &infoParcel, const sptr<IRemoteObject>& anonyStub)
{
    uint32_t callingTokenID = IPCSkeleton::GetCallingTokenID();
    if ((AccessTokenKit::GetTokenTypeFlag(callingTokenID) == TOKEN_HAP) && (!IsSystemAppCalling())) {
        return PrivacyError::ERR_NOT_SYSTEM_APP;
    }
    if (!VerifyPermission(PERMISSION_USED_STATS)) {
        return PrivacyError::ERR_PERMISSION_DENIED;
    }

    int32_t callerPid = IPCSkeleton::GetCallingPid();
    LOGI(PRI_DOMAIN, PRI_TAG, "Caller pid = %{public}d.", callerPid);
    ProcessProxyDeathStub(anonyStub, callerPid);
    return PermissionRecordManager::GetInstance().StartUsingPermission(infoParcel.info, callerPid);
}

int32_t PrivacyManagerService::StartUsingPermissionCallback(const PermissionUsedTypeInfoParcel &infoParcel,
    const sptr<IRemoteObject>& callback, const sptr<IRemoteObject>& anonyStub)
{
#ifdef HITRACE_NATIVE_ENABLE
    PRIVACY_SYNC_TRACE;
#endif
    LOGI(PRI_DOMAIN, PRI_TAG, "Entry!");
    uint32_t callingTokenID = IPCSkeleton::GetCallingTokenID();
    if ((AccessTokenKit::GetTokenTypeFlag(callingTokenID) == TOKEN_HAP) && (!IsSystemAppCalling())) {
        return PrivacyError::ERR_NOT_SYSTEM_APP;
    }
    if (!VerifyPermission(PERMISSION_USED_STATS)) {
        return PrivacyError::ERR_PERMISSION_DENIED;
    }

    int32_t callerPid = IPCSkeleton::GetCallingPid();
    ProcessProxyDeathStub(anonyStub, callerPid);
    int32_t res = PermissionRecordManager::GetInstance().StartUsingPermission(infoParcel.info, callback, callerPid);
    LOGI(PRI_DOMAIN, PRI_TAG, "Exit!");
    return res;
}

int32_t PrivacyManagerService::StopUsingPermission(
    AccessTokenID tokenId, int32_t pid, const std::string& permissionName)
{
    uint32_t callingTokenID = IPCSkeleton::GetCallingTokenID();
    if ((AccessTokenKit::GetTokenTypeFlag(callingTokenID) == TOKEN_HAP) && (!IsSystemAppCalling())) {
        return PrivacyError::ERR_NOT_SYSTEM_APP;
    }
    if (!VerifyPermission(PERMISSION_USED_STATS)) {
        return PrivacyError::ERR_PERMISSION_DENIED;
    }

    LOGI(PRI_DOMAIN, PRI_TAG, "id: %{public}u, pid: %{public}d, perm: %{public}s",
        tokenId, pid, permissionName.c_str());
    int32_t callerPid = IPCSkeleton::GetCallingPid();
    int32_t ret = PermissionRecordManager::GetInstance().StopUsingPermission(tokenId, pid, permissionName, callerPid);
    if (ret != Constant::SUCCESS) {
        return ret;
    }
    if (!PermissionRecordManager::GetInstance().HasCallerInStartList(callerPid)) {
        LOGI(PRI_DOMAIN, PRI_TAG, "No permission record from caller = %{public}d", callerPid);
        ReleaseDeathStub(callerPid);
    }
    return ret;
}

int32_t PrivacyManagerService::RemovePermissionUsedRecords(AccessTokenID tokenId)
{
    uint32_t callingTokenID = IPCSkeleton::GetCallingTokenID();
    if ((AccessTokenKit::GetTokenTypeFlag(callingTokenID) == TOKEN_HAP) && (!IsSystemAppCalling())) {
        return PrivacyError::ERR_NOT_SYSTEM_APP;
    }
    if (!IsAccessTokenCalling() && !VerifyPermission(PERMISSION_USED_STATS)) {
        return PrivacyError::ERR_PERMISSION_DENIED;
    }

    LOGI(PRI_DOMAIN, PRI_TAG, "id: %{public}u", tokenId);
    PermissionRecordManager::GetInstance().RemovePermissionUsedRecords(tokenId);
    return Constant::SUCCESS;
}

int32_t PrivacyManagerService::GetPermissionUsedRecords(
    const PermissionUsedRequestParcel& request, PermissionUsedResultParcel& resultParcel)
{
    uint32_t callingTokenID = IPCSkeleton::GetCallingTokenID();
    if ((AccessTokenKit::GetTokenTypeFlag(callingTokenID) == TOKEN_HAP) && (!IsSystemAppCalling())) {
        return PrivacyError::ERR_NOT_SYSTEM_APP;
    }
    if (!VerifyPermission(PERMISSION_USED_STATS)) {
        return PrivacyError::ERR_PERMISSION_DENIED;
    }

    std::string permissionList;
    for (const auto& perm : request.request.permissionList) {
        permissionList.append(perm);
        permissionList.append(" ");
    }
    LOGI(PRI_DOMAIN, PRI_TAG, "id: %{public}d, timestamp: [%{public}s-%{public}s], flag: %{public}d, perm: %{public}s.",
        request.request.tokenId, std::to_string(request.request.beginTimeMillis).c_str(),
        std::to_string(request.request.endTimeMillis).c_str(), request.request.flag, permissionList.c_str());

    PermissionUsedResult permissionRecord;
    int32_t ret =  PermissionRecordManager::GetInstance().GetPermissionUsedRecords(request.request, permissionRecord);
    resultParcel.result = permissionRecord;
    return ret;
}

int32_t PrivacyManagerService::GetPermissionUsedRecordsAsync(
    const PermissionUsedRequestParcel& request, const sptr<OnPermissionUsedRecordCallback>& callback)
{
    uint32_t callingTokenID = IPCSkeleton::GetCallingTokenID();
    if ((AccessTokenKit::GetTokenTypeFlag(callingTokenID) == TOKEN_HAP) && (!IsSystemAppCalling())) {
        return PrivacyError::ERR_NOT_SYSTEM_APP;
    }
    if (!VerifyPermission(PERMISSION_USED_STATS)) {
        return PrivacyError::ERR_PERMISSION_DENIED;
    }

    LOGD(PRI_DOMAIN, PRI_TAG, "id: %{public}d", request.request.tokenId);
    return PermissionRecordManager::GetInstance().GetPermissionUsedRecordsAsync(request.request, callback);
}

int32_t PrivacyManagerService::RegisterPermActiveStatusCallback(
    const std::vector<std::string>& permList, const sptr<IRemoteObject>& callback)
{
    uint32_t callingTokenID = IPCSkeleton::GetCallingTokenID();
    if ((AccessTokenKit::GetTokenTypeFlag(callingTokenID) == TOKEN_HAP) && (!IsSystemAppCalling())) {
        return PrivacyError::ERR_NOT_SYSTEM_APP;
    }
    if (!VerifyPermission(PERMISSION_USED_STATS)) {
        return PrivacyError::ERR_PERMISSION_DENIED;
    }

    if (permList.size() > PERM_LIST_SIZE_MAX) {
        LOGE(PRI_DOMAIN, PRI_TAG, "permList oversize");
        return PrivacyError::ERR_OVERSIZE;
    }

    return PermissionRecordManager::GetInstance().RegisterPermActiveStatusCallback(
        IPCSkeleton::GetCallingTokenID(), permList, callback);
}

int32_t PrivacyManagerService::ResponseDumpCommand(int32_t fd, const std::vector<std::u16string>& args)
{
    if (args.size() < 2) { // 2 :need two args 0:command 1:tokenId
        return ERR_INVALID_VALUE;
    }
    long long tokenId = atoll(static_cast<const char*>(Str16ToStr8(args.at(1)).c_str()));
    PermissionUsedRequest request;
    if (tokenId <= 0) {
        return ERR_INVALID_VALUE;
    }
    request.tokenId = static_cast<uint32_t>(tokenId);
    request.flag = FLAG_PERMISSION_USAGE_SUMMARY;
    PermissionUsedResult result;
    if (PermissionRecordManager::GetInstance().GetPermissionUsedRecords(request, result) != 0) {
        return ERR_INVALID_VALUE;
    }
    std::string infos;
    if (result.bundleRecords.empty() || result.bundleRecords[0].permissionRecords.empty()) {
        dprintf(fd, "No Record \n");
        return ERR_OK;
    }
    size_t size = result.bundleRecords[0].permissionRecords.size();
    infos.append("{\n");
    infos.append(R"(  "permissionRecord": [)");
    infos.append("\n");
    for (size_t index = 0; index < size; index++) {
        infos.append("    {\n");
        infos.append(R"(      "bundleName": ")" + result.bundleRecords[0].bundleName + R"(")" + ",\n");
        std::string isRemoteStr = (result.bundleRecords[0].isRemote ? "true" : "false");
        infos.append(R"(      "isRemote": )" + isRemoteStr + ",\n");
        infos.append(R"(      "permissionName": ")" + result.bundleRecords[0].permissionRecords[index].permissionName +
                    R"(")" + ",\n");
        time_t lastAccessTime = static_cast<time_t>(result.bundleRecords[0].permissionRecords[index].lastAccessTime);
        infos.append(R"(      "lastAccessTime": )" + std::to_string(lastAccessTime) + ",\n");
        infos.append(R"(      "lastAccessDuration": )" +
                    std::to_string(result.bundleRecords[0].permissionRecords[index].lastAccessDuration) + ",\n");
        infos.append(R"(      "accessCount": )" +
            std::to_string(result.bundleRecords[0].permissionRecords[index].accessCount) + "\n");
        infos.append("    }");
        if (index != (size - 1)) {
            infos.append(",");
        }
        infos.append("\n");
    }
    infos.append("  ]\n");
    infos.append("}");
    dprintf(fd, "%s\n", infos.c_str());
    return ERR_OK;
}

int32_t PrivacyManagerService::Dump(int32_t fd, const std::vector<std::u16string>& args)
{
    if (fd < 0) {
        LOGE(PRI_DOMAIN, PRI_TAG, "Dump fd invalid value");
        return ERR_INVALID_VALUE;
    }
    int32_t ret = ERR_OK;
    dprintf(fd, "Privacy Dump:\n");
    if (args.size() == 0) {
        dprintf(fd, "please use hidumper -s said -a '-h' command help\n");
        return ret;
    }
    std::string arg0 = Str16ToStr8(args.at(0));
    if (arg0.compare("-h") == 0) {
        dprintf(fd, "Usage:\n");
        dprintf(fd, "       -h: command help\n");
        dprintf(fd, "       -t <TOKEN_ID>: according to specific token id dump permission used records\n");
    } else if (arg0.compare("-t") == 0) {
        ret = PrivacyManagerService::ResponseDumpCommand(fd, args);
    } else {
        dprintf(fd, "please use hidumper -s said -a '-h' command help\n");
        ret = ERR_INVALID_VALUE;
    }
    return ret;
}

int32_t PrivacyManagerService::UnRegisterPermActiveStatusCallback(const sptr<IRemoteObject>& callback)
{
    uint32_t callingTokenID = IPCSkeleton::GetCallingTokenID();
    if ((AccessTokenKit::GetTokenTypeFlag(callingTokenID) == TOKEN_HAP) && (!IsSystemAppCalling())) {
        return PrivacyError::ERR_NOT_SYSTEM_APP;
    }
    if (!VerifyPermission(PERMISSION_USED_STATS)) {
        return PrivacyError::ERR_PERMISSION_DENIED;
    }

    return PermissionRecordManager::GetInstance().UnRegisterPermActiveStatusCallback(callback);
}

int32_t PrivacyManagerService::IsAllowedUsingPermission(AccessTokenID tokenId, const std::string& permissionName,
    int32_t pid, bool& isAllowed)
{
#ifdef HITRACE_NATIVE_ENABLE
    PRIVACY_SYNC_TRACE;
#endif
    LOGI(PRI_DOMAIN, PRI_TAG, "Entry!");
    uint32_t callingTokenID = IPCSkeleton::GetCallingTokenID();
    if ((AccessTokenKit::GetTokenTypeFlag(callingTokenID) == TOKEN_HAP) && (!IsSystemAppCalling())) {
        LOGE(PRI_DOMAIN, PRI_TAG, "Permission denied(tokenID=%{public}d)", callingTokenID);
        return PrivacyError::ERR_NOT_SYSTEM_APP;
    }
    if (!VerifyPermission(PERMISSION_USED_STATS)) {
        return PrivacyError::ERR_PERMISSION_DENIED;
    }

    isAllowed = PermissionRecordManager::GetInstance().IsAllowedUsingPermission(tokenId, permissionName, pid);
    LOGI(PRI_DOMAIN, PRI_TAG, "Exit!");
    return ERR_OK;
}

int32_t PrivacyManagerService::SetMutePolicy(uint32_t policyType, uint32_t callerType, bool isMute,
    AccessTokenID tokenID)
{
    AccessTokenID callingTokenID = IPCSkeleton::GetCallingTokenID();
    if ((AccessTokenKit::GetTokenTypeFlag(callingTokenID) != TOKEN_NATIVE) &&
        (AccessTokenKit::GetTokenTypeFlag(callingTokenID) != TOKEN_SHELL)) {
        return PrivacyError::ERR_PERMISSION_DENIED;
    }

    if (!VerifyPermission(SET_MUTE_POLICY)) {
        return PrivacyError::ERR_PERMISSION_DENIED;
    }

    LOGI(PRI_DOMAIN, PRI_TAG, "PolicyType %{public}d, callerType %{public}d, isMute %{public}d, tokenId %{public}u",
        policyType, callerType, isMute, tokenID);
    return PermissionRecordManager::GetInstance().SetMutePolicy(
        static_cast<PolicyType>(policyType), static_cast<CallerType>(callerType), isMute, tokenID);
}

int32_t PrivacyManagerService::SetHapWithFGReminder(uint32_t tokenId, bool isAllowed)
{
    if (!VerifyPermission(SET_FOREGROUND_HAP_REMINDER)) {
        return PrivacyError::ERR_PERMISSION_DENIED;
    }

    LOGI(PRI_DOMAIN, PRI_TAG, "id: %{public}d, isAllowed: %{public}d", tokenId, isAllowed);
    return PermissionRecordManager::GetInstance().SetHapWithFGReminder(tokenId, isAllowed);
}

int32_t PrivacyManagerService::GetPermissionUsedTypeInfos(const AccessTokenID tokenId,
    const std::string& permissionName, std::vector<PermissionUsedTypeInfoParcel>& resultsParcel)
{
    uint32_t callingTokenID = IPCSkeleton::GetCallingTokenID();
    if ((AccessTokenKit::GetTokenTypeFlag(callingTokenID) == TOKEN_HAP) && (!IsSystemAppCalling())) {
        return PrivacyError::ERR_NOT_SYSTEM_APP;
    }
    if (!VerifyPermission(PERMISSION_USED_STATS)) {
        return PrivacyError::ERR_PERMISSION_DENIED;
    }

    LOGD(PRI_DOMAIN, PRI_TAG, "id: %{public}d, perm: %{public}s", tokenId, permissionName.c_str());
    std::vector<PermissionUsedTypeInfo> results;
    int32_t res = PermissionRecordManager::GetInstance().GetPermissionUsedTypeInfos(tokenId, permissionName, results);
    if (res != RET_SUCCESS) {
        return res;
    }

    for (const auto& result : results) {
        PermissionUsedTypeInfoParcel parcel;
        parcel.info = result;
        resultsParcel.emplace_back(parcel);
    }

    return RET_SUCCESS;
}

void PrivacyManagerService::OnAddSystemAbility(int32_t systemAbilityId, const std::string& deviceId)
{
    LOGI(PRI_DOMAIN, PRI_TAG, "saId is %{public}d", systemAbilityId);
#ifdef COMMON_EVENT_SERVICE_ENABLE
    if (systemAbilityId == COMMON_EVENT_SERVICE_ID) {
        PrivacyCommonEventSubscriber::RegisterEvent();
        return;
    }
#endif //COMMON_EVENT_SERVICE_ENABLE

    if (systemAbilityId == SCREENLOCK_SERVICE_ID) {
        int32_t lockScreenStatus = PermissionRecordManager::GetInstance().GetLockScreenStatus(true);
        PermissionRecordManager::GetInstance().SetLockScreenStatus(lockScreenStatus);
        return;
    }

    std::lock_guard<std::mutex> lock(stateMutex_);
    if (systemAbilityId == ACCESS_TOKEN_MANAGER_SERVICE_ID && state_ != ServiceRunningState::STATE_RUNNING) {
        bool ret = Publish(DelayedSingleton<PrivacyManagerService>::GetInstance().get());
        if (!ret) {
            LOGE(PRI_DOMAIN, PRI_TAG, "Failed to publish service!");
            return;
        }
        state_ = ServiceRunningState::STATE_RUNNING;
        LOGI(PRI_DOMAIN, PRI_TAG, "Congratulations, PrivacyManagerService start successfully!");
        return;
    }
}

bool PrivacyManagerService::Initialize()
{
    PermissionRecordManager::GetInstance().Init();
#ifdef EVENTHANDLER_ENABLE
    eventRunner_ = AppExecFwk::EventRunner::Create(true, AppExecFwk::ThreadMode::FFRT);
    if (!eventRunner_) {
        LOGE(PRI_DOMAIN, PRI_TAG, "Failed to create eventRunner.");
        return false;
    }
    eventHandler_ = std::make_shared<AccessEventHandler>(eventRunner_);
    ActiveStatusCallbackManager::GetInstance().InitEventHandler(eventHandler_);
#endif
    std::thread reportUserData(ReportPrivacyUserData);
    reportUserData.detach();
    return true;
}

bool PrivacyManagerService::IsPrivilegedCalling() const
{
    // shell process is root in debug mode.
#ifndef ATM_BUILD_VARIANT_USER_ENABLE
    int32_t callingUid = IPCSkeleton::GetCallingUid();
    return callingUid == ROOT_UID;
#else
    return false;
#endif
}

bool PrivacyManagerService::IsAccessTokenCalling() const
{
    int32_t callingUid = IPCSkeleton::GetCallingUid();
    return callingUid == ACCESSTOKEN_UID;
}

bool PrivacyManagerService::IsSystemAppCalling() const
{
    uint64_t fullTokenId = IPCSkeleton::GetCallingFullTokenID();
    return TokenIdKit::IsSystemAppByFullTokenID(fullTokenId);
}

bool PrivacyManagerService::VerifyPermission(const std::string& permission) const
{
    uint32_t callingTokenID = IPCSkeleton::GetCallingTokenID();
    if (AccessTokenKit::VerifyAccessToken(callingTokenID, permission) == PERMISSION_DENIED) {
        LOGE(PRI_DOMAIN, PRI_TAG, "Permission denied(callingTokenID=%{public}d)", callingTokenID);
        return false;
    }
    return true;
}
} // namespace AccessToken
} // namespace Security
} // namespace OHOS
