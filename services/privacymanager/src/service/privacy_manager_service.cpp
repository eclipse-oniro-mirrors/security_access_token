/*
 * Copyright (c) 2022-2024 Huawei Device Co., Ltd.
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
#include "accesstoken_log.h"
#include "active_status_callback_manager.h"
#ifdef COMMON_EVENT_SERVICE_ENABLE
#include "privacy_common_event_subscriber.h"
#endif //COMMON_EVENT_SERVICE_ENABLE
#include "constant_common.h"
#include "constant.h"
#include "ipc_skeleton.h"
#include "permission_record_manager.h"
#ifdef SECURITY_COMPONENT_ENHANCE_ENABLE
#include "privacy_sec_comp_enhance_agent.h"
#endif
#include "screenlock_manager_access_loader.h"
#include "system_ability_definition.h"
#include "string_ex.h"

namespace OHOS {
namespace Security {
namespace AccessToken {
namespace {
static constexpr OHOS::HiviewDFX::HiLogLabel LABEL = {
    LOG_CORE, SECURITY_DOMAIN_PRIVACY, "PrivacyManagerService"
};
}

const bool REGISTER_RESULT =
    SystemAbility::MakeAndRegisterAbility(DelayedSingleton<PrivacyManagerService>::GetInstance().get());

PrivacyManagerService::PrivacyManagerService()
    : SystemAbility(SA_ID_PRIVACY_MANAGER_SERVICE, true), state_(ServiceRunningState::STATE_NOT_START)
{
    ACCESSTOKEN_LOG_INFO(LABEL, "PrivacyManagerService()");
}

PrivacyManagerService::~PrivacyManagerService()
{
    ACCESSTOKEN_LOG_INFO(LABEL, "~PrivacyManagerService()");
#ifdef COMMON_EVENT_SERVICE_ENABLE
    PrivacyCommonEventSubscriber::UnRegisterEvent();
#endif //COMMON_EVENT_SERVICE_ENABLE
}

void PrivacyManagerService::OnStart()
{
    if (state_ == ServiceRunningState::STATE_RUNNING) {
        ACCESSTOKEN_LOG_INFO(LABEL, "PrivacyManagerService has already started!");
        return;
    }
    if (!Initialize()) {
        ACCESSTOKEN_LOG_ERROR(LABEL, "Failed to initialize");
        return;
    }

    AddSystemAbilityListener(COMMON_EVENT_SERVICE_ID);
    AddSystemAbilityListener(SCREENLOCK_SERVICE_ID);

    state_ = ServiceRunningState::STATE_RUNNING;
    bool ret = Publish(DelayedSingleton<PrivacyManagerService>::GetInstance().get());
    if (!ret) {
        ACCESSTOKEN_LOG_ERROR(LABEL, "Failed to publish service!");
        return;
    }
    ACCESSTOKEN_LOG_INFO(LABEL, "Congratulations, PrivacyManagerService start successfully!");
}

void PrivacyManagerService::OnStop()
{
    ACCESSTOKEN_LOG_INFO(LABEL, "stop service");
    state_ = ServiceRunningState::STATE_NOT_START;
}

int32_t PrivacyManagerService::AddPermissionUsedRecord(const AddPermParamInfoParcel& infoParcel,
    bool asyncMode)
{
    ACCESSTOKEN_LOG_INFO(LABEL, "tokenId: %{public}d, permissionName: %{public}s, successCount: %{public}d,"
        " failCount: %{public}d, type: %{public}d", infoParcel.info.tokenId, infoParcel.info.permissionName.c_str(),
        infoParcel.info.successCount, infoParcel.info.failCount, infoParcel.info.type);
    AddPermParamInfo info = infoParcel.info;
    return PermissionRecordManager::GetInstance().AddPermissionUsedRecord(info);
}

int32_t PrivacyManagerService::StartUsingPermission(AccessTokenID tokenId, const std::string& permissionName)
{
    ACCESSTOKEN_LOG_INFO(LABEL, "tokenId: %{public}d, permissionName: %{public}s", tokenId, permissionName.c_str());
    return PermissionRecordManager::GetInstance().StartUsingPermission(tokenId, permissionName);
}

int32_t PrivacyManagerService::StartUsingPermission(AccessTokenID tokenId, const std::string& permissionName,
    const sptr<IRemoteObject>& callback)
{
    ACCESSTOKEN_LOG_INFO(LABEL, "tokenId: %{public}d, permissionName: %{public}s", tokenId, permissionName.c_str());
    return PermissionRecordManager::GetInstance().StartUsingPermission(tokenId, permissionName, callback);
}

int32_t PrivacyManagerService::StopUsingPermission(AccessTokenID tokenId, const std::string& permissionName)
{
    ACCESSTOKEN_LOG_INFO(LABEL, "tokenId: %{public}d, permissionName: %{public}s", tokenId, permissionName.c_str());
    return PermissionRecordManager::GetInstance().StopUsingPermission(tokenId, permissionName);
}

int32_t PrivacyManagerService::RemovePermissionUsedRecords(AccessTokenID tokenId, const std::string& deviceID)
{
    ACCESSTOKEN_LOG_INFO(LABEL, "tokenId: %{public}d, deviceID: %{public}s", tokenId, deviceID.c_str());
    PermissionRecordManager::GetInstance().RemovePermissionUsedRecords(tokenId, deviceID);
    return Constant::SUCCESS;
}

int32_t PrivacyManagerService::GetPermissionUsedRecords(
    const PermissionUsedRequestParcel& request, PermissionUsedResultParcel& result)
{
    std::string permissionList;
    for (const auto& perm : request.request.permissionList) {
        permissionList.append(perm);
        permissionList.append(" ");
    }
    ACCESSTOKEN_LOG_INFO(LABEL, "tokenId: %{public}d, timestamp: [%{public}" PRId64 "-%{public}" PRId64
        "], flag: %{public}d, perm: %{public}s", request.request.tokenId, request.request.beginTimeMillis,
        request.request.endTimeMillis, request.request.flag, permissionList.c_str());

    PermissionUsedResult permissionRecord;
    int32_t ret =  PermissionRecordManager::GetInstance().GetPermissionUsedRecords(request.request, permissionRecord);
    result.result = permissionRecord;
    return ret;
}

int32_t PrivacyManagerService::GetPermissionUsedRecords(
    const PermissionUsedRequestParcel& request, const sptr<OnPermissionUsedRecordCallback>& callback)
{
    ACCESSTOKEN_LOG_INFO(LABEL, "tokenId: %{public}d", request.request.tokenId);
    return PermissionRecordManager::GetInstance().GetPermissionUsedRecordsAsync(request.request, callback);
}

int32_t PrivacyManagerService::RegisterPermActiveStatusCallback(
    std::vector<std::string>& permList, const sptr<IRemoteObject>& callback)
{
    return PermissionRecordManager::GetInstance().RegisterPermActiveStatusCallback(permList, callback);
}

#ifdef SECURITY_COMPONENT_ENHANCE_ENABLE
int32_t PrivacyManagerService::RegisterSecCompEnhance(const SecCompEnhanceDataParcel& enhanceParcel)
{
    ACCESSTOKEN_LOG_INFO(LABEL, "pid: %{public}d", enhanceParcel.enhanceData.pid);
    return PrivacySecCompEnhanceAgent::GetInstance().RegisterSecCompEnhance(enhanceParcel.enhanceData);
}

int32_t PrivacyManagerService::UpdateSecCompEnhance(int32_t pid, int32_t seqNum)
{
    return PrivacySecCompEnhanceAgent::GetInstance().UpdateSecCompEnhance(pid, seqNum);
}

int32_t PrivacyManagerService::GetSecCompEnhance(int32_t pid, SecCompEnhanceDataParcel& enhanceParcel)
{
    SecCompEnhanceData enhanceData;
    int32_t res = PrivacySecCompEnhanceAgent::GetInstance().GetSecCompEnhance(pid, enhanceData);
    if (res != RET_SUCCESS) {
        ACCESSTOKEN_LOG_WARN(LABEL, "pid: %{public}d get enhance failed ", pid);
        return res;
    }

    enhanceParcel.enhanceData = enhanceData;
    return RET_SUCCESS;
}

int32_t PrivacyManagerService::GetSpecialSecCompEnhance(const std::string& bundleName,
    std::vector<SecCompEnhanceDataParcel>& enhanceParcelList)
{
    std::vector<SecCompEnhanceData> enhanceList;
    PrivacySecCompEnhanceAgent::GetInstance().GetSpecialSecCompEnhance(bundleName, enhanceList);
    for (const auto& enhance : enhanceList) {
        SecCompEnhanceDataParcel parcel;
        parcel.enhanceData = enhance;
        enhanceParcelList.emplace_back(parcel);
    }

    return RET_SUCCESS;
}
#endif

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
    for (size_t index = 0; index < result.bundleRecords[0].permissionRecords.size(); index++) {
        infos.append(R"(  "permissionRecord": [)");
        infos.append("\n");
        infos.append(R"(    "bundleName": )" + result.bundleRecords[0].bundleName + ",\n");
        infos.append(R"(    "isRemote": )" + std::to_string(result.bundleRecords[0].isRemote) + ",\n");
        infos.append(R"(    "permissionName": ")" + result.bundleRecords[0].permissionRecords[index].permissionName +
                    R"(")" + ",\n");
        time_t lastAccessTime = static_cast<time_t>(result.bundleRecords[0].permissionRecords[index].lastAccessTime);
        infos.append(R"(    "lastAccessTime": )" + std::to_string(lastAccessTime) + ",\n");
        infos.append(R"(    "lastAccessDuration": )" +
                    std::to_string(result.bundleRecords[0].permissionRecords[index].lastAccessDuration) + ",\n");
        infos.append(R"(    "accessCount": ")" +
                    std::to_string(result.bundleRecords[0].permissionRecords[index].accessCount) + R"(")" + ",\n");
        infos.append("  ]");
        infos.append("\n");
    }
    dprintf(fd, "%s\n", infos.c_str());
    return ERR_OK;
}

int32_t PrivacyManagerService::Dump(int32_t fd, const std::vector<std::u16string>& args)
{
    if (fd < 0) {
        ACCESSTOKEN_LOG_ERROR(LABEL, "Dump fd invalid value");
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
    return PermissionRecordManager::GetInstance().UnRegisterPermActiveStatusCallback(callback);
}

bool PrivacyManagerService::IsAllowedUsingPermission(AccessTokenID tokenId, const std::string& permissionName)
{
    ACCESSTOKEN_LOG_INFO(LABEL, "tokenId: %{public}d, permissionName: %{public}s", tokenId, permissionName.c_str());
    return PermissionRecordManager::GetInstance().IsAllowedUsingPermission(tokenId, permissionName);
}

int32_t PrivacyManagerService::SetMutePolicy(uint32_t policyType, uint32_t callerType, bool isMute)
{
    ACCESSTOKEN_LOG_INFO(LABEL, "CallerType: %{public}d, isMute: %{public}d", callerType, isMute);
    return PermissionRecordManager::GetInstance().SetMutePolicy(
        static_cast<PolicyType>(policyType), static_cast<CallerType>(callerType), isMute);
}

int32_t PrivacyManagerService::GetPermissionUsedTypeInfos(const AccessTokenID tokenId,
    const std::string& permissionName, std::vector<PermissionUsedTypeInfoParcel>& resultsParcel)
{
    ACCESSTOKEN_LOG_INFO(LABEL, "tokenId: %{public}d, permissionName: %{public}s", tokenId, permissionName.c_str());

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
    ACCESSTOKEN_LOG_INFO(LABEL, "systemAbilityId is %{public}d", systemAbilityId);
#ifdef COMMON_EVENT_SERVICE_ENABLE
    if (systemAbilityId == COMMON_EVENT_SERVICE_ID) {
        PrivacyCommonEventSubscriber::RegisterEvent();
        return;
    }
#endif //COMMON_EVENT_SERVICE_ENABLE

    if (systemAbilityId == SCREENLOCK_SERVICE_ID) {
        LibraryLoader loader(SCREENLOCK_MANAGER_LIBPATH);
        ScreenLockManagerAccessLoaderInterface* screenlockManagerLoader =
            loader.GetObject<ScreenLockManagerAccessLoaderInterface>();
        if (screenlockManagerLoader != nullptr) {
            PermissionRecordManager::GetInstance().SetLockScreenStatus(screenlockManagerLoader->IsScreenLocked());
        }
        return;
    }
}

bool PrivacyManagerService::Initialize()
{
    PermissionRecordManager::GetInstance().Init();
#ifdef EVENTHANDLER_ENABLE
    eventRunner_ = AppExecFwk::EventRunner::Create(true);
    if (!eventRunner_) {
        ACCESSTOKEN_LOG_ERROR(LABEL, "failed to create a recvRunner.");
        return false;
    }
    eventHandler_ = std::make_shared<AccessEventHandler>(eventRunner_);
    ActiveStatusCallbackManager::GetInstance().InitEventHandler(eventHandler_);
#endif
    return true;
}
} // namespace AccessToken
} // namespace Security
} // namespace OHOS
