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

#include "permission_record_manager.h"

#include <algorithm>
#include <cinttypes>
#include <dlfcn.h>
#include <numeric>

#include "accesstoken_kit.h"
#include "accesstoken_log.h"
#include "active_status_callback_manager.h"
#include "constant.h"
#include "constant_common.h"
#include "data_translator.h"
#include "i_state_change_callback.h"
#include "iservice_registry.h"
#include "permission_record_repository.h"
#include "permission_used_record_cache.h"
#include "privacy_error.h"
#include "privacy_field_const.h"
#include "state_change_callback_proxy.h"
#include "system_ability_definition.h"
#include "time_util.h"
#include "want.h"

using StartAbilityFunc = int32_t (*)(const OHOS::AAFwk::Want& want, void* callerToken);

using SetMuteCallbackFunc = int32_t (*)(void* callback);
using IsCameraMutedFunc = bool (*)();
using GetCameraServiceCallbackStubFunc = void* (*)();
using DelCameraServiceCallbackStubFunc = void (*)(void* cameraServiceCallbackStub);
using RegisterApplicationStateObserverFunc = int32_t (*)(void* observer);
using UnregisterApplicationStateObserverFunc = int32_t (*)(void* observer);
using GetForegroundApplicationsFunc = void* (*)(std::vector<OHOS::Security::AccessToken::PrivacyAppStateData>& list);
using GetApplicationStateObserverStubFunc = void* (*)();
using DelApplicationStateObserverStubFunc = void (*)(void* applicationStateObserverStub);
using SetMicStateChangeCallbackFunc = int32_t (*)(void* callback);
using IsMicrophoneMuteFunc = bool (*)();
using GetAudioRoutingManagerListenerStubFunc = void* (*)();
using DelAudioRoutingManagerListenerStubFunc = void (*)(void* audioRoutingManagerListenerStub);
using RegisterWindowManagerAgentFunc = bool (*)(
    OHOS::Security::AccessToken::PrivacyWindowManagerAgentType type, void* windowManagerAgent);
using UnregisterWindowManagerAgentFunc = bool (*)(
    OHOS::Security::AccessToken::PrivacyWindowManagerAgentType type, void* windowManagerAgent);
using GetWindowManagerPrivacyAgentFunc = void* (*)();
using DelGetWindowManagerPrivacyAgentFunc = void (*)(void* windowManagerAgent);
namespace OHOS {
namespace Security {
namespace AccessToken {
namespace {
static constexpr OHOS::HiviewDFX::HiLogLabel LABEL = {
    LOG_CORE, SECURITY_DOMAIN_PRIVACY, "PermissionRecordManager"
};
static const std::string DEFAULT_DEVICEID = "0";
static const std::string FIELD_COUNT_NUMBER = "count";
constexpr const char* CAMERA_PERMISSION_NAME = "ohos.permission.CAMERA";
constexpr const char* MICROPHONE_PERMISSION_NAME = "ohos.permission.MICROPHONE";
static const std::string PERMISSION_MANAGER_BUNDLE_NAME = "com.ohos.permissionmanager";
static const std::string PERMISSION_MANAGER_DIALOG_ABILITY = "com.ohos.permissionmanager.GlobalExtAbility";
static const std::string RESOURCE_KEY = "ohos.sensitive.resource";
const std::string SENSITIVE_MANAGER_PATH = "libsensitive_manager_service.z.so";
}
PermissionRecordManager& PermissionRecordManager::GetInstance()
{
    static PermissionRecordManager instance;
    return instance;
}

PermissionRecordManager::PermissionRecordManager() : deleteTaskWorker_("DeleteRecord"), hasInited_(false) {}

PermissionRecordManager::~PermissionRecordManager()
{
    if (!hasInited_) {
        return;
    }
    deleteTaskWorker_.Stop();
    hasInited_ = false;
    Unregister();
    UnLoadSensitiveLib();
}

bool PermissionRecordManager::LoadSensitiveLib()
{
    std::lock_guard<std::mutex> lock(handlerMutex_);
    if (handler_ == nullptr) {
        dlerror();
        handler_ = dlopen(SENSITIVE_MANAGER_PATH.c_str(), RTLD_LAZY);
        if (handler_ == nullptr) {
            ACCESSTOKEN_LOG_ERROR(LABEL, "open sensitivelib fail");
            return false;
        }
        ACCESSTOKEN_LOG_DEBUG(LABEL, "open sensitivelib success");
    }
    ACCESSTOKEN_LOG_DEBUG(LABEL, "sensitivelib is already opened");
    return true;
}

bool PermissionRecordManager::UnLoadSensitiveLib()
{
    std::lock_guard<std::mutex> lock(handlerMutex_);
    if (handler_ == nullptr) {
        ACCESSTOKEN_LOG_ERROR(LABEL, "sensitivelib handler is nullptr");
        return false;
    }
    ACCESSTOKEN_LOG_DEBUG(LABEL, "dlclose called");
    dlclose(handler_);
    handler_ = nullptr;
    return true;
}

void PermissionRecordManager::AddRecord(const PermissionRecord& record)
{
    Utils::UniqueWriteGuard<Utils::RWLock> lk(this->rwLock_);
    ACCESSTOKEN_LOG_INFO(LABEL,
        "add record: tokenId %{public}d, opCode %{public}d, status: %{public}d, timestamp: %{public}" PRId64,
        record.tokenId, record.opCode, record.status, record.timestamp);
    PermissionUsedRecordCache::GetInstance().AddRecordToBuffer(record);
}

int32_t PermissionRecordManager::GetPermissionRecord(AccessTokenID tokenId, const std::string& permissionName,
    int32_t successCount, int32_t failCount, PermissionRecord& record)
{
    HapTokenInfo tokenInfo;
    if (AccessTokenKit::GetHapTokenInfo(tokenId, tokenInfo) != Constant::SUCCESS) {
        ACCESSTOKEN_LOG_ERROR(LABEL, "invalid tokenId(%{public}d)", tokenId);
        return PrivacyError::ERR_TOKENID_NOT_EXIST;
    }
    int32_t opCode;
    if (!Constant::TransferPermissionToOpcode(permissionName, opCode)) {
        ACCESSTOKEN_LOG_ERROR(LABEL, "invalid (%{public}s)", permissionName.c_str());
        return PrivacyError::ERR_PERMISSION_NOT_EXIST;
    }
    if (successCount == 0 && failCount == 0) {
        record.status = PERM_INACTIVE;
    } else {
        record.status = IsForegroundApp(tokenId);
    }
    record.tokenId = tokenId;
    record.accessCount = successCount;
    record.rejectCount = failCount;
    record.opCode = opCode;
    record.timestamp = TimeUtil::GetCurrentTimestamp();
    record.accessDuration = 0;
    ACCESSTOKEN_LOG_DEBUG(LABEL, "record status: %{public}d", record.status);
    return Constant::SUCCESS;
}

int32_t PermissionRecordManager::AddPermissionUsedRecord(AccessTokenID tokenId, const std::string& permissionName,
    int32_t successCount, int32_t failCount)
{
    ExecuteDeletePermissionRecordTask();

    PermissionRecord record;
    int32_t result = GetPermissionRecord(tokenId, permissionName, successCount, failCount, record);
    if (result != Constant::SUCCESS) {
        return result;
    }

    if (record.status == PERM_INACTIVE) {
        return PrivacyError::ERR_PARAM_INVALID;
    }

    AddRecord(record);
    return Constant::SUCCESS;
}

void PermissionRecordManager::RemovePermissionUsedRecords(AccessTokenID tokenId, const std::string& deviceID)
{
    // only support remove by tokenId(local)
    std::string device = GetDeviceId(tokenId);
    if (device.empty()) {
        ACCESSTOKEN_LOG_ERROR(LABEL, "invalid tokenId = %{public}d", tokenId);
        return;
    }

    if (!deviceID.empty() && device != deviceID) {
        ACCESSTOKEN_LOG_ERROR(LABEL, "deviceID mismatch");
        return;
    }

    Utils::UniqueWriteGuard<Utils::RWLock> lk(this->rwLock_);
    PermissionUsedRecordCache::GetInstance().RemoveRecords(tokenId); // remove from cache and database
}

int32_t PermissionRecordManager::GetPermissionUsedRecords(
    const PermissionUsedRequest& request, PermissionUsedResult& result)
{
    ExecuteDeletePermissionRecordTask();

    if (!request.isRemote && !GetRecordsFromLocalDB(request, result)) {
        ACCESSTOKEN_LOG_ERROR(LABEL, "Failed to GetRecordsFromLocalDB");
        return  PrivacyError::ERR_PARAM_INVALID;
    }
    return Constant::SUCCESS;
}

int32_t PermissionRecordManager::GetPermissionUsedRecordsAsync(
    const PermissionUsedRequest& request, const sptr<OnPermissionUsedRecordCallback>& callback)
{
    auto task = [request, callback]() {
        ACCESSTOKEN_LOG_INFO(LABEL, "GetPermissionUsedRecordsAsync task called");
        PermissionUsedResult result;
        int32_t retCode = PermissionRecordManager::GetInstance().GetPermissionUsedRecords(request, result);
        callback->OnQueried(retCode, result);
    };
    std::thread recordThread(task);
    recordThread.detach();
    return Constant::SUCCESS;
}

void PermissionRecordManager::GetLocalRecordTokenIdList(std::set<AccessTokenID>& tokenIdList)
{
    std::vector<GenericValues> results;
    {
        Utils::UniqueWriteGuard<Utils::RWLock> lk(this->rwLock_);
        // find tokenId from cache
        PermissionUsedRecordCache::GetInstance().FindTokenIdList(tokenIdList);
        // find tokenId from database
        PermissionRecordRepository::GetInstance().GetAllRecordValuesByKey(PrivacyFiledConst::FIELD_TOKEN_ID, results);
    }
    for (const auto& res : results) {
        tokenIdList.emplace(res.GetInt(PrivacyFiledConst::FIELD_TOKEN_ID));
    }
}

bool PermissionRecordManager::GetRecordsFromLocalDB(const PermissionUsedRequest& request, PermissionUsedResult& result)
{
    GenericValues andConditionValues;
    GenericValues orConditionValues;
    if (DataTranslator::TranslationIntoGenericValues(request, andConditionValues, orConditionValues)
        != Constant::SUCCESS) {
        ACCESSTOKEN_LOG_ERROR(LABEL, "query time or flag is invalid");
        return false;
    }

    std::set<AccessTokenID> tokenIdList;
    if (request.tokenId == 0) {
        GetLocalRecordTokenIdList(tokenIdList);
    } else {
        tokenIdList.emplace(request.tokenId);
    }
    ACCESSTOKEN_LOG_DEBUG(LABEL, "GetLocalRecordTokenIdList.size = %{public}zu", tokenIdList.size());
    Utils::UniqueWriteGuard<Utils::RWLock> lk(this->rwLock_);
    for (const auto& tokenId : tokenIdList) {
        andConditionValues.Put(PrivacyFiledConst::FIELD_TOKEN_ID, static_cast<int32_t>(tokenId));
        std::vector<GenericValues> findRecordsValues;
        PermissionUsedRecordCache::GetInstance().GetRecords(request.permissionList,
            andConditionValues, orConditionValues, findRecordsValues); // find records from cache and database
        andConditionValues.Remove(PrivacyFiledConst::FIELD_TOKEN_ID);
        BundleUsedRecord bundleRecord;
        if (!CreateBundleUsedRecord(tokenId, bundleRecord)) {
            continue;
        }
        if (!findRecordsValues.empty()) {
            GetRecords(request.flag, findRecordsValues, bundleRecord, result);
        }
        if (!bundleRecord.permissionRecords.empty()) {
            result.bundleRecords.emplace_back(bundleRecord);
        }
    }
    return true;
}

bool PermissionRecordManager::CreateBundleUsedRecord(const AccessTokenID tokenId, BundleUsedRecord& bundleRecord)
{
    HapTokenInfo tokenInfo;
    if (AccessTokenKit::GetHapTokenInfo(tokenId, tokenInfo) != Constant::SUCCESS) {
        ACCESSTOKEN_LOG_ERROR(LABEL, "GetHapTokenInfo failed");
        return false;
    }
    bundleRecord.tokenId = tokenId;
    bundleRecord.isRemote = false;
    bundleRecord.deviceId = GetDeviceId(tokenId);
    bundleRecord.bundleName = tokenInfo.bundleName;
    return true;
}

void PermissionRecordManager::GetRecords(
    int32_t flag, std::vector<GenericValues> recordValues, BundleUsedRecord& bundleRecord, PermissionUsedResult& result)
{
    std::vector<PermissionUsedRecord> permissionRecords;
    for (auto it = recordValues.rbegin(); it != recordValues.rend(); ++it) {
        GenericValues record = *it;
        PermissionUsedRecord tmpPermissionRecord;
        int64_t timestamp = record.GetInt64(PrivacyFiledConst::FIELD_TIMESTAMP);
        result.beginTimeMillis = ((result.beginTimeMillis == 0) || (timestamp < result.beginTimeMillis)) ?
            timestamp : result.beginTimeMillis;
        result.endTimeMillis = (timestamp > result.endTimeMillis) ? timestamp : result.endTimeMillis;

        record.Put(PrivacyFiledConst::FIELD_FLAG, flag);
        if (DataTranslator::TranslationGenericValuesIntoPermissionUsedRecord(record, tmpPermissionRecord)
            != Constant::SUCCESS) {
            ACCESSTOKEN_LOG_ERROR(LABEL, "Failed to transform opcode(%{public}d) into permission",
                record.GetInt(PrivacyFiledConst::FIELD_OP_CODE));
            continue;
        }

        auto iter = std::find_if(permissionRecords.begin(), permissionRecords.end(),
            [tmpPermissionRecord](const PermissionUsedRecord& rec) {
            return tmpPermissionRecord.permissionName == rec.permissionName;
        });
        if (iter != permissionRecords.end()) {
            UpdateRecords(flag, tmpPermissionRecord, *iter);
        } else {
            permissionRecords.emplace_back(tmpPermissionRecord);
        }
    }
    bundleRecord.permissionRecords = permissionRecords;
}

void PermissionRecordManager::UpdateRecords(
    int32_t flag, const PermissionUsedRecord& inBundleRecord, PermissionUsedRecord& outBundleRecord)
{
    outBundleRecord.accessCount += inBundleRecord.accessCount;
    outBundleRecord.rejectCount += inBundleRecord.rejectCount;
    if (inBundleRecord.lastAccessTime > outBundleRecord.lastAccessTime) {
        outBundleRecord.lastAccessTime = inBundleRecord.lastAccessTime;
        outBundleRecord.lastAccessDuration = inBundleRecord.lastAccessDuration;
    }
    outBundleRecord.lastRejectTime = (inBundleRecord.lastRejectTime > outBundleRecord.lastRejectTime) ?
        inBundleRecord.lastRejectTime : outBundleRecord.lastRejectTime;

    if (flag == 0) {
        return;
    }
    if (inBundleRecord.lastAccessTime > 0 && outBundleRecord.accessRecords.size() < Constant::MAX_DETAIL_RECORD) {
        outBundleRecord.accessRecords.emplace_back(inBundleRecord.accessRecords[0]);
    }
    if (inBundleRecord.lastRejectTime > 0 && outBundleRecord.rejectRecords.size() < Constant::MAX_DETAIL_RECORD) {
        outBundleRecord.rejectRecords.emplace_back(inBundleRecord.rejectRecords[0]);
    }
}

void PermissionRecordManager::ExecuteDeletePermissionRecordTask()
{
    if (deleteTaskWorker_.GetCurTaskNum() > 1) {
        ACCESSTOKEN_LOG_INFO(LABEL, "Already has delete task!");
        return;
    }

    auto deleteRecordsTask = [this]() {
        ACCESSTOKEN_LOG_DEBUG(LABEL, "DeletePermissionRecord task called");
        DeletePermissionRecord(Constant::RECORD_DELETE_TIME);
    };
    deleteTaskWorker_.AddTask(deleteRecordsTask);
}

int32_t PermissionRecordManager::DeletePermissionRecord(int32_t days)
{
    Utils::UniqueWriteGuard<Utils::RWLock> lk(this->rwLock_);
    GenericValues countValue;
    PermissionRecordRepository::GetInstance().CountRecordValues(countValue);
    int64_t total = countValue.GetInt64(FIELD_COUNT_NUMBER);
    if (total > Constant::MAX_TOTAL_RECORD) {
        uint32_t excessiveSize = total - Constant::MAX_TOTAL_RECORD;
        if (!PermissionRecordRepository::GetInstance().DeleteExcessiveSizeRecordValues(excessiveSize)) {
            return Constant::FAILURE;
        }
    }
    GenericValues andConditionValues;
    int64_t deleteTimestamp = TimeUtil::GetCurrentTimestamp() - days;
    andConditionValues.Put(PrivacyFiledConst::FIELD_TIMESTAMP_END, deleteTimestamp);
    if (!PermissionRecordRepository::GetInstance().DeleteExpireRecordsValues(andConditionValues)) {
        return Constant::FAILURE;
    }
    return Constant::SUCCESS;
}

bool PermissionRecordManager::HasStarted(const PermissionRecord& record)
{
    std::lock_guard<std::mutex> lock(startRecordListMutex_);
    bool hasStarted = std::any_of(startRecordList_.begin(), startRecordList_.end(),
        [record](const auto& rec) { return (rec.opCode == record.opCode) && (rec.tokenId == record.tokenId); });
    if (hasStarted) {
        ACCESSTOKEN_LOG_ERROR(LABEL, "tokenId(%{public}d), opCode(%{public}d) has been started.",
            record.tokenId, record.opCode);
    }

    return hasStarted;
}

void PermissionRecordManager::FindRecordsToUpdateAndExecuted(uint32_t tokenId,
    ActiveChangeType status, std::vector<std::string>& permList, std::vector<std::string>& camPermList)
{
    std::lock_guard<std::mutex> lock(startRecordListMutex_);
    for (auto it = startRecordList_.begin(); it != startRecordList_.end(); ++it) {
        if ((it->tokenId == tokenId) && ((it->status) != status)) {
            std::string perm;
            Constant::TransferOpcodeToPermission(it->opCode, perm);
            if (!GetGlobalSwitchStatus(perm)) {
                continue;
            }

            // app use camera background without float window
            bool isShow = IsFlowWindowShow(tokenId);
            if ((perm == CAMERA_PERMISSION_NAME) && (status == PERM_ACTIVE_IN_BACKGROUND) && (!isShow)) {
                ACCESSTOKEN_LOG_INFO(LABEL, "camera float window is close!");
                camPermList.emplace_back(perm);
                continue;
            }
            permList.emplace_back(perm);
            int64_t curStamp = TimeUtil::GetCurrentTimestamp();
            // update accessDuration and store in database
            it->accessDuration = curStamp - it->timestamp;
            AddRecord(*it);

            // update status to input, accessDuration to 0 and timestamp to now in cache
            it->status = status;
            it->accessDuration = 0;
            it->timestamp = curStamp;
            ACCESSTOKEN_LOG_DEBUG(LABEL, "tokenId %{public}d get target permission %{public}s.", tokenId, perm.c_str());
        }
    }
}

/*
 * when foreground change background or background change foreground，change accessDuration and store in database,
 * change status and accessDuration and timestamp in cache
*/
void PermissionRecordManager::NotifyAppStateChange(AccessTokenID tokenId, ActiveChangeType status)
{
    ACCESSTOKEN_LOG_INFO(LABEL, "tokenId %{public}d, status %{public}d", tokenId, status);
    std::vector<std::string> permList;
    std::vector<std::string> camPermList;
    // find permissions from startRecordList_ by tokenId which status diff from currStatus
    FindRecordsToUpdateAndExecuted(tokenId, status, permList, camPermList);

    if (!camPermList.empty()) {
        ExecuteCameraCallbackAsync(tokenId);
    }
    // each permission sends a status change notice
    for (const auto& perm : permList) {
        CallbackExecute(tokenId, perm, status);
    }
}

void PermissionRecordManager::AddRecordToStartList(const PermissionRecord& record)
{
    std::lock_guard<std::mutex> lock(startRecordListMutex_);
    startRecordList_.emplace_back(record);
}

bool PermissionRecordManager::GetRecordFromStartList(uint32_t tokenId,  int32_t opCode, PermissionRecord& record)
{
    std::lock_guard<std::mutex> lock(startRecordListMutex_);
    for (auto it = startRecordList_.begin(); it != startRecordList_.end(); ++it) {
        if ((it->opCode == opCode) && (it->tokenId == tokenId)) {
            return DelRecordFromStartList(it, record);
        }
    }
    return false;
}

bool PermissionRecordManager::DelRecordFromStartList(
    std::vector<PermissionRecord>::iterator it, PermissionRecord& record)
{
    record = *it;
    record.accessDuration = TimeUtil::GetCurrentTimestamp() - record.timestamp;
    startRecordList_.erase(it);
    if ((startRecordList_.empty()) && (!ActiveStatusCallbackManager::GetInstance().HasCallback())) {
        if (!UnLoadSensitiveLib()) {
            ACCESSTOKEN_LOG_ERROR(LABEL, "UnLoadSensitiveLib failed");
            return ERR_SERVICE_ABNORMAL;
        }
    }
    return true;
}

void PermissionRecordManager::CallbackExecute(
    AccessTokenID tokenId, const std::string& permissionName, int32_t status)
{
    ACCESSTOKEN_LOG_INFO(LABEL, "entry ExecuteCallbackAsync, int32_t status is %{public}d", status);
    ActiveStatusCallbackManager::GetInstance().ExecuteCallbackAsync(
        tokenId, permissionName, GetDeviceId(tokenId), (ActiveChangeType)status);
}

bool PermissionRecordManager::GetGlobalSwitchStatus(const std::string& permissionName)
{
    bool isOpen = true;
    std::lock_guard<std::mutex> lock(handlerMutex_);
    // only manage camera and microphone global switch now, other default true
    if (permissionName == MICROPHONE_PERMISSION_NAME) {
        auto isMicrophoneMute = reinterpret_cast<IsCameraMutedFunc>(dlsym(handler_, "IsMicrophoneMute"));
        if (isMicrophoneMute == nullptr) {
            ACCESSTOKEN_LOG_ERROR(LABEL, "isMicrophoneMute is nullptr");
            return false;
        }
        isOpen = !isMicrophoneMute();
    } else if (permissionName == CAMERA_PERMISSION_NAME) {
        auto isCameraMuted = reinterpret_cast<IsCameraMutedFunc>(dlsym(handler_, "IsCameraMuted"));
        if (isCameraMuted == nullptr) {
            ACCESSTOKEN_LOG_ERROR(LABEL, "isCameraMuted is nullptr");
            return false;
        }
        isOpen = !isCameraMuted();
    }

    ACCESSTOKEN_LOG_INFO(LABEL, "permission is %{public}s, status is %{public}d", permissionName.c_str(), isOpen);
    return isOpen;
}

/*
 * StartUsing when close and choose open, update status to foreground or background from inactive
 * StartUsing when open and choose close, update status to inactive and store in database
 */
void PermissionRecordManager::SavePermissionRecords(
    const std::string& permissionName, PermissionRecord& record, bool switchStatus)
{
    int64_t curStamp = TimeUtil::GetCurrentTimestamp();
    if (switchStatus) {
        ACCESSTOKEN_LOG_INFO(LABEL, "global switch is open, update record from inactive");
        // no need to store in database when status from inactive to foreground or background
        record.status = IsForegroundApp(record.tokenId);
        record.timestamp = curStamp;
    } else {
        ACCESSTOKEN_LOG_INFO(LABEL, "global switch is close, update record to inactive");
        if (record.status != PERM_INACTIVE) {
            // update accessDuration and store in database
            record.accessDuration = curStamp - record.timestamp;
            AddRecord(record);
            // update status to input, accessDuration to 0 and timestamp to now in cache
            record.status = PERM_INACTIVE;
            record.accessDuration = 0;
            record.timestamp = curStamp;
        }
    }
    CallbackExecute(record.tokenId, permissionName, record.status);
}

void PermissionRecordManager::NotifyMicChange(bool switchStatus)
{
    ACCESSTOKEN_LOG_INFO(LABEL, "===========OnMicStateChange(%{public}d)", switchStatus);
    for (auto it = startRecordList_.begin(); it != startRecordList_.end(); ++it) {
        if ((it->opCode) != Constant::OP_MICROPHONE) {
            continue;
        }
        SavePermissionRecords("ohos.permission.MICROPHONE", *it, switchStatus);
    }
}

void PermissionRecordManager::NotifyCameraChange(bool switchStatus)
{
    ACCESSTOKEN_LOG_INFO(LABEL, "=========OnCameraStateChange(%{public}d)", switchStatus);
    for (auto it = startRecordList_.begin(); it != startRecordList_.end(); ++it) {
        if ((it->opCode) != Constant::OP_CAMERA) {
            continue;
        }
        SavePermissionRecords("ohos.permission.CAMERA", *it, switchStatus);
    }
}

bool PermissionRecordManager::ShowGlobalDialog(const std::string& permissionName)
{
    StartAbilityFunc startAbility;
    {
        std::lock_guard<std::mutex> lock(handlerMutex_);
        startAbility = reinterpret_cast<StartAbilityFunc>(dlsym(handler_, "StartAbility"));
        if (startAbility == nullptr) {
            ACCESSTOKEN_LOG_ERROR(LABEL, "startAbility is nullptr");
            return false;
        }
    }
    std::string resource;
    if (permissionName == CAMERA_PERMISSION_NAME) {
        resource = "camera";
    } else if (permissionName == MICROPHONE_PERMISSION_NAME) {
        resource = "microphone";
    } else {
        ACCESSTOKEN_LOG_INFO(LABEL, "invalid permissionName(%{public}s).", permissionName.c_str());
        return true;
    }

    AAFwk::Want want;
    want.SetElementName(PERMISSION_MANAGER_BUNDLE_NAME, PERMISSION_MANAGER_DIALOG_ABILITY);
    want.SetParam(RESOURCE_KEY, resource);
    ErrCode err = startAbility(want, nullptr);
    if (err != ERR_OK) {
        ACCESSTOKEN_LOG_ERROR(LABEL, "Fail to StartAbility, err:%{public}d", err);
        return false;
    }
    return true;
}

int32_t PermissionRecordManager::StartUsingPermission(AccessTokenID tokenId, const std::string& permissionName)
{
    if (!LoadSensitiveLib()) {
        return PrivacyError::ERR_MALLOC_FAILED;
    }
    if (!Register()) {
        return PrivacyError::ERR_MALLOC_FAILED;
    }
    int32_t accessCount = 1;
    int32_t failCount = 0;

    PermissionRecord record = { 0 };
    int32_t result = GetPermissionRecord(tokenId, permissionName, accessCount, failCount, record);
    if (result != Constant::SUCCESS) {
        return result;
    }

    if (HasStarted(record)) {
        return PrivacyError::ERR_PERMISSION_ALREADY_START_USING;
    }

    if (!GetGlobalSwitchStatus(permissionName)) {
        if (!ShowGlobalDialog(permissionName)) {
            ACCESSTOKEN_LOG_ERROR(LABEL, "show permission dialog failed.");
            return ERR_SERVICE_ABNORMAL;
        }
        record.status = PERM_INACTIVE;
    } else {
        CallbackExecute(tokenId, permissionName, record.status);
    }
    AddRecordToStartList(record);
    return Constant::SUCCESS;
}

void PermissionRecordManager::SetCameraCallback(sptr<IRemoteObject> callback)
{
    std::lock_guard<std::mutex> lock(cameraMutex_);
    cameraCallback_ = callback;
}

void PermissionRecordManager::ExecuteCameraCallbackAsync(AccessTokenID tokenId)
{
    ACCESSTOKEN_LOG_DEBUG(LABEL, "entry");
    sptr<IRemoteObject> cameraCallback = nullptr;
    {
        std::lock_guard<std::mutex> lock(cameraMutex_);
        cameraCallback = cameraCallback_;
        if (cameraCallback == nullptr) {
            ACCESSTOKEN_LOG_ERROR(LABEL, "cameraCallback is null");
            return;
        }
    }
    auto callback = iface_cast<IStateChangeCallback>(cameraCallback);
    if (callback != nullptr) {
        ACCESSTOKEN_LOG_INFO(LABEL, "callback excute changeType %{public}d", PERM_INACTIVE);
        callback->StateChangeNotify(tokenId, false);
        SetCameraCallback(nullptr);
    }
    ACCESSTOKEN_LOG_DEBUG(LABEL, "The callback execution is complete");
}

/*
 * when camera float window is not show, notice camera service to use StopUsingPermission
 */
void PermissionRecordManager::NotifyCameraFloatWindowChange(AccessTokenID tokenId, bool isShowing)
{
    camFloatWindowShowing_ = isShowing;
    floatWindowTokenId_ = tokenId;
    if (!IsForegroundApp(tokenId) && !isShowing) {
        ACCESSTOKEN_LOG_INFO(LABEL, "camera float window is close!");
        ExecuteCameraCallbackAsync(tokenId);
    } else {
        ACCESSTOKEN_LOG_INFO(LABEL, "camera float window is show!");
    }
}

int32_t PermissionRecordManager::StartUsingPermission(AccessTokenID tokenId, const std::string& permissionName,
    const sptr<IRemoteObject>& callback)
{
    if (!LoadSensitiveLib()) {
        return PrivacyError::ERR_MALLOC_FAILED;
    }
    if (permissionName != CAMERA_PERMISSION_NAME) {
        ACCESSTOKEN_LOG_ERROR(LABEL, "ERR_PARAM_INVALID is null.");
        return PrivacyError::ERR_PARAM_INVALID;
    }
    if (!Register()) {
        return PrivacyError::ERR_MALLOC_FAILED;
    }

    int32_t accessCount = 1;
    int32_t failCount = 0;

    PermissionRecord record = { 0 };
    int32_t result = GetPermissionRecord(tokenId, permissionName, accessCount, failCount, record);
    if (result != Constant::SUCCESS) {
        return result;
    }

    if (HasStarted(record)) {
        return PrivacyError::ERR_PERMISSION_ALREADY_START_USING;
    }

    if (!GetGlobalSwitchStatus(permissionName)) {
        if (!ShowGlobalDialog(permissionName)) {
            ACCESSTOKEN_LOG_ERROR(LABEL, "show permission dialog failed.");
            return ERR_SERVICE_ABNORMAL;
        }
        record.status = PERM_INACTIVE;
    } else {
        CallbackExecute(tokenId, permissionName, record.status);
    }
    AddRecordToStartList(record);
    SetCameraCallback(callback);
    return Constant::SUCCESS;
}

int32_t PermissionRecordManager::StopUsingPermission(AccessTokenID tokenId, const std::string& permissionName)
{
    ExecuteDeletePermissionRecordTask();

    if (AccessTokenKit::GetTokenTypeFlag(tokenId) != TOKEN_HAP) {
        ACCESSTOKEN_LOG_ERROR(LABEL, "invalid tokenId(%{public}d)", tokenId);
        return PrivacyError::ERR_TOKENID_NOT_EXIST;
    }
    int32_t opCode;
    if (!Constant::TransferPermissionToOpcode(permissionName, opCode)) {
        ACCESSTOKEN_LOG_ERROR(LABEL, "invalid permission(%{public}s)", permissionName.c_str());
        return PrivacyError::ERR_PERMISSION_NOT_EXIST;
    }

    PermissionRecord record;
    if (!GetRecordFromStartList(tokenId, opCode, record)) {
        return PrivacyError::ERR_PERMISSION_NOT_START_USING;
    }

    if (record.status != PERM_INACTIVE) {
        AddRecord(record);
        CallbackExecute(tokenId, permissionName, PERM_INACTIVE);
    }
    return Constant::SUCCESS;
}

void PermissionRecordManager::PermListToString(const std::vector<std::string>& permList)
{
    std::string permStr;
    permStr = accumulate(permList.begin(), permList.end(), std::string(" "));

    ACCESSTOKEN_LOG_INFO(LABEL, "permStr =%{public}s", permStr.c_str());
}

int32_t PermissionRecordManager::PermissionListFilter(
    const std::vector<std::string>& listSrc, std::vector<std::string>& listRes)
{
    PermissionDef permissionDef;
    std::set<std::string> permSet;
    for (const auto& permissionName : listSrc) {
        if (AccessTokenKit::GetDefPermission(permissionName, permissionDef) == Constant::SUCCESS &&
            permSet.count(permissionName) == 0) {
            listRes.emplace_back(permissionName);
            permSet.insert(permissionName);
            continue;
        }
        ACCESSTOKEN_LOG_ERROR(LABEL, "permission %{public}s invalid!", permissionName.c_str());
    }
    if ((listRes.empty()) && (!listSrc.empty())) {
        ACCESSTOKEN_LOG_ERROR(LABEL, "valid permission size is 0!");
        return PrivacyError::ERR_PARAM_INVALID;
    }
    PermListToString(listRes);
    return Constant::SUCCESS;
}

bool PermissionRecordManager::IsAllowedUsingPermission(AccessTokenID tokenId, const std::string& permissionName)
{
    if (!LoadSensitiveLib()) {
        return PrivacyError::ERR_MALLOC_FAILED;
    }
    // when app in foreground, return true, only for camera and microphone
    if ((permissionName != CAMERA_PERMISSION_NAME) && (permissionName != MICROPHONE_PERMISSION_NAME)) {
        return false;
    }

    HapTokenInfo tokenInfo;
    if (AccessTokenKit::GetTokenTypeFlag(tokenId) != TOKEN_HAP) {
        ACCESSTOKEN_LOG_ERROR(LABEL, "invalid tokenId(%{public}d)", tokenId);
        return false;
    }

    int32_t status = IsForegroundApp(tokenId);
    ACCESSTOKEN_LOG_INFO(LABEL, "tokenId %{public}d, status is %{public}d", tokenId, status);

    if (status == ActiveChangeType::PERM_ACTIVE_IN_FOREGROUND) {
        return true;
    } else if (permissionName == CAMERA_PERMISSION_NAME) {
        return IsFlowWindowShow(tokenId);
    }
    return false;
}

int32_t PermissionRecordManager::RegisterPermActiveStatusCallback(
    const std::vector<std::string>& permList, const sptr<IRemoteObject>& callback)
{
    if (!LoadSensitiveLib()) {
        return PrivacyError::ERR_MALLOC_FAILED;
    }
    std::vector<std::string> permListRes;
    int32_t res = PermissionListFilter(permList, permListRes);
    if (res != Constant::SUCCESS) {
        return res;
    }
    return ActiveStatusCallbackManager::GetInstance().AddCallback(permListRes, callback);
}

int32_t PermissionRecordManager::UnRegisterPermActiveStatusCallback(const sptr<IRemoteObject>& callback)
{
    int32_t res = ActiveStatusCallbackManager::GetInstance().RemoveCallback(callback);
    if ((!ActiveStatusCallbackManager::GetInstance().HasCallback()) && (startRecordList_.empty())) {
        if (!UnLoadSensitiveLib()) {
            ACCESSTOKEN_LOG_ERROR(LABEL, "UnLoadSensitiveLib failed");
            return ERR_SERVICE_ABNORMAL;
        }
    }
    return res;
}

std::string PermissionRecordManager::GetDeviceId(AccessTokenID tokenId)
{
    HapTokenInfo tokenInfo;
    if (AccessTokenKit::GetHapTokenInfo(tokenId, tokenInfo) != Constant::SUCCESS) {
        return "";
    }
    if (tokenInfo.deviceID == DEFAULT_DEVICEID) { // local
        return ConstantCommon::GetLocalDeviceId();
    }
    return tokenInfo.deviceID;
}

int32_t PermissionRecordManager::IsForegroundApp(AccessTokenID tokenId)
{
    GetForegroundApplicationsFunc getForegroundApplications;
    {
        std::lock_guard<std::mutex> lock(handlerMutex_);
        getForegroundApplications = reinterpret_cast<GetForegroundApplicationsFunc>(
            dlsym(handler_, "GetForegroundApplications"));
        if (getForegroundApplications == nullptr) {
            ACCESSTOKEN_LOG_ERROR(LABEL, "getForegroundApplications is nullptr");
            return PrivacyError::ERR_SERVICE_ABNORMAL;
        }
    }
    int32_t status = PERM_INACTIVE;
    HapTokenInfo tokenInfo;
    if (AccessTokenKit::GetHapTokenInfo(tokenId, tokenInfo) != Constant::SUCCESS) {
        ACCESSTOKEN_LOG_ERROR(LABEL, "invalid tokenId(%{public}d)", tokenId);
        return status;
    }
    status = PERM_ACTIVE_IN_BACKGROUND;
    std::vector<PrivacyAppStateData> foreGroundAppList;
    getForegroundApplications(foreGroundAppList);

    if (std::any_of(foreGroundAppList.begin(), foreGroundAppList.end(),
        [=](const auto& foreGroundApp) { return foreGroundApp.bundleName == tokenInfo.bundleName; })) {
        status = PERM_ACTIVE_IN_FOREGROUND;
    }
    return status;
}

bool PermissionRecordManager::IsFlowWindowShow(AccessTokenID tokenId)
{
    return floatWindowTokenId_ == tokenId && camFloatWindowShowing_;
}

bool PermissionRecordManager::Register()
{
    std::lock_guard<std::mutex> lock(handlerMutex_);
    if (RegisterAudioRoutingManagerListener() && RegisterApplicationStateObserver() &&
        RegisterCameraServiceCallback() && RegisterWindowManagerPrivacyAgent()) {
        return true;
    }
    return false;
}

bool PermissionRecordManager::RegisterAudioRoutingManagerListener()
{
    if (micMuteCallback_ == nullptr) {
        auto getAudioRoutingManagerListenerStub = reinterpret_cast<GetAudioRoutingManagerListenerStubFunc>(
            dlsym(handler_, "GetAudioRoutingManagerListenerStub"));
        if (getAudioRoutingManagerListenerStub == nullptr) {
            ACCESSTOKEN_LOG_ERROR(LABEL, "dlsym failed getAudioRoutingManagerListenerStub is nullptr");
            return false;
        }
        micMuteCallback_ = getAudioRoutingManagerListenerStub();
        if (micMuteCallback_ == nullptr) {
            return false;
        }
        auto setMicStateChangeCallback = reinterpret_cast<SetMicStateChangeCallbackFunc>(
            dlsym(handler_, "SetMicStateChangeCallback"));
        if (setMicStateChangeCallback == nullptr) {
            ACCESSTOKEN_LOG_ERROR(LABEL, "dlsym failed setMicStateChangeCallback is nullptr");
            auto delAudioRoutingManagerListenerStub = reinterpret_cast<DelAudioRoutingManagerListenerStubFunc>(
                dlsym(handler_, "DelAudioRoutingManagerListenerStub"));
            if (delAudioRoutingManagerListenerStub == nullptr) {
                ACCESSTOKEN_LOG_ERROR(LABEL, "dlsym failed delAudioRoutingManagerListenerStub is nullptr");
                return false;
            }
            delAudioRoutingManagerListenerStub(micMuteCallback_);
            micMuteCallback_ = nullptr;
            return false;
        }
        setMicStateChangeCallback(micMuteCallback_);
    }
    return true;
}

bool PermissionRecordManager::RegisterApplicationStateObserver()
{
    if (appStateCallback_ == nullptr) {
        auto getApplicationStateObserverStub = reinterpret_cast<GetApplicationStateObserverStubFunc>(
            dlsym(handler_, "GetApplicationStateObserverStub"));
        if (getApplicationStateObserverStub == nullptr) {
            ACCESSTOKEN_LOG_ERROR(LABEL, "dlsym failed getApplicationStateObserverStub is nullptr");
            return false;
        }
        appStateCallback_ = getApplicationStateObserverStub();
        if (appStateCallback_ == nullptr) {
            return false;
        }
        auto registerApplicationStateObserver = reinterpret_cast<RegisterApplicationStateObserverFunc>(
            dlsym(handler_, "RegisterApplicationStateObserver"));
        if (registerApplicationStateObserver == nullptr) {
            ACCESSTOKEN_LOG_ERROR(LABEL, "dlsym failed registerApplicationStateObserver is nullptr");
            auto delApplicationStateObserverStub = reinterpret_cast<DelApplicationStateObserverStubFunc>(
                dlsym(handler_, "DelApplicationStateObserverStub"));
            if (delApplicationStateObserverStub == nullptr) {
                ACCESSTOKEN_LOG_ERROR(LABEL, "dlsym failed delApplicationStateObserverStub is nullptr");
                return false;
            }
            delApplicationStateObserverStub(appStateCallback_);
            appStateCallback_ = nullptr;
            return false;
        }
        registerApplicationStateObserver(appStateCallback_);
    }
    return true;
}

bool PermissionRecordManager::RegisterCameraServiceCallback()
{
    if (camMuteCallback_ == nullptr) {
        auto getCameraServiceCallbackStub = reinterpret_cast<GetCameraServiceCallbackStubFunc>(
            dlsym(handler_, "GetCameraServiceCallbackStub"));
        if (getCameraServiceCallbackStub == nullptr) {
            ACCESSTOKEN_LOG_ERROR(LABEL, "dlsym failed getCameraServiceCallbackStub is nullptr");
            return false;
        }
        camMuteCallback_ = getCameraServiceCallbackStub();
        if (camMuteCallback_ == nullptr) {
            return false;
        }
        auto setMuteCallback = reinterpret_cast<SetMuteCallbackFunc>(dlsym(handler_, "SetMuteCallback"));
        if (setMuteCallback == nullptr) {
            ACCESSTOKEN_LOG_ERROR(LABEL, "dlsym failed setMuteCallback is nullptr");
            auto delCameraServiceCallbackStub = reinterpret_cast<DelCameraServiceCallbackStubFunc>(
                dlsym(handler_, "DelCameraServiceCallbackStub"));
            if (delCameraServiceCallbackStub == nullptr) {
                ACCESSTOKEN_LOG_ERROR(LABEL, "dlsym failed delCameraServiceCallbackStub is nullptr");
                return false;
            }
            delCameraServiceCallbackStub(camMuteCallback_);
            camMuteCallback_ = nullptr;
            return false;
        }
        setMuteCallback(camMuteCallback_);
    }
    return true;
}

bool PermissionRecordManager::RegisterWindowManagerPrivacyAgent()
{
    if (floatWindowCallback_ == nullptr) {
        auto getWindowManagerPrivacyAgent = reinterpret_cast<GetWindowManagerPrivacyAgentFunc>(
            dlsym(handler_, "GetWindowManagerPrivacyAgent"));
        if (getWindowManagerPrivacyAgent == nullptr) {
            ACCESSTOKEN_LOG_ERROR(LABEL, "dlsym failed getWindowManagerPrivacyAgent is nullptr");
            return false;
        }
        floatWindowCallback_ = getWindowManagerPrivacyAgent();
        if (floatWindowCallback_ == nullptr) {
            return false;
        }
        auto registerWindowManagerAgent = reinterpret_cast<RegisterWindowManagerAgentFunc>(
            dlsym(handler_, "RegisterWindowManagerAgent"));
        if (registerWindowManagerAgent == nullptr) {
            ACCESSTOKEN_LOG_ERROR(LABEL, "dlsym failed registerWindowManagerAgent is nullptr");
            auto delGetWindowManagerPrivacyAgent = reinterpret_cast<DelGetWindowManagerPrivacyAgentFunc>(
                dlsym(handler_, "DelGetWindowManagerPrivacyAgent"));
            if (delGetWindowManagerPrivacyAgent == nullptr) {
                ACCESSTOKEN_LOG_ERROR(LABEL, "dlsym failed delGetWindowManagerPrivacyAgent is nullptr");
                return false;
            }
            delGetWindowManagerPrivacyAgent(floatWindowCallback_);
            floatWindowCallback_ = nullptr;
            return false;
        }
        registerWindowManagerAgent(
            PrivacyWindowManagerAgentType::WINDOW_MANAGER_AGENT_TYPE_CAMERA_FLOAT, floatWindowCallback_);
    }
    return true;
}

void PermissionRecordManager::Unregister()
{
    std::lock_guard<std::mutex> lock(handlerMutex_);
    if (appStateCallback_ != nullptr) {
        auto unregisterApplicationStateObserver = reinterpret_cast<UnregisterApplicationStateObserverFunc>(
            dlsym(handler_, "UnregisterApplicationStateObserver"));
        if (unregisterApplicationStateObserver == nullptr) {
            ACCESSTOKEN_LOG_ERROR(LABEL, "unregisterApplicationStateObserver is nullptr");
            return;
        }
        unregisterApplicationStateObserver(appStateCallback_);
        auto delApplicationStateObserverStub = reinterpret_cast<DelApplicationStateObserverStubFunc>(
            dlsym(handler_, "DelApplicationStateObserverStub"));
        if (delApplicationStateObserverStub == nullptr) {
            ACCESSTOKEN_LOG_ERROR(LABEL, "dlsym failed delApplicationStateObserverStub is nullptr");
            return;
        }
        delApplicationStateObserverStub(appStateCallback_);
        appStateCallback_ = nullptr;
    }
    if (floatWindowCallback_ == nullptr) {
        auto unregisterWindowManagerAgent = reinterpret_cast<UnregisterWindowManagerAgentFunc>(
            dlsym(handler_, "UnregisterWindowManagerAgent"));
        if (unregisterWindowManagerAgent == nullptr) {
            ACCESSTOKEN_LOG_ERROR(LABEL, "unregisterWindowManagerAgent is nullptr");
            return;
        }
        unregisterWindowManagerAgent(
            PrivacyWindowManagerAgentType::WINDOW_MANAGER_AGENT_TYPE_CAMERA_FLOAT, floatWindowCallback_);
        auto delGetWindowManagerPrivacyAgent = reinterpret_cast<DelGetWindowManagerPrivacyAgentFunc>(
            dlsym(handler_, "DelGetWindowManagerPrivacyAgent"));
        if (delGetWindowManagerPrivacyAgent == nullptr) {
            ACCESSTOKEN_LOG_ERROR(LABEL, "dlsym failed delGetWindowManagerPrivacyAgent is nullptr");
            return;
        }
        delGetWindowManagerPrivacyAgent(floatWindowCallback_);
        floatWindowCallback_ = nullptr;
    }
}

void PermissionRecordManager::OnAppMgrRemoteDiedHandle()
{
    auto delApplicationStateObserverStub = reinterpret_cast<DelApplicationStateObserverStubFunc>(
        dlsym(handler_, "DelApplicationStateObserverStub"));
    if (delApplicationStateObserverStub == nullptr) {
        ACCESSTOKEN_LOG_ERROR(LABEL, "dlsym failed delApplicationStateObserverStub is nullptr");
        return;
    }
    delApplicationStateObserverStub(appStateCallback_);
    appStateCallback_ = nullptr;
}

void PermissionRecordManager::OnAudioMgrRemoteDiedHandle()
{
    auto delAudioRoutingManagerListenerStub = reinterpret_cast<DelAudioRoutingManagerListenerStubFunc>(
        dlsym(handler_, "DelAudioRoutingManagerListenerStub"));
    if (delAudioRoutingManagerListenerStub == nullptr) {
        ACCESSTOKEN_LOG_ERROR(LABEL, "dlsym failed delAudioRoutingManagerListenerStub is nullptr");
        return;
    }
    delAudioRoutingManagerListenerStub(micMuteCallback_);
    micMuteCallback_ = nullptr;
}

void PermissionRecordManager::OnCameraMgrRemoteDiedHandle()
{
    auto delCameraServiceCallbackStub = reinterpret_cast<DelCameraServiceCallbackStubFunc>(
        dlsym(handler_, "DelCameraServiceCallbackStub"));
    if (delCameraServiceCallbackStub == nullptr) {
        ACCESSTOKEN_LOG_ERROR(LABEL, "dlsym failed delCameraServiceCallbackStub is nullptr");
        return;
    }
    delCameraServiceCallbackStub(camMuteCallback_);
    camMuteCallback_ = nullptr;
}

void PermissionRecordManager::OnWindowMgrRemoteDiedHandle()
{
    auto delGetWindowManagerPrivacyAgent = reinterpret_cast<DelGetWindowManagerPrivacyAgentFunc>(
        dlsym(handler_, "DelGetWindowManagerPrivacyAgent"));
    if (delGetWindowManagerPrivacyAgent == nullptr) {
        ACCESSTOKEN_LOG_ERROR(LABEL, "dlsym failed delGetWindowManagerPrivacyAgent is nullptr");
        return;
    }
    delGetWindowManagerPrivacyAgent(floatWindowCallback_);
    floatWindowCallback_ = nullptr;
}

void PermissionRecordManager::Init()
{
    if (hasInited_) {
        return;
    }
    ACCESSTOKEN_LOG_INFO(LABEL, "init");
    deleteTaskWorker_.Start(1);
    hasInited_ = true;
}
} // namespace AccessToken
} // namespace Security
} // namespace OHOS