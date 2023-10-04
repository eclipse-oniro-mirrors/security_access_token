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
#include <numeric>

#include "ability_manager_privacy_client.h"
#include "accesstoken_kit.h"
#include "accesstoken_log.h"
#include "active_status_callback_manager.h"
#include "app_manager_privacy_client.h"
#include "audio_manager_privacy_client.h"
#include "camera_manager_privacy_client.h"
#include "constant.h"
#include "constant_common.h"
#include "data_translator.h"
#include "i_state_change_callback.h"
#include "iservice_registry.h"
#include "lockscreen_status_observer.h"
#include "permission_record_repository.h"
#include "permission_used_record_cache.h"
#include "privacy_error.h"
#include "privacy_field_const.h"
#include "refbase.h"
#include "screenlock_manager.h"
#include "state_change_callback_proxy.h"
#include "system_ability_definition.h"
#include "time_util.h"
#include "want.h"
#ifdef CAMERA_FLOAT_WINDOW_ENABLE
#include "window_manager_privacy_client.h"
#endif

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
}

void PermissionRecordManager::AddRecord(const PermissionRecord& record)
{
    Utils::UniqueWriteGuard<Utils::RWLock> lk(this->rwLock_);
    ACCESSTOKEN_LOG_INFO(LABEL,
        "add record: tokenId %{public}d, opCode %{public}d, status: %{public}d, lockscreenStatus: %{public}d, timestamp: %{public}" PRId64,
        record.tokenId, record.opCode, record.status, record.lockscreenStatus, record.timestamp);
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
        record.status = GetAppStatus(tokenId);
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
        Utils::UniqueReadGuard<Utils::RWLock> lk(this->rwLock_);
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
    if (DataTranslator::TranslationIntoGenericValues(request, andConditionValues)
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
    Utils::UniqueReadGuard<Utils::RWLock> lk(this->rwLock_);
    for (const auto& tokenId : tokenIdList) {
        andConditionValues.Put(PrivacyFiledConst::FIELD_TOKEN_ID, static_cast<int32_t>(tokenId));
        std::vector<GenericValues> findRecordsValues;
        PermissionUsedRecordCache::GetInstance().GetRecords(request.permissionList,
            andConditionValues, findRecordsValues); // find records from cache and database
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

int32_t PermissionRecordManager::DeletePermissionRecord(int64_t days)
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

bool PermissionRecordManager::AddRecordIfNotStarted(const PermissionRecord& record)
{
    std::lock_guard<std::mutex> lock(startRecordListMutex_);
    bool hasStarted = std::any_of(startRecordList_.begin(), startRecordList_.end(),
        [record](const auto& rec) { return (rec.opCode == record.opCode) && (rec.tokenId == record.tokenId); });
    if (hasStarted) {
        ACCESSTOKEN_LOG_ERROR(LABEL, "tokenId(%{public}d), opCode(%{public}d) has been started.",
            record.tokenId, record.opCode);
    } else {
        ACCESSTOKEN_LOG_DEBUG(LABEL, "tokenId(%{public}d), opCode(%{public}d) add record.",
            record.tokenId, record.opCode);
        startRecordList_.emplace_back(record);
        AddRecord(record); // when start using permission, add a instananeous record which accessDuration is 0
    }
    return hasStarted;
}

void PermissionRecordManager::FindRecordsToUpdateAndExecuted(uint32_t tokenId, ActiveChangeType status)
{
    std::lock_guard<std::mutex> lock(startRecordListMutex_);
    int32_t lockscreenStatus = ScreenLock::ScreenLockManager::GetInstance()->IsScreenLocked()
        ? LockscreenStatusChangeType::PERM_ACTIVE_IN_LOCKED : LockscreenStatusChangeType::PERM_ACTIVE_IN_UNLOCK;
    if (lockscreenStatus == LockscreenStatusChangeType::PERM_ACTIVE_IN_LOCKED) {
        ACCESSTOKEN_LOG_WARN(LABEL, "current lockscreen status is : %{public}d", lockscreenStatus);
        return;
    }
    std::vector<std::string> permList;
    std::vector<std::string> camPermList;
    for (auto it = startRecordList_.begin(); it != startRecordList_.end(); ++it) {
        if ((it->tokenId == tokenId) && ((it->status) != status)) {
            std::string perm;
            Constant::TransferOpcodeToPermission(it->opCode, perm);
            if (!GetGlobalSwitchStatus(perm)) {
                continue;
            }

            // app use camera background without float window
            bool isShow = true;
#ifdef CAMERA_FLOAT_WINDOW_ENABLE
            isShow = IsFlowWindowShow(tokenId);
#endif
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
            it->lockscreenStatus = lockscreenStatus;
            it->accessDuration = 0;
            it->timestamp = curStamp;
            ACCESSTOKEN_LOG_DEBUG(LABEL, "tokenId %{public}d get target permission %{public}s.", tokenId, perm.c_str());
        }
    }
    if (!camPermList.empty()) {
        ExecuteCameraCallbackAsync(tokenId);
    }
    // each permission sends a status change notice
    for (const auto& perm : permList) {
        CallbackExecute(tokenId, perm, status);
    }
}

/*
 * when foreground change background or background change foreground，change accessDuration and store in database,
 * change status and accessDuration and timestamp in cache
*/
void PermissionRecordManager::NotifyAppStateChange(AccessTokenID tokenId, ActiveChangeType status)
{
    ACCESSTOKEN_LOG_INFO(LABEL, "tokenId %{public}d, status %{public}d", tokenId, status);
    // find permissions from startRecordList_ by tokenId which status diff from currStatus
    FindRecordsToUpdateAndExecuted(tokenId, status);
}

void PermissionRecordManager::GenerateRecordsWhenScreenStatusChanged(LockscreenStatusChangeType lockscreenStatus)
{
    std::lock_guard<std::mutex> lock(startRecordListMutex_);
    for (auto it = startRecordList_.begin(); it != startRecordList_.end(); ++it) {
        std::string perm;
        Constant::TransferOpcodeToPermission(it->opCode, perm);
        if (!GetGlobalSwitchStatus(perm)) {
            continue;
        }
        int64_t curStamp = TimeUtil::GetCurrentTimestamp();
        // update accessDuration and store in databases
        it->accessDuration = curStamp - it->timestamp;
        /**
         * In screen lock and screen unlock scenarios, do not modify the status of the front-end and back-end of
         *  startRecordList_. The logic of changing the screen lock status is not processed. Therefore,
         *  permission access records are not generated repeatedly.
         */
        int32_t tempStatus = it->status;
        if (lockscreenStatus == LockscreenStatusChangeType::PERM_ACTIVE_IN_UNLOCK) {
            it->status = ActiveChangeType::PERM_ACTIVE_IN_BACKGROUND;
        }
        AddRecord(*it);

        // update lockscreenStatus to input, accessDuration to 0 and timestamp to now in cache
        it->status = tempStatus;
        it->lockscreenStatus = lockscreenStatus;
        it->accessDuration = 0;
        it->timestamp = curStamp;
        ACCESSTOKEN_LOG_DEBUG(LABEL, "get target permission %{public}s.", perm.c_str());
    }
}

void PermissionRecordManager::NotifyLockscreenStatusChange(LockscreenStatusChangeType lockscreenStatus)
{
    ACCESSTOKEN_LOG_INFO(LABEL, "lockscreenStatus %{public}d", lockscreenStatus);
    GenerateRecordsWhenScreenStatusChanged(lockscreenStatus);
}

void PermissionRecordManager::RemoveRecordFromStartList(const PermissionRecord& record)
{
    ACCESSTOKEN_LOG_DEBUG(LABEL, "tokenId %{public}d, opCode %{public}d", record.tokenId, record.opCode);
    std::lock_guard<std::mutex> lock(startRecordListMutex_);
    for (auto it = startRecordList_.begin(); it != startRecordList_.end(); ++it) {
        if ((it->opCode == record.opCode) && (it->tokenId == record.tokenId)) {
            startRecordList_.erase(it);
            return;
        }
    }
}

void PermissionRecordManager::UpdateRecord(const PermissionRecord& record)
{
    ACCESSTOKEN_LOG_DEBUG(LABEL, "tokenId %{public}d, opCode %{public}d", record.tokenId, record.opCode);
    std::lock_guard<std::mutex> lock(startRecordListMutex_);
    for (auto it = startRecordList_.begin(); it != startRecordList_.end(); ++it) {
        if ((it->opCode == record.opCode) && (it->tokenId == record.tokenId)) {
            it->status = record.status;
            return;
        }
    }
}

bool PermissionRecordManager::GetRecordFromStartList(uint32_t tokenId,  int32_t opCode, PermissionRecord& record)
{
    std::lock_guard<std::mutex> lock(startRecordListMutex_);
    for (auto it = startRecordList_.begin(); it != startRecordList_.end(); ++it) {
        if ((it->opCode == opCode) && (it->tokenId == tokenId)) {
            record = *it;
            record.accessDuration = TimeUtil::GetCurrentTimestamp() - record.timestamp;
            startRecordList_.erase(it);
            return true;
        }
    }
    return false;
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
    // only manage camera and microphone global switch now, other default true
    if (permissionName == MICROPHONE_PERMISSION_NAME) {
        isOpen = !AudioManagerPrivacyClient::GetInstance().IsMicrophoneMute();
    } else if (permissionName == CAMERA_PERMISSION_NAME) {
        isOpen = !CameraManagerPrivacyClient::GetInstance().IsCameraMuted();
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
        record.status = GetAppStatus(record.tokenId);
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
    ErrCode err = AbilityManagerPrivacyClient::GetInstance().StartAbility(want, nullptr);
    if (err != ERR_OK) {
        ACCESSTOKEN_LOG_ERROR(LABEL, "Fail to StartAbility, err:%{public}d", err);
        return false;
    }
    return true;
}

int32_t PermissionRecordManager::StartUsingPermission(AccessTokenID tokenId, const std::string& permissionName)
{
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

    if (AddRecordIfNotStarted(record)) {
        return PrivacyError::ERR_PERMISSION_ALREADY_START_USING;
    }

    if (!GetGlobalSwitchStatus(permissionName)) {
        if (!ShowGlobalDialog(permissionName)) {
            ACCESSTOKEN_LOG_ERROR(LABEL, "show permission dialog failed.");
            RemoveRecordFromStartList(record);
            return ERR_SERVICE_ABNORMAL;
        }
        record.status = PERM_INACTIVE;
    } else {
        CallbackExecute(tokenId, permissionName, record.status);
    }
    UpdateRecord(record);
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
    auto task = [tokenId, this]() {
        ACCESSTOKEN_LOG_INFO(LABEL, "ExecuteCameraCallbackAsync task called");
        sptr<IRemoteObject> cameraCallback = nullptr;
        {
            std::lock_guard<std::mutex> lock(this->cameraMutex_);
            cameraCallback = this->cameraCallback_;
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
    };
    std::thread executeThread(task);
    executeThread.detach();
    ACCESSTOKEN_LOG_DEBUG(LABEL, "The callback execution is complete");
}

int32_t PermissionRecordManager::StartUsingPermission(AccessTokenID tokenId, const std::string& permissionName,
    const sptr<IRemoteObject>& callback)
{
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

    if (AddRecordIfNotStarted(record)) {
        return PrivacyError::ERR_PERMISSION_ALREADY_START_USING;
    }

    if (!GetGlobalSwitchStatus(permissionName)) {
        if (!ShowGlobalDialog(permissionName)) {
            ACCESSTOKEN_LOG_ERROR(LABEL, "show permission dialog failed.");
            RemoveRecordFromStartList(record);
            return ERR_SERVICE_ABNORMAL;
        }
        record.status = PERM_INACTIVE;
    } else {
        CallbackExecute(tokenId, permissionName, record.status);
    }
    SetCameraCallback(callback);
    UpdateRecord(record);
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
    // when app in foreground, return true, only for camera and microphone
    if ((permissionName != CAMERA_PERMISSION_NAME) && (permissionName != MICROPHONE_PERMISSION_NAME)) {
        return false;
    }

    HapTokenInfo tokenInfo;
    if (AccessTokenKit::GetTokenTypeFlag(tokenId) != TOKEN_HAP) {
        ACCESSTOKEN_LOG_ERROR(LABEL, "invalid tokenId(%{public}d)", tokenId);
        return false;
    }

    int32_t status = GetAppStatus(tokenId);
    ACCESSTOKEN_LOG_INFO(LABEL, "tokenId %{public}d, status is %{public}d", tokenId, status);

    if (status == ActiveChangeType::PERM_ACTIVE_IN_FOREGROUND) {
        return true;
    }
#ifdef CAMERA_FLOAT_WINDOW_ENABLE
    if (permissionName == CAMERA_PERMISSION_NAME) {
        return IsFlowWindowShow(tokenId);
    }
#endif
    return false;
}

int32_t PermissionRecordManager::RegisterPermActiveStatusCallback(
    const std::vector<std::string>& permList, const sptr<IRemoteObject>& callback)
{
    std::vector<std::string> permListRes;
    int32_t res = PermissionListFilter(permList, permListRes);
    if (res != Constant::SUCCESS) {
        return res;
    }
    return ActiveStatusCallbackManager::GetInstance().AddCallback(permListRes, callback);
}

int32_t PermissionRecordManager::UnRegisterPermActiveStatusCallback(const sptr<IRemoteObject>& callback)
{
    return ActiveStatusCallbackManager::GetInstance().RemoveCallback(callback);
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

int32_t PermissionRecordManager::GetAppStatus(AccessTokenID tokenId)
{
    int32_t status = PERM_INACTIVE;
    HapTokenInfo tokenInfo;
    if (AccessTokenKit::GetHapTokenInfo(tokenId, tokenInfo) != Constant::SUCCESS) {
        ACCESSTOKEN_LOG_ERROR(LABEL, "invalid tokenId(%{public}d)", tokenId);
        return status;
    }
    status = PERM_ACTIVE_IN_BACKGROUND;
    std::vector<AppStateData> foreGroundAppList;
    AppManagerPrivacyClient::GetInstance().GetForegroundApplications(foreGroundAppList);
    if (std::any_of(foreGroundAppList.begin(), foreGroundAppList.end(),
        [=](const auto& foreGroundApp) { return foreGroundApp.bundleName == tokenInfo.bundleName; })) {
        status = PERM_ACTIVE_IN_FOREGROUND;
        std::vector<AppStateData> foreGroundAppList;
        AppManagerPrivacyClient::GetInstance().GetForegroundApplications(foreGroundAppList);
    }
    return status;
}

bool PermissionRecordManager::Register()
{
    // microphone mute
    {
        std::lock_guard<std::mutex> lock(micMuteMutex_);
        if (micMuteCallback_ == nullptr) {
            micMuteCallback_ = new(std::nothrow) AudioRoutingManagerListenerStub();
            if (micMuteCallback_ == nullptr) {
                ACCESSTOKEN_LOG_ERROR(LABEL, "register micMuteCallback failed.");
                return false;
            }
            AudioManagerPrivacyClient::GetInstance().SetMicStateChangeCallback(micMuteCallback_);
        }
    }

    // camera mute
    {
        std::lock_guard<std::mutex> lock(camMuteMutex_);
        if (camMuteCallback_ == nullptr) {
            camMuteCallback_ = new(std::nothrow) CameraServiceCallbackStub();
            if (camMuteCallback_ == nullptr) {
                ACCESSTOKEN_LOG_ERROR(LABEL, "register camMuteCallback failed.");
                return false;
            }
            CameraManagerPrivacyClient::GetInstance().SetMuteCallback(camMuteCallback_);
        }
    }

    // app state change callback register
    {
        std::lock_guard<std::mutex> lock(appStateMutex_);
        if (appStateCallback_ == nullptr) {
            appStateCallback_ = new(std::nothrow) ApplicationStateObserverStub();
            if (appStateCallback_ == nullptr) {
                ACCESSTOKEN_LOG_ERROR(LABEL, "register appStateCallback failed.");
                return false;
            }
            AppManagerPrivacyClient::GetInstance().RegisterApplicationStateObserver(appStateCallback_);
        }
    }

    // screen status change callback register
    {
        std::lock_guard<std::mutex> lock(lockscreenStateMutex_);
        LockscreenObserver::RegisterEvent();
    }

#ifdef CAMERA_FLOAT_WINDOW_ENABLE
    // float window status change callback register
    {
        std::lock_guard<std::mutex> lock(floatWinMutex_);
        if (floatWindowCallback_ == nullptr) {
            floatWindowCallback_ = new(std::nothrow) WindowManagerPrivacyAgent();
            if (floatWindowCallback_ == nullptr) {
                ACCESSTOKEN_LOG_ERROR(LABEL, "register floatWindowCallback failed.");
                return false;
            }
            WindowManagerPrivacyClient::GetInstance().RegisterWindowManagerAgent(
                WindowManagerAgentType::WINDOW_MANAGER_AGENT_TYPE_CAMERA_FLOAT, floatWindowCallback_);
        }
    }
#endif
    return true;
}

void PermissionRecordManager::Unregister()
{
    // app state change callback unregister
    {
        std::lock_guard<std::mutex> lock(appStateMutex_);
        if (appStateCallback_ != nullptr) {
            AppManagerPrivacyClient::GetInstance().UnregisterApplicationStateObserver(appStateCallback_);
            appStateCallback_= nullptr;
        }
    }

    // screen state change callback unregister
    {
        std::lock_guard<std::mutex> lock(lockscreenStateMutex_);
        LockscreenObserver::UnRegisterEvent();
    }

#ifdef CAMERA_FLOAT_WINDOW_ENABLE
    // float window status change callback unregister
    {
        std::lock_guard<std::mutex> lock(floatWinMutex_);
        if (floatWindowCallback_ != nullptr) {
            WindowManagerPrivacyClient::GetInstance().UnregisterWindowManagerAgent(
                WindowManagerAgentType::WINDOW_MANAGER_AGENT_TYPE_CAMERA_FLOAT, floatWindowCallback_);
            floatWindowCallback_ = nullptr;
        }
    }
#endif
}

void PermissionRecordManager::OnAppMgrRemoteDiedHandle()
{
    std::lock_guard<std::mutex> lock(appStateMutex_);
    appStateCallback_ = nullptr;
}

void PermissionRecordManager::OnAudioMgrRemoteDiedHandle()
{
    std::lock_guard<std::mutex> lock(micMuteMutex_);
    micMuteCallback_ = nullptr;
}

void PermissionRecordManager::OnCameraMgrRemoteDiedHandle()
{
    std::lock_guard<std::mutex> lock(camMuteMutex_);
    camMuteCallback_ = nullptr;
}

#ifdef CAMERA_FLOAT_WINDOW_ENABLE
/*
 * when camera float window is not show, notice camera service to use StopUsingPermission
 */
void PermissionRecordManager::NotifyCameraFloatWindowChange(AccessTokenID tokenId, bool isShowing)
{
    camFloatWindowShowing_ = isShowing;
    floatWindowTokenId_ = tokenId;
    if ((GetAppStatus(tokenId) == ActiveChangeType::PERM_ACTIVE_IN_BACKGROUND) && !isShowing) {
        ACCESSTOKEN_LOG_INFO(LABEL, "camera float window is close!");
        ExecuteCameraCallbackAsync(tokenId);
    } else {
        ACCESSTOKEN_LOG_INFO(LABEL, "camera float window is show!");
    }
}

void PermissionRecordManager::OnWindowMgrRemoteDiedHandle()
{
    std::lock_guard<std::mutex> lock(floatWinMutex_);
    floatWindowCallback_ = nullptr;
}

bool PermissionRecordManager::IsFlowWindowShow(AccessTokenID tokenId)
{
    return floatWindowTokenId_ == tokenId && camFloatWindowShowing_;
}
#endif

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