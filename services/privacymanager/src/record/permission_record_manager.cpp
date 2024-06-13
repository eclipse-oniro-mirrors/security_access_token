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

#include "permission_record_manager.h"

#include <algorithm>
#include <cinttypes>
#include <numeric>

#include "ability_manager_access_client.h"
#include "access_token.h"
#include "accesstoken_config_policy.h"
#include "accesstoken_kit.h"
#include "accesstoken_log.h"
#include "active_status_callback_manager.h"
#include "app_manager_access_client.h"
#include "audio_manager_privacy_client.h"
#ifdef BGTASKMGR_CONTINUOUS_TASK_ENABLE
#include "background_task_manager_access_client.h"
#include "continuous_task_callback_info.h"
#endif
#include "camera_manager_privacy_client.h"
#include "constant.h"
#include "constant_common.h"
#include "data_translator.h"
#include "i_state_change_callback.h"
#include "iservice_registry.h"
#include "libraryloader.h"
#include "parameter.h"
#include "parcel_utils.h"
#include "permission_record_repository.h"
#include "permission_used_record_cache.h"
#include "power_manager_access_loader.h"
#include "privacy_error.h"
#include "privacy_field_const.h"
#include "refbase.h"
#include "state_change_callback_proxy.h"
#include "system_ability_definition.h"
#include "time_util.h"
#include "want.h"
#ifdef CAMERA_FLOAT_WINDOW_ENABLE
#include "window_manager_loader.h"
#endif

namespace OHOS {
namespace Security {
namespace AccessToken {
namespace {
static constexpr OHOS::HiviewDFX::HiLogLabel LABEL = {
    LOG_CORE, SECURITY_DOMAIN_PRIVACY, "PermissionRecordManager"
};
static const int32_t VALUE_MAX_LEN = 32;
static const std::string DEFAULT_DEVICEID = "0";
static const std::string FIELD_COUNT_NUMBER = "count";
constexpr const char* CAMERA_PERMISSION_NAME = "ohos.permission.CAMERA";
constexpr const char* MICROPHONE_PERMISSION_NAME = "ohos.permission.MICROPHONE";
constexpr const char* EDM_MIC_MUTE_KEY = "persist.edm.mic_disable";
static const std::string DEFAULT_PERMISSION_MANAGER_BUNDLE_NAME = "com.ohos.permissionmanager";
static const std::string DEFAULT_PERMISSION_MANAGER_DIALOG_ABILITY = "com.ohos.permissionmanager.GlobalExtAbility";
static const std::string RESOURCE_KEY = "ohos.sensitive.resource";
static const int32_t DEFAULT_PERMISSION_USED_RECORD_SIZE_MAXIMUM = 500000;
static const int32_t DEFAULT_PERMISSION_USED_RECORD_AGING_TIME = 7;
static const uint32_t NORMAL_TYPE_ADD_VALUE = 1;
static const uint32_t PICKER_TYPE_ADD_VALUE = 2;
static const uint32_t SEC_COMPONENT_TYPE_ADD_VALUE = 4;
std::recursive_mutex g_instanceMutex;
}
PermissionRecordManager& PermissionRecordManager::GetInstance()
{
    static PermissionRecordManager* instance = nullptr;
    if (instance == nullptr) {
        std::lock_guard<std::recursive_mutex> lock(g_instanceMutex);
        if (instance == nullptr) {
            instance = new PermissionRecordManager();
        }
    }
    return *instance;
}

PermissionRecordManager::PermissionRecordManager() : deleteTaskWorker_("DeleteRecord"), hasInited_(false)
{
    bool isEdmMute = false;
    if (!GetMuteParameter(EDM_MIC_MUTE_KEY, isEdmMute)) {
        ACCESSTOKEN_LOG_ERROR(LABEL, "Get param failed");
        return;
    }
    ModifyMuteStatus(MICROPHONE_PERMISSION_NAME, EDM, isEdmMute);
}

PermissionRecordManager::~PermissionRecordManager()
{
    if (!hasInited_) {
        return;
    }
    deleteTaskWorker_.Stop();
    hasInited_ = false;
    Unregister();
}

void PrivacyAppStateObserver::OnForegroundApplicationChanged(const AppStateData &appStateData)
{
    ACCESSTOKEN_LOG_DEBUG(LABEL, "OnChange(accessTokenId=%{public}d, state=%{public}d)",
        appStateData.accessTokenId, appStateData.state);

    uint32_t tokenId = appStateData.accessTokenId;

    ActiveChangeType status = PERM_INACTIVE;
    if (appStateData.state == static_cast<int32_t>(ApplicationState::APP_STATE_FOREGROUND)) {
        status = PERM_ACTIVE_IN_FOREGROUND;
    } else if (appStateData.state == static_cast<int32_t>(ApplicationState::APP_STATE_BACKGROUND)) {
        status = PERM_ACTIVE_IN_BACKGROUND;
    }
    PermissionRecordManager::GetInstance().NotifyAppStateChange(tokenId, status);
}

void PrivacyAppStateObserver::OnApplicationStateChanged(const AppStateData &appStateData)
{
    ACCESSTOKEN_LOG_DEBUG(LABEL, "OnChange(accessTokenId=%{public}d, state=%{public}d)",
        appStateData.accessTokenId, appStateData.state);

    if (appStateData.state == static_cast<int32_t>(ApplicationState::APP_STATE_TERMINATED)) {
        PermissionRecordManager::GetInstance().RemoveRecordFromStartListByToken(appStateData.accessTokenId);
    }
}

void PrivacyAppStateObserver::OnProcessDied(const ProcessData &processData)
{
    ACCESSTOKEN_LOG_DEBUG(LABEL, "OnChange(accessTokenId=%{public}d, state=%{public}d)",
        processData.accessTokenId, processData.state);

    PermissionRecordManager::GetInstance().RemoveRecordFromStartListByToken(processData.accessTokenId);
}

void PrivacyAppManagerDeathCallback::NotifyAppManagerDeath()
{
    ACCESSTOKEN_LOG_INFO(LABEL, "AppManagerDeath called");

    PermissionRecordManager::GetInstance().OnAppMgrRemoteDiedHandle();
}

void PermissionRecordManager::AddRecord(const PermissionRecord& record)
{
    Utils::UniqueWriteGuard<Utils::RWLock> lk(this->rwLock_);
    ACCESSTOKEN_LOG_INFO(LABEL,
        "add record: tokenId %{public}d, opCode %{public}d, status: %{public}d,"
        "lockScreenStatus %{public}d, timestamp %{public}" PRId64 ", type %{public}d",
        record.tokenId, record.opCode, record.status, record.lockScreenStatus, record.timestamp, record.type);
    PermissionUsedRecordCache::GetInstance().AddRecordToBuffer(record);
}

int32_t PermissionRecordManager::GetPermissionRecord(const AddPermParamInfo& info, PermissionRecord& record)
{
    if (AccessTokenKit::GetTokenTypeFlag(info.tokenId) != TOKEN_HAP) {
        ACCESSTOKEN_LOG_DEBUG(LABEL, "Not hap(%{public}d)", info.tokenId);
        return PrivacyError::ERR_PARAM_INVALID;
    }
    int32_t opCode;
    if (!Constant::TransferPermissionToOpcode(info.permissionName, opCode)) {
        ACCESSTOKEN_LOG_ERROR(LABEL, "Invalid perm(%{public}s)", info.permissionName.c_str());
        return PrivacyError::ERR_PERMISSION_NOT_EXIST;
    }
    if ((GetMuteStatus(info.permissionName, EDM)) || (!GetGlobalSwitchStatus(info.permissionName))) {
        record.status = PERM_INACTIVE;
    } else {
        record.status = GetAppStatus(info.tokenId);
    }
    record.lockScreenStatus = GetLockScreenStatus();
    record.tokenId = info.tokenId;
    record.accessCount = info.successCount;
    record.rejectCount = info.failCount;
    record.opCode = opCode;
    record.timestamp = TimeUtil::GetCurrentTimestamp();
    record.accessDuration = 0;
    record.type = info.type;
    ACCESSTOKEN_LOG_DEBUG(LABEL, "record status: %{public}d", record.status);
    return Constant::SUCCESS;
}

void PermissionRecordManager::TransformEnumToBitValue(const PermissionUsedType type, uint32_t& value)
{
    if (type == PermissionUsedType::NORMAL_TYPE) {
        value = NORMAL_TYPE_ADD_VALUE;
    } else if (type == PermissionUsedType::PICKER_TYPE) {
        value = PICKER_TYPE_ADD_VALUE;
    } else if (type == PermissionUsedType::SECURITY_COMPONENT_TYPE) {
        value = SEC_COMPONENT_TYPE_ADD_VALUE;
    }
}

bool PermissionRecordManager::AddOrUpdateUsedTypeIfNeeded(const AccessTokenID tokenId, const int32_t opCode,
    const PermissionUsedType type)
{
    uint32_t inputType = 0;
    TransformEnumToBitValue(type, inputType);

    GenericValues conditionValue;
    conditionValue.Put(PrivacyFiledConst::FIELD_TOKEN_ID, static_cast<int32_t>(tokenId));
    conditionValue.Put(PrivacyFiledConst::FIELD_PERMISSION_CODE, opCode);

    std::vector<GenericValues> results;
    if (!PermissionRecordRepository::GetInstance().Query(
        PermissionUsedRecordDb::DataType::PERMISSION_USED_TYPE, conditionValue, results)) {
        return false;
    }

    if (results.empty()) {
        // empty means there is no permission used type record, add it
        ACCESSTOKEN_LOG_DEBUG(LABEL, "No exsit record, add it.");

        GenericValues recordValue;
        recordValue.Put(PrivacyFiledConst::FIELD_TOKEN_ID, static_cast<int32_t>(tokenId));
        recordValue.Put(PrivacyFiledConst::FIELD_PERMISSION_CODE, opCode);
        recordValue.Put(PrivacyFiledConst::FIELD_USED_TYPE, static_cast<int32_t>(inputType));

        std::vector<GenericValues> recordValues;
        recordValues.emplace_back(recordValue);
        if (!PermissionRecordRepository::GetInstance().Add(
            PermissionUsedRecordDb::DataType::PERMISSION_USED_TYPE, recordValues)) {
            return false;
        }
    } else {
        // not empty means there is permission used type record exsit, update it if needed
        uint32_t dbType = static_cast<uint32_t>(results[0].GetInt(PrivacyFiledConst::FIELD_USED_TYPE));
        ACCESSTOKEN_LOG_DEBUG(LABEL, "Record exsit, type is %{public}u.", dbType);

        if ((dbType & inputType) == inputType) {
            // true means visitTypeEnum has exsits, no need to add
            ACCESSTOKEN_LOG_DEBUG(LABEL, "Used type has add.");
            return true;
        } else {
            results[0].Remove(PrivacyFiledConst::FIELD_USED_TYPE);
            dbType |= inputType;

            // false means visitTypeEnum not exsits, update record
            ACCESSTOKEN_LOG_DEBUG(LABEL, "Used type not add, generate new %{public}u.", dbType);

            GenericValues newValue;
            newValue.Put(PrivacyFiledConst::FIELD_USED_TYPE, static_cast<int32_t>(dbType));
            return PermissionRecordRepository::GetInstance().Update(
                PermissionUsedRecordDb::DataType::PERMISSION_USED_TYPE, newValue, results[0]);
        }
    }

    return true;
}

int32_t PermissionRecordManager::AddPermissionUsedRecord(const AddPermParamInfo& info)
{
    ExecuteDeletePermissionRecordTask();

    if ((info.successCount == 0) && (info.failCount == 0)) {
        return PrivacyError::ERR_PARAM_INVALID;
    }

    PermissionRecord record;
    int32_t result = GetPermissionRecord(info, record);
    if (result != Constant::SUCCESS || record.status == PERM_INACTIVE) {
        return result;
    }

    AddRecord(record);
    return AddOrUpdateUsedTypeIfNeeded(
        info.tokenId, record.opCode, info.type) ? Constant::SUCCESS : Constant::FAILURE;
}

void PermissionRecordManager::RemovePermissionUsedType(AccessTokenID tokenId)
{
    GenericValues conditionValues;
    conditionValues.Put(PrivacyFiledConst::FIELD_TOKEN_ID, static_cast<int32_t>(tokenId));
    PermissionRecordRepository::GetInstance().Remove(
        PermissionUsedRecordDb::DataType::PERMISSION_USED_TYPE, conditionValues);
}

void PermissionRecordManager::RemovePermissionUsedRecords(AccessTokenID tokenId, const std::string& deviceID)
{
    // only support remove by tokenId(local)
    std::string device = GetDeviceId(tokenId);
    if (!deviceID.empty() && device != deviceID) {
        ACCESSTOKEN_LOG_ERROR(LABEL, "deviceID mismatch");
        return;
    }

    Utils::UniqueWriteGuard<Utils::RWLock> lk(this->rwLock_);
    PermissionUsedRecordCache::GetInstance().RemoveRecords(tokenId); // remove from cache and database
    RemovePermissionUsedType(tokenId);

    RemoveRecordFromStartListByToken(tokenId);
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

static void AddDebugLog(const AccessTokenID tokenId, const BundleUsedRecord& bundleRecord, const int32_t currentCount,
    int32_t& totalSuccCount, int32_t& totalFailCount)
{
    int32_t tokenTotalSuccCount = 0;
    int32_t tokenTotalFailCount = 0;
    for (const auto& permissionRecord : bundleRecord.permissionRecords) {
        tokenTotalSuccCount += permissionRecord.accessCount;
        tokenTotalFailCount += permissionRecord.rejectCount;
    }
    ACCESSTOKEN_LOG_INFO(LABEL, "tokenId %{public}d[%{public}s] get %{public}d records, success %{public}d,"
        " failure %{public}d", tokenId, bundleRecord.bundleName.c_str(), currentCount, tokenTotalSuccCount,
        tokenTotalFailCount);
    totalSuccCount += tokenTotalSuccCount;
    totalFailCount += tokenTotalFailCount;
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

    // sumarry don't limit querry data num, detail do
    int32_t dataLimitNum = request.flag == FLAG_PERMISSION_USAGE_DETAIL ? MAX_ACCESS_RECORD_SIZE : recordSizeMaximum_;
    int32_t totalSuccCount = 0;
    int32_t totalFailCount = 0;

    Utils::UniqueReadGuard<Utils::RWLock> lk(this->rwLock_);
    for (const auto& tokenId : tokenIdList) {
        andConditionValues.Put(PrivacyFiledConst::FIELD_TOKEN_ID, static_cast<int32_t>(tokenId));
        std::vector<GenericValues> findRecordsValues;
        PermissionUsedRecordCache::GetInstance().GetRecords(request.permissionList,
            andConditionValues, findRecordsValues, dataLimitNum); // find records from cache and database
        andConditionValues.Remove(PrivacyFiledConst::FIELD_TOKEN_ID);
        uint32_t currentCount = findRecordsValues.size();
        dataLimitNum -= static_cast<int32_t>(currentCount);
        BundleUsedRecord bundleRecord;
        if (!CreateBundleUsedRecord(tokenId, bundleRecord)) {
            continue;
        }

        if (currentCount > 0) {
            GetRecords(request.flag, findRecordsValues, bundleRecord, result);
            // add debug log when get exsit record
            AddDebugLog(tokenId, bundleRecord, currentCount, totalSuccCount, totalFailCount);
        }

        if (!bundleRecord.permissionRecords.empty()) {
            result.bundleRecords.emplace_back(bundleRecord);
        }
    }

    if (request.flag == FLAG_PERMISSION_USAGE_SUMMARY) {
        ACCESSTOKEN_LOG_INFO(LABEL, "total success count is %{public}d, total failure count is %{public}d",
            totalSuccCount, totalFailCount);
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

    if (flag != FLAG_PERMISSION_USAGE_DETAIL) {
        return;
    }
    if (inBundleRecord.lastAccessTime > 0) {
        outBundleRecord.accessRecords.emplace_back(inBundleRecord.accessRecords[0]);
    }
    if (inBundleRecord.lastRejectTime > 0) {
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
        DeletePermissionRecord(recordAgingTime_);
    };
    deleteTaskWorker_.AddTask(deleteRecordsTask);
}

int32_t PermissionRecordManager::DeletePermissionRecord(int32_t days)
{
    int64_t interval = days * Constant::ONE_DAY_MILLISECONDS;
    GenericValues countValue;
    PermissionRecordRepository::GetInstance().CountRecordValues(countValue);
    int64_t total = countValue.GetInt64(FIELD_COUNT_NUMBER);
    if (total > recordSizeMaximum_) {
        uint32_t excessiveSize = static_cast<uint32_t>(total) - static_cast<uint32_t>(recordSizeMaximum_);
        if (!PermissionRecordRepository::GetInstance().DeleteExcessiveSizeRecordValues(excessiveSize)) {
            return Constant::FAILURE;
        }
    }
    GenericValues andConditionValues;
    int64_t deleteTimestamp = TimeUtil::GetCurrentTimestamp() - interval;
    andConditionValues.Put(PrivacyFiledConst::FIELD_TIMESTAMP_END, deleteTimestamp);
    if (!PermissionRecordRepository::GetInstance().DeleteExpireRecordsValues(andConditionValues)) {
        return Constant::FAILURE;
    }
    return Constant::SUCCESS;
}

bool PermissionRecordManager::AddRecordToStartList(const PermissionRecord& record)
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
    }
    return hasStarted;
}

void PermissionRecordManager::ExecuteAndUpdateRecord(uint32_t tokenId, ActiveChangeType status)
{
    std::vector<std::string> permList;
    std::vector<std::string> camPermList;
    std::lock_guard<std::mutex> lock(startRecordListMutex_);
    for (auto it = startRecordList_.begin(); it != startRecordList_.end(); ++it) {
        if ((it->tokenId == tokenId) && ((it->status) != PERM_INACTIVE) && ((it->status) != status)) {
            std::string perm;
            Constant::TransferOpcodeToPermission(it->opCode, perm);
            if ((GetMuteStatus(perm, EDM)) || (!GetGlobalSwitchStatus(perm))) {
                continue;
            }

            // app use camera background without float window
            bool isShow = IsCameraWindowShow(tokenId);
            if ((perm == CAMERA_PERMISSION_NAME) && (status == PERM_ACTIVE_IN_BACKGROUND) && (!isShow)) {
                ACCESSTOKEN_LOG_INFO(LABEL, "camera float window is close!");
                camPermList.emplace_back(perm);
                continue;
            }
            permList.emplace_back(perm);
            int64_t curStamp = TimeUtil::GetCurrentTimestamp();

            // update status to input and timestamp to now in cache
            it->status = status;
            it->timestamp = curStamp;
            ACCESSTOKEN_LOG_DEBUG(LABEL, "tokenId %{public}d get permission %{public}s.", tokenId, perm.c_str());
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
    ExecuteAndUpdateRecord(tokenId, status);
}

void PermissionRecordManager::SetLockScreenStatus(int32_t lockScreenStatus)
{
    ACCESSTOKEN_LOG_INFO(LABEL, "lockScreenStatus %{public}d", lockScreenStatus);
    std::lock_guard<std::mutex> lock(lockScreenStateMutex_);
    lockScreenStatus_ = lockScreenStatus;
}

int32_t PermissionRecordManager::GetLockScreenStatus()
{
    std::lock_guard<std::mutex> lock(lockScreenStateMutex_);
    return lockScreenStatus_;
}

bool PermissionRecordManager::IsScreenOn()
{
    LibraryLoader loader(POWER_MANAGER_LIBPATH);
    PowerManagerLoaderInterface* powerManagerLoader = loader.GetObject<PowerManagerLoaderInterface>();
    if (powerManagerLoader == nullptr) {
        ACCESSTOKEN_LOG_ERROR(LABEL, "Failed to load powermanager so.");
        return false;
    }
    return powerManagerLoader->IsScreenOn();
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

void PermissionRecordManager::RemoveRecordFromStartListByToken(const AccessTokenID tokenId)
{
    ACCESSTOKEN_LOG_INFO(LABEL, "tokenId %{public}d", tokenId);
    bool isUsingCamera = false;
    {
        std::vector<std::string> permList;
        std::lock_guard<std::mutex> lock(startRecordListMutex_);
        for (auto it = startRecordList_.begin(); it != startRecordList_.end();) {
            if (it->tokenId != tokenId) {
                it++;
                continue;
            }
            isUsingCamera = (it->opCode == Constant::OP_CAMERA);
            std::string perm;
            Constant::TransferOpcodeToPermission(it->opCode, perm);
            permList.emplace_back(perm);
            it = startRecordList_.erase(it);
        }
        for (const auto& perm : permList) {
            CallbackExecute(tokenId, perm, PERM_INACTIVE);
        }
    }
    if (isUsingCamera) {
        cameraCallbackMap_.Erase(tokenId);
        UnRegisterWindowCallback(); // unregister window linstener
    }
}

void PermissionRecordManager::RemoveRecordFromStartListByOp(int32_t opCode)
{
    ACCESSTOKEN_LOG_INFO(LABEL, "opCode %{public}d", opCode);
    bool isUsingCamera = (opCode == Constant::OP_CAMERA);
    std::string perm;
    Constant::TransferOpcodeToPermission(opCode, perm);
    {
        std::vector<AccessTokenID> tokenList;
        std::lock_guard<std::mutex> lock(startRecordListMutex_);
        for (auto it = startRecordList_.begin(); it != startRecordList_.end();) {
            if (it->opCode != opCode) {
                it++;
                continue;
            }
            tokenList.emplace_back(it->tokenId);
            it = startRecordList_.erase(it);
        }
        for (size_t i = 0; i < tokenList.size(); ++i) {
            CallbackExecute(tokenList[i], perm, PERM_INACTIVE);
        }
    }
    if (isUsingCamera) {
        UnRegisterWindowCallback(); // unregister window linstener
    }
}

bool PermissionRecordManager::GetRecordFromStartList(uint32_t tokenId,  int32_t opCode, PermissionRecord& record)
{
    std::lock_guard<std::mutex> lock(startRecordListMutex_);
    for (auto it = startRecordList_.begin(); it != startRecordList_.end(); ++it) {
        if ((it->opCode == opCode) && (it->tokenId == tokenId)) {
            it->accessCount = 1;
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
    ACCESSTOKEN_LOG_INFO(LABEL,
        "ExecuteCallbackAsync, tokenId %{public}d using permission %{public}s, status %{public}d",
        tokenId, permissionName.c_str(), status);
    ActiveStatusCallbackManager::GetInstance().ExecuteCallbackAsync(
        tokenId, permissionName, GetDeviceId(tokenId), (ActiveChangeType)status);
}

bool PermissionRecordManager::GetGlobalSwitchStatus(const std::string& permissionName)
{
    bool isOpen = true;
    // only manage camera and microphone global switch now, other default true
    if (permissionName == MICROPHONE_PERMISSION_NAME) {
        isOpen = !isMicMixMute_;
    } else if (permissionName == CAMERA_PERMISSION_NAME) {
        isOpen = !isCamMixMute_;
    }

    ACCESSTOKEN_LOG_INFO(LABEL, "permission is %{public}s, status is %{public}d", permissionName.c_str(), isOpen);
    return isOpen;
}

/*
 * StartUsing when close and choose open, update status to foreground or background from inactive
 * StartUsing when open and choose close, update status to inactive and store in database
 */
void PermissionRecordManager::ExecuteAndUpdateRecordByPerm(const std::string& permissionName, bool switchStatus)
{
    int32_t opCode;
    Constant::TransferPermissionToOpcode(permissionName, opCode);
    std::vector<PermissionRecord> recordList;
    std::lock_guard<std::mutex> lock(startRecordListMutex_);
    for (auto it = startRecordList_.begin(); it != startRecordList_.end(); ++it) {
        PermissionRecord& record = *it;
        if ((record.opCode) != static_cast<int32_t>(opCode)) {
            continue;
        }
        if (switchStatus) {
            ACCESSTOKEN_LOG_INFO(LABEL, "global switch is open, update record from inactive");
            // no need to store in database when status from inactive to foreground or background
            record.status = GetAppStatus(record.tokenId);
        } else {
            ACCESSTOKEN_LOG_INFO(LABEL, "global switch is close, update record to inactive");
            record.status = PERM_INACTIVE;
        }
        recordList.emplace_back(*it);
    }
    // each permission sends a status change notice
    for (const auto& record : recordList) {
        CallbackExecute(record.tokenId, permissionName, record.status);
    }
}

void PermissionRecordManager::NotifyMicChange(bool isMute)
{
    ACCESSTOKEN_LOG_INFO(LABEL, "OnMicStateChange(%{public}d)", isMute);
    if (SetPrivacyMutePolicy(MICROPHONE_PERMISSION_NAME, isMute) != RET_SUCCESS) {
        return;
    }
    // find permissions from startRecordList_ by tokenId which status diff from currStatus
    ExecuteAndUpdateRecordByPerm(MICROPHONE_PERMISSION_NAME, !isMute);
}

void PermissionRecordManager::NotifyCameraChange(bool isMute)
{
    ACCESSTOKEN_LOG_INFO(LABEL, "OnCameraStateChange(%{public}d)", isMute);
    if (SetPrivacyMutePolicy(CAMERA_PERMISSION_NAME, isMute) != RET_SUCCESS) {
        return;
    }

    // find permissions from startRecordList_ by tokenId which status diff from currStatus
    ExecuteAndUpdateRecordByPerm(CAMERA_PERMISSION_NAME, !isMute);
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
    want.SetElementName(globalDialogBundleName_, globalDialogAbilityName_);
    want.SetParam(RESOURCE_KEY, resource);
    ErrCode err = AbilityManagerAccessClient::GetInstance().StartAbility(want, nullptr);
    if (err != ERR_OK) {
        ACCESSTOKEN_LOG_ERROR(LABEL, "Fail to StartAbility, err:%{public}d", err);
        return false;
    }
    return true;
}

int32_t PermissionRecordManager::StartUsingPermission(AccessTokenID tokenId, const std::string& permissionName)
{
    ACCESSTOKEN_LOG_INFO(LABEL, "Entry, tokenId=0x%{public}x, permissionName=%{public}s",
        tokenId, permissionName.c_str());
    if (GetMuteStatus(permissionName, EDM)) {
        ACCESSTOKEN_LOG_ERROR(LABEL, "EDM not allow.");
        return PrivacyError::ERR_EDM_POLICY_CHECK_FAILED;
    }
    if (!Register()) {
        return PrivacyError::ERR_MALLOC_FAILED;
    }

    // instantaneous record accessCount set to zero in StartUsingPermission, wait for combine in StopUsingPermission
    int32_t accessCount = 0;
    int32_t failCount = 0;
    AddPermParamInfo info;
    info.tokenId = tokenId;
    info.permissionName = permissionName;
    info.successCount = accessCount;
    info.failCount = failCount;

    PermissionRecord record = { 0 };
    int32_t result = GetPermissionRecord(info, record);
    if (result != Constant::SUCCESS) {
        return result;
    }

    if (AddRecordToStartList(record)) {
        return PrivacyError::ERR_PERMISSION_ALREADY_START_USING;
    }

    if (!GetGlobalSwitchStatus(permissionName)) {
        if (!ShowGlobalDialog(permissionName)) {
            ACCESSTOKEN_LOG_ERROR(LABEL, "show permission dialog failed.");
            RemoveRecordFromStartList(record);
            UnRegisterWindowCallback();
            return ERR_SERVICE_ABNORMAL;
        }
    } else {
        CallbackExecute(tokenId, permissionName, record.status);
    }
    return Constant::SUCCESS;
}

void PermissionRecordManager::ExecuteAllCameraExecuteCallback()
{
    std::vector<AccessTokenID> tokenList;
    {
        std::lock_guard<std::mutex> lock(startRecordListMutex_);
        for (auto iter = startRecordList_.begin(); iter != startRecordList_.end(); ++iter) {
            if (iter->opCode != Constant::OP_CAMERA) {
                continue;
            }
            tokenList.emplace_back(iter->tokenId);
        }
    }
    for (size_t i = 0; i < tokenList.size(); ++i) {
        ExecuteCameraCallbackAsync(tokenList[i]);
    }
}

void PermissionRecordManager::ExecuteCameraCallbackAsync(AccessTokenID tokenId)
{
    ACCESSTOKEN_LOG_DEBUG(LABEL, "entry");
    auto task = [tokenId, this]() {
        ACCESSTOKEN_LOG_INFO(LABEL, "ExecuteCameraCallbackAsync task called");
        auto it = [&](AccessTokenID id, sptr<IRemoteObject> cameraCallback) {
            auto callback = iface_cast<IStateChangeCallback>(cameraCallback);
            if ((tokenId == id) && (callback != nullptr)) {
                ACCESSTOKEN_LOG_INFO(
                    LABEL, "CameraCallback tokenId %{public}d changeType %{public}d", tokenId, PERM_INACTIVE);
                callback->StateChangeNotify(tokenId, false);
            }
        };
        this->cameraCallbackMap_.Iterate(it);
    };
    std::thread executeThread(task);
    executeThread.detach();
    ACCESSTOKEN_LOG_DEBUG(LABEL, "The cameraCallback execution is complete");
}

int32_t PermissionRecordManager::StartUsingPermission(AccessTokenID tokenId, const std::string& permissionName,
    const sptr<IRemoteObject>& callback)
{
    ACCESSTOKEN_LOG_INFO(LABEL, "Entry, tokenId=0x%{public}x, permissionName=%{public}s",
        tokenId, permissionName.c_str());
    if (permissionName != CAMERA_PERMISSION_NAME) {
        ACCESSTOKEN_LOG_ERROR(LABEL, "ERR_PARAM_INVALID is null.");
        return PrivacyError::ERR_PARAM_INVALID;
    }

    if (!Register()) {
        return PrivacyError::ERR_MALLOC_FAILED;
    }

    // instantaneous record accessCount set to zero in StartUsingPermission, wait for combine in StopUsingPermission
    int32_t accessCount = 0;
    int32_t failCount = 0;
    PermissionRecord record = { 0 };
    AddPermParamInfo info;
    info.tokenId = tokenId;
    info.permissionName = permissionName;
    info.successCount = accessCount;
    info.failCount = failCount;
    int32_t result = GetPermissionRecord(info, record);
    if (result != Constant::SUCCESS) {
        return result;
    }
    cameraCallbackMap_.EnsureInsert(tokenId, callback);
    if (AddRecordToStartList(record)) {
        cameraCallbackMap_.Erase(tokenId);
        return PrivacyError::ERR_PERMISSION_ALREADY_START_USING;
    }
    if (!RegisterWindowCallback()) {
        cameraCallbackMap_.Erase(tokenId);
        return PrivacyError::ERR_WINDOW_CALLBACK_FAILED;
    }
    if (!GetGlobalSwitchStatus(permissionName)) {
        if (!ShowGlobalDialog(permissionName)) {
            ACCESSTOKEN_LOG_ERROR(LABEL, "show permission dialog failed.");
            RemoveRecordFromStartList(record);
            UnRegisterWindowCallback();
            cameraCallbackMap_.Erase(tokenId);
            return ERR_SERVICE_ABNORMAL;
        }
    } else {
        CallbackExecute(tokenId, permissionName, record.status);
    }
    return Constant::SUCCESS;
}

int32_t PermissionRecordManager::StopUsingPermission(AccessTokenID tokenId, const std::string& permissionName)
{
    ACCESSTOKEN_LOG_INFO(LABEL, "Entry, tokenId=0x%{public}x, permissionName=%{public}s",
        tokenId, permissionName.c_str());
    ExecuteDeletePermissionRecordTask();

    if (AccessTokenKit::GetTokenTypeFlag(tokenId) != TOKEN_HAP) {
        ACCESSTOKEN_LOG_ERROR(LABEL, "invalid tokenId(%{public}d)", tokenId);
        return PrivacyError::ERR_PARAM_INVALID;
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
        CallbackExecute(tokenId, permissionName, PERM_INACTIVE);
    }
    // clear callback
    UnRegisterWindowCallback();
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
    // filter legal permissions
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

bool PermissionRecordManager::IsAllowedUsingCamera(AccessTokenID tokenId)
{
    int32_t status = GetAppStatus(tokenId);
    bool isScreenOn = IsScreenOn();
    ACCESSTOKEN_LOG_INFO(LABEL, "tokenId(%{public}d), appStatus(%{public}d), isScreenOn(%{public}d)",
        tokenId, status, isScreenOn);

    return (status == ActiveChangeType::PERM_ACTIVE_IN_FOREGROUND) && isScreenOn;
}

bool PermissionRecordManager::IsAllowedUsingMicrophone(AccessTokenID tokenId)
{
    bool isEdmMute = false;
    if (!GetMuteParameter(EDM_MIC_MUTE_KEY, isEdmMute)) {
        ACCESSTOKEN_LOG_ERROR(LABEL, "Get param failed");
        return false;
    }
    if (isEdmMute) {
        ACCESSTOKEN_LOG_ERROR(LABEL, "EDM not allow.");
        return false;
    }

    int32_t status = GetAppStatus(tokenId);
    ACCESSTOKEN_LOG_INFO(LABEL, "TokenId %{public}d, status is %{public}d", tokenId, status);
    if (status == ActiveChangeType::PERM_ACTIVE_IN_FOREGROUND) {
        return true;
    }

    bool isContinuousTaskExist = false;
#ifdef BGTASKMGR_CONTINUOUS_TASK_ENABLE
    std::vector<std::shared_ptr<ContinuousTaskCallbackInfo>> continuousTaskList;
    BackgourndTaskManagerAccessClient::GetInstance().GetContinuousTaskApps(continuousTaskList);
    for (const auto& callbackInfo : continuousTaskList) {
        if (callbackInfo == nullptr) {
            ACCESSTOKEN_LOG_ERROR(LABEL, "callbackInfo is NULL.");
            continue;
        }
        AccessTokenID conTaskTokenID = static_cast<AccessTokenID>(callbackInfo->tokenId_);
        ACCESSTOKEN_LOG_INFO(LABEL, "tokenId %{public}d, typeId is %{public}d", conTaskTokenID, callbackInfo->typeId_);
        if ((conTaskTokenID == tokenId) &&
            (static_cast<BackgroundMode>(callbackInfo->typeId_) == BackgroundMode::VOIP)) {
            isContinuousTaskExist = true;
            break;
        }
    }
#endif
    return isContinuousTaskExist;
}

bool PermissionRecordManager::IsAllowedUsingPermission(AccessTokenID tokenId, const std::string& permissionName)
{
    if (AccessTokenKit::GetTokenTypeFlag(tokenId) != TOKEN_HAP) {
        ACCESSTOKEN_LOG_ERROR(LABEL, "tokenId(%{public}d) is not hap.", tokenId);
        return false;
    }

    if (permissionName == CAMERA_PERMISSION_NAME) {
        return IsAllowedUsingCamera(tokenId);
    } else if (permissionName == MICROPHONE_PERMISSION_NAME) {
        return IsAllowedUsingMicrophone(tokenId);
    }
    ACCESSTOKEN_LOG_ERROR(LABEL, "Invalid permission(%{public}s).", permissionName.c_str());
    return false;
}

int32_t PermissionRecordManager::SetMutePolicy(const PolicyType& policyType, const CallerType& callerType, bool isMute)
{
    ACCESSTOKEN_LOG_INFO(LABEL, "CallerType: %{public}d, isMute: %{public}d", callerType, isMute);
    std::string permissionName;
    if (callerType == MICROPHONE) {
        permissionName = MICROPHONE_PERMISSION_NAME;
    } else if (callerType == CAMERA) {
        permissionName = CAMERA_PERMISSION_NAME;
    } else {
        ACCESSTOKEN_LOG_ERROR(LABEL, "Invalid type: %{public}d.", callerType);
        return PrivacyError::ERR_PARAM_INVALID;
    }

    if (policyType == EDM) {
        return SetEdmMutePolicy(permissionName, isMute);
    }

    if (policyType == PRIVACY) {
        return SetPrivacyMutePolicy(permissionName, isMute);
    }

    if (policyType == TEMPORARY) {
        return SetTempMutePolicy(permissionName, isMute);
    }
    return RET_FAILED;
}

int32_t PermissionRecordManager::SetEdmMutePolicy(const std::string permissionName, bool& isMute)
{
    if (isMute) {
        ModifyMuteStatus(permissionName, EDM, isMute);
        ModifyMuteStatus(permissionName, MIXED, isMute);
    } else {
        ModifyMuteStatus(permissionName, EDM, isMute);
        isMute = GetMuteStatus(permissionName, MIXED);
    }
    ACCESSTOKEN_LOG_INFO(LABEL, "permissionName: %{public}s, isMute: %{public}d", permissionName.c_str(), isMute);
    return RET_SUCCESS;
}

int32_t PermissionRecordManager::SetPrivacyMutePolicy(const std::string permissionName, bool& isMute)
{
    if (isMute) {
        ModifyMuteStatus(permissionName, MIXED, isMute);
    } else {
        if (GetMuteStatus(permissionName, EDM)) {
            isMute = true;
            return PrivacyError::ERR_EDM_POLICY_CHECK_FAILED;
        }
        ModifyMuteStatus(permissionName, MIXED, isMute);
    }
    ACCESSTOKEN_LOG_INFO(LABEL, "permissionName: %{public}s, isMute: %{public}d", permissionName.c_str(), isMute);
    return RET_SUCCESS;
}

int32_t PermissionRecordManager::SetTempMutePolicy(const std::string permissionName, bool& isMute)
{
    if (!isMute) {
        if (GetMuteStatus(permissionName, EDM)) {
            return PrivacyError::ERR_EDM_POLICY_CHECK_FAILED;
        }
        if (GetMuteStatus(permissionName, MIXED)) {
            if (!ShowGlobalDialog(permissionName)) {
                ACCESSTOKEN_LOG_ERROR(LABEL, "show permission dialog failed.");
                return ERR_SERVICE_ABNORMAL;
            }
            isMute = true;
            return PrivacyError::ERR_PRIVACY_POLICY_CHECK_FAILED;
        }
    }
    ACCESSTOKEN_LOG_INFO(LABEL, "permissionName: %{public}s, isMute: %{public}d", permissionName.c_str(), isMute);
    return RET_SUCCESS;
}

void PermissionRecordManager::ModifyMuteStatus(const std::string& permissionName, int32_t index, bool isMute)
{
    if (permissionName == MICROPHONE_PERMISSION_NAME) {
        std::lock_guard<std::mutex> lock(micMuteMutex_);
        if (index == EDM) {
            isMicEdmMute_ = isMute;
        } else {
            isMicMixMute_ = isMute;
        }
    } else if (permissionName == CAMERA_PERMISSION_NAME) {
        std::lock_guard<std::mutex> lock(camMuteMutex_);
        if (index == EDM) {
            isCamEdmMute_ = isMute;
        } else {
            isCamMixMute_ = isMute;
        }
    }
    ACCESSTOKEN_LOG_INFO(LABEL, "permissionName: %{public}s, isMute: %{public}d, index: %{public}d",
        permissionName.c_str(), isMute, index);
}

bool PermissionRecordManager::GetMuteStatus(const std::string& permissionName, int32_t index)
{
    bool isMute = false;
    if (permissionName == MICROPHONE_PERMISSION_NAME) {
        std::lock_guard<std::mutex> lock(micMuteMutex_);
        isMute = (index == EDM) ? isMicEdmMute_ : isMicMixMute_;
    } else if (permissionName == CAMERA_PERMISSION_NAME) {
        std::lock_guard<std::mutex> lock(camMuteMutex_);
        isMute = (index == EDM) ? isCamEdmMute_ : isCamMixMute_;
    }
    ACCESSTOKEN_LOG_INFO(LABEL, "permissionName: %{public}s, isMute: %{public}d, index: %{public}d",
        permissionName.c_str(), isMute, index);
    return isMute;
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

void PermissionRecordManager::AddDataValueToResults(const GenericValues value,
    std::vector<PermissionUsedTypeInfo>& results)
{
    PermissionUsedTypeInfo info;
    info.tokenId = static_cast<AccessTokenID>(value.GetInt(PrivacyFiledConst::FIELD_TOKEN_ID));
    Constant::TransferOpcodeToPermission(value.GetInt(PrivacyFiledConst::FIELD_PERMISSION_CODE), info.permissionName);
    uint32_t type = static_cast<uint32_t>(value.GetInt(PrivacyFiledConst::FIELD_USED_TYPE));
    if ((type & NORMAL_TYPE_ADD_VALUE) == NORMAL_TYPE_ADD_VALUE) { // normal first
        info.type = PermissionUsedType::NORMAL_TYPE;
        results.emplace_back(info);
    }
    if ((type & PICKER_TYPE_ADD_VALUE) == PICKER_TYPE_ADD_VALUE) { // picker second
        info.type = PermissionUsedType::PICKER_TYPE;
        results.emplace_back(info);
    }
    if ((type & SEC_COMPONENT_TYPE_ADD_VALUE) == SEC_COMPONENT_TYPE_ADD_VALUE) { // security component last
        info.type = PermissionUsedType::SECURITY_COMPONENT_TYPE;
        results.emplace_back(info);
    }
}

int32_t PermissionRecordManager::GetPermissionUsedTypeInfos(AccessTokenID tokenId, const std::string& permissionName,
    std::vector<PermissionUsedTypeInfo>& results)
{
    GenericValues value;

    if (tokenId != INVALID_TOKENID) {
        HapTokenInfo tokenInfo;
        if (AccessTokenKit::GetHapTokenInfo(tokenId, tokenInfo) != Constant::SUCCESS) {
            ACCESSTOKEN_LOG_ERROR(LABEL, "invalid tokenId(%{public}d)", tokenId);
            return PrivacyError::ERR_TOKENID_NOT_EXIST;
        }
        value.Put(PrivacyFiledConst::FIELD_TOKEN_ID, static_cast<int32_t>(tokenId));
    }

    if (!permissionName.empty()) {
        int32_t opCode;
        if (!Constant::TransferPermissionToOpcode(permissionName, opCode)) {
            ACCESSTOKEN_LOG_ERROR(LABEL, "invalid (%{public}s)", permissionName.c_str());
            return PrivacyError::ERR_PERMISSION_NOT_EXIST;
        }
        value.Put(PrivacyFiledConst::FIELD_PERMISSION_CODE, opCode);
    }

    std::vector<GenericValues> valueResults;
    if (!PermissionRecordRepository::GetInstance().Query(
        PermissionUsedRecordDb::DataType::PERMISSION_USED_TYPE, value, valueResults)) {
        return Constant::FAILURE;
    }

    for (const auto& valueResult : valueResults) {
        AddDataValueToResults(valueResult, results);
    }

    ACCESSTOKEN_LOG_INFO(LABEL, "get %{public}zu permission used type records", results.size());

    return Constant::SUCCESS;
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
    int32_t status = PERM_ACTIVE_IN_BACKGROUND;
    std::vector<AppStateData> foreGroundAppList;
    AppManagerAccessClient::GetInstance().GetForegroundApplications(foreGroundAppList);
    if (std::any_of(foreGroundAppList.begin(), foreGroundAppList.end(),
        [=](const auto& foreGroundApp) { return foreGroundApp.accessTokenId == tokenId; })) {
        status = PERM_ACTIVE_IN_FOREGROUND;
    }
    return status;
}

bool PermissionRecordManager::RegisterAppStatusListener()
{
    // app manager death callback register
    {
        std::lock_guard<std::mutex> lock(appManagerDeathMutex_);
        if (appManagerDeathCallback_ == nullptr) {
            appManagerDeathCallback_ = std::make_shared<PrivacyAppManagerDeathCallback>();
            if (appManagerDeathCallback_ == nullptr) {
                ACCESSTOKEN_LOG_ERROR(LABEL, "register appManagerDeathCallback failed.");
                return false;
            }
            AppManagerAccessClient::GetInstance().RegisterDeathCallbak(appManagerDeathCallback_);
        }
    }
    // app state change callback register
    {
        std::lock_guard<std::mutex> lock(appStateMutex_);
        if (appStateCallback_ == nullptr) {
            appStateCallback_ = new (std::nothrow) PrivacyAppStateObserver();
            if (appStateCallback_ == nullptr) {
                ACCESSTOKEN_LOG_ERROR(LABEL, "register appStateCallback failed.");
                return false;
            }
            AppManagerAccessClient::GetInstance().RegisterApplicationStateObserver(appStateCallback_);
        }
    }
    return true;
}

#ifdef CAMERA_FLOAT_WINDOW_ENABLE
bool PermissionRecordManager::HasUsingCamera()
{
    std::lock_guard<std::mutex> lock(startRecordListMutex_);
    bool hasCamera = std::any_of(startRecordList_.begin(), startRecordList_.end(),
        [](const auto& record) { return record.opCode == Constant::OP_CAMERA; });
    return hasCamera;
}

void UpdateCameraFloatWindowStatus(AccessTokenID tokenId, bool isShowing)
{
    PermissionRecordManager::GetInstance().NotifyCameraWindowChange(false, tokenId, isShowing);
}

void UpdatePipWindowStatus(AccessTokenID tokenId, bool isShowing)
{
    PermissionRecordManager::GetInstance().NotifyCameraWindowChange(true, tokenId, isShowing);
}

/* Handle window manager die */
void HandleWindowDied()
{
    PermissionRecordManager::GetInstance().OnWindowMgrRemoteDied();
}
#endif

bool PermissionRecordManager::RegisterWindowCallback()
{
#ifdef CAMERA_FLOAT_WINDOW_ENABLE
    std::lock_guard<std::mutex> lock(windowLoaderMutex_);
    ACCESSTOKEN_LOG_INFO(LABEL, "Begin to RegisterWindowCallback.");
    if (windowLoader_ != nullptr) {
        ACCESSTOKEN_LOG_INFO(LABEL, "WindowCallback has already been registered.");
        return true;
    }
    if (!HasUsingCamera()) {
        ACCESSTOKEN_LOG_INFO(LABEL, "Camera is not using.");
        return true;
    }
    windowLoader_ = new (std::nothrow) LibraryLoader(WINDOW_MANAGER_PATH);
    if (windowLoader_ == nullptr) {
        ACCESSTOKEN_LOG_ERROR(LABEL, "Failed to new %{public}s.", WINDOW_MANAGER_PATH.c_str());
        return false;
    }
    WindowManagerLoaderInterface* winManagerLoader = windowLoader_->GetObject<WindowManagerLoaderInterface>();
    if (winManagerLoader == nullptr) {
        ACCESSTOKEN_LOG_ERROR(LABEL, "Failed to dlopen %{public}s.", WINDOW_MANAGER_PATH.c_str());
        delete windowLoader_;
        windowLoader_ = nullptr;
        return false;
    }
    WindowChangeCallback floatCallback = UpdateCameraFloatWindowStatus;
    ErrCode err = winManagerLoader->RegisterFloatWindowListener(floatCallback);
    if (err != ERR_OK) {
        ACCESSTOKEN_LOG_ERROR(LABEL, "Failed to register float window listener, err:%{public}d", err);
        delete windowLoader_;
        windowLoader_ = nullptr;
        return false;
    }
    WindowChangeCallback pipCallback = UpdatePipWindowStatus;
    err = winManagerLoader->RegisterPipWindowListener(pipCallback);
    if (err != ERR_OK) {
        ACCESSTOKEN_LOG_ERROR(LABEL, "Failed to register pip window listener, err:%{public}d", err);
        winManagerLoader->UnregisterFloatWindowListener(floatCallback);
        delete windowLoader_;
        windowLoader_ = nullptr;
        return false;
    }
    winManagerLoader->AddDeathCallback(HandleWindowDied);
#endif
    return true;
}

bool PermissionRecordManager::UnRegisterWindowCallback()
{
    bool isSuccess = true;
#ifdef CAMERA_FLOAT_WINDOW_ENABLE
    if (!isAutoClose) {
        return true;
    }
    ACCESSTOKEN_LOG_INFO(LABEL, "Begin to UnRegisterWindowCallback.");
    std::lock_guard<std::mutex> lock(windowLoaderMutex_);
    if (windowLoader_ == nullptr) {
        ACCESSTOKEN_LOG_INFO(LABEL, "WindowCallback has already been unregistered.");
        return true;
    }
    if (HasUsingCamera()) {
        ACCESSTOKEN_LOG_INFO(LABEL, "Camera is using.");
        return true;
    }
    WindowManagerLoaderInterface* winManagerLoader = windowLoader_->GetObject<WindowManagerLoaderInterface>();
    if (winManagerLoader == nullptr) {
        ACCESSTOKEN_LOG_ERROR(LABEL, "Failed to dlopen %{public}s.", WINDOW_MANAGER_PATH.c_str());
        delete windowLoader_;
        windowLoader_ = nullptr;
        return false;
    }
    WindowChangeCallback floatCallback = UpdateCameraFloatWindowStatus;
    ErrCode err = winManagerLoader->UnregisterFloatWindowListener(floatCallback);
    if (err != ERR_OK) {
        ACCESSTOKEN_LOG_ERROR(LABEL, "Failed to unregister float window, err:%{public}d", err);
        isSuccess = false;
    }
    WindowChangeCallback pipCallback = UpdatePipWindowStatus;
    err = winManagerLoader->UnregisterPipWindowListener(pipCallback);
    if (err != ERR_OK) {
        ACCESSTOKEN_LOG_ERROR(LABEL, "Failed to unregister pip window, err:%{public}d", err);
        isSuccess = false;
    }
    delete windowLoader_;
    windowLoader_ = nullptr;
#endif
    return isSuccess;
}

bool PermissionRecordManager::Register()
{
    // microphone mute
    {
        std::lock_guard<std::mutex> lock(micCallbackMutex_);
        if (micMuteCallback_ == nullptr) {
            micMuteCallback_ = new (std::nothrow) AudioRoutingManagerListenerStub();
            if (micMuteCallback_ == nullptr) {
                ACCESSTOKEN_LOG_ERROR(LABEL, "register micMuteCallback failed.");
                return false;
            }
            AudioManagerPrivacyClient::GetInstance().SetMicStateChangeCallback(micMuteCallback_);
            bool isMicMute = AudioManagerPrivacyClient::GetInstance().IsMicrophoneMute();
            ModifyMuteStatus(MICROPHONE_PERMISSION_NAME, MIXED, isMicMute);
            // get EDM
            bool isEdmMute = false;
            if (!GetMuteParameter(EDM_MIC_MUTE_KEY, isEdmMute)) {
                ACCESSTOKEN_LOG_ERROR(LABEL, "Get param failed");
                return false;
            }
            ModifyMuteStatus(MICROPHONE_PERMISSION_NAME, EDM, isEdmMute);
        }
    }
    // camera mute
    {
        std::lock_guard<std::mutex> lock(cameraCallbackMutex_);
        if (camMuteCallback_ == nullptr) {
            camMuteCallback_ = new (std::nothrow) CameraServiceCallbackStub();
            if (camMuteCallback_ == nullptr) {
                ACCESSTOKEN_LOG_ERROR(LABEL, "register camMuteCallback failed.");
                return false;
            }
            CameraManagerPrivacyClient::GetInstance().SetMuteCallback(camMuteCallback_);
            bool isCameraMute = CameraManagerPrivacyClient::GetInstance().IsCameraMuted();
            ModifyMuteStatus(CAMERA_PERMISSION_NAME, MIXED, isCameraMute);
        }
    }
    // app state change and lockscreen state change callback register
    return RegisterAppStatusListener();
}

void PermissionRecordManager::Unregister()
{
    // app state change callback unregister
    std::lock_guard<std::mutex> lock(appStateMutex_);
    if (appStateCallback_ != nullptr) {
        AppManagerAccessClient::GetInstance().UnregisterApplicationStateObserver(appStateCallback_);
        appStateCallback_= nullptr;
    }
}

bool PermissionRecordManager::GetMuteParameter(const char* key, bool& isMute)
{
    char value[VALUE_MAX_LEN] = {0};
    int32_t ret = GetParameter(key, "", value, VALUE_MAX_LEN - 1);
    if (ret < 0) {
        ACCESSTOKEN_LOG_ERROR(LABEL, "Return default value, ret=%{public}d", ret);
        return false;
    }
    isMute = false;
    if (strncmp(value, "true", VALUE_MAX_LEN) == 0) {
        ACCESSTOKEN_LOG_INFO(LABEL, "EDM not allow.");
        isMute = true;
    }
    return true;
}

void PermissionRecordManager::OnAppMgrRemoteDiedHandle()
{
    std::lock_guard<std::mutex> lock(appStateMutex_);
    appStateCallback_ = nullptr;
}

void PermissionRecordManager::OnAudioMgrRemoteDiedHandle()
{
    {
        std::lock_guard<std::mutex> lock(micCallbackMutex_);
        micMuteCallback_ = nullptr;
    }
}

void PermissionRecordManager::OnCameraMgrRemoteDiedHandle()
{
    ACCESSTOKEN_LOG_INFO(LABEL, "Handle camera fwk died.");

    RemoveRecordFromStartListByOp(Constant::OP_CAMERA);
#ifdef CAMERA_FLOAT_WINDOW_ENABLE
    ClearWindowShowing();
    {
        std::lock_guard<std::mutex> lock(windowLoaderMutex_);
        if (windowLoader_ != nullptr) {
            delete windowLoader_;
            windowLoader_ = nullptr;
        }
    }
#endif
}

bool PermissionRecordManager::IsCameraWindowShow(AccessTokenID tokenId)
{
    bool isShow = true;
#ifdef CAMERA_FLOAT_WINDOW_ENABLE
    std::lock_guard<std::mutex> lock(windowStausMutex_);
    isShow = (floatWindowTokenId_ == tokenId) && camFloatWindowShowing_;
    isShow |= ((pipWindowTokenId_ == tokenId) && pipWindowShowing_);
#endif
    return isShow;
}

#ifdef CAMERA_FLOAT_WINDOW_ENABLE
/*
 * when camera float window is not show, notice camera service to use StopUsingPermission
 */
void PermissionRecordManager::NotifyCameraWindowChange(bool isPip, AccessTokenID tokenId, bool isShowing)
{
    ACCESSTOKEN_LOG_INFO(LABEL, "Update window, isPip(%{public}d), token(%{public}d), status(%{public}d)",
        isPip, tokenId, isShowing);
    {
        std::lock_guard<std::mutex> lock(windowStausMutex_);
        if (isPip) {
            pipWindowShowing_ = isShowing;
            pipWindowTokenId_ = tokenId;
        } else {
            camFloatWindowShowing_ = isShowing;
            floatWindowTokenId_ = tokenId;
        }
    }
    if (isShowing) {
        ACCESSTOKEN_LOG_INFO(LABEL, "camera float window is showing!");
    } else {
        if ((GetAppStatus(tokenId) == ActiveChangeType::PERM_ACTIVE_IN_BACKGROUND) &&
            !IsCameraWindowShow(tokenId)) {
            ACCESSTOKEN_LOG_INFO(LABEL, "Token(%{public}d) is background, pip and float window is not show.", tokenId);
            ExecuteCameraCallbackAsync(tokenId);
        }
    }
}

void PermissionRecordManager::ClearWindowShowing()
{
    ACCESSTOKEN_LOG_INFO(LABEL, "Clear window show status.");
    {
        std::lock_guard<std::mutex> lock(windowStausMutex_);
        camFloatWindowShowing_ = false;
        floatWindowTokenId_ = 0;

        pipWindowShowing_ = false;
        pipWindowTokenId_ = 0;
    }
}

/* Handle window manager die */
void PermissionRecordManager::OnWindowMgrRemoteDied()
{
    ACCESSTOKEN_LOG_INFO(LABEL, "Handle window manager died.");
    ClearWindowShowing();
}
#endif

void PermissionRecordManager::SetDefaultConfigValue()
{
    ACCESSTOKEN_LOG_INFO(LABEL, "no config file or config file is not valid, use default values");

    recordSizeMaximum_ = DEFAULT_PERMISSION_USED_RECORD_SIZE_MAXIMUM;
    recordAgingTime_ = DEFAULT_PERMISSION_USED_RECORD_AGING_TIME;
    globalDialogBundleName_ = DEFAULT_PERMISSION_MANAGER_BUNDLE_NAME;
    globalDialogAbilityName_ = DEFAULT_PERMISSION_MANAGER_DIALOG_ABILITY;
}

void PermissionRecordManager::GetConfigValue()
{
    AccessTokenConfigPolicy policy;
    AccessTokenConfigValue value;
    if (policy.GetConfigValue(ServiceType::PRIVACY_SERVICE, value)) {
        // set value from config
        recordSizeMaximum_ = value.pConfig.sizeMaxImum;
        recordAgingTime_ = value.pConfig.agingTime;
        globalDialogBundleName_ = value.pConfig.globalDialogBundleName;
        globalDialogAbilityName_ = value.pConfig.globalDialogAbilityName;
    } else {
        SetDefaultConfigValue();
    }

    ACCESSTOKEN_LOG_INFO(LABEL, "recordSizeMaximum_ is %{public}d, recordAgingTime_ is %{public}d,"
        " globalDialogBundleName_ is %{public}s, globalDialogAbilityName_ is %{public}s.",
        recordSizeMaximum_, recordAgingTime_, globalDialogBundleName_.c_str(), globalDialogAbilityName_.c_str());
}

void PermissionRecordManager::Init()
{
    if (hasInited_) {
        return;
    }
    ACCESSTOKEN_LOG_INFO(LABEL, "init");
    deleteTaskWorker_.Start(1);
    hasInited_ = true;

    GetConfigValue();
}
} // namespace AccessToken
} // namespace Security
} // namespace OHOS