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
#include "accesstoken_kit.h"
#include "accesstoken_log.h"
#include "active_status_callback_manager.h"
#include "app_manager_access_client.h"
#include "audio_manager_privacy_client.h"
#include "camera_manager_privacy_client.h"
#include "config_policy_loader.h"
#include "constant.h"
#include "constant_common.h"
#include "data_translator.h"
#include "i_state_change_callback.h"
#include "ipc_skeleton.h"
#include "iservice_registry.h"
#include "libraryloader.h"
#include "parameter.h"
#include "parcel_utils.h"
#include "permission_used_record_db.h"
#include "power_manager_client.h"
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
constexpr const char* DEFAULT_DEVICEID = "0";
constexpr const char* CAMERA_PERMISSION_NAME = "ohos.permission.CAMERA";
constexpr const char* MICROPHONE_PERMISSION_NAME = "ohos.permission.MICROPHONE";
constexpr const char* EDM_MIC_MUTE_KEY = "persist.edm.mic_disable";
constexpr const char* EDM_CAMERA_MUTE_KEY = "persist.edm.camera_disable";
constexpr const char* DEFAULT_PERMISSION_MANAGER_BUNDLE_NAME = "com.ohos.permissionmanager";
constexpr const char* DEFAULT_PERMISSION_MANAGER_DIALOG_ABILITY = "com.ohos.permissionmanager.GlobalExtAbility";
constexpr const char* RESOURCE_KEY = "ohos.sensitive.resource";
static const int32_t DEFAULT_PERMISSION_USED_RECORD_SIZE_MAXIMUM = 500000;
static const int32_t DEFAULT_PERMISSION_USED_RECORD_AGING_TIME = 7;
static const uint32_t NORMAL_TYPE_ADD_VALUE = 1;
static const uint32_t PICKER_TYPE_ADD_VALUE = 2;
static const uint32_t SEC_COMPONENT_TYPE_ADD_VALUE = 4;
static constexpr int64_t ONE_MINUTE_MILLISECONDS = 60 * 1000; // 1 min = 60 * 1000 ms
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

PermissionRecordManager::PermissionRecordManager()
{
    bool isEdmMute = false;
    if (GetMuteParameter(EDM_MIC_MUTE_KEY, isEdmMute)) {
        ModifyMuteStatus(MICROPHONE_PERMISSION_NAME, EDM, isEdmMute);
    }
}

PermissionRecordManager::~PermissionRecordManager()
{
    if (!hasInited_) {
        return;
    }
    hasInited_ = false;
    Unregister();
}

void PrivacyAppStateObserver::OnAppStateChanged(const AppStateData &appStateData)
{
    ACCESSTOKEN_LOG_DEBUG(LABEL, "OnChange(id=%{public}d, pid=%{public}d, state=%{public}d).",
        appStateData.accessTokenId, appStateData.pid, appStateData.state);

    ActiveChangeType status = PERM_INACTIVE;
    if (appStateData.state == static_cast<int32_t>(ApplicationState::APP_STATE_FOREGROUND)) {
        status = PERM_ACTIVE_IN_FOREGROUND;
    } else if (appStateData.state == static_cast<int32_t>(ApplicationState::APP_STATE_BACKGROUND)) {
        status = PERM_ACTIVE_IN_BACKGROUND;
    }
    PermissionRecordManager::GetInstance().NotifyAppStateChange(appStateData.accessTokenId, appStateData.pid, status);
}

void PrivacyAppStateObserver::OnAppStopped(const AppStateData &appStateData)
{
    ACCESSTOKEN_LOG_DEBUG(LABEL, "OnChange(id=%{public}d, state=%{public}d).",
        appStateData.accessTokenId, appStateData.state);

    if (appStateData.state == static_cast<int32_t>(ApplicationState::APP_STATE_TERMINATED)) {
        PermissionRecordManager::GetInstance().RemoveRecordFromStartListByToken(appStateData.accessTokenId);
    }
}

void PrivacyAppStateObserver::OnProcessDied(const ProcessData &processData)
{
    ACCESSTOKEN_LOG_DEBUG(LABEL, "OnChange(id=%{public}u, pid=%{public}d, state=%{public}d).",
        processData.accessTokenId, processData.pid, processData.state);

    PermissionRecordManager::GetInstance().RemoveRecordFromStartListByPid(processData.accessTokenId, processData.pid);
}

void PrivacyAppManagerDeathCallback::NotifyAppManagerDeath()
{
    PermissionRecordManager::GetInstance().OnAppMgrRemoteDiedHandle();
}

void PermissionRecordManager::AddRecordToCacheAndDb(const PermissionRecord& record, GenericValues& value)
{
    PermissionRecordCache cache;
    cache.record = record;
    permUsedRecList_.emplace_back(cache);

    PermissionRecord::TranslationIntoGenericValues(record, value);
}

static bool RecordMergeCheck(const PermissionRecord& record1, const PermissionRecord& record2)
{
    // timestamp in the same minute
    if (!AccessToken::TimeUtil::IsTimeStampsSameMinute(record1.timestamp, record2.timestamp)) {
        return false;
    }

    // the same tokenID + opCode + status + lockScreenStatus + usedType
    if ((record1.tokenId != record2.tokenId) ||
        (record1.opCode != record2.opCode) ||
        (record1.status != record2.status) ||
        (record1.lockScreenStatus != record2.lockScreenStatus) ||
        (record1.type != record2.type)) {
        return false;
    }

    // both success
    if (((record1.accessCount > 0) && (record2.accessCount == 0)) ||
        ((record1.accessCount == 0) && (record2.accessCount > 0))) {
        return false;
    }

    // both failure
    if (((record1.rejectCount > 0) && (record2.rejectCount == 0)) ||
        ((record1.rejectCount == 0) && (record2.rejectCount > 0))) {
        return false;
    }

    return true;
}

static void MergeRecord(PermissionRecord& record, const PermissionRecord& curRec)
{
    record.accessCount += curRec.accessCount;
    record.rejectCount += curRec.rejectCount;
}

int32_t PermissionRecordManager::MergeOrInsertRecord(const PermissionRecord& record)
{
    std::vector<GenericValues> insertRecords;
    {
        std::lock_guard<std::mutex> lock(permUsedRecMutex_);
        if (permUsedRecList_.empty()) {
            ACCESSTOKEN_LOG_INFO(LABEL, "First record in cache!");

            GenericValues value;
            AddRecordToCacheAndDb(record, value);
            insertRecords.emplace_back(value);
        } else {
            bool mergeFlag = false;
            for (auto it = permUsedRecList_.begin(); it != permUsedRecList_.end(); ++it) {
                if (RecordMergeCheck(it->record, record)) {
                    ACCESSTOKEN_LOG_INFO(LABEL, "Merge record, ori timestamp is %{public}" PRId64 ".",
                        it->record.timestamp);

                    // merge new record to older one if match the merge condition
                    MergeRecord(it->record, record);

                    // set update flag to true
                    it->needUpdate = true;
                    mergeFlag = true;

                    break;
                }
            }

            if (!mergeFlag) {
                // record can't merge store to database immediately and add to cache
                GenericValues value;
                AddRecordToCacheAndDb(record, value);
                insertRecords.emplace_back(value);
            }
        }
    }

    if (insertRecords.empty()) {
        return Constant::SUCCESS;
    }

    Utils::UniqueWriteGuard<Utils::RWLock> lk(this->rwLock_);
    int32_t res = PermissionUsedRecordDb::GetInstance().Add(PermissionUsedRecordDb::DataType::PERMISSION_RECORD,
        insertRecords);
    if (res != PermissionUsedRecordDb::ExecuteResult::SUCCESS) {
        ACCESSTOKEN_LOG_INFO(LABEL, "Add permission_record_table failed!");
        return res;
    }

    ACCESSTOKEN_LOG_INFO(LABEL, "Add record, id %{public}d, op %{public}d, status: %{public}d, sucCnt: %{public}d, "
        "failCnt: %{public}d, lockScreenStatus %{public}d, timestamp %{public}" PRId64 ", type %{public}d.",
        record.tokenId, record.opCode, record.status, record.accessCount, record.rejectCount, record.lockScreenStatus,
        record.timestamp, record.type);

    return Constant::SUCCESS;
}

bool PermissionRecordManager::UpdatePermissionUsedRecord(const PermissionRecord& record)
{
    GenericValues modifyValue;
    modifyValue.Put(PrivacyFiledConst::FIELD_ACCESS_COUNT, record.accessCount);
    modifyValue.Put(PrivacyFiledConst::FIELD_REJECT_COUNT, record.rejectCount);

    GenericValues conditionValue;
    conditionValue.Put(PrivacyFiledConst::FIELD_TOKEN_ID, static_cast<int32_t>(record.tokenId));
    conditionValue.Put(PrivacyFiledConst::FIELD_OP_CODE, record.opCode);
    conditionValue.Put(PrivacyFiledConst::FIELD_STATUS, record.status);
    conditionValue.Put(PrivacyFiledConst::FIELD_TIMESTAMP, record.timestamp);
    conditionValue.Put(PrivacyFiledConst::FIELD_USED_TYPE, record.type);

    {
        Utils::UniqueWriteGuard<Utils::RWLock> lk(this->rwLock_);
        return (PermissionUsedRecordDb::GetInstance().Update(PermissionUsedRecordDb::DataType::PERMISSION_RECORD,
            modifyValue, conditionValue) == PermissionUsedRecordDb::ExecuteResult::SUCCESS);
    }
}

int32_t PermissionRecordManager::AddRecord(const PermissionRecord& record)
{
    int32_t res = MergeOrInsertRecord(record);
    if (res != Constant::SUCCESS) {
        return res;
    }

    int64_t updateStamp = record.timestamp - ONE_MINUTE_MILLISECONDS; // timestamp less than 1 min from now
    std::lock_guard<std::mutex> lock(permUsedRecMutex_);
    auto it = permUsedRecList_.begin();
    while (it != permUsedRecList_.end()) {
        if (it->record.timestamp > updateStamp) {
            // record from cache less than updateStamp may merge, ignore them
            ++it;
            continue;
        }

        // needUpdate flase means record not merge, when the timestamp of those records less than 1 min from now
        // they can not merge any more, remove it
        if ((!it->needUpdate) || (UpdatePermissionUsedRecord(it->record))) {
            it = permUsedRecList_.erase(it);
        } else {
            ++it;
        }
    }

    return Constant::SUCCESS;
}

void PermissionRecordManager::UpdatePermRecImmediately()
{
    std::lock_guard<std::mutex> lock(permUsedRecMutex_);
    for (auto it = permUsedRecList_.begin(); it != permUsedRecList_.end(); ++it) {
        if (it->needUpdate) {
            UpdatePermissionUsedRecord(it->record);
        }
    }
}

int32_t PermissionRecordManager::GetPermissionRecord(const AddPermParamInfo& info, PermissionRecord& record)
{
    if (AccessTokenKit::GetTokenTypeFlag(info.tokenId) != TOKEN_HAP) {
        ACCESSTOKEN_LOG_ERROR(LABEL, "Not hap(%{public}d).", info.tokenId);
        return PrivacyError::ERR_PARAM_INVALID;
    }
    int32_t opCode;
    if (!Constant::TransferPermissionToOpcode(info.permissionName, opCode)) {
        ACCESSTOKEN_LOG_ERROR(LABEL, "Invalid perm(%{public}s)", info.permissionName.c_str());
        return PrivacyError::ERR_PERMISSION_NOT_EXIST;
    }
    if (GetMuteStatus(info.permissionName, EDM)) {
        record.status = PERM_INACTIVE;
    } else {
        record.status = GetAppStatus(info.tokenId);
    }
    record.lockScreenStatus = GetLockScreenStatus();
    record.tokenId = info.tokenId;
    record.accessCount = info.successCount;
    record.rejectCount = info.failCount;
    record.opCode = opCode;
    record.timestamp = AccessToken::TimeUtil::GetCurrentTimestamp();
    record.accessDuration = 0;
    record.type = info.type;
    ACCESSTOKEN_LOG_DEBUG(LABEL, "Record status: %{public}d", record.status);
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
    int32_t res = PermissionUsedRecordDb::GetInstance().Query(PermissionUsedRecordDb::DataType::PERMISSION_USED_TYPE,
        conditionValue, results);
    if (res != PermissionUsedRecordDb::SUCCESS) {
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
        int32_t res = PermissionUsedRecordDb::GetInstance().Add(PermissionUsedRecordDb::DataType::PERMISSION_USED_TYPE,
            recordValues);
        if (res != PermissionUsedRecordDb::ExecuteResult::SUCCESS) {
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
            return (PermissionUsedRecordDb::GetInstance().Update(PermissionUsedRecordDb::DataType::PERMISSION_USED_TYPE,
                newValue, results[0]) == PermissionUsedRecordDb::ExecuteResult::SUCCESS);
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
    if ((result != Constant::SUCCESS) || (!GetGlobalSwitchStatus(info.permissionName))) {
        return result;
    }

    result = AddRecord(record);
    if (result != Constant::SUCCESS) {
        return result;
    }

    return AddOrUpdateUsedTypeIfNeeded(
        info.tokenId, record.opCode, info.type) ? Constant::SUCCESS : Constant::FAILURE;
}

void PermissionRecordManager::RemovePermissionUsedRecords(AccessTokenID tokenId, const std::string& deviceID)
{
    // only support remove by tokenId(local)
    std::string device = GetDeviceId(tokenId);
    if (!deviceID.empty() && device != deviceID) {
        ACCESSTOKEN_LOG_ERROR(LABEL, "DeviceID mismatch");
        return;
    }

    {
        // remove from record cache
        std::lock_guard<std::mutex> lock(permUsedRecMutex_);
        auto it = permUsedRecList_.begin();
        while (it != permUsedRecList_.end()) {
            if (tokenId == it->record.tokenId) {
                it = permUsedRecList_.erase(it);
            } else {
                ++it;
            }
        }
    }

    GenericValues conditions;
    conditions.Put(PrivacyFiledConst::FIELD_TOKEN_ID, static_cast<int32_t>(tokenId));
    {
        // remove from database
        Utils::UniqueWriteGuard<Utils::RWLock> lk(this->rwLock_);
        PermissionUsedRecordDb::GetInstance().Remove(PermissionUsedRecordDb::DataType::PERMISSION_RECORD, conditions);
        PermissionUsedRecordDb::GetInstance().Remove(PermissionUsedRecordDb::DataType::PERMISSION_USED_TYPE,
            conditions);
    }

    // remove from start list
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

static void TransferToOpcode(const std::vector<std::string>& permissionList, std::set<int32_t>& opCodeList)
{
    for (const auto& permission : permissionList) {
        int32_t opCode = Constant::OP_INVALID;
        Constant::TransferPermissionToOpcode(permission, opCode);
        opCodeList.insert(opCode);
    }
}

void PermissionRecordManager::GetMergedRecordsFromCache(std::vector<PermissionRecord>& mergedRecords)
{
    std::lock_guard<std::mutex> lock(permUsedRecMutex_);
    for (const auto& cache : permUsedRecList_) {
        if (cache.needUpdate) {
            mergedRecords.emplace_back(cache.record);
        }
    }
}

void PermissionRecordManager::InsteadMergedRecIfNessary(GenericValues& queryValue,
    std::vector<PermissionRecord>& mergedRecords)
{
    uint32_t tokenId = static_cast<uint32_t>(queryValue.GetInt(PrivacyFiledConst::FIELD_TOKEN_ID));
    int32_t opCode = queryValue.GetInt(PrivacyFiledConst::FIELD_OP_CODE);
    int32_t status = queryValue.GetInt(PrivacyFiledConst::FIELD_STATUS);
    int64_t timestamp = queryValue.GetInt64(PrivacyFiledConst::FIELD_TIMESTAMP);
    PermissionUsedType type = static_cast<PermissionUsedType>(queryValue.GetInt(PrivacyFiledConst::FIELD_USED_TYPE));

    for (const auto& record : mergedRecords) {
        if ((tokenId == record.tokenId) &&
            (opCode == record.opCode) &&
            (status == record.status) &&
            (timestamp == record.timestamp) &&
            (type == record.type)) {
            // find merged record, instead accessCount and rejectCount
            queryValue.Remove(PrivacyFiledConst::FIELD_ACCESS_COUNT);
            queryValue.Put(PrivacyFiledConst::FIELD_ACCESS_COUNT, record.accessCount);
            queryValue.Remove(PrivacyFiledConst::FIELD_REJECT_COUNT);
            queryValue.Put(PrivacyFiledConst::FIELD_REJECT_COUNT, record.rejectCount);
            return;
        }
    }
}

void PermissionRecordManager::MergeSamePermission(const PermissionUsageFlag& flag, const PermissionUsedRecord& inRecord,
    PermissionUsedRecord& outRecord)
{
    outRecord.accessCount += inRecord.accessCount;
    outRecord.rejectCount += inRecord.rejectCount;

    // update lastAccessTime、lastRejectTime and lastAccessDuration to the nearer one
    outRecord.lastAccessTime = (inRecord.lastAccessTime > outRecord.lastAccessTime) ?
        inRecord.lastAccessTime : outRecord.lastAccessTime;
    outRecord.lastAccessDuration = (inRecord.lastAccessTime > outRecord.lastAccessTime) ?
        inRecord.lastAccessDuration : outRecord.lastAccessDuration;
    outRecord.lastRejectTime = (inRecord.lastRejectTime > outRecord.lastRejectTime) ?
        inRecord.lastRejectTime : outRecord.lastRejectTime;

    // summary do not handle detail
    if (flag == FLAG_PERMISSION_USAGE_SUMMARY) {
        return;
    }

    if (inRecord.lastAccessTime > 0) {
        outRecord.accessRecords.emplace_back(inRecord.accessRecords[0]);
    }
    if (inRecord.lastRejectTime > 0) {
        outRecord.rejectRecords.emplace_back(inRecord.rejectRecords[0]);
    }
}

void PermissionRecordManager::FillPermissionUsedRecords(const PermissionUsedRecord& record,
    const PermissionUsageFlag& flag, std::vector<PermissionUsedRecord>& permissionRecords)
{
    // check whether the permission has exsit
    auto iter = std::find_if(permissionRecords.begin(), permissionRecords.end(),
        [record](const PermissionUsedRecord& rec) {
        return record.permissionName == rec.permissionName;
    });
    if (iter != permissionRecords.end()) {
        // permission exsit, merge it
        MergeSamePermission(flag, record, *iter);
    } else {
        // permission not exsit, add it
        permissionRecords.emplace_back(record);
    }
}

bool PermissionRecordManager::FillBundleUsedRecord(const GenericValues& value, const PermissionUsageFlag& flag,
    std::map<int32_t, BundleUsedRecord>& tokenIdToBundleMap, std::map<int32_t, int32_t>& tokenIdToCountMap,
    PermissionUsedResult& result)
{
    // translate database value into PermissionUsedRecord value
    PermissionUsedRecord record;
    if (DataTranslator::TranslationGenericValuesIntoPermissionUsedRecord(flag, value, record) != Constant::SUCCESS) {
        ACCESSTOKEN_LOG_ERROR(LABEL, "Failed to transform op(%{public}d)",
            value.GetInt(PrivacyFiledConst::FIELD_OP_CODE));
        return false;
    }

    // update beginTimeMillis and endTimeMillis if necessary
    int64_t timestamp = value.GetInt64(PrivacyFiledConst::FIELD_TIMESTAMP);
    result.beginTimeMillis = ((result.beginTimeMillis == 0) || (timestamp < result.beginTimeMillis)) ?
            timestamp : result.beginTimeMillis;
    result.endTimeMillis = (timestamp > result.endTimeMillis) ? timestamp : result.endTimeMillis;

    int32_t tokenId = value.GetInt(PrivacyFiledConst::FIELD_TOKEN_ID);
    FillPermissionUsedRecords(record, flag, tokenIdToBundleMap[tokenId].permissionRecords);
    tokenIdToCountMap[tokenId] += 1;

    return true;
}

static void AddDebugLog(const AccessTokenID tokenId, const BundleUsedRecord& bundleRecord, const int32_t queryCount,
    int32_t& totalSuccCount, int32_t& totalFailCount)
{
    int32_t tokenTotalSuccCount = 0;
    int32_t tokenTotalFailCount = 0;
    for (const auto& permissionRecord : bundleRecord.permissionRecords) {
        tokenTotalSuccCount += permissionRecord.accessCount;
        tokenTotalFailCount += permissionRecord.rejectCount;
    }
    ACCESSTOKEN_LOG_INFO(LABEL, "TokenId %{public}d[%{public}s] get %{public}d records, success %{public}d,"
        " failure %{public}d", tokenId, bundleRecord.bundleName.c_str(), queryCount, tokenTotalSuccCount,
        tokenTotalFailCount);
    totalSuccCount += tokenTotalSuccCount;
    totalFailCount += tokenTotalFailCount;
}

bool PermissionRecordManager::GetRecordsFromLocalDB(const PermissionUsedRequest& request, PermissionUsedResult& result)
{
    GenericValues andConditionValues;
    if (DataTranslator::TranslationIntoGenericValues(request, andConditionValues) != Constant::SUCCESS) {
        ACCESSTOKEN_LOG_ERROR(LABEL, "Query time or flag is invalid");
        return false;
    }

    int32_t dataLimitNum = request.flag == FLAG_PERMISSION_USAGE_DETAIL ? MAX_ACCESS_RECORD_SIZE : recordSizeMaximum_;
    int32_t totalSuccCount = 0;
    int32_t totalFailCount = 0;
    std::vector<GenericValues> findRecordsValues; // sumarry don't limit querry data num, detail do

    std::set<int32_t> opCodeList;
    TransferToOpcode(request.permissionList, opCodeList);
    PermissionUsedRecordDb::GetInstance().FindByConditions(PermissionUsedRecordDb::DataType::PERMISSION_RECORD,
        opCodeList, andConditionValues, findRecordsValues, dataLimitNum);

    uint32_t currentCount = findRecordsValues.size(); // handle query result
    if (currentCount == 0) {
        ACCESSTOKEN_LOG_INFO(LABEL, "No record match the condition.");
        return true;
    }

    std::vector<PermissionRecord> mergedRecords;
    GetMergedRecordsFromCache(mergedRecords);

    std::set<int32_t> tokenIdList;
    std::map<int32_t, BundleUsedRecord> tokenIdToBundleMap;
    std::map<int32_t, int32_t> tokenIdToCountMap;

    for (auto& recordValue : findRecordsValues) {
        InsteadMergedRecIfNessary(recordValue, mergedRecords);

        int32_t tokenId = recordValue.GetInt(PrivacyFiledConst::FIELD_TOKEN_ID);
        if (tokenIdList.count(tokenId) == 0) {
            tokenIdList.insert(tokenId); // new tokenId, inset into set

            BundleUsedRecord bundleRecord; // get bundle info
            if (!CreateBundleUsedRecord(tokenId, bundleRecord)) {
                continue;
            }

            tokenIdToBundleMap[tokenId] = bundleRecord; // add into map
            tokenIdToCountMap[tokenId] = 0;
        }

        if (!FillBundleUsedRecord(recordValue, request.flag, tokenIdToBundleMap, tokenIdToCountMap, result)) {
            continue;
        }
    }

    for (auto iter = tokenIdToBundleMap.begin(); iter != tokenIdToBundleMap.end(); ++iter) {
        result.bundleRecords.emplace_back(iter->second);

        AddDebugLog(iter->first, iter->second, tokenIdToCountMap[iter->first], totalSuccCount, totalFailCount);
    }

    if (request.flag == FLAG_PERMISSION_USAGE_SUMMARY) {
        ACCESSTOKEN_LOG_INFO(LABEL, "Total success count is %{public}d, total failure count is %{public}d",
            totalSuccCount, totalFailCount);
    }

    return true;
}

bool PermissionRecordManager::CreateBundleUsedRecord(const AccessTokenID tokenId, BundleUsedRecord& bundleRecord)
{
    HapTokenInfo tokenInfo;
    if (AccessTokenKit::GetHapTokenInfo(tokenId, tokenInfo) != Constant::SUCCESS) {
        ACCESSTOKEN_LOG_ERROR(LABEL, "GetHapTokenInfo failed, tokenId is %{public}u.", tokenId);
        return false;
    }
    bundleRecord.tokenId = tokenId;
    bundleRecord.isRemote = false;
    bundleRecord.deviceId = GetDeviceId(tokenId);
    bundleRecord.bundleName = tokenInfo.bundleName;
    return true;
}

void PermissionRecordManager::ExecuteDeletePermissionRecordTask()
{
#ifdef EVENTHANDLER_ENABLE
    if (GetCurDeleteTaskNum() > 1) {
        ACCESSTOKEN_LOG_INFO(LABEL, "Has delete task!");
        return;
    }
    AddDeleteTaskNum();
    if (deleteEventHandler_ == nullptr) {
        ACCESSTOKEN_LOG_ERROR(LABEL, "Fail to get EventHandler.");
        ReduceDeleteTaskNum();
        return;
    }

    std::function<void()> delayed = ([this]() {
        DeletePermissionRecord(recordAgingTime_);
        ACCESSTOKEN_LOG_INFO(LABEL, "Delete record end.");
        // Sleep for one minute to avoid frequent refresh of the file.
        std::this_thread::sleep_for(std::chrono::minutes(1));
        ReduceDeleteTaskNum();
    });

    deleteEventHandler_->ProxyPostTask(delayed);
#endif
}

int32_t PermissionRecordManager::GetCurDeleteTaskNum()
{
    return deleteTaskNum_.load();
}

void PermissionRecordManager::AddDeleteTaskNum()
{
    deleteTaskNum_++;
}

void PermissionRecordManager::ReduceDeleteTaskNum()
{
    deleteTaskNum_--;
}

int32_t PermissionRecordManager::DeletePermissionRecord(int32_t days)
{
    int64_t interval = days * Constant::ONE_DAY_MILLISECONDS;
    int32_t total = PermissionUsedRecordDb::GetInstance().Count(PermissionUsedRecordDb::DataType::PERMISSION_RECORD);
    if (total > recordSizeMaximum_) {
        uint32_t excessiveSize = static_cast<uint32_t>(total) - static_cast<uint32_t>(recordSizeMaximum_);
        int32_t res = PermissionUsedRecordDb::GetInstance().DeleteExcessiveRecords(
            PermissionUsedRecordDb::DataType::PERMISSION_RECORD, excessiveSize);
        if (res != PermissionUsedRecordDb::ExecuteResult::SUCCESS) {
            return Constant::FAILURE;
        }
    }
    GenericValues andConditionValues;
    int64_t deleteTimestamp = AccessToken::TimeUtil::GetCurrentTimestamp() - interval;
    andConditionValues.Put(PrivacyFiledConst::FIELD_TIMESTAMP_END, deleteTimestamp);
    int32_t res = PermissionUsedRecordDb::GetInstance().DeleteExpireRecords(
        PermissionUsedRecordDb::DataType::PERMISSION_RECORD, andConditionValues);
    if (res != PermissionUsedRecordDb::ExecuteResult::SUCCESS) {
        return Constant::FAILURE;
    }
    return Constant::SUCCESS;
}

int32_t PermissionRecordManager::AddRecordToStartList(
    uint32_t tokenId, int32_t pid, const std::string& permissionName, int32_t status)
{
    int32_t ret = Constant::SUCCESS;
    int32_t opCode;
    if (!Constant::TransferPermissionToOpcode(permissionName, opCode)) {
        ACCESSTOKEN_LOG_ERROR(LABEL, "Invalid perm(%{public}s)", permissionName.c_str());
        return PrivacyError::ERR_PERMISSION_NOT_EXIST;
    }

    std::lock_guard<std::mutex> lock(startRecordListMutex_);
    bool hasTokenStarted = false;
    bool hasPidStarted = false;
    for (auto& record : startRecordList_) {
        if ((record.opCode == opCode) && (record.tokenId == tokenId)) { // find token
            hasTokenStarted = true;
            if (!IsPidValid(pid) || record.pidList.find(pid) != record.pidList.end()) {
                hasPidStarted = true;
            } else {
                record.pidList.insert(pid);
            }
            break;
        }
    }
    ACCESSTOKEN_LOG_INFO(LABEL, "Id(%{public}u), pid(%{public}d), opCode(%{public}d),\
        hasTokenStarted(%{public}d), hasPidStarted(%{public}d).",
        tokenId, pid, opCode, hasTokenStarted, hasPidStarted);
    if (!hasTokenStarted) {
        ContinusPermissionRecord record = { 0 };
        record.tokenId = tokenId;
        record.status = status;
        record.opCode = opCode;
        if (IsPidValid(pid)) {
            record.pidList.insert(pid);
        }
        startRecordList_.emplace_back(record);
    }
    CallbackExecute(tokenId, permissionName, status);
    if (hasTokenStarted && hasPidStarted) {
        ret = PrivacyError::ERR_PERMISSION_ALREADY_START_USING;
    }
    return ret;
}

void PermissionRecordManager::ExecuteAndUpdateRecord(uint32_t tokenId, int32_t pid, ActiveChangeType status)
{
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
            bool isAllowedBackGround = false;
            if (AccessTokenKit::VerifyAccessToken(tokenId, "ohos.permission.CAMERA_BACKGROUND") == PERMISSION_GRANTED) {
                isAllowedBackGround = true;
            }
            if ((perm == CAMERA_PERMISSION_NAME) && (status == PERM_ACTIVE_IN_BACKGROUND) &&
                (!isShow) && (!isAllowedBackGround)) {
                ACCESSTOKEN_LOG_INFO(LABEL, "Camera float window is close!");
                camPermList.emplace_back(perm);
                continue;
            }

            // update status to input and timestamp to now in cache
            it->status = status;
            ACCESSTOKEN_LOG_DEBUG(LABEL, "TokenId %{public}d get permission %{public}s.", tokenId, perm.c_str());
        }
    }

    if (!camPermList.empty()) {
        ExecuteCameraCallbackAsync(tokenId, pid);
    }
}

/*
 * when foreground change background or background change foreground，change accessDuration and store in database,
 * change status and accessDuration and timestamp in cache
*/
void PermissionRecordManager::NotifyAppStateChange(AccessTokenID tokenId, int32_t pid, ActiveChangeType status)
{
    ACCESSTOKEN_LOG_INFO(LABEL, "Id %{public}u, pid %{public}d, status %{public}d", tokenId, pid, status);
    // find permissions from startRecordList_ by tokenId which status diff from currStatus
    ExecuteAndUpdateRecord(tokenId, pid, status);
}

void PermissionRecordManager::SetLockScreenStatus(int32_t lockScreenStatus)
{
    ACCESSTOKEN_LOG_INFO(LABEL, "LockScreenStatus %{public}d", lockScreenStatus);
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
    return PowerMgrClient::GetInstance().IsScreenOn();
}

int32_t PermissionRecordManager::RemoveRecordFromStartList(
    AccessTokenID tokenId, int32_t pid, const std::string& permissionName)
{
    int32_t opCode;
    if (!Constant::TransferPermissionToOpcode(permissionName, opCode)) {
        ACCESSTOKEN_LOG_ERROR(LABEL, "Invalid permission(%{public}s)", permissionName.c_str());
        return PrivacyError::ERR_PERMISSION_NOT_EXIST;
    }

    ACCESSTOKEN_LOG_DEBUG(LABEL, "Id %{public}u, pid %{public}d, perm %{public}s",
        tokenId, pid, permissionName.c_str());
    int32_t status = PERM_INACTIVE;
    bool isFind = false;
    int32_t ret = Constant::SUCCESS;
    std::lock_guard<std::mutex> lock(startRecordListMutex_);
    for (auto it = startRecordList_.begin(); it != startRecordList_.end();) {
        if ((it->opCode != opCode) || (it->tokenId != tokenId)) {
            ++it;
            continue;
        }
        isFind = !IsPidValid(pid);
        // erase pid from pidList
        if (!isFind && it->pidList.find(pid) != it->pidList.end()) {
            isFind = true;
            it->pidList.erase(pid);
        }
        if (it->pidList.empty()) {
            status = it->status;
            it = startRecordList_.erase(it);
        }
        break;
    }
    if (status != PERM_INACTIVE) {
        CallbackExecute(tokenId, permissionName, PERM_INACTIVE);
    }
    if (!isFind) {
        ret = PrivacyError::ERR_PERMISSION_NOT_START_USING;
        ACCESSTOKEN_LOG_ERROR(LABEL, "No records started, tokenId=%{public}u, pid=%{public}d, opCode=%{public}d",
            tokenId, pid, opCode);
    }
    return ret;
}

/*
* remove all record of pid,
* when pidList is empty, execute active callback
*/
void PermissionRecordManager::RemoveRecordFromStartListByPid(const AccessTokenID tokenId, int32_t pid)
{
    ACCESSTOKEN_LOG_INFO(LABEL, "TokenId %{public}u, pid %{public}d", tokenId, pid);
    bool isUsingCamera = false;
    {
        std::vector<std::string> permList;
        std::lock_guard<std::mutex> lock(startRecordListMutex_);
        for (auto it = startRecordList_.begin(); it != startRecordList_.end();) {
            if (it->tokenId != tokenId || (!it->pidList.empty() && it->pidList.find(pid) == it->pidList.end())) {
                ++it;
                continue;
            }
            it->pidList.erase(pid);
            isUsingCamera = (it->opCode == Constant::OP_CAMERA);
            if (it->pidList.empty()) {
                std::string perm;
                Constant::TransferOpcodeToPermission(it->opCode, perm);
                permList.emplace_back(perm);
                it = startRecordList_.erase(it);
            }
        }
        for (const auto& perm : permList) {
            CallbackExecute(tokenId, perm, PERM_INACTIVE);
        }
    }
    if (isUsingCamera) {
        cameraCallbackMap_.Erase(GetUniqueId(tokenId, pid));
        UnRegisterWindowCallback(); // unregister window linstener
    }
}

/*
* remove all record of token, and execute active callback
*/
void PermissionRecordManager::RemoveRecordFromStartListByToken(const AccessTokenID tokenId)
{
    ACCESSTOKEN_LOG_INFO(LABEL, "TokenId %{public}u", tokenId);
    bool isUsingCamera = false;
    {
        std::vector<std::string> permList;
        std::lock_guard<std::mutex> lock(startRecordListMutex_);
        for (auto it = startRecordList_.begin(); it != startRecordList_.end();) {
            if (it->tokenId != tokenId) {
                ++it;
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
        cameraCallbackMap_.Erase(GetUniqueId(tokenId, -1));
        UnRegisterWindowCallback(); // unregister window linstener
    }
}

void PermissionRecordManager::RemoveRecordFromStartListByOp(int32_t opCode)
{
    ACCESSTOKEN_LOG_INFO(LABEL, "OpCode %{public}d", opCode);
    bool isUsingCamera = (opCode == Constant::OP_CAMERA);
    std::string perm;
    Constant::TransferOpcodeToPermission(opCode, perm);
    {
        std::vector<AccessTokenID> tokenList;
        std::lock_guard<std::mutex> lock(startRecordListMutex_);
        for (auto it = startRecordList_.begin(); it != startRecordList_.end();) {
            if (it->opCode != opCode) {
                ++it;
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
        ACCESSTOKEN_LOG_INFO(LABEL, "Permission is %{public}s, status is %{public}d", permissionName.c_str(), isOpen);
    } else if (permissionName == CAMERA_PERMISSION_NAME) {
        isOpen = !isCamMixMute_;
        ACCESSTOKEN_LOG_INFO(LABEL, "Permission is %{public}s, status is %{public}d", permissionName.c_str(), isOpen);
    }
    return isOpen;
}
#ifndef APP_SECURITY_PRIVACY_SERVICE
/*
 * StartUsing when close and choose open, update status to foreground or background from inactive
 * StartUsing when open and choose close, update status to inactive and store in database
 */
void PermissionRecordManager::ExecuteAndUpdateRecordByPerm(const std::string& permissionName, bool switchStatus)
{
    int32_t opCode;
    Constant::TransferPermissionToOpcode(permissionName, opCode);
    std::vector<ContinusPermissionRecord> recordList;
    std::lock_guard<std::mutex> lock(startRecordListMutex_);
    for (auto it = startRecordList_.begin(); it != startRecordList_.end(); ++it) {
        ContinusPermissionRecord& record = *it;
        if ((record.opCode) != static_cast<int32_t>(opCode)) {
            continue;
        }
        if (switchStatus) {
            ACCESSTOKEN_LOG_INFO(LABEL, "Global switch is open, update record from inactive");
            // no need to store in database when status from inactive to foreground or background
            record.status = GetAppStatus(record.tokenId);
        } else {
            ACCESSTOKEN_LOG_INFO(LABEL, "Global switch is close, update record to inactive");
            record.status = PERM_INACTIVE;
        }
        recordList.emplace_back(*it);
    }
    // each permission sends a status change notice
    for (const auto& record : recordList) {
        CallbackExecute(record.tokenId, permissionName, record.status);
    }
}
#endif
bool PermissionRecordManager::ShowGlobalDialog(const std::string& permissionName)
{
    std::string resource;
    if (permissionName == CAMERA_PERMISSION_NAME) {
        resource = "camera";
    } else if (permissionName == MICROPHONE_PERMISSION_NAME) {
        resource = "microphone";
    } else {
        ACCESSTOKEN_LOG_INFO(LABEL, "Invalid permissionName(%{public}s).", permissionName.c_str());
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

void PermissionRecordManager::ExecuteAllCameraExecuteCallback()
{
    ACCESSTOKEN_LOG_INFO(LABEL, "ExecuteAllCameraExecuteCallback called");
    auto it = [&](uint64_t id, sptr<IRemoteObject> cameraCallback) {
        auto callback = iface_cast<IStateChangeCallback>(cameraCallback);
        AccessTokenID tokenId = static_cast<AccessTokenID>(id);
        if (callback != nullptr) {
            ACCESSTOKEN_LOG_INFO(
                LABEL, "CameraCallback tokenId %{public}d changeType %{public}d.", tokenId, PERM_INACTIVE);
            callback->StateChangeNotify(tokenId, false);
        }
    };
    this->cameraCallbackMap_.Iterate(it);
}

void PermissionRecordManager::ExecuteCameraCallbackAsync(AccessTokenID tokenId, int32_t pid)
{
    ACCESSTOKEN_LOG_DEBUG(LABEL, "Entry.");
    auto task = [tokenId, pid, this]() {
        uint64_t uniqueId = GetUniqueId(tokenId, pid);
        ACCESSTOKEN_LOG_INFO(LABEL, "ExecuteCameraCallbackAsync task called.");
        auto it = [&](uint64_t id, sptr<IRemoteObject> cameraCallback) {
            auto callback = iface_cast<IStateChangeCallback>(cameraCallback);
            if ((uniqueId == id) && (callback != nullptr)) {
                ACCESSTOKEN_LOG_INFO(LABEL, "CameraCallback tokenId(%{public}u) pid( %{public}d) changeType %{public}d",
                    tokenId, pid, PERM_INACTIVE);
                callback->StateChangeNotify(tokenId, false);
            }
        };
        this->cameraCallbackMap_.Iterate(it);
    };
    std::thread executeThread(task);
    executeThread.detach();
    ACCESSTOKEN_LOG_DEBUG(LABEL, "The cameraCallback execution is complete.");
}

int32_t PermissionRecordManager::StartUsingPermission(
    AccessTokenID tokenId, int32_t pid, const std::string& permissionName)
{
    if (AccessTokenKit::GetTokenTypeFlag(tokenId) != TOKEN_HAP) {
        ACCESSTOKEN_LOG_DEBUG(LABEL, "Not hap(%{public}d).", tokenId);
        return PrivacyError::ERR_PARAM_INVALID;
    }

    InitializeMuteState(permissionName);
    if (GetMuteStatus(permissionName, EDM)) {
        ACCESSTOKEN_LOG_ERROR(LABEL, "EDM not allow.");
        return PrivacyError::ERR_EDM_POLICY_CHECK_FAILED;
    }
    if (!Register()) {
        return PrivacyError::ERR_MALLOC_FAILED;
    }

    int32_t status = GetAppStatus(tokenId);
#ifndef APP_SECURITY_PRIVACY_SERVICE
    if (!GetGlobalSwitchStatus(permissionName)) {
        if (!ShowGlobalDialog(permissionName)) {
            return ERR_SERVICE_ABNORMAL;
        }
        status = PERM_INACTIVE;
    }
#endif
    return AddRecordToStartList(tokenId, pid, permissionName, status);
}

int32_t PermissionRecordManager::StartUsingPermission(
    AccessTokenID tokenId, int32_t pid, const std::string& permissionName, const sptr<IRemoteObject>& callback)
{
    if ((permissionName != CAMERA_PERMISSION_NAME) || (AccessTokenKit::GetTokenTypeFlag(tokenId) != TOKEN_HAP)) {
        ACCESSTOKEN_LOG_DEBUG(LABEL, "Token(%{public}u), perm(%{public}s).", tokenId, permissionName.c_str());
        return PrivacyError::ERR_PARAM_INVALID;
    }

    InitializeMuteState(permissionName);
    if (GetMuteStatus(permissionName, EDM)) {
        ACCESSTOKEN_LOG_ERROR(LABEL, "EDM not allow.");
        return PrivacyError::ERR_EDM_POLICY_CHECK_FAILED;
    }

    if (!Register()) {
        return PrivacyError::ERR_MALLOC_FAILED;
    }
    int32_t status = GetAppStatus(tokenId);
#ifndef APP_SECURITY_PRIVACY_SERVICE
    if (!GetGlobalSwitchStatus(permissionName)) {
        if (!ShowGlobalDialog(permissionName)) {
            return ERR_SERVICE_ABNORMAL;
        }
        status = PERM_INACTIVE;
    }
#endif
    uint64_t id = GetUniqueId(tokenId, pid);
    cameraCallbackMap_.EnsureInsert(id, callback);
    if (!RegisterWindowCallback()) {
        cameraCallbackMap_.Erase(id);
        return PrivacyError::ERR_WINDOW_CALLBACK_FAILED;
    }
    int32_t ret = AddRecordToStartList(tokenId, pid, permissionName, status);
    if (ret != RET_SUCCESS) {
        cameraCallbackMap_.Erase(id);
    }
    return ret;
}

int32_t PermissionRecordManager::StopUsingPermission(
    AccessTokenID tokenId, int32_t pid, const std::string& permissionName)
{
    ExecuteDeletePermissionRecordTask();

    if (AccessTokenKit::GetTokenTypeFlag(tokenId) != TOKEN_HAP) {
        ACCESSTOKEN_LOG_DEBUG(LABEL, "Not hap(%{public}d).", tokenId);
        return PrivacyError::ERR_PARAM_INVALID;
    }

    // clear callback
    UnRegisterWindowCallback();
    return RemoveRecordFromStartList(tokenId, pid, permissionName);
}

void PermissionRecordManager::PermListToString(const std::vector<std::string>& permList)
{
    std::string permStr;
    permStr = accumulate(permList.begin(), permList.end(), std::string(" "));

    ACCESSTOKEN_LOG_INFO(LABEL, "PermStr =%{public}s.", permStr.c_str());
}

int32_t PermissionRecordManager::PermissionListFilter(
    const std::vector<std::string>& listSrc, std::vector<std::string>& listRes)
{
    // filter legal permissions
    PermissionDef permissionDef;
    std::set<std::string> permSet;
    for (const auto& perm : listSrc) {
        if (AccessTokenKit::GetDefPermission(perm, permissionDef) == Constant::SUCCESS &&
            permSet.count(perm) == 0) {
            listRes.emplace_back(perm);
            permSet.insert(perm);
            continue;
        }
        ACCESSTOKEN_LOG_ERROR(LABEL, "Permission %{public}s invalid!", perm.c_str());
    }
    if ((listRes.empty()) && (!listSrc.empty())) {
        ACCESSTOKEN_LOG_ERROR(LABEL, "Valid permission size is 0!");
        return PrivacyError::ERR_PARAM_INVALID;
    }
    PermListToString(listRes);
    return Constant::SUCCESS;
}

bool PermissionRecordManager::IsAllowedUsingCamera(AccessTokenID tokenId)
{
    int32_t status = GetAppStatus(tokenId);
    bool isScreenOn = IsScreenOn();
    bool isAllowedBackGround = false;
    if (AccessTokenKit::VerifyAccessToken(tokenId, "ohos.permission.CAMERA_BACKGROUND") == PERMISSION_GRANTED) {
        isAllowedBackGround = true;
    }
    ACCESSTOKEN_LOG_INFO(LABEL,
        "Id(%{public}d), appStatus(%{public}d), isScreenOn(%{public}d, isAllowedBackGround(%{public}d)).",
        tokenId, status, isScreenOn, isAllowedBackGround);
    return ((status == ActiveChangeType::PERM_ACTIVE_IN_FOREGROUND) && isScreenOn) || isAllowedBackGround;
}

bool PermissionRecordManager::IsAllowedUsingMicrophone(AccessTokenID tokenId)
{
    int32_t status = GetAppStatus(tokenId);
    ACCESSTOKEN_LOG_INFO(LABEL, "Id %{public}d, status is %{public}d.", tokenId, status);
    if (status == ActiveChangeType::PERM_ACTIVE_IN_FOREGROUND) {
        return true;
    }

    std::lock_guard<std::mutex> lock(foreReminderMutex_);
    auto iter = std::find(foreTokenIdList_.begin(), foreTokenIdList_.end(), tokenId);
    if (iter != foreTokenIdList_.end()) {
        return true;
    }
    return false;
}

bool PermissionRecordManager::IsAllowedUsingPermission(AccessTokenID tokenId, const std::string& permissionName)
{
    if (AccessTokenKit::GetTokenTypeFlag(tokenId) != TOKEN_HAP) {
        ACCESSTOKEN_LOG_DEBUG(LABEL, "Id(%{public}d) is not hap.", tokenId);
        return false;
    }

    if (GetMuteStatus(permissionName, EDM)) {
        ACCESSTOKEN_LOG_ERROR(LABEL, "EDM not allow.");
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
    std::string permissionName;
    if (callerType == MICROPHONE) {
        permissionName = MICROPHONE_PERMISSION_NAME;
    } else if (callerType == CAMERA) {
        permissionName = CAMERA_PERMISSION_NAME;
    } else {
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
    return ERR_PARAM_INVALID;
}

int32_t PermissionRecordManager::SetHapWithFGReminder(uint32_t tokenId, bool isAllowed)
{
    if (AccessTokenKit::GetTokenTypeFlag(tokenId) != TOKEN_HAP) {
        ACCESSTOKEN_LOG_ERROR(LABEL, "Not hap(%{public}d).", tokenId);
        return PrivacyError::ERR_PARAM_INVALID;
    }
    std::lock_guard<std::mutex> lock(foreReminderMutex_);
    auto iter = std::find(foreTokenIdList_.begin(), foreTokenIdList_.end(), tokenId);
    if (iter == foreTokenIdList_.end() && isAllowed) {
        foreTokenIdList_.emplace_back(tokenId);
        ACCESSTOKEN_LOG_INFO(LABEL, "Set hap(%{public}d) foreground.", tokenId);
        return RET_SUCCESS;
    }
    if (iter != foreTokenIdList_.end() && !isAllowed) {
        foreTokenIdList_.erase(iter);
        ACCESSTOKEN_LOG_INFO(LABEL, "cancel hap(%{public}d) foreground.", tokenId);
        return RET_SUCCESS;
    }
    ACCESSTOKEN_LOG_ERROR(LABEL, "(%{public}d) is invalid to be operated.", tokenId);
    return PrivacyError::ERR_PARAM_INVALID;
}

int32_t PermissionRecordManager::SetEdmMutePolicy(const std::string permissionName, bool isMute)
{
    if (isMute) {
        ModifyMuteStatus(permissionName, EDM, isMute);
        ModifyMuteStatus(permissionName, MIXED, isMute);
#ifndef APP_SECURITY_PRIVACY_SERVICE
        ExecuteAndUpdateRecordByPerm(permissionName, false);
#endif
    } else {
        ModifyMuteStatus(permissionName, EDM, isMute);
        if (GetMuteStatus(permissionName, MIXED)) {
            return ERR_PRIVACY_POLICY_CHECK_FAILED;
        }
    }
    return RET_SUCCESS;
}

int32_t PermissionRecordManager::SetPrivacyMutePolicy(const std::string permissionName, bool isMute)
{
    if (isMute) {
        ModifyMuteStatus(permissionName, MIXED, isMute);
    } else {
        if (GetMuteStatus(permissionName, EDM)) {
            return PrivacyError::ERR_EDM_POLICY_CHECK_FAILED;
        }
        ModifyMuteStatus(permissionName, MIXED, isMute);
    }
#ifndef APP_SECURITY_PRIVACY_SERVICE
    ExecuteAndUpdateRecordByPerm(permissionName, !isMute);
#endif
    return RET_SUCCESS;
}

int32_t PermissionRecordManager::SetTempMutePolicy(const std::string permissionName, bool isMute)
{
    if (!isMute) {
        if (GetMuteStatus(permissionName, EDM)) {
            return PrivacyError::ERR_EDM_POLICY_CHECK_FAILED;
        }
        if (GetMuteStatus(permissionName, MIXED)) {
            AccessTokenID callingTokenID = IPCSkeleton::GetCallingTokenID();
            CallbackExecute(callingTokenID, permissionName, PERM_TEMPORARY_CALL);
            return PrivacyError::ERR_PRIVACY_POLICY_CHECK_FAILED;
        }
    }
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
    ACCESSTOKEN_LOG_INFO(LABEL, "permissionName: %{public}s, isMute: %{public}d, index: %{public}d.",
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
    } else {
        return false;
    }
    ACCESSTOKEN_LOG_INFO(LABEL, "perm: %{public}s, isMute: %{public}d, index: %{public}d.",
        permissionName.c_str(), isMute, index);
    return isMute;
}

int32_t PermissionRecordManager::RegisterPermActiveStatusCallback(
    AccessTokenID regiterTokenId, const std::vector<std::string>& permList, const sptr<IRemoteObject>& callback)
{
    std::vector<std::string> permListRes;
    int32_t res = PermissionListFilter(permList, permListRes);
    if (res != Constant::SUCCESS) {
        return res;
    }
    return ActiveStatusCallbackManager::GetInstance().AddCallback(regiterTokenId, permListRes, callback);
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
            ACCESSTOKEN_LOG_ERROR(LABEL, "Invalid tokenId(%{public}d).", tokenId);
            return PrivacyError::ERR_TOKENID_NOT_EXIST;
        }
        value.Put(PrivacyFiledConst::FIELD_TOKEN_ID, static_cast<int32_t>(tokenId));
    }

    if (!permissionName.empty()) {
        int32_t opCode;
        if (!Constant::TransferPermissionToOpcode(permissionName, opCode)) {
            ACCESSTOKEN_LOG_ERROR(LABEL, "Invalid (%{public}s).", permissionName.c_str());
            return PrivacyError::ERR_PERMISSION_NOT_EXIST;
        }
        value.Put(PrivacyFiledConst::FIELD_PERMISSION_CODE, opCode);
    }

    std::vector<GenericValues> valueResults;
    if (PermissionUsedRecordDb::GetInstance().Query(PermissionUsedRecordDb::DataType::PERMISSION_USED_TYPE,
        value, valueResults) != PermissionUsedRecordDb::ExecuteResult::SUCCESS) {
        return Constant::FAILURE;
    }

    for (const auto& valueResult : valueResults) {
        AddDataValueToResults(valueResult, results);
    }

    ACCESSTOKEN_LOG_INFO(LABEL, "Get %{public}zu permission used type records.", results.size());

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

bool PermissionRecordManager::Register()
{
    // app manager death callback register
    {
        std::lock_guard<std::mutex> lock(appManagerDeathMutex_);
        if (appManagerDeathCallback_ == nullptr) {
            appManagerDeathCallback_ = std::make_shared<PrivacyAppManagerDeathCallback>();
            if (appManagerDeathCallback_ == nullptr) {
                ACCESSTOKEN_LOG_ERROR(LABEL, "Register appManagerDeathCallback failed.");
                return false;
            }
            AppManagerAccessClient::GetInstance().RegisterDeathCallback(appManagerDeathCallback_);
        }
    }
    // app state change callback register
    {
        std::lock_guard<std::mutex> lock(appStateMutex_);
        if (appStateCallback_ == nullptr) {
            appStateCallback_ = new (std::nothrow) PrivacyAppStateObserver();
            if (appStateCallback_ == nullptr) {
                ACCESSTOKEN_LOG_ERROR(LABEL, "Register appStateCallback failed.");
                return false;
            }
            int32_t result = AppManagerAccessClient::GetInstance().RegisterApplicationStateObserver(appStateCallback_);
            if (result != ERR_OK) {
                ACCESSTOKEN_LOG_ERROR(LABEL, "Register application state observer failed.");
                return false;
            }
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

void PermissionRecordManager::InitializeMuteState(const std::string& permissionName)
{
    if (permissionName == MICROPHONE_PERMISSION_NAME) {
        bool isMicMute = AudioManagerPrivacyClient::GetInstance().GetPersistentMicMuteState();
        ACCESSTOKEN_LOG_INFO(LABEL, "Mic mute state: %{public}d.", isMicMute);
        ModifyMuteStatus(MICROPHONE_PERMISSION_NAME, MIXED, isMicMute);
        {
            std::lock_guard<std::mutex> lock(micLoadMutex_);
            if (!isMicLoad_) {
                ACCESSTOKEN_LOG_INFO(LABEL, "Mic mute state: %{public}d.", isMicLoad_);
                bool isEdmMute = false;
                if (!GetMuteParameter(EDM_MIC_MUTE_KEY, isEdmMute)) {
                    ACCESSTOKEN_LOG_ERROR(LABEL, "Get param failed");
                    return;
                }
                ModifyMuteStatus(MICROPHONE_PERMISSION_NAME, EDM, isEdmMute);
            }
        }
    } else if (permissionName == CAMERA_PERMISSION_NAME) {
        bool isCameraMute = CameraManagerPrivacyClient::GetInstance().IsCameraMuted();
        ACCESSTOKEN_LOG_INFO(LABEL, "Camera mute state: %{public}d.", isCameraMute);
        ModifyMuteStatus(CAMERA_PERMISSION_NAME, MIXED, isCameraMute);
        {
            std::lock_guard<std::mutex> lock(camLoadMutex_);
            if (!isCamLoad_) {
                bool isEdmMute = false;
                if (!GetMuteParameter(EDM_CAMERA_MUTE_KEY, isEdmMute)) {
                    ACCESSTOKEN_LOG_ERROR(LABEL, "Get camera param failed");
                    return;
                }
                ModifyMuteStatus(CAMERA_PERMISSION_NAME, EDM, isEdmMute);
            }
        }
    }
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
    ACCESSTOKEN_LOG_INFO(LABEL, "Handle app fwk died.");
    std::lock_guard<std::mutex> lock(appStateMutex_);
    appStateCallback_ = nullptr;
}

void PermissionRecordManager::OnAudioMgrRemoteDiedHandle()
{
    ACCESSTOKEN_LOG_INFO(LABEL, "Handle audio fwk died.");
    {
        std::lock_guard<std::mutex> lock(micLoadMutex_);
        isMicLoad_ = false;
    }
    RemoveRecordFromStartListByOp(Constant::OP_MICROPHONE);
}

void PermissionRecordManager::OnCameraMgrRemoteDiedHandle()
{
    ACCESSTOKEN_LOG_INFO(LABEL, "Handle camera fwk died.");
    {
        std::lock_guard<std::mutex> lock(camLoadMutex_);
        isCamLoad_ = false;
    }
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
    std::lock_guard<std::mutex> lock(windowStatusMutex_);
    isShow = (((floatWindowTokenId_ == tokenId) && camFloatWindowShowing_) ||
        ((pipWindowTokenId_ == tokenId) && pipWindowShowing_));
#endif
    return isShow;
}

#ifdef CAMERA_FLOAT_WINDOW_ENABLE
/*
 * when camera float window is not show, notice camera service to use StopUsingPermission
 */
void PermissionRecordManager::NotifyCameraWindowChange(bool isPip, AccessTokenID tokenId, bool isShowing)
{
    ACCESSTOKEN_LOG_INFO(LABEL, "Update window, isPip(%{public}d), id(%{public}u), status(%{public}d)",
        isPip, tokenId, isShowing);
    {
        std::lock_guard<std::mutex> lock(windowStatusMutex_);
        if (isPip) {
            pipWindowShowing_ = isShowing;
            pipWindowTokenId_ = tokenId;
        } else {
            camFloatWindowShowing_ = isShowing;
            floatWindowTokenId_ = tokenId;
        }
    }
    if (isShowing) {
        ACCESSTOKEN_LOG_INFO(LABEL, "Camera float window is showing!");
    } else {
        if ((GetAppStatus(tokenId) == ActiveChangeType::PERM_ACTIVE_IN_BACKGROUND) &&
            !IsCameraWindowShow(tokenId)) {
            ACCESSTOKEN_LOG_INFO(LABEL, "Token(%{public}d) is background, pip and float window is not show.", tokenId);
            ExecuteCameraCallbackAsync(tokenId, -1);
        }
    }
}

void PermissionRecordManager::ClearWindowShowing()
{
    ACCESSTOKEN_LOG_INFO(LABEL, "Clear window show status.");
    {
        std::lock_guard<std::mutex> lock(windowStatusMutex_);
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
    recordSizeMaximum_ = DEFAULT_PERMISSION_USED_RECORD_SIZE_MAXIMUM;
    recordAgingTime_ = DEFAULT_PERMISSION_USED_RECORD_AGING_TIME;
    globalDialogBundleName_ = DEFAULT_PERMISSION_MANAGER_BUNDLE_NAME;
    globalDialogAbilityName_ = DEFAULT_PERMISSION_MANAGER_DIALOG_ABILITY;
}

void PermissionRecordManager::GetConfigValue()
{
    LibraryLoader loader(CONFIG_POLICY_LIBPATH);
    ConfigPolicyLoaderInterface* policy = loader.GetObject<ConfigPolicyLoaderInterface>();
    if (policy == nullptr) {
        ACCESSTOKEN_LOG_ERROR(LABEL, "Dlopen libaccesstoken_config_policy failed.");
        return;
    }
    AccessTokenConfigValue value;
    if (policy->GetConfigValue(ServiceType::PRIVACY_SERVICE, value)) {
        // set value from config
        recordSizeMaximum_ = value.pConfig.sizeMaxImum == 0
            ? DEFAULT_PERMISSION_USED_RECORD_SIZE_MAXIMUM : value.pConfig.sizeMaxImum;
        recordAgingTime_ = value.pConfig.agingTime == 0
            ? DEFAULT_PERMISSION_USED_RECORD_AGING_TIME : value.pConfig.agingTime;
        globalDialogBundleName_ = value.pConfig.globalDialogBundleName.empty()
            ? DEFAULT_PERMISSION_MANAGER_BUNDLE_NAME : value.pConfig.globalDialogBundleName;
        globalDialogAbilityName_ = value.pConfig.globalDialogAbilityName.empty()
            ? DEFAULT_PERMISSION_MANAGER_DIALOG_ABILITY : value.pConfig.globalDialogAbilityName;
    } else {
        SetDefaultConfigValue();
    }

    ACCESSTOKEN_LOG_INFO(LABEL, "RecordSizeMaximum_ is %{public}d, recordAgingTime_ is %{public}d,"
        " globalDialogBundleName_ is %{public}s, globalDialogAbilityName_ is %{public}s.",
        recordSizeMaximum_, recordAgingTime_, globalDialogBundleName_.c_str(), globalDialogAbilityName_.c_str());
}

uint64_t PermissionRecordManager::GetUniqueId(uint32_t tokenId, int32_t pid) const
{
    uint32_t tmpPid = (pid <= 0) ? 0 : (uint32_t)pid;
    return ((uint64_t)tmpPid << 32) | ((uint64_t)tokenId & 0xFFFFFFFF); // 32: bit
}

bool PermissionRecordManager::IsPidValid(int32_t pid) const
{
    return pid > 0;
}

void PermissionRecordManager::Init()
{
    if (hasInited_) {
        return;
    }
    ACCESSTOKEN_LOG_INFO(LABEL, "Init");
    hasInited_ = true;

#ifdef EVENTHANDLER_ENABLE
    deleteEventRunner_ = AppExecFwk::EventRunner::Create(true, AppExecFwk::ThreadMode::FFRT);
    if (deleteEventRunner_ != nullptr) {
        deleteEventHandler_ = std::make_shared<AccessEventHandler>(deleteEventRunner_);
    }
#endif

    GetConfigValue();
}
} // namespace AccessToken
} // namespace Security
} // namespace OHOS