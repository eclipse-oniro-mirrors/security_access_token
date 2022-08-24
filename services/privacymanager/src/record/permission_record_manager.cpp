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

#include "accesstoken_kit.h"
#include "accesstoken_log.h"
#include "active_status_callback_manager.h"
#include "constant.h"
#include "constant_common.h"
#include "data_translator.h"
#include "field_const.h"
#include "permission_record_repository.h"
#include "permission_used_record_cache.h"
#include "time_util.h"
#include "to_string.h"

namespace OHOS {
namespace Security {
namespace AccessToken {
namespace {
static constexpr OHOS::HiviewDFX::HiLogLabel LABEL = {
    LOG_CORE, SECURITY_DOMAIN_PRIVACY, "PermissionRecordManager"
};
static const std::string DEFAULT_DEVICEID = "0";
}
PermissionRecordManager& PermissionRecordManager::GetInstance()
{
    static PermissionRecordManager instance;
    return instance;
}

PermissionRecordManager::PermissionRecordManager() : hasInited_(false) {}

PermissionRecordManager::~PermissionRecordManager()
{
    if (!hasInited_) {
        return;
    }
    deleteTaskWorker_.Stop();
    hasInited_ = false;
}

void PermissionRecordManager::AddRecord(const PermissionRecord& record)
{
    Utils::UniqueWriteGuard<Utils::RWLock> lk(this->rwLock_);
    PermissionUsedRecordCache::GetInstance().AddRecordToBuffer(const_cast<PermissionRecord&>(record));
}

bool PermissionRecordManager::GetPermissionRecord(AccessTokenID tokenId, const std::string& permissionName,
    int32_t successCount, int32_t failCount, PermissionRecord& record)
{
    HapTokenInfo tokenInfo;
    if (AccessTokenKit::GetHapTokenInfo(tokenId, tokenInfo) != Constant::SUCCESS) {
        ACCESSTOKEN_LOG_ERROR(LABEL, "invalid tokenId(%{public}d)", tokenId);
        return false;
    }
    int32_t opCode;
    if (!Constant::TransferPermissionToOpcode(permissionName, opCode)) {
        ACCESSTOKEN_LOG_ERROR(LABEL, "invalid permission(%{public}s)", permissionName.c_str());
        return false;
    }
    if (successCount == 0 && failCount == 0) {
        record.status = PERM_INACTIVE;
    } else {
        record.status = PERM_ACTIVE_IN_FOREGROUND;
    }
    record.tokenId = tokenId;
    record.accessCount = successCount;
    record.rejectCount = failCount;
    record.opCode = opCode;
    record.timestamp = TimeUtil::GetCurrentTimestamp();
    record.accessDuration = 0;
    ACCESSTOKEN_LOG_DEBUG(LABEL, "record status: %{public}d", record.status);
    return true;
}

int32_t PermissionRecordManager::AddPermissionUsedRecord(AccessTokenID tokenId, const std::string& permissionName,
    int32_t successCount, int32_t failCount)
{
    ExecuteDeletePermissionRecordTask();

    PermissionRecord record;
    if (!GetPermissionRecord(tokenId, permissionName, successCount, failCount, record)) {
        return Constant::FAILURE;
    }

    if (record.status == PERM_INACTIVE) {
        return Constant::FAILURE;
    }

    AddRecord(record);
    return Constant::SUCCESS;
}

void PermissionRecordManager::RemovePermissionUsedRecords(AccessTokenID tokenId, const std::string& deviceID)
{
    if (tokenId == 0) {
        ACCESSTOKEN_LOG_ERROR(LABEL, "tokenId is 0");
        return;
    }

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
    GenericValues record;
    record.Put(FIELD_TOKEN_ID, (int32_t)tokenId);
    PermissionUsedRecordCache::GetInstance().RemoveRecords(record); // remove from cache and database
}

int32_t PermissionRecordManager::GetPermissionUsedRecords(
    const PermissionUsedRequest& request, PermissionUsedResult& result)
{
    ExecuteDeletePermissionRecordTask();

    if (!request.isRemote && !GetRecordsFromLocalDB(request, result)) {
        ACCESSTOKEN_LOG_ERROR(LABEL, "Failed to GetRecordsFromLocalDB");
        return  Constant::FAILURE;
    }
    return Constant::SUCCESS;
}

int32_t PermissionRecordManager::GetPermissionUsedRecordsAsync(
    const PermissionUsedRequest& request, const sptr<OnPermissionUsedRecordCallback>& callback)
{
    auto task = [request, callback]() {
        ACCESSTOKEN_LOG_INFO(LABEL, "GetPermissionUsedRecordsAsync task called");
        PermissionUsedResult result;
        int32_t ret = PermissionRecordManager::GetInstance().GetPermissionUsedRecords(request, result);
        callback->OnQueried(ret, result);
    };
    std::thread recordThread(task);
    recordThread.detach();
    return Constant::SUCCESS;
}

bool PermissionRecordManager::GetLocalRecordTokenIdList(std::set<AccessTokenID>& tokenIdList)
{
    std::vector<GenericValues> results;
    {
        Utils::UniqueWriteGuard<Utils::RWLock> lk(this->rwLock_);
        // find tokenId from cache
        PermissionUsedRecordCache::GetInstance().FindTokenIdList(tokenIdList);
        // find tokenId from database
        PermissionRecordRepository::GetInstance().GetAllRecordValuesByKey(FIELD_TOKEN_ID, results);
    }
    for (const auto& res : results) {
        tokenIdList.emplace(res.GetInt(FIELD_TOKEN_ID));
    }
    return true;
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
        andConditionValues.Put(FIELD_TOKEN_ID, (int32_t)tokenId);
        std::vector<GenericValues> findRecordsValues;
        PermissionUsedRecordCache::GetInstance().GetRecords(request.permissionList,
            andConditionValues, orConditionValues, findRecordsValues); // find records from cache and database
        andConditionValues.Remove(FIELD_TOKEN_ID);
        BundleUsedRecord bundleRecord;
        CreateBundleUsedRecord(tokenId, bundleRecord);
        if (!findRecordsValues.empty()) {
            if (!GetRecords(request.flag, findRecordsValues, bundleRecord, result)) {
                return false;
            }
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

bool PermissionRecordManager::GetRecords(
    int32_t flag, std::vector<GenericValues> recordValues, BundleUsedRecord& bundleRecord, PermissionUsedResult& result)
{
    std::vector<PermissionUsedRecord> permissionRecords;
    for (auto it = recordValues.rbegin(); it != recordValues.rend(); ++it) {
        GenericValues record = *it;
        PermissionUsedRecord tmpPermissionRecord;
        int64_t timestamp = record.GetInt64(FIELD_TIMESTAMP);
        result.beginTimeMillis = ((result.beginTimeMillis == 0) || (timestamp < result.beginTimeMillis)) ?
            timestamp : result.beginTimeMillis;
        result.endTimeMillis = (timestamp > result.endTimeMillis) ? timestamp : result.endTimeMillis;

        record.Put(FIELD_FLAG, flag);
        if (DataTranslator::TranslationGenericValuesIntoPermissionUsedRecord(record, tmpPermissionRecord)
            != Constant::SUCCESS) {
            ACCESSTOKEN_LOG_ERROR(LABEL, "Failed to transform opcode(%{public}d) into permission",
                record.GetInt(FIELD_OP_CODE));
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
    return true;
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
    andConditionValues.Put(FIELD_TIMESTAMP_END, deleteTimestamp);
    if (!PermissionRecordRepository::GetInstance().DeleteExpireRecordsValues(andConditionValues)) {
        return Constant::FAILURE;
    }
    return Constant::SUCCESS;
}

std::string PermissionRecordManager::DumpRecordInfo(AccessTokenID tokenId, const std::string& permissionName)
{
    PermissionUsedRequest request;
    request.tokenId = tokenId;
    request.flag = FLAG_PERMISSION_USAGE_DETAIL;
    if (!permissionName.empty()) {
        request.permissionList.emplace_back(permissionName);
    }

    PermissionUsedResult result;
    if (!GetRecordsFromLocalDB(request, result)) {
        ACCESSTOKEN_LOG_ERROR(LABEL, "failed to GetRecordsFromLocalDB");
        return "";
    }

    if (result.bundleRecords.empty()) {
        ACCESSTOKEN_LOG_DEBUG(LABEL, "no record");
        return "";
    }
    std::string dumpInfo;
    ToString::PermissionUsedResultToString(result, dumpInfo);
    return dumpInfo;
}

bool PermissionRecordManager::HasStarted(const PermissionRecord& record)
{
    Utils::UniqueWriteGuard<Utils::RWLock> lk(this->startRecordListRWLock_);
    for (const auto& rec : startRecordList_) {
        if ((rec.opCode == record.opCode) && (rec.tokenId == record.tokenId)) {
            ACCESSTOKEN_LOG_ERROR(LABEL, "tokenId(%{public}d), opCode(%{public}d) has been started.",
                record.tokenId, record.opCode);
            return true;
        }
    }
    return false;
}

void PermissionRecordManager::AddRecordToStartList(const PermissionRecord& record)
{
    Utils::UniqueWriteGuard<Utils::RWLock> lk(this->startRecordListRWLock_);
    startRecordList_.emplace_back(record);
}

bool PermissionRecordManager::GetRecordFromStartList(uint32_t tokenId,  int32_t opCode, PermissionRecord& record)
{
    Utils::UniqueWriteGuard<Utils::RWLock> lk(this->startRecordListRWLock_);
    for (auto it = startRecordList_.begin(); it != startRecordList_.end(); ++it) {
        if ((it->opCode == opCode) && (tokenId == (it->tokenId))) {
            record = *it;
            record.accessDuration = TimeUtil::GetCurrentTimestamp() - record.timestamp;
            startRecordList_.erase(it);
            return true;
        }
    }
    return false;
}

void PermissionRecordManager::ResetRecord(PermissionRecord& record, int32_t status)
{
    record.status = status;
    record.accessDuration = 0;
    record.timestamp = TimeUtil::GetCurrentTimestamp();
}

std::vector<PermissionRecord> PermissionRecordManager::GetRecordsAndReset(uint32_t tokenId, int32_t status)
{
    std::vector<PermissionRecord> recordList;
    Utils::UniqueWriteGuard<Utils::RWLock> lk(this->startRecordListRWLock_);
    for (auto it = startRecordList_.begin(); it != startRecordList_.end(); ++it) {
        if ((it->tokenId == tokenId) && status != (it->status)) {
            PermissionRecord record = *it;
            record.accessDuration = TimeUtil::GetCurrentTimestamp() - record.timestamp;
            recordList.emplace_back(record);
            ResetRecord(*it, status);
        }
    }
    return recordList;
}

void PermissionRecordManager::CallbackExecute(
    AccessTokenID tokenId, const std::string& permissionName, int32_t status)
{
    ActiveStatusCallbackManager::GetInstance().ExecuteCallbackAsync(
        tokenId, permissionName, GetDeviceId(tokenId), (ActiveChangeType)status);
}

int32_t PermissionRecordManager::StartUsingPermission(AccessTokenID tokenId, const std::string& permissionName)
{
    int32_t accessCount = 1;
    int32_t failCount = 0;

    PermissionRecord record = { 0 };
    if (!GetPermissionRecord(tokenId, permissionName, accessCount, failCount, record)) {
        return Constant::FAILURE;
    }

    if (HasStarted(record)) {
        return Constant::FAILURE;
    }

    AddRecordToStartList(record);
    if (record.status != PERM_INACTIVE) {
        CallbackExecute(tokenId, permissionName, record.status);
    }
    return Constant::SUCCESS;
}

int32_t PermissionRecordManager::StopUsingPermission(AccessTokenID tokenId, const std::string& permissionName)
{
    ExecuteDeletePermissionRecordTask();

    if (AccessTokenKit::GetTokenTypeFlag(tokenId) != TOKEN_HAP) {
        ACCESSTOKEN_LOG_ERROR(LABEL, "invalid tokenId(%{public}d)", tokenId);
        return Constant::FAILURE;
    }

    int32_t opCode;
    if (!Constant::TransferPermissionToOpcode(permissionName, opCode)) {
        ACCESSTOKEN_LOG_ERROR(LABEL, "invalid permission(%{public}s)", permissionName.c_str());
        return Constant::FAILURE;
    }

    PermissionRecord record;
    if (!GetRecordFromStartList(tokenId, opCode, record)) {
        return Constant::FAILURE;
    }

    if (record.status != PERM_INACTIVE) {
        ACCESSTOKEN_LOG_INFO(LABEL, "AddRecord(tokenId: %{public}d, opCode: %{public}d, status: %{public}d)",
            record.tokenId, record.opCode, record.status);
        AddRecord(record);
        CallbackExecute(tokenId, permissionName, PERM_INACTIVE);
    }
    return Constant::SUCCESS;
}

int32_t PermissionRecordManager::RegisterPermActiveStatusCallback(
    std::vector<std::string>& permList, const sptr<IRemoteObject>& callback)
{
    return ActiveStatusCallbackManager::GetInstance().AddCallback(permList, callback);
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
