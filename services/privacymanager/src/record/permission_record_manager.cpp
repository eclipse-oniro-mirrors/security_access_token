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
#include "constant.h"
#include "constant_common.h"
#include "data_translator.h"
#include "field_const.h"
#include "permission_record_repository.h"
#include "permission_visitor_repository.h"
#include "time_util.h"
#include "to_string.h"

namespace OHOS {
namespace Security {
namespace AccessToken {
namespace {
static constexpr OHOS::HiviewDFX::HiLogLabel LABEL = {
    LOG_CORE, SECURITY_DOMAIN_PRIVACY, "PermissionRecordManager"
};
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

bool PermissionRecordManager::AddVisitor(AccessTokenID tokenID, int32_t& visitorId)
{
    ACCESSTOKEN_LOG_DEBUG(LABEL, "Entry");
    PermissionVisitor visitor;
    if (!GetPermissionVisitor(tokenID, visitor)) {
        return false;
    }

    GenericValues visitorValues;
    GenericValues nullValues;
    std::vector<GenericValues> resultValues;
    PermissionVisitor::TranslationIntoGenericValues(visitor, visitorValues);
    if (!PermissionVisitorRepository::GetInstance().FindVisitorValues(visitorValues, nullValues, resultValues)) {
        return false;
    }
    if (resultValues.empty()) {
        if (!PermissionVisitorRepository::GetInstance().AddVisitorValues(visitorValues)) {
            return false;
        }
        if (!PermissionVisitorRepository::GetInstance().FindVisitorValues(visitorValues, nullValues, resultValues)) {
            return false;
        }
    }
    PermissionVisitor::TranslationIntoPermissionVisitor(resultValues[0], visitor);
    visitorId = visitor.id;
    return true;
}

bool PermissionRecordManager::GetPermissionVisitor(AccessTokenID tokenID, PermissionVisitor& visitor)
{
    HapTokenInfo tokenInfo;
    if (AccessTokenKit::GetHapTokenInfo(tokenID, tokenInfo) != Constant::SUCCESS) {
        ACCESSTOKEN_LOG_ERROR(LABEL, "GetHapTokenInfo fail");
        return false;
    }
    visitor.isRemoteDevice = true;
    visitor.userId = tokenInfo.userID;
    visitor.bundleName = tokenInfo.bundleName;
    if (IsLocalDevice(tokenInfo.deviceID)) {
        visitor.deviceId = ConstantCommon::GetLocalDeviceId();
        visitor.isRemoteDevice = false;
        visitor.tokenId = tokenID;
    }
    return true;
}

bool PermissionRecordManager::AddRecord(
    int32_t visitorId, const std::string& permissionName, int32_t successCount, int32_t failCount)
{
    ACCESSTOKEN_LOG_DEBUG(LABEL, "Entry");
    PermissionRecord record;
    if (!GetPermissionsRecord(visitorId, permissionName, successCount, failCount, record)) {
        return false;
    }

    GenericValues nullValues;
    GenericValues recordValues;
    std::vector<GenericValues> insertValues;
    std::vector<GenericValues> findValues;
    PermissionRecord::TranslationIntoGenericValues(record, recordValues);

    int64_t insertTimestamp = record.timestamp;
    int64_t insertAccessDuration = record.accessDuration;
    int32_t insertAccessCount = record.accessCount;
    int32_t insertRejectCount = record.rejectCount;
    recordValues.Remove(FIELD_TIMESTAMP);
    recordValues.Remove(FIELD_ACCESS_DURATION);
    recordValues.Remove(FIELD_ACCESS_COUNT);
    recordValues.Remove(FIELD_REJECT_COUNT);
    if (!PermissionRecordRepository::GetInstance().FindRecordValues(recordValues, nullValues, findValues)) {
        return false;
    }

    recordValues.Put(FIELD_TIMESTAMP, insertTimestamp);
    recordValues.Put(FIELD_ACCESS_DURATION, insertAccessDuration);
    recordValues.Put(FIELD_ACCESS_COUNT, insertAccessCount);
    recordValues.Put(FIELD_REJECT_COUNT, insertRejectCount);
    for (const auto& rec : findValues) {
        if (insertTimestamp - rec.GetInt64(FIELD_TIMESTAMP) < Constant::PRECISE) {
            insertAccessDuration += rec.GetInt64(FIELD_ACCESS_DURATION);
            insertAccessCount += rec.GetInt(FIELD_ACCESS_COUNT);
            insertRejectCount += rec.GetInt(FIELD_REJECT_COUNT);
            recordValues.Remove(FIELD_ACCESS_DURATION);
            recordValues.Remove(FIELD_ACCESS_COUNT);
            recordValues.Remove(FIELD_REJECT_COUNT);

            recordValues.Put(FIELD_ACCESS_DURATION, insertAccessDuration);
            recordValues.Put(FIELD_ACCESS_COUNT, insertAccessCount);
            recordValues.Put(FIELD_REJECT_COUNT, insertRejectCount);

            if (!PermissionRecordRepository::GetInstance().RemoveRecordValues(rec)) {
                return false;
            }
            break;
        }
    }
    insertValues.emplace_back(recordValues);
    return PermissionRecordRepository::GetInstance().AddRecordValues(insertValues);
}

bool PermissionRecordManager::GetPermissionsRecord(int32_t visitorId, const std::string& permissionName,
    int32_t successCount, int32_t failCount, PermissionRecord& record)
{
    int32_t opCode;
    if (!Constant::TransferPermissionToOpcode(permissionName, opCode)) {
        ACCESSTOKEN_LOG_ERROR(LABEL, "Failed to TransferPermissionToOpcode");
        return false;
    }
    if (successCount == 0 && failCount == 0) {
        ACCESSTOKEN_LOG_ERROR(LABEL, "successCount and failCount are both zero");
        return false;
    }
    record.visitorId = visitorId;
    record.accessCount = successCount;
    record.rejectCount = failCount;
    record.opCode = opCode;
    record.status = 0; // get isForeground by uid  lockscreen
    record.timestamp = TimeUtil::GetCurrentTimestamp();
    record.accessDuration = 0;
    return true;
}

int32_t PermissionRecordManager::AddPermissionUsedRecord(AccessTokenID tokenID, const std::string& permissionName,
    int32_t successCount, int32_t failCount)
{
    ACCESSTOKEN_LOG_DEBUG(LABEL, "Entry, tokenId: %{public}x, permissionName: %{public}s",
        tokenID, permissionName.c_str());
    ExecuteDeletePermissionRecordTask();

    if (AccessTokenKit::GetTokenTypeFlag(tokenID) != TOKEN_HAP) {
        ACCESSTOKEN_LOG_DEBUG(LABEL, "Invalid token type");
        return Constant::SUCCESS;
    }

    Utils::UniqueWriteGuard<Utils::RWLock> lk(this->rwLock_);
    int32_t visitorId;
    if (!AddVisitor(tokenID, visitorId)) {
        return Constant::FAILURE;
    }
    if (!AddRecord(visitorId, permissionName, successCount, failCount)) {
        return Constant::FAILURE;
    }
    return Constant::SUCCESS;
}

void PermissionRecordManager::RemovePermissionUsedRecords(AccessTokenID tokenID, const std::string& deviceID)
{
    ACCESSTOKEN_LOG_DEBUG(LABEL, "Entry, tokenId: %{public}x", tokenID);

    Utils::UniqueWriteGuard<Utils::RWLock> lk(this->rwLock_);
    PermissionVisitor visitor;
    if (!GetPermissionVisitor(tokenID, visitor) && deviceID.empty()) {
        return;
    }
    if (!deviceID.empty()) {
        visitor.deviceId = deviceID;
    }

    GenericValues nullValues;
    GenericValues visitorValues;
    std::vector<GenericValues> findVisitorValues;
    PermissionVisitor::TranslationIntoGenericValues(visitor, visitorValues);
    if (!PermissionVisitorRepository::GetInstance().FindVisitorValues(visitorValues, nullValues, findVisitorValues)) {
        return;
    }

    for (const auto& visitor : findVisitorValues) {
        GenericValues record;
        record.Put(FIELD_VISITOR_ID, visitor.GetInt(FIELD_ID));
        PermissionRecordRepository::GetInstance().RemoveRecordValues(record);
    }
    PermissionVisitorRepository::GetInstance().RemoveVisitorValues(visitorValues);
}

int32_t PermissionRecordManager::GetPermissionUsedRecords(
    const PermissionUsedRequest& request, PermissionUsedResult& result)
{
    ACCESSTOKEN_LOG_DEBUG(LABEL, "Entry");
    ExecuteDeletePermissionRecordTask();

    if (!GetRecordsFromDB(request, result)) {
        ACCESSTOKEN_LOG_ERROR(LABEL, "Failed to GetRecordsFromDB");
        return  Constant::FAILURE;
    }
    return Constant::SUCCESS;
}

int32_t PermissionRecordManager::GetPermissionUsedRecordsAsync(
    const PermissionUsedRequest& request, const sptr<OnPermissionUsedRecordCallback>& callback)
{
    ACCESSTOKEN_LOG_DEBUG(LABEL, "Entry");
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

bool PermissionRecordManager::GetRecordsFromDB(const PermissionUsedRequest& request, PermissionUsedResult& result)
{
    GenericValues visitorValues;
    GenericValues andConditionValues;
    GenericValues orConditionValues;
    if (DataTranslator::TranslationIntoGenericValues(request, visitorValues, andConditionValues,
        orConditionValues) != Constant::SUCCESS) {
        ACCESSTOKEN_LOG_ERROR(LABEL, "query time is invalid");
        return false;
    }
    
    GenericValues nullValues;
    std::vector<GenericValues> findVisitorValues;
    if (!PermissionVisitorRepository::GetInstance().FindVisitorValues(visitorValues, nullValues, findVisitorValues)) {
        return false;
    }
    if (findVisitorValues.empty()) {
        ACCESSTOKEN_LOG_INFO(LABEL, "no visitor");
        return true;
    }

    for (const auto& visitor : findVisitorValues) {
        andConditionValues.Put(FIELD_VISITOR_ID, visitor.GetInt(FIELD_ID));
        std::vector<GenericValues> findRecordsValues;
        BundleUsedRecord bundleRecord;
        if (!PermissionRecordRepository::GetInstance().FindRecordValues(
            andConditionValues, orConditionValues, findRecordsValues)) {
            return false;
        }
        andConditionValues.Remove(FIELD_VISITOR_ID);
        bundleRecord.tokenId = (AccessTokenID)visitor.GetInt(FIELD_TOKEN_ID);
        bundleRecord.isRemote = visitor.GetInt(FIELD_IS_REMOTE_DEVICE);
        bundleRecord.deviceId = visitor.GetString(FIELD_DEVICE_ID);
        bundleRecord.bundleName = visitor.GetString(FIELD_BUNDLE_NAME);

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
            ACCESSTOKEN_LOG_INFO(LABEL, "Failed to transform permission to opcode");
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
    GenericValues nullValues;
    std::vector<GenericValues> deleteRecordValues;
    if (!PermissionRecordRepository::GetInstance().FindRecordValues(nullValues, nullValues, deleteRecordValues)) {
        return Constant::FAILURE;
    }

    size_t deleteSize = 0;
    if (deleteRecordValues.size() > Constant::MAX_TOTAL_RECORD) {
        deleteSize = deleteRecordValues.size() - Constant::MAX_TOTAL_RECORD;
        for (size_t i = 0; i < deleteSize; ++i) {
            PermissionRecordRepository::GetInstance().RemoveRecordValues(deleteRecordValues[i]);
        }
    }
    int64_t deleteTimestamp = TimeUtil::GetCurrentTimestamp() - days;
    for (size_t i = deleteSize; i < deleteRecordValues.size(); ++i) {
        if (deleteRecordValues[i].GetInt64(FIELD_TIMESTAMP) < deleteTimestamp) {
            PermissionRecordRepository::GetInstance().RemoveRecordValues(deleteRecordValues[i]);
        }
    }
    return Constant::SUCCESS;
}

std::string PermissionRecordManager::DumpRecordInfo(const std::string& bundleName, const std::string& permissionName)
{
    ACCESSTOKEN_LOG_DEBUG(LABEL, "Entry, bundleName=%{public}s, permissionName=%{public}s",
        bundleName.c_str(), permissionName.c_str());
    PermissionUsedRequest request;
    request.bundleName = bundleName;
    request.flag = FLAG_PERMISSION_USAGE_DETAIL;
    if (!permissionName.empty()) {
        request.permissionList.emplace_back(permissionName);
    }

    PermissionUsedResult result;
    if (!GetRecordsFromDB(request, result)) {
        ACCESSTOKEN_LOG_ERROR(LABEL, "failed to GetRecordsFromDB");
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

bool PermissionRecordManager::IsLocalDevice(const std::string& deviceId)
{
    if (deviceId == "0") { // local
        return true;
    }
    return false;
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
