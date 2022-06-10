/*
 * Copyright (c) 2021-2022 Huawei Device Co., Ltd.
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

PermissionRecordManager::PermissionRecordManager()
{
}

PermissionRecordManager::~PermissionRecordManager()
{
}

bool PermissionRecordManager::AddVisitor(AccessTokenID tokenID, int32_t& visitorId)
{
    ACCESSTOKEN_LOG_DEBUG(LABEL, "%{public}s called", __func__);
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
        ACCESSTOKEN_LOG_ERROR(LABEL, "%{public}s GetHapTokenInfo fail", __func__);
        return false;
    }
    visitor.isRemoteDevice = true;
    visitor.userId = tokenInfo.userID;
    visitor.bundleName = tokenInfo.bundleName;
    if (IsLocalDevice(tokenInfo.deviceID)) {
        visitor.deviceId = Constant::GetLocalDeviceUdid();
        visitor.isRemoteDevice = false;
        visitor.tokenId = tokenID;
    }
    return true;
}

bool PermissionRecordManager::AddRecord(
    int32_t visitorId, const std::string& permissionName, int32_t successCount, int32_t failCount)
{
    ACCESSTOKEN_LOG_DEBUG(LABEL, "%{public}s called", __func__);
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
    for (auto rec : findValues) {
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
        ACCESSTOKEN_LOG_ERROR(LABEL, "%{public}s TransferPermissionToOpcode fail", __func__);
        return false;
    }
    if (successCount == 0 && failCount == 0) {
        ACCESSTOKEN_LOG_ERROR(LABEL, "%{public}s successCount and failCount are both zero", __func__);
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
    ACCESSTOKEN_LOG_DEBUG(LABEL, "%{public}s called, tokenId: %{public}x, permissionName: %{public}s", __func__,
        tokenID, permissionName.c_str());
    auto deleteRecordsTask = [this]() {
        ACCESSTOKEN_LOG_DEBUG(LABEL, "DeletePermissionRecord task called");
        DeletePermissionRecord(Constant::RECORD_DELETE_TIME);
    };
    std::thread deleteRecordsThread(deleteRecordsTask);
    deleteRecordsThread.detach();

    if (AccessTokenKit::GetTokenTypeFlag(tokenID) != TOKEN_HAP) {
        ACCESSTOKEN_LOG_DEBUG(LABEL, "%{public}s Invalid token type", __func__);
        return Constant::SUCCESS;
    }

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
    ACCESSTOKEN_LOG_DEBUG(LABEL, "%{public}s called, tokenId: %{public}x", __func__, tokenID);
    auto deleteRecordsTask = [this]() {
        ACCESSTOKEN_LOG_DEBUG(LABEL, "DeletePermissionRecord task called");
        DeletePermissionRecord(Constant::RECORD_DELETE_TIME);
    };
    std::thread deleteRecordsThread(deleteRecordsTask);
    deleteRecordsThread.detach();

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

    for (auto visitor : findVisitorValues) {
        GenericValues record;
        record.Put(FIELD_VISITOR_ID, visitor.GetInt(FIELD_ID));
        PermissionRecordRepository::GetInstance().RemoveRecordValues(record);
    }
    PermissionVisitorRepository::GetInstance().RemoveVisitorValues(visitorValues);
}

int32_t PermissionRecordManager::GetPermissionUsedRecords(
    const PermissionUsedRequest& request, PermissionUsedResult& result)
{
    ACCESSTOKEN_LOG_DEBUG(LABEL, "%{public}s called", __func__);
    auto deleteRecordsTask = [this]() {
        ACCESSTOKEN_LOG_DEBUG(LABEL, "DeletePermissionRecord task called");
        DeletePermissionRecord(Constant::RECORD_DELETE_TIME);
    };
    std::thread deleteRecordsThread(deleteRecordsTask);
    deleteRecordsThread.detach();

    if (!GetRecordsFromDB(request, result)) {
        ACCESSTOKEN_LOG_ERROR(LABEL, "Failed to GetRecordsFromDB");
        return  Constant::FAILURE;
    }
    return Constant::SUCCESS;
}

int32_t PermissionRecordManager::GetPermissionUsedRecordsAsync(
    const PermissionUsedRequest& request, const sptr<OnPermissionUsedRecordCallback>& callback)
{
    ACCESSTOKEN_LOG_DEBUG(LABEL, "%{public}s called", __func__);
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
        ACCESSTOKEN_LOG_ERROR(LABEL, "%{public}s: query time is invalid", __func__);
        return false;
    }
    
    GenericValues nullValues;
    std::vector<GenericValues> findVisitorValues;
    if (!PermissionVisitorRepository::GetInstance().FindVisitorValues(visitorValues, nullValues, findVisitorValues)) {
        return false;
    }
    if (findVisitorValues.empty()) {
        ACCESSTOKEN_LOG_INFO(LABEL, "%{public}s: no visitor", __func__);
        return true;
    }

    for (auto visitor : findVisitorValues) {
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

        if (findRecordsValues.size() != 0) {
            if (!GetRecords(request.flag, findRecordsValues, bundleRecord, result)) {
                return false;
            }
        }

        if (bundleRecord.permissionRecords.size() != 0) {
            result.bundleRecords.emplace_back(bundleRecord);
        }
    }
    return true;
}

bool PermissionRecordManager::GetRecords(
    int32_t flag, std::vector<GenericValues> recordValues, BundleUsedRecord& bundleRecord, PermissionUsedResult& result)
{
    std::vector<PermissionUsedRecord> permissionRecords;
    for (auto record : recordValues) {
        PermissionUsedRecord tmpPermissionRecord;
        int64_t timestamp = record.GetInt64(FIELD_TIMESTAMP);
        result.beginTimeMillis = ((result.beginTimeMillis == 0) || (timestamp < result.beginTimeMillis)) ?
            timestamp : result.beginTimeMillis;
        result.endTimeMillis = (timestamp > result.endTimeMillis) ? timestamp : result.endTimeMillis;

        record.Put(FIELD_FLAG, flag);
        if (DataTranslator::TranslationGenericValuesIntoPermissionUsedRecord(record, tmpPermissionRecord)
            != Constant::SUCCESS) {
            ACCESSTOKEN_LOG_INFO(LABEL, "%{public}s: failed to transform permission to opcode", __func__);
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

int32_t PermissionRecordManager::DeletePermissionRecord(int32_t days)
{
    GenericValues nullValues;
    std::vector<GenericValues> deleteRecordValues;
    if (!PermissionRecordRepository::GetInstance().FindRecordValues(nullValues, nullValues, deleteRecordValues)) {
        return Constant::FAILURE;
    }

    int32_t recordNum = 0;
    for (auto record : deleteRecordValues) {
        recordNum++;
        if ((TimeUtil::GetCurrentTimestamp() - record.GetInt64(FIELD_TIMESTAMP)) > days ||
            recordNum > Constant::MAX_TOTAL_RECORD) {
            PermissionRecordRepository::GetInstance().RemoveRecordValues(record);
        }
    }
    return Constant::SUCCESS;
}

std::string PermissionRecordManager::DumpRecordInfo(const std::string& bundleName, const std::string& permissionName)
{
    ACCESSTOKEN_LOG_INFO(LABEL, "%{public}s called, bundleName=%{public}s, permissionName=%{public}s",
        __func__, bundleName.c_str(), permissionName.c_str());
    PermissionUsedRequest request;
    request.bundleName = bundleName;
    request.flag = FLAG_PERMISSION_USAGE_DETAIL;
    request.permissionList.emplace_back(permissionName);

    PermissionUsedResult result;
    if (!GetRecordsFromDB(request, result)) {
        ACCESSTOKEN_LOG_ERROR(LABEL, "failed to GetRecordsFromDB");
        return "";
    }

    if (result.bundleRecords.size() == 0) {
        ACCESSTOKEN_LOG_INFO(LABEL, "result.bundleRecords.size() = 0");
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
}
} // namespace AccessToken
} // namespace Security
} // namespace OHOS
