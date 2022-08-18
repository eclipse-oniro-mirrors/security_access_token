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

#include "permission_used_record_cache.h"
#include "accesstoken_log.h"
#include "constant.h"
#include "field_const.h"
#include "generic_values.h"
#include "permission_record.h"
#include "permission_record_manager.h"
#include "permission_record_node.h"
#include "permission_record_repository.h"
#include "permission_used_record_db.h"
#include "time_util.h"
#include "to_string.h"

namespace OHOS {
namespace Security {
namespace AccessToken {
namespace {
static constexpr OHOS::HiviewDFX::HiLogLabel LABEL = {
    LOG_CORE, SECURITY_DOMAIN_PRIVACY, "PermissionUsedRecordCache"
};
}

PermissionUsedRecordCache& PermissionUsedRecordCache::GetInstance()
{
    static PermissionUsedRecordCache instance;
    return instance;
}

int32_t PermissionUsedRecordCache::AddRecordToBuffer(PermissionRecord& record)
{
    if (nextPersistTimestamp_ == 0) {
        nextPersistTimestamp_ = record.timestamp + INTERVAL;
    }
    std::shared_ptr<PermissionUsedRecordNode> curFindMergePos;
    std::shared_ptr<PermissionUsedRecordNode> persistPendingBufferHead;
    std::shared_ptr<PermissionUsedRecordNode> persistPendingBufferEnd = nullptr;
    {
        Utils::UniqueWriteGuard<Utils::RWLock> lock1(this->cacheLock_);
        curFindMergePos = curRecordBufferPos_;
        persistPendingBufferHead = recordBufferHead_;
        int32_t remainCount = 0;
        while (curFindMergePos != recordBufferHead_) {
            auto pre = curFindMergePos->pre.lock();
            if ((record.timestamp - curFindMergePos->record.timestamp) >= INTERVAL) {
                persistPendingBufferEnd = curFindMergePos;
                break;
            } else if (curFindMergePos->record.tokenId == record.tokenId &&
                record.opCode == curFindMergePos->record.opCode &&
                (record.timestamp - curFindMergePos->record.timestamp) <= Constant::PRECISE) {
                MergeRecord(record, curFindMergePos);
            } else {
                remainCount++;
            }
            curFindMergePos = pre;
        }
        AddRecordNode(record); // refresh curRecordBUfferPos and readableSize
        remainCount++;
        if (persistPendingBufferEnd != nullptr) {
            readableSize_ = remainCount;
            std::shared_ptr<PermissionUsedRecordNode> tmpRecordBufferHead =
                std::make_shared<PermissionUsedRecordNode>();
            tmpRecordBufferHead->next = persistPendingBufferEnd->next;
            persistPendingBufferEnd->next.reset();
            recordBufferHead_ = tmpRecordBufferHead;
            if (persistPendingBufferEnd == curRecordBufferPos_) { // persistPendingBufferEnd == curRecordBufferPos
                curRecordBufferPos_ = recordBufferHead_;
            } else { // remainCount !=0 ==> recordBufferHead->next != nullptr
                recordBufferHead_->next->pre = recordBufferHead_;
            }
        }
    }
    if (persistPendingBufferEnd != nullptr) {
        AddToPersistQueue(persistPendingBufferHead);
    }
    return Constant::SUCCESS;
}

void PermissionUsedRecordCache::MergeRecord(PermissionRecord& record,
    std::shared_ptr<PermissionUsedRecordNode> curFindMergePos)
{
    record.accessDuration += curFindMergePos->record.accessDuration;
    record.accessCount += curFindMergePos->record.accessCount;
    record.rejectCount += curFindMergePos->record.rejectCount;
    if (curRecordBufferPos_ == curFindMergePos) {
        curRecordBufferPos_ = curRecordBufferPos_->pre.lock();
    }
    DeleteRecordNode(curFindMergePos); // delete old same node
    readableSize_--;
}

void PermissionUsedRecordCache::AddToPersistQueue(
    const std::shared_ptr<PermissionUsedRecordNode> persistPendingBufferHead)
{
    bool startPersist = false;
    {
        Utils::UniqueWriteGuard<Utils::RWLock> lock2(this->cacheLock_);
        persistPendingBufferQueue_.emplace_back(persistPendingBufferHead);
        if ((TimeUtil::GetCurrentTimestamp() >= nextPersistTimestamp_ ||
            readableSize_ >= MAX_PERSIST_SIZE) && persistIsRunning_ == 0) {
            startPersist = true;
        }
    }
    if (startPersist) {
        ExecuteReadRecordBufferTask();
    }
}

void PermissionUsedRecordCache::ExecuteReadRecordBufferTask()
{
    if (readRecordBufferTaskWorker_.GetCurTaskNum() > 1) {
        ACCESSTOKEN_LOG_INFO(LABEL, "Already has read record buffer task!");
        return;
    }
    auto readRecordBufferTask = [this]() {
        ACCESSTOKEN_LOG_INFO(LABEL, "ReadRecordBuffer task called");
        PersistPendingRecords();
    };
    readRecordBufferTaskWorker_.AddTask(readRecordBufferTask);
}

int32_t PermissionUsedRecordCache::PersistPendingRecords()
{
    std::shared_ptr<PermissionUsedRecordNode> persistPendingBufferHead;
    bool isEmpty;
    std::vector<GenericValues> insertValues;
    {
        Utils::UniqueReadGuard<Utils::RWLock> lock2(this->cacheLock_);
        isEmpty = persistPendingBufferQueue_.empty();
        persistIsRunning_ = 1;
        nextPersistTimestamp_ = 0;
    }
    while (!isEmpty) {
        {
            Utils::UniqueWriteGuard<Utils::RWLock> lock2(this->cacheLock_);
            persistPendingBufferHead = persistPendingBufferQueue_[0];
            persistPendingBufferQueue_.erase(persistPendingBufferQueue_.begin());
        }
        std::shared_ptr<PermissionUsedRecordNode> curPendingRecordNode =
            persistPendingBufferHead->next;
        while (curPendingRecordNode != nullptr) {
            auto next = curPendingRecordNode->next;
            GenericValues tmpRecordValues;
            PermissionRecord tmpRecord = curPendingRecordNode->record;
            PermissionRecord::TranslationIntoGenericValues(tmpRecord, tmpRecordValues);
            insertValues.emplace_back(tmpRecordValues);
            DeleteRecordNode(curPendingRecordNode);
            curPendingRecordNode = next;
        }
        if (!insertValues.empty() && !PermissionRecordRepository::GetInstance().AddRecordValues(insertValues)) {
            ACCESSTOKEN_LOG_ERROR(LABEL, "Failed to persist pending records");
        }
        ACCESSTOKEN_LOG_DEBUG(LABEL, "Persist pending records successful");
        {
            Utils::UniqueReadGuard<Utils::RWLock> lock2(this->cacheLock_);
            isEmpty = persistPendingBufferQueue_.empty();
        }
    }
    {
        Utils::UniqueReadGuard<Utils::RWLock> lock2(this->cacheLock_);
        if (isEmpty) { // free persistPendingBufferQueue
            std::vector<std::shared_ptr<PermissionUsedRecordNode>> tmpPersistPendingBufferQueue;
            std::swap(tmpPersistPendingBufferQueue, persistPendingBufferQueue_);
        }
        persistIsRunning_ = 0;
    }
    return true;
}

int32_t PermissionUsedRecordCache::RemoveRecords(const GenericValues &record)
{
    AccessTokenID tokenID = record.GetInt(FIELD_TOKEN_ID);
    std::shared_ptr<PermissionUsedRecordNode> curFindDeletePos;
    std::shared_ptr<PermissionUsedRecordNode> persistPendingBufferHead;
    std::shared_ptr<PermissionUsedRecordNode> persistPendingBufferEnd = nullptr;
    int32_t countPersistPendingNode = 0;
    {
        Utils::UniqueWriteGuard<Utils::RWLock> lock1(this->cacheLock_);
        curFindDeletePos = recordBufferHead_->next;
        persistPendingBufferHead = recordBufferHead_;
        while (curFindDeletePos != nullptr) {
            auto next = curFindDeletePos->next;
            if (curFindDeletePos->record.tokenId == tokenID) {
                if (curRecordBufferPos_ == curFindDeletePos) {
                    curRecordBufferPos_ = curFindDeletePos->pre.lock();
                }
                DeleteRecordNode(curFindDeletePos);
                readableSize_--;
            } else if (TimeUtil::GetCurrentTimestamp() -
                curFindDeletePos->record.timestamp >= INTERVAL) {
                persistPendingBufferEnd = curFindDeletePos;
                countPersistPendingNode++;
            }
            curFindDeletePos = next;
        }
        if (countPersistPendingNode != 0) { // refresh recordBufferHead
            readableSize_ -= countPersistPendingNode;
            std::shared_ptr<PermissionUsedRecordNode> tmpRecordBufferHead =
                std::make_shared<PermissionUsedRecordNode>();
            tmpRecordBufferHead->next = persistPendingBufferEnd->next;
            persistPendingBufferEnd->next.reset();
            recordBufferHead_ = tmpRecordBufferHead;
            recordBufferHead_->pre.reset();
            if (persistPendingBufferEnd == curRecordBufferPos_) {
                curRecordBufferPos_ = recordBufferHead_;
            } else { // remainCount !=0 ==> recordBufferHead->next != nullptr
                recordBufferHead_->next->pre = recordBufferHead_;
            }
        }
    }
    RemoveRecordsFromPersistPendingBufferQueue(record, persistPendingBufferHead, persistPendingBufferEnd);
    return Constant::SUCCESS;
}

void PermissionUsedRecordCache::RemoveRecordsFromPersistPendingBufferQueue(const GenericValues &record,
    std::shared_ptr<PermissionUsedRecordNode> persistPendingBufferHead,
    std::shared_ptr<PermissionUsedRecordNode> persistPendingBufferEnd)
{
    AccessTokenID tokenID = record.GetInt(FIELD_TOKEN_ID);
    {
        std::shared_ptr<PermissionUsedRecordNode> curFindDeletePos;
        Utils::UniqueWriteGuard<Utils::RWLock> lock2(this->cacheLock_);
        if (!persistPendingBufferQueue_.empty()) {
            for (auto persistHead : persistPendingBufferQueue_) {
                curFindDeletePos = persistHead->next;
                while (curFindDeletePos != nullptr) {
                    auto next = curFindDeletePos->next;
                    if (curFindDeletePos->record.tokenId == tokenID) {
                        DeleteRecordNode(curFindDeletePos);
                    }
                    curFindDeletePos = next;
                }
            }
        }
        PermissionRecordRepository::GetInstance().RemoveRecordValues(record); // remove from database
    }
    if (persistPendingBufferEnd != nullptr) { // add to queue
        AddToPersistQueue(persistPendingBufferHead);
    }
}

void PermissionUsedRecordCache::GetRecords(const std::vector<std::string>& permissionList,
    const GenericValues &andConditionValues, const GenericValues& orConditionValues,
    std::vector<GenericValues>& findRecordsValues)
{
    std::set<int32_t> opCodeList;
    std::shared_ptr<PermissionUsedRecordNode> curFindPos;
    std::shared_ptr<PermissionUsedRecordNode> persistPendingBufferHead;
    std::shared_ptr<PermissionUsedRecordNode> persistPendingBufferEnd = nullptr;
    int32_t countPersistPendingNode = 0;
    AccessTokenID tokenID = andConditionValues.GetInt(FIELD_TOKEN_ID);
    TransferToOpcode(opCodeList, permissionList);
    {
        Utils::UniqueWriteGuard<Utils::RWLock> lock1(this->cacheLock_);
        curFindPos = recordBufferHead_->next;
        persistPendingBufferHead = recordBufferHead_;
        while (curFindPos != nullptr) {
            auto next = curFindPos->next;
            if (RecordCompare(tokenID, opCodeList, andConditionValues, curFindPos->record)) {
                GenericValues recordValues;
                PermissionRecord::TranslationIntoGenericValues(curFindPos->record, recordValues);
                findRecordsValues.emplace_back(recordValues);
            }
            if (TimeUtil::GetCurrentTimestamp() - curFindPos->record.timestamp >= INTERVAL) {
                persistPendingBufferEnd = curFindPos;
                countPersistPendingNode++;
            }
            curFindPos = next;
        }
        if (countPersistPendingNode != 0) { // refresh recordBufferHead
            readableSize_ -= countPersistPendingNode;
            std::shared_ptr<PermissionUsedRecordNode> tmpRecordBufferHead =
                std::make_shared<PermissionUsedRecordNode>();
            tmpRecordBufferHead->next = persistPendingBufferEnd->next;
            persistPendingBufferEnd->next.reset();
            recordBufferHead_ = tmpRecordBufferHead;
            if (persistPendingBufferEnd == curRecordBufferPos_) {
                curRecordBufferPos_ = recordBufferHead_;
            } else { // remainCount !=0 ==> recordBufferHead->next != nullptr
                recordBufferHead_->next->pre = recordBufferHead_;
            }
        }
    }
    GetRecordsFromPersistPendingBufferQueue(permissionList, andConditionValues,
        orConditionValues, findRecordsValues, opCodeList);
    if (countPersistPendingNode != 0) {
        AddToPersistQueue(persistPendingBufferHead);
    }
}

void PermissionUsedRecordCache::GetRecordsFromPersistPendingBufferQueue(
    const std::vector<std::string>& permissionList, const GenericValues& andConditionValues,
    const GenericValues& orConditionValues, std::vector<GenericValues>& findRecordsValues,
    const std::set<int32_t>& opCodeList)
{
    AccessTokenID tokenID = andConditionValues.GetInt(FIELD_TOKEN_ID);
    std::shared_ptr<PermissionUsedRecordNode> curFindPos;
    Utils::UniqueWriteGuard<Utils::RWLock> lock2(this->cacheLock_);
    if (!persistPendingBufferQueue_.empty()) {
        for (auto persistHead : persistPendingBufferQueue_) {
            curFindPos = persistHead->next;
            while (curFindPos != nullptr) {
                auto next = curFindPos->next;
                if (RecordCompare(tokenID, opCodeList, andConditionValues, curFindPos->record)) {
                    GenericValues recordValues;
                    PermissionRecord::TranslationIntoGenericValues(curFindPos->record, recordValues);
                    findRecordsValues.emplace_back(recordValues);
                }
                curFindPos = next;
            }
        }
    }
    if (tokenID != INVALID_TOKENID && !PermissionRecordRepository::GetInstance().FindRecordValues(
        andConditionValues, orConditionValues, findRecordsValues)) { // find records from database
        ACCESSTOKEN_LOG_ERROR(LABEL, "find records from database failed");
    }
}

void PermissionUsedRecordCache::TransferToOpcode(std::set<int32_t>& opCodeList,
    const std::vector<std::string>& permissionList)
{
    for (const auto& permission : permissionList) {
        int32_t opCode = Constant::OP_INVALID;
        Constant::TransferPermissionToOpcode(permission, opCode);
        opCodeList.insert(opCode);
    }
}

bool PermissionUsedRecordCache::RecordCompare(const AccessTokenID tokenID, const std::set<int32_t>& opCodeList,
    const GenericValues &andConditionValues, const PermissionRecord &record)
{
    // compare tokenId
    if (record.tokenId != (int32_t)tokenID) {
        return false;
    }
    // compare opCode
    if (!opCodeList.empty() && opCodeList.find(record.opCode) == opCodeList.end()) {
        return false;
    }
    // compare timestamp
    std::vector<std::string> andColumns = andConditionValues.GetAllKeys();
    if (!andColumns.empty()) {
        for (auto andColumn : andColumns) {
            if (andColumn == FIELD_TIMESTAMP_BEGIN &&
                record.timestamp < andConditionValues.GetInt64(andColumn)) {
                return false;
            } else if (andColumn == FIELD_TIMESTAMP_END &&
                record.timestamp > andConditionValues.GetInt64(andColumn)) {
                return false;
            } else if (andColumn == FIELD_TIMESTAMP &&
                record.timestamp != andConditionValues.GetInt64(andColumn)) {
                return false;
            }
        }
    }
    return true;
}

void PermissionUsedRecordCache::FindTokenIdList(std::set<AccessTokenID>& tokenIdList)
{
    std::shared_ptr<PermissionUsedRecordNode> curFindPos;
    {
        // find tokenIdList from recordBuffer
        Utils::UniqueWriteGuard<Utils::RWLock> lock1(this->cacheLock_);
        curFindPos = recordBufferHead_->next;
        while (curFindPos != nullptr) {
            auto next = curFindPos->next;
            tokenIdList.emplace((AccessTokenID)curFindPos->record.tokenId);
            curFindPos = next;
        }
    }
    {
        // find tokenIdList from BufferQueue
        Utils::UniqueWriteGuard<Utils::RWLock> lock2(this->cacheLock_);
        if (!persistPendingBufferQueue_.empty()) {
            for (auto persistHead : persistPendingBufferQueue_) {
                curFindPos = persistHead->next;
                while (curFindPos != nullptr) {
                    auto next = curFindPos->next;
                    tokenIdList.emplace((AccessTokenID)curFindPos->record.tokenId);
                    curFindPos = next;
                }
            }
        }
    }
}

void PermissionUsedRecordCache::AddRecordNode(const PermissionRecord& record)
{
    std::shared_ptr<PermissionUsedRecordNode> tmpRecordNode = std::make_shared<PermissionUsedRecordNode>();
    tmpRecordNode->record = record;
    tmpRecordNode->pre = curRecordBufferPos_;
    curRecordBufferPos_->next = tmpRecordNode;
    curRecordBufferPos_ = curRecordBufferPos_->next;
    readableSize_++;
}

void PermissionUsedRecordCache::DeleteRecordNode(std::shared_ptr<PermissionUsedRecordNode> deleteRecordNode)
{
    std::shared_ptr<PermissionUsedRecordNode> pre = deleteRecordNode->pre.lock();
    if (deleteRecordNode->next == nullptr) { // End of the linked list
        pre->next = nullptr;
    } else {
        std::shared_ptr<PermissionUsedRecordNode> next = deleteRecordNode->next;
        pre->next = next;
        next->pre = pre;
    }
}
} // namespace AccessToken
} // namespace Security
} // namespace OHOS