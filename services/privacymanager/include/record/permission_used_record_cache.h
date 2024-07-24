/*
 * Copyright (c) 2022-2023 Huawei Device Co., Ltd.
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

#ifndef PERMISSION_USED_RECORD_CACHE_H
#define PERMISSION_USED_RECORD_CACHE_H

#include <string>
#include <set>
#include <vector>
#ifdef EVENTHANDLER_ENABLE
#include "access_event_handler.h"
#endif
#include "access_token.h"
#include "nocopyable.h"
#include "permission_record.h"
#include "permission_record_node.h"
#include "rwlock.h"
#include "thread_pool.h"
namespace OHOS {
namespace Security {
namespace AccessToken {
class PermissionUsedRecordCache {
public:
    static PermissionUsedRecordCache& GetInstance();
    ~PermissionUsedRecordCache();
    void AddRecordToBuffer(const PermissionRecord& record);
    void MergeRecord(PermissionRecord& record, std::shared_ptr<PermissionUsedRecordNode> curFindMergePos);
    void AddToPersistQueue(const std::shared_ptr<PermissionUsedRecordNode> persistPendingBufferHead);
    void ExecuteReadRecordBufferTask();
    int32_t PersistPendingRecords();
    int32_t RemoveRecords(const AccessTokenID tokenId);
    void RemoveFromPersistQueueAndDatabase(const AccessTokenID tokenId);
    void GetRecords(const std::vector<std::string>& permissionList, const GenericValues& andConditionValues,
        std::vector<GenericValues>& findRecordsValues, int32_t cache1QueryCount);
    void GetFromPersistQueueAndDatabase(const std::set<int32_t>& opCodeList, const GenericValues& andConditionValues,
        std::vector<GenericValues>& findRecordsValues, int32_t cache2QueryCount);
    bool RecordCompare(const AccessTokenID tokenId, const std::set<int32_t>& opCodeList,
        const GenericValues& andConditionValues, const PermissionRecord& record);
    void TransferToOpcode(std::set<int32_t>& opCodeList,
        const std::vector<std::string>& permissionList);
    void ResetRecordBuffer(const int32_t remainCount,
        std::shared_ptr<PermissionUsedRecordNode>& persistPendingBufferEnd);
    void ResetRecordBufferWhenAdd(const int32_t remainCount,
        std::shared_ptr<PermissionUsedRecordNode>& persistPendingBufferEnd);
    void AddRecordNode(const PermissionRecord& record);
    void DeleteRecordNode(std::shared_ptr<PermissionUsedRecordNode> deleteRecordNode);
    void PersistPendingRecordsImmediately();

private:
    PermissionUsedRecordCache();
    DISALLOW_COPY_AND_MOVE(PermissionUsedRecordCache);
    bool RecordMergeCheck(const PermissionRecord& record1, const PermissionRecord& record2);
    void DeepCopyFromHead(const std::shared_ptr<PermissionUsedRecordNode>& oriHeadNode,
        std::shared_ptr<PermissionUsedRecordNode>& copyHeadNode, int32_t copyCount);
    int32_t GetCurBufferTaskNum();
    void AddBufferTaskNum();
    void ReduceBufferTaskNum();
    bool hasInited_;
    OHOS::Utils::RWLock initLock_;
    int32_t readableSize_ = 0;
    std::shared_ptr<PermissionUsedRecordNode> recordBufferHead_ = std::make_shared<PermissionUsedRecordNode>();
    std::shared_ptr<PermissionUsedRecordNode> curRecordBufferPos_ = recordBufferHead_;
    std::vector<std::shared_ptr<PermissionUsedRecordNode>> persistPendingBufferQueue_;
    const static int64_t INTERVAL = 15 * 60 * 1000; // 1s = 1000ms
    const static int32_t MAX_PERSIST_SIZE = 100;
    bool persistIsRunning_ = false;
    // cacheLock1_ is used for locking recordBufferHead_ and curRecordBufferPos_
    OHOS::Utils::RWLock cacheLock1_;
    // cacheLock2_ is used for locking persistPendingBufferQueue_ and persistIsRunning_
    OHOS::Utils::RWLock cacheLock2_;
#ifdef EVENTHANDLER_ENABLE
    std::shared_ptr<AppExecFwk::EventRunner> bufferEventRunner_;
    std::shared_ptr<AccessEventHandler> bufferEventHandler_;
#endif
    std::atomic_int32_t bufferTaskNum_ = 0;
};
} // namespace AccessToken
} // namespace Security
} // namespace OHOS
#endif // PERMISSION_USED_RECORD_CACHE_H
