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

#ifndef PERMISSION_USED_RECORD_CACHE_H
#define PERMISSION_USED_RECORD_CACHE_H

#include <map>
#include <memory>
#include <string>
#include <set>
#include <vector>
#include "accesstoken_kit.h"
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
    void AddRecordToBuffer(PermissionRecord& record);
    void MergeRecord(PermissionRecord& record, std::shared_ptr<PermissionUsedRecordNode> curFindMergePos);
    void AddToPersistQueue(const std::shared_ptr<PermissionUsedRecordNode> persistPendingBufferHead);
    void ExecuteReadRecordBufferTask();
    int32_t PersistPendingRecords();
    void GetPersistPendingRecordsAndReset();
    int32_t RemoveRecords(const AccessTokenID tokenId);
    void RemoveRecordsFromPersistPendingBufferQueue(const AccessTokenID tokenId,
        std::shared_ptr<PermissionUsedRecordNode> persistPendingBufferHead,
        std::shared_ptr<PermissionUsedRecordNode> persistPendingBufferEnd);
    void GetRecords(const std::vector<std::string>& permissionList,
        const GenericValues& andConditionValues, const GenericValues& orConditionValues,
        std::vector<GenericValues>& findRecordsValues);
    void GetRecordsFromPersistPendingBufferQueue(const std::vector<std::string>& permissionList,
        const GenericValues& andConditionValues, const GenericValues& orConditionValues,
        std::vector<GenericValues>& findRecordsValues, const std::set<int32_t>& opCodeList);
    bool RecordCompare(const AccessTokenID tokenId, const std::set<int32_t>& opCodeList,
        const GenericValues& andConditionValues, const PermissionRecord& record);
    void FindTokenIdList(std::set<AccessTokenID>& tokenIdList);
    void TransferToOpcode(std::set<int32_t>& opCodeList,
        const std::vector<std::string>& permissionList);
    void ResetRecordBuffer(const int32_t remainCount,
        std::shared_ptr<PermissionUsedRecordNode>& persistPendingBufferEnd);
    void AddRecordNode(const PermissionRecord& record);
    void DeleteRecordNode(std::shared_ptr<PermissionUsedRecordNode> deleteRecordNode);
	    
private:
    int32_t readableSize_ = 0;
    std::shared_ptr<PermissionUsedRecordNode> recordBufferHead_ = std::make_shared<PermissionUsedRecordNode>();
    std::shared_ptr<PermissionUsedRecordNode> curRecordBufferPos_ = recordBufferHead_;
    std::vector<std::shared_ptr<PermissionUsedRecordNode>> persistPendingBufferQueue_;
    int64_t nextPersistTimestamp_ = 0L;
    const static int32_t INTERVAL = 60 * 15;
    const static int32_t MAX_PERSIST_SIZE = 100;
    int32_t persistIsRunning_ = 0;
    OHOS::Utils::RWLock cacheLock_;
    OHOS::ThreadPool readRecordBufferTaskWorker_;
};
} // namespace AccessToken
} // namespace Security
} // namespace OHOS
#endif // PERMISSION_USED_RECORD_CACHE_H
