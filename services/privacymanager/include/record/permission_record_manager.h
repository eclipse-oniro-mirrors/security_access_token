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

#ifndef PERMISSION_RECORD_MANAGER_H
#define PERMISSION_RECORD_MANAGER_H

#include <vector>
#include <string>

#include "access_token.h"
#include "nocopyable.h"
#include "on_permission_used_record_callback.h"
#include "permission_record.h"
#include "permission_used_request.h"
#include "permission_used_result.h"
#include "permission_visitor.h"

#include "rwlock.h"
#include "thread_pool.h"

namespace OHOS {
namespace Security {
namespace AccessToken {
class PermissionRecordManager final {
public:
    static PermissionRecordManager& GetInstance();
    virtual ~PermissionRecordManager();

    void Init();
    int32_t AddPermissionUsedRecord(
        AccessTokenID tokenID, const std::string& permissionName, int32_t successCount, int32_t failCount);
    void RemovePermissionUsedRecords(AccessTokenID tokenID, const std::string& deviceID);
    int32_t GetPermissionUsedRecords(const PermissionUsedRequest& request, PermissionUsedResult& result);
    int32_t GetPermissionUsedRecordsAsync(
        const PermissionUsedRequest& request, const sptr<OnPermissionUsedRecordCallback>& callback);
    std::string DumpRecordInfo(const std::string& bundleName, const std::string& permissionName);
    int32_t StartUsingPermission(AccessTokenID tokenID, const std::string& permissionName);
    int32_t StopUsingPermission(AccessTokenID tokenID, const std::string& permissionName);
    int32_t RegisterPermActiveStatusCallback(
        std::vector<std::string>& permList, const sptr<IRemoteObject>& callback);
    int32_t UnRegisterPermActiveStatusCallback(const sptr<IRemoteObject>& callback);
    bool GetPermissionVisitor(AccessTokenID tokenID, PermissionVisitor& visitor);

private:
    PermissionRecordManager();
    DISALLOW_COPY_AND_MOVE(PermissionRecordManager);

    bool AddVisitor(AccessTokenID tokenID, int32_t& visitorId);
    bool AddRecord(int32_t visitorId, const std::string& permissionName, int32_t successCount, int32_t failCount);
    bool GetPermissionsRecord(int32_t visitorId, const std::string& permissionName,
        int32_t successCount, int32_t failCount, PermissionRecord& record);

    void ExecuteDeletePermissionRecordTask();
    int32_t DeletePermissionRecord(int32_t days);
    bool GetRecordsFromDB(const PermissionUsedRequest& request, PermissionUsedResult& result);
    bool GetRecords(int32_t flag, std::vector<GenericValues> recordValues,
        BundleUsedRecord& bundleRecord, PermissionUsedResult& result);
    void UpdateRecords(int32_t flag, const PermissionUsedRecord& inBundleRecord, PermissionUsedRecord& outBundleRecord);

    bool IsLocalDevice(const std::string& deviceId);

    OHOS::ThreadPool deleteTaskWorker_;
    bool hasInited_;
    OHOS::Utils::RWLock rwLock_;
};
} // namespace AccessToken
} // namespace Security
} // namespace OHOS
#endif // PERMISSION_RECORD_MANAGER_H
