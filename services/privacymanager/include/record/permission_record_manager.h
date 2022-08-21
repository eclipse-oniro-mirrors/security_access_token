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
#include <set>
#include <string>

#include "access_token.h"
#include "hap_token_info.h"
#include "nocopyable.h"
#include "on_permission_used_record_callback.h"
#include "permission_record.h"
#include "permission_used_request.h"
#include "permission_used_result.h"

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
        AccessTokenID tokenId, const std::string& permissionName, int32_t successCount, int32_t failCount);
    void RemovePermissionUsedRecords(AccessTokenID tokenId, const std::string& deviceID);
    int32_t GetPermissionUsedRecords(const PermissionUsedRequest& request, PermissionUsedResult& result);
    int32_t GetPermissionUsedRecordsAsync(
        const PermissionUsedRequest& request, const sptr<OnPermissionUsedRecordCallback>& callback);
    std::string DumpRecordInfo(AccessTokenID tokenId, const std::string& permissionName);
    int32_t StartUsingPermission(AccessTokenID tokenId, const std::string& permissionName);
    int32_t StopUsingPermission(AccessTokenID tokenId, const std::string& permissionName);
    int32_t RegisterPermActiveStatusCallback(
        std::vector<std::string>& permList, const sptr<IRemoteObject>& callback);
    int32_t UnRegisterPermActiveStatusCallback(const sptr<IRemoteObject>& callback);

private:
    PermissionRecordManager();
    DISALLOW_COPY_AND_MOVE(PermissionRecordManager);

    bool GetLocalRecordTokenIdList(std::set<AccessTokenID>& tokenIdList);
    bool AddRecord(const PermissionRecord& record);
    bool GetPermissionsRecord(AccessTokenID tokenId, const std::string& permissionName,
        int32_t successCount, int32_t failCount, PermissionRecord& record);
    bool CreateBundleUsedRecord(const AccessTokenID tokenId, BundleUsedRecord& bundleRecord);
    void ExecuteDeletePermissionRecordTask();
    int32_t DeletePermissionRecord(int32_t days);
    bool GetRecordsFromLocalDB(const PermissionUsedRequest& request, PermissionUsedResult& result);
    bool GetRecords(int32_t flag, std::vector<GenericValues> recordValues,
        BundleUsedRecord& bundleRecord, PermissionUsedResult& result);
    void UpdateRecords(int32_t flag, const PermissionUsedRecord& inBundleRecord, PermissionUsedRecord& outBundleRecord);

    std::string GetDeviceId(AccessTokenID tokenId);

    OHOS::ThreadPool deleteTaskWorker_;
    bool hasInited_;
    OHOS::Utils::RWLock rwLock_;
};
} // namespace AccessToken
} // namespace Security
} // namespace OHOS
#endif // PERMISSION_RECORD_MANAGER_H
