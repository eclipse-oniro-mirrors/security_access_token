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

#ifndef PRIVACY_MANAGER_CLIENT_H
#define PRIVACY_MANAGER_CLIENT_H

#include <mutex>
#include <string>
#include <vector>

#include "i_privacy_manager.h"
#include "privacy_death_recipient.h"

namespace OHOS {
namespace Security {
namespace AccessToken {
class PrivacyManagerClient final {
public:
    static PrivacyManagerClient& GetInstance();

    virtual ~PrivacyManagerClient();

    int AddPermissionUsedRecord(
        AccessTokenID tokenID, const std::string& permissionName, int successCount, int failCount);
    int StartUsingPermission(AccessTokenID tokenID, const std::string& permissionName);
    int StopUsingPermission(AccessTokenID tokenID, const std::string& permissionName);
    int RemovePermissionUsedRecords(AccessTokenID tokenID, const std::string& deviceID);
    int GetPermissionUsedRecords(const PermissionUsedRequest& request, PermissionUsedResult& result);
    int GetPermissionUsedRecords(
        const PermissionUsedRequest& request, const sptr<OnPermissionUsedRecordCallback>& callback);
    std::string DumpRecordInfo(const std::string& bundleName, const std::string& permissionName);

    void OnRemoteDiedHandle();
private:
    PrivacyManagerClient();

    DISALLOW_COPY_AND_MOVE(PrivacyManagerClient);
    std::mutex proxyMutex_;
    sptr<IPrivacyManager> proxy_ = nullptr;
    sptr<PrivacyDeathRecipient> serviceDeathObserver_ = nullptr;
    void InitProxy();
    sptr<IPrivacyManager> GetProxy();
};
} // namespace AccessToken
} // namespace Security
} // namespace OHOS
#endif // PRIVACY_MANAGER_CLIENT_H
