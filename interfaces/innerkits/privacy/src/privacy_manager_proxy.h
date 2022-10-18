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

#ifndef PRIVACY_MANAGER_PROXY_H
#define PRIVACY_MANAGER_PROXY_H

#include <string>

#include "i_privacy_manager.h"
#include "iremote_proxy.h"

namespace OHOS {
namespace Security {
namespace AccessToken {
class PrivacyManagerProxy : public IRemoteProxy<IPrivacyManager> {
public:
    explicit PrivacyManagerProxy(const sptr<IRemoteObject>& impl);
    ~PrivacyManagerProxy() override;

    int32_t AddPermissionUsedRecord(
        AccessTokenID tokenID, const std::string& permissionName, int32_t successCount, int32_t failCount) override;
    int32_t StartUsingPermission(AccessTokenID tokenID, const std::string& permissionName) override;
    int32_t StartUsingPermission(AccessTokenID tokenID, const std::string& permissionName,
        const sptr<IRemoteObject>& callback) override;
    int32_t StopUsingPermission(AccessTokenID tokenID, const std::string& permissionName) override;
    int32_t RemovePermissionUsedRecords(AccessTokenID tokenID, const std::string& deviceID) override;
    int32_t GetPermissionUsedRecords(
        const PermissionUsedRequestParcel& request, PermissionUsedResultParcel& result) override;
    int32_t GetPermissionUsedRecords(const PermissionUsedRequestParcel& request,
        const sptr<OnPermissionUsedRecordCallback>& callback) override;
    int32_t RegisterPermActiveStatusCallback(
        std::vector<std::string>& permList, const sptr<IRemoteObject>& callback) override;
    int32_t UnRegisterPermActiveStatusCallback(const sptr<IRemoteObject>& callback) override;
    bool IsAllowedUsingPermission(AccessTokenID tokenID, const std::string& permissionName) override;

private:
    bool SendRequest(IPrivacyManager::InterfaceCode code, MessageParcel& data, MessageParcel& reply);
    static inline BrokerDelegator<PrivacyManagerProxy> delegator_;
};
} // namespace AccessToken
} // namespace Security
} // namespace OHOS
#endif // PRIVACY_MANAGER_PROXY_H