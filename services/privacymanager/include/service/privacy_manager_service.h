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

#ifndef PRIVACY_MANAGER_SERVICE_H
#define PRIVACY_MANAGER_SERVICE_H

#include <string>

#include "privacy_manager_stub.h"
#include "iremote_object.h"
#include "nocopyable.h"
#include "singleton.h"
#include "system_ability.h"

namespace OHOS {
namespace Security {
namespace AccessToken {
enum class ServiceRunningState { STATE_NOT_START, STATE_RUNNING };
class PrivacyManagerService final : public SystemAbility, public PrivacyManagerStub {
    DECLARE_DELAYED_SINGLETON(PrivacyManagerService);
    DECLEAR_SYSTEM_ABILITY(PrivacyManagerService);

public:
    void OnStart() override;
    void OnStop() override;

    int32_t AddPermissionUsedRecord(
        AccessTokenID tokenId, const std::string& permissionName, int32_t successCount, int32_t failCount) override;
    int32_t StartUsingPermission(AccessTokenID tokenId, const std::string& permissionName) override;
    int32_t StartUsingPermission(AccessTokenID tokenId, const std::string& permissionName,
        const sptr<IRemoteObject>& callback) override;
    int32_t StopUsingPermission(AccessTokenID tokenId, const std::string& permissionName) override;
    int32_t RemovePermissionUsedRecords(AccessTokenID tokenId, const std::string& deviceID) override;
    int32_t GetPermissionUsedRecords(
        const PermissionUsedRequestParcel& request, PermissionUsedResultParcel& result) override;
    int32_t GetPermissionUsedRecords(
        const PermissionUsedRequestParcel& request, const sptr<OnPermissionUsedRecordCallback>& callback) override;
    int32_t RegisterPermActiveStatusCallback(
        std::vector<std::string>& permList, const sptr<IRemoteObject>& callback) override;
    int32_t UnRegisterPermActiveStatusCallback(const sptr<IRemoteObject>& callback) override;
    bool IsAllowedUsingPermission(AccessTokenID tokenId, const std::string& permissionName) override;
    int32_t Dump(int32_t fd, const std::vector<std::u16string>& args) override;
private:
    bool Initialize() const;
    int32_t ResponseDumpCommand(int32_t fd,  const std::vector<std::u16string>& args);

    ServiceRunningState state_;
};
} // namespace AccessToken
} // namespace Security
} // namespace OHOS
#endif // PRIVACY_MANAGER_SERVICE_H
