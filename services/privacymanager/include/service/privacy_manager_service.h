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

#ifndef PRIVACY_MANAGER_SERVICE_H
#define PRIVACY_MANAGER_SERVICE_H

#include <string>

#ifdef EVENTHANDLER_ENABLE
#include "access_event_handler.h"
#endif
#include "privacy_manager_stub.h"
#include "iremote_object.h"
#include "nocopyable.h"
#include "proxy_death_handler.h"
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

    int32_t AddPermissionUsedRecord(const AddPermParamInfoParcel& infoParcel, bool asyncMode = false) override;
    int32_t SetPermissionUsedRecordToggleStatus(int32_t userID, bool status) override;
    int32_t GetPermissionUsedRecordToggleStatus(int32_t userID, bool& status) override;
    int32_t StartUsingPermission(const PermissionUsedTypeInfoParcel &infoParcel,
        const sptr<IRemoteObject>& anonyStub) override;
    int32_t StartUsingPermission(const PermissionUsedTypeInfoParcel &infoParcel,
        const sptr<IRemoteObject>& callback, const sptr<IRemoteObject>& anonyStub) override;
    int32_t StopUsingPermission(AccessTokenID tokenId, int32_t pid, const std::string& permissionName) override;
    int32_t RemovePermissionUsedRecords(AccessTokenID tokenId) override;
    int32_t GetPermissionUsedRecords(
        const PermissionUsedRequestParcel& request, PermissionUsedResultParcel& result) override;
    int32_t GetPermissionUsedRecords(
        const PermissionUsedRequestParcel& request, const sptr<OnPermissionUsedRecordCallback>& callback) override;
    int32_t RegisterPermActiveStatusCallback(
        std::vector<std::string>& permList, const sptr<IRemoteObject>& callback) override;
    int32_t UnRegisterPermActiveStatusCallback(const sptr<IRemoteObject>& callback) override;
#ifdef SECURITY_COMPONENT_ENHANCE_ENABLE
    int32_t RegisterSecCompEnhance(const SecCompEnhanceDataParcel& enhanceParcel) override;
    int32_t UpdateSecCompEnhance(int32_t pid, uint32_t seqNum) override;
    int32_t GetSecCompEnhance(int32_t pid, SecCompEnhanceDataParcel& enhanceParcel) override;
    int32_t GetSpecialSecCompEnhance(const std::string& bundleName,
        std::vector<SecCompEnhanceDataParcel>& enhanceParcelList) override;
#endif
    bool IsAllowedUsingPermission(AccessTokenID tokenId, const std::string& permissionName, int32_t pid) override;
    int32_t GetPermissionUsedTypeInfos(const AccessTokenID tokenId, const std::string& permissionName,
        std::vector<PermissionUsedTypeInfoParcel>& resultsParcel) override;
    int32_t Dump(int32_t fd, const std::vector<std::u16string>& args) override;
    int32_t SetMutePolicy(uint32_t policyType, uint32_t callerType, bool isMute) override;
    int32_t SetHapWithFGReminder(uint32_t tokenId, bool isAllowed) override;
private:
    void OnAddSystemAbility(int32_t systemAbilityId, const std::string& deviceId) override;
    bool Initialize();
    int32_t ResponseDumpCommand(int32_t fd,  const std::vector<std::u16string>& args);
    std::shared_ptr<ProxyDeathHandler> GetProxyDeathHandler();
    void ProcessProxyDeathStub(const sptr<IRemoteObject>& anonyStub, int32_t callerPid);
    void ReleaseDeathStub(int32_t callerPid);

    ServiceRunningState state_;

#ifdef EVENTHANDLER_ENABLE
    std::shared_ptr<AppExecFwk::EventRunner> eventRunner_;
    std::shared_ptr<AccessEventHandler> eventHandler_;
#endif
    std::mutex deathHandlerMutex_;
    std::shared_ptr<ProxyDeathHandler> proxyDeathHandler_;
};
} // namespace AccessToken
} // namespace Security
} // namespace OHOS
#endif // PRIVACY_MANAGER_SERVICE_H
