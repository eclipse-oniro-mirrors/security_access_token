/*
 * Copyright (c) 2022-2025 Huawei Device Co., Ltd.
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

#include <map>
#include <mutex>
#include <string>
#include <vector>

#include "iprivacy_manager.h"
#include "perm_active_status_change_callback.h"
#include "perm_active_status_customized_cbk.h"
#include "privacy_death_recipient.h"
#include "proxy_death_callback_stub.h"
#include "state_change_callback.h"
#include "state_customized_cbk.h"

namespace OHOS {
namespace Security {
namespace AccessToken {
class PrivacyManagerClient final {
public:
    static PrivacyManagerClient& GetInstance();

    virtual ~PrivacyManagerClient();

    int32_t AddPermissionUsedRecord(const AddPermParamInfo& info, bool asyncMode = false);
    int32_t SetPermissionUsedRecordToggleStatus(int32_t userID, bool status);
    int32_t GetPermissionUsedRecordToggleStatus(int32_t userID, bool& status);
    int32_t StartUsingPermission(AccessTokenID tokenID, int32_t pid, const std::string& permissionName,
        PermissionUsedType type);
    int32_t CreateStateChangeCbk(uint64_t id, const std::shared_ptr<StateCustomizedCbk>& callback,
        sptr<StateChangeCallback>& callbackWrap);
    int32_t StartUsingPermission(AccessTokenID tokenId, int32_t pid, const std::string& permissionName,
        const std::shared_ptr<StateCustomizedCbk>& callback, PermissionUsedType type);
    int32_t StopUsingPermission(AccessTokenID tokenID, int32_t pid, const std::string& permissionName);
    int32_t RemovePermissionUsedRecords(AccessTokenID tokenID);
    int32_t GetPermissionUsedRecords(const PermissionUsedRequest& request, PermissionUsedResult& result);
    int32_t GetPermissionUsedRecords(
        const PermissionUsedRequest& request, const sptr<OnPermissionUsedRecordCallback>& callback);
    int32_t RegisterPermActiveStatusCallback(const std::shared_ptr<PermActiveStatusCustomizedCbk>& callback);
    int32_t UnRegisterPermActiveStatusCallback(const std::shared_ptr<PermActiveStatusCustomizedCbk>& callback);
    int32_t CreateActiveStatusChangeCbk(
        const std::shared_ptr<PermActiveStatusCustomizedCbk>& callback,
        sptr<PermActiveStatusChangeCallback>& callbackWrap);
    bool IsAllowedUsingPermission(AccessTokenID tokenID, const std::string& permissionName, int32_t pid);
    void OnRemoteDiedHandle();
    int32_t GetPermissionUsedTypeInfos(const AccessTokenID tokenId, const std::string& permissionName,
        std::vector<PermissionUsedTypeInfo>& results);
    int32_t SetMutePolicy(uint32_t policyType, uint32_t callerType, bool isMute, AccessTokenID tokenID);
    int32_t SetHapWithFGReminder(uint32_t tokenId, bool isAllowed);

private:
    PrivacyManagerClient();

    DISALLOW_COPY_AND_MOVE(PrivacyManagerClient);
    std::mutex proxyMutex_;
    sptr<IPrivacyManager> proxy_ = nullptr;
    sptr<PrivacyDeathRecipient> serviceDeathObserver_ = nullptr;
    void InitProxy();
    sptr<IPrivacyManager> GetProxy();
    void ReleaseProxy();
    uint64_t GetUniqueId(uint32_t tokenId, int32_t pid) const;
    sptr<ProxyDeathCallBackStub> GetAnonyStub();

private:
    std::mutex activeCbkMutex_;
    std::map<std::shared_ptr<PermActiveStatusCustomizedCbk>, sptr<PermActiveStatusChangeCallback>> activeCbkMap_;
    std::mutex stateCbkMutex_;
    std::map<uint64_t, sptr<StateChangeCallback>> stateChangeCallbackMap_;
    std::mutex stubMutex_;
    sptr<ProxyDeathCallBackStub> anonyStub_ = nullptr;
};
} // namespace AccessToken
} // namespace Security
} // namespace OHOS
#endif // PRIVACY_MANAGER_CLIENT_H
