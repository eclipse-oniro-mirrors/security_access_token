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

    int32_t AddPermissionUsedRecord(const AddPermParamInfoParcel& infoParcel, bool asyncMode = false) override;
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
#ifdef SECURITY_COMPONENT_ENHANCE_ENABLE
    int32_t RegisterSecCompEnhance(const SecCompEnhanceDataParcel& enhance) override;
    int32_t UpdateSecCompEnhance(int32_t pid, int32_t seqNum) override;
    int32_t GetSecCompEnhance(int32_t pid, SecCompEnhanceDataParcel& enhanceParcel) override;
    int32_t GetSpecialSecCompEnhance(const std::string& bundleName,
        std::vector<SecCompEnhanceDataParcel>& enhanceParcelList) override;
#endif
    int32_t GetPermissionUsedTypeInfos(const AccessTokenID tokenId, const std::string& permissionName,
        std::vector<PermissionUsedTypeInfoParcel>& resultsParcel) override;
    int32_t SetMutePolicy(uint32_t policyType, uint32_t callerType, bool isMute) override;
private:
    bool SendRequest(PrivacyInterfaceCode code, MessageParcel& data, MessageParcel& reply, bool asyncMode = false);
    static inline BrokerDelegator<PrivacyManagerProxy> delegator_;
};
} // namespace AccessToken
} // namespace Security
} // namespace OHOS
#endif // PRIVACY_MANAGER_PROXY_H
