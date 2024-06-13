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

#ifndef I_PRIVACY_MANAGER_H
#define I_PRIVACY_MANAGER_H

#include <string>

#include "access_token.h"
#include "add_perm_param_info_parcel.h"
#include "errors.h"
#include "iremote_broker.h"

#include "on_permission_used_record_callback.h"
#include "privacy_service_ipc_interface_code.h"
#include "permission_used_request_parcel.h"
#include "permission_used_result_parcel.h"
#include "permission_used_type_info_parcel.h"
#include "privacy_param.h"
#ifdef SECURITY_COMPONENT_ENHANCE_ENABLE
#include "sec_comp_enhance_data_parcel.h"
#endif

/* SAID:3505 */
namespace OHOS {
namespace Security {
namespace AccessToken {
class IPrivacyManager : public IRemoteBroker {
public:
    static const int32_t SA_ID_PRIVACY_MANAGER_SERVICE = 3505;

    DECLARE_INTERFACE_DESCRIPTOR(u"ohos.security.accesstoken.IPrivacyManager");

    virtual int32_t AddPermissionUsedRecord(const AddPermParamInfoParcel& infoParcel, bool asyncMode = false) = 0;
    virtual int32_t StartUsingPermission(AccessTokenID tokenID, const std::string& permissionName) = 0;
    virtual int32_t StartUsingPermission(AccessTokenID tokenID, const std::string& permissionName,
        const sptr<IRemoteObject>& callback) = 0;
    virtual int32_t StopUsingPermission(AccessTokenID tokenID, const std::string& permissionName) = 0;
    virtual int32_t RemovePermissionUsedRecords(AccessTokenID tokenID, const std::string& deviceID) = 0;
    virtual int32_t GetPermissionUsedRecords(
        const PermissionUsedRequestParcel& request, PermissionUsedResultParcel& result) = 0;
    virtual int32_t GetPermissionUsedRecords(
        const PermissionUsedRequestParcel& request, const sptr<OnPermissionUsedRecordCallback>& callback) = 0;
    virtual int32_t RegisterPermActiveStatusCallback(
        std::vector<std::string>& permList, const sptr<IRemoteObject>& callback) = 0;
    virtual int32_t UnRegisterPermActiveStatusCallback(const sptr<IRemoteObject>& callback) = 0;
    virtual bool IsAllowedUsingPermission(AccessTokenID tokenID, const std::string& permissionName) = 0;
    virtual int32_t SetMutePolicy(uint32_t policyType, uint32_t callerType, bool isMute) = 0;
#ifdef SECURITY_COMPONENT_ENHANCE_ENABLE
    virtual int32_t RegisterSecCompEnhance(const SecCompEnhanceDataParcel& enhanceParcel) = 0;
    virtual int32_t UpdateSecCompEnhance(int32_t pid, int32_t seqNum) = 0;
    virtual int32_t GetSecCompEnhance(int32_t pid, SecCompEnhanceDataParcel& enhanceParcel) = 0;
    virtual int32_t GetSpecialSecCompEnhance(const std::string& bundleName,
        std::vector<SecCompEnhanceDataParcel>& enhanceParcelList) = 0;
#endif
    virtual int32_t GetPermissionUsedTypeInfos(const AccessTokenID tokenId, const std::string& permissionName,
        std::vector<PermissionUsedTypeInfoParcel>& resultsParcel) = 0;
};
} // namespace AccessToken
} // namespace Security
} // namespace OHOS

#endif // I_PRIVACY_MANAGER_H
