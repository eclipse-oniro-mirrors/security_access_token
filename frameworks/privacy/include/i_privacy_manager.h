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

#ifndef I_PRIVACY_MANAGER_H
#define I_PRIVACY_MANAGER_H

#include <string>

#include "access_token.h"
#include "errors.h"
#include "iremote_broker.h"

#include "on_permission_used_record_callback.h"
#include "permission_used_request_parcel.h"
#include "permission_used_result_parcel.h"

namespace OHOS {
namespace Security {
namespace AccessToken {
class IPrivacyManager : public IRemoteBroker {
public:
    static const int32_t SA_ID_PRIVACY_MANAGER_SERVICE = 3505;

    DECLARE_INTERFACE_DESCRIPTOR(u"ohos.security.accesstoken.IPrivacyManager");

    virtual int32_t AddPermissionUsedRecord(
        AccessTokenID tokenID, const std::string& permissionName, int32_t successCount, int32_t failCount) = 0;
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
    enum class InterfaceCode {
        ADD_PERMISSION_USED_RECORD = 0xf001,
        START_USING_PERMISSION,
        START_USING_PERMISSION_CALLBACK,
        STOP_USING_PERMISSION,
        DELETE_PERMISSION_USED_RECORDS,
        GET_PERMISSION_USED_RECORDS,
        GET_PERMISSION_USED_RECORDS_ASYNC,
        REGISTER_PERM_ACTIVE_STATUS_CHANGE_CALLBACK,
        UNREGISTER_PERM_ACTIVE_STATUS_CHANGE_CALLBACK,
        IS_ALLOWED_USING_PERMISSION,
    };
};
} // namespace AccessToken
} // namespace Security
} // namespace OHOS

#endif // I_PRIVACY_MANAGER_H
