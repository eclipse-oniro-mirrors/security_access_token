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

#ifndef INTERFACES_INNER_KITS_PRIVACY_KIT_H
#define INTERFACES_INNER_KITS_PRIVACY_KIT_H

#include <string>

#include "access_token.h"
#include "on_permission_used_record_callback.h"
#include "permission_used_request.h"
#include "permission_used_result.h"
#include "perm_active_status_customized_cbk.h"
#include "state_customized_cbk.h"

namespace OHOS {
namespace Security {
namespace AccessToken {
class PrivacyKit {
public:
    static int32_t AddPermissionUsedRecord(
        AccessTokenID tokenID, const std::string& permissionName, int32_t successCount, int32_t failCount);
    static int32_t StartUsingPermission(AccessTokenID tokenID, const std::string& permissionName);
    static int32_t StartUsingPermission(AccessTokenID tokenID, const std::string& permissionName,
        const std::shared_ptr<StateCustomizedCbk>& callback);
    static int32_t StopUsingPermission(AccessTokenID tokenID, const std::string& permissionName);
    static int32_t RemovePermissionUsedRecords(AccessTokenID tokenID, const std::string& deviceID);
    static int32_t GetPermissionUsedRecords(const PermissionUsedRequest& request, PermissionUsedResult& result);
    static int32_t GetPermissionUsedRecords(
        const PermissionUsedRequest& request, const sptr<OnPermissionUsedRecordCallback>& callback);
    static int32_t RegisterPermActiveStatusCallback(const std::shared_ptr<PermActiveStatusCustomizedCbk>& callback);
    static int32_t UnRegisterPermActiveStatusCallback(const std::shared_ptr<PermActiveStatusCustomizedCbk>& callback);
    static bool IsAllowedUsingPermission(AccessTokenID tokenID, const std::string& permissionName);
};
} // namespace AccessToken
} // namespace Security
} // namespace OHOS
#endif
