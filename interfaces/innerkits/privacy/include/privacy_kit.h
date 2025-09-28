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

/**
 * @addtogroup Privacy
 * @{
 *
 * @brief Provides sensitive permissions access management.
 *
 * @since 8.0
 * @version 8.0
 */

/**
 * @file privacy_kit.h
 *
 * @brief Declares PrivacyKit interfaces.
 *
 * @since 8.0
 * @version 8.0
 */

#ifndef INTERFACES_INNER_KITS_PRIVACY_KIT_H
#define INTERFACES_INNER_KITS_PRIVACY_KIT_H

#include <string>

#include "access_token.h"
#include "add_perm_param_info.h"
#include "disable_policy_change_callback.h"
#include "on_permission_used_record_callback.h"
#include "permission_used_request.h"
#include "permission_used_result.h"
#include "permission_used_type_info.h"
#include "perm_active_status_customized_cbk.h"
#include "privacy_param.h"
#include "state_customized_cbk.h"

namespace OHOS {
namespace Security {
namespace AccessToken {
/**
 * @brief Declares PrivacyKit class
 */
class PrivacyKit {
public:
    /**
     * @brief Add input tokenID access input permission record.
     * @param tokenID token id
     * @param permissionName permission nanme
     * @param successCount access success count
     * @param failCount fail success count
     * @return error code, see privacy_error.h
     */
    static int32_t AddPermissionUsedRecord(AccessTokenID tokenID, const std::string& permissionName,
        int32_t successCount, int32_t failCount, bool asyncMode = false);
    /**
     * @brief Add input tokenID access input permission record.
     * @param info struct AddPermParamInfo, see add_perm_param_info.h
     * @param asyncMode ipc wait type, true means sync waiting, false means async waiting
     * @return error code, see privacy_error.h
     */
    static int32_t AddPermissionUsedRecord(const AddPermParamInfo& info, bool asyncMode = false);
    /**
     * @brief Set permission used record toggle status.
     * @param userID the userID
     * @param status permission used record toggle status, true means record, false means not record
     * @return error code, see privacy_error.h
     */
    static int32_t SetPermissionUsedRecordToggleStatus(int32_t userID, bool status);
    /**
     * @brief Get permission used record toggle status.
     * @param userID the userID
     * @param status permission used record toggle status, true means record, false means not record
     * @return error code, see privacy_error.h
     */
    static int32_t GetPermissionUsedRecordToggleStatus(int32_t userID, bool& status);
    /**
     * @brief Input tokenID start using input permission.
     * @param tokenID token id
     * @param permissionName permission nanme
     * @return error code, see privacy_error.h
     */
    static int32_t StartUsingPermission(AccessTokenID tokenID, const std::string& permissionName, int32_t pid = -1,
        PermissionUsedType type = PermissionUsedType::NORMAL_TYPE);
    /**
     * @brief Input tokenID start using input permission and return by callback,
     *        only those services which has float window such as camera or
     *        microphone can use this interface.
     * @param tokenID token id
     * @param permissionName permission nanme
     * @param callback StateCustomizedCbk nanme
     * @return error code, see privacy_error.h
     */
    static int32_t StartUsingPermission(AccessTokenID tokenID, const std::string& permissionName,
        const std::shared_ptr<StateCustomizedCbk>& callback, int32_t pid = -1,
        PermissionUsedType type = PermissionUsedType::NORMAL_TYPE);
    /**
     * @brief Input tokenID stop using input permission.
     * @param tokenID token id
     * @param permissionName permission nanme
     * @return error code, see privacy_error.h
     */
    static int32_t StopUsingPermission(AccessTokenID tokenID, const std::string& permissionName, int32_t pid = -1);
    /**
     * @brief Remove input tokenID sensitive permission used records.
     * @param tokenID token id
     * @return error code, see privacy_error.h
     */
    static int32_t RemovePermissionUsedRecords(AccessTokenID tokenID);
    /**
     * @brief Get sensitive permission used records.
     * @param request PermissionUsedRequest quote
     * @param result PermissionUsedResult quote, as query result
     * @return error code, see privacy_error.h
     */
    static int32_t GetPermissionUsedRecords(const PermissionUsedRequest& request, PermissionUsedResult& result);
    /**
     * @brief Get sensitive permission used records.
     * @param request PermissionUsedRequest quote
     * @param callback OnPermissionUsedRecordCallback smart pointer quote
     * @return error code, see privacy_error.h
     */
    static int32_t GetPermissionUsedRecords(
        const PermissionUsedRequest& request, const sptr<OnPermissionUsedRecordCallback>& callback);
    /**
     * @brief Register sensitive permission active status change callback.
     * @param callback PermActiveStatusCustomizedCbk smark pointer quote
     * @return error code, see privacy_error.h
     */
    static int32_t RegisterPermActiveStatusCallback(const std::shared_ptr<PermActiveStatusCustomizedCbk>& callback);
    /**
     * @brief Unregister sensitive permission active status change callback.
     * @param callback PermActiveStatusCustomizedCbk smark pointer quote
     * @return error code, see privacy_error.h
     */
    static int32_t UnRegisterPermActiveStatusCallback(const std::shared_ptr<PermActiveStatusCustomizedCbk>& callback);
    /**
     * @brief Judge whether the input tokenID can use the input permission or not.
     * @param tokenID token id
     * @param permissionName permission nanme
     * @return true means allow to user the permission, false means not allow
     */
    static bool IsAllowedUsingPermission(AccessTokenID tokenID, const std::string& permissionName, int32_t pid = -1);

    /**
     * @brief query permission used type.
     * @param tokenId token id, if 0 return all tokenIds
     * @param permissionName permission name, if null return all permissions
     * @param results query result as PermissionUsedTypeInfo array
     * @return error code, see privacy_error.h
     */
    static int32_t GetPermissionUsedTypeInfos(const AccessTokenID tokenId, const std::string& permissionName,
        std::vector<PermissionUsedTypeInfo>& results);

    /**
     * @brief try set mute policy.
     * @param policyType policy type, see privacy_param.h
     * @param caller caller type, see privacy_param.h
     * @param isMute mute or unmute
     * @param tokenID when policyType is EDM, this param should be first caller token id,
     *                when policyType is not EDM, this param will be ignore.
     * @return error code, see privacy_error.h
     */
    static int32_t SetMutePolicy(uint32_t policyType, uint32_t callerType, bool isMute, AccessTokenID tokenID);

    /**
     * @brief try set background visit policy.
     * @param tokenId token id
     * @param isAllowed allow or disallow
     * @return error code, see privacy_error.h
     */
    static int32_t SetHapWithFGReminder(uint32_t tokenId, bool isAllowed);

    /**
     * @brief Set permission disable policy.
     * @param permission permission name
     * @param isDisable true means set permission disable
     * @return error code, see privacy_error.h
     */
    static int32_t SetDisablePolicy(const std::string& permissionName, bool isDisable);

    /**
     * @brief Get permission disable policy.
     * @param permission permission name
     * @param isDisable permission disable policy
     * @return error code, see privacy_error.h
     */
    static int32_t GetDisablePolicy(const std::string& permissionName, bool& isDisable);

    /**
     * @brief Register permission disable policy change callback.
     * @param callback DisablePolicyChangeCallback smark pointer quote
     * @return error code, see privacy_error.h
     */
    static int32_t RegisterPermDisablePolicyCallback(const std::shared_ptr<DisablePolicyChangeCallback>& callback);

    /**
     * @brief UnRegister permission disable policy change callback.
     * @param callback DisablePolicyChangeCallback smark pointer quote
     * @return error code, see privacy_error.h
     */
    static int32_t UnRegisterPermDisablePolicyCallback(const std::shared_ptr<DisablePolicyChangeCallback>& callback);
};
} // namespace AccessToken
} // namespace Security
} // namespace OHOS
#endif
