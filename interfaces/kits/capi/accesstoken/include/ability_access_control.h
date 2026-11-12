/*
 * Copyright (c) 2024-2026 Huawei Device Co., Ltd.
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
 * @addtogroup AbilityAccessControl
 * @{
 *
 * @brief Provides the capability to manage access token.
 *
 * @since 12
 */

/**
 * @file ability_access_control.h
 *
 * @brief Declares the APIs for managing access token.
 *
 * @syscap SystemCapability.Security.AccessToken
 * @include <accesstoken/ability_access_control.h>
 * @library libability_access_control.so
 * @kit AbilityKit
 * @since 12
 */

#ifndef ABILITY_ACCESS_CONTROL_H
#define ABILITY_ACCESS_CONTROL_H

#include <stdbool.h>
#include <stdint.h>

#ifdef __cplusplus
extern "C" {
#endif

/**
 * @brief Checks whether this application has been granted the given permission.
 *
 * @param permission - Name of the permission to be granted.
 * @return true  - The permission has been granted to this application.
 *         false - The permission has not been granted to this application.
 * @since 12
 */
bool OH_AT_CheckSelfPermission(const char *permission);

/**
 * @brief Error codes for ability access control operations.
 *
 * @since 26.1.0
 */
typedef enum OH_AT_AbilityAccessControlErrorCode {
    /**
     * @brief Operation succeeded.
     * @since 26.1.0
     */
    OH_AT_ABILITY_ACCESS_CONTROL_SUCCESS = 0,
    /**
     * @brief This capability is not supported.
     * @since 26.1.0
     */
    OH_AT_ABILITY_ACCESS_CONTROL_NOT_SUPPORTED_ERROR = 801,
    /**
     * @brief Parameter error. Permission array is NULL, permission contains NULL or empty string,
     * permCount <= 0, permCount > 1024, or NULL callback.
     * @since 26.1.0
     */
    OH_AT_ABILITY_ACCESS_CONTROL_INVALID_PARAMETER_ERROR = 12100001,
    /**
     * @brief Service exception.
     * @since 26.1.0
     */
    OH_AT_ABILITY_ACCESS_CONTROL_SERVICE_EXCEPTION_ERROR = 12100007,
    /**
     * @brief An internal service error occurs. For example, a pop-up window fails to be opened or a user
     * operation result fails to be obtained.
     * @since 26.1.0
     */
    OH_AT_ABILITY_ACCESS_CONTROL_COMMON_INNER_ERROR = 12100009,
    /**
     * @brief The process type is not allowed.
     * @since 26.1.0
     */
    OH_AT_ABILITY_ACCESS_CONTROL_NOT_PERMITTED_PROCESS_TYPE_ERROR = 12100016
} OH_AT_AbilityAccessControlErrorCode;

/**
 * @brief Enumeration of the result of the permission request.
 *
 * @since 26.1.0
 */
typedef enum OH_AT_PermissionOperResult {
    /**
     * @brief Authorized.
     * @since 26.1.0
     */
    OH_AT_PERMISSION_OPER_GRANTED = 0,
    /**
     * @brief If the user is not authorized, determine the cause based on
     * {@link OH_AT_PermissionsRequestResult.dialogShownResults}. If the value of dialogShownResults is true, the user
     * rejects the application. If the value is false, no dialog box is displayed for the current status. Generally,
     * you need to go to Settings to modify the authorization status of the permission.
     * @since 26.1.0
     */
    OH_AT_PERMISSION_OPER_SETTING = 1,
    /**
     * @brief Permission name is invalid.
     * @since 26.1.0
     */
    OH_AT_PERMISSION_OPER_INVALID_NAME = 2,
    /**
     * @brief The lifter application or standalone binary (BIN) does not declare this permission.
     * @since 26.1.0
     */
    OH_AT_PERMISSION_OPER_NOT_DECLARED = 3,
    /**
     * @brief The permission application conditions are not met. For example, some location permissions must meet the
     * additional prerequisites. Currently, only the location permission is involved, including
     * ohos.permission.LOCATION and ohos.permission.APPROXIMATELY_LOCATION.
     * @since 26.1.0
     */
    OH_AT_PERMISSION_OPER_CONSTRAINTS_NOT_MET = 4,
    /**
     * @brief The authorization mode of the permission does not match this interface. For example, if the permission
     * is of the manual_settings type, you need to go to Settings to enable the corresponding function.
     * @since 26.1.0
     */
    OH_AT_PERMISSION_OPER_GRANT_MODE_MISMATCH = 5,
    /**
     * @brief The user does not agree to the privacy statement.
     * @since 26.1.0
     */
    OH_AT_PERMISSION_OPER_PRIVACY_STATEMENT_REQUIRED = 6,
    /**
     * @brief This permission cannot be applied for in the permission pop-up window. The application method may be
     * restricted or controlled by system policies. The authorization status cannot be modified for this permission.
     * @since 26.1.0
     */
    OH_AT_PERMISSION_OPER_POP_UP_RESTRICTED = 7
} OH_AT_PermissionOperResult;

/**
 * @brief Permission request result.
 * @since 26.1.0
 */
typedef struct OH_AT_PermissionsRequestResult {
    /**
     * @brief Request error code. For details, see {@link OH_AT_AbilityAccessControlErrorCode}.
     * @since 26.1.0
     */
    OH_AT_AbilityAccessControlErrorCode errorCode;
    /**
     * @brief Permission array of the current request.
     * @since 26.1.0
     */
    const char **permissions;
    /**
     * @brief Number of permissions requested to be granted.
     * @since 26.1.0
     */
    int32_t permCount;
    /**
     * @brief The operation result of each permission corresponds to the permission.
     * @since 26.1.0
     */
    OH_AT_PermissionOperResult *operResults;
    /**
     * @brief Indicates whether the authorization pop-up window is displayed for each permission during this
     * application. true indicates that the authorization pop-up window is displayed, and false indicates that the
     * authorization pop-up window is not displayed.
     * @since 26.1.0
     */
    bool *dialogShownResults;
} OH_AT_PermissionsRequestResult;

/**
 * @brief Callback function type of the permission request result.
 * Callbacks may be triggered concurrently, and the triggering sequence is not guaranteed.
 *
 * @param result [in] Permission request result. Must not be NULL. This parameter is valid only during the callback
 *     execution and becomes invalid after the callback is returned. The caller must not hold or release the result.
 * @param userData [in,out] User data passed to the callback. Can be empty. The callback may modify what userData
 *     points to. Its life cycle is the responsibility of the caller and must cover the entire execution of the
 *     callback.
 *
 * @since 26.1.0
 */
typedef void (*OH_AT_PermissionsRequestResultCallback)(
    const OH_AT_PermissionsRequestResult *result,
    void *userData);

/**
 * @brief Supports independent binary startup pop-up windows to request user authorization.
 *
 * @param permissions [in] Permission array to be requested. Must not be NULL and must not contain NULL or an empty
 *     string. Permissions must be declared in the startup application. Before this function returns, the system
 *     copies the permission name, so the caller can release the array and its strings after the function returns.
 * @param permCount [in] Number of permissions.
 *     <br>The value cannot exceed 1024 and cannot be 0.
 * @param callback [in] Callback function for receiving the authorization result of each permission. Must not be
 *     NULL. The result passed to the callback is valid only for the duration of the callback execution. If this
 *     function returns an error code, no callback is triggered.
 * @param userData [in] User data passed to the callback. The value can be NULL.
 *     Its life cycle is the responsibility of the caller and must cover the entire execution of the callback.
 * @return <ul>
 *     <li>{@link OH_AT_ABILITY_ACCESS_CONTROL_SUCCESS} Permission request succeeded.</li>
 *     <li>{@link OH_AT_ABILITY_ACCESS_CONTROL_NOT_SUPPORTED_ERROR} Does not support this capability.</li>
 *     <li>{@link OH_AT_ABILITY_ACCESS_CONTROL_INVALID_PARAMETER_ERROR} The parameter is incorrect. Possible causes:
 *     1. The permission contains NULL or an empty string.
 *     2. permCount <= 0 or permCount > 1024.
 *     3. Empty callback.</li>
 *     <li>{@link OH_AT_ABILITY_ACCESS_CONTROL_SERVICE_EXCEPTION_ERROR} The service is abnormal.</li>
 *     <li>{@link OH_AT_ABILITY_ACCESS_CONTROL_COMMON_INNER_ERROR} An internal service error occurs. For example,
 *     a pop-up window fails to be created or the user operation result fails to be obtained.</li>
 *     <li>{@link OH_AT_ABILITY_ACCESS_CONTROL_NOT_PERMITTED_PROCESS_TYPE_ERROR} The process type is not
 *     allowed.</li>
 *     </ul>
 * @since 26.1.0
 */
OH_AT_AbilityAccessControlErrorCode OH_AT_RequestPermissionsFromUser(
    const char *permissions[],
    int32_t permCount,
    OH_AT_PermissionsRequestResultCallback callback,
    void *userData);

#ifdef __cplusplus
}
#endif

/** @} */
#endif /* ABILITY_ACCESS_CONTROL_H */
