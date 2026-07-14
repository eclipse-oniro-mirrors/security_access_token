/*
 * Copyright (c) 2022-2026 Huawei Device Co., Ltd.
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
 * @addtogroup AccessToken
 * @{
 *
 * @brief Provides permission management interfaces.
 *
 * Provides tokenID-based application permission verification mechanism.
 * When an application accesses sensitive data or APIs, this module can check
 * whether the application has the corresponding permission. Allows applications
 * to query their access token information or APL levcels based on token IDs.
 *
 * @since 7.0
 * @version 7.0
 */

/**
 * @file access_token_error.h
 *
 * @brief Declares error numbers.
 *
 * @since 7.0
 * @version 7.0
 */

#ifndef ACCESS_TOKEN_ERROR_H
#define ACCESS_TOKEN_ERROR_H

namespace OHOS {
namespace Security {
namespace AccessToken {
typedef enum {
    TICKET_CODE_BASE = 0X19 << 12,
} ExtErrorType;

typedef enum {
    ERR_TICKET_NETWORK_DISCONNECTED = TICKET_CODE_BASE | 3,
    ERR_TICKET_NOT_LOGGED_IN = TICKET_CODE_BASE | 4,
} ExtResultCode;

/**
 * @brief error numbers
 */
enum AccessTokenError {
    ERR_PERMISSION_DENIED = 201,
    ERR_NOT_SYSTEM_APP = 202,
    ERR_PARAM_INVALID = 12100001,
    ERR_TOKEN_INVALID,
    ERR_TOKEN_MAP_FAILED,
    ERR_TOKENID_NOT_EXIST,
    ERR_TOKENID_HAS_EXISTED,
    ERR_TOKENID_CREATE_FAILED,
    ERR_PERMISSION_NOT_EXIST,
    ERR_INTERFACE_NOT_USED_TOGETHER,
    ERR_CALLBACK_ALREADY_EXIST,
    ERR_CALLBACKS_EXCEED_LIMITATION,
    ERR_IDENTITY_CHECK_FAILED,
    ERR_SERVICE_ABNORMAL,
    ERR_MALLOC_FAILED,
    ERR_DEVICE_NOT_EXIST,
    ERR_PROCESS_NOT_EXIST,
    ERR_OVERSIZE,
    ERROR_IPC_REQUEST_FAIL,
    ERR_READ_PARCEL_FAILED,
    ERR_WRITE_PARCEL_FAILED,
    ERR_CHECK_DCAP_FAIL,
    ERR_FILE_OPERATE_FAILED,
    ERR_DATABASE_OPERATE_FAILED,
    ERR_SIZE_NOT_EQUAL,
    ERR_PERM_REQUEST_CFG_FAILED,
    ERR_USER_POLICY_INITIALIZED,
    ERR_USER_POLICY_NOT_INITIALIZED,
    ERR_LOAD_SO_FAILED,
    ERR_REMOTE_CONNECTION,
    ERR_ADD_DEATH_RECIPIENT_FAILED,
    ERR_PRASE_RAW_DATA_FAILED,
    ERR_PERMISSION_WITHOUT_VALUE,
    ERR_PERMISSION_RESTRICTED,
    ERR_EXPECTED_PERMISSION_TYPE,
    ERR_UTIL_OPER_FAILED,
    ERR_RESOURCE_IS_NOT_READY,
    ERR_CREATE_KEY_FAILED,
    ERR_SESSION_NOT_EXIST,
    ERR_HAP_SIGN_VERIFY_FAILED,
    ERR_CHECK_MULTIPLE_HAP_FAILED,
    ERR_BUILD_POLICY_FAILED,
    ERR_BUNDLE_ALREADY_EXIST,
    ERR_CHECK_ACL_OR_EDM_FAILED,
    ERR_ALREADY_PREPARE,
    ERR_UID_CREATE_FAILED,
    ERR_KERNEL_OPERATION_FAILED,
    ERR_ALREADY_FINISH_INSTALL,
    ERR_BUNDLE_NOT_EXIST,
    ERR_UID_NOT_EXIST,
    ERR_NOT_CHECK_PERMISSION,
    ERR_HAP_PROVISION_INVALID,

    ERR_MIGRATION_COMPLETED,
    ERR_MIGRATION_UID_DUPLICATED,
    ERR_MIGRATION_UID_EXISTED,
    ERR_TOKEN_ACTIVE,
    ERR_INVALID_UID,
    ERR_PERMISSION_REQUEST_TOGGLE_SUBPROFILE_NOT_EXIST,
    ERR_PERMISSION_REQUEST_TOGGLE_STORAGE_MODE_CONFLICT,

    // user policy error
    ERR_PERM_POLICY_ALREADY_SET_BY_OTHER = 12100100,
    ERR_PERM_POLICY_NOT_SET,
    ERR_TOKENID_ALREADY_IN_POLICY_WHITELIST,
    ERR_TOKENID_NOT_IN_POLICY_WHITELIST,
    ERR_TOKENID_NOT_IN_POLICY_USERLIST,
    ERR_PERM_POLICY_PERSISTENCE_FLAG_NOT_MATCH,
    // claw error
    ERR_TOOL_TOKEN_ALREADY_EXIST = 12100200,
    ERR_NOT_LOGGED_IN = 12100201,
    ERR_NETWORK_DISCONNECTED = 12100202,
    ERR_QUERY_PERMISSION_FAILED = 12100203,

    // kernel error
    ERR_KERNEL_COMMON_FAILED = 12100300,
    ERR_IOCTL_UNSUPPORT = 12100301,
    ERR_DATA_CONFLICT_WITH_KERNEL = 12100302,
    ERR_NO_DATA_FROM_KERNEL = 12100303,

    ERR_VERIFY_CANT_OPEN = 12100400,
    ERR_VERIFY_FILE_NOT_EXIST = 12100401,

    ERR_CAPABILITY_NOT_SUPPORT = 12110000
};
} // namespace AccessToken
} // namespace Security
} // namespace OHOS

#endif  // ACCESS_TOKEN_ERROR_H
