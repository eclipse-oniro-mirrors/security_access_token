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
    ERR_LOAD_SO_FAILED,
};
} // namespace AccessToken
} // namespace Security
} // namespace OHOS

#endif  // ACCESS_TOKEN_ERROR_H