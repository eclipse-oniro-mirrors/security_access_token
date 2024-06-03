/*
 * Copyright (c) 2022-2024 Huawei Device Co., Ltd.
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
 * @brief Provides sensitive data access management.
 *
 * @since 8.0
 * @version 8.0
 */

/**
 * @file privacy_error.h
 *
 * @brief Declares error codes.
 *
 * @since 8.0
 * @version 8.0
 */

#ifndef INTERFACES_INNERKITS_PRIVACY_ERROR_H
#define INTERFACES_INNERKITS_PRIVACY_ERROR_H
namespace OHOS {
namespace Security {
namespace AccessToken {
/**
 * @brief Error code values
 */
enum PrivacyError {
    ERR_PERMISSION_DENIED = 201,
    ERR_NOT_SYSTEM_APP = 202,
    ERR_PARAM_INVALID = 13100001,
    ERR_TOKENID_NOT_EXIST,
    ERR_PERMISSION_NOT_EXIST,
    ERR_CALLBACKS_EXCEED_LIMITATION,
    ERR_IDENTITY_CHECK_FAILED,
    ERR_SERVICE_ABNORMAL,
    ERR_MALLOC_FAILED,
    ERR_OVERSIZE,
    ERROR_IPC_REQUEST_FAIL,
    ERR_READ_PARCEL_FAILED,
    ERR_WRITE_PARCEL_FAILED,
    ERR_CALLBACK_ALREADY_EXIST,
    ERR_CALLBACK_NOT_EXIST,
    ERR_PERMISSION_ALREADY_START_USING,
    ERR_PERMISSION_NOT_START_USING,
    ERR_FILE_OPERATE_FAILED,
    ERR_WINDOW_CALLBACK_FAILED,
    ERR_EDM_POLICY_CHECK_FAILED,
    ERR_PRIVACY_POLICY_CHECK_FAILED,
};
} // namespace AccessToken
} // namespace Security
} // namespace OHOS
#endif
