/*
 * Copyright (c) 2024 Huawei Device Co., Ltd.
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

#ifndef EL5_FILEKEY_MANAGER_ERROR_H
#define EL5_FILEKEY_MANAGER_ERROR_H

namespace OHOS {
namespace Security {
namespace AccessToken {
enum El5FilekeyManagerErrCode {
    EFM_SUCCESS = 0,
    EFM_ERR_NO_PERMISSION = 201,
    EFM_ERR_NOT_SYSTEM_APP = 202,
    EFM_ERR_INVALID_PARAMETER = 401,
    EFM_ERR_SYSTEMCAP_NOT_SUPPORT = 801,
    EFM_ERR_INVALID_DATATYPE = 29300001,
    EFM_ERR_REMOTE_CONNECTION,
    EFM_ERR_FIND_ACCESS_FAILED,
    EFM_ERR_ACCESS_RELEASED,
    EFM_ERR_RELEASE_ACCESS_FAILED,
    EFM_ERR_IPC_TOKEN_INVALID,
    EFM_ERR_IPC_READ_DATA,
    EFM_ERR_IPC_WRITE_DATA,
    EFM_ERR_SA_GET_PROXY,
    EFM_ERR_CALL_POLICY_FAILED,
    EFM_ERR_CALL_POLICY_ERROR,
    EFM_ERR_DATABASE_FAILED,
    EFM_ERR_OPEN_FILE_FAILED,
    EFM_ERR_IOCTL_FAILED,
    EFM_ERR_KEYID_EXISTED,
    EFM_ERR_GET_GROUP_INFO,
};
}  // namespace AccessToken
}  // namespace Security
}  // namespace OHOS
#endif // EL5_FILEKEY_MANAGER_ERROR_H
