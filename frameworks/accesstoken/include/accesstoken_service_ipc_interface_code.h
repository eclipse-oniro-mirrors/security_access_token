/*
 * Copyright (c) 2023-2024 Huawei Device Co., Ltd.
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

#ifndef ACCESSTOKEN_SERVICE_IPC_INTERFACE_CODE_H
#define ACCESSTOKEN_SERVICE_IPC_INTERFACE_CODE_H

namespace OHOS {
namespace Security {
namespace AccessToken {
/* SAID:3503 */
enum class AccessTokenInterfaceCode {
    VERIFY_ACCESSTOKEN = 0x0000,
    GET_DEF_PERMISSION,
    GET_DEF_PERMISSIONS,
    GET_REQ_PERMISSIONS,
    GET_PERMISSION_FLAG,
    GRANT_PERMISSION,
    REVOKE_PERMISSION,
    CLEAR_USER_GRANT_PERMISSION,
    ALLOC_TOKEN_HAP,
    TOKEN_DELETE,
    INIT_TOKEN_HAP,
    SET_PERMISSION_REQUEST_TOGGLE_STATUS,
    GET_PERMISSION_REQUEST_TOGGLE_STATUS,

    GET_TOKEN_TYPE = 0x0010,
    CHECK_NATIVE_DCAP,
    GET_HAP_TOKEN_ID,
    ALLOC_LOCAL_TOKEN_ID,
    GET_NATIVE_TOKENINFO,
    GET_HAP_TOKENINFO,
    UPDATE_HAP_TOKEN,

    GET_HAP_TOKEN_FROM_REMOTE = 0x0020,
    GET_ALL_NATIVE_TOKEN_FROM_REMOTE,
    SET_REMOTE_HAP_TOKEN_INFO,
    SET_REMOTE_NATIVE_TOKEN_INFO,
    DELETE_REMOTE_TOKEN_INFO,
    DELETE_REMOTE_DEVICE_TOKEN,
    GET_NATIVE_REMOTE_TOKEN,
    REGISTER_TOKEN_SYNC_CALLBACK,
    UNREGISTER_TOKEN_SYNC_CALLBACK,

    DUMP_TOKENINFO = 0x0030,
    GET_PERMISSION_OPER_STATE,
    GET_PERMISSIONS_STATUS,
    REGISTER_PERM_STATE_CHANGE_CALLBACK,
    UNREGISTER_PERM_STATE_CHANGE_CALLBACK,
    RELOAD_NATIVE_TOKEN_INFO,
    GET_NATIVE_TOKEN_ID,
    SET_PERM_DIALOG_CAPABILITY,
    GET_USER_GRANTED_PERMISSION_USED_TYPE,
    DUMP_PERM_DEFINITION_INFO,
    GET_VERSION,
};
} // namespace AccessToken
} // namespace Security
} // namespace OHOS

#endif // ACCESSTOKEN_SERVICE_IPC_INTERFACE_CODE_H
