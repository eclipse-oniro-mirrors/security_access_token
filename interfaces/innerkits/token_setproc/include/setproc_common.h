/*
 * Copyright (c) 2023 Huawei Device Co., Ltd.
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

#ifndef SETPROC_COMMON_H
#define SETPROC_COMMON_H
#ifdef __cplusplus
extern "C" {
#endif

#define ACCESS_TOKEN_OK 0
#define ACCESS_TOKEN_PARAM_INVALID (-1)
#define ACCESS_TOKEN_OPEN_ERROR (-2)
#define ACCESS_TOKEN_ID_IOCTL_BASE 'A'
#define TOKENID_DEVNODE "/dev/access_token_id"

#define SPM_DATA_BATCH_SIZE 50
#define MAX_PERM_BIT_MAP_SIZE 64
#define UINT32_T_BITS 32

enum {
    GET_TOKEN_ID = 1,
    SET_TOKEN_ID,
    GET_FTOKEN_ID,
    SET_FTOKEN_ID,
    ADD_PERMISSIONS,
    REMOVE_PERMISSIONS,
    GET_PERMISSION,
    SET_PERMISSION,
    GET_ALL_PERMISSIONS = 11,
    ADD_SPM_ENTRIES = 16,
    SET_SPM_ENTRIES = 17,
    GET_SPM_ENTRY = 18,
    REMOVE_SPM_ENTRY = 19,
    SET_REFCNT_UID = 20,
    GET_REFCNT_UID = 21,
    SET_REFCNT_TOKENID = 22,
    GET_REFCNT_TOKENID = 23,
    CLEAR_REFCNT_SPAWNID = 24,
    GET_SPM_VERSION = 25,
    ACCESS_TOKENID_MAX_NR,
};
#ifdef __cplusplus
}
#endif
#endif // SETPROC_COMMON_H
