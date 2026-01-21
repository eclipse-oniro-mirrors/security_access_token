/*
 * Copyright (c) 2025 Huawei Device Co., Ltd.
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

#ifndef ACCESSTOKEN_HISYSEVENT_COMMON_H
#define ACCESSTOKEN_HISYSEVENT_COMMON_H


#ifdef __cplusplus
extern "C" {
#endif

typedef enum SceneCode {
    SA_PUBLISH_FAILED,
    EVENTRUNNER_CREATE_ERROR,
    INIT_HAP_TOKENINFO_ERROR,
    INIT_NATIVE_TOKENINFO_ERROR,
    INIT_PERM_DEF_JSON_ERROR,
    TOKENID_NOT_EQUAL,
} SceneCode;

typedef enum UpdatePermStatusErrorCode {
    GRANT_TEMP_PERMISSION_FAILED = 0,
    DLP_CHECK_FAILED = 1,
    UPDATE_PERMISSION_STATUS_FAILED = 2,
} UpdatePermStatusErrorCode;

typedef enum CommonSceneCode {
    AT_COMMON_START = 0,
    AT_COMMON_FINISH = 1,
} CommonSceneCode;

typedef enum AddHapSceneCode {
    INSTALL_START = 0,
    TOKEN_ID_CHANGE,
    INIT,
    MAP,
    INSTALL_FINISH,
} AddHapSceneCode;

typedef enum AccessTokenDbSceneCode {
    AT_DB_INSERT_RESTORE = 1001,
    AT_DB_DELETE_RESTORE = 1002,
    AT_DB_UPDATE_RESTORE = 1003,
    AT_DB_QUERY_RESTORE = 1004,
    AT_DB_COMMIT_RESTORE = 1005,
} AccessTokenDbSceneCode;

typedef enum AccessTokenExceptionSceneCode {
    // 0~0xFFF reserved for ipc code of access token manager

    // 0x1000~0x1FFF reserved for native token
    NATIVE_TOKEN_INIT = 0x1000,
    CHECK_PROCESS_INFO,
    ADD_NODE,
    UPDATE_NODE
} AccessTokenExceptionSceneCode;

typedef enum AccessTokenExceptionErrorCode {
    // 0~1 reserved for ATRET_SUCCESS and ATRET_FAILED
    LOCK_FILE_FAILED = 2,
    MALLOC_FAILED,
    GET_FILE_BUFF_FAILED,
    GET_TOKEN_LIST_FAILED,
    CLEAR_CREATE_FILE_FAILED,
    PROCESS_NAME_INVALID,
    DCAPS_INVALID,
    PERMS_INVALID,
    ACLS_INVALID,
    ACL_GREATER_THAN_PERMS,
    APL_INVALID,
    CREATE_NATIVETOKEN_ID_FAILED,
    STRCPY_FAILED,
    CREATE_ARRAY_FAILED,
    SAVE_CONTENT_TO_CFG_FAILED,
} AccessTokenExceptionErrorCode;

#ifdef __cplusplus
}
#endif

#endif // ACCESSTOKEN_HISYSEVENT_COMMON_H
