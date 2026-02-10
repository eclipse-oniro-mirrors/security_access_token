/*
 * Copyright (c) 2025-2026 Huawei Device Co., Ltd.
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

#ifndef NATIVE_TOKEN_HISYSEVENT_H
#define NATIVE_TOKEN_HISYSEVENT_H

#include <stdint.h>

#ifdef __cplusplus
extern "C" {
#endif

#define ACCESS_TOKEND_DOMAIN "ACCESS_TOKEN"
#define EVENT_NATIVE_TOKEN_EXCEPTION "ACCESSTOKEN_EXCEPTION"
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

void ReportNativeTokenExceptionEvent(int32_t sceneCode, int32_t errorCode, const char* errorMsg);

#ifdef __cplusplus
}
#endif
#endif // NATIVE_TOKEN_HISYSEVENT_H
