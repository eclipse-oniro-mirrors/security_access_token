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

#ifndef ACCESSTOKEN_DFX_DEFINE_H
#define ACCESSTOKEN_DFX_DEFINE_H

#include "hisysevent.h"

namespace OHOS {
namespace Security {
namespace AccessToken {
enum AccessTokenDfxCode {
    VERIFY_TOKEN_ID_ERROR = 101,            // token id is error when verifying permission
    VERIFY_PERMISSION_ERROR,                // verify permission fail
    LOAD_DATABASE_ERROR,                    // load access token info from database error
    TOKEN_SYNC_CALL_ERROR,                  // token sync send request error
    TOKEN_SYNC_RESPONSE_ERROR,              // remote device response error
    PERMISSION_STORE_ERROR,                 // permission grant status write to database error

    ACCESS_TOKEN_SERVICE_INIT_EVENT = 201,  // access token service init event
    USER_GRANT_PERMISSION_EVENT,            // user grant permission event
    BACKGROUND_CALL_EVENT,                  // background call (e.g location or camera) event
};
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

typedef enum DeleteHapSceneCode {
    AT_DELETE_KEEP_TOKEN_FINISH = 2,
} DeleteHapSceneCode;

typedef enum AccessTokenDbSceneCode {
    AT_DB_INSERT_RESTORE = 1001,
    AT_DB_DELETE_RESTORE = 1002,
    AT_DB_UPDATE_RESTORE = 1003,
    AT_DB_QUERY_RESTORE = 1004,
    AT_DB_COMMIT_RESTORE = 1005,
} AccessTokenDbSceneCode;
} // namespace AccessToken
} // namespace Security
} // namespace OHOS
#endif // ACCESSTOKEN_DFX_DEFINE_H
