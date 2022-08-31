/*
 * Copyright (c) 2022 Huawei Device Co., Ltd.
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
} // namespace AccessToken
} // namespace Security
} // namespace OHOS
#endif // ACCESSTOKEN_DFX_DEFINE_H
