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

#ifndef  INTERFACES_PRIVACY_KITS_NAPI_ERROR_H
#define  INTERFACES_PRIVACY_KITS_NAPI_ERROR_H
#include "string"
#include "access_token.h"
#include "napi/native_api.h"
#include "napi/native_node_api.h"

namespace OHOS {
namespace Security {
namespace AccessToken {
typedef enum {
    JS_OK = 0,
    JS_ERROR_PERMISSION_DENIED = 201,
    JS_ERROR_NOT_SYSTEM_APP = 202,
    JS_ERROR_PARAM_ILLEGAL = 401,
    JS_ERROR_SYSTEM_CAPABILITY_NOT_SUPPORT = 801,
    JS_ERROR_START_ABILITY_FAIL = 1011,
    JS_ERROR_BACKGROUND_FAIL = 1012,
    JS_ERROR_TERMINATE_FAIL = 1013,
    JS_ERROR_PARAM_INVALID = 12100001,
    JS_ERROR_TOKENID_NOT_EXIST,
    JS_ERROR_PERMISSION_NOT_EXIST,
    JS_ERROR_NOT_USE_TOGETHER,
    JS_ERROR_REGISTERS_EXCEED_LIMITATION,
    JS_ERROR_PERMISSION_OPERATION_NOT_ALLOWED,
    JS_ERROR_SERVICE_NOT_RUNNING,
    JS_ERROR_OUT_OF_MEMORY,
    JS_ERROR_INNER,
    JS_ERROR_REQUEST_IS_ALREADY_EXIST = 12100010,
    JS_ERROR_ALL_PERM_GRANTED = 12100011,
    JS_ERROR_PERM_REVOKE_BY_USER = 12100012,
    JS_ERROR_GLOBAL_SWITCH_IS_ALREADY_OPEN = 12100013,
} JsErrorCode;

std::string GetParamErrorMsg(const std::string& param, const std::string& type);
napi_value GenerateBusinessError(napi_env env, int32_t errCode, const std::string& errMsg);
std::string GetErrorMessage(uint32_t errCode);
napi_value GetNapiNull(napi_env env);
}  // namespace AccessToken
}  // namespace Security
}  // namespace OHOS
#endif /* INTERFACES_PRIVACY_KITS_NAPI_ERROR_H */

