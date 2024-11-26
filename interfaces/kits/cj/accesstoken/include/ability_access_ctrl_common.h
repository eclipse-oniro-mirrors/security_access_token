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

#ifndef OHOS_ABILITY_ACCESS_CTRL_COMMON_H
#define OHOS_ABILITY_ACCESS_CTRL_COMMON_H

#include <cstdint>
#include <cstring>

namespace OHOS {
namespace CJSystemapi {

const std::string RESULT_ERROR_KEY = "ohos.user.setting.error_code";
const std::string EXTENSION_TYPE_KEY = "ability.want.params.uiExtensionType";
const std::string UI_EXTENSION_TYPE = "sys/commonUI";

typedef enum {
    CJ_OK = 0,
    CJ_ERROR_PERMISSION_DENIED = 201,
    CJ_ERROR_NOT_SYSTEM_APP = 202,
    CJ_ERROR_PARAM_ILLEGAL = 401,
    CJ_ERROR_SYSTEM_CAPABILITY_NOT_SUPPORT = 801,
    CJ_ERROR_PARAM_INVALID = 12100001,
    CJ_ERROR_TOKENID_NOT_EXIST,
    CJ_ERROR_PERMISSION_NOT_EXIST,
    CJ_ERROR_NOT_USE_TOGETHER,
    CJ_ERROR_REGISTERS_EXCEED_LIMITATION,
    CJ_ERROR_PERMISSION_OPERATION_NOT_ALLOWED,
    CJ_ERROR_SERVICE_NOT_RUNNING,
    CJ_ERROR_OUT_OF_MEMORY,
    CJ_ERROR_INNER,
    CJ_ERROR_REQUEST_IS_ALREADY_EXIST,
    CJ_ERROR_ALL_PERM_GRANTED,
    CJ_ERROR_PERM_REVOKE_BY_USER,
    CJ_ERROR_GLOBAL_SWITCH_IS_ALREADY_OPEN,
} CjErrorCode;
}
}
#endif // OHOS_ABILITY_ACCESS_CTRL_COMMON_H