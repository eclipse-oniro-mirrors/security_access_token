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

#ifndef  INTERFACES_PRIVACY_KITS_ANI_ERROR_H
#define  INTERFACES_PRIVACY_KITS_ANI_ERROR_H

#include <ani.h>
#include <string>

namespace OHOS {
namespace Security {
namespace AccessToken {
typedef enum {
    STS_OK = 0,
    STS_ERROR_PERMISSION_DENIED = 201,
    STS_ERROR_NOT_SYSTEM_APP = 202,
    STS_ERROR_PARAM_ILLEGAL = 401,
    STS_ERROR_SYSTEM_CAPABILITY_NOT_SUPPORT = 801,
    STS_ERROR_START_ABILITY_FAIL = 1011,
    STS_ERROR_BACKGROUND_FAIL = 1012,
    STS_ERROR_TERMINATE_FAIL = 1013,
    STS_ERROR_PARAM_INVALID = 12100001,
    STS_ERROR_TOKENID_NOT_EXIST,
    STS_ERROR_PERMISSION_NOT_EXIST,
    STS_ERROR_NOT_USE_TOGETHER,
    STS_ERROR_REGISTERS_EXCEED_LIMITATION,
    STS_ERROR_PERMISSION_OPERATION_NOT_ALLOWED,
    STS_ERROR_SERVICE_NOT_RUNNING,
    STS_ERROR_OUT_OF_MEMORY,
    STS_ERROR_INNER,
    STS_ERROR_REQUEST_IS_ALREADY_EXIST = 12100010,
    STS_ERROR_ALL_PERM_GRANTED = 12100011,
    STS_ERROR_PERM_REVOKE_BY_USER = 12100012,
    STS_ERROR_GLOBAL_SWITCH_IS_ALREADY_OPEN = 12100013,
} STSErrorCode;
std::string GetParamErrorMsg(const std::string& param, const std::string& type);
std::string GetErrorMessage(uint32_t errCode);
class BusinessErrorAni {
public:
    static ani_object CreateError(ani_env* env, ani_int code, const std::string& msg);
    static ani_object CreateCommonError(
        ani_env* env, int32_t err, const std::string& functionName = "", const std::string& permissionName = "");
    static ani_object CreateEnumError(ani_env* env, const std::string& parameter, const std::string& enumClass);
    static void ThrowTooFewParametersError(ani_env* env, int32_t err);
    static void ThrowParameterTypeError(ani_env* env, int32_t err,
        const std::string& parameter, const std::string& type);
    static void ThrowEnumError(ani_env* env, const std::string& parameter, const std::string& type);
    static void ThrowError(ani_env* env, int32_t err, const std::string& msg = "");
    static int32_t GetStsErrorCode(int32_t errCode);
private:
    static void ThrowError(ani_env* env, ani_object err);
};
}  // namespace AccessToken
}  // namespace Security
}  // namespace OHOS
#endif /* INTERFACES_PRIVACY_KITS_ANI_ERROR_H */

