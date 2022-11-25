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
#include "napi_error.h"
#include <map>

namespace OHOS {
namespace Security {
namespace AccessToken {
static const std::map<uint32_t, std::string> g_errorStringMap = {
    {JS_ERROR_PERMISSION_DENIED, "Permission denied."},
    {JS_ERROR_SYSTEM_CAPABILITY_NOT_SUPPORT, "Not support system capability."},
    {JS_ERROR_PARAM_INVALID, "The parameter is invalid."},
    {JS_ERROR_TOKENID_NOT_EXIST, "The specified token id does not exist."},
    {JS_ERROR_PERMISSION_NOT_EXIST, "The specified permission does not exist."},
    {JS_ERROR_NOT_USE_TOGETHER, "The listener is not used together."},
    {JS_ERROR_REGISTERS_EXCEED_LIMITATION, "The number of registered listeners exceeds limitation."},
    {JS_ERROR_PERMISSION_OPERATION_NOT_ALLOWED, "The operation of specified permission is not allowed."},
    {JS_ERROR_SERVICE_NOT_RUNNING, "The service not running."},
    {JS_ERROR_OUT_OF_MEMORY, "Out of memory."},
    {JS_ERROR_INNER, "Common inner error."},
};

std::string GetParamErrorMsg(const std::string& param, const std::string& type)
{
    std::string msg = "Parameter Error. The type of \"" + param + "\" must be " + type + ".";
    return msg;
}

std::string GetErrorMessage(uint32_t errCode)
{
    auto iter = g_errorStringMap.find(errCode);
    if (iter != g_errorStringMap.end()) {
        return iter->second;
    }
    std::string errMsg = "Unknown error, errCode + " + std::to_string(errCode) + ".";
    return errMsg;
}

napi_value GenerateBusinessError(napi_env env, int32_t errCode, const std::string& errMsg)
{
    napi_value businessError = nullptr;

    napi_value code = nullptr;
    NAPI_CALL(env, napi_create_uint32(env, errCode, &code));

    napi_value msg = nullptr;
    NAPI_CALL(env, napi_create_string_utf8(env, errMsg.c_str(), NAPI_AUTO_LENGTH, &msg));

    NAPI_CALL(env, napi_create_error(env, nullptr, msg, &businessError));
    NAPI_CALL(env, napi_set_named_property(env, businessError, "code", code));
    NAPI_CALL(env, napi_set_named_property(env, businessError, "message", msg));

    return businessError;
}

napi_value GetNapiNull(napi_env env)
{
    napi_value result = nullptr;
    NAPI_CALL(env, napi_get_null(env, &result));
    return result;
}
}  // namespace AccessToken
}  // namespace Security
}  // namespace OHOS
