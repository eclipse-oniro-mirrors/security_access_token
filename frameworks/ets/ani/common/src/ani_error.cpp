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
#include "ani_error.h"

#include <unordered_map>

#include "access_token_error.h"
#include "accesstoken_log.h"
#include "data_validator.h"

namespace OHOS {
namespace Security {
namespace AccessToken {
namespace {
static constexpr OHOS::HiviewDFX::HiLogLabel LABEL = { LOG_CORE, SECURITY_DOMAIN_PRIVACY, "CommonAni" };
} // namespace
constexpr const char* BUSINESS_ERROR_CLASS = "@ohos.base.BusinessError";
static const std::unordered_map<uint32_t, const char*> g_errorStringMap = {
    { STS_ERROR_PERMISSION_DENIED, "Permission denied." },
    { STS_ERROR_NOT_SYSTEM_APP, "Not system app." },
    { STS_ERROR_SYSTEM_CAPABILITY_NOT_SUPPORT, "Not support system capability." },
    { STS_ERROR_START_ABILITY_FAIL, "Start grant ability failed." },
    { STS_ERROR_BACKGROUND_FAIL, "UI extension turn background failed." },
    { STS_ERROR_TERMINATE_FAIL, "UI extension terminate failed." },
    { STS_ERROR_PARAM_INVALID, "Invalid parameter." },
    { STS_ERROR_TOKENID_NOT_EXIST, "The specified token id does not exist." },
    { STS_ERROR_PERMISSION_NOT_EXIST, "The specified permission does not exist." },
    { STS_ERROR_NOT_USE_TOGETHER, "The API is not used in pair with others." },
    { STS_ERROR_REGISTERS_EXCEED_LIMITATION, "The number of registered listeners exceeds limitation." },
    { STS_ERROR_PERMISSION_OPERATION_NOT_ALLOWED, "The operation of specified permission is not allowed." },
    { STS_ERROR_SERVICE_NOT_RUNNING, "The service is abnormal." },
    { STS_ERROR_OUT_OF_MEMORY, "Out of memory." },
    { STS_ERROR_INNER, "Common inner error." },
    { STS_ERROR_REQUEST_IS_ALREADY_EXIST, "The request already exists." },
    { STS_ERROR_ALL_PERM_GRANTED, "All permissions in the permission list have been granted." },
    { STS_ERROR_PERM_NOT_REVOKE_BY_USER,
        "The permission list contains the permission that has not been revoked by the user." },
    { STS_ERROR_GLOBAL_SWITCH_IS_ALREADY_OPEN, "The specific global switch is already open." },
};

void BusinessErrorAni::ThrowError(ani_env* env, int32_t err, const std::string& errMsg)
{
    if (env == nullptr) {
        return;
    }
    ani_object error = CreateError(env, err, errMsg);
    ThrowError(env, error);
}

ani_object BusinessErrorAni::CreateError(ani_env* env, ani_int code, const std::string& msg)
{
    if (env == nullptr) {
        ACCESSTOKEN_LOG_ERROR(LABEL, "env is nullptr");
        return nullptr;
    }
    ani_class cls = nullptr;
    ani_field field = nullptr;
    ani_method method = nullptr;
    ani_object obj = nullptr;

    ani_status status = env->FindClass(BUSINESS_ERROR_CLASS, &cls);
    if (status != ANI_OK) {
        ACCESSTOKEN_LOG_ERROR(LABEL, "FindClass : %{public}d", status);
        return nullptr;
    }
    status = env->Class_FindMethod(cls, "<ctor>", ":", &method);
    if (status != ANI_OK) {
        ACCESSTOKEN_LOG_ERROR(LABEL, "Class_FindMethod : %{public}d", status);
        return nullptr;
    }
    status = env->Object_New(cls, method, &obj);
    if (status != ANI_OK) {
        ACCESSTOKEN_LOG_ERROR(LABEL, "Object_New : %{public}d", status);
        return nullptr;
    }
    status = env->Class_FindField(cls, "code", &field);
    if (status != ANI_OK) {
        ACCESSTOKEN_LOG_ERROR(LABEL, "Class_FindField : %{public}d", status);
        return nullptr;
    }
    status = env->Object_SetField_Int(obj, field, code);
    if (status != ANI_OK) {
        ACCESSTOKEN_LOG_ERROR(LABEL, "Object_SetField_Int : %{public}d", status);
        return nullptr;
    }
    status = env->Class_FindField(cls, "data", &field);
    if (status != ANI_OK) {
        ACCESSTOKEN_LOG_ERROR(LABEL, "Class_FindField : %{public}d", status);
        return nullptr;
    }
    ani_string string = nullptr;
    env->String_NewUTF8(msg.c_str(), msg.size(), &string);
    status = env->Object_SetField_Ref(obj, field, static_cast<ani_ref>(string));
    if (status != ANI_OK) {
        ACCESSTOKEN_LOG_ERROR(LABEL, "Object_SetField_Ref : %{public}d", status);
        return nullptr;
    }
    return obj;
}

std::string GetParamErrorMsg(const std::string& param, const std::string& errMsg)
{
    std::string msg = "Parameter Error. The type of \"" + param + "\" must be " + errMsg + ".";
    return msg;
}

std::string GetErrorMessage(int32_t errCode, const std::string& extendMsg)
{
    auto iter = g_errorStringMap.find(errCode);
    if (iter != g_errorStringMap.end()) {
        return iter->second + (extendMsg.empty() ? "" : ("" + extendMsg));
    }
    std::string errMsg = "Unknown error, errCode " + std::to_string(errCode) + ".";
    return errMsg;
}

void BusinessErrorAni::ThrowParameterTypeError(ani_env* env, int32_t err, const std::string& errMsg)
{
    if (env == nullptr) {
        return;
    }
    ani_object error = CreateError(env, err, errMsg);
    ThrowError(env, error);
}

void BusinessErrorAni::ThrowError(ani_env* env, ani_object err)
{
    if (err == nullptr) {
        ACCESSTOKEN_LOG_ERROR(LABEL, "err is nullptr");
        return;
    }
    env->ThrowError(static_cast<ani_error>(err));
}

int32_t BusinessErrorAni::GetStsErrorCode(int32_t errCode)
{
    int32_t stsCode;
    switch (errCode) {
        case RET_SUCCESS:
            stsCode = STS_OK;
            break;
        case ERR_PERMISSION_DENIED:
            stsCode = STS_ERROR_PERMISSION_DENIED;
            break;
        case ERR_NOT_SYSTEM_APP:
            stsCode = STS_ERROR_NOT_SYSTEM_APP;
            break;
        case ERR_PARAM_INVALID:
            stsCode = STS_ERROR_PARAM_INVALID;
            break;
        case ERR_TOKENID_NOT_EXIST:
            stsCode = STS_ERROR_TOKENID_NOT_EXIST;
            break;
        case ERR_PERMISSION_NOT_EXIST:
            stsCode = STS_ERROR_PERMISSION_NOT_EXIST;
            break;
        case ERR_INTERFACE_NOT_USED_TOGETHER:
        case ERR_CALLBACK_ALREADY_EXIST:
            stsCode = STS_ERROR_NOT_USE_TOGETHER;
            break;
        case ERR_CALLBACKS_EXCEED_LIMITATION:
            stsCode = STS_ERROR_REGISTERS_EXCEED_LIMITATION;
            break;
        case ERR_IDENTITY_CHECK_FAILED:
            stsCode = STS_ERROR_PERMISSION_OPERATION_NOT_ALLOWED;
            break;
        case ERR_SERVICE_ABNORMAL:
        case ERROR_IPC_REQUEST_FAIL:
        case ERR_READ_PARCEL_FAILED:
        case ERR_WRITE_PARCEL_FAILED:
            stsCode = STS_ERROR_SERVICE_NOT_RUNNING;
            break;
        case ERR_MALLOC_FAILED:
            stsCode = STS_ERROR_OUT_OF_MEMORY;
            break;
        default:
            stsCode = STS_ERROR_INNER;
            break;
    }
    ACCESSTOKEN_LOG_DEBUG(LABEL, "GetStsErrorCode nativeCode(%{public}d) stsCode(%{public}d).", errCode, stsCode);
    return stsCode;
}

bool BusinessErrorAni::ValidateTokenIDdWithThrowError(ani_env* env, AccessTokenID tokenID)
{
    if (!DataValidator::IsTokenIDValid(tokenID)) {
        std::string errMsg = GetErrorMessage(STS_ERROR_PARAM_INVALID, "The tokenID is 0.");
        BusinessErrorAni::ThrowError(env, STS_ERROR_PARAM_INVALID, errMsg);
        return false;
    }
    return true;
}

bool BusinessErrorAni::ValidatePermissionWithThrowError(ani_env* env, const std::string& permission)
{
    if (!DataValidator::IsPermissionNameValid(permission)) {
        std::string errMsg = GetErrorMessage(
            STS_ERROR_PARAM_INVALID, "The permissionName is empty or exceeds 256 characters.");
        BusinessErrorAni::ThrowError(env, STS_ERROR_PARAM_INVALID, errMsg);
        return false;
    }
    return true;
}

bool BusinessErrorAni::ValidatePermissionFlagWithThrowError(ani_env* env, uint32_t flag)
{
    if (!DataValidator::IsPermissionFlagValid(flag)) {
        std::string errMsg = GetErrorMessage(STS_ERROR_PARAM_INVALID, "The permissionFlags is invalid.");
        BusinessErrorAni::ThrowError(env, STS_ERROR_PARAM_INVALID, errMsg);
        return false;
    }
    return true;
}
} // namespace AccessToken
} // namespace Security
} // namespace OHOS
