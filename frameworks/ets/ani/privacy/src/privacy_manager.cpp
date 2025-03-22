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

#include <iostream>

#include "accesstoken_log.h"
#include "ani.h"
#include "privacy_error.h"
#include "privacy_kit.h"
#include "ani_error.h"

namespace OHOS {
namespace Security {
namespace AccessToken {
static constexpr OHOS::HiviewDFX::HiLogLabel LABEL = { LOG_CORE, SECURITY_DOMAIN_PRIVACY, "AniPrivacyManager" };
constexpr int32_t MAX_LENGTH = 256;

static int AddPermissionUsedRecordSync(
    ani_int tokenID, const std::string &permissionName, ani_int successCount, ani_int failCount, ani_int ntype)
{
    AddPermParamInfo info;
    info.tokenId = tokenID;
    info.permissionName = permissionName;
    info.successCount = successCount;
    info.failCount = failCount;
    info.type = static_cast<PermissionUsedType>(ntype);
    auto retCode = PrivacyKit::AddPermissionUsedRecord(info);
    ACCESSTOKEN_LOG_INFO(LABEL, "call addPermissionUsedRecord retCode : %{public}d", retCode);
    return retCode;
}

static ani_int AddPermissionUsedRecord([[maybe_unused]] ani_env *env, [[maybe_unused]] ani_object object,
    ani_int tokenID, ani_string permissionName, ani_int successCount, ani_int failCount, ani_object options)
{
    if (env == nullptr) {
        ACCESSTOKEN_LOG_ERROR(LABEL, "nullptr env");
        return PrivacyError::ERR_PARAM_INVALID;
    }
    ani_size strSize;
    ani_status status = ANI_ERROR;
    if (ANI_OK != (status = env->String_GetUTF8Size(permissionName, &strSize))) {
        BusinessErrorAni::ThrowParameterTypeError(env, STSErrorCode::STS_ERROR_PARAM_ILLEGAL,
            "AddPermissionUsedRecord", "");
        return STSErrorCode::STS_ERROR_PARAM_ILLEGAL;
    }
    if (strSize > MAX_LENGTH) {
        ACCESSTOKEN_LOG_ERROR(LABEL, "the max lenth : %{public}d", MAX_LENGTH);
        return PrivacyError::ERR_PARAM_INVALID;
    }
    std::vector<char> buffer(strSize + 1);
    char *utf8Buffer = buffer.data();
    ani_size bytesWritten = 0;
    if (ANI_OK != (status = env->String_GetUTF8(permissionName, utf8Buffer, strSize + 1, &bytesWritten))) {
        ACCESSTOKEN_LOG_ERROR(LABEL, "get String_GetUTF8 Faild status : %{public}d", status);
        return PrivacyError::ERR_PARAM_INVALID;
    }
    utf8Buffer[bytesWritten] = '\0';
    std::string outputPermissionName = std::string(utf8Buffer);
    ani_ref usedTypeRef;
    if (ANI_OK != (status = env->Object_GetPropertyByName_Ref(options, "usedType", &usedTypeRef))) {
        ACCESSTOKEN_LOG_ERROR(LABEL, "Object_GetFieldByName_Ref Faild status : %{public}d", status);
        return PrivacyError::ERR_PARAM_INVALID;
    }
    ani_int usedType = 0;
    ani_boolean isUndefined = true;
    if (ANI_OK != (status = env->Reference_IsUndefined(usedTypeRef, &isUndefined))) {
        ACCESSTOKEN_LOG_ERROR(LABEL, "status : %{public}d", status);
        return PrivacyError::ERR_PARAM_INVALID;
    }
    if (!isUndefined) {
        ani_enum_item usedTypeEnum = static_cast<ani_enum_item>(usedTypeRef);
        if (ANI_OK != env->EnumItem_GetValue_Int(usedTypeEnum, &usedType)) {
            ACCESSTOKEN_LOG_ERROR(LABEL, "EnumItem_GetValue_Int Faild");
            return PrivacyError::ERR_PARAM_INVALID;
        }
    }
    ACCESSTOKEN_LOG_INFO(LABEL,"Object_GetFieldByName_Ref tokenID:%{public}d PermissionName:%{public}s \
        successCount:%{public}d failCount:%{public}d usedType:%{public}d",
        tokenID, outputPermissionName.c_str(), successCount, failCount, usedType);
    return AddPermissionUsedRecordSync(tokenID, outputPermissionName, successCount, failCount, usedType);
}

extern "C"{
ANI_EXPORT ani_status ANI_Constructor(ani_vm *vm, uint32_t *result)
{
    if (vm == nullptr || result == nullptr) {
        ACCESSTOKEN_LOG_ERROR(LABEL, "nullptr vm or result");
        return ANI_INVALID_ARGS;
    }
    ani_env *env;
    if (ANI_OK != vm->GetEnv(ANI_VERSION_1, &env)) {
        ACCESSTOKEN_LOG_ERROR(LABEL, "Unsupported ANI_VERSION_1");
        return ANI_OUT_OF_MEMORY;
    }

    if (env == nullptr) {
        ACCESSTOKEN_LOG_ERROR(LABEL, "nullptr env");
        return ANI_NOT_FOUND;
    }

    const char *className = "L@ohos/privacyManager/privacyManager/PrivacyManagerInner;";
    ani_class cls;
    if (ANI_OK != env->FindClass(className, &cls)) {
        ACCESSTOKEN_LOG_ERROR(LABEL, "Not found %{public}s", className);
        return ANI_NOT_FOUND;
    }

    std::array methods = {
        ani_native_function{ "addPermissionUsedRecordSync",
            "ILstd/core/String;IIL@ohos/privacyManager/privacyManager/AddPermissionUsedRecordOptionsInner;:I",
            reinterpret_cast<void *>(AddPermissionUsedRecord) },
    };

    if (ANI_OK != env->Class_BindNativeMethods(cls, methods.data(), methods.size())) {
        ACCESSTOKEN_LOG_ERROR(LABEL, "Cannot bind native methods to %{public}s", className);
        return ANI_ERROR;
    };

    *result = ANI_VERSION_1;
    return ANI_OK;
}
}
} // namespace AccessToken
} // namespace Security
} // namespace OHOS