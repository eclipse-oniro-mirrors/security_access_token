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
#include "screen_lock_file_manager.h"

#include <iostream>
#include <unordered_map>

#include "ani_error.h"
#include "ani_utils.h"
#include "data_lock_type.h"
#include "el5_filekey_manager_kit.h"
#include "el5_filekey_manager_error.h"
#include "el5_filekey_manager_log.h"

namespace OHOS {
namespace Security {
namespace AccessToken {
namespace {
const std::unordered_map<uint32_t, std::string> EL5ErrMsgMap {
    {EFM_ERR_NO_PERMISSION, "Permission denied."},
    {EFM_ERR_NOT_SYSTEM_APP, "Not system app."},
    {EFM_ERR_INVALID_PARAMETER, "Parameter error."},
    {EFM_ERR_SYSTEMCAP_NOT_SUPPORT, "The specified SystemCapability name was not found."},
    {EFM_ERR_INVALID_DATATYPE, "Invalid DataType."},
    {EFM_ERR_REMOTE_CONNECTION, "The system ability work abnormally."},
    {EFM_ERR_FIND_ACCESS_FAILED, "The application is not enabled the data protection under lock screen."},
    {EFM_ERR_ACCESS_RELEASED, "File access is denied."},
    {EFM_ERR_RELEASE_ACCESS_FAILED, "File access was not acquired."},
};
}

std::string GetErrorMessage(uint32_t errCode, const std::string& extendMsg)
{
    auto iter = EL5ErrMsgMap.find(errCode);
    if (iter != EL5ErrMsgMap.end()) {
        return iter->second + (extendMsg.empty() ? "" : (" " + extendMsg));
    }
    std::string errMsg = "Unknown error, errCode " + std::to_string(errCode) + ".";
    return errMsg;
}

bool CheckDataType(ani_env* env, int32_t dataLockType)
{
    if ((static_cast<DataLockType>(dataLockType) != DataLockType::MEDIA_DATA) &&
        (static_cast<DataLockType>(dataLockType) != DataLockType::ALL_DATA)) {
        BusinessErrorAni::ThrowError(
            env, EFM_ERR_INVALID_DATATYPE, GetErrorMessage(EFM_ERR_INVALID_DATATYPE));
        return false;
    }
    return true;
}

static ani_int AcquireAccessSync([[maybe_unused]] ani_env* env)
{
    int32_t flag = AccessStatus::ACCESS_DENIED;
    if (env == nullptr) {
        LOG_ERROR("Env null");
        return flag;
    }

    int32_t dataLockType = static_cast<int32_t>(DataLockType::DEFAULT_DATA);
    auto retCode = El5FilekeyManagerKit::AcquireAccess(static_cast<DataLockType>(dataLockType));
    if (retCode != EFM_SUCCESS) {
        BusinessErrorAni::ThrowError(env, retCode, GetErrorMessage(retCode));
        return flag;
    } else {
        return static_cast<ani_int>(retCode);
    }
}

static ani_int AcquireAccessExecute([[maybe_unused]] ani_env* env, ani_int datatype)
{
    int32_t flag = AccessStatus::ACCESS_DENIED;
    if (env == nullptr) {
        LOG_ERROR("Env null");
        return flag;
    }

    int32_t dataLockType = static_cast<int32_t>(datatype);
    if (!CheckDataType(env, dataLockType)) {
        LOG_ERROR("Invalid DataType.");
        return flag;
    }

    auto retCode = El5FilekeyManagerKit::AcquireAccess(static_cast<DataLockType>(dataLockType));
    if (retCode != EFM_SUCCESS) {
        BusinessErrorAni::ThrowError(env, retCode, GetErrorMessage(retCode));
        return flag;
    } else {
        return static_cast<ani_int>(retCode);
    }
}

static ani_int ReleaseAccessSync([[maybe_unused]] ani_env* env)
{
    int32_t flag = ReleaseStatus::RELEASE_DENIED;
    if (env == nullptr) {
        LOG_ERROR("Env null");
        return flag;
    }

    int32_t dataLockType = static_cast<int32_t>(DataLockType::DEFAULT_DATA);
    auto retCode = El5FilekeyManagerKit::ReleaseAccess(static_cast<DataLockType>(dataLockType));
    if (retCode != EFM_SUCCESS) {
        BusinessErrorAni::ThrowError(env, retCode, GetErrorMessage(retCode));
        return flag;
    } else {
        return static_cast<ani_int>(retCode);
    }
}

static ani_int ReleaseAccessExecute([[maybe_unused]] ani_env* env, ani_int datatype)
{
    int32_t flag = ReleaseStatus::RELEASE_DENIED;
    if (env == nullptr) {
        LOG_ERROR("Env null");
        return flag;
    }

    int32_t dataLockType = static_cast<int32_t>(datatype);
    if (!CheckDataType(env, dataLockType)) {
        LOG_ERROR("Invalid DataType.");
        return flag;
    }

    auto retCode = El5FilekeyManagerKit::ReleaseAccess(static_cast<DataLockType>(dataLockType));
    if (retCode != EFM_SUCCESS) {
        BusinessErrorAni::ThrowError(env, retCode, GetErrorMessage(retCode));
        return flag;
    } else {
        return static_cast<ani_int>(retCode);
    }
}

static ani_int QueryAppKeyStateSync([[maybe_unused]] ani_env* env)
{
    int32_t flag = KeyStatus::KEY_RELEASED;
    if (env == nullptr) {
        LOG_ERROR("Env null");
        return flag;
    }

    int32_t dataLockType = static_cast<int32_t>(DataLockType::DEFAULT_DATA);
    auto retCode = El5FilekeyManagerKit::QueryAppKeyState(static_cast<DataLockType>(dataLockType));
    switch (retCode) {
        case EFM_SUCCESS:
            retCode = KEY_EXIST;
            break;
        case EFM_ERR_ACCESS_RELEASED:
            retCode = KEY_RELEASED;
            break;
        case EFM_ERR_FIND_ACCESS_FAILED:
            retCode = KEY_NOT_EXIST;
            break;
        default:
            BusinessErrorAni::ThrowError(env, retCode, GetErrorMessage(retCode));
            retCode = KEY_RELEASED;
            break;
    }
    return static_cast<ani_int>(retCode);
}

static ani_int QueryAppKeyStateExecute([[maybe_unused]] ani_env* env, ani_int datatype)
{
    int32_t flag = KEY_RELEASED;
    if (env == nullptr) {
        LOG_ERROR("Env null");
        return flag;
    }

    int32_t dataLockType = static_cast<int32_t>(datatype);
    if (!CheckDataType(env, dataLockType)) {
        LOG_ERROR("Invalid DataType.");
        return flag;
    }

    auto retCode = El5FilekeyManagerKit::QueryAppKeyState(static_cast<DataLockType>(dataLockType));
    switch (retCode) {
        case EFM_SUCCESS:
            retCode = KEY_EXIST;
            break;
        case EFM_ERR_ACCESS_RELEASED:
            retCode = KEY_RELEASED;
            break;
        case EFM_ERR_FIND_ACCESS_FAILED:
            retCode = KEY_NOT_EXIST;
            break;
        default:
            BusinessErrorAni::ThrowError(env, retCode, GetErrorMessage(retCode));
            retCode = KEY_RELEASED;
            break;
    }
    return static_cast<ani_int>(retCode);
}

extern "C" {
ANI_EXPORT ani_status ANI_Constructor(ani_vm* vm, uint32_t* result)
{
    LOG_INFO("ANI_Constructor begin");
    if (vm == nullptr || result == nullptr) {
        LOG_ERROR("nullptr vm or result");
        return ANI_INVALID_ARGS;
    }
    ani_env* env;
    if (ANI_OK != vm->GetEnv(ANI_VERSION_1, &env)) {
        LOG_ERROR("Unsupported ANI_VERSION_1");
        return ANI_OUT_OF_MEMORY;
    }

    if (env == nullptr) {
        LOG_ERROR("nullptr env");
        return ANI_NOT_FOUND;
    }

    if (env->ResetError() != ANI_OK) {
        LOG_ERROR("ResetError failed.");
    }

    ani_namespace ns;
    if (ANI_OK != env->FindNamespace("@ohos.ability.screenLockFileManager.screenLockFileManager", &ns)) {
        LOG_ERROR("FindNamespace screenLockFileManager failed.");
        return ANI_NOT_FOUND;
    }

    // namespace method input param without ani_object
    std::array nsMethods = {
        ani_native_function {"acquireAccessSync", nullptr, reinterpret_cast<void*>(AcquireAccessSync)},
        ani_native_function {"acquireAccessExecute", nullptr, reinterpret_cast<void*>(AcquireAccessExecute)},
        ani_native_function {"releaseAccessSync", nullptr, reinterpret_cast<void*>(ReleaseAccessSync)},
        ani_native_function {"releaseAccessExecute", nullptr, reinterpret_cast<void*>(ReleaseAccessExecute)},
        ani_native_function {"queryAppKeyStateSync", nullptr, reinterpret_cast<void*>(QueryAppKeyStateSync)},
        ani_native_function {"queryAppKeyStateExecute", nullptr, reinterpret_cast<void*>(QueryAppKeyStateExecute)},
    };
    ani_status status = env->Namespace_BindNativeFunctions(ns, nsMethods.data(), nsMethods.size());
    if (status != ANI_OK) {
        LOG_ERROR("Namespace_BindNativeFunctions failed status : %{public}d.", status);
    }
    if (env->ResetError() != ANI_OK) {
        LOG_ERROR("ResetError failed.");
    }

    *result = ANI_VERSION_1;
    return ANI_OK;
}
}
}  // namespace AccessToken
}  // namespace Security
}  // namespace OHOS
