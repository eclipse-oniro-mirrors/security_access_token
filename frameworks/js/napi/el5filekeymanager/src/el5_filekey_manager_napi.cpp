/*
 * Copyright (c) 2024-2025 Huawei Device Co., Ltd.
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

#include "el5_filekey_manager_napi.h"

#include <unordered_map>

#include "data_lock_type.h"
#include "el5_filekey_manager_error.h"
#include "el5_filekey_manager_kit.h"
#include "el5_filekey_manager_log.h"

namespace OHOS {
namespace Security {
namespace AccessToken {
namespace {
constexpr uint32_t MAX_PARAM_SIZE = 1;
const std::unordered_map<uint32_t, std::string> ErrMsgMap {
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

void ThrowError(napi_env env, int32_t errCode)
{
    napi_value businessError = nullptr;

    napi_value code = nullptr;
    napi_create_int32(env, errCode, &code);

    std::string errMsg = "Unknown error, errCode + " + std::to_string(errCode) + ".";
    auto iter = ErrMsgMap.find(errCode);
    if (iter != ErrMsgMap.end()) {
        errMsg = iter->second;
    }

    napi_value msg = nullptr;
    napi_create_string_utf8(env, errMsg.c_str(), NAPI_AUTO_LENGTH, &msg);

    napi_create_error(env, nullptr, msg, &businessError);
    napi_set_named_property(env, businessError, "code", code);
    napi_set_named_property(env, businessError, "message", msg);

    napi_throw(env, businessError);
}

bool ParseDataType(const napi_env &env, napi_value args, int32_t &dataLockType)
{
    // data-lock-type
    napi_valuetype valuetype = napi_undefined;
    napi_typeof(env, args, &valuetype);
    if (valuetype != napi_number) {
        LOG_ERROR("Parameter type %{public}d error. Number expected.", valuetype);
        ThrowError(env, EFM_ERR_INVALID_PARAMETER);
        return false;
    }
    napi_get_value_int32(env, args, &dataLockType);
    return true;
}

bool CheckDataType(napi_env env, int32_t dataLockType)
{
    if ((static_cast<DataLockType>(dataLockType) != DataLockType::DEFAULT_DATA) &&
        (static_cast<DataLockType>(dataLockType) != DataLockType::MEDIA_DATA) &&
        (static_cast<DataLockType>(dataLockType) != DataLockType::GROUP_ID_DATA) &&
        (static_cast<DataLockType>(dataLockType) != DataLockType::ALL_DATA)) {
        ThrowError(env, EFM_ERR_INVALID_DATATYPE);
        return false;
    }
    return true;
}

napi_value AcquireAccess(napi_env env, napi_callback_info info)
{
    size_t argc = MAX_PARAM_SIZE;
    napi_value argv[MAX_PARAM_SIZE] = { nullptr };
    if (napi_get_cb_info(env, info, &argc, argv, NULL, NULL) != napi_ok) {
        LOG_ERROR("napi_get_cb_info failed.");
        ThrowError(env, EFM_ERR_INVALID_PARAMETER);
        return nullptr;
    }

    int32_t dataLockType = static_cast<int32_t>(DataLockType::DEFAULT_DATA);
    if ((argc == MAX_PARAM_SIZE) && !ParseDataType(env, argv[0], dataLockType)) {
        return nullptr;
    }

    if (!CheckDataType(env, dataLockType)) {
        LOG_ERROR("Invalid DataType.");
        return nullptr;
    }

    int32_t retCode = El5FilekeyManagerKit::AcquireAccess(static_cast<DataLockType>(dataLockType));
    if (retCode != EFM_SUCCESS) {
        ThrowError(env, retCode);
        retCode = ACCESS_DENIED;
    }

    napi_value result = nullptr;
    NAPI_CALL(env, napi_create_int32(env, retCode, &result));
    return result;
}

napi_value ReleaseAccess(napi_env env, napi_callback_info info)
{
    size_t argc = MAX_PARAM_SIZE;
    napi_value argv[MAX_PARAM_SIZE] = { nullptr };
    if (napi_get_cb_info(env, info, &argc, argv, NULL, NULL) != napi_ok) {
        LOG_ERROR("napi_get_cb_info failed.");
        ThrowError(env, EFM_ERR_INVALID_PARAMETER);
        return nullptr;
    }

    int32_t dataLockType = static_cast<int32_t>(DataLockType::DEFAULT_DATA);
    if ((argc == MAX_PARAM_SIZE) && !ParseDataType(env, argv[0], dataLockType)) {
        return nullptr;
    }

    if (!CheckDataType(env, dataLockType)) {
        LOG_ERROR("Invalid DataType.");
        return nullptr;
    }

    int32_t retCode = El5FilekeyManagerKit::ReleaseAccess(static_cast<DataLockType>(dataLockType));
    if (retCode != EFM_SUCCESS) {
        ThrowError(env, retCode);
        retCode = RELEASE_DENIED;
    }

    napi_value result = nullptr;
    NAPI_CALL(env, napi_create_int32(env, retCode, &result));
    return result;
}

napi_value QueryAppKeyState(napi_env env, napi_callback_info info)
{
    size_t argc = MAX_PARAM_SIZE;
    napi_value argv[MAX_PARAM_SIZE] = { nullptr };
    if (napi_get_cb_info(env, info, &argc, argv, NULL, NULL) != napi_ok) {
        LOG_ERROR("napi_get_cb_info failed.");
        ThrowError(env, EFM_ERR_INVALID_PARAMETER);
        return nullptr;
    }

    int32_t dataLockType = static_cast<int32_t>(DataLockType::DEFAULT_DATA);
    if ((argc == MAX_PARAM_SIZE) && !ParseDataType(env, argv[0], dataLockType)) {
        return nullptr;
    }

    if (!CheckDataType(env, dataLockType)) {
        LOG_ERROR("Invalid DataType.");
        return nullptr;
    }

    int32_t retCode = El5FilekeyManagerKit::QueryAppKeyState(static_cast<DataLockType>(dataLockType));
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
            ThrowError(env, retCode);
            retCode = KEY_RELEASED;
            break;
    }

    napi_value result = nullptr;
    NAPI_CALL(env, napi_create_int32(env, retCode, &result));
    return result;
}

static void SetNamedProperty(napi_env env, napi_value dstObj, const int32_t objValue, const char* propName)
{
    napi_value prop = nullptr;
    napi_create_int32(env, objValue, &prop);
    napi_set_named_property(env, dstObj, propName, prop);
}

EXTERN_C_START
/*
 * function for module exports
 */
static napi_value Init(napi_env env, napi_value exports)
{
    napi_property_descriptor properties[] = {
        DECLARE_NAPI_FUNCTION("acquireAccess", AcquireAccess),
        DECLARE_NAPI_FUNCTION("releaseAccess", ReleaseAccess),
        DECLARE_NAPI_FUNCTION("queryAppKeyState", QueryAppKeyState)
    };

    napi_define_properties(env, exports, sizeof(properties) / sizeof(properties[0]), properties);

    napi_value dataType = nullptr;
    napi_create_object(env, &dataType);
    SetNamedProperty(env, dataType, static_cast<int32_t>(DataLockType::MEDIA_DATA), "MEDIA_DATA");
    SetNamedProperty(env, dataType, static_cast<int32_t>(DataLockType::ALL_DATA), "ALL_DATA");

    napi_value accessStatus = nullptr;
    napi_create_object(env, &accessStatus);
    SetNamedProperty(env, accessStatus, ACCESS_GRANTED, "ACCESS_GRANTED");
    SetNamedProperty(env, accessStatus, ACCESS_DENIED, "ACCESS_DENIED");

    napi_value releaseStatus = nullptr;
    napi_create_object(env, &releaseStatus);
    SetNamedProperty(env, releaseStatus, RELEASE_GRANTED, "RELEASE_GRANTED");
    SetNamedProperty(env, releaseStatus, RELEASE_DENIED, "RELEASE_DENIED");

    napi_value keyStatus = nullptr;
    napi_create_object(env, &keyStatus);
    SetNamedProperty(env, keyStatus, KEY_NOT_EXIST, "KEY_NOT_EXIST");
    SetNamedProperty(env, keyStatus, KEY_EXIST, "KEY_EXIST");
    SetNamedProperty(env, keyStatus, KEY_RELEASED, "KEY_RELEASED");

    napi_property_descriptor exportFuncs[] = {
        DECLARE_NAPI_PROPERTY("DataType", dataType),
        DECLARE_NAPI_PROPERTY("AccessStatus", accessStatus),
        DECLARE_NAPI_PROPERTY("ReleaseStatus", releaseStatus),
        DECLARE_NAPI_PROPERTY("KeyStatus", keyStatus),
    };
    napi_define_properties(env, exports, sizeof(exportFuncs) / sizeof(exportFuncs[0]), exportFuncs);

    return exports;
}
EXTERN_C_END

/*
 * Module define
 */
static napi_module g_module = {
    .nm_version = 1,
    .nm_flags = 0,
    .nm_filename = nullptr,
    .nm_register_func = Init,
    .nm_modname = "ability.screenLockFileManager",
    .nm_priv = static_cast<void*>(nullptr),
    .reserved = {nullptr}
};

/*
 * Module register function
 */
extern "C" __attribute__((constructor)) void RegisterEl5FilekeyManager(void)
{
    napi_module_register(&g_module);
}
}  // namespace AccessToken
}  // namespace Security
}  // namespace OHOS
