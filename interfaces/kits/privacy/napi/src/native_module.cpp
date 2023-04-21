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
#include "native_module.h"
#include "permission_record_manager_napi.h"
#include "permission_used_request.h"

namespace OHOS {
namespace Security {
namespace AccessToken {
EXTERN_C_START
/*
 * function for module exports
 */
static napi_value Init(napi_env env, napi_value exports)
{
    napi_property_descriptor descriptor[] = {
        DECLARE_NAPI_FUNCTION("addPermissionUsedRecord", AddPermissionUsedRecord),
        DECLARE_NAPI_FUNCTION("startUsingPermission", StartUsingPermission),
        DECLARE_NAPI_FUNCTION("stopUsingPermission", StopUsingPermission),
        DECLARE_NAPI_FUNCTION("getPermissionUsedRecord", GetPermissionUsedRecords),
        DECLARE_NAPI_FUNCTION("getPermissionUsedRecords", GetPermissionUsedRecords),
        DECLARE_NAPI_FUNCTION("on", RegisterPermActiveChangeCallback),
        DECLARE_NAPI_FUNCTION("off", UnregisterPermActiveChangeCallback)
    };

    napi_define_properties(env, exports, sizeof(descriptor) / sizeof(descriptor[0]), descriptor);

    napi_value permissionUsageFlag = nullptr;
    napi_create_object(env, &permissionUsageFlag);

    napi_value prop = nullptr;
    napi_create_int32(env, FLAG_PERMISSION_USAGE_SUMMARY, &prop);
    napi_set_named_property(env, permissionUsageFlag, "FLAG_PERMISSION_USAGE_SUMMARY", prop);

    prop = nullptr;
    napi_create_int32(env, FLAG_PERMISSION_USAGE_DETAIL, &prop);
    napi_set_named_property(env, permissionUsageFlag, "FLAG_PERMISSION_USAGE_DETAIL", prop);

    napi_value permActiveStatus = nullptr;
    napi_create_object(env, &permActiveStatus); // create enmu permActiveStatus

    prop = nullptr;
    napi_create_int32(env, PERM_INACTIVE, &prop);
    napi_set_named_property(env, permActiveStatus, "PERM_INACTIVE", prop);

    prop = nullptr;
    napi_create_int32(env, PERM_ACTIVE_IN_FOREGROUND, &prop);
    napi_set_named_property(env, permActiveStatus, "PERM_ACTIVE_IN_FOREGROUND", prop);

    prop = nullptr;
    napi_create_int32(env, PERM_ACTIVE_IN_BACKGROUND, &prop);
    napi_set_named_property(env, permActiveStatus, "PERM_ACTIVE_IN_BACKGROUND", prop);

    napi_property_descriptor exportFuncs[] = {
        DECLARE_NAPI_PROPERTY("PermissionUsageFlag", permissionUsageFlag),
        DECLARE_NAPI_PROPERTY("PermissionActiveStatus", permActiveStatus)
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
    .nm_modname = "privacyManager",
    .nm_priv = ((void *)0),
    .reserved = {0}
};

/*
 * Module register function
 */
extern "C" __attribute__((constructor)) void RegisterPrivacyModule(void)
{
    napi_module_register(&g_module);
}
}  // namespace AccessToken
}  // namespace Security
}  // namespace OHOS