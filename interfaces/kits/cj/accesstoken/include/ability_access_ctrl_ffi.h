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

#ifndef OHOS_ABILITY_ACCESS_CTRL_FFI_H
#define OHOS_ABILITY_ACCESS_CTRL_FFI_H

#include <cstdint>

#include "cj_common_ffi.h"
#include "ffi_remote_data.h"
#include "at_manager_impl.h"
#include "request_global_switch_on_setting.h"
#include "request_permission_on_setting.h"

extern "C" {
    FFI_EXPORT int32_t FfiOHOSAbilityAccessCtrlCheckAccessTokenSync(unsigned int tokenID, const char* cPermissionName);
    FFI_EXPORT int32_t FfiOHOSAbilityAccessCtrlGrantUserGrantedPermission(unsigned int tokenID,
        const char* cPermissionName, unsigned int permissionFlags);
    FFI_EXPORT int32_t FfiOHOSAbilityAccessCtrlRevokeUserGrantedPermission(unsigned int tokenID,
        const char* cPermissionName, unsigned int permissionFlags);
    FFI_EXPORT int32_t FfiOHOSAbilityAccessCtrlOn(const char* cType, CArrUI32 cTokenIDList, CArrString cPermissionList,
        int64_t callbackRef);
    FFI_EXPORT int32_t FfiOHOSAbilityAccessCtrlOff(const char* cType, CArrUI32 cTokenIDList, CArrString cPermissionList,
        int64_t callbackRef);
    FFI_EXPORT void FfiOHOSAbilityAccessCtrlRequestPermissionsFromUser(OHOS::AbilityRuntime::Context* context,
        CArrString cPermissionList, void (*callbackRef)(RetDataCPermissionRequestResult infoRef));
    FFI_EXPORT void FfiOHOSAbilityAccessCtrlRequestPermissionsFromUserByStdFunc(OHOS::AbilityRuntime::Context* context,
        CArrString cPermissionList, const std::function<void (RetDataCPermissionRequestResult)> *callbackPtr);
    FFI_EXPORT void FfiOHOSAbilityAccessCtrlRequestPermissionOnSetting(OHOS::AbilityRuntime::Context* context,
        CArrString cPermissionList, void (*callbackRef)(RetDataCArrI32 infoRef));
    FFI_EXPORT void FfiOHOSAbilityAccessCtrlRequestGlobalSwitch(OHOS::AbilityRuntime::Context* context, int32_t type,
        void (*callbackRef)(RetDataBool infoRef));
}

#endif // OHOS_ABILITY_ACCESS_CTRL_FFI_H