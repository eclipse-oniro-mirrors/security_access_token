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

#include "ability_access_ctrl_ffi.h"

#include "at_manager_impl.h"
#include "macro.h"

using namespace OHOS::FFI;
using namespace OHOS::Security::AccessToken;

namespace OHOS {
namespace CJSystemapi {

extern "C" {
int32_t FfiOHOSAbilityAccessCtrlCheckAccessTokenSync(unsigned int tokenID, const char* cPermissionName)
{
    LOGI("ACCESS_CTRL_TEST::FfiOHOSAbilityAccessCtrlCheckAccessTokenSync START");
    auto result = AtManagerImpl::VerifyAccessTokenSync(tokenID, cPermissionName);
    return result;
}

int32_t FfiOHOSAbilityAccessCtrlGrantUserGrantedPermission(unsigned int tokenID, const char* cPermissionName,
    unsigned int permissionFlags)
{
    LOGI("ACCESS_CTRL_TEST::FfiOHOSAbilityAccessCtrlGrantUserGrantedPermission START");
    auto error = AtManagerImpl::GrantUserGrantedPermission(tokenID, cPermissionName, permissionFlags);
    return error;
}

int32_t FfiOHOSAbilityAccessCtrlRevokeUserGrantedPermission(unsigned int tokenID, const char* cPermissionName,
    unsigned int permissionFlags)
{
    LOGI("ACCESS_CTRL_TEST::FfiOHOSAbilityAccessCtrlRevokeUserGrantedPermission START");
    auto error = AtManagerImpl::RevokeUserGrantedPermission(tokenID, cPermissionName, permissionFlags);
    return error;
}

int32_t FfiOHOSAbilityAccessCtrlOn(const char* cType, CArrUI32 cTokenIDList, CArrString cPermissionList,
    int64_t callbackRef)
{
    LOGI("ACCESS_CTRL_TEST::FfiOHOSAbilityAccessCtrlOn START");
    return AtManagerImpl::RegisterPermStateChangeCallback(cType, cTokenIDList, cPermissionList, callbackRef);
}

int32_t FfiOHOSAbilityAccessCtrlOff(const char* cType, CArrUI32 cTokenIDList, CArrString cPermissionList,
    int64_t callbackRef)
{
    LOGI("ACCESS_CTRL_TEST::FfiOHOSAbilityAccessCtrlOff START");
    return AtManagerImpl::UnregisterPermStateChangeCallback(cType, cTokenIDList, cPermissionList, callbackRef);
}

void FfiOHOSAbilityAccessCtrlRequestPermissionsFromUser(OHOS::AbilityRuntime::Context* context,
    CArrString cPermissionList, void (*callbackRef)(RetDataCPermissionRequestResult infoRef))
{
    auto onChange = [lambda = CJLambda::Create(callbackRef)]
        (RetDataCPermissionRequestResult infoRef) -> void { lambda(infoRef); };
    AtManagerImpl::RequestPermissionsFromUser(context, cPermissionList, onChange);
}

void FfiOHOSAbilityAccessCtrlRequestPermissionsFromUserByStdFunc(OHOS::AbilityRuntime::Context* context,
    CArrString cPermissionList, const std::function<void (RetDataCPermissionRequestResult)> *callbackPtr)
{
    auto onChange = *callbackPtr;
    AtManagerImpl::RequestPermissionsFromUser(context, cPermissionList, onChange);
}

void FfiOHOSAbilityAccessCtrlRequestPermissionOnSetting(OHOS::AbilityRuntime::Context* context,
    CArrString cPermissionList, void (*callbackRef)(RetDataCArrI32 infoRef))
{
    auto callback = [lambda = CJLambda::Create(callbackRef)]
        (RetDataCArrI32 infoRef) -> void { lambda(infoRef); };
    FfiRequestPermissionOnSetting::RequestPermissionOnSetting(context, cPermissionList, callback);
}

void FfiOHOSAbilityAccessCtrlRequestGlobalSwitch(OHOS::AbilityRuntime::Context* context, int32_t type,
    void (*callbackRef)(RetDataBool infoRef))
{
    auto callback = [lambda = CJLambda::Create(callbackRef)]
        (RetDataBool infoRef) -> void { lambda(infoRef); };
    FfiRequestGlobalSwitchOnSetting::RequestGlobalSwitch(context, type, callback);
}
}
} // namespace CJSystemapi
} // namespace OHOS
