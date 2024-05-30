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
    void (*callback)(CPermStateChangeInfo info), void (*callbackRef)(CPermStateChangeInfo infoRef))
{
    LOGI("ACCESS_CTRL_TEST::FfiOHOSAbilityAccessCtrlOn START");
    auto onChange = [lambda = CJLambda::Create(callbackRef)](
        CPermStateChangeInfo infoRef) -> void { lambda(infoRef); };
    auto error = AtManagerImpl::RegisterPermStateChangeCallback(cType, cTokenIDList, cPermissionList,
        (std::function<void(CPermStateChangeInfo)>*)(callback), onChange);
    return error;
}

int32_t FfiOHOSAbilityAccessCtrlOff(const char* cType, CArrUI32 cTokenIDList, CArrString cPermissionList,
    void (*callback)(CPermStateChangeInfo info), void (*callbackRef)(CPermStateChangeInfo infoRef))
{
    LOGI("ACCESS_CTRL_TEST::FfiOHOSAbilityAccessCtrlOff START");
    if (callback == nullptr) {
        LOGI("ACCESS_CTRL_TEST::FfiOHOSAbilityAccessCtrlOff the callback is None");
        return AtManagerImpl::UnregisterPermStateChangeCallback(cType, cTokenIDList, cPermissionList, nullptr,
            nullptr);
    }
    auto onChange = [lambda = CJLambda::Create(callbackRef)](
        CPermStateChangeInfo infoRef) -> void { lambda(infoRef); };
    auto error = AtManagerImpl::UnregisterPermStateChangeCallback(cType, cTokenIDList, cPermissionList,
        (std::function<void(CPermStateChangeInfo)>*)(callback), onChange);
    return error;
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
}
} //namespace CJSystemapi
} //namespace OHOS
