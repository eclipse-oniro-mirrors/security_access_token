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

static constexpr OHOS::HiviewDFX::HiLogLabel LABEL = { LOG_CORE, SECURITY_DOMAIN_ACCESSTOKEN, "AniAbilityAccessCtrl" };

static ani_object CreateAtManager([[maybe_unused]] ani_env *env, [[maybe_unused]] ani_object object)
{
    ani_object atManagerObj = {};
    if (env == nullptr || object == nullptr) {
        ACCESSTOKEN_LOG_ERROR(LABEL, "nullptr env or object");
        return atManagerObj;
    }

    static const char *className = "LabilityAccessCtrlAni/abilityAccessCtrl/AtManagerInner;";
    ani_class cls;
    if (ANI_OK != env->FindClass(className, &cls)) {
        ACCESSTOKEN_LOG_ERROR(LABEL, "Not found %{public}s", className);
        return atManagerObj;
    }

    ani_method ctor;
    if (ANI_OK != env->Class_FindMethod(cls, "<ctor>", nullptr, &ctor)) {
        ACCESSTOKEN_LOG_ERROR(LABEL, "get ctor Failed %{public}s", className);
        return atManagerObj;
    }

    if (ANI_OK != env->Object_New(cls, ctor, &atManagerObj)) {
        ACCESSTOKEN_LOG_ERROR(LABEL, "Create Object Failed %{public}s", className);
        return atManagerObj;
    }

    return atManagerObj;
}

ANI_EXPORT ani_status ANI_Constructor(ani_vm *vm, uint32_t *result)
{
    ACCESSTOKEN_LOG_INFO(LABEL, "ANI_Constructor called");
    if (vm == nullptr) {
        ACCESSTOKEN_LOG_ERROR(LABEL, "nullptr vm");
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

    const char *spaceName = "LabilityAccessCtrlAni/abilityAccessCtrl;";
    ani_namespace spc;
    if (ANI_OK != env->FindNamespace(spaceName, &spc)) {
        ACCESSTOKEN_LOG_ERROR(LABEL, "Not found %{public}s", spaceName);
        return ANI_NOT_FOUND;
    }

    ACCESSTOKEN_LOG_INFO(LABEL, "array methods called");
    std::array methods = {
        ani_native_function{ "createAtManager", nullptr, reinterpret_cast<void *>(CreateAtManager) },
    };

    if (ANI_OK != env->Namespace_BindNativeFunctions(spc, methods.data(), methods.size())) {
        ACCESSTOKEN_LOG_ERROR(LABEL, "Cannot bind native methods to %{public}s", spaceName);
        return ANI_ERROR;
    };

    *result = ANI_VERSION_1;
    return ANI_OK;
}