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
#include "ani_common.h"
#include "accesstoken_common_log.h"
#include <sstream>
namespace OHOS {
namespace Security {
namespace AccessToken {
namespace {
constexpr const char* WRAPPER_CLASS_NAME = "@ohos.abilityAccessCtrl.AsyncCallbackWrapper";
constexpr const char* INVOKE_METHOD_NAME = "invoke";
} // namespace

bool ExecuteAsyncCallback(ani_env* env, ani_object callback, ani_object error, ani_object result)
{
    if (env == nullptr || callback == nullptr || error == nullptr || result == nullptr) {
        LOGE(ATM_DOMAIN, ATM_TAG, "Invalid paramter.");
        return false;
    }
    ani_status status = ANI_ERROR;
    ani_class clsCall {};

    if ((status = env->FindClass(WRAPPER_CLASS_NAME, &clsCall)) != ANI_OK) {
        LOGE(ATM_DOMAIN, ATM_TAG, "Failed to FindClass, error=%{public}d.", static_cast<int32_t>(status));
        return false;
    }
    ani_method method = {};
    if ((status = env->Class_FindMethod(
        clsCall, INVOKE_METHOD_NAME, "C{@ohos.base.BusinessError}C{std.core.Object}:", &method)) != ANI_OK) {
        LOGE(ATM_DOMAIN, ATM_TAG, "Failed to Class_FindMethod, error=%{public}d.", static_cast<int32_t>(status));
        return false;
    }

    status = env->Object_CallMethod_Void(static_cast<ani_object>(callback), method, error, result);
    if (status != ANI_OK) {
        LOGE(ATM_DOMAIN, ATM_TAG, "Failed to Object_CallMethod_Void, error=%{public}d.", static_cast<int32_t>(status));
        return false;
    }
    return true;
}

OHOS::Ace::UIContent* GetUIContent(const std::shared_ptr<OHOS::AbilityRuntime::AbilityContext>& abilityContext,
    std::shared_ptr<OHOS::AbilityRuntime::UIExtensionContext>& uiExtensionContext, bool uiAbilityFlag)
{
    OHOS::Ace::UIContent* uiContent = nullptr;
    if (uiAbilityFlag) {
        if (abilityContext == nullptr) {
            return nullptr;
        }
        uiContent = abilityContext->GetUIContent();
    } else {
        if (uiExtensionContext == nullptr) {
            return nullptr;
        }
        uiContent = uiExtensionContext->GetUIContent();
    }
    return uiContent;
}
} // namespace AccessToken
} // namespace Security
} // namespace OHOS
