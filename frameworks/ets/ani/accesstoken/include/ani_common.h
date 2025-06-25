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

#ifndef INTERFACES_ETS_ANI_COMMON_H
#define INTERFACES_ETS_ANI_COMMON_H

#include "ability_context.h"
#include "ani.h"
#include "ani_base_context.h"
#include "ui_content.h"
#include "ui_extension_context.h"

namespace OHOS {
namespace Security {
namespace AccessToken {
bool ExecuteAsyncCallback(ani_env* env, ani_object callback, ani_object error, ani_object result);
OHOS::Ace::UIContent* GetUIContent(const std::shared_ptr<OHOS::AbilityRuntime::AbilityContext>& abilityContext,
    std::shared_ptr<OHOS::AbilityRuntime::UIExtensionContext>& uiExtensionContext, bool uiAbilityFlag);
} // namespace AccessToken
} // namespace Security
} // namespace OHOS
#endif /* INTERFACES_ETS_ANI_COMMON_H */