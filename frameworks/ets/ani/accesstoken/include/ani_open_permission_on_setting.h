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
#ifndef ANI_OPEN_PERMISSION_ON_SETTING_H
#define ANI_OPEN_PERMISSION_ON_SETTING_H

#include "access_token.h"
#include "ani.h"
#include "ani_error.h"
#include "ani_request_base.h"
#include "ani_utils.h"
#ifdef EVENTHANDLER_ENABLE
#include "event_handler.h"
#include "event_queue.h"
#endif
#include "permission_grant_info.h"
#include "ui_content.h"
#include "ui_extension_context.h"

namespace OHOS {
namespace Security {
namespace AccessToken {
struct OpenPermOnSettingAsyncContext: public RequestAsyncContextBase {
    std::string permissionName;

    // result after requesting
    int32_t resultCode = 0;

    OpenPermOnSettingAsyncContext(ani_vm* vm_, ani_env* env_);
    ~OpenPermOnSettingAsyncContext() override;
    bool IsSameRequest(const std::shared_ptr<RequestAsyncContextBase> other) override;
    void CopyResult(const std::shared_ptr<RequestAsyncContextBase> other) override;
    void ProcessFailResult(int32_t code) override;
    void ProcessUIExtensionCallback(const OHOS::AAFwk::Want& result) override;
    int32_t ConvertErrorCode(int32_t code) override;
    ani_object WrapResult(ani_env* env) override;
    void StartExtensionAbility(std::shared_ptr<RequestAsyncContextBase> asyncContext) override;
    bool CheckDynamicRequest() override;
    bool NoNeedUpdate() override;
};

void OpenPermissionOnSettingExecute([[maybe_unused]] ani_env* env,
    [[maybe_unused]] ani_object object, ani_object aniContext, ani_string aniPermission, ani_object callback);
} // namespace AccessToken
} // namespace Security
} // namespace OHOS
#endif /* ANI_OPEN_PERMISSION_ON_SETTING_H */
