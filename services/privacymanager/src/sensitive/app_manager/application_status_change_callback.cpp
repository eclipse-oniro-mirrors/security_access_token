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

#include "application_status_change_callback.h"
#include "accesstoken_log.h"
#include "permission_record_manager.h"

namespace OHOS {
namespace Security {
namespace AccessToken {
namespace {
static constexpr OHOS::HiviewDFX::HiLogLabel LABEL = {
    LOG_CORE, SECURITY_DOMAIN_PRIVACY, "ApplicationStatusChangeCallback"
};
}

void ApplicationStatusChangeCallback::OnForegroundApplicationChanged(const AppExecFwk::AppStateData& appStateData)
{
    ACCESSTOKEN_LOG_INFO(LABEL, "OnChange(accessTokenId=%{public}d, state=%{public}d)",
        appStateData.accessTokenId, appStateData.state);

    uint32_t tokenId = appStateData.accessTokenId;

    ActiveChangeType status = PERM_INACTIVE;
    if (appStateData.state == static_cast<int32_t>(AppExecFwk::ApplicationState::APP_STATE_FOREGROUND)) {
        status = PERM_ACTIVE_IN_FOREGROUND;
    } else if (appStateData.state == static_cast<int32_t>(AppExecFwk::ApplicationState::APP_STATE_BACKGROUND)) {
        status = PERM_ACTIVE_IN_BACKGROUND;
    }
    PermissionRecordManager::GetInstance().NotifyAppStateChange(tokenId, status);
}
} // namespace AccessToken
} // namespace Security
} // namespace OHOS