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
#include "window_manager_privacy_death_recipient.h"
#include "accesstoken_log.h"
#include "window_manager_privacy_client.h"
#include "permission_record_manager.h"

namespace OHOS {
namespace Security {
namespace AccessToken {
namespace {
static constexpr OHOS::HiviewDFX::HiLogLabel LABEL = {
    LOG_CORE, SECURITY_DOMAIN_PRIVACY, "WindowManagerPrivacyDeathRecipient"};
} // namespace

void WindowManagerPrivacyDeathRecipient::OnRemoteDied(const wptr<IRemoteObject>& object)
{
    ACCESSTOKEN_LOG_INFO(LABEL, "%{public}s called", __func__);
    WindowManagerPrivacyClient::GetInstance().OnRemoteDiedHandle();
    PermissionRecordManager::GetInstance().OnWindowMgrRemoteDiedHandle();
}
}  // namespace AccessToken
}  // namespace Security
}  // namespace OHOS

