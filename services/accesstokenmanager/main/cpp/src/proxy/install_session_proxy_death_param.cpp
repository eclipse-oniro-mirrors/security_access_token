/*
 * Copyright (c) 2026 Huawei Device Co., Ltd.
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 *
 *     http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 */

#include "install_session_proxy_death_param.h"

#include "accesstoken_common_log.h"
#include "install_session_manager.h"

namespace OHOS {
namespace Security {
namespace AccessToken {

void InstallSessionProxyDeathParam::ProcessParam()
{
    LOGI(ATM_DOMAIN, ATM_TAG, "ProcessParam pid=%{public}d", pid_);
    InstallSessionManager::GetInstance().ClearSessionByPid(pid_);
}

bool InstallSessionProxyDeathParam::IsEqual(ProxyDeathParam* param)
{
    if (param == nullptr) {
        return false;
    }
    return pid_ == reinterpret_cast<InstallSessionProxyDeathParam*>(param)->pid_;
}

} // namespace AccessToken
} // namespace Security
} // namespace OHOS