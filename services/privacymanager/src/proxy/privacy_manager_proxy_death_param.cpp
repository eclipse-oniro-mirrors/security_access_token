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

#include "privacy_manager_proxy_death_param.h"

#include "accesstoken_common_log.h"
#include "permission_record_manager.h"

namespace OHOS {
namespace Security {
namespace AccessToken {

PrivacyManagerProxyDeathParam::PrivacyManagerProxyDeathParam(int32_t pid): pid_(pid) {}

void PrivacyManagerProxyDeathParam::ProcessParam()
{
    LOGI(PRI_DOMAIN, PRI_TAG, "Remove by caller pid, pid = %{public}d.", pid_);
    PermissionRecordManager::GetInstance().RemoveRecordFromStartListByCallerPid(pid_);
}

bool PrivacyManagerProxyDeathParam::IsEqual(ProxyDeathParam* param)
{
    if (param == nullptr) {
        return false;
    }
    return pid_ == (reinterpret_cast<PrivacyManagerProxyDeathParam*>(param))->pid_;
}
} // namespace AccessToken
} // namespace Security
} // namespace OHOS

