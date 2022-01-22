/*
 * Copyright (c) 2021 Huawei Device Co., Ltd.
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

#include "tokensync_manager_client.h"

#include "accesstoken_log.h"

#include "iservice_registry.h"

namespace OHOS {
namespace Security {
namespace AccessToken {
namespace {
static constexpr OHOS::HiviewDFX::HiLogLabel LABEL = {LOG_CORE, SECURITY_DOMAIN_ACCESSTOKEN, "TokenSyncManagerClient"};
} // namespace

TokenSyncManagerClient& TokenSyncManagerClient::GetInstance()
{
    static TokenSyncManagerClient instance;
    return instance;
}

TokenSyncManagerClient::TokenSyncManagerClient()
{}

TokenSyncManagerClient::~TokenSyncManagerClient()
{}

int TokenSyncManagerClient::VerifyPermission(
    const std::string& bundleName, const std::string& permissionName, int userId) const
{
    ACCESSTOKEN_LOG_DEBUG(LABEL, "%{public}s: called!", __func__);
    auto proxy = GetProxy();
    if (proxy == nullptr) {
        ACCESSTOKEN_LOG_ERROR(LABEL, "%{public}s: proxy is null", __func__);
        return -1;
    }
    return proxy->VerifyPermission(bundleName, permissionName, userId);
}

sptr<ITokenSyncManager> TokenSyncManagerClient::GetProxy() const
{
    auto sam = SystemAbilityManagerClient::GetInstance().GetSystemAbilityManager();
    if (sam == nullptr) {
        ACCESSTOKEN_LOG_DEBUG(LABEL, "%{public}s: GetSystemAbilityManager is null", __func__);
        return nullptr;
    }
    auto tokensyncSa = sam->GetSystemAbility(ITokenSyncManager::SA_ID_TOKENSYNC_MANAGER_SERVICE);
    if (tokensyncSa == nullptr) {
        ACCESSTOKEN_LOG_DEBUG(LABEL, "%{public}s: GetSystemAbility %{public}d is null", __func__,
            ITokenSyncManager::SA_ID_TOKENSYNC_MANAGER_SERVICE);
        return nullptr;
    }

    auto proxy = iface_cast<ITokenSyncManager>(tokensyncSa);
    if (proxy == nullptr) {
        ACCESSTOKEN_LOG_DEBUG(LABEL, "%{public}s: iface_cast get null", __func__);
        return nullptr;
    }
    return proxy;
}
} // namespace AccessToken
} // namespace Security
} // namespace OHOS
