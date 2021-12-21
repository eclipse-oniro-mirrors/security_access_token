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

#include "accesstoken_manager_client.h"

#include "accesstoken_log.h"

#include "iservice_registry.h"

namespace OHOS {
namespace Security {
namespace AccessToken {
namespace {
static constexpr OHOS::HiviewDFX::HiLogLabel LABEL = {
    LOG_CORE, SECURITY_DOMAIN_ACCESSTOKEN, "AccessTokenManagerClient"
};
} // namespace

AccessTokenManagerClient& AccessTokenManagerClient::GetInstance()
{
    static AccessTokenManagerClient instance;
    return instance;
}

AccessTokenManagerClient::AccessTokenManagerClient()
{}

AccessTokenManagerClient::~AccessTokenManagerClient()
{}

int AccessTokenManagerClient::VerifyAccesstoken(AccessTokenID tokenID, const std::string& permissionName) const
{
    ACCESSTOKEN_LOG_DEBUG(LABEL, "%{public}s: called!", __func__);
    auto proxy = GetProxy();
    if (proxy == nullptr) {
        ACCESSTOKEN_LOG_ERROR(LABEL, "%{public}s: proxy is null", __func__);
        return PERMISSION_DENIED;
    }
    return proxy->VerifyAccesstoken(tokenID, permissionName);
}

sptr<IAccessTokenManager> AccessTokenManagerClient::GetProxy() const
{
    auto sam = SystemAbilityManagerClient::GetInstance().GetSystemAbilityManager();
    if (sam == nullptr) {
        ACCESSTOKEN_LOG_DEBUG(LABEL, "%{public}s: GetSystemAbilityManager is null", __func__);
        return nullptr;
    }
    auto accesstokenSa = sam->GetSystemAbility(IAccessTokenManager::SA_ID_ACCESSTOKEN_MANAGER_SERVICE);
    if (accesstokenSa == nullptr) {
        ACCESSTOKEN_LOG_DEBUG(LABEL, "%{public}s: GetSystemAbility %{public}d is null", __func__,
            IAccessTokenManager::SA_ID_ACCESSTOKEN_MANAGER_SERVICE);
        return nullptr;
    }

    auto proxy = iface_cast<IAccessTokenManager>(accesstokenSa);
    if (proxy == nullptr) {
        ACCESSTOKEN_LOG_DEBUG(LABEL, "%{public}s: iface_cast get null", __func__);
        return nullptr;
    }
    return proxy;
}
} // namespace AccessToken
} // namespace Security
} // namespace OHOS