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

#include "accesstoken_compat_client.h"

#include "access_token_error.h"
#include "accesstoken_common_log.h"
#include "accesstoken_compat_proxy.h"
#include "iservice_registry.h"
#include "parameter.h"

namespace OHOS {
namespace Security {
namespace AccessToken {
namespace {
static constexpr int32_t VALUE_MAX_LEN = 32;
static const char* ACCESS_TOKEN_SERVICE_INIT_KEY = "accesstoken.permission.init";
std::recursive_mutex g_instanceMutex;
static constexpr int32_t SA_ID_ACCESSTOKEN_MANAGER_SERVICE = 3503;
} // namespace

static bool IsNativeToken(AccessTokenID tokenID)
{
    AccessTokenIDInner* idInner = reinterpret_cast<AccessTokenIDInner*>(&tokenID);
    return static_cast<ATokenTypeEnum>(idInner->type) == TOKEN_NATIVE;
}

AccessTokenCompatClient& AccessTokenCompatClient::GetInstance()
{
    static AccessTokenCompatClient* instance = nullptr;
    if (instance == nullptr) {
        std::lock_guard<std::recursive_mutex> lock(g_instanceMutex);
        if (instance == nullptr) {
            AccessTokenCompatClient* tmp = new (std::nothrow) AccessTokenCompatClient();
            instance = std::move(tmp);
        }
    }
    return *instance;
}

AccessTokenCompatClient::AccessTokenCompatClient()
{}

AccessTokenCompatClient::~AccessTokenCompatClient()
{
    LOGE(ATM_DOMAIN, ATM_TAG, "~AccessTokenCompatClient");
    std::lock_guard<std::mutex> lock(proxyMutex_);
    ReleaseProxy();
}

int32_t AccessTokenCompatClient::GetPermissionCode(const std::string& permission, uint32_t& opCode)
{
    auto proxy = GetProxy();
    if (proxy == nullptr) {
        LOGE(ATM_DOMAIN, ATM_TAG, "Proxy is null.");
        return ERR_SERVICE_ABNORMAL;
    }
    return proxy->GetPermissionCode(permission, opCode);
}

AccessTokenID AccessTokenCompatClient::GetNativeTokenId(const std::string& processName)
{
    auto proxy = GetProxy();
    if (proxy == nullptr) {
        LOGE(ATM_DOMAIN, ATM_TAG, "Proxy is null.");
        return INVALID_TOKENID;
    }
    AccessTokenID tokenID;
    int32_t errCode = proxy->GetNativeTokenId(processName, tokenID);
    LOGI(ATM_DOMAIN, ATM_TAG, "Result from server (error=%{public}d, process=%{public}s, Id=%{public}u).",
        errCode, processName.c_str(), tokenID);
    return tokenID;
}

int32_t AccessTokenCompatClient::GetHapTokenInfo(AccessTokenID tokenID, HapTokenInfoCompatParcel& hapTokenInfoIdl)
{
    auto proxy = GetProxy();
    if (proxy == nullptr) {
        LOGE(ATM_DOMAIN, ATM_TAG, "Proxy is null.");
        return ERR_SERVICE_ABNORMAL;
    }
    int32_t errCode = proxy->GetHapTokenInfo(tokenID, hapTokenInfoIdl);
    LOGI(ATM_DOMAIN, ATM_TAG, "Result from server (error=%{public}d, Id=%{public}u).", errCode, tokenID);
    return errCode;
}

PermissionState AccessTokenCompatClient::VerifyAccessToken(AccessTokenID tokenID, const std::string& permission)
{
    auto proxy = GetProxy();
    if (proxy != nullptr) {
        int32_t state = PERMISSION_DENIED;
        int32_t errCode = proxy->VerifyAccessToken(tokenID, permission, state);
        if (errCode != RET_SUCCESS) {
            LOGE(ATM_DOMAIN, ATM_TAG, "Request fail, result: %{public}d.", errCode);
            return PERMISSION_DENIED;
        }
        return static_cast<PermissionState>(state);
    }
    char value[VALUE_MAX_LEN] = {0};
    int32_t ret = GetParameter(ACCESS_TOKEN_SERVICE_INIT_KEY, "", value, VALUE_MAX_LEN - 1);
    if ((ret < 0) || (static_cast<uint64_t>(std::atoll(value)) != 0)) {
        LOGE(ATM_DOMAIN, ATM_TAG, "At service has been started, ret=%{public}d.", ret);
        return PERMISSION_DENIED;
    }
    if (IsNativeToken(tokenID)) {
        LOGI(ATM_DOMAIN, ATM_TAG, "At service has not been started.");
        return PERMISSION_GRANTED;
    }
    LOGE(ATM_DOMAIN, ATM_TAG, "Proxy is null.");
    return PERMISSION_DENIED;
}

void AccessTokenCompatClient::InitProxy()
{
    if ((proxy_ == nullptr) || (proxy_->AsObject() == nullptr) || (proxy_->AsObject()->IsObjectDead())) {
        auto sam = SystemAbilityManagerClient::GetInstance().GetSystemAbilityManager();
        if (sam == nullptr) {
            LOGE(ATM_DOMAIN, ATM_TAG, "GetSystemAbilityManager is null.");
            return;
        }
        sptr<IRemoteObject> accesstokenSa =
            sam->GetSystemAbility(SA_ID_ACCESSTOKEN_MANAGER_SERVICE);
        if (accesstokenSa == nullptr) {
            LOGE(ATM_DOMAIN, ATM_TAG, "GetSystemAbility %{public}d is null.",
                SA_ID_ACCESSTOKEN_MANAGER_SERVICE);
            return;
        }

        serviceDeathObserver_ = sptr<AccessTokenCompatDeathRecipient>::MakeSptr();
        if ((serviceDeathObserver_ != nullptr) && !accesstokenSa->AddDeathRecipient(serviceDeathObserver_)) {
            LOGE(ATM_DOMAIN, ATM_TAG, "AddDeathRecipient failed.");
        }
        proxy_ = new (std::nothrow) AccessTokenCompatProxy(accesstokenSa);
        if (proxy_ == nullptr || proxy_->AsObject() == nullptr || proxy_->AsObject()->IsObjectDead()) {
            proxy_ = nullptr;
            LOGE(ATM_DOMAIN, ATM_TAG, "Iface_cast get null.");
        }
    }
}

void AccessTokenCompatClient::OnRemoteDiedHandle()
{
    std::lock_guard<std::mutex> lock(proxyMutex_);
    ReleaseProxy();
    InitProxy();
}

sptr<IAccessTokenManager> AccessTokenCompatClient::GetProxy()
{
    std::lock_guard<std::mutex> lock(proxyMutex_);
    if ((proxy_ == nullptr) || (proxy_->AsObject() == nullptr) || (proxy_->AsObject()->IsObjectDead())) {
        InitProxy();
    }
    return proxy_;
}

void AccessTokenCompatClient::ReleaseProxy()
{
    if ((proxy_ != nullptr) && (serviceDeathObserver_ != nullptr) && (proxy_->AsObject() != nullptr)) {
        proxy_->AsObject()->RemoveDeathRecipient(serviceDeathObserver_);
    }
    proxy_ = nullptr;
    serviceDeathObserver_ = nullptr;
}

void AccessTokenCompatClient::AccessTokenCompatDeathRecipient::OnRemoteDied(const wptr<IRemoteObject>& object)
{
    LOGI(ATM_DOMAIN, ATM_TAG, "Accesstoken service is died.");
    AccessTokenCompatClient::GetInstance().OnRemoteDiedHandle();
}
} // namespace AccessToken
} // namespace Security
} // namespace OHOS
