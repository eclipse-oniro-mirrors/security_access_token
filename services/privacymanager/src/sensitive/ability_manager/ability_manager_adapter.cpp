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

#include "ability_manager_adapter.h"
#include "ability_manager_ipc_interface_code.h"
#include "access_token_error.h"
#include "accesstoken_log.h"
#include <iremote_proxy.h>
#include "iservice_registry.h"
#include "system_ability_definition.h"

namespace OHOS {
namespace Security {
namespace AccessToken {
namespace {
static constexpr OHOS::HiviewDFX::HiLogLabel LABEL = {
    LOG_CORE, SECURITY_DOMAIN_PRIVACY, "AbilityManagerAdapter"
};
const int32_t DEFAULT_INVAL_VALUE = -1;
const std::u16string ABILITY_MGR_DESCRIPTOR = u"ohos.aafwk.AbilityManager";
}
using namespace AAFwk;
AbilityManagerAdapter& AbilityManagerAdapter::GetInstance()
{
    static AbilityManagerAdapter *instance = new (std::nothrow) AbilityManagerAdapter();
    return *instance;
}

AbilityManagerAdapter::AbilityManagerAdapter()
{}

AbilityManagerAdapter::~AbilityManagerAdapter()
{}

int32_t AbilityManagerAdapter::StartAbility(const AAFwk::Want &want, const sptr<IRemoteObject> &callerToken)
{
    auto abms = GetProxy();
    if (abms == nullptr) {
        ACCESSTOKEN_LOG_ERROR(LABEL, "Failed to GetProxy.");
        return AccessTokenError::ERR_WRITE_PARCEL_FAILED;
    }

    MessageParcel data;
    MessageParcel reply;
    MessageOption option;

    if (!data.WriteInterfaceToken(ABILITY_MGR_DESCRIPTOR)) {
        ACCESSTOKEN_LOG_ERROR(LABEL, "Failed to write WriteInterfaceToken.");
        return AccessTokenError::ERR_WRITE_PARCEL_FAILED;
    }

    if (!data.WriteParcelable(&want)) {
        ACCESSTOKEN_LOG_ERROR(LABEL, "Want write failed.");
        return AccessTokenError::ERR_WRITE_PARCEL_FAILED;
    }
    if (!data.WriteInt32(DEFAULT_INVAL_VALUE)) {
        ACCESSTOKEN_LOG_ERROR(LABEL, "UserId write failed.");
        return AccessTokenError::ERR_WRITE_PARCEL_FAILED;
    }
    if (!data.WriteInt32(DEFAULT_INVAL_VALUE)) {
        ACCESSTOKEN_LOG_ERROR(LABEL, "RequestCode write failed.");
        return AccessTokenError::ERR_WRITE_PARCEL_FAILED;
    }
    int32_t error = abms->SendRequest(static_cast<uint32_t>(AbilityManagerInterfaceCode::START_ABILITY),
        data, reply, option);
    if (error != NO_ERROR) {
        ACCESSTOKEN_LOG_ERROR(LABEL, "SendRequest error: %{public}d", error);
        return error;
    }
    return reply.ReadInt32();
}

void AbilityManagerAdapter::InitProxy()
{
    if (proxy_ != nullptr) {
        return;
    }
    sptr<ISystemAbilityManager> systemManager = SystemAbilityManagerClient::GetInstance().GetSystemAbilityManager();
    if (systemManager == nullptr) {
        ACCESSTOKEN_LOG_ERROR(LABEL, "Fail to get system ability registry.");
        return;
    }
    sptr<IRemoteObject> remoteObj = systemManager->CheckSystemAbility(ABILITY_MGR_SERVICE_ID);
    if (remoteObj == nullptr) {
        ACCESSTOKEN_LOG_ERROR(LABEL, "Fail to connect ability manager service.");
        return;
    }

    deathRecipient_ = sptr<IRemoteObject::DeathRecipient>(new (std::nothrow) AbilityMgrDeathRecipient());
    if (deathRecipient_ == nullptr) {
        ACCESSTOKEN_LOG_ERROR(LABEL, "Failed to create AbilityMgrDeathRecipient!");
        return;
    }
    if ((remoteObj->IsProxyObject()) && (!remoteObj->AddDeathRecipient(deathRecipient_))) {
        ACCESSTOKEN_LOG_ERROR(LABEL, "Add death recipient to AbilityManagerService failed.");
        return;
    }
    proxy_ = remoteObj;
}

sptr<IRemoteObject> AbilityManagerAdapter::GetProxy()
{
    std::lock_guard<std::mutex> lock(proxyMutex_);
    if (proxy_ == nullptr) {
        InitProxy();
    }
    return proxy_;
}

void AbilityManagerAdapter::ReleaseProxy(const wptr<IRemoteObject>& remote)
{
    std::lock_guard<std::mutex> lock(proxyMutex_);
    if ((proxy_ != nullptr) && (proxy_ == remote.promote())) {
        proxy_->RemoveDeathRecipient(deathRecipient_);
        proxy_ = nullptr;
        deathRecipient_ = nullptr;
    }
}

void AbilityManagerAdapter::AbilityMgrDeathRecipient::OnRemoteDied(const wptr<IRemoteObject>& remote)
{
    ACCESSTOKEN_LOG_ERROR(LABEL, "AbilityMgrDeathRecipient handle remote died.");
    AbilityManagerAdapter::GetInstance().ReleaseProxy(remote);
}
} // namespace AccessToken
} // namespace Security
} // namespace OHOS
