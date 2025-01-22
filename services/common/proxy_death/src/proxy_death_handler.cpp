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

#include "accesstoken_common_log.h"
#include "iremote_object.h"
#include "proxy_death_handler.h"
#include "proxy_death_recipient.h"

namespace OHOS {
namespace Security {
namespace AccessToken {

void ProxyDeathHandler::AddProxyStub(const sptr<IRemoteObject>& proxyStub,
    std::shared_ptr<ProxyDeathParam>& param)
{
    std::lock_guard lock(proxyLock_);
    if (proxyStub == nullptr || param == nullptr) {
        return;
    }
    if (proxyStubAndRecipientMap_.find(proxyStub) != proxyStubAndRecipientMap_.end()) {
        LOGI(ATM_DOMAIN, ATM_TAG, "Proxy is found.");
        return;
    }
    auto proxyDeathRecipient = sptr<ProxyDeathRecipient>::MakeSptr(this);
    if (proxyDeathRecipient == nullptr) {
        LOGE(ATM_DOMAIN, ATM_TAG, "Create proxy death recipient failed.");
        return;
    }
    if (proxyStub->IsObjectDead()) {
        LOGE(ATM_DOMAIN, ATM_TAG, "Remote stub is dead.");
        return;
    }
    proxyStub->AddDeathRecipient(proxyDeathRecipient);
    RecipientAndParam cur(proxyDeathRecipient, param);
    proxyStubAndRecipientMap_.emplace(proxyStub, cur);
    if (proxyStub->IsObjectDead()) {
        proxyStubAndRecipientMap_.erase(proxyStub);
        return;
    }
}

void ProxyDeathHandler::HandleRemoteDied(const sptr<IRemoteObject>& object)
{
    if (object == nullptr) {
        return;
    }
    std::lock_guard lock(proxyLock_);
    auto iter = proxyStubAndRecipientMap_.find(object);
    if (iter == proxyStubAndRecipientMap_.end()) {
        LOGE(ATM_DOMAIN, ATM_TAG, "Cannot find object in map");
        return;
    }
    object->RemoveDeathRecipient(iter->second.first);
    ProcessProxyData(iter->second.second);
    proxyStubAndRecipientMap_.erase(iter);
}

void ProxyDeathHandler::ProcessProxyData(const std::shared_ptr<ProxyDeathParam>& param)
{
    LOGI(ATM_DOMAIN, ATM_TAG, "called");
    param->ProcessParam();
}

void ProxyDeathHandler::ReleaseProxies()
{
    std::lock_guard lock(proxyLock_);
    for (auto iter: proxyStubAndRecipientMap_) {
        auto object = iter.first;
        if (!object->IsObjectDead()) {
            object->RemoveDeathRecipient(iter.second.first);
        }
    }
}

void ProxyDeathHandler::ReleaseProxyByParam(const std::shared_ptr<ProxyDeathParam>& param)
{
    std::lock_guard lock(proxyLock_);
    for (auto iter = proxyStubAndRecipientMap_.begin(); iter != proxyStubAndRecipientMap_.end();) {
        if (iter->second.second->IsEqual(param.get())) {
            auto object = iter->first;
            if (!object->IsObjectDead()) {
                object->RemoveDeathRecipient(iter->second.first);
            }
            iter = proxyStubAndRecipientMap_.erase(iter);
        } else {
            ++iter;
        }
    }
}
}  // namespace AccessToken
} // namespace Security
}  // namespace OHOS
