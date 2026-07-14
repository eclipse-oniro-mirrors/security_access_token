/*
 * Copyright (c) 2023 Huawei Device Co., Ltd.
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
#include "sec_comp_enhance_agent.h"

#include <cinttypes>
#include <cstring>

#include "access_token_error.h"
#include "accesstoken_common_log.h"
#include "app_manager_access_client.h"
#include "ipc_skeleton.h"
#include "securec.h"

namespace OHOS {
namespace Security {
namespace AccessToken {
namespace {
std::recursive_mutex g_instanceMutex;

bool IsEnhanceKeySizeValid(uint32_t size)
{
    return (size > 0) && (size <= MAX_HMAC_SIZE);
}

void ClearSecCompEnhanceKey(SecCompEnhanceKey& enhanceKey)
{
    if (memset_s(enhanceKey.key.data, MAX_HMAC_SIZE, 0, MAX_HMAC_SIZE) != EOK) {
        LOGE(ATM_DOMAIN, ATM_TAG, "Clear enhance key failed.");
    }
    enhanceKey.key.size = 0;
    enhanceKey.epoch = 0;
}

bool CopySecCompEnhanceKey(const SecCompEnhanceKey& source, SecCompEnhanceKey& destination)
{
    if (!IsEnhanceKeySizeValid(source.key.size)) {
        return false;
    }
    ClearSecCompEnhanceKey(destination);
    destination.key.size = source.key.size;
    destination.epoch = source.epoch;
    if (memcpy_s(destination.key.data, MAX_HMAC_SIZE, source.key.data, source.key.size) != EOK) {
        ClearSecCompEnhanceKey(destination);
        return false;
    }
    return true;
}

bool IsSameSecCompEnhanceKey(const SecCompEnhanceKey& first, const SecCompEnhanceKey& second)
{
    return (first.key.size == second.key.size) &&
        (memcmp(first.key.data, second.key.data, first.key.size) == 0);
}
}

void SecCompUsageObserver::OnProcessDied(const ProcessData &processData)
{
    LOGI(ATM_DOMAIN, ATM_TAG, "OnProcessDied pid %{public}d", processData.pid);
    SecCompEnhanceAgent::GetInstance().RemoveSecCompEnhance(processData.pid, processData.accessTokenId);
}

void SecCompAppManagerDeathCallback::NotifyAppManagerDeath()
{
    LOGI(ATM_DOMAIN, ATM_TAG, "AppManagerDeath called");

    SecCompEnhanceAgent::GetInstance().OnAppMgrRemoteDiedHandle();
}

SecCompEnhanceAgent& SecCompEnhanceAgent::GetInstance()
{
    static SecCompEnhanceAgent* instance = nullptr;
    if (instance == nullptr) {
        std::lock_guard<std::recursive_mutex> lock(g_instanceMutex);
        if (instance == nullptr) {
            SecCompEnhanceAgent* tmp = new (std::nothrow) SecCompEnhanceAgent();
            instance = std::move(tmp);
        }
    }
    return *instance;
}

void SecCompEnhanceAgent::InitAppObserver()
{
    if (observer_ != nullptr) {
        return;
    }
    observer_ = new (std::nothrow) SecCompUsageObserver();
    if (observer_ == nullptr) {
        LOGE(ATM_DOMAIN, ATM_TAG, "New observer failed.");
        return;
    }
    if (AppManagerAccessClient::GetInstance().RegisterApplicationStateObserver(observer_) != 0) {
        LOGE(ATM_DOMAIN, ATM_TAG, "Register observer failed.");
        observer_ = nullptr;
        return;
    }
    if (appManagerDeathCallback_ == nullptr) {
        appManagerDeathCallback_ = std::make_shared<SecCompAppManagerDeathCallback>();
        AppManagerAccessClient::GetInstance().RegisterDeathCallback(appManagerDeathCallback_);
    }
}

SecCompEnhanceAgent::SecCompEnhanceAgent()
{
    InitAppObserver();
}

SecCompEnhanceAgent::~SecCompEnhanceAgent()
{
    if (observer_ != nullptr) {
        AppManagerAccessClient::GetInstance().UnregisterApplicationStateObserver(observer_);
        observer_ = nullptr;
    }
    std::lock_guard<std::mutex> lock(secCompEnhanceKeyMutex_);
    ClearSecCompEnhanceKey(secCompEnhanceKey_);
    hasSecCompEnhanceKey_ = false;
}

void SecCompEnhanceAgent::OnAppMgrRemoteDiedHandle()
{
    LOGI(ATM_DOMAIN, ATM_TAG, "OnAppMgrRemoteDiedHandle.");
    std::lock_guard<std::mutex> lock(secCompEnhanceMutex_);
    secCompEnhanceData_.clear();
    observer_ = nullptr;
}

void SecCompEnhanceAgent::RemoveSecCompEnhance(int pid, uint32_t tokenId)
{
    std::lock_guard<std::mutex> lock(secCompEnhanceMutex_);
    for (auto iter = secCompEnhanceData_.begin(); iter != secCompEnhanceData_.end(); ++iter) {
        if (iter->pid == pid && iter->token == tokenId) {
            --iter->count;
            if (iter->count <= 0) {
                secCompEnhanceData_.erase(iter);
                LOGI(ATM_DOMAIN, ATM_TAG, "Remove pid %{public}d data.", pid);
            }
            return;
        }
    }
    LOGD(ATM_DOMAIN, ATM_TAG, "Not found pid %{public}d data.", pid);
    return;
}

int32_t SecCompEnhanceAgent::RegisterSecCompEnhance(const SecCompEnhanceData& enhanceData)
{
    std::lock_guard<std::mutex> lock(secCompEnhanceMutex_);
    InitAppObserver();
    int pid = IPCSkeleton::GetCallingPid();
    uint32_t token = IPCSkeleton::GetCallingTokenID();

    for (auto iter = secCompEnhanceData_.begin(); iter != secCompEnhanceData_.end(); ++iter) {
        if (iter->pid == pid && iter->token == token) {
            iter->callback = enhanceData.callback;
            iter->challenge = enhanceData.challenge;
            iter->sessionId = enhanceData.sessionId;
            iter->seqNum = enhanceData.seqNum;
            ++iter->count;
            if (memcpy_s(iter->key, AES_KEY_STORAGE_LEN, enhanceData.key, AES_KEY_STORAGE_LEN) != EOK) {
                return AccessTokenError::ERR_UTIL_OPER_FAILED;
            }
            LOGI(ATM_DOMAIN, ATM_TAG, "Refresh sec comp enhance data, pid %{public}d, count %{public}d.",
                pid, iter->count);
            return RET_SUCCESS;
        }
    }
    SecCompEnhanceData enhance;
    enhance.callback = enhanceData.callback;
    enhance.pid = pid;
    enhance.token = IPCSkeleton::GetCallingTokenID();
    enhance.challenge = enhanceData.challenge;
    enhance.sessionId = enhanceData.sessionId;
    enhance.seqNum = enhanceData.seqNum;
    enhance.count = 1;
    if (memcpy_s(enhance.key, AES_KEY_STORAGE_LEN, enhanceData.key, AES_KEY_STORAGE_LEN) != EOK) {
        return AccessTokenError::ERR_UTIL_OPER_FAILED;
    }
    secCompEnhanceData_.emplace_back(enhance);
    LOGI(ATM_DOMAIN, ATM_TAG, "Register sec comp enhance success, pid %{public}d, total %{public}u.",
        pid, static_cast<uint32_t>(secCompEnhanceData_.size()));
    return RET_SUCCESS;
}

int32_t SecCompEnhanceAgent::UpdateSecCompEnhance(int32_t pid, uint32_t seqNum)
{
    std::lock_guard<std::mutex> lock(secCompEnhanceMutex_);
    InitAppObserver();
    for (auto iter = secCompEnhanceData_.begin(); iter != secCompEnhanceData_.end(); ++iter) {
        if (iter->pid == pid) {
            iter->seqNum = seqNum;
            LOGI(ATM_DOMAIN, ATM_TAG, "Update pid=%{public}d data successful.", pid);
            return RET_SUCCESS;
        }
    }
    return ERR_PARAM_INVALID;
}

int32_t SecCompEnhanceAgent::GetSecCompEnhance(int32_t pid, SecCompEnhanceData& enhanceData)
{
    std::lock_guard<std::mutex> lock(secCompEnhanceMutex_);
    InitAppObserver();
    for (auto iter = secCompEnhanceData_.begin(); iter != secCompEnhanceData_.end(); ++iter) {
        if (iter->pid == pid) {
            enhanceData = *iter;
            LOGI(ATM_DOMAIN, ATM_TAG, "Get pid %{public}d data.", pid);
            return RET_SUCCESS;
        }
    }
    return ERR_PARAM_INVALID;
}

int32_t SecCompEnhanceAgent::StoreSecCompEnhanceKey(const SecCompEnhanceKey& enhanceKey)
{
    if (!IsEnhanceKeySizeValid(enhanceKey.key.size)) {
        LOGE(ATM_DOMAIN, ATM_TAG, "Enhance key size %{public}u is invalid.", enhanceKey.key.size);
        return AccessTokenError::ERR_PARAM_INVALID;
    }

    std::lock_guard<std::mutex> lock(secCompEnhanceKeyMutex_);
    if (hasSecCompEnhanceKey_ && (enhanceKey.epoch < secCompEnhanceKey_.epoch)) {
        LOGE(ATM_DOMAIN, ATM_TAG, "Enhance key epoch rollback, current=%{public}" PRIu64
            ", new=%{public}" PRIu64 ".", secCompEnhanceKey_.epoch, enhanceKey.epoch);
        return AccessTokenError::ERR_PARAM_INVALID;
    }
    if (hasSecCompEnhanceKey_ && (enhanceKey.epoch == secCompEnhanceKey_.epoch)) {
        if (!IsSameSecCompEnhanceKey(enhanceKey, secCompEnhanceKey_)) {
            LOGE(ATM_DOMAIN, ATM_TAG, "Different enhance key for epoch %{public}" PRIu64
                ", size=%{public}u.", enhanceKey.epoch, enhanceKey.key.size);
            return AccessTokenError::ERR_PARAM_INVALID;
        }
        LOGI(ATM_DOMAIN, ATM_TAG, "Store same enhance key, epoch=%{public}" PRIu64
            ", size=%{public}u.", enhanceKey.epoch, enhanceKey.key.size);
        return RET_SUCCESS;
    }
    SecCompEnhanceKey storedKey;
    if (!CopySecCompEnhanceKey(enhanceKey, storedKey)) {
        LOGE(ATM_DOMAIN, ATM_TAG, "Copy enhance key failed.");
        return AccessTokenError::ERR_PARAM_INVALID;
    }
    ClearSecCompEnhanceKey(secCompEnhanceKey_);
    secCompEnhanceKey_ = storedKey;
    ClearSecCompEnhanceKey(storedKey);
    hasSecCompEnhanceKey_ = true;
    LOGI(ATM_DOMAIN, ATM_TAG, "Store enhance key, epoch=%{public}" PRIu64
        ", size=%{public}u.", secCompEnhanceKey_.epoch, secCompEnhanceKey_.key.size);
    return RET_SUCCESS;
}

int32_t SecCompEnhanceAgent::GetSecCompEnhanceKey(SecCompEnhanceKey& enhanceKey)
{
    std::lock_guard<std::mutex> lock(secCompEnhanceKeyMutex_);
    if (!hasSecCompEnhanceKey_) {
        LOGW(ATM_DOMAIN, ATM_TAG, "Enhance key is not ready.");
        return AccessTokenError::ERR_RESOURCE_IS_NOT_READY;
    }
    if (!CopySecCompEnhanceKey(secCompEnhanceKey_, enhanceKey)) {
        LOGE(ATM_DOMAIN, ATM_TAG, "Copy stored enhance key failed.");
        return AccessTokenError::ERR_PARAM_INVALID;
    }
    LOGI(ATM_DOMAIN, ATM_TAG, "Get enhance key, epoch=%{public}" PRIu64
        ", size=%{public}u.", enhanceKey.epoch, enhanceKey.key.size);
    return RET_SUCCESS;
}

} // namespace AccessToken
} // namespace Security
} // namespace OHOS
