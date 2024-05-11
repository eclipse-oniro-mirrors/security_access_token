/*
 * Copyright (c) 2021-2022 Huawei Device Co., Ltd.
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

#include "permission_definition_cache.h"

#include "access_token.h"
#include "access_token_error.h"
#include "accesstoken_log.h"
#include "generic_values.h"
#include "token_field_const.h"

namespace OHOS {
namespace Security {
namespace AccessToken {
namespace {
static const int32_t EXTENSION_PERMISSION_ID = 0;
static constexpr OHOS::HiviewDFX::HiLogLabel LABEL = {
    LOG_CORE, SECURITY_DOMAIN_ACCESSTOKEN, "PermissionDefinitionCache"
};
std::recursive_mutex g_instanceMutex;
}

PermissionDefinitionCache& PermissionDefinitionCache::GetInstance()
{
    static PermissionDefinitionCache* instance = nullptr;
    if (instance == nullptr) {
        std::lock_guard<std::recursive_mutex> lock(g_instanceMutex);
        if (instance == nullptr) {
            instance = new PermissionDefinitionCache();
        }
    }
    return *instance;
}

PermissionDefinitionCache::PermissionDefinitionCache()
{}

PermissionDefinitionCache::~PermissionDefinitionCache()
{}

bool PermissionDefinitionCache::Insert(const PermissionDef& info, AccessTokenID tokenId)
{
    Utils::UniqueWriteGuard<Utils::RWLock> cacheGuard(this->cacheLock_);
    auto it = permissionDefinitionMap_.find(info.permissionName);
    if (it != permissionDefinitionMap_.end()) {
        ACCESSTOKEN_LOG_WARN(LABEL, "info for permission: %{public}s has been insert, please check!",
            info.permissionName.c_str());
        return false;
    }
    permissionDefinitionMap_[info.permissionName].permDef = info;
    permissionDefinitionMap_[info.permissionName].tokenId = tokenId;
    if (!hasHapPermissionDefinition_ && (tokenId != EXTENSION_PERMISSION_ID)) {
        hasHapPermissionDefinition_ = true;
    }
    return true;
}

bool PermissionDefinitionCache::Update(const PermissionDef& info, AccessTokenID tokenId)
{
    Utils::UniqueWriteGuard<Utils::RWLock> cacheGuard(this->cacheLock_);
    permissionDefinitionMap_[info.permissionName].permDef = info;
    permissionDefinitionMap_[info.permissionName].tokenId = tokenId;
    return true;
}

void PermissionDefinitionCache::DeleteByBundleName(const std::string& bundleName)
{
    Utils::UniqueWriteGuard<Utils::RWLock> cacheGuard(this->cacheLock_);
    auto it = permissionDefinitionMap_.begin();
    while (it != permissionDefinitionMap_.end()) {
        if (bundleName == it->second.permDef.bundleName) {
            permissionDefinitionMap_.erase(it++);
        } else {
            ++it;
        }
    }
}

int PermissionDefinitionCache::FindByPermissionName(const std::string& permissionName, PermissionDef& info)
{
    Utils::UniqueReadGuard<Utils::RWLock> cacheGuard(this->cacheLock_);
    auto it = permissionDefinitionMap_.find(permissionName);
    if (it == permissionDefinitionMap_.end()) {
        ACCESSTOKEN_LOG_DEBUG(LABEL, "can not find definition info for permission: %{public}s",
            permissionName.c_str());
        return AccessTokenError::ERR_PARAM_INVALID;
    }
    info = it->second.permDef;
    return RET_SUCCESS;
}

bool PermissionDefinitionCache::IsSystemGrantedPermission(const std::string& permissionName)
{
    Utils::UniqueReadGuard<Utils::RWLock> cacheGuard(this->cacheLock_);
    return IsGrantedModeEqualInner(permissionName, SYSTEM_GRANT);
}

bool PermissionDefinitionCache::IsUserGrantedPermission(const std::string& permissionName)
{
    Utils::UniqueReadGuard<Utils::RWLock> cacheGuard(this->cacheLock_);
    return IsGrantedModeEqualInner(permissionName, USER_GRANT);
}

bool PermissionDefinitionCache::IsGrantedModeEqualInner(const std::string& permissionName, int grantMode) const
{
    auto it = permissionDefinitionMap_.find(permissionName);
    if (it == permissionDefinitionMap_.end()) {
        return false;
    }
    return it->second.permDef.grantMode == grantMode;
}

bool PermissionDefinitionCache::HasDefinition(const std::string& permissionName)
{
    Utils::UniqueReadGuard<Utils::RWLock> cacheGuard(this->cacheLock_);
    return permissionDefinitionMap_.count(permissionName) == 1;
}

bool PermissionDefinitionCache::HasHapPermissionDefinitionForHap(const std::string& permissionName)
{
    Utils::UniqueReadGuard<Utils::RWLock> cacheGuard(this->cacheLock_);
    auto it = permissionDefinitionMap_.find(permissionName);
    if ((it != permissionDefinitionMap_.end()) && (it->second.tokenId != EXTENSION_PERMISSION_ID)) {
        return true;
    }
    return false;
}

bool PermissionDefinitionCache::IsHapPermissionDefEmpty()
{
    Utils::UniqueReadGuard<Utils::RWLock> cacheGuard(this->cacheLock_);
    return !hasHapPermissionDefinition_;
}

void PermissionDefinitionCache::StorePermissionDef(std::vector<GenericValues>& valueList)
{
    Utils::UniqueReadGuard<Utils::RWLock> cacheGuard(this->cacheLock_);
    auto it = permissionDefinitionMap_.begin();
    while (it != permissionDefinitionMap_.end()) {
        GenericValues genericValues;
        genericValues.Put(TokenFiledConst::FIELD_TOKEN_ID, static_cast<int32_t>(it->second.tokenId));
        DataTranslator::TranslationIntoGenericValues(it->second.permDef, genericValues);
        valueList.emplace_back(genericValues);
        ++it;
    }
}

void PermissionDefinitionCache::StorePermissionDef(AccessTokenID tokenID, std::vector<GenericValues>& valueList)
{
    Utils::UniqueWriteGuard<Utils::RWLock> cacheGuard(this->cacheLock_);
    auto it = permissionDefinitionMap_.begin();
    while (it != permissionDefinitionMap_.end()) {
        if (tokenID == it->second.tokenId) {
            GenericValues genericValues;
            genericValues.Put(TokenFiledConst::FIELD_TOKEN_ID, static_cast<int32_t>(it->second.tokenId));
            DataTranslator::TranslationIntoGenericValues(it->second.permDef, genericValues);
            valueList.emplace_back(genericValues);
        }
        ++it;
    }
}

void PermissionDefinitionCache::GetDefPermissionsByTokenId(std::vector<PermissionDef>& permList,
    AccessTokenID tokenId)
{
    Utils::UniqueReadGuard<Utils::RWLock> cacheGuard(this->cacheLock_);
    auto it = permissionDefinitionMap_.begin();
    while (it != permissionDefinitionMap_.end()) {
        if (tokenId == it->second.tokenId) {
            permList.emplace_back(it->second.permDef);
        }
        ++it;
    }
}

int32_t PermissionDefinitionCache::RestorePermDefInfo(std::vector<GenericValues>& permDefRes)
{
    for (const GenericValues& defValue : permDefRes) {
        PermissionDef def;
        AccessTokenID tokenId = (AccessTokenID)defValue.GetInt(TokenFiledConst::FIELD_TOKEN_ID);
        int32_t ret = DataTranslator::TranslationIntoPermissionDef(defValue, def);
        if (ret != RET_SUCCESS) {
            ACCESSTOKEN_LOG_ERROR(LABEL, "tokenId 0x%{public}x permDef is wrong.", tokenId);
            return ret;
        }
        Insert(def, tokenId);
    }
    return RET_SUCCESS;
}
} // namespace AccessToken
} // namespace Security
} // namespace OHOS
