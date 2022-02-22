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

#include "accesstoken_info_manager.h"

#include "accesstoken_id_manager.h"
#include "accesstoken_log.h"
#include "accesstoken_remote_token_manager.h"
#include "data_storage.h"
#include "data_translator.h"
#include "data_validator.h"
#include "field_const.h"
#include "generic_values.h"
#include "hap_token_info_inner.h"
#include "permission_manager.h"
#include "token_modify_notifier.h"
#include "token_sync_kit.h"

namespace OHOS {
namespace Security {
namespace AccessToken {
namespace {
static constexpr OHOS::HiviewDFX::HiLogLabel LABEL = {LOG_CORE, SECURITY_DOMAIN_ACCESSTOKEN, "AccessTokenInfoManager"};
}

AccessTokenInfoManager::AccessTokenInfoManager() : hasInited_(false) {}

AccessTokenInfoManager::~AccessTokenInfoManager()
{
    if (!hasInited_) {
        return;
    }
    this->tokenDataWorker_.Stop();
    this->hasInited_ = false;
}

void AccessTokenInfoManager::Init()
{
    OHOS::Utils::UniqueWriteGuard<OHOS::Utils::RWLock> lk(this->managerLock_);
    if (hasInited_) {
        return;
    }

    ACCESSTOKEN_LOG_INFO(LABEL, "init begin!");
    InitHapTokenInfos();
    InitNativeTokenInfos();
    this->tokenDataWorker_.Start(1);
    hasInited_ = true;
    ACCESSTOKEN_LOG_INFO(LABEL, "Init success");
}

void AccessTokenInfoManager::InitHapTokenInfos()
{
    std::vector<GenericValues> hapTokenRes;
    std::vector<GenericValues> permDefRes;
    std::vector<GenericValues> permStateRes;

    DataStorage::GetRealDataStorage().Find(DataStorage::ACCESSTOKEN_HAP_INFO, hapTokenRes);
    DataStorage::GetRealDataStorage().Find(DataStorage::ACCESSTOKEN_PERMISSION_DEF, permDefRes);
    DataStorage::GetRealDataStorage().Find(DataStorage::ACCESSTOKEN_PERMISSION_STATE, permStateRes);

    for (GenericValues& tokenValue : hapTokenRes) {
        AccessTokenID tokenId = (AccessTokenID)tokenValue.GetInt(FIELD_TOKEN_ID);
        int ret = AccessTokenIDManager::GetInstance().RegisterTokenId(tokenId, TOKEN_HAP);
        if (ret != RET_SUCCESS) {
            ACCESSTOKEN_LOG_ERROR(LABEL, "tokenId 0x%{public}x add id failed.", tokenId);
            continue;
        }
        std::shared_ptr<HapTokenInfoInner> hap = std::make_shared<HapTokenInfoInner>();
        if (hap == nullptr) {
            AccessTokenIDManager::GetInstance().ReleaseTokenId(tokenId);
            ACCESSTOKEN_LOG_ERROR(LABEL, "tokenId 0x%{public}x alloc failed.", tokenId);
            continue;
        }
        ret = hap->RestoreHapTokenInfo(tokenId, tokenValue, permDefRes, permStateRes);
        if (ret != RET_SUCCESS) {
            AccessTokenIDManager::GetInstance().ReleaseTokenId(tokenId);
            ACCESSTOKEN_LOG_ERROR(LABEL, "tokenId 0x%{public}x restore failed.", tokenId);
            continue;
        }

        ret = AddHapTokenInfo(hap);
        if (ret != RET_SUCCESS) {
            AccessTokenIDManager::GetInstance().ReleaseTokenId(tokenId);
            ACCESSTOKEN_LOG_ERROR(LABEL, "tokenId 0x%{public}x add failed.", tokenId);
            continue;
        }
        ACCESSTOKEN_LOG_INFO(LABEL,
            " restore hap token 0x%{public}x bundle name %{public}s user %{public}d inst %{public}d ok!",
            tokenId, hap->GetBundleName().c_str(), hap->GetUserID(), hap->GetInstIndex());
    }
}

void AccessTokenInfoManager::InitNativeTokenInfos()
{
    std::vector<GenericValues> nativeTokenResults;
    DataStorage::GetRealDataStorage().Find(DataStorage::ACCESSTOKEN_NATIVE_INFO, nativeTokenResults);
    for (GenericValues nativeTokenValue : nativeTokenResults) {
        AccessTokenID tokenId = (AccessTokenID)nativeTokenValue.GetInt(FIELD_TOKEN_ID);
        int ret = AccessTokenIDManager::GetInstance().RegisterTokenId(tokenId, TOKEN_NATIVE);
        if (ret != RET_SUCCESS) {
            ACCESSTOKEN_LOG_ERROR(LABEL, "tokenId 0x%{public}x add failed.", tokenId);
            continue;
        }
        std::shared_ptr<NativeTokenInfoInner> native = std::make_shared<NativeTokenInfoInner>();
        if (native == nullptr) {
            AccessTokenIDManager::GetInstance().ReleaseTokenId(tokenId);
            ACCESSTOKEN_LOG_ERROR(LABEL, "tokenId 0x%{public}x alloc failed.", tokenId);
            continue;
        }

        ret = native->RestoreNativeTokenInfo(tokenId, nativeTokenValue);
        if (ret != RET_SUCCESS) {
            AccessTokenIDManager::GetInstance().ReleaseTokenId(tokenId);
            ACCESSTOKEN_LOG_ERROR(LABEL, "tokenId 0x%{public}x restore failed.", tokenId);
            continue;
        }

        ret = AddNativeTokenInfo(native);
        if (ret != RET_SUCCESS) {
            AccessTokenIDManager::GetInstance().ReleaseTokenId(tokenId);
            ACCESSTOKEN_LOG_ERROR(LABEL, "tokenId 0x%{public}x add failed.", tokenId);
            continue;
        }
        ACCESSTOKEN_LOG_INFO(LABEL,
            "restore native token 0x%{public}x process name %{public}s ok!",
            tokenId, native->GetProcessName().c_str());
    }
}

std::string AccessTokenInfoManager::GetHapUniqueStr(const int& userID,
    const std::string& bundleName, const int& instIndex) const
{
    return bundleName + "&" + std::to_string(userID) + "&" + std::to_string(instIndex);
}

std::string AccessTokenInfoManager::GetHapUniqueStr(const std::shared_ptr<HapTokenInfoInner>& info) const
{
    if (info == nullptr) {
        return std::string("");
    }
    return GetHapUniqueStr(info->GetUserID(), info->GetBundleName(), info->GetInstIndex());
}

int AccessTokenInfoManager::AddHapTokenInfo(const std::shared_ptr<HapTokenInfoInner>& info)
{
    if (info == nullptr) {
        ACCESSTOKEN_LOG_ERROR(LABEL, "token info is null.");
        return RET_FAILED;
    }
    AccessTokenID id = info->GetTokenID();

    {
        Utils::UniqueWriteGuard<Utils::RWLock> infoGuard(this->hapTokenInfoLock_);
        if (hapTokenInfoMap_.count(id) > 0) {
            ACCESSTOKEN_LOG_ERROR(LABEL, "token %{public}x info has exist.", id);
            return RET_FAILED;
        }

        if (!info->IsRemote()) {
            std::string HapUniqueKey = GetHapUniqueStr(info);
            if (hapTokenIdMap_.count(HapUniqueKey) > 0) {
                ACCESSTOKEN_LOG_ERROR(LABEL, "token %{public}x Unique info has exist.", id);
                return RET_FAILED;
            }
            hapTokenIdMap_[HapUniqueKey] = id;
        }
        hapTokenInfoMap_[id] = info;
    }
    if (!info->IsRemote()) {
        PermissionManager::GetInstance().AddDefPermissions(info, false);
    }
    return RET_SUCCESS;
}

int AccessTokenInfoManager::AddNativeTokenInfo(const std::shared_ptr<NativeTokenInfoInner>& info)
{
    if (info == nullptr) {
        ACCESSTOKEN_LOG_ERROR(LABEL, "token info is null.");
        return RET_FAILED;
    }

    AccessTokenID id = info->GetTokenID();
    std::string processName = info->GetProcessName();
    Utils::UniqueWriteGuard<Utils::RWLock> infoGuard(this->nativeTokenInfoLock_);
    if (nativeTokenInfoMap_.count(id) > 0) {
        ACCESSTOKEN_LOG_ERROR(
            LABEL, "token %{public}x has exist.", id);
        return RET_FAILED;
    }
    if (!info->IsRemote()) {
        if (nativeTokenIdMap_.count(processName) > 0) {
            ACCESSTOKEN_LOG_ERROR(
                LABEL, "token %{public}x process name %{public}s has exist.", id, processName.c_str());
            return RET_FAILED;
        }
        nativeTokenIdMap_[processName] = id;
    }
    nativeTokenInfoMap_[id] = info;

    return RET_SUCCESS;
}

std::shared_ptr<HapTokenInfoInner> AccessTokenInfoManager::GetHapTokenInfoInner(AccessTokenID id)
{
    Utils::UniqueReadGuard<Utils::RWLock> infoGuard(this->hapTokenInfoLock_);
    if (hapTokenInfoMap_.count(id) == 0) {
        ACCESSTOKEN_LOG_ERROR(
            LABEL, "token %{public}x is invalid.", id);
        return nullptr;
    }
    return hapTokenInfoMap_[id];
}

int AccessTokenInfoManager::GetHapTokenInfo(AccessTokenID tokenID, HapTokenInfo& InfoParcel)
{
    std::shared_ptr<HapTokenInfoInner> infoPtr = GetHapTokenInfoInner(tokenID);
    if (infoPtr == nullptr) {
        ACCESSTOKEN_LOG_ERROR(
            LABEL, "token %{public}x is invalid.", tokenID);
        return RET_FAILED;
    }
    infoPtr->TranslateToHapTokenInfo(InfoParcel);
    return RET_SUCCESS;
}

std::shared_ptr<PermissionPolicySet> AccessTokenInfoManager::GetHapPermissionPolicySet(AccessTokenID id)
{
    std::shared_ptr<HapTokenInfoInner> infoPtr = GetHapTokenInfoInner(id);
    if (infoPtr == nullptr) {
        ACCESSTOKEN_LOG_ERROR(
            LABEL, "token %{public}x is invalid.", id);
        return nullptr;
    }
    return infoPtr->GetHapInfoPermissionPolicySet();
}

std::shared_ptr<NativeTokenInfoInner> AccessTokenInfoManager::GetNativeTokenInfoInner(AccessTokenID id)
{
    Utils::UniqueReadGuard<Utils::RWLock> infoGuard(this->nativeTokenInfoLock_);
    if (nativeTokenInfoMap_.count(id) == 0) {
        ACCESSTOKEN_LOG_ERROR(
            LABEL, "token %{public}x is invalid.", id);
        return nullptr;
    }
    return nativeTokenInfoMap_[id];
}

int AccessTokenInfoManager::GetNativeTokenInfo(AccessTokenID tokenID, NativeTokenInfo& InfoParcel)
{
    std::shared_ptr<NativeTokenInfoInner> infoPtr = GetNativeTokenInfoInner(tokenID);
    if (infoPtr == nullptr) {
        ACCESSTOKEN_LOG_ERROR(
            LABEL, "token %{public}x is invalid.", tokenID);
        return RET_FAILED;
    }

    infoPtr->TranslateToNativeTokenInfo(InfoParcel);
    return RET_SUCCESS;
}

int AccessTokenInfoManager::RemoveHapTokenInfo(AccessTokenID id)
{
    ATokenTypeEnum type = AccessTokenIDManager::GetInstance().GetTokenIdType(id);
    if (type != TOKEN_HAP) {
        ACCESSTOKEN_LOG_ERROR(
            LABEL, "token %{public}x is not hap.", id);
        return RET_FAILED;
    }

    // make sure that RemoveDefPermissions is called outside of the lock to avoid deadlocks.
    PermissionManager::GetInstance().RemoveDefPermissions(id);
    {
        Utils::UniqueWriteGuard<Utils::RWLock> infoGuard(this->hapTokenInfoLock_);
        if (hapTokenInfoMap_.count(id) == 0) {
            ACCESSTOKEN_LOG_ERROR(LABEL, "hap token %{public}x no exist.", id);
            return RET_FAILED;
        }

        const std::shared_ptr<HapTokenInfoInner> info = hapTokenInfoMap_[id];
        if (info == nullptr) {
            ACCESSTOKEN_LOG_ERROR(LABEL, "hap token %{public}x is null.", id);
            return RET_FAILED;
        }
        if (info->IsRemote()) {
            ACCESSTOKEN_LOG_ERROR(LABEL, "remote hap token %{public}x can not delete.", id);
            return RET_FAILED;
        }
        std::string HapUniqueKey = GetHapUniqueStr(info);
        if (hapTokenIdMap_.count(HapUniqueKey) != 0) {
            hapTokenIdMap_.erase(HapUniqueKey);
        }
        hapTokenInfoMap_.erase(id);
    }

    AccessTokenIDManager::GetInstance().ReleaseTokenId(id);
    ACCESSTOKEN_LOG_INFO(LABEL, "remove hap token 0x%{public}x ok!", id);
    RefreshTokenInfoIfNeeded();
    TokenModifyNotifier::GetInstance().NotifyTokenDelete(id);

    return RET_SUCCESS;
}

int AccessTokenInfoManager::RemoveNativeTokenInfo(AccessTokenID id)
{
    ATokenTypeEnum type = AccessTokenIDManager::GetInstance().GetTokenIdType(id);
    if (type != TOKEN_NATIVE) {
        ACCESSTOKEN_LOG_ERROR(
            LABEL, "token %{public}x is not hap.", id);
        return RET_FAILED;
    }

    bool isRemote = false;
    {
        Utils::UniqueWriteGuard<Utils::RWLock> infoGuard(this->nativeTokenInfoLock_);
        if (nativeTokenInfoMap_.count(id) == 0) {
            ACCESSTOKEN_LOG_ERROR(LABEL, "native token %{public}x is null.", id);
            return RET_FAILED;
        }

        std::shared_ptr<NativeTokenInfoInner> info = nativeTokenInfoMap_[id];
        if (info->IsRemote()) {
            ACCESSTOKEN_LOG_ERROR(LABEL, "remote native token %{public}x can not delete.", id);
            return RET_FAILED;
        }
        std::string processName = nativeTokenInfoMap_[id]->GetProcessName();
        if (nativeTokenIdMap_.count(processName) != 0) {
            nativeTokenIdMap_.erase(processName);
        }
        nativeTokenInfoMap_.erase(id);
    }
    AccessTokenIDManager::GetInstance().ReleaseTokenId(id);
    ACCESSTOKEN_LOG_INFO(LABEL, "remove native token 0x%{public}x ok!", id);
    if (!isRemote) {
        RefreshTokenInfoIfNeeded();
    }
    return RET_SUCCESS;
}

int AccessTokenInfoManager::CreateHapTokenInfo(
    const HapInfoParams& info, const HapPolicyParams& policy, AccessTokenIDEx& tokenIdEx)
{
    if (!DataValidator::IsUserIdValid(info.userID) || !DataValidator::IsBundleNameValid(info.bundleName)
        || !DataValidator::IsAppIDDescValid(info.appIDDesc) || !DataValidator::IsDomainValid(policy.domain)) {
        ACCESSTOKEN_LOG_ERROR(LABEL, "hap token param failed");
        return RET_FAILED;
    }

    AccessTokenID tokenId = AccessTokenIDManager::GetInstance().CreateAndRegisterTokenId(TOKEN_HAP);
    if (tokenId == 0) {
        ACCESSTOKEN_LOG_INFO(LABEL, "token Id create failed");
        return RET_FAILED;
    }

    std::shared_ptr<HapTokenInfoInner> tokenInfo = std::make_shared<HapTokenInfoInner>(tokenId, info, policy);
    if (tokenInfo == nullptr) {
        AccessTokenIDManager::GetInstance().ReleaseTokenId(tokenId);
        ACCESSTOKEN_LOG_INFO(LABEL, "alloc token info failed");
        return RET_FAILED;
    }

    int ret = AddHapTokenInfo(tokenInfo);
    if (ret != RET_SUCCESS) {
        ACCESSTOKEN_LOG_WARN(LABEL, "%{public}s add token info failed", info.bundleName.c_str());
        AccessTokenIDManager::GetInstance().ReleaseTokenId(tokenId);
        return RET_FAILED;
    }
    ACCESSTOKEN_LOG_INFO(LABEL,
        "create hap token 0x%{public}x bundle name %{public}s user %{public}d inst %{public}d ok!",
        tokenId, tokenInfo->GetBundleName().c_str(), tokenInfo->GetUserID(), tokenInfo->GetInstIndex());

    tokenIdEx.tokenIdExStruct.tokenID = tokenId;
    tokenIdEx.tokenIdExStruct.tokenAttr = 0;
    RefreshTokenInfoIfNeeded();
    return RET_SUCCESS;
}

int AccessTokenInfoManager::CheckNativeDCap(AccessTokenID tokenID, const std::string& dcap)
{
    std::shared_ptr<NativeTokenInfoInner> infoPtr = GetNativeTokenInfoInner(tokenID);
    if (infoPtr == nullptr) {
        ACCESSTOKEN_LOG_ERROR(
            LABEL, "token %{public}x is invalid.", tokenID);
        return RET_FAILED;
    }

    std::vector<std::string> dcaps = infoPtr->GetDcap();
    for (auto iter = dcaps.begin(); iter != dcaps.end(); iter++) {
        if (*iter == dcap) {
            return RET_SUCCESS;
        }
    }
    return RET_FAILED;
}

AccessTokenID AccessTokenInfoManager::GetHapTokenID(int userID, const std::string& bundleName, int instIndex)
{
    Utils::UniqueReadGuard<Utils::RWLock> infoGuard(this->hapTokenInfoLock_);
    std::string HapUniqueKey = GetHapUniqueStr(userID, bundleName, instIndex);
    if (hapTokenIdMap_.count(HapUniqueKey) > 0) {
        return hapTokenIdMap_[HapUniqueKey];
    }
    return 0;
}

bool AccessTokenInfoManager::TryUpdateExistNativeToken(const std::shared_ptr<NativeTokenInfoInner>& infoPtr)
{
    if (infoPtr == nullptr) {
        ACCESSTOKEN_LOG_WARN(LABEL, "info is null");
        return false;
    }

    Utils::UniqueWriteGuard<Utils::RWLock> infoGuard(this->nativeTokenInfoLock_);
    AccessTokenID id = infoPtr->GetTokenID();
    std::string processName = infoPtr->GetProcessName();
    bool idExist = (nativeTokenInfoMap_.count(id) > 0);
    bool processExist = (nativeTokenIdMap_.count(processName) > 0);
    // id is exist, but it is not this process, so neither update nor add.
    if (idExist && !processExist) {
        ACCESSTOKEN_LOG_ERROR(
            LABEL, "token Id is exist, but process name is not exist, can not update.");
        return true;
    }

    // this process is exist, but id is not same, perhaps libat lose his data, we need delete old, add new later.
    if (!idExist && processExist) {
        AccessTokenID idRemove = nativeTokenIdMap_[processName];
        nativeTokenIdMap_.erase(processName);
        if (nativeTokenInfoMap_.count(idRemove) > 0) {
            nativeTokenInfoMap_.erase(idRemove);
        }
        AccessTokenIDManager::GetInstance().ReleaseTokenId(idRemove);
        return false;
    }

    if (!idExist && !processExist) {
        return false;
    }

    nativeTokenInfoMap_[id] = infoPtr;
    return true;
}

void AccessTokenInfoManager::ProcessNativeTokenInfos(
    const std::vector<std::shared_ptr<NativeTokenInfoInner>>& tokenInfos)
{
    for (auto& infoPtr: tokenInfos) {
        if (infoPtr == nullptr) {
            ACCESSTOKEN_LOG_WARN(LABEL, "token info from libat is null");
            continue;
        }
        bool isUpdated = TryUpdateExistNativeToken(infoPtr);
        if (!isUpdated) {
            ACCESSTOKEN_LOG_INFO(LABEL,
                "token 0x%{public}x process name %{public}s is new, add to manager!",
                infoPtr->GetTokenID(), infoPtr->GetProcessName().c_str());
            AccessTokenID id = infoPtr->GetTokenID();
            int ret = AccessTokenIDManager::GetInstance().RegisterTokenId(id, TOKEN_NATIVE);
            if (ret != RET_SUCCESS) {
                ACCESSTOKEN_LOG_ERROR(LABEL, "token Id register fail");
                continue;
            }
            ret = AddNativeTokenInfo(infoPtr);
            if (ret != RET_SUCCESS) {
                AccessTokenIDManager::GetInstance().ReleaseTokenId(id);
                ACCESSTOKEN_LOG_ERROR(LABEL,
                    "token 0x%{public}x process name %{public}s add to manager failed!",
                    infoPtr->GetTokenID(), infoPtr->GetProcessName().c_str());
            }
        }
    }
    RefreshTokenInfoIfNeeded();
}

int AccessTokenInfoManager::UpdateHapToken(AccessTokenID tokenID,
    const std::string& appIDDesc, const HapPolicyParams& policy)
{
    if (!DataValidator::IsAppIDDescValid(appIDDesc)) {
        ACCESSTOKEN_LOG_INFO(LABEL, "token 0x%{public}x parm format error!", tokenID);
        return RET_FAILED;
    }
    std::shared_ptr<HapTokenInfoInner> infoPtr = GetHapTokenInfoInner(tokenID);
    if (infoPtr == nullptr) {
        ACCESSTOKEN_LOG_INFO(LABEL, "token 0x%{public}x is null, can not update!", tokenID);
        return RET_FAILED;
    }

    if (infoPtr->IsRemote()) {
        ACCESSTOKEN_LOG_ERROR(LABEL, "remote hap token 0x%{public}x can not update!", tokenID);
        return RET_FAILED;
    }

    {
        Utils::UniqueWriteGuard<Utils::RWLock> infoGuard(this->hapTokenInfoLock_);
        infoPtr->Update(appIDDesc, policy);
        ACCESSTOKEN_LOG_INFO(LABEL,
            "token 0x%{public}x bundle name %{public}s user %{public}d inst %{public}d update ok!",
            tokenID, infoPtr->GetBundleName().c_str(), infoPtr->GetUserID(), infoPtr->GetInstIndex());
    }

    PermissionManager::GetInstance().AddDefPermissions(infoPtr, true);
    TokenModifyNotifier::GetInstance().NotifyTokenModify(tokenID);
    RefreshTokenInfoIfNeeded();
    return RET_SUCCESS;
}

int AccessTokenInfoManager::GetHapTokenSync(AccessTokenID tokenID, HapTokenInfoForSync& hapSync)
{
    std::shared_ptr<HapTokenInfoInner> infoPtr = GetHapTokenInfoInner(tokenID);
    if (infoPtr == nullptr || infoPtr->IsRemote()) {
        ACCESSTOKEN_LOG_ERROR(
            LABEL, "token %{public}x is invalid.", tokenID);
        return RET_FAILED;
    }
    hapSync.baseInfo = infoPtr->GetHapInfoBasic();
    std::shared_ptr<PermissionPolicySet> permSetPtr = infoPtr->GetHapInfoPermissionPolicySet();
    if (permSetPtr == nullptr) {
        ACCESSTOKEN_LOG_ERROR(
            LABEL, "token %{public}x permSet is invalid.", tokenID);
        return RET_FAILED;
    }
    permSetPtr->GetPermissionStateList(hapSync.permStateList);
    return RET_SUCCESS;
}

int AccessTokenInfoManager::GetHapTokenInfoFromRemote(AccessTokenID tokenID,
    HapTokenInfoForSync& hapSync)
{
    int ret = GetHapTokenSync(tokenID, hapSync);
    TokenModifyNotifier::GetInstance().AddHapTokenObservation(tokenID);
    return ret;
}

void AccessTokenInfoManager::GetAllNativeTokenInfo(std::vector<NativeTokenInfo>& nativeTokenInfosRes)
{
    Utils::UniqueReadGuard<Utils::RWLock> infoGuard(this->nativeTokenInfoLock_);
    for (auto nativeTokenInner : nativeTokenInfoMap_) {
        std::shared_ptr<NativeTokenInfoInner> nativeTokenInnerPtr = nativeTokenInner.second;
        if (nativeTokenInnerPtr == nullptr || nativeTokenInnerPtr->IsRemote()
            || nativeTokenInnerPtr->GetDcap().size() <= 0) {
            continue;
        }
        NativeTokenInfo token;
        nativeTokenInnerPtr->TranslateToNativeTokenInfo(token);
        nativeTokenInfosRes.emplace_back(token);
    }
    return;
}

int AccessTokenInfoManager::UpdateRemoteHapTokenInfo(AccessTokenID mapID, HapTokenInfoForSync& hapSync)
{
    std::shared_ptr<HapTokenInfoInner> infoPtr = GetHapTokenInfoInner(mapID);
    if (infoPtr == nullptr || !infoPtr->IsRemote()) {
        ACCESSTOKEN_LOG_INFO(LABEL, "token 0x%{public}x is null or not remote, can not update!", mapID);
        return RET_FAILED;
    }

    std::vector<PermissionDef> permList = {};
    std::shared_ptr<PermissionPolicySet> newPermPolicySet =
        PermissionPolicySet::BuildPermissionPolicySet(mapID, permList, hapSync.permStateList);

    {
        Utils::UniqueWriteGuard<Utils::RWLock> infoGuard(this->hapTokenInfoLock_);
        infoPtr->SetTokenBaseInfo(hapSync.baseInfo);
        infoPtr->SetPermissionPolicySet(newPermPolicySet);
    }
    return RET_SUCCESS;
}

int AccessTokenInfoManager::CreateRemoteHapTokenInfo(AccessTokenID mapID, HapTokenInfoForSync& hapSync)
{
    std::shared_ptr<HapTokenInfoInner> hap = std::make_shared<HapTokenInfoInner>(mapID,
        hapSync.baseInfo, hapSync.permStateList);
    if (hap == nullptr) {
        ACCESSTOKEN_LOG_ERROR(LABEL, "alloc local token failed.");
        return RET_FAILED;
    }
    hap->SetRemote(true);

    int ret = AddHapTokenInfo(hap);
    if (ret != RET_SUCCESS) {
        ACCESSTOKEN_LOG_ERROR(LABEL, "add local token failed.");
        return RET_FAILED;
    }

    return RET_SUCCESS;
}

int AccessTokenInfoManager::SetRemoteHapTokenInfo(const std::string& deviceID, HapTokenInfoForSync& hapSync)
{
    if (!DataValidator::IsDeviceIdValid(deviceID)
        || !DataValidator::IsUserIdValid(hapSync.baseInfo.userID)
        || !DataValidator::IsBundleNameValid(hapSync.baseInfo.bundleName)
        || !DataValidator::IsAplNumValid(hapSync.baseInfo.apl)
        || !DataValidator::IsTokenIDValid(hapSync.baseInfo.tokenID)
        || !DataValidator::IsAppIDDescValid(hapSync.baseInfo.appID)
        || !DataValidator::IsDeviceIdValid(hapSync.baseInfo.deviceID)
        || hapSync.baseInfo.ver != DEFAULT_TOKEN_VERSION
        || AccessTokenIDManager::GetInstance().GetTokenIdTypeEnum(hapSync.baseInfo.tokenID) != TOKEN_HAP) {
        ACCESSTOKEN_LOG_ERROR(LABEL, "device %{public}s parms invalid", deviceID.c_str());
        return RET_FAILED;
    }

    AccessTokenID remoteID = hapSync.baseInfo.tokenID;
    AccessTokenID mapID = AccessTokenRemoteTokenManager::GetInstance().GetDeviceMappingTokenID(deviceID, remoteID);
    if (mapID != 0) {
        ACCESSTOKEN_LOG_INFO(LABEL, "device %{public}s token %{public}x update exist remote hap token %{public}x.",
            deviceID.c_str(), remoteID, mapID);
        // update remote token mapping id
        hapSync.baseInfo.tokenID = mapID;
        hapSync.baseInfo.deviceID = deviceID;
        return UpdateRemoteHapTokenInfo(mapID, hapSync);
    }

    mapID = AccessTokenRemoteTokenManager::GetInstance().MapRemoteDeviceTokenToLocal(deviceID, remoteID);
    if (mapID == 0) {
        ACCESSTOKEN_LOG_ERROR(
            LABEL, "device %{public}s token %{public}x map failed.", deviceID.c_str(), remoteID);
        return RET_FAILED;
    }

    // update remote token mapping id
    hapSync.baseInfo.tokenID = mapID;
    hapSync.baseInfo.deviceID = deviceID;

    if (CreateRemoteHapTokenInfo(mapID, hapSync) == RET_FAILED) {
        AccessTokenRemoteTokenManager::GetInstance().RemoveDeviceMappingTokenID(deviceID, mapID);
        ACCESSTOKEN_LOG_INFO(LABEL, "device %{public}s token %{public}x map to local token %{public}x failed.",
            deviceID.c_str(), remoteID, mapID);
        return RET_FAILED;
    }
    ACCESSTOKEN_LOG_INFO(LABEL, "device %{public}s token %{public}x map to local token %{public}x success.",
        deviceID.c_str(), remoteID, mapID);
    return RET_SUCCESS;
}

int AccessTokenInfoManager::SetRemoteNativeTokenInfo(const std::string& deviceID,
    std::vector<NativeTokenInfo>& nativeTokenInfoList)
{
    if (!DataValidator::IsDeviceIdValid(deviceID)) {
        ACCESSTOKEN_LOG_ERROR(LABEL, "device %{public}s parms invalid", deviceID.c_str());
        return RET_FAILED;
    }

    for (NativeTokenInfo& nativeToken : nativeTokenInfoList) {
        if (!DataValidator::IsAplNumValid(nativeToken.apl) || nativeToken.ver != DEFAULT_TOKEN_VERSION
            || !DataValidator::IsProcessNameValid(nativeToken.processName) || nativeToken.dcap.size() <= 0
            || AccessTokenIDManager::GetInstance().GetTokenIdTypeEnum(nativeToken.tokenID) != TOKEN_NATIVE) {
            ACCESSTOKEN_LOG_ERROR(
                LABEL, "device %{public}s token %{public}x is invalid.", deviceID.c_str(), nativeToken.tokenID);
            continue;
        }

        AccessTokenID remoteID = nativeToken.tokenID;
        AccessTokenID mapID = AccessTokenRemoteTokenManager::GetInstance().GetDeviceMappingTokenID(deviceID, remoteID);
        if (mapID != 0) {
            ACCESSTOKEN_LOG_ERROR(
                LABEL, "device %{public}s token %{public}x has maped, no need update it.",
                deviceID.c_str(), nativeToken.tokenID);
            continue;
        }

        mapID = AccessTokenRemoteTokenManager::GetInstance().MapRemoteDeviceTokenToLocal(deviceID, remoteID);
        if (mapID == 0) {
            AccessTokenRemoteTokenManager::GetInstance().RemoveDeviceMappingTokenID(deviceID, mapID);
            ACCESSTOKEN_LOG_ERROR(
                LABEL, "device %{public}s token %{public}x map failed.",
                deviceID.c_str(), remoteID);
            continue;
        }
        nativeToken.tokenID = mapID;
        ACCESSTOKEN_LOG_INFO(LABEL, "device %{public}s token %{public}x map to local token %{public}x.",
            deviceID.c_str(), remoteID, mapID);

        std::shared_ptr<NativeTokenInfoInner> nativePtr = std::make_shared<NativeTokenInfoInner>(nativeToken);
        if (nativePtr == nullptr) {
            AccessTokenRemoteTokenManager::GetInstance().RemoveDeviceMappingTokenID(deviceID, mapID);
            ACCESSTOKEN_LOG_ERROR(LABEL, "device %{public}s tokenId 0x%{public}x alloc local token failed.",
                deviceID.c_str(), remoteID);
            continue;
        }
        nativePtr->SetRemote(true);
        int ret = AddNativeTokenInfo(nativePtr);
        if (ret != RET_SUCCESS) {
            AccessTokenRemoteTokenManager::GetInstance().RemoveDeviceMappingTokenID(deviceID, mapID);
            ACCESSTOKEN_LOG_ERROR(LABEL, "device %{public}s tokenId 0x%{public}x add local token failed.",
                deviceID.c_str(), remoteID);
            continue;
        }
        ACCESSTOKEN_LOG_INFO(LABEL, "device %{public}s token %{public}x map token %{public}x add success.",
            deviceID.c_str(), remoteID, mapID);
    }

    return RET_SUCCESS;
}

int AccessTokenInfoManager::DeleteRemoteToken(const std::string& deviceID, AccessTokenID tokenID)
{
    if (!DataValidator::IsDeviceIdValid(deviceID)) {
        ACCESSTOKEN_LOG_ERROR(LABEL, "device %{public}s parms invalid", deviceID.c_str());
        return RET_FAILED;
    }
    AccessTokenID mapID = AccessTokenRemoteTokenManager::GetInstance().GetDeviceMappingTokenID(deviceID, tokenID);
    if (mapID == 0) {
        ACCESSTOKEN_LOG_ERROR(LABEL, "device %{public}s tokenId 0x%{public}x is not mapped",
            deviceID.c_str(), tokenID);
        return RET_FAILED;
    }

    ATokenTypeEnum type = AccessTokenIDManager::GetInstance().GetTokenIdTypeEnum(mapID);
    if (type == TOKEN_HAP) {
        Utils::UniqueWriteGuard<Utils::RWLock> infoGuard(this->hapTokenInfoLock_);
        if (hapTokenInfoMap_.count(mapID) == 0) {
            ACCESSTOKEN_LOG_ERROR(LABEL, "hap token %{public}x no exist.", mapID);
            return RET_FAILED;
        }
        hapTokenInfoMap_.erase(mapID);
    } else if (type == TOKEN_NATIVE) {
        Utils::UniqueWriteGuard<Utils::RWLock> infoGuard(this->nativeTokenInfoLock_);
        if (nativeTokenInfoMap_.count(mapID) == 0) {
            ACCESSTOKEN_LOG_ERROR(
                LABEL, "native token %{public}x is null.", mapID);
            return RET_FAILED;
        }
        nativeTokenInfoMap_.erase(mapID);
    } else {
        ACCESSTOKEN_LOG_ERROR(LABEL, "mapping tokenId 0x%{public}x type is unknown", mapID);
    }

    return AccessTokenRemoteTokenManager::GetInstance().RemoveDeviceMappingTokenID(deviceID, tokenID);
}

AccessTokenID AccessTokenInfoManager::GetRemoteNativeTokenID(const std::string& deviceID, AccessTokenID tokenID)
{
    if (!DataValidator::IsDeviceIdValid(deviceID)
        || AccessTokenIDManager::GetInstance().GetTokenIdTypeEnum(tokenID) != TOKEN_NATIVE) {
        ACCESSTOKEN_LOG_ERROR(LABEL, "device %{public}s parms invalid", deviceID.c_str());
        return 0;
    }
    return AccessTokenRemoteTokenManager::GetInstance().GetDeviceMappingTokenID(deviceID, tokenID);
}

int AccessTokenInfoManager::DeleteRemoteDeviceTokens(const std::string& deviceID)
{
    if (!DataValidator::IsDeviceIdValid(deviceID)) {
        ACCESSTOKEN_LOG_ERROR(LABEL, "device %{public}s parms invalid", deviceID.c_str());
        return RET_FAILED;
    }
    std::vector<AccessTokenID> remoteTokens;
    int ret = AccessTokenRemoteTokenManager::GetInstance().GetDeviceAllRemoteTokenID(deviceID, remoteTokens);
    if (ret == RET_FAILED) {
        ACCESSTOKEN_LOG_ERROR(LABEL, "device %{public}s have no remote token", deviceID.c_str());
        return RET_FAILED;
    }
    for (AccessTokenID remoteID : remoteTokens) {
        DeleteRemoteToken(deviceID, remoteID);
    }
    return RET_SUCCESS;
}

AccessTokenID AccessTokenInfoManager::AllocLocalTokenID(const std::string& remoteDeviceID,
    AccessTokenID remoteTokenID)
{
    if (!DataValidator::IsDeviceIdValid(remoteDeviceID)) {
        ACCESSTOKEN_LOG_ERROR(LABEL, "device %{public}s parms invalid", remoteDeviceID.c_str());
        return 0;
    }
    AccessTokenID mapID = AccessTokenRemoteTokenManager::GetInstance().GetDeviceMappingTokenID(remoteDeviceID,
        remoteTokenID);
    if (mapID != 0) {
        return mapID;
    }
    int ret = TokenSyncKit::GetRemoteHapTokenInfo(remoteDeviceID, remoteTokenID);
    if (ret != RET_SUCCESS) {
        ACCESSTOKEN_LOG_ERROR(LABEL, "device %{public}s token %{public}x sync failed",
            remoteDeviceID.c_str(), remoteTokenID);
        return 0;
    }

    return AccessTokenRemoteTokenManager::GetInstance().GetDeviceMappingTokenID(remoteDeviceID, remoteTokenID);
}

AccessTokenInfoManager& AccessTokenInfoManager::GetInstance()
{
    static AccessTokenInfoManager instance;
    return instance;
}

void AccessTokenInfoManager::StoreAllTokenInfo()
{
    std::vector<GenericValues> hapInfoValues;
    std::vector<GenericValues> permDefValues;
    std::vector<GenericValues> permStateValues;
    std::vector<GenericValues> nativeTokenValues;
    {
        Utils::UniqueReadGuard<Utils::RWLock> infoGuard(this->hapTokenInfoLock_);
        for (auto iter = hapTokenInfoMap_.begin(); iter != hapTokenInfoMap_.end(); iter++) {
            if (iter->second != nullptr) {
                iter->second->StoreHapInfo(hapInfoValues, permDefValues, permStateValues);
            }
        }
    }

    {
        Utils::UniqueReadGuard<Utils::RWLock> infoGuard(this->nativeTokenInfoLock_);
        for (auto iter = nativeTokenInfoMap_.begin(); iter != nativeTokenInfoMap_.end(); iter++) {
            if (iter->second != nullptr) {
                iter->second->StoreNativeInfo(nativeTokenValues);
            }
        }
    }

    DataStorage::GetRealDataStorage().RefreshAll(DataStorage::ACCESSTOKEN_HAP_INFO, hapInfoValues);
    DataStorage::GetRealDataStorage().RefreshAll(DataStorage::ACCESSTOKEN_NATIVE_INFO, nativeTokenValues);
    DataStorage::GetRealDataStorage().RefreshAll(DataStorage::ACCESSTOKEN_PERMISSION_DEF, permDefValues);
    DataStorage::GetRealDataStorage().RefreshAll(DataStorage::ACCESSTOKEN_PERMISSION_STATE, permStateValues);
}

void AccessTokenInfoManager::RefreshTokenInfoIfNeeded()
{
    if (tokenDataWorker_.GetCurTaskNum() > 1) {
        ACCESSTOKEN_LOG_INFO(LABEL, "has refresh task!");
        return;
    }

    tokenDataWorker_.AddTask([]() {
        AccessTokenInfoManager::GetInstance().StoreAllTokenInfo();

        // Sleep for one second to avoid frequent refresh of the database.
        std::this_thread::sleep_for(std::chrono::seconds(1));
    });
}

void AccessTokenInfoManager::DumpTokenInfo(std::string& dumpInfo)
{
    ACCESSTOKEN_LOG_INFO(LABEL, "%{public}s called", __func__);
    ACCESSTOKEN_LOG_INFO(LABEL, "get hapTokenInfo");

    Utils::UniqueReadGuard<Utils::RWLock> hapInfoGuard(this->hapTokenInfoLock_);
    for (auto iter = hapTokenInfoMap_.begin(); iter != hapTokenInfoMap_.end(); iter++) {
        if (iter->second != nullptr) {
            iter->second->ToString(dumpInfo);
            dumpInfo.append("\n");
        }
    }

    ACCESSTOKEN_LOG_INFO(LABEL, "get nativeTokenInfo");
    Utils::UniqueReadGuard<Utils::RWLock> nativeInfoGuard(this->nativeTokenInfoLock_);
    for (auto iter = nativeTokenInfoMap_.begin(); iter != nativeTokenInfoMap_.end(); iter++) {
        if (iter->second != nullptr) {
            iter->second->ToString(dumpInfo);
            dumpInfo.append("\n");
        }
    }
    ACCESSTOKEN_LOG_INFO(LABEL, "get tokeninfo: %{public}s", dumpInfo.c_str());
}
} // namespace AccessToken
} // namespace Security
} // namespace OHOS
