/*
 * Copyright (c) 2021-2024 Huawei Device Co., Ltd.
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

#include <cinttypes>
#include <cstdint>
#include <fcntl.h>
#include <unistd.h>
#include <securec.h>
#include "access_token.h"
#include "accesstoken_dfx_define.h"
#include "accesstoken_id_manager.h"
#include "accesstoken_log.h"
#include "accesstoken_remote_token_manager.h"
#include "access_token_error.h"
#include "atm_tools_param_info_parcel.h"
#include "callback_manager.h"
#include "constant_common.h"
#include "data_translator.h"
#include "data_validator.h"
#ifdef SUPPORT_SANDBOX_APP
#include "dlp_permission_set_manager.h"
#endif
#ifdef RESOURCESCHEDULE_FFRT_ENABLE
#include "ffrt.h"
#endif
#include "generic_values.h"
#include "hap_token_info_inner.h"
#include "ipc_skeleton.h"
#include "permission_definition_cache.h"
#include "permission_manager.h"
#include "softbus_bus_center.h"
#include "access_token_db.h"
#include "token_field_const.h"
#include "token_setproc.h"
#ifdef TOKEN_SYNC_ENABLE
#include "token_modify_notifier.h"
#endif

namespace OHOS {
namespace Security {
namespace AccessToken {
namespace {
std::recursive_mutex g_instanceMutex;
static constexpr OHOS::HiviewDFX::HiLogLabel LABEL = {LOG_CORE, SECURITY_DOMAIN_ACCESSTOKEN, "AccessTokenInfoManager"};
static const std::string ACCESS_TOKEN_PACKAGE_NAME = "ohos.security.distributed_token_sync";
static const unsigned int SYSTEM_APP_FLAG = 0x0001;
const std::string DUMP_JSON_PATH = "/data/service/el1/public/access_token/nativetoken.log";
}

#ifdef RESOURCESCHEDULE_FFRT_ENABLE
AccessTokenInfoManager::AccessTokenInfoManager() : curTaskNum_(0), hasInited_(false) {}
#else
AccessTokenInfoManager::AccessTokenInfoManager() : tokenDataWorker_("TokenStore"), hasInited_(false) {}
#endif

AccessTokenInfoManager::~AccessTokenInfoManager()
{
    if (!hasInited_) {
        return;
    }
#ifndef RESOURCESCHEDULE_FFRT_ENABLE
    this->tokenDataWorker_.Stop();
#endif
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
#ifndef RESOURCESCHEDULE_FFRT_ENABLE
    this->tokenDataWorker_.Start(1);
#endif
    hasInited_ = true;
    ACCESSTOKEN_LOG_INFO(LABEL, "Init success");
}

void AccessTokenInfoManager::InitHapTokenInfos()
{
    std::vector<GenericValues> hapTokenRes;
    std::vector<GenericValues> permDefRes;
    std::vector<GenericValues> permStateRes;

    AccessTokenDb::GetInstance().Find(AccessTokenDb::ACCESSTOKEN_HAP_INFO, hapTokenRes);
    AccessTokenDb::GetInstance().Find(AccessTokenDb::ACCESSTOKEN_PERMISSION_DEF, permDefRes);
    AccessTokenDb::GetInstance().Find(AccessTokenDb::ACCESSTOKEN_PERMISSION_STATE, permStateRes);

    for (const GenericValues& tokenValue : hapTokenRes) {
        AccessTokenID tokenId = (AccessTokenID)tokenValue.GetInt(TokenFiledConst::FIELD_TOKEN_ID);
        int ret = AccessTokenIDManager::GetInstance().RegisterTokenId(tokenId, TOKEN_HAP);
        if (ret != RET_SUCCESS) {
            ACCESSTOKEN_LOG_ERROR(LABEL, "tokenId %{public}u add id failed.", tokenId);
            HiSysEventWrite(HiviewDFX::HiSysEvent::Domain::ACCESS_TOKEN, "PERMISSION_CHECK",
                HiviewDFX::HiSysEvent::EventType::FAULT, "CODE", LOAD_DATABASE_ERROR,
                "ERROR_REASON", "hap tokenID error");
            continue;
        }
        std::shared_ptr<HapTokenInfoInner> hap = std::make_shared<HapTokenInfoInner>();
        ret = hap->RestoreHapTokenInfo(tokenId, tokenValue, permStateRes);
        if (ret != RET_SUCCESS) {
            AccessTokenIDManager::GetInstance().ReleaseTokenId(tokenId);
            ACCESSTOKEN_LOG_ERROR(LABEL, "tokenId %{public}u restore failed.", tokenId);
            continue;
        }

        ret = AddHapTokenInfo(hap);
        if (ret != RET_SUCCESS) {
            AccessTokenIDManager::GetInstance().ReleaseTokenId(tokenId);
            ACCESSTOKEN_LOG_ERROR(LABEL, "tokenId %{public}u add failed.", tokenId);
            HiSysEventWrite(HiviewDFX::HiSysEvent::Domain::ACCESS_TOKEN, "PERMISSION_CHECK",
                HiviewDFX::HiSysEvent::EventType::FAULT, "CODE", LOAD_DATABASE_ERROR,
                "ERROR_REASON", "hap token has exist");
            continue;
        }
        ACCESSTOKEN_LOG_INFO(LABEL,
            " restore hap token %{public}u bundle name %{public}s user %{public}d inst %{public}d ok!",
            tokenId, hap->GetBundleName().c_str(), hap->GetUserID(), hap->GetInstIndex());
    }
    PermissionDefinitionCache::GetInstance().RestorePermDefInfo(permDefRes);
}

void AccessTokenInfoManager::InitNativeTokenInfos()
{
    std::vector<GenericValues> nativeTokenResults;
    std::vector<GenericValues> permStateRes;

    AccessTokenDb::GetInstance().Find(AccessTokenDb::ACCESSTOKEN_NATIVE_INFO, nativeTokenResults);
    AccessTokenDb::GetInstance().Find(AccessTokenDb::ACCESSTOKEN_PERMISSION_STATE, permStateRes);
    for (const GenericValues& nativeTokenValue : nativeTokenResults) {
        AccessTokenID tokenId = (AccessTokenID)nativeTokenValue.GetInt(TokenFiledConst::FIELD_TOKEN_ID);
        ATokenTypeEnum type = AccessTokenIDManager::GetInstance().GetTokenIdTypeEnum(tokenId);
        int ret = AccessTokenIDManager::GetInstance().RegisterTokenId(tokenId, type);
        if (ret != RET_SUCCESS) {
            HiSysEventWrite(HiviewDFX::HiSysEvent::Domain::ACCESS_TOKEN, "PERMISSION_CHECK",
                HiviewDFX::HiSysEvent::EventType::FAULT, "CODE", LOAD_DATABASE_ERROR,
                "ERROR_REASON", "native tokenID error");
            ACCESSTOKEN_LOG_ERROR(LABEL, "tokenId %{public}u add failed.", tokenId);
            continue;
        }
        std::shared_ptr<NativeTokenInfoInner> native = std::make_shared<NativeTokenInfoInner>();

        ret = native->RestoreNativeTokenInfo(tokenId, nativeTokenValue, permStateRes);
        if (ret != RET_SUCCESS) {
            AccessTokenIDManager::GetInstance().ReleaseTokenId(tokenId);
            ACCESSTOKEN_LOG_ERROR(LABEL, "tokenId %{public}u restore failed.", tokenId);
            continue;
        }

        ret = AddNativeTokenInfo(native);
        if (ret != RET_SUCCESS) {
            AccessTokenIDManager::GetInstance().ReleaseTokenId(tokenId);
            ACCESSTOKEN_LOG_ERROR(LABEL, "tokenId %{public}u add failed.", tokenId);
            HiSysEventWrite(HiviewDFX::HiSysEvent::Domain::ACCESS_TOKEN, "PERMISSION_CHECK",
                HiviewDFX::HiSysEvent::EventType::FAULT, "CODE", LOAD_DATABASE_ERROR,
                "ERROR_REASON", "native tokenID error");
            continue;
        }
        ACCESSTOKEN_LOG_INFO(LABEL,
            "restore native token %{public}u process name %{public}s ok!",
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
        return AccessTokenError::ERR_PARAM_INVALID;
    }
    AccessTokenID id = info->GetTokenID();
    AccessTokenID idRemoved = INVALID_TOKENID;
    {
        Utils::UniqueWriteGuard<Utils::RWLock> infoGuard(this->hapTokenInfoLock_);
        if (hapTokenInfoMap_.count(id) > 0) {
            ACCESSTOKEN_LOG_ERROR(LABEL, "token %{public}u info has exist.", id);
            return AccessTokenError::ERR_TOKENID_NOT_EXIST;
        }

        if (!info->IsRemote()) {
            std::string HapUniqueKey = GetHapUniqueStr(info);
            auto iter = hapTokenIdMap_.find(HapUniqueKey);
            if (iter != hapTokenIdMap_.end()) {
                ACCESSTOKEN_LOG_INFO(LABEL, "token %{public}u Unique info has exist, update.", id);
                idRemoved = iter->second;
            }
            hapTokenIdMap_[HapUniqueKey] = id;
        }
        hapTokenInfoMap_[id] = info;
    }
    if (idRemoved != INVALID_TOKENID) {
        RemoveHapTokenInfo(idRemoved);
    }
    // add hap to kernel
    std::shared_ptr<PermissionPolicySet> policySet = info->GetHapInfoPermissionPolicySet();
    PermissionManager::GetInstance().AddPermToKernel(id, policySet);

    HiSysEventWrite(HiviewDFX::HiSysEvent::Domain::ACCESS_TOKEN, "ADD_HAP", HiviewDFX::HiSysEvent::EventType::STATISTIC,
        "TOKENID", info->GetTokenID(), "USERID", info->GetUserID(), "BUNDLENAME", info->GetBundleName(),
        "INSTINDEX", info->GetInstIndex());

    return RET_SUCCESS;
}

int AccessTokenInfoManager::AddNativeTokenInfo(const std::shared_ptr<NativeTokenInfoInner>& info)
{
    if (info == nullptr) {
        ACCESSTOKEN_LOG_ERROR(LABEL, "token info is null.");
        return AccessTokenError::ERR_PARAM_INVALID;
    }

    AccessTokenID id = info->GetTokenID();
    std::string processName = info->GetProcessName();
    Utils::UniqueWriteGuard<Utils::RWLock> infoGuard(this->nativeTokenInfoLock_);
    if (nativeTokenInfoMap_.count(id) > 0) {
        ACCESSTOKEN_LOG_ERROR(
            LABEL, "token %{public}u has exist.", id);
        return AccessTokenError::ERR_TOKENID_NOT_EXIST;
    }
    if (!info->IsRemote()) {
        if (nativeTokenIdMap_.count(processName) > 0) {
            ACCESSTOKEN_LOG_ERROR(
                LABEL, "token %{public}u process name %{public}s has exist.", id, processName.c_str());
            return AccessTokenError::ERR_PROCESS_NOT_EXIST;
        }
        nativeTokenIdMap_[processName] = id;
    }

    ACCESSTOKEN_LOG_INFO(LABEL, "token info is added %{public}u.", id);
    nativeTokenInfoMap_[id] = info;

    // add native to kernel
    std::shared_ptr<PermissionPolicySet> policySet = info->GetNativeInfoPermissionPolicySet();
    PermissionManager::GetInstance().AddPermToKernel(id, policySet);

    return RET_SUCCESS;
}

std::shared_ptr<HapTokenInfoInner> AccessTokenInfoManager::GetHapTokenInfoInner(AccessTokenID id)
{
    Utils::UniqueReadGuard<Utils::RWLock> infoGuard(this->hapTokenInfoLock_);
    auto iter = hapTokenInfoMap_.find(id);
    if (iter != hapTokenInfoMap_.end()) {
        return iter->second;
    }
    ACCESSTOKEN_LOG_ERROR(LABEL, "token %{public}u is invalid.", id);
    return nullptr;
}

int32_t AccessTokenInfoManager::GetHapTokenDlpType(AccessTokenID id)
{
    Utils::UniqueReadGuard<Utils::RWLock> infoGuard(this->hapTokenInfoLock_);
    auto iter = hapTokenInfoMap_.find(id);
    if ((iter != hapTokenInfoMap_.end()) && (iter->second != nullptr)) {
        return iter->second->GetDlpType();
    }
    ACCESSTOKEN_LOG_ERROR(LABEL, "token %{public}u is invalid.", id);
    return BUTT_DLP_TYPE;
}

bool AccessTokenInfoManager::IsTokenIdExist(AccessTokenID id)
{
    {
        Utils::UniqueReadGuard<Utils::RWLock> infoGuard(this->hapTokenInfoLock_);
        if (hapTokenInfoMap_.count(id) != 0) {
            return true;
        }
    }
    {
        Utils::UniqueReadGuard<Utils::RWLock> infoGuard(this->nativeTokenInfoLock_);
        if (nativeTokenInfoMap_.count(id) != 0) {
            return true;
        }
    }
    return false;
}

int AccessTokenInfoManager::GetHapTokenInfo(AccessTokenID tokenID, HapTokenInfo& info)
{
    std::shared_ptr<HapTokenInfoInner> infoPtr = GetHapTokenInfoInner(tokenID);
    if (infoPtr == nullptr) {
        ACCESSTOKEN_LOG_ERROR(
            LABEL, "token %{public}u is invalid.", tokenID);
        return AccessTokenError::ERR_TOKENID_NOT_EXIST;
    }
    infoPtr->TranslateToHapTokenInfo(info);
    return RET_SUCCESS;
}

std::shared_ptr<PermissionPolicySet> AccessTokenInfoManager::GetHapPermissionPolicySet(AccessTokenID id)
{
    std::shared_ptr<HapTokenInfoInner> infoPtr = GetHapTokenInfoInner(id);
    if (infoPtr == nullptr) {
        ACCESSTOKEN_LOG_ERROR(
            LABEL, "token %{public}u is invalid.", id);
        return nullptr;
    }
    return infoPtr->GetHapInfoPermissionPolicySet();
}

std::shared_ptr<NativeTokenInfoInner> AccessTokenInfoManager::GetNativeTokenInfoInner(AccessTokenID id)
{
    Utils::UniqueReadGuard<Utils::RWLock> infoGuard(this->nativeTokenInfoLock_);
    auto iter = nativeTokenInfoMap_.find(id);
    if (iter != nativeTokenInfoMap_.end()) {
        return iter->second;
    }

    ACCESSTOKEN_LOG_ERROR(LABEL, "token %{public}u is invalid.", id);
    return nullptr;
}

int AccessTokenInfoManager::GetNativeTokenInfo(AccessTokenID tokenID, NativeTokenInfo& infoParcel)
{
    std::shared_ptr<NativeTokenInfoInner> infoPtr = GetNativeTokenInfoInner(tokenID);
    if (infoPtr == nullptr) {
        ACCESSTOKEN_LOG_ERROR(
            LABEL, "token %{public}u is invalid.", tokenID);
        return AccessTokenError::ERR_TOKENID_NOT_EXIST;
    }

    infoPtr->TranslateToNativeTokenInfo(infoParcel);
    return RET_SUCCESS;
}

std::shared_ptr<PermissionPolicySet> AccessTokenInfoManager::GetNativePermissionPolicySet(AccessTokenID id)
{
    std::shared_ptr<NativeTokenInfoInner> infoPtr = GetNativeTokenInfoInner(id);
    if (infoPtr == nullptr) {
        ACCESSTOKEN_LOG_ERROR(
            LABEL, "token %{public}u is invalid.", id);
        return nullptr;
    }
    return infoPtr->GetNativeInfoPermissionPolicySet();
}

int AccessTokenInfoManager::RemoveHapTokenInfo(AccessTokenID id)
{
    ATokenTypeEnum type = AccessTokenIDManager::GetInstance().GetTokenIdType(id);
    if (type != TOKEN_HAP) {
        ACCESSTOKEN_LOG_ERROR(
            LABEL, "token %{public}u is not hap.", id);
        return ERR_PARAM_INVALID;
    }
    std::shared_ptr<HapTokenInfoInner> info;
    // make sure that RemoveDefPermissions is called outside of the lock to avoid deadlocks.
    PermissionManager::GetInstance().RemoveDefPermissions(id);
    {
        Utils::UniqueWriteGuard<Utils::RWLock> infoGuard(this->hapTokenInfoLock_);
        if (hapTokenInfoMap_.count(id) == 0) {
            ACCESSTOKEN_LOG_ERROR(LABEL, "hap token %{public}u no exist.", id);
            return ERR_TOKENID_NOT_EXIST;
        }

        info = hapTokenInfoMap_[id];
        if (info == nullptr) {
            ACCESSTOKEN_LOG_ERROR(LABEL, "hap token %{public}u is null.", id);
            return ERR_TOKEN_INVALID;
        }
        if (info->IsRemote()) {
            ACCESSTOKEN_LOG_ERROR(LABEL, "remote hap token %{public}u can not delete.", id);
            return ERR_IDENTITY_CHECK_FAILED;
        }
        std::string HapUniqueKey = GetHapUniqueStr(info);
        auto iter = hapTokenIdMap_.find(HapUniqueKey);
        if ((iter != hapTokenIdMap_.end()) && (iter->second == id)) {
            hapTokenIdMap_.erase(HapUniqueKey);
        }
        hapTokenInfoMap_.erase(id);
    }

    AccessTokenIDManager::GetInstance().ReleaseTokenId(id);
    ACCESSTOKEN_LOG_INFO(LABEL, "remove hap token %{public}u ok!", id);
    RemoveHapTokenInfoFromDb(id);
    // remove hap to kernel
    PermissionManager::GetInstance().RemovePermFromKernel(id);
    PermissionStateNotify(info, id);
#ifdef TOKEN_SYNC_ENABLE
    TokenModifyNotifier::GetInstance().NotifyTokenDelete(id);
#endif

    HiSysEventWrite(HiviewDFX::HiSysEvent::Domain::ACCESS_TOKEN, "DEL_HAP", HiviewDFX::HiSysEvent::EventType::STATISTIC,
        "TOKENID", info->GetTokenID(), "USERID", info->GetUserID(), "BUNDLENAME", info->GetBundleName(),
        "INSTINDEX", info->GetInstIndex());

    return RET_SUCCESS;
}

int AccessTokenInfoManager::RemoveNativeTokenInfo(AccessTokenID id)
{
    ATokenTypeEnum type = AccessTokenIDManager::GetInstance().GetTokenIdType(id);
    if ((type != TOKEN_NATIVE) && (type != TOKEN_SHELL)) {
        ACCESSTOKEN_LOG_ERROR(
            LABEL, "token %{public}u is not hap.", id);
        return ERR_PARAM_INVALID;
    }

    {
        Utils::UniqueWriteGuard<Utils::RWLock> infoGuard(this->nativeTokenInfoLock_);
        if (nativeTokenInfoMap_.count(id) == 0) {
            ACCESSTOKEN_LOG_ERROR(LABEL, "native token %{public}u is null.", id);
            return ERR_TOKENID_NOT_EXIST;
        }

        std::shared_ptr<NativeTokenInfoInner> info = nativeTokenInfoMap_[id];
        if (info->IsRemote()) {
            ACCESSTOKEN_LOG_ERROR(LABEL, "remote native token %{public}u can not delete.", id);
            return ERR_TOKEN_INVALID;
        }
        std::string processName = nativeTokenInfoMap_[id]->GetProcessName();
        if (nativeTokenIdMap_.count(processName) != 0) {
            nativeTokenIdMap_.erase(processName);
        }
        nativeTokenInfoMap_.erase(id);
    }
    AccessTokenIDManager::GetInstance().ReleaseTokenId(id);
    ACCESSTOKEN_LOG_INFO(LABEL, "remove native token %{public}u ok!", id);
    RefreshTokenInfoIfNeeded();
    // remove native to kernel
    PermissionManager::GetInstance().RemovePermFromKernel(id);
    return RET_SUCCESS;
}

#ifdef SUPPORT_SANDBOX_APP
static void GetPolicyCopied(const HapPolicyParams& policy, HapPolicyParams& policyNew)
{
    policyNew.apl = policy.apl;
    policyNew.domain = policy.domain;

    for (const auto& state : policy.permStateList) {
        policyNew.permStateList.emplace_back(state);
    }
    for (const auto& def : policy.permList) {
        policyNew.permList.emplace_back(def);
    }
}
#endif

int AccessTokenInfoManager::CreateHapTokenInfo(
    const HapInfoParams& info, const HapPolicyParams& policy, AccessTokenIDEx& tokenIdEx)
{
    if ((!DataValidator::IsUserIdValid(info.userID)) || (!DataValidator::IsBundleNameValid(info.bundleName)) ||
        (!DataValidator::IsAppIDDescValid(info.appIDDesc)) || (!DataValidator::IsDomainValid(policy.domain)) ||
        (!DataValidator::IsDlpTypeValid(info.dlpType))) {
        ACCESSTOKEN_LOG_ERROR(LABEL, "hap token param failed");
        return AccessTokenError::ERR_PARAM_INVALID;
    }
    AccessTokenID tokenId = AccessTokenIDManager::GetInstance().CreateAndRegisterTokenId(TOKEN_HAP, info.dlpType);
    if (tokenId == 0) {
        ACCESSTOKEN_LOG_INFO(LABEL, "token Id create failed");
        return ERR_TOKENID_CREATE_FAILED;
    }
    PermissionManager::GetInstance().AddDefPermissions(policy.permList, tokenId, false);
#ifdef SUPPORT_SANDBOX_APP
    std::shared_ptr<HapTokenInfoInner> tokenInfo;
    if (info.dlpType != DLP_COMMON) {
        HapPolicyParams policyNew;
        GetPolicyCopied(policy, policyNew);
        DlpPermissionSetManager::GetInstance().UpdatePermStateWithDlpInfo(info.dlpType, policyNew.permStateList);
        tokenInfo = std::make_shared<HapTokenInfoInner>(tokenId, info, policyNew);
    } else {
        tokenInfo = std::make_shared<HapTokenInfoInner>(tokenId, info, policy);
    }
#else
    std::shared_ptr<HapTokenInfoInner> tokenInfo = std::make_shared<HapTokenInfoInner>(tokenId, info, policy);
#endif
    int ret = AddHapTokenInfo(tokenInfo);
    if (ret != RET_SUCCESS) {
        ACCESSTOKEN_LOG_ERROR(LABEL, "%{public}s add token info failed", info.bundleName.c_str());
        AccessTokenIDManager::GetInstance().ReleaseTokenId(tokenId);
        PermissionManager::GetInstance().RemoveDefPermissions(tokenId);
        return ret;
    }
    ACCESSTOKEN_LOG_INFO(LABEL, "Create hap token %{public}u bundleName %{public}s user %{public}d inst %{public}d ok",
        tokenId, tokenInfo->GetBundleName().c_str(), tokenInfo->GetUserID(), tokenInfo->GetInstIndex());
    AllocAccessTokenIDEx(info, tokenId, tokenIdEx);
    AddHapTokenInfoToDb(tokenId);
    return RET_SUCCESS;
}

int AccessTokenInfoManager::AllocAccessTokenIDEx(
    const HapInfoParams& info, AccessTokenID tokenId, AccessTokenIDEx& tokenIdEx)
{
    tokenIdEx.tokenIdExStruct.tokenID = tokenId;
    if (info.isSystemApp) {
        tokenIdEx.tokenIdExStruct.tokenAttr |= SYSTEM_APP_FLAG;
    }
    return RET_SUCCESS;
}

int AccessTokenInfoManager::CheckNativeDCap(AccessTokenID tokenID, const std::string& dcap)
{
    std::shared_ptr<NativeTokenInfoInner> infoPtr = GetNativeTokenInfoInner(tokenID);
    if (infoPtr == nullptr) {
        ACCESSTOKEN_LOG_ERROR(
            LABEL, "token %{public}u is invalid.", tokenID);
        return ERR_TOKENID_NOT_EXIST;
    }

    std::vector<std::string> dcaps = infoPtr->GetDcap();
    for (auto iter = dcaps.begin(); iter != dcaps.end(); iter++) {
        if (*iter == dcap) {
            return RET_SUCCESS;
        }
    }
    return ERR_CHECK_DCAP_FAIL;
}

AccessTokenIDEx AccessTokenInfoManager::GetHapTokenID(int32_t userID, const std::string& bundleName, int32_t instIndex)
{
    Utils::UniqueReadGuard<Utils::RWLock> infoGuard(this->hapTokenInfoLock_);
    std::string HapUniqueKey = GetHapUniqueStr(userID, bundleName, instIndex);
    AccessTokenIDEx tokenIdEx = {0};
    auto iter = hapTokenIdMap_.find(HapUniqueKey);
    if (iter != hapTokenIdMap_.end()) {
        AccessTokenID tokenId = iter->second;
        auto infoIter = hapTokenInfoMap_.find(tokenId);
        if (infoIter != hapTokenInfoMap_.end()) {
            if (infoIter->second == nullptr) {
                ACCESSTOKEN_LOG_ERROR(LABEL, "HapTokenInfoInner is nullptr");
                return tokenIdEx;
            }
            HapTokenInfo info = infoIter->second->GetHapInfoBasic();
            tokenIdEx.tokenIdExStruct.tokenID = info.tokenID;
            tokenIdEx.tokenIdExStruct.tokenAttr = info.tokenAttr;
        }
    }
    return tokenIdEx;
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

    // add native to kernel
    std::shared_ptr<PermissionPolicySet> policySet = infoPtr->GetNativeInfoPermissionPolicySet();
    PermissionManager::GetInstance().AddPermToKernel(id, policySet);
    return true;
}

void AccessTokenInfoManager::ProcessNativeTokenInfos(
    const std::vector<std::shared_ptr<NativeTokenInfoInner>>& tokenInfos)
{
    for (const auto& infoPtr: tokenInfos) {
        if (infoPtr == nullptr) {
            ACCESSTOKEN_LOG_WARN(LABEL, "token info from libat is null");
            continue;
        }
        bool isUpdated = TryUpdateExistNativeToken(infoPtr);
        if (!isUpdated) {
            ACCESSTOKEN_LOG_INFO(LABEL,
                "token %{public}u process name %{public}s is new, add to manager!",
                infoPtr->GetTokenID(), infoPtr->GetProcessName().c_str());
            AccessTokenID id = infoPtr->GetTokenID();
            ATokenTypeEnum type = AccessTokenIDManager::GetInstance().GetTokenIdTypeEnum(id);
            int ret = AccessTokenIDManager::GetInstance().RegisterTokenId(id, type);
            if (ret != RET_SUCCESS) {
                ACCESSTOKEN_LOG_ERROR(LABEL, "token Id register fail");
                continue;
            }
            ret = AddNativeTokenInfo(infoPtr);
            if (ret != RET_SUCCESS) {
                AccessTokenIDManager::GetInstance().ReleaseTokenId(id);
                ACCESSTOKEN_LOG_ERROR(LABEL,
                    "token %{public}u process name %{public}s add to manager failed!",
                    infoPtr->GetTokenID(), infoPtr->GetProcessName().c_str());
            }
        }
    }
    AddAllNativeTokenInfoToDb();
}

int32_t AccessTokenInfoManager::UpdateHapToken(AccessTokenIDEx& tokenIdEx, const UpdateHapInfoParams& info,
    const std::vector<PermissionStateFull>& permStateList, ATokenAplEnum apl,
    const std::vector<PermissionDef>& permList)
{
    AccessTokenID tokenID = tokenIdEx.tokenIdExStruct.tokenID;
    if (!DataValidator::IsAppIDDescValid(info.appIDDesc)) {
        ACCESSTOKEN_LOG_INFO(LABEL, "token %{public}u parm format error!", tokenID);
        return AccessTokenError::ERR_PARAM_INVALID;
    }
    std::shared_ptr<HapTokenInfoInner> infoPtr = GetHapTokenInfoInner(tokenID);
    if (infoPtr == nullptr) {
        ACCESSTOKEN_LOG_INFO(LABEL, "token %{public}u is null, can not update!", tokenID);
        return AccessTokenError::ERR_TOKENID_NOT_EXIST;
    }

    if (infoPtr->IsRemote()) {
        ACCESSTOKEN_LOG_ERROR(LABEL, "remote hap token %{public}u can not update!", tokenID);
        return ERR_IDENTITY_CHECK_FAILED;
    }
    if (info.isSystemApp) {
        tokenIdEx.tokenIdExStruct.tokenAttr |= SYSTEM_APP_FLAG;
    } else {
        tokenIdEx.tokenIdExStruct.tokenAttr &= ~SYSTEM_APP_FLAG;
    }
    {
        Utils::UniqueWriteGuard<Utils::RWLock> infoGuard(this->hapTokenInfoLock_);
        infoPtr->Update(info, permStateList, apl);
        ACCESSTOKEN_LOG_INFO(LABEL,
            "token %{public}u bundle name %{public}s user %{public}d inst %{public}d tokenAttr %{public}d update ok!",
            tokenID, infoPtr->GetBundleName().c_str(), infoPtr->GetUserID(), infoPtr->GetInstIndex(),
            infoPtr->GetHapInfoBasic().tokenAttr);
    }
    PermissionManager::GetInstance().AddDefPermissions(permList, tokenID, true);
#ifdef TOKEN_SYNC_ENABLE
    TokenModifyNotifier::GetInstance().NotifyTokenModify(tokenID);
#endif
    // update hap to kernel
    std::shared_ptr<PermissionPolicySet> policySet = infoPtr->GetHapInfoPermissionPolicySet();
    PermissionManager::GetInstance().AddPermToKernel(tokenID, policySet);
    ModifyHapTokenInfoFromDb(tokenID);
    return RET_SUCCESS;
}

#ifdef TOKEN_SYNC_ENABLE
int AccessTokenInfoManager::GetHapTokenSync(AccessTokenID tokenID, HapTokenInfoForSync& hapSync)
{
    std::shared_ptr<HapTokenInfoInner> infoPtr = GetHapTokenInfoInner(tokenID);
    if (infoPtr == nullptr || infoPtr->IsRemote()) {
        ACCESSTOKEN_LOG_ERROR(
            LABEL, "token %{public}u is invalid.", tokenID);
        return ERR_IDENTITY_CHECK_FAILED;
    }
    hapSync.baseInfo = infoPtr->GetHapInfoBasic();
    std::shared_ptr<PermissionPolicySet> permSetPtr = infoPtr->GetHapInfoPermissionPolicySet();
    if (permSetPtr == nullptr) {
        ACCESSTOKEN_LOG_ERROR(
            LABEL, "token %{public}u permSet is invalid.", tokenID);
        return ERR_TOKEN_INVALID;
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

void AccessTokenInfoManager::GetAllNativeTokenInfo(
    std::vector<NativeTokenInfoForSync>& nativeTokenInfosRes)
{
    Utils::UniqueReadGuard<Utils::RWLock> infoGuard(this->nativeTokenInfoLock_);
    for (const auto& nativeTokenInner : nativeTokenInfoMap_) {
        std::shared_ptr<NativeTokenInfoInner> nativeTokenInnerPtr = nativeTokenInner.second;
        if (nativeTokenInnerPtr == nullptr || nativeTokenInnerPtr->IsRemote()
            || nativeTokenInnerPtr->GetDcap().empty()) {
            continue;
        }
        NativeTokenInfoForSync token;
        nativeTokenInnerPtr->TranslateToNativeTokenInfo(token.baseInfo);

        std::shared_ptr<PermissionPolicySet> permSetPtr =
            nativeTokenInnerPtr->GetNativeInfoPermissionPolicySet();
        if (permSetPtr == nullptr) {
            ACCESSTOKEN_LOG_ERROR(
                LABEL, "token %{public}u permSet is invalid.", token.baseInfo.tokenID);
            return;
        }
        permSetPtr->GetPermissionStateList(token.permStateList);

        nativeTokenInfosRes.emplace_back(token);
    }
    return;
}

int AccessTokenInfoManager::UpdateRemoteHapTokenInfo(AccessTokenID mapID, HapTokenInfoForSync& hapSync)
{
    std::shared_ptr<HapTokenInfoInner> infoPtr = GetHapTokenInfoInner(mapID);
    if (infoPtr == nullptr || !infoPtr->IsRemote()) {
        ACCESSTOKEN_LOG_INFO(LABEL, "token %{public}u is null or not remote, can not update!", mapID);
        return ERR_IDENTITY_CHECK_FAILED;
    }

    std::shared_ptr<PermissionPolicySet> newPermPolicySet =
        PermissionPolicySet::BuildPolicySetWithoutDefCheck(mapID, hapSync.permStateList);

    {
        Utils::UniqueWriteGuard<Utils::RWLock> infoGuard(this->hapTokenInfoLock_);
        infoPtr->SetTokenBaseInfo(hapSync.baseInfo);
        infoPtr->SetPermissionPolicySet(newPermPolicySet);
    }
    // update remote hap to kernel
    PermissionManager::GetInstance().AddPermToKernel(mapID, newPermPolicySet);
    return RET_SUCCESS;
}

int AccessTokenInfoManager::CreateRemoteHapTokenInfo(AccessTokenID mapID, HapTokenInfoForSync& hapSync)
{
    std::shared_ptr<HapTokenInfoInner> hap = std::make_shared<HapTokenInfoInner>(mapID, hapSync);
    hap->SetRemote(true);

    int ret = AddHapTokenInfo(hap);
    if (ret != RET_SUCCESS) {
        ACCESSTOKEN_LOG_ERROR(LABEL, "add local token failed.");
        return ret;
    }

    return RET_SUCCESS;
}

bool AccessTokenInfoManager::IsRemoteHapTokenValid(const std::string& deviceID, const HapTokenInfoForSync& hapSync)
{
    std::string errReason;
    if (!DataValidator::IsDeviceIdValid(deviceID) || !DataValidator::IsDeviceIdValid(hapSync.baseInfo.deviceID)) {
        errReason = "respond deviceID error";
    } else if (!DataValidator::IsUserIdValid(hapSync.baseInfo.userID)) {
        errReason = "respond userID error";
    } else if (!DataValidator::IsBundleNameValid(hapSync.baseInfo.bundleName)) {
        errReason = "respond bundleName error";
    } else if (!DataValidator::IsAplNumValid(hapSync.baseInfo.apl)) {
        errReason = "respond apl error";
    } else if (!DataValidator::IsTokenIDValid(hapSync.baseInfo.tokenID)) {
        errReason = "respond tokenID error";
    } else if (!DataValidator::IsAppIDDescValid(hapSync.baseInfo.appID)) {
        errReason = "respond appID error";
    } else if (!DataValidator::IsDlpTypeValid(hapSync.baseInfo.dlpType)) {
        errReason = "respond dlpType error";
    } else if (hapSync.baseInfo.ver != DEFAULT_TOKEN_VERSION) {
        errReason = "respond version error";
    } else if (AccessTokenIDManager::GetInstance().GetTokenIdTypeEnum(hapSync.baseInfo.tokenID) != TOKEN_HAP) {
        errReason = "respond token type error";
    } else {
        return true;
    }

    HiSysEventWrite(HiviewDFX::HiSysEvent::Domain::ACCESS_TOKEN, "PERMISSION_SYNC",
        HiviewDFX::HiSysEvent::EventType::FAULT, "CODE", TOKEN_SYNC_RESPONSE_ERROR,
        "REMOTE_ID", ConstantCommon::EncryptDevId(deviceID), "ERROR_REASON", errReason);
    return false;
}

int AccessTokenInfoManager::SetRemoteHapTokenInfo(const std::string& deviceID, HapTokenInfoForSync& hapSync)
{
    if (!IsRemoteHapTokenValid(deviceID, hapSync)) {
        ACCESSTOKEN_LOG_ERROR(LABEL, "device %{public}s parms invalid", ConstantCommon::EncryptDevId(deviceID).c_str());
        return ERR_IDENTITY_CHECK_FAILED;
    }

    AccessTokenID remoteID = hapSync.baseInfo.tokenID;
    AccessTokenID mapID = AccessTokenRemoteTokenManager::GetInstance().GetDeviceMappingTokenID(deviceID, remoteID);
    if (mapID != 0) {
        ACCESSTOKEN_LOG_INFO(LABEL, "device %{public}s token %{public}u update exist remote hap token %{public}u.",
            ConstantCommon::EncryptDevId(deviceID).c_str(), remoteID, mapID);
        // update remote token mapping id
        hapSync.baseInfo.tokenID = mapID;
        hapSync.baseInfo.deviceID = deviceID;
        return UpdateRemoteHapTokenInfo(mapID, hapSync);
    }

    mapID = AccessTokenRemoteTokenManager::GetInstance().MapRemoteDeviceTokenToLocal(deviceID, remoteID);
    if (mapID == 0) {
        ACCESSTOKEN_LOG_ERROR(LABEL, "device %{public}s token %{public}u map failed.",
            ConstantCommon::EncryptDevId(deviceID).c_str(), remoteID);
        return ERR_TOKEN_MAP_FAILED;
    }

    // update remote token mapping id
    hapSync.baseInfo.tokenID = mapID;
    hapSync.baseInfo.deviceID = deviceID;
    int ret = CreateRemoteHapTokenInfo(mapID, hapSync);
    if (ret != RET_SUCCESS) {
        AccessTokenRemoteTokenManager::GetInstance().RemoveDeviceMappingTokenID(deviceID, mapID);
        ACCESSTOKEN_LOG_INFO(LABEL, "device %{public}s token %{public}u map to local token %{public}u failed.",
            ConstantCommon::EncryptDevId(deviceID).c_str(), remoteID, mapID);
        return ret;
    }
    ACCESSTOKEN_LOG_INFO(LABEL, "device %{public}s token %{public}u map to local token %{public}u success.",
        ConstantCommon::EncryptDevId(deviceID).c_str(), remoteID, mapID);
    return RET_SUCCESS;
}

int AccessTokenInfoManager::SetRemoteNativeTokenInfo(const std::string& deviceID,
    std::vector<NativeTokenInfoForSync>& nativeTokenInfoList)
{
    if (!DataValidator::IsDeviceIdValid(deviceID)) {
        ACCESSTOKEN_LOG_ERROR(LABEL, "device %{public}s parms invalid", ConstantCommon::EncryptDevId(deviceID).c_str());
        return AccessTokenError::ERR_PARAM_INVALID;
    }

    for (NativeTokenInfoForSync& nativeToken : nativeTokenInfoList) {
        AccessTokenID remoteID = nativeToken.baseInfo.tokenID;
        auto encryptDevId = ConstantCommon::EncryptDevId(deviceID);
        ATokenTypeEnum type = AccessTokenIDManager::GetInstance().GetTokenIdTypeEnum(remoteID);
        if (!DataValidator::IsAplNumValid(nativeToken.baseInfo.apl) ||
            nativeToken.baseInfo.ver != DEFAULT_TOKEN_VERSION ||
            !DataValidator::IsProcessNameValid(nativeToken.baseInfo.processName) ||
            nativeToken.baseInfo.dcap.empty() ||
            (type != TOKEN_NATIVE && type != TOKEN_SHELL)) {
            ACCESSTOKEN_LOG_ERROR(LABEL, "device %{public}s token %{public}u is invalid.",
                encryptDevId.c_str(), remoteID);
            continue;
        }

        AccessTokenID mapID = AccessTokenRemoteTokenManager::GetInstance().GetDeviceMappingTokenID(deviceID, remoteID);
        if (mapID != 0) {
            ACCESSTOKEN_LOG_ERROR(LABEL, "device %{public}s token %{public}u has maped, no need update it.",
                encryptDevId.c_str(), remoteID);
            continue;
        }

        mapID = AccessTokenRemoteTokenManager::GetInstance().MapRemoteDeviceTokenToLocal(deviceID, remoteID);
        if (mapID == 0) {
            AccessTokenRemoteTokenManager::GetInstance().RemoveDeviceMappingTokenID(deviceID, mapID);
            ACCESSTOKEN_LOG_ERROR(LABEL, "device %{public}s token %{public}u map failed.",
                encryptDevId.c_str(), remoteID);
            continue;
        }
        nativeToken.baseInfo.tokenID = mapID;
        ACCESSTOKEN_LOG_INFO(LABEL, "device %{public}s token %{public}u map to local token %{public}u.",
            encryptDevId.c_str(), remoteID, mapID);

        std::shared_ptr<NativeTokenInfoInner> nativePtr =
            std::make_shared<NativeTokenInfoInner>(nativeToken.baseInfo, nativeToken.permStateList);
        nativePtr->SetRemote(true);
        int ret = AddNativeTokenInfo(nativePtr);
        if (ret != RET_SUCCESS) {
            AccessTokenRemoteTokenManager::GetInstance().RemoveDeviceMappingTokenID(deviceID, mapID);
            ACCESSTOKEN_LOG_ERROR(LABEL, "device %{public}s tokenId %{public}u add local token failed.",
                encryptDevId.c_str(), remoteID);
            continue;
        }
        ACCESSTOKEN_LOG_INFO(LABEL, "device %{public}s token %{public}u map token %{public}u add success.",
            encryptDevId.c_str(), remoteID, mapID);
    }

    return RET_SUCCESS;
}

int AccessTokenInfoManager::DeleteRemoteToken(const std::string& deviceID, AccessTokenID tokenID)
{
    if (!DataValidator::IsDeviceIdValid(deviceID)) {
        ACCESSTOKEN_LOG_ERROR(LABEL, "device %{public}s parms invalid", ConstantCommon::EncryptDevId(deviceID).c_str());
        return AccessTokenError::ERR_PARAM_INVALID;
    }
    AccessTokenID mapID = AccessTokenRemoteTokenManager::GetInstance().GetDeviceMappingTokenID(deviceID, tokenID);
    if (mapID == 0) {
        ACCESSTOKEN_LOG_ERROR(LABEL, "device %{public}s tokenId %{public}u is not mapped",
            ConstantCommon::EncryptDevId(deviceID).c_str(), tokenID);
        return ERR_TOKEN_MAP_FAILED;
    }

    ATokenTypeEnum type = AccessTokenIDManager::GetInstance().GetTokenIdTypeEnum(mapID);
    if (type == TOKEN_HAP) {
        Utils::UniqueWriteGuard<Utils::RWLock> infoGuard(this->hapTokenInfoLock_);
        if (hapTokenInfoMap_.count(mapID) == 0) {
            ACCESSTOKEN_LOG_ERROR(LABEL, "hap token %{public}u no exist.", mapID);
            return ERR_TOKEN_INVALID;
        }
        hapTokenInfoMap_.erase(mapID);
    } else if ((type == TOKEN_NATIVE) || (type == TOKEN_SHELL)) {
        Utils::UniqueWriteGuard<Utils::RWLock> infoGuard(this->nativeTokenInfoLock_);
        if (nativeTokenInfoMap_.count(mapID) == 0) {
            ACCESSTOKEN_LOG_ERROR(
                LABEL, "native token %{public}u is null.", mapID);
            return ERR_TOKEN_INVALID;
        }
        nativeTokenInfoMap_.erase(mapID);
    } else {
        ACCESSTOKEN_LOG_ERROR(LABEL, "mapping tokenId %{public}u type is unknown", mapID);
    }

    return AccessTokenRemoteTokenManager::GetInstance().RemoveDeviceMappingTokenID(deviceID, tokenID);
}

AccessTokenID AccessTokenInfoManager::GetRemoteNativeTokenID(const std::string& deviceID, AccessTokenID tokenID)
{
    if ((!DataValidator::IsDeviceIdValid(deviceID)) || (tokenID == 0) ||
        ((AccessTokenIDManager::GetInstance().GetTokenIdTypeEnum(tokenID) != TOKEN_NATIVE) &&
        (AccessTokenIDManager::GetInstance().GetTokenIdTypeEnum(tokenID) != TOKEN_SHELL))) {
        ACCESSTOKEN_LOG_ERROR(LABEL, "device %{public}s parms invalid", ConstantCommon::EncryptDevId(deviceID).c_str());
        return 0;
    }
    return AccessTokenRemoteTokenManager::GetInstance().GetDeviceMappingTokenID(deviceID, tokenID);
}

int AccessTokenInfoManager::DeleteRemoteDeviceTokens(const std::string& deviceID)
{
    if (!DataValidator::IsDeviceIdValid(deviceID)) {
        ACCESSTOKEN_LOG_ERROR(LABEL, "device %{public}s parms invalid", ConstantCommon::EncryptDevId(deviceID).c_str());
        return AccessTokenError::ERR_PARAM_INVALID;
    }
    std::vector<AccessTokenID> remoteTokens;
    int ret = AccessTokenRemoteTokenManager::GetInstance().GetDeviceAllRemoteTokenID(deviceID, remoteTokens);
    if (ret != RET_SUCCESS) {
        ACCESSTOKEN_LOG_ERROR(LABEL, "device %{public}s have no remote token",
            ConstantCommon::EncryptDevId(deviceID).c_str());
        return ret;
    }
    for (AccessTokenID remoteID : remoteTokens) {
        DeleteRemoteToken(deviceID, remoteID);
    }
    return RET_SUCCESS;
}

std::string AccessTokenInfoManager::GetUdidByNodeId(const std::string &nodeId)
{
    uint8_t info[UDID_MAX_LENGTH + 1] = {0};

    int32_t ret = ::GetNodeKeyInfo(
        ACCESS_TOKEN_PACKAGE_NAME.c_str(), nodeId.c_str(), NodeDeviceInfoKey::NODE_KEY_UDID, info, UDID_MAX_LENGTH);
    if (ret != RET_SUCCESS) {
        ACCESSTOKEN_LOG_WARN(LABEL, "GetNodeKeyInfo error, code: %{public}d", ret);
        return "";
    }
    std::string udid(reinterpret_cast<char *>(info));
    return udid;
}

AccessTokenID AccessTokenInfoManager::AllocLocalTokenID(const std::string& remoteDeviceID,
    AccessTokenID remoteTokenID)
{
    if (!DataValidator::IsDeviceIdValid(remoteDeviceID)) {
        ACCESSTOKEN_LOG_ERROR(LABEL, "device %{public}s parms invalid",
            ConstantCommon::EncryptDevId(remoteDeviceID).c_str());
        HiSysEventWrite(HiviewDFX::HiSysEvent::Domain::ACCESS_TOKEN, "PERMISSION_SYNC",
            HiviewDFX::HiSysEvent::EventType::FAULT, "CODE", TOKEN_SYNC_CALL_ERROR,
            "REMOTE_ID", ConstantCommon::EncryptDevId(remoteDeviceID), "ERROR_REASON", "deviceID error");
        return 0;
    }
    uint64_t fullTokenId = IPCSkeleton::GetCallingFullTokenID();
    SetFirstCallerTokenID(fullTokenId);
    ACCESSTOKEN_LOG_INFO(LABEL, "Set first caller %{public}" PRIu64 ".", fullTokenId);
    std::string remoteUdid = GetUdidByNodeId(remoteDeviceID);
    ACCESSTOKEN_LOG_INFO(LABEL, "Device %{public}s remoteUdid.", ConstantCommon::EncryptDevId(remoteUdid).c_str());
    AccessTokenID mapID = AccessTokenRemoteTokenManager::GetInstance().GetDeviceMappingTokenID(remoteUdid,
        remoteTokenID);
    if (mapID != 0) {
        return mapID;
    }
    int ret = TokenModifyNotifier::GetInstance().GetRemoteHapTokenInfo(remoteUdid, remoteTokenID);
    if (ret != RET_SUCCESS) {
        ACCESSTOKEN_LOG_ERROR(LABEL, "device %{public}s token %{public}u sync failed",
            ConstantCommon::EncryptDevId(remoteUdid).c_str(), remoteTokenID);
        std::string errorReason = "token sync call error, error number is " + std::to_string(ret);
        HiSysEventWrite(HiviewDFX::HiSysEvent::Domain::ACCESS_TOKEN, "PERMISSION_SYNC",
            HiviewDFX::HiSysEvent::EventType::FAULT, "CODE", TOKEN_SYNC_CALL_ERROR,
            "REMOTE_ID", ConstantCommon::EncryptDevId(remoteDeviceID), "ERROR_REASON", errorReason);
        return 0;
    }

    return AccessTokenRemoteTokenManager::GetInstance().GetDeviceMappingTokenID(remoteUdid, remoteTokenID);
}
#else
AccessTokenID AccessTokenInfoManager::AllocLocalTokenID(const std::string& remoteDeviceID,
    AccessTokenID remoteTokenID)
{
    ACCESSTOKEN_LOG_ERROR(LABEL, "tokensync is disable, check dependent components");
    return 0;
}
#endif

AccessTokenInfoManager& AccessTokenInfoManager::GetInstance()
{
    static AccessTokenInfoManager* instance = nullptr;
    if (instance == nullptr) {
        std::lock_guard<std::recursive_mutex> lock(g_instanceMutex);
        if (instance == nullptr) {
            instance = new AccessTokenInfoManager();
        }
    }
    return *instance;
}

void AccessTokenInfoManager::StoreAllTokenInfo()
{
    std::vector<GenericValues> hapInfoValues;
    std::vector<GenericValues> permDefValues;
    std::vector<GenericValues> permStateValues;
    std::vector<GenericValues> nativeTokenValues;
    uint64_t lastestUpdateStamp = 0;
    {
        Utils::UniqueReadGuard<Utils::RWLock> infoGuard(this->hapTokenInfoLock_);
        for (auto iter = hapTokenInfoMap_.begin(); iter != hapTokenInfoMap_.end(); iter++) {
            if (iter->second != nullptr) {
                std::shared_ptr<HapTokenInfoInner>& hapInfo = iter->second;
                hapInfo->StoreHapInfo(hapInfoValues);
                hapInfo->StorePermissionPolicy(permStateValues);
                if (hapInfo->permUpdateTimestamp_ > lastestUpdateStamp) {
                    lastestUpdateStamp = hapInfo->permUpdateTimestamp_;
                }
            }
        }
    }

    {
        Utils::UniqueReadGuard<Utils::RWLock> infoGuard(this->nativeTokenInfoLock_);
        for (auto iter = nativeTokenInfoMap_.begin(); iter != nativeTokenInfoMap_.end(); iter++) {
            if (iter->second != nullptr) {
                iter->second->StoreNativeInfo(nativeTokenValues);
                iter->second->StorePermissionPolicy(permStateValues);
            }
        }
    }

    PermissionDefinitionCache::GetInstance().StorePermissionDef(permDefValues);

    AccessTokenDb::GetInstance().RefreshAll(AccessTokenDb::ACCESSTOKEN_HAP_INFO, hapInfoValues);
    AccessTokenDb::GetInstance().RefreshAll(AccessTokenDb::ACCESSTOKEN_NATIVE_INFO, nativeTokenValues);
    AccessTokenDb::GetInstance().RefreshAll(AccessTokenDb::ACCESSTOKEN_PERMISSION_DEF, permDefValues);
    int res = AccessTokenDb::GetInstance().RefreshAll(AccessTokenDb::ACCESSTOKEN_PERMISSION_STATE, permStateValues);
    PermissionManager::GetInstance().NotifyPermGrantStoreResult((res == 0), lastestUpdateStamp);
}

int AccessTokenInfoManager::AddAllNativeTokenInfoToDb(void)
{
    std::vector<GenericValues> permStateValues;
    std::vector<GenericValues> nativeTokenValues;

    Utils::UniqueReadGuard<Utils::RWLock> infoGuard(this->nativeTokenInfoLock_);
    for (auto iter = nativeTokenInfoMap_.begin(); iter != nativeTokenInfoMap_.end(); iter++) {
        if (iter->second != nullptr) {
            iter->second->StoreNativeInfo(nativeTokenValues);
            iter->second->StorePermissionPolicy(permStateValues);
        }
    }
    AccessTokenDb::GetInstance().Add(AccessTokenDb::ACCESSTOKEN_PERMISSION_STATE, permStateValues);
    AccessTokenDb::GetInstance().Add(AccessTokenDb::ACCESSTOKEN_NATIVE_INFO, nativeTokenValues);
    return RET_SUCCESS;
}

int AccessTokenInfoManager::ModifyHapTokenInfoFromDb(AccessTokenID tokenID)
{
    Utils::UniqueWriteGuard<Utils::RWLock> infoGuard(this->modifyLock_);
    RemoveHapTokenInfoFromDb(tokenID);
    return AddHapTokenInfoToDb(tokenID);
}

int32_t AccessTokenInfoManager::ModifyHapPermStateFromDb(AccessTokenID tokenID, const std::string& permission)
{
    std::vector<GenericValues> permStateValues;
    Utils::UniqueWriteGuard<Utils::RWLock> infoGuard(this->modifyLock_);
    std::shared_ptr<HapTokenInfoInner> hapInfo = GetHapTokenInfoInner(tokenID);
    if (hapInfo == nullptr) {
        ACCESSTOKEN_LOG_INFO(LABEL, "token %{public}u info is null!", tokenID);
        return AccessTokenError::ERR_TOKENID_NOT_EXIST;
    }
    hapInfo->StorePermissionPolicy(permStateValues);

    for (size_t i = 0; i < permStateValues.size(); i++) {
        if (permStateValues[i].GetString(TokenFiledConst::FIELD_PERMISSION_NAME) != permission) {
            continue;
        }
        GenericValues conditions;
        conditions.Put(TokenFiledConst::FIELD_TOKEN_ID, static_cast<int32_t>(tokenID));
        conditions.Put(TokenFiledConst::FIELD_PERMISSION_NAME, permission);
        AccessTokenDb::GetInstance().Modify(
            AccessTokenDb::ACCESSTOKEN_PERMISSION_STATE, permStateValues[i], conditions);
    }
    return RET_SUCCESS;
}

int AccessTokenInfoManager::AddHapTokenInfoToDb(AccessTokenID tokenID)
{
    std::vector<GenericValues> hapInfoValues;
    std::vector<GenericValues> permDefValues;
    std::vector<GenericValues> permStateValues;

    std::shared_ptr<HapTokenInfoInner> hapInfo = GetHapTokenInfoInner(tokenID);
    if (hapInfo == nullptr) {
        ACCESSTOKEN_LOG_INFO(LABEL, "token %{public}u info is null!", tokenID);
        return AccessTokenError::ERR_TOKENID_NOT_EXIST;
    }
    hapInfo->StoreHapInfo(hapInfoValues);
    hapInfo->StorePermissionPolicy(permStateValues);

    PermissionDefinitionCache::GetInstance().StorePermissionDef(tokenID, permDefValues);
    AccessTokenDb::GetInstance().Add(AccessTokenDb::ACCESSTOKEN_HAP_INFO, hapInfoValues);
    AccessTokenDb::GetInstance().Add(AccessTokenDb::ACCESSTOKEN_PERMISSION_STATE, permStateValues);
    AccessTokenDb::GetInstance().Add(AccessTokenDb::ACCESSTOKEN_PERMISSION_DEF, permDefValues);
    return RET_SUCCESS;
}

int AccessTokenInfoManager::RemoveHapTokenInfoFromDb(AccessTokenID tokenID)
{
    GenericValues values;
    values.Put(TokenFiledConst::FIELD_TOKEN_ID, static_cast<int32_t>(tokenID));

    AccessTokenDb::GetInstance().Remove(AccessTokenDb::ACCESSTOKEN_HAP_INFO, values);
    AccessTokenDb::GetInstance().Remove(AccessTokenDb::ACCESSTOKEN_PERMISSION_DEF, values);
    AccessTokenDb::GetInstance().Remove(AccessTokenDb::ACCESSTOKEN_PERMISSION_STATE, values);
    return RET_SUCCESS;
}

#ifdef RESOURCESCHEDULE_FFRT_ENABLE
int32_t AccessTokenInfoManager::GetCurTaskNum()
{
    return curTaskNum_.load();
}

void AccessTokenInfoManager::AddCurTaskNum()
{
    curTaskNum_++;
}

void AccessTokenInfoManager::ReduceCurTaskNum()
{
    curTaskNum_--;
}
#endif

void AccessTokenInfoManager::RefreshTokenInfoIfNeeded()
{
#ifdef RESOURCESCHEDULE_FFRT_ENABLE
    if (GetCurTaskNum() > 1) {
        ACCESSTOKEN_LOG_INFO(LABEL, "has refresh task!");
        return;
    }

    auto tokenStore = []() {
        AccessTokenInfoManager::GetInstance().StoreAllTokenInfo();

        // Sleep for one second to avoid frequent refresh of the database.
        ffrt::this_task::sleep_for(std::chrono::seconds(1));
        AccessTokenInfoManager::GetInstance().ReduceCurTaskNum();
    };
    AddCurTaskNum();
    ffrtTaskQueue_->submit(tokenStore, ffrt::task_attr().qos(ffrt::qos_default));
#else
    if (tokenDataWorker_.GetCurTaskNum() > 1) {
        ACCESSTOKEN_LOG_INFO(LABEL, "has refresh task!");
        return;
    }

    tokenDataWorker_.AddTask([]() {
        AccessTokenInfoManager::GetInstance().StoreAllTokenInfo();

        // Sleep for one second to avoid frequent refresh of the database.
        std::this_thread::sleep_for(std::chrono::seconds(1));
    });
#endif
}

void AccessTokenInfoManager::PermissionStateNotify(const std::shared_ptr<HapTokenInfoInner>& info, AccessTokenID id)
{
    std::shared_ptr<PermissionPolicySet> policy = info->GetHapInfoPermissionPolicySet();
    if (policy == nullptr) {
        return;
    }

    std::vector<std::string> permissionList;
    policy->GetDeletedPermissionListToNotify(permissionList);
    if (permissionList.size() != 0) {
        PermissionManager::GetInstance().ParamUpdate(permissionList[0], 0, true);
    }
    for (const auto& permissionName : permissionList) {
        CallbackManager::GetInstance().ExecuteCallbackAsync(id, permissionName, PermStateChangeType::REVOKED);
    }
}

AccessTokenID AccessTokenInfoManager::GetNativeTokenId(const std::string& processName)
{
    AccessTokenID tokenID = INVALID_TOKENID;
    Utils::UniqueReadGuard<Utils::RWLock> infoGuard(this->nativeTokenInfoLock_);
    for (auto iter = nativeTokenInfoMap_.begin(); iter != nativeTokenInfoMap_.end(); iter++) {
        if (iter->second != nullptr && iter->second->GetProcessName() == processName) {
            tokenID = iter->first;
            break;
        }
    }
    return tokenID;
}

void AccessTokenInfoManager::DumpHapTokenInfoByTokenId(const AccessTokenID tokenId, std::string& dumpInfo)
{
    ACCESSTOKEN_LOG_DEBUG(LABEL, "get hap token info by tokenId[%{public}u].", tokenId);

    ATokenTypeEnum type = AccessTokenIDManager::GetInstance().GetTokenIdType(tokenId);
    if (type == TOKEN_HAP) {
        std::shared_ptr<HapTokenInfoInner> infoPtr = GetHapTokenInfoInner(tokenId);
        if (infoPtr != nullptr) {
            infoPtr->ToString(dumpInfo);
        }
    } else if (type == TOKEN_NATIVE || type == TOKEN_SHELL) {
        std::shared_ptr<NativeTokenInfoInner> infoPtr = GetNativeTokenInfoInner(tokenId);
        if (infoPtr != nullptr) {
            infoPtr->ToString(dumpInfo);
        }
    } else {
        dumpInfo.append("invalid tokenId");
    }
}

void AccessTokenInfoManager::DumpHapTokenInfoByBundleName(const std::string& bundleName, std::string& dumpInfo)
{
    ACCESSTOKEN_LOG_DEBUG(LABEL, "get hap token info by bundleName[%{public}s].", bundleName.c_str());

    Utils::UniqueReadGuard<Utils::RWLock> hapInfoGuard(this->hapTokenInfoLock_);
    for (auto iter = hapTokenInfoMap_.begin(); iter != hapTokenInfoMap_.end(); iter++) {
        if (iter->second != nullptr) {
            if (bundleName != iter->second->GetBundleName()) {
                continue;
            }

            iter->second->ToString(dumpInfo);
            dumpInfo.append("\n"); // probilly exsits remote hap token with the same bundleName
        }
    }
}

void AccessTokenInfoManager::DumpAllHapTokenInfo(std::string& dumpInfo)
{
    ACCESSTOKEN_LOG_DEBUG(LABEL, "get all hap token info.");

    Utils::UniqueReadGuard<Utils::RWLock> hapInfoGuard(this->hapTokenInfoLock_);
    for (auto iter = hapTokenInfoMap_.begin(); iter != hapTokenInfoMap_.end(); iter++) {
        if (iter->second != nullptr) {
            iter->second->ToString(dumpInfo);
            dumpInfo.append("\n");
        }
    }
}

void AccessTokenInfoManager::DumpNativeTokenInfoByProcessName(const std::string& processName, std::string& dumpInfo)
{
    ACCESSTOKEN_LOG_DEBUG(LABEL, "get native token info by processName[%{public}s].", processName.c_str());

    Utils::UniqueReadGuard<Utils::RWLock> infoGuard(this->nativeTokenInfoLock_);
    for (auto iter = nativeTokenInfoMap_.begin(); iter != nativeTokenInfoMap_.end(); iter++) {
        if ((iter->second != nullptr) && (processName == iter->second->GetProcessName())) {
            iter->second->ToString(dumpInfo);
            dumpInfo.append("\n");
            break;
        }
    }
}

void AccessTokenInfoManager::DumpAllNativeTokenInfo(std::string& dumpInfo)
{
    ACCESSTOKEN_LOG_DEBUG(LABEL, "get all native token info.");

    Utils::UniqueReadGuard<Utils::RWLock> infoGuard(this->nativeTokenInfoLock_);
    for (auto iter = nativeTokenInfoMap_.begin(); iter != nativeTokenInfoMap_.end(); iter++) {
        if (iter->second != nullptr) {
            iter->second->ToString(dumpInfo);
            dumpInfo.append("\n");
        }
    }
}

int32_t AccessTokenInfoManager::GetCurDumpTaskNum()
{
    return dumpTaskNum_.load();
}

void AccessTokenInfoManager::AddDumpTaskNum()
{
    dumpTaskNum_++;
}

void AccessTokenInfoManager::ReduceDumpTaskNum()
{
    dumpTaskNum_--;
}

void AccessTokenInfoManager::DumpToken()
{
    ACCESSTOKEN_LOG_INFO(LABEL, "AccessToken Dump");
    int32_t fd = open(DUMP_JSON_PATH.c_str(), O_RDWR | O_CREAT, S_IRUSR | S_IWUSR | S_IRGRP);
    if (fd < 0) {
        ACCESSTOKEN_LOG_ERROR(LABEL, "open failed errno %{public}d.", errno);
        return;
    }
    std::string dumpStr;
    AtmToolsParamInfoParcel infoParcel;
    DumpTokenInfo(infoParcel.info, dumpStr);
    dprintf(fd, "%s\n", dumpStr.c_str());
    close(fd);
}

void AccessTokenInfoManager::DumpTokenInfo(const AtmToolsParamInfo& info, std::string& dumpInfo)
{
    if (info.tokenId != 0) {
        DumpHapTokenInfoByTokenId(info.tokenId, dumpInfo);
        return;
    }

    if ((!info.bundleName.empty()) && (info.bundleName.length() > 0)) {
        DumpHapTokenInfoByBundleName(info.bundleName, dumpInfo);
        return;
    }

    if ((!info.processName.empty()) && (info.processName.length() > 0)) {
        DumpNativeTokenInfoByProcessName(info.processName, dumpInfo);
        return;
    }

    DumpAllHapTokenInfo(dumpInfo);
    DumpAllNativeTokenInfo(dumpInfo);
}

void AccessTokenInfoManager::GetRelatedSandBoxHapList(AccessTokenID tokenId, std::vector<AccessTokenID>& tokenIdList)
{
    Utils::UniqueReadGuard<Utils::RWLock> infoGuard(this->hapTokenInfoLock_);

    std::string bundleName;
    int32_t userID;
    auto infoIter = hapTokenInfoMap_.find(tokenId);
    if (infoIter == hapTokenInfoMap_.end()) {
        return;
    }
    if (infoIter->second == nullptr) {
        ACCESSTOKEN_LOG_ERROR(LABEL, "HapTokenInfoInner is nullptr");
        return;
    }
    bundleName = infoIter->second->GetBundleName();
    userID = infoIter->second->GetUserID();

    for (auto iter = hapTokenInfoMap_.begin(); iter != hapTokenInfoMap_.end(); ++iter) {
        if (iter->second != nullptr) {
            if ((bundleName == iter->second->GetBundleName()) && (userID == iter->second->GetUserID()) &&
                (tokenId != iter->second->GetTokenID())) {
                tokenIdList.emplace_back(iter->second->GetTokenID());
            }
        }
    }
}

int32_t AccessTokenInfoManager::SetPermDialogCap(AccessTokenID tokenID, bool enable)
{
    Utils::UniqueWriteGuard<Utils::RWLock> infoGuard(this->hapTokenInfoLock_);
    auto infoIter = hapTokenInfoMap_.find(tokenID);
    if ((infoIter == hapTokenInfoMap_.end()) || (infoIter->second == nullptr)) {
        ACCESSTOKEN_LOG_ERROR(LABEL, "HapTokenInfoInner is nullptr");
        return ERR_TOKENID_NOT_EXIST;
    }
    infoIter->second->SetPermDialogForbidden(enable);
    RefreshTokenInfoIfNeeded();
    return RET_SUCCESS;
}

bool AccessTokenInfoManager::GetPermDialogCap(AccessTokenID tokenID)
{
    if (tokenID == INVALID_TOKENID) {
        ACCESSTOKEN_LOG_ERROR(LABEL, "invaid tokenid(0)");
        return true;
    }
    Utils::UniqueReadGuard<Utils::RWLock> infoGuard(this->hapTokenInfoLock_);
    auto infoIter = hapTokenInfoMap_.find(tokenID);
    if ((infoIter == hapTokenInfoMap_.end()) || (infoIter->second == nullptr)) {
        ACCESSTOKEN_LOG_ERROR(LABEL, "tokenId is not exist in map");
        return true;
    }
    return infoIter->second->IsPermDialogForbidden();
}
} // namespace AccessToken
} // namespace Security
} // namespace OHOS
