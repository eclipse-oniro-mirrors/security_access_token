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
#include "generic_values.h"
#include "hap_token_info_inner.h"
#include "hisysevent_adapter.h"
#include "ipc_skeleton.h"
#include "permission_definition_cache.h"
#include "permission_manager.h"
#include "permission_map.h"
#include "permission_validator.h"
#include "perm_setproc.h"
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
static const unsigned int SYSTEM_APP_FLAG = 0x0001;
#ifdef TOKEN_SYNC_ENABLE
static const int MAX_PTHREAD_NAME_LEN = 15; // pthread name max length
static const std::string ACCESS_TOKEN_PACKAGE_NAME = "ohos.security.distributed_token_sync";
#endif
static const std::string DUMP_JSON_PATH = "/data/service/el1/public/access_token/nativetoken.log";
}

AccessTokenInfoManager::AccessTokenInfoManager() : hasInited_(false) {}

AccessTokenInfoManager::~AccessTokenInfoManager()
{
    if (!hasInited_) {
        return;
    }

#ifdef TOKEN_SYNC_ENABLE
    int32_t ret = DistributedHardware::DeviceManager::GetInstance().UnInitDeviceManager(ACCESS_TOKEN_PACKAGE_NAME);
    if (ret != ERR_OK) {
        ACCESSTOKEN_LOG_ERROR(LABEL, "UnInitDeviceManager failed, code: %{public}d", ret);
    }
#endif

    this->hasInited_ = false;
}

void AccessTokenInfoManager::Init()
{
    OHOS::Utils::UniqueWriteGuard<OHOS::Utils::RWLock> lk(this->managerLock_);
    if (hasInited_) {
        return;
    }

    ACCESSTOKEN_LOG_INFO(LABEL, "Init begin!");
    uint32_t hapSize = 0;
    uint32_t nativeSize = 0;
    InitHapTokenInfos(hapSize);
    InitNativeTokenInfos(nativeSize);
    uint32_t pefDefSize = PermissionDefinitionCache::GetInstance().GetDefPermissionsSize();
    ReportSysEventServiceStart(getpid(), hapSize, nativeSize, pefDefSize);
    ACCESSTOKEN_LOG_INFO(LABEL, "InitTokenInfo end, hapSize %{public}d, nativeSize %{public}d, pefDefSize %{public}d.",
        hapSize, nativeSize, pefDefSize);

    hasInited_ = true;
    ACCESSTOKEN_LOG_INFO(LABEL, "Init success");
}

#ifdef TOKEN_SYNC_ENABLE
void AccessTokenInfoManager::InitDmCallback(void)
{
    std::function<void()> runner = []() {
        std::string name = "AtmInfoMgrInit";
        pthread_setname_np(pthread_self(), name.substr(0, MAX_PTHREAD_NAME_LEN).c_str());
        std::shared_ptr<AccessTokenDmInitCallback> ptrDmInitCallback = std::make_shared<AccessTokenDmInitCallback>();
        int32_t ret = DistributedHardware::DeviceManager::GetInstance().InitDeviceManager(ACCESS_TOKEN_PACKAGE_NAME,
            ptrDmInitCallback);
        if (ret != ERR_OK) {
            ACCESSTOKEN_LOG_ERROR(LABEL, "Initialize: InitDeviceManager error, result: %{public}d", ret);
        }
        ACCESSTOKEN_LOG_INFO(LABEL, "device manager part init end");
        return;
    };
    std::thread initThread(runner);
    initThread.detach();
}
#endif

void AccessTokenInfoManager::InitHapTokenInfos(uint32_t& hapSize)
{
    GenericValues conditionValue;
    std::vector<GenericValues> hapTokenRes;
    std::vector<GenericValues> permDefRes;
    std::vector<GenericValues> permStateRes;
    int32_t ret = AccessTokenDb::GetInstance().Find(AtmDataType::ACCESSTOKEN_HAP_INFO, conditionValue, hapTokenRes);
    if (ret != RET_SUCCESS || hapTokenRes.empty()) {
        ReportSysEventServiceStartError(INIT_HAP_TOKENINFO_ERROR, "Load hap from db fail.", ret);
    }
    ret = AccessTokenDb::GetInstance().Find(AtmDataType::ACCESSTOKEN_PERMISSION_DEF, conditionValue, permDefRes);
    if (ret != RET_SUCCESS || permDefRes.empty()) {
        ReportSysEventServiceStartError(INIT_HAP_TOKENINFO_ERROR, "Load perm def from db fail.", ret);
    }
    ret = AccessTokenDb::GetInstance().Find(AtmDataType::ACCESSTOKEN_PERMISSION_STATE, conditionValue, permStateRes);
    if (ret != RET_SUCCESS || permStateRes.empty()) {
        ReportSysEventServiceStartError(INIT_HAP_TOKENINFO_ERROR, "Load perm state from db fail.", ret);
    }
    for (const GenericValues& tokenValue : hapTokenRes) {
        AccessTokenID tokenId = (AccessTokenID)tokenValue.GetInt(TokenFiledConst::FIELD_TOKEN_ID);
        std::string bundle = tokenValue.GetString(TokenFiledConst::FIELD_BUNDLE_NAME);
        int result = AccessTokenIDManager::GetInstance().RegisterTokenId(tokenId, TOKEN_HAP);
        if (result != RET_SUCCESS) {
            ACCESSTOKEN_LOG_ERROR(LABEL, "TokenId %{public}u add id failed, error=%{public}d.", tokenId, result);
            ReportSysEventServiceStartError(INIT_HAP_TOKENINFO_ERROR,
                "RegisterTokenId fail, " + bundle + std::to_string(tokenId), result);
            continue;
        }
        std::shared_ptr<HapTokenInfoInner> hap = std::make_shared<HapTokenInfoInner>();
        result = hap->RestoreHapTokenInfo(tokenId, tokenValue, permStateRes);
        if (result != RET_SUCCESS) {
            AccessTokenIDManager::GetInstance().ReleaseTokenId(tokenId);
            ACCESSTOKEN_LOG_ERROR(LABEL, "TokenId %{public}u restore failed.", tokenId);
            continue;
        }

        result = AddHapTokenInfo(hap);
        if (result != RET_SUCCESS) {
            AccessTokenIDManager::GetInstance().ReleaseTokenId(tokenId);
            ACCESSTOKEN_LOG_ERROR(LABEL, "TokenId %{public}u add failed.", tokenId);
            ReportSysEventServiceStartError(INIT_HAP_TOKENINFO_ERROR,
                "AddHapTokenInfo fail, " + bundle + std::to_string(tokenId), result);
            continue;
        }
        hapSize++;
        ACCESSTOKEN_LOG_INFO(LABEL,
            " Restore hap token %{public}u bundle name %{public}s user %{public}d,"
            " permSize %{public}d, inst %{public}d ok!",
            tokenId, hap->GetBundleName().c_str(), hap->GetUserID(), hap->GetReqPermissionSize(), hap->GetInstIndex());
    }
    PermissionDefinitionCache::GetInstance().RestorePermDefInfo(permDefRes);
}

void AccessTokenInfoManager::InitNativeTokenInfos(uint32_t& nativeSize)
{
    GenericValues conditionValue;
    std::vector<GenericValues> nativeTokenResults;
    std::vector<GenericValues> permStateRes;
    int32_t ret = AccessTokenDb::GetInstance().Find(
        AtmDataType::ACCESSTOKEN_NATIVE_INFO, conditionValue, nativeTokenResults);
    if (ret != RET_SUCCESS || nativeTokenResults.empty()) {
        ReportSysEventServiceStartError(INIT_NATIVE_TOKENINFO_ERROR, "Load native from db fail.", ret);
    }
    ret = AccessTokenDb::GetInstance().Find(AtmDataType::ACCESSTOKEN_PERMISSION_STATE, conditionValue, permStateRes);
    if (ret != RET_SUCCESS || permStateRes.empty()) {
        ReportSysEventServiceStartError(INIT_NATIVE_TOKENINFO_ERROR, "Load perm state from db fail.", ret);
    }
    for (const GenericValues& nativeTokenValue : nativeTokenResults) {
        AccessTokenID tokenId = (AccessTokenID)nativeTokenValue.GetInt(TokenFiledConst::FIELD_TOKEN_ID);
        std::string process = nativeTokenValue.GetString(TokenFiledConst::FIELD_PROCESS_NAME);
        ATokenTypeEnum type = AccessTokenIDManager::GetInstance().GetTokenIdTypeEnum(tokenId);
        int result = AccessTokenIDManager::GetInstance().RegisterTokenId(tokenId, type);
        if (result != RET_SUCCESS) {
            ReportSysEventServiceStartError(INIT_NATIVE_TOKENINFO_ERROR,
                "RegisterTokenId fail, " + process + std::to_string(tokenId), result);
            ACCESSTOKEN_LOG_ERROR(LABEL, "TokenId %{public}u add failed, error=%{public}d.", tokenId, result);
            continue;
        }
        std::shared_ptr<NativeTokenInfoInner> native = std::make_shared<NativeTokenInfoInner>();
        result = native->RestoreNativeTokenInfo(tokenId, nativeTokenValue, permStateRes);
        if (result != RET_SUCCESS) {
            AccessTokenIDManager::GetInstance().ReleaseTokenId(tokenId);
            ACCESSTOKEN_LOG_ERROR(LABEL, "Id %{public}u restore failed.", tokenId);
            continue;
        }

        result = AddNativeTokenInfo(native);
        if (result != RET_SUCCESS) {
            AccessTokenIDManager::GetInstance().ReleaseTokenId(tokenId);
            ACCESSTOKEN_LOG_ERROR(LABEL, "Id %{public}u add failed.", tokenId);
            ReportSysEventServiceStartError(INIT_NATIVE_TOKENINFO_ERROR,
                "AddNativeTokenInfo fail, " + process + std::to_string(tokenId), result);
            continue;
        }
        nativeSize++;
        ACCESSTOKEN_LOG_INFO(LABEL,
            "restore native token %{public}u process name %{public}s, permSize %{public}u ok!",
            tokenId, native->GetProcessName().c_str(), native->GetReqPermissionSize());
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
        ACCESSTOKEN_LOG_ERROR(LABEL, "Token info is null.");
        return AccessTokenError::ERR_PARAM_INVALID;
    }
    AccessTokenID id = info->GetTokenID();
    AccessTokenID idRemoved = INVALID_TOKENID;
    {
        Utils::UniqueWriteGuard<Utils::RWLock> infoGuard(this->hapTokenInfoLock_);
        if (hapTokenInfoMap_.count(id) > 0) {
            ACCESSTOKEN_LOG_ERROR(LABEL, "Token %{public}u info has exist.", id);
            return AccessTokenError::ERR_TOKENID_NOT_EXIST;
        }

        if (!info->IsRemote()) {
            std::string hapUniqueKey = GetHapUniqueStr(info);
            auto iter = hapTokenIdMap_.find(hapUniqueKey);
            if (iter != hapTokenIdMap_.end()) {
                ACCESSTOKEN_LOG_INFO(LABEL, "Token %{public}u Unique info has exist, update.", id);
                idRemoved = iter->second;
            }
            hapTokenIdMap_[hapUniqueKey] = id;
        }
        hapTokenInfoMap_[id] = info;
    }
    if (idRemoved != INVALID_TOKENID) {
        RemoveHapTokenInfo(idRemoved);
    }
    HiSysEventWrite(HiviewDFX::HiSysEvent::Domain::ACCESS_TOKEN, "ADD_HAP",
        HiviewDFX::HiSysEvent::EventType::STATISTIC,
        "TOKENID", info->GetTokenID(), "USERID", info->GetUserID(), "BUNDLENAME", info->GetBundleName(),
        "INSTINDEX", info->GetInstIndex());

    // add hap to kernel
    int32_t userId = info->GetUserID();
    {
        Utils::UniqueReadGuard<Utils::RWLock> infoGuard(this->userPolicyLock_);
        if (!permPolicyList_.empty() &&
            (std::find(inactiveUserList_.begin(), inactiveUserList_.end(), userId) != inactiveUserList_.end())) {
            ACCESSTOKEN_LOG_INFO(LABEL, "Execute user policy.");
            PermissionManager::GetInstance().AddPermToKernel(id, permPolicyList_);
            return RET_SUCCESS;
        }
    }
    PermissionManager::GetInstance().AddPermToKernel(id);
    return RET_SUCCESS;
}

int AccessTokenInfoManager::AddNativeTokenInfo(const std::shared_ptr<NativeTokenInfoInner>& info)
{
    if (info == nullptr) {
        ACCESSTOKEN_LOG_ERROR(LABEL, "Token info is null.");
        return AccessTokenError::ERR_PARAM_INVALID;
    }

    AccessTokenID id = info->GetTokenID();
    Utils::UniqueWriteGuard<Utils::RWLock> infoGuard(this->nativeTokenInfoLock_);
    if (nativeTokenInfoMap_.count(id) > 0) {
        ACCESSTOKEN_LOG_ERROR(
            LABEL, "Token %{public}u has exist.", id);
        return AccessTokenError::ERR_TOKENID_HAS_EXISTED;
    }

    ACCESSTOKEN_LOG_DEBUG(LABEL, "Token info is added %{public}u.", id);
    nativeTokenInfoMap_[id].processName = info->GetProcessName();
    nativeTokenInfoMap_[id].apl = ATokenAplEnum(info->GetApl());

    std::shared_ptr<PermissionPolicySet> policySet = info->GetNativeInfoPermissionPolicySet();
    if (policySet != nullptr) {
        policySet->GetPermissionStateList(nativeTokenInfoMap_[id].opCodeList, nativeTokenInfoMap_[id].statusList);
    }

    PermissionManager::GetInstance().AddPermToKernel(id, policySet);
    return RET_SUCCESS;
}

std::shared_ptr<HapTokenInfoInner> AccessTokenInfoManager::GetHapTokenInfoInner(AccessTokenID id)
{
    {
        Utils::UniqueReadGuard<Utils::RWLock> infoGuard(this->hapTokenInfoLock_);
        auto iter = hapTokenInfoMap_.find(id);
        if (iter != hapTokenInfoMap_.end()) {
            return iter->second;
        }
    }

    Utils::UniqueWriteGuard<Utils::RWLock> infoGuard(this->hapTokenInfoLock_);
    GenericValues conditionValue;
    if (PermissionDefinitionCache::GetInstance().IsHapPermissionDefEmpty()) {
        std::vector<GenericValues> permDefRes;
        AccessTokenDb::GetInstance().Find(AtmDataType::ACCESSTOKEN_PERMISSION_DEF, conditionValue, permDefRes);
        PermissionDefinitionCache::GetInstance().RestorePermDefInfo(permDefRes); // restore all permission definition
        ACCESSTOKEN_LOG_INFO(LABEL, "Restore perm def size: %{public}zu, mapSize: %{public}zu.",
            permDefRes.size(), hapTokenInfoMap_.size());
    }

    conditionValue.Put(TokenFiledConst::FIELD_TOKEN_ID, static_cast<int32_t>(id));
    std::vector<GenericValues> hapTokenResults;
    int32_t ret = AccessTokenDb::GetInstance().Find(AtmDataType::ACCESSTOKEN_HAP_INFO, conditionValue, hapTokenResults);
    if (ret != RET_SUCCESS || hapTokenResults.empty()) {
        ACCESSTOKEN_LOG_ERROR(LABEL, "Failed to find Id(%{public}u) from hap_token_table, err: %{public}d, "
            "hapSize: %{public}zu, mapSize: %{public}zu.", id, ret, hapTokenResults.size(), hapTokenInfoMap_.size());
        return nullptr;
    }
    std::vector<GenericValues> permStateRes;
    ret = AccessTokenDb::GetInstance().Find(AtmDataType::ACCESSTOKEN_PERMISSION_STATE, conditionValue, permStateRes);
    if (ret != RET_SUCCESS) {
        ACCESSTOKEN_LOG_ERROR(LABEL, "Failed to find Id(%{public}u) from perm_state_table, err: %{public}d, "
            "mapSize: %{public}zu.", id, ret, hapTokenInfoMap_.size());
        return nullptr;
    }

    std::shared_ptr<HapTokenInfoInner> hap = std::make_shared<HapTokenInfoInner>();
    ret = hap->RestoreHapTokenInfo(id, hapTokenResults[0], permStateRes);
    if (ret != RET_SUCCESS) {
        ACCESSTOKEN_LOG_ERROR(LABEL, "Id %{public}u restore failed, err: %{public}d, mapSize: %{public}zu.",
            id, ret, hapTokenInfoMap_.size());
        return nullptr;
    }
    AccessTokenIDManager::GetInstance().RegisterTokenId(id, TOKEN_HAP);
    hapTokenIdMap_[GetHapUniqueStr(hap)] = id;
    hapTokenInfoMap_[id] = hap;
    PermissionManager::GetInstance().AddPermToKernel(id);
    ACCESSTOKEN_LOG_INFO(LABEL, " Token %{public}u is not found in map(mapSize: %{public}zu), begin load from DB,"
        " restore bundle %{public}s user %{public}d, idx %{public}d, permSize %{public}d.", id, hapTokenInfoMap_.size(),
        hap->GetBundleName().c_str(), hap->GetUserID(), hap->GetInstIndex(), hap->GetReqPermissionSize());
    return hap;
}

int32_t AccessTokenInfoManager::GetHapTokenDlpType(AccessTokenID id)
{
    Utils::UniqueReadGuard<Utils::RWLock> infoGuard(this->hapTokenInfoLock_);
    auto iter = hapTokenInfoMap_.find(id);
    if ((iter != hapTokenInfoMap_.end()) && (iter->second != nullptr)) {
        return iter->second->GetDlpType();
    }
    ACCESSTOKEN_LOG_ERROR(LABEL, "Token %{public}u is invalid, mapSize: %{public}zu.", id, hapTokenInfoMap_.size());
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
            LABEL, "Token %{public}u is invalid.", tokenID);
        return AccessTokenError::ERR_TOKENID_NOT_EXIST;
    }
    infoPtr->TranslateToHapTokenInfo(info);
    return RET_SUCCESS;
}

std::shared_ptr<NativeTokenInfoInner> AccessTokenInfoManager::GetNativeTokenInfoInner(AccessTokenID id)
{
    GenericValues conditionValue;
    std::vector<GenericValues> nativeTokenResults;
    std::vector<GenericValues> permStateRes;
    conditionValue.Put(TokenFiledConst::FIELD_TOKEN_ID, static_cast<int32_t>(id));

    int32_t ret = AccessTokenDb::GetInstance().Find(
        AtmDataType::ACCESSTOKEN_NATIVE_INFO, conditionValue, nativeTokenResults);
    if (ret != RET_SUCCESS) {
        ACCESSTOKEN_LOG_ERROR(LABEL, "Id %{public}u find native info failed.", id);
        return nullptr;
    }
    if (nativeTokenResults.empty()) {
        ACCESSTOKEN_LOG_ERROR(LABEL, "Id %{public}u find native info empty.", id);
        return nullptr;
    }
    ret = AccessTokenDb::GetInstance().Find(AtmDataType::ACCESSTOKEN_PERMISSION_STATE, conditionValue, permStateRes);
    if (ret != RET_SUCCESS) {
        ACCESSTOKEN_LOG_ERROR(LABEL, "Id %{public}u find permState info failed.", id);
        return nullptr;
    }

    std::shared_ptr<NativeTokenInfoInner> native = std::make_shared<NativeTokenInfoInner>();
    ret = native->RestoreNativeTokenInfo(id, nativeTokenResults[0], permStateRes);
    if (ret != RET_SUCCESS) {
        ACCESSTOKEN_LOG_ERROR(LABEL, "Id %{public}u restore failed.", id);
        return nullptr;
    }
    return native;
}

int AccessTokenInfoManager::GetNativeTokenInfo(AccessTokenID tokenID, NativeTokenInfoBase& info)
{
    Utils::UniqueReadGuard<Utils::RWLock> infoGuard(this->nativeTokenInfoLock_);
    auto iter = nativeTokenInfoMap_.find(tokenID);
    if (iter == nativeTokenInfoMap_.end()) {
        ACCESSTOKEN_LOG_ERROR(LABEL, "Id %{public}u is not exist.", tokenID);
        return AccessTokenError::ERR_TOKENID_NOT_EXIST;
    }
    info.apl = iter->second.apl;
    info.processName = iter->second.processName;
    return RET_SUCCESS;
}

int AccessTokenInfoManager::RemoveHapTokenInfo(AccessTokenID id)
{
    ATokenTypeEnum type = AccessTokenIDManager::GetInstance().GetTokenIdType(id);
    if (type != TOKEN_HAP) {
        ACCESSTOKEN_LOG_ERROR(LABEL, "Token %{public}u is not hap.", id);
        return ERR_PARAM_INVALID;
    }
    std::shared_ptr<HapTokenInfoInner> info;
    // make sure that RemoveDefPermissions is called outside of the lock to avoid deadlocks.
    PermissionManager::GetInstance().RemoveDefPermissions(id);
    {
        Utils::UniqueWriteGuard<Utils::RWLock> infoGuard(this->hapTokenInfoLock_);
        RemoveTokenInfoFromDb(id, true);
        // remove hap to kernel
        PermissionManager::GetInstance().RemovePermFromKernel(id);
        AccessTokenIDManager::GetInstance().ReleaseTokenId(id);

        if (hapTokenInfoMap_.count(id) == 0) {
            ACCESSTOKEN_LOG_ERROR(LABEL, "Hap token %{public}u no exist.", id);
            return ERR_TOKENID_NOT_EXIST;
        }

        info = hapTokenInfoMap_[id];
        if (info == nullptr) {
            ACCESSTOKEN_LOG_ERROR(LABEL, "Hap token %{public}u is null.", id);
            return ERR_TOKEN_INVALID;
        }
        if (info->IsRemote()) {
            ACCESSTOKEN_LOG_ERROR(LABEL, "Remote hap token %{public}u can not delete.", id);
            return ERR_IDENTITY_CHECK_FAILED;
        }
        std::string HapUniqueKey = GetHapUniqueStr(info);
        auto iter = hapTokenIdMap_.find(HapUniqueKey);
        if ((iter != hapTokenIdMap_.end()) && (iter->second == id)) {
            hapTokenIdMap_.erase(HapUniqueKey);
        }
        hapTokenInfoMap_.erase(id);
    }

    ACCESSTOKEN_LOG_INFO(LABEL, "Remove hap token %{public}u ok!", id);
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
            LABEL, "Token %{public}u is not native or shell.", id);
        return ERR_PARAM_INVALID;
    }

    {
        Utils::UniqueWriteGuard<Utils::RWLock> infoGuard(this->nativeTokenInfoLock_);
        if (nativeTokenInfoMap_.count(id) == 0) {
            ACCESSTOKEN_LOG_ERROR(LABEL, "Native token %{public}u is null.", id);
            return ERR_TOKENID_NOT_EXIST;
        }

        nativeTokenInfoMap_.erase(id);
    }
    AccessTokenIDManager::GetInstance().ReleaseTokenId(id);
    ACCESSTOKEN_LOG_INFO(LABEL, "Remove native token %{public}u ok!", id);
    if (RemoveTokenInfoFromDb(id, false) != RET_SUCCESS) {
        return AccessTokenError::ERR_DATABASE_OPERATE_FAILED;
    }

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
        ACCESSTOKEN_LOG_ERROR(LABEL, "Hap token param failed");
        return AccessTokenError::ERR_PARAM_INVALID;
    }
    int32_t dlpFlag = (info.dlpType > DLP_COMMON) ? 1 : 0;
    int32_t cloneFlag = ((dlpFlag == 0) && (info.instIndex) > 0) ? 1 : 0;
    AccessTokenID tokenId = AccessTokenIDManager::GetInstance().CreateAndRegisterTokenId(TOKEN_HAP, dlpFlag, cloneFlag);
    if (tokenId == 0) {
        ACCESSTOKEN_LOG_ERROR(LABEL, "Token Id create failed");
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
    AddHapTokenInfoToDb(tokenId, tokenInfo);
    int ret = AddHapTokenInfo(tokenInfo);
    if (ret != RET_SUCCESS) {
        ACCESSTOKEN_LOG_ERROR(LABEL, "%{public}s add token info failed", info.bundleName.c_str());
        AccessTokenIDManager::GetInstance().ReleaseTokenId(tokenId);
        PermissionManager::GetInstance().RemoveDefPermissions(tokenId);
        RemoveTokenInfoFromDb(tokenId, true);
        return ret;
    }
    ACCESSTOKEN_LOG_INFO(LABEL, "Create hap token %{public}u bundleName %{public}s user %{public}d inst %{public}d ok",
        tokenId, tokenInfo->GetBundleName().c_str(), tokenInfo->GetUserID(), tokenInfo->GetInstIndex());
    AllocAccessTokenIDEx(info, tokenId, tokenIdEx);
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
        ACCESSTOKEN_LOG_WARN(LABEL, "Info is null.");
        return false;
    }

    Utils::UniqueWriteGuard<Utils::RWLock> infoGuard(this->nativeTokenInfoLock_);
    AccessTokenID id = infoPtr->GetTokenID();
    std::string processName = infoPtr->GetProcessName();
    AccessTokenID findId = INVALID_TOKENID;
    bool idExist = (nativeTokenInfoMap_.count(id) > 0);
    bool processExist = false;
    for (auto iter = nativeTokenInfoMap_.begin(); iter != nativeTokenInfoMap_.end(); ++iter) {
        if (iter->second.processName == processName) {
            processExist = true;
            findId = iter->first;
            break;
        }
    }
    // id is exist, but it is not this process, so neither update nor add.
    if (idExist && !processExist) {
        ACCESSTOKEN_LOG_ERROR(
            LABEL, "Id(%{public}u) is exist, process(%{public}s) is noexist, can not update.", id, processName.c_str());
        return true;
    }

    // this process is exist, but id is not same, perhaps libat lose his data, we need delete old, add new later.
    if (!idExist && processExist) {
        if (nativeTokenInfoMap_.count(findId) > 0) {
            nativeTokenInfoMap_.erase(findId);
        }
        AccessTokenIDManager::GetInstance().ReleaseTokenId(findId);
        return false;
    }

    if (!idExist && !processExist) {
        return false;
    }

    nativeTokenInfoMap_[id].processName = processName;
    nativeTokenInfoMap_[id].apl = ATokenAplEnum(infoPtr->GetApl());
    nativeTokenInfoMap_[id].opCodeList.clear();
    nativeTokenInfoMap_[id].statusList.clear();

    std::shared_ptr<PermissionPolicySet> policySet = infoPtr->GetNativeInfoPermissionPolicySet();
    if (policySet != nullptr) {
        policySet->GetPermissionStateList(nativeTokenInfoMap_[id].opCodeList, nativeTokenInfoMap_[id].statusList);
    }

    PermissionManager::GetInstance().AddPermToKernel(id, policySet);
    return true;
}

void AccessTokenInfoManager::ProcessNativeTokenInfos(
    const std::vector<std::shared_ptr<NativeTokenInfoInner>>& tokenInfos)
{
    std::vector<GenericValues> permStateValues;
    std::vector<GenericValues> nativeTokenValues;
    for (const auto& infoPtr: tokenInfos) {
        if (infoPtr == nullptr) {
            ACCESSTOKEN_LOG_WARN(LABEL, "Token info from libat is null");
            continue;
        }
        if (!TryUpdateExistNativeToken(infoPtr)) {
            AccessTokenID id = infoPtr->GetTokenID();
            std::string processName = infoPtr->GetProcessName();
            ATokenTypeEnum type = AccessTokenIDManager::GetInstance().GetTokenIdTypeEnum(id);
            ACCESSTOKEN_LOG_INFO(LABEL,
                "Token %{public}u process name %{public}s is new, add to manager!", id, processName.c_str());

            int ret = AccessTokenIDManager::GetInstance().RegisterTokenId(id, type);
            if (ret != RET_SUCCESS) {
                ACCESSTOKEN_LOG_ERROR(LABEL, "Token Id register fail, err=%{public}d.", ret);
                continue;
            }
            ret = AddNativeTokenInfo(infoPtr);
            if (ret != RET_SUCCESS) {
                AccessTokenIDManager::GetInstance().ReleaseTokenId(id);
                ACCESSTOKEN_LOG_ERROR(LABEL,
                    "Token %{public}u process name %{public}s add to manager failed!", id, processName.c_str());
            }
            infoPtr->TransferNativeInfo(nativeTokenValues);
            infoPtr->TransferPermissionPolicy(permStateValues);
        }
    }
    AddNativeTokenInfoToDb(nativeTokenValues, permStateValues);
}

int32_t AccessTokenInfoManager::UpdateHapToken(AccessTokenIDEx& tokenIdEx, const UpdateHapInfoParams& info,
    const std::vector<PermissionStateFull>& permStateList, ATokenAplEnum apl,
    const std::vector<PermissionDef>& permList)
{
    AccessTokenID tokenID = tokenIdEx.tokenIdExStruct.tokenID;
    if (!DataValidator::IsAppIDDescValid(info.appIDDesc)) {
        ACCESSTOKEN_LOG_ERROR(LABEL, "Token %{public}u parm format error!", tokenID);
        return AccessTokenError::ERR_PARAM_INVALID;
    }
    std::shared_ptr<HapTokenInfoInner> infoPtr = GetHapTokenInfoInner(tokenID);
    if (infoPtr == nullptr) {
        ACCESSTOKEN_LOG_ERROR(LABEL, "Token %{public}u is invalid, can not update!", tokenID);
        return AccessTokenError::ERR_TOKENID_NOT_EXIST;
    }

    if (infoPtr->IsRemote()) {
        ACCESSTOKEN_LOG_ERROR(LABEL, "Remote hap token %{public}u can not update!", tokenID);
        return ERR_IDENTITY_CHECK_FAILED;
    }
    if (info.isSystemApp) {
        tokenIdEx.tokenIdExStruct.tokenAttr |= SYSTEM_APP_FLAG;
    } else {
        tokenIdEx.tokenIdExStruct.tokenAttr &= ~SYSTEM_APP_FLAG;
    }
    PermissionManager::GetInstance().AddDefPermissions(permList, tokenID, true);
    {
        Utils::UniqueWriteGuard<Utils::RWLock> infoGuard(this->hapTokenInfoLock_);
        int32_t ret = infoPtr->Update(info, permStateList, apl);
        if (ret != RET_SUCCESS) {
            return ret;
        }
        ACCESSTOKEN_LOG_INFO(LABEL, "Token %{public}u bundle name %{public}s user %{public}d \
inst %{public}d tokenAttr %{public}d update ok!", tokenID, infoPtr->GetBundleName().c_str(),
            infoPtr->GetUserID(), infoPtr->GetInstIndex(), infoPtr->GetHapInfoBasic().tokenAttr);
        // DFX
        HiSysEventWrite(HiviewDFX::HiSysEvent::Domain::ACCESS_TOKEN, "UPDATE_HAP",
            HiviewDFX::HiSysEvent::EventType::STATISTIC, "TOKENID", infoPtr->GetTokenID(), "USERID",
            infoPtr->GetUserID(), "BUNDLENAME", infoPtr->GetBundleName(), "INSTINDEX", infoPtr->GetInstIndex());
    }

#ifdef TOKEN_SYNC_ENABLE
    TokenModifyNotifier::GetInstance().NotifyTokenModify(tokenID);
#endif
    // update hap to kernel
    int32_t userId = infoPtr->GetUserID();
    {
        Utils::UniqueReadGuard<Utils::RWLock> infoGuard(this->userPolicyLock_);
        if (!permPolicyList_.empty() &&
            (std::find(inactiveUserList_.begin(), inactiveUserList_.end(), userId) != inactiveUserList_.end())) {
            ACCESSTOKEN_LOG_INFO(LABEL, "Execute user policy.");
            PermissionManager::GetInstance().AddPermToKernel(tokenID, permPolicyList_);
            return RET_SUCCESS;
        }
    }
    PermissionManager::GetInstance().AddPermToKernel(tokenID);
    return RET_SUCCESS;
}

#ifdef TOKEN_SYNC_ENABLE
int AccessTokenInfoManager::GetHapTokenSync(AccessTokenID tokenID, HapTokenInfoForSync& hapSync)
{
    std::shared_ptr<HapTokenInfoInner> infoPtr = GetHapTokenInfoInner(tokenID);
    if (infoPtr == nullptr || infoPtr->IsRemote()) {
        ACCESSTOKEN_LOG_ERROR(
            LABEL, "Token %{public}u is invalid.", tokenID);
        return ERR_IDENTITY_CHECK_FAILED;
    }
    hapSync.baseInfo = infoPtr->GetHapInfoBasic();
    return infoPtr->GetPermissionStateList(hapSync.permStateList);
}

int AccessTokenInfoManager::GetHapTokenInfoFromRemote(AccessTokenID tokenID,
    HapTokenInfoForSync& hapSync)
{
    int ret = GetHapTokenSync(tokenID, hapSync);
    TokenModifyNotifier::GetInstance().AddHapTokenObservation(tokenID);
    return ret;
}

int AccessTokenInfoManager::UpdateRemoteHapTokenInfo(AccessTokenID mapID, HapTokenInfoForSync& hapSync)
{
    std::shared_ptr<HapTokenInfoInner> infoPtr = GetHapTokenInfoInner(mapID);
    if (infoPtr == nullptr || !infoPtr->IsRemote()) {
        ACCESSTOKEN_LOG_INFO(LABEL, "Token %{public}u is null or not remote, can not update!", mapID);
        return ERR_IDENTITY_CHECK_FAILED;
    }
    Utils::UniqueWriteGuard<Utils::RWLock> infoGuard(this->hapTokenInfoLock_);
    infoPtr->UpdateRemoteHapTokenInfo(mapID, hapSync.baseInfo, hapSync.permStateList);
    // update remote hap to kernel
    PermissionManager::GetInstance().AddPermToKernel(mapID);
    return RET_SUCCESS;
}

int AccessTokenInfoManager::CreateRemoteHapTokenInfo(AccessTokenID mapID, HapTokenInfoForSync& hapSync)
{
    std::shared_ptr<HapTokenInfoInner> hap = std::make_shared<HapTokenInfoInner>(mapID, hapSync);
    hap->SetRemote(true);

    int ret = AddHapTokenInfo(hap);
    if (ret != RET_SUCCESS) {
        ACCESSTOKEN_LOG_ERROR(LABEL, "Add local token failed.");
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
        ACCESSTOKEN_LOG_ERROR(LABEL, "Device %{public}s parms invalid", ConstantCommon::EncryptDevId(deviceID).c_str());
        return ERR_IDENTITY_CHECK_FAILED;
    }

    AccessTokenID remoteID = hapSync.baseInfo.tokenID;
    AccessTokenID mapID = AccessTokenRemoteTokenManager::GetInstance().GetDeviceMappingTokenID(deviceID, remoteID);
    if (mapID != 0) {
        ACCESSTOKEN_LOG_INFO(LABEL, "Device %{public}s token %{public}u update exist remote hap token %{public}u.",
            ConstantCommon::EncryptDevId(deviceID).c_str(), remoteID, mapID);
        // update remote token mapping id
        hapSync.baseInfo.tokenID = mapID;
        hapSync.baseInfo.deviceID = deviceID;
        return UpdateRemoteHapTokenInfo(mapID, hapSync);
    }

    mapID = AccessTokenRemoteTokenManager::GetInstance().MapRemoteDeviceTokenToLocal(deviceID, remoteID);
    if (mapID == 0) {
        ACCESSTOKEN_LOG_ERROR(LABEL, "Device %{public}s token %{public}u map failed.",
            ConstantCommon::EncryptDevId(deviceID).c_str(), remoteID);
        return ERR_TOKEN_MAP_FAILED;
    }

    // update remote token mapping id
    hapSync.baseInfo.tokenID = mapID;
    hapSync.baseInfo.deviceID = deviceID;
    int ret = CreateRemoteHapTokenInfo(mapID, hapSync);
    if (ret != RET_SUCCESS) {
        int result = AccessTokenRemoteTokenManager::GetInstance().RemoveDeviceMappingTokenID(deviceID, mapID);
        if (result != RET_SUCCESS) {
            ACCESSTOKEN_LOG_ERROR(LABEL, "remove device map token id failed");
        }
        ACCESSTOKEN_LOG_INFO(LABEL, "Device %{public}s token %{public}u map to local token %{public}u failed.",
            ConstantCommon::EncryptDevId(deviceID).c_str(), remoteID, mapID);
        return ret;
    }
    ACCESSTOKEN_LOG_INFO(LABEL, "Device %{public}s token %{public}u map to local token %{public}u success.",
        ConstantCommon::EncryptDevId(deviceID).c_str(), remoteID, mapID);
    return RET_SUCCESS;
}

int AccessTokenInfoManager::DeleteRemoteToken(const std::string& deviceID, AccessTokenID tokenID)
{
    if (!DataValidator::IsDeviceIdValid(deviceID)) {
        ACCESSTOKEN_LOG_ERROR(LABEL, "Device %{public}s parms invalid.",
            ConstantCommon::EncryptDevId(deviceID).c_str());
        return AccessTokenError::ERR_PARAM_INVALID;
    }
    AccessTokenID mapID = AccessTokenRemoteTokenManager::GetInstance().GetDeviceMappingTokenID(deviceID, tokenID);
    if (mapID == 0) {
        ACCESSTOKEN_LOG_ERROR(LABEL, "Device %{public}s tokenId %{public}u is not mapped.",
            ConstantCommon::EncryptDevId(deviceID).c_str(), tokenID);
        return ERR_TOKEN_MAP_FAILED;
    }

    ATokenTypeEnum type = AccessTokenIDManager::GetInstance().GetTokenIdTypeEnum(mapID);
    if (type == TOKEN_HAP) {
        Utils::UniqueWriteGuard<Utils::RWLock> infoGuard(this->hapTokenInfoLock_);
        if (hapTokenInfoMap_.count(mapID) == 0) {
            ACCESSTOKEN_LOG_ERROR(LABEL, "Hap token %{public}u no exist.", mapID);
            return ERR_TOKEN_INVALID;
        }
        hapTokenInfoMap_.erase(mapID);
    } else if ((type == TOKEN_NATIVE) || (type == TOKEN_SHELL)) {
        Utils::UniqueWriteGuard<Utils::RWLock> infoGuard(this->nativeTokenInfoLock_);
        if (nativeTokenInfoMap_.count(mapID) == 0) {
            ACCESSTOKEN_LOG_ERROR(
                LABEL, "Native token %{public}u is null.", mapID);
            return ERR_TOKEN_INVALID;
        }
        nativeTokenInfoMap_.erase(mapID);
    } else {
        ACCESSTOKEN_LOG_ERROR(LABEL, "Mapping tokenId %{public}u type is unknown.", mapID);
    }

    return AccessTokenRemoteTokenManager::GetInstance().RemoveDeviceMappingTokenID(deviceID, tokenID);
}

AccessTokenID AccessTokenInfoManager::GetRemoteNativeTokenID(const std::string& deviceID, AccessTokenID tokenID)
{
    if ((!DataValidator::IsDeviceIdValid(deviceID)) || (tokenID == 0) ||
        ((AccessTokenIDManager::GetInstance().GetTokenIdTypeEnum(tokenID) != TOKEN_NATIVE) &&
        (AccessTokenIDManager::GetInstance().GetTokenIdTypeEnum(tokenID) != TOKEN_SHELL))) {
        ACCESSTOKEN_LOG_ERROR(LABEL, "Device %{public}s parms invalid.",
            ConstantCommon::EncryptDevId(deviceID).c_str());
        return 0;
    }
    return AccessTokenRemoteTokenManager::GetInstance().GetDeviceMappingTokenID(deviceID, tokenID);
}

int AccessTokenInfoManager::DeleteRemoteDeviceTokens(const std::string& deviceID)
{
    if (!DataValidator::IsDeviceIdValid(deviceID)) {
        ACCESSTOKEN_LOG_ERROR(LABEL, "Device %{public}s parms invalid.",
            ConstantCommon::EncryptDevId(deviceID).c_str());
        return AccessTokenError::ERR_PARAM_INVALID;
    }
    std::vector<AccessTokenID> remoteTokens;
    int ret = AccessTokenRemoteTokenManager::GetInstance().GetDeviceAllRemoteTokenID(deviceID, remoteTokens);
    if (ret != RET_SUCCESS) {
        ACCESSTOKEN_LOG_ERROR(LABEL, "Device %{public}s have no remote token.",
            ConstantCommon::EncryptDevId(deviceID).c_str());
        return ret;
    }
    for (AccessTokenID remoteID : remoteTokens) {
        ret = DeleteRemoteToken(deviceID, remoteID);
        if (ret != RET_SUCCESS) {
            ACCESSTOKEN_LOG_ERROR(LABEL, "delete remote token failed! deviceId=%{public}s, remoteId=%{public}d.", \
                deviceID.c_str(), remoteID);
        }
    }
    return ret;
}

AccessTokenID AccessTokenInfoManager::AllocLocalTokenID(const std::string& remoteDeviceID,
    AccessTokenID remoteTokenID)
{
    if (!DataValidator::IsDeviceIdValid(remoteDeviceID)) {
        ACCESSTOKEN_LOG_ERROR(LABEL, "Device %{public}s parms invalid.",
            ConstantCommon::EncryptDevId(remoteDeviceID).c_str());
        HiSysEventWrite(HiviewDFX::HiSysEvent::Domain::ACCESS_TOKEN, "PERMISSION_SYNC",
            HiviewDFX::HiSysEvent::EventType::FAULT, "CODE", TOKEN_SYNC_CALL_ERROR,
            "REMOTE_ID", ConstantCommon::EncryptDevId(remoteDeviceID), "ERROR_REASON", "deviceID error");
        return 0;
    }
    uint64_t fullTokenId = IPCSkeleton::GetCallingFullTokenID();
    int result = SetFirstCallerTokenID(fullTokenId); // for debug
    ACCESSTOKEN_LOG_INFO(LABEL, "Set first caller %{public}" PRIu64 "., ret is %{public}d", fullTokenId, result);

    std::string remoteUdid;
    DistributedHardware::DeviceManager::GetInstance().GetUdidByNetworkId(ACCESS_TOKEN_PACKAGE_NAME, remoteDeviceID,
        remoteUdid);
    ACCESSTOKEN_LOG_INFO(LABEL, "Device %{public}s remoteUdid.", ConstantCommon::EncryptDevId(remoteUdid).c_str());
    AccessTokenID mapID = AccessTokenRemoteTokenManager::GetInstance().GetDeviceMappingTokenID(remoteUdid,
        remoteTokenID);
    if (mapID != 0) {
        return mapID;
    }
    int ret = TokenModifyNotifier::GetInstance().GetRemoteHapTokenInfo(remoteUdid, remoteTokenID);
    if (ret != RET_SUCCESS) {
        ACCESSTOKEN_LOG_ERROR(LABEL, "Device %{public}s token %{public}u sync failed",
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
    ACCESSTOKEN_LOG_ERROR(LABEL, "Tokensync is disable, check dependent components");
    return 0;
}
#endif

AccessTokenInfoManager& AccessTokenInfoManager::GetInstance()
{
    static AccessTokenInfoManager* instance = nullptr;
    if (instance == nullptr) {
        std::lock_guard<std::recursive_mutex> lock(g_instanceMutex);
        if (instance == nullptr) {
            AccessTokenInfoManager* tmp = new AccessTokenInfoManager();
            instance = std::move(tmp);
        }
    }
    return *instance;
}

int AccessTokenInfoManager::AddHapTokenInfoToDb(
    AccessTokenID tokenID, const std::shared_ptr<HapTokenInfoInner>& hapInfo)
{
    std::vector<GenericValues> hapInfoValues;
    std::vector<GenericValues> permDefValues;
    std::vector<GenericValues> permStateValues;
    if (hapInfo == nullptr) {
        ACCESSTOKEN_LOG_ERROR(LABEL, "Token %{public}u info is null!", tokenID);
        return AccessTokenError::ERR_TOKENID_NOT_EXIST;
    }
    hapInfo->StoreHapInfo(hapInfoValues);
    hapInfo->StorePermissionPolicy(permStateValues);
    PermissionDefinitionCache::GetInstance().StorePermissionDef(tokenID, permDefValues);
    AccessTokenDb::GetInstance().Add(AtmDataType::ACCESSTOKEN_HAP_INFO, hapInfoValues);
    AccessTokenDb::GetInstance().Add(AtmDataType::ACCESSTOKEN_PERMISSION_STATE, permStateValues);
    AccessTokenDb::GetInstance().Add(AtmDataType::ACCESSTOKEN_PERMISSION_DEF, permDefValues);
    return RET_SUCCESS;
}

int AccessTokenInfoManager::AddNativeTokenInfoToDb(
    const std::vector<GenericValues>& nativeInfoValues, const std::vector<GenericValues>& permStateValues)
{
    AccessTokenDb::GetInstance().Add(AtmDataType::ACCESSTOKEN_NATIVE_INFO, nativeInfoValues);
    AccessTokenDb::GetInstance().Add(AtmDataType::ACCESSTOKEN_PERMISSION_STATE, permStateValues);
    return RET_SUCCESS;
}

int AccessTokenInfoManager::RemoveTokenInfoFromDb(AccessTokenID tokenID, bool isHap)
{
    GenericValues values;
    values.Put(TokenFiledConst::FIELD_TOKEN_ID, static_cast<int32_t>(tokenID));

    if (isHap) {
        AccessTokenDb::GetInstance().Remove(AtmDataType::ACCESSTOKEN_HAP_INFO, values);
        AccessTokenDb::GetInstance().Remove(AtmDataType::ACCESSTOKEN_PERMISSION_DEF, values);
    } else {
        AccessTokenDb::GetInstance().Remove(AtmDataType::ACCESSTOKEN_NATIVE_INFO, values);
    }
    AccessTokenDb::GetInstance().Remove(AtmDataType::ACCESSTOKEN_PERMISSION_STATE, values);
    return RET_SUCCESS;
}

void AccessTokenInfoManager::PermissionStateNotify(const std::shared_ptr<HapTokenInfoInner>& info, AccessTokenID id)
{
    std::vector<std::string> permissionList;
    int32_t userId = info->GetUserID();
    {
        Utils::UniqueReadGuard<Utils::RWLock> infoGuard(this->userPolicyLock_);
        if (!permPolicyList_.empty() &&
            (std::find(inactiveUserList_.begin(), inactiveUserList_.end(), userId) != inactiveUserList_.end())) {
            ACCESSTOKEN_LOG_INFO(LABEL, "Execute user policy.");
            HapTokenInfoInner::GetGrantedPermByTokenId(id, permPolicyList_, permissionList);
        } else {
            std::vector<std::string> emptyList;
            HapTokenInfoInner::GetGrantedPermByTokenId(id, emptyList, permissionList);
        }
    }
    if (permissionList.size() != 0) {
        PermissionManager::GetInstance().ParamUpdate(permissionList[0], 0, true);
    }
    for (const auto& permissionName : permissionList) {
        CallbackManager::GetInstance().ExecuteCallbackAsync(
            id, permissionName, PermStateChangeType::STATE_CHANGE_REVOKED);
    }
}

int32_t AccessTokenInfoManager::GetHapAppIdByTokenId(AccessTokenID tokenID, std::string& appId)
{
    GenericValues conditionValue;
    conditionValue.Put(TokenFiledConst::FIELD_TOKEN_ID, static_cast<int32_t>(tokenID));
    std::vector<GenericValues> hapTokenResults;
    int32_t ret = AccessTokenDb::GetInstance().Find(AtmDataType::ACCESSTOKEN_HAP_INFO, conditionValue, hapTokenResults);
    if (ret != RET_SUCCESS) {
        ACCESSTOKEN_LOG_ERROR(LABEL,
            "Failed to find Id(%{public}u) from hap_token_table, err: %{public}d.", tokenID, ret);
        return ret;
    }

    if (hapTokenResults.empty()) {
        ACCESSTOKEN_LOG_ERROR(LABEL, "Id(%{public}u) is not in hap_token_table.", tokenID);
        return AccessTokenError::ERR_TOKENID_NOT_EXIST;
    }
    std::string result = hapTokenResults[0].GetString(TokenFiledConst::FIELD_APP_ID);
    if (!DataValidator::IsAppIDDescValid(result)) {
        ACCESSTOKEN_LOG_ERROR(LABEL, "TokenID: 0x%{public}x appID is error.", tokenID);
        return AccessTokenError::ERR_PARAM_INVALID;
    }
    appId = result;
    return RET_SUCCESS;
}

AccessTokenID AccessTokenInfoManager::GetNativeTokenId(const std::string& processName)
{
    AccessTokenID tokenID = INVALID_TOKENID;
    Utils::UniqueReadGuard<Utils::RWLock> infoGuard(this->nativeTokenInfoLock_);
    for (auto iter = nativeTokenInfoMap_.begin(); iter != nativeTokenInfoMap_.end(); ++iter) {
        if (iter->second.processName == processName) {
            tokenID = iter->first;
            break;
        }
    }
    return tokenID;
}

void AccessTokenInfoManager::DumpHapTokenInfoByTokenId(const AccessTokenID tokenId, std::string& dumpInfo)
{
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
    Utils::UniqueReadGuard<Utils::RWLock> hapInfoGuard(this->hapTokenInfoLock_);
    for (auto iter = hapTokenInfoMap_.begin(); iter != hapTokenInfoMap_.end(); iter++) {
        if (iter->second != nullptr) {
            if (bundleName != iter->second->GetBundleName()) {
                continue;
            }

            iter->second->ToString(dumpInfo);
            dumpInfo.append("\n");
        }
    }
}

void AccessTokenInfoManager::DumpAllHapTokenname(std::string& dumpInfo)
{
    ACCESSTOKEN_LOG_DEBUG(LABEL, "Get all hap token name.");

    Utils::UniqueReadGuard<Utils::RWLock> hapInfoGuard(this->hapTokenInfoLock_);
    for (auto iter = hapTokenInfoMap_.begin(); iter != hapTokenInfoMap_.end(); iter++) {
        if (iter->second != nullptr) {
            dumpInfo += std::to_string(iter->second->GetTokenID()) + ": " + iter->second->GetBundleName();
            dumpInfo.append("\n");
        }
    }
}

void AccessTokenInfoManager::DumpNativeTokenInfoByProcessName(const std::string& processName, std::string& dumpInfo)
{
    AccessTokenID id = GetNativeTokenId(processName);
    std::shared_ptr<NativeTokenInfoInner> infoPtr = GetNativeTokenInfoInner(id);
    if (infoPtr != nullptr) {
        infoPtr->ToString(dumpInfo);
    }
}

void AccessTokenInfoManager::DumpAllNativeTokenName(std::string& dumpInfo)
{
    ACCESSTOKEN_LOG_DEBUG(LABEL, "Get all native token name.");

    Utils::UniqueReadGuard<Utils::RWLock> infoGuard(this->nativeTokenInfoLock_);
    for (auto iter = nativeTokenInfoMap_.begin(); iter != nativeTokenInfoMap_.end(); iter++) {
        dumpInfo += std::to_string(iter->first) + ": " + iter->second.processName;
        dumpInfo.append("\n");
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
        ACCESSTOKEN_LOG_ERROR(LABEL, "Open failed errno %{public}d.", errno);
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

    DumpAllHapTokenname(dumpInfo);
    DumpAllNativeTokenName(dumpInfo);
}


void AccessTokenInfoManager::ClearUserGrantedPermissionState(AccessTokenID tokenID)
{
    if (ClearUserGrantedPermission(tokenID) != RET_SUCCESS) {
        return;
    }
    std::vector<AccessTokenID> tokenIdList;
    GetRelatedSandBoxHapList(tokenID, tokenIdList);
    for (const auto& id : tokenIdList) {
        (void)ClearUserGrantedPermission(id);
    }
    // DFX
    HiSysEventWrite(HiviewDFX::HiSysEvent::Domain::ACCESS_TOKEN, "CLEAR_USER_PERMISSION_STATE",
        HiviewDFX::HiSysEvent::EventType::BEHAVIOR, "TOKENID", tokenID,
        "TOKENID_LEN", static_cast<uint32_t>(tokenIdList.size()));
}

int32_t AccessTokenInfoManager::ClearUserGrantedPermission(AccessTokenID id)
{
    std::shared_ptr<HapTokenInfoInner> infoPtr = AccessTokenInfoManager::GetInstance().GetHapTokenInfoInner(id);
    if (infoPtr == nullptr) {
        ACCESSTOKEN_LOG_ERROR(LABEL, "Token %{public}u is invalid.", id);
        return ERR_PARAM_INVALID;
    }
    if (infoPtr->IsRemote()) {
        ACCESSTOKEN_LOG_ERROR(LABEL, "It is a remote hap token %{public}u!", id);
        return ERR_IDENTITY_CHECK_FAILED;
    }
    std::vector<std::string> grantedPermListBefore;
    std::vector<std::string> emptyList;
    HapTokenInfoInner::GetGrantedPermByTokenId(id, emptyList, grantedPermListBefore);

    // reset permission.
    infoPtr->ResetUserGrantPermissionStatus();

    std::vector<std::string> grantedPermListAfter;
    HapTokenInfoInner::GetGrantedPermByTokenId(id, emptyList, grantedPermListAfter);

    {
        int32_t userId = infoPtr->GetUserID();
        Utils::UniqueReadGuard<Utils::RWLock> infoGuard(this->userPolicyLock_);
        if (!permPolicyList_.empty() &&
            (std::find(inactiveUserList_.begin(), inactiveUserList_.end(), userId) != inactiveUserList_.end())) {
            PermissionManager::GetInstance().AddPermToKernel(id, permPolicyList_);
            PermissionManager::GetInstance().NotifyUpdatedPermList(grantedPermListBefore, grantedPermListAfter, id);
            return RET_SUCCESS;
        }
    }
    PermissionManager::GetInstance().AddPermToKernel(id);
    ACCESSTOKEN_LOG_INFO(LABEL,
        "grantedPermListBefore size %{public}zu, grantedPermListAfter size %{public}zu!",
        grantedPermListBefore.size(), grantedPermListAfter.size());
    PermissionManager::GetInstance().NotifyUpdatedPermList(grantedPermListBefore, grantedPermListAfter, id);
    return RET_SUCCESS;
}

bool AccessTokenInfoManager::IsPermissionRestrictedByUserPolicy(AccessTokenID id, const std::string& permissionName)
{
    std::shared_ptr<HapTokenInfoInner> infoPtr = AccessTokenInfoManager::GetInstance().GetHapTokenInfoInner(id);
    if (infoPtr == nullptr) {
        ACCESSTOKEN_LOG_ERROR(LABEL, "Token %{public}u is invalid.", id);
        return ERR_PARAM_INVALID;
    }
    int32_t userId = infoPtr->GetUserID();
    Utils::UniqueReadGuard<Utils::RWLock> infoGuard(this->userPolicyLock_);
    if ((std::find(permPolicyList_.begin(), permPolicyList_.end(), permissionName) != permPolicyList_.end()) &&
        (std::find(inactiveUserList_.begin(), inactiveUserList_.end(), userId) != inactiveUserList_.end())) {
        ACCESSTOKEN_LOG_INFO(LABEL, "id %{public}u perm %{public}s.", id, permissionName.c_str());
        return true;
    }
    return false;
}

void AccessTokenInfoManager::GetRelatedSandBoxHapList(AccessTokenID tokenId, std::vector<AccessTokenID>& tokenIdList)
{
    Utils::UniqueReadGuard<Utils::RWLock> infoGuard(this->hapTokenInfoLock_);

    auto infoIter = hapTokenInfoMap_.find(tokenId);
    if (infoIter == hapTokenInfoMap_.end()) {
        return;
    }
    if (infoIter->second == nullptr) {
        ACCESSTOKEN_LOG_ERROR(LABEL, "HapTokenInfoInner is nullptr.");
        return;
    }
    std::string bundleName = infoIter->second->GetBundleName();
    int32_t userID = infoIter->second->GetUserID();
    int32_t index = infoIter->second->GetInstIndex();
    int32_t dlpType = infoIter->second->GetDlpType();
    // the permissions of a common application whose index is not equal 0 are managed independently.
    if ((dlpType == DLP_COMMON) && (index != 0)) {
        return;
    }

    for (auto iter = hapTokenInfoMap_.begin(); iter != hapTokenInfoMap_.end(); ++iter) {
        if (iter->second == nullptr) {
            continue;
        }
        if ((bundleName == iter->second->GetBundleName()) && (userID == iter->second->GetUserID()) &&
            (tokenId != iter->second->GetTokenID())) {
            if ((iter->second->GetDlpType() == DLP_COMMON) && (iter->second->GetInstIndex() != 0)) {
                continue;
            }
            tokenIdList.emplace_back(iter->second->GetTokenID());
        }
    }
}

int32_t AccessTokenInfoManager::SetPermDialogCap(AccessTokenID tokenID, bool enable)
{
    Utils::UniqueWriteGuard<Utils::RWLock> infoGuard(this->hapTokenInfoLock_);
    auto infoIter = hapTokenInfoMap_.find(tokenID);
    if ((infoIter == hapTokenInfoMap_.end()) || (infoIter->second == nullptr)) {
        ACCESSTOKEN_LOG_ERROR(LABEL, "HapTokenInfoInner is nullptr.");
        return ERR_TOKENID_NOT_EXIST;
    }
    infoIter->second->SetPermDialogForbidden(enable);

    if (!UpdateCapStateToDatabase(tokenID, enable)) {
        return RET_FAILED;
    }

    return RET_SUCCESS;
}

int32_t AccessTokenInfoManager::ParseUserPolicyInfo(const std::vector<UserState>& userList,
    const std::vector<std::string>& permList, std::map<int32_t, bool>& changedUserList)
{
    if (!permPolicyList_.empty()) {
        ACCESSTOKEN_LOG_ERROR(LABEL, "UserPolicy has been initialized.");
        return ERR_USER_POLICY_INITIALIZED;
    }
    for (const auto &permission : permList) {
        if (std::find(permPolicyList_.begin(), permPolicyList_.end(), permission) == permPolicyList_.end()) {
            permPolicyList_.emplace_back(permission);
        }
    }

    if (permPolicyList_.empty()) {
        ACCESSTOKEN_LOG_ERROR(LABEL, "permList is invalid.");
        return ERR_PARAM_INVALID;
    }
    for (const auto &userInfo : userList) {
        if (userInfo.userId < 0) {
            ACCESSTOKEN_LOG_WARN(LABEL, "userId %{public}d is invalid.", userInfo.userId);
            continue;
        }
        if (userInfo.isActive) {
            ACCESSTOKEN_LOG_INFO(LABEL, "userid %{public}d is active.", userInfo.userId);
            continue;
        }
        inactiveUserList_.emplace_back(userInfo.userId);
        changedUserList[userInfo.userId] = false;
    }

    return RET_SUCCESS;
}

int32_t AccessTokenInfoManager::ParseUserPolicyInfo(const std::vector<UserState>& userList,
    std::map<int32_t, bool>& changedUserList)
{
    if (permPolicyList_.empty()) {
        ACCESSTOKEN_LOG_ERROR(LABEL, "UserPolicy has been initialized.");
        return ERR_USER_POLICY_NOT_INITIALIZED;
    }
    for (const auto &userInfo : userList) {
        if (userInfo.userId < 0) {
            ACCESSTOKEN_LOG_WARN(LABEL, "UserId %{public}d is invalid.", userInfo.userId);
            continue;
        }
        auto iter = std::find(inactiveUserList_.begin(), inactiveUserList_.end(), userInfo.userId);
        // the userid is changed to foreground
        if ((iter != inactiveUserList_.end() && userInfo.isActive)) {
            inactiveUserList_.erase(iter);
            changedUserList[userInfo.userId] = userInfo.isActive;
        }
        // the userid is changed to background
        if ((iter == inactiveUserList_.end() && !userInfo.isActive)) {
            changedUserList[userInfo.userId] = userInfo.isActive;
            inactiveUserList_.emplace_back(userInfo.userId);
        }
    }
    return RET_SUCCESS;
}

void AccessTokenInfoManager::GetGoalHapList(std::map<AccessTokenID, bool>& tokenIdList,
    std::map<int32_t, bool>& changedUserList)
{
    Utils::UniqueReadGuard<Utils::RWLock> infoGuard(this->hapTokenInfoLock_);
    for (auto iter = hapTokenInfoMap_.begin(); iter != hapTokenInfoMap_.end(); ++iter) {
        AccessTokenID tokenId = iter->first;
        std::shared_ptr<HapTokenInfoInner> infoPtr = iter->second;
        if (infoPtr == nullptr) {
            ACCESSTOKEN_LOG_ERROR(LABEL, "TokenId infoPtr is null.");
            continue;
        }
        auto userInfo = changedUserList.find(infoPtr->GetUserID());
        if (userInfo != changedUserList.end()) {
            // Record the policy status of hap (active or not).
            tokenIdList[tokenId] = userInfo->second;
        }
    }
    return;
}

int32_t AccessTokenInfoManager::UpdatePermissionStateToKernel(const std::map<AccessTokenID, bool>& tokenIdList)
{
    for (auto iter = tokenIdList.begin(); iter != tokenIdList.end(); ++iter) {
        AccessTokenID tokenId = iter->first;
        bool isActive = iter->second;
        // refresh under userPolicyLock_
        {
            Utils::UniqueReadGuard<Utils::RWLock> infoGuard(this->userPolicyLock_);
            std::map<std::string, bool> refreshedPermList;
            HapTokenInfoInner::RefreshPermStateToKernel(permPolicyList_, isActive, tokenId, refreshedPermList);

            if (refreshedPermList.size() != 0) {
                PermissionManager::GetInstance().ParamUpdate(std::string(), 0, true);
            }
            for (auto perm = refreshedPermList.begin(); perm != refreshedPermList.end(); ++perm) {
                PermStateChangeType change = perm->second ?
                    PermStateChangeType::STATE_CHANGE_GRANTED : PermStateChangeType::STATE_CHANGE_REVOKED;
                CallbackManager::GetInstance().ExecuteCallbackAsync(tokenId, perm->first, change);
            }
        }
    }
    return RET_SUCCESS;
}

int32_t AccessTokenInfoManager::UpdatePermissionStateToKernel(const std::vector<std::string>& permCodeList,
    const std::map<AccessTokenID, bool>& tokenIdList)
{
    for (auto iter = tokenIdList.begin(); iter != tokenIdList.end(); ++iter) {
        AccessTokenID tokenId = iter->first;
        bool isActive = iter->second;
        std::map<std::string, bool> refreshedPermList;
        HapTokenInfoInner::RefreshPermStateToKernel(permCodeList, isActive, tokenId, refreshedPermList);

        if (refreshedPermList.size() != 0) {
            PermissionManager::GetInstance().ParamUpdate(std::string(), 0, true);
        }
        for (auto perm = refreshedPermList.begin(); perm != refreshedPermList.end(); ++perm) {
            ACCESSTOKEN_LOG_INFO(LABEL, "Perm %{public}s refreshed by user policy, isActive %{public}d.",
                perm->first.c_str(), perm->second);
            PermStateChangeType change = perm->second ?
                PermStateChangeType::STATE_CHANGE_GRANTED : PermStateChangeType::STATE_CHANGE_REVOKED;
            CallbackManager::GetInstance().ExecuteCallbackAsync(tokenId, perm->first, change);
        }
    }
    return RET_SUCCESS;
}

int32_t AccessTokenInfoManager::InitUserPolicy(
    const std::vector<UserState>& userList, const std::vector<std::string>& permList)
{
    std::map<AccessTokenID, bool> tokenIdList;
    {
        Utils::UniqueWriteGuard<Utils::RWLock> infoGuard(this->userPolicyLock_);
        std::map<int32_t, bool> changedUserList;
        int32_t ret = ParseUserPolicyInfo(userList, permList, changedUserList);
        if (ret != RET_SUCCESS) {
            return ret;
        }
        if (changedUserList.empty()) {
            ACCESSTOKEN_LOG_INFO(LABEL, "changedUserList is empty.");
            return ret;
        }
        GetGoalHapList(tokenIdList, changedUserList);
    }
    return UpdatePermissionStateToKernel(tokenIdList);
}

int32_t AccessTokenInfoManager::UpdateUserPolicy(const std::vector<UserState>& userList)
{
    std::map<AccessTokenID, bool> tokenIdList;
    {
        std::map<int32_t, bool> changedUserList;
        Utils::UniqueWriteGuard<Utils::RWLock> infoGuard(this->userPolicyLock_);
        int32_t ret = ParseUserPolicyInfo(userList, changedUserList);
        if (ret != RET_SUCCESS) {
            return ret;
        }
        if (changedUserList.empty()) {
            ACCESSTOKEN_LOG_INFO(LABEL, "changedUserList is empty.");
            return ret;
        }
        GetGoalHapList(tokenIdList, changedUserList);
    }
    return UpdatePermissionStateToKernel(tokenIdList);
}

int32_t AccessTokenInfoManager::ClearUserPolicy()
{
    std::map<AccessTokenID, bool> tokenIdList;
    std::vector<std::string> permList;
    Utils::UniqueWriteGuard<Utils::RWLock> infoGuard(this->userPolicyLock_);
    if (permPolicyList_.empty()) {
        ACCESSTOKEN_LOG_WARN(LABEL, "UserPolicy has been cleared.");
        return RET_SUCCESS;
    }
    permList.assign(permPolicyList_.begin(), permPolicyList_.end());
    std::map<int32_t, bool> changedUserList;
    for (const auto &userId : inactiveUserList_) {
        // All user comes to be active for permission manager.
        changedUserList[userId] = true;
    }
    GetGoalHapList(tokenIdList, changedUserList);
    int32_t ret = UpdatePermissionStateToKernel(permList, tokenIdList);
    // Lock range is large. While The number of ClearUserPolicy function calls is very small.
    if (ret == RET_SUCCESS) {
        permPolicyList_.clear();
        inactiveUserList_.clear();
    }
    return ret;
}

bool AccessTokenInfoManager::GetPermDialogCap(AccessTokenID tokenID)
{
    if (tokenID == INVALID_TOKENID) {
        ACCESSTOKEN_LOG_ERROR(LABEL, "Invalid tokenId.");
        return true;
    }
    Utils::UniqueReadGuard<Utils::RWLock> infoGuard(this->hapTokenInfoLock_);
    auto infoIter = hapTokenInfoMap_.find(tokenID);
    if ((infoIter == hapTokenInfoMap_.end()) || (infoIter->second == nullptr)) {
        ACCESSTOKEN_LOG_ERROR(LABEL, "TokenId is not exist in map.");
        return true;
    }
    return infoIter->second->IsPermDialogForbidden();
}

bool AccessTokenInfoManager::UpdateCapStateToDatabase(AccessTokenID tokenID, bool enable)
{
    GenericValues modifyValue;
    modifyValue.Put(TokenFiledConst::FIELD_FORBID_PERM_DIALOG, enable);

    GenericValues conditionValue;
    conditionValue.Put(TokenFiledConst::FIELD_TOKEN_ID, static_cast<int32_t>(tokenID));

    int32_t res = AccessTokenDb::GetInstance().Modify(AtmDataType::ACCESSTOKEN_HAP_INFO, modifyValue, conditionValue);
    if (res != 0) {
        ACCESSTOKEN_LOG_ERROR(LABEL,
            "Update tokenID %{public}u permissionDialogForbidden %{public}d to database failed", tokenID, enable);
        return false;
    }

    return true;
}

int AccessTokenInfoManager::VerifyNativeAccessToken(AccessTokenID tokenID, const std::string& permissionName)
{
    if (!PermissionDefinitionCache::GetInstance().HasDefinition(permissionName)) {
        if (PermissionDefinitionCache::GetInstance().IsHapPermissionDefEmpty()) {
            ACCESSTOKEN_LOG_INFO(LABEL, "Permission definition set has not been installed!");
            if (AccessTokenIDManager::GetInstance().GetTokenIdTypeEnum(tokenID) == TOKEN_NATIVE) {
                return PERMISSION_GRANTED;
            }
            ACCESSTOKEN_LOG_ERROR(LABEL, "Token: %{public}d type error!", tokenID);
            return PERMISSION_DENIED;
        }
        ACCESSTOKEN_LOG_ERROR(LABEL, "No definition for permission: %{public}s!", permissionName.c_str());
        return PERMISSION_DENIED;
    }
    uint32_t code;
    if (!TransferPermissionToOpcode(permissionName, code)) {
        ACCESSTOKEN_LOG_ERROR(LABEL, "Invalid perm(%{public}s)", permissionName.c_str());
        return PERMISSION_DENIED;
    }

    Utils::UniqueReadGuard<Utils::RWLock> infoGuard(this->nativeTokenInfoLock_);
    auto iter = nativeTokenInfoMap_.find(tokenID);
    if (iter == nativeTokenInfoMap_.end()) {
        ACCESSTOKEN_LOG_ERROR(LABEL, "Id %{public}u is not exist.", tokenID);
        return PERMISSION_DENIED;
    }

    NativeTokenInfoCache cache = iter->second;
    for (size_t i = 0; i < cache.opCodeList.size(); ++i) {
        if (code == cache.opCodeList[i]) {
            return cache.statusList[i] ? PERMISSION_GRANTED : PERMISSION_DENIED;
        }
    }

    return PERMISSION_DENIED;
}

int32_t AccessTokenInfoManager::VerifyAccessToken(AccessTokenID tokenID, const std::string& permissionName)
{
    if (tokenID == INVALID_TOKENID) {
        HiSysEventWrite(HiviewDFX::HiSysEvent::Domain::ACCESS_TOKEN, "PERMISSION_CHECK",
            HiviewDFX::HiSysEvent::EventType::FAULT, "CODE", VERIFY_TOKEN_ID_ERROR, "CALLER_TOKENID",
            static_cast<AccessTokenID>(IPCSkeleton::GetCallingTokenID()), "PERMISSION_NAME", permissionName);
        ACCESSTOKEN_LOG_ERROR(LABEL, "TokenID is invalid");
        return PERMISSION_DENIED;
    }

    if (!PermissionValidator::IsPermissionNameValid(permissionName)) {
        ACCESSTOKEN_LOG_ERROR(LABEL, "PermissionName: %{public}s, invalid params!", permissionName.c_str());
        return PERMISSION_DENIED;
    }

    ATokenTypeEnum tokenType = AccessTokenIDManager::GetInstance().GetTokenIdTypeEnum(tokenID);
    if ((tokenType == TOKEN_NATIVE) || (tokenType == TOKEN_SHELL)) {
        return VerifyNativeAccessToken(tokenID, permissionName);
    }
    if (tokenType == TOKEN_HAP) {
        return PermissionManager::GetInstance().VerifyHapAccessToken(tokenID, permissionName);
    }
    ACCESSTOKEN_LOG_ERROR(LABEL, "TokenID: %{public}d, invalid tokenType!", tokenID);
    return PERMISSION_DENIED;
}

void AccessTokenInfoManager::ClearHapPolicy()
{
    ACCESSTOKEN_LOG_INFO(LABEL, "Enter.");
    Utils::UniqueReadGuard<Utils::RWLock> infoGuard(this->hapTokenInfoLock_);
    for (auto iter = hapTokenInfoMap_.begin(); iter != hapTokenInfoMap_.end(); iter++) {
        iter->second->ClearHapInfoPermissionPolicySet();
    }
}
} // namespace AccessToken
} // namespace Security
} // namespace OHOS
