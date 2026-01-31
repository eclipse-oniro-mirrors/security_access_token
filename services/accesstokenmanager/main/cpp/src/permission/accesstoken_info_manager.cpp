/*
 * Copyright (c) 2021-2025 Huawei Device Co., Ltd.
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
#include <cstdio>
#include <fcntl.h>
#include <unistd.h>
#include <securec.h>
#include "access_token.h"
#include "accesstoken_dfx_define.h"
#include "accesstoken_id_manager.h"
#include "accesstoken_common_log.h"
#include "accesstoken_remote_token_manager.h"
#include "access_token_db_operator.h"
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
#include "json_parse_loader.h"
#include "permission_manager.h"
#include "permission_map.h"
#include "permission_validator.h"
#include "perm_setproc.h"
#include "tokenid_attributes.h"
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
static const unsigned int SYSTEM_APP_FLAG = 0x0001;
static const unsigned int ATOMIC_SERVICE_FLAG = 0x0002;
static constexpr int32_t BASE_USER_RANGE = 200000;
static constexpr int32_t SYSTEM_APP = 1;
#ifdef SUPPORT_MANAGE_USER_POLICY
static constexpr int32_t MAX_USER_POLICY_SIZE = 1024;
#endif
#ifdef TOKEN_SYNC_ENABLE
static const int MAX_PTHREAD_NAME_LEN = 15; // pthread name max length
static const char* ACCESS_TOKEN_PACKAGE_NAME = "ohos.security.distributed_token_sync";
#endif
static const char* SYSTEM_RESOURCE_BUNDLE_NAME = "ohos.global.systemres";
static constexpr uint32_t TOKEN_ID_LOWMASK = 0xffffffff;
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
        LOGE(ATM_DOMAIN, ATM_TAG, "UnInitDeviceManager failed, code: %{public}d", ret);
    }
#endif

    this->hasInited_ = false;
    std::unique_lock<std::shared_mutex> monitorLock(this->monitorLock_);
    this->tokenMonitor_ = nullptr;
}

void AccessTokenInfoManager::Init(uint32_t& hapSize, uint32_t& nativeSize, uint32_t& pefDefSize, uint32_t& dlpSize,
    std::map<int32_t, TokenIdInfo>& tokenIdAplMap)
{
    std::unique_lock<std::shared_mutex> lk(this->managerLock_);
    if (hasInited_) {
        return;
    }

    LOGI(ATM_DOMAIN, ATM_TAG, "Init begin!");
    LibraryLoader loader(CONFIG_PARSE_LIBPATH);
    ConfigPolicyLoaderInterface* policy = loader.GetObject<ConfigPolicyLoaderInterface>();
    if (policy == nullptr) {
        LOGE(ATM_DOMAIN, ATM_TAG, "Dlopen libaccesstoken_json_parse failed.");
        return;
    }
    std::vector<NativeTokenInfoBase> tokenInfos;
    int ret = policy->GetAllNativeTokenInfo(tokenInfos);
    if (ret != RET_SUCCESS) {
        ReportSysEventServiceStartError(
            INIT_NATIVE_TOKENINFO_ERROR, "GetAllNativeTokenInfo fail from native json.", ret);
        LOGE(ATM_DOMAIN, ATM_TAG, "Failed to load native from native json, err=%{public}d.", ret);
        return;
    }

#ifdef SUPPORT_SANDBOX_APP
    std::vector<PermissionDlpMode> dlpPerms;
    ret = policy->GetDlpPermissions(dlpPerms);
    dlpSize = dlpPerms.size();
    if (ret == RET_SUCCESS) {
        LOGI(ATM_DOMAIN, ATM_TAG, "Load dlpPer size=%{public}u.", dlpSize);
        DlpPermissionSetManager::GetInstance().ProcessDlpPermInfos(dlpPerms);
    }
#endif

    InitHapTokenInfos(hapSize, tokenIdAplMap);
    nativeSize = tokenInfos.size();
    InitNativeTokenInfos(tokenInfos);
    pefDefSize = GetDefPermissionsSize();

    LOGI(ATM_DOMAIN, ATM_TAG,
        "Init success, hapSize %{public}u, nativeSize %{public}u, pefDefSize %{public}u, dlpSize %{public}u.",
        hapSize, nativeSize, pefDefSize, dlpSize);

    hasInited_ = true;
    {
        std::unique_lock<std::shared_mutex> monitorLock(this->monitorLock_);
        if (this->tokenMonitor_ == nullptr) {
            this->tokenMonitor_ = std::make_shared<VerifyAccessTokenMonitor>();
        }
    }
}

static bool IsSystemResource(const std::string& bundleName)
{
    return std::string(SYSTEM_RESOURCE_BUNDLE_NAME) == bundleName;
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
            LOGE(ATM_DOMAIN, ATM_TAG, "Initialize: InitDeviceManager error, result: %{public}d", ret);
        }
        LOGI(ATM_DOMAIN, ATM_TAG, "device manager part init end");
        return;
    };
    std::thread initThread(runner);
    initThread.detach();
}
#endif

int32_t AccessTokenInfoManager::AddHapInfoToCache(const GenericValues& tokenValue,
    const std::vector<GenericValues>& permStateRes, const std::vector<GenericValues>& extendedPermRes)
{
    AccessTokenID tokenId = static_cast<AccessTokenID>(tokenValue.GetInt(TokenFiledConst::FIELD_TOKEN_ID));
    std::string bundle = tokenValue.GetString(TokenFiledConst::FIELD_BUNDLE_NAME);
    int result = AccessTokenIDManager::GetInstance().RegisterTokenId(tokenId, TOKEN_HAP);
    if (result != RET_SUCCESS) {
        LOGE(ATM_DOMAIN, ATM_TAG, "TokenId %{public}u add id failed, error=%{public}d.", tokenId, result);
        ReportSysEventServiceStartError(INIT_HAP_TOKENINFO_ERROR,
            "RegisterTokenId fail, " + bundle + std::to_string(tokenId), result);
        return result;
    }
    std::shared_ptr<HapTokenInfoInner> hap = std::make_shared<HapTokenInfoInner>();
    result = hap->RestoreHapTokenInfo(tokenId, tokenValue, permStateRes, extendedPermRes);
    if (result != RET_SUCCESS) {
        AccessTokenIDManager::GetInstance().ReleaseTokenId(tokenId);
        LOGE(ATM_DOMAIN, ATM_TAG, "TokenId %{public}u restore failed.", tokenId);
        return result;
    }

    AccessTokenID oriTokenId = 0;
    result = AddHapTokenInfo(hap, oriTokenId);
    if (result != RET_SUCCESS) {
        AccessTokenIDManager::GetInstance().ReleaseTokenId(tokenId);
        LOGE(ATM_DOMAIN, ATM_TAG, "TokenId %{public}u add failed.", tokenId);
        ReportSysEventServiceStartError(INIT_HAP_TOKENINFO_ERROR,
            "AddHapTokenInfo fail, " + bundle + std::to_string(tokenId), result);
        return result;
    }

    AccessTokenIDEx tokenIdEx = {0};
    tokenIdEx.tokenIdExStruct.tokenID = tokenId;
    tokenIdEx.tokenIdExStruct.tokenAttr = hap->GetAttr();

    HapDfxInfo dfxInfo;
    dfxInfo.sceneCode = AddHapSceneCode::INIT;
    dfxInfo.tokenId = tokenId;
    dfxInfo.oriTokenId = oriTokenId;
    dfxInfo.tokenIdEx = tokenIdEx;
    dfxInfo.userID = hap->GetUserID();
    dfxInfo.bundleName = hap->GetBundleName();
    dfxInfo.instIndex = hap->GetInstIndex();
    ReportSysEventAddHap(RET_SUCCESS, dfxInfo, false);

    LOGI(ATM_DOMAIN, ATM_TAG,
        " Restore hap token %{public}u bundle name %{public}s user %{public}d,"
        " permSize %{public}d, inst %{public}d ok!",
        tokenId, hap->GetBundleName().c_str(), hap->GetUserID(), hap->GetReqPermissionSize(), hap->GetInstIndex());

    return RET_SUCCESS;
}

void AccessTokenInfoManager::InitHapTokenInfos(uint32_t& hapSize, std::map<int32_t, TokenIdInfo>& tokenIdAplMap)
{
    GenericValues conditionValue;
    std::vector<GenericValues> hapTokenRes;
    std::vector<GenericValues> permStateRes;
    std::vector<GenericValues> extendedPermRes;
    int32_t ret = AccessTokenDbOperator::Find(AtmDataType::ACCESSTOKEN_HAP_INFO, conditionValue, hapTokenRes);
    if (ret != RET_SUCCESS) {
        ReportSysEventServiceStartError(INIT_HAP_TOKENINFO_ERROR, "Load hap from db fail.", ret);
    }
    ret = AccessTokenDbOperator::Find(AtmDataType::ACCESSTOKEN_PERMISSION_STATE, conditionValue, permStateRes);
    if (ret != RET_SUCCESS) {
        ReportSysEventServiceStartError(INIT_HAP_TOKENINFO_ERROR, "Load perm state from db fail.", ret);
    }
    ret = AccessTokenDbOperator::Find(AtmDataType::ACCESSTOKEN_PERMISSION_EXTEND_VALUE, conditionValue,
        extendedPermRes);
    if (ret != RET_SUCCESS) { // extendedPermRes may be empty
        ReportSysEventServiceStartError(INIT_HAP_TOKENINFO_ERROR, "Load exetended value from db fail.", ret);
    }
    for (const GenericValues& tokenValue : hapTokenRes) {
        int32_t tokenId = tokenValue.GetInt(TokenFiledConst::FIELD_TOKEN_ID);
        TokenIdInfo tokenIdInfo;
        tokenIdInfo.apl = tokenValue.GetInt(TokenFiledConst::FIELD_APL);
        tokenIdInfo.isSystemApp = tokenValue.GetInt(TokenFiledConst::FIELD_TOKEN_ATTR) == SYSTEM_APP;
        ret = AddHapInfoToCache(tokenValue, permStateRes, extendedPermRes);
        if (ret != RET_SUCCESS) {
            continue;
        }
        hapSize++;
        tokenIdAplMap[tokenId] = tokenIdInfo;
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

int AccessTokenInfoManager::AddHapTokenInfo(const std::shared_ptr<HapTokenInfoInner>& info, AccessTokenID& oriTokenId)
{
    if (info == nullptr) {
        LOGE(ATM_DOMAIN, ATM_TAG, "Token info is null.");
        return AccessTokenError::ERR_PARAM_INVALID;
    }
    AccessTokenID id = info->GetTokenID();
    AccessTokenID idRemoved = INVALID_TOKENID;
    {
        std::unique_lock<std::shared_mutex> infoGuard(this->hapTokenInfoLock_);
        if (hapTokenInfoMap_.count(id) > 0) {
            LOGC(ATM_DOMAIN, ATM_TAG, "Token %{public}u info has exist.", id);
            return AccessTokenError::ERR_TOKENID_HAS_EXISTED;
        }

        if (!info->IsRemote()) {
            std::string hapUniqueKey = GetHapUniqueStr(info);
            auto iter = hapTokenIdMap_.find(hapUniqueKey);
            if (iter != hapTokenIdMap_.end()) {
                LOGI(ATM_DOMAIN, ATM_TAG, "Token %{public}u Unique info has exist, update.", id);
                idRemoved = iter->second;
            }
            hapTokenIdMap_[hapUniqueKey] = id;
        }
        hapTokenInfoMap_[id] = info;
    }
    if (idRemoved != INVALID_TOKENID) {
        oriTokenId = idRemoved;
        (void)RemoveHapTokenInfo(idRemoved);
    }
    // add hap to kernel
    int32_t userId = info->GetUserID();
    PermissionManager::GetInstance().AddHapPermToKernel(id, GetRestrictedPermListByUserId(userId));
    return RET_SUCCESS;
}

std::shared_ptr<HapTokenInfoInner> AccessTokenInfoManager::GetHapTokenInfoInnerFromDb(AccessTokenID id)
{
    GenericValues conditionValue;
    conditionValue.Put(TokenFiledConst::FIELD_TOKEN_ID, static_cast<int32_t>(id));

    std::vector<GenericValues> hapTokenResults;
    int32_t ret = AccessTokenDbOperator::Find(AtmDataType::ACCESSTOKEN_HAP_INFO, conditionValue, hapTokenResults);
    if (ret != RET_SUCCESS || hapTokenResults.empty()) {
        LOGC(ATM_DOMAIN, ATM_TAG, "Failed to find Id(%{public}u) from hap_token_table, err: %{public}d, "
            "hapSize: %{public}zu, mapSize: %{public}zu.", id, ret, hapTokenResults.size(), hapTokenInfoMap_.size());
        return nullptr;
    }

    std::vector<GenericValues> permStateRes;
    ret = AccessTokenDbOperator::Find(AtmDataType::ACCESSTOKEN_PERMISSION_STATE, conditionValue, permStateRes);
    if (ret != RET_SUCCESS) {
        LOGC(ATM_DOMAIN, ATM_TAG, "Failed to find Id(%{public}u) from perm_state_table, err: %{public}d, "
            "mapSize: %{public}zu.", id, ret, hapTokenInfoMap_.size());
        return nullptr;
    }

    std::vector<GenericValues> extendedPermRes;
    ret = AccessTokenDbOperator::Find(AtmDataType::ACCESSTOKEN_PERMISSION_EXTEND_VALUE, conditionValue,
        extendedPermRes);
    if (ret != RET_SUCCESS) { // extendedPermRes may be empty
        LOGC(ATM_DOMAIN, ATM_TAG, "Failed to find Id(%{public}u) from perm_extend_value_table, err: %{public}d, "
            "mapSize: %{public}zu.", id, ret, hapTokenInfoMap_.size());
        return nullptr;
    }

    std::shared_ptr<HapTokenInfoInner> hap = std::make_shared<HapTokenInfoInner>();
    ret = hap->RestoreHapTokenInfo(id, hapTokenResults[0], permStateRes, extendedPermRes);
    if (ret != RET_SUCCESS) {
        LOGC(ATM_DOMAIN, ATM_TAG, "Id %{public}u restore failed, err: %{public}d, mapSize: %{public}zu.",
            id, ret, hapTokenInfoMap_.size());
        return nullptr;
    }

    std::unique_lock<std::shared_mutex> infoGuard(this->hapTokenInfoLock_);
    (void)AccessTokenIDManager::GetInstance().RegisterTokenId(id, TOKEN_HAP);
    hapTokenIdMap_[GetHapUniqueStr(hap)] = id;
    hapTokenInfoMap_[id] = hap;
    PermissionManager::GetInstance().AddHapPermToKernel(id, std::vector<uint32_t>());
    LOGI(ATM_DOMAIN, ATM_TAG, " Token %{public}u is not found in map(mapSize: %{public}zu), begin load from DB,"
        " restore bundle %{public}s user %{public}d, idx %{public}d, permSize %{public}d.", id, hapTokenInfoMap_.size(),
        hap->GetBundleName().c_str(), hap->GetUserID(), hap->GetInstIndex(), hap->GetReqPermissionSize());
    return hap;
}

std::shared_ptr<HapTokenInfoInner> AccessTokenInfoManager::GetHapTokenInfoInner(AccessTokenID id)
{
    {
        std::shared_lock<std::shared_mutex> infoGuard(this->hapTokenInfoLock_);
        auto iter = hapTokenInfoMap_.find(id);
        if (iter != hapTokenInfoMap_.end()) {
            return iter->second;
        }
    }
    return GetHapTokenInfoInnerFromDb(id);
}

int32_t AccessTokenInfoManager::GetHapTokenDlpType(AccessTokenID id)
{
    std::shared_lock<std::shared_mutex> infoGuard(this->hapTokenInfoLock_);
    auto iter = hapTokenInfoMap_.find(id);
    if ((iter != hapTokenInfoMap_.end()) && (iter->second != nullptr)) {
        return iter->second->GetDlpType();
    }
    LOGE(ATM_DOMAIN, ATM_TAG, "Token %{public}u is invalid, mapSize: %{public}zu.", id, hapTokenInfoMap_.size());
    return BUTT_DLP_TYPE;
}

bool AccessTokenInfoManager::IsTokenIdExist(AccessTokenID id)
{
    {
        std::shared_lock<std::shared_mutex> infoGuard(this->hapTokenInfoLock_);
        if (hapTokenInfoMap_.count(id) != 0) {
            return true;
        }
    }
    {
        std::shared_lock<std::shared_mutex> infoGuard(this->nativeTokenInfoLock_);
        if (nativeTokenInfoMap_.count(id) != 0) {
            return true;
        }
    }
    return false;
}

int32_t AccessTokenInfoManager::GetTokenIDByUserID(int32_t userID, std::unordered_set<AccessTokenID>& tokenIdList)
{
    GenericValues conditionValue;
    std::vector<GenericValues> tokenIDResults;
    conditionValue.Put(TokenFiledConst::FIELD_USER_ID, userID);

    int32_t ret = AccessTokenDbOperator::Find(AtmDataType::ACCESSTOKEN_HAP_INFO, conditionValue, tokenIDResults);
    if (ret != RET_SUCCESS) {
        LOGE(ATM_DOMAIN, ATM_TAG, "UserID(%{public}d) find tokenID failed, ret: %{public}d.", userID, ret);
        return ret;
    }
    if (tokenIDResults.empty()) {
        LOGE(ATM_DOMAIN, ATM_TAG, "UserID(%{public}d) find tokenID empty.", userID);
        return RET_SUCCESS;
    }

    for (const GenericValues& tokenIDResult : tokenIDResults) {
        AccessTokenID tokenId = (AccessTokenID)tokenIDResult.GetInt(TokenFiledConst::FIELD_TOKEN_ID);
        tokenIdList.emplace(tokenId);
    }
    return RET_SUCCESS;
}

int AccessTokenInfoManager::GetHapTokenInfo(AccessTokenID tokenID, HapTokenInfo& info)
{
    std::shared_ptr<HapTokenInfoInner> infoPtr = GetHapTokenInfoInner(tokenID);
    if (infoPtr == nullptr) {
        LOGE(ATM_DOMAIN, ATM_TAG, "Token %{public}u is invalid.", tokenID);
        return AccessTokenError::ERR_TOKENID_NOT_EXIST;
    }
    infoPtr->TranslateToHapTokenInfo(info);
    return RET_SUCCESS;
}

int AccessTokenInfoManager::GetNativeTokenInfo(AccessTokenID tokenID, NativeTokenInfoBase& info)
{
    std::shared_lock<std::shared_mutex> infoGuard(this->nativeTokenInfoLock_);
    auto iter = nativeTokenInfoMap_.find(tokenID);
    if (iter == nativeTokenInfoMap_.end()) {
        LOGE(ATM_DOMAIN, ATM_TAG, "Id %{public}u is not exist.", tokenID);
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
        LOGC(ATM_DOMAIN, ATM_TAG, "Token %{public}u is not hap.", id);
        return ERR_PARAM_INVALID;
    }
    std::shared_ptr<HapTokenInfoInner> info;
    {
        std::unique_lock<std::shared_mutex> infoGuard(this->hapTokenInfoLock_);
        // remove hap to kernel
        PermissionManager::GetInstance().RemovePermFromKernel(id);
        AccessTokenIDManager::GetInstance().ReleaseTokenId(id);

        if (hapTokenInfoMap_.count(id) == 0) {
            LOGC(ATM_DOMAIN, ATM_TAG, "Hap token %{public}u no exist.", id);
            return ERR_TOKENID_NOT_EXIST;
        }

        info = hapTokenInfoMap_[id];
        if (info == nullptr) {
            LOGC(ATM_DOMAIN, ATM_TAG, "Hap token %{public}u is null.", id);
            return ERR_TOKEN_INVALID;
        }
        if (info->IsRemote()) {
            LOGC(ATM_DOMAIN, ATM_TAG, "Remote hap token %{public}u can not delete.", id);
            return ERR_IDENTITY_CHECK_FAILED;
        }
        std::string HapUniqueKey = GetHapUniqueStr(info);
        auto iter = hapTokenIdMap_.find(HapUniqueKey);
        if ((iter != hapTokenIdMap_.end()) && (iter->second == id)) {
            hapTokenIdMap_.erase(HapUniqueKey);
        }
        hapTokenInfoMap_.erase(id);
    }
    int32_t ret = RemoveHapTokenInfoFromDb(info);
    if (ret != RET_SUCCESS) {
        LOGC(ATM_DOMAIN, ATM_TAG, "Remove info from db failed, ret is %{public}d", ret);
    }

    LOGI(ATM_DOMAIN, ATM_TAG, "Remove hap token %{public}u ok!", id);
    std::vector<std::string> permissionList;
    HapTokenInfoInner::GetGrantedPermByTokenId(id, GetRestrictedPermListByUserId(info->GetUserID()), permissionList);
    if (permissionList.size() != 0) {
        PermissionManager::GetInstance().ParamUpdate(permissionList[0], 0, true);
    }
    for (const auto& perm : permissionList) {
        CallbackManager::GetInstance().ExecuteCallbackAsync(id, perm, STATE_CHANGE_REVOKED);
    }

#ifdef TOKEN_SYNC_ENABLE
    TokenModifyNotifier::GetInstance().NotifyTokenDelete(id);
#endif

    return RET_SUCCESS;
}

int AccessTokenInfoManager::RemoveNativeTokenInfo(AccessTokenID id)
{
    ATokenTypeEnum type = AccessTokenIDManager::GetInstance().GetTokenIdType(id);
    if ((type != TOKEN_NATIVE) && (type != TOKEN_SHELL)) {
        LOGE(ATM_DOMAIN, ATM_TAG, "Token %{public}u is not native or shell.", id);
        return ERR_PARAM_INVALID;
    }

    {
        std::unique_lock<std::shared_mutex> infoGuard(this->nativeTokenInfoLock_);
        if (nativeTokenInfoMap_.count(id) == 0) {
            LOGE(ATM_DOMAIN, ATM_TAG, "Native token %{public}u is null.", id);
            return ERR_TOKENID_NOT_EXIST;
        }

        nativeTokenInfoMap_.erase(id);
    }
    AccessTokenIDManager::GetInstance().ReleaseTokenId(id);
    LOGI(ATM_DOMAIN, ATM_TAG, "Remove native token %{public}u ok!", id);

    // remove native to kernel
    PermissionManager::GetInstance().RemovePermFromKernel(id);
    return RET_SUCCESS;
}

int32_t AccessTokenInfoManager::CheckHapInfoParam(const HapInfoParams& info, const HapPolicy& policy)
{
    if ((!DataValidator::IsUserIdValid(info.userID)) || (!DataValidator::IsBundleNameValid(info.bundleName)) ||
        (!DataValidator::IsAppIDDescValid(info.appIDDesc)) || (!DataValidator::IsDomainValid(policy.domain)) ||
        (!DataValidator::IsDlpTypeValid(info.dlpType)) || (info.isRestore && info.tokenID == INVALID_TOKENID) ||
         !DataValidator::IsAclExtendedMapSizeValid(policy.aclExtendedMap)) {
        LOGC(ATM_DOMAIN, ATM_TAG, "Hap token param failed");
        return AccessTokenError::ERR_PARAM_INVALID;
    }

    for (const auto& extendValue : policy.aclExtendedMap) {
        if (!IsDefinedPermission(extendValue.first)) {
            continue;
        }
        if (!DataValidator::IsAclExtendedMapContentValid(extendValue.first, extendValue.second)) {
            LOGC(ATM_DOMAIN, ATM_TAG, "Acl extended content is invalid.");
            return AccessTokenError::ERR_PARAM_INVALID;
        }
    }
    return ERR_OK;
}

void AccessTokenInfoManager::ReportAddHapIdChange(const std::shared_ptr<HapTokenInfoInner>& hapInfo,
    AccessTokenID oriTokenId)
{
    HapDfxInfo dfxInfo;
    dfxInfo.sceneCode = AddHapSceneCode::TOKEN_ID_CHANGE;
    dfxInfo.tokenId = hapInfo->GetTokenID();
    dfxInfo.oriTokenId = oriTokenId;
    dfxInfo.userID = hapInfo->GetUserID();
    dfxInfo.bundleName = hapInfo->GetBundleName();
    dfxInfo.instIndex = hapInfo->GetInstIndex();
    ReportSysEventAddHap(RET_SUCCESS, dfxInfo, false);
}

int32_t AccessTokenInfoManager::RegisterTokenId(const HapInfoParams& info, AccessTokenID& tokenId)
{
    int32_t res = RET_SUCCESS;

    if (info.isRestore) {
        LOGI(ATM_DOMAIN, ATM_TAG, "IsRestore is true, tokenId is %{public}u.", info.tokenID);

        res = AccessTokenIDManager::GetInstance().RegisterTokenId(info.tokenID, TOKEN_HAP);
        if (res != RET_SUCCESS) {
            LOGC(ATM_DOMAIN, ATM_TAG, "Token Id register failed, errCode is %{public}d.", res);
            return res;
        }

        tokenId = info.tokenID;
    } else {
        int32_t dlpFlag = (info.dlpType > DLP_COMMON) ? 1 : 0;
        int32_t cloneFlag = ((dlpFlag == 0) && (info.instIndex) > 0) ? 1 : 0;
        tokenId = AccessTokenIDManager::GetInstance().CreateAndRegisterTokenId(TOKEN_HAP, dlpFlag, cloneFlag);
        if (tokenId == 0) {
            LOGC(ATM_DOMAIN, ATM_TAG, "Token Id create failed");
            return ERR_TOKENID_CREATE_FAILED;
        }
    }

    return res;
}

void AccessTokenInfoManager::AddTokenIdToUndefValues(AccessTokenID tokenId, std::vector<GenericValues>& undefValues)
{
    for (auto& value : undefValues) {
        value.Put(TokenFiledConst::FIELD_TOKEN_ID, static_cast<int32_t>(tokenId));
    }
}

int AccessTokenInfoManager::CreateHapTokenInfo(const HapInfoParams& info, const HapPolicy& policy,
    AccessTokenIDEx& tokenIdEx, std::vector<GenericValues>& undefValues)
{
    if (CheckHapInfoParam(info, policy) != ERR_OK) {
        return AccessTokenError::ERR_PARAM_INVALID;
    }
    AccessTokenID tokenId;
    int32_t ret = RegisterTokenId(info, tokenId);
    if (ret != RET_SUCCESS) {
        return ret;
    }
    AddTokenIdToUndefValues(tokenId, undefValues);
#ifdef SUPPORT_SANDBOX_APP
    std::shared_ptr<HapTokenInfoInner> tokenInfo;
    HapPolicy policyNew = policy;
    if (info.dlpType != DLP_COMMON) {
        DlpPermissionSetManager::GetInstance().UpdatePermStateWithDlpInfo(info.dlpType, policyNew.permStateList);
    }
    tokenInfo = std::make_shared<HapTokenInfoInner>(tokenId, info, policyNew);
#else
    std::shared_ptr<HapTokenInfoInner> tokenInfo = std::make_shared<HapTokenInfoInner>(tokenId, info, policy);
#endif
    ret = AddHapTokenInfoToDb(tokenInfo, info.appIDDesc, policy, false, undefValues);
    if (ret != RET_SUCCESS) {
        LOGC(ATM_DOMAIN, ATM_TAG, "AddHapTokenInfoToDb failed, errCode is %{public}d.", ret);
        AccessTokenIDManager::GetInstance().ReleaseTokenId(tokenId);
        return ret;
    }

    AccessTokenID oriTokenID = 0;
    ret = AddHapTokenInfo(tokenInfo, oriTokenID);
    if (ret != RET_SUCCESS) {
        LOGC(ATM_DOMAIN, ATM_TAG, "%{public}s add token info failed", info.bundleName.c_str());
        AccessTokenIDManager::GetInstance().ReleaseTokenId(tokenId);
        (void)RemoveHapTokenInfoFromDb(tokenInfo);
        return ret;
    }

    if (oriTokenID != 0) {
        ReportAddHapIdChange(tokenInfo, oriTokenID);
    }

    LOGI(ATM_DOMAIN, ATM_TAG,
        "Create hap token %{public}u bundleName %{public}s user %{public}d inst %{public}d isRestore %{public}d ok",
        tokenId, tokenInfo->GetBundleName().c_str(), tokenInfo->GetUserID(), tokenInfo->GetInstIndex(), info.isRestore);
    (void)AllocAccessTokenIDEx(info, tokenId, tokenIdEx);
    return RET_SUCCESS;
}

int AccessTokenInfoManager::AllocAccessTokenIDEx(
    const HapInfoParams& info, AccessTokenID tokenId, AccessTokenIDEx& tokenIdEx)
{
    tokenIdEx.tokenIdExStruct.tokenID = tokenId;
    if (info.isSystemApp) {
        tokenIdEx.tokenIdExStruct.tokenAttr |= SYSTEM_APP_FLAG;
    }
    if (info.isAtomicService) {
        tokenIdEx.tokenIdExStruct.tokenAttr |= ATOMIC_SERVICE_FLAG;
    }
    return RET_SUCCESS;
}

AccessTokenIDEx AccessTokenInfoManager::GetHapTokenID(int32_t userID, const std::string& bundleName, int32_t instIndex)
{
    std::shared_lock<std::shared_mutex> infoGuard(this->hapTokenInfoLock_);
    std::string HapUniqueKey = GetHapUniqueStr(userID, bundleName, instIndex);
    AccessTokenIDEx tokenIdEx = {0};
    auto iter = hapTokenIdMap_.find(HapUniqueKey);
    if (iter != hapTokenIdMap_.end()) {
        AccessTokenID tokenId = iter->second;
        auto infoIter = hapTokenInfoMap_.find(tokenId);
        if (infoIter != hapTokenInfoMap_.end()) {
            if (infoIter->second == nullptr) {
                LOGE(ATM_DOMAIN, ATM_TAG, "HapTokenInfoInner is nullptr");
                return tokenIdEx;
            }
            HapTokenInfo info = infoIter->second->GetHapInfoBasic();
            tokenIdEx.tokenIdExStruct.tokenID = info.tokenID;
            tokenIdEx.tokenIdExStruct.tokenAttr = info.tokenAttr;
        }
    }
    return tokenIdEx;
}

void AccessTokenInfoManager::GetNativePermissionList(const NativeTokenInfoBase& native,
    std::vector<uint32_t>& opCodeList, std::vector<bool>& statusList)
{
    // need to process aclList
    for (const auto& state : native.permStateList) {
        uint32_t code;
        // add IsPermissionReqValid to filter invalid permission
        if (TransferPermissionToOpcode(state.permissionName, code)) {
            opCodeList.emplace_back(code);
            statusList.emplace_back(state.grantStatus == PERMISSION_GRANTED);
        }
    }
}

void AccessTokenInfoManager::InitNativeTokenInfos(const std::vector<NativeTokenInfoBase>& tokenInfos)
{
    for (const auto& info: tokenInfos) {
        AccessTokenID tokenId = info.tokenID;
        std::string process = info.processName;
        // add tokenId to cache
        ATokenTypeEnum type = TokenIDAttributes::GetTokenIdTypeEnum(tokenId);
        int32_t res = AccessTokenIDManager::GetInstance().RegisterTokenId(tokenId, type);
        if (res != RET_SUCCESS && res != ERR_TOKENID_HAS_EXISTED) {
            LOGE(ATM_DOMAIN, ATM_TAG, "Token id register fail, res is %{public}d.", res);
            ReportSysEventServiceStartError(INIT_NATIVE_TOKENINFO_ERROR,
                "RegisterTokenId fail, " + process + std::to_string(tokenId), res);
            continue;
        }
        std::vector<uint32_t> opCodeList;
        std::vector<bool> statusList;
        GetNativePermissionList(info, opCodeList, statusList);
        // add native token info to cache
        std::unique_lock<std::shared_mutex> infoGuard(this->nativeTokenInfoLock_);
        NativeTokenInfoCache cache;
        cache.processName = process;
        cache.apl = static_cast<ATokenAplEnum>(info.apl);
        cache.opCodeList = opCodeList;
        cache.statusList = statusList;

        nativeTokenInfoMap_[tokenId] = cache;
        PermissionManager::GetInstance().AddNativePermToKernel(tokenId, cache.opCodeList, cache.statusList);
        LOGI(ATM_DOMAIN, ATM_TAG,
            "Init native token %{public}u process name %{public}s, permSize %{public}zu ok!",
            tokenId, process.c_str(), info.permStateList.size());
    }
}

int32_t AccessTokenInfoManager::UpdateHapToken(AccessTokenIDEx& tokenIdEx, const UpdateHapInfoParams& info,
    const std::vector<PermissionStatus>& permStateList, const HapPolicy& hapPolicy,
    std::vector<GenericValues>& undefValues)
{
    AccessTokenID tokenID = tokenIdEx.tokenIdExStruct.tokenID;
    if (!DataValidator::IsAppIDDescValid(info.appIDDesc)) {
        LOGC(ATM_DOMAIN, ATM_TAG, "Token %{public}u parm format error!", tokenID);
        return AccessTokenError::ERR_PARAM_INVALID;
    }
    std::shared_ptr<HapTokenInfoInner> infoPtr = GetHapTokenInfoInner(tokenID);
    if (infoPtr == nullptr) {
        LOGC(ATM_DOMAIN, ATM_TAG, "Token %{public}u is invalid, can not update!", tokenID);
        return AccessTokenError::ERR_TOKENID_NOT_EXIST;
    }

    if (infoPtr->IsRemote()) {
        LOGC(ATM_DOMAIN, ATM_TAG, "Remote hap token %{public}u can not update!", tokenID);
        return ERR_IDENTITY_CHECK_FAILED;
    }
    if (info.isSystemApp) {
        tokenIdEx.tokenIdExStruct.tokenAttr |= SYSTEM_APP_FLAG;
    } else {
        tokenIdEx.tokenIdExStruct.tokenAttr &= ~SYSTEM_APP_FLAG;
    }
    if (info.isAtomicService) {
        tokenIdEx.tokenIdExStruct.tokenAttr |= ATOMIC_SERVICE_FLAG;
    } else {
        tokenIdEx.tokenIdExStruct.tokenAttr &= ~ATOMIC_SERVICE_FLAG;
    }
    {
        std::unique_lock<std::shared_mutex> infoGuard(this->hapTokenInfoLock_);
        infoPtr->Update(info, permStateList, hapPolicy);
    }

    AddTokenIdToUndefValues(tokenID, undefValues);
    int32_t ret = AddHapTokenInfoToDb(infoPtr, info.appIDDesc, hapPolicy, true, undefValues);
    if (ret != RET_SUCCESS) {
        LOGC(ATM_DOMAIN, ATM_TAG, "Add hap info %{public}u to db failed!", tokenID);
        return ret;
    }
    LOGI(ATM_DOMAIN, ATM_TAG, "Token %{public}u bundle name %{public}s user %{public}d \
        inst %{public}d tokenAttr %{public}d update ok!", tokenID, infoPtr->GetBundleName().c_str(),
        infoPtr->GetUserID(), infoPtr->GetInstIndex(), infoPtr->GetHapInfoBasic().tokenAttr);

#ifdef TOKEN_SYNC_ENABLE
    TokenModifyNotifier::GetInstance().NotifyTokenModify(tokenID);
#endif
    // update hap to kernel
    PermissionManager::GetInstance().AddHapPermToKernel(tokenID, GetRestrictedPermListByUserId(infoPtr->GetUserID()));
    return RET_SUCCESS;
}

#ifdef TOKEN_SYNC_ENABLE
int AccessTokenInfoManager::GetHapTokenSync(AccessTokenID tokenID, HapTokenInfoForSync& hapSync)
{
    std::shared_ptr<HapTokenInfoInner> infoPtr = GetHapTokenInfoInner(tokenID);
    if (infoPtr == nullptr || infoPtr->IsRemote()) {
        LOGE(ATM_DOMAIN, ATM_TAG, "Token %{public}u is invalid.", tokenID);
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
        LOGI(ATM_DOMAIN, ATM_TAG, "Token %{public}u is null or not remote, can not update!", mapID);
        return ERR_IDENTITY_CHECK_FAILED;
    }
    std::unique_lock<std::shared_mutex> infoGuard(this->hapTokenInfoLock_);
    infoPtr->UpdateRemoteHapTokenInfo(mapID, hapSync.baseInfo, hapSync.permStateList);
    // update remote hap to kernel
    PermissionManager::GetInstance().AddHapPermToKernel(mapID, std::vector<uint32_t>());
    return RET_SUCCESS;
}

int AccessTokenInfoManager::CreateRemoteHapTokenInfo(AccessTokenID mapID, HapTokenInfoForSync& hapSync)
{
    std::shared_ptr<HapTokenInfoInner> hap = std::make_shared<HapTokenInfoInner>(mapID, hapSync);
    hap->SetRemote(true);

    AccessTokenID oriTokenId = 0;
    int ret = AddHapTokenInfo(hap, oriTokenId);
    if (ret != RET_SUCCESS) {
        LOGE(ATM_DOMAIN, ATM_TAG, "Add local token failed, err: %{public}d.", ret);
        return ret;
    }

    HapDfxInfo dfxInfo;
    dfxInfo.sceneCode = AddHapSceneCode::MAP;
    dfxInfo.tokenId = hap->GetTokenID();
    dfxInfo.oriTokenId = oriTokenId;
    dfxInfo.userID = hap->GetUserID();
    dfxInfo.bundleName = hap->GetBundleName();
    dfxInfo.instIndex = hap->GetInstIndex();
    ReportSysEventAddHap(RET_SUCCESS, dfxInfo, false);

    return RET_SUCCESS;
}

bool AccessTokenInfoManager::IsRemoteHapTokenValid(const std::string& deviceID, const HapTokenInfoForSync& hapSync)
{
    std::string errReason;
    if (!DataValidator::IsDeviceIdValid(deviceID)) {
        errReason = "respond deviceID error";
    } else if (!DataValidator::IsUserIdValid(hapSync.baseInfo.userID)) {
        errReason = "respond userID error";
    } else if (!DataValidator::IsBundleNameValid(hapSync.baseInfo.bundleName)) {
        errReason = "respond bundleName error";
    } else if (!DataValidator::IsTokenIDValid(hapSync.baseInfo.tokenID)) {
        errReason = "respond tokenID error";
    } else if (!DataValidator::IsDlpTypeValid(hapSync.baseInfo.dlpType)) {
        errReason = "respond dlpType error";
    } else if (hapSync.baseInfo.ver != DEFAULT_TOKEN_VERSION) {
        errReason = "respond version error";
    } else if (TokenIDAttributes::GetTokenIdTypeEnum(hapSync.baseInfo.tokenID) != TOKEN_HAP) {
        errReason = "respond token type error";
    } else {
        return true;
    }

    (void)HiSysEventWrite(HiviewDFX::HiSysEvent::Domain::ACCESS_TOKEN, "PERMISSION_SYNC",
        HiviewDFX::HiSysEvent::EventType::FAULT, "CODE", TOKEN_SYNC_RESPONSE_ERROR,
        "REMOTE_ID", ConstantCommon::EncryptDevId(deviceID), "ERROR_REASON", errReason);
    return false;
}

int AccessTokenInfoManager::SetRemoteHapTokenInfo(const std::string& deviceID, HapTokenInfoForSync& hapSync)
{
    if (!IsRemoteHapTokenValid(deviceID, hapSync)) {
        LOGE(ATM_DOMAIN, ATM_TAG, "Device %{public}s parms invalid", ConstantCommon::EncryptDevId(deviceID).c_str());
        return ERR_IDENTITY_CHECK_FAILED;
    }

    AccessTokenID remoteID = hapSync.baseInfo.tokenID;
    AccessTokenID mapID = AccessTokenRemoteTokenManager::GetInstance().GetDeviceMappingTokenID(deviceID, remoteID);
    if (mapID != 0) {
        LOGI(ATM_DOMAIN, ATM_TAG, "Device %{public}s token %{public}u update exist remote hap token %{public}u.",
            ConstantCommon::EncryptDevId(deviceID).c_str(), remoteID, mapID);
        // update remote token mapping id
        hapSync.baseInfo.tokenID = mapID;
        return UpdateRemoteHapTokenInfo(mapID, hapSync);
    }

    mapID = AccessTokenRemoteTokenManager::GetInstance().MapRemoteDeviceTokenToLocal(deviceID, remoteID);
    if (mapID == 0) {
        LOGE(ATM_DOMAIN, ATM_TAG, "Device %{public}s token %{public}u map failed.",
            ConstantCommon::EncryptDevId(deviceID).c_str(), remoteID);
        return ERR_TOKEN_MAP_FAILED;
    }

    // update remote token mapping id
    hapSync.baseInfo.tokenID = mapID;
    int ret = CreateRemoteHapTokenInfo(mapID, hapSync);
    if (ret != RET_SUCCESS) {
        int result = AccessTokenRemoteTokenManager::GetInstance().RemoveDeviceMappingTokenID(deviceID, mapID);
        if (result != RET_SUCCESS) {
            LOGE(ATM_DOMAIN, ATM_TAG, "remove device map token id failed");
        }
        LOGI(ATM_DOMAIN, ATM_TAG, "Device %{public}s token %{public}u map to local token %{public}u failed.",
            ConstantCommon::EncryptDevId(deviceID).c_str(), remoteID, mapID);
        return ret;
    }
    LOGI(ATM_DOMAIN, ATM_TAG, "Device %{public}s token %{public}u map to local token %{public}u success.",
        ConstantCommon::EncryptDevId(deviceID).c_str(), remoteID, mapID);
    return RET_SUCCESS;
}

int AccessTokenInfoManager::DeleteRemoteToken(const std::string& deviceID, AccessTokenID tokenID)
{
    if (!DataValidator::IsDeviceIdValid(deviceID)) {
        LOGE(ATM_DOMAIN, ATM_TAG, "Device %{public}s parms invalid.",
            ConstantCommon::EncryptDevId(deviceID).c_str());
        return AccessTokenError::ERR_PARAM_INVALID;
    }
    AccessTokenID mapID = AccessTokenRemoteTokenManager::GetInstance().GetDeviceMappingTokenID(deviceID, tokenID);
    if (mapID == 0) {
        LOGE(ATM_DOMAIN, ATM_TAG, "Device %{public}s tokenId %{public}u is not mapped.",
            ConstantCommon::EncryptDevId(deviceID).c_str(), tokenID);
        return ERR_TOKEN_MAP_FAILED;
    }

    ATokenTypeEnum type = TokenIDAttributes::GetTokenIdTypeEnum(mapID);
    if (type == TOKEN_HAP) {
        std::unique_lock<std::shared_mutex> infoGuard(this->hapTokenInfoLock_);
        if (hapTokenInfoMap_.count(mapID) == 0) {
            LOGE(ATM_DOMAIN, ATM_TAG, "Hap token %{public}u no exist.", mapID);
            return ERR_TOKEN_INVALID;
        }
        hapTokenInfoMap_.erase(mapID);
    } else if ((type == TOKEN_NATIVE) || (type == TOKEN_SHELL)) {
        std::unique_lock<std::shared_mutex> infoGuard(this->nativeTokenInfoLock_);
        if (nativeTokenInfoMap_.count(mapID) == 0) {
            LOGE(ATM_DOMAIN, ATM_TAG, "Native token %{public}u is null.", mapID);
            return ERR_TOKEN_INVALID;
        }
        nativeTokenInfoMap_.erase(mapID);
    } else {
        LOGE(ATM_DOMAIN, ATM_TAG, "Mapping tokenId %{public}u type is unknown.", mapID);
    }

    return AccessTokenRemoteTokenManager::GetInstance().RemoveDeviceMappingTokenID(deviceID, tokenID);
}

AccessTokenID AccessTokenInfoManager::GetRemoteNativeTokenID(const std::string& deviceID, AccessTokenID tokenID)
{
    if ((!DataValidator::IsDeviceIdValid(deviceID)) || (tokenID == 0) ||
        ((TokenIDAttributes::GetTokenIdTypeEnum(tokenID) != TOKEN_NATIVE) &&
        (TokenIDAttributes::GetTokenIdTypeEnum(tokenID) != TOKEN_SHELL))) {
        LOGE(ATM_DOMAIN, ATM_TAG, "Device %{public}s parms invalid.",
            ConstantCommon::EncryptDevId(deviceID).c_str());
        return 0;
    }
    return AccessTokenRemoteTokenManager::GetInstance().GetDeviceMappingTokenID(deviceID, tokenID);
}

int AccessTokenInfoManager::DeleteRemoteDeviceTokens(const std::string& deviceID)
{
    if (!DataValidator::IsDeviceIdValid(deviceID)) {
        LOGE(ATM_DOMAIN, ATM_TAG, "Device %{public}s parms invalid.",
            ConstantCommon::EncryptDevId(deviceID).c_str());
        return AccessTokenError::ERR_PARAM_INVALID;
    }
    std::vector<AccessTokenID> remoteTokens;
    int ret = AccessTokenRemoteTokenManager::GetInstance().GetDeviceAllRemoteTokenID(deviceID, remoteTokens);
    if (ret != RET_SUCCESS) {
        LOGE(ATM_DOMAIN, ATM_TAG, "Device %{public}s have no remote token.",
            ConstantCommon::EncryptDevId(deviceID).c_str());
        return ret;
    }
    for (AccessTokenID remoteID : remoteTokens) {
        ret = DeleteRemoteToken(deviceID, remoteID);
        if (ret != RET_SUCCESS) {
            LOGE(ATM_DOMAIN, ATM_TAG, "delete remote token failed! deviceId=%{public}s, remoteId=%{public}d.", \
                ConstantCommon::EncryptDevId(deviceID).c_str(), remoteID);
        }
    }
    return ret;
}

FullTokenID AccessTokenInfoManager::GetFullRemoteTokenId(AccessTokenID id)
{
    HapTokenInfo info;
    int32_t ret = GetHapTokenInfo(id, info);
    if (ret != 0) {
        LOGE(ATM_DOMAIN, ATM_TAG, "Failed to GetHapTokenInfo, ret is %{public}d.", ret);
        return id;
    }
    AccessTokenIDEx idEx;
    idEx.tokenIdExStruct.tokenID = id;
    idEx.tokenIdExStruct.tokenAttr = info.tokenAttr;
    return idEx.tokenIDEx;
}

FullTokenID AccessTokenInfoManager::AllocLocalTokenID(const std::string& remoteDeviceID,
    AccessTokenID remoteTokenID)
{
    if (!DataValidator::IsDeviceIdValid(remoteDeviceID)) {
        LOGE(ATM_DOMAIN, ATM_TAG, "Device %{public}s parms invalid.",
            ConstantCommon::EncryptDevId(remoteDeviceID).c_str());
        (void)HiSysEventWrite(HiviewDFX::HiSysEvent::Domain::ACCESS_TOKEN, "PERMISSION_SYNC",
            HiviewDFX::HiSysEvent::EventType::FAULT, "CODE", TOKEN_SYNC_CALL_ERROR,
            "REMOTE_ID", ConstantCommon::EncryptDevId(remoteDeviceID), "ERROR_REASON", "deviceID error");
        return 0;
    }
    uint64_t fullTokenId = IPCSkeleton::GetCallingFullTokenID();
    int result = SetFirstCallerTokenID(fullTokenId); // for debug
    LOGI(ATM_DOMAIN, ATM_TAG, "Set first caller %{public}" PRIu64 "., ret is %{public}d", fullTokenId, result);

    std::string remoteUdid;
    DistributedHardware::DeviceManager::GetInstance().GetUdidByNetworkId(ACCESS_TOKEN_PACKAGE_NAME, remoteDeviceID,
        remoteUdid);
    LOGI(ATM_DOMAIN, ATM_TAG, "Device %{public}s remoteUdid.", ConstantCommon::EncryptDevId(remoteUdid).c_str());
    AccessTokenID mapID = AccessTokenRemoteTokenManager::GetInstance().GetDeviceMappingTokenID(remoteUdid,
        remoteTokenID);
    if (mapID != 0) {
        return GetFullRemoteTokenId(mapID);
    }
    int ret = TokenModifyNotifier::GetInstance().GetRemoteHapTokenInfo(remoteUdid, remoteTokenID);
    if (ret != RET_SUCCESS) {
        LOGE(ATM_DOMAIN, ATM_TAG, "Device %{public}s token %{public}u sync failed",
            ConstantCommon::EncryptDevId(remoteUdid).c_str(), remoteTokenID);
        std::string errorReason = "token sync call error, error number is " + std::to_string(ret);
        (void)HiSysEventWrite(HiviewDFX::HiSysEvent::Domain::ACCESS_TOKEN, "PERMISSION_SYNC",
            HiviewDFX::HiSysEvent::EventType::FAULT, "CODE", TOKEN_SYNC_CALL_ERROR,
            "REMOTE_ID", ConstantCommon::EncryptDevId(remoteDeviceID), "ERROR_REASON", errorReason);
        return 0;
    }

    mapID = AccessTokenRemoteTokenManager::GetInstance().GetDeviceMappingTokenID(remoteUdid, remoteTokenID);
    return GetFullRemoteTokenId(mapID);
}
#else
uint64_t AccessTokenInfoManager::AllocLocalTokenID(const std::string& remoteDeviceID,
    AccessTokenID remoteTokenID)
{
    LOGE(ATM_DOMAIN, ATM_TAG, "Tokensync is disable, check dependent components");
    return 0;
}
#endif

AccessTokenInfoManager& AccessTokenInfoManager::GetInstance()
{
    static AccessTokenInfoManager* instance = nullptr;
    if (instance == nullptr) {
        std::lock_guard<std::recursive_mutex> lock(g_instanceMutex);
        if (instance == nullptr) {
            AccessTokenInfoManager* tmp = new (std::nothrow) AccessTokenInfoManager();
            instance = std::move(tmp);
        }
    }
    return *instance;
}

static void GeneratePermExtendValues(AccessTokenID tokenID, const std::vector<PermissionWithValue> kernelPermList,
    std::vector<GenericValues>& permExtendValues)
{
    for (auto& extendValue : kernelPermList) {
        GenericValues genericValues;
        genericValues.Put(TokenFiledConst::FIELD_TOKEN_ID, static_cast<int32_t>(tokenID));
        genericValues.Put(TokenFiledConst::FIELD_PERMISSION_NAME, extendValue.permissionName);
        genericValues.Put(TokenFiledConst::FIELD_VALUE, extendValue.value);
        permExtendValues.emplace_back(genericValues);
    }
}

static void GetUserGrantPermFromDef(const std::vector<PermissionDef>& permList, AccessTokenID tokenID,
    std::vector<GenericValues>& permDefValues)
{
    for (const auto& def : permList) {
        GenericValues value;
        value.Put(TokenFiledConst::FIELD_TOKEN_ID, static_cast<int32_t>(tokenID));
        DataTranslator::TranslationIntoGenericValues(def, value);
        permDefValues.emplace_back(value);
    }
}

void AccessTokenInfoManager::GenerateAddInfoToVec(AtmDataType type, const std::vector<GenericValues>& addValues,
    std::vector<AddInfo>& addInfoVec)
{
    AddInfo addInfo;
    addInfo.addType = type;
    addInfo.addValues = addValues;
    addInfoVec.emplace_back(addInfo);
}

void AccessTokenInfoManager::GenerateDelInfoToVec(AtmDataType type, const GenericValues& delValue,
    std::vector<DelInfo>& delInfoVec)
{
    DelInfo delInfo;
    delInfo.delType = type;
    delInfo.delValue = delValue;
    delInfoVec.emplace_back(delInfo);
}

int AccessTokenInfoManager::AddHapTokenInfoToDb(const std::shared_ptr<HapTokenInfoInner>& hapInfo,
    const std::string& appId, const HapPolicy& policy, bool isUpdate, const std::vector<GenericValues>& undefValues)
{
    if (hapInfo == nullptr) {
        LOGC(ATM_DOMAIN, ATM_TAG, "Token info is null!");
        return AccessTokenError::ERR_TOKENID_NOT_EXIST;
    }
    if (hapInfo->IsRemote()) {
        LOGC(ATM_DOMAIN, ATM_TAG, "It is a remote hap!");
        return AccessTokenError::ERR_TOKENID_NOT_EXIST;
    }
    AccessTokenID tokenID = hapInfo->GetTokenID();
    bool isSystemRes = IsSystemResource(hapInfo->GetBundleName());

    std::vector<AddInfo> addInfoVec;
    GenerateAddInfoToVec(AtmDataType::ACCESSTOKEN_HAP_UNDEFINE_INFO, undefValues, addInfoVec);

    std::vector<GenericValues> hapInfoValues; // get new hap token info from cache
    hapInfo->StoreHapInfo(hapInfoValues, appId, policy.apl);
    GenerateAddInfoToVec(AtmDataType::ACCESSTOKEN_HAP_INFO, hapInfoValues, addInfoVec);

    std::vector<GenericValues> permStateValues; // get new permission status from cache if exist
    hapInfo->StorePermissionPolicy(permStateValues);
    GenerateAddInfoToVec(AtmDataType::ACCESSTOKEN_PERMISSION_STATE, permStateValues, addInfoVec);

    std::vector<PermissionWithValue> extendedPermList;
    PermissionDataBrief::GetInstance().GetExtendedValueList(tokenID, extendedPermList);
    std::vector<GenericValues> permExtendValues; // get new extend permission value
    GeneratePermExtendValues(tokenID, extendedPermList, permExtendValues);
    GenerateAddInfoToVec(AtmDataType::ACCESSTOKEN_PERMISSION_EXTEND_VALUE, permExtendValues, addInfoVec);

    if (isSystemRes) {
        std::vector<GenericValues> permDefValues;
        GetUserGrantPermFromDef(policy.permList, tokenID, permDefValues);
        GenerateAddInfoToVec(AtmDataType::ACCESSTOKEN_PERMISSION_DEF, permDefValues, addInfoVec);
    }

    std::vector<DelInfo> delInfoVec;
    GenericValues delValue;
    delValue.Put(TokenFiledConst::FIELD_TOKEN_ID, static_cast<int32_t>(tokenID));
    if (isUpdate) { // udapte: delete and add; otherwise add only
        for (auto const& addInfo : addInfoVec) {
            GenerateDelInfoToVec(addInfo.addType, delValue, delInfoVec);
        }
    }

    return AccessTokenDbOperator::DeleteAndInsertValues(delInfoVec, addInfoVec);
}

int AccessTokenInfoManager::RemoveHapTokenInfoFromDb(const std::shared_ptr<HapTokenInfoInner>& info)
{
    AccessTokenID tokenID = info->GetTokenID();
    GenericValues condition;
    condition.Put(TokenFiledConst::FIELD_TOKEN_ID, static_cast<int32_t>(tokenID));

    std::vector<DelInfo> delInfoVec;
    GenerateDelInfoToVec(AtmDataType::ACCESSTOKEN_HAP_INFO, condition, delInfoVec);
    GenerateDelInfoToVec(AtmDataType::ACCESSTOKEN_PERMISSION_STATE, condition, delInfoVec);
    GenerateDelInfoToVec(AtmDataType::ACCESSTOKEN_PERMISSION_EXTEND_VALUE, condition, delInfoVec);
    GenerateDelInfoToVec(AtmDataType::ACCESSTOKEN_HAP_UNDEFINE_INFO, condition, delInfoVec);

    if (IsSystemResource(info->GetBundleName())) {
        GenerateDelInfoToVec(AtmDataType::ACCESSTOKEN_PERMISSION_DEF, condition, delInfoVec);
    }

    std::vector<AddInfo> addInfoVec;
    int32_t ret = AccessTokenDbOperator::DeleteAndInsertValues(delInfoVec, addInfoVec);
    if (ret != RET_SUCCESS) {
        LOGC(ATM_DOMAIN, ATM_TAG, "Id %{public}d DeleteAndInsertHap failed, ret %{public}d.", tokenID, ret);
        return ret;
    }
    return RET_SUCCESS;
}

int32_t AccessTokenInfoManager::GetHapAppIdByTokenId(AccessTokenID tokenID, std::string& appId)
{
    GenericValues conditionValue;
    conditionValue.Put(TokenFiledConst::FIELD_TOKEN_ID, static_cast<int32_t>(tokenID));
    std::vector<GenericValues> hapTokenResults;
    int32_t ret = AccessTokenDbOperator::Find(AtmDataType::ACCESSTOKEN_HAP_INFO, conditionValue, hapTokenResults);
    if (ret != RET_SUCCESS) {
        LOGE(ATM_DOMAIN, ATM_TAG,
            "Failed to find Id(%{public}u) from hap_token_table, err: %{public}d.", tokenID, ret);
        return ret;
    }

    if (hapTokenResults.empty()) {
        LOGE(ATM_DOMAIN, ATM_TAG, "Id(%{public}u) is not in hap_token_table.", tokenID);
        return AccessTokenError::ERR_TOKENID_NOT_EXIST;
    }
    std::string result = hapTokenResults[0].GetString(TokenFiledConst::FIELD_APP_ID);
    if (!DataValidator::IsAppIDDescValid(result)) {
        LOGE(ATM_DOMAIN, ATM_TAG, "TokenID: 0x%{public}x appID is error.", tokenID);
        return AccessTokenError::ERR_PARAM_INVALID;
    }
    appId = result;
    return RET_SUCCESS;
}

AccessTokenID AccessTokenInfoManager::GetNativeTokenId(const std::string& processName)
{
    AccessTokenID tokenID = INVALID_TOKENID;
    std::shared_lock<std::shared_mutex> infoGuard(this->nativeTokenInfoLock_);
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
            dumpInfo = infoPtr->ToString();
        }
    } else if (type == TOKEN_NATIVE || type == TOKEN_SHELL) {
        dumpInfo = NativeTokenToString(tokenId);
    } else {
        dumpInfo.append("invalid tokenId");
    }
}

void AccessTokenInfoManager::DumpHapTokenInfoByBundleName(const std::string& bundleName, std::string& dumpInfo)
{
    std::shared_lock<std::shared_mutex> hapInfoGuard(this->hapTokenInfoLock_);
    for (auto iter = hapTokenInfoMap_.begin(); iter != hapTokenInfoMap_.end(); iter++) {
        if (iter->second != nullptr) {
            if (bundleName != iter->second->GetBundleName()) {
                continue;
            }
            dumpInfo = iter->second->ToString();
            dumpInfo.append("\n");
        }
    }
}

void AccessTokenInfoManager::DumpAllHapTokenname(std::string& dumpInfo)
{
    LOGD(ATM_DOMAIN, ATM_TAG, "Get all hap token name.");

    std::shared_lock<std::shared_mutex> hapInfoGuard(this->hapTokenInfoLock_);
    for (auto iter = hapTokenInfoMap_.begin(); iter != hapTokenInfoMap_.end(); iter++) {
        if (iter->second != nullptr) {
            dumpInfo += std::to_string(iter->second->GetTokenID()) + ": " + iter->second->GetBundleName();
            dumpInfo.append("\n");
        }
    }
}

void AccessTokenInfoManager::DumpNativeTokenInfoByProcessName(const std::string& processName, std::string& dumpInfo)
{
    dumpInfo = NativeTokenToString(GetNativeTokenId(processName));
}

void AccessTokenInfoManager::DumpAllNativeTokenName(std::string& dumpInfo)
{
    LOGD(ATM_DOMAIN, ATM_TAG, "Get all native token name.");

    std::shared_lock<std::shared_mutex> infoGuard(this->nativeTokenInfoLock_);
    for (auto iter = nativeTokenInfoMap_.begin(); iter != nativeTokenInfoMap_.end(); iter++) {
        dumpInfo += std::to_string(iter->first) + ": " + iter->second.processName;
        dumpInfo.append("\n");
    }
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
    (void)HiSysEventWrite(HiviewDFX::HiSysEvent::Domain::ACCESS_TOKEN, "CLEAR_USER_PERMISSION_STATE",
        HiviewDFX::HiSysEvent::EventType::BEHAVIOR, "TOKENID", tokenID,
        "TOKENID_LEN", static_cast<uint32_t>(tokenIdList.size()));
}

int32_t AccessTokenInfoManager::ClearUserGrantedPermission(AccessTokenID id)
{
    std::shared_ptr<HapTokenInfoInner> infoPtr = AccessTokenInfoManager::GetInstance().GetHapTokenInfoInner(id);
    if (infoPtr == nullptr) {
        LOGE(ATM_DOMAIN, ATM_TAG, "Token %{public}u is invalid.", id);
        return ERR_PARAM_INVALID;
    }
    if (infoPtr->IsRemote()) {
        LOGE(ATM_DOMAIN, ATM_TAG, "It is a remote hap token %{public}u!", id);
        return ERR_IDENTITY_CHECK_FAILED;
    }
    std::vector<std::string> grantedPermListBefore;
    std::vector<uint32_t> emptyList;
    HapTokenInfoInner::GetGrantedPermByTokenId(id, emptyList, grantedPermListBefore);

    // reset permission.
    int32_t ret = infoPtr->ResetUserGrantPermissionStatus();
    if (ret != RET_SUCCESS) {
        return ret;
    }

    std::vector<std::string> grantedPermListAfter;
    HapTokenInfoInner::GetGrantedPermByTokenId(id, emptyList, grantedPermListAfter);
    PermissionManager::GetInstance().AddHapPermToKernel(id, GetRestrictedPermListByUserId(infoPtr->GetUserID()));
    LOGI(ATM_DOMAIN, ATM_TAG,
        "grantedPermListBefore size %{public}zu, grantedPermListAfter size %{public}zu!",
        grantedPermListBefore.size(), grantedPermListAfter.size());
    PermissionManager::GetInstance().NotifyUpdatedPermList(grantedPermListBefore, grantedPermListAfter, id);
    return RET_SUCCESS;
}

bool AccessTokenInfoManager::IsPermissionRestrictedByUserPolicy(AccessTokenID id, const std::string& permissionName)
{
#ifdef SUPPORT_MANAGE_USER_POLICY
    std::shared_ptr<HapTokenInfoInner> infoPtr = AccessTokenInfoManager::GetInstance().GetHapTokenInfoInner(id);
    if (infoPtr == nullptr) {
        LOGE(ATM_DOMAIN, ATM_TAG, "Token %{public}u is invalid.", id);
        return true;
    }
    uint32_t permCode;
    if (!TransferPermissionToOpcode(permissionName, permCode)) {
        LOGE(ATM_DOMAIN, ATM_TAG, "permissionName %{public}s is invalid.", permissionName.c_str());
        return true;
    }
    std::shared_lock<std::shared_mutex> infoGuard(this->userPolicyLock_);
    auto iter = userPermPolicyList_.find(permCode);
    if (iter != userPermPolicyList_.end() &&
        std::find(iter->second.begin(), iter->second.end(), infoPtr->GetUserID()) != iter->second.end()) {
        LOGW(ATM_DOMAIN, ATM_TAG, "Perm %{public}s of %{public}u is restricted.", permissionName.c_str(), id);
        return true;
    }
    return false;
#else
    return false;
#endif
}

std::vector<uint32_t> AccessTokenInfoManager::GetRestrictedPermListByUserId(int32_t userId)
{
#ifdef SUPPORT_MANAGE_USER_POLICY
    std::vector<uint32_t> permList;
    std::shared_lock<std::shared_mutex> infoGuard(this->userPolicyLock_);
    for (auto iter = userPermPolicyList_.begin(); iter != userPermPolicyList_.end(); ++iter) {
        std::vector<int32_t> userList = iter->second;
        if (std::find(userList.begin(), userList.end(), userId) != userList.end()) {
            permList.emplace_back(iter->first);
        }
    }
    return permList;
#else
    return {};
#endif
}

void AccessTokenInfoManager::GetRelatedSandBoxHapList(AccessTokenID tokenId, std::vector<AccessTokenID>& tokenIdList)
{
    std::shared_lock<std::shared_mutex> infoGuard(this->hapTokenInfoLock_);

    auto infoIter = hapTokenInfoMap_.find(tokenId);
    if (infoIter == hapTokenInfoMap_.end()) {
        return;
    }
    if (infoIter->second == nullptr) {
        LOGE(ATM_DOMAIN, ATM_TAG, "HapTokenInfoInner is nullptr.");
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
    std::unique_lock<std::shared_mutex> infoGuard(this->hapTokenInfoLock_);
    auto infoIter = hapTokenInfoMap_.find(tokenID);
    if ((infoIter == hapTokenInfoMap_.end()) || (infoIter->second == nullptr)) {
        LOGE(ATM_DOMAIN, ATM_TAG, "Id %{publid}u is not exits.", tokenID);
        return ERR_TOKENID_NOT_EXIST;
    }
    infoIter->second->SetPermDialogForbidden(enable);

    if (!UpdateCapStateToDatabase(tokenID, enable)) {
        return RET_FAILED;
    }

    return RET_SUCCESS;
}

#ifdef SUPPORT_MANAGE_USER_POLICY
void AccessTokenInfoManager::GetHapTokenInfoListByUserId(
    const std::map<int32_t, bool>& changedUserList, std::map<AccessTokenID, bool>& tokenIdList)
{
    std::shared_lock<std::shared_mutex> infoGuard(this->hapTokenInfoLock_);
    for (auto iter = hapTokenInfoMap_.begin(); iter != hapTokenInfoMap_.end(); ++iter) {
        std::shared_ptr<HapTokenInfoInner> infoPtr = iter->second;
        AccessTokenID tokenId = iter->first;
        if (infoPtr == nullptr) {
            LOGE(ATM_DOMAIN, ATM_TAG, "TokenId infoPtr is null.");
            continue;
        }
        int32_t userId = infoPtr->GetUserID();
        auto it = changedUserList.find(userId);
        if (it == changedUserList.end()) {
            continue;
        }
        tokenIdList[tokenId] = !it->second;
    }
}

void AccessTokenInfoManager::UpdatePermissionStateToKernel(
    uint32_t permCode, const std::map<int32_t, bool>& changedUserList)
{
    if (changedUserList.empty()) {
        LOGI(ATM_DOMAIN, ATM_TAG, "Empty changedUserList.");
        return;
    }

    std::map<AccessTokenID, bool> tokenIdList; // value: isGranted
    GetHapTokenInfoListByUserId(changedUserList, tokenIdList);
    for (auto iter = tokenIdList.begin(); iter != tokenIdList.end(); ++iter) {
        AccessTokenID tokenId = iter->first;
        bool isActive = iter->second;
        std::map<std::string, bool> refreshedPermList;
        HapTokenInfoInner::RefreshPermStateToKernel(tokenId, permCode, isActive, refreshedPermList);

        if (refreshedPermList.size() != 0) {
            PermissionManager::GetInstance().ParamUpdate(std::string(), 0, true);
        }
        for (auto perm = refreshedPermList.begin(); perm != refreshedPermList.end(); ++perm) {
            LOGI(ATM_DOMAIN, ATM_TAG, "Perm %{public}s refreshed by user policy, isActive %{public}d.",
                perm->first.c_str(), perm->second);
            PermStateChangeType change = perm->second ?
                PermStateChangeType::STATE_CHANGE_GRANTED : PermStateChangeType::STATE_CHANGE_REVOKED;
            CallbackManager::GetInstance().ExecuteCallbackAsync(tokenId, perm->first, change);
        }
    }
    return;
}

int32_t AccessTokenInfoManager::SetUserPolicy(const std::vector<UserPermissionPolicy>& userPermissionList)
{
    AccessTokenID callerToken = IPCSkeleton::GetCallingTokenID();
    std::vector<UserPolicyInner> userPolist;
    std::unique_lock<std::shared_mutex> infoGuard(this->userPolicyLock_);
    for (const auto& policy : userPermissionList) {
        PermissionBriefDef briefDef;
        uint32_t code;
        if (!GetPermissionBriefDef(policy.permissionName, briefDef, code) || (briefDef.grantMode != SYSTEM_GRANT)) {
            LOGE(ATM_DOMAIN, ATM_TAG, "Permission(%{public}s) is invalid.", policy.permissionName.c_str());
            return AccessTokenError::ERR_PARAM_INVALID;
        }
        size_t len = policy.userPolicyList.size();
        if ((len == 0) || (len > MAX_USER_POLICY_SIZE)) {
            LOGE(ATM_DOMAIN, ATM_TAG, "Size(%{public}zu) is invalid(%{public}s).", len, policy.permissionName.c_str());
            return AccessTokenError::ERR_PARAM_INVALID;
        }
        if (policyController_.find(code) != policyController_.end() && policyController_[code] != callerToken) {
            LOGE(ATM_DOMAIN, ATM_TAG, "Perm(%{public}s) is already set by %{public}u, currCaller(%{public}u).",
                policy.permissionName.c_str(), policyController_[code], callerToken);
            return AccessTokenError::ERR_PERM_POLICY_ALREADY_SET_BY_OTHER;
        }
        UserPolicyInner policyInner = { .permCode = code };
        if (userPermPolicyList_.find(code) != userPermPolicyList_.end()) {
            policyInner.userList.assign(userPermPolicyList_[code].begin(), userPermPolicyList_[code].end());
        }
        for (size_t i = 0; i < len; ++i) {
            int32_t userId = policy.userPolicyList[i].userId;
            bool isRestricted = policy.userPolicyList[i].isRestricted;
            if (userId < 0) {
                LOGE(ATM_DOMAIN, ATM_TAG, "Invalid userId %{public}d.", userId);
                return AccessTokenError::ERR_PARAM_INVALID;
            }
            auto iter = std::find(policyInner.userList.begin(), policyInner.userList.end(), userId);
            if ((iter != policyInner.userList.end() && !isRestricted)) {
                policyInner.userList.erase(iter);
                policyInner.changedUserList[userId] = isRestricted;
            } else if ((iter == policyInner.userList.end() && isRestricted)) {
                policyInner.userList.emplace_back(userId);
                policyInner.changedUserList[userId] = isRestricted;
            }
        }
        userPolist.emplace_back(policyInner);
    }
    for (const auto& policy : userPolist) {
        userPermPolicyList_[policy.permCode].assign(policy.userList.begin(), policy.userList.end());
        policyController_[policy.permCode] = callerToken;
        UpdatePermissionStateToKernel(policy.permCode, policy.changedUserList);
    }
    return RET_SUCCESS;
}

int32_t AccessTokenInfoManager::ClearUserPolicy(const std::vector<std::string>& permissionList)
{
    AccessTokenID callerToken = IPCSkeleton::GetCallingTokenID();
    std::unique_lock<std::shared_mutex> infoGuard(this->userPolicyLock_);
    std::vector<uint32_t> permCodeList;
    for (const auto& permission : permissionList) {
        uint32_t permCode;
        if (!TransferPermissionToOpcode(permission, permCode)) {
            LOGE(ATM_DOMAIN, ATM_TAG, "Permission(%{public}s) is invalid.", permission.c_str());
            return AccessTokenError::ERR_PARAM_INVALID;
        }
        if (policyController_.find(permCode) != policyController_.end() &&
            policyController_[permCode] != callerToken) {
            LOGE(ATM_DOMAIN, ATM_TAG, "Permission(%{public}s) is already set by %{public}u, currCaller(%{public}u).",
                permission.c_str(), policyController_[permCode], callerToken);
            return AccessTokenError::ERR_PERM_POLICY_ALREADY_SET_BY_OTHER;
        }
        if (userPermPolicyList_.find(permCode) == userPermPolicyList_.end()) {
            return AccessTokenError::ERR_PERM_POLICY_NOT_SET;
        }
        permCodeList.emplace_back(permCode);
    }
    for (auto code : permCodeList) {
        std::map<int32_t, bool> changedUserList;
        std::vector<int32_t> userList = userPermPolicyList_[code];
        for (auto userId : userList) {
            changedUserList[userId] = false;
        }
        UpdatePermissionStateToKernel(code, changedUserList);
        userPermPolicyList_.erase(code);
        policyController_.erase(code);
    }
    return RET_SUCCESS;
}
#endif

bool AccessTokenInfoManager::GetPermDialogCap(AccessTokenID tokenID)
{
    if (tokenID == INVALID_TOKENID) {
        LOGE(ATM_DOMAIN, ATM_TAG, "Invalid tokenId.");
        return true;
    }
    std::shared_lock<std::shared_mutex> infoGuard(this->hapTokenInfoLock_);
    auto infoIter = hapTokenInfoMap_.find(tokenID);
    if ((infoIter == hapTokenInfoMap_.end()) || (infoIter->second == nullptr)) {
        LOGE(ATM_DOMAIN, ATM_TAG, "TokenId is not exist in map.");
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

    int32_t res = AccessTokenDbOperator::Modify(AtmDataType::ACCESSTOKEN_HAP_INFO, modifyValue, conditionValue);
    if (res != 0) {
        LOGE(ATM_DOMAIN, ATM_TAG,
            "Update tokenID %{public}u permissionDialogForbidden %{public}d to database failed", tokenID, enable);
        return false;
    }

    return true;
}

static bool IsCallerNormalApp(uint64_t fulltokenID)
{
    ATokenTypeEnum tokenType =
        TokenIDAttributes::GetTokenIdTypeEnum(static_cast<AccessTokenID>(fulltokenID & TOKEN_ID_LOWMASK));
    if (tokenType != TOKEN_HAP) {
        return false;
    }
    return !TokenIDAttributes::IsSystemApp(fulltokenID);
}

int AccessTokenInfoManager::VerifyNativeAccessToken(AccessTokenID tokenID, const std::string& permissionName)
{
    if (!IsDefinedPermission(permissionName)) {
        LOGE(ATM_DOMAIN, ATM_TAG, "No definition for permission: %{public}s!", permissionName.c_str());
        return PERMISSION_DENIED;
    }
    uint32_t code;
    if (!TransferPermissionToOpcode(permissionName, code)) {
        LOGE(ATM_DOMAIN, ATM_TAG, "Invalid perm(%{public}s)", permissionName.c_str());
        return PERMISSION_DENIED;
    }

    std::shared_lock<std::shared_mutex> infoGuard(this->nativeTokenInfoLock_);
    auto iter = nativeTokenInfoMap_.find(tokenID);
    if (iter == nativeTokenInfoMap_.end()) {
        LOGE(ATM_DOMAIN, ATM_TAG, "Id %{public}u is not exist.", tokenID);
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
        (void)HiSysEventWrite(HiviewDFX::HiSysEvent::Domain::ACCESS_TOKEN, "PERMISSION_CHECK",
            HiviewDFX::HiSysEvent::EventType::FAULT, "CODE", VERIFY_TOKEN_ID_ERROR, "CALLER_TOKENID",
            static_cast<AccessTokenID>(IPCSkeleton::GetCallingTokenID()), "PERMISSION_NAME", permissionName);
        LOGE(ATM_DOMAIN, ATM_TAG, "TokenID is invalid");
        return PERMISSION_DENIED;
    }

    if (!PermissionValidator::IsPermissionNameValid(permissionName)) {
        LOGE(ATM_DOMAIN, ATM_TAG, "%{public}s of %{public}u is invalid!", permissionName.c_str(), tokenID);
        return PERMISSION_DENIED;
    }
    uint64_t callerFullTokenID = IPCSkeleton::GetCallingFullTokenID();
    AccessTokenID callertokenID = static_cast<AccessTokenID>(callerFullTokenID & TOKEN_ID_LOWMASK);
    bool isCallerNormalApp = IsCallerNormalApp(callerFullTokenID);
    ATokenTypeEnum tokenType = AccessTokenIDManager::GetInstance().GetTokenIdType(tokenID);
    if (isCallerNormalApp && tokenID != callertokenID) {
        std::shared_lock<std::shared_mutex> monitorLock(this->monitorLock_);
        tokenMonitor_->ReportExceptionalAccessTokenUsage();
        if (tokenType == ATokenTypeEnum::TOKEN_INVALID) {
            // record
            std::shared_ptr<HapTokenInfoInner> hap = GetHapTokenInfoInner(callertokenID);
            if (hap == nullptr) {
                LOGE(ATM_DOMAIN, ATM_TAG, "TokenID(%{public}u) not exist!", callertokenID);
                return PERMISSION_DENIED;
            }
            tokenMonitor_->RecordExceptionalBehavior(hap->GetHapInfoBasic(), tokenID, permissionName);
            return PERMISSION_DENIED;
        }
        if (tokenMonitor_->IsInPunishingTime(callertokenID)) {
            LOGE(ATM_DOMAIN, ATM_TAG, "TokenID(%{public}u) is in punishing time!", callertokenID);
            return PERMISSION_DENIED;
        }
    }
    if ((tokenType == TOKEN_NATIVE) || (tokenType == TOKEN_SHELL)) {
        return VerifyNativeAccessToken(tokenID, permissionName);
    }
    if (tokenType == TOKEN_HAP) {
        return PermissionManager::GetInstance().VerifyHapAccessToken(tokenID, permissionName);
    }
    LOGE(ATM_DOMAIN, ATM_TAG, "TokenID: %{public}d, invalid tokenType!", tokenID);
    return PERMISSION_DENIED;
}

int32_t AccessTokenInfoManager::AddPermRequestToggleStatusToDb(
    int32_t userID, const std::string& permissionName, int32_t status)
{
    GenericValues condition;
    condition.Put(TokenFiledConst::FIELD_USER_ID, userID);
    condition.Put(TokenFiledConst::FIELD_PERMISSION_NAME, permissionName);

    std::vector<DelInfo> delInfoVec;
    GenerateDelInfoToVec(AtmDataType::ACCESSTOKEN_PERMISSION_REQUEST_TOGGLE_STATUS, condition, delInfoVec);

    std::vector<GenericValues> values;
    condition.Put(TokenFiledConst::FIELD_REQUEST_TOGGLE_STATUS, status);
    values.emplace_back(condition);

    std::vector<AddInfo> addInfoVec;
    GenerateAddInfoToVec(AtmDataType::ACCESSTOKEN_PERMISSION_REQUEST_TOGGLE_STATUS, values, addInfoVec);

    int32_t ret = AccessTokenDbOperator::DeleteAndInsertValues(delInfoVec, addInfoVec);
    if (ret != RET_SUCCESS) {
        LOGE(ATM_DOMAIN, ATM_TAG, "DeleteAndInsertHap failed, ret %{public}d.", ret);
        return ret;
    }
    return RET_SUCCESS;
}

int32_t AccessTokenInfoManager::SetPermissionRequestToggleStatus(const std::string& permissionName, uint32_t status,
    int32_t userID)
{
    if (userID == 0) {
        userID = IPCSkeleton::GetCallingUid() / BASE_USER_RANGE;
    }

    LOGI(ATM_DOMAIN, ATM_TAG, "UserID=%{public}u, permission=%{public}s, status=%{public}d", userID,
        permissionName.c_str(), status);
    if (!PermissionValidator::IsUserIdValid(userID) ||
        !PermissionValidator::IsPermissionNameValid(permissionName) ||
        !PermissionValidator::IsToggleStatusValid(status)) {
        LOGE(ATM_DOMAIN, ATM_TAG, "Invalid parameter(userId=%{public}d, perm=%{public}s, status=%{public}d).",
            userID, permissionName.c_str(), status);
        return AccessTokenError::ERR_PARAM_INVALID;
    }
    if (!IsDefinedPermission(permissionName)) {
        LOGE(ATM_DOMAIN, ATM_TAG, "Permission=%{public}s is not defined.", permissionName.c_str());
        return AccessTokenError::ERR_PERMISSION_NOT_EXIST;
    }
    if (!IsUserGrantPermission(permissionName)) {
        LOGE(ATM_DOMAIN, ATM_TAG, "Only support permissions of user_grant to set.");
        return AccessTokenError::ERR_PARAM_INVALID;
    }

    int32_t ret = AddPermRequestToggleStatusToDb(userID, permissionName, status);
    if (ret != RET_SUCCESS) {
        return ret;
    }

    (void)HiSysEventWrite(HiviewDFX::HiSysEvent::Domain::ACCESS_TOKEN, "PERM_DIALOG_STATUS_INFO",
        HiviewDFX::HiSysEvent::EventType::STATISTIC, "USERID", userID, "PERMISSION_NAME", permissionName,
        "TOGGLE_STATUS", status);

    return RET_SUCCESS;
}

int32_t AccessTokenInfoManager::FindPermRequestToggleStatusFromDb(int32_t userID, const std::string& permissionName)
{
    std::vector<GenericValues> result;
    GenericValues conditionValue;
    conditionValue.Put(TokenFiledConst::FIELD_USER_ID, userID);
    conditionValue.Put(TokenFiledConst::FIELD_PERMISSION_NAME, permissionName);

    (void)AccessTokenDbOperator::Find(AtmDataType::ACCESSTOKEN_PERMISSION_REQUEST_TOGGLE_STATUS, conditionValue,
        result);
    if (result.empty()) {
        // never set, return default status: CLOSED if APP_TRACKING_CONSENT
        return (permissionName == "ohos.permission.APP_TRACKING_CONSENT") ?
            PermissionRequestToggleStatus::CLOSED : PermissionRequestToggleStatus::OPEN;
    }
    return result[0].GetInt(TokenFiledConst::FIELD_REQUEST_TOGGLE_STATUS);
}

int32_t AccessTokenInfoManager::GetPermissionRequestToggleStatus(const std::string& permissionName, uint32_t& status,
    int32_t userID)
{
    if (userID == 0) {
        userID = IPCSkeleton::GetCallingUid() / BASE_USER_RANGE;
    }

    LOGI(ATM_DOMAIN, ATM_TAG, "UserID=%{public}u, permissionName=%{public}s", userID, permissionName.c_str());
    if (!PermissionValidator::IsUserIdValid(userID) ||
        !PermissionValidator::IsPermissionNameValid(permissionName)) {
        LOGE(ATM_DOMAIN, ATM_TAG, "Invalid parameter(userId=%{public}d, perm=%{public}s.",
            userID, permissionName.c_str());
        return AccessTokenError::ERR_PARAM_INVALID;
    }
    if (!IsDefinedPermission(permissionName)) {
        LOGE(ATM_DOMAIN, ATM_TAG, "Permission=%{public}s is not defined.", permissionName.c_str());
        return AccessTokenError::ERR_PERMISSION_NOT_EXIST;
    }
    if (!IsUserGrantPermission(permissionName)) {
        LOGE(ATM_DOMAIN, ATM_TAG, "Only support permissions of user_grant to get.");
        return AccessTokenError::ERR_PARAM_INVALID;
    }

    status = static_cast<uint32_t>(FindPermRequestToggleStatusFromDb(userID, permissionName));

    return 0;
}


int32_t AccessTokenInfoManager::GetKernelPermissions(
    AccessTokenID tokenId, std::vector<PermissionWithValue>& kernelPermList)
{
    return PermissionDataBrief::GetInstance().GetKernelPermissions(tokenId, kernelPermList);
}


int32_t AccessTokenInfoManager::GetReqPermissionByName(
    AccessTokenID tokenId, const std::string& permissionName, std::string& value)
{
    return PermissionDataBrief::GetInstance().GetReqPermissionByName(
        tokenId, permissionName, value, true);
}

std::string AccessTokenInfoManager::NativeTokenToString(AccessTokenID tokenID)
{
    std::vector<NativeTokenInfoBase> tokenInfos;
    LibraryLoader loader(CONFIG_PARSE_LIBPATH);
    ConfigPolicyLoaderInterface* policy = loader.GetObject<ConfigPolicyLoaderInterface>();
    if (policy == nullptr) {
        LOGE(ATM_DOMAIN, ATM_TAG, "Dlopen libaccesstoken_json_parse failed.");
        return "";
    }
    int32_t ret = policy->GetAllNativeTokenInfo(tokenInfos);
    if (ret != RET_SUCCESS || tokenInfos.empty()) {
        LOGE(ATM_DOMAIN, ATM_TAG, "Failed to load native from native json, err=%{public}d.", ret);
        return "";
    }
    auto iter = tokenInfos.begin();
    while (iter != tokenInfos.end()) {
        if (iter->tokenID == tokenID) {
            break;
        }
        ++iter;
    }
    if (iter == tokenInfos.end()) {
        LOGE(ATM_DOMAIN, ATM_TAG, "Id %{public}u is not exist.", tokenID);
        return "";
    }
    NativeTokenInfoBase native = *iter;
    return policy->DumpNativeTokenInfo(native);
}
} // namespace AccessToken
} // namespace Security
} // namespace OHOS
