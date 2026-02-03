/*
 * Copyright (c) 2021-2026 Huawei Device Co., Ltd.
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

#include "hap_token_info_inner.h"

#include "accesstoken_dfx_define.h"
#include "accesstoken_id_manager.h"
#include "accesstoken_common_log.h"
#include "access_token_db_operator.h"
#include "access_token_error.h"
#include "data_translator.h"
#include "data_validator.h"
#include "hisysevent_adapter.h"
#include "json_parse_loader.h"
#include "short_grant_manager.h"
#include "token_field_const.h"
#include "permission_map.h"
#include "permission_data_brief.h"
#ifdef SUPPORT_SANDBOX_APP
#include "dlp_permission_set_manager.h"
#endif

namespace OHOS {
namespace Security {
namespace AccessToken {
namespace {
static const std::string DEFAULT_DEVICEID = "0";
static const unsigned int SYSTEM_APP_FLAG = 0x0001;
static const unsigned int ATOMIC_SERVICE_FLAG = 0x0002;
}

HapTokenInfoInner::HapTokenInfoInner() : permUpdateTimestamp_(0), isRemote_(false)
{
    std::unique_lock<std::shared_mutex> infoGuard(this->policySetLock_);
    tokenInfoBasic_.ver = DEFAULT_TOKEN_VERSION;
    tokenInfoBasic_.tokenID = 0;
    tokenInfoBasic_.tokenAttr = 0;
    tokenInfoBasic_.userID = 0;
    tokenInfoBasic_.apiVersion = 0;
    tokenInfoBasic_.instIndex = 0;
    tokenInfoBasic_.dlpType = 0;
}

HapTokenInfoInner::HapTokenInfoInner(AccessTokenID id,
    const HapInfoParams &info, const HapPolicy &policy) : permUpdateTimestamp_(0), isRemote_(false)
{
    {
        std::unique_lock<std::shared_mutex> infoGuard(this->policySetLock_);
        tokenInfoBasic_.tokenID = id;
        tokenInfoBasic_.userID = info.userID;
        tokenInfoBasic_.ver = DEFAULT_TOKEN_VERSION;
        tokenInfoBasic_.tokenAttr = 0;
        if (info.isSystemApp) {
            tokenInfoBasic_.tokenAttr |= SYSTEM_APP_FLAG;
        }
        if (info.isAtomicService) {
            tokenInfoBasic_.tokenAttr |= ATOMIC_SERVICE_FLAG;
        }
        tokenInfoBasic_.bundleName = info.bundleName;
        tokenInfoBasic_.apiVersion = GetApiVersion(info.apiVersion);
        tokenInfoBasic_.instIndex = info.instIndex;
        tokenInfoBasic_.dlpType = info.dlpType;
    }
    PermissionDataBrief::GetInstance().AddPermToBriefPermission(id, policy.permStateList, policy.aclExtendedMap, true);
}

HapTokenInfoInner::HapTokenInfoInner(AccessTokenID id,
    const HapTokenInfo &info, const std::vector<PermissionStatus>& permStateList) : isRemote_(false)
{
    {
        std::unique_lock<std::shared_mutex> infoGuard(this->policySetLock_);
        permUpdateTimestamp_ = 0;
        tokenInfoBasic_ = info;
    }
    PermissionDataBrief::GetInstance().AddPermToBriefPermission(id, permStateList, true);
}

HapTokenInfoInner::HapTokenInfoInner(AccessTokenID id,
    const HapTokenInfoForSync& info) : isRemote_(true)
{
    {
        std::unique_lock<std::shared_mutex> infoGuard(this->policySetLock_);
        permUpdateTimestamp_ = 0;
        tokenInfoBasic_ = info.baseInfo;
    }
    PermissionDataBrief::GetInstance().AddPermToBriefPermission(id, info.permStateList, false);
}

HapTokenInfoInner::~HapTokenInfoInner()
{
    std::shared_lock<std::shared_mutex> infoGuard(this->policySetLock_);
    LOGI(ATM_DOMAIN, ATM_TAG, "TokenID: %{public}d destruction", tokenInfoBasic_.tokenID);
    (void)PermissionDataBrief::GetInstance().DeleteBriefPermDataByTokenId(tokenInfoBasic_.tokenID);
}

void HapTokenInfoInner::Update(const UpdateHapInfoParams& info, const std::vector<PermissionStatus>& permStateList,
    const HapPolicy& hapPolicy)
{
    std::unique_lock<std::shared_mutex> infoGuard(this->policySetLock_);
    tokenInfoBasic_.apiVersion = GetApiVersion(info.apiVersion);
    if (info.isSystemApp) {
        tokenInfoBasic_.tokenAttr |= SYSTEM_APP_FLAG;
    } else {
        tokenInfoBasic_.tokenAttr &= ~SYSTEM_APP_FLAG;
    }
    if (info.isAtomicService) {
        tokenInfoBasic_.tokenAttr |= ATOMIC_SERVICE_FLAG;
    } else {
        tokenInfoBasic_.tokenAttr &= ~ATOMIC_SERVICE_FLAG;
    }
    PermissionDataBrief::GetInstance().Update(tokenInfoBasic_.tokenID, permStateList, hapPolicy.aclExtendedMap);
}

void HapTokenInfoInner::TranslateToHapTokenInfo(HapTokenInfo& infoParcel) const
{
    std::shared_lock<std::shared_mutex> infoGuard(this->policySetLock_);
    infoParcel = tokenInfoBasic_;
}

void HapTokenInfoInner::TranslationIntoGenericValues(GenericValues& outGenericValues) const
{
    outGenericValues.Put(TokenFiledConst::FIELD_TOKEN_ID, static_cast<int32_t>(tokenInfoBasic_.tokenID));
    outGenericValues.Put(TokenFiledConst::FIELD_USER_ID, tokenInfoBasic_.userID);
    outGenericValues.Put(TokenFiledConst::FIELD_BUNDLE_NAME, tokenInfoBasic_.bundleName);
    outGenericValues.Put(TokenFiledConst::FIELD_API_VERSION, tokenInfoBasic_.apiVersion);
    outGenericValues.Put(TokenFiledConst::FIELD_INST_INDEX, tokenInfoBasic_.instIndex);
    outGenericValues.Put(TokenFiledConst::FIELD_DLP_TYPE, tokenInfoBasic_.dlpType);
    outGenericValues.Put(TokenFiledConst::FIELD_TOKEN_VERSION, tokenInfoBasic_.ver);
    outGenericValues.Put(TokenFiledConst::FIELD_TOKEN_ATTR, static_cast<int32_t>(tokenInfoBasic_.tokenAttr));
    outGenericValues.Put(TokenFiledConst::FIELD_FORBID_PERM_DIALOG, isPermDialogForbidden_);
}

int HapTokenInfoInner::RestoreHapTokenBasicInfo(const GenericValues& inGenericValues)
{
    tokenInfoBasic_.userID = inGenericValues.GetInt(TokenFiledConst::FIELD_USER_ID);
    tokenInfoBasic_.bundleName = inGenericValues.GetString(TokenFiledConst::FIELD_BUNDLE_NAME);
    if (!DataValidator::IsBundleNameValid(tokenInfoBasic_.bundleName)) {
        LOGE(ATM_DOMAIN, ATM_TAG, "Invalid bundle of id: 0x%{public}x.", tokenInfoBasic_.tokenID);
        ReportPermissionCheckEvent(LOAD_DATABASE_ERROR, "bundleName error");
        return AccessTokenError::ERR_PARAM_INVALID;
    }

    tokenInfoBasic_.apiVersion = GetApiVersion(inGenericValues.GetInt(TokenFiledConst::FIELD_API_VERSION));
    tokenInfoBasic_.instIndex = inGenericValues.GetInt(TokenFiledConst::FIELD_INST_INDEX);
    tokenInfoBasic_.dlpType = inGenericValues.GetInt(TokenFiledConst::FIELD_DLP_TYPE);

    tokenInfoBasic_.ver = (char)inGenericValues.GetInt(TokenFiledConst::FIELD_TOKEN_VERSION);
    if (tokenInfoBasic_.ver != DEFAULT_TOKEN_VERSION) {
        LOGE(ATM_DOMAIN, ATM_TAG, "TokenID: 0x%{public}x version is error, version %{public}d",
            tokenInfoBasic_.tokenID, tokenInfoBasic_.ver);
        ReportPermissionCheckEvent(LOAD_DATABASE_ERROR, "Invalid ersion.");
        return AccessTokenError::ERR_PARAM_INVALID;
    }
    tokenInfoBasic_.tokenAttr = (uint32_t)inGenericValues.GetInt(TokenFiledConst::FIELD_TOKEN_ATTR);
    isPermDialogForbidden_ = inGenericValues.GetInt(TokenFiledConst::FIELD_FORBID_PERM_DIALOG);
    return RET_SUCCESS;
}

int HapTokenInfoInner::RestoreHapTokenInfo(AccessTokenID tokenId,
    const GenericValues& tokenValue,
    const std::vector<GenericValues>& permStateRes,
    const std::vector<GenericValues> extendedPermRes)
{
    {
        std::unique_lock<std::shared_mutex> infoGuard(this->policySetLock_);
        tokenInfoBasic_.tokenID = tokenId;
        int ret = RestoreHapTokenBasicInfo(tokenValue);
        if (ret != RET_SUCCESS) {
            return ret;
        }
    }

    PermissionDataBrief::GetInstance().RestorePermissionBriefData(tokenId, permStateRes, extendedPermRes);
    return RET_SUCCESS;
}

void HapTokenInfoInner::StoreHapInfo(std::vector<GenericValues>& valueList,
    const std::string& appId, ATokenAplEnum apl) const
{
    std::shared_lock<std::shared_mutex> infoGuard(this->policySetLock_);
    if (isRemote_) {
        LOGI(ATM_DOMAIN, ATM_TAG, "Token %{public}u is remote hap token, will not store", tokenInfoBasic_.tokenID);
        return;
    }
    GenericValues genericValues;
    TranslationIntoGenericValues(genericValues);
    genericValues.Put(TokenFiledConst::FIELD_APP_ID, appId);
    genericValues.Put(TokenFiledConst::FIELD_APL, static_cast<int32_t>(apl));
    genericValues.Put(TokenFiledConst::FIELD_DEVICE_ID, "0");
    valueList.emplace_back(genericValues);
}

void HapTokenInfoInner::StorePermissionPolicy(std::vector<GenericValues>& permStateValues)
{
    std::shared_lock<std::shared_mutex> infoGuard(this->policySetLock_);
    if (isRemote_) {
        LOGI(ATM_DOMAIN, ATM_TAG, "Token %{public}u is remote hap token, will not store.", tokenInfoBasic_.tokenID);
        return;
    }
    (void)PermissionDataBrief::GetInstance().StorePermissionBriefData(tokenInfoBasic_.tokenID, permStateValues);
}

uint32_t HapTokenInfoInner::GetReqPermissionSize()
{
    std::shared_lock<std::shared_mutex> infoGuard(this->policySetLock_);
    std::vector<BriefPermData> briefPermDataList;
    int32_t ret = PermissionDataBrief::GetInstance().GetBriefPermDataByTokenId(
        tokenInfoBasic_.tokenID, briefPermDataList);
    if (ret != RET_SUCCESS) {
        return 0;
    }
    return static_cast<uint32_t>(briefPermDataList.size());
}

int HapTokenInfoInner::GetUserID() const
{
    std::shared_lock<std::shared_mutex> infoGuard(this->policySetLock_);
    return tokenInfoBasic_.userID;
}

int HapTokenInfoInner::GetDlpType() const
{
    std::shared_lock<std::shared_mutex> infoGuard(this->policySetLock_);
    return tokenInfoBasic_.dlpType;
}

AccessTokenAttr HapTokenInfoInner::GetAttr() const
{
    std::shared_lock<std::shared_mutex> infoGuard(this->policySetLock_);
    return tokenInfoBasic_.tokenAttr;
}

std::string HapTokenInfoInner::GetBundleName() const
{
    std::shared_lock<std::shared_mutex> infoGuard(this->policySetLock_);
    return tokenInfoBasic_.bundleName;
}

int HapTokenInfoInner::GetInstIndex() const
{
    std::shared_lock<std::shared_mutex> infoGuard(this->policySetLock_);
    return tokenInfoBasic_.instIndex;
}

AccessTokenID HapTokenInfoInner::GetTokenID() const
{
    std::shared_lock<std::shared_mutex> infoGuard(this->policySetLock_);
    return tokenInfoBasic_.tokenID;
}

HapTokenInfo HapTokenInfoInner::GetHapInfoBasic() const
{
    std::shared_lock<std::shared_mutex> infoGuard(this->policySetLock_);
    return tokenInfoBasic_;
}

void HapTokenInfoInner::SetTokenBaseInfo(const HapTokenInfo& baseInfo)
{
    std::unique_lock<std::shared_mutex> infoGuard(this->policySetLock_);
    tokenInfoBasic_ = baseInfo;
}

bool HapTokenInfoInner::IsRemote() const
{
    std::shared_lock<std::shared_mutex> infoGuard(this->policySetLock_);
    return isRemote_;
}

void HapTokenInfoInner::SetRemote(bool isRemote)
{
    std::unique_lock<std::shared_mutex> infoGuard(this->policySetLock_);
    isRemote_ = isRemote;
}

bool HapTokenInfoInner::IsPermDialogForbidden() const
{
    std::shared_lock<std::shared_mutex> infoGuard(this->policySetLock_);
    LOGI(ATM_DOMAIN, ATM_TAG, "%{public}d", isPermDialogForbidden_);
    return isPermDialogForbidden_;
}

void HapTokenInfoInner::SetPermDialogForbidden(bool isForbidden)
{
    std::unique_lock<std::shared_mutex> infoGuard(this->policySetLock_);
    isPermDialogForbidden_ = isForbidden;
}

int32_t HapTokenInfoInner::GetApiVersion(int32_t apiVersion)
{
    uint32_t apiSize = 3; // 3: api version length
    std::string apiStr = std::to_string(apiVersion);
    uint32_t inputSize = apiStr.length();
    if (inputSize <= apiSize) {
        return apiVersion;
    }
    std::string api = apiStr.substr(inputSize - apiSize);
    return std::atoi(api.c_str());
}

void HapTokenInfoInner::UpdateRemoteHapTokenInfo(AccessTokenID mapID,
    const HapTokenInfo& baseInfo, std::vector<PermissionStatus>& permStateList)
{
    SetTokenBaseInfo(baseInfo);
    PermissionDataBrief::GetInstance().AddPermToBriefPermission(baseInfo.tokenID, permStateList, false);
}

int32_t HapTokenInfoInner::UpdatePermissionStatus(
    const std::string& permissionName, bool isGranted, uint32_t flag, bool& statusChanged)
{
    std::unique_lock<std::shared_mutex> infoGuard(this->policySetLock_);
    int32_t ret = PermissionDataBrief::GetInstance().UpdatePermissionStatus(tokenInfoBasic_.tokenID,
        permissionName, isGranted, flag, statusChanged);
    if (ret != RET_SUCCESS) {
        LOGC(ATM_DOMAIN, ATM_TAG, "Failed to update %{public}s of %{public}u, isGranted(%{public}d), ret(%{public}d).",
            permissionName.c_str(), tokenInfoBasic_.tokenID, isGranted, ret);
        return ret;
    }
    if (ShortGrantManager::GetInstance().IsShortGrantPermission(permissionName)) {
        LOGI(ATM_DOMAIN, ATM_TAG,
            "Short grant perm %{public}s should not be notified to db.", permissionName.c_str());
        return RET_SUCCESS;
    }
    if (isRemote_) {
        LOGI(ATM_DOMAIN, ATM_TAG, "Token %{public}u is remote hap token, will not store.", tokenInfoBasic_.tokenID);
        return RET_SUCCESS;
    }
    std::vector<GenericValues> permStateValues;
    ret = PermissionDataBrief::GetInstance().StorePermissionBriefData(tokenInfoBasic_.tokenID, permStateValues);
    if (ret != RET_SUCCESS) {
        return ret;
    }

    for (size_t i = 0; i < permStateValues.size(); i++) {
        if (permStateValues[i].GetString(TokenFiledConst::FIELD_PERMISSION_NAME) != permissionName) {
            continue;
        }
        GenericValues conditions;
        conditions.Put(TokenFiledConst::FIELD_TOKEN_ID, static_cast<int32_t>(tokenInfoBasic_.tokenID));
        conditions.Put(TokenFiledConst::FIELD_PERMISSION_NAME, permissionName);
        (void)AccessTokenDbOperator::Modify(AtmDataType::ACCESSTOKEN_PERMISSION_STATE, permStateValues[i], conditions);
    }
    return RET_SUCCESS;
}

int32_t HapTokenInfoInner::GetPermissionStateList(std::vector<PermissionStatus>& permList) const
{
    std::shared_lock<std::shared_mutex> infoGuard(this->policySetLock_);
    return GetPermissionStateListInner(permList);
}

int32_t HapTokenInfoInner::GetPermissionStateListInner(std::vector<PermissionStatus>& permList) const
{
    std::vector<BriefPermData> briefPermDataList;
    int32_t ret = PermissionDataBrief::GetInstance().GetBriefPermDataByTokenId(
        tokenInfoBasic_.tokenID, briefPermDataList);
    if (ret != RET_SUCCESS) {
        return ret;
    }
    for (const auto& perm : briefPermDataList) {
        PermissionStatus fullData;
        fullData.permissionName = TransferOpcodeToPermission(perm.permCode);
        fullData.grantStatus = static_cast<int32_t>(perm.status);
        fullData.grantFlag = perm.flag;
        permList.emplace_back(fullData);
    }
    return RET_SUCCESS;
}

bool HapTokenInfoInner::UpdateStatesToDB(AccessTokenID tokenID, std::vector<PermissionStatus>& stateChangeList)
{
    for (const auto& state : stateChangeList) {
        GenericValues modifyValue;
        modifyValue.Put(TokenFiledConst::FIELD_GRANT_STATE, state.grantStatus);
        modifyValue.Put(TokenFiledConst::FIELD_GRANT_FLAG, static_cast<int32_t>(state.grantFlag));

        GenericValues conditionValue;
        conditionValue.Put(TokenFiledConst::FIELD_TOKEN_ID, static_cast<int32_t>(tokenID));
        conditionValue.Put(TokenFiledConst::FIELD_PERMISSION_NAME, state.permissionName);
        int32_t res = AccessTokenDbOperator::Modify(AtmDataType::ACCESSTOKEN_PERMISSION_STATE, modifyValue,
            conditionValue);
        if (res != 0) {
            LOGE(ATM_DOMAIN, ATM_TAG,
                "Update tokenID %{public}u permission %{public}s to database failed, err %{public}d ",
                tokenID, state.permissionName.c_str(), res);
            return false;
        }
    }

    return true;
}

int32_t HapTokenInfoInner::ResetUserGrantPermissionStatus(void)
{
    std::unique_lock<std::shared_mutex> infoGuard(this->policySetLock_);

    int32_t ret = PermissionDataBrief::GetInstance().ResetUserGrantPermissionStatus(tokenInfoBasic_.tokenID);
    if (ret != RET_SUCCESS) {
        LOGE(ATM_DOMAIN, ATM_TAG, "Failed to reset user permission status.");
        return ret;
    }

    std::vector<PermissionStatus> permListOfHap;
    ret = GetPermissionStateListInner(permListOfHap);
    if (ret != RET_SUCCESS) {
        LOGE(ATM_DOMAIN, ATM_TAG, "Failed to get permission state list.");
        return ret;
    }

#ifdef SUPPORT_SANDBOX_APP
    // update permission status with dlp permission rule.
    DlpPermissionSetManager::GetInstance().UpdatePermStateWithDlpInfo(tokenInfoBasic_.dlpType, permListOfHap);
    std::vector<PermissionWithValue> extendedPermList;
    PermissionDataBrief::GetInstance().GetExtendedValueList(tokenInfoBasic_.tokenID, extendedPermList);
    std::map<std::string, std::string> aclExtendedMap;
    for (const auto& extendedperm : extendedPermList) {
        aclExtendedMap[extendedperm.permissionName] = extendedperm.value;
    }
    PermissionDataBrief::GetInstance().Update(tokenInfoBasic_.tokenID, permListOfHap, aclExtendedMap);
#endif
    if (!UpdateStatesToDB(tokenInfoBasic_.tokenID, permListOfHap)) {
        return ERR_DATABASE_OPERATE_FAILED;
    }
    return RET_SUCCESS;
}

void HapTokenInfoInner::RefreshPermStateToKernel(AccessTokenID tokenId, uint32_t permCode, bool hapUserIsActive,
    std::map<std::string, bool>& refreshedPermList)
{
    (void)PermissionDataBrief::GetInstance().RefreshPermStateToKernel(
        tokenId, permCode, hapUserIsActive, refreshedPermList);
}

int32_t HapTokenInfoInner::VerifyPermissionStatus(AccessTokenID tokenID, const std::string& permissionName)
{
    return PermissionDataBrief::GetInstance().VerifyPermissionStatus(tokenID, permissionName);
}

PermUsedTypeEnum HapTokenInfoInner::GetPermissionUsedType(AccessTokenID tokenID, const std::string& permissionName)
{
    uint32_t code;
    if (!TransferPermissionToOpcode(permissionName, code)) {
        LOGE(ATM_DOMAIN, ATM_TAG, "permissionName is invalid %{public}s.", permissionName.c_str());
        return PermUsedTypeEnum::INVALID_USED_TYPE;
    }
    return PermissionDataBrief::GetInstance().GetPermissionUsedType(tokenID, code);
}

int32_t HapTokenInfoInner::QueryPermissionFlag(AccessTokenID tokenID, const std::string& permissionName, uint32_t& flag)
{
    return PermissionDataBrief::GetInstance().QueryPermissionFlag(tokenID, permissionName, flag);
}

void HapTokenInfoInner::GetPermStatusListByTokenId(AccessTokenID tokenID,
    const std::vector<uint32_t> constrainedList, std::vector<uint32_t>& opCodeList, std::vector<bool>& statusList)
{
    return PermissionDataBrief::GetInstance().GetPermStatusListByTokenId(
        tokenID, constrainedList, opCodeList, statusList);
}

void HapTokenInfoInner::GetGrantedPermByTokenId(AccessTokenID tokenID,
    const std::vector<uint32_t>& constrainedList, std::vector<std::string>& permissionList)
{
    return PermissionDataBrief::GetInstance().GetGrantedPermByTokenId(tokenID, constrainedList, permissionList);
}

void HapTokenInfoInner::ClearAllSecCompGrantedPerm()
{
    PermissionDataBrief::GetInstance().ClearAllSecCompGrantedPerm();
}

bool HapTokenInfoInner::IsPermissionGrantedWithSecComp(AccessTokenID tokenID, const std::string& permissionName)
{
    return PermissionDataBrief::GetInstance().IsPermissionGrantedWithSecComp(tokenID, permissionName);
}

std::string HapTokenInfoInner::ToString() const
{
    std::vector<PermissionStatus> permStateList;
    std::vector<NativeTokenInfoBase> tokenInfos;
    LibraryLoader loader(CONFIG_PARSE_LIBPATH);
    ConfigPolicyLoaderInterface* policy = loader.GetObject<ConfigPolicyLoaderInterface>();
    if (policy == nullptr) {
        LOGE(ATM_DOMAIN, ATM_TAG, "Dlopen libaccesstoken_json_parse failed.");
        return "";
    }
    std::shared_lock<std::shared_mutex> infoGuard(this->policySetLock_);
    (void)GetPermissionStateListInner(permStateList);
    return policy->DumpHapTokenInfo(tokenInfoBasic_, isRemote_, isPermDialogForbidden_, permStateList);
}
} // namespace AccessToken
} // namespace Security
} // namespace OHOS
