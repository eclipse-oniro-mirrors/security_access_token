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

#include "hap_token_info_inner.h"

#include "accesstoken_dfx_define.h"
#include "accesstoken_id_manager.h"
#include "accesstoken_log.h"
#include "access_token_error.h"
#include "data_translator.h"
#include "data_validator.h"
#include "token_field_const.h"

namespace OHOS {
namespace Security {
namespace AccessToken {
namespace {
static constexpr OHOS::HiviewDFX::HiLogLabel LABEL = {LOG_CORE, SECURITY_DOMAIN_ACCESSTOKEN, "HapTokenInfoInner"};
static const std::string DEFAULT_DEVICEID = "0";
static const unsigned int SYSTEM_APP_FLAG = 0x0001;
}

HapTokenInfoInner::HapTokenInfoInner() :  permUpdateTimestamp_(0), isRemote_(false)
{
    tokenInfoBasic_.ver = DEFAULT_TOKEN_VERSION;
    tokenInfoBasic_.tokenID = 0;
    tokenInfoBasic_.tokenAttr = 0;
    tokenInfoBasic_.userID = 0;
    tokenInfoBasic_.apiVersion = 0;
    tokenInfoBasic_.instIndex = 0;
    tokenInfoBasic_.dlpType = 0;
    tokenInfoBasic_.apl = APL_NORMAL;
}

HapTokenInfoInner::HapTokenInfoInner(AccessTokenID id,
    const HapInfoParams &info, const HapPolicyParams &policy) : permUpdateTimestamp_(0), isRemote_(false)
{
    tokenInfoBasic_.tokenID = id;
    tokenInfoBasic_.userID = info.userID;
    tokenInfoBasic_.ver = DEFAULT_TOKEN_VERSION;
    tokenInfoBasic_.tokenAttr = 0;
    if (info.isSystemApp) {
        tokenInfoBasic_.tokenAttr |= SYSTEM_APP_FLAG;
    }
    tokenInfoBasic_.bundleName = info.bundleName;
    tokenInfoBasic_.apiVersion = GetApiVersion(info.apiVersion);
    tokenInfoBasic_.instIndex = info.instIndex;
    tokenInfoBasic_.dlpType = info.dlpType;
    tokenInfoBasic_.appID = info.appIDDesc;
    tokenInfoBasic_.deviceID = DEFAULT_DEVICEID;
    tokenInfoBasic_.apl = policy.apl;
    permPolicySet_ = PermissionPolicySet::BuildPermissionPolicySet(id, policy.permStateList);
}

HapTokenInfoInner::HapTokenInfoInner(AccessTokenID id,
    const HapTokenInfo &info, const std::vector<PermissionStateFull>& permStateList) : isRemote_(false)
{
    permUpdateTimestamp_ = 0;
    tokenInfoBasic_ = info;
    permPolicySet_ = PermissionPolicySet::BuildPermissionPolicySet(id, permStateList);
}

HapTokenInfoInner::HapTokenInfoInner(AccessTokenID id,
    const HapTokenInfoForSync& info) : isRemote_(true)
{
    permUpdateTimestamp_ = 0;
    tokenInfoBasic_ = info.baseInfo;
    permPolicySet_ = PermissionPolicySet::BuildPolicySetWithoutDefCheck(id, info.permStateList);
}

HapTokenInfoInner::~HapTokenInfoInner()
{
    ACCESSTOKEN_LOG_DEBUG(LABEL,
        "tokenID: 0x%{public}x destruction", tokenInfoBasic_.tokenID);
}

void HapTokenInfoInner::Update(const UpdateHapInfoParams& info,
    const std::vector<PermissionStateFull>& permStateList, ATokenAplEnum apl)
{
    tokenInfoBasic_.appID = info.appIDDesc;
    tokenInfoBasic_.apiVersion = GetApiVersion(info.apiVersion);
    tokenInfoBasic_.apl = apl;
    if (info.isSystemApp) {
        tokenInfoBasic_.tokenAttr |= SYSTEM_APP_FLAG;
    } else {
        tokenInfoBasic_.tokenAttr &= ~SYSTEM_APP_FLAG;
    }
    if (permPolicySet_ == nullptr) {
        permPolicySet_ = PermissionPolicySet::BuildPermissionPolicySet(tokenInfoBasic_.tokenID,
            permStateList);
        return;
    }

    permPolicySet_->Update(permStateList);
    return;
}

void HapTokenInfoInner::TranslateToHapTokenInfo(HapTokenInfo& infoParcel) const
{
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
    outGenericValues.Put(TokenFiledConst::FIELD_APP_ID, tokenInfoBasic_.appID);
    outGenericValues.Put(TokenFiledConst::FIELD_DEVICE_ID, tokenInfoBasic_.deviceID);
    outGenericValues.Put(TokenFiledConst::FIELD_APL, tokenInfoBasic_.apl);
    outGenericValues.Put(TokenFiledConst::FIELD_TOKEN_VERSION, tokenInfoBasic_.ver);
    outGenericValues.Put(TokenFiledConst::FIELD_TOKEN_ATTR, static_cast<int32_t>(tokenInfoBasic_.tokenAttr));
    outGenericValues.Put(TokenFiledConst::FIELD_FORBID_PERM_DIALOG, isPermDialogForbidden_);
}

int HapTokenInfoInner::RestoreHapTokenBasicInfo(const GenericValues& inGenericValues)
{
    tokenInfoBasic_.userID = inGenericValues.GetInt(TokenFiledConst::FIELD_USER_ID);
    tokenInfoBasic_.bundleName = inGenericValues.GetString(TokenFiledConst::FIELD_BUNDLE_NAME);
    if (!DataValidator::IsBundleNameValid(tokenInfoBasic_.bundleName)) {
        ACCESSTOKEN_LOG_ERROR(LABEL, "tokenID: 0x%{public}x bundle name is error", tokenInfoBasic_.tokenID);
        HiSysEventWrite(HiviewDFX::HiSysEvent::Domain::ACCESS_TOKEN, "PERMISSION_CHECK",
            HiviewDFX::HiSysEvent::EventType::FAULT, "CODE", LOAD_DATABASE_ERROR, "ERROR_REASON", "bundleName error");
        return AccessTokenError::ERR_PARAM_INVALID;
    }

    tokenInfoBasic_.apiVersion = GetApiVersion(inGenericValues.GetInt(TokenFiledConst::FIELD_API_VERSION));
    tokenInfoBasic_.instIndex = inGenericValues.GetInt(TokenFiledConst::FIELD_INST_INDEX);
    tokenInfoBasic_.dlpType = inGenericValues.GetInt(TokenFiledConst::FIELD_DLP_TYPE);
    tokenInfoBasic_.appID = inGenericValues.GetString(TokenFiledConst::FIELD_APP_ID);
    if (!DataValidator::IsAppIDDescValid(tokenInfoBasic_.appID)) {
        ACCESSTOKEN_LOG_ERROR(LABEL, "tokenID: 0x%{public}x appID is error", tokenInfoBasic_.tokenID);
        HiSysEventWrite(HiviewDFX::HiSysEvent::Domain::ACCESS_TOKEN, "PERMISSION_CHECK",
            HiviewDFX::HiSysEvent::EventType::FAULT, "CODE", LOAD_DATABASE_ERROR, "ERROR_REASON", "appID error");
        return AccessTokenError::ERR_PARAM_INVALID;
    }

    tokenInfoBasic_.deviceID = inGenericValues.GetString(TokenFiledConst::FIELD_DEVICE_ID);
    if (!DataValidator::IsDeviceIdValid(tokenInfoBasic_.deviceID)) {
        ACCESSTOKEN_LOG_ERROR(LABEL,
            "tokenID: 0x%{public}x devId is error", tokenInfoBasic_.tokenID);
        HiSysEventWrite(HiviewDFX::HiSysEvent::Domain::ACCESS_TOKEN, "PERMISSION_CHECK",
            HiviewDFX::HiSysEvent::EventType::FAULT, "CODE", LOAD_DATABASE_ERROR, "ERROR_REASON", "deviceID error");
        return AccessTokenError::ERR_PARAM_INVALID;
    }
    int aplNum = inGenericValues.GetInt(TokenFiledConst::FIELD_APL);
    if (DataValidator::IsAplNumValid(aplNum)) {
        tokenInfoBasic_.apl = static_cast<ATokenAplEnum>(aplNum);
    } else {
        ACCESSTOKEN_LOG_ERROR(LABEL, "tokenID: 0x%{public}x apl is error, value %{public}d",
            tokenInfoBasic_.tokenID, aplNum);
        HiSysEventWrite(HiviewDFX::HiSysEvent::Domain::ACCESS_TOKEN, "PERMISSION_CHECK",
            HiviewDFX::HiSysEvent::EventType::FAULT, "CODE", LOAD_DATABASE_ERROR, "ERROR_REASON", "apl error");
        return AccessTokenError::ERR_PARAM_INVALID;
    }
    tokenInfoBasic_.ver = (char)inGenericValues.GetInt(TokenFiledConst::FIELD_TOKEN_VERSION);
    if (tokenInfoBasic_.ver != DEFAULT_TOKEN_VERSION) {
        ACCESSTOKEN_LOG_ERROR(LABEL, "tokenID: 0x%{public}x version is error, version %{public}d",
            tokenInfoBasic_.tokenID, tokenInfoBasic_.ver);
        HiSysEventWrite(HiviewDFX::HiSysEvent::Domain::ACCESS_TOKEN, "PERMISSION_CHECK",
            HiviewDFX::HiSysEvent::EventType::FAULT, "CODE", LOAD_DATABASE_ERROR, "ERROR_REASON", "version error");
        return AccessTokenError::ERR_PARAM_INVALID;
    }
    tokenInfoBasic_.tokenAttr = (uint32_t)inGenericValues.GetInt(TokenFiledConst::FIELD_TOKEN_ATTR);
    isPermDialogForbidden_ = inGenericValues.GetInt(TokenFiledConst::FIELD_FORBID_PERM_DIALOG);
    return RET_SUCCESS;
}

int HapTokenInfoInner::RestoreHapTokenInfo(AccessTokenID tokenId,
    const GenericValues& tokenValue,
    const std::vector<GenericValues>& permStateRes)
{
    tokenInfoBasic_.tokenID = tokenId;
    int ret = RestoreHapTokenBasicInfo(tokenValue);
    if (ret != RET_SUCCESS) {
        return ret;
    }
    permPolicySet_ = PermissionPolicySet::RestorePermissionPolicy(tokenId, permStateRes);
    return RET_SUCCESS;
}

void HapTokenInfoInner::StoreHapInfo(std::vector<GenericValues>& valueList) const
{
    if (isRemote_) {
        ACCESSTOKEN_LOG_INFO(LABEL,
            "token %{public}x is remote hap token, will not store", tokenInfoBasic_.tokenID);
        return;
    }
    GenericValues genericValues;
    TranslationIntoGenericValues(genericValues);
    valueList.emplace_back(genericValues);
}

void HapTokenInfoInner::StorePermissionPolicy(std::vector<GenericValues>& permStateValues) const
{
    if (isRemote_) {
        ACCESSTOKEN_LOG_INFO(LABEL,
            "token %{public}x is remote hap token, will not store", tokenInfoBasic_.tokenID);
        return;
    }
    if (permPolicySet_ != nullptr) {
        permPolicySet_->StorePermissionPolicySet(permStateValues);
    }
}

std::shared_ptr<PermissionPolicySet> HapTokenInfoInner::GetHapInfoPermissionPolicySet() const
{
    return permPolicySet_;
}

int HapTokenInfoInner::GetUserID() const
{
    return tokenInfoBasic_.userID;
}

int HapTokenInfoInner::GetDlpType() const
{
    return tokenInfoBasic_.dlpType;
}

std::string HapTokenInfoInner::GetBundleName() const
{
    return tokenInfoBasic_.bundleName;
}

int HapTokenInfoInner::GetInstIndex() const
{
    return tokenInfoBasic_.instIndex;
}

AccessTokenID HapTokenInfoInner::GetTokenID() const
{
    return tokenInfoBasic_.tokenID;
}

HapTokenInfo HapTokenInfoInner::GetHapInfoBasic() const
{
    return tokenInfoBasic_;
}

void HapTokenInfoInner::SetTokenBaseInfo(const HapTokenInfo& baseInfo)
{
    tokenInfoBasic_ = baseInfo;
}

void HapTokenInfoInner::SetPermissionPolicySet(std::shared_ptr<PermissionPolicySet>& policySet)
{
    permPolicySet_ = policySet;
}

bool HapTokenInfoInner::IsRemote() const
{
    return isRemote_;
}

void HapTokenInfoInner::SetRemote(bool isRemote)
{
    isRemote_ = isRemote;
}

bool HapTokenInfoInner::IsPermDialogForbidden() const
{
    ACCESSTOKEN_LOG_INFO(LABEL, "%{public}d", isPermDialogForbidden_);
    return isPermDialogForbidden_;
}

void HapTokenInfoInner::SetPermDialogForbidden(bool isForbidden)
{
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
    return std::stoi(api);
}

void HapTokenInfoInner::ToString(std::string& info) const
{
    info.append(R"({)");
    info.append("\n");
    info.append(R"(  "tokenID": )" + std::to_string(tokenInfoBasic_.tokenID) + ",\n");
    info.append(R"(  "tokenAttr": )" + std::to_string(tokenInfoBasic_.tokenAttr) + ",\n");
    info.append(R"(  "ver": )" + std::to_string(tokenInfoBasic_.ver) + ",\n");
    info.append(R"(  "userId": )" + std::to_string(tokenInfoBasic_.userID) + ",\n");
    info.append(R"(  "bundleName": ")" + tokenInfoBasic_.bundleName + R"(")" + ",\n");
    info.append(R"(  "instIndex": )" + std::to_string(tokenInfoBasic_.instIndex) + ",\n");
    info.append(R"(  "dlpType": )" + std::to_string(tokenInfoBasic_.dlpType) + ",\n");
    info.append(R"(  "appID": ")" + tokenInfoBasic_.appID + R"(")" + ",\n");
#ifndef ATM_BUILD_VARIANT_USER_ENABLE
    info.append(R"(  "deviceID": ")" + tokenInfoBasic_.deviceID + R"(")" + ",\n");
#endif
    info.append(R"(  "apl": )" + std::to_string(tokenInfoBasic_.apl) + ",\n");
    info.append(R"(  "isRemote": )" + std::to_string(isRemote_) + ",\n");
    info.append(R"(  "isPermDialogForbidden": )" + std::to_string(isPermDialogForbidden_) + ",\n");

    if (permPolicySet_ != nullptr) {
        permPolicySet_->ToString(info);
    }
    info.append("}");
}
} // namespace AccessToken
} // namespace Security
} // namespace OHOS
