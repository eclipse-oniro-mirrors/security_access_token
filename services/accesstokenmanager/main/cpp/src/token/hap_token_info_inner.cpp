/*
 * Copyright (c) 2021 Huawei Device Co., Ltd.
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

#include "accesstoken_id_manager.h"
#include "accesstoken_log.h"
#include "data_translator.h"
#include "data_validator.h"
#include "field_const.h"

namespace OHOS {
namespace Security {
namespace AccessToken {
namespace {
static constexpr OHOS::HiviewDFX::HiLogLabel LABEL = {LOG_CORE, SECURITY_DOMAIN_ACCESSTOKEN, "HapTokenInfoInner"};
}

HapTokenInfoInner::HapTokenInfoInner() : isRemote_(false)
{
    tokenInfoBasic_.ver = DEFAULT_TOKEN_VERSION;
    tokenInfoBasic_.tokenID = 0;
    tokenInfoBasic_.tokenAttr = 0;
    tokenInfoBasic_.userID = 0;
    tokenInfoBasic_.instIndex = 0;
    tokenInfoBasic_.apl = APL_NORMAL;
}

HapTokenInfoInner::HapTokenInfoInner(AccessTokenID id,
    const HapInfoParams &info, const HapPolicyParams &policy) : isRemote_(false)
{
    tokenInfoBasic_.tokenID = id;
    tokenInfoBasic_.userID = info.userID;
    tokenInfoBasic_.ver = DEFAULT_TOKEN_VERSION;
    tokenInfoBasic_.tokenAttr = 0;
    tokenInfoBasic_.bundleName = info.bundleName;
    tokenInfoBasic_.instIndex = info.instIndex;
    tokenInfoBasic_.appID = info.appIDDesc;
    tokenInfoBasic_.deviceID = "0";
    tokenInfoBasic_.apl = policy.apl;
    permPolicySet_ = PermissionPolicySet::BuildPermissionPolicySet(id, policy.permList, policy.permStateList);
}

HapTokenInfoInner::HapTokenInfoInner(AccessTokenID id,
    const HapTokenInfo &info, const std::vector<PermissionStateFull>& permStateList) : isRemote_(false)
{
    tokenInfoBasic_ = info;
    const std::vector<PermissionDef> permDefList;
    permPolicySet_ = PermissionPolicySet::BuildPermissionPolicySet(id, permDefList, permStateList);
}

HapTokenInfoInner::~HapTokenInfoInner()
{
    ACCESSTOKEN_LOG_DEBUG(LABEL,
        "tokenID: 0x%{public}x destruction", tokenInfoBasic_.tokenID);
}

void HapTokenInfoInner::Update(const std::string& appIDDesc, const HapPolicyParams& policy)
{
    tokenInfoBasic_.appID = appIDDesc;
    tokenInfoBasic_.apl = policy.apl;
    if (permPolicySet_ == nullptr) {
        permPolicySet_ = PermissionPolicySet::BuildPermissionPolicySet(tokenInfoBasic_.tokenID,
            policy.permList, policy.permStateList);
        return;
    }

    permPolicySet_->Update(policy.permList, policy.permStateList);
    return;
}

void HapTokenInfoInner::TranslateToHapTokenInfo(HapTokenInfo& InfoParcel) const
{
    InfoParcel = tokenInfoBasic_;
}

void HapTokenInfoInner::TranslationIntoGenericValues(GenericValues& outGenericValues) const
{
    outGenericValues.Put(FIELD_TOKEN_ID, tokenInfoBasic_.tokenID);
    outGenericValues.Put(FIELD_USER_ID, tokenInfoBasic_.userID);
    outGenericValues.Put(FIELD_BUNDLE_NAME, tokenInfoBasic_.bundleName);
    outGenericValues.Put(FIELD_INST_INDEX, tokenInfoBasic_.instIndex);
    outGenericValues.Put(FIELD_APP_ID, tokenInfoBasic_.appID);
    outGenericValues.Put(FIELD_DEVICE_ID, tokenInfoBasic_.deviceID);
    outGenericValues.Put(FIELD_APL, tokenInfoBasic_.apl);
    outGenericValues.Put(FIELD_TOKEN_VERSION, tokenInfoBasic_.ver);
    outGenericValues.Put(FIELD_TOKEN_ATTR, tokenInfoBasic_.tokenAttr);
}

int HapTokenInfoInner::RestoreHapTokenBasicInfo(const GenericValues& inGenericValues)
{
    tokenInfoBasic_.userID = inGenericValues.GetInt(FIELD_USER_ID);
    tokenInfoBasic_.bundleName = inGenericValues.GetString(FIELD_BUNDLE_NAME);
    if (!DataValidator::IsBundleNameValid(tokenInfoBasic_.bundleName)) {
        ACCESSTOKEN_LOG_ERROR(LABEL,
            "tokenID: 0x%{public}x bundle name is error", tokenInfoBasic_.tokenID);
        return RET_FAILED;
    }

    tokenInfoBasic_.instIndex = inGenericValues.GetInt(FIELD_INST_INDEX);
    tokenInfoBasic_.appID = inGenericValues.GetString(FIELD_APP_ID);
    if (!DataValidator::IsAppIDDescValid(tokenInfoBasic_.appID)) {
        ACCESSTOKEN_LOG_ERROR(LABEL,
            "tokenID: 0x%{public}x appID is error", tokenInfoBasic_.tokenID);
        return RET_FAILED;
    }

    tokenInfoBasic_.deviceID = inGenericValues.GetString(FIELD_DEVICE_ID);
    if (!DataValidator::IsDeviceIdValid(tokenInfoBasic_.deviceID)) {
        ACCESSTOKEN_LOG_ERROR(LABEL,
            "tokenID: 0x%{public}x devId is error", tokenInfoBasic_.tokenID);
        return RET_FAILED;
    }
    int aplNum = inGenericValues.GetInt(FIELD_APL);
    if (DataValidator::IsAplNumValid(aplNum)) {
        tokenInfoBasic_.apl = (ATokenAplEnum)aplNum;
    } else {
        ACCESSTOKEN_LOG_ERROR(LABEL,
            "tokenID: 0x%{public}x apl is error, value %{public}d",
            tokenInfoBasic_.tokenID, aplNum);
        return RET_FAILED;
    }
    tokenInfoBasic_.ver = (char)inGenericValues.GetInt(FIELD_TOKEN_VERSION);
    if (tokenInfoBasic_.ver != DEFAULT_TOKEN_VERSION) {
        ACCESSTOKEN_LOG_ERROR(LABEL,
            "tokenID: 0x%{public}x version is error, version %{public}d",
            tokenInfoBasic_.tokenID, tokenInfoBasic_.ver);
        return RET_FAILED;
    }
    tokenInfoBasic_.tokenAttr = (uint32_t)inGenericValues.GetInt(FIELD_TOKEN_ATTR);
    return RET_SUCCESS;
}

int HapTokenInfoInner::RestoreHapTokenInfo(AccessTokenID tokenId,
    GenericValues& tokenValue, const std::vector<GenericValues>& permDefRes,
    const std::vector<GenericValues>& permStateRes)
{
    tokenInfoBasic_.tokenID = tokenId;
    int ret = RestoreHapTokenBasicInfo(tokenValue);
    if (ret != RET_SUCCESS) {
        return RET_FAILED;
    }
    permPolicySet_ = PermissionPolicySet::RestorePermissionPolicy(tokenId,
        permDefRes, permStateRes);
    return RET_SUCCESS;
}

void HapTokenInfoInner::StoreHapBasicInfo(std::vector<GenericValues>& valueList) const
{
    GenericValues genericValues;
    TranslationIntoGenericValues(genericValues);
    valueList.emplace_back(genericValues);
}

void HapTokenInfoInner::StoreHapInfo(std::vector<GenericValues>& hapInfoValues,
    std::vector<GenericValues>& permDefValues,
    std::vector<GenericValues>& permStateValues) const
{
    if (isRemote_) {
        ACCESSTOKEN_LOG_INFO(LABEL,
            "token %{public}x is remote hap token, will not store", tokenInfoBasic_.tokenID);
        return;
    }
    StoreHapBasicInfo(hapInfoValues);
    if (permPolicySet_ != nullptr) {
        permPolicySet_->StorePermissionPolicySet(permDefValues, permStateValues);
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

void HapTokenInfoInner::ToString(std::string& info) const
{
    info.append(R"({"tokenID": )" + std::to_string(tokenInfoBasic_.tokenID));
    info.append(R"(, "tokenAttr": )" + std::to_string(tokenInfoBasic_.tokenAttr));
    info.append(R"(, "ver": )" + std::to_string(tokenInfoBasic_.ver));
    info.append(R"(, "userId": )" + std::to_string(tokenInfoBasic_.userID));
    info.append(R"(, "bundleName": ")" + tokenInfoBasic_.bundleName + R"(")");
    info.append(R"(, "instIndex": )" + std::to_string(tokenInfoBasic_.instIndex));
    info.append(R"(, "appID": ")" + tokenInfoBasic_.appID + R"(")");
    info.append(R"(, "deviceID": ")" + tokenInfoBasic_.deviceID + R"(")");
    info.append(R"(, "apl": )" + std::to_string(tokenInfoBasic_.apl));
    info.append(R"(, "isRemote": )" + std::to_string(isRemote_));

    if (permPolicySet_ != nullptr) {
        permPolicySet_->ToString(info);
    }
    info.append("}");
}
} // namespace AccessToken
} // namespace Security
} // namespace OHOS
