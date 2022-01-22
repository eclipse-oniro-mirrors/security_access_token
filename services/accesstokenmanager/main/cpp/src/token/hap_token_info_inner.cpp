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

HapTokenInfoInner::~HapTokenInfoInner()
{
    ACCESSTOKEN_LOG_DEBUG(LABEL,
        "%{public}s called, tokenID: 0x%{public}x destruction", __func__, tokenID_);
}

void HapTokenInfoInner::Init(AccessTokenID id, const HapInfoParams &info, const HapPolicyParams &policy)
{
    tokenID_ = id;
    userID_ = info.userID;
    bundleName_ = info.bundleName;
    instIndex_ = info.instIndex;
    appID_ = info.appIDDesc;
    deviceID_ = "0";
    apl_ = policy.apl;
    permPolicySet_ = PermissionPolicySet::BuildPermissionPolicySet(id, policy.permList, policy.permStateList);
}

void HapTokenInfoInner::Update(const std::string& appIDDesc, const HapPolicyParams& policy)
{
    appID_ = appIDDesc;
    apl_ = policy.apl;
    if (permPolicySet_ == nullptr) {
        permPolicySet_ = PermissionPolicySet::BuildPermissionPolicySet(tokenID_,
            policy.permList, policy.permStateList);
        return;
    }

    permPolicySet_->Update(policy.permList, policy.permStateList);
    return;
}

void HapTokenInfoInner::TranslateToHapTokenInfo(HapTokenInfo& InfoParcel) const
{
    InfoParcel.apl = apl_;
    InfoParcel.ver = ver_;
    InfoParcel.userID = userID_;
    InfoParcel.bundleName = bundleName_;
    InfoParcel.instIndex = instIndex_;
    InfoParcel.appID = appID_;
    InfoParcel.deviceID = deviceID_;
    InfoParcel.tokenID = tokenID_;
    InfoParcel.tokenAttr = tokenAttr_;
}

void HapTokenInfoInner::TranslationIntoGenericValues(GenericValues& outGenericValues) const
{
    outGenericValues.Put(FIELD_TOKEN_ID, tokenID_);
    outGenericValues.Put(FIELD_USER_ID, userID_);
    outGenericValues.Put(FIELD_BUNDLE_NAME, bundleName_);
    outGenericValues.Put(FIELD_INST_INDEX, instIndex_);
    outGenericValues.Put(FIELD_APP_ID, appID_);
    outGenericValues.Put(FIELD_DEVICE_ID, deviceID_);
    outGenericValues.Put(FIELD_APL, apl_);
    outGenericValues.Put(FIELD_TOKEN_VERSION, ver_);
    outGenericValues.Put(FIELD_TOKEN_ATTR, tokenAttr_);
}

int HapTokenInfoInner::RestoreHapTokenBasicInfo(const GenericValues& inGenericValues)
{
    userID_ = inGenericValues.GetInt(FIELD_USER_ID);
    bundleName_ = inGenericValues.GetString(FIELD_BUNDLE_NAME);
    if (!DataValidator::IsBundleNameValid(bundleName_)) {
        ACCESSTOKEN_LOG_ERROR(LABEL,
            "%{public}s called, tokenID: 0x%{public}x bundle name is error", __func__, tokenID_);
        return RET_FAILED;
    }

    instIndex_ = inGenericValues.GetInt(FIELD_INST_INDEX);
    appID_ = inGenericValues.GetString(FIELD_APP_ID);
    if (!DataValidator::IsAppIDDescValid(appID_)) {
        ACCESSTOKEN_LOG_ERROR(LABEL,
            "%{public}s called, tokenID: 0x%{public}x appID is error", __func__, tokenID_);
        return RET_FAILED;
    }

    deviceID_ = inGenericValues.GetString(FIELD_DEVICE_ID);
    if (!DataValidator::IsDeviceIdValid(deviceID_)) {
        ACCESSTOKEN_LOG_ERROR(LABEL,
            "%{public}s called, tokenID: 0x%{public}x devId is error", __func__, tokenID_);
        return RET_FAILED;
    }
    int aplNum = inGenericValues.GetInt(FIELD_APL);
    if (DataValidator::IsAplNumValid(aplNum)) {
        apl_ = (ATokenAplEnum)aplNum;
    } else {
        ACCESSTOKEN_LOG_ERROR(LABEL,
            "%{public}s called, tokenID: 0x%{public}x apl is error, value %{public}d", __func__, tokenID_, aplNum);
        return RET_FAILED;
    }
    ver_ = (char)inGenericValues.GetInt(FIELD_TOKEN_VERSION);
    if (ver_ != DEFAULT_TOKEN_VERSION) {
        ACCESSTOKEN_LOG_ERROR(LABEL,
            "%{public}s called, tokenID: 0x%{public}x version is error, version %{public}d", __func__, tokenID_, ver_);
        return RET_FAILED;
    }
    tokenAttr_ = (uint32_t)inGenericValues.GetInt(FIELD_TOKEN_ATTR);
    return RET_SUCCESS;
}

int HapTokenInfoInner::RestoreHapTokenInfo(AccessTokenID tokenId,
    GenericValues& tokenValue, const std::vector<GenericValues>& permDefRes,
    const std::vector<GenericValues>& permStateRes)
{
    tokenID_ = tokenId;
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
    return userID_;
}

std::string HapTokenInfoInner::GetBundleName() const
{
    return bundleName_;
}

int HapTokenInfoInner::GetInstIndex() const
{
    return instIndex_;
}

AccessTokenID HapTokenInfoInner::GetTokenID() const
{
    return tokenID_;
}

void HapTokenInfoInner::ToString(std::string& info) const
{
    info.append(R"({"tokenID": )" + std::to_string(tokenID_));
    info.append(R"(, "tokenAttr": )" + std::to_string(tokenAttr_));
    info.append(R"(, "ver": )" + std::to_string(ver_));
    info.append(R"(, "userId": )" + std::to_string(userID_));
    info.append(R"(, "bundleName": ")" + bundleName_ + R"(")");
    info.append(R"(, "instIndex": )" + std::to_string(instIndex_));
    info.append(R"(, "appID": ")" + appID_ + R"(")");
    info.append(R"(, "deviceID": ")" + deviceID_ + R"(")");
    info.append(R"(, "apl": )" + std::to_string(apl_));

    if (permPolicySet_ != nullptr) {
        permPolicySet_->ToString(info);
    }
    info.append("}");
}
} // namespace AccessToken
} // namespace Security
} // namespace OHOS
