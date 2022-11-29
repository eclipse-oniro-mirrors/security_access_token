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

#include "native_token_info_inner.h"

#include "accesstoken_dfx_define.h"
#include "accesstoken_log.h"
#include "data_translator.h"
#include "data_validator.h"
#include "nlohmann/json.hpp"
#include "token_field_const.h"

namespace OHOS {
namespace Security {
namespace AccessToken {
namespace {
static constexpr OHOS::HiviewDFX::HiLogLabel LABEL = {LOG_CORE, SECURITY_DOMAIN_ACCESSTOKEN, "NativeTokenInfoInner"};
}

NativeTokenInfoInner::NativeTokenInfoInner() : isRemote_(false)
{
    tokenInfoBasic_.ver = DEFAULT_TOKEN_VERSION;
    tokenInfoBasic_.tokenID = 0;
    tokenInfoBasic_.tokenAttr = 0;
    tokenInfoBasic_.apl = APL_NORMAL;
}

NativeTokenInfoInner::NativeTokenInfoInner(NativeTokenInfo& native,
    const std::vector<PermissionStateFull>& permStateList) : isRemote_(false)
{
    tokenInfoBasic_ = native;
    permPolicySet_ = PermissionPolicySet::BuildPermissionPolicySet(native.tokenID,
        permStateList);
}

NativeTokenInfoInner::~NativeTokenInfoInner()
{
    ACCESSTOKEN_LOG_DEBUG(LABEL,
        "tokenID: %{public}u destruction", tokenInfoBasic_.tokenID);
}

int NativeTokenInfoInner::Init(AccessTokenID id, const std::string& processName,
    int apl, const std::vector<std::string>& dcap,
    const std::vector<std::string>& nativeAcls,
    const std::vector<PermissionStateFull>& permStateList)
{
    tokenInfoBasic_.tokenID = id;
    if (!DataValidator::IsProcessNameValid(processName)) {
        ACCESSTOKEN_LOG_ERROR(LABEL,
            "tokenID: %{public}u process name is null", tokenInfoBasic_.tokenID);
        return RET_FAILED;
    }
    tokenInfoBasic_.processName = processName;
    if (!DataValidator::IsAplNumValid(apl)) {
        ACCESSTOKEN_LOG_ERROR(LABEL,
            "tokenID: %{public}u init failed, apl %{public}d is invalid",
            tokenInfoBasic_.tokenID, apl);
        return RET_FAILED;
    }
    tokenInfoBasic_.apl = static_cast<ATokenAplEnum>(apl);
    tokenInfoBasic_.dcap = dcap;
    tokenInfoBasic_.nativeAcls = nativeAcls;

    permPolicySet_ = PermissionPolicySet::BuildPermissionPolicySet(id,
        permStateList);
    return RET_SUCCESS;
}

std::string NativeTokenInfoInner::DcapToString(const std::vector<std::string>& dcap) const
{
    std::string dcapStr;
    for (auto iter = dcap.begin(); iter != dcap.end(); iter++) {
        dcapStr.append(*iter);
        if (iter != (dcap.end() - 1)) {
            dcapStr.append(",");
        }
    }
    return dcapStr;
}

std::string NativeTokenInfoInner::NativeAclsToString(const std::vector<std::string>& nativeAcls) const
{
    std::string nativeAclsStr;
    for (auto iter = nativeAcls.begin(); iter != nativeAcls.end(); iter++) {
        nativeAclsStr.append(*iter);
        if (iter != (nativeAcls.end() - 1)) {
            nativeAclsStr.append(",");
        }
    }
    return nativeAclsStr;
}

int NativeTokenInfoInner::TranslationIntoGenericValues(GenericValues& outGenericValues) const
{
    outGenericValues.Put(TokenFiledConst::FIELD_TOKEN_ID, static_cast<int32_t>(tokenInfoBasic_.tokenID));
    outGenericValues.Put(TokenFiledConst::FIELD_PROCESS_NAME, tokenInfoBasic_.processName);
    outGenericValues.Put(TokenFiledConst::FIELD_APL, tokenInfoBasic_.apl);
    outGenericValues.Put(TokenFiledConst::FIELD_TOKEN_VERSION, tokenInfoBasic_.ver);
    outGenericValues.Put(TokenFiledConst::FIELD_DCAP, DcapToString(tokenInfoBasic_.dcap));
    outGenericValues.Put(TokenFiledConst::FIELD_NATIVE_ACLS, NativeAclsToString(tokenInfoBasic_.nativeAcls));
    outGenericValues.Put(TokenFiledConst::FIELD_TOKEN_ATTR, static_cast<int32_t>(tokenInfoBasic_.tokenAttr));

    return RET_SUCCESS;
}

int NativeTokenInfoInner::RestoreNativeTokenInfo(AccessTokenID tokenId, const GenericValues& inGenericValues,
    const std::vector<GenericValues>& permStateRes)
{
    tokenInfoBasic_.tokenID = tokenId;
    tokenInfoBasic_.processName = inGenericValues.GetString(TokenFiledConst::FIELD_PROCESS_NAME);
    if (!DataValidator::IsProcessNameValid(tokenInfoBasic_.processName)) {
        ACCESSTOKEN_LOG_ERROR(LABEL,
            "tokenID: %{public}u process name is null", tokenInfoBasic_.tokenID);
        HiviewDFX::HiSysEvent::Write(HiviewDFX::HiSysEvent::Domain::ACCESS_TOKEN, "PERMISSION_CHECK",
            HiviewDFX::HiSysEvent::EventType::FAULT, "CODE", LOAD_DATABASE_ERROR,
            "ERROR_REASON", "native token processName error");
        return RET_FAILED;
    }
    int aplNum = inGenericValues.GetInt(TokenFiledConst::FIELD_APL);
    if (!DataValidator::IsAplNumValid(aplNum)) {
        ACCESSTOKEN_LOG_ERROR(LABEL,
            "tokenID: %{public}u apl is error, value %{public}d",
            tokenInfoBasic_.tokenID, aplNum);
        HiviewDFX::HiSysEvent::Write(HiviewDFX::HiSysEvent::Domain::ACCESS_TOKEN, "PERMISSION_CHECK",
            HiviewDFX::HiSysEvent::EventType::FAULT, "CODE", LOAD_DATABASE_ERROR,
            "ERROR_REASON", "native token apl error");
        return RET_FAILED;
    }
    tokenInfoBasic_.apl = static_cast<ATokenAplEnum>(aplNum);
    tokenInfoBasic_.ver = (char)inGenericValues.GetInt(TokenFiledConst::FIELD_TOKEN_VERSION);
    if (tokenInfoBasic_.ver != DEFAULT_TOKEN_VERSION) {
        ACCESSTOKEN_LOG_ERROR(LABEL,
            "tokenID: %{public}u version is error, version %{public}d",
            tokenInfoBasic_.tokenID, tokenInfoBasic_.ver);
        HiviewDFX::HiSysEvent::Write(HiviewDFX::HiSysEvent::Domain::ACCESS_TOKEN, "PERMISSION_CHECK",
            HiviewDFX::HiSysEvent::EventType::FAULT, "CODE", LOAD_DATABASE_ERROR,
            "ERROR_REASON", "native token version error");
        return RET_FAILED;
    }

    SetDcaps(inGenericValues.GetString(TokenFiledConst::FIELD_DCAP));
    SetNativeAcls(inGenericValues.GetString(TokenFiledConst::FIELD_NATIVE_ACLS));
    tokenInfoBasic_.tokenAttr = (uint32_t)inGenericValues.GetInt(TokenFiledConst::FIELD_TOKEN_ATTR);

    permPolicySet_ = PermissionPolicySet::RestorePermissionPolicy(tokenId, permStateRes);
    return RET_SUCCESS;
}

void NativeTokenInfoInner::TranslateToNativeTokenInfo(NativeTokenInfo& infoParcel) const
{
    infoParcel.apl = tokenInfoBasic_.apl;
    infoParcel.ver = tokenInfoBasic_.ver;
    infoParcel.processName = tokenInfoBasic_.processName;
    infoParcel.dcap = tokenInfoBasic_.dcap;
    infoParcel.nativeAcls = tokenInfoBasic_.nativeAcls;
    infoParcel.tokenID = tokenInfoBasic_.tokenID;
    infoParcel.tokenAttr = tokenInfoBasic_.tokenAttr;
}

void NativeTokenInfoInner::StoreNativeInfo(std::vector<GenericValues>& valueList,
    std::vector<GenericValues>& permStateValues) const
{
    if (isRemote_) {
        return;
    }
    GenericValues genericValues;
    TranslationIntoGenericValues(genericValues);
    valueList.emplace_back(genericValues);

    if (permPolicySet_ != nullptr) {
        permPolicySet_->StorePermissionPolicySet(permStateValues);
    }
}

AccessTokenID NativeTokenInfoInner::GetTokenID() const
{
    return tokenInfoBasic_.tokenID;
}

std::vector<std::string> NativeTokenInfoInner::GetDcap() const
{
    return tokenInfoBasic_.dcap;
}

std::vector<std::string> NativeTokenInfoInner::GetNativeAcls() const
{
    return tokenInfoBasic_.nativeAcls;
}

std::string NativeTokenInfoInner::GetProcessName() const
{
    return tokenInfoBasic_.processName;
}

std::shared_ptr<PermissionPolicySet> NativeTokenInfoInner::GetNativeInfoPermissionPolicySet() const
{
    return permPolicySet_;
}

bool NativeTokenInfoInner::IsRemote() const
{
    return isRemote_;
}

void NativeTokenInfoInner::SetRemote(bool isRemote)
{
    isRemote_ = isRemote;
}

void NativeTokenInfoInner::SetDcaps(const std::string& dcapStr)
{
    std::string::size_type start = 0;
    while (true) {
        std::string::size_type offset = dcapStr.find(',', start);
        if (offset == std::string::npos) {
            tokenInfoBasic_.dcap.push_back(dcapStr.substr(start));
            break;
        }
        tokenInfoBasic_.dcap.push_back(dcapStr.substr(start, offset));
        start = offset + 1;
    }
}

void NativeTokenInfoInner::SetNativeAcls(const std::string& AclsStr)
{
    std::string::size_type start = 0;
    while (true) {
        std::string::size_type offset = AclsStr.find(',', start);
        if (offset == std::string::npos) {
            tokenInfoBasic_.nativeAcls.push_back(AclsStr.substr(start));
            break;
        }
        tokenInfoBasic_.nativeAcls.push_back(AclsStr.substr(start, offset));
        start = offset + 1;
    }
}

void NativeTokenInfoInner::ToString(std::string& info) const
{
    info.append(R"({)");
    info.append("\n");
    info.append(R"(  "tokenID": )" + std::to_string(tokenInfoBasic_.tokenID) + ",\n");
    info.append(R"(  "tokenAttr": )" + std::to_string(tokenInfoBasic_.tokenAttr) + ",\n");
    info.append(R"(  "ver": )" + std::to_string(tokenInfoBasic_.ver) + ",\n");
    info.append(R"(  "processName": ")" + tokenInfoBasic_.processName + R"(")" + ",\n");
    info.append(R"(  "apl": )" + std::to_string(tokenInfoBasic_.apl) + ",\n");
    info.append(R"(  "dcap": ")" + DcapToString(tokenInfoBasic_.dcap) + R"(")" + ",\n");
    info.append(R"(  "nativeAcls": ")" + NativeAclsToString(tokenInfoBasic_.nativeAcls) + R"(")" + ",\n");
    info.append(R"(  "isRemote": )" + std::to_string(isRemote_? 1 : 0) + ",\n");
    if (permPolicySet_ != nullptr) {
        permPolicySet_->PermStateToString(tokenInfoBasic_.apl, tokenInfoBasic_.nativeAcls, info);
    }
    info.append("}");
}
} // namespace AccessToken
} // namespace Security
} // namespace OHOS
