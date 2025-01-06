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

#include "native_token_info_inner.h"

#include "access_token_error.h"
#include "accesstoken_dfx_define.h"
#include "accesstoken_log.h"
#include "data_translator.h"
#include "data_validator.h"
#include "token_field_const.h"

namespace OHOS {
namespace Security {
namespace AccessToken {
namespace {
static constexpr OHOS::HiviewDFX::HiLogLabel LABEL = {LOG_CORE, SECURITY_DOMAIN_ACCESSTOKEN, "NativeTokenInfoInner"};
}

NativeTokenInfoInner::NativeTokenInfoInner()
{
    tokenInfoBasic_.ver = DEFAULT_TOKEN_VERSION;
    tokenInfoBasic_.tokenID = 0;
    tokenInfoBasic_.tokenAttr = 0;
    tokenInfoBasic_.apl = APL_NORMAL;
}

NativeTokenInfoInner::NativeTokenInfoInner(NativeTokenInfoBase& native,
    const std::vector<PermissionStatus>& permStateList)
{
    tokenInfoBasic_ = native;
    permPolicySet_ = PermissionPolicySet::BuildPermissionPolicySet(native.tokenID,
        permStateList);
}

NativeTokenInfoInner::~NativeTokenInfoInner()
{
    ACCESSTOKEN_LOG_DEBUG(LABEL, "TokenID: %{public}u destruction", tokenInfoBasic_.tokenID);
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

int NativeTokenInfoInner::RestoreNativeTokenInfo(AccessTokenID tokenId, const GenericValues& inGenericValues,
    const std::vector<GenericValues>& permStateRes)
{
    tokenInfoBasic_.tokenID = tokenId;
    tokenInfoBasic_.processName = inGenericValues.GetString(TokenFiledConst::FIELD_PROCESS_NAME);
    if (!DataValidator::IsProcessNameValid(tokenInfoBasic_.processName)) {
        ACCESSTOKEN_LOG_ERROR(LABEL,
            "tokenID: %{public}u process name is null", tokenInfoBasic_.tokenID);
        HiSysEventWrite(HiviewDFX::HiSysEvent::Domain::ACCESS_TOKEN, "PERMISSION_CHECK",
            HiviewDFX::HiSysEvent::EventType::FAULT, "CODE", LOAD_DATABASE_ERROR,
            "ERROR_REASON", "native token processName error");
        return ERR_PARAM_INVALID;
    }
    int aplNum = inGenericValues.GetInt(TokenFiledConst::FIELD_APL);
    if (!DataValidator::IsAplNumValid(aplNum)) {
        ACCESSTOKEN_LOG_ERROR(LABEL,
            "tokenID: %{public}u apl is error, value %{public}d",
            tokenInfoBasic_.tokenID, aplNum);
        HiSysEventWrite(HiviewDFX::HiSysEvent::Domain::ACCESS_TOKEN, "PERMISSION_CHECK",
            HiviewDFX::HiSysEvent::EventType::FAULT, "CODE", LOAD_DATABASE_ERROR,
            "ERROR_REASON", "native token apl error");
        return ERR_PARAM_INVALID;
    }
    tokenInfoBasic_.apl = static_cast<ATokenAplEnum>(aplNum);
    tokenInfoBasic_.ver = (char)inGenericValues.GetInt(TokenFiledConst::FIELD_TOKEN_VERSION);
    if (tokenInfoBasic_.ver != DEFAULT_TOKEN_VERSION) {
        ACCESSTOKEN_LOG_ERROR(LABEL,
            "tokenID: %{public}u version is error, version %{public}d",
            tokenInfoBasic_.tokenID, tokenInfoBasic_.ver);
        HiSysEventWrite(HiviewDFX::HiSysEvent::Domain::ACCESS_TOKEN, "PERMISSION_CHECK",
            HiviewDFX::HiSysEvent::EventType::FAULT, "CODE", LOAD_DATABASE_ERROR,
            "ERROR_REASON", "native token version error");
        return ERR_PARAM_INVALID;
    }

    SetDcaps(inGenericValues.GetString(TokenFiledConst::FIELD_DCAP));
    SetNativeAcls(inGenericValues.GetString(TokenFiledConst::FIELD_NATIVE_ACLS));
    tokenInfoBasic_.tokenAttr = (uint32_t)inGenericValues.GetInt(TokenFiledConst::FIELD_TOKEN_ATTR);

    permPolicySet_ = PermissionPolicySet::RestorePermissionPolicy(tokenId, permStateRes);
    return RET_SUCCESS;
}

void NativeTokenInfoInner::TransferNativeInfo(std::vector<GenericValues>& valueList) const
{
    GenericValues value;
    value.Put(TokenFiledConst::FIELD_TOKEN_ID, static_cast<int32_t>(tokenInfoBasic_.tokenID));
    value.Put(TokenFiledConst::FIELD_PROCESS_NAME, tokenInfoBasic_.processName);
    value.Put(TokenFiledConst::FIELD_APL, tokenInfoBasic_.apl);
    value.Put(TokenFiledConst::FIELD_TOKEN_VERSION, tokenInfoBasic_.ver);
    value.Put(TokenFiledConst::FIELD_DCAP, DcapToString(tokenInfoBasic_.dcap));
    value.Put(TokenFiledConst::FIELD_NATIVE_ACLS, NativeAclsToString(tokenInfoBasic_.nativeAcls));
    value.Put(TokenFiledConst::FIELD_TOKEN_ATTR, static_cast<int32_t>(tokenInfoBasic_.tokenAttr));
    valueList.emplace_back(value);
}

void NativeTokenInfoInner::TransferPermissionPolicy(std::vector<GenericValues>& permStateValues) const
{
    if (permPolicySet_ != nullptr) {
        permPolicySet_->StorePermissionPolicySet(permStateValues);
    }
}

AccessTokenID NativeTokenInfoInner::GetTokenID() const
{
    return tokenInfoBasic_.tokenID;
}

AccessTokenID NativeTokenInfoInner::GetApl() const
{
    return tokenInfoBasic_.apl;
}

std::string NativeTokenInfoInner::GetProcessName() const
{
    return tokenInfoBasic_.processName;
}

std::shared_ptr<PermissionPolicySet> NativeTokenInfoInner::GetNativeInfoPermissionPolicySet() const
{
    return permPolicySet_;
}

uint32_t NativeTokenInfoInner::GetReqPermissionSize() const
{
    if (permPolicySet_ != nullptr) {
        return permPolicySet_->GetReqPermissionSize();
    }
    return static_cast<uint32_t>(0);
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
        tokenInfoBasic_.dcap.push_back(dcapStr.substr(start, start - offset));
        start = offset + 1;
    }
}

void NativeTokenInfoInner::SetNativeAcls(const std::string& aclsStr)
{
    std::string::size_type start = 0;
    while (true) {
        std::string::size_type offset = aclsStr.find(',', start);
        if (offset == std::string::npos) {
            tokenInfoBasic_.nativeAcls.push_back(aclsStr.substr(start));
            break;
        }
        tokenInfoBasic_.nativeAcls.push_back(aclsStr.substr(start, offset - start));
        start = offset + 1;
    }
}

void NativeTokenInfoInner::ToString(std::string& info) const
{
    info.append(R"({)");
    info.append("\n");
    info.append(R"(  "tokenID": )" + std::to_string(tokenInfoBasic_.tokenID) + ",\n");
    info.append(R"(  "processName": ")" + tokenInfoBasic_.processName + R"(")" + ",\n");
    info.append(R"(  "apl": )" + std::to_string(tokenInfoBasic_.apl) + ",\n");
    if (permPolicySet_ != nullptr) {
        permPolicySet_->PermStateToString(tokenInfoBasic_.apl, tokenInfoBasic_.nativeAcls, info);
    }
    info.append("}");
}
} // namespace AccessToken
} // namespace Security
} // namespace OHOS
