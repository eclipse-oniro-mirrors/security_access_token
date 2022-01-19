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

#include "native_token_info_inner.h"

#include "data_translator.h"
#include "data_validator.h"
#include "field_const.h"
#include "nlohmann/json.hpp"

#include "accesstoken_log.h"

namespace OHOS {
namespace Security {
namespace AccessToken {
namespace {
static constexpr OHOS::HiviewDFX::HiLogLabel LABEL = {LOG_CORE, SECURITY_DOMAIN_ACCESSTOKEN, "NativeTokenInfoInner"};
}

NativeTokenInfoInner::NativeTokenInfoInner(NativeTokenInfo& native)
    : ver_(native.ver), tokenID_(native.tokenID), tokenAttr_(native.tokenAttr),
    processName_(native.processName), apl_(native.apl), dcap_(native.dcap)
{}

NativeTokenInfoInner::~NativeTokenInfoInner()
{
    ACCESSTOKEN_LOG_DEBUG(LABEL,
        "%{public}s called, tokenID: 0x%{public}x destruction", __func__, tokenID_);
}

int NativeTokenInfoInner::Init(AccessTokenID id, const std::string& processName,
    int apl, const std::vector<std::string>& dcap)
{
    tokenID_ = id;
    if (!DataValidator::IsProcessNameValid(processName)) {
        ACCESSTOKEN_LOG_ERROR(LABEL,
            "%{public}s called, tokenID: 0x%{public}x process name is null", __func__, tokenID_);
        return RET_FAILED;
    }
    processName_ = processName;
    if (!DataValidator::IsAplNumValid(apl)) {
        ACCESSTOKEN_LOG_ERROR(LABEL,
            "%{public}s called, tokenID: 0x%{public}x init failed, apl %{public}d is invalid",
            __func__, tokenID_, apl);
        return RET_FAILED;
    }
    apl_ = (ATokenAplEnum)apl;
    dcap_ = dcap;
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

int NativeTokenInfoInner::TranslationIntoGenericValues(GenericValues& outGenericValues) const
{
    outGenericValues.Put(FIELD_TOKEN_ID, tokenID_);
    outGenericValues.Put(FIELD_PROCESS_NAME, processName_);
    outGenericValues.Put(FIELD_APL, apl_);
    outGenericValues.Put(FIELD_TOKEN_VERSION, ver_);
    outGenericValues.Put(FIELD_DCAP, DcapToString(dcap_));
    outGenericValues.Put(FIELD_TOKEN_ATTR, tokenAttr_);

    return RET_SUCCESS;
}

int NativeTokenInfoInner::RestoreNativeTokenInfo(AccessTokenID tokenId, const GenericValues& inGenericValues)
{
    tokenID_ = tokenId;
    processName_ = inGenericValues.GetString(FIELD_PROCESS_NAME);
    if (!DataValidator::IsProcessNameValid(processName_)) {
        ACCESSTOKEN_LOG_ERROR(LABEL,
            "%{public}s called, tokenID: 0x%{public}x process name is null", __func__, tokenID_);
        return RET_FAILED;
    }
    int aplNum = inGenericValues.GetInt(FIELD_APL);
    if (!DataValidator::IsAplNumValid(aplNum)) {
        ACCESSTOKEN_LOG_ERROR(LABEL,
            "%{public}s called, tokenID: 0x%{public}x apl is error, value %{public}d", __func__, tokenID_, aplNum);
        return RET_FAILED;
    }
    apl_ = (ATokenAplEnum)aplNum;
    ver_ = inGenericValues.GetInt(FIELD_TOKEN_VERSION);
    if (ver_ != DEFAULT_TOKEN_VERSION) {
        ACCESSTOKEN_LOG_ERROR(LABEL,
            "%{public}s called, tokenID: 0x%{public}x version is error, version %{public}d", __func__, tokenID_, ver_);
        return RET_FAILED;
    }

    SetDcaps(inGenericValues.GetString(FIELD_DCAP));
    tokenAttr_ = (uint32_t)inGenericValues.GetInt(FIELD_TOKEN_ATTR);
    return RET_SUCCESS;
}

void NativeTokenInfoInner::TranslateToNativeTokenInfo(NativeTokenInfo& InfoParcel) const
{
    InfoParcel.apl = apl_;
    InfoParcel.ver = ver_;
    InfoParcel.processName = processName_;
    InfoParcel.dcap = dcap_;
    InfoParcel.tokenID = tokenID_;
    InfoParcel.tokenAttr = tokenAttr_;
}

void NativeTokenInfoInner::StoreNativeInfo(std::vector<GenericValues>& valueList) const
{
    GenericValues genericValues;
    TranslationIntoGenericValues(genericValues);
    valueList.emplace_back(genericValues);
}

bool NativeTokenInfoInner::FromJsonString(const std::string& jsonString)
{
    nlohmann::json jsonObject = nlohmann::json::parse(jsonString);
    if (jsonObject.is_discarded()) {
        return false;
    }

    if (jsonObject.find(JSON_PROCESS_NAME) != jsonObject.end()) {
        processName_ = jsonObject.at(JSON_PROCESS_NAME).get<std::string>();
    }

    if (jsonObject.find(JSON_APL) != jsonObject.end()) {
        int aplNum = jsonObject.at(JSON_APL).get<int>();
        if (DataValidator::IsAplNumValid(aplNum)) {
            apl_ = (ATokenAplEnum)aplNum;
        }
    }

    if (jsonObject.find(JSON_VERSION) != jsonObject.end()) {
        ver_ = jsonObject.at(JSON_VERSION).get<char>();
    }

    if (jsonObject.find(JSON_TOKEN_ID) != jsonObject.end()) {
        tokenID_ = jsonObject.at(JSON_TOKEN_ID).get<unsigned int>();
    }

    if (jsonObject.find(JSON_TOKEN_ATTR) != jsonObject.end()) {
        tokenAttr_ = jsonObject.at(JSON_TOKEN_ATTR).get<unsigned int>();
    }

    if (jsonObject.find(JSON_DCAPS) != jsonObject.end()) {
        dcap_ = jsonObject.at(JSON_DCAPS).get<std::vector<std::string>>();
    }

    return true;
}

AccessTokenID NativeTokenInfoInner::GetTokenID() const
{
    return tokenID_;
}

std::vector<std::string> NativeTokenInfoInner::GetDcap() const
{
    return dcap_;
}

std::string NativeTokenInfoInner::GetProcessName() const
{
    return processName_;
}

void NativeTokenInfoInner::SetDcaps(const std::string& dcapStr)
{
    std::string::size_type start = 0;
    while (true) {
        std::string::size_type offset = dcapStr.find(',', start);
        if (offset == std::string::npos) {
            dcap_.push_back(dcapStr.substr(start));
            break;
        }
        dcap_.push_back(dcapStr.substr(start, offset));
        start = offset + 1;
    }
}

void NativeTokenInfoInner::ToString(std::string& info) const
{
    info.append(R"({"tokenID": )" + std::to_string(tokenID_));
    info.append(R"(, "tokenAttr": )" + std::to_string(tokenAttr_));
    info.append(R"(, "ver": )" + std::to_string(ver_));
    info.append(R"(, "processName": ")" + processName_ + R"(")");
    info.append(R"(, "apl": )" + std::to_string(apl_));
    info.append(R"(, "dcap": ")" + DcapToString(dcap_) + R"(")");
    info.append("}");
}
} // namespace AccessToken
} // namespace Security
} // namespace OHOS
