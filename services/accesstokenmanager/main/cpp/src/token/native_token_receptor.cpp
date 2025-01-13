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
#include <fcntl.h>
#include <memory>
#include <sys/stat.h>
#include <sys/types.h>
#include <unistd.h>

#include "access_token_error.h"
#include "accesstoken_id_manager.h"
#include "accesstoken_info_manager.h"
#include "accesstoken_log.h"
#include "data_validator.h"
#include "json_parser.h"
#include "native_token_receptor.h"
#include "securec.h"

namespace OHOS {
namespace Security {
namespace AccessToken {
namespace {
std::recursive_mutex g_instanceMutex;
static constexpr OHOS::HiviewDFX::HiLogLabel LABEL = {LOG_CORE, SECURITY_DOMAIN_ACCESSTOKEN, "NativeTokenReceptor"};
static const char* JSON_PROCESS_NAME = "processName";
static const char* JSON_APL = "APL";
static const char* JSON_VERSION = "version";
static const char* JSON_TOKEN_ID = "tokenId";
static const char* JSON_TOKEN_ATTR = "tokenAttr";
static const char* JSON_DCAPS = "dcaps";
static const char* JSON_PERMS = "permissions";
static const char* JSON_ACLS = "nativeAcls";
static const int MAX_DCAPS_NUM = 10 * 1024;
static const int MAX_REQ_PERM_NUM = 10 * 1024;
}

int32_t NativeReqPermsGet(
    const nlohmann::json& j, std::vector<PermissionStatus>& permStateList)
{
    std::vector<std::string> permReqList;
    if (j.find(JSON_PERMS) == j.end() || (!j.at(JSON_PERMS).is_array())) {
        ACCESSTOKEN_LOG_ERROR(LABEL, "JSON_PERMS is invalid.");
        return ERR_PARAM_INVALID;
    }
    permReqList = j.at(JSON_PERMS).get<std::vector<std::string>>();
    if (permReqList.size() > MAX_REQ_PERM_NUM) {
        ACCESSTOKEN_LOG_ERROR(LABEL, "Permission num oversize.");
        return ERR_OVERSIZE;
    }
    std::set<std::string> permRes;
    for (const auto& permReq : permReqList) {
        PermissionStatus permState;
        if (permRes.count(permReq) != 0) {
            continue;
        }
        permState.permissionName = permReq;
        permState.grantStatus = PERMISSION_GRANTED;
        permState.grantFlag = PERMISSION_SYSTEM_FIXED;
        permStateList.push_back(permState);
        permRes.insert(permReq);
    }
    return RET_SUCCESS;
}

// nlohmann json need the function named from_json to parse NativeTokenInfoBase
void from_json(const nlohmann::json& j, NativeTokenInfoBase& native)
{
    NativeTokenInfoBase info;
    int aplNum = 0;
    if (!JsonParser::GetIntFromJson(j, JSON_APL, aplNum) || !DataValidator::IsAplNumValid(aplNum)) {
        return;
    }

    info.apl = static_cast<ATokenAplEnum>(aplNum);

    if (j.find(JSON_VERSION) == j.end() || (!j.at(JSON_VERSION).is_number())) {
        return;
    }
    info.ver = (uint8_t)j.at(JSON_VERSION).get<int>();
    if (info.ver != DEFAULT_TOKEN_VERSION) {
        return;
    }

    if (!JsonParser::GetUnsignedIntFromJson(j, JSON_TOKEN_ID, info.tokenID) || (info.tokenID == 0)) {
        return;
    }

    ATokenTypeEnum type = AccessTokenIDManager::GetTokenIdTypeEnum(info.tokenID);
    if ((type != TOKEN_NATIVE) && (type != TOKEN_SHELL)) {
        return;
    }

    if (!JsonParser::GetUnsignedIntFromJson(j, JSON_TOKEN_ATTR, info.tokenAttr)) {
        return;
    }

    if (j.find(JSON_DCAPS) == j.end() || (!j.at(JSON_DCAPS).is_array())) {
        return;
    }
    info.dcap = j.at(JSON_DCAPS).get<std::vector<std::string>>();
    if (info.dcap.size() > MAX_DCAPS_NUM) {
        ACCESSTOKEN_LOG_ERROR(LABEL, "Native dcap oversize.");
        return;
    }

    if (j.find(JSON_ACLS) == j.end() || (!j.at(JSON_DCAPS).is_array())) {
        return;
    }
    info.nativeAcls = j.at(JSON_ACLS).get<std::vector<std::string>>();
    if (info.nativeAcls.size() > MAX_REQ_PERM_NUM) {
        ACCESSTOKEN_LOG_ERROR(LABEL, "Permission num oversize.");
        return;
    }

    if (NativeReqPermsGet(j, info.permStateList) != RET_SUCCESS) {
        return;
    }

    if (!JsonParser::GetStringFromJson(j, JSON_PROCESS_NAME, info.processName) ||
        !DataValidator::IsProcessNameValid(info.processName)) {
        return;
    }
    native = info;
}

int32_t NativeTokenReceptor::ParserNativeRawData(const std::string& nativeRawData,
    std::vector<NativeTokenInfoBase>& tokenInfos)
{
    nlohmann::json jsonRes = nlohmann::json::parse(nativeRawData, nullptr, false);
    if (jsonRes.is_discarded()) {
        ACCESSTOKEN_LOG_ERROR(LABEL, "JsonRes is invalid.");
        return ERR_PARAM_INVALID;
    }
    for (auto it = jsonRes.begin(); it != jsonRes.end(); it++) {
        auto token = it->get<NativeTokenInfoBase>();
        if (!token.processName.empty()) {
            tokenInfos.emplace_back(token);
        }
    }
    return RET_SUCCESS;
}

int NativeTokenReceptor::GetAllNativeTokenInfo(std::vector<NativeTokenInfoBase>& tokenInfos)
{
    std::string nativeRawData;
    int ret = JsonParser::ReadCfgFile(NATIVE_TOKEN_CONFIG_FILE, nativeRawData);
    if (ret != RET_SUCCESS) {
        ACCESSTOKEN_LOG_ERROR(LABEL, "ReadCfgFile failed.");
        return ret;
    }
    ret = ParserNativeRawData(nativeRawData, tokenInfos);
    if (ret != RET_SUCCESS) {
        ACCESSTOKEN_LOG_ERROR(LABEL, "ParserNativeRawData failed.");
        return ret;
    }
    return RET_SUCCESS;
}

NativeTokenReceptor& NativeTokenReceptor::GetInstance()
{
    static NativeTokenReceptor* instance = nullptr;
    if (instance == nullptr) {
        std::lock_guard<std::recursive_mutex> lock(g_instanceMutex);
        if (instance == nullptr) {
            NativeTokenReceptor* tmp = new NativeTokenReceptor();
            instance = std::move(tmp);
        }
    }
    return *instance;
}
} // namespace AccessToken
} // namespace Security
} // namespace OHOS
