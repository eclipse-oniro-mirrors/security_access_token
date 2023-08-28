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
#include <fcntl.h>
#include <memory>
#include <sys/stat.h>
#include <sys/types.h>
#include <unistd.h>

#include "accesstoken_id_manager.h"
#include "accesstoken_info_manager.h"
#include "accesstoken_log.h"
#include "data_validator.h"
#include "native_token_receptor.h"
#include "securec.h"

namespace OHOS {
namespace Security {
namespace AccessToken {
namespace {
static constexpr OHOS::HiviewDFX::HiLogLabel LABEL = {LOG_CORE, SECURITY_DOMAIN_ACCESSTOKEN, "NativeTokenReceptor"};
static const std::string DEFAULT_DEVICEID = "0";
static const std::string JSON_PROCESS_NAME = "processName";
static const std::string JSON_APL = "APL";
static const std::string JSON_VERSION = "version";
static const std::string JSON_TOKEN_ID = "tokenId";
static const std::string JSON_TOKEN_ATTR = "tokenAttr";
static const std::string JSON_DCAPS = "dcaps";
static const std::string JSON_PERMS = "permissions";
static const std::string JSON_ACLS = "nativeAcls";
}

int32_t NativeReqPermsGet(
    const nlohmann::json& j, std::vector<PermissionStateFull>& permStateList)
{
    std::vector<std::string> permReqList;
    if (j.find(JSON_PERMS) == j.end() || (!j.at(JSON_PERMS).is_array())) {
        return RET_FAILED;
    }
    permReqList = j.at(JSON_PERMS).get<std::vector<std::string>>();
    if (permReqList.size() > MAX_REQ_PERM_NUM) {
        return RET_FAILED;
    }
    std::set<std::string> permRes;
    for (const auto& permReq : permReqList) {
        PermissionStateFull permState;
        if (permRes.count(permReq) != 0) {
            continue;
        }
        permState.permissionName = permReq;
        permState.isGeneral = true;
        permState.resDeviceID.push_back(DEFAULT_DEVICEID);
        permState.grantStatus.push_back(PERMISSION_GRANTED);
        permState.grantFlags.push_back(PERMISSION_SYSTEM_FIXED);
        permStateList.push_back(permState);
        permRes.insert(permReq);
    }
    return RET_SUCCESS;
}

static bool GetStringFromJson(const nlohmann::json& j, const std::string& tag, std::string& out)
{
    if (j.find(tag) != j.end() && j.at(tag).is_string()) {
        out = j.at(tag).get<std::string>();
        return true;
    }
    return false;
}

static bool GetIntFromJson(const nlohmann::json& j, const std::string& tag, int& out)
{
    if (j.find(tag) != j.end() && j.at(tag).is_number()) {
        out = j.at(tag).get<int>();
        return true;
    }
    return false;
}

static bool GetUnsignIntFromJson(const nlohmann::json& j, const std::string& tag, unsigned int& out)
{
    if (j.find(tag) != j.end() && j.at(tag).is_number()) {
        out = j.at(tag).get<unsigned int>();
        return true;
    }
    return false;
}

// nlohmann json need the function named from_json to parse NativeTokenInfo
void from_json(const nlohmann::json& j, std::shared_ptr<NativeTokenInfoInner>& p)
{
    NativeTokenInfo native;

    if (!GetStringFromJson(j, JSON_PROCESS_NAME, native.processName) ||
        !DataValidator::IsProcessNameValid(native.processName)) {
        return;
    }

    int aplNum = 0;
    if (!GetIntFromJson(j, JSON_APL, aplNum) || !DataValidator::IsAplNumValid(aplNum)) {
        return;
    }

    native.apl = static_cast<ATokenAplEnum>(aplNum);

    if (j.find(JSON_VERSION) == j.end() || (!j.at(JSON_VERSION).is_number())) {
        return;
    }
    native.ver = (uint8_t)j.at(JSON_VERSION).get<int>();
    if (native.ver != DEFAULT_TOKEN_VERSION) {
        return;
    }

    if (!GetUnsignIntFromJson(j, JSON_TOKEN_ID, native.tokenID) || (native.tokenID == 0)) {
        return;
    }

    ATokenTypeEnum type = AccessTokenIDManager::GetTokenIdTypeEnum(native.tokenID);
    if ((type != TOKEN_NATIVE) && (type != TOKEN_SHELL)) {
        return;
    }

    if (!GetUnsignIntFromJson(j, JSON_TOKEN_ATTR, native.tokenAttr)) {
        return;
    }

    if (j.find(JSON_DCAPS) == j.end() || (!j.at(JSON_DCAPS).is_array())) {
        return;
    }
    native.dcap = j.at(JSON_DCAPS).get<std::vector<std::string>>();
    if (native.dcap.size() > MAX_DCAPS_NUM) {
        return;
    }

    if (j.find(JSON_ACLS) == j.end() || (!j.at(JSON_DCAPS).is_array())) {
        return;
    }
    native.nativeAcls = j.at(JSON_ACLS).get<std::vector<std::string>>();
    if (native.nativeAcls.size() > MAX_REQ_PERM_NUM) {
        return;
    }

    std::vector<PermissionStateFull> permStateList;
    if (NativeReqPermsGet(j, permStateList) != RET_SUCCESS) {
        return;
    }

    p = std::make_shared<NativeTokenInfoInner>(native, permStateList);
}

int32_t NativeTokenReceptor::ParserNativeRawData(const std::string& nativeRawData,
    std::vector<std::shared_ptr<NativeTokenInfoInner>>& tokenInfos)
{
    nlohmann::json jsonRes = nlohmann::json::parse(nativeRawData, nullptr, false);
    if (jsonRes.is_discarded()) {
        ACCESSTOKEN_LOG_ERROR(LABEL, "jsonRes is invalid.");
        return RET_FAILED;
    }
    for (auto it = jsonRes.begin(); it != jsonRes.end(); it++) {
        auto token = it->get<std::shared_ptr<NativeTokenInfoInner>>();
        if (token != nullptr) {
            tokenInfos.emplace_back(token);
        }
    }
    return RET_SUCCESS;
}

int NativeTokenReceptor::ReadCfgFile(std::string& nativeRawData)
{
    int32_t fd = open(NATIVE_TOKEN_CONFIG_FILE.c_str(), O_RDONLY);
    if (fd < 0) {
        ACCESSTOKEN_LOG_ERROR(LABEL, "open failed errno %{public}d.", errno);
        return RET_FAILED;
    }
    struct stat statBuffer;

    if (fstat(fd, &statBuffer) != 0) {
        ACCESSTOKEN_LOG_ERROR(LABEL, "fstat failed.");
        close(fd);
        return RET_FAILED;
    }

    if (statBuffer.st_size == 0) {
        ACCESSTOKEN_LOG_ERROR(LABEL, "config file size is invalid.");
        close(fd);
        return RET_FAILED;
    }
    if (statBuffer.st_size > MAX_NATIVE_CONFIG_FILE_SIZE) {
        ACCESSTOKEN_LOG_ERROR(LABEL, "config file size is too large.");
        close(fd);
        return RET_FAILED;
    }
    nativeRawData.reserve(statBuffer.st_size);

    char buff[BUFFER_SIZE] = { 0 };
    ssize_t readLen = 0;
    while ((readLen = read(fd, buff, BUFFER_SIZE)) > 0) {
        nativeRawData.append(buff, readLen);
    }
    close(fd);

    if (readLen == 0) {
        return RET_SUCCESS;
    }
    return RET_FAILED;
}

int NativeTokenReceptor::Init()
{
    std::string nativeRawData;
    int ret = ReadCfgFile(nativeRawData);
    if (ret != RET_SUCCESS) {
        ACCESSTOKEN_LOG_ERROR(LABEL, "readCfgFile failed.");
        return RET_FAILED;
    }
    std::vector<std::shared_ptr<NativeTokenInfoInner>> tokenInfos;
    ret = ParserNativeRawData(nativeRawData, tokenInfos);
    if (ret != RET_SUCCESS) {
        ACCESSTOKEN_LOG_ERROR(LABEL, "ParserNativeRawData failed.");
        return RET_FAILED;
    }
    AccessTokenInfoManager::GetInstance().ProcessNativeTokenInfos(tokenInfos);

    ACCESSTOKEN_LOG_INFO(LABEL, "init ok.");
    return RET_SUCCESS;
}

NativeTokenReceptor& NativeTokenReceptor::GetInstance()
{
    static NativeTokenReceptor instance;
    return instance;
}
} // namespace AccessToken
} // namespace Security
} // namespace OHOS
