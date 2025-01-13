/*
 * Copyright (c) 2022 Huawei Device Co., Ltd.
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
#include "base_remote_command.h"

#include "accesstoken_log.h"
#include "data_validator.h"

namespace OHOS {
namespace Security {
namespace AccessToken {
namespace {
static constexpr OHOS::HiviewDFX::HiLogLabel LABEL = {LOG_CORE, SECURITY_DOMAIN_ACCESSTOKEN, "BaseRemoteCommand"};
static const std::string JSON_COMMAND_NAME = "commandName";
static const std::string JSON_UNIQUEID = "uniqueId";
static const std::string JSON_REQUEST_VERSION = "requestVersion";
static const std::string JSON_SRC_DEVICEID = "srcDeviceId";
static const std::string JSON_SRC_DEVICE_LEVEL = "srcDeviceLevel";
static const std::string JSON_DST_DEVICEID = "dstDeviceId";
static const std::string JSON_DST_DEVICE_LEVEL = "dstDeviceLevel";
static const std::string JSON_STATUS_CODE = "statusCode";
static const std::string JSON_MESSAGE = "message";
static const std::string JSON_RESPONSE_VERSION = "responseVersion";
static const std::string JSON_RESPONSE_DEVICEID = "responseDeviceId";
static const std::string JSON_VERSION = "version";
static const std::string JSON_TOKENID = "tokenID";
static const std::string JSON_TOKEN_ATTR = "tokenAttr";
static const std::string JSON_USERID = "userID";
static const std::string JSON_BUNDLE_NAME = "bundleName";
static const std::string JSON_INST_INDEX = "instIndex";
static const std::string JSON_DLP_TYPE = "dlpType";
}

static void GetStringFromJson(const nlohmann::json& jsonObject, const std::string& tag, std::string& out)
{
    if (jsonObject.find(tag) != jsonObject.end() && jsonObject.at(tag).is_string()) {
        out = jsonObject.at(tag).get<std::string>();
    }
}

static void GetIntFromJson(const nlohmann::json& jsonObject, const std::string& tag, int32_t& out)
{
    if (jsonObject.find(tag) != jsonObject.end() && jsonObject.at(tag).is_number()) {
        out = jsonObject.at(tag).get<int32_t>();
    }
}

static void GetUnSignedIntFromJson(const nlohmann::json& jsonObject, const std::string& tag,
    unsigned int& out)
{
    if (jsonObject.find(tag) != jsonObject.end() && jsonObject.at(tag).is_number()) {
        out = jsonObject.at(tag).get<unsigned int>();
    }
}

void BaseRemoteCommand::FromRemoteProtocolJson(const nlohmann::json& jsonObject)
{
    GetStringFromJson(jsonObject, JSON_COMMAND_NAME, remoteProtocol_.commandName);
    GetStringFromJson(jsonObject, JSON_UNIQUEID, remoteProtocol_.uniqueId);
    GetIntFromJson(jsonObject, JSON_REQUEST_VERSION, remoteProtocol_.requestVersion);
    GetStringFromJson(jsonObject, JSON_SRC_DEVICEID, remoteProtocol_.srcDeviceId);
    GetStringFromJson(jsonObject, JSON_SRC_DEVICE_LEVEL, remoteProtocol_.srcDeviceLevel);
    GetStringFromJson(jsonObject, JSON_DST_DEVICEID, remoteProtocol_.dstDeviceId);
    GetStringFromJson(jsonObject, JSON_DST_DEVICE_LEVEL, remoteProtocol_.dstDeviceLevel);
    GetIntFromJson(jsonObject, JSON_STATUS_CODE, remoteProtocol_.statusCode);
    GetStringFromJson(jsonObject, JSON_MESSAGE, remoteProtocol_.message);
    GetIntFromJson(jsonObject, JSON_RESPONSE_VERSION, remoteProtocol_.responseVersion);
    GetStringFromJson(jsonObject, JSON_RESPONSE_DEVICEID, remoteProtocol_.responseDeviceId);
}

nlohmann::json BaseRemoteCommand::ToRemoteProtocolJson()
{
    nlohmann::json j;
    j["commandName"] = remoteProtocol_.commandName;
    j["uniqueId"] = remoteProtocol_.uniqueId;
    j["requestVersion"] = remoteProtocol_.requestVersion;
    j["srcDeviceId"] = remoteProtocol_.srcDeviceId;
    j["srcDeviceLevel"] = remoteProtocol_.srcDeviceLevel;
    j["dstDeviceId"] = remoteProtocol_.dstDeviceId;
    j["dstDeviceLevel"] = remoteProtocol_.dstDeviceLevel;
    j["statusCode"] = remoteProtocol_.statusCode;
    j["message"] = remoteProtocol_.message;
    j["responseVersion"] = remoteProtocol_.responseVersion;
    j["responseDeviceId"] = remoteProtocol_.responseDeviceId;
    return j;
}

nlohmann::json BaseRemoteCommand::ToNativeTokenInfoJson(const NativeTokenInfoBase& tokenInfo)
{
    nlohmann::json permStatesJson;
    for (const auto& permState : tokenInfo.permStateList) {
        nlohmann::json permStateJson;
        ToPermStateJson(permStateJson, permState);
        permStatesJson.emplace_back(permStateJson);
    }

    nlohmann::json DcapsJson = nlohmann::json(tokenInfo.dcap);
    nlohmann::json NativeAclsJson = nlohmann::json(tokenInfo.nativeAcls);
    nlohmann::json nativeTokenJson = nlohmann::json {
        {"processName", tokenInfo.processName},
        {"apl", tokenInfo.apl},
        {"version", tokenInfo.ver},
        {"tokenId", tokenInfo.tokenID},
        {"tokenAttr", tokenInfo.tokenAttr},
        {"dcaps", DcapsJson},
        {"nativeAcls", NativeAclsJson},
        {"permState", permStatesJson},
    };
    return nativeTokenJson;
}

void BaseRemoteCommand::ToPermStateJson(nlohmann::json& permStateJson, const PermissionStatus& state)
{
    permStateJson["permissionName"] = state.permissionName;
    permStateJson["grantStatus"] = state.grantStatus;
    permStateJson["grantFlag"] = state.grantFlag;
}

nlohmann::json BaseRemoteCommand::ToHapTokenInfosJson(const HapTokenInfoForSync& tokenInfo)
{
    nlohmann::json permStatesJson;
    for (const auto& permState : tokenInfo.permStateList) {
        nlohmann::json permStateJson;
        ToPermStateJson(permStateJson, permState);
        permStatesJson.emplace_back(permStateJson);
    }

    nlohmann::json hapTokensJson = nlohmann::json {
        {"version", tokenInfo.baseInfo.ver},
        {"tokenID", tokenInfo.baseInfo.tokenID},
        {"tokenAttr", tokenInfo.baseInfo.tokenAttr},
        {"userID", tokenInfo.baseInfo.userID},
        {"bundleName", tokenInfo.baseInfo.bundleName},
        {"instIndex", tokenInfo.baseInfo.instIndex},
        {"dlpType", tokenInfo.baseInfo.dlpType},
        {"permState", permStatesJson}
    };
    return hapTokensJson;
}

void BaseRemoteCommand::FromHapTokenBasicInfoJson(const nlohmann::json& hapTokenJson,
    HapTokenInfo& hapTokenBasicInfo)
{
    if (hapTokenJson.find("version") != hapTokenJson.end() && hapTokenJson.at("version").is_number()) {
        hapTokenJson.at("version").get_to(hapTokenBasicInfo.ver);
    }

    GetUnSignedIntFromJson(hapTokenJson, JSON_TOKENID, hapTokenBasicInfo.tokenID);
    GetUnSignedIntFromJson(hapTokenJson, JSON_TOKEN_ATTR, hapTokenBasicInfo.tokenAttr);
    GetIntFromJson(hapTokenJson, JSON_USERID, hapTokenBasicInfo.userID);
    GetStringFromJson(hapTokenJson, JSON_BUNDLE_NAME, hapTokenBasicInfo.bundleName);
    GetIntFromJson(hapTokenJson, JSON_INST_INDEX, hapTokenBasicInfo.instIndex);
    GetIntFromJson(hapTokenJson, JSON_DLP_TYPE, hapTokenBasicInfo.dlpType);
}

void BaseRemoteCommand::FromPermStateListJson(const nlohmann::json& hapTokenJson,
    std::vector<PermissionStatus>& permStateList)
{
    if (hapTokenJson.find("permState") != hapTokenJson.end()
        && hapTokenJson.at("permState").is_array()
        && !hapTokenJson.at("permState").empty()) {
        nlohmann::json permissionsJson = hapTokenJson.at("permState").get<nlohmann::json>();
        for (const auto& permissionJson : permissionsJson) {
            PermissionStatus permission;
            if (permissionJson.find("permissionName") == permissionJson.end() ||
                !permissionJson.at("permissionName").is_string() ||
                permissionJson.find("grantStatus") == permissionJson.end() ||
                !permissionJson.at("grantStatus").is_number() ||
                permissionJson.find("grantFlag") == permissionJson.end() ||
                !permissionJson.at("grantFlag").is_number()) {
                continue;
            }
            permissionJson.at("permissionName").get_to(permission.permissionName);
            permissionJson.at("grantStatus").get_to(permission.grantStatus);
            permissionJson.at("grantFlag").get_to(permission.grantFlag);
        }
    }
}

void BaseRemoteCommand::FromHapTokenInfoJson(const nlohmann::json& hapTokenJson,
    HapTokenInfoForSync& hapTokenInfo)
{
    FromHapTokenBasicInfoJson(hapTokenJson, hapTokenInfo.baseInfo);
    if (hapTokenInfo.baseInfo.tokenID == 0) {
        ACCESSTOKEN_LOG_ERROR(LABEL, "Hap token basic info is error.");
        return;
    }
    FromPermStateListJson(hapTokenJson, hapTokenInfo.permStateList);
}

void BaseRemoteCommand::FromNativeTokenInfoJson(const nlohmann::json& nativeTokenJson,
    NativeTokenInfoBase& nativeTokenInfo)
{
    if (nativeTokenJson.find("processName") != nativeTokenJson.end() && nativeTokenJson.at("processName").is_string()) {
        nativeTokenInfo.processName = nativeTokenJson.at("processName").get<std::string>();
    }
    if (nativeTokenJson.find("apl") != nativeTokenJson.end() && nativeTokenJson.at("apl").is_number()) {
        int apl = nativeTokenJson.at("apl").get<int>();
        if (DataValidator::IsAplNumValid(apl)) {
            nativeTokenInfo.apl = static_cast<ATokenAplEnum>(apl);
        }
    }
    if (nativeTokenJson.find("version") != nativeTokenJson.end() && nativeTokenJson.at("version").is_number()) {
        nativeTokenInfo.ver = (unsigned)nativeTokenJson.at("version").get<int32_t>();
    }
    if (nativeTokenJson.find("tokenId") != nativeTokenJson.end() && nativeTokenJson.at("tokenId").is_number()) {
        nativeTokenInfo.tokenID = (unsigned)nativeTokenJson.at("tokenId").get<int32_t>();
    }
    if (nativeTokenJson.find("tokenAttr") != nativeTokenJson.end() && nativeTokenJson.at("tokenAttr").is_number()) {
        nativeTokenInfo.tokenAttr = (unsigned)nativeTokenJson.at("tokenAttr").get<int32_t>();
    }
    if (nativeTokenJson.find("dcaps") != nativeTokenJson.end() && nativeTokenJson.at("dcaps").is_array()
        && !nativeTokenJson.at("dcaps").empty() && (nativeTokenJson.at("dcaps"))[0].is_string()) {
        nativeTokenInfo.dcap = nativeTokenJson.at("dcaps").get<std::vector<std::string>>();
    }
    if (nativeTokenJson.find("nativeAcls") != nativeTokenJson.end() && nativeTokenJson.at("nativeAcls").is_array()
        && !nativeTokenJson.at("nativeAcls").empty() && (nativeTokenJson.at("nativeAcls"))[0].is_string()) {
        nativeTokenInfo.nativeAcls = nativeTokenJson.at("nativeAcls").get<std::vector<std::string>>();
    }

    FromPermStateListJson(nativeTokenJson, nativeTokenInfo.permStateList);
}
}  // namespace AccessToken
}  // namespace Security
}  // namespace OHOS
