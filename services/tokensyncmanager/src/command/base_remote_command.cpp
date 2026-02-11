/*
 * Copyright (c) 2022-2026 Huawei Device Co., Ltd.
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

#include "accesstoken_common_log.h"
#include "data_validator.h"
#include "device_info.h"
#include "device_info_manager.h"
#include "parcel_utils.h"

namespace OHOS {
namespace Security {
namespace AccessToken {
namespace {
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
static const std::string JSON_APPID = "appID";
static const std::string JSON_DEVICEID = "deviceID";
static const std::string JSON_APL = "apl";
static const std::string DEFAULT_VALUE = "0";
}

void BaseRemoteCommand::FromRemoteProtocolJson(const CJson* jsonObject)
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

CJsonUnique BaseRemoteCommand::ToRemoteProtocolJson()
{
    CJsonUnique j = CreateJson();
    AddStringToJson(j, "commandName", remoteProtocol_.commandName);
    AddStringToJson(j, "uniqueId", remoteProtocol_.uniqueId);
    AddIntToJson(j, "requestVersion", remoteProtocol_.requestVersion);
    AddStringToJson(j, "srcDeviceId", remoteProtocol_.srcDeviceId);
    AddStringToJson(j, "srcDeviceLevel", remoteProtocol_.srcDeviceLevel);
    AddStringToJson(j, "dstDeviceId", remoteProtocol_.dstDeviceId);
    AddStringToJson(j, "dstDeviceLevel", remoteProtocol_.dstDeviceLevel);
    AddIntToJson(j, "statusCode", remoteProtocol_.statusCode);
    AddStringToJson(j, "message", remoteProtocol_.message);
    AddIntToJson(j, "responseVersion", remoteProtocol_.responseVersion);
    AddStringToJson(j, "responseDeviceId", remoteProtocol_.responseDeviceId);
    return j;
}

CJsonUnique BaseRemoteCommand::ToNativeTokenInfoJson(const NativeTokenInfoBase& tokenInfo)
{
    CJsonUnique permStatesJson = CreateJsonArray();
    for (const auto& permState : tokenInfo.permStateList) {
        CJsonUnique permStateJson = CreateJson();
        ToPermStateJson(permStateJson.get(), permState);
        AddObjToArray(permStatesJson, permStateJson);
    }
    CJsonUnique dcapsJson = CreateJsonArray();
    for (const auto& item : tokenInfo.dcap) {
        CJsonUnique dcapJson = CreateJsonString(item.c_str());
        AddObjToArray(dcapsJson.get(), dcapJson.get());
    }
    CJsonUnique nativeAclsJson = CreateJsonArray();
    for (const auto& item : tokenInfo.nativeAcls) {
        CJsonUnique nativeAclJson = CreateJsonString(item.c_str());
        AddObjToArray(nativeAclsJson.get(), nativeAclJson.get());
    }
    CJsonUnique nativeTokenJson = CreateJson();
    AddStringToJson(nativeTokenJson, "processName", tokenInfo.processName);
    AddIntToJson(nativeTokenJson, "apl", tokenInfo.apl);
    AddUnsignedIntToJson(nativeTokenJson, "version", tokenInfo.ver);
    AddUnsignedIntToJson(nativeTokenJson, "tokenId", tokenInfo.tokenID);
    AddUnsignedIntToJson(nativeTokenJson, "tokenAttr", tokenInfo.tokenAttr);
    AddObjToJson(nativeTokenJson, "dcaps", dcapsJson);
    AddObjToJson(nativeTokenJson, "nativeAcls", nativeAclsJson);
    AddObjToJson(nativeTokenJson, "permState", permStatesJson);
    return nativeTokenJson;
}

void BaseRemoteCommand::ToPermStateJson(CJson* permStateJson, const PermissionStatus& state)
{
    AddStringToJson(permStateJson, "permissionName", state.permissionName);
    AddIntToJson(permStateJson, "grantStatus", state.grantStatus);
    AddUnsignedIntToJson(permStateJson, "grantFlag", state.grantFlag);

    // Compatible with old version data formats
    AddBoolToJson(permStateJson, "isGeneral", true);
    CJsonUnique grantConfigJson = CreateJsonArray();
    CJsonUnique grantConfigJsonItem = CreateJson();
    AddStringToJson(grantConfigJsonItem, "resDeviceID", DEFAULT_VALUE);
    AddIntToJson(grantConfigJsonItem, "grantStatus", state.grantStatus);
    AddUnsignedIntToJson(grantConfigJsonItem, "grantFlags", state.grantFlag);
    AddObjToArray(grantConfigJson, grantConfigJsonItem);
    AddObjToJson(permStateJson, "grantConfig", grantConfigJson.get());
}

CJsonUnique BaseRemoteCommand::ToHapTokenInfosJson(const HapTokenInfoForSync& tokenInfo)
{
    CJsonUnique permStatesJson = CreateJsonArray();
    for (const auto& permState : tokenInfo.permStateList) {
        CJsonUnique permStateJson = CreateJson();
        ToPermStateJson(permStateJson.get(), permState);
        AddObjToArray(permStatesJson, permStateJson);
    }
    CJsonUnique hapTokensJson = CreateJson();
    AddIntToJson(hapTokensJson, JSON_VERSION, tokenInfo.baseInfo.ver);
    AddUnsignedIntToJson(hapTokensJson, JSON_TOKENID, tokenInfo.baseInfo.tokenID);
    AddUnsignedIntToJson(hapTokensJson, JSON_TOKEN_ATTR, tokenInfo.baseInfo.tokenAttr);
    AddIntToJson(hapTokensJson, JSON_USERID, tokenInfo.baseInfo.userID);
    AddStringToJson(hapTokensJson, JSON_BUNDLE_NAME, tokenInfo.baseInfo.bundleName);
    AddIntToJson(hapTokensJson, JSON_INST_INDEX, tokenInfo.baseInfo.instIndex);
    AddIntToJson(hapTokensJson, JSON_DLP_TYPE, tokenInfo.baseInfo.dlpType);
    AddObjToJson(hapTokensJson, "permState", permStatesJson);
    AddStringToJson(hapTokensJson, JSON_DEVICEID, DEFAULT_VALUE);
    AddStringToJson(hapTokensJson, JSON_APPID, DEFAULT_VALUE);
    AddIntToJson(hapTokensJson, JSON_APL, APL_NORMAL);
    return hapTokensJson;
}

void BaseRemoteCommand::FromHapTokenBasicInfoJson(const CJson* hapTokenJson,
    HapTokenInfo& hapTokenBasicInfo)
{
    int32_t ver;
    GetIntFromJson(hapTokenJson, JSON_VERSION, ver);
    hapTokenBasicInfo.ver = (char)ver;
    GetUnsignedIntFromJson(hapTokenJson, JSON_TOKENID, hapTokenBasicInfo.tokenID);
    GetUnsignedIntFromJson(hapTokenJson, JSON_TOKEN_ATTR, hapTokenBasicInfo.tokenAttr);
    GetIntFromJson(hapTokenJson, JSON_USERID, hapTokenBasicInfo.userID);
    GetStringFromJson(hapTokenJson, JSON_BUNDLE_NAME, hapTokenBasicInfo.bundleName);
    GetIntFromJson(hapTokenJson, JSON_INST_INDEX, hapTokenBasicInfo.instIndex);
    GetIntFromJson(hapTokenJson, JSON_DLP_TYPE, hapTokenBasicInfo.dlpType);
}

bool BaseRemoteCommand::FromPermStateJson(const CJson* permStateJson, PermissionStatus& permission)
{
    if (!GetStringFromJson(permStateJson, "permissionName", permission.permissionName)) {
        return false;
    }

    CJson* jsonObjTmp = cJSON_GetObjectItemCaseSensitive(permStateJson, "grantStatus");
    if (jsonObjTmp != nullptr) {
        if (!GetIntFromJson(permStateJson, "grantStatus", permission.grantStatus)) {
            return false;
        }
        if (!GetUnsignedIntFromJson(permStateJson, "grantFlag", permission.grantFlag)) {
            return false;
        }
        return true;
    }

    // Compatible with old version data formats
    CJson* grantConfig = GetArrayFromJson(permStateJson, "grantConfig");
    if (grantConfig == nullptr) {
        return false;
    }
    CJson* grantConfigItem = cJSON_GetArrayItem(grantConfig, 0);
    if (grantConfigItem == nullptr) {
        return false;
    }
    if (!GetIntFromJson(grantConfigItem, "grantStatus", permission.grantStatus)) {
        return false;
    }
    if (!GetUnsignedIntFromJson(grantConfigItem, "grantFlags", permission.grantFlag)) {
        return false;
    }
    return true;
}

void BaseRemoteCommand::FromPermStateListJson(const CJson* hapTokenJson,
    std::vector<PermissionStatus>& permStateList)
{
    CJson* jsonObjTmp = GetArrayFromJson(hapTokenJson, "permState");
    if (jsonObjTmp != nullptr) {
        int len = cJSON_GetArraySize(jsonObjTmp);
        if (len > MAX_PERMLIST_SIZE) {
            LOGE(ATM_DOMAIN, ATM_TAG, "PermState list size %d exceeds MAX_PERMLIST_SIZE %d", len, MAX_PERMLIST_SIZE);
            return;
        }
        for (int i = 0; i < len; i++) {
            CJson* permissionJson = cJSON_GetArrayItem(jsonObjTmp, i);
            PermissionStatus permission;
            if (!FromPermStateJson(permissionJson, permission)) {
                continue;
            }
            permStateList.emplace_back(permission);
        }
    }
}

void BaseRemoteCommand::FromHapTokenInfoJson(const CJson* hapTokenJson,
    HapTokenInfoForSync& hapTokenInfo)
{
    FromHapTokenBasicInfoJson(hapTokenJson, hapTokenInfo.baseInfo);
    if (hapTokenInfo.baseInfo.tokenID == 0) {
        LOGE(ATM_DOMAIN, ATM_TAG, "Hap token basic info is error.");
        return;
    }
    FromPermStateListJson(hapTokenJson, hapTokenInfo.permStateList);
}

void BaseRemoteCommand::FromNativeTokenInfoJson(const CJson* nativeTokenJson,
    NativeTokenInfoBase& nativeTokenInfo)
{
    GetStringFromJson(nativeTokenJson, "processName", nativeTokenInfo.processName);
    int32_t apl;
    GetIntFromJson(nativeTokenJson, "apl", apl);
    if (DataValidator::IsAplNumValid(apl)) {
        nativeTokenInfo.apl = static_cast<ATokenAplEnum>(apl);
    }
    int32_t ver;
    GetIntFromJson(nativeTokenJson, JSON_VERSION, ver);
    nativeTokenInfo.ver = (char)ver;
    GetUnsignedIntFromJson(nativeTokenJson, "tokenId", nativeTokenInfo.tokenID);
    GetUnsignedIntFromJson(nativeTokenJson, "tokenAttr", nativeTokenInfo.tokenAttr);

    CJson* dcapsJson = GetArrayFromJson(nativeTokenJson, "dcaps");
    if (dcapsJson != nullptr) {
        CJson* dcap = nullptr;
        std::vector<std::string> dcaps;
        cJSON_ArrayForEach(dcap, dcapsJson) {
            std::string item = cJSON_GetStringValue(dcap);
            dcaps.push_back(item);
        }
        nativeTokenInfo.dcap = dcaps;
    }
    CJson* nativeAclsJson = GetArrayFromJson(nativeTokenJson, "nativeAcls");
    if (nativeAclsJson != nullptr) {
        CJson* acl = nullptr;
        std::vector<std::string> nativeAcls;
        cJSON_ArrayForEach(acl, nativeAclsJson) {
            std::string item = cJSON_GetStringValue(acl);
            nativeAcls.push_back(item);
        }
        nativeTokenInfo.nativeAcls = nativeAcls;
    }
    FromPermStateListJson(nativeTokenJson, nativeTokenInfo.permStateList);
}

bool BaseRemoteCommand::CheckDeviceIdValid(const std::string& deviceId)
{
    DeviceInfo devInfo;
    bool result = DeviceInfoManager::GetInstance().GetDeviceInfo(deviceId, DeviceIdType::UNKNOWN, devInfo);
    if (!result) {
        LOGI(ATM_DOMAIN, ATM_TAG, "Failed to get remote uniqueDeviceId.");
        remoteProtocol_.statusCode = Constant::FAILURE_BUT_CAN_RETRY;
        return false;
    }

    std::string uniqueDeviceId = devInfo.GetDeviceId().GetUniqueDeviceId();
    if (uniqueDeviceId != rawDeviceId_) {
        remoteProtocol_.statusCode = Constant::FAILURE;
        remoteProtocol_.message = Constant::COMMAND_RESULT_FAILED;
        return false;
    }
    return true;
}
}  // namespace AccessToken
}  // namespace Security
}  // namespace OHOS
