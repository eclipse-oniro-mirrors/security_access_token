/*
 * Copyright (c) 2024 Huawei Device Co., Ltd.
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
#include "json_parse_loader.h"

#include <cstdio>
#include <fcntl.h>
#include <memory>
#include <set>
#include <sys/stat.h>
#include <sys/types.h>
#include <unistd.h>

#include "access_token_error.h"
#include "accesstoken_common_log.h"
#include "cjson_utils.h"
#ifdef CUSTOMIZATION_CONFIG_POLICY_ENABLE
#include "config_policy_utils.h"
#endif
#include "data_validator.h"

namespace OHOS {
namespace Security {
namespace AccessToken {
namespace {
constexpr int32_t MAX_NATIVE_CONFIG_FILE_SIZE = 5 * 1024 * 1024; // 5M
constexpr size_t BUFFER_SIZE = 1024;
constexpr uint64_t FD_TAG = 0xD005A01;

#ifdef CUSTOMIZATION_CONFIG_POLICY_ENABLE
static constexpr const char* ACCESSTOKEN_CONFIG_FILE = "/etc/access_token/accesstoken_config.json";
static constexpr const char* PERMISSION_MANAGER_BUNDLE_NAME_KEY = "permission_manager_bundle_name";
static constexpr const char* GRANT_ABILITY_NAME_KEY = "grant_ability_name";
static constexpr const char* GRANT_SERVICE_ABILITY_NAME_KEY = "grant_service_ability_name";
static constexpr const char* PERMISSION_STATE_SHEET_ABILITY_NAME_KEY = "permission_state_sheet_ability_name";
static constexpr const char* GLOBAL_SWITCH_SHEET_ABILITY_NAME_KEY = "global_switch_sheet_ability_name";
static constexpr const char* TEMP_PERM_CANCLE_TIME_KEY = "temp_perm_cencle_time";
static constexpr const char* APPLICATION_SETTING_ABILITY_NAME_KEY = "application_setting_ability_name";

static constexpr const char* RECORD_SIZE_MAXIMUM_KEY = "permission_used_record_size_maximum";
static constexpr const char* RECORD_AGING_TIME_KEY = "permission_used_record_aging_time";
static constexpr const char* GLOBAL_DIALOG_BUNDLE_NAME_KEY = "global_dialog_bundle_name";
static constexpr const char* GLOBAL_DIALOG_ABILITY_NAME_KEY = "global_dialog_ability_name";

static constexpr const char* SEND_REQUEST_REPEAT_TIMES_KEY = "send_request_repeat_times";
#endif // CUSTOMIZATION_CONFIG_POLICY_ENABLE

// native_token.json
static const char* NATIVE_TOKEN_CONFIG_FILE = "/data/service/el0/access_token/nativetoken.json";
static const char* JSON_PROCESS_NAME = "processName";
static const char* JSON_APL = "APL";
static const char* JSON_VERSION = "version";
static const char* JSON_TOKEN_ID = "tokenId";
static const char* JSON_TOKEN_ATTR = "tokenAttr";
static const char* JSON_DCAPS = "dcaps";
static const char* JSON_PERMS = "permissions";
static const char* JSON_ACLS = "nativeAcls";
static const int32_t MAX_DCAPS_NUM = 10 * 1024;
static const int32_t MAX_REQ_PERM_NUM = 10 * 1024;

// dlp json
static const char* CLONE_PERMISSION_CONFIG_FILE = "/system/etc/dlp_permission/clone_app_permission.json";
}

int32_t ConfigPolicLoader::ReadCfgFile(const std::string& file, std::string& rawData)
{
    char filePath[PATH_MAX] = {0};
    if (realpath(file.c_str(), filePath) == nullptr) {
        return ERR_FILE_OPERATE_FAILED;
    }
    int32_t fd = open(filePath, O_RDONLY);
    if (fd < 0) {
        LOGE(ATM_DOMAIN, ATM_TAG, "Open failed errno %{public}d.", errno);
        return ERR_FILE_OPERATE_FAILED;
    }
    fdsan_exchange_owner_tag(fd, 0, FD_TAG);
    struct stat statBuffer;

    if (fstat(fd, &statBuffer) != 0) {
        LOGE(ATM_DOMAIN, ATM_TAG, "Fstat failed.");
        fdsan_close_with_tag(fd, FD_TAG);
        return ERR_FILE_OPERATE_FAILED;
    }

    if (statBuffer.st_size == 0) {
        LOGE(ATM_DOMAIN, ATM_TAG, "Config file size is invalid.");
        fdsan_close_with_tag(fd, FD_TAG);
        return ERR_PARAM_INVALID;
    }
    if (statBuffer.st_size > MAX_NATIVE_CONFIG_FILE_SIZE) {
        LOGE(ATM_DOMAIN, ATM_TAG, "Config file size is too large.");
        fdsan_close_with_tag(fd, FD_TAG);
        return ERR_OVERSIZE;
    }
    rawData.reserve(statBuffer.st_size);

    char buff[BUFFER_SIZE] = { 0 };
    ssize_t readLen = 0;
    while ((readLen = read(fd, buff, BUFFER_SIZE)) > 0) {
        rawData.append(buff, readLen);
    }
    fdsan_close_with_tag(fd, FD_TAG);
    if (readLen == 0) {
        return RET_SUCCESS;
    }
    return ERR_FILE_OPERATE_FAILED;
}

bool ConfigPolicLoader::IsDirExsit(const std::string& file)
{
    if (file.empty()) {
        LOGE(ATM_DOMAIN, ATM_TAG, "File path is empty");
        return false;
    }

    struct stat buf;
    if (stat(file.c_str(), &buf) != 0) {
        LOGE(ATM_DOMAIN, ATM_TAG, "Get file attributes failed, errno %{public}d.", errno);
        return false;
    }

    if (!S_ISDIR(buf.st_mode)) {
        LOGE(ATM_DOMAIN, ATM_TAG, "File mode is not directory.");
        return false;
    }

    return true;
}

#ifdef CUSTOMIZATION_CONFIG_POLICY_ENABLE
void ConfigPolicLoader::GetConfigFilePathList(std::vector<std::string>& pathList)
{
    CfgDir *dirs = GetCfgDirList(); // malloc a CfgDir point, need to free later
    if (dirs == nullptr) {
        LOGE(ATM_DOMAIN, ATM_TAG, "Can't get cfg file path.");
        return;
    }

    for (const auto& path : dirs->paths) {
        if ((path == nullptr) || (!IsDirExsit(path))) {
            continue;
        }

        LOGI(ATM_DOMAIN, ATM_TAG, "Accesstoken cfg dir: %{public}s.", path);
        pathList.emplace_back(path);
    }

    FreeCfgDirList(dirs); // free
}

bool GetAtCfgFromJson(const CJson* j, AccessTokenServiceConfig& a)
{
    if (!GetStringFromJson(j, PERMISSION_MANAGER_BUNDLE_NAME_KEY, a.grantBundleName)) {
        return false;
    }

    if (!GetStringFromJson(j, GRANT_ABILITY_NAME_KEY, a.grantAbilityName)) {
        return false;
    }

    if (!GetStringFromJson(j, GRANT_SERVICE_ABILITY_NAME_KEY, a.grantAbilityName)) {
        return false;
    }

    if (!GetStringFromJson(j, PERMISSION_STATE_SHEET_ABILITY_NAME_KEY, a.permStateAbilityName)) {
        return false;
    }

    if (!GetStringFromJson(j, GLOBAL_SWITCH_SHEET_ABILITY_NAME_KEY, a.globalSwitchAbilityName)) {
        return false;
    }

    if (!GetIntFromJson(j, TEMP_PERM_CANCLE_TIME_KEY, a.cancelTime)) {
        return false;
    }

    GetStringFromJson(j, APPLICATION_SETTING_ABILITY_NAME_KEY, a.applicationSettingAbilityName);
    return true;
}

bool GetPrivacyCfgFromJson(const CJson* j, PrivacyServiceConfig& p)
{
    if (!GetIntFromJson(j, RECORD_SIZE_MAXIMUM_KEY, p.sizeMaxImum)) {
        return false;
    }

    if (!GetIntFromJson(j, RECORD_AGING_TIME_KEY, p.agingTime)) {
        return false;
    }

    if (!GetStringFromJson(j, GLOBAL_DIALOG_BUNDLE_NAME_KEY, p.globalDialogBundleName)) {
        return false;
    }

    if (!GetStringFromJson(j, GLOBAL_DIALOG_ABILITY_NAME_KEY, p.globalDialogAbilityName)) {
        return false;
    }
    return true;
}

bool GetTokenSyncCfgFromJson(const CJson* j, TokenSyncServiceConfig& t)
{
    if (!GetIntFromJson(j, SEND_REQUEST_REPEAT_TIMES_KEY, t.sendRequestRepeatTimes)) {
        return false;
    }
    return true;
}

bool ConfigPolicLoader::GetConfigValueFromFile(const ServiceType& type, const std::string& fileContent,
    AccessTokenConfigValue& config)
{
    CJsonUnique jsonRes = CreateJsonFromString(fileContent);
    if (jsonRes == nullptr) {
        LOGE(ATM_DOMAIN, ATM_TAG, "JsonRes is invalid.");
        return false;
    }

    if (type == ServiceType::ACCESSTOKEN_SERVICE) {
        CJson *atJson = GetObjFromJson(jsonRes, "accesstoken");
        return GetAtCfgFromJson(atJson, config.atConfig);
    } else if (type == ServiceType::PRIVACY_SERVICE) {
        CJson *prJson = GetObjFromJson(jsonRes, "privacy");
        return GetPrivacyCfgFromJson(prJson, config.pConfig);
    }
    CJson *toSyncJson = GetObjFromJson(jsonRes, "tokensync");
    return GetTokenSyncCfgFromJson(toSyncJson, config.tsConfig);
}
#endif // CUSTOMIZATION_CONFIG_POLICY_ENABLE

bool ConfigPolicLoader::GetConfigValue(const ServiceType& type, AccessTokenConfigValue& config)
{
    bool successFlag = false;
#ifdef CUSTOMIZATION_CONFIG_POLICY_ENABLE
    std::vector<std::string> pathList;
    GetConfigFilePathList(pathList);

    for (const auto& path : pathList) {
        std::string filePath = path + ACCESSTOKEN_CONFIG_FILE;
        std::string fileContent;
        int32_t res = ReadCfgFile(filePath, fileContent);
        if (res != 0) {
            continue;
        }

        if (GetConfigValueFromFile(type, fileContent, config)) {
            LOGI(ATM_DOMAIN, ATM_TAG, "Get valid config value from file [%{public}s]!", filePath.c_str());
            successFlag = true;
            break; // once get the config value, break the loop
        }
    }
#endif // CUSTOMIZATION_CONFIG_POLICY_ENABLE
    return successFlag;
}

static int32_t NativeReqPermsGet(const CJson* j, std::vector<PermissionStatus>& permStateList)
{
    CJson *permJson = GetArrayFromJson(j, JSON_PERMS);
    if (permJson == nullptr) {
        LOGE(ATM_DOMAIN, ATM_TAG, "JSON_PERMS is invalid.");
        return ERR_PARAM_INVALID;
    }
    int32_t len = cJSON_GetArraySize(permJson);
    if (len > MAX_REQ_PERM_NUM) {
        LOGE(ATM_DOMAIN, ATM_TAG, "Permission num oversize.");
        return ERR_OVERSIZE;
    }
    std::set<std::string> permRes;
    for (int32_t i = 0; i < len; i++) {
        std::string permReq = cJSON_GetStringValue(cJSON_GetArrayItem(permJson, i));
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

static ATokenTypeEnum GetTokenIdTypeEnum(AccessTokenID id)
{
    AccessTokenIDInner *idInner = reinterpret_cast<AccessTokenIDInner *>(&id);
    return static_cast<ATokenTypeEnum>(idInner->type);
}

static void GetSingleNativeTokenFromJson(const CJson* j,  NativeTokenInfoBase& native)
{
    NativeTokenInfoBase info;
    int32_t aplNum = 0;
    if (!GetIntFromJson(j, JSON_APL, aplNum) || !DataValidator::IsAplNumValid(aplNum)) {
        return;
    }
    info.apl = static_cast<ATokenAplEnum>(aplNum);
    int32_t ver;
    GetIntFromJson(j, JSON_VERSION, ver);
    info.ver = (uint8_t)ver;
    GetUnsignedIntFromJson(j, JSON_TOKEN_ID, info.tokenID);
    if ((info.ver != DEFAULT_TOKEN_VERSION) || (info.tokenID == 0)) {
        return;
    }
    ATokenTypeEnum type = GetTokenIdTypeEnum(info.tokenID);
    if ((type != TOKEN_NATIVE) && (type != TOKEN_SHELL)) {
        return;
    }
    if (!GetUnsignedIntFromJson(j, JSON_TOKEN_ATTR, info.tokenAttr)) {
        return;
    }
    CJson *dcapsJson = GetArrayFromJson(j, JSON_DCAPS);
    CJson *aclsJson = GetArrayFromJson(j, JSON_ACLS);
    if ((dcapsJson == nullptr) || (aclsJson == nullptr)) {
        return;
    }
    int32_t dcapLen = cJSON_GetArraySize(dcapsJson);
    int32_t aclLen = cJSON_GetArraySize(aclsJson);
    if ((dcapLen > MAX_DCAPS_NUM) || (aclLen > MAX_REQ_PERM_NUM)) {
        LOGE(ATM_DOMAIN, ATM_TAG, "Native dcap oversize.");
        return;
    }
    for (int32_t i = 0; i < dcapLen; i++) {
        std::string item = cJSON_GetStringValue(cJSON_GetArrayItem(dcapsJson, i));
        info.dcap.push_back(item);
    }
    for (int i = 0; i < aclLen; i++) {
        std::string item = cJSON_GetStringValue(cJSON_GetArrayItem(aclsJson, i));
        info.nativeAcls.push_back(item);
    }

    if (NativeReqPermsGet(j, info.permStateList) != RET_SUCCESS) {
        return;
    }

    if (!GetStringFromJson(j, JSON_PROCESS_NAME, info.processName) ||
        !DataValidator::IsProcessNameValid(info.processName)) {
        return;
    }
    native = info;
}

bool ConfigPolicLoader::ParserNativeRawData(
    const std::string& nativeRawData, std::vector<NativeTokenInfoBase>& tokenInfos)
{
    CJsonUnique jsonRes = CreateJsonFromString(nativeRawData);
    if (jsonRes == nullptr) {
        LOGE(ATM_DOMAIN, ATM_TAG, "JsonRes is invalid.");
        return false;
    }
    int32_t len = cJSON_GetArraySize(jsonRes.get());
    for (int32_t i = 0; i < len; i++) {
        cJSON *item = cJSON_GetArrayItem(jsonRes.get(), i);
        NativeTokenInfoBase token;
        GetSingleNativeTokenFromJson(item, token);
        if (!token.processName.empty()) {
            tokenInfos.emplace_back(token);
        }
    }
    return true;
}

int32_t ConfigPolicLoader::GetAllNativeTokenInfo(std::vector<NativeTokenInfoBase>& tokenInfos)
{
    std::string nativeRawData;
    int32_t ret = ReadCfgFile(NATIVE_TOKEN_CONFIG_FILE, nativeRawData);
    if (ret != RET_SUCCESS) {
        LOGE(ATM_DOMAIN, ATM_TAG,
            "Read native token json file failed, err = %{public}d.", ret);
        return ret;
    }
    if (!ParserNativeRawData(nativeRawData, tokenInfos)) {
        LOGE(ATM_DOMAIN, ATM_TAG, "ParserNativeRawData failed.");
        return ERR_PRASE_RAW_DATA_FAILED;
    }
    return RET_SUCCESS;
}

static void JsonFromPermissionDlpMode(const CJson *j, PermissionDlpMode& p)
{
    if (!GetStringFromJson(j, "name", p.permissionName)) {
        return;
    }
    if (!DataValidator::IsProcessNameValid(p.permissionName)) {
        return;
    }

    std::string dlpModeStr;
    if (!GetStringFromJson(j, "dlpGrantRange", dlpModeStr)) {
        return;
    }
    if (dlpModeStr == "all") {
        p.dlpMode = DLP_PERM_ALL;
        return;
    }
    if (dlpModeStr == "full_control") {
        p.dlpMode = DLP_PERM_FULL_CONTROL;
        return;
    }
    p.dlpMode = DLP_PERM_NONE;
    return;
}

bool ConfigPolicLoader::ParserDlpPermsRawData(
    const std::string& dlpPermsRawData, std::vector<PermissionDlpMode>& dlpPerms)
{
    CJsonUnique jsonRes = CreateJsonFromString(dlpPermsRawData);
    if (jsonRes == nullptr) {
        LOGE(ATM_DOMAIN, ATM_TAG, "JsonRes is invalid.");
        return false;
    }

    cJSON *dlpPermTokenJson = GetArrayFromJson(jsonRes.get(), "dlpPermissions");
    if ((dlpPermTokenJson != nullptr)) {
        CJson *j = nullptr;
        std::vector<PermissionDlpMode> dlpPermissions;
        cJSON_ArrayForEach(j, dlpPermTokenJson) {
            PermissionDlpMode p;
            JsonFromPermissionDlpMode(j, p);
            dlpPerms.emplace_back(p);
        }
    }
    return true;
}

int32_t ConfigPolicLoader::GetDlpPermissions(std::vector<PermissionDlpMode>& dlpPerms)
{
    std::string dlpPermsRawData;
    int32_t ret = ReadCfgFile(CLONE_PERMISSION_CONFIG_FILE, dlpPermsRawData);
    if (ret != RET_SUCCESS) {
        LOGE(ATM_DOMAIN, ATM_TAG,
            "Read(%{public}s) failed, err = %{public}d.", CLONE_PERMISSION_CONFIG_FILE, ret);
        return ret;
    }
    if (!ParserDlpPermsRawData(dlpPermsRawData, dlpPerms)) {
        LOGE(ATM_DOMAIN, ATM_TAG, "ParserDlpPermsRawData failed.");
        return ERR_PRASE_RAW_DATA_FAILED;
    }
    return RET_SUCCESS;
}

extern "C" {
void* Create()
{
    return reinterpret_cast<void*>(new ConfigPolicLoader);
}

void Destroy(void* loaderPtr)
{
    ConfigPolicyLoaderInterface* loader = reinterpret_cast<ConfigPolicyLoaderInterface*>(loaderPtr);
    if (loader != nullptr) {
        delete loader;
    }
}
}
} // namespace AccessToken
} // namespace Security
} // namespace OHOS
