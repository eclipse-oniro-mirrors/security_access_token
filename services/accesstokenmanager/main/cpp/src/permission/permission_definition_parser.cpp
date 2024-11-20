/*
 * Copyright (c) 2023 Huawei Device Co., Ltd.
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
#include "permission_definition_parser.h"

#include <fcntl.h>
#include <memory>
#include <sys/stat.h>
#include <sys/types.h>
#include <unistd.h>

#include "accesstoken_log.h"
#include "access_token.h"
#include "access_token_error.h"
#include "accesstoken_info_manager.h"
#include "data_validator.h"
#include "hisysevent_adapter.h"
#include "json_parser.h"
#include "permission_def.h"
#include "permission_definition_cache.h"
#include "securec.h"

namespace OHOS {
namespace Security {
namespace AccessToken {
namespace {
std::recursive_mutex g_instanceMutex;
static const int32_t EXTENSION_PERMISSION_ID = 0;
constexpr const char* PERMISSION_NAME = "name";
constexpr const char* PERMISSION_GRANT_MODE = "grantMode";
constexpr const char* PERMISSION_AVAILABLE_LEVEL = "availableLevel";
constexpr const char* PERMISSION_AVAILABLE_TYPE = "availableType";
constexpr const char* PERMISSION_PROVISION_ENABLE = "provisionEnable";
constexpr const char* PERMISSION_DISTRIBUTED_SCENE_ENABLE = "distributedSceneEnable";
constexpr const char* PERMISSION_LABEL = "label";
constexpr const char* PERMISSION_DESCRIPTION = "description";
constexpr const char* AVAILABLE_TYPE_NORMAL_HAP = "NORMAL";
constexpr const char* AVAILABLE_TYPE_SYSTEM_HAP = "SYSTEM";
constexpr const char* AVAILABLE_TYPE_MDM = "MDM";
constexpr const char* AVAILABLE_TYPE_SYSTEM_AND_MDM = "SYSTEM_AND_MDM";
constexpr const char* AVAILABLE_TYPE_SERVICE = "SERVICE";
constexpr const char* AVAILABLE_TYPE_ENTERPRISE_NORMAL = "ENTERPRISE_NORMAL";
constexpr const char* AVAILABLE_LEVEL_NORMAL = "normal";
constexpr const char* AVAILABLE_LEVEL_SYSTEM_BASIC = "system_basic";
constexpr const char* AVAILABLE_LEVEL_SYSTEM_CORE = "system_core";
constexpr const char* PERMISSION_GRANT_MODE_SYSTEM_GRANT = "system_grant";
constexpr const char* SYSTEM_GRANT_DEFINE_PERMISSION = "systemGrantPermissions";
constexpr const char* USER_GRANT_DEFINE_PERMISSION = "userGrantPermissions";
constexpr const char* DEFINE_PERMISSION_FILE = "/system/etc/access_token/permission_definitions.json";
}

static bool GetPermissionApl(const std::string &apl, AccessToken::ATokenAplEnum& aplNum)
{
    if (apl == AVAILABLE_LEVEL_SYSTEM_CORE) {
        aplNum = AccessToken::ATokenAplEnum::APL_SYSTEM_CORE;
        return true;
    }
    if (apl == AVAILABLE_LEVEL_SYSTEM_BASIC) {
        aplNum = AccessToken::ATokenAplEnum::APL_SYSTEM_BASIC;
        return true;
    }
    if (apl == AVAILABLE_LEVEL_NORMAL) {
        aplNum = AccessToken::ATokenAplEnum::APL_NORMAL;
        return true;
    }
    LOGE(AT_DOMAIN, AT_TAG, "Apl: %{public}s is invalid.", apl.c_str());
    return false;
}

static bool GetPermissionAvailableType(const std::string &availableType, AccessToken::ATokenAvailableTypeEnum& typeNum)
{
    if (availableType == AVAILABLE_TYPE_NORMAL_HAP) {
        typeNum = AccessToken::ATokenAvailableTypeEnum::NORMAL;
        return true;
    }
    if (availableType == AVAILABLE_TYPE_SYSTEM_HAP) {
        typeNum = AccessToken::ATokenAvailableTypeEnum::SYSTEM;
        return true;
    }
    if (availableType == AVAILABLE_TYPE_MDM) {
        typeNum = AccessToken::ATokenAvailableTypeEnum::MDM;
        return true;
    }
    if (availableType == AVAILABLE_TYPE_SYSTEM_AND_MDM) {
        typeNum = AccessToken::ATokenAvailableTypeEnum::SYSTEM_AND_MDM;
        return true;
    }
    if (availableType == AVAILABLE_TYPE_SERVICE) {
        typeNum = AccessToken::ATokenAvailableTypeEnum::SERVICE;
        return true;
    }
    if (availableType == AVAILABLE_TYPE_ENTERPRISE_NORMAL) {
        typeNum = AccessToken::ATokenAvailableTypeEnum::ENTERPRISE_NORMAL;
        return true;
    }
    typeNum = AccessToken::ATokenAvailableTypeEnum::INVALID;
    LOGE(AT_DOMAIN, AT_TAG, "AvailableType: %{public}s is invalid.", availableType.c_str());
    return false;
}

static int32_t GetPermissionGrantMode(const std::string &mode)
{
    if (mode == PERMISSION_GRANT_MODE_SYSTEM_GRANT) {
        return AccessToken::GrantMode::SYSTEM_GRANT;
    }
    return AccessToken::GrantMode::USER_GRANT;
}

void from_json(const nlohmann::json& j, PermissionDefParseRet& result)
{
    result.isSuccessful = false;
    PermissionDef permDef;
    if (!JsonParser::GetStringFromJson(j, PERMISSION_NAME, permDef.permissionName) ||
        !DataValidator::IsProcessNameValid(permDef.permissionName)) {
        return;
    }
    std::string grantModeStr;
    if (!JsonParser::GetStringFromJson(j, PERMISSION_GRANT_MODE, grantModeStr)) {
        return;
    }
    permDef.grantMode = GetPermissionGrantMode(grantModeStr);

    std::string availableLevelStr;
    if (!JsonParser::GetStringFromJson(j, PERMISSION_AVAILABLE_LEVEL, availableLevelStr)) {
        return;
    }
    if (!GetPermissionApl(availableLevelStr, permDef.availableLevel)) {
        return;
    }

    std::string availableTypeStr;
    if (!JsonParser::GetStringFromJson(j, PERMISSION_AVAILABLE_TYPE, availableTypeStr)) {
        return;
    }
    if (!GetPermissionAvailableType(availableTypeStr, permDef.availableType)) {
        return;
    }

    if (!JsonParser::GetBoolFromJson(j, PERMISSION_PROVISION_ENABLE, permDef.provisionEnable)) {
        return;
    }
    if (!JsonParser::GetBoolFromJson(j, PERMISSION_DISTRIBUTED_SCENE_ENABLE, permDef.distributedSceneEnable)) {
        return;
    }
    permDef.bundleName = "system_ability";
    if (permDef.grantMode == AccessToken::GrantMode::SYSTEM_GRANT) {
        result.permDef = permDef;
        result.isSuccessful = true;
        return;
    }
    if (!JsonParser::GetStringFromJson(j, PERMISSION_LABEL, permDef.label)) {
        return;
    }
    if (!JsonParser::GetStringFromJson(j, PERMISSION_DESCRIPTION, permDef.description)) {
        return;
    }
    result.permDef = permDef;
    result.isSuccessful = true;
    return;
}

static bool CheckPermissionDefRules(const PermissionDef& permDef)
{
    // Extension permission support permission for service only.
    if (permDef.availableType != AccessToken::ATokenAvailableTypeEnum::SERVICE) {
        LOGD(AT_DOMAIN, AT_TAG, "%{public}s is for hap.", permDef.permissionName.c_str());
        return false;
    }
    return true;
}

int32_t PermissionDefinitionParser::GetPermissionDefList(const nlohmann::json& json, const std::string& permsRawData,
    const std::string& type, std::vector<PermissionDef>& permDefList)
{
    if ((json.find(type) == json.end()) || (!json.at(type).is_array())) {
        LOGE(AT_DOMAIN, AT_TAG, "Json is not array.");
        return ERR_PARAM_INVALID;
    }

    nlohmann::json JsonData = json.at(type).get<nlohmann::json>();
    for (auto it = JsonData.begin(); it != JsonData.end(); it++) {
        auto result = it->get<PermissionDefParseRet>();
        if (!result.isSuccessful) {
            LOGE(AT_DOMAIN, AT_TAG, "Get permission def failed.");
            return ERR_PERM_REQUEST_CFG_FAILED;
        }
        if (!CheckPermissionDefRules(result.permDef)) {
            continue;
        }
        LOGD(AT_DOMAIN, AT_TAG, "%{public}s insert.", result.permDef.permissionName.c_str());
        permDefList.emplace_back(result.permDef);
    }
    return RET_SUCCESS;
}

int32_t PermissionDefinitionParser::ParserPermsRawData(const std::string& permsRawData,
    std::vector<PermissionDef>& permDefList)
{
    nlohmann::json jsonRes = nlohmann::json::parse(permsRawData, nullptr, false);
    if (jsonRes.is_discarded()) {
        LOGE(AT_DOMAIN, AT_TAG, "JsonRes is invalid.");
        return ERR_PARAM_INVALID;
    }

    int32_t ret = GetPermissionDefList(jsonRes, permsRawData, SYSTEM_GRANT_DEFINE_PERMISSION, permDefList);
    if (ret != RET_SUCCESS) {
        LOGE(AT_DOMAIN, AT_TAG, "Get system_grant permission def list failed.");
        return ret;
    }
    LOGI(AT_DOMAIN, AT_TAG, "Get system_grant permission size=%{public}zu.", permDefList.size());
    ret = GetPermissionDefList(jsonRes, permsRawData, USER_GRANT_DEFINE_PERMISSION, permDefList);
    if (ret != RET_SUCCESS) {
        LOGE(AT_DOMAIN, AT_TAG, "Get user_grant permission def list failed.");
        return ret;
    }
    LOGI(AT_DOMAIN, AT_TAG, "Get permission size=%{public}zu.", permDefList.size());
    return RET_SUCCESS;
}

int32_t PermissionDefinitionParser::Init()
{
    LOGI(AT_DOMAIN, AT_TAG, "System permission set begin.");
    if (ready_) {
        LOGE(AT_DOMAIN, AT_TAG, " system permission has been set.");
        return RET_SUCCESS;
    }

    std::string permsRawData;
    int32_t ret = JsonParser::ReadCfgFile(DEFINE_PERMISSION_FILE, permsRawData);
    if (ret != RET_SUCCESS) {
        LOGE(AT_DOMAIN, AT_TAG, "ReadCfgFile failed.");
        ReportSysEventServiceStartError(INIT_PERM_DEF_JSON_ERROR, "ReadCfgFile fail.", ret);
        return ERR_FILE_OPERATE_FAILED;
    }
    std::vector<PermissionDef> permDefList;
    ret = ParserPermsRawData(permsRawData, permDefList);
    if (ret != RET_SUCCESS) {
        ReportSysEventServiceStartError(INIT_PERM_DEF_JSON_ERROR, "ParserPermsRawData fail.", ret);
        LOGE(AT_DOMAIN, AT_TAG, "ParserPermsRawData failed.");
        return ret;
    }

    for (const auto& perm : permDefList) {
        PermissionDefinitionCache::GetInstance().Insert(perm, EXTENSION_PERMISSION_ID);
    }
    ready_ = true;
    LOGI(AT_DOMAIN, AT_TAG, "Init ok.");
    return RET_SUCCESS;
}

PermissionDefinitionParser& PermissionDefinitionParser::GetInstance()
{
    static PermissionDefinitionParser* instance = nullptr;
    if (instance == nullptr) {
        std::lock_guard<std::recursive_mutex> lock(g_instanceMutex);
        if (instance == nullptr) {
            instance = new PermissionDefinitionParser();
        }
    }
    return *instance;
}
} // namespace AccessToken
} // namespace Security
} // namespace OHOS
