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
#include "config_policy_loader.h"

#ifdef CUSTOMIZATION_CONFIG_POLICY_ENABLE
#include "accesstoken_log.h"
#include "config_policy_utils.h"
#include "json_parser.h"
#endif

namespace OHOS {
namespace Security {
namespace AccessToken {
namespace {
#ifdef CUSTOMIZATION_CONFIG_POLICY_ENABLE
static constexpr OHOS::HiviewDFX::HiLogLabel LABEL = {LOG_CORE, SECURITY_DOMAIN_ACCESSTOKEN, "ConfigPolicLoader"};
static const std::string ACCESSTOKEN_CONFIG_FILE = "/etc/access_token/accesstoken_config.json";

static const std::string PERMISSION_MANAGER_BUNDLE_NAME_KEY = "permission_manager_bundle_name";
static const std::string GRANT_ABILITY_NAME_KEY = "grant_ability_name";
static const std::string PERMISSION_STATE_SHEET_ABILITY_NAME_KEY = "permission_state_sheet_ability_name";
static const std::string GLOBAL_SWITCH_SHEET_ABILITY_NAME_KEY = "global_switch_sheet_ability_name";
static const std::string TEMP_PERM_CANCLE_TIME_KEY = "temp_perm_cencle_time";

static const std::string RECORD_SIZE_MAXIMUM_KEY = "permission_used_record_size_maximum";
static const std::string RECORD_AGING_TIME_KEY = "permission_used_record_aging_time";
static const std::string GLOBAL_DIALOG_BUNDLE_NAME_KEY = "global_dialog_bundle_name";
static const std::string GLOBAL_DIALOG_ABILITY_NAME_KEY = "global_dialog_ability_name";

static const std::string SEND_REQUEST_REPEAT_TIMES_KEY = "send_request_repeat_times";
#endif // CUSTOMIZATION_CONFIG_POLICY_ENABLE
}

#ifdef CUSTOMIZATION_CONFIG_POLICY_ENABLE
void ConfigPolicLoader::GetConfigFilePathList(std::vector<std::string>& pathList)
{
    CfgDir *dirs = GetCfgDirList(); // malloc a CfgDir point, need to free later
    if (dirs == nullptr) {
        ACCESSTOKEN_LOG_ERROR(LABEL, "Can't get cfg file path.");
        return;
    }

    for (const auto& path : dirs->paths) {
        if ((path == nullptr) || (!JsonParser::IsDirExsit(path))) {
            continue;
        }

        ACCESSTOKEN_LOG_INFO(LABEL, "Accesstoken cfg dir: %{public}s.", path);
        pathList.emplace_back(path);
    }

    FreeCfgDirList(dirs); // free
}

void from_json(const nlohmann::json& j, AccessTokenServiceConfig& a)
{
    if (!JsonParser::GetStringFromJson(j, PERMISSION_MANAGER_BUNDLE_NAME_KEY, a.grantBundleName)) {
        return;
    }

    if (!JsonParser::GetStringFromJson(j, GRANT_ABILITY_NAME_KEY, a.grantAbilityName)) {
        return;
    }

    if (!JsonParser::GetStringFromJson(j, PERMISSION_STATE_SHEET_ABILITY_NAME_KEY, a.permStateAbilityName)) {
        return;
    }

    if (!JsonParser::GetStringFromJson(j, GLOBAL_SWITCH_SHEET_ABILITY_NAME_KEY, a.globalSwitchAbilityName)) {
        return;
    }

    if (!JsonParser::GetIntFromJson(j, TEMP_PERM_CANCLE_TIME_KEY, a.cancleTime)) {
        return;
    }
}

void from_json(const nlohmann::json& j, PrivacyServiceConfig& p)
{
    if (!JsonParser::GetIntFromJson(j, RECORD_SIZE_MAXIMUM_KEY, p.sizeMaxImum)) {
        return;
    }

    if (!JsonParser::GetIntFromJson(j, RECORD_AGING_TIME_KEY, p.agingTime)) {
        return;
    }

    if (!JsonParser::GetStringFromJson(j, GLOBAL_DIALOG_BUNDLE_NAME_KEY, p.globalDialogBundleName)) {
        return;
    }

    if (!JsonParser::GetStringFromJson(j, GLOBAL_DIALOG_ABILITY_NAME_KEY, p.globalDialogAbilityName)) {
        return;
    }
}

void from_json(const nlohmann::json& j, TokenSyncServiceConfig& t)
{
    if (!JsonParser::GetIntFromJson(j, SEND_REQUEST_REPEAT_TIMES_KEY, t.sendRequestRepeatTimes)) {
        return;
    }
}

bool ConfigPolicLoader::GetConfigValueFromFile(const ServiceType& type, const std::string& fileContent,
    AccessTokenConfigValue& config)
{
    nlohmann::json jsonRes = nlohmann::json::parse(fileContent, nullptr, false);
    if (jsonRes.is_discarded()) {
        ACCESSTOKEN_LOG_ERROR(LABEL, "JsonRes is invalid.");
        return false;
    }

    if (type == ServiceType::ACCESSTOKEN_SERVICE) {
        if ((jsonRes.find("accesstoken") != jsonRes.end()) && (jsonRes.at("accesstoken").is_object())) {
            config.atConfig = jsonRes.at("accesstoken").get<nlohmann::json>();
            return true;
        } else {
            return false;
        }
    } else if (type == ServiceType::PRIVACY_SERVICE) {
        if ((jsonRes.find("privacy") != jsonRes.end()) && (jsonRes.at("privacy").is_object())) {
            config.pConfig = jsonRes.at("privacy").get<nlohmann::json>();
            return true;
        } else {
            return false;
        }
    }

    if ((jsonRes.find("tokensync") != jsonRes.end()) && (jsonRes.at("tokensync").is_object())) {
        config.tsConfig = jsonRes.at("tokensync").get<nlohmann::json>();
        return true;
    } else {
        return false;
    }
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
        int32_t res = JsonParser::ReadCfgFile(filePath, fileContent);
        if (res != 0) {
            ACCESSTOKEN_LOG_ERROR(LABEL, "Read Cfg file [%{public}s] failed, error(%{public}d).",
                filePath.c_str(), res);
            continue;
        }

        if (GetConfigValueFromFile(type, fileContent, config)) {
            ACCESSTOKEN_LOG_INFO(LABEL, "Get valid config value!");
            successFlag = true;
            break; // once get the config value, break the loop
        }
    }
#endif // CUSTOMIZATION_CONFIG_POLICY_ENABLE
    return successFlag;
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
