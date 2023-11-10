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
#include "system_permission_definition_parser.h"

#include <fcntl.h>
#include <memory>
#include <sys/stat.h>
#include <sys/types.h>
#include <unistd.h>

#include "accesstoken_log.h"
#include "access_token.h"
#include "data_validator.h"
#include "json_parser.h"
#include "permission_def.h"
#include "permission_definition_cache.h"
#include "securec.h"

namespace OHOS {
namespace Security {
namespace AccessToken {
namespace {
static const int32_t EXTENSION_PERMISSION_ID = 0;
static const std::string PERMISSION_NAME = "name";
static const std::string PERMISSION_GRANT_MODE = "grantMode";
static const std::string PERMISSION_AVAILABLE_LEVEL = "availableLevel";
static const std::string PERMISSION_PROVISION_ENABLE = "provisionEnable";
static const std::string PERMISSION_DISTRIBUTED_SCENE_ENABLE = "distributedSceneEnable";
static const std::string PERMISSION_LABEL = "label";
static const std::string PERMISSION_DESCRIPTION = "description";
static const std::string AVAILABLE_LEVEL_NORMAL = "normal";
static const std::string AVAILABLE_LEVEL_SYSTEM_BASIC = "system_basic";
static const std::string AVAILABLE_LEVEL_SYSTEM_CORE = "system_core";
static const std::string PERMISSION_GRANT_MODE_SYSTEM_GRANT = "system_grant";
static const std::string PERMISSION_GRANT_MODE_USER_GRANT = "user_grant";
static const std::string DEFINE_PERMISSION = "definePermissions";
static const std::string DEFINE_PERMISSION_FILE = "/system/etc/access_token/permission_definitions.json";
static constexpr OHOS::HiviewDFX::HiLogLabel LABEL = {LOG_CORE,
    SECURITY_DOMAIN_ACCESSTOKEN, "SystemPermissionDefinitionParser"};
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
    if (!JsonParser::GetStringFromJson(j, PERMISSION_LABEL, permDef.description)) {
        return;
    }
    result.permDef = permDef;
    result.isSuccessful = true;
    return;
}

static bool CheckPermissionDefRules(const PermissionDef& permDef)
{
    // Extension permission support system_grant permission only.
    if (permDef.grantMode != SYSTEM_GRANT) {
        return false;
    }
    return true;
}

int32_t SystemPermissionDefinitionParser::ParserPermsRawData(const std::string& permsRawData,
    std::vector<PermissionDef>& permDefList)
{
    nlohmann::json jsonRes = nlohmann::json::parse(permsRawData, nullptr, false);
    if (jsonRes.is_discarded()) {
        ACCESSTOKEN_LOG_ERROR(LABEL, "jsonRes is invalid.");
        return RET_FAILED;
    }

    if ((jsonRes.find(DEFINE_PERMISSION) == jsonRes.end()) || (!jsonRes.at(DEFINE_PERMISSION).is_array())) {
        ACCESSTOKEN_LOG_ERROR(LABEL, "jsonRes is not array.");
        return RET_FAILED;
    }
    nlohmann::json JsonData = jsonRes.at(DEFINE_PERMISSION).get<nlohmann::json>();
    for (auto it = JsonData.begin(); it != JsonData.end(); it++) {
        auto result = it->get<PermissionDefParseRet>();
        if (result.isSuccessful) {
            ACCESSTOKEN_LOG_DEBUG(LABEL, "permDef.grantMode %{public}s.", result.permDef.permissionName.c_str());
            if (!CheckPermissionDefRules(result.permDef)) {
                continue;
            }
            permDefList.emplace_back(result.permDef);
        }
    }
    return RET_SUCCESS;
}

int32_t SystemPermissionDefinitionParser::Init()
{
    ACCESSTOKEN_LOG_ERROR(LABEL, "system permission set begin.");
    if (ready_) {
        ACCESSTOKEN_LOG_ERROR(LABEL, " system permission has been set.");
        return RET_SUCCESS;
    }

    std::string permsRawData;
    int32_t ret = JsonParser::ReadCfgFile(DEFINE_PERMISSION_FILE, permsRawData);
    if (ret != RET_SUCCESS) {
        ACCESSTOKEN_LOG_ERROR(LABEL, "readCfgFile failed.");
        return RET_FAILED;
    }
    std::vector<PermissionDef> permDefList;
    ret = ParserPermsRawData(permsRawData, permDefList);
    if (ret != RET_SUCCESS) {
        ACCESSTOKEN_LOG_ERROR(LABEL, "ParserPermsRawData failed.");
        return RET_FAILED;
    }
    for (const auto& perm : permDefList) {
        PermissionDefinitionCache::GetInstance().Insert(perm, EXTENSION_PERMISSION_ID);
    }

    ready_ = true;
    ACCESSTOKEN_LOG_INFO(LABEL, "init ok.");
    return RET_SUCCESS;
}

SystemPermissionDefinitionParser& SystemPermissionDefinitionParser::GetInstance()
{
    static SystemPermissionDefinitionParser instance;
    return instance;
}
} // namespace AccessToken
} // namespace Security
} // namespace OHOS
