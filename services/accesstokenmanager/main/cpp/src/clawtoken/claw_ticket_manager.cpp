/*
 * Copyright (c) 2026 Huawei Device Co., Ltd.
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

#include "claw_ticket_manager.h"

#include <mutex>
#include <unordered_set>

#include "access_token_error.h"
#include "accesstoken_common_log.h"
#include "accesstoken_info_manager.h"
#include "claw_permission_metadata_provider.h"
#include "claw_permission_status_helper.h"
#include "cjson_utils.h"
#ifdef SAF_AGENT_FENCE_ENABLE
#include "saf_agent_fence.h"
#endif

namespace OHOS {
namespace Security {
namespace AccessToken {
namespace {
std::recursive_mutex g_instanceMutex;
constexpr const char* LEGACY_CHALLENGE_PREFIX = "legacy:";

int32_t GetUserIdByTokenId(AccessTokenID callerTokenId)
{
    auto hapInfo = AccessTokenInfoManager::GetInstance().GetHapTokenInfoInner(callerTokenId);
    if (hapInfo == nullptr) {
        LOGE(ATM_DOMAIN, ATM_TAG,
            "Get userId by tokenId failed, hapInfo is nullptr, tokenId: %{public}u", callerTokenId);
        return -1;
    }

    return hapInfo->GetUserID();
}

std::string SerializeCliAuthInfo(const CliAuthInfo& cliAuth)
{
    CJsonUnique cliObj = CreateJson();
    if (cliObj == nullptr) {
        LOGE(ATM_DOMAIN, ATM_TAG, "Create cli auth info failed");
        return "";
    }

    CJsonUnique cliInfoObj = CreateJson();
    if (cliInfoObj == nullptr) {
        LOGE(ATM_DOMAIN, ATM_TAG, "Create cli info object failed");
        return "";
    }
    (void)AddStringToJson(cliInfoObj, "cliName", cliAuth.cliInfo.cliName);
    (void)AddStringToJson(cliInfoObj, "subCliName", cliAuth.cliInfo.subCliName);
    (void)AddObjToJson(cliObj, "cliInfo", cliInfoObj);

    CJsonUnique permNamesArr = CreateJsonArray();
    if (permNamesArr != nullptr) {
        for (const auto& permName : cliAuth.permissionNames) {
            (void)AddStringToArray(permNamesArr, permName);
        }
        (void)AddObjToJson(cliObj, "permissionNames", permNamesArr);
    }

    CJsonUnique permStatusArr = CreateJsonArray();
    if (permStatusArr != nullptr) {
        for (bool status : cliAuth.authorizationResults) {
            (void)AddStringToArray(permStatusArr, status ? "true" : "false");
        }
        (void)AddObjToJson(cliObj, "authorizationResults", permStatusArr);
    }

    return PackJsonToString(cliObj);
}

#ifdef SAF_AGENT_FENCE_ENABLE
void StableUnique(std::vector<std::string>& values)
{
    std::unordered_set<std::string> seen;
    std::vector<std::string> uniqueValues;
    uniqueValues.reserve(values.size());
    for (const auto& value : values) {
        if (seen.insert(value).second) {
            uniqueValues.emplace_back(value);
        }
    }
    values = std::move(uniqueValues);
}

bool IsReturnedCliInfoMatched(
    const SAF::CliInfo& verifyCliInfo, AccessTokenID hostTokenId, const CliInfo& cliInfo)
{
    if (verifyCliInfo.callerTokenId != std::to_string(hostTokenId)) {
        return false;
    }
    return verifyCliInfo.cliCmdName == cliInfo.cliName && verifyCliInfo.subCliCmdName == cliInfo.subCliName;
}

int32_t AppendGrantedPermissionsByCliPermission(
    const std::string& requiredCliPermission, std::unordered_set<std::string>& grantedPermissionSet,
    std::vector<PermissionStatus>& permList)
{
    std::vector<std::string> usedPermissions;
    int32_t ret = ClawPermissionMetadataProvider::GetInstance().GetUsedPermissionsByCliPermission(
        requiredCliPermission, usedPermissions);
    if (ret != RET_SUCCESS) {
        return ret;
    }
    for (const auto& permissionName : usedPermissions) {
        if (!grantedPermissionSet.insert(permissionName).second) {
            continue;
        }
        PermissionStatus status = {};
        status.permissionName = permissionName;
        status.grantStatus = PERMISSION_GRANTED;
        status.grantFlag = PERMISSION_DEFAULT_FLAG;
        permList.emplace_back(status);
    }
    return RET_SUCCESS;
}

#endif

bool IsLegacyChallenge(const std::string& challenge)
{
    return challenge.rfind(LEGACY_CHALLENGE_PREFIX, 0) == 0;
}

std::string NormalizeLegacyChallenge(const std::string& challenge)
{
    if (!IsLegacyChallenge(challenge)) {
        return challenge;
    }
    return challenge.substr(std::char_traits<char>::length(LEGACY_CHALLENGE_PREFIX));
}

#ifdef SAF_AGENT_FENCE_ENABLE
std::string WrapLegacyChallenge(const std::string& challenge)
{
    return std::string(LEGACY_CHALLENGE_PREFIX) + challenge;
}

bool IsLegacyChallengeStored(const std::string& challenge, const std::unordered_map<std::string, ClawTicket>& ticketMap)
{
    return ticketMap.find(challenge) != ticketMap.end();
}

bool IsCliInfoMatched(const CliInfo& expectedCliInfo, const CliInfo& actualCliInfo)
{
    return (expectedCliInfo.cliName == actualCliInfo.cliName) &&
        (expectedCliInfo.subCliName == actualCliInfo.subCliName);
}

CliAuthInfo DeserializeCliAuthInfo(const std::string& json)
{
    CliAuthInfo cliAuth;
    if (json.empty()) {
        return cliAuth;
    }
    CJsonUnique jsonRoot = CreateJsonFromString(json);
    if (jsonRoot == nullptr) {
        LOGE(ATM_DOMAIN, ATM_TAG, "Deserialize cli auth info failed");
        return cliAuth;
    }
    cJSON* root = jsonRoot.get();

    cJSON* cliInfoObj = GetObjFromJson(root, "cliInfo");
    if (cliInfoObj != nullptr) {
        GetStringFromJson(cliInfoObj, "cliName", cliAuth.cliInfo.cliName);
        GetStringFromJson(cliInfoObj, "subCliName", cliAuth.cliInfo.subCliName);
    }

    cJSON* permNamesArr = GetArrayFromJson(root, "permissionNames");
    if (permNamesArr != nullptr) {
        int size = cJSON_GetArraySize(permNamesArr);
        for (int i = 0; i < size; ++i) {
            cJSON* item = cJSON_GetArrayItem(permNamesArr, i);
            if (item != nullptr && item->type == cJSON_String) {
                cliAuth.permissionNames.emplace_back(item->valuestring);
            }
        }
    }

    cJSON* permStatusArr = GetArrayFromJson(root, "authorizationResults");
    if (permStatusArr != nullptr) {
        int size = cJSON_GetArraySize(permStatusArr);
        for (int i = 0; i < size; ++i) {
            cJSON* item = cJSON_GetArrayItem(permStatusArr, i);
            if (item != nullptr && item->type == cJSON_String) {
                cliAuth.authorizationResults.emplace_back(std::string(item->valuestring) == "true");
            }
        }
    }
    return cliAuth;
}
#endif
}

ClawTicketManager& ClawTicketManager::GetInstance()
{
    static ClawTicketManager* instance = nullptr;
    if (instance == nullptr) {
        std::lock_guard<std::recursive_mutex> lock(g_instanceMutex);
        if (instance == nullptr) {
            ClawTicketManager* tmp = new ClawTicketManager();
            instance = std::move(tmp);
        }
    }
    return *instance;
}

ClawTicketManager::ClawTicketManager()
{
    (void)RegisterAppStateObserver();
}

ClawTicketManager::~ClawTicketManager()
{
    (void)UnregisterAppStateObserver();
}

void ClawTicketManager::RegisterAppStateObserver()
{
    {
        std::lock_guard<std::mutex> lock(appStateObserverMutex_);
        if (appStateObserver_ == nullptr) {
            appStateObserver_ = new (std::nothrow) ClawTicketAppStateObserver();
            if (appStateObserver_ == nullptr) {
                LOGE(ATM_DOMAIN, ATM_TAG, "Register appStateObserver failed.");
                return;
            }
        }
    }
    {
        if (appManagerDeathCallback_ == nullptr) {
            appManagerDeathCallback_ = std::make_shared<ClawTicketAppManagerDeathCallback>();
            AppManagerAccessClient::GetInstance().RegisterDeathCallback(appManagerDeathCallback_);
        }
    }
    int ret = AppManagerAccessClient::GetInstance().RegisterApplicationStateObserver(appStateObserver_);
    if (ret != ERR_OK) {
        LOGI(ATM_DOMAIN, ATM_TAG, "Register appStateObserver ret: %{public}d.", ret);
    }
}

void ClawTicketManager::UnregisterAppStateObserver()
{
    std::lock_guard<std::mutex> lock(appStateObserverMutex_);
    if (appStateObserver_ != nullptr) {
        (void)AppManagerAccessClient::GetInstance().UnregisterApplicationStateObserver(appStateObserver_);
        appStateObserver_ = nullptr;
    }
}

void ClawTicketManager::OnAppMgrRemoteDiedHandle()
{
    std::lock_guard<std::mutex> lock(appStateObserverMutex_);
    appStateObserver_ = nullptr;
    LOGI(ATM_DOMAIN, ATM_TAG, "ClawTicket AppManagerDeath, observer reset.");
}

void ClawTicketAppStateObserver::OnAppStopped(const AppStateData &appStateData)
{
    if (appStateData.state == static_cast<int32_t>(ApplicationState::APP_STATE_TERMINATED)) {
        AccessTokenID tokenId = appStateData.accessTokenId;
        LOGI(ATM_DOMAIN, ATM_TAG, "ClawTicket TokenID:%{public}u died.", tokenId);
        ClawTicketManager::GetInstance().DeleteClawTicketByCallerTokenId(tokenId);
    }
}

void ClawTicketAppManagerDeathCallback::NotifyAppManagerDeath()
{
    LOGI(ATM_DOMAIN, ATM_TAG, "ClawTicketManager AppManagerDeath called");
    ClawTicketManager::GetInstance().OnAppMgrRemoteDiedHandle();
}

int32_t ClawTicketManager::GenerateCliTicket(AccessTokenID callerTokenId,
    const std::vector<CliAuthInfo>& cliAuthInfos, std::vector<std::string>& authResults)
{
    if (callerTokenId == INVALID_TOKENID) {
        return AccessTokenError::ERR_TOKEN_INVALID;
    }

    int32_t userId = GetUserIdByTokenId(callerTokenId);
    if (userId < 0) {
        return AccessTokenError::ERR_TOKENID_NOT_EXIST;
    }

    std::vector<std::string> messages;
    for (const auto& cliAuth : cliAuthInfos) {
        messages.emplace_back(SerializeCliAuthInfo(cliAuth));
    }

#ifdef SAF_AGENT_FENCE_ENABLE
    SAF::SafAgentFence safAgentFence;
    std::vector<SAF::VerifyTicketInfo> tickets;
    int32_t ret = safAgentFence.BatchGenerateTicket(userId, std::to_string(callerTokenId), messages, tickets);
    if (ret != RET_SUCCESS) {
        LOGE(ATM_DOMAIN, ATM_TAG, "Generate cli ticket failed, ret=%{public}d", ret);
        return TransferErrorCode(ret);
    }

    std::unique_lock<std::shared_mutex> lock(multiLock_);

    for (size_t i = 0; i < tickets.size(); ++i) {
        authResults.emplace_back(tickets[i].challenge.empty() ? "" : WrapLegacyChallenge(tickets[i].challenge));
        if (tickets[i].challenge.empty()) {
            continue;
        }
        ClawTicket ticket;
        ticket.callerTokenId = callerTokenId;
        ticket.message = tickets[i].message;
        ticket.ticket = tickets[i].ticket;
        ticketMap_[tickets[i].challenge] = ticket;
    }
#endif

    return RET_SUCCESS;
}

int32_t ClawTicketManager::VerifyCliClawTicket(AccessTokenID hostTokenId, const std::string& challenge,
    const CliInfo& cliInfo, std::vector<PermissionStatus>& permList)
{
    const std::string rawChallenge = NormalizeLegacyChallenge(challenge);
#ifndef ENHANCE_CAPABILITY
    if (rawChallenge.empty()) {
        return QueryCommandPermissions(cliInfo, permList);
    }
#endif

#ifdef SAF_AGENT_FENCE_ENABLE
    std::shared_lock<std::shared_mutex> lock(multiLock_);
    if (IsLegacyChallenge(challenge) || IsLegacyChallengeStored(rawChallenge, ticketMap_)) {
        return VerifyCliClawTicketLegacy(hostTokenId, rawChallenge, cliInfo, permList);
    }
    return VerifyCliClawTicketByVerifyInfo(hostTokenId, challenge, cliInfo, permList);
#else
    return RET_SUCCESS;
#endif
}

#ifdef SAF_AGENT_FENCE_ENABLE
int32_t ClawTicketManager::VerifyCliClawTicketLegacy(AccessTokenID hostTokenId, const std::string& challenge,
    const CliInfo& cliInfo, std::vector<PermissionStatus>& permList)
{
    ClawTicket ticket;
    std::vector<SAF::VerifyTicketInfo> verifyInfos;
    std::vector<int32_t> verifyRes;
    int32_t ret = PrepareVerifiedTicketInfo(hostTokenId, challenge, ticket, verifyInfos, verifyRes);
    if (ret != RET_SUCCESS) {
        return ret;
    }
    if (hostTokenId != ticket.callerTokenId) {
        LOGE(ATM_DOMAIN, ATM_TAG, "Verify cli ticket failed, hostTokenId=%{public}d", hostTokenId);
        return AccessTokenError::ERR_PARAM_INVALID;
    }
    for (size_t ticketIdx = 0; ticketIdx < verifyInfos.size(); ++ticketIdx) {
        bool ticketValid = (verifyRes[ticketIdx] == 0);
        CliAuthInfo cliAuth = DeserializeCliAuthInfo(verifyInfos[ticketIdx].message);
        if (!IsCliInfoMatched(cliInfo, cliAuth.cliInfo)) {
            LOGE(ATM_DOMAIN, ATM_TAG,
                "Verify cli ticket failed, cliInfo mismatch, inputCliName=%{public}s, inputSubCliName=%{public}s, "
                "ticketCliName=%{public}s, ticketSubCliName=%{public}s.", cliInfo.cliName.c_str(),
                cliInfo.subCliName.c_str(), cliAuth.cliInfo.cliName.c_str(), cliAuth.cliInfo.subCliName.c_str());
            return AccessTokenError::ERR_PARAM_INVALID;
        }
        for (size_t permIdx = 0; permIdx < cliAuth.permissionNames.size(); ++permIdx) {
            PermissionStatus status = {};
            status.permissionName = cliAuth.permissionNames[permIdx];
            status.grantStatus = (ticketValid && cliAuth.authorizationResults[permIdx]) ?
                PERMISSION_GRANTED : PERMISSION_DENIED;
            status.grantFlag = PERMISSION_DEFAULT_FLAG;
            permList.emplace_back(status);
        }
    }

    return RET_SUCCESS;
}

int32_t ClawTicketManager::VerifyCliClawTicketByVerifyInfo(AccessTokenID hostTokenId,
    const std::string& challenge, const CliInfo& cliInfo, std::vector<PermissionStatus>& permList)
{
    int32_t userId = GetUserIdByTokenId(hostTokenId);
    if (userId < 0) {
        return AccessTokenError::ERR_TOKENID_NOT_EXIST;
    }

    SAF::SafAgentFence safAgentFence;
    std::vector<SAF::CliInfo> verifiedCliInfos;
    int32_t ret = safAgentFence.VerifyTicket(userId, std::to_string(hostTokenId), challenge, verifiedCliInfos);
    if (ret != RET_SUCCESS) {
        LOGE(ATM_DOMAIN, ATM_TAG, "Verify cli ticket by verifyInfo failed, ret=%{public}d", ret);
        return TransferErrorCode(ret);
    }

    std::vector<std::string> grantedCliPermissions;
    bool hasMatchedCliInfo = false;
    for (const auto& verifyCliInfo : verifiedCliInfos) {
        if (!IsReturnedCliInfoMatched(verifyCliInfo, hostTokenId, cliInfo)) {
            continue;
        }
        hasMatchedCliInfo = true;
        grantedCliPermissions.insert(grantedCliPermissions.end(),
            verifyCliInfo.permissionList.begin(), verifyCliInfo.permissionList.end());
    }
    if (!hasMatchedCliInfo) {
        LOGE(ATM_DOMAIN, ATM_TAG,
            "Verify cli ticket by verifyInfo failed, no matched cli info, hostTokenId=%{public}u, "
            "cliName=%{public}s, subCliName=%{public}s.", hostTokenId, cliInfo.cliName.c_str(),
            cliInfo.subCliName.c_str());
        return AccessTokenError::ERR_PARAM_INVALID;
    }

    StableUnique(grantedCliPermissions);
    std::unordered_set<std::string> grantedPermissionSet;
    for (const auto& requiredCliPermission : grantedCliPermissions) {
        ret = AppendGrantedPermissionsByCliPermission(requiredCliPermission, grantedPermissionSet, permList);
        if (ret != RET_SUCCESS) {
            LOGE(ATM_DOMAIN, ATM_TAG,
                "Resolve cli permission mapping failed, cliPermission=%{public}s, ret=%{public}d.",
                requiredCliPermission.c_str(), ret);
            return ret;
        }
    }
    return RET_SUCCESS;
}

int32_t ClawTicketManager::PrepareVerifiedTicketInfo(AccessTokenID hostTokenId, const std::string& challenge,
    ClawTicket& ticket, std::vector<SAF::VerifyTicketInfo>& verifyInfos, std::vector<int32_t>& verifyRes)
{
    auto it = ticketMap_.find(challenge);
    if (it == ticketMap_.end()) {
        LOGE(ATM_DOMAIN, ATM_TAG, "Verify ticket failed, challenge not found");
        return AccessTokenError::ERR_PARAM_INVALID;
    }
    ticket = it->second;

    int32_t userId = GetUserIdByTokenId(hostTokenId);
    if (userId < 0) {
        return AccessTokenError::ERR_TOKENID_NOT_EXIST;
    }

    SAF::SafAgentFence safAgentFence;
    verifyInfos = {{ticket.message, challenge, ticket.ticket}};
    int32_t ret = safAgentFence.BatchVerifyTicket(userId, std::to_string(hostTokenId), verifyInfos, verifyRes);
    if (ret != RET_SUCCESS) {
        LOGE(ATM_DOMAIN, ATM_TAG, "Verify ticket failed, ret=%{public}d", ret);
        return TransferErrorCode(ret);
    }
    return RET_SUCCESS;
}
#endif

int32_t ClawTicketManager::DeleteClawTicket(const std::string& challenge)
{
    const std::string rawChallenge = NormalizeLegacyChallenge(challenge);
    if (rawChallenge.empty()) {
        return AccessTokenError::ERR_PARAM_INVALID;
    }

    std::unique_lock<std::shared_mutex> lock(multiLock_);

    auto it = ticketMap_.find(rawChallenge);
    if (it == ticketMap_.end()) {
        return AccessTokenError::ERR_PARAM_INVALID;
    }

    ticketMap_.erase(it);

    LOGI(ATM_DOMAIN, ATM_TAG, "Tickets deleted, legacyPrefix=%{public}d, challengeLength=%{public}zu.",
        IsLegacyChallenge(challenge), rawChallenge.length());
    return RET_SUCCESS;
}

void ClawTicketManager::DeleteClawTicketByCallerTokenId(AccessTokenID callerTokenId)
{
    std::unique_lock<std::shared_mutex> lock(multiLock_);

    std::vector<std::string> challengesToDelete;
    for (const auto& entry : ticketMap_) {
        if (entry.second.callerTokenId == callerTokenId) {
            challengesToDelete.emplace_back(entry.first);
        }
    }

    for (const auto& challenge : challengesToDelete) {
        ticketMap_.erase(challenge);
    }

    LOGI(ATM_DOMAIN, ATM_TAG, "Deleted %{public}zu tickets for callerTokenId=%{public}u", challengesToDelete.size(),
        callerTokenId);
}

int32_t ClawTicketManager::QueryCommandPermissions(const CliInfo& cliInfo, std::vector<PermissionStatus>& permList)
{
#ifdef SAF_AGENT_FENCE_ENABLE
    std::vector<SAF::CommandInfo> cmds;
    SAF::CommandInfo cmd;
    cmd.cmdName = cliInfo.cliName;
    cmd.subCmd = cliInfo.subCliName;
    cmds.emplace_back(cmd);

    std::vector<SAF::CommandPermissionInfo> permissionInfos;
    SAF::SafAgentFence safAgentFence;
    int32_t ret = safAgentFence.BatchQueryCommandPermission(cmds, permissionInfos);
    if (ret != RET_SUCCESS) {
        LOGE(ATM_DOMAIN, ATM_TAG, "Query cli callable permissions failed, ret=%{public}d.", ret);
        return ret;
    }
    if (permissionInfos.size() != cmds.size()) {
        LOGE(ATM_DOMAIN, ATM_TAG,
            "Query cli callable permissions size mismatch, input=%{public}zu, output=%{public}zu.",
            cmds.size(), permissionInfos.size());
        return AccessTokenError::ERR_PERMISSION_NOT_EXIST;
    }

    for (size_t i = 0; i < permissionInfos.size(); ++i) {
        for (const auto& perm : permissionInfos[i].permissions) {
            PermissionStatus status;
            status.permissionName = perm;
            status.grantStatus = PERMISSION_GRANTED;
            permList.emplace_back(status);
        }
    }
#endif
    return RET_SUCCESS;
}
} // namespace AccessToken
} // namespace Security
} // namespace OHOS
