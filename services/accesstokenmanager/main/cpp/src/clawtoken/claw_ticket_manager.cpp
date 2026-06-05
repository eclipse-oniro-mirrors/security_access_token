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

#include "access_token_error.h"
#include "accesstoken_common_log.h"
#include "accesstoken_info_manager.h"
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

std::string SerializeSkillAuthInfo(const SkillAuthInfo& skillAuth)
{
    CJsonUnique skillObj = CreateJson();
    if (skillObj == nullptr) {
        LOGE(ATM_DOMAIN, ATM_TAG, "Create skill auth info failed");
        return "";
    }

    CJsonUnique skillInfoObj = CreateJson();
    if (skillInfoObj == nullptr) {
        LOGE(ATM_DOMAIN, ATM_TAG, "Create skill info object failed");
        return "";
    }
    (void)AddStringToJson(skillInfoObj, "bundleName", skillAuth.skillInfo.bundleName);
    (void)AddStringToJson(skillInfoObj, "moduleName", skillAuth.skillInfo.moduleName);
    (void)AddStringToJson(skillInfoObj, "skillName", skillAuth.skillInfo.skillName);
    (void)AddObjToJson(skillObj, "skillInfo", skillInfoObj);

    CJsonUnique permNamesArr = CreateJsonArray();
    if (permNamesArr != nullptr) {
        for (const auto& permName : skillAuth.permissionNames) {
            (void)AddStringToArray(permNamesArr, permName);
        }
        (void)AddObjToJson(skillObj, "permissionNames", permNamesArr);
    }

    CJsonUnique permStatusArr = CreateJsonArray();
    if (permStatusArr != nullptr) {
        for (bool status : skillAuth.authorizationResults) {
            (void)AddStringToArray(permStatusArr, status ? "true" : "false");
        }
        (void)AddObjToJson(skillObj, "authorizationResults", permStatusArr);
    }

    return PackJsonToString(skillObj);
}

#ifdef SAF_AGENT_FENCE_ENABLE
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

SkillAuthInfo DeserializeSkillAuthInfo(const std::string& json)
{
    SkillAuthInfo skillAuth;
    if (json.empty()) {
        return skillAuth;
    }
    CJsonUnique jsonRoot = CreateJsonFromString(json);
    if (jsonRoot == nullptr) {
        LOGE(ATM_DOMAIN, ATM_TAG, "Deserialize skill auth info failed");
        return skillAuth;
    }
    cJSON* root = jsonRoot.get();

    cJSON* skillInfoObj = GetObjFromJson(root, "skillInfo");
    if (skillInfoObj != nullptr) {
        GetStringFromJson(skillInfoObj, "bundleName", skillAuth.skillInfo.bundleName);
        GetStringFromJson(skillInfoObj, "moduleName", skillAuth.skillInfo.moduleName);
        GetStringFromJson(skillInfoObj, "skillName", skillAuth.skillInfo.skillName);
    }

    cJSON* permNamesArr = GetArrayFromJson(root, "permissionNames");
    if (permNamesArr != nullptr) {
        int size = cJSON_GetArraySize(permNamesArr);
        for (int i = 0; i < size; ++i) {
            cJSON* item = cJSON_GetArrayItem(permNamesArr, i);
            if (item != nullptr && item->type == cJSON_String) {
                skillAuth.permissionNames.emplace_back(item->valuestring);
            }
        }
    }

    cJSON* permStatusArr = GetArrayFromJson(root, "authorizationResults");
    if (permStatusArr != nullptr) {
        int size = cJSON_GetArraySize(permStatusArr);
        for (int i = 0; i < size; ++i) {
            cJSON* item = cJSON_GetArrayItem(permStatusArr, i);
            if (item != nullptr && item->type == cJSON_String) {
                skillAuth.authorizationResults.emplace_back(std::string(item->valuestring) == "true");
            }
        }
    }

    return skillAuth;
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
        authResults.emplace_back(tickets[i].challenge);
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

int32_t ClawTicketManager::GenerateSkillTicket(AccessTokenID callerTokenId,
    const std::vector<SkillAuthInfo>& skillAuthInfos, std::vector<std::string>& authResults)
{
    LOGI(ATM_DOMAIN, ATM_TAG, "callerTokenId=%{public}u", callerTokenId);
    if (callerTokenId == INVALID_TOKENID) {
        return AccessTokenError::ERR_TOKEN_INVALID;
    }

    int32_t userId = GetUserIdByTokenId(callerTokenId);
    if (userId < 0) {
        return AccessTokenError::ERR_TOKENID_NOT_EXIST;
    }

    std::vector<std::string> messages;
    for (const auto& skillAuth : skillAuthInfos) {
        messages.emplace_back(SerializeSkillAuthInfo(skillAuth));
    }

#ifdef SAF_AGENT_FENCE_ENABLE
    SAF::SafAgentFence safAgentFence;
    std::vector<SAF::VerifyTicketInfo> tickets;
    int32_t ret = safAgentFence.BatchGenerateTicket(userId, std::to_string(callerTokenId), messages, tickets);
    if (ret != RET_SUCCESS) {
        LOGE(ATM_DOMAIN, ATM_TAG, "Generate skill ticket failed, ret=%{public}d", ret);
        return TransferErrorCode(ret);
    }

    std::unique_lock<std::shared_mutex> lock(multiLock_);

    for (size_t i = 0; i < tickets.size(); ++i) {
        authResults.emplace_back(tickets[i].challenge);
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
    std::shared_lock<std::shared_mutex> lock(multiLock_);

#ifndef ENHANCE_CAPABILITY
    if (challenge.empty()) {
        return RET_SUCCESS;
    }
#endif

#ifdef SAF_AGENT_FENCE_ENABLE
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
#endif

    return RET_SUCCESS;
}

int32_t ClawTicketManager::VerifySkillClawTicket(AccessTokenID hostTokenId, const std::string& challenge,
    const SkillInfo& skillInfo, std::vector<PermissionStatus>& permList)
{
    std::shared_lock<std::shared_mutex> lock(multiLock_);

#ifndef ENHANCE_CAPABILITY
    return RET_SUCCESS;
#endif

#ifdef SAF_AGENT_FENCE_ENABLE
    ClawTicket ticket;
    std::vector<SAF::VerifyTicketInfo> verifyInfos;
    std::vector<int32_t> verifyRes;
    int32_t ret = PrepareVerifiedTicketInfo(hostTokenId, challenge, ticket, verifyInfos, verifyRes);
    if (ret != RET_SUCCESS) {
        return ret;
    }

    for (size_t ticketIdx = 0; ticketIdx < verifyInfos.size(); ++ticketIdx) {
        bool ticketValid = (verifyRes[ticketIdx] == 0);
        SkillAuthInfo skillAuth = DeserializeSkillAuthInfo(verifyInfos[ticketIdx].message);
        for (size_t permIdx = 0; permIdx < skillAuth.permissionNames.size(); ++permIdx) {
            PermissionStatus status = {};
            status.permissionName = skillAuth.permissionNames[permIdx];
            status.grantStatus = (ticketValid && skillAuth.authorizationResults[permIdx]) ?
                PERMISSION_GRANTED : PERMISSION_DENIED;
            status.grantFlag = PERMISSION_DEFAULT_FLAG;
            permList.emplace_back(status);
        }
    }
#endif

    return RET_SUCCESS;
}

#ifdef SAF_AGENT_FENCE_ENABLE
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
    if (challenge.empty()) {
        return AccessTokenError::ERR_PARAM_INVALID;
    }

    std::unique_lock<std::shared_mutex> lock(multiLock_);

    auto it = ticketMap_.find(challenge);
    if (it == ticketMap_.end()) {
        return AccessTokenError::ERR_PARAM_INVALID;
    }

    ticketMap_.erase(it);

    LOGI(ATM_DOMAIN, ATM_TAG, "Tickets deleted, challenge=%s", challenge.c_str());
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
} // namespace AccessToken
} // namespace Security
} // namespace OHOS
