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

#ifndef CLAW_TICKET_MANAGER_H
#define CLAW_TICKET_MANAGER_H

#include <memory>
#include <mutex>
#include <shared_mutex>
#include <string>
#include <unordered_map>
#include <vector>

#ifdef SAF_AGENT_FENCE_ENABLE
#include "saf_agent_fence.h"
#endif
#include "access_token.h"
#include "app_manager_access_client.h"
#include "app_manager_death_callback.h"
#include "app_status_change_callback.h"
#include "claw_permission_info.h"
#include "nocopyable.h"
#include "permission_status.h"

namespace OHOS {
namespace Security {
namespace AccessToken {

struct ClawTicket {
    AccessTokenID callerTokenId = INVALID_TOKENID;
    std::string message;
    std::string ticket;
};

class ClawTicketAppStateObserver : public ApplicationStateObserverStub {
public:
    ClawTicketAppStateObserver() = default;
    ~ClawTicketAppStateObserver() = default;

    void OnAppStopped(const AppStateData &appStateData) override;

    DISALLOW_COPY_AND_MOVE(ClawTicketAppStateObserver);
};

class ClawTicketAppManagerDeathCallback : public AppManagerDeathCallback {
public:
    ClawTicketAppManagerDeathCallback() = default;
    ~ClawTicketAppManagerDeathCallback() = default;

    void NotifyAppManagerDeath() override;

    DISALLOW_COPY_AND_MOVE(ClawTicketAppManagerDeathCallback);
};

class ClawTicketManager {
public:
    static ClawTicketManager& GetInstance();

    int32_t GenerateCliTicket(AccessTokenID callerTokenId,
        const std::vector<CliAuthInfo>& cliAuthInfos, std::vector<std::string>& authResults);

    int32_t VerifyCliClawTicket(AccessTokenID hostTokenId, const std::string& challenge,
        const CliInfo& cliInfo, std::vector<PermissionStatus>& permList);

    int32_t DeleteClawTicket(const std::string& challenge);

    void DeleteClawTicketByCallerTokenId(AccessTokenID callerTokenId);

    void OnAppMgrRemoteDiedHandle();
private:
    ClawTicketManager();
    ~ClawTicketManager();
    DISALLOW_COPY_AND_MOVE(ClawTicketManager);

    void RegisterAppStateObserver();
    void UnregisterAppStateObserver();
#ifdef SAF_AGENT_FENCE_ENABLE
    int32_t VerifyCliClawTicketLegacy(AccessTokenID hostTokenId, const std::string& challenge,
        const CliInfo& cliInfo, std::vector<PermissionStatus>& permList);
    int32_t VerifyCliClawTicketByVerifyInfo(AccessTokenID hostTokenId, const std::string& challenge,
        const CliInfo& cliInfo, std::vector<PermissionStatus>& permList);
    int32_t PrepareVerifiedTicketInfo(AccessTokenID hostTokenId, const std::string& challenge,
        ClawTicket& ticket, std::vector<SAF::VerifyTicketInfo>& verifyInfos, std::vector<int32_t>& verifyRes);
#endif
    std::shared_mutex multiLock_;
    std::unordered_map<std::string, ClawTicket> ticketMap_;

    std::mutex appStateObserverMutex_;
    sptr<ClawTicketAppStateObserver> appStateObserver_ = nullptr;
    std::shared_ptr<ClawTicketAppManagerDeathCallback> appManagerDeathCallback_;
};
} // namespace AccessToken
} // namespace Security
} // namespace OHOS
#endif // CLAW_TICKET_MANAGER_H
