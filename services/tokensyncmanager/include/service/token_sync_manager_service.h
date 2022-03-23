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

#ifndef TOKEN_SYNC_MANAGER_SERVICE_H
#define TOKEN_SYNC_MANAGER_SERVICE_H

#include <string>

#include "event_handler.h"
#include "hap_token_info_for_sync_parcel.h"
#include "iremote_object.h"
#include "nocopyable.h"
#include "singleton.h"
#include "system_ability.h"
#include "token_sync_event_handler.h"
#include "token_sync_manager_stub.h"

namespace OHOS {
namespace Security {
namespace AccessToken {
enum class ServiceRunningState { STATE_NOT_START, STATE_RUNNING };
class TokenSyncManagerService final : public SystemAbility, public TokenSyncManagerStub {
    DECLARE_DELAYED_SINGLETON(TokenSyncManagerService);
    DECLEAR_SYSTEM_ABILITY(TokenSyncManagerService);

public:
    void OnStart() override;
    void OnStop() override;

    std::shared_ptr<TokenSyncEventHandler> GetSendEventHandler() const;
    std::shared_ptr<TokenSyncEventHandler> GetRecvEventHandler() const;
    int GetRemoteHapTokenInfo(const std::string& deviceID, AccessTokenID tokenID) override;
    int DeleteRemoteHapTokenInfo(AccessTokenID tokenID) override;
    int UpdateRemoteHapTokenInfo(const HapTokenInfoForSync& tokenInfo) override;

private:
    bool Initialize();

    std::shared_ptr<AppExecFwk::EventRunner> sendRunner_;
    std::shared_ptr<AppExecFwk::EventRunner> recvRunner_;
    std::shared_ptr<TokenSyncEventHandler> sendHandler_;
    std::shared_ptr<TokenSyncEventHandler> recvHandler_;
    ServiceRunningState state_;
};
} // namespace AccessToken
} // namespace Security
} // namespace OHOS
#endif // TOKEN_SYNC_MANAGER_SERVICE_H
