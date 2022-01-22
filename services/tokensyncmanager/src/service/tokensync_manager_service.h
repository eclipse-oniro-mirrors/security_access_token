/*
 * Copyright (c) 2021 Huawei Device Co., Ltd.
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

#ifndef TOKENSYNC_MANAGER_SERVICE_H
#define TOKENSYNC_MANAGER_SERVICE_H

#include <string>

#include "iremote_object.h"
#include "nocopyable.h"
#include "singleton.h"
#include "system_ability.h"
#include "tokensync_manager_stub.h"

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

    int VerifyPermission(const std::string& bundleName, const std::string& permissionName, int userId) override;

private:
    bool Initialize() const;

    ServiceRunningState state_;
};
} // namespace AccessToken
} // namespace Security
} // namespace OHOS
#endif // TOKENSYNC_MANAGER_SERVICE_H
