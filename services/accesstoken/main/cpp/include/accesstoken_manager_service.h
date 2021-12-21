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

#ifndef ACCESSTOKEN_MANAGER_SERVICE_H
#define ACCESSTOKEN_MANAGER_SERVICE_H

#include "accesstoken_manager_stub.h"
#include "singleton.h"
#include "iremote_object.h"
#include "system_ability.h"
#include "nocopyable.h"

namespace OHOS {
namespace Security {
namespace AccessToken {
enum class ServiceRunningState { STATE_NOT_START, STATE_RUNNING };
class AccessTokenManagerService final : public SystemAbility, public AccessTokenManagerStub {
    DECLARE_DELAYED_SINGLETON(AccessTokenManagerService);
    DECLEAR_SYSTEM_ABILITY(AccessTokenManagerService);

public:
    void OnStart() override;
    void OnStop() override;

    int VerifyAccesstoken(AccessTokenID tokenID, const std::string& permissionName) override;

private:
    bool Initialize() const;

    ServiceRunningState state_;
};
} // namespace AccessToken
} // namespace Security
} // namespace OHOS
#endif // ACCESSTOKEN_MANAGER_SERVICE_H
