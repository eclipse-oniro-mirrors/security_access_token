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

#ifndef ABILITY_MANAGER_PRIVACY_CLIENT_H
#define ABILITY_MANAGER_PRIVACY_CLIENT_H

#include <mutex>
#include <string>

#include "ability_manager_privacy_death_recipient.h"
#include "ability_manager_privacy_proxy.h"
#include "nocopyable.h"

namespace OHOS {
namespace Security {
namespace AccessToken {
class AbilityManagerPrivacyClient final {
public:
    static AbilityManagerPrivacyClient& GetInstance();

    virtual ~AbilityManagerPrivacyClient();

    int StartAbility(const AAFwk::Want &want, const sptr<IRemoteObject> &callerToken,
        int requestCode = DEFAULT_INVAL_VALUE, int32_t userId = DEFAULT_INVAL_VALUE);
    void OnRemoteDiedHandle();

private:
    AbilityManagerPrivacyClient();
    DISALLOW_COPY_AND_MOVE(AbilityManagerPrivacyClient);

    void InitProxy();
    sptr<IAbilityManager> GetProxy();

    sptr<AbilityManagerPrivacyDeathRecipient> serviceDeathObserver_ = nullptr;
    std::mutex proxyMutex_;
    sptr<IAbilityManager> proxy_ = nullptr;
};
} // namespace AccessToken
} // namespace Security
} // namespace OHOS
#endif // ABILITY_MANAGER_PRIVACY_CLIENT_H

