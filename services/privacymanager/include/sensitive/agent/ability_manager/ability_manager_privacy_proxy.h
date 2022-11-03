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

#ifndef OHOS_ABILITY_MANAGER_PRIVACY_PROXY_H
#define OHOS_ABILITY_MANAGER_PRIVACY_PROXY_H

#include <iremote_proxy.h>
#include "want.h"

namespace OHOS {
namespace Security {
namespace AccessToken {
const int DEFAULT_INVAL_VALUE = -1;
class IAbilityManager : public IRemoteBroker {
public:
    DECLARE_INTERFACE_DESCRIPTOR(u"ohos.aafwk.AbilityManager")

    enum class AbilityManagerMessage : uint32_t {
        START_ABILITY_ADD_CALLER = 1005,
    };

    virtual int StartAbility(const AAFwk::Want &want, const sptr<IRemoteObject> &callerToken,
        int requestCode = DEFAULT_INVAL_VALUE, int32_t userId = DEFAULT_INVAL_VALUE) = 0;
};

class AbilityManagerPrivacyProxy : public IRemoteProxy<IAbilityManager> {
public:
    explicit AbilityManagerPrivacyProxy(const sptr<IRemoteObject>& impl) : IRemoteProxy<IAbilityManager>(impl) {};

    ~AbilityManagerPrivacyProxy() {};
    int StartAbility(const AAFwk::Want &want, const sptr<IRemoteObject> &callerToken,
        int requestCode = DEFAULT_INVAL_VALUE, int32_t userId = DEFAULT_INVAL_VALUE) override;

private:
    static inline BrokerDelegator<AbilityManagerPrivacyProxy> delegator_;
};
}
}
}
#endif // OHOS_ABILITY_MANAGER_PRIVACY_PROXY_H
