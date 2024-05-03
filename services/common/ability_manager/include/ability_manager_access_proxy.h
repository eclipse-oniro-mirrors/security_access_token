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

#ifndef OHOS_ABILITY_MANAGER_ACCESS_PROXY_H
#define OHOS_ABILITY_MANAGER_ACCESS_PROXY_H

#include <iremote_proxy.h>

#include "service_ipc_interface_code.h"
#include "want.h"

namespace OHOS {
namespace Security {
namespace AccessToken {
const int DEFAULT_INVAL_VALUE = -1;
class IAbilityManager : public IRemoteBroker {
public:
    DECLARE_INTERFACE_DESCRIPTOR(u"ohos.aafwk.AbilityManager")

    virtual int StartAbility(const AAFwk::Want &want, const sptr<IRemoteObject> &callerToken,
        int requestCode = DEFAULT_INVAL_VALUE, int32_t userId = DEFAULT_INVAL_VALUE) = 0;
};

class AbilityManagerAccessProxy : public IRemoteProxy<IAbilityManager> {
public:
    explicit AbilityManagerAccessProxy(const sptr<IRemoteObject>& impl) : IRemoteProxy<IAbilityManager>(impl) {}

    ~AbilityManagerAccessProxy() {}
    int StartAbility(const AAFwk::Want &want, const sptr<IRemoteObject> &callerToken,
        int requestCode = DEFAULT_INVAL_VALUE, int32_t userId = DEFAULT_INVAL_VALUE) override;

private:
    static inline BrokerDelegator<AbilityManagerAccessProxy> delegator_;
};
}
}
}
#endif // OHOS_ABILITY_MANAGER_ACCESS_PROXY_H
