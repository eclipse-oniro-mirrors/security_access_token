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

#ifndef ACCESS_TOKEN_MANAGER_SYSTEM_ABILITY_STATUS_CHANGE_LISTENER_H
#define ACCESS_TOKEN_MANAGER_SYSTEM_ABILITY_STATUS_CHANGE_LISTENER_H

#include <functional>
#include <string>

#include "system_ability_status_change_stub.h"

namespace OHOS {
namespace Security {
namespace AccessToken {
using SubscribeSACallbackFunc = std::function<void(int32_t, const std::string&)>;
class AtmSystemAbilityStatusChangeListener : public OHOS::SystemAbilityStatusChangeStub {
public:
    explicit AtmSystemAbilityStatusChangeListener(const SubscribeSACallbackFunc& callback);
    ~AtmSystemAbilityStatusChangeListener() = default;
    void OnAddSystemAbility(int32_t systemAbilityId, const std::string& deviceId) override;
    void OnRemoveSystemAbility(int32_t systemAbilityId, const std::string& deviceId) override;

private:
    SubscribeSACallbackFunc callback_ = nullptr;
};
} // namespace AccessToken
} // namespace Security
} // namespace OHOS

#endif // ACCESS_TOKEN_MANAGER_SYSTEM_ABILITY_STATUS_CHANGE_LISTENER_H
