/*
 * Copyright (c) 2024 Huawei Device Co., Ltd.
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
#ifndef PRIVACY_WINDOW_MANAGER_DEATH_RECIPIENT_H
#define PRIVACY_WINDOW_MANAGER_DEATH_RECIPIENT_H

#include "iremote_object.h"

namespace OHOS {
namespace Security {
namespace AccessToken {
class PrivacyWindowManagerDeathRecipient : public IRemoteObject::DeathRecipient {
public:
    PrivacyWindowManagerDeathRecipient() {}
    virtual ~PrivacyWindowManagerDeathRecipient() override = default;
    void OnRemoteDied(const wptr<IRemoteObject>& object) override;
};
}  // namespace AccessToken
} // namespace Security
}  // namespace OHOS
#endif  // PRIVACY_WINDOW_MANAGER_DEATH_RECIPIENT_H

