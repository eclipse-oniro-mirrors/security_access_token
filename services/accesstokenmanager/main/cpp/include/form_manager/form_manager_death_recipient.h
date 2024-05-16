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

#ifndef ACCESS_FORM_MANAGER_DEATH_RECIPIENT_H
#define ACCESS_FORM_MANAGER_DEATH_RECIPIENT_H

#include "iremote_object.h"

namespace OHOS {
namespace Security {
namespace AccessToken {
class FormMgrDeathRecipient : public IRemoteObject::DeathRecipient {
public:
    FormMgrDeathRecipient() {}
    virtual ~FormMgrDeathRecipient() override = default;
    void OnRemoteDied(const wptr<IRemoteObject>& object) override;
};
}  // namespace AccessToken
}  // namespace Security
}  // namespace OHOS
#endif  // ACCESS_FORM_MANAGER_DEATH_RECIPIENT_H