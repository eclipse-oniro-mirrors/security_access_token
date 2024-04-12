/*
 * Copyright (c) 2022-2024 Huawei Device Co., Ltd.
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

#ifndef PERM_STATE_CALLBACK_DEATH_RECIPIENT_H
#define PERM_STATE_CALLBACK_DEATH_RECIPIENT_H

#include "iremote_object.h"

namespace OHOS {
namespace Security {
namespace AccessToken {
class PermStateCallbackDeathRecipient : public IRemoteObject::DeathRecipient {
public:
    PermStateCallbackDeathRecipient() = default;
    virtual ~PermStateCallbackDeathRecipient() override = default;

    virtual void OnRemoteDied(const wptr<IRemoteObject>& remote) override;
};

#ifdef TOKEN_SYNC_ENABLE
class TokenSyncCallbackDeathRecipient : public IRemoteObject::DeathRecipient {
public:
    TokenSyncCallbackDeathRecipient() = default;
    virtual ~TokenSyncCallbackDeathRecipient() override = default;

    virtual void OnRemoteDied(const wptr<IRemoteObject>& remote) override;
};
#endif // TOKEN_SYNC_ENABLE
} // namespace AccessToken
} // namespace Security
} // namespace OHOS
#endif // PERM_STATE_CALLBACK_DEATH_RECIPIENT_H
