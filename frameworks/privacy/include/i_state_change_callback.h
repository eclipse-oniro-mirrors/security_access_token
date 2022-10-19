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

#ifndef I_STATE_CHANGE_CALLBACK_H
#define I_STATE_CHANGE_CALLBACK_H

#include "iremote_broker.h"
#include "access_token.h"

namespace OHOS {
namespace Security {
namespace AccessToken {
class IStateChangeCallback : public IRemoteBroker {
public:
    DECLARE_INTERFACE_DESCRIPTOR(u"ohos.security.privacy.IStateChangeCallback");

    virtual void StateChangeNotify(AccessTokenID tokenId, bool isShowing) = 0;

    enum {
        STATE_CHANGE_CALLBACK = 0,
    };
};
} // namespace AccessToken
} // namespace Security
} // namespace OHOS

#endif // I_STATE_CHANGE_CALLBACK_H
