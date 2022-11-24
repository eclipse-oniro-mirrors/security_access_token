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

#ifndef PRIVACY_APP_STATUS_CHANGE_CALLBACK_H
#define PRIVACY_APP_STATUS_CHANGE_CALLBACK_H

#include <vector>
#include "app_manager_privacy_proxy.h"
#include "iremote_stub.h"
#include "nocopyable.h"

namespace OHOS {
namespace Security {
namespace AccessToken {
class ApplicationStateObserverStub : public IRemoteStub<IApplicationStateObserver> {
public:
    ApplicationStateObserverStub();
    virtual ~ApplicationStateObserverStub();

    virtual int OnRemoteRequest(
        uint32_t code, MessageParcel &data, MessageParcel &reply, MessageOption &option) override;

    virtual void OnForegroundApplicationChanged(const AppStateData &appStateData) override;
    DISALLOW_COPY_AND_MOVE(ApplicationStateObserverStub);
private:
    int32_t HandleOnForegroundApplicationChanged(MessageParcel &data, MessageParcel &reply);
};
} // namespace AccessToken
} // namespace Security
} // namespace OHOS
#endif // PRIVACY_APP_STATUS_CHANGE_CALLBACK_H
