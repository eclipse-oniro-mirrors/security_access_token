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

#ifndef ACCESS_APP_STATUS_CHANGE_CALLBACK_H
#define ACCESS_APP_STATUS_CHANGE_CALLBACK_H

#include <vector>
#include "app_state_data.h"
#include "process_data.h"
#include "iremote_stub.h"
#include "nocopyable.h"

namespace OHOS {
namespace Security {
namespace AccessToken {
class IApplicationStateObserver : public IRemoteBroker {
public:
    DECLARE_INTERFACE_DESCRIPTOR(u"ohos.appexecfwk.IApplicationStateObserver");

    virtual void OnProcessStateChanged(const ProcessData &processData) = 0;
    virtual void OnProcessDied(const ProcessData &processData) = 0;
    virtual void OnAppStateChanged(const AppStateData &appStateData) = 0;
    virtual void OnAppStopped(const AppStateData &appStateData) = 0;
    virtual void OnAppCacheStateChanged(const AppStateData &appStateData) = 0;

    enum class Message {
        TRANSACT_ON_PROCESS_STATE_CHANGED = 4,
        TRANSACT_ON_PROCESS_DIED = 5,
        TRANSACT_ON_APP_STATE_CHANGED = 7,
        TRANSACT_ON_APP_STOPPED = 10,
        TRANSACT_ON_APP_CACHE_STATE_CHANGED = 13,
    };
};

class ApplicationStateObserverStub : public IRemoteStub<IApplicationStateObserver> {
public:
    ApplicationStateObserverStub();
    virtual ~ApplicationStateObserverStub() override;

    virtual int OnRemoteRequest(
        uint32_t code, MessageParcel &data, MessageParcel &reply, MessageOption &option) override;

    virtual void OnProcessStateChanged(const ProcessData &processData) override {}
    virtual void OnProcessDied(const ProcessData &processData) override {}
    virtual void OnAppStateChanged(const AppStateData &appStateData) override {}
    virtual void OnAppStopped(const AppStateData &appStateData) override {}
    virtual void OnAppCacheStateChanged(const AppStateData &appStateData) override {}

    DISALLOW_COPY_AND_MOVE(ApplicationStateObserverStub);
private:
    int32_t HandleOnProcessStateChanged(MessageParcel &data, MessageParcel &reply);
    int32_t HandleOnProcessDied(MessageParcel &data, MessageParcel &reply);
    int32_t HandleOnAppStateChanged(MessageParcel &data, MessageParcel &reply);
    int32_t HandleOnAppStopped(MessageParcel &data, MessageParcel &reply);
    int32_t HandleOnAppCacheStateChanged(MessageParcel &data, MessageParcel &reply);
};
} // namespace AccessToken
} // namespace Security
} // namespace OHOS
#endif // ACCESS_APP_STATUS_CHANGE_CALLBACK_H
