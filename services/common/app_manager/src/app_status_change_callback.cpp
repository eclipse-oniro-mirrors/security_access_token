/*
 * Copyright (c) 2022-2023 Huawei Device Co., Ltd.
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

#include "app_status_change_callback.h"
#include "accesstoken_common_log.h"
#include "access_token_error.h"

namespace OHOS {
namespace Security {
namespace AccessToken {

ApplicationStateObserverStub::ApplicationStateObserverStub()
{
    LOGI(ATM_DOMAIN, ATM_TAG, "ApplicationStateObserverStub Instance create");
}

ApplicationStateObserverStub::~ApplicationStateObserverStub()
{
    LOGI(ATM_DOMAIN, ATM_TAG, "ApplicationStateObserverStub Instance destroy");
}

int32_t ApplicationStateObserverStub::OnRemoteRequest(
    uint32_t code, MessageParcel &data, MessageParcel &reply, MessageOption &option)
{
    if (data.ReadInterfaceToken() != GetDescriptor()) {
        LOGI(ATM_DOMAIN, ATM_TAG, "ApplicationStateObserverStub: ReadInterfaceToken failed");
        return ERROR_IPC_REQUEST_FAIL;
    }
    switch (static_cast<IApplicationStateObserver::Message>(code)) {
        case IApplicationStateObserver::Message::TRANSACT_ON_PROCESS_STATE_CHANGED: {
            HandleOnProcessStateChanged(data, reply);
            return NO_ERROR;
        }
        case IApplicationStateObserver::Message::TRANSACT_ON_PROCESS_DIED: {
            HandleOnProcessDied(data, reply);
            return NO_ERROR;
        }
        case IApplicationStateObserver::Message::TRANSACT_ON_APP_STATE_CHANGED: {
            HandleOnAppStateChanged(data, reply);
            return NO_ERROR;
        }
        case IApplicationStateObserver::Message::TRANSACT_ON_APP_STOPPED: {
            HandleOnAppStopped(data, reply);
            return NO_ERROR;
        }
        case IApplicationStateObserver::Message::TRANSACT_ON_APP_CACHE_STATE_CHANGED: {
            HandleOnAppCacheStateChanged(data, reply);
            return NO_ERROR;
        }
        default: {
            LOGD(ATM_DOMAIN, ATM_TAG, "Default case, need check AudioListenerStub");
            return IPCObjectStub::OnRemoteRequest(code, data, reply, option);
        }
    }
    return NO_ERROR;
}

int32_t ApplicationStateObserverStub::HandleOnProcessStateChanged(MessageParcel &data, MessageParcel &reply)
{
    std::unique_ptr<ProcessData> processData(data.ReadParcelable<ProcessData>());
    if (processData == nullptr) {
        LOGE(ATM_DOMAIN, ATM_TAG, "ReadParcelable failed");
        return -1;
    }

    OnProcessStateChanged(*processData);
    return NO_ERROR;
}

int32_t ApplicationStateObserverStub::HandleOnProcessDied(MessageParcel &data, MessageParcel &reply)
{
    std::unique_ptr<ProcessData> processData(data.ReadParcelable<ProcessData>());
    if (processData == nullptr) {
        LOGE(ATM_DOMAIN, ATM_TAG, "ReadParcelable failed");
        return -1;
    }

    OnProcessDied(*processData);
    return NO_ERROR;
}

int32_t ApplicationStateObserverStub::HandleOnAppStateChanged(MessageParcel &data, MessageParcel &reply)
{
    std::unique_ptr<AppStateData> processData(data.ReadParcelable<AppStateData>());
    if (processData == nullptr) {
        LOGE(ATM_DOMAIN, ATM_TAG, "ReadParcelable failed");
        return -1;
    }

    OnAppStateChanged(*processData);
    return NO_ERROR;
}

int32_t ApplicationStateObserverStub::HandleOnAppStopped(MessageParcel &data, MessageParcel &reply)
{
    std::unique_ptr<AppStateData> appStateData(data.ReadParcelable<AppStateData>());
    if (appStateData == nullptr) {
        LOGE(ATM_DOMAIN, ATM_TAG, "ReadParcelable failed");
        return -1;
    }

    OnAppStopped(*appStateData);
    return NO_ERROR;
}

int32_t ApplicationStateObserverStub::HandleOnAppCacheStateChanged(MessageParcel &data, MessageParcel &reply)
{
    std::unique_ptr<AppStateData> appStateData(data.ReadParcelable<AppStateData>());
    if (appStateData == nullptr) {
        LOGE(ATM_DOMAIN, ATM_TAG, "ReadParcelable failed");
        return -1;
    }

    OnAppCacheStateChanged(*appStateData);
    return NO_ERROR;
}
} // namespace AccessToken
} // namespace Security
} // namespace OHOS
