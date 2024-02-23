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
#include "accesstoken_log.h"
#include "access_token_error.h"

namespace OHOS {
namespace Security {
namespace AccessToken {
namespace {
static constexpr OHOS::HiviewDFX::HiLogLabel LABEL = {
    LOG_CORE, SECURITY_DOMAIN_ACCESSTOKEN, "ApplicationStateObserverStub"
};
}

ApplicationStateObserverStub::ApplicationStateObserverStub()
{
    ACCESSTOKEN_LOG_INFO(LABEL, "ApplicationStateObserverStub Instance create");
}

ApplicationStateObserverStub::~ApplicationStateObserverStub()
{
    ACCESSTOKEN_LOG_INFO(LABEL, "ApplicationStateObserverStub Instance destroy");
}

int32_t ApplicationStateObserverStub::OnRemoteRequest(
    uint32_t code, MessageParcel &data, MessageParcel &reply, MessageOption &option)
{
    if (data.ReadInterfaceToken() != GetDescriptor()) {
        ACCESSTOKEN_LOG_INFO(LABEL, "ApplicationStateObserverStub: ReadInterfaceToken failed");
        return ERROR_IPC_REQUEST_FAIL;
    }
    switch (static_cast<IApplicationStateObserver::Message>(code)) {
        case IApplicationStateObserver::Message::TRANSACT_ON_FOREGROUND_APPLICATION_CHANGED: {
            HandleOnForegroundApplicationChanged(data, reply);
            return NO_ERROR;
        }
        case IApplicationStateObserver::Message::TRANSACT_ON_PROCESS_DIED: {
            HandleOnProcessDied(data, reply);
            return NO_ERROR;
        }
        case IApplicationStateObserver::Message::TRANSACT_ON_APPLICATION_STATE_CHANGED: {
            HandleOnApplicationStateChanged(data, reply);
            return NO_ERROR;
        }
        default: {
            ACCESSTOKEN_LOG_DEBUG(LABEL, "default case, need check AudioListenerStub");
            return IPCObjectStub::OnRemoteRequest(code, data, reply, option);
        }
    }
    return NO_ERROR;
}

int32_t ApplicationStateObserverStub::HandleOnForegroundApplicationChanged(MessageParcel &data, MessageParcel &reply)
{
    std::unique_ptr<AppStateData> processData(data.ReadParcelable<AppStateData>());
    if (processData == nullptr) {
        ACCESSTOKEN_LOG_ERROR(LABEL, "ReadParcelable failed");
        return -1;
    }

    OnForegroundApplicationChanged(*processData);
    return NO_ERROR;
}

int32_t ApplicationStateObserverStub::HandleOnProcessDied(MessageParcel &data, MessageParcel &reply)
{
    std::unique_ptr<ProcessData> processData(data.ReadParcelable<ProcessData>());
    if (processData == nullptr) {
        ACCESSTOKEN_LOG_ERROR(LABEL, "ReadParcelable failed");
        return -1;
    }

    OnProcessDied(*processData);
    return NO_ERROR;
}

int32_t ApplicationStateObserverStub::HandleOnApplicationStateChanged(MessageParcel &data, MessageParcel &reply)
{
    std::unique_ptr<AppStateData> appStateData(data.ReadParcelable<AppStateData>());
    if (appStateData == nullptr) {
        ACCESSTOKEN_LOG_ERROR(LABEL, "ReadParcelable failed");
        return -1;
    }

    OnApplicationStateChanged(*appStateData);
    return NO_ERROR;
}
} // namespace AccessToken
} // namespace Security
} // namespace OHOS
