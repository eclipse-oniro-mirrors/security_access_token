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

#include "form_status_change_callback.h"
#include "access_token.h"
#include "accesstoken_log.h"
#include "access_token_error.h"

namespace OHOS {
namespace Security {
namespace AccessToken {
namespace {
static constexpr int32_t MAX_ALLOW_SIZE = 8 * 1024;
static constexpr OHOS::HiviewDFX::HiLogLabel LABEL = {
    LOG_CORE, SECURITY_DOMAIN_ACCESSTOKEN, "FormStateObserverStub"
};
}

FormStateObserverStub::FormStateObserverStub()
{
    ACCESSTOKEN_LOG_INFO(LABEL, "FormStateObserverStub Instance create.");
}

FormStateObserverStub::~FormStateObserverStub()
{
    ACCESSTOKEN_LOG_INFO(LABEL, "FormStateObserverStub Instance destroy.");
}

int32_t FormStateObserverStub::OnRemoteRequest(
    uint32_t code, MessageParcel &data, MessageParcel &reply, MessageOption &option)
{
    if (data.ReadInterfaceToken() != GetDescriptor()) {
        ACCESSTOKEN_LOG_INFO(LABEL, "FormStateObserverStub: ReadInterfaceToken failed.");
        return ERROR_IPC_REQUEST_FAIL;
    }
    switch (static_cast<IJsFormStateObserver::Message>(code)) {
        case IJsFormStateObserver::Message::FORM_STATE_OBSERVER_NOTIFY_WHETHER_FORMS_VISIBLE: {
            HandleNotifyWhetherFormsVisible(data, reply);
            return NO_ERROR;
        }
        default: {
            ACCESSTOKEN_LOG_DEBUG(LABEL, "Default case code: %{public}d.", code);
            return IPCObjectStub::OnRemoteRequest(code, data, reply, option);
        }
    }
    return NO_ERROR;
}

int32_t FormStateObserverStub::HandleNotifyWhetherFormsVisible(MessageParcel &data, MessageParcel &reply)
{
    FormVisibilityType visibleType = static_cast<FormVisibilityType>(data.ReadInt32());
    std::string bundleName = data.ReadString();
    std::vector<FormInstance> formInstances;
    int32_t infoSize = data.ReadInt32();
    if (infoSize < 0 || infoSize > MAX_ALLOW_SIZE) {
        ACCESSTOKEN_LOG_ERROR(LABEL, "Invalid size: %{public}d.", infoSize);
        return ERR_OVERSIZE;
    }
    for (int32_t i = 0; i < infoSize; i++) {
        std::unique_ptr<FormInstance> info(data.ReadParcelable<FormInstance>());
        if (info == nullptr) {
            ACCESSTOKEN_LOG_ERROR(LABEL, "Failed to Read Parcelable infos.");
            return RET_FAILED;
        }
        formInstances.emplace_back(*info);
    }
    NotifyWhetherFormsVisible(visibleType, bundleName, formInstances);
    return NO_ERROR;
}
} // namespace AccessToken
} // namespace Security
} // namespace OHOS
