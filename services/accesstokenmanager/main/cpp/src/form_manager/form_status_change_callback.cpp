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
#include "accesstoken_common_log.h"
#include "access_token_error.h"

namespace OHOS {
namespace Security {
namespace AccessToken {
namespace {
static constexpr int32_t MAX_ALLOW_SIZE = 8 * 1024;
}

FormStateObserverStub::FormStateObserverStub()
{
    LOGI(ATM_DOMAIN, ATM_TAG, "FormStateObserverStub Instance create.");
}

FormStateObserverStub::~FormStateObserverStub()
{
    LOGI(ATM_DOMAIN, ATM_TAG, "FormStateObserverStub Instance destroy.");
}

int32_t FormStateObserverStub::OnRemoteRequest(
    uint32_t code, MessageParcel &data, MessageParcel &reply, MessageOption &option)
{
    if (data.ReadInterfaceToken() != GetDescriptor()) {
        LOGI(ATM_DOMAIN, ATM_TAG, "FormStateObserverStub: ReadInterfaceToken failed.");
        return ERROR_IPC_REQUEST_FAIL;
    }
    switch (static_cast<IJsFormStateObserver::Message>(code)) {
        case IJsFormStateObserver::Message::FORM_STATE_OBSERVER_NOTIFY_WHETHER_FORMS_VISIBLE: {
            (void)HandleNotifyWhetherFormsVisible(data, reply);
            return NO_ERROR;
        }
        default: {
            LOGD(ATM_DOMAIN, ATM_TAG, "Default case code: %{public}d.", code);
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
        LOGE(ATM_DOMAIN, ATM_TAG, "Invalid size: %{public}d.", infoSize);
        return ERR_OVERSIZE;
    }
    for (int32_t i = 0; i < infoSize; i++) {
        std::unique_ptr<FormInstance> info(data.ReadParcelable<FormInstance>());
        if (info == nullptr) {
            LOGE(ATM_DOMAIN, ATM_TAG, "Failed to Read Parcelable infos.");
            return RET_FAILED;
        }
        formInstances.emplace_back(*info);
    }
    (void)NotifyWhetherFormsVisible(visibleType, bundleName, formInstances);
    return NO_ERROR;
}
} // namespace AccessToken
} // namespace Security
} // namespace OHOS
