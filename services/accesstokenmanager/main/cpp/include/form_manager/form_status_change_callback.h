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

#ifndef ACCESS_FORM_STATUS_CHANGE_CALLBACK_H
#define ACCESS_FORM_STATUS_CHANGE_CALLBACK_H

#include "form_manager_access_proxy.h"
#include "iremote_stub.h"
#include "nocopyable.h"

namespace OHOS {
namespace Security {
namespace AccessToken {
class FormStateObserverStub : public IRemoteStub<IJsFormStateObserver> {
public:
    FormStateObserverStub();
    virtual ~FormStateObserverStub() override;

    virtual int OnRemoteRequest(
        uint32_t code, MessageParcel &data, MessageParcel &reply, MessageOption &option) override;

    virtual int32_t NotifyWhetherFormsVisible(const FormVisibilityType visibleType,
        const std::string &bundleName, std::vector<FormInstance> &formInstances) override
    {
        return 0;
    }

    DISALLOW_COPY_AND_MOVE(FormStateObserverStub);
private:
    int32_t HandleNotifyWhetherFormsVisible(MessageParcel &data, MessageParcel &reply);
};
} // namespace AccessToken
} // namespace Security
} // namespace OHOS
#endif // ACCESS_FORM_STATUS_CHANGE_CALLBACK_H
