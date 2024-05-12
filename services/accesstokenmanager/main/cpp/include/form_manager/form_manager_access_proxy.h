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

#ifndef ACCESS_FORM_MANAGER_ACCESS_PROXY_H
#define ACCESS_FORM_MANAGER_ACCESS_PROXY_H

#include <iremote_proxy.h>
#include "form_instance.h"
#include "running_form_info.h"
#include "service_ipc_interface_code.h"

namespace OHOS {
namespace Security {
namespace AccessToken {
class IJsFormStateObserver : public IRemoteBroker {
public:
    DECLARE_INTERFACE_DESCRIPTOR(u"ohos.aafwk.IJsFormStateObserver");

    virtual int32_t NotifyWhetherFormsVisible(const FormVisibilityType visibleType,
        const std::string &bundleName, std::vector<FormInstance> &formInstances) = 0;

    enum class Message {
        FORM_STATE_OBSERVER_NOTIFY_WHETHER_FORMS_VISIBLE = 4304,
    };
};

class IFormMgr : public IRemoteBroker {
public:
    DECLARE_INTERFACE_DESCRIPTOR(u"ohos.appexecfwk.FormMgr")

    virtual int32_t RegisterAddObserver(const std::string &bundleName, const sptr<IRemoteObject> &callerToken) = 0;
    virtual int32_t RegisterRemoveObserver(const std::string &bundleName, const sptr<IRemoteObject> &callerToken) = 0;
    virtual bool HasFormVisible(const uint32_t tokenId) = 0;

    enum class Message {
        FORM_MGR_REGISTER_ADD_OBSERVER = 3053,
        FORM_MGR_REGISTER_REMOVE_OBSERVER = 3054,
        FORM_MGR_HAS_FORM_VISIBLE_WITH_TOKENID = 3067,
    };
};

class FormManagerAccessProxy : public IRemoteProxy<IFormMgr> {
public:
    explicit FormManagerAccessProxy(const sptr<IRemoteObject>& impl) : IRemoteProxy<IFormMgr>(impl) {}

    virtual ~FormManagerAccessProxy() = default;

    int32_t RegisterAddObserver(const std::string &bundleName, const sptr<IRemoteObject> &callerToken) override;
    int32_t RegisterRemoveObserver(const std::string &bundleName, const sptr<IRemoteObject> &callerToken) override;
    bool HasFormVisible(const uint32_t tokenId) override;
private:
    static inline BrokerDelegator<FormManagerAccessProxy> delegator_;
};
} // namespace AccessToken
} // namespace Security
} // namespace OHOS
#endif // ACCESS_FORM_MANAGER_ACCESS_PROXY_H
