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

#ifndef ACCESS_FORM_MANAGER_ACCESS_CLIENT_H
#define ACCESS_FORM_MANAGER_ACCESS_CLIENT_H

#include <mutex>
#include <string>

#include "form_status_change_callback.h"
#include "form_manager_death_recipient.h"
#include "form_manager_access_proxy.h"
#include "nocopyable.h"

namespace OHOS {
namespace Security {
namespace AccessToken {
class FormManagerAccessClient final {
public:
    static FormManagerAccessClient& GetInstance();
    virtual ~FormManagerAccessClient();

    int32_t RegisterAddObserver(const std::string &bundleName, const sptr<IRemoteObject> &callerToken);
    int32_t RegisterRemoveObserver(const std::string &bundleName, const sptr<IRemoteObject> &callerToken);
    bool HasFormVisible(const uint32_t tokenId);
    void OnRemoteDiedHandle();

private:
    FormManagerAccessClient();
    DISALLOW_COPY_AND_MOVE(FormManagerAccessClient);

    void InitProxy();
    sptr<IFormMgr> GetProxy();

    sptr<FormMgrDeathRecipient> serviceDeathObserver_ = nullptr;
    std::mutex proxyMutex_;
    sptr<IFormMgr> proxy_ = nullptr;
};
} // namespace AccessToken
} // namespace Security
} // namespace OHOS
#endif // ACCESS_FORM_MANAGER_ACCESS_CLIENT_H

