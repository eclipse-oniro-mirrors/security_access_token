/*
 * Copyright (c) 2025 Huawei Device Co., Ltd.
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

#ifndef SEC_AT_DISABLE_POLICY_CBK_MANAGER_H
#define SEC_AT_DISABLE_POLICY_CBK_MANAGER_H

#include <shared_mutex>
#include <vector>

#ifdef EVENTHANDLER_ENABLE
#include "access_event_handler.h"
#endif
#include "access_token.h"
#include "accesstoken_common_log.h"
#include "nocopyable.h"
#include "perm_disable_policy_info.h"
#include "perm_disable_policy_cbk_death_recipient.h"
#include "perm_disable_policy_cbk_proxy.h"
#include "singleton.h"

namespace OHOS {
namespace Security {
namespace AccessToken {
struct DisableCallbackData {
    DisableCallbackData(AccessTokenID registerTokenId, const std::vector<std::string>& permList,
        const sptr<IRemoteObject> callback)
        : registerTokenId(registerTokenId), permList(permList), callbackObject(callback) {}

    AccessTokenID registerTokenId;
    std::vector<std::string> permList;
    sptr<IRemoteObject> callbackObject;
};

class DisablePolicyCbkManager : public DelayedSingleton<DisablePolicyCbkManager> {
public:
    DisablePolicyCbkManager();
    virtual ~DisablePolicyCbkManager();

    int32_t AddCallback(AccessTokenID registerTokenId, const std::vector<std::string>& permList,
        const sptr<IRemoteObject>& callback);
    int32_t RemoveCallback(const sptr<IRemoteObject>& callback);
    void ExecuteCallbackAsync(const PermDisablePolicyInfo& info);

private:
    DISALLOW_COPY_AND_MOVE(DisablePolicyCbkManager);

    uint32_t GetCurCallbackSize();
    void AddToCallbackList(AccessTokenID registerTokenId, const std::vector<std::string>& permList,
        const sptr<IRemoteObject>& callback);
    void RemoveFromCallbackList(const sptr<IRemoteObject>& callback);
    bool NeedCalled(const std::vector<std::string>& permList, const std::string& permName);
    void GetCallbackFromList(const std::string& permissionName, std::vector<sptr<IRemoteObject>>& list);
    void PermDisablePolicyCallback(const PermDisablePolicyInfo& info);

    std::shared_mutex callbackMutex_;
    std::vector<DisableCallbackData> callbackDataList_;
    sptr<IRemoteObject::DeathRecipient> callbackDeathRecipient_;
#ifdef EVENTHANDLER_ENABLE
    std::mutex eventHandlerLock_;
    std::shared_ptr<AccessEventHandler> eventHandler_;
    std::shared_ptr<AccessEventHandler> GetEventHandler();
    void InitEventHandler();
#endif
};
} // namespace AccessToken
} // namespace Security
} // namespace OHOS
#endif // SEC_AT_DISABLE_POLICY_CBK_MANAGER_H
