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

#ifndef ACCESS_TOKEN_PERMISSION_CALLBACK_MANAGER_H
#define ACCESS_TOKEN_PERMISSION_CALLBACK_MANAGER_H

#include <mutex>
#include <vector>

#include "access_token.h"
#include "accesstoken_log.h"
#ifdef RESOURCESCHEDULE_FFRT_ENABLE
#include "ffrt.h"
#endif
#include "i_permission_state_callback.h"
#include "permission_state_change_info.h"
#include "accesstoken_callback_proxys.h"

namespace OHOS {
namespace Security {
namespace AccessToken {
enum PermStateChangeType {
    REVOKED = 0,
    GRANTED = 1,
};
struct CallbackRecord {
    CallbackRecord() : scopePtr_(nullptr), callbackObject_(nullptr)
    {}
    CallbackRecord(std::shared_ptr<PermStateChangeScope> callbackScopePtr, sptr<IRemoteObject> callback)
        : scopePtr_(callbackScopePtr), callbackObject_(callback)
    {}

    std::shared_ptr<PermStateChangeScope> scopePtr_;
    sptr<IRemoteObject> callbackObject_;
};

class CallbackManager {
public:
    virtual ~CallbackManager();
    CallbackManager();
    static CallbackManager& GetInstance();

    int32_t AddCallback(const PermStateChangeScope& scope, const sptr<IRemoteObject>& callback);
    int32_t RemoveCallback(const sptr<IRemoteObject>& callback);
    bool CalledAccordingToTokenIdLlist(const std::vector<AccessTokenID>& tokenIDList, AccessTokenID tokenID);
    bool CalledAccordingToPermLlist(const std::vector<std::string>& permList, const std::string& permName);
    void ExecuteCallbackAsync(AccessTokenID tokenID, const std::string& permName, int32_t changeType);

private:
    void ExcuteAllCallback(std::vector<sptr<IRemoteObject>>& list, AccessTokenID tokenID, const std::string& permName,
        int32_t changeType);
    void GetCallbackObjectList(AccessTokenID tokenID, const std::string& permName,
        std::vector<sptr<IRemoteObject>>& list);
#ifdef RESOURCESCHEDULE_FFRT_ENABLE
    ffrt::mutex mutex_;
#else
    std::mutex mutex_;
#endif
    std::vector<CallbackRecord> callbackInfoList_;
    sptr<IRemoteObject::DeathRecipient> callbackDeathRecipient_;
};
} // namespace AccessToken
} // namespace Security
} // namespace OHOS
#endif // ACCESS_TOKEN_PERMISSION_CALLBACK_MANAGER_H
