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

#ifndef TOKEN_MODIFY_NOTIFIER_H
#define TOKEN_MODIFY_NOTIFIER_H

#include <atomic>
#include <set>
#include <vector>

#include "access_token.h"
#include "i_token_sync_callback.h"
#include "nocopyable.h"
#include "rwlock.h"
#include "thread_pool.h"
#include "callback_death_recipients.h"

namespace OHOS {
namespace Security {
namespace AccessToken {
class TokenModifyNotifier final {
public:
    static TokenModifyNotifier& GetInstance();
    ~TokenModifyNotifier();
    void AddHapTokenObservation(AccessTokenID tokenID);
    void NotifyTokenDelete(AccessTokenID tokenID);
    void NotifyTokenModify(AccessTokenID tokenID);
    void NotifyTokenChangedIfNeed();
    void NotifyTokenSyncTask();
    int32_t GetRemoteHapTokenInfo(const std::string& deviceID, AccessTokenID tokenID);
    int32_t RegisterTokenSyncCallback(const sptr<IRemoteObject>& callback);
    void UnRegisterTokenSyncCallback();

private:
    TokenModifyNotifier();
    DISALLOW_COPY_AND_MOVE(TokenModifyNotifier);

    bool hasInited_;
    OHOS::Utils::RWLock initLock_;
    OHOS::Utils::RWLock listLock_;
    OHOS::Utils::RWLock notifyLock_;
    OHOS::ThreadPool notifyTokenWorker_;
    std::set<AccessTokenID> observationSet_;
    std::vector<AccessTokenID> deleteTokenList_;
    std::vector<AccessTokenID> modifiedTokenList_;
    sptr<ITokenSyncCallback> tokenSyncCallbackObject_ = nullptr;
#ifdef TOKEN_SYNC_ENABLE
    sptr<TokenSyncCallbackDeathRecipient> tokenSyncCallbackDeathRecipient_ = nullptr;
#endif
};
} // namespace AccessToken
} // namespace Security
} // namespace OHOS
#endif // TOKEN_MODIFY_NOTIFIER_H
