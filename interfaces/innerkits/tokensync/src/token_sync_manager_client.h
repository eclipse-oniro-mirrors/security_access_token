/*
 * Copyright (c) 2022 Huawei Device Co., Ltd.
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

#ifndef ACCESSTOKEN_MANAGER_CLIENT_H
#define ACCESSTOKEN_MANAGER_CLIENT_H

#include <string>
#include <mutex>
#include <condition_variable>

#include "access_token.h"
#include "hap_token_info.h"
#include "i_token_sync_manager.h"
#include "nocopyable.h"

namespace OHOS {
namespace Security {
namespace AccessToken {
class TokenSyncManagerClient final {
public:
    static const int TOKEN_SYNC_LOAD_SA_TIMEOUT_MS = 60000;

    static TokenSyncManagerClient& GetInstance();

    virtual ~TokenSyncManagerClient();

    int GetRemoteHapTokenInfo(const std::string& deviceID, AccessTokenID tokenID);
    int DeleteRemoteHapTokenInfo(AccessTokenID tokenID);
    int UpdateRemoteHapTokenInfo(const HapTokenInfoForSync& tokenInfo);
    void LoadTokenSync();
    void FinishStartSASuccess(const sptr<IRemoteObject>& remoteObject);
    void FinishStartSAFailed();
    void SetRemoteObject(const sptr<IRemoteObject>& remoteObject);
    sptr<IRemoteObject> GetRemoteObject();
    void OnRemoteDiedHandle();

private:
    std::condition_variable tokenSyncCon_;
    std::mutex tokenSyncMutex_;
    std::mutex remoteMutex_;
    bool ready_ = false;
    sptr<IRemoteObject> remoteObject_ = nullptr;

    TokenSyncManagerClient();

    DISALLOW_COPY_AND_MOVE(TokenSyncManagerClient);

    sptr<ITokenSyncManager> GetProxy();
};
} // namespace AccessToken
} // namespace Security
} // namespace OHOS
#endif // ACCESSTOKEN_MANAGER_CLIENT_H
