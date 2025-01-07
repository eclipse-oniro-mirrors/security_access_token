/*
 * Copyright (c) 2024 Huawei Device Co., Ltd.
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 *
 * http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 */

#ifndef EL5_FILEKEY_MANAGER_CLIENT_H
#define EL5_FILEKEY_MANAGER_CLIENT_H

#include "el5_filekey_manager_interface.h"

#include <condition_variable>

namespace OHOS {
namespace Security {
namespace AccessToken {
constexpr int32_t DEFAULT_SA_REQUEST_RETRY_TIMES = 1;
class El5FilekeyManagerClient {
public:
    static El5FilekeyManagerClient &GetInstance();
    ~El5FilekeyManagerClient();

    int32_t AcquireAccess(DataLockType type);
    int32_t ReleaseAccess(DataLockType type);
    int32_t GenerateAppKey(uint32_t uid, const std::string &bundleName, std::string &keyId);
    int32_t DeleteAppKey(const std::string &bundleName, int32_t userId);
    int32_t GetUserAppKey(int32_t userId, bool getAllFlag, std::vector<std::pair<int32_t, std::string>> &keyInfos);
    int32_t ChangeUserAppkeysLoadInfo(int32_t userId, std::vector<std::pair<std::string, bool>> &loadInfos);
    int32_t SetFilePathPolicy();
    int32_t RegisterCallback(const sptr<El5FilekeyCallbackInterface> &callback);
    int32_t GenerateGroupIDKey(uint32_t uid, const std::string &groupID, std::string &keyId);
    int32_t DeleteGroupIDKey(uint32_t uid, const std::string &groupID);
    int32_t QueryAppKeyState(DataLockType type);
    int32_t CallProxyWithRetry(const std::function<int32_t(sptr<El5FilekeyManagerInterface> &)> &func,
        const char *funcName, int32_t retryTimes = DEFAULT_SA_REQUEST_RETRY_TIMES);
    bool IsRequestNeedRetry(int32_t ret);

private:
    El5FilekeyManagerClient();
    DISALLOW_COPY_AND_MOVE(El5FilekeyManagerClient);
    std::mutex proxyMutex_;
    sptr<El5FilekeyManagerInterface> GetProxy();
};
} // namespace AccessToken
} // namespace Security
} // namespace OHOS
#endif // EL5_FILEKEY_MANAGER_CLIENT_H
