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

#ifndef EL5_FILEKEY_MANAGER_PROXY_H
#define EL5_FILEKEY_MANAGER_PROXY_H

#include "el5_filekey_manager_interface.h"
#include "el5_filekey_manager_interface_code.h"
#include "iremote_proxy.h"

namespace OHOS {
namespace Security {
namespace AccessToken {
class El5FilekeyManagerProxy : public IRemoteProxy<El5FilekeyManagerInterface> {
public:
    explicit El5FilekeyManagerProxy(const sptr<IRemoteObject> &impl);
    virtual ~El5FilekeyManagerProxy();

    int32_t AcquireAccess(DataLockType type) override;
    int32_t ReleaseAccess(DataLockType type) override;
    int32_t GenerateAppKey(uint32_t uid, const std::string& bundleName, std::string& keyId) override;
    int32_t DeleteAppKey(const std::string& keyId) override;
    int32_t GetUserAppKey(int32_t userId, std::vector<std::pair<int32_t, std::string>> &keyInfos) override;
    int32_t ChangeUserAppkeysLoadInfo(int32_t userId, std::vector<std::pair<std::string, bool>> &loadInfos) override;
    int32_t SetFilePathPolicy() override;
    int32_t RegisterCallback(const sptr<El5FilekeyCallbackInterface> &callback) override;
private:
    static inline BrokerDelegator<El5FilekeyManagerProxy> delegator_;
};
}  // namespace AccessToken
}  // namespace Security
}  // namespace OHOS
#endif // EL5_FILEKEY_MANAGER_PROXY_H
