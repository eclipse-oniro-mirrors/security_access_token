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

#ifndef ACCESS_APP_MANAGER_ACCESS_CLIENT_H
#define ACCESS_APP_MANAGER_ACCESS_CLIENT_H

#include <mutex>
#include <string>

#include "app_manager_access_proxy.h"
#include "nocopyable.h"

namespace OHOS {
namespace Security {
namespace AccessToken {
class AppManagerAccessClient final {
public:
    static AppManagerAccessClient& GetInstance();
    virtual ~AppManagerAccessClient();
    int32_t GetForegroundApplications(std::vector<AppStateData>& list);
    void OnRemoteDiedHandle();

private:
    AppManagerAccessClient();
    DISALLOW_COPY_AND_MOVE(AppManagerAccessClient);

    void InitProxy();
    sptr<IAppMgr> GetProxy();
    void ReleaseProxy();

    std::mutex proxyMutex_;
    sptr<IAppMgr> proxy_ = nullptr;
};
} // namespace AccessToken
} // namespace Security
} // namespace OHOS
#endif // ACCESS_APP_MANAGER_ACCESS_CLIENT_H

