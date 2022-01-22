/*
 * Copyright (c) 2021 Huawei Device Co., Ltd.
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

#ifndef I_TOKENSYNC_MANAGER_H
#define I_TOKENSYNC_MANAGER_H

#include <string>

#include "iremote_broker.h"
#include "errors.h"

namespace OHOS {
namespace Security {
namespace AccessToken {
class ITokenSyncManager : public IRemoteBroker {
public:
    static const int SA_ID_TOKENSYNC_MANAGER_SERVICE = 3504;

    DECLARE_INTERFACE_DESCRIPTOR(u"ohos.security.accesstoken.ITokenSyncManager");

    virtual int VerifyPermission(const std::string& bundleName, const std::string& permissionName, int userId) = 0;

    enum class InterfaceCode {
        VERIFY_PERMISSION = 0xff01,
    };
};
} // namespace AccessToken
} // namespace Security
} // namespace OHOS

#endif // I_TOKENSYNC_MANAGER_H
