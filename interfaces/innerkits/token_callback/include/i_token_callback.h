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

#ifndef I_TOKEN_CALLBACK_H
#define I_TOKEN_CALLBACK_H

#include <iremote_broker.h>

namespace OHOS {
namespace Security {
namespace AccessToken {
class ITokenCallback : public IRemoteBroker {
public:
    DECLARE_INTERFACE_DESCRIPTOR(u"ohos.security.accesstoken.tokencallback");

    virtual void GrantResultsCallback(
        const std::vector<std::string> &permissions, const std::vector<int> &grantResults) = 0;

    enum InterfaceCode {
        GRANT_RESULT_CALLBACK = 0,
    };
};
} // namespace AccessToken
} // namespace Security
} // namespace OHOS
#endif  // I_TOKEN_CALLBACK_H