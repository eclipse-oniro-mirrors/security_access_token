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

#ifndef PRIVACY_PROXY_DEATH_PARAM_H
#define PRIVACY_PROXY_DEATH_PARAM_H

#include "privacy_manager_proxy_death_param.h"

#include <cstdint>
#include "accesstoken_common_log.h"
#include "access_token.h"
#include "proxy_death_param.h"

namespace OHOS {
namespace Security {
namespace AccessToken {

class PrivacyManagerProxyDeathParam : public ProxyDeathParam {
public:
    PrivacyManagerProxyDeathParam(int32_t callerPid);
    ~PrivacyManagerProxyDeathParam() override {};
    void ProcessParam() override;
    bool IsEqual(ProxyDeathParam* param) override;
private:
    int32_t pid_;
};

}  // namespace AccessToken
} // namespace Security
}  // namespace OHOS
#endif  // PRIVACY_PROXY_DEATH_PARAM_H