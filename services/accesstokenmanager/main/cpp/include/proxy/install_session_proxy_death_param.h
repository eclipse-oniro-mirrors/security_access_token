/*
 * Copyright (c) 2026 Huawei Device Co., Ltd.
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 *
 *     http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 */

#ifndef INSTALL_SESSION_PROXY_DEATH_PARAM_H
#define INSTALL_SESSION_PROXY_DEATH_PARAM_H

#include <cstdint>
#include "proxy_death_param.h"

namespace OHOS {
namespace Security {
namespace AccessToken {

class InstallSessionProxyDeathParam : public ProxyDeathParam {
public:
    explicit InstallSessionProxyDeathParam(int32_t pid) : pid_(pid) {}
    ~InstallSessionProxyDeathParam() override = default;
    
    void ProcessParam() override;
    bool IsEqual(ProxyDeathParam* param) override;

private:
    int32_t pid_ = 0;
};

} // namespace AccessToken
} // namespace Security
} // namespace OHOS

#endif // INSTALL_SESSION_PROXY_DEATH_PARAM_H