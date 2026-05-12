/*
 * Copyright (c) 2026 Huawei Device Co., Ltd.
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

#ifndef PERMISSION_CHANGE_NOTIFIER_H
#define PERMISSION_CHANGE_NOTIFIER_H

#include <cstdint>
#include <shared_mutex>
#include <string>
#include <vector>

#include "access_token.h"

namespace OHOS {
namespace Security {
namespace AccessToken {
class PermissionChangeNotifier final {
public:
    static PermissionChangeNotifier& GetInstance();

    void ParamUpdate(const std::string& permissionName, uint32_t flag, bool filtered);
    void ParamFlagUpdate();

private:
    PermissionChangeNotifier();
    ~PermissionChangeNotifier() = default;

    std::shared_mutex permParamSetLock_;
    uint64_t paramValue_ = 0;

    std::shared_mutex permFlagParamSetLock_;
    uint64_t paramFlagValue_ = 0;
};
} // namespace AccessToken
} // namespace Security
} // namespace OHOS
#endif // PERMISSION_CHANGE_NOTIFIER_H
