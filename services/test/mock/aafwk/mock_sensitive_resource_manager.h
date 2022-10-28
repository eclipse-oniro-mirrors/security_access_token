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

#ifndef MOCK_RESOURCE_MANAGER_H
#define MOCK_RESOURCE_MANAGER_H

#include <string>
#include "app_mgr_proxy.h"
#include "application_status_change_callback.h"

namespace OHOS {
namespace Security {
namespace AccessToken {
enum FlagType {
    INVALID = -1,
    INACTIVE = 0,
    FOREGROUND = 1,
    BACKGROUND = 2,
};
void SetFlag(uint32_t flag);
class SensitiveResourceManager final {
public:
    static SensitiveResourceManager& GetInstance();
    SensitiveResourceManager();
    virtual ~SensitiveResourceManager();
    
    bool GetAppStatus(const std::string& pkgName, int32_t& status);
};
} // namespace AccessToken
} // namespace Security
} // namespace OHOS
#endif // MOCK_RESOURCE_MANAGER_H
