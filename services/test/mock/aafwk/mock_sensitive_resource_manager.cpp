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

#include "active_change_response_info.h"
#include "mock_sensitive_resource_manager.h"

namespace OHOS {
namespace Security {
namespace AccessToken {
static uint32_t g_mockFlag = 0;
void SetFlag(uint32_t flag)
{
    g_mockFlag = flag;
}
SensitiveResourceManager::SensitiveResourceManager()
{
}

SensitiveResourceManager::~SensitiveResourceManager()
{
}

bool SensitiveResourceManager::GetAppStatus(const std::string& pkgName, int32_t& status)
{
    if (g_mockFlag == INVALID) {
        return false;
    } else if (g_mockFlag == INACTIVE) {
        status = ActiveChangeType::PERM_INACTIVE;
    } else if (g_mockFlag == FOREGROUND) {
        status = ActiveChangeType::PERM_ACTIVE_IN_FOREGROUND;
    } else if (g_mockFlag == BACKGROUND) {
        status = ActiveChangeType::PERM_ACTIVE_IN_BACKGROUND;
    }
    return true;
}
} // namespace AccessToken
} // namespace Security
} // namespace OHOS
