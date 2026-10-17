/*
 * Copyright (C) 2025-2026 Huawei Device Co., Ltd.
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

#include "parameters.h"
#include "accesstoken_common_log.h"

namespace OHOS {
namespace system {
std::map<std::string, bool> systemParameter = {{"const.security.developermode.state", true}};

bool GetBoolParameter(const std::string& key, bool def)
{
    auto iter = system::systemParameter.find(key);
    if (iter != system::systemParameter.end()) {
        return system::systemParameter[key];
    } else {
        return def;
    }
}
void SetBoolParameter(const std::string& key, bool status)
{
    auto iter = system::systemParameter.find(key);
    if (iter != system::systemParameter.end()) {
        iter->second = status;
    } else {
        system::systemParameter[key] = status;
    }
}
}
} // namespace OHOS
