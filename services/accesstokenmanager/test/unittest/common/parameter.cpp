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

#include <cstring>
#include <map>
#include <securec.h>
#include <string>

#include "accesstoken_info_utils.h"
#include "parameter.h"

static std::map<std::string, std::string> systemParameter = {
    {OHOS::Security::AccessToken::ACCESS_TOKEN_SERVICE_APP_VERIFY_KEY, "0"},
    {OHOS::Security::AccessToken::ACCESS_TOKEN_SERVICE_SPM_ENFORCING_KEY, "0"}
};

static constexpr int32_t VALUE_MAX_LEN = 32;

int GetParameter(const char *key, const char *def, char *value, uint32_t len)
{
    if (key != nullptr && strcmp(key, "const.cust.config_dir_layer") == 0) {
        const char* dirs = "/data/cust:/system/cust";
        size_t dirsLen = strlen(dirs);
        if (value != nullptr && len > dirsLen) {
            if (strncpy_s(value, len - 1, dirs, dirsLen) != EOK) {
                return 0;
            }
            value[len - 1] = '\0';
        }
        return static_cast<int>(dirsLen);
    }

    auto it = systemParameter.find(key);
    if (it != systemParameter.end()) {
        (void)memcpy_s(value, len, it->second.c_str(), it->second.length());
    }
    return 0;
}

int SetParameter(const char *key, const char *value)
{
    if (key == nullptr || value == nullptr || strlen(value) >= VALUE_MAX_LEN) {
        return -1;
    }
    systemParameter[key] = value;
    return 0;
}
