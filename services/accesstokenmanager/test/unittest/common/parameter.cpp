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

#include "parameter.h"

#include <cstring>
#include <securec.h>

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
    return 0;
}

int SetParameter(const char *key, const char *value)
{
    return 0;
}
