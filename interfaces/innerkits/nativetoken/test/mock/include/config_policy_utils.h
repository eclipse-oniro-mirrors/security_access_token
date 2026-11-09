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

#ifndef CUSTOMIZATION_CONFIG_POLICY_UTILS_H
#define CUSTOMIZATION_CONFIG_POLICY_UTILS_H

#include <stdint.h>

#ifdef __cplusplus
extern "C" {
#endif

#define MAX_CFG_POLICY_DIRS_CNT 32
#define MAX_PATH_LEN 256

struct CfgFiles {
    char *paths[MAX_CFG_POLICY_DIRS_CNT];
};

struct CfgDir {
    char *paths[MAX_CFG_POLICY_DIRS_CNT];
    char *realPolicyValue;
};

typedef struct CfgDir CfgDir;

void FreeCfgDirList(CfgDir *res);
CfgDir *GetCfgDirList(void);

// Test-only helpers to control the mock behavior.
void MockConfigPolicySetReturnNull(int32_t val);
void MockConfigPolicySetCfgDir(const char *dir);

#ifdef __cplusplus
}
#endif

#endif // CUSTOMIZATION_CONFIG_POLICY_UTILS_H