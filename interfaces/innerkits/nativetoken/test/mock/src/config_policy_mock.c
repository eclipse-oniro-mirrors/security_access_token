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

#include "config_policy_utils.h"

#include <stdint.h>
#include <stdlib.h>
#include <string.h>

static int32_t g_returnNull = 0;
static char g_cfgDir[MAX_PATH_LEN] = {0};

void MockConfigPolicySetReturnNull(int32_t val)
{
    g_returnNull = val;
}

void MockConfigPolicySetCfgDir(const char *dir)
{
    if (dir == NULL) {
        g_cfgDir[0] = '\0';
        return;
    }
    (void)strncpy(g_cfgDir, dir, sizeof(g_cfgDir) - 1);
    g_cfgDir[sizeof(g_cfgDir) - 1] = '\0';
}

CfgDir *GetCfgDirList(void)
{
    if (g_returnNull != 0) {
        return NULL;
    }
    CfgDir *dirs = (CfgDir *)calloc(1, sizeof(CfgDir));
    if (dirs == NULL) {
        return NULL;
    }
    // First slot carries the configured dir (may be empty); the rest stay NULL
    // to exercise the NULL-path branch in the caller.
    if (g_cfgDir[0] != '\0') {
        dirs->paths[0] = strdup(g_cfgDir);
    }
    return dirs;
}

void FreeCfgDirList(CfgDir *res)
{
    if (res == NULL) {
        return;
    }
    for (int32_t i = 0; i < MAX_CFG_POLICY_DIRS_CNT; ++i) {
        free(res->paths[i]);
    }
    free(res);
}