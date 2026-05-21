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

#ifndef NATIVE_TOKEN_TEST_COMMON_H
#define NATIVE_TOKEN_TEST_COMMON_H

#include <cerrno>

#include "nativetoken.h"
#include "spm_setproc.h"

constexpr uint32_t MAX_SPM_PERM_NUM = 256;
constexpr uint32_t DEFAULT_EXTERM_SIZE = 1;

static bool IsKernelSupportSpm()
{
    static bool isSupportSpm = false;
    static bool hasChecked = false;
    if (hasChecked) {
        return isSupportSpm;
    }
    uint32_t version = 0;
    int32_t ret = SpmGetVersion(&version);
    isSupportSpm = (ret != ENOTSUP) ? true : false;
    hasChecked = true;
    std::cout << "IsKernelSupportSpm: " << isSupportSpm << std::endl;
    return isSupportSpm;
}

#endif // NATIVE_TOKEN_TEST_COMMON_H
