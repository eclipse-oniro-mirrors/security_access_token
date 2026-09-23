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

#include "kernel_and_db_lock.h"

#include <cstdlib>

#include "accesstoken_common_log.h"

namespace OHOS {
namespace Security {
namespace AccessToken {
namespace {
// Depth instead of bool: nested transactions join the outer one, so the flag
// must stay set until the outermost transaction finishes.
thread_local int32_t g_kernelAndDbDepth = 0;
} // namespace

std::shared_mutex& KernelAndDBLock::Get()
{
    static std::shared_mutex mutex;
    return mutex;
}

bool IsKernelAndDBWriteHeldByCurrentThread()
{
    return g_kernelAndDbDepth > 0;
}

void ReportKernelAndDBGuardViolation(const char* apiName)
{
    LOGC(ATM_DOMAIN, ATM_TAG,
        "KernelAndDB guard violated at %{public}s, kernel mutation outside transaction", apiName);
#ifdef ATM_TEST_ENABLE
    // Abort during UT to eliminate bypasses; release builds only log.
    abort();
#endif
}

void KernelAndDBDetail::EnterWrite()
{
    ++g_kernelAndDbDepth;
}

void KernelAndDBDetail::ExitWrite()
{
    if (g_kernelAndDbDepth > 0) {
        --g_kernelAndDbDepth;
    }
}
} // namespace AccessToken
} // namespace Security
} // namespace OHOS
