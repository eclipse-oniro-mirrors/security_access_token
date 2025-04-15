/*
 * Copyright (c) 2024 Huawei Device Co., Ltd.
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

#ifndef OHOS_SCREEN_LOCK_FILE_MGR_FFI_H
#define OHOS_SCREEN_LOCK_FILE_MGR_FFI_H

#include <cstdint>

#include "cj_common_ffi.h"

extern "C" {
    FFI_EXPORT int32_t FfiOHOSScreenLockFileManagerAcquireAccess();
    FFI_EXPORT int32_t FfiOHOSScreenLockFileManagerReleaseAccess();
}

#endif // OHOS_SCREEN_LOCK_FILE_MGR_FFI_H