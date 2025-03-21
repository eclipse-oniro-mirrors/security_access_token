/*
 * Copyright (c) 2024-2025 Huawei Device Co., Ltd.
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

#include "screen_lock_file_manager_ffi.h"
#include "data_lock_type.h"
#include "el5_filekey_manager_kit.h"

using namespace OHOS::Security::AccessToken;

namespace OHOS {
namespace CJSystemapi {
namespace ScreenLockFileManager {

extern "C" {
int32_t FfiOHOSScreenLockFileManagerAcquireAccess()
{
    return El5FilekeyManagerKit::AcquireAccess(DataLockType::DEFAULT_DATA);
}

int32_t FfiOHOSScreenLockFileManagerReleaseAccess()
{
    return El5FilekeyManagerKit::ReleaseAccess(DataLockType::DEFAULT_DATA);
}
}
} // namespace ScreenLockFileManager
} // namespace CJSystemapi
} // namespace OHOS
