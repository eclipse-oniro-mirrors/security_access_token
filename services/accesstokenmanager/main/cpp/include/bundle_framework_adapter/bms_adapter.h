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

#ifndef BMS_ADAPTER_H
#define BMS_ADAPTER_H

#include <string>
#include <vector>

#include "atm_bundle_recovery_info.h"

namespace OHOS {
namespace Security {
namespace AccessToken {

// Adapter wrapping the non-IPC interfaces.
class BmsAdapter final {
public:
    // Query the list of apps to recover. Returns the code (0 on success);
    // appInfoList is empty on failure.
    static int32_t QueryAppInfoList(std::vector<AppExecFwk::AtmBundleRecoveryInfo>& appInfoList);

    // Compute the app data dir name (sandbox data dir name) by (bundleName, appIndex).
    static std::string GetAppDataDirName(const std::string& bundleName, int32_t appIndex);
};

} // namespace AccessToken
} // namespace Security
} // namespace OHOS

#endif // BMS_ADAPTER_H