/*
 * Copyright (c) 2026 Huawei Device Co., Ltd.
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 *
 * http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 */

#ifndef BUNDLE_INFO_MANAGER_H
#define BUNDLE_INFO_MANAGER_H

#include <string>
#include <vector>

#include "access_token.h"
#include "hap_token_info.h"
#include "nocopyable.h"

namespace OHOS {
namespace Security {
namespace AccessToken {

class BundleInfoManager final {
public:
    static BundleInfoManager& GetInstance();
    ~BundleInfoManager();

    // Query the installed bundle sign info: reads the persisted package-info
    // rows of the resolved mode, fast-verifies each hap and converts to the
    // requested output sections. CURRENT_MODE resolves the current mode at
    // runtime; a sub-mode query with no rows falls back to the main mode
    // (fallback applies to the CURRENT_MODE path only).
    int32_t GetHapSignInfo(const std::string& bundleName,
        std::vector<TrustedBundleInfo>& bundleInfo, uint32_t flag,
        MultipleMode mode = MultipleMode::CURRENT_MODE);

    // AppId query for the GetHapTokenInfo extension chain: tries the sign-info
    // channel first (mode from the token's instIndex), falls back to the
    // hap_token_info table row.
    int32_t GetHapAppIdByTokenId(AccessTokenID tokenID, std::string& appId);

private:
    BundleInfoManager();
    DISALLOW_COPY_AND_MOVE(BundleInfoManager);
};
} // namespace AccessToken
} // namespace Security
} // namespace OHOS

#endif // BUNDLE_INFO_MANAGER_H
