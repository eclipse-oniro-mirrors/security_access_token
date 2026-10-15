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

#ifndef INSTALL_IDENTITY_MANAGER_H
#define INSTALL_IDENTITY_MANAGER_H

#include <memory>

#include "access_token.h"
#include "generic_values.h"
#include "hap_token_info.h"
#include "hap_token_info_inner.h"
#include "install_session_cache.h"

namespace OHOS {
namespace Security {
namespace AccessToken {

class InstallIdentityManager final {
public:
    static int32_t GetTokenIdAndUid(InstallCache& cache, const BundlePolicy& bundlePolicy);
    // Session success path: settle id states (updated tokens -> ACTIVE, reserved
    // transitions). Mirror of RollbackIdentity.
    static void CommitIdentity(const InstallCache& cache, const FinishContext& context);
    // Session failure path: release every id acquired by this session (allocated
    // token, new bundle ids, inactive cache entries). Mirror of CommitIdentity.
    static void RollbackIdentity(const InstallCache& cache);
    static int32_t ResolveUpdateUid(int32_t& uid, const std::shared_ptr<HapTokenInfoInner>& infoPtr,
        bool& isNewBundleId, bool& fromCaller);
    static AccessTokenAttr BuildTokenAttr(const BundleParam& param);

private:
    static int32_t CreateTokenIdAndUid(InstallCache& cache, const BundlePolicy& bundlePolicy, int32_t bundleRefUid);
    static void RestoreIdentityFromReservedData(
        InstallCache& cache, AccessTokenID tokenId, int32_t uid, int32_t oldAttr);
    static int32_t ResolveExistingTokenReuse(InstallCache& cache,
        const GenericValues& tokenValue);
};

} // namespace AccessToken
} // namespace Security
} // namespace OHOS
#endif // INSTALL_IDENTITY_MANAGER_H
