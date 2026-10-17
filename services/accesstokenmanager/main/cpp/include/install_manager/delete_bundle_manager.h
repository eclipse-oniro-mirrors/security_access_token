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

#ifndef DEL_BUNDLE_MANAGER_H
#define DEL_BUNDLE_MANAGER_H

#include <memory>
#include <string>
#include <vector>

#include "access_token.h"
#include "accesstoken_dfx_define.h"
#include "accesstoken_id_manager.h"
#include "atm_data_type.h"
#include "hap_token_info.h"
#include "hap_token_info_inner.h"
#include "nocopyable.h"

namespace OHOS {
namespace Security {
namespace AccessToken {

// Bundle-clean judgment: db part joins the caller's delInfoVec; the memory
// part (bundleId release) runs only after CommitDb succeeds.
struct BundleCleanPlan final {
    bool cleanBundleInfo = false;
    bool cleanBundleId = false;
};

// Bundle-clean judgment input: the target token's coordinates and deletion
// mode. uid is -1 when unavailable (a RESERVED_IDENTITY row).
struct BundleCleanParam final {
    AccessTokenID tokenId = INVALID_TOKENID;
    int32_t uid = -1;
    MultipleMode mode = MultipleMode::DEFAULT_OR_MAIN_MODE;
    ReservedType delType = ReservedType::NONE;
};

// DFX-only outputs of DeleteIdentityWithDfx; business logic must not branch
// on any field. sceneCode defaults to a valid scene for unset paths.
struct DeleteDfxInfo final {
    int32_t sceneCode = static_cast<int32_t>(AT_DELETE_COMMON_FINISH);
    int32_t userId = 0;
    int32_t instIndex = 0;
};

// Owner of the DeleteIdentity chain; one-way dependency:
// service -> install_manager -> permission -> database.
class DeleteBundleManager final {
public:
    static DeleteBundleManager& GetInstance();
    ~DeleteBundleManager();

    // Dispatch: tokenID 0 = whole bundle (Case 1), reserved = Case 2.1, active = Case 2.2.
    int32_t DeleteIdentityWithDfx(AccessTokenID tokenID, const std::string& bundleName,
        ReservedType reservedType, DeleteDfxInfo& dfxInfo);

    // Delete one ACTIVE or UNTRUSTED HAP token (Case 2.2): the chain's
    // single validation point. All three deletion modes are accepted for both
    // statuses (the reserve transition moves the id out of whichever set
    // holds it).
    int32_t DeleteActiveAndUntrustedToken(AccessTokenID id, const std::string& bundleName, ReservedType type,
        DeleteDfxInfo& dfxInfo);

    // Whole-bundle deletion (Case 1).
    int32_t DeleteWholeBundle(const std::string& bundleName);

    // Delete a reserved token completely (Case 2.1): db-only transaction; the
    // mode's package-info rows and the bundleId go on the last same-mode
    // trace.
    int32_t DeleteReservedToken(AccessTokenID tokenID, const std::string& bundleName, DeleteDfxInfo& dfxInfo);

private:
    // Token-scope builder: the token's OWN tables only.
    static void BuildTokenRemoveDbOps(const std::shared_ptr<HapTokenInfoInner>& info, ReservedType type,
        std::vector<DelInfo>& delInfoVec, std::vector<AddInfo>& addInfoVec);

    // Judge whether the package info row and the target token's bundleId
    // become ownerless.
    static int32_t JudgeBundleClean(const BundleCleanParam& param, const std::string& bundleName,
        BundleCleanPlan& plan);

    // Judgment core over pre-fetched bundle rows: only a same-mode active row
    // suppresses the package-info cleanup.
    static void JudgeBundleCleanFromRows(const std::vector<GenericValues>& tokenResults,
        const BundleCleanParam& param, BundleCleanPlan& plan);

    // Judge and append the hap_info_table deletion when it holds (Case 2.2).
    static int32_t BuildBundleCleanDbOps(const std::shared_ptr<HapTokenInfoInner>& info, ReservedType delType,
        std::vector<DelInfo>& delInfoVec, BundleCleanPlan& plan);

    // Whole-bundle builder (Case 1): partition active/reserved tokens, collect uids.
    static int32_t BuildBundleDelDbOps(const std::string& bundleName,
        std::vector<AccessTokenID>& activeTokens, std::vector<AccessTokenID>& reservedTokens,
        std::vector<int32_t>& uids, std::vector<DelInfo>& delInfoVec);

    // includePermissionState follows the deletion mode only, never the stored type.
    static void GenerateHapTokenDelInfoVec(AccessTokenID tokenID, const std::string& bundleName,
        std::vector<DelInfo>& delInfoVec, bool includePermissionState);

    // Complete Case 2.2 db op set: token matrix + bundle clean + whitelist drop,
    // committed in a single CommitDb.
    int32_t BuildDeleteDbAllOps(const std::shared_ptr<HapTokenInfoInner>& info, ReservedType delType,
        std::vector<DelInfo>& delInfoVec, std::vector<AddInfo>& addInfoVec,
        BundleCleanPlan& cleanPlan);

    int32_t DeleteActiveTokenInner(std::shared_ptr<HapTokenInfoInner> info, ReservedType delType);

    // Gather the Case 2.1 pre-commit state under the caller's L0 lock: the
    // judgment input (BundleCleanParam, the common type shared with
    // JudgeBundleCleanFromRows) and its result.
    int32_t PrepareReservedTokenDelete(AccessTokenID tokenID, const std::string& bundleName,
        DeleteDfxInfo& dfxInfo, BundleCleanParam& cleanParam, BundleCleanPlan& cleanPlan);

    // Row-not-found branch of Case 2.1: mismatch rejects, missing row is idempotent.
    int32_t HandleReservedRowNotFound(AccessTokenID tokenID, const std::string& bundleName);

    // In-memory half of a committed Case 2.2 deletion, inside the L0 scope.
    // The NONE-mode release is set-agnostic (ReleaseTokenIdForce: active or
    // untrusted id alike).
    void PublishActiveTokenDeletion(const std::shared_ptr<HapTokenInfoInner>& info,
        ReservedType delType, const BundleCleanPlan& cleanPlan);

    // Per-token notification tail; runs after the L0 lock is released.
    void NotifyTokenDeleted(AccessTokenID tokenId, const std::vector<std::string>& grantedPerms);

    // Batch wrapper for a whole-bundle delete; grantedPermLists captured beforehand.
    void NotifyBundleTokensDeleted(const std::vector<AccessTokenID>& activeTokens,
        const std::vector<std::vector<std::string>>& grantedPermLists);

    DeleteBundleManager();
    DISALLOW_COPY_AND_MOVE(DeleteBundleManager);
};
} // namespace AccessToken
} // namespace Security
} // namespace OHOS

#endif // DEL_BUNDLE_MANAGER_H
