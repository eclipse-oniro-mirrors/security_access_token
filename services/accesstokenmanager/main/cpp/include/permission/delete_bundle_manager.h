/*
 * Copyright (c) 2021-2026 Huawei Device Co., Ltd.
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
#include "atm_data_type.h"
#include "hap_token_info.h"
#include "hap_token_info_inner.h"
#include "nocopyable.h"

namespace OHOS {
namespace Security {
namespace AccessToken {

class DeleteBundleManager final {
public:
    static DeleteBundleManager& GetInstance();
    ~DeleteBundleManager();

    /**
     * @brief Delete a reserved token completely.
     * @param tokenID Token ID to delete.
     * @param bundleName Bundle name.
     * @return Returns 0 if success, otherwise failed.
     */
    int32_t DeleteReservedToken(AccessTokenID tokenID, const std::string& bundleName);

    /**
     * @brief Delete all reserved tokens for a bundle and package info.
     * @param bundleName Bundle name.
     * @return Returns 0 if success, otherwise failed.
     */
    int32_t DeleteBundleAndAllTokens(const std::string& bundleName);

    /**
     * @brief Remove HAP token info from database.
     * @param info HAP token info.
     * @param type Reserved type.
     * @param id Token ID.
     * @return Returns 0 if success, otherwise failed.
     */
    static int32_t RemoveHapTokenInfoFromDb(
        const std::shared_ptr<HapTokenInfoInner>& info, ReservedType type, AccessTokenID id);

    /**
     * @brief Try to clean bundle info when all tokens are reserved.
     * @param info HAP token info.
     * @return Returns 0 if success, otherwise failed.
     */
    static int32_t TryCleanBundleInfo(const std::shared_ptr<HapTokenInfoInner>& info);

    /**
     * @brief Delete all data related to a token ID from database.
     * @param tokenID Token ID to delete.
     * @param bundleName Bundle name.
     * @return Returns 0 if success, otherwise failed.
     */
    static int32_t DeleteDataByTokenId(AccessTokenID tokenID, const std::string& bundleName);

private:
    /**
     * @brief Generate delete info vector for HAP token related tables.
     * @param tokenID Token ID to delete.
     * @param bundleName Bundle name.
     * @param delInfoVec Output delete info vector.
     * @param includePermissionState Whether to include permission state table.
     */
    static void GenerateHapTokenDelInfoVec(
        AccessTokenID tokenID,
        const std::string& bundleName,
        std::vector<DelInfo>& delInfoVec,
        bool includePermissionState);

    DeleteBundleManager();
    DISALLOW_COPY_AND_MOVE(DeleteBundleManager);
};
} // namespace AccessToken
} // namespace Security
} // namespace OHOS

#endif // DEL_BUNDLE_MANAGER_H
