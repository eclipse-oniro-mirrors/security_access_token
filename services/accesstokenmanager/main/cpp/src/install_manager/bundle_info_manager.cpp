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

#include "bundle_info_manager.h"

#include "access_token_db_operator.h"
#include "access_token_error.h"
#include "accesstoken_common_log.h"
#include "accesstoken_info_manager.h"
#include "accesstoken_info_utils.h"
#include "atm_data_type.h"
#include "data_validator.h"
#include "generic_values.h"
#include "hap_sign_verify_manager.h"
#include "install_db_repository.h"
#include "multiple_mode_utils.h"
#include "token_field_const.h"

namespace OHOS {
namespace Security {
namespace AccessToken {

BundleInfoManager& BundleInfoManager::GetInstance()
{
    static BundleInfoManager instance;
    return instance;
}

BundleInfoManager::BundleInfoManager() {}

BundleInfoManager::~BundleInfoManager() {}

int32_t BundleInfoManager::GetHapSignInfo(const std::string& bundleName,
    std::vector<TrustedBundleInfo>& bundleInfo, uint32_t flag, MultipleMode mode)
{
    if (bundleName.empty()) {
        LOGE(ATM_DOMAIN, ATM_TAG, "bundleName is empty");
        return AccessTokenError::ERR_PARAM_INVALID;
    }
    if (!DataValidator::IsSignInfoQueryFlagValid(flag)) {
        LOGE(ATM_DOMAIN, ATM_TAG, "Query flag is invalid.");
        return AccessTokenError::ERR_PARAM_INVALID;
    }
    MultipleMode resolvedMode = (mode == MultipleMode::CURRENT_MODE) ?
        MultipleModeUtils::GetCurrentMode() : mode;
    std::vector<std::string> hapPaths;
    std::vector<std::vector<uint8_t>> persistDatas;
    int32_t ret = InstallDbRepository::GetInstalledBundleInfo(bundleName, resolvedMode, hapPaths, persistDatas);
    if (ret != RET_SUCCESS) {
        LOGE(ATM_DOMAIN, ATM_TAG, "Get installed bundle info failed ret=%{public}d", ret);
        return ret;
    }
    if (hapPaths.empty() && (mode == MultipleMode::CURRENT_MODE) &&
        (resolvedMode == MultipleMode::SUB_MODE)) {
        LOGI(ATM_DOMAIN, ATM_TAG, "Current mode empty, fallback to default mode.");
        ret = InstallDbRepository::GetInstalledBundleInfo(bundleName, MultipleMode::DEFAULT_OR_MAIN_MODE,
            hapPaths, persistDatas);
        if (ret != RET_SUCCESS) {
            LOGE(ATM_DOMAIN, ATM_TAG, "Get installed bundle info failed ret=%{public}d", ret);
            return ret;
        }
    }
    if (hapPaths.empty()) {
        LOGE(ATM_DOMAIN, ATM_TAG, "Bundle %{public}s not exist", bundleName.c_str());
        return ERR_BUNDLE_NOT_EXIST;
    }

    std::vector<TrustedBundleInfoInner> bundleInfos;
    ret = HapSignVerifyManager::FastVerify(hapPaths, persistDatas, bundleInfos);
    if (ret != RET_SUCCESS) {
        LOGE(ATM_DOMAIN, ATM_TAG, "FastVerify failed ret=%{public}d", ret);
        return ret;
    }
    HapSignVerifyManager::GetInstance().ConvertTrustedBundleInfo(bundleInfos, bundleInfo, flag);
    return RET_SUCCESS;
}

int32_t BundleInfoManager::GetHapAppIdByTokenId(AccessTokenID tokenID, std::string& appId)
{
    std::shared_ptr<HapTokenInfoInner> infoPtr =
        AccessTokenInfoManager::GetInstance().GetHapTokenInfoInner(tokenID);
    if (infoPtr == nullptr) {
        LOGE(ATM_DOMAIN, ATM_TAG, "Token %{public}u not found.", tokenID);
        return AccessTokenError::ERR_TOKENID_NOT_EXIST;
    }
    // Try the sign-info channel first; the token's mode derives from its instIndex.
    HapTokenInfo hapInfo;
    AccessTokenInfoManager::GetInstance().GetHapTokenInfo(tokenID, hapInfo);
    std::vector<TrustedBundleInfo> bundleInfos;
    int32_t ret = GetHapSignInfo(infoPtr->GetBundleName(), bundleInfos, QUERY_PROFILE,
        MultipleModeUtils::GetTokenMode(hapInfo.instIndex));
    if (ret == RET_SUCCESS && !bundleInfos.empty() && !bundleInfos.front().profileData.appId.empty()) {
        appId = bundleInfos.front().profileData.appId;
        return RET_SUCCESS;
    }
    // Legacy fallback: tokens installed via the legacy path have no
    // package-info row; read the appId directly from hap_token_info table.
    if (!AccessTokenInfoUtils::IsSystemSpmEnforcing()) {
        return AccessTokenInfoManager::GetInstance().GetHapAppIdByTokenId(tokenID, appId);
    }
    return ERR_BUNDLE_NOT_EXIST;
}
} // namespace AccessToken
} // namespace Security
} // namespace OHOS
