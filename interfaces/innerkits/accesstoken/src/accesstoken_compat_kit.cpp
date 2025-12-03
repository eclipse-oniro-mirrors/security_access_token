/*
 * Copyright (c) 2025 Huawei Device Co., Ltd.
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

#include "accesstoken_compat_kit.h"
#include <map>
#include <mutex>

#include "access_token_error.h"
#include "accesstoken_common_log.h"
#include "accesstoken_compat_client.h"
#include "perm_setproc.h"
#include "token_setproc.h"

namespace OHOS {
namespace Security {
namespace AccessToken {
namespace {
std::mutex g_lockCache;
std::map<std::string, uint32_t> g_permCode;
static constexpr int32_t MAX_LENGTH = 256;
static const uint64_t SYSTEM_APP_MASK = (static_cast<uint64_t>(1) << 32);
static const uint64_t TOKEN_ID_LOWMASK = 0xffffffff;
}
static bool IsRenderToken(AccessTokenID tokenID)
{
    AccessTokenIDInner* idInner = reinterpret_cast<AccessTokenIDInner*>(&tokenID);
    return idInner->renderFlag;
}

static bool IsNeedCrossIpc(AccessTokenID verifyingTokenID)
{
    uint64_t selfTokenId = GetSelfTokenID();
    AccessTokenID tokenId = static_cast<AccessTokenID>(selfTokenId & TOKEN_ID_LOWMASK);
    bool isSelfNormalApp = (AccessTokenCompatKit::GetTokenTypeFlag(tokenId) == TOKEN_HAP) &&
                           !((selfTokenId & SYSTEM_APP_MASK) == SYSTEM_APP_MASK);

    return isSelfNormalApp && ((selfTokenId & TOKEN_ID_LOWMASK) != verifyingTokenID);
}


bool TransferPermissionToOpcode(const std::string& permission, uint32_t& code)
{
    std::lock_guard<std::mutex> lock(g_lockCache);
    auto iter = g_permCode.find(permission);
    if (iter != g_permCode.end()) {
        code = iter->second;
        return true;
    }
    if (AccessTokenCompatClient::GetInstance().GetPermissionCode(permission, code) != 0) {
        return false;
    }
    g_permCode[permission] = code; // insert
    return true;
}

ATokenTypeEnum AccessTokenCompatKit::GetTokenTypeFlag(AccessTokenID tokenID)
{
    LOGD(ATM_DOMAIN, ATM_TAG, "Id=%{public}u.", tokenID);
    if (tokenID == INVALID_TOKENID) {
        LOGE(ATM_DOMAIN, ATM_TAG, "TokenID is invalid.");
        return TOKEN_INVALID;
    }
    AccessTokenIDInner* idInner = reinterpret_cast<AccessTokenIDInner*>(&tokenID);
    return static_cast<ATokenTypeEnum>(idInner->type);
}

PermissionState AccessTokenCompatKit::VerifyAccessToken(AccessTokenID tokenID, const std::string& permission)
{
    LOGD(ATM_DOMAIN, ATM_TAG, "Id=%{public}u, permission=%{public}s.", tokenID, permission.c_str());
    if (IsRenderToken(tokenID)) {
        LOGI(ATM_DOMAIN, ATM_TAG, "Id %{public}u is render process, perm denied.", tokenID);
        return PERMISSION_DENIED;
    }
    uint32_t code;
    if (!TransferPermissionToOpcode(permission, code)) {
        LOGE(ATM_DOMAIN, ATM_TAG, "Permission=%{public}s is not exist.", permission.c_str());
        return PERMISSION_DENIED;
    }
    if (IsNeedCrossIpc(tokenID)) {
        return AccessTokenCompatClient::GetInstance().VerifyAccessToken(tokenID, permission);
    }
    bool isGranted = false;
    int32_t ret = GetPermissionFromKernel(tokenID, code, isGranted);
    if (ret != 0) {
        LOGD(ATM_DOMAIN, ATM_TAG,
            "Failed to get permission from kernel, err=%{public}d, id=%{public}u, permission=%{public}s.",
            ret, tokenID, permission.c_str());
        return AccessTokenCompatClient::GetInstance().VerifyAccessToken(tokenID, permission);
    }
    return isGranted ? PERMISSION_GRANTED : PERMISSION_DENIED;
}

int32_t AccessTokenCompatKit::GetHapTokenInfo(AccessTokenID tokenID, HapTokenInfoCompat& hapTokenInfo)
{
    LOGD(ATM_DOMAIN, ATM_TAG, "Id=%{public}u.", tokenID);
    if (AccessTokenCompatKit::GetTokenTypeFlag(tokenID) != TOKEN_HAP) {
        LOGE(ATM_DOMAIN, ATM_TAG, "Id=%{public}u is invalid.", tokenID);
        return ERR_PARAM_INVALID;
    }
    if (IsRenderToken(tokenID)) {
        LOGI(ATM_DOMAIN, ATM_TAG, "Id %{public}u is render process.", tokenID);
        return ERR_TOKENID_NOT_EXIST;
    }
    HapTokenInfoCompatParcel hapInfoParcel;
    int32_t error = AccessTokenCompatClient::GetInstance().GetHapTokenInfo(tokenID, hapInfoParcel);
    hapTokenInfo.bundleName = hapInfoParcel.bundleName;
    hapTokenInfo.userID = hapInfoParcel.userID;
    hapTokenInfo.instIndex = hapInfoParcel.instIndex;
    hapTokenInfo.apiVersion = hapInfoParcel.apiVersion;
    return error;
}

AccessTokenID AccessTokenCompatKit::GetNativeTokenId(const std::string& processName)
{
    if ((processName.empty()) || ((processName.length() > MAX_LENGTH))) {
        LOGE(ATM_DOMAIN, ATM_TAG, "ProcessName(%{public}s) is invalid.", processName.c_str());
        return INVALID_TOKENID;
    }
    return AccessTokenCompatClient::GetInstance().GetNativeTokenId(processName);
}
}  // namespace AccessToken
}  // namespace Security
}  // namespace OHOS
