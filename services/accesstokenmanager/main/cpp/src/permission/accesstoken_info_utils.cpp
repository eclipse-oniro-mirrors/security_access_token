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

#include "accesstoken_info_utils.h"

#include <algorithm>
#include <atomic>
#include <cctype>
#include <cerrno>
#include <climits>
#include <cstdlib>
#include <cstring>
#include <mutex>
#include <unordered_set>

#include "access_token_error.h"
#include "accesstoken_common_log.h"
#include "accesstoken_id_manager.h"
#include "parameter.h"
#include "permission_constraint_check.h"
#include "permission_feature_manager.h"
#include "permission_map.h"
#include "spm_setproc.h"
#include "token_field_const.h"

namespace OHOS {
namespace Security {
namespace AccessToken {
namespace {
static const char* SYSTEM_RESOURCE_BUNDLE_NAME = "ohos.global.systemres";
static const unsigned int SYSTEM_APP_FLAG = 0x0001;
static const unsigned int ATOMIC_SERVICE_FLAG = 0x0002;
static const unsigned int DEBUG_APP_FLAG = 0x0008;
static constexpr int32_t BASE_USER_RANGE = 200000;

// Reject path traversal components in the hap path: blocks ".." and "../" / "/.."
// patterns, backslashes, embedded NUL and control characters.
static bool IsHapPathValid(const std::string& filePath)
{
    if (filePath.empty()) {
        return false;
    }
    if (filePath == "..") {
        return false;
    }
    if (filePath.find("../") != std::string::npos ||
        filePath.find("/..") != std::string::npos) {
        return false;
    }
    if (filePath.find('\\') != std::string::npos) {
        return false;
    }
    if (filePath.find('\0') != std::string::npos) {
        return false;
    }
    for (char c : filePath) {
        if (static_cast<unsigned char>(c) < 0x20) {
            return false;
        }
    }
    return true;
}

constexpr int32_t INVALID_UID = -1;
constexpr const char* PERMISSION_CUSTOM_SANDBOX = "ohos.permission.CUSTOM_SANDBOX";
#if defined(ACCESS_TOKEN_SUPPORT_SHAREDUID) && defined(ACCESS_TOKEN_ENABLE_SHAREDUID)
constexpr char DEVICE_TYPE_2IN1[] = "2in1";
#endif

// Query the SPM kernel version for the appUid/uid switch decision. The kernel SPM version
// is immutable at runtime, so the result is cached at this caller layer per review;
// failures are still logged on each uncached probe. Returns RET_SUCCESS with spmVersion
// filled on success.
int32_t QuerySpmVersionForSharedUid(uint32_t& spmVersion)
{
#ifndef ATM_TEST_ENABLE
    static std::atomic<bool> hasCached{false};
    static std::atomic<int32_t> cachedRet{0};
    static std::atomic<uint32_t> cachedVersion{0};
    static std::mutex cacheMutex;

    if (hasCached.load(std::memory_order_acquire)) {
        spmVersion = cachedVersion.load(std::memory_order_acquire);
        return cachedRet.load(std::memory_order_acquire);
    }

    std::lock_guard<std::mutex> lock(cacheMutex);
    if (hasCached.load(std::memory_order_relaxed)) {
        spmVersion = cachedVersion.load(std::memory_order_relaxed);
        return cachedRet.load(std::memory_order_relaxed);
    }
#endif

    uint32_t version = 0;
    int32_t ret = SpmGetVersion(&version);
    if (ret != RET_SUCCESS) {
        LOGE(ATM_DOMAIN, ATM_TAG, "SpmGetVersion failed, ret=%{public}d, fallback to appUid.", ret);
    }
#ifndef ATM_TEST_ENABLE
    if (ret != RET_SUCCESS && ret != ENOTSUP && ret != EOPNOTSUPP) {
        // Transient failure: never cache it, retry the probe on the next call.
        return ret;
    }
    cachedVersion.store(version, std::memory_order_release);
    cachedRet.store(ret, std::memory_order_release);
    hasCached.store(true, std::memory_order_release);
#endif
    spmVersion = version;
    return ret;
}
}

bool AccessTokenInfoUtils::IsSystemResource(const std::string& bundleName)
{
    return std::string(SYSTEM_RESOURCE_BUNDLE_NAME) == bundleName;
}

bool AccessTokenInfoUtils::IsPlaceholderModuleName(const std::string& moduleName)
{
    size_t moduleNameMinSize = 2; // placeholder module name should be at least 2 characters, e.g. "#0"
    if (moduleName.size() < moduleNameMinSize || moduleName[0] != '#') {
        return false;
    }
    return std::all_of(moduleName.begin() + 1, moduleName.end(), [](unsigned char ch) {
        return std::isdigit(ch) != 0;
    });
}

int32_t AccessTokenInfoUtils::CheckAndResolveHapPath(const std::string& filePath, std::string& resolvedPath)
{
    if (!IsHapPathValid(filePath)) {
        LOGW(ATM_DOMAIN, ATM_TAG, "Invalid hap path %{private}s.", filePath.c_str());
        return ERR_VERIFY_CANT_OPEN;
    }
#ifdef ATM_TEST_ENABLE
    // Install tests use virtual mock hap paths (e.g. "/SYSTEM/...") that do not
    // exist on the real filesystem; keep the original path instead of failing realpath.
    resolvedPath = filePath;
    return RET_SUCCESS;
#else
    char resolved[PATH_MAX] = {0};
    if (realpath(filePath.c_str(), resolved) == nullptr) {
        if (errno != ENOENT) {
            LOGC(ATM_DOMAIN, ATM_TAG, "Failed to resolve path %{private}s: %{public}s.",
                filePath.c_str(), strerror(errno));
            return ERR_VERIFY_CANT_OPEN;
        }
        LOGW(ATM_DOMAIN, ATM_TAG, "Failed to resolve path %{private}s: %{public}s.",
            filePath.c_str(), strerror(errno));
        return ERR_VERIFY_FILE_NOT_EXIST;
    }
    resolvedPath = resolved;
    return RET_SUCCESS;
#endif
}

bool AccessTokenInfoUtils::CheckSpecifiedFlag(uint32_t tokenAttr, uint32_t flag)
{
    return (tokenAttr & flag) != 0;
}

std::string AccessTokenInfoUtils::GetHapUniqueStr(
    int32_t userID, const std::string& bundleName, int32_t instIndex)
{
    return bundleName + "&" + std::to_string(userID) + "&" + std::to_string(instIndex);
}

std::string AccessTokenInfoUtils::GetHapUniqueStr(const std::shared_ptr<HapTokenInfoInner>& info)
{
    if (info == nullptr) {
        return std::string("");
    }
    return GetHapUniqueStr(info->GetUserID(), info->GetBundleName(), info->GetInstIndex());
}

void AccessTokenInfoUtils::GenerateAddInfoToVec(
    AtmDataType type, const std::vector<GenericValues>& addValues, std::vector<AddInfo>& addInfoVec)
{
    AddInfo addInfo;
    addInfo.addType = type;
    addInfo.addValues = addValues;
    addInfoVec.emplace_back(addInfo);
}

void AccessTokenInfoUtils::GenerateDelInfoToVec(
    AtmDataType type, const GenericValues& delValue, std::vector<DelInfo>& delInfoVec)
{
    DelInfo delInfo;
    delInfo.delType = type;
    delInfo.delValue = delValue;
    delInfoVec.emplace_back(delInfo);
}

void AccessTokenInfoUtils::AddTokenIdToUndefValues(AccessTokenID tokenId, std::vector<GenericValues>& undefValues)
{
    for (auto& value : undefValues) {
        value.Put(TokenFiledConst::FIELD_TOKEN_ID, static_cast<int32_t>(tokenId));
    }
}

void AccessTokenInfoUtils::BuildHapTokenInfo(const Identity& id, const BundleParam& param, HapTokenInfo& info)
{
    uint32_t apiSize = 3; // 3: api version length
    std::string apiStr = std::to_string(param.apiVersion);
    uint32_t inputSize = apiStr.length();

    info = {};
    info.tokenID = AccessTokenIDManager::ExtractTokenIdFromFull(id.tokenId);
    info.userID = id.appUid / BASE_USER_RANGE;
    info.ver = DEFAULT_TOKEN_VERSION;
    info.tokenAttr = 0;
    if (param.isSystem) {
        info.tokenAttr |= SYSTEM_APP_FLAG;
    }
    if (param.isAtomicService) {
        info.tokenAttr |= ATOMIC_SERVICE_FLAG;
    }
    if (param.isDebug) {
        info.tokenAttr |= DEBUG_APP_FLAG;
    }
    info.bundleName = param.bundleName;
    info.apiVersion = (inputSize <= apiSize) ? param.apiVersion : std::atoi(apiStr.substr(inputSize - apiSize).c_str());
    info.instIndex = 0;
    info.dlpType = DLP_COMMON;
    info.uid = id.appUid;
}

void AccessTokenInfoUtils::BuildBundleFullInfo(const BundleParam& param, const HapPolicy& policy,
    std::shared_ptr<BundleInfoInner>& innerInfo, BundleNoCachedInfo& noCached)
{
    if (innerInfo == nullptr) {
        innerInfo = std::make_shared<BundleInfoInner>();
    }
    innerInfo->permCodeList.clear();
    noCached.apl = policy.apl;
    noCached.distributionType = param.distributionType;
    noCached.idType = param.idType;
    noCached.ownerid = param.appIdentifier;
    noCached.isSharedUid = param.isSharedUid;

    std::unordered_set<uint32_t> permCodeSet;
    for (const auto& status : policy.permStateList) {
        if (param.isSystem && !PermissionFeatureManager::GetInstance().IsSupportFeature(status)) {
            continue;
        }
        PermissionBriefDef briefDef;
        if (!GetPermissionBriefDef(status.permissionName, briefDef) || !briefDef.isEnable) {
            continue;
        }
        if (!PermissionConstraintCheck::IsAclSatisfied(param.isSideloadApp, briefDef, policy)) {
            continue;
        }

        PermissionRulesEnum rule = PERMISSION_ACL_RULE;
        if (!PermissionConstraintCheck::IsPermAvailableRangeSatisfied(param, briefDef, rule)) {
            continue;
        }

        uint32_t permCode = 0;
        if (!TransferPermissionToOpcode(status.permissionName, permCode)) {
            continue;
        }
        uint16_t shortPermCode = static_cast<uint16_t>(permCode);
        if (permCodeSet.insert(permCode).second) {
            innerInfo->permCodeList.emplace_back(shortPermCode);
        }
    }
}

ReservedType AccessTokenInfoUtils::GetReservedTokenTypeDBValue(const GenericValues& values)
{
#ifdef SPM_DATA_ENABLE
    return static_cast<ReservedType>(values.GetInt(TokenFiledConst::FIELD_RESERVED));
#else
    if (AccessTokenInfoUtils::CheckSpecifiedFlag(
        values.GetInt(TokenFiledConst::FIELD_TOKEN_ATTR), 0x0004)) { // 0x0004: reserved
        return ReservedType::RESERVED_IDENTITY;
    }
    return ReservedType::NONE;
#endif
}

bool AccessTokenInfoUtils::IsSharedUid(bool sharedUID, const std::vector<std::string>& deviceTypes,
    bool hasCustomSandboxPerm)
{
#if defined(ACCESS_TOKEN_SUPPORT_SHAREDUID) && defined(ACCESS_TOKEN_ENABLE_SHAREDUID)
    return hasCustomSandboxPerm || (sharedUID && deviceTypes.size() == 1 && deviceTypes[0] == DEVICE_TYPE_2IN1);
#else
    (void)sharedUID;
    (void)deviceTypes;
    (void)hasCustomSandboxPerm;
    return false;
#endif
}

int32_t AccessTokenInfoUtils::ResolveHapUid(int32_t appUid, bool isSharedUid)
{
    if (appUid == INVALID_UID) {
        return INVALID_UID;
    }
    uint32_t spmVersion = 0;
    if (QuerySpmVersionForSharedUid(spmVersion) != RET_SUCCESS) {
        return appUid;
    }
    if (spmVersion < SPM_MIN_VERSION_SUPPORT_APPUID) {
        LOGD(ATM_DOMAIN, ATM_TAG, "Spm version %{public}u below switch version %{public}u, keep appUid form, "
            "appUid=%{public}d.", spmVersion, SPM_MIN_VERSION_SUPPORT_APPUID, appUid);
        return appUid;
    }
    int32_t uid = isSharedUid ? AccessTokenIDManager::ExtractUserId(appUid) : appUid;
    LOGD(ATM_DOMAIN, ATM_TAG, "Resolved uid %{public}d from appUid %{public}d, switch flag %{public}d.",
        uid, appUid, isSharedUid);
    return uid;
}

bool AccessTokenInfoUtils::HasCustomSandboxPermission(const std::vector<PermissionStatus>& permStateList)
{
    if (!IsDefinedPermissionInner(PERMISSION_CUSTOM_SANDBOX)) {
        return false;
    }
    for (const auto& perm : permStateList) {
        if (perm.permissionName == PERMISSION_CUSTOM_SANDBOX) {
            return true;
        }
    }
    return false;
}

void AccessTokenInfoUtils::AccessTokenServiceAppVerifyParamSet()
{
    int32_t res = SetParameter(ACCESS_TOKEN_SERVICE_APP_VERIFY_KEY, "1");
    if (res != 0) {
        LOGE(ATM_DOMAIN, ATM_TAG, "SetParameter ACCESS_TOKEN_SERVICE_APP_VERIFY_KEY failed %{public}d.", res);
    }
}

bool AccessTokenInfoUtils::IsSystemAppVerified()
{
    constexpr int NAME_BUFFER_LEN = 32;
    char value[NAME_BUFFER_LEN] = {0};
    int32_t ret = GetParameter(ACCESS_TOKEN_SERVICE_APP_VERIFY_KEY, "", value, NAME_BUFFER_LEN - 1);
    if (ret < 0) {
        LOGE(ATM_DOMAIN, ATM_TAG, "GetParameter ACCESS_TOKEN_SERVICE_APP_VERIFY_KEY failed, ret=%{public}d.", ret);
        return false;
    }
    return std::atoi(value) > 0;
}

bool AccessTokenInfoUtils::IsSystemSpmEnforcing()
{
    constexpr int NAME_BUFFER_LEN = 32;
    static bool isEnforcing = false;
    char value[NAME_BUFFER_LEN] = {0};
    int32_t ret = GetParameter(ACCESS_TOKEN_SERVICE_SPM_ENFORCING_KEY, "", value, NAME_BUFFER_LEN - 1);
    if (ret < 0) {
        LOGE(ATM_DOMAIN, ATM_TAG, "GetParameter ACCESS_TOKEN_SERVICE_SPM_ENFORCING_KEY failed, ret=%{public}d.",
            ret);
        return false;
    }
    isEnforcing = std::atoi(value) > 0;
    return isEnforcing;
}
} // namespace AccessToken
} // namespace Security
} // namespace OHOS
