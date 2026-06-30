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

#include "hap_sign_verify_manager.h"

#include <algorithm>
#include <cerrno>
#include <climits>
#include <cstdlib>
#include <cstring>
#include <fcntl.h>
#include <mutex>
#include <securec.h>
#include <unistd.h>

#include "access_token_error.h"
#include "accesstoken_common_log.h"
#include "hap_sign_verify_helper.h"
#include "hap_token_info_inner.h"
#include "parameter.h"
#include "permission_manager.h"
#include "provision/provision_info.h"
#include "provision/provision_verify.h"
#include "spm_module_parser.h"

namespace OHOS {
namespace Security {
namespace AccessToken {
namespace {
constexpr const char* HAP_POLICY_DEFAULT_DOMAIN = "domain";
constexpr const char* MODULE_NAME_ENTRY = "entry";
constexpr char APP_PROVISION_TYPE_DEBUG[] = "debug";
constexpr char APP_PROVISION_TYPE_RELEASE[] = "release";
constexpr const char* ENTERPRISE_CERT_PATH =
    "/data/service/el1/public/bms/bundle_manager_service/certificates/enterprise/";

constexpr int32_t API_VERSION_MASK = 1000;
constexpr size_t MAX_PARAM_SIZE = 4096;

// Cached allowed HAP path prefixes, initialized lazily.
std::vector<std::string> g_allowedHapPathPrefixes;
std::once_flag g_allowedHapPathInitFlag;

static void InitAllowedHapPaths()
{
    g_allowedHapPathPrefixes.emplace_back("/data/app/el1/bundle/public");
    g_allowedHapPathPrefixes.emplace_back("/data/service/el1/public/bms/bundle_manager_service");
    g_allowedHapPathPrefixes.emplace_back("/data/preload/app");

    char paramValue[MAX_PARAM_SIZE] = {0};
    int ret = GetParameter("const.cust.config_dir_layer", "", paramValue, sizeof(paramValue) - 1);
    if (ret > 0) {
        std::string dirs(paramValue);
        size_t pos = 0;
        size_t next = 0;
        while ((next = dirs.find(':', pos)) != std::string::npos) {
            std::string dir = dirs.substr(pos, next - pos);
            if (!dir.empty()) {
                g_allowedHapPathPrefixes.emplace_back(std::move(dir));
            }
            pos = next + 1;
        }
        std::string lastDir = dirs.substr(pos);
        if (!lastDir.empty()) {
            g_allowedHapPathPrefixes.emplace_back(std::move(lastDir));
        }
    } else {
        g_allowedHapPathPrefixes.emplace_back("/system");
    }
    LOGD(ATM_DOMAIN, ATM_TAG, "Allowed HAP path prefixes:");
    for (const auto& prefix : g_allowedHapPathPrefixes) {
        LOGD(ATM_DOMAIN, ATM_TAG, "  %s", prefix.c_str());
    }
}

static bool IsHapPathAllowed(const char* resolvedPath)
{
    std::call_once(g_allowedHapPathInitFlag, InitAllowedHapPaths);

    std::string absPath(resolvedPath);
    for (const auto& prefix : g_allowedHapPathPrefixes) {
        if (absPath.size() > prefix.size() && absPath.compare(0, prefix.size(), prefix) == 0) {
            if (absPath[prefix.size()] == '/') {
                return true;
            }
        }
    }
    LOGC(ATM_DOMAIN, ATM_TAG, "Hap path is not in allowed directories, path=%{public}s.", resolvedPath);
    return false;
}

#ifdef X86_EMULATOR_MODE
bool IsIgnoredTrustedBundleInfo(const TrustedBundleInfoInner& info)
{
    return info.ignoreVerificationFailure;
}
#endif

const AppVerifyAdapter& GetDefaultAppVerifyAdapter()
{
    static const AppVerifyAdapter adapter;
    return adapter;
}

std::string GetEnterpriseCertPath(int32_t userId)
{
    if (userId == -1) {
        return "";
    }
    return std::string(ENTERPRISE_CERT_PATH) + std::to_string(userId);
}

void SortTrustedBundles(std::vector<TrustedBundleInfoInner>& infos)
{
    std::sort(infos.begin(), infos.end(), [](const TrustedBundleInfoInner& left,
        const TrustedBundleInfoInner& right) {
        const std::string& leftName = left.GetModuleName();
        const std::string& rightName = right.GetModuleName();
        const bool leftIsEntry = (leftName == MODULE_NAME_ENTRY);
        const bool rightIsEntry = (rightName == MODULE_NAME_ENTRY);
        if (leftIsEntry != rightIsEntry) {
            return leftIsEntry;
        }
        return leftName < rightName;
    });
}
}

int32_t RdDeviceChecker::isRdDevice = RdDeviceChecker::NOT_INITIALIZE;
std::mutex RdDeviceChecker::rdDeviceMutex;

bool RdDeviceChecker::CheckDeviceMode(char *buf, ssize_t bufLen)
{
    bool status = false;
    char *onStr = strstr(buf, "oemmode=rd");
    char *offStr = strstr(buf, "oemmode=user");
    char *statusStr = strstr(buf, "oemmode=");
    if (onStr == nullptr && offStr == nullptr) {
        LOGI(ATM_DOMAIN, ATM_TAG, "Not rd mode, cmdline = %{private}s", buf);
    } else if (offStr != nullptr && statusStr != nullptr && offStr != statusStr) {
        LOGE(ATM_DOMAIN, ATM_TAG, "cmdline attacked, cmdline = %{private}s", buf);
    } else if (onStr != nullptr && offStr == nullptr) {
        status = true;
        LOGD(ATM_DOMAIN, ATM_TAG, "Oemode is rd");
    }
    return status;
}

bool RdDeviceChecker::CheckEfuseStatus(char *buf, ssize_t bufLen)
{
    bool status = false;
    char *onStr = strstr(buf, "efuse_status=1");
    char *offStr = strstr(buf, "efuse_status=0");
    char *statusStr = strstr(buf, "efuse_status=");
    if (onStr == nullptr && offStr == nullptr) {
        LOGI(ATM_DOMAIN, ATM_TAG, "device is efused, cmdline = %{private}s", buf);
    } else if (offStr != nullptr && statusStr != nullptr && offStr != statusStr) {
        LOGE(ATM_DOMAIN, ATM_TAG, "cmdline attacked, cmdline = %{private}s", buf);
    } else if (onStr != nullptr && offStr == nullptr) {
        status = true;
        LOGD(ATM_DOMAIN, ATM_TAG, "device is not efused");
    }
    return status;
}

void RdDeviceChecker::ParseCMDLine()
{
    int32_t fd = open(PROC_CMDLINE_FILE_PATH, O_RDONLY);
    if (fd < 0) {
        isRdDevice = DEVICE_MODE_NOT_RD;
        LOGE(ATM_DOMAIN, ATM_TAG, "open %{public}s failed, %{public}s",
            PROC_CMDLINE_FILE_PATH, strerror(errno));
        return;
    }
    fdsan_exchange_owner_tag(fd, 0, ATM_DOMAIN);
    char *buf = nullptr;
    int32_t status = DEVICE_MODE_NOT_RD;
    do {
        buf = static_cast<char *>(malloc(CMDLINE_MAX_BUF_LEN));
        if (buf == nullptr) {
            LOGE(ATM_DOMAIN, ATM_TAG, "Alloc buffer for reading cmdline failed.");
            break;
        }
        (void) memset_s(buf, CMDLINE_MAX_BUF_LEN, 0, CMDLINE_MAX_BUF_LEN);
        ssize_t bufLen = read(fd, buf, CMDLINE_MAX_BUF_LEN - 1);
        if (bufLen < 0) {
            LOGE(ATM_DOMAIN, ATM_TAG, "Read %{public}s failed, %{public}s.",
                PROC_CMDLINE_FILE_PATH, strerror(errno));
            break;
        }
        if (CheckDeviceMode(buf, bufLen) || CheckEfuseStatus(buf, bufLen)) {
            status = DEVICE_MODE_RD;
        }
    } while (0);
    isRdDevice = status;
    (void)fdsan_close_with_tag(fd, ATM_DOMAIN);
    free(buf);
}

bool RdDeviceChecker::IsRdDevice()
{
    std::lock_guard<std::mutex> lock(rdDeviceMutex);
    if (isRdDevice == NOT_INITIALIZE) {
        ParseCMDLine();
    }
    return isRdDevice == DEVICE_MODE_RD;
}

int32_t HapSignVerifyManager::BuildTrustedBundleInfo(
    const std::shared_ptr<Security::Verify::BootstrapInfo>& bootstrapInfo,
    const Security::Verify::ProvisionInfo& provisionInfo, TrustedBundleInfoInner& info) const
{
    if (bootstrapInfo == nullptr) {
        return AccessTokenError::ERR_PARAM_INVALID;
    }
    AppExecFwk::Spm::InnerModuleInfoForSpm moduleInfo;
    int32_t ret = adapter_->ParseHapModuleInfo(bootstrapInfo->moduleRaw, moduleInfo);
    if (ret != RET_SUCCESS) {
        LOGE(ATM_DOMAIN, ATM_TAG, "ParseHapModuleInfo failed, ret=%{public}d.", ret);
        return ret;
    }
    moduleInfo.apiTargetVersion %= API_VERSION_MASK;
    info.moduleData = moduleInfo;
    info.provisionInfo = provisionInfo;
    info.shareFilesRaw = bootstrapInfo->shareFilesRaw;
    info.bootstrapInfo = bootstrapInfo;
    return RET_SUCCESS;
}

const std::string& TrustedBundleInfoInner::GetModuleName() const
{
    return moduleData.moduleName;
}

int32_t TrustedBundleInfoInner::GetBundleType() const
{
    return static_cast<int32_t>(moduleData.bundleType);
}

int32_t TrustedBundleInfoInner::GetApiTargetVersion() const
{
    return moduleData.apiTargetVersion;
}

std::string TrustedBundleInfoInner::GetBundleName() const
{
    if (!provisionInfo.bundleInfo.bundleName.empty()) {
        return provisionInfo.bundleInfo.bundleName;
    }
    if (!moduleData.bundleName.empty()) {
        return moduleData.bundleName;
    }
    return moduleData.moduleName;
}

std::string TrustedBundleInfoInner::GetAppIdentifier() const
{
    return provisionInfo.bundleInfo.appIdentifier;
}

std::string TrustedBundleInfoInner::GetAppId() const
{
    return provisionInfo.appId;
}

std::string TrustedBundleInfoInner::GetApl() const
{
    return provisionInfo.bundleInfo.apl;
}

std::string TrustedBundleInfoInner::GetAppProvisionType() const
{
    return provisionInfo.type == Security::Verify::DEBUG ?
        APP_PROVISION_TYPE_DEBUG : APP_PROVISION_TYPE_RELEASE;
}

bool TrustedBundleInfoInner::IsSystemApp() const
{
    return provisionInfo.bundleInfo.appFeature == "hos_system_app";
}

bool TrustedBundleInfoInner::IsAtomicService() const
{
    return moduleData.bundleType == AppExecFwk::Spm::BundleType::ATOMIC_SERVICE;
}

std::string TrustedBundleInfoInner::GetAppDistributionType() const
{
#ifdef IS_SUPPORT_HAP_RUNNING
    return Verify::AppDistTypeToString(provisionInfo.distributionType);
#else
    return "undefined";
#endif
}

HapSignVerifyManager& HapSignVerifyManager::GetInstance()
{
    static HapSignVerifyManager instance;
    return instance;
}

HapSignVerifyManager::HapSignVerifyManager() : HapSignVerifyManager(GetDefaultAppVerifyAdapter())
{}

HapSignVerifyManager::HapSignVerifyManager(const IAppVerifyAdapter& adapter) : adapter_(&adapter)
{
    if (RdDeviceChecker::IsRdDevice()) {
        LOGI(ATM_DOMAIN, ATM_TAG, "Detected RD device, enabling dev mode.");
        Security::Verify::SetDevMode(Security::Verify::DevMode::DEV);
        Security::Verify::SetRdDevice(true);
    }
}

Security::Verify::VerifyParams HapSignVerifyManager::MakeVerifyParams(
    const std::string& path, Security::Verify::VerifyType type, int32_t userId)
{
    Security::Verify::VerifyParams params;
    params.filePath = path;
    params.certPath = GetEnterpriseCertPath(userId);
    params.type = type;
    return params;
}

int32_t HapSignVerifyManager::VerifyFailed(int32_t ret, bool& isChanged, TrustedBundleInfoInner& info,
    Security::Verify::ProvisionInfo& provisionInfo) const
{
#ifdef X86_EMULATOR_MODE
    LOGI(ATM_DOMAIN, ATM_TAG, "Verify hap failed in X86_EMULATOR_MODE, ignore verification result, ret=%{public}d.",
        ret);
    isChanged = false;
    ret = BuildTrustedBundleInfo(info.bootstrapInfo, provisionInfo, info);
    info.provisionInfo.appId.clear();
    info.ignoreVerificationFailure = true;
    if (ret != RET_SUCCESS) {
        LOGE(ATM_DOMAIN, ATM_TAG, "Build trusted bundle info failed, ret=%{public}d.", ret);
    }
    return ret;
#else
    LOGE(ATM_DOMAIN, ATM_TAG, "Verify hap failed, ret=%{public}d.", ret);
    return ret;
#endif
}

int32_t HapSignVerifyManager::CheckHapsSignInfo(Security::Verify::VerifyParams params, bool booting,
    TrustedBundleInfoInner& info, bool& isChanged) const
{
    char resolvedPath[PATH_MAX] = {0};
    std::string path = params.filePath;
    if (realpath(path.c_str(), resolvedPath) == nullptr) {
        if (errno != ENOENT) {
            LOGC(ATM_DOMAIN, ATM_TAG, "Failed to resolve path %{public}s: %{public}s", path.c_str(), strerror(errno));
            return ERR_VERIFY_CANT_OPEN;
        } else {
            LOGW(ATM_DOMAIN, ATM_TAG, "Failed to resolve path %{public}s: %{public}s", path.c_str(), strerror(errno));
            return ERR_VERIFY_FILE_NOT_EXIST;
        }
    }

    if (!IsHapPathAllowed(resolvedPath)) {
        LOGW(ATM_DOMAIN, ATM_TAG, "Hap path is not allowed, path=%{public}s.",
            params.filePath.c_str());
    }
    if (info.bootstrapInfo == nullptr) {
        info.bootstrapInfo = std::make_shared<Security::Verify::BootstrapInfo>();
    }
    Security::Verify::ProvisionInfo provisionInfo;
    int32_t ret = adapter_->VerifyHap(params, *info.bootstrapInfo, provisionInfo, isChanged);
    if (ret != RET_SUCCESS) {
        return VerifyFailed(ret, isChanged, info, provisionInfo);
    }
    if (!isChanged) {
        if (booting) {
            ret = adapter_->ParseProfile(info.bootstrapInfo->profileJsonRaw, provisionInfo);
        } else {
            ret = adapter_->ParseProvision(info.bootstrapInfo->profileJsonRaw, provisionInfo);
        }
        if (ret != RET_SUCCESS) {
            LOGE(ATM_DOMAIN, ATM_TAG, "Parse provision failed, ret=%{public}d.", ret);
            return ERR_HAP_PROVISION_INVALID;
        }
    }
    std::shared_ptr<Security::Verify::BootstrapInfo> bootstrapInfo = info.bootstrapInfo;
    ret = BuildTrustedBundleInfo(bootstrapInfo, provisionInfo, info);
    if (ret != RET_SUCCESS) {
        LOGE(ATM_DOMAIN, ATM_TAG, "Build trusted bundle info failed, ret=%{public}d.", ret);
    }
    return ret;
}

bool HapSignVerifyManager::CheckAppIdentifier(const TrustedBundleInfoInner &oldInfo,
    const TrustedBundleInfoInner &newInfo) const
{
    const auto &oldAppIdentifier = oldInfo.GetAppIdentifier();
    const auto &newAppIdentifier = newInfo.GetAppIdentifier();
    const auto &oldAppId = oldInfo.GetAppId();
    const auto &newAppId = newInfo.GetAppId();

    // for versionCode update
    if (!oldAppIdentifier.empty() &&
        !newAppIdentifier.empty() &&
        oldAppIdentifier == newAppIdentifier) {
        return true;
    }
    if (oldAppId == newAppId) {
        return true;
    }
    return false;
}

int32_t HapSignVerifyManager::CheckMultipleHaps(const std::vector<TrustedBundleInfoInner>& infos) const
{
    LOGD(ATM_DOMAIN, ATM_TAG, "Check multiple trusted haps.");
    if (infos.empty()) {
        LOGC(ATM_DOMAIN, ATM_TAG, "Check multiple haps failed, infos is empty.");
        return AccessTokenError::ERR_PARAM_INVALID;
    }

#ifdef X86_EMULATOR_MODE
    if (std::any_of(infos.begin(), infos.end(), [](const auto& info) {
        return IsIgnoredTrustedBundleInfo(info);
    })) {
        LOGD(ATM_DOMAIN, ATM_TAG, "Check multiple trusted haps skipped in X86_EMULATOR_MODE.");
        return RET_SUCCESS;
    }
#endif

    const TrustedBundleInfoInner& baseline = infos.front();
    bool isInvalid = std::any_of(infos.begin(), infos.end(), [&baseline, this](const auto& info) {
        if (baseline.GetBundleName() != info.GetBundleName()) {
            LOGC(ATM_DOMAIN, ATM_TAG, "Check multiple haps failed, hap files have different bundleName.");
            return true;
        }
        if (!CheckAppIdentifier(baseline, info)) {
            LOGC(ATM_DOMAIN, ATM_TAG, "Check multiple haps failed, hap files have different appId and appIdentifier.");
            return true;
        }
        if (baseline.GetApl() != info.GetApl()) {
            LOGC(ATM_DOMAIN, ATM_TAG, "Check multiple haps failed, hap files have different apl.");
            return true;
        }
        if (baseline.GetAppDistributionType() != info.GetAppDistributionType()) {
            LOGC(ATM_DOMAIN, ATM_TAG, "Check multiple haps failed, hap files have different appDistributionType.");
            return true;
        }
        if (baseline.GetAppProvisionType() != info.GetAppProvisionType()) {
            LOGC(ATM_DOMAIN, ATM_TAG, "Check multiple haps failed, hap files have different appProvisionType.");
            return true;
        }
        return false;
    });
    if (!isInvalid) {
        LOGD(ATM_DOMAIN, ATM_TAG, "Check multiple trusted haps successfully.");
    }
    return isInvalid ? AccessTokenError::ERR_PARAM_INVALID : RET_SUCCESS;
}

int32_t HapSignVerifyManager::BuildHapPolicy(
    const std::vector<TrustedBundleInfoInner>& infos, HapPolicy& policy, BundleParam& param) const
{
    if (infos.empty()) {
        LOGC(ATM_DOMAIN, ATM_TAG, "Build hap policy failed, sortedInfos is empty.");
        return AccessTokenError::ERR_PARAM_INVALID;
    }

    const std::vector<TrustedBundleInfoInner> sortedInfos = [&infos]() {
        std::vector<TrustedBundleInfoInner> copy = infos;
        SortTrustedBundles(copy);
        return copy;
    }();

    const TrustedBundleInfoInner& baseline = sortedInfos.front();
#ifdef X86_EMULATOR_MODE
    policy.checkIgnore = std::any_of(sortedInfos.begin(), sortedInfos.end(), [](const auto& info) {
        return IsIgnoredTrustedBundleInfo(info);
    }) ?
        HapPolicyCheckIgnore::ACL_IGNORE_CHECK : HapPolicyCheckIgnore::NONE;
#else
    policy.checkIgnore = HapPolicyCheckIgnore::NONE;
#endif
    policy.apl = HapSignVerifyHelper::ConvertApl(baseline.GetApl());
    policy.domain = HAP_POLICY_DEFAULT_DOMAIN;
    HapSignVerifyHelper::FillPermissionDefList(sortedInfos, policy.permList);
    HapSignVerifyHelper::FillAclRequestedList(sortedInfos, policy.aclRequestedList);
    HapSignVerifyHelper::FillAclExtendedMap(sortedInfos, policy.aclExtendedMap);
    policy.isDebugGrant = false;
    HapSignVerifyHelper::FillPermissionStateList(sortedInfos, policy.permStateList);

    param.bundleName = baseline.GetBundleName();
    param.appId = param.bundleName + "_" + baseline.provisionInfo.appId;
#ifdef X86_EMULATOR_MODE
    if (policy.checkIgnore == HapPolicyCheckIgnore::ACL_IGNORE_CHECK) {
        param.appId.clear();
    }
#endif
    param.apiVersion = baseline.moduleData.apiTargetVersion;
    param.distributionType = baseline.provisionInfo.distributionType;
    param.isSystem = baseline.IsSystemApp();
    param.isAtomicService = baseline.IsAtomicService();
    param.isDebug = (baseline.GetAppProvisionType() == "debug");
    param.appIdentifier = HapSignVerifyHelper::BuildOwnerId(
        baseline.GetAppIdentifier());

    param.idType = HapSignVerifyHelper::BuildIdType(
        param.isDebug, baseline.GetAppIdentifier(), policy.permStateList);

    return RET_SUCCESS;
}

int32_t HapSignVerifyManager::CheckPermissionRequestValid(
    const TrustedBundleInfoInner& info, const HapPolicy& policy, HapInfoCheckResult& result) const
{
    BundleParam bundleParam;
    bundleParam.bundleName = info.GetBundleName();
    bundleParam.distributionType = info.provisionInfo.distributionType;
    bundleParam.isSystem = info.IsSystemApp();
    bundleParam.isDebug = (info.GetAppProvisionType() == "debug");

    std::vector<PermissionStatus> initializedList;
    std::vector<GenericValues> undefValues;
    if (!PermissionManager::GetInstance().InitPermissionList(bundleParam, policy, initializedList,
        result, undefValues)) {
        return AccessTokenError::ERR_PERM_REQUEST_CFG_FAILED;
    }
    return RET_SUCCESS;
}

void HapSignVerifyManager::ConvertTrustedBundleInfo(
    const std::vector<TrustedBundleInfoInner>& bundleInfos, std::vector<TrustedBundleInfo>& bundleInfo) const
{
    for (const auto& infoInner : bundleInfos) {
        if (infoInner.bootstrapInfo != nullptr) {
            TrustedBundleInfo info;
            info.profileData.provisionRaw = infoInner.bootstrapInfo->profileJsonRaw;
            info.profileData.profileBlockLength = infoInner.provisionInfo.profileBlockLength;
            if (infoInner.provisionInfo.profileBlock != nullptr && infoInner.provisionInfo.profileBlockLength > 0) {
                info.profileData.profileBlock.assign(infoInner.provisionInfo.profileBlock.get(),
                    infoInner.provisionInfo.profileBlock.get() + infoInner.provisionInfo.profileBlockLength);
            }
            info.profileData.appId = infoInner.provisionInfo.appId;
            info.profileData.fingerprint = infoInner.provisionInfo.fingerprint;
            info.profileData.organization = infoInner.provisionInfo.organization;
            info.profileData.isOpenHarmony = infoInner.provisionInfo.isOpenHarmony;
            info.profileData.isEnterpriseResigned = infoInner.provisionInfo.isEnterpriseResigned;
            info.moduleInfo = infoInner.bootstrapInfo->moduleRaw;
            info.sharedFiles = infoInner.bootstrapInfo->shareFilesRaw;
            bundleInfo.emplace_back(info);
        }
    }
}
} // namespace AccessToken
} // namespace Security
} // namespace OHOS
