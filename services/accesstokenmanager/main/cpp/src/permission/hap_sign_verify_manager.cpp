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
#include "permission_manager.h"
#include "provision/provision_info.h"
#include "provision/provision_verify.h"
#include "spm_module_parser.h"

namespace OHOS {
namespace Security {
namespace AccessToken {
namespace {
constexpr const char* HAP_POLICY_DEFAULT_DOMAIN = "domain";
constexpr char APP_PROVISION_TYPE_DEBUG[] = "debug";
constexpr char APP_PROVISION_TYPE_RELEASE[] = "release";
constexpr const char* ENTERPRISE_CERT_PATH =
    "/data/service/el1/public/bms/bundle_manager_service/certificates/enterprise/";

constexpr int32_t API_VERSION_MASK = 1000;

constexpr uint32_t PROCESS_OWNERID_APP = 2;
constexpr uint32_t PROCESS_OWNERID_DEBUG = 3;
constexpr uint32_t PROCESS_OWNERID_COMPAT = 5;

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
        return AccessTokenError::ERR_PARAM_INVALID;
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

uint32_t TrustedBundleInfoInner::GetSpmIdType() const
{
    if (provisionInfo.type == Security::Verify::DEBUG) {
        return PROCESS_OWNERID_DEBUG;
    }
    if (provisionInfo.bundleInfo.appIdentifier.empty()) {
        return PROCESS_OWNERID_COMPAT;
    }
    // access_token does not currently receive the APP_FLAGS_TEMP_JIT signal used by
    // appspawn SetXpmConfig(), so PROCESS_OWNERID_APP_TEMP_ALLOW cannot be derived here yet.
    return PROCESS_OWNERID_APP;
}

#ifdef X86_EMULATOR_MODE
TrustedBundleInfoInner HapSignVerifyManager::BuildIgnoredTrustedBundleInfo()
{
    TrustedBundleInfoInner info;
    info.bootstrapInfo = std::make_shared<Security::Verify::BootstrapInfo>();
    info.provisionInfo.appId.clear();
    info.shareFilesRaw.clear();
    info.ignoreVerificationFailure = true;
    return info;
}
#endif

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

int32_t HapSignVerifyManager::CheckHapsSignInfo(const std::string path,
    const Security::Verify::VerifyType type, int32_t userId,
    TrustedBundleInfoInner& info, bool& isChanged) const
{
    if (info.bootstrapInfo == nullptr) {
        info.bootstrapInfo = std::make_shared<Security::Verify::BootstrapInfo>();
    }
    Security::Verify::VerifyParams params;
    params.filePath = path;
    params.certPath = GetEnterpriseCertPath(userId);
    params.type = type;
    Security::Verify::ProvisionInfo provisionInfo;
    int32_t ret = adapter_->VerifyHap(params, *info.bootstrapInfo, provisionInfo, isChanged);
    if (ret != RET_SUCCESS) {
#ifdef X86_EMULATOR_MODE
        LOGW(ATM_DOMAIN, ATM_TAG, "Verify hap failed in X86_EMULATOR_MODE, ignore verification result, ret=%{public}d.",
            ret);
        info = BuildIgnoredTrustedBundleInfo();
        isChanged = false;
        return RET_SUCCESS;
#else
        return ret;
#endif
    }
    if (!isChanged) {
        ret = adapter_->ParseProvision(info.bootstrapInfo->profileJsonRaw, provisionInfo);
        if (ret != RET_SUCCESS) {
            LOGE(ATM_DOMAIN, ATM_TAG, "Parse provision failed, ret=%{public}d.", ret);
            return ret;
        }
    }
    std::shared_ptr<Security::Verify::BootstrapInfo> bootstrapInfo = info.bootstrapInfo;
    ret = BuildTrustedBundleInfo(bootstrapInfo, provisionInfo, info);
    if (ret != RET_SUCCESS) {
        LOGE(ATM_DOMAIN, ATM_TAG, "Build trusted bundle info failed, ret=%{public}d.", ret);
    }
    return ret;
}

int32_t HapSignVerifyManager::CheckMultipleHaps(const std::vector<TrustedBundleInfoInner>& infos) const
{
    LOGD(ATM_DOMAIN, ATM_TAG, "Check multiple trusted haps.");
    if (infos.empty()) {
        LOGE(ATM_DOMAIN, ATM_TAG, "Check multiple haps failed, infos is empty.");
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
    bool isInvalid = std::any_of(infos.begin(), infos.end(), [&baseline](const auto& info) {
        if (baseline.GetBundleName() != info.GetBundleName()) {
            LOGE(ATM_DOMAIN, ATM_TAG, "Check multiple haps failed, hap files have different bundleName.");
            return true;
        }
        if (baseline.GetAppId() != info.GetAppId()) {
            LOGE(ATM_DOMAIN, ATM_TAG, "Check multiple haps failed, hap files have different appId.");
            return true;
        }
        if (baseline.GetAppIdentifier() != info.GetAppIdentifier()) {
            LOGE(ATM_DOMAIN, ATM_TAG, "Check multiple haps failed, hap files have different appIdentifier.");
            return true;
        }
        if (baseline.GetApl() != info.GetApl()) {
            LOGE(ATM_DOMAIN, ATM_TAG, "Check multiple haps failed, hap files have different apl.");
            return true;
        }
        if (baseline.GetAppDistributionType() != info.GetAppDistributionType()) {
            LOGE(ATM_DOMAIN, ATM_TAG, "Check multiple haps failed, hap files have different appDistributionType.");
            return true;
        }
        if (baseline.GetAppProvisionType() != info.GetAppProvisionType()) {
            LOGE(ATM_DOMAIN, ATM_TAG, "Check multiple haps failed, hap files have different appProvisionType.");
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
        LOGE(ATM_DOMAIN, ATM_TAG, "Build hap policy failed, infos is empty.");
        return AccessTokenError::ERR_PARAM_INVALID;
    }

    const TrustedBundleInfoInner& baseline = infos.front();
#ifdef X86_EMULATOR_MODE
    policy.checkIgnore = std::any_of(infos.begin(), infos.end(), [](const auto& info) {
        return IsIgnoredTrustedBundleInfo(info);
    }) ?
        HapPolicyCheckIgnore::ACL_IGNORE_CHECK : HapPolicyCheckIgnore::NONE;
#else
    policy.checkIgnore = HapPolicyCheckIgnore::NONE;
#endif
    policy.apl = HapSignVerifyHelper::ConvertApl(baseline.GetApl());
    policy.domain = HAP_POLICY_DEFAULT_DOMAIN;
    HapSignVerifyHelper::FillPermissionDefList(infos, policy.permList);
    HapSignVerifyHelper::FillAclRequestedList(infos, policy.aclRequestedList);
    HapSignVerifyHelper::FillAclExtendedMap(infos, policy.aclExtendedMap);
    policy.isDebugGrant = false;
    HapSignVerifyHelper::FillPermissionStateList(infos, policy.permStateList);

    param.bundleName = baseline.GetBundleName();
    param.appId = param.bundleName + "_" + baseline.provisionInfo.appId;
    param.apiVersion = baseline.moduleData.apiTargetVersion;
    param.distributionType = baseline.provisionInfo.distributionType;
    param.isSystem = baseline.IsSystemApp();
    param.isAtomicService = baseline.IsAtomicService();
    param.isDebug = (baseline.GetAppProvisionType() == "debug");
    param.appIdentifier = HapSignVerifyHelper::BuildOwnerId(
        baseline.GetAppIdentifier());
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
} // namespace AccessToken
} // namespace Security
} // namespace OHOS
