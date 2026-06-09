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

#define private public
#include "hap_sign_verify_manager.h"
#undef private

#include "access_token_error.h"
#include <sstream>

namespace OHOS {
namespace Security {
namespace AccessToken {
namespace {
constexpr char APP_PROVISION_TYPE_DEBUG[] = "debug";
constexpr char APP_PROVISION_TYPE_RELEASE[] = "release";
constexpr int32_t TEST_API_VERSION = 10;
}

HapSignVerifyManager& HapSignVerifyManager::GetInstance()
{
    static HapSignVerifyManager instance;
    return instance;
}

HapSignVerifyManager::HapSignVerifyManager()
{
    adapter_ = nullptr;
}

HapSignVerifyManager::HapSignVerifyManager(const IAppVerifyAdapter& adapter) : adapter_(&adapter)
{}

bool CheckFailed(const std::string path)
{
    if (path.find("checkfailed") != std::string::npos || path.find("CheckFailed") != std::string::npos) {
        return true;
    }
    return false;
}

bool FillModuelData(const std::string path, TrustedBundleInfoInner& info)
{
    std::string bundleName = path.substr(path.find_last_of('/') + 1);
    std::string temp = path.substr(0, path.find_last_of('/'));
    std::string moduleName = temp.substr(temp.find_last_of('/') + 1);
    if (bundleName.empty() || moduleName.empty()) {
        return false;
    }

    info.moduleData.bundleName = bundleName;
    info.moduleData.moduleName = moduleName;

    info.moduleData.bundleType = AppExecFwk::Spm::BundleType::APP;
    if (path.find("SHARED") != std::string::npos) {
        info.moduleData.bundleType = AppExecFwk::Spm::BundleType::SHARED;
    } else if (path.find("APP_SERVICE_FWK") != std::string::npos) {
        info.moduleData.bundleType = AppExecFwk::Spm::BundleType::APP_SERVICE_FWK;
    } else if (path.find("APP_PLUGIN") != std::string::npos) {
        info.moduleData.bundleType = AppExecFwk::Spm::BundleType::APP_PLUGIN;
    } else if (path.find("SKILL") != std::string::npos) {
        info.moduleData.bundleType = AppExecFwk::Spm::BundleType::SKILL;
    }

    info.provisionInfo.bundleInfo.appIdentifier = bundleName;
    info.provisionInfo.appId = bundleName;
    info.shareFilesRaw = path;

    info.bootstrapInfo = std::make_shared<Security::Verify::BootstrapInfo>();
    return true;
}

int32_t HapSignVerifyManager::CheckHapsSignInfo(Security::Verify::VerifyParams params, bool booting,
    TrustedBundleInfoInner& info, bool& isChanged) const
{
    if (CheckFailed(params.filePath)) {
        return AccessTokenError::ERR_PARAM_INVALID;
    }

    if (!FillModuelData(params.filePath, info)) {
        return AccessTokenError::ERR_PARAM_INVALID;
    }

    return RET_SUCCESS;
}

int32_t HapSignVerifyManager::CheckMultipleHaps(const std::vector<TrustedBundleInfoInner>& infos) const
{
    if (infos.empty()) {
        return RET_SUCCESS;
    }

    const std::string& firstBundleName = infos[0].GetBundleName();
    for (size_t i = 1; i < infos.size(); ++i) {
        if (infos[i].GetBundleName() != firstBundleName) {
            return AccessTokenError::ERR_PARAM_INVALID;
        }
    }

    for (size_t i = 0; i < infos.size(); ++i) {
        if (infos[i].moduleData.moduleName.find("MultipleFailed") != std::string::npos) {
            return AccessTokenError::ERR_PARAM_INVALID;
        }
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

Security::Verify::VerifyParams HapSignVerifyManager::MakeVerifyParams(
    const std::string& path, Security::Verify::VerifyType type, int32_t userId)
{
    Security::Verify::VerifyParams params;
    params.filePath = path;
    params.certPath = "";
    params.type = type;
    return params;
}


void FillBundleParam(const TrustedBundleInfoInner& info, BundleParam& param)
{
    param.bundleName = info.moduleData.bundleName;
    param.appId = info.moduleData.bundleName + "aaaaa";
    param.appIdentifier = 0;
    param.apiVersion = TEST_API_VERSION;
    param.distributionType = 0;

    if (info.shareFilesRaw.find("SYSTEM") != std::string::npos) {
        param.isSystem = true;
    }
    if (info.shareFilesRaw.find("DEBUG") != std::string::npos) {
        param.isDebug = true;
    }
    if (info.shareFilesRaw.find("MDM") != std::string::npos) {
        param.distributionType = Security::Verify::AppDistType::ENTERPRISE_MDM;
    }
}

std::vector<std::string> EextractItems(const std::string& str, const std::string& key)
{
    std::vector<std::string> items;
    
    std::string prefix = key + ":[";
    size_t start = str.find(prefix);
    if (start == std::string::npos) return items;
    
    size_t contentStart = start + prefix.length();
    size_t end = str.find(']', contentStart);
    if (end == std::string::npos) return items;
    
    std::string content = str.substr(contentStart, end - contentStart);
    
    std::stringstream ss(content);
    std::string item;
    while (std::getline(ss, item, ',')) {
        items.push_back(item);
    }
    
    return items;
}

bool ConvertPerm(const std::string& key, std::string& permissionName)
{
    if (key == "cam") {
        permissionName = "ohos.permission.CAMERA";
    } else if (key == "mic") {
        permissionName = "ohos.permission.MICROPHONE";
    } else if (key == "manblue") {
        permissionName = "ohos.permission.MANAGE_BLUETOOTH"; // system_basic + system
    } else if (key == "syswin") {
        permissionName = "ohos.permission.SYSTEM_FLOAT_WINDOW"; // system_basic + normal
    } else if (key == "getwifi") {
        permissionName = "ohos.permission.GET_WIFI_INFO_INTERNAL"; // system_core + system
    } else if (key == "manwifi") {
        permissionName = "ohos.permission.MANAGE_WIFI_CONNECTION"; // system_core + system
    }  else if (key == "mdminfo") {
        permissionName = "ohos.permission.SET_ENTERPRISE_INFO"; // system_basic + MDM
    } else if (key == "kernel") {
        permissionName = "ohos.permission.kernel.SUPPORT_PLUGIN"; // system_basic + hasValue
    } else {
        return false;
    }
    return true;
}

void FillPolicyByInfo(const std::string& str, HapPolicy& policy)
{
    std::vector<std::string> state = EextractItems(str, "state");
    for (auto& perm : state) {
        PermissionStatus cameraPerm;
        cameraPerm.grantStatus = PERMISSION_DENIED;
        cameraPerm.grantFlag = PERMISSION_DEFAULT_FLAG;
        if (!ConvertPerm(perm, cameraPerm.permissionName)) {
            continue;
        }
        policy.permStateList.emplace_back(cameraPerm);
    }

    std::vector<std::string> acls = EextractItems(str, "acl");
    for (auto& perm : acls) {
        std::string permissionName;
        if (!ConvertPerm(perm, permissionName)) {
            continue;
        }
        policy.aclRequestedList.emplace_back(permissionName);
    }

    std::vector<std::string> ext = EextractItems(str, "ext");
    for (auto& perm : ext) {
        std::string permissionName;
        if (!ConvertPerm(perm, permissionName)) {
            continue;
        }
        policy.aclExtendedMap[permissionName] = "extValue";
    }
}

void FillHapPolicy(const std::vector<TrustedBundleInfoInner>& infos, HapPolicy& policy)
{
    policy.apl = APL_NORMAL;
    if (infos[0].shareFilesRaw.find("system_basic") != std::string::npos) {
        policy.apl = APL_SYSTEM_BASIC;
    } else if (infos[0].shareFilesRaw.find("system_core") != std::string::npos) {
        policy.apl = APL_SYSTEM_CORE;
    }

    if (infos[0].shareFilesRaw.find("debug") != std::string::npos) {
        policy.isDebugGrant = true;
    }

    for (auto& info : infos) {
        FillPolicyByInfo(info.shareFilesRaw, policy);
    }
}

bool BuildFailed(const std::vector<TrustedBundleInfoInner>& infos)
{
    for (auto& info : infos) {
        if (info.shareFilesRaw.find("buildfailed") != std::string::npos ||
            info.shareFilesRaw.find("BuildFailed") != std::string::npos) {
            return true;
        }
    }
    return false;
}

int32_t HapSignVerifyManager::BuildHapPolicy(const std::vector<TrustedBundleInfoInner>& infos, HapPolicy& policy,
    BundleParam& param) const
{
    if (infos.empty()) {
        return AccessTokenError::ERR_PARAM_INVALID;
    }

    if (BuildFailed(infos)) {
        return AccessTokenError::ERR_PARAM_INVALID;
    }

    FillBundleParam(infos[0], param);
    FillHapPolicy(infos, policy);

    return RET_SUCCESS;
}

int32_t HapSignVerifyManager::CheckPermissionRequestValid(const TrustedBundleInfoInner& info, const HapPolicy& policy,
    HapInfoCheckResult& result) const
{
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

int32_t HapSignVerifyManager::BuildTrustedBundleInfo(
    const std::shared_ptr<Security::Verify::BootstrapInfo>& bootstrapInfo,
    const Security::Verify::ProvisionInfo& provisionInfo, TrustedBundleInfoInner& info) const
{
    return 0;
}

#ifdef X86_EMULATOR_MODE
TrustedBundleInfoInner HapSignVerifyManager::BuildIgnoredTrustedBundleInfo()
{
    TrustedBundleInfoInner info;
    return info;
}
#endif

std::string TrustedBundleInfoInner::GetAppDistributionType() const
{
    return "undefined";
}

bool RdDeviceChecker::IsRdDevice()
{
    return true;
}

bool RdDeviceChecker::CheckDeviceMode(char *buf, ssize_t bufLen)
{
    return true;
}

bool RdDeviceChecker::CheckEfuseStatus(char *buf, ssize_t bufLen)
{
    return true;
}

void RdDeviceChecker::ParseCMDLine()
{}
} // namespace AccessToken
} // namespace Security
} // namespace OHOS
