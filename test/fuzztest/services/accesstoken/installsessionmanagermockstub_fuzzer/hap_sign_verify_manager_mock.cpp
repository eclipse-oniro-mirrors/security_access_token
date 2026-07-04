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

int32_t HapSignVerifyManager::CheckHapsSignInfo(Security::Verify::VerifyParams params, bool booting,
    TrustedBundleInfoInner& info, bool& isChanged) const
{
    if (params.filePath.empty()) {
        return RET_FAILED;
    }
    info.moduleData.bundleName = "install_session_manager_fuzz_mock_test";
    info.moduleData.moduleName = params.filePath;
    info.moduleData.bundleType = AppExecFwk::Spm::BundleType::APP;
    info.provisionInfo.bundleInfo.appIdentifier = params.filePath;
    info.provisionInfo.appId = params.filePath;
    info.shareFilesRaw = params.filePath;
    info.bootstrapInfo = std::make_shared<Security::Verify::BootstrapInfo>();
    return RET_SUCCESS;
}

int32_t HapSignVerifyManager::CheckMultipleHaps(const std::vector<TrustedBundleInfoInner>& infos) const
{
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

void FillPolicyByInfo(HapPolicy& policy)
{
    PermissionStatus perm;
    perm.grantStatus = PERMISSION_DENIED;
    perm.grantFlag = PERMISSION_DEFAULT_FLAG;
    perm.permissionName = "ohos.permission.CAMERA";
    policy.permStateList.emplace_back(perm);
    perm.permissionName = "ohos.permission.MANAGE_WIFI_CONNECTION";
    policy.permStateList.emplace_back(perm);
    perm.permissionName = "ohos.permission.kernel.SUPPORT_PLUGIN";
    policy.permStateList.emplace_back(perm);

    policy.aclRequestedList.emplace_back("ohos.permission.MANAGE_WIFI_CONNECTION");

    policy.aclExtendedMap["ohos.permission.kernel.SUPPORT_PLUGIN"] = "extValue";
}

void FillHapPolicy(HapPolicy& policy)
{
    policy.apl = APL_SYSTEM_CORE;
    FillPolicyByInfo(policy);
}

int32_t HapSignVerifyManager::BuildHapPolicy(const std::vector<TrustedBundleInfoInner>& infos, HapPolicy& policy,
    BundleParam& param) const
{
    if (infos.empty()) {
        return AccessTokenError::ERR_PARAM_INVALID;
    }

    FillBundleParam(infos[0], param);
    FillHapPolicy(policy);

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

int32_t HapSignVerifyManager::VerifyFailed(int32_t ret, bool& isChanged, TrustedBundleInfoInner& info,
    Security::Verify::ProvisionInfo& provisionInfo) const
{
    return 0;
}

int32_t HapSignVerifyManager::BuildTrustedBundleInfo(
    const std::shared_ptr<Security::Verify::BootstrapInfo>& bootstrapInfo,
    const Security::Verify::ProvisionInfo& provisionInfo, TrustedBundleInfoInner& info) const
{
    return 0;
}

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
