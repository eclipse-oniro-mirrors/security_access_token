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

#ifndef ACCESS_TOKEN_MOCK_APP_VERIFY_ADAPTER_H
#define ACCESS_TOKEN_MOCK_APP_VERIFY_ADAPTER_H

#include <string>
#include <vector>

#include "access_token.h"
#include "app_verify_adapter.h"

namespace OHOS {
namespace Security {
namespace AccessToken {

inline std::vector<AppExecFwk::Spm::RequestPermission> BuildDefaultMockRequestPermissions()
{
    AppExecFwk::Spm::RequestPermission requestPermission;
    requestPermission.name = "ohos.permission.CAMERA";
    requestPermission.requiredFeature = "";
    return { requestPermission };
}

// Mock adapter for testing HapSignVerifyManager with controllable return values.
// verifyRet_ and parseRet_ let tests inject failures at the VerifyHap or ParseHapModuleInfo stages.
class MockAppVerifyAdapter final : public IAppVerifyAdapter {
public:
    int32_t VerifyHap(const Security::Verify::VerifyParams& params,
        Security::Verify::BootstrapInfo& bootstrapInfo, Security::Verify::ProvisionInfo& provisionInfo,
        bool& isChanged) const override
    {
        if (verifyRet_ != RET_SUCCESS) {
            return verifyRet_;
        }
        bootstrapInfo.version = bootstrapVersion_;
        bootstrapInfo.moduleRaw = moduleRaw_.empty() ? params.filePath : moduleRaw_;
        bootstrapInfo.shareFilesRaw = shareFilesRaw_;
        bootstrapInfo.profileJsonRaw = profileJsonRaw_.empty() ? params.filePath : profileJsonRaw_;
        lastCertPath_ = params.certPath;
        provisionInfo.versionCode = 1;
        provisionInfo.type = provisionType_;
        provisionInfo.distributionType = distributionType_;
        provisionInfo.bundleInfo.apl = apl_;
        provisionInfo.bundleInfo.appIdentifier = appIdentifier_.empty() ? params.filePath : appIdentifier_;
        provisionInfo.bundleInfo.bundleName = bundleName_.empty() ? params.filePath : bundleName_;
        provisionInfo.bundleInfo.appFeature = appFeature_;
        provisionInfo.appId = appId_.empty() ? params.filePath : appId_;
        provisionInfo.acls.allowedAcls = allowedAcls_;
        provisionInfo.appServiceCapabilities = appServiceCapabilities_;
        isChanged = verifyIsChanged_;
        ++verifyCallCount_;
        return RET_SUCCESS;
    }

    int32_t ParseHapModuleInfo(const std::string& moduleRaw,
        AppExecFwk::Spm::InnerModuleInfoForSpm& moduleInfo) const override
    {
        isParseCalled_ = true;
        if (parseRet_ != RET_SUCCESS) {
            return parseRet_;
        }
        moduleInfo.bundleName = bundleName_.empty() ? moduleRaw : bundleName_;
        moduleInfo.moduleName = moduleName_;
        moduleInfo.apiTargetVersion = apiTargetVersion_;
        moduleInfo.bundleType = bundleType_;
        moduleInfo.requestPermission = requestPermissions_;
        moduleInfo.definePermission = definePermissions_;
        ++parseCallCount_;
        return RET_SUCCESS;
    }

    int32_t ParseProvision(const std::string& appProvision, Security::Verify::ProvisionInfo& info) const override
    {
        (void)appProvision;
        ++parseProvisionCallCount_;
        info.versionCode = 1;
        info.type = provisionType_;
        info.distributionType = distributionType_;
        info.bundleInfo.apl = apl_;
        info.bundleInfo.appIdentifier = appIdentifier_;
        info.bundleInfo.bundleName = bundleName_;
        info.bundleInfo.appFeature = appFeature_;
        info.appId = appId_;
        info.acls.allowedAcls = allowedAcls_;
        info.appServiceCapabilities = appServiceCapabilities_;
        return RET_SUCCESS;
    }

    int32_t verifyRet_ = RET_SUCCESS;
    int32_t parseRet_ = RET_SUCCESS;
    bool verifyIsChanged_ = false;
    int32_t bootstrapVersion_ = 1;
    int32_t apiTargetVersion_ = 12;
    std::string moduleRaw_;
    std::string shareFilesRaw_;
    std::string profileJsonRaw_;
    std::string bundleName_ = "com.example.bundle";
    std::string moduleName_ = "entry";
    std::string apl_ = "normal";
    std::string appIdentifier_ = "mock.identifier";
    std::string appId_ = "mock.appid";
    std::string appFeature_;
    std::string appServiceCapabilities_;
    std::vector<std::string> allowedAcls_;
    Security::Verify::AppDistType distributionType_ = Security::Verify::NONE_TYPE;
    Security::Verify::ProvisionType provisionType_ = Security::Verify::RELEASE;
    AppExecFwk::Spm::BundleType bundleType_ = AppExecFwk::Spm::BundleType::APP;
    std::vector<AppExecFwk::Spm::RequestPermission> requestPermissions_ = BuildDefaultMockRequestPermissions();
    std::vector<AppExecFwk::Spm::DefinePermission> definePermissions_;
    mutable bool isParseCalled_ = false;
    mutable std::string lastCertPath_;
    mutable uint32_t verifyCallCount_ = 0;
    mutable uint32_t parseCallCount_ = 0;
    mutable uint32_t parseProvisionCallCount_ = 0;
};

} // namespace AccessToken
} // namespace Security
} // namespace OHOS

#endif // ACCESS_TOKEN_MOCK_APP_VERIFY_ADAPTER_H
