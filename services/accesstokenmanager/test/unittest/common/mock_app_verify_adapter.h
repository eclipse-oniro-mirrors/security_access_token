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

#include "access_token.h"
#include "app_verify_adapter.h"

namespace OHOS {
namespace Security {
namespace AccessToken {

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
        bootstrapInfo.moduleRaw = params.filePath;
        bootstrapInfo.profileJsonRaw = params.filePath;
        lastCertPath_ = params.certPath;
        provisionInfo.versionCode = 1;
        provisionInfo.type = Security::Verify::RELEASE;
        provisionInfo.distributionType = Security::Verify::NONE_TYPE;
        provisionInfo.bundleInfo.apl = "normal";
        provisionInfo.bundleInfo.appIdentifier = params.filePath;
        provisionInfo.bundleInfo.bundleName = params.filePath;
        provisionInfo.appId = params.filePath;
        isChanged = false;
        return RET_SUCCESS;
    }

    int32_t ParseHapModuleInfo(const std::string& moduleRaw,
        AppExecFwk::Spm::InnerModuleInfoForSpm& moduleInfo) const override
    {
        isParseCalled_ = true;
        if (parseRet_ != RET_SUCCESS) {
            return parseRet_;
        }
        moduleInfo.bundleName = moduleRaw;
        moduleInfo.moduleName = "parsed_module";
        AppExecFwk::Spm::RequestPermission reqPerm;
        reqPerm.name = "ohos.permission.CAMERA";
        moduleInfo.requestPermission.emplace_back(reqPerm);
        return RET_SUCCESS;
    }

    int32_t ParseProvision(const std::string& appProvision, Security::Verify::ProvisionInfo& info) const override
    {
        return RET_SUCCESS;
    }

    int32_t verifyRet_ = RET_SUCCESS;
    int32_t parseRet_ = RET_SUCCESS;
    mutable bool isParseCalled_ = false;
    mutable std::string lastCertPath_;
};

} // namespace AccessToken
} // namespace Security
} // namespace OHOS

#endif // ACCESS_TOKEN_MOCK_APP_VERIFY_ADAPTER_H
