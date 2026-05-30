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

#ifndef ACCESS_TOKEN_APP_VERIFY_ADAPTER_H
#define ACCESS_TOKEN_APP_VERIFY_ADAPTER_H

#include <memory>
#include <string>

#include "interfaces/hap_verify.h"
#include "spm_module_parser.h"

namespace OHOS {
namespace Security {
namespace AccessToken {

class IAppVerifyAdapter {
public:
    virtual ~IAppVerifyAdapter() = default;
    virtual int32_t VerifyHap(const Security::Verify::VerifyParams& params,
        Security::Verify::BootstrapInfo& bootstrapInfo, Security::Verify::ProvisionInfo& provisionInfo,
        bool& isChanged) const = 0;
    virtual int32_t ParseHapModuleInfo(const std::string& moduleRaw,
        AppExecFwk::Spm::InnerModuleInfoForSpm& moduleInfo) const = 0;
    virtual int32_t ParseProvision(const std::string& appProvision, Security::Verify::ProvisionInfo& info) const = 0;
};

class AppVerifyAdapter final : public IAppVerifyAdapter {
public:
    ~AppVerifyAdapter() override = default;
    int32_t VerifyHap(const Security::Verify::VerifyParams& params,
        Security::Verify::BootstrapInfo& bootstrapInfo, Security::Verify::ProvisionInfo& provisionInfo,
        bool& isChanged) const override;
    int32_t ParseHapModuleInfo(const std::string& moduleRaw,
        AppExecFwk::Spm::InnerModuleInfoForSpm& moduleInfo) const override;
    int32_t ParseProvision(const std::string& appProvision, Security::Verify::ProvisionInfo& info) const override;
};
} // namespace AccessToken
} // namespace Security
} // namespace OHOS

#endif // ACCESS_TOKEN_APP_VERIFY_ADAPTER_H
