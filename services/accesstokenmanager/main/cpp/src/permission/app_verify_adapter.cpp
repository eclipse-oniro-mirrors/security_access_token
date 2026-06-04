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

#include "app_verify_adapter.h"

#include "access_token.h"
#include "access_token_error.h"
#include "interfaces/hap_verify.h"
#include "provision/provision_verify.h"
#include "spm_module_parser.h"

namespace OHOS {
namespace Security {
namespace AccessToken {
int32_t AppVerifyAdapter::VerifyHap(const Security::Verify::VerifyParams& params,
    Security::Verify::BootstrapInfo& bootstrapInfo, Security::Verify::ProvisionInfo& provisionInfo,
    bool& isChanged) const
{
    return Security::Verify::VerifyOrParseHapPermission(params, bootstrapInfo, provisionInfo, isChanged);
}

int32_t AppVerifyAdapter::ParseHapModuleInfo(const std::string& moduleRaw,
    AppExecFwk::Spm::InnerModuleInfoForSpm& moduleInfo) const
{
    return AppExecFwk::Spm::ParseSpmModule(moduleRaw, moduleInfo) ?
        RET_SUCCESS : AccessTokenError::ERR_PARAM_INVALID;
}

int32_t AppVerifyAdapter::ParseProvision(const std::string& appProvision, Security::Verify::ProvisionInfo& info) const
{
    int32_t ret = Security::Verify::ParseProvisionJson(appProvision, info);
    return ret == Security::Verify::HapVerifyResultCode::VERIFY_SUCCESS ? RET_SUCCESS : ret;
}

} // namespace AccessToken
} // namespace Security
} // namespace OHOS
