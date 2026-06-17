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

#ifndef ACCESS_TOKEN_INFO_UTILS_H
#define ACCESS_TOKEN_INFO_UTILS_H

#include <memory>
#include <string>
#include <vector>

#include "access_token.h"
#include "atm_data_type.h"
#include "hap_data_structure.h"
#include "hap_token_info.h"
#include "hap_token_info_inner.h"

namespace OHOS {
namespace Security {
namespace AccessToken {

static const char* ACCESS_TOKEN_SERVICE_APP_VERIFY_KEY = "accesstoken.permission.appverified";
static const char* ACCESS_TOKEN_SERVICE_SPM_ENFORCING_KEY = "accesstoken.permission.spm.enforcing";

class AccessTokenInfoUtils final {
public:
    static bool IsSystemResource(const std::string& bundleName);
    static bool CheckSpecifiedFlag(uint32_t tokenAttr, uint32_t flag);
    static std::string GetHapUniqueStr(int32_t userID, const std::string& bundleName, int32_t instIndex);
    static std::string GetHapUniqueStr(const std::shared_ptr<HapTokenInfoInner>& info);
    static void GenerateAddInfoToVec(
        AtmDataType type, const std::vector<GenericValues>& addValues, std::vector<AddInfo>& addInfoVec);
    static void GenerateDelInfoToVec(AtmDataType type, const GenericValues& delValue, std::vector<DelInfo>& delInfoVec);
    static void AddTokenIdToUndefValues(AccessTokenID tokenId, std::vector<GenericValues>& undefValues);
    static void BuildHapTokenInfo(const Identity& id, const BundleParam& param, HapTokenInfo& info);
    static void BuildBundleFullInfo(const BundleParam& param, const HapPolicy& policy,
        std::shared_ptr<BundleInfoInner>& innerInfo, BundleNoCachedInfo& noCached);
    static ReservedType GetReservedTokenTypeDBValue(const GenericValues& values);
    static void AccessTokenServiceAppVerifyParamSet();
    static bool IsSystemAppVerified();
    static bool IsSystemSpmEnforcing();

private:
    AccessTokenInfoUtils() = delete;
    ~AccessTokenInfoUtils() = delete;
};
} // namespace AccessToken
} // namespace Security
} // namespace OHOS
#endif // ACCESS_TOKEN_INFO_HELPER_H
