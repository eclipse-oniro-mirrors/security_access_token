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

#ifndef PERMISSION_KERNEL_UTILS_H
#define PERMISSION_KERNEL_UTILS_H

#include <string>
#include <vector>

#include "access_token.h"
#include "hap_data_structure.h"
#include "hap_token_info.h"
#include "permission_data_brief.h"

namespace OHOS {
namespace Security {
namespace AccessToken {

struct SpmDataParam final {
    std::reference_wrapper<const HapTokenInfo> hapInfo;
    std::reference_wrapper<const BundleNoCachedInfo> noCachedInfo;
    std::reference_wrapper<const std::vector<BriefPermData>> permBriefDataList;
    std::reference_wrapper<const std::vector<PermissionWithValue>> extendPermList;
    const std::vector<BriefPermData>* oldPermBriefDataList = nullptr;
    bool updateWithPerm = false;
};

class PermissionKernelUtils final {
public:
    static void AddNativePermToKernel(
        AccessTokenID tokenID, const std::vector<uint32_t>& opCodeList, const std::vector<bool>& statusList);
    static int32_t AddHapPermToKernel(AccessTokenID tokenID, const std::vector<uint32_t>& opCodeList);
    static int32_t AddHapPermToKernel(AccessTokenID tokenID, const std::vector<BriefPermData>& permBriefDataList);
    static int32_t GetBundleInfoFromKernel(AccessTokenID tokenId, BundleNoCachedInfo& noCachedInfo,
        std::vector<PermissionWithValue>& permList);
    static void RemovePermFromKernel(AccessTokenID tokenID);
    static void SetPermToKernel(AccessTokenID tokenID, const std::string& permissionName, bool isGranted);
    static bool IsKernelSupportSpm();
    static void RemoveSpmEntryFromKernel(AccessTokenID tokenId);

private:
    PermissionKernelUtils() = delete;
};
} // namespace AccessToken
} // namespace Security
} // namespace OHOS
#endif // PERMISSION_KERNEL_HELPER_H
