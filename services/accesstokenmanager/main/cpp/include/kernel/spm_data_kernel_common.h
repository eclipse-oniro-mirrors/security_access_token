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

#ifndef SPM_DATA_KERNEL_COMMON_H
#define SPM_DATA_KERNEL_COMMON_H

#include <memory>
#include <vector>

#include "permission_kernel_utils.h"
#include "spm_setproc.h"

namespace OHOS {
namespace Security {
namespace AccessToken {
constexpr uint32_t SPM_NAME_BUF_SIZE = 256;

class SpmDataDeleter final {
public:
    void operator()(SpmData* data) const
    {
        if (data != nullptr) {
            SpmDataFree(data);
        }
    }
};

using SpmDataPtr = std::unique_ptr<SpmData, SpmDataDeleter>;

class SpmDataTaskItem final {
public:
    AccessTokenID tokenId = INVALID_TOKENID;
    std::vector<BriefPermData> permBriefDataList;
    const std::vector<BriefPermData>* oldPermBriefDataList = nullptr;
    SpmDataPtr newSpmData = nullptr;
    SpmDataPtr oldSpmData = nullptr;
};

namespace KernelDetail {
void BuildPermissionBitmap(const std::vector<BriefPermData>& permBriefDataList, std::vector<uint32_t>& bitmap,
    bool needGrant =  false);
void BuildExtendedPermissionBuffer(const std::vector<PermissionWithValue>& extendedPermList,
    std::vector<uint8_t>& buffer);
int32_t ParseExtendedPermissionBuffer(const SpmBlob& extendPermBlob, std::vector<PermissionWithValue>& permList);
int32_t BuildSpmData(const HapTokenInfo& hapInfo, const BundleNoCachedInfo& noCachedInfo,
    const std::vector<BriefPermData>& permBriefDataList, const std::vector<PermissionWithValue>& extendPermList,
    SpmDataPtr& spmData);
int32_t AddSpmEntriesToKernel(const std::vector<SpmData*>& entries, uint8_t& idxErr);
int32_t SetSpmEntriesToKernel(const std::vector<SpmData*>& entries, uint8_t& idxErr);
int32_t LoadSpmDataFromKernel(AccessTokenID tokenId, SpmDataPtr& spmData);
void RemoveSpmEntryFromKernel(AccessTokenID tokenId);
} // namespace KernelDetail
} // namespace AccessToken
} // namespace Security
} // namespace OHOS

#endif // SPM_DATA_KERNEL_COMMON_H
