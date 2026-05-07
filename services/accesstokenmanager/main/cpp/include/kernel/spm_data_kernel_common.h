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
#include "token_setproc.h"

namespace OHOS {
namespace Security {
namespace AccessToken {
namespace KernelDetail {
constexpr uint32_t SPM_NAME_BUF_SIZE = 256;

class SpmDataDeleter final {
public:
    void operator()(SpmData* data) const;
};

using SpmDataPtr = std::unique_ptr<SpmData, SpmDataDeleter>;

void BuildPermissionBitmap(const std::vector<BriefPermData>& permBriefDataList, std::vector<uint32_t>& bitmap);
int32_t BuildExtendedPermissionBuffer(const std::vector<PermissionWithValue>& extendedPermList,
    std::vector<uint8_t>& buffer);
int32_t ParseExtendedPermissionBuffer(const SpmBlob& extendPermBlob, std::vector<PermissionWithValue>& permList);
int32_t CopyBufferIfNeeded(void* dest, size_t destSize, const void* src, size_t count, const char* name);
int32_t BuildSpmData(const HapTokenInfo& hapInfo, const BundleNoCachedInfo& noCachedInfo,
    const std::vector<BriefPermData>& permBriefDataList, const std::vector<PermissionWithValue>& extendPermList,
    SpmDataPtr& spmData);
int32_t AddSpmEntriesToKernel(const std::vector<SpmData*>& entries, const std::vector<AccessTokenID>& tokenIds,
    uint8_t& idxErr);
int32_t SetSpmEntriesToKernel(const std::vector<SpmData*>& entries, const std::vector<AccessTokenID>& tokenIds,
    uint8_t& idxErr);
int32_t SetSpmEntryToKernel(const SpmDataPtr& spmData, AccessTokenID tokenId);
int32_t LoadSpmDataFromKernel(AccessTokenID tokenId, SpmDataPtr& spmData);
int32_t RemoveSpmEntryFromKernel(AccessTokenID tokenId);
} // namespace KernelDetail
} // namespace AccessToken
} // namespace Security
} // namespace OHOS

#endif // SPM_DATA_KERNEL_COMMON_H
