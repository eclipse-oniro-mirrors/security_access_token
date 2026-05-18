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

#include "spm_data_kernel_common.h"

#include <cerrno>
#include <cstdint>
#include <cstring>

#include "access_token_error.h"
#include "accesstoken_common_log.h"
#include "permission_map.h"
#include "securec.h"

namespace OHOS {
namespace Security {
namespace AccessToken {

namespace KernelDetail {
namespace {
static constexpr uint32_t MAX_PERMISSION_BITMAP_WORDS = 64; // support 2048 permissions at most
static constexpr uint32_t DEFAULT_EXTENDED_PERMS = 4096;
}

void BuildPermissionBitmap(const std::vector<BriefPermData>& permBriefDataList, std::vector<uint32_t>& bitmap,
    bool isGranted)
{
    bitmap.assign(MAX_PERMISSION_BITMAP_WORDS, 0);
    for (const auto& permData : permBriefDataList) {
        if (isGranted && permData.status != PermissionState::PERMISSION_GRANTED) {
            continue;
        }
        uint32_t idx = permData.permCode / UINT32_T_BITS;
        uint32_t bitIdx = permData.permCode % UINT32_T_BITS;
        if (idx >= bitmap.size()) {
            continue;
        }
        bitmap[idx] |= static_cast<uint32_t>(0x01) << bitIdx;
    }
}

bool IsKernelNotSupported(int32_t ret)
{
#if ENOTSUP == EOPNOTSUPP
    return ret == EOPNOTSUPP;
#else
    return ret == EOPNOTSUPP || ret == ENOTSUP;
#endif
}

int32_t BuildExtendedPermissionBuffer(const std::vector<PermissionWithValue>& extendedPermList,
    std::vector<uint8_t>& buffer)
{
    buffer.clear();
    for (const auto& extendedPerm : extendedPermList) {
        uint32_t opCode = 0;
        if (!TransferPermissionToOpcode(extendedPerm.permissionName, opCode)) {
            LOGE(ATM_DOMAIN, ATM_TAG, "Build extended permission buffer failed, invalid permission=%{public}s.",
                extendedPerm.permissionName.c_str());
            return RET_FAILED;
        }
        uint32_t valueSize = static_cast<uint32_t>(extendedPerm.value.size() + 1);
        const auto* opCodePtr = reinterpret_cast<const uint8_t*>(&opCode);
        buffer.insert(buffer.end(), opCodePtr, opCodePtr + sizeof(uint32_t));
        const auto* sizePtr = reinterpret_cast<const uint8_t*>(&valueSize);
        buffer.insert(buffer.end(), sizePtr, sizePtr + sizeof(uint32_t));
        const auto* valuePtr = reinterpret_cast<const uint8_t*>(extendedPerm.value.data());
        buffer.insert(buffer.end(), valuePtr, valuePtr + extendedPerm.value.size());
        buffer.push_back('\0');
    }
    return RET_SUCCESS;
}

int32_t ParseExtendedPermissionBuffer(const SpmBlob& extendPermBlob, std::vector<PermissionWithValue>& permList)
{
    permList.clear();
    if ((extendPermBlob.buf == nullptr) || (extendPermBlob.bufSize == 0)) {
        return RET_SUCCESS;
    }

    size_t offset = 0;
    while ((offset + sizeof(uint32_t) + sizeof(uint32_t)) <= extendPermBlob.bufSize) {
        uint32_t permCode = *(reinterpret_cast<uint32_t*>(extendPermBlob.buf + offset));
        offset += sizeof(uint32_t);
        uint32_t valueSize = *(reinterpret_cast<uint32_t*>(extendPermBlob.buf + offset));
        offset += sizeof(uint32_t);

        if (valueSize == 0) {
            break;
        }
        if (valueSize > extendPermBlob.bufSize || offset > extendPermBlob.bufSize - valueSize) {
            LOGE(ATM_DOMAIN, ATM_TAG, "Parse extend perms failed, invalid size=%{public}u, remain=%{public}zu.",
                valueSize, extendPermBlob.bufSize - offset);
            return RET_FAILED;
        }

        PermissionWithValue perm;
        perm.permissionName = TransferOpcodeToPermission(permCode);
        if (perm.permissionName.empty()) {
            LOGE(ATM_DOMAIN, ATM_TAG, "Parse extend perms failed, invalid permCode=%{public}u.", permCode);
            return RET_FAILED;
        }
        perm.value.assign(extendPermBlob.buf + offset, extendPermBlob.buf + offset + valueSize - 1);
        permList.emplace_back(perm);
        offset += valueSize;
    }
    return RET_SUCCESS;
}

int32_t BuildSpmData(const HapTokenInfo& hapInfo, const BundleNoCachedInfo& noCachedInfo,
    const std::vector<BriefPermData>& permBriefDataList, const std::vector<PermissionWithValue>& extendPermList,
    SpmDataPtr& spmData)
{
    std::vector<uint32_t> permsBitmap;
    BuildPermissionBitmap(permBriefDataList, permsBitmap, false);
    std::vector<uint8_t> extendPermsBuffer;
    int32_t ret = BuildExtendedPermissionBuffer(extendPermList, extendPermsBuffer);
    if (ret != RET_SUCCESS) {
        return ret;
    }

    std::string nameBuffer = hapInfo.bundleName;
    uint32_t permsBufferSize = static_cast<uint32_t>(permsBitmap.size() * sizeof(uint32_t));
    spmData.reset(SpmDataNew(permsBufferSize, static_cast<uint32_t>(extendPermsBuffer.size()),
        static_cast<uint32_t>(nameBuffer.size() + 1)));
    if (spmData == nullptr) {
        LOGE(ATM_DOMAIN, ATM_TAG, "SpmDataNew failed when building token=%{public}u.", hapInfo.tokenID);
        return RET_FAILED;
    }

    spmData->uid = hapInfo.uid;
    spmData->tokenid = static_cast<uint32_t>(hapInfo.tokenID);
    spmData->tokenidAttr = static_cast<uint32_t>(hapInfo.tokenAttr);
    spmData->index = static_cast<uint32_t>(hapInfo.instIndex);
    spmData->apl = static_cast<uint16_t>(noCachedInfo.apl);
    spmData->distributionType = static_cast<uint16_t>(noCachedInfo.distributionType);
    spmData->idType = noCachedInfo.idType;
    spmData->ownerid = noCachedInfo.ownerid;

    ret = memcpy_s(spmData->name.buf, spmData->name.bufSize, nameBuffer.c_str(), nameBuffer.size());
    if (ret != RET_SUCCESS) {
        LOGE(ATM_DOMAIN, ATM_TAG, "Build SPM name failed, ret = %{public}d.", ret);
        return ret;
    }
    spmData->name.buf[nameBuffer.size()] = '\0';

    ret = memcpy_s(spmData->perms.buf, spmData->perms.bufSize, permsBitmap.data(), permsBufferSize);
    if (ret != RET_SUCCESS) {
        LOGE(ATM_DOMAIN, ATM_TAG, "Build SPM perms, ret = %{public}d.", ret);
        return ret;
    }

    if (extendPermsBuffer.empty()) {
        return RET_SUCCESS;
    }
    ret = memcpy_s(spmData->extendPerms.buf, spmData->extendPerms.bufSize, extendPermsBuffer.data(),
        extendPermsBuffer.size());
    if (ret != RET_SUCCESS) {
        LOGE(ATM_DOMAIN, ATM_TAG, "Build SPM extened perms, ret = %{public}d.", ret);
        return ret;
    }
    return RET_SUCCESS;
}

int32_t AddSpmEntriesToKernel(const std::vector<SpmData*>& entries, const std::vector<AccessTokenID>& tokenIds,
    uint8_t& idxErr)
{
    idxErr = 0;
    if (entries.empty() || entries.size() != tokenIds.size()) {
        return RET_FAILED;
    }

    int32_t ret = SpmAddEntries(const_cast<SpmData**>(entries.data()), static_cast<uint8_t>(entries.size()), &idxErr);
    if (ret == RET_SUCCESS) {
        return RET_SUCCESS;
    }
    if (KernelDetail::IsKernelNotSupported(ret)) {
        LOGW(ATM_DOMAIN, ATM_TAG, "SpmAddEntries is not supported in current system.");
        return AccessTokenError::ERR_IOCTL_UNSUPPORT;
    }
    if (ret == EEXIST) {
        LOGE(ATM_DOMAIN, ATM_TAG, "SpmAddEntries conflict for token=%{public}u.", tokenIds[idxErr]);
        return AccessTokenError::ERR_DATA_CONFLICT_WITH_KERNEL;
    }
    LOGE(ATM_DOMAIN, ATM_TAG, "SpmAddEntries failed for token=%{public}u, ret=%{public}d, idxErr=%{public}u.",
        tokenIds[idxErr], ret, idxErr);
    return RET_FAILED;
}

int32_t SetSpmEntriesToKernel(const std::vector<SpmData*>& entries, const std::vector<AccessTokenID>& tokenIds,
    uint8_t& idxErr)
{
    idxErr = 0;
    if (entries.empty() || entries.size() != tokenIds.size()) {
        return RET_FAILED;
    }

    int32_t ret = SpmSetEntries(const_cast<SpmData**>(entries.data()), static_cast<uint8_t>(entries.size()), &idxErr);
    if (ret == RET_SUCCESS) {
        return RET_SUCCESS;
    }
    if (KernelDetail::IsKernelNotSupported(ret)) {
        LOGW(ATM_DOMAIN, ATM_TAG, "SpmSetEntries is not supported in current system.");
        return AccessTokenError::ERR_IOCTL_UNSUPPORT;
    }
    if (ret == EEXIST) {
        LOGE(ATM_DOMAIN, ATM_TAG, "SpmSetEntries conflict for token=%{public}u.", tokenIds[idxErr]);
        return AccessTokenError::ERR_DATA_CONFLICT_WITH_KERNEL;
    }
    LOGE(ATM_DOMAIN, ATM_TAG, "SpmSetEntries failed for token=%{public}u, ret=%{public}d, idxErr=%{public}u.",
        tokenIds[idxErr], ret, idxErr);
    return RET_FAILED;
}

int32_t LoadSpmDataFromKernel(AccessTokenID tokenId, SpmDataPtr& spmData)
{
    spmData.reset(SpmDataNew(MAX_PERMISSION_BITMAP_WORDS * sizeof(uint32_t),
        DEFAULT_EXTENDED_PERMS, SPM_NAME_BUF_SIZE));
    if (spmData == nullptr) {
        LOGE(ATM_DOMAIN, ATM_TAG, "SpmDataNew failed when querying token=%{public}u.", tokenId);
        return RET_FAILED;
    }

    int32_t ret = SpmGetEntry(static_cast<uint32_t>(tokenId), spmData.get());
    if (ret == RET_SUCCESS) {
        return RET_SUCCESS;
    }
    if (KernelDetail::IsKernelNotSupported(ret)) {
        LOGW(ATM_DOMAIN, ATM_TAG, "SpmGetEntry is not supported in current system.");
        return AccessTokenError::ERR_IOCTL_UNSUPPORT;
    }
    if (ret == ENODATA) {
        LOGE(ATM_DOMAIN, ATM_TAG, "SpmGetEntry none for token=%{public}u.", tokenId);
        return AccessTokenError::ERR_NO_DATA_FROM_KERNEL;
    }

    LOGE(ATM_DOMAIN, ATM_TAG, "SpmGetEntry(token=%{public}u) load buffers failed, ret=%{public}d.", tokenId, ret);
    return RET_FAILED;
}

void RemoveSpmEntryFromKernel(AccessTokenID tokenId)
{
    int32_t ret = SpmRemoveEntry(static_cast<uint32_t>(tokenId));
    if (ret == RET_SUCCESS || ret == EOPNOTSUPP || ret == ENODATA) {
        return;
    }
    ret = SpmRemoveEntry(static_cast<uint32_t>(tokenId));
    if (ret != RET_SUCCESS) {
        LOGE(ATM_DOMAIN, ATM_TAG, "SpmRemoveEntry(token=%{public}u) failed, ret=%{public}d.", tokenId, ret);
    }
}
} // namespace KernelDetail
} // namespace AccessToken
} // namespace Security
} // namespace OHOS
