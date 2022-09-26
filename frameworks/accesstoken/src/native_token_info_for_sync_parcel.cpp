/*
 * Copyright (c) 2022 Huawei Device Co., Ltd.
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

#include "native_token_info_for_sync_parcel.h"
#include "refbase.h"
#include "native_token_info_parcel.h"
#include "parcel_utils.h"
#include "permission_state_full.h"
#include "permission_state_full_parcel.h"

namespace OHOS {
namespace Security {
namespace AccessToken {
bool NativeTokenInfoForSyncParcel::Marshalling(Parcel& out) const
{
    NativeTokenInfoParcel baseInfoParcel;
    baseInfoParcel.nativeTokenInfoParams = this->nativeTokenInfoForSyncParams.baseInfo;
    RETURN_IF_FALSE(out.WriteParcelable(&baseInfoParcel));

    const std::vector<PermissionStateFull>& permStateList = this->nativeTokenInfoForSyncParams.permStateList;
    uint32_t permStateListSize = permStateList.size();
    RETURN_IF_FALSE(permStateListSize <= MAX_PERMLIST_SIZE);
    RETURN_IF_FALSE(out.WriteUint32(permStateListSize));
    for (uint32_t i = 0; i < permStateListSize; i++) {
        PermissionStateFullParcel permStateParcel;
        permStateParcel.permStatFull = permStateList[i];
        RETURN_IF_FALSE(out.WriteParcelable(&permStateParcel));
    }

    return true;
}

NativeTokenInfoForSyncParcel* NativeTokenInfoForSyncParcel::Unmarshalling(Parcel& in)
{
    auto* nativeTokenInfoForSyncParcel = new (std::nothrow) NativeTokenInfoForSyncParcel();
    if (nativeTokenInfoForSyncParcel == nullptr) {
        return nullptr;
    }

    sptr<NativeTokenInfoParcel> baseInfoParcel = in.ReadParcelable<NativeTokenInfoParcel>();
    RELEASE_IF_FALSE(baseInfoParcel != nullptr, nativeTokenInfoForSyncParcel);
    nativeTokenInfoForSyncParcel->nativeTokenInfoForSyncParams.baseInfo = baseInfoParcel->nativeTokenInfoParams;

    uint32_t permStateListSize;
    RELEASE_IF_FALSE(in.ReadUint32(permStateListSize), nativeTokenInfoForSyncParcel);
    RELEASE_IF_FALSE(permStateListSize <= MAX_PERMLIST_SIZE, nativeTokenInfoForSyncParcel);
    for (uint32_t i = 0; i < permStateListSize; i++) {
        sptr<PermissionStateFullParcel> permissionStateParcel = in.ReadParcelable<PermissionStateFullParcel>();
        RELEASE_IF_FALSE(permissionStateParcel != nullptr, nativeTokenInfoForSyncParcel);
        nativeTokenInfoForSyncParcel->nativeTokenInfoForSyncParams.permStateList.emplace_back(
            permissionStateParcel->permStatFull);
    }
    return nativeTokenInfoForSyncParcel;
}
} // namespace AccessToken
} // namespace Security
} // namespace OHOS
