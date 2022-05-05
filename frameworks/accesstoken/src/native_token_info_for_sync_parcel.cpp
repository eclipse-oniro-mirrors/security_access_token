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
#include "native_token_info_parcel.h"
#include "permission_state_full_parcel.h"

namespace OHOS {
namespace Security {
namespace AccessToken {
#define RETURN_IF_FALSE(expr) \
    if (!(expr)) { \
        return false; \
    }

#define RELEASE_IF_FALSE(expr, obj) \
    if (!(expr)) { \
        delete (obj); \
        (obj) = nullptr; \
        return (obj); \
    }

bool NativeTokenInfoForSyncParcel::Marshalling(Parcel& out) const
{
    NativeTokenInfoParcel baseInfoParcel;
    baseInfoParcel.nativeTokenInfoParams = this->nativeTokenInfoForSyncParams.baseInfo;
    RETURN_IF_FALSE(out.WriteParcelable(&baseInfoParcel));

    const std::vector<PermissionStateFull>& permStateList = this->nativeTokenInfoForSyncParams.permStateList;
    int32_t permStateListSize = static_cast<int32_t>(permStateList.size());
    RETURN_IF_FALSE(out.WriteInt32(permStateListSize));

    for (int i = 0; i < permStateListSize; i++) {
        PermissionStateFullParcel permStateParcel;
        permStateParcel.permStatFull = permStateList[i];
        RETURN_IF_FALSE(out.WriteParcelable(&permStateParcel));
    }

    return true;
}

NativeTokenInfoForSyncParcel* NativeTokenInfoForSyncParcel::Unmarshalling(Parcel& in)
{
    auto* nativeTokenInfoForSyncParcel = new (std::nothrow) NativeTokenInfoForSyncParcel();
    RELEASE_IF_FALSE(nativeTokenInfoForSyncParcel != nullptr, nativeTokenInfoForSyncParcel);

    sptr<NativeTokenInfoParcel> baseInfoParcel = in.ReadParcelable<NativeTokenInfoParcel>();
    RELEASE_IF_FALSE(baseInfoParcel != nullptr, nativeTokenInfoForSyncParcel);
    nativeTokenInfoForSyncParcel->nativeTokenInfoForSyncParams.baseInfo = baseInfoParcel->nativeTokenInfoParams;

    int permStateListSize;
    RELEASE_IF_FALSE(in.ReadInt32(permStateListSize), nativeTokenInfoForSyncParcel);
    for (int i = 0; i < permStateListSize; i++) {
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
