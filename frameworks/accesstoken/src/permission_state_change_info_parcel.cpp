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

#include "permission_state_change_info_parcel.h"
#include "parcel_utils.h"

namespace OHOS {
namespace Security {
namespace AccessToken {
bool PermissionStateChangeInfoParcel::Marshalling(Parcel& out) const
{
    RETURN_IF_FALSE(out.WriteInt32(this->changeInfo.PermStateChangeType));
    RETURN_IF_FALSE(out.WriteUint32(this->changeInfo.tokenID));
    RETURN_IF_FALSE(out.WriteString(this->changeInfo.permissionName));
    return true;
}

PermissionStateChangeInfoParcel* PermissionStateChangeInfoParcel::Unmarshalling(Parcel& in)
{
    auto* permissionStateParcel = new (std::nothrow) PermissionStateChangeInfoParcel();
    if (permissionStateParcel == nullptr) {
        return nullptr;
    }
    RELEASE_IF_FALSE(in.ReadInt32(permissionStateParcel->changeInfo.PermStateChangeType), permissionStateParcel);
    RELEASE_IF_FALSE(in.ReadUint32(permissionStateParcel->changeInfo.tokenID), permissionStateParcel);
    RELEASE_IF_FALSE(in.ReadString(permissionStateParcel->changeInfo.permissionName), permissionStateParcel);

    return permissionStateParcel;
}
} // namespace AccessToken
} // namespace Security
} // namespace OHOS
