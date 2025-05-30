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

#include "permission_list_state_parcel.h"
#include "parcel_utils.h"
#include <cstdint>

namespace OHOS {
namespace Security {
namespace AccessToken {
bool PermissionListStateParcel::Marshalling(Parcel& out) const
{
    RETURN_IF_FALSE(out.WriteString(this->permsState.permissionName));
    RETURN_IF_FALSE(out.WriteInt32(static_cast<int32_t>(this->permsState.state)));
    RETURN_IF_FALSE(out.WriteInt32(static_cast<int32_t>(this->permsState.errorReason)));
    return true;
}

PermissionListStateParcel* PermissionListStateParcel::Unmarshalling(Parcel& in)
{
    auto* permissionStateParcel = new (std::nothrow) PermissionListStateParcel();
    if (permissionStateParcel == nullptr) {
        return nullptr;
    }

    RELEASE_IF_FALSE(in.ReadString(permissionStateParcel->permsState.permissionName), permissionStateParcel);
    int32_t state;
    RELEASE_IF_FALSE(in.ReadInt32(state), permissionStateParcel);
    if (state >= static_cast<int32_t>(BUTT_OPER) || state < static_cast<int32_t>(SETTING_OPER)) {
        delete permissionStateParcel;
        return nullptr;
    }
    permissionStateParcel->permsState.state = static_cast<PermissionOper>(state);
    int32_t errorReason;
    RELEASE_IF_FALSE(in.ReadInt32(errorReason), permissionStateParcel);
    permissionStateParcel->permsState.errorReason = static_cast<PermissionErrorReason>(errorReason);

    return permissionStateParcel;
}
} // namespace AccessToken
} // namespace Security
} // namespace OHOS
