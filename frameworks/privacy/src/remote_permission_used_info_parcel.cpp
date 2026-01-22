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

#include "remote_permission_used_info_parcel.h"
#include "parcel_utils.h"
#include "refbase.h"

namespace OHOS {
namespace Security {
namespace AccessToken {
bool RemotePermissionUsedInfoParcel::Marshalling(Parcel& out) const
{
    RETURN_IF_FALSE(out.WriteString(this->info.remoteDeviceId));
    RETURN_IF_FALSE(out.WriteString(this->info.remoteDeviceName));
    RETURN_IF_FALSE(out.WriteString(this->info.permissionName));
    return true;
}

RemotePermissionUsedInfoParcel* RemotePermissionUsedInfoParcel::Unmarshalling(Parcel& in)
{
    auto* parcel = new (std::nothrow) RemotePermissionUsedInfoParcel();
    if (parcel == nullptr) {
        return nullptr;
    }

    RELEASE_IF_FALSE(in.ReadString(parcel->info.remoteDeviceId), parcel);
    RELEASE_IF_FALSE(in.ReadString(parcel->info.remoteDeviceName), parcel);
    RELEASE_IF_FALSE(in.ReadString(parcel->info.permissionName), parcel);

    return parcel;
}
} // namespace AccessToken
} // namespace Security
} // namespace OHOS