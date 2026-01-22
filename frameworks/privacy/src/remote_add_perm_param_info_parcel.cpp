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

#include "remote_add_perm_param_info_parcel.h"
#include "parcel_utils.h"
#include "refbase.h"

namespace OHOS {
namespace Security {
namespace AccessToken {
bool RemoteAddPermParamInfoParcel::Marshalling(Parcel& out) const
{
    RETURN_IF_FALSE(out.WriteString(this->info.deviceId));
    RETURN_IF_FALSE(out.WriteString(this->info.deviceName));
    RETURN_IF_FALSE(out.WriteString(this->info.permissionName));
    RETURN_IF_FALSE(out.WriteInt32(this->info.successCount));
    RETURN_IF_FALSE(out.WriteInt32(this->info.failCount));
    return true;
}

RemoteAddPermParamInfoParcel* RemoteAddPermParamInfoParcel::Unmarshalling(Parcel& in)
{
    auto* infoParcel = new (std::nothrow) RemoteAddPermParamInfoParcel();
    if (infoParcel == nullptr) {
        return nullptr;
    }

    RELEASE_IF_FALSE(in.ReadString(infoParcel->info.deviceId), infoParcel);
    RELEASE_IF_FALSE(in.ReadString(infoParcel->info.deviceName), infoParcel);
    RELEASE_IF_FALSE(in.ReadString(infoParcel->info.permissionName), infoParcel);
    RELEASE_IF_FALSE(in.ReadInt32(infoParcel->info.successCount), infoParcel);
    RELEASE_IF_FALSE(in.ReadInt32(infoParcel->info.failCount), infoParcel);

    return infoParcel;
}
} // namespace AccessToken
} // namespace Security
} // namespace OHOS
