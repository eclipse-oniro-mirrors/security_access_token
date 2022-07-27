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

#include "parcel_utils.h"
#include "perm_active_response_parcel.h"

namespace OHOS {
namespace Security {
namespace AccessToken {
bool ActiveChangeResponseParcel::Marshalling(Parcel& out) const
{
    RETURN_IF_FALSE(out.WriteUint32(this->changeResponse.tokenID));
    RETURN_IF_FALSE(out.WriteString(this->changeResponse.permissionName));
    RETURN_IF_FALSE(out.WriteString(this->changeResponse.deviceId));
    RETURN_IF_FALSE(out.WriteInt32(this->changeResponse.type));
    return true;
}

ActiveChangeResponseParcel* ActiveChangeResponseParcel::Unmarshalling(Parcel& in)
{
    auto* activeChangeResponseParcel = new (std::nothrow) ActiveChangeResponseParcel();
    if (activeChangeResponseParcel == nullptr) {
        return nullptr;
    }

    RELEASE_IF_FALSE(in.ReadUint32(activeChangeResponseParcel->changeResponse.tokenID), activeChangeResponseParcel);
    RELEASE_IF_FALSE(in.ReadString(activeChangeResponseParcel->changeResponse.permissionName),
        activeChangeResponseParcel);
    RELEASE_IF_FALSE(in.ReadString(activeChangeResponseParcel->changeResponse.deviceId), activeChangeResponseParcel);

    int32_t type;
    RELEASE_IF_FALSE(in.ReadInt32(type), activeChangeResponseParcel);
    activeChangeResponseParcel->changeResponse.type = static_cast<ActiveChangeType>(type);
    return activeChangeResponseParcel;
}
} // namespace AccessToken
} // namespace Security
} // namespace OHOS
