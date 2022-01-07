/*
 * Copyright (c) 2021 Huawei Device Co., Ltd.
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

bool PermissionStateFullParcel::Marshalling(Parcel& out) const
{
    RETURN_IF_FALSE(out.WriteString(this->permStatFull.permissionName));
    RETURN_IF_FALSE(out.WriteBool(this->permStatFull.isGeneral));

    RETURN_IF_FALSE(out.WriteInt32(this->permStatFull.resDeviceID.size()));
    for (auto devId : this->permStatFull.resDeviceID) {
        RETURN_IF_FALSE(out.WriteString(devId));
    }

    RETURN_IF_FALSE(out.WriteInt32(this->permStatFull.grantStatus.size()));
    for (auto grantStat : this->permStatFull.grantStatus) {
        RETURN_IF_FALSE(out.WriteInt32(grantStat));
    }

    RETURN_IF_FALSE(out.WriteInt32(this->permStatFull.grantFlags.size()));
    for (auto grantFlag : this->permStatFull.grantFlags) {
        RETURN_IF_FALSE(out.WriteInt32(grantFlag));
    }
    return true;
}

PermissionStateFullParcel* PermissionStateFullParcel::Unmarshalling(Parcel& in)
{
    auto* permissionStateParcel = new (std::nothrow) PermissionStateFullParcel();
    RELEASE_IF_FALSE(permissionStateParcel != nullptr, permissionStateParcel);

    RELEASE_IF_FALSE(in.ReadString(permissionStateParcel->permStatFull.permissionName), permissionStateParcel);
    RELEASE_IF_FALSE(in.ReadBool(permissionStateParcel->permStatFull.isGeneral), permissionStateParcel);

    int resIdSize = 0;
    RELEASE_IF_FALSE(in.ReadInt32(resIdSize), permissionStateParcel);
    for (int i = 0; i < resIdSize; i++) {
        std::string resId;
        RELEASE_IF_FALSE(in.ReadString(resId), permissionStateParcel);
        permissionStateParcel->permStatFull.resDeviceID.emplace_back(resId);
    }

    int grantStatsSize = 0;
    RELEASE_IF_FALSE(in.ReadInt32(grantStatsSize), permissionStateParcel);
    for (int i = 0; i < grantStatsSize; i++) {
        int grantStat;
        RELEASE_IF_FALSE(in.ReadInt32(grantStat), permissionStateParcel);
        permissionStateParcel->permStatFull.grantStatus.emplace_back(grantStat);
    }

    int grantFlagSize = 0;
    RELEASE_IF_FALSE(in.ReadInt32(grantFlagSize), permissionStateParcel);
    for (int i = 0; i < grantFlagSize; i++) {
        int flag;
        RELEASE_IF_FALSE(in.ReadInt32(flag), permissionStateParcel);
        permissionStateParcel->permStatFull.grantFlags.emplace_back(flag);
    }
    return permissionStateParcel;
}
} // namespace AccessToken
} // namespace Security
} // namespace OHOS