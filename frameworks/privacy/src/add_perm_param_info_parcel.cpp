/*
 * Copyright (c) 2024 Huawei Device Co., Ltd.
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

#include "add_perm_param_info_parcel.h"
#include "parcel_utils.h"
#include "refbase.h"

namespace OHOS {
namespace Security {
namespace AccessToken {
bool AddPermParamInfoParcel::Marshalling(Parcel& out) const
{
    RETURN_IF_FALSE(out.WriteUint32(this->info.tokenId));
    RETURN_IF_FALSE(out.WriteString(this->info.permissionName));
    RETURN_IF_FALSE(out.WriteInt32(this->info.successCount));
    RETURN_IF_FALSE(out.WriteInt32(this->info.failCount));
    RETURN_IF_FALSE(out.WriteUint32(static_cast<uint32_t>(this->info.type)));
    return true;
}

AddPermParamInfoParcel* AddPermParamInfoParcel::Unmarshalling(Parcel& in)
{
    auto* infoParcel = new (std::nothrow) AddPermParamInfoParcel();
    if (infoParcel == nullptr) {
        return nullptr;
    }

    RELEASE_IF_FALSE(in.ReadUint32(infoParcel->info.tokenId), infoParcel);
    RELEASE_IF_FALSE(in.ReadString(infoParcel->info.permissionName), infoParcel);
    RELEASE_IF_FALSE(in.ReadInt32(infoParcel->info.successCount), infoParcel);
    RELEASE_IF_FALSE(in.ReadInt32(infoParcel->info.failCount), infoParcel);
    uint32_t type = 0;
    RELEASE_IF_FALSE(in.ReadUint32(type), infoParcel);
    infoParcel->info.type = static_cast<PermissionUsedType>(type);

    return infoParcel;
}
} // namespace AccessToken
} // namespace Security
} // namespace OHOS
