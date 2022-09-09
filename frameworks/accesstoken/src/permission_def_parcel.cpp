/*
 * Copyright (c) 2021-2022 Huawei Device Co., Ltd.
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

#include "permission_def_parcel.h"

#include "access_token.h"
#include "parcel_utils.h"

namespace OHOS {
namespace Security {
namespace AccessToken {
bool PermissionDefParcel::Marshalling(Parcel& out) const
{
    RETURN_IF_FALSE(out.WriteString(this->permissionDef.permissionName));
    RETURN_IF_FALSE(out.WriteString(this->permissionDef.bundleName));
    RETURN_IF_FALSE(out.WriteInt32(this->permissionDef.grantMode));
    RETURN_IF_FALSE(out.WriteInt32(this->permissionDef.availableLevel));
    RETURN_IF_FALSE(out.WriteBool(this->permissionDef.provisionEnable));
    RETURN_IF_FALSE(out.WriteBool(this->permissionDef.distributedSceneEnable));
    RETURN_IF_FALSE(out.WriteString(this->permissionDef.label));
    RETURN_IF_FALSE(out.WriteInt32(this->permissionDef.labelId));
    RETURN_IF_FALSE(out.WriteString(this->permissionDef.description));
    RETURN_IF_FALSE(out.WriteInt32(this->permissionDef.descriptionId));
    return true;
}

PermissionDefParcel* PermissionDefParcel::Unmarshalling(Parcel& in)
{
    auto* permissionDefParcel = new (std::nothrow) PermissionDefParcel();
    if (permissionDefParcel == nullptr) {
        return nullptr;
    }

    permissionDefParcel->permissionDef.permissionName = in.ReadString();
    permissionDefParcel->permissionDef.bundleName = in.ReadString();
    RELEASE_IF_FALSE(in.ReadInt32(permissionDefParcel->permissionDef.grantMode), permissionDefParcel);

    int level;
    RELEASE_IF_FALSE(in.ReadInt32(level), permissionDefParcel);
    permissionDefParcel->permissionDef.availableLevel = ATokenAplEnum(level);

    RELEASE_IF_FALSE(in.ReadBool(permissionDefParcel->permissionDef.provisionEnable), permissionDefParcel);
    RELEASE_IF_FALSE(in.ReadBool(permissionDefParcel->permissionDef.distributedSceneEnable), permissionDefParcel);
    permissionDefParcel->permissionDef.label = in.ReadString();
    RELEASE_IF_FALSE(in.ReadInt32(permissionDefParcel->permissionDef.labelId), permissionDefParcel);
    permissionDefParcel->permissionDef.description = in.ReadString();
    RELEASE_IF_FALSE(in.ReadInt32(permissionDefParcel->permissionDef.descriptionId), permissionDefParcel);
    return permissionDefParcel;
}
} // namespace AccessToken
} // namespace Security
} // namespace OHOS
