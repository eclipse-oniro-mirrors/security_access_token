/*
 * Copyright (c) 2023 Huawei Device Co., Ltd.
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

#include "permission_grant_info_parcel.h"
#include "parcel_utils.h"

namespace OHOS {
namespace Security {
namespace AccessToken {
bool PermissionGrantInfoParcel::Marshalling(Parcel& out) const
{
    RETURN_IF_FALSE(out.WriteString(this->info.grantBundleName));
    RETURN_IF_FALSE(out.WriteString(this->info.grantAbilityName));
    return true;
}

PermissionGrantInfoParcel* PermissionGrantInfoParcel::Unmarshalling(Parcel& in)
{
    auto* permissionGrantInfoParcel = new (std::nothrow) PermissionGrantInfoParcel();
    if (permissionGrantInfoParcel == nullptr) {
        return nullptr;
    }
    permissionGrantInfoParcel->info.grantBundleName = in.ReadString();
    permissionGrantInfoParcel->info.grantAbilityName = in.ReadString();
    return permissionGrantInfoParcel;
}
} // namespace AccessToken
} // namespace Security
} // namespace OHOS
