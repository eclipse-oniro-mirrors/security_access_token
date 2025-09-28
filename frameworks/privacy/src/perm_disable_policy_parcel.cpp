/*
 * Copyright (c) 2025 Huawei Device Co., Ltd.
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
#include "perm_disable_policy_parcel.h"

namespace OHOS {
namespace Security {
namespace AccessToken {
bool PermDisablePolicyParcel::Marshalling(Parcel& out) const
{
    RETURN_IF_FALSE(out.WriteString(this->info.permissionName));
    RETURN_IF_FALSE(out.WriteBool(this->info.isDisable));
    return true;
}

PermDisablePolicyParcel* PermDisablePolicyParcel::Unmarshalling(Parcel& in)
{
    auto* permDisablePolicyParcel = new (std::nothrow) PermDisablePolicyParcel();
    if (permDisablePolicyParcel == nullptr) {
        return nullptr;
    }

    RELEASE_IF_FALSE(in.ReadString(permDisablePolicyParcel->info.permissionName), permDisablePolicyParcel);
    RELEASE_IF_FALSE(in.ReadBool(permDisablePolicyParcel->info.isDisable), permDisablePolicyParcel);
    
    return permDisablePolicyParcel;
}
} // namespace AccessToken
} // namespace Security
} // namespace OHOS
