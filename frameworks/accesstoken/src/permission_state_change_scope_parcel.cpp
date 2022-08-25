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

#include "permission_state_change_scope_parcel.h"
#include "parcel_utils.h"

namespace OHOS {
namespace Security {
namespace AccessToken {
bool PermStateChangeScopeParcel::Marshalling(Parcel& out) const
{
    RETURN_IF_FALSE(out.WriteUint32((this->scope.tokenIDs.size())));
    for (const auto& tokenID : this->scope.tokenIDs) {
        RETURN_IF_FALSE(out.WriteUint32(tokenID));
    }

    RETURN_IF_FALSE(out.WriteUint32((this->scope.permList.size())));
    for (const auto& permissionName : this->scope.permList) {
        RETURN_IF_FALSE(out.WriteString(permissionName));
    }
    return true;
}

PermStateChangeScopeParcel* PermStateChangeScopeParcel::Unmarshalling(Parcel& in)
{
    auto* permStateChangeScopeParcel = new (std::nothrow) PermStateChangeScopeParcel();
    if (permStateChangeScopeParcel == nullptr) {
        return nullptr;
    }
    uint32_t tokenIdListSize = 0;
    RELEASE_IF_FALSE(in.ReadUint32(tokenIdListSize), permStateChangeScopeParcel);
    RELEASE_IF_FALSE(tokenIdListSize <= TOKENIDS_LIST_SIZE_MAX, permStateChangeScopeParcel);
    for (uint32_t i = 0; i < tokenIdListSize; i++) {
        AccessTokenID tokenID;
        RELEASE_IF_FALSE(in.ReadUint32(tokenID), permStateChangeScopeParcel);
        permStateChangeScopeParcel->scope.tokenIDs.emplace_back(tokenID);
    }

    uint32_t permListSize = 0;
    RELEASE_IF_FALSE(in.ReadUint32(permListSize), permStateChangeScopeParcel);
    RELEASE_IF_FALSE(permListSize <= PERMS_LIST_SIZE_MAX, permStateChangeScopeParcel);
    for (uint32_t i = 0; i < permListSize; i++) {
        std::string permName;
        RELEASE_IF_FALSE(in.ReadString(permName), permStateChangeScopeParcel);
        permStateChangeScopeParcel->scope.permList.emplace_back(permName);
    }
    return permStateChangeScopeParcel;
}
} // namespace AccessToken
} // namespace Security
} // namespace OHOS
