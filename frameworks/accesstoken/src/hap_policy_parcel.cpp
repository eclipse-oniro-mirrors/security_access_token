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

#include "hap_policy_parcel.h"
#include "refbase.h"
#include "access_token.h"
#include "parcel_utils.h"
#include "permission_def.h"
#include "permission_def_parcel.h"
#include "permission_state_full.h"
#include "permission_state_full_parcel.h"

namespace OHOS {
namespace Security {
namespace AccessToken {
bool HapPolicyParcel::Marshalling(Parcel& out) const
{
    RETURN_IF_FALSE(out.WriteInt32(this->hapPolicyParameter.apl));
    RETURN_IF_FALSE(out.WriteString(this->hapPolicyParameter.domain));

    const std::vector<PermissionDef>& permList = this->hapPolicyParameter.permList;
    uint32_t permListSize = permList.size();
    RETURN_IF_FALSE(out.WriteUint32(permListSize));

    for (uint32_t i = 0; i < permListSize; i++) {
        PermissionDefParcel permDefParcel;
        permDefParcel.permissionDef = permList[i];
        out.WriteParcelable(&permDefParcel);
    }

    const std::vector<PermissionStateFull>& permStateList = this->hapPolicyParameter.permStateList;
    uint32_t permStateListSize = permStateList.size();
    RETURN_IF_FALSE(out.WriteUint32(permStateListSize));

    for (uint32_t i = 0; i < permStateListSize; i++) {
        PermissionStateFullParcel permStateParcel;
        permStateParcel.permStatFull = permStateList[i];
        out.WriteParcelable(&permStateParcel);
    }

    const std::vector<std::string>& aclRequestedList = this->hapPolicyParameter.aclRequestedList;
    uint32_t aclRequestedListSize = aclRequestedList.size();
    RETURN_IF_FALSE(out.WriteUint32(aclRequestedListSize));

    for (uint32_t i = 0; i < aclRequestedListSize; i++) {
        RETURN_IF_FALSE(out.WriteString(aclRequestedList[i]));
    }

    const std::vector<PreAuthorizationInfo>& info = this->hapPolicyParameter.preAuthorizationInfo;
    uint32_t infoSize = info.size();
    RETURN_IF_FALSE(out.WriteUint32(infoSize));

    for (uint32_t i = 0; i < infoSize; i++) {
        RETURN_IF_FALSE(out.WriteString(info[i].permissionName));
        RETURN_IF_FALSE(out.WriteBool(info[i].userCancelable));
    }
    return true;
}

HapPolicyParcel* HapPolicyParcel::Unmarshalling(Parcel& in)
{
    auto* hapPolicyParcel = new (std::nothrow) HapPolicyParcel();
    if (hapPolicyParcel == nullptr) {
        return nullptr;
    }

    int32_t apl;
    RELEASE_IF_FALSE(in.ReadInt32(apl), hapPolicyParcel);
    hapPolicyParcel->hapPolicyParameter.apl = ATokenAplEnum(apl);

    hapPolicyParcel->hapPolicyParameter.domain = in.ReadString();

    uint32_t permListSize;
    RELEASE_IF_FALSE(in.ReadUint32(permListSize), hapPolicyParcel);
    RELEASE_IF_FALSE((permListSize <= MAX_PERMLIST_SIZE), hapPolicyParcel);

    for (uint32_t i = 0; i < permListSize; i++) {
        sptr<PermissionDefParcel> permDefParcel = in.ReadParcelable<PermissionDefParcel>();
        RELEASE_IF_FALSE(permDefParcel != nullptr, hapPolicyParcel);
        hapPolicyParcel->hapPolicyParameter.permList.emplace_back(permDefParcel->permissionDef);
    }

    uint32_t permStateListSize;
    RELEASE_IF_FALSE(in.ReadUint32(permStateListSize), hapPolicyParcel);
    RELEASE_IF_FALSE((permStateListSize <= MAX_PERMLIST_SIZE), hapPolicyParcel);
    for (uint32_t i = 0; i < permStateListSize; i++) {
        sptr<PermissionStateFullParcel> permissionStateParcel = in.ReadParcelable<PermissionStateFullParcel>();
        RELEASE_IF_FALSE(permissionStateParcel != nullptr, hapPolicyParcel);
        hapPolicyParcel->hapPolicyParameter.permStateList.emplace_back(permissionStateParcel->permStatFull);
    }
    uint32_t aclRequestedListSize;
    RELEASE_IF_FALSE(in.ReadUint32(aclRequestedListSize), hapPolicyParcel);
    RELEASE_IF_FALSE((aclRequestedListSize <= MAX_PERMLIST_SIZE), hapPolicyParcel);
    for (uint32_t i = 0; i < aclRequestedListSize; i++) {
        std::string acl;
        RELEASE_IF_FALSE(in.ReadString(acl), hapPolicyParcel);
        hapPolicyParcel->hapPolicyParameter.aclRequestedList.emplace_back(acl);
    }
    uint32_t infoSize;
    RELEASE_IF_FALSE(in.ReadUint32(infoSize), hapPolicyParcel);
    RELEASE_IF_FALSE((infoSize <= MAX_PERMLIST_SIZE), hapPolicyParcel);
    for (uint32_t i = 0; i < infoSize; i++) {
        PreAuthorizationInfo info;
        RELEASE_IF_FALSE(in.ReadString(info.permissionName), hapPolicyParcel);
        RELEASE_IF_FALSE(in.ReadBool(info.userCancelable), hapPolicyParcel);
        hapPolicyParcel->hapPolicyParameter.preAuthorizationInfo.emplace_back(info);
    }
    return hapPolicyParcel;
}
} // namespace AccessToken
} // namespace Security
} // namespace OHOS
