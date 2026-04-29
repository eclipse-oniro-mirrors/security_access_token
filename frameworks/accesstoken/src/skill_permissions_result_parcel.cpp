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

#include "skill_permissions_result_parcel.h"

#include "parcel_utils.h"

namespace OHOS {
namespace Security {
namespace AccessToken {
namespace {
bool WriteDecisionStatusList(Parcel& out, const std::vector<PermissionDecisionStatus>& statusList)
{
    RETURN_IF_FALSE(out.WriteUint32(statusList.size()));
    for (const auto& status : statusList) {
        RETURN_IF_FALSE(out.WriteInt32(static_cast<int32_t>(status)));
    }
    return true;
}

bool ReadDecisionStatusList(Parcel& in, std::vector<PermissionDecisionStatus>& statusList)
{
    uint32_t size = 0;
    RETURN_IF_FALSE(in.ReadUint32(size));
    statusList.clear();
    statusList.reserve(size);
    for (uint32_t i = 0; i < size; ++i) {
        int32_t status = 0;
        RETURN_IF_FALSE(in.ReadInt32(status));
        statusList.emplace_back(static_cast<PermissionDecisionStatus>(status));
    }
    return true;
}
}

bool SkillPermissionsResultParcel::Marshalling(Parcel& out) const
{
    RETURN_IF_FALSE(out.WriteUint32(result.permList.size()));
    for (const auto& commandResult : result.permList) {
        RETURN_IF_FALSE(out.WriteStringVector(commandResult.usedPermissions));
        RETURN_IF_FALSE(WriteDecisionStatusList(out, commandResult.statusList));
    }
    return true;
}

SkillPermissionsResultParcel* SkillPermissionsResultParcel::Unmarshalling(Parcel& in)
{
    auto* parcel = new (std::nothrow) SkillPermissionsResultParcel();
    if (parcel == nullptr) {
        return nullptr;
    }
    uint32_t commandSize = 0;
    RELEASE_IF_FALSE(in.ReadUint32(commandSize), parcel);
    parcel->result.permList.clear();
    parcel->result.permList.reserve(commandSize);
    for (uint32_t i = 0; i < commandSize; ++i) {
        SkillCommandPermissionResult commandResult;
        RELEASE_IF_FALSE(in.ReadStringVector(&commandResult.usedPermissions), parcel);
        RELEASE_IF_FALSE(ReadDecisionStatusList(in, commandResult.statusList), parcel);
        parcel->result.permList.emplace_back(commandResult);
    }
    return parcel;
}
} // namespace AccessToken
} // namespace Security
} // namespace OHOS
