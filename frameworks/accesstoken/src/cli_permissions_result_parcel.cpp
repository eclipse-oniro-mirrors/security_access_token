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

#include "cli_permissions_result_parcel.h"

#include "parcel_utils.h"

namespace OHOS {
namespace Security {
namespace AccessToken {
namespace {
bool WriteDecisionStatus(Parcel& out, PermissionDecisionStatus status)
{
    return out.WriteInt32(static_cast<int32_t>(status));
}

bool ReadDecisionStatus(Parcel& in, PermissionDecisionStatus& status)
{
    int32_t value = 0;
    RETURN_IF_FALSE(in.ReadInt32(value));
    status = static_cast<PermissionDecisionStatus>(value);
    return true;
}
}

bool CliPermissionsResultParcel::Marshalling(Parcel& out) const
{
    RETURN_IF_FALSE(out.WriteUint32(result.permList.size()));
    for (const auto& commandResult : result.permList) {
        RETURN_IF_FALSE(out.WriteUint32(commandResult.requiredCliPermissions.size()));
        for (const auto& detail : commandResult.requiredCliPermissions) {
            RETURN_IF_FALSE(out.WriteString(detail.requiredCliPermission));
            RETURN_IF_FALSE(WriteDecisionStatus(out, detail.cliPermissionStatus));
            RETURN_IF_FALSE(out.WriteStringVector(detail.usedPermissions));
        }
    }
    return true;
}

CliPermissionsResultParcel* CliPermissionsResultParcel::Unmarshalling(Parcel& in)
{
    auto* parcel = new (std::nothrow) CliPermissionsResultParcel();
    if (parcel == nullptr) {
        return nullptr;
    }
    uint32_t commandSize = 0;
    RELEASE_IF_FALSE(in.ReadUint32(commandSize), parcel);
    RELEASE_IF_FALSE(commandSize <= MAX_COMMAND_LIST_SIZE, parcel);
    parcel->result.permList.clear();
    parcel->result.permList.reserve(commandSize);
    for (uint32_t i = 0; i < commandSize; ++i) {
        CliCommandPermissionResult commandResult;
        uint32_t detailSize = 0;
        RELEASE_IF_FALSE(in.ReadUint32(detailSize), parcel);
        RELEASE_IF_FALSE(detailSize <= MAX_PERMLIST_SIZE, parcel);
        commandResult.requiredCliPermissions.reserve(detailSize);
        for (uint32_t j = 0; j < detailSize; ++j) {
            CliPermissionDetail detail;
            RELEASE_IF_FALSE(in.ReadString(detail.requiredCliPermission), parcel);
            RELEASE_IF_FALSE(ReadDecisionStatus(in, detail.cliPermissionStatus), parcel);
            RELEASE_IF_FALSE(in.ReadStringVector(&detail.usedPermissions), parcel);
            commandResult.requiredCliPermissions.emplace_back(detail);
        }
        parcel->result.permList.emplace_back(commandResult);
    }
    return parcel;
}
} // namespace AccessToken
} // namespace Security
} // namespace OHOS
