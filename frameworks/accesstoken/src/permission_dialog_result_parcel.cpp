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

#include "permission_dialog_result_parcel.h"

#include "parcel_utils.h"

namespace OHOS {
namespace Security {
namespace AccessToken {
namespace {
bool WriteStatusList(Parcel& out, const std::vector<PermissionDecisionStatus>& statusList)
{
    RETURN_IF_FALSE(out.WriteUint32(statusList.size()));
    for (const auto& status : statusList) {
        RETURN_IF_FALSE(out.WriteInt32(static_cast<int32_t>(status)));
    }
    return true;
}

bool ReadStatusList(Parcel& in, std::vector<PermissionDecisionStatus>& statusList)
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

bool PermissionDialogResultParcel::Marshalling(Parcel& out) const
{
    RETURN_IF_FALSE(out.WriteUint32(result.detailList.size()));
    for (const auto& detail : result.detailList) {
        RETURN_IF_FALSE(out.WriteBool(detail.needPermissionDialog));
        RETURN_IF_FALSE(out.WriteStringVector(detail.permissionNameList));
        RETURN_IF_FALSE(WriteStatusList(out, detail.statusList));
        RETURN_IF_FALSE(out.WriteString(detail.authResult));
    }
    return true;
}

PermissionDialogResultParcel* PermissionDialogResultParcel::Unmarshalling(Parcel& in)
{
    auto* parcel = new (std::nothrow) PermissionDialogResultParcel();
    if (parcel == nullptr) {
        return nullptr;
    }
    uint32_t size = 0;
    RELEASE_IF_FALSE(in.ReadUint32(size), parcel);
    parcel->result.detailList.clear();
    parcel->result.detailList.reserve(size);
    for (uint32_t i = 0; i < size; ++i) {
        PermissionDialogDetail detail;
        RELEASE_IF_FALSE(in.ReadBool(detail.needPermissionDialog), parcel);
        RELEASE_IF_FALSE(in.ReadStringVector(&detail.permissionNameList), parcel);
        RELEASE_IF_FALSE(ReadStatusList(in, detail.statusList), parcel);
        RELEASE_IF_FALSE(in.ReadString(detail.authResult), parcel);
        parcel->result.detailList.emplace_back(detail);
    }
    return parcel;
}
} // namespace AccessToken
} // namespace Security
} // namespace OHOS
