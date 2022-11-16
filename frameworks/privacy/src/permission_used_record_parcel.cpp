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

#include "permission_used_record_parcel.h"
#include "refbase.h"
#include "parcel_utils.h"
#include "used_record_detail_parcel.h"

namespace OHOS {
namespace Security {
namespace AccessToken {
bool PermissionUsedRecordParcel::Marshalling(Parcel& out) const
{
    RETURN_IF_FALSE(out.WriteString(this->permissionRecord.permissionName));
    RETURN_IF_FALSE(out.WriteInt32(this->permissionRecord.accessCount));
    RETURN_IF_FALSE(out.WriteInt32(this->permissionRecord.rejectCount));
    RETURN_IF_FALSE(out.WriteInt64(this->permissionRecord.lastAccessTime));
    RETURN_IF_FALSE(out.WriteInt64(this->permissionRecord.lastRejectTime));
    RETURN_IF_FALSE(out.WriteInt64(this->permissionRecord.lastAccessDuration));

    RETURN_IF_FALSE(out.WriteUint32(this->permissionRecord.accessRecords.size()));
    for (const auto& accRecord : this->permissionRecord.accessRecords) {
        UsedRecordDetailParcel detailParcel;
        detailParcel.detail = accRecord;
        out.WriteParcelable(&detailParcel);
    }

    RETURN_IF_FALSE(out.WriteUint32(this->permissionRecord.rejectRecords.size()));
    for (const auto& rejRecord : this->permissionRecord.rejectRecords) {
        UsedRecordDetailParcel detailParcel;
        detailParcel.detail = rejRecord;
        out.WriteParcelable(&detailParcel);
    }
    return true;
}

PermissionUsedRecordParcel* PermissionUsedRecordParcel::Unmarshalling(Parcel& in)
{
    auto* permissionRecordParcel = new (std::nothrow) PermissionUsedRecordParcel();
    if (permissionRecordParcel == nullptr) {
        return nullptr;
    }

    RELEASE_IF_FALSE(in.ReadString(permissionRecordParcel->permissionRecord.permissionName), permissionRecordParcel);
    RELEASE_IF_FALSE(in.ReadInt32(permissionRecordParcel->permissionRecord.accessCount), permissionRecordParcel);
    RELEASE_IF_FALSE(in.ReadInt32(permissionRecordParcel->permissionRecord.rejectCount), permissionRecordParcel);
    RELEASE_IF_FALSE(in.ReadInt64(permissionRecordParcel->permissionRecord.lastAccessTime), permissionRecordParcel);
    RELEASE_IF_FALSE(in.ReadInt64(permissionRecordParcel->permissionRecord.lastRejectTime), permissionRecordParcel);
    RELEASE_IF_FALSE(in.ReadInt64(permissionRecordParcel->permissionRecord.lastAccessDuration), permissionRecordParcel);

    uint32_t accRecordSize = 0;
    RELEASE_IF_FALSE(in.ReadUint32(accRecordSize), permissionRecordParcel);
    RELEASE_IF_FALSE(accRecordSize <= MAX_ACCESS_RECORD_SIZE, permissionRecordParcel);
    for (uint32_t i = 0; i < accRecordSize; i++) {
        sptr<UsedRecordDetailParcel> detailParcel = in.ReadParcelable<UsedRecordDetailParcel>();
        RELEASE_IF_FALSE(detailParcel != nullptr, permissionRecordParcel);
        permissionRecordParcel->permissionRecord.accessRecords.emplace_back(detailParcel->detail);
    }

    uint32_t rejRecordSize = 0;
    RELEASE_IF_FALSE(in.ReadUint32(rejRecordSize), permissionRecordParcel);
    RELEASE_IF_FALSE(rejRecordSize <= MAX_ACCESS_RECORD_SIZE, permissionRecordParcel);
    for (uint32_t i = 0; i < rejRecordSize; i++) {
        sptr<UsedRecordDetailParcel> detailParcel = in.ReadParcelable<UsedRecordDetailParcel>();
        RELEASE_IF_FALSE(detailParcel != nullptr, permissionRecordParcel);
        permissionRecordParcel->permissionRecord.rejectRecords.emplace_back(detailParcel->detail);
    }
    return permissionRecordParcel;
}
} // namespace AccessToken
} // namespace Security
} // namespace OHOS
