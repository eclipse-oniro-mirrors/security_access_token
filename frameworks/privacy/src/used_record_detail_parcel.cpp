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

#include "used_record_detail_parcel.h"
#include "parcel_utils.h"

namespace OHOS {
namespace Security {
namespace AccessToken {
bool UsedRecordDetailParcel::Marshalling(Parcel& out) const
{
    RETURN_IF_FALSE(out.WriteInt32(this->detail.status));
    RETURN_IF_FALSE(out.WriteInt32(this->detail.lockScreenStatus));
    RETURN_IF_FALSE(out.WriteInt64(this->detail.timestamp));
    RETURN_IF_FALSE(out.WriteInt64(this->detail.accessDuration));
    RETURN_IF_FALSE(out.WriteInt32(this->detail.count));
    RETURN_IF_FALSE(out.WriteUint32(static_cast<uint32_t>(this->detail.type)));
    return true;
}

UsedRecordDetailParcel* UsedRecordDetailParcel::Unmarshalling(Parcel& in)
{
    auto* detailRecordParcel = new (std::nothrow) UsedRecordDetailParcel();
    if (detailRecordParcel == nullptr) {
        return nullptr;
    }

    RELEASE_IF_FALSE(in.ReadInt32(detailRecordParcel->detail.status), detailRecordParcel);
    RELEASE_IF_FALSE(in.ReadInt32(detailRecordParcel->detail.lockScreenStatus), detailRecordParcel);
    RELEASE_IF_FALSE(in.ReadInt64(detailRecordParcel->detail.timestamp), detailRecordParcel);
    RELEASE_IF_FALSE(in.ReadInt64(detailRecordParcel->detail.accessDuration), detailRecordParcel);
    RELEASE_IF_FALSE(in.ReadInt32(detailRecordParcel->detail.count), detailRecordParcel);
    uint32_t type = 0;
    RELEASE_IF_FALSE(in.ReadUint32(type), detailRecordParcel);
    detailRecordParcel->detail.type = static_cast<PermissionUsedType>(type);
    return detailRecordParcel;
}
} // namespace AccessToken
} // namespace Security
} // namespace OHOS
