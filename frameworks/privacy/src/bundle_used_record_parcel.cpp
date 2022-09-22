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

#include "bundle_used_record_parcel.h"
#include "refbase.h"
#include "parcel_utils.h"
#include "permission_used_record_parcel.h"

namespace OHOS {
namespace Security {
namespace AccessToken {
bool BundleUsedRecordParcel::Marshalling(Parcel& out) const
{
    RETURN_IF_FALSE(out.WriteUint32(this->bundleRecord.tokenId));
    RETURN_IF_FALSE(out.WriteBool(this->bundleRecord.isRemote));
    RETURN_IF_FALSE(out.WriteString(this->bundleRecord.deviceId));
    RETURN_IF_FALSE(out.WriteString(this->bundleRecord.bundleName));

    RETURN_IF_FALSE(out.WriteUint32(this->bundleRecord.permissionRecords.size()));
    for (const auto& permRecord : this->bundleRecord.permissionRecords) {
        PermissionUsedRecordParcel permRecordParcel;
        permRecordParcel.permissionRecord = permRecord;
        out.WriteParcelable(&permRecordParcel);
    }
    return true;
}

BundleUsedRecordParcel* BundleUsedRecordParcel::Unmarshalling(Parcel& in)
{
    auto* bundleRecordParcel = new (std::nothrow) BundleUsedRecordParcel();
    if (bundleRecordParcel == nullptr) {
        return nullptr;
    }

    RELEASE_IF_FALSE(in.ReadUint32(bundleRecordParcel->bundleRecord.tokenId), bundleRecordParcel);
    RELEASE_IF_FALSE(in.ReadBool(bundleRecordParcel->bundleRecord.isRemote), bundleRecordParcel);
    RELEASE_IF_FALSE(in.ReadString(bundleRecordParcel->bundleRecord.deviceId), bundleRecordParcel);
    RELEASE_IF_FALSE(in.ReadString(bundleRecordParcel->bundleRecord.bundleName), bundleRecordParcel);

    uint32_t permRecordSize = 0;
    RELEASE_IF_FALSE(in.ReadUint32(permRecordSize), bundleRecordParcel);
    RELEASE_IF_FALSE(permRecordSize <= MAX_RECORD_SIZE, bundleRecordParcel);
    for (uint32_t i = 0; i < permRecordSize; i++) {
        sptr<PermissionUsedRecordParcel> permRecord = in.ReadParcelable<PermissionUsedRecordParcel>();
        RELEASE_IF_FALSE(permRecord != nullptr, bundleRecordParcel);
        bundleRecordParcel->bundleRecord.permissionRecords.emplace_back(permRecord->permissionRecord);
    }
    return bundleRecordParcel;
}
} // namespace AccessToken
} // namespace Security
} // namespace OHOS
