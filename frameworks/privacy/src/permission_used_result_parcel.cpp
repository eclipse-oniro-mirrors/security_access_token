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

#include "permission_used_result_parcel.h"
#include "bundle_used_record_parcel.h"
#include "parcel_utils.h"
#include <stdint.h>
#include <new>
#include "refbase.h"
#include <vector>

namespace OHOS {
namespace Security {
namespace AccessToken {
bool PermissionUsedResultParcel::Marshalling(Parcel& out) const
{
    RETURN_IF_FALSE(out.WriteInt64(this->result.beginTimeMillis));
    RETURN_IF_FALSE(out.WriteInt64(this->result.endTimeMillis));

    RETURN_IF_FALSE(out.WriteInt32((int32_t)(this->result.bundleRecords.size())));
    for (const auto& bundRecord : this->result.bundleRecords) {
        BundleUsedRecordParcel bundleParcel;
        bundleParcel.bundleRecord = bundRecord;
        out.WriteParcelable(&bundleParcel);
    }
    return true;
}

PermissionUsedResultParcel* PermissionUsedResultParcel::Unmarshalling(Parcel& in)
{
    auto* resultParcel = new (std::nothrow) PermissionUsedResultParcel();
    RELEASE_IF_FALSE(resultParcel != nullptr, resultParcel);

    RELEASE_IF_FALSE(in.ReadInt64(resultParcel->result.beginTimeMillis), resultParcel);
    RELEASE_IF_FALSE(in.ReadInt64(resultParcel->result.endTimeMillis), resultParcel);

    int32_t bundResponseSize = 0;
    RELEASE_IF_FALSE(in.ReadInt32(bundResponseSize), resultParcel);
    for (int32_t i = 0; i < bundResponseSize; i++) {
        sptr<BundleUsedRecordParcel> bunRecordParcel = in.ReadParcelable<BundleUsedRecordParcel>();
        RELEASE_IF_FALSE(bunRecordParcel != nullptr, resultParcel);
        resultParcel->result.bundleRecords.emplace_back(bunRecordParcel->bundleRecord);
    }
    return resultParcel;
}
} // namespace AccessToken
} // namespace Security
} // namespace OHOS
