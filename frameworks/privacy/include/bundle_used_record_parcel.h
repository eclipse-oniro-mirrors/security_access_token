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

#ifndef BUNDLE_USED_RECORD_PARCEL_H
#define BUNDLE_USED_RECORD_PARCEL_H

#include "parcel.h"
#include "permission_used_result.h"

namespace OHOS {
namespace Security {
namespace AccessToken {
struct BundleUsedRecordParcel final : public Parcelable {
    BundleUsedRecordParcel() = default;

    ~BundleUsedRecordParcel() override = default;

    bool Marshalling(Parcel& out) const override;

    static BundleUsedRecordParcel* Unmarshalling(Parcel& in);

    BundleUsedRecord bundleRecord;
};
} // namespace AccessToken
} // namespace Security
} // namespace OHOS

#endif // BUNDLE_USED_RECORD_PARCEL_H
