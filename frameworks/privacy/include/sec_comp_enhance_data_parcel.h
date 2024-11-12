/*
 * Copyright (c) 2023 Huawei Device Co., Ltd.
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

#ifndef SEC_COMP_ENHANCE_DATA_PARCEL_H
#define SEC_COMP_ENHANCE_DATA_PARCEL_H

#include "parcel.h"
#include "sec_comp_enhance_data.h"

namespace OHOS {
namespace Security {
namespace AccessToken {
struct SecCompEnhanceDataParcel final : public Parcelable {
    SecCompEnhanceDataParcel() = default;

    ~SecCompEnhanceDataParcel() override = default;

    bool Marshalling(Parcel& out) const override;

    static SecCompEnhanceDataParcel* Unmarshalling(Parcel& in);

    SecCompEnhanceData enhanceData;
};
} // namespace AccessToken
} // namespace Security
} // namespace OHOS

#endif // SEC_COMP_ENHANCE_DATA_PARCEL_H
