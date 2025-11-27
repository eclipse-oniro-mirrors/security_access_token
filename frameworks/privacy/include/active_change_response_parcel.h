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

#ifndef PERM_ACTIVE_RESPONES_PARCEL_H
#define PERM_ACTIVE_RESPONES_PARCEL_H

#include "active_change_response_info.h"
#include "parcel.h"

namespace OHOS {
namespace Security {
namespace AccessToken {
struct ActiveChangeResponseParcel final : public Parcelable {
    ActiveChangeResponseParcel() = default;

    ~ActiveChangeResponseParcel() override = default;

    bool Marshalling(Parcel& out) const override;

    static ActiveChangeResponseParcel* Unmarshalling(Parcel& in);

    ActiveChangeResponse changeResponse;
};
} // namespace AccessToken
} // namespace Security
} // namespace OHOS

#endif // PERM_ACTIVE_RESPONES_PARCEL_H
