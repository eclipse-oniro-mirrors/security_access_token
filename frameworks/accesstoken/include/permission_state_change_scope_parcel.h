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

#ifndef PERMISSION_STATE_CHANGE_SCOPE_PARCEL_H
#define PERMISSION_STATE_CHANGE_SCOPE_PARCEL_H

#include "parcel.h"
#include "permission_state_change_info.h"

namespace OHOS {
namespace Security {
namespace AccessToken {
struct PermStateChangeScopeParcel final : public Parcelable {
    PermStateChangeScopeParcel() = default;

    ~PermStateChangeScopeParcel() override = default;

    bool Marshalling(Parcel& out) const override;

    static PermStateChangeScopeParcel* Unmarshalling(Parcel& in);

    PermStateChangeScope scope;
};
} // namespace AccessToken
} // namespace Security
} // namespace OHOS

#endif // PERMISSION_STATE_CHANGE_SCOPE_PARCEL_H
