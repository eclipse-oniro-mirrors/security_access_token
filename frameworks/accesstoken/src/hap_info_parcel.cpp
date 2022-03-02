/*
 * Copyright (c) 2021-2022 Huawei Device Co., Ltd.
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

#include "hap_info_parcel.h"

namespace OHOS {
namespace Security {
namespace AccessToken {
#define RETURN_IF_FALSE(expr) \
    if (!(expr)) { \
        return false; \
    }

#define RELEASE_IF_FALSE(expr, obj) \
    if (!(expr)) { \
        delete (obj); \
        (obj) = nullptr; \
        return (obj); \
    }

bool HapInfoParcel::Marshalling(Parcel& out) const
{
    RETURN_IF_FALSE(out.WriteInt32(this->hapInfoParameter.userID));
    RETURN_IF_FALSE(out.WriteString(this->hapInfoParameter.bundleName));
    RETURN_IF_FALSE(out.WriteInt32(this->hapInfoParameter.instIndex));
    RETURN_IF_FALSE(out.WriteString(this->hapInfoParameter.appIDDesc));
    return true;
}

HapInfoParcel* HapInfoParcel::Unmarshalling(Parcel& in)
{
    auto* hapInfoParcel = new (std::nothrow) HapInfoParcel();
    RELEASE_IF_FALSE(hapInfoParcel != nullptr, hapInfoParcel);
    RELEASE_IF_FALSE(in.ReadInt32(hapInfoParcel->hapInfoParameter.userID), hapInfoParcel);
    hapInfoParcel->hapInfoParameter.bundleName = in.ReadString();
    RELEASE_IF_FALSE(in.ReadInt32(hapInfoParcel->hapInfoParameter.instIndex), hapInfoParcel);
    hapInfoParcel->hapInfoParameter.appIDDesc = in.ReadString();

    return hapInfoParcel;
}
} // namespace AccessToken
} // namespace Security
} // namespace OHOS
