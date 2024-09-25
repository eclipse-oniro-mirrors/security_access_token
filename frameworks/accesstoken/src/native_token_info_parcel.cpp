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

#include "native_token_info_parcel.h"
#include <iosfwd>
#include <new>
#include <string>
#include <vector>
#include "access_token.h"
#include "parcel_utils.h"

namespace OHOS {
namespace Security {
namespace AccessToken {
bool NativeTokenInfoParcel::Marshalling(Parcel& out) const
{
    RETURN_IF_FALSE(out.WriteInt32(this->nativeTokenInfoParams.apl));
    RETURN_IF_FALSE(out.WriteString(this->nativeTokenInfoParams.processName));
    return true;
}

NativeTokenInfoParcel* NativeTokenInfoParcel::Unmarshalling(Parcel& in)
{
    auto* nativeTokenInfoParcel = new (std::nothrow) NativeTokenInfoParcel();
    if (nativeTokenInfoParcel == nullptr) {
        return nullptr;
    }

    int32_t apl;
    RELEASE_IF_FALSE(in.ReadInt32(apl), nativeTokenInfoParcel);
    nativeTokenInfoParcel->nativeTokenInfoParams.apl = ATokenAplEnum(apl);
    nativeTokenInfoParcel->nativeTokenInfoParams.processName = in.ReadString();
    return nativeTokenInfoParcel;
}
} // namespace AccessToken
} // namespace Security
} // namespace OHOS
