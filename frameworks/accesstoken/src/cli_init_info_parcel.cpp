/*
 * Copyright (c) 2026 Huawei Device Co., Ltd.
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

#include "cli_init_info_parcel.h"

#include <new>

#include "parcel_utils.h"

namespace OHOS {
namespace Security {
namespace AccessToken {
bool CliInitInfoParcel::Marshalling(Parcel& out) const
{
    RETURN_IF_FALSE(out.WriteUint32(cliInitInfo.hostTokenId));
    RETURN_IF_FALSE(out.WriteString(cliInitInfo.challenge));
    RETURN_IF_FALSE(out.WriteString(cliInitInfo.cliInfo.cliName));
    RETURN_IF_FALSE(out.WriteString(cliInitInfo.cliInfo.subCliName));
    return true;
}

CliInitInfoParcel* CliInitInfoParcel::Unmarshalling(Parcel& in)
{
    auto* parcel = new (std::nothrow) CliInitInfoParcel();
    if (parcel == nullptr) {
        return nullptr;
    }
    RELEASE_IF_FALSE(in.ReadUint32(parcel->cliInitInfo.hostTokenId), parcel);
    RELEASE_IF_FALSE(in.ReadString(parcel->cliInitInfo.challenge), parcel);
    RELEASE_IF_FALSE(in.ReadString(parcel->cliInitInfo.cliInfo.cliName), parcel);
    RELEASE_IF_FALSE(in.ReadString(parcel->cliInitInfo.cliInfo.subCliName), parcel);
    return parcel;
}
} // namespace AccessToken
} // namespace Security
} // namespace OHOS
