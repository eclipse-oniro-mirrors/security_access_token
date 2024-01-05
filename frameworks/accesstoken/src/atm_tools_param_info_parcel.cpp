/*
 * Copyright (c) 2024 Huawei Device Co., Ltd.
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

#include "atm_tools_param_info_parcel.h"
#include "parcel_utils.h"

namespace OHOS {
namespace Security {
namespace AccessToken {
bool AtmToolsParamInfoParcel::Marshalling(Parcel& out) const
{
    RETURN_IF_FALSE(out.WriteInt32(this->info.type));
    RETURN_IF_FALSE(out.WriteUint32(this->info.tokenId));
    RETURN_IF_FALSE(out.WriteString(this->info.permissionName));
    RETURN_IF_FALSE(out.WriteString(this->info.bundleName));
    RETURN_IF_FALSE(out.WriteString(this->info.processName));
    return true;
}

AtmToolsParamInfoParcel* AtmToolsParamInfoParcel::Unmarshalling(Parcel& in)
{
    auto* atmToolsParamInfoParcel = new (std::nothrow) AtmToolsParamInfoParcel();
    if (atmToolsParamInfoParcel == nullptr) {
        return nullptr;
    }

    int32_t type;
    RELEASE_IF_FALSE(in.ReadInt32(type), atmToolsParamInfoParcel);
    atmToolsParamInfoParcel->info.type = OptType(type);
    RELEASE_IF_FALSE(in.ReadUint32(atmToolsParamInfoParcel->info.tokenId), atmToolsParamInfoParcel);
    atmToolsParamInfoParcel->info.permissionName = in.ReadString();
    atmToolsParamInfoParcel->info.bundleName = in.ReadString();
    atmToolsParamInfoParcel->info.processName = in.ReadString();
    return atmToolsParamInfoParcel;
}
} // namespace AccessToken
} // namespace Security
} // namespace OHOS
