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

#include "hap_token_info_parcel.h"
#include "parcel_utils.h"

namespace OHOS {
namespace Security {
namespace AccessToken {
bool HapTokenInfoParcel::Marshalling(Parcel& out) const
{
    RETURN_IF_FALSE(out.WriteInt32(this->hapTokenInfoParams.apl));
    RETURN_IF_FALSE(out.WriteUint8(this->hapTokenInfoParams.ver));
    RETURN_IF_FALSE(out.WriteInt32(this->hapTokenInfoParams.userID));
    RETURN_IF_FALSE(out.WriteString(this->hapTokenInfoParams.bundleName));
    RETURN_IF_FALSE(out.WriteInt32(this->hapTokenInfoParams.apiVersion));
    RETURN_IF_FALSE(out.WriteInt32(this->hapTokenInfoParams.instIndex));
    RETURN_IF_FALSE(out.WriteInt32(this->hapTokenInfoParams.dlpType));
    RETURN_IF_FALSE(out.WriteString(this->hapTokenInfoParams.appID));
    RETURN_IF_FALSE(out.WriteString(this->hapTokenInfoParams.deviceID));
    RETURN_IF_FALSE(out.WriteUint32(this->hapTokenInfoParams.tokenID));
    RETURN_IF_FALSE(out.WriteUint32(this->hapTokenInfoParams.tokenAttr));
    return true;
}

HapTokenInfoParcel* HapTokenInfoParcel::Unmarshalling(Parcel& in)
{
    auto* hapTokenInfoParcel = new (std::nothrow) HapTokenInfoParcel();
    if (hapTokenInfoParcel == nullptr) {
        return nullptr;
    }

    int apl;
    uint8_t ver;
    RELEASE_IF_FALSE(in.ReadInt32(apl), hapTokenInfoParcel);
    hapTokenInfoParcel->hapTokenInfoParams.apl = ATokenAplEnum(apl);
    RELEASE_IF_FALSE(in.ReadUint8(ver), hapTokenInfoParcel);
    hapTokenInfoParcel->hapTokenInfoParams.ver = ver;
    RELEASE_IF_FALSE(in.ReadInt32(hapTokenInfoParcel->hapTokenInfoParams.userID), hapTokenInfoParcel);
    hapTokenInfoParcel->hapTokenInfoParams.bundleName = in.ReadString();
    RELEASE_IF_FALSE(in.ReadInt32(hapTokenInfoParcel->hapTokenInfoParams.apiVersion), hapTokenInfoParcel);
    RELEASE_IF_FALSE(in.ReadInt32(hapTokenInfoParcel->hapTokenInfoParams.instIndex), hapTokenInfoParcel);
    RELEASE_IF_FALSE(in.ReadInt32(hapTokenInfoParcel->hapTokenInfoParams.dlpType), hapTokenInfoParcel);
    hapTokenInfoParcel->hapTokenInfoParams.appID = in.ReadString();
    hapTokenInfoParcel->hapTokenInfoParams.deviceID = in.ReadString();
    RELEASE_IF_FALSE(in.ReadUint32(hapTokenInfoParcel->hapTokenInfoParams.tokenID), hapTokenInfoParcel);
    RELEASE_IF_FALSE(in.ReadUint32(hapTokenInfoParcel->hapTokenInfoParams.tokenAttr), hapTokenInfoParcel);
    return hapTokenInfoParcel;
}
} // namespace AccessToken
} // namespace Security
} // namespace OHOS
