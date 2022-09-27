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
    RETURN_IF_FALSE(out.WriteUint8(this->nativeTokenInfoParams.ver));
    RETURN_IF_FALSE(out.WriteString(this->nativeTokenInfoParams.processName));
    RETURN_IF_FALSE(out.WriteUint32(this->nativeTokenInfoParams.tokenID));
    RETURN_IF_FALSE(out.WriteUint32(this->nativeTokenInfoParams.tokenAttr));

    if ((this->nativeTokenInfoParams.dcap).size() > MAX_DCAP_SIZE) {
        return false;
    }
    uint32_t dcapSize = (this->nativeTokenInfoParams.dcap).size();
    RETURN_IF_FALSE(out.WriteUint32(dcapSize));

    for (const auto& dcapItem : this->nativeTokenInfoParams.dcap) {
        RETURN_IF_FALSE(out.WriteString(dcapItem));
    }

    if ((this->nativeTokenInfoParams.nativeAcls).size() > MAX_ACL_SIZE) {
        return false;
    }
    uint32_t nativeAclSize = (this->nativeTokenInfoParams.nativeAcls).size();
    RETURN_IF_FALSE(out.WriteUint32(nativeAclSize));

    for (const auto& item : this->nativeTokenInfoParams.nativeAcls) {
        RETURN_IF_FALSE(out.WriteString(item));
    }

    return true;
}

NativeTokenInfoParcel* NativeTokenInfoParcel::Unmarshalling(Parcel& in)
{
    auto* nativeTokenInfoParcel = new (std::nothrow) NativeTokenInfoParcel();
    if (nativeTokenInfoParcel == nullptr) {
        return nullptr;
    }

    int32_t apl;
    uint8_t ver;
    RELEASE_IF_FALSE(in.ReadInt32(apl), nativeTokenInfoParcel);
    RELEASE_IF_FALSE(in.ReadUint8(ver), nativeTokenInfoParcel);
    nativeTokenInfoParcel->nativeTokenInfoParams.apl = ATokenAplEnum(apl);
    nativeTokenInfoParcel->nativeTokenInfoParams.ver = ver;

    nativeTokenInfoParcel->nativeTokenInfoParams.processName = in.ReadString();
    RELEASE_IF_FALSE(in.ReadUint32(nativeTokenInfoParcel->nativeTokenInfoParams.tokenID), nativeTokenInfoParcel);
    RELEASE_IF_FALSE(in.ReadUint32(nativeTokenInfoParcel->nativeTokenInfoParams.tokenAttr), nativeTokenInfoParcel);

    uint32_t dcapSize;
    RELEASE_IF_FALSE(in.ReadUint32(dcapSize), nativeTokenInfoParcel);
    RELEASE_IF_FALSE(dcapSize <= MAX_DCAP_SIZE, nativeTokenInfoParcel);

    for (uint32_t i = 0; i < dcapSize; i++) {
        std::string dcapsItem;
        RELEASE_IF_FALSE(in.ReadString(dcapsItem), nativeTokenInfoParcel);
        nativeTokenInfoParcel->nativeTokenInfoParams.dcap.emplace_back(dcapsItem);
    }

    uint32_t nativeAclSize;
    RELEASE_IF_FALSE(in.ReadUint32(nativeAclSize), nativeTokenInfoParcel);
    RELEASE_IF_FALSE(nativeAclSize <= MAX_ACL_SIZE, nativeTokenInfoParcel);

    for (uint32_t i = 0; i < nativeAclSize; i++) {
        std::string item;
        RELEASE_IF_FALSE(in.ReadString(item), nativeTokenInfoParcel);
        nativeTokenInfoParcel->nativeTokenInfoParams.nativeAcls.emplace_back(item);
    }
    return nativeTokenInfoParcel;
}
} // namespace AccessToken
} // namespace Security
} // namespace OHOS
