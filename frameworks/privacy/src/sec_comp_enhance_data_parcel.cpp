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

#include "sec_comp_enhance_data_parcel.h"
#include "parcel_utils.h"

namespace OHOS {
namespace Security {
namespace AccessToken {
bool SecCompEnhanceDataParcel::Marshalling(Parcel& out) const
{
    RETURN_IF_FALSE(out.WriteInt32(this->enhanceData.pid));
    RETURN_IF_FALSE(out.WriteUint32(this->enhanceData.token));
    RETURN_IF_FALSE(out.WriteUint64(this->enhanceData.challenge));
    RETURN_IF_FALSE(out.WriteInt32(this->enhanceData.sessionId));
    RETURN_IF_FALSE(out.WriteInt32(this->enhanceData.seqNum));
    RETURN_IF_FALSE((static_cast<MessageParcel*>(&out))->WriteRemoteObject(this->enhanceData.callback));
    return true;
}

SecCompEnhanceDataParcel* SecCompEnhanceDataParcel::Unmarshalling(Parcel& in)
{
    auto* enhanceDataParcel = new (std::nothrow) SecCompEnhanceDataParcel();
    if (enhanceDataParcel == nullptr) {
        return nullptr;
    }

    RELEASE_IF_FALSE(in.ReadInt32(enhanceDataParcel->enhanceData.pid), enhanceDataParcel);
    RELEASE_IF_FALSE(in.ReadUint32(enhanceDataParcel->enhanceData.token), enhanceDataParcel);
    RELEASE_IF_FALSE(in.ReadUint64(enhanceDataParcel->enhanceData.challenge), enhanceDataParcel);
    RELEASE_IF_FALSE(in.ReadInt32(enhanceDataParcel->enhanceData.sessionId), enhanceDataParcel);
    RELEASE_IF_FALSE(in.ReadInt32(enhanceDataParcel->enhanceData.seqNum), enhanceDataParcel);

    enhanceDataParcel->enhanceData.callback = (static_cast<MessageParcel*>(&in))->ReadRemoteObject();
    if (enhanceDataParcel->enhanceData.callback == nullptr) {
        delete enhanceDataParcel;
        return nullptr;
    }

    return enhanceDataParcel;
}
} // namespace AccessToken
} // namespace Security
} // namespace OHOS

