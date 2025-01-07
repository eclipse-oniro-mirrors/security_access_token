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

#include "app_key_info.h"
#include "parcel_utils.h"

namespace OHOS {
namespace Security {
namespace AccessToken {
bool AppKeyInfo::Marshalling(Parcel &parcel) const
{
    RETURN_IF_FALSE(parcel.WriteUint32(static_cast<uint32_t>(this->type)));
    RETURN_IF_FALSE(parcel.WriteUint32(this->uid));
    RETURN_IF_FALSE(parcel.WriteString(this->bundleName));
    RETURN_IF_FALSE(parcel.WriteInt32(this->userId));
    RETURN_IF_FALSE(parcel.WriteString(this->groupID));
    return true;
}

AppKeyInfo *AppKeyInfo::Unmarshalling(Parcel &parcel)
{
    AppKeyInfo *info = new (std::nothrow) AppKeyInfo();
    if (info == nullptr) {
        return nullptr;
    }

    uint32_t type;
    RELEASE_IF_FALSE(parcel.ReadUint32(type), info);
    info->type = static_cast<AppKeyType>(type);
    RELEASE_IF_FALSE(parcel.ReadUint32(info->uid), info);
    RELEASE_IF_FALSE(parcel.ReadString(info->bundleName), info);
    RELEASE_IF_FALSE(parcel.ReadInt32(info->userId), info);
    RELEASE_IF_FALSE(parcel.ReadString(info->groupID), info);
    return info;
}
}  // namespace AccessToken
}  // namespace Security
}  // namespace OHOS
