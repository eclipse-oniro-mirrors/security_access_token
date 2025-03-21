/*
 * Copyright (c) 2025 Huawei Device Co., Ltd.
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

#include "app_key_load_info.h"
#include "parcel_utils.h"

namespace OHOS {
namespace Security {
namespace AccessToken {
bool AppKeyLoadInfo::Marshalling(Parcel &parcel) const
{
    RETURN_IF_FALSE(parcel.WriteString(this->first));
    RETURN_IF_FALSE(parcel.WriteBool(this->second));
    return true;
}

AppKeyLoadInfo *AppKeyLoadInfo::Unmarshalling(Parcel &parcel)
{
    AppKeyLoadInfo *info = new (std::nothrow) AppKeyLoadInfo();
    if (info == nullptr) {
        return nullptr;
    }

    RELEASE_IF_FALSE(parcel.ReadString(info->first), info);
    RELEASE_IF_FALSE(parcel.ReadBool(info->second), info);
    return info;
}
}  // namespace AccessToken
}  // namespace Security
}  // namespace OHOS
