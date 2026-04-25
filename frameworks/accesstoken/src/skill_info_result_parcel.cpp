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

#include "skill_info_result_parcel.h"

#include <new>

#include "parcel_utils.h"

namespace OHOS {
namespace Security {
namespace AccessToken {
bool SkillInfoResultParcel::Marshalling(Parcel& out) const
{
    RETURN_IF_FALSE(out.WriteUint32(skillTokenInfo.hostTokenId));
    RETURN_IF_FALSE(out.WriteInt32(skillTokenInfo.userId));
    RETURN_IF_FALSE(out.WriteString(skillTokenInfo.skillName));
    RETURN_IF_FALSE(out.WriteString(skillTokenInfo.bundleName));
    RETURN_IF_FALSE(out.WriteString(skillTokenInfo.moduleName));
    return true;
}

SkillInfoResultParcel* SkillInfoResultParcel::Unmarshalling(Parcel& in)
{
    auto* parcel = new (std::nothrow) SkillInfoResultParcel();
    if (parcel == nullptr) {
        return nullptr;
    }
    RELEASE_IF_FALSE(in.ReadUint32(parcel->skillTokenInfo.hostTokenId), parcel);
    RELEASE_IF_FALSE(in.ReadInt32(parcel->skillTokenInfo.userId), parcel);
    RELEASE_IF_FALSE(in.ReadString(parcel->skillTokenInfo.skillName), parcel);
    RELEASE_IF_FALSE(in.ReadString(parcel->skillTokenInfo.bundleName), parcel);
    RELEASE_IF_FALSE(in.ReadString(parcel->skillTokenInfo.moduleName), parcel);
    return parcel;
}
} // namespace AccessToken
} // namespace Security
} // namespace OHOS
