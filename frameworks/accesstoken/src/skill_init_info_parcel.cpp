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

#include "skill_init_info_parcel.h"

#include <new>

#include "parcel_utils.h"

namespace OHOS {
namespace Security {
namespace AccessToken {
bool SkillInitInfoParcel::Marshalling(Parcel& out) const
{
    RETURN_IF_FALSE(out.WriteUint32(skillInitInfo.hostTokenId));
    RETURN_IF_FALSE(out.WriteString(skillInitInfo.challenge));
    RETURN_IF_FALSE(out.WriteString(skillInitInfo.skillInfo.skillName));
    RETURN_IF_FALSE(out.WriteString(skillInitInfo.skillInfo.bundleName));
    RETURN_IF_FALSE(out.WriteString(skillInitInfo.skillInfo.moduleName));
    return true;
}

SkillInitInfoParcel* SkillInitInfoParcel::Unmarshalling(Parcel& in)
{
    auto* parcel = new (std::nothrow) SkillInitInfoParcel();
    if (parcel == nullptr) {
        return nullptr;
    }
    RELEASE_IF_FALSE(in.ReadUint32(parcel->skillInitInfo.hostTokenId), parcel);
    RELEASE_IF_FALSE(in.ReadString(parcel->skillInitInfo.challenge), parcel);
    RELEASE_IF_FALSE(in.ReadString(parcel->skillInitInfo.skillInfo.skillName), parcel);
    RELEASE_IF_FALSE(in.ReadString(parcel->skillInitInfo.skillInfo.bundleName), parcel);
    RELEASE_IF_FALSE(in.ReadString(parcel->skillInitInfo.skillInfo.moduleName), parcel);
    return parcel;
}
} // namespace AccessToken
} // namespace Security
} // namespace OHOS
