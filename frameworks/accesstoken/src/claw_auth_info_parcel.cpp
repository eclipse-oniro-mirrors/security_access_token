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

#include "claw_auth_info_parcel.h"

#include <memory>

#include "cli_info_parcel.h"
#include "parcel_utils.h"
#include "skill_info_parcel.h"

namespace OHOS {
namespace Security {
namespace AccessToken {
namespace {
bool WriteCliAuthInfo(Parcel& out, const CliAuthInfo& info)
{
    CliInfoParcel cliInfoParcel;
    cliInfoParcel.cliInfo = info.cliInfo;
    RETURN_IF_FALSE(cliInfoParcel.Marshalling(out));
    RETURN_IF_FALSE(out.WriteStringVector(info.permissionNames));
    RETURN_IF_FALSE(out.WriteBoolVector(info.authorizationResults));
    return true;
}

bool WriteSkillAuthInfo(Parcel& out, const SkillAuthInfo& info)
{
    SkillInfoParcel skillInfoParcel;
    skillInfoParcel.skillInfo = info.skillInfo;
    RETURN_IF_FALSE(skillInfoParcel.Marshalling(out));
    RETURN_IF_FALSE(out.WriteStringVector(info.permissionNames));
    RETURN_IF_FALSE(out.WriteBoolVector(info.authorizationResults));
    return true;
}
}

bool CliAuthInfoParcel::Marshalling(Parcel& out) const
{
    return WriteCliAuthInfo(out, info);
}

CliAuthInfoParcel* CliAuthInfoParcel::Unmarshalling(Parcel& in)
{
    auto* parcel = new (std::nothrow) CliAuthInfoParcel();
    if (parcel == nullptr) {
        return nullptr;
    }
    std::unique_ptr<CliInfoParcel> cliInfoParcel(CliInfoParcel::Unmarshalling(in));
    RELEASE_IF_FALSE(cliInfoParcel != nullptr, parcel);
    parcel->info.cliInfo = cliInfoParcel->cliInfo;
    RELEASE_IF_FALSE(in.ReadStringVector(&parcel->info.permissionNames), parcel);
    RELEASE_IF_FALSE(in.ReadBoolVector(&parcel->info.authorizationResults), parcel);
    return parcel;
}

bool SkillAuthInfoParcel::Marshalling(Parcel& out) const
{
    return WriteSkillAuthInfo(out, info);
}

SkillAuthInfoParcel* SkillAuthInfoParcel::Unmarshalling(Parcel& in)
{
    auto* parcel = new (std::nothrow) SkillAuthInfoParcel();
    if (parcel == nullptr) {
        return nullptr;
    }
    std::unique_ptr<SkillInfoParcel> skillInfoParcel(SkillInfoParcel::Unmarshalling(in));
    RELEASE_IF_FALSE(skillInfoParcel != nullptr, parcel);
    parcel->info.skillInfo = skillInfoParcel->skillInfo;
    RELEASE_IF_FALSE(in.ReadStringVector(&parcel->info.permissionNames), parcel);
    RELEASE_IF_FALSE(in.ReadBoolVector(&parcel->info.authorizationResults), parcel);
    return parcel;
}
} // namespace AccessToken
} // namespace Security
} // namespace OHOS
