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

#include "running_form_info.h"
#include "accesstoken_log.h"
#include "string_ex.h"

namespace OHOS {
namespace Security {
namespace AccessToken {
namespace {
static constexpr OHOS::HiviewDFX::HiLogLabel LABEL = {
    LOG_CORE, SECURITY_DOMAIN_ACCESSTOKEN, "RunningFormInfo"
};
}
bool RunningFormInfo::ReadFromParcel(Parcel &parcel)
{
    if (!parcel.ReadInt64(formId_)) {
        ACCESSTOKEN_LOG_ERROR(LABEL, "WriteString16 failed.");
        return false;
    }
    std::u16string u16FormName;
    std::u16string u16BundleName;
    std::u16string u16ModuleName;
    std::u16string u16AbilityName;
    if ((!parcel.ReadString16(u16FormName)) || (!parcel.ReadString16(u16BundleName)) ||
        (!parcel.ReadString16(u16ModuleName)) || (!parcel.ReadString16(u16AbilityName))) {
        ACCESSTOKEN_LOG_ERROR(LABEL, "ReadString16 failed.");
        return false;
    }
    formName_ = Str16ToStr8(u16FormName);
    bundleName_ = Str16ToStr8(u16BundleName);
    moduleName_ = Str16ToStr8(u16ModuleName);
    abilityName_ = Str16ToStr8(u16AbilityName);

    if (!parcel.ReadString(description_)) {
        ACCESSTOKEN_LOG_ERROR(LABEL, "ReadString failed.");
        return false;
    }

    if (!parcel.ReadInt32(dimension_)) {
        ACCESSTOKEN_LOG_ERROR(LABEL, "ReadInt32 failed.");
        return false;
    }

    std::u16string u16HostBundleName;
    if (!parcel.ReadString16(u16HostBundleName)) {
        ACCESSTOKEN_LOG_ERROR(LABEL, "ReadString16 failed.");
        return false;
    }
    hostBundleName_ = Str16ToStr8(u16HostBundleName);

    int32_t formVisiblity;
    int32_t formUsageState;
    int32_t formLocation;
    if ((!parcel.ReadInt32(formVisiblity)) || (!parcel.ReadInt32(formUsageState)) ||
        (!parcel.ReadInt32(formLocation))) {
        ACCESSTOKEN_LOG_ERROR(LABEL, "ReadInt32 failed.");
        return false;
    }
    formVisiblity_ = static_cast<FormVisibilityType>(formVisiblity);
    formUsageState_ = static_cast<FormUsageState>(formUsageState);
    formLocation_ = static_cast<FormLocation>(formLocation);
    return true;
}

bool RunningFormInfo::Marshalling(Parcel &parcel) const
{
    if (!parcel.WriteInt64(formId_)) {
        ACCESSTOKEN_LOG_ERROR(LABEL, "WriteInt64 failed.");
        return false;
    }

    if (!parcel.WriteString16(Str8ToStr16(formName_))) {
        ACCESSTOKEN_LOG_ERROR(LABEL, "WriteString16 failed.");
        return false;
    }

    if (!parcel.WriteString16(Str8ToStr16(bundleName_))) {
        ACCESSTOKEN_LOG_ERROR(LABEL, "WriteString16 failed.");
        return false;
    }

    if (!parcel.WriteString16(Str8ToStr16(moduleName_))) {
        ACCESSTOKEN_LOG_ERROR(LABEL, "WriteString16 failed.");
        return false;
    }

    if (!parcel.WriteString16(Str8ToStr16(abilityName_))) {
        ACCESSTOKEN_LOG_ERROR(LABEL, "WriteString16 failed.");
        return false;
    }

    if (!parcel.WriteString(description_)) {
        ACCESSTOKEN_LOG_ERROR(LABEL, "WriteString failed.");
        return false;
    }

    if (!parcel.WriteInt32(dimension_)) {
        ACCESSTOKEN_LOG_ERROR(LABEL, "WriteInt32 failed.");
        return false;
    }

    if (!parcel.WriteString16(Str8ToStr16(hostBundleName_))) {
        ACCESSTOKEN_LOG_ERROR(LABEL, "WriteString16 failed.");
        return false;
    }

    if (!parcel.WriteInt32((int32_t)formVisiblity_)) {
        ACCESSTOKEN_LOG_ERROR(LABEL, "WriteInt32 failed.");
        return false;
    }

    if (!parcel.WriteInt32(static_cast<int32_t>(formUsageState_))) {
        ACCESSTOKEN_LOG_ERROR(LABEL, "WriteInt32 failed.");
        return false;
    }

    if (!parcel.WriteInt32(static_cast<int32_t>(formLocation_))) {
        ACCESSTOKEN_LOG_ERROR(LABEL, "WriteInt32 failed.");
        return false;
    }
    return true;
}

RunningFormInfo* RunningFormInfo::Unmarshalling(Parcel &parcel)
{
    std::unique_ptr<RunningFormInfo> object = std::make_unique<RunningFormInfo>();
    if (object && !object->ReadFromParcel(parcel)) {
        object = nullptr;
        return nullptr;
    }
    return object.release();
}
} // namespace AccessToken
} // namespace Security
} // namespace OHOS