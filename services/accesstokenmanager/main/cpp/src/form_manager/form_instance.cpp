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

#include "form_instance.h"
#include "accesstoken_log.h"
#include "string_ex.h"

namespace OHOS {
namespace Security {
namespace AccessToken {
namespace {
static constexpr OHOS::HiviewDFX::HiLogLabel LABEL = {
    LOG_CORE, SECURITY_DOMAIN_ACCESSTOKEN, "FormInstance"
};
}
bool FormInstance::ReadFromParcel(Parcel &parcel)
{
    if (!parcel.ReadInt64(formId_)) {
        ACCESSTOKEN_LOG_ERROR(LABEL, "ReadInt64 failed.");
        return false;
    }

    std::u16string u16FormHostName;
    if (!parcel.ReadString16(u16FormHostName)) {
        ACCESSTOKEN_LOG_ERROR(LABEL, "ReadString16 failed.");
        return false;
    }
    formHostName_ = Str16ToStr8(u16FormHostName);

    int32_t formVisiblity;
    if (!parcel.ReadInt32(formVisiblity)) {
        ACCESSTOKEN_LOG_ERROR(LABEL, "ReadInt32 failed.");
        return false;
    }
    formVisiblity_ = static_cast<FormVisibilityType>(formVisiblity);
    if (!parcel.ReadInt32(specification_)) {
        ACCESSTOKEN_LOG_ERROR(LABEL, "ReadInt32 failed.");
        return false;
    }

    std::u16string u16BundleName;
    std::u16string u16ModuleName;
    std::u16string u16AbilityName;
    std::u16string u16FormName;
    if (!parcel.ReadString16(u16BundleName) || (!parcel.ReadString16(u16ModuleName)) ||
        (!parcel.ReadString16(u16AbilityName)) || (!parcel.ReadString16(u16FormName))) {
        ACCESSTOKEN_LOG_ERROR(LABEL, "ReadString16 failed.");
        return false;
    }
    bundleName_ = Str16ToStr8(u16BundleName);
    moduleName_ = Str16ToStr8(u16ModuleName);
    abilityName_ = Str16ToStr8(u16AbilityName);
    formName_ = Str16ToStr8(u16FormName);

    int32_t formUsageState;
    if (!parcel.ReadInt32(formUsageState)) {
        ACCESSTOKEN_LOG_ERROR(LABEL, "ReadInt32 failed.");
        return false;
    }
    formUsageState_ = static_cast<FormUsageState>(formUsageState);
    return true;
}

bool FormInstance::Marshalling(Parcel &parcel) const
{
    if (!parcel.WriteInt64(formId_)) {
        ACCESSTOKEN_LOG_ERROR(LABEL, "WriteInt64 failed.");
        return false;
    }

    if (!parcel.WriteString16(Str8ToStr16(formHostName_))) {
        ACCESSTOKEN_LOG_ERROR(LABEL, "WriteString16 failed.");
        return false;
    }

    if (!parcel.WriteInt32(static_cast<int32_t>(formVisiblity_))) {
        ACCESSTOKEN_LOG_ERROR(LABEL, "WriteInt32 failed.");
        return false;
    }

    if (!parcel.WriteInt32(specification_)) {
        ACCESSTOKEN_LOG_ERROR(LABEL, "WriteInt32 failed.");
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

    if (!parcel.WriteString16(Str8ToStr16(formName_))) {
        ACCESSTOKEN_LOG_ERROR(LABEL, "WriteString16 failed.");
        return false;
    }

    if (!parcel.WriteInt32(static_cast<int32_t>(formUsageState_))) {
        ACCESSTOKEN_LOG_ERROR(LABEL, "WriteInt32 failed.");
        return false;
    }
    return true;
}

FormInstance* FormInstance::Unmarshalling(Parcel &parcel)
{
    std::unique_ptr<FormInstance> object = std::make_unique<FormInstance>();
    if (object && !object->ReadFromParcel(parcel)) {
        object = nullptr;
        return nullptr;
    }
    return object.release();
}
}  // namespace AccessToken
}  // namespace Security
}  // namespace OHOS
