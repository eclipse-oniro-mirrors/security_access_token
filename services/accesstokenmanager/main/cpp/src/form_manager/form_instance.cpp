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
#include "accesstoken_common_log.h"
#include "string_ex.h"

namespace OHOS {
namespace Security {
namespace AccessToken {

bool FormInstance::ReadFromParcel(Parcel &parcel)
{
    if (!parcel.ReadInt64(formId_)) {
        LOGE(ATM_DOMAIN, ATM_TAG, "ReadInt64 failed.");
        return false;
    }

    std::u16string u16FormHostName;
    if (!parcel.ReadString16(u16FormHostName)) {
        LOGE(ATM_DOMAIN, ATM_TAG, "ReadString16 failed.");
        return false;
    }
    formHostName_ = Str16ToStr8(u16FormHostName);

    int32_t formVisiblity;
    if ((!parcel.ReadInt32(formVisiblity)) || (!parcel.ReadInt32(specification_))) {
        LOGE(ATM_DOMAIN, ATM_TAG, "ReadInt32 failed.");
        return false;
    }
    formVisiblity_ = static_cast<FormVisibilityType>(formVisiblity);

    std::u16string u16BundleName;
    std::u16string u16ModuleName;
    std::u16string u16AbilityName;
    std::u16string u16FormName;
    if (!parcel.ReadString16(u16BundleName) || (!parcel.ReadString16(u16ModuleName)) ||
        (!parcel.ReadString16(u16AbilityName)) || (!parcel.ReadString16(u16FormName))) {
        LOGE(ATM_DOMAIN, ATM_TAG, "ReadString16 failed.");
        return false;
    }
    bundleName_ = Str16ToStr8(u16BundleName);
    moduleName_ = Str16ToStr8(u16ModuleName);
    abilityName_ = Str16ToStr8(u16AbilityName);
    formName_ = Str16ToStr8(u16FormName);

    int32_t formUsageState;
    if (!parcel.ReadInt32(formUsageState)) {
        LOGE(ATM_DOMAIN, ATM_TAG, "ReadInt32 failed.");
        return false;
    }
    formUsageState_ = static_cast<FormUsageState>(formUsageState);
    std::u16string u16description;
    if (!parcel.ReadString16(u16description)) {
        LOGE(ATM_DOMAIN, ATM_TAG, "ReadString16 failed.");
        return false;
    }
    description_ = Str16ToStr8(u16description);

    if ((!parcel.ReadInt32(appIndex_)) || (!parcel.ReadInt32(userId_))) {
        LOGE(ATM_DOMAIN, ATM_TAG, "ReadInt32 failed.");
        return false;
    }

    return true;
}

bool FormInstance::Marshalling(Parcel &parcel) const
{
    if (!parcel.WriteInt64(formId_)) {
        LOGE(ATM_DOMAIN, ATM_TAG, "WriteInt64 failed.");
        return false;
    }

    if (!parcel.WriteString16(Str8ToStr16(formHostName_))) {
        LOGE(ATM_DOMAIN, ATM_TAG, "WriteString16 failed.");
        return false;
    }

    if ((!parcel.WriteInt32(static_cast<int32_t>(formVisiblity_))) || (!parcel.WriteInt32(specification_))) {
        LOGE(ATM_DOMAIN, ATM_TAG, "WriteInt32 failed.");
        return false;
    }

    if ((!parcel.WriteString16(Str8ToStr16(bundleName_))) || (!parcel.WriteString16(Str8ToStr16(moduleName_))) ||
        (!parcel.WriteString16(Str8ToStr16(abilityName_))) || (!parcel.WriteString16(Str8ToStr16(formName_)))) {
        LOGE(ATM_DOMAIN, ATM_TAG, "WriteString16 failed.");
        return false;
    }

    if (!parcel.WriteInt32(static_cast<int32_t>(formUsageState_))) {
        LOGE(ATM_DOMAIN, ATM_TAG, "WriteInt32 failed.");
        return false;
    }
    if (!parcel.WriteString16(Str8ToStr16(description_))) {
        LOGE(ATM_DOMAIN, ATM_TAG, "WriteString16 failed.");
        return false;
    }

    if (!parcel.WriteInt32(appIndex_)) {
        LOGE(ATM_DOMAIN, ATM_TAG, "WriteInt32 failed.");
        return false;
    }

    if (!parcel.WriteInt32(userId_)) {
        LOGE(ATM_DOMAIN, ATM_TAG, "WriteInt32 failed.");
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
