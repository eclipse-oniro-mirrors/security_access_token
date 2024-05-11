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

#ifndef ACCESS_FORM_INSTANCE_H
#define ACCESS_FORM_INSTANCE_H

#include <sys/types.h>

#include "parcel.h"
#include "iremote_object.h"

namespace OHOS {
namespace Security {
namespace AccessToken {
enum class FormUsageState {
    USED = 0,
    UNUSED,
};

enum class FormVisibilityType {
    UNKNOWN = 0,
    VISIBLE,
    INVISIBLE,
};

enum class FormLocation : int8_t {
    OTHER = -1,
    DESKTOP = 0,
    FORM_CENTER = 1,
    FORM_MANAGER = 2,
    NEGATIVE_SCREEN = 3,
    FORM_CENTER_NEGATIVE_SCREEN = 4,
    FORM_MANAGER_NEGATIVE_SCREEN = 5,
    SCREEN_LOCK = 6,
    AI_SUGGESTION = 7,
};

struct FormInstance : public Parcelable {
    int64_t formId_ = 0;
    std::string formHostName_ = "";
    FormVisibilityType formVisiblity_ = FormVisibilityType::UNKNOWN;
    int32_t specification_ = 0;
    std::string bundleName_ = "";
    std::string moduleName_ = "";
    std::string abilityName_ = "";
    std::string formName_ = "";
    FormUsageState formUsageState_ = FormUsageState::USED;
    std::string description_;

    bool ReadFromParcel(Parcel &parcel);
    bool Marshalling(Parcel &parcel) const override;
    static FormInstance *Unmarshalling(Parcel &parcel);
};
}  // namespace AccessToken
}  // namespace Security
}  // namespace OHOS

#endif  // ACCESS_FORM_INSTANCE_H
