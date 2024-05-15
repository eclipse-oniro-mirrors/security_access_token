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

#ifndef ACCESS_RUNNING_FORM_INFO_H
#define ACCESS_RUNNING_FORM_INFO_H

#include <singleton.h>
#include <string>

#include "form_instance.h"
#include "parcel.h"
#include "iremote_object.h"

namespace OHOS {
namespace Security {
namespace AccessToken {
/**
 * @struct RunningFormInfo
 * Defines running form info.
 */
struct RunningFormInfo : public Parcelable {
    int64_t formId_;
    std::string formName_;
    std::string bundleName_;
    std::string moduleName_;
    std::string abilityName_;
    std::string description_;
    int32_t dimension_;
    std::string hostBundleName_;
    FormLocation formLocation_;
    FormVisibilityType formVisiblity_ = FormVisibilityType::UNKNOWN;
    FormUsageState formUsageState_ = FormUsageState::USED;

    bool ReadFromParcel(Parcel &parcel);
    bool Marshalling(Parcel &parcel) const override;
    static RunningFormInfo *Unmarshalling(Parcel &parcel);
};
} // namespace AccessToken
} // namespace Security
} // namespace OHOS
#endif // ACCESS_RUNNING_FORM_INFO_H
