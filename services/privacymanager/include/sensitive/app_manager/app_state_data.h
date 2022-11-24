/*
 * Copyright (c) 2022 Huawei Device Co., Ltd.
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

#ifndef OHOS_PRIVACY_APP_STATE_DATA_H
#define OHOS_PRIVACY_APP_STATE_DATA_H

#include <sys/types.h>

#include "parcel.h"
#include "iremote_object.h"

namespace OHOS {
namespace Security {
namespace AccessToken {
enum class ApplicationState {
    APP_STATE_BEGIN = 0,
    APP_STATE_CREATE = APP_STATE_BEGIN,
    APP_STATE_READY,
    APP_STATE_FOREGROUND,
    APP_STATE_FOCUS,
    APP_STATE_BACKGROUND,
    APP_STATE_TERMINATED,
    APP_STATE_END,
};
struct AppStateData : public Parcelable {
    virtual bool Marshalling(Parcel &parcel) const override;
    static AppStateData *Unmarshalling(Parcel &parcel);

    std::string bundleName;
    int32_t pid = -1;
    int32_t uid = 0;
    int32_t state = 0;
    int32_t accessTokenId = 0;
    bool isFocused = false;
};
}  // namespace AccessToken
}  // namespace Security
}  // namespace OHOS

#endif  // OHOS_PRIVACY_APP_STATE_DATA_H
