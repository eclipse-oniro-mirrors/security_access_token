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

#ifndef EL5FILEKEYMANAGER_INCLUDE_APP_KEY_LOAD_INFO_H
#define EL5FILEKEYMANAGER_INCLUDE_APP_KEY_LOAD_INFO_H

#include <vector>

#include "message_parcel.h"
#include "iremote_broker.h"

namespace OHOS {
namespace Security {
namespace AccessToken {
struct AppKeyLoadInfo : public Parcelable {
    std::string first;
    bool second = false;

    AppKeyLoadInfo() {}
    AppKeyLoadInfo(std::string &first, bool second) : first(first), second(second) {}

    bool Marshalling(Parcel &parcel) const override;
    static AppKeyLoadInfo *Unmarshalling(Parcel &parcel);
};
}  // namespace AccessToken
}  // namespace Security
}  // namespace OHOS
#endif // EL5FILEKEYMANAGER_INCLUDE_APP_KEY_LOAD_INFO_H
