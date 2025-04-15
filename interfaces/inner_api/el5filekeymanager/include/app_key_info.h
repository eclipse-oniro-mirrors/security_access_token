/*
 * Copyright (c) 2024-2025 Huawei Device Co., Ltd.
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

#ifndef EL5FILEKEYMANAGER_INCLUDE_APP_KEY_INFO_H
#define EL5FILEKEYMANAGER_INCLUDE_APP_KEY_INFO_H

#include <vector>

#include "message_parcel.h"
#include "iremote_broker.h"

namespace OHOS {
namespace Security {
namespace AccessToken {
enum AppKeyType {
    APP = 1,
    GROUPID,
};

struct AppKeyInfo : public Parcelable {
    AppKeyType type = AppKeyType::APP;
    uint32_t uid = 0;
    std::string bundleName;
    int32_t userId = -1;
    std::string groupID;

    AppKeyInfo() {}
    AppKeyInfo(AppKeyType type, uint32_t uid, const std::string &bundleName, int32_t userId,
        const std::string &groupID) : type(type), uid(uid), bundleName(bundleName), userId(userId), groupID(groupID) {}

    bool Marshalling(Parcel &parcel) const override;
    static AppKeyInfo *Unmarshalling(Parcel &parcel);
};
}  // namespace AccessToken
}  // namespace Security
}  // namespace OHOS
#endif // EL5FILEKEYMANAGER_INCLUDE_APP_KEY_INFO_H
