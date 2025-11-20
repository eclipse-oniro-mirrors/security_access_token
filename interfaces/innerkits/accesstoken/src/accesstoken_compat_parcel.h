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

#ifndef ACCESSTOKEN_COMPAT_PARCEL_H
#define ACCESSTOKEN_COMPAT_PARCEL_H
#include <string>
#include <iremote_proxy.h>

namespace OHOS {
namespace Security {
namespace AccessToken {
struct HapTokenInfoCompatParcel {
    std::string bundleName;
    int32_t userID;
    int32_t instIndex;
    int32_t apiVersion;
};
int32_t HapTokenInfoCompatUnmarshalling(OHOS::MessageParcel& data, HapTokenInfoCompatParcel& dataBlock);
} // namespace AccessToken
} // namespace Security
} // namespace OHOS

#endif // ACCESSTOKEN_COMPAT_PARCEL_H

