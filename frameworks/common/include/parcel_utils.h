/*
 * Copyright (c) 2021-2022 Huawei Device Co., Ltd.
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

#ifndef PARCEL_UTILS_H
#define PARCEL_UTILS_H

#define MAX_PERMLIST_SIZE 1024
#define MAX_DCAP_SIZE 32
#define MAX_ACL_SIZE 64
#define MAX_DEVICE_ID_SIZE 1024
#define MAX_RECORD_SIZE 1024
#define MAX_ACCESS_RECORD_SIZE 10

namespace OHOS {
namespace Security {
namespace AccessToken {
#define RETURN_IF_FALSE(expr) \
    if (!(expr)) { \
        return false; \
    }

#define RELEASE_IF_FALSE(expr, obj) \
    if (!(expr)) { \
        delete (obj); \
        (obj) = nullptr; \
        return (obj); \
    }
} // namespace AccessToken
} // namespace Security
} // namespace OHOS
#endif // PARCEL_UTILS_H
