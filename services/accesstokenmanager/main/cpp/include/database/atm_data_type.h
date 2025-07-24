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

#ifndef ACCESS_TOKEN_ATM_DATA_TYPE_H
#define ACCESS_TOKEN_ATM_DATA_TYPE_H

#include "generic_values.h"

namespace OHOS {
namespace Security {
namespace AccessToken {
enum AtmDataType {
    ACCESSTOKEN_HAP_INFO,
    ACCESSTOKEN_NATIVE_INFO,
    ACCESSTOKEN_PERMISSION_DEF,
    ACCESSTOKEN_PERMISSION_STATE,
    ACCESSTOKEN_PERMISSION_REQUEST_TOGGLE_STATUS,
    ACCESSTOKEN_PERMISSION_EXTEND_VALUE,
    ACCESSTOKEN_HAP_UNDEFINE_INFO,
    ACCESSTOKEN_SYSTEM_CONFIG,
};

typedef struct TypeDelInfo {
    AtmDataType delType;
    GenericValues delValue;
} DelInfo;

typedef struct TypeAddInfo {
    AtmDataType addType;
    std::vector<GenericValues> addValues;
} AddInfo;
} // namespace AccessToken
} // namespace Security
} // namespace OHOS
#endif // ACCESS_TOKEN_ATM_DATA_TYPE_H
