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

#ifndef DATA_TRANSLATOR_H
#define DATA_TRANSLATOR_H

#include <string>

#include "generic_values.h"
#include "permission_def.h"
#include "permission_status.h"
#include "hap_token_info.h"

namespace OHOS {
namespace Security {
namespace AccessToken {
class DataTranslator final {
public:
    static int TranslationIntoGenericValues(const PermissionDef& inPermissionDef, GenericValues& outGenericValues);
    static int TranslationIntoPermissionDef(const GenericValues& inGenericValues, PermissionDef& outPermissionDef);
    static int TranslationIntoGenericValues(const PermissionStatus& inPermissionState,
        GenericValues& outGenericValues);
    static int TranslationIntoPermissionStatus(const GenericValues& inGenericValues,
        PermissionStatus& outPermissionState);
    static int32_t TranslationIntoExtendedPermission(const GenericValues& inGenericValues, PermissionWithValue& perm);
};
} // namespace AccessToken
} // namespace Security
} // namespace OHOS
#endif // DATA_TRANSLATOR_H
