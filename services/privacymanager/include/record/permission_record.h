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

#ifndef PERMISSION_RECORD_H
#define PERMISSION_RECORD_H

#include "generic_values.h"

namespace OHOS {
namespace Security {
namespace AccessToken {
struct PermissionRecord {
    uint32_t tokenId = 0;
    int32_t opCode = 0;
    int32_t status = 0;
    int64_t timestamp = 0L;
    int64_t accessDuration = 0L;
    int32_t accessCount = 0;
    int32_t rejectCount = 0;

    PermissionRecord() = default;

    static void TranslationIntoGenericValues(const PermissionRecord& record, GenericValues& values);
    static void TranslationIntoPermissionRecord(const GenericValues& values, PermissionRecord& record);
};
} // namespace AccessToken
} // namespace Security
} // namespace OHOS
#endif // PERMISSION_RECORD_H
