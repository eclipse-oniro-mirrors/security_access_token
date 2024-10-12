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

/**
 * @addtogroup Privacy
 * @{
 *
 * @brief Provides sensitive data access management.
 *
 * @since 8.0
 * @version 8.0
 */

/**
 * @file permission_used_type.h
 *
 * @brief Declares enum PermissionUsedType.
 *
 * @since 12.0
 * @version 12.0
 */

#ifndef PRIVACY_PARAM_H
#define PRIVACY_PARAM_H

#include <string>
#include <vector>

namespace OHOS {
namespace Security {
namespace AccessToken {
/**
 * @brief policy type
 */
enum PolicyType {
    EDM = 0,
    PRIVACY = 1,
    TEMPORARY = 2,
    MIXED = 3
};

/**
 * @brief caller type
 */
enum CallerType {
    MICROPHONE = 0,
    CAMERA = 1
};
} // namespace AccessToken
} // namespace Security
} // namespace OHOS
#endif // PRIVACY_PARAM_H
