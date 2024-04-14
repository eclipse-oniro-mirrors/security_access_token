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

#ifndef SECURITY_ACCESSTOKEN_PERMISSION_USED_TYPE_H
#define SECURITY_ACCESSTOKEN_PERMISSION_USED_TYPE_H

namespace OHOS {
namespace Security {
namespace AccessToken {
/**
 * @brief Permission permission used type values
 */
typedef enum PermissionUsedTypeValue {
    /** invalid type */
    INVALID_USED_TYPE = -1,
    /** normal type for permision request */
    NORMAL_TYPE,
    /** picker type for permision request */
    PICKER_TYPE,
    /** security component type for permision request */
    SECURITY_COMPONENT_TYPE,
    /** max of type for no use */
    PERM_USED_TYPE_BUTT,
} PermissionUsedType;
} // namespace AccessToken
} // namespace Security
} // namespace OHOS

#endif // SECURITY_ACCESSTOKEN_PERMISSION_USED_TYPE_H