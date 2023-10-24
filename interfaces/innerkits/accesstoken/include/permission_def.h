/*
 * Copyright (c) 2021-2023 Huawei Device Co., Ltd.
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
 * @addtogroup AccessToken
 * @{
 *
 * @brief Provides permission management interfaces.
 *
 * Provides tokenID-based application permission verification mechanism.
 * When an application accesses sensitive data or APIs, this module can check
 * whether the application has the corresponding permission. Allows applications
 * to query their access token information or APL levcels based on token IDs.
 *
 * @since 7.0
 * @version 7.0
 */

/**
 * @file permission_def.h
 *
 * @brief Declares permission definition.
 *
 * @since 7.0
 * @version 7.0
 */

#ifndef INTERFACES_INNER_KITS_ACCESSTOKEN_PERMISSION_DEF_H
#define INTERFACES_INNER_KITS_ACCESSTOKEN_PERMISSION_DEF_H

#include <string>

#include "access_token.h"

namespace OHOS {
namespace Security {
namespace AccessToken {
/**
 * @brief Declares permission definition class
 */
class PermissionDef final {
public:
    /** permission name */
    std::string permissionName;
    /** bundle name */
    std::string bundleName = "";
    /**
     * grant mode, for details about the valid values,
     * see the definition of GrantMode in the access_token.h file.
     */
    int grantMode;
    /** which SDK version can use this permission to develop app */
    ATokenAplEnum availableLevel;
    /** indicats whether this permission can be access control list permission */
    bool provisionEnable;
    /**
     * indicates whether the distributed scene can use this permission or not
     */
    bool distributedSceneEnable;
    std::string label = "";
    int labelId = 0;
    std::string description = "";
    int descriptionId = 0;
    ATokenAvailableTypeEnum availableType = NORMAL;
};

/**
 * @brief Declares permission definition data class
 */
class PermissionDefData final {
public:
    AccessTokenID tokenId;
    PermissionDef permDef;
};
} // namespace AccessToken
} // namespace Security
} // namespace OHOS

#endif // INTERFACES_INNER_KITS_ACCESSTOKEN_PERMISSION_DEF_H
