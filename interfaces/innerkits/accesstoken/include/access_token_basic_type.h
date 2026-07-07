/*
 * Copyright (c) 2026 Huawei Device Co., Ltd.
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

#ifndef ACCESS_TOKEN_BASIC_TYPE_H
#define ACCESS_TOKEN_BASIC_TYPE_H

#include <cstdint>

namespace OHOS {
namespace Security {
namespace AccessToken {
typedef unsigned int AccessTokenID;
typedef uint64_t FullTokenID;
typedef unsigned int AccessTokenAttr;
constexpr const int DEFAULT_TOKEN_VERSION = 1;
constexpr const AccessTokenID INVALID_TOKENID = 0;

/**
 * @brief AccessTokenID 32 bits map
 */
typedef struct {
    unsigned int tokenUniqueID : 20;
    unsigned int toolFlag : 1;
    /** reserved, default 00 */
    unsigned int res : 2;
    unsigned int type_ext : 1;
    unsigned int cloneFlag : 1;
    /** renderflag, default 0 */
    unsigned int renderFlag : 1;
    unsigned int dlpFlag : 1;
    /**
     * token type, for details about the valid values,
     * see the definition of ATokenTypeEnum in the access_token.h file.
     */
    unsigned int type : 2;
    /** version, default 001 */
    unsigned int version : 3;
} AccessTokenIDInner;

/**
 * @brief Token id type
 */
typedef enum TypeATokenTypeEnum {
    TOKEN_INVALID = -1,
    TOKEN_HAP = 0,
    TOKEN_NATIVE,
    TOKEN_SHELL,
    TOKEN_TYPE_BUTT,
} ATokenTypeEnum;

/**
 * @brief Permission states
 */
typedef enum TypePermissionState {
    PERMISSION_DENIED = -1,
    PERMISSION_GRANTED = 0,
} PermissionState;
} // namespace AccessToken
} // namespace Security
} // namespace OHOS

#endif // ACCESS_TOKEN_BASIC_TYPE_H
