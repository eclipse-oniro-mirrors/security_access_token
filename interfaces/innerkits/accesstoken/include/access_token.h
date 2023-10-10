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
 * @file access_token.h
 *
 * @brief Declares typedefs, enums and const values.
 *
 * @since 7.0
 * @version 7.0
 */

#ifndef ACCESS_TOKEN_H
#define ACCESS_TOKEN_H

#include <string>

namespace OHOS {
namespace Security {
namespace AccessToken {
typedef unsigned int AccessTokenID;
typedef uint64_t FullTokenID;
typedef unsigned int AccessTokenAttr;
static const int DEFAULT_TOKEN_VERSION = 1;
static const AccessTokenID INVALID_TOKENID = 0;

/**
 * @brief Access token kit return code
 */
enum AccessTokenKitRet {
    RET_FAILED = -1,
    RET_SUCCESS = 0,
};

/**
 * @brief AccessTokenID 32 bits map
 */
typedef struct {
    unsigned int tokenUniqueID : 20;
    /** reserved, default 00000 */
    unsigned int res : 5;
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
 * @brief Apl level
 */
typedef enum TypeATokenAplEnum {
    APL_INVALID = 0,
    APL_NORMAL = 1,
    APL_SYSTEM_BASIC = 2,
    APL_SYSTEM_CORE = 3,
} ATokenAplEnum;

/**
 * @brief Token id full definition
 */
typedef union {
    unsigned long long tokenIDEx;
    struct {
        AccessTokenID tokenID;
        /** tokenID attribute */
        AccessTokenAttr tokenAttr;
    } tokenIdExStruct;
} AccessTokenIDEx;

/**
 * @brief Permission states
 */
typedef enum TypePermissionState {
    PERMISSION_DENIED = -1,
    PERMISSION_GRANTED = 0,
} PermissionState;

/**
 * @brief Permission grant mode
 */
typedef enum TypeGrantMode {
    /** user grant the permisson by dynamic pop-up window */
    USER_GRANT = 0,
    /**
     * system grant the permission automated when
     * the permission is decleared and app is installed
     */
    SYSTEM_GRANT = 1,
} GrantMode;

/**
 * @brief Permission flag
 */
typedef enum TypePermissionFlag {
    /**
     * permission has not been set by user.
     */
    PERMISSION_DEFAULT_FLAG = 0,
    /**
     * permission has been set by user, If the permission is not granted,
     * a permission window is allowed to apply for permission.
     */
    PERMISSION_USER_SET = 1 << 0,
    /**
     * permission has been set by user, If the permission is not granted,
     * a permission window is not allowed to apply for permission.
     */
    PERMISSION_USER_FIXED = 1 << 1,
    /**
     * permission has been set by system,
     * the permission can be a user_grant one which is granted for pre-authorization and is non-cancellable.
     */
    PERMISSION_SYSTEM_FIXED = 1 << 2,
    /**
     * a user_grant permission has been set by system for pre-authorization,
     * and it is cancellable. it always works with other flags.
     */
    PERMISSION_GRANTED_BY_POLICY = 1 << 3,
    /**
     * permission has been set by security component.
     */
    PERMISSION_COMPONENT_SET = 1 << 4,
    /*
     * permission is fixed by policy and the permission cannot be granted or revoked by user
     */
    PERMISSION_POLICY_FIXED = 1 << 5,
    /*
     * permission is only allowed during the current lifecycle foreground period
     */
    PERMISSION_ALLOW_THIS_TIME = 1 << 6,
} PermissionFlag;

/**
 * @brief Permission operate result
 */
typedef enum TypePermissionOper {
    /** permission has been set, only can change it in settings */
    SETTING_OPER = -1,
    /** operate is passed, no need to do anything */
    PASS_OPER = 0,
    /** permission need dynamic pop-up windows to grant it */
    DYNAMIC_OPER = 1,
    /** invalid operation, something is wrong, see in md files */
    INVALID_OPER = 2,
} PermissionOper;

/**
 * @brief Dlp types
 */
typedef enum DlpType {
    DLP_COMMON = 0,
    DLP_READ = 1,
    DLP_FULL_CONTROL = 2,
    DLP_FULL_BUTT,
} HapDlpType;

/**
 * @brief Dlp permission type
 */
typedef enum TypeDlpPerm {
    DLP_PERM_ALL = 0,
    DLP_PERM_FULL_CONTROL = 1,
    DLP_PERM_NONE = 2,
} DlpPermMode;
} // namespace AccessToken
} // namespace Security
} // namespace OHOS
#endif // ACCESS_TOKEN_H
