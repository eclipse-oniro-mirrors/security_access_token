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

#ifndef ACCESS_TOKEN_DEF_H
#define ACCESS_TOKEN_DEF_H

namespace OHOS {
namespace Security {
namespace AccessToken {
typedef unsigned int AccessTokenID;
typedef unsigned int AccessTokenAttr;
static const int DEFAULT_TOKEN_VERSION = 1;
static const AccessTokenID INVALID_TOKENID = 0;

enum AccessTokenKitRet {
    RET_FAILED = -1,
    RET_SUCCESS = 0,
};

typedef struct {
    unsigned int tokenUniqueID : 20;
    unsigned int res : 6;
    unsigned int dlpFlag : 1;
    unsigned int type : 2;
    unsigned int version : 3;
} AccessTokenIDInner;

typedef enum TypeATokenTypeEnum {
    TOKEN_INVALID = -1,
    TOKEN_HAP = 0,
    TOKEN_NATIVE,
    TOKEN_SHELL,
    TOKEN_TYPE_BUTT,
} ATokenTypeEnum;

typedef enum TypeATokenAplEnum {
    APL_INVALID = 0,
    APL_NORMAL = 1,
    APL_SYSTEM_BASIC = 2,
    APL_SYSTEM_CORE = 3,
} ATokenAplEnum;

typedef union {
    unsigned long long tokenIDEx;
    struct {
        AccessTokenID tokenID;
        AccessTokenAttr tokenAttr;
    } tokenIdExStruct;
} AccessTokenIDEx;

typedef enum TypePermissionState {
    PERMISSION_DENIED = -1,
    PERMISSION_GRANTED = 0,
} PermissionState;

typedef enum TypeGrantMode {
    USER_GRANT = 0,
    SYSTEM_GRANT = 1,
} GrantMode;

typedef enum TypePermissionFlag {
    PERMISSION_DEFAULT_FLAG = 0,
    PERMISSION_USER_SET = 1 << 0,
    PERMISSION_USER_FIXED = 1 << 1,
    PERMISSION_SYSTEM_FIXED = 1 << 2,
    PERMISSION_GRANTED_BY_POLICY = 1 << 3,
} PermissionFlag;

typedef enum TypePermissionOper {
    SETTING_OPER = -1,
    PASS_OPER = 0,
    DYNAMIC_OPER = 1,
    INVALID_OPER = 2,
} PermissionOper;

typedef enum DlpType {
    DLP_COMMON = 0,
    DLP_READ = 1,
    DLP_FULL_CONTROL = 2,
} HapDlpType;

typedef enum TypeDlpPerm {
    DLP_PERM_ALL = 0,
    DLP_PERM_FULL_CONTROL = 1,
    DLP_PERM_NONE = 2,
} DlpPermMode;
} // namespace AccessToken
} // namespace Security
} // namespace OHOS
#endif // ACCESS_TOKEN_DEF_H
