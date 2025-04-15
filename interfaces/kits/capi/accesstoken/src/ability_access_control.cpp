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

#include "ability_access_control.h"

#include <string>

#include "accesstoken_kit.h"
#include "token_setproc.h"

using namespace OHOS::Security::AccessToken;

bool OH_AT_CheckSelfPermission(const char *permission)
{
    if (permission == nullptr) {
        return false;
    }

    uint64_t tokenId = GetSelfTokenID();
    std::string permissionName(permission);
    return (AccessTokenKit::VerifyAccessToken(tokenId, permissionName) == PermissionState::PERMISSION_GRANTED);
}