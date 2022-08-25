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

#ifndef ACCESSTOKEN_HAP_TOKEN_INFO_H
#define ACCESSTOKEN_HAP_TOKEN_INFO_H

#include "access_token.h"
#include "permission_def.h"
#include "permission_state_full.h"
#include <string>
#include <vector>

namespace OHOS {
namespace Security {
namespace AccessToken {
class HapInfoParams final {
public:
    int userID;
    std::string bundleName;
    int instIndex;
    int dlpType;
    std::string appIDDesc;
    int32_t apiVersion;
};

class HapPolicyParams final {
public:
    ATokenAplEnum apl;
    std::string domain;
    std::vector<PermissionDef> permList;
    std::vector<PermissionStateFull> permStateList;
};

class HapTokenInfo final {
public:
    ATokenAplEnum apl;
    char ver;
    int userID;
    std::string bundleName;
    int32_t apiVersion;
    int instIndex;
    int dlpType;
    std::string appID;
    std::string deviceID;
    AccessTokenID tokenID;
    AccessTokenAttr tokenAttr;
};

class HapTokenInfoForSync final {
public:
    HapTokenInfo baseInfo;
    std::vector<PermissionStateFull> permStateList;
};
} // namespace AccessToken
} // namespace Security
} // namespace OHOS
#endif // ACCESSTOKEN_HAP_TOKEN_INFO_H
