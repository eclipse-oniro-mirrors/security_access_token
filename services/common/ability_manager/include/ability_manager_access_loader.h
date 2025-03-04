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

#ifndef ABILITY_MANAGER_ACCESS_LOADER_H
#define ABILITY_MANAGER_ACCESS_LOADER_H

#include <iremote_proxy.h>
#include <optional>
#include "access_token.h"

namespace OHOS {
namespace Security {
namespace AccessToken {
const static std::string ABILITY_MANAGER_LIBPATH = "libaccesstoken_ability_manager_adapter.z.so";

struct InnerWant {
    std::optional<std::string> bundleName;
    std::optional<std::string> abilityName;
    std::optional<std::string> hapBundleName;
    std::optional<std::string> resource;
    std::optional<int> hapAppIndex;
    std::optional<int> hapUserID;
    std::optional<AccessTokenID> callerTokenId;
};

class AbilityManagerAccessLoaderInterface {
public:
    AbilityManagerAccessLoaderInterface() {}
    virtual ~AbilityManagerAccessLoaderInterface() {}
    virtual int32_t StartAbility(const InnerWant &innerWant, const sptr<IRemoteObject> &callerToken);
    virtual int32_t KillProcessForPermissionUpdate(uint32_t accessTokenId);
};

class AbilityManagerAccessLoader final: public AbilityManagerAccessLoaderInterface {
    int32_t StartAbility(const InnerWant &innerWant, const sptr<IRemoteObject> &callerToken) override;
    int32_t KillProcessForPermissionUpdate(uint32_t accessTokenId) override;
};

#ifdef __cplusplus
extern "C" {
#endif
    __attribute__((visibility("default"))) void* Create();
    __attribute__((visibility("default"))) void Destroy(void* loaderPtr);
#ifdef __cplusplus
}
#endif
} // namespace AccessToken
} // namespace Security
} // namespace OHOS
#endif // ABILITY_MANAGER_ACCESS_LOADER_H
