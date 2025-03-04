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
#include "ability_manager_access_loader.h"

#include "ability_manager_adapter.h"

namespace OHOS {
namespace Security {
namespace AccessToken {
int32_t AbilityManagerAccessLoader::StartAbility(
    const InnerWant &innerWant, const sptr<IRemoteObject> &callerToken)
{
#ifdef ABILITY_RUNTIME_ENABLE
    return AbilityManagerAdapter::GetInstance().StartAbility(innerWant, callerToken);
#else
    return 0;
#endif
}

int32_t AbilityManagerAccessLoader::KillProcessForPermissionUpdate(uint32_t accessTokenId)
{
    return AbilityManagerAdapter::GetInstance().KillProcessForPermissionUpdate(accessTokenId);
}

void* Create()
{
    return reinterpret_cast<void*>(new AbilityManagerAccessLoader);
}

void Destroy(void* loaderPtr)
{
    AbilityManagerAccessLoaderInterface* loader = reinterpret_cast<AbilityManagerAccessLoaderInterface*>(loaderPtr);
    if (loader != nullptr) {
        delete loader;
    }
}
} // namespace AccessToken
} // namespace Security
} // namespace OHOS
